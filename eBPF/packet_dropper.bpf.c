// SPDX-License-Identifier: GPL-2.0
//#include "vmlinux.h"
//#include <bpf/bpf_helpers.h>
//#include <bpf/bpf_endian.h>
//#include "blake2s.h"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stddef.h>
#include "blake2s.h"

#define DEBUG 0

/* Debug configuration - define DEBUG to enable debug prints */
#if DEBUG
#define debug_print(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define debug_print(fmt, ...) do {} while (0)
#endif


/* Network protocol constants */
#define ETH_P_IP    0x0800
#define IPPROTO_TCP 6

/* Traffic Control action codes */  
#define TC_ACT_OK   0
#define TC_ACT_SHOT 2

static const __u32 hash_len = 32;

/* Helper function to check if packet should be skipped */
static __always_inline int should_skip_packet(struct __sk_buff *skb) {
    if (skb->gso_segs > 1) {
        return 1;
    }
    
    if (skb->len > 2000) {
        return 1;
    }
    
    if (skb->gso_size > 0) {
        return 1;
    }
    
    return 0;
}

/* Parse packet headers and return packet type */
static __always_inline int parse_packet(struct __sk_buff *skb, struct ethhdr **eth, struct iphdr **iph, struct tcphdr **tcph) {
    void *data, *data_end;
    __u32 ihl;
    
    if (bpf_skb_pull_data(skb, sizeof(struct ethhdr) + sizeof(struct iphdr)) < 0)
        return -1;
    
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    
    *eth = data;
    if ((void*)(*eth + 1) > data_end)
        return -1;
    
    if ((*eth)->h_proto != bpf_htons(ETH_P_IP))
        return 0;
    
    *iph = (void*)(*eth + 1);
    if ((void*)(*iph + 1) > data_end)
        return -1;

    if ((*iph)->protocol == IPPROTO_TCP) {
        ihl = (*iph)->ihl * 4;
        
        if (bpf_skb_pull_data(skb, sizeof(struct ethhdr) + ihl + sizeof(struct tcphdr)) < 0)
            return -1;
        
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        *eth = data;
        *iph = (void*)(*eth + 1);
        
        *tcph = (void*)(*iph) + ihl;
        if ((void*)(*eth + 1) > data_end)
            return -1;
        if ((void*)(*iph + 1) > data_end)
            return -1;
        if ((void*)(*tcph + 1) > data_end)
            return -1;
        
        return 2;
    }
    
    return 1;   
}


/* Update IP and TCP checksums after packet length change */
static __always_inline int update_len_and_checksums(struct __sk_buff *skb, __u32 ip_header_len, __u16 old_ip_len, __u16 new_ip_len)
{
    __be16 new_ip_len_be = bpf_htons(new_ip_len);
    __be16 old_ip_len_be = bpf_htons(old_ip_len); 
    
    if (bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, tot_len),
                            &new_ip_len_be, sizeof(new_ip_len_be), 0) < 0)
        return -1;
    
    if (bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check),
                            old_ip_len_be, new_ip_len_be,
                            sizeof(__u16)) < 0)
        return -1;

    if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + ip_header_len + offsetof(struct tcphdr, check),
                           old_ip_len - ip_header_len, new_ip_len - ip_header_len,
                           BPF_F_PSEUDO_HDR | sizeof(__u16)) < 0)
        return -1;   
    
    return 0;
}

/* Add keyed BLAKE2s authentication tag to packet */
static __always_inline int add_hmac(struct __sk_buff *skb, __u32 ip_header_len) {
    __u32 new_len;
    __u32 digest[8];
    __u8 secret_key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    __u8 message[32];

    __u32 tcp_payload_offset = sizeof(struct ethhdr) + ip_header_len + sizeof(struct tcphdr);
    
    debug_print("[ADD_HMAC] Processing packet: len=%d, tcp_payload_offset=%d", skb->len, tcp_payload_offset);
    
    if (skb->len < tcp_payload_offset + hash_len) {
        debug_print("[ADD_HMAC] Packet too small for HMAC addition, returning 0");
        return 0;
    }

    if (bpf_skb_load_bytes(skb, skb->len - hash_len, message, hash_len) < 0) {
        debug_print("[ADD_HMAC] Failed to load message bytes for HMAC calculation");
        return -1;
    }
    
    new_len = skb->len + hash_len;
    debug_print("[ADD_HMAC] Expanding packet from %d to %d bytes", skb->len, new_len);
    
    if (bpf_skb_change_tail(skb, new_len, 0) < 0) {
        debug_print("[ADD_HMAC] Failed to expand packet tail");
        return -1;
    }

    blake2sCompute(secret_key, message, digest);
    if (bpf_skb_store_bytes(skb, skb->len - hash_len, digest, hash_len, 0) < 0) {
        debug_print("[ADD_HMAC] Failed to store HMAC digest in packet");
        return -1;
    }
    debug_print("[ADD_HMAC] HMAC successfully added to packet");
    return 1;
}

/* Remove and verify keyed BLAKE2s authentication tag */
static __always_inline int remove_hmac(struct __sk_buff *skb, __u32 ip_header_len) {
    __u8 secret_key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    __u8 message[32];
    __u8 received_tag[32];
    __u32 calculated_digest[8];
    __u32 message_start_pos;
    
    __u32 tcp_payload_offset = sizeof(struct ethhdr) + ip_header_len + sizeof(struct tcphdr);
    
    debug_print("[REMOVE_HMAC] Processing packet: len=%d, tcp_payload_offset=%d", skb->len, tcp_payload_offset);
    
    if (skb->len < tcp_payload_offset + 64) {
        debug_print("[REMOVE_HMAC] Packet too small for HMAC removal");
        return 0;
    }
    
    message_start_pos = skb->len - (hash_len + 32);
    debug_print("[REMOVE_HMAC] HMAC message starts at position %d", message_start_pos);
    
    if (bpf_skb_load_bytes(skb, message_start_pos, message, 32) < 0) {
        debug_print("[REMOVE_HMAC] Failed to load HMAC message bytes");
        return -1;
    }
    
    if (bpf_skb_load_bytes(skb, skb->len - hash_len, received_tag, hash_len) < 0) {
        debug_print("[REMOVE_HMAC] Failed to load received HMAC tag");
        return -1;
    }
    
    blake2sCompute(secret_key, message, calculated_digest);
    
    if (memcmp(calculated_digest, received_tag, hash_len) != 0) {
        debug_print("[REMOVE_HMAC] HMAC verification failed - invalid tag");
        return 0;
    }
    
    debug_print("[REMOVE_HMAC] HMAC verified successfully, removing tag");
    if (bpf_skb_change_tail(skb, skb->len - hash_len, 0) < 0) {
        debug_print("[REMOVE_HMAC] Failed to shrink packet after HMAC removal");
        return -1;
    }
    
    debug_print("[REMOVE_HMAC] HMAC successfully removed from packet");
    return 1;
}


SEC("classifier")
int handle_ingress(struct __sk_buff *skb) {
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;
    __u16 ip_tot_old;
    __u32 ip_header_len;
    int remove_result;
    
    debug_print("[INGRESS] Packet received: len=%d", skb->len);
    
    if (should_skip_packet(skb)) {
        debug_print("[INGRESS] Packet skipped (GSO or oversized)");
        return TC_ACT_OK;
    }
    
    int parse_result = parse_packet(skb, &eth, &iph, &tcph);
    debug_print("[INGRESS] Packet parsing result: %d", parse_result);
    
    if (parse_result != 2)
        return TC_ACT_OK;
    
    ip_tot_old = bpf_ntohs(iph->tot_len);
    ip_header_len = iph->ihl * 4;
    debug_print("[INGRESS] IP packet: total_len=%d, header_len=%d", ip_tot_old, ip_header_len);

    __u8 i;
    for (i = 0; i < 10; i++) {
        debug_print("[INGRESS] HMAC removal loop iteration %d", i);
        remove_result = remove_hmac(skb, ip_header_len);
        debug_print("[INGRESS] remove_hmac result: %d", remove_result);
        
        if (remove_result < 0) {
            debug_print("[INGRESS] Error in remove_hmac, dropping packet");
            return TC_ACT_SHOT;
        }

        if (remove_result == 0) {
            break;
        }
    }

    debug_print("[INGRESS] HMAC processing complete, updating checksums");
    if(i == 0) {
        debug_print("[INGRESS] No HMACs found to remove, packet unchanged");
        return TC_ACT_OK;
    }
    if (update_len_and_checksums(skb, ip_header_len, ip_tot_old, ip_tot_old - i*hash_len) < 0) {
        debug_print("[INGRESS] Error updating checksums, dropping packet");
        return TC_ACT_SHOT;
    }
    bpf_set_hash_invalid(skb);
    bpf_get_hash_recalc(skb);
    debug_print("[INGRESS] Packet processing successful: removed %d HMACs", i);
    return TC_ACT_OK;
}


SEC("classifier")
int handle_egress(struct __sk_buff *skb) {
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;
    __u16 ip_tot_old;
    __u32 ip_header_len;
    int hmac_result;
    
    debug_print("[EGRESS] Packet received: len=%d", skb->len);
    
    if (should_skip_packet(skb)) {
        debug_print("[EGRESS] Packet skipped (GSO or oversized)");
        return TC_ACT_OK;
    }
    
    int parse_result = parse_packet(skb, &eth, &iph, &tcph);
    debug_print("[EGRESS] Packet parsing result: %d", parse_result);
    if (parse_result != 2)
        return TC_ACT_OK;
    
    ip_tot_old = bpf_ntohs(iph->tot_len);
    ip_header_len = iph->ihl * 4;
    debug_print("[EGRESS] IP packet: total_len=%d, header_len=%d", ip_tot_old, ip_header_len);

    __u32 random_val = bpf_get_prandom_u32() % 11;
    debug_print("[EGRESS] Random HMAC count: %d", random_val);
    
    __u8 i;

    for (i = 0; i < 10; i++) {
        if (i >= random_val) {
            debug_print("[EGRESS] Stopping at iteration %d (reached random limit %d)", i, random_val);
            break;
        }
        debug_print("[EGRESS] Adding HMAC iteration %d", i);
        hmac_result = add_hmac(skb, ip_header_len);
        debug_print("[EGRESS] add_hmac result: %d", hmac_result);
        if (hmac_result < 0) {
            debug_print("[EGRESS] Error in add_hmac, dropping packet");
            return TC_ACT_SHOT;
        }
        if (hmac_result == 0) {
            debug_print("[EGRESS] Cannot add more HMACs, stopping");
            break;
        }
    }
    
    if(i == 0) {
        debug_print("[EGRESS] No HMACs added to packet");
        return TC_ACT_OK;
    }

    debug_print("[EGRESS] Updating checksums for %d added HMACs", i);
    if (update_len_and_checksums(skb, ip_header_len, ip_tot_old, ip_tot_old + i*hash_len) < 0) {
        debug_print("[EGRESS] Error updating checksums, dropping packet");
        return TC_ACT_SHOT;
    }

    bpf_set_hash_invalid(skb);
    bpf_get_hash_recalc(skb);
    debug_print("[EGRESS] Packet processing successful: added %d HMACs", i);
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
