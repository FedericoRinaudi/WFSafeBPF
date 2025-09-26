// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "blake2s.h"
//#include <linux/bpf.h>
//#include <linux/if_ether.h>
//#include <linux/ip.h>
//#include <linux/tcp.h>
//#include <linux/udp.h>
//#include <linux/pkt_cls.h>
//#include <bpf/bpf_helpers.h>
//#include <bpf/bpf_endian.h>
//#include <stddef.h>
//#include "blake2s.h"

#define DEBUG 0

/* Debug configuration - define DEBUG to enable debug prints */
#if DEBUG
#define debug_print(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define debug_print(fmt, ...) do {} while (0)
#endif

#define MAX_PKT_SIZE 1500

/* Network protocol constants */
#define ETH_P_IP    0x0800
#define IPPROTO_TCP 6
#define ETH_HLEN    14
/* Traffic Control action codes */  
#define TC_ACT_OK   0
#define TC_ACT_SHOT 2

static const __u32 hash_len = 32;

/* Helper function to check if packet should be skipped */
static __always_inline __u8 should_skip_packet(struct __sk_buff *skb) {
    if (skb->gso_segs > 1) {
        return 1;
    }
    
    if (skb->len > MAX_PKT_SIZE) {
        return 1;
    }
    
    if (skb->gso_size > 0) {
        return 1;
    }
    
    return 0;
}

/* Extract IP header length, TCP payload offset, and IP total length */
static __always_inline __u8 extract_from_packet(struct __sk_buff *skb, __u8 *ip_header_len, __u8 *tcp_payload_offset, __u16 *ip_tot_len) {
    __u8 l4_protocol;
    __u8 tcp_header_len;
    if(skb->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    if(bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, protocol), &l4_protocol, 1) < 0)
        return TC_ACT_SHOT;
    if (l4_protocol != IPPROTO_TCP)
        return TC_ACT_OK;
    if(bpf_skb_load_bytes(skb, sizeof(struct ethhdr), ip_header_len, sizeof(__u8)) < 0)
        return TC_ACT_SHOT;
    *ip_header_len = (*ip_header_len & 0x0F) * 4;
    debug_print("[EXTRACT] IP header length: %d bytes", *ip_header_len);
    if(bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, tot_len), ip_tot_len, sizeof(__u16)) < 0)
        return TC_ACT_SHOT;
    *ip_tot_len = bpf_ntohs(*ip_tot_len);
    debug_print("[EXTRACT] IP total length: %d bytes", *ip_tot_len);
    if(bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + *ip_header_len + 12, &tcp_header_len, 1) < 0)
        return TC_ACT_SHOT;
    tcp_header_len = (tcp_header_len >> 4) * 4;
    debug_print("[EXTRACT] TCP header length: %d bytes", tcp_header_len);
    *tcp_payload_offset = sizeof(struct ethhdr) + *ip_header_len + tcp_header_len;
    return 1;
}

/* helper: delta csum per un campo 16-bit on-wire (usa buffer 32-bit) */
//static __always_inline int csum_diff_16(__be16 old_be, __be16 new_be, __wsum *acc)
//{
//    __be32 old32 = (__be32)(((__u32)old_be) << 16);
//    __be32 new32 = (__be32)(((__u32)new_be) << 16);
//    __s64 t = bpf_csum_diff(&old32, sizeof(old32), &new32, sizeof(new32), *acc);
//    if (t < 0)
//        return -1;
//    *acc = (__wsum)t;
//    return 0;
//}


/* Update IP and TCP checksums after packet length change */
static __always_inline __s8 update_len_and_checksums(struct __sk_buff *skb, __u8 ip_header_len, __u16 old_ip_len, __u16 new_ip_len, __wsum acc)
{
    __be16 new_ip_len_be = bpf_htons(new_ip_len);
    __be16 old_ip_len_be = bpf_htons(old_ip_len); 

    /* leggi IP checksum "old" on-wire */
    //__be16 ip_csum_old_be;
    //if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), &ip_csum_old_be, sizeof(ip_csum_old_be)) < 0)
    //    return -1;

    //bpf_printk("[UPDATE] Old IP checksum (on-wire): 0x%04x", bpf_ntohs(ip_csum_old_be));
    
    if (bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, tot_len),
                            &new_ip_len_be, sizeof(new_ip_len_be), 0) < 0)
        return -1;

    //__be16 ip_csum_should_be_old;
    //if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), &ip_csum_should_be_old, sizeof(ip_csum_should_be_old)) < 0)
    //    return -1;

    //bpf_printk("[UPDATE] Old IP checksum (on-wire): 0x%04x, should be: 0x%04x", bpf_ntohs(ip_csum_old_be), bpf_ntohs(ip_csum_should_be_old));

    if (bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check),
                            old_ip_len_be, new_ip_len_be,
                            sizeof(__u16)) < 0)
        return -1;

    //__be16 ip_csum_new_be;
    //if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), &ip_csum_new_be, sizeof(ip_csum_new_be)) < 0)
    //    return -1;

    //bpf_printk("[UPDATE] New IP checksum: 0x%04x, should be different from old: 0x%04x", bpf_ntohs(ip_csum_new_be), bpf_ntohs(ip_csum_old_be));

    __u16 old_tcp_len = old_ip_len - ip_header_len;
    __u16 new_tcp_len = new_ip_len - ip_header_len;
    __be16 old_tcp_len_be = bpf_htons(old_tcp_len);
    __be16 new_tcp_len_be = bpf_htons(new_tcp_len);

    __be16 tcp_csum_old_be;
    if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + ip_header_len + offsetof(struct tcphdr, check), &tcp_csum_old_be, sizeof(tcp_csum_old_be)) < 0)
        return -1;
    //bpf_printk("[UPDATE] Old TCP checksum (on-wire): 0x%04x", bpf_ntohs(tcp_csum_old_be));

    if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + ip_header_len + offsetof(struct tcphdr, check),
                           old_tcp_len_be, new_tcp_len_be,
                           BPF_F_PSEUDO_HDR | sizeof(__u16)) < 0)
        return -1;

    //__be16 tcp_csum_intermediate_be;
    //if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + ip_header_len + offsetof(struct tcphdr, check), &tcp_csum_intermediate_be, sizeof(tcp_csum_intermediate_be)) < 0)
    //    return -1;
    //bpf_printk("[UPDATE] Intermediate TCP checksum: 0x%04x, should be different from old: 0x%04x", bpf_ntohs(tcp_csum_intermediate_be), bpf_ntohs(tcp_csum_old_be));
    
    if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + ip_header_len + offsetof(struct tcphdr, check),
                           0, acc, 0) < 0)
        return -1;
    
    //__be16 tcp_csum_new_be;
    //if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + ip_header_len + offsetof(struct tcphdr, check), &tcp_csum_new_be, sizeof(tcp_csum_new_be)) < 0)
    //    return -1;
    //bpf_printk("[UPDATE] New TCP checksum: 0x%04x, should be different from old: 0x%04x and from intermediate: 0x%04x", bpf_ntohs(tcp_csum_new_be), bpf_ntohs(tcp_csum_old_be), bpf_ntohs(tcp_csum_intermediate_be));

        /* 2) IP tot_len: old->new (2 byte on-wire) */
    //if (csum_diff_16(old_ip_len_be, new_ip_len_be, &acc) < 0)
    //    return -1;
//
    ///* 3) IP checksum: old->new (2 byte on-wire) */
    //if (csum_diff_16(ip_csum_old_be, ip_csum_new_be, &acc) < 0)
    //    return -1;
//
    ///* 4) TCP checksum: old->new (2 byte on-wire) */
    //if (csum_diff_16(tcp_csum_old_be, tcp_csum_new_be, &acc) < 0)
    //    return -1;
//
    //if (bpf_csum_update(skb, acc) < 0){
    //    bpf_printk("[UPDATE] bpf_csum_update not needed");
    //} else {
    //    bpf_printk("[UPDATE] bpf_csum_update applied");
    //}

    
    
    return 0;
}

/* Add keyed BLAKE2s authentication tag to packet */
static __always_inline __s8 add_hmac(struct __sk_buff *skb, __u8 tcp_payload_offset, __wsum *acc) {
    __u32 new_len;
    __u32 digest[8];
    __u8 secret_key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    __u8 message[32];
    
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
    __s64 t = bpf_csum_diff(NULL, 0, digest, hash_len, *acc);
    if (t < 0)
        return TC_ACT_SHOT;
    *acc = (__wsum)t;
    debug_print("[ADD_HMAC] HMAC successfully added to packet");
    return 1;
}

/* Remove and verify keyed BLAKE2s authentication tag */
static __always_inline __s8 remove_hmac(struct __sk_buff *skb, __u8 tcp_payload_offset, __u32 message_start_pos, __wsum *acc) {
    __u8 secret_key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    __u8 message[32];
    __u8 received_tag[32];
    __u32 calculated_digest[8];
    
    debug_print("[REMOVE_HMAC] Processing packet: len=%d, tcp_payload_offset=%d", skb->len, tcp_payload_offset);
    
    if (message_start_pos < tcp_payload_offset) {
        debug_print("[REMOVE_HMAC] Packet too small for HMAC removal");
        return 0;
    }

    debug_print("[REMOVE_HMAC] HMAC message starts at position %d", message_start_pos);
    
    if (bpf_skb_load_bytes(skb, message_start_pos, message, 32) < 0) {
        debug_print("[REMOVE_HMAC] Failed to load HMAC message bytes");
        return -1;
    }

    if (bpf_skb_load_bytes(skb, message_start_pos + 32, received_tag, hash_len) < 0) {
        debug_print("[REMOVE_HMAC] Failed to load received HMAC tag");
        return -1;
    }
    
    blake2sCompute(secret_key, message, calculated_digest);
    
    if (memcmp(calculated_digest, received_tag, hash_len) != 0) {
        debug_print("[REMOVE_HMAC] HMAC verification failed - invalid tag");
        return 0;
    }

    __s64 t = bpf_csum_diff(calculated_digest, hash_len, NULL, 0, *acc);
    if (t < 0)
        return TC_ACT_SHOT;
    *acc = (__wsum)t;
    
    debug_print("[REMOVE_HMAC] HMAC verified successfully, need to remove tag");
    return 1;
}


SEC("classifier")
int handle_ingress(struct __sk_buff *skb) {
    __u16 ip_tot_old;
    __u8 ip_header_len, tcp_payload_offset;
    __s8 remove_result;
    
    debug_print("[INGRESS] Packet received: len=%d", skb->len);
    
    if (should_skip_packet(skb)) {
        debug_print("[INGRESS] Packet skipped (GSO or oversized)");
        return TC_ACT_OK;
    }

    __u8 extraction_result = extract_from_packet(skb, &ip_header_len, &tcp_payload_offset, &ip_tot_old);
    debug_print("[INGRESS] Packet parsing result: %d", extraction_result);

    if (extraction_result != 1) 
        return extraction_result;

    debug_print("[INGRESS] IP packet: total_len=%d, header_len=%d", ip_tot_old, ip_header_len);

    __u8 i;
    __wsum acc = 0;
    for (i = 0; i < 10; i++) {
        debug_print("[INGRESS] HMAC removal loop iteration %d", i);
        remove_result = remove_hmac(skb, tcp_payload_offset, skb->len - (32 * (i + 2)), &acc);
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
    if (bpf_skb_change_tail(skb, skb->len - hash_len*i, 0) < 0) {
        debug_print("[REMOVE_HMAC] Failed to shrink packet after HMAC removal");
        return -1;
    }
    
    debug_print("[REMOVE_HMAC] HMAC successfully removed from packet");

    if (update_len_and_checksums(skb, ip_header_len, ip_tot_old, ip_tot_old - i*hash_len, acc) < 0) {
        debug_print("[INGRESS] Error updating checksums, dropping packet");
        return TC_ACT_SHOT;
    }
    debug_print("[INGRESS] Packet processing successful: removed %d HMACs", i);
    return TC_ACT_OK;
}


SEC("classifier")
int handle_egress(struct __sk_buff *skb) {
    __u16 ip_tot_old;
    __u8 ip_header_len, tcp_payload_offset;
    __s8 hmac_result;
    
    debug_print("[EGRESS] Packet received: len=%d", skb->len);
    
    if (should_skip_packet(skb)) {
        debug_print("[EGRESS] Packet skipped (GSO or oversized)");
        return TC_ACT_OK;
    }
    
    __u8 extraction_result = extract_from_packet(skb, &ip_header_len, &tcp_payload_offset, &ip_tot_old);
    debug_print("[EGRESS] Packet parsing result: %d", extraction_result);
    if (extraction_result != 1) 
        return extraction_result; // Non-TCP, lascia intatto
    
    debug_print("[EGRESS] IP packet: total_len=%d, header_len=%d", ip_tot_old, ip_header_len);

    __u8 random_val = bpf_get_prandom_u32() % 11;
    debug_print("[EGRESS] Random HMAC count: %d", random_val);
    random_val += 1; // DEBUG: Garantisce almeno 1 HMAC
    __u8 i;
    __wsum acc = 0;
    for (i = 0; i < 10; i++) {
        if (i >= random_val) {
            debug_print("[EGRESS] Stopping at iteration %d (reached random limit %d)", i, random_val);
            break;
        }
        if (skb->len + hash_len > MAX_PKT_SIZE) {
            debug_print("[EGRESS] Cannot add mosudo apt install tmux -yre HMACs, packet size limit reached");
            break;
        }
        debug_print("[EGRESS] Adding HMAC iteration %d", i);
        hmac_result = add_hmac(skb, tcp_payload_offset, &acc);
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
    if (update_len_and_checksums(skb, ip_header_len, ip_tot_old, ip_tot_old + i*hash_len, acc) < 0) {
        debug_print("[EGRESS] Error updating checksums, dropping packet");
        return TC_ACT_SHOT;
    }
    debug_print("[EGRESS] Packet processing successful: added %d HMACs", i);
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
