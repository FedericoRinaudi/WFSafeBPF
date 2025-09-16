// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stddef.h>

/* Protocol definitions */
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

/* Traffic Control action codes */
#define TC_ACT_UNSPEC        (-1)
#define TC_ACT_OK             0
#define TC_ACT_RECLASSIFY     1
#define TC_ACT_SHOT           2
#define TC_ACT_PIPE           3
#define TC_ACT_STOLEN         4
#define TC_ACT_QUEUED         5
#define TC_ACT_REPEAT         6
#define TC_ACT_REDIRECT       7

/* Ethernet protocol types */
#ifndef ETH_P_IP
#define ETH_P_IP    0x0800
#endif

/* Secret key and hash configuration */
static const __u32 secret_key = 0xdeadbeef;
static const __u32 hash_len = sizeof(__u32);

/* Helper function for common packet parsing */
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
        return 0; /* not IPv4 */
    
    *iph = (void*)(*eth + 1);
    if ((void*)(*iph + 1) > data_end)
        return -1;
    
    /* Initialize TCP header pointer to NULL */
    if (tcph)
        *tcph = NULL;
    
    /* If it's TCP, parse TCP header */
    if ((*iph)->protocol == IPPROTO_TCP && tcph) {
        ihl = (*iph)->ihl * 4; /* IP header length in bytes */
        
        /* Ensure we have enough data for TCP header */
        if (bpf_skb_pull_data(skb, sizeof(struct ethhdr) + ihl + sizeof(struct tcphdr)) < 0)
            return -1;
        
        /* Reload pointers after potential reallocation */
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        *eth = data;
        *iph = (void*)(*eth + 1);
        
        *tcph = (void*)(*iph) + ihl;
        if ((void*)(*tcph + 1) > data_end)
            return -1;
        
        return 2; /* valid IPv4 TCP packet */
    }
    
    return 1; /* valid IPv4 packet */
}

/* Helper function to update TCP checksum */
static __always_inline int update_tcp_checksum(struct __sk_buff *skb, int is_tcp, __u16 old_len, __u16 new_len) {
    __u32 csum_offset;
    __u16 tcp_len_old, tcp_len_new;
    __u8 ihl_byte;
    __u32 ihl;
    
    if (!is_tcp)
        return 0; /* Not TCP, nothing to update */
    
    /* Load IP header length from packet */
    if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr), &ihl_byte, 1) < 0)
        return -1;
    
    ihl = (ihl_byte & 0xf) * 4;
    tcp_len_old = old_len - ihl;
    tcp_len_new = new_len - ihl;
    
    /* Calculate TCP checksum offset from start of packet */
    csum_offset = sizeof(struct ethhdr) + ihl + offsetof(struct tcphdr, check);
    
    /* Update TCP checksum using L4 checksum replace */
    if (bpf_l4_csum_replace(skb, csum_offset, tcp_len_old, tcp_len_new, 
                           BPF_F_PSEUDO_HDR | sizeof(__u16)) < 0)
        return -1;
    
    return 0;
}

/* Helper function to update IP length and checksum */
static __always_inline int update_ip_checksum(struct __sk_buff *skb, __u16 old_len, __u16 new_len) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    __be16 new_len_be = bpf_htons(new_len);
    
    /* Recheck bounds after potential packet modifications */
    if ((void*)(eth + 1) > data_end)
        return -1;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;
    
    iph = (void*)(eth + 1);
    if ((void*)(iph + 1) > data_end)
        return -1;
    
    /* Update IP total length at fixed offset */
    if (bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, tot_len),
                            &new_len_be, sizeof(new_len_be), 0) < 0)
        return -1;
    
    /* Update IP checksum at fixed offset */
    if (bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check),
                            bpf_htons(old_len), bpf_htons(new_len),
                            sizeof(__u16)) < 0)
        return -1;
    
    return 0;
}


SEC("classifier")
int handle_ingress(struct __sk_buff *skb) {
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;
    __u32 old_len, hash_offset, found_hash, calculated_hash;
    __u16 ip_tot_old, ip_tot_without_hash;
    
    /* Parse packet headers */
    int parse_result = parse_packet(skb, &eth, &iph, &tcph);
    if (parse_result <= 0)
        return (parse_result == 0) ? TC_ACT_OK : TC_ACT_SHOT;
    
    old_len = skb->len;
    
    /* Check if packet contains hash */
    if (old_len < hash_len)
        return TC_ACT_OK;
    
    hash_offset = old_len - hash_len;
    if (bpf_skb_load_bytes(skb, hash_offset, &found_hash, hash_len) < 0)
        return TC_ACT_OK;
    
    /* Update IP header for hash verification */
    __u16 tot_len_offset = sizeof(struct ethhdr) + offsetof(struct iphdr, tot_len);
    __u16 ip_tot_be;
    
    if (bpf_skb_load_bytes(skb, tot_len_offset, &ip_tot_be, sizeof(ip_tot_be)) < 0)
        return TC_ACT_SHOT;
    
    ip_tot_old = bpf_ntohs(ip_tot_be);
    ip_tot_without_hash = ip_tot_old - hash_len;
    
    if (update_ip_checksum(skb, ip_tot_old, ip_tot_without_hash) < 0)
        return TC_ACT_SHOT;
    
    /* Update TCP checksum if it's a TCP packet */
    int is_tcp = (parse_result == 2);
    if (is_tcp && update_tcp_checksum(skb, is_tcp, ip_tot_old, ip_tot_without_hash) < 0)
        return TC_ACT_SHOT;
    
    /* Replace hash with secret key for verification */
    if (bpf_skb_store_bytes(skb, hash_offset, &secret_key, hash_len, 0) < 0)
        return TC_ACT_SHOT;
    
    calculated_hash = bpf_get_hash_recalc(skb);
    
    if (found_hash != calculated_hash) {
        /* Hash mismatch - restore original packet */
        bpf_skb_store_bytes(skb, hash_offset, &found_hash, hash_len, 0);
        update_ip_checksum(skb, ip_tot_without_hash, ip_tot_old);
        /* Restore TCP checksum if needed */
        if (is_tcp)
            update_tcp_checksum(skb, is_tcp, ip_tot_without_hash, ip_tot_old);
        return TC_ACT_OK;
    } else {
        /* Hash match - drop packet */
        return TC_ACT_OK;
    }
    
    /* Valid hash - remove it */
    if (bpf_skb_change_tail(skb, old_len - hash_len, 0) < 0)
        return TC_ACT_SHOT;
    
    return TC_ACT_OK;
}


SEC("classifier")
int handle_egress(struct __sk_buff *skb) {
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;
    __u32 old_len, new_len, key_offset, hmac_hash;
    __u16 ip_tot_old;
    
    /* Parse packet headers */
    int parse_result = parse_packet(skb, &eth, &iph, &tcph);
    if (parse_result <= 0)
        return (parse_result == 0) ? TC_ACT_OK : TC_ACT_SHOT;
    
    int is_tcp = (parse_result == 2);
    
    /* Random 50% packet marking */
    if ((bpf_get_prandom_u32() & 1) == 0)
        return TC_ACT_OK;
    
    /* Load IP total length using offset */
    __u16 tot_len_offset = sizeof(struct ethhdr) + offsetof(struct iphdr, tot_len);
    __u16 ip_tot_be;
    
    if (bpf_skb_load_bytes(skb, tot_len_offset, &ip_tot_be, sizeof(ip_tot_be)) < 0)
        return TC_ACT_SHOT;
    
    ip_tot_old = bpf_ntohs(ip_tot_be);
    old_len = skb->len;
    new_len = old_len + hash_len;
    key_offset = old_len;
    
    /* Add space for hash */
    if (bpf_skb_change_tail(skb, new_len, 0) < 0)
        return TC_ACT_SHOT;
    
    /* Write secret key */
    if (bpf_skb_store_bytes(skb, key_offset, &secret_key, hash_len, 0) < 0)
        return TC_ACT_SHOT;
    
    /* Calculate hash and replace secret key */
    hmac_hash = bpf_get_hash_recalc(skb);
    if (bpf_skb_store_bytes(skb, key_offset, &hmac_hash, hash_len, 0) < 0)
        return TC_ACT_SHOT;
    
    /* Reload pointers after tail change */
    parse_result = parse_packet(skb, &eth, &iph, &tcph);
    if (parse_result != 1 && parse_result != 2)
        return TC_ACT_SHOT;
    
    /* Update IP header */
    if (update_ip_checksum(skb, ip_tot_old, ip_tot_old + hash_len) < 0)
        return TC_ACT_SHOT;
    
    /* Update TCP checksum if it's a TCP packet */
    if (is_tcp && update_tcp_checksum(skb, is_tcp, ip_tot_old, ip_tot_old + hash_len) < 0)
        return TC_ACT_SHOT;
    
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
