#ifndef __NETWORK_UTILS_H
#define __NETWORK_UTILS_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "config.h"

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

/* Extract TCP/IP header lengths without IP total length (simplified version) */
static __always_inline __u8 extract_tcp_ip_header_lengths_simple(struct __sk_buff *skb, __u8 *ip_header_len, __u8 *tcp_header_len) {
    __u8 l4_protocol;
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
    if(bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + *ip_header_len + 12, tcp_header_len, 1) < 0)
        return TC_ACT_SHOT;
    *tcp_header_len = (*tcp_header_len >> 4) * 4;
    debug_print("[EXTRACT] TCP header length: %d bytes", *tcp_header_len);
    return 1;
}

/* Extract TCP/IP header lengths and IP total length */
static __always_inline __u8 extract_tcp_ip_header_lengths(struct __sk_buff *skb, __u8 *ip_header_len, __u8 *tcp_header_len, __u16 *ip_tot_len) {
    __u8 result = extract_tcp_ip_header_lengths_simple(skb, ip_header_len, tcp_header_len);
    if(result != 1)
        return result;
    if(bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, tot_len), ip_tot_len, sizeof(__u16)) < 0)
        return TC_ACT_SHOT;
    *ip_tot_len = bpf_ntohs(*ip_tot_len);
    debug_print("[EXTRACT] IP total length: %d bytes", *ip_tot_len);
    return 1;
}

#endif // __NETWORK_UTILS_H
