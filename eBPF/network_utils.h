#ifndef __NETWORK_UTILS_H
#define __NETWORK_UTILS_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "config.h"


/* TCP flags */
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_RST 0x04

struct flow_info {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

static __always_inline void reverse_flow(struct flow_info *flow) {
    __u32 tmp;
    tmp = flow->saddr;
    flow->saddr = flow->daddr;
    flow->daddr = tmp;
    tmp = (__u32)flow->sport;
    flow->sport = flow->dport;
    flow->dport = (__u16)tmp;
}

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

static __always_inline __u8 extract_ip_header_len(struct __sk_buff *skb, __u8 *ip_header_len) {
    if(skb->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr), ip_header_len, sizeof(__u8)) < 0)
        return TC_ACT_SHOT;
    *ip_header_len = (*ip_header_len & 0x0F) * 4;
    return 1;
}

/* Extract TCP/IP header lengths without IP total length (simplified version) */
static __always_inline __u8 extract_tcp_ip_header_lengths_simple(struct __sk_buff *skb, __u8 *ip_header_len, __u8 *tcp_header_len) {
    __u8 l4_protocol, result;
    result = extract_ip_header_len(skb, ip_header_len);
    if(result!=1)
        return result;
    if(bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, protocol), &l4_protocol, 1) < 0)
        return TC_ACT_SHOT;
    if (l4_protocol != IPPROTO_TCP)
        return TC_ACT_OK;
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

/* ============================================================================
 * TCP Packet Inspection Functions
 * ============================================================================ */

/**
 * Get TCP flags from packet
 * Returns the flags byte, or 0 on error
 */
static __always_inline __u8 extract_tcp_flags(struct __sk_buff *skb, __u8 ip_hdr_len, __u8 *tcp_flags) {
    // Load TCP flags (in the 13th byte of TCP header)
    __u8 flags;
    __u32 tcp_offset = sizeof(struct ethhdr) + ip_hdr_len;
    if (bpf_skb_load_bytes(skb, tcp_offset + 13, &flags, sizeof(__u8)) < 0)
        return TC_ACT_SHOT;
    
    *tcp_flags = flags;

    return 1;
}

/**
 * Check if this is the first SYN packet of the handshake
 */
static __always_inline int is_syn(__u8 flags) {
    // SYN without ACK (first packet of handshake)
    return (flags & TCP_FLAG_SYN);
}

/**
 * Check if packet has FIN flag
 */
static __always_inline int is_fin(__u8 flags) {
    return (flags & TCP_FLAG_FIN);
}


/**
 * Check if packet has RST flag
 */
static __always_inline int is_rst(__u8 flags) {
    return (flags & TCP_FLAG_RST);
}

/**
 * Check if packet has ACK flag
 */
static __always_inline int has_ack_flag(__u8 flags) {
    return (flags & TCP_FLAG_ACK);
}

/* ============================================================================
 * TCP Sequence/Acknowledgment Number Functions
 * ============================================================================ */

/**
 * Get current seq_num from packet
 */
static __always_inline __u8 extract_seq_num(struct __sk_buff *skb, __u8 ip_hdr_len, __u32 *seq) {
    // Load TCP sequence number
    __u32 tcp_offset = sizeof(struct ethhdr) + ip_hdr_len;
    if (bpf_skb_load_bytes(skb, tcp_offset + offsetof(struct tcphdr, seq), seq, sizeof(*seq)) < 0)
        return TC_ACT_SHOT;

    *seq = bpf_ntohl(*seq);

    return 1;
}

/**
 * Get current ack_num from packet
 */
static __always_inline __u32 extract_ack_num(struct __sk_buff *skb, __u8 ip_hdr_len, __u32 *ack_seq) {
    // Load TCP acknowledgment number
    __u32 tcp_offset = sizeof(struct ethhdr) + ip_hdr_len;
    if (bpf_skb_load_bytes(skb, tcp_offset + offsetof(struct tcphdr, ack_seq), ack_seq, sizeof(*ack_seq)) < 0)
        return TC_ACT_SHOT;

    *ack_seq = bpf_ntohl(*ack_seq);
    return 1;
}

/**
 * Replace seq_num in packet with new value
 */
static __always_inline int replace_seq_num(struct __sk_buff *skb, __u8 ip_hdr_len, __u32 new_seq) {
    __u32 tcp_offset = sizeof(struct ethhdr) + ip_hdr_len;
    
    __u32 new_seq_net = bpf_htonl(new_seq);
    __u32 seq_offset = tcp_offset + offsetof(struct tcphdr, seq);
    if (bpf_skb_store_bytes(skb, seq_offset, &new_seq_net, sizeof(new_seq_net), 0) < 0)
        return TC_ACT_SHOT;
    
    debug_print("[SEQ_TRANS] Replaced seq in packet: %u", new_seq);
    return 1;
}

/**
 * Replace ack_num in packet with new value
 */
static __always_inline int replace_ack_num(struct __sk_buff *skb, __u8 ip_hdr_len, __u32 new_ack) {
    __u32 tcp_offset = sizeof(struct ethhdr) + ip_hdr_len;
    
    // Update ack_num
    __u32 new_ack_net = bpf_htonl(new_ack);
    __u32 ack_offset = tcp_offset + offsetof(struct tcphdr, ack_seq);
    if (bpf_skb_store_bytes(skb, ack_offset, &new_ack_net, sizeof(new_ack_net), 0) < 0)
        return -1;
    
    debug_print("[SEQ_TRANS] Replaced ack in packet: %u", new_ack);
    return 0;
}

/* ============================================================================
 * Flow Key Extraction
 * ============================================================================ */

/**
 * Extract flow key from packet
 * Returns 0 on success, negative on error
 */
static __always_inline __u8 extract_flow_info(struct __sk_buff *skb, __u8 ip_hdr_len, struct flow_info *flow) {
    // Load IP addresses
    if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, saddr), &(flow->saddr), sizeof(__u32)) < 0)
        return TC_ACT_SHOT;
    if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, daddr), &(flow->daddr), sizeof(__u32)) < 0)
        return TC_ACT_SHOT;
    // Load TCP ports
    __u32 tcp_offset = sizeof(struct ethhdr) + ip_hdr_len;

    if (bpf_skb_load_bytes(skb, tcp_offset + offsetof(struct tcphdr, source), &(flow->sport), sizeof(__u16)) < 0)
        return TC_ACT_SHOT;
    if (bpf_skb_load_bytes(skb, tcp_offset + offsetof(struct tcphdr, dest), &(flow->dport), sizeof(__u16)) < 0)
        return TC_ACT_SHOT;
    return 1;
}

#endif // __NETWORK_UTILS_H
