#ifndef __CHECKSUM_H
#define __CHECKSUM_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "config.h"
#include "consts.h"
#include "network_utils.h"

static __always_inline __s8 update_ip_len_and_csum(struct __sk_buff *skb, __u8 ip_header_len, __u16 old_ip_len, __u16 new_ip_len) {
    __be16 new_ip_len_be = bpf_htons(new_ip_len);
    __be16 old_ip_len_be = bpf_htons(old_ip_len); 
    
    if (bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, tot_len),
                            &new_ip_len_be, sizeof(new_ip_len_be), 0) < 0)
        return -1;

    if (bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check),
                            old_ip_len_be, new_ip_len_be,
                            sizeof(__u16)) < 0)
        return -1;
    
    return 0;
}

/* Update IP and TCP checksums after packet length change */
static __always_inline __s8 update_checksums_inc(struct __sk_buff *skb, __u8 ip_header_len, __u16 old_ip_len, __wsum acc)
{
    __u16 new_ip_len = skb->len - ETH_HLEN;

    if (update_ip_len_and_csum(skb, ip_header_len, old_ip_len, new_ip_len) < 0)
        return -1;

    __u16 old_tcp_len = old_ip_len - ip_header_len;
    __u16 new_tcp_len = new_ip_len - ip_header_len;
    __be16 old_tcp_len_be = bpf_htons(old_tcp_len);
    __be16 new_tcp_len_be = bpf_htons(new_tcp_len);

    if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + ip_header_len + offsetof(struct tcphdr, check),
                           old_tcp_len_be, new_tcp_len_be,
                           BPF_F_PSEUDO_HDR | sizeof(__u16)) < 0)
        return -1;
    
    if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + ip_header_len + offsetof(struct tcphdr, check),
                           0, acc, 0) < 0)
        return -1;
    
    return 0;
}

static __always_inline __s8 update_checksums_seq_num(struct __sk_buff *skb, __u8 ip_header_len, __u32 old_seq_num, __u32 new_seq_num) {
    __be32 old_seq_num_be = bpf_htonl(old_seq_num);
    __be32 new_seq_num_be = bpf_htonl(new_seq_num);
    return bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + ip_header_len + offsetof(struct tcphdr, check),
                           old_seq_num_be, new_seq_num_be,
                           0) < 0;
}

static __always_inline __s8 update_checksums_ack_num(struct __sk_buff *skb, __u8 ip_header_len, __u32 old_ack_num, __u32 new_ack_num) {
    __be32 old_ack_num_be = bpf_htonl(old_ack_num);
    __be32 new_ack_num_be = bpf_htonl(new_ack_num);
    if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + ip_header_len + offsetof(struct tcphdr, check),
                           old_ack_num_be, new_ack_num_be,
                           0) < 0)
        return -1;
    return 0;
}

/* Recompute TCP checksum for the entire packet */
static __always_inline __s8 recompute_tcp_checksum_internal(struct __sk_buff *skb) {

    __u8 ip_header_len, tcp_header_len;
    __u16 ip_total_len_old;
    __u8 extract_result = extract_tcp_ip_header_lengths(skb, &ip_header_len, &tcp_header_len, &ip_total_len_old);
    if(extract_result != 1)
        return extract_result;
    __wsum payload_csum = 0;
    __u8 buffer[FRAG_BUFF_MAX_SIZE];
    __u8 tcp_payload_offset = ETH_HLEN + ip_header_len + tcp_header_len;
    __u16 tcp_payload_len = skb->len - tcp_payload_offset; 
    __u32 bytes_remaining = tcp_payload_len;
    __u16 ip_total_len_new = skb->len - ETH_HLEN;
    __sum16 old_tcp_check;
    if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + ip_header_len + offsetof(struct tcphdr, check), &old_tcp_check, sizeof(old_tcp_check)) < 0)
        return TC_ACT_SHOT;
    if (update_ip_len_and_csum(skb, ip_header_len, ip_total_len_old, ip_total_len_new) < 0)
        return -1;


   __u8 chunk;
    for (chunk = 0; chunk < (MAX_PKT_SIZE / FRAG_BUFF_MAX_SIZE) + 1; chunk++) {
  
        if(bytes_remaining < FRAG_BUFF_MAX_SIZE) {
            break;
        }
        
        if (bpf_skb_load_bytes(skb, tcp_payload_offset + (chunk * FRAG_BUFF_MAX_SIZE), buffer, FRAG_BUFF_MAX_SIZE) < 0) {
            debug_print("[RECOMPUTE_CSUM] ERROR: Failed to load bytes for chunk %u", chunk);
            return TC_ACT_SHOT;
        }
        
        __s64 csum_result = bpf_csum_diff((__u32*)buffer, FRAG_BUFF_MAX_SIZE, NULL, 0, payload_csum);
        if (csum_result < 0) {
            debug_print("[RECOMPUTE_CSUM] ERROR: csum_diff failed for chunk %u", chunk);
            return TC_ACT_SHOT;
        }
        payload_csum = (__wsum)csum_result;
        bytes_remaining -= FRAG_BUFF_MAX_SIZE;

    }
    if(bytes_remaining > 0) {
        __builtin_memset(buffer, 0, FRAG_BUFF_MAX_SIZE);
        /* Help the verifier understand the bounds */
        bytes_remaining &= 0xFF;
        if(bytes_remaining > FRAG_BUFF_MAX_SIZE || bytes_remaining == 0) {
            debug_print("[RECOMPUTE_CSUM] ERROR: Invalid bytes_remaining=%u after padding", bytes_remaining);
            return TC_ACT_SHOT;
        }
        
        if (bpf_skb_load_bytes(skb, tcp_payload_offset + (chunk * FRAG_BUFF_MAX_SIZE), buffer, bytes_remaining) < 0) {
            debug_print("[RECOMPUTE_CSUM] ERROR: Failed to load remaining bytes %d", bytes_remaining);
            return TC_ACT_SHOT;
        }

        bytes_remaining += (4 - (bytes_remaining % 4)) % 4;
        
        __s64 csum_result = bpf_csum_diff((__u32*)buffer, bytes_remaining, NULL, 0, payload_csum);
        if (csum_result < 0) {
            debug_print("[RECOMPUTE_CSUM] ERROR: csum_diff failed for remaining bytes %d", bytes_remaining);
            return TC_ACT_SHOT;
        }
        payload_csum = (__wsum)csum_result;

    }


    __u8 tcp_header_off = sizeof(struct ethhdr) + ip_header_len;

    /* zero out checksum field */
    __u16 zero = 0;
    if(bpf_skb_store_bytes(skb, tcp_header_off + offsetof(struct tcphdr, check), &zero, sizeof(zero), 0) < 0) {
        debug_print("[RECOMPUTE_CSUM] ERROR: Failed to zero checksum field");
        return TC_ACT_SHOT;
    }

    extract_result = extract_tcp_ip_header_lengths_simple(skb, &ip_header_len, &tcp_header_len);
    if(extract_result != 1)
        return extract_result;
    if(tcp_header_len < 20 || tcp_header_len > 60) {
        debug_print("[RECOMPUTE_CSUM] ERROR: Invalid TCP header length: %u", tcp_header_len);
        return TC_ACT_SHOT;
    }
    
    /* Store validated tcp_header_len in a register-backed variable */
    __u8 validated_tcp_len = tcp_header_len;
    
    /* Re-validate bounds for the verifier after loading from stack */
    if (validated_tcp_len < 20 || validated_tcp_len > 60) {
        debug_print("[RECOMPUTE_CSUM] ERROR: validated_tcp_len out of bounds");
        return TC_ACT_SHOT;
    }
    
    if (bpf_skb_load_bytes(skb, tcp_header_off, buffer, validated_tcp_len) < 0) {
        debug_print("[RECOMPUTE_CSUM] ERROR: Failed to load TCP header");
        return TC_ACT_SHOT;
    }

    __s64 t = bpf_csum_diff(NULL, 0, (__be32 *)buffer, validated_tcp_len, payload_csum);
    if (t < 0) {
        debug_print("[RECOMPUTE_CSUM] ERROR: csum_diff failed for TCP header");
        return TC_ACT_SHOT;
    }
    payload_csum = (__wsum)t;

    if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + ip_header_len + offsetof(struct tcphdr, check),
                           0, payload_csum, 0) < 0) {
        debug_print("[RECOMPUTE_CSUM] ERROR: Failed to replace L4 checksum (first)");
        return TC_ACT_SHOT;
    }
    
    /* add pseudo-header contribution to checksum */
    if (bpf_skb_load_bytes(skb,
            sizeof(struct ethhdr) + offsetof(struct iphdr, saddr),
            buffer, 8) < 0) {
        debug_print("[RECOMPUTE_CSUM] ERROR: Failed to load IP addresses");
        return -1;
    }
    
    buffer[8] = 0;
    buffer[9] = IPPROTO_TCP;
    /* Pseudo-header needs TOTAL TCP length (header + payload) */
    __u16 tcp_total_len = tcp_header_len + tcp_payload_len;
    __be16 tcp_total_len_be = bpf_htons(tcp_total_len);
    __builtin_memcpy(&buffer[10], &tcp_total_len_be, 2);    
    payload_csum = bpf_csum_diff(NULL, 0, (__be32 *)buffer, 12, 0);
    if (payload_csum < 0) {
        debug_print("[RECOMPUTE_CSUM] ERROR: csum_diff failed for pseudo-header");
        return TC_ACT_SHOT;
    }

    if (bpf_l4_csum_replace(skb, tcp_header_off + offsetof(struct tcphdr, check), 0, payload_csum, BPF_F_PSEUDO_HDR) < 0) {
        debug_print("[RECOMPUTE_CSUM] ERROR: Failed to replace L4 checksum (pseudo-header)");
        return TC_ACT_SHOT;
    }
    
    return TC_ACT_OK;
}

#endif // __CHECKSUM_H
