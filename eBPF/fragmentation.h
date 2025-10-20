#ifndef __FRAGMENTATION_H
#define __FRAGMENTATION_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "config.h"
#include "network_utils.h"
#include "checksum.h"

/* Clone fragment to packet - moves fragment data to the beginning of the packet */
static __always_inline __u8 fragmentation_clone_to_packet_internal(struct __sk_buff *skb) {
    debug_print("[FRAG_CLONE] Entry: mark=%u, len=%u", skb->mark, skb->len);
    
    /* Fragment info from skb->mark */
    if(skb->mark <= 32)
        return 1; // Signal to continue with fragmentation
    
    __u16 prev_payload_len = skb->mark & 0xFFFF;
    __u16 old_ip_len, new_ip_len;
    __u8 ip_header_len, tcp_header_len;
    __u8 extract_result = extract_tcp_ip_header_lengths(skb, &ip_header_len, &tcp_header_len, &old_ip_len);
    if(extract_result != 1)
        return extract_result;
    
    debug_print("[FRAG_CLONE] Headers: ip_len=%u, tcp_len=%u", ip_header_len, tcp_header_len);

    /* Calculate packet structure offsets */
    __u8 tcp_payload_offset = sizeof(struct ethhdr) + ip_header_len + tcp_header_len;
    __u16 fragment_start = tcp_payload_offset + prev_payload_len;
    __u16 fragment_len = skb->len - fragment_start;
    
    debug_print("[FRAG_CLONE] prev_payload_len=%u, fragment_start=%u, fragment_len=%u", 
                prev_payload_len, fragment_start, fragment_len);
    
    /* Working variables */
    __u8 buffer[FRAG_BUFF_MAX_SIZE];

    /* copy fragment data into the right place */
    __u16 bytes_left = fragment_len;
    debug_print("[FRAG_CLONE] Starting copy: bytes_left=%u", bytes_left);
    
    for(__u8 i = 0; i < (MAX_PKT_SIZE / FRAG_BUFF_MAX_SIZE) + 1; i++) {
        __u32 chunk_size = bytes_left;
        if(chunk_size > FRAG_BUFF_MAX_SIZE)
            chunk_size = FRAG_BUFF_MAX_SIZE;

        if(chunk_size == 0)
            break;

        debug_print("[FRAG_CLONE] Chunk %u: size=%u, from=%u, to=%u", 
                    i, chunk_size, fragment_start + (i * FRAG_BUFF_MAX_SIZE), 
                    tcp_payload_offset + (i * FRAG_BUFF_MAX_SIZE));

        if(bpf_skb_load_bytes(skb, fragment_start + (i * FRAG_BUFF_MAX_SIZE), buffer, chunk_size) < 0) {
            debug_print("[FRAG_CLONE] ERROR: Failed to load bytes at chunk %u", i);
            return TC_ACT_SHOT;
        }
        
        if(bpf_skb_store_bytes(skb, tcp_payload_offset + (i * FRAG_BUFF_MAX_SIZE), buffer, chunk_size, 0) < 0) {
            debug_print("[FRAG_CLONE] ERROR: Failed to store bytes at chunk %u", i);
            return TC_ACT_SHOT;
        }

        bytes_left -= chunk_size;
    }

    /* update packet and IP lengths */
    __u16 new_packet_len = tcp_payload_offset + fragment_len;
    
    debug_print("[FRAG_CLONE] Resizing packet to %u bytes", new_packet_len);
    
    if(bpf_skb_change_tail(skb, new_packet_len, 0) < 0) {
        debug_print("[FRAG_CLONE] ERROR: Failed to change tail");
        return TC_ACT_SHOT;
    }

    new_ip_len = skb->len - ETH_HLEN;
    
    if(update_ip_len_and_csum(skb, ip_header_len, old_ip_len, new_ip_len) < 0) {
        debug_print("[FRAG_CLONE] ERROR: Failed to update IP len and csum");
        return TC_ACT_SHOT;
    }

    /* Update TCP sequence number for this fragment */
    __be32 tcp_seq;
    if(bpf_skb_load_bytes(skb, ETH_HLEN + ip_header_len + offsetof(struct tcphdr, seq), 
                          &tcp_seq, sizeof(tcp_seq)) < 0) {
        debug_print("[FRAG_CLONE] ERROR: Failed to load TCP seq");
        return TC_ACT_SHOT;
    }
    
    __u32 new_seq = bpf_ntohl(tcp_seq) + prev_payload_len;
    __be32 new_seq_be = bpf_htonl(new_seq);
    
    if(bpf_skb_store_bytes(skb, ETH_HLEN + ip_header_len + offsetof(struct tcphdr, seq),
                           &new_seq_be, sizeof(new_seq_be), 0) < 0) {
        debug_print("[FRAG_CLONE] ERROR: Failed to store TCP seq");
        return TC_ACT_SHOT;
    }
    
    debug_print("[FRAG_CLONE] Updated TCP seq: old=%u, new=%u", bpf_ntohl(tcp_seq), new_seq);
    
    debug_print("[FRAG_CLONE] Success: packet resized, clearing mark");
    skb->mark = 1; // Clear mark after fragmentation
    
    return 1; // Signal to continue with fragmentation
}

/* Fragment packet into multiple smaller packets */
static __always_inline __u8 fragment_packet_internal(struct __sk_buff *skb) {
    __u8 ip_header_len, tcp_header_len;
    __u16 old_ip_len, new_ip_len;
    
    debug_print("[FRAGMENT] Entry: len=%u, mark=%u", skb->len, skb->mark);
    
    __u8 extract_result = extract_tcp_ip_header_lengths(skb, &ip_header_len, &tcp_header_len, &old_ip_len);
    if(extract_result != 1)
        return extract_result;
    
    __u32 tcp_payload_offset = sizeof(struct ethhdr)
                             + (__u32)ip_header_len
                             + (__u32)tcp_header_len;
    __u16 payload_len = skb->len - tcp_payload_offset;
    
    debug_print("[FRAGMENT] Headers: ip_len=%u, tcp_len=%u, payload_len=%u", 
                ip_header_len, tcp_header_len, payload_len);
    
    __u8 i;
    // Fragment creation loop
    for (i = 0; i < 10; i++) {
        // Check if we should fragment
        if ((bpf_get_prandom_u32() % 100) > PROBABILITY_OF_FRAGMENTATION || payload_len < 64) {
            debug_print("[FRAGMENT] Stopping fragmentation at iteration %u (payload_len=%u)", i, payload_len);
            break; // No fragmentation for small payloads
        }
        // Calculate new fragment size (minimum 32 bytes)
        payload_len = (bpf_get_prandom_u32() % (payload_len - 32)) + 32; // size of the fragment payload
        
        debug_print("[FRAGMENT] Iteration %u: Creating fragment with payload_len=%u", i, payload_len);
        
        // Store fragment info and clone packet
        skb->mark = payload_len;
        if (bpf_clone_redirect(skb, skb->ifindex, 0) < 0) {
            debug_print("[FRAGMENT] ERROR: Failed to clone packet at iteration %u", i);
            return TC_ACT_SHOT;
        }
        
        debug_print("[FRAGMENT] Iteration %u: Clone successful, resizing original", i);
        
        if (bpf_skb_change_tail(skb, tcp_payload_offset + payload_len, 0) < 0) {
            debug_print("[FRAGMENT] ERROR: Failed to change tail at iteration %u", i);
            return TC_ACT_SHOT;
        }
    }

    new_ip_len = skb->len - ETH_HLEN;

    if(update_ip_len_and_csum(skb, ip_header_len, old_ip_len, new_ip_len) < 0) {
        debug_print("[FRAG_CLONE] ERROR: Failed to update IP len and csum");
        return TC_ACT_SHOT;
    }
    
    if(i != 0) {
        debug_print("[FRAGMENT] Created %u fragments, setting mark=1", i);
        skb->mark = 1;
    } else {
        debug_print("[FRAGMENT] No fragments created");
    }

    return 1; // Success, continue to add_padding
}

#endif // __FRAGMENTATION_H
