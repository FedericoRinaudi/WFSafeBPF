#ifndef __FRAGMENTATION_H
#define __FRAGMENTATION_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "config.h"
#include "network_utils.h"
#include "checksum.h"
#include "skb_mark.h"

/* Clone fragment to packet - moves fragment data to the beginning of the packet */
static __always_inline __u8 fragmentation_clone_to_packet_internal(struct __sk_buff *skb) {
    debug_print("[FRAG_CLONE] Entry: mark=%u, len=%u", skb->mark, skb->len);
    
    /* Extract fragment info from skb->mark */
    __u16 payload_len = skb_mark_get_frag_payload_len(skb);
    if(payload_len == 0) {
        debug_print("[FRAG_CLONE] No fragment payload length set, nothing to clone");
        return 1; // Nothing to do
    }

    __u16 old_ip_len, new_ip_len;
    __u8 ip_header_len, tcp_header_len;
    __u8 result = extract_tcp_ip_header_lengths(skb, &ip_header_len, &tcp_header_len, &old_ip_len);
    if(result != 1)
        return result;

    __u32 new_packet_len = ETH_HLEN + ip_header_len + tcp_header_len + payload_len;
    
    if(bpf_skb_change_tail(skb, new_packet_len, 0) < 0) {
        debug_print("[FRAG_CLONE] ERROR: Failed to change tail");
        return TC_ACT_SHOT;
    }

    new_ip_len = new_packet_len - ETH_HLEN;
    
    if(update_ip_len_and_csum(skb, ip_header_len, old_ip_len, new_ip_len) < 0) {
        debug_print("[FRAG_CLONE] ERROR: Failed to update IP len and csum");
        return TC_ACT_SHOT;
    }    
    /* Clear frag_payload_len and set checksum_flag (packet modified) */
    skb_mark_set_frag_payload_len(skb, 0);
    skb_mark_set_checksum_flag(skb, 1);  // Checksum recalculation needed
        
    return 1; // Signal to continue with fragmentation
}

/* Fragment packet into multiple smaller packets */
static __always_inline __u8 fragment_packet_internal(struct __sk_buff *skb) {
    __u8 ip_header_len, tcp_header_len;
    __u16 old_ip_len, new_ip_len;
    
    debug_print("[FRAGMENT] Entry: len=%u, mark=%u", skb->len, skb->mark);
    
    __u8 result = extract_tcp_ip_header_lengths(skb, &ip_header_len, &tcp_header_len, &old_ip_len);
    if(result != 1)
        return result;
    
    __u32 tcp_payload_offset = sizeof(struct ethhdr)
                             + (__u32)ip_header_len
                             + (__u32)tcp_header_len;
    __u16 payload_len = skb->len - tcp_payload_offset;
    
    debug_print("[FRAGMENT] Headers: ip_len=%u, tcp_len=%u, payload_len=%u", 
                ip_header_len, tcp_header_len, payload_len);
    
    // Check if we should fragment
    if ((bpf_get_prandom_u32() % 100) > PROBABILITY_OF_FRAGMENTATION || payload_len < 64 || skb_mark_get_redirect_count(skb) > 8 ) {
        return 1; // No fragmentation for small payloads
    }
    // Calculate new fragment size (minimum 32 bytes)
    u16 frag_payload_len = (bpf_get_prandom_u32() % (payload_len - 32)) + 32; // size of the fragment payload
    payload_len -= frag_payload_len;
    
    // Increment redirect count and store fragment info in mark
    skb_mark_increment_redirect_count(skb);
    skb_mark_set_frag_payload_len(skb, frag_payload_len);
    
    if (bpf_clone_redirect(skb, skb->ifindex, 0) < 0) {
        debug_print("[FRAGMENT] ERROR: Failed to clone packet at iteration");
        return TC_ACT_SHOT;
    }

    skb_mark_set_frag_payload_len(skb, 0);  // Clear frag payload, keep other fields
    
    debug_print("[FRAGMENT] Clone successful, resizing original");

    __u16 read_start_offset = tcp_payload_offset + frag_payload_len;
    new_ip_len = old_ip_len - frag_payload_len;
    __u16 bytes_left = payload_len;
    __u8 buffer[FRAG_BUFF_MAX_SIZE];
    
    for(__u8 i = 0; i < (MAX_PKT_SIZE / FRAG_BUFF_MAX_SIZE) + 1; i++) {
        __u32 chunk_size = bytes_left;
        if(chunk_size > FRAG_BUFF_MAX_SIZE)
            chunk_size = FRAG_BUFF_MAX_SIZE;

        if(chunk_size == 0)
            break;

        if(bpf_skb_load_bytes(skb, read_start_offset + (i * FRAG_BUFF_MAX_SIZE), buffer, chunk_size) < 0) {
            debug_print("[FRAG_CLONE] ERROR: Failed to load bytes at chunk %u", i);
            return TC_ACT_SHOT;
        }
        
        if(bpf_skb_store_bytes(skb, tcp_payload_offset + (i * FRAG_BUFF_MAX_SIZE), buffer, chunk_size, 0) < 0) {
            debug_print("[FRAG_CLONE] ERROR: Failed to store bytes at chunk %u", i);
            return TC_ACT_SHOT;
        }

        bytes_left -= chunk_size;
    }
    
    
    if (bpf_skb_change_tail(skb, tcp_payload_offset + payload_len, 0) < 0) {
        debug_print("[FRAGMENT] ERROR: Failed to change tail");
        return TC_ACT_SHOT;
    }

    if(update_ip_len_and_csum(skb, ip_header_len, old_ip_len, new_ip_len) < 0) {
        debug_print("[FRAG_CLONE] ERROR: Failed to update IP len and csum");
        return TC_ACT_SHOT;
    }
    
    skb_mark_set_checksum_flag(skb, 1);

    __u32 old_seq;
    result = extract_seq_num(skb, ip_header_len, &old_seq);
    __u32 new_seq = old_seq + frag_payload_len;

    return replace_seq_num(skb, ip_header_len, new_seq);
}

#endif // __FRAGMENTATION_H
