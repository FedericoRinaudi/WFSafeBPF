#ifndef __PADDING_H
#define __PADDING_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "config.h"
#include "consts.h"
#include "network_utils.h"
#include "checksum.h"
#include "hmac.h"
#include "skb_mark.h"

/* Remove all padding HMACs from packet */
static __always_inline __s8 remove_all_padding(struct __sk_buff *skb, __u8 tcp_payload_offset, __u8 ip_header_len, __u16 ip_tot_old, __wsum *acc) {
    __u8 i;
    __s8 remove_result;
    __u8 secret_key[32] = SECRET_KEY_PADDING;

    for (i = 0; i < 10; i++) {
        __s32 message_start_pos = skb->len - (32 * (i + 2));
        if (message_start_pos < tcp_payload_offset) {
            break;
        }
        remove_result = remove_hmac(skb, message_start_pos, acc, secret_key);
        
        if (remove_result < 0) {
            debug_print("[INGRESS] Error in remove_hmac, dropping packet");
            return -1;
        }

        if (remove_result == 0) {
            break;
        }
    }

    if(i == 0) {
        return 0;
    }
    
    debug_print("[PADDING] Removed %u bytes of padding (%u HMACs)", HASH_LEN*i, i);
    
    if (bpf_skb_change_tail(skb, skb->len - HASH_LEN*i, 0) < 0) {
        debug_print("[REMOVE_HMAC] Failed to shrink packet after HMAC removal");
        return -1;
    }
    
    return 1;
}

/* Add padding HMACs to packet */
static __always_inline __s8 add_padding_internal(struct __sk_buff *skb) {
    if((bpf_get_prandom_u32() % 100) > PROBABILITY_OF_PADDING){
        return 1;
    }
    __s8 hmac_result;
    __u8 i, tcp_payload_offset, ip_header_len, tcp_header_len;
    __u8 random_val = bpf_get_prandom_u32() % 11;
    __u8 secret_key[32] = SECRET_KEY_PADDING;
    
    __u8 extract_result = extract_tcp_ip_header_lengths_simple(skb, &ip_header_len, &tcp_header_len);
    if (extract_result != 1) {
        debug_print("[EGRESS] Non-TCP/IP packet or extraction error, skipping HMAC addition");
        return extract_result;
    }
    tcp_payload_offset = sizeof(struct ethhdr) + ip_header_len + tcp_header_len;
    if(skb->len < tcp_payload_offset + HASH_LEN) {
        return 1;
    }
    for (i = 0; i < 10; i++) {
        if (i >= random_val) {
            break;
        }
        if (skb->len + HASH_LEN > MAX_PKT_SIZE) {
            break;
        }
        if (bpf_skb_change_tail(skb, skb->len + HASH_LEN, 0) < 0) {
            debug_print("[PADDING] Failed to expand packet tail");
            return -1;
        }
        hmac_result = add_hmac(skb, secret_key);
        if (hmac_result < 0) {
            debug_print("[EGRESS] Error in add_hmac, dropping packet");
            return TC_ACT_SHOT;
        }
        if (hmac_result == 0) {
            break;
        }
    }
    if(i == 0) {
        return 1;
    }
    
    debug_print("[PADDING] Added %u bytes of padding (%u HMACs)", HASH_LEN*i, i);
    
    // Set checksum flag to indicate checksum recalculation is needed
    skb_mark_set_checksum_flag(skb, 1);

    return 1;
}

#endif // __PADDING_H
