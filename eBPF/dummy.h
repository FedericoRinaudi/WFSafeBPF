#ifndef DUMMY_H
#define DUMMY_H
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "config.h"
#include "consts.h"
#include "network_utils.h"
#include "checksum.h"
#include "skb_mark.h"


static __always_inline __s8 is_dummy(struct __sk_buff *skb, __u8 tcp_payload_offset, __u8 ip_header_len, __u16 ip_tot_old) {
    __u8 secret_key[32] = SECRET_KEY_DUMMY;
    __wsum acc = 0;
    if(skb->len - tcp_payload_offset < HASH_LEN*2) {
        return 0;
    }
    return remove_hmac(skb, skb->len - (HASH_LEN*2), &acc, secret_key);
}

static __always_inline __u8 dummy_clone_to_packet_internal(struct __sk_buff *skb) {
    __u16 payload_len = skb_mark_get_len(skb);
    if(payload_len == 0) {
        return TC_ACT_SHOT; // Nothing to do
    }
    __u16 old_ip_len, new_ip_len;
    __u8 ip_header_len, tcp_header_len;
    __u8 result = extract_tcp_ip_header_lengths(skb, &ip_header_len, &tcp_header_len, &old_ip_len);
    if(result != 1)
        return result;

    __u32 new_packet_len = ETH_HLEN + ip_header_len + tcp_header_len + payload_len;
    
    debug_print("[DUMMY] Dummy resized to %u bytes", new_packet_len);
    
    if(bpf_skb_change_tail(skb, new_packet_len, 0) < 0) {
        debug_print("[DUMMY] ERROR: Failed to change tail");
        return TC_ACT_SHOT;
    }

    for(__u16 i = 0; i < MAX_PKT_SIZE/4; i++) {
        if(i*4 >= payload_len)
            break;
        __u32 random_val = bpf_get_prandom_u32();
        if(bpf_skb_store_bytes(skb, ETH_HLEN + ip_header_len + tcp_header_len + i, &random_val, 4, 0) < 0) {
            debug_print("[DUMMY] ERROR: Failed to store zero byte at offset %u", i);
            return TC_ACT_SHOT;
        }
    }

    __u8 secret_key[32] = SECRET_KEY_DUMMY;
    
    __s8 hmac_result = add_hmac(skb, secret_key);
    if (hmac_result < 0) {
        debug_print("[EGRESS] Error in add_hmac, dropping packet");
        return TC_ACT_SHOT;
    }

    new_ip_len = new_packet_len - ETH_HLEN;
    
    if(update_ip_len_and_csum(skb, ip_header_len, old_ip_len, new_ip_len) < 0) {
        debug_print("[DUMMY] ERROR: Failed to update IP len and csum");
        return TC_ACT_SHOT;
    }
    
    __u8 flags;
    if (extract_tcp_flags(skb, ip_header_len, &flags) != 1) {
        debug_print("[DUMMY_CLONE] ERROR: Failed to extract TCP flags");
        return TC_ACT_SHOT;
    }
    reset_syn(&flags);
    reset_fin(&flags);
    reset_rst(&flags);
    if (replace_tcp_flags(skb, ip_header_len, flags) != 1) {
        debug_print("[DUMMY_CLONE] ERROR: Failed to replace TCP flags");
        return TC_ACT_SHOT;
    }

    skb_mark_set_checksum_flag(skb, 1);  // Checksum recalculation needed
        
    return 1; // Signal to continue with fragmentation
}

static __always_inline __u8 insert_dummy_packet_internal(struct __sk_buff *skb) {
    __u8 ip_header_len, tcp_header_len;
    
    __u8 result = extract_tcp_ip_header_lengths_simple(skb, &ip_header_len, &tcp_header_len);
    if(result != 1)
        return result;
    __u32 tcp_payload_offset = sizeof(struct ethhdr)
                             + (__u32)ip_header_len
                             + (__u32)tcp_header_len;
    __u16 payload_len = skb->len - tcp_payload_offset;
    #if DEBUG == 0
    if ((bpf_get_prandom_u32() % 100) > PROBABILITY_OF_DUMMY || payload_len < 32 || skb_mark_get_redirect_count(skb) > 8 ) {
        return 1; // No fragmentation for small payloads
    }
    #else
    __u8 skip_reason = 0; // 0=no skip, 1=small payload, 2=too many redirects, 3=probability
    if (payload_len < 32) {
        skip_reason = 1;
    } else if (skb_mark_get_redirect_count(skb) > 8) {
        skip_reason = 2;
    } else if ((bpf_get_prandom_u32() % 100) > PROBABILITY_OF_DUMMY) {
        skip_reason = 3;
    }
    
    if (skip_reason > 0) {
        if(skip_reason == 1) {
            bpf_printk("[DUMMY] Skip: payload troppo piccolo (%u bytes < 32)", payload_len);
        } else if(skip_reason == 2) {
            bpf_printk("[DUMMY] Skip: troppi redirect (%u > 8)", skb_mark_get_redirect_count(skb));
        } else if(skip_reason == 3) {
            bpf_printk("[DUMMY] Skip: controllo probabilità (payload=%u bytes)", payload_len);
        }
        return 1; // No fragmentation for small payloads
    }
    #endif
    // Calculate dummy packet size (minimum 64 bytes)
    u16 dummy_payload_len = (bpf_get_prandom_u32() % (MAX_PKT_SIZE - tcp_payload_offset - 64)) + 64; // size of the dummy payload
    debug_print("[DUMMY] Inserting dummy packet: dummy_payload=%u bytes", dummy_payload_len);
    skb_mark_increment_redirect_count(skb);
    skb_mark_set_len(skb, dummy_payload_len);
    skb_mark_set_type(skb, SKB_MARK_TYPE_DUMMY_CLONE);
    if (bpf_clone_redirect(skb, skb->ifindex, 0) < 0) {
        debug_print("[DUMMY] ERROR: Failed to clone packet at iteration");
        return TC_ACT_SHOT;
    }
    skb_mark_set_type(skb, SKB_MARK_TYPE_CLONED_FOR_DUMMY);
    return 1; // Signal to continue processing
}

#endif // DUMMY_H