#ifndef __PADDING_H
#define __PADDING_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "config.h"
#include "network_utils.h"
#include "checksum.h"
#include "hmac.h"

/* Remove all padding HMACs from packet */
static __always_inline __s8 remove_all_padding(struct __sk_buff *skb, __u8 tcp_payload_offset, __u8 ip_header_len, __u16 ip_tot_old) {
    __u8 i;
    __wsum acc = 0;
    __s8 remove_result;
    __u8 secret_key[32] = SECRET_KEY_INIT;

    for (i = 0; i < 10; i++) {
        debug_print("[INGRESS] HMAC removal loop iteration %d", i);
        __s32 message_start_pos = skb->len - (32 * (i + 2));
        if (message_start_pos < tcp_payload_offset) {
            debug_print("[INGRESS] Invalid HMAC removal position");
            break;
        }
        remove_result = remove_hmac(skb, tcp_payload_offset, message_start_pos, &acc, secret_key);
        debug_print("[INGRESS] remove_hmac result: %d", remove_result);
        
        if (remove_result < 0) {
            debug_print("[INGRESS] Error in remove_hmac, dropping packet");
            return -1;
        }

        if (remove_result == 0) {
            break;
        }
    }

    debug_print("[INGRESS] HMAC processing complete, updating checksums");
    if(i == 0) {
        debug_print("[INGRESS] No HMACs found to remove, packet unchanged");
        return 0;
    }
    if (bpf_skb_change_tail(skb, skb->len - HASH_LEN*i, 0) < 0) {
        debug_print("[REMOVE_HMAC] Failed to shrink packet after HMAC removal");
        return -1;
    }
    
    debug_print("[REMOVE_HMAC] HMAC successfully removed from packet");

    if (update_len_and_checksums(skb, ip_header_len, ip_tot_old, ip_tot_old - i*HASH_LEN, acc) < 0) {
        debug_print("[INGRESS] Error updating checksums, dropping packet");
        return -1;
    }
    return 1;
}

#endif // __PADDING_H
