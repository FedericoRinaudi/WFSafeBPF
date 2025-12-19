#ifndef __HMAC_H
#define __HMAC_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "config.h"
#include "consts.h"
#include "blake2s.h"
#include "checksum.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} events SEC(".maps");

/* Add keyed BLAKE2s authentication tag to packet */
static __always_inline __s8 add_hmac(struct __sk_buff *skb, __u8 *secret_key, __u8 i) {
    __u32 digest[8];
    __u8 message[32];

    if (bpf_skb_load_bytes(skb, skb->len - HASH_LEN*2, message, HASH_LEN) < 0) {
        debug_print("[ADD_HMAC] Failed to load message bytes for HMAC calculation");
        return -1;
    }
    __u64 measure_start = bpf_ktime_get_ns();
    blake2sCompute(secret_key, message, digest);
    __u64 duration = bpf_ktime_get_ns() - measure_start;
    __u64 *val = bpf_ringbuf_reserve(&events, sizeof(__u64) * 2, 0);
    if (!val) {                                                              
         bpf_printk("ringbuf_reserve failed\\n");       
         return -1;                                                              
    }                                                                        
    val[0] = (__u64)i;
    val[1] = duration;
    bpf_ringbuf_submit(val, 0);  
    if (bpf_skb_store_bytes(skb, skb->len - HASH_LEN, digest, HASH_LEN, 0) < 0) {
        debug_print("[ADD_HMAC] Failed to store HMAC digest in packet");
        return -1;
    }
    return 1;
}

/* Remove and verify keyed BLAKE2s authentication tag */
static __always_inline __s8 remove_hmac(struct __sk_buff *skb, __u32 message_start_pos, __u8 *secret_key) {
    __u8 message[32];
    __u8 received_tag[32];
    __u32 calculated_digest[8];
    
    if (bpf_skb_load_bytes(skb, message_start_pos, message, 32) < 0) {
        debug_print("[REMOVE_HMAC] Failed to load HMAC message bytes");
        return -1;
    }

    if (bpf_skb_load_bytes(skb, message_start_pos + 32, received_tag, HASH_LEN) < 0) {
        debug_print("[REMOVE_HMAC] Failed to load received HMAC tag");
        return -1;
    }
    
    blake2sCompute(secret_key, message, calculated_digest);
    
    if (memcmp(calculated_digest, received_tag, HASH_LEN) != 0) {
        //debug_print("[REMOVE_HMAC] HMAC verification failed - invalid tag");
        return 0;
    }
    
    return 1;
}

#endif // __HMAC_H
