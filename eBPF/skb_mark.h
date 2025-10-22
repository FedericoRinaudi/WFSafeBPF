#ifndef __SKB_MARK_H
#define __SKB_MARK_H

#include "vmlinux.h"

/*
 * skb->mark encoding (32 bits total):
 * 
 * Bit layout:
 * [31-16] frag_payload_len (16 bits)    - Length of payload fragment for cloning
 * [15-8]  checksum_flag (8 bits)        - Flag: 1 = recalculate checksum, 0 = no recalculation
 * [7-0]   redirect_count (8 bits)       - Number of redirects performed on this packet
 *
 * Example: 0x01234501
 *          ││││││└┴─ redirect_count = 0x01 (1)
 *          ││││└┴─── checksum_flag = 0x45 (69)
 *          └┴┴┴───── frag_payload_len = 0x0123 (291)
 */

/* Bit masks and shifts */
#define SKB_MARK_REDIRECT_COUNT_MASK      0x000000FF
#define SKB_MARK_REDIRECT_COUNT_SHIFT     0

#define SKB_MARK_CHECKSUM_FLAG_MASK       0x0000FF00
#define SKB_MARK_CHECKSUM_FLAG_SHIFT      8

#define SKB_MARK_FRAG_PAYLOAD_MASK        0xFFFF0000
#define SKB_MARK_FRAG_PAYLOAD_SHIFT       16

/* Getter functions */
static __always_inline __u8 skb_mark_get_redirect_count(struct __sk_buff *skb) {
    return (__u8)((skb->mark & SKB_MARK_REDIRECT_COUNT_MASK) >> SKB_MARK_REDIRECT_COUNT_SHIFT);
}

static __always_inline __u8 skb_mark_get_checksum_flag(struct __sk_buff *skb) {
    return (__u8)((skb->mark & SKB_MARK_CHECKSUM_FLAG_MASK) >> SKB_MARK_CHECKSUM_FLAG_SHIFT);
}

static __always_inline __u16 skb_mark_get_frag_payload_len(struct __sk_buff *skb) {
    return (__u16)((skb->mark & SKB_MARK_FRAG_PAYLOAD_MASK) >> SKB_MARK_FRAG_PAYLOAD_SHIFT);
}

/* Setter functions - set individual fields */
static __always_inline void skb_mark_set_redirect_count(struct __sk_buff *skb, __u8 redirect_count) {
    //__u32 old_mark = skb->mark;
    volatile __u32 new_mark = (skb->mark & ~SKB_MARK_REDIRECT_COUNT_MASK) | 
            (((__u32)redirect_count << SKB_MARK_REDIRECT_COUNT_SHIFT) & SKB_MARK_REDIRECT_COUNT_MASK);
    skb->mark = new_mark;
    //bpf_printk("[SKB_MARK] set_redirect_count: old_mark=0x%x, new_mark=0x%x, redirect_count=%u", old_mark, new_mark, redirect_count);
}

static __always_inline void skb_mark_set_checksum_flag(struct __sk_buff *skb, __u8 checksum_flag) {
    //__u32 old_mark = skb->mark;
    volatile __u32 new_mark = (skb->mark & ~SKB_MARK_CHECKSUM_FLAG_MASK) | 
            (((__u32)checksum_flag << SKB_MARK_CHECKSUM_FLAG_SHIFT) & SKB_MARK_CHECKSUM_FLAG_MASK);
    skb->mark = new_mark;
    //bpf_printk("[SKB_MARK] set_checksum_flag: old_mark=0x%x, new_mark=0x%x, checksum_flag=%u", old_mark, new_mark, checksum_flag);
}

static __always_inline void skb_mark_set_frag_payload_len(struct __sk_buff *skb, __u16 payload_len) {
    //__u32 old_mark = skb->mark;
    volatile __u32 new_mark = (skb->mark & ~SKB_MARK_FRAG_PAYLOAD_MASK) | 
            (((__u32)payload_len << SKB_MARK_FRAG_PAYLOAD_SHIFT) & SKB_MARK_FRAG_PAYLOAD_MASK);
    skb->mark = new_mark;
    //bpf_printk("[SKB_MARK] set_frag_payload_len: old_mark=0x%x, new_mark=0x%x, payload_len=%u", old_mark, new_mark, payload_len);
}

/* Increment redirect count */
static __always_inline void skb_mark_increment_redirect_count(struct __sk_buff *skb) {
    __u8 current = skb_mark_get_redirect_count(skb);
    skb_mark_set_redirect_count(skb, current + 1);
}

/* Reset all mark fields to 0 */
static __always_inline void skb_mark_reset(struct __sk_buff *skb) {
    //__u32 old_mark = skb->mark;
    skb->mark = 0;
    //bpf_printk("[SKB_MARK] reset: old_mark=0x%x, new_mark=0x0", old_mark);
}

/* Build mark from components */
static __always_inline __u32 skb_mark_build(__u16 frag_payload, __u8 checksum_flag, __u8 redirect_count) {
    return (((__u32)frag_payload << SKB_MARK_FRAG_PAYLOAD_SHIFT) & SKB_MARK_FRAG_PAYLOAD_MASK) |
           (((__u32)checksum_flag << SKB_MARK_CHECKSUM_FLAG_SHIFT) & SKB_MARK_CHECKSUM_FLAG_MASK) |
           (((__u32)redirect_count << SKB_MARK_REDIRECT_COUNT_SHIFT) & SKB_MARK_REDIRECT_COUNT_MASK);
}

#endif // __SKB_MARK_H
