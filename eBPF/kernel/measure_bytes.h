#ifndef __BYTES_MEASURE_BPF_H
#define __BYTES_MEASURE_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/*
 * Macro che dichiara:
 * - <prefix>_bytes_counter_map : PERCPU_ARRAY[1] con __u64
 * - <prefix>_bytes_events      : RINGBUF che contiene __u64 (byte_totali)
 * - <prefix>_* funzioni        : add/reset/flush
 */

#define BYTES_MEASURE_DECLARE_REAL(prefix, RB_SIZE)                                   \
struct {                                                                              \
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);                                          \
    __uint(max_entries, 1);                                                          \
    __type(key, __u32);                                                              \
    __type(value, __u64);                                                            \
} prefix##_bytes_counter_map SEC(".maps");                                           \
                                                                                     \
struct {                                                                              \
    __uint(type, BPF_MAP_TYPE_RINGBUF);                                               \
    __uint(max_entries, RB_SIZE);                                                    \
} prefix##_bytes_events SEC(".maps");                                                \
                                                                                     \
static __always_inline __u64 *prefix##_bytes_get_counter(void)                       \
{                                                                                    \
    __u32 key = 0;                                                                   \
    return bpf_map_lookup_elem(&prefix##_bytes_counter_map, &key);                  \
}                                                                                    \
                                                                                     \
static __always_inline void prefix##_bytes_reset(void)                               \
{                                                                                    \
    __u64 *cnt = prefix##_bytes_get_counter();                                       \
    if (!cnt) {                                                                      \
        bpf_printk("bytes[" #prefix "]: state lookup failed in reset\\n");           \
        return;                                                                      \
    }                                                                                \
    *cnt = 0;                                                                        \
}                                                                                    \
                                                                                     \
/* Aggiunge "len" byte al contatore */                                               \
static __always_inline void prefix##_bytes_add(__u64 len)                            \
{                                                                                    \
    __u64 *cnt = prefix##_bytes_get_counter();                                       \
    if (!cnt) {                                                                      \
        bpf_printk("bytes[" #prefix "]: state lookup failed in add\\n");             \
        return;                                                                      \
    }                                                                                \
    *cnt += len;                                                                     \
}                                                                                    \
                                                                                     \
/* Emaggia il totale su ringbuf e azzera il contatore */                             \
static __always_inline void prefix##_bytes_flush(void)                               \
{                                                                                    \
    __u64 *cnt = prefix##_bytes_get_counter();                                       \
    if (!cnt) {                                                                      \
        bpf_printk("bytes[" #prefix "]: state lookup failed in flush\\n");           \
        return;                                                                      \
    }                                                                                \
                                                                                     \
    __u64 total = *cnt;                                                              \
    *cnt = 0;                                                                        \
                                                                                     \
    if (!total) {                                                                    \
        /* flush senza aver contato nulla */                                         \
        bpf_printk("bytes[" #prefix "]: flush with zero total_bytes\\n");            \
        return;                                                                      \
    }                                                                                \
                                                                                     \
    __u64 *val = bpf_ringbuf_reserve(&prefix##_bytes_events, sizeof(__u64), 0);      \
    if (!val) {                                                                      \
        bpf_printk("bytes[" #prefix "]: ringbuf_reserve failed\\n");                 \
        return;                                                                      \
    }                                                                                \
    *val = total;                                                                    \
    bpf_ringbuf_submit(val, 0);                                                      \
}


/* versione placeholder (no-op) */

#define BYTES_MEASURE_DECLARE_PLACEHOLDER(prefix, RB_SIZE)                           \
static __always_inline __u64 *prefix##_bytes_get_counter(void)                       \
{                                                                                    \
    return NULL;                                                                     \
}                                                                                    \
                                                                                     \
static __always_inline void prefix##_bytes_reset(void)                               \
{                                                                                    \
}                                                                                    \
                                                                                     \
static __always_inline void prefix##_bytes_add(__u64 len)                            \
{                                                                                    \
    (void)len;                                                                       \
}                                                                                    \
                                                                                     \
static __always_inline void prefix##_bytes_flush(void)                               \
{                                                                                    \
}

#endif /* __BYTES_MEASURE_BPF_H */
