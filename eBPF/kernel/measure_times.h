
#ifndef __MEASURE_TIMES_H
#define __MEASURE_TIMES_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct measure_state {
    __u64 start_ns;
    __u64 acc_ns;
};

/* Versione reale: crea mappe + funzioni */
#define MEASURE_DECLARE(prefix, RB_SIZE)                                      \
struct {                                                                      \
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);                                  \
    __uint(max_entries, 1);                                                  \
    __type(key, __u32);                                                      \
    __type(value, struct measure_state);                                     \
} prefix##_state_map SEC(".maps");                                           \
                                                                             \
struct {                                                                      \
    __uint(type, BPF_MAP_TYPE_RINGBUF);                                       \
    __uint(max_entries, RB_SIZE);                                            \
} prefix##_events SEC(".maps");                                              \
                                                                             \
static __always_inline struct measure_state *__##prefix##_get_state(void)    \
{                                                                            \
    __u32 key = 0;                                                           \
    return bpf_map_lookup_elem(&prefix##_state_map, &key);                   \
}                                                                            \
                                                                             \
static __always_inline void __##prefix##_reset_state(struct measure_state *st)\
{                                                                            \
    st->start_ns = 0;                                                        \
    st->acc_ns   = 0;                                                        \
}                                                                            \
                                                                             \
/* API: annulla la misura attuale senza inserirla */                         \
static __always_inline void prefix##_reset_measure(void)                     \
{                                                                            \
    struct measure_state *st = __##prefix##_get_state();                     \
    if (!st) {                                                               \
        bpf_printk("measure[" #prefix "]: state lookup failed in reset\\n"); \
        return;                                                              \
    }                                                                        \
    __##prefix##_reset_state(st);                                            \
}                                                                            \
                                                                             \
/* Inizia una NUOVA misurazione */                                           \
static __always_inline void prefix##_start_measure(void)                     \
{                                                                            \
    __u64 now = bpf_ktime_get_ns();                                          \
                                                                             \
    struct measure_state *st = __##prefix##_get_state();                     \
    if (!st) {                                                               \
        bpf_printk("measure[" #prefix "]: state lookup failed in start\\n"); \
        return;                                                              \
    }                                                                        \
                                                                             \
    __##prefix##_reset_state(st);                                            \
    st->start_ns = now;                                                      \
}                                                                            \
                                                                             \
/* Pausa la misura (chiude segmento attivo) */                               \
static __always_inline void prefix##_stop_measure(void)                      \
{                                                                            \
    __u64 now = bpf_ktime_get_ns();                                          \
                                                                             \
    struct measure_state *st = __##prefix##_get_state();                     \
    if (!st) {                                                               \
        bpf_printk("measure[" #prefix "]: state lookup failed in stop\\n");  \
        return;                                                              \
    }                                                                        \
    if (!st->start_ns) {                                                     \
        bpf_printk("measure[" #prefix "]: stop without active segment\\n");  \
        return;                                                              \
    }                                                                        \
                                                                             \
    st->acc_ns  += now - st->start_ns;                                       \
    st->start_ns = 0;                                                        \
}                                                                            \
                                                                             \
/* Riprende la misura (apre nuovo segmento se era fermo) */                  \
static __always_inline void prefix##_resume_measure(void)                    \
{                                                                            \
    __u64 now = bpf_ktime_get_ns();                                          \
                                                                             \
    struct measure_state *st = __##prefix##_get_state();                     \
    if (!st) {                                                               \
        bpf_printk("measure[" #prefix "]: state lookup failed in resume\\n");\
        return;                                                              \
    }                                                                        \
    if (st->start_ns) {                                                      \
        bpf_printk("measure[" #prefix "]: resume while active\\n");          \
        return;                                                              \
    }                                                                        \
                                                                             \
    st->start_ns = now;                                                      \
}                                                                            \
                                                                             \
/* Termina la misura e manda un __u64 (delta_ns) in ringbuf */               \
static __always_inline void prefix##_end_measure(void)                       \
{                                                                            \
    __u64 now = bpf_ktime_get_ns();                                          \
                                                                             \
    struct measure_state *st = __##prefix##_get_state();                     \
    if (!st) {                                                               \
        bpf_printk("measure[" #prefix "]: state lookup failed in end\\n");   \
        return;                                                              \
    }                                                                        \
                                                                             \
    if (st->start_ns) {                                                      \
        st->acc_ns  += now - st->start_ns;                                   \
        st->start_ns = 0;                                                    \
    }                                                                        \
                                                                             \
    __u64 total = st->acc_ns;                                                \
    __##prefix##_reset_state(st);                                            \
                                                                             \
    if (!total) {                                                            \
        bpf_printk("measure[" #prefix "]: end with zero total_ns\\n");       \
        return;                                                              \
    }                                                                        \
                                                                             \
    __u64 *val = bpf_ringbuf_reserve(&prefix##_events, sizeof(__u64), 0);    \
    if (!val) {                                                              \
        bpf_printk("measure[" #prefix "]: ringbuf_reserve failed\\n");       \
        return;                                                              \
    }                                                                        \
    *val = total;                                                            \
    bpf_ringbuf_submit(val, 0);                                              \
}


/* Versione placeholder: API esposta ma tutta no-op */
#define MEASURE_DECLARE_PLACEHOLDER(prefix, RB_SIZE)                          \
static __always_inline struct measure_state *__##prefix##_get_state(void)    \
{                                                                            \
    return NULL;                                                             \
}                                                                            \
                                                                             \
static __always_inline void __##prefix##_reset_state(struct measure_state *st)\
{                                                                            \
    (void)st;                                                                \
}                                                                            \
                                                                             \
static __always_inline void prefix##_reset_measure(void)                     \
{                                                                            \
    /* misurazione disabilitata */                                           \
}                                                                            \
                                                                             \
static __always_inline void prefix##_start_measure(void)                     \
{                                                                            \
    /* misurazione disabilitata */                                           \
}                                                                            \
                                                                             \
static __always_inline void prefix##_stop_measure(void)                      \
{                                                                            \
    /* misurazione disabilitata */                                           \
}                                                                            \
                                                                             \
static __always_inline void prefix##_resume_measure(void)                    \
{                                                                            \
    /* misurazione disabilitata */                                           \
}                                                                            \
                                                                             \
static __always_inline void prefix##_end_measure(void)                       \
{                                                                            \
    /* misurazione disabilitata */                                           \
}

/* Alias for delay measurements */
#define DELAY_MEASURE_DECLARE_REAL(prefix, RB_SIZE) MEASURE_DECLARE(prefix, RB_SIZE)
#define DELAY_MEASURE_DECLARE_PLACEHOLDER(prefix, RB_SIZE) MEASURE_DECLARE_PLACEHOLDER(prefix, RB_SIZE)

#endif /* __MEASURE_TIMES_H */
