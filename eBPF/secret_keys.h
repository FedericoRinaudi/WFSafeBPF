#ifndef __SECRET_KEYS_H
#define __SECRET_KEYS_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "config.h"

/* Structure to hold secret keys for padding and dummy */
struct secret_keys {
    __u8 padding_key[32];
    __u8 dummy_key[32];
    __u64 expiration_time;  // Unix timestamp in seconds when keys expire
};

/* Key structure for secret keys map (IP address + server port) */
struct secret_keys_key {
    __u32 ip_addr;      // IP address
    __u16 server_port;  // Server port
};

/* Map for secret keys indexed by IP address and server port */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct secret_keys_key);
    __type(value, struct secret_keys);
    __uint(max_entries, 1024);
} secret_keys_map SEC(".maps");

/* Get padding key for given IP address and server port */
static __always_inline __u8* get_padding_key(__u32 ip_addr, __u16 server_port) {
    struct secret_keys_key key = {};
    key.ip_addr = ip_addr;
    key.server_port = server_port;
    struct secret_keys *keys = bpf_map_lookup_elem(&secret_keys_map, &key);
    if (!keys) {
        debug_print("[SECRET_KEYS] No keys found for IP:port a for ip 0x%x:%u", ip_addr, server_port);
        return NULL;
    }
    return keys->padding_key;
}

/* Get dummy key for given IP address and server port */
static __always_inline __u8* get_dummy_key(__u32 ip_addr, __u16 server_port) {
    struct secret_keys_key key = {};
    key.ip_addr = ip_addr;
    key.server_port = server_port;
    struct secret_keys *keys = bpf_map_lookup_elem(&secret_keys_map, &key);
    if (!keys) {
        debug_print("[SECRET_KEYS] No keys found for IP:port b for ip 0x%x:%u", ip_addr, server_port);
        return NULL;
    }
    return keys->dummy_key;
}


/* Check if IP address and server port have keys configured */
static __always_inline int has_secret_keys(__u32 ip_addr, __u16 server_port) {
    struct secret_keys_key key = {};
    key.ip_addr = ip_addr;
    key.server_port = server_port;
    struct secret_keys *keys = bpf_map_lookup_elem(&secret_keys_map, &key);
    return keys != NULL;
}

#endif // __SECRET_KEYS_H
