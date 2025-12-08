#ifndef __CLIENT_CONFIG_H
#define __CLIENT_CONFIG_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "config.h"

/* Structure to hold client configuration including keys and probabilities */
struct client_config {
    __u8 padding_key[32];
    __u8 dummy_key[32];
    __u64 expiration_time;  // Unix timestamp in seconds when config expires
    __u8 padding_probability;  // Probability (0-100) of applying padding
    __u8 dummy_probability;    // Probability (0-100) of inserting dummy packets
    __u8 fragmentation_probability;  // Probability (0-100) of fragmenting packets
};

/* Key structure for client config map (IP address + server port) */
struct client_config_key {
    __u32 ip_addr;      // IP address
    __u16 server_port;  // Server port
};

/* Map for client configurations indexed by IP address and server port */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct client_config_key);
    __type(value, struct client_config);
    __uint(max_entries, 1024);
} client_config_map SEC(".maps");

/* Get padding key and probability for given IP address and server port */
static __always_inline struct client_config* get_padding_key(__u32 ip_addr, __u16 server_port) {
    struct client_config_key key = {};
    key.ip_addr = ip_addr;
    key.server_port = server_port;
    struct client_config *config = bpf_map_lookup_elem(&client_config_map, &key);
    if (!config) {
        debug_print("[CLIENT_CONFIG] No config found for IP:port (padding) for ip 0x%x:%u", ip_addr, server_port);
        return NULL;
    }
    return config;
}

/* Get dummy key and probability for given IP address and server port */
static __always_inline struct client_config* get_dummy_key(__u32 ip_addr, __u16 server_port) {
    struct client_config_key key = {};
    key.ip_addr = ip_addr;
    key.server_port = server_port;
    struct client_config *config = bpf_map_lookup_elem(&client_config_map, &key);
    if (!config) {
        debug_print("[CLIENT_CONFIG] No config found for IP:port (dummy) for ip 0x%x:%u", ip_addr, server_port);
        return NULL;
    }
    return config;
}


/* Check if IP address and server port have configuration */
static __always_inline int has_client_config(__u32 ip_addr, __u16 server_port) {
    struct client_config_key key = {};
    key.ip_addr = ip_addr;
    key.server_port = server_port;
    struct client_config *config = bpf_map_lookup_elem(&client_config_map, &key);
    return config != NULL;
}

/* Get fragmentation probability for given IP address and server port */
static __always_inline struct client_config* get_fragmentation_probability(__u32 ip_addr, __u16 server_port) {
    struct client_config_key key = {};
    key.ip_addr = ip_addr;
    key.server_port = server_port;
    struct client_config *config = bpf_map_lookup_elem(&client_config_map, &key);
    if (!config) {
        debug_print("[CLIENT_CONFIG] No config found for IP:port (fragmentation) for ip 0x%x:%u", ip_addr, server_port);
        return NULL;
    }
    return config;
}

#endif // __CLIENT_CONFIG_H
