#ifndef __CONFIG_H
#define __CONFIG_H

/* Debug configuration - define DEBUG to enable debug prints */
#define DEBUG 0

#if DEBUG
#define debug_print(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define debug_print(fmt, ...) do {} while (0)
#endif

/* Packet size limits */
#define MAX_PKT_SIZE 1500
#define FRAG_BUFF_MAX_SIZE 200

/* Probability thresholds (0-100) */
#define PROBABILITY_OF_FRAGMENTATION 30
#define PROBABILITY_OF_PADDING 30

/* Network protocol constants */
#define ETH_P_IP    0x0800
#define IPPROTO_TCP 6
#define ETH_HLEN    14

/* Traffic Control action codes */  
#define TC_ACT_OK   0
#define TC_ACT_SHOT 2

/* BLAKE2s authentication tag size */
#define HASH_LEN 32

/* Secret key for HMAC (BLAKE2s) */
#define SECRET_KEY_INIT { \
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, \
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, \
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, \
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F  \
}

#endif // __CONFIG_H
