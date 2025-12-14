#ifndef __CONSTS_H
#define __CONSTS_H
/* Network protocol constants */
#define ETH_P_IP    0x0800
#define IPPROTO_TCP 6
#define ETH_HLEN    14

/* Traffic Control action codes */  
#define TC_ACT_OK   0
#define TC_ACT_SHOT 2
#define TC_ACT_REDIRECT 7

/* Skb mark types */
enum skb_mark_type {
    SKB_MARK_TYPE_NONE = 0,
    SKB_MARK_TYPE_FRAGMENT_CLONE = 1,
    SKB_MARK_TYPE_FRAGMENTED = 2,
    SKB_MARK_TYPE_DUMMY_CLONE = 3,
    SKB_MARK_TYPE_CLONED_FOR_DUMMY = 4,
    SKB_MARK_TYPE_DUMMY = 5,
};
/* BLAKE2s authentication tag size */

#define HASH_LEN 32

#endif