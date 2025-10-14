// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "blake2s.h"
//#include <linux/bpf.h>
//#include <linux/if_ether.h>
//#include <linux/ip.h>
//#include <linux/tcp.h>
//#include <linux/udp.h>
//#include <linux/pkt_cls.h>
//#include <bpf/bpf_helpers.h>
//#include <bpf/bpf_endian.h>
//#include <stddef.h>
//#include "blake2s.h"

#define DEBUG 0

/* Debug configuration - define DEBUG to enable debug prints */
#if DEBUG
#define debug_print(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define debug_print(fmt, ...) do {} while (0)
#endif

#define MAX_PKT_SIZE 1500
#define FRAG_BUFF_MAX_SIZE 200
#define PROBABILITY_OF_FRAGMENTATION 30
#define PROBABILITY_OF_PADDING 30
/* Network protocol constants */
#define ETH_P_IP    0x0800
#define IPPROTO_TCP 6
#define ETH_HLEN    14
/* Traffic Control action codes */  
#define TC_ACT_OK   0
#define TC_ACT_SHOT 2

static const __u32 hash_len = 32;

/* Helper function to check if packet should be skipped */
static __always_inline __u8 should_skip_packet(struct __sk_buff *skb) {
    if (skb->gso_segs > 1) {
        return 1;
    }
    
    if (skb->len > MAX_PKT_SIZE) {
        return 1;
    }
    
    if (skb->gso_size > 0) {
        return 1;
    }
    
    return 0;
}

static __always_inline __u8 extract_from_packet(struct __sk_buff *skb, __u8 *ip_header_len, __u8 *tcp_header_len, __u16 *ip_tot_len) {
    __u8 l4_protocol;
    if(skb->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    if(bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, protocol), &l4_protocol, 1) < 0)
        return TC_ACT_SHOT;
    if (l4_protocol != IPPROTO_TCP)
        return TC_ACT_OK;
    if(bpf_skb_load_bytes(skb, sizeof(struct ethhdr), ip_header_len, sizeof(__u8)) < 0)
        return TC_ACT_SHOT;
    *ip_header_len = (*ip_header_len & 0x0F) * 4;
    debug_print("[EXTRACT] IP header length: %d bytes", *ip_header_len);
    if(bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, tot_len), ip_tot_len, sizeof(__u16)) < 0)
        return TC_ACT_SHOT;
    *ip_tot_len = bpf_ntohs(*ip_tot_len);
    debug_print("[EXTRACT] IP total length: %d bytes", *ip_tot_len);
    if(bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + *ip_header_len + 12, tcp_header_len, 1) < 0)
        return TC_ACT_SHOT;
    *tcp_header_len = (*tcp_header_len >> 4) * 4;
    debug_print("[EXTRACT] TCP header length: %d bytes", *tcp_header_len);
    return 1;
}

static __always_inline __u8 extract_from_packet1(struct __sk_buff *skb, __u8 *ip_header_len, __u8 *tcp_header_len) {
    __u8 l4_protocol;
    if(skb->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    if(bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, protocol), &l4_protocol, 1) < 0)
        return TC_ACT_SHOT;
    if (l4_protocol != IPPROTO_TCP)
        return TC_ACT_OK;
    if(bpf_skb_load_bytes(skb, sizeof(struct ethhdr), ip_header_len, sizeof(__u8)) < 0)
        return TC_ACT_SHOT;
    *ip_header_len = (*ip_header_len & 0x0F) * 4;
    debug_print("[EXTRACT] IP header length: %d bytes", *ip_header_len);
    if(bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + *ip_header_len + 12, tcp_header_len, 1) < 0)
        return TC_ACT_SHOT;
    *tcp_header_len = (*tcp_header_len >> 4) * 4;
    debug_print("[EXTRACT] TCP header length: %d bytes", *tcp_header_len);
    return 1;
}

/* Update IP and TCP checksums after packet length change */
static __always_inline __s8 update_len_and_checksums(struct __sk_buff *skb, __u8 ip_header_len, __u16 old_ip_len, __u16 new_ip_len, __wsum acc)
{
    __be16 new_ip_len_be = bpf_htons(new_ip_len);
    __be16 old_ip_len_be = bpf_htons(old_ip_len); 
    
    if (bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, tot_len),
                            &new_ip_len_be, sizeof(new_ip_len_be), 0) < 0)
        return -1;

    if (bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check),
                            old_ip_len_be, new_ip_len_be,
                            sizeof(__u16)) < 0)
        return -1;

    __u16 old_tcp_len = old_ip_len - ip_header_len;
    __u16 new_tcp_len = new_ip_len - ip_header_len;
    __be16 old_tcp_len_be = bpf_htons(old_tcp_len);
    __be16 new_tcp_len_be = bpf_htons(new_tcp_len);

    //__be16 tcp_csum_old_be;
    //if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + ip_header_len + offsetof(struct tcphdr, check), &tcp_csum_old_be, sizeof(tcp_csum_old_be)) < 0)
    //    return -1;

    if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + ip_header_len + offsetof(struct tcphdr, check),
                           old_tcp_len_be, new_tcp_len_be,
                           BPF_F_PSEUDO_HDR | sizeof(__u16)) < 0)
        return -1;
    
    if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + ip_header_len + offsetof(struct tcphdr, check),
                           0, acc, 0) < 0)
        return -1;
    
    return 0;
}

// Forward declarations for tail call map
SEC("classifier") int add_padding(struct __sk_buff *skb);
SEC("classifier") int fragment_packet(struct __sk_buff *skb);
SEC("classifier") int fragmentation_clone_to_packet(struct __sk_buff *skb);
SEC("classifier") int recompute_tcp_checksum(struct __sk_buff *skb);

// Tail call program array map
struct {
     __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
     __uint(key_size, sizeof(u32));
     __uint(max_entries, 4);
     __array(values, u32 (void *));
 } progs_eg SEC(".maps") = {
     .values = {
         [0] = (void *)&add_padding,
         [1] = (void *)&fragment_packet,
         [2] = (void *)&fragmentation_clone_to_packet,
         [3] = (void *)&recompute_tcp_checksum,
     },
 };



SEC("classifier")
int recompute_tcp_checksum(struct __sk_buff *skb) {

    __u8 ip_header_len, tcp_header_len;
    __u16 ip_total_len_old;
    __u8 extract_result = extract_from_packet(skb, &ip_header_len, &tcp_header_len, &ip_total_len_old);
    if(extract_result != 1)
        return extract_result;
    __wsum payload_csum = 0;
    __u8 buffer[FRAG_BUFF_MAX_SIZE];
    __u8 tcp_payload_offset = ETH_HLEN + ip_header_len + tcp_header_len;
    __u16 tcp_payload_len = skb->len - tcp_payload_offset; 
    __u32 bytes_remaining = tcp_payload_len;
    __u16 ip_total_len_new = skb->len - ETH_HLEN;
    debug_print("[RECOMPUTE_CSUM] IP total length: old=%u, new=%u", ip_total_len_old, ip_total_len_new);
    __be16 ip_total_len_new_be = bpf_htons(ip_total_len_new);
    __be16 ip_total_len_old_be = bpf_htons(ip_total_len_old);
    __sum16 old_tcp_check;
    if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + ip_header_len + offsetof(struct tcphdr, check), &old_tcp_check, sizeof(old_tcp_check)) < 0)
        return TC_ACT_SHOT;
    if (bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, tot_len),
                            &ip_total_len_new_be, sizeof(ip_total_len_new_be), 0) < 0)
        return TC_ACT_SHOT;
    if (bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check),
                            ip_total_len_old_be, ip_total_len_new_be,
                            sizeof(__u16)) < 0)
        return TC_ACT_SHOT;


   __u8 chunk;
    debug_print("[RECOMPUTE_CSUM] Starting payload checksum calculation, bytes_remaining=%u", bytes_remaining);
    for (chunk = 0; chunk < (MAX_PKT_SIZE / FRAG_BUFF_MAX_SIZE) + 1; chunk++) {
  
        if(bytes_remaining < FRAG_BUFF_MAX_SIZE) {
            debug_print("[RECOMPUTE_CSUM] Chunk %u: bytes_remaining < FRAG_BUFF_MAX_SIZE, breaking", chunk);
            break;
        }
        
        debug_print("[RECOMPUTE_CSUM] Processing chunk %u, bytes_remaining=%u", chunk, bytes_remaining);
        if (bpf_skb_load_bytes(skb, tcp_payload_offset + (chunk * FRAG_BUFF_MAX_SIZE), buffer, FRAG_BUFF_MAX_SIZE) < 0) {
            debug_print("[RECOMPUTE_CSUM] ERROR: Failed to load bytes for chunk %u", chunk);
            return TC_ACT_SHOT;
        }
        
        __s64 csum_result = bpf_csum_diff((__u32*)buffer, FRAG_BUFF_MAX_SIZE, NULL, 0, payload_csum);
        if (csum_result < 0) {
            debug_print("[RECOMPUTE_CSUM] ERROR: csum_diff failed for chunk %u", chunk);
            return TC_ACT_SHOT;
        }
        payload_csum = (__wsum)csum_result;
        bytes_remaining -= FRAG_BUFF_MAX_SIZE;

    }
    if(bytes_remaining > 0) {
        debug_print("[RECOMPUTE_CSUM] Processing remaining bytes: %u", bytes_remaining);
        __builtin_memset(buffer, 0, FRAG_BUFF_MAX_SIZE);
        /* Help the verifier understand the bounds */
        bytes_remaining &= 0xFF;
        if(bytes_remaining > FRAG_BUFF_MAX_SIZE || bytes_remaining == 0) {
            debug_print("[RECOMPUTE_CSUM] ERROR: Invalid bytes_remaining=%u after padding", bytes_remaining);
            return TC_ACT_SHOT;
        }
        
        if (bpf_skb_load_bytes(skb, tcp_payload_offset + (chunk * FRAG_BUFF_MAX_SIZE), buffer, bytes_remaining) < 0) {
            debug_print("[RECOMPUTE_CSUM] ERROR: Failed to load remaining bytes %d", bytes_remaining);
            return TC_ACT_SHOT;
        }

        bytes_remaining += (4 - (bytes_remaining % 4)) % 4;
        
        __s64 csum_result = bpf_csum_diff((__u32*)buffer, bytes_remaining, NULL, 0, payload_csum);
        if (csum_result < 0) {
            debug_print("[RECOMPUTE_CSUM] ERROR: csum_diff failed for remaining bytes %d", bytes_remaining);
            return TC_ACT_SHOT;
        }
        payload_csum = (__wsum)csum_result;

    }


    __u8 tcp_header_off = sizeof(struct ethhdr) + ip_header_len;

    debug_print("[RECOMPUTE_CSUM] Zeroing out checksum field");
    /* zero out checksum field */
    __u16 zero = 0;
    if(bpf_skb_store_bytes(skb, tcp_header_off + offsetof(struct tcphdr, check), &zero, sizeof(zero), 0) < 0) {
        debug_print("[RECOMPUTE_CSUM] ERROR: Failed to zero checksum field");
        return TC_ACT_SHOT;
    }

    ///* Safe: th_len is now proven 20..60 */
    extract_result = extract_from_packet1(skb, &ip_header_len, &tcp_header_len);
    if(extract_result != 1)
        return extract_result;
    if(tcp_header_len < 20 || tcp_header_len > 60) {
        debug_print("[RECOMPUTE_CSUM] ERROR: Invalid TCP header length: %u", tcp_header_len);
        return TC_ACT_SHOT;
    }
    
    debug_print("[RECOMPUTE_CSUM] TCP header length validated: %u", tcp_header_len);
    /* Store validated tcp_header_len in a register-backed variable */
    __u8 validated_tcp_len = tcp_header_len;
    
    /* Re-validate bounds for the verifier after loading from stack */
    if (validated_tcp_len < 20 || validated_tcp_len > 60) {
        debug_print("[RECOMPUTE_CSUM] ERROR: validated_tcp_len out of bounds");
        return TC_ACT_SHOT;
    }
    
    if (bpf_skb_load_bytes(skb, tcp_header_off, buffer, validated_tcp_len) < 0) {
        debug_print("[RECOMPUTE_CSUM] ERROR: Failed to load TCP header");
        return TC_ACT_SHOT;
    }

    __s64 t = bpf_csum_diff(NULL, 0, (__be32 *)buffer, validated_tcp_len, payload_csum);
    if (t < 0) {
        debug_print("[RECOMPUTE_CSUM] ERROR: csum_diff failed for TCP header");
        return TC_ACT_SHOT;
    }
    payload_csum = (__wsum)t;

    if (bpf_l4_csum_replace(skb, sizeof(struct ethhdr) + ip_header_len + offsetof(struct tcphdr, check),
                           0, payload_csum, 0) < 0) {
        debug_print("[RECOMPUTE_CSUM] ERROR: Failed to replace L4 checksum (first)");
        return TC_ACT_SHOT;
    }
    
    debug_print("[RECOMPUTE_CSUM] Adding pseudo-header contribution");
    /* add pseudo-header contribution to checksum */
    if (bpf_skb_load_bytes(skb,
            sizeof(struct ethhdr) + offsetof(struct iphdr, saddr),
            buffer, 8) < 0) {
        debug_print("[RECOMPUTE_CSUM] ERROR: Failed to load IP addresses");
        return -1;
    }
    
    buffer[8] = 0;
    buffer[9] = IPPROTO_TCP;
    /* Pseudo-header needs TOTAL TCP length (header + payload) */
    __u16 tcp_total_len = tcp_header_len + tcp_payload_len;
    __be16 tcp_total_len_be = bpf_htons(tcp_total_len);
    debug_print("[RECOMPUTE_CSUM] TCP total length for pseudo-header: %u", tcp_total_len);
    __builtin_memcpy(&buffer[10], &tcp_total_len_be, 2);    
    payload_csum = bpf_csum_diff(NULL, 0, (__be32 *)buffer, 12, 0);
    if (payload_csum < 0) {
        debug_print("[RECOMPUTE_CSUM] ERROR: csum_diff failed for pseudo-header");
        return TC_ACT_SHOT;
    }

    if (bpf_l4_csum_replace(skb, tcp_header_off + offsetof(struct tcphdr, check), 0, payload_csum, BPF_F_PSEUDO_HDR) < 0) {
        debug_print("[RECOMPUTE_CSUM] ERROR: Failed to replace L4 checksum (pseudo-header)");
        return TC_ACT_SHOT;
    }
    
    __sum16 new_tcp_check;
    if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + ip_header_len + offsetof(struct tcphdr, check), &new_tcp_check, sizeof(new_tcp_check)) < 0)
        return TC_ACT_SHOT;
    debug_print("[RECOMPUTE_CSUM] TCP checksum recomputed: old=0x%04x, new=0x%04x", bpf_ntohs(old_tcp_check), bpf_ntohs(new_tcp_check));
    return TC_ACT_OK;
}


SEC("classifier")
int fragmentation_clone_to_packet(struct __sk_buff *skb) {
    debug_print("[FRAG_CLONE] Entry: mark=%u, len=%u", skb->mark, skb->len);
    
    /* Fragment info from skb->mark */
    if(skb->mark <= 32)
        goto fragmentation;
    __u16 prev_payload_len = skb->mark & 0xFFFF;
    __u8 ip_header_len, tcp_header_len;
    __u16 ip_total_len;
    __u8 extract_result = extract_from_packet(skb, &ip_header_len, &tcp_header_len, &ip_total_len);
    if(extract_result != 1)
        return extract_result;
    
    debug_print("[FRAG_CLONE] Headers: ip_len=%u, tcp_len=%u", ip_header_len, tcp_header_len);
    
    /* Calculate packet structure offsets */
    __u8 tcp_payload_offset = sizeof(struct ethhdr) + ip_header_len + tcp_header_len;
    __u16 fragment_start = tcp_payload_offset + prev_payload_len;
    __u16 fragment_len = skb->len - fragment_start;
    
    debug_print("[FRAG_CLONE] prev_payload_len=%u, fragment_start=%u, fragment_len=%u", 
                prev_payload_len, fragment_start, fragment_len);
    
    /* Working variables */
    __u8 buffer[FRAG_BUFF_MAX_SIZE];

    /* copy fragment data into the right place */
    __u16 bytes_left = fragment_len;
    debug_print("[FRAG_CLONE] Starting copy: bytes_left=%u", bytes_left);
    
    for(__u8 i = 0; i < (MAX_PKT_SIZE / FRAG_BUFF_MAX_SIZE) + 1 > 0; i++) {
        __u32 chunk_size = bytes_left;
        if(chunk_size > FRAG_BUFF_MAX_SIZE)
            chunk_size = FRAG_BUFF_MAX_SIZE;

        if(chunk_size == 0)
            break;

        debug_print("[FRAG_CLONE] Chunk %u: size=%u, from=%u, to=%u", 
                    i, chunk_size, fragment_start + (i * FRAG_BUFF_MAX_SIZE), 
                    tcp_payload_offset + (i * FRAG_BUFF_MAX_SIZE));

        if(bpf_skb_load_bytes(skb, fragment_start + (i * FRAG_BUFF_MAX_SIZE), buffer, chunk_size) < 0) {
            debug_print("[FRAG_CLONE] ERROR: Failed to load bytes at chunk %u", i);
            return TC_ACT_SHOT;
        }
        
        if(bpf_skb_store_bytes(skb, tcp_payload_offset + (i * FRAG_BUFF_MAX_SIZE), buffer, chunk_size, 0) < 0) {
            debug_print("[FRAG_CLONE] ERROR: Failed to store bytes at chunk %u", i);
            return TC_ACT_SHOT;
        }

        bytes_left -= chunk_size;

    }

    /* update packet and IP lengths */
    __u16 new_packet_len = tcp_payload_offset + fragment_len;
    
    debug_print("[FRAG_CLONE] Resizing packet to %u bytes", new_packet_len);
    
    if(bpf_skb_change_tail(skb, new_packet_len, 0) < 0) {
        debug_print("[FRAG_CLONE] ERROR: Failed to change tail");
        return TC_ACT_SHOT;
    }
    
    /* Update TCP sequence number for this fragment */
    __be32 tcp_seq;
    if(bpf_skb_load_bytes(skb, ETH_HLEN + ip_header_len + offsetof(struct tcphdr, seq), 
                          &tcp_seq, sizeof(tcp_seq)) < 0) {
        debug_print("[FRAG_CLONE] ERROR: Failed to load TCP seq");
        return TC_ACT_SHOT;
    }
    
    __u32 new_seq = bpf_ntohl(tcp_seq) + prev_payload_len;
    __be32 new_seq_be = bpf_htonl(new_seq);
    
    if(bpf_skb_store_bytes(skb, ETH_HLEN + ip_header_len + offsetof(struct tcphdr, seq),
                           &new_seq_be, sizeof(new_seq_be), 0) < 0) {
        debug_print("[FRAG_CLONE] ERROR: Failed to store TCP seq");
        return TC_ACT_SHOT;
    }
    
    debug_print("[FRAG_CLONE] Updated TCP seq: old=%u, new=%u", bpf_ntohl(tcp_seq), new_seq);
    
    debug_print("[FRAG_CLONE] Success: packet resized, clearing mark");
    skb->mark = 1; // Clear mark after fragmentation
fragmentation:
    
    debug_print("[FRAG_CLONE] Tail call to fragment_packet");
    bpf_tail_call(skb, &progs_eg, 1); // add_padding
    return TC_ACT_OK;
}


SEC("classifier")
int fragment_packet(struct __sk_buff *skb) {
    __u8 ip_header_len, tcp_header_len;
    __u16 ip_total_len;
    
    debug_print("[FRAGMENT] Entry: len=%u, mark=%u", skb->len, skb->mark);
    
    __u8 extract_result = extract_from_packet(skb, &ip_header_len, &tcp_header_len, &ip_total_len);
    if(extract_result != 1)
        return extract_result;
    
    __u32 tcp_payload_offset = sizeof(struct ethhdr)
                             + (__u32)ip_header_len
                             + (__u32)tcp_header_len;
    __u16 payload_len = skb->len - tcp_payload_offset;
    
    debug_print("[FRAGMENT] Headers: ip_len=%u, tcp_len=%u, payload_len=%u", 
                ip_header_len, tcp_header_len, payload_len);
    
    __u8 i;
    // Fragment creation loop
    for (i = 0; i < 10; i++) {
        // Check if we should fragment
        if ((bpf_get_prandom_u32() % 100) > PROBABILITY_OF_FRAGMENTATION || payload_len < 64) {
            debug_print("[FRAGMENT] Stopping fragmentation at iteration %u (payload_len=%u)", i, payload_len);
            break; // No fragmentation for small payloads
        }
        // Calculate new fragment size (minimum 32 bytes)
        payload_len = (bpf_get_prandom_u32() % (payload_len - 32)) + 32; // size of the fragment payload
        
        debug_print("[FRAGMENT] Iteration %u: Creating fragment with payload_len=%u", i, payload_len);
        
        // Store fragment info and clone packet
        skb->mark = payload_len;
        if (bpf_clone_redirect(skb, skb->ifindex, 0) < 0) {
            debug_print("[FRAGMENT] ERROR: Failed to clone packet at iteration %u", i);
            return TC_ACT_SHOT;
        }
        
        debug_print("[FRAGMENT] Iteration %u: Clone successful, resizing original", i);
        
        if (bpf_skb_change_tail(skb, tcp_payload_offset + payload_len, 0) < 0) {
            debug_print("[FRAGMENT] ERROR: Failed to change tail at iteration %u", i);
            return TC_ACT_SHOT;
        }

    }
    if(i != 0) {
        debug_print("[FRAGMENT] Created %u fragments, setting mark=1", i);
        skb->mark = 1;
    } else {
        debug_print("[FRAGMENT] No fragments created");
    }

    debug_print("[FRAGMENT] Tail call to add_padding");
    bpf_tail_call(skb, &progs_eg, 0); // add_padding
    return TC_ACT_OK;
}


/* Add keyed BLAKE2s authentication tag to packet */
static __always_inline __s8 add_hmac(struct __sk_buff *skb, __u8 tcp_payload_offset, __u8 *secret_key) {
    __u32 new_len;
    __u32 digest[8];
    __u8 message[32];
    
    debug_print("[ADD_HMAC] Processing packet: len=%d, tcp_payload_offset=%d", skb->len, tcp_payload_offset);

    if (bpf_skb_load_bytes(skb, skb->len - hash_len, message, hash_len) < 0) {
        debug_print("[ADD_HMAC] Failed to load message bytes for HMAC calculation");
        return -1;
    }
    
    new_len = skb->len + hash_len;
    debug_print("[ADD_HMAC] Expanding packet from %d to %d bytes", skb->len, new_len);
    
    if (bpf_skb_change_tail(skb, new_len, 0) < 0) {
        debug_print("[ADD_HMAC] Failed to expand packet tail");
        return -1;
    }

    blake2sCompute(secret_key, message, digest);
    if (bpf_skb_store_bytes(skb, skb->len - hash_len, digest, hash_len, 0) < 0) {
        debug_print("[ADD_HMAC] Failed to store HMAC digest in packet");
        return -1;
    }
    return 1;
}

/* Remove and verify keyed BLAKE2s authentication tag */
static __always_inline __s8 remove_hmac(struct __sk_buff *skb, __u8 tcp_payload_offset, __u32 message_start_pos, __wsum *acc, __u8 *secret_key) {
    __u8 message[32];
    __u8 received_tag[32];
    __u32 calculated_digest[8];
    
    debug_print("[REMOVE_HMAC] Processing packet: len=%d, tcp_payload_offset=%d", skb->len, tcp_payload_offset);

    debug_print("[REMOVE_HMAC] HMAC message starts at position %d", message_start_pos);
    
    if (bpf_skb_load_bytes(skb, message_start_pos, message, 32) < 0) {
        debug_print("[REMOVE_HMAC] Failed to load HMAC message bytes");
        return -1;
    }

    if (bpf_skb_load_bytes(skb, message_start_pos + 32, received_tag, hash_len) < 0) {
        debug_print("[REMOVE_HMAC] Failed to load received HMAC tag");
        return -1;
    }
    
    blake2sCompute(secret_key, message, calculated_digest);
    
    if (memcmp(calculated_digest, received_tag, hash_len) != 0) {
        debug_print("[REMOVE_HMAC] HMAC verification failed - invalid tag");
        return 0;
    }

    __s64 t = bpf_csum_diff(calculated_digest, hash_len, NULL, 0, *acc);
    if (t < 0)
        return -1;
    *acc = (__wsum)t;
    
    debug_print("[REMOVE_HMAC] HMAC verified successfully, need to remove tag");
    return 1;
}

static __always_inline __s8 remove_all_padding(struct __sk_buff *skb, __u8 tcp_payload_offset, __u8 ip_header_len, __u16 ip_tot_old) {
    __u8 i;
    __wsum acc = 0;
    __s8 remove_result;
    __u8 secret_key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

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
    if (bpf_skb_change_tail(skb, skb->len - hash_len*i, 0) < 0) {
        debug_print("[REMOVE_HMAC] Failed to shrink packet after HMAC removal");
        return -1;
    }
    
    debug_print("[REMOVE_HMAC] HMAC successfully removed from packet");

    if (update_len_and_checksums(skb, ip_header_len, ip_tot_old, ip_tot_old - i*hash_len, acc) < 0) {
        debug_print("[INGRESS] Error updating checksums, dropping packet");
        return -1;
    }
    return 1;
}

SEC("classifier")
int add_padding(struct __sk_buff *skb) {
    if((bpf_get_prandom_u32() % 100) > PROBABILITY_OF_PADDING){
        goto checksum;
    }
    __s8 hmac_result;
    __u8 i, tcp_payload_offset, ip_header_len, tcp_header_len;
    __u16 ip_tot_old;
    __u8 random_val = bpf_get_prandom_u32() % 11;
    __u8 secret_key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    __u8 extract_result = extract_from_packet(skb, &ip_header_len, &tcp_header_len, &ip_tot_old);
    if (extract_result != 1) {
        debug_print("[EGRESS] Non-TCP/IP packet or extraction error, skipping HMAC addition");
        return extract_result;
    }
    tcp_payload_offset = sizeof(struct ethhdr) + ip_header_len + tcp_header_len;
    debug_print("[EGRESS] Random HMAC count: %d", random_val);
    if(skb->len < tcp_payload_offset + hash_len) {
        debug_print("[EGRESS] Packet too small for HMAC addition, returning 0");
        return TC_ACT_OK;
    }
    for (i = 0; i < 10; i++) {
        if (i >= random_val) {
            debug_print("[EGRESS] Stopping at iteration %d (reached random limit %d)", i, random_val);
            break;
        }
        if (skb->len + hash_len > MAX_PKT_SIZE) {
            debug_print("[EGRESS] Cannot add mosudo apt install tmux -yre HMACs, packet size limit reached");
            break;
        }
        debug_print("[EGRESS] Adding HMAC iteration %d", i);
        hmac_result = add_hmac(skb, tcp_payload_offset, secret_key);
        debug_print("[EGRESS] add_hmac result: %d", hmac_result);
        if (hmac_result < 0) {
            debug_print("[EGRESS] Error in add_hmac, dropping packet");
            return TC_ACT_SHOT;
        }
        if (hmac_result == 0) {
            debug_print("[EGRESS] Cannot add more HMACs, stopping");
            break;
        }
    }
    
    if(i == 0) {
        debug_print("[EGRESS] No HMACs added to packet");
        return TC_ACT_OK;
    }

    skb->mark = 1;
checksum: 
    if (skb->mark == 1)
        bpf_tail_call(skb, &progs_eg, 3); // fragmentation_clone_to_packet

    return TC_ACT_OK;

}


SEC("classifier")
int handle_ingress(struct __sk_buff *skb) {
    __u16 ip_tot_old;
    __u8 ip_header_len, tcp_header_len;
    
    bpf_printk("Packet received: len=%d", skb->len);
    
    debug_print("[INGRESS] Packet received: len=%d", skb->len);
    
    if (should_skip_packet(skb)) {
        debug_print("[INGRESS] Packet skipped (GSO or oversized)");
        return TC_ACT_OK;
    }

    __u8 extract_result = extract_from_packet(skb, &ip_header_len, &tcp_header_len, &ip_tot_old);
    if(extract_result != 1) {
        debug_print("[INGRESS] Non-TCP/IP packet or extraction error, skipping HMAC removal");
        return extract_result;
    }

    debug_print("[INGRESS] IP packet: total_len=%d, header_len=%d", ip_tot_old, ip_header_len);

    if (remove_all_padding(skb, tcp_header_len + ip_header_len + sizeof(struct ethhdr), ip_header_len, ip_tot_old) < 0) {
        debug_print("[INGRESS] Error removing padding, dropping packet");
        return TC_ACT_SHOT;
    }
    debug_print("[INGRESS] Packet processing successful");

    return TC_ACT_OK;
}


SEC("classifier")
int handle_egress(struct __sk_buff *skb) {
    
    if(skb->mark == 0)
        bpf_printk("Sending packet: len=%d", skb->len);
    debug_print("[EGRESS] Packet received: len=%d", skb->len);
    //int res = recompute_tcp_checksum_and_print(skb);
    //if (res != 3) {
    //    return res;
    //}
    
    if (should_skip_packet(skb)) {
        debug_print("[EGRESS] Packet skipped (GSO or oversized)");
        return TC_ACT_OK;
    }

    bpf_tail_call(skb, &progs_eg, 2); // add_padding

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
