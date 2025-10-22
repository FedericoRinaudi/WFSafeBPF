// SPDX-License-Identifier: GPL-2.0
#ifndef __SEQ_NUM_TRANSLATION_H
#define __SEQ_NUM_TRANSLATION_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "network_utils.h"
#include "checksum.h"
#include "skb_mark.h"

/* Maximum   for flow tracking and seq_num translations */
#define MAX_FLOWS 100000



struct map_key {
    struct flow_info flow;
    __u32 seq;
};

struct map_value {
    __u32 translated_seq;
    __u32 prev_seq;
    __u64 timestamp_ns;
};

/* Macro per definire mappe BPF hash */
#define DEFINE_TRANSLATION_HASH_MAP(map_name) \
    struct { \
        __uint(type, BPF_MAP_TYPE_HASH); \
        __uint(key_size, sizeof(struct map_key)); \
        __uint(value_size, sizeof(struct map_value)); \
        __uint(max_entries, MAX_FLOWS); \
    } map_name SEC(".maps");

/* Macro per definire code BPF per cleanup */
#define DEFINE_CLEANUP_QUEUE(map_name) \
    struct { \
        __uint(type, BPF_MAP_TYPE_QUEUE); \
        __uint(value_size, sizeof(struct map_key)); \
        __uint(max_entries, 4096); \
    } map_name SEC(".maps");

/* Definizione delle mappe hash usando la macro */
DEFINE_TRANSLATION_HASH_MAP(host_to_network_seq_map);
DEFINE_TRANSLATION_HASH_MAP(network_to_host_seq_map);
DEFINE_TRANSLATION_HASH_MAP(host_to_network_ack_map);
DEFINE_TRANSLATION_HASH_MAP(network_to_host_ack_map);

/* Definizione dei ring buffer per la pulizia delle mappe */
DEFINE_CLEANUP_QUEUE(cleanup_received_ack);
DEFINE_CLEANUP_QUEUE(cleanup_sent_ack);




/* ============================================================================
 * Sequence Number Translation Functions
 * ============================================================================ */

/**
 * Offload cleanup to userspace by pushing a key to the cleanup queue
 */
static __always_inline void offload_cleanup_to_user_space(void* queue_map, struct flow_info *flow, __u32 seq_num) {
    struct map_key key;
    key.flow = *flow;
    key.seq = seq_num;
    
    // Push the key to the queue (BPF_EXIST: only if there's space)
    if (bpf_map_push_elem(queue_map, &key, BPF_EXIST) < 0) {
        debug_print("[SEQ_TRANS] Failed to push key to cleanup queue (queue full?)");
    }
}

/**
 * Initialize flow translation maps for SYN packet
 * Both original and translated seq_num are the same at handshake
 */
static __always_inline __u8 init_translation_map(void* map, struct flow_info *flow, __u32 seq_num) {
    struct map_key key;
    key.flow = *flow;
    key.seq = seq_num;

    struct map_value value;
    value.translated_seq = seq_num;
    value.prev_seq = 0;
    value.timestamp_ns = bpf_ktime_get_ns();
    if (bpf_map_update_elem(map, &key, &value, BPF_ANY) < 0) {
        debug_print("[SEQ_TRANS] Failed to initialize translation map");
        return TC_ACT_SHOT;
    }

    debug_print("[SEQ_TRANS] Initialized flow with seq=%u", seq_num);
    //bpf_printk("Initialized flow with seq=%u", seq_num);
    return 1;
}

/**
 * Lookup seq_num translation for a flow
 * Returns pointer to seq_translation struct, or NULL if not found
 */
static __always_inline struct map_value * lookup_translation_map(void *map, struct flow_info *flow, __u32 seq_num) {
    struct map_key key;
    key.flow = *flow;
    key.seq = seq_num;
    return bpf_map_lookup_elem(map, &key);
}

static __always_inline __u8 seq_num_map_translation_init(struct __sk_buff *skb, void* seq_num_map, void* ack_map, __u64 redirect_flags) { // da chiamare sia in ingress che in egress
    __u8 flag, ip_header_len;
    __u8 result = extract_ip_header_len(skb, &ip_header_len);
    __u32 seq_num;
    struct flow_info flow;
    if(result!=1){
        return result;
    }
    result = extract_tcp_flags(skb, ip_header_len, &flag);
    if(result!=1){
        return result;
    }
    result = extract_flow_info(skb, ip_header_len, &flow);
    if(result!=1){
        return result;
    }
    result = extract_seq_num(skb, ip_header_len, &seq_num);
    if(result!=1){
        return result;
    }
    //bpf_printk("flag=%u, mark=%u", flag, skb->mark);
    if(is_syn(flag)){
        if(has_ack_flag(flag)){
            //bpf_printk("SYN/ACK");
        } else {
            //bpf_printk("SYN");
        }
        seq_num += 1;
        //bpf_printk("Initializing seq_num maps");
        result = init_translation_map(seq_num_map, &flow, seq_num);
        if (result !=1 )
            return result;
        reverse_flow(&flow);
        //bpf_printk("Initializing ack_num maps");
        result = init_translation_map(ack_map, &flow, seq_num);
        if (result !=1 )
            return result;
        return TC_ACT_OK;
    }
    if(lookup_translation_map(seq_num_map, &flow, seq_num)!=NULL){
        //bpf_printk("Translation already initialized");
        return 1;
    }
    //bpf_printk("Translation not initialized, missing seq_num=%u", seq_num);
    
    // Use redirect_count field to track retries and avoid infinite loops
    __u8 retry_count = skb_mark_get_redirect_count(skb);
    if(retry_count > 8){
        //bpf_printk("dropping packet to avoid infinite loop (retry_count=%u)", retry_count);
        return TC_ACT_SHOT;
    }
    //bpf_printk("Redirecting packet to initialize translation (retry_count=%u)", retry_count);
    skb_mark_increment_redirect_count(skb);
    bpf_clone_redirect(skb, skb->ifindex, redirect_flags);
    return TC_ACT_SHOT;
}

static __always_inline __u8 translate_seq_num(struct __sk_buff *skb, void* seq_num_map, __u32 input_seq_num, struct flow_info *flow, __u32 *output_seq_num, __u8 ip_header_len) {
    struct map_value *translation = lookup_translation_map(seq_num_map, flow, input_seq_num);
    if (!translation) {
        //bpf_printk("[SEQ_TRANS] No translation found for seq_num=%u", input_seq_num);
        debug_print("[SEQ_TRANS] No translation found for seq_num=%u", input_seq_num);
        return TC_ACT_SHOT;
    }

    //bpf_printk("Found seq num translation: original=%u, translated=%u", input_seq_num, translation->translated_seq);

    *output_seq_num = translation->translated_seq;

    int result = replace_seq_num(skb, ip_header_len, *output_seq_num);
    if (result != 1) {
        debug_print("[SEQ_TRANS] Failed to replace seq_num");
        //bpf_printk("[SEQ_TRANS] Failed to replace seq_num");
        return result;
    }

    //bpf_printk("Replaced seq num in packet: %u", *output_seq_num);

    if (update_checksums_seq_num(skb, ip_header_len, translation->prev_seq, *output_seq_num) < 0) {
        debug_print("[SEQ_TRANS] Failed to update checksums for seq_num");
        //bpf_printk("[SEQ_TRANS] Failed to update checksums for seq_num");
        return TC_ACT_SHOT;
    }
    //bpf_printk("Updated checksums for seq num change: old=%u, new=%u", translation->prev_seq, *output_seq_num);

    return 1;
}

static __always_inline __u8 insert_new_seq(void* seq_num_map, void* ack_map_reverse, struct flow_info *flow, __u32 input_seq_num, __u32 translated_seq, __u16 input_payload_len, __u16 translated_payload_len) {
    struct map_key key;
    key.flow = *flow;
    key.seq = input_seq_num + input_payload_len;

    struct map_value value;
    value.translated_seq = translated_seq + translated_payload_len;
    value.prev_seq = input_seq_num;
    value.timestamp_ns = bpf_ktime_get_ns();

    //bpf_printk("Inserting new seq mapping: original=%u (%u + %u), translated=%u (%u + %u)", key.seq, input_seq_num, input_payload_len, value.translated_seq, translated_seq, translated_payload_len);
    if (bpf_map_update_elem(seq_num_map, &key, &value, BPF_ANY) < 0) {
        debug_print("[SEQ_TRANS] Failed to insert new seq_num");
        return TC_ACT_SHOT;
    }

    reverse_flow(&(key.flow));
    key.seq = translated_seq + translated_payload_len;

    value.translated_seq = input_seq_num + input_payload_len;
    value.prev_seq = translated_seq;
    value.timestamp_ns = bpf_ktime_get_ns();

    //bpf_printk("Inserting new ack mapping: original=%u (%u + %u), translated=%u (%u + %u)", key.seq, input_seq_num, input_payload_len, value.translated_seq, translated_seq, translated_payload_len);
    if (bpf_map_update_elem(ack_map_reverse, &key, &value, BPF_ANY) < 0) {
        debug_print("[SEQ_TRANS] Failed to insert new ack_num");
        return TC_ACT_SHOT;
    }

    return 1;
}

static __always_inline __u8 manage_ack(struct __sk_buff *skb, void* ack_map, void* cleanup_queue, __u32 input_ack_num, struct flow_info flow, __u8 ip_header_len) {

    // Lookup translation
    struct map_value *translation = lookup_translation_map(ack_map, &flow, input_ack_num);
    if (!translation) {
        debug_print("[SEQ_TRANS] No translation found for ack_num=%u", input_ack_num);
        //bpf_printk("[SEQ_TRANS] No translation found for ack_num=%u", input_ack_num);
        return TC_ACT_SHOT;
    }
    //bpf_printk("Found ack translation: original=%u, translated=%u", input_ack_num, translation->translated_seq);
   // Replace ack_num in packet
    if (replace_ack_num(skb, ip_header_len, translation->translated_seq) < 0) {
        debug_print("[SEQ_TRANS] Failed to replace ack_num");
        return TC_ACT_SHOT;
    }

    // Offload cleanup to user-space
    offload_cleanup_to_user_space(cleanup_queue, &flow, input_ack_num);

    return 1;
}

static __always_inline __u8 manage_seq_and_ack(struct __sk_buff *skb, void* seq_num_map, void* ack_map, void* ack_map_reverse, void* cleanup_queue) {

    __u8 ip_header_len, tcp_header_len;
    struct flow_info flow;
    __u16 input_ip_len, input_payload_len, translated_payload_len;
    __u32 input_seq_num, translated_seq_num;
    __u8 tcp_flags;
    __u8 result = extract_tcp_ip_header_lengths(skb, &ip_header_len, &tcp_header_len, &input_ip_len);
    if(result != 1)
        return result;
    result = extract_flow_info(skb, ip_header_len, &flow);
    if(result != 1)
        return result;
    //bpf_printk("IP header length: %u, TCP header length: %u, IP total length: %u", ip_header_len, tcp_header_len, input_ip_len);
    result = extract_seq_num(skb, ip_header_len, &input_seq_num);
    if(result != 1)
        return result;
    result = extract_tcp_flags(skb, ip_header_len, &tcp_flags);
    if(result != 1)
        return result;
    //bpf_printk("IP header length: %u, TCP header length: %u, IP total length: %u", ip_header_len, tcp_header_len, input_ip_len);
    input_payload_len = input_ip_len - (ip_header_len + tcp_header_len);
    //bpf_printk("Input payload length: %u bytes (%u - (%u + %u))", input_payload_len, input_ip_len, ip_header_len, tcp_header_len);
    translated_payload_len = skb->len - (ip_header_len + tcp_header_len + sizeof(struct ethhdr));

    // Translate seq_num
    result = translate_seq_num(skb, seq_num_map, input_seq_num, &flow, &translated_seq_num, ip_header_len);
    if (result != 1) {
        return result;
    }
    if(is_fin(tcp_flags)){
        translated_payload_len +=1;
        input_payload_len +=1;
    }
    // Insert new seq_num mapping for next expected seq_num
    result = insert_new_seq(seq_num_map, ack_map_reverse, &flow, input_seq_num, translated_seq_num, input_payload_len, translated_payload_len);
    if (result != 1) {
        return result;
    }

    if (has_ack_flag(tcp_flags) == 0) {
        //bpf_printk("No ACK flag set");
        return 1; // No ACK flag, nothing more to do
    }
    //bpf_printk("ACK flag set");
    __u32 input_ack_num;
    result = extract_ack_num(skb, ip_header_len, &input_ack_num);
    if (result != 1) {
        return result;
    }
    result = manage_ack(skb, ack_map, cleanup_queue, input_ack_num, flow, ip_header_len);
    if (result != 1) {
        return result;
    }

    return 1;
}

static __always_inline __u8 seq_num_translation_init_ingress(struct __sk_buff *skb) {
    return seq_num_map_translation_init(skb, &network_to_host_seq_map, &host_to_network_ack_map, BPF_F_INGRESS);
}

static __always_inline __u8 seq_num_translation_init_egress(struct __sk_buff *skb) {
    return seq_num_map_translation_init(skb, &host_to_network_seq_map, &network_to_host_ack_map, 0);
}

static __always_inline __u8 manage_seq_num_ingress(struct __sk_buff *skb) {
    return manage_seq_and_ack(skb, &network_to_host_seq_map, &network_to_host_ack_map, &host_to_network_ack_map, &cleanup_received_ack);
}

static __always_inline __u8 manage_seq_num_egress(struct __sk_buff *skb) {
    return manage_seq_and_ack(skb, &host_to_network_seq_map, &host_to_network_ack_map, &network_to_host_ack_map, &cleanup_sent_ack);
}

#endif /* __SEQ_NUM_TRANSLATION_H */
