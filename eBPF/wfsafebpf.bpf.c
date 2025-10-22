// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "config.h"
#include "skb_mark.h"
#include "blake2s.h"
#include "network_utils.h"
#include "checksum.h"
#include "hmac.h"
#include "padding.h"
#include "fragmentation.h"
#include "seq_num_translation.h"

// Enum for tail call program indices
enum tail_call_index {
    TAIL_CALL_FRAG_CLONE = 0,
    TAIL_CALL_TCP_STATE_INIT = 1,
    TAIL_CALL_FRAGMENT_PACKET = 2,
    TAIL_CALL_ADD_PADDING = 3,
    TAIL_CALL_MANAGE_TCP_STATE = 4,
    TAIL_CALL_RECOMPUTE_CHECKSUM = 5,
    TAIL_CALL_MAX_ENTRIES = 6
};

// Forward declarations for tail call map
SEC("classifier") int fragmentation_clone_to_packet(struct __sk_buff *skb);
SEC("classifier") int tcp_state_init(struct __sk_buff *skb);
SEC("classifier") int fragment_packet(struct __sk_buff *skb);
SEC("classifier") int add_padding(struct __sk_buff *skb);
SEC("classifier") int manage_tcp_state_translations(struct __sk_buff *skb);
SEC("classifier") int recompute_tcp_checksum(struct __sk_buff *skb);

// Tail call program array map
struct {
     __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
     __uint(key_size, sizeof(u32));
     __uint(max_entries, TAIL_CALL_MAX_ENTRIES);
     __array(values, u32 (void *));
 } progs_eg SEC(".maps") = {
     .values = {
         [TAIL_CALL_FRAG_CLONE] = (void *)&fragmentation_clone_to_packet,
         [TAIL_CALL_TCP_STATE_INIT] = (void *)&tcp_state_init,
         [TAIL_CALL_FRAGMENT_PACKET] = (void *)&fragment_packet,
         [TAIL_CALL_ADD_PADDING] = (void *)&add_padding,
         [TAIL_CALL_MANAGE_TCP_STATE] = (void *)&manage_tcp_state_translations,
         [TAIL_CALL_RECOMPUTE_CHECKSUM] = (void *)&recompute_tcp_checksum
    },
 };

/* eBPF program sections using modular functions */

SEC("classifier")
int fragmentation_clone_to_packet(struct __sk_buff *skb) {
    //bpf_printk("[EGRESS] TAIL_CALL_FRAG_CLONE: packet_len=%u", skb->len);
    __u8 result = fragmentation_clone_to_packet_internal(skb);
    if (result != 1)
        return result;
    
    // Continue with fragmentation if result is 0
    debug_print("[FRAG_CLONE] Tail call to fragment_packet");
    //bpf_printk("[EGRESS] TAIL_CALL_FRAG_CLONE done: packet_len=%u, calling TCP_STATE_INIT", skb->len);
    bpf_tail_call(skb, &progs_eg, TAIL_CALL_TCP_STATE_INIT);
    return TC_ACT_OK;
}

SEC("classifier")
int tcp_state_init(struct __sk_buff *skb){
    //bpf_printk("[EGRESS] TAIL_CALL_TCP_STATE_INIT: packet_len=%u", skb->len);
    __u8 result = seq_num_translation_init_egress(skb);
    if(result != 1)
        return result;
    //bpf_printk("[EGRESS] TAIL_CALL_TCP_STATE_INIT done: packet_len=%u, calling FRAGMENT_PACKET", skb->len);
    bpf_tail_call(skb, &progs_eg, TAIL_CALL_FRAGMENT_PACKET);
    return TC_ACT_OK;
}

SEC("classifier")
int fragment_packet(struct __sk_buff *skb) {
    //bpf_printk("[EGRESS] TAIL_CALL_FRAGMENT_PACKET: packet_len=%u", skb->len);
    __u8 result = fragment_packet_internal(skb);
    if (result != 1)
        return result;
    //bpf_printk("[EGRESS] TAIL_CALL_FRAGMENT_PACKET done: packet_len=%u, calling ADD_PADDING", skb->len);
    bpf_tail_call(skb, &progs_eg, TAIL_CALL_ADD_PADDING);
    return TC_ACT_OK;
}

SEC("classifier")
int add_padding(struct __sk_buff *skb) {
    //bpf_printk("[EGRESS] TAIL_CALL_ADD_PADDING: packet_len=%u", skb->len);
    __u8 result = add_padding_internal(skb);
    if (result != 1)
        return result;
    //bpf_printk("[EGRESS] TAIL_CALL_ADD_PADDING done: packet_len=%u, calling MANAGE_TCP_STATE", skb->len);
    bpf_tail_call(skb, &progs_eg, TAIL_CALL_MANAGE_TCP_STATE);
    return TC_ACT_OK;
}

SEC("classifier")
int manage_tcp_state_translations(struct __sk_buff *skb){
    //bpf_printk("[EGRESS] TAIL_CALL_MANAGE_TCP_STATE: packet_len=%u", skb->len);
    __u8 result = manage_seq_num_egress(skb);
    if(result != 1)
        return result;
    
    // Check if checksum recalculation is needed
    if (skb_mark_get_checksum_flag(skb)) {
        //bpf_printk("[EGRESS] TAIL_CALL_MANAGE_TCP_STATE done: packet_len=%u, calling RECOMPUTE_CHECKSUM", skb->len);
        bpf_tail_call(skb, &progs_eg, TAIL_CALL_RECOMPUTE_CHECKSUM);
    }

    //bpf_printk("[EGRESS] end: packet_len=%u", skb->len);
    return TC_ACT_OK;
}

SEC("classifier")
int recompute_tcp_checksum(struct __sk_buff *skb) {
    //bpf_printk("[EGRESS] TAIL_CALL_RECOMPUTE_CHECKSUM: packet_len=%u", skb->len);
    __u8 result = recompute_tcp_checksum_internal(skb);
    //bpf_printk("[EGRESS] end: packet_len=%u", skb->len);
    //bpf_printk("[EGRESS] TAIL_CALL_RECOMPUTE_CHECKSUM done: packet_len=%u", skb->len);
    return result;
}



SEC("classifier")
int handle_ingress(struct __sk_buff *skb) {
    __u16 ip_tot_old;
    __u8 ip_header_len, tcp_header_len;
    __wsum acc = 0;
    __u32 seq_num_old;
    
    //bpf_printk("[INGRESS] START: packet_len=%u", skb->len);
    
    debug_print("[INGRESS] Packet received: len=%d", skb->len);
    
    if (should_skip_packet(skb)) {
        debug_print("[INGRESS] Packet skipped (GSO or oversized)");
        //bpf_printk("[INGRESS] SKIPPED: packet_len=%u (GSO or oversized)", skb->len);
        return TC_ACT_OK;
    }
    
    __u8 result = seq_num_translation_init_ingress(skb);
    if (result != 1)
        return result;
    skb_mark_reset(skb);  // Reset all mark fields

    result = extract_tcp_ip_header_lengths(skb, &ip_header_len, &tcp_header_len, &ip_tot_old);
    if(result != 1) {
        debug_print("[INGRESS] Non-TCP/IP packet or extraction error, skipping HMAC removal");
        return result;
    }

    result = extract_seq_num(skb, ip_header_len, &seq_num_old);
    if (result != 1)
        return result;
    
    debug_print("[INGRESS] IP packet: total_len=%d, header_len=%d", ip_tot_old, ip_header_len);

    if (remove_all_padding(skb, tcp_header_len + ip_header_len + sizeof(struct ethhdr), ip_header_len, ip_tot_old, &acc) < 0) {
        debug_print("[INGRESS] Error removing padding, dropping packet");
        return TC_ACT_SHOT;
    }
    debug_print("[INGRESS] Packet processing successful");
    result = manage_seq_num_ingress(skb);
    if (result != 1)
        return result;

    if (update_checksums_inc(skb, ip_header_len, ip_tot_old, acc) < 0) {
        debug_print("[INGRESS] Error updating checksums, dropping packet");
        return -1;
    }

    //bpf_printk("[INGRESS] END: packet_len=%u", skb->len);
    return TC_ACT_OK;
}


SEC("classifier")
int handle_egress(struct __sk_buff *skb) {
    //if(skb_mark_get_frag_payload_len(skb) == 0) {
        //bpf_printk("[EGRESS] START: packet_len=%u", skb->len);
    //}
    
    debug_print("[EGRESS] Packet received: len=%d", skb->len);
    
    if (should_skip_packet(skb)) {
        debug_print("[EGRESS] Packet skipped (GSO or oversized)");
        //bpf_printk("[EGRESS] SKIPPED: packet_len=%u (GSO or oversized)", skb->len);
        return TC_ACT_OK;
    }

    //bpf_printk("[EGRESS] Calling TAIL_CALL_FRAG_CLONE");
    bpf_tail_call(skb, &progs_eg, TAIL_CALL_FRAG_CLONE);

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
