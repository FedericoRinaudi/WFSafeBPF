// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Include modular headers */
#include "config.h"
#include "blake2s.h"
#include "network_utils.h"
#include "checksum.h"
#include "hmac.h"
#include "padding.h"
#include "fragmentation.h"
#include "seq_num_translation.h"

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
     __uint(max_entries, 6);
     __array(values, u32 (void *));
 } progs_eg SEC(".maps") = {
     .values = {
         [0] = (void *)&fragmentation_clone_to_packet,
         [1] = (void *)&tcp_state_init,
         [2] = (void *)&fragment_packet,
         [3] = (void *)&add_padding,
         [4] = (void *)&manage_tcp_state_translations,
         [5] = (void *)&recompute_tcp_checksum
    },
 };

/* eBPF program sections using modular functions */

SEC("classifier")
int fragmentation_clone_to_packet(struct __sk_buff *skb) {
    __u8 result = fragmentation_clone_to_packet_internal(skb);
    if (result != 1)
        return result;
    
    // Continue with fragmentation if result is 0
    debug_print("[FRAG_CLONE] Tail call to fragment_packet");
    bpf_tail_call(skb, &progs_eg, 1);
    return TC_ACT_OK;
}

SEC("classifier")
int tcp_state_init(struct __sk_buff *skb){
    __u8 result = seq_num_translation_init_egress(skb);
    if(result != 1)
        return result;
    skb->mark = 0;
    bpf_tail_call(skb, &progs_eg, 2);
    return TC_ACT_OK;
}

SEC("classifier")
int fragment_packet(struct __sk_buff *skb) {
    __u8 result = fragment_packet_internal(skb);
    if (result != 1)
        return result;
    bpf_tail_call(skb, &progs_eg, 3);
    return TC_ACT_OK;
}

SEC("classifier")
int add_padding(struct __sk_buff *skb) {
    __u8 result = add_padding_internal(skb);
    if (result != 1)
        return result;
    bpf_tail_call(skb, &progs_eg, 4);
    return TC_ACT_OK;
}

SEC("classifier")
int manage_tcp_state_translations(struct __sk_buff *skb){
    __u8 result = manage_seq_num_egress(skb);
    if(result != 1)
        return result;
    if (skb->mark == 1)
        bpf_tail_call(skb, &progs_eg, 5);
    return TC_ACT_OK;
}

SEC("classifier")
int recompute_tcp_checksum(struct __sk_buff *skb) {
    return recompute_tcp_checksum_internal(skb);
}



SEC("classifier")
int handle_ingress(struct __sk_buff *skb) {
    __u16 ip_tot_old;
    __u8 ip_header_len, tcp_header_len;
    __wsum acc = 0;
    __u32 seq_num_old;
    
    //bpf_printk("Packet received: len=%d", skb->len);
    
    debug_print("[INGRESS] Packet received: len=%d", skb->len);
    
    if (should_skip_packet(skb)) {
        debug_print("[INGRESS] Packet skipped (GSO or oversized)");
        return TC_ACT_OK;
    }
    
    __u8 result = seq_num_translation_init_ingress(skb);
    if (result != 1)
        return result;
    skb->mark = 0;

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

    return TC_ACT_OK;
}


SEC("classifier")
int handle_egress(struct __sk_buff *skb) {
    
    //if(skb->mark == 0)
    //    bpf_printk("Sending packet: len=%d", skb->len);
    debug_print("[EGRESS] Packet received: len=%d", skb->len);
    
    if (should_skip_packet(skb)) {
        debug_print("[EGRESS] Packet skipped (GSO or oversized)");
        return TC_ACT_OK;
    }

    bpf_tail_call(skb, &progs_eg, 0); // fragmentation_clone_to_packet

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
