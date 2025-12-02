// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "config.h"
#include "consts.h"
#include "skb_mark.h"
#include "blake2s.h"
#include "network_utils.h"
#include "checksum.h"
#include "hmac.h"
#include "padding.h"
#include "fragmentation.h"
#include "seq_num_translation.h"
#include "dummy.h"

// Enum for tail call program indices
enum tail_call_index {
    TAIL_CALL_FRAG_CLONE = 0,
    TAIL_CALL_TCP_DUMMY_CLONE = 1,
    TAIL_CALL_TCP_STATE_INIT = 2,
    TAIL_CALL_FRAGMENT_PACKET = 3,
    TAIL_CALL_INSERT_DUMMY = 4,
    TAIL_CALL_ADD_PADDING = 5,
    TAIL_CALL_MANAGE_TCP_STATE = 6,
    TAIL_CALL_RECOMPUTE_CHECKSUM = 7,
    TAIL_CALL_MAX_ENTRIES = 8
};

// Forward declarations for tail call map
SEC("classifier") int fragmentation_clone_to_packet(struct __sk_buff *skb);
SEC("classifier") int dummy_clone_to_packet(struct __sk_buff *skb);
SEC("classifier") int tcp_state_init(struct __sk_buff *skb);
SEC("classifier") int fragment_packet(struct __sk_buff *skb);
SEC("classifier") int insert_dummy_packet(struct __sk_buff *skb);
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
         [TAIL_CALL_TCP_DUMMY_CLONE] = (void *)&dummy_clone_to_packet,
         [TAIL_CALL_TCP_STATE_INIT] = (void *)&tcp_state_init,
         [TAIL_CALL_FRAGMENT_PACKET] = (void *)&fragment_packet,
         [TAIL_CALL_INSERT_DUMMY] = (void *)&insert_dummy_packet,
         [TAIL_CALL_ADD_PADDING] = (void *)&add_padding,
         [TAIL_CALL_MANAGE_TCP_STATE] = (void *)&manage_tcp_state_translations,
         [TAIL_CALL_RECOMPUTE_CHECKSUM] = (void *)&recompute_tcp_checksum
    },
 };

/* eBPF program sections using modular functions */

SEC("classifier")
int fragmentation_clone_to_packet(struct __sk_buff *skb) {
    __u8 result = fragmentation_clone_to_packet_internal(skb);
    if (result != 1) {
        debug_print("[EGRESS-EXIT] FRAG_CLONE: result=%d", result);
        return result;
    }
    bpf_tail_call(skb, &progs_eg, TAIL_CALL_TCP_STATE_INIT);
    return TC_ACT_OK;
}

SEC("classifier")
int dummy_clone_to_packet(struct __sk_buff *skb) {
    __u8 result = dummy_clone_to_packet_internal(skb);
    if (result != 1) {
        debug_print("[EGRESS-EXIT] DUMMY_CLONE: result=%d", result);
        return result;
    }
    bpf_tail_call(skb, &progs_eg, TAIL_CALL_MANAGE_TCP_STATE);
    return TC_ACT_OK;
}


SEC("classifier")
int tcp_state_init(struct __sk_buff *skb){
    __u8 result = seq_num_translation_init_egress(skb);
    if(result != 1) {
        debug_print("[EGRESS-EXIT] TCP_STATE_INIT: result=%d", result);
        return result;
    }
    bpf_tail_call(skb, &progs_eg, TAIL_CALL_FRAGMENT_PACKET);
    return TC_ACT_OK;
}

SEC("classifier")
int fragment_packet(struct __sk_buff *skb) {
    __u8 result = fragment_packet_internal(skb);
    if (result != 1) {
        debug_print("[EGRESS-EXIT] FRAGMENT_PACKET: result=%d", result);
        return result;
    }
    bpf_tail_call(skb, &progs_eg, TAIL_CALL_INSERT_DUMMY);
    return TC_ACT_OK;
}

SEC("classifier")
int insert_dummy_packet(struct __sk_buff *skb) {
    __u8 result = insert_dummy_packet_internal(skb);
    if (result != 1) {
        debug_print("[EGRESS-EXIT] INSERT_DUMMY_PACKET: result=%d", result);
        return result;
    }
    bpf_tail_call(skb, &progs_eg, TAIL_CALL_ADD_PADDING);
    return TC_ACT_OK;
}

SEC("classifier")
int add_padding(struct __sk_buff *skb) {
    __u8 result = add_padding_internal(skb);
    if (result != 1) {
        debug_print("[EGRESS-EXIT] ADD_PADDING: result=%d", result);
        return result;
    }
    bpf_tail_call(skb, &progs_eg, TAIL_CALL_MANAGE_TCP_STATE);
    return TC_ACT_OK;
}

SEC("classifier")
int manage_tcp_state_translations(struct __sk_buff *skb){
    __u8 result = manage_seq_num_egress(skb);
    if(result != 1) {
        debug_print("[EGRESS-EXIT] MANAGE_TCP_STATE: result=%d", result);
        return result;
    }
    
    // Check if checksum recalculation is needed
    if (skb_mark_get_checksum_flag(skb)) {
        bpf_tail_call(skb, &progs_eg, TAIL_CALL_RECOMPUTE_CHECKSUM);
    }

    debug_print("[EGRESS] END: len=%u", skb->len);
    return TC_ACT_OK;
}

SEC("classifier")
int recompute_tcp_checksum(struct __sk_buff *skb) {
    __u8 result = recompute_tcp_checksum_internal(skb);
    debug_print("[EGRESS] END: len=%u", skb->len);
    return result;
}



SEC("classifier")
int handle_ingress(struct __sk_buff *skb) {
    __u16 ip_tot_old;
    __u8 ip_header_len, tcp_header_len;
    __wsum acc = 0;
    __u32 seq_num_old;
    
    debug_print("[INGRESS] START: len=%u", skb->len);
    
    if (should_skip_packet(skb)) {
        return TC_ACT_OK;
    }
    
    __u8 result = seq_num_translation_init_ingress(skb);
    if (result != 1) {
        debug_print("[INGRESS-EXIT] seq_num_translation_init_ingress: result=%d", result);
        return result;
    }
    skb_mark_reset(skb);  // Reset all mark fields

    result = extract_tcp_ip_header_lengths(skb, &ip_header_len, &tcp_header_len, &ip_tot_old);
    if(result != 1) {
        debug_print("[INGRESS-EXIT] extract_tcp_ip_header_lengths: result=%d", result);
        return result;
    }

    result = extract_seq_num(skb, ip_header_len, &seq_num_old);
    if (result != 1) {
        debug_print("[INGRESS-EXIT] extract_seq_num: result=%d", result);
        return result;
    }
    __s8 dummy = is_dummy(skb, tcp_header_len + ip_header_len + sizeof(struct ethhdr), ip_header_len, ip_tot_old);
    if (dummy < 0) {
        debug_print("[INGRESS-EXIT] is_dummy: error");
        return TC_ACT_SHOT;
    } else if (dummy == 1) {
        skb_mark_set_type(skb, SKB_MARK_TYPE_DUMMY);
        result = manage_seq_num_ingress(skb); // Update seq num mappings for dummy packets
        if (result != 1) {
            debug_print("[INGRESS-EXIT] manage_seq_num_ingress (dummy): result=%d", result);
            return result;
        }
        debug_print("[INGRESS] Detected dummy packet, dropping");
        return TC_ACT_SHOT;
    }
    if (remove_all_padding(skb, tcp_header_len + ip_header_len + sizeof(struct ethhdr), ip_header_len, ip_tot_old, &acc) < 0) {
        debug_print("[INGRESS-EXIT] remove_all_padding: TC_ACT_SHOT");
        return TC_ACT_SHOT;
    }
    result = manage_seq_num_ingress(skb);
    if (result != 1) {
        debug_print("[INGRESS-EXIT] manage_seq_num_ingress: result=%d", result);
        return result;
    }

    if (update_checksums_inc(skb, ip_header_len, ip_tot_old, acc) < 0) {
        debug_print("[INGRESS-EXIT] update_checksums_inc: error");
        return -1;
    }

    debug_print("[INGRESS] END: len=%u", skb->len);
    return TC_ACT_OK;
}


SEC("classifier")
int handle_egress(struct __sk_buff *skb) {
    debug_print("[EGRESS] START: len=%u", skb->len);
    
    if (should_skip_packet(skb)) {
        return TC_ACT_OK;
    }
    __u8 result = skb_mark_get_type(skb);
    
    switch(result) {
        case SKB_MARK_TYPE_FRAGMENT_CLONE:
            bpf_tail_call(skb, &progs_eg, TAIL_CALL_FRAG_CLONE);
            break;
        case SKB_MARK_TYPE_DUMMY_CLONE:
            bpf_tail_call(skb, &progs_eg, TAIL_CALL_TCP_DUMMY_CLONE);
            break;
        default:
            bpf_tail_call(skb, &progs_eg, TAIL_CALL_TCP_STATE_INIT);
    }

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
