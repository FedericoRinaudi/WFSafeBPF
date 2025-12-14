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
#include "client_config.h"
#include "padding.h"
#include "fragmentation.h"
#include "seq_num_translation.h"
#include "dummy.h"
#include "measure_config.h"

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
    delay_egress_stop_measure();
    __u8 ip_header_len;
    if(extract_ip_header_len(skb, &ip_header_len) != 1) {
        return result;
    }
    __u8 tcp_flags;
    if(extract_tcp_flags(skb, ip_header_len, &tcp_flags) != 1) { // Dummy call to ensure ip_header_len is used
        return result;
    }
    if(!is_syn(tcp_flags) && !is_fin(tcp_flags) && skb->len>64) {
        delay_egress_end_measure();
    }
    debug_print("[EGRESS] END: len=%u", skb->len);
    return TC_ACT_OK;
}

SEC("classifier")
int recompute_tcp_checksum(struct __sk_buff *skb) {
    checksum_delay_egress_start_measure();
    __u8 result = recompute_tcp_checksum_internal(skb);
    checksum_delay_egress_end_measure();
    debug_print("[EGRESS] END: len=%u", skb->len);
    delay_egress_stop_measure();
    __u8 ip_header_len;
    __u8 type = skb_mark_get_type(skb);
    if(extract_ip_header_len(skb, &ip_header_len) != 1) {
        return result;
    }
    __u8 tcp_flags;
    if(extract_tcp_flags(skb, ip_header_len, &tcp_flags) != 1) { // Dummy call to ensure ip_header_len is used
        return result;
    }
    if(!is_syn(tcp_flags) && !is_fin(tcp_flags) && skb->len>64 && type != SKB_MARK_TYPE_FRAGMENT_CLONE && type != SKB_MARK_TYPE_DUMMY_CLONE) {
        delay_egress_end_measure();
    }
    return result;
}



SEC("classifier")
int handle_ingress(struct __sk_buff *skb) {
    __u16 ip_tot_old;
    __u8 ip_header_len, tcp_header_len;
    __wsum acc = 0;
    //__u32 seq_num_old;
    
    debug_print("[INGRESS] START: len=%u", skb->len);
    
    if (should_skip_packet(skb)) {
        return TC_ACT_OK;
    }

    __u8 result = extract_tcp_ip_header_lengths(skb, &ip_header_len, &tcp_header_len, &ip_tot_old);
    if(result != 1) {
        debug_print("[INGRESS-EXIT] extract_tcp_ip_header_lengths: result=%d", result);
        return result;
    }

    __u8 tcp_flags;
    if(extract_tcp_flags(skb, ip_header_len, &tcp_flags) != 1) {
        debug_print("[INGRESS-EXIT] extract_tcp_flags: result=%d", result);
        return result;
    }
    if(is_syn(tcp_flags)){
        delay_ingress_start_measure();
        delay_ingress_stop_measure();
    } else if (is_fin(tcp_flags)){
        delay_ingress_end_measure();
    } else if (skb->len>64){
        delay_ingress_resume_measure();
    }
    
    // Check if source IP has keys configured and get config once
    struct client_config *config = get_client_config_ingress(skb, ip_header_len);
    if (!config) {
        debug_print("[INGRESS-EXIT] No config for source IP, passing through");
        delay_ingress_reset_measure();
        return TC_ACT_OK;
    }
    if(!is_syn(tcp_flags) && !is_fin(tcp_flags) && skb->len>64) {
        seq_num_trans_delay_ingress_start_measure();
    }
    result = seq_num_translation_init_ingress(skb);
    if (result != 1) {
        debug_print("[INGRESS-EXIT] seq_num_translation_init_ingress: result=%d", result);
        return result;
    }
    if(!is_syn(tcp_flags) && !is_fin(tcp_flags) && skb->len>64) {
        seq_num_trans_delay_ingress_stop_measure();
    }
    skb_mark_reset(skb);  // Reset all mark fields

    //result = extract_seq_num(skb, ip_header_len, &seq_num_old);
    //if (result != 1) {
    //    debug_print("[INGRESS-EXIT] extract_seq_num: result=%d", result);
    //    return result;
    //}
    __s8 dummy = is_dummy(skb, tcp_header_len + ip_header_len + sizeof(struct ethhdr), ip_header_len, ip_tot_old, config);
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
        delay_ingress_stop_measure();
        return TC_ACT_SHOT;
    }
    if (remove_all_padding(skb, tcp_header_len + ip_header_len + sizeof(struct ethhdr), ip_header_len, ip_tot_old, &acc, config) < 0) {
        debug_print("[INGRESS-EXIT] remove_all_padding: TC_ACT_SHOT");
        return TC_ACT_SHOT;
    }

    seq_num_trans_delay_ingress_resume_measure();
    result = manage_seq_num_ingress(skb);
    seq_num_trans_delay_ingress_end_measure();
    if (result != 1) {
        debug_print("[INGRESS-EXIT] manage_seq_num_ingress: result=%d", result);
        return result;
    }

    
    checksum_delay_ingress_start_measure();
    if (update_checksums_inc(skb, ip_header_len, ip_tot_old, acc) < 0) {
        debug_print("[INGRESS-EXIT] update_checksums_inc: error");
        return -1;
    }
    checksum_delay_ingress_end_measure();

    if(!is_syn(tcp_flags) && !is_fin(tcp_flags) && skb->len>64) {
        delay_ingress_stop_measure();
    }

    debug_print("[INGRESS] END: len=%u", skb->len);
    return TC_ACT_OK;
}


SEC("classifier")
int handle_egress(struct __sk_buff *skb) {
    debug_print("[EGRESS] START: len=%u", skb->len);
    __u8 mark_type = skb_mark_get_type(skb);
    __u8 tcp_flags;
    if (should_skip_packet(skb)) {
        return TC_ACT_OK;
    }
    
    __u8 ip_header_len;
    if(extract_ip_header_len(skb, &ip_header_len) != 1) {
        return TC_ACT_OK;
    }
    if(extract_tcp_flags(skb, ip_header_len, &tcp_flags) != 1) {
        return TC_ACT_OK;
    }
    if(!is_syn(tcp_flags) && !is_fin(tcp_flags) && skb->len>64 && mark_type != SKB_MARK_TYPE_FRAGMENT_CLONE && mark_type != SKB_MARK_TYPE_DUMMY_CLONE) {
        delay_egress_start_measure();
    }

    // Check if destination IP has keys configured
    struct client_config *config = get_client_config_egress(skb, ip_header_len);
    if (!config) {
        delay_egress_reset_measure();
        debug_print("[EGRESS] No config for destination IP, passing through");
        return TC_ACT_OK;
    }
    
    switch(mark_type) {
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
