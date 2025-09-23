#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// Evita conflitto di nomi con vmlinux.h
#undef BLAKE2S_BLOCK_SIZE

#include "blake2s.h"

// Mappa per memorizzare i risultati dei test
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u32);
} test_results SEC(".maps");

// Test completo con confronto hash di riferimento 
static int blake2s_test(void)
{
    __u8 test_key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    
    __u8 test_data[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    
    // Hash di riferimento calcolato con implementazione standard libb2
    static const __u32 expected_hash[8] = {
        0x42c63bc0, 0xcb5909b2, 0x30a033e1, 0xbf1a0c3e,
        0xc81ee3f3, 0xec28a3e1, 0x6dc36585, 0x6552ffec
    };
    
    __u32 digest[8];
    __u32 key, value;
    
    /* Calcola Blake2s una sola volta */
    blake2sCompute(test_key, test_data, digest);
    
    // Salva l'hash calcolato nella mappa (chiavi 0-7)
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        key = i;
        value = digest[i];
        bpf_map_update_elem(&test_results, &key, &value, BPF_ANY);
    }
    
    // Confronta con hash di riferimento (invece di chiamare blake2s_verify_test)
    int test_result = 1; // Assume successo
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        if (digest[i] != expected_hash[i]) {
            test_result = 0; // Fallimento - hash diverso
            break;
        }
    }
    
    // Salva il risultato del test nella mappa
    key = 9;
    value = test_result; // 1 se perfetto match, 0 altrimenti
    bpf_map_update_elem(&test_results, &key, &value, BPF_ANY);
    
    // Salva anche informazioni aggiuntive per il debugging
    key = 8;
    value = test_result ? 8 : 0; // Se successo, tutti 8 gli hash coincidono
    bpf_map_update_elem(&test_results, &key, &value, BPF_ANY);
    
    return test_result ? 0 : -1;  // 0 per successo, -1 per fallimento
}

SEC("xdp_test")
int blake2s_test_prog(struct xdp_md *ctx)
{
    __u32 key = 15;
    __u32 result = blake2s_test();
    
    // Memorizza il risultato finale 
    bpf_map_update_elem(&test_results, &key, (__u32*)&result, BPF_ANY);
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";