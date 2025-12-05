use crate::BpfState;
use crate::models::MapValue;

/// Pulisce le entry vecchie da una mappa basandosi sul timestamp
pub fn cleanup_by_timestamp(
    bpf_state: &BpfState,
    map_name: &str,
    threshold_ns: u64,
) -> Result<usize, Box<dyn std::error::Error>> {
    // Usa il tempo monotonic (dal boot) per matchare bpf_ktime_get_ns()
    // Leggiamo il monotonic time da /proc/uptime che è in secondi
    let uptime_str = std::fs::read_to_string("/proc/uptime")?;
    let uptime_secs: f64 = uptime_str
        .split_whitespace()
        .next()
        .ok_or("Cannot read uptime")?
        .parse()?;
    let current_time_ns = (uptime_secs * 1_000_000_000.0) as u64;
    
    let mut cleaned = 0;
    
    // Ottieni tutte le chiavi (metodo di sola lettura)
    let keys = {
        let loader = bpf_state.loader.lock().unwrap();
        loader.read_map_keys(map_name)?
    };
    
    // Itera su tutte le entry
    for key_bytes in keys {
        // Leggi il valore per controllare il timestamp (metodo di sola lettura)
        let value_bytes = {
            let loader = bpf_state.loader.lock().unwrap();
            loader.read_map_value(map_name, &key_bytes)?
        };
        
        if let Some(vb) = value_bytes {
            if let Ok(value) = MapValue::from_bytes(&vb) {
                let age_ns = current_time_ns.saturating_sub(value.timestamp_ns);
                
                // Se l'entry è più vecchia della soglia, eliminala
                if age_ns > threshold_ns {
                    let mut loader = bpf_state.loader.lock().unwrap();
                    let mut maps = loader.maps();
                    if maps.delete(map_name, &key_bytes).is_ok() {
                        cleaned += 1;
                    }
                }
            }
        }
    }
    
    Ok(cleaned)
}

/// Pulisce tutte le mappe seq e ack basandosi sul timestamp
pub fn cleanup_all_maps_by_timestamp(
    bpf_state: &BpfState,
    threshold_ns: u64,
) -> usize {
    let seq_maps = [
        "network_to_host_seq_map",
        "host_to_network_seq_map",
    ];
    let ack_maps = [
        "host_to_network_ack_map",
        "network_to_host_ack_map",
    ];
    
    let mut total = 0;
    
    // Pulisci tutte le mappe seq
    for map_name in &seq_maps {
        if let Ok(count) = cleanup_by_timestamp(bpf_state, map_name, threshold_ns) {
            total += count;
        }
    }
    
    // Pulisci tutte le mappe ack
    for map_name in &ack_maps {
        if let Ok(count) = cleanup_by_timestamp(bpf_state, map_name, threshold_ns) {
            total += count;
        }
    }
    
    if total > 0 {
        println!("[CLEANUP] Age-based cleanup: {} entries removed", total);
    }
    
    total
}
