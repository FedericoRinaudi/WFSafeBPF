use std::sync::Arc;
use std::time::Duration;
use tokio::time;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::{Rocket, Build};
use crate::BpfState;
use crate::models::{MapKey, MapValue};

use super::monitoring::get_cpu_usage;
use super::timestamp_cleanup::cleanup_all_maps_by_timestamp;

/// Inverte il flusso in una chiave (swap di saddr/daddr e sport/dport)
fn reverse_flow_in_key(mut key: MapKey) -> MapKey {
    let tmp_addr = key.flow.saddr;
    let tmp_port = key.flow.sport;
    key.flow.saddr = key.flow.daddr;
    key.flow.sport = key.flow.dport;
    key.flow.daddr = tmp_addr;
    key.flow.dport = tmp_port;
    key
}

/// Pulisce ricorsivamente le entry SEQ e le corrispondenti entry ACK
/// Strategia:
/// - Cerca nella mappa SEQ con flow e seq_num forniti
/// - Per ogni entry trovata:
///   1. Pulisce l'entry SEQ corrente
///   2. Usa il translated_seq con flow invertito per trovare e pulire l'ACK corrispondente
///   3. Continua ricorsivamente con prev_seq
/// Nota: Le entry ACK non vengono più processate ricorsivamente (prev_seq=0)
fn cleanup_seq_recursive(
    bpf_state: &BpfState,
    seq_map_name: &str,
    ack_map_name: &str,
    mut key: MapKey,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut seq_count = 0;
    let mut ack_count = 0;
    
    loop {
        let mut loader = bpf_state.loader.lock().unwrap();
        let maps = loader.maps();
        
        let key_bytes = key.to_bytes();
        
        // Lookup nella mappa SEQ
        let value_bytes = match maps.lookup(seq_map_name, &key_bytes)? {
            Some(bytes) => bytes,
            None => {
                // Entry non trovata, fine della ricorsione
                drop(maps);
                drop(loader);
                break;
            }
        };
        
        let value = MapValue::from_bytes(&value_bytes)?;
        let prev_seq = value.prev_seq;
        let translated_seq = value.translated_seq;
        
        drop(maps);
        
        // Elimina l'entry SEQ corrente
        let mut maps_mut = loader.maps();
        maps_mut.delete(seq_map_name, &key_bytes)?;
        seq_count += 1;
        drop(maps_mut);
        drop(loader);
        
        // Pulisci l'ACK corrispondente: flow invertito + translated_seq
        // Gli ACK hanno prev_seq=0, quindi non vengono processati ricorsivamente
        let mut ack_key = reverse_flow_in_key(key.clone());
        ack_key.seq = translated_seq;
        
        let mut loader = bpf_state.loader.lock().unwrap();
        let ack_key_bytes = ack_key.to_bytes();
        
        // Verifica se esiste l'ACK entry e eliminala direttamente
        if let Ok(Some(_)) = loader.maps().lookup(ack_map_name, &ack_key_bytes) {
            drop(loader);
            let mut loader = bpf_state.loader.lock().unwrap();
            let mut maps_mut = loader.maps();
            
            if maps_mut.delete(ack_map_name, &ack_key_bytes).is_ok() {
                ack_count += 1;
            }
            drop(maps_mut);
            drop(loader);
        } else {
            drop(loader);
        }
        
        // Se prev_seq è 0, abbiamo raggiunto l'inizio (SYN)
        if prev_seq == 0 {
            break;
        }
        
        // Continua ricorsivamente con prev_seq
        key.seq = prev_seq;
    }
    
    Ok(seq_count + ack_count)
}

/// Processa una coda di flussi completati e pulisce ricorsivamente le mappe
/// Strategia:
/// - Pop dalla coda → otteniamo seq_num tradotto con flow già invertito
/// - Cerchiamo direttamente nella mappa SEQ con questi dati
/// - Puliamo ricorsivamente tutte le entry SEQ e le corrispondenti ACK
fn process_cleanup_queue(
    bpf_state: &BpfState,
    queue_name: &str,
    seq_map_name: &str,
    ack_map_name: &str,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut total_cleaned = 0;
    let mut _flows_processed = 0;
    
    loop {
        let mut loader = bpf_state.loader.lock().unwrap();
        let maps = loader.maps();
        
        // Pop dalla coda
        let key_bytes = match maps.pop_from_queue(queue_name)? {
            Some(bytes) => bytes,
            None => break,
        };
        
        // Deserializza la chiave (contiene seq_num tradotto e flow invertito)
        let key = MapKey::from_bytes(&key_bytes)?;
        _flows_processed += 1;
        
        drop(maps);
        drop(loader);
        
        // Pulisci ricorsivamente le entry SEQ e le corrispondenti ACK
        match cleanup_seq_recursive(bpf_state, seq_map_name, ack_map_name, key) {
            Ok(count) => {
                total_cleaned += count;
            }
            Err(e) => {
                eprintln!("[TRANSLATION_CLEANUP] Errore durante pulizia ricorsiva: {}", e);
            }
        }
    }
    
    Ok(total_cleaned)
}

/// Funzione principale di cleanup che processa tutte le code
fn cleanup_translation_maps(
    bpf_state: &BpfState,
    cpu_threshold: f32,
    timestamp_threshold_ns: u64,
    iteration_count: u32,
    force_cleanup_every: u32,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut total = 0;
    
    // Processa la coda completed_flow_ingress
    // Flusso completato in ingress (ACK ricevuto per FIN mandato)
    // La coda contiene translated_seq con flow già invertito
    if let Ok(count) = process_cleanup_queue(
        bpf_state,
        "completed_flow_ingress",
        "network_to_host_seq_map",
        "host_to_network_ack_map",
    ) {
        total += count;
    }
    
    // Processa la coda completed_flow_egress
    // Flusso completato in egress (ACK mandato per FIN ricevuto)
    // La coda contiene translated_seq con flow già invertito
    if let Ok(count) = process_cleanup_queue(
        bpf_state,
        "completed_flow_egress",
        "host_to_network_seq_map",
        "network_to_host_ack_map",
    ) {
        total += count;
    }
    
    let queue_cleaned = total;
    if queue_cleaned > 0 {
        println!("[CLEANUP] Completed flows cleanup: {} entries removed", queue_cleaned);
    }
    
    // Logica di pulizia aggressiva:
    // - CPU scarica: pulisci sempre in modo preventivo
    // - CPU carica: non pulire per evitare sovraccarico
    // - Ogni N iterazioni: pulizia forzata anche con CPU carica
    let cpu_usage = get_cpu_usage().unwrap_or(0.0);
    let force_cleanup = iteration_count % force_cleanup_every == 0;
    
    if cpu_usage <= cpu_threshold || force_cleanup {
        let cleaned = cleanup_all_maps_by_timestamp(bpf_state, timestamp_threshold_ns);
        total += cleaned;
    }
    
    Ok(total)
}

/// Avvia il task di cleanup periodico per le mappe di traduzione
fn start_translation_cleanup_task(
    bpf_state: Arc<BpfState>,
    interval_secs: u64,
    cpu_threshold: f32,
    timestamp_threshold_ns: u64,
    force_cleanup_every: u32,
) {
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(interval_secs));
        let mut iteration_count: u32 = 1;
        
        loop {
            interval.tick().await;
            
            match cleanup_translation_maps(
                &bpf_state,
                cpu_threshold,
                timestamp_threshold_ns,
                iteration_count,
                force_cleanup_every,
            ) {
                Ok(_) => {},
                Err(_) => {}
            }
            iteration_count = iteration_count.wrapping_add(1);
        }
    });
}

/// Fairing per avviare il task di cleanup delle traduzioni quando il server è pronto
pub struct TranslationCleanupFairing {
    pub interval_secs: u64,
    pub cpu_threshold: f32,
    pub timestamp_threshold_secs: u64,
    pub force_cleanup_every: u32,
}

#[rocket::async_trait]
impl Fairing for TranslationCleanupFairing {
    fn info(&self) -> Info {
        Info {
            name: "Translation Cleanup Task Starter",
            kind: Kind::Ignite,
        }
    }

    async fn on_ignite(&self, rocket: Rocket<Build>) -> rocket::fairing::Result {
        let bpf_state = rocket.state::<Arc<BpfState>>()
            .expect("BpfState non trovato nello stato di Rocket");
        
        // Converti secondi in nanosecondi
        let timestamp_threshold_ns = self.timestamp_threshold_secs * 1_000_000_000;
        
        start_translation_cleanup_task(
            Arc::clone(bpf_state),
            self.interval_secs,
            self.cpu_threshold,
            timestamp_threshold_ns,
            self.force_cleanup_every,
        );
        
        Ok(rocket)
    }
}
