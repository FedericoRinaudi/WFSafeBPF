#[macro_use] extern crate rocket;

mod config;
mod crons;
mod dtos;
mod guards;
mod models;
mod services;

use std::sync::{Arc, Mutex};
use rocket::serde::json::Json;
use rocket::http::Status;
use dtos::ClientConfig;
use guards::ClientRealAddr;
use services::ClientConfigService;
use shared::{BpfLoader, BpfState};

// Struttura per le probabilità di default
pub struct DefaultProbabilities {
    pub padding: u8,
    pub dummy: u8,
    pub fragmentation: u8,
}

// Endpoint per inserire la configurazione del client nella mappa BPF
#[post("/config", format = "json", data = "<config>")]
fn set_config(
    bpf_state: &rocket::State<Arc<BpfState>>,
    default_probs: &rocket::State<DefaultProbabilities>,
    config: Json<ClientConfig>,
    client_ip: ClientRealAddr,
) -> Result<String, Status> {
    // Parsing delle chiavi dal DTO e impostazione probabilità default
    let mut config = config.into_inner();
    println!("[CONFIG] Ricevute probabilità: padding={:?}, dummy={:?}, fragmentation={:?}", 
             config.padding_probability, config.dummy_probability, config.fragmentation_probability);
    
    config = config.with_default_probabilities(default_probs.padding, default_probs.dummy, default_probs.fragmentation);
    let (padding_prob, dummy_prob, frag_prob) = config.get_probabilities();
    println!("[CONFIG] Dopo default: padding={}, dummy={}, fragmentation={}", 
             padding_prob, dummy_prob, frag_prob);
    
    let (padding_key, dummy_key) = config.parse_keys()
        .map_err(|_| Status::BadRequest)?;
    
    // Inserimento tramite il service
    let (ip, port, expiration_time) = ClientConfigService::insert_config(
        bpf_state.inner(),
        padding_key,
        dummy_key,
        config.duration_seconds,
        client_ip.0,
        config.server_port,
        padding_prob,
        dummy_prob,
        frag_prob,
    ).map_err(|e| {
        eprintln!("Errore inserimento configurazione: {}", e);
        Status::InternalServerError
    })?;
    
    Ok(format!("Configurazione inserita correttamente per IP:porta {}:{} (scadenza: {})", ip, port, expiration_time))
}

#[launch]
fn rocket() -> _ {
    let rocket = rocket::build();
    let ifname = config::Config::get_interface(&rocket);
    
    // Leggi gli intervalli di cleanup dalla configurazione
    let keys_cleanup_interval = rocket.figment()
        .extract_inner::<u64>("keys_cleanup_interval_seconds")
        .unwrap_or(60); // Default: 60 secondi
    
    let translation_cleanup_interval = rocket.figment()
        .extract_inner::<u64>("translation_cleanup_interval_seconds")
        .unwrap_or(5); // Default: 5 secondi (più frequente per le traduzioni)
    
    // Leggi le soglie per la pulizia aggressiva
    let cpu_threshold = rocket.figment()
        .extract_inner::<f32>("cpu_threshold")
        .unwrap_or(70.0); // Default: 70%
    
    let timestamp_threshold_seconds = rocket.figment()
        .extract_inner::<u64>("timestamp_threshold_seconds")
        .unwrap_or(3600); // Default: 1 ora
    
    let force_cleanup_every = rocket.figment()
        .extract_inner::<u32>("force_cleanup_every")
        .unwrap_or(12); // Default: ogni 12 iterazioni
    
    let default_padding_probability = rocket.figment()
        .extract_inner::<u8>("default_padding_probability")
        .unwrap_or(70); // Default: 70%
    
    let default_dummy_probability = rocket.figment()
        .extract_inner::<u8>("default_dummy_probability")
        .unwrap_or(70); // Default: 70%
    
    let default_fragmentation_probability = rocket.figment()
        .extract_inner::<u8>("default_fragmentation_probability")
        .unwrap_or(70); // Default: 70%
    
    // Carica e attacca i programmi eBPF
    let bpf_loader = BpfLoader::run(&ifname).unwrap_or_else(|e| {
        panic!("Error running eBPF program: {}", e);
    });
    
    let bpf_state = Arc::new(BpfState {
        loader: Arc::new(Mutex::new(bpf_loader)),
    });
    
    let default_probabilities = DefaultProbabilities {
        padding: default_padding_probability,
        dummy: default_dummy_probability,
        fragmentation: default_fragmentation_probability,
    };
    
    rocket
        .manage(bpf_state)
        .manage(default_probabilities)
        .attach(crons::ConfigCleanupFairing { 
            interval_secs: keys_cleanup_interval 
        })
        .attach(crons::TranslationCleanupFairing { 
            interval_secs: translation_cleanup_interval,
            cpu_threshold,
            timestamp_threshold_secs: timestamp_threshold_seconds,
            force_cleanup_every,
        })
        .mount("/", routes![set_config])
}