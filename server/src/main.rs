#[macro_use] extern crate rocket;

mod bpf;
mod config;
mod crons;
mod dtos;
mod guards;
mod models;
mod services;

use std::sync::{Arc, Mutex};
use rocket::serde::json::Json;
use rocket::http::Status;
use dtos::SecretKeys;
use guards::ClientRealAddr;
use services::KeysService;

// Stato globale per gestire il BPF loader
pub struct BpfState {
    pub loader: Mutex<bpf::BpfLoader>,
}

// Endpoint per inserire le chiavi secret nella mappa BPF
#[post("/keys", format = "json", data = "<keys>")]
fn set_keys(
    bpf_state: &rocket::State<Arc<BpfState>>,
    keys: Json<SecretKeys>,
    client_ip: ClientRealAddr,
) -> Result<String, Status> {
    // Parsing delle chiavi dal DTO
    let (padding_key, dummy_key) = keys.parse_keys()
        .map_err(|_| Status::BadRequest)?;
    
    // Inserimento tramite il service
    let (ip, port, expiration_time) = KeysService::insert_keys(
        bpf_state.inner(),
        padding_key,
        dummy_key,
        keys.duration_seconds,
        client_ip.0,
        keys.server_port,
    ).map_err(|e| {
        eprintln!("Errore inserimento chiavi: {}", e);
        Status::InternalServerError
    })?;
    
    Ok(format!("Chiavi inserite correttamente per IP:porta {}:{} (scadenza: {})", ip, port, expiration_time))
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
    
    // Carica e attacca i programmi eBPF
    let bpf_loader = bpf::BpfLoader::run(&ifname).unwrap_or_else(|e| {
        panic!("Error running eBPF program: {}", e);
    });
    
    let bpf_state = Arc::new(BpfState {
        loader: Mutex::new(bpf_loader),
    });
    
    rocket
        .manage(bpf_state)
        .attach(crons::KeysCleanupFairing { 
            interval_secs: keys_cleanup_interval 
        })
        .attach(crons::TranslationCleanupFairing { 
            interval_secs: translation_cleanup_interval,
            cpu_threshold,
            timestamp_threshold_secs: timestamp_threshold_seconds,
            force_cleanup_every,
        })
        .mount("/", routes![set_keys])
}