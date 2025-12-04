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
    
    // Leggi l'intervallo di cleanup dalla configurazione
    let cleanup_interval = rocket.figment()
        .extract_inner::<u64>("cleanup_interval_seconds")
        .unwrap_or(60); // Default: 60 secondi
    
    // Carica e attacca i programmi eBPF
    let bpf_loader = bpf::BpfLoader::run(&ifname).unwrap_or_else(|e| {
        panic!("Error running eBPF program: {}", e);
    });
    
    let bpf_state = Arc::new(BpfState {
        loader: Mutex::new(bpf_loader),
    });
    
    rocket
        .manage(bpf_state)
        .attach(crons::CleanupFairing { interval_secs: cleanup_interval })
        .mount("/", routes![set_keys])
}