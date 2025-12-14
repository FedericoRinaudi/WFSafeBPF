#[macro_use] extern crate rocket;

#[macro_use]
mod log_macros;

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
use user::{BpfLoader, BpfState, ExperimentType, MeasurementReader, CsvWriter};

// Struttura per le probabilità di default
pub struct DefaultProbabilities {
    pub padding: u8,
    pub dummy: u8,
    pub fragmentation: u8,
}

// Struttura per gestire le misure di performance
pub struct MeasurementManager {
    pub reader: Arc<MeasurementReader>,
    pub writer: Arc<Mutex<CsvWriter>>,
    pub run_name: String,
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
    log_debug!("[CONFIG] Ricevute probabilità: padding={:?}, dummy={:?}, fragmentation={:?}", 
             config.padding_probability, config.dummy_probability, config.fragmentation_probability);
    
    config = config.with_default_probabilities(default_probs.padding, default_probs.dummy, default_probs.fragmentation);
    let (padding_prob, dummy_prob, frag_prob) = config.get_probabilities();
    log_debug!("[CONFIG] Dopo default: padding={}, dummy={}, fragmentation={}", 
             padding_prob, dummy_prob, frag_prob);
    
    let (padding_key, dummy_key) = config.parse_keys()
        .map_err(|_| Status::BadRequest)?;
    
    // Crea la configurazione BPF
    let bpf_config = user::models::BpfConfig::new(
        padding_key,
        dummy_key,
        config.duration_seconds,
        client_ip.0,
        config.server_port,
        padding_prob,
        dummy_prob,
        frag_prob,
    );
    
    // Inserimento tramite il service
    let (ip, port, expiration_time) = ClientConfigService::insert_config(
        bpf_state.inner(),
        bpf_config,
    ).map_err(|e| {
        log_error!("Errore inserimento configurazione: {}", e);
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
    
    // Leggi configurazione esperimento (opzionale)
    let experiment_type = rocket.figment()
        .extract_inner::<String>("experiment_type")
        .ok();
    let experiment_run_name = rocket.figment()
        .extract_inner::<String>("experiment_run_name")
        .unwrap_or_else(|_| "default_run".to_string());
    let experiment_results_dir = rocket.figment()
        .extract_inner::<String>("experiment_results_dir")
        .unwrap_or_else(|_| "./results".to_string());
    
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
    
    // Setup misure se configurato un esperimento
    let measurement_manager = if let Some(exp_type_str) = experiment_type {
        println!("Configurazione esperimento rilevata:");
        println!("  - Tipo: {}", exp_type_str);
        println!("  - Nome run: {}", experiment_run_name);
        println!("  - Directory risultati: {}", experiment_results_dir);
        
        match exp_type_str.parse::<ExperimentType>() {
            Ok(exp_type) => {
                let reader = Arc::new(MeasurementReader::new(exp_type));
                match CsvWriter::new(&experiment_results_dir) {
                    Ok(writer) => {
                        // Verifica che le mappe esistano
                        {
                            let loader = bpf_state.loader.lock().unwrap();
                            let map_names = exp_type.ringbuf_names();
                            let maps = loader.get_measurement_maps(&map_names);
                            
                            for name in &map_names {
                                if maps.iter().any(|(n, _)| n == name) {
                                    println!("  ✓ Trovata mappa: {}", name);
                                }
                            }
                        }
                        
                        let writer_arc = Arc::new(Mutex::new(writer));
                        let reader_clone = Arc::clone(&reader);
                        let bpf_state_clone = Arc::clone(&bpf_state);
                        
                        // Avvia task di polling
                        let map_names = exp_type.ringbuf_names();
                        std::thread::spawn(move || {
                            println!("✓ Task di lettura misure avviato\n");
                            loop {
                                // Lock, ottieni mappe, setup ringbuf, poll, drop
                                let result = {
                                    let loader = match bpf_state_clone.loader.lock() {
                                        Ok(l) => l,
                                        Err(e) => {
                                            eprintln!("Errore lock loader: {}", e);
                                            break;
                                        }
                                    };
                                    
                                    let maps = loader.get_measurement_maps(&map_names);
                                    let map_refs: Vec<(&str, &libbpf_rs::Map)> = maps.iter()
                                        .map(|(name, map)| (*name, map))
                                        .collect();
                                    
                                    let ringbuf = match reader_clone.setup_ringbufs(&map_refs) {
                                        Ok(rb) => rb,
                                        Err(e) => {
                                            eprintln!("Errore setup ringbuffer: {}", e);
                                            return;
                                        }
                                    };
                                    
                                    // Poll per 100ms, poi rilascia tutto
                                    ringbuf.poll(std::time::Duration::from_millis(100))
                                    // loader e ringbuf vengono droppati qui
                                };
                                
                                if let Err(e) = result {
                                    eprintln!("Errore nel polling del ringbuffer: {}", e);
                                    break;
                                }
                            }
                        });
                        
                        // Avvia task di salvataggio periodico
                        let reader_save = Arc::clone(&reader);
                        let writer_save = Arc::clone(&writer_arc);
                        let run_name_save = experiment_run_name.clone();
                        std::thread::spawn(move || {
                            println!("✓ Task di salvataggio periodico avviato (ogni 5 secondi)\n");
                            loop {
                                std::thread::sleep(std::time::Duration::from_secs(5));
                                
                                let measurements = reader_save.get_measurements();
                                if let Ok(mut w) = writer_save.lock() {
                                    match w.write_all_measurements(
                                        reader_save.experiment_type(),
                                        &run_name_save,
                                        &measurements,
                                    ) {
                                        Ok(count) if count > 0 => {
                                            println!("✓ Salvate {} nuove misure su disco", count);
                                        }
                                        Err(e) => {
                                            eprintln!("⚠ Errore nel salvataggio periodico: {}", e);
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        });
                        
                        Some(MeasurementManager {
                            reader,
                            writer: writer_arc,
                            run_name: experiment_run_name,
                        })
                    }
                    Err(e) => {
                        eprintln!("⚠ Errore creazione CsvWriter: {}", e);
                        None
                    }
                }
            }
            Err(e) => {
                eprintln!("⚠ Tipo di esperimento non valido: {}", e);
                None
            }
        }
    } else {
        None
    };
    
    let mut rocket_instance = rocket
        .manage(bpf_state)
        .manage(default_probabilities);
    
    if let Some(manager) = measurement_manager {
        rocket_instance = rocket_instance.manage(manager);
    }
    
    rocket_instance
        .attach(crons::ConfigCleanupFairing { 
            interval_secs: keys_cleanup_interval 
        })
        .attach(crons::TranslationCleanupFairing { 
            interval_secs: translation_cleanup_interval,
            cpu_threshold,
            timestamp_threshold_secs: timestamp_threshold_seconds,
            force_cleanup_every,
        })
        .attach(crons::MeasurementShutdownFairing)
        .mount("/", routes![set_config])
}