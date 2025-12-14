use crate::config::ClientConfig;
use crate::http_client::HttpClient;
use crate::ipc_server::IpcServer;
use user::bpf::BpfLoader;
use user::{BpfState, start_translation_cleanup_task, ExperimentType, MeasurementReader, CsvWriter};
use tokio::time::{sleep, Duration};
use std::sync::{Arc, Mutex};
use tokio::signal;

/// Struttura principale del daemon
pub struct Daemon {
    config_path: String,
    config: ClientConfig,
    http_client: HttpClient,
    bpf_loader: Arc<Mutex<BpfLoader>>,
    measurement_reader: Option<Arc<MeasurementReader>>,
    csv_writer: Option<Arc<Mutex<CsvWriter>>>,
}

impl Daemon {
    /// Crea e inizializza un nuovo daemon
    pub fn new(config_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        log_info!("=== WFSafe Client Daemon ===\n");
        log_debug!("Caricamento configurazione da: {}", config_path);
        
        // Carica la configurazione iniziale
        let config = ClientConfig::from_file(config_path)?;
        log_info!("✓ Configurazione caricata: {} server configurati", config.servers.len());
        
        // Carica il programma eBPF
        log_info!("\nCaricamento programma eBPF sull'interfaccia '{}'...", config.interface);
        let loader = BpfLoader::run(&config.interface)?;
        log_info!("✓ Programma eBPF caricato con successo\n");
        let bpf_loader = Arc::new(Mutex::new(loader));
        
        // Crea il client HTTP
        let http_client = HttpClient::new();
        
        // Inizializza il lettore di misure se configurato un esperimento
        let (measurement_reader, csv_writer) = if let Some(ref exp_config) = config.experiment {
            log_info!("Configurazione esperimento rilevata:");
            log_info!("  - Tipo: {}", exp_config.experiment_type);
            log_info!("  - Nome run: {}", exp_config.run_name);
            log_info!("  - Directory risultati: {}\n", exp_config.results_dir);
            
            match exp_config.experiment_type.parse::<ExperimentType>() {
                Ok(exp_type) => {
                    let reader = Arc::new(MeasurementReader::new(exp_type));
                    let writer = CsvWriter::new(&exp_config.results_dir)
                        .map_err(|e| format!("Errore creazione CsvWriter: {}", e))?;
                    (Some(reader), Some(Arc::new(Mutex::new(writer))))
                }
                Err(e) => {
                    log_error!("⚠ Tipo di esperimento non valido: {}", e);
                    (None, None)
                }
            }
        } else {
            (None, None)
        };
        
        Ok(Self {
            config_path: config_path.to_string(),
            config,
            http_client,
            bpf_loader,
            measurement_reader,
            csv_writer,
        })
    }
    
    /// Avvia il daemon
    pub async fn run(mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Carica tutte le configurazioni in eBPF all'avvio, rinnovando quelle scadute
        self.load_initial_configs().await;
        
        // Avvia il task di cleanup delle mappe di traduzione usando i parametri di configurazione
        let bpf_state = Arc::new(BpfState {
            loader: Arc::clone(&self.bpf_loader),
        });
        let timestamp_threshold_ns = self.config.timestamp_threshold_seconds * 1_000_000_000;
        start_translation_cleanup_task(
            bpf_state,
            self.config.translation_cleanup_interval_seconds,
            self.config.cpu_threshold,
            timestamp_threshold_ns,
            self.config.force_cleanup_every,
        );
        log_debug!("✓ Task di cleanup delle mappe di traduzione avviato");
        log_debug!("  - Intervallo: {} secondi", self.config.translation_cleanup_interval_seconds);
        log_debug!("  - Soglia CPU: {}%", self.config.cpu_threshold);
        log_debug!("  - Threshold timestamp: {} secondi", self.config.timestamp_threshold_seconds);
        log_debug!("  - Cleanup forzato ogni: {} iterazioni\n", self.config.force_cleanup_every);
        
        // Avvia il task di lettura dei ringbuffer se configurato un esperimento
        if let (Some(ref reader), Some(ref writer)) = (&self.measurement_reader, &self.csv_writer) {
            self.start_measurement_task(Arc::clone(reader))?;
            self.start_periodic_save_task(Arc::clone(reader), Arc::clone(writer))?;
        }
        
        // Avvia il server IPC in un task separato
        let ipc_server = IpcServer::new(self.config_path.clone(), Arc::clone(&self.bpf_loader));
        tokio::spawn(async move {
            if let Err(e) = ipc_server.run().await {
                eprintln!("Errore nel server IPC: {}", e);
            }
        });
        
        // Aspetta un momento per assicurarsi che il socket IPC sia creato
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // Loop principale per il controllo periodico delle configurazioni con gestione dei segnali
        tokio::select! {
            result = self.main_loop() => result,
            _ = signal::ctrl_c() => {
                log_info!("\n\nRicevuto SIGINT (Ctrl+C), cleanup in corso...");
                self.cleanup();
                Ok(())
            }
            _ = Self::wait_for_sigterm() => {
                log_info!("\n\nRicevuto SIGTERM, cleanup in corso...");
                self.cleanup();
                Ok(())
            }
        }
    }
    
    /// Loop principale del daemon
    async fn main_loop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            log_debug!("--- Controllo configurazioni ---");
            
            // Ricarica il file di configurazione (potrebbe essere stato modificato)
            self.reload_config();
            
            // Controlla e aggiorna ogni server
            let config_changed = self.check_and_update_servers().await;
            
            // Salva la configurazione aggiornata se necessario
            if config_changed {
                self.save_config();
            }
            
            // Pulizia configurazioni scadute dalla mappa eBPF
            if let Ok(mut loader) = self.bpf_loader.lock() {
                match loader.cleanup_expired_configs() {
                    Ok(count) if count > 0 => {
                        log_debug!("✓ Rimosse {} configurazioni scadute dalla mappa eBPF", count);
                    }
                    Err(e) => {
                        log_error!("\n⚠ Errore nella pulizia delle configurazioni scadute: {}", e);
                    }
                    _ => {}
                }
            }
            
            log_debug!("\n--- Attesa {} secondi prima del prossimo controllo ---\n", 
                     self.config.check_interval_seconds);
            sleep(Duration::from_secs(self.config.check_interval_seconds)).await;
        }
    }
    
    /// Ricarica la configurazione dal file
    fn reload_config(&mut self) {
        match ClientConfig::from_file(&self.config_path) {
            Ok(new_config) => {
                self.config = new_config;
                log_debug!("✓ Configurazione aggiornata dal file");
            }
            Err(e) => {
                log_error!("⚠ Errore nel ricaricamento della configurazione: {}", e);
                log_error!("  Continuo con la configurazione precedente");
            }
        }
    }
    
    /// Controlla e aggiorna tutti i server configurati
    async fn check_and_update_servers(&mut self) -> bool {
        let mut config_changed = false;
        
        // Cloniamo bpf_loader per evitare problemi di borrow con il loop mutabile
        let bpf_loader = Arc::clone(&self.bpf_loader);
        
        for server in &mut self.config.servers {
            log_debug!("\nServer: {}", server.name);
            log_debug!("  Endpoint: http://{}:{}{}", server.server_ip, server.http_port, server.endpoint);
            log_debug!("  Service Port: {}", server.service_port);
            let expiration = server.last_sent_at + chrono::Duration::seconds(server.duration_seconds as i64);
            log_debug!("  Ultimo invio: {} (scade: {})", server.last_sent_at, expiration);
            
            if server.needs_renewal() {
                log_info!("  ⚠ Server '{}': chiavi scadute, rinnovo in corso...", server.name);
                
                // Genera nuove chiavi al volo (non salvate)
                let (padding_key, dummy_key) = crate::config::ServerConfig::generate_keys();
                let (padding_key_hex, dummy_key_hex) = (hex::encode(&padding_key), hex::encode(&dummy_key));
                
                // Invia la configurazione al server HTTP con le nuove chiavi
                match self.http_client.send_config_with_keys(
                    server, 
                    &padding_key_hex, 
                    &dummy_key_hex
                ).await {
                    Ok(_) => {
                        log_debug!("  ✓ Configurazione inviata al server HTTP");
                        
                        // Se l'invio ha successo, carica in eBPF con le stesse chiavi
                        if let Err(e) = Self::load_server_to_ebpf_with_keys(&bpf_loader, server, &padding_key, &dummy_key) {
                            log_error!("  ✗ Errore nel caricamento in eBPF: {}", e);
                        } else {
                            // Aggiorna il timestamp di invio
                            server.update_last_sent();
                            config_changed = true;
                            
                            let new_expiration = server.last_sent_at + chrono::Duration::seconds(server.duration_seconds as i64);
                            log_info!("  ✓ Server '{}': configurazione rinnovata con successo", server.name);
                            log_debug!("  ✓ Scade: {}", new_expiration);
                        }
                    }
                    Err(e) => {
                        log_error!("  ✗ Errore nell'invio al server '{}': {}", server.name, e);
                    }
                }
            } else {
                log_debug!("  ✓ Chiavi ancora valide");
            }
        }
        
        config_changed
    }
    
    /// Carica una singola configurazione del server in eBPF con chiavi specifiche
    fn load_server_to_ebpf_with_keys(
        bpf_loader: &Arc<Mutex<BpfLoader>>, 
        server: &crate::config::ServerConfig,
        padding_key: &[u8],
        dummy_key: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + 'static>> {
        let mut loader = bpf_loader.lock().map_err(|e| format!("Lock error: {}", e))?;
        
        let client_ip = match server.server_ip.parse::<std::net::IpAddr>() {
            Ok(ip) => ip,
            Err(e) => return Err(format!("IP non valido '{}': {}", server.server_ip, e).into()),
        };
        
        let expiration_timestamp = server.expiration_timestamp() as u64;
        let duration = expiration_timestamp.saturating_sub(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        );
        
        let bpf_config = user::models::BpfConfig::new(
            padding_key.to_vec(),
            dummy_key.to_vec(),
            duration,
            client_ip,
            server.service_port,
            server.padding_probability,
            server.dummy_probability,
            server.fragmentation_probability,
        );
        
        loader.load_config(&bpf_config)?;
        
        Ok(())
    }
    
    /// Carica tutte le configurazioni in eBPF all'avvio, inviando richieste HTTP per quelle scadute
    async fn load_initial_configs(&mut self) {
        log_info!("\nCaricamento configurazioni iniziali in eBPF...");
        let mut loaded = 0;
        let mut renewed = 0;
        
        for server in &mut self.config.servers {
            log_debug!("  ℹ {}: invio configurazione...", server.name);
            
            // Genera sempre nuove chiavi al volo (non salvate)
            let (padding_key, dummy_key) = crate::config::ServerConfig::generate_keys();
            let (padding_key_hex, dummy_key_hex) = (hex::encode(&padding_key), hex::encode(&dummy_key));
            
            // Invia la configurazione al server HTTP
            match self.http_client.send_config_with_keys(server, &padding_key_hex, &dummy_key_hex).await {
                Ok(_) => {
                    // Se l'invio ha successo, carica in eBPF con le stesse chiavi
                    match Self::load_server_to_ebpf_with_keys(&self.bpf_loader, server, &padding_key, &dummy_key) {
                        Ok(_) => {
                            // Aggiorna il timestamp di invio
                            server.update_last_sent();
                            
                            if server.needs_renewal() {
                                log_info!("  ✓ {}: configurazione rinnovata e caricata", server.name);
                                renewed += 1;
                            } else {
                                log_debug!("  ✓ {}: configurazione inviata e caricata", server.name);
                                loaded += 1;
                            }
                        }
                        Err(e) => {
                            log_error!("  ✗ {}: errore nel caricamento in eBPF: {}", server.name, e);
                        }
                    }
                }
                Err(e) => {
                    log_error!("  ✗ {}: errore nell'invio al server HTTP: {}", server.name, e);
                }
            }
        }
        
        log_info!("\n✓ Caricate {} configurazioni valide, {} rinnovate", loaded, renewed);
        
        // Salva le configurazioni aggiornate se ci sono state modifiche
        if renewed > 0 {
            self.save_config();
        }
    }
    
    /// Salva la configurazione su file
    fn save_config(&self) {
        if let Err(e) = self.config.save_to_file(&self.config_path) {
            log_error!("\n⚠ Errore nel salvataggio della configurazione: {}", e);
        } else {
            log_debug!("\n✓ Configurazione salvata su file");
        }
    }
    
    /// Attende il segnale SIGTERM (usato da systemd)
    #[cfg(unix)]
    async fn wait_for_sigterm() {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("Failed to setup SIGTERM handler");
        sigterm.recv().await;
    }
    
    #[cfg(not(unix))]
    async fn wait_for_sigterm() {
        // Su Windows non gestiamo SIGTERM
        std::future::pending::<()>().await;
    }
    
    /// Esegue il cleanup quando il daemon viene fermato
    fn cleanup(&mut self) {
        log_info!("Detaching e rimozione programma eBPF...");
        
        // Salva le misure raccolte prima di terminare
        if let (Some(ref reader), Some(ref writer)) = (&self.measurement_reader, &self.csv_writer) {
            if let Some(ref exp_config) = self.config.experiment {
                log_info!("Salvataggio finale misure raccolte...");
                let measurements = reader.get_measurements();
                if let Ok(mut w) = writer.lock() {
                    match w.write_all_measurements(
                        reader.experiment_type(),
                        &exp_config.run_name,
                        &measurements,
                    ) {
                        Ok(count) if count > 0 => {
                            log_info!("✓ Salvate {} nuove misure in {}", count, exp_config.results_dir);
                        }
                        Ok(_) => {
                            log_info!("✓ Nessuna nuova misura da salvare");
                        }
                        Err(e) => {
                            log_error!("⚠ Errore nel salvataggio delle misure: {}", e);
                        }
                    }
                }
            }
        }
        
        // Rilascia il lock e forza il drop del BpfLoader
        // Il Drop trait di BpfLoader farà automaticamente detach dei programmi TC
        drop(self.bpf_loader.lock());
        
        log_info!("✓ Programma eBPF detached e rimosso");
        log_info!("Daemon terminato");
    }
    
    /// Avvia il task per leggere i ringbuffer delle misure
    fn start_measurement_task(&self, reader: Arc<MeasurementReader>) -> Result<(), Box<dyn std::error::Error>> {
        log_info!("Avvio lettura ringbuffer per esperimento '{}'", reader.experiment_type());
        
        let bpf_loader_clone = Arc::clone(&self.bpf_loader);
        let map_names = reader.experiment_type().ringbuf_names();
        
        // Verifica che le mappe esistano
        {
            let loader = bpf_loader_clone.lock().map_err(|e| format!("Lock error: {}", e))?;
            let maps = loader.get_measurement_maps(&map_names);
            for name in &map_names {
                if maps.iter().any(|(n, _)| n == name) {
                    log_debug!("  ✓ Trovata mappa: {}", name);
                } else {
                    log_error!("  ✗ Mappa non trovata: {}", name);
                }
            }
        }
        
        // Avvia il task di polling
        tokio::task::spawn_blocking(move || {
            log_info!("✓ Task di lettura misure avviato\n");
            
            loop {
                // Lock, ottieni mappe, setup ringbuf, poll, drop
                let result = {
                    let loader = match bpf_loader_clone.lock() {
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
                    
                    let ringbuf = match reader.setup_ringbufs(&map_refs) {
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
        
        Ok(())
    }
    
    /// Avvia il task per salvare periodicamente le misure raccolte
    fn start_periodic_save_task(
        &self,
        reader: Arc<MeasurementReader>,
        writer: Arc<Mutex<CsvWriter>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let exp_config = self.config.experiment.as_ref()
            .ok_or("Experiment config not found")?
            .clone();
        
        let save_interval_secs = exp_config.save_interval_seconds;
        
        tokio::spawn(async move {
            log_info!("✓ Task di salvataggio periodico avviato (ogni {} secondi)\n", save_interval_secs);
            
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(save_interval_secs)).await;
                
                // Ottieni le misure correnti
                let measurements = reader.get_measurements();
                
                // Salva incrementalmente
                if let Ok(mut w) = writer.lock() {
                    match w.write_all_measurements(
                        reader.experiment_type(),
                        &exp_config.run_name,
                        &measurements,
                    ) {
                        Ok(count) if count > 0 => {
                            log_debug!("✓ Salvate {} nuove misure su disco", count);
                        }
                        Ok(_) => {
                            // Nessuna nuova misura, non logghiamo nulla
                        }
                        Err(e) => {
                            log_error!("⚠ Errore nel salvataggio periodico: {}", e);
                        }
                    }
                }
            }
        });
        
        Ok(())
    }
}
