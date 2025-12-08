use std::net::IpAddr;
use std::sync::Arc;
use crate::BpfState;
use user::models::BpfConfig;

/// Servizio per gestire l'inserimento della configurazione client nella mappa BPF
pub struct ClientConfigService;

impl ClientConfigService {
    /// Inserisce la configurazione nella mappa BPF per un determinato IP e porta server
    pub fn insert_config(
        bpf_state: &Arc<BpfState>,
        config: BpfConfig,
    ) -> Result<(IpAddr, u16, u64), Box<dyn std::error::Error>> {
        let expiration_time = config.calculate_expiration()?;
        let client_ip = config.client_ip;
        let server_port = config.server_port;
        
        // Inserisci nella mappa BPF usando il metodo di BpfLoader
        let mut loader = bpf_state.loader.lock().unwrap();
        loader.load_config(&config)?;
        
        Ok((client_ip, server_port, expiration_time))
    }
}
