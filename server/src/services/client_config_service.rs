use std::net::IpAddr;
use std::sync::Arc;
use std::time::UNIX_EPOCH;
use crate::BpfState;

/// Servizio per gestire l'inserimento della configurazione client nella mappa BPF
pub struct ClientConfigService;

impl ClientConfigService {
    /// Inserisce la configurazione nella mappa BPF per un determinato IP e porta server
    pub fn insert_config(
        bpf_state: &Arc<BpfState>,
        padding_key: Vec<u8>,
        dummy_key: Vec<u8>,
        duration_seconds: u64,
        client_ip: IpAddr,
        server_port: u16,
        padding_probability: u8,
        dummy_probability: u8,
        fragmentation_probability: u8,
    ) -> Result<(IpAddr, u16, u64), Box<dyn std::error::Error>> {
        // Ottieni l'IP sorgente del client (solo IPv4 supportato)
        let ip_u32 = match client_ip {
            IpAddr::V4(ipv4) => u32::from_be_bytes(ipv4.octets()),
            IpAddr::V6(_) => return Err("Solo IPv4 supportato".into()),
        };
        
        // Calcola il timestamp di scadenza
        let now = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)?;
        let expiration_time = now.as_secs() + duration_seconds;
        
        // Inserisci nella mappa BPF usando il metodo di BpfLoader
        let mut loader = bpf_state.loader.lock().unwrap();
        loader.load_config(
            ip_u32,
            server_port,
            &padding_key,
            &dummy_key,
            expiration_time,
            padding_probability,
            dummy_probability,
            fragmentation_probability,
        )?;
        
        Ok((client_ip, server_port, expiration_time))
    }
}
