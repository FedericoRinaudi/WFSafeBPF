use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use tokio::time;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::{Rocket, Build};
use crate::BpfState;
use crate::models::ClientConfigValue;

/// Funzione per pulire le configurazioni client scadute dalla mappa BPF
fn cleanup_expired_configs(bpf_state: &BpfState) -> Result<usize, Box<dyn std::error::Error>> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs();
    
    let mut loader = bpf_state.loader.lock().unwrap();
    let maps = loader.maps();
    
    // Itera tutte le chiavi usando il metodo aggiornato
    let all_keys = maps.iter_keys("client_config_map")?;
    let mut expired_keys: Vec<Vec<u8>> = Vec::new();
    
    // Controlla quali configurazioni sono scadute
    for key_bytes in all_keys {
        if let Some(value_bytes) = maps.lookup("client_config_map", &key_bytes)? {
            // Deserializza il valore usando il modello
            if let Ok(value) = ClientConfigValue::from_bytes(&value_bytes) {
                // Verifica se è scaduto
                if value.is_expired(now) {
                    expired_keys.push(key_bytes);
                }
            }
        }
    }
    
    // Elimina le entry scadute (ottieni maps mutabile)
    drop(maps); // Rilascia il borrow immutabile
    let mut maps_mut = loader.maps();
    
    let count = expired_keys.len();
    for key_bytes in expired_keys {
        if let Err(e) = maps_mut.delete("client_config_map", &key_bytes) {
            eprintln!("Error deleting expired config: {}", e);
        }
    }
    
    Ok(count)
}

/// Avvia il task di cleanup periodico
fn start_cleanup_task(bpf_state: Arc<BpfState>, interval_secs: u64) {
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(interval_secs));
        loop {
            interval.tick().await;
            match cleanup_expired_configs(&bpf_state) {
                Ok(count) if count > 0 => {
                    println!("[CONFIG_CLEANUP] Removed {} expired configs", count);
                }
                Ok(_) => {}
                Err(e) => {
                    eprintln!("[CONFIG_CLEANUP] Error during cleanup: {}", e);
                }
            }
        }
    });
}

/// Fairing per avviare il task di cleanup quando il server è pronto
pub struct ConfigCleanupFairing {
    pub interval_secs: u64,
}

#[rocket::async_trait]
impl Fairing for ConfigCleanupFairing {
    fn info(&self) -> Info {
        Info {
            name: "Client Config Cleanup Task Starter",
            kind: Kind::Ignite,
        }
    }

    async fn on_ignite(&self, rocket: Rocket<Build>) -> rocket::fairing::Result {
        let bpf_state = rocket.state::<Arc<BpfState>>()
            .expect("BpfState non trovato nello stato di Rocket");
        
        start_cleanup_task(Arc::clone(bpf_state), self.interval_secs);
        println!("[CONFIG_CLEANUP] Task started with interval of {} seconds", self.interval_secs);
        
        Ok(rocket)
    }
}
