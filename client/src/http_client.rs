use serde::Serialize;
use crate::config::ServerConfig;

/// Payload da inviare al server
#[derive(Debug, Serialize)]
pub struct ConfigPayload {
    pub padding_key: String,
    pub dummy_key: String,
    pub duration_seconds: u64,
    pub server_port: u16,
    pub padding_probability: u8,
    pub dummy_probability: u8,
    pub fragmentation_probability: u8,
}

/// Client HTTP per comunicare con i server
pub struct HttpClient {
    client: reqwest::Client,
}

impl HttpClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
    
    /// Invia la configurazione ad un server con chiavi specifiche
    pub async fn send_config_with_keys(
        &self, 
        server: &ServerConfig,
        padding_key_hex: &str,
        dummy_key_hex: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let payload = ConfigPayload {
            padding_key: padding_key_hex.to_string(),
            dummy_key: dummy_key_hex.to_string(),
            duration_seconds: server.duration_seconds,
            server_port: server.service_port,
            padding_probability: server.padding_probability,
            dummy_probability: server.dummy_probability,
            fragmentation_probability: server.fragmentation_probability,
        };
        
        let url = format!("http://{}:{}{}", server.server_ip, server.http_port, server.endpoint);
        
        let response = self.client
            .post(&url)
            .json(&payload)
            .send()
            .await?;
        
        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            Err(format!("Server restituito errore {}: {}", status, error_text).into())
        }
    }
}
