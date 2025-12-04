use rocket::serde::Deserialize;

/// Struttura per ricevere le chiavi via JSON
#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct SecretKeys {
    pub padding_key: String,      // 64 caratteri esadecimali (32 byte)
    pub dummy_key: String,        // 64 caratteri esadecimali (32 byte)
    pub duration_seconds: u64,    // Durata validità chiavi in secondi
    pub server_port: u16,         // Porta del server
}

impl SecretKeys {
    /// Converti le chiavi esadecimali in byte array
    pub fn parse_keys(&self) -> Result<(Vec<u8>, Vec<u8>), ()> {
        let padding_key = hex_to_bytes(&self.padding_key)?;
        let dummy_key = hex_to_bytes(&self.dummy_key)?;
        
        if padding_key.len() != 32 || dummy_key.len() != 32 {
            return Err(());
        }
        
        Ok((padding_key, dummy_key))
    }
}

/// Helper per convertire stringa esadecimale in bytes
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, ()> {
    if hex.len() % 2 != 0 {
        return Err(());
    }
    
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| ()))
        .collect()
}
