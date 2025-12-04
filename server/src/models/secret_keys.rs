use std::mem;

/// Struttura chiave per la mappa BPF (corrisponde a struct secret_keys_key in C)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SecretKeysKey {
    pub ip_addr: u32,
    pub server_port: u16,
    // Il padding di 2 bytes viene gestito automaticamente dal compilatore con #[repr(C)]
}

impl SecretKeysKey {
    pub fn new(ip_addr: u32, server_port: u16) -> Self {
        Self { ip_addr, server_port }
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const Self as *const u8,
                mem::size_of::<Self>()
            )
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != mem::size_of::<Self>() {
            return Err("Lunghezza byte non valida per SecretKeysKey");
        }
        
        let key = unsafe {
            std::ptr::read(bytes.as_ptr() as *const Self)
        };
        Ok(key)
    }
}

/// Struttura valore per la mappa BPF (corrisponde a struct secret_keys in C)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SecretKeysValue {
    pub padding_key: [u8; 32],
    pub dummy_key: [u8; 32],
    pub expiration_time: u64,
}

impl SecretKeysValue {
    pub fn new(padding_key: &[u8], dummy_key: &[u8], expiration_time: u64) -> Self {
        let mut value = Self {
            padding_key: [0u8; 32],
            dummy_key: [0u8; 32],
            expiration_time,
        };
        value.padding_key.copy_from_slice(padding_key);
        value.dummy_key.copy_from_slice(dummy_key);
        value
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const Self as *const u8,
                mem::size_of::<Self>()
            )
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != mem::size_of::<Self>() {
            return Err("Lunghezza byte non valida per SecretKeysValue");
        }
        
        let value = unsafe {
            std::ptr::read(bytes.as_ptr() as *const Self)
        };
        Ok(value)
    }

    /// Verifica se le chiavi sono scadute
    pub fn is_expired(&self, current_time: u64) -> bool {
        self.expiration_time < current_time
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_keys_key_size() {
        // Verifica che la dimensione sia 8 bytes (4 IP + 2 port + 2 padding)
        assert_eq!(mem::size_of::<SecretKeysKey>(), 8);
    }

    #[test]
    fn test_secret_keys_value_size() {
        // Verifica che la dimensione sia 72 bytes (32 + 32 + 8)
        assert_eq!(mem::size_of::<SecretKeysValue>(), 72);
    }

    #[test]
    fn test_secret_keys_value_expiration() {
        let value = SecretKeysValue::new(&[0u8; 32], &[0u8; 32], 100);
        assert!(!value.is_expired(50));
        assert!(value.is_expired(150));
    }
}
