use std::mem;

/// Struttura chiave per la mappa BPF (corrisponde a struct client_config_key in C)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ClientConfigKey {
    pub ip_addr: u32,
    pub server_port: u16,
    _padding: u16,  // Padding esplicito per allineamento a 8 bytes
}

impl ClientConfigKey {
    pub fn new(ip_addr: u32, server_port: u16) -> Self {
        Self { 
            ip_addr, 
            server_port,
            _padding: 0,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const Self as *const u8,
                mem::size_of::<Self>()
            )
        }
    }
}

/// Struttura valore per la mappa BPF (corrisponde a struct client_config in C)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ClientConfigValue {
    pub padding_key: [u8; 32],
    pub dummy_key: [u8; 32],
    pub expiration_time: u64,
    pub padding_probability: u8,
    pub dummy_probability: u8,
    pub fragmentation_probability: u8,
}

impl ClientConfigValue {
    pub fn new(
        padding_key: &[u8],
        dummy_key: &[u8],
        expiration_time: u64,
        padding_probability: u8,
        dummy_probability: u8,
        fragmentation_probability: u8,
    ) -> Self {
        let mut value = Self {
            padding_key: [0u8; 32],
            dummy_key: [0u8; 32],
            expiration_time,
            padding_probability,
            dummy_probability,
            fragmentation_probability,
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
            return Err("Lunghezza byte non valida per ClientConfigValue");
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
    fn test_client_config_key_size() {
        // Verifica che la dimensione sia 8 bytes (4 IP + 2 port + 2 padding)
        assert_eq!(mem::size_of::<ClientConfigKey>(), 8);
    }

    #[test]
    fn test_client_config_value_size() {
        // Verifica che la dimensione sia 75 bytes (32 + 32 + 8 + 1 + 1 + 1)
        assert_eq!(mem::size_of::<ClientConfigValue>(), 75);
    }

    #[test]
    fn test_client_config_value_expiration() {
        let value = ClientConfigValue::new(&[0u8; 32], &[0u8; 32], 100, 70, 70, 70);
        assert!(!value.is_expired(50));
        assert!(value.is_expired(150));
    }
}
