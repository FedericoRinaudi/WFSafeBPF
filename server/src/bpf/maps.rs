use libbpf_rs::MapCore;
use std::os::fd::{AsRawFd, AsFd};

/// Wrapper per gestire le operazioni sulle mappe eBPF
pub struct BpfMapManager<'a> {
    object: &'a mut libbpf_rs::Object,
}

impl<'a> BpfMapManager<'a> {
    /// Crea un nuovo manager per le mappe eBPF
    pub fn new(object: &'a mut libbpf_rs::Object) -> Self {
        Self { object }
    }
    
    /// Elenca tutte le mappe disponibili
    pub fn list(&self) -> Vec<String> {
        self.object.maps().map(|m| m.name().to_string_lossy().to_string()).collect()
    }
    
    /// Ottiene una mappa per nome
    fn get_map(&self, name: &str) -> Result<libbpf_rs::Map<'_>, String> {
        self.object
            .maps()
            .find(|m| m.name().to_string_lossy() == name)
            .ok_or_else(|| format!("Mappa '{}' non trovata", name))
    }
    
    /// Ottiene una mappa mutabile per nome
    fn get_map_mut(&mut self, name: &str) -> Result<libbpf_rs::MapMut<'_>, String> {
        self.object
            .maps_mut()
            .find(|m| m.name().to_string_lossy() == name)
            .ok_or_else(|| format!("Mappa '{}' non trovata", name))
    }
    
    /// Inserisce o aggiorna un elemento in una mappa
    pub fn update(
        &mut self,
        map_name: &str,
        key: &[u8],
        value: &[u8],
        flags: libbpf_rs::MapFlags,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let map = self.get_map_mut(map_name)?;
        map.update(key, value, flags)?;
        Ok(())
    }
    
    /// Rimuove un elemento da una mappa
    pub fn delete(
        &mut self,
        map_name: &str,
        key: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let map = self.get_map_mut(map_name)?;
        map.delete(key)?;
        Ok(())
    }
    
    /// Legge un elemento da una mappa
    pub fn lookup(
        &self,
        map_name: &str,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        let map = self.get_map(map_name)?;
        Ok(map.lookup(key, libbpf_rs::MapFlags::ANY)?)
    }
    
    /// Ottiene la prossima chiave da una mappa
    pub fn get_next_key(
        &self,
        map_name: &str,
        current_key: Option<&[u8]>,
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        let map = self.get_map(map_name)?;
        let key_size = map.key_size() as usize;
        let mut next_key = vec![0u8; key_size];
        
        let result = unsafe {
            libbpf_rs::libbpf_sys::bpf_map_get_next_key(
                map.as_fd().as_raw_fd(),
                current_key.map_or(std::ptr::null(), |k| k.as_ptr() as *const std::ffi::c_void),
                next_key.as_mut_ptr() as *mut std::ffi::c_void,
            )
        };
        
        if result == 0 {
            Ok(Some(next_key))
        } else {
            Ok(None)
        }
    }

    /// Itera tutte le entry di una mappa
    pub fn iter_keys(
        &self,
        map_name: &str,
    ) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
        let mut keys = Vec::new();
        let mut current_key: Option<Vec<u8>> = None;
        
        loop {
            let next_key = if let Some(ref key) = current_key {
                self.get_next_key(map_name, Some(key))?
            } else {
                self.get_next_key(map_name, None)?
            };
            
            match next_key {
                Some(k) => {
                    keys.push(k.clone());
                    current_key = Some(k);
                }
                None => break,
            }
        }
        
        Ok(keys)
    }

    /// Pop un elemento da una coda BPF (BPF_MAP_TYPE_QUEUE)
    /// Usa bpf_map_lookup_and_delete_elem per prelevare e rimuovere atomicamente
    pub fn pop_from_queue(
        &self,
        queue_name: &str,
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        let map = self.get_map(queue_name)?;
        let value_size = map.value_size() as usize;
        let mut value_bytes = vec![0u8; value_size];
        
        let result = unsafe {
            libbpf_rs::libbpf_sys::bpf_map_lookup_and_delete_elem(
                map.as_fd().as_raw_fd(),
                std::ptr::null(),
                value_bytes.as_mut_ptr() as *mut std::ffi::c_void,
            )
        };
        
        if result == 0 {
            Ok(Some(value_bytes))
        } else {
            Ok(None)
        }
    }
}
