use libbpf_rs::MapCore;

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
}
