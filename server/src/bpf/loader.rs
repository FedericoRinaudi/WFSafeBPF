use libbpf_rs::skel::{SkelBuilder, Skel, OpenSkel};
use libbpf_rs::{TcHookBuilder, TC_EGRESS, TC_INGRESS, MapCore};
use std::os::fd::AsFd;
use std::env;

use super::maps::BpfMapManager;

// Include the generated libbpf skeleton so the types are available at compile time
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf/wfsafebpf_skel.rs"));

pub struct BpfLoader {
    skel: WfsafebpfSkel<'static>,
    ifindex: i32,
}

impl BpfLoader {
    /// Esegue il caricamento e l'attivazione dei programmi eBPF
    pub fn run(ifname: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let ifindex = nix::net::if_::if_nametoindex(ifname)? as i32;
        // Open and load the skeleton
        let open_obj_box = Box::leak(Box::new(std::mem::MaybeUninit::<libbpf_rs::OpenObject>::uninit()));
        let skel = WfsafebpfSkelBuilder::default().open(open_obj_box)?.load()?;
        
        // Attach ingress program manually using TC hook
        let mut ingress_hook = TcHookBuilder::new(skel.progs.handle_ingress.as_fd())
            .ifindex(ifindex)
            .replace(true)
            .handle(1)
            .priority(1)
            .hook(TC_INGRESS);
        
        ingress_hook.create()?;
        ingress_hook.attach()?;
        
        // Attach egress program manually using TC hook
        let mut egress_hook = TcHookBuilder::new(skel.progs.handle_egress.as_fd())
            .ifindex(ifindex)
            .replace(true)
            .handle(1)
            .priority(1)
            .hook(TC_EGRESS);
        
        egress_hook.create()?;
        egress_hook.attach()?;
        
        println!("Programmi eBPF attaccati correttamente a {}", ifname);
        
        Ok(BpfLoader { skel, ifindex })
    }
    
    /// Ottiene un manager per gestire le operazioni sulle mappe eBPF
    pub fn maps(&mut self) -> BpfMapManager<'_> {
        // Convert from skeleton to the underlying libbpf_rs::Object
        BpfMapManager::new(self.skel.object_mut())
    }
    
    /// Conta le entry in una mappa (solo lettura)
    pub fn count_map_entries(&self, map_name: &str) -> Result<usize, Box<dyn std::error::Error>> {
        use std::os::fd::AsRawFd;
        
        let map = self.skel.object()
            .maps()
            .find(|m| m.name().to_string_lossy() == map_name)
            .ok_or_else(|| format!("Mappa '{}' non trovata", map_name))?;
        
        let key_size = map.key_size() as usize;
        let mut count = 0;
        let mut current_key: Option<Vec<u8>> = None;
        
        loop {
            let mut next_key = vec![0u8; key_size];
            let result = unsafe {
                libbpf_rs::libbpf_sys::bpf_map_get_next_key(
                    map.as_fd().as_raw_fd(),
                    current_key.as_ref().map_or(std::ptr::null(), |k| k.as_ptr() as *const std::ffi::c_void),
                    next_key.as_mut_ptr() as *mut std::ffi::c_void,
                )
            };
            
            if result == 0 {
                count += 1;
                current_key = Some(next_key);
            } else {
                break;
            }
        }
        
        Ok(count)
    }
    
    /// Legge tutte le chiavi di una mappa (solo lettura)
    pub fn read_map_keys(&self, map_name: &str) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
        use std::os::fd::AsRawFd;
        
        let map = self.skel.object()
            .maps()
            .find(|m| m.name().to_string_lossy() == map_name)
            .ok_or_else(|| format!("Mappa '{}' non trovata", map_name))?;
        
        let key_size = map.key_size() as usize;
        let mut keys = Vec::new();
        let mut current_key: Option<Vec<u8>> = None;
        
        loop {
            let mut next_key = vec![0u8; key_size];
            let result = unsafe {
                libbpf_rs::libbpf_sys::bpf_map_get_next_key(
                    map.as_fd().as_raw_fd(),
                    current_key.as_ref().map_or(std::ptr::null(), |k| k.as_ptr() as *const std::ffi::c_void),
                    next_key.as_mut_ptr() as *mut std::ffi::c_void,
                )
            };
            
            if result == 0 {
                keys.push(next_key.clone());
                current_key = Some(next_key);
            } else {
                break;
            }
        }
        
        Ok(keys)
    }
    
    /// Legge un valore da una mappa (solo lettura)
    pub fn read_map_value(&self, map_name: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        let map = self.skel.object()
            .maps()
            .find(|m| m.name().to_string_lossy() == map_name)
            .ok_or_else(|| format!("Mappa '{}' non trovata", map_name))?;
        
        Ok(map.lookup(key, libbpf_rs::MapFlags::ANY)?)
    }
    
    /// Detach un programma TC ingress
    pub fn detach_ingress<F: AsFd>(&self, prog_fd: &F) -> Result<(), Box<dyn std::error::Error>> {
        let mut hook = TcHookBuilder::new(prog_fd.as_fd())
            .ifindex(self.ifindex)
            .replace(true)
            .handle(1)
            .priority(1)
            .hook(TC_INGRESS);
        
        hook.detach()?;
        hook.destroy()?;
        Ok(())
    }
    
    /// Detach un programma TC egress
    pub fn detach_egress<F: AsFd>(&self, prog_fd: &F) -> Result<(), Box<dyn std::error::Error>> {
        let mut hook = TcHookBuilder::new(prog_fd.as_fd())
            .ifindex(self.ifindex)
            .replace(true)
            .handle(1)
            .priority(1)
            .hook(TC_EGRESS);
        
        hook.detach()?;
        hook.destroy()?;
        Ok(())
    }
}

impl Drop for BpfLoader {
    fn drop(&mut self) {
        let _ = self.detach_ingress(&self.skel.progs.handle_ingress);
        let _ = self.detach_egress(&self.skel.progs.handle_egress);
    }
}
