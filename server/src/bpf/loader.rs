use libbpf_rs::skel::{SkelBuilder, Skel, OpenSkel};
use libbpf_rs::{TcHookBuilder, TC_EGRESS, TC_INGRESS};
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
        let mut skel = WfsafebpfSkelBuilder::default().open(open_obj_box)?.load()?;
        // Attach the programs
        skel.attach()?;
        Ok(BpfLoader { skel, ifindex })
    }
    
    /// Ottiene un manager per gestire le operazioni sulle mappe eBPF
    pub fn maps(&mut self) -> BpfMapManager<'_> {
        // Convert from skeleton to the underlying libbpf_rs::Object
        BpfMapManager::new(self.skel.object_mut())
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
