#[macro_use] extern crate rocket;

mod bpf;
mod config;

use std::sync::Mutex;

// Stato globale per gestire il BPF loader
pub struct BpfState {
    pub loader: Mutex<bpf::BpfLoader>,
}

#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

// Esempio di endpoint che accede alle mappe eBPF
#[get("/maps")]
fn list_maps(bpf_state: &rocket::State<BpfState>) -> String {
    let mut loader = bpf_state.loader.lock().unwrap();
    let maps = loader.maps().list();
    format!("Mappe eBPF disponibili: {:?}", maps)
}

#[launch]
fn rocket() -> _ {
    let rocket = rocket::build();
    let ifname = config::Config::get_interface(&rocket);
    // Carica e attacca i programmi eBPF
    let bpf_loader = bpf::BpfLoader::run(&ifname).unwrap_or_else(|e| {
        panic!("Error running eBPF program: {}", e);
    });
    let bpf_state = BpfState {
        loader: Mutex::new(bpf_loader),
    };
    rocket
        .manage(bpf_state)
        .mount("/", routes![index, list_maps])
}