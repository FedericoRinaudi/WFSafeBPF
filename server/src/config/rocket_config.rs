use rocket::Rocket;

pub struct Config;

impl Config {
    /// Legge l'interfaccia di rete dalla configurazione Rocket
    pub fn get_interface(rocket: &Rocket<rocket::Build>) -> String {
        let ifname: String = rocket
            .figment()
            .extract_inner("iface")
            .unwrap_or_else(|_| {
                log_debug!("Configurazione 'iface' non trovata, usando 'lo' come default");
                "lo".to_string()
            });
        
        log_info!("Interfaccia di rete configurata: {}", ifname);
        ifname
    }
    
}
