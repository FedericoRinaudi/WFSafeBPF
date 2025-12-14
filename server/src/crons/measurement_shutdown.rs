use rocket::fairing::{Fairing, Info, Kind};
use rocket::{Rocket, Orbit};
use crate::MeasurementManager;

pub struct MeasurementShutdownFairing;

#[rocket::async_trait]
impl Fairing for MeasurementShutdownFairing {
    fn info(&self) -> Info {
        Info {
            name: "Measurement Shutdown Handler",
            kind: Kind::Shutdown,
        }
    }

    async fn on_shutdown(&self, rocket: &Rocket<Orbit>) {
        if let Some(manager) = rocket.state::<MeasurementManager>() {
            println!("Salvataggio finale misure raccolte...");
            let measurements = manager.reader.get_measurements();
            if let Ok(mut w) = manager.writer.lock() {
                match w.write_all_measurements(
                    manager.reader.experiment_type(),
                    &manager.run_name,
                    &measurements,
                ) {
                    Ok(count) if count > 0 => {
                        println!("✓ Salvate {} nuove misure in {:?}", count, w.results_dir());
                    }
                    Ok(_) => {
                        println!("✓ Nessuna nuova misura da salvare");
                    }
                    Err(e) => {
                        eprintln!("⚠ Errore nel salvataggio delle misure: {}", e);
                    }
                }
            }
        }
    }
}
