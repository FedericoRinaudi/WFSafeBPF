use libbpf_rs::{Map, RingBufferBuilder};
use std::sync::{Arc, Mutex};
use super::ExperimentType;

/// Struttura per raccogliere le misure da un ringbuffer
pub struct MeasurementData {
    pub map_name: String,
    pub values: Vec<u64>,
}

impl MeasurementData {
    pub fn new(map_name: String) -> Self {
        Self {
            map_name,
            values: Vec::new(),
        }
    }
}

/// Reader per i ringbuffer delle misure
pub struct MeasurementReader {
    experiment_type: ExperimentType,
    measurements: Arc<Mutex<Vec<MeasurementData>>>,
}

impl MeasurementReader {
    pub fn new(experiment_type: ExperimentType) -> Self {
        let ringbuf_names = experiment_type.ringbuf_names();
        let measurements = ringbuf_names
            .iter()
            .map(|name| MeasurementData::new(name.to_string()))
            .collect();

        Self {
            experiment_type,
            measurements: Arc::new(Mutex::new(measurements)),
        }
    }

    /// Inizializza i ringbuffer da leggere
    /// Accetta un array di tuple (nome_mappa, riferimento_mappa)
    pub fn setup_ringbufs<'a>(&self, maps: &[(&str, &'a Map)]) -> Result<libbpf_rs::RingBuffer<'a>, String> {
        let mut builder = RingBufferBuilder::new();
        let ringbuf_names = self.experiment_type.ringbuf_names();

        for (idx, expected_name) in ringbuf_names.iter().enumerate() {
            // Trova la mappa corrispondente
            let map = maps
                .iter()
                .find(|(name, _)| *name == *expected_name)
                .ok_or_else(|| format!("Ringbuffer '{}' not found", expected_name))?
                .1;

            let measurements_clone = Arc::clone(&self.measurements);
            
            // Aggiungi callback per questo ringbuffer
            builder
                .add(map, move |data: &[u8]| {
                    if data.len() >= 8 {
                        // Leggi u64 dal ringbuffer
                        let value = u64::from_ne_bytes([
                            data[0], data[1], data[2], data[3],
                            data[4], data[5], data[6], data[7],
                        ]);

                        // Aggiungi ai dati raccolti
                        if let Ok(mut measurements) = measurements_clone.lock() {
                            if let Some(measurement) = measurements.get_mut(idx) {
                                measurement.values.push(value);
                            }
                        }
                    }
                    0 // Continua a processare
                })
                .map_err(|e| format!("Failed to add ringbuffer {}: {}", expected_name, e))?;
        }

        builder.build().map_err(|e| format!("Failed to build ringbuffer: {}", e))
    }

    /// Ottieni i dati raccolti finora
    pub fn get_measurements(&self) -> Vec<MeasurementData> {
        if let Ok(measurements) = self.measurements.lock() {
            measurements.clone()
        } else {
            Vec::new()
        }
    }

    /// Pulisci tutti i dati raccolti
    pub fn clear(&self) {
        if let Ok(mut measurements) = self.measurements.lock() {
            for measurement in measurements.iter_mut() {
                measurement.values.clear();
            }
        }
    }

    pub fn experiment_type(&self) -> ExperimentType {
        self.experiment_type
    }
}

impl Clone for MeasurementData {
    fn clone(&self) -> Self {
        Self {
            map_name: self.map_name.clone(),
            values: self.values.clone(),
        }
    }
}
