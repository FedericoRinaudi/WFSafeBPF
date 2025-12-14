use std::fs::{self, File, OpenOptions};
use std::io::{Write, BufWriter};
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use super::{ExperimentType, ringbuf_reader::MeasurementData};

/// Writer per salvare le misure in file CSV
pub struct CsvWriter {
    results_dir: PathBuf,
    // Tiene traccia delle misure già scritte per ogni file
    written_counts: HashMap<String, usize>,
}

impl CsvWriter {
    pub fn new<P: AsRef<Path>>(results_dir: P) -> Result<Self, std::io::Error> {
        let results_dir = results_dir.as_ref().to_path_buf();
        
        // Crea la directory se non esiste
        if !results_dir.exists() {
            fs::create_dir_all(&results_dir)?;
        }

        Ok(Self { 
            results_dir,
            written_counts: HashMap::new(),
        })
    }

    /// Scrive i dati di una misura in un file CSV (append incrementale)
    /// Il nome del file sarà: {experiment_name}_{run_name}_{measure_name}.csv
    pub fn write_measurement(
        &mut self,
        experiment_type: ExperimentType,
        run_name: &str,
        measurement: &MeasurementData,
    ) -> Result<usize, std::io::Error> {
        // Estrai il nome della misura dal nome della mappa (rimuovi _events o _bytes_events)
        let measure_name = self.extract_measure_name(&measurement.map_name);
        
        // Costruisci il nome del file
        let filename = format!(
            "{}_{}_{}_{}.csv",
            experiment_type.experiment_name(),
            run_name,
            measure_name,
            if experiment_type.is_time_measurement() { "ns" } else { "bytes" }
        );
        
        let filepath = self.results_dir.join(&filename);
        
        // Determina quante misure sono già state scritte per questo file
        let already_written = *self.written_counts.get(&filename).unwrap_or(&0);
        
        // Se non ci sono nuovi dati da scrivere, ritorna 0
        if measurement.values.len() <= already_written {
            return Ok(0);
        }
        
        // Se il file non esiste, crealo con header
        let file_exists = filepath.exists();
        let mut file = if file_exists {
            OpenOptions::new().append(true).open(&filepath)?
        } else {
            let mut f = File::create(&filepath)?;
            // Scrivi header
            let unit = if experiment_type.is_time_measurement() { "time_ns" } else { "bytes" };
            writeln!(f, "{}", unit)?;
            f
        };
        
        // Scrivi solo i nuovi dati
        let mut writer = BufWriter::new(&mut file);
        let mut written = 0;
        for value in &measurement.values[already_written..] {
            writeln!(writer, "{}", value)?;
            written += 1;
        }
        writer.flush()?;
        
        // Aggiorna il contatore
        self.written_counts.insert(filename, already_written + written);
        
        Ok(written)
    }

    /// Scrive tutte le misure raccolte (append incrementale)
    /// Ritorna il numero totale di nuove misure scritte
    pub fn write_all_measurements(
        &mut self,
        experiment_type: ExperimentType,
        run_name: &str,
        measurements: &[MeasurementData],
    ) -> Result<usize, std::io::Error> {
        let mut total_written = 0;
        for measurement in measurements {
            if !measurement.values.is_empty() {
                total_written += self.write_measurement(experiment_type, run_name, measurement)?;
            }
        }
        Ok(total_written)
    }

    /// Estrae il nome della misura dal nome della mappa ringbuffer
    fn extract_measure_name(&self, map_name: &str) -> String {
        // Rimuovi i suffissi comuni
        let name = map_name
            .trim_end_matches("_events")
            .trim_end_matches("_bytes");
        
        name.to_string()
    }

    /// Ottieni il percorso della directory dei risultati
    pub fn results_dir(&self) -> &Path {
        &self.results_dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_measure_name() {
        let writer = CsvWriter::new("test_results").unwrap();
        
        assert_eq!(
            writer.extract_measure_name("delay_ingress_events"),
            "delay_ingress"
        );
        
        assert_eq!(
            writer.extract_measure_name("dummy_added_bytes_bytes_events"),
            "dummy_added_bytes"
        );
    }
}
