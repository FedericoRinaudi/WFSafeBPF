use std::fmt;

/// Tipo di esperimento di performance, corrisponde all'enum lato eBPF
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExperimentType {
    None = 0,
    Delay = 1,
    DelayChecksum = 2,
    DelaySeqNumTrans = 3,
    DelayBlake2s = 4,
    DelayMapLookup = 5,
    DelayMapUpdate = 6,
    AddedBytes = 7,
}

impl ExperimentType {
    /// Restituisce i nomi delle mappe ringbuffer associate all'esperimento
    pub fn ringbuf_names(&self) -> Vec<&'static str> {
        match self {
            ExperimentType::None => vec![],
            ExperimentType::Delay => vec![
                "delay_ingress_events",
                "delay_egress_events",
            ],
            ExperimentType::DelayChecksum => vec![
                "checksum_delay_ingress_events",
                "checksum_delay_egress_events",
            ],
            ExperimentType::DelaySeqNumTrans => vec![
                "seq_num_trans_delay_ingress_events",
                "seq_num_trans_delay_egress_events",
            ],
            ExperimentType::DelayBlake2s => vec![
                "blake2s_delay_events",
            ],
            ExperimentType::DelayMapLookup => vec![
                "map_lookup_delay_events",
            ],
            ExperimentType::DelayMapUpdate => vec![
                "map_update_delay_events",
            ],
            ExperimentType::AddedBytes => vec![
                "dummy_added_bytes_bytes_events",
                "padding_added_bytes_bytes_events",
                "fragmentation_added_bytes_bytes_events",
            ],
        }
    }

    /// Nome descrittivo dell'esperimento per i file CSV
    pub fn experiment_name(&self) -> &'static str {
        match self {
            ExperimentType::None => "none",
            ExperimentType::Delay => "delay",
            ExperimentType::DelayChecksum => "delay_checksum",
            ExperimentType::DelaySeqNumTrans => "delay_seq_num_trans",
            ExperimentType::DelayBlake2s => "delay_blake2s",
            ExperimentType::DelayMapLookup => "delay_map_lookup",
            ExperimentType::DelayMapUpdate => "delay_map_update",
            ExperimentType::AddedBytes => "added_bytes",
        }
    }

    /// Se l'esperimento misura tempi (ns) o byte
    pub fn is_time_measurement(&self) -> bool {
        match self {
            ExperimentType::AddedBytes => false,
            ExperimentType::None => false,
            _ => true,
        }
    }
}

impl fmt::Display for ExperimentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.experiment_name())
    }
}

impl std::str::FromStr for ExperimentType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(ExperimentType::None),
            "delay" => Ok(ExperimentType::Delay),
            "delay_checksum" => Ok(ExperimentType::DelayChecksum),
            "delay_seq_num_trans" => Ok(ExperimentType::DelaySeqNumTrans),
            "delay_blake2s" => Ok(ExperimentType::DelayBlake2s),
            "delay_map_lookup" => Ok(ExperimentType::DelayMapLookup),
            "delay_map_update" => Ok(ExperimentType::DelayMapUpdate),
            "added_bytes" => Ok(ExperimentType::AddedBytes),
            _ => Err(format!("Unknown experiment type: {}", s)),
        }
    }
}
