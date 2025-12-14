use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

const SERVER_ADDRESS: &str = match option_env!("CLIENT_SERVER_ADDRESS") {
    Some(addr) => addr,
    None => "127.0.0.1:8080",
};

const BYTES_TO_SEND: usize = match option_env!("CLIENT_BYTES_TO_SEND") {
    Some(s) => match const_parse_usize(s) {
        Some(n) => n,
        None => 1024,
    },
    None => 1024,
};

const BYTES_TO_RECEIVE: usize = match option_env!("CLIENT_BYTES_TO_RECEIVE") {
    Some(s) => match const_parse_usize(s) {
        Some(n) => n,
        None => 2048,
    },
    None => 2048,
};

const N_REQUESTS: usize = match option_env!("CLIENT_N_REQUESTS") {
    Some(s) => match const_parse_usize(s) {
        Some(n) => n,
        None => 100,
    },
    None => 100,
};

const fn const_parse_usize(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    
    let mut result: usize = 0;
    let mut i = 0;
    while i < bytes.len() {
        let digit = bytes[i];
        if digit < b'0' || digit > b'9' {
            return None;
        }
        result = result * 10 + (digit - b'0') as usize;
        i += 1;
    }
    Some(result)
}

fn main() {
    println!("Connessione a {}", SERVER_ADDRESS);
    println!("Configurazione:");
    println!("  - Bytes da inviare: {}", BYTES_TO_SEND);
    println!("  - Bytes da ricevere: {}", BYTES_TO_RECEIVE);
    println!("  - Numero totale richieste: {}", N_REQUESTS);
    println!("  - Nuova connessione per ogni richiesta");
    println!();
    
    for i in 0..N_REQUESTS {
        // Crea una nuova connessione per ogni richiesta
        let mut stream = match TcpStream::connect(SERVER_ADDRESS) {
            Ok(stream) => stream,
            Err(e) => {
                eprintln!("Errore nella connessione: {}", e);
                continue;
            }
        };
        
        // Prepara i dati da inviare
        let data = vec![0u8; BYTES_TO_SEND];
        
        // Invia prima la dimensione dei dati (4 bytes)
        let size_bytes = (BYTES_TO_SEND as u32).to_be_bytes();
        if let Err(e) = stream.write_all(&size_bytes) {
            eprintln!("Errore nell'invio della dimensione: {}", e);
            continue;
        }
        
        // Invia i dati
        if let Err(e) = stream.write_all(&data) {
            eprintln!("Errore nell'invio dei dati: {}", e);
            continue;
        }
        
        // Invia quanti bytes vogliamo ricevere in risposta
        let response_size_bytes = (BYTES_TO_RECEIVE as u32).to_be_bytes();
        if let Err(e) = stream.write_all(&response_size_bytes) {
            eprintln!("Errore nell'invio della dimensione risposta: {}", e);
            continue;
        }
        
        // Ricevi la risposta
        let mut response = vec![0u8; BYTES_TO_RECEIVE];
        if let Err(e) = stream.read_exact(&mut response) {
            eprintln!("Errore nella ricezione: {}", e);
            continue;
        }
        
        println!("Richiesta {}/{}: inviati {} bytes, ricevuti {} bytes", 
                 i + 1, N_REQUESTS, BYTES_TO_SEND, BYTES_TO_RECEIVE);
        
        // La connessione viene chiusa automaticamente quando stream esce dallo scope
        
        // Aspetta 0.1s prima della prossima richiesta
        thread::sleep(Duration::from_millis(100));
    }
    
    println!("\nCompletate tutte le {} richieste", N_REQUESTS);
}
