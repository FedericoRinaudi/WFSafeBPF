use std::io::{Read, Write};
use std::net::{TcpStream, Shutdown};
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};
use std::fs::OpenOptions;
use std::env;
use std::thread;

const SERVER_ADDRESS: &str = "10.10.0.2:8080";
const BYTES_TO_SEND: usize = 90; //+ 54 di headers
const BYTES_TO_RECEIVE: usize = 211; //+ 54 di headers
const N_REQUESTS: usize = 100;

fn set_tcp_quickack(stream: &TcpStream, enable: bool) {
    unsafe {
        let optval: libc::c_int = if enable { 1 } else { 0 };
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_QUICKACK,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of_val(&optval) as libc::socklen_t,
        );
    }
}

fn main() {
    // Leggi il percorso del file di output dagli argomenti
    let args: Vec<String> = env::args().collect();
    let output_file = if args.len() > 1 {
        args[1].clone()
    } else {
        eprintln!("Uso: {} <output_file>", args[0]);
        std::process::exit(1);
    };
    
    println!("Connessione a {}", SERVER_ADDRESS);
    println!("Configurazione:");
    println!("  - Bytes da inviare: {}", BYTES_TO_SEND);
    println!("  - Bytes da ricevere: {}", BYTES_TO_RECEIVE);
    let n_requests = if args.len() > 2 {
        args[2].parse::<usize>().unwrap_or(N_REQUESTS)
    } else if let Ok(value) = env::var("N_REQUESTS") {
        value.parse::<usize>().unwrap_or(N_REQUESTS)
    } else {
        N_REQUESTS
    };

    println!("  - Numero totale richieste: {}", n_requests);
    println!("  - Nuova connessione per ogni richiesta");
    println!("  - Output file: {}", output_file);
    println!();
    
    let mut rtts = Vec::with_capacity(n_requests);
    
    for i in 0..n_requests {
        // Crea una nuova connessione per ogni richiesta
        let mut stream = match TcpStream::connect(SERVER_ADDRESS) {
            Ok(stream) => stream,
            Err(e) => {
                eprintln!("Errore nella connessione: {}", e);
                continue;
            }
        };
        
        // Disabilita TCP_QUICKACK per combinare ACK con i dati
        set_tcp_quickack(&stream, false);
        
        // Prepara i dati da inviare
        let data = vec![0u8; BYTES_TO_SEND];
 
        
        // Invia i dati e inizia a misurare il tempo
        let start = Instant::now();
        
        if let Err(e) = stream.write_all(&data) {
            eprintln!("Errore nell'invio dei dati: {}", e);
            continue;
        }
        
        // Ricevi la risposta
        let mut response = vec![0u8; BYTES_TO_RECEIVE];
        if let Err(e) = stream.read_exact(&mut response) {
            eprintln!("Errore nella ricezione: {}", e);
            continue;
        }
        
        // Misura RTT (tempo tra invio e ricezione completa)
        let rtt = start.elapsed();
        rtts.push(rtt.as_micros());
        
        println!("Richiesta {}/{}: inviati {} bytes, ricevuti {} bytes, RTT: {:.3} ms", 
                 i + 1, n_requests, BYTES_TO_SEND, BYTES_TO_RECEIVE, rtt.as_secs_f64() * 1000.0);
        
        // Chiudi la scrittura per inviare FIN
        let _ = stream.shutdown(Shutdown::Write);
        
        // Aspetta il FIN dal server leggendo fino a EOF
        let mut buf = [0u8; 1];
        let _ = stream.read(&mut buf); // Legge fino a quando il server chiude (FIN)
  
        thread::sleep(Duration::from_millis(2));
    }
    
    println!("\nCompletate tutte le {} richieste", n_requests);
    
    // Calcola statistiche
    if !rtts.is_empty() {
        let sum: u128 = rtts.iter().sum();
        let avg = sum / rtts.len() as u128;
        let min = *rtts.iter().min().unwrap();
        let max = *rtts.iter().max().unwrap();
        
        println!("\nStatistiche RTT:");
        println!("  - Media: {:.3} ms", avg as f64 / 1000.0);
        println!("  - Min: {:.3} ms", min as f64 / 1000.0);
        println!("  - Max: {:.3} ms", max as f64 / 1000.0);
        
        // Scrivi risultati su file (append)
        match OpenOptions::new().create(true).append(true).open(&output_file) {
            Ok(mut file) => {
                use std::io::Write as _;
                let is_empty = file.metadata().map(|m| m.len() == 0).unwrap_or(true);
                if is_empty {
                    writeln!(file, "rtt_us").ok();
                }

                for rtt in rtts.iter() {
                    writeln!(file, "{}", rtt).ok();
                }

                println!("\n✓ Risultati salvati in: {}", output_file);
            }
            Err(e) => {
                eprintln!("✗ Errore nella scrittura del file: {}", e);
            }
        }
    }
}
