use std::io::{Read, Write};
use std::net::{TcpStream, Shutdown};
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};
use std::fs::File;
use std::env;
use tokio::task;

const SERVER_ADDRESS: &str = "10.10.0.2:8080";
const BYTES_TO_SEND: usize = 90; //+ 54 di headers
const BYTES_TO_RECEIVE: usize = 211; //+ 54 di headers
const N_REQUESTS: usize = 3000;
const N_PARALLEL_PACKETS: usize = 20;

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

// Funzione che invia un singolo pacchetto e riceve la risposta
// Restituisce il tempo impiegato per il data transfer (senza handshake)
fn send_and_receive_packet() -> Result<Duration, std::io::Error> {
    let mut stream = TcpStream::connect(SERVER_ADDRESS)?;
    
    // Disabilita TCP_QUICKACK per combinare ACK con i dati
    set_tcp_quickack(&stream, false);
    
    // Prepara i dati da inviare
    let data = vec![0u8; BYTES_TO_SEND];
    
    // Inizia la misurazione PRIMA di inviare i dati (dopo l'handshake)
    let start = Instant::now();
    
    // Invia i dati
    stream.write_all(&data)?;
    
    // Ricevi la risposta
    let mut response = vec![0u8; BYTES_TO_RECEIVE];
    stream.read_exact(&mut response)?;
    
    // Ferma la misurazione DOPO aver ricevuto l'ultimo byte
    let duration = start.elapsed();
    
    // Chiudi la scrittura per inviare FIN
    let _ = stream.shutdown(Shutdown::Write);
    
    // Aspetta il FIN dal server leggendo fino a EOF
    let mut buf = [0u8; 1];
    let _ = stream.read(&mut buf);
    
    Ok(duration)
}

#[tokio::main]
async fn main() {
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
    println!("  - Numero totale richieste: {}", N_REQUESTS);
    println!("  - Nuova connessione per ogni richiesta");
    println!("  - Output file: {}", output_file);
    println!();
    
    let mut rtts = Vec::with_capacity(N_REQUESTS);
    
    for i in 0..N_REQUESTS {
        // Crea N_PARALLEL_PACKETS task paralleli
        let mut tasks = Vec::new();
        
        for _j in 0..N_PARALLEL_PACKETS {
            let task = task::spawn_blocking(|| {
                send_and_receive_packet()
            });
            tasks.push(task);
        }
        
        // Aspetta che tutti i task completino e raccogli i tempi
        let mut all_ok = true;
        let mut durations = Vec::new();
        
        for task in tasks {
            match task.await {
                Ok(Ok(duration)) => {
                    durations.push(duration);
                },
                Ok(Err(e)) => {
                    eprintln!("Errore in un pacchetto: {}", e);
                    all_ok = false;
                },
                Err(e) => {
                    eprintln!("Errore nel task: {}", e);
                    all_ok = false;
                }
            }
        }
        
        if all_ok && !durations.is_empty() {
            // Calcola il tempo massimo (l'ultimo pacchetto a completare)
            let max_duration = durations.iter().max().unwrap();
            rtts.push(max_duration.as_micros());
            println!("Richiesta {}/{}: {} pacchetti paralleli completati, tempo massimo data transfer: {:.3} ms", 
                     i + 1, N_REQUESTS, N_PARALLEL_PACKETS, max_duration.as_secs_f64() * 1000.0);
        } else {
            eprintln!("Richiesta {}/{}: alcuni pacchetti hanno fallito", i + 1, N_REQUESTS);
        }
        
        // Aspetta 0.1s prima della prossima richiesta
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    
    println!("\nCompletate tutte le {} richieste", N_REQUESTS);
    
    // Calcola statistiche
    if !rtts.is_empty() {
        let sum: u128 = rtts.iter().sum();
        let avg = sum / rtts.len() as u128;
        let min = *rtts.iter().min().unwrap();
        let max = *rtts.iter().max().unwrap();
        
        println!("\nStatistiche tempo data transfer:");
        println!("  - Media: {:.3} ms", avg as f64 / 1000.0);
        println!("  - Min: {:.3} ms", min as f64 / 1000.0);
        println!("  - Max: {:.3} ms", max as f64 / 1000.0);
        
        // Scrivi risultati su file
        match File::create(&output_file) {
            Ok(mut file) => {
                use std::io::Write as _;
                writeln!(file, "data_transfer_time_us").ok();
                
                for (_idx, rtt) in rtts.iter().enumerate() {
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