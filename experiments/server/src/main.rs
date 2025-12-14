use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

const BIND_ADDRESS: &str = match option_env!("SERVER_BIND_ADDRESS") {
    Some(addr) => addr,
    None => "0.0.0.0:8080",
};

fn handle_client(mut stream: TcpStream) {
    println!("Nuova connessione da: {}", stream.peer_addr().unwrap());
    
    let mut buffer = vec![0u8; 65536]; // Buffer di 64KB per ricevere dati
    
    loop {
        // Leggi prima 4 bytes per sapere quanti bytes aspettarsi
        let mut size_buf = [0u8; 4];
        match stream.read_exact(&mut size_buf) {
            Ok(_) => {},
            Err(_) => {
                println!("Client disconnesso");
                break;
            }
        }
        
        let bytes_to_receive = u32::from_be_bytes(size_buf) as usize;
        
        // Leggi i dati del client
        if bytes_to_receive > buffer.len() {
            buffer.resize(bytes_to_receive, 0);
        }
        
        match stream.read_exact(&mut buffer[..bytes_to_receive]) {
            Ok(_) => {
                println!("Ricevuti {} bytes", bytes_to_receive);
            },
            Err(e) => {
                eprintln!("Errore nella lettura: {}", e);
                break;
            }
        }
        
        // Leggi quanti bytes rispondere (prossimi 4 bytes)
        let mut response_size_buf = [0u8; 4];
        match stream.read_exact(&mut response_size_buf) {
            Ok(_) => {},
            Err(_) => {
                println!("Client disconnesso");
                break;
            }
        }
        
        let bytes_to_send = u32::from_be_bytes(response_size_buf) as usize;
        
        // Invia la risposta
        let response = vec![0u8; bytes_to_send];
        match stream.write_all(&response) {
            Ok(_) => {
                println!("Inviati {} bytes in risposta", bytes_to_send);
            },
            Err(e) => {
                eprintln!("Errore nell'invio: {}", e);
                break;
            }
        }
    }
}

fn main() {
    let listener = TcpListener::bind(BIND_ADDRESS).unwrap();
    println!("Server in ascolto su {}", BIND_ADDRESS);
    
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(|| {
                    handle_client(stream);
                });
            }
            Err(e) => {
                eprintln!("Errore nella connessione: {}", e);
            }
        }
    }
}
