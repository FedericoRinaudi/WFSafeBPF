use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, Shutdown};
use std::thread;
use std::os::unix::io::AsRawFd;

const BIND_ADDRESS: &str = "0.0.0.0:8080";

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

fn handle_client(mut stream: TcpStream) {
    println!("Nuova connessione da: {}", stream.peer_addr().unwrap());
    
    // Imposta TCP_NODELAY per inviare immediatamente i dati senza buffering
    stream.set_nodelay(true).ok();
    
    // Disabilita TCP_QUICKACK subito, prima di qualsiasi I/O
    set_tcp_quickack(&stream, false);
    
    let mut buffer = vec![0u8; 65536]; // Buffer di 64KB per ricevere dati
    
    let bytes_to_receive = 90; //+ 54 di header fissi
    
    match stream.read_exact(&mut buffer[..bytes_to_receive]) {
        Ok(_) => {
            //println!("Ricevuti {} bytes", bytes_to_receive);
        },
        Err(e) => {
            eprintln!("Errore nella lettura: {}", e);
            return;
        }
    }
    
    let bytes_to_send = 211; //+ 54 di header fissi
    
    // Invia la risposta
    let response = vec![0u8; bytes_to_send];
    match stream.write_all(&response) {
        Ok(_) => {
            //println!("Inviati {} bytes in risposta", bytes_to_send);
        },
        Err(e) => {
            eprintln!("Errore nell'invio: {}", e);
            return;
        }
    }
    
    // Aspetta il FIN dal client leggendo fino a EOF
    let mut buf = [0u8; 1];
    let _ = stream.read(&mut buf); // Legge fino a quando il client chiude (FIN)
    
    // Chiudi solo la scrittura per inviare FIN-ACK
    // SO_LINGER si occuperà di aspettare che il FIN venga confermato
    let _ = stream.shutdown(Shutdown::Write);
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