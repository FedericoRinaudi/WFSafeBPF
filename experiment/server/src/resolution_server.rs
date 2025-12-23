use std::os::unix::io::AsRawFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const BIND_ADDRESS: &str = "0.0.0.0:8081";

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

async fn handle_client(mut stream: TcpStream) {
    let peer_addr = stream.peer_addr().unwrap();
    println!("Nuova connessione da: {}", peer_addr);
    
    // Imposta TCP_NODELAY per inviare immediatamente i dati senza buffering
    stream.set_nodelay(true).ok();
    
    // Disabilita TCP_QUICKACK subito, prima di qualsiasi I/O
    set_tcp_quickack(&stream, false);
    
    let mut buffer = vec![0u8; 65536]; // Buffer di 64KB per ricevere dati
    
    let bytes_to_receive = 90; //+ 54 di header fissi
    
    match stream.read_exact(&mut buffer[..bytes_to_receive]).await {
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
    match stream.write_all(&response).await {
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
    let _ = stream.read(&mut buf).await; // Legge fino a quando il client chiude (FIN)
    
    // Chiudi solo la scrittura per inviare FIN-ACK
    // SO_LINGER si occuperà di aspettare che il FIN venga confermato
    let _ = stream.shutdown().await;
}

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind(BIND_ADDRESS).await.unwrap();
    
    println!("Server in ascolto su {}", BIND_ADDRESS);
    
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                tokio::spawn(async move {
                    handle_client(stream).await;
                });
            }
            Err(e) => {
                eprintln!("Errore nella connessione: {}", e);
            }
        }
    }
}