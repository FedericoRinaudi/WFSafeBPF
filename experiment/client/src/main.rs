use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use libbpf_rs::{MapCore, MapHandle, RingBuffer, RingBufferBuilder};

const SERVER_ADDRESS: &str = "10.10.0.2:8080";
const BYTES_TO_SEND: usize = 90;
const BYTES_TO_RECEIVE: usize = 211;
const N_REQUESTS: usize = 5000;

const DEFAULT_RINGBUF_PIN_PATH: &str = "/sys/fs/bpf/events";

#[derive(Clone, Copy, Debug)]
struct Measurement {
    index: u64,
    duration_ns: u64,
}

fn init_ringbuf() -> (RingBuffer<'static>, Arc<Mutex<Vec<Measurement>>>, MapHandle) {
    let pin_path =
        env::var("RINGBUF_PIN_PATH").unwrap_or_else(|_| DEFAULT_RINGBUF_PIN_PATH.to_string());

    let map_handle =
        MapHandle::from_pinned_path(&pin_path).unwrap_or_else(|e| panic!("ringbuf open: {e}"));

    let storage = Arc::new(Mutex::new(Vec::<Measurement>::new()));
    let storage_cb = Arc::clone(&storage);

    let mut builder = RingBufferBuilder::new();

    builder
        .add(&map_handle as &dyn MapCore, move |data: &[u8]| {
            if data.len() >= 16 {
                let mut buf_i = [0u8; 8];
                let mut buf_dur = [0u8; 8];
                buf_i.copy_from_slice(&data[..8]);
                buf_dur.copy_from_slice(&data[8..16]);
                let index = u64::from_ne_bytes(buf_i);
                let duration = u64::from_ne_bytes(buf_dur);
                storage_cb.lock().unwrap().push(Measurement { 
                    index, 
                    duration_ns: duration 
                });
            }
            0
        })
        .unwrap();

    let rb = builder.build().unwrap();

    (rb, storage, map_handle)
}

fn drain_ringbuf(rb: &RingBuffer<'static>, store: &Arc<Mutex<Vec<Measurement>>>) -> Vec<Measurement> {
    let _ = rb.consume();
    let mut guard = store.lock().unwrap();
    guard.drain(..).collect()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let output_file = args.get(1).expect("usage: client <csv_out>").clone();

    println!("Server: {SERVER_ADDRESS}");
    println!("Target complete measurements: {N_REQUESTS}");
    println!("Output: {output_file}");

    let (ringbuf, storage, _map_handle) = init_ringbuf();

    let mut file = File::create(&output_file).expect("csv");
    writeln!(file, "0,1,2,3,4,5,6,7").unwrap();

    let mut completed_measurements = 0;
    let mut total_requests = 0;

    while completed_measurements < N_REQUESTS {
        total_requests += 1;

        let mut stream = TcpStream::connect(SERVER_ADDRESS)
            .unwrap_or_else(|e| panic!("connect: {e}"));

        let data = vec![0u8; BYTES_TO_SEND];
        stream.write_all(&data).expect("write");

        let mut response = vec![0u8; BYTES_TO_RECEIVE];
        stream.read_exact(&mut response).expect("read");

        stream.shutdown(Shutdown::Write).ok();
        let mut tmp = [0u8; 1];
        let _ = stream.read(&mut tmp);

        let samples = drain_ringbuf(&ringbuf, &storage);
        
        // Validate: must have exactly 8 samples with indices 0-7
        if samples.len() == 8 {
            let mut indices_present = [false; 8];
            let mut valid = true;
            
            for sample in &samples {
                if sample.index < 8 {
                    indices_present[sample.index as usize] = true;
                } else {
                    valid = false;
                    break;
                }
            }
            
            if valid && indices_present.iter().all(|&x| x) {
                // All indices 0-7 present exactly once
                let mut durations = [0u64; 8];
                for sample in &samples {
                    durations[sample.index as usize] = sample.duration_ns;
                }
                
                write!(file, "{}", durations[0]).ok();
                for i in 1..8 {
                    write!(file, ",{}", durations[i]).ok();
                }
                writeln!(file).ok();
                
                completed_measurements += 1;
                println!("Valid measurement {}/{} (total requests: {})", 
                         completed_measurements, N_REQUESTS, total_requests);
            } else {
                println!("Request {}: Invalid - duplicate or out-of-range indices", total_requests);
            }
        } else {
            println!("Request {}: Invalid - got {} samples, expected 8", total_requests, samples.len());
        }

        thread::sleep(Duration::from_millis(100));
    }

    println!("Done. Completed {} valid measurements out of {} total requests.", 
             N_REQUESTS, total_requests);
}
