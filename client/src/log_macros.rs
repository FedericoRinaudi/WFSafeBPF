/// Macro per il logging condizionale basato sul profilo di compilazione
/// In debug: stampa tutti i log
/// In release: stampa solo errori e operazioni critiche

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        println!($($arg)*);
    };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        println!($($arg)*);
    };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        eprintln!($($arg)*);
    };
}
