use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;
use std::fs;

fn main() {
    // Determine if we're building for client or server
    let is_server = if cfg!(feature = "server-mode") {
        1
    } else if cfg!(feature = "client-mode") {
        0
    } else {
        // If neither feature is enabled, don't build the skeleton
        return;
    };

    // Path to the eBPF source file
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set");
    let in_path = PathBuf::from(&manifest_dir)
        .join("..").join("eBPF").join("wfsafebpf.bpf.c");
    
    // Output directory: shared/src/bpf/
    let mut out = PathBuf::from(&manifest_dir).join("src").join("bpf");
    
    // Create the folder if it doesn't exist
    fs::create_dir_all(&out).expect("failed to create src/bpf directory");
    out.push("wfsafebpf_skel.rs");

    // Pass IS_SERVER flag to clang
    let clang_arg = format!("-DIS_SERVER={}", is_server);

    println!("cargo:warning=Building eBPF skeleton with IS_SERVER={}", is_server);

    SkeletonBuilder::new()
        .source(&in_path)
        .clang_args([clang_arg.as_str()])
        .build_and_generate(&out)
        .unwrap();
    
    println!("cargo:rerun-if-changed={}", in_path.display());
}
