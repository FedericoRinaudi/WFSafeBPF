use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;
use std::fs;

fn main() {
    let in_path = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    ).join("..").join("eBPF").join("wfsafebpf.bpf.c");
    // Ensure we generate the skeleton inside `src/bpf/` so the crate can include it
    let mut out = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    );
    out.push("src");
    out.push("bpf");
    // Create the folder if it doesn't exist
    if let Err(e) = fs::create_dir_all(&out) {
        panic!("failed to create src/bpf directory: {}", e);
    }
    out.push("wfsafebpf_skel.rs");

    SkeletonBuilder::new()
        .source(&in_path)
        .clang_args(["-DIS_SERVER=1"])  // Define IS_SERVER=1 for server build
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={}", in_path.display());
}
