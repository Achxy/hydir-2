fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    // Cargo build scripts run before the compiler and set this only for the
    // current build-script process. No application runtime environment changes.
    unsafe { std::env::set_var("PROTOC", protoc) };
    let schemas = [
        "proto/hydir.proto",
        "proto/hydir_v2.proto",
        "proto/hydir_interchange/specification.proto",
        "proto/hydir_interchange/service.proto",
        "proto/hydir_patch/service.proto",
    ];
    tonic_prost_build::configure()
        // Deterministic HydIR interchange re-encoding requires ordered protobuf maps.
        // Keep the existing HydIR v1/v2 generated Rust field types unchanged.
        .btree_map(".hydir.interchange")
        .compile_protos(&schemas, &["proto"])?;
    for schema in schemas {
        println!("cargo:rerun-if-changed={schema}");
    }
    println!("cargo:rerun-if-changed=proto/NOTICE.md");
    Ok(())
}
