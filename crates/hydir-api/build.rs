fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    // Cargo build scripts run before the compiler and set this only for the
    // current build-script process. No application runtime environment changes.
    unsafe { std::env::set_var("PROTOC", protoc) };
    tonic_prost_build::compile_protos("proto/hydir.proto")?;
    tonic_prost_build::compile_protos("proto/hydir_v2.proto")?;
    println!("cargo:rerun-if-changed=proto/hydir.proto");
    println!("cargo:rerun-if-changed=proto/hydir_v2.proto");
    Ok(())
}
