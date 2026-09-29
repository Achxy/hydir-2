#[cfg(all(target_os = "linux", feature = "frida-runtime"))]
fn main() {
    if let Err(error) = run() {
        eprintln!("hydir-frida-observer: {error}");
        std::process::exit(1);
    }
}

#[cfg(all(target_os = "linux", feature = "frida-runtime"))]
fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() == Some("--doctor") {
        if args.next().is_some() {
            return Err("unexpected doctor arguments".into());
        }
        let _frida = unsafe { frida::Frida::obtain() };
        println!(
            "{}",
            serde_json::json!({
                "schema_version": 1,
                "frida_version": frida::Frida::version(),
                "observer": "hydir-frida-observer",
            })
        );
        return Ok(());
    }
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() == Some("--inside") {
        return hydir_frida_observer::inside(&args.collect::<Vec<_>>());
    }
    let mut args = std::env::args().skip(1);
    let binary = args
        .next()
        .ok_or("usage: hydir-frida-observer <elf> <input.json> <elf-vaddr-hex>")?;
    let input_path = args.next().ok_or("missing InputSpec path")?;
    let address = args.next().ok_or("missing ELF virtual address")?;
    if args.next().is_some() {
        return Err("unexpected arguments".into());
    }
    let elf = std::fs::read(binary).map_err(|error| error.to_string())?;
    let input_json = std::fs::read(input_path).map_err(|error| error.to_string())?;
    let input = hydir_execution::parse_input_spec(&input_json)?;
    let selected = u64::from_str_radix(address.trim_start_matches("0x"), 16)
        .map_err(|_| "ELF virtual address must be hex")?;
    let trace = hydir_frida_observer::observe(&elf, &input, selected)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&trace).map_err(|error| error.to_string())?
    );
    Ok(())
}

#[cfg(not(all(target_os = "linux", feature = "frida-runtime")))]
fn main() {
    eprintln!("Frida observation requires the Linux frida-runtime build");
    std::process::exit(1);
}
