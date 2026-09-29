use frida::{
    DeviceManager, Frida, Message, ScriptHandler, ScriptOption, ScriptRuntime, SpawnOptions,
    SpawnStdio,
};
use hydir_execution::{
    DYNAMIC_TRACE_VERSION, DynamicTrace, InputSpec, TraceBudget, TraceEvent, TraceEventKind,
    TraceStatus, TraceWitness, decode_hex, input_sha256, validate_dynamic_trace,
    validate_input_spec,
};
use object::{Object, ObjectSegment, SegmentFlags};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, process::CommandExt},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

const AGENT: &str = include_str!("agent.js");
const MAX_EVENTS: usize = 4096;
const CAPTURE_TIMEOUT_MS: u64 = 10_000;

#[derive(Default)]
struct Collector {
    base: Option<u64>,
    events: Vec<RawEvent>,
    done: bool,
    lost: u64,
    errors: Vec<String>,
}

#[derive(Deserialize)]
struct RawWitness {
    address: String,
    bytes: Option<String>,
}

#[derive(Deserialize)]
struct RawEvent {
    kind: String,
    thread_id: u32,
    source: RawWitness,
    target: Option<RawWitness>,
}

struct Handler(Arc<Mutex<Collector>>);

impl ScriptHandler for Handler {
    fn on_message(&mut self, message: Message, _data: Option<Vec<u8>>) {
        let mut state = self.0.lock().expect("Frida collector lock poisoned");
        match message {
            Message::Log(log) => {
                if let Some(json) = log.payload.strip_prefix("HYDIR_BATCH:") {
                    match serde_json::from_str::<Vec<RawEvent>>(json) {
                        Ok(batch) if batch.len() <= MAX_EVENTS => {
                            for event in batch {
                                if state.events.len() < MAX_EVENTS {
                                    state.events.push(event);
                                } else {
                                    state.lost += 1;
                                }
                            }
                        }
                        _ => state
                            .errors
                            .push("invalid or oversized Frida event batch".into()),
                    }
                } else if let Some(json) = log.payload.strip_prefix("HYDIR_META:") {
                    #[derive(Deserialize)]
                    struct Meta {
                        base: String,
                    }
                    match serde_json::from_str::<Meta>(json)
                        .ok()
                        .and_then(|m| parse_address(&m.base).ok())
                    {
                        Some(base) => state.base = Some(base),
                        None => state.errors.push("invalid agent module base".into()),
                    }
                } else if let Some(json) = log.payload.strip_prefix("HYDIR_DONE:") {
                    #[derive(Deserialize)]
                    struct Done {
                        lost: u64,
                    }
                    match serde_json::from_str::<Done>(json) {
                        Ok(done) => {
                            state.done = true;
                            state.lost += done.lost;
                        }
                        Err(error) => state
                            .errors
                            .push(format!("invalid agent completion: {error}")),
                    }
                }
            }
            Message::Error(error) => state
                .errors
                .push(format!("Frida agent: {}", error.description)),
            Message::Other(value) => state
                .errors
                .push(format!("unexpected Frida message: {value}")),
            Message::Send(_) => state.errors.push("unexpected Frida send message".into()),
        }
        state.errors.truncate(16);
    }
}

/// Observe a selected ELF address using a helper and target in the same
/// Bubblewrap PID/user/network namespace. This is an opt-in Linux capability.
pub fn observe(elf: &[u8], input: &InputSpec, selected: u64) -> Result<DynamicTrace, String> {
    validate_input_spec(elf, input)?;
    let file = object::File::parse(elf).map_err(|error| error.to_string())?;
    if file_backed_byte(&file, elf, selected).is_none() {
        return Err("selected address is not file-backed executable ELF code".into());
    }
    if !input.stdin_hex.is_empty() {
        return Err(
            "Frida F0 currently supports argv and files; stdin observation is pending".into(),
        );
    }
    if input.budget.memory_bytes < 1024 * 1024 * 1024 {
        return Err("Frida F0 requires a 1 GiB InputSpec memory budget".into());
    }
    let argv = input
        .argv_hex
        .iter()
        .map(|hex| {
            let bytes = decode_hex(hex, 4096)?;
            if !bytes.iter().all(|byte| byte.is_ascii_graphic()) {
                return Err("Frida F0 argv must use printable ASCII".into());
            }
            String::from_utf8(bytes).map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let image_base = file
        .segments()
        .filter_map(|segment| {
            let (offset, size) = segment.file_range();
            (size > 0 && offset == 0).then_some(segment.address() & !4095)
        })
        .min()
        .or_else(|| {
            file.segments()
                .map(|segment| segment.address() & !4095)
                .min()
        })
        .ok_or("ELF has no load segments")?;
    let offset = selected
        .checked_sub(image_base)
        .ok_or("selected address precedes ELF image base")?;
    let timeout_ms = input.budget.timeout_ms.min(CAPTURE_TIMEOUT_MS);
    let scratch = tempfile::tempdir().map_err(|error| error.to_string())?;
    let program = scratch.path().join(".hydir-program");
    fs::write(&program, elf).map_err(|error| error.to_string())?;
    fs::set_permissions(&program, fs::Permissions::from_mode(0o500))
        .map_err(|error| error.to_string())?;
    for staged in &input.files {
        let path = scratch.path().join(&staged.path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        fs::write(
            &path,
            decode_hex(&staged.bytes_hex, hydir_execution::MAX_INPUT_BYTES)?,
        )
        .map_err(|error| error.to_string())?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400))
            .map_err(|error| error.to_string())?;
    }
    let helper = scratch.path().join(".hydir-observer");
    fs::copy(
        std::env::current_exe().map_err(|error| error.to_string())?,
        &helper,
    )
    .map_err(|error| error.to_string())?;
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o500))
        .map_err(|error| error.to_string())?;
    let result_path = scratch.path().join(".hydir-trace.json");
    let stdout_path = scratch.path().join(".hydir-stdout");
    let stderr_path = scratch.path().join(".hydir-stderr");
    let mut command = Command::new("bwrap");
    command.args([
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--setenv",
        "HOME",
        "/work",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "LC_ALL",
        "C",
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind-try",
        "/lib",
        "/lib",
        "--ro-bind-try",
        "/lib64",
        "/lib64",
        "--ro-bind-try",
        "/bin",
        "/bin",
        "--dir",
        "/etc",
        "--ro-bind-try",
        "/etc/ld.so.cache",
        "/etc/ld.so.cache",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--bind",
    ]);
    command.arg(scratch.path()).arg("/work");
    command.args([
        "--chdir",
        "/work",
        "--",
        "/work/.hydir-observer",
        "--inside",
    ]);
    command.arg(format!("{offset:x}"));
    command.arg(format!("{image_base:x}"));
    command.arg(timeout_ms.to_string());
    command.arg(input_sha256(input)?);
    command.args(["/work/.hydir-trace.json", "/work/.hydir-program"]);
    command.args(argv.iter());
    command.stdin(Stdio::null());
    command.stdout(Stdio::from(
        fs::File::create(&stdout_path).map_err(|error| error.to_string())?,
    ));
    command.stderr(Stdio::from(
        fs::File::create(&stderr_path).map_err(|error| error.to_string())?,
    ));
    let memory = input.budget.memory_bytes;
    let cpu_seconds = timeout_ms.div_ceil(1000).saturating_add(3);
    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            for (resource, limit) in [
                (libc::RLIMIT_AS, memory),
                (libc::RLIMIT_CPU, cpu_seconds),
                (libc::RLIMIT_CORE, 0),
                // Frida materializes its agent through a memfd. A 1 MiB file
                // limit aborts injection before the target starts.
                (libc::RLIMIT_FSIZE, 256 * 1024 * 1024),
            ] {
                let value = libc::rlimit {
                    rlim_cur: limit,
                    rlim_max: limit,
                };
                if libc::setrlimit(resource, &value) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("Bubblewrap launch failed: {error}"))?;
    let start = Instant::now();
    let timeout = Duration::from_millis(timeout_ms.saturating_add(3000));
    let exit = loop {
        if let Some(exit) = child.try_wait().map_err(|error| error.to_string())? {
            break exit;
        }
        if start.elapsed() > timeout {
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.wait();
            return Err("Frida helper exceeded isolated wall-clock budget".into());
        }
        thread::sleep(Duration::from_millis(10));
    };
    if !exit.success() {
        let stderr = fs::File::open(&stderr_path)
            .and_then(|file| file.take(4096).bytes().collect::<std::io::Result<Vec<_>>>())
            .unwrap_or_default();
        return Err(format!(
            "isolated Frida helper failed: {}",
            String::from_utf8_lossy(&stderr[..stderr.len().min(4096)])
        ));
    }
    let json =
        fs::read(result_path).map_err(|error| format!("Frida trace file missing: {error}"))?;
    let mut trace = hydir_execution::parse_dynamic_trace(&json)?;
    for path in [&stdout_path, &stderr_path] {
        if fs::metadata(path).map_err(|error| error.to_string())?.len() > input.budget.output_bytes
        {
            return Err("observed target output exceeded InputSpec budget".into());
        }
    }
    let stdout = fs::read(stdout_path).map_err(|error| error.to_string())?;
    let stderr = fs::read(stderr_path).map_err(|error| error.to_string())?;
    if stdout.len() + stderr.len() > input.budget.output_bytes as usize {
        return Err("observed target output exceeded InputSpec budget".into());
    }
    trace.stdout_hex = hydir_execution::encode_hex(&stdout);
    trace.stderr_hex = hydir_execution::encode_hex(&stderr);
    validate_dynamic_trace(elf, input, &trace)?;
    Ok(trace)
}

pub fn inside(args: &[String]) -> Result<(), String> {
    if args.len() < 6 {
        return Err("invalid isolated helper arguments".into());
    }
    let offset = parse_address(&args[0])?;
    let image_base = parse_address(&args[1])?;
    let timeout_ms = args[2].parse::<u64>().map_err(|_| "invalid timeout")?;
    let input_digest = &args[3];
    if input_digest.len() != 64 || !input_digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid InputSpec digest".into());
    }
    let result_path = &args[4];
    let program = &args[5];
    let elf = fs::read(program).map_err(|error| error.to_string())?;
    let file = object::File::parse(elf.as_slice()).map_err(|error| error.to_string())?;
    let selected = image_base.checked_add(offset).ok_or("address overflow")?;
    if file_backed_byte(&file, &elf, selected).is_none() {
        return Err("invalid selected address".into());
    }
    let source = AGENT
        .replace("__OFFSET__", &format!("0x{offset:x}"))
        .replace("__CAP__", &MAX_EVENTS.to_string());
    let frida = unsafe { Frida::obtain() };
    let manager = DeviceManager::obtain(&frida);
    let mut device = manager
        .get_local_device()
        .map_err(|error| error.to_string())?;
    let argv = std::iter::once(program.as_str()).chain(args[6..].iter().map(String::as_str));
    let options = SpawnOptions::new().argv(argv).stdio(SpawnStdio::Inherit);
    let pid = device
        .spawn(program, &options)
        .map_err(|error| error.to_string())?;
    let result = (|| {
        let session = device.attach(pid).map_err(|error| error.to_string())?;
        let mut script_options = ScriptOption::new()
            .set_name("hydir-observer")
            .set_runtime(ScriptRuntime::QJS);
        let mut script = session
            .create_script(&source, &mut script_options)
            .map_err(|error| error.to_string())?;
        let collector = Arc::new(Mutex::new(Collector::default()));
        script
            .handle_message(Handler(collector.clone()))
            .map_err(|error| error.to_string())?;
        script.load().map_err(|error| error.to_string())?;
        device.resume(pid).map_err(|error| error.to_string())?;
        let start = Instant::now();
        while !session.is_detached() && start.elapsed() < Duration::from_millis(timeout_ms) {
            thread::sleep(Duration::from_millis(10));
        }
        let timed_out = !session.is_detached();
        thread::sleep(Duration::from_millis(50));
        let state = collector.lock().map_err(|_| "collector lock poisoned")?;
        let base = state.base.ok_or("Frida agent did not report module base")?;
        let bias = base
            .checked_sub(image_base)
            .ok_or("runtime module base precedes ELF image base")?;
        let mut events = Vec::new();
        for raw in &state.events {
            let kind = match raw.kind.as_str() {
                "entry" => TraceEventKind::Entry,
                "block" => TraceEventKind::Block,
                "call" => TraceEventKind::Call,
                "exit" => TraceEventKind::Exit,
                _ => return Err("unknown Frida event kind".into()),
            };
            events.push(TraceEvent {
                sequence: events.len() as u64,
                thread_id: raw.thread_id,
                kind,
                source: normalize(&file, &elf, bias, &raw.source)?,
                target: raw
                    .target
                    .as_ref()
                    .map(|value| normalize(&file, &elf, bias, value))
                    .transpose()?,
            });
        }
        let mut diagnostics = state.errors.clone();
        if timed_out {
            diagnostics.push("isolated target exceeded Frida observation timeout".into());
        }
        let status = if timed_out {
            TraceStatus::TimedOut
        } else if !state.errors.is_empty() {
            TraceStatus::InjectionError
        } else if state.lost > 0 || events.len() >= MAX_EVENTS {
            TraceStatus::Truncated
        } else if state.done {
            TraceStatus::Completed
        } else {
            TraceStatus::Detached
        };
        let trace = DynamicTrace {
            schema_version: DYNAMIC_TRACE_VERSION,
            binary_sha256: format!("{:x}", Sha256::digest(&elf)),
            input_sha256: input_digest.clone(),
            selected_elf_vaddr: selected,
            ghidra_snapshot_sha256: None,
            observer: "bubblewrap-frida-rust-linux-v1".into(),
            frida_version: Frida::version().into(),
            agent_sha256: format!("{:x}", Sha256::digest(AGENT.as_bytes())),
            runtime_module_base: Some(base),
            elf_load_bias: Some(bias),
            budget: TraceBudget {
                max_events: MAX_EVENTS,
                timeout_ms,
            },
            status,
            lost_events: state.lost,
            stdout_hex: String::new(),
            stderr_hex: String::new(),
            diagnostics,
            events,
        };
        let json = serde_json::to_vec(&trace).map_err(|error| error.to_string())?;
        fs::File::create(result_path)
            .and_then(|mut output| output.write_all(&json))
            .map_err(|error| error.to_string())?;
        Ok(())
    })();
    let _ = device.kill(pid);
    result
}

fn parse_address(value: &str) -> Result<u64, String> {
    u64::from_str_radix(value.trim_start_matches("0x"), 16)
        .map_err(|_| "invalid hex address".into())
}

fn file_backed_byte(file: &object::File<'_>, elf: &[u8], address: u64) -> Option<u8> {
    for segment in file.segments() {
        if !matches!(segment.flags(), SegmentFlags::Elf { p_flags } if p_flags & object::elf::PF_X != 0)
        {
            continue;
        }
        let (offset, size) = segment.file_range();
        let Some(relative) = address.checked_sub(segment.address()) else {
            continue;
        };
        if relative >= size {
            continue;
        }
        return elf
            .get(usize::try_from(offset.checked_add(relative)?).ok()?)
            .copied();
    }
    None
}

fn normalize(
    file: &object::File<'_>,
    elf: &[u8],
    bias: u64,
    raw: &RawWitness,
) -> Result<TraceWitness, String> {
    let runtime_address = parse_address(&raw.address)?;
    let maybe_address = runtime_address.checked_sub(bias);
    let verified = maybe_address
        .zip(raw.bytes.as_ref())
        .and_then(|(address, hex)| {
            let bytes = decode_hex(hex, 16).ok()?;
            (!bytes.is_empty()
                && bytes.iter().enumerate().all(|(index, byte)| {
                    address
                        .checked_add(index as u64)
                        .and_then(|address| file_backed_byte(file, elf, address))
                        == Some(*byte)
                }))
            .then_some((address, hex.clone()))
        });
    Ok(TraceWitness {
        runtime_address,
        elf_vaddr: verified.as_ref().map(|value| value.0),
        original_bytes_hex: verified.map(|value| value.1),
    })
}
