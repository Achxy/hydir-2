use frida::{
    DeviceManager, Frida, Message, ScriptHandler, ScriptOption, ScriptRuntime, SpawnOptions,
    SpawnStdio,
};
use hydir_execution::{
    DYNAMIC_TRACE_V2_VERSION, DynamicTrace, InputSpec, TraceBudget, TraceEvent, TraceEventKind,
    TraceStatus, TraceWitness, decode_hex, input_sha256, validate_dynamic_trace,
    validate_input_spec,
};
use object::{Object, ObjectSegment, SegmentFlags};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    os::unix::{
        fs::PermissionsExt,
        io::AsRawFd,
        process::{CommandExt, ExitStatusExt},
    },
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc::{SyncSender, sync_channel},
    },
    thread,
    time::{Duration, Instant},
};

const AGENT: &str = include_str!("agent.js");
const MAX_EVENTS: usize = 4096;
const CAPTURE_TIMEOUT_MS: u64 = 10_000;

/// Keep the helper's result pipe out of the target's descriptor table. Frida's
/// Inherit mode observes the temporary stdout/stderr redirection at spawn.
struct TargetStdioRedirect {
    saved_stdout: libc::c_int,
    saved_stderr: libc::c_int,
}

impl TargetStdioRedirect {
    fn install(stdout: &fs::File, stderr: &fs::File) -> Result<Self, String> {
        std::io::stdout()
            .flush()
            .map_err(|error| error.to_string())?;
        std::io::stderr()
            .flush()
            .map_err(|error| error.to_string())?;
        let saved_stdout = unsafe { libc::dup(libc::STDOUT_FILENO) };
        if saved_stdout < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let saved_stderr = unsafe { libc::dup(libc::STDERR_FILENO) };
        if saved_stderr < 0 {
            unsafe { libc::close(saved_stdout) };
            return Err(std::io::Error::last_os_error().to_string());
        }
        let guard = Self {
            saved_stdout,
            saved_stderr,
        };
        let redirected = unsafe {
            libc::fcntl(saved_stdout, libc::F_SETFD, libc::FD_CLOEXEC) == 0
                && libc::fcntl(saved_stderr, libc::F_SETFD, libc::FD_CLOEXEC) == 0
                && libc::dup2(stdout.as_raw_fd(), libc::STDOUT_FILENO) >= 0
                && libc::dup2(stderr.as_raw_fd(), libc::STDERR_FILENO) >= 0
        };
        if !redirected {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(guard)
    }
}

impl Drop for TargetStdioRedirect {
    fn drop(&mut self) {
        unsafe {
            libc::dup2(self.saved_stdout, libc::STDOUT_FILENO);
            libc::dup2(self.saved_stderr, libc::STDERR_FILENO);
            libc::close(self.saved_stdout);
            libc::close(self.saved_stderr);
        }
    }
}

#[derive(Default)]
struct Collector {
    base: Option<u64>,
    events: Vec<RawEvent>,
    done: bool,
    lost: u64,
    errors: Vec<String>,
    received_bytes: usize,
}

struct AgentMessages {
    sender: SyncSender<Value>,
    dropped: Arc<AtomicU64>,
}

impl ScriptHandler for AgentMessages {
    fn on_message(&mut self, message: Message, _data: Option<Vec<u8>>) {
        let value = match message {
            Message::Send(sent) if sent.payload.r#type == "hydir" => sent.payload.returns,
            Message::Error(error) => serde_json::json!({
                "type": "error",
                "detail": error.description,
            }),
            Message::Log(_) => return,
            other => serde_json::json!({
                "type": "error",
                "detail": format!("unexpected Frida message: {other:?}"),
            }),
        };
        if self.sender.try_send(value).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
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
    registers: Option<BTreeMap<String, String>>,
}

fn apply_agent_record(state: &mut Collector, value: Value) -> Result<(), String> {
    let size = serde_json::to_vec(&value)
        .map_err(|error| error.to_string())?
        .len();
    if size > 1024 * 1024 {
        return Err("Frida agent event batch exceeds 1 MiB".into());
    }
    state.received_bytes = state
        .received_bytes
        .checked_add(size)
        .ok_or("Frida agent evidence size overflow")?;
    if state.received_bytes > hydir_execution::MAX_DYNAMIC_TRACE_JSON_BYTES {
        return Err("Frida agent evidence exceeds 16 MiB".into());
    }
    match value.get("type").and_then(|value| value.as_str()) {
        Some("meta") => {
            if state.base.is_some() {
                return Err("Frida agent reported multiple module bases".into());
            }
            state.base = value
                .get("base")
                .and_then(|value| value.as_str())
                .and_then(|value| parse_address(value).ok());
        }
        Some("batch") => {
            let batch: Vec<RawEvent> = serde_json::from_value(
                value
                    .get("events")
                    .cloned()
                    .ok_or("missing Frida event batch")?,
            )
            .map_err(|error| error.to_string())?;
            if batch.len() > MAX_EVENTS {
                return Err("Frida event batch exceeds cap".into());
            }
            for event in batch {
                if state.events.len() < MAX_EVENTS {
                    state.events.push(event);
                } else {
                    state.lost += 1;
                }
            }
        }
        Some("done") => {
            if state.done {
                return Err("Frida agent reported completion twice".into());
            }
            state.done = true;
            state.lost += value
                .get("lost")
                .and_then(|value| value.as_u64())
                .ok_or("invalid Frida loss count")?;
        }
        Some("error") => {
            if state.errors.len() < 16 {
                state.errors.push(
                    value
                        .get("detail")
                        .and_then(Value::as_str)
                        .unwrap_or("Frida agent error")
                        .chars()
                        .take(512)
                        .collect(),
                );
            }
        }
        _ => return Err("unknown Frida agent record".into()),
    }
    Ok(())
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
    command.args([
        "/work/.hydir-stdout",
        "/work/.hydir-stderr",
        "/work/.hydir-program",
    ]);
    command.args(argv.iter());
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
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
    let result_pipe = child.stdout.take().ok_or("Frida result pipe unavailable")?;
    let diagnostic_pipe = child
        .stderr
        .take()
        .ok_or("Frida diagnostic pipe unavailable")?;
    let result_reader = thread::spawn(move || {
        read_limited(result_pipe, hydir_execution::MAX_DYNAMIC_TRACE_JSON_BYTES)
    });
    let diagnostic_reader = thread::spawn(move || read_limited(diagnostic_pipe, 8192));
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
            let _ = result_reader.join();
            let _ = diagnostic_reader.join();
            return Err("Frida helper exceeded isolated wall-clock budget".into());
        }
        thread::sleep(Duration::from_millis(10));
    };
    let json = result_reader
        .join()
        .map_err(|_| "Frida result reader panicked")?
        .map_err(|error| error.to_string())?;
    let helper_stderr = diagnostic_reader
        .join()
        .map_err(|_| "Frida diagnostic reader panicked")?
        .map_err(|error| error.to_string())?;
    if !exit.success() {
        let stdout = fs::File::open(&stdout_path)
            .and_then(|file| file.take(4096).bytes().collect::<std::io::Result<Vec<_>>>())
            .unwrap_or_default();
        let stderr = fs::File::open(&stderr_path)
            .and_then(|file| file.take(4096).bytes().collect::<std::io::Result<Vec<_>>>())
            .unwrap_or_default();
        return Err(format!(
            "isolated Frida helper failed (exit={:?}, signal={:?}, helper={:?}, stdout={:?}, stderr={:?})",
            exit.code(),
            exit.signal(),
            String::from_utf8_lossy(&helper_stderr),
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        ));
    }
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
    if args.len() < 7 {
        return Err("invalid isolated helper arguments".into());
    }
    let offset = parse_address(&args[0])?;
    let image_base = parse_address(&args[1])?;
    let timeout_ms = args[2].parse::<u64>().map_err(|_| "invalid timeout")?;
    let input_digest = &args[3];
    if input_digest.len() != 64 || !input_digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid InputSpec digest".into());
    }
    stage("start");
    let target_stdout = fs::File::create(&args[4]).map_err(|error| error.to_string())?;
    let target_stderr = fs::File::create(&args[5]).map_err(|error| error.to_string())?;
    let program = &args[6];
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
    stage("frida initialized");
    let manager = DeviceManager::obtain(&frida);
    stage("device manager acquired");
    let mut device = manager
        .get_local_device()
        .map_err(|error| error.to_string())?;
    stage("local device acquired");
    let argv = std::iter::once(program.as_str()).chain(args[7..].iter().map(String::as_str));
    let options = SpawnOptions::new().argv(argv).stdio(SpawnStdio::Inherit);
    let redirect = TargetStdioRedirect::install(&target_stdout, &target_stderr)?;
    let spawned = device.spawn(program, &options);
    drop(redirect);
    let pid = spawned.map_err(|error| error.to_string())?;
    stage("target spawned paused");
    let result = (|| {
        let session = device.attach(pid).map_err(|error| error.to_string())?;
        stage("target attached");
        let mut script_options = ScriptOption::new().set_runtime(ScriptRuntime::QJS);
        let mut script = session
            .create_script(&source, &mut script_options)
            .map_err(|error| error.to_string())?;
        stage("script created");
        let (sender, receiver) = sync_channel(32);
        let dropped = Arc::new(AtomicU64::new(0));
        script
            .handle_message(AgentMessages {
                sender,
                dropped: Arc::clone(&dropped),
            })
            .map_err(|error| error.to_string())?;
        stage("message callback installed");
        script.load().map_err(|error| error.to_string())?;
        stage("script loaded");
        device.resume(pid).map_err(|error| error.to_string())?;
        stage("target resumed");
        let start = Instant::now();
        let mut state = Collector::default();
        while !session.is_detached() && start.elapsed() < Duration::from_millis(timeout_ms) {
            while let Ok(record) = receiver.try_recv() {
                apply_agent_record(&mut state, record)?;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let timed_out = !session.is_detached();
        stage("target detached or timed out");
        thread::sleep(Duration::from_millis(50));
        while let Ok(record) = receiver.try_recv() {
            apply_agent_record(&mut state, record)?;
        }
        state.lost = state.lost.saturating_add(dropped.load(Ordering::Relaxed));
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
                registers: raw
                    .registers
                    .as_ref()
                    .map(|registers| {
                        registers
                            .iter()
                            .map(|(name, value)| Ok((name.clone(), parse_register_value(value)?)))
                            .collect::<Result<BTreeMap<_, _>, String>>()
                    })
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
            schema_version: DYNAMIC_TRACE_V2_VERSION,
            binary_sha256: format!("{:x}", Sha256::digest(&elf)),
            input_sha256: input_digest.clone(),
            selected_elf_vaddr: selected,
            ghidra_snapshot_sha256: None,
            observer: "bubblewrap-frida-rust-message-v4".into(),
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
        std::io::stdout()
            .write_all(&json)
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

fn parse_register_value(value: &str) -> Result<u64, String> {
    let digits = value
        .strip_prefix("0x")
        .ok_or("Frida register value lacks 0x prefix")?;
    if digits.is_empty() || digits.len() > 16 {
        return Err("Frida register value exceeds 64 bits".into());
    }
    u64::from_str_radix(digits, 16).map_err(|_| "invalid Frida register value".into())
}

fn stage(label: &str) {
    eprintln!("hydir-frida stage: {label}");
}

fn read_limited<R: Read>(mut reader: R, limit: usize) -> std::io::Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Ok(output);
        }
        if output.len() <= limit {
            let remaining = limit + 1 - output.len();
            output.extend_from_slice(&buffer[..count.min(remaining)]);
        }
    }
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
