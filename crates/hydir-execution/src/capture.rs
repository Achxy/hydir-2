//! Bounded single-thread GDB/MI capture inside the local Bubblewrap runner.

use crate::{
    EXECUTION_SNAPSHOT_VERSION, ExecutionSnapshot, InputSpec, MemoryMapping, MemoryPage,
    MemoryPageState, MiListEntry, MiRecord, MiValue, RegisterObservation, SnapshotStatus,
    StopPoint, decode_hex, input_sha256, parse_mi_line, validate_execution_snapshot,
    validate_input_spec,
};
use object::{Object, ObjectKind, ObjectSegment, SegmentFlags};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::{fs::PermissionsExt, process::CommandExt},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver, RecvTimeoutError},
    },
    thread,
    time::{Duration, Instant},
};

const MAX_MI_OUTPUT: u64 = 4 * 1024 * 1024;
const MAX_CONSOLE_OUTPUT: usize = 512 * 1024;
const MAX_MAPS_BYTES: usize = 128 * 1024;
const MAX_CAPTURE_PAGES: usize = 8;
const CAPTURE_MEMORY_LIMIT: u64 = 1024 * 1024 * 1024;
const MAPS_SCRIPT: &str = "import gdb\nwith open('/proc/%d/maps' % gdb.selected_inferior().pid, 'rb') as f:\n    data = f.read(131073)\nif len(data) > 131072:\n    print('HYDIR_MAPS_TOO_LARGE')\nelse:\n    print('HYDIR_MAPS:' + data.hex())\n";

#[derive(Debug)]
enum CaptureFailure {
    TimedOut,
    Runner(String),
}

impl From<String> for CaptureFailure {
    fn from(value: String) -> Self {
        Self::Runner(value)
    }
}

impl From<&str> for CaptureFailure {
    fn from(value: &str) -> Self {
        Self::Runner(value.to_owned())
    }
}

#[derive(Clone, Copy)]
enum CaptureTarget<'a> {
    Symbol(&'a str),
    ElfVaddr(u64),
}

/// Capture one symbol entry. Arbitrary-byte argv and multi-threaded state are
/// explicitly outside this first worker's scope; replay accepts broader argv.
pub fn capture_function_entry(
    elf: &[u8],
    input: &InputSpec,
    symbol: &str,
) -> Result<ExecutionSnapshot, String> {
    capture_target(elf, input, CaptureTarget::Symbol(symbol))
}

/// Capture at a file-backed executable ELF virtual address, including in a
/// stripped PIE. The runtime address is resolved after starting the inferior.
pub fn capture_elf_address(
    elf: &[u8],
    input: &InputSpec,
    elf_vaddr: u64,
) -> Result<ExecutionSnapshot, String> {
    capture_target(elf, input, CaptureTarget::ElfVaddr(elf_vaddr))
}

fn capture_target(
    elf: &[u8],
    input: &InputSpec,
    target: CaptureTarget<'_>,
) -> Result<ExecutionSnapshot, String> {
    validate_input_spec(elf, input)?;
    let mut snapshot = ExecutionSnapshot {
        schema_version: EXECUTION_SNAPSHOT_VERSION,
        binary_sha256: input.binary_sha256.clone(),
        input_sha256: input_sha256(input)?,
        status: SnapshotStatus::RunnerError,
        stop: None,
        thread_id: None,
        thread_count: 0,
        registers: BTreeMap::new(),
        mappings: Vec::new(),
        pages: Vec::new(),
        runner: "bubblewrap-gdb-mi-linux-v1".into(),
        diagnostics: Vec::new(),
    };
    let result = capture_inner(elf, input, target, snapshot.clone());
    match result {
        Ok(candidate) => match validate_execution_snapshot(elf, input, &candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) => snapshot
                .diagnostics
                .push(format!("captured state failed validation: {error}")),
        },
        Err(CaptureFailure::TimedOut) => {
            snapshot.status = SnapshotStatus::TimedOut;
            snapshot
                .diagnostics
                .push("GDB/MI capture exceeded its wall-clock budget".into());
        }
        Err(CaptureFailure::Runner(error)) => {
            snapshot.diagnostics.push(error.chars().take(512).collect())
        }
    }
    validate_execution_snapshot(elf, input, &snapshot)?;
    Ok(snapshot)
}

fn capture_inner(
    elf: &[u8],
    input: &InputSpec,
    target: CaptureTarget<'_>,
    mut snapshot: ExecutionSnapshot,
) -> Result<ExecutionSnapshot, CaptureFailure> {
    match target {
        CaptureTarget::Symbol(symbol) if !valid_capture_symbol(symbol) => {
            return Err("capture requires a simple C function symbol".into());
        }
        CaptureTarget::ElfVaddr(address) => validate_elf_address(elf, address)?,
        _ => {}
    }
    let argv = input
        .argv_hex
        .iter()
        .map(|arg| {
            let bytes = decode_hex(arg, 4096)?;
            if !bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/'))
            {
                return Err(
                    "capture argv currently supports ASCII letters, digits, _, -, ., and /".into(),
                );
            }
            String::from_utf8(bytes).map_err(|_| "capture argv must be ASCII".into())
        })
        .collect::<Result<Vec<_>, String>>()?;
    let scratch =
        tempfile::tempdir().map_err(|e| format!("capture scratch creation failed: {e}"))?;
    let program = scratch.path().join(".hydir-program");
    fs::write(&program, elf).map_err(|e| format!("capture ELF staging failed: {e}"))?;
    fs::set_permissions(&program, fs::Permissions::from_mode(0o500)).map_err(|e| e.to_string())?;
    let stdin = scratch.path().join(".hydir-stdin");
    fs::write(
        &stdin,
        decode_hex(&input.stdin_hex, crate::MAX_INPUT_BYTES)?,
    )
    .map_err(|e| e.to_string())?;
    fs::set_permissions(&stdin, fs::Permissions::from_mode(0o400)).map_err(|e| e.to_string())?;
    let script = scratch.path().join(".hydir-maps.py");
    fs::write(&script, MAPS_SCRIPT).map_err(|e| e.to_string())?;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o400)).map_err(|e| e.to_string())?;
    for file in &input.files {
        let path = scratch.path().join(&file.path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        fs::write(&path, decode_hex(&file.bytes_hex, crate::MAX_INPUT_BYTES)?)
            .map_err(|e| e.to_string())?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).map_err(|e| e.to_string())?;
    }
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
        "--ro-bind",
    ]);
    command.arg(scratch.path()).arg("/work");
    command.args([
        "--chdir",
        "/work",
        "--",
        "/usr/bin/gdb",
        "--nx",
        "--quiet",
        "--interpreter=mi2",
        "-iex",
        "set auto-load off",
        "--args",
        "/work/.hydir-program",
    ]);
    for arg in &argv {
        command.arg(arg);
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let seconds = input.budget.timeout_ms.div_ceil(1000).saturating_add(3);
    // SAFETY: the child hook only makes async-signal-safe libc calls.
    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            for (resource, limit) in [
                (libc::RLIMIT_AS, CAPTURE_MEMORY_LIMIT),
                (libc::RLIMIT_CPU, seconds),
                (libc::RLIMIT_CORE, 0),
                (libc::RLIMIT_FSIZE, 1024 * 1024),
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
    let timeout = Duration::from_millis(input.budget.timeout_ms.saturating_add(5000));
    let mut session = MiSession::spawn(command, timeout)?;
    session.wait_prompt()?;
    session.required("-gdb-set pagination off")?;
    session.required("-gdb-set confirm off")?;
    session.required("-gdb-set disable-randomization off")?;
    run_to_target(&mut session, elf, target, &argv)?;
    let thread = session.required("-thread-info")?;
    let (thread_count, thread_id) = parse_threads(&thread.record)?;
    if thread_count != 1 {
        snapshot.status = SnapshotStatus::UnsupportedThreads;
        snapshot.thread_count = thread_count;
        snapshot
            .diagnostics
            .push("capture currently supports one stopped thread".into());
        return Ok(snapshot);
    }
    let names = session.required("-data-list-register-names")?;
    let values = session.required("-data-list-register-values x")?;
    let registers = parse_registers(&names.record, &values.record)?;
    let rip = required_register(&registers, "rip")?;
    let rsp = required_register(&registers, "rsp")?;
    required_register(&registers, "eflags")?;
    let mappings = read_mappings(&mut session)?;
    if !in_staged_executable_mapping(&mappings, rip) {
        return Err("stop PC is not in the staged ELF mapping".into());
    }
    let bias = elf_load_bias(elf, &mappings);
    let (elf_vaddr, load_bias) = match bias {
        Some(value) if rip >= value => (Some(rip - value), Some(value)),
        None => (None, None),
        Some(_) => (None, None),
    };
    if let CaptureTarget::ElfVaddr(requested) = target {
        if elf_vaddr != Some(requested) {
            return Err("stopped address differs from requested ELF virtual address".into());
        }
    }
    let mut selected = BTreeSet::new();
    // Reserve code and stack pages before optional argument pages. A sorted
    // inventory must not evict the high-address stack page at the page limit.
    selected.insert(rip & !((crate::snapshot::PAGE_BYTES as u64) - 1));
    selected.insert(rsp & !((crate::snapshot::PAGE_BYTES as u64) - 1));
    for name in ["rdi", "rsi", "rdx", "rcx", "r8", "r9"] {
        if let Some(RegisterObservation::Present { value }) = registers.get(name) {
            let page = value & !((crate::snapshot::PAGE_BYTES as u64) - 1);
            if mappings.iter().any(|mapping| {
                mapping.readable
                    && mapping.start <= page
                    && page.checked_add(4096).is_some_and(|end| end <= mapping.end)
            }) {
                selected.insert(page);
            }
        }
        if selected.len() >= MAX_CAPTURE_PAGES {
            break;
        }
    }
    let mut pages = Vec::new();
    for address in selected.into_iter().take(MAX_CAPTURE_PAGES) {
        let mapped = mappings.iter().any(|mapping| {
            mapping.readable
                && mapping.start <= address
                && address
                    .checked_add(4096)
                    .is_some_and(|end| end <= mapping.end)
        });
        let value = if mapped {
            let reply = session.command(&format!("-data-read-memory-bytes 0x{address:x} 4096"))?;
            parse_memory_page(&reply.record, address)
        } else {
            MemoryPageState::Unavailable {
                reason: "page is not fully readable in captured mappings".into(),
            }
        };
        pages.push(MemoryPage { address, value });
    }
    snapshot.status = SnapshotStatus::Stopped;
    snapshot.stop = Some(StopPoint {
        runtime_pc: rip,
        elf_vaddr,
        load_bias,
        symbol: match target {
            CaptureTarget::Symbol(symbol) => Some(symbol.to_owned()),
            CaptureTarget::ElfVaddr(_) => None,
        },
    });
    snapshot.thread_id = Some(thread_id);
    snapshot.thread_count = thread_count;
    snapshot.registers = registers;
    snapshot.mappings = mappings;
    snapshot.pages = pages;
    Ok(snapshot)
}

fn run_to_target(
    session: &mut MiSession,
    elf: &[u8],
    target: CaptureTarget<'_>,
    argv: &[String],
) -> Result<(), CaptureFailure> {
    match target {
        CaptureTarget::Symbol(symbol) => {
            session.required(&format!("-break-insert {symbol}"))?;
            run_command(session, &launch_command("run", argv))?;
            require_breakpoint_hit(session.wait_stop()?)?;
        }
        CaptureTarget::ElfVaddr(address) => {
            run_command(session, &launch_command("starti", argv))?;
            let first_stop = session.wait_stop()?;
            let reason = stop_reason(&first_stop);
            if !is_first_instruction_stop(&first_stop) {
                let signal = first_stop
                    .field("signal-name")
                    .and_then(MiValue::as_text)
                    .unwrap_or("unknown");
                let meaning = first_stop
                    .field("signal-meaning")
                    .and_then(MiValue::as_text)
                    .unwrap_or("unknown");
                let pc = first_stop
                    .field("frame")
                    .and_then(|value| match value {
                        MiValue::Tuple(fields) => tuple_field(fields, "addr"),
                        _ => None,
                    })
                    .and_then(MiValue::as_text)
                    .unwrap_or("unknown");
                return Err(format!(
                    "process did not stop at its first instruction: {reason}, signal={signal}, meaning={meaning}, pc={pc}"
                )
                .into());
            }
            let mappings = read_mappings(session)?;
            let first_pc = first_stop
                .field("frame")
                .and_then(|value| match value {
                    MiValue::Tuple(fields) => tuple_field(fields, "addr"),
                    _ => None,
                })
                .and_then(MiValue::as_text)
                .and_then(parse_hex_u64)
                .ok_or("GDB first-instruction stop has no program counter")?;
            if !mappings.iter().any(|mapping| {
                mapping.executable && mapping.start <= first_pc && first_pc < mapping.end
            }) {
                return Err("GDB first-instruction stop is not in executable memory".into());
            }
            let bias = elf_load_bias(elf, &mappings)
                .ok_or("cannot resolve the staged ELF load bias at process start")?;
            let runtime = address
                .checked_add(bias)
                .ok_or("ELF virtual address overflows after relocation")?;
            if !in_staged_executable_mapping(&mappings, runtime) {
                return Err("requested ELF address is not executable in the staged process".into());
            }
            if first_pc != runtime {
                session.required(&format!("-break-insert *0x{runtime:x}"))?;
                run_command(session, "-exec-continue")?;
                let final_stop = session.wait_stop()?;
                if stop_reason(&final_stop) != "breakpoint-hit" {
                    let exit_code = final_stop
                        .field("exit-code")
                        .and_then(MiValue::as_text)
                        .unwrap_or("unknown");
                    return Err(format!(
                        "process stopped before requested ELF address 0x{address:x} (runtime 0x{runtime:x}, bias 0x{bias:x}): reason={}, exit-code={exit_code}",
                        stop_reason(&final_stop)
                    )
                    .into());
                }
            }
        }
    }
    Ok(())
}

fn launch_command(verb: &str, argv: &[String]) -> String {
    // GDB treats a launch command containing redirections as new arguments;
    // include the validated argv rather than relying on --args defaults.
    let arguments = if argv.is_empty() {
        String::new()
    } else {
        format!(" {}", argv.join(" "))
    };
    format!("-interpreter-exec console \"{verb}{arguments} < /work/.hydir-stdin > /dev/null 2>&1\"")
}

fn run_command(session: &mut MiSession, command: &str) -> Result<(), CaptureFailure> {
    let reply = session.command(command)?;
    if matches!(reply.class(), "done" | "running") {
        Ok(())
    } else {
        Err(reply.error().into())
    }
}

fn stop_reason(record: &MiRecord) -> &str {
    record
        .field("reason")
        .and_then(MiValue::as_text)
        .unwrap_or("unknown")
}

fn is_first_instruction_stop(record: &MiRecord) -> bool {
    // GDB can report `starti`'s synthetic "Program stopped" event as a
    // signal-received record with signal-name 0. Real signals stay fatal here.
    matches!(
        stop_reason(record),
        "breakpoint-hit" | "end-stepping-range" | "location-reached"
    ) || (stop_reason(record) == "signal-received"
        && record.field("signal-name").and_then(MiValue::as_text) == Some("0"))
}

fn require_breakpoint_hit(record: MiRecord) -> Result<(), CaptureFailure> {
    if stop_reason(&record) == "breakpoint-hit" {
        Ok(())
    } else {
        Err(format!(
            "process stopped before requested target: {}",
            stop_reason(&record)
        )
        .into())
    }
}

fn read_mappings(session: &mut MiSession) -> Result<Vec<MemoryMapping>, CaptureFailure> {
    let reply = session.required(
        "-interpreter-exec console \"python exec(open('/work/.hydir-maps.py').read())\"",
    )?;
    parse_maps_console(&reply.console)
}

fn in_staged_executable_mapping(mappings: &[MemoryMapping], address: u64) -> bool {
    mappings.iter().any(|mapping| {
        mapping.path.as_deref() == Some("/work/.hydir-program")
            && mapping.executable
            && mapping.start <= address
            && address < mapping.end
    })
}

struct CommandReply {
    record: MiRecord,
    console: Vec<u8>,
}

impl CommandReply {
    fn class(&self) -> &str {
        match &self.record {
            MiRecord::Result { class, .. } => class,
            _ => "invalid",
        }
    }

    fn error(&self) -> String {
        self.record
            .field("msg")
            .and_then(MiValue::as_text)
            .unwrap_or("GDB/MI command did not complete")
            .chars()
            .take(512)
            .collect()
    }
}

struct MiSession {
    child: Child,
    stdin: ChildStdin,
    records: Receiver<Result<MiRecord, String>>,
    stderr_prefix: Arc<Mutex<Vec<u8>>>,
    deadline: Instant,
    next_token: u64,
    stopped: VecDeque<MiRecord>,
}

impl MiSession {
    fn spawn(mut command: Command, timeout: Duration) -> Result<Self, CaptureFailure> {
        let mut child = command
            .spawn()
            .map_err(|e| format!("GDB sandbox launch failed: {e}"))?;
        let stdin = child.stdin.take().ok_or("GDB/MI stdin pipe is missing")?;
        let stdout = child.stdout.take().ok_or("GDB/MI stdout pipe is missing")?;
        let stderr = child.stderr.take().ok_or("GDB/MI stderr pipe is missing")?;
        let (sender, records) = mpsc::channel();
        thread::spawn(move || {
            let mut source = BufReader::new(stdout).take(MAX_MI_OUTPUT + 1);
            let mut consumed = 0u64;
            loop {
                let mut line = Vec::new();
                match source.read_until(b'\n', &mut line) {
                    Ok(0) => break,
                    Ok(size) => {
                        consumed += size as u64;
                        if consumed > MAX_MI_OUTPUT {
                            let _ = sender.send(Err("GDB/MI output exceeded 4 MiB".into()));
                            break;
                        }
                        if line == b"\n" || line == b"\r\n" {
                            continue;
                        }
                        let result = parse_mi_line(&line).map_err(|error| {
                            let prefix = crate::encode_hex(&line[..line.len().min(64)]);
                            format!("{error}: line_prefix_hex={prefix}")
                        });
                        let failed = result.is_err();
                        if sender.send(result).is_err() || failed {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = sender.send(Err(format!("GDB/MI output read failed: {error}")));
                        break;
                    }
                }
            }
        });
        let stderr_prefix = Arc::new(Mutex::new(Vec::new()));
        let stderr_copy = stderr_prefix.clone();
        thread::spawn(move || {
            let mut stream = stderr;
            let mut buf = [0u8; 4096];
            while let Ok(size) = stream.read(&mut buf) {
                if size == 0 {
                    break;
                }
                if let Ok(mut prefix) = stderr_copy.lock() {
                    let remaining = 16_384usize.saturating_sub(prefix.len());
                    prefix.extend_from_slice(&buf[..size.min(remaining)]);
                }
            }
        });
        Ok(Self {
            child,
            stdin,
            records,
            stderr_prefix,
            deadline: Instant::now() + timeout,
            next_token: 1,
            stopped: VecDeque::new(),
        })
    }

    fn stderr_text(&self) -> String {
        self.stderr_prefix
            .lock()
            .ok()
            .map(|bytes| String::from_utf8_lossy(&bytes).chars().take(512).collect())
            .unwrap_or_default()
    }

    fn next_record(&mut self) -> Result<MiRecord, CaptureFailure> {
        loop {
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(CaptureFailure::TimedOut);
            }
            match self
                .records
                .recv_timeout(remaining.min(Duration::from_millis(100)))
            {
                Ok(Ok(record)) => return Ok(record),
                Ok(Err(error)) => return Err(CaptureFailure::Runner(error)),
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(format!(
                        "GDB/MI ended without a complete result: {}",
                        self.stderr_text()
                    )
                    .into());
                }
                Err(RecvTimeoutError::Timeout) => {
                    if self.child.try_wait().map_err(|e| e.to_string())?.is_some() {
                        return Err(format!("GDB sandbox exited: {}", self.stderr_text()).into());
                    }
                }
            }
        }
    }

    fn wait_prompt(&mut self) -> Result<(), CaptureFailure> {
        loop {
            if matches!(self.next_record()?, MiRecord::Prompt) {
                return Ok(());
            }
        }
    }

    fn command(&mut self, command: &str) -> Result<CommandReply, CaptureFailure> {
        if command.len() > 4096 || command.contains('\n') || !command.is_ascii() {
            return Err("GDB/MI command is invalid".into());
        }
        let token = self.next_token;
        self.next_token += 1;
        self.stdin
            .write_all(format!("{token}{command}\n").as_bytes())
            .map_err(|e| e.to_string())?;
        self.stdin.flush().map_err(|e| e.to_string())?;
        let mut console = Vec::new();
        loop {
            let record = self.next_record()?;
            match record {
                MiRecord::Result {
                    token: Some(found), ..
                } if found == token => return Ok(CommandReply { record, console }),
                MiRecord::Result { .. } => return Err("unexpected GDB/MI result token".into()),
                MiRecord::Async {
                    kind: b'*',
                    ref class,
                    ..
                } if class == "stopped" => self.stopped.push_back(record),
                MiRecord::Stream {
                    kind: b'~',
                    ref bytes,
                } => {
                    if console.len().saturating_add(bytes.len()) > MAX_CONSOLE_OUTPUT {
                        return Err("GDB console output exceeded 512 KiB".into());
                    }
                    console.extend_from_slice(bytes);
                }
                _ => {}
            }
        }
    }

    fn required(&mut self, command: &str) -> Result<CommandReply, CaptureFailure> {
        let reply = self.command(command)?;
        if reply.class() == "done" {
            Ok(reply)
        } else {
            Err(reply.error().into())
        }
    }

    fn wait_stop(&mut self) -> Result<MiRecord, CaptureFailure> {
        if let Some(record) = self.stopped.pop_front() {
            return Ok(record);
        }
        loop {
            let record = self.next_record()?;
            if matches!(&record, MiRecord::Async { kind: b'*', class, .. } if class == "stopped") {
                return Ok(record);
            }
        }
    }
}

impl Drop for MiSession {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            // SAFETY: pre_exec placed the spawned Bubblewrap process in its own process group.
            unsafe {
                libc::kill(-(self.child.id() as i32), libc::SIGKILL);
            }
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

fn tuple_field<'a>(fields: &'a [(String, MiValue)], name: &str) -> Option<&'a MiValue> {
    fields
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value)
}

fn parse_threads(record: &MiRecord) -> Result<(u32, u64), CaptureFailure> {
    let Some(MiValue::List(threads)) = record.field("threads") else {
        return Err("GDB/MI thread list is missing".into());
    };
    let count = u32::try_from(threads.len()).map_err(|_| "GDB/MI thread count overflow")?;
    if count == 0 || count > 1024 {
        return Err("GDB/MI thread count is outside limits".into());
    }
    let current = record
        .field("current-thread-id")
        .and_then(MiValue::as_text)
        .ok_or("GDB/MI current thread ID is missing")?;
    let id = current
        .parse::<u64>()
        .map_err(|_| "GDB/MI current thread ID is invalid")?;
    Ok((count, id))
}

fn parse_hex_u64(text: &str) -> Option<u64> {
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))?;
    u64::from_str_radix(digits, 16).ok()
}

fn parse_registers(
    names: &MiRecord,
    values: &MiRecord,
) -> Result<BTreeMap<String, RegisterObservation>, CaptureFailure> {
    let Some(MiValue::List(name_entries)) = names.field("register-names") else {
        return Err("GDB/MI register names are missing".into());
    };
    if name_entries.len() > 1024 {
        return Err("GDB/MI register inventory exceeds limit".into());
    }
    let mut name_by_number = Vec::new();
    for entry in name_entries {
        let MiListEntry::Value(value) = entry else {
            return Err("GDB/MI register name is malformed".into());
        };
        let name = value.as_text().ok_or("GDB/MI register name is not text")?;
        name_by_number.push(name);
    }
    let wanted = [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14", "r15", "rip", "eflags", "fs_base", "gs_base",
    ];
    let mut result = BTreeMap::new();
    for name in wanted {
        result.insert(
            name.to_owned(),
            RegisterObservation::Unavailable {
                reason: "GDB did not expose this register".into(),
            },
        );
    }
    let Some(MiValue::List(value_entries)) = values.field("register-values") else {
        return Err("GDB/MI register values are missing".into());
    };
    let mut seen = BTreeSet::new();
    for entry in value_entries {
        let MiListEntry::Value(MiValue::Tuple(fields)) = entry else {
            return Err("GDB/MI register value is malformed".into());
        };
        let number = tuple_field(fields, "number")
            .and_then(MiValue::as_text)
            .ok_or("GDB/MI register number is missing")?
            .parse::<usize>()
            .map_err(|_| "GDB/MI register number is invalid")?;
        if !seen.insert(number) {
            return Err("GDB/MI register number is duplicated".into());
        }
        let name = *name_by_number
            .get(number)
            .ok_or("GDB/MI register number exceeds inventory")?;
        if !result.contains_key(name) {
            continue;
        }
        let text = tuple_field(fields, "value")
            .and_then(MiValue::as_text)
            .ok_or("GDB/MI register value is missing")?;
        let observation = match parse_hex_u64(text) {
            Some(value) => RegisterObservation::Present { value },
            None => RegisterObservation::Unavailable {
                reason: "GDB reported a non-scalar or unavailable value".into(),
            },
        };
        result.insert(name.to_owned(), observation);
    }
    Ok(result)
}

fn required_register(
    registers: &BTreeMap<String, RegisterObservation>,
    name: &str,
) -> Result<u64, CaptureFailure> {
    match registers.get(name) {
        Some(RegisterObservation::Present { value }) => Ok(*value),
        _ => Err(format!("GDB did not capture required {name} register").into()),
    }
}

fn parse_maps_console(console: &[u8]) -> Result<Vec<MemoryMapping>, CaptureFailure> {
    let text = std::str::from_utf8(console).map_err(|_| "GDB mapping output is not UTF-8")?;
    if text.lines().any(|line| line == "HYDIR_MAPS_TOO_LARGE") {
        return Err("process mapping list exceeds 128 KiB".into());
    }
    let hex = text
        .lines()
        .find_map(|line| line.strip_prefix("HYDIR_MAPS:"))
        .ok_or("GDB did not return process mappings")?;
    let bytes = decode_hex(hex, MAX_MAPS_BYTES)?;
    let maps =
        std::str::from_utf8(&bytes).map_err(|_| "process mappings contain non-UTF-8 paths")?;
    let mut result = Vec::new();
    for line in maps.lines() {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 5 {
            return Err("malformed /proc process mapping".into());
        }
        let (start, end) = parts[0]
            .split_once('-')
            .ok_or("mapping address range is malformed")?;
        let start = u64::from_str_radix(start, 16).map_err(|_| "mapping start is invalid")?;
        let end = u64::from_str_radix(end, 16).map_err(|_| "mapping end is invalid")?;
        let flags = parts[1].as_bytes();
        if flags.len() < 4 {
            return Err("mapping permission flags are invalid".into());
        }
        let file_offset =
            u64::from_str_radix(parts[2], 16).map_err(|_| "mapping file offset is invalid")?;
        let path = if parts.len() > 5 {
            Some(parts[5..].join(" "))
        } else {
            None
        };
        result.push(MemoryMapping {
            start,
            end,
            file_offset,
            readable: flags[0] == b'r',
            writable: flags[1] == b'w',
            executable: flags[2] == b'x',
            path,
        });
        if result.len() > 1024 {
            return Err("process mapping count exceeds limit".into());
        }
    }
    result.sort_by_key(|mapping| mapping.start);
    Ok(result)
}

fn valid_capture_symbol(symbol: &str) -> bool {
    !symbol.is_empty()
        && symbol.len() <= 128
        && symbol
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && symbol
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn validate_elf_address(elf: &[u8], address: u64) -> Result<(), CaptureFailure> {
    let file = object::File::parse(elf).map_err(|_| "capture ELF cannot be parsed")?;
    if !matches!(file.kind(), ObjectKind::Executable | ObjectKind::Dynamic) {
        return Err("capture address requires a linked executable ELF".into());
    }
    let covered = file.segments().any(|segment| {
        let executable = matches!(
            segment.flags(),
            SegmentFlags::Elf { p_flags } if p_flags & object::elf::PF_X != 0
        );
        let (_, file_size) = segment.file_range();
        executable
            && segment.address() <= address
            && segment
                .address()
                .checked_add(file_size)
                .is_some_and(|end| address < end)
    });
    if !covered {
        return Err("capture address is outside file-backed executable ELF segments".into());
    }
    Ok(())
}

fn elf_load_bias(elf: &[u8], mappings: &[MemoryMapping]) -> Option<u64> {
    let file = object::File::parse(elf).ok()?;
    match file.kind() {
        ObjectKind::Executable => Some(0),
        ObjectKind::Dynamic => {
            for segment in file.segments() {
                let (offset, _) = segment.file_range();
                let aligned_offset = offset & !4095;
                let aligned_vaddr = segment.address() & !4095;
                if let Some(mapping) = mappings.iter().find(|mapping| {
                    mapping.path.as_deref() == Some("/work/.hydir-program")
                        && mapping.file_offset == aligned_offset
                }) {
                    if let Some(bias) = mapping.start.checked_sub(aligned_vaddr) {
                        return Some(bias);
                    }
                }
            }
            None
        }
        _ => None,
    }
}

fn parse_memory_page(record: &MiRecord, address: u64) -> MemoryPageState {
    let unavailable = |reason: &str| MemoryPageState::Unavailable {
        reason: reason.chars().take(512).collect(),
    };
    if !matches!(record, MiRecord::Result { class, .. } if class == "done") {
        return unavailable(
            record
                .field("msg")
                .and_then(MiValue::as_text)
                .unwrap_or("GDB memory read failed"),
        );
    }
    let Some(MiValue::List(entries)) = record.field("memory") else {
        return unavailable("GDB memory response has no ranges");
    };
    if entries.len() != 1 {
        return unavailable("GDB memory response is partial or fragmented");
    }
    let MiListEntry::Value(MiValue::Tuple(fields)) = &entries[0] else {
        return unavailable("GDB memory response is malformed");
    };
    let begin = tuple_field(fields, "begin")
        .and_then(MiValue::as_text)
        .and_then(parse_hex_u64);
    let contents = tuple_field(fields, "contents").and_then(MiValue::as_text);
    if begin != Some(address) {
        return unavailable("GDB memory range begins at another address");
    }
    let Some(contents) = contents else {
        return unavailable("GDB memory contents are missing");
    };
    if contents.len() != 8192 || decode_hex(contents, 4096).is_err() {
        return unavailable("GDB did not return a complete 4096-byte page");
    }
    MemoryPageState::Present {
        bytes_hex: contents.to_ascii_lowercase(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_thread_and_register_inventory() {
        let threads = parse_mi_line(
            br#"1^done,threads=[{id="2",target-id="Thread 1"}],current-thread-id="2""#,
        )
        .unwrap();
        assert_eq!(parse_threads(&threads).unwrap(), (1, 2));
        let names =
            parse_mi_line(br#"2^done,register-names=["rax","rip","rsp","eflags","fs_base"]"#)
                .unwrap();
        let values = parse_mi_line(br#"3^done,register-values=[{number="0",value="0x2a"},{number="1",value="0x401000"},{number="2",value="0x7fff0000"},{number="3",value="0x202"},{number="4",value="<unavailable>"}]"#).unwrap();
        let registers = parse_registers(&names, &values).unwrap();
        assert_eq!(required_register(&registers, "rip").unwrap(), 0x401000);
        assert_eq!(required_register(&registers, "eflags").unwrap(), 0x202);
        assert!(matches!(
            registers.get("fs_base"),
            Some(RegisterObservation::Unavailable { .. })
        ));
    }

    #[test]
    fn first_instruction_accepts_only_gdb_zero_signal() {
        let zero = parse_mi_line(
            br#"*stopped,reason="signal-received",signal-name="0",signal-meaning="Signal 0""#,
        )
        .unwrap();
        let fault = parse_mi_line(
            br#"*stopped,reason="signal-received",signal-name="SIGSEGV",signal-meaning="Segmentation fault""#,
        )
        .unwrap();
        let breakpoint = parse_mi_line(br#"*stopped,reason="breakpoint-hit""#).unwrap();
        assert!(is_first_instruction_stop(&zero));
        assert!(is_first_instruction_stop(&breakpoint));
        assert!(!is_first_instruction_stop(&fault));
    }

    #[test]
    fn gdb_launch_retains_program_argv_with_input_redirection() {
        assert_eq!(
            launch_command("starti", &["open".into()]),
            "-interpreter-exec console \"starti open < /work/.hydir-stdin > /dev/null 2>&1\""
        );
        assert_eq!(
            launch_command("run", &[]),
            "-interpreter-exec console \"run < /work/.hydir-stdin > /dev/null 2>&1\""
        );
    }

    #[test]
    fn parses_readable_maps_without_inventing_memory() {
        let maps = b"55555000-55557000 r-xp 00000000 00:01 42 /work/.hydir-program\n7fff0000-7fff1000 rw-p 00000000 00:00 0 [stack]\n";
        let console = format!("HYDIR_MAPS:{}\n", crate::encode_hex(maps));
        let parsed = parse_maps_console(console.as_bytes()).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].start, 0x55555000);
        assert!(parsed[0].executable);
        assert_eq!(parsed[1].path.as_deref(), Some("[stack]"));
        assert!(parse_maps_console(b"HYDIR_MAPS:zz\n").is_err());
        let empty = parse_mi_line(br#"4^done,memory=[]"#).unwrap();
        assert!(matches!(
            parse_memory_page(&empty, 0x55555000),
            MemoryPageState::Unavailable { .. }
        ));
    }

    #[test]
    fn address_target_must_be_file_backed_executable_code() {
        let elf = include_bytes!("../../../demo/hydir-prism.elf");
        let file = object::File::parse(elf.as_slice()).unwrap();
        let code = file
            .segments()
            .find(|segment| {
                matches!(
                    segment.flags(),
                    SegmentFlags::Elf { p_flags } if p_flags & object::elf::PF_X != 0
                ) && segment.file_range().1 > 0
            })
            .unwrap();
        assert!(validate_elf_address(elf, code.address()).is_ok());
        assert!(validate_elf_address(elf, u64::MAX).is_err());
    }
}
