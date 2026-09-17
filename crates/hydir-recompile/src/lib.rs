//! Fail-closed, trusted-fixture whole-executable reconstruction for a tiny
//! freestanding Linux/x86-64 subset. This does not copy executable code.
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use object::{
    Architecture, BinaryFormat, Object, ObjectSection, ObjectSymbol, SectionKind, SymbolKind,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs,
    path::Path,
    process::Command,
};

type R<T> = Result<T, Box<dyn Error>>;

struct Function {
    name: String,
    start: u64,
    instructions: BTreeMap<u64, Instruction>,
}

fn fail(message: impl Into<String>) -> Box<dyn Error> {
    message.into().into()
}

pub fn run(args: &[String]) -> R<()> {
    if args.len() != 4 && args.len() != 6 {
        return Err(fail(
            "rebuild <elf> --trusted-fixture --output-dir <new-directory> [--clang <path>]",
        ));
    }
    if args[1] != "--trusted-fixture" || args[2] != "--output-dir" {
        return Err(fail(
            "rebuild requires --trusted-fixture --output-dir <new-directory>",
        ));
    }
    let clang = if args.len() == 6 {
        if args[4] != "--clang" {
            return Err(fail("invalid rebuild option"));
        }
        args[5].as_str()
    } else {
        "clang"
    };
    let binary = fs::read(&args[0])?;
    let dir = Path::new(&args[3]);
    if dir.exists() {
        return Err(fail(format!(
            "output directory already exists: {}",
            dir.display()
        )));
    }
    let result = rebuild_bytes(&binary, Path::new(clang), Path::new("opt"))?;
    fs::create_dir(dir)?;
    fs::write(dir.join("whole.ll"), &result.ir)?;
    fs::write(dir.join("runtime.c"), RUNTIME_C)?;
    let executable = dir.join("rebuilt");
    fs::write(&executable, &result.executable)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))?;
    }
    fs::write(dir.join("report.json"), &result.report_json)?;
    println!("{}", String::from_utf8(result.report_json)?);
    Ok(())
}

const RUNTIME_C: &str = include_str!("../../../native/whole-runtime/runtime.c");
pub const MAX_REBUILT_BYTES: usize = 16 * 1024 * 1024;

pub struct RebuildArtifacts {
    pub ir: Vec<u8>,
    pub executable: Vec<u8>,
    pub report_json: Vec<u8>,
}

/// Reconstruct a complete program without executing it or copying its code
/// bytes. This is only a trusted-fixture operation, not a hostile-input sandbox.
pub fn rebuild_bytes(binary: &[u8], clang: &Path, opt: &Path) -> R<RebuildArtifacts> {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return Err(fail("rebuild requires Linux x86-64; run the Docker gate"));
    }
    if binary.is_empty() || binary.len() > 64 * 1024 * 1024 {
        return Err(fail("binary must be 1..=64 MiB"));
    }
    for (tool, label) in [(clang, "Clang"), (opt, "LLVM opt")] {
        let version = Command::new(tool).arg("--version").output()?;
        if !version.status.success() || !String::from_utf8_lossy(&version.stdout).contains("14.0.6")
        {
            return Err(fail(format!("rebuild requires pinned {label} 14.0.6")));
        }
    }
    let (ir, mut report) = lift(binary)?;
    let directory = tempfile::tempdir()?;
    let ir_path = directory.path().join("whole.ll");
    let runtime_path = directory.path().join("runtime.c");
    let executable_path = directory.path().join("rebuilt");
    fs::write(&ir_path, &ir)?;
    fs::write(&runtime_path, RUNTIME_C)?;
    let verified = Command::new(opt)
        .args(["-verify", "-disable-output"])
        .arg(&ir_path)
        .output()?;
    if !verified.status.success() {
        return Err(fail(format!(
            "generated LLVM IR failed verification: {}",
            String::from_utf8_lossy(&verified.stderr)
        )));
    }
    let compiled = Command::new(clang)
        .args([
            "-O0",
            "-nostdlib",
            "-no-pie",
            "-fno-builtin",
            "-fno-stack-protector",
            "-Wl,-e,_start",
            "-o",
        ])
        .arg(&executable_path)
        .arg(&ir_path)
        .arg(&runtime_path)
        .output()?;
    if !compiled.status.success() {
        return Err(fail(format!(
            "rebuild compiler failed: {}",
            String::from_utf8_lossy(&compiled.stderr)
        )));
    }
    let executable_size = fs::metadata(&executable_path)?.len();
    if executable_size > MAX_REBUILT_BYTES as u64 {
        return Err(fail("rebuilt executable exceeds 16 MiB"));
    }
    report["llvm_verified"] = json!(true);
    report["toolchain"] = json!("Clang/LLVM 14.0.6");
    Ok(RebuildArtifacts {
        ir: ir.into_bytes(),
        executable: fs::read(&executable_path)?,
        report_json: serde_json::to_vec_pretty(&report)?,
    })
}

fn lift(bytes: &[u8]) -> R<(String, serde_json::Value)> {
    let file = object::File::parse(bytes)?;
    if file.format() != BinaryFormat::Elf
        || file.architecture() != Architecture::X86_64
        || !file.is_little_endian()
        || file.kind() != object::ObjectKind::Executable
    {
        return Err(fail(
            "rebuild requires a linked little-endian x86-64 ELF executable",
        ));
    }
    if file.section_by_name(".interp").is_some()
        || file.section_by_name(".dynamic").is_some()
        || file.section_by_name(".rela.dyn").is_some()
    {
        return Err(fail(
            "dynamic linking/relocation is outside the rebuild subset",
        ));
    }
    let mut data = Vec::<(u64, Vec<u8>, bool)>::new();
    let mut text = Vec::<(u64, Vec<u8>)>::new();
    for section in file.sections() {
        let name = section.name().unwrap_or("");
        match section.kind() {
            SectionKind::Text if name == ".text" => {
                text.push((section.address(), section.data()?.to_vec()))
            }
            SectionKind::Text => {
                return Err(fail(format!(
                    "extra executable section {name:?} is unsupported"
                )));
            }
            SectionKind::ReadOnlyData | SectionKind::Data | SectionKind::UninitializedData
                if matches!(name, ".rodata" | ".data" | ".bss") =>
            {
                let size = usize::try_from(section.size())?;
                if size > 65536 {
                    return Err(fail("mapped data section exceeds 64 KiB"));
                }
                let mut image = section.data()?.to_vec();
                image.resize(size, 0);
                data.push((section.address(), image, name != ".rodata"));
            }
            _ => {}
        }
    }
    if text.len() != 1 || data.is_empty() {
        return Err(fail(
            "rebuild needs one .text and mapped .rodata/.data/.bss",
        ));
    }
    let base = data.iter().map(|(start, _, _)| *start).min().unwrap();
    let end = data
        .iter()
        .map(|(start, bytes, _)| start.saturating_add(bytes.len() as u64))
        .max()
        .unwrap();
    let span = usize::try_from(end.checked_sub(base).ok_or("mapped-data range overflow")?)?;
    if span == 0 || span > 65536 {
        return Err(fail("mapped-data span must be 1..=65536 bytes"));
    }
    let mut memory = vec![0_u8; span];
    let mut owned = vec![false; span];
    let mut writable = vec![false; span];
    for (start, bytes, write) in &data {
        let offset = usize::try_from(start - base)?;
        for (i, byte) in bytes.iter().enumerate() {
            if owned[offset + i] {
                return Err(fail("overlapping data sections"));
            }
            owned[offset + i] = true;
            memory[offset + i] = *byte;
            writable[offset + i] = *write;
        }
    }
    let (text_base, text_bytes) = &text[0];
    let text_end = text_base
        .checked_add(text_bytes.len() as u64)
        .ok_or("text range overflow")?;
    let mut functions = BTreeMap::<u64, Function>::new();
    for symbol in file.symbols() {
        if symbol.kind() != SymbolKind::Text || !symbol.is_definition() || symbol.size() == 0 {
            continue;
        }
        let start = symbol.address();
        let end = start
            .checked_add(symbol.size())
            .ok_or("function range overflow")?;
        if start < *text_base || end > text_end || symbol.size() > 4096 {
            return Err(fail("function outside bounded .text"));
        }
        let offset = usize::try_from(start - text_base)?;
        let size = usize::try_from(symbol.size())?;
        let mut decoder = Decoder::with_ip(
            64,
            &text_bytes[offset..offset + size],
            start,
            DecoderOptions::NONE,
        );
        let mut instructions = BTreeMap::new();
        while decoder.can_decode() {
            let instruction = decoder.decode();
            if instruction.is_invalid() || instruction.next_ip() > end {
                return Err(fail(format!(
                    "invalid/truncated instruction at 0x{:x}",
                    instruction.ip()
                )));
            }
            instructions.insert(instruction.ip(), instruction);
        }
        if instructions.last_key_value().map(|(_, i)| i.next_ip()) != Some(end) {
            return Err(fail("function does not decode to symbol extent"));
        }
        let name = symbol.name()?.to_owned();
        if functions
            .insert(
                start,
                Function {
                    name,
                    start,
                    instructions,
                },
            )
            .is_some()
        {
            return Err(fail("duplicate function address"));
        }
    }
    let mut covered_until = *text_base;
    for function in functions.values() {
        if function.start != covered_until {
            return Err(fail(format!(
                "uncovered or overlapping .text at 0x{covered_until:x}"
            )));
        }
        covered_until = function.instructions.last_key_value().unwrap().1.next_ip();
    }
    if covered_until != text_end {
        return Err(fail("function symbols do not cover all .text bytes"));
    }
    if functions.is_empty()
        || !functions.contains_key(&file.entry())
        || functions.get(&file.entry()).map(|f| f.name.as_str()) != Some("_start")
    {
        return Err(fail("ELF entry must equal a sized _start function symbol"));
    }
    // Every decoded instruction in every symbol is checked, including unreachable code.
    // Reject unmodelled calls/branches before generating any executable.
    let entries: BTreeSet<u64> = functions.keys().copied().collect();
    let mut ir = format!(
        "; HydIR restricted decoded whole-program lift\n; source sha256 {:x}\n@hydir_memory = global [{} x i8] c\"{}\"\n@hydir_owned = constant [{} x i8] c\"{}\"\n@hydir_writable = constant [{} x i8] c\"{}\"\n@hydir_guest_base = constant i64 {}\n@hydir_memory_len = constant i64 {}\n",
        Sha256::digest(bytes),
        span,
        llvm_bytes(&memory),
        span,
        llvm_bytes(&owned.iter().map(|v| u8::from(*v)).collect::<Vec<_>>()),
        span,
        llvm_bytes(&writable.iter().map(|v| u8::from(*v)).collect::<Vec<_>>()),
        base,
        span
    );
    for reg in ["rax", "rdi", "rsi", "rdx", "rcx"] {
        ir.push_str(&format!("@{reg} = global i64 0\n"));
    }
    ir.push_str("@zf = global i1 false\ndeclare i64 @hydir_syscall(i64, i64, i64, i64)\ndeclare void @hydir_trap()\n");
    for function in functions.values() {
        validate_initialized(function)?;
        validate_syscalls(function, base, span, &owned, &writable)?;
        ir.push_str(&format!("define void @f_{:x}() {{\n", function.start));
        for instruction in function.instructions.values() {
            ir.push_str(&format!("b_{:x}:\n", instruction.ip()));
            ir.push_str(&emit(
                instruction,
                function,
                &entries,
                base,
                span,
                &owned,
                &writable,
            )?);
        }
        ir.push_str("}\n");
    }
    ir.push_str(&format!("define void @_start() {{\nentry:\n  call void @f_{:x}()\n  call void @hydir_trap()\n  unreachable\n}}\n", file.entry()));
    let report = json!({
        "status": "restricted_trusted_fixture_rebuild",
        "source_sha256": format!("{:x}", Sha256::digest(bytes)),
        "function_count": functions.len(),
        "function_names": functions.values().map(|f| f.name.as_str()).collect::<Vec<_>>(),
        "decoded_instruction_count": functions.values().map(|f| f.instructions.len()).sum::<usize>(),
        "guest_data_base": format!("0x{base:x}"),
        "guest_data_bytes": span,
        "assumptions": ["freestanding static ELF", "sized non-overlapping function symbols", "direct calls and branches only", "guest stack is unobserved", "statically proven read/write/exit Linux syscall sites and mapped buffers", "trusted fixture execution only"],
        "not_supported": ["arbitrary ELF", "dynamic linking", "indirect control flow", "stack memory", "threads", "exceptions", "signal/ABI equivalence", "hostile binary sandboxing"]
    });
    Ok((ir, report))
}

fn llvm_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("\\{byte:02X}")).collect()
}

fn reg(register: Register) -> R<&'static str> {
    match register {
        Register::RAX => Ok("rax"),
        Register::RDI => Ok("rdi"),
        Register::RSI => Ok("rsi"),
        Register::RDX => Ok("rdx"),
        Register::RCX => Ok("rcx"),
        _ => Err(fail(format!("unsupported register {register:?}"))),
    }
}
fn immediate(i: &Instruction, op: u32) -> R<u64> {
    match i.op_kind(op) {
        OpKind::Immediate8 => Ok(i.immediate8() as u64),
        OpKind::Immediate8to64 => Ok(i.immediate8to64() as u64),
        OpKind::Immediate32 => Ok(i.immediate32() as u64),
        OpKind::Immediate32to64 => Ok(i.immediate32to64() as u64),
        OpKind::Immediate64 => Ok(i.immediate64()),
        _ => Err(fail(format!("unsupported immediate at 0x{:x}", i.ip()))),
    }
}
fn mapped(i: &Instruction, base: u64, span: usize, owned: &[bool], width: usize) -> R<usize> {
    if !i.is_ip_rel_memory_operand()
        || i.memory_base() != Register::RIP
        || i.memory_index() != Register::None
    {
        return Err(fail(format!(
            "only RIP-relative mapped memory is supported at 0x{:x}",
            i.ip()
        )));
    }
    let start = i.ip_rel_memory_address();
    let offset = usize::try_from(
        start
            .checked_sub(base)
            .ok_or("guest address below mapped data")?,
    )?;
    let end = offset.checked_add(width).ok_or("guest address overflow")?;
    if end > span || !owned[offset..end].iter().all(|owned| *owned) {
        return Err(fail(format!("unmapped guest access at 0x{:x}", i.ip())));
    }
    Ok(offset)
}

const RAX: u8 = 1;
const RDI: u8 = 2;
const RSI: u8 = 4;
const RDX: u8 = 8;
const RCX: u8 = 16;
const ZF: u8 = 32;

fn bit(register: Register) -> R<u8> {
    Ok(match reg(register)? {
        "rax" => RAX,
        "rdi" => RDI,
        "rsi" => RSI,
        "rdx" => RDX,
        "rcx" => RCX,
        _ => unreachable!(),
    })
}

fn reg_index(register: Register) -> R<usize> {
    Ok(match reg(register)? {
        "rax" => 0,
        "rdi" => 1,
        "rsi" => 2,
        "rdx" => 3,
        "rcx" => 4,
        _ => unreachable!(),
    })
}

/// Proves the syscall number and buffer extent at every supported callsite.
/// A direct call invalidates constants because its effects are not summarized
/// here; this can reject safe programs but cannot invent pointer safety.
fn validate_syscalls(
    function: &Function,
    base: u64,
    span: usize,
    owned: &[bool],
    writable: &[bool],
) -> R<()> {
    let mut inputs = BTreeMap::<u64, [Option<u64>; 5]>::new();
    let mut pending = vec![function.start];
    inputs.insert(function.start, [None; 5]);
    while let Some(ip) = pending.pop() {
        let i = function
            .instructions
            .get(&ip)
            .ok_or("invalid syscall-analysis edge")?;
        let mut state = inputs[&ip];
        match i.mnemonic() {
            Mnemonic::Mov if i.op0_kind() == OpKind::Register => {
                let dst = reg_index(i.op0_register())?;
                state[dst] = if i.op1_kind() == OpKind::Register {
                    state[reg_index(i.op1_register())?]
                } else if i.op1_kind() == OpKind::Memory {
                    None
                } else {
                    Some(immediate(i, 1)?)
                };
            }
            Mnemonic::Lea if i.op0_kind() == OpKind::Register => {
                state[reg_index(i.op0_register())?] = Some(i.ip_rel_memory_address());
            }
            Mnemonic::Movzx if i.op0_kind() == OpKind::Register => {
                state[reg_index(i.op0_register())?] = None;
            }
            Mnemonic::Xor
                if i.op0_kind() == OpKind::Register && i.op0_register() == i.op1_register() =>
            {
                state[reg_index(i.op0_register())?] = Some(0);
            }
            Mnemonic::Add | Mnemonic::Sub if i.op0_kind() == OpKind::Register => {
                let index = reg_index(i.op0_register())?;
                let amount = immediate(i, 1)?;
                state[index] = state[index].map(|value| {
                    if i.mnemonic() == Mnemonic::Add {
                        value.wrapping_add(amount)
                    } else {
                        value.wrapping_sub(amount)
                    }
                });
            }
            Mnemonic::Call => state = [None; 5],
            Mnemonic::Syscall => {
                match state[0] {
                    Some(0 | 1) => {
                        let number = state[0].unwrap();
                        let fd = state[1]
                            .ok_or_else(|| fail(format!("unknown syscall fd at 0x{ip:x}")))?;
                        if (number == 0 && fd != 0) || (number == 1 && fd != 1 && fd != 2) {
                            return Err(fail(format!("unsupported syscall fd {fd} at 0x{ip:x}")));
                        }
                        let address = state[2]
                            .ok_or_else(|| fail(format!("unknown syscall buffer at 0x{ip:x}")))?;
                        let length = state[3]
                            .ok_or_else(|| fail(format!("unknown syscall length at 0x{ip:x}")))?;
                        let offset = usize::try_from(
                            address
                                .checked_sub(base)
                                .ok_or("syscall buffer below mapped data")?,
                        )?;
                        let size = usize::try_from(length)?;
                        let end = offset
                            .checked_add(size)
                            .ok_or("syscall buffer range overflow")?;
                        if end > span
                            || !owned[offset..end].iter().all(|v| *v)
                            || (number == 0 && !writable[offset..end].iter().all(|v| *v))
                        {
                            return Err(fail(format!(
                                "unmapped or forbidden syscall buffer at 0x{ip:x}"
                            )));
                        }
                    }
                    Some(60) => {}
                    _ => {
                        return Err(fail(format!(
                            "unknown or unsupported syscall number at 0x{ip:x}"
                        )));
                    }
                }
                state[0] = None;
                state[4] = Some(i.next_ip());
            }
            _ => {}
        }
        let mut successors = Vec::new();
        match i.mnemonic() {
            Mnemonic::Ret => {}
            Mnemonic::Jmp => successors.push(i.near_branch_target()),
            Mnemonic::Je | Mnemonic::Jne => {
                successors.push(i.near_branch_target());
                successors.push(i.next_ip());
            }
            _ if function.instructions.contains_key(&i.next_ip()) => successors.push(i.next_ip()),
            _ => {}
        }
        for target in successors {
            let merged = inputs
                .get(&target)
                .map(|old| {
                    std::array::from_fn(|index| {
                        if old[index] == state[index] {
                            old[index]
                        } else {
                            None
                        }
                    })
                })
                .unwrap_or(state);
            if inputs.insert(target, merged) != Some(merged) {
                pending.push(target);
            }
        }
    }
    Ok(())
}

/// A conservative must-initialize analysis. Each function must be safe to
/// enter with unknown registers; calls preserve knownness of already-defined
/// registers, but never infer callee output. This is deliberately restrictive.
fn validate_initialized(function: &Function) -> R<()> {
    let mut input = BTreeMap::<u64, u8>::new();
    let mut pending = vec![function.start];
    input.insert(function.start, 0);
    while let Some(ip) = pending.pop() {
        let instruction = function
            .instructions
            .get(&ip)
            .ok_or("CFG edge is not instruction-aligned")?;
        let mut state = input[&ip];
        let mut reads = 0_u8;
        let mut defines = 0_u8;
        let mut clears = 0_u8;
        match instruction.mnemonic() {
            Mnemonic::Mov => {
                if instruction.op0_kind() == OpKind::Register {
                    defines = bit(instruction.op0_register())?;
                    if instruction.op1_kind() == OpKind::Register {
                        reads = bit(instruction.op1_register())?;
                    }
                } else if instruction.op0_kind() == OpKind::Memory {
                    reads = bit(instruction.op1_register())?;
                }
            }
            Mnemonic::Movzx | Mnemonic::Lea => defines = bit(instruction.op0_register())?,
            Mnemonic::Xor => defines = bit(instruction.op0_register())? | ZF,
            Mnemonic::Add | Mnemonic::Sub => {
                reads = bit(instruction.op0_register())?;
                defines = reads | ZF;
            }
            Mnemonic::Cmp => {
                reads = bit(instruction.op0_register())?;
                defines = ZF;
            }
            Mnemonic::Je | Mnemonic::Jne => reads = ZF,
            Mnemonic::Syscall => {
                reads = RAX | RDI | RSI | RDX;
                defines = RAX | RCX;
                clears = ZF;
            }
            Mnemonic::Call => clears = ZF,
            Mnemonic::Jmp | Mnemonic::Ret => {}
            other => {
                return Err(fail(format!(
                    "unmodelled initialization effect {other:?} at 0x{ip:x}"
                )));
            }
        }
        if state & reads != reads {
            return Err(fail(format!(
                "register/flag read before definite initialization at 0x{ip:x}"
            )));
        }
        state = (state & !clears) | defines;
        let mut successors = Vec::new();
        match instruction.mnemonic() {
            Mnemonic::Ret => {}
            Mnemonic::Jmp => successors.push(instruction.near_branch_target()),
            Mnemonic::Je | Mnemonic::Jne => {
                successors.push(instruction.near_branch_target());
                successors.push(instruction.next_ip());
            }
            _ if function.instructions.contains_key(&instruction.next_ip()) => {
                successors.push(instruction.next_ip())
            }
            _ => {}
        }
        for target in successors {
            if !function.instructions.contains_key(&target) {
                return Err(fail(format!("invalid CFG target 0x{target:x}")));
            }
            let merged = input.get(&target).map(|old| *old & state).unwrap_or(state);
            if input.insert(target, merged) != Some(merged) {
                pending.push(target);
            }
        }
    }
    if input.len() != function.instructions.len() {
        return Err(fail(format!(
            "unreachable instruction bytes in function {}",
            function.name
        )));
    }
    Ok(())
}
fn next(i: &Instruction, f: &Function) -> String {
    if f.instructions.contains_key(&i.next_ip()) {
        format!("  br label %b_{:x}\n", i.next_ip())
    } else {
        "  call void @hydir_trap()\n  unreachable\n".to_owned()
    }
}
fn emit(
    i: &Instruction,
    f: &Function,
    entries: &BTreeSet<u64>,
    base: u64,
    span: usize,
    owned: &[bool],
    writable: &[bool],
) -> R<String> {
    let ip = i.ip();
    let mut out = String::new();
    let at = format!("0x{ip:x}");
    match i.mnemonic() {
        Mnemonic::Mov if i.op0_kind() == OpKind::Register && i.op1_kind() == OpKind::Register => {
            let dst = reg(i.op0_register())?;
            let src = reg(i.op1_register())?;
            out.push_str(&format!(
                "  %v_{ip:x} = load i64, i64* @{src}\n  store i64 %v_{ip:x}, i64* @{dst}\n"
            ));
        }
        Mnemonic::Mov if i.op0_kind() == OpKind::Register && i.op1_kind() == OpKind::Memory => {
            let dst = reg(i.op0_register())?;
            let off = mapped(i, base, span, owned, 8)?;
            out.push_str(&format!("  %p_{ip:x} = getelementptr [{span} x i8], [{span} x i8]* @hydir_memory, i64 0, i64 {off}\n  %q_{ip:x} = bitcast i8* %p_{ip:x} to i64*\n  %v_{ip:x} = load i64, i64* %q_{ip:x}, align 1\n  store i64 %v_{ip:x}, i64* @{dst}\n"));
        }
        Mnemonic::Mov if i.op0_kind() == OpKind::Memory && i.op1_kind() == OpKind::Register => {
            let src = reg(i.op1_register())?;
            let off = mapped(i, base, span, owned, 8)?;
            if !writable[off..off + 8].iter().all(|w| *w) {
                return Err(fail(format!("write to read-only guest data at {at}")));
            }
            out.push_str(&format!("  %p_{ip:x} = getelementptr [{span} x i8], [{span} x i8]* @hydir_memory, i64 0, i64 {off}\n  %q_{ip:x} = bitcast i8* %p_{ip:x} to i64*\n  %v_{ip:x} = load i64, i64* @{src}\n  store i64 %v_{ip:x}, i64* %q_{ip:x}, align 1\n"));
        }
        Mnemonic::Mov if i.op0_kind() == OpKind::Register => {
            let dst = reg(i.op0_register())?;
            let value = immediate(i, 1)?;
            out.push_str(&format!("  store i64 {value}, i64* @{dst}\n"));
        }
        Mnemonic::Movzx if i.op0_kind() == OpKind::Register && i.op1_kind() == OpKind::Memory => {
            let dst = reg(i.op0_register())?;
            let off = mapped(i, base, span, owned, 1)?;
            out.push_str(&format!("  %p_{ip:x} = getelementptr [{span} x i8], [{span} x i8]* @hydir_memory, i64 0, i64 {off}\n  %byte_{ip:x} = load i8, i8* %p_{ip:x}\n  %v_{ip:x} = zext i8 %byte_{ip:x} to i64\n  store i64 %v_{ip:x}, i64* @{dst}\n"));
        }
        Mnemonic::Lea if i.op0_kind() == OpKind::Register && i.op1_kind() == OpKind::Memory => {
            let dst = reg(i.op0_register())?;
            mapped(i, base, span, owned, 1)?;
            out.push_str(&format!(
                "  store i64 {}, i64* @{dst}\n",
                i.ip_rel_memory_address()
            ));
        }
        Mnemonic::Xor
            if i.op0_kind() == OpKind::Register
                && i.op1_kind() == OpKind::Register
                && i.op0_register() == i.op1_register() =>
        {
            let dst = reg(i.op0_register())?;
            out.push_str(&format!(
                "  store i64 0, i64* @{dst}\n  store i1 true, i1* @zf\n"
            ));
        }
        Mnemonic::Add | Mnemonic::Sub | Mnemonic::Cmp if i.op0_kind() == OpKind::Register => {
            let dst = reg(i.op0_register())?;
            let value = immediate(i, 1)?;
            let operation = if i.mnemonic() == Mnemonic::Add {
                "add"
            } else {
                "sub"
            };
            out.push_str(&format!("  %old_{ip:x} = load i64, i64* @{dst}\n  %v_{ip:x} = {operation} i64 %old_{ip:x}, {value}\n  %z_{ip:x} = icmp eq i64 %v_{ip:x}, 0\n  store i1 %z_{ip:x}, i1* @zf\n"));
            if i.mnemonic() != Mnemonic::Cmp {
                out.push_str(&format!("  store i64 %v_{ip:x}, i64* @{dst}\n"));
            }
        }
        Mnemonic::Call if i.op0_kind() == OpKind::NearBranch64 => {
            let target = i.near_branch_target();
            if !entries.contains(&target) {
                return Err(fail(format!("unresolved call at {at}")));
            }
            out.push_str(&format!("  call void @f_{target:x}()\n"));
        }
        Mnemonic::Jmp | Mnemonic::Je | Mnemonic::Jne if i.op0_kind() == OpKind::NearBranch64 => {
            let target = i.near_branch_target();
            if !f.instructions.contains_key(&target) {
                return Err(fail(format!("branch outside function at {at}")));
            }
            match i.mnemonic() {
                Mnemonic::Jmp => out.push_str(&format!("  br label %b_{target:x}\n")),
                Mnemonic::Je => out.push_str(&format!("  %z_{ip:x} = load i1, i1* @zf\n  br i1 %z_{ip:x}, label %b_{target:x}, label %b_{:x}\n", i.next_ip())),
                _ => out.push_str(&format!("  %z_{ip:x} = load i1, i1* @zf\n  br i1 %z_{ip:x}, label %b_{:x}, label %b_{target:x}\n", i.next_ip())),
            }
            if i.mnemonic() != Mnemonic::Jmp && !f.instructions.contains_key(&i.next_ip()) {
                return Err(fail(format!(
                    "conditional fallthrough outside function at {at}"
                )));
            }
            return Ok(out);
        }
        Mnemonic::Ret if i.op_count() == 0 => {
            return Ok("  ret void\n".to_owned());
        }
        Mnemonic::Syscall if i.op_count() == 0 => {
            for r in ["rax", "rdi", "rsi", "rdx"] {
                out.push_str(&format!("  %{r}_{ip:x} = load i64, i64* @{r}\n"));
            }
            out.push_str(&format!("  %result_{ip:x} = call i64 @hydir_syscall(i64 %rax_{ip:x}, i64 %rdi_{ip:x}, i64 %rsi_{ip:x}, i64 %rdx_{ip:x})\n  store i64 %result_{ip:x}, i64* @rax\n  store i64 {}, i64* @rcx\n", i.next_ip()));
        }
        _ => {
            return Err(fail(format!(
                "unsupported instruction {:?} at {at}",
                i.mnemonic()
            )));
        }
    }
    out.push_str(&next(i, f));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn llvm_byte_encoding_is_exact() {
        assert_eq!(llvm_bytes(&[0, 10, 255]), "\\00\\0A\\FF");
    }
    #[test]
    fn rejects_non_elf() {
        assert!(lift(b"not an elf").is_err());
    }
}
