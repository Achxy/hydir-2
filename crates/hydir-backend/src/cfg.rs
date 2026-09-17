//! Reachable direct-control-flow recovery and a deliberately small scalar
//! x86-64-to-LLVM lift. Each recovered instruction is an LLVM basic block;
//! machine registers and arithmetic flags are joined with explicit phi nodes.
//! This does not model guest memory, calls, or arbitrary x86 instructions.

use super::{Result, checked_register, error};
use hydir_core::{Address, AddressKind, BlockSpec, EdgeKind, EdgeSpec, FunctionCfg, SPEC_VERSION};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};
use std::collections::{BTreeMap, VecDeque};

const ALL_FIELDS: [Field; 9] = [
    Field::Rax,
    Field::Rdi,
    Field::Rsi,
    Field::Rdx,
    Field::Rcx,
    Field::Zf,
    Field::Sf,
    Field::Of,
    Field::Cf,
];
const FLAGS: u16 = Field::Zf.bit() | Field::Sf.bit() | Field::Of.bit() | Field::Cf.bit();
const INPUTS: u16 = Field::Rdi.bit() | Field::Rsi.bit();

#[derive(Clone, Copy, Debug)]
enum Field {
    Rax,
    Rdi,
    Rsi,
    Rdx,
    Rcx,
    Zf,
    Sf,
    Of,
    Cf,
}

impl Field {
    const fn bit(self) -> u16 {
        1 << (self as u8)
    }

    fn name(self) -> &'static str {
        match self {
            Self::Rax => "rax",
            Self::Rdi => "rdi",
            Self::Rsi => "rsi",
            Self::Rdx => "rdx",
            Self::Rcx => "rcx",
            Self::Zf => "zf",
            Self::Sf => "sf",
            Self::Of => "of",
            Self::Cf => "cf",
        }
    }

    fn ty(self) -> &'static str {
        match self {
            Self::Rax | Self::Rdi | Self::Rsi | Self::Rdx | Self::Rcx => "i64",
            _ => "i1",
        }
    }
}

fn register_field(register: Register) -> Field {
    match register {
        Register::RAX => Field::Rax,
        Register::RDI => Field::Rdi,
        Register::RSI => Field::Rsi,
        Register::RDX => Field::Rdx,
        Register::RCX => Field::Rcx,
        _ => unreachable!("all registers were checked during classification"),
    }
}

#[derive(Clone, Copy)]
enum Value {
    Register(Register),
    Immediate(i64),
}

#[derive(Clone, Copy)]
enum Alu {
    Add,
    Sub,
}

#[derive(Clone, Copy)]
enum Condition {
    E,
    Ne,
    G,
    Ge,
    L,
    Le,
    A,
    Ae,
    B,
    Be,
    S,
    Ns,
    O,
    No,
}

#[derive(Clone, Copy)]
enum Op {
    Mov {
        dst: Register,
        src: Value,
    },
    Lea {
        dst: Register,
        base: Option<Register>,
        index: Option<Register>,
        scale: u32,
        displacement: i64,
    },
    Alu {
        kind: Alu,
        dst: Register,
        src: Value,
    },
    Cmp {
        lhs: Register,
        rhs: Value,
    },
    Test {
        lhs: Register,
        rhs: Value,
    },
    Jcc(Condition),
    Jmp,
    Ret,
    Nop,
}

impl Op {
    fn defs(self) -> u16 {
        match self {
            Self::Mov { dst, .. } | Self::Lea { dst, .. } => register_field(dst).bit(),
            Self::Alu { dst, .. } => register_field(dst).bit() | FLAGS,
            Self::Cmp { .. } | Self::Test { .. } => FLAGS,
            _ => 0,
        }
    }

    fn reads(self) -> u16 {
        let value_bits = |value: Value| match value {
            Value::Register(register) => register_field(register).bit(),
            Value::Immediate(_) => 0,
        };
        match self {
            Self::Mov { src, .. } => value_bits(src),
            Self::Lea { base, index, .. } => {
                base.map_or(0, |r| register_field(r).bit())
                    | index.map_or(0, |r| register_field(r).bit())
            }
            Self::Alu { dst, src, .. } => register_field(dst).bit() | value_bits(src),
            Self::Cmp { lhs, rhs } | Self::Test { lhs, rhs } => {
                register_field(lhs).bit() | value_bits(rhs)
            }
            Self::Jcc(_) => FLAGS,
            Self::Ret => Field::Rax.bit(),
            Self::Jmp | Self::Nop => 0,
        }
    }
}

struct Node {
    raw: Vec<u8>,
    mnemonic: String,
    op: Op,
    successors: Vec<u64>,
}

fn operand(instruction: &Instruction, index: u32) -> Result<Value> {
    let ip = instruction.ip();
    Ok(match instruction.op_kind(index) {
        OpKind::Register => Value::Register(checked_register(instruction.op_register(index), ip)?),
        OpKind::Immediate8to64 => Value::Immediate(instruction.immediate8to64()),
        OpKind::Immediate32to64 => Value::Immediate(instruction.immediate32to64()),
        OpKind::Immediate64 => Value::Immediate(instruction.immediate64() as i64),
        _ => return Err(error(format!("operand kind unsupported at 0x{ip:x}"))),
    })
}

fn classify(instruction: &Instruction) -> Result<Op> {
    let ip = instruction.ip();
    if instruction.has_lock_prefix()
        || instruction.has_rep_prefix()
        || instruction.has_repne_prefix()
    {
        return Err(error(format!("instruction prefix unsupported at 0x{ip:x}")));
    }
    let register_dest = || checked_register(instruction.op0_register(), ip);
    let register_lhs = || checked_register(instruction.op0_register(), ip);
    let op = match instruction.mnemonic() {
        Mnemonic::Mov
            if instruction.op_count() == 2 && instruction.op0_kind() == OpKind::Register =>
        {
            Op::Mov {
                dst: register_dest()?,
                src: operand(instruction, 1)?,
            }
        }
        Mnemonic::Lea
            if instruction.op_count() == 2
                && instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Memory =>
        {
            if instruction.segment_prefix() != Register::None
                || instruction.memory_base() == Register::RIP
            {
                return Err(error(format!(
                    "segment/RIP-relative LEA unsupported at 0x{ip:x}"
                )));
            }
            let optional_register = |r| {
                if r == Register::None {
                    Ok(None)
                } else {
                    checked_register(r, ip).map(Some)
                }
            };
            Op::Lea {
                dst: register_dest()?,
                base: optional_register(instruction.memory_base())?,
                index: optional_register(instruction.memory_index())?,
                scale: instruction.memory_index_scale(),
                displacement: instruction.memory_displacement64() as i64,
            }
        }
        Mnemonic::Add | Mnemonic::Sub
            if instruction.op_count() == 2 && instruction.op0_kind() == OpKind::Register =>
        {
            Op::Alu {
                kind: if instruction.mnemonic() == Mnemonic::Add {
                    Alu::Add
                } else {
                    Alu::Sub
                },
                dst: register_dest()?,
                src: operand(instruction, 1)?,
            }
        }
        Mnemonic::Cmp | Mnemonic::Test
            if instruction.op_count() == 2 && instruction.op0_kind() == OpKind::Register =>
        {
            let lhs = register_lhs()?;
            let rhs = operand(instruction, 1)?;
            if instruction.mnemonic() == Mnemonic::Cmp {
                Op::Cmp { lhs, rhs }
            } else {
                Op::Test { lhs, rhs }
            }
        }
        Mnemonic::Jmp if instruction.flow_control() == FlowControl::UnconditionalBranch => Op::Jmp,
        Mnemonic::Je => Op::Jcc(Condition::E),
        Mnemonic::Jne => Op::Jcc(Condition::Ne),
        Mnemonic::Jg => Op::Jcc(Condition::G),
        Mnemonic::Jge => Op::Jcc(Condition::Ge),
        Mnemonic::Jl => Op::Jcc(Condition::L),
        Mnemonic::Jle => Op::Jcc(Condition::Le),
        Mnemonic::Ja => Op::Jcc(Condition::A),
        Mnemonic::Jae => Op::Jcc(Condition::Ae),
        Mnemonic::Jb => Op::Jcc(Condition::B),
        Mnemonic::Jbe => Op::Jcc(Condition::Be),
        Mnemonic::Js => Op::Jcc(Condition::S),
        Mnemonic::Jns => Op::Jcc(Condition::Ns),
        Mnemonic::Jo => Op::Jcc(Condition::O),
        Mnemonic::Jno => Op::Jcc(Condition::No),
        Mnemonic::Ret if instruction.op_count() == 0 => Op::Ret,
        Mnemonic::Nop if instruction.op_count() == 0 => Op::Nop,
        _ => {
            return Err(error(format!(
                "unsupported {:?} at 0x{ip:x}",
                instruction.mnemonic()
            )));
        }
    };
    if matches!(op, Op::Jcc(_) | Op::Jmp)
        && !matches!(
            instruction.op0_kind(),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        )
    {
        return Err(error(format!("non-direct branch unsupported at 0x{ip:x}")));
    }
    Ok(op)
}

fn recover(code: &[u8], address: u64) -> Result<BTreeMap<u64, Node>> {
    let end = address
        .checked_add(code.len() as u64)
        .ok_or_else(|| error("function address range overflow"))?;
    let mut pending = VecDeque::from([address]);
    let mut nodes = BTreeMap::new();
    let mut owners = vec![None; code.len()];
    while let Some(ip) = pending.pop_front() {
        if nodes.contains_key(&ip) {
            continue;
        }
        if !(address..end).contains(&ip) {
            return Err(error(format!("control flow leaves symbol at 0x{ip:x}")));
        }
        let offset = (ip - address) as usize;
        let mut decoder = Decoder::with_ip(64, &code[offset..], ip, DecoderOptions::NONE);
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            return Err(error(format!("invalid x86 instruction at 0x{ip:x}")));
        }
        let next = instruction.next_ip();
        let length = decoder.position();
        for owner in &mut owners[offset..offset + length] {
            if let Some(other) = owner {
                return Err(error(format!(
                    "overlapping instruction at 0x{ip:x} and 0x{other:x}"
                )));
            }
            *owner = Some(ip);
        }
        let op = classify(&instruction)?;
        let successors = match op {
            Op::Ret => vec![],
            Op::Jmp => vec![instruction.near_branch_target()],
            Op::Jcc(_) => vec![instruction.near_branch_target(), next],
            _ => vec![next],
        };
        for successor in successors.iter().rev() {
            if !(address..end).contains(successor) {
                return Err(error(format!(
                    "control flow from 0x{ip:x} leaves symbol at 0x{successor:x}"
                )));
            }
            pending.push_back(*successor);
        }
        nodes.insert(
            ip,
            Node {
                raw: code[offset..offset + length].to_vec(),
                mnemonic: format!("{:?}", instruction.mnemonic()),
                op,
                successors,
            },
        );
    }
    Ok(nodes)
}

pub(super) fn recover_function_cfg(
    code: &[u8],
    address: u64,
    address_kind: AddressKind,
    symbol_name: &str,
    binary_sha256: String,
    provenance: &str,
) -> Result<FunctionCfg> {
    if code.is_empty() || code.len() > 4096 {
        return Err(error("function must contain 1..=4096 bytes"));
    }
    let nodes = recover(code, address)?;
    let mut blocks = Vec::with_capacity(nodes.len());
    let mut edges = Vec::new();
    for (ip, node) in nodes {
        blocks.push(BlockSpec {
            address: Address(ip),
            bytes_hex: node.raw.iter().map(|byte| format!("{byte:02x}")).collect(),
            mnemonic: node.mnemonic,
        });
        for (index, successor) in node.successors.into_iter().enumerate() {
            let kind = match node.op {
                Op::Jcc(_) if index == 0 => EdgeKind::Taken,
                Op::Jcc(_) => EdgeKind::Fallthrough,
                Op::Jmp => EdgeKind::Direct,
                _ => EdgeKind::Fallthrough,
            };
            edges.push(EdgeSpec {
                source: Address(ip),
                target: Address(successor),
                kind,
            });
        }
    }
    Ok(FunctionCfg {
        schema_version: SPEC_VERSION,
        binary_sha256,
        symbol_name: symbol_name.to_owned(),
        entry: Address(address),
        address_kind,
        symbol_size: code.len() as u64,
        blocks,
        edges,
        provenance: provenance.to_owned(),
        recovery_scope: "Reachable direct control flow within the selected symbol; unsupported calls, indirect edges, and instructions reject recovery".to_owned(),
    })
}

struct Flow {
    incoming: BTreeMap<u64, u16>,
    predecessors: BTreeMap<u64, Vec<u64>>,
}

fn analyze(nodes: &BTreeMap<u64, Node>, address: u64) -> Result<Flow> {
    let mut predecessors: BTreeMap<u64, Vec<u64>> =
        nodes.keys().map(|ip| (*ip, Vec::new())).collect();
    for (ip, node) in nodes {
        for successor in &node.successors {
            predecessors
                .get_mut(successor)
                .ok_or_else(|| error("internal CFG successor missing"))?
                .push(*ip);
        }
    }
    let all = ALL_FIELDS.iter().fold(0, |bits, field| bits | field.bit());
    let mut incoming: BTreeMap<u64, u16> = nodes.keys().map(|ip| (*ip, all)).collect();
    let mut outgoing = incoming.clone();
    loop {
        let mut changed = false;
        for (ip, node) in nodes {
            let mut bits = all;
            if *ip == address {
                bits &= INPUTS;
            }
            for predecessor in &predecessors[ip] {
                bits &= outgoing[predecessor];
            }
            let out = bits | node.op.defs();
            if incoming[ip] != bits || outgoing[ip] != out {
                incoming.insert(*ip, bits);
                outgoing.insert(*ip, out);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    for (ip, node) in nodes {
        let missing = node.op.reads() & !incoming[ip];
        if missing != 0 {
            let field = ALL_FIELDS
                .iter()
                .find(|field| missing & field.bit() != 0)
                .unwrap();
            return Err(error(format!(
                "read of uninitialized {} at 0x{ip:x} on at least one path",
                field.name().to_uppercase()
            )));
        }
    }
    Ok(Flow {
        incoming,
        predecessors,
    })
}

fn input_name(field: Field, ip: u64) -> String {
    format!("%{}_in_{ip:x}", field.name())
}

fn output_name(field: Field, ip: u64) -> String {
    format!("%{}_out_{ip:x}", field.name())
}

fn value_name(value: Value, ip: u64) -> String {
    match value {
        Value::Register(register) => input_name(register_field(register), ip),
        Value::Immediate(value) => value.to_string(),
    }
}

fn temporary(body: &mut String, ip: u64, sequence: &mut usize, operation: &str) -> String {
    let name = format!("%t_{ip:x}_{}", *sequence);
    *sequence += 1;
    body.push_str(&format!("  {name} = {operation}\n"));
    name
}

fn emit_flags(
    body: &mut String,
    ip: u64,
    lhs: &str,
    rhs: &str,
    result: &str,
    kind: Option<Alu>,
    sequence: &mut usize,
) {
    body.push_str(&format!(
        "  {} = icmp eq i64 {result}, 0\n",
        output_name(Field::Zf, ip)
    ));
    body.push_str(&format!(
        "  {} = icmp slt i64 {result}, 0\n",
        output_name(Field::Sf, ip)
    ));
    match kind {
        None => {
            body.push_str(&format!(
                "  {} = and i1 false, false\n",
                output_name(Field::Of, ip)
            ));
            body.push_str(&format!(
                "  {} = and i1 false, false\n",
                output_name(Field::Cf, ip)
            ));
        }
        Some(kind) => {
            let lhs_neg = temporary(body, ip, sequence, &format!("icmp slt i64 {lhs}, 0"));
            let rhs_neg = temporary(body, ip, sequence, &format!("icmp slt i64 {rhs}, 0"));
            let first = temporary(
                body,
                ip,
                sequence,
                &format!(
                    "icmp {} i1 {lhs_neg}, {rhs_neg}",
                    if matches!(kind, Alu::Add) { "eq" } else { "ne" }
                ),
            );
            let changed = temporary(
                body,
                ip,
                sequence,
                &format!("icmp ne i1 {lhs_neg}, {}", output_name(Field::Sf, ip)),
            );
            body.push_str(&format!(
                "  {} = and i1 {first}, {changed}\n",
                output_name(Field::Of, ip)
            ));
            let carry = if matches!(kind, Alu::Add) {
                format!("icmp ult i64 {result}, {lhs}")
            } else {
                format!("icmp ult i64 {lhs}, {rhs}")
            };
            body.push_str(&format!("  {} = {carry}\n", output_name(Field::Cf, ip)));
        }
    }
}

fn condition_name(
    condition: Condition,
    ip: u64,
    body: &mut String,
    sequence: &mut usize,
) -> String {
    let zf = input_name(Field::Zf, ip);
    let sf = input_name(Field::Sf, ip);
    let of = input_name(Field::Of, ip);
    let cf = input_name(Field::Cf, ip);
    let negate = |body: &mut String, sequence: &mut usize, value: &str| {
        temporary(body, ip, sequence, &format!("xor i1 {value}, true"))
    };
    match condition {
        Condition::E => zf,
        Condition::Ne => negate(body, sequence, &zf),
        Condition::S => sf,
        Condition::Ns => negate(body, sequence, &sf),
        Condition::O => of,
        Condition::No => negate(body, sequence, &of),
        Condition::B => cf,
        Condition::Ae => negate(body, sequence, &cf),
        Condition::Be => temporary(body, ip, sequence, &format!("or i1 {cf}, {zf}")),
        Condition::A => {
            let either = temporary(body, ip, sequence, &format!("or i1 {cf}, {zf}"));
            negate(body, sequence, &either)
        }
        Condition::L => temporary(body, ip, sequence, &format!("xor i1 {sf}, {of}")),
        Condition::Ge => temporary(body, ip, sequence, &format!("icmp eq i1 {sf}, {of}")),
        Condition::Le => {
            let less = temporary(body, ip, sequence, &format!("xor i1 {sf}, {of}"));
            temporary(body, ip, sequence, &format!("or i1 {zf}, {less}"))
        }
        Condition::G => {
            let equal_sign = temporary(body, ip, sequence, &format!("icmp eq i1 {sf}, {of}"));
            let nonzero = negate(body, sequence, &zf);
            temporary(
                body,
                ip,
                sequence,
                &format!("and i1 {nonzero}, {equal_sign}"),
            )
        }
    }
}

fn emit_node(body: &mut String, ip: u64, node: &Node) {
    let mut sequence = 0;
    match node.op {
        Op::Mov { dst, src } => {
            body.push_str(&format!(
                "  {} = add i64 0, {}\n",
                output_name(register_field(dst), ip),
                value_name(src, ip)
            ));
        }
        Op::Lea {
            dst,
            base,
            index,
            scale,
            displacement,
        } => {
            let base = base.map_or_else(|| "0".to_owned(), |r| input_name(register_field(r), ip));
            let index = index.map_or_else(|| "0".to_owned(), |r| input_name(register_field(r), ip));
            let scaled = if scale == 1 {
                index
            } else {
                temporary(
                    body,
                    ip,
                    &mut sequence,
                    &format!("mul i64 {index}, {scale}"),
                )
            };
            let sum = temporary(
                body,
                ip,
                &mut sequence,
                &format!("add i64 {base}, {scaled}"),
            );
            body.push_str(&format!(
                "  {} = add i64 {sum}, {displacement}\n",
                output_name(register_field(dst), ip)
            ));
        }
        Op::Alu { kind, dst, src } => {
            let lhs = input_name(register_field(dst), ip);
            let rhs = value_name(src, ip);
            let result = output_name(register_field(dst), ip);
            body.push_str(&format!(
                "  {result} = {} i64 {lhs}, {rhs}\n",
                if matches!(kind, Alu::Add) {
                    "add"
                } else {
                    "sub"
                }
            ));
            emit_flags(body, ip, &lhs, &rhs, &result, Some(kind), &mut sequence);
        }
        Op::Cmp { lhs, rhs } => {
            let lhs = input_name(register_field(lhs), ip);
            let rhs = value_name(rhs, ip);
            let result = temporary(body, ip, &mut sequence, &format!("sub i64 {lhs}, {rhs}"));
            emit_flags(body, ip, &lhs, &rhs, &result, Some(Alu::Sub), &mut sequence);
        }
        Op::Test { lhs, rhs } => {
            let lhs = input_name(register_field(lhs), ip);
            let rhs = value_name(rhs, ip);
            let result = temporary(body, ip, &mut sequence, &format!("and i64 {lhs}, {rhs}"));
            emit_flags(body, ip, &lhs, &rhs, &result, None, &mut sequence);
        }
        Op::Jcc(condition) => {
            let predicate = condition_name(condition, ip, body, &mut sequence);
            body.push_str(&format!(
                "  br i1 {predicate}, label %b{:x}, label %b{:x}\n",
                node.successors[0], node.successors[1]
            ));
        }
        Op::Jmp => body.push_str(&format!("  br label %b{:x}\n", node.successors[0])),
        Op::Ret => body.push_str(&format!("  ret i64 {}\n", input_name(Field::Rax, ip))),
        Op::Nop => body.push_str(&format!("  br label %b{:x}\n", node.successors[0])),
    }
    if matches!(
        node.op,
        Op::Mov { .. } | Op::Lea { .. } | Op::Alu { .. } | Op::Cmp { .. } | Op::Test { .. }
    ) {
        body.push_str(&format!("  br label %b{:x}\n", node.successors[0]));
    }
}

/// Lift all instructions reachable from the first byte of a symbol-bounded
/// function. Only direct branches within the symbol are allowed. The caller
/// asserts the `u64(u64, u64)` SysV ABI contract; uninitialized register or
/// flag reads on any recovered path are rejected before IR is emitted.
pub fn lift_cfg(code: &[u8], address: u64) -> Result<String> {
    if code.is_empty() || code.len() > 4096 {
        return Err(error("function must contain 1..=4096 bytes"));
    }
    let nodes = recover(code, address)?;
    let flow = analyze(&nodes, address)?;
    let mut body = format!("prologue:\n  br label %b{address:x}\n");
    for (ip, node) in &nodes {
        body.push_str(&format!("b{ip:x}:\n"));
        body.push_str(&format!(
            "  ; 0x{ip:x}: {}\n",
            node.raw
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        for field in ALL_FIELDS {
            if flow.incoming[ip] & field.bit() == 0 {
                continue;
            }
            let mut values = Vec::new();
            if *ip == address && INPUTS & field.bit() != 0 {
                let arg = if matches!(field, Field::Rdi) {
                    "%arg0"
                } else {
                    "%arg1"
                };
                values.push(format!("[{arg}, %prologue]"));
            }
            for predecessor in &flow.predecessors[ip] {
                let predecessor_node = &nodes[predecessor];
                let name = if predecessor_node.op.defs() & field.bit() != 0 {
                    output_name(field, *predecessor)
                } else {
                    input_name(field, *predecessor)
                };
                values.push(format!("[{name}, %b{predecessor:x}]"));
            }
            body.push_str(&format!(
                "  {} = phi {} {}\n",
                input_name(field, *ip),
                field.ty(),
                values.join(", ")
            ));
        }
        emit_node(&mut body, *ip, node);
    }
    Ok(format!(
        "; HydIR raw direct-CFG lift; asserted prototype: u64(u64, u64)\n\
         ; Unmodeled memory, calls, indirect edges, and partial registers are rejected.\n\
         target triple = \"x86_64-unknown-linux-gnu\"\n\n\
         define i64 @hydir_lifted(i64 %arg0, i64 %arg1) {{\n{body}}}\n"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovers_diamond_with_phis() {
        // mov rax,rdi; cmp rdi,rsi; jae +3; mov rax,rsi; ret
        let code = [
            0x48, 0x89, 0xf8, 0x48, 0x39, 0xf7, 0x73, 0x03, 0x48, 0x89, 0xf0, 0xc3,
        ];
        let ir = lift_cfg(&code, 0x1000).unwrap();
        assert!(ir.contains("phi i64"));
        assert!(ir.contains("br i1"));
        assert!(ir.contains("%rax_out_1008"));
    }

    #[test]
    fn rejects_branch_into_instruction() {
        // cmp rdi,rsi; je +1 reaches the second byte of mov rax,rdi,
        // while the fallthrough reaches its first byte.
        let code = [0x48, 0x39, 0xf7, 0x74, 0x01, 0x48, 0x89, 0xf8, 0xc3];
        let err = lift_cfg(&code, 0).unwrap_err();
        assert!(err.0.contains("overlapping instruction"), "{err}");
    }

    #[test]
    fn rejects_uninitialized_flags() {
        // je +3; mov rax,rdi; ret
        let code = [0x74, 0x03, 0x48, 0x89, 0xf8, 0xc3];
        assert!(
            lift_cfg(&code, 0)
                .unwrap_err()
                .0
                .contains("uninitialized ZF")
        );
    }

    #[test]
    fn rejects_uninitialized_result_on_one_path() {
        // cmp rdi,rsi; je +3; mov rax,rdi; ret
        let code = [0x48, 0x39, 0xf7, 0x74, 0x03, 0x48, 0x89, 0xf8, 0xc3];
        assert!(
            lift_cfg(&code, 0)
                .unwrap_err()
                .0
                .contains("uninitialized RAX")
        );
    }
}
