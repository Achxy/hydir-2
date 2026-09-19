//! Reachable direct-control-flow recovery and a deliberately small scalar
//! x86-64-to-LLVM lift. Each recovered instruction is an LLVM basic block;
//! machine registers and arithmetic flags are joined with explicit phi nodes.
//! Balanced frame-only stack operations may be erased after a separate stack
//! proof when they cannot affect scalar return values or branch flags.
//! Four- and eight-byte stack locals use proven, nonoverlapping frame slots
//! and SSA values. Calls and arbitrary x86 instructions remain unsupported.

use super::{Result, error};
use hydir_core::{Address, AddressKind, BlockSpec, EdgeKind, EdgeSpec, FunctionCfg, SPEC_VERSION};
use hydir_semantics::{Alu, Condition, Op, Value, Value32, classify};
use iced_x86::{Decoder, DecoderOptions, Register};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const ALL_FIELDS: [Field; 26] = [
    Field::Rax,
    Field::Rbx,
    Field::Rdi,
    Field::Rsi,
    Field::Rdx,
    Field::Rcx,
    Field::R8,
    Field::R9,
    Field::R10,
    Field::R11,
    Field::R12,
    Field::R13,
    Field::R14,
    Field::R15,
    Field::Zf,
    Field::Sf,
    Field::Of,
    Field::Cf,
    Field::Slot(0),
    Field::Slot(1),
    Field::Slot(2),
    Field::Slot(3),
    Field::Slot(4),
    Field::Slot(5),
    Field::Slot(6),
    Field::Slot(7),
];
const INPUTS: u32 = Field::Rdi.bit()
    | Field::Rsi.bit()
    | Field::Rdx.bit()
    | Field::Rcx.bit()
    | Field::R8.bit()
    | Field::R9.bit();

#[derive(Clone, Copy, Debug)]
enum Field {
    Rax,
    Rbx,
    Rdi,
    Rsi,
    Rdx,
    Rcx,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    Zf,
    Sf,
    Of,
    Cf,
    Slot(u8),
}

impl Field {
    const fn bit(self) -> u32 {
        let index = match self {
            Self::Rax => 0,
            Self::Rbx => 11,
            Self::Rdi => 1,
            Self::Rsi => 2,
            Self::Rdx => 3,
            Self::Rcx => 4,
            Self::R8 => 9,
            Self::R9 => 10,
            Self::R10 => 12,
            Self::R11 => 13,
            Self::R12 => 14,
            Self::R13 => 15,
            Self::R14 => 16,
            Self::R15 => 17,
            Self::Zf => 5,
            Self::Sf => 6,
            Self::Of => 7,
            Self::Cf => 8,
            Self::Slot(index) => 18 + index,
        };
        1 << index
    }

    fn name(self) -> String {
        match self {
            Self::Rax => "rax".into(),
            Self::Rbx => "rbx".into(),
            Self::Rdi => "rdi".into(),
            Self::Rsi => "rsi".into(),
            Self::Rdx => "rdx".into(),
            Self::Rcx => "rcx".into(),
            Self::R8 => "r8".into(),
            Self::R9 => "r9".into(),
            Self::R10 => "r10".into(),
            Self::R11 => "r11".into(),
            Self::R12 => "r12".into(),
            Self::R13 => "r13".into(),
            Self::R14 => "r14".into(),
            Self::R15 => "r15".into(),
            Self::Zf => "zf".into(),
            Self::Sf => "sf".into(),
            Self::Of => "of".into(),
            Self::Cf => "cf".into(),
            Self::Slot(index) => format!("slot{index}"),
        }
    }

    fn ty(self) -> &'static str {
        match self {
            Self::Rax
            | Self::Rbx
            | Self::Rdi
            | Self::Rsi
            | Self::Rdx
            | Self::Rcx
            | Self::R8
            | Self::R9
            | Self::R10
            | Self::R11
            | Self::R12
            | Self::R13
            | Self::R14
            | Self::R15
            | Self::Slot(_) => "i64",
            _ => "i1",
        }
    }
}

fn register_field(register: Register) -> Field {
    match register {
        Register::RAX => Field::Rax,
        Register::RBX => Field::Rbx,
        Register::RDI => Field::Rdi,
        Register::RSI => Field::Rsi,
        Register::RDX => Field::Rdx,
        Register::RCX => Field::Rcx,
        Register::R8 => Field::R8,
        Register::R9 => Field::R9,
        Register::R10 => Field::R10,
        Register::R11 => Field::R11,
        Register::R12 => Field::R12,
        Register::R13 => Field::R13,
        Register::R14 => Field::R14,
        Register::R15 => Field::R15,
        _ => unreachable!("all registers were checked during classification"),
    }
}

trait OpEffects {
    fn defs(self) -> u32;
    fn reads(self) -> u32;
}

impl OpEffects for Op {
    fn defs(self) -> u32 {
        if is_frame_op(self) {
            return 0;
        }
        let effects = self.effects();
        register_effect_fields(effects.write_registers) | (u32::from(effects.write_flags) << 5)
    }

    fn reads(self) -> u32 {
        if is_frame_op(self) {
            return 0;
        }
        if matches!(self, Op::Ret) {
            return Field::Rax.bit();
        }
        let effects = self.effects();
        register_effect_fields(effects.read_registers) | (u32::from(effects.read_flags) << 5)
    }
}

fn register_effect_fields(registers: u16) -> u32 {
    [
        (hydir_semantics::RAX, Field::Rax),
        (hydir_semantics::RBX, Field::Rbx),
        (hydir_semantics::RDI, Field::Rdi),
        (hydir_semantics::RSI, Field::Rsi),
        (hydir_semantics::RDX, Field::Rdx),
        (hydir_semantics::RCX, Field::Rcx),
        (hydir_semantics::R8, Field::R8),
        (hydir_semantics::R9, Field::R9),
        (hydir_semantics::R10, Field::R10),
        (hydir_semantics::R11, Field::R11),
        (hydir_semantics::R12, Field::R12),
        (hydir_semantics::R13, Field::R13),
        (hydir_semantics::R14, Field::R14),
        (hydir_semantics::R15, Field::R15),
    ]
    .into_iter()
    .fold(0, |fields, (bit, field)| {
        fields | if registers & bit != 0 { field.bit() } else { 0 }
    })
}

fn is_frame_op(op: Op) -> bool {
    matches!(
        op,
        Op::SaveFramePointer
            | Op::RestoreFramePointer
            | Op::SetFramePointer
            | Op::RestoreStackPointerFromFrame
            | Op::AdjustStack { .. }
            | Op::LeaveFrame
    )
}

fn reject_stack_flag_uses(nodes: &BTreeMap<u64, Node>, entry: u64) -> Result<()> {
    let mut pending = VecDeque::from([(entry, false)]);
    let mut visited = std::collections::BTreeSet::new();
    while let Some((ip, mut stack_flags_live)) = pending.pop_front() {
        if !visited.insert((ip, stack_flags_live)) {
            continue;
        }
        let node = nodes
            .get(&ip)
            .ok_or_else(|| error("internal stack flag path leaves CFG"))?;
        if stack_flags_live && matches!(node.op, Op::Jcc(_)) {
            return Err(error(
                "stack adjustment may set flags used by a conditional branch",
            ));
        }
        if matches!(node.op, Op::AdjustStack { .. }) {
            stack_flags_live = true;
        } else if node.op.effects().write_flags != 0 {
            stack_flags_live = false;
        }
        for successor in &node.successors {
            pending.push_back((*successor, stack_flags_live));
        }
    }
    Ok(())
}

struct Node {
    raw: Vec<u8>,
    mnemonic: String,
    op: Op,
    successors: Vec<u64>,
    call_target: Option<u64>,
    slot: Option<u8>,
}

impl Node {
    fn defs(&self) -> u32 {
        if matches!(self.op, Op::CallDirect { .. }) {
            return Field::Rax.bit();
        }
        self.op.defs()
            | if matches!(
                self.op,
                Op::StoreStack64 { .. } | Op::StoreStack32 { .. } | Op::AluStack32 { .. }
            ) {
                Field::Slot(self.slot.expect("validated stack store")).bit()
            } else {
                0
            }
    }

    fn reads(&self) -> u32 {
        if matches!(self.op, Op::CallDirect { .. }) {
            return INPUTS;
        }
        self.op.reads()
            | if matches!(
                self.op,
                Op::LoadStack64 { .. }
                    | Op::LoadStack32 { .. }
                    | Op::AluStack32 { .. }
                    | Op::CmpRegStack32 { .. }
                    | Op::CmpStack32 { .. }
            ) {
                Field::Slot(self.slot.expect("validated stack load")).bit()
            } else {
                0
            }
    }

    fn kills(&self) -> u32 {
        if matches!(self.op, Op::CallDirect { .. }) {
            (Field::Rax.bit()
                | Field::Rdi.bit()
                | Field::Rsi.bit()
                | Field::Rdx.bit()
                | Field::Rcx.bit()
                | Field::R8.bit()
                | Field::R9.bit()
                | Field::R10.bit()
                | Field::R11.bit()
                | Field::Zf.bit()
                | Field::Sf.bit()
                | Field::Of.bit()
                | Field::Cf.bit())
                & !Field::Rax.bit()
        } else {
            0
        }
    }
}

fn recover_bounded(
    code: &[u8],
    address: u64,
    allowed_calls: Option<&BTreeSet<u64>>,
    boundary_exits: Option<&BTreeSet<u64>>,
    prove_stack: bool,
) -> Result<BTreeMap<u64, Node>> {
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
        let op = classify(&instruction).map_err(error)?;
        if let Op::CallDirect { target } = op
            && allowed_calls.is_some_and(|allowed| !allowed.contains(&target))
        {
            return Err(error(format!(
                "direct call at 0x{ip:x} to 0x{target:x} requires a resolved callee and ABI state proof"
            )));
        }
        let call_target = if let Op::CallDirect { target } = op {
            Some(target)
        } else {
            None
        };
        let successors = match op {
            Op::Ret => vec![],
            Op::Jmp => vec![instruction.near_branch_target()],
            Op::Jcc(_) => vec![instruction.near_branch_target(), next],
            _ => vec![next],
        };
        for successor in successors.iter().rev() {
            if !(address..end).contains(successor) {
                if boundary_exits.is_some_and(|exits| exits.contains(successor)) {
                    continue;
                }
                return Err(error(format!(
                    "control flow from 0x{ip:x} leaves symbol at undeclared exit 0x{successor:x}"
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
                call_target,
                slot: None,
            },
        );
    }
    if prove_stack
        && nodes.values().any(|node| {
            is_frame_op(node.op)
                || matches!(
                    node.op,
                    Op::LoadStack64 { .. }
                        | Op::LoadStack32 { .. }
                        | Op::StoreStack64 { .. }
                        | Op::StoreStack32 { .. }
                        | Op::AluStack32 { .. }
                        | Op::CmpRegStack32 { .. }
                        | Op::CmpStack32 { .. }
                        | Op::CallDirect { .. }
                )
        })
    {
        let evidence = if allowed_calls.is_some_and(BTreeSet::is_empty) {
            super::stack::analyze_stack(code, address)?
        } else {
            super::stack::analyze_stack_with_calls(code, address)?
        };
        for (ip, slot_offset) in evidence.slot_by_ip {
            let index = evidence
                .slots
                .binary_search(&slot_offset)
                .map_err(|_| error("internal stack-local slot is missing"))?;
            nodes
                .get_mut(&ip)
                .ok_or_else(|| error("internal stack-local instruction is missing"))?
                .slot = Some(index as u8);
        }
        reject_stack_flag_uses(&nodes, address)?;
    }
    Ok(nodes)
}

fn recover(
    code: &[u8],
    address: u64,
    allowed_calls: Option<&BTreeSet<u64>>,
) -> Result<BTreeMap<u64, Node>> {
    recover_bounded(code, address, allowed_calls, None, true)
}

pub(super) fn recover_declared_region_cfg(
    code: &[u8],
    address: u64,
    exits: &[Address],
    address_kind: AddressKind,
    symbol_name: &str,
    binary_sha256: String,
    provenance: &str,
) -> Result<FunctionCfg> {
    if code.is_empty() || code.len() > 4096 {
        return Err(error("region must contain 1..=4096 bytes"));
    }
    let end = address
        .checked_add(code.len() as u64)
        .ok_or_else(|| error("region address range overflow"))?;
    let declared = exits.iter().map(|exit| exit.0).collect::<BTreeSet<_>>();
    if declared.iter().any(|exit| (address..end).contains(exit)) {
        return Err(error("declared region exit lies inside selected bytes"));
    }
    let nodes = recover_bounded(code, address, None, Some(&declared), false)?;
    let mut observed = nodes
        .values()
        .flat_map(|node| node.successors.iter().copied())
        .filter(|successor| !(address..end).contains(successor))
        .chain(
            nodes
                .values()
                .filter_map(|node| node.call_target)
                .filter(|target| declared.contains(target)),
        )
        .collect::<Vec<_>>();
    observed.sort_unstable();
    let mut expected = exits.iter().map(|exit| exit.0).collect::<Vec<_>>();
    expected.sort_unstable();
    if observed != expected {
        return Err(error(format!(
            "declared region exits are not exact; expected {expected:x?}, observed {observed:x?}"
        )));
    }

    let mut blocks = Vec::with_capacity(nodes.len());
    let mut edges = Vec::new();
    for (ip, node) in nodes {
        if let Some(target) = node.call_target {
            edges.push(EdgeSpec {
                source: Address(ip),
                target: Address(target),
                kind: EdgeKind::Call,
            });
        }
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
        recovery_scope: "Exact direct control flow inside RegionSpec bytes with declared external exits and separately typed direct-call edges; semantic boundary state is not inferred"
            .to_owned(),
    })
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
    let nodes = recover(code, address, Some(&BTreeSet::new()))?;
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
    incoming: BTreeMap<u64, u32>,
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
    let mut incoming: BTreeMap<u64, u32> = nodes.keys().map(|ip| (*ip, all)).collect();
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
            let out = (bits & !node.kills()) | node.defs();
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
        let missing = node.reads() & !incoming[ip];
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

fn value32_name(value: Value32, ip: u64) -> String {
    match value {
        Value32::Register(register) => input_name(register_field(register), ip),
        Value32::Immediate(value) => value.to_string(),
    }
}

fn temporary(body: &mut String, ip: u64, sequence: &mut usize, operation: &str) -> String {
    let name = format!("%t_{ip:x}_{}", *sequence);
    *sequence += 1;
    body.push_str(&format!("  {name} = {operation}\n"));
    name
}

fn mask32(body: &mut String, ip: u64, sequence: &mut usize, value: &str) -> String {
    temporary(body, ip, sequence, &format!("and i64 {value}, 4294967295"))
}

fn sign32(body: &mut String, ip: u64, sequence: &mut usize, value: &str) -> String {
    let bit = temporary(body, ip, sequence, &format!("and i64 {value}, 2147483648"));
    temporary(body, ip, sequence, &format!("icmp ne i64 {bit}, 0"))
}

fn emit_flags32(
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
    let lhs_negative = sign32(body, ip, sequence, lhs);
    let rhs_negative = sign32(body, ip, sequence, rhs);
    let result_negative = sign32(body, ip, sequence, result);
    body.push_str(&format!(
        "  {} = or i1 {result_negative}, false\n",
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
        Some(kind @ (Alu::Add | Alu::Sub)) => {
            let operands_differ = temporary(
                body,
                ip,
                sequence,
                &format!("xor i1 {lhs_negative}, {rhs_negative}"),
            );
            let lhs_result_differ = temporary(
                body,
                ip,
                sequence,
                &format!("xor i1 {lhs_negative}, {result_negative}"),
            );
            let overflow = if kind == Alu::Add {
                let same_operands = temporary(
                    body,
                    ip,
                    sequence,
                    &format!("xor i1 {operands_differ}, true"),
                );
                temporary(
                    body,
                    ip,
                    sequence,
                    &format!("and i1 {same_operands}, {lhs_result_differ}"),
                )
            } else {
                temporary(
                    body,
                    ip,
                    sequence,
                    &format!("and i1 {operands_differ}, {lhs_result_differ}"),
                )
            };
            body.push_str(&format!(
                "  {} = or i1 {overflow}, false\n",
                output_name(Field::Of, ip)
            ));
            let carry_operation = if kind == Alu::Add {
                format!("icmp ult i64 {result}, {lhs}")
            } else {
                format!("icmp ult i64 {lhs}, {rhs}")
            };
            let carry = temporary(body, ip, sequence, &carry_operation);
            body.push_str(&format!(
                "  {} = or i1 {carry}, false\n",
                output_name(Field::Cf, ip)
            ));
        }
        Some(Alu::And | Alu::Or | Alu::Xor) => {
            body.push_str(&format!(
                "  {} = and i1 false, false\n  {} = and i1 false, false\n",
                output_name(Field::Of, ip),
                output_name(Field::Cf, ip)
            ));
        }
    }
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
        Some(kind @ (Alu::Add | Alu::Sub)) => {
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
        Some(Alu::And | Alu::Or | Alu::Xor) => {
            body.push_str(&format!(
                "  {} = and i1 false, false\n",
                output_name(Field::Of, ip)
            ));
            body.push_str(&format!(
                "  {} = and i1 false, false\n",
                output_name(Field::Cf, ip)
            ));
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
        Op::Mov32 { dst, src } => {
            let value = match src {
                Value32::Register(register) => {
                    let source = input_name(register_field(register), ip);
                    temporary(
                        body,
                        ip,
                        &mut sequence,
                        &format!("trunc i64 {source} to i32"),
                    )
                }
                Value32::Immediate(value) => value.to_string(),
            };
            body.push_str(&format!(
                "  {} = zext i32 {value} to i64\n",
                output_name(register_field(dst), ip),
            ));
        }
        Op::LoadStack64 { dst, .. } => {
            let slot = Field::Slot(node.slot.expect("validated stack load"));
            body.push_str(&format!(
                "  {} = add i64 0, {}\n",
                output_name(register_field(dst), ip),
                input_name(slot, ip)
            ));
        }
        Op::LoadStack32 { dst, .. } => {
            let slot = Field::Slot(node.slot.expect("validated stack load"));
            let value = mask32(body, ip, &mut sequence, &input_name(slot, ip));
            body.push_str(&format!(
                "  {} = add i64 0, {value}\n",
                output_name(register_field(dst), ip)
            ));
        }
        Op::StoreStack64 { src, .. } => {
            let slot = Field::Slot(node.slot.expect("validated stack store"));
            body.push_str(&format!(
                "  {} = add i64 0, {}\n",
                output_name(slot, ip),
                input_name(register_field(src), ip)
            ));
        }
        Op::StoreStack32 { src, .. } => {
            let slot = Field::Slot(node.slot.expect("validated stack store"));
            let value = mask32(body, ip, &mut sequence, &value32_name(src, ip));
            body.push_str(&format!(
                "  {} = add i64 0, {value}\n",
                output_name(slot, ip)
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
                match kind {
                    Alu::Add => "add",
                    Alu::Sub => "sub",
                    Alu::And => "and",
                    Alu::Or => "or",
                    Alu::Xor => "xor",
                }
            ));
            emit_flags(body, ip, &lhs, &rhs, &result, Some(kind), &mut sequence);
        }
        Op::Alu32 { kind, dst, src } => {
            let lhs = mask32(
                body,
                ip,
                &mut sequence,
                &input_name(register_field(dst), ip),
            );
            let rhs = mask32(body, ip, &mut sequence, &value32_name(src, ip));
            let raw = temporary(
                body,
                ip,
                &mut sequence,
                &format!(
                    "{} i64 {lhs}, {rhs}",
                    match kind {
                        Alu::Add => "add",
                        Alu::Sub => "sub",
                        Alu::And => "and",
                        Alu::Or => "or",
                        Alu::Xor => "xor",
                    }
                ),
            );
            let result = mask32(body, ip, &mut sequence, &raw);
            body.push_str(&format!(
                "  {} = add i64 0, {result}\n",
                output_name(register_field(dst), ip)
            ));
            emit_flags32(body, ip, &lhs, &rhs, &result, Some(kind), &mut sequence);
        }
        Op::AluStack32 { kind, src, .. } => {
            let slot = Field::Slot(node.slot.expect("validated stack arithmetic"));
            let lhs = mask32(body, ip, &mut sequence, &input_name(slot, ip));
            let rhs = mask32(body, ip, &mut sequence, &value32_name(src, ip));
            let raw = temporary(
                body,
                ip,
                &mut sequence,
                &format!(
                    "{} i64 {lhs}, {rhs}",
                    match kind {
                        Alu::Add => "add",
                        Alu::Sub => "sub",
                        Alu::And => "and",
                        Alu::Or => "or",
                        Alu::Xor => "xor",
                    }
                ),
            );
            let result = mask32(body, ip, &mut sequence, &raw);
            body.push_str(&format!(
                "  {} = add i64 0, {result}\n",
                output_name(slot, ip)
            ));
            emit_flags32(body, ip, &lhs, &rhs, &result, Some(kind), &mut sequence);
        }
        Op::Cmp { lhs, rhs } => {
            let lhs = input_name(register_field(lhs), ip);
            let rhs = value_name(rhs, ip);
            let result = temporary(body, ip, &mut sequence, &format!("sub i64 {lhs}, {rhs}"));
            emit_flags(body, ip, &lhs, &rhs, &result, Some(Alu::Sub), &mut sequence);
        }
        Op::Cmp32 { lhs, rhs } => {
            let lhs = mask32(
                body,
                ip,
                &mut sequence,
                &input_name(register_field(lhs), ip),
            );
            let rhs = mask32(body, ip, &mut sequence, &value32_name(rhs, ip));
            let raw = temporary(body, ip, &mut sequence, &format!("sub i64 {lhs}, {rhs}"));
            let result = mask32(body, ip, &mut sequence, &raw);
            emit_flags32(body, ip, &lhs, &rhs, &result, Some(Alu::Sub), &mut sequence);
        }
        Op::CmpRegStack32 { lhs, .. } => {
            let slot = Field::Slot(node.slot.expect("validated stack comparison"));
            let lhs = mask32(
                body,
                ip,
                &mut sequence,
                &input_name(register_field(lhs), ip),
            );
            let rhs = mask32(body, ip, &mut sequence, &input_name(slot, ip));
            let raw = temporary(body, ip, &mut sequence, &format!("sub i64 {lhs}, {rhs}"));
            let result = mask32(body, ip, &mut sequence, &raw);
            emit_flags32(body, ip, &lhs, &rhs, &result, Some(Alu::Sub), &mut sequence);
        }
        Op::CmpStack32 { rhs, .. } => {
            let slot = Field::Slot(node.slot.expect("validated stack comparison"));
            let lhs = mask32(body, ip, &mut sequence, &input_name(slot, ip));
            let rhs = mask32(body, ip, &mut sequence, &value32_name(rhs, ip));
            let raw = temporary(body, ip, &mut sequence, &format!("sub i64 {lhs}, {rhs}"));
            let result = mask32(body, ip, &mut sequence, &raw);
            emit_flags32(body, ip, &lhs, &rhs, &result, Some(Alu::Sub), &mut sequence);
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
        Op::CallDirect { target } => {
            body.push_str(&format!(
                "  {} = call i64 @hydir_callee_{target:x}(i64 {}, i64 {}, i64 {}, i64 {}, i64 {}, i64 {})\n  br label %b{:x}\n",
                output_name(Field::Rax, ip),
                input_name(Field::Rdi, ip),
                input_name(Field::Rsi, ip),
                input_name(Field::Rdx, ip),
                input_name(Field::Rcx, ip),
                input_name(Field::R8, ip),
                input_name(Field::R9, ip),
                node.successors[0]
            ));
        }
        Op::Ret => body.push_str(&format!("  ret i64 {}\n", input_name(Field::Rax, ip))),
        Op::Nop => body.push_str(&format!("  br label %b{:x}\n", node.successors[0])),
        Op::SaveFramePointer
        | Op::RestoreFramePointer
        | Op::SetFramePointer
        | Op::RestoreStackPointerFromFrame
        | Op::AdjustStack { .. }
        | Op::LeaveFrame => body.push_str(&format!("  br label %b{:x}\n", node.successors[0])),
    }
    if matches!(
        node.op,
        Op::Mov { .. }
            | Op::Mov32 { .. }
            | Op::LoadStack64 { .. }
            | Op::LoadStack32 { .. }
            | Op::StoreStack64 { .. }
            | Op::StoreStack32 { .. }
            | Op::Lea { .. }
            | Op::Alu { .. }
            | Op::Alu32 { .. }
            | Op::AluStack32 { .. }
            | Op::Cmp { .. }
            | Op::Cmp32 { .. }
            | Op::CmpRegStack32 { .. }
            | Op::CmpStack32 { .. }
            | Op::Test { .. }
    ) {
        body.push_str(&format!("  br label %b{:x}\n", node.successors[0]));
    }
}

/// Lift all instructions reachable from the first byte of a symbol-bounded
/// function. Only direct branches within the symbol are allowed. The caller
/// asserts the six-register SysV integer ABI contract; uninitialized register or
/// flag reads on any recovered path are rejected before IR is emitted.
pub fn lift_cfg(code: &[u8], address: u64) -> Result<String> {
    lift_cfg_with_calls(code, address, &BTreeSet::new())
}

pub(super) fn discover_direct_calls(code: &[u8], address: u64) -> Result<BTreeSet<u64>> {
    Ok(recover(code, address, None)?
        .into_values()
        .filter_map(|node| match node.op {
            Op::CallDirect { target } => Some(target),
            _ => None,
        })
        .collect())
}

pub(super) fn lift_cfg_with_calls(
    code: &[u8],
    address: u64,
    allowed_calls: &BTreeSet<u64>,
) -> Result<String> {
    if code.is_empty() || code.len() > 4096 {
        return Err(error("function must contain 1..=4096 bytes"));
    }
    let nodes = recover(code, address, Some(allowed_calls))?;
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
                let arg = match field {
                    Field::Rdi => "%arg0",
                    Field::Rsi => "%arg1",
                    Field::Rdx => "%arg2",
                    Field::Rcx => "%arg3",
                    Field::R8 => "%arg4",
                    Field::R9 => "%arg5",
                    _ => unreachable!("INPUTS contains only SysV integer argument registers"),
                };
                values.push(format!("[{arg}, %prologue]"));
            }
            for predecessor in &flow.predecessors[ip] {
                let predecessor_node = &nodes[predecessor];
                let name = if predecessor_node.defs() & field.bit() != 0 {
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
    let call_scope = if allowed_calls.is_empty() {
        "Calls are rejected."
    } else {
        "Only resolved scalar leaf calls with aligned stack and defined ABI state are accepted."
    };
    Ok(format!(
        "; HydIR raw direct-CFG lift; physical SysV signature: u64(u64, u64, u64, u64, u64, u64)\n\
         ; Unmodeled memory aliases or widths, indirect edges, and unsupported partial registers are rejected. {call_scope}\n\
         target triple = \"x86_64-unknown-linux-gnu\"\n\n\
         define i64 @hydir_lifted(i64 %arg0, i64 %arg1, i64 %arg2, i64 %arg3, i64 %arg4, i64 %arg5) {{\n{body}}}\n"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_region_exit_is_preserved_and_must_be_exact() {
        // mov rax,rdi; jmp 0x100a
        let code = [0x48, 0x89, 0xf8, 0xeb, 0x05];
        let cfg = recover_declared_region_cfg(
            &code,
            0x1000,
            &[Address(0x100a)],
            AddressKind::Virtual,
            "region",
            "0".repeat(64),
            "test",
        )
        .unwrap();
        assert_eq!(cfg.blocks.len(), 2);
        assert_eq!(cfg.edges.last().unwrap().target, Address(0x100a));
        assert!(cfg.recovery_scope.contains("declared external exits"));

        assert!(
            recover_declared_region_cfg(
                &code,
                0x1000,
                &[],
                AddressKind::Virtual,
                "region",
                "0".repeat(64),
                "test",
            )
            .unwrap_err()
            .0
            .contains("undeclared exit")
        );
        assert!(
            recover_declared_region_cfg(
                &code,
                0x1000,
                &[Address(0x100a), Address(0x2000)],
                AddressKind::Virtual,
                "region",
                "0".repeat(64),
                "test",
            )
            .unwrap_err()
            .0
            .contains("declared region exits are not exact")
        );
    }

    #[test]
    fn region_cfg_records_call_target_separately_from_continuation_exit() {
        // call 0x2000; jmp 0x100a
        let code = [0xe8, 0xfb, 0x0f, 0x00, 0x00, 0xeb, 0x03];
        let cfg = recover_declared_region_cfg(
            &code,
            0x1000,
            &[Address(0x100a)],
            AddressKind::Virtual,
            "region",
            "0".repeat(64),
            "test",
        )
        .unwrap();
        assert!(cfg.edges.iter().any(|edge| {
            edge.kind == EdgeKind::Call
                && edge.source == Address(0x1000)
                && edge.target == Address(0x2000)
        }));
        assert!(cfg.edges.iter().any(|edge| {
            edge.kind == EdgeKind::Direct
                && edge.source == Address(0x1005)
                && edge.target == Address(0x100a)
        }));
    }

    #[test]
    fn direct_call_needs_resolved_callee_contract() {
        let error = lift_cfg(&[0xe8, 0, 0, 0, 0, 0xc3], 0x1000).unwrap_err();
        assert!(
            error
                .0
                .contains("requires a resolved callee and ABI state proof")
        );
    }

    #[test]
    fn aligned_direct_call_defines_rax_and_invalidates_caller_saved_values() {
        // sub rsp,8; call 0x2000; add rsp,8; ret
        let code = [
            0x48, 0x83, 0xec, 0x08, 0xe8, 0xf7, 0x0f, 0, 0, 0x48, 0x83, 0xc4, 0x08, 0xc3,
        ];
        let allowed = BTreeSet::from([0x2000]);
        let ir = lift_cfg_with_calls(&code, 0x1000, &allowed).unwrap();
        assert!(ir.contains("call i64 @hydir_callee_2000"));
        let mut reads_clobbered = code.to_vec();
        reads_clobbered.splice(13..13, [0x48, 0x89, 0xf8]); // mov rax,rdi
        assert!(
            lift_cfg_with_calls(&reads_clobbered, 0x1000, &allowed)
                .unwrap_err()
                .0
                .contains("uninitialized RDI")
        );
        assert!(
            lift_cfg_with_calls(&code[4..], 0x1004, &allowed)
                .unwrap_err()
                .0
                .contains("unaligned stack")
        );
    }

    #[test]
    fn erases_proven_balanced_frame_without_stack_locals() {
        // push rbp; mov rbp,rsp; sub rsp,32; lea rax,[rdi+rsi];
        // add rsp,32; pop rbp; ret
        let code = [
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0x48, 0x8d, 0x04, 0x37, 0x48, 0x83,
            0xc4, 0x20, 0x5d, 0xc3,
        ];
        let ir = lift_cfg(&code, 0x1000).unwrap();
        assert!(ir.contains("add i64 %rdi_in_1008, %rsi_in_1008"));
        assert!(ir.contains("ret i64 %rax_in_1011"));
        assert!(!ir.contains("%zf_out_1004"));
    }

    #[test]
    fn lifts_initialized_bounded_stack_local() {
        // push rbp; mov rbp,rsp; sub rsp,16; mov [rbp-8],rdi;
        // mov rax,[rbp-8]; add rax,rsi; leave; ret
        let code = [
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10, 0x48, 0x89, 0x7d, 0xf8, 0x48, 0x8b,
            0x45, 0xf8, 0x48, 0x01, 0xf0, 0xc9, 0xc3,
        ];
        let ir = lift_cfg(&code, 0x1000).unwrap();
        assert!(ir.contains("%slot0_out_1008 = add i64 0, %rdi_in_1008"));
        assert!(ir.contains("%rax_out_100c = add i64 0, %slot0_in_100c"));
    }

    #[test]
    fn lifts_typed_32_bit_red_zone_fibonacci() {
        // GCC's leaf fibIterative from the pinned Irene3 x86-64 fixture. It
        // uses five disjoint dword locals in the SysV red zone.
        let code = [
            0xf3, 0x0f, 0x1e, 0xfa, 0x55, 0x48, 0x89, 0xe5, 0x89, 0x7d, 0xec, 0xc7, 0x45, 0xf0,
            0x00, 0x00, 0x00, 0x00, 0xc7, 0x45, 0xf4, 0x01, 0x00, 0x00, 0x00, 0xc7, 0x45, 0xfc,
            0x00, 0x00, 0x00, 0x00, 0xc7, 0x45, 0xf8, 0x02, 0x00, 0x00, 0x00, 0xeb, 0x1b, 0x8b,
            0x55, 0xf0, 0x8b, 0x45, 0xf4, 0x01, 0xd0, 0x89, 0x45, 0xfc, 0x8b, 0x45, 0xf4, 0x89,
            0x45, 0xf0, 0x8b, 0x45, 0xfc, 0x89, 0x45, 0xf4, 0x83, 0x45, 0xf8, 0x01, 0x8b, 0x45,
            0xf8, 0x3b, 0x45, 0xec, 0x7e, 0xdd, 0x83, 0x7d, 0xec, 0x00, 0x7e, 0x05, 0x8b, 0x45,
            0xf4, 0xeb, 0x03, 0x8b, 0x45, 0xf0, 0x5d, 0xc3,
        ];
        let ir = lift_cfg(&code, 0x11a9).unwrap();
        assert!(ir.contains("%slot0_out_11b1"));
        assert!(ir.contains("and i64 %rdi_in_11b1, 4294967295"));
        assert!(ir.contains("and i64 %t_11d8_2, 4294967295"));
        assert!(ir.contains("and i64 %t_11f0_3, 2147483648"));
        assert!(ir.contains("br i1 %t_11f3_1, label %b11d2, label %b11f5"));
        assert!(ir.contains("ret i64 %rax_in_1204"));
    }

    #[test]
    fn rejects_stack_local_read_before_write_and_partial_alias() {
        // push rbp; mov rbp,rsp; sub rsp,16; mov rax,[rbp-8]; leave; ret
        let uninitialized = [
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10, 0x48, 0x8b, 0x45, 0xf8, 0xc9, 0xc3,
        ];
        assert!(
            lift_cfg(&uninitialized, 0x1000)
                .unwrap_err()
                .0
                .contains("uninitialized SLOT")
        );
        // store [rbp-16] then read an overlapping eight-byte [rbp-12].
        let alias = [
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0x48, 0x89, 0x7d, 0xf0, 0x48, 0x8b,
            0x45, 0xf4, 0xc9, 0xc3,
        ];
        assert!(
            lift_cfg(&alias, 0x1000)
                .unwrap_err()
                .0
                .contains("overlapping")
        );
    }

    #[test]
    fn joins_stack_local_written_on_both_branch_paths() {
        // sub rsp,16; cmp rdi,rsi; jae left; mov [rsp],rsi; jmp join;
        // left: mov [rsp],rdi; join: mov rax,[rsp]; add rsp,16; ret
        let code = [
            0x48, 0x83, 0xec, 0x10, 0x48, 0x39, 0xf7, 0x73, 0x06, 0x48, 0x89, 0x34, 0x24, 0xeb,
            0x04, 0x48, 0x89, 0x3c, 0x24, 0x48, 0x8b, 0x04, 0x24, 0x48, 0x83, 0xc4, 0x10, 0xc3,
        ];
        let ir = lift_cfg(&code, 0x1000).unwrap();
        assert!(ir.contains("%slot0_in_1013 = phi i64"));
        assert!(ir.contains("%slot0_out_1009"));
        assert!(ir.contains("%slot0_out_100f"));
    }

    #[test]
    fn rejects_stack_local_written_on_only_one_branch() {
        let code = [
            0x48, 0x83, 0xec, 0x10, 0x48, 0x39, 0xf7, 0x73, 0x04, 0x48, 0x89, 0x34, 0x24, 0x48,
            0x8b, 0x04, 0x24, 0x48, 0x83, 0xc4, 0x10, 0xc3,
        ];
        assert!(
            lift_cfg(&code, 0x1000)
                .unwrap_err()
                .0
                .contains("uninitialized SLOT")
        );
    }

    #[test]
    fn refuses_stack_adjustment_flags_at_branch() {
        // sub rsp,8; je +0; add rsp,8; ret
        let code = [0x48, 0x83, 0xec, 8, 0x74, 0, 0x48, 0x83, 0xc4, 8, 0xc3];
        assert!(
            lift_cfg(&code, 0x1000)
                .unwrap_err()
                .0
                .contains("flags used by a conditional branch")
        );
    }

    #[test]
    fn mov32_zero_extends_register_result() {
        // mov eax, edi; ret
        let ir = lift_cfg(&[0x89, 0xf8, 0xc3], 0x1000).unwrap();
        assert!(ir.contains("trunc i64 %rdi_in_1000 to i32"));
        assert!(ir.contains("%rax_out_1000 = zext i32 %t_1000_0 to i64"));
        assert!(!ir.contains("nsw"));
    }

    #[test]
    fn preserves_extended_register_dataflow_and_sixth_argument_identity() {
        // mov r10,r9; mov rax,r10; ret
        let ir = lift_cfg(&[0x4d, 0x89, 0xca, 0x4c, 0x89, 0xd0, 0xc3], 0x1000).unwrap();
        assert!(ir.contains("%r9_in_1000 = phi i64 [%arg5, %prologue]"));
        assert!(ir.contains("%r10_out_1000 = add i64 0, %r9_in_1000"));
        assert!(ir.contains("%rax_out_1003 = add i64 0, %r10_in_1003"));
        assert!(ir.contains("ret i64 %rax_in_1006"));
    }

    #[test]
    fn logical_alu_uses_logical_ir_and_clears_carry_and_overflow() {
        // mov rax,rdi; and rax,rsi; ret
        let ir = lift_cfg(&[0x48, 0x89, 0xf8, 0x48, 0x21, 0xf0, 0xc3], 0x1000).unwrap();
        assert!(ir.contains("%rax_out_1003 = and i64 %rax_in_1003, %rsi_in_1003"));
        assert!(ir.contains("%of_out_1003 = and i1 false, false"));
        assert!(ir.contains("%cf_out_1003 = and i1 false, false"));
    }

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
