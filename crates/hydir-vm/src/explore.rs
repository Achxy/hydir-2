//! Bounded, VPC-sensitive host-code exploration. This produces a host/VPC
//! graph, not a devirtualized guest function. Unsupported instructions and
//! addresses terminate an edge explicitly.

use crate::{VmGuestEffect, VmProfile, VmRange, VmStorage, validate_profile};
use hydir_core::{Address, Location, ProgramSpec};
use hydir_loader::import_elf;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const MAX_NODES: usize = 10_000;
const MAX_CONTEXT_BYTES: u64 = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct VmNodeKey {
    pub host_pc: Location,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpc: Option<Location>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VmExploreNode {
    pub key: VmNodeKey,
    pub mnemonic: String,
    pub bytes_hex: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmEdgeKind {
    Next,
    Taken,
    Fallthrough,
    Jump,
    Call,
    CallReturn,
    Exit,
    Unresolved,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct VmEdge {
    pub from: VmNodeKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<VmNodeKey>,
    pub kind: VmEdgeKind,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VmExploreReport {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub entry: VmNodeKey,
    pub nodes: Vec<VmExploreNode>,
    pub edges: Vec<VmEdge>,
    pub unique_vpcs: Vec<Location>,
    pub observed_guest_effects: Vec<String>,
    pub diagnostics: Vec<String>,
    pub unresolved_edges: usize,
    pub hit_node_limit: bool,
    pub guest_cfg_recovered: bool,
    pub rewrite_ready: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Value {
    Unknown,
    Constant(u64),
    ContextBase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Flags {
    Unknown,
    Compare { equal: bool, below: bool },
    Test { zero: bool },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct State {
    pc: u64,
    registers: BTreeMap<&'static str, Value>,
    context_bytes: BTreeMap<u64, Option<u8>>,
    stack: Vec<Value>,
    call_stack: Option<Vec<u64>>,
    flags: Flags,
}

impl State {
    fn new(pc: u64, context_entry_register: &'static str) -> Self {
        let mut registers = BTreeMap::new();
        registers.insert(context_entry_register, Value::ContextBase);
        Self {
            pc,
            registers,
            context_bytes: BTreeMap::new(),
            stack: Vec::new(),
            call_stack: Some(Vec::new()),
            flags: Flags::Unknown,
        }
    }

    fn read_register(&self, register: Register) -> Value {
        let Some((name, bits)) = register_name(register) else {
            return Value::Unknown;
        };
        let value = self.registers.get(name).cloned().unwrap_or(Value::Unknown);
        if bits == 32 {
            match value {
                Value::Constant(value) => Value::Constant(value as u32 as u64),
                _ => Value::Unknown,
            }
        } else {
            value
        }
    }

    fn write_register(&mut self, register: Register, value: Value) -> Result<(), String> {
        let (name, bits) =
            register_name(register).ok_or_else(|| format!("unsupported register {register:?}"))?;
        let value = if bits == 32 {
            match value {
                Value::Constant(value) => Value::Constant(value as u32 as u64),
                _ => Value::Unknown,
            }
        } else {
            value
        };
        self.registers.insert(name, value);
        Ok(())
    }

    fn read_context(&self, offset: u64, size: usize) -> Value {
        let mut value = 0_u64;
        for index in 0..size {
            let Some(Some(byte)) = self.context_bytes.get(&(offset + index as u64)) else {
                return Value::Unknown;
            };
            value |= u64::from(*byte) << (index * 8);
        }
        Value::Constant(value)
    }

    fn write_context(&mut self, offset: u64, size: usize, value: &Value) {
        for index in 0..size {
            let byte = match value {
                Value::Constant(value) => Some((value >> (index * 8)) as u8),
                _ => None,
            };
            self.context_bytes.insert(offset + index as u64, byte);
        }
    }

    fn vpc(&self, profile: &VmProfile) -> Option<Location> {
        let value = match &profile.vpc.value.storage {
            VmStorage::Register { name } => self.registers.get(name.to_ascii_lowercase().as_str()),
            VmStorage::ContextOffset { offset, width_bits } => {
                return match self.read_context(*offset, usize::from(*width_bits / 8)) {
                    Value::Constant(value) => Some(Location {
                        address_space: 0,
                        value: Address(value),
                    }),
                    _ => None,
                };
            }
        };
        match value {
            Some(Value::Constant(value)) => Some(Location {
                address_space: 0,
                value: Address(*value),
            }),
            _ => None,
        }
    }

    fn key(&self, profile: &VmProfile) -> VmNodeKey {
        VmNodeKey {
            host_pc: Location {
                address_space: 0,
                value: Address(self.pc),
            },
            vpc: self.vpc(profile),
        }
    }

    /// A join may lose concrete data, but can never create a concrete target.
    /// Reprocess a node when its abstract inputs widen.
    fn join(&mut self, other: &Self) -> bool {
        let before = self.clone();
        let keys = self
            .registers
            .keys()
            .chain(other.registers.keys())
            .copied()
            .collect::<BTreeSet<_>>();
        for key in keys {
            let left = self.registers.get(key).cloned().unwrap_or(Value::Unknown);
            let right = other.registers.get(key).cloned().unwrap_or(Value::Unknown);
            self.registers
                .insert(key, if left == right { left } else { Value::Unknown });
        }
        let offsets = self
            .context_bytes
            .keys()
            .chain(other.context_bytes.keys())
            .copied()
            .collect::<BTreeSet<_>>();
        for offset in offsets {
            let left = self.context_bytes.get(&offset).copied().flatten();
            let right = other.context_bytes.get(&offset).copied().flatten();
            self.context_bytes
                .insert(offset, if left == right { left } else { None });
        }
        if self.stack != other.stack {
            self.stack = vec![Value::Unknown; self.stack.len().max(other.stack.len())];
        }
        if self.call_stack != other.call_stack {
            self.call_stack = None;
        }
        if self.flags != other.flags {
            self.flags = Flags::Unknown;
        }
        *self != before
    }
}

fn register_name(register: Register) -> Option<(&'static str, u8)> {
    use Register::*;
    Some(match register {
        RAX => ("rax", 64),
        EAX => ("rax", 32),
        RBX => ("rbx", 64),
        EBX => ("rbx", 32),
        RCX => ("rcx", 64),
        ECX => ("rcx", 32),
        RDX => ("rdx", 64),
        EDX => ("rdx", 32),
        RSI => ("rsi", 64),
        ESI => ("rsi", 32),
        RDI => ("rdi", 64),
        EDI => ("rdi", 32),
        RBP => ("rbp", 64),
        EBP => ("rbp", 32),
        RSP => ("rsp", 64),
        ESP => ("rsp", 32),
        R8 => ("r8", 64),
        R8D => ("r8", 32),
        R9 => ("r9", 64),
        R9D => ("r9", 32),
        R10 => ("r10", 64),
        R10D => ("r10", 32),
        R11 => ("r11", 64),
        R11D => ("r11", 32),
        R12 => ("r12", 64),
        R12D => ("r12", 32),
        R13 => ("r13", 64),
        R13D => ("r13", 32),
        R14 => ("r14", 64),
        R14D => ("r14", 32),
        R15 => ("r15", 64),
        R15D => ("r15", 32),
        _ => return Option::None,
    })
}

fn image_bytes<'a>(
    bytes: &'a [u8],
    spec: &ProgramSpec,
    address: u64,
    size: usize,
) -> Option<&'a [u8]> {
    let end = address.checked_add(size as u64)?;
    let segment = spec.mapped_segments.iter().find(|segment| {
        segment.address_space == 0
            && segment.virtual_address.0 <= address
            && segment
                .virtual_address
                .0
                .checked_add(segment.file_size)
                .is_some_and(|limit| end <= limit)
    })?;
    let start = segment
        .file_offset
        .0
        .checked_add(address - segment.virtual_address.0)? as usize;
    bytes.get(start..start.checked_add(size)?)
}

fn in_bytecode(profile: &VmProfile, address: u64, size: usize) -> bool {
    profile.bytecode_ranges.iter().any(|fact| {
        let VmRange {
            start,
            size: length,
        } = fact.value;
        start.address_space == 0
            && address >= start.value.0
            && address.checked_add(size as u64).is_some_and(|end| {
                start
                    .value
                    .0
                    .checked_add(length)
                    .is_some_and(|limit| end <= limit)
            })
    })
}

fn decoded(bytes: &[u8], spec: &ProgramSpec, pc: u64) -> Option<(Instruction, Vec<u8>)> {
    let segment = spec.mapped_segments.iter().find(|segment| {
        segment.address_space == 0
            && segment.executable
            && segment.virtual_address.0 <= pc
            && segment
                .virtual_address
                .0
                .checked_add(segment.file_size)
                .is_some_and(|end| pc < end)
    })?;
    let available = segment.virtual_address.0 + segment.file_size - pc;
    let code = image_bytes(bytes, spec, pc, available.min(15) as usize)?;
    let mut decoder = Decoder::with_ip(64, code, pc, DecoderOptions::NONE);
    let instruction = decoder.decode();
    if instruction.is_invalid() || instruction.len() == 0 {
        return None;
    }
    Some((instruction, code[..instruction.len()].to_vec()))
}

#[derive(Clone, Copy)]
enum AddressKind {
    Image(u64),
    Context(u64),
    Other,
}

fn address_of(instruction: &Instruction, state: &State) -> AddressKind {
    if instruction.is_ip_rel_memory_operand() {
        return AddressKind::Image(instruction.ip_rel_memory_address());
    }
    let base = if instruction.memory_base() == Register::None {
        Value::Constant(0)
    } else {
        state.read_register(instruction.memory_base())
    };
    let index = if instruction.memory_index() == Register::None {
        Value::Constant(0)
    } else {
        state.read_register(instruction.memory_index())
    };
    let displacement = instruction.memory_displacement64() as i64;
    match (base, index) {
        (Value::ContextBase, Value::Constant(index)) => (index
            .wrapping_mul(u64::from(instruction.memory_index_scale()))
            .wrapping_add_signed(displacement)
            < MAX_CONTEXT_BYTES)
            .then(|| {
                AddressKind::Context(
                    index
                        .wrapping_mul(u64::from(instruction.memory_index_scale()))
                        .wrapping_add_signed(displacement),
                )
            })
            .unwrap_or(AddressKind::Other),
        (Value::Constant(base), Value::Constant(index)) => AddressKind::Image(
            base.wrapping_add(index.wrapping_mul(u64::from(instruction.memory_index_scale())))
                .wrapping_add_signed(displacement),
        ),
        _ => AddressKind::Other,
    }
}

fn memory_width(instruction: &Instruction) -> Result<usize, String> {
    let size = instruction.memory_size().size();
    if matches!(size, 1 | 2 | 4 | 8) {
        Ok(size)
    } else {
        Err(format!("unsupported memory width {size}"))
    }
}

fn read_operand(
    bytes: &[u8],
    spec: &ProgramSpec,
    profile: &VmProfile,
    instruction: &Instruction,
    operand: u32,
    state: &State,
) -> Result<Value, String> {
    use OpKind::*;
    Ok(match instruction.op_kind(operand) {
        Register => state.read_register(instruction.op_register(operand)),
        Immediate8 => Value::Constant(u64::from(instruction.immediate8())),
        Immediate16 => Value::Constant(u64::from(instruction.immediate16())),
        Immediate32 => Value::Constant(u64::from(instruction.immediate32())),
        Immediate64 => Value::Constant(instruction.immediate64()),
        Immediate8to64 => Value::Constant(instruction.immediate8to64() as u64),
        Immediate32to64 => Value::Constant(instruction.immediate32to64() as u64),
        Immediate8to32 => Value::Constant(instruction.immediate8to32() as u64),
        Memory => {
            let width = memory_width(instruction)?;
            match address_of(instruction, state) {
                AddressKind::Context(offset)
                    if offset + width as u64 <= profile.context.value.size =>
                {
                    state.read_context(offset, width)
                }
                AddressKind::Image(address) if in_bytecode(profile, address, width) => {
                    let segment = spec.mapped_segments.iter().find(|segment| {
                        segment.address_space == 0
                            && segment.virtual_address.0 <= address
                            && segment
                                .virtual_address
                                .0
                                .checked_add(segment.file_size)
                                .is_some_and(|end| address + width as u64 <= end)
                    });
                    if segment.is_some_and(|segment| !segment.writable) {
                        image_bytes(bytes, spec, address, width)
                            .map(|data| {
                                Value::Constant(data.iter().enumerate().fold(
                                    0_u64,
                                    |value, (index, byte)| {
                                        value | (u64::from(*byte) << (index * 8))
                                    },
                                ))
                            })
                            .unwrap_or(Value::Unknown)
                    } else {
                        Value::Unknown
                    }
                }
                _ => Value::Unknown,
            }
        }
        kind => return Err(format!("unsupported operand kind {kind:?}")),
    })
}

fn write_operand(
    spec: &ProgramSpec,
    profile: &VmProfile,
    instruction: &Instruction,
    operand: u32,
    state: &mut State,
    value: Value,
    effects: &mut BTreeSet<String>,
) -> Result<(), String> {
    match instruction.op_kind(operand) {
        OpKind::Register => state.write_register(instruction.op_register(operand), value),
        OpKind::Memory => {
            let width = memory_width(instruction)?;
            match address_of(instruction, state) {
                AddressKind::Context(offset)
                    if offset + width as u64 <= profile.context.value.size =>
                {
                    state.write_context(offset, width, &value);
                    if profile.guest_effects.iter().any(|fact| {
                        matches!(
                            fact.value,
                            VmGuestEffect::ContextRange { offset: start, size }
                                if offset < start + size && start < offset + width as u64
                        )
                    }) {
                        effects.insert(format!("guest context write at offset {offset}"));
                    }
                    Ok(())
                }
                AddressKind::Context(_) => {
                    Err("VM context write is outside the annotated context".to_owned())
                }
                AddressKind::Image(address) if in_bytecode(profile, address, width) => {
                    Err("write into annotated bytecode requires runtime memory modeling".to_owned())
                }
                AddressKind::Image(address) => {
                    if spec.mapped_segments.iter().any(|segment| {
                        segment.address_space == 0
                            && segment.executable
                            && segment.virtual_address.0 <= address
                            && segment
                                .virtual_address
                                .0
                                .checked_add(segment.memory_size)
                                .is_some_and(|end| address < end)
                    }) {
                        return Err(
                            "write into executable image requires self-modifying-code modeling"
                                .to_owned(),
                        );
                    }
                    effects.insert("guest or unknown memory write".to_owned());
                    Ok(())
                }
                AddressKind::Other => {
                    let disjoint = profile.guest_effects.iter().any(|fact| {
                        matches!(
                            fact.value,
                            VmGuestEffect::Memory {
                                disjoint_from_vm: true
                            }
                        )
                    });
                    if !disjoint {
                        return Err("unknown memory write may alias VM state or bytecode; annotate a disjoint guest-memory contract".to_owned());
                    }
                    effects.insert(
                        "guest or unknown memory write under disjointness assertion".to_owned(),
                    );
                    Ok(())
                }
            }
        }
        kind => Err(format!("unsupported destination kind {kind:?}")),
    }
}

fn add_values(left: Value, right: Value) -> Value {
    match (left, right) {
        (Value::Constant(left), Value::Constant(right)) => {
            Value::Constant(left.wrapping_add(right))
        }
        (Value::ContextBase, Value::Constant(0)) | (Value::Constant(0), Value::ContextBase) => {
            Value::ContextBase
        }
        _ => Value::Unknown,
    }
}

fn branch_target(instruction: &Instruction, state: &State) -> Option<u64> {
    match instruction.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            Some(instruction.near_branch_target())
        }
        OpKind::Register => match state.read_register(instruction.op0_register()) {
            Value::Constant(target) => Some(target),
            _ => None,
        },
        _ => None,
    }
}

fn branch_decision(mnemonic: Mnemonic, flags: Flags) -> Option<bool> {
    match (mnemonic, flags) {
        (Mnemonic::Je, Flags::Compare { equal, .. }) => Some(equal),
        (Mnemonic::Jne, Flags::Compare { equal, .. }) => Some(!equal),
        (Mnemonic::Jb, Flags::Compare { below, .. }) => Some(below),
        (Mnemonic::Jae, Flags::Compare { below, .. }) => Some(!below),
        (Mnemonic::Je, Flags::Test { zero }) => Some(zero),
        (Mnemonic::Jne, Flags::Test { zero }) => Some(!zero),
        _ => None,
    }
}

fn step(
    bytes: &[u8],
    spec: &ProgramSpec,
    profile: &VmProfile,
    instruction: &Instruction,
    state: &State,
    effects: &mut BTreeSet<String>,
) -> Result<Vec<(VmEdgeKind, Option<State>)>, String> {
    let next_pc = instruction.next_ip();
    let mut next = state.clone();
    next.pc = next_pc;
    let result = match instruction.mnemonic() {
        Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd => {
            let mut value = read_operand(bytes, spec, profile, instruction, 1, &next)?;
            if matches!(instruction.mnemonic(), Mnemonic::Movsx | Mnemonic::Movsxd) {
                if let Value::Constant(raw) = value {
                    let bits = if instruction.op1_kind() == OpKind::Memory {
                        memory_width(instruction)? * 8
                    } else {
                        32
                    };
                    let shift = 64 - bits;
                    value = Value::Constant((((raw << shift) as i64) >> shift) as u64);
                }
            }
            write_operand(spec, profile, instruction, 0, &mut next, value, effects)?;
            vec![(VmEdgeKind::Next, Some(next))]
        }
        Mnemonic::Lea => {
            let value = match address_of(instruction, &next) {
                AddressKind::Image(address) => Value::Constant(address),
                AddressKind::Context(0) => Value::ContextBase,
                _ => Value::Unknown,
            };
            write_operand(spec, profile, instruction, 0, &mut next, value, effects)?;
            vec![(VmEdgeKind::Next, Some(next))]
        }
        Mnemonic::Add | Mnemonic::Xor | Mnemonic::Inc => {
            let left = read_operand(bytes, spec, profile, instruction, 0, &next)?;
            let right = if instruction.mnemonic() == Mnemonic::Inc {
                Value::Constant(1)
            } else {
                read_operand(bytes, spec, profile, instruction, 1, &next)?
            };
            let value = if instruction.mnemonic() == Mnemonic::Xor {
                match (left, right) {
                    (Value::Constant(left), Value::Constant(right)) => {
                        Value::Constant(left ^ right)
                    }
                    _ => Value::Unknown,
                }
            } else {
                add_values(left, right)
            };
            write_operand(spec, profile, instruction, 0, &mut next, value, effects)?;
            next.flags = Flags::Unknown;
            vec![(VmEdgeKind::Next, Some(next))]
        }
        Mnemonic::Cmp => {
            let left = read_operand(bytes, spec, profile, instruction, 0, &next)?;
            let right = read_operand(bytes, spec, profile, instruction, 1, &next)?;
            next.flags = match (left, right) {
                (Value::Constant(left), Value::Constant(right)) => Flags::Compare {
                    equal: left == right,
                    below: left < right,
                },
                _ => Flags::Unknown,
            };
            vec![(VmEdgeKind::Next, Some(next))]
        }
        Mnemonic::Test => {
            let left = read_operand(bytes, spec, profile, instruction, 0, &next)?;
            let right = read_operand(bytes, spec, profile, instruction, 1, &next)?;
            next.flags = match (left, right) {
                (Value::Constant(left), Value::Constant(right)) => Flags::Test {
                    zero: left & right == 0,
                },
                _ => Flags::Unknown,
            };
            vec![(VmEdgeKind::Next, Some(next))]
        }
        Mnemonic::Je | Mnemonic::Jne | Mnemonic::Jb | Mnemonic::Jae => {
            let target = branch_target(instruction, &next)
                .ok_or_else(|| "conditional branch target is unresolved".to_owned())?;
            let decision = branch_decision(instruction.mnemonic(), next.flags);
            let mut paths = Vec::new();
            if decision != Some(false) {
                let mut taken = next.clone();
                taken.pc = target;
                paths.push((VmEdgeKind::Taken, Some(taken)));
            }
            if decision != Some(true) {
                paths.push((VmEdgeKind::Fallthrough, Some(next)));
            }
            paths
        }
        Mnemonic::Jmp => {
            next.pc = branch_target(instruction, &next)
                .ok_or_else(|| "indirect jump target is unresolved".to_owned())?;
            vec![(VmEdgeKind::Jump, Some(next))]
        }
        Mnemonic::Call => {
            let target = branch_target(instruction, &next)
                .ok_or_else(|| "indirect call target is unresolved".to_owned())?;
            let call_stack = next
                .call_stack
                .as_mut()
                .ok_or_else(|| "merged call stack prevents return resolution".to_owned())?;
            call_stack.push(next_pc);
            next.pc = target;
            effects.insert(format!("host call at 0x{:x}", instruction.ip()));
            vec![(VmEdgeKind::Call, Some(next))]
        }
        Mnemonic::Ret => {
            let call_stack = next
                .call_stack
                .as_mut()
                .ok_or_else(|| "merged call stack prevents return resolution".to_owned())?;
            if let Some(target) = call_stack.pop() {
                next.pc = target;
                vec![(VmEdgeKind::CallReturn, Some(next))]
            } else {
                if !profile.exits.iter().any(|exit| {
                    exit.value.value.0 == instruction.ip()
                        || (exit.value.value.0 < instruction.ip()
                            && spec.functions.iter().any(|function| {
                                function.location == Some(exit.value)
                                    && function.size > 0
                                    && instruction.ip()
                                        < exit.value.value.0.saturating_add(function.size)
                            }))
                }) {
                    return Err("return leaves the VM through an unannotated exit".to_owned());
                }
                effects.insert(format!("host return at 0x{:x}", instruction.ip()));
                vec![(VmEdgeKind::Exit, None)]
            }
        }
        Mnemonic::Push => {
            let value = read_operand(bytes, spec, profile, instruction, 0, &next)?;
            next.stack.push(value);
            vec![(VmEdgeKind::Next, Some(next))]
        }
        Mnemonic::Pop => {
            let value = next
                .stack
                .pop()
                .ok_or_else(|| "abstract stack underflow".to_owned())?;
            write_operand(spec, profile, instruction, 0, &mut next, value, effects)?;
            vec![(VmEdgeKind::Next, Some(next))]
        }
        Mnemonic::Ud2 => Err("reachable UD2 in VM region".to_owned())?,
        mnemonic => Err(format!("unsupported VM-region instruction {mnemonic:?}"))?,
    };
    Ok(result)
}

/// Explore host instructions with distinct states for distinct VPCs. The
/// bounded graph is useful evidence even when a guest CFG cannot be emitted.
pub fn explore_profile(bytes: &[u8], profile: &VmProfile) -> Result<VmExploreReport, String> {
    let validated = validate_profile(bytes, profile)?;
    if profile.context.value.size > MAX_CONTEXT_BYTES {
        return Err(format!(
            "VM context exceeds the {MAX_CONTEXT_BYTES}-byte analysis bound"
        ));
    }
    let spec = import_elf(bytes).map_err(|error| error.to_string())?;
    let entry_register = register_name_by_text(&profile.context.value.entry_register)
        .ok_or_else(|| "unsupported context entry register".to_owned())?;
    let initial = State::new(profile.entry.value.value.0, entry_register);
    let entry = initial.key(profile);
    let mut states = BTreeMap::<VmNodeKey, State>::new();
    let mut queue = VecDeque::new();
    states.insert(entry, initial);
    queue.push_back(entry);
    let mut nodes = BTreeMap::<VmNodeKey, VmExploreNode>::new();
    let mut edges = BTreeSet::<VmEdge>::new();
    let mut effects = BTreeSet::new();
    let mut diagnostics = BTreeSet::new();
    let mut hit_node_limit = false;
    let mut checked_initial_vpc = false;
    while let Some(key) = queue.pop_front() {
        if nodes.len() >= MAX_NODES && !nodes.contains_key(&key) {
            diagnostics.insert(format!("VM exploration reached the {MAX_NODES}-node bound"));
            hit_node_limit = true;
            break;
        }
        let state = states.get(&key).expect("queued state exists").clone();
        if !checked_initial_vpc {
            if let Some(vpc) = key.vpc {
                checked_initial_vpc = true;
                if profile
                    .vpc
                    .value
                    .initial_value
                    .is_some_and(|expected| expected != vpc)
                {
                    diagnostics.insert(format!(
                        "first recovered VPC 0x{:x} differs from annotated initial VPC",
                        vpc.value.0
                    ));
                }
            }
        }
        let Some((instruction, instruction_bytes)) = decoded(bytes, &spec, state.pc) else {
            diagnostics.insert(format!(
                "unmapped or invalid host instruction at 0x{:x} (VPC {:?})",
                state.pc, key.vpc
            ));
            edges.insert(VmEdge {
                from: key,
                to: None,
                kind: VmEdgeKind::Unresolved,
            });
            continue;
        };
        nodes.insert(
            key,
            VmExploreNode {
                key,
                mnemonic: format!("{:?}", instruction.mnemonic()).to_ascii_lowercase(),
                bytes_hex: instruction_bytes
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
            },
        );
        let transitions = match step(bytes, &spec, profile, &instruction, &state, &mut effects) {
            Ok(transitions) => transitions,
            Err(reason) => {
                diagnostics.insert(format!("0x{:x} (VPC {:?}): {reason}", state.pc, key.vpc));
                edges.insert(VmEdge {
                    from: key,
                    to: None,
                    kind: VmEdgeKind::Unresolved,
                });
                continue;
            }
        };
        for (kind, target) in transitions {
            let target_key = target.as_ref().map(|state| state.key(profile));
            edges.insert(VmEdge {
                from: key,
                to: target_key,
                kind,
            });
            let Some(target) = target else { continue };
            let target_key = target_key.expect("state has a key");
            if let Some(existing) = states.get_mut(&target_key) {
                if existing.join(&target) {
                    queue.push_back(target_key);
                }
            } else {
                states.insert(target_key, target);
                queue.push_back(target_key);
            }
        }
    }
    let unique_vpcs = nodes
        .keys()
        .filter_map(|key| key.vpc)
        .collect::<BTreeSet<_>>();
    let unresolved_edges = edges
        .iter()
        .filter(|edge| edge.kind == VmEdgeKind::Unresolved)
        .count();
    Ok(VmExploreReport {
        schema_version: 1,
        binary_sha256: validated.binary_sha256,
        entry,
        nodes: nodes.into_values().collect(),
        edges: edges.into_iter().collect(),
        unique_vpcs: unique_vpcs.into_iter().collect(),
        observed_guest_effects: effects.into_iter().collect(),
        diagnostics: diagnostics.into_iter().collect(),
        unresolved_edges,
        hit_node_limit,
        guest_cfg_recovered: false,
        rewrite_ready: false,
    })
}

fn register_name_by_text(name: &str) -> Option<&'static str> {
    Some(match name.to_ascii_lowercase().as_str() {
        "rax" => "rax",
        "rbx" => "rbx",
        "rcx" => "rcx",
        "rdx" => "rdx",
        "rsi" => "rsi",
        "rdi" => "rdi",
        "rbp" => "rbp",
        "rsp" => "rsp",
        "r8" => "r8",
        "r9" => "r9",
        "r10" => "r10",
        "r11" => "r11",
        "r12" => "r12",
        "r13" => "r13",
        "r14" => "r14",
        "r15" => "r15",
        _ => return None,
    })
}
