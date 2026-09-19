//! Shared, typed decode for the full-width scalar instruction subset.
//! Classification rejects effects that neither consumer can model exactly.

use iced_x86::{FlowControl, Instruction, Mnemonic, OpKind, Register};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value {
    Register(Register),
    Immediate(i64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value32 {
    Register(Register),
    Immediate(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alu {
    Add,
    Sub,
    And,
    Or,
    Xor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Condition {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Mov {
        dst: Register,
        src: Value,
    },
    /// A 32-bit destination write clears the upper half of its 64-bit parent.
    Mov32 {
        dst: Register,
        src: Value32,
    },
    LoadStack64 {
        dst: Register,
        base: Register,
        displacement: i64,
    },
    StoreStack64 {
        base: Register,
        displacement: i64,
        src: Register,
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
    SaveFramePointer,
    RestoreFramePointer,
    SetFramePointer,
    RestoreStackPointerFromFrame,
    AdjustStack {
        kind: Alu,
        amount: i64,
    },
    LeaveFrame,
    Jcc(Condition),
    Jmp,
    CallDirect {
        target: u64,
    },
    Ret,
    Nop,
}

pub const RAX: u16 = 1 << 0;
pub const RDI: u16 = 1 << 1;
pub const RSI: u16 = 1 << 2;
pub const RDX: u16 = 1 << 3;
pub const RCX: u16 = 1 << 4;
pub const R8: u16 = 1 << 7;
pub const R9: u16 = 1 << 8;
pub const RBX: u16 = 1 << 9;
pub const R10: u16 = 1 << 10;
pub const R11: u16 = 1 << 11;
pub const R12: u16 = 1 << 12;
pub const R13: u16 = 1 << 13;
pub const R14: u16 = 1 << 14;
pub const R15: u16 = 1 << 15;
pub const RSP: u16 = 1 << 5;
pub const RBP: u16 = 1 << 6;
pub const ZF: u8 = 1 << 0;
pub const SF: u8 = 1 << 1;
pub const OF: u8 = 1 << 2;
pub const CF: u8 = 1 << 3;
const ALL_FLAGS: u8 = ZF | SF | OF | CF;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlEffect {
    Next,
    DirectBranch,
    ConditionalBranch,
    DirectCall,
    Return,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryEffect {
    None,
    ReadReturnAddress,
    WriteSavedFramePointer,
    ReadSavedFramePointer,
    ReadStackLocal,
    WriteStackLocal,
    WriteReturnAddress,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Effects {
    pub read_registers: u16,
    pub write_registers: u16,
    pub read_flags: u8,
    pub write_flags: u8,
    pub memory: MemoryEffect,
    pub control: ControlEffect,
}

fn register_bit(register: Register) -> u16 {
    match register {
        Register::RAX => RAX,
        Register::RDI => RDI,
        Register::RSI => RSI,
        Register::RDX => RDX,
        Register::RCX => RCX,
        Register::R8 => R8,
        Register::R9 => R9,
        Register::RBX => RBX,
        Register::R10 => R10,
        Register::R11 => R11,
        Register::R12 => R12,
        Register::R13 => R13,
        Register::R14 => R14,
        Register::R15 => R15,
        _ => unreachable!("classifier establishes canonical register parents"),
    }
}

impl Op {
    /// Exact architectural effects of the decoded subset. A caller may impose
    /// additional ABI requirements, such as RAX being defined at function return.
    pub fn effects(self) -> Effects {
        let mut effect = Effects {
            read_registers: 0,
            write_registers: 0,
            read_flags: 0,
            write_flags: 0,
            memory: MemoryEffect::None,
            control: ControlEffect::Next,
        };
        let value_reads = |value| match value {
            Value::Register(register) => register_bit(register),
            Value::Immediate(_) => 0,
        };
        match self {
            Op::Mov { dst, src } => {
                effect.read_registers = value_reads(src);
                effect.write_registers = register_bit(dst);
            }
            Op::Mov32 { dst, src } => {
                effect.read_registers = match src {
                    Value32::Register(register) => register_bit(register),
                    Value32::Immediate(_) => 0,
                };
                effect.write_registers = register_bit(dst);
            }
            Op::LoadStack64 { dst, base, .. } => {
                effect.read_registers = if base == Register::RSP { RSP } else { RBP };
                effect.write_registers = register_bit(dst);
                effect.memory = MemoryEffect::ReadStackLocal;
            }
            Op::StoreStack64 { base, src, .. } => {
                effect.read_registers =
                    register_bit(src) | if base == Register::RSP { RSP } else { RBP };
                effect.memory = MemoryEffect::WriteStackLocal;
            }
            Op::Lea {
                dst, base, index, ..
            } => {
                effect.read_registers =
                    base.map_or(0, register_bit) | index.map_or(0, register_bit);
                effect.write_registers = register_bit(dst);
            }
            Op::Alu { dst, src, .. } => {
                effect.read_registers = register_bit(dst) | value_reads(src);
                effect.write_registers = register_bit(dst);
                effect.write_flags = ALL_FLAGS;
            }
            Op::Cmp { lhs, rhs } | Op::Test { lhs, rhs } => {
                effect.read_registers = register_bit(lhs) | value_reads(rhs);
                effect.write_flags = ALL_FLAGS;
            }
            Op::SaveFramePointer => {
                effect.read_registers = RSP | RBP;
                effect.write_registers = RSP;
                effect.memory = MemoryEffect::WriteSavedFramePointer;
            }
            Op::RestoreFramePointer => {
                effect.read_registers = RSP;
                effect.write_registers = RSP | RBP;
                effect.memory = MemoryEffect::ReadSavedFramePointer;
            }
            Op::SetFramePointer => {
                effect.read_registers = RSP;
                effect.write_registers = RBP;
            }
            Op::RestoreStackPointerFromFrame => {
                effect.read_registers = RBP;
                effect.write_registers = RSP;
            }
            Op::AdjustStack { .. } => {
                effect.read_registers = RSP;
                effect.write_registers = RSP;
                effect.write_flags = ALL_FLAGS;
            }
            Op::LeaveFrame => {
                effect.read_registers = RBP;
                effect.write_registers = RSP | RBP;
                effect.memory = MemoryEffect::ReadSavedFramePointer;
            }
            Op::Jcc(condition) => {
                effect.read_flags = match condition {
                    Condition::E | Condition::Ne => ZF,
                    Condition::S | Condition::Ns => SF,
                    Condition::O | Condition::No => OF,
                    Condition::B | Condition::Ae => CF,
                    Condition::Be | Condition::A => CF | ZF,
                    Condition::L | Condition::Ge => SF | OF,
                    Condition::Le | Condition::G => ZF | SF | OF,
                };
                effect.control = ControlEffect::ConditionalBranch;
            }
            Op::Jmp => effect.control = ControlEffect::DirectBranch,
            Op::CallDirect { .. } => {
                effect.read_registers = RSP;
                effect.write_registers = RSP;
                effect.memory = MemoryEffect::WriteReturnAddress;
                effect.control = ControlEffect::DirectCall;
            }
            Op::Ret => {
                effect.read_registers = RSP;
                effect.write_registers = RSP;
                effect.memory = MemoryEffect::ReadReturnAddress;
                effect.control = ControlEffect::Return;
            }
            Op::Nop => {}
        }
        effect
    }
}

fn checked_register(register: Register, ip: u64) -> Result<Register, String> {
    match register {
        Register::RAX
        | Register::RDI
        | Register::RSI
        | Register::RDX
        | Register::RCX
        | Register::R8
        | Register::R9
        | Register::RBX
        | Register::R10
        | Register::R11
        | Register::R12
        | Register::R13
        | Register::R14
        | Register::R15 => Ok(register),
        _ => Err(format!(
            "register {register:?} unsupported at 0x{ip:x}; only full 64-bit scalar registers are modeled"
        )),
    }
}

fn parent_of_32(register: Register, ip: u64) -> Result<Register, String> {
    match register {
        Register::EAX => Ok(Register::RAX),
        Register::EDI => Ok(Register::RDI),
        Register::ESI => Ok(Register::RSI),
        Register::EDX => Ok(Register::RDX),
        Register::ECX => Ok(Register::RCX),
        Register::R8D => Ok(Register::R8),
        Register::R9D => Ok(Register::R9),
        Register::EBX => Ok(Register::RBX),
        Register::R10D => Ok(Register::R10),
        Register::R11D => Ok(Register::R11),
        Register::R12D => Ok(Register::R12),
        Register::R13D => Ok(Register::R13),
        Register::R14D => Ok(Register::R14),
        Register::R15D => Ok(Register::R15),
        _ => Err(format!(
            "32-bit register {register:?} unsupported at 0x{ip:x}"
        )),
    }
}

fn operand32(instruction: &Instruction, index: u32) -> Result<Value32, String> {
    let ip = instruction.ip();
    match instruction.op_kind(index) {
        OpKind::Register => Ok(Value32::Register(parent_of_32(
            instruction.op_register(index),
            ip,
        )?)),
        OpKind::Immediate32 => Ok(Value32::Immediate(instruction.immediate32())),
        _ => Err(format!("32-bit operand kind unsupported at 0x{ip:x}")),
    }
}

fn operand(instruction: &Instruction, index: u32) -> Result<Value, String> {
    let ip = instruction.ip();
    Ok(match instruction.op_kind(index) {
        OpKind::Register => Value::Register(checked_register(instruction.op_register(index), ip)?),
        OpKind::Immediate8to64 => Value::Immediate(instruction.immediate8to64()),
        OpKind::Immediate32to64 => Value::Immediate(instruction.immediate32to64()),
        OpKind::Immediate64 => Value::Immediate(instruction.immediate64() as i64),
        _ => return Err(format!("operand kind unsupported at 0x{ip:x}")),
    })
}

fn stack_adjustment(instruction: &Instruction) -> Result<i64, String> {
    match instruction.op1_kind() {
        OpKind::Immediate8to64 => Ok(instruction.immediate8to64()),
        OpKind::Immediate32to64 => Ok(instruction.immediate32to64()),
        _ => Err(format!(
            "stack adjustment needs sign-extended immediate at 0x{:x}",
            instruction.ip()
        )),
    }
}

fn stack_memory(instruction: &Instruction) -> Result<(Register, i64), String> {
    let ip = instruction.ip();
    let base = instruction.memory_base();
    if !matches!(base, Register::RSP | Register::RBP)
        || instruction.memory_index() != Register::None
        || instruction.segment_prefix() != Register::None
    {
        return Err(format!(
            "stack memory needs an unindexed RSP/RBP base at 0x{ip:x}"
        ));
    }
    Ok((base, instruction.memory_displacement64() as i64))
}

pub fn classify(instruction: &Instruction) -> Result<Op, String> {
    let ip = instruction.ip();
    if instruction.has_lock_prefix()
        || instruction.has_rep_prefix()
        || instruction.has_repne_prefix()
    {
        return Err(format!("instruction prefix unsupported at 0x{ip:x}"));
    }
    let register_dest = || checked_register(instruction.op0_register(), ip);
    let op = match instruction.mnemonic() {
        Mnemonic::Push
            if instruction.op_count() == 1
                && instruction.op0_kind() == OpKind::Register
                && instruction.op0_register() == Register::RBP =>
        {
            Op::SaveFramePointer
        }
        Mnemonic::Pop
            if instruction.op_count() == 1
                && instruction.op0_kind() == OpKind::Register
                && instruction.op0_register() == Register::RBP =>
        {
            Op::RestoreFramePointer
        }
        Mnemonic::Mov
            if instruction.op_count() == 2
                && instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register
                && instruction.op0_register() == Register::RBP
                && instruction.op1_register() == Register::RSP =>
        {
            Op::SetFramePointer
        }
        Mnemonic::Mov
            if instruction.op_count() == 2
                && instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Register
                && instruction.op0_register() == Register::RSP
                && instruction.op1_register() == Register::RBP =>
        {
            Op::RestoreStackPointerFromFrame
        }
        Mnemonic::Add | Mnemonic::Sub
            if instruction.op_count() == 2
                && instruction.op0_kind() == OpKind::Register
                && instruction.op0_register() == Register::RSP =>
        {
            Op::AdjustStack {
                kind: match instruction.mnemonic() {
                    Mnemonic::Add => Alu::Add,
                    Mnemonic::Sub => Alu::Sub,
                    _ => unreachable!(),
                },
                amount: stack_adjustment(instruction)?,
            }
        }
        Mnemonic::Leave if instruction.op_count() == 0 => Op::LeaveFrame,
        Mnemonic::Mov
            if instruction.op_count() == 2
                && instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Memory
                && instruction.op0_register().size() == 8 =>
        {
            let (base, displacement) = stack_memory(instruction)?;
            Op::LoadStack64 {
                dst: register_dest()?,
                base,
                displacement,
            }
        }
        Mnemonic::Mov
            if instruction.op_count() == 2
                && instruction.op0_kind() == OpKind::Memory
                && instruction.op1_kind() == OpKind::Register
                && instruction.op1_register().size() == 8 =>
        {
            let (base, displacement) = stack_memory(instruction)?;
            Op::StoreStack64 {
                base,
                displacement,
                src: checked_register(instruction.op1_register(), ip)?,
            }
        }
        Mnemonic::Mov
            if instruction.op_count() == 2 && instruction.op0_kind() == OpKind::Register =>
        {
            if let Ok(dst) = parent_of_32(instruction.op0_register(), ip) {
                Op::Mov32 {
                    dst,
                    src: operand32(instruction, 1)?,
                }
            } else {
                Op::Mov {
                    dst: register_dest()?,
                    src: operand(instruction, 1)?,
                }
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
                return Err(format!("segment/RIP-relative LEA unsupported at 0x{ip:x}"));
            }
            let optional_register = |register| {
                if register == Register::None {
                    Ok(None)
                } else {
                    checked_register(register, ip).map(Some)
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
        Mnemonic::Add | Mnemonic::Sub | Mnemonic::And | Mnemonic::Or | Mnemonic::Xor
            if instruction.op_count() == 2 && instruction.op0_kind() == OpKind::Register =>
        {
            Op::Alu {
                kind: match instruction.mnemonic() {
                    Mnemonic::Add => Alu::Add,
                    Mnemonic::Sub => Alu::Sub,
                    Mnemonic::And => Alu::And,
                    Mnemonic::Or => Alu::Or,
                    Mnemonic::Xor => Alu::Xor,
                    _ => unreachable!(),
                },
                dst: register_dest()?,
                src: operand(instruction, 1)?,
            }
        }
        Mnemonic::Cmp | Mnemonic::Test
            if instruction.op_count() == 2 && instruction.op0_kind() == OpKind::Register =>
        {
            let lhs = register_dest()?;
            let rhs = operand(instruction, 1)?;
            if instruction.mnemonic() == Mnemonic::Cmp {
                Op::Cmp { lhs, rhs }
            } else {
                Op::Test { lhs, rhs }
            }
        }
        Mnemonic::Jmp if instruction.flow_control() == FlowControl::UnconditionalBranch => Op::Jmp,
        Mnemonic::Call
            if instruction.flow_control() == FlowControl::Call
                && matches!(
                    instruction.op0_kind(),
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                ) =>
        {
            Op::CallDirect {
                target: instruction.near_branch_target(),
            }
        }
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
        Mnemonic::Nop | Mnemonic::Endbr64 if instruction.op_count() == 0 => Op::Nop,
        _ => {
            return Err(format!(
                "unsupported {:?} at 0x{ip:x}",
                instruction.mnemonic()
            ));
        }
    };
    if matches!(op, Op::Jcc(_) | Op::Jmp | Op::CallDirect { .. })
        && !matches!(
            instruction.op0_kind(),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        )
    {
        return Err(format!("non-direct branch or call unsupported at 0x{ip:x}"));
    }
    Ok(op)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions};

    #[test]
    fn thirty_two_bit_write_has_distinct_typed_operation() {
        let mut decoder = Decoder::with_ip(64, &[0x89, 0xf8], 0x1000, DecoderOptions::NONE);
        assert!(matches!(
            classify(&decoder.decode()),
            Ok(Op::Mov32 {
                dst: Register::RAX,
                src: Value32::Register(Register::RDI)
            })
        ));
    }

    #[test]
    fn sysv_sixth_argument_and_bitwise_ops_are_typed() {
        let mut decoder = Decoder::with_ip(
            64,
            &[0x49, 0x23, 0xc1], // and rax, r9
            0x2000,
            DecoderOptions::NONE,
        );
        let instruction = decoder.decode();
        assert_eq!(
            classify(&instruction).unwrap(),
            Op::Alu {
                kind: Alu::And,
                dst: Register::RAX,
                src: Value::Register(Register::R9),
            }
        );
        assert_eq!(
            classify(&instruction).unwrap().effects().read_registers,
            RAX | R9
        );
    }

    #[test]
    fn full_width_add_has_typed_register_and_source() {
        let mut decoder = Decoder::with_ip(64, &[0x48, 0x01, 0xf0], 0x1000, DecoderOptions::NONE);
        assert!(matches!(
            classify(&decoder.decode()),
            Ok(Op::Alu {
                kind: Alu::Add,
                dst: Register::RAX,
                src: Value::Register(Register::RSI)
            })
        ));
    }

    #[test]
    fn cet_landing_pad_is_a_zero_effect_operation() {
        let mut decoder =
            Decoder::with_ip(64, &[0xf3, 0x0f, 0x1e, 0xfa], 0x3000, DecoderOptions::NONE);
        let operation = classify(&decoder.decode()).unwrap();
        assert_eq!(operation, Op::Nop);
        assert_eq!(operation.effects().read_registers, 0);
        assert_eq!(operation.effects().write_registers, 0);
    }

    #[test]
    fn callee_saved_and_extended_registers_are_first_class() {
        let mut decoder = Decoder::with_ip(64, &[0x4c, 0x89, 0xe3], 0x4000, DecoderOptions::NONE);
        let operation = classify(&decoder.decode()).unwrap();
        assert_eq!(
            operation,
            Op::Mov {
                dst: Register::RBX,
                src: Value::Register(Register::R12),
            }
        );
        assert_eq!(operation.effects().read_registers, R12);
        assert_eq!(operation.effects().write_registers, RBX);
    }

    #[test]
    fn effects_distinguish_flags_and_implicit_return_stack_read() {
        let comparison = Op::Cmp {
            lhs: Register::RDI,
            rhs: Value::Register(Register::RSI),
        }
        .effects();
        assert_eq!(comparison.read_registers, RDI | RSI);
        assert_eq!(comparison.write_flags, ZF | SF | OF | CF);
        let branch = Op::Jcc(Condition::Be).effects();
        assert_eq!(branch.read_flags, ZF | CF);
        assert_eq!(branch.control, ControlEffect::ConditionalBranch);
        let ret = Op::Ret.effects();
        assert_eq!(ret.read_registers, RSP);
        assert_eq!(ret.write_registers, RSP);
        assert_eq!(ret.memory, MemoryEffect::ReadReturnAddress);
    }

    #[test]
    fn frame_operations_have_explicit_stack_and_memory_effects() {
        let mut decoder = Decoder::with_ip(
            64,
            &[0x55, 0x48, 0x83, 0xec, 0x20, 0xc9],
            0x1000,
            DecoderOptions::NONE,
        );
        let saved = classify(&decoder.decode()).unwrap();
        assert!(matches!(saved, Op::SaveFramePointer));
        assert_eq!(saved.effects().memory, MemoryEffect::WriteSavedFramePointer);
        let adjusted = classify(&decoder.decode()).unwrap();
        assert!(matches!(
            adjusted,
            Op::AdjustStack {
                kind: Alu::Sub,
                amount: 32
            }
        ));
        assert_eq!(adjusted.effects().write_registers, RSP);
        assert!(matches!(classify(&decoder.decode()), Ok(Op::LeaveFrame)));
    }

    #[test]
    fn stack_load_and_store_are_typed_memory_effects() {
        // mov [rbp-8],rdi; mov rax,[rbp-8]
        let mut decoder = Decoder::with_ip(
            64,
            &[0x48, 0x89, 0x7d, 0xf8, 0x48, 0x8b, 0x45, 0xf8],
            0x1000,
            DecoderOptions::NONE,
        );
        let store = classify(&decoder.decode()).unwrap();
        assert!(matches!(
            store,
            Op::StoreStack64 {
                base: Register::RBP,
                displacement: -8,
                src: Register::RDI,
            }
        ));
        assert_eq!(store.effects().memory, MemoryEffect::WriteStackLocal);
        let load = classify(&decoder.decode()).unwrap();
        assert!(matches!(
            load,
            Op::LoadStack64 {
                dst: Register::RAX,
                base: Register::RBP,
                displacement: -8,
            }
        ));
        assert_eq!(load.effects().memory, MemoryEffect::ReadStackLocal);
    }

    #[test]
    fn direct_call_records_target_and_stack_effect_and_rejects_indirection() {
        let mut direct = Decoder::with_ip(64, &[0xe8, 0x05, 0, 0, 0], 0x1000, DecoderOptions::NONE);
        let call = classify(&direct.decode()).unwrap();
        assert!(matches!(call, Op::CallDirect { target: 0x100a }));
        let effect = call.effects();
        assert_eq!(effect.read_registers, RSP);
        assert_eq!(effect.write_registers, RSP);
        assert_eq!(effect.memory, MemoryEffect::WriteReturnAddress);
        assert_eq!(effect.control, ControlEffect::DirectCall);

        let mut indirect = Decoder::with_ip(64, &[0xff, 0xd0], 0x1000, DecoderOptions::NONE);
        assert!(classify(&indirect.decode()).is_err());
    }
}
