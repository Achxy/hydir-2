//! Conservative read-only stack-delta proof for one symbol-bounded region.

use crate::{Result, error};
use hydir_core::Address;
use hydir_semantics::{Alu, Op, classify};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Register};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct State {
    rsp: i64,
    rbp: Option<i64>,
    saved_rbp: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct StackSlot {
    pub offset: i64,
    pub width_bytes: u8,
}

#[derive(Debug)]
pub(super) struct StackEvidence {
    pub return_sites: Vec<Address>,
    /// RSP after near RET, relative to RSP at the region entry.
    pub exit_rsp_delta: i64,
    /// Exact typed local extent, relative to entry RSP, per access.
    pub slot_by_ip: BTreeMap<u64, StackSlot>,
    pub slots: Vec<StackSlot>,
}

fn stack_access(op: Op) -> Option<(Register, i64, u8)> {
    match op {
        Op::LoadStack64 {
            base, displacement, ..
        }
        | Op::StoreStack64 {
            base, displacement, ..
        } => Some((base, displacement, 8)),
        Op::LoadStack32 {
            base, displacement, ..
        }
        | Op::StoreStack32 {
            base, displacement, ..
        }
        | Op::AluStack32 {
            base, displacement, ..
        }
        | Op::CmpRegStack32 {
            base, displacement, ..
        }
        | Op::CmpStack32 {
            base, displacement, ..
        } => Some((base, displacement, 4)),
        _ => None,
    }
}

pub(super) fn analyze_stack(code: &[u8], address: u64) -> Result<StackEvidence> {
    analyze_stack_inner(code, address, false)
}

pub(super) fn analyze_stack_with_calls(code: &[u8], address: u64) -> Result<StackEvidence> {
    analyze_stack_inner(code, address, true)
}

fn analyze_stack_inner(code: &[u8], address: u64, allow_calls: bool) -> Result<StackEvidence> {
    if code.is_empty() || code.len() > 4096 {
        return Err(error("stack analysis requires 1..=4096 symbol bytes"));
    }
    let end = address
        .checked_add(code.len() as u64)
        .ok_or_else(|| error("stack analysis address overflow"))?;
    let mut pending = VecDeque::from([(
        address,
        State {
            rsp: 0,
            rbp: None,
            saved_rbp: false,
        },
    )]);
    let mut incoming = BTreeMap::<u64, State>::new();
    let mut owners = vec![None; code.len()];
    let mut return_sites = BTreeSet::new();
    let mut slot_by_ip = BTreeMap::new();
    let mut slots = BTreeSet::<StackSlot>::new();
    while let Some((ip, mut state)) = pending.pop_front() {
        if !(address..end).contains(&ip) {
            return Err(error(format!(
                "stack-analysis edge leaves symbol at 0x{ip:x}"
            )));
        }
        if let Some(previous) = incoming.get(&ip) {
            if *previous != state {
                return Err(error(format!("conflicting stack state at 0x{ip:x}")));
            }
            continue;
        }
        incoming.insert(ip, state);
        let offset = (ip - address) as usize;
        let mut decoder = Decoder::with_ip(64, &code[offset..], ip, DecoderOptions::NONE);
        let instruction = decoder.decode();
        if instruction.is_invalid() || decoder.position() == 0 {
            return Err(error(format!("invalid instruction at 0x{ip:x}")));
        }
        for owner in &mut owners[offset..offset + decoder.position()] {
            if let Some(other) = owner {
                return Err(error(format!(
                    "overlapping instructions at 0x{other:x} and 0x{ip:x}"
                )));
            }
            *owner = Some(ip);
        }
        let op = classify(&instruction).map_err(error)?;
        if let Some((base, displacement, width_bytes)) = stack_access(op) {
            let base_offset = if base == Register::RSP {
                Some(state.rsp)
            } else {
                state.rbp
            }
            .ok_or_else(|| error(format!("unknown stack base at 0x{ip:x}")))?;
            let offset = base_offset
                .checked_add(displacement)
                .ok_or_else(|| error("stack-local address overflow"))?;
            let slot_end = offset
                .checked_add(i64::from(width_bytes))
                .ok_or_else(|| error("stack-local extent overflow"))?;
            let local_top = if state.saved_rbp { -8 } else { 0 };
            let local_bottom = if allow_calls {
                state.rsp
            } else {
                state
                    .rsp
                    .checked_sub(128)
                    .ok_or_else(|| error("red-zone displacement overflows"))?
            };
            if offset < local_bottom || slot_end > local_top {
                return Err(error(format!(
                    "stack-local access at 0x{ip:x} leaves allocated frame or aliases saved state"
                )));
            }
            let slot = StackSlot {
                offset,
                width_bytes,
            };
            if slots.iter().any(|other| {
                *other != slot
                    && offset < other.offset + i64::from(other.width_bytes)
                    && other.offset < slot_end
            }) {
                return Err(error(
                    "overlapping stack-local widths or aliases are unresolved",
                ));
            }
            slots.insert(slot);
            if slots.len() > 8 {
                return Err(error("more than eight stack-local slots are unsupported"));
            }
            slot_by_ip.insert(ip, slot);
        } else {
            match op {
                Op::SaveFramePointer => {
                    if state.saved_rbp || state.rsp != 0 {
                        return Err(error(
                            "nested or displaced frame-pointer save is unresolved",
                        ));
                    }
                    state.rsp = -8;
                    state.saved_rbp = true;
                }
                Op::RestoreFramePointer => {
                    if !state.saved_rbp || state.rsp != -8 {
                        return Err(error("frame-pointer restore does not match saved slot"));
                    }
                    state.rsp = 0;
                    state.rbp = None;
                    state.saved_rbp = false;
                }
                Op::SetFramePointer => {
                    if !state.saved_rbp {
                        return Err(error("frame pointer set without saved RBP"));
                    }
                    state.rbp = Some(state.rsp);
                }
                Op::RestoreStackPointerFromFrame => {
                    state.rsp = state
                        .rbp
                        .ok_or_else(|| error("unknown RBP used to restore RSP"))?;
                }
                Op::AdjustStack { kind, amount } => {
                    if !(0..=4096).contains(&amount) {
                        return Err(error("stack adjustment exceeds bounded nonnegative range"));
                    }
                    state.rsp = if matches!(kind, Alu::Sub) {
                        state.rsp.checked_sub(amount)
                    } else {
                        state.rsp.checked_add(amount)
                    }
                    .ok_or_else(|| error("stack displacement overflows"))?;
                    if !(-4096..=0).contains(&state.rsp) {
                        return Err(error("stack displacement leaves bounded frame"));
                    }
                }
                Op::LeaveFrame => {
                    if !state.saved_rbp || state.rbp != Some(-8) {
                        return Err(error("LEAVE has no proven matching frame"));
                    }
                    state.rsp = 0;
                    state.rbp = None;
                    state.saved_rbp = false;
                }
                Op::CallDirect { .. } if allow_calls && state.rsp.rem_euclid(16) != 8 => {
                    // SysV AMD64 requires 16-byte alignment immediately before CALL.
                    // Function-entry RSP is eight bytes past that boundary.
                    return Err(error(format!("unaligned stack at call 0x{ip:x}")));
                }
                _ => {}
            }
        }
        if matches!(op, Op::Ret) {
            if state.saved_rbp || state.rsp != 0 {
                return Err(error(format!("unbalanced stack at return 0x{ip:x}")));
            }
            return_sites.insert(Address(ip));
            continue;
        }
        let mut successors = Vec::new();
        match instruction.flow_control() {
            FlowControl::Next => successors.push(instruction.next_ip()),
            FlowControl::ConditionalBranch => {
                successors.push(instruction.near_branch_target());
                successors.push(instruction.next_ip());
            }
            FlowControl::UnconditionalBranch => successors.push(instruction.near_branch_target()),
            FlowControl::Call if allow_calls && matches!(op, Op::CallDirect { .. }) => {
                successors.push(instruction.next_ip());
            }
            _ => {
                return Err(error(format!(
                    "unresolved stack effect or control flow at 0x{ip:x}"
                )));
            }
        }
        for target in successors {
            pending.push_back((target, state));
        }
    }
    if return_sites.is_empty() {
        return Err(error("no reachable return with proven stack state"));
    }
    Ok(StackEvidence {
        return_sites: return_sites.into_iter().collect(),
        exit_rsp_delta: 8,
        slot_by_ip,
        slots: slots.into_iter().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proves_balanced_frame_and_near_return_delta() {
        // push rbp; mov rbp,rsp; sub rsp,32; add rsp,32; pop rbp; ret
        let bytes = [
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0x48, 0x83, 0xc4, 0x20, 0x5d, 0xc3,
        ];
        let evidence = analyze_stack(&bytes, 0x1000).unwrap();
        assert_eq!(evidence.exit_rsp_delta, 8);
        assert_eq!(evidence.return_sites, vec![Address(0x100d)]);
    }

    #[test]
    fn refuses_unbalanced_frame_and_unknown_memory() {
        assert!(analyze_stack(&[0x55, 0xc3], 0x1000).is_err());
        // mov rax,[rbp-8]; ret
        assert!(analyze_stack(&[0x48, 0x8b, 0x45, 0xf8, 0xc3], 0x1000).is_err());
    }

    #[test]
    fn refuses_branch_join_with_different_stack_offsets() {
        // test rdi,rdi; je ret; sub rsp,8; ret
        let bytes = [0x48, 0x85, 0xff, 0x74, 0x04, 0x48, 0x83, 0xec, 0x08, 0xc3];
        assert!(
            analyze_stack(&bytes, 0x1000)
                .unwrap_err()
                .0
                .contains("conflicting stack state")
        );
    }

    #[test]
    fn rejects_overlapping_stack_slots_with_different_widths() {
        // push rbp; mov rbp,rsp; sub rsp,16; mov [rbp-8],edi;
        // mov rax,[rbp-8]; add rsp,16; pop rbp; ret
        let bytes = [
            0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10, 0x89, 0x7d, 0xf8, 0x48, 0x8b, 0x45,
            0xf8, 0x48, 0x83, 0xc4, 0x10, 0x5d, 0xc3,
        ];
        assert!(
            analyze_stack(&bytes, 0x1000)
                .unwrap_err()
                .0
                .contains("overlapping stack-local widths")
        );
    }
}
