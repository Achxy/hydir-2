//! A standalone LLVM lowering for one validated Ghidra raw P-code value op.
//!
//! This intentionally does not lower an instruction, state, memory, or CFG.
//! Non-constant source inputs become parameters named by their source index;
//! constant varnodes are embedded. The function can therefore be checked or
//! differentially executed without implying whole-function equivalence.

use hydir_ir::pcode::{
    GhidraFlowKind, GhidraSnapshot, PcodeAddress, PcodeEffect, PcodeExactOp,
    PcodeSemanticOperation, PcodeVarnode,
};
use hydir_ir::{SemanticFidelity, VerificationStatus};
use serde::{Deserialize, Serialize};

pub const PCODE_LLVM_PREFIX_VERSION: u32 = 1;
const MAX_PREFIX_OPERATIONS: usize = 4096;

/// An inspectable state transition prefix, stopping before the first effect
/// or flow that this emitter cannot preserve. It is not a complete function.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PcodeLlvmPrefixArtifact {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub entry: PcodeAddress,
    pub emitted_operations: usize,
    pub source_operations: Vec<PcodeLlvmSourceOperation>,
    pub stop_reason: String,
    pub stopped_at: Option<PcodeAddress>,
    pub state_abi: String,
    pub llvm_ir: String,
    pub semantic_fidelity: SemanticFidelity,
    pub verification: VerificationStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PcodeLlvmSourceOperation {
    pub address: PcodeAddress,
    pub instruction_index: usize,
    pub operation_index: usize,
    pub mnemonic: String,
}

pub(crate) fn pcode_offset(varnode: &PcodeVarnode) -> Result<u64, String> {
    let digits = varnode
        .offset
        .strip_prefix("0x")
        .ok_or("P-code offset requires 0x prefix")?;
    let offset =
        u64::from_str_radix(digits, 16).map_err(|_| "invalid P-code varnode offset".to_owned())?;
    offset
        .checked_add(u64::from(varnode.size - 1))
        .ok_or("P-code varnode byte range overflows u64")?;
    Ok(offset)
}

pub(crate) fn pcode_space_id(space: &str) -> Result<u32, String> {
    match space {
        "register" => Ok(1),
        "unique" => Ok(2),
        _ => Err(format!(
            "exact P-code operation uses unsupported state space {space}"
        )),
    }
}

/// Emit a straight-line prefix from a validated Ghidra snapshot. The state
/// helpers are external: read returns a zero-extended little-endian varnode;
/// write replaces exactly that byte range, including overlapping aliases.
/// IDs 1 and 2 designate Ghidra register and unique spaces respectively.
/// The unique space is cleared at each instruction boundary. Guest memory and
/// control effects stop emission before they occur.
pub fn emit_pcode_linear_prefix_llvm(
    snapshot: &GhidraSnapshot,
) -> Result<PcodeLlvmPrefixArtifact, String> {
    let cfg = snapshot.pcode_cfg_ir()?;
    let first = cfg
        .nodes
        .first()
        .ok_or("Ghidra selected function has no CFG nodes")?;
    if first.address != cfg.state.entry {
        return Err("selected function entry differs from first instruction".to_owned());
    }
    let mut helpers = String::new();
    let mut body = String::new();
    let mut sources = Vec::new();
    let mut stop_reason =
        "end of selected instruction list; return and later effects unverified".to_owned();
    let mut stopped_at = None;
    'instructions: for (instruction_index, instruction) in cfg.state.instructions.iter().enumerate()
    {
        if instruction_index > 0 {
            let previous = &cfg.nodes[instruction_index - 1];
            let linear = previous.outgoing_calls.is_empty()
                && !previous.has_unresolved_control
                && previous.outgoing_edges.len() == 1
                && cfg.edges[previous.outgoing_edges[0] as usize].target_node
                    == Some(instruction_index as u32)
                && cfg.edges[previous.outgoing_edges[0] as usize].evidence.kind
                    == GhidraFlowKind::Fallthrough;
            if !linear {
                stop_reason = "next instruction lacks a sole proven fallthrough edge".to_owned();
                stopped_at = Some(instruction.address.clone());
                break;
            }
        }
        body.push_str("  call void @hydir_clear_unique(ptr %state)\n");
        for (operation_index, state_operation) in instruction.operations.iter().enumerate() {
            if sources.len() >= MAX_PREFIX_OPERATIONS {
                stop_reason =
                    format!("P-code LLVM prefix exceeds {MAX_PREFIX_OPERATIONS} operations");
                stopped_at = Some(instruction.address.clone());
                break 'instructions;
            }
            if !matches!(state_operation.effect, PcodeEffect::Assign { .. }) {
                stop_reason = format!("opaque {} effect", state_operation.source.mnemonic);
                stopped_at = Some(instruction.address.clone());
                break 'instructions;
            }
            let operation = PcodeSemanticOperation {
                source: state_operation.source.clone(),
                effect: state_operation.effect.clone(),
            };
            let helper_name = format!("hydir_exact_{}", sources.len());
            let helper = match emit_pcode_exact_operation_llvm(&operation) {
                Ok(helper) => helper,
                Err(reason) => {
                    stop_reason =
                        format!("invalid {} operation: {reason}", operation.source.mnemonic);
                    stopped_at = Some(instruction.address.clone());
                    break 'instructions;
                }
            }
            .replacen("@hydir_pcode_exact(", &format!("@{helper_name}("), 1);
            helpers.push_str(&helper);
            helpers.push('\n');
            let mut arguments = Vec::new();
            for (input_index, input) in operation.source.inputs.iter().enumerate() {
                if input.space == "const" {
                    continue;
                }
                let space_id = pcode_space_id(&input.space)?;
                let bits = input.size * 8;
                let raw_name = format!("%op{}_in{}_raw", sources.len(), input_index);
                let (raw_bits, read_helper) = if bits > 64 {
                    (128, "hydir_read_varnode_wide")
                } else {
                    (64, "hydir_read_varnode")
                };
                body.push_str(&format!(
                    "  {raw_name} = call i{raw_bits} @{read_helper}(ptr %state, i32 {space_id}, i64 {}, i32 {})\n",
                    pcode_offset(input)?, input.size
                ));
                let typed_name = if bits == raw_bits {
                    raw_name
                } else {
                    let name = format!("%op{}_in{}", sources.len(), input_index);
                    body.push_str(&format!(
                        "  {name} = trunc i{raw_bits} {raw_name} to i{bits}\n"
                    ));
                    name
                };
                arguments.push(format!("i{bits} {typed_name}"));
            }
            if let PcodeEffect::Assign {
                operation: kind, ..
            } = &operation.effect
            {
                if matches!(
                    kind,
                    PcodeExactOp::UnsignedDivide
                        | PcodeExactOp::SignedDivide
                        | PcodeExactOp::UnsignedRemainder
                        | PcodeExactOp::SignedRemainder
                ) {
                    let input_operand = |input_index: usize| -> Result<String, String> {
                        let input = &operation.source.inputs[input_index];
                        let bits = input.size * 8;
                        if input.space == "const" {
                            Ok(format!(
                                "{}",
                                parse_constant(&input.offset)? & width_mask(bits)
                            ))
                        } else if bits == 64 {
                            Ok(format!("%op{}_in{}_raw", sources.len(), input_index))
                        } else {
                            Ok(format!("%op{}_in{}", sources.len(), input_index))
                        }
                    };
                    let divisor = input_operand(1)?;
                    let bits = operation.source.inputs[1].size * 8;
                    let id = sources.len();
                    body.push_str(&format!(
                        "  %division_zero_{id} = icmp eq i{bits} {divisor}, 0\n"
                    ));
                    let invalid = if *kind == PcodeExactOp::SignedDivide {
                        let dividend = input_operand(0)?;
                        let minimum = 1u64 << (bits - 1);
                        body.push_str(&format!(
                            "  %division_minimum_{id} = icmp eq i{bits} {dividend}, {minimum}\n  %division_negative_one_{id} = icmp eq i{bits} {divisor}, -1\n  %division_overflow_{id} = and i1 %division_minimum_{id}, %division_negative_one_{id}\n  %division_invalid_{id} = or i1 %division_zero_{id}, %division_overflow_{id}\n"
                        ));
                        format!("%division_invalid_{id}")
                    } else {
                        format!("%division_zero_{id}")
                    };
                    body.push_str(&format!(
                        "  br i1 {invalid}, label %division_stop_{id}, label %division_valid_{id}\ndivision_stop_{id}:\n  ret i32 {id}\ndivision_valid_{id}:\n"
                    ));
                }
            }
            let output = operation
                .source
                .output
                .as_ref()
                .ok_or("exact P-code operation lacks output")?;
            let result_bits = output.size * 8;
            let result_name = format!("%op{}_result", sources.len());
            body.push_str(&format!(
                "  {result_name} = call i{result_bits} @{helper_name}({})\n",
                arguments.join(", ")
            ));
            let raw_bits = if result_bits > 64 { 128 } else { 64 };
            let raw_result = if result_bits == raw_bits {
                result_name
            } else {
                let name = format!("%op{}_result_raw", sources.len());
                body.push_str(&format!(
                    "  {name} = zext i{result_bits} {result_name} to i{raw_bits}\n"
                ));
                name
            };
            let write_helper = if result_bits > 64 {
                "hydir_write_varnode_wide"
            } else {
                "hydir_write_varnode"
            };
            body.push_str(&format!(
                "  call void @{write_helper}(ptr %state, i32 {}, i64 {}, i32 {}, i{raw_bits} {raw_result})\n",
                pcode_space_id(&output.space)?, pcode_offset(output)?, output.size
            ));
            sources.push(PcodeLlvmSourceOperation {
                address: instruction.address.clone(),
                instruction_index,
                operation_index,
                mnemonic: operation.source.mnemonic,
            });
        }
    }
    let ir = format!(
        "; Hydir P-code linear prefix, not a whole-function equivalence claim.\n\
         ; state ABI: space 1=register, 2=unique; byte offsets, little-endian widths.\n\
         declare i64 @hydir_read_varnode(ptr, i32, i64, i32)\n\
         declare void @hydir_write_varnode(ptr, i32, i64, i32, i64)\n\n\
         declare i128 @hydir_read_varnode_wide(ptr, i32, i64, i32)\n\
         declare void @hydir_write_varnode_wide(ptr, i32, i64, i32, i128)\n\n\
         declare void @hydir_clear_unique(ptr)\n\n\
         {helpers}define i32 @hydir_pcode_prefix(ptr %state) {{\nentry:\n{body}  ret i32 {}\n}}\n",
        sources.len()
    );
    Ok(PcodeLlvmPrefixArtifact {
        schema_version: PCODE_LLVM_PREFIX_VERSION,
        binary_sha256: snapshot.binary_sha256.clone(),
        entry: cfg.state.entry,
        emitted_operations: sources.len(),
        source_operations: sources,
        stop_reason,
        stopped_at,
        state_abi: "hydir-pcode-state-v1: opaque pointer; helper spaces 1=register,2=unique; byte offsets; little-endian exact-width reads/writes; clear unique at instruction start; runtime undefined division returns the number of completed source operations without writing its output".to_owned(),
        llvm_ir: ir,
        semantic_fidelity: SemanticFidelity::Unknown,
        verification: VerificationStatus::NotRun,
    })
}

/// Emit a verifier-clean LLVM function for one exact operation. The selected
/// Checked 128-bit value operations cover x86-64 scalar extension, arithmetic,
/// and a bounded subset of SIMD bitvector P-code. User operations and memory
/// effects remain explicit boundaries.
/// The function is named `hydir_pcode_exact` and has an integer return type
/// equal to the output varnode width. Every non-constant source input is a
/// width-typed parameter `%inN`, where N is its source-input index. Division
/// by a dynamic zero divisor and signed MIN / -1 are totalized to zero and
/// low quotient bits in this standalone helper to avoid LLVM poison. Those
/// are not exact P-code results; stateful prefix/CFG emitters stop first.
pub fn emit_pcode_exact_operation_llvm(
    operation: &PcodeSemanticOperation,
) -> Result<String, String> {
    let PcodeEffect::Assign {
        operation: kind,
        result_width_bits: result_bits,
    } = operation.effect
    else {
        return Err("opaque P-code effect cannot be emitted as exact LLVM".to_owned());
    };
    let wide = result_bits > 64 || operation.source.inputs.iter().any(|input| input.size > 8);
    if wide
        && !matches!(
            kind,
            PcodeExactOp::Copy
                | PcodeExactOp::ZeroExtend
                | PcodeExactOp::SignExtend
                | PcodeExactOp::TwosComplement
                | PcodeExactOp::BitwiseNegate
                | PcodeExactOp::Piece
                | PcodeExactOp::Multiply
                | PcodeExactOp::Subpiece
                | PcodeExactOp::Add
                | PcodeExactOp::Sub
                | PcodeExactOp::Xor
                | PcodeExactOp::And
                | PcodeExactOp::Or
                | PcodeExactOp::Equal
                | PcodeExactOp::NotEqual
                | PcodeExactOp::UnsignedLess
                | PcodeExactOp::UnsignedLessEqual
                | PcodeExactOp::SignedLess
                | PcodeExactOp::SignedLessEqual
                | PcodeExactOp::ShiftLeft
                | PcodeExactOp::LogicalShiftRight
                | PcodeExactOp::ArithmeticShiftRight
        )
    {
        return Err("wide P-code operation lacks checked LLVM lowering".to_owned());
    }

    // The public evaluator rechecks that the effect still matches the source
    // opcode, mnemonic, operand spaces, arity, and widths. Supply matching
    // values for constant varnodes so this also rejects forged artifacts.
    let is_division = matches!(
        kind,
        PcodeExactOp::UnsignedDivide
            | PcodeExactOp::SignedDivide
            | PcodeExactOp::UnsignedRemainder
            | PcodeExactOp::SignedRemainder
    );
    let witness = operation
        .source
        .inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            if input.space == "const" {
                parse_constant(&input.offset).map(u128::from)
            } else if is_division && index == 1 {
                // A zero witness would reject every otherwise valid dynamic
                // division before LLVM has a chance to guard its divisor.
                Ok(1u128)
            } else {
                Ok(0u128)
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    if operation.evaluate_exact_wide(&witness)?.is_none() {
        return Err("P-code operation is not exact".to_owned());
    }

    let mut parameters = Vec::new();
    let mut operands = Vec::new();
    for (index, input) in operation.source.inputs.iter().enumerate() {
        let bits = input.size * 8;
        if input.space == "const" {
            operands.push(format!("{}", witness[index] & wide_mask(bits)));
        } else {
            let name = format!("%in{index}");
            parameters.push(format!("i{bits} {name}"));
            operands.push(name);
        }
    }
    let result_type = format!("i{result_bits}");
    let mut body = String::new();
    let value = match kind {
        PcodeExactOp::Copy => operands[0].clone(),
        PcodeExactOp::TwosComplement | PcodeExactOp::BitwiseNegate => {
            let (instruction, first) = if kind == PcodeExactOp::TwosComplement {
                ("sub", "0")
            } else {
                ("xor", "-1")
            };
            body.push_str(&format!(
                "  %result = {instruction} {result_type} {first}, {}\n",
                operands[0]
            ));
            "%result".to_owned()
        }
        PcodeExactOp::BooleanNegate => {
            body.push_str(&format!("  %result = xor i8 {}, 1\n", operands[0]));
            "%result".to_owned()
        }
        PcodeExactOp::BooleanXor | PcodeExactOp::BooleanAnd | PcodeExactOp::BooleanOr => {
            let instruction = match kind {
                PcodeExactOp::BooleanXor => "xor",
                PcodeExactOp::BooleanAnd => "and",
                PcodeExactOp::BooleanOr => "or",
                _ => unreachable!(),
            };
            body.push_str(&format!(
                "  %result = {instruction} i8 {}, {}\n",
                operands[0], operands[1]
            ));
            "%result".to_owned()
        }
        PcodeExactOp::Piece => {
            let high_bits = operation.source.inputs[0].size * 8;
            let low_bits = operation.source.inputs[1].size * 8;
            body.push_str(&format!(
                "  %high_wide = zext i{high_bits} {} to {result_type}\n  %low_wide = zext i{low_bits} {} to {result_type}\n  %high_shifted = shl {result_type} %high_wide, {low_bits}\n  %result = or {result_type} %high_shifted, %low_wide\n",
                operands[0], operands[1]
            ));
            "%result".to_owned()
        }
        PcodeExactOp::Subpiece => {
            let input_bits = operation.source.inputs[0].size * 8;
            let drop_bits = witness[1] * 8;
            let shifted = if drop_bits == 0 {
                operands[0].clone()
            } else {
                body.push_str(&format!(
                    "  %shifted = lshr i{input_bits} {}, {drop_bits}\n",
                    operands[0]
                ));
                "%shifted".to_owned()
            };
            if input_bits == result_bits {
                shifted
            } else {
                body.push_str(&format!(
                    "  %result = trunc i{input_bits} {shifted} to {result_type}\n"
                ));
                "%result".to_owned()
            }
        }
        PcodeExactOp::PopCount => {
            // A fixed 64-bit SWAR count avoids an external intrinsic
            // declaration in each independently emitted helper. The source
            // input is zero extended first; its high bits do not contribute.
            let input_bits = operation.source.inputs[0].size * 8;
            let wide_input = if input_bits == 64 {
                operands[0].clone()
            } else {
                body.push_str(&format!(
                    "  %pop_input = zext i{input_bits} {} to i64\n",
                    operands[0]
                ));
                "%pop_input".to_owned()
            };
            body.push_str(&format!(
                "  %pop_shift1 = lshr i64 {wide_input}, 1\n\
                   %pop_mask1 = and i64 %pop_shift1, 6148914691236517205\n\
                   %pop_sub = sub i64 {wide_input}, %pop_mask1\n\
                   %pop_mask2 = and i64 %pop_sub, 3689348814741910323\n\
                   %pop_shift2 = lshr i64 %pop_sub, 2\n\
                   %pop_mask3 = and i64 %pop_shift2, 3689348814741910323\n\
                   %pop_add2 = add i64 %pop_mask2, %pop_mask3\n\
                   %pop_shift4 = lshr i64 %pop_add2, 4\n\
                   %pop_add4 = add i64 %pop_add2, %pop_shift4\n\
                   %pop_nibbles = and i64 %pop_add4, 1085102592571150095\n\
                   %pop_sum = mul i64 %pop_nibbles, 72340172838076673\n\
                   %pop_count = lshr i64 %pop_sum, 56\n"
            ));
            if result_bits == 64 {
                "%pop_count".to_owned()
            } else {
                body.push_str(&format!(
                    "  %result = trunc i64 %pop_count to {result_type}\n"
                ));
                "%result".to_owned()
            }
        }
        PcodeExactOp::LeadingZeroCount => {
            let input_bits = operation.source.inputs[0].size * 8;
            let wide_input = if input_bits == 64 {
                operands[0].clone()
            } else {
                body.push_str(&format!(
                    "  %lz_input = zext i{input_bits} {} to i64\n",
                    operands[0]
                ));
                "%lz_input".to_owned()
            };
            // Each step shifts away a known-zero high region. The zero input
            // needs one final count; subtract the zero-extension padding.
            let mut current = wide_input.clone();
            let mut total = "0".to_owned();
            for (step, threshold) in [(32, 32), (16, 48), (8, 56), (4, 60), (2, 62), (1, 63)] {
                body.push_str(&format!(
                    "  %lz_small_{step} = icmp ult i64 {current}, {}\n  %lz_step_{step} = select i1 %lz_small_{step}, i64 {step}, i64 0\n  %lz_shifted_{step} = shl i64 {current}, %lz_step_{step}\n  %lz_total_{step} = add i64 {total}, %lz_step_{step}\n",
                    1u64 << threshold
                ));
                current = format!("%lz_shifted_{step}");
                total = format!("%lz_total_{step}");
            }
            body.push_str(&format!(
                "  %lz_zero = icmp eq i64 {wide_input}, 0\n  %lz_zero_adjust = zext i1 %lz_zero to i64\n  %lz_count64 = add i64 {total}, %lz_zero_adjust\n  %lz_unpadded = sub i64 %lz_count64, {}\n",
                64 - input_bits
            ));
            if result_bits == 64 {
                "%lz_unpadded".to_owned()
            } else {
                body.push_str(&format!(
                    "  %result = trunc i64 %lz_unpadded to {result_type}\n"
                ));
                "%result".to_owned()
            }
        }
        PcodeExactOp::ZeroExtend | PcodeExactOp::SignExtend => {
            let input_bits = operation.source.inputs[0].size * 8;
            let instruction = if kind == PcodeExactOp::ZeroExtend {
                "zext"
            } else {
                "sext"
            };
            body.push_str(&format!(
                "  %result = {instruction} i{input_bits} {} to {result_type}\n",
                operands[0]
            ));
            "%result".to_owned()
        }
        PcodeExactOp::Add
        | PcodeExactOp::Sub
        | PcodeExactOp::Multiply
        | PcodeExactOp::Xor
        | PcodeExactOp::And
        | PcodeExactOp::Or => {
            let instruction = match kind {
                PcodeExactOp::Add => "add",
                PcodeExactOp::Sub => "sub",
                PcodeExactOp::Multiply => "mul",
                PcodeExactOp::Xor => "xor",
                PcodeExactOp::And => "and",
                PcodeExactOp::Or => "or",
                _ => unreachable!(),
            };
            body.push_str(&format!(
                "  %result = {instruction} {result_type} {}, {}\n",
                operands[0], operands[1]
            ));
            "%result".to_owned()
        }
        PcodeExactOp::UnsignedDivide
        | PcodeExactOp::SignedDivide
        | PcodeExactOp::UnsignedRemainder
        | PcodeExactOp::SignedRemainder => {
            let signed = matches!(
                kind,
                PcodeExactOp::SignedDivide | PcodeExactOp::SignedRemainder
            );
            let remainder = matches!(
                kind,
                PcodeExactOp::UnsignedRemainder | PcodeExactOp::SignedRemainder
            );
            let instruction = match (signed, remainder) {
                (false, false) => "udiv",
                (false, true) => "urem",
                (true, false) => "sdiv",
                (true, true) => "srem",
            };
            body.push_str(&format!(
                "  %zero_divisor = icmp eq {result_type} {}, 0\n",
                operands[1]
            ));
            if signed {
                let signed_minimum = 1u64 << (result_bits - 1);
                body.push_str(&format!(
                    "  %minimum_dividend = icmp eq {result_type} {}, {signed_minimum}\n  %negative_one_divisor = icmp eq {result_type} {}, -1\n  %signed_overflow = and i1 %minimum_dividend, %negative_one_divisor\n  %unsafe_division = or i1 %zero_divisor, %signed_overflow\n  %safe_dividend = select i1 %unsafe_division, {result_type} 0, {result_type} {}\n  %safe_divisor = select i1 %unsafe_division, {result_type} 1, {result_type} {}\n  %divided = {instruction} {result_type} %safe_dividend, %safe_divisor\n  %overflow_value = select i1 %signed_overflow, {result_type} {}, {result_type} %divided\n  %result = select i1 %zero_divisor, {result_type} 0, {result_type} %overflow_value\n",
                    operands[0], operands[1], operands[0], operands[1],
                    if remainder { 0 } else { signed_minimum }
                ));
            } else {
                body.push_str(&format!(
                    "  %safe_divisor = select i1 %zero_divisor, {result_type} 1, {result_type} {}\n  %divided = {instruction} {result_type} {}, %safe_divisor\n  %result = select i1 %zero_divisor, {result_type} 0, {result_type} %divided\n",
                    operands[1], operands[0]
                ));
            }
            "%result".to_owned()
        }
        PcodeExactOp::UnsignedCarry | PcodeExactOp::SignedCarry | PcodeExactOp::SignedBorrow => {
            let input_bits = operation.source.inputs[0].size * 8;
            let instruction = if kind == PcodeExactOp::SignedBorrow {
                "sub"
            } else {
                "add"
            };
            body.push_str(&format!(
                "  %arithmetic = {instruction} i{input_bits} {}, {}\n",
                operands[0], operands[1]
            ));
            if kind == PcodeExactOp::UnsignedCarry {
                body.push_str(&format!(
                    "  %overflow = icmp ult i{input_bits} %arithmetic, {}\n",
                    operands[0]
                ));
            } else {
                body.push_str(&format!(
                    "  %left_sign = icmp slt i{input_bits} {}, 0\n  %right_sign = icmp slt i{input_bits} {}, 0\n  %result_sign = icmp slt i{input_bits} %arithmetic, 0\n",
                    operands[0], operands[1]
                ));
                let operand_relation = if kind == PcodeExactOp::SignedCarry {
                    "icmp eq"
                } else {
                    "xor"
                };
                body.push_str(&format!(
                    "  %operand_relation = {operand_relation} i1 %left_sign, %right_sign\n  %result_relation = xor i1 %left_sign, %result_sign\n  %overflow = and i1 %operand_relation, %result_relation\n"
                ));
            }
            body.push_str("  %result = zext i1 %overflow to i8\n");
            "%result".to_owned()
        }
        PcodeExactOp::Equal
        | PcodeExactOp::NotEqual
        | PcodeExactOp::UnsignedLess
        | PcodeExactOp::UnsignedLessEqual
        | PcodeExactOp::SignedLess
        | PcodeExactOp::SignedLessEqual => {
            let predicate = match kind {
                PcodeExactOp::Equal => "eq",
                PcodeExactOp::NotEqual => "ne",
                PcodeExactOp::UnsignedLess => "ult",
                PcodeExactOp::UnsignedLessEqual => "ule",
                PcodeExactOp::SignedLess => "slt",
                PcodeExactOp::SignedLessEqual => "sle",
                _ => unreachable!(),
            };
            let input_bits = operation.source.inputs[0].size * 8;
            body.push_str(&format!(
                "  %comparison = icmp {predicate} i{input_bits} {}, {}\n",
                operands[0], operands[1]
            ));
            body.push_str(&format!(
                "  %result = zext i1 %comparison to {result_type}\n"
            ));
            "%result".to_owned()
        }
        PcodeExactOp::ShiftLeft
        | PcodeExactOp::LogicalShiftRight
        | PcodeExactOp::ArithmeticShiftRight => {
            let count_bits = operation.source.inputs[1].size * 8;
            let count = if count_bits == result_bits {
                operands[1].clone()
            } else {
                let cast = if count_bits < result_bits {
                    "zext"
                } else {
                    "trunc"
                };
                body.push_str(&format!(
                    "  %count = {cast} i{count_bits} {} to {result_type}\n",
                    operands[1]
                ));
                "%count".to_owned()
            };
            // LLVM shifts by >= bitwidth are poison; raw P-code defines them.
            // Compare before narrowing the count, then shift only by a safe
            // count and select the P-code overshift value.
            body.push_str(&format!(
                "  %overshift = icmp uge i{count_bits} {}, {result_bits}\n",
                operands[1]
            ));
            body.push_str(&format!(
                "  %safe_count = select i1 %overshift, {result_type} 0, {result_type} {count}\n"
            ));
            let instruction = match kind {
                PcodeExactOp::ShiftLeft => "shl",
                PcodeExactOp::LogicalShiftRight => "lshr",
                PcodeExactOp::ArithmeticShiftRight => "ashr",
                _ => unreachable!(),
            };
            body.push_str(&format!(
                "  %shifted = {instruction} {result_type} {}, %safe_count\n",
                operands[0]
            ));
            let overshift = if kind == PcodeExactOp::ArithmeticShiftRight {
                body.push_str(&format!(
                    "  %sign_fill = ashr {result_type} {}, {}\n",
                    operands[0],
                    result_bits - 1
                ));
                "%sign_fill"
            } else {
                "0"
            };
            body.push_str(&format!(
                "  %result = select i1 %overshift, {result_type} {overshift}, {result_type} %shifted\n"
            ));
            "%result".to_owned()
        }
    };
    Ok(format!(
        "define {result_type} @hydir_pcode_exact({}) {{\nentry:\n{body}  ret {result_type} {value}\n}}\n",
        parameters.join(", ")
    ))
}

fn parse_constant(offset: &str) -> Result<u64, String> {
    let digits = offset
        .strip_prefix("0x")
        .ok_or_else(|| "P-code constant offset requires 0x prefix".to_owned())?;
    u64::from_str_radix(digits, 16).map_err(|_| "invalid P-code constant offset".to_owned())
}

fn width_mask(bits: u32) -> u64 {
    if bits == 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

fn wide_mask(bits: u32) -> u128 {
    if bits == 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydir_ir::pcode::{PcodeAddress, PcodeOperation, PcodeVarnode};
    use std::io::Write;
    use std::process::{Command, Stdio};

    fn operation(
        opcode: u32,
        mnemonic: &str,
        output: u32,
        inputs: &[u32],
    ) -> PcodeSemanticOperation {
        let source = PcodeOperation {
            mnemonic: mnemonic.to_owned(),
            opcode,
            sequence_index: 0,
            sequence_time: 0,
            source_address: PcodeAddress {
                space: "ram".to_owned(),
                offset: "0x1000".to_owned(),
            },
            userop_name: None,
            output: Some(PcodeVarnode {
                space: "unique".to_owned(),
                offset: "0x0".to_owned(),
                size: output,
            }),
            inputs: inputs
                .iter()
                .map(|&size| PcodeVarnode {
                    space: "register".to_owned(),
                    offset: "0x0".to_owned(),
                    size,
                })
                .collect(),
        };
        let kind = match opcode {
            1 => PcodeExactOp::Copy,
            11 => PcodeExactOp::Equal,
            12 => PcodeExactOp::NotEqual,
            13 => PcodeExactOp::SignedLess,
            14 => PcodeExactOp::SignedLessEqual,
            15 => PcodeExactOp::UnsignedLess,
            16 => PcodeExactOp::UnsignedLessEqual,
            17 => PcodeExactOp::ZeroExtend,
            18 => PcodeExactOp::SignExtend,
            19 => PcodeExactOp::Add,
            20 => PcodeExactOp::Sub,
            21 => PcodeExactOp::UnsignedCarry,
            22 => PcodeExactOp::SignedCarry,
            23 => PcodeExactOp::SignedBorrow,
            24 => PcodeExactOp::TwosComplement,
            25 => PcodeExactOp::BitwiseNegate,
            26 => PcodeExactOp::Xor,
            27 => PcodeExactOp::And,
            28 => PcodeExactOp::Or,
            29 => PcodeExactOp::ShiftLeft,
            30 => PcodeExactOp::LogicalShiftRight,
            31 => PcodeExactOp::ArithmeticShiftRight,
            32 => PcodeExactOp::Multiply,
            33 => PcodeExactOp::UnsignedDivide,
            34 => PcodeExactOp::SignedDivide,
            35 => PcodeExactOp::UnsignedRemainder,
            36 => PcodeExactOp::SignedRemainder,
            37 => PcodeExactOp::BooleanNegate,
            38 => PcodeExactOp::BooleanXor,
            39 => PcodeExactOp::BooleanAnd,
            40 => PcodeExactOp::BooleanOr,
            62 => PcodeExactOp::Piece,
            63 => PcodeExactOp::Subpiece,
            72 => PcodeExactOp::PopCount,
            73 => PcodeExactOp::LeadingZeroCount,
            _ => panic!("unexpected opcode"),
        };
        PcodeSemanticOperation {
            source,
            effect: PcodeEffect::Assign {
                operation: kind,
                result_width_bits: output * 8,
            },
        }
    }

    fn run_opt(source: &str, args: &[&str]) -> Option<String> {
        if Command::new("opt").arg("--version").output().is_err() {
            return None;
        }
        let mut child = Command::new("opt")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(source.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "opt failed: {}\n{source}",
            String::from_utf8_lossy(&output.stderr)
        );
        Some(String::from_utf8(output.stdout).unwrap())
    }

    fn folded_return(op: &PcodeSemanticOperation) -> Option<u64> {
        let llvm = emit_pcode_exact_operation_llvm(op).unwrap();
        let folded = run_opt(&llvm, &["-S", "-O2", "-"])?;
        let return_line = folded
            .lines()
            .map(str::trim)
            .find(|line| line.starts_with("ret i"))
            .expect("optimized function must return an integer");
        let literal = return_line.split_whitespace().last().unwrap();
        let signed = literal
            .parse::<i128>()
            .expect("optimized result must be a constant");
        let bits = match op.effect {
            PcodeEffect::Assign {
                result_width_bits, ..
            } => result_width_bits,
            PcodeEffect::Opaque { .. } => unreachable!(),
        };
        Some((signed as u64) & width_mask(bits))
    }

    #[test]
    fn every_exact_kind_emits_valid_llvm() {
        for (opcode, mnemonic, output, inputs) in [
            (1, "COPY", 1, vec![1]),
            (11, "INT_EQUAL", 1, vec![8, 8]),
            (12, "INT_NOTEQUAL", 1, vec![8, 8]),
            (13, "INT_SLESS", 1, vec![8, 8]),
            (14, "INT_SLESSEQUAL", 1, vec![8, 8]),
            (15, "INT_LESS", 1, vec![8, 8]),
            (16, "INT_LESSEQUAL", 1, vec![8, 8]),
            (17, "INT_ZEXT", 8, vec![1]),
            (18, "INT_SEXT", 8, vec![1]),
            (19, "INT_ADD", 1, vec![1, 1]),
            (20, "INT_SUB", 1, vec![1, 1]),
            (21, "INT_CARRY", 1, vec![8, 8]),
            (22, "INT_SCARRY", 1, vec![8, 8]),
            (23, "INT_SBORROW", 1, vec![8, 8]),
            (24, "INT_2COMP", 1, vec![1]),
            (25, "INT_NEGATE", 1, vec![1]),
            (26, "INT_XOR", 1, vec![1, 1]),
            (27, "INT_AND", 1, vec![1, 1]),
            (28, "INT_OR", 1, vec![1, 1]),
            (29, "INT_LEFT", 1, vec![1, 8]),
            (30, "INT_RIGHT", 1, vec![1, 8]),
            (31, "INT_SRIGHT", 1, vec![1, 8]),
            (32, "INT_MULT", 1, vec![1, 1]),
            (33, "INT_DIV", 1, vec![1, 1]),
            (34, "INT_SDIV", 8, vec![8, 8]),
            (35, "INT_REM", 2, vec![2, 2]),
            (36, "INT_SREM", 4, vec![4, 4]),
            (37, "BOOL_NEGATE", 1, vec![1]),
            (38, "BOOL_XOR", 1, vec![1, 1]),
            (39, "BOOL_AND", 1, vec![1, 1]),
            (40, "BOOL_OR", 1, vec![1, 1]),
            (62, "PIECE", 8, vec![4, 4]),
            (63, "SUBPIECE", 4, vec![8, 1]),
            (72, "POPCOUNT", 1, vec![8]),
            (72, "POPCOUNT", 8, vec![1]),
            (73, "LZCOUNT", 1, vec![8]),
            (73, "LZCOUNT", 8, vec![1]),
        ] {
            let mut op = operation(opcode, mnemonic, output, &inputs);
            if opcode == 63 {
                op.source.inputs[1].space = "const".to_owned();
                op.source.inputs[1].offset = "0x2".to_owned();
            }
            let llvm = emit_pcode_exact_operation_llvm(&op).unwrap();
            let _ = run_opt(&llvm, &["-passes=verify", "-disable-output", "-"]);
        }
    }

    #[test]
    fn wide_bitvector_llvm_matches_concrete_pcode() {
        let cases: &[(u32, &str, u32, &[u32], &[u128])] = &[
            (
                1,
                "COPY",
                16,
                &[16],
                &[0xfedc_ba98_7654_3210_0123_4567_89ab_cdef],
            ),
            (17, "INT_ZEXT", 16, &[8], &[0xfedc_ba98_7654_3210]),
            (18, "INT_SEXT", 16, &[8], &[0xfedc_ba98_7654_3210]),
            (19, "INT_ADD", 16, &[16, 16], &[u128::MAX, 2]),
            (20, "INT_SUB", 16, &[16, 16], &[0, 1]),
            (24, "INT_2COMP", 16, &[16], &[1]),
            (25, "INT_NEGATE", 16, &[16], &[0]),
            (26, "INT_XOR", 16, &[16, 16], &[u128::MAX, 0x55]),
            (
                27,
                "INT_AND",
                16,
                &[16, 16],
                &[u128::MAX, 0x00ff_00ff_00ff_00ff_00ff_00ff_00ff_00ff],
            ),
            (30, "INT_RIGHT", 16, &[16, 1], &[u128::MAX, 65]),
            (30, "INT_RIGHT", 16, &[16, 1], &[u128::MAX, 128]),
            (29, "INT_LEFT", 16, &[16, 1], &[1, 127]),
            (31, "INT_SRIGHT", 16, &[16, 1], &[1u128 << 127, 128]),
            (28, "INT_OR", 16, &[16, 16], &[1u128 << 127, 1]),
            (32, "INT_MULT", 16, &[16, 16], &[u128::MAX, 2]),
            (11, "INT_EQUAL", 1, &[16, 16], &[u128::MAX, u128::MAX]),
            (12, "INT_NOTEQUAL", 1, &[16, 16], &[1u128 << 127, 0]),
            (13, "INT_SLESS", 1, &[16, 16], &[1u128 << 127, 0]),
            (
                14,
                "INT_SLESSEQUAL",
                1,
                &[16, 16],
                &[1u128 << 127, 1u128 << 127],
            ),
            (15, "INT_LESS", 1, &[16, 16], &[0, 1u128 << 127]),
            (16, "INT_LESSEQUAL", 1, &[16, 16], &[u128::MAX, u128::MAX]),
            (
                62,
                "PIECE",
                16,
                &[8, 8],
                &[0xfedc_ba98_7654_3210, 0x0123_4567_89ab_cdef],
            ),
            (
                63,
                "SUBPIECE",
                8,
                &[16, 1],
                &[0xfedc_ba98_7654_3210_0123_4567_89ab_cdef, 8],
            ),
        ];
        for &(opcode, mnemonic, output, inputs, values) in cases {
            let mut op = operation(opcode, mnemonic, output, inputs);
            if opcode == 63 {
                op.source.inputs[1].space = "const".to_owned();
                op.source.inputs[1].offset = "0x8".to_owned();
            }
            let expected = op.evaluate_exact_wide(values).unwrap().unwrap();
            let llvm = emit_pcode_exact_operation_llvm(&op).unwrap();
            let _ = run_opt(&llvm, &["-passes=verify", "-disable-output", "-"]);
            if Command::new("lli").arg("--version").output().is_err() {
                continue;
            }
            let arguments = op
                .source
                .inputs
                .iter()
                .enumerate()
                .filter_map(|(index, input)| {
                    (input.space != "const")
                        .then(|| format!("i{} {}", input.size * 8, values[index]))
                })
                .collect::<Vec<_>>()
                .join(", ");
            let bits = output * 8;
            let main = format!(
                "define i32 @main() {{\nentry:\n  %value = call i{bits} @hydir_pcode_exact({arguments})\n  %equal = icmp eq i{bits} %value, {expected}\n  %failed = xor i1 %equal, true\n  %status = zext i1 %failed to i32\n  ret i32 %status\n}}\n"
            );
            let file = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(file.path(), format!("{llvm}\n{main}")).unwrap();
            let result = Command::new("lli").arg(file.path()).output().unwrap();
            assert!(
                result.status.success(),
                "{mnemonic}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
    }

    #[test]
    fn rejects_opaque_and_forged_exact_operations() {
        let mut op = operation(19, "INT_ADD", 1, &[1, 1]);
        op.effect = PcodeEffect::Opaque {
            class: hydir_ir::pcode::PcodeOpaqueClass::Unknown,
            reason: "test".to_owned(),
            may_read_memory: true,
            may_write_memory: true,
            may_change_control: true,
            may_write_output: true,
        };
        assert!(emit_pcode_exact_operation_llvm(&op).is_err());
        op.effect = PcodeEffect::Assign {
            operation: PcodeExactOp::Add,
            result_width_bits: 8,
        };
        op.source.inputs[1].size = 8;
        assert!(emit_pcode_exact_operation_llvm(&op).is_err());
        op.source.inputs[1].size = 1;
        op.source.mnemonic = "INT_SUB".to_owned();
        assert!(emit_pcode_exact_operation_llvm(&op).is_err());
    }

    #[test]
    fn overshifts_guard_llvm_poison_and_preserve_sign() {
        for (opcode, mnemonic, expected) in [
            (29, "INT_LEFT", 0),
            (30, "INT_RIGHT", 0),
            (31, "INT_SRIGHT", 255),
        ] {
            let mut op = operation(opcode, mnemonic, 1, &[1, 8]);
            op.source.inputs[0].space = "const".to_owned();
            op.source.inputs[0].offset = "0x80".to_owned();
            op.source.inputs[1].space = "const".to_owned();
            op.source.inputs[1].offset = "0x100".to_owned();
            assert_eq!(op.evaluate_exact(&[0x80, 0x100]).unwrap(), Some(expected));
            if let Some(actual) = folded_return(&op) {
                assert_eq!(actual, expected);
            }
        }
    }

    #[test]
    fn division_llvm_matches_defined_inputs_and_totalizes_undefined_inputs_safely() {
        if Command::new("lli").arg("--version").output().is_err() {
            return;
        }
        let cases = [
            (33, "INT_DIV", 1, 0xff, 2, 0x7f),
            (35, "INT_REM", 1, 0xff, 2, 1),
            (34, "INT_SDIV", 1, 0xf9, 2, 0xfd),
            (36, "INT_SREM", 1, 0xf9, 2, 0xff),
            (34, "INT_SDIV", 2, 0x8001, 0xffff, 0x7fff),
            (36, "INT_SREM", 2, 0x8001, 0xffff, 0),
            (33, "INT_DIV", 4, 0xffff_ffff, 2, 0x7fff_ffff),
            (35, "INT_REM", 4, 0xffff_ffff, 2, 1),
            (34, "INT_SDIV", 8, (-7i64) as u64, 2, (-3i64) as u64),
            (36, "INT_SREM", 8, (-7i64) as u64, 2, u64::MAX),
            // Ghidra leaves zero divisors without a result. Standalone LLVM
            // totalizes them to zero; the stateful emitters stop beforehand.
            (33, "INT_DIV", 8, 17, 0, 0),
            (35, "INT_REM", 8, 17, 0, 0),
            (34, "INT_SDIV", 8, 17, 0, 0),
            (36, "INT_SREM", 8, 17, 0, 0),
            // LLVM sdiv/srem are poison for MIN / -1; the helper never
            // executes those operands and uses explicit fallback values.
            (
                34,
                "INT_SDIV",
                8,
                i64::MIN as u64,
                u64::MAX,
                i64::MIN as u64,
            ),
            (36, "INT_SREM", 8, i64::MIN as u64, u64::MAX, 0),
        ];
        for (opcode, mnemonic, width, left, right, expected) in cases {
            let op = operation(opcode, mnemonic, width, &[width, width]);
            let llvm = emit_pcode_exact_operation_llvm(&op).unwrap();
            let _ = run_opt(&llvm, &["-passes=verify", "-disable-output", "-"]);
            let bits = width * 8;
            let main = format!(
                "define i32 @main() {{\nentry:\n  %value = call i{bits} @hydir_pcode_exact(i{bits} {left}, i{bits} {right})\n  %equal = icmp eq i{bits} %value, {expected}\n  %failed = xor i1 %equal, true\n  %status = zext i1 %failed to i32\n  ret i32 %status\n}}\n"
            );
            let file = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(file.path(), format!("{llvm}\n{main}")).unwrap();
            let result = Command::new("lli").arg(file.path()).output().unwrap();
            assert!(
                result.status.success(),
                "{mnemonic} width {width} {left:#x} / {right:#x}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
        }

        let mut zero_constant = operation(33, "INT_DIV", 1, &[1, 1]);
        zero_constant.source.inputs[1].space = "const".to_owned();
        zero_constant.source.inputs[1].offset = "0x0".to_owned();
        assert!(
            emit_pcode_exact_operation_llvm(&zero_constant)
                .unwrap_err()
                .contains("zero")
        );
    }

    #[test]
    fn linear_prefix_stops_before_undefined_division() {
        let bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/ghidra_prism_bit_prefix_v2.json"
        ));
        let digest = "4b3d29186ad32957cd12f1f4b581f3cad544903f0c4da152603394cc45ee3bb0";
        let mut snapshot = hydir_ir::pcode::parse_ghidra_snapshot(bytes, digest).unwrap();
        let source = &mut snapshot.selected_function.instructions[0].pcode[0];
        source.mnemonic = "INT_SDIV".to_owned();
        source.opcode = 34;
        source.inputs = vec![
            PcodeVarnode {
                space: "register".to_owned(),
                offset: "0x38".to_owned(),
                size: 8,
            },
            PcodeVarnode {
                space: "register".to_owned(),
                offset: "0x30".to_owned(),
                size: 8,
            },
        ];
        let dynamic = emit_pcode_linear_prefix_llvm(&snapshot).unwrap();
        assert!(dynamic.llvm_ir.contains("division_stop_0"));
        assert!(dynamic.llvm_ir.contains("%division_overflow_0"));
        assert!(
            dynamic
                .state_abi
                .contains("number of completed source operations")
        );
        let _ = run_opt(
            &dynamic.llvm_ir,
            &["-passes=verify", "-disable-output", "-"],
        );

        snapshot.selected_function.instructions[0].pcode[0].inputs[1] = PcodeVarnode {
            space: "const".to_owned(),
            offset: "0x0".to_owned(),
            size: 8,
        };
        let static_zero = emit_pcode_linear_prefix_llvm(&snapshot).unwrap();
        assert_eq!(static_zero.emitted_operations, 0);
        assert!(static_zero.stop_reason.contains("zero"));
        assert_eq!(
            static_zero.stopped_at,
            Some(snapshot.selected_function.entry.clone())
        );
        let _ = run_opt(
            &static_zero.llvm_ir,
            &["-passes=verify", "-disable-output", "-"],
        );
    }

    #[test]
    fn optimized_llvm_matches_exact_evaluator_on_representative_values() {
        let cases: &[(u32, &str, u32, &[u32], &[u64])] = &[
            (1, "COPY", 1, &[1], &[0xff]),
            (11, "INT_EQUAL", 1, &[1, 1], &[0x80, 0x80]),
            (12, "INT_NOTEQUAL", 1, &[1, 1], &[0x80, 0x7f]),
            (13, "INT_SLESS", 1, &[1, 1], &[0x80, 1]),
            (14, "INT_SLESSEQUAL", 1, &[1, 1], &[0x80, 0x80]),
            (15, "INT_LESS", 1, &[1, 1], &[0x80, 1]),
            (16, "INT_LESSEQUAL", 1, &[1, 1], &[0x80, 0x80]),
            (17, "INT_ZEXT", 8, &[1], &[0x80]),
            (18, "INT_SEXT", 8, &[1], &[0x80]),
            (19, "INT_ADD", 1, &[1, 1], &[0xff, 2]),
            (20, "INT_SUB", 1, &[1, 1], &[0, 1]),
            (21, "INT_CARRY", 1, &[1, 1], &[0xff, 1]),
            (22, "INT_SCARRY", 1, &[1, 1], &[0x7f, 1]),
            (23, "INT_SBORROW", 1, &[1, 1], &[0x80, 1]),
            (22, "INT_SCARRY", 1, &[8, 8], &[i64::MAX as u64, 1]),
            (23, "INT_SBORROW", 1, &[8, 8], &[i64::MIN as u64, 1]),
            (24, "INT_2COMP", 1, &[1], &[0x80]),
            (25, "INT_NEGATE", 1, &[1], &[0x80]),
            (26, "INT_XOR", 1, &[1, 1], &[0xf0, 0x0f]),
            (27, "INT_AND", 1, &[1, 1], &[0xf0, 0x0f]),
            (28, "INT_OR", 1, &[1, 1], &[0xf0, 0x0f]),
            (29, "INT_LEFT", 1, &[1, 8], &[3, 2]),
            (30, "INT_RIGHT", 1, &[1, 8], &[0x80, 2]),
            (31, "INT_SRIGHT", 1, &[1, 8], &[0x80, 2]),
            (31, "INT_SRIGHT", 1, &[1, 8], &[0x7f, 8]),
            (32, "INT_MULT", 1, &[1, 1], &[0x80, 3]),
            (33, "INT_DIV", 1, &[1, 1], &[0xff, 2]),
            (35, "INT_REM", 2, &[2, 2], &[0xffff, 3]),
            (34, "INT_SDIV", 1, &[1, 1], &[0xf9, 2]),
            (36, "INT_SREM", 1, &[1, 1], &[0xf9, 2]),
            (34, "INT_SDIV", 8, &[8, 8], &[(-7i64) as u64, 2]),
            (36, "INT_SREM", 8, &[8, 8], &[(-7i64) as u64, 2]),
            (37, "BOOL_NEGATE", 1, &[1], &[0]),
            (37, "BOOL_NEGATE", 1, &[1], &[1]),
            (37, "BOOL_NEGATE", 1, &[1], &[2]),
            (38, "BOOL_XOR", 1, &[1, 1], &[1, 0]),
            (38, "BOOL_XOR", 1, &[1, 1], &[2, 1]),
            (39, "BOOL_AND", 1, &[1, 1], &[2, 1]),
            (39, "BOOL_AND", 1, &[1, 1], &[2, 0]),
            (40, "BOOL_OR", 1, &[1, 1], &[0, 2]),
            (40, "BOOL_OR", 1, &[1, 1], &[0, 0]),
            (62, "PIECE", 8, &[4, 4], &[0x1122_3344, 0x5566_7788]),
            (63, "SUBPIECE", 4, &[8, 1], &[0x1122_3344_5566_7788, 2]),
            (63, "SUBPIECE", 1, &[8, 1], &[0x1122_3344_5566_7788, 7]),
            (29, "INT_LEFT", 1, &[1, 8], &[3, 0x100]),
            (72, "POPCOUNT", 1, &[8], &[u64::MAX]),
            (72, "POPCOUNT", 8, &[1], &[0x81]),
            (72, "POPCOUNT", 1, &[8], &[0]),
            (73, "LZCOUNT", 1, &[1], &[0]),
            (73, "LZCOUNT", 8, &[1], &[1]),
            (73, "LZCOUNT", 1, &[3], &[0x80_0000]),
            (73, "LZCOUNT", 1, &[8], &[0]),
            (73, "LZCOUNT", 8, &[8], &[1]),
        ];
        for &(opcode, mnemonic, output, inputs, values) in cases {
            let mut op = operation(opcode, mnemonic, output, inputs);
            for (input, &value) in op.source.inputs.iter_mut().zip(values) {
                input.space = "const".to_owned();
                input.offset = format!("0x{value:x}");
            }
            let expected = op.evaluate_exact(values).unwrap().unwrap();
            if let Some(actual) = folded_return(&op) {
                assert_eq!(actual, expected, "{mnemonic} {values:?}");
            }
        }
    }

    #[test]
    fn real_ghidra_prefix_includes_popcount_and_stops_at_branch() {
        let bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/ghidra_prism_bit_prefix_v2.json"
        ));
        let digest = "4b3d29186ad32957cd12f1f4b581f3cad544903f0c4da152603394cc45ee3bb0";
        let snapshot = hydir_ir::pcode::parse_ghidra_snapshot(bytes, digest).unwrap();
        let artifact = emit_pcode_linear_prefix_llvm(&snapshot).unwrap();
        assert_eq!(artifact.binary_sha256, digest);
        assert_eq!(artifact.emitted_operations, 10);
        assert_eq!(artifact.stopped_at.as_ref().unwrap().offset, "0x2013d9");
        assert!(artifact.stop_reason.contains("opaque CBRANCH"));
        assert!(
            artifact
                .source_operations
                .iter()
                .any(|operation| operation.mnemonic == "POPCOUNT")
        );
        assert_eq!(artifact.semantic_fidelity, SemanticFidelity::Unknown);
        assert_eq!(artifact.verification, VerificationStatus::NotRun);
        assert_eq!(artifact.source_operations[0].address.offset, "0x2013cf");
        assert!(artifact.llvm_ir.contains("@hydir_read_varnode"));
        let _ = run_opt(
            &artifact.llvm_ir,
            &["-passes=verify", "-disable-output", "-"],
        );
    }
}
