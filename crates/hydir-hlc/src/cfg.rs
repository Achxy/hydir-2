//! A bounded CFG form of typed C. It deliberately admits only operations
//! whose scalar behavior can be expressed without an opaque machine state.
//! Each branch retains its recovered target and instruction site.

use crate::{BinaryOp, HighExpr, HighParameter, parameters, u64_type, valid_ident};
use hydir_core::Location;
use hydir_ir::{
    FunctionIr, MachineControlEffect, MachineEdgeKind, MachineFunctionIr, MachineInstruction,
    MachineMemoryEffect, MachineOperand, MachineOperation, SemanticFidelity,
    StructuralCompleteness, validate_function_ir, validate_machine_function_ir,
};
use hydir_model::{AnalysisModel, TypeRef, validate_structure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub const HIGH_LEVEL_CFG_CIR_VERSION: u32 = 2;
// Caller-saved GPRs only. Callee-saved state and the stack need separate ABI
// proofs before this C view can claim to preserve them.
const REGISTERS: [&str; 9] = ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"];
const FLAG_LEFT: &str = "hydir_flag_left";
const FLAG_RIGHT: &str = "hydir_flag_right";
mod structure;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HighCfgCompareOp {
    Equal,
    NotEqual,
    UnsignedLess,
    UnsignedLessEqual,
    UnsignedGreater,
    UnsignedGreaterEqual,
    SignedLess,
    SignedLessEqual,
    SignedGreater,
    SignedGreaterEqual,
    TestZero,
    TestNonzero,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HighCfgPredicate {
    pub op: HighCfgCompareOp,
    pub left: HighExpr,
    pub right: HighExpr,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HighCfgStatement {
    pub target: String,
    pub value: HighExpr,
    pub site: Location,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HighCfgTerminator {
    Goto {
        target: Location,
        site: Location,
    },
    Branch {
        predicate: HighCfgPredicate,
        taken: Location,
        fallthrough: Location,
        site: Location,
    },
    Return {
        value: HighExpr,
        site: Location,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HighCfgBlock {
    pub address: Location,
    pub statements: Vec<HighCfgStatement>,
    pub terminator: HighCfgTerminator,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HighLevelCfgCir {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub model_revision: u64,
    pub function_id: String,
    pub entry: Location,
    pub name: String,
    pub parameters: Vec<HighParameter>,
    pub return_type: TypeRef,
    pub blocks: Vec<HighCfgBlock>,
    pub structural_completeness: StructuralCompleteness,
    pub semantic_fidelity: SemanticFidelity,
    pub rewrite_ready: bool,
}

fn local(name: &str) -> Result<String, String> {
    if REGISTERS.contains(&name) {
        Ok(format!("hydir_{name}"))
    } else {
        Err(format!("typed CFG register {name} is unsupported"))
    }
}

fn register(operand: &MachineOperand) -> Result<String, String> {
    match operand {
        MachineOperand::Register {
            name,
            width_bits: 64,
        } => local(name),
        _ => Err("typed CFG requires a 64-bit GPR operand".to_owned()),
    }
}

fn value(operand: &MachineOperand) -> Result<HighExpr, String> {
    match operand {
        MachineOperand::Register { .. } => Ok(HighExpr::Variable {
            name: register(operand)?,
        }),
        MachineOperand::Immediate {
            value,
            width_bits: 64,
        } => Ok(HighExpr::Constant { value: *value }),
        _ => Err("typed CFG requires a 64-bit register or normalized immediate".to_owned()),
    }
}

fn edge(instruction: &MachineInstruction, kind: MachineEdgeKind) -> Result<Location, String> {
    let mut matching = instruction.edges.iter().filter(|edge| edge.kind == kind);
    let result = matching
        .next()
        .and_then(|edge| edge.target)
        .ok_or("typed CFG edge target is unresolved")?;
    if matching.next().is_some() {
        return Err("typed CFG has duplicate control edges".to_owned());
    }
    Ok(result)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FlagSource {
    Compare,
    Test,
}

fn flag_transfer(
    instruction: &MachineInstruction,
    incoming: Option<FlagSource>,
) -> Option<FlagSource> {
    let MachineOperation::Exact { family } = &instruction.operation else {
        return None;
    };
    match family.as_str() {
        "cmp" => Some(FlagSource::Compare),
        "test" => Some(FlagSource::Test),
        "add" | "sub" | "xor" | "and" | "or" => None,
        _ => incoming,
    }
}

fn flag_inputs(
    machine: &MachineFunctionIr,
) -> Result<BTreeMap<Location, Option<FlagSource>>, String> {
    let blocks = machine
        .blocks
        .iter()
        .map(|block| (block.address, block))
        .collect::<BTreeMap<_, _>>();
    let mut predecessors = BTreeMap::<Location, Vec<Location>>::new();
    for block in &machine.blocks {
        let last = block
            .instructions
            .last()
            .ok_or("typed CFG block is empty")?;
        for target in last.edges.iter().filter_map(|edge| edge.target) {
            if blocks.contains_key(&target) {
                predecessors.entry(target).or_default().push(block.address);
            }
        }
    }
    let mut input = blocks
        .keys()
        .map(|address| (*address, None))
        .collect::<BTreeMap<_, _>>();
    let mut output = input.clone();
    for _ in 0..(blocks.len() * 4 + 1) {
        let mut changed = false;
        for block in &machine.blocks {
            let incoming = if block.address == machine.entry {
                None
            } else {
                let preds = predecessors
                    .get(&block.address)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                let first = preds
                    .first()
                    .and_then(|pred| output.get(pred))
                    .copied()
                    .flatten();
                if first.is_some() && preds.iter().all(|pred| output.get(pred) == Some(&first)) {
                    first
                } else {
                    None
                }
            };
            let mut outgoing = incoming;
            for instruction in &block.instructions {
                outgoing = flag_transfer(instruction, outgoing);
            }
            changed |= input.insert(block.address, incoming) != Some(incoming);
            changed |= output.insert(block.address, outgoing) != Some(outgoing);
        }
        if !changed {
            return Ok(input);
        }
    }
    Err("typed CFG flag provenance did not converge".to_owned())
}

fn predicate(family: &str, source: Option<FlagSource>) -> Result<HighCfgPredicate, String> {
    let op = match (source, family) {
        (Some(FlagSource::Compare), "je" | "jz") => HighCfgCompareOp::Equal,
        (Some(FlagSource::Compare), "jne" | "jnz") => HighCfgCompareOp::NotEqual,
        (Some(FlagSource::Compare), "jb" | "jc" | "jnae") => HighCfgCompareOp::UnsignedLess,
        (Some(FlagSource::Compare), "jbe" | "jna") => HighCfgCompareOp::UnsignedLessEqual,
        (Some(FlagSource::Compare), "ja" | "jnbe") => HighCfgCompareOp::UnsignedGreater,
        (Some(FlagSource::Compare), "jae" | "jnb" | "jnc") => {
            HighCfgCompareOp::UnsignedGreaterEqual
        }
        (Some(FlagSource::Compare), "jl" | "jnge") => HighCfgCompareOp::SignedLess,
        (Some(FlagSource::Compare), "jle" | "jng") => HighCfgCompareOp::SignedLessEqual,
        (Some(FlagSource::Compare), "jg" | "jnle") => HighCfgCompareOp::SignedGreater,
        (Some(FlagSource::Compare), "jge" | "jnl") => HighCfgCompareOp::SignedGreaterEqual,
        (Some(FlagSource::Test), "je" | "jz") => HighCfgCompareOp::TestZero,
        (Some(FlagSource::Test), "jne" | "jnz") => HighCfgCompareOp::TestNonzero,
        _ => {
            return Err(format!(
                "typed CFG has no supported flag proof for {family}"
            ));
        }
    };
    Ok(HighCfgPredicate {
        op,
        left: HighExpr::Variable {
            name: FLAG_LEFT.to_owned(),
        },
        right: HighExpr::Variable {
            name: FLAG_RIGHT.to_owned(),
        },
    })
}

fn lower_instruction(
    instruction: &MachineInstruction,
    flag_source: &mut Option<FlagSource>,
    statements: &mut Vec<HighCfgStatement>,
) -> Result<Option<HighCfgTerminator>, String> {
    let MachineOperation::Exact { family } = &instruction.operation else {
        return Err("typed CFG cannot lower an opaque operation".to_owned());
    };
    if instruction.effects.conservative
        || instruction.decorators != Default::default()
        || (instruction.effects.memory != MachineMemoryEffect::None
            && !(family == "ret" && instruction.effects.memory == MachineMemoryEffect::Read))
    {
        return Err(format!(
            "typed CFG effect at 0x{:x} is unsupported",
            instruction.address.value.0
        ));
    }
    let site = instruction.address;
    let operands = instruction.operands.as_slice();
    let mut assign = |target: String, value: HighExpr| {
        statements.push(HighCfgStatement {
            target,
            value,
            site,
        });
    };
    let terminator = match (family.as_str(), operands) {
        ("mov", [destination, source])
            if instruction.effects.control == MachineControlEffect::Next =>
        {
            assign(register(destination)?, value(source)?);
            None
        }
        ("add" | "sub" | "xor" | "and" | "or", [destination, source])
            if instruction.effects.control == MachineControlEffect::Next =>
        {
            let target = register(destination)?;
            let right = value(source)?;
            let op = match family.as_str() {
                "add" => BinaryOp::Add,
                "sub" => BinaryOp::Sub,
                "xor" => BinaryOp::Xor,
                "and" => BinaryOp::And,
                _ => BinaryOp::Or,
            };
            let expression = if op == BinaryOp::Xor
                && matches!(&right, HighExpr::Variable { name } if name == &target)
            {
                HighExpr::Constant { value: 0 }
            } else {
                HighExpr::Binary {
                    op,
                    left: Box::new(HighExpr::Variable {
                        name: target.clone(),
                    }),
                    right: Box::new(right),
                }
            };
            assign(target, expression);
            *flag_source = None;
            None
        }
        ("cmp" | "test", [left, right])
            if instruction.effects.control == MachineControlEffect::Next =>
        {
            // Snapshot operands now: later register writes must not alter the flags.
            assign(FLAG_LEFT.to_owned(), value(left)?);
            assign(FLAG_RIGHT.to_owned(), value(right)?);
            *flag_source = Some(if family == "cmp" {
                FlagSource::Compare
            } else {
                FlagSource::Test
            });
            None
        }
        ("nop" | "endbr64", []) if instruction.effects.control == MachineControlEffect::Next => {
            None
        }
        ("ret", []) if instruction.effects.control == MachineControlEffect::Return => {
            Some(HighCfgTerminator::Return {
                value: HighExpr::Variable {
                    name: "hydir_rax".to_owned(),
                },
                site,
            })
        }
        ("jmp", [MachineOperand::Branch { target }])
            if instruction.effects.control == MachineControlEffect::DirectBranch =>
        {
            let direct = edge(instruction, MachineEdgeKind::Direct)?;
            if direct != *target || instruction.edges.len() != 1 {
                return Err("typed CFG jump operand and edge disagree".to_owned());
            }
            Some(HighCfgTerminator::Goto {
                target: direct,
                site,
            })
        }
        (family, [MachineOperand::Branch { target }])
            if instruction.effects.control == MachineControlEffect::ConditionalBranch =>
        {
            let taken = edge(instruction, MachineEdgeKind::Taken)?;
            let fallthrough = edge(instruction, MachineEdgeKind::Fallthrough)?;
            if taken != *target || instruction.edges.len() != 2 {
                return Err("typed CFG branch operand and edges disagree".to_owned());
            }
            Some(HighCfgTerminator::Branch {
                predicate: predicate(family, *flag_source)?,
                taken,
                fallthrough,
                site,
            })
        }
        _ => {
            return Err(format!(
                "typed CFG operation {family} at 0x{:x} is unsupported",
                site.value.0
            ));
        }
    };
    Ok(terminator)
}

/// Lower exact, memory-free 64-bit SysV scalar flow. Unsupported operations
/// reject the typed CFG view; the existing low-level view remains available.
pub fn lower_high_level_cfg_cir(
    machine: &MachineFunctionIr,
    function: &FunctionIr,
    model: &AnalysisModel,
) -> Result<HighLevelCfgCir, String> {
    validate_structure(model)?;
    validate_machine_function_ir(machine)?;
    validate_function_ir(function)?;
    if machine.binary_sha256 != model.binary_sha256
        || function.binary_sha256 != model.binary_sha256
        || machine.entry != function.entry
        || machine.function_id != function.function_id
        || machine.structural_completeness != StructuralCompleteness::Complete
        || machine.semantic_fidelity != SemanticFidelity::ExactUnderModel
        || machine.blocks.is_empty()
        || machine.blocks.len() > 4096
    {
        return Err("typed CFG requires a complete, exact, model-bound function".to_owned());
    }
    let model_row = model
        .functions
        .iter()
        .find(|row| row.entry == machine.entry);
    if model_row
        .and_then(|row| row.prototype.as_ref())
        .is_some_and(|prototype| prototype.calling_convention != "sysv_amd64")
    {
        return Err("typed CFG requires a SysV AMD64 prototype".to_owned());
    }
    let parameters = parameters(model_row, function)?;
    if parameters
        .iter()
        .any(|parameter| parameter.ty != u64_type())
    {
        return Err("typed CFG currently requires uint64_t parameters".to_owned());
    }
    let return_type = model_row
        .and_then(|row| row.prototype.as_ref())
        .map(|prototype| prototype.return_type.clone())
        .unwrap_or_else(u64_type);
    if return_type != u64_type() {
        return Err("typed CFG currently requires a uint64_t return".to_owned());
    }
    let name = model_row
        .map(|row| row.name.as_str())
        .filter(|name| valid_ident(name))
        .map(str::to_owned)
        .unwrap_or_else(|| {
            format!(
                "hydir_typed_{}_{:x}",
                machine.entry.address_space, machine.entry.value.0
            )
        });
    let flag_input = flag_inputs(machine)?;
    let mut blocks = Vec::with_capacity(machine.blocks.len());
    for block in &machine.blocks {
        let mut statements = Vec::new();
        let mut flag_source = *flag_input
            .get(&block.address)
            .ok_or("typed CFG block flag state is missing")?;
        let mut terminator = None;
        for (index, instruction) in block.instructions.iter().enumerate() {
            if terminator.is_some() {
                return Err("typed CFG has instructions after a control transfer".to_owned());
            }
            terminator = lower_instruction(instruction, &mut flag_source, &mut statements)?;
            if terminator.is_some() && index + 1 != block.instructions.len() {
                return Err("typed CFG has an internal control transfer".to_owned());
            }
        }
        let last = block
            .instructions
            .last()
            .ok_or("typed CFG block is empty")?;
        let terminator = match terminator {
            Some(terminator) => terminator,
            None if last.effects.control == MachineControlEffect::Next && last.edges.len() == 1 => {
                HighCfgTerminator::Goto {
                    target: edge(last, MachineEdgeKind::Fallthrough)?,
                    site: last.address,
                }
            }
            _ => return Err("typed CFG block has no resolved terminator".to_owned()),
        };
        blocks.push(HighCfgBlock {
            address: block.address,
            statements,
            terminator,
        });
    }
    let result = HighLevelCfgCir {
        schema_version: HIGH_LEVEL_CFG_CIR_VERSION,
        binary_sha256: machine.binary_sha256.clone(),
        model_revision: model.revision,
        function_id: machine.function_id.clone(),
        entry: machine.entry,
        name,
        parameters,
        return_type,
        blocks,
        structural_completeness: StructuralCompleteness::Complete,
        semantic_fidelity: SemanticFidelity::Conservative,
        rewrite_ready: false,
    };
    validate_high_level_cfg_cir(&result)?;
    Ok(result)
}

fn scalar_reads(
    expr: &HighExpr,
    output: &mut BTreeSet<String>,
    depth: usize,
) -> Result<(), String> {
    if depth > 64 {
        return Err("typed CFG expression depth exceeds 64".to_owned());
    }
    match expr {
        HighExpr::Variable { name } => {
            if !valid_local(name) {
                return Err(format!(
                    "typed CFG variable {name} is not a scalar register"
                ));
            }
            output.insert(name.clone());
        }
        HighExpr::Constant { .. } => {}
        HighExpr::Binary { left, right, .. } => {
            scalar_reads(left, output, depth + 1)?;
            scalar_reads(right, output, depth + 1)?;
        }
        HighExpr::Field { .. } | HighExpr::Call { .. } => {
            return Err("typed CFG cannot contain a field or call expression".to_owned());
        }
    }
    Ok(())
}

fn valid_local(name: &str) -> bool {
    name == FLAG_LEFT
        || name == FLAG_RIGHT
        || REGISTERS
            .iter()
            .any(|register| name == format!("hydir_{register}"))
}

fn successors(terminator: &HighCfgTerminator) -> Vec<Location> {
    match terminator {
        HighCfgTerminator::Goto { target, .. } => vec![*target],
        HighCfgTerminator::Branch {
            taken, fallthrough, ..
        } => vec![*taken, *fallthrough],
        HighCfgTerminator::Return { .. } => Vec::new(),
    }
}

fn expression_is_initialized(
    expr: &HighExpr,
    initialized: &BTreeSet<String>,
) -> Result<(), String> {
    let mut reads = BTreeSet::new();
    scalar_reads(expr, &mut reads, 0)?;
    if let Some(name) = reads.difference(initialized).next() {
        return Err(format!(
            "typed CFG reads {name} before assignment on some path"
        ));
    }
    Ok(())
}

pub fn validate_high_level_cfg_cir(ir: &HighLevelCfgCir) -> Result<(), String> {
    if ir.schema_version != HIGH_LEVEL_CFG_CIR_VERSION
        || ir.binary_sha256.len() != 64
        || !ir
            .binary_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || ir.model_revision == 0
        || ir.function_id.is_empty()
        || !valid_ident(&ir.name)
        || ir.return_type != u64_type()
        || ir.structural_completeness != StructuralCompleteness::Complete
        || ir.semantic_fidelity != SemanticFidelity::Conservative
        || ir.rewrite_ready
    {
        return Err("invalid typed CFG identity, scope, or version".to_owned());
    }
    if ir.parameters.len() > 6 || ir.blocks.is_empty() || ir.blocks.len() > 4096 {
        return Err("typed CFG parameter/block limit exceeded".to_owned());
    }
    let mut initial = BTreeSet::new();
    let mut parameter_names = BTreeSet::new();
    for parameter in &ir.parameters {
        if parameter.ty != u64_type()
            || !valid_ident(&parameter.name)
            || valid_local(&parameter.name)
            || !parameter_names.insert(parameter.name.clone())
            || !REGISTERS.contains(&parameter.location.as_str())
            || !initial.insert(local(&parameter.location)?)
        {
            return Err("typed CFG has an invalid or duplicate parameter".to_owned());
        }
    }
    let mut blocks = BTreeMap::new();
    let mut statement_count = 0usize;
    for block in &ir.blocks {
        if block.address.address_space != ir.entry.address_space {
            return Err("typed CFG block address space differs from entry".to_owned());
        }
        if blocks.insert(block.address, block).is_some() {
            return Err("typed CFG has duplicate block addresses".to_owned());
        }
        statement_count += block.statements.len();
        if statement_count > 16_384 {
            return Err("typed CFG statement limit exceeded".to_owned());
        }
        for statement in &block.statements {
            if statement.site.address_space != ir.entry.address_space
                || statement.site.value.0 < block.address.value.0
            {
                return Err("typed CFG assignment site differs from its block".to_owned());
            }
            if !valid_local(&statement.target) {
                return Err("typed CFG has an invalid assignment target".to_owned());
            }
            scalar_reads(&statement.value, &mut BTreeSet::new(), 0)?;
        }
        match &block.terminator {
            HighCfgTerminator::Branch {
                predicate,
                taken,
                fallthrough,
                site,
            } => {
                if site.address_space != ir.entry.address_space
                    || site.value.0 < block.address.value.0
                {
                    return Err("typed CFG branch site differs from its block".to_owned());
                }
                if taken == fallthrough {
                    return Err("typed CFG branch has identical successors".to_owned());
                }
                scalar_reads(&predicate.left, &mut BTreeSet::new(), 0)?;
                scalar_reads(&predicate.right, &mut BTreeSet::new(), 0)?;
            }
            HighCfgTerminator::Return { value, site } => {
                if site.address_space != ir.entry.address_space
                    || site.value.0 < block.address.value.0
                {
                    return Err("typed CFG return site differs from its block".to_owned());
                }
                scalar_reads(value, &mut BTreeSet::new(), 0)?;
            }
            HighCfgTerminator::Goto { site, .. } => {
                if site.address_space != ir.entry.address_space
                    || site.value.0 < block.address.value.0
                {
                    return Err("typed CFG goto site differs from its block".to_owned());
                }
            }
        }
    }
    if !blocks.contains_key(&ir.entry) {
        return Err("typed CFG entry block is missing".to_owned());
    }
    let mut predecessors = BTreeMap::<Location, Vec<Location>>::new();
    for block in &ir.blocks {
        for successor in successors(&block.terminator) {
            if !blocks.contains_key(&successor) {
                return Err("typed CFG successor is missing".to_owned());
            }
            predecessors
                .entry(successor)
                .or_default()
                .push(block.address);
        }
    }
    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::from([ir.entry]);
    while let Some(address) = queue.pop_front() {
        if seen.insert(address) {
            queue.extend(successors(&blocks[&address].terminator));
        }
    }
    if seen.len() != blocks.len() {
        return Err("typed CFG contains unreachable blocks".to_owned());
    }
    if !ir
        .blocks
        .iter()
        .any(|block| matches!(block.terminator, HighCfgTerminator::Return { .. }))
    {
        return Err("typed CFG has no recovered return".to_owned());
    }
    let universe = REGISTERS
        .iter()
        .map(|register| format!("hydir_{register}"))
        .chain([FLAG_LEFT.to_owned(), FLAG_RIGHT.to_owned()])
        .collect::<BTreeSet<_>>();
    let mut inputs = blocks
        .keys()
        .map(|address| (*address, universe.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut outputs = inputs.clone();
    inputs.insert(ir.entry, initial.clone());
    let mut converged = false;
    for _ in 0..(blocks.len() * universe.len() + 1) {
        let mut changed = false;
        for block in &ir.blocks {
            let incoming = if block.address == ir.entry {
                initial.clone()
            } else {
                let preds = &predecessors[&block.address];
                let mut incoming = universe.clone();
                for predecessor in preds {
                    incoming = incoming
                        .intersection(&outputs[predecessor])
                        .cloned()
                        .collect();
                }
                incoming
            };
            let mut outgoing = incoming.clone();
            outgoing.extend(
                block
                    .statements
                    .iter()
                    .map(|statement| statement.target.clone()),
            );
            changed |= inputs.insert(block.address, incoming.clone()) != Some(incoming);
            changed |= outputs.insert(block.address, outgoing.clone()) != Some(outgoing);
        }
        if !changed {
            converged = true;
            break;
        }
    }
    if !converged {
        return Err("typed CFG definite-assignment analysis did not converge".to_owned());
    }
    for block in &ir.blocks {
        let mut initialized = inputs[&block.address].clone();
        for statement in &block.statements {
            expression_is_initialized(&statement.value, &initialized)?;
            initialized.insert(statement.target.clone());
        }
        match &block.terminator {
            HighCfgTerminator::Branch { predicate, .. } => {
                expression_is_initialized(&predicate.left, &initialized)?;
                expression_is_initialized(&predicate.right, &initialized)?;
            }
            HighCfgTerminator::Return { value, .. } => {
                expression_is_initialized(value, &initialized)?
            }
            HighCfgTerminator::Goto { .. } => {}
        }
    }
    Ok(())
}

fn c_expr(expr: &HighExpr) -> String {
    match expr {
        HighExpr::Variable { name } => name.clone(),
        HighExpr::Constant { value } => format!("UINT64_C({value})"),
        HighExpr::Binary { op, left, right } => {
            let op = match op {
                BinaryOp::Add => "+",
                BinaryOp::Sub => "-",
                BinaryOp::Xor => "^",
                BinaryOp::And => "&",
                BinaryOp::Or => "|",
            };
            format!("({} {op} {})", c_expr(left), c_expr(right))
        }
        HighExpr::Field { .. } | HighExpr::Call { .. } => {
            unreachable!("validated scalar expression")
        }
    }
}

fn c_predicate(predicate: &HighCfgPredicate) -> String {
    let left = c_expr(&predicate.left);
    let right = c_expr(&predicate.right);
    let (left, right, op) = match predicate.op {
        HighCfgCompareOp::Equal => (left, right, "=="),
        HighCfgCompareOp::NotEqual => (left, right, "!="),
        HighCfgCompareOp::UnsignedLess => (left, right, "<"),
        HighCfgCompareOp::UnsignedLessEqual => (left, right, "<="),
        HighCfgCompareOp::UnsignedGreater => (left, right, ">"),
        HighCfgCompareOp::UnsignedGreaterEqual => (left, right, ">="),
        HighCfgCompareOp::SignedLess => (
            format!("({left} ^ UINT64_C(0x8000000000000000))"),
            format!("({right} ^ UINT64_C(0x8000000000000000))"),
            "<",
        ),
        HighCfgCompareOp::SignedLessEqual => (
            format!("({left} ^ UINT64_C(0x8000000000000000))"),
            format!("({right} ^ UINT64_C(0x8000000000000000))"),
            "<=",
        ),
        HighCfgCompareOp::SignedGreater => (
            format!("({left} ^ UINT64_C(0x8000000000000000))"),
            format!("({right} ^ UINT64_C(0x8000000000000000))"),
            ">",
        ),
        HighCfgCompareOp::SignedGreaterEqual => (
            format!("({left} ^ UINT64_C(0x8000000000000000))"),
            format!("({right} ^ UINT64_C(0x8000000000000000))"),
            ">=",
        ),
        HighCfgCompareOp::TestZero => (
            format!("({left} & {right})"),
            "UINT64_C(0)".to_owned(),
            "==",
        ),
        HighCfgCompareOp::TestNonzero => (
            format!("({left} & {right})"),
            "UINT64_C(0)".to_owned(),
            "!=",
        ),
    };
    format!("({left} {op} {right})")
}

fn c_label(address: Location) -> String {
    format!("hydir_bb_{}_{:x}", address.address_space, address.value.0)
}

/// Emit strict C11 for the bounded scalar CFG. Gotos preserve loops and joins
/// exactly; a later structuring pass may replace them when it can prove shape.
pub fn emit_typed_cfg_c(ir: &HighLevelCfgCir, model: &AnalysisModel) -> Result<String, String> {
    validate_structure(model)?;
    validate_high_level_cfg_cir(ir)?;
    if ir.binary_sha256 != model.binary_sha256 || ir.model_revision != model.revision {
        return Err("typed CFG model identity/revision differs".to_owned());
    }
    let body = structure::emit_body(ir);
    let mut output = String::from("#include <stdint.h>\n\n");
    output.push_str(&format!("uint64_t {}(", ir.name));
    if ir.parameters.is_empty() {
        output.push_str("void");
    }
    for (index, parameter) in ir.parameters.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        output.push_str(&format!("uint64_t {}", parameter.name));
    }
    output.push_str(") {\n");
    let mut used = BTreeSet::new();
    for parameter in &ir.parameters {
        used.insert(local(&parameter.location)?);
    }
    let mut reads = BTreeSet::new();
    for block in &ir.blocks {
        for statement in &block.statements {
            used.insert(statement.target.clone());
            scalar_reads(&statement.value, &mut reads, 0)?;
        }
        match &block.terminator {
            HighCfgTerminator::Branch { predicate, .. } => {
                scalar_reads(&predicate.left, &mut reads, 0)?;
                scalar_reads(&predicate.right, &mut reads, 0)?;
            }
            HighCfgTerminator::Return { value, .. } => scalar_reads(value, &mut reads, 0)?,
            HighCfgTerminator::Goto { .. } => {}
        }
    }
    used.extend(reads.iter().cloned());
    used.retain(|name| (name != FLAG_LEFT && name != FLAG_RIGHT) || body.contains(name));
    for name in &used {
        let initializer = ir
            .parameters
            .iter()
            .find(|parameter| local(&parameter.location).ok().as_ref() == Some(name));
        output.push_str(&format!(
            "  uint64_t {name} = {};\n",
            initializer
                .map(|parameter| parameter.name.as_str())
                .unwrap_or("UINT64_C(0)")
        ));
        if !reads.contains(name) {
            output.push_str(&format!("  (void){name};\n"));
        }
    }
    output.push_str(&body);
    output.push_str("}\n");
    Ok(output)
}
