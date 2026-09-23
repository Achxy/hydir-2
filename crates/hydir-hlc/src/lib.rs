//! A deliberately narrow source-level IR. Lowering returns a diagnostic for
//! control flow or effects it cannot express; the native low-level C remains
//! the available view for those functions.

use hydir_core::Location;
use hydir_ir::{
    FunctionIr, MachineControlEffect, MachineEdgeKind, MachineFunctionIr, MachineInstruction,
    MachineOperand, MachineOperation, SemanticFidelity, StructuralCompleteness,
};
use hydir_model::{
    AnalysisModel, ModelFunction, PrimitiveType, TypeDefinitionKind, TypeRef, validate_structure,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

mod emit;
pub use emit::emit_typed_c;
mod cfg;
pub use cfg::{
    HIGH_LEVEL_CFG_CIR_VERSION, HighCfgBlock, HighCfgCompareOp, HighCfgPredicate, HighCfgStatement,
    HighCfgTerminator, HighLevelCfgCir, emit_typed_cfg_c, lower_high_level_cfg_cir,
    validate_high_level_cfg_cir,
};

pub const HIGH_LEVEL_CIR_VERSION: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HighParameter {
    pub name: String,
    pub location: String,
    pub ty: TypeRef,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryOp {
    Add,
    Sub,
    Mul,
    Xor,
    And,
    Or,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HighExpr {
    Variable {
        name: String,
    },
    Constant {
        value: u64,
    },
    Binary {
        op: BinaryOp,
        left: Box<HighExpr>,
        right: Box<HighExpr>,
    },
    Field {
        base: Box<HighExpr>,
        field: String,
    },
    Call {
        callee: Location,
        name: String,
        arguments: Vec<HighExpr>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HighStatement {
    Let {
        name: String,
        ty: TypeRef,
        value: HighExpr,
        site: Location,
    },
    StoreField {
        base: HighExpr,
        field: String,
        value: HighExpr,
        site: Location,
    },
    Return {
        value: HighExpr,
        site: Location,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HighLevelCir {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub model_revision: u64,
    pub function_id: String,
    pub entry: Location,
    pub name: String,
    pub parameters: Vec<HighParameter>,
    pub return_type: TypeRef,
    pub statements: Vec<HighStatement>,
    pub structural_completeness: StructuralCompleteness,
    pub semantic_fidelity: SemanticFidelity,
    pub rewrite_ready: bool,
}

#[derive(Clone)]
struct Value {
    expr: HighExpr,
    ty: TypeRef,
}

fn u64_type() -> TypeRef {
    TypeRef::Primitive {
        name: PrimitiveType::U64,
    }
}

fn valid_ident(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        && !matches!(
            name,
            "auto"
                | "break"
                | "case"
                | "char"
                | "const"
                | "continue"
                | "default"
                | "do"
                | "double"
                | "else"
                | "enum"
                | "extern"
                | "float"
                | "for"
                | "goto"
                | "if"
                | "int"
                | "long"
                | "register"
                | "return"
                | "short"
                | "signed"
                | "sizeof"
                | "static"
                | "struct"
                | "switch"
                | "typedef"
                | "union"
                | "unsigned"
                | "void"
                | "volatile"
                | "while"
                | "_Bool"
        )
}

fn validate_expr(expr: &HighExpr, declared: &BTreeSet<String>, depth: usize) -> Result<(), String> {
    if depth > 64 {
        return Err("HighLevelCIR expression depth exceeds 64".to_owned());
    }
    match expr {
        HighExpr::Variable { name } if !declared.contains(name) => Err(format!(
            "HighLevelCIR references undeclared variable {name}"
        )),
        HighExpr::Variable { .. } | HighExpr::Constant { .. } => Ok(()),
        HighExpr::Binary { left, right, .. } => {
            validate_expr(left, declared, depth + 1)?;
            validate_expr(right, declared, depth + 1)
        }
        HighExpr::Field { base, field } => {
            if !valid_ident(field) {
                return Err("HighLevelCIR field name is invalid".to_owned());
            }
            validate_expr(base, declared, depth + 1)
        }
        HighExpr::Call {
            name, arguments, ..
        } => {
            if !valid_ident(name) || arguments.len() > 6 {
                return Err("HighLevelCIR call name/arity is invalid".to_owned());
            }
            for argument in arguments {
                validate_expr(argument, declared, depth + 1)?;
            }
            Ok(())
        }
    }
}

pub fn validate_high_level_cir(ir: &HighLevelCir) -> Result<(), String> {
    if ir.schema_version != HIGH_LEVEL_CIR_VERSION
        || ir.binary_sha256.len() != 64
        || !ir
            .binary_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("invalid HighLevelCIR identity/version".to_owned());
    }
    if ir.model_revision == 0
        || ir.function_id.is_empty()
        || !valid_ident(&ir.name)
        || ir.rewrite_ready
    {
        return Err("invalid HighLevelCIR function/model state".to_owned());
    }
    if ir.structural_completeness != StructuralCompleteness::Complete
        || ir.semantic_fidelity != SemanticFidelity::Conservative
    {
        return Err("invalid HighLevelCIR scope claim".to_owned());
    }
    if ir.parameters.len() > 6 || ir.statements.is_empty() || ir.statements.len() > 8192 {
        return Err("HighLevelCIR parameter/statement limit exceeded".to_owned());
    }
    let mut declared = BTreeSet::new();
    for parameter in &ir.parameters {
        if !valid_ident(&parameter.name) || !declared.insert(parameter.name.clone()) {
            return Err("duplicate or invalid HighLevelCIR parameter".to_owned());
        }
    }
    for (index, statement) in ir.statements.iter().enumerate() {
        match statement {
            HighStatement::Let { name, value, .. } => {
                if !valid_ident(name) || declared.contains(name) {
                    return Err("duplicate or invalid HighLevelCIR local".to_owned());
                }
                validate_expr(value, &declared, 0)?;
                declared.insert(name.clone());
            }
            HighStatement::StoreField {
                base, field, value, ..
            } => {
                if !valid_ident(field) {
                    return Err("invalid HighLevelCIR store field".to_owned());
                }
                validate_expr(base, &declared, 0)?;
                validate_expr(value, &declared, 0)?;
            }
            HighStatement::Return { value, .. } => {
                if index + 1 != ir.statements.len() {
                    return Err("HighLevelCIR return must be final".to_owned());
                }
                validate_expr(value, &declared, 0)?;
            }
        }
    }
    if !matches!(ir.statements.last(), Some(HighStatement::Return { .. })) {
        return Err("HighLevelCIR has no final return".to_owned());
    }
    Ok(())
}

fn ordered_instructions(machine: &MachineFunctionIr) -> Result<Vec<&MachineInstruction>, String> {
    if machine.structural_completeness != StructuralCompleteness::Complete {
        return Err("typed C requires a complete recovered function CFG".to_owned());
    }
    let bounded_direct_calls = machine.semantic_fidelity == SemanticFidelity::Conservative
        && machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .any(|instruction| instruction.effects.control == MachineControlEffect::DirectCall)
        && machine
            .diagnostics
            .iter()
            .all(|diagnostic| !diagnostic.blocks_stable_operation);
    if machine.semantic_fidelity != SemanticFidelity::ExactUnderModel && !bounded_direct_calls {
        return Err("typed C requires exact modeled instruction effects".to_owned());
    }
    if machine.blocks.len() > 4096 {
        return Err("typed C block limit exceeded".to_owned());
    }
    let blocks = machine
        .blocks
        .iter()
        .map(|block| (block.address, block))
        .collect::<BTreeMap<_, _>>();
    let mut current = machine.entry;
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    loop {
        if !seen.insert(current) {
            return Err("typed C linear lowering found a cycle".to_owned());
        }
        let block = blocks
            .get(&current)
            .ok_or("typed C block target is missing")?;
        if block.instructions.is_empty() {
            return Err("typed C block is empty".to_owned());
        }
        for instruction in &block.instructions {
            if !matches!(instruction.operation, MachineOperation::Exact { .. })
                || instruction.effects.conservative
            {
                return Err(format!(
                    "typed C cannot lower opaque or conservative operation at 0x{:x}",
                    instruction.address.value.0
                ));
            }
            result.push(instruction);
        }
        if block.instructions[..block.instructions.len() - 1]
            .iter()
            .any(|instruction| instruction.effects.control != MachineControlEffect::Next)
        {
            return Err("typed C block has an internal control transfer".to_owned());
        }
        let last = block.instructions.last().unwrap();
        if last.effects.control == MachineControlEffect::Return {
            break;
        }
        let mut targets = last
            .edges
            .iter()
            .filter(|edge| edge.kind == MachineEdgeKind::Fallthrough)
            .filter_map(|edge| edge.target);
        let Some(next) = targets.next() else {
            return Err("typed C requires a linear fallthrough path".to_owned());
        };
        let extra_edges_ok = if last.effects.control == MachineControlEffect::DirectCall {
            last.edges
                .iter()
                .filter(|edge| edge.kind == MachineEdgeKind::Call && edge.target.is_some())
                .count()
                == 1
                && last.edges.iter().all(|edge| {
                    matches!(
                        edge.kind,
                        MachineEdgeKind::Call | MachineEdgeKind::Fallthrough
                    )
                })
        } else {
            last.effects.control == MachineControlEffect::Next
                && last
                    .edges
                    .iter()
                    .all(|edge| edge.kind == MachineEdgeKind::Fallthrough)
        };
        if targets.next().is_some() || !extra_edges_ok {
            return Err("typed C branch/exception edge is unsupported".to_owned());
        }
        current = next;
    }
    if seen.len() != blocks.len() {
        return Err("typed C function has additional CFG blocks".to_owned());
    }
    Ok(result)
}

fn parameters(
    model_row: Option<&ModelFunction>,
    function: &FunctionIr,
) -> Result<Vec<HighParameter>, String> {
    const REGS: [&str; 6] = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
    if let Some(proto) = model_row.and_then(|row| row.prototype.as_ref()) {
        if proto.parameters.len() > REGS.len() || proto.variadic {
            return Err("typed C supports at most six fixed SysV GPR parameters".to_owned());
        }
        return Ok(proto
            .parameters
            .iter()
            .enumerate()
            .map(|(index, parameter)| HighParameter {
                name: if valid_ident(&parameter.name) {
                    parameter.name.clone()
                } else {
                    format!("arg_{index}")
                },
                location: REGS[index].to_owned(),
                ty: parameter.ty.clone(),
            })
            .collect());
    }
    let highest = function
        .parameters
        .iter()
        .filter_map(|parameter| REGS.iter().position(|reg| *reg == parameter.location))
        .max();
    let Some(highest) = highest else {
        return Ok(Vec::new());
    };
    Ok((0..=highest)
        .map(|index| {
            let location = REGS[index].to_owned();
            let ty = model_row
                .and_then(|row| row.inferred_parameters.get(&location))
                .cloned()
                .unwrap_or_else(u64_type);
            HighParameter {
                name: format!("arg_{index}"),
                location,
                ty,
            }
        })
        .collect())
}

fn read_field(
    operand: &MachineOperand,
    registers: &BTreeMap<String, Value>,
    model: &AnalysisModel,
) -> Result<Value, String> {
    let MachineOperand::Memory {
        segment: None,
        base: Some(base),
        index: None,
        displacement,
        absolute: None,
        width_bits,
        ..
    } = operand
    else {
        return Err("typed C memory access is not a fixed-offset pointer field".to_owned());
    };
    let pointer = registers
        .get(base)
        .ok_or_else(|| format!("typed C pointer base {base} has unknown value"))?;
    let TypeRef::Pointer { to } = &pointer.ty else {
        return Err("typed C memory base has no pointer type".to_owned());
    };
    let TypeRef::Named { id } = to.as_ref() else {
        return Err("typed C pointer referent is not a named aggregate".to_owned());
    };
    let definition = model
        .types
        .iter()
        .find(|def| &def.id == id)
        .ok_or("typed C referenced aggregate is missing")?;
    let (TypeDefinitionKind::Struct { fields } | TypeDefinitionKind::Union { fields }) =
        &definition.kind
    else {
        return Err("typed C pointer referent is not a struct or union".to_owned());
    };
    let offset = u64::try_from(*displacement)
        .map_err(|_| "typed C negative field displacement is unsupported")?;
    let field = fields
        .iter()
        .find(|field| field.offset_bytes == offset)
        .ok_or("typed C memory access has no modeled field")?;
    let expected = match &field.ty {
        TypeRef::Primitive { name } => name.size_bytes(),
        TypeRef::Pointer { .. } => Some(8),
        _ => None,
    };
    if expected != Some(u64::from(*width_bits / 8)) {
        return Err("typed C field access width differs from model".to_owned());
    }
    Ok(Value {
        expr: HighExpr::Field {
            base: Box::new(pointer.expr.clone()),
            field: field.name.clone(),
        },
        ty: field.ty.clone(),
    })
}

fn operand_value(
    operand: &MachineOperand,
    registers: &BTreeMap<String, Value>,
    model: &AnalysisModel,
) -> Result<Value, String> {
    match operand {
        MachineOperand::Register {
            name,
            width_bits: 64,
        } => registers
            .get(name)
            .cloned()
            .ok_or_else(|| format!("typed C register {name} has unknown value")),
        MachineOperand::Immediate {
            value,
            width_bits: 64,
        } => Ok(Value {
            expr: HighExpr::Constant { value: *value },
            ty: u64_type(),
        }),
        MachineOperand::Memory { .. } => read_field(operand, registers, model),
        _ => Err("typed C operand width/kind is unsupported".to_owned()),
    }
}

fn frame_slot(operand: &MachineOperand) -> Option<i64> {
    let MachineOperand::Memory {
        segment: None,
        base: Some(base),
        index: None,
        displacement,
        absolute: None,
        width_bits: 64,
        ..
    } = operand
    else {
        return None;
    };
    (base == "rbp" && (-65_536..=-8).contains(displacement) && displacement % 8 == 0)
        .then_some(*displacement)
}

fn closed_rbp_frame(instructions: &[&MachineInstruction]) -> bool {
    let family = |index: usize| match &instructions[index].operation {
        MachineOperation::Exact { family } => family.as_str(),
        _ => "",
    };
    let rbp = |operand: &MachineOperand| matches!(operand, MachineOperand::Register { name, width_bits: 64 } if name == "rbp");
    let rsp = |operand: &MachineOperand| matches!(operand, MachineOperand::Register { name, width_bits: 64 } if name == "rsp");
    instructions.len() >= 4
        && family(0) == "push"
        && instructions[0].operands.as_slice().first().is_some_and(rbp)
        && family(1) == "mov"
        && matches!(instructions[1].operands.as_slice(), [left, right] if rbp(left) && rsp(right))
        && family(instructions.len() - 2) == "pop"
        && instructions[instructions.len() - 2]
            .operands
            .as_slice()
            .first()
            .is_some_and(rbp)
        && family(instructions.len() - 1) == "ret"
}

fn closed_frame_allocation(instructions: &[&MachineInstruction]) -> Option<u64> {
    if instructions.len() < 7 || !closed_rbp_frame(instructions) {
        return None;
    }
    let adjustment = |instruction: &MachineInstruction, family: &str| {
        matches!(&instruction.operation, MachineOperation::Exact { family: found } if found == family)
            .then_some(instruction.operands.as_slice())
            .and_then(|operands| match operands {
                [MachineOperand::Register { name, width_bits: 64 }, MachineOperand::Immediate { value, width_bits: 64 }]
                    if name == "rsp" && *value > 0 && *value <= 65_536 && *value % 8 == 0 => Some(*value),
                _ => None,
            })
    };
    let allocation = adjustment(instructions[2], "sub")?;
    (adjustment(instructions[instructions.len() - 3], "add") == Some(allocation))
        .then_some(allocation)
}

/// Lower a complete linear function with exact 64-bit operations. Other
/// functions retain their existing low-level and structured views.
pub fn lower_high_level_cir(
    machine: &MachineFunctionIr,
    function: &FunctionIr,
    model: &AnalysisModel,
) -> Result<HighLevelCir, String> {
    validate_structure(model)?;
    if machine.binary_sha256 != model.binary_sha256
        || function.binary_sha256 != model.binary_sha256
        || machine.entry != function.entry
    {
        return Err("typed C artifact identity differs from model".to_owned());
    }
    let instructions = ordered_instructions(machine)?;
    let frame_mode = closed_rbp_frame(&instructions);
    let frame_allocation = closed_frame_allocation(&instructions);
    let model_row = model
        .functions
        .iter()
        .find(|row| row.entry == machine.entry);
    let parameters = parameters(model_row, function)?;
    let return_type = model_row
        .and_then(|row| row.prototype.as_ref())
        .map(|proto| proto.return_type.clone())
        .unwrap_or_else(u64_type);
    if return_type != u64_type() {
        return Err("typed C currently requires a uint64_t return type".to_owned());
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
    let mut registers = parameters
        .iter()
        .map(|parameter| {
            (
                parameter.location.clone(),
                Value {
                    expr: HighExpr::Variable {
                        name: parameter.name.clone(),
                    },
                    ty: parameter.ty.clone(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut statements = Vec::new();
    let mut stack_slots = BTreeMap::<i64, Value>::new();
    let mut pushed = Vec::<Option<Value>>::new();
    let instruction_count = instructions.len();
    for (index, instruction) in instructions.into_iter().enumerate() {
        let MachineOperation::Exact { family } = &instruction.operation else {
            unreachable!()
        };
        if family == "ret" {
            let result = registers
                .get("rax")
                .ok_or("typed C return register has unknown value")?;
            if result.ty != return_type {
                return Err("typed C return type differs from RAX value".to_owned());
            }
            statements.push(HighStatement::Return {
                value: result.expr.clone(),
                site: instruction.address,
            });
            continue;
        }
        if frame_mode && (index == 0 || index == 1 || index + 2 == instruction_count) {
            continue;
        }
        if frame_allocation.is_some() && (index == 2 || index + 3 == instruction_count) {
            continue;
        }
        let operands = instruction.operands.as_slice();
        let result = match (family.as_str(), operands) {
            (
                "push",
                [
                    MachineOperand::Register {
                        name,
                        width_bits: 64,
                    },
                ],
            ) if pushed.len() < 64 => {
                pushed.push(registers.get(name).cloned());
                None
            }
            (
                "pop",
                [
                    MachineOperand::Register {
                        name,
                        width_bits: 64,
                    },
                ],
            ) => {
                let saved = pushed.pop().ok_or("typed C pop has no matching push")?;
                if saved.is_none() {
                    registers.remove(name);
                }
                saved.map(|value| (name.clone(), value))
            }
            ("call", [_]) if instruction.effects.control == MachineControlEffect::DirectCall => {
                let mut call_edges = instruction
                    .edges
                    .iter()
                    .filter(|edge| edge.kind == MachineEdgeKind::Call)
                    .filter_map(|edge| edge.target);
                let callee = call_edges
                    .next()
                    .ok_or("typed C call target is unresolved")?;
                if call_edges.next().is_some() {
                    return Err("typed C call has multiple targets".to_owned());
                }
                let row = model
                    .functions
                    .iter()
                    .find(|row| row.entry == callee)
                    .ok_or("typed C call target has no model function")?;
                let prototype = row
                    .prototype
                    .as_ref()
                    .ok_or("typed C call target has no asserted prototype")?;
                if !valid_ident(&row.name)
                    || prototype.variadic
                    || prototype.calling_convention != "sysv_amd64"
                    || prototype.parameters.len() > 6
                    || prototype.return_type != u64_type()
                {
                    return Err("typed C call prototype is unsupported".to_owned());
                }
                let arg_registers = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
                let mut arguments = Vec::new();
                for (parameter, register) in prototype.parameters.iter().zip(arg_registers) {
                    let value = registers
                        .get(register)
                        .ok_or("typed C call argument register has unknown value")?;
                    if value.ty != parameter.ty {
                        return Err("typed C call argument type differs from prototype".to_owned());
                    }
                    arguments.push(value.expr.clone());
                }
                for register in ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"] {
                    registers.remove(register);
                }
                Some((
                    "rax".to_owned(),
                    Value {
                        expr: HighExpr::Call {
                            callee,
                            name: row.name.clone(),
                            arguments,
                        },
                        ty: u64_type(),
                    },
                ))
            }
            (
                "mov",
                [
                    MachineOperand::Register {
                        name,
                        width_bits: 64,
                    },
                    source,
                ],
            ) if frame_mode && frame_slot(source).is_some() => {
                let slot = frame_slot(source).unwrap();
                let value = stack_slots
                    .get(&slot)
                    .cloned()
                    .ok_or("typed C reads an uninitialized frame slot")?;
                Some((name.clone(), value))
            }
            ("mov", [destination @ MachineOperand::Memory { .. }, source])
                if frame_mode && frame_slot(destination).is_some() =>
            {
                let slot = frame_slot(destination).unwrap();
                let value = operand_value(source, &registers, model)?;
                stack_slots.insert(slot, value);
                None
            }
            (
                "mov",
                [
                    MachineOperand::Register {
                        name,
                        width_bits: 64,
                    },
                    source,
                ],
            ) => Some((name.clone(), operand_value(source, &registers, model)?)),
            ("mov", [destination @ MachineOperand::Memory { .. }, source]) => {
                let field = read_field(destination, &registers, model)?;
                let value = operand_value(source, &registers, model)?;
                if field.ty != value.ty {
                    return Err("typed C store value differs from field type".to_owned());
                }
                let HighExpr::Field { base, field } = field.expr else {
                    unreachable!()
                };
                statements.push(HighStatement::StoreField {
                    base: *base,
                    field,
                    value: value.expr,
                    site: instruction.address,
                });
                None
            }
            (
                "add" | "sub" | "xor" | "and" | "or",
                [
                    MachineOperand::Register {
                        name,
                        width_bits: 64,
                    },
                    source,
                ],
            ) => {
                let left = registers
                    .get(name)
                    .ok_or("typed C arithmetic register has unknown value")?;
                let right = operand_value(source, &registers, model)?;
                if left.ty != u64_type() || right.ty != u64_type() {
                    return Err("typed C arithmetic requires unsigned 64-bit values".to_owned());
                }
                let op = match family.as_str() {
                    "add" => BinaryOp::Add,
                    "sub" => BinaryOp::Sub,
                    "xor" => BinaryOp::Xor,
                    "and" => BinaryOp::And,
                    _ => BinaryOp::Or,
                };
                Some((
                    name.clone(),
                    Value {
                        expr: HighExpr::Binary {
                            op,
                            left: Box::new(left.expr.clone()),
                            right: Box::new(right.expr),
                        },
                        ty: u64_type(),
                    },
                ))
            }
            ("nop" | "endbr64", []) => None,
            _ => {
                return Err(format!(
                    "typed C operation {family} at 0x{:x} is unsupported",
                    instruction.address.value.0
                ));
            }
        };
        if let Some((register, value)) = result {
            let name = format!("hydir_v{}", statements.len());
            statements.push(HighStatement::Let {
                name: name.clone(),
                ty: value.ty.clone(),
                value: value.expr,
                site: instruction.address,
            });
            registers.insert(
                register,
                Value {
                    expr: HighExpr::Variable { name },
                    ty: value.ty,
                },
            );
        }
    }
    if !pushed.is_empty() {
        return Err("typed C has unmatched stack pushes".to_owned());
    }
    if !matches!(statements.last(), Some(HighStatement::Return { .. })) {
        return Err("typed C has no return statement".to_owned());
    }
    let ir = HighLevelCir {
        schema_version: HIGH_LEVEL_CIR_VERSION,
        binary_sha256: machine.binary_sha256.clone(),
        model_revision: model.revision,
        function_id: machine.function_id.clone(),
        entry: machine.entry,
        name,
        parameters,
        return_type,
        statements,
        structural_completeness: StructuralCompleteness::Complete,
        semantic_fidelity: SemanticFidelity::Conservative,
        rewrite_ready: false,
    };
    validate_high_level_cir(&ir)?;
    Ok(ir)
}
