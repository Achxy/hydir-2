//! A bounded CFG form of typed C. It deliberately admits only operations
//! whose scalar behavior can be expressed without an opaque machine state.
//! Each branch retains its recovered target and instruction site.

use crate::emit::{c_decl, collect_used_types, emit_model_type_declarations};
use crate::{BinaryOp, HighExpr, HighParameter, parameters, u64_type, valid_ident};
use hydir_core::Location;
use hydir_decompile::{lower_expression_ir, lower_state_ir};
use hydir_ir::expression::{
    AddressExpression, BinaryOperator as ExpressionBinaryOperator, ComparisonOperator, Expression,
    ExpressionFunctionIr, ExpressionInstruction, MemoryByteOrder, validate_expression_function_ir,
};
use hydir_ir::{
    FunctionIr, MachineControlEffect, MachineEdgeKind, MachineFunctionIr, MachineInstruction,
    MachineMemoryEffect, MachineOperand, MachineOperation, SemanticFidelity, StateComponentVersion,
    StructuralCompleteness, validate_function_ir, validate_machine_function_ir,
};
use hydir_model::{
    AnalysisModel, ModelField, TypeDefinition, TypeDefinitionKind, TypeRef, validate_structure,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub const HIGH_LEVEL_CFG_CIR_VERSION: u32 = 3;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HighCfgAggregateKind {
    Struct,
    Union,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HighCfgFieldView {
    pub type_id: String,
    pub type_name: String,
    pub aggregate_kind: HighCfgAggregateKind,
    pub field: String,
    pub base: HighExpr,
    pub offset_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derived_base: Option<HighCfgDerivedBase>,
    /// An array subscript is a layout annotation, not a proof that the
    /// runtime index is within the modeled array's bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub array_index: Option<HighExpr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub array_element: Option<HighCfgArrayElementView>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HighCfgArrayElementView {
    pub element_type_id: String,
    pub element_type_name: String,
    pub field: String,
    pub field_offset_bytes: u64,
    /// Register and scale encoded by the memory instruction. The register is
    /// a proven multiple of `array_index` at this access.
    pub raw_index: String,
    pub raw_scale: u32,
    pub index_multiplier: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HighCfgDerivedBase {
    /// Raw register used by the memory instruction; `base` is the stable
    /// origin parameter whose type supplies the field interpretation.
    pub register: String,
    pub origin_offset_bytes: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HighCfgStatement {
    Assign {
        target: String,
        value: HighExpr,
        site: Location,
    },
    Load {
        target: String,
        address: HighExpr,
        width_bits: u16,
        byte_order: MemoryByteOrder,
        memory_inputs: Vec<StateComponentVersion>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        field_view: Option<HighCfgFieldView>,
        site: Location,
    },
    Store {
        address: HighExpr,
        value: HighExpr,
        width_bits: u16,
        byte_order: MemoryByteOrder,
        memory_inputs: Vec<StateComponentVersion>,
        memory_outputs: Vec<StateComponentVersion>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        field_view: Option<HighCfgFieldView>,
        site: Location,
    },
}

impl HighCfgStatement {
    fn site(&self) -> Location {
        match self {
            Self::Assign { site, .. } | Self::Load { site, .. } | Self::Store { site, .. } => *site,
        }
    }
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

fn scalar_expression(expression: &Expression) -> Result<HighExpr, String> {
    match expression {
        Expression::Read {
            source,
            width_bits: 64,
        } => {
            let name = source
                .component
                .strip_prefix("register:")
                .ok_or("typed CFG expression reads a non-register component")?;
            Ok(HighExpr::Variable { name: local(name)? })
        }
        Expression::Constant {
            value,
            width_bits: 64,
        } => Ok(HighExpr::Constant { value: *value }),
        Expression::EffectiveAddress { address } => address_expression(address),
        Expression::Binary {
            operator: ExpressionBinaryOperator::Xor,
            width_bits: 64,
            left,
            right,
        } if matches!((left.as_ref(), right.as_ref()),
            (Expression::Read { source: a, width_bits: 64 }, Expression::Read { source: b, width_bits: 64 }) if a == b) =>
        {
            // x86's XOR-zeroing idiom does not read the old register value.
            Ok(HighExpr::Constant { value: 0 })
        }
        Expression::Binary {
            operator,
            width_bits: 64,
            left,
            right,
        } => {
            let op = match operator {
                ExpressionBinaryOperator::Add => BinaryOp::Add,
                ExpressionBinaryOperator::Subtract => BinaryOp::Sub,
                ExpressionBinaryOperator::And => BinaryOp::And,
                ExpressionBinaryOperator::Or => BinaryOp::Or,
                ExpressionBinaryOperator::Xor => BinaryOp::Xor,
            };
            Ok(HighExpr::Binary {
                op,
                left: Box::new(scalar_expression(left)?),
                right: Box::new(scalar_expression(right)?),
            })
        }
        _ => {
            Err("typed CFG requires a normalized 64-bit scalar ExpressionIR assignment".to_owned())
        }
    }
}

fn address_expression(address: &AddressExpression) -> Result<HighExpr, String> {
    if address.absolute.is_some() {
        return Err("typed CFG absolute memory address requires load-bias proof".to_owned());
    }
    let mut parts = Vec::new();
    if let Some(base) = &address.base {
        parts.push(scalar_expression(base)?);
    }
    if let Some(index) = &address.index {
        let mut index = scalar_expression(index)?;
        if address.scale != 1 {
            index = HighExpr::Binary {
                op: BinaryOp::Mul,
                left: Box::new(index),
                right: Box::new(HighExpr::Constant {
                    value: u64::from(address.scale),
                }),
            };
        }
        parts.push(index);
    }
    let mut parts = parts.into_iter();
    let mut result = parts
        .next()
        .ok_or("typed CFG memory address has no register base or index")?;
    for part in parts {
        result = HighExpr::Binary {
            op: BinaryOp::Add,
            left: Box::new(result),
            right: Box::new(part),
        };
    }
    if address.displacement != 0 {
        result = HighExpr::Binary {
            op: if address.displacement < 0 {
                BinaryOp::Sub
            } else {
                BinaryOp::Add
            },
            left: Box::new(result),
            right: Box::new(HighExpr::Constant {
                value: address.displacement.unsigned_abs(),
            }),
        };
    }
    Ok(result)
}

fn eight_byte_type(ty: &TypeRef) -> bool {
    match ty {
        TypeRef::Primitive { name } => name.size_bytes() == Some(8),
        TypeRef::Pointer { .. } => true,
        _ => false,
    }
}

fn eight_byte_field(field: &ModelField, indexed: bool) -> bool {
    if indexed {
        matches!(&field.ty, TypeRef::Array { of, .. } if eight_byte_type(of))
    } else {
        eight_byte_type(&field.ty)
    }
}

fn aggregate_fields(definition: &TypeDefinition) -> Option<(HighCfgAggregateKind, &[ModelField])> {
    match &definition.kind {
        TypeDefinitionKind::Struct { fields } => Some((HighCfgAggregateKind::Struct, fields)),
        TypeDefinitionKind::Union { fields } => Some((HighCfgAggregateKind::Union, fields)),
        _ => None,
    }
}

#[derive(Clone, Debug)]
struct FieldRoot {
    type_id: String,
    origin_register: String,
    origin_offset_bytes: i64,
}

#[derive(Clone, Debug)]
struct IndexRoot {
    origin_register: String,
    multiplier: u64,
}

/// Returns coefficient and constant for a bounded unsigned affine expression
/// in one register. All arithmetic is checked before it becomes a layout
/// claim; the emitted C still uses the exact modular register expression.
fn affine_coefficient(expr: &HighExpr, variable: &str, depth: usize) -> Option<(u64, u64)> {
    if depth > 32 {
        return None;
    }
    match expr {
        HighExpr::Variable { name } if name == variable => Some((1, 0)),
        HighExpr::Constant { value } => Some((0, *value)),
        HighExpr::Binary {
            op: BinaryOp::Add,
            left,
            right,
        } => {
            let (left_coefficient, left_constant) = affine_coefficient(left, variable, depth + 1)?;
            let (right_coefficient, right_constant) =
                affine_coefficient(right, variable, depth + 1)?;
            Some((
                left_coefficient.checked_add(right_coefficient)?,
                left_constant.checked_add(right_constant)?,
            ))
        }
        HighExpr::Binary {
            op: BinaryOp::Mul,
            left,
            right,
        } => {
            let (left_coefficient, left_constant) = affine_coefficient(left, variable, depth + 1)?;
            let (right_coefficient, right_constant) =
                affine_coefficient(right, variable, depth + 1)?;
            if left_coefficient == 0 {
                Some((
                    right_coefficient.checked_mul(left_constant)?,
                    right_constant.checked_mul(left_constant)?,
                ))
            } else if right_coefficient == 0 {
                Some((
                    left_coefficient.checked_mul(right_constant)?,
                    left_constant.checked_mul(right_constant)?,
                ))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn register_read(expression: &Expression) -> Option<&str> {
    let Expression::Read {
        source,
        width_bits: 64,
    } = expression
    else {
        return None;
    };
    source.component.strip_prefix("register:")
}

fn derived_pointer_origin(expression: &Expression) -> Option<(&str, i64)> {
    if let Some(register) = register_read(expression) {
        return Some((register, 0));
    }
    let Expression::EffectiveAddress { address } = expression else {
        return None;
    };
    if address.absolute.is_some() || address.index.is_some() {
        return None;
    }
    Some((
        register_read(address.base.as_deref()?)?,
        address.displacement,
    ))
}

fn stable_field_roots(
    parameters: &[HighParameter],
    expression: &ExpressionFunctionIr,
) -> BTreeMap<String, FieldRoot> {
    let mut writes = BTreeMap::<&str, usize>::new();
    for component in expression
        .blocks
        .iter()
        .flat_map(|block| &block.instructions)
        .flat_map(|instruction| &instruction.output_components)
        .map(|output| output.component.as_str())
    {
        *writes.entry(component).or_default() += 1;
    }
    let mut roots = parameters
        .iter()
        .filter_map(|parameter| {
            let TypeRef::Pointer { to } = &parameter.ty else {
                return None;
            };
            let TypeRef::Named { id } = to.as_ref() else {
                return None;
            };
            (!writes.contains_key(format!("register:{}", parameter.location).as_str())).then(|| {
                (
                    parameter.location.clone(),
                    FieldRoot {
                        type_id: id.clone(),
                        origin_register: parameter.location.clone(),
                        origin_offset_bytes: 0,
                    },
                )
            })
        })
        .collect::<BTreeMap<_, _>>();
    // Entry-block, single-write copies and LEAs dominate every later block.
    // Do not derive from a parameter register: it is initialized on entry, so
    // a skipped assignment could otherwise appear valid at a join.
    if let Some(entry_block) = expression
        .blocks
        .iter()
        .find(|block| block.address == expression.entry)
    {
        for instruction in &entry_block.instructions {
            if instruction.residual.is_some() || !instruction.memory_writes.is_empty() {
                continue;
            }
            for assignment in &instruction.assignments {
                let Some(target) = assignment.target.component.strip_prefix("register:") else {
                    continue;
                };
                if roots.contains_key(target)
                    || parameters
                        .iter()
                        .any(|parameter| parameter.location == target)
                    || writes.get(assignment.target.component.as_str()) != Some(&1)
                {
                    continue;
                }
                let Some((origin, offset)) = derived_pointer_origin(&assignment.value) else {
                    continue;
                };
                let Some(root) = roots.get(origin) else {
                    continue;
                };
                if root.origin_register != origin {
                    continue;
                }
                let Some(total_offset) = root.origin_offset_bytes.checked_add(offset) else {
                    continue;
                };
                let new_root = FieldRoot {
                    type_id: root.type_id.clone(),
                    origin_register: root.origin_register.clone(),
                    origin_offset_bytes: total_offset,
                };
                roots.insert(target.to_owned(), new_root);
            }
        }
    }
    roots
}

fn stable_index_roots(
    parameters: &[HighParameter],
    expression: &ExpressionFunctionIr,
) -> BTreeMap<String, IndexRoot> {
    let mut writes = BTreeMap::<&str, usize>::new();
    for component in expression
        .blocks
        .iter()
        .flat_map(|block| &block.instructions)
        .flat_map(|instruction| &instruction.output_components)
        .map(|output| output.component.as_str())
    {
        *writes.entry(component).or_default() += 1;
    }
    let mut roots = parameters
        .iter()
        .filter(|parameter| {
            parameter.ty == u64_type()
                && !writes.contains_key(format!("register:{}", parameter.location).as_str())
        })
        .map(|parameter| {
            (
                parameter.location.clone(),
                IndexRoot {
                    origin_register: parameter.location.clone(),
                    multiplier: 1,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    if let Some(entry_block) = expression
        .blocks
        .iter()
        .find(|block| block.address == expression.entry)
    {
        for instruction in &entry_block.instructions {
            if instruction.residual.is_some() || !instruction.memory_writes.is_empty() {
                continue;
            }
            for assignment in &instruction.assignments {
                let Some(target) = assignment.target.component.strip_prefix("register:") else {
                    continue;
                };
                if roots.contains_key(target)
                    || parameters
                        .iter()
                        .any(|parameter| parameter.location == target)
                    || writes.get(assignment.target.component.as_str()) != Some(&1)
                {
                    continue;
                }
                let Ok(value) = scalar_expression(&assignment.value) else {
                    continue;
                };
                let mut candidates = roots.iter().filter_map(|(register, root)| {
                    if root.origin_register != *register {
                        return None;
                    }
                    let variable = local(register).ok()?;
                    let (factor, constant) = affine_coefficient(&value, &variable, 0)?;
                    (constant == 0 && (1..=1_000_000).contains(&factor))
                        .then(|| (root.origin_register.clone(), factor))
                });
                let Some((origin_register, multiplier)) = candidates.next() else {
                    continue;
                };
                if candidates.next().is_some() {
                    continue;
                }
                roots.insert(
                    target.to_owned(),
                    IndexRoot {
                        origin_register,
                        multiplier,
                    },
                );
            }
        }
    }
    roots
}

fn field_view_from_address(
    address: &AddressExpression,
    roots: &BTreeMap<String, FieldRoot>,
    index_roots: &BTreeMap<String, IndexRoot>,
    model: &AnalysisModel,
) -> Option<HighCfgFieldView> {
    if address.absolute.is_some() {
        return None;
    }
    let Expression::Read {
        source,
        width_bits: 64,
    } = address.base.as_deref()?
    else {
        return None;
    };
    let register_name = source.component.strip_prefix("register:")?;
    let root = roots.get(register_name)?;
    let total_offset =
        u64::try_from(root.origin_offset_bytes.checked_add(address.displacement)?).ok()?;
    let type_id = &root.type_id;
    let definition = model
        .types
        .iter()
        .find(|definition| &definition.id == type_id)?;
    let (aggregate_kind, fields) = aggregate_fields(definition)?;
    // A union with several views has no selected interpretation. Leave its
    // memory access raw even if only one member has this exact width.
    if aggregate_kind == HighCfgAggregateKind::Union && fields.len() > 1 {
        return None;
    }
    let mut matching = Vec::new();
    if let Some(index) = address.index.as_deref() {
        if address.scale == 8 {
            let raw_index = scalar_expression(index).ok()?;
            for field in fields
                .iter()
                .filter(|field| field.offset_bytes == total_offset && eight_byte_field(field, true))
            {
                matching.push((field, Some(raw_index.clone()), None));
            }
        }
        if let Some(raw_register) = register_read(index) {
            if let Some(index_root) = index_roots.get(raw_register) {
                let stride = index_root
                    .multiplier
                    .checked_mul(u64::from(address.scale))?;
                for field in fields {
                    let TypeRef::Array { of, .. } = &field.ty else {
                        continue;
                    };
                    let TypeRef::Named { id } = of.as_ref() else {
                        continue;
                    };
                    let Some(element_type) = model.types.iter().find(|item| item.id == *id) else {
                        continue;
                    };
                    if element_type.size_is_lower_bound || element_type.size_bytes != stride {
                        continue;
                    }
                    let TypeDefinitionKind::Struct {
                        fields: element_fields,
                    } = &element_type.kind
                    else {
                        continue;
                    };
                    for element_field in element_fields {
                        if !eight_byte_type(&element_field.ty)
                            || field.offset_bytes.checked_add(element_field.offset_bytes)
                                != Some(total_offset)
                        {
                            continue;
                        }
                        matching.push((
                            field,
                            Some(HighExpr::Variable {
                                name: local(&index_root.origin_register).ok()?,
                            }),
                            Some(HighCfgArrayElementView {
                                element_type_id: element_type.id.clone(),
                                element_type_name: element_type.name.clone(),
                                field: element_field.name.clone(),
                                field_offset_bytes: element_field.offset_bytes,
                                raw_index: local(raw_register).ok()?,
                                raw_scale: address.scale,
                                index_multiplier: index_root.multiplier,
                            }),
                        ));
                    }
                }
            }
        }
    } else {
        for field in fields
            .iter()
            .filter(|field| field.offset_bytes == total_offset && eight_byte_field(field, false))
        {
            matching.push((field, None, None));
        }
    }
    if matching.len() != 1 {
        return None;
    }
    let (field, array_index, array_element) = matching.pop()?;
    let derived_base = if root.origin_register != register_name {
        Some(HighCfgDerivedBase {
            register: local(register_name).ok()?,
            origin_offset_bytes: root.origin_offset_bytes,
        })
    } else {
        None
    };
    Some(HighCfgFieldView {
        type_id: type_id.clone(),
        type_name: definition.name.clone(),
        aggregate_kind,
        field: field.name.clone(),
        base: HighExpr::Variable {
            name: local(&root.origin_register).ok()?,
        },
        offset_bytes: field.offset_bytes,
        derived_base,
        array_index,
        array_element,
    })
}

fn field_view_address(view: &HighCfgFieldView) -> Option<HighExpr> {
    let total_offset = view.offset_bytes.checked_add(
        view.array_element
            .as_ref()
            .map_or(0, |element| element.field_offset_bytes),
    )?;
    let (mut address, displacement) = if let Some(derived) = &view.derived_base {
        (
            HighExpr::Variable {
                name: derived.register.clone(),
            },
            i64::try_from(total_offset)
                .ok()?
                .checked_sub(derived.origin_offset_bytes)?,
        )
    } else {
        (view.base.clone(), i64::try_from(total_offset).ok()?)
    };
    if let Some(element) = &view.array_element {
        let mut raw_index = HighExpr::Variable {
            name: element.raw_index.clone(),
        };
        if element.raw_scale != 1 {
            raw_index = HighExpr::Binary {
                op: BinaryOp::Mul,
                left: Box::new(raw_index),
                right: Box::new(HighExpr::Constant {
                    value: u64::from(element.raw_scale),
                }),
            };
        }
        address = HighExpr::Binary {
            op: BinaryOp::Add,
            left: Box::new(address),
            right: Box::new(raw_index),
        };
    } else if let Some(index) = &view.array_index {
        address = HighExpr::Binary {
            op: BinaryOp::Add,
            left: Box::new(address),
            right: Box::new(HighExpr::Binary {
                op: BinaryOp::Mul,
                left: Box::new(index.clone()),
                right: Box::new(HighExpr::Constant { value: 8 }),
            }),
        };
    }
    if displacement != 0 {
        address = HighExpr::Binary {
            op: if displacement < 0 {
                BinaryOp::Sub
            } else {
                BinaryOp::Add
            },
            left: Box::new(address),
            right: Box::new(HighExpr::Constant {
                value: displacement.unsigned_abs(),
            }),
        };
    }
    Some(address)
}

fn normalized_memory_load(
    semantic: &ExpressionInstruction,
    register_name: &str,
    roots: &BTreeMap<String, FieldRoot>,
    index_roots: &BTreeMap<String, IndexRoot>,
    model: &AnalysisModel,
) -> Result<
    (
        HighExpr,
        Vec<StateComponentVersion>,
        Option<HighCfgFieldView>,
    ),
    String,
> {
    let component = format!("register:{register_name}");
    let mut assignments = semantic
        .assignments
        .iter()
        .filter(|assignment| assignment.target.component == component);
    let assignment = assignments
        .next()
        .ok_or("typed CFG memory load lacks normalized ExpressionIR semantics")?;
    if assignments.next().is_some()
        || semantic.assignments.len() != 1
        || semantic.residual.is_some()
        || !semantic.memory_writes.is_empty()
    {
        return Err("typed CFG memory load has residual or ambiguous effects".to_owned());
    }
    match &assignment.value {
        Expression::MemoryRead {
            address,
            width_bits: 64,
            byte_order: MemoryByteOrder::Little,
            memory_inputs,
        } => Ok((
            address_expression(address)?,
            memory_inputs.clone(),
            field_view_from_address(address, roots, index_roots, model),
        )),
        _ => Err("typed CFG requires a normalized 64-bit memory load".to_owned()),
    }
}

fn normalized_memory_store(
    semantic: &ExpressionInstruction,
    roots: &BTreeMap<String, FieldRoot>,
    index_roots: &BTreeMap<String, IndexRoot>,
    model: &AnalysisModel,
) -> Result<
    (
        HighExpr,
        HighExpr,
        Vec<StateComponentVersion>,
        Vec<StateComponentVersion>,
        Option<HighCfgFieldView>,
    ),
    String,
> {
    let [write] = semantic.memory_writes.as_slice() else {
        return Err("typed CFG memory store lacks one normalized ExpressionIR write".to_owned());
    };
    if write.width_bits != 64
        || write.byte_order != MemoryByteOrder::Little
        || semantic.residual.is_some()
        || !semantic.assignments.is_empty()
    {
        return Err("typed CFG memory store has residual or unsupported effects".to_owned());
    }
    Ok((
        address_expression(&write.address)?,
        scalar_expression(&write.value)?,
        write.memory_inputs.clone(),
        write.memory_outputs.clone(),
        field_view_from_address(&write.address, roots, index_roots, model),
    ))
}

fn normalized_register_value(
    instruction: &ExpressionInstruction,
    register_name: &str,
) -> Result<HighExpr, String> {
    let component = format!("register:{register_name}");
    let mut assignments = instruction
        .assignments
        .iter()
        .filter(|assignment| assignment.target.component == component);
    let assignment = assignments
        .next()
        .ok_or("typed CFG register write lacks normalized ExpressionIR semantics")?;
    if assignments.next().is_some() || assignment.value.width_bits() != 64 {
        return Err("typed CFG register write has ambiguous ExpressionIR semantics".to_owned());
    }
    scalar_expression(&assignment.value)
}

fn normalized_zero_flag(
    semantic: &ExpressionInstruction,
) -> Result<(&Expression, &Expression), String> {
    let mut assignments = semantic
        .assignments
        .iter()
        .filter(|assignment| assignment.target.component == "flag:zf");
    let assignment = assignments
        .next()
        .ok_or("typed CFG flag write lacks normalized ExpressionIR semantics")?;
    if assignments.next().is_some() {
        return Err("typed CFG has ambiguous zero-flag semantics".to_owned());
    }
    match &assignment.value {
        Expression::Compare {
            operator: ComparisonOperator::Equal,
            left,
            right,
        } if left.width_bits() == 64 && right.width_bits() == 64 => Ok((left, right)),
        _ => Err("typed CFG requires a normalized 64-bit zero-flag comparison".to_owned()),
    }
}

fn zero_constant(expression: &Expression) -> bool {
    matches!(
        expression,
        Expression::Constant {
            value: 0,
            width_bits: 64
        }
    )
}

fn normalized_flag_operands(
    semantic: &ExpressionInstruction,
    family: &str,
) -> Result<(HighExpr, HighExpr), String> {
    let (left, right) = normalized_zero_flag(semantic)?;
    if family == "cmp" {
        return Ok((scalar_expression(left)?, scalar_expression(right)?));
    }
    if family == "test"
        && zero_constant(right)
        && let Expression::Binary {
            operator: ExpressionBinaryOperator::And,
            width_bits: 64,
            left,
            right,
        } = left
    {
        return Ok((scalar_expression(left)?, scalar_expression(right)?));
    }
    Err("typed CFG test flags lack normalized ExpressionIR operands".to_owned())
}

fn normalized_result_zero(
    semantic: &ExpressionInstruction,
    family: &str,
) -> Result<HighExpr, String> {
    let (result, zero) = normalized_zero_flag(semantic)?;
    let operator = match family {
        "add" => ExpressionBinaryOperator::Add,
        "sub" => ExpressionBinaryOperator::Subtract,
        "and" => ExpressionBinaryOperator::And,
        "or" => ExpressionBinaryOperator::Or,
        "xor" => ExpressionBinaryOperator::Xor,
        _ => return Err("typed CFG has no normalized arithmetic flag result".to_owned()),
    };
    if !zero_constant(zero)
        || !matches!(result, Expression::Binary { operator: actual, width_bits: 64, .. } if *actual == operator)
    {
        return Err("typed CFG arithmetic flag result differs from its register write".to_owned());
    }
    scalar_expression(result)
}

fn normalized_zero_branch(semantic: &ExpressionInstruction, family: &str) -> bool {
    let flag_read = |expression: &Expression| matches!(expression, Expression::Read { source, width_bits: 1 } if source.component == "flag:zf");
    match (family, semantic.condition.as_ref()) {
        ("je" | "jz", Some(condition)) => flag_read(condition),
        (
            "jne" | "jnz",
            Some(Expression::Binary {
                operator: ExpressionBinaryOperator::Xor,
                width_bits: 1,
                left,
                right,
            }),
        ) => {
            flag_read(left)
                && matches!(
                    right.as_ref(),
                    Expression::Constant {
                        value: 1,
                        width_bits: 1
                    }
                )
        }
        _ => false,
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
    Logical,
    Add,
}

fn writes_flags(instruction: &MachineInstruction) -> bool {
    matches!(
        &instruction.operation,
        MachineOperation::Exact { family }
            if matches!(family.as_str(), "cmp" | "test" | "add" | "sub" | "xor" | "and" | "or")
    )
}

// A flag-setting instruction needs C snapshots only when some branch reads its
// flags before the next write. Work backwards through edges so loops and joins
// keep the same snapshots as straight-line code.
fn flag_snapshot_sites(machine: &MachineFunctionIr) -> Result<BTreeSet<Location>, String> {
    let mut live_in = machine
        .blocks
        .iter()
        .map(|block| (block.address, false))
        .collect::<BTreeMap<_, _>>();
    for _ in 0..(machine.blocks.len() * 4 + 1) {
        let mut changed = false;
        for block in machine.blocks.iter().rev() {
            let last = block
                .instructions
                .last()
                .ok_or("typed CFG block is empty")?;
            let mut live = last
                .edges
                .iter()
                .filter_map(|edge| edge.target)
                .any(|target| live_in.get(&target).copied().unwrap_or(false));
            for instruction in block.instructions.iter().rev() {
                if instruction.effects.control == MachineControlEffect::ConditionalBranch {
                    live = true;
                }
                if writes_flags(instruction) {
                    live = false;
                }
            }
            changed |= live_in.insert(block.address, live) != Some(live);
        }
        if !changed {
            let mut sites = BTreeSet::new();
            for block in &machine.blocks {
                let last = block.instructions.last().unwrap();
                let mut live = last
                    .edges
                    .iter()
                    .filter_map(|edge| edge.target)
                    .any(|target| live_in.get(&target).copied().unwrap_or(false));
                for instruction in block.instructions.iter().rev() {
                    if instruction.effects.control == MachineControlEffect::ConditionalBranch {
                        live = true;
                    }
                    if writes_flags(instruction) {
                        if live {
                            sites.insert(instruction.address);
                        }
                        live = false;
                    }
                }
            }
            return Ok(sites);
        }
    }
    Err("typed CFG flag liveness did not converge".to_owned())
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
        "test" => Some(FlagSource::Logical),
        // SUB and CMP set CF/SF/OF/ZF from the same ordered operands. The
        // destination write must not replace those operands before a branch.
        "sub" => Some(FlagSource::Compare),
        "add" => Some(FlagSource::Add),
        "xor" | "and" | "or" => Some(FlagSource::Logical),
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
    if source == Some(FlagSource::Add) {
        return addition_predicate(family);
    }
    // Keep the direct two-operand form when the branch reads only ZF. The
    // structurer can then fold sole-reader snapshots back into readable C.
    let simple_zero = match (source, family) {
        (Some(FlagSource::Logical), "je" | "jz" | "jbe" | "jna") => Some(HighCfgCompareOp::Equal),
        (Some(FlagSource::Logical), "jne" | "jnz" | "ja" | "jnbe") => {
            Some(HighCfgCompareOp::NotEqual)
        }
        _ => None,
    };
    if let Some(op) = simple_zero {
        return Ok(HighCfgPredicate {
            op,
            left: HighExpr::Variable {
                name: FLAG_LEFT.to_owned(),
            },
            right: HighExpr::Variable {
                name: FLAG_RIGHT.to_owned(),
            },
        });
    }
    if source == Some(FlagSource::Logical) {
        return logical_flag_predicate(
            family,
            HighExpr::Variable {
                name: FLAG_LEFT.to_owned(),
            },
        );
    }
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

/// TEST, AND, OR, and XOR clear CF and OF. Their signed and unsigned branches
/// therefore depend only on the sign and zero bits of the exact 64-bit result.
fn logical_flag_predicate(family: &str, result: HighExpr) -> Result<HighCfgPredicate, String> {
    let zero = HighExpr::Constant { value: 0 };
    let high_bit = HighExpr::Constant {
        value: 0x8000_0000_0000_0000,
    };
    let (op, left, right) = match family {
        "je" | "jz" | "jbe" | "jna" => (HighCfgCompareOp::Equal, result, zero),
        "jne" | "jnz" | "ja" | "jnbe" => (HighCfgCompareOp::NotEqual, result, zero),
        "js" | "jl" | "jnge" => (HighCfgCompareOp::TestNonzero, result, high_bit),
        "jns" | "jge" | "jnl" => (HighCfgCompareOp::TestZero, result, high_bit),
        "jle" | "jng" => (HighCfgCompareOp::SignedLessEqual, result, zero),
        "jg" | "jnle" => (HighCfgCompareOp::SignedGreater, result, zero),
        "jb" | "jc" | "jnae" | "jo" => (
            HighCfgCompareOp::NotEqual,
            HighExpr::Constant { value: 0 },
            HighExpr::Constant { value: 0 },
        ),
        "jae" | "jnb" | "jnc" | "jno" => (
            HighCfgCompareOp::Equal,
            HighExpr::Constant { value: 0 },
            HighExpr::Constant { value: 0 },
        ),
        _ => {
            return Err(format!(
                "typed CFG has no supported logical flag proof for {family}"
            ));
        }
    };
    Ok(HighCfgPredicate { op, left, right })
}

fn addition_predicate(family: &str) -> Result<HighCfgPredicate, String> {
    let left = HighExpr::Variable {
        name: FLAG_LEFT.to_owned(),
    };
    let right = HighExpr::Variable {
        name: FLAG_RIGHT.to_owned(),
    };
    let sum = HighExpr::Binary {
        op: BinaryOp::Add,
        left: Box::new(left.clone()),
        right: Box::new(right.clone()),
    };
    let high_bit = HighExpr::Constant {
        value: 0x8000_0000_0000_0000,
    };
    let overflow_bits = HighExpr::Binary {
        op: BinaryOp::And,
        left: Box::new(HighExpr::Binary {
            op: BinaryOp::Xor,
            left: Box::new(left.clone()),
            right: Box::new(sum.clone()),
        }),
        right: Box::new(HighExpr::Binary {
            op: BinaryOp::Xor,
            left: Box::new(right),
            right: Box::new(sum.clone()),
        }),
    };
    let (op, left, right) = match family {
        "je" | "jz" => (
            HighCfgCompareOp::Equal,
            sum,
            HighExpr::Constant { value: 0 },
        ),
        "jne" | "jnz" => (
            HighCfgCompareOp::NotEqual,
            sum,
            HighExpr::Constant { value: 0 },
        ),
        "jb" | "jc" | "jnae" => (HighCfgCompareOp::UnsignedLess, sum, left),
        "jae" | "jnb" | "jnc" => (HighCfgCompareOp::UnsignedGreaterEqual, sum, left),
        "jo" => (HighCfgCompareOp::TestNonzero, overflow_bits, high_bit),
        "jno" => (HighCfgCompareOp::TestZero, overflow_bits, high_bit),
        "js" => (HighCfgCompareOp::TestNonzero, sum, high_bit),
        "jns" => (HighCfgCompareOp::TestZero, sum, high_bit),
        _ => {
            return Err(format!(
                "typed CFG has no supported addition flag proof for {family}"
            ));
        }
    };
    Ok(HighCfgPredicate { op, left, right })
}

fn push_assignment(
    statements: &mut Vec<HighCfgStatement>,
    target: String,
    value: HighExpr,
    site: Location,
) {
    statements.push(HighCfgStatement::Assign {
        target,
        value,
        site,
    });
}

fn lower_instruction(
    instruction: &MachineInstruction,
    semantic: &ExpressionInstruction,
    field_roots: &BTreeMap<String, FieldRoot>,
    index_roots: &BTreeMap<String, IndexRoot>,
    model: &AnalysisModel,
    flag_source: &mut Option<FlagSource>,
    snapshot_flags: bool,
    statements: &mut Vec<HighCfgStatement>,
) -> Result<Option<HighCfgTerminator>, String> {
    if instruction.address != semantic.address
        || instruction.bytes_hex != semantic.bytes_hex
        || instruction.mnemonic != semantic.mnemonic
        || instruction.edges != semantic.edges
    {
        return Err("typed CFG MachineIR and ExpressionIR instruction differ".to_owned());
    }
    let MachineOperation::Exact { family } = &instruction.operation else {
        return Err("typed CFG cannot lower an opaque operation".to_owned());
    };
    if instruction.effects.conservative
        || instruction.decorators != Default::default()
        || (instruction.effects.memory != MachineMemoryEffect::None
            && !(family == "ret" && instruction.effects.memory == MachineMemoryEffect::Read)
            && !(family == "mov"
                && matches!(
                    instruction.effects.memory,
                    MachineMemoryEffect::Read | MachineMemoryEffect::Write
                )))
    {
        return Err(format!(
            "typed CFG effect at 0x{:x} is unsupported",
            instruction.address.value.0
        ));
    }
    let site = instruction.address;
    let operands = instruction.operands.as_slice();
    let terminator = match (family.as_str(), operands) {
        ("mov", [destination, MachineOperand::Memory { width_bits: 64, .. }])
            if instruction.effects.control == MachineControlEffect::Next
                && instruction.effects.memory == MachineMemoryEffect::Read =>
        {
            let target = register(destination)?;
            let register_name = target.strip_prefix("hydir_").unwrap();
            let (address, memory_inputs, field_view) =
                normalized_memory_load(semantic, register_name, field_roots, index_roots, model)?;
            statements.push(HighCfgStatement::Load {
                target,
                address,
                width_bits: 64,
                byte_order: MemoryByteOrder::Little,
                memory_inputs,
                field_view,
                site,
            });
            None
        }
        ("mov", [MachineOperand::Memory { width_bits: 64, .. }, _source])
            if instruction.effects.control == MachineControlEffect::Next
                && instruction.effects.memory == MachineMemoryEffect::Write =>
        {
            let (address, value, memory_inputs, memory_outputs, field_view) =
                normalized_memory_store(semantic, field_roots, index_roots, model)?;
            statements.push(HighCfgStatement::Store {
                address,
                value,
                width_bits: 64,
                byte_order: MemoryByteOrder::Little,
                memory_inputs,
                memory_outputs,
                field_view,
                site,
            });
            None
        }
        ("mov", [destination, _source])
            if instruction.effects.control == MachineControlEffect::Next
                && instruction.effects.memory == MachineMemoryEffect::None =>
        {
            let target = register(destination)?;
            let register_name = target.strip_prefix("hydir_").unwrap();
            let expression = normalized_register_value(semantic, register_name)?;
            push_assignment(statements, target, expression, site);
            None
        }
        ("lea", [destination, MachineOperand::Memory { .. }])
            if instruction.effects.control == MachineControlEffect::Next
                && instruction.effects.memory == MachineMemoryEffect::None =>
        {
            let target = register(destination)?;
            let register_name = target.strip_prefix("hydir_").unwrap();
            if semantic.residual.is_some()
                || semantic.assignments.len() != 1
                || !matches!(
                    &semantic.assignments[0].value,
                    Expression::EffectiveAddress { .. }
                )
            {
                return Err("typed CFG LEA lacks normalized effective-address semantics".to_owned());
            }
            let expression = normalized_register_value(semantic, register_name)?;
            push_assignment(statements, target, expression, site);
            None
        }
        ("sub", [destination, _source])
            if instruction.effects.control == MachineControlEffect::Next =>
        {
            let target = register(destination)?;
            let register_name = target.strip_prefix("hydir_").unwrap();
            let expression = normalized_register_value(semantic, register_name)?;
            if snapshot_flags {
                if normalized_result_zero(semantic, family)? != expression {
                    return Err("typed CFG subtraction result and flags disagree".to_owned());
                }
                let HighExpr::Binary {
                    op: BinaryOp::Sub,
                    left,
                    right,
                } = &expression
                else {
                    return Err("typed CFG subtraction lacks ordered operands".to_owned());
                };
                push_assignment(statements, FLAG_LEFT.to_owned(), *left.clone(), site);
                push_assignment(statements, FLAG_RIGHT.to_owned(), *right.clone(), site);
            }
            push_assignment(statements, target, expression, site);
            *flag_source = Some(FlagSource::Compare);
            None
        }
        ("add", [destination, _source])
            if instruction.effects.control == MachineControlEffect::Next =>
        {
            let target = register(destination)?;
            let register_name = target.strip_prefix("hydir_").unwrap();
            let expression = normalized_register_value(semantic, register_name)?;
            if snapshot_flags {
                if normalized_result_zero(semantic, family)? != expression {
                    return Err("typed CFG addition result and flags disagree".to_owned());
                }
                let HighExpr::Binary {
                    op: BinaryOp::Add,
                    left,
                    right,
                } = &expression
                else {
                    return Err("typed CFG addition lacks ordered operands".to_owned());
                };
                push_assignment(statements, FLAG_LEFT.to_owned(), *left.clone(), site);
                push_assignment(statements, FLAG_RIGHT.to_owned(), *right.clone(), site);
            }
            push_assignment(statements, target, expression, site);
            *flag_source = Some(FlagSource::Add);
            None
        }
        ("xor" | "and" | "or", [destination, _source])
            if instruction.effects.control == MachineControlEffect::Next =>
        {
            let target = register(destination)?;
            let register_name = target.strip_prefix("hydir_").unwrap();
            let expression = normalized_register_value(semantic, register_name)?;
            if snapshot_flags && normalized_result_zero(semantic, family)? != expression {
                return Err("typed CFG arithmetic result and zero flag disagree".to_owned());
            }
            push_assignment(statements, target.clone(), expression, site);
            if snapshot_flags {
                push_assignment(
                    statements,
                    FLAG_LEFT.to_owned(),
                    HighExpr::Variable { name: target },
                    site,
                );
                push_assignment(
                    statements,
                    FLAG_RIGHT.to_owned(),
                    HighExpr::Constant { value: 0 },
                    site,
                );
            }
            *flag_source = Some(FlagSource::Logical);
            None
        }
        ("cmp", [_left, _right]) if instruction.effects.control == MachineControlEffect::Next => {
            // Snapshot operands now: later register writes must not alter the flags.
            if snapshot_flags {
                let (left, right) = normalized_flag_operands(semantic, family)?;
                push_assignment(statements, FLAG_LEFT.to_owned(), left, site);
                push_assignment(statements, FLAG_RIGHT.to_owned(), right, site);
            }
            *flag_source = Some(FlagSource::Compare);
            None
        }
        ("test", [_left, _right]) if instruction.effects.control == MachineControlEffect::Next => {
            if snapshot_flags {
                let (left, right) = normalized_flag_operands(semantic, family)?;
                push_assignment(
                    statements,
                    FLAG_LEFT.to_owned(),
                    HighExpr::Binary {
                        op: BinaryOp::And,
                        left: Box::new(left),
                        right: Box::new(right),
                    },
                    site,
                );
                push_assignment(
                    statements,
                    FLAG_RIGHT.to_owned(),
                    HighExpr::Constant { value: 0 },
                    site,
                );
            }
            *flag_source = Some(FlagSource::Logical);
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
            if semantic.condition.is_none()
                || (matches!(family, "je" | "jz" | "jne" | "jnz")
                    && !normalized_zero_branch(semantic, family))
            {
                return Err("typed CFG branch lacks matching ExpressionIR condition".to_owned());
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

/// Lower the supported 64-bit SysV CFG, including normalized MOV memory
/// effects. Unsupported operations reject this view; low-level C remains
/// available.
pub fn lower_high_level_cfg_cir(
    machine: &MachineFunctionIr,
    function: &FunctionIr,
    model: &AnalysisModel,
) -> Result<HighLevelCfgCir, String> {
    let state = lower_state_ir(machine)?;
    let expression = lower_expression_ir(machine, &state)?;
    lower_high_level_cfg_cir_from_expression(machine, function, model, &expression)
}

// Consume freshly validated ExpressionIR scalar writes and zero-flag
// expressions. Other branch predicates still use the bounded compare/test
// interpretation of their recovered operands.
fn lower_high_level_cfg_cir_from_expression(
    machine: &MachineFunctionIr,
    function: &FunctionIr,
    model: &AnalysisModel,
    expression: &ExpressionFunctionIr,
) -> Result<HighLevelCfgCir, String> {
    validate_structure(model)?;
    validate_machine_function_ir(machine)?;
    validate_function_ir(function)?;
    validate_expression_function_ir(expression)?;
    if machine.binary_sha256 != model.binary_sha256
        || function.binary_sha256 != model.binary_sha256
        || expression.binary_sha256 != model.binary_sha256
        || machine.entry != function.entry
        || machine.entry != expression.entry
        || machine.function_id != function.function_id
        || machine.function_id != expression.function_id
        || machine.structural_completeness != StructuralCompleteness::Complete
        || machine.semantic_fidelity != SemanticFidelity::ExactUnderModel
        || expression.structural_completeness != StructuralCompleteness::Complete
        || machine.blocks.is_empty()
        || machine.blocks.len() > 4096
        || machine.blocks.len() != expression.blocks.len()
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
    if parameters.iter().any(|parameter| {
        parameter.ty != u64_type()
            && !matches!(&parameter.ty, TypeRef::Pointer { to } if matches!(to.as_ref(), TypeRef::Named { .. }))
    }) {
        return Err("typed CFG requires uint64_t or pointer-to-named parameters".to_owned());
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
    let flag_snapshots = flag_snapshot_sites(machine)?;
    let field_roots = stable_field_roots(&parameters, expression);
    let index_roots = stable_index_roots(&parameters, expression);
    let mut blocks = Vec::with_capacity(machine.blocks.len());
    for (block, expression_block) in machine.blocks.iter().zip(&expression.blocks) {
        if block.address != expression_block.address
            || block.instructions.len() != expression_block.instructions.len()
        {
            return Err("typed CFG MachineIR and ExpressionIR blocks differ".to_owned());
        }
        let mut statements = Vec::new();
        let mut flag_source = *flag_input
            .get(&block.address)
            .ok_or("typed CFG block flag state is missing")?;
        let mut terminator = None;
        for (index, (instruction, semantic)) in block
            .instructions
            .iter()
            .zip(&expression_block.instructions)
            .enumerate()
        {
            if terminator.is_some() {
                return Err("typed CFG has instructions after a control transfer".to_owned());
            }
            terminator = lower_instruction(
                instruction,
                semantic,
                &field_roots,
                &index_roots,
                model,
                &mut flag_source,
                flag_snapshots.contains(&instruction.address),
                &mut statements,
            )?;
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

fn valid_memory_versions(versions: &[StateComponentVersion]) -> bool {
    !versions.is_empty()
        && versions.len() <= 16
        && versions
            .iter()
            .all(|version| version.component.starts_with("memory:"))
        && versions.iter().collect::<BTreeSet<_>>().len() == versions.len()
}

fn validate_field_view(view: &HighCfgFieldView, address: &HighExpr) -> Result<(), String> {
    if view.type_id.is_empty()
        || !valid_ident(&view.type_name)
        || !valid_ident(&view.field)
        || !matches!(&view.base, HighExpr::Variable { name } if valid_local(name))
        || view.derived_base.as_ref().is_some_and(|derived| {
            !derived
                .register
                .strip_prefix("hydir_")
                .is_some_and(|register| REGISTERS.contains(&register))
                || matches!(&view.base, HighExpr::Variable { name } if name == &derived.register)
        })
        || view.array_element.as_ref().is_some_and(|element| {
            view.array_index.is_none()
                || element.element_type_id.is_empty()
                || !valid_ident(&element.element_type_name)
                || !valid_ident(&element.field)
                || !matches!(element.raw_scale, 1 | 2 | 4 | 8)
                || !(1..=1_000_000).contains(&element.index_multiplier)
                || !element
                    .raw_index
                    .strip_prefix("hydir_")
                    .is_some_and(|register| REGISTERS.contains(&register))
        })
        || field_view_address(view).as_ref() != Some(address)
    {
        return Err("typed CFG field annotation differs from its address".to_owned());
    }
    if let Some(index) = &view.array_index {
        scalar_reads(index, &mut BTreeSet::new(), 0)?;
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
        if (parameter.ty != u64_type()
            && !matches!(&parameter.ty, TypeRef::Pointer { to } if matches!(to.as_ref(), TypeRef::Named { .. })))
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
            if statement.site().address_space != ir.entry.address_space
                || statement.site().value.0 < block.address.value.0
            {
                return Err("typed CFG assignment site differs from its block".to_owned());
            }
            match statement {
                HighCfgStatement::Assign { target, value, .. } => {
                    if !valid_local(target) {
                        return Err("typed CFG has an invalid assignment target".to_owned());
                    }
                    scalar_reads(value, &mut BTreeSet::new(), 0)?;
                }
                HighCfgStatement::Load {
                    target,
                    address,
                    width_bits,
                    memory_inputs,
                    field_view,
                    ..
                } => {
                    if !valid_local(target)
                        || *width_bits != 64
                        || !valid_memory_versions(memory_inputs)
                    {
                        return Err("typed CFG has an invalid memory load".to_owned());
                    }
                    scalar_reads(address, &mut BTreeSet::new(), 0)?;
                    if let Some(view) = field_view {
                        validate_field_view(view, address)?;
                    }
                }
                HighCfgStatement::Store {
                    address,
                    value,
                    width_bits,
                    memory_inputs,
                    memory_outputs,
                    field_view,
                    ..
                } => {
                    if *width_bits != 64
                        || !valid_memory_versions(memory_inputs)
                        || !valid_memory_versions(memory_outputs)
                        || memory_inputs
                            .iter()
                            .map(|version| &version.component)
                            .collect::<BTreeSet<_>>()
                            != memory_outputs
                                .iter()
                                .map(|version| &version.component)
                                .collect::<BTreeSet<_>>()
                    {
                        return Err("typed CFG has an invalid memory store".to_owned());
                    }
                    scalar_reads(address, &mut BTreeSet::new(), 0)?;
                    scalar_reads(value, &mut BTreeSet::new(), 0)?;
                    if let Some(view) = field_view {
                        validate_field_view(view, address)?;
                    }
                }
            }
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
                    .filter_map(|statement| match statement {
                        HighCfgStatement::Assign { target, .. }
                        | HighCfgStatement::Load { target, .. } => Some(target.clone()),
                        HighCfgStatement::Store { .. } => None,
                    }),
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
            match statement {
                HighCfgStatement::Assign { target, value, .. } => {
                    expression_is_initialized(value, &initialized)?;
                    initialized.insert(target.clone());
                }
                HighCfgStatement::Load {
                    target, address, ..
                } => {
                    expression_is_initialized(address, &initialized)?;
                    initialized.insert(target.clone());
                }
                HighCfgStatement::Store { address, value, .. } => {
                    expression_is_initialized(address, &initialized)?;
                    expression_is_initialized(value, &initialized)?;
                }
            }
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
                BinaryOp::Mul => "*",
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

fn c_memory_address(address: &HighExpr, field_view: &Option<HighCfgFieldView>) -> String {
    let Some(view) = field_view else {
        return c_expr(address);
    };
    let kind = match view.aggregate_kind {
        HighCfgAggregateKind::Struct => "struct",
        HighCfgAggregateKind::Union => "union",
    };
    let offset = format!(
        "(uint64_t)offsetof({kind} {}, {})",
        view.type_name, view.field
    );
    let (base, offset) = if let Some(derived) = &view.derived_base {
        let correction = if derived.origin_offset_bytes < 0 {
            format!(
                "({offset} + UINT64_C({}))",
                derived.origin_offset_bytes.unsigned_abs()
            )
        } else {
            format!("({offset} - UINT64_C({}))", derived.origin_offset_bytes)
        };
        (derived.register.clone(), correction)
    } else {
        (c_expr(&view.base), offset)
    };
    if let Some(element) = &view.array_element {
        return format!(
            "((({base} + {offset}) + ({} * ((uint64_t)sizeof(struct {}) / UINT64_C({})))) + (uint64_t)offsetof(struct {}, {}))",
            element.raw_index,
            element.element_type_name,
            element.index_multiplier,
            element.element_type_name,
            element.field
        );
    }
    match &view.array_index {
        None => format!("({base} + {offset})"),
        Some(index) => format!(
            "(({base} + {offset}) + ({} * (uint64_t)sizeof((({kind} {} *)0)->{}[0])))",
            c_expr(index),
            view.type_name,
            view.field
        ),
    }
}

fn c_statement(statement: &HighCfgStatement) -> String {
    match statement {
        HighCfgStatement::Assign { target, value, .. } => {
            format!("{target} = {};", c_expr(value))
        }
        HighCfgStatement::Load {
            target,
            address,
            field_view,
            ..
        } => format!(
            "{target} = hydir_load_u64({});",
            c_memory_address(address, field_view)
        ),
        HighCfgStatement::Store {
            address,
            value,
            field_view,
            ..
        } => {
            format!(
                "hydir_store_u64({}, {});",
                c_memory_address(address, field_view),
                c_expr(value)
            )
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
    format!("{left} {op} {right}")
}

fn c_label(address: Location) -> String {
    format!("hydir_bb_{}_{:x}", address.address_space, address.value.0)
}

fn validate_model_field_views(ir: &HighLevelCfgCir, model: &AnalysisModel) -> Result<(), String> {
    let model_row = model.functions.iter().find(|row| row.entry == ir.entry);
    let mut writes = BTreeMap::<&str, Vec<(Location, Option<&HighExpr>)>>::new();
    for block in &ir.blocks {
        for statement in &block.statements {
            match statement {
                HighCfgStatement::Assign { target, value, .. } => {
                    writes
                        .entry(target)
                        .or_default()
                        .push((block.address, Some(value)));
                }
                HighCfgStatement::Load { target, .. } => {
                    writes
                        .entry(target)
                        .or_default()
                        .push((block.address, None));
                }
                HighCfgStatement::Store { .. } => {}
            }
        }
    }
    for block in &ir.blocks {
        for statement in &block.statements {
            let view = match statement {
                HighCfgStatement::Load { field_view, .. }
                | HighCfgStatement::Store { field_view, .. } => field_view.as_ref(),
                HighCfgStatement::Assign { .. } => None,
            };
            let Some(view) = view else { continue };
            let definition = model
                .types
                .iter()
                .find(|definition| {
                    definition.id == view.type_id && definition.name == view.type_name
                })
                .ok_or("typed CFG field annotation has no matching model type")?;
            let (kind, fields) = aggregate_fields(definition)
                .ok_or("typed CFG field annotation refers to a non-aggregate")?;
            if kind != view.aggregate_kind
                || (kind == HighCfgAggregateKind::Union && fields.len() > 1)
            {
                return Err("typed CFG field annotation differs from model layout".to_owned());
            }
            let mut matching_fields = fields.iter().filter(|field| {
                field.name == view.field && field.offset_bytes == view.offset_bytes
            });
            let Some(field) = matching_fields.next() else {
                return Err("typed CFG field annotation differs from model layout".to_owned());
            };
            if matching_fields.next().is_some() {
                return Err("typed CFG field annotation is ambiguous".to_owned());
            }
            if let Some(element) = &view.array_element {
                let TypeRef::Array { of, .. } = &field.ty else {
                    return Err("typed CFG element view has no array field".to_owned());
                };
                let TypeRef::Named { id } = of.as_ref() else {
                    return Err("typed CFG array element is not a named type".to_owned());
                };
                let element_type = model
                    .types
                    .iter()
                    .find(|item| {
                        item.id == *id
                            && item.id == element.element_type_id
                            && item.name == element.element_type_name
                    })
                    .ok_or("typed CFG array element type differs from model")?;
                let TypeDefinitionKind::Struct {
                    fields: element_fields,
                } = &element_type.kind
                else {
                    return Err("typed CFG array element is not a struct".to_owned());
                };
                if element_type.size_is_lower_bound
                    || element
                        .index_multiplier
                        .checked_mul(u64::from(element.raw_scale))
                        != Some(element_type.size_bytes)
                    || element_fields
                        .iter()
                        .filter(|candidate| {
                            candidate.name == element.field
                                && candidate.offset_bytes == element.field_offset_bytes
                                && eight_byte_type(&candidate.ty)
                        })
                        .count()
                        != 1
                {
                    return Err(
                        "typed CFG array element layout or stride differs from model".to_owned(),
                    );
                }
                let Some(HighExpr::Variable {
                    name: logical_index,
                }) = &view.array_index
                else {
                    return Err(
                        "typed CFG array element needs an invariant integer index".to_owned()
                    );
                };
                let (logical_position, logical_parameter) = ir
                    .parameters
                    .iter()
                    .enumerate()
                    .find(|(_, parameter)| {
                        parameter.ty == u64_type()
                            && local(&parameter.location).ok().as_deref() == Some(logical_index)
                    })
                    .ok_or("typed CFG array index is not an integer parameter")?;
                if writes.contains_key(logical_index.as_str()) {
                    return Err("typed CFG array index is not an invariant parameter".to_owned());
                }
                let index_row = model_row.ok_or("typed CFG array index has no function model")?;
                let modeled_index_type = index_row
                    .prototype
                    .as_ref()
                    .and_then(|prototype| {
                        prototype
                            .parameters
                            .get(logical_position)
                            .map(|item| &item.ty)
                    })
                    .or_else(|| {
                        index_row
                            .inferred_parameters
                            .get(&logical_parameter.location)
                    });
                if modeled_index_type != Some(&logical_parameter.ty) {
                    return Err("typed CFG array index differs from current model".to_owned());
                }
                if element.raw_index == *logical_index {
                    if element.index_multiplier != 1 {
                        return Err(
                            "typed CFG direct array index has a nonunit multiplier".to_owned()
                        );
                    }
                } else {
                    if ir.parameters.iter().any(|parameter| {
                        local(&parameter.location).ok().as_deref()
                            == Some(element.raw_index.as_str())
                    }) {
                        return Err(
                            "typed CFG derived array index is an input parameter".to_owned()
                        );
                    }
                    let Some(assignments) = writes.get(element.raw_index.as_str()) else {
                        return Err("typed CFG derived array index has no assignment".to_owned());
                    };
                    let [(site, Some(value))] = assignments.as_slice() else {
                        return Err("typed CFG derived array index has multiple writes".to_owned());
                    };
                    if *site != ir.entry
                        || affine_coefficient(value, logical_index, 0)
                            != Some((element.index_multiplier, 0))
                    {
                        return Err(
                            "typed CFG derived array index lacks a dominating scale proof"
                                .to_owned(),
                        );
                    }
                }
            } else if !eight_byte_field(field, view.array_index.is_some()) {
                return Err("typed CFG scalar field width differs from model".to_owned());
            }
            let HighExpr::Variable { name: base } = &view.base else {
                return Err("typed CFG field base is not an invariant parameter".to_owned());
            };
            if writes.contains_key(base.as_str()) {
                return Err("typed CFG modeled field base is modified".to_owned());
            }
            let (index, parameter) = ir
                .parameters
                .iter()
                .enumerate()
                .find(|(_, parameter)| local(&parameter.location).ok().as_ref() == Some(base))
                .ok_or("typed CFG modeled field base is not a parameter")?;
            if !matches!(&parameter.ty, TypeRef::Pointer { to } if matches!(to.as_ref(), TypeRef::Named { id } if id == &view.type_id))
            {
                return Err("typed CFG modeled field base has a different pointer type".to_owned());
            }
            let row = model_row.ok_or("typed CFG modeled field has no function model")?;
            let modeled_type = row
                .prototype
                .as_ref()
                .and_then(|prototype| prototype.parameters.get(index).map(|item| &item.ty))
                .or_else(|| row.inferred_parameters.get(&parameter.location));
            if modeled_type != Some(&parameter.ty) {
                return Err("typed CFG field parameter differs from current model".to_owned());
            }
            if let Some(derived) = &view.derived_base {
                if ir.parameters.iter().any(|parameter| {
                    local(&parameter.location).ok().as_deref() == Some(derived.register.as_str())
                }) {
                    return Err("typed CFG derived field register is an input parameter".to_owned());
                }
                let Some(assignments) = writes.get(derived.register.as_str()) else {
                    return Err("typed CFG derived field register has no assignment".to_owned());
                };
                let expected = if derived.origin_offset_bytes == 0 {
                    view.base.clone()
                } else {
                    HighExpr::Binary {
                        op: if derived.origin_offset_bytes < 0 {
                            BinaryOp::Sub
                        } else {
                            BinaryOp::Add
                        },
                        left: Box::new(view.base.clone()),
                        right: Box::new(HighExpr::Constant {
                            value: derived.origin_offset_bytes.unsigned_abs(),
                        }),
                    }
                };
                if assignments.as_slice() != [(ir.entry, Some(&expected))] {
                    return Err(
                        "typed CFG derived field base lacks one dominating assignment".to_owned(),
                    );
                }
            }
        }
    }
    Ok(())
}

/// Emit strict C11 for the bounded CFG. Gotos preserve loops and joins
/// exactly; a later structuring pass may replace them when it can prove shape.
pub fn emit_typed_cfg_c(ir: &HighLevelCfgCir, model: &AnalysisModel) -> Result<String, String> {
    validate_structure(model)?;
    validate_high_level_cfg_cir(ir)?;
    if ir.binary_sha256 != model.binary_sha256 || ir.model_revision != model.revision {
        return Err("typed CFG model identity/revision differs".to_owned());
    }
    validate_model_field_views(ir, model)?;
    let body = structure::emit_body(ir);
    let mut output = String::from("#include <stdint.h>\n#include <stddef.h>\n\n");
    let mut used_types = BTreeSet::new();
    for parameter in &ir.parameters {
        collect_used_types(&parameter.ty, model, &mut used_types, 0)?;
    }
    if !used_types.is_empty() {
        output.push_str(&emit_model_type_declarations(model, &used_types)?);
    }
    if ir.blocks.iter().any(|block| {
        block
            .statements
            .iter()
            .any(|statement| matches!(statement, HighCfgStatement::Load { .. }))
    }) {
        output.push_str(
            r#"#ifndef HYDIR_LOAD_U64_V1
#define HYDIR_LOAD_U64_V1
static inline uint64_t hydir_load_u64(uint64_t address) {
  const unsigned char *bytes = (const unsigned char *)(uintptr_t)address;
  uint64_t value = UINT64_C(0);
  for (unsigned i = 0; i < 8; ++i) value |= ((uint64_t)bytes[i]) << (i * 8u);
  return value;
}
#endif

"#,
        );
    }
    if ir.blocks.iter().any(|block| {
        block
            .statements
            .iter()
            .any(|statement| matches!(statement, HighCfgStatement::Store { .. }))
    }) {
        output.push_str(
            r#"#ifndef HYDIR_STORE_U64_V1
#define HYDIR_STORE_U64_V1
static inline void hydir_store_u64(uint64_t address, uint64_t value) {
  unsigned char *bytes = (unsigned char *)(uintptr_t)address;
  for (unsigned i = 0; i < 8; ++i) bytes[i] = (unsigned char)(value >> (i * 8u));
}
#endif

"#,
        );
    }
    output.push_str(&format!("uint64_t {}(", ir.name));
    if ir.parameters.is_empty() {
        output.push_str("void");
    }
    for (index, parameter) in ir.parameters.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        output.push_str(&c_decl(&parameter.ty, &parameter.name, model)?);
    }
    output.push_str(") {\n");
    let mut used = BTreeSet::new();
    for parameter in &ir.parameters {
        used.insert(local(&parameter.location)?);
    }
    let mut reads = BTreeSet::new();
    for block in &ir.blocks {
        for statement in &block.statements {
            match statement {
                HighCfgStatement::Assign { target, value, .. } => {
                    used.insert(target.clone());
                    scalar_reads(value, &mut reads, 0)?;
                }
                HighCfgStatement::Load {
                    target, address, ..
                } => {
                    used.insert(target.clone());
                    scalar_reads(address, &mut reads, 0)?;
                }
                HighCfgStatement::Store { address, value, .. } => {
                    scalar_reads(address, &mut reads, 0)?;
                    scalar_reads(value, &mut reads, 0)?;
                }
            }
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
        let initializer = initializer
            .map(|parameter| {
                if parameter.ty == u64_type() {
                    parameter.name.clone()
                } else {
                    format!("(uint64_t)(uintptr_t){}", parameter.name)
                }
            })
            .unwrap_or_else(|| "UINT64_C(0)".to_owned());
        output.push_str(&format!("  uint64_t {name} = {initializer};\n"));
        if !reads.contains(name) {
            output.push_str(&format!("  (void){name};\n"));
        }
    }
    output.push_str(&body);
    output.push_str("}\n");
    Ok(output)
}
