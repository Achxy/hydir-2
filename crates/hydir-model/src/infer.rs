use crate::{
    AnalysisModel, ModelConflict, ModelEvidence, ModelField, ModelFunction, ModelSource,
    PrimitiveType, TypeDefinition, TypeDefinitionKind, TypeRef, validate_structure,
};
use hydir_core::Location;
use hydir_ir::{
    FunctionIr, MachineControlEffect, MachineEdgeKind, MachineFunctionIr, MachineInstruction,
    MachineMemoryEffect, MachineOperand, MachineOperation,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const ARG_REGS: [&str; 6] = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
const MAX_FUNCTIONS: usize = 256;
const MAX_STATES: usize = 16_384;
const MAX_FIELDS: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InferenceReport {
    pub schema_version: u32,
    pub analyzed_functions: usize,
    pub skipped_functions: usize,
    pub inferred_types: usize,
    pub inferred_pointer_fields: usize,
    pub propagated_parameter_types: usize,
    pub conflicts: usize,
    pub model_revision: u64,
    pub bounded: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct Origin {
    parameter: String,
    offset: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LoadedField {
    parameter: String,
    offset: u64,
    site: Location,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct FlowState {
    regs: BTreeMap<String, Origin>,
    slots: BTreeMap<i64, Origin>,
    loaded: BTreeMap<String, LoadedField>,
    loaded_slots: BTreeMap<i64, LoadedField>,
}

impl FlowState {
    fn meet(&mut self, other: &Self) -> bool {
        let old = self.clone();
        self.regs
            .retain(|key, value| other.regs.get(key) == Some(value));
        self.slots
            .retain(|key, value| other.slots.get(key) == Some(value));
        self.loaded
            .retain(|key, value| other.loaded.get(key) == Some(value));
        self.loaded_slots
            .retain(|key, value| other.loaded_slots.get(key) == Some(value));
        *self != old
    }
}

#[derive(Clone)]
struct Access {
    offset: u64,
    width_bytes: u64,
    site: Location,
}

#[derive(Clone)]
struct CallBinding {
    caller: Location,
    callee: Location,
    caller_parameter: String,
    callee_register: String,
    site: Location,
}

#[derive(Clone)]
struct FieldCallBinding {
    caller: Location,
    caller_parameter: String,
    field_offset: u64,
    field_site: Location,
    callee: Location,
    callee_register: String,
    call_site: Location,
}

fn loaded_field(
    operand: &MachineOperand,
    state: &FlowState,
    site: Location,
) -> Option<LoadedField> {
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
    let origin = state.regs.get(canonical_register(base))?;
    let offset = origin.offset.checked_add(*displacement)?;
    if !(0..=65_536).contains(&offset) {
        return None;
    }
    Some(LoadedField {
        parameter: origin.parameter.clone(),
        offset: offset as u64,
        site,
    })
}

fn canonical_register(name: &str) -> &str {
    match name {
        "edi" | "di" | "dil" => "rdi",
        "esi" | "si" | "sil" => "rsi",
        "edx" | "dx" | "dl" | "dh" => "rdx",
        "ecx" | "cx" | "cl" | "ch" => "rcx",
        "eax" | "ax" | "al" | "ah" => "rax",
        "ebx" | "bx" | "bl" | "bh" => "rbx",
        "ebp" | "bp" | "bpl" => "rbp",
        "esp" | "sp" | "spl" => "rsp",
        "r8d" | "r8w" | "r8b" => "r8",
        "r9d" | "r9w" | "r9b" => "r9",
        "r10d" | "r10w" | "r10b" => "r10",
        "r11d" | "r11w" | "r11b" => "r11",
        "r12d" | "r12w" | "r12b" => "r12",
        "r13d" | "r13w" | "r13b" => "r13",
        "r14d" | "r14w" | "r14b" => "r14",
        "r15d" | "r15w" | "r15b" => "r15",
        _ => name,
    }
}

fn stack_slot(operand: &MachineOperand) -> Option<i64> {
    let MachineOperand::Memory {
        segment,
        base,
        index,
        displacement,
        absolute,
        ..
    } = operand
    else {
        return None;
    };
    if segment.is_none() && base.as_deref() == Some("rbp") && index.is_none() && absolute.is_none()
    {
        Some(*displacement)
    } else {
        None
    }
}

fn transfer(instruction: &MachineInstruction, state: &mut FlowState) {
    let mut new_reg: Option<(String, Origin)> = None;
    let mut new_slot: Option<(i64, Origin)> = None;
    let mut new_loaded: Option<(String, LoadedField)> = None;
    let mut new_loaded_slot: Option<(i64, LoadedField)> = None;
    let mut written_slot = None;
    if let MachineOperation::Exact { family } = &instruction.operation {
        if family == "mov" && instruction.operands.len() == 2 {
            let dst = &instruction.operands[0];
            let src = &instruction.operands[1];
            match (dst, src) {
                (
                    MachineOperand::Register {
                        name,
                        width_bits: 64,
                    },
                    MachineOperand::Register {
                        name: source,
                        width_bits: 64,
                    },
                ) => {
                    if let Some(origin) = state.regs.get(canonical_register(source)) {
                        new_reg = Some((canonical_register(name).to_owned(), origin.clone()));
                    }
                    if let Some(field) = state.loaded.get(canonical_register(source)) {
                        new_loaded = Some((canonical_register(name).to_owned(), field.clone()));
                    }
                }
                (
                    MachineOperand::Register {
                        name,
                        width_bits: 64,
                    },
                    source,
                ) => {
                    if let Some(slot) = stack_slot(source) {
                        if let Some(origin) = state.slots.get(&slot) {
                            new_reg = Some((canonical_register(name).to_owned(), origin.clone()));
                        }
                        if let Some(field) = state.loaded_slots.get(&slot) {
                            new_loaded = Some((canonical_register(name).to_owned(), field.clone()));
                        }
                    } else if let Some(field) = loaded_field(source, state, instruction.address) {
                        new_loaded = Some((canonical_register(name).to_owned(), field));
                    }
                }
                (
                    destination,
                    MachineOperand::Register {
                        name,
                        width_bits: 64,
                    },
                ) => {
                    if let Some(slot) = stack_slot(destination) {
                        written_slot = Some(slot);
                        if let Some(origin) = state.regs.get(canonical_register(name)) {
                            new_slot = Some((slot, origin.clone()));
                        }
                        if let Some(field) = state.loaded.get(canonical_register(name)) {
                            new_loaded_slot = Some((slot, field.clone()));
                        }
                    }
                }
                (destination, _) => {
                    written_slot = stack_slot(destination);
                }
            }
        } else if family == "lea" && instruction.operands.len() == 2 {
            if let (
                MachineOperand::Register {
                    name,
                    width_bits: 64,
                },
                MachineOperand::Memory {
                    segment: None,
                    base: Some(base),
                    index: None,
                    displacement,
                    absolute: None,
                    ..
                },
            ) = (&instruction.operands[0], &instruction.operands[1])
            {
                if let Some(origin) = state.regs.get(canonical_register(base)) {
                    if let Some(offset) = origin.offset.checked_add(*displacement) {
                        new_reg = Some((
                            canonical_register(name).to_owned(),
                            Origin {
                                parameter: origin.parameter.clone(),
                                offset,
                            },
                        ));
                    }
                }
            }
        }
    } else {
        state.regs.clear();
        state.slots.clear();
        state.loaded.clear();
        state.loaded_slots.clear();
        return;
    }
    for register in &instruction.effects.written_registers {
        let register = canonical_register(register);
        state.regs.remove(register);
        state.loaded.remove(register);
        if register == "rbp" {
            state.slots.clear();
            state.loaded_slots.clear();
        }
    }
    if let Some(slot) = written_slot {
        state.slots.remove(&slot);
        state.loaded_slots.remove(&slot);
    }
    if matches!(
        instruction.effects.control,
        MachineControlEffect::DirectCall | MachineControlEffect::IndirectCall
    ) {
        for register in ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"] {
            state.regs.remove(register);
            state.loaded.remove(register);
        }
        state.slots.clear();
        state.loaded_slots.clear();
    }
    if let Some((register, origin)) = new_reg {
        state.regs.insert(register, origin);
    }
    if let Some((slot, origin)) = new_slot {
        state.slots.insert(slot, origin);
    }
    if let Some((register, field)) = new_loaded {
        state.loaded.insert(register, field);
    }
    if let Some((slot, field)) = new_loaded_slot {
        state.loaded_slots.insert(slot, field);
    }
}

fn flow_inputs(
    machine: &MachineFunctionIr,
    function: &FunctionIr,
) -> Result<BTreeMap<Location, FlowState>, String> {
    let blocks = machine
        .blocks
        .iter()
        .map(|block| (block.address, block))
        .collect::<BTreeMap<_, _>>();
    let mut entry = FlowState::default();
    for parameter in &function.parameters {
        if ARG_REGS.contains(&parameter.location.as_str()) {
            entry.regs.insert(
                parameter.location.clone(),
                Origin {
                    parameter: parameter.location.clone(),
                    offset: 0,
                },
            );
        }
    }
    let mut inputs = BTreeMap::from([(machine.entry, entry)]);
    let mut queue = VecDeque::from([machine.entry]);
    let mut iterations = 0;
    while let Some(location) = queue.pop_front() {
        iterations += 1;
        if iterations > MAX_STATES {
            return Err("pointer-origin dataflow exceeded worklist limit".to_owned());
        }
        let Some(block) = blocks.get(&location) else {
            continue;
        };
        let mut state = inputs[&location].clone();
        for instruction in &block.instructions {
            transfer(instruction, &mut state);
        }
        let successors = block
            .instructions
            .iter()
            .flat_map(|instruction| &instruction.edges)
            .filter(|edge| {
                matches!(
                    edge.kind,
                    MachineEdgeKind::Fallthrough
                        | MachineEdgeKind::Taken
                        | MachineEdgeKind::Direct
                        | MachineEdgeKind::IndirectTarget
                )
            })
            .filter_map(|edge| edge.target)
            .filter(|target| blocks.contains_key(target))
            .collect::<BTreeSet<_>>();
        for successor in successors {
            let changed = if let Some(old) = inputs.get_mut(&successor) {
                old.meet(&state)
            } else {
                inputs.insert(successor, state.clone());
                true
            };
            if changed {
                queue.push_back(successor);
            }
        }
    }
    Ok(inputs)
}

fn collect(
    machine: &MachineFunctionIr,
    function: &FunctionIr,
) -> Result<
    (
        BTreeMap<String, Vec<Access>>,
        Vec<CallBinding>,
        Vec<FieldCallBinding>,
    ),
    String,
> {
    let inputs = flow_inputs(machine, function)?;
    let call_targets = function
        .calls
        .iter()
        .filter_map(|call| call.target.map(|target| (call.site, target)))
        .collect::<BTreeMap<_, _>>();
    let mut accesses = BTreeMap::<String, Vec<Access>>::new();
    let mut calls = Vec::new();
    let mut field_calls = Vec::new();
    for block in &machine.blocks {
        let Some(mut state) = inputs.get(&block.address).cloned() else {
            continue;
        };
        for instruction in &block.instructions {
            if matches!(
                instruction.effects.memory,
                MachineMemoryEffect::Read
                    | MachineMemoryEffect::Write
                    | MachineMemoryEffect::ReadWrite
            ) {
                for operand in &instruction.operands {
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
                        continue;
                    };
                    let Some(origin) = state.regs.get(canonical_register(base)) else {
                        continue;
                    };
                    let Some(offset) = origin.offset.checked_add(*displacement) else {
                        continue;
                    };
                    if !(0..=65_536).contains(&offset) || !matches!(width_bits, 8 | 16 | 32 | 64) {
                        continue;
                    }
                    accesses
                        .entry(origin.parameter.clone())
                        .or_default()
                        .push(Access {
                            offset: offset as u64,
                            width_bytes: u64::from(*width_bits / 8),
                            site: instruction.address,
                        });
                }
            }
            if let Some(callee) = call_targets.get(&instruction.address) {
                for reg in ARG_REGS {
                    if let Some(origin) = state.regs.get(reg) {
                        if origin.offset == 0 {
                            calls.push(CallBinding {
                                caller: machine.entry,
                                callee: *callee,
                                caller_parameter: origin.parameter.clone(),
                                callee_register: reg.to_owned(),
                                site: instruction.address,
                            });
                        }
                    }
                    if let Some(field) = state.loaded.get(reg) {
                        field_calls.push(FieldCallBinding {
                            caller: machine.entry,
                            caller_parameter: field.parameter.clone(),
                            field_offset: field.offset,
                            field_site: field.site,
                            callee: *callee,
                            callee_register: reg.to_owned(),
                            call_site: instruction.address,
                        });
                    }
                }
            }
            transfer(instruction, &mut state);
        }
    }
    Ok((accesses, calls, field_calls))
}

fn scalar(width: u64) -> TypeRef {
    TypeRef::Primitive {
        name: match width {
            1 => PrimitiveType::U8,
            2 => PrimitiveType::U16,
            4 => PrimitiveType::U32,
            _ => PrimitiveType::U64,
        },
    }
}

fn inferred_struct_id(ty: &TypeRef) -> Option<&str> {
    let TypeRef::Pointer { to } = ty else {
        return None;
    };
    let TypeRef::Named { id } = to.as_ref() else {
        return None;
    };
    Some(id)
}

fn inferred_field_end(field: &ModelField) -> Option<u64> {
    let width = match &field.ty {
        TypeRef::Primitive { name } => name.size_bytes()?,
        TypeRef::Pointer { .. } => 8,
        _ => return None,
    };
    field.offset_bytes.checked_add(width)
}

fn fixed_access_matches_field(field: &ModelField, offset: u64, width: u64) -> bool {
    fn width_of(ty: &TypeRef) -> Option<u64> {
        match ty {
            TypeRef::Primitive { name } => name.size_bytes(),
            TypeRef::Pointer { .. } => Some(8),
            _ => None,
        }
    }
    match &field.ty {
        TypeRef::Array { of, count } => {
            let Some(element_width) = width_of(of) else {
                return false;
            };
            let Some(delta) = offset.checked_sub(field.offset_bytes) else {
                return false;
            };
            element_width == width && delta % element_width == 0 && delta / element_width < *count
        }
        other => field.offset_bytes == offset && width_of(other) == Some(width),
    }
}

/// Only copy constraints from a callee's inferred partial layout to a caller
/// that is proven to pass the unchanged pointer. Return None for an ambiguous
/// overlap or a layout that cannot be safely merged.
fn merge_inferred_callee_layout(
    model: &mut AnalysisModel,
    caller_ty: &TypeRef,
    callee_ty: &TypeRef,
) -> Option<bool> {
    let caller_id = inferred_struct_id(caller_ty)?;
    let callee_id = inferred_struct_id(callee_ty)?;
    let callee = model.types.iter().find(|ty| ty.id == callee_id)?;
    let TypeDefinitionKind::Struct {
        fields: callee_fields,
    } = &callee.kind
    else {
        return None;
    };
    if !callee.size_is_lower_bound {
        return None;
    }
    let callee_fields = callee_fields.clone();
    let caller = model.types.iter_mut().find(|ty| ty.id == caller_id)?;
    let TypeDefinitionKind::Struct {
        fields: caller_fields,
    } = &mut caller.kind
    else {
        return None;
    };
    if !caller.size_is_lower_bound {
        return None;
    }
    let mut merged = caller_fields.clone();
    let mut changed = false;
    for field in callee_fields {
        let end = inferred_field_end(&field)?;
        if let Some(existing) = merged
            .iter_mut()
            .find(|existing| existing.offset_bytes == field.offset_bytes)
        {
            if existing.ty != field.ty {
                return None;
            }
            for evidence in field.evidence {
                if !existing.evidence.contains(&evidence) && existing.evidence.len() < 256 {
                    existing.evidence.push(evidence);
                    changed = true;
                }
            }
        } else {
            if merged.iter().any(|existing| {
                inferred_field_end(existing).is_none_or(|old_end| {
                    field.offset_bytes < old_end && existing.offset_bytes < end
                })
            }) {
                return None;
            }
            merged.push(field);
            changed = true;
        }
    }
    if merged.len() > MAX_FIELDS {
        return None;
    }
    merged.sort_by_key(|field| field.offset_bytes);
    let end = merged
        .iter()
        .filter_map(inferred_field_end)
        .max()
        .unwrap_or(0);
    if end > 1_048_576 {
        return None;
    }
    if changed {
        *caller_fields = merged;
        caller.size_bytes = caller.size_bytes.max(end);
    }
    Some(changed)
}

fn parameter_type(model: &AnalysisModel, entry: Location, register: &str) -> Option<TypeRef> {
    let row = model.functions.iter().find(|row| row.entry == entry)?;
    let explicit = ARG_REGS
        .iter()
        .position(|name| *name == register)
        .and_then(|position| row.prototype.as_ref()?.parameters.get(position))
        .map(|parameter| parameter.ty.clone());
    explicit.or_else(|| row.inferred_parameters.get(register).cloned())
}

enum FieldResolution {
    Unknown,
    Compatible,
    Changed,
    Conflict,
}

fn resolve_loaded_pointer_field(
    model: &mut AnalysisModel,
    binding: &FieldCallBinding,
) -> FieldResolution {
    let Some(callee_ty) = parameter_type(model, binding.callee, &binding.callee_register) else {
        return FieldResolution::Unknown;
    };
    if inferred_struct_id(&callee_ty).is_none() {
        return FieldResolution::Unknown;
    }
    let Some(caller_ty) = parameter_type(model, binding.caller, &binding.caller_parameter) else {
        return FieldResolution::Unknown;
    };
    let Some(caller_id) = inferred_struct_id(&caller_ty) else {
        return FieldResolution::Unknown;
    };
    let Some(definition) = model.types.iter_mut().find(|ty| ty.id == caller_id) else {
        return FieldResolution::Unknown;
    };
    let TypeDefinitionKind::Struct { fields } = &mut definition.kind else {
        return FieldResolution::Unknown;
    };
    let Some(field) = fields
        .iter_mut()
        .find(|field| field.offset_bytes == binding.field_offset)
    else {
        return FieldResolution::Unknown;
    };
    let evidence = ModelEvidence {
        source: ModelSource::NativeAnalysis,
        detail: format!(
            "64-bit field load passed to resolved callee {:x} in {}",
            binding.callee.value.0, binding.callee_register
        ),
        site: Some(binding.field_site),
    };
    if field.ty == callee_ty {
        if !field.evidence.contains(&evidence) && field.evidence.len() < 256 {
            field.evidence.push(evidence);
            return FieldResolution::Changed;
        }
        return FieldResolution::Compatible;
    }
    if definition.size_is_lower_bound
        && field.ty
            == (TypeRef::Primitive {
                name: PrimitiveType::U64,
            })
        && !field
            .evidence
            .iter()
            .any(|evidence| evidence.source == ModelSource::AnalystAssertion)
    {
        field.ty = callee_ty;
        if !field.evidence.contains(&evidence) && field.evidence.len() < 256 {
            field.evidence.push(evidence);
        }
        return FieldResolution::Changed;
    }
    FieldResolution::Conflict
}

fn clear_ambiguous_inferred_field(
    model: &mut AnalysisModel,
    caller: Location,
    parameter: &str,
    offset: u64,
) -> bool {
    let Some(ty) = model
        .functions
        .iter()
        .find(|row| row.entry == caller)
        .and_then(|row| row.inferred_parameters.get(parameter))
    else {
        return false;
    };
    let Some(id) = inferred_struct_id(ty) else {
        return false;
    };
    let Some(definition) = model
        .types
        .iter_mut()
        .find(|definition| definition.id == id)
    else {
        return false;
    };
    if !definition.size_is_lower_bound {
        return false;
    }
    let TypeDefinitionKind::Struct { fields } = &mut definition.kind else {
        return false;
    };
    let Some(field) = fields.iter_mut().find(|field| field.offset_bytes == offset) else {
        return false;
    };
    if !matches!(field.ty, TypeRef::Pointer { .. })
        || field
            .evidence
            .iter()
            .any(|evidence| evidence.source == ModelSource::AnalystAssertion)
        || !field.evidence.iter().any(|evidence| {
            evidence
                .detail
                .starts_with("64-bit field load passed to resolved callee")
        })
    {
        return false;
    }
    field.ty = TypeRef::Primitive {
        name: PrimitiveType::U64,
    };
    field.evidence.retain(|evidence| {
        !evidence
            .detail
            .starts_with("64-bit field load passed to resolved callee")
    });
    true
}

fn conflict(model: &mut AnalysisModel, subject: String, detail: String, site: Option<Location>) {
    if model
        .conflicts
        .iter()
        .any(|entry| entry.subject == subject && entry.detail == detail)
    {
        return;
    }
    model.conflicts.push(ModelConflict {
        subject,
        detail,
        evidence: vec![ModelEvidence {
            source: ModelSource::NativeAnalysis,
            detail: "bounded native pointer-origin analysis".to_owned(),
            site,
        }],
    });
}

/// An explicit prototype owns presentation. Native observations can support
/// its fields or record a conflict, but never replace its type.
fn reconcile_explicit_parameter(
    model: &mut AnalysisModel,
    entry: Location,
    register: &str,
    sites: &[Access],
) -> bool {
    let Some(position) = ARG_REGS.iter().position(|name| *name == register) else {
        return false;
    };
    let Some(ty) = model
        .functions
        .iter()
        .find(|row| row.entry == entry)
        .and_then(|row| row.prototype.as_ref())
        .and_then(|proto| proto.parameters.get(position))
        .map(|parameter| parameter.ty.clone())
    else {
        return false;
    };
    let subject = format!("function:{:x}:{register}", entry.value.0);
    let TypeRef::Pointer { to } = ty else {
        conflict(
            model,
            subject,
            "native dereference conflicts with explicit non-pointer parameter".to_owned(),
            sites.first().map(|site| site.site),
        );
        return true;
    };
    let TypeRef::Named { id } = to.as_ref() else {
        return false;
    };
    let Some(definition) = model.types.iter().find(|definition| definition.id == *id) else {
        return false;
    };
    if !matches!(
        definition.kind,
        TypeDefinitionKind::Struct { .. } | TypeDefinitionKind::Union { .. }
    ) {
        return false;
    }
    for site in sites {
        let matching = model
            .types
            .iter()
            .find(|definition| definition.id == *id)
            .and_then(|definition| {
                let fields = match &definition.kind {
                    TypeDefinitionKind::Struct { fields }
                    | TypeDefinitionKind::Union { fields } => fields,
                    _ => return None,
                };
                fields
                    .iter()
                    .find(|field| fixed_access_matches_field(field, site.offset, site.width_bytes))
                    .map(|field| field.name.clone())
            });
        if let Some(name) = matching {
            let evidence = ModelEvidence {
                source: ModelSource::NativeAnalysis,
                detail: format!(
                    "{}-byte access agrees with explicit field",
                    site.width_bytes
                ),
                site: Some(site.site),
            };
            if let Some(definition) = model
                .types
                .iter_mut()
                .find(|definition| definition.id == *id)
            {
                let fields = match &mut definition.kind {
                    TypeDefinitionKind::Struct { fields }
                    | TypeDefinitionKind::Union { fields } => fields,
                    _ => unreachable!(),
                };
                if let Some(field) = fields.iter_mut().find(|field| field.name == name)
                    && !field.evidence.contains(&evidence)
                {
                    field.evidence.push(evidence);
                }
            }
        } else {
            conflict(
                model,
                subject.clone(),
                format!(
                    "{}-byte native access at offset {} disagrees with explicit aggregate layout",
                    site.width_bytes, site.offset
                ),
                Some(site.site),
            );
        }
    }
    true
}

/// Recover fixed-offset, disjoint aggregate layouts and propagate directly
/// evidenced call arguments. Unknown aliases and indexed accesses do not
/// become struct fields or arrays here.
pub fn infer_model(
    model: &mut AnalysisModel,
    inputs: &[(&MachineFunctionIr, &FunctionIr)],
) -> Result<InferenceReport, String> {
    validate_structure(model)?;
    let original = model.clone();
    let mut bindings = Vec::new();
    let mut field_bindings = Vec::new();
    let mut analyzed = 0;
    let mut skipped = inputs.len().saturating_sub(MAX_FUNCTIONS);
    let mut inferred = 0;
    let mut propagated = 0;
    for (machine, function) in inputs.iter().take(MAX_FUNCTIONS) {
        if machine.binary_sha256 != model.binary_sha256
            || function.binary_sha256 != model.binary_sha256
            || machine.entry != function.entry
        {
            skipped += 1;
            continue;
        }
        let (accesses, calls, loaded_fields) = match collect(machine, function) {
            Ok(value) => value,
            Err(error) => {
                conflict(
                    model,
                    format!(
                        "function:{}:{:x}",
                        machine.entry.address_space, machine.entry.value.0
                    ),
                    error,
                    Some(machine.entry),
                );
                skipped += 1;
                continue;
            }
        };
        analyzed += 1;
        bindings.extend(calls);
        field_bindings.extend(loaded_fields);
        if !model.functions.iter().any(|row| row.entry == machine.entry) {
            model.functions.push(ModelFunction {
                entry: machine.entry,
                name: machine.name.clone(),
                prototype: None,
                inferred_parameters: BTreeMap::new(),
                evidence: vec![ModelEvidence {
                    source: ModelSource::NativeAnalysis,
                    detail: "native FunctionIndex entry".to_owned(),
                    site: Some(machine.entry),
                }],
            });
        }
        for (register, mut sites) in accesses {
            if sites.len() > 4096 {
                conflict(
                    model,
                    format!("function:{:x}:{register}", machine.entry.value.0),
                    "aggregate access count exceeds 4096".to_owned(),
                    Some(machine.entry),
                );
                continue;
            }
            sites.sort_by_key(|site| (site.offset, site.width_bytes, site.site));
            sites.dedup_by_key(|site| (site.offset, site.width_bytes));
            if sites.is_empty() || sites.len() > MAX_FIELDS {
                continue;
            }
            if reconcile_explicit_parameter(model, machine.entry, &register, &sites) {
                continue;
            }
            let mut end = 0;
            let mut fields = Vec::new();
            let mut bad = false;
            for site in &sites {
                if site.offset < end {
                    bad = true;
                    break;
                }
                let Some(next) = site.offset.checked_add(site.width_bytes) else {
                    bad = true;
                    break;
                };
                end = next;
                fields.push(ModelField {
                    name: format!("offset_{}", site.offset),
                    offset_bytes: site.offset,
                    ty: scalar(site.width_bytes),
                    evidence: vec![ModelEvidence {
                        source: ModelSource::NativeAnalysis,
                        detail: format!(
                            "{}-byte fixed-offset access through unmodified parameter origin",
                            site.width_bytes
                        ),
                        site: Some(site.site),
                    }],
                });
            }
            if bad || end == 0 || end > 1_048_576 {
                conflict(
                    model,
                    format!("function:{:x}:{register}", machine.entry.value.0),
                    "overlapping or invalid aggregate accesses; type left unresolved".to_owned(),
                    sites.first().map(|site| site.site),
                );
                continue;
            }
            let id = format!(
                "inferred_{}_{:x}_{register}",
                machine.entry.address_space, machine.entry.value.0
            );
            if !model.types.iter().any(|ty| ty.id == id) {
                model.types.push(TypeDefinition {
                    id: id.clone(),
                    name: format!(
                        "hydir_struct_{}_{:x}_{register}",
                        machine.entry.address_space, machine.entry.value.0
                    ),
                    size_bytes: end,
                    size_is_lower_bound: true,
                    kind: TypeDefinitionKind::Struct { fields },
                    evidence: vec![ModelEvidence {
                        source: ModelSource::NativeAnalysis,
                        detail: "disjoint fixed-offset accesses rooted in one parameter".to_owned(),
                        site: Some(machine.entry),
                    }],
                });
                inferred += 1;
            }
            let ty = TypeRef::Pointer {
                to: Box::new(TypeRef::Named { id }),
            };
            let row = model
                .functions
                .iter_mut()
                .find(|row| row.entry == machine.entry)
                .unwrap();
            row.inferred_parameters.entry(register).or_insert(ty);
        }
    }
    // Propagate only unchanged argument origins to directly resolved callees.
    let mut hit_fixed_point_limit = false;
    for pass in 0..=MAX_FUNCTIONS {
        let mut changed = false;
        for binding in &bindings {
            let Some(callee_type) = model
                .functions
                .iter()
                .find(|row| row.entry == binding.callee)
                .and_then(|row| row.inferred_parameters.get(&binding.callee_register))
                .cloned()
            else {
                continue;
            };
            let caller_type = model
                .functions
                .iter()
                .find(|row| row.entry == binding.caller)
                .and_then(|row| row.inferred_parameters.get(&binding.caller_parameter))
                .cloned();
            match caller_type.as_ref() {
                None => {
                    let Some(caller) = model
                        .functions
                        .iter_mut()
                        .find(|row| row.entry == binding.caller)
                    else {
                        continue;
                    };
                    caller
                        .inferred_parameters
                        .insert(binding.caller_parameter.clone(), callee_type);
                    propagated += 1;
                    changed = true;
                }
                Some(existing) if *existing != callee_type => {
                    match merge_inferred_callee_layout(model, existing, &callee_type) {
                        Some(true) => {
                            propagated += 1;
                            changed = true;
                        }
                        Some(false) => {}
                        None => conflict(
                            model,
                            format!("call:{:x}", binding.site.value.0),
                            "callee parameter layout conflicts with caller parameter evidence"
                                .to_owned(),
                            Some(binding.site),
                        ),
                    }
                }
                _ => {}
            }
        }
        let mut field_candidates = BTreeMap::<(Location, String, u64), Vec<TypeRef>>::new();
        for binding in &field_bindings {
            let Some(ty) = parameter_type(model, binding.callee, &binding.callee_register) else {
                continue;
            };
            if inferred_struct_id(&ty).is_none() {
                continue;
            }
            let key = (
                binding.caller,
                binding.caller_parameter.clone(),
                binding.field_offset,
            );
            let values = field_candidates.entry(key).or_default();
            if !values.contains(&ty) {
                values.push(ty)
            }
        }
        let ambiguous = field_candidates
            .iter()
            .filter(|(_, values)| values.len() > 1)
            .map(|(key, _)| key.clone())
            .collect::<BTreeSet<_>>();
        for (caller, parameter, offset) in &ambiguous {
            changed |= clear_ambiguous_inferred_field(model, *caller, parameter, *offset);
            conflict(
                model,
                format!("field_call:{:x}:{parameter}:{offset}", caller.value.0),
                "loaded field reaches incompatible pointer parameter types; field left unresolved"
                    .to_owned(),
                field_bindings
                    .iter()
                    .find(|binding| {
                        binding.caller == *caller
                            && binding.caller_parameter == *parameter
                            && binding.field_offset == *offset
                    })
                    .map(|binding| binding.field_site),
            );
        }
        for binding in &field_bindings {
            if ambiguous.contains(&(
                binding.caller,
                binding.caller_parameter.clone(),
                binding.field_offset,
            )) {
                continue;
            }
            match resolve_loaded_pointer_field(model, binding) {
                FieldResolution::Changed => {
                    changed = true;
                }
                FieldResolution::Conflict => conflict(
                    model,
                    format!("field_call:{:x}", binding.call_site.value.0),
                    "loaded field pointer conflicts with an asserted or inferred field type"
                        .to_owned(),
                    Some(binding.field_site),
                ),
                FieldResolution::Unknown | FieldResolution::Compatible => {}
            }
        }
        if !changed {
            break;
        }
        if pass == MAX_FUNCTIONS {
            hit_fixed_point_limit = true;
            conflict(
                model,
                "call_graph".to_owned(),
                "pointer constraints did not converge within 257 passes".to_owned(),
                None,
            );
        }
    }
    if *model != original {
        model.revision = model
            .revision
            .checked_add(1)
            .ok_or("analysis model revision overflow")?;
    }
    if let Err(error) = validate_structure(model) {
        *model = original;
        return Err(error);
    }
    let pointer_fields = model
        .types
        .iter()
        .filter(|definition| definition.size_is_lower_bound)
        .flat_map(|definition| match &definition.kind {
            TypeDefinitionKind::Struct { fields } => fields.iter().collect::<Vec<_>>(),
            _ => Vec::new(),
        })
        .filter(|field| {
            matches!(field.ty, TypeRef::Pointer { .. })
                && field.evidence.iter().any(|evidence| {
                    evidence
                        .detail
                        .starts_with("64-bit field load passed to resolved callee")
                })
        })
        .count();
    Ok(InferenceReport {
        schema_version: 1,
        analyzed_functions: analyzed,
        skipped_functions: skipped,
        inferred_types: inferred,
        inferred_pointer_fields: pointer_fields,
        propagated_parameter_types: propagated,
        conflicts: model.conflicts.len(),
        model_revision: model.revision,
        bounded: inputs.len() > MAX_FUNCTIONS || skipped > 0 || hit_fixed_point_limit,
    })
}
