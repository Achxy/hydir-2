use crate::{
    BinaryOp, HIGH_LEVEL_CIR_VERSION, HighExpr, HighLevelCir, HighStatement,
    validate_high_level_cir,
};
use hydir_core::Location;
use hydir_model::{
    AnalysisModel, PrimitiveType, TypeDefinition, TypeDefinitionKind, TypeRef, validate_structure,
};
use std::collections::{BTreeMap, BTreeSet};

fn primitive_name(value: PrimitiveType) -> &'static str {
    match value {
        PrimitiveType::Void => "void",
        PrimitiveType::Bool => "_Bool",
        PrimitiveType::U8 => "uint8_t",
        PrimitiveType::U16 => "uint16_t",
        PrimitiveType::U32 => "uint32_t",
        PrimitiveType::U64 => "uint64_t",
        PrimitiveType::I8 => "int8_t",
        PrimitiveType::I16 => "int16_t",
        PrimitiveType::I32 => "int32_t",
        PrimitiveType::I64 => "int64_t",
        PrimitiveType::F32 => "float",
        PrimitiveType::F64 => "double",
    }
}

fn named_prefix<'a>(model: &'a AnalysisModel, id: &str) -> Result<(&'static str, &'a str), String> {
    let def = model
        .types
        .iter()
        .find(|def| def.id == id)
        .ok_or("typed C referenced type is missing")?;
    let prefix = match def.kind {
        TypeDefinitionKind::Struct { .. } => "struct",
        TypeDefinitionKind::Union { .. } => "union",
        TypeDefinitionKind::Enum { .. } | TypeDefinitionKind::Alias { .. } => "",
    };
    Ok((prefix, &def.name))
}

fn c_decl(ty: &TypeRef, name: &str, model: &AnalysisModel) -> Result<String, String> {
    match ty {
        TypeRef::Primitive { name: primitive } => {
            Ok(format!("{} {name}", primitive_name(*primitive)))
        }
        TypeRef::Named { id } => {
            let (prefix, named) = named_prefix(model, id)?;
            Ok(format!("{prefix} {named} {name}").trim_start().to_owned())
        }
        TypeRef::Pointer { to } => {
            let pointer_name = if matches!(to.as_ref(), TypeRef::Array { .. }) {
                format!("(*{name})")
            } else {
                format!("*{name}")
            };
            c_decl(to, &pointer_name, model)
        }
        TypeRef::Array { of, count } => c_decl(of, &format!("{name}[{count}]"), model),
        TypeRef::Bytes { size } => Ok(format!("uint8_t {name}[{size}]")),
    }
}

fn by_value_deps(ty: &TypeRef, output: &mut BTreeSet<String>) {
    match ty {
        TypeRef::Named { id } => {
            output.insert(id.clone());
        }
        TypeRef::Array { of, .. } => by_value_deps(of, output),
        TypeRef::Pointer { .. } | TypeRef::Primitive { .. } | TypeRef::Bytes { .. } => {}
    }
}

fn collect_used_types(
    ty: &TypeRef,
    model: &AnalysisModel,
    used: &mut BTreeSet<String>,
    depth: usize,
) -> Result<(), String> {
    if depth > 64 {
        return Err("typed C type dependency depth exceeds 64".to_owned());
    }
    match ty {
        TypeRef::Named { id } => {
            if !used.insert(id.clone()) {
                return Ok(());
            }
            let def = model
                .types
                .iter()
                .find(|def| def.id == *id)
                .ok_or("typed C referenced type is missing")?;
            match &def.kind {
                TypeDefinitionKind::Struct { fields } | TypeDefinitionKind::Union { fields } => {
                    for field in fields {
                        collect_used_types(&field.ty, model, used, depth + 1)?;
                    }
                }
                TypeDefinitionKind::Alias { target } => {
                    collect_used_types(target, model, used, depth + 1)?
                }
                TypeDefinitionKind::Enum { .. } => {}
            }
        }
        TypeRef::Pointer { to } => collect_used_types(to, model, used, depth + 1)?,
        TypeRef::Array { of, .. } => collect_used_types(of, model, used, depth + 1)?,
        TypeRef::Primitive { .. } | TypeRef::Bytes { .. } => {}
    }
    Ok(())
}

fn emit_definition(
    output: &mut String,
    def: &TypeDefinition,
    model: &AnalysisModel,
) -> Result<(), String> {
    match &def.kind {
        TypeDefinitionKind::Struct { fields } => {
            output.push_str(&format!("struct {} {{\n", def.name));
            if def.size_is_lower_bound {
                output.push_str("  /* observed minimum extent; full object size is unknown */\n");
            }
            let mut cursor = 0;
            for (index, field) in fields.iter().enumerate() {
                if field.offset_bytes > cursor {
                    output.push_str(&format!(
                        "  uint8_t _hydir_pad_{index}[{}];\n",
                        field.offset_bytes - cursor
                    ));
                }
                output.push_str(&format!("  {};\n", c_decl(&field.ty, &field.name, model)?));
                cursor = field.offset_bytes + field_size(&field.ty, model)?;
            }
            if cursor < def.size_bytes {
                output.push_str(&format!(
                    "  uint8_t _hydir_tail[{}];\n",
                    def.size_bytes - cursor
                ));
            }
            if fields.is_empty() && def.size_bytes > 0 {
                output.push_str(&format!("  uint8_t _hydir_unknown[{}];\n", def.size_bytes));
            }
            output.push_str("};\n");
            for field in fields {
                output.push_str(&format!(
                    "_Static_assert(offsetof(struct {}, {}) == {}, \"field offset\");\n",
                    def.name, field.name, field.offset_bytes
                ));
            }
            if !def.size_is_lower_bound {
                output.push_str(&format!(
                    "_Static_assert(sizeof(struct {}) == {}, \"struct size\");\n",
                    def.name, def.size_bytes
                ));
            }
        }
        TypeDefinitionKind::Union { fields } => {
            output.push_str(&format!("union {} {{\n", def.name));
            output.push_str(&format!("  uint8_t _hydir_storage[{}];\n", def.size_bytes));
            for field in fields {
                output.push_str(&format!("  {};\n", c_decl(&field.ty, &field.name, model)?));
            }
            output.push_str("};\n");
            if !def.size_is_lower_bound {
                output.push_str(&format!(
                    "_Static_assert(sizeof(union {}) == {}, \"union size\");\n",
                    def.name, def.size_bytes
                ));
            }
        }
        TypeDefinitionKind::Enum { underlying, .. } => {
            output.push_str(&format!(
                "typedef {} {};\n",
                primitive_name(*underlying),
                def.name
            ));
        }
        TypeDefinitionKind::Alias { target } => {
            output.push_str(&format!("typedef {};\n", c_decl(target, &def.name, model)?));
        }
    }
    Ok(())
}

fn field_size(ty: &TypeRef, model: &AnalysisModel) -> Result<u64, String> {
    match ty {
        TypeRef::Primitive { name } => name.size_bytes().ok_or("void field has no size".to_owned()),
        TypeRef::Pointer { .. } => Ok(8),
        TypeRef::Array { of, count } => field_size(of, model)?
            .checked_mul(*count)
            .ok_or("array size overflow".to_owned()),
        TypeRef::Bytes { size } => Ok(*size),
        TypeRef::Named { id } => model
            .types
            .iter()
            .find(|def| def.id == *id)
            .map(|def| def.size_bytes)
            .ok_or("type missing".to_owned()),
    }
}

fn emit_expr(expr: &HighExpr) -> String {
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
            format!("({} {op} {})", emit_expr(left), emit_expr(right))
        }
        HighExpr::Field { base, field } => format!("({})->{field}", emit_expr(base)),
        HighExpr::Call {
            name, arguments, ..
        } => format!(
            "{name}({})",
            arguments
                .iter()
                .map(emit_expr)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn collect_calls(
    expr: &HighExpr,
    calls: &mut BTreeMap<Location, (String, usize)>,
) -> Result<(), String> {
    match expr {
        HighExpr::Call {
            callee,
            name,
            arguments,
        } => {
            if calls
                .insert(*callee, (name.clone(), arguments.len()))
                .is_some_and(|old| old != (name.clone(), arguments.len()))
            {
                return Err("HighLevelCIR call target has inconsistent name/arity".to_owned());
            }
            for argument in arguments {
                collect_calls(argument, calls)?;
            }
        }
        HighExpr::Binary { left, right, .. } => {
            collect_calls(left, calls)?;
            collect_calls(right, calls)?;
        }
        HighExpr::Field { base, .. } => collect_calls(base, calls)?,
        HighExpr::Variable { .. } | HighExpr::Constant { .. } => {}
    }
    Ok(())
}

/// Emit C11 source for a HighLevelCIR artifact. Exact field offsets are
/// checked in the emitted translation unit; partial types retain a comment.
pub fn emit_typed_c(ir: &HighLevelCir, model: &AnalysisModel) -> Result<String, String> {
    validate_structure(model)?;
    validate_high_level_cir(ir)?;
    if ir.schema_version != HIGH_LEVEL_CIR_VERSION
        || ir.binary_sha256 != model.binary_sha256
        || ir.model_revision != model.revision
    {
        return Err("typed C artifact identity/model revision differs".to_owned());
    }
    let mut used = BTreeSet::new();
    collect_used_types(&ir.return_type, model, &mut used, 0)?;
    for parameter in &ir.parameters {
        collect_used_types(&parameter.ty, model, &mut used, 0)?;
    }
    for statement in &ir.statements {
        if let HighStatement::Let { ty, .. } = statement {
            collect_used_types(ty, model, &mut used, 0)?;
        }
    }
    let mut calls = BTreeMap::new();
    for statement in &ir.statements {
        match statement {
            HighStatement::Let { value, .. } | HighStatement::Return { value, .. } => {
                collect_calls(value, &mut calls)?;
            }
            HighStatement::StoreField { base, value, .. } => {
                collect_calls(base, &mut calls)?;
                collect_calls(value, &mut calls)?;
            }
        }
    }
    for (callee, (name, arity)) in &calls {
        if *callee != ir.entry && *name == ir.name {
            return Err("typed C call target collides with emitted function name".to_owned());
        }
        let row = model
            .functions
            .iter()
            .find(|row| row.entry == *callee && row.name == *name)
            .ok_or("typed C call target differs from model")?;
        let prototype = row
            .prototype
            .as_ref()
            .ok_or("typed C call prototype is missing")?;
        if prototype.variadic
            || prototype.parameters.len() != *arity
            || prototype.return_type
                != (TypeRef::Primitive {
                    name: PrimitiveType::U64,
                })
        {
            return Err("typed C call prototype is unsupported".to_owned());
        }
        collect_used_types(&prototype.return_type, model, &mut used, 0)?;
        for parameter in &prototype.parameters {
            collect_used_types(&parameter.ty, model, &mut used, 0)?;
        }
    }
    let definitions = model
        .types
        .iter()
        .filter(|def| used.contains(&def.id))
        .collect::<Vec<_>>();
    let mut output = String::from("#include <stdint.h>\n#include <stddef.h>\n\n");
    for def in &definitions {
        match def.kind {
            TypeDefinitionKind::Struct { .. } => {
                output.push_str(&format!("struct {};\n", def.name))
            }
            TypeDefinitionKind::Union { .. } => output.push_str(&format!("union {};\n", def.name)),
            _ => {}
        }
    }
    output.push_str("\n#pragma pack(push, 1)\n");
    let mut emitted = BTreeSet::new();
    let mut remaining = definitions.clone();
    while !remaining.is_empty() {
        let before = remaining.len();
        remaining.retain(|def| {
            let mut deps = BTreeSet::new();
            match &def.kind {
                TypeDefinitionKind::Struct { fields } | TypeDefinitionKind::Union { fields } => {
                    for field in fields {
                        by_value_deps(&field.ty, &mut deps);
                    }
                }
                TypeDefinitionKind::Alias { target } => by_value_deps(target, &mut deps),
                TypeDefinitionKind::Enum { .. } => {}
            }
            if deps.iter().all(|id| emitted.contains(id)) {
                // Emission failures are handled in the second pass below.
                false
            } else {
                true
            }
        });
        if remaining.len() == before {
            return Err("typed C type dependency cycle".to_owned());
        }
        // Resolve dependencies with a stable topological order.
        for def in &definitions {
            if emitted.contains(&def.id) || remaining.iter().any(|item| item.id == def.id) {
                continue;
            }
            emit_definition(&mut output, def, model)?;
            emitted.insert(def.id.clone());
        }
    }
    output.push_str("#pragma pack(pop)\n\n");
    for (callee, (name, _)) in &calls {
        let row = model
            .functions
            .iter()
            .find(|row| row.entry == *callee)
            .unwrap();
        let prototype = row.prototype.as_ref().unwrap();
        output.push_str(&c_decl(&prototype.return_type, name, model)?);
        output.push('(');
        if prototype.parameters.is_empty() {
            output.push_str("void");
        }
        for (index, parameter) in prototype.parameters.iter().enumerate() {
            if index > 0 {
                output.push_str(", ");
            }
            output.push_str(&c_decl(&parameter.ty, &parameter.name, model)?);
        }
        output.push_str(");\n");
    }
    if !calls.is_empty() {
        output.push('\n');
    }
    output.push_str(&c_decl(&ir.return_type, &ir.name, model)?);
    output.push('(');
    if ir.parameters.is_empty() {
        output.push_str("void");
    }
    for (index, parameter) in ir.parameters.iter().enumerate() {
        if index > 0 {
            output.push_str(", ");
        }
        output.push_str(&c_decl(&parameter.ty, &parameter.name, model)?);
    }
    output.push_str(") {\n");
    for statement in &ir.statements {
        match statement {
            HighStatement::Let {
                name, ty, value, ..
            } => {
                output.push_str(&format!(
                    "  {} = {};\n  (void){name};\n",
                    c_decl(ty, name, model)?,
                    emit_expr(value)
                ));
            }
            HighStatement::StoreField {
                base, field, value, ..
            } => {
                output.push_str(&format!(
                    "  ({})->{field} = {};\n",
                    emit_expr(base),
                    emit_expr(value)
                ));
            }
            HighStatement::Return { value, .. } => {
                output.push_str(&format!("  return {};\n", emit_expr(value)))
            }
        }
    }
    output.push_str("}\n");
    Ok(output)
}
