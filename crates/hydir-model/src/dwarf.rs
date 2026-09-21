use crate::{
    AnalysisModel, ModelEvidence, ModelField, ModelParameter, ModelPrototype, ModelSource,
    PrimitiveType, TypeDefinition, TypeDefinitionKind, TypeRef, validate_model,
};
use gimli::{AttributeValue, Dwarf, EndianSlice, LittleEndian, Reader};
use object::{Object, ObjectSection, ObjectSymbol, RelocationKind, RelocationTarget};
use std::collections::{BTreeMap, BTreeSet};

const MAX_DWARF_DIES: usize = 500_000;
const MAX_DWARF_UNITS: usize = 4_096;

#[derive(Clone)]
struct Die {
    tag: gimli::DwTag,
    name: Option<String>,
    size: Option<u64>,
    encoding: Option<gimli::DwAte>,
    target: Option<usize>,
    offset: Option<u64>,
    count: Option<u64>,
    members: Vec<usize>,
    parameters: Vec<usize>,
}

fn attr_u64<R: Reader>(value: Option<AttributeValue<R>>) -> Option<u64> {
    match value? {
        AttributeValue::Udata(value) => Some(value),
        AttributeValue::Data1(value) => Some(u64::from(value)),
        AttributeValue::Data2(value) => Some(u64::from(value)),
        AttributeValue::Data4(value) => Some(u64::from(value)),
        AttributeValue::Data8(value) => Some(value),
        _ => None,
    }
}

fn primitive(size: u64, encoding: Option<gimli::DwAte>) -> Option<PrimitiveType> {
    Some(match (encoding?, size) {
        (gimli::DW_ATE_boolean, 1) => PrimitiveType::Bool,
        (gimli::DW_ATE_unsigned | gimli::DW_ATE_unsigned_char, 1) => PrimitiveType::U8,
        (gimli::DW_ATE_unsigned | gimli::DW_ATE_unsigned_char, 2) => PrimitiveType::U16,
        (gimli::DW_ATE_unsigned | gimli::DW_ATE_unsigned_char, 4) => PrimitiveType::U32,
        (gimli::DW_ATE_unsigned | gimli::DW_ATE_unsigned_char, 8) => PrimitiveType::U64,
        (gimli::DW_ATE_signed | gimli::DW_ATE_signed_char, 1) => PrimitiveType::I8,
        (gimli::DW_ATE_signed | gimli::DW_ATE_signed_char, 2) => PrimitiveType::I16,
        (gimli::DW_ATE_signed | gimli::DW_ATE_signed_char, 4) => PrimitiveType::I32,
        (gimli::DW_ATE_signed | gimli::DW_ATE_signed_char, 8) => PrimitiveType::I64,
        (gimli::DW_ATE_float, 4) => PrimitiveType::F32,
        (gimli::DW_ATE_float, 8) => PrimitiveType::F64,
        _ => return None,
    })
}

fn type_ref(
    offset: usize,
    nodes: &BTreeMap<usize, Die>,
    ids: &BTreeMap<usize, String>,
    seen: &mut BTreeSet<usize>,
    depth: usize,
) -> Option<TypeRef> {
    if depth > 24 || !seen.insert(offset) {
        return None;
    }
    let node = nodes.get(&offset)?;
    let result = match node.tag {
        gimli::DW_TAG_base_type => Some(TypeRef::Primitive {
            name: primitive(node.size?, node.encoding)?,
        }),
        gimli::DW_TAG_pointer_type => {
            let to = node
                .target
                .and_then(|target| type_ref(target, nodes, ids, seen, depth + 1))
                .unwrap_or(TypeRef::Primitive {
                    name: PrimitiveType::Void,
                });
            Some(TypeRef::Pointer { to: Box::new(to) })
        }
        gimli::DW_TAG_const_type
        | gimli::DW_TAG_volatile_type
        | gimli::DW_TAG_restrict_type
        | gimli::DW_TAG_typedef => type_ref(node.target?, nodes, ids, seen, depth + 1),
        gimli::DW_TAG_array_type => {
            let count = node.count?;
            if count == 0 || count > 1_000_000 {
                None
            } else {
                Some(TypeRef::Array {
                    of: Box::new(type_ref(node.target?, nodes, ids, seen, depth + 1)?),
                    count,
                })
            }
        }
        gimli::DW_TAG_structure_type | gimli::DW_TAG_union_type => {
            ids.get(&offset).map(|id| TypeRef::Named { id: id.clone() })
        }
        _ => None,
    };
    seen.remove(&offset);
    result
}

fn ident(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

/// Import only fully bounded DWARF aggregate layouts. Unsupported DWARF
/// expressions, incomplete field types, and cross-unit references are skipped.
pub fn import_dwarf(bytes: &[u8], model: &mut AnalysisModel) -> Result<usize, String> {
    let mut candidate = model.clone();
    let imported = import_dwarf_inner(bytes, &mut candidate)?;
    if candidate != *model {
        candidate.revision = candidate
            .revision
            .checked_add(1)
            .ok_or("analysis model revision overflow")?;
    }
    *model = candidate;
    Ok(imported)
}

fn import_dwarf_inner(bytes: &[u8], model: &mut AnalysisModel) -> Result<usize, String> {
    validate_model(bytes, model)?;
    let original = model.clone();
    let file = object::File::parse(bytes).map_err(|error| error.to_string())?;
    let mut sections = BTreeMap::<String, Vec<u8>>::new();
    for section in file.sections() {
        let Ok(name) = section.name() else { continue };
        if !name.starts_with(".debug_") {
            continue;
        }
        let Ok(data) = section.data() else { continue };
        if data.len() > 64 * 1024 * 1024 {
            return Err("DWARF section exceeds 64 MiB".to_owned());
        }
        let mut data = data.to_vec();
        for (offset, relocation) in section.relocations() {
            if relocation.kind() != RelocationKind::Absolute
                || !matches!(relocation.size(), 32 | 64)
            {
                continue;
            }
            let target = match relocation.target() {
                RelocationTarget::Symbol(index) => file
                    .symbol_by_index(index)
                    .map_err(|error| error.to_string())?
                    .address(),
                RelocationTarget::Section(index) => file
                    .section_by_index(index)
                    .map_err(|error| error.to_string())?
                    .address(),
                RelocationTarget::Absolute => 0,
                _ => continue,
            };
            let value = i128::from(target) + i128::from(relocation.addend());
            if value < 0 || value > i128::from(u64::MAX) {
                continue;
            }
            let width = usize::from(relocation.size() / 8);
            let start = usize::try_from(offset).map_err(|_| "DWARF relocation offset overflow")?;
            let end = start
                .checked_add(width)
                .ok_or("DWARF relocation width overflow")?;
            let Some(slot) = data.get_mut(start..end) else {
                return Err("DWARF relocation is out of bounds".to_owned());
            };
            slot.copy_from_slice(&(value as u64).to_le_bytes()[..width]);
        }
        sections.insert(name.to_owned(), data);
    }
    let dwarf = Dwarf::load(|id| {
        let data = sections.get(id.name()).map(Vec::as_slice).unwrap_or(&[]);
        Ok::<_, gimli::Error>(EndianSlice::new(data, LittleEndian))
    })
    .map_err(|error| error.to_string())?;
    let mut units = dwarf.units();
    let mut unit_index = 0;
    let mut count = 0;
    while let Some(header) = units.next().map_err(|error| error.to_string())? {
        unit_index += 1;
        if unit_index > MAX_DWARF_UNITS {
            return Err("DWARF unit count exceeds limit".to_owned());
        }
        let unit = dwarf.unit(header).map_err(|error| error.to_string())?;
        let mut entries = unit.entries();
        let mut depth = 0isize;
        let mut parents: Vec<Option<usize>> = Vec::new();
        let mut nodes = BTreeMap::<usize, Die>::new();
        while let Some((delta, entry)) = entries.next_dfs().map_err(|error| error.to_string())? {
            count += 1;
            if count > MAX_DWARF_DIES {
                return Err("DWARF DIE count exceeds limit".to_owned());
            }
            depth += delta;
            if depth < 0 || depth > 64 {
                return Err("DWARF nesting exceeds limit".to_owned());
            }
            let level = depth as usize;
            parents.truncate(level);
            let offset = entry.offset().0;
            let name = entry
                .attr_value(gimli::DW_AT_name)
                .map_err(|error| error.to_string())?
                .and_then(|value| dwarf.attr_string(&unit, value).ok())
                .map(|value| value.to_string_lossy())
                .map(|value| value.into_owned());
            let size = attr_u64(
                entry
                    .attr_value(gimli::DW_AT_byte_size)
                    .map_err(|error| error.to_string())?,
            );
            let encoding = entry
                .attr_value(gimli::DW_AT_encoding)
                .map_err(|error| error.to_string())?
                .and_then(|value| match value {
                    AttributeValue::Encoding(value) => Some(value),
                    _ => None,
                });
            let target = entry
                .attr_value(gimli::DW_AT_type)
                .map_err(|error| error.to_string())?
                .and_then(|value| match value {
                    AttributeValue::UnitRef(value) => Some(value.0),
                    _ => None,
                });
            let member_offset = attr_u64(
                entry
                    .attr_value(gimli::DW_AT_data_member_location)
                    .map_err(|error| error.to_string())?,
            );
            let mut count_attr = attr_u64(
                entry
                    .attr_value(gimli::DW_AT_count)
                    .map_err(|error| error.to_string())?,
            );
            if count_attr.is_none() {
                count_attr = attr_u64(
                    entry
                        .attr_value(gimli::DW_AT_upper_bound)
                        .map_err(|error| error.to_string())?,
                )
                .and_then(|upper| upper.checked_add(1));
            }
            let parent = if level == 0 {
                None
            } else {
                parents.get(level - 1).copied().flatten()
            };
            if entry.tag() == gimli::DW_TAG_member {
                if let Some(parent) = parent {
                    if let Some(owner) = nodes.get_mut(&parent) {
                        owner.members.push(offset);
                    }
                }
            }
            if entry.tag() == gimli::DW_TAG_formal_parameter {
                if let Some(parent) = parent {
                    if let Some(owner) = nodes.get_mut(&parent) {
                        owner.parameters.push(offset);
                    }
                }
            }
            if entry.tag() == gimli::DW_TAG_subrange_type {
                if let Some(parent) = parent {
                    if let Some(owner) = nodes.get_mut(&parent) {
                        owner.count = count_attr;
                    }
                }
            }
            nodes.insert(
                offset,
                Die {
                    tag: entry.tag(),
                    name,
                    size,
                    encoding,
                    target,
                    offset: member_offset,
                    count: count_attr,
                    members: Vec::new(),
                    parameters: Vec::new(),
                },
            );
            parents.push(Some(offset));
        }
        let mut ids = BTreeMap::new();
        for (offset, node) in &nodes {
            if matches!(
                node.tag,
                gimli::DW_TAG_structure_type | gimli::DW_TAG_union_type
            ) && node.size.is_some_and(|size| size > 0 && size <= 1_048_576)
                && node.name.as_ref().is_some_and(|name| ident(name))
            {
                ids.insert(*offset, format!("dwarf_{unit_index}_{offset:x}"));
            }
        }
        let mut pending = Vec::new();
        for (offset, id) in &ids {
            let node = &nodes[offset];
            let mut fields = Vec::new();
            let mut complete = true;
            for member_offset in &node.members {
                let member = &nodes[member_offset];
                let (Some(name), Some(offset_bytes), Some(target)) =
                    (&member.name, member.offset, member.target)
                else {
                    complete = false;
                    break;
                };
                if !ident(name) {
                    complete = false;
                    break;
                }
                let Some(ty) = type_ref(target, &nodes, &ids, &mut BTreeSet::new(), 0) else {
                    complete = false;
                    break;
                };
                fields.push(ModelField {
                    name: name.clone(),
                    offset_bytes,
                    ty,
                    evidence: vec![ModelEvidence {
                        source: ModelSource::Dwarf,
                        detail: format!("DWARF unit {unit_index}, member DIE 0x{member_offset:x}"),
                        site: None,
                    }],
                });
            }
            if !complete {
                continue;
            }
            fields.sort_by_key(|field| field.offset_bytes);
            let size_bytes = node.size.unwrap();
            let definition = TypeDefinition {
                id: id.clone(),
                name: format!(
                    "{}_dwarf_{unit_index}_{offset:x}",
                    node.name.as_ref().unwrap()
                ),
                size_bytes,
                size_is_lower_bound: false,
                kind: if node.tag == gimli::DW_TAG_union_type {
                    TypeDefinitionKind::Union { fields }
                } else {
                    TypeDefinitionKind::Struct { fields }
                },
                evidence: vec![ModelEvidence {
                    source: ModelSource::Dwarf,
                    detail: format!("DWARF unit {unit_index}, type DIE 0x{offset:x}"),
                    site: None,
                }],
            };
            pending.push(definition);
        }
        // A rejected type cannot leave a dangling reference in accepted types.
        let accepted: BTreeSet<_> = pending.iter().map(|def| def.id.clone()).collect();
        pending.retain(|def| match &def.kind {
            TypeDefinitionKind::Struct { fields } | TypeDefinitionKind::Union { fields } => {
                fields.iter().all(|field| {
                    fn refs_valid(ty: &TypeRef, accepted: &BTreeSet<String>) -> bool {
                        match ty {
                            TypeRef::Named { id } => accepted.contains(id),
                            TypeRef::Pointer { to } => refs_valid(to, accepted),
                            TypeRef::Array { of, .. } => refs_valid(of, accepted),
                            _ => true,
                        }
                    }
                    refs_valid(&field.ty, &accepted)
                })
            }
            _ => true,
        });
        let mut combined = model.clone();
        combined.types.extend(pending.iter().cloned());
        if validate_model(bytes, &combined).is_ok() {
            *model = combined;
        } else {
            // One malformed layout must not discard independent valid types.
            for def in pending {
                let mut candidate = model.clone();
                candidate.types.push(def);
                if validate_model(bytes, &candidate).is_ok() {
                    *model = candidate;
                }
            }
        }
        for (offset, node) in &nodes {
            if node.tag != gimli::DW_TAG_subprogram {
                continue;
            }
            let Some(name) = node.name.as_deref() else {
                continue;
            };
            let Some(function_index) = model
                .functions
                .iter()
                .position(|function| function.name == name && function.prototype.is_none())
            else {
                continue;
            };
            let return_type = match node.target {
                Some(target) => type_ref(target, &nodes, &ids, &mut BTreeSet::new(), 0),
                None => Some(TypeRef::Primitive {
                    name: PrimitiveType::Void,
                }),
            };
            let Some(return_type) = return_type else {
                continue;
            };
            let mut parameters = Vec::new();
            let mut complete = true;
            for (index, parameter_offset) in node.parameters.iter().enumerate() {
                let param = &nodes[parameter_offset];
                let Some(target) = param.target else {
                    complete = false;
                    break;
                };
                let Some(ty) = type_ref(target, &nodes, &ids, &mut BTreeSet::new(), 0) else {
                    complete = false;
                    break;
                };
                let name = param
                    .name
                    .as_deref()
                    .filter(|name| ident(name))
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("arg_{index}"));
                parameters.push(ModelParameter { name, ty });
            }
            if !complete {
                continue;
            }
            let mut candidate = model.clone();
            candidate.functions[function_index].prototype = Some(ModelPrototype {
                parameters,
                return_type,
                calling_convention: "sysv_amd64".to_owned(),
                variadic: false,
            });
            candidate.functions[function_index]
                .evidence
                .push(ModelEvidence {
                    source: ModelSource::Dwarf,
                    detail: format!("DWARF unit {unit_index}, subprogram DIE 0x{offset:x}"),
                    site: None,
                });
            if validate_model(bytes, &candidate).is_ok() {
                *model = candidate;
            }
        }
    }
    Ok(model.types.len().saturating_sub(original.types.len())
        + model
            .functions
            .iter()
            .zip(&original.functions)
            .filter(|(new, old)| new.prototype != old.prototype)
            .count())
}
