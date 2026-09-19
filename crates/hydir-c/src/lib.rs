//! Fail-closed C emission for HydIR's raw scalar direct-CFG LLVM lift.
//!
//! This is a small LLVM-to-C backend, not a general LLVM parser or Rellic.
//! It preserves explicit control flow and lowers SSA phis with parallel edge
//! copies. Only the exact instruction subset emitted by `hydir-backend` is
//! accepted; unfamiliar LLVM syntax is an error, never an ignored operation.

use hydir_core::{
    DECOMPILATION_UNIT_VERSION, DecompilationDiagnostic, DecompilationUnit, DiagnosticSeverity,
    RegionSpec, validate_decompilation_unit,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug)]
struct Phi {
    destination: String,
    incoming: BTreeMap<String, String>,
}

#[derive(Debug)]
enum Terminator {
    Jump(String),
    Branch(String, String, String),
    Return(String),
}

#[derive(Debug)]
struct Block {
    label: String,
    phis: Vec<Phi>,
    statements: Vec<String>,
    terminator: Option<Terminator>,
}

fn identifier(input: &str) -> Result<String, String> {
    let stripped = input.strip_prefix('%').unwrap_or(input);
    if stripped.is_empty()
        || !stripped
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        || !stripped
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(format!("invalid identifier: {input}"));
    }
    Ok(stripped.to_owned())
}

fn value(input: &str, used: &mut BTreeSet<String>) -> Result<String, String> {
    let input = input.trim();
    if input.starts_with('%') {
        let name = identifier(input)?;
        used.insert(name.clone());
        return Ok(format!("v_{name}"));
    }
    match input {
        "true" => return Ok("UINT64_C(1)".to_owned()),
        "false" => return Ok("UINT64_C(0)".to_owned()),
        _ => {}
    }
    let number = input
        .parse::<i64>()
        .map_err(|_| format!("unsupported LLVM value: {input}"))?;
    Ok(format!("UINT64_C({})", number as u64))
}

fn operands(input: &str) -> Result<(&str, &str), String> {
    let (left, right) = input
        .split_once(", ")
        .ok_or_else(|| format!("expected two operands: {input}"))?;
    if right.contains(", ") {
        return Err(format!("too many operands: {input}"));
    }
    Ok((left, right))
}

fn expression(
    input: &str,
    used: &mut BTreeSet<String>,
    helpers: &BTreeSet<String>,
) -> Result<String, String> {
    if let Some(call) = input.strip_prefix("call i64 @") {
        let (callee, arguments) = call
            .split_once('(')
            .ok_or_else(|| format!("invalid scalar call: {input}"))?;
        if !helpers.contains(callee) {
            return Err(format!("unresolved scalar call: {callee}"));
        }
        let arguments = arguments
            .strip_suffix(')')
            .ok_or_else(|| format!("invalid scalar call arguments: {input}"))?;
        let arguments = arguments
            .split(", ")
            .map(|argument| {
                argument
                    .strip_prefix("i64 ")
                    .ok_or_else(|| format!("invalid scalar call argument: {input}"))
                    .and_then(|operand| value(operand, used))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if arguments.is_empty() || arguments.len() > 6 {
            return Err(format!("scalar call has unsupported arity: {input}"));
        }
        return Ok(format!("{callee}({})", arguments.join(", ")));
    }
    let (operation, tail) = input
        .split_once(' ')
        .ok_or_else(|| format!("unsupported LLVM operation: {input}"))?;
    if operation == "trunc" || operation == "zext" {
        let (source, destination_width) = tail
            .split_once(" to ")
            .ok_or_else(|| format!("invalid integer conversion: {input}"))?;
        let (source_width, operand) = source
            .split_once(' ')
            .ok_or_else(|| format!("invalid integer conversion source: {input}"))?;
        let valid = (operation == "trunc" && source_width == "i64" && destination_width == "i32")
            || (operation == "zext" && source_width == "i32" && destination_width == "i64");
        if !valid {
            return Err(format!("unsupported integer conversion: {input}"));
        }
        return Ok(format!(
            "({} & UINT64_C(4294967295))",
            value(operand, used)?
        ));
    }
    if operation == "icmp" {
        let (predicate, typed) = tail
            .split_once(' ')
            .ok_or_else(|| format!("invalid icmp: {input}"))?;
        let (width, args) = typed
            .split_once(' ')
            .ok_or_else(|| format!("invalid icmp width: {input}"))?;
        if width != "i1" && width != "i64" {
            return Err(format!("unsupported icmp width: {width}"));
        }
        let (left, right) = operands(args)?;
        let left = value(left, used)?;
        let right = value(right, used)?;
        let result = match predicate {
            "eq" => format!("({left} == {right})"),
            "ne" => format!("({left} != {right})"),
            "ult" if width == "i64" => format!("({left} < {right})"),
            "slt" if width == "i64" => format!(
                "(({left} ^ UINT64_C(9223372036854775808)) < ({right} ^ UINT64_C(9223372036854775808)))"
            ),
            _ => {
                return Err(format!(
                    "unsupported icmp predicate/width: {predicate} {width}"
                ));
            }
        };
        return Ok(format!("(uint64_t){result}"));
    }
    let (width, args) = tail
        .split_once(' ')
        .ok_or_else(|| format!("invalid binary operation: {input}"))?;
    if width != "i1" && width != "i64" {
        return Err(format!("unsupported LLVM width: {width}"));
    }
    let (left, right) = operands(args)?;
    let left = value(left, used)?;
    let right = value(right, used)?;
    let operator = match operation {
        "add" if width == "i64" => "+",
        "sub" if width == "i64" => "-",
        "mul" if width == "i64" => "*",
        "and" => "&",
        "or" => "|",
        "xor" => "^",
        _ => return Err(format!("unsupported LLVM operation: {operation} {width}")),
    };
    let result = format!("({left} {operator} {right})");
    Ok(if width == "i1" {
        format!("({result} & UINT64_C(1))")
    } else {
        result
    })
}

fn parse_phi(input: &str, used: &mut BTreeSet<String>) -> Result<BTreeMap<String, String>, String> {
    let mut incoming = BTreeMap::new();
    let mut rest = input;
    while !rest.is_empty() {
        let after_open = rest
            .strip_prefix('[')
            .ok_or_else(|| format!("invalid phi incoming: {rest}"))?;
        let (pair, following) = after_open
            .split_once(']')
            .ok_or_else(|| format!("unterminated phi incoming: {rest}"))?;
        let (source, predecessor) = operands(pair)?;
        let predecessor = identifier(predecessor)?;
        let source = value(source, used)?;
        if incoming.insert(predecessor.clone(), source).is_some() {
            return Err(format!("duplicate phi predecessor: {predecessor}"));
        }
        rest = if following.is_empty() {
            ""
        } else {
            following
                .strip_prefix(", ")
                .ok_or_else(|| format!("invalid phi separator: {following}"))?
        };
    }
    if incoming.is_empty() {
        return Err("phi requires at least one incoming edge".to_owned());
    }
    Ok(incoming)
}

fn parse_terminator(line: &str, used: &mut BTreeSet<String>) -> Result<Terminator, String> {
    if let Some(target) = line.strip_prefix("br label %") {
        return Ok(Terminator::Jump(identifier(target)?));
    }
    if let Some(rest) = line.strip_prefix("br i1 ") {
        let (condition, targets) = rest
            .split_once(", label %")
            .ok_or_else(|| format!("invalid conditional branch: {line}"))?;
        let (yes, no) = targets
            .split_once(", label %")
            .ok_or_else(|| format!("invalid conditional branch: {line}"))?;
        return Ok(Terminator::Branch(
            value(condition, used)?,
            identifier(yes)?,
            identifier(no)?,
        ));
    }
    if let Some(result) = line.strip_prefix("ret i64 ") {
        return Ok(Terminator::Return(value(result, used)?));
    }
    Err(format!("unsupported LLVM terminator: {line}"))
}

fn edge(
    from: &str,
    to: &str,
    blocks: &BTreeMap<String, Block>,
    output: &mut String,
) -> Result<(), String> {
    let target = blocks
        .get(to)
        .ok_or_else(|| format!("unknown branch destination: {to}"))?;
    for (index, phi) in target.phis.iter().enumerate() {
        let source = phi
            .incoming
            .get(from)
            .ok_or_else(|| format!("phi {} missing predecessor {from}", phi.destination))?;
        output.push_str(&format!("    uint64_t edge_{index} = {source};\n"));
    }
    for (index, phi) in target.phis.iter().enumerate() {
        output.push_str(&format!("    v_{} = edge_{index};\n", phi.destination));
    }
    output.push_str(&format!("    goto L_{to};\n"));
    Ok(())
}

/// Convert only HydIR's verified, scalar `u64(u64,u64)` raw-lift grammar to C11.
///
/// The source must be produced by `hydir-backend`, not an arbitrary upload.
/// Branches and loops remain explicit labels/gotos. C unsigned arithmetic
/// models LLVM's modular i64 operations; signed comparisons use sign-bit
/// biasing instead of implementation-defined C signed conversions.
pub fn emit_c(raw_llvm: &str) -> Result<String, String> {
    if raw_llvm.len() > 2 * 1024 * 1024 || raw_llvm.contains('\0') {
        return Err("raw LLVM input exceeds limit or contains NUL".to_owned());
    }
    let mut functions = Vec::<(String, String)>::new();
    let mut current = None::<(String, String)>;
    for line in raw_llvm.lines() {
        let trimmed = line.trim();
        if let Some(name) = parse_function_header(trimmed) {
            if current.is_some() || !valid_function_name(&name) {
                return Err(format!("invalid or nested scalar function: {name}"));
            }
            current = Some((name.to_owned(), format!("{trimmed}\n")));
        } else if let Some((_, source)) = current.as_mut() {
            source.push_str(line);
            source.push('\n');
            if trimmed == "}" {
                functions.push(current.take().expect("function is open"));
            }
        } else if !(trimmed.is_empty()
            || trimmed.starts_with(';')
            || trimmed.starts_with("target triple = "))
        {
            return Err(format!("unexpected LLVM module line: {trimmed}"));
        }
    }
    if current.is_some() || functions.is_empty() || functions.len() > 9 {
        return Err("expected one complete main and at most eight scalar helpers".to_owned());
    }
    let helpers: BTreeSet<String> = functions
        .iter()
        .filter(|(name, _)| name != "hydir_lifted")
        .map(|(name, _)| name.clone())
        .collect();
    if functions
        .iter()
        .filter(|(name, _)| name == "hydir_lifted")
        .count()
        != 1
        || helpers.len() + 1 != functions.len()
    {
        return Err("duplicate or missing scalar function definition".to_owned());
    }
    let mut output = String::new();
    for (name, source) in functions.iter().filter(|(name, _)| name != "hydir_lifted") {
        output.push_str(&emit_single_c(source, name, &BTreeSet::new())?);
    }
    let main = functions
        .iter()
        .find(|(name, _)| name == "hydir_lifted")
        .expect("main count checked");
    output.push_str(&emit_single_c(&main.1, &main.0, &helpers)?);
    Ok(output)
}

fn valid_function_name(name: &str) -> bool {
    name == "hydir_lifted"
        || name.strip_prefix("hydir_callee_").is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix.len() <= 16
                && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

fn parse_function_header(line: &str) -> Option<String> {
    let rest = line.strip_prefix("define i64 @")?.strip_suffix(" {")?;
    let (name, args) = rest.split_once('(')?;
    let args = args.strip_suffix(')')?;
    let params: Vec<_> = if args.trim().is_empty() {
        Vec::new()
    } else {
        args.split(", ").collect()
    };
    if params
        .iter()
        .enumerate()
        .all(|(index, param)| *param == format!("i64 %arg{index}"))
    {
        Some(name.to_owned())
    } else {
        None
    }
}

fn emit_single_c(
    raw_llvm: &str,
    function_name: &str,
    helpers: &BTreeSet<String>,
) -> Result<String, String> {
    let mut blocks = BTreeMap::<String, Block>::new();
    let mut order = Vec::<String>::new();
    let mut current = None::<Block>;
    let mut argument_names = Vec::new();
    let mut definitions = BTreeSet::new();
    let mut used = BTreeSet::new();
    let mut opened = false;
    let mut closed = false;
    for (line_number, line) in raw_llvm.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with("target triple = ") {
            continue;
        }
        if line.starts_with(&format!("define i64 @{function_name}("))
            && line.ends_with(" {")
            && !opened
        {
            let header = parse_function_header(line)
                .filter(|name| name == function_name)
                .ok_or_else(|| format!("invalid scalar function header: {line}"))?;
            let args = line
                .strip_prefix(&format!("define i64 @{header}("))
                .and_then(|rest| rest.strip_suffix(" {"))
                .and_then(|rest| rest.strip_suffix(')'))
                .unwrap_or_default();
            argument_names = if args.is_empty() {
                Vec::new()
            } else {
                args.split(", ")
                    .map(|arg| arg.trim_start_matches("i64 %").to_owned())
                    .collect()
            };
            definitions.clear();
            definitions.extend(argument_names.iter().cloned());
            opened = true;
            continue;
        }
        if line == "}" && opened && !closed {
            if let Some(block) = current.take() {
                order.push(block.label.clone());
                blocks.insert(block.label.clone(), block);
            }
            closed = true;
            continue;
        }
        if !opened || closed {
            return Err(format!("unexpected LLVM line {}: {line}", line_number + 1));
        }
        if let Some(label) = line.strip_suffix(':') {
            let label = identifier(label)?;
            if blocks.contains_key(&label)
                || current.as_ref().is_some_and(|block| block.label == label)
            {
                return Err(format!("duplicate LLVM block: {label}"));
            }
            if let Some(block) = current.take() {
                if block.terminator.is_none() {
                    return Err(format!("block {} lacks terminator", block.label));
                }
                order.push(block.label.clone());
                blocks.insert(block.label.clone(), block);
            }
            current = Some(Block {
                label,
                phis: Vec::new(),
                statements: Vec::new(),
                terminator: None,
            });
            continue;
        }
        let block = current.as_mut().ok_or("instruction before first block")?;
        if block.terminator.is_some() {
            return Err(format!("instruction after terminator in {}", block.label));
        }
        if line.starts_with("br ") || line.starts_with("ret ") {
            block.terminator = Some(parse_terminator(line, &mut used)?);
            continue;
        }
        let (destination, operation) = line
            .split_once(" = ")
            .ok_or_else(|| format!("unsupported LLVM statement: {line}"))?;
        let destination = identifier(destination)?;
        if !definitions.insert(destination.clone()) {
            return Err(format!("duplicate SSA definition: {destination}"));
        }
        if let Some(phi) = operation
            .strip_prefix("phi i64 ")
            .or_else(|| operation.strip_prefix("phi i1 "))
        {
            if !block.statements.is_empty() {
                return Err(format!("phi after non-phi in {}", block.label));
            }
            block.phis.push(Phi {
                destination,
                incoming: parse_phi(phi, &mut used)?,
            });
        } else {
            let expression = expression(operation, &mut used, helpers)?;
            block
                .statements
                .push(format!("  v_{destination} = {expression};\n"));
        }
    }
    if !opened || !closed || order.first().map(String::as_str) != Some("prologue") {
        return Err("expected one complete HydIR lifted function beginning at prologue".to_owned());
    }
    for name in &used {
        if !definitions.contains(name) {
            return Err(format!("undefined LLVM SSA value: %{name}"));
        }
    }
    let mut predecessors = BTreeMap::<String, BTreeSet<String>>::new();
    for (from, block) in &blocks {
        let targets: Vec<&String> = match block
            .terminator
            .as_ref()
            .ok_or_else(|| format!("block {from} lacks terminator"))?
        {
            Terminator::Jump(to) => vec![to],
            Terminator::Branch(_, yes, no) => vec![yes, no],
            Terminator::Return(_) => Vec::new(),
        };
        for target in targets {
            if !blocks.contains_key(target) {
                return Err(format!("unknown branch destination: {target}"));
            }
            predecessors
                .entry(target.clone())
                .or_default()
                .insert(from.clone());
        }
    }
    for (label, block) in &blocks {
        for phi in &block.phis {
            let actual: BTreeSet<_> = phi.incoming.keys().cloned().collect();
            if actual != predecessors.get(label).cloned().unwrap_or_default() {
                return Err(format!(
                    "phi {} predecessor set does not match CFG",
                    phi.destination
                ));
            }
        }
    }
    let params = argument_names
        .iter()
        .map(|name| format!("uint64_t {name}"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut output = String::from(&format!(
        "/* HydIR scalar direct-CFG C output; explicit SSA edge copies. */\n#include <stdint.h>\nuint64_t {function_name}({params}) {{\n"
    ));
    for name in &argument_names {
        output.push_str(&format!("  uint64_t v_{name} = {name};\n"));
    }
    for name in definitions
        .iter()
        .filter(|name| !argument_names.iter().any(|arg| arg == *name))
    {
        output.push_str(&format!("  uint64_t v_{name} = 0;\n"));
    }
    output.push_str("  goto L_prologue;\n");
    for label in order {
        let block = &blocks[&label];
        output.push_str(&format!("L_{label}: {{\n"));
        for statement in &block.statements {
            output.push_str(statement);
        }
        match block.terminator.as_ref().expect("validated above") {
            Terminator::Jump(to) => edge(&label, to, &blocks, &mut output)?,
            Terminator::Branch(condition, yes, no) => {
                output.push_str(&format!("  if (({condition} & UINT64_C(1)) != 0) {{\n"));
                edge(&label, yes, &blocks, &mut output)?;
                output.push_str("  } else {\n");
                edge(&label, no, &blocks, &mut output)?;
                output.push_str("  }\n");
            }
            Terminator::Return(result) => output.push_str(&format!("  return {result};\n")),
        }
        output.push_str("}\n");
    }
    output.push_str("}\n");
    Ok(output)
}

/// Emit a conservative, source-shaped C view when the raw lift matches a
/// small recognized idiom. Unknown shapes deliberately fall back to the
/// explicit direct-CFG form above.
pub fn emit_structured_c(raw_llvm: &str) -> Result<String, String> {
    // Validate the complete raw grammar before applying any presentation
    // rewrite. The structured view is never allowed to hide a lift error.
    let fallback = emit_c(raw_llvm)?;
    if raw_llvm.matches("define i64 @").count() == 1 && matches_unsigned_max(raw_llvm) {
        return Ok(
            "/* HydIR structured scalar C output; recognized unsigned max idiom. */\n\
#include <stdint.h>\n\
uint64_t hydir_lifted(uint64_t arg0, uint64_t arg1) {\n\
  return arg0 >= arg1 ? arg0 : arg1;\n\
}\n"
            .to_owned(),
        );
    }
    Ok(fallback)
}

/// Package the current native region lift and deterministic C view without
/// claiming that the dedicated CIR or statement-level provenance already
/// exists. Those missing facts remain machine-readable release blockers.
pub fn build_decompilation_unit(
    region: RegionSpec,
    raw_llvm: String,
    engine_version: &str,
) -> Result<DecompilationUnit, String> {
    let c_source = emit_structured_c(&raw_llvm)?;
    let mut diagnostics = vec![
        DecompilationDiagnostic {
            code: "cir_unavailable".to_owned(),
            severity: DiagnosticSeverity::Warning,
            message: "Dedicated structured CIR is not yet emitted; c_source is derived from the verified LLVM-compatible RegionIR"
                .to_owned(),
            blocks_stable_operation: true,
        },
        DecompilationDiagnostic {
            code: "statement_provenance_unavailable".to_owned(),
            severity: DiagnosticSeverity::Warning,
            message: "Statement-to-address provenance has not yet been established".to_owned(),
            blocks_stable_operation: true,
        },
    ];
    if !region.unresolved_facts.is_empty() {
        diagnostics.push(DecompilationDiagnostic {
            code: "region_contract_incomplete".to_owned(),
            severity: DiagnosticSeverity::Warning,
            message: format!(
                "RegionSpec retains {} unresolved fact(s)",
                region.unresolved_facts.len()
            ),
            blocks_stable_operation: true,
        });
    }
    let unit = DecompilationUnit {
        schema_version: DECOMPILATION_UNIT_VERSION,
        binary_sha256: region.binary_sha256.clone(),
        region,
        region_ir_llvm: raw_llvm,
        cir: None,
        c_source,
        statement_provenance: Vec::new(),
        diagnostics,
        engine_version: engine_version.to_owned(),
    };
    validate_decompilation_unit(&unit)?;
    Ok(unit)
}

/// Match every operation, edge, and returned value of the supported idiom.
/// A partial text match could silently replace a different valid function.
fn matches_unsigned_max(raw_llvm: &str) -> bool {
    let mut definitions = BTreeMap::<&str, &str>::new();
    let mut terminators = BTreeMap::<&str, &str>::new();
    let mut current = None;
    for line in raw_llvm.lines().map(str::trim) {
        if line.ends_with(':') {
            current = line.strip_suffix(':');
        } else if let Some((name, operation)) = line.split_once(" = ") {
            if name.starts_with('%') {
                definitions.insert(name, operation);
            }
        } else if (line.starts_with("br ") || line.starts_with("ret ")) && current.is_some() {
            terminators.insert(current.unwrap_or_default(), line);
        }
    }
    let mut at = "prologue";
    let mut visited = BTreeSet::new();
    let (condition, yes, no) = loop {
        if !visited.insert(at) {
            return false;
        }
        let Some(terminator) = terminators.get(at) else {
            return false;
        };
        if let Some(target) = terminator.strip_prefix("br label %") {
            at = target;
        } else if let Some(rest) = terminator.strip_prefix("br i1 ") {
            let Some((condition, targets)) = rest.split_once(", label %") else {
                return false;
            };
            let Some((yes, no)) = targets.split_once(", label %") else {
                return false;
            };
            break (condition, yes, no);
        } else {
            return false;
        }
    };
    let Some(invert) = definitions
        .get(condition)
        .and_then(|operation| operation.strip_prefix("xor i1 "))
        .and_then(|operation| operation.strip_suffix(", true"))
    else {
        return false;
    };
    let Some(carry) = resolve_copy(invert, None, &definitions, 0) else {
        return false;
    };
    let Some(compare) = definitions
        .get(carry.as_str())
        .and_then(|operation| operation.strip_prefix("icmp ult i64 "))
    else {
        return false;
    };
    let Some((left, right)) = compare.split_once(", ") else {
        return false;
    };
    if resolve_copy(left, None, &definitions, 0).as_deref() != Some("%arg0")
        || resolve_copy(right, None, &definitions, 0).as_deref() != Some("%arg1")
    {
        return false;
    }
    trace_return(yes, at, &definitions, &terminators).as_deref() == Some("%arg0")
        && trace_return(no, at, &definitions, &terminators).as_deref() == Some("%arg1")
}

fn resolve_copy(
    value: &str,
    predecessor: Option<&str>,
    definitions: &BTreeMap<&str, &str>,
    depth: usize,
) -> Option<String> {
    if depth > definitions.len() || !value.starts_with('%') {
        return (depth <= definitions.len()).then(|| value.to_owned());
    }
    let Some(operation) = definitions.get(value) else {
        return Some(value.to_owned());
    };
    if let Some(source) = operation.strip_prefix("add i64 0, ").or_else(|| {
        operation
            .strip_prefix("add i64 ")
            .and_then(|tail| tail.strip_suffix(", 0"))
    }) {
        return resolve_copy(source, None, definitions, depth + 1);
    }
    if operation.starts_with("phi i64 [") || operation.starts_with("phi i1 [") {
        let incoming: Vec<_> = operation
            .split('[')
            .skip(1)
            .filter_map(|part| part.split_once(']').map(|(pair, _)| pair))
            .filter_map(|pair| pair.split_once(", %"))
            .collect();
        let source = if incoming.len() == 1 {
            incoming[0].0
        } else {
            incoming
                .iter()
                .find(|(_, from)| Some(*from) == predecessor)
                .map(|(source, _)| *source)?
        };
        return resolve_copy(source, None, definitions, depth + 1);
    }
    Some(value.to_owned())
}

fn trace_return(
    start: &str,
    branch: &str,
    definitions: &BTreeMap<&str, &str>,
    terminators: &BTreeMap<&str, &str>,
) -> Option<String> {
    let mut at = start;
    let mut predecessor = branch;
    let mut visited = BTreeSet::new();
    loop {
        if !visited.insert(at) {
            return None;
        }
        let terminator = terminators.get(at)?;
        if let Some(target) = terminator.strip_prefix("br label %") {
            predecessor = at;
            at = target;
        } else if let Some(value) = terminator.strip_prefix("ret i64 ") {
            return resolve_copy(value, Some(predecessor), definitions, 0);
        } else {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{build_decompilation_unit, emit_c, emit_structured_c};

    #[test]
    fn emits_parallel_phi_edge_copies() {
        let llvm = "define i64 @hydir_lifted(i64 %arg0, i64 %arg1) {\nprologue:\n  br label %first\nfirst:\n  %a = phi i64 [%arg0, %prologue], [%b, %first]\n  %b = phi i64 [%arg1, %prologue], [%a, %first]\n  br i1 false, label %first, label %done\ndone:\n  %answer = phi i64 [%a, %first]\n  ret i64 %answer\n}\n";
        let c = emit_c(llvm).unwrap();
        assert!(c.contains("uint64_t edge_0 = v_b;"));
        assert!(c.contains("uint64_t edge_1 = v_a;"));
        assert!(c.contains("v_a = edge_0;"));
    }

    #[test]
    fn rejects_unknown_semantics_and_malformed_cfg() {
        for llvm in [
            "define i64 @hydir_lifted(i64 %arg0, i64 %arg1) {\nprologue:\n  %x = call i64 @evil()\n  ret i64 %x\n}\n",
            "define i64 @hydir_lifted(i64 %arg0, i64 %arg1) {\nprologue:\n  br label %missing\n}\n",
            "define i64 @hydir_lifted(i64 %arg0, i64 %arg1) {\nprologue:\n  br label %end\nend:\n  %x = phi i64 [%arg0, %wrong]\n  ret i64 %x\n}\n",
        ] {
            assert!(emit_c(llvm).is_err());
        }
    }

    #[test]
    fn structures_unsigned_max_idiom() {
        let llvm = "define i64 @hydir_lifted(i64 %arg0, i64 %arg1) {\nprologue:\n  br label %check\ncheck:\n  %cf = icmp ult i64 %arg0, %arg1\n  %not_cf = xor i1 %cf, true\n  br i1 %not_cf, label %left, label %right\nleft:\n  %left_value = add i64 0, %arg0\n  br label %done\nright:\n  %right_value = add i64 0, %arg1\n  br label %done\ndone:\n  %answer = phi i64 [%left_value, %left], [%right_value, %right]\n  ret i64 %answer\n}\n";
        let c = emit_structured_c(llvm).unwrap();
        assert!(c.contains("return arg0 >= arg1 ? arg0 : arg1;"));
        assert!(!c.contains("edge_0"));
    }

    #[test]
    fn unrelated_valid_return_never_becomes_unsigned_max() {
        let llvm = "define i64 @hydir_lifted(i64 %arg0, i64 %arg1) {\nprologue:\n  %cf = icmp ult i64 %arg0, %arg1\n  %not_cf = xor i1 %cf, true\n  %left_value = add i64 0, %arg0\n  %right_value = add i64 0, %arg1\n  ret i64 %arg0\n}\n";
        let c = emit_structured_c(llvm).unwrap();
        assert!(c.contains("return v_arg0;"));
        assert!(!c.contains("return arg0 >= arg1"));
    }

    #[test]
    fn real_max_lift_structures_only_with_original_return_path() {
        let machine = [
            0x48, 0x89, 0xf8, 0x48, 0x39, 0xf7, 0x73, 0x03, 0x48, 0x89, 0xf0, 0xc3,
        ];
        let ir = hydir_backend::lift_cfg(&machine, 0x401000).unwrap();
        assert!(
            emit_structured_c(&ir)
                .unwrap()
                .contains("return arg0 >= arg1")
        );
        let changed = ir.replace("ret i64 %rax_in_40100b", "ret i64 %arg0");
        assert_ne!(changed, ir);
        assert!(
            !emit_structured_c(&changed)
                .unwrap()
                .contains("return arg0 >= arg1")
        );
    }

    #[test]
    fn mov32_lift_masks_high_bits_in_c() {
        let ir = hydir_backend::lift_cfg(&[0x89, 0xf8, 0xc3], 0x1000).unwrap();
        let c = emit_structured_c(&ir).unwrap();
        assert!(c.contains("UINT64_C(4294967295)"));
        assert!(c.contains("return v_rax_in_1002;"));
    }

    #[test]
    fn unsupported_integer_conversion_fails_closed() {
        let llvm = "define i64 @hydir_lifted(i64 %arg0, i64 %arg1) {\nprologue:\n  %x = zext i16 %arg0 to i64\n  ret i64 %x\n}\n";
        assert!(
            emit_structured_c(llvm)
                .unwrap_err()
                .contains("unsupported integer conversion")
        );
    }

    #[test]
    fn emits_resolved_leaf_call_and_rejects_helper_recursion() {
        let helper = "define i64 @hydir_callee_2000(i64 %arg0, i64 %arg1) {\nprologue:\n  ret i64 %arg0\n}\n";
        let main = "define i64 @hydir_lifted(i64 %arg0, i64 %arg1) {\nprologue:\n  %answer = call i64 @hydir_callee_2000(i64 %arg0, i64 %arg1)\n  ret i64 %answer\n}\n";
        let c = emit_c(&format!("{helper}{main}")).unwrap();
        assert!(c.contains("uint64_t hydir_callee_2000("));
        assert!(c.contains("hydir_callee_2000(v_arg0, v_arg1)"));
        let recursive = helper.replace(
            "ret i64 %arg0",
            "  %x = call i64 @hydir_callee_2000(i64 %arg0, i64 %arg1)\n  ret i64 %x",
        );
        assert!(emit_c(&format!("{recursive}{main}")).is_err());
    }

    #[test]
    fn decompilation_unit_is_digest_bound_and_explicitly_incomplete() {
        let binary = include_bytes!("../../../fuzz/corpus/elf_import/max2.elf");
        let region = hydir_backend::region_contract(binary, "hydir_max2").unwrap();
        let ir = hydir_backend::lift_symbol(binary, "hydir_max2").unwrap();
        let unit = build_decompilation_unit(region, ir, "hydir-test").unwrap();
        assert_eq!(unit.schema_version, hydir_core::DECOMPILATION_UNIT_VERSION);
        assert_eq!(unit.binary_sha256, unit.region.binary_sha256);
        assert!(unit.cir.is_none());
        assert!(
            unit.diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "statement_provenance_unavailable")
        );
    }
}
