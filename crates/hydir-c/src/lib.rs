//! Fail-closed C emission for HydIR's raw scalar direct-CFG LLVM lift.
//!
//! This is a small LLVM-to-C backend, not a general LLVM parser or Rellic.
//! It preserves explicit control flow and lowers SSA phis with parallel edge
//! copies. Only the exact instruction subset emitted by `hydir-backend` is
//! accepted; unfamiliar LLVM syntax is an error, never an ignored operation.

use hydir_ir::{
    Cir, CirStatement, CirTerminator, InstructionDecorators, MachineOperand, validate_cir,
};

use hydir_core::{
    Address, DECOMPILATION_UNIT_VERSION, DecompilationArtifactDigests, DecompilationDiagnostic,
    DecompilationSemanticFidelity, DecompilationStructuralCompleteness, DecompilationUnit,
    DecompilationVerificationStatus, DiagnosticSeverity, FactProvenance, FactSource,
    RegionDecisionIr, RegionPredicate, RegionSpec, StatementAddressProvenance,
    validate_decompilation_unit, validate_region_decision_ir,
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

fn decision_integer_type(width_bits: u16) -> Result<(&'static str, &'static str), String> {
    match width_bits {
        1 => Ok(("i1", "uint8_t")),
        8 => Ok(("i8", "uint8_t")),
        16 => Ok(("i16", "uint16_t")),
        32 => Ok(("i32", "uint32_t")),
        64 => Ok(("i64", "uint64_t")),
        other => Err(format!(
            "decision RegionIR cannot render {other}-bit physical state"
        )),
    }
}

fn decision_flag_input(ir: &RegionDecisionIr, name: &str) -> Result<usize, String> {
    ir.physical_inputs
        .iter()
        .position(|input| input.name.eq_ignore_ascii_case(name))
        .ok_or_else(|| format!("decision RegionIR lacks required {name} input"))
}

fn emit_decision_llvm_predicate(
    ir: &RegionDecisionIr,
    body: &mut String,
) -> Result<String, String> {
    let mut flag = |name: &str| -> Result<String, String> {
        let index = decision_flag_input(ir, name)?;
        match ir.physical_inputs[index].width_bits {
            1 => Ok(format!("%in{index}")),
            8 => {
                let value = format!("%flag_{}", name.to_ascii_lowercase());
                body.push_str(&format!("  {value} = trunc i8 %in{index} to i1\n"));
                Ok(value)
            }
            width => Err(format!(
                "decision RegionIR {name} input has unsupported width {width}"
            )),
        }
    };
    let mut sequence = 0usize;
    let temporary = |body: &mut String, sequence: &mut usize, operation: String| {
        let name = format!("%predicate_{sequence}");
        *sequence += 1;
        body.push_str(&format!("  {name} = {operation}\n"));
        name
    };
    let predicate = match ir.predicate {
        RegionPredicate::Equal => flag("ZF")?,
        RegionPredicate::NotEqual => {
            let zf = flag("ZF")?;
            temporary(body, &mut sequence, format!("xor i1 {zf}, true"))
        }
        RegionPredicate::Signed => flag("SF")?,
        RegionPredicate::NotSigned => {
            let sf = flag("SF")?;
            temporary(body, &mut sequence, format!("xor i1 {sf}, true"))
        }
        RegionPredicate::Overflow => flag("OF")?,
        RegionPredicate::NotOverflow => {
            let of = flag("OF")?;
            temporary(body, &mut sequence, format!("xor i1 {of}, true"))
        }
        RegionPredicate::Below => flag("CF")?,
        RegionPredicate::AboveOrEqual => {
            let cf = flag("CF")?;
            temporary(body, &mut sequence, format!("xor i1 {cf}, true"))
        }
        RegionPredicate::BelowOrEqual | RegionPredicate::Above => {
            let cf = flag("CF")?;
            let zf = flag("ZF")?;
            let either = temporary(body, &mut sequence, format!("or i1 {cf}, {zf}"));
            if ir.predicate == RegionPredicate::Above {
                temporary(body, &mut sequence, format!("xor i1 {either}, true"))
            } else {
                either
            }
        }
        RegionPredicate::Less | RegionPredicate::GreaterOrEqual => {
            let sf = flag("SF")?;
            let of = flag("OF")?;
            let less = temporary(body, &mut sequence, format!("xor i1 {sf}, {of}"));
            if ir.predicate == RegionPredicate::GreaterOrEqual {
                temporary(body, &mut sequence, format!("xor i1 {less}, true"))
            } else {
                less
            }
        }
        RegionPredicate::LessOrEqual | RegionPredicate::Greater => {
            let zf = flag("ZF")?;
            let sf = flag("SF")?;
            let of = flag("OF")?;
            let less = temporary(body, &mut sequence, format!("xor i1 {sf}, {of}"));
            if ir.predicate == RegionPredicate::LessOrEqual {
                temporary(body, &mut sequence, format!("or i1 {zf}, {less}"))
            } else {
                let nonzero = temporary(body, &mut sequence, format!("xor i1 {zf}, true"));
                let same_sign = temporary(body, &mut sequence, format!("xor i1 {less}, true"));
                temporary(
                    body,
                    &mut sequence,
                    format!("and i1 {nonzero}, {same_sign}"),
                )
            }
        }
    };
    Ok(predicate)
}

fn emit_decision_llvm_exit(
    body: &mut String,
    label: &str,
    exit: Address,
    ir: &RegionDecisionIr,
) -> Result<(), String> {
    body.push_str(&format!("{label}:\n"));
    let mut value = format!("%{label}_result_0");
    body.push_str(&format!(
        "  {value} = insertvalue %hydir_region_result poison, i64 {}, 0\n",
        exit.0
    ));
    for (index, binding) in ir.pass_through.iter().enumerate() {
        let input_index = usize::try_from(binding.input_index)
            .map_err(|_| "decision RegionIR input index overflows")?;
        let output_index = usize::try_from(binding.output_index)
            .map_err(|_| "decision RegionIR output index overflows")?;
        let (llvm_type, _) = decision_integer_type(ir.physical_outputs[output_index].width_bits)?;
        let next = format!("%{label}_result_{}", index + 1);
        body.push_str(&format!(
            "  {next} = insertvalue %hydir_region_result {value}, {llvm_type} %in{input_index}, {}\n",
            output_index + 1
        ));
        value = next;
    }
    body.push_str(&format!("  ret %hydir_region_result {value}\n"));
    Ok(())
}

/// Render LLVM 17-compatible text for a validated typed decision RegionIR.
pub fn emit_decision_region_llvm(
    ir: &RegionDecisionIr,
    region: &RegionSpec,
) -> Result<String, String> {
    validate_region_decision_ir(ir, region)?;
    let output_types = ir
        .physical_outputs
        .iter()
        .map(|output| decision_integer_type(output.width_bits).map(|types| types.0))
        .collect::<Result<Vec<_>, _>>()?;
    let input_parameters = ir
        .physical_inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            decision_integer_type(input.width_bits).map(|types| format!("{} %in{index}", types.0))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut body = String::new();
    for address in &ir.instruction_addresses {
        body.push_str(&format!("  ; 0x{:x}\n", address.0));
    }
    let predicate = emit_decision_llvm_predicate(ir, &mut body)?;
    body.push_str(&format!(
        "  br i1 {predicate}, label %exit_true, label %exit_false\n"
    ));
    emit_decision_llvm_exit(&mut body, "exit_true", ir.true_exit, ir)?;
    emit_decision_llvm_exit(&mut body, "exit_false", ir.false_exit, ir)?;
    let mut result_types = vec!["i64"];
    result_types.extend(output_types);
    Ok(format!(
        "; HydIR typed decision RegionIR v1; all physical outputs are explicit pass-through bindings.\n\
         target triple = \"x86_64-unknown-linux-gnu\"\n\n\
         %hydir_region_result = type {{ {} }}\n\n\
         define %hydir_region_result @hydir_region({}) {{\nentry:\n{body}}}\n",
        result_types.join(", "),
        input_parameters.join(", ")
    ))
}

fn decision_c_flag(ir: &RegionDecisionIr, name: &str) -> Result<String, String> {
    let index = decision_flag_input(ir, name)?;
    Ok(format!("((in{index} & UINT8_C(1)) != 0)"))
}

fn decision_c_comment(value: &str) -> String {
    value.replace("*/", "* /").replace(['\r', '\n'], " ")
}

fn decision_c_predicate(ir: &RegionDecisionIr) -> Result<String, String> {
    let flag = |name| decision_c_flag(ir, name);
    Ok(match ir.predicate {
        RegionPredicate::Equal => flag("ZF")?,
        RegionPredicate::NotEqual => format!("!{}", flag("ZF")?),
        RegionPredicate::Signed => flag("SF")?,
        RegionPredicate::NotSigned => format!("!{}", flag("SF")?),
        RegionPredicate::Overflow => flag("OF")?,
        RegionPredicate::NotOverflow => format!("!{}", flag("OF")?),
        RegionPredicate::Below => flag("CF")?,
        RegionPredicate::AboveOrEqual => format!("!{}", flag("CF")?),
        RegionPredicate::BelowOrEqual => format!("({} || {})", flag("CF")?, flag("ZF")?),
        RegionPredicate::Above => format!("(!{} && !{})", flag("CF")?, flag("ZF")?),
        RegionPredicate::Less => format!("({} != {})", flag("SF")?, flag("OF")?),
        RegionPredicate::GreaterOrEqual => format!("({} == {})", flag("SF")?, flag("OF")?),
        RegionPredicate::LessOrEqual => {
            format!("({} || ({} != {}))", flag("ZF")?, flag("SF")?, flag("OF")?)
        }
        RegionPredicate::Greater => {
            format!("(!{} && ({} == {}))", flag("ZF")?, flag("SF")?, flag("OF")?)
        }
    })
}

fn emit_decision_c_return(
    output: &mut String,
    exit: Address,
    ir: &RegionDecisionIr,
) -> Result<(), String> {
    output.push_str(&format!(
        "    return (hydir_region_result){{ .exit_address = UINT64_C({})",
        exit.0
    ));
    for binding in &ir.pass_through {
        output.push_str(&format!(
            ", .out{} = in{}",
            binding.output_index, binding.input_index
        ));
    }
    output.push_str(" };\n");
    Ok(())
}

/// Render deterministic C for a validated typed decision RegionIR.
pub fn emit_decision_region_c(
    ir: &RegionDecisionIr,
    region: &RegionSpec,
) -> Result<String, String> {
    validate_region_decision_ir(ir, region)?;
    let mut output = String::from(
        "/* HydIR typed decision RegionIR v1; explicit continuations and pass-through state. */\n#include <stdint.h>\n\ntypedef struct {\n  uint64_t exit_address;\n",
    );
    for (index, physical) in ir.physical_outputs.iter().enumerate() {
        let (_, c_type) = decision_integer_type(physical.width_bits)?;
        output.push_str(&format!(
            "  {c_type} out{index}; /* {} */\n",
            decision_c_comment(&physical.name)
        ));
    }
    output.push_str("} hydir_region_result;\n\nhydir_region_result hydir_region(");
    let parameters = ir
        .physical_inputs
        .iter()
        .enumerate()
        .map(|(index, physical)| {
            decision_integer_type(physical.width_bits).map(|types| {
                format!(
                    "{} in{index} /* {} */",
                    types.1,
                    decision_c_comment(&physical.name)
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    output.push_str(&parameters.join(", "));
    output.push_str(") {\n");
    for address in &ir.instruction_addresses {
        output.push_str(&format!("  /* 0x{:x} */\n", address.0));
    }
    output.push_str(&format!("  if ({}) {{\n", decision_c_predicate(ir)?));
    emit_decision_c_return(&mut output, ir.true_exit, ir)?;
    output.push_str("  } else {\n");
    emit_decision_c_return(&mut output, ir.false_exit, ir)?;
    output.push_str("  }\n}\n");
    Ok(output)
}

/// Package a typed decision RegionIR and its deterministic C view. Unlike the
/// legacy scalar unit, this unit contains a native CIR payload and has no
/// implicit SysV function-signature assumption.
pub fn build_decision_decompilation_unit(
    region: RegionSpec,
    ir: RegionDecisionIr,
    engine_version: &str,
) -> Result<DecompilationUnit, String> {
    validate_region_decision_ir(&ir, &region)?;
    let region_ir_llvm = emit_decision_region_llvm(&ir, &region)?;
    let c_source = emit_decision_region_c(&ir, &region)?;
    let c_line = c_source
        .lines()
        .position(|line| line.trim_start().starts_with("if ("))
        .and_then(|index| u32::try_from(index + 1).ok())
        .ok_or_else(|| "decision C output lacks its condition statement".to_owned())?;
    let statement_provenance = vec![StatementAddressProvenance {
        c_start_line: c_line,
        c_end_line: c_line,
        addresses: ir.instruction_addresses.clone(),
        provenance: FactProvenance {
            source: FactSource::NativeAnalysis,
            scope: "typed decision C emitted from all RegionDecisionIR instructions".to_owned(),
        },
    }];
    let mut diagnostics = Vec::new();
    if !region.unresolved_facts.is_empty() {
        diagnostics.push(DecompilationDiagnostic {
            code: "region_contract_incomplete".to_owned(),
            severity: DiagnosticSeverity::Warning,
            message: format!(
                "RegionSpec retains {} unresolved fact(s); decompilation is available but replacement is not authorized",
                region.unresolved_facts.len()
            ),
            blocks_stable_operation: true,
        });
    }
    let structurally_complete = region.unresolved_facts.is_empty();
    let rewrite_ready = region.replacement_ready && structurally_complete;
    let unit = DecompilationUnit {
        schema_version: DECOMPILATION_UNIT_VERSION,
        binary_sha256: region.binary_sha256.clone(),
        function_id: Some(format!(
            "sha256:{}:region:0x{:x}",
            region.binary_sha256, region.entry.0
        )),
        model_revision: None,
        artifacts: DecompilationArtifactDigests::default(),
        region,
        region_ir_llvm,
        cir: Some(serde_json::to_string_pretty(&ir).map_err(|error| error.to_string())?),
        c_source: c_source.clone(),
        low_level_c: Some(c_source.clone()),
        structured_c: Some(c_source),
        structural_completeness: if structurally_complete {
            DecompilationStructuralCompleteness::Complete
        } else {
            DecompilationStructuralCompleteness::Partial
        },
        semantic_fidelity: DecompilationSemanticFidelity::ExactUnderModel,
        verification: DecompilationVerificationStatus::StaticallyValidated,
        rewrite_ready,
        statement_provenance,
        diagnostics,
        engine_version: engine_version.to_owned(),
    };
    validate_decompilation_unit(&unit)?;
    Ok(unit)
}

fn block_address(label: &str, prefix: &str, suffix: &str) -> Option<Address> {
    let value = label.trim().strip_prefix(prefix)?.strip_suffix(suffix)?;
    (!value.is_empty())
        .then(|| u64::from_str_radix(value, 16).ok().map(Address))
        .flatten()
}

fn address_in_region(region: &RegionSpec, address: Address) -> bool {
    region
        .entry
        .0
        .checked_add(region.byte_length)
        .is_some_and(|end| (region.entry.0..end).contains(&address.0))
}

/// Emit Hydir's native CIR as a deterministic, compilable C11 translation
/// unit. The explicit machine-state ABI is intentional: until ABI recovery is
/// complete, it preserves state without inventing a source signature.
pub fn emit_native_low_level_c(cir: &Cir) -> Result<String, String> {
    validate_cir(cir)?;
    let labels = cir
        .blocks
        .iter()
        .map(|block| block.address)
        .collect::<std::collections::BTreeSet<_>>();
    let mut output = native_prelude(&cir.name);
    output.push_str(&format!("  goto {};\n", c_label(cir.entry)));
    for block in &cir.blocks {
        output.push_str(&format!("{}:\n  ;\n", c_label(block.address)));
        for statement in &block.statements {
            emit_native_statement(&mut output, statement)?;
        }
        emit_native_terminator(&mut output, &block.terminator, &labels)?;
    }
    output.push_str("}\n");
    Ok(output)
}

/// Emit a structured view when CIR proves a supported control-flow shape.
/// Reducible natural loops may be mixed with explicit labels/gotos for the
/// residual regions; those transfers remain visible rather than being folded
/// into an invented source construct.
pub fn emit_native_structured_c(cir: &Cir) -> Result<Option<String>, String> {
    validate_cir(cir)?;
    let mut ordered = cir.blocks.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|block| block.address);
    if ordered.first().map(|block| block.address) != Some(cir.entry) {
        return Ok(None);
    }
    let linear = ordered
        .iter()
        .enumerate()
        .all(|(index, block)| match &block.terminator {
            CirTerminator::Fallthrough { target }
                if ordered.get(index + 1).map(|next| next.address) == Some(*target) =>
            {
                true
            }
            CirTerminator::Return if index + 1 == ordered.len() => true,
            CirTerminator::Exit { .. } if index + 1 == ordered.len() => true,
            _ => false,
        });
    if !linear {
        if let Some(diamond) = emit_single_diamond_c(cir)? {
            return Ok(Some(diamond));
        }
        if let Some(guarded_switch) = emit_guarded_switch_c(cir)? {
            return Ok(Some(guarded_switch));
        }
        if let Some(acyclic) = emit_acyclic_structured_c(cir)? {
            return Ok(Some(acyclic));
        }
        if let Some(header_loop) = emit_single_header_loop_c(cir)? {
            return Ok(Some(header_loop));
        }
        if let Some(latch_loop) = emit_single_latch_loop_c(cir)? {
            return Ok(Some(latch_loop));
        }
        return emit_natural_loop_regions_c(cir);
    }
    let mut output = native_prelude(&cir.name);
    for block in ordered {
        for statement in &block.statements {
            emit_native_statement(&mut output, statement)?;
        }
        match block.terminator {
            CirTerminator::Return => {
                output.push_str("  state->rsp += UINT64_C(8);\n  return;\n");
            }
            CirTerminator::Exit { target } => {
                let target = target.map_or(0, |location| location.value.0);
                output.push_str(&format!(
                    "  hydir_external_exit(state, UINT64_C(0x{target:x}));\n"
                ));
            }
            _ => {}
        }
    }
    output.push_str("}\n");
    Ok(Some(output))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NaturalLoopRegion {
    header: usize,
    end: usize,
}

/// Structure every proven, non-overlapping natural loop while preserving the
/// rest of the CIR CFG literally. This is the safe fallback for compiler CFGs
/// containing several loops or guards that cannot yet be rendered as a fully
/// goto-free syntax tree.
fn emit_natural_loop_regions_c(cir: &Cir) -> Result<Option<String>, String> {
    let mut blocks = cir.blocks.iter().collect::<Vec<_>>();
    blocks.sort_by_key(|block| block.address);
    let Some(entry) = blocks.iter().position(|block| block.address == cir.entry) else {
        return Ok(None);
    };
    let by_location = blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.address, index))
        .collect::<BTreeMap<_, _>>();
    let successors = blocks
        .iter()
        .map(|block| cir_successor_indices(&block.terminator, &by_location))
        .collect::<Vec<_>>();
    let mut reachable = BTreeSet::new();
    let mut pending = vec![entry];
    while let Some(index) = pending.pop() {
        if reachable.insert(index) {
            pending.extend(successors[index].iter().copied());
        }
    }
    if reachable.len() != blocks.len() {
        return Ok(None);
    }

    let universe = reachable.clone();
    let mut dominators = vec![universe.clone(); blocks.len()];
    dominators[entry] = BTreeSet::from([entry]);
    loop {
        let mut changed = false;
        for index in reachable.iter().copied().filter(|index| *index != entry) {
            let predecessors = successors
                .iter()
                .enumerate()
                .filter_map(|(source, targets)| targets.contains(&index).then_some(source))
                .collect::<Vec<_>>();
            let Some((first, rest)) = predecessors.split_first() else {
                return Ok(None);
            };
            let mut next = dominators[*first].clone();
            for predecessor in rest {
                next = next
                    .intersection(&dominators[*predecessor])
                    .copied()
                    .collect();
            }
            next.insert(index);
            if next != dominators[index] {
                dominators[index] = next;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    let predecessors = (0..blocks.len())
        .map(|target| {
            successors
                .iter()
                .enumerate()
                .filter_map(|(source, targets)| targets.contains(&target).then_some(source))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let mut loop_nodes = BTreeMap::<usize, BTreeSet<usize>>::new();
    for (source, targets) in successors.iter().enumerate() {
        for header in targets {
            if !dominators[source].contains(header) {
                continue;
            }
            let nodes = loop_nodes
                .entry(*header)
                .or_insert_with(|| BTreeSet::from([*header]));
            nodes.insert(source);
            let mut work = vec![source];
            while let Some(node) = work.pop() {
                if node == *header {
                    continue;
                }
                for predecessor in &predecessors[node] {
                    if nodes.insert(*predecessor) {
                        work.push(*predecessor);
                    }
                }
            }
        }
    }
    if loop_nodes.is_empty() {
        return Ok(None);
    }

    let mut regions = Vec::new();
    for (header, nodes) in loop_nodes {
        let Some(end) = nodes.iter().next_back().copied() else {
            continue;
        };
        if nodes.iter().next().copied() != Some(header)
            || nodes.len() != end - header + 1
            || (header..=end).any(|index| !nodes.contains(&index))
        {
            return Ok(None);
        }
        if (header..=end).any(|index| {
            index != header
                && predecessors[index]
                    .iter()
                    .any(|predecessor| *predecessor < header || *predecessor > end)
        }) {
            return Ok(None);
        }
        regions.push(NaturalLoopRegion { header, end });
    }
    regions.sort_by_key(|region| region.header);
    if regions.windows(2).any(|pair| pair[0].end >= pair[1].header) {
        return Ok(None);
    }

    let labels = blocks
        .iter()
        .map(|block| block.address)
        .collect::<BTreeSet<_>>();
    let mut referenced_labels = BTreeSet::from([cir.entry]);
    for (source, block) in blocks.iter().enumerate() {
        let region = regions
            .iter()
            .copied()
            .find(|region| region.header <= source && source <= region.end);
        for target in cir_terminator_targets(&block.terminator) {
            if labels.contains(&target)
                && !is_hybrid_structured_transfer(target, source, region, &by_location)
            {
                referenced_labels.insert(target);
            }
        }
    }
    let mut output = native_prelude(&cir.name);
    output.push_str(&format!("  goto {};\n", c_label(cir.entry)));
    for (index, block) in blocks.iter().enumerate() {
        let region = regions
            .iter()
            .copied()
            .find(|region| region.header <= index && index <= region.end);
        if region.is_some_and(|region| region.header == index) {
            output.push_str("  for (;;) {\n");
        }
        let indent = if region.is_some() { "  " } else { "" };
        if referenced_labels.contains(&block.address) {
            output.push_str(&format!(
                "{indent}{}:\n{indent}  ;\n",
                c_label(block.address)
            ));
        }
        emit_structured_statements(&mut output, block, indent)?;
        emit_hybrid_terminator(
            &mut output,
            &block.terminator,
            index,
            region,
            &by_location,
            &labels,
            indent,
        )?;
        if region.is_some_and(|region| region.end == index) {
            output.push_str("  }\n");
        }
    }
    output.push_str("}\n");
    Ok(Some(output))
}

fn cir_terminator_targets(terminator: &CirTerminator) -> Vec<hydir_core::Location> {
    match terminator {
        CirTerminator::Fallthrough { target } | CirTerminator::Goto { target } => vec![*target],
        CirTerminator::Branch {
            taken, fallthrough, ..
        } => vec![*taken, *fallthrough],
        CirTerminator::Call { next, .. } => next.iter().copied().collect(),
        CirTerminator::Switch { targets, .. } => targets.clone(),
        CirTerminator::Return | CirTerminator::Exit { .. } | CirTerminator::Unresolved { .. } => {
            Vec::new()
        }
    }
}

fn cir_successor_indices(
    terminator: &CirTerminator,
    by_location: &BTreeMap<hydir_core::Location, usize>,
) -> Vec<usize> {
    let targets = match terminator {
        CirTerminator::Fallthrough { target } | CirTerminator::Goto { target } => vec![*target],
        CirTerminator::Branch {
            taken, fallthrough, ..
        } => vec![*taken, *fallthrough],
        CirTerminator::Call { next, .. } => next.iter().copied().collect(),
        CirTerminator::Switch { targets, .. } => targets.clone(),
        CirTerminator::Return | CirTerminator::Exit { .. } | CirTerminator::Unresolved { .. } => {
            Vec::new()
        }
    };
    targets
        .into_iter()
        .filter_map(|target| by_location.get(&target).copied())
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn emit_hybrid_terminator(
    output: &mut String,
    terminator: &CirTerminator,
    source: usize,
    region: Option<NaturalLoopRegion>,
    by_location: &BTreeMap<hydir_core::Location, usize>,
    labels: &BTreeSet<hydir_core::Location>,
    extra_indent: &str,
) -> Result<(), String> {
    let indent = format!("{extra_indent}  ");
    match terminator {
        CirTerminator::Fallthrough { target } | CirTerminator::Goto { target } => {
            emit_hybrid_target(
                output,
                *target,
                source,
                region,
                by_location,
                labels,
                &indent,
            );
        }
        CirTerminator::Branch {
            condition,
            taken,
            fallthrough,
        } => {
            output.push_str(&format!("{indent}if ({}) {{\n", c_condition(condition)?));
            emit_hybrid_target(
                output,
                *taken,
                source,
                region,
                by_location,
                labels,
                &format!("{indent}  "),
            );
            output.push_str(&format!("{indent}}} else {{\n"));
            emit_hybrid_target(
                output,
                *fallthrough,
                source,
                region,
                by_location,
                labels,
                &format!("{indent}  "),
            );
            output.push_str(&format!("{indent}}}\n"));
        }
        CirTerminator::Call {
            target,
            target_operand,
            next,
        } => {
            if let Some(target) = target {
                output.push_str(&format!(
                    "{indent}hydir_call(state, UINT64_C(0x{:x}));\n",
                    target.value.0
                ));
            } else if let Some(target_operand) = target_operand {
                output.push_str(&format!(
                    "{indent}/* unresolved indirect call target */\n{indent}hydir_unknown_call(state, (uint64_t)({}));\n",
                    read_operand(target_operand)?
                ));
            } else {
                output.push_str(&format!(
                    "{indent}/* unresolved call target */\n{indent}hydir_unknown_call(state, UINT64_C(0));\n"
                ));
            }
            if let Some(next) = next {
                emit_hybrid_target(output, *next, source, region, by_location, labels, &indent);
            } else {
                output.push_str(&format!("{indent}return;\n"));
            }
        }
        CirTerminator::Switch {
            dispatch,
            targets,
            unresolved_default,
        } => {
            output.push_str(&format!(
                "{indent}switch (hydir_indirect_target(state, UINT64_C(0x{:x}))) {{\n",
                dispatch.value.0
            ));
            for target in targets {
                output.push_str(&format!(
                    "{indent}  case UINT64_C(0x{:x}):\n",
                    target.value.0
                ));
                emit_hybrid_target(
                    output,
                    *target,
                    source,
                    region,
                    by_location,
                    labels,
                    &format!("{indent}    "),
                );
            }
            if *unresolved_default {
                output.push_str(&format!(
                    "{indent}  default:\n{indent}    hydir_unknown_control(state, UINT64_C(0));\n{indent}    return;\n"
                ));
            }
            output.push_str(&format!("{indent}}}\n"));
        }
        CirTerminator::Return => {
            output.push_str(&format!(
                "{indent}state->rsp += UINT64_C(8);\n{indent}return;\n"
            ));
        }
        CirTerminator::Exit { target } => {
            let target = target.map_or(0, |location| location.value.0);
            output.push_str(&format!(
                "{indent}hydir_external_exit(state, UINT64_C(0x{target:x}));\n{indent}return;\n"
            ));
        }
        CirTerminator::Unresolved {
            reason,
            target_operand,
        } => {
            let target = target_operand
                .as_ref()
                .map(read_operand)
                .transpose()?
                .unwrap_or_else(|| "UINT64_C(0)".to_owned());
            output.push_str(&format!(
                "{indent}/* {} */\n{indent}hydir_unknown_control(state, (uint64_t)({target}));\n{indent}return;\n",
                c_comment(reason)
            ));
        }
    }
    Ok(())
}

fn emit_hybrid_target(
    output: &mut String,
    target: hydir_core::Location,
    source: usize,
    region: Option<NaturalLoopRegion>,
    by_location: &BTreeMap<hydir_core::Location, usize>,
    labels: &BTreeSet<hydir_core::Location>,
    indent: &str,
) {
    if let (Some(region), Some(target_index)) = (region, by_location.get(&target).copied()) {
        if target_index == region.header && source >= region.header {
            output.push_str(&format!("{indent}continue;\n"));
            return;
        }
        if target_index == region.end + 1 {
            output.push_str(&format!("{indent}break;\n"));
            return;
        }
    }
    emit_target_indented(output, target, labels, indent);
}

fn is_hybrid_structured_transfer(
    target: hydir_core::Location,
    source: usize,
    region: Option<NaturalLoopRegion>,
    by_location: &BTreeMap<hydir_core::Location, usize>,
) -> bool {
    let (Some(region), Some(target_index)) = (region, by_location.get(&target).copied()) else {
        return false;
    };
    (target_index == region.header && source >= region.header) || target_index == region.end + 1
}

fn emit_single_header_loop_c(cir: &Cir) -> Result<Option<String>, String> {
    let blocks = cir
        .blocks
        .iter()
        .map(|block| (block.address, block))
        .collect::<BTreeMap<_, _>>();
    let branches = cir
        .blocks
        .iter()
        .filter(|block| matches!(block.terminator, CirTerminator::Branch { .. }))
        .collect::<Vec<_>>();
    let [condition_block] = branches.as_slice() else {
        return Ok(None);
    };
    let back_edges = cir
        .blocks
        .iter()
        .filter_map(|block| {
            let target = match block.terminator {
                CirTerminator::Fallthrough { target } | CirTerminator::Goto { target } => target,
                _ => return None,
            };
            (target.address_space == block.address.address_space
                && target.value.0 <= block.address.value.0
                && blocks.contains_key(&target))
            .then_some((block.address, target))
        })
        .collect::<Vec<_>>();
    let [(back_source, header)] = back_edges.as_slice() else {
        return Ok(None);
    };
    let Some(test_path) = linear_path_until(*header, condition_block.address, &blocks) else {
        return Ok(None);
    };
    let CirTerminator::Branch {
        condition,
        taken,
        fallthrough,
    } = &condition_block.terminator
    else {
        unreachable!("condition block selected above")
    };
    let candidates = [(*taken, *fallthrough, true), (*fallthrough, *taken, false)];
    let Some((body_path, suffix, repeat_when_true)) =
        candidates.into_iter().find_map(|(body, exit, repeat)| {
            let body_path = linear_path_until(body, *back_source, &blocks)?;
            let suffix = linear_structured_path(exit, &blocks)?;
            Some((body_path, suffix, repeat))
        })
    else {
        return Ok(None);
    };
    let Some(mut prefix) = linear_path_until(cir.entry, *header, &blocks) else {
        return Ok(None);
    };
    prefix.pop();
    let listed = prefix.len() + test_path.len() + body_path.len() + suffix.len();
    let covered = prefix
        .iter()
        .chain(&test_path)
        .chain(&body_path)
        .chain(&suffix)
        .copied()
        .collect::<BTreeSet<_>>();
    if listed != covered.len() || covered.len() != cir.blocks.len() {
        return Ok(None);
    }

    let mut output = native_prelude(&cir.name);
    for location in &prefix {
        emit_structured_statements(
            &mut output,
            blocks.get(location).copied().expect("prefix block exists"),
            "",
        )?;
    }
    output.push_str("  for (;;) {\n");
    for location in &test_path {
        emit_structured_statements(
            &mut output,
            blocks
                .get(location)
                .copied()
                .expect("loop test block exists"),
            "  ",
        )?;
    }
    let condition = c_condition(condition)?;
    if repeat_when_true {
        output.push_str(&format!("    if (!({condition})) break;\n"));
    } else {
        output.push_str(&format!("    if ({condition}) break;\n"));
    }
    for location in &body_path {
        emit_structured_statements(
            &mut output,
            blocks
                .get(location)
                .copied()
                .expect("loop body block exists"),
            "  ",
        )?;
    }
    output.push_str("  }\n");
    for location in &suffix {
        emit_structured_statements(
            &mut output,
            blocks.get(location).copied().expect("suffix block exists"),
            "",
        )?;
    }
    let Some(last) = suffix
        .last()
        .and_then(|location| blocks.get(location))
        .copied()
    else {
        return Ok(None);
    };
    emit_structured_terminal(&mut output, &last.terminator)?;
    output.push_str("}\n");
    Ok(Some(output))
}

fn emit_single_latch_loop_c(cir: &Cir) -> Result<Option<String>, String> {
    let blocks = cir
        .blocks
        .iter()
        .map(|block| (block.address, block))
        .collect::<BTreeMap<_, _>>();
    let branches = cir
        .blocks
        .iter()
        .filter(|block| matches!(block.terminator, CirTerminator::Branch { .. }))
        .collect::<Vec<_>>();
    let [latch] = branches.as_slice() else {
        return Ok(None);
    };
    let CirTerminator::Branch {
        condition,
        taken,
        fallthrough,
    } = &latch.terminator
    else {
        unreachable!("latch selected above")
    };
    let (header, exit, repeat_when_true) = if taken.value.0 <= latch.address.value.0
        && taken.address_space == latch.address.address_space
    {
        (*taken, *fallthrough, true)
    } else if fallthrough.value.0 <= latch.address.value.0
        && fallthrough.address_space == latch.address.address_space
    {
        (*fallthrough, *taken, false)
    } else {
        return Ok(None);
    };
    if !blocks.contains_key(&header) || !blocks.contains_key(&exit) {
        return Ok(None);
    }
    let Some(mut prefix) = linear_path_until(cir.entry, header, &blocks) else {
        return Ok(None);
    };
    prefix.pop();
    let Some(loop_body) = linear_path_until(header, latch.address, &blocks) else {
        return Ok(None);
    };
    let Some(suffix) = linear_structured_path(exit, &blocks) else {
        return Ok(None);
    };
    let covered = prefix
        .iter()
        .chain(&loop_body)
        .chain(&suffix)
        .copied()
        .collect::<BTreeSet<_>>();
    if covered.len() != cir.blocks.len() {
        return Ok(None);
    }
    let mut output = native_prelude(&cir.name);
    for location in &prefix {
        emit_structured_statements(
            &mut output,
            blocks.get(location).copied().expect("prefix block exists"),
            "",
        )?;
    }
    output.push_str("  do {\n");
    for location in &loop_body {
        emit_structured_statements(
            &mut output,
            blocks
                .get(location)
                .copied()
                .expect("loop body block exists"),
            "  ",
        )?;
    }
    let condition = c_condition(condition)?;
    if repeat_when_true {
        output.push_str(&format!("  }} while ({condition});\n"));
    } else {
        output.push_str(&format!("  }} while (!({condition}));\n"));
    }
    for location in &suffix {
        emit_structured_statements(
            &mut output,
            blocks.get(location).copied().expect("suffix block exists"),
            "",
        )?;
    }
    let Some(last) = suffix
        .last()
        .and_then(|location| blocks.get(location))
        .copied()
    else {
        return Ok(None);
    };
    emit_structured_terminal(&mut output, &last.terminator)?;
    output.push_str("}\n");
    Ok(Some(output))
}

fn emit_guarded_switch_c(cir: &Cir) -> Result<Option<String>, String> {
    let blocks = cir
        .blocks
        .iter()
        .map(|block| (block.address, block))
        .collect::<BTreeMap<_, _>>();
    let branches = cir
        .blocks
        .iter()
        .filter(|block| matches!(block.terminator, CirTerminator::Branch { .. }))
        .collect::<Vec<_>>();
    let switches = cir
        .blocks
        .iter()
        .filter(|block| matches!(block.terminator, CirTerminator::Switch { .. }))
        .collect::<Vec<_>>();
    let ([branch], [switch_block]) = (branches.as_slice(), switches.as_slice()) else {
        return Ok(None);
    };
    let CirTerminator::Branch {
        condition,
        taken,
        fallthrough,
    } = &branch.terminator
    else {
        unreachable!("branch selected above")
    };
    let CirTerminator::Switch {
        dispatch,
        targets,
        unresolved_default,
    } = &switch_block.terminator
    else {
        unreachable!("switch selected above")
    };
    let (terminal_start, switch_when_true) = if *taken == switch_block.address {
        (*fallthrough, true)
    } else if *fallthrough == switch_block.address {
        (*taken, false)
    } else {
        return Ok(None);
    };
    let Some(mut prefix) = linear_path_until(cir.entry, branch.address, &blocks) else {
        return Ok(None);
    };
    let Some(terminal_path) = linear_structured_path(terminal_start, &blocks) else {
        return Ok(None);
    };
    let mut case_paths = Vec::with_capacity(targets.len());
    for target in targets {
        let Some(path) = linear_structured_path(*target, &blocks) else {
            return Ok(None);
        };
        case_paths.push((*target, path));
    }
    let listed = prefix.len()
        + 1
        + terminal_path.len()
        + case_paths.iter().map(|(_, path)| path.len()).sum::<usize>();
    let covered = prefix
        .iter()
        .chain(std::iter::once(&switch_block.address))
        .chain(&terminal_path)
        .chain(case_paths.iter().flat_map(|(_, path)| path))
        .copied()
        .collect::<BTreeSet<_>>();
    if listed != covered.len() || covered.len() != cir.blocks.len() {
        return Ok(None);
    }

    let mut output = native_prelude(&cir.name);
    for location in prefix.drain(..) {
        emit_structured_statements(
            &mut output,
            blocks.get(&location).copied().expect("prefix block exists"),
            "",
        )?;
    }
    let condition = c_condition(condition)?;
    output.push_str(&format!("  if ({condition}) {{\n"));
    if switch_when_true {
        emit_structured_switch_region(
            &mut output,
            switch_block,
            *dispatch,
            *unresolved_default,
            &case_paths,
            &blocks,
            "  ",
        )?;
    } else {
        emit_structured_terminal_path(&mut output, &terminal_path, &blocks, "  ")?;
    }
    output.push_str("  } else {\n");
    if switch_when_true {
        emit_structured_terminal_path(&mut output, &terminal_path, &blocks, "  ")?;
    } else {
        emit_structured_switch_region(
            &mut output,
            switch_block,
            *dispatch,
            *unresolved_default,
            &case_paths,
            &blocks,
            "  ",
        )?;
    }
    output.push_str("  }\n}\n");
    Ok(Some(output))
}

fn emit_acyclic_structured_c(cir: &Cir) -> Result<Option<String>, String> {
    let blocks = cir.blocks.iter().collect::<Vec<_>>();
    let by_location = blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.address, index))
        .collect::<BTreeMap<_, _>>();
    let Some(&entry) = by_location.get(&cir.entry) else {
        return Ok(None);
    };
    let exit = blocks.len();
    let mut successors = Vec::with_capacity(blocks.len());
    for block in &blocks {
        let locations = match &block.terminator {
            CirTerminator::Fallthrough { target } | CirTerminator::Goto { target } => {
                vec![*target]
            }
            CirTerminator::Branch {
                taken, fallthrough, ..
            } => vec![*taken, *fallthrough],
            CirTerminator::Return | CirTerminator::Exit { .. } => Vec::new(),
            _ => return Ok(None),
        };
        let mut indices = Vec::with_capacity(locations.len().max(1));
        for location in locations {
            let Some(index) = by_location.get(&location).copied() else {
                return Ok(None);
            };
            indices.push(index);
        }
        if indices.is_empty() {
            indices.push(exit);
        }
        successors.push(indices);
    }
    if !is_acyclic_cfg(&successors, exit) {
        return Ok(None);
    }
    let immediate_postdominators = immediate_postdominators(&successors, exit);
    let mut output = native_prelude(&cir.name);
    let mut seen = BTreeSet::new();
    let Some(terminated) = emit_acyclic_region(
        &mut output,
        entry,
        exit,
        &blocks,
        &by_location,
        &immediate_postdominators,
        &mut seen,
        "",
    )?
    else {
        return Ok(None);
    };
    if !terminated || seen.len() != blocks.len() {
        return Ok(None);
    }
    output.push_str("}\n");
    Ok(Some(output))
}

fn is_acyclic_cfg(successors: &[Vec<usize>], exit: usize) -> bool {
    let mut indegrees = vec![0usize; successors.len()];
    for targets in successors {
        for target in targets.iter().copied().filter(|target| *target != exit) {
            indegrees[target] = indegrees[target].saturating_add(1);
        }
    }
    let mut pending = indegrees
        .iter()
        .enumerate()
        .filter_map(|(index, degree)| (*degree == 0).then_some(index))
        .collect::<Vec<_>>();
    let mut visited = 0usize;
    while let Some(index) = pending.pop() {
        visited += 1;
        for target in successors[index]
            .iter()
            .copied()
            .filter(|target| *target != exit)
        {
            indegrees[target] -= 1;
            if indegrees[target] == 0 {
                pending.push(target);
            }
        }
    }
    visited == successors.len()
}

fn immediate_postdominators(successors: &[Vec<usize>], exit: usize) -> Vec<usize> {
    let universe = (0..=exit).collect::<BTreeSet<_>>();
    let mut postdominators = vec![universe.clone(); exit + 1];
    postdominators[exit] = BTreeSet::from([exit]);
    loop {
        let mut changed = false;
        for index in (0..exit).rev() {
            let mut targets = successors[index].iter();
            let Some(first) = targets.next() else {
                continue;
            };
            let mut intersection = postdominators[*first].clone();
            for target in targets {
                intersection = intersection
                    .intersection(&postdominators[*target])
                    .copied()
                    .collect();
            }
            intersection.insert(index);
            if intersection != postdominators[index] {
                postdominators[index] = intersection;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    (0..exit)
        .map(|index| {
            postdominators[index]
                .iter()
                .copied()
                .filter(|candidate| *candidate != index)
                .max_by_key(|candidate| postdominators[*candidate].len())
                .unwrap_or(exit)
        })
        .chain(std::iter::once(exit))
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn emit_acyclic_region(
    output: &mut String,
    start: usize,
    stop: usize,
    blocks: &[&hydir_ir::CirBlock],
    by_location: &BTreeMap<hydir_core::Location, usize>,
    immediate_postdominators: &[usize],
    seen: &mut BTreeSet<usize>,
    extra_indent: &str,
) -> Result<Option<bool>, String> {
    let exit = blocks.len();
    let mut cursor = start;
    loop {
        if cursor == stop {
            return Ok(Some(false));
        }
        if cursor == exit || !seen.insert(cursor) {
            return Ok(None);
        }
        let block = blocks[cursor];
        emit_structured_statements(output, block, extra_indent)?;
        match &block.terminator {
            CirTerminator::Fallthrough { target } | CirTerminator::Goto { target } => {
                let Some(next) = by_location.get(target).copied() else {
                    return Ok(None);
                };
                cursor = next;
            }
            CirTerminator::Branch {
                condition,
                taken,
                fallthrough,
            } => {
                let Some(taken) = by_location.get(taken).copied() else {
                    return Ok(None);
                };
                let Some(fallthrough) = by_location.get(fallthrough).copied() else {
                    return Ok(None);
                };
                let join = immediate_postdominators[cursor];
                output.push_str(&format!(
                    "{extra_indent}  if ({}) {{\n",
                    c_condition(condition)?
                ));
                let nested_indent = format!("{extra_indent}  ");
                let Some(taken_terminated) = emit_acyclic_region(
                    output,
                    taken,
                    join,
                    blocks,
                    by_location,
                    immediate_postdominators,
                    seen,
                    &nested_indent,
                )?
                else {
                    return Ok(None);
                };
                output.push_str(&format!("{extra_indent}  }} else {{\n"));
                let Some(fallthrough_terminated) = emit_acyclic_region(
                    output,
                    fallthrough,
                    join,
                    blocks,
                    by_location,
                    immediate_postdominators,
                    seen,
                    &nested_indent,
                )?
                else {
                    return Ok(None);
                };
                output.push_str(&format!("{extra_indent}  }}\n"));
                if join == exit {
                    return Ok((taken_terminated && fallthrough_terminated).then_some(true));
                }
                if taken_terminated || fallthrough_terminated {
                    return Ok(None);
                }
                cursor = join;
            }
            CirTerminator::Return | CirTerminator::Exit { .. } => {
                let mut terminal = String::new();
                emit_structured_terminal(&mut terminal, &block.terminator)?;
                for line in terminal.lines() {
                    output.push_str(extra_indent);
                    output.push_str(line);
                    output.push('\n');
                }
                return Ok(Some(true));
            }
            _ => return Ok(None),
        }
    }
}

fn emit_structured_switch_region(
    output: &mut String,
    switch_block: &hydir_ir::CirBlock,
    dispatch: hydir_core::Location,
    unresolved_default: bool,
    case_paths: &[(hydir_core::Location, Vec<hydir_core::Location>)],
    blocks: &BTreeMap<hydir_core::Location, &hydir_ir::CirBlock>,
    extra_indent: &str,
) -> Result<(), String> {
    emit_structured_statements(output, switch_block, extra_indent)?;
    output.push_str(&format!(
        "{extra_indent}  switch (hydir_indirect_target(state, UINT64_C(0x{:x}))) {{\n",
        dispatch.value.0
    ));
    for (target, path) in case_paths {
        output.push_str(&format!(
            "{extra_indent}    case UINT64_C(0x{:x}):\n",
            target.value.0
        ));
        emit_structured_terminal_path(output, path, blocks, &format!("{extra_indent}    "))?;
    }
    if unresolved_default {
        output.push_str(&format!(
            "{extra_indent}    default:\n{extra_indent}      hydir_unknown_control(state, UINT64_C(0));\n{extra_indent}      return;\n"
        ));
    }
    output.push_str(&format!("{extra_indent}  }}\n"));
    Ok(())
}

fn emit_structured_terminal_path(
    output: &mut String,
    path: &[hydir_core::Location],
    blocks: &BTreeMap<hydir_core::Location, &hydir_ir::CirBlock>,
    extra_indent: &str,
) -> Result<(), String> {
    for location in path {
        emit_structured_statements(
            output,
            blocks.get(location).copied().expect("path block exists"),
            extra_indent,
        )?;
    }
    let last = path
        .last()
        .and_then(|location| blocks.get(location))
        .copied()
        .ok_or_else(|| "structured terminal path is empty".to_owned())?;
    let mut terminal = String::new();
    emit_structured_terminal(&mut terminal, &last.terminator)?;
    for line in terminal.lines() {
        output.push_str(extra_indent);
        output.push_str(line);
        output.push('\n');
    }
    Ok(())
}

fn linear_path_until(
    start: hydir_core::Location,
    stop: hydir_core::Location,
    blocks: &BTreeMap<hydir_core::Location, &hydir_ir::CirBlock>,
) -> Option<Vec<hydir_core::Location>> {
    let mut path = Vec::new();
    let mut seen = BTreeSet::new();
    let mut cursor = start;
    loop {
        if !seen.insert(cursor) {
            return None;
        }
        let block = blocks.get(&cursor).copied()?;
        if cursor == stop {
            path.push(cursor);
            return Some(path);
        }
        path.push(cursor);
        cursor = match block.terminator {
            CirTerminator::Fallthrough { target } | CirTerminator::Goto { target }
                if blocks.contains_key(&target) =>
            {
                target
            }
            _ => return None,
        };
    }
}

fn emit_structured_terminal(output: &mut String, terminator: &CirTerminator) -> Result<(), String> {
    match terminator {
        CirTerminator::Return => {
            output.push_str("  state->rsp += UINT64_C(8);\n  return;\n");
            Ok(())
        }
        CirTerminator::Exit { target } => {
            let target = target.map_or(0, |location| location.value.0);
            output.push_str(&format!(
                "  hydir_external_exit(state, UINT64_C(0x{target:x}));\n  return;\n"
            ));
            Ok(())
        }
        _ => Err("structured suffix does not end in return or exit".to_owned()),
    }
}

fn emit_single_diamond_c(cir: &Cir) -> Result<Option<String>, String> {
    let blocks = cir
        .blocks
        .iter()
        .map(|block| (block.address, block))
        .collect::<BTreeMap<_, _>>();
    let branches = cir
        .blocks
        .iter()
        .filter(|block| matches!(block.terminator, CirTerminator::Branch { .. }))
        .collect::<Vec<_>>();
    let [branch] = branches.as_slice() else {
        return Ok(None);
    };
    let mut prefix = Vec::new();
    let mut cursor = cir.entry;
    let mut seen = BTreeSet::new();
    loop {
        if !seen.insert(cursor) {
            return Ok(None);
        }
        let Some(block) = blocks.get(&cursor).copied() else {
            return Ok(None);
        };
        prefix.push(cursor);
        if block.address == branch.address {
            break;
        }
        cursor = match block.terminator {
            CirTerminator::Fallthrough { target } | CirTerminator::Goto { target }
                if blocks.contains_key(&target) =>
            {
                target
            }
            _ => return Ok(None),
        };
    }
    let CirTerminator::Branch {
        condition,
        taken,
        fallthrough,
    } = &branch.terminator
    else {
        unreachable!("branch selected above")
    };
    let Some(taken_path) = linear_structured_path(*taken, &blocks) else {
        return Ok(None);
    };
    let Some(fallthrough_path) = linear_structured_path(*fallthrough, &blocks) else {
        return Ok(None);
    };
    let fallthrough_set = fallthrough_path.iter().copied().collect::<BTreeSet<_>>();
    let Some(join) = taken_path
        .iter()
        .copied()
        .find(|location| fallthrough_set.contains(location))
    else {
        return Ok(None);
    };
    let taken_arm = taken_path
        .iter()
        .copied()
        .take_while(|location| *location != join)
        .collect::<Vec<_>>();
    let fallthrough_arm = fallthrough_path
        .iter()
        .copied()
        .take_while(|location| *location != join)
        .collect::<Vec<_>>();
    let Some(suffix) = linear_structured_path(join, &blocks) else {
        return Ok(None);
    };
    let covered = prefix
        .iter()
        .chain(&taken_arm)
        .chain(&fallthrough_arm)
        .chain(&suffix)
        .copied()
        .collect::<BTreeSet<_>>();
    if covered.len() != cir.blocks.len() {
        return Ok(None);
    }

    let mut output = native_prelude(&cir.name);
    for location in &prefix {
        emit_structured_statements(
            &mut output,
            blocks.get(location).copied().expect("prefix block exists"),
            "",
        )?;
    }
    output.push_str(&format!("  if ({}) {{\n", c_condition(condition)?));
    for location in &taken_arm {
        emit_structured_statements(
            &mut output,
            blocks.get(location).copied().expect("taken block exists"),
            "  ",
        )?;
    }
    output.push_str("  } else {\n");
    for location in &fallthrough_arm {
        emit_structured_statements(
            &mut output,
            blocks
                .get(location)
                .copied()
                .expect("fallthrough block exists"),
            "  ",
        )?;
    }
    output.push_str("  }\n");
    for location in &suffix {
        emit_structured_statements(
            &mut output,
            blocks.get(location).copied().expect("suffix block exists"),
            "",
        )?;
    }
    let Some(last) = suffix
        .last()
        .and_then(|location| blocks.get(location))
        .copied()
    else {
        return Ok(None);
    };
    match last.terminator {
        CirTerminator::Return => output.push_str("  state->rsp += UINT64_C(8);\n  return;\n"),
        CirTerminator::Exit { target } => {
            let target = target.map_or(0, |location| location.value.0);
            output.push_str(&format!(
                "  hydir_external_exit(state, UINT64_C(0x{target:x}));\n"
            ));
        }
        _ => return Ok(None),
    }
    output.push_str("}\n");
    Ok(Some(output))
}

fn linear_structured_path(
    start: hydir_core::Location,
    blocks: &BTreeMap<hydir_core::Location, &hydir_ir::CirBlock>,
) -> Option<Vec<hydir_core::Location>> {
    let mut path = Vec::new();
    let mut seen = BTreeSet::new();
    let mut cursor = start;
    loop {
        if !seen.insert(cursor) {
            return None;
        }
        let block = blocks.get(&cursor).copied()?;
        path.push(cursor);
        match block.terminator {
            CirTerminator::Fallthrough { target } | CirTerminator::Goto { target }
                if blocks.contains_key(&target) =>
            {
                cursor = target
            }
            CirTerminator::Return | CirTerminator::Exit { .. } => return Some(path),
            _ => return None,
        }
    }
}

fn emit_structured_statements(
    output: &mut String,
    block: &hydir_ir::CirBlock,
    extra_indent: &str,
) -> Result<(), String> {
    for statement in &block.statements {
        let mut fragment = String::new();
        emit_native_statement(&mut fragment, statement)?;
        for line in fragment.lines() {
            output.push_str(extra_indent);
            output.push_str(line);
            output.push('\n');
        }
    }
    Ok(())
}

fn native_prelude(name: &str) -> String {
    let template = r#"#include <stdint.h>
#include <string.h>

typedef struct HydirMachineState {
  uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp;
  uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
  uint8_t zf, sf, of, cf, pf, af, df;
  uint64_t rflags_unmodeled;
  uint32_t mxcsr, mxcsr_mask;
  uint64_t k[8];
  uint8_t ymm[32][32];
  uint8_t zmm_hi256[32][32];
  uint8_t x87_st[8][10];
  uint16_t x87_control, x87_status, x87_tag;
  uint64_t x87_instruction_pointer, x87_data_pointer;
  uint16_t x87_opcode;
} HydirMachineState;

extern void hydir_opaque_effect(HydirMachineState *, uint64_t, const char *);
extern void hydir_external_exit(HydirMachineState *, uint64_t);
extern void hydir_unknown_control(HydirMachineState *, uint64_t);
extern void hydir_call(HydirMachineState *, uint64_t);
extern void hydir_unknown_call(HydirMachineState *, uint64_t);
extern uint8_t hydir_undefined_flag(HydirMachineState *, uint64_t, const char *);
extern uint64_t hydir_undefined_value(HydirMachineState *, uint64_t, const char *, unsigned);
extern uint64_t hydir_indirect_target(HydirMachineState *, uint64_t);
extern uint64_t hydir_segment_address(HydirMachineState *, const char *, uint64_t);
_Noreturn void hydir_divide_error(HydirMachineState *, uint64_t);
_Noreturn void hydir_invalid_opcode(HydirMachineState *, uint64_t);
_Noreturn void hydir_breakpoint(HydirMachineState *, uint64_t);
_Noreturn void hydir_software_interrupt(HydirMachineState *, uint64_t, uint8_t);
extern void hydir_pushfq(HydirMachineState *, uint64_t);
extern void hydir_popfq(HydirMachineState *, uint64_t);
/* These helpers implement x86 SSE scalar arithmetic from raw IEEE bits under
   state->mxcsr, update its sticky exception flags, and do not return when an
   enabled SIMD floating-point exception is delivered. */
extern uint32_t hydir_fp_binary32(HydirMachineState *, uint64_t, const char *, uint32_t, uint32_t);
extern uint64_t hydir_fp_binary64(HydirMachineState *, uint64_t, const char *, uint64_t, uint64_t);
extern uint32_t hydir_fp_unary32(HydirMachineState *, uint64_t, const char *, uint32_t);
extern uint64_t hydir_fp_unary64(HydirMachineState *, uint64_t, const char *, uint64_t);
extern uint64_t hydir_fp_convert32_to64(HydirMachineState *, uint64_t, uint32_t);
extern uint32_t hydir_fp_convert64_to32(HydirMachineState *, uint64_t, uint64_t);
extern uint32_t hydir_i64_to_fp32(HydirMachineState *, uint64_t, uint64_t, unsigned);
extern uint64_t hydir_i64_to_fp64(HydirMachineState *, uint64_t, uint64_t, unsigned);
extern uint64_t hydir_fp32_to_i64(HydirMachineState *, uint64_t, uint32_t, unsigned, uint8_t);
extern uint64_t hydir_fp64_to_i64(HydirMachineState *, uint64_t, uint64_t, unsigned, uint8_t);
extern void hydir_fp_compare32(HydirMachineState *, uint64_t, const char *, uint32_t, uint32_t);
extern void hydir_fp_compare64(HydirMachineState *, uint64_t, const char *, uint64_t, uint64_t);
/* The x87 helper implements the named instruction's normal path over the
   eight raw 80-bit physical registers plus TOP/tag/status/control and
   instruction/data-pointer/opcode state. It performs stack rotation, memory
   conversion, environment-image save/restore, rounding, condition-code and
   integer-flag updates, and does not return when an enabled x87 exception is
   delivered. UINT32_MAX denotes an implicit or absent logical ST operand. */
extern void hydir_x87_operation(HydirMachineState *, uint64_t, const char *, uint64_t, unsigned, unsigned, unsigned);
/* FXSAVE/FXRSTOR and MXCSR transfers implement the complete 512-byte legacy
   state image represented above. The helper does not return when alignment,
   reserved-bit, or memory exception delivery wins over the normal path. */
extern void hydir_extended_state_operation(HydirMachineState *, uint64_t, const char *, uint64_t);
/* Environment operations provide CPUID/time/XCR/random values without running
   them during analysis. They update only their architectural destinations and
   flags, and do not return on a privilege or unsupported-feature exception. */
extern void hydir_environment_operation(HydirMachineState *, uint64_t, const char *, const char *, unsigned);
/* Aligned vector moves check 16/32/64-byte alignment and do not return when an
   alignment or memory exception wins over the byte-exact normal path. */
extern void hydir_aligned_vector_move(HydirMachineState *, uint64_t, const char *, uint64_t, uint8_t *, unsigned, uint8_t);
/* Masked vector memory moves access only active elements; masked-off elements
   cannot fault. Loads merge into or zero the supplied destination image and
   stores leave masked-off memory unchanged. */
extern void hydir_masked_vector_move(HydirMachineState *, uint64_t, const char *, uint64_t, uint8_t *, unsigned, unsigned, uint64_t, uint8_t, uint8_t);
/* Atomic helpers perform one indivisible x86 read-modify-write operation with
   LOCK-equivalent ordering. RMW and CMPXCHG update architectural flags in
   state; all helpers return the original memory value, masked to width. For
   BTS/BTR/BTC, the RMW value is the architectural bit offset and the helper
   applies the x86 memory bit-string address adjustment. */
extern uint64_t hydir_atomic_rmw(HydirMachineState *, uint64_t, const char *, uint64_t, unsigned);
extern uint64_t hydir_atomic_cmpxchg(HydirMachineState *, uint64_t, uint64_t, uint64_t, unsigned);
extern uint64_t hydir_atomic_exchange(HydirMachineState *, uint64_t, uint64_t, unsigned);
extern void hydir_atomic_cmpxchg_wide(HydirMachineState *, uint64_t, unsigned, uint8_t);
extern void hydir_memory_fence(HydirMachineState *, const char *);
/* Performs a byte-exact non-temporal store with x86 weak-ordering semantics. */
extern void hydir_non_temporal_vector_store(HydirMachineState *, uint64_t, const uint8_t *, unsigned);

static inline uint8_t hydir_load8(uint64_t address) { uint8_t value; memcpy(&value, (const void *)(uintptr_t)address, sizeof(value)); return value; }
static inline uint16_t hydir_load16(uint64_t address) { uint16_t value; memcpy(&value, (const void *)(uintptr_t)address, sizeof(value)); return value; }
static inline uint32_t hydir_load32(uint64_t address) { uint32_t value; memcpy(&value, (const void *)(uintptr_t)address, sizeof(value)); return value; }
static inline uint64_t hydir_load64(uint64_t address) { uint64_t value; memcpy(&value, (const void *)(uintptr_t)address, sizeof(value)); return value; }
static inline void hydir_store8(uint64_t address, uint8_t value) { memcpy((void *)(uintptr_t)address, &value, sizeof(value)); }
static inline void hydir_store16(uint64_t address, uint16_t value) { memcpy((void *)(uintptr_t)address, &value, sizeof(value)); }
static inline void hydir_store32(uint64_t address, uint32_t value) { memcpy((void *)(uintptr_t)address, &value, sizeof(value)); }
static inline void hydir_store64(uint64_t address, uint64_t value) { memcpy((void *)(uintptr_t)address, &value, sizeof(value)); }
static inline uint64_t hydir_sign_extend(uint64_t value, unsigned width) { uint64_t sign = UINT64_C(1) << (width - 1U); uint64_t mask = UINT64_MAX >> (64U - width); value &= mask; return (value ^ sign) - sign; }
static inline uint8_t hydir_imul_overflow(uint64_t lhs, uint64_t rhs, unsigned width) { uint64_t mask = width == 64U ? UINT64_MAX : ((UINT64_C(1) << width) - UINT64_C(1)); uint64_t sign = UINT64_C(1) << (width - 1U); lhs &= mask; rhs &= mask; uint64_t lhs_magnitude = (lhs & sign) != 0U ? ((~lhs + UINT64_C(1)) & mask) : lhs; uint64_t rhs_magnitude = (rhs & sign) != 0U ? ((~rhs + UINT64_C(1)) & mask) : rhs; uint64_t limit = ((lhs ^ rhs) & sign) != 0U ? sign : (sign - UINT64_C(1)); return (uint8_t)(rhs_magnitude != 0U && lhs_magnitude > limit / rhs_magnitude); }
static inline void hydir_umul64wide(uint64_t lhs, uint64_t rhs, uint64_t *high, uint64_t *low) { uint64_t lhs_low = (uint32_t)lhs, lhs_high = lhs >> 32U, rhs_low = (uint32_t)rhs, rhs_high = rhs >> 32U; uint64_t product_low = lhs_low * rhs_low, product_left = lhs_low * rhs_high, product_right = lhs_high * rhs_low, product_high = lhs_high * rhs_high; uint64_t middle = (product_low >> 32U) + (uint32_t)product_left + (uint32_t)product_right; *low = (middle << 32U) | (uint32_t)product_low; *high = product_high + (product_left >> 32U) + (product_right >> 32U) + (middle >> 32U); }
static inline uint8_t hydir_udiv128by64(uint64_t high, uint64_t low, uint64_t divisor, uint64_t *quotient, uint64_t *remainder) { if (divisor == 0U || high >= divisor) return 0U; uint64_t q = 0U, r = high; for (unsigned bit = 64U; bit-- > 0U;) { uint64_t carry = r >> 63U; r = (r << 1U) | ((low >> bit) & UINT64_C(1)); if (carry != 0U || r >= divisor) { r -= divisor; q |= UINT64_C(1) << bit; } } *quotient = q; *remainder = r; return 1U; }
static inline uint64_t hydir_popcount64(uint64_t value) { uint64_t count = 0U; while (value != 0U) { count += value & UINT64_C(1); value >>= 1U; } return count; }
static inline uint64_t hydir_lzcnt64(uint64_t value, unsigned width) { if (value == 0U) return width; uint64_t count = 0U; for (unsigned bit = width; bit-- > 0U;) { if (((value >> bit) & UINT64_C(1)) != 0U) break; ++count; } return count; }
static inline uint64_t hydir_tzcnt64(uint64_t value, unsigned width) { if (value == 0U) return width; uint64_t count = 0U; while ((value & UINT64_C(1)) == 0U) { ++count; value >>= 1U; } return count; }
static inline uint8_t hydir_aes_mul(uint8_t left, uint8_t right) { uint8_t product = 0U; for (unsigned bit = 0U; bit < 8U; ++bit) { if ((right & 1U) != 0U) product ^= left; uint8_t high = (uint8_t)(left >> 7U); left = (uint8_t)(left << 1U); if (high != 0U) left ^= UINT8_C(0x1b); right = (uint8_t)(right >> 1U); } return product; }
static inline uint8_t hydir_aes_sbox(uint8_t value) { uint8_t inverse = 0U; if (value != 0U) { inverse = 1U; uint8_t base = value; unsigned exponent = 254U; while (exponent != 0U) { if ((exponent & 1U) != 0U) inverse = hydir_aes_mul(inverse, base); base = hydir_aes_mul(base, base); exponent >>= 1U; } } uint8_t rotated1 = (uint8_t)((inverse << 1U) | (inverse >> 7U)); uint8_t rotated2 = (uint8_t)((inverse << 2U) | (inverse >> 6U)); uint8_t rotated3 = (uint8_t)((inverse << 3U) | (inverse >> 5U)); uint8_t rotated4 = (uint8_t)((inverse << 4U) | (inverse >> 4U)); return (uint8_t)(inverse ^ rotated1 ^ rotated2 ^ rotated3 ^ rotated4 ^ UINT8_C(0x63)); }
static inline void hydir_aesenc_round(uint8_t state[16], const uint8_t round_key[16]) { uint8_t shifted[16], mixed[16]; for (unsigned column = 0U; column < 4U; ++column) for (unsigned row = 0U; row < 4U; ++row) shifted[4U * column + row] = hydir_aes_sbox(state[4U * ((column + row) & 3U) + row]); for (unsigned column = 0U; column < 4U; ++column) { const uint8_t *source = shifted + 4U * column; uint8_t *target = mixed + 4U * column; target[0] = (uint8_t)(hydir_aes_mul(source[0], 2U) ^ hydir_aes_mul(source[1], 3U) ^ source[2] ^ source[3]); target[1] = (uint8_t)(source[0] ^ hydir_aes_mul(source[1], 2U) ^ hydir_aes_mul(source[2], 3U) ^ source[3]); target[2] = (uint8_t)(source[0] ^ source[1] ^ hydir_aes_mul(source[2], 2U) ^ hydir_aes_mul(source[3], 3U)); target[3] = (uint8_t)(hydir_aes_mul(source[0], 3U) ^ source[1] ^ source[2] ^ hydir_aes_mul(source[3], 2U)); } for (unsigned index = 0U; index < 16U; ++index) state[index] = (uint8_t)(mixed[index] ^ round_key[index]); }
static inline uint8_t hydir_parity8(uint64_t value) { uint8_t bits = (uint8_t)value, parity = 1U; for (unsigned bit = 0U; bit < 8U; ++bit) { parity ^= (uint8_t)((bits >> bit) & 1U); } return parity; }

void hydir___HYDIR_FUNCTION__(HydirMachineState *state) {
  (void)&hydir_load8; (void)&hydir_load16; (void)&hydir_load32; (void)&hydir_load64;
  (void)&hydir_store8; (void)&hydir_store16; (void)&hydir_store32; (void)&hydir_store64;
  (void)&hydir_sign_extend;
  (void)&hydir_imul_overflow;
  (void)&hydir_umul64wide;
  (void)&hydir_udiv128by64;
  (void)&hydir_popcount64; (void)&hydir_lzcnt64; (void)&hydir_tzcnt64;
  (void)&hydir_aesenc_round;
  (void)&hydir_parity8;
  if (state == 0) return;
"#;
    template.replace("__HYDIR_FUNCTION__", &c_identifier(name))
}

fn c_identifier(name: &str) -> String {
    let mut identifier = String::with_capacity(name.len().max(1));
    for (index, character) in name.chars().enumerate() {
        if character.is_ascii_alphanumeric() || character == '_' {
            if index == 0 && character.is_ascii_digit() {
                identifier.push('_');
            }
            identifier.push(character);
        } else {
            identifier.push('_');
        }
    }
    if identifier.is_empty() {
        "function".to_owned()
    } else {
        identifier
    }
}

fn c_label(location: hydir_core::Location) -> String {
    format!("hydir_b_{}_{}", location.address_space, location.value.0)
}

fn emit_native_statement(output: &mut String, statement: &CirStatement) -> Result<(), String> {
    match statement {
        CirStatement::OpaqueEffect {
            address,
            bytes_hex,
            reason,
            ..
        } => {
            output.push_str(&format!(
                "  /* opaque 0x{:x}: {} */\n  hydir_opaque_effect(state, UINT64_C(0x{:x}), \"{}\");\n",
                address.value.0,
                c_comment(reason),
                address.value.0,
                c_string(bytes_hex)
            ));
            Ok(())
        }
        CirStatement::Operation {
            address,
            family,
            operands,
            decorators,
            effects,
        } => {
            output.push_str(&format!("  /* 0x{:x}: {} */\n", address.value.0, family));
            emit_exact_operation(output, address.value.0, family, operands, decorators)?;
            for flag in &effects.undefined_flags {
                if !matches!(flag.as_str(), "zf" | "sf" | "of" | "cf" | "pf" | "af") {
                    return Err(format!(
                        "native C backend cannot represent undefined flag {flag}"
                    ));
                }
                output.push_str(&format!(
                    "  state->{flag} = hydir_undefined_flag(state, UINT64_C(0x{:x}), \"{flag}\");\n",
                    address.value.0
                ));
            }
            Ok(())
        }
    }
}

fn emit_exact_operation(
    output: &mut String,
    address: u64,
    family: &str,
    operands: &[MachineOperand],
    decorators: &InstructionDecorators,
) -> Result<(), String> {
    if decorators.rounding.is_some() || decorators.suppress_all_exceptions {
        return Err(format!(
            "native C backend lacks embedded rounding/SAE lowering for {family} at 0x{address:x}"
        ));
    }
    match family {
        "nop" | "pause" | "endbr64" => Ok(()),
        "ud2" => {
            output.push_str(&format!(
                "  hydir_invalid_opcode(state, UINT64_C(0x{address:x}));\n"
            ));
            Ok(())
        }
        "int3" => {
            output.push_str(&format!(
                "  hydir_breakpoint(state, UINT64_C(0x{address:x}));\n"
            ));
            Ok(())
        }
        "int" if operands.len() == 1 => {
            let vector = read_operand(&operands[0])?;
            output.push_str(&format!(
                "  hydir_software_interrupt(state, UINT64_C(0x{address:x}), (uint8_t)({vector}));\n"
            ));
            Ok(())
        }
        "wait" => emit_x87_operation(output, address, family, operands),
        "lfence" | "sfence" | "mfence" => {
            output.push_str(&format!("  hydir_memory_fence(state, \"{family}\");\n"));
            Ok(())
        }
        "pushfq" if operands.is_empty() => {
            output.push_str(&format!(
                "  hydir_pushfq(state, UINT64_C(0x{address:x}));\n"
            ));
            Ok(())
        }
        "popfq" if operands.is_empty() => {
            output.push_str(&format!(
                "  hydir_popfq(state, UINT64_C(0x{address:x}));\n"
            ));
            Ok(())
        }
        "cld" => {
            output.push_str("  state->df = 0U;\n");
            Ok(())
        }
        "std" => {
            output.push_str("  state->df = 1U;\n");
            Ok(())
        }
        "movsb" | "movsw" | "movsq" | "stosb" | "stosw" | "stosd" | "stosq" | "cmpsb"
        | "cmpsw" | "cmpsd" | "cmpsq" | "scasb" | "scasw" | "scasd" | "scasq" | "rep_movsb"
        | "rep_movsw" | "rep_movsd" | "rep_movsq" | "rep_stosb" | "rep_stosw" | "rep_stosd"
        | "rep_stosq" | "repe_cmpsb" | "repe_cmpsw" | "repe_cmpsd" | "repe_cmpsq"
        | "repe_scasb" | "repe_scasw" | "repe_scasd" | "repe_scasq" | "repne_cmpsb"
        | "repne_cmpsw" | "repne_cmpsd" | "repne_cmpsq" | "repne_scasb" | "repne_scasw"
        | "repne_scasd" | "repne_scasq" => emit_string_operation(output, address, family),
        "movsd"
            if !operands.iter().any(
                |operand| matches!(operand, MachineOperand::Register { name, width_bits: 128 } if name.starts_with("xmm")),
            ) =>
        {
            emit_string_operation(output, address, family)
        }
        "vzeroupper" if operands.is_empty() => {
            output.push_str(
                "  for (unsigned hydir_vec_i = 0; hydir_vec_i < 16U; ++hydir_vec_i) {\n    memset(state->ymm[hydir_vec_i] + 16U, 0, 16U);\n  }\n",
            );
            Ok(())
        }
        "vzeroall" if operands.is_empty() => {
            output.push_str("  memset(state->ymm, 0, 16U * 32U);\n");
            Ok(())
        }
        "movd" | "vmovd" if operands.len() == 2 => {
            emit_vector_scalar_move(output, address, family, &operands[0], &operands[1], 32)
        }
        "movq" | "vmovq" if operands.len() == 2 => {
            emit_vector_scalar_move(output, address, family, &operands[0], &operands[1], 64)
        }
        "movss" | "movsd" if operands.len() == 2 => {
            emit_scalar_float_move(output, address, family, operands, family == "movss")
        }
        "vmovss" | "vmovsd" if matches!(operands.len(), 2 | 3) => {
            emit_scalar_float_move(output, address, family, operands, family == "vmovss")
        }
        "addss" | "subss" | "mulss" | "divss" | "minss" | "maxss" | "addsd" | "subsd"
        | "mulsd" | "divsd" | "minsd" | "maxsd" | "vaddss" | "vsubss" | "vmulss"
        | "vdivss" | "vminss" | "vmaxss" | "vaddsd" | "vsubsd" | "vmulsd" | "vdivsd"
        | "vminsd" | "vmaxsd" if matches!(operands.len(), 2 | 3) => {
            emit_scalar_float_binary(output, address, family, operands)
        }
        "addps" | "subps" | "mulps" | "divps" | "addpd" | "subpd" | "mulpd" | "divpd"
        | "vaddps" | "vsubps" | "vmulps" | "vdivps" | "vaddpd" | "vsubpd" | "vmulpd"
        | "vdivpd" if matches!(operands.len(), 2 | 3) => {
            emit_packed_float_binary(output, address, family, operands, decorators)
        }
        "comiss" | "ucomiss" | "vcomiss" | "vucomiss" | "comisd" | "ucomisd" | "vcomisd"
        | "vucomisd" if operands.len() == 2 => {
            emit_scalar_float_compare(output, address, family, &operands[0], &operands[1])
        }
        "sqrtss" | "sqrtsd" | "vsqrtss" | "vsqrtsd" if matches!(operands.len(), 2 | 3) => {
            emit_scalar_float_sqrt(output, address, family, operands)
        }
        "sqrtps" | "sqrtpd" | "vsqrtps" | "vsqrtpd" if operands.len() == 2 => {
            emit_packed_float_sqrt(output, address, family, &operands[0], &operands[1])
        }
        "cvtss2sd" | "cvtsd2ss" | "vcvtss2sd" | "vcvtsd2ss"
            if matches!(operands.len(), 2 | 3) =>
        {
            emit_scalar_float_conversion(output, address, family, operands)
        }
        "cvtsi2ss" | "cvtsi2sd" | "vcvtsi2ss" | "vcvtsi2sd"
        | "cvtss2si" | "cvtsd2si" | "cvttss2si" | "cvttsd2si"
        | "vcvtss2si" | "vcvtsd2si" | "vcvttss2si" | "vcvttsd2si"
            if matches!(operands.len(), 2 | 3) =>
        {
            emit_scalar_integer_float_conversion(output, address, family, operands)
        }
        "cvtdq2ps" | "vcvtdq2ps" | "cvtps2dq" | "cvttps2dq" | "vcvtps2dq"
        | "vcvttps2dq" if operands.len() == 2 => {
            emit_packed_integer_float_conversion(
                output,
                address,
                family,
                &operands[0],
                &operands[1],
            )
        }
        "cvtps2pd" | "vcvtps2pd" | "cvtpd2ps" | "vcvtpd2ps" | "cvtdq2pd"
        | "vcvtdq2pd" | "cvtpd2dq" | "cvttpd2dq" | "vcvtpd2dq" | "vcvttpd2dq"
            if operands.len() == 2 =>
        {
            emit_packed_precision_conversion(
                output,
                address,
                family,
                &operands[0],
                &operands[1],
            )
        }
        "lock_xadd" | "lock_cmpxchg" | "atomic_xchg" | "lock_add" | "lock_sub"
        | "lock_adc" | "lock_sbb" | "lock_and" | "lock_or" | "lock_xor" | "lock_btc"
        | "lock_btr" | "lock_bts" if operands.len() == 2 => {
            emit_atomic_operation(output, address, family, &operands[0], &operands[1])
        }
        "lock_inc" | "lock_dec" | "lock_neg" | "lock_not" if operands.len() == 1 => {
            emit_atomic_unary(output, address, family, &operands[0])
        }
        "cmpxchg8b" | "cmpxchg16b" | "lock_cmpxchg8b" | "lock_cmpxchg16b"
            if operands.len() == 1 =>
        {
            emit_atomic_wide_compare_exchange(output, address, family, &operands[0])
        }
        "fxsave" | "fxsave64" | "fxrstor" | "fxrstor64" | "ldmxcsr" | "stmxcsr"
            if operands.len() == 1 =>
        {
            emit_extended_state_operation(output, address, family, &operands[0])
        }
        "cpuid" | "rdtsc" | "rdtscp" | "xgetbv" if operands.is_empty() => {
            emit_environment_operation(output, address, family, None)
        }
        "rdrand" | "rdseed" if operands.len() == 1 => {
            emit_environment_operation(output, address, family, Some(&operands[0]))
        }
        family if family.starts_with('f') => emit_x87_operation(output, address, family, operands),
        "mov" if operands.len() == 2 => {
            let value = read_operand(&operands[1])?;
            write_operand(output, &operands[0], &value)
        }
        "movzx" if operands.len() == 2 => {
            let value = read_operand(&operands[1])?;
            write_operand(output, &operands[0], &value)
        }
        "movsx" | "movsxd" if operands.len() == 2 => {
            let source_width = operand_width(&operands[1])?;
            let value = read_operand(&operands[1])?;
            write_operand(
                output,
                &operands[0],
                &format!("hydir_sign_extend((uint64_t)({value}), {source_width}U)"),
            )
        }
        family if family.starts_with("set") && operands.len() == 1 => {
            let condition = c_condition(family)?;
            write_operand(output, &operands[0], &format!("({condition})"))
        }
        family if family.starts_with("cmov") && operands.len() == 2 => {
            let condition = c_condition(family)?;
            let value = read_operand(&operands[1])?;
            output.push_str(&format!("  if ({condition}) {{\n"));
            let mut assignment = String::new();
            write_operand(&mut assignment, &operands[0], &value)?;
            for line in assignment.lines() {
                output.push_str("  ");
                output.push_str(line);
                output.push('\n');
            }
            output.push_str("  }\n");
            Ok(())
        }
        "lea" if operands.len() == 2 => {
            let value = memory_address(&operands[1])?;
            write_operand(output, &operands[0], &value)
        }
        "movups" | "movupd" | "movdqu" | "vmovups" | "vmovupd" | "vmovdqu"
        | "vmovdqu32" | "vmovdqu64" | "movaps" | "movapd" | "movdqa" | "vmovaps"
        | "vmovapd" | "vmovdqa" | "vmovdqa32" | "vmovdqa64"
            if operands.len() == 2 =>
        {
            emit_vector_move(
                output,
                address,
                family,
                &operands[0],
                &operands[1],
                decorators,
            )
        }
        "aesenc" if operands.len() == 2 => {
            emit_aesenc(output, address, &operands[0], &operands[1])
        }
        "kmovb" | "kmovw" | "kmovd" | "kmovq" if operands.len() == 2 => {
            emit_opmask_move(output, address, family, &operands[0], &operands[1])
        }
        "vpopcntb" if operands.len() == 2 => {
            emit_vector_byte_popcount(
                output,
                address,
                &operands[0],
                &operands[1],
                decorators,
            )
        }
        "vpermb" if operands.len() == 3 => emit_vector_byte_permute(
            output,
            address,
            &operands[0],
            &operands[1],
            &operands[2],
            decorators,
        ),
        "vpermi2b" if operands.len() == 3 => emit_vector_byte_permute2(
            output,
            address,
            &operands[0],
            &operands[1],
            &operands[2],
            decorators,
        ),
        "vgf2p8affineqb" if operands.len() == 4 => {
            emit_vector_gf2_affine(output, address, operands, decorators)
        }
        "vpcmpuq" if operands.len() == 4 => {
            emit_vector_unsigned_qword_compare(output, address, operands, decorators)
        }
        "vpcompressq" if operands.len() == 2 => emit_vector_qword_compress(
            output,
            address,
            &operands[0],
            &operands[1],
            decorators,
        ),
        "pinsrw" | "pinsrd" | "pinsrq" if operands.len() == 3 => {
            emit_vector_insert_scalar(output, address, family, operands)
        }
        "vmovntdq" if operands.len() == 2 => {
            emit_non_temporal_vector_store(output, address, &operands[0], &operands[1])
        }
        "pxor" | "xorps" | "xorpd" | "pand" | "pandn" | "por" | "andps" | "andpd" | "andnps"
        | "andnpd" | "orps" | "orpd" | "vpxor" | "vpxord" | "vxorps" | "vxorpd" | "vpand" | "vpandn"
        | "vpor" | "vpandq" | "vporq" | "vandps" | "vandpd" | "vandnps" | "vandnpd"
        | "vorps" | "vorpd"
            if matches!(operands.len(), 2 | 3) =>
        {
            emit_vector_bitwise(output, address, family, operands, decorators)
        }
        "paddb" | "paddw" | "paddd" | "paddq" | "psubb" | "psubw" | "psubd" | "psubq"
        | "paddsb" | "paddsw" | "paddusb" | "paddusw" | "psubsb" | "psubsw"
        | "psubusb" | "psubusw"
        | "pmullw" | "pmulld" | "pmuludq" | "pcmpeqb" | "pcmpeqw" | "pcmpeqd"
        | "pcmpeqq" | "pcmpgtb" | "pcmpgtw" | "pcmpgtd" | "pcmpgtq" | "vpaddb"
        | "vpaddw" | "vpaddd" | "vpaddq" | "vpsubb" | "vpsubw" | "vpsubd" | "vpsubq"
        | "vpaddsb" | "vpaddsw" | "vpaddusb" | "vpaddusw" | "vpsubsb" | "vpsubsw"
        | "vpsubusb" | "vpsubusw"
        | "vpmullw" | "vpmulld" | "vpmuludq" | "vpcmpeqb" | "vpcmpeqw" | "vpcmpeqd"
        | "vpcmpeqq" | "vpcmpgtb" | "vpcmpgtw" | "vpcmpgtd" | "vpcmpgtq" | "pminub"
        | "pminuw" | "pminud" | "pminsw" | "pminsd" | "pmaxub" | "pmaxuw" | "pmaxud"
        | "pmaxsw" | "pmaxsd" | "vpminub" | "vpminuw" | "vpminud" | "vpminsw"
        | "vpminsd" | "vpmaxub" | "vpmaxuw" | "vpmaxud" | "vpmaxsw" | "vpmaxsd"
            if matches!(operands.len(), 2 | 3) =>
        {
            emit_vector_lane_binary(output, address, family, operands)
        }
        "packsswb" | "packssdw" | "packuswb" | "packusdw" | "vpacksswb"
        | "vpackssdw" | "vpackuswb" | "vpackusdw" if matches!(operands.len(), 2 | 3) => {
            emit_vector_pack(output, address, family, operands)
        }
        "punpcklbw" | "punpcklwd" | "punpckldq" | "punpcklqdq" | "punpckhbw"
        | "punpckhwd" | "punpckhdq" | "punpckhqdq" | "vpunpcklbw" | "vpunpcklwd"
        | "vpunpckldq" | "vpunpcklqdq" | "vpunpckhbw" | "vpunpckhwd" | "vpunpckhdq"
        | "vpunpckhqdq" if matches!(operands.len(), 2 | 3) => {
            emit_vector_unpack(output, address, family, operands)
        }
        "pshufb" | "vpshufb" if matches!(operands.len(), 2 | 3) => {
            emit_vector_byte_shuffle(output, address, family, operands)
        }
        "psllw" | "pslld" | "psllq" | "psrlw" | "psrld" | "psrlq" | "psraw" | "psrad"
        | "vpsllw" | "vpslld" | "vpsllq" | "vpsrlw" | "vpsrld" | "vpsrlq" | "vpsraw"
        | "vpsrad" if matches!(operands.len(), 2 | 3) => {
            emit_vector_qword_shift(output, address, family, operands)
        }
        "pshufd" | "vpshufd" if operands.len() == 3 => {
            emit_vector_dword_shuffle(output, address, family, operands)
        }
        "pshuflw" | "pshufhw" | "vpshuflw" | "vpshufhw" if operands.len() == 3 => {
            emit_vector_word_half_shuffle(output, address, family, operands)
        }
        "vpbroadcastb" | "vpbroadcastq" | "vbroadcastss" if operands.len() == 2 => {
            emit_vector_broadcast(output, address, family, &operands[0], &operands[1])
        }
        "ptest" | "vptest" if operands.len() == 2 => {
            emit_vector_test(output, address, &operands[0], &operands[1])
        }
        "vextracti128" if operands.len() == 3 => {
            emit_vector_extract_128(output, address, &operands[0], &operands[1], &operands[2])
        }
        "vinserti128" if operands.len() == 4 => emit_vector_insert_128(
            output,
            address,
            &operands[0],
            &operands[1],
            &operands[2],
            &operands[3],
        ),
        "add" | "sub" | "and" | "or" | "xor" if operands.len() == 2 => {
            emit_binary_operation(output, address, family, &operands[0], &operands[1])
        }
        "adc" | "sbb" if operands.len() == 2 => {
            emit_carry_binary_operation(output, address, family, &operands[0], &operands[1])
        }
        "andn" if operands.len() == 3 => {
            emit_andn_operation(output, address, &operands[0], &operands[1], &operands[2])
        }
        "cmp" | "test" if operands.len() == 2 => {
            emit_compare_operation(output, address, family, &operands[0], &operands[1])
        }
        "inc" | "dec" | "neg" | "not" if operands.len() == 1 => {
            emit_unary_operation(output, address, family, &operands[0])
        }
        "shl" | "shr" | "sar" if operands.len() == 2 => {
            emit_shift_operation(output, address, family, &operands[0], &operands[1])
        }
        "shld" | "shrd" if operands.len() == 3 => emit_double_shift_operation(
            output,
            address,
            family,
            &operands[0],
            &operands[1],
            &operands[2],
        ),
        "shlx" | "shrx" | "sarx" | "rorx" if operands.len() == 3 => {
            emit_flagless_shift_operation(
                output,
                address,
                family,
                &operands[0],
                &operands[1],
                &operands[2],
            )
        }
        "pdep" | "pext" if operands.len() == 3 => emit_bmi2_permutation(
            output,
            address,
            family,
            &operands[0],
            &operands[1],
            &operands[2],
        ),
        "rol" | "ror" if operands.len() == 2 => {
            emit_rotate_operation(output, address, family, &operands[0], &operands[1])
        }
        "rcl" | "rcr" if operands.len() == 2 => emit_rotate_through_carry_operation(
            output,
            address,
            family,
            &operands[0],
            &operands[1],
        ),
        "xchg" if operands.len() == 2 => {
            emit_register_exchange(output, address, &operands[0], &operands[1])
        }
        "bswap" if operands.len() == 1 => emit_bswap_operation(output, address, &operands[0]),
        "pmovmskb" | "vpmovmskb" if operands.len() == 2 => emit_vector_byte_mask(
            output,
            address,
            &operands[0],
            &operands[1],
        ),
        "prefetchnta" | "prefetcht0" | "prefetcht1" | "prefetcht2" | "prefetchw"
        | "prefetchwt1"
            if operands.len() == 1 =>
        {
            let address_expression = memory_address(&operands[0])?;
            output.push_str(&format!(
                "  (void)({address_expression}); /* architectural cache hint */\n"
            ));
            Ok(())
        }
        "bsf" | "bsr" if operands.len() == 2 => {
            emit_bit_scan_operation(output, address, family, &operands[0], &operands[1])
        }
        "bt" | "btc" | "btr" | "bts" if operands.len() == 2 => {
            emit_register_bit_test_operation(
                output,
                address,
                family,
                &operands[0],
                &operands[1],
            )
        }
        "popcnt" | "lzcnt" | "tzcnt" if operands.len() == 2 => {
            emit_bit_count_operation(output, address, family, &operands[0], &operands[1])
        }
        "imul" if operands.len() == 1 => {
            emit_full_multiply_operation(output, address, &operands[0], true)
        }
        "imul" if matches!(operands.len(), 2 | 3) => emit_imul_operation(output, address, operands),
        "mul" if operands.len() == 1 => {
            emit_full_multiply_operation(output, address, &operands[0], false)
        }
        "div" if operands.len() == 1 => {
            emit_unsigned_divide_operation(output, address, &operands[0])
        }
        "idiv" if operands.len() == 1 => {
            emit_signed_divide_operation(output, address, &operands[0])
        }
        "cbw" | "cwde" | "cdqe" | "cwd" | "cdq" | "cqo" if operands.is_empty() => {
            emit_accumulator_sign_extension(output, family)
        }
        "push" if operands.len() == 1 => {
            let value = read_operand(&operands[0])?;
            output.push_str(&format!(
                "  uint64_t hydir_push_{address:x} = (uint64_t)({value});\n  state->rsp -= UINT64_C(8);\n  hydir_store64(state->rsp, hydir_push_{address:x});\n"
            ));
            Ok(())
        }
        "pop" if operands.len() == 1 => {
            output.push_str(&format!(
                "  uint64_t hydir_pop_{address:x} = hydir_load64(state->rsp);\n  state->rsp += UINT64_C(8);\n"
            ));
            write_operand(output, &operands[0], &format!("hydir_pop_{address:x}"))?;
            Ok(())
        }
        "leave" if operands.is_empty() => {
            output.push_str("  state->rsp = state->rbp;\n  state->rbp = hydir_load64(state->rsp);\n  state->rsp += UINT64_C(8);\n");
            Ok(())
        }
        other => Err(format!(
            "native C backend lacks exact lowering for {other} at 0x{address:x}"
        )),
    }
}

fn emit_vector_move(
    output: &mut String,
    address: u64,
    family: &str,
    destination: &MachineOperand,
    source: &MachineOperand,
    decorators: &InstructionDecorators,
) -> Result<(), String> {
    let width = operand_width(destination)?;
    if !matches!(width, 128 | 256 | 512) || operand_width(source)? != width {
        return Err("native vector move has incompatible widths".to_owned());
    }
    let aligned_memory = matches!(
        family,
        "movaps"
            | "movapd"
            | "movdqa"
            | "vmovaps"
            | "vmovapd"
            | "vmovdqa"
            | "vmovdqa32"
            | "vmovdqa64"
    ) && (matches!(destination, MachineOperand::Memory { .. })
        || matches!(source, MachineOperand::Memory { .. }));
    if decorators.broadcast {
        return Err(format!(
            "native vector move broadcast is invalid at 0x{address:x}"
        ));
    }
    if decorators.op_mask.is_some() {
        return emit_masked_vector_move(
            output,
            address,
            family,
            destination,
            source,
            decorators,
            aligned_memory,
        );
    }
    if decorators.zeroing {
        return Err(format!(
            "native vector move zeroing requires an opmask at 0x{address:x}"
        ));
    }
    let byte_width = width / 8;
    if width == 512 {
        output.push_str(&format!("  uint8_t hydir_vector_move_{address:x}[64];\n"));
        if aligned_memory {
            match (destination, source) {
                (
                    register @ MachineOperand::Register { .. },
                    memory @ MachineOperand::Memory { .. },
                ) => {
                    output.push_str(&format!(
                        "  hydir_aligned_vector_move(state, UINT64_C(0x{address:x}), \"{family}\", (uint64_t)({}), hydir_vector_move_{address:x}, 64U, 0U);\n",
                        memory_address(memory)?
                    ));
                    emit_vector_commit(
                        output,
                        register,
                        &format!("hydir_vector_move_{address:x}"),
                        64,
                    )?;
                }
                (
                    memory @ MachineOperand::Memory { .. },
                    register @ MachineOperand::Register { .. },
                ) => {
                    emit_vector_snapshot(
                        output,
                        &format!("hydir_vector_move_{address:x}"),
                        register,
                        64,
                    )?;
                    output.push_str(&format!(
                        "  hydir_aligned_vector_move(state, UINT64_C(0x{address:x}), \"{family}\", (uint64_t)({}), hydir_vector_move_{address:x}, 64U, 1U);\n",
                        memory_address(memory)?
                    ));
                }
                _ => {
                    return Err(
                        "aligned 512-bit vector move requires memory and register operands"
                            .to_owned(),
                    );
                }
            }
        } else {
            emit_vector_snapshot(
                output,
                &format!("hydir_vector_move_{address:x}"),
                source,
                64,
            )?;
            match destination {
                MachineOperand::Register { .. } => emit_vector_commit(
                    output,
                    destination,
                    &format!("hydir_vector_move_{address:x}"),
                    64,
                )?,
                MachineOperand::Memory { .. } => output.push_str(&format!(
                    "  memcpy((void *)(uintptr_t)({}), hydir_vector_move_{address:x}, 64U);\n",
                    memory_address(destination)?
                )),
                _ => return Err("native vector move has an invalid destination".to_owned()),
            }
        }
        return Ok(());
    }
    if aligned_memory {
        let (memory, register, store) = match (destination, source) {
            (
                register @ MachineOperand::Register { .. },
                memory @ MachineOperand::Memory { .. },
            ) => (memory, register, 0),
            (
                memory @ MachineOperand::Memory { .. },
                register @ MachineOperand::Register { .. },
            ) => (memory, register, 1),
            _ => {
                return Err(
                    "aligned vector move requires one memory and one register operand".to_owned(),
                );
            }
        };
        output.push_str(&format!(
            "  hydir_aligned_vector_move(state, UINT64_C(0x{address:x}), \"{family}\", (uint64_t)({}), {}, {byte_width}U, {store}U);\n",
            memory_address(memory)?,
            vector_register_storage(register)?
        ));
    } else {
        match (destination, source) {
            (MachineOperand::Register { .. }, source @ MachineOperand::Register { .. }) => output
                .push_str(&format!(
                    "  memmove({}, {}, {byte_width}U);\n",
                    vector_register_storage(destination)?,
                    vector_register_storage(source)?
                )),
            (MachineOperand::Register { .. }, source @ MachineOperand::Memory { .. }) => {
                output.push_str(&format!(
                    "  memcpy({}, (const void *)(uintptr_t)({}), {byte_width}U);\n",
                    vector_register_storage(destination)?,
                    memory_address(source)?
                ));
            }
            (destination @ MachineOperand::Memory { .. }, MachineOperand::Register { .. }) => {
                output.push_str(&format!(
                    "  memcpy((void *)(uintptr_t)({}), {}, {byte_width}U);\n",
                    memory_address(destination)?,
                    vector_register_storage(source)?
                ));
            }
            _ => return Err("native vector move requires one register operand".to_owned()),
        }
    }
    if family.starts_with('v')
        && width == 128
        && let MachineOperand::Register { .. } = destination
    {
        output.push_str(&format!(
            "  memset({} + 16U, 0, 16U);\n",
            vector_register_storage(destination)?
        ));
    }
    Ok(())
}

fn emit_masked_vector_move(
    output: &mut String,
    address: u64,
    family: &str,
    destination: &MachineOperand,
    source: &MachineOperand,
    decorators: &InstructionDecorators,
    aligned_memory: bool,
) -> Result<(), String> {
    let Some(mask_index) = decorators.op_mask.as_deref().and_then(opmask_name_index) else {
        return Err(format!(
            "native vector move opmask is invalid at 0x{address:x}"
        ));
    };
    if operand_width(destination)? != 512 || operand_width(source)? != 512 {
        return Err(format!(
            "native masked vector move currently requires 512-bit operands at 0x{address:x}"
        ));
    }
    let lane_bytes = match family {
        "vmovdqu32" | "vmovdqa32" | "vmovups" | "vmovaps" => 4_u16,
        "vmovdqu64" | "vmovdqa64" | "vmovupd" | "vmovapd" => 8_u16,
        _ => {
            return Err(format!(
                "native masked vector move family {family} is unsupported at 0x{address:x}"
            ));
        }
    };
    let lanes = 64_u16 / lane_bytes;
    match (destination, source) {
        (MachineOperand::Register { .. }, MachineOperand::Register { .. }) => {
            output.push_str(&format!(
                "  uint8_t hydir_masked_move_source_{address:x}[64];\n  uint8_t hydir_masked_move_result_{address:x}[64];\n"
            ));
            emit_vector_snapshot(
                output,
                &format!("hydir_masked_move_source_{address:x}"),
                source,
                64,
            )?;
            if decorators.zeroing {
                output.push_str(&format!(
                    "  memset(hydir_masked_move_result_{address:x}, 0, 64U);\n"
                ));
            } else {
                emit_vector_snapshot(
                    output,
                    &format!("hydir_masked_move_result_{address:x}"),
                    destination,
                    64,
                )?;
            }
            output.push_str(&format!(
                "  for (unsigned hydir_lane_{address:x} = 0U; hydir_lane_{address:x} < {lanes}U; ++hydir_lane_{address:x}) {{\n    if (((state->k[{mask_index}] >> hydir_lane_{address:x}) & UINT64_C(1)) != 0U) memcpy(hydir_masked_move_result_{address:x} + hydir_lane_{address:x} * {lane_bytes}U, hydir_masked_move_source_{address:x} + hydir_lane_{address:x} * {lane_bytes}U, {lane_bytes}U);\n  }}\n"
            ));
            emit_vector_commit(
                output,
                destination,
                &format!("hydir_masked_move_result_{address:x}"),
                64,
            )
        }
        (MachineOperand::Register { .. }, memory @ MachineOperand::Memory { .. }) => {
            output.push_str(&format!(
                "  uint8_t hydir_masked_move_result_{address:x}[64];\n"
            ));
            if decorators.zeroing {
                output.push_str(&format!(
                    "  memset(hydir_masked_move_result_{address:x}, 0, 64U);\n"
                ));
            } else {
                emit_vector_snapshot(
                    output,
                    &format!("hydir_masked_move_result_{address:x}"),
                    destination,
                    64,
                )?;
            }
            output.push_str(&format!(
                "  hydir_masked_vector_move(state, UINT64_C(0x{address:x}), \"{family}\", (uint64_t)({}), hydir_masked_move_result_{address:x}, 64U, {lane_bytes}U, state->k[{mask_index}], 0U, {}U);\n",
                memory_address(memory)?,
                u8::from(aligned_memory)
            ));
            emit_vector_commit(
                output,
                destination,
                &format!("hydir_masked_move_result_{address:x}"),
                64,
            )
        }
        (memory @ MachineOperand::Memory { .. }, MachineOperand::Register { .. }) => {
            if decorators.zeroing {
                return Err(format!(
                    "native masked vector store cannot use zeroing at 0x{address:x}"
                ));
            }
            output.push_str(&format!(
                "  uint8_t hydir_masked_move_source_{address:x}[64];\n"
            ));
            emit_vector_snapshot(
                output,
                &format!("hydir_masked_move_source_{address:x}"),
                source,
                64,
            )?;
            output.push_str(&format!(
                "  hydir_masked_vector_move(state, UINT64_C(0x{address:x}), \"{family}\", (uint64_t)({}), hydir_masked_move_source_{address:x}, 64U, {lane_bytes}U, state->k[{mask_index}], 1U, {}U);\n",
                memory_address(memory)?,
                u8::from(aligned_memory)
            ));
            Ok(())
        }
        _ => Err(format!(
            "native masked vector move needs at least one register at 0x{address:x}"
        )),
    }
}

fn emit_vector_byte_mask(
    output: &mut String,
    address: u64,
    destination: &MachineOperand,
    source: &MachineOperand,
) -> Result<(), String> {
    let destination_width = operand_width(destination)?;
    let source_width = operand_width(source)?;
    if !matches!(destination_width, 32 | 64)
        || !matches!(destination, MachineOperand::Register { .. })
        || !matches!(source_width, 128 | 256)
        || !matches!(source, MachineOperand::Register { .. })
    {
        return Err(format!(
            "native vector byte-mask operands are invalid at 0x{address:x}"
        ));
    }
    let byte_width = source_width / 8;
    output.push_str(&format!(
        "  uint32_t hydir_byte_mask_{address:x} = 0U;\n  for (unsigned hydir_byte_{address:x} = 0U; hydir_byte_{address:x} < {byte_width}U; ++hydir_byte_{address:x}) {{\n    hydir_byte_mask_{address:x} |= (uint32_t)(({}[hydir_byte_{address:x}] >> 7U) & 1U) << hydir_byte_{address:x};\n  }}\n",
        vector_register_storage(source)?
    ));
    write_operand(output, destination, &format!("hydir_byte_mask_{address:x}"))
}

fn emit_aesenc(
    output: &mut String,
    address: u64,
    destination: &MachineOperand,
    round_key: &MachineOperand,
) -> Result<(), String> {
    if operand_width(destination)? != 128
        || operand_width(round_key)? != 128
        || !matches!(destination, MachineOperand::Register { .. })
        || !matches!(
            round_key,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
    {
        return Err(format!(
            "native AESENC operands are invalid at 0x{address:x}"
        ));
    }
    output.push_str(&format!(
        "  uint8_t hydir_aes_state_{address:x}[16];\n  uint8_t hydir_aes_key_{address:x}[16];\n"
    ));
    emit_vector_snapshot(
        output,
        &format!("hydir_aes_state_{address:x}"),
        destination,
        16,
    )?;
    emit_vector_snapshot(output, &format!("hydir_aes_key_{address:x}"), round_key, 16)?;
    output.push_str(&format!(
        "  hydir_aesenc_round(hydir_aes_state_{address:x}, hydir_aes_key_{address:x});\n"
    ));
    emit_vector_commit(
        output,
        destination,
        &format!("hydir_aes_state_{address:x}"),
        16,
    )
}

fn emit_opmask_move(
    output: &mut String,
    address: u64,
    family: &str,
    destination: &MachineOperand,
    source: &MachineOperand,
) -> Result<(), String> {
    let width = match family {
        "kmovb" => 8,
        "kmovw" => 16,
        "kmovd" => 32,
        "kmovq" => 64,
        _ => return Err(format!("unknown opmask move {family}")),
    };
    let destination_mask = opmask_register_index(destination);
    let source_mask = opmask_register_index(source);
    let general_width = if width == 64 { 64 } else { 32 };
    let valid_non_mask = |operand: &MachineOperand| match operand {
        MachineOperand::Register { width_bits, .. } => *width_bits == general_width,
        MachineOperand::Memory { width_bits, .. } => *width_bits == width,
        _ => false,
    };
    if destination_mask.is_none() && source_mask.is_none()
        || (destination_mask.is_none() && !valid_non_mask(destination))
        || (source_mask.is_none() && !valid_non_mask(source))
        || (matches!(destination, MachineOperand::Memory { .. })
            && matches!(source, MachineOperand::Memory { .. }))
    {
        return Err(format!(
            "native {family} operands are invalid at 0x{address:x}"
        ));
    }
    let source_value = if let Some(index) = source_mask {
        format!("state->k[{index}]")
    } else {
        read_operand(source)?
    };
    let value = format!("(uint{width}_t)({source_value})");
    if let Some(index) = destination_mask {
        output.push_str(&format!("  state->k[{index}] = {value};\n"));
        Ok(())
    } else {
        write_operand(output, destination, &value).map_err(|error| {
            format!("native {family} destination is invalid at 0x{address:x}: {error}")
        })
    }
}

fn opmask_register_index(operand: &MachineOperand) -> Option<u8> {
    let MachineOperand::Register {
        name,
        width_bits: 64,
    } = operand
    else {
        return None;
    };
    name.strip_prefix('k')
        .and_then(|index| index.parse::<u8>().ok())
        .filter(|index| *index < 8)
}

fn opmask_name_index(name: &str) -> Option<u8> {
    name.strip_prefix('k')
        .and_then(|index| index.parse::<u8>().ok())
        .filter(|index| *index < 8)
}

fn emit_vector_byte_popcount(
    output: &mut String,
    address: u64,
    destination: &MachineOperand,
    source: &MachineOperand,
    decorators: &InstructionDecorators,
) -> Result<(), String> {
    if operand_width(destination)? != 512
        || operand_width(source)? != 512
        || !matches!(destination, MachineOperand::Register { .. })
        || !matches!(
            source,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
    {
        return Err(format!(
            "native VPOPCNTB operands are invalid at 0x{address:x}"
        ));
    }
    if decorators.broadcast {
        return Err(format!(
            "native VPOPCNTB broadcast is invalid at 0x{address:x}"
        ));
    }
    let mask_index = match decorators.op_mask.as_deref() {
        Some(mask) => Some(
            opmask_name_index(mask)
                .ok_or_else(|| format!("native VPOPCNTB opmask is invalid at 0x{address:x}"))?,
        ),
        None => None,
    };
    output.push_str(&format!(
        "  uint8_t hydir_popcount_result_{address:x}[64];\n"
    ));
    let source_array = !matches!(source, MachineOperand::Memory { .. }) || mask_index.is_none();
    if source_array {
        output.push_str(&format!(
            "  uint8_t hydir_popcount_source_{address:x}[64];\n"
        ));
        emit_vector_snapshot(
            output,
            &format!("hydir_popcount_source_{address:x}"),
            source,
            64,
        )?;
    }
    if mask_index.is_some() && !decorators.zeroing {
        emit_vector_snapshot(
            output,
            &format!("hydir_popcount_result_{address:x}"),
            destination,
            64,
        )?;
    } else {
        output.push_str(&format!(
            "  memset(hydir_popcount_result_{address:x}, 0, 64U);\n"
        ));
    }
    let source_value = if source_array {
        format!("hydir_popcount_source_{address:x}[hydir_lane_{address:x}]")
    } else {
        format!(
            "hydir_load8((uint64_t)({}) + hydir_lane_{address:x})",
            memory_address(source)?
        )
    };
    if let Some(mask_index) = mask_index {
        output.push_str(&format!(
            "  for (unsigned hydir_lane_{address:x} = 0U; hydir_lane_{address:x} < 64U; ++hydir_lane_{address:x}) {{\n    if (((state->k[{mask_index}] >> hydir_lane_{address:x}) & UINT64_C(1)) != 0U) hydir_popcount_result_{address:x}[hydir_lane_{address:x}] = (uint8_t)hydir_popcount64({source_value});\n  }}\n"
        ));
    } else {
        output.push_str(&format!(
            "  for (unsigned hydir_lane_{address:x} = 0U; hydir_lane_{address:x} < 64U; ++hydir_lane_{address:x}) {{\n    hydir_popcount_result_{address:x}[hydir_lane_{address:x}] = (uint8_t)hydir_popcount64({source_value});\n  }}\n"
        ));
    }
    emit_vector_commit(
        output,
        destination,
        &format!("hydir_popcount_result_{address:x}"),
        64,
    )
}

fn emit_vector_byte_permute(
    output: &mut String,
    address: u64,
    destination: &MachineOperand,
    indices: &MachineOperand,
    source: &MachineOperand,
    decorators: &InstructionDecorators,
) -> Result<(), String> {
    if operand_width(destination)? != 512
        || operand_width(indices)? != 512
        || operand_width(source)? != 512
        || !matches!(destination, MachineOperand::Register { .. })
        || !matches!(indices, MachineOperand::Register { .. })
        || !matches!(
            source,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
    {
        return Err(format!(
            "native VPERMB operands are invalid at 0x{address:x}"
        ));
    }
    if decorators.broadcast {
        return Err(format!(
            "native VPERMB broadcast is unsupported at 0x{address:x}"
        ));
    }
    let mask_index = match decorators.op_mask.as_deref() {
        Some(mask) => Some(
            opmask_name_index(mask)
                .ok_or_else(|| format!("native VPERMB opmask is invalid at 0x{address:x}"))?,
        ),
        None => None,
    };
    output.push_str(&format!(
        "  uint8_t hydir_permute_indices_{address:x}[64];\n  uint8_t hydir_permute_result_{address:x}[64];\n"
    ));
    emit_vector_snapshot(
        output,
        &format!("hydir_permute_indices_{address:x}"),
        indices,
        64,
    )?;
    let source_array = !matches!(source, MachineOperand::Memory { .. }) || mask_index.is_none();
    if source_array {
        output.push_str(&format!(
            "  uint8_t hydir_permute_source_{address:x}[64];\n"
        ));
        emit_vector_snapshot(
            output,
            &format!("hydir_permute_source_{address:x}"),
            source,
            64,
        )?;
    }
    if mask_index.is_some() && !decorators.zeroing {
        emit_vector_snapshot(
            output,
            &format!("hydir_permute_result_{address:x}"),
            destination,
            64,
        )?;
    } else {
        output.push_str(&format!(
            "  memset(hydir_permute_result_{address:x}, 0, 64U);\n"
        ));
    }
    let source_value = if source_array {
        format!("hydir_permute_source_{address:x}[hydir_permute_index_{address:x}]")
    } else {
        format!(
            "hydir_load8((uint64_t)({}) + hydir_permute_index_{address:x})",
            memory_address(source)?
        )
    };
    let active = mask_index.map_or_else(
        || "1".to_owned(),
        |mask| format!("((state->k[{mask}] >> hydir_lane_{address:x}) & UINT64_C(1)) != 0U"),
    );
    output.push_str(&format!(
        "  for (unsigned hydir_lane_{address:x} = 0U; hydir_lane_{address:x} < 64U; ++hydir_lane_{address:x}) {{\n    if ({active}) {{\n      uint8_t hydir_permute_index_{address:x} = hydir_permute_indices_{address:x}[hydir_lane_{address:x}] & UINT8_C(63);\n      hydir_permute_result_{address:x}[hydir_lane_{address:x}] = {source_value};\n    }}\n  }}\n"
    ));
    emit_vector_commit(
        output,
        destination,
        &format!("hydir_permute_result_{address:x}"),
        64,
    )
}

fn emit_vector_byte_permute2(
    output: &mut String,
    address: u64,
    destination: &MachineOperand,
    first_table: &MachineOperand,
    second_table: &MachineOperand,
    decorators: &InstructionDecorators,
) -> Result<(), String> {
    if operand_width(destination)? != 512
        || operand_width(first_table)? != 512
        || operand_width(second_table)? != 512
        || !matches!(destination, MachineOperand::Register { .. })
        || !matches!(first_table, MachineOperand::Register { .. })
        || !matches!(
            second_table,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
    {
        return Err(format!(
            "native VPERMI2B operands are invalid at 0x{address:x}"
        ));
    }
    if decorators.broadcast {
        return Err(format!(
            "native VPERMI2B broadcast is unsupported at 0x{address:x}"
        ));
    }
    let mask_index = match decorators.op_mask.as_deref() {
        Some(mask) => Some(
            opmask_name_index(mask)
                .ok_or_else(|| format!("native VPERMI2B opmask is invalid at 0x{address:x}"))?,
        ),
        None => None,
    };
    output.push_str(&format!(
        "  uint8_t hydir_permute2_indices_{address:x}[64];\n  uint8_t hydir_permute2_first_{address:x}[64];\n  uint8_t hydir_permute2_result_{address:x}[64];\n"
    ));
    emit_vector_snapshot(
        output,
        &format!("hydir_permute2_indices_{address:x}"),
        destination,
        64,
    )?;
    emit_vector_snapshot(
        output,
        &format!("hydir_permute2_first_{address:x}"),
        first_table,
        64,
    )?;
    let second_array =
        !matches!(second_table, MachineOperand::Memory { .. }) || mask_index.is_none();
    if second_array {
        output.push_str(&format!(
            "  uint8_t hydir_permute2_second_{address:x}[64];\n"
        ));
        emit_vector_snapshot(
            output,
            &format!("hydir_permute2_second_{address:x}"),
            second_table,
            64,
        )?;
    }
    if mask_index.is_some() {
        if decorators.zeroing {
            output.push_str(&format!(
                "  memset(hydir_permute2_result_{address:x}, 0, 64U);\n"
            ));
        } else {
            output.push_str(&format!(
                "  memcpy(hydir_permute2_result_{address:x}, hydir_permute2_indices_{address:x}, 64U);\n"
            ));
        }
    }
    let second_value = if second_array {
        format!("hydir_permute2_second_{address:x}[hydir_index_{address:x} & UINT8_C(63)]")
    } else {
        format!(
            "hydir_load8((uint64_t)({}) + (hydir_index_{address:x} & UINT8_C(63)))",
            memory_address(second_table)?
        )
    };
    let active = mask_index.map_or_else(
        || "1".to_owned(),
        |mask| format!("((state->k[{mask}] >> hydir_lane_{address:x}) & UINT64_C(1)) != 0U"),
    );
    output.push_str(&format!(
        "  for (unsigned hydir_lane_{address:x} = 0U; hydir_lane_{address:x} < 64U; ++hydir_lane_{address:x}) {{\n    if ({active}) {{\n      uint8_t hydir_index_{address:x} = hydir_permute2_indices_{address:x}[hydir_lane_{address:x}] & UINT8_C(127);\n      hydir_permute2_result_{address:x}[hydir_lane_{address:x}] = (hydir_index_{address:x} & UINT8_C(64)) != 0U ? {second_value} : hydir_permute2_first_{address:x}[hydir_index_{address:x} & UINT8_C(63)];\n    }}\n  }}\n"
    ));
    emit_vector_commit(
        output,
        destination,
        &format!("hydir_permute2_result_{address:x}"),
        64,
    )
}

fn emit_vector_gf2_affine(
    output: &mut String,
    address: u64,
    operands: &[MachineOperand],
    decorators: &InstructionDecorators,
) -> Result<(), String> {
    let [
        destination,
        input,
        matrix,
        MachineOperand::Immediate {
            value: immediate,
            width_bits: 8,
        },
    ] = operands
    else {
        return Err(format!(
            "native VGF2P8AFFINEQB operands are invalid at 0x{address:x}"
        ));
    };
    let broadcast = decorators.broadcast;
    if operand_width(destination)? != 512
        || operand_width(input)? != 512
        || !matches!(destination, MachineOperand::Register { .. })
        || !matches!(input, MachineOperand::Register { .. })
        || !matches!(
            matrix,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
        || if broadcast {
            !matches!(matrix, MachineOperand::Memory { width_bits: 64, .. })
        } else {
            operand_width(matrix)? != 512
        }
        || (decorators.zeroing && decorators.op_mask.is_none())
    {
        return Err(format!(
            "native VGF2P8AFFINEQB widths are invalid at 0x{address:x}"
        ));
    }
    let mask_index =
        match decorators.op_mask.as_deref() {
            Some(mask) => Some(opmask_name_index(mask).ok_or_else(|| {
                format!("native VGF2P8AFFINEQB opmask is invalid at 0x{address:x}")
            })?),
            None => None,
        };
    output.push_str(&format!(
        "  uint8_t hydir_affine_input_{address:x}[64];\n  uint8_t hydir_affine_result_{address:x}[64];\n"
    ));
    emit_vector_snapshot(
        output,
        &format!("hydir_affine_input_{address:x}"),
        input,
        64,
    )?;
    if mask_index.is_some() && !decorators.zeroing {
        emit_vector_snapshot(
            output,
            &format!("hydir_affine_result_{address:x}"),
            destination,
            64,
        )?;
    } else {
        output.push_str(&format!(
            "  memset(hydir_affine_result_{address:x}, 0, 64U);\n"
        ));
    }
    let matrix_array =
        !broadcast && (matches!(matrix, MachineOperand::Register { .. }) || mask_index.is_none());
    if matrix_array {
        output.push_str(&format!("  uint8_t hydir_affine_matrix_{address:x}[64];\n"));
        emit_vector_snapshot(
            output,
            &format!("hydir_affine_matrix_{address:x}"),
            matrix,
            64,
        )?;
    } else if broadcast {
        output.push_str(&format!(
            "  uint8_t hydir_affine_matrix_{address:x}[8] = {{0}};\n"
        ));
        let load = format!(
            "memcpy(hydir_affine_matrix_{address:x}, (const void *)(uintptr_t)({}), 8U);",
            memory_address(matrix)?
        );
        if let Some(mask_index) = mask_index {
            output.push_str(&format!(
                "  if (state->k[{mask_index}] != UINT64_C(0)) {load}\n"
            ));
        } else {
            output.push_str(&format!("  {load}\n"));
        }
    }
    let row = if broadcast {
        format!("hydir_affine_matrix_{address:x}[7U - hydir_bit_{address:x}]")
    } else if matrix_array {
        format!(
            "hydir_affine_matrix_{address:x}[hydir_matrix_base_{address:x} + 7U - hydir_bit_{address:x}]"
        )
    } else {
        format!(
            "hydir_load8((uint64_t)({}) + hydir_matrix_base_{address:x} + 7U - hydir_bit_{address:x})",
            memory_address(matrix)?
        )
    };
    let active = mask_index.map_or_else(
        || "1".to_owned(),
        |mask| format!("((state->k[{mask}] >> hydir_lane_{address:x}) & UINT64_C(1)) != 0U"),
    );
    let matrix_base_declaration = if broadcast {
        String::new()
    } else {
        format!("      unsigned hydir_matrix_base_{address:x} = hydir_lane_{address:x} & ~7U;\n")
    };
    output.push_str(&format!(
        "  for (unsigned hydir_lane_{address:x} = 0U; hydir_lane_{address:x} < 64U; ++hydir_lane_{address:x}) {{\n    if ({active}) {{\n      uint8_t hydir_affine_byte_{address:x} = 0U;\n{matrix_base_declaration}      for (unsigned hydir_bit_{address:x} = 0U; hydir_bit_{address:x} < 8U; ++hydir_bit_{address:x}) {{\n        uint8_t hydir_row_{address:x} = {row};\n        uint8_t hydir_output_bit_{address:x} = (uint8_t)((hydir_parity8((uint64_t)(hydir_row_{address:x} & hydir_affine_input_{address:x}[hydir_lane_{address:x}])) ^ 1U) ^ ((UINT8_C(0x{immediate:02x}) >> hydir_bit_{address:x}) & 1U));\n        hydir_affine_byte_{address:x} |= (uint8_t)(hydir_output_bit_{address:x} << hydir_bit_{address:x});\n      }}\n      hydir_affine_result_{address:x}[hydir_lane_{address:x}] = hydir_affine_byte_{address:x};\n    }}\n  }}\n"
    ));
    emit_vector_commit(
        output,
        destination,
        &format!("hydir_affine_result_{address:x}"),
        64,
    )
}

fn emit_vector_unsigned_qword_compare(
    output: &mut String,
    address: u64,
    operands: &[MachineOperand],
    decorators: &InstructionDecorators,
) -> Result<(), String> {
    let [
        destination,
        left,
        right,
        MachineOperand::Immediate {
            value: predicate,
            width_bits: 8,
        },
    ] = operands
    else {
        return Err(format!(
            "native VPCMPUQ operands are invalid at 0x{address:x}"
        ));
    };
    let Some(destination_index) = opmask_register_index(destination) else {
        return Err(format!(
            "native VPCMPUQ destination is invalid at 0x{address:x}"
        ));
    };
    let broadcast = decorators.broadcast;
    if *predicate > 7
        || operand_width(left)? != 512
        || !matches!(left, MachineOperand::Register { .. })
        || !matches!(
            right,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
        || if broadcast {
            !matches!(right, MachineOperand::Memory { width_bits: 64, .. })
        } else {
            operand_width(right)? != 512
        }
        || decorators.zeroing
    {
        return Err(format!(
            "native VPCMPUQ widths or predicate are invalid at 0x{address:x}"
        ));
    }
    let write_mask_index = match decorators.op_mask.as_deref() {
        Some(mask) => Some(
            opmask_name_index(mask)
                .ok_or_else(|| format!("native VPCMPUQ writemask is invalid at 0x{address:x}"))?,
        ),
        None => None,
    };
    output.push_str(&format!(
        "  uint8_t hydir_compare_left_{address:x}[64];\n  uint64_t hydir_compare_mask_{address:x} = UINT64_C(0);\n"
    ));
    emit_vector_snapshot(output, &format!("hydir_compare_left_{address:x}"), left, 64)?;
    let right_array = !broadcast
        && (matches!(right, MachineOperand::Register { .. }) || write_mask_index.is_none());
    if right_array {
        output.push_str(&format!("  uint8_t hydir_compare_right_{address:x}[64];\n"));
        emit_vector_snapshot(
            output,
            &format!("hydir_compare_right_{address:x}"),
            right,
            64,
        )?;
    }
    if broadcast {
        output.push_str(&format!(
            "  uint64_t hydir_compare_broadcast_{address:x} = UINT64_C(0);\n"
        ));
        let load = format!(
            "memcpy(&hydir_compare_broadcast_{address:x}, (const void *)(uintptr_t)({}), 8U);",
            memory_address(right)?
        );
        if let Some(mask) = write_mask_index {
            output.push_str(&format!(
                "  if ((state->k[{mask}] & UINT64_C(0xff)) != 0U) {load}\n"
            ));
        } else {
            output.push_str(&format!("  {load}\n"));
        }
    }
    let comparison = match *predicate {
        0 => "hydir_left == hydir_right",
        1 => "hydir_left < hydir_right",
        2 => "hydir_left <= hydir_right",
        3 => "0",
        4 => "hydir_left != hydir_right",
        5 => "hydir_left >= hydir_right",
        6 => "hydir_left > hydir_right",
        7 => "1",
        _ => unreachable!(),
    };
    let active = write_mask_index.map_or_else(
        || "1".to_owned(),
        |mask| format!("((state->k[{mask}] >> hydir_lane_{address:x}) & UINT64_C(1)) != 0U"),
    );
    let right_load = if broadcast {
        format!("hydir_right = hydir_compare_broadcast_{address:x};")
    } else if right_array {
        format!(
            "memcpy(&hydir_right, hydir_compare_right_{address:x} + hydir_lane_{address:x} * 8U, 8U);"
        )
    } else {
        format!(
            "memcpy(&hydir_right, (const void *)(uintptr_t)((uint64_t)({}) + hydir_lane_{address:x} * 8U), 8U);",
            memory_address(right)?
        )
    };
    output.push_str(&format!(
        "  for (unsigned hydir_lane_{address:x} = 0U; hydir_lane_{address:x} < 8U; ++hydir_lane_{address:x}) {{\n    if ({active}) {{\n      uint64_t hydir_left = UINT64_C(0), hydir_right = UINT64_C(0);\n      memcpy(&hydir_left, hydir_compare_left_{address:x} + hydir_lane_{address:x} * 8U, 8U);\n      {right_load}\n      if ({comparison}) hydir_compare_mask_{address:x} |= UINT64_C(1) << hydir_lane_{address:x};\n    }}\n  }}\n  state->k[{destination_index}] = hydir_compare_mask_{address:x};\n"
    ));
    Ok(())
}

fn emit_vector_qword_compress(
    output: &mut String,
    address: u64,
    destination: &MachineOperand,
    source: &MachineOperand,
    decorators: &InstructionDecorators,
) -> Result<(), String> {
    let Some(mask_index) = decorators.op_mask.as_deref().and_then(opmask_name_index) else {
        return Err(format!(
            "native VPCOMPRESSQ requires a valid opmask at 0x{address:x}"
        ));
    };
    if decorators.broadcast
        || operand_width(destination)? != 512
        || operand_width(source)? != 512
        || !matches!(
            destination,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
        || !matches!(
            source,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
        || (matches!(destination, MachineOperand::Memory { .. })
            && (!matches!(source, MachineOperand::Register { .. }) || decorators.zeroing))
    {
        return Err(format!(
            "native VPCOMPRESSQ operands are invalid at 0x{address:x}"
        ));
    }
    output.push_str(&format!(
        "  uint8_t hydir_compress_source_{address:x}[64];\n"
    ));
    emit_vector_snapshot(
        output,
        &format!("hydir_compress_source_{address:x}"),
        source,
        64,
    )?;
    if matches!(destination, MachineOperand::Memory { .. }) {
        output.push_str(&format!(
            "  unsigned hydir_output_lane_{address:x} = 0U;\n  for (unsigned hydir_lane_{address:x} = 0U; hydir_lane_{address:x} < 8U; ++hydir_lane_{address:x}) {{\n    if (((state->k[{mask_index}] >> hydir_lane_{address:x}) & UINT64_C(1)) != 0U) {{\n      memcpy((void *)(uintptr_t)((uint64_t)({}) + hydir_output_lane_{address:x} * 8U), hydir_compress_source_{address:x} + hydir_lane_{address:x} * 8U, 8U);\n      ++hydir_output_lane_{address:x};\n    }}\n  }}\n",
            memory_address(destination)?
        ));
        return Ok(());
    }
    output.push_str(&format!(
        "  uint8_t hydir_compress_result_{address:x}[64];\n"
    ));
    if decorators.zeroing {
        output.push_str(&format!(
            "  memset(hydir_compress_result_{address:x}, 0, 64U);\n"
        ));
    } else {
        emit_vector_snapshot(
            output,
            &format!("hydir_compress_result_{address:x}"),
            destination,
            64,
        )?;
    }
    output.push_str(&format!(
        "  unsigned hydir_output_lane_{address:x} = 0U;\n  for (unsigned hydir_lane_{address:x} = 0U; hydir_lane_{address:x} < 8U; ++hydir_lane_{address:x}) {{\n    if (((state->k[{mask_index}] >> hydir_lane_{address:x}) & UINT64_C(1)) != 0U) {{\n      memcpy(hydir_compress_result_{address:x} + hydir_output_lane_{address:x} * 8U, hydir_compress_source_{address:x} + hydir_lane_{address:x} * 8U, 8U);\n      ++hydir_output_lane_{address:x};\n    }}\n  }}\n"
    ));
    emit_vector_commit(
        output,
        destination,
        &format!("hydir_compress_result_{address:x}"),
        64,
    )
}

fn emit_vector_insert_scalar(
    output: &mut String,
    address: u64,
    family: &str,
    operands: &[MachineOperand],
) -> Result<(), String> {
    let [
        destination,
        source,
        MachineOperand::Immediate { value: control, .. },
    ] = operands
    else {
        return Err(format!(
            "native {family} operands are invalid at 0x{address:x}"
        ));
    };
    if operand_width(destination)? != 128
        || !matches!(destination, MachineOperand::Register { .. })
        || !matches!(
            source,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
    {
        return Err(format!(
            "native {family} widths are invalid at 0x{address:x}"
        ));
    }
    let scalar_width: u16 = match family {
        "pinsrw" => 16,
        "pinsrd" => 32,
        "pinsrq" => 64,
        _ => return Err(format!("unknown vector scalar insert {family}")),
    };
    let scalar_bytes = scalar_width / 8;
    let lanes = 128 / scalar_width;
    let lane = control % u64::from(lanes);
    let value = read_operand(source)?;
    output.push_str(&format!(
        "  uint{scalar_width}_t hydir_insert_scalar_{address:x} = (uint{scalar_width}_t)({value});\n  memcpy({} + {}U, &hydir_insert_scalar_{address:x}, {scalar_bytes}U);\n",
        vector_register_storage(destination)?,
        lane * u64::from(scalar_bytes)
    ));
    Ok(())
}

fn emit_non_temporal_vector_store(
    output: &mut String,
    address: u64,
    destination: &MachineOperand,
    source: &MachineOperand,
) -> Result<(), String> {
    let width = operand_width(destination)?;
    if !matches!(width, 128 | 256)
        || operand_width(source)? != width
        || !matches!(destination, MachineOperand::Memory { .. })
        || !matches!(source, MachineOperand::Register { .. })
    {
        return Err(format!(
            "native non-temporal vector store operands are invalid at 0x{address:x}"
        ));
    }
    let byte_width = width / 8;
    output.push_str(&format!(
        "  uint8_t hydir_non_temporal_{address:x}[{byte_width}];\n"
    ));
    emit_vector_snapshot(
        output,
        &format!("hydir_non_temporal_{address:x}"),
        source,
        byte_width,
    )?;
    output.push_str(&format!(
        "  hydir_non_temporal_vector_store(state, (uint64_t)({}), hydir_non_temporal_{address:x}, {byte_width}U);\n",
        memory_address(destination)?
    ));
    Ok(())
}

fn emit_vector_scalar_move(
    output: &mut String,
    address: u64,
    family: &str,
    destination: &MachineOperand,
    source: &MachineOperand,
    scalar_width: u16,
) -> Result<(), String> {
    let byte_width = scalar_width / 8;
    let scalar_type = format!("uint{scalar_width}_t");
    let destination_is_vector = matches!(
        destination,
        MachineOperand::Register {
            name,
            width_bits: 128
        } if name.starts_with("xmm")
    );
    let source_is_vector = matches!(
        source,
        MachineOperand::Register {
            name,
            width_bits: 128
        } if name.starts_with("xmm")
    );
    if destination_is_vector {
        output.push_str(&format!(
            "  {scalar_type} hydir_vec_scalar_{address:x} = 0;\n"
        ));
        if source_is_vector {
            output.push_str(&format!(
                "  memcpy(&hydir_vec_scalar_{address:x}, {}, {byte_width}U);\n",
                vector_register_storage(source)?
            ));
        } else {
            let value = read_operand(source)?;
            output.push_str(&format!(
                "  hydir_vec_scalar_{address:x} = ({scalar_type})({value});\n"
            ));
        }
        output.push_str(&format!(
            "  memset({}, 0, 16U);\n  memcpy({}, &hydir_vec_scalar_{address:x}, {byte_width}U);\n",
            vector_register_storage(destination)?,
            vector_register_storage(destination)?
        ));
        if family.starts_with('v') {
            output.push_str(&format!(
                "  memset({} + 16U, 0, 16U);\n",
                vector_register_storage(destination)?
            ));
        }
        return Ok(());
    }
    if !source_is_vector {
        return Err(format!(
            "native {family} at 0x{address:x} has no vector operand"
        ));
    }
    output.push_str(&format!(
        "  {scalar_type} hydir_vec_scalar_{address:x} = 0;\n  memcpy(&hydir_vec_scalar_{address:x}, {}, {byte_width}U);\n",
        vector_register_storage(source)?
    ));
    write_operand(
        output,
        destination,
        &format!("hydir_vec_scalar_{address:x}"),
    )
}

fn emit_scalar_float_move(
    output: &mut String,
    address: u64,
    family: &str,
    operands: &[MachineOperand],
    single_precision: bool,
) -> Result<(), String> {
    let scalar_width = if single_precision { 32 } else { 64 };
    let byte_width = scalar_width / 8;
    let vector_register = |operand: &MachineOperand| {
        matches!(
            operand,
            MachineOperand::Register { name, width_bits: 128 } if name.starts_with("xmm")
        )
    };
    let scalar_memory = |operand: &MachineOperand| {
        matches!(
            operand,
            MachineOperand::Memory { width_bits, .. } if *width_bits == scalar_width
        )
    };
    match operands {
        [destination, source] if !family.starts_with('v') && vector_register(destination) => {
            if vector_register(source) {
                output.push_str(&format!(
                    "  memmove({}, {}, {byte_width}U);\n",
                    vector_register_storage(destination)?,
                    vector_register_storage(source)?
                ));
            } else if scalar_memory(source) {
                output.push_str(&format!(
                    "  memcpy({}, (const void *)(uintptr_t)({}), {byte_width}U);\n  memset({} + {byte_width}U, 0, {}U);\n",
                    vector_register_storage(destination)?,
                    memory_address(source)?,
                    vector_register_storage(destination)?,
                    16 - byte_width
                ));
            } else {
                return Err(format!(
                    "native {family} at 0x{address:x} has an invalid scalar source"
                ));
            }
            Ok(())
        }
        [destination, source] if scalar_memory(destination) && vector_register(source) => {
            output.push_str(&format!(
                "  memcpy((void *)(uintptr_t)({}), {}, {byte_width}U);\n",
                memory_address(destination)?,
                vector_register_storage(source)?
            ));
            Ok(())
        }
        [destination, merge, scalar]
            if family.starts_with('v')
                && vector_register(destination)
                && vector_register(merge)
                && (vector_register(scalar) || scalar_memory(scalar)) =>
        {
            output.push_str(&format!(
                "  uint8_t hydir_vec_merge_{address:x}[16];\n  uint8_t hydir_vec_scalar_{address:x}[{byte_width}];\n  memcpy(hydir_vec_merge_{address:x}, {}, 16U);\n",
                vector_register_storage(merge)?
            ));
            if vector_register(scalar) {
                output.push_str(&format!(
                    "  memcpy(hydir_vec_scalar_{address:x}, {}, {byte_width}U);\n",
                    vector_register_storage(scalar)?
                ));
            } else {
                output.push_str(&format!(
                    "  memcpy(hydir_vec_scalar_{address:x}, (const void *)(uintptr_t)({}), {byte_width}U);\n",
                    memory_address(scalar)?
                ));
            }
            output.push_str(&format!(
                "  memcpy({}, hydir_vec_scalar_{address:x}, {byte_width}U);\n  memcpy({} + {byte_width}U, hydir_vec_merge_{address:x} + {byte_width}U, {}U);\n  memset({} + 16U, 0, 16U);\n",
                vector_register_storage(destination)?,
                vector_register_storage(destination)?,
                16 - byte_width,
                vector_register_storage(destination)?
            ));
            Ok(())
        }
        _ => Err(format!(
            "native {family} at 0x{address:x} has invalid scalar floating move operands"
        )),
    }
}

fn emit_scalar_float_binary(
    output: &mut String,
    address: u64,
    family: &str,
    operands: &[MachineOperand],
) -> Result<(), String> {
    let single_precision = family.ends_with("ss");
    let scalar_width = if single_precision { 32 } else { 64 };
    let byte_width = scalar_width / 8;
    let vector_register = |operand: &MachineOperand| {
        matches!(
            operand,
            MachineOperand::Register { name, width_bits: 128 } if name.starts_with("xmm")
        )
    };
    let scalar_source = |operand: &MachineOperand| {
        vector_register(operand)
            || matches!(
                operand,
                MachineOperand::Memory { width_bits, .. } if *width_bits == scalar_width
            )
    };
    let (destination, merge, right) = match operands {
        [destination, right] if !family.starts_with('v') => (destination, destination, right),
        [destination, merge, right] if family.starts_with('v') => (destination, merge, right),
        _ => {
            return Err(format!(
                "native {family} at 0x{address:x} has invalid scalar floating arithmetic arity"
            ));
        }
    };
    if !vector_register(destination) || !vector_register(merge) || !scalar_source(right) {
        return Err(format!(
            "native {family} at 0x{address:x} has invalid scalar floating arithmetic operands"
        ));
    }
    let scalar_type = if single_precision {
        "uint32_t"
    } else {
        "uint64_t"
    };
    let helper = if single_precision {
        "hydir_fp_binary32"
    } else {
        "hydir_fp_binary64"
    };
    let operation = family
        .trim_start_matches('v')
        .strip_suffix(if single_precision { "ss" } else { "sd" })
        .ok_or_else(|| format!("native scalar floating family {family} is invalid"))?;
    output.push_str(&format!(
        "  {scalar_type} hydir_fp_left_{address:x} = 0;\n  {scalar_type} hydir_fp_right_{address:x} = 0;\n  uint8_t hydir_fp_merge_{address:x}[16];\n  memcpy(hydir_fp_merge_{address:x}, {}, 16U);\n  memcpy(&hydir_fp_left_{address:x}, hydir_fp_merge_{address:x}, {byte_width}U);\n",
        vector_register_storage(merge)?
    ));
    if vector_register(right) {
        output.push_str(&format!(
            "  memcpy(&hydir_fp_right_{address:x}, {}, {byte_width}U);\n",
            vector_register_storage(right)?
        ));
    } else {
        output.push_str(&format!(
            "  memcpy(&hydir_fp_right_{address:x}, (const void *)(uintptr_t)({}), {byte_width}U);\n",
            memory_address(right)?
        ));
    }
    output.push_str(&format!(
        "  {scalar_type} hydir_fp_result_{address:x} = {helper}(state, UINT64_C(0x{address:x}), \"{operation}\", hydir_fp_left_{address:x}, hydir_fp_right_{address:x});\n  memcpy({}, hydir_fp_merge_{address:x}, 16U);\n  memcpy({}, &hydir_fp_result_{address:x}, {byte_width}U);\n",
        vector_register_storage(destination)?,
        vector_register_storage(destination)?
    ));
    if family.starts_with('v') {
        output.push_str(&format!(
            "  memset({} + 16U, 0, 16U);\n",
            vector_register_storage(destination)?
        ));
    }
    Ok(())
}

fn emit_packed_float_binary(
    output: &mut String,
    address: u64,
    family: &str,
    operands: &[MachineOperand],
    decorators: &InstructionDecorators,
) -> Result<(), String> {
    let single_precision = family.ends_with("ps");
    let lane_width: u16 = if single_precision { 32 } else { 64 };
    let lane_bytes = lane_width / 8;
    let (destination, left, right) = match operands {
        [destination, right] if !family.starts_with('v') => (destination, destination, right),
        [destination, left, right] if family.starts_with('v') => (destination, left, right),
        _ => {
            return Err(format!(
                "native {family} at 0x{address:x} has invalid packed floating arithmetic arity"
            ));
        }
    };
    let width = operand_width(destination)?;
    let right_is_broadcast = decorators.broadcast;
    if !matches!(width, 128 | 256 | 512)
        || (!family.starts_with('v') && width != 128)
        || operand_width(left)? != width
        || !matches!(destination, MachineOperand::Register { .. })
        || !matches!(left, MachineOperand::Register { .. })
        || !matches!(
            right,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
        || if right_is_broadcast {
            !matches!(right, MachineOperand::Memory { width_bits, .. } if *width_bits == lane_width)
        } else {
            operand_width(right)? != width
        }
        || (decorators.zeroing && decorators.op_mask.is_none())
    {
        return Err(format!(
            "native {family} at 0x{address:x} has invalid packed floating arithmetic operands"
        ));
    }
    let byte_width = width / 8;
    let scalar_type = if single_precision {
        "uint32_t"
    } else {
        "uint64_t"
    };
    let helper = if single_precision {
        "hydir_fp_binary32"
    } else {
        "hydir_fp_binary64"
    };
    let operation = family
        .trim_start_matches('v')
        .strip_suffix(if single_precision { "ps" } else { "pd" })
        .ok_or_else(|| format!("native packed floating family {family} is invalid"))?;
    let mask_index =
        match decorators.op_mask.as_deref() {
            Some(mask) => Some(opmask_name_index(mask).ok_or_else(|| {
                format!("native packed floating opmask is invalid at 0x{address:x}")
            })?),
            None => None,
        };
    output.push_str(&format!(
        "  uint8_t hydir_fp_left_{address:x}[{byte_width}];\n  uint8_t hydir_fp_result_{address:x}[{byte_width}];\n"
    ));
    emit_vector_snapshot(
        output,
        &format!("hydir_fp_left_{address:x}"),
        left,
        byte_width,
    )?;
    if mask_index.is_some() && !decorators.zeroing {
        emit_vector_snapshot(
            output,
            &format!("hydir_fp_result_{address:x}"),
            destination,
            byte_width,
        )?;
    } else {
        output.push_str(&format!(
            "  memset(hydir_fp_result_{address:x}, 0, {byte_width}U);\n"
        ));
    }
    let right_array = !right_is_broadcast
        && (matches!(right, MachineOperand::Register { .. }) || mask_index.is_none());
    if right_array {
        output.push_str(&format!(
            "  uint8_t hydir_fp_right_{address:x}[{byte_width}];\n"
        ));
        emit_vector_snapshot(
            output,
            &format!("hydir_fp_right_{address:x}"),
            right,
            byte_width,
        )?;
    }
    if right_is_broadcast {
        output.push_str(&format!(
            "  {scalar_type} hydir_fp_broadcast_{address:x} = 0;\n"
        ));
        let load = format!(
            "memcpy(&hydir_fp_broadcast_{address:x}, (const void *)(uintptr_t)({}), {lane_bytes}U);",
            memory_address(right)?
        );
        if let Some(mask_index) = mask_index {
            let active_mask = if single_precision { "0xffff" } else { "0xff" };
            output.push_str(&format!(
                "  if ((state->k[{mask_index}] & UINT64_C({active_mask})) != 0U) {load}\n"
            ));
        } else {
            output.push_str(&format!("  {load}\n"));
        }
    }
    for offset in (0..byte_width).step_by(usize::from(lane_bytes)) {
        let lane = offset / lane_bytes;
        let indent = if mask_index.is_some() { "    " } else { "  " };
        if let Some(mask_index) = mask_index {
            output.push_str(&format!(
                "  if (((state->k[{mask_index}] >> {lane}U) & UINT64_C(1)) != 0U) {{\n"
            ));
        }
        output.push_str(&format!(
            "{indent}{scalar_type} hydir_fp_lane_left_{address:x}_{offset} = 0;\n{indent}{scalar_type} hydir_fp_lane_right_{address:x}_{offset} = 0;\n{indent}memcpy(&hydir_fp_lane_left_{address:x}_{offset}, hydir_fp_left_{address:x} + {offset}U, {lane_bytes}U);\n"
        ));
        if right_is_broadcast {
            output.push_str(&format!(
                "{indent}hydir_fp_lane_right_{address:x}_{offset} = hydir_fp_broadcast_{address:x};\n"
            ));
        } else if right_array {
            output.push_str(&format!(
                "{indent}memcpy(&hydir_fp_lane_right_{address:x}_{offset}, hydir_fp_right_{address:x} + {offset}U, {lane_bytes}U);\n"
            ));
        } else {
            output.push_str(&format!(
                "{indent}memcpy(&hydir_fp_lane_right_{address:x}_{offset}, (const void *)(uintptr_t)((uint64_t)({}) + {offset}U), {lane_bytes}U);\n",
                memory_address(right)?
            ));
        }
        output.push_str(&format!(
            "{indent}{scalar_type} hydir_fp_lane_result_{address:x}_{offset} = {helper}(state, UINT64_C(0x{address:x}), \"{operation}\", hydir_fp_lane_left_{address:x}_{offset}, hydir_fp_lane_right_{address:x}_{offset});\n{indent}memcpy(hydir_fp_result_{address:x} + {offset}U, &hydir_fp_lane_result_{address:x}_{offset}, {lane_bytes}U);\n"
        ));
        if mask_index.is_some() {
            output.push_str("  }\n");
        }
    }
    emit_vector_commit(
        output,
        destination,
        &format!("hydir_fp_result_{address:x}"),
        byte_width,
    )?;
    zero_vex_xmm_upper(output, family, width, destination)
}

fn emit_scalar_float_compare(
    output: &mut String,
    address: u64,
    family: &str,
    left: &MachineOperand,
    right: &MachineOperand,
) -> Result<(), String> {
    let single_precision = family.ends_with("ss");
    let scalar_width: u16 = if single_precision { 32 } else { 64 };
    let byte_width = scalar_width / 8;
    if !matches!(
        left,
        MachineOperand::Register {
            width_bits: 128,
            ..
        }
    ) || !(matches!(
        right,
        MachineOperand::Register {
            width_bits: 128,
            ..
        }
    ) || matches!(right, MachineOperand::Memory { width_bits, .. } if *width_bits == scalar_width))
    {
        return Err(format!(
            "native {family} at 0x{address:x} has invalid scalar floating comparison operands"
        ));
    }
    let scalar_type = if single_precision {
        "uint32_t"
    } else {
        "uint64_t"
    };
    let helper = if single_precision {
        "hydir_fp_compare32"
    } else {
        "hydir_fp_compare64"
    };
    output.push_str(&format!(
        "  {scalar_type} hydir_fp_compare_left_{address:x} = 0;\n  {scalar_type} hydir_fp_compare_right_{address:x} = 0;\n  memcpy(&hydir_fp_compare_left_{address:x}, {}, {byte_width}U);\n",
        vector_register_storage(left)?
    ));
    if matches!(right, MachineOperand::Register { .. }) {
        output.push_str(&format!(
            "  memcpy(&hydir_fp_compare_right_{address:x}, {}, {byte_width}U);\n",
            vector_register_storage(right)?
        ));
    } else {
        output.push_str(&format!(
            "  memcpy(&hydir_fp_compare_right_{address:x}, (const void *)(uintptr_t)({}), {byte_width}U);\n",
            memory_address(right)?
        ));
    }
    output.push_str(&format!(
        "  {helper}(state, UINT64_C(0x{address:x}), \"{family}\", hydir_fp_compare_left_{address:x}, hydir_fp_compare_right_{address:x});\n"
    ));
    Ok(())
}

fn emit_scalar_float_sqrt(
    output: &mut String,
    address: u64,
    family: &str,
    operands: &[MachineOperand],
) -> Result<(), String> {
    let single_precision = family.ends_with("ss");
    let scalar_width: u16 = if single_precision { 32 } else { 64 };
    let byte_width = scalar_width / 8;
    let (destination, merge, source) = match operands {
        [destination, source] if !family.starts_with('v') => (destination, destination, source),
        [destination, merge, source] if family.starts_with('v') => (destination, merge, source),
        _ => {
            return Err(format!(
                "native {family} at 0x{address:x} has invalid scalar square-root arity"
            ));
        }
    };
    if !matches!(
        destination,
        MachineOperand::Register {
            width_bits: 128,
            ..
        }
    ) || !matches!(
        merge,
        MachineOperand::Register {
            width_bits: 128,
            ..
        }
    ) || !(matches!(
        source,
        MachineOperand::Register {
            width_bits: 128,
            ..
        }
    ) || matches!(source, MachineOperand::Memory { width_bits, .. } if *width_bits == scalar_width))
    {
        return Err(format!(
            "native {family} at 0x{address:x} has invalid scalar square-root operands"
        ));
    }
    let scalar_type = if single_precision {
        "uint32_t"
    } else {
        "uint64_t"
    };
    let helper = if single_precision {
        "hydir_fp_unary32"
    } else {
        "hydir_fp_unary64"
    };
    output.push_str(&format!(
        "  uint8_t hydir_fp_sqrt_merge_{address:x}[16];\n  {scalar_type} hydir_fp_sqrt_source_{address:x} = 0;\n  memcpy(hydir_fp_sqrt_merge_{address:x}, {}, 16U);\n",
        vector_register_storage(merge)?
    ));
    if matches!(source, MachineOperand::Register { .. }) {
        output.push_str(&format!(
            "  memcpy(&hydir_fp_sqrt_source_{address:x}, {}, {byte_width}U);\n",
            vector_register_storage(source)?
        ));
    } else {
        output.push_str(&format!(
            "  memcpy(&hydir_fp_sqrt_source_{address:x}, (const void *)(uintptr_t)({}), {byte_width}U);\n",
            memory_address(source)?
        ));
    }
    output.push_str(&format!(
        "  {scalar_type} hydir_fp_sqrt_result_{address:x} = {helper}(state, UINT64_C(0x{address:x}), \"sqrt\", hydir_fp_sqrt_source_{address:x});\n  memcpy({}, hydir_fp_sqrt_merge_{address:x}, 16U);\n  memcpy({}, &hydir_fp_sqrt_result_{address:x}, {byte_width}U);\n",
        vector_register_storage(destination)?,
        vector_register_storage(destination)?
    ));
    zero_vex_xmm_upper(output, family, 128, destination)
}

fn emit_packed_float_sqrt(
    output: &mut String,
    address: u64,
    family: &str,
    destination: &MachineOperand,
    source: &MachineOperand,
) -> Result<(), String> {
    let single_precision = family.ends_with("ps");
    let lane_width: u16 = if single_precision { 32 } else { 64 };
    let lane_bytes = lane_width / 8;
    let width = operand_width(destination)?;
    if !matches!(width, 128 | 256)
        || (!family.starts_with('v') && width != 128)
        || operand_width(source)? != width
        || !matches!(destination, MachineOperand::Register { .. })
        || !matches!(
            source,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
    {
        return Err(format!(
            "native {family} at 0x{address:x} has invalid packed square-root operands"
        ));
    }
    let byte_width = width / 8;
    let scalar_type = if single_precision {
        "uint32_t"
    } else {
        "uint64_t"
    };
    let helper = if single_precision {
        "hydir_fp_unary32"
    } else {
        "hydir_fp_unary64"
    };
    output.push_str(&format!(
        "  uint8_t hydir_fp_sqrt_source_{address:x}[{byte_width}];\n  uint8_t hydir_fp_sqrt_result_{address:x}[{byte_width}];\n"
    ));
    emit_vector_snapshot(
        output,
        &format!("hydir_fp_sqrt_source_{address:x}"),
        source,
        byte_width,
    )?;
    for offset in (0..byte_width).step_by(usize::from(lane_bytes)) {
        output.push_str(&format!(
            "  {scalar_type} hydir_fp_sqrt_lane_{address:x}_{offset} = 0;\n  memcpy(&hydir_fp_sqrt_lane_{address:x}_{offset}, hydir_fp_sqrt_source_{address:x} + {offset}U, {lane_bytes}U);\n  {scalar_type} hydir_fp_sqrt_lane_result_{address:x}_{offset} = {helper}(state, UINT64_C(0x{address:x}), \"sqrt\", hydir_fp_sqrt_lane_{address:x}_{offset});\n  memcpy(hydir_fp_sqrt_result_{address:x} + {offset}U, &hydir_fp_sqrt_lane_result_{address:x}_{offset}, {lane_bytes}U);\n"
        ));
    }
    output.push_str(&format!(
        "  memcpy({}, hydir_fp_sqrt_result_{address:x}, {byte_width}U);\n",
        vector_register_storage(destination)?
    ));
    zero_vex_xmm_upper(output, family, width, destination)
}

fn emit_scalar_float_conversion(
    output: &mut String,
    address: u64,
    family: &str,
    operands: &[MachineOperand],
) -> Result<(), String> {
    let single_to_double = family.ends_with("ss2sd");
    let source_width: u16 = if single_to_double { 32 } else { 64 };
    let destination_width: u16 = if single_to_double { 64 } else { 32 };
    let source_bytes = source_width / 8;
    let destination_bytes = destination_width / 8;
    let (destination, merge, source) = match operands {
        [destination, source] if !family.starts_with('v') => (destination, destination, source),
        [destination, merge, source] if family.starts_with('v') => (destination, merge, source),
        _ => {
            return Err(format!(
                "native {family} at 0x{address:x} has invalid floating conversion arity"
            ));
        }
    };
    if !matches!(
        destination,
        MachineOperand::Register {
            width_bits: 128,
            ..
        }
    ) || !matches!(
        merge,
        MachineOperand::Register {
            width_bits: 128,
            ..
        }
    ) || !(matches!(
        source,
        MachineOperand::Register {
            width_bits: 128,
            ..
        }
    ) || matches!(source, MachineOperand::Memory { width_bits, .. } if *width_bits == source_width))
    {
        return Err(format!(
            "native {family} at 0x{address:x} has invalid floating conversion operands"
        ));
    }
    let source_type = if single_to_double {
        "uint32_t"
    } else {
        "uint64_t"
    };
    let result_type = if single_to_double {
        "uint64_t"
    } else {
        "uint32_t"
    };
    let helper = if single_to_double {
        "hydir_fp_convert32_to64"
    } else {
        "hydir_fp_convert64_to32"
    };
    output.push_str(&format!(
        "  uint8_t hydir_fp_convert_merge_{address:x}[16];\n  {source_type} hydir_fp_convert_source_{address:x} = 0;\n  memcpy(hydir_fp_convert_merge_{address:x}, {}, 16U);\n",
        vector_register_storage(merge)?
    ));
    if matches!(source, MachineOperand::Register { .. }) {
        output.push_str(&format!(
            "  memcpy(&hydir_fp_convert_source_{address:x}, {}, {source_bytes}U);\n",
            vector_register_storage(source)?
        ));
    } else {
        output.push_str(&format!(
            "  memcpy(&hydir_fp_convert_source_{address:x}, (const void *)(uintptr_t)({}), {source_bytes}U);\n",
            memory_address(source)?
        ));
    }
    output.push_str(&format!(
        "  {result_type} hydir_fp_convert_result_{address:x} = {helper}(state, UINT64_C(0x{address:x}), hydir_fp_convert_source_{address:x});\n  memcpy({}, hydir_fp_convert_merge_{address:x}, 16U);\n  memcpy({}, &hydir_fp_convert_result_{address:x}, {destination_bytes}U);\n",
        vector_register_storage(destination)?,
        vector_register_storage(destination)?
    ));
    zero_vex_xmm_upper(output, family, 128, destination)
}

fn emit_scalar_integer_float_conversion(
    output: &mut String,
    address: u64,
    family: &str,
    operands: &[MachineOperand],
) -> Result<(), String> {
    let integer_to_float = matches!(family, "cvtsi2ss" | "cvtsi2sd" | "vcvtsi2ss" | "vcvtsi2sd");
    let single_precision = family.contains("ss");
    let float_width: u16 = if single_precision { 32 } else { 64 };
    let float_bytes = float_width / 8;
    if integer_to_float {
        let (destination, merge, source) = match operands {
            [destination, source] if !family.starts_with('v') => (destination, destination, source),
            [destination, merge, source] if family.starts_with('v') => (destination, merge, source),
            _ => {
                return Err(format!(
                    "native {family} at 0x{address:x} has invalid integer-to-floating conversion arity"
                ));
            }
        };
        let source_width = operand_width(source)?;
        if !matches!(source_width, 32 | 64)
            || !matches!(
                destination,
                MachineOperand::Register {
                    width_bits: 128,
                    ..
                }
            )
            || !matches!(
                merge,
                MachineOperand::Register {
                    width_bits: 128,
                    ..
                }
            )
            || !matches!(
                source,
                MachineOperand::Register { .. } | MachineOperand::Memory { .. }
            )
        {
            return Err(format!(
                "native {family} at 0x{address:x} has invalid integer-to-floating conversion operands"
            ));
        }
        let result_type = if single_precision {
            "uint32_t"
        } else {
            "uint64_t"
        };
        let helper = if single_precision {
            "hydir_i64_to_fp32"
        } else {
            "hydir_i64_to_fp64"
        };
        output.push_str(&format!(
            "  uint8_t hydir_int_fp_merge_{address:x}[16];\n  memcpy(hydir_int_fp_merge_{address:x}, {}, 16U);\n  {result_type} hydir_int_fp_result_{address:x} = {helper}(state, UINT64_C(0x{address:x}), (uint64_t)({}), {source_width}U);\n  memcpy({}, hydir_int_fp_merge_{address:x}, 16U);\n  memcpy({}, &hydir_int_fp_result_{address:x}, {float_bytes}U);\n",
            vector_register_storage(merge)?,
            read_operand(source)?,
            vector_register_storage(destination)?,
            vector_register_storage(destination)?,
        ));
        return zero_vex_xmm_upper(output, family, 128, destination);
    }

    let [destination, source] = operands else {
        return Err(format!(
            "native {family} at 0x{address:x} has invalid floating-to-integer conversion arity"
        ));
    };
    let destination_width = operand_width(destination)?;
    if !matches!(destination_width, 32 | 64)
        || !matches!(destination, MachineOperand::Register { .. })
        || !(matches!(
            source,
            MachineOperand::Register {
                width_bits: 128,
                ..
            }
        ) || matches!(source, MachineOperand::Memory { width_bits, .. } if *width_bits == float_width))
    {
        return Err(format!(
            "native {family} at 0x{address:x} has invalid floating-to-integer conversion operands"
        ));
    }
    let source_type = if single_precision {
        "uint32_t"
    } else {
        "uint64_t"
    };
    let helper = if single_precision {
        "hydir_fp32_to_i64"
    } else {
        "hydir_fp64_to_i64"
    };
    output.push_str(&format!(
        "  {source_type} hydir_fp_int_source_{address:x} = 0;\n"
    ));
    if matches!(source, MachineOperand::Register { .. }) {
        output.push_str(&format!(
            "  memcpy(&hydir_fp_int_source_{address:x}, {}, {float_bytes}U);\n",
            vector_register_storage(source)?
        ));
    } else {
        output.push_str(&format!(
            "  memcpy(&hydir_fp_int_source_{address:x}, (const void *)(uintptr_t)({}), {float_bytes}U);\n",
            memory_address(source)?
        ));
    }
    let converted = format!(
        "{helper}(state, UINT64_C(0x{address:x}), hydir_fp_int_source_{address:x}, {destination_width}U, {}U)",
        u8::from(family.contains("cvtt"))
    );
    write_operand(output, destination, &converted)
}

fn emit_packed_integer_float_conversion(
    output: &mut String,
    address: u64,
    family: &str,
    destination: &MachineOperand,
    source: &MachineOperand,
) -> Result<(), String> {
    let width = operand_width(destination)?;
    if !matches!(width, 128 | 256)
        || (!family.starts_with('v') && width != 128)
        || operand_width(source)? != width
        || !matches!(destination, MachineOperand::Register { .. })
        || !matches!(
            source,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
    {
        return Err(format!(
            "native {family} at 0x{address:x} has invalid packed integer/floating conversion operands"
        ));
    }
    let byte_width = width / 8;
    let integer_to_float = matches!(family, "cvtdq2ps" | "vcvtdq2ps");
    output.push_str(&format!(
        "  uint8_t hydir_packed_convert_source_{address:x}[{byte_width}];\n  uint8_t hydir_packed_convert_result_{address:x}[{byte_width}];\n"
    ));
    emit_vector_snapshot(
        output,
        &format!("hydir_packed_convert_source_{address:x}"),
        source,
        byte_width,
    )?;
    for offset in (0..byte_width).step_by(4) {
        output.push_str(&format!(
            "  uint32_t hydir_packed_convert_lane_{address:x}_{offset} = 0;\n  memcpy(&hydir_packed_convert_lane_{address:x}_{offset}, hydir_packed_convert_source_{address:x} + {offset}U, 4U);\n"
        ));
        if integer_to_float {
            output.push_str(&format!(
                "  uint32_t hydir_packed_convert_result_lane_{address:x}_{offset} = hydir_i64_to_fp32(state, UINT64_C(0x{address:x}), hydir_packed_convert_lane_{address:x}_{offset}, 32U);\n"
            ));
        } else {
            output.push_str(&format!(
                "  uint32_t hydir_packed_convert_result_lane_{address:x}_{offset} = (uint32_t)hydir_fp32_to_i64(state, UINT64_C(0x{address:x}), hydir_packed_convert_lane_{address:x}_{offset}, 32U, {}U);\n",
                u8::from(family.contains("cvtt"))
            ));
        }
        output.push_str(&format!(
            "  memcpy(hydir_packed_convert_result_{address:x} + {offset}U, &hydir_packed_convert_result_lane_{address:x}_{offset}, 4U);\n"
        ));
    }
    output.push_str(&format!(
        "  memcpy({}, hydir_packed_convert_result_{address:x}, {byte_width}U);\n",
        vector_register_storage(destination)?
    ));
    zero_vex_xmm_upper(output, family, width, destination)
}

fn emit_packed_precision_conversion(
    output: &mut String,
    address: u64,
    family: &str,
    destination: &MachineOperand,
    source: &MachineOperand,
) -> Result<(), String> {
    let destination_width = operand_width(destination)?;
    let source_width = operand_width(source)?;
    if !matches!(destination, MachineOperand::Register { .. })
        || !matches!(
            source,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
    {
        return Err(format!(
            "native {family} at 0x{address:x} has invalid packed precision-conversion operands"
        ));
    }
    let widen = matches!(family, "cvtps2pd" | "vcvtps2pd" | "cvtdq2pd" | "vcvtdq2pd");
    let integer_conversion = matches!(
        family,
        "cvtdq2pd" | "vcvtdq2pd" | "cvtpd2dq" | "cvttpd2dq" | "vcvtpd2dq" | "vcvttpd2dq"
    );
    let lane_count = if widen {
        if !matches!(destination_width, 128 | 256) {
            return Err(format!(
                "native {family} at 0x{address:x} has invalid widening destination width"
            ));
        }
        destination_width / 64
    } else {
        if destination_width != 128 || !matches!(source_width, 128 | 256) {
            return Err(format!(
                "native {family} at 0x{address:x} has invalid narrowing widths"
            ));
        }
        source_width / 64
    };
    let source_lane_bytes: u16 = if widen { 4 } else { 8 };
    let result_lane_bytes: u16 = if widen { 8 } else { 4 };
    let source_bytes = lane_count * source_lane_bytes;
    let result_bytes = lane_count * result_lane_bytes;
    if source_width < source_bytes * 8 {
        return Err(format!(
            "native {family} at 0x{address:x} has an undersized source"
        ));
    }
    output.push_str(&format!(
        "  uint8_t hydir_precision_source_{address:x}[{source_bytes}];\n  uint8_t hydir_precision_result_{address:x}[{result_bytes}];\n"
    ));
    emit_vector_snapshot(
        output,
        &format!("hydir_precision_source_{address:x}"),
        source,
        source_bytes,
    )?;
    for lane in 0..lane_count {
        let source_offset = lane * source_lane_bytes;
        let result_offset = lane * result_lane_bytes;
        if widen {
            output.push_str(&format!(
                "  uint32_t hydir_precision_lane_{address:x}_{lane} = 0;\n  memcpy(&hydir_precision_lane_{address:x}_{lane}, hydir_precision_source_{address:x} + {source_offset}U, 4U);\n"
            ));
            let helper = if integer_conversion {
                "hydir_i64_to_fp64"
            } else {
                "hydir_fp_convert32_to64"
            };
            let arguments = if integer_conversion {
                format!("hydir_precision_lane_{address:x}_{lane}, 32U")
            } else {
                format!("hydir_precision_lane_{address:x}_{lane}")
            };
            output.push_str(&format!(
                "  uint64_t hydir_precision_result_lane_{address:x}_{lane} = {helper}(state, UINT64_C(0x{address:x}), {arguments});\n  memcpy(hydir_precision_result_{address:x} + {result_offset}U, &hydir_precision_result_lane_{address:x}_{lane}, 8U);\n"
            ));
        } else {
            output.push_str(&format!(
                "  uint64_t hydir_precision_lane_{address:x}_{lane} = 0;\n  memcpy(&hydir_precision_lane_{address:x}_{lane}, hydir_precision_source_{address:x} + {source_offset}U, 8U);\n"
            ));
            let (helper, suffix) = if integer_conversion {
                (
                    "hydir_fp64_to_i64",
                    format!(", 32U, {}U", u8::from(family.contains("cvtt"))),
                )
            } else {
                ("hydir_fp_convert64_to32", String::new())
            };
            output.push_str(&format!(
                "  uint32_t hydir_precision_result_lane_{address:x}_{lane} = (uint32_t){helper}(state, UINT64_C(0x{address:x}), hydir_precision_lane_{address:x}_{lane}{suffix});\n  memcpy(hydir_precision_result_{address:x} + {result_offset}U, &hydir_precision_result_lane_{address:x}_{lane}, 4U);\n"
            ));
        }
    }
    output.push_str(&format!(
        "  memset({}, 0, 16U);\n  memcpy({}, hydir_precision_result_{address:x}, {result_bytes}U);\n",
        vector_register_storage(destination)?,
        vector_register_storage(destination)?
    ));
    zero_vex_xmm_upper(output, family, destination_width, destination)
}

fn emit_atomic_operation(
    output: &mut String,
    address: u64,
    family: &str,
    destination: &MachineOperand,
    source: &MachineOperand,
) -> Result<(), String> {
    let width = operand_width(destination)?;
    let bit_modify = matches!(family, "lock_btc" | "lock_btr" | "lock_bts");
    if !matches!(width, 8 | 16 | 32 | 64)
        || (!bit_modify && operand_width(source)? != width)
        || (bit_modify
            && matches!(source, MachineOperand::Register { .. })
            && operand_width(source)? != width)
        || !matches!(destination, MachineOperand::Memory { .. })
    {
        return Err(format!(
            "native {family} requires a width-matched memory destination at 0x{address:x}"
        ));
    }
    let value = read_operand(source)?;
    let memory = memory_address(destination)?;
    let (c_type, _) = integer_types(width)?;
    output.push_str(&format!(
        "  {c_type} hydir_atomic_source_{address:x} = ({c_type})({value});\n"
    ));
    match family {
        "lock_xadd" if matches!(source, MachineOperand::Register { .. }) => {
            output.push_str(&format!(
                "  {c_type} hydir_atomic_old_{address:x} = ({c_type})hydir_atomic_rmw(state, (uint64_t)({memory}), \"add\", hydir_atomic_source_{address:x}, {width}U);\n"
            ));
            write_operand(output, source, &format!("hydir_atomic_old_{address:x}"))
        }
        "lock_cmpxchg" if matches!(source, MachineOperand::Register { .. }) => {
            output.push_str(&format!(
                "  {c_type} hydir_atomic_accumulator_{address:x} = ({c_type})state->rax;\n  {c_type} hydir_atomic_old_{address:x} = ({c_type})hydir_atomic_cmpxchg(state, (uint64_t)({memory}), hydir_atomic_accumulator_{address:x}, hydir_atomic_source_{address:x}, {width}U);\n"
            ));
            let accumulator = MachineOperand::Register {
                name: "rax".to_owned(),
                width_bits: width,
            };
            write_operand(
                output,
                &accumulator,
                &format!("hydir_atomic_old_{address:x}"),
            )
        }
        "atomic_xchg" if matches!(source, MachineOperand::Register { .. }) => {
            output.push_str(&format!(
                "  {c_type} hydir_atomic_old_{address:x} = ({c_type})hydir_atomic_exchange(state, (uint64_t)({memory}), hydir_atomic_source_{address:x}, {width}U);\n"
            ));
            write_operand(output, source, &format!("hydir_atomic_old_{address:x}"))
        }
        family if family.starts_with("lock_") => {
            let operation = family.trim_start_matches("lock_");
            output.push_str(&format!(
                "  (void)hydir_atomic_rmw(state, (uint64_t)({memory}), \"{operation}\", hydir_atomic_source_{address:x}, {width}U);\n"
            ));
            Ok(())
        }
        _ => Err(format!("unsupported native atomic family {family}")),
    }
}

fn emit_x87_operation(
    output: &mut String,
    address: u64,
    family: &str,
    operands: &[MachineOperand],
) -> Result<(), String> {
    if operands.len() > 2 {
        return Err(format!(
            "native x87 family {family} has too many operands at 0x{address:x}"
        ));
    }
    let mut memory = "UINT64_C(0)".to_owned();
    let mut memory_width = 0u16;
    let mut stack_operands = [u32::MAX; 2];
    let mut stack_index = 0usize;
    for operand in operands {
        match operand {
            MachineOperand::Register {
                name,
                width_bits: 80,
            } => {
                let index = name
                    .strip_prefix("st")
                    .and_then(|index| index.parse::<u32>().ok())
                    .filter(|index| *index < 8)
                    .ok_or_else(|| {
                        format!("native x87 family {family} has invalid register {name}")
                    })?;
                stack_operands[stack_index] = index;
                stack_index += 1;
            }
            MachineOperand::Memory { width_bits, .. }
                if memory_width == 0
                    && matches!(width_bits, 16 | 32 | 64 | 80 | 112 | 224 | 752 | 864) =>
            {
                memory = memory_address(operand)?;
                memory_width = *width_bits;
            }
            MachineOperand::Register {
                name,
                width_bits: 16,
            } if name == "rax" && matches!(family, "fnstsw" | "fstsw") => {}
            _ => {
                return Err(format!(
                    "native x87 family {family} has an invalid operand at 0x{address:x}"
                ));
            }
        }
    }
    output.push_str(&format!(
        "  hydir_x87_operation(state, UINT64_C(0x{address:x}), \"{family}\", (uint64_t)({memory}), {memory_width}U, {}U, {}U);\n",
        stack_operands[0], stack_operands[1]
    ));
    Ok(())
}

fn emit_extended_state_operation(
    output: &mut String,
    address: u64,
    family: &str,
    operand: &MachineOperand,
) -> Result<(), String> {
    let expected_width = if matches!(family, "fxsave" | "fxsave64" | "fxrstor" | "fxrstor64") {
        4096
    } else {
        32
    };
    if operand_width(operand)? != expected_width
        || !matches!(operand, MachineOperand::Memory { .. })
    {
        return Err(format!(
            "native extended-state family {family} has an invalid memory image at 0x{address:x}"
        ));
    }
    output.push_str(&format!(
        "  hydir_extended_state_operation(state, UINT64_C(0x{address:x}), \"{family}\", (uint64_t)({}));\n",
        memory_address(operand)?
    ));
    Ok(())
}

fn emit_environment_operation(
    output: &mut String,
    address: u64,
    family: &str,
    destination: Option<&MachineOperand>,
) -> Result<(), String> {
    let (name, width) = match destination {
        None => ("0".to_owned(), 0),
        Some(MachineOperand::Register { name, width_bits })
            if matches!(width_bits, 16 | 32 | 64) =>
        {
            (format!("\"{}\"", c_string(name)), *width_bits)
        }
        Some(_) => {
            return Err(format!(
                "native environment family {family} has an invalid destination at 0x{address:x}"
            ));
        }
    };
    output.push_str(&format!(
        "  hydir_environment_operation(state, UINT64_C(0x{address:x}), \"{family}\", {name}, {width}U);\n"
    ));
    Ok(())
}

fn emit_atomic_unary(
    output: &mut String,
    address: u64,
    family: &str,
    destination: &MachineOperand,
) -> Result<(), String> {
    let width = operand_width(destination)?;
    if !matches!(width, 8 | 16 | 32 | 64) || !matches!(destination, MachineOperand::Memory { .. }) {
        return Err(format!(
            "native {family} requires an integer memory destination at 0x{address:x}"
        ));
    }
    let operation = family
        .strip_prefix("lock_")
        .ok_or_else(|| format!("native atomic unary family {family} is invalid"))?;
    output.push_str(&format!(
        "  (void)hydir_atomic_rmw(state, (uint64_t)({}), \"{operation}\", UINT64_C(0), {width}U);\n",
        memory_address(destination)?
    ));
    Ok(())
}

fn emit_atomic_wide_compare_exchange(
    output: &mut String,
    address: u64,
    family: &str,
    destination: &MachineOperand,
) -> Result<(), String> {
    let width = operand_width(destination)?;
    if !matches!(
        (family.trim_start_matches("lock_"), width),
        ("cmpxchg8b", 64) | ("cmpxchg16b", 128)
    ) || !matches!(destination, MachineOperand::Memory { .. })
    {
        return Err(format!(
            "native {family} has an invalid wide compare-exchange operand at 0x{address:x}"
        ));
    }
    output.push_str(&format!(
        "  hydir_atomic_cmpxchg_wide(state, (uint64_t)({}), {width}U, {}U);\n",
        memory_address(destination)?,
        u8::from(family.starts_with("lock_"))
    ));
    Ok(())
}

fn emit_vector_bitwise(
    output: &mut String,
    address: u64,
    family: &str,
    operands: &[MachineOperand],
    decorators: &InstructionDecorators,
) -> Result<(), String> {
    let destination = &operands[0];
    let width = operand_width(destination)?;
    if !matches!(width, 128 | 256 | 512) || !matches!(destination, MachineOperand::Register { .. })
    {
        return Err(format!(
            "native vector bitwise destination is invalid at 0x{address:x}"
        ));
    }
    let (left, right) = if operands.len() == 2 {
        (destination, &operands[1])
    } else {
        (&operands[1], &operands[2])
    };
    if operand_width(left)? != width || operand_width(right)? != width {
        return Err(format!(
            "native vector bitwise widths differ at 0x{address:x}"
        ));
    }
    if decorators.broadcast || (decorators.zeroing && decorators.op_mask.is_none()) {
        return Err(format!(
            "native vector bitwise decorators are invalid at 0x{address:x}"
        ));
    }
    let mask = match decorators.op_mask.as_deref() {
        Some(name) => {
            let index = opmask_name_index(name).ok_or_else(|| {
                format!("native vector bitwise opmask is invalid at 0x{address:x}")
            })?;
            let lane_bytes = match family {
                "vpxord" => 4_u16,
                "vpandq" | "vporq" => 8_u16,
                _ => {
                    return Err(format!(
                        "native masked vector bitwise family {family} is unsupported at 0x{address:x}"
                    ));
                }
            };
            Some((index, lane_bytes))
        }
        None => None,
    };
    let byte_width = width / 8;
    output.push_str(&format!(
        "  uint8_t hydir_vec_result_{address:x}[{byte_width}];\n"
    ));
    let left_array = !matches!(left, MachineOperand::Memory { .. }) || mask.is_none();
    let right_array = !matches!(right, MachineOperand::Memory { .. }) || mask.is_none();
    if left_array {
        output.push_str(&format!(
            "  uint8_t hydir_vec_lhs_{address:x}[{byte_width}];\n"
        ));
        emit_vector_snapshot(
            output,
            &format!("hydir_vec_lhs_{address:x}"),
            left,
            byte_width,
        )?;
    }
    if right_array {
        output.push_str(&format!(
            "  uint8_t hydir_vec_rhs_{address:x}[{byte_width}];\n"
        ));
        emit_vector_snapshot(
            output,
            &format!("hydir_vec_rhs_{address:x}"),
            right,
            byte_width,
        )?;
    }
    if mask.is_some() && !decorators.zeroing {
        emit_vector_snapshot(
            output,
            &format!("hydir_vec_result_{address:x}"),
            destination,
            byte_width,
        )?;
    } else {
        output.push_str(&format!(
            "  memset(hydir_vec_result_{address:x}, 0, {byte_width}U);\n"
        ));
    }
    let left_value = if left_array {
        format!("hydir_vec_lhs_{address:x}[hydir_vec_i_{address:x}]")
    } else {
        format!(
            "hydir_load8((uint64_t)({}) + hydir_vec_i_{address:x})",
            memory_address(left)?
        )
    };
    let right_value = if right_array {
        format!("hydir_vec_rhs_{address:x}[hydir_vec_i_{address:x}]")
    } else {
        format!(
            "hydir_load8((uint64_t)({}) + hydir_vec_i_{address:x})",
            memory_address(right)?
        )
    };
    let assignment = match family {
        "pxor" | "xorps" | "xorpd" | "vpxor" | "vpxord" | "vxorps" | "vxorpd" => {
            format!("{left_value} ^ {right_value}")
        }
        "pand" | "andps" | "andpd" | "vpand" | "vpandq" | "vandps" | "vandpd" => {
            format!("{left_value} & {right_value}")
        }
        "por" | "orps" | "orpd" | "vpor" | "vporq" | "vorps" | "vorpd" => {
            format!("{left_value} | {right_value}")
        }
        "pandn" | "andnps" | "andnpd" | "vpandn" | "vandnps" | "vandnpd" => {
            format!("(uint8_t)~({left_value}) & {right_value}")
        }
        _ => return Err(format!("native vector bitwise family {family} is invalid")),
    };
    if let Some((mask_index, lane_bytes)) = mask {
        output.push_str(&format!(
            "  for (unsigned hydir_vec_i_{address:x} = 0U; hydir_vec_i_{address:x} < {byte_width}U; ++hydir_vec_i_{address:x}) {{\n    if (((state->k[{mask_index}] >> (hydir_vec_i_{address:x} / {lane_bytes}U)) & UINT64_C(1)) != 0U) hydir_vec_result_{address:x}[hydir_vec_i_{address:x}] = (uint8_t)({assignment});\n  }}\n"
        ));
    } else {
        output.push_str(&format!(
            "  for (unsigned hydir_vec_i_{address:x} = 0U; hydir_vec_i_{address:x} < {byte_width}U; ++hydir_vec_i_{address:x}) {{\n    hydir_vec_result_{address:x}[hydir_vec_i_{address:x}] = (uint8_t)({assignment});\n  }}\n"
        ));
    }
    emit_vector_commit(
        output,
        destination,
        &format!("hydir_vec_result_{address:x}"),
        byte_width,
    )?;
    if family.starts_with('v') && width == 128 {
        output.push_str(&format!(
            "  memset({} + 16U, 0, 16U);\n",
            vector_register_storage(destination)?
        ));
    }
    Ok(())
}

fn emit_vector_test(
    output: &mut String,
    address: u64,
    left: &MachineOperand,
    right: &MachineOperand,
) -> Result<(), String> {
    let width = operand_width(left)?;
    if !matches!(width, 128 | 256)
        || operand_width(right)? != width
        || !matches!(left, MachineOperand::Register { .. })
        || !matches!(
            right,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
    {
        return Err(format!(
            "native vector test operands are invalid at 0x{address:x}"
        ));
    }
    let byte_width = width / 8;
    output.push_str(&format!(
        "  uint8_t hydir_test_left_{address:x}[{byte_width}];\n  uint8_t hydir_test_right_{address:x}[{byte_width}];\n"
    ));
    emit_vector_snapshot(
        output,
        &format!("hydir_test_left_{address:x}"),
        left,
        byte_width,
    )?;
    emit_vector_snapshot(
        output,
        &format!("hydir_test_right_{address:x}"),
        right,
        byte_width,
    )?;
    output.push_str(&format!(
        "  uint8_t hydir_test_and_{address:x} = 0U, hydir_test_andn_{address:x} = 0U;\n  for (unsigned hydir_test_i_{address:x} = 0U; hydir_test_i_{address:x} < {byte_width}U; ++hydir_test_i_{address:x}) {{\n    hydir_test_and_{address:x} |= (uint8_t)(hydir_test_left_{address:x}[hydir_test_i_{address:x}] & hydir_test_right_{address:x}[hydir_test_i_{address:x}]);\n    hydir_test_andn_{address:x} |= (uint8_t)((uint8_t)~hydir_test_left_{address:x}[hydir_test_i_{address:x}] & hydir_test_right_{address:x}[hydir_test_i_{address:x}]);\n  }}\n  state->zf = (uint8_t)(hydir_test_and_{address:x} == 0U);\n  state->cf = (uint8_t)(hydir_test_andn_{address:x} == 0U);\n  state->of = 0U;\n  state->sf = 0U;\n  state->pf = 0U;\n  state->af = 0U;\n"
    ));
    Ok(())
}

fn emit_vector_lane_binary(
    output: &mut String,
    address: u64,
    family: &str,
    operands: &[MachineOperand],
) -> Result<(), String> {
    let destination = &operands[0];
    let width = operand_width(destination)?;
    let (left, right) = if operands.len() == 2 {
        (destination, &operands[1])
    } else {
        (&operands[1], &operands[2])
    };
    if !matches!(width, 128 | 256)
        || !matches!(destination, MachineOperand::Register { .. })
        || operand_width(left)? != width
        || operand_width(right)? != width
    {
        return Err(format!(
            "native vector lane operation is invalid at 0x{address:x}"
        ));
    }
    let byte_width = width / 8;
    output.push_str(&format!(
        "  uint8_t hydir_vec_lhs_{address:x}[{byte_width}];\n  uint8_t hydir_vec_rhs_{address:x}[{byte_width}];\n"
    ));
    emit_vector_snapshot(
        output,
        &format!("hydir_vec_lhs_{address:x}"),
        left,
        byte_width,
    )?;
    emit_vector_snapshot(
        output,
        &format!("hydir_vec_rhs_{address:x}"),
        right,
        byte_width,
    )?;
    let operation = family.strip_prefix('v').unwrap_or(family);
    if operation == "pmuludq" {
        output.push_str(&format!(
            "  for (unsigned hydir_lane_{address:x} = 0; hydir_lane_{address:x} < {byte_width}U; hydir_lane_{address:x} += 8U) {{\n    uint32_t hydir_lane_lhs_{address:x}, hydir_lane_rhs_{address:x};\n    uint64_t hydir_lane_result_{address:x};\n    memcpy(&hydir_lane_lhs_{address:x}, hydir_vec_lhs_{address:x} + hydir_lane_{address:x}, 4U);\n    memcpy(&hydir_lane_rhs_{address:x}, hydir_vec_rhs_{address:x} + hydir_lane_{address:x}, 4U);\n    hydir_lane_result_{address:x} = (uint64_t)hydir_lane_lhs_{address:x} * hydir_lane_rhs_{address:x};\n    memcpy({} + hydir_lane_{address:x}, &hydir_lane_result_{address:x}, 8U);\n  }}\n",
            vector_register_storage(destination)?
        ));
        return zero_vex_xmm_upper(output, family, width, destination);
    }
    if operation.starts_with("padds")
        || operation.starts_with("psubs")
        || operation.starts_with("paddus")
        || operation.starts_with("psubus")
    {
        let lane_bytes: u16 = if operation.ends_with('b') { 1 } else { 2 };
        let c_type = if lane_bytes == 1 {
            "uint8_t"
        } else {
            "uint16_t"
        };
        let signed_type = if lane_bytes == 1 { "int8_t" } else { "int16_t" };
        let unsigned = operation.contains("us");
        let add = operation.starts_with("padd");
        let calculation = match (unsigned, add, lane_bytes) {
            (true, true, 1) => format!(
                "uint32_t hydir_sat_wide_{address:x} = (uint32_t)hydir_lane_lhs_{address:x} + (uint32_t)hydir_lane_rhs_{address:x};\n    hydir_lane_result_{address:x} = (uint8_t)(hydir_sat_wide_{address:x} > UINT32_C(255) ? UINT32_C(255) : hydir_sat_wide_{address:x});"
            ),
            (true, true, 2) => format!(
                "uint32_t hydir_sat_wide_{address:x} = (uint32_t)hydir_lane_lhs_{address:x} + (uint32_t)hydir_lane_rhs_{address:x};\n    hydir_lane_result_{address:x} = (uint16_t)(hydir_sat_wide_{address:x} > UINT32_C(65535) ? UINT32_C(65535) : hydir_sat_wide_{address:x});"
            ),
            (true, false, _) => format!(
                "hydir_lane_result_{address:x} = hydir_lane_lhs_{address:x} < hydir_lane_rhs_{address:x} ? ({c_type})0 : ({c_type})(hydir_lane_lhs_{address:x} - hydir_lane_rhs_{address:x});"
            ),
            (false, add, 1) => format!(
                "int32_t hydir_sat_wide_{address:x} = (int32_t)({signed_type})hydir_lane_lhs_{address:x} {} (int32_t)({signed_type})hydir_lane_rhs_{address:x};\n    if (hydir_sat_wide_{address:x} > INT8_MAX) hydir_sat_wide_{address:x} = INT8_MAX;\n    if (hydir_sat_wide_{address:x} < INT8_MIN) hydir_sat_wide_{address:x} = INT8_MIN;\n    hydir_lane_result_{address:x} = (uint8_t)(int8_t)hydir_sat_wide_{address:x};",
                if add { "+" } else { "-" }
            ),
            (false, add, 2) => format!(
                "int32_t hydir_sat_wide_{address:x} = (int32_t)({signed_type})hydir_lane_lhs_{address:x} {} (int32_t)({signed_type})hydir_lane_rhs_{address:x};\n    if (hydir_sat_wide_{address:x} > INT16_MAX) hydir_sat_wide_{address:x} = INT16_MAX;\n    if (hydir_sat_wide_{address:x} < INT16_MIN) hydir_sat_wide_{address:x} = INT16_MIN;\n    hydir_lane_result_{address:x} = (uint16_t)(int16_t)hydir_sat_wide_{address:x};",
                if add { "+" } else { "-" }
            ),
            _ => unreachable!("saturating vector lanes are byte or word sized"),
        };
        output.push_str(&format!(
            "  for (unsigned hydir_lane_{address:x} = 0; hydir_lane_{address:x} < {byte_width}U; hydir_lane_{address:x} += {lane_bytes}U) {{\n    {c_type} hydir_lane_lhs_{address:x}, hydir_lane_rhs_{address:x}, hydir_lane_result_{address:x};\n    memcpy(&hydir_lane_lhs_{address:x}, hydir_vec_lhs_{address:x} + hydir_lane_{address:x}, {lane_bytes}U);\n    memcpy(&hydir_lane_rhs_{address:x}, hydir_vec_rhs_{address:x} + hydir_lane_{address:x}, {lane_bytes}U);\n    {calculation}\n    memcpy({} + hydir_lane_{address:x}, &hydir_lane_result_{address:x}, {lane_bytes}U);\n  }}\n",
            vector_register_storage(destination)?
        ));
        return zero_vex_xmm_upper(output, family, width, destination);
    }
    let lane_bytes: u16 = if operation.ends_with('b') {
        1
    } else if operation.ends_with('w') {
        2
    } else if operation.ends_with('d') {
        4
    } else if operation.ends_with('q') {
        8
    } else {
        return Err(format!("unknown vector lane operation {family}"));
    };
    let c_type = match lane_bytes {
        1 => "uint8_t",
        2 => "uint16_t",
        4 => "uint32_t",
        8 => "uint64_t",
        _ => unreachable!("lane byte width was selected from a fixed set"),
    };
    let lane_bits = lane_bytes * 8;
    let expression = if operation.starts_with("padd") {
        format!("hydir_lane_lhs_{address:x} + hydir_lane_rhs_{address:x}")
    } else if operation.starts_with("psub") {
        format!("hydir_lane_lhs_{address:x} - hydir_lane_rhs_{address:x}")
    } else if operation.starts_with("pmull") {
        format!("hydir_lane_lhs_{address:x} * hydir_lane_rhs_{address:x}")
    } else if operation.starts_with("pcmpeq") {
        format!(
            "hydir_lane_lhs_{address:x} == hydir_lane_rhs_{address:x} ? ({c_type})~({c_type})0 : ({c_type})0"
        )
    } else if operation.starts_with("pcmpgt") {
        format!(
            "(hydir_lane_lhs_{address:x} ^ (({c_type})1U << {}U)) > (hydir_lane_rhs_{address:x} ^ (({c_type})1U << {}U)) ? ({c_type})~({c_type})0 : ({c_type})0",
            lane_bits - 1,
            lane_bits - 1
        )
    } else if operation.starts_with("pminu") {
        format!(
            "hydir_lane_lhs_{address:x} < hydir_lane_rhs_{address:x} ? hydir_lane_lhs_{address:x} : hydir_lane_rhs_{address:x}"
        )
    } else if operation.starts_with("pmaxu") {
        format!(
            "hydir_lane_lhs_{address:x} > hydir_lane_rhs_{address:x} ? hydir_lane_lhs_{address:x} : hydir_lane_rhs_{address:x}"
        )
    } else if operation.starts_with("pmins") {
        format!(
            "(hydir_lane_lhs_{address:x} ^ (({c_type})1U << {}U)) < (hydir_lane_rhs_{address:x} ^ (({c_type})1U << {}U)) ? hydir_lane_lhs_{address:x} : hydir_lane_rhs_{address:x}",
            lane_bits - 1,
            lane_bits - 1
        )
    } else if operation.starts_with("pmaxs") {
        format!(
            "(hydir_lane_lhs_{address:x} ^ (({c_type})1U << {}U)) > (hydir_lane_rhs_{address:x} ^ (({c_type})1U << {}U)) ? hydir_lane_lhs_{address:x} : hydir_lane_rhs_{address:x}",
            lane_bits - 1,
            lane_bits - 1
        )
    } else {
        return Err(format!("unknown vector lane operation {family}"));
    };
    output.push_str(&format!(
        "  for (unsigned hydir_lane_{address:x} = 0; hydir_lane_{address:x} < {byte_width}U; hydir_lane_{address:x} += {lane_bytes}U) {{\n    {c_type} hydir_lane_lhs_{address:x}, hydir_lane_rhs_{address:x}, hydir_lane_result_{address:x};\n    memcpy(&hydir_lane_lhs_{address:x}, hydir_vec_lhs_{address:x} + hydir_lane_{address:x}, {lane_bytes}U);\n    memcpy(&hydir_lane_rhs_{address:x}, hydir_vec_rhs_{address:x} + hydir_lane_{address:x}, {lane_bytes}U);\n    hydir_lane_result_{address:x} = ({c_type})({expression});\n    memcpy({} + hydir_lane_{address:x}, &hydir_lane_result_{address:x}, {lane_bytes}U);\n  }}\n",
        vector_register_storage(destination)?
    ));
    zero_vex_xmm_upper(output, family, width, destination)
}

fn emit_vector_pack(
    output: &mut String,
    address: u64,
    family: &str,
    operands: &[MachineOperand],
) -> Result<(), String> {
    let destination = &operands[0];
    let width = operand_width(destination)?;
    let (left, right) = match operands {
        [destination, right] if !family.starts_with('v') => (destination, right),
        [_, left, right] if family.starts_with('v') => (left, right),
        _ => {
            return Err(format!(
                "native vector pack has invalid arity at 0x{address:x}"
            ));
        }
    };
    if !matches!(width, 128 | 256)
        || (!family.starts_with('v') && width != 128)
        || !matches!(destination, MachineOperand::Register { .. })
        || operand_width(left)? != width
        || operand_width(right)? != width
    {
        return Err(format!(
            "native vector pack operands are invalid at 0x{address:x}"
        ));
    }
    let operation = family.strip_prefix('v').unwrap_or(family);
    let (source_type, source_bytes, result_type, result_bytes, minimum, maximum) = match operation {
        "packsswb" => ("int16_t", 2u16, "int8_t", 1u16, "INT8_MIN", "INT8_MAX"),
        "packssdw" => ("int32_t", 4u16, "int16_t", 2u16, "INT16_MIN", "INT16_MAX"),
        "packuswb" => ("int16_t", 2u16, "uint8_t", 1u16, "0", "UINT8_MAX"),
        "packusdw" => ("int32_t", 4u16, "uint16_t", 2u16, "0", "UINT16_MAX"),
        _ => return Err(format!("unknown vector pack family {family}")),
    };
    let byte_width = width / 8;
    let elements = 16 / source_bytes;
    output.push_str(&format!(
        "  uint8_t hydir_pack_left_{address:x}[{byte_width}];\n  uint8_t hydir_pack_right_{address:x}[{byte_width}];\n  uint8_t hydir_pack_result_{address:x}[{byte_width}];\n"
    ));
    emit_vector_snapshot(
        output,
        &format!("hydir_pack_left_{address:x}"),
        left,
        byte_width,
    )?;
    emit_vector_snapshot(
        output,
        &format!("hydir_pack_right_{address:x}"),
        right,
        byte_width,
    )?;
    output.push_str(&format!(
        "  for (unsigned hydir_pack_group_{address:x} = 0; hydir_pack_group_{address:x} < {byte_width}U; hydir_pack_group_{address:x} += 16U) {{\n    for (unsigned hydir_pack_i_{address:x} = 0; hydir_pack_i_{address:x} < {elements}U; ++hydir_pack_i_{address:x}) {{\n      {source_type} hydir_pack_source_{address:x};\n      int64_t hydir_pack_wide_{address:x};\n      {result_type} hydir_pack_narrow_{address:x};\n      memcpy(&hydir_pack_source_{address:x}, hydir_pack_left_{address:x} + hydir_pack_group_{address:x} + hydir_pack_i_{address:x} * {source_bytes}U, {source_bytes}U);\n      hydir_pack_wide_{address:x} = (int64_t)hydir_pack_source_{address:x};\n      if (hydir_pack_wide_{address:x} < (int64_t)({minimum})) hydir_pack_wide_{address:x} = (int64_t)({minimum});\n      if (hydir_pack_wide_{address:x} > (int64_t)({maximum})) hydir_pack_wide_{address:x} = (int64_t)({maximum});\n      hydir_pack_narrow_{address:x} = ({result_type})hydir_pack_wide_{address:x};\n      memcpy(hydir_pack_result_{address:x} + hydir_pack_group_{address:x} + hydir_pack_i_{address:x} * {result_bytes}U, &hydir_pack_narrow_{address:x}, {result_bytes}U);\n      memcpy(&hydir_pack_source_{address:x}, hydir_pack_right_{address:x} + hydir_pack_group_{address:x} + hydir_pack_i_{address:x} * {source_bytes}U, {source_bytes}U);\n      hydir_pack_wide_{address:x} = (int64_t)hydir_pack_source_{address:x};\n      if (hydir_pack_wide_{address:x} < (int64_t)({minimum})) hydir_pack_wide_{address:x} = (int64_t)({minimum});\n      if (hydir_pack_wide_{address:x} > (int64_t)({maximum})) hydir_pack_wide_{address:x} = (int64_t)({maximum});\n      hydir_pack_narrow_{address:x} = ({result_type})hydir_pack_wide_{address:x};\n      memcpy(hydir_pack_result_{address:x} + hydir_pack_group_{address:x} + ({elements}U + hydir_pack_i_{address:x}) * {result_bytes}U, &hydir_pack_narrow_{address:x}, {result_bytes}U);\n    }}\n  }}\n  memcpy({}, hydir_pack_result_{address:x}, {byte_width}U);\n",
        vector_register_storage(destination)?
    ));
    zero_vex_xmm_upper(output, family, width, destination)
}

fn emit_vector_byte_shuffle(
    output: &mut String,
    address: u64,
    family: &str,
    operands: &[MachineOperand],
) -> Result<(), String> {
    let destination = &operands[0];
    let width = operand_width(destination)?;
    let (data, control) = match operands {
        [destination, control] if family == "pshufb" => (destination, control),
        [_, data, control] if family == "vpshufb" => (data, control),
        _ => {
            return Err(format!(
                "native byte shuffle has invalid arity at 0x{address:x}"
            ));
        }
    };
    if !matches!(width, 128 | 256)
        || (family == "pshufb" && width != 128)
        || !matches!(destination, MachineOperand::Register { .. })
        || operand_width(data)? != width
        || operand_width(control)? != width
    {
        return Err(format!(
            "native byte shuffle operands are invalid at 0x{address:x}"
        ));
    }
    let byte_width = width / 8;
    output.push_str(&format!(
        "  uint8_t hydir_shuffle_data_{address:x}[{byte_width}];\n  uint8_t hydir_shuffle_control_{address:x}[{byte_width}];\n  uint8_t hydir_shuffle_result_{address:x}[{byte_width}];\n"
    ));
    emit_vector_snapshot(
        output,
        &format!("hydir_shuffle_data_{address:x}"),
        data,
        byte_width,
    )?;
    emit_vector_snapshot(
        output,
        &format!("hydir_shuffle_control_{address:x}"),
        control,
        byte_width,
    )?;
    output.push_str(&format!(
        "  for (unsigned hydir_shuffle_i_{address:x} = 0; hydir_shuffle_i_{address:x} < {byte_width}U; ++hydir_shuffle_i_{address:x}) {{\n    uint8_t hydir_shuffle_selector_{address:x} = hydir_shuffle_control_{address:x}[hydir_shuffle_i_{address:x}];\n    unsigned hydir_shuffle_group_{address:x} = hydir_shuffle_i_{address:x} & ~15U;\n    hydir_shuffle_result_{address:x}[hydir_shuffle_i_{address:x}] = (hydir_shuffle_selector_{address:x} & 0x80U) != 0U ? 0U : hydir_shuffle_data_{address:x}[hydir_shuffle_group_{address:x} + (hydir_shuffle_selector_{address:x} & 0x0fU)];\n  }}\n  memcpy({}, hydir_shuffle_result_{address:x}, {byte_width}U);\n",
        vector_register_storage(destination)?
    ));
    zero_vex_xmm_upper(output, family, width, destination)
}

fn emit_vector_unpack(
    output: &mut String,
    address: u64,
    family: &str,
    operands: &[MachineOperand],
) -> Result<(), String> {
    let destination = &operands[0];
    let width = operand_width(destination)?;
    let (left, right) = match operands {
        [destination, right] if !family.starts_with('v') => (destination, right),
        [_, left, right] if family.starts_with('v') => (left, right),
        _ => {
            return Err(format!(
                "native vector unpack has invalid arity at 0x{address:x}"
            ));
        }
    };
    if !matches!(width, 128 | 256)
        || (!family.starts_with('v') && width != 128)
        || !matches!(destination, MachineOperand::Register { .. })
        || operand_width(left)? != width
        || operand_width(right)? != width
    {
        return Err(format!(
            "native vector unpack operands are invalid at 0x{address:x}"
        ));
    }
    let operation = family.strip_prefix('v').unwrap_or(family);
    let element_bytes: u16 = if operation.ends_with("bw") {
        1
    } else if operation.ends_with("wd") {
        2
    } else if operation.ends_with("dq") && !operation.ends_with("qdq") {
        4
    } else if operation.ends_with("qdq") {
        8
    } else {
        return Err(format!("unknown vector unpack family {family}"));
    };
    let high_half = operation.starts_with("punpckh");
    let half_offset = if high_half { 8 } else { 0 };
    let byte_width = width / 8;
    output.push_str(&format!(
        "  uint8_t hydir_unpack_left_{address:x}[{byte_width}];\n  uint8_t hydir_unpack_right_{address:x}[{byte_width}];\n  uint8_t hydir_unpack_result_{address:x}[{byte_width}];\n"
    ));
    emit_vector_snapshot(
        output,
        &format!("hydir_unpack_left_{address:x}"),
        left,
        byte_width,
    )?;
    emit_vector_snapshot(
        output,
        &format!("hydir_unpack_right_{address:x}"),
        right,
        byte_width,
    )?;
    for group in (0..byte_width).step_by(16) {
        for element_offset in (0..8).step_by(usize::from(element_bytes)) {
            let source_offset = group + half_offset + element_offset as u16;
            let result_offset = group + 2 * element_offset as u16;
            output.push_str(&format!(
                "  memcpy(hydir_unpack_result_{address:x} + {result_offset}U, hydir_unpack_left_{address:x} + {source_offset}U, {element_bytes}U);\n  memcpy(hydir_unpack_result_{address:x} + {}U, hydir_unpack_right_{address:x} + {source_offset}U, {element_bytes}U);\n",
                result_offset + element_bytes
            ));
        }
    }
    output.push_str(&format!(
        "  memcpy({}, hydir_unpack_result_{address:x}, {byte_width}U);\n",
        vector_register_storage(destination)?
    ));
    zero_vex_xmm_upper(output, family, width, destination)
}

fn emit_vector_qword_shift(
    output: &mut String,
    address: u64,
    family: &str,
    operands: &[MachineOperand],
) -> Result<(), String> {
    let (destination, source, immediate) = if operands.len() == 2 {
        (&operands[0], &operands[0], &operands[1])
    } else {
        (&operands[0], &operands[1], &operands[2])
    };
    let MachineOperand::Immediate { value: count, .. } = immediate else {
        return Err(format!(
            "native vector lane shift count is not immediate at 0x{address:x}"
        ));
    };
    let width = operand_width(destination)?;
    if !matches!(width, 128 | 256)
        || !matches!(destination, MachineOperand::Register { .. })
        || operand_width(source)? != width
    {
        return Err(format!(
            "native vector lane shift operands are invalid at 0x{address:x}"
        ));
    }
    let byte_width = width / 8;
    output.push_str(&format!(
        "  uint8_t hydir_vec_source_{address:x}[{byte_width}];\n"
    ));
    emit_vector_snapshot(
        output,
        &format!("hydir_vec_source_{address:x}"),
        source,
        byte_width,
    )?;
    let operation = family.strip_prefix('v').unwrap_or(family);
    let lane_bits: u16 = if operation.ends_with('w') {
        16
    } else if operation.ends_with('d') {
        32
    } else if operation.ends_with('q') {
        64
    } else {
        return Err(format!("unknown vector lane shift {family}"));
    };
    let lane_bytes = lane_bits / 8;
    let c_type = match lane_bits {
        16 => "uint16_t",
        32 => "uint32_t",
        64 => "uint64_t",
        _ => unreachable!("lane width was selected from a fixed set"),
    };
    let mask = if lane_bits == 64 {
        u64::MAX
    } else {
        (1u64 << lane_bits) - 1
    };
    let sign = 1u64 << (lane_bits - 1);
    let shifted_value = if operation.starts_with("psll") {
        if *count >= u64::from(lane_bits) {
            "UINT64_C(0)".to_owned()
        } else {
            format!("hydir_lane_value_{address:x} << {count}U")
        }
    } else if operation.starts_with("psrl") {
        if *count >= u64::from(lane_bits) {
            "UINT64_C(0)".to_owned()
        } else {
            format!("hydir_lane_value_{address:x} >> {count}U")
        }
    } else if operation.starts_with("psra") {
        if *count == 0 {
            format!("hydir_lane_value_{address:x}")
        } else if *count >= u64::from(lane_bits) {
            format!(
                "(hydir_lane_value_{address:x} & UINT64_C(0x{sign:x})) != 0U ? UINT64_C(0x{mask:x}) : UINT64_C(0)"
            )
        } else {
            format!(
                "(hydir_lane_value_{address:x} >> {count}U) | ((hydir_lane_value_{address:x} & UINT64_C(0x{sign:x})) != 0U ? (UINT64_C(0x{mask:x}) << {}U) & UINT64_C(0x{mask:x}) : UINT64_C(0))",
                u64::from(lane_bits) - *count
            )
        }
    } else {
        return Err(format!("unknown vector lane shift {family}"));
    };
    output.push_str(&format!(
        "  for (unsigned hydir_lane_{address:x} = 0; hydir_lane_{address:x} < {byte_width}U; hydir_lane_{address:x} += {lane_bytes}U) {{\n    {c_type} hydir_lane_value_{address:x}, hydir_lane_result_{address:x};\n    memcpy(&hydir_lane_value_{address:x}, hydir_vec_source_{address:x} + hydir_lane_{address:x}, {lane_bytes}U);\n    hydir_lane_result_{address:x} = ({c_type})({shifted_value});\n    memcpy({} + hydir_lane_{address:x}, &hydir_lane_result_{address:x}, {lane_bytes}U);\n  }}\n",
        vector_register_storage(destination)?
    ));
    zero_vex_xmm_upper(output, family, width, destination)
}

fn emit_vector_dword_shuffle(
    output: &mut String,
    address: u64,
    family: &str,
    operands: &[MachineOperand],
) -> Result<(), String> {
    let [
        destination,
        source,
        MachineOperand::Immediate { value: control, .. },
    ] = operands
    else {
        return Err(format!(
            "native vector dword shuffle operands are invalid at 0x{address:x}"
        ));
    };
    let width = operand_width(destination)?;
    if !matches!(width, 128 | 256)
        || !matches!(destination, MachineOperand::Register { .. })
        || operand_width(source)? != width
    {
        return Err(format!(
            "native vector dword shuffle widths are invalid at 0x{address:x}"
        ));
    }
    let byte_width = width / 8;
    output.push_str(&format!(
        "  uint8_t hydir_vec_source_{address:x}[{byte_width}];\n"
    ));
    emit_vector_snapshot(
        output,
        &format!("hydir_vec_source_{address:x}"),
        source,
        byte_width,
    )?;
    output.push_str(&format!(
        "  for (unsigned hydir_group_{address:x} = 0; hydir_group_{address:x} < {byte_width}U; hydir_group_{address:x} += 16U) {{\n    for (unsigned hydir_lane_{address:x} = 0; hydir_lane_{address:x} < 4U; ++hydir_lane_{address:x}) {{\n      unsigned hydir_source_lane_{address:x} = (unsigned)((UINT64_C({control}) >> (2U * hydir_lane_{address:x})) & UINT64_C(3));\n      memcpy({} + hydir_group_{address:x} + 4U * hydir_lane_{address:x}, hydir_vec_source_{address:x} + hydir_group_{address:x} + 4U * hydir_source_lane_{address:x}, 4U);\n    }}\n  }}\n",
        vector_register_storage(destination)?
    ));
    zero_vex_xmm_upper(output, family, width, destination)
}

fn emit_vector_word_half_shuffle(
    output: &mut String,
    address: u64,
    family: &str,
    operands: &[MachineOperand],
) -> Result<(), String> {
    let [
        destination,
        source,
        MachineOperand::Immediate { value: control, .. },
    ] = operands
    else {
        return Err(format!(
            "native vector word shuffle operands are invalid at 0x{address:x}"
        ));
    };
    let width = operand_width(destination)?;
    if !matches!(width, 128 | 256)
        || (!family.starts_with('v') && width != 128)
        || !matches!(destination, MachineOperand::Register { .. })
        || operand_width(source)? != width
    {
        return Err(format!(
            "native vector word shuffle widths are invalid at 0x{address:x}"
        ));
    }
    let byte_width = width / 8;
    let first_word = if family.ends_with("hw") { 4 } else { 0 };
    output.push_str(&format!(
        "  uint8_t hydir_word_shuffle_source_{address:x}[{byte_width}];\n  uint8_t hydir_word_shuffle_result_{address:x}[{byte_width}];\n"
    ));
    emit_vector_snapshot(
        output,
        &format!("hydir_word_shuffle_source_{address:x}"),
        source,
        byte_width,
    )?;
    output.push_str(&format!(
        "  memcpy(hydir_word_shuffle_result_{address:x}, hydir_word_shuffle_source_{address:x}, {byte_width}U);\n  for (unsigned hydir_group_{address:x} = 0U; hydir_group_{address:x} < {byte_width}U; hydir_group_{address:x} += 16U) {{\n    for (unsigned hydir_word_{address:x} = 0U; hydir_word_{address:x} < 4U; ++hydir_word_{address:x}) {{\n      unsigned hydir_source_word_{address:x} = (unsigned)((UINT64_C({control}) >> (2U * hydir_word_{address:x})) & UINT64_C(3));\n      memcpy(hydir_word_shuffle_result_{address:x} + hydir_group_{address:x} + 2U * ({first_word}U + hydir_word_{address:x}), hydir_word_shuffle_source_{address:x} + hydir_group_{address:x} + 2U * ({first_word}U + hydir_source_word_{address:x}), 2U);\n    }}\n  }}\n"
    ));
    output.push_str(&format!(
        "  memcpy({}, hydir_word_shuffle_result_{address:x}, {byte_width}U);\n",
        vector_register_storage(destination)?
    ));
    zero_vex_xmm_upper(output, family, width, destination)
}

fn emit_vector_broadcast(
    output: &mut String,
    address: u64,
    family: &str,
    destination: &MachineOperand,
    source: &MachineOperand,
) -> Result<(), String> {
    let width = operand_width(destination)?;
    if !matches!(width, 128 | 256) || !matches!(destination, MachineOperand::Register { .. }) {
        return Err(format!(
            "native vector broadcast destination is invalid at 0x{address:x}"
        ));
    }
    let scalar_width = match family {
        "vpbroadcastb" => 8,
        "vpbroadcastq" => 64,
        "vbroadcastss" => 32,
        _ => return Err(format!("unknown vector broadcast {family}")),
    };
    let (scalar_type, _) = integer_types(scalar_width)?;
    let scalar_bytes = scalar_width / 8;
    output.push_str(&format!(
        "  {scalar_type} hydir_broadcast_{address:x} = 0;\n"
    ));
    match source {
        MachineOperand::Register { .. } => output.push_str(&format!(
            "  memcpy(&hydir_broadcast_{address:x}, {}, {scalar_bytes}U);\n",
            vector_register_storage(source)?
        )),
        MachineOperand::Memory { .. } => {
            if operand_width(source)? != scalar_width {
                return Err(format!(
                    "native vector broadcast source width is invalid at 0x{address:x}"
                ));
            }
            let value = read_operand(source)?;
            output.push_str(&format!(
                "  hydir_broadcast_{address:x} = ({scalar_type})({value});\n"
            ));
        }
        _ => {
            return Err(format!(
                "native vector broadcast source is invalid at 0x{address:x}"
            ));
        }
    }
    let byte_width = width / 8;
    output.push_str(&format!(
        "  for (unsigned hydir_lane_{address:x} = 0; hydir_lane_{address:x} < {byte_width}U; hydir_lane_{address:x} += {scalar_bytes}U) memcpy({} + hydir_lane_{address:x}, &hydir_broadcast_{address:x}, {scalar_bytes}U);\n",
        vector_register_storage(destination)?
    ));
    zero_vex_xmm_upper(output, family, width, destination)
}

fn emit_vector_extract_128(
    output: &mut String,
    address: u64,
    destination: &MachineOperand,
    source: &MachineOperand,
    immediate: &MachineOperand,
) -> Result<(), String> {
    let MachineOperand::Immediate { value: lane, .. } = immediate else {
        return Err(format!(
            "native vector extract selector is invalid at 0x{address:x}"
        ));
    };
    if operand_width(destination)? != 128 || operand_width(source)? != 256 {
        return Err(format!(
            "native vector extract widths are invalid at 0x{address:x}"
        ));
    }
    output.push_str(&format!("  uint8_t hydir_vec_source_{address:x}[32];\n"));
    emit_vector_snapshot(output, &format!("hydir_vec_source_{address:x}"), source, 32)?;
    let offset = (lane & 1) * 16;
    match destination {
        MachineOperand::Register { .. } => {
            output.push_str(&format!(
                "  memcpy({}, hydir_vec_source_{address:x} + {offset}U, 16U);\n  memset({} + 16U, 0, 16U);\n",
                vector_register_storage(destination)?,
                vector_register_storage(destination)?
            ));
        }
        MachineOperand::Memory { .. } => output.push_str(&format!(
            "  memcpy((void *)(uintptr_t)({}), hydir_vec_source_{address:x} + {offset}U, 16U);\n",
            memory_address(destination)?
        )),
        _ => {
            return Err(format!(
                "native vector extract destination is invalid at 0x{address:x}"
            ));
        }
    }
    Ok(())
}

fn emit_vector_insert_128(
    output: &mut String,
    address: u64,
    destination: &MachineOperand,
    left: &MachineOperand,
    right: &MachineOperand,
    immediate: &MachineOperand,
) -> Result<(), String> {
    let MachineOperand::Immediate { value: lane, .. } = immediate else {
        return Err(format!(
            "native vector insert selector is not immediate at 0x{address:x}"
        ));
    };
    if operand_width(destination)? != 256
        || operand_width(left)? != 256
        || operand_width(right)? != 128
        || !matches!(destination, MachineOperand::Register { .. })
        || !matches!(left, MachineOperand::Register { .. })
        || !matches!(
            right,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
    {
        return Err(format!(
            "native vector insert operands are invalid at 0x{address:x}"
        ));
    }
    output.push_str(&format!(
        "  uint8_t hydir_insert_base_{address:x}[32];\n  uint8_t hydir_insert_lane_{address:x}[16];\n"
    ));
    emit_vector_snapshot(output, &format!("hydir_insert_base_{address:x}"), left, 32)?;
    emit_vector_snapshot(output, &format!("hydir_insert_lane_{address:x}"), right, 16)?;
    output.push_str(&format!(
        "  memcpy(hydir_insert_base_{address:x} + {}U, hydir_insert_lane_{address:x}, 16U);\n  memcpy({}, hydir_insert_base_{address:x}, 32U);\n",
        (lane & 1) * 16,
        vector_register_storage(destination)?
    ));
    Ok(())
}

fn zero_vex_xmm_upper(
    output: &mut String,
    family: &str,
    width: u16,
    destination: &MachineOperand,
) -> Result<(), String> {
    if family.starts_with('v') && width == 128 {
        output.push_str(&format!(
            "  memset({} + 16U, 0, 16U);\n",
            vector_register_storage(destination)?
        ));
    }
    Ok(())
}

fn emit_vector_snapshot(
    output: &mut String,
    variable: &str,
    operand: &MachineOperand,
    byte_width: u16,
) -> Result<(), String> {
    match operand {
        MachineOperand::Register {
            name,
            width_bits: 512,
        } => {
            let index = vector_register_index(name, "zmm")?;
            if byte_width != 64 {
                return Err("native ZMM snapshot does not cover 512 bits".to_owned());
            }
            output.push_str(&format!(
                "  memcpy({variable}, state->ymm[{index}], 32U);\n  memcpy({variable} + 32U, state->zmm_hi256[{index}], 32U);\n"
            ));
        }
        MachineOperand::Register { .. } => output.push_str(&format!(
            "  memcpy({variable}, {}, {byte_width}U);\n",
            vector_register_storage(operand)?
        )),
        operand @ MachineOperand::Memory { .. } => output.push_str(&format!(
            "  memcpy({variable}, (const void *)(uintptr_t)({}), {byte_width}U);\n",
            memory_address(operand)?
        )),
        _ => return Err("native vector source is neither register nor memory".to_owned()),
    }
    Ok(())
}

fn emit_vector_commit(
    output: &mut String,
    destination: &MachineOperand,
    source: &str,
    byte_width: u16,
) -> Result<(), String> {
    match destination {
        MachineOperand::Register {
            name,
            width_bits: 512,
        } if byte_width == 64 => {
            let index = vector_register_index(name, "zmm")?;
            output.push_str(&format!(
                "  memcpy(state->ymm[{index}], {source}, 32U);\n  memcpy(state->zmm_hi256[{index}], {source} + 32U, 32U);\n"
            ));
            Ok(())
        }
        MachineOperand::Register { .. } => {
            output.push_str(&format!(
                "  memcpy({}, {source}, {byte_width}U);\n",
                vector_register_storage(destination)?
            ));
            Ok(())
        }
        _ => Err("native vector destination is not a register".to_owned()),
    }
}

fn vector_register_storage(operand: &MachineOperand) -> Result<String, String> {
    let MachineOperand::Register { name, width_bits } = operand else {
        return Err("native vector operand is not a register".to_owned());
    };
    let prefix = match width_bits {
        128 => "xmm",
        256 => "ymm",
        width => return Err(format!("unsupported native vector width {width}")),
    };
    let index = vector_register_index(name, prefix)?;
    Ok(format!("state->ymm[{index}]"))
}

fn vector_register_index(name: &str, prefix: &str) -> Result<u8, String> {
    name.strip_prefix(prefix)
        .and_then(|index| index.parse::<u8>().ok())
        .filter(|index| *index < 32)
        .ok_or_else(|| format!("unsupported native vector register {name}"))
}

fn emit_string_operation(output: &mut String, address: u64, family: &str) -> Result<(), String> {
    let (repeat_mode, operation) = if let Some(operation) = family.strip_prefix("repne_") {
        ("repne", operation)
    } else if let Some(operation) = family.strip_prefix("repe_") {
        ("repe", operation)
    } else if let Some(operation) = family.strip_prefix("rep_") {
        ("rep", operation)
    } else {
        ("none", family)
    };
    let (width, byte_width, operation_kind) = match operation {
        "movsb" => (8, 1, "move"),
        "movsw" => (16, 2, "move"),
        "movsd" => (32, 4, "move"),
        "movsq" => (64, 8, "move"),
        "stosb" => (8, 1, "store"),
        "stosw" => (16, 2, "store"),
        "stosd" => (32, 4, "store"),
        "stosq" => (64, 8, "store"),
        "cmpsb" => (8, 1, "compare"),
        "cmpsw" => (16, 2, "compare"),
        "cmpsd" => (32, 4, "compare"),
        "cmpsq" => (64, 8, "compare"),
        "scasb" => (8, 1, "scan"),
        "scasw" => (16, 2, "scan"),
        "scasd" => (32, 4, "scan"),
        "scasq" => (64, 8, "scan"),
        _ => return Err(format!("unknown string operation family {family}")),
    };
    let repeated = repeat_mode != "none";
    let uses_rsi = matches!(operation_kind, "move" | "compare");
    let indent = if repeated { "    " } else { "  " };
    if repeated {
        output.push_str("  while (state->rcx != UINT64_C(0)) {\n");
    }
    match operation_kind {
        "move" => output.push_str(&format!(
            "{indent}uint{width}_t hydir_string_value_{address:x} = hydir_load{width}(state->rsi);\n{indent}hydir_store{width}(state->rdi, hydir_string_value_{address:x});\n"
        )),
        "store" => output.push_str(&format!(
            "{indent}hydir_store{width}(state->rdi, (uint{width}_t)state->rax);\n"
        )),
        "compare" | "scan" => {
            let lhs = if operation_kind == "compare" {
                format!("hydir_load{width}(state->rsi)")
            } else {
                format!("(uint{width}_t)state->rax")
            };
            output.push_str(&format!(
                "{indent}uint{width}_t hydir_string_lhs_{address:x} = {lhs};\n{indent}uint{width}_t hydir_string_rhs_{address:x} = hydir_load{width}(state->rdi);\n{indent}uint{width}_t hydir_string_result_{address:x} = (uint{width}_t)(hydir_string_lhs_{address:x} - hydir_string_rhs_{address:x});\n{indent}state->zf = (uint8_t)(hydir_string_result_{address:x} == 0U);\n{indent}state->sf = (uint8_t)((hydir_string_result_{address:x} >> {}U) & 1U);\n{indent}state->pf = hydir_parity8(hydir_string_result_{address:x});\n{indent}state->cf = (uint8_t)(hydir_string_lhs_{address:x} < hydir_string_rhs_{address:x});\n{indent}state->of = (uint8_t)((((hydir_string_lhs_{address:x} ^ hydir_string_rhs_{address:x}) & (hydir_string_lhs_{address:x} ^ hydir_string_result_{address:x})) >> {}U) & 1U);\n{indent}state->af = (uint8_t)(((hydir_string_lhs_{address:x} ^ hydir_string_rhs_{address:x} ^ hydir_string_result_{address:x}) >> 4U) & 1U);\n",
                width - 1,
                width - 1
            ));
        }
        _ => unreachable!(),
    }
    output.push_str(&format!("{indent}if (state->df != 0U) {{\n"));
    if uses_rsi {
        output.push_str(&format!(
            "{indent}  state->rsi -= UINT64_C({byte_width});\n"
        ));
    }
    output.push_str(&format!(
        "{indent}  state->rdi -= UINT64_C({byte_width});\n{indent}}} else {{\n"
    ));
    if uses_rsi {
        output.push_str(&format!(
            "{indent}  state->rsi += UINT64_C({byte_width});\n"
        ));
    }
    output.push_str(&format!(
        "{indent}  state->rdi += UINT64_C({byte_width});\n{indent}}}\n"
    ));
    if repeated {
        output.push_str("    state->rcx -= UINT64_C(1);\n");
        if repeat_mode == "repe" {
            output.push_str("    if (!state->zf) break;\n");
        } else if repeat_mode == "repne" {
            output.push_str("    if (state->zf) break;\n");
        }
        output.push_str("  }\n");
    }
    Ok(())
}

fn emit_andn_operation(
    output: &mut String,
    address: u64,
    destination: &MachineOperand,
    left: &MachineOperand,
    right: &MachineOperand,
) -> Result<(), String> {
    let width = operand_width(destination)?;
    if !matches!(width, 32 | 64)
        || operand_width(left)? != width
        || operand_width(right)? != width
        || !matches!(destination, MachineOperand::Register { .. })
    {
        return Err(format!("native andn operands are invalid at 0x{address:x}"));
    }
    let (c_type, _) = integer_types(width)?;
    let left = read_operand(left)?;
    let right = read_operand(right)?;
    output.push_str(&format!(
        "  {c_type} hydir_lhs_{address:x} = ({c_type})({left});\n  {c_type} hydir_rhs_{address:x} = ({c_type})({right});\n  {c_type} hydir_result_{address:x} = ({c_type})(~hydir_lhs_{address:x} & hydir_rhs_{address:x});\n"
    ));
    write_operand(output, destination, &format!("hydir_result_{address:x}"))?;
    output.push_str(&format!(
        "  state->zf = (uint8_t)(hydir_result_{address:x} == 0U);\n  state->sf = (uint8_t)((hydir_result_{address:x} >> {}U) & 1U);\n  state->of = 0U;\n  state->cf = 0U;\n",
        width - 1
    ));
    Ok(())
}

fn emit_binary_operation(
    output: &mut String,
    address: u64,
    family: &str,
    destination: &MachineOperand,
    source: &MachineOperand,
) -> Result<(), String> {
    let width = operand_width(destination)?;
    if !matches!(width, 8 | 16 | 32 | 64) {
        return Err(format!(
            "unsupported native ALU width {width} at 0x{address:x}"
        ));
    }
    let (c_type, signed_type) = integer_types(width)?;
    let lhs = read_operand(destination)?;
    let rhs = read_operand(source)?;
    let operator = match family {
        "add" => "+",
        "sub" => "-",
        "and" => "&",
        "or" => "|",
        "xor" => "^",
        _ => unreachable!(),
    };
    output.push_str(&format!(
        "  {c_type} hydir_lhs_{address:x} = ({c_type})({lhs});\n  {c_type} hydir_rhs_{address:x} = ({c_type})({rhs});\n  {c_type} hydir_result_{address:x} = ({c_type})(hydir_lhs_{address:x} {operator} hydir_rhs_{address:x});\n"
    ));
    write_operand(output, destination, &format!("hydir_result_{address:x}"))?;
    output.push_str(&format!(
        "  state->zf = (uint8_t)(hydir_result_{address:x} == 0);\n  state->sf = (uint8_t)((({signed_type})hydir_result_{address:x}) < 0);\n  state->pf = hydir_parity8(hydir_result_{address:x});\n"
    ));
    match family {
        "add" => output.push_str(&format!(
            "  state->cf = (uint8_t)(hydir_result_{address:x} < hydir_lhs_{address:x});\n  state->of = (uint8_t)(((~(hydir_lhs_{address:x} ^ hydir_rhs_{address:x}) & (hydir_lhs_{address:x} ^ hydir_result_{address:x})) >> {}) & 1U);\n  state->af = (uint8_t)(((hydir_lhs_{address:x} ^ hydir_rhs_{address:x} ^ hydir_result_{address:x}) >> 4U) & 1U);\n",
            width - 1
        )),
        "sub" => output.push_str(&format!(
            "  state->cf = (uint8_t)(hydir_lhs_{address:x} < hydir_rhs_{address:x});\n  state->of = (uint8_t)((((hydir_lhs_{address:x} ^ hydir_rhs_{address:x}) & (hydir_lhs_{address:x} ^ hydir_result_{address:x})) >> {}) & 1U);\n  state->af = (uint8_t)(((hydir_lhs_{address:x} ^ hydir_rhs_{address:x} ^ hydir_result_{address:x}) >> 4U) & 1U);\n",
            width - 1
        )),
        _ => output.push_str("  state->cf = 0;\n  state->of = 0;\n"),
    }
    Ok(())
}

fn emit_carry_binary_operation(
    output: &mut String,
    address: u64,
    family: &str,
    destination: &MachineOperand,
    source: &MachineOperand,
) -> Result<(), String> {
    let width = operand_width(destination)?;
    let (c_type, signed_type) = integer_types(width)?;
    let lhs = read_operand(destination)?;
    let rhs = read_operand(source)?;
    output.push_str(&format!(
        "  {c_type} hydir_lhs_{address:x} = ({c_type})({lhs});\n  {c_type} hydir_rhs_{address:x} = ({c_type})({rhs});\n  {c_type} hydir_carry_{address:x} = ({c_type})(state->cf & 1U);\n"
    ));
    if family == "adc" {
        output.push_str(&format!(
            "  {c_type} hydir_intermediate_{address:x} = ({c_type})(hydir_lhs_{address:x} + hydir_rhs_{address:x});\n  {c_type} hydir_result_{address:x} = ({c_type})(hydir_intermediate_{address:x} + hydir_carry_{address:x});\n  uint8_t hydir_carry_out_{address:x} = (uint8_t)((hydir_intermediate_{address:x} < hydir_lhs_{address:x}) | (hydir_result_{address:x} < hydir_intermediate_{address:x}));\n"
        ));
    } else {
        output.push_str(&format!(
            "  {c_type} hydir_intermediate_{address:x} = ({c_type})(hydir_lhs_{address:x} - hydir_rhs_{address:x});\n  {c_type} hydir_result_{address:x} = ({c_type})(hydir_intermediate_{address:x} - hydir_carry_{address:x});\n  uint8_t hydir_carry_out_{address:x} = (uint8_t)((hydir_lhs_{address:x} < hydir_rhs_{address:x}) | (hydir_intermediate_{address:x} < hydir_carry_{address:x}));\n"
        ));
    }
    write_operand(output, destination, &format!("hydir_result_{address:x}"))?;
    output.push_str(&format!(
        "  state->zf = (uint8_t)(hydir_result_{address:x} == 0);\n  state->sf = (uint8_t)((({signed_type})hydir_result_{address:x}) < 0);\n  state->pf = hydir_parity8(hydir_result_{address:x});\n  state->af = (uint8_t)(((hydir_lhs_{address:x} ^ hydir_rhs_{address:x} ^ hydir_result_{address:x}) >> 4U) & 1U);\n  state->cf = hydir_carry_out_{address:x};\n"
    ));
    if family == "adc" {
        output.push_str(&format!(
            "  state->of = (uint8_t)(((~(hydir_lhs_{address:x} ^ hydir_rhs_{address:x}) & (hydir_lhs_{address:x} ^ hydir_result_{address:x})) >> {}) & 1U);\n",
            width - 1
        ));
    } else {
        output.push_str(&format!(
            "  state->of = (uint8_t)((((hydir_lhs_{address:x} ^ hydir_rhs_{address:x}) & (hydir_lhs_{address:x} ^ hydir_result_{address:x})) >> {}) & 1U);\n",
            width - 1
        ));
    }
    Ok(())
}

fn emit_compare_operation(
    output: &mut String,
    address: u64,
    family: &str,
    left: &MachineOperand,
    right: &MachineOperand,
) -> Result<(), String> {
    let width = operand_width(left)?;
    if !matches!(width, 8 | 16 | 32 | 64) {
        return Err(format!(
            "unsupported native compare width {width} at 0x{address:x}"
        ));
    }
    let (c_type, signed_type) = integer_types(width)?;
    let lhs = read_operand(left)?;
    let rhs = read_operand(right)?;
    let operator = if family == "cmp" { "-" } else { "&" };
    output.push_str(&format!(
        "  {c_type} hydir_lhs_{address:x} = ({c_type})({lhs});\n  {c_type} hydir_rhs_{address:x} = ({c_type})({rhs});\n  {c_type} hydir_result_{address:x} = ({c_type})(hydir_lhs_{address:x} {operator} hydir_rhs_{address:x});\n  state->zf = (uint8_t)(hydir_result_{address:x} == 0);\n  state->sf = (uint8_t)((({signed_type})hydir_result_{address:x}) < 0);\n  state->pf = hydir_parity8(hydir_result_{address:x});\n"
    ));
    if family == "cmp" {
        output.push_str(&format!(
            "  state->cf = (uint8_t)(hydir_lhs_{address:x} < hydir_rhs_{address:x});\n  state->of = (uint8_t)((((hydir_lhs_{address:x} ^ hydir_rhs_{address:x}) & (hydir_lhs_{address:x} ^ hydir_result_{address:x})) >> {}) & 1U);\n  state->af = (uint8_t)(((hydir_lhs_{address:x} ^ hydir_rhs_{address:x} ^ hydir_result_{address:x}) >> 4U) & 1U);\n",
            width - 1
        ));
    } else {
        output.push_str("  state->cf = 0;\n  state->of = 0;\n");
    }
    Ok(())
}

fn emit_unary_operation(
    output: &mut String,
    address: u64,
    family: &str,
    destination: &MachineOperand,
) -> Result<(), String> {
    let width = operand_width(destination)?;
    let (c_type, signed_type) = integer_types(width)?;
    let value = read_operand(destination)?;
    let expression = match family {
        "inc" => format!("({c_type})(hydir_lhs_{address:x} + ({c_type})1U)"),
        "dec" => format!("({c_type})(hydir_lhs_{address:x} - ({c_type})1U)"),
        "neg" => format!("({c_type})(0U - hydir_lhs_{address:x})"),
        "not" => format!("({c_type})(~hydir_lhs_{address:x})"),
        _ => unreachable!(),
    };
    output.push_str(&format!(
        "  {c_type} hydir_lhs_{address:x} = ({c_type})({value});\n  {c_type} hydir_result_{address:x} = {expression};\n"
    ));
    write_operand(output, destination, &format!("hydir_result_{address:x}"))?;
    if family == "not" {
        return Ok(());
    }
    output.push_str(&format!(
        "  state->zf = (uint8_t)(hydir_result_{address:x} == 0);\n  state->sf = (uint8_t)((({signed_type})hydir_result_{address:x}) < 0);\n  state->pf = hydir_parity8(hydir_result_{address:x});\n"
    ));
    let sign_mask = format!("(({c_type})1U << {})", width - 1);
    match family {
        "inc" => output.push_str(&format!(
            "  state->of = (uint8_t)(hydir_lhs_{address:x} == ({sign_mask} - ({c_type})1U));\n  state->af = (uint8_t)(((hydir_lhs_{address:x} ^ ({c_type})1U ^ hydir_result_{address:x}) >> 4U) & 1U);\n"
        )),
        "dec" => output.push_str(&format!(
            "  state->of = (uint8_t)(hydir_lhs_{address:x} == {sign_mask});\n  state->af = (uint8_t)(((hydir_lhs_{address:x} ^ ({c_type})1U ^ hydir_result_{address:x}) >> 4U) & 1U);\n"
        )),
        "neg" => output.push_str(&format!(
            "  state->cf = (uint8_t)(hydir_lhs_{address:x} != 0);\n  state->of = (uint8_t)(hydir_lhs_{address:x} == {sign_mask});\n  state->af = (uint8_t)(((hydir_lhs_{address:x} ^ hydir_result_{address:x}) >> 4U) & 1U);\n"
        )),
        _ => unreachable!(),
    }
    Ok(())
}

fn emit_immediate_shift_operation(
    output: &mut String,
    address: u64,
    family: &str,
    destination: &MachineOperand,
    count: &MachineOperand,
) -> Result<(), String> {
    let MachineOperand::Immediate {
        value: raw_count, ..
    } = count
    else {
        return Err(format!(
            "native exact shift requires an immediate count at 0x{address:x}"
        ));
    };
    let width = operand_width(destination)?;
    if *raw_count == 0 || *raw_count >= u64::from(width) {
        return Err(format!(
            "native exact shift count is outside the modeled range at 0x{address:x}"
        ));
    }
    let count = u16::try_from(*raw_count)
        .map_err(|_| format!("native shift count overflows at 0x{address:x}"))?;
    let (c_type, signed_type) = integer_types(width)?;
    let value = read_operand(destination)?;
    let sign_bit = width - 1;
    let expression = match family {
        "shl" => format!("({c_type})(hydir_lhs_{address:x} << {count}U)"),
        "shr" => format!("({c_type})(hydir_lhs_{address:x} >> {count}U)"),
        "sar" => format!(
            "({c_type})((hydir_lhs_{address:x} >> {count}U) | (((hydir_lhs_{address:x} >> {sign_bit}) & 1U) != 0U ? (UINT64_MAX << {}) : UINT64_C(0)))",
            width - count
        ),
        _ => unreachable!(),
    };
    output.push_str(&format!(
        "  {c_type} hydir_lhs_{address:x} = ({c_type})({value});\n  {c_type} hydir_result_{address:x} = {expression};\n"
    ));
    write_operand(output, destination, &format!("hydir_result_{address:x}"))?;
    output.push_str(&format!(
        "  state->zf = (uint8_t)(hydir_result_{address:x} == 0);\n  state->sf = (uint8_t)((({signed_type})hydir_result_{address:x}) < 0);\n  state->pf = hydir_parity8(hydir_result_{address:x});\n"
    ));
    match (family, count) {
        ("shl", _) => output.push_str(&format!(
            "  state->cf = (uint8_t)((hydir_lhs_{address:x} >> {}) & 1U);\n",
            width - count
        )),
        ("shr" | "sar", _) => output.push_str(&format!(
            "  state->cf = (uint8_t)((hydir_lhs_{address:x} >> {}) & 1U);\n",
            count - 1
        )),
        _ => unreachable!(),
    }
    if count == 1 {
        match family {
            "shl" => output.push_str(&format!(
                "  state->of = (uint8_t)(((hydir_result_{address:x} >> {sign_bit}) & 1U) ^ state->cf);\n"
            )),
            "shr" => output.push_str(&format!(
                "  state->of = (uint8_t)((hydir_lhs_{address:x} >> {sign_bit}) & 1U);\n"
            )),
            "sar" => output.push_str("  state->of = 0;\n"),
            _ => unreachable!(),
        }
    }
    Ok(())
}

fn emit_shift_operation(
    output: &mut String,
    address: u64,
    family: &str,
    destination: &MachineOperand,
    count: &MachineOperand,
) -> Result<(), String> {
    if matches!(count, MachineOperand::Immediate { .. }) {
        emit_immediate_shift_operation(output, address, family, destination, count)
    } else {
        emit_variable_shift_operation(output, address, family, destination, count)
    }
}

fn emit_variable_shift_operation(
    output: &mut String,
    address: u64,
    family: &str,
    destination: &MachineOperand,
    count: &MachineOperand,
) -> Result<(), String> {
    let width = operand_width(destination)?;
    if !matches!(width, 8 | 16 | 32 | 64) || operand_width(count)? != 8 {
        return Err(format!(
            "native variable shift operands are invalid at 0x{address:x}"
        ));
    }
    let (c_type, signed_type) = integer_types(width)?;
    let value = read_operand(destination)?;
    let count_value = read_operand(count)?;
    let count_mask = if width == 64 { 63 } else { 31 };
    let sign_bit = width - 1;
    output.push_str(&format!(
        "  {c_type} hydir_lhs_{address:x} = ({c_type})({value});\n  unsigned hydir_count_{address:x} = (unsigned)({count_value}) & {count_mask}U;\n  if (hydir_count_{address:x} != 0U) {{\n    {c_type} hydir_result_{address:x};\n    if (hydir_count_{address:x} >= {width}U) {{\n      hydir_result_{address:x} = ({c_type})hydir_undefined_value(state, UINT64_C(0x{address:x}), \"{family}_overshift_result\", {width}U);\n      state->cf = hydir_undefined_flag(state, UINT64_C(0x{address:x}), \"cf\");\n      state->of = hydir_undefined_flag(state, UINT64_C(0x{address:x}), \"of\");\n    }} else {{\n"
    ));
    match family {
        "shl" => output.push_str(&format!(
            "      hydir_result_{address:x} = ({c_type})(hydir_lhs_{address:x} << hydir_count_{address:x});\n      state->cf = (uint8_t)((hydir_lhs_{address:x} >> ({width}U - hydir_count_{address:x})) & 1U);\n"
        )),
        "shr" => output.push_str(&format!(
            "      hydir_result_{address:x} = ({c_type})(hydir_lhs_{address:x} >> hydir_count_{address:x});\n      state->cf = (uint8_t)((hydir_lhs_{address:x} >> (hydir_count_{address:x} - 1U)) & 1U);\n"
        )),
        "sar" => output.push_str(&format!(
            "      hydir_result_{address:x} = ({c_type})((hydir_lhs_{address:x} >> hydir_count_{address:x}) | (((hydir_lhs_{address:x} >> {sign_bit}U) & 1U) != 0U ? ((~({c_type})0U) << ({width}U - hydir_count_{address:x})) : ({c_type})0U));\n      state->cf = (uint8_t)((hydir_lhs_{address:x} >> (hydir_count_{address:x} - 1U)) & 1U);\n"
        )),
        _ => return Err(format!("unknown variable shift family {family}")),
    }
    output.push_str(&format!("      if (hydir_count_{address:x} == 1U) {{\n"));
    match family {
        "shl" => output.push_str(&format!(
            "        state->of = (uint8_t)(((hydir_result_{address:x} >> {sign_bit}U) & 1U) ^ state->cf);\n"
        )),
        "shr" => output.push_str(&format!(
            "        state->of = (uint8_t)((hydir_lhs_{address:x} >> {sign_bit}U) & 1U);\n"
        )),
        "sar" => output.push_str("        state->of = 0U;\n"),
        _ => unreachable!(),
    }
    output.push_str(&format!(
        "      }} else {{\n        state->of = hydir_undefined_flag(state, UINT64_C(0x{address:x}), \"of\");\n      }}\n    }}\n"
    ));
    let mut assignment = String::new();
    write_operand(
        &mut assignment,
        destination,
        &format!("hydir_result_{address:x}"),
    )?;
    for line in assignment.lines() {
        output.push_str("  ");
        output.push_str(line);
        output.push('\n');
    }
    output.push_str(&format!(
        "    state->zf = (uint8_t)(hydir_result_{address:x} == 0);\n    state->sf = (uint8_t)((({signed_type})hydir_result_{address:x}) < 0);\n    state->pf = hydir_parity8(hydir_result_{address:x});\n    state->af = hydir_undefined_flag(state, UINT64_C(0x{address:x}), \"af\");\n"
    ));
    output.push_str("  }\n");
    Ok(())
}

fn emit_double_shift_operation(
    output: &mut String,
    address: u64,
    family: &str,
    destination: &MachineOperand,
    source: &MachineOperand,
    count: &MachineOperand,
) -> Result<(), String> {
    let width = operand_width(destination)?;
    if !matches!(width, 32 | 64)
        || operand_width(source)? != width
        || !matches!(source, MachineOperand::Register { .. })
    {
        return Err(format!(
            "native double shift operands are invalid at 0x{address:x}"
        ));
    }
    let variable_count = matches!(count, MachineOperand::Register { width_bits: 8, .. });
    let count_value = match count {
        MachineOperand::Immediate { value, .. } if (*value & u64::from(width - 1)) != 0 => {
            format!("{}U", *value & u64::from(width - 1))
        }
        MachineOperand::Register { width_bits: 8, .. } => {
            format!("((unsigned)({}) & {}U)", read_operand(count)?, width - 1)
        }
        _ => {
            return Err(format!(
                "native double shift count is invalid at 0x{address:x}"
            ));
        }
    };
    let (c_type, signed_type) = integer_types(width)?;
    let destination_value = read_operand(destination)?;
    let source_value = read_operand(source)?;
    let sign_bit = width - 1;
    output.push_str(&format!(
        "  {c_type} hydir_lhs_{address:x} = ({c_type})({destination_value});\n  {c_type} hydir_rhs_{address:x} = ({c_type})({source_value});\n  unsigned hydir_count_{address:x} = {count_value};\n  if (hydir_count_{address:x} != 0U) {{\n    {c_type} hydir_result_{address:x};\n"
    ));
    match family {
        "shld" => output.push_str(&format!(
            "    hydir_result_{address:x} = ({c_type})((hydir_lhs_{address:x} << hydir_count_{address:x}) | (hydir_rhs_{address:x} >> ({width}U - hydir_count_{address:x})));\n"
        )),
        "shrd" => output.push_str(&format!(
            "    hydir_result_{address:x} = ({c_type})((hydir_lhs_{address:x} >> hydir_count_{address:x}) | (hydir_rhs_{address:x} << ({width}U - hydir_count_{address:x})));\n"
        )),
        _ => return Err(format!("unknown double shift family {family}")),
    }
    let mut assignment = String::new();
    write_operand(
        &mut assignment,
        destination,
        &format!("hydir_result_{address:x}"),
    )?;
    for line in assignment.lines() {
        output.push_str("  ");
        output.push_str(line);
        output.push('\n');
    }
    output.push_str(&format!(
        "    state->zf = (uint8_t)(hydir_result_{address:x} == 0);\n    state->sf = (uint8_t)((({signed_type})hydir_result_{address:x}) < 0);\n    state->pf = hydir_parity8(hydir_result_{address:x});\n    state->af = hydir_undefined_flag(state, UINT64_C(0x{address:x}), \"af\");\n"
    ));
    match family {
        "shld" => output.push_str(&format!(
            "    state->cf = (uint8_t)((hydir_lhs_{address:x} >> ({width}U - hydir_count_{address:x})) & 1U);\n"
        )),
        "shrd" => output.push_str(&format!(
            "    state->cf = (uint8_t)((hydir_lhs_{address:x} >> (hydir_count_{address:x} - 1U)) & 1U);\n"
        )),
        _ => unreachable!(),
    }
    output.push_str(&format!("    if (hydir_count_{address:x} == 1U) {{\n"));
    if family == "shld" {
        output.push_str(&format!(
            "      state->of = (uint8_t)(((hydir_result_{address:x} >> {sign_bit}U) & 1U) ^ state->cf);\n"
        ));
    } else {
        output.push_str(&format!(
            "      state->of = (uint8_t)(((hydir_lhs_{address:x} >> {sign_bit}U) & 1U) ^ ((hydir_result_{address:x} >> {sign_bit}U) & 1U));\n"
        ));
    }
    if variable_count {
        output.push_str(&format!(
            "    }} else {{\n      state->of = hydir_undefined_flag(state, UINT64_C(0x{address:x}), \"of\");\n"
        ));
    }
    output.push_str("    }\n  }\n");
    Ok(())
}

fn emit_flagless_shift_operation(
    output: &mut String,
    address: u64,
    family: &str,
    destination: &MachineOperand,
    source: &MachineOperand,
    count: &MachineOperand,
) -> Result<(), String> {
    let width = operand_width(destination)?;
    if !matches!(width, 32 | 64)
        || !matches!(destination, MachineOperand::Register { .. })
        || operand_width(source)? != width
    {
        return Err(format!(
            "native flagless shift operands are invalid at 0x{address:x}"
        ));
    }
    let (c_type, _) = integer_types(width)?;
    let source_value = read_operand(source)?;
    let count_value = read_operand(count)?;
    output.push_str(&format!(
        "  {c_type} hydir_lhs_{address:x} = ({c_type})({source_value});\n  unsigned hydir_count_{address:x} = (unsigned)({count_value}) & {}U;\n  {c_type} hydir_result_{address:x};\n",
        width - 1
    ));
    match family {
        "shlx" => output.push_str(&format!(
            "  hydir_result_{address:x} = ({c_type})(hydir_lhs_{address:x} << hydir_count_{address:x});\n"
        )),
        "shrx" => output.push_str(&format!(
            "  hydir_result_{address:x} = ({c_type})(hydir_lhs_{address:x} >> hydir_count_{address:x});\n"
        )),
        "sarx" => output.push_str(&format!(
            "  hydir_result_{address:x} = hydir_count_{address:x} == 0U ? hydir_lhs_{address:x} : ({c_type})((hydir_lhs_{address:x} >> hydir_count_{address:x}) | ((((hydir_lhs_{address:x} >> {}U) & 1U) != 0U) ? ((~({c_type})0U) << ({width}U - hydir_count_{address:x})) : ({c_type})0U));\n",
            width - 1
        )),
        "rorx" => output.push_str(&format!(
            "  hydir_result_{address:x} = hydir_count_{address:x} == 0U ? hydir_lhs_{address:x} : ({c_type})((hydir_lhs_{address:x} >> hydir_count_{address:x}) | (hydir_lhs_{address:x} << ({width}U - hydir_count_{address:x})));\n"
        )),
        _ => return Err(format!("unknown flagless shift family {family}")),
    }
    write_operand(output, destination, &format!("hydir_result_{address:x}"))
}

fn emit_bmi2_permutation(
    output: &mut String,
    address: u64,
    family: &str,
    destination: &MachineOperand,
    source: &MachineOperand,
    mask: &MachineOperand,
) -> Result<(), String> {
    let width = operand_width(destination)?;
    if !matches!(width, 32 | 64)
        || !matches!(destination, MachineOperand::Register { .. })
        || operand_width(source)? != width
        || operand_width(mask)? != width
    {
        return Err(format!(
            "native BMI2 permutation operands are invalid at 0x{address:x}"
        ));
    }
    let (c_type, _) = integer_types(width)?;
    let source_value = read_operand(source)?;
    let mask_value = read_operand(mask)?;
    output.push_str(&format!(
        "  {c_type} hydir_source_{address:x} = ({c_type})({source_value});\n  {c_type} hydir_mask_{address:x} = ({c_type})({mask_value});\n  {c_type} hydir_result_{address:x} = 0U;\n  {c_type} hydir_source_bit_{address:x} = 1U;\n"
    ));
    match family {
        "pdep" => output.push_str(&format!(
            "  while (hydir_mask_{address:x} != 0U) {{\n    {c_type} hydir_lowest_{address:x} = ({c_type})(hydir_mask_{address:x} & ({c_type})(0U - hydir_mask_{address:x}));\n    if ((hydir_source_{address:x} & hydir_source_bit_{address:x}) != 0U) hydir_result_{address:x} |= hydir_lowest_{address:x};\n    hydir_mask_{address:x} &= ({c_type})(hydir_mask_{address:x} - 1U);\n    hydir_source_bit_{address:x} <<= 1U;\n  }}\n"
        )),
        "pext" => output.push_str(&format!(
            "  while (hydir_mask_{address:x} != 0U) {{\n    {c_type} hydir_lowest_{address:x} = ({c_type})(hydir_mask_{address:x} & ({c_type})(0U - hydir_mask_{address:x}));\n    if ((hydir_source_{address:x} & hydir_lowest_{address:x}) != 0U) hydir_result_{address:x} |= hydir_source_bit_{address:x};\n    hydir_mask_{address:x} &= ({c_type})(hydir_mask_{address:x} - 1U);\n    hydir_source_bit_{address:x} <<= 1U;\n  }}\n"
        )),
        _ => return Err(format!("unknown BMI2 permutation family {family}")),
    }
    write_operand(output, destination, &format!("hydir_result_{address:x}"))
}

fn emit_rotate_operation(
    output: &mut String,
    address: u64,
    family: &str,
    destination: &MachineOperand,
    count: &MachineOperand,
) -> Result<(), String> {
    if matches!(count, MachineOperand::Immediate { .. }) {
        emit_immediate_rotate_operation(output, address, family, destination, count)
    } else {
        emit_variable_rotate_operation(output, address, family, destination, count)
    }
}

fn emit_variable_rotate_operation(
    output: &mut String,
    address: u64,
    family: &str,
    destination: &MachineOperand,
    count: &MachineOperand,
) -> Result<(), String> {
    let width = operand_width(destination)?;
    if !matches!(width, 8 | 16 | 32 | 64) || operand_width(count)? != 8 {
        return Err(format!(
            "native variable rotate operands are invalid at 0x{address:x}"
        ));
    }
    let (c_type, _) = integer_types(width)?;
    let value = read_operand(destination)?;
    let count_value = read_operand(count)?;
    let mask = if width == 64 { 63 } else { 31 };
    output.push_str(&format!(
        "  {c_type} hydir_lhs_{address:x} = ({c_type})({value});\n  unsigned hydir_count_{address:x} = ((unsigned)({count_value}) & {mask}U) % {width}U;\n  if (hydir_count_{address:x} != 0U) {{\n    {c_type} hydir_result_{address:x} = ({c_type})("
    ));
    match family {
        "rol" => output.push_str(&format!(
            "(hydir_lhs_{address:x} << hydir_count_{address:x}) | (hydir_lhs_{address:x} >> ({width}U - hydir_count_{address:x}))"
        )),
        "ror" => output.push_str(&format!(
            "(hydir_lhs_{address:x} >> hydir_count_{address:x}) | (hydir_lhs_{address:x} << ({width}U - hydir_count_{address:x}))"
        )),
        _ => return Err(format!("unknown variable rotate family {family}")),
    }
    output.push_str(");\n");
    let mut assignment = String::new();
    write_operand(
        &mut assignment,
        destination,
        &format!("hydir_result_{address:x}"),
    )?;
    for line in assignment.lines() {
        output.push_str("  ");
        output.push_str(line);
        output.push('\n');
    }
    let sign_bit = width - 1;
    if family == "rol" {
        output.push_str(&format!(
            "    state->cf = (uint8_t)(hydir_result_{address:x} & 1U);\n"
        ));
    } else {
        output.push_str(&format!(
            "    state->cf = (uint8_t)((hydir_result_{address:x} >> {sign_bit}U) & 1U);\n"
        ));
    }
    output.push_str(&format!("    if (hydir_count_{address:x} == 1U) {{\n"));
    if family == "rol" {
        output.push_str(&format!(
            "      state->of = (uint8_t)(((hydir_result_{address:x} >> {sign_bit}U) & 1U) ^ state->cf);\n"
        ));
    } else {
        output.push_str(&format!(
            "      state->of = (uint8_t)(((hydir_result_{address:x} >> {sign_bit}U) & 1U) ^ ((hydir_result_{address:x} >> {}U) & 1U));\n",
            sign_bit - 1
        ));
    }
    output.push_str(&format!(
        "    }} else {{\n      state->of = hydir_undefined_flag(state, UINT64_C(0x{address:x}), \"of\");\n    }}\n  }}\n"
    ));
    Ok(())
}

fn emit_immediate_rotate_operation(
    output: &mut String,
    address: u64,
    family: &str,
    destination: &MachineOperand,
    count: &MachineOperand,
) -> Result<(), String> {
    let MachineOperand::Immediate {
        value: raw_count, ..
    } = count
    else {
        return Err(format!(
            "native exact rotate requires an immediate count at 0x{address:x}"
        ));
    };
    let width = operand_width(destination)?;
    let count = u16::try_from(*raw_count % u64::from(width))
        .map_err(|_| format!("native rotate count overflows at 0x{address:x}"))?;
    if count == 0 {
        return Err(format!(
            "native exact rotate has an effective zero count at 0x{address:x}"
        ));
    }
    let (c_type, _) = integer_types(width)?;
    let value = read_operand(destination)?;
    let expression = match family {
        "rol" => format!(
            "({c_type})((hydir_lhs_{address:x} << {count}U) | (hydir_lhs_{address:x} >> {}U))",
            width - count
        ),
        "ror" => format!(
            "({c_type})((hydir_lhs_{address:x} >> {count}U) | (hydir_lhs_{address:x} << {}U))",
            width - count
        ),
        _ => unreachable!(),
    };
    output.push_str(&format!(
        "  {c_type} hydir_lhs_{address:x} = ({c_type})({value});\n  {c_type} hydir_result_{address:x} = {expression};\n"
    ));
    write_operand(output, destination, &format!("hydir_result_{address:x}"))?;
    let sign_bit = width - 1;
    match family {
        "rol" => output.push_str(&format!(
            "  state->cf = (uint8_t)(hydir_result_{address:x} & 1U);\n"
        )),
        "ror" => output.push_str(&format!(
            "  state->cf = (uint8_t)((hydir_result_{address:x} >> {sign_bit}) & 1U);\n"
        )),
        _ => unreachable!(),
    }
    if count == 1 {
        if family == "rol" {
            output.push_str(&format!(
                "  state->of = (uint8_t)(((hydir_result_{address:x} >> {sign_bit}) & 1U) ^ state->cf);\n"
            ));
        } else {
            output.push_str(&format!(
                "  state->of = (uint8_t)(((hydir_result_{address:x} >> {sign_bit}) & 1U) ^ ((hydir_result_{address:x} >> {}) & 1U));\n",
                sign_bit - 1
            ));
        }
    }
    Ok(())
}

fn emit_rotate_through_carry_operation(
    output: &mut String,
    address: u64,
    family: &str,
    destination: &MachineOperand,
    count: &MachineOperand,
) -> Result<(), String> {
    let width = operand_width(destination)?;
    if !matches!(width, 8 | 16 | 32 | 64)
        || !matches!(
            count,
            MachineOperand::Immediate { .. } | MachineOperand::Register { width_bits: 8, .. }
        )
    {
        return Err(format!(
            "native rotate-through-carry operands are invalid at 0x{address:x}"
        ));
    }
    let (c_type, _) = integer_types(width)?;
    let value = read_operand(destination)?;
    let count_value = read_operand(count)?;
    let count_mask = if width == 64 { 63 } else { 31 };
    let reduction = if width < 32 {
        format!(" % {}U", width + 1)
    } else {
        String::new()
    };
    output.push_str(&format!(
        "  {c_type} hydir_rotate_lhs_{address:x} = ({c_type})({value});\n  unsigned hydir_rotate_count_{address:x} = ((unsigned)({count_value}) & {count_mask}U){reduction};\n  if (hydir_rotate_count_{address:x} != 0U) {{\n    {c_type} hydir_rotate_result_{address:x} = hydir_rotate_lhs_{address:x};\n    uint8_t hydir_rotate_carry_{address:x} = (uint8_t)(state->cf & 1U);\n    for (unsigned hydir_rotate_i_{address:x} = 0U; hydir_rotate_i_{address:x} < hydir_rotate_count_{address:x}; ++hydir_rotate_i_{address:x}) {{\n"
    ));
    match family {
        "rcr" => output.push_str(&format!(
            "      uint8_t hydir_rotate_next_carry_{address:x} = (uint8_t)(hydir_rotate_result_{address:x} & 1U);\n      hydir_rotate_result_{address:x} = ({c_type})((hydir_rotate_result_{address:x} >> 1U) | (({c_type})hydir_rotate_carry_{address:x} << {}U));\n      hydir_rotate_carry_{address:x} = hydir_rotate_next_carry_{address:x};\n",
            width - 1
        )),
        "rcl" => output.push_str(&format!(
            "      uint8_t hydir_rotate_next_carry_{address:x} = (uint8_t)((hydir_rotate_result_{address:x} >> {}U) & 1U);\n      hydir_rotate_result_{address:x} = ({c_type})((hydir_rotate_result_{address:x} << 1U) | hydir_rotate_carry_{address:x});\n      hydir_rotate_carry_{address:x} = hydir_rotate_next_carry_{address:x};\n",
            width - 1
        )),
        _ => return Err(format!("unknown rotate-through-carry family {family}")),
    }
    output.push_str("    }\n");
    let mut assignment = String::new();
    write_operand(
        &mut assignment,
        destination,
        &format!("hydir_rotate_result_{address:x}"),
    )?;
    for line in assignment.lines() {
        output.push_str("  ");
        output.push_str(line);
        output.push('\n');
    }
    output.push_str(&format!(
        "    state->cf = hydir_rotate_carry_{address:x};\n    if (hydir_rotate_count_{address:x} == 1U) {{\n"
    ));
    if family == "rcr" {
        output.push_str(&format!(
            "      state->of = (uint8_t)(((hydir_rotate_result_{address:x} >> {}U) ^ (hydir_rotate_result_{address:x} >> {}U)) & 1U);\n",
            width - 1,
            width - 2
        ));
    } else {
        output.push_str(&format!(
            "      state->of = (uint8_t)(((hydir_rotate_result_{address:x} >> {}U) & 1U) ^ state->cf);\n",
            width - 1
        ));
    }
    output.push_str(&format!(
        "    }} else {{\n      state->of = hydir_undefined_flag(state, UINT64_C(0x{address:x}), \"of\");\n    }}\n  }}\n"
    ));
    Ok(())
}

fn emit_register_exchange(
    output: &mut String,
    address: u64,
    left: &MachineOperand,
    right: &MachineOperand,
) -> Result<(), String> {
    let width = operand_width(left)?;
    if operand_width(right)? != width
        || !matches!(left, MachineOperand::Register { .. })
        || !matches!(right, MachineOperand::Register { .. })
    {
        return Err(format!(
            "native exact xchg requires equally sized registers at 0x{address:x}"
        ));
    }
    let (c_type, _) = integer_types(width)?;
    let left_value = read_operand(left)?;
    let right_value = read_operand(right)?;
    output.push_str(&format!(
        "  {c_type} hydir_left_{address:x} = ({c_type})({left_value});\n  {c_type} hydir_right_{address:x} = ({c_type})({right_value});\n"
    ));
    write_operand(output, left, &format!("hydir_right_{address:x}"))?;
    write_operand(output, right, &format!("hydir_left_{address:x}"))
}

fn emit_bit_scan_operation(
    output: &mut String,
    address: u64,
    family: &str,
    destination: &MachineOperand,
    source: &MachineOperand,
) -> Result<(), String> {
    let width = operand_width(destination)?;
    if !matches!(width, 16 | 32 | 64)
        || operand_width(source)? != width
        || !matches!(destination, MachineOperand::Register { .. })
    {
        return Err(format!(
            "native {family} operands are invalid at 0x{address:x}"
        ));
    }
    let value = read_operand(source)?;
    output.push_str(&format!(
        "  uint64_t hydir_scan_source_{address:x} = (uint{width}_t)({value});\n  uint64_t hydir_scan_result_{address:x};\n  state->zf = (uint8_t)(hydir_scan_source_{address:x} == 0U);\n  if (state->zf != 0U) {{\n    hydir_scan_result_{address:x} = hydir_undefined_value(state, UINT64_C(0x{address:x}), \"{family}_destination\", {width}U);\n  }} else {{\n"
    ));
    let expression = if family == "bsf" {
        format!("hydir_tzcnt64(hydir_scan_source_{address:x}, {width}U)")
    } else {
        format!(
            "UINT64_C({}) - hydir_lzcnt64(hydir_scan_source_{address:x}, {width}U)",
            width - 1
        )
    };
    output.push_str(&format!(
        "    hydir_scan_result_{address:x} = {expression};\n  }}\n"
    ));
    write_operand(
        output,
        destination,
        &format!("hydir_scan_result_{address:x}"),
    )
}

fn emit_register_bit_test_operation(
    output: &mut String,
    address: u64,
    family: &str,
    destination: &MachineOperand,
    bit_index: &MachineOperand,
) -> Result<(), String> {
    let width = operand_width(destination)?;
    if !matches!(width, 16 | 32 | 64)
        || !matches!(destination, MachineOperand::Register { .. })
        || !matches!(
            bit_index,
            MachineOperand::Register { .. } | MachineOperand::Immediate { .. }
        )
        || (matches!(bit_index, MachineOperand::Register { .. })
            && operand_width(bit_index)? != width)
    {
        return Err(format!(
            "native {family} register bit-test operands are invalid at 0x{address:x}"
        ));
    }
    let destination_value = read_operand(destination)?;
    let index_value = read_operand(bit_index)?;
    let (c_type, _) = integer_types(width)?;
    output.push_str(&format!(
        "  {c_type} hydir_bit_base_{address:x} = ({c_type})({destination_value});\n  unsigned hydir_bit_index_{address:x} = (unsigned)((uint64_t)({index_value}) & UINT64_C({}));\n  state->cf = (uint8_t)((hydir_bit_base_{address:x} >> hydir_bit_index_{address:x}) & 1U);\n",
        width - 1
    ));
    if family == "bt" {
        return Ok(());
    }
    output.push_str(&format!(
        "  {c_type} hydir_bit_mask_{address:x} = ({c_type})(({c_type})1U << hydir_bit_index_{address:x});\n"
    ));
    let result = match family {
        "bts" => format!("hydir_bit_base_{address:x} | hydir_bit_mask_{address:x}"),
        "btr" => format!("hydir_bit_base_{address:x} & ({c_type})~hydir_bit_mask_{address:x}"),
        "btc" => format!("hydir_bit_base_{address:x} ^ hydir_bit_mask_{address:x}"),
        _ => return Err(format!("unknown native bit-test operation {family}")),
    };
    write_operand(output, destination, &result)
}

fn emit_bit_count_operation(
    output: &mut String,
    address: u64,
    family: &str,
    destination: &MachineOperand,
    source: &MachineOperand,
) -> Result<(), String> {
    let width = operand_width(destination)?;
    if !matches!(width, 16 | 32 | 64)
        || operand_width(source)? != width
        || !matches!(destination, MachineOperand::Register { .. })
    {
        return Err(format!(
            "native {family} operands are invalid at 0x{address:x}"
        ));
    }
    let value = read_operand(source)?;
    let helper = match family {
        "popcnt" => "hydir_popcount64",
        "lzcnt" => "hydir_lzcnt64",
        "tzcnt" => "hydir_tzcnt64",
        _ => return Err(format!("unknown native bit-count operation {family}")),
    };
    output.push_str(&format!(
        "  uint64_t hydir_count_source_{address:x} = (uint{width}_t)({value});\n  uint64_t hydir_count_result_{address:x} = {helper}(hydir_count_source_{address:x}{});\n",
        if family == "popcnt" {
            String::new()
        } else {
            format!(", {width}U")
        }
    ));
    write_operand(
        output,
        destination,
        &format!("hydir_count_result_{address:x}"),
    )?;
    if family == "popcnt" {
        output.push_str(&format!(
            "  state->zf = (uint8_t)(hydir_count_source_{address:x} == 0U);\n  state->sf = 0U;\n  state->of = 0U;\n  state->cf = 0U;\n  state->pf = 0U;\n  state->af = 0U;\n"
        ));
    } else {
        output.push_str(&format!(
            "  state->zf = (uint8_t)(hydir_count_result_{address:x} == 0U);\n  state->cf = (uint8_t)(hydir_count_source_{address:x} == 0U);\n"
        ));
    }
    Ok(())
}

fn emit_bswap_operation(
    output: &mut String,
    address: u64,
    destination: &MachineOperand,
) -> Result<(), String> {
    let width = operand_width(destination)?;
    if !matches!(width, 32 | 64) || !matches!(destination, MachineOperand::Register { .. }) {
        return Err(format!(
            "native exact bswap requires a 32- or 64-bit register at 0x{address:x}"
        ));
    }
    let (c_type, _) = integer_types(width)?;
    let value = read_operand(destination)?;
    output.push_str(&format!(
        "  {c_type} hydir_lhs_{address:x} = ({c_type})({value});\n"
    ));
    let expression = if width == 32 {
        format!(
            "((hydir_lhs_{address:x} & UINT32_C(0x000000ff)) << 24U) | ((hydir_lhs_{address:x} & UINT32_C(0x0000ff00)) << 8U) | ((hydir_lhs_{address:x} & UINT32_C(0x00ff0000)) >> 8U) | ((hydir_lhs_{address:x} & UINT32_C(0xff000000)) >> 24U)"
        )
    } else {
        format!(
            "((hydir_lhs_{address:x} & UINT64_C(0x00000000000000ff)) << 56U) | ((hydir_lhs_{address:x} & UINT64_C(0x000000000000ff00)) << 40U) | ((hydir_lhs_{address:x} & UINT64_C(0x0000000000ff0000)) << 24U) | ((hydir_lhs_{address:x} & UINT64_C(0x00000000ff000000)) << 8U) | ((hydir_lhs_{address:x} & UINT64_C(0x000000ff00000000)) >> 8U) | ((hydir_lhs_{address:x} & UINT64_C(0x0000ff0000000000)) >> 24U) | ((hydir_lhs_{address:x} & UINT64_C(0x00ff000000000000)) >> 40U) | ((hydir_lhs_{address:x} & UINT64_C(0xff00000000000000)) >> 56U)"
        )
    };
    write_operand(output, destination, &format!("({c_type})({expression})"))
}

fn emit_full_multiply_operation(
    output: &mut String,
    address: u64,
    source: &MachineOperand,
    signed: bool,
) -> Result<(), String> {
    let width = operand_width(source)?;
    if !matches!(width, 8 | 16 | 32 | 64) {
        return Err(format!(
            "native full-width multiply has unsupported width {width} at 0x{address:x}"
        ));
    }
    let value = read_operand(source)?;
    let (unsigned_type, signed_type) = integer_types(width)?;
    output.push_str(&format!(
        "  {unsigned_type} hydir_mul_source_bits_{address:x} = ({unsigned_type})({value});\n"
    ));
    if !signed {
        match width {
            8 => output.push_str(&format!(
                "  uint16_t hydir_product_{address:x} = (uint16_t)(uint8_t)state->rax * hydir_mul_source_bits_{address:x};\n  state->rax = (state->rax & ~UINT64_C(0xffff)) | hydir_product_{address:x};\n  state->cf = (uint8_t)((hydir_product_{address:x} >> 8U) != 0U);\n"
            )),
            16 => output.push_str(&format!(
                "  uint32_t hydir_product_{address:x} = (uint32_t)(uint16_t)state->rax * hydir_mul_source_bits_{address:x};\n  state->rax = (state->rax & ~UINT64_C(0xffff)) | (uint16_t)hydir_product_{address:x};\n  state->rdx = (state->rdx & ~UINT64_C(0xffff)) | (uint16_t)(hydir_product_{address:x} >> 16U);\n  state->cf = (uint8_t)((hydir_product_{address:x} >> 16U) != 0U);\n"
            )),
            32 => output.push_str(&format!(
                "  uint64_t hydir_product_{address:x} = (uint64_t)(uint32_t)state->rax * hydir_mul_source_bits_{address:x};\n  state->rax = (uint32_t)hydir_product_{address:x};\n  state->rdx = (uint32_t)(hydir_product_{address:x} >> 32U);\n  state->cf = (uint8_t)((hydir_product_{address:x} >> 32U) != 0U);\n"
            )),
            64 => output.push_str(&format!(
                "  uint64_t hydir_product_high_{address:x} = 0U, hydir_product_low_{address:x} = 0U;\n  hydir_umul64wide(state->rax, hydir_mul_source_bits_{address:x}, &hydir_product_high_{address:x}, &hydir_product_low_{address:x});\n  state->rax = hydir_product_low_{address:x};\n  state->rdx = hydir_product_high_{address:x};\n  state->cf = (uint8_t)(hydir_product_high_{address:x} != 0U);\n"
            )),
            _ => unreachable!(),
        }
        output.push_str("  state->of = state->cf;\n");
        return Ok(());
    }
    if width < 64 {
        let (wide_signed, wide_unsigned, minimum, maximum) = match width {
            8 => ("int16_t", "uint16_t", "INT8_MIN", "INT8_MAX"),
            16 => ("int32_t", "uint32_t", "INT16_MIN", "INT16_MAX"),
            32 => ("int64_t", "uint64_t", "INT32_MIN", "INT32_MAX"),
            _ => unreachable!(),
        };
        output.push_str(&format!(
            "  {signed_type} hydir_mul_source_{address:x};\n  memcpy(&hydir_mul_source_{address:x}, &hydir_mul_source_bits_{address:x}, sizeof(hydir_mul_source_{address:x}));\n  {unsigned_type} hydir_mul_accumulator_bits_{address:x} = ({unsigned_type})state->rax;\n  {signed_type} hydir_mul_accumulator_{address:x};\n  memcpy(&hydir_mul_accumulator_{address:x}, &hydir_mul_accumulator_bits_{address:x}, sizeof(hydir_mul_accumulator_{address:x}));\n  {wide_signed} hydir_product_{address:x} = ({wide_signed})hydir_mul_accumulator_{address:x} * ({wide_signed})hydir_mul_source_{address:x};\n  {wide_unsigned} hydir_product_bits_{address:x};\n  memcpy(&hydir_product_bits_{address:x}, &hydir_product_{address:x}, sizeof(hydir_product_bits_{address:x}));\n"
        ));
        match width {
            8 => output.push_str(&format!(
                "  state->rax = (state->rax & ~UINT64_C(0xffff)) | hydir_product_bits_{address:x};\n"
            )),
            16 => output.push_str(&format!(
                "  state->rax = (state->rax & ~UINT64_C(0xffff)) | (uint16_t)hydir_product_bits_{address:x};\n  state->rdx = (state->rdx & ~UINT64_C(0xffff)) | (uint16_t)(hydir_product_bits_{address:x} >> 16U);\n"
            )),
            32 => output.push_str(&format!(
                "  state->rax = (uint32_t)hydir_product_bits_{address:x};\n  state->rdx = (uint32_t)(hydir_product_bits_{address:x} >> 32U);\n"
            )),
            _ => unreachable!(),
        }
        output.push_str(&format!(
            "  state->cf = (uint8_t)(hydir_product_{address:x} < {minimum} || hydir_product_{address:x} > {maximum});\n  state->of = state->cf;\n"
        ));
        return Ok(());
    }
    output.push_str(&format!(
        "  uint8_t hydir_mul_left_negative_{address:x} = (uint8_t)(state->rax >> 63U);\n  uint8_t hydir_mul_right_negative_{address:x} = (uint8_t)(hydir_mul_source_bits_{address:x} >> 63U);\n  uint64_t hydir_mul_left_magnitude_{address:x} = hydir_mul_left_negative_{address:x} != 0U ? (~state->rax + UINT64_C(1)) : state->rax;\n  uint64_t hydir_mul_right_magnitude_{address:x} = hydir_mul_right_negative_{address:x} != 0U ? (~hydir_mul_source_bits_{address:x} + UINT64_C(1)) : hydir_mul_source_bits_{address:x};\n  uint64_t hydir_product_high_{address:x} = 0U, hydir_product_low_{address:x} = 0U;\n  hydir_umul64wide(hydir_mul_left_magnitude_{address:x}, hydir_mul_right_magnitude_{address:x}, &hydir_product_high_{address:x}, &hydir_product_low_{address:x});\n  if ((hydir_mul_left_negative_{address:x} ^ hydir_mul_right_negative_{address:x}) != 0U) {{ hydir_product_low_{address:x} = ~hydir_product_low_{address:x} + UINT64_C(1); hydir_product_high_{address:x} = ~hydir_product_high_{address:x} + (hydir_product_low_{address:x} == 0U ? UINT64_C(1) : UINT64_C(0)); }}\n  state->rax = hydir_product_low_{address:x};\n  state->rdx = hydir_product_high_{address:x};\n  state->cf = (uint8_t)(hydir_product_high_{address:x} != ((hydir_product_low_{address:x} >> 63U) != 0U ? UINT64_MAX : UINT64_C(0)));\n  state->of = state->cf;\n"
    ));
    Ok(())
}

fn emit_imul_operation(
    output: &mut String,
    address: u64,
    operands: &[MachineOperand],
) -> Result<(), String> {
    let destination = &operands[0];
    let width = operand_width(destination)?;
    if !matches!(width, 16 | 32 | 64) || !matches!(destination, MachineOperand::Register { .. }) {
        return Err(format!(
            "native exact imul requires a 16-, 32-, or 64-bit destination register at 0x{address:x}"
        ));
    }
    let (left, right) = if operands.len() == 2 {
        (read_operand(destination)?, read_operand(&operands[1])?)
    } else {
        (read_operand(&operands[1])?, read_operand(&operands[2])?)
    };
    let (c_type, _) = integer_types(width)?;
    output.push_str(&format!(
        "  {c_type} hydir_lhs_{address:x} = ({c_type})({left});\n  {c_type} hydir_rhs_{address:x} = ({c_type})({right});\n  {c_type} hydir_result_{address:x} = ({c_type})(hydir_lhs_{address:x} * hydir_rhs_{address:x});\n"
    ));
    write_operand(output, destination, &format!("hydir_result_{address:x}"))?;
    output.push_str(&format!(
        "  state->cf = hydir_imul_overflow((uint64_t)hydir_lhs_{address:x}, (uint64_t)hydir_rhs_{address:x}, {width}U);\n  state->of = state->cf;\n"
    ));
    Ok(())
}

fn emit_unsigned_divide_operation(
    output: &mut String,
    address: u64,
    divisor: &MachineOperand,
) -> Result<(), String> {
    let width = operand_width(divisor)?;
    if !matches!(width, 8 | 16 | 32 | 64) {
        return Err(format!(
            "native exact div has unsupported width {width} at 0x{address:x}"
        ));
    }
    let value = read_operand(divisor)?;
    let (c_type, _) = integer_types(width)?;
    output.push_str(&format!(
        "  {c_type} hydir_divisor_{address:x} = ({c_type})({value});\n"
    ));
    match width {
        8 => output.push_str(&format!(
            "  uint16_t hydir_dividend_{address:x} = (uint16_t)state->rax;\n  if (hydir_divisor_{address:x} == 0U || (uint16_t)(hydir_dividend_{address:x} / hydir_divisor_{address:x}) > UINT8_MAX) hydir_divide_error(state, UINT64_C(0x{address:x}));\n  uint8_t hydir_quotient_{address:x} = (uint8_t)(hydir_dividend_{address:x} / hydir_divisor_{address:x});\n  uint8_t hydir_remainder_{address:x} = (uint8_t)(hydir_dividend_{address:x} % hydir_divisor_{address:x});\n  state->rax = (state->rax & ~UINT64_C(0xffff)) | (uint64_t)hydir_quotient_{address:x} | ((uint64_t)hydir_remainder_{address:x} << 8U);\n"
        )),
        16 => output.push_str(&format!(
            "  uint32_t hydir_dividend_{address:x} = ((uint32_t)(uint16_t)state->rdx << 16U) | (uint16_t)state->rax;\n  if (hydir_divisor_{address:x} == 0U || hydir_dividend_{address:x} / hydir_divisor_{address:x} > UINT16_MAX) hydir_divide_error(state, UINT64_C(0x{address:x}));\n  uint16_t hydir_quotient_{address:x} = (uint16_t)(hydir_dividend_{address:x} / hydir_divisor_{address:x});\n  uint16_t hydir_remainder_{address:x} = (uint16_t)(hydir_dividend_{address:x} % hydir_divisor_{address:x});\n  state->rax = (state->rax & ~UINT64_C(0xffff)) | (uint64_t)hydir_quotient_{address:x};\n  state->rdx = (state->rdx & ~UINT64_C(0xffff)) | (uint64_t)hydir_remainder_{address:x};\n"
        )),
        32 => output.push_str(&format!(
            "  uint64_t hydir_dividend_{address:x} = ((uint64_t)(uint32_t)state->rdx << 32U) | (uint32_t)state->rax;\n  if (hydir_divisor_{address:x} == 0U || hydir_dividend_{address:x} / hydir_divisor_{address:x} > UINT32_MAX) hydir_divide_error(state, UINT64_C(0x{address:x}));\n  uint32_t hydir_quotient_{address:x} = (uint32_t)(hydir_dividend_{address:x} / hydir_divisor_{address:x});\n  uint32_t hydir_remainder_{address:x} = (uint32_t)(hydir_dividend_{address:x} % hydir_divisor_{address:x});\n  state->rax = hydir_quotient_{address:x};\n  state->rdx = hydir_remainder_{address:x};\n"
        )),
        64 => output.push_str(&format!(
            "  uint64_t hydir_quotient_{address:x} = 0U, hydir_remainder_{address:x} = 0U;\n  if (!hydir_udiv128by64(state->rdx, state->rax, hydir_divisor_{address:x}, &hydir_quotient_{address:x}, &hydir_remainder_{address:x})) hydir_divide_error(state, UINT64_C(0x{address:x}));\n  state->rax = hydir_quotient_{address:x};\n  state->rdx = hydir_remainder_{address:x};\n"
        )),
        _ => unreachable!(),
    }
    Ok(())
}

fn emit_signed_divide_operation(
    output: &mut String,
    address: u64,
    divisor: &MachineOperand,
) -> Result<(), String> {
    let width = operand_width(divisor)?;
    if !matches!(width, 8 | 16 | 32 | 64) {
        return Err(format!(
            "native exact idiv has unsupported width {width} at 0x{address:x}"
        ));
    }
    let value = read_operand(divisor)?;
    let (unsigned_type, signed_type) = integer_types(width)?;
    output.push_str(&format!(
        "  {unsigned_type} hydir_divisor_bits_{address:x} = ({unsigned_type})({value});\n  {signed_type} hydir_divisor_{address:x};\n  memcpy(&hydir_divisor_{address:x}, &hydir_divisor_bits_{address:x}, sizeof(hydir_divisor_{address:x}));\n"
    ));
    match width {
        8 => output.push_str(&format!(
            "  uint16_t hydir_dividend_bits_{address:x} = (uint16_t)state->rax;\n  int16_t hydir_dividend_{address:x};\n  memcpy(&hydir_dividend_{address:x}, &hydir_dividend_bits_{address:x}, sizeof(hydir_dividend_{address:x}));\n  if (hydir_divisor_{address:x} == 0) hydir_divide_error(state, UINT64_C(0x{address:x}));\n  int32_t hydir_quotient_{address:x} = (int32_t)hydir_dividend_{address:x} / (int32_t)hydir_divisor_{address:x};\n  if (hydir_quotient_{address:x} < INT8_MIN || hydir_quotient_{address:x} > INT8_MAX) hydir_divide_error(state, UINT64_C(0x{address:x}));\n  int32_t hydir_remainder_{address:x} = (int32_t)hydir_dividend_{address:x} % (int32_t)hydir_divisor_{address:x};\n  state->rax = (state->rax & ~UINT64_C(0xffff)) | (uint8_t)hydir_quotient_{address:x} | ((uint64_t)(uint8_t)hydir_remainder_{address:x} << 8U);\n"
        )),
        16 => output.push_str(&format!(
            "  uint32_t hydir_dividend_bits_{address:x} = ((uint32_t)(uint16_t)state->rdx << 16U) | (uint16_t)state->rax;\n  int32_t hydir_dividend_{address:x};\n  memcpy(&hydir_dividend_{address:x}, &hydir_dividend_bits_{address:x}, sizeof(hydir_dividend_{address:x}));\n  if (hydir_divisor_{address:x} == 0) hydir_divide_error(state, UINT64_C(0x{address:x}));\n  int64_t hydir_quotient_{address:x} = (int64_t)hydir_dividend_{address:x} / (int64_t)hydir_divisor_{address:x};\n  if (hydir_quotient_{address:x} < INT16_MIN || hydir_quotient_{address:x} > INT16_MAX) hydir_divide_error(state, UINT64_C(0x{address:x}));\n  int64_t hydir_remainder_{address:x} = (int64_t)hydir_dividend_{address:x} % (int64_t)hydir_divisor_{address:x};\n  state->rax = (state->rax & ~UINT64_C(0xffff)) | (uint16_t)hydir_quotient_{address:x};\n  state->rdx = (state->rdx & ~UINT64_C(0xffff)) | (uint16_t)hydir_remainder_{address:x};\n"
        )),
        32 => output.push_str(&format!(
            "  uint64_t hydir_dividend_bits_{address:x} = ((uint64_t)(uint32_t)state->rdx << 32U) | (uint32_t)state->rax;\n  int64_t hydir_dividend_{address:x};\n  memcpy(&hydir_dividend_{address:x}, &hydir_dividend_bits_{address:x}, sizeof(hydir_dividend_{address:x}));\n  if (hydir_divisor_{address:x} == 0 || (hydir_dividend_{address:x} == INT64_MIN && hydir_divisor_{address:x} == -1)) hydir_divide_error(state, UINT64_C(0x{address:x}));\n  int64_t hydir_quotient_{address:x} = hydir_dividend_{address:x} / hydir_divisor_{address:x};\n  if (hydir_quotient_{address:x} < INT32_MIN || hydir_quotient_{address:x} > INT32_MAX) hydir_divide_error(state, UINT64_C(0x{address:x}));\n  int64_t hydir_remainder_{address:x} = hydir_dividend_{address:x} % hydir_divisor_{address:x};\n  state->rax = (uint32_t)hydir_quotient_{address:x};\n  state->rdx = (uint32_t)hydir_remainder_{address:x};\n"
        )),
        64 => output.push_str(&format!(
            "  uint8_t hydir_dividend_negative_{address:x} = (uint8_t)(state->rdx >> 63U);\n  uint8_t hydir_divisor_negative_{address:x} = (uint8_t)(hydir_divisor_bits_{address:x} >> 63U);\n  uint64_t hydir_divisor_magnitude_{address:x} = hydir_divisor_negative_{address:x} != 0U ? (~hydir_divisor_bits_{address:x} + UINT64_C(1)) : hydir_divisor_bits_{address:x};\n  uint64_t hydir_low_magnitude_{address:x} = state->rax;\n  uint64_t hydir_high_magnitude_{address:x} = state->rdx;\n  if (hydir_dividend_negative_{address:x} != 0U) {{ hydir_low_magnitude_{address:x} = ~hydir_low_magnitude_{address:x} + UINT64_C(1); hydir_high_magnitude_{address:x} = ~hydir_high_magnitude_{address:x} + (hydir_low_magnitude_{address:x} == 0U ? UINT64_C(1) : UINT64_C(0)); }}\n  uint64_t hydir_quotient_magnitude_{address:x} = 0U, hydir_remainder_magnitude_{address:x} = 0U;\n  if (!hydir_udiv128by64(hydir_high_magnitude_{address:x}, hydir_low_magnitude_{address:x}, hydir_divisor_magnitude_{address:x}, &hydir_quotient_magnitude_{address:x}, &hydir_remainder_magnitude_{address:x})) hydir_divide_error(state, UINT64_C(0x{address:x}));\n  uint8_t hydir_quotient_negative_{address:x} = (uint8_t)(hydir_dividend_negative_{address:x} ^ hydir_divisor_negative_{address:x});\n  if ((hydir_quotient_negative_{address:x} == 0U && hydir_quotient_magnitude_{address:x} > (uint64_t)INT64_MAX) || (hydir_quotient_negative_{address:x} != 0U && hydir_quotient_magnitude_{address:x} > (UINT64_C(1) << 63U))) hydir_divide_error(state, UINT64_C(0x{address:x}));\n  state->rax = hydir_quotient_negative_{address:x} != 0U ? (~hydir_quotient_magnitude_{address:x} + UINT64_C(1)) : hydir_quotient_magnitude_{address:x};\n  state->rdx = hydir_dividend_negative_{address:x} != 0U ? (~hydir_remainder_magnitude_{address:x} + UINT64_C(1)) : hydir_remainder_magnitude_{address:x};\n"
        )),
        _ => unreachable!(),
    }
    Ok(())
}

fn emit_accumulator_sign_extension(output: &mut String, family: &str) -> Result<(), String> {
    match family {
        "cbw" => output.push_str(
            "  state->rax = (state->rax & ~UINT64_C(0xffff)) | (uint16_t)hydir_sign_extend((uint8_t)state->rax, 8U);\n",
        ),
        "cwde" => output.push_str(
            "  state->rax = (uint32_t)hydir_sign_extend((uint16_t)state->rax, 16U);\n",
        ),
        "cdqe" => output.push_str(
            "  state->rax = hydir_sign_extend((uint32_t)state->rax, 32U);\n",
        ),
        "cwd" => output.push_str(
            "  state->rdx = (state->rdx & ~UINT64_C(0xffff)) | (((state->rax >> 15U) & 1U) != 0U ? UINT64_C(0xffff) : UINT64_C(0));\n",
        ),
        "cdq" => output.push_str(
            "  state->rdx = (uint32_t)((((uint32_t)state->rax >> 31U) & 1U) != 0U ? UINT32_MAX : UINT32_C(0));\n",
        ),
        "cqo" => output.push_str(
            "  state->rdx = ((state->rax >> 63U) & 1U) != 0U ? UINT64_MAX : UINT64_C(0);\n",
        ),
        _ => return Err(format!("unknown accumulator sign extension {family}")),
    }
    Ok(())
}

fn integer_types(width: u16) -> Result<(&'static str, &'static str), String> {
    match width {
        8 => Ok(("uint8_t", "int8_t")),
        16 => Ok(("uint16_t", "int16_t")),
        32 => Ok(("uint32_t", "int32_t")),
        64 => Ok(("uint64_t", "int64_t")),
        _ => Err(format!("unsupported native integer width {width}")),
    }
}

fn operand_width(operand: &MachineOperand) -> Result<u16, String> {
    match operand {
        MachineOperand::Register { width_bits, .. }
        | MachineOperand::Immediate { width_bits, .. }
        | MachineOperand::Memory { width_bits, .. } => Ok(*width_bits),
        MachineOperand::Branch { .. } | MachineOperand::RelocatedBranch { .. } => {
            Err("branch operand has no scalar width".to_owned())
        }
    }
}

fn read_operand(operand: &MachineOperand) -> Result<String, String> {
    match operand {
        MachineOperand::Register { name, width_bits } => match width_bits {
            8 => Ok(format!("(uint8_t)state->{name}")),
            16 => Ok(format!("(uint16_t)state->{name}")),
            32 => Ok(format!("(uint32_t)state->{name}")),
            64 => Ok(format!("state->{name}")),
            width => Err(format!("unsupported native register width {width}")),
        },
        MachineOperand::Immediate { value, width_bits } => match width_bits {
            8 | 16 | 32 | 64 => Ok(format!("UINT64_C(0x{value:x})")),
            width => Err(format!("unsupported native immediate width {width}")),
        },
        operand @ MachineOperand::Memory { width_bits, .. } => {
            let address = memory_address(operand)?;
            match width_bits {
                8 => Ok(format!("hydir_load8({address})")),
                16 => Ok(format!("hydir_load16({address})")),
                32 => Ok(format!("hydir_load32({address})")),
                64 => Ok(format!("hydir_load64({address})")),
                width => Err(format!("unsupported native memory width {width}")),
            }
        }
        MachineOperand::Branch { target } => Ok(format!("UINT64_C(0x{:x})", target.value.0)),
        MachineOperand::RelocatedBranch { target, .. } => Ok(target.map_or_else(
            || "UINT64_C(0) /* unresolved relocated branch */".to_owned(),
            |target| format!("UINT64_C(0x{:x})", target.value.0),
        )),
    }
}

fn write_operand(
    output: &mut String,
    destination: &MachineOperand,
    value: &str,
) -> Result<(), String> {
    match destination {
        MachineOperand::Register { name, width_bits } => match width_bits {
            8 => output.push_str(&format!(
                "  state->{name} = (state->{name} & ~UINT64_C(0xff)) | ((uint8_t)({value}));\n"
            )),
            16 => output.push_str(&format!(
                "  state->{name} = (state->{name} & ~UINT64_C(0xffff)) | ((uint16_t)({value}));\n"
            )),
            32 => output.push_str(&format!("  state->{name} = (uint32_t)({value});\n")),
            64 => output.push_str(&format!("  state->{name} = (uint64_t)({value});\n")),
            width => return Err(format!("unsupported native register write width {width}")),
        },
        destination @ MachineOperand::Memory { width_bits, .. } => {
            let address = memory_address(destination)?;
            match width_bits {
                8 => output.push_str(&format!("  hydir_store8({address}, (uint8_t)({value}));\n")),
                16 => output.push_str(&format!(
                    "  hydir_store16({address}, (uint16_t)({value}));\n"
                )),
                32 => output.push_str(&format!(
                    "  hydir_store32({address}, (uint32_t)({value}));\n"
                )),
                64 => output.push_str(&format!(
                    "  hydir_store64({address}, (uint64_t)({value}));\n"
                )),
                width => return Err(format!("unsupported native memory write width {width}")),
            }
        }
        _ => return Err("native operation has a non-writable destination".to_owned()),
    }
    Ok(())
}

fn memory_address(operand: &MachineOperand) -> Result<String, String> {
    let MachineOperand::Memory {
        segment,
        base,
        index,
        scale,
        displacement,
        absolute,
        ..
    } = operand
    else {
        return Err("expected native memory operand".to_owned());
    };
    let mut expression = absolute.map_or_else(
        || "UINT64_C(0)".to_owned(),
        |value| format!("UINT64_C(0x{value:x})"),
    );
    if let Some(base) = base {
        expression = format!("({expression} + state->{base})");
    }
    if let Some(index) = index {
        expression = format!("({expression} + state->{index} * UINT64_C({scale}))");
    }
    if *displacement != 0 {
        expression = format!("({expression} + (uint64_t)INT64_C({displacement}))");
    }
    if let Some(segment) = segment {
        expression = format!(
            "hydir_segment_address(state, \"{}\", {expression})",
            c_string(segment)
        );
    }
    Ok(expression)
}

fn emit_native_terminator(
    output: &mut String,
    terminator: &CirTerminator,
    labels: &std::collections::BTreeSet<hydir_core::Location>,
) -> Result<(), String> {
    match terminator {
        CirTerminator::Fallthrough { target } | CirTerminator::Goto { target } => {
            emit_target(output, *target, labels)
        }
        CirTerminator::Branch {
            condition,
            taken,
            fallthrough,
        } => {
            let condition = c_condition(condition)?;
            output.push_str(&format!("  if ({condition}) {{\n"));
            emit_target_indented(output, *taken, labels, "    ");
            output.push_str("  } else {\n");
            emit_target_indented(output, *fallthrough, labels, "    ");
            output.push_str("  }\n");
            Ok(())
        }
        CirTerminator::Call {
            target,
            target_operand,
            next,
        } => {
            if let Some(target) = target {
                output.push_str(&format!(
                    "  hydir_call(state, UINT64_C(0x{:x}));\n",
                    target.value.0
                ));
            } else if let Some(target_operand) = target_operand {
                output.push_str(&format!(
                    "  /* unresolved indirect call target */\n  hydir_unknown_call(state, (uint64_t)({}));\n",
                    read_operand(target_operand)?
                ));
            } else {
                output.push_str(
                    "  /* unresolved call target */\n  hydir_unknown_call(state, UINT64_C(0));\n",
                );
            }
            if let Some(next) = next {
                emit_target(output, *next, labels)
            } else {
                output.push_str("  return;\n");
                Ok(())
            }
        }
        CirTerminator::Switch {
            dispatch,
            targets,
            unresolved_default,
        } => {
            output.push_str(&format!(
                "  switch (hydir_indirect_target(state, UINT64_C(0x{:x}))) {{\n",
                dispatch.value.0
            ));
            for target in targets {
                output.push_str(&format!("    case UINT64_C(0x{:x}):\n", target.value.0));
                emit_target_indented(output, *target, labels, "      ");
            }
            if *unresolved_default {
                output.push_str(
                    "    default:\n      hydir_unknown_control(state, UINT64_C(0));\n      return;\n",
                );
            }
            output.push_str("  }\n");
            Ok(())
        }
        CirTerminator::Return => {
            output.push_str("  state->rsp += UINT64_C(8);\n  return;\n");
            Ok(())
        }
        CirTerminator::Exit { target } => {
            let target = target.map_or(0, |location| location.value.0);
            output.push_str(&format!(
                "  hydir_external_exit(state, UINT64_C(0x{target:x}));\n  return;\n"
            ));
            Ok(())
        }
        CirTerminator::Unresolved {
            reason,
            target_operand,
        } => {
            let target = target_operand
                .as_ref()
                .map(read_operand)
                .transpose()?
                .unwrap_or_else(|| "UINT64_C(0)".to_owned());
            output.push_str(&format!(
                "  /* {} */\n  hydir_unknown_control(state, (uint64_t)({target}));\n  return;\n",
                c_comment(reason)
            ));
            Ok(())
        }
    }
}

fn emit_target(
    output: &mut String,
    target: hydir_core::Location,
    labels: &std::collections::BTreeSet<hydir_core::Location>,
) -> Result<(), String> {
    emit_target_indented(output, target, labels, "  ");
    Ok(())
}

fn emit_target_indented(
    output: &mut String,
    target: hydir_core::Location,
    labels: &std::collections::BTreeSet<hydir_core::Location>,
    indent: &str,
) {
    if labels.contains(&target) {
        output.push_str(&format!("{indent}goto {};\n", c_label(target)));
    } else {
        output.push_str(&format!(
            "{indent}hydir_external_exit(state, UINT64_C(0x{:x}));\n{indent}return;\n",
            target.value.0
        ));
    }
}

fn c_condition(mnemonic: &str) -> Result<&'static str, String> {
    let suffix = mnemonic
        .strip_prefix("cmov")
        .or_else(|| mnemonic.strip_prefix("set"))
        .or_else(|| mnemonic.strip_prefix('j'))
        .unwrap_or(mnemonic);
    match suffix {
        "e" | "z" => Ok("state->zf"),
        "ne" | "nz" => Ok("!state->zf"),
        "g" | "nle" => Ok("!state->zf && state->sf == state->of"),
        "ge" | "nl" => Ok("state->sf == state->of"),
        "l" | "nge" => Ok("state->sf != state->of"),
        "le" | "ng" => Ok("state->zf || state->sf != state->of"),
        "a" | "nbe" => Ok("!state->cf && !state->zf"),
        "ae" | "nb" | "nc" => Ok("!state->cf"),
        "b" | "nae" | "c" => Ok("state->cf"),
        "be" | "na" => Ok("state->cf || state->zf"),
        "s" => Ok("state->sf"),
        "ns" => Ok("!state->sf"),
        "o" => Ok("state->of"),
        "no" => Ok("!state->of"),
        "p" | "pe" => Ok("state->pf"),
        "np" | "po" => Ok("!state->pf"),
        other => Err(format!("native C backend lacks branch condition {other}")),
    }
}

fn c_comment(value: &str) -> String {
    value.replace("*/", "* /").replace(['\r', '\n'], " ")
}

fn c_string(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}

fn generated_statement_provenance(
    region: &RegionSpec,
    raw_llvm: &str,
    c_source: &str,
) -> Vec<StatementAddressProvenance> {
    let provenance = |address: Address| FactProvenance {
        source: FactSource::NativeAnalysis,
        scope: format!(
            "deterministic C emitted from verified RegionIR instruction block 0x{:x}",
            address.0
        ),
    };
    let mut mappings = Vec::new();
    let mut current = None;
    for (index, line) in c_source.lines().enumerate() {
        if let Some(address) = block_address(line, "L_b", ": {") {
            current = address_in_region(region, address).then_some(address);
            continue;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || matches!(trimmed, "{" | "}") {
            continue;
        }
        if let Some(address) = current {
            let line = u32::try_from(index + 1).unwrap_or(u32::MAX);
            mappings.push(StatementAddressProvenance {
                c_start_line: line,
                c_end_line: line,
                addresses: vec![address],
                provenance: provenance(address),
            });
        }
    }
    if !mappings.is_empty() {
        return mappings;
    }

    // A proven structuring rewrite may collapse several direct-CFG blocks
    // into one source statement. Preserve the many-to-one relationship.
    let addresses = raw_llvm
        .lines()
        .filter_map(|line| block_address(line, "b", ":"))
        .filter(|address| address_in_region(region, *address))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return mappings;
    }
    if let Some((index, _)) = c_source
        .lines()
        .enumerate()
        .find(|(_, line)| line.trim_start().starts_with("return "))
    {
        let line = u32::try_from(index + 1).unwrap_or(u32::MAX);
        mappings.push(StatementAddressProvenance {
            c_start_line: line,
            c_end_line: line,
            provenance: FactProvenance {
                source: FactSource::NativeAnalysis,
                scope: "structured C statement proven from all contributing RegionIR instruction blocks"
                    .to_owned(),
            },
            addresses,
        });
    }
    mappings
}

/// Package the current native region lift and deterministic C view without
/// claiming that the dedicated CIR already exists. Machine block labels are
/// retained as validated statement/address provenance in the generated view.
pub fn build_decompilation_unit(
    region: RegionSpec,
    raw_llvm: String,
    engine_version: &str,
) -> Result<DecompilationUnit, String> {
    let c_source = emit_structured_c(&raw_llvm)?;
    let statement_provenance = generated_statement_provenance(&region, &raw_llvm, &c_source);
    let mut diagnostics = vec![DecompilationDiagnostic {
            code: "cir_unavailable".to_owned(),
            severity: DiagnosticSeverity::Warning,
            message: "Dedicated structured CIR is not yet emitted; c_source is derived from the verified LLVM-compatible RegionIR"
                .to_owned(),
            blocks_stable_operation: true,
        }];
    if statement_provenance.is_empty() {
        diagnostics.push(DecompilationDiagnostic {
            code: "statement_provenance_unavailable".to_owned(),
            severity: DiagnosticSeverity::Warning,
            message: "The verified RegionIR did not retain a selected-region instruction label that could be mapped into C"
                .to_owned(),
            blocks_stable_operation: true,
        });
    }
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
    let structurally_complete = region.unresolved_facts.is_empty();
    let rewrite_ready = region.replacement_ready && structurally_complete;
    let unit = DecompilationUnit {
        schema_version: DECOMPILATION_UNIT_VERSION,
        binary_sha256: region.binary_sha256.clone(),
        function_id: Some(format!(
            "sha256:{}:region:0x{:x}",
            region.binary_sha256, region.entry.0
        )),
        model_revision: None,
        artifacts: DecompilationArtifactDigests::default(),
        region,
        region_ir_llvm: raw_llvm,
        cir: None,
        c_source: c_source.clone(),
        low_level_c: Some(c_source.clone()),
        structured_c: Some(c_source),
        structural_completeness: if structurally_complete {
            DecompilationStructuralCompleteness::Complete
        } else {
            DecompilationStructuralCompleteness::Partial
        },
        semantic_fidelity: DecompilationSemanticFidelity::ExactUnderModel,
        verification: DecompilationVerificationStatus::StaticallyValidated,
        rewrite_ready,
        statement_provenance,
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
    use super::{
        build_decision_decompilation_unit, build_decompilation_unit, emit_c,
        emit_decision_region_c, emit_decision_region_llvm, emit_structured_c,
    };
    use hydir_core::{
        Address, AddressKind, FactProvenance, FactSource, PhysicalLocationKind,
        PhysicalLocationSpec, REGION_SPEC_VERSION, RegionSpec,
    };
    use sha2::{Digest, Sha256};

    fn decision_location(name: &str) -> PhysicalLocationSpec {
        PhysicalLocationSpec {
            name: name.to_owned(),
            kind: PhysicalLocationKind::Register,
            width_bits: 8,
            type_name: Some("u8".to_owned()),
            provenance: FactProvenance {
                source: FactSource::InterchangeImport,
                scope: "test physical state".to_owned(),
            },
        }
    }

    fn decision_region() -> RegionSpec {
        let code = [0x7f, 0x05];
        let inputs = ["AL", "OF", "SF", "ZF"]
            .into_iter()
            .map(decision_location)
            .collect::<Vec<_>>();
        RegionSpec {
            schema_version: REGION_SPEC_VERSION,
            binary_sha256: "0".repeat(64),
            symbol_name: "decision".to_owned(),
            address_kind: AddressKind::Virtual,
            entry: Address(0x1000),
            byte_length: code.len() as u64,
            bytes_sha256: format!("{:x}", Sha256::digest(code)),
            bytes_hex: "7f05".to_owned(),
            exits: vec![Address(0x1007), Address(0x1002)],
            calls: Vec::new(),
            relocations: Vec::new(),
            observed_interior_entries: Vec::new(),
            live_in: None,
            live_out: None,
            physical_live_in: inputs.clone(),
            physical_live_out: vec![inputs[0].clone()],
            stack_delta: Some(0),
            stack_entry_alignment: None,
            exit_stack_relations: Vec::new(),
            global_references: Vec::new(),
            variable_locations: Vec::new(),
            assumptions: Vec::new(),
            unresolved_facts: vec!["test uncertainty".to_owned()],
            replacement_ready: false,
            provenance: FactProvenance {
                source: FactSource::InterchangeImport,
                scope: "test region".to_owned(),
            },
        }
    }

    #[test]
    fn decision_region_emits_explicit_llvm_c_and_cir() {
        assert_eq!(super::decision_c_comment("AL*/\ncode"), "AL* / code");
        let region = decision_region();
        let ir = hydir_backend::lift_region_decision(&region).unwrap();
        let llvm = emit_decision_region_llvm(&ir, &region).unwrap();
        assert!(llvm.contains("%hydir_region_result = type { i64, i8 }"));
        assert!(llvm.contains("insertvalue %hydir_region_result"));
        assert!(llvm.contains("br i1 %predicate_3"));
        let c = emit_decision_region_c(&ir, &region).unwrap();
        assert!(c.contains("uint64_t exit_address;"));
        assert!(c.contains(".out0 = in0"));
        assert!(c.contains("in3") && c.contains("in2") && c.contains("in1"));
        let unit = build_decision_decompilation_unit(region, ir, "hydir-test").unwrap();
        assert!(unit.cir.is_some());
        assert_eq!(unit.statement_provenance.len(), 1);
        assert!(
            !unit
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "cir_unavailable")
        );
    }

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
    fn dword_red_zone_lift_round_trips_to_c() {
        // push rbp; mov rbp,rsp; mov [rbp-4],edi; mov eax,[rbp-4];
        // add eax,1; pop rbp; ret
        let machine = [
            0x55, 0x48, 0x89, 0xe5, 0x89, 0x7d, 0xfc, 0x8b, 0x45, 0xfc, 0x83, 0xc0, 0x01, 0x5d,
            0xc3,
        ];
        let ir = hydir_backend::lift_cfg(&machine, 0x1000).unwrap();
        let c = emit_structured_c(&ir).unwrap();
        assert!(c.contains("UINT64_C(4294967295)"));
        assert!(c.contains("v_slot0_out_1004"));
        assert!(c.contains("return v_rax_in_100e;"));
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
        assert!(!unit.statement_provenance.is_empty());
        assert!(unit.statement_provenance.iter().all(|mapping| {
            mapping.addresses.iter().all(|address| {
                (unit.region.entry.0..unit.region.entry.0 + unit.region.byte_length)
                    .contains(&address.0)
            })
        }));
        assert!(
            !unit
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "statement_provenance_unavailable")
        );
        let mut invalid = unit.clone();
        invalid.statement_provenance[0].addresses = vec![hydir_core::Address(
            invalid.region.entry.0 + invalid.region.byte_length,
        )];
        assert!(
            hydir_core::validate_decompilation_unit(&invalid)
                .unwrap_err()
                .contains("invalid statement provenance")
        );
    }

    #[test]
    fn direct_cfg_c_lines_retain_instruction_addresses() {
        let binary = include_bytes!("../../../fuzz/corpus/elf_import/frame.elf");
        let region = hydir_backend::region_contract(binary, "hydir_frame_balance").unwrap();
        let ir = hydir_backend::lift_symbol(binary, "hydir_frame_balance").unwrap();
        let unit = build_decompilation_unit(region, ir, "hydir-test").unwrap();
        assert!(unit.statement_provenance.len() > 1);
        assert!(
            unit.statement_provenance
                .iter()
                .all(|mapping| mapping.addresses.len() == 1)
        );
        assert!(unit.statement_provenance.iter().any(|mapping| {
            mapping
                .addresses
                .contains(&hydir_core::Address(unit.region.entry.0))
        }));
    }
}
