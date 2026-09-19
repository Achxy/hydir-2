//! Fail-closed C emission for HydIR's raw scalar direct-CFG LLVM lift.
//!
//! This is a small LLVM-to-C backend, not a general LLVM parser or Rellic.
//! It preserves explicit control flow and lowers SSA phis with parallel edge
//! copies. Only the exact instruction subset emitted by `hydir-backend` is
//! accepted; unfamiliar LLVM syntax is an error, never an ignored operation.

use hydir_core::{
    Address, DECOMPILATION_UNIT_VERSION, DecompilationDiagnostic, DecompilationUnit,
    DiagnosticSeverity, FactProvenance, FactSource, RegionDecisionIr, RegionPredicate, RegionSpec,
    StatementAddressProvenance, validate_decompilation_unit, validate_region_decision_ir,
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
    let unit = DecompilationUnit {
        schema_version: DECOMPILATION_UNIT_VERSION,
        binary_sha256: region.binary_sha256.clone(),
        region,
        region_ir_llvm,
        cir: Some(serde_json::to_string_pretty(&ir).map_err(|error| error.to_string())?),
        c_source,
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
    let unit = DecompilationUnit {
        schema_version: DECOMPILATION_UNIT_VERSION,
        binary_sha256: region.binary_sha256.clone(),
        region,
        region_ir_llvm: raw_llvm,
        cir: None,
        c_source,
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
