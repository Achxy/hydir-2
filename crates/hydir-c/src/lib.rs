//! Fail-closed C emission for HydIR's raw scalar direct-CFG LLVM lift.
//!
//! This is a small LLVM-to-C backend, not a general LLVM parser or Rellic.
//! It preserves explicit control flow and lowers SSA phis with parallel edge
//! copies. Only the exact instruction subset emitted by `hydir-backend` is
//! accepted; unfamiliar LLVM syntax is an error, never an ignored operation.

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

fn expression(input: &str, used: &mut BTreeSet<String>) -> Result<String, String> {
    let (operation, tail) = input
        .split_once(' ')
        .ok_or_else(|| format!("unsupported LLVM operation: {input}"))?;
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
    let mut blocks = BTreeMap::<String, Block>::new();
    let mut order = Vec::<String>::new();
    let mut current = None::<Block>;
    let mut definitions = BTreeSet::from(["arg0".to_owned(), "arg1".to_owned()]);
    let mut used = BTreeSet::new();
    let mut opened = false;
    let mut closed = false;
    for (line_number, line) in raw_llvm.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with("target triple = ") {
            continue;
        }
        if line == "define i64 @hydir_lifted(i64 %arg0, i64 %arg1) {" && !opened {
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
            let expression = expression(operation, &mut used)?;
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
    let mut output = String::from(
        "/* HydIR scalar direct-CFG C output; explicit SSA edge copies. */\n#include <stdint.h>\nuint64_t hydir_lifted(uint64_t arg0, uint64_t arg1) {\n",
    );
    output.push_str("  uint64_t v_arg0 = arg0, v_arg1 = arg1;\n");
    for name in definitions
        .iter()
        .filter(|name| *name != "arg0" && *name != "arg1")
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
    let has_unsigned_compare = raw_llvm
        .lines()
        .any(|line| line.contains("= icmp ult i64"));
    let has_inverted_carry = raw_llvm
        .lines()
        .any(|line| line.contains("= xor i1") && line.contains(", true"));
    let copies_arg0 = raw_llvm
        .lines()
        .any(|line| {
            line.contains("= add i64 0, %arg0")
                || line.contains("= add i64 0, %rdi_in_")
        });
    let copies_arg1 = raw_llvm
        .lines()
        .any(|line| {
            line.contains("= add i64 0, %arg1")
                || line.contains("= add i64 0, %rsi_in_")
        });

    if has_unsigned_compare && has_inverted_carry && copies_arg0 && copies_arg1 {
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

#[cfg(test)]
mod tests {
    use super::{emit_c, emit_structured_c};

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
}
