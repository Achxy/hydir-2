//! Structure only CFG regions with a single entry and proven private arms.
//! Everything else retains explicit gotos. This pass changes C presentation,
//! not the versioned CFG artifact or its source-address provenance.

use super::{
    FLAG_LEFT, FLAG_RIGHT, HighCfgBlock, HighCfgCompareOp, HighCfgPredicate, HighCfgTerminator,
    HighLevelCfgCir, c_expr, c_label, c_predicate, successors,
};
use crate::HighExpr;
use hydir_core::Location;
use std::collections::{BTreeMap, BTreeSet};

struct Graph<'a> {
    ir: &'a HighLevelCfgCir,
    blocks: BTreeMap<Location, &'a HighCfgBlock>,
    predecessors: BTreeMap<Location, usize>,
    flag_reads: BTreeMap<&'static str, usize>,
}

fn count_flag_reads(expr: &HighExpr, counts: &mut BTreeMap<&'static str, usize>) {
    match expr {
        HighExpr::Variable { name } if name == FLAG_LEFT => {
            *counts.entry(FLAG_LEFT).or_default() += 1
        }
        HighExpr::Variable { name } if name == FLAG_RIGHT => {
            *counts.entry(FLAG_RIGHT).or_default() += 1
        }
        HighExpr::Binary { left, right, .. } => {
            count_flag_reads(left, counts);
            count_flag_reads(right, counts);
        }
        HighExpr::Variable { .. } | HighExpr::Constant { .. } => {}
        HighExpr::Field { .. } | HighExpr::Call { .. } => {
            unreachable!("validated scalar expression")
        }
    }
}

fn invert(op: HighCfgCompareOp) -> HighCfgCompareOp {
    match op {
        HighCfgCompareOp::Equal => HighCfgCompareOp::NotEqual,
        HighCfgCompareOp::NotEqual => HighCfgCompareOp::Equal,
        HighCfgCompareOp::UnsignedLess => HighCfgCompareOp::UnsignedGreaterEqual,
        HighCfgCompareOp::UnsignedLessEqual => HighCfgCompareOp::UnsignedGreater,
        HighCfgCompareOp::UnsignedGreater => HighCfgCompareOp::UnsignedLessEqual,
        HighCfgCompareOp::UnsignedGreaterEqual => HighCfgCompareOp::UnsignedLess,
        HighCfgCompareOp::SignedLess => HighCfgCompareOp::SignedGreaterEqual,
        HighCfgCompareOp::SignedLessEqual => HighCfgCompareOp::SignedGreater,
        HighCfgCompareOp::SignedGreater => HighCfgCompareOp::SignedLessEqual,
        HighCfgCompareOp::SignedGreaterEqual => HighCfgCompareOp::SignedLess,
        HighCfgCompareOp::TestZero => HighCfgCompareOp::TestNonzero,
        HighCfgCompareOp::TestNonzero => HighCfgCompareOp::TestZero,
    }
}

impl<'a> Graph<'a> {
    fn new(ir: &'a HighLevelCfgCir) -> Self {
        let blocks = ir
            .blocks
            .iter()
            .map(|block| (block.address, block))
            .collect::<BTreeMap<_, _>>();
        let mut predecessors = BTreeMap::new();
        for block in &ir.blocks {
            for successor in successors(&block.terminator) {
                *predecessors.entry(successor).or_insert(0) += 1;
            }
        }
        let mut flag_reads = BTreeMap::new();
        for block in &ir.blocks {
            for statement in &block.statements {
                count_flag_reads(&statement.value, &mut flag_reads);
            }
            match &block.terminator {
                HighCfgTerminator::Branch { predicate, .. } => {
                    count_flag_reads(&predicate.left, &mut flag_reads);
                    count_flag_reads(&predicate.right, &mut flag_reads);
                }
                HighCfgTerminator::Return { value, .. } => count_flag_reads(value, &mut flag_reads),
                HighCfgTerminator::Goto { .. } => {}
            }
        }
        Self {
            ir,
            blocks,
            predecessors,
            flag_reads,
        }
    }

    fn block(&self, address: Location) -> &'a HighCfgBlock {
        self.blocks[&address]
    }

    /// Follow a unique-predecessor chain. A private arm requires its first
    /// block to have only the branch edge that selected it.
    fn chain(
        &self,
        start: Location,
        emitted: &BTreeSet<Location>,
        reserved: &BTreeSet<Location>,
        private_start: bool,
    ) -> Option<Vec<Location>> {
        if private_start && self.predecessors.get(&start) != Some(&1) {
            return None;
        }
        let mut path = Vec::new();
        let mut seen = BTreeSet::new();
        let mut current = start;
        loop {
            if !seen.insert(current) || emitted.contains(&current) || reserved.contains(&current) {
                return None;
            }
            path.push(current);
            let HighCfgTerminator::Goto { target, .. } = &self.block(current).terminator else {
                break;
            };
            if *target == self.ir.entry || self.predecessors.get(target) != Some(&1) {
                break;
            }
            if emitted.contains(target) || reserved.contains(target) || seen.contains(target) {
                break;
            }
            current = *target;
        }
        Some(path)
    }

    fn tail(&self, path: &[Location]) -> &'a HighCfgTerminator {
        &self.block(*path.last().expect("nonempty chain")).terminator
    }

    fn emit_statements(&self, output: &mut String, path: &[Location], indent: &str) {
        self.emit_statements_skip_tail(output, path, indent, 0);
    }

    fn emit_statements_skip_tail(
        &self,
        output: &mut String,
        path: &[Location],
        indent: &str,
        skip: usize,
    ) {
        let total = path
            .iter()
            .map(|address| self.block(*address).statements.len())
            .sum::<usize>();
        let mut index = 0;
        for address in path {
            for statement in &self.block(*address).statements {
                if index + skip < total {
                    output.push_str(&format!(
                        "{indent}{} = {};\n",
                        statement.target,
                        c_expr(&statement.value)
                    ));
                }
                index += 1;
            }
        }
    }

    /// Replace a pair of flag snapshots by their original scalar operands
    /// only when the branch is their sole reader and nothing follows them.
    fn rendered_predicate(
        &self,
        path: &[Location],
        predicate: &HighCfgPredicate,
    ) -> (HighCfgPredicate, usize) {
        let HighExpr::Variable { name: left_name } = &predicate.left else {
            return (predicate.clone(), 0);
        };
        let HighExpr::Variable { name: right_name } = &predicate.right else {
            return (predicate.clone(), 0);
        };
        if left_name != FLAG_LEFT
            || right_name != FLAG_RIGHT
            || self.flag_reads.get(FLAG_LEFT) != Some(&1)
            || self.flag_reads.get(FLAG_RIGHT) != Some(&1)
        {
            return (predicate.clone(), 0);
        }
        let statements = path
            .iter()
            .flat_map(|address| &self.block(*address).statements)
            .collect::<Vec<_>>();
        if statements.len() < 2 {
            return (predicate.clone(), 0);
        }
        let left = statements[statements.len() - 2];
        let right = statements[statements.len() - 1];
        if left.target != FLAG_LEFT || right.target != FLAG_RIGHT || left.site != right.site {
            return (predicate.clone(), 0);
        }
        let direct = HighCfgPredicate {
            op: predicate.op,
            left: left.value.clone(),
            right: right.value.clone(),
        };
        (direct, 2)
    }

    fn reserve(path: &[Location]) -> BTreeSet<Location> {
        path.iter().copied().collect()
    }

    fn emit_loop(
        &self,
        output: &mut String,
        head: &[Location],
        emitted: &mut BTreeSet<Location>,
    ) -> bool {
        let HighCfgTerminator::Branch {
            predicate,
            taken,
            fallthrough,
            ..
        } = self.tail(head)
        else {
            return false;
        };
        let head_set = Self::reserve(head);
        for (body_start, exit, exit_on_true) in
            [(*fallthrough, *taken, true), (*taken, *fallthrough, false)]
        {
            if head_set.contains(&exit) || head_set.contains(&body_start) {
                continue;
            }
            let Some(body) = self.chain(body_start, emitted, &head_set, true) else {
                continue;
            };
            let HighCfgTerminator::Goto { target, .. } = self.tail(&body) else {
                continue;
            };
            if *target != head[0] || Self::reserve(&body).contains(&exit) {
                continue;
            }
            let (condition, skip) = self.rendered_predicate(head, predicate);
            let head_statement_count = head
                .iter()
                .map(|address| self.block(*address).statements.len())
                .sum::<usize>();
            output.push_str(&format!("{}:\n", c_label(head[0])));
            if head_statement_count == skip {
                let mut keep_going = condition;
                if exit_on_true {
                    keep_going.op = invert(keep_going.op);
                }
                output.push_str(&format!("  while ({}) {{\n", c_predicate(&keep_going)));
                self.emit_statements(output, &body, "    ");
                output.push_str("  }\n");
            } else {
                output.push_str("  for (;;) {\n");
                self.emit_statements_skip_tail(output, head, "    ", skip);
                let condition = c_predicate(&condition);
                if exit_on_true {
                    output.push_str(&format!("    if ({condition}) break;\n"));
                } else {
                    output.push_str(&format!("    if (!({condition})) break;\n"));
                }
                self.emit_statements(output, &body, "    ");
                output.push_str("  }\n");
            }
            output.push_str(&format!("  goto {};\n", c_label(exit)));
            emitted.extend(head.iter().chain(body.iter()).copied());
            return true;
        }
        false
    }

    fn emit_diamond(
        &self,
        output: &mut String,
        head: &[Location],
        emitted: &mut BTreeSet<Location>,
    ) -> bool {
        let HighCfgTerminator::Branch {
            predicate,
            taken,
            fallthrough,
            ..
        } = self.tail(head)
        else {
            return false;
        };
        let head_set = Self::reserve(head);
        let Some(taken_path) = self.chain(*taken, emitted, &head_set, true) else {
            return false;
        };
        let mut reserved = head_set.clone();
        reserved.extend(&taken_path);
        let Some(fallthrough_path) = self.chain(*fallthrough, emitted, &reserved, true) else {
            return false;
        };
        let join = match (self.tail(&taken_path), self.tail(&fallthrough_path)) {
            (
                HighCfgTerminator::Goto { target: left, .. },
                HighCfgTerminator::Goto { target: right, .. },
            ) if left == right && !reserved.contains(left) && !fallthrough_path.contains(left) => {
                Some(*left)
            }
            (HighCfgTerminator::Return { .. }, HighCfgTerminator::Return { .. }) => None,
            _ => return false,
        };
        output.push_str(&format!("{}:\n", c_label(head[0])));
        let (condition, skip) = self.rendered_predicate(head, predicate);
        self.emit_statements_skip_tail(output, head, "  ", skip);
        output.push_str(&format!("  if ({}) {{\n", c_predicate(&condition)));
        self.emit_statements(output, &taken_path, "    ");
        if let HighCfgTerminator::Return { value, .. } = self.tail(&taken_path) {
            output.push_str(&format!("    return {};\n", c_expr(value)));
        }
        output.push_str("  } else {\n");
        self.emit_statements(output, &fallthrough_path, "    ");
        if let HighCfgTerminator::Return { value, .. } = self.tail(&fallthrough_path) {
            output.push_str(&format!("    return {};\n", c_expr(value)));
        }
        output.push_str("  }\n");
        if let Some(join) = join {
            output.push_str(&format!("  goto {};\n", c_label(join)));
        }
        emitted.extend(
            head.iter()
                .chain(taken_path.iter())
                .chain(fallthrough_path.iter())
                .copied(),
        );
        true
    }

    fn emit_plain(&self, output: &mut String, path: &[Location], emitted: &mut BTreeSet<Location>) {
        output.push_str(&format!("{}:\n", c_label(path[0])));
        let branch_condition = if let HighCfgTerminator::Branch { predicate, .. } = self.tail(path)
        {
            Some(self.rendered_predicate(path, predicate))
        } else {
            None
        };
        self.emit_statements_skip_tail(
            output,
            path,
            "  ",
            branch_condition.as_ref().map_or(0, |(_, skip)| *skip),
        );
        match self.tail(path) {
            HighCfgTerminator::Goto { target, .. } => {
                output.push_str(&format!("  goto {};\n", c_label(*target)));
            }
            HighCfgTerminator::Branch {
                predicate,
                taken,
                fallthrough,
                ..
            } => {
                output.push_str(&format!(
                    "  if ({}) goto {};\n  goto {};\n",
                    branch_condition
                        .as_ref()
                        .map(|(condition, _)| c_predicate(condition))
                        .unwrap_or_else(|| c_predicate(predicate)),
                    c_label(*taken),
                    c_label(*fallthrough)
                ));
            }
            HighCfgTerminator::Return { value, .. } => {
                output.push_str(&format!("  return {};\n", c_expr(value)));
            }
        }
        emitted.extend(path.iter().copied());
    }
}

/// Remove only jumps to the immediately following generated label, then
/// labels with no remaining jumps. No branch target or statement is moved.
fn omit_redundant_labels(body: String) -> String {
    let lines = body.lines().collect::<Vec<_>>();
    let mut kept = Vec::with_capacity(lines.len());
    for (index, line) in lines.iter().enumerate() {
        let adjacent = line
            .strip_prefix("  goto ")
            .and_then(|line| line.strip_suffix(';'))
            .is_some_and(|target| {
                lines
                    .get(index + 1)
                    .is_some_and(|next| *next == format!("{target}:"))
            });
        if !adjacent {
            kept.push(*line);
        }
    }
    let jump_targets = kept
        .iter()
        .filter_map(|line| line.split_once("goto "))
        .filter_map(|(_, tail)| tail.split_once(';'))
        .map(|(target, _)| target)
        .collect::<BTreeSet<_>>();
    let kept = kept
        .into_iter()
        .filter(|line| {
            let Some(label) = line.strip_suffix(':') else {
                return true;
            };
            !label.starts_with("hydir_bb_") || jump_targets.contains(label)
        })
        .collect::<Vec<_>>();
    format!("{}\n", kept.join("\n"))
}

pub(super) fn emit_body(ir: &HighLevelCfgCir) -> String {
    let graph = Graph::new(ir);
    let mut output = format!("  goto {};\n", c_label(ir.entry));
    let mut emitted = BTreeSet::new();
    for block in &ir.blocks {
        if emitted.contains(&block.address) {
            continue;
        }
        let path = graph
            .chain(block.address, &emitted, &BTreeSet::new(), false)
            .expect("validated CFG block chain");
        if graph.emit_loop(&mut output, &path, &mut emitted)
            || graph.emit_diamond(&mut output, &path, &mut emitted)
        {
            continue;
        }
        graph.emit_plain(&mut output, &path, &mut emitted);
    }
    omit_redundant_labels(output)
}
