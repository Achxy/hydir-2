use hydir_decompile::{decompile_symbol, lower_expression_ir};
use hydir_ir::SemanticFidelity;
use hydir_ir::expression::{Expression, ExpressionFunctionIr, validate_expression_function_ir};
use std::{fs, path::PathBuf, process::Command};

fn prism() -> Vec<u8> {
    fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../demo/hydir-prism.elf")).unwrap()
}

#[test]
fn expression_ir_preserves_branch_joins_and_unlowered_effects() {
    let native = decompile_symbol(&prism(), "hydir_stage_decision").unwrap();
    let expressions = lower_expression_ir(&native.machine_ir, &native.state_ir).unwrap();
    assert_eq!(expressions.blocks.len(), native.state_ir.blocks.len());
    assert!(
        expressions
            .blocks
            .iter()
            .any(|block| !block.component_phis.is_empty())
    );
    assert!(
        expressions
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .any(|instruction| instruction.residual.is_some())
    );
    assert_eq!(
        expressions.semantic_fidelity,
        SemanticFidelity::Conservative
    );
    for (machine_block, expression_block) in
        native.machine_ir.blocks.iter().zip(&expressions.blocks)
    {
        for (machine_instruction, expression_instruction) in machine_block
            .instructions
            .iter()
            .zip(&expression_block.instructions)
        {
            assert_eq!(
                expression_instruction.bytes_hex,
                machine_instruction.bytes_hex
            );
            if let Some(residual) = &expression_instruction.residual {
                assert_eq!(residual.operands, machine_instruction.operands);
                assert_eq!(residual.memory, machine_instruction.effects.memory);
                assert_eq!(residual.control, machine_instruction.effects.control);
            }
        }
    }

    let serialized = serde_json::to_vec(&expressions).unwrap();
    let round_trip: ExpressionFunctionIr = serde_json::from_slice(&serialized).unwrap();
    assert_eq!(round_trip, expressions);
    validate_expression_function_ir(&round_trip).unwrap();
}

#[test]
fn expression_ir_never_loses_a_register_or_flag_definition() {
    let native = decompile_symbol(&prism(), "hydir_stage_leaf_add").unwrap();
    let mut expressions = lower_expression_ir(&native.machine_ir, &native.state_ir).unwrap();
    assert!(
        expressions
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .any(|instruction| !instruction.assignments.is_empty())
    );

    let instruction = expressions
        .blocks
        .iter_mut()
        .flat_map(|block| &mut block.instructions)
        .find(|instruction| {
            instruction
                .residual
                .as_ref()
                .is_some_and(|residual| !residual.outputs.is_empty())
        })
        .expect("the arithmetic flags or return state remain explicit");
    instruction.residual = None;
    assert!(validate_expression_function_ir(&expressions).is_err());
}

#[test]
fn expression_ir_handles_32_bit_and_low_byte_writes_and_preserves_high_byte_unknowns() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/expression_widths.S");
    let temp = tempfile::tempdir().unwrap();
    let object = temp.path().join("expression_widths.o");
    let compile = Command::new("clang")
        .args(["--target=x86_64-unknown-linux-gnu", "-c"])
        .arg(fixture)
        .arg("-o")
        .arg(&object)
        .output()
        .expect("Clang is required for the width fixture");
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let native = decompile_symbol(&fs::read(object).unwrap(), "hydir_expression_widths").unwrap();
    let expressions = lower_expression_ir(&native.machine_ir, &native.state_ir).unwrap();
    let assignments = expressions
        .blocks
        .iter()
        .flat_map(|block| &block.instructions)
        .flat_map(|instruction| &instruction.assignments)
        .collect::<Vec<_>>();
    assert!(
        assignments
            .iter()
            .any(|assignment| matches!(assignment.value, Expression::ZeroExtend { .. }))
    );
    let byte_writes = expressions
        .blocks
        .iter()
        .flat_map(|block| &block.instructions)
        .filter(|instruction| matches!(instruction.bytes_hex.as_str(), "88dc" | "88c8"))
        .collect::<Vec<_>>();
    assert_eq!(byte_writes.len(), 2);
    let high_byte = byte_writes
        .iter()
        .find(|instruction| instruction.bytes_hex == "88dc")
        .unwrap();
    assert!(high_byte.assignments.is_empty());
    let residual = high_byte
        .residual
        .as_ref()
        .expect("AH write must remain explicit");
    assert!(residual.reason.contains("register AH unsupported"));
    assert_eq!(residual.outputs.len(), high_byte.output_components.len());
    let low_byte = byte_writes
        .iter()
        .find(|instruction| instruction.bytes_hex == "88c8")
        .unwrap();
    assert!(low_byte.residual.is_none());
    assert!(matches!(
        low_byte.assignments[0].value,
        Expression::InsertBits { lsb_bits: 0, .. }
    ));
    validate_expression_function_ir(&expressions).unwrap();
}
