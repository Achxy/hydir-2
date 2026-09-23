use hydir_decompile::{decompile_symbol, lower_expression_ir};
use hydir_ir::SemanticFidelity;
use hydir_ir::expression::{ExpressionFunctionIr, validate_expression_function_ir};
use std::{fs, path::PathBuf};

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
