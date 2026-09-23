use hydir_decompile::{decompile_symbol, lower_expression_ir};
use hydir_ir::SemanticFidelity;
use hydir_ir::expression::{
    BinaryOperator, ComparisonOperator, Expression, ExpressionFunctionIr,
    validate_expression_function_ir,
};
use std::{collections::BTreeMap, fs, path::PathBuf, process::Command};

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

fn evaluate(expression: &Expression, inputs: &BTreeMap<&str, u64>) -> u64 {
    let mask = |width: u16| {
        if width == 64 {
            u64::MAX
        } else {
            (1u64 << width) - 1
        }
    };
    match expression {
        Expression::Read { source, width_bits } => {
            inputs[source.component.as_str()] & mask(*width_bits)
        }
        Expression::Constant { value, .. } => *value,
        Expression::Extract {
            value,
            lsb_bits,
            width_bits,
        } => (evaluate(value, inputs) >> lsb_bits) & mask(*width_bits),
        Expression::ZeroExtend { value, .. } => evaluate(value, inputs),
        Expression::InsertBits {
            original,
            value,
            lsb_bits,
            ..
        } => {
            let bits = mask(value.width_bits()) << lsb_bits;
            (evaluate(original, inputs) & !bits) | ((evaluate(value, inputs) << lsb_bits) & bits)
        }
        Expression::Binary {
            operator,
            width_bits,
            left,
            right,
        } => {
            let left = evaluate(left, inputs);
            let right = evaluate(right, inputs);
            (match operator {
                BinaryOperator::Add => left.wrapping_add(right),
                BinaryOperator::Subtract => left.wrapping_sub(right),
                BinaryOperator::And => left & right,
                BinaryOperator::Or => left | right,
                BinaryOperator::Xor => left ^ right,
            }) & mask(*width_bits)
        }
        Expression::Compare {
            operator,
            left,
            right,
        } => {
            let left = evaluate(left, inputs);
            let right = evaluate(right, inputs);
            u64::from(match operator {
                ComparisonOperator::Equal => left == right,
                ComparisonOperator::UnsignedLess => left < right,
            })
        }
        Expression::ParityEven { value } => {
            u64::from(((evaluate(value, inputs) & 0xff) as u8).count_ones() % 2 == 0)
        }
    }
}

#[test]
fn expression_ir_exposes_cmp_test_flags_and_branch_predicates() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/expression_conditions.S");
    let temp = tempfile::tempdir().unwrap();
    let object = temp.path().join("expression_conditions.o");
    let compile = Command::new("clang")
        .args(["--target=x86_64-unknown-linux-gnu", "-c"])
        .arg(fixture)
        .arg("-o")
        .arg(&object)
        .output()
        .expect("Clang is required for the condition fixture");
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let native =
        decompile_symbol(&fs::read(object).unwrap(), "hydir_expression_conditions").unwrap();
    let expressions = lower_expression_ir(&native.machine_ir, &native.state_ir).unwrap();
    let instructions = expressions
        .blocks
        .iter()
        .flat_map(|block| &block.instructions)
        .collect::<Vec<_>>();

    let cmp = instructions
        .iter()
        .find(|instruction| instruction.mnemonic == "cmp")
        .unwrap();
    let flags = cmp
        .assignments
        .iter()
        .map(|assignment| (assignment.target.component.as_str(), &assignment.value))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(flags.len(), 6);
    for (left, right, expected) in [
        (0u64, 0u64, [1, 0, 0, 0]),
        (0, 1, [0, 1, 1, 0]),
        (0x8000_0000, 1, [0, 0, 0, 1]),
        (0x7fff_ffff, 0xffff_ffff, [0, 1, 1, 1]),
    ] {
        let inputs = BTreeMap::from([("register:rdi", left), ("register:rsi", right)]);
        let actual =
            ["flag:zf", "flag:cf", "flag:sf", "flag:of"].map(|name| evaluate(flags[name], &inputs));
        assert_eq!(actual, expected, "cmp {left:#x}, {right:#x}");
    }
    assert!(cmp.residual.is_none());
    let inputs = BTreeMap::from([("register:rdi", 0xfu64), ("register:rsi", 1u64)]);
    assert_eq!(evaluate(flags["flag:af"], &inputs), 0);
    assert_eq!(evaluate(flags["flag:pf"], &inputs), 0);
    let inputs = BTreeMap::from([("register:rdi", 0x10u64), ("register:rsi", 1u64)]);
    assert_eq!(evaluate(flags["flag:af"], &inputs), 1);
    assert_eq!(evaluate(flags["flag:pf"], &inputs), 1);

    let test = instructions
        .iter()
        .find(|instruction| instruction.mnemonic == "test")
        .unwrap();
    let test_flags = test
        .assignments
        .iter()
        .map(|assignment| (assignment.target.component.as_str(), &assignment.value))
        .collect::<BTreeMap<_, _>>();
    for (value, expected) in [(0u64, [1, 0, 0, 0]), (0x8000_0000, [0, 0, 1, 0])] {
        let inputs = BTreeMap::from([("register:rsi", value)]);
        let actual = ["flag:zf", "flag:cf", "flag:sf", "flag:of"]
            .map(|name| evaluate(test_flags[name], &inputs));
        assert_eq!(actual, expected, "test {value:#x}");
    }
    assert!(
        test.residual
            .as_ref()
            .unwrap()
            .undefined_outputs
            .contains(&"flag:af".to_owned())
    );

    for (mnemonic, inputs, expected) in [
        ("jae", BTreeMap::from([("flag:cf", 0)]), 1),
        ("je", BTreeMap::from([("flag:zf", 1)]), 1),
        (
            "jg",
            BTreeMap::from([("flag:zf", 0), ("flag:sf", 1), ("flag:of", 1)]),
            1,
        ),
        (
            "jg",
            BTreeMap::from([("flag:zf", 0), ("flag:sf", 1), ("flag:of", 0)]),
            0,
        ),
    ] {
        let branch = instructions
            .iter()
            .find(|instruction| instruction.mnemonic == mnemonic)
            .unwrap();
        assert_eq!(
            evaluate(branch.condition.as_ref().unwrap(), &inputs),
            expected
        );
        assert!(branch.residual.is_some());
    }
    validate_expression_function_ir(&expressions).unwrap();
}

#[test]
fn expression_ir_scalar_flags_match_arithmetic_boundaries() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/expression_conditions.S");
    let temp = tempfile::tempdir().unwrap();
    let object = temp.path().join("expression_conditions.o");
    let compile = Command::new("clang")
        .args(["--target=x86_64-unknown-linux-gnu", "-c"])
        .arg(fixture)
        .arg("-o")
        .arg(&object)
        .output()
        .expect("Clang is required for the arithmetic fixture");
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let native =
        decompile_symbol(&fs::read(object).unwrap(), "hydir_expression_arithmetic").unwrap();
    let expressions = lower_expression_ir(&native.machine_ir, &native.state_ir).unwrap();
    let instructions = expressions
        .blocks
        .iter()
        .flat_map(|block| &block.instructions)
        .collect::<Vec<_>>();
    for (mnemonic, source, cases) in [
        (
            "add",
            "register:rsi",
            [
                (0xffff_ffff, 1, [1, 1, 0, 0]),
                (0x7fff_ffff, 1, [0, 0, 1, 1]),
            ],
        ),
        (
            "sub",
            "register:rdx",
            [(0, 1, [0, 1, 1, 0]), (0x8000_0000, 1, [0, 0, 0, 1])],
        ),
        (
            "xor",
            "register:rcx",
            [
                (0xffff_ffff, 0xffff_ffff, [1, 0, 0, 0]),
                (0x8000_0000, 0, [0, 0, 1, 0]),
            ],
        ),
    ] {
        let instruction = instructions
            .iter()
            .find(|instruction| instruction.mnemonic == mnemonic)
            .unwrap();
        let flags = instruction
            .assignments
            .iter()
            .map(|assignment| (assignment.target.component.as_str(), &assignment.value))
            .collect::<BTreeMap<_, _>>();
        assert!(flags.contains_key("register:rax"));
        for (left, right, expected) in cases {
            let inputs = BTreeMap::from([("register:rax", left), (source, right)]);
            let actual = ["flag:zf", "flag:cf", "flag:sf", "flag:of"]
                .map(|name| evaluate(flags[name], &inputs));
            assert_eq!(actual, expected, "{mnemonic} {left:#x}, {right:#x}");
        }
        let mut seed = 0x4d59_5df4_d0f3_3173u64;
        for _ in 0..2048 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let left = (seed >> 32) as u32;
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let right = (seed >> 32) as u32;
            let (result, carry, overflow) = match mnemonic {
                "add" => {
                    let (result, carry) = left.overflowing_add(right);
                    let (_, overflow) = (left as i32).overflowing_add(right as i32);
                    (result, carry, overflow)
                }
                "sub" => {
                    let (result, borrow) = left.overflowing_sub(right);
                    let (_, overflow) = (left as i32).overflowing_sub(right as i32);
                    (result, borrow, overflow)
                }
                "xor" => (left ^ right, false, false),
                _ => unreachable!(),
            };
            let expected = [
                u64::from(result == 0),
                u64::from(carry),
                u64::from(result >> 31),
                u64::from(overflow),
            ];
            let inputs = BTreeMap::from([
                ("register:rax", u64::from(left)),
                (source, u64::from(right)),
            ]);
            let actual = ["flag:zf", "flag:cf", "flag:sf", "flag:of"]
                .map(|name| evaluate(flags[name], &inputs));
            assert_eq!(actual, expected, "{mnemonic} {left:#x}, {right:#x}");
            let parity_even = u64::from((result as u8).count_ones() % 2 == 0);
            assert_eq!(
                evaluate(flags["flag:pf"], &inputs),
                parity_even,
                "{mnemonic} parity {left:#x}, {right:#x}"
            );
            if mnemonic != "xor" {
                let auxiliary_carry = if mnemonic == "add" {
                    (left & 0xf) + (right & 0xf) > 0xf
                } else {
                    (left & 0xf) < (right & 0xf)
                };
                assert_eq!(
                    evaluate(flags["flag:af"], &inputs),
                    u64::from(auxiliary_carry),
                    "{mnemonic} auxiliary carry {left:#x}, {right:#x}"
                );
            }
        }
        if mnemonic == "xor" {
            let residual = instruction.residual.as_ref().unwrap();
            assert_eq!(residual.undefined_outputs, ["flag:af"]);
        } else {
            assert!(instruction.residual.is_none());
        }
    }
    validate_expression_function_ir(&expressions).unwrap();
}

#[test]
fn expression_ir_flag_widths_cover_byte_word_and_qword() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/expression_conditions.S");
    let temp = tempfile::tempdir().unwrap();
    let object = temp.path().join("expression_conditions.o");
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
    let bytes = fs::read(object).unwrap();
    for (function, sign_bit) in [
        ("hydir_expression_arithmetic8", 1u64 << 7),
        ("hydir_expression_arithmetic16", 1u64 << 15),
        ("hydir_expression_arithmetic64", 1u64 << 63),
    ] {
        let native = decompile_symbol(&bytes, function).unwrap();
        let expressions = lower_expression_ir(&native.machine_ir, &native.state_ir).unwrap();
        let instructions = expressions
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        let add = instructions
            .iter()
            .find(|instruction| instruction.mnemonic == "add")
            .unwrap();
        let flags = add
            .assignments
            .iter()
            .map(|assignment| (assignment.target.component.as_str(), &assignment.value))
            .collect::<BTreeMap<_, _>>();
        let inputs = BTreeMap::from([("register:rax", sign_bit - 1), ("register:rsi", 1)]);
        let actual = [
            "flag:zf", "flag:cf", "flag:sf", "flag:of", "flag:pf", "flag:af",
        ]
        .map(|name| evaluate(flags[name], &inputs));
        assert_eq!(
            actual,
            [0, 0, 1, 1, u64::from(sign_bit > 0x80), 1],
            "{function}"
        );
        assert!(add.residual.is_none());

        let sub = instructions
            .iter()
            .find(|instruction| instruction.mnemonic == "sub")
            .unwrap();
        let flags = sub
            .assignments
            .iter()
            .map(|assignment| (assignment.target.component.as_str(), &assignment.value))
            .collect::<BTreeMap<_, _>>();
        let inputs = BTreeMap::from([("register:rax", 0), ("register:rdx", 1)]);
        let actual = [
            "flag:zf", "flag:cf", "flag:sf", "flag:of", "flag:pf", "flag:af",
        ]
        .map(|name| evaluate(flags[name], &inputs));
        assert_eq!(actual, [0, 1, 1, 0, 1, 1], "{function}");
        assert!(sub.residual.is_none());
        validate_expression_function_ir(&expressions).unwrap();
    }
}
