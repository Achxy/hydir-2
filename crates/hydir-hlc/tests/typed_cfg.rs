use hydir_decompile::decompile_symbol;
use hydir_hlc::{
    HighCfgStatement, HighCfgTerminator, HighLevelCfgCir, emit_typed_cfg_c,
    lower_high_level_cfg_cir, validate_high_level_cfg_cir,
};
use hydir_model::init_model;
use std::{fs, path::PathBuf, process::Command};

#[test]
fn scalar_cfg_branches_and_loops_compile_and_match_oracles() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/typed_cfg.S");
    let temp = tempfile::tempdir().unwrap();
    let object = temp.path().join("typed_cfg.o");
    let compile = Command::new("clang")
        .args(["--target=x86_64-unknown-linux-gnu", "-c"])
        .arg(&fixture)
        .arg("-o")
        .arg(&object)
        .output()
        .expect("Clang is required for the CFG fixture");
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let bytes = fs::read(&object).unwrap();
    let model = init_model(&bytes).unwrap();
    let mut sources = Vec::new();
    for symbol in ["hydir_cfg_min", "hydir_cfg_sum"] {
        let native = decompile_symbol(&bytes, symbol).unwrap();
        let ir = lower_high_level_cfg_cir(&native.machine_ir, &native.function_ir, &model)
            .unwrap_or_else(|error| panic!("{symbol}: {error}"));
        assert!(ir.blocks.len() > 2);
        assert!(
            ir.blocks
                .iter()
                .any(|block| matches!(block.terminator, HighCfgTerminator::Branch { .. }))
        );
        let json = serde_json::to_vec(&ir).unwrap();
        let round_trip: HighLevelCfgCir = serde_json::from_slice(&json).unwrap();
        assert_eq!(round_trip, ir);
        validate_high_level_cfg_cir(&round_trip).unwrap();
        let c = emit_typed_cfg_c(&ir, &model).unwrap();
        assert!(!c.contains("goto hydir_bb_") && !c.contains("hydir_flag_left"));
        if symbol == "hydir_cfg_min" {
            assert!(c.contains("if (") && c.contains("} else {"));
        } else {
            assert!(c.contains("while (") && !c.contains("for (;;)"));
        }
        let path = temp.path().join(format!("{symbol}.c"));
        fs::write(&path, &c).unwrap();
        for compiler in ["clang", "gcc"] {
            if Command::new(compiler).arg("--version").output().is_err() {
                continue;
            }
            let result = Command::new(compiler)
                .args(["-std=c11", "-Wall", "-Wextra", "-Werror", "-c"])
                .arg(&path)
                .arg("-o")
                .arg(temp.path().join(format!("{symbol}_{compiler}.o")))
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{symbol} {compiler}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
        let mut stale = model.clone();
        stale.revision += 1;
        assert!(emit_typed_cfg_c(&ir, &stale).is_err());
        let mut missing_edge = ir.clone();
        if let Some(HighCfgTerminator::Branch { taken, .. }) = missing_edge
            .blocks
            .iter_mut()
            .map(|block| &mut block.terminator)
            .find(|term| matches!(term, HighCfgTerminator::Branch { .. }))
        {
            taken.value.0 = u64::MAX;
        }
        assert!(validate_high_level_cfg_cir(&missing_edge).is_err());
        let mut uninitialized = ir.clone();
        if let HighCfgStatement::Assign { value, .. } = &mut uninitialized.blocks[0].statements[0] {
            *value = hydir_hlc::HighExpr::Variable {
                name: "hydir_r10".to_owned(),
            };
        } else {
            panic!("expected an initial scalar assignment");
        }
        assert!(validate_high_level_cfg_cir(&uninitialized).is_err());
        sources.push(c);
    }
    let source = format!(
        "#include <stdint.h>\n#define hydir_cfg_min generated_min\n{}\n#undef hydir_cfg_min\n#define hydir_cfg_sum generated_sum\n{}\n#undef hydir_cfg_sum\nstatic uint64_t oracle_min(uint64_t a, uint64_t b) {{ return a < b ? a : b; }}\nstatic uint64_t oracle_sum(uint64_t a, uint64_t b) {{ uint64_t s = 0; for (; a < b; ++a) s += a; return s; }}\nint main(void) {{ for (uint64_t a = 0; a < 80; ++a) for (uint64_t b = 0; b < 80; ++b) {{ if (generated_min(a,b) != oracle_min(a,b) || generated_sum(a,b) != oracle_sum(a,b)) return 1; }} uint64_t edge[] = {{0, 1, UINT64_C(0x7fffffffffffffff), UINT64_C(0x8000000000000000), UINT64_MAX}}; for (unsigned i = 0; i < 5; ++i) for (unsigned j = 0; j < 5; ++j) if (generated_min(edge[i],edge[j]) != oracle_min(edge[i],edge[j])) return 2; return 0; }}\n",
        sources[0], sources[1]
    );
    let harness = temp.path().join("harness.c");
    fs::write(&harness, source).unwrap();
    let exe = temp.path().join("harness.exe");
    let compile = Command::new("clang")
        .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg(&harness)
        .arg("-o")
        .arg(&exe)
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    assert!(Command::new(exe).status().unwrap().success());
}

#[test]
fn scalar_cfg_rejects_unmodeled_widths_and_callee_saved_writes() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/typed_cfg.S");
    let temp = tempfile::tempdir().unwrap();
    let object = temp.path().join("typed_cfg.o");
    let compile = Command::new("clang")
        .args(["--target=x86_64-unknown-linux-gnu", "-c"])
        .arg(fixture)
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let bytes = fs::read(&object).unwrap();
    let model = init_model(&bytes).unwrap();
    for symbol in ["hydir_cfg_memory_byte", "hydir_cfg_callee_saved"] {
        let native = decompile_symbol(&bytes, symbol).unwrap();
        assert!(
            lower_high_level_cfg_cir(&native.machine_ir, &native.function_ir, &model).is_err(),
            "{symbol} was admitted"
        );
    }
}

#[test]
fn memory_flow_through_branches_and_loops_compiles_and_matches_oracles() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/typed_cfg.S");
    let temp = tempfile::tempdir().unwrap();
    let object = temp.path().join("typed_cfg.o");
    let compile = Command::new("clang")
        .args(["--target=x86_64-unknown-linux-gnu", "-c"])
        .arg(fixture)
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let bytes = fs::read(&object).unwrap();
    let model = init_model(&bytes).unwrap();
    let mut source = String::from("#include <stdint.h>\n");
    for (symbol, renamed) in [
        ("hydir_cfg_memory", "generated_load"),
        ("hydir_cfg_array_sum", "generated_sum"),
        ("hydir_cfg_array_fill", "generated_fill"),
        ("hydir_cfg_indexed_sum", "generated_indexed"),
        ("hydir_cfg_overlap", "generated_overlap"),
        ("hydir_cfg_negative_offset", "generated_negative"),
    ] {
        let native = decompile_symbol(&bytes, symbol).unwrap();
        let ir = lower_high_level_cfg_cir(&native.machine_ir, &native.function_ir, &model)
            .unwrap_or_else(|error| panic!("{symbol}: {error}"));
        let json = serde_json::to_vec(&ir).unwrap();
        let round_trip: HighLevelCfgCir = serde_json::from_slice(&json).unwrap();
        validate_high_level_cfg_cir(&round_trip).unwrap();
        let mut invalid = ir.clone();
        if let Some(statement) = invalid
            .blocks
            .iter_mut()
            .flat_map(|block| &mut block.statements)
            .find(|statement| {
                matches!(
                    statement,
                    HighCfgStatement::Load { .. } | HighCfgStatement::Store { .. }
                )
            })
        {
            match statement {
                HighCfgStatement::Load { memory_inputs, .. }
                | HighCfgStatement::Store { memory_inputs, .. } => memory_inputs.clear(),
                HighCfgStatement::Assign { .. } => unreachable!(),
            }
            assert!(validate_high_level_cfg_cir(&invalid).is_err());
        } else {
            panic!("{symbol} has no recovered memory action");
        }
        let c = emit_typed_cfg_c(&ir, &model).unwrap();
        assert!(c.contains("hydir_load_u64") || c.contains("hydir_store_u64"));
        if symbol == "hydir_cfg_indexed_sum" {
            assert!(c.contains("* UINT64_C(8)"));
        }
        if symbol == "hydir_cfg_negative_offset" {
            assert!(c.contains("- UINT64_C(8)"));
        }
        source.push_str(&format!(
            "#define {symbol} {renamed}\n{c}\n#undef {symbol}\n"
        ));
    }
    source.push_str(concat!(
        "static int overlap_check(void) {\n",
        "  unsigned char bytes[16], oracle[16];\n",
        "  uint64_t edge[] = {0, 1, UINT64_MAX, UINT64_C(0x8000000000000000), UINT64_C(0x0102030405060708)};\n",
        "  for (unsigned j = 0; j < 5; ++j) {\n",
        "    for (unsigned i = 0; i < 16; ++i) bytes[i] = oracle[i] = (unsigned char)(i + 31u);\n",
        "    uint64_t value = edge[j];\n",
        "    for (unsigned i = 0; i < 8; ++i) oracle[i] = (unsigned char)(value >> (8u * i));\n",
        "    uint64_t expected = 0;\n",
        "    for (unsigned i = 0; i < 8; ++i) expected |= ((uint64_t)oracle[i + 1]) << (8u * i);\n",
        "    if (generated_overlap((uint64_t)(uintptr_t)bytes,value) != expected) return 1;\n",
        "    for (unsigned i = 0; i < 16; ++i) if (bytes[i] != oracle[i]) return 2;\n",
        "  }\n",
        "  return 0;\n",
        "}\n"
    ));
    source.push_str("int main(void) {\n");
    source.push_str(
        "  uint64_t values[8] = {UINT64_MAX, 1, 7, 9, 0, 3, UINT64_C(0x8000000000000000), 4};\n",
    );
    source.push_str("  for (uint64_t n = 0; n <= 8; ++n) {\n");
    source.push_str(
        "    uint64_t expected = 0; for (uint64_t i = 0; i < n; ++i) expected += values[i];\n",
    );
    source
        .push_str("    if (generated_sum((uint64_t)(uintptr_t)values,n) != expected) return 1;\n");
    source.push_str(
        "    if (generated_indexed((uint64_t)(uintptr_t)values,n) != expected) return 2;\n",
    );
    source.push_str("  }\n");
    source.push_str(
        "  if (generated_load((uint64_t)(uintptr_t)&values[3]) != values[3]) return 3;\n",
    );
    source.push_str(
        "  if (generated_negative((uint64_t)(uintptr_t)&values[4]) != values[3]) return 7;\n",
    );
    source.push_str("  uint64_t filled[8] = {0};\n");
    source.push_str("  for (uint64_t n = 0; n <= 8; ++n) {\n");
    source.push_str("    for (unsigned i = 0; i < 8; ++i) filled[i] = 0;\n");
    source.push_str(
        "    if (generated_fill((uint64_t)(uintptr_t)filled, UINT64_MAX, n) != 0) return 4;\n",
    );
    source.push_str("    for (uint64_t i = 0; i < 8; ++i) if (filled[i] != (i < n ? UINT64_MAX : 0)) return 5;\n");
    source.push_str("  }\n  if (overlap_check() != 0) return 6;\n  return 0;\n}\n");
    let path = temp.path().join("memory_cfg.c");
    fs::write(&path, source).unwrap();
    for compiler in ["clang", "gcc"] {
        if Command::new(compiler).arg("--version").output().is_err() {
            continue;
        }
        let exe = temp.path().join(format!("memory_cfg_{compiler}.exe"));
        let result = Command::new(compiler)
            .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
            .arg(&path)
            .arg("-o")
            .arg(&exe)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{compiler}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(Command::new(exe).status().unwrap().success());
    }
}

#[test]
fn arithmetic_zero_flags_compile_and_match_boundary_oracles() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/typed_cfg.S");
    let temp = tempfile::tempdir().unwrap();
    let object = temp.path().join("typed_cfg.o");
    let compile = Command::new("clang")
        .args(["--target=x86_64-unknown-linux-gnu", "-c"])
        .arg(fixture)
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let bytes = fs::read(&object).unwrap();
    let model = init_model(&bytes).unwrap();
    let mut source = String::from("#include <stdint.h>\n");
    for (symbol, renamed) in [
        ("hydir_cfg_add_flags", "generated_add"),
        ("hydir_cfg_add_snapshot", "generated_snapshot"),
        ("hydir_cfg_sub_flags", "generated_sub"),
        ("hydir_cfg_and_flags", "generated_and"),
        ("hydir_cfg_xor_flags", "generated_xor"),
    ] {
        let native = decompile_symbol(&bytes, symbol).unwrap();
        let ir = lower_high_level_cfg_cir(&native.machine_ir, &native.function_ir, &model)
            .unwrap_or_else(|error| panic!("{symbol}: {error}"));
        let c = emit_typed_cfg_c(&ir, &model).unwrap();
        if symbol == "hydir_cfg_add_snapshot" {
            assert!(c.contains("hydir_flag_left"));
        }
        source.push_str(&format!(
            "#define {symbol} {renamed}\n{c}\n#undef {symbol}\n"
        ));
    }
    source.push_str("int main(void) {\n");
    source.push_str(
        "  uint64_t edge[] = {0, 1, 2, UINT64_C(0x7fffffffffffffff), UINT64_C(0x8000000000000000), UINT64_MAX};\n"
    );
    source.push_str("  for (unsigned i = 0; i < 6; ++i) for (unsigned j = 0; j < 6; ++j) {\n");
    source.push_str(
        "    uint64_t a = edge[i], b = edge[j], sum = a + b, diff = a - b, bits = a & b;\n",
    );
    source.push_str("    if (generated_add(a,b) != (sum == 0 ? 1 : sum)) return 1;\n");
    source.push_str("    if (generated_snapshot(a,b) != (sum == 0 ? 1 : 2)) return 2;\n");
    source.push_str("    if (generated_sub(a,b) != (diff == 0 ? 11 : diff)) return 3;\n");
    source.push_str("    if (generated_and(a,b) != (bits == 0 ? 13 : bits)) return 4;\n");
    source.push_str("    if (generated_xor() != 17) return 5;\n");
    source.push_str("  }\n  return 0;\n}\n");
    let path = temp.path().join("arithmetic_flags.c");
    fs::write(&path, source).unwrap();
    for compiler in ["clang", "gcc"] {
        if Command::new(compiler).arg("--version").output().is_err() {
            continue;
        }
        let exe = temp.path().join(format!("arithmetic_flags_{compiler}.exe"));
        let result = Command::new(compiler)
            .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
            .arg(&path)
            .arg("-o")
            .arg(&exe)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{compiler}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(Command::new(exe).status().unwrap().success());
    }
}

#[test]
fn subtraction_comparison_flags_survive_joins_and_register_writes() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/typed_cfg.S");
    let temp = tempfile::tempdir().unwrap();
    let object = temp.path().join("typed_cfg.o");
    let compile = Command::new("clang")
        .args(["--target=x86_64-unknown-linux-gnu", "-c"])
        .arg(&fixture)
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let bytes = fs::read(&object).unwrap();
    let model = init_model(&bytes).unwrap();
    let mut source = String::from("#include <stdint.h>\n");
    for (symbol, renamed) in [
        ("hydir_cfg_sub_unsigned_join", "generated_unsigned"),
        ("hydir_cfg_sub_signed_snapshot", "generated_signed"),
    ] {
        let native = decompile_symbol(&bytes, symbol).unwrap();
        let ir = lower_high_level_cfg_cir(&native.machine_ir, &native.function_ir, &model)
            .unwrap_or_else(|error| panic!("{symbol}: {error}"));
        let c = emit_typed_cfg_c(&ir, &model).unwrap();
        assert!(c.contains("hydir_flag_left") && c.contains("hydir_flag_right"));
        source.push_str(&format!(
            "#define {symbol} {renamed}\n{c}\n#undef {symbol}\n"
        ));
    }
    source.push_str(
        r#"int main(void) {
  const uint64_t edge[] = {0, 1, 2, UINT64_C(0x7fffffffffffffff),
                           UINT64_C(0x8000000000000000), UINT64_MAX};
  for (unsigned i = 0; i < 6; ++i) for (unsigned j = 0; j < 6; ++j) {
    uint64_t a = edge[i], b = edge[j];
    for (uint64_t select = 0; select < 2; ++select)
      if (generated_unsigned(a,b,select) != (a < b)) return 1;
    if (generated_signed(a,b) != ((a ^ UINT64_C(0x8000000000000000)) <
                                  (b ^ UINT64_C(0x8000000000000000)))) return 2;
  }
  uint64_t state = UINT64_C(0xd1b54a32d192ed03);
  for (unsigned i = 0; i < 10000; ++i) {
    state ^= state << 13; state ^= state >> 7; state ^= state << 17;
    uint64_t a = state;
    state ^= state << 13; state ^= state >> 7; state ^= state << 17;
    uint64_t b = state;
    if (generated_unsigned(a,b,i & 1) != (a < b)) return 3;
    if (generated_signed(a,b) != ((a ^ UINT64_C(0x8000000000000000)) <
                                  (b ^ UINT64_C(0x8000000000000000)))) return 4;
  }
  return 0;
}
"#,
    );
    let path = temp.path().join("subtraction_comparisons.c");
    fs::write(&path, source).unwrap();
    for compiler in ["clang", "gcc"] {
        if Command::new(compiler).arg("--version").output().is_err() {
            continue;
        }
        let exe = temp
            .path()
            .join(format!("subtraction_comparisons_{compiler}.exe"));
        let result = Command::new(compiler)
            .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
            .arg(&path)
            .arg("-o")
            .arg(&exe)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{compiler}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(Command::new(exe).status().unwrap().success());
    }
}

#[test]
fn nested_branch_keeps_goto_fallback_and_matches_oracle() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/typed_cfg.S");
    let temp = tempfile::tempdir().unwrap();
    let object = temp.path().join("typed_cfg.o");
    let compile = Command::new("clang")
        .args(["--target=x86_64-unknown-linux-gnu", "-c"])
        .arg(fixture)
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let bytes = fs::read(&object).unwrap();
    let model = init_model(&bytes).unwrap();
    let native = decompile_symbol(&bytes, "hydir_cfg_nested").unwrap();
    let ir = lower_high_level_cfg_cir(&native.machine_ir, &native.function_ir, &model).unwrap();
    let c = emit_typed_cfg_c(&ir, &model).unwrap();
    assert!(c.contains("goto hydir_bb_") && c.contains("if (") && c.contains("} else {"));
    let harness = format!(
        "#include <stdint.h>\n#define hydir_cfg_nested generated_nested\n{c}\n#undef hydir_cfg_nested\nstatic uint64_t oracle(uint64_t a, uint64_t b) {{ if (a < b) return 7; if (a == 0) return b; return a; }}\nint main(void) {{ for (uint64_t a = 0; a < 100; ++a) for (uint64_t b = 0; b < 100; ++b) if (generated_nested(a,b) != oracle(a,b)) return 1; return 0; }}\n"
    );
    let path = temp.path().join("nested.c");
    fs::write(&path, harness).unwrap();
    let exe = temp.path().join("nested.exe");
    let compile = Command::new("clang")
        .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg(path)
        .arg("-o")
        .arg(&exe)
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    assert!(Command::new(exe).status().unwrap().success());
}

#[test]
fn signed_loop_condition_preserves_boundary_order() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/typed_cfg.S");
    let temp = tempfile::tempdir().unwrap();
    let object = temp.path().join("typed_cfg.o");
    let compile = Command::new("clang")
        .args(["--target=x86_64-unknown-linux-gnu", "-c"])
        .arg(fixture)
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let bytes = fs::read(&object).unwrap();
    let model = init_model(&bytes).unwrap();
    let native = decompile_symbol(&bytes, "hydir_cfg_signed_count").unwrap();
    let ir = lower_high_level_cfg_cir(&native.machine_ir, &native.function_ir, &model).unwrap();
    let c = emit_typed_cfg_c(&ir, &model).unwrap();
    assert!(c.contains("while (") && c.contains("0x8000000000000000"));
    let harness = format!(
        "#include <stdint.h>\n#define hydir_cfg_signed_count generated_signed_count\n{c}\n#undef hydir_cfg_signed_count\nstatic uint64_t oracle(int64_t a, int64_t b) {{ uint64_t n=0; for (; a < b; ++a) ++n; return n; }}\nint main(void) {{ int64_t x[] = {{INT64_MIN, INT64_MIN+1, -3, -2, -1, 0, 1, 2, 3, INT64_MAX-1, INT64_MAX}}; for (unsigned i=0;i<11;++i) for (unsigned j=0;j<11;++j) {{ if (x[j] < x[i] || (uint64_t)x[j]-(uint64_t)x[i] > 3) continue; if (generated_signed_count((uint64_t)x[i],(uint64_t)x[j]) != oracle(x[i],x[j])) return 1; }} return 0; }}\n"
    );
    let path = temp.path().join("signed.c");
    fs::write(&path, harness).unwrap();
    let exe = temp.path().join("signed.exe");
    let compile = Command::new("clang")
        .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg(path)
        .arg("-o")
        .arg(&exe)
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    assert!(Command::new(exe).status().unwrap().success());
}

#[test]
fn expression_ir_zeroing_idiom_never_reads_uninitialized_rax() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/typed_cfg.S");
    let temp = tempfile::tempdir().unwrap();
    let object = temp.path().join("typed_cfg.o");
    let compile = Command::new("clang")
        .args(["--target=x86_64-unknown-linux-gnu", "-c"])
        .arg(fixture)
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let bytes = fs::read(&object).unwrap();
    let model = init_model(&bytes).unwrap();
    let native = decompile_symbol(&bytes, "hydir_cfg_zeroing").unwrap();
    let ir = lower_high_level_cfg_cir(&native.machine_ir, &native.function_ir, &model).unwrap();
    let c = emit_typed_cfg_c(&ir, &model).unwrap();
    assert!(c.contains("hydir_rax = UINT64_C(0)"));
    let harness = format!(
        "#include <stdint.h>\n#define hydir_cfg_zeroing generated_zeroing\n{c}\n#undef hydir_cfg_zeroing\nint main(void) {{ for (uint64_t x=0;x<10000;++x) if (generated_zeroing(x) != x) return 1; return 0; }}\n"
    );
    let path = temp.path().join("zeroing.c");
    fs::write(&path, harness).unwrap();
    let exe = temp.path().join("zeroing.exe");
    let compile = Command::new("clang")
        .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg(path)
        .arg("-o")
        .arg(&exe)
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    assert!(Command::new(exe).status().unwrap().success());
}
