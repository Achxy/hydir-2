use hydir_decompile::decompile_symbol;
use hydir_hlc::{HighExpr, HighStatement, emit_typed_c, lower_high_level_cir};
use hydir_model::{import_dwarf, init_model};
use std::{fs, path::PathBuf, process::Command};

#[test]
fn direct_call_views_compile_and_match_source_at_o0_and_o2() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/typed_call.c");
    let source = fs::read_to_string(&fixture).unwrap();
    let temp = tempfile::tempdir().unwrap();
    for optimization in ["-O0", "-O2"] {
        let object = temp.path().join(format!("input_{optimization}.o"));
        let output = Command::new("clang")
            .args([
                "--target=x86_64-unknown-linux-gnu",
                optimization,
                "-g",
                "-c",
            ])
            .arg(&fixture)
            .arg("-o")
            .arg(&object)
            .output();
        let Ok(output) = output else { return };
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let bytes = fs::read(&object).unwrap();
        let native = decompile_symbol(&bytes, "hydir_call_wrapper").unwrap();
        let mut model = init_model(&bytes).unwrap();
        assert!(lower_high_level_cir(&native.machine_ir, &native.function_ir, &model).is_err());
        assert!(import_dwarf(&bytes, &mut model).unwrap() > 0);
        let ir = lower_high_level_cir(&native.machine_ir, &native.function_ir, &model).unwrap();
        let c = emit_typed_c(&ir, &model).unwrap();
        let mut wrong_arity = ir.clone();
        for statement in &mut wrong_arity.statements {
            if let HighStatement::Let {
                value: HighExpr::Call { arguments, .. },
                ..
            } = statement
            {
                arguments.clear();
            }
        }
        assert!(emit_typed_c(&wrong_arity, &model).is_err());
        assert!(c.contains("hydir_call_leaf(") && c.contains("hydir_call_wrapper("));
        let generated_file = temp.path().join(format!("generated_{optimization}.c"));
        fs::write(&generated_file, &c).unwrap();
        for compiler in ["clang", "gcc"] {
            let available = Command::new(compiler).arg("--version").output().is_ok();
            if !available {
                continue;
            }
            let output = Command::new(compiler)
                .args([
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-pedantic-errors",
                    "-c",
                ])
                .arg(&generated_file)
                .arg("-o")
                .arg(
                    temp.path()
                        .join(format!("generated_{optimization}_{compiler}.o")),
                )
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{optimization}/{compiler}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let harness = format!(
            "#define hydir_call_wrapper original_wrapper\n{source}\n#undef hydir_call_wrapper\n#define hydir_call_wrapper generated_wrapper\n{c}\n#undef hydir_call_wrapper\nint main(void) {{\n  for (uint64_t i = 0; i < 10000; ++i) {{\n    uint64_t x = i * UINT64_C(0x9e3779b97f4a7c15);\n    if (original_wrapper(x) != generated_wrapper(x)) return 1;\n  }}\n  return 0;\n}}\n"
        );
        let harness_file = temp.path().join(format!("harness_{optimization}.c"));
        let executable = temp.path().join(format!("harness_{optimization}.exe"));
        fs::write(&harness_file, harness).unwrap();
        let output = Command::new("clang")
            .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
            .arg(&harness_file)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{optimization}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(Command::new(executable).status().unwrap().success());
    }
}
