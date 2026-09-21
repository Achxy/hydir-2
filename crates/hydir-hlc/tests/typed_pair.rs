use hydir_decompile::decompile_symbol;
use hydir_hlc::{emit_typed_c, lower_high_level_cir};
use hydir_model::{import_dwarf, infer_model, init_model};
use std::{fs, path::PathBuf, process::Command};

#[test]
fn typed_pair_views_compile_and_match_source_for_debug_and_stripped_elf() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/typed_pair.c");
    let temp = tempfile::tempdir().unwrap();
    let source = fs::read_to_string(&fixture).unwrap();
    for debug in [false, true] {
        let input = temp.path().join(if debug {
            "pair_debug.o"
        } else {
            "pair_stripped.o"
        });
        let mut compile = Command::new("clang");
        compile.args(["--target=x86_64-unknown-linux-gnu", "-O2", "-c"]);
        if debug {
            compile.arg("-g");
        }
        let output = compile.arg(&fixture).arg("-o").arg(&input).output();
        let Ok(output) = output else {
            return;
        };
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let bytes = fs::read(&input).unwrap();
        let mut model = init_model(&bytes).unwrap();
        let native_sum = decompile_symbol(&bytes, "hydir_pair_sum").unwrap();
        let native_xor = decompile_symbol(&bytes, "hydir_pair_xor").unwrap();
        if debug {
            assert!(import_dwarf(&bytes, &mut model).unwrap() >= 1);
        } else {
            let inputs = [
                (&native_sum.machine_ir, &native_sum.function_ir),
                (&native_xor.machine_ir, &native_xor.function_ir),
            ];
            let report = infer_model(&mut model, &inputs).unwrap();
            assert_eq!(report.inferred_types, 2);
        }
        for (name, native) in [
            ("hydir_pair_sum", &native_sum),
            ("hydir_pair_xor", &native_xor),
        ] {
            let ir = lower_high_level_cir(&native.machine_ir, &native.function_ir, &model).unwrap();
            let generated = emit_typed_c(&ir, &model).unwrap();
            assert!(generated.contains("->"));
            if debug {
                assert!(generated.contains("left") && generated.contains("right"));
            }
            let c_path = temp.path().join(format!(
                "{name}_{}.c",
                if debug { "debug" } else { "stripped" }
            ));
            fs::write(&c_path, &generated).unwrap();
            let object = temp.path().join(format!(
                "{name}_{}.o",
                if debug { "debug" } else { "stripped" }
            ));
            let result = Command::new("clang")
                .args([
                    "--target=x86_64-unknown-linux-gnu",
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-c",
                ])
                .arg(&c_path)
                .arg("-o")
                .arg(&object)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            if Command::new("gcc").arg("--version").output().is_ok() {
                let gcc_object = temp.path().join(format!("{name}_gcc_{debug}.o"));
                let result = Command::new("gcc")
                    .args(["-std=c11", "-Wall", "-Wextra", "-Werror", "-c"])
                    .arg(&c_path)
                    .arg("-o")
                    .arg(&gcc_object)
                    .output()
                    .unwrap();
                assert!(
                    result.status.success(),
                    "{}",
                    String::from_utf8_lossy(&result.stderr)
                );
            }
            let original_name = format!("original_{name}");
            let generated_name = format!("generated_{name}");
            let harness = format!(
                "#define {name} {original_name}\n{source}\n#undef {name}\n#define {name} {generated_name}\n{generated}\n#undef {name}\nint main(void) {{\n  struct hydir_pair p;\n  for (uint64_t i = 0; i < 10000; ++i) {{\n    p.left = i * UINT64_C(0x9e3779b97f4a7c15);\n    p.right = ~i;\n    if ({original_name}(&p) != {generated_name}((void *)&p)) return 1;\n  }}\n  return 0;\n}}\n"
            );
            let harness_path = temp.path().join(format!(
                "harness_{name}_{}.c",
                if debug { "debug" } else { "stripped" }
            ));
            fs::write(&harness_path, harness).unwrap();
            let exe = temp.path().join(format!(
                "harness_{name}_{}.exe",
                if debug { "debug" } else { "stripped" }
            ));
            let compile = Command::new("clang")
                .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
                .arg(&harness_path)
                .arg("-o")
                .arg(&exe)
                .output()
                .unwrap();
            assert!(
                compile.status.success(),
                "{}",
                String::from_utf8_lossy(&compile.stderr)
            );
            assert!(Command::new(&exe).status().unwrap().success());
            let mut stale = model.clone();
            stale.revision += 1;
            assert!(emit_typed_c(&ir, &stale).is_err());
        }
    }
}
