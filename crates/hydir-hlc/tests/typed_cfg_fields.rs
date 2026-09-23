use hydir_decompile::decompile_symbol;
use hydir_hlc::{
    HighCfgStatement, HighLevelCfgCir, emit_typed_cfg_c, lower_high_level_cfg_cir,
    validate_high_level_cfg_cir,
};
use hydir_model::{
    ModelEvidence, ModelField, ModelParameter, ModelPrototype, ModelSource, PrimitiveType,
    TypeDefinition, TypeDefinitionKind, TypeRef, init_model, validate_structure,
};
use std::{fs, path::PathBuf, process::Command};

fn fixture() -> (tempfile::TempDir, Vec<u8>) {
    let temp = tempfile::tempdir().unwrap();
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/typed_cfg.S");
    let object = temp.path().join("typed_cfg.o");
    let compile = Command::new("clang")
        .args(["--target=x86_64-unknown-linux-gnu", "-c"])
        .arg(source)
        .arg("-o")
        .arg(&object)
        .output()
        .expect("Clang is required for the CFG fixture");
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let bytes = fs::read(object).unwrap();
    (temp, bytes)
}

fn typed_model(bytes: &[u8]) -> hydir_model::AnalysisModel {
    let mut model = init_model(bytes).unwrap();
    let evidence = vec![ModelEvidence {
        source: ModelSource::AnalystAssertion,
        detail: "fixture context layout".to_owned(),
        site: None,
    }];
    let u64_type = TypeRef::Primitive {
        name: PrimitiveType::U64,
    };
    model.types.push(TypeDefinition {
        id: "hydir_ctx_type".to_owned(),
        name: "hydir_ctx".to_owned(),
        size_bytes: 16,
        size_is_lower_bound: false,
        kind: TypeDefinitionKind::Struct {
            fields: ["seed", "count"]
                .into_iter()
                .enumerate()
                .map(|(index, name)| ModelField {
                    name: name.to_owned(),
                    offset_bytes: (index as u64) * 8,
                    ty: u64_type.clone(),
                    evidence: evidence.clone(),
                })
                .collect(),
        },
        evidence: evidence.clone(),
    });
    model.types.push(TypeDefinition {
        id: "hydir_array_ctx_type".to_owned(),
        name: "hydir_array_ctx".to_owned(),
        size_bytes: 40,
        size_is_lower_bound: false,
        kind: TypeDefinitionKind::Struct {
            fields: vec![
                ModelField {
                    name: "seed".to_owned(),
                    offset_bytes: 0,
                    ty: u64_type.clone(),
                    evidence: evidence.clone(),
                },
                ModelField {
                    name: "slots".to_owned(),
                    offset_bytes: 8,
                    ty: TypeRef::Array {
                        of: Box::new(u64_type.clone()),
                        count: 4,
                    },
                    evidence: evidence.clone(),
                },
            ],
        },
        evidence: evidence.clone(),
    });
    model.types.push(TypeDefinition {
        id: "hydir_ambiguous_type".to_owned(),
        name: "hydir_ambiguous".to_owned(),
        size_bytes: 8,
        size_is_lower_bound: false,
        kind: TypeDefinitionKind::Union {
            fields: vec![
                ModelField {
                    name: "value".to_owned(),
                    offset_bytes: 0,
                    ty: u64_type.clone(),
                    evidence: evidence.clone(),
                },
                ModelField {
                    name: "raw".to_owned(),
                    offset_bytes: 0,
                    ty: TypeRef::Bytes { size: 8 },
                    evidence: evidence.clone(),
                },
            ],
        },
        evidence: evidence.clone(),
    });
    for (symbol, type_id) in [
        ("hydir_cfg_ctx_step", "hydir_ctx_type"),
        ("hydir_cfg_ctx_drain", "hydir_ctx_type"),
        ("hydir_cfg_ctx_shift", "hydir_ctx_type"),
        ("hydir_cfg_ctx_derived_count", "hydir_ctx_type"),
        ("hydir_cfg_ctx_derived_seed", "hydir_ctx_type"),
        ("hydir_cfg_ctx_copy_count", "hydir_ctx_type"),
        ("hydir_cfg_ctx_derived_mutated", "hydir_ctx_type"),
        ("hydir_cfg_ctx_derived_loop", "hydir_ctx_type"),
        ("hydir_cfg_ctx_slot_add", "hydir_array_ctx_type"),
        ("hydir_cfg_ctx_bad_stride", "hydir_array_ctx_type"),
        ("hydir_cfg_memory", "hydir_ambiguous_type"),
    ] {
        let row = model
            .functions
            .iter_mut()
            .find(|row| row.name == symbol)
            .unwrap();
        let mut parameters = vec![ModelParameter {
            name: "ctx".to_owned(),
            ty: TypeRef::Pointer {
                to: Box::new(TypeRef::Named {
                    id: type_id.to_owned(),
                }),
            },
        }];
        if symbol == "hydir_cfg_ctx_slot_add"
            || symbol == "hydir_cfg_ctx_bad_stride"
            || symbol == "hydir_cfg_ctx_derived_loop"
        {
            parameters.push(ModelParameter {
                name: "index".to_owned(),
                ty: u64_type.clone(),
            });
        }
        if symbol == "hydir_cfg_ctx_slot_add" {
            parameters.push(ModelParameter {
                name: "delta".to_owned(),
                ty: u64_type.clone(),
            });
        }
        row.prototype = Some(ModelPrototype {
            parameters,
            return_type: u64_type.clone(),
            calling_convention: "sysv_amd64".to_owned(),
            variadic: false,
        });
        row.evidence.extend(evidence.clone());
    }
    model.revision += 1;
    validate_structure(&model).unwrap();
    model
}

#[test]
fn model_fields_survive_cfg_branches_and_loops_and_compile() {
    let (temp, bytes) = fixture();
    let model = typed_model(&bytes);
    for symbol in [
        "hydir_cfg_ctx_step",
        "hydir_cfg_ctx_drain",
        "hydir_cfg_ctx_shift",
    ] {
        let native = decompile_symbol(&bytes, symbol).unwrap();
        let ir = lower_high_level_cfg_cir(&native.machine_ir, &native.function_ir, &model)
            .unwrap_or_else(|error| panic!("{symbol}: {error}"));
        let json = serde_json::to_vec(&ir).unwrap();
        let round_trip: HighLevelCfgCir = serde_json::from_slice(&json).unwrap();
        assert_eq!(ir, round_trip);
        validate_high_level_cfg_cir(&round_trip).unwrap();
        let views = ir
            .blocks
            .iter()
            .flat_map(|block| &block.statements)
            .filter_map(|statement| match statement {
                HighCfgStatement::Load { field_view, .. }
                | HighCfgStatement::Store { field_view, .. } => field_view.as_ref(),
                HighCfgStatement::Assign { .. } => None,
            })
            .collect::<Vec<_>>();
        if symbol == "hydir_cfg_ctx_shift" {
            assert!(
                views.is_empty(),
                "modified pointer must not carry a stable field name"
            );
        } else {
            assert!(!views.is_empty(), "{symbol} should carry model field names");
            assert!(
                views
                    .iter()
                    .all(|view| view.field == "seed" || view.field == "count")
            );
        }
        let c = emit_typed_cfg_c(&ir, &model).unwrap();
        assert!(c.contains("struct hydir_ctx *ctx"));
        assert!(c.contains("offsetof(struct hydir_ctx, count)"));
        if symbol == "hydir_cfg_ctx_step" {
            assert!(c.contains(
                "hydir_load_u64((hydir_rdi + (uint64_t)offsetof(struct hydir_ctx, count)))"
            ));
            assert!(c.contains("offsetof(struct hydir_ctx, seed)"));
        }
        if symbol == "hydir_cfg_ctx_shift" {
            assert!(c.contains("hydir_load_u64(hydir_rdi)"));
        }
        let oracle = match symbol {
            "hydir_cfg_ctx_step" => {
                "for (uint64_t seed=0; seed<100; ++seed) for (uint64_t n=0; n<100; ++n) { struct hydir_ctx ctx={seed,n}; uint64_t got=hydir_cfg_ctx_step(&ctx); uint64_t want=n ? seed+n : seed; if (got!=want || ctx.count!=(n ? want : 0)) return 1; }"
            }
            "hydir_cfg_ctx_drain" => {
                "for (uint64_t n=0; n<100; ++n) { struct hydir_ctx ctx={0,n}; uint64_t got=hydir_cfg_ctx_drain(&ctx); if (got!=n*(n+1)/2 || ctx.count!=0) return 2; }"
            }
            _ => {
                "for (uint64_t n=0; n<100; ++n) { struct hydir_ctx ctx={7,n}; if (hydir_cfg_ctx_shift(&ctx)!=n) return 3; }"
            }
        };
        let path = temp.path().join(format!("{symbol}.c"));
        fs::write(
            &path,
            format!("{c}\nint main(void) {{ {oracle} return 0; }}\n"),
        )
        .unwrap();
        for compiler in ["clang", "gcc"] {
            if Command::new(compiler).arg("--version").output().is_err() {
                continue;
            }
            let executable = temp.path().join(format!("{symbol}_{compiler}.exe"));
            let output = Command::new(compiler)
                .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
                .arg(&path)
                .arg("-o")
                .arg(&executable)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{symbol} {compiler}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                Command::new(executable).status().unwrap().success(),
                "{symbol} {compiler} oracle failed"
            );
        }
    }
}

#[test]
fn stale_or_forged_field_view_is_rejected() {
    let (_temp, bytes) = fixture();
    let model = typed_model(&bytes);
    let native = decompile_symbol(&bytes, "hydir_cfg_ctx_step").unwrap();
    let ir = lower_high_level_cfg_cir(&native.machine_ir, &native.function_ir, &model).unwrap();
    let mut forged = ir.clone();
    for statement in forged
        .blocks
        .iter_mut()
        .flat_map(|block| &mut block.statements)
    {
        if let HighCfgStatement::Load {
            field_view: Some(view),
            ..
        } = statement
        {
            view.field = "unmodeled".to_owned();
            break;
        }
    }
    assert!(emit_typed_cfg_c(&forged, &model).is_err());
    let mut edited = model.clone();
    edited.revision += 1;
    assert!(emit_typed_cfg_c(&ir, &edited).is_err());
}

#[test]
fn modeled_array_field_keeps_index_arithmetic_and_matches_oracle() {
    let (temp, bytes) = fixture();
    let model = typed_model(&bytes);
    let native = decompile_symbol(&bytes, "hydir_cfg_ctx_slot_add").unwrap();
    let ir = lower_high_level_cfg_cir(&native.machine_ir, &native.function_ir, &model).unwrap();
    let indexed_views = ir
        .blocks
        .iter()
        .flat_map(|block| &block.statements)
        .filter_map(|statement| match statement {
            HighCfgStatement::Load { field_view, .. }
            | HighCfgStatement::Store { field_view, .. } => field_view.as_ref(),
            HighCfgStatement::Assign { .. } => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(indexed_views.len(), 2);
    assert!(
        indexed_views.iter().all(|view| view.field == "slots"
            && view.offset_bytes == 8
            && view.array_index.is_some())
    );
    let json = serde_json::to_vec(&ir).unwrap();
    let round_trip: HighLevelCfgCir = serde_json::from_slice(&json).unwrap();
    assert_eq!(ir, round_trip);
    validate_high_level_cfg_cir(&round_trip).unwrap();
    let c = emit_typed_cfg_c(&ir, &model).unwrap();
    assert!(c.contains("offsetof(struct hydir_array_ctx, slots)"));
    assert!(c.contains("sizeof(((struct hydir_array_ctx *)0)->slots[0])"));
    let source = format!(
        r#"{c}
int main(void) {{
  uint64_t deltas[] = {{0, 1, UINT64_MAX}};
  for (uint64_t i = 0; i < 6; ++i) for (unsigned d = 0; d < 3; ++d) {{
    struct hydir_array_ctx ctx = {{7, {{10, 20, 30, 40}}}};
    uint64_t before[] = {{10, 20, 30, 40}};
    uint64_t got = hydir_cfg_ctx_slot_add(&ctx, i, deltas[d]);
    uint64_t want = i < 4 ? before[i] + deltas[d] : 0;
    if (got != want) return 1;
    for (unsigned j = 0; j < 4; ++j)
      if (ctx.slots[j] != (i == j ? want : before[j])) return 2;
  }}
  return 0;
}}
"#
    );
    let path = temp.path().join("array_field.c");
    fs::write(&path, source).unwrap();
    for compiler in ["clang", "gcc"] {
        if Command::new(compiler).arg("--version").output().is_err() {
            continue;
        }
        let executable = temp.path().join(format!("array_field_{compiler}.exe"));
        let output = Command::new(compiler)
            .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
            .arg(&path)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{compiler}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            Command::new(executable).status().unwrap().success(),
            "{compiler} array oracle failed"
        );
    }
    let mut forged = ir.clone();
    for statement in forged
        .blocks
        .iter_mut()
        .flat_map(|block| &mut block.statements)
    {
        if let HighCfgStatement::Load {
            field_view: Some(view),
            ..
        } = statement
        {
            view.field = "seed".to_owned();
            break;
        }
    }
    assert!(emit_typed_cfg_c(&forged, &model).is_err());
}

#[test]
fn overlapping_union_members_leave_memory_unresolved() {
    let (_temp, bytes) = fixture();
    let model = typed_model(&bytes);
    let native = decompile_symbol(&bytes, "hydir_cfg_memory").unwrap();
    let ir = lower_high_level_cfg_cir(&native.machine_ir, &native.function_ir, &model).unwrap();
    assert!(ir.blocks.iter().flat_map(|block| &block.statements).all(
        |statement| match statement {
            HighCfgStatement::Load { field_view, .. }
            | HighCfgStatement::Store { field_view, .. } => field_view.is_none(),
            HighCfgStatement::Assign { .. } => true,
        }
    ));
    let c = emit_typed_cfg_c(&ir, &model).unwrap();
    assert!(c.contains("hydir_load_u64(hydir_rdi)"));
}

#[test]
fn mismatched_array_stride_keeps_raw_address() {
    let (_temp, bytes) = fixture();
    let model = typed_model(&bytes);
    let native = decompile_symbol(&bytes, "hydir_cfg_ctx_bad_stride").unwrap();
    let ir = lower_high_level_cfg_cir(&native.machine_ir, &native.function_ir, &model).unwrap();
    assert!(ir.blocks.iter().flat_map(|block| &block.statements).all(
        |statement| match statement {
            HighCfgStatement::Load { field_view, .. }
            | HighCfgStatement::Store { field_view, .. } => field_view.is_none(),
            HighCfgStatement::Assign { .. } => true,
        }
    ));
    let c = emit_typed_cfg_c(&ir, &model).unwrap();
    assert!(c.contains("hydir_load_u64(((hydir_rdi + (hydir_rsi * UINT64_C(4))) + UINT64_C(8)))"));
}

#[test]
fn entry_block_derived_pointers_render_fields_and_match_oracles() {
    let (temp, bytes) = fixture();
    let model = typed_model(&bytes);
    for (symbol, field, offset, want_count) in [
        ("hydir_cfg_ctx_derived_count", "count", 8, true),
        ("hydir_cfg_ctx_derived_seed", "seed", 8, false),
        ("hydir_cfg_ctx_copy_count", "count", 0, true),
    ] {
        let native = decompile_symbol(&bytes, symbol).unwrap();
        let ir = lower_high_level_cfg_cir(&native.machine_ir, &native.function_ir, &model)
            .unwrap_or_else(|error| panic!("{symbol}: {error}"));
        let views = ir
            .blocks
            .iter()
            .flat_map(|block| &block.statements)
            .filter_map(|statement| match statement {
                HighCfgStatement::Load { field_view, .. }
                | HighCfgStatement::Store { field_view, .. } => field_view.as_ref(),
                HighCfgStatement::Assign { .. } => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(views.len(), 1, "{symbol}");
        assert_eq!(views[0].field, field);
        let derived = views[0].derived_base.as_ref().unwrap();
        assert_eq!(derived.register, "hydir_rcx");
        assert_eq!(derived.origin_offset_bytes, offset);
        let json = serde_json::to_vec(&ir).unwrap();
        let round_trip: HighLevelCfgCir = serde_json::from_slice(&json).unwrap();
        assert_eq!(ir, round_trip);
        let c = emit_typed_cfg_c(&ir, &model).unwrap();
        assert!(c.contains(&format!("offsetof(struct hydir_ctx, {field})")));
        let expected = if want_count { "ctx.count" } else { "ctx.seed" };
        let source = format!(
            "{c}\nint main(void) {{ for (uint64_t seed=0; seed<100; ++seed) for (uint64_t n=0; n<100; ++n) {{ struct hydir_ctx ctx={{seed,n}}; if ({symbol}(&ctx)!={expected}) return 1; }} return 0; }}\n"
        );
        let path = temp.path().join(format!("{symbol}.c"));
        fs::write(&path, source).unwrap();
        for compiler in ["clang", "gcc"] {
            if Command::new(compiler).arg("--version").output().is_err() {
                continue;
            }
            let executable = temp.path().join(format!("{symbol}_{compiler}.exe"));
            let output = Command::new(compiler)
                .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
                .arg(&path)
                .arg("-o")
                .arg(&executable)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{symbol} {compiler}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                Command::new(executable).status().unwrap().success(),
                "{symbol} {compiler} oracle failed"
            );
        }
        if symbol == "hydir_cfg_ctx_derived_count" {
            let mut forged = ir.clone();
            for statement in forged
                .blocks
                .iter_mut()
                .flat_map(|block| &mut block.statements)
            {
                if let HighCfgStatement::Assign { target, value, .. } = statement {
                    if target == "hydir_rcx" {
                        *value = hydir_hlc::HighExpr::Variable {
                            name: "hydir_rdi".to_owned(),
                        };
                        break;
                    }
                }
            }
            assert!(validate_high_level_cfg_cir(&forged).is_ok());
            assert!(emit_typed_cfg_c(&forged, &model).is_err());
        }
    }
}

#[test]
fn modified_derived_register_keeps_raw_memory_address() {
    let (_temp, bytes) = fixture();
    let model = typed_model(&bytes);
    let native = decompile_symbol(&bytes, "hydir_cfg_ctx_derived_mutated").unwrap();
    let ir = lower_high_level_cfg_cir(&native.machine_ir, &native.function_ir, &model).unwrap();
    assert!(ir.blocks.iter().flat_map(|block| &block.statements).all(
        |statement| match statement {
            HighCfgStatement::Load { field_view, .. }
            | HighCfgStatement::Store { field_view, .. } => field_view.is_none(),
            HighCfgStatement::Assign { .. } => true,
        }
    ));
    let c = emit_typed_cfg_c(&ir, &model).unwrap();
    assert!(c.contains("hydir_load_u64(hydir_rcx)"));
}

#[test]
fn entry_block_derived_pointer_survives_a_loop() {
    let (temp, bytes) = fixture();
    let model = typed_model(&bytes);
    let native = decompile_symbol(&bytes, "hydir_cfg_ctx_derived_loop").unwrap();
    let ir = lower_high_level_cfg_cir(&native.machine_ir, &native.function_ir, &model).unwrap();
    assert!(ir.blocks.len() > 2);
    let views = ir
        .blocks
        .iter()
        .flat_map(|block| &block.statements)
        .filter_map(|statement| match statement {
            HighCfgStatement::Load { field_view, .. }
            | HighCfgStatement::Store { field_view, .. } => field_view.as_ref(),
            HighCfgStatement::Assign { .. } => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].field, "count");
    assert!(views[0].derived_base.is_some());
    let c = emit_typed_cfg_c(&ir, &model).unwrap();
    assert!(c.contains("offsetof(struct hydir_ctx, count)"));
    let source = format!(
        "{c}\nint main(void) {{ for (uint64_t n=0;n<100;++n) for (uint64_t times=0;times<100;++times) {{ struct hydir_ctx ctx={{7,n}}; if (hydir_cfg_ctx_derived_loop(&ctx,times)!=n*times) return 1; }} return 0; }}\n"
    );
    let path = temp.path().join("derived_loop.c");
    fs::write(&path, source).unwrap();
    for compiler in ["clang", "gcc"] {
        if Command::new(compiler).arg("--version").output().is_err() {
            continue;
        }
        let executable = temp.path().join(format!("derived_loop_{compiler}.exe"));
        let output = Command::new(compiler)
            .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
            .arg(&path)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{compiler}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            Command::new(executable).status().unwrap().success(),
            "{compiler} derived loop oracle failed"
        );
    }
}

#[test]
fn lea_index_arithmetic_matches_modular_oracle_without_a_model() {
    let (temp, bytes) = fixture();
    let model = init_model(&bytes).unwrap();
    let native = decompile_symbol(&bytes, "hydir_cfg_lea_index").unwrap();
    let ir = lower_high_level_cfg_cir(&native.machine_ir, &native.function_ir, &model).unwrap();
    let c = emit_typed_cfg_c(&ir, &model).unwrap();
    let source = format!(
        "{c}\nint main(void) {{ uint64_t v[]={{0,1,2,UINT64_MAX,UINT64_C(0x8000000000000000)}}; for(unsigned i=0;i<5;++i) for(unsigned j=0;j<5;++j) if(hydir_cfg_lea_index(v[i],v[j]) != v[i]+v[j]*UINT64_C(8)) return 1; return 0; }}\n"
    );
    let path = temp.path().join("lea_index.c");
    fs::write(&path, source).unwrap();
    let executable = temp.path().join("lea_index.exe");
    let output = Command::new("clang")
        .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg(&path)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(Command::new(executable).status().unwrap().success());
}
