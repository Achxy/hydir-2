use hydir_decompile::decompile_symbol;
use hydir_model::{
    ModelSource, PrimitiveType, TypeDefinitionKind, TypeRef, import_dwarf, infer_model, init_model,
    parse_model, validate_model,
};
use std::{fs, path::PathBuf, process::Command};

#[test]
fn dwarf_import_recovers_array_and_recursive_pointer_layout() {
    let source =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/type_layout.c");
    let temp = tempfile::tempdir().unwrap();
    let object = temp.path().join("type_layout.o");
    let output = Command::new("clang")
        .args(["--target=x86_64-unknown-linux-gnu", "-g", "-O0", "-c"])
        .arg(&source)
        .arg("-o")
        .arg(&object)
        .output();
    let Ok(output) = output else {
        return;
    };
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bytes = fs::read(object).unwrap();
    let mut model = init_model(&bytes).unwrap();
    assert_eq!(import_dwarf(&bytes, &mut model).unwrap(), 3);
    assert_eq!(model.revision, 2);
    assert_eq!(import_dwarf(&bytes, &mut model).unwrap(), 0);
    assert_eq!(model.revision, 2);
    let round_trip = parse_model(&serde_json::to_vec(&model).unwrap()).unwrap();
    assert_eq!(round_trip, model);
    assert!(
        model
            .functions
            .iter()
            .all(|function| function.prototype.is_some())
    );
    validate_model(&bytes, &model).unwrap();
    let TypeDefinitionKind::Struct { fields } = &model.types[0].kind else {
        panic!("expected struct")
    };
    assert_eq!(model.types[0].size_bytes, 48);
    assert_eq!(fields[0].offset_bytes, 0);
    assert!(matches!(fields[0].ty, TypeRef::Array { count: 5, .. }));
    assert_eq!(fields[1].offset_bytes, 40);
    assert!(matches!(fields[1].ty, TypeRef::Pointer { .. }));
    let mut bad = model.clone();
    bad.types[0].size_bytes = 40;
    assert!(validate_model(&bytes, &bad).is_err());
    let mut bad = model.clone();
    bad.binary_sha256 = "0".repeat(64);
    assert!(validate_model(&bytes, &bad).is_err());
}

#[test]
fn explicit_layout_keeps_native_agreement_and_disagreement_visible() {
    let source =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/typed_pair.c");
    let temp = tempfile::tempdir().unwrap();
    let object = temp.path().join("typed_pair.o");
    let output = Command::new("clang")
        .args(["--target=x86_64-unknown-linux-gnu", "-g", "-O2", "-c"])
        .arg(&source)
        .arg("-o")
        .arg(&object)
        .output();
    let Ok(output) = output else { return };
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bytes = fs::read(object).unwrap();
    let native = decompile_symbol(&bytes, "hydir_pair_sum").unwrap();
    let mut model = init_model(&bytes).unwrap();
    import_dwarf(&bytes, &mut model).unwrap();
    let type_count = model.types.len();
    let inputs = [(&native.machine_ir, &native.function_ir)];
    let report = infer_model(&mut model, &inputs).unwrap();
    assert_eq!(report.inferred_types, 0);
    assert_eq!(model.types.len(), type_count);
    assert!(model.conflicts.is_empty());
    let TypeDefinitionKind::Struct { fields } = &model.types[0].kind else {
        panic!("expected struct")
    };
    assert!(fields.iter().any(|field| {
        field
            .evidence
            .iter()
            .any(|evidence| evidence.source == ModelSource::NativeAnalysis)
    }));

    let mut edited = init_model(&bytes).unwrap();
    import_dwarf(&bytes, &mut edited).unwrap();
    let TypeDefinitionKind::Struct { fields } = &mut edited.types[0].kind else {
        panic!("expected struct")
    };
    fields[0].ty = TypeRef::Primitive {
        name: PrimitiveType::U32,
    };
    validate_model(&bytes, &edited).unwrap();
    let report = infer_model(&mut edited, &inputs).unwrap();
    assert_eq!(report.inferred_types, 0);
    assert!(!edited.conflicts.is_empty());
    let TypeDefinitionKind::Struct { fields } = &edited.types[0].kind else {
        panic!("expected struct")
    };
    assert_eq!(
        fields[0].ty,
        TypeRef::Primitive {
            name: PrimitiveType::U32
        }
    );
}

#[test]
fn direct_call_constraints_merge_into_caller_aggregate() {
    let source =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/typed_chain.c");
    let temp = tempfile::tempdir().unwrap();
    let object = temp.path().join("typed_chain.o");
    let output = Command::new("clang")
        .args(["--target=x86_64-unknown-linux-gnu", "-O2", "-c"])
        .arg(&source)
        .arg("-o")
        .arg(&object)
        .output();
    let Ok(output) = output else { return };
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bytes = fs::read(object).unwrap();
    let callee = decompile_symbol(&bytes, "hydir_chain_right").unwrap();
    let caller = decompile_symbol(&bytes, "hydir_chain_sum").unwrap();
    let mut model = init_model(&bytes).unwrap();
    let inputs = [
        (&callee.machine_ir, &callee.function_ir),
        (&caller.machine_ir, &caller.function_ir),
    ];
    let report = infer_model(&mut model, &inputs).unwrap();
    assert_eq!(report.inferred_types, 2);
    assert!(report.propagated_parameter_types > 0);
    let caller_row = model
        .functions
        .iter()
        .find(|row| row.entry == caller.machine_ir.entry)
        .unwrap();
    let TypeRef::Pointer { to } = &caller_row.inferred_parameters["rdi"] else {
        panic!("pointer expected")
    };
    let TypeRef::Named { id } = to.as_ref() else {
        panic!("named type expected")
    };
    let TypeDefinitionKind::Struct { fields } =
        &model.types.iter().find(|ty| ty.id == *id).unwrap().kind
    else {
        panic!("struct expected")
    };
    assert_eq!(
        fields
            .iter()
            .map(|field| field.offset_bytes)
            .collect::<Vec<_>>(),
        vec![0, 8]
    );
    assert!(model.conflicts.is_empty());
}

#[test]
fn fixed_array_element_accesses_agree_with_dwarf_bounds() {
    let source =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/typed_array.c");
    let temp = tempfile::tempdir().unwrap();
    let object = temp.path().join("typed_array.o");
    let output = Command::new("clang")
        .args([
            "--target=x86_64-unknown-linux-gnu",
            "-g",
            "-O2",
            "-fno-vectorize",
            "-fno-slp-vectorize",
            "-c",
        ])
        .arg(&source)
        .arg("-o")
        .arg(&object)
        .output();
    let Ok(output) = output else { return };
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bytes = fs::read(object).unwrap();
    let native = decompile_symbol(&bytes, "hydir_array_sum").unwrap();
    let mut model = init_model(&bytes).unwrap();
    import_dwarf(&bytes, &mut model).unwrap();
    let inputs = [(&native.machine_ir, &native.function_ir)];
    infer_model(&mut model, &inputs).unwrap();
    assert!(model.conflicts.is_empty(), "{:?}", model.conflicts);
    let TypeDefinitionKind::Struct { fields } = &model.types[0].kind else {
        panic!("struct expected")
    };
    assert!(fields.iter().any(|field| {
        matches!(field.ty, TypeRef::Array { count: 3, .. })
            && field
                .evidence
                .iter()
                .any(|item| item.source == ModelSource::NativeAnalysis)
    }));
}

#[test]
fn recursive_call_use_proves_a_recursive_pointer_field() {
    let source =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/typed_recursive.c");
    let temp = tempfile::tempdir().unwrap();
    for debug in [false, true] {
        let object = temp.path().join(if debug {
            "recursive_debug.o"
        } else {
            "recursive_stripped.o"
        });
        let mut command = Command::new("clang");
        command.args([
            "--target=x86_64-unknown-linux-gnu",
            "-O1",
            "-fno-optimize-sibling-calls",
            "-c",
        ]);
        if debug {
            command.arg("-g");
        }
        let output = command.arg(&source).arg("-o").arg(&object).output();
        let Ok(output) = output else { return };
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let bytes = fs::read(object).unwrap();
        let native = decompile_symbol(&bytes, "hydir_recursive_sum").unwrap();
        let mut model = init_model(&bytes).unwrap();
        if debug {
            import_dwarf(&bytes, &mut model).unwrap();
        }
        let report = infer_model(&mut model, &[(&native.machine_ir, &native.function_ir)]).unwrap();
        assert!(model.conflicts.is_empty(), "{:?}", model.conflicts);
        if !debug {
            assert!(report.inferred_pointer_fields > 0, "{report:?}");
        }
        let function = model
            .functions
            .iter()
            .find(|row| row.entry == native.machine_ir.entry)
            .unwrap();
        let ty = if debug {
            &function.prototype.as_ref().unwrap().parameters[0].ty
        } else {
            &function.inferred_parameters["rdi"]
        };
        let TypeRef::Pointer { to } = ty else {
            panic!("pointer parameter expected")
        };
        let TypeRef::Named { id } = to.as_ref() else {
            panic!("named referent expected")
        };
        let TypeDefinitionKind::Struct { fields } =
            &model.types.iter().find(|ty| ty.id == *id).unwrap().kind
        else {
            panic!("struct expected")
        };
        let next = fields.iter().find(|field| field.offset_bytes == 8).unwrap();
        assert_eq!(
            next.ty,
            TypeRef::Pointer {
                to: Box::new(TypeRef::Named { id: id.clone() })
            }
        );
    }
}

#[test]
fn incompatible_field_call_types_remain_unresolved() {
    let source =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/typed_conflict.c");
    let temp = tempfile::tempdir().unwrap();
    let object = temp.path().join("typed_conflict.o");
    let output = Command::new("clang")
        .args([
            "--target=x86_64-unknown-linux-gnu",
            "-O1",
            "-fno-optimize-sibling-calls",
            "-c",
        ])
        .arg(&source)
        .arg("-o")
        .arg(&object)
        .output();
    let Ok(output) = output else { return };
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bytes = fs::read(object).unwrap();
    let read_a = decompile_symbol(&bytes, "hydir_read_a").unwrap();
    let read_b = decompile_symbol(&bytes, "hydir_read_b").unwrap();
    let caller = decompile_symbol(&bytes, "hydir_conflicting_next").unwrap();
    let mut model = init_model(&bytes).unwrap();
    let inputs = [
        (&read_a.machine_ir, &read_a.function_ir),
        (&read_b.machine_ir, &read_b.function_ir),
        (&caller.machine_ir, &caller.function_ir),
    ];
    let report = infer_model(&mut model, &inputs).unwrap();
    assert_eq!(report.inferred_pointer_fields, 0);
    assert!(!model.conflicts.is_empty());
    let row = model
        .functions
        .iter()
        .find(|row| row.entry == caller.machine_ir.entry)
        .unwrap();
    let TypeRef::Pointer { to } = &row.inferred_parameters["rdi"] else {
        panic!("pointer expected")
    };
    let TypeRef::Named { id } = to.as_ref() else {
        panic!("named type expected")
    };
    let TypeDefinitionKind::Struct { fields } =
        &model.types.iter().find(|ty| ty.id == *id).unwrap().kind
    else {
        panic!("struct expected")
    };
    let next = fields.iter().find(|field| field.offset_bytes == 8).unwrap();
    assert_eq!(
        next.ty,
        TypeRef::Primitive {
            name: PrimitiveType::U64
        }
    );
}
