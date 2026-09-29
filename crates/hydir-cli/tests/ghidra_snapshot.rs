use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf, process::Command};

#[test]
fn ghidra_project_import_cli_requires_exact_program_selector() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let scratch = tempfile::tempdir().unwrap();
    let project = scratch.path().join("Expert.gpr");
    fs::write(&project, b"project").unwrap();
    let binary = root.join("tests/fixtures/ghidra_userop_rdtsc.elf");
    let output = scratch.path().join("snapshot.json");
    let result = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
        .args(["ghidra", "import-project"])
        .arg(&binary)
        .arg(&project)
        .args(["--program", "folder/*.elf", "--output"])
        .arg(&output)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("wildcard"));
    assert!(!output.exists());
}

#[test]
fn ghidra_simplification_cli_preserves_digest_and_raw_evidence() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let binary = root.join("demo/hydir-prism.elf");
    let snapshot = root.join("tests/fixtures/ghidra_prism_snapshot_v2.json");
    let result = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
        .args(["ghidra-snapshot", "simplify"])
        .arg(&binary)
        .arg(&snapshot)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let artifact: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    let digest = format!("{:x}", Sha256::digest(fs::read(&binary).unwrap()));
    assert_eq!(artifact["binary_sha256"], digest);
    assert_eq!(artifact["before"]["binary_sha256"], digest);
    assert_eq!(artifact["after"]["binary_sha256"], digest);
    assert_eq!(artifact["before"]["entry"], artifact["after"]["entry"]);
    assert_eq!(
        artifact["before"]["instructions"].as_array().unwrap().len(),
        artifact["after"]["instructions"].as_array().unwrap().len()
    );
}

#[test]
fn real_ghidra_rewrite_flows_into_cfg_llvm_with_provenance() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let binary = root.join("tests/fixtures/ghidra_add_zero.elf");
    let snapshot = root.join("tests/fixtures/ghidra_add_zero_v2.json");
    let result = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
        .args(["ghidra-snapshot", "llvm-cfg-simplified"])
        .arg(&binary)
        .arg(&snapshot)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let artifact: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    let digest = format!("{:x}", Sha256::digest(fs::read(&binary).unwrap()));
    assert_eq!(artifact["binary_sha256"], digest);
    assert_eq!(artifact["simplification"]["binary_sha256"], digest);
    assert_eq!(artifact["verification"], "not_run");
    assert_eq!(artifact["semantic_fidelity"], "unknown");
    let rewrites = artifact["simplification"]["rewrites"].as_array().unwrap();
    assert_eq!(rewrites.len(), 1);
    let rewrite = &rewrites[0];
    assert_eq!(rewrite["before"]["mnemonic"], "INT_ADD");
    assert_eq!(rewrite["after"]["mnemonic"], "COPY");
    assert_eq!(rewrite["source_address"]["offset"], "0x201177");
    assert!(
        artifact["llvm"]["source_operations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|op| op["address"] == rewrite["source_address"] && op["mnemonic"] == "COPY")
    );
    assert!(
        artifact["llvm"]["llvm_ir"]
            .as_str()
            .unwrap()
            .starts_with("; Hydir hydir_checked_pcode_simplification concrete CFG path")
    );
}

#[test]
fn real_prism_call_trace_uses_two_binary_bound_snapshots() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let result = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
        .args(["ghidra-snapshot", "trace-calls"])
        .arg(root.join("demo/hydir-prism.elf"))
        .arg(root.join("tests/fixtures/ghidra_prism_calls_flow_v2.json"))
        .arg(root.join("tests/fixtures/ghidra_prism_call_seed_v1.json"))
        .arg("--callee")
        .arg(root.join("tests/fixtures/ghidra_prism_leaf_add_v2.json"))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let trace: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(
        trace["schema_version"],
        hydir_ir::pcode::PCODE_CALL_PATH_VERSION
    );
    assert_eq!(trace["stop"]["kind"], "return");
    assert_eq!(trace["segments"].as_array().unwrap().len(), 3);
    assert_eq!(trace["calls"][0]["callee_entry"]["offset"], "0x2013a2");
    assert_eq!(trace["calls"][0]["return_address"]["offset"], "0x2013b2");
    assert_eq!(trace["final_state"]["register_bytes"]["0"], 12);
    assert_eq!(trace["snapshot_diagnostics"].as_array().unwrap().len(), 0);
}

#[test]
fn real_prism_call_snapshots_emit_one_binary_bound_llvm_module() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let binary = root.join("demo/hydir-prism.elf");
    let result = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
        .args(["ghidra-snapshot", "llvm-cfg-calls"])
        .arg(&binary)
        .arg(root.join("tests/fixtures/ghidra_prism_calls_flow_v2.json"))
        .arg("--callee")
        .arg(root.join("tests/fixtures/ghidra_prism_leaf_add_v2.json"))
        .arg("--max-depth")
        .arg("4")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let artifact: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(artifact["schema_version"], 1);
    assert_eq!(
        artifact["binary_sha256"],
        format!("{:x}", Sha256::digest(fs::read(&binary).unwrap()))
    );
    assert_eq!(artifact["snapshot_sha256"].as_array().unwrap().len(), 2);
    assert_eq!(artifact["function_entries"][1]["offset"], "0x2013a2");
    assert_eq!(artifact["llvm"]["semantic_fidelity"], "unknown");
    assert!(
        artifact["llvm"]["llvm_ir"]
            .as_str()
            .unwrap()
            .contains("%call_depth = alloca i32")
    );
}

#[test]
fn ghidra_function_index_imports_into_analysis_model() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let directory = tempfile::tempdir().unwrap();
    let binary = root.join("demo/hydir-prism.elf");
    let snapshot = root.join("tests/fixtures/ghidra_prism_metadata_v2.json");
    let model = directory.path().join("model.json");
    let imported = directory.path().join("imported.json");

    let init = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
        .args(["model", "init"])
        .arg(&binary)
        .args(["--output"])
        .arg(&model)
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );

    let run = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
        .args(["model", "import-ghidra"])
        .arg(&binary)
        .arg(&model)
        .arg(&snapshot)
        .args(["--output"])
        .arg(&imported)
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let data: serde_json::Value = serde_json::from_slice(&fs::read(&imported).unwrap()).unwrap();
    assert_eq!(data["schema_version"], 1);
    assert!(
        data["functions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|function| {
                function["evidence"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|evidence| evidence["source"] == "ghidra_analysis")
            })
    );

    let verify = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
        .args(["model", "verify"])
        .arg(&binary)
        .arg(&imported)
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );

    let wrong_binary = directory.path().join("wrong.elf");
    fs::write(&wrong_binary, b"not this binary").unwrap();
    let rejected = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
        .args(["model", "import-ghidra"])
        .arg(&wrong_binary)
        .arg(&model)
        .arg(&snapshot)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
}

#[test]
fn ghidra_high_pcode_hints_round_trip_through_model_cli() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let directory = tempfile::tempdir().unwrap();
    let binary = root.join("tests/fixtures/ghidra_prototype.elf");
    let snapshot = root.join("tests/fixtures/ghidra_prototype_high_v2.json");
    let initial = directory.path().join("initial.json");
    let imported = directory.path().join("imported.json");
    let cli = env!("CARGO_BIN_EXE_hydirctl");

    let init = Command::new(cli)
        .args(["model", "init"])
        .arg(&binary)
        .arg("--output")
        .arg(&initial)
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let import = Command::new(cli)
        .args(["model", "import-ghidra"])
        .arg(&binary)
        .arg(&initial)
        .arg(&snapshot)
        .arg("--output")
        .arg(&imported)
        .output()
        .unwrap();
    assert!(
        import.status.success(),
        "{}",
        String::from_utf8_lossy(&import.stderr)
    );
    let model: serde_json::Value = serde_json::from_slice(&fs::read(&imported).unwrap()).unwrap();
    let hints = model["high_pcode_hints"].as_array().unwrap();
    assert!(hints.iter().any(|hint| {
        hint["high_name"] == "node"
            && hint["high_type"]["display_name"] == "Node *"
            && hint["source"] == "ghidra_analysis"
    }));
    let verify = Command::new(cli)
        .args(["model", "verify"])
        .arg(&binary)
        .arg(&imported)
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
}

#[test]
fn pcode_slice_cli_reports_bounded_source_linked_dependencies() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let binary = root.join("demo/hydir-prism.elf");
    let snapshot = root.join("tests/fixtures/ghidra_prism_bit_prefix_v2.json");
    let output = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
        .args(["ghidra-snapshot", "slice"])
        .arg(&binary)
        .arg(&snapshot)
        .args(["--instruction", "0", "--op", "0"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let slice: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(slice["schema_version"], 1);
    assert_eq!(slice["target"]["instruction_index"], 0);
    assert_eq!(slice["path_proven"], false);
    assert!(!slice["steps"].as_array().unwrap().is_empty());
    assert!(slice["steps"][0]["source"]["source_address"]["offset"].is_string());

    let rejected = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
        .args(["ghidra-snapshot", "slice"])
        .arg(&binary)
        .arg(&snapshot)
        .args(["--instruction", "999999", "--op", "0"])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
}

#[test]
fn raw_pcode_snapshot_cli_binds_binary_and_emits_unclaimed_ir() {
    let directory = tempfile::tempdir().unwrap();
    let binary = directory.path().join("sample.bin");
    let snapshot = directory.path().join("snapshot.json");
    fs::write(&binary, [0xc3]).unwrap();
    let digest = format!("{:x}", Sha256::digest([0xc3]));
    let document = json!({
        "schema_version": 2, "source": "ghidra", "flow_overrides_applied": true, "binary_sha256": digest,
        "program": {"name": "sample.bin", "ghidra_version": "12.1.4", "language_id": "x86:LE:64:default", "compiler_spec_id": "gcc", "image_base": {"space": "ram", "offset": "0x0"}},
        "address_spaces": [
            {"name":"const", "id":0, "type":0, "addressable_unit_size":1, "pointer_size":8},
            {"name":"ram", "id":1, "type":1, "addressable_unit_size":1, "pointer_size":8}
        ],
        "functions": [{"entry":{"space":"ram","offset":"0x0"},"name":"f","size":1}],
        "selected_function": {"entry":{"space":"ram","offset":"0x0"},"instructions":[{
            "address":{"space":"ram","offset":"0x0"}, "bytes":"c3", "parsed_bytes":"c3", "mnemonic":"RET",
            "pcode":[{"mnemonic":"RETURN","opcode":10,"sequence_index":0,"sequence_time":0,
                "source_address":{"space":"ram","offset":"0x0"},"output":null,
                "inputs":[{"space":"const","offset":"0x0","size":8}]}]
        }]}
    });
    fs::write(&snapshot, serde_json::to_vec(&document).unwrap()).unwrap();

    let verify = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
        .args(["ghidra-snapshot", "verify"])
        .arg(&binary)
        .arg(&snapshot)
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(summary["pcode_operations"], 1);

    let pcode = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
        .args(["ghidra-snapshot", "pcode"])
        .arg(&binary)
        .arg(&snapshot)
        .output()
        .unwrap();
    assert!(
        pcode.status.success(),
        "{}",
        String::from_utf8_lossy(&pcode.stderr)
    );
    let ir: serde_json::Value = serde_json::from_slice(&pcode.stdout).unwrap();
    assert_eq!(ir["schema_version"], 1);
    assert_eq!(ir["semantic_fidelity"], "unknown");
    assert_eq!(ir["verification"], "not_run");

    fs::write(&binary, [0x90]).unwrap();
    let rejected = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
        .args(["ghidra-snapshot", "verify"])
        .arg(&binary)
        .arg(&snapshot)
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("digest"));
}

#[test]
fn ghidra_project_cli_reopens_a_saved_binary_bound_snapshot() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let directory = tempfile::tempdir().unwrap();
    let binary = directory.path().join("prism.elf");
    let database = directory.path().join("analyst.sqlite");
    let snapshot = root.join("tests/fixtures/ghidra_prism_bit_prefix_v2.json");
    fs::copy(root.join("demo/hydir-prism.elf"), &binary).unwrap();

    let save = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
        .env("HYDIR_LOCAL_DB", &database)
        .args(["ghidra-project", "save"])
        .arg(&binary)
        .arg(&snapshot)
        .output()
        .unwrap();
    assert!(
        save.status.success(),
        "{}",
        String::from_utf8_lossy(&save.stderr)
    );
    let saved: serde_json::Value = serde_json::from_slice(&save.stdout).unwrap();
    assert_eq!(saved["selected_function"]["offset"], "0x2013cf");

    let model_output = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
        .env("HYDIR_LOCAL_DB", &database)
        .args(["local", "model"])
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        model_output.status.success(),
        "{}",
        String::from_utf8_lossy(&model_output.stderr)
    );
    let model: serde_json::Value = serde_json::from_slice(&model_output.stdout).unwrap();
    assert!(
        model["functions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|function| {
                function["evidence"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|evidence| evidence["source"] == "ghidra_analysis")
            })
    );

    let get = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
        .env("HYDIR_LOCAL_DB", &database)
        .args(["ghidra-project", "get"])
        .arg(&binary)
        .args(["--function", "0x2013cf"])
        .output()
        .unwrap();
    assert!(
        get.status.success(),
        "{}",
        String::from_utf8_lossy(&get.stderr)
    );
    let reopened: serde_json::Value = serde_json::from_slice(&get.stdout).unwrap();
    assert_eq!(reopened["binary_sha256"], saved["binary_sha256"]);
    assert_eq!(
        reopened["selected_function"]["entry"],
        saved["selected_function"]
    );

    fs::write(&binary, b"changed binary").unwrap();
    let stale = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
        .env("HYDIR_LOCAL_DB", &database)
        .args(["ghidra-project", "get"])
        .arg(&binary)
        .args(["--function", "0x2013cf"])
        .output()
        .unwrap();
    assert!(!stale.status.success());
}

#[test]
fn imports_snapshot_exported_by_headless_ghidra() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let binary = root.join("demo/hydir-prism.elf");
    let snapshot = root.join("tests/fixtures/ghidra_prism_snapshot_v2.json");
    let output = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
        .args(["ghidra-snapshot", "pcode"])
        .arg(binary)
        .arg(snapshot)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let ir: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(ir["source"], "ghidra_raw_pcode");
    assert_eq!(ir["flow_overrides_applied"], true);
    assert_eq!(ir["instructions"].as_array().unwrap().len(), 5);
    assert_eq!(ir["instructions"][4]["pcode"][2]["mnemonic"], "RETURN");

    let semantic = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
        .args(["ghidra-snapshot", "semantics"])
        .arg(root.join("demo/hydir-prism.elf"))
        .arg(root.join("tests/fixtures/ghidra_prism_snapshot_v2.json"))
        .output()
        .unwrap();
    assert!(
        semantic.status.success(),
        "{}",
        String::from_utf8_lossy(&semantic.stderr)
    );
    let state: serde_json::Value = serde_json::from_slice(&semantic.stdout).unwrap();
    let operations = state["instructions"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|instruction| instruction["operations"].as_array().unwrap());
    let kinds = operations
        .map(|operation| operation["effect"]["kind"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert!(kinds.iter().any(|kind| kind == "assign"));
    assert!(kinds.iter().any(|kind| kind == "opaque"));
    assert_eq!(state["semantic_fidelity"], "unknown");

    let state_output = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
        .args(["ghidra-snapshot", "state"])
        .arg(root.join("demo/hydir-prism.elf"))
        .arg(root.join("tests/fixtures/ghidra_prism_snapshot_v2.json"))
        .output()
        .unwrap();
    assert!(
        state_output.status.success(),
        "{}",
        String::from_utf8_lossy(&state_output.stderr)
    );
    let state_ir: serde_json::Value = serde_json::from_slice(&state_output.stdout).unwrap();
    assert_eq!(state_ir["semantic_fidelity"], "unknown");
    assert_eq!(
        state_ir["instructions"][0]["operations"][0]["accesses"][0]["kind"],
        "read"
    );
    assert_eq!(
        state_ir["instructions"][0]["operations"][0]["accesses"][1]["kind"],
        "write"
    );

    let llvm = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
        .args(["ghidra-snapshot", "llvm-op"])
        .arg(root.join("demo/hydir-prism.elf"))
        .arg(root.join("tests/fixtures/ghidra_prism_snapshot_v2.json"))
        .args(["--instruction", "0x20137c", "--op", "0"])
        .output()
        .unwrap();
    assert!(
        llvm.status.success(),
        "{}",
        String::from_utf8_lossy(&llvm.stderr)
    );
    assert!(String::from_utf8_lossy(&llvm.stdout).contains("define i64 @hydir_pcode_exact"));

    let flow = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
        .args(["ghidra-snapshot", "verify"])
        .arg(root.join("demo/hydir-prism.elf"))
        .arg(root.join("tests/fixtures/ghidra_prism_calls_flow_v2.json"))
        .output()
        .unwrap();
    assert!(
        flow.status.success(),
        "{}",
        String::from_utf8_lossy(&flow.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&flow.stdout).unwrap();
    assert_eq!(summary["call_targets"], 1);
    assert!(summary["flow_edges"].as_u64().unwrap() >= 2);
    let cfg = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
        .args(["ghidra-snapshot", "cfg"])
        .arg(root.join("demo/hydir-prism.elf"))
        .arg(root.join("tests/fixtures/ghidra_prism_calls_flow_v2.json"))
        .output()
        .unwrap();
    assert!(
        cfg.status.success(),
        "{}",
        String::from_utf8_lossy(&cfg.stderr)
    );
    let artifact: serde_json::Value = serde_json::from_slice(&cfg.stdout).unwrap();
    assert_eq!(artifact["cfg_completeness"], "incomplete");
    assert_eq!(artifact["calls"].as_array().unwrap().len(), 1);
    assert_eq!(artifact["binary_sha256"], summary["binary_sha256"]);
    let coverage = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
        .args(["ghidra-snapshot", "coverage"])
        .arg(root.join("demo/hydir-prism.elf"))
        .arg(root.join("tests/fixtures/ghidra_prism_bit_prefix_v2.json"))
        .output()
        .unwrap();
    assert!(
        coverage.status.success(),
        "{}",
        String::from_utf8_lossy(&coverage.stderr)
    );
    let coverage: serde_json::Value = serde_json::from_slice(&coverage.stdout).unwrap();
    assert_eq!(coverage["semantic_fidelity"], "unknown");
    assert!(coverage["exact_assignments"].as_u64().unwrap() >= 10);
    assert!(
        coverage["by_opcode"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["mnemonic"] == "POPCOUNT" && row["exact_assignments"] == 1)
    );

    let prefix = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
        .args(["ghidra-snapshot", "llvm-prefix"])
        .arg(root.join("demo/hydir-prism.elf"))
        .arg(root.join("tests/fixtures/ghidra_prism_bit_prefix_v2.json"))
        .output()
        .unwrap();
    assert!(
        prefix.status.success(),
        "{}",
        String::from_utf8_lossy(&prefix.stderr)
    );
    let prefix: serde_json::Value = serde_json::from_slice(&prefix.stdout).unwrap();
    assert_eq!(prefix["emitted_operations"], 10);
    assert_eq!(prefix["verification"], "not_run");
    assert!(prefix["stop_reason"].as_str().unwrap().contains("CBRANCH"));
    let standalone = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
        .args(["ghidra-snapshot", "llvm-standalone"])
        .arg(root.join("demo/hydir-prism.elf"))
        .arg(root.join("tests/fixtures/ghidra_prism_bit_prefix_v2.json"))
        .output()
        .unwrap();
    assert!(
        standalone.status.success(),
        "{}",
        String::from_utf8_lossy(&standalone.stderr)
    );
    let standalone: serde_json::Value = serde_json::from_slice(&standalone.stdout).unwrap();
    assert_eq!(standalone["emitted_operations"], 10);
    assert!(standalone["state_bytes"].as_u64().unwrap() > 0);
    assert!(
        standalone["llvm_ir"]
            .as_str()
            .unwrap()
            .contains("define i64 @hydir_read_varnode")
    );
    let cfg_llvm = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
        .args(["ghidra-snapshot", "llvm-cfg"])
        .arg(root.join("demo/hydir-prism.elf"))
        .arg(root.join("tests/fixtures/ghidra_prism_bit_prefix_v2.json"))
        .args(["--start", "0x2013d9"])
        .output()
        .unwrap();
    assert!(
        cfg_llvm.status.success(),
        "{}",
        String::from_utf8_lossy(&cfg_llvm.stderr)
    );
    let cfg_llvm: serde_json::Value = serde_json::from_slice(&cfg_llvm.stdout).unwrap();
    assert_eq!(cfg_llvm["start"]["offset"], "0x2013d9");
    assert_eq!(cfg_llvm["semantic_fidelity"], "unknown");
    assert_eq!(cfg_llvm["verification"], "not_run");
    assert!(
        cfg_llvm["llvm_ir"]
            .as_str()
            .unwrap()
            .contains("define i32 @hydir_pcode_cfg")
    );
    assert!(cfg_llvm["source_operations"].as_array().unwrap().len() > 7);
}

#[test]
fn concrete_trace_prefix_uses_binary_bound_seed_and_reports_boundary() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let snapshot_path = root.join("tests/fixtures/ghidra_prism_bit_prefix_v2.json");
    let snapshot: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&snapshot_path).unwrap()).unwrap();
    let seed = serde_json::json!({
        "schema_version": 1,
        "binary_sha256": snapshot["binary_sha256"],
        "entry": snapshot["selected_function"]["entry"],
        "registers": [
            {"offset": "0x38", "size": 8, "value": "0xf0f"},
            {"offset": "0x30", "size": 8, "value": "0xff"}
        ]
    });
    let seed_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(seed_file.path(), serde_json::to_vec(&seed).unwrap()).unwrap();
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_hydirctl"))
            .args(["ghidra-snapshot", "trace-prefix"])
            .arg(root.join("demo/hydir-prism.elf"))
            .arg(&snapshot_path)
            .arg(seed_file.path())
            .output()
            .unwrap()
    };
    let output = run();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let trace: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(trace["executed"].as_array().unwrap().len(), 10);
    assert_eq!(
        trace["schema_version"],
        hydir_ir::pcode::PCODE_EXECUTION_TRACE_VERSION
    );
    assert_eq!(trace["verification"], "not_run");
    assert_eq!(trace["stop"]["kind"], "opaque_boundary");
    assert_eq!(trace["stop"]["source"]["mnemonic"], "CBRANCH");

    let mut wrong = seed.clone();
    wrong["binary_sha256"] = serde_json::json!("0".repeat(64));
    std::fs::write(seed_file.path(), serde_json::to_vec(&wrong).unwrap()).unwrap();
    let rejected = run();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("disagrees with snapshot"));

    let mut overlapping = seed;
    overlapping["registers"][1]["offset"] = serde_json::json!("0x39");
    std::fs::write(seed_file.path(), serde_json::to_vec(&overlapping).unwrap()).unwrap();
    let rejected = run();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("overlap"));
}

#[test]
fn concrete_path_cli_follows_real_ghidra_conditional_branch() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let snapshot_path = root.join("tests/fixtures/ghidra_prism_bit_prefix_v2.json");
    let snapshot: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&snapshot_path).unwrap()).unwrap();
    let seed = serde_json::json!({
        "schema_version": 1,
        "binary_sha256": snapshot["binary_sha256"],
        "entry": snapshot["selected_function"]["entry"],
        "registers": [{"offset": "0x206", "size": 1, "value": "0x1"}]
    });
    let seed_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(seed_file.path(), serde_json::to_vec(&seed).unwrap()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
        .args(["ghidra-snapshot", "trace-path"])
        .arg(root.join("demo/hydir-prism.elf"))
        .arg(&snapshot_path)
        .arg(seed_file.path())
        .args(["--start", "0x2013d9", "--max-ops", "8", "--max-visits", "4"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("seed-only P-code memory"));
    let trace: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(trace["start"]["offset"], "0x2013d9");
    assert_eq!(trace["instruction_visits"][1]["offset"], "0x2013e2");
    assert_eq!(trace["events"][0]["kind"], "branch");
    assert_eq!(trace["events"][0]["taken"], true);
    assert_eq!(trace["semantic_fidelity"], "unknown");
}

#[test]
fn stripped_secure_equals_cli_uses_binary_rodata_without_manual_seed() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let binary = root.join("tests/fixtures/hydir-password-gate-stripped.elf");
    let snapshot = root.join("tests/fixtures/ghidra_password_secure_equals_o1_v2.json");
    let digest = format!("{:x}", Sha256::digest(fs::read(&binary).unwrap()));
    let seed_file = tempfile::NamedTempFile::new().unwrap();
    for (input_head, expected) in [
        ("0x43412d5249445948", 1), // HYDIR-AC
        ("0x43412d5249445968", 0), // hYDIR-AC
    ] {
        let seed = json!({
            "schema_version": 1,
            "binary_sha256": digest,
            "entry": {"space": "ram", "offset": "0x2016d0"},
            "registers": [
                {"offset":"0x38", "size":8, "value":"0x700100"},
                {"offset":"0x30", "size":8, "value":"0xc"},
                {"offset":"0x20", "size":8, "value":"0x700000"},
                {"offset":"0x0", "size":8, "value":"0x0"},
                {"offset":"0x8", "size":8, "value":"0x0"}
            ],
            "memory": [
                {"space":"ram", "byte_offset":"0x700000", "size":8, "value":"0xdeadbeef"},
                {"space":"ram", "byte_offset":"0x700100", "size":8, "value":input_head},
                {"space":"ram", "byte_offset":"0x700108", "size":4, "value":"0x53534543"}
            ]
        });
        fs::write(seed_file.path(), serde_json::to_vec(&seed).unwrap()).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
            .args(["ghidra-snapshot", "trace-path"])
            .arg(&binary)
            .arg(&snapshot)
            .arg(seed_file.path())
            .args(["--max-ops", "2048", "--max-visits", "128"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let trace: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            trace["schema_version"],
            hydir_ir::pcode::PCODE_PATH_TRACE_VERSION
        );
        assert_eq!(trace["binary_sha256"], digest);
        assert_eq!(trace["stop"]["kind"], "return");
        assert_eq!(trace["final_state"]["register_bytes"]["0"], expected);
        assert!(trace["events"].as_array().unwrap().iter().any(|event| {
            event["kind"] == "effect"
                && event["operation"]["source"]["source_address"]["offset"] == "0x2016f0"
                && event["operation"]["memory_access"]["byte_offset"] == 0x2001f0
                && event["operation"]["memory_access"]["value"] == u64::from(b'H')
        }));
        if expected == 1 {
            let calls = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
                .args(["ghidra-snapshot", "trace-calls"])
                .arg(&binary)
                .arg(&snapshot)
                .arg(seed_file.path())
                .args(["--max-ops", "2048", "--max-visits", "128"])
                .output()
                .unwrap();
            assert!(
                calls.status.success(),
                "{}",
                String::from_utf8_lossy(&calls.stderr)
            );
            let call_trace: serde_json::Value = serde_json::from_slice(&calls.stdout).unwrap();
            assert_eq!(call_trace["stop"]["kind"], "return");
            assert_eq!(call_trace["segments"].as_array().unwrap().len(), 1);
            assert_eq!(call_trace["final_state"]["register_bytes"]["0"], 1);
        }
    }
}

#[test]
fn stripped_secure_equals_cli_emits_versioned_binary_bound_image_llvm() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let binary = root.join("tests/fixtures/hydir-password-gate-stripped.elf");
    let snapshot = root.join("tests/fixtures/ghidra_password_secure_equals_o1_v2.json");
    let digest = format!("{:x}", Sha256::digest(fs::read(&binary).unwrap()));
    let image = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
        .args(["ghidra-snapshot", "llvm-cfg-image"])
        .arg(&binary)
        .arg(&snapshot)
        .output()
        .unwrap();
    assert!(
        image.status.success(),
        "{}",
        String::from_utf8_lossy(&image.stderr)
    );
    let image: serde_json::Value = serde_json::from_slice(&image.stdout).unwrap();
    assert_eq!(image["schema_version"], 3);
    assert_eq!(image["binary_sha256"], digest);
    assert_eq!(image["read_only_image"]["space"], "ram");
    assert!(
        image["read_only_image"]["known_byte_count"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(image["llvm_ir"].as_str().unwrap().contains("define i32"));

    let legacy = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
        .args(["ghidra-snapshot", "llvm-cfg"])
        .arg(&binary)
        .arg(&snapshot)
        .output()
        .unwrap();
    assert!(legacy.status.success());
    let legacy: serde_json::Value = serde_json::from_slice(&legacy.stdout).unwrap();
    assert_eq!(legacy["schema_version"], 2);
    assert!(legacy.get("read_only_image").is_none());

    let changed = tempfile::NamedTempFile::new().unwrap();
    let mut tampered = fs::read(&binary).unwrap();
    *tampered.last_mut().unwrap() ^= 1;
    fs::write(changed.path(), tampered).unwrap();
    let wrong_binary = Command::new(env!("CARGO_BIN_EXE_hydirctl"))
        .args(["ghidra-snapshot", "llvm-cfg-image"])
        .arg(changed.path())
        .arg(&snapshot)
        .output()
        .unwrap();
    assert!(!wrong_binary.status.success());
}
