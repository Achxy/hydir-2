use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf, process::Command};

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
    assert!(coverage["exact_assignments"].as_u64().unwrap() >= 7);
    assert!(
        coverage["opaque_sites"]
            .as_array()
            .unwrap()
            .iter()
            .any(|site| site["mnemonic"] == "POPCOUNT")
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
    assert_eq!(prefix["emitted_operations"], 7);
    assert_eq!(prefix["verification"], "not_run");
    assert!(prefix["stop_reason"].as_str().unwrap().contains("POPCOUNT"));
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
    assert_eq!(standalone["emitted_operations"], 7);
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
    assert_eq!(trace["executed"].as_array().unwrap().len(), 7);
    assert_eq!(trace["schema_version"], 2);
    assert_eq!(trace["verification"], "not_run");
    assert_eq!(trace["stop"]["kind"], "opaque_boundary");
    assert_eq!(trace["stop"]["source"]["mnemonic"], "POPCOUNT");

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
    let trace: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(trace["start"]["offset"], "0x2013d9");
    assert_eq!(trace["instruction_visits"][1]["offset"], "0x2013e2");
    assert_eq!(trace["events"][0]["kind"], "branch");
    assert_eq!(trace["events"][0]["taken"], true);
    assert_eq!(trace["semantic_fidelity"], "unknown");
}
