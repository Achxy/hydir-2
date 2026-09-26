use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf, process::Command};

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
}
