use hydir_backend::import_elf;
use hydir_core::{
    CallingConvention, FactProvenance, FactSource, PrototypeAssertion, ScalarType, StackFact,
};
use std::{fs, process::Command};

#[test]
fn typed_stack_assertion_must_match_a_proven_local() {
    let bytes = include_bytes!("../../../fuzz/corpus/elf_import/stack.elf");
    let directory = tempfile::tempdir().unwrap();
    let binary = directory.path().join("stack.elf");
    let model = directory.path().join("model.json");
    fs::write(&binary, bytes).unwrap();
    let mut spec = import_elf(bytes).unwrap();
    let entry = spec
        .functions
        .iter()
        .find(|function| function.name == "hydir_stack_slot_add")
        .unwrap()
        .address;
    let provenance = FactProvenance {
        source: FactSource::AnalystAssertion,
        scope: "trusted stack fixture".to_owned(),
    };
    spec.typed_model.prototypes.push(PrototypeAssertion {
        id: "prototype-stack-add".to_owned(),
        entry,
        return_type: ScalarType::U64,
        parameters: vec![ScalarType::U64, ScalarType::U64],
        calling_convention: CallingConvention::SysvAmd64,
        provenance: provenance.clone(),
    });
    spec.typed_model.stack_facts.push(StackFact {
        id: "slot-minus-16".to_owned(),
        function_entry: entry,
        entry_rsp_offset: -16,
        width_bits: 64,
        provenance,
    });
    fs::write(&model, serde_json::to_vec(&spec).unwrap()).unwrap();
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_hydirctl"))
            .args([
                "lift-model",
                binary.to_str().unwrap(),
                "hydir_stack_slot_add",
                model.to_str().unwrap(),
            ])
            .output()
            .unwrap()
    };
    let accepted = run();
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    assert!(
        String::from_utf8_lossy(&accepted.stdout)
            .contains("stack assertion: slot-minus-16 offset -16 width 64")
    );

    spec.typed_model.stack_facts[0].entry_rsp_offset = -24;
    fs::write(&model, serde_json::to_vec(&spec).unwrap()).unwrap();
    let rejected = run();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("not a proven eight-byte local"));
}
