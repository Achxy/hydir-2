use hydir_core::Location;
use hydir_loader::import_elf;
use hydir_vm::{
    EvidenceKind, VmContext, VmEdgeKind, VmEvidence, VmFact, VmGuestEffect, VmProfile, VmRange,
    VmStorage, VmVpc, explore_profile, validate_profile,
};
use std::{path::PathBuf, process::Command};

fn fact<T>(value: T, detail: &str) -> VmFact<T> {
    VmFact {
        value,
        evidence: vec![VmEvidence {
            kind: EvidenceKind::AnalystAssertion,
            detail: detail.to_owned(),
            site: None,
        }],
    }
}

fn fixture() -> (Vec<u8>, VmProfile) {
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/vm_whole.S");
    let output_dir = tempfile::tempdir().expect("temporary fixture directory");
    let elf = output_dir.path().join("vm_whole.elf");
    let status = Command::new("clang")
        .args([
            "--target=x86_64-unknown-linux-gnu",
            "-nostdlib",
            "-static",
            "-fuse-ld=lld",
        ])
        .arg(&source)
        .arg("-o")
        .arg(&elf)
        .status()
        .expect("clang is required for the VM fixture");
    assert!(status.success(), "fixture must compile");
    let bytes = std::fs::read(elf).expect("linked fixture bytes");
    let spec = import_elf(&bytes).expect("valid linked fixture");
    let function = |name: &str| -> Location {
        spec.functions
            .iter()
            .find(|function| function.name == name)
            .and_then(|function| function.location)
            .expect("fixture function symbol")
    };
    let bytecode = spec
        .sections
        .iter()
        .find(|section| section.name == ".rodata")
        .expect("bytecode section");
    let bytecode_start = bytecode.location.expect("bytecode location");
    let profile = VmProfile {
        schema_version: 1,
        binary_sha256: spec.binary_sha256,
        entry: fact(
            function("vm_run"),
            "vm_run saves context and enters the interpreter",
        ),
        exits: vec![fact(function("vm_halt"), "vm_halt returns to the caller")],
        vpc: fact(
            VmVpc {
                storage: VmStorage::Register {
                    name: "r12".to_owned(),
                },
                initial_value: Some(bytecode_start),
            },
            "vm_run loads R12 with vm_bytecode",
        ),
        bytecode_ranges: vec![fact(
            VmRange {
                start: bytecode_start,
                size: bytecode.size,
            },
            "the rodata section holds vm_bytecode through vm_bytecode_end",
        )],
        context: fact(
            VmContext {
                entry_register: "rdi".to_owned(),
                base_register: "rbx".to_owned(),
                size: 48,
            },
            "RBX receives the VMState pointer at vm_run",
        ),
        guest_effects: vec![
            fact(
                VmGuestEffect::ContextRange {
                    offset: 40,
                    size: 8,
                },
                "vm_halt writes the guest result",
            ),
            fact(
                VmGuestEffect::Memory {
                    disjoint_from_vm: true,
                },
                "the caller supplies an output pointer disjoint from VM code, bytecode, and state",
            ),
            fact(VmGuestEffect::Call, "vm_call invokes vm_helper"),
            fact(VmGuestEffect::Return, "vm_halt returns the accumulator"),
        ],
    };
    (bytes, profile)
}

#[test]
fn whole_vm_profile_is_binary_pinned_and_does_not_claim_devirtualization() {
    let (bytes, profile) = fixture();
    let report = validate_profile(&bytes, &profile).expect("valid whole VM profile");
    assert_eq!(report.static_bytecode_ranges, 1);
    assert!(report.profile_validated);
    assert!(!report.guest_cfg_recovered);
    assert!(!report.rewrite_ready);

    let mut wrong_binary = profile.clone();
    wrong_binary.binary_sha256 = "0".repeat(64);
    assert!(validate_profile(&bytes, &wrong_binary).is_err());

    let mut wrong_vpc = profile;
    wrong_vpc.vpc.value.initial_value = Some(wrong_vpc.entry.value);
    assert!(validate_profile(&bytes, &wrong_vpc).is_err());
}

#[test]
fn whole_vm_explorer_separates_dispatch_by_vpc_and_reaches_guest_effects() {
    let (bytes, profile) = fixture();
    let report = explore_profile(&bytes, &profile).expect("bounded VM exploration");
    assert_eq!(report.unresolved_edges, 0, "{:?}", report.diagnostics);
    assert!(!report.hit_node_limit);
    assert!(report.unique_vpcs.len() >= 15);
    let spec = import_elf(&bytes).unwrap();
    let dispatcher = spec
        .functions
        .iter()
        .find(|function| function.name == "vm_dispatch")
        .and_then(|function| function.location)
        .unwrap();
    let dispatch_instances = report
        .nodes
        .iter()
        .filter(|node| node.key.host_pc == dispatcher)
        .map(|node| node.key.vpc)
        .collect::<std::collections::BTreeSet<_>>();
    assert!(
        dispatch_instances.len() >= 8,
        "dispatcher must be VPC-sensitive"
    );
    assert!(
        report
            .edges
            .iter()
            .any(|edge| edge.kind == VmEdgeKind::Taken)
    );
    assert!(
        report
            .edges
            .iter()
            .any(|edge| edge.kind == VmEdgeKind::Fallthrough)
    );
    assert!(
        report
            .edges
            .iter()
            .any(|edge| edge.kind == VmEdgeKind::Call)
    );
    assert!(
        report
            .edges
            .iter()
            .any(|edge| edge.kind == VmEdgeKind::Exit)
    );
    assert!(
        report
            .observed_guest_effects
            .iter()
            .any(|effect| effect.contains("guest context write"))
    );
    assert!(
        report
            .observed_guest_effects
            .iter()
            .any(|effect| effect.contains("memory write"))
    );
    assert!(!report.guest_cfg_recovered);
    assert!(!report.rewrite_ready);
}
