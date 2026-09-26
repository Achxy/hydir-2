//! A self-contained byte-state ABI for bounded exact P-code LLVM prefixes.
//! This provides a runnable comparison target, not whole-function semantics.

use crate::pcode_llvm::emit_pcode_linear_prefix_llvm;
use hydir_ir::pcode::{GhidraSnapshot, PcodeAddress, PcodeVarnode};
use hydir_ir::{SemanticFidelity, VerificationStatus};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const PCODE_STANDALONE_PREFIX_VERSION: u32 = 1;
pub(crate) const MAX_STATE_BYTES: usize = 65_536;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PcodeStateByte {
    pub space: String,
    pub offset: String,
    pub index: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PcodeStandalonePrefixArtifact {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub entry: PcodeAddress,
    pub emitted_operations: usize,
    pub stop_reason: String,
    pub stopped_at: Option<PcodeAddress>,
    pub state_bytes: usize,
    /// Each Ghidra register/unique byte is mapped to one compact state byte.
    /// Overlapping varnodes share entries and therefore alias exactly.
    pub byte_map: Vec<PcodeStateByte>,
    pub llvm_ir: String,
    pub semantic_fidelity: SemanticFidelity,
    pub verification: VerificationStatus,
}

pub(crate) fn node_bytes(
    node: &PcodeVarnode,
    bytes: &mut BTreeSet<(String, u64)>,
) -> Result<(), String> {
    if node.space == "const" {
        return Ok(());
    }
    if !matches!(node.space.as_str(), "register" | "unique") || !(1..=8).contains(&node.size) {
        return Err("standalone P-code state requires a bounded register or unique varnode".into());
    }
    let offset = u64::from_str_radix(
        node.offset
            .strip_prefix("0x")
            .ok_or("invalid P-code offset")?,
        16,
    )
    .map_err(|_| "invalid P-code offset")?;
    for index in 0..node.size {
        let address = offset
            .checked_add(u64::from(index))
            .ok_or("P-code byte address overflows u64")?;
        bytes.insert((node.space.clone(), address));
    }
    Ok(())
}

fn byte_helper(name: &str, byte_map: &[PcodeStateByte], store: bool) -> String {
    let signature = if store {
        format!("define void @{name}(ptr %state, i32 %space, i64 %offset, i8 %value)")
    } else {
        format!("define i8 @{name}(ptr %state, i32 %space, i64 %offset)")
    };
    let mut ir = format!(
        "{signature} {{\nentry:\n  %is_register = icmp eq i32 %space, 1\n  br i1 %is_register, label %register, label %test_unique\n\
         test_unique:\n  %is_unique = icmp eq i32 %space, 2\n  br i1 %is_unique, label %unique, label %missing\n"
    );
    for (space, label) in [("register", "register"), ("unique", "unique")] {
        ir.push_str(&format!(
            "{label}:\n  switch i64 %offset, label %missing [\n"
        ));
        for byte in byte_map.iter().filter(|byte| byte.space == space) {
            ir.push_str(&format!(
                "    i64 {}, label %byte{}\n",
                u64::from_str_radix(&byte.offset[2..], 16).unwrap(),
                byte.index
            ));
        }
        ir.push_str("  ]\n");
    }
    ir.push_str("missing:\n  call void @llvm.trap()\n  unreachable\n");
    for byte in byte_map {
        ir.push_str(&format!(
            "byte{}:\n  %ptr{} = getelementptr i8, ptr %state, i64 {}\n",
            byte.index, byte.index, byte.index
        ));
        if store {
            ir.push_str(&format!(
                "  store i8 %value, ptr %ptr{}\n  ret void\n",
                byte.index
            ));
        } else {
            ir.push_str(&format!(
                "  %value{} = load i8, ptr %ptr{}\n  ret i8 %value{}\n",
                byte.index, byte.index, byte.index
            ));
        }
    }
    ir.push_str("}\n\n");
    ir
}

pub(crate) fn helper_definitions(byte_map: &[PcodeStateByte]) -> String {
    let mut ir = String::from("declare void @llvm.trap()\n\n");
    ir.push_str(&byte_helper("hydir_load_byte", byte_map, false));
    ir.push_str(&byte_helper("hydir_store_byte", byte_map, true));
    ir.push_str(
        "define i64 @hydir_read_varnode(ptr %state, i32 %space, i64 %offset, i32 %size) {\n\
         entry:\n  %length = zext i32 %size to i64\n  br label %loop\n\
         loop:\n  %i = phi i64 [ 0, %entry ], [ %next, %loop ]\n\
           %acc = phi i64 [ 0, %entry ], [ %acc_next, %loop ]\n\
           %address = add i64 %offset, %i\n\
           %byte = call i8 @hydir_load_byte(ptr %state, i32 %space, i64 %address)\n\
           %wide = zext i8 %byte to i64\n\
           %shift = mul i64 %i, 8\n\
           %part = shl i64 %wide, %shift\n\
           %acc_next = or i64 %acc, %part\n\
           %next = add i64 %i, 1\n\
           %continue = icmp ult i64 %next, %length\n\
           br i1 %continue, label %loop, label %done\n\
         done:\n  ret i64 %acc_next\n}\n\n",
    );
    ir.push_str(
        "define void @hydir_write_varnode(ptr %state, i32 %space, i64 %offset, i32 %size, i64 %value) {\n\
         entry:\n  %length = zext i32 %size to i64\n  br label %loop\n\
         loop:\n  %i = phi i64 [ 0, %entry ], [ %next, %loop ]\n\
           %shift = mul i64 %i, 8\n\
           %shifted = lshr i64 %value, %shift\n\
           %byte = trunc i64 %shifted to i8\n\
           %address = add i64 %offset, %i\n\
           call void @hydir_store_byte(ptr %state, i32 %space, i64 %address, i8 %byte)\n\
           %next = add i64 %i, 1\n\
           %continue = icmp ult i64 %next, %length\n\
           br i1 %continue, label %loop, label %done\n\
         done:\n  ret void\n}\n\n"
    );
    ir.push_str("define void @hydir_clear_unique(ptr %state) {\nentry:\n");
    for byte in byte_map.iter().filter(|byte| byte.space == "unique") {
        ir.push_str(&format!(
            "  %clear{} = getelementptr i8, ptr %state, i64 {}\n  store i8 0, ptr %clear{}\n",
            byte.index, byte.index, byte.index
        ));
    }
    ir.push_str("  ret void\n}\n");
    ir
}

/// Emit a runnable, compact state-buffer module for the exact linear prefix.
/// The caller allocates `state_bytes` bytes and seeds entries from `byte_map`.
/// The module returns the number of operations it ran, not a guest return value.
pub fn emit_pcode_standalone_prefix_llvm(
    snapshot: &GhidraSnapshot,
) -> Result<PcodeStandalonePrefixArtifact, String> {
    let prefix = emit_pcode_linear_prefix_llvm(snapshot)?;
    let mut bytes = BTreeSet::new();
    for source in &prefix.source_operations {
        let operation = &snapshot.selected_function.instructions[source.instruction_index].pcode
            [source.operation_index];
        for input in &operation.inputs {
            node_bytes(input, &mut bytes)?;
        }
        if let Some(output) = &operation.output {
            node_bytes(output, &mut bytes)?;
        }
    }
    if bytes.len() > MAX_STATE_BYTES {
        return Err(format!(
            "standalone P-code state exceeds {MAX_STATE_BYTES} bytes"
        ));
    }
    let byte_map = bytes
        .into_iter()
        .enumerate()
        .map(|(index, (space, offset))| PcodeStateByte {
            space,
            offset: format!("0x{offset:x}"),
            index: index as u32,
        })
        .collect::<Vec<_>>();
    let declarations = [
        "declare i64 @hydir_read_varnode(ptr, i32, i64, i32)\n",
        "declare void @hydir_write_varnode(ptr, i32, i64, i32, i64)\n",
        "declare void @hydir_clear_unique(ptr)\n",
    ];
    let mut llvm_ir = prefix.llvm_ir.clone();
    for declaration in declarations {
        if !llvm_ir.contains(declaration) {
            return Err("P-code prefix helper declaration changed".into());
        }
        llvm_ir = llvm_ir.replacen(declaration, "", 1);
    }
    llvm_ir.push('\n');
    llvm_ir.push_str(&helper_definitions(&byte_map));
    Ok(PcodeStandalonePrefixArtifact {
        schema_version: PCODE_STANDALONE_PREFIX_VERSION,
        binary_sha256: prefix.binary_sha256,
        entry: prefix.entry,
        emitted_operations: prefix.emitted_operations,
        stop_reason: prefix.stop_reason,
        stopped_at: prefix.stopped_at,
        state_bytes: byte_map.len(),
        byte_map,
        llvm_ir,
        semantic_fidelity: prefix.semantic_fidelity,
        verification: prefix.verification,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydir_ir::pcode::{PcodeConcreteState, parse_ghidra_snapshot};
    use std::io::Write;
    use std::process::{Command, Stdio};

    #[test]
    fn real_prefix_has_compact_alias_preserving_state_and_verifies() {
        let bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/ghidra_prism_bit_prefix_v2.json"
        ));
        let digest = "4b3d29186ad32957cd12f1f4b581f3cad544903f0c4da152603394cc45ee3bb0";
        let snapshot = parse_ghidra_snapshot(bytes, digest).unwrap();
        let artifact = emit_pcode_standalone_prefix_llvm(&snapshot).unwrap();
        assert_eq!(artifact.emitted_operations, 7);
        assert!(artifact.state_bytes > 0 && artifact.state_bytes < 256);
        assert_eq!(artifact.byte_map.len(), artifact.state_bytes);
        assert!(artifact.llvm_ir.contains("define i64 @hydir_read_varnode"));
        assert!(artifact.llvm_ir.contains("define void @hydir_clear_unique"));
        assert!(!artifact.llvm_ir.contains("declare i64 @hydir_read_varnode"));
        if Command::new("opt").arg("--version").output().is_ok() {
            let mut child = Command::new("opt")
                .args(["-passes=verify", "-disable-output", "-"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(artifact.llvm_ir.as_bytes())
                .unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        if Command::new("lli").arg("--version").output().is_ok() {
            let mut seed = PcodeConcreteState::default();
            for (offset, value) in [("0x38", 0x0f0f_u64), ("0x30", 0x00ff_u64)] {
                seed.write_varnode(
                    &PcodeVarnode {
                        space: "register".to_owned(),
                        offset: offset.to_owned(),
                        size: 8,
                    },
                    value,
                )
                .unwrap();
            }
            let trace = snapshot
                .pcode_function_ir()
                .unwrap()
                .execute_exact_prefix(&seed, 4096)
                .unwrap();
            assert_eq!(trace.executed.len(), artifact.emitted_operations);
            let output_node = snapshot.selected_function.instructions[1].pcode[2]
                .output
                .as_ref()
                .unwrap();
            let expected = trace
                .final_state
                .read_varnode(output_node)
                .unwrap()
                .unwrap() as u8;
            let output_index = artifact
                .byte_map
                .iter()
                .find(|byte| byte.space == "unique" && byte.offset == output_node.offset)
                .unwrap()
                .index;
            let mut main = format!(
                "define i32 @main() {{\nentry:\n  %state = alloca [{} x i8]\n  %base = getelementptr [{} x i8], ptr %state, i64 0, i64 0\n",
                artifact.state_bytes, artifact.state_bytes
            );
            for byte in &artifact.byte_map {
                let value = if byte.space == "register" {
                    seed.read_varnode(&PcodeVarnode {
                        space: byte.space.clone(),
                        offset: byte.offset.clone(),
                        size: 1,
                    })
                    .unwrap()
                    .unwrap_or(0) as u8
                } else {
                    0
                };
                main.push_str(&format!(
                    "  %seed{} = getelementptr i8, ptr %base, i64 {}\n  store i8 {value}, ptr %seed{}\n",
                    byte.index, byte.index, byte.index
                ));
            }
            main.push_str(&format!(
                "  %count = call i32 @hydir_pcode_prefix(ptr %base)\n  %result_ptr = getelementptr i8, ptr %base, i64 {output_index}\n  %result = load i8, ptr %result_ptr\n  %return = zext i8 %result to i32\n  ret i32 %return\n}}\n"
            ));
            let file = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(file.path(), format!("{}\n{main}", artifact.llvm_ir)).unwrap();
            let output = Command::new("lli").arg(file.path()).output().unwrap();
            assert_eq!(
                output.status.code(),
                Some(i32::from(expected)),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
