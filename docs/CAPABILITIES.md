# Capability matrix — 2026-09-17

Legend: **yes** means implemented and tested in this checkout; **partial**
means a restricted contract; **no** means absent. Import never implies safe
lifting or rebuilding.

| Target / operation | Import | Function lift | C output | Patching | Whole-executable rebuild | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| x86-64 little-endian ELF, symbolized, Linux SysV | yes | partial: linear scalar two-argument functions | no | no | no | `hydirctl inspect/lift`, LLVM verification, trusted fixture differential test |
| x86-64 ELF, stripped | partial: sections only | no | no | no | no | Missing symbol rejected |
| x86-64 ELF with branches/calls/memory | yes | no | no | no | no | Unsupported instruction diagnostic |
| Other ELF architectures or endian modes | no | no | no | no | no | Import rejection |
| PE/Mach-O | no | no | no | no | no | Import rejection |

The `ProgramSpec` currently records content hash, target, ABI assertion,
file-derived sections, and ELF symbol facts. It does not yet have mapped
segments, relocations, references, CFG, typed assumptions, instruction bytes
in the serialized model, persistence, or revision histories. It is a versioned
starting model, not the complete contract in the implementation plan.

There is no `hydir` egui executable, `hydird` service, Python SDK, Ghidra
adapter, interprocedural analysis, decompiler, or executable rebuild yet.
