# Quick start

Open the checked-in PRISM ELF for a tour of the workbench. Use the smaller
`max2.elf` for a focused command-line walkthrough. Run these commands from the
repository root with Rust 1.96:

```bash
cargo run --locked --bin hydirctl -- doctor
cargo run --locked --bin hydir -- --open-local demo/hydir-prism.elf hydir_stage_decision
cargo run --locked --bin hydirctl -- discover fuzz/corpus/elf_import/max2.elf
cargo run --locked --bin hydirctl -- lift fuzz/corpus/elf_import/max2.elf --function hydir_max2 --ir state
cargo run --locked --bin hydirctl -- decompile fuzz/corpus/elf_import/max2.elf --function hydir_max2 --view unit
```

To reproduce the Ghidra-backed path from the CLI, run the following commands.
HydIR provisions its pinned container on the first analysis; no Ghidra project
setup is required. The GUI starts the same analysis when you open the ELF.

```bash
cargo run --locked -p hydir-cli -- ghidra analyze demo/hydir-prism.elf --output target/prism-ghidra.json --function 0x20137c
cargo run --locked -p hydir-cli -- ghidra-snapshot verify demo/hydir-prism.elf target/prism-ghidra.json
cargo run --locked -p hydir-cli -- ghidra-snapshot coverage demo/hydir-prism.elf target/prism-ghidra.json
cargo run --locked -p hydir-cli -- ghidra trace-calls demo/hydir-prism.elf tests/fixtures/ghidra_prism_call_seed_v1.json --function 0x2013a9
cargo run --locked -p hydir-cli -- ghidra trace-calls tests/fixtures/ghidra_indirect_call.elf tests/fixtures/ghidra_indirect_seed_v1.json --function 0x20117c
cargo run --locked -p hydir-cli -- ghidra llvm-cfg-calls tests/fixtures/ghidra_indirect_call.elf tests/fixtures/ghidra_indirect_seed_v1.json --function 0x20117c --max-functions 2
cargo run --locked -p hydir-cli -- ghidra-snapshot trace-calls tests/fixtures/ghidra_choose_calls.elf tests/fixtures/ghidra_choose_root_v2.json tests/fixtures/ghidra_choose_right_seed_v1.json --callee tests/fixtures/ghidra_choose_right_v2.json --callee tests/fixtures/ghidra_choose_left_v2.json --allocations allocations.json
cargo run --locked -p hydir-cli -- ghidra-snapshot llvm-cfg tests/fixtures/ghidra_indirect_jump.elf tests/fixtures/ghidra_indirect_jump_v2.json
cargo run --locked -p hydir-cli -- ghidra llvm-cfg-image tests/fixtures/hydir-password-gate-stripped.elf --function 0x2016d0 --output target/password-image-llvm.json
cargo run --locked -p hydir-cli -- ghidra-snapshot llvm-cfg-calls demo/hydir-prism.elf tests/fixtures/ghidra_prism_calls_flow_v2.json --callee tests/fixtures/ghidra_prism_leaf_add_v2.json --max-depth 4
```

For the declared-stack example, create `allocations.json` containing
`{"schema_version":1,"regions":[{"kind":"stack","space":"ram","base":7340024,"byte_len":16}]}`.
The declaration bounds memory; the seed supplies any known initial bytes.
For a completed DynamicTrace v3, `ghidra-snapshot rediscover-jumps` produces a
byte-verified, input-specific candidate plan. `rediscover-jumps-apply` runs
targeted Ghidra reanalysis in an isolated project copy and keeps the unknown
computed branch edge in the resulting snapshot.

For a stripped ELF with no function names, open
`tests/fixtures/hydir-password-gate-stripped.elf` in the GUI and select the
recovered function at `0x2016d0`. The P-code view links its loop, `.rodata`
load, and bounded trace to disassembly. On Linux, run
`bash scripts/demo-ghidra-password-lift.sh` to reproduce a fresh automatic
Ghidra export, coverage and CFG LLVM artifacts, and matching versus mismatching
password traces. The script writes its artifacts under
`target/demo-ghidra-password-lift/` and reports both return values. It uses the
same pinned worker as the GUI; `HYDIR_GHIDRA_HOME` can select a local Ghidra
12.1.4 installation for development. `llvm-cfg-image` emits a version 3 module
with up to 64 KiB of validated read-only ELF bytes embedded beside a separate
mutable guest-memory window. Unknown bytes and unsupported effects still stop
explicitly; the existing version 2 LLVM path remains available.

Replace the ELF path and function selector with your own. `discover` returns
FunctionIndex IDs for entries without usable names. The GUI also opens an ELF
through its local file control. The call trace uses a concrete seed and stops
explicitly at unsupported or unresolved call boundaries. In the GUI, open
`hydir_stage_call_chain` and use the Call trace panel with the seed JSON.
The indirect call command exercises bounded automatic export for a concrete
callee. Unknown indirect targets stop without guessing a function.
Automatic call tracing exports the function reached by the seed before spending
its function budget on other static call targets.
The indirect-jump command emits a bounded LLVM path module that dispatches a known
indirect jump to an instruction in the selected function. The call LLVM
commands emit one state machine over the loaded caller and callee snapshots.
The automatic form collects functions reached by the seed; the snapshot form
accepts saved exports. Both share register and RAM state, check return targets, and leave unsupported
effects and missing callees as explicit stops. Its fidelity is still unknown
until a path is compared with Rust, Ghidra, or native execution.
Native CLI commands
cover every IR stage, low-level and structured C, whole-file batch output,
coverage, and per-address explanations.

## Showcase ELF

[`demo/hydir-prism.elf`](../../../demo/hydir-prism.elf) is a ready-to-open, 3.2 KB
Linux x86-64 executable with 13 named functions. Its source is
[`hydir_prism_showcase.S`](../../../tests/fixtures/hydir_prism_showcase.S). Select
`hydir_stage_decision` for a branching CFG and C output, `hydir_stage_stack_mix`
for physical stack state, `hydir_stage_call_chain` for a direct call,
`hydir_stage_loop_sum` for a back edge, and `hydir_stage_record_parent` for
mapped-global effects. `hydir_stage_leaf_add` is a compact Triton example;
`hydir_stage_patch_portal` is sized to demonstrate a verified entry trampoline
into a new ELF copy.

Seven functions have exact native instruction coverage. The Linux entry point
and three `prism_write_*` runtime helpers contain `syscall`; their native C
keeps those instructions as explicit opaque effects. Region Studio and the
C output tab show that low-level C and its fidelity status when structured C
is unavailable. Select `hydir_stage_patch_portal` for the PatchLang
demonstration.

The PRISM presenter guide gives a short GUI route,
commands, and the expected evidence. The binary can be inspected on Windows;
native execution and whole-executable rebuild require Linux x86-64. Triton
requires its optional Python dependency, and remote features require a running
authenticated service.
