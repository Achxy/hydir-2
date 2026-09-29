# Lifting engine: autonomous execution plan

Status: ready for implementation. Created 2026-09-29 on `lifting-engine` from
`bde1901` (`hydir-launch`). This is the execution plan for the Ghidra-backed
lifting core. [HYDIR_LAUNCH_PLAN.md](HYDIR_LAUNCH_PLAN.md) remains the product
direction; this document defines the next implementation sequence and gates.

## Outcome and scope

An analyst opens a Linux x86-64 ELF in Hydir. Hydir runs its managed Ghidra
worker, presents a source-linked Rust IR and executable LLVM artifact for a
selected function, and states exactly which code, effects, calls, and memory
are understood. For a supported test input, Hydir can identify the first
difference between the original ELF, its Rust execution, and compiled LLVM.
One checked transformation must pass the same comparison before it is offered
for a restricted patch/rebuild workflow.

The existing Hydir GUI, CLI, API, and Python SDK expose the same capabilities.
This plan adds functional views to the GUI without redesigning it. Linux
x86-64 ELF is the release target. Broader architectures, PE, complete OS
emulation, general binary recompilation, and VM guest recovery follow these
gates.

## External software decision

External dependencies are useful when they supply a distinct, well-defined
service. A container makes a dependency reproducible; it does not remove the
need for a working container runtime on the user's machine.

| Software | Role and availability | Decision |
| --- | --- | --- |
| Ghidra 12.1.4 + JDK 21 | Required frontend for the Ghidra-backed workflow; Hydir already offers a managed Docker worker and `HYDIR_GHIDRA_HOME` local fallback | Keep one pinned frontend. The Java script only exports facts; Rust owns semantics, analysis, and LLVM. Record exact Ghidra, exporter, JDK image, and analysis settings in artifacts. |
| Docker-compatible container runtime | Default way to launch the headless worker | Keep the local-Ghidra fallback. `hydirctl doctor` and the GUI must explain missing runtime, offline first build, version mismatch, and cache reuse. Pin the base image by digest, retain Ghidra's notices, and record the built image digest. |
| Clang/LLVM tools | Compile and check lifted LLVM; existing transform/rebuild routes require `opt` 14.0.6 while Ghidra test gates use a newer LLVM toolchain | LLVM export must remain possible without loading LLVM libraries. Pin tool versions per route and report incompatibility; do not silently mix the legacy 14.0.6 path with the current CFG LLVM gate. |
| GDB + Bubblewrap | Linux native capture and differential execution | Validation and optional capture tools, not required to browse or lift a binary. Run untrusted fixture binaries under the existing bounded Linux runner. |
| Triton | Existing optional symbolic bridge | Use for targeted witness generation after the concrete lift is sound. A solver result is evidence for its modeled path, not a binary-equivalence claim. |
| Alive2 | LLVM-to-LLVM local rewrite checking | Optional CI/research tool after a compatible LLVM version is pinned. It does not validate P-code-to-LLVM translation or interprocedural changes. |
| Remill, McSema, Patchestry, angr, rev.ng, Goblin, QEMU | Design and comparison references | No new production dependency. Add one only after a measured gap and a versioned adapter/test contract justify it. Keep existing `object`, `gimli`, and `iced-x86` Rust crates. |

Current worker touchpoints: `integrations/ghidra/Dockerfile.worker` and
`crates/hydir-ghidra-worker/src/lib.rs`. The Ghidra archive has a checked
SHA-256, while the Temurin base currently uses a mutable tag. The worker cache
hashes the Dockerfile text, so a moved base tag could change the image without
changing that text. Fix this before claiming reproducibility across fresh and
cached worker runs. The container already uses no network, read-only root,
dropped capabilities, and CPU/memory/process limits at run time.

Sources: [Ghidra P-code manual](https://ghidra.re/ghidra_docs/languages/html/pcoderef.html),
[Ghidra NOTICE](https://github.com/NationalSecurityAgency/ghidra/blob/master/NOTICE),
[LLVM undefined behavior manual](https://llvm.org/docs/UndefinedBehavior.html),
[Alive2 scope](https://github.com/AliveToolkit/alive2), and
[Remill memory intrinsics](https://github.com/lifting-bits/remill/blob/master/docs/INTRINSICS.md).

## Existing baseline to preserve

- Raw instruction P-code is the semantic input. High P-code, symbols, types,
  and Ghidra's CFG are separately tagged evidence.
- `crates/hydir-ir/src/pcode/semantics.rs` classifies bounded exact scalar
  operations and explicit opaque effects. `execution.rs` executes selected
  memory and control operations with known bytes and explicit stop reasons.
- `image.rs` binds read-only file-backed ELF bytes. `interprocedural.rs`
  follows direct and concretely resolved indirect calls through validated
  snapshots and stops on recursion, missing callees, and budgets.
- `crates/hydir-decompile/src/pcode_cfg_llvm.rs` emits bounded state-machine
  LLVM with source event IDs and known-byte state; its interprocedural artifact
  is built from loaded snapshots and does not assert whole-program fidelity.
- `integrations/ghidra/HydIROracle.java` is an independent bounded Ghidra
  emulator **test** oracle; it is not in the production worker image. Existing
  native GDB and compiled-LLVM gates already cover selected fixtures.
- The current `PcodeCoverageReport` counts pure assignments separately from
  memory/control effects even when another Hydir layer can execute them. It
  is an opcode-classification inventory, not a function usability score.
- The native x86-64 path has a changed-address indirect-target worklist;
  Ghidra-backed `pcode/cfg.rs` retains unresolved targets but does not yet use
  an incremental discovery loop. Preserve both paths and old artifact readers.

## Rules for autonomous execution

Check a phase only after its complete acceptance gate passes, and record the
verifying commit or CI run beside it.

- [ ] L0 capability report
- [ ] L1 differential harness
- [ ] L2 process memory
- [ ] L3 calls
- [ ] L4 discovery
- [ ] L5 analyses and rewriting
- [ ] L6 release gate

1. Work in phase order. Within a phase, make the smallest reviewable code
   change that passes its gate, commit it, and update this document's status.
   Run independent fixture generation or research in parallel when useful.
2. Before editing an interface, inspect its current schema and compatibility
   readers. Add a new artifact version for changed serialized meaning. Old
   ProgramSpec, P-code snapshots, CIR, and low-level C readers stay usable.
3. Add a reproducer for each newly found semantic or CFG mismatch. Fix the
   responsible layer; retain the reproducer in the gate. Do not broaden tests
   after the specific risk is resolved.
4. Every result binds the binary digest, Ghidra snapshot hash/version, Hydir
   analysis version, model revision where relevant, and execution options.
   Unknown bytes, aliases, calls, user operations, and targets remain explicit.
5. Distinguish: **LLVM syntax valid**, **operation modeled**, **selected paths
   matched**, **reachable graph closed under stated assumptions**, and
   **rewrite eligible**. None implies the next automatically. Finite tests
   are observations, not a proof for all inputs.
6. Add each new CLI/core artifact to the API, Python SDK, and existing GUI
   during its phase. The GUI needs a useful display and source navigation;
   visual redesign is outside this plan.
7. Use existing CI gates and extend their path filters for new scripts and
   fixtures. The Ghidra smoke workflow currently triggers push runs only on
   `hydir-launch`; include `lifting-engine` while this branch is active.
8. An unsupported feature is an explicit bounded stop with a source address,
   never a zero-filled value, assumed fallthrough, silent no-op, or exactness
   claim. If a phase meets a true external blocker, record its fixture,
   command, stop reason, and narrower supported scope before proceeding.

## L0 — Make lift capability measurable

**Problem.** The existing opcode inventory cannot tell a user whether a
function can execute through its branches, calls, and memory accesses.

**Build.** Add `PcodeFunctionCapabilityReport v1` in `hydir-ir` with separate
fields for discovered code/edges, executable operations, memory regions,
call closure, unresolved source sites, and observed validation witnesses.
Compute it from validated snapshots and actual executor/emitter support rather
than inferring it from `PcodeEffect::Opaque`. Keep `PcodeCoverageReport v1`
unchanged. Show the report in CLI, v3 API, SDK, and the GUI's P-code view. A
report may say “partial” or “unknown”; it must not call an observed target set
complete.

**Gate.** A real load/store fixture reports those operations as executable
under a supplied memory model; the same operations report a missing-memory
boundary without that model. A direct-call fixture distinguishes loaded and
missing callees. The `RDTSC` userop remains visible as unsupported. JSON
round-trips, binary/snapshot mismatches fail, and old coverage readers pass.

**Touchpoints.** `pcode/coverage.rs`, `pcode/cfg.rs`, `pcode/execution.rs`,
`pcode_cfg_llvm.rs`, CLI/API/SDK/GUI artifact routes.

## L1 — Find the first semantic difference automatically

**Problem.** A passing `opt -verify` or one return-value comparison can miss
wrong flags, memory writes, control flow, and LLVM poison behavior.

**Build.** Extend the existing `HydIROracle.java` and native GDB/compiled LLVM
harnesses into one versioned comparison result. For the same input and initial
state, compare source instruction visits, registers and flags used by the
function, guest-memory writes, return target/value, and stop or fault reason.
Align all four executions at machine-instruction addresses. On mismatch,
report the first differing instruction boundary, the differing bytes, the
binary/snapshot/tool versions, and a runnable seed. Refine to the first
P-code operation only when both compared engines expose operation-level
state; native GDB samples cannot justify that precision.
When the Ghidra oracle itself stops at a call or userop, label that oracle
unavailable and continue with the independent native result.

**Gate.** Existing PRISM, password, aggregate, float, indirect-jump, and frame
fixtures pass their supported paths. Inject one deliberate arithmetic and one
memory discrepancy into test-only copies; the harness identifies their first
source site. Cover signed division overflow, shifts at/above width, carry and
overflow flags, partial-register writes, NaNs, and unknown bytes. Preserve a
new independent source holdout for the final gate.

**Touchpoints.** `integrations/ghidra/HydIROracle.java`,
`tests/ghidra_oracle_test.py`, `scripts/check-ghidra-*.py`, semantic-gate CI.
The current oracle test skips when local Ghidra is unavailable; wire a pinned,
test-only Ghidra installation into CI so this gate is required for supported
cases. This is verification infrastructure, not a new runtime dependency.

## L2 — Model an ELF process's memory

**Problem.** A file-backed read-only window plus one mutable guest-RAM window
cannot represent ordinary writable globals, `.bss`, relocations, stack, heap,
or TLS. The ELF process image is defined by load segments rather than section
names alone.

**Build in slices.**

1. Introduce a bounded sparse guest memory map with per-region address space,
   base, length, permissions, byte values/known mask, source, and load bias.
   Materialize file-backed `PT_LOAD` bytes and zero-fill the `p_memsz-p_filesz`
   tail. Preserve unknown gaps. Bind the map to binary digest and Ghidra
   memory-layout hash; reject overlaps with conflicting bytes/permissions.
2. Add writable initialized globals and stack writes, then selected supported
   ELF relocations/GOT contents. Keep unresolved dynamic-linker work explicit.
   Add bounded heap regions only when an allocation contract supplies them.
3. Make Rust execution and CFG LLVM use the same memory-map contract. Keep
   v2/v3 single-window artifacts readable and make the new ABI a new version.
   Reads/writes outside modeled regions stop before changing state.

**Gate.** A new stripped PIE and non-PIE fixture reads and updates `.data`,
reads zero-initialized `.bss`, aliases a stack slot, and uses a relocated
pointer. Rust and compiled LLVM match native GDB on boundary values and write
order. A missing relocation, unknown region, permission violation, and
conflicting map each produce a precise stop. Existing read-only image tests
continue to pass.

**Touchpoints.** `pcode/image.rs`, `pcode/execution.rs`, `pcode_cfg_llvm.rs`,
ELF loader, worker snapshot validation. References: [ELF program loading](https://refspecs.linuxfoundation.org/elf/gabi4%2B/ch5.pheader.html),
[dynamic linking](https://refspecs.linuxfoundation.org/elf/gabi4%2B/ch5.dynamic.html).

## L3 — Close supported calls and environment effects

**Problem.** Current modules stop at recursion and at calls absent from the
loaded snapshot set. External function prototypes and side effects affect
binary-translation correctness.

**Build in slices.**

1. Define a versioned `CallContract`: target identity, SysV argument/return
   locations, clobbers, memory read/write footprint, possible non-return, and
   evidence source. Keep Ghidra prototypes and analyst edits as evidence until
   ABI mapping validates them. Add a small registry driven by corpus needs,
   initially integer/pointer signatures and selected `strlen`, `memcmp`, and
   `memcpy` behavior over known bounded memory. All other imports stop.
2. Implement bounded recursive call frames and returns in Rust and LLVM,
   retaining explicit depth/step exhaustion and return-address checks. Add
   tail-call handling only where the jump and ABI evidence justify it.
3. Handle PLT/GOT targets under the L2 memory model. Record contract version
   and every external effect in the trace and capability report.

**Gate.** New fixtures cover two internal callees, one recursive function,
one PLT import, and a wrong or missing prototype. Both Rust and compiled LLVM
match native values, relevant state, memory writes, and source visits on
supported cases; the other cases stop at the call site. No host library call
is silently treated as equivalent to the guest call.

**Touchpoints.** `pcode/interprocedural.rs`, `pcode_cfg_llvm.rs`, AnalysisModel
prototype import, worker call collection. References: [Anvill function specification](https://github.com/lifting-bits/anvill/blob/master/docs/SpecificationFormat.md),
[EFACT external-call study](https://arxiv.org/abs/2405.09132),
[McSema limitations](https://github.com/lifting-bits/mcsema/blob/master/docs/Limitations.md).

## L4 — Recover more control flow without hiding uncertainty

**Problem.** Ghidra's analyzed edges can omit or misclassify indirect targets.
The native Hydir path already has a changed-address worklist, but the P-code
path has only an incomplete snapshot CFG. Observed targets cover particular
runs and do not establish the full target set.

**Build.** For Ghidra-backed projects, maintain a bounded worklist of changed
addresses and affected functions. Seed from Ghidra's function index and flow
facts, direct branches, pointer/relocation tables, and separately tagged
execution observations. Re-run target analysis only for affected regions.
Represent `noreturn`, fallthrough changes, tail calls, and overlapping code as
revisable hypotheses with provenance. An indirect edge is closed only under a
stated finite-target proof; otherwise the generated module retains an
unknown-target stop. Invalidate changed functions and callers, not unrelated
artifacts.

**Gate.** A jump-table fixture discovers all oracle targets; an indirect-call
fixture adds an observed target but keeps the unknown edge; a `noreturn` or
tail-call correction revisits the affected upstream site. Budget exhaustion
records the remaining frontier. Repeated analysis produces byte-identical
artifacts under the same versions and options.

**Touchpoints.** `pcode/cfg.rs`, Ghidra snapshot/worker orchestration,
`hydir-decompile/src/lib.rs` native-worklist reference, project dependencies.
References: [rev.ng iterative discovery](https://docs.rev.ng/developer-manual/code-discovery/),
[angr CFG modes](https://docs.angr.io/en/latest/analyses/cfg.html),
[BinRec's observed-path limits](https://people.cs.kuleuven.be/~stijn.volckaert/papers/2020_EuroSys_BinRec.pdf).

## L5 — Make analysis and rewriting usable as a framework

**Problem.** Downstream clients need stable, source-linked facts and explicit
preconditions. Lifted LLVM alone has performed poorly for rigorous pointer
analysis, and a local P-code identity rewrite is not yet a general patch.

**Build in slices.**

1. Expose a minimal versioned pass contract over Hydir PcodeIR/state/CFG:
   required facts, read dependencies, emitted facts, budget, source links,
   assumptions, and invalidation key. Ship one useful built-in pass such as
   bounded value or dependency analysis using this contract. The SDK/API can
   invoke it; loading arbitrary native plugins is a later decision.
2. Make aggregate and alias facts consume the same memory/call evidence and
   retain conflicts. Use the existing AnalysisModel and typed-C path; do not
   assert a struct or pointer target from one observed access.
3. Add a second checked bitvector rewrite to the existing `INT_ADD x,0` pass.
   Require side-effect/order preservation, width preconditions, before/after
   Rust tests, LLVM local validation where applicable, and native differential
   tests for a supported function. Reuse the restricted patch/rebuild route
   only when the separate integration gate passes.

**Gate.** A client pass gets identical source IDs via CLI/API/SDK and GUI. An
edit to one model fact invalidates affected function/caller results while
unaffected functions are reused. A supported rewrite passes all stated checks;
an opaque effect, unknown alias, unresolved edge, or ABI gap blocks patch
eligibility with a reason. Existing low-level C remains available.

**Touchpoints.** `pcode/slice.rs`, `pcode/simplify.rs`, AnalysisModel,
`hydir-project` cache, `hydir-transform`, `hydir-patch`, API/SDK/GUI. References:
[binary-lifter downstream study](https://augusta.elsevierpure.com/en/publications/sok-demystifying-binary-lifters-through-the-lens-of-downstream-ap/),
[Retypd](https://arxiv.org/abs/1603.05495),
[Alive2](https://github.com/AliveToolkit/alive2).

## L6 — Release gate and honest comparison

**Corpus.** Keep existing PRISM/password/aggregate/frame/float fixtures as
regressions. Add at least three independent source programs unseen by the
implementation of L0-L5: writable-global/relocation, recursive/import-heavy,
and indirect-control/alias-heavy. Build relevant variants with GCC and Clang,
O0 and O2, stripped and DWARF-bearing, PIE and fixed-address. Include one
deliberately unsupported userop and one ambiguous target. Record source,
compiler commands/versions, ELF hashes, and native oracle expectations.

**Automated measurements.** For each selected function record: Ghidra import
success; discovered and unresolved blocks/edges; executable operations and
first stop; selected-path native agreement for return, flags, memory, and
source visits; time and peak memory; deterministic artifact hashes; model-edit
invalidation; and whether an attempted rewrite passed its distinct gate.
Use the same task inputs when comparing with Ghidra, angr, or rev.ng; report
their supported task scope rather than a blanket “better” claim.

**Demo go/no-go.** On a prepared machine, opening one unfamiliar stripped ELF
automatically runs the pinned worker and populates the current GUI. Selecting
a function shows linked disassembly, raw P-code, Hydir IR, LLVM, capability
report, and one source-linked analysis. The comparison view identifies a
supported path and an explicit unsupported path. A checked local rewrite of a
supported function passes native execution on held-out inputs. The CLI, SDK,
and API reproduce the same artifact identities. The user never operates
Ghidra or the container directly.

## Deferred work and research watch

- AArch64, PE64, exceptional control flow, self-modifying code, multi-thread
  state, comprehensive SIMD/x87, and general syscalls require new semantic and
  environment gates. A Ghidra language existing does not make Hydir's lift
  correct for that language.
- VM guest CFG, symbolic exploration, and CTF solving can consume the stronger
  memory, call, and evidence model after L2-L4. Triton remains a focused tool.
- General source recompilation or arbitrary binary round trips require a
  separate ABI, relocation, exception, and patch-integration program.
- Research to revisit: [verified x86-64 lifting](https://ssrg.ece.vt.edu/papers/pldi22.pdf),
  [scalable lifter validation](https://cwfletcher.github.io/content/research/2020.pldi.lifters.paper.pdf),
  [SLEIGH specification testing](https://arxiv.org/abs/2608.13042),
  [rev.ng's root lift](https://docs.rev.ng/references/artifacts/), and
  [SAILR structuring](https://www.usenix.org/conference/usenixsecurity24/presentation/basque).
