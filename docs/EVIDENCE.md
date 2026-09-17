# HydIR evidence — 2026-09-18

## Bounded analyzed-program overlay — 2026-09-18

The `analyze-spec` operation joins symbol-bounded call and memory-reference
instruction sites to the v2 ELF inventory. Five analysis unit tests now
check direct call targets, mapped-global references, unresolved/indirect
calls, recursive effect propagation, and that a syscall is not fabricated as
an ordinary function call. The ordinary `inspect` result still reports
`not_attempted` call/reference recovery; the analyzed view reports
`partial`. Both outputs retain string-encoded virtual addresses and an
explicit SHA-256 identity.

On macOS, `cargo test --locked --offline --workspace` passed **40 Rust
tests**. Seven Python SDK unit tests passed using the pinned local SDK
environment. `cargo fmt --all`, `git diff --check`, and `bash -n` for the
modified demo scripts passed. The installed pinned macOS Rust toolchain does
not provide an applicable Clippy binary, so no final-tree Clippy result is
claimed here. The generated Python protobuf bindings were regenerated with
`grpcio-tools==1.84.0` and imported by the SDK unit suite.

A separate local authenticated `hydird`/`hydirctl` loopback test on macOS
used the linked `global-effects` ELF from the retained trusted fixture
artifacts. Discovery advertised `analyzed_program_spec`; explicit upload and
`remote analyze-spec` returned partial call/reference states, a nullable
indirect target, and the analysis-contract assumption. A second identity's
cross-project `analyze-spec` request was denied. The Python
`examples/global_analysis.py` client uploaded the fixture through the SDK
and saved both the report and analyzed specification. Retained non-secret
outputs are under `target/demo-analyzed-spec-mac/`. The two generated token
files were removed after the service stopped; the ignored test database and
project artifacts must still not be published.

The updated Linux `demo-analysis.sh`, `demo-remote.sh`, and `demo-sdk.sh`
assert this operation, but were **not run** on this final tree. Docker
Desktop did not become responsive during this run; its older backend log
records a no-space startup error, which is not proof of the current cause.
The prior Linux corpus and rebuild counts below belong to earlier commits,
not a fresh run of this overlay. No broader recovery or hostile-input claim
follows from the macOS RPC test.

## Upstream revision and notice boundary — 2026-09-18

`git ls-remote` and a fresh 405-path checkout both resolved IRENE-3 `main`
to `d97aee937ebb6d1cb8a362748c56414404eb75ff`. Its root AGPLv3 text
matches this repository's `LICENSE` byte-for-byte, while upstream Ghidra,
grammar, Scala, version-helper, Gradle, and LLVM-derived files carry distinct
Apache, BSD, MIT, and LLVM-exception notices. The exact scoped findings are
in [the source/license inventory](UPSTREAM_LICENSE_AUDIT.md). No upstream
implementation code was copied or built. This does not close transitive
redistribution notices, submodule audits, or legal review.

## ProgramSpec v2 inventory and bounded inspection — 2026-09-18

The native ELF inspection path now reports `PT_LOAD` file/memory mappings and
permissions, the ELF entry, dynamic imports, section/dynamic relocations, and
typed provenance. Dynamic relocation targets are resolved against `.dynsym`;
the first live inspection exposed and corrected a wrong ordinary-symbol-table
lookup. Calls/references remain explicitly `not_attempted`, and the OS is not
inferred as Linux from a generic System V ELF OSABI. Count/name limits reject
excessive metadata rather than emitting an unbounded inspection response.

On the final v2 tree, a pinned Linux x86-64 Docker run of `cargo test --locked
--workspace` passed **38 Rust tests**, workspace `cargo clippy --locked
--workspace --all-targets -- -D warnings` passed, and
`scripts/demo-analysis.sh`, `scripts/demo-remote.sh`, and
`scripts/demo-recompile.sh` all exited 0. Their new artifacts are
`target/demo-analysis/run.nQuJK6/`, `target/demo-remote/run.gEnOHw/`, and
`target/demo-recompile/run.fjsI5n/`. The remote test again exercised v2
inspection through a separate authenticated client/server and project
reopening; the three complete-program fixtures again matched all five
controlled stdout/stderr/exit cases.

Before adding the final metadata limits, `scripts/demo-linux-docker.sh`
passed the workspace test/Clippy stages and the complete local scalar and
stripped-function differential demo in `target/demo-local/run.fiV0GX/`.
The local v2 fixture asserted nonempty load mapping data, unrecovered call
state, and a correctly named dynamic relocation target. The integrated run
was intentionally stopped during the 16-function corpus after the first
function passed 1,008/1,008 raw-LLVM/native and 1,008/1,008 compiled-C/native
cases. It is **not** counted as a completed integrated run for this commit.
The earlier full 21,168-pair corpus result below is for the preceding code
revision; the scalar lift/C backends were not modified in this v2 change.
The current complete local demo result precedes only the metadata bounds,
which are covered by final-tree unit, remote, and rebuild gates. No general
equivalence or hostile-input safety claim follows from these fixtures.

## Shared local/remote rebuild and workbench operations — 2026-09-18

`bash scripts/demo-linux-docker.sh` exited 0 on the macOS Apple Silicon host
running the pinned Linux x86-64 image (Rust 1.96.0, Debian Clang/LLVM
14.0.6). The run passed **34 Rust tests** and workspace Clippy with
`-D warnings`. Retained outputs are `target/demo-local/run.QPv9E4/`,
`target/demo-corpus/run.S6xag3/`, `target/demo-analysis/run.pSR2ZX/`,
`target/demo-passes/run.k2WQow/`, `target/demo-patch/run.QBv5E2/`,
`target/demo-remote/run.jHYm7i/`, and
`target/demo-recompile/run.vs8g1v/`. The 20 distinct scalar functions and a
stripped variant again matched **21,168/21,168 raw-LLVM/native** and
**21,168/21,168 compiled-C/native** controlled input pairs. The three
freestanding complete programs rebuilt into new executables and matched
five controlled stdout/stderr/exit cases. Five deliberate semantic
unsupported cases were rejected. These are trusted fixtures, not general
equivalence or a hostile-input security evaluation.
After that integrated run, two headless GUI state-transition tests were
added. A targeted Linux `cargo test --locked --workspace` then passed **36
Rust tests**, and workspace Clippy again passed with `-D warnings`. The two
tests check that an ambiguous remote mutation forces reopen/clears privileged
state and that a local pass result updates verified views and resets trust.

The separate-process remote demo exercised authenticated upload, global
analysis, scalar C, a named pass experiment, scalar patch, and a whole-ELF
rebuild. The remote rebuild created revision 2 with owner-scoped IR, ELF, and
report artifacts. It matched three controlled client-side inputs, survived
restart and exact-key retry without a third revision, and denied a second
identity. The egui headless operation probes separately exercised local and
remote pass, patch, and rebuild/export functions. They are not a visual UI
interaction test. A subsequent macOS run used `hydir --open-local <trusted
ELF> hydir_max2` and visually inspected the populated function tree, selected
disassembly row, CFG summary, and inspector at
`target/visual-qa/hydir-populated-collapsed.png`.
The optional mutation controls were collapsed after an earlier capture showed
them pushing function facts below the fold. Direct pointer/keyboard control of
the eframe canvas was not reliably established, so this is a render/initial-
selection smoke check, not full visual interaction QA. The service never
executed the samples.

`bash scripts/demo-sdk-linux-docker.sh` exited 0 with the SDK image and
retained `target/demo-sdk/run.5Kuqam/`. Its seven Python boundary tests,
separate-client smoke, typed remote rebuild, digest-checked artifact export,
and three controlled client-side behavior comparisons passed. Separately,
`sdk/python/examples/validate_program.py` saved
`target/demo-remote/run.y382s5/sdk-docker-validation.json` with **3/3**
matched original/rebuilt choice cases under no-network, read-only,
resource-limited Docker runs. An initial attempt with an eight-second outer
timeout expired while Docker was under concurrent build load; a thirty-second
startup bound plus a five-second in-container execution bound then passed.
Omitting the required `--trusted-fixture` flag exited 2 before execution.
The Docker controls are not a proof of safe hostile execution.

An earlier integrated run on this date reached the pass/patch gates but
exited during a concurrent Cargo manifest/lockfile edit (`--locked` refused
the in-progress lockfile). After the lockfile settled, the full unchanged
gate above passed. Matching-source verification for this new code revision
must be repeated after a clean commit; previous source-offer hashes below are
historical, not evidence for this tree. No release, public service, push, or
deployment was made.

## Revisioned remote pass and integrated checkpoint — 2026-09-18

`bash scripts/demo-linux-docker.sh` exited 0 with pinned Rust 1.96.0 and
Debian Clang/LLVM 14.0.6. The retained outputs are
`target/demo-local/run.9uLItp/`, `target/demo-corpus/run.MmwQbR/`,
`target/demo-analysis/run.QmNtdc/`, `target/demo-passes/run.WE3Dkw/`,
`target/demo-patch/run.nr5jmq/`, `target/demo-remote/run.bYNYmw/`, and
`target/demo-recompile/run.tjaZ3O/`. Across 20 distinct supported scalar
functions and a stripped variant, the local/corpus gates again observed
**21,168/21,168 compiled-C/native** and **21,168/21,168 raw-LLVM/native**
matches. These are trusted-fixture tests, not an equivalence proof. The
whole-program gate rebuilt three static freestanding ELFs and matched five
controlled stdout/stderr/exit cases. The integrated cross-function,
allowlisted pass, and scalar patch gates also exited 0.

`bash scripts/demo-remote.sh` exited 0 again after the final service
refactor in `target/demo-remote/run.XXNJQa/`. An authenticated owner created
an LLVM pass result as revision 2 while retaining the uploaded ELF hash,
verified the transformed IR, retrieved the artifact after service restart,
replayed the same idempotency key without a third revision, and rejected a
changed request using that key. A second identity was denied access. The
same demo also verified remote C compilation, a deliberate scalar ELF patch,
durable lift-job replay/cancellation, and owner isolation. `cargo test
--locked --workspace` then passed **33 Rust tests** on Linux, workspace
Clippy passed with `-D warnings`, and **6 Python SDK boundary tests** passed.
The revised separate-process Python SDK smoke script has not yet been run;
SDK transform integration is covered by the shared protocol/CLI demo and SDK
boundary tests, not claimed as separately executed Python integration.

Source-offer verification is tied to an exact clean commit and must be
repeated for each new HEAD. The earlier clean-revision result below is
historical; current source-offer results live under `target/demo-source/`.
This checkpoint is not a public release or a hostile-input sandbox.

## Scalar patch and matching-source checkpoint — 2026-09-17

`bash scripts/demo-patch.sh` exited 0 in
`target/demo-patch/run.EzQOzL/`. Its trusted source fixture was patched
from addition to subtraction through the versioned C-like return-expression
AST. Four declared patched outputs matched expected modular-u64 results;
stderr stayed empty and exit status stayed zero for original and patched
runners. The `cases.tsv` and per-case output files are retained. A first
case explicitly differed from the original, as an intentional patch should.
The gate also refused a replacement needing 11 bytes in a five-byte
function, a wrong input hash, and an existing output path; it created no
output for the first two refusals. This is not an equivalence proof or a
general patch-region workflow.

`bash scripts/demo-remote.sh` exited 0 in
`target/demo-remote/run.tRzScz/` after the remote patch API was added. The
owner uploaded `hydir_max2` at revision 1, applied a subtraction patch to
create revision 2, observed the changed output for input `(9,4)`, recovered
the patched ELF after server restart, replayed the idempotent request without
creating revision 3, and denied a second identity's attempt to patch the
first project. The server never executed either ELF. The patch output was
only executed by the trusted demo client.

For the pre-patch clean revision `ceb7eb42a04b19b3d431eb2c0d9a06bdccd29dee`,
`bash scripts/demo-source-offer.sh` exited 0 in
`target/demo-source/run.7KOWxM/`. The archive advertised and returned by
the authenticated service was byte-identical to `git archive` for that
revision, with SHA-256
`3037a95bbf1f12dafc34fda01e52e6682e707a3ec1424d9470cb0594b17a4747`.
This tests technical source matching, not license sufficiency or publication.
After any patch/API or other tracked change, the source-offer gate must be
rerun for the new clean commit before distribution.

The latest Linux Docker `cargo test --locked --workspace` run passed **31
Rust tests**, and workspace Clippy passed with `-D warnings`. Five Python
SDK boundary tests passed. The remote patch demo was run before the final
CLI output-existence preflight change; that change has compiled and passed
workspace tests, and the integrated demo will be rerun before final handoff.

## Scalar C and remote C checkpoint — 2026-09-17

`hydir-c` emits C11 from the raw, machine-byte-derived scalar LLVM lift,
with explicit CFG labels and parallel SSA phi edge copies. It is not
Rellic, high-level structuring, or general LLVM-to-C. The Linux x86-64
`demo-corpus.sh` run exited 0 in `target/demo-corpus/run.chVCwq/`:
16/16 distinct functions produced LLVM and C, both compiled, and each
matched the original on 1,008 controlled input pairs. Thus this new lane
had **16,128/16,128 compiled-C/native matches** with no observed mismatch.
`demo-local.sh` separately exited 0 in `target/demo-local/run.pGSnye/`:
four symbolized functions plus one stripped-address variant each had
**1,008/1,008 compiled-C/native matches**, adding 5,040 comparisons.
Combined scalar C evidence is **21 supported variants and 21,168/21,168
observed matches** across 20 distinct functions; the unsupported `push`
variant remains rejected before C generation. The same inputs were tested
for the raw LLVM path. All execution validation was unsandboxed and limited
to trusted fixtures.

The authenticated, separate-process `demo-remote.sh` run exited 0 in
`target/demo-remote/run.mBvVaK/`: it generated a C artifact for
`hydir_max2`, compiled and compared three inputs against the original,
retrieved the same SHA-256-addressed C bytes after a service restart,
and denied another identity access to that artifact. The SDK's four local
boundary tests passed. Linux Docker `cargo test --locked --workspace`
passed **29 Rust tests** and workspace Clippy passed with `-D warnings`.
The GUI C view compiled and its remote headless probe passed; visual
interaction with that view was not established. Source-offer embedding and
retrieval are implemented but not counted as verified in this checkpoint
until the clean-tree source-offer demo runs.

| Corpus unit | Attempted | Supported | Lifted | IR-valid | Executable LLVM | LLVM matches | C-generated/compiled | C matches | Whole-program rebuilt |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Scalar variants | 22 | 21 | 21 | 21 | 21 | 21,168 input pairs | 21 | 21,168 input pairs | 0 |

## Twenty-function scalar corpus checkpoint — 2026-09-17

The macOS `cargo run --locked --bin hydir` launch compiled and opened a real
desktop window. Its initial empty state was visually inspected: dark-first
three-pane layout, explicit local ELF entry, labelled remote-transfer section,
disabled analysis/job actions, and a visible “No project open” diagnostic.
The GUI canvas did not expose addressable controls to the available
accessibility interface; an attempted click did not reliably target the
program input, so file-open and function-selection interaction were **not**
visually verified. Automation was stopped, the app was closed, and temporary
screen captures containing unrelated desktop content were removed. The
existing headless GUI probes remain the functional UI-path evidence.

The final `bash scripts/demo-linux-docker.sh` exited 0 with the new corpus
gate integrated. Rust 1.96.0 ran **27 passing unit tests**, workspace Clippy
passed with `-D warnings`, and pinned Clang/LLVM 14.0.6 handled every LLVM
module. The original `demo-local.sh` variants matched **5,040/5,040**
boundary/seeded cases in `target/demo-local/run.TrJWrj/`. The added
`demo-corpus.sh` gate matched **16,128/16,128** cases across 16 new distinct
functions in `target/demo-corpus/run.xCv35Y/`, each with 8 boundary inputs,
1,000 seeded pairs, an LLVM-verifier pass, and a retained JSON report. The
new functions include identity, wrapping arithmetic, signed/unsigned minima
and predicates, bit overlap, and bounded loops. Combined, this is **20
distinct supported functions**, **21 supported variants** including the
stripped max fixture, and **21,168/21,168 observed comparisons**. The
deliberately unsupported `push` function is a 22nd attempted variant and was
rejected. These results are not an equivalence proof or optimized/stack/
buffer coverage.

| Corpus unit | Attempted | Supported | Lifted | IR-valid | Executable lifted form | Behaviorally matched | C-generated | Whole-program rebuilt |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Scalar function variants | 22 | 21 | 21 | 21 | 21 | 21 (21,168 input pairs) | 0 | 0 |

The same integrated run passed the mapped-global/call analysis fixture
(`target/demo-analysis/run.lf1mn8/`), named LLVM-pass experiment (8 boundary
matches; `target/demo-passes/run.OrScuV/`), authenticated separate-process
remote demo (`target/demo-remote/run.UPVvv4/`), and restricted whole-rebuild
gate (`target/demo-recompile/run.P9bfgc/`). The latter remained three
supported complete programs, five matched controlled executions, and five
rejected semantic cases.

## Restricted local whole-program rebuild checkpoint — 2026-09-17

`bash scripts/demo-linux-docker.sh` exited 0 after the whole-rebuild path was
added. The pinned Linux x86-64 image ran Rust 1.96.0 and Debian Clang/LLVM
14.0.6; **27 Rust unit tests** passed and workspace Clippy passed with
`-D warnings`. The existing five function fixture variants again matched
**5,040/5,040** seeded/boundary executions. The direct-call/global-effect
analysis fixture, named LLVM-pass experiment (8 boundary matches), and
separate-process remote demo also passed. Their final artifacts are under
`target/demo-local/run.TrJWrj/`, `target/demo-analysis/run.lf1mn8/`,
`target/demo-passes/run.OrScuV/`, and `target/demo-remote/run.UPVvv4/`.

The new `scripts/demo-recompile.sh` gate in that run passed and left
`target/demo-recompile/run.P9bfgc/`. It compiled three complete fixture
programs to static ELFs, passed only those ELF bytes to `hydirctl rebuild`,
verified each generated LLVM module with `opt`, linked three new executables,
and compared stdout, stderr, and exit status for five controlled cases:
`whole_hello` (empty input), `whole_choice` (`A`, `B`, EOF), and `whole_loop`
(empty input). All five matched with exit status 0. These are **5 observed
whole-program cases across 3 supported/rebuilt programs**, not 1,000-case
equivalence evidence. The choice fixture exercises `.bss`; the loop fixture
exercises a shared data counter and a direct helper call. Three further complete
ELFs were deliberately unsupported: a `push` instruction, an uninitialized
RAX read, a write to `.rodata`, an unmapped syscall buffer, and an unsupported
syscall number were rejected with explicit diagnostics.
An invocation without `--trusted-fixture` was also rejected. The three
rebuilt files differ byte-for-byte from their originals; the source fixtures
are read by the test harness, not the rebuilder.
An initial `.bss`-only choice ELF failed under Docker's Apple Silicon x86-64
emulation with `rosetta error: bss_size overflow` before its behavior could be
compared. Adding a one-byte `.data` anchor produced a normal writable LOAD
segment with `.bss`, after which both original and rebuilt fixtures passed.
This is an emulation-specific observed failure, not evidence of native Linux
support for that original BSS-only layout.

| Corpus unit | Attempted | Supported | Lifted | IR-valid | Executable | Behaviorally matched | C-generated | Whole-program rebuilt |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Complete-program ELFs | 8 | 3 | 3 | 3 | 3 | 3 (5 controlled cases) | 0 | 3 |

This is a **restricted local M4 engineering gate**, not completion of the
overall release milestone. The rebuild grammar is static, fully symbolized,
freestanding x86-64; the guest stack must be unobserved and only read/write/
exit are modeled. There is no hostile-binary sandbox, no remote/API/GUI rebuild,
no C generation, and no patch workflow. M0 licensing/reference-lift closure,
M2 full remote product/security, M3 C/patch workflow, and M5 release hardening
remain open. No source release, public service, push, or deployment was made.

The remaining sections below preserve earlier chronological checkpoints.
Counts are fixture variants, not claims about arbitrary ELF programs.

The checkout started at initial commit `b6228a3dd2753d91260d3f5868d6b576388a1742`
with only a nine-byte README. No prior HydIR implementation was present here.

## Initial linear-slice checkpoint

### Executed checks

- `cargo test --locked --workspace` on macOS arm64 with Rust 1.96.0: 7 unit
  tests passed (6 backend, 1 core); no ignored or failed tests.
- Built `tests/fixtures/add2.S` as x86-64 ELF object with Homebrew Clang
  22.1.8. `hydirctl inspect` reported its text symbol; `hydirctl lift`
  decoded its five instruction bytes into LLVM IR. Homebrew LLVM 22.1.8
  `opt -passes=verify -disable-output` exited 0.
- `bash scripts/demo-linux-docker.sh` exited 0 on the final run. Docker ran
  Linux x86-64 on an Apple Silicon macOS host. The image used Rust 1.96.0,
  Debian Clang 14.0.6, and LLVM 14.0.6. The command passed 7 unit tests,
  `cargo clippy --locked --workspace --all-targets -- -D warnings`, and the
  `opt -passes=verify` check in `demo-local.sh`.
- The final demo artifacts are under `target/demo-local/run.faVu5W/`. The
  original executable SHA-256 is
  `27dfedba347efa8ce9704ce64d06a02d0a9c54c6298426c70dc17754027930aa`.
  The five-byte `hydir_add2` symbol begins at `0x401138`; the emitted IR
  contains `add i64 %arg0, %arg1` and `ret i64 %v0`, without `nsw`/`nuw`.
- `hydirctl validate` compared stdout, stderr, and exit status on 8 boundary
  inputs plus 1,000 seeded pairs (`0x6859644952203236`): **1,008 attempted,
  1,008 matched, 0 mismatched**. This is a tested function lift, not a
  whole-executable rebuild or proof of equivalence.
- The unsupported fixture was rejected with `unsupported Push at 0x0`.
  The demo executable has a non-executable GNU stack (`RW`, not `RWE`).
- `git diff --check` and `bash -n` on both demo scripts exited 0.

The first Linux attempt did not reach tests because a login shell reset the
container's Rust `PATH`; the script now uses a non-login shell. A subsequent
run produced 1,008 matches but its outer script exited 2 because the script
was edited while running. The final, unchanged run above exited 0.

### Corpus ledger for this checkpoint

| Unit of evidence | Attempted | Supported | Lifted | IR-valid | Executable lifted form | Behaviorally matched | C-generated | Whole-program rebuilt |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Function fixtures | 2 | 1 | 1 | 1 | 1 | 1 (1,008 inputs) | 0 | 0 |

The `unsupported` fixture is deliberately included in attempted totals. The
other upstream test ELF tried locally (`test-hello-elf-x64`, `main`) was also
rejected at an unsupported `Push` (`0x1140`); it is not copied into this
repository or included in the two-fixture ledger.

### Status at this checkpoint

M0 is partial: upstream IRENE-3 source, build files, schemas, transforms,
patch parser, tests, root and Ghidra licenses were inspected; Rust and the M1
container toolchain are pinned. The complete Remill/Anvill/Rellic/MLIR/Ghidra
version and per-file license audit, reference upstream lift, and distribution
notices are not done. The narrow M1 end-to-end demonstration passed, but
stripped recovery, control flow, memory, calls, comprehensive ABI modeling,
and the 20-function corpus are absent. M2 through M5 are not implemented.

No `hydir` GUI, `hydird` service, remote API, SDK, C output, interprocedural
analysis, patch application, or whole-executable rebuild exists. There is no
release artifact or remote corresponding-source offer. Execution validation
has **no sandbox** and is limited to explicitly trusted fixtures. No benchmark
timings or memory measurements were recorded.

At that checkpoint, the next engineering task was direct control flow and
memory with explicit machine-state and ABI effects.

## Direct-CFG and stripped-entry expansion

Executed `cargo fmt --all`, `cargo test --locked --workspace`,
`bash -n scripts/demo-local.sh`, `git diff --check`, and
`bash scripts/demo-linux-docker.sh`. The final Docker run exited 0 with Rust
1.96.0, Debian Clang/LLVM 14.0.6, 11 Rust unit tests, Clippy with
`-D warnings`, and `opt -passes=verify` for all five emitted modules. The
host Cargo test also passed; host Clippy was unavailable, so the pinned Linux
container provided that gate.

The final run's artifacts are under `target/demo-local/run.8yQbEY/`. Four
symbolized function fixtures (`add2`, unsigned `max2`, signed `max2`, and
`repeat16`) and one truly stripped copy of `max2` were each tested on eight
boundary input pairs and 1,000 seeded pairs. All five reports recorded
**1,008 attempted, 1,008 matched, 0 mismatched**; aggregate 5,040 attempts.
The stripped variant used the analyst-supplied virtual entry
`0x0000000000401138` and 16-byte extent obtained before stripping. `nm` on
the stripped file did not find the function symbol. The native CFG export
recorded five reachable instruction blocks and five edges in both the
symbolized and stripped max cases. `repeat16` recorded six blocks and six
edges. This does not prove equivalence outside the tested inputs or contract.

| Unit of evidence | Attempted | Supported | Lifted | IR-valid | Executable lifted form | Behaviorally matched | C-generated | Whole-program rebuilt |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Function fixture variants | 6 | 5 | 5 | 5 | 5 | 5 (5,040 input pairs) | 0 | 0 |

The sixth variant is the deliberately unsupported `push` fixture, which was
rejected rather than lifted. The unit suite also checks overlap rejection,
uninitialized flags, and an uninitialized return value on one CFG path.

M0 remains partial: a reference upstream lift, native dependency set, full
per-file license review, and release notices are not complete. M1's narrow
native import/lift/execute/differential gate passes, including direct branches
and bounded loops, but calls, memory, complete ABI state, and the 20-function
corpus remain. M2 through M5 are absent. In particular there is still no
`hydir` GUI, `hydird` service, project persistence, remote API, C output,
interprocedural analysis, patching, or whole-executable rebuild. Validation
has **no sandbox** and must remain limited to trusted fixtures.

The next blocking engineering task is memory and direct-call semantics with
declared machine-state, ABI, and observable-memory contracts; remote/product
gates will also require persistent projects and isolated workers.

## Partial M2 local service and desktop checkpoint

On 2026-09-17, `cargo fmt --all`, `cargo test --locked --workspace`,
`git diff --check`, and `bash -n scripts/demo-linux-docker.sh
scripts/demo-remote.sh` exited 0 on the macOS arm64 development host. The
workspace suite passed **18 tests**: 10 backend, 1 core, 2 GUI, and 5 server.

The final `bash scripts/demo-linux-docker.sh` exited 0. In the pinned Linux
x86-64 image (Rust 1.96.0; Debian Clang and LLVM 14.0.6), the same 18 tests
passed and `cargo clippy --locked --workspace --all-targets -- -D warnings`
completed without warnings. The local demo artifacts are under
`target/demo-local/run.7HTzAz/`. Four symbolized function fixtures and one
stripped variant again produced **5,040 attempted, 5,040 matched, 0
mismatched** cases with seed `0x6859644952203236`. The five emitted IR
modules passed `opt -passes=verify` in the script. The unsupported `push`
fixture remained rejected. This is the same narrow function contract as the
M1 evidence above, not additional whole-program coverage.

The separate-process remote demo in that same Docker run exited 0 and wrote
`target/demo-remote/run.vzEe46/`. It exercised two identities and two
projects, an explicit binary upload, inspect/CFG/lift, SHA-256-verified IR
artifact retrieval after server restart, project creation retry, stale
revision rejection, denied cross-project and cross-artifact reads, token
rotation with old-token rejection, and rejection of the unsupported `push`
fixture through a child worker. The headless `hydir --probe-remote` path,
which calls the same remote functions as the GUI, reported **4 discovered
functions, 5 selected CFG blocks, and 2,704 IR bytes**. The child worker has
a 30-second deadline and 16 MiB output cap. No execution request or public
binding was exposed.

The macOS `hydir` process launched and remained running until stopped, and
the GUI compiled and passed unit tests on macOS and Linux. A visual/window
interaction test was **not** completed: the desktop-control surface did not
identify the unbundled Cargo binary as an app. The headless probe is remote
logic evidence, not visual QA. No Windows build was attempted.

M2 remains **partial**. The SQLite store persists identities, owner-scoped
projects, immutable binary revisions, and artifacts; the GUI can inspect a
local ELF or explicitly connect to an existing remote project. It cannot
upload remotely, reopen saved local layouts/projects, run a pass editor, or
show completed C/global-analysis/rebuild views. The service lacks durable
jobs, cancellation/event streams, per-role authorization, quotas, OS-level
worker sandboxing, TLS/non-loopback mode, source archive/offer, and full API/
SDK coverage. Worker subprocess isolation is not a hostile-sample sandbox.
M0 native-dependency/license gates and M1 general memory/call/ABI coverage
also remain open. M3–M5 are not implemented; there is no decompiler, tested
interprocedural analysis, patching, or whole-executable recompilation. No
benchmark timing or memory measurements were recorded. The next blocking
product task is durable, cancellable, resource-constrained jobs and a complete
typed local/remote operation surface; semantic expansion needs explicit
memory and call models before broader lifting or rebuilding claims.

## Durable lift-job expansion (partial M2)

`cargo fmt --all`, `cargo test --locked --workspace`, `bash -n
scripts/demo-linux-docker.sh scripts/demo-remote.sh`, and `git diff --check`
passed on the macOS host. The workspace suite passed **21 tests**: 10 backend,
1 core, 2 GUI, and 8 server. `bash scripts/demo-linux-docker.sh` exited 0
on Linux x86-64 in the pinned Rust 1.96.0 / Clang and LLVM 14.0.6 image.
There, all 21 tests and `cargo clippy --locked --workspace --all-targets --
-D warnings` passed. The five function variants in
`target/demo-local/run.NwwiES/` again produced **5,040/5,040 matches**,
with LLVM verification and the unsupported `push` rejection.

The separate-process remote demonstration exited 0 and left evidence in
`target/demo-remote/run.hA905k/`. It exercised idempotent lift-job creation,
queued-to-succeeded events, retrieval and exact replay after service restart,
an unsupported lift job ending failed or cancelled, owner-scoped job denial,
and the prior binary-transfer/revision/artifact/token-rotation checks. Server
unit tests cover v1-to-v2 schema migration, idempotence, event replay,
cross-identity isolation, cancellation, and restart
interruption. The demo does not prove cancellation of a long-running hostile
process tree or persistence of an active worker across restart.

M2 remains partial: the desktop lacks a live jobs panel, remote binary upload,
and saved layout; service authorization is owner-only rather than per-role and
the worker has no OS sandbox. M3–M5 and the broad M0 licensing/backend audit
remain open. Do not infer release readiness from this job-slice result.

## Bounded interprocedural effect analysis and workbench expansion

On 2026-09-17, `cargo fmt --all`, `cargo test --locked --workspace`,
`bash -n scripts/demo-analysis.sh scripts/demo-remote.sh
scripts/demo-linux-docker.sh`, and `git diff --check` passed on the macOS
development host. The workspace had **24 passing tests**: 3 analysis, 10
backend, 1 core, 2 GUI, and 8 server. The final
`bash scripts/demo-linux-docker.sh` exited 0 in the pinned Linux x86-64 image:
all 24 tests, warning-free Clippy, the five LLVM verifier/differential fixture
variants (**5,040/5,040 matches**), `scripts/demo-analysis.sh`, and the
separate-process remote demo passed. New artifacts are under
`target/demo-local/run.OxXSUZ/`, `target/demo-analysis/run.uQsqpz/`, and
`target/demo-remote/run.E1LvSk/`.

The linked ELF analysis fixture demonstrates a leaf write to `.data` at
`0x402000`, a caller whose direct write set is empty but propagated possible
write set contains that address, and an indirect-call function with
`unknown_global_effects=true`. Three Rust tests cover a changed callee
summary, unresolved-call conservatism, and recursive SCC fixed-point
propagation. The remote demo uploads the fixture into a separate project,
retrieves the analysis via gRPC, and denies another identity's attempt to
analyze it. The GUI's headless remote-operation probe now also exercises
analysis and a completed job with verified artifact retrieval; this is not
visual interaction evidence.

M3 is **partial**: this is one concrete interprocedural property, but there
is no named pass pipeline, C output, or patching. M2 remains partial due
missing remote GUI upload, saved layouts, fine-grained roles, OS worker
sandbox, and non-loopback TLS. M4 whole-executable rebuild and M5 release
hardening are absent. No hostile binary or remote execution was attempted.

## Named LLVM pass experiment (partial M3)

`cargo fmt --all`, `cargo test --locked --workspace`, `bash -n
scripts/demo-passes.sh scripts/demo-linux-docker.sh`, and `git diff --check`
passed on the macOS host. The workspace had **25 passing tests**, including
a pass allowlist test. The final `bash scripts/demo-linux-docker.sh` exited 0
with all 25 tests and warning-free Clippy in the pinned Linux image. The
five earlier function variants again matched **5,040/5,040** differential
cases, and local analysis plus separate-process remote checks passed. This
run wrote `target/demo-local/run.eqXstp/`,
`target/demo-analysis/run.RLfSKF/`,
`target/demo-passes/run.fPwks3/`, and
`target/demo-remote/run.HqovHb/`.

`scripts/demo-passes.sh` lifted the real `hydir_max2` bytes, saved raw,
canonical-before, and after IR, ran allowlisted
`instcombine,sccp,simplifycfg,dce` with LLVM `opt` 14.0.6 and verification,
observed a text change in the IR, compiled the transformed function, and
matched stdout/stderr/zero exit status against the original trusted fixture
on eight boundary inputs. It did not validate arbitrary programs or prove
the pass pipeline semantics universally. The command is opt-in and local-only
because `opt` is not sandboxed for hostile inputs. Remote passes, a GUI pass
editor, C generation, and patching remain M3 blockers.

## Explicit desktop remote transfer

The workbench now has separate, labelled create-project and upload-ELF actions.
Opening a local binary or an existing remote project never transfers local
bytes. The upload path checks the local file size, sends a SHA-256 assertion
and expected project revision, and verifies the returned revision, hash, and
reopened model. The same operations are exercised in
`hydir --probe-create-upload`; this verifies UI code paths, not a visual
interaction or a real mouse click.

`cargo fmt --all`, `cargo test --locked --workspace` (**25 passing tests**),
`bash -n scripts/demo-remote.sh`, and `git diff --check` passed on the macOS
host. A targeted Linux container run of warning-free workspace Clippy and
`scripts/demo-remote.sh` exited 0, leaving
`target/demo-remote/run.QfVNkn/`. A subsequent full
`bash scripts/demo-linux-docker.sh` exited 0 with 25 tests, Clippy,
5,040/5,040 differential matches, the global-effect fixture, the LLVM pass
experiment's eight boundary matches, and separate-process remote checks. Its
artifacts are under `target/demo-local/run.kBDkpn/`,
`target/demo-analysis/run.HnIjKp/`,
`target/demo-passes/run.S0pObU/`, and
`target/demo-remote/run.kpx0gy/`.

M2 remains partial: visual GUI interaction QA, saved/reopened layouts,
fine-grained roles, quotas/audit, an OS-level worker sandbox, non-loopback TLS,
and full operation coverage are not present. The upload demo uses a trusted
fixture and an authenticated loopback service; it is not a hostile-sample or
public-network security demonstration.

## Python SDK for the implemented remote subset

The Python package was generated from the checked-in v1 `.proto` with
`grpcio-tools==1.84.0` and wrapped in `sdk/python/hydir_sdk`. It covers
discovery, owner-scoped projects, explicit upload, inspect/CFG/lift,
conservative analysis, lift jobs and reconnectable events, and artifact
retrieval with SHA-256 verification. `PYTHONPATH=sdk/python
target/sdk-venv/bin/python -m unittest discover -s sdk/python/tests -v`
passed **3 tests** for non-loopback refusal, private credential permissions,
artifact hash checking, and exclusive output creation.

With pinned `grpcio==1.84.0` and `protobuf==7.36.1` in a private local
virtual environment, `HYDIR_SDK_PYTHON=target/sdk-venv/bin/python bash
scripts/demo-sdk.sh
/Users/achu/Projects/hydir-2/target/demo-remote/run.kpx0gy/max2-original`
exited 0 on the macOS development host. It started a separate `hydird`,
used the SDK to create a project and explicitly upload the Linux fixture,
inspected/decoded/lifted it, obtained global summaries, retried a lift job
with the same idempotency key, consumed terminal events, and compared the
SHA-verified job artifact with the direct lift. Evidence remains under
`target/demo-sdk/run.ekEeQP/`. The SDK ran on macOS against an ELF fixture;
this is not macOS native execution validation or a visual GUI test.

The SDK does not expose pass experiments, C generation, patching, rebuilding,
or execution because no corresponding remote operations exist. Its package
build succeeded locally; there is no published wheel, release archive, or
complete license-notice/source-offer audit.

## Linux worker resource limits

The server now clears the child worker's environment and applies Linux
`setrlimit` caps before exec. Host `cargo test --offline --workspace` passed
all 25 Rust tests after the change. The first Linux remote run with a
512 MiB address-space cap failed intermittently: a worker exited via
`SIGTRAP` during fixture inspection under Docker's emulated x86-64 mode on
Apple Silicon. That cap was raised to 2 GiB; two subsequent separate-process
`scripts/demo-remote.sh` runs exited 0 and left artifacts in
`target/demo-remote/run.DsaGCs/` and
`target/demo-remote/run.89FGva/`. The cause of `SIGTRAP` has not been proven;
the emulation/address-space interaction is a hypothesis, not a verified root
cause. Native Linux stress testing and hostile-input isolation remain open.

The subsequent full `bash scripts/demo-linux-docker.sh` exited 0 with 25
Rust tests, warning-free Clippy, 5,040/5,040 trusted differential matches,
the analysis and named-pass demonstrations, and the separate-process remote
demonstration. Artifacts are under `target/demo-local/run.QEprei/`,
`target/demo-analysis/run.vhpqK3/`,
`target/demo-passes/run.GdkBFC/`, and
`target/demo-remote/run.Km7w5d/`. This does not prove that the limits safely
contain malicious code or child process trees.
