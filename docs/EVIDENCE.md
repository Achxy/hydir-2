# HydIR evidence — 2026-09-17

## Restricted local whole-program rebuild checkpoint — 2026-09-17

`bash scripts/demo-linux-docker.sh` exited 0 after the whole-rebuild path was
added. The pinned Linux x86-64 image ran Rust 1.96.0 and Debian Clang/LLVM
14.0.6; **27 Rust unit tests** passed and workspace Clippy passed with
`-D warnings`. The existing five function fixture variants again matched
**5,040/5,040** seeded/boundary executions. The direct-call/global-effect
analysis fixture, named LLVM-pass experiment (8 boundary matches), and
separate-process remote demo also passed. Their final artifacts are under
`target/demo-local/run.442o8y/`, `target/demo-analysis/run.1RCq7p/`,
`target/demo-passes/run.rk7mAY/`, and `target/demo-remote/run.Kwjvqk/`.

The new `scripts/demo-recompile.sh` gate in that run passed and left
`target/demo-recompile/run.o2gyHw/`. It compiled three complete fixture
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
