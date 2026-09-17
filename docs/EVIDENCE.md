# M1 evidence — 2026-09-17

The first section records the linear-slice checkpoint. The second section
records the subsequent direct-CFG and analyst-entry expansion. Counts are
fixture variants, not claims about arbitrary ELF programs.

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
