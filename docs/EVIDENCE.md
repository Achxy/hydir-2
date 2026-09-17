# M1 prototype evidence — 2026-09-17

The checkout started at initial commit `b6228a3dd2753d91260d3f5868d6b576388a1742`
with only a nine-byte README. No prior HydIR implementation was present here.

## Executed checks

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

## Corpus ledger for this checkpoint

| Unit of evidence | Attempted | Supported | Lifted | IR-valid | Executable lifted form | Behaviorally matched | C-generated | Whole-program rebuilt |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Function fixtures | 2 | 1 | 1 | 1 | 1 | 1 (1,008 inputs) | 0 | 0 |

The `unsupported` fixture is deliberately included in attempted totals. The
other upstream test ELF tried locally (`test-hello-elf-x64`, `main`) was also
rejected at an unsupported `Push` (`0x1140`); it is not copied into this
repository or included in the two-fixture ledger.

## Status and blockers

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

The next blocking engineering task is stateful recovery/lifting of direct
control flow and memory, with explicit machine-state and ABI effects and
differential fixtures. Packaging or GUI work would not remove that blocker.
