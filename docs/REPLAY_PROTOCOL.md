# Replay protocol v1 (experimental)

`hydirctl replay init <linked-elf>` emits a JSON `InputSpec v1` bound to the exact ELF SHA-256. Edit its input bytes and goal, then run `hydirctl replay verify <linked-elf> <input.json>`. On Linux with Bubblewrap installed, `hydirctl replay <linked-elf> <input.json>` attempts one fresh execution and emits `NativeReplayReport v1`.

On other hosts, `replay` emits an `unsupported_host` report with no observed exit or output.

The current contract accepts little-endian linked x86-64 ELF, raw hex-encoded `argv_hex` (excluding argv0), `stdin_hex`, and relative input `files`. `origins` name byte ranges within those channels with raw, ASCII, or UTF-8 encoding and optional allowed-byte alphabets. Ranges and alphabets are checked against the supplied bytes. An output goal combines its present predicates with AND: exit code, stdout substring, and stderr substring. The default goal created by `init` is exit code zero. Limits are 32 arguments, 16 files, 256 origins, 1 MiB combined input, 30 seconds, 1 GiB address space, and 1 MiB captured output. The JSON parser rejects unknown fields and oversized input.

The Linux runner stages the exact ELF and files into a read-only work tree, clears the environment, creates private user, PID, network, IPC, and UTS namespaces, and applies address-space, CPU, core-file, and file-size limits. It requires Bubblewrap and fails closed when it cannot confirm child startup and exit through Bubblewrap's separate JSON status FD. A timeout, output limit, setup failure, or unsupported host never becomes `goal_matched`. Native output is an observation for one input under this environment; it is not an equivalence proof. Bubblewrap shares the host kernel, so use an isolated machine for hostile binaries.

`NativeReplayReport v1` records the binary and canonical input digests, runner, status, exit value, hex output, elapsed time, and diagnostics. `validate_replay_report` checks its binding, bounds, and whether an asserted goal result agrees with the recorded output. Bubblewrap reports signal termination as a shell-style exit value. Values at least 128 remain `runner_error` with an ambiguity diagnostic and no exact exit or signal claim. Input files are read-only and process-created output files are not collected.

This is an M4 foundation. It does not yet implement GDB/MI process capture, snapshot production, PIE load-map observation, Triton resumption, file output capture, cancellation, or Windows WSL launch. `doctor` keeps `native_replay_v1` false until the complete M4 replay gate is verified; it separately reports whether the experimental Linux runner dependency is installed.

## ExecutionSnapshot v1 contract

`ExecutionSnapshot v1` now defines the captured-state artifact for the next GDB/MI worker. It binds the exact ELF and canonical `InputSpec`, records a stop point with optional ELF virtual address and load bias, one thread's register observations, process mappings, and at most 32 selected 4096-byte pages. Each register or page is explicitly present or unavailable. Pages absent from the artifact are also unavailable: `read_snapshot_memory` returns a missing-page error and never substitutes zero bytes. `hydirctl snapshot verify <elf> <input.json> <snapshot.json>` checks bounds, digest bindings, mapping/page consistency, RIP versus stop PC, and the one-thread claim. No current command produces a stopped snapshot yet; `doctor` reports the schema separately from capture availability.

The capture worker can use the bounded GDB/MI record parser in `hydir-execution`. It handles command results, asynchronous stop records, console/inferior streams, nested tuples and lists, and escaped byte strings. The parser is present; session control and snapshot production remain open.
