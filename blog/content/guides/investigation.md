# Replay and captured-state investigation

Static analysis describes a program model. Native replay observes the original ELF for one declared input. Captured-state solving explores a bounded function window. Keep the evidence from these operations separate.

## Prerequisites and first replay

Native replay requires Linux x86-64 and Bubblewrap with working isolation probes. Capture also needs GDB. The bounded return solver needs the optional Triton Python bridge. Start with `hydirctl doctor`; a Windows Frida worker does not imply that these separate replay/capture operations are available.

```text
hydirctl replay init program.elf --output input.json
hydirctl replay verify program.elf input.json
hydirctl replay program.elf input.json --output replay.json
```

Edit the generated InputSpec before verification. It binds the ELF digest and records raw hex-encoded arguments, stdin, relative input files, optional named origin ranges, output goals, and budgets. Use the generated schema rather than guessing field names. Present goal predicates are combined with AND.

| InputSpec field | Meaning |
| --- | --- |
| `argv_hex` | Argument bytes excluding argv0 |
| `stdin_hex` | Bytes supplied on standard input |
| `files` | Relative file paths and hex contents |
| `origins` | Named byte ranges with encoding and optional alphabet |
| `goal` | Optional exit, stdout-substring, and stderr-substring predicates |
| `budget` | Timeout, memory, and captured-output limits |

Input limits include 32 arguments, 16 files, 256 origins, and 1 MiB combined input bytes. JSON is bounded separately and rejects unknown fields. Read the report's status rather than treating any produced JSON as a successful run.

## Interpret the replay report

`NativeReplayReport` binds the binary and canonical input digests and records the runner, status, exit/signal fields, hex output, elapsed time, and diagnostic. Statuses distinguish `goal_matched`, `goal_mismatched`, `timed_out`, `output_limit`, `runner_error`, and `unsupported_host`.

The Linux runner stages inputs, clears the environment, isolates namespaces, and applies resource limits. A setup error or unsupported host does not become a matched goal. One successful replay is an observation under that environment, not whole-program equivalence.

## Capture a bounded stop

```text
hydirctl capture program.elf input.json --function validator --output snapshot.json
hydirctl snapshot verify program.elf input.json snapshot.json
```

Use `--address 0x...` instead of `--function` for a file-backed executable address, including a stripped PIE. The runner resolves the runtime load bias before continuing to the selected address. `validator` and the address must identify your binary's actual target.

An ExecutionSnapshot v1 records one thread's observed registers, mappings, stop point, and selected pages. The artifact allows at most 32 pages; capture currently selects up to eight. A register or page can be unavailable. Missing memory is not zero-filled. Stopping at a function does not automatically recover the relationship between its buffer and the original input channel.

## Probe a declared input origin

```text
hydirctl snapshot probe-origin program.elf input.json snapshot.json ORIGIN_ID --register rdi --output probe.json
hydirctl snapshot verify-origin program.elf input.json snapshot.json probe.json
```

Choose `ORIGIN_ID` from the InputSpec and a register that points to the suspected buffer. The probe compares captured memory with origin bytes and reports matched, different, or unavailable. Its scope is byte equality only. Equality is not causal provenance: using it as a solver mapping is an analyst assumption.

## Build and solve a return plan

```text
hydirctl snapshot plan-return program.elf input.json snapshot.json probe.json --code-bytes 64 --return 1 --output plan.json
hydirctl snapshot verify-plan program.elf input.json snapshot.json probe.json plan.json
hydirctl solve snapshot-return program.elf input.json snapshot.json probe.json plan.json --candidate-output candidate.json --slice-output slice.json --claim-output claim.json --recipe-output recipe.json --output solve.json
```

The example's 64-byte window and return value 1 are analyst-selected goals. They must fit your captured function. Plan validation requires a stopped snapshot, matched probe, captured code in an executable mapping, all 16 GPRs plus RIP and EFLAGS, and at most eight present pages. Code is bounded to 1–4096 bytes; a symbolic origin is bounded to 1–32 bytes.

The current plan fixes 16 seeds, 1,024 instructions per seed, 32 solver queries, a 1-second query timeout, and a 20-second overall timeout. Unsupported effects or exhausted search budgets do not prove global unreachability. Missing state, calls, syscalls, and flow outside the supported window remain boundaries.

A function witness satisfies the bounded return condition in the model. Only fresh original-ELF replay can promote a candidate to a native-validated result for the declared InputSpec goal. If native replay is unavailable, that stronger claim remains unavailable.

## Verify and reproduce an investigation

```text
hydirctl recipe verify program.elf recipe.json
hydirctl recipe replay program.elf recipe.json
```

Recipe export requires the appropriate failing-seed dependency slice, witness, and before/after native replay evidence. It is not emitted merely because a solver returned a value. Verification checks digest bindings and internal consistency; replay performs fresh native observations.

The slice records structural input dependencies for one trace. It can overapproximate causal relevance and does not prove minimality. Recipes can contain captured memory and input bytes, so their contents matter when sharing an investigation.

## Implementation references

- [InputSpec and replay statuses](https://github.com/Achxy/hydir-2/blob/main/crates/hydir-execution/src/lib.rs)
- [Snapshot representation](https://github.com/Achxy/hydir-2/blob/main/crates/hydir-execution/src/snapshot.rs)
- [Return-plan validation and budgets](https://github.com/Achxy/hydir-2/blob/main/crates/hydir-execution/src/snapshot_resume.rs)
