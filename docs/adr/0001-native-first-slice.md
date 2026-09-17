# ADR 0001: native ELF scalar lift before service and GUI

Status: accepted for the M1 prototype, 2026-09-17.

The checkout began with only an initial README. We chose to build one
independent Rust path from ELF bytes to decoded instructions to verified LLVM
IR, then compare a trusted original executable with compiled lifted IR. This
establishes a real vertical slice without importing IRENE-3 servers or
claiming their LLVM/Remill/Rellic coverage.

The first prototype is intentionally symbol-bounded and linear. The asserted
`u64(u64,u64)` ABI contract is visible in the IR and CLI. It rejects unsupported
state, control flow, and memory rather than representing uncertainty as
`unreachable`, undef, or dummy returns. Flags from accepted `add`/`sub` are
not live in the accepted instruction grammar and are outside the declared
return contract. No optimization flags promising absence of overflow are
added.

The local validation command is explicitly for trusted fixtures. It does not
isolate execution and cannot be exposed remotely. Before a remote execution
API or untrusted-sample validation, implement a disposable sandbox, resource
limits, authorization, and an explicit threat model.

The next substantial engineering task is to expand the program model and
stateful lift to direct control flow, memory, calls, and ABI effects with
differential tests. A GUI or network facade around this narrow core would not
satisfy the later milestones.
