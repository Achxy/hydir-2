# ADR 0005 — restricted decoded whole-executable rebuild

Status: accepted for a trusted-fixture local CLI slice (2026-09-17).

## Context

The earlier function lifter has an explicit `u64(u64,u64)` boundary and
rejects memory/calls. Treating its output as a whole executable would erase
machine state and OS effects. A small freestanding ELF class allows an honest
complete-program gate without claiming general binary recovery.

## Decision

`hydirctl rebuild` uses `object` to parse a linked static x86-64 ELF and
`iced-x86` to decode every byte of a fully symbol-covered `.text`. It rejects
dynamic sections, overlapping/uncovered text, indirect calls/branches, stack
access, partial registers, unsupported instructions, unmapped direct data
references, writes to `.rodata`, and reads of non-definitely initialized
registers/flags. It does not read fixture source. Each machine instruction
becomes an LLVM basic block, with full-width registers and ZF in explicit
global state. Direct calls become LLVM calls, while the guest stack is assumed
unobserved; host call nesting implements return locations. `syscall` models
RAX and RCX effects. The runtime maps guest data addresses to a bounded byte
image, including `.bss`; read/write buffers receive range and permission
checks. A conservative forward constant analysis requires every syscall site
to have a known read/write/exit number; read/write require a known standard
descriptor and a mapped, permission-compatible buffer and length. Unknown
call effects invalidate constants, potentially rejecting otherwise safe
programs. The generated `.ll` and
runtime are linked by pinned Clang/LLVM 14.0.6 into a new ELF.

The output directory must be new. `--trusted-fixture` is required; no hostile
execution sandbox exists. The runtime traps on unsupported syscalls and does
not call into the original binary or interpret its original bytes. This path
is independent of the scalar function lifter and is not a general decompiler.

## Consequences and remaining work

The three fixture programs now have a reproducible whole-program behavior
gate. The stricter grammar rejects many normal compiler-generated binaries;
the GUI, server, and SDK cannot request rebuild. Full flags/registers, stack
semantics, imports, dynamic linking, FFI/ABI interactions, execution isolation,
source-level C output, and remote parity require separate work and evidence.
