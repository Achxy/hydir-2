# ADR 0011: bounded analysis overlay for ProgramSpec

Status: accepted for the development checkpoint, 2026-09-18.

ELF `inspect` is a metadata operation. Its empty call and reference arrays
must continue to mean `not_attempted`, not a proof that the program has no
calls or data references. A separate `analyze-spec` operation joins the
existing conservative, symbol-bounded analysis with the v2 ELF inventory.
It records instruction-site call and memory-reference facts with
`native_analysis` provenance, nullable targets, a scoped analysis-contract
assumption, and `partial` recovery status. It is exposed through the local
CLI, authenticated project RPC, remote CLI, and Python SDK; the desktop
analysis view displays the same site-level report without claiming an
exhaustive graph.

This is a derived view over an immutable binary revision. It does not
persist analyst assumptions or mutate the project. Direct targets outside
the bounded selected-symbol set remain unresolved for effect propagation;
syscalls are external effects, not ordinary function-call graph edges. Stack
bookkeeping for direct and indirect calls and returns is not reported as a
program memory reference. Non-RIP memory still yields a nullable reference
and conservative unknown effects. The overlay does not certify coverage of
stripped code, indirect targets, or whole-program control flow.
