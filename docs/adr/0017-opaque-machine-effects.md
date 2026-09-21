# ADR 0017: Explicit opaque machine effects

Status: accepted, 2026-09-20.

Rejecting an entire function at the first unsupported instruction prevents
useful analysis of real binaries. Treating that instruction as a no-op is
unsound. The native pipeline instead emits `OpaqueEffect` with the original
address and bytes, a diagnostic, and a conservative effect summary.

The M1 implementation consumes and produces every modeled general-purpose
register and arithmetic flag and marks memory unknown. Direct fallthrough is
retained when the decoder establishes it. Indirect or otherwise unresolved
control terminates that recovered path explicitly. Later instruction-info
analysis may narrow an opaque effect, but may never omit a possible effect.

Low-level C emits a call to `hydir_opaque_effect` and remains compilable.
Artifacts containing opaque effects cannot be `rewrite_ready`. This preserves
partial decompilation while keeping patch and rebuild authorization fail-closed.
