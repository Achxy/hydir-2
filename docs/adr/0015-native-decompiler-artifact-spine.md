# ADR 0015: Native decompiler artifact spine

Status: accepted, 2026-09-20.

Hydir's first scalar lift used generated LLVM text as both an output and the
input to its C backend. That remains a supported legacy workflow, but it is
not a scalable canonical representation for whole ELF decompilation.

The native decompiler therefore owns five independently versioned artifacts:
`MachineFunctionIR`, `StateFunctionIR`, `FunctionIR`, `CIR`, and
`DecompilationUnit`. MachineIR preserves instruction bytes, operands, effects,
and control edges. StateIR initially versions the complete architectural state
at every operation; later analysis may scalarize registers, flags, and memory
without changing the MachineIR contract. FunctionIR is the ABI-normalization
boundary. CIR is the only input to the new C renderer.

LLVM is now an optional export target. Existing LLVM lift, transform, rebuild,
and validation commands remain available and are not silently redirected.
The native CLI forms are selected explicitly with `--function` plus `--ir` or
`--view`. `hydir-backend` remains the compatibility facade while loader and
discovery ownership are extracted in later milestones.

The first slice began symbol bounded and now also admits ELF-entry and direct-
call candidates from bounded recursive probes. This is an explicit delivery
boundary, not a claim of whole-program discovery: candidate extents stay
partial and `FunctionIndex` records that unwind, indirect-target, and complete
recursive discovery remain unresolved.
