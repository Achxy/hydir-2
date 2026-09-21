# ADR 0019: LLVM is an optional export format

Status: accepted, 2026-09-20.

LLVM text is no longer the canonical representation of native decompilation.
Machine bytes and effects belong to MachineFunctionIR, explicit architectural
state belongs to StateFunctionIR, ABI facts belong to FunctionIR, and C control
and expression structure belongs to CIR. The native C renderer accepts CIR and
does not parse LLVM.

The existing LLVM-driven scalar lift, transformation, validation, and rebuild
workflows remain available as legacy-compatible product paths. The native LLVM
exporter consumes FunctionIR, preserves opaque effects and provenance, and
makes no stronger exactness claim than its source artifact. LLVM verifier or
optimizer success is validation evidence only; it cannot make a partial native
artifact `rewrite_ready`.

The native exporter emits an explicit-machine-state module whose exact and
opaque operations are embedded as deterministic JSON descriptors for declared
effect hooks. This form is verifier-friendly and losslessly inspectable but
deliberately does not claim standalone executable equivalence. The native CLI
exposes it as `--ir llvm`; the output does not pass through the legacy scalar
lift or feed the C renderer.
