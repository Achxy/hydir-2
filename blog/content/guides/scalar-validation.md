# Verified scalar lift

The earlier scalar lift is a separate, narrower path for explicitly asserted
`u64(u64,u64)` functions. Its checked-in demos emit LLVM IR and C for 20
distinct scalar fixtures, run the LLVM verifier where the required tools are
available, and compare output with native execution on 1,008 input pairs.

```bash
bash scripts/demo-local.sh
bash scripts/demo-corpus.sh
```

The bounded scalar contract now also covers proven balanced frames, initialized
nonoverlapping 32/64-bit stack locals (including the SysV leaf red zone),
32-bit arithmetic/comparisons with explicit flags, `mov` zero-extension, and
RIP-relative address formation, plus direct calls to uniquely bounded scalar
leaf symbols. Other memory, unresolved calls, and unmodelled aliases remain
explicit refusals.

RegionSpec v3 CFG recovery is a separate structural stage. It requires decoded
external edges to match the declared continuation exits exactly, records direct
call targets with a distinct edge kind, and does not promote imported liveness
or stack facts into semantic proof. MachineIR preserves mapped/TLS memory and
non-frame register-save effects, while the scalar lift refuses them until a
physical-state and memory contract is available.
Imported call-site `stop`/`noreturn` facts are kept distinct, source-attributed,
and may suppress a region fallthrough only at their exact instruction address.

The scripts retain CFG, LLVM IR, C, and comparison reports. Their finite
fixture results do not establish equivalence for arbitrary programs. A C
generation refusal also does not discard an independently recovered CFG or
LLVM lift; the workbench presents each stage's status separately.
