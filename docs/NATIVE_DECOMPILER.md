# Native ELF decompiler program

Hydir's long-running native decompiler is delivered as gated vertical slices.
The product target is bounded, normal compiler-generated Linux x86-64 ELF;
packed, self-modifying, and adversarially obfuscated binaries remain outside
the first mature release.

## Implemented foundation

- ProgramSpec v5 canonical address-space locations with v1-v4 readers.
- `hydir-loader` ownership for bounded ELF parsing and ProgramSpec creation,
  with the existing backend API retained as a compatibility facade.
- Static and dynamic ELF text symbols feed ProgramSpec and FunctionIndex;
  duplicate table entries are deterministically coalesced.
- ProgramSpec records every ELF program header, GNU-versioned dynamic symbols,
  PLT/GOT/TLS/unwind section ranges, and init/fini pointer slots. Relative
  relocations are applied to pointer slots without executing the binary.
- Linked `.eh_frame` CIE/FDE records are decoded with bounded iteration.
  Executable FDE ranges become explicit ProgramSpec facts and FunctionIndex
  entry/extent evidence; malformed records remain visible uncertainties.
- Resolved init/fini entries seed probable functions; unresolved entries stay
  explicit and cannot strengthen completeness or rewrite claims.
- Relocatable ELF symbols retain section-relative identity. Relocation-backed
  init/fini slots resolve across sections, and control relocations replace
  encoded linker placeholders in MachineIR. Undefined call targets remain
  named but unresolved and render as `hydir_unknown_call` in low-level C.
- FunctionIndex v1 with symbol, ELF-entry, direct-call, and decoded PLT-stub
  evidence. Standard x86-64 PLT slots receive bounded extents and imported
  names when JUMP_SLOT relocation order supplies them. Every bounded function
  row retains candidate control targets and separate terminal-branch tail-call
  evidence; rows without extents are probed only to the next entry or size cap.
- Candidate inventory and recursive block-membership enrichment are separable:
  interactive selection defers membership and decodes the chosen extent,
  while explicit `discover` eagerly enriches at most 256 candidates under the
  byte budget. Large indexes retain every entry/evidence row for lazy lifting.
- Conservative Rust v0/legacy, Itanium C++, and Go symbol-family evidence is
  recorded without treating a matching spelling as recovered source types.
- Defined Itanium RTTI names, type-info objects, vtables, construction
  vtables, and VTTs are retained as symbol-bounded language-metadata ranges;
  ordinary `.rodata` and `.data.rel.ro` bytes are not overclassified.
- Linked Go 1.18+ `.gopclntab` metadata is decoded under row/name/extent
  bounds, recovering named stripped function entries and extents without
  executing the binary.
- Bounded absolute pointer-table and relocation-backed ET_REL relative-table
  recovery with explicit indirect-target CFG edges and unresolved switch
  defaults. Pointer tables reached through backward-proven constant base
  registers are recovered too, and discovery iterates to a fixed point so a
  newly reached block can expose a later table. No speculative target is
  silently promoted; proven out-of-extent register targets remain explicit
  external/tail candidates.
- MachineFunctionIR v1, StateFunctionIR v1, FunctionIR v1, and CIR v1.
- Compatibility whole-state numbering plus component-level SSA for every GPR,
  modeled flag, control state, and separate stack/image/TLS/heap/unknown memory
  regions. Unproven pointer accesses conservatively alias heap and unknown.
  Blocks carry component phis and predecessor versions at joins and
  loop backedges; stores consume and define their memory region.
- Architecturally undefined flags are first-class outputs. They survive StateIR
  and CIR and become visible `hydir_undefined_flag` calls in low-level C rather
  than silently retaining stale values.
- Conservative `OpaqueEffect` propagation through every native IR layer.
  Unsupported atomics, SSE/AVX/x87 operations, and unsupported EVEX forms retain
  bounded register, flag, memory, and floating-environment footprints instead
  of automatically consuming and producing the full machine state.
- DecompilationUnit v2 with independent structural, semantic, verification,
  and rewrite-readiness claims plus a v1 compatibility reader.
- CIR-to-C11 low-level emission with explicit machine state, memory helpers,
  control labels, and opaque-effect helpers.
- Straight-line, nested acyclic if/else, guarded jump-table switch, pre-tested
  single-header loop, and post-tested single-latch loop structuring. Other
  reducible or irreducible shapes retain explicit labels and gotos.
- Initial SysV AMD64 recovery for integer, XMM/YMM, normalized stack, and
  directly evidenced pointer parameters; RAX:RDX and vector returns;
  uniquely evidenced scalar `float`/`double` and packed floating vector types;
  direct/indirect/tail calls; audited version-aware libc/POSIX/pthread/dynamic
  loader prototypes; fixed argument/result locations and variadic markers on
  audited external calls; noreturn evidence; stack/global objects; and alias sets.
- Entry-RSP stack normalization across common frame-pointer and
  frame-pointer-omitted prologues, with raw accesses retained when joins or
  dynamic stack changes make normalization unprovable.
- Width-generic integer move/extension, ALU including ADC/SBB, compare/test,
  conditional move, setcc, LEA, unary arithmetic, immediate and variable
  shifts/rotates, SHLD/SHRD, flagless SHLX/SHRX/SARX/RORX, bit counts and
  scans, register bit-test/modify,
  register exchange, byte swap,
  full-width MUL/IMUL, two/three-operand IMUL, signed/unsigned division normal
  paths with explicit exception edges and divide-error helpers, accumulator sign extension, and
  common stack operations for 8/16/32/64-bit operands. Narrow CL-count shifts
  and RCL/RCR avoid host-C undefined behavior; architecturally undefined
  results or OF values are emitted explicitly. PUSHFQ/POPFQ preserve modeled
  flags while marking environment-owned RFLAGS bits conservative. PF, AF, and DF are
  first-class state components; parity conditions and undefined flags remain
  explicit. CET `endbr64`, `pause`, and multi-byte NOPs are exact no-effects.
- DF-aware MOVS/STOS/CMPS/SCAS and REP/REPE/REPNE lowering updates the
  implicit registers and comparison flags. Results remain conservative until
  interruption and fault-time partial progress are explicit CFG outcomes.
- Initial native SSE/AVX support covers aligned register moves, unaligned
  128/256-bit moves, scalar MOVD/MOVQ and MOVSS/MOVSD bit transfers, scalar
  and packed ADD/SUB/MUL/DIV/SQRT, scalar single/double precision conversion,
  signed integer-to/from scalar and packed floating conversion with
  direction-sensitive ABI vector types, scalar COMIS/UCOMIS flag production, bitwise
  AND/ANDN/OR/XOR families, modular byte/word/dword/qword lane add/subtract,
  signed/unsigned saturating byte/word add/subtract, signed/unsigned
  saturating packs, low multiply, signed comparisons, signed/unsigned min/max,
  low/high unpack, immediate logical/arithmetic shifts, PSHUFB/PSHUFD/
  PSHUFLW/PSHUFHW, PINSR*, PMOVMSKB, PTEST, byte broadcasts,
  VINSERTI128/VEXTRACTI128, VZEROUPPER/VZEROALL, AESENC, non-temporal vector
  stores with conservative ordering, and 512-bit VPXORD/VPANDQ/VPORQ,
  packed floating arithmetic, and aligned/unaligned moves with XMM/YMM/ZMM
  alias-aware component SSA. Common EVEX opmask merge/zero forms are exact for
  those bitwise and move families, packed floating arithmetic and broadcast,
  VPOPCNTB, VPERMB/VPERMI2B, VGF2P8AFFINEQB, VPCMPUQ, and VPCOMPRESSQ.
  Masked memory forms access only active elements, preserving fault
  suppression, while embedded-rounding and SAE decorators remain explicit and
  fail closed when their environment semantics are not modeled.
  Floating operations use raw-bit MXCSR-aware helper contracts
  and explicit unresolved exception edges. Common LOCK XADD/CMPXCHG,
  CMPXCHG8B/16B, locked binary/unary/carry/bit-test operations, implicit-lock
  memory XCHG, and LFENCE/SFENCE/MFENCE are exact under helper contracts;
  fences thread all StateIR memory
  regions. Common x87 stack, arithmetic, comparison, integer-conversion, and
  transcendental instructions use explicit raw 80-bit registers plus
  control/status/tag and instruction/data-pointer/opcode state. FLDENV,
  FNSTENV/FSTENV, FRSTOR, FNSAVE/FSAVE, and standalone WAIT preserve bounded
  14/28-byte environment and 94/108-byte state-image effects with unresolved
  exception edges where applicable. FXSAVE64/FXRSTOR64 and LDMXCSR/STMXCSR
  use a separate bounded 512-byte legacy extended-state helper, including
  XMM, x87, MXCSR, and MXCSR-mask state. XSAVE/XSAVEOPT/XSAVEC/XSAVES and
  XRSTOR/XRSTORS retain bounded request-mask, XCR0/XSS, directional-memory,
  extended-state, and exception effects while their dynamic image layout
  stays explicit and opaque. CPUID, RDTSC/RDTSCP, XGETBV, and
  RDRAND/RDSEED have bounded environment-helper semantics and explicit
  unsupported-feature or privilege edges where applicable; analysis never
  executes them. INT3 and immediate INT have explicit non-returning
  environment delivery. Other EVEX families retain an explicit ZMM/opmask
  footprint conservatively.
- Aligned MOVAPS/MOVAPD/MOVDQA and VEX equivalents preserve 128/256-bit
  memory transfers on an alignment-checking helper path with explicit fault
  edges instead of becoming opaque solely because an operand is in memory.
- Linux x86-64 SYSCALL remains an opaque kernel/environment transition, but
  its ABI inputs, RAX/RCX/R11 clobbers, flags, unknown-memory effect, unknown
  call edge, and fallthrough are bounded so wrapper analysis can continue.
- Optional verifier-friendly LLVM export from FunctionIR; LLVM is not an
  input to the native C renderer.
- CLI discovery, per-stage lifting, dual-view decompilation, batch output,
  explanations, and coverage. Coverage includes exact/opaque family histograms
  and bounded source-location samples for every opaque family. Legacy
  `--assume-u64x2` commands are unchanged.
- Authenticated gRPC v3 program-analysis jobs, event replay/cancellation,
  per-stage native artifact retrieval, and revision-checked analyst facts.
  v1/v2 remain mounted.
- Python SDK v3 negotiation and digest/media/schema/revision validation.
- Desktop FunctionIndex browsing for symbolized and anonymous stripped
  entries, with native IR, low-level C, structured C, diagnostics, and
  rewrite-readiness shown locally or through v3.
- Dedicated native-pipeline and native-IR validator fuzz targets.
- A manual/weekly real-ELF stress workflow decompiles every one of the 1,481
  functions in the pinned stripped Go executable, pins semantic/artifact
  counts, and compiles every emitted low-level and structured C unit with both
  GCC and Clang.
- A Linux native gate checks deterministic re-emission, controlled stripped
  discovery precision/recall, all-stage lifting, and strict GCC/Clang C11
  compilation for linked, stripped-unwind, absolute/relative jump-table,
  relocatable, Go-pclntab, AVX2/BMI2, floating, atomic/fence, XSAVE,
  mixed exact/opaque AVX-512, tail-call, and REP-string inputs.

The current implementation completes the artifact spine and substantial
vertical portions of loading/discovery, scalar semantics, CFG recovery, stack
normalization, ABI facts, basic structuring, and product integration. Symbol
extents are used when available; stripped linked ELFs can also be lifted from
FunctionIndex entries using bounded recursive recovery that stops at other
known entries. Candidate extents remain explicitly partial, unknown calls and
effects remain conservative, and `rewrite_ready` is always false on the
native path. This is not yet the mature arbitrary-ELF gate: complete
floating-point exception lowering, remaining vector families, exact dynamic
XSAVE component layout, and remaining atomic semantics, full
alias-sensitive heap modeling,
fixed-point whole-program type recovery,
general cyclic/irreducible structuring, and the measured real-world corpus
thresholds remain open.

## Reproduction

```text
hydirctl discover program.elf
hydirctl lift program.elf --function symbol --ir machine
hydirctl lift program.elf --function symbol --ir cir
hydirctl lift program.elf --function symbol --ir llvm
hydirctl decompile program.elf --function symbol --view low
hydirctl decompile program.elf --function symbol --view unit
hydirctl coverage program.elf
hydirctl explain program.elf --function symbol --address 0x401000
hydirctl decompile-all program.elf --output-dir new-output-directory
```

The current local gate covers twenty-two checked-in linked, stripped, and
relocatable fixtures. It discovered and lifted 45/45 functions, recorded 430
exact instruction occurrences and six deliberately opaque dynamic
XSAVE-family operations, and strict-compiled all 45 low-level plus 41 safely
structured C11 views with
Clang 22 under `-Wall -Wextra -Werror`. Four larger compiler probes add seven
functions and 485 exact occurrences with zero opacity; their nine C views
also strict-compile. Deterministic re-emission is byte-identical. These are
fixture measurements, not the mature real-world corpus gate.

The M2 metadata fixture is a stripped shared object with GNU symbol versions,
an undefined PLT import, GOT/PLT, TLS, `.eh_frame`, and relocation-backed
init/fini arrays. Its two hidden constructor/destructor entries are recovered
from the arrays even though the regular symbol table has been removed.
The same source is also pinned as an `ET_REL` object: its section address
spaces, relocation-resolved constructor/destructor pointers, unresolved
external call, native unit artifact, C11 output, and LLVM export form a
reproducible relocatable-object regression path.
An additional stripped shared object has no usable static or dynamic function
symbols. Its two functions are recovered solely from `.eh_frame` FDE ranges,
lifted through the native pipeline, and emitted as compilable low-level and
structured C.
An optimized C++ ET_REL object exercises duplicate-base/index LEA reads,
Itanium destructor aliases, symbol-bounded RTTI/vtable metadata, an explicit
UD2 exception path, and a virtual call whose instruction semantics are exact
while its target remains an explicit partial-CFG terminator.
An optimized Rust 1.96.0 Linux ET_REL object contributes two exact functions
and 80 exact instruction occurrences. Its v0-mangled slice fold retains Rust
symbol evidence and recovers the data pointer in RDI, length in RSI, and RAX
return location; both low-level and hybrid structured views were emitted for
both functions, and all four C views strict-compile.
A separate 1.2 MiB stripped Linux/amd64 binary produced by Go 1.27.0 retains
1,481 bounded pclntab function rows. The test selects `main.hydirMix` from
runtime metadata and lifts its optimized 11-instruction loop with zero opaque
operations. On this Windows debug build, the lazy CLI selection, native
decompilation, and strict C compilation path completed in 1.6 seconds;
explicit eager discovery of all candidates plus 256 block-membership probes
completed in 14.9 seconds. A bounded whole-file coverage pass then lifted all
1,481 rows and counted 116,592 exact versus 37 opaque occurrences (99.968%
exact for this fixture), with 157 exact-under-model, 1,324 conservative, and
four structurally partial functions. Unresolved indirect calls preserve their
target expression and caller fallthrough as conservative, structurally
complete call sites. Unresolved indirect jumps retain exact instruction
effects and target expressions but remain partial-CFG terminators. The only
opaque family in this binary is the Linux `syscall` environment transition.
A full batch emitted 1,481 low-level C units and DecompilationUnit files plus
165 structured views; all 1,646 C files strict-compiled to objects with Clang
22 after the batch gate exposed and drove a dead-temporary fix in `BT` output.
This is evidence that the occurrence target is achievable, not a broad-corpus
or differential-correctness claim.

## Remaining gated work

1. Reproduce and audit the now-demonstrated 95% static-occurrence x86-64 gate
   across the full pinned cross-compiler corpus, then differentially test the
   exact families. Continue closing uncommon atomics, exact dynamic XSAVE
   component layouts, unsigned/packed floating conversions, remaining
   AVX-512 families/decorators, and other vector families without treating
   opacity as exact.
2. Refine the current heap/unknown alias partition into allocation-sensitive
   objects, refine the current atomic/fence volatile partition into mapped
   volatile objects with richer ordering constraints, and
   propagate precise unwind handlers beyond explicit divide/SIMD exception
   edges.
3. Generalize indirect value-set recovery beyond absolute tables and the
   relocation-backed relative-table compiler pattern, then measure controlled
   jump-table target recall.
4. Add call-graph SCC fixed points, aggregate and call-site variadic recovery,
   stronger signedness and pointer/type constraints, and metadata-level
   C++/Rust type evidence plus broader Go runtime/ABI evidence beyond the
   current symbol-family, bounded Itanium metadata-range, and pclntab facts.
5. Extend the post-dominator acyclic structurer and proven latch/switch forms
   with loop forests, control dependence, short-circuit recovery, and phi
   elimination while retaining minimal goto fallback.
6. Build the pinned optimization/language/real-world corpus and publish the
   separate precision, recall, semantics, C-compilation, differential,
   latency, memory, crash, and timeout gates. Run the new fuzz targets in CI.
7. Add AArch64 only after the x86-64 artifact contracts and mature gates are
   stable.

No later milestone may weaken explicit uncertainty or allow partial artifacts
to authorize mutation.
