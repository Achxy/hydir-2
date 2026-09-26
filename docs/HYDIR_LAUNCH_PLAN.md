# Hydir product plan: a Ghidra-backed lifting and reverse-engineering framework

Status: active direction, updated 2026-09-26. This is the current product and implementation plan. The earlier [CTF workflow proposal](HYDIR_CTF_WORKFLOW_PLAN.md) is retained as historical research; its release priorities are superseded here.

## What Hydir is

**Hydir is a binary lifting and reverse-engineering framework with its own GUI.** A user opens a binary in Hydir. Hydir starts a version-pinned, containerized Ghidra headless worker, imports and analyzes the binary there, extracts P-code and other facts, then populates Hydir's GUI and artifacts. Hydir converts P-code into its own explicit semantic IR, runs inspectable analyses and checked transformations, and exports useful LLVM IR and other results with links to the source instructions.

Hydir's existing desktop GUI is the primary user experience. The CLI, Python SDK, and API invoke the same pipeline. The Ghidra project is a managed internal analysis cache; an expert may also import an existing project or use Ghidra directly. Analyst corrections happen in Hydir's model and GUI. CTF challenges are useful fixtures and demos for the framework.

The first competitive reason to use Hydir should be concrete: **open one binary, get a reproducible address-linked lift automatically, run a custom analysis or transformation, and see exactly which semantics and facts support the result.** We should measure this workflow before claiming an advantage over Ghidra, angr, Miasm, rev.ng, or another tool.

## Where the code stands today

| Existing component | Reuse in the new direction | Missing contract |
| --- | --- | --- |
| Native x86-64 ELF loader, discovery, MachineIR, StateIR, FunctionIR, CIR, model, C output | Keep as a native frontend, semantic reference, and regression corpus | It does not ingest Ghidra P-code or project facts |
| `integrations/ghidra/HydIRExport.java` | Extend the existing Ghidra script path | It exports function/CFG/call-graph facts and a program name, but no P-code, types, bytes, or durable project identity |
| `integrations/ghidra/HydIR` extension | Later entry point and address navigation | It currently calls Hydir's remote decompile/patch commands; it is not a project/P-code importer |
| Desktop GUI, including its Ghidra graph view | Make this the entry point that launches analysis and presents linked results | It displays external graph JSON but cannot orchestrate Ghidra or lift P-code yet |
| LLVM exporter | Reuse its validation and artifact plumbing | Its current native form contains effect descriptors and does not establish executable equivalence |
| AnalysisModel, typed C, cache, API/SDK, VM explorer, capture/solver work | Build on these after the importer works | None makes Ghidra the primary frontend yet |

**Status claim:** automatic Ghidra analysis and the P-code lift have not been implemented or validated. The previous estimate that roughly 60% of the *typed native decompilation* milestone was done does not measure progress on this revised product. The first new gate below is open.

## Architecture and artifact contract

```text
Binary opened in Hydir GUI (or passed to CLI/SDK/API)
  -> Hydir job orchestrator -> pinned Ghidra headless container
     -> managed project + auto-analysis
  -> bounded, versioned project snapshot
     raw P-code + instruction bytes + address spaces + flow overrides
     CFG/calls + symbols + prototypes/types + analyst changes
  -> validated PcodeIR -> explicit StateIR -> analyses/transforms
  -> LLVM IR / analysis artifacts / optional C
  -> Hydir desktop GUI + CLI/SDK/API
  -> links back to source instructions in Hydir

Native ELF frontend -> existing MachineIR/StateIR path (retained)
```

1. **Project snapshot v1.** Headless Ghidra creates a managed project from the binary and exports a program/function index; selected functions receive bounded P-code snapshots on demand. The same exporter can read an existing expert-supplied project. Include Ghidra version, language ID, compiler specification, original binary SHA-256, project/program identity, image base, memory blocks, entry, instruction bytes, address-space metadata, ordered raw P-code operations, varnodes (space, offset, size), op sequence numbers, CFG edges, calls, symbols, prototype and type facts, and source labels for analyst changes. Bound operation count and serialized size. Use stable IDs based on address spaces and addresses, not display names. Validate digest, ranges, sizes, references, edges, and schema version on import. Never silently merge snapshots from different binaries.
2. **Separate raw and high P-code.** Raw instruction P-code is the semantic input. Export decompiler/high P-code in an optional second section for SSA, inferred variables, and type hints; keep it tagged as Ghidra's analysis and retain op/address provenance. Raw and high P-code can differ, including overrides and decompiler-created operations. A high-P-code type is evidence, not proof of raw-machine semantics.
3. **PcodeIR v1.** Preserve operation ordering and unique temporaries, register aliasing, bit widths, endian and address-space rules, `LOAD`/`STORE` space IDs, control-flow destinations, `CALLOTHER` userops, and unknown or injected effects. Lower to Hydir's explicit state/effect layer through a specified opcode table. The first lift targets x86-64; architecture-neutral state concepts must be separated from x86-specific registers before adding other Ghidra languages. Unsupported operations stay explicit and block exactness claims.
4. **LLVM export.** Emit verifier-clean LLVM for the supported P-code subset with a documented state and memory ABI. Use memory intrinsics or typed helper calls where ordinary LLVM loads/stores would erase guest-memory distinctions. Export a manifest of translated, opaque, and assumed effects; a module with opaque hooks is inspectable but not standalone equivalent. Do not feed optimized LLVM back into a rewrite path until its preconditions are checked.
5. **Analysis layer.** Expose graph traversal, def-use, slicing, type and alias evidence, symbolic/concrete evaluation, and transformation passes over stable artifact APIs. Cache by binary digest, Ghidra snapshot revision/fingerprint, Hydir analysis version, and options. A project edit invalidates the affected function and dependent summaries. Keep provenance and unresolved facts visible in API results.
6. **Integration.** Opening a binary in the existing Hydir GUI starts or reuses the container job, shows progress and errors, imports the index, and links functions, graph, raw P-code, state IR, LLVM, provenance, and diagnostics. `hydirctl analyze <binary>` and equivalent SDK/API calls invoke the same orchestrator. Direct snapshot import remains available for advanced users and tests. Exact command spelling can change before release; the versioned snapshot contract cannot change silently. The Ghidra extension is an optional expert integration.

## Implementation order and gates

| Order | Deliverable | Acceptance gate |
| --- | --- | --- |
| 0. Contract | Freeze snapshot v1 and PcodeIR v1, with a small checked-in Ghidra-exported fixture | Deterministic round-trip; invalid digests, widths, varnodes, edges, and schema versions fail clearly |
| 1. Project bridge | Extend the exporter to capture the program index and a selected function's raw P-code, bytes, CFG, calls, and project metadata; import it in Rust | Headless import and export of a binary succeeds; every P-code op has an address and order; existing-project export agrees on the same semantic section |
| 1a. Automatic Ghidra worker | Package a pinned Ghidra release, required JDK, and exporter in a container; have Hydir provision, launch, and monitor it | On a prepared demo machine, opening a binary in Hydir requires no Ghidra or container commands and populates the function index; cancellation, timeout, cache reuse, and failure diagnostics work |
| 2. Semantic lift | Lower core integer, bitwise, comparison, extension, branch, memory, and call operations into explicit state/effects | Per-op and per-function tests at multiple optimization levels; unsupported operations appear as opaque effects |
| 3. LLVM | Emit runnable LLVM for the exact supported subset and inspectable LLVM with explicit hooks for partial functions | `opt -verify` plus behavioral comparison against original function and a Ghidra P-code oracle on exact fixtures; failed comparison removes the exact claim |
| 4. Workbench and framework API | Hydir GUI plus stable CLI, Python, and service access to snapshot, IR, provenance, diagnostics, and pass outputs | A user opens a binary and inspects linked results in Hydir GUI; an external script runs the same analysis and maps results to source addresses |
| 5. Analyses | Incremental project updates, interprocedural summaries, type constraints, transformation preconditions, VM-aware views | Changed-function and caller invalidation tests; ambiguous aliases stay unresolved; checked transforms survive differential tests |
| 6. Breadth | More Ghidra languages, whole-program import, richer decompilation and UI, VM recovery | Add each target only with a project fixture, semantic oracle, coverage report, and explicit unsupported cases |

**First end-to-end demo:** start Hydir and open a stripped x86-64 ELF. Hydir automatically runs containerized Ghidra analysis and fills the function list. Select a function and inspect its linked raw P-code, state IR, LLVM, slice, and source instructions inside Hydir. Repeat the analysis through the CLI/SDK. Show one unsupported instruction whose effect remains visible. The presenter does not launch or operate Ghidra. CTF binaries can stress the same path later.

The test matrix starts with straight-line arithmetic, branches, loops, calls, stack/global memory, indirect flow, and at least one `CALLOTHER` case. Use stripped and DWARF-bearing builds at several optimization levels. Record coverage by opcode and artifact fidelity. LLVM verification alone is never a semantic test.

### Automatic container contract

Hydir's default Ghidra-backed analysis path launches a reproducible **headless Ghidra worker** automatically. Pin the official Ghidra release and JDK, verify the release checksum during the image build, retain bundled license notices, and record exact versions in each snapshot. Run as a non-root user with bounded CPU, memory, and time; default to no network, a read-only binary mount, writable scratch project space, and a mounted output directory. Hydir checks or provisions the pinned image and reports missing runtime setup or analysis failures inside its GUI; users never need Ghidra or container commands for the normal flow. Keep the native ELF path available. For expert-supplied projects, process an isolated copy after it is closed in the Ghidra GUI. Container packaging follows the snapshot contract so it can be tested against a real exporter. The demo host may have its runtime preinstalled; a public installer needs an in-app runtime setup path.

## Design references and limits

- Ghidra documents [instruction P-code](https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Instruction.html), [P-code operations](https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/PcodeOp.html), and [headless project analysis](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/RuntimeScripts/support/analyzeHeadlessREADME.md). Headless analysis can process an existing project or import a new binary; Ghidra warns that a project already open in its GUI may not run headlessly.
- Ghidra's [NOTICE](https://github.com/NationalSecurityAgency/ghidra/blob/master/NOTICE) describes its Apache 2.0 license and bundled third-party components. Container redistribution must carry the corresponding notices.
- [Ghidrall](https://github.com/toor-de-force/Ghidrall) demonstrates P-code-to-LLVM translation and is a research reference. Its coverage and validation are not Hydir's correctness contract.
- [Remill's explicit memory intrinsics](https://github.com/lifting-bits/remill/blob/master/docs/INTRINSICS.md) and [Anvill's specification-driven lift](https://github.com/lifting-bits/anvill) are useful design comparisons. Hydir still needs its own import, semantics, and tests.
- [Goblin](https://github.com/m4b/goblin) parses object formats; it does not translate P-code. The existing `object`/`gimli` loader is adequate until a measured loader gap appears.

## Product decisions

- Opening a binary in Hydir is the default front door. Hydir manages Ghidra headlessly and imports its project/P-code facts. The native x86-64 ELF path remains supported and can cross-check results.
- Hydir's versioned IR remains canonical inside the framework. LLVM is an export and analysis interchange, not an implicit replacement for the IR or a proof of equivalence.
- Raw P-code is the semantics baseline. High P-code, prototypes, types, and analyst edits are valuable project evidence with separate provenance.
- Hydir's existing desktop GUI is the primary workbench and owns the automatic analysis flow. CLI, SDK, and API access expose the same framework; the Ghidra extension supports expert project exchange.
- No broad architecture, decompiler-quality, VM, solve-rate, or competitive superiority claim ships without a task-specific gate.
