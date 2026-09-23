# Hydir master plan: understand binaries, solve challenges, verify results

Status: active implementation roadmap. Updated 2026-09-23. This is the single source of truth for launch scope, order, gates, and claims.

This document consolidates the typed-decompiler milestone, CTF workflow, VM roadmap, competitor research, desktop workbench, and launch requirements. It replaces the earlier fragmented proposals. The status below distinguishes implemented capabilities from proposed launch gates. No competitive benchmark or end-to-end launch workflow has passed yet.

## 0. The launch decision

Hydir should win a **specific investigation**, not a feature-count contest: an analyst opens an unfamiliar stripped x86-64 ELF, finds the check that rejects an input, understands the relevant code and data, produces a changed input, and sees that input succeed in a fresh run of the original binary. The project must retain enough evidence to reproduce and challenge that answer. A second, bounded demo explains a virtualized check through a guest graph and checked expression simplification. General decompiler parity, broad architectures, and commercial VM support are later goals.

| Order | User-visible result | Engineering gate | Status on launch branch |
| --- | --- | --- | --- |
| 1. Trust the base | Open a binary and retain low-level views when recovery fails | M0 compatibility, deterministic fixtures, truthful capability report | Partly integrated; full GUI/package gate open |
| 2. Understand the check | Navigate from a condition to typed C, field evidence, calls, and machine instructions | M1 expressions, M2 typed flow and type constraints, M3 dependency invalidation | Model and typed subsets implemented; widths, calls, indirect flow, and targeted rediscovery open |
| 3. Observe the original | Run a controlled input, stop at a useful boundary, inspect real state, and replay | M4 capture, origin mapping, runner, PIE/missing-memory gates | Replay and snapshot contracts exist; named-symbol capture is experimental and awaits live Linux gate |
| 4. Solve and explain | Show the bytes behind failure, generate a candidate, and validate it natively | M5 guided solving plus M6 slices, trace indexing, and result states | Function-level Triton bridge exists; guided input solve is open |
| 5. Explain a VM | Map host activity to a bounded guest CFG and check one scoped simplification | M7 guest graph, effects, multiple-input comparison, equivalence query | VM profile and bounded VPC explorer exist; guest CFG/checks open |
| 6. Ship and compare | Complete the investigation in the installed app and reproduce it by CLI | M8 usability, package, independent challenges, fair baselines | Not yet gated |

The order expresses dependencies, not six isolated projects. Build UI affordances and regression fixtures with the feature they expose. Prioritize a failed end-to-end workflow over adding another disconnected analysis pass.

**Launch rule:** a result card must distinguish an observation, a static inference, an analyst assertion, a solver result under assumptions, and a native-validated candidate. A timeout, incomplete CFG, missing page, or unknown alias must remain visible at the point where it affects the answer. Never use C compilation, one successful replay, or an SMT equivalence of a small expression as a broader correctness claim.

## 1. Product objective and positioning

Build a reverse-engineering workbench in which an analyst can open a stripped binary, understand its data and control flow, identify why an input fails, generate a candidate input, and verify the result against the original executable. The same project should explain a virtualized validation routine and retain the evidence behind every important conclusion.

The three required launch workflows are:

1. **Understand:** recover useful types and readable C, inspect evidence, edit interpretations, and navigate all related views.
2. **Solve:** choose an input and a goal, follow its dependencies, run bounded exploration, and replay a generated input against the original program.
3. **Explain obfuscation:** recover a bounded guest CFG, separate interpreter activity from relevant guest effects, and check a proposed simplification.

The competitive objective is lower analyst effort and shorter time to a verified answer on these workflows. Measure this against Ghidra, angr with angr-management, rev.ng, and Miasm where each supports the task. General architecture coverage and ecosystem parity remain longer-term work.

Reasons for a user to choose Hydir should be visible in ordinary use:

- A type field, C expression, instruction, trace occurrence, and input byte can all refer to the same underlying evidence.
- An analyst can ask why a condition failed and move directly to the relevant input bytes and writes.
- A generated solution comes with a fresh execution result and a reproducible recipe.
- Recovered VM logic remains connected to host instructions and observed executions.
- Unknowns, assumptions, conflicting facts, and exhausted budgets remain inspectable.

These are product differentiation hypotheses. GUI symbolic execution, SSA, snapshots, taint analysis, structure recovery, and trace navigation already have substantial prior art, including [Ponce](https://github.com/illera88/Ponce).

### Competitive contract

| Reference | Established strength | Hydir's launch test |
| --- | --- | --- |
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/languages/html/pcoderef.html) | Broad disassembly/decompilation built on explicit instruction semantics | Recover the declared ELF subset accurately, then move from a failed check to its input bytes and a verified repair in one project |
| [angr and angr-management](https://docs.angr.io/en/latest/) | Symbolic execution, configurable exploration, decompilation, and a graphical analysis environment | Make a CTF solve reproducible from capture to native replay with visible constraints, unresolved effects, and a usable guided interface |
| [rev.ng](https://docs.rev.ng/user-manual/key-concepts/artifacts-and-analyses/) | Validated editable model and function-granular cached artifacts | Connect each type edit to C, xrefs, slices, and observed execution while proving selective invalidation |
| [Miasm](https://github.com/cea-sec/miasm) | Scriptable IR, emulation, symbolic execution, and expression simplification | Give a repeatable analyst workflow with inspectable intermediate artifacts and a checked result |

This table defines experiments, not claims that Hydir already exceeds these tools. Compare the same binary, goal, hardware, budgets, and analyst guidance; count preparation time and failed runs.

### Critical path to the first public demo

1. **Make the existing spine trustworthy:** finish M0 integration and the bounded M1 expression/semantics gates. Preserve low-level output whenever a typed view is unsupported.
2. **Make the binary understandable:** finish M2 typed flow, aggregate recovery, and model editing, then M3 targeted discovery and artifact invalidation. Demo a type edit changing C and xrefs without reprocessing unrelated functions.
3. **Make a result verifiable:** implement M4 capture and fresh replay, then M5 goal solving and M6 input-to-condition slices. Demo a failing input, a generated candidate, and a native-confirmed success from the same project.
4. **Explain the virtualized check:** complete the bounded M7 guest graph and checked simplification on the first-party VM fixture. Show unexplored edges and assumptions alongside the recovered logic.
5. **Ship and measure:** complete M8 navigation, recipes, packaging, installation, external trials, and fair comparisons. Publish failures and unsupported cases with the successful demo.

The first public demo requires all five steps. An earlier typed-C or solver preview can be shown with its narrower verified scope.

## 2. Current baseline

| Area | Verified status | Remaining work |
| --- | --- | --- |
| Main checkout | `main` at `bec9a88`; native ELF discovery, artifact pipeline, low-level/structured C, desktop explorer, bounded Triton bridge, and existing patch/interchange paths | Merge the verified launch branch when the stage is reviewable |
| Launch branch | `codex/hydir-launch` integrates the typed/model/VM foundation, fixes Triton solver-status handling, exposes capability status, and implements the first bounded `ExpressionIR v1` and typed CFG consumers | Finish M0 GUI/package gates and extend M1 semantics |
| Analysis model | Digest-bound JSON, bounded DWARF import, named types/prototypes, evidence, local analyst edits and revision checks | Stronger propagation, stable variable identities, remote edits, better editing UX |
| Aggregate recovery | Offset/width constraints, bounded cross-function propagation, recursive pointer evidence, explicit conflicts | Derived pointers, stronger array evidence, interactive roots, broader fixtures |
| Typed C and expression layer | `HighLevelCIR v1` handles linear supported 64-bit operations, frame spills, fields, and fixed direct calls. `HighLevelCfgCir v3` adds a separate bounded 64-bit subset for direct branches, joins, loops, normalized MOV memory reads/writes, and 64-bit LEA; its renderer structures private diamonds and simple pre-test loops, retaining gotos elsewhere. Scalar writes, live zero-flag snapshots, and memory addresses/effects lower from `ExpressionIR v1`. CFG memory actions retain alias-region versions, emit bytewise little-endian C11 helpers, and can carry model-backed fixed 64-bit fields, indexed eight-byte array fields, and one field within an array of named structs when an invariant pointer and index multiplier match exact model layout. Entry-block, single-write derived bases and indexes are supported. Index bounds remain unproven. ExpressionIR preserves SSA joins, source bytes, and residual effects | Finish general flag/control translation, broader derived-pointer and index propagation, calls, full widths, indirect control flow, and selective caching for v3 |
| Low-level C | Existing structured flow and goto fallbacks | Preserve availability throughout typed-C work |
| Cache/API/SDK | Local selective typed cache; model/HLC/typed-C read artifacts | General artifact dependency tracking, remote writes/cache, execution artifacts |
| Triton integration | Bounded function-level symbolic bridge with two symbolic argument registers; solver timeout/unknown no longer reports UNSAT | Captured process state, input models, environment summaries, goal solving, native replay |
| Execution foundation | `InputSpec v1`, bounded Bubblewrap replay, `NativeReplayReport v1`, `ExecutionSnapshot v1`, sparse reads, and an experimental named-symbol GDB/MI capture producer | Live Linux capture gate, address and post-input stops, original-byte origin mapping, Triton resumption, cancellation, WSL2 launch |
| VM support | Profile and bounded host/VPC explorer | Guest CFG, traces, slices, checked simplification; current completeness/rewrite flags remain false |

The integrated branch passes `cargo test --workspace --locked`; the Triton bridge, instruction oracle, SDK boundary, CLI doctor, model verification, and ExpressionIR smoke checks also passed in this development environment. The typed CFG now snapshots ordered 64-bit subtraction operands before a register write and uses their compare-equivalent flags across a bounded CFG join. It also handles direct and compound addition checks over carry, overflow, sign, and zero from prewrite operands, plus signed and unsigned compound branches after 64-bit `test`, `and`, `or`, and `xor`. Logical results are normalized so `test` and `and` flag paths can rejoin. These tests cover bounded behavior and do not establish launch readiness. GCC and WSL2 are absent on the current Windows host, so Linux runner and dual-compiler gates require another environment. Replace any approximate completion percentage with this capability matrix and the gates below.

## 3. Scope and architectural decisions

- **Initial target:** Linux x86-64 little-endian ELF, including stripped and DWARF-bearing builds, PIE and ordinary executables, and the supported SysV ABI subset.
- **Desktop:** Windows application with a local Linux runner through WSL2; support the same runner and CLI on Linux. Pin and test an Ubuntu 24.04 runner environment.
- **Analysis engines:** Hydir native analysis plus Triton. Use GDB/MI as a process capture/control component. Competitor frameworks are research and evaluation references.
- **Canonical representation:** retain Hydir's native artifact pipeline. LLVM remains optional export, consistent with ADR 0019. Current descriptor-based LLVM output is inspectable and verifier-friendly; executable equivalence requires separate semantics and validation.
- **Model:** JSON remains canonical; analyst edits affect presentation and analysis through explicit, validated model revisions.
- **Release:** quality gates determine readiness. Each milestone produces a usable workflow and a reproducible acceptance result.
- **Execution:** opening a binary performs analysis. The Run action starts a separate Linux job with bounded resources, controlled inputs, no network by default, and scoped filesystem access. Execution stays local in the first release.

### Shared data flow

```text
ELF -> ProgramSpec / FunctionIndex -> MachineIR -> StateIR -> FunctionIR
                                                        |
                                                        v
                                                ExpressionIR v1
                                                  /     |     \
                                        typed C       slices    semantic checks
                                           ^            ^          ^
                                           |            |          |
                                      AnalysisModel <-> evidence <-> Triton sessions
                                                                      ^
                                                                      |
                                                        Linux capture and replay

VM analysis consumes the same expressions, memory effects, model, and traces.
```

Existing StateIR has component SSA, but its operations still describe machine operations. Introduce a normalized expression graph rather than extending the current register-to-text lowering into several independent implementations.

## 4. Research principles to apply

| Reference | Principle used in Hydir |
| --- | --- |
| [angr decompiler API](https://docs.angr.io/en/latest/api/angr.analyses.decompiler.html) | Keep expression, variable, call-site, structuring, and rendering passes independently inspectable; cache intermediate graphs for retyping |
| [angr CFG recovery](https://docs.angr.io/en/v9.2.140/analyses/cfg.html) and [guided exploration](https://docs.angr.io/en/latest/api/angr.exploration_techniques.explorer.html) | Start with fast static recovery, invoke expensive execution on selected unknowns, and retain find/avoid/exhausted result sets explicitly |
| [Ghidra p-code](https://ghidra.re/ghidra_docs/languages/html/pcoderef.html) | Separate instruction semantics from recovered source expressions; keep mappings between levels |
| [rev.ng artifacts](https://docs.rev.ng/user-manual/key-concepts/artifacts-and-analyses/) | Editable model facts, function-level artifacts, and dependency-based invalidation |
| [Retypd](https://arxiv.org/abs/1603.05495) and [Symless](https://github.com/thalium/symless) | Interprocedural type constraints, recursive aggregates, and analyst-selected roots for structure propagation |
| [SAILR](https://www.usenix.org/conference/usenixsecurity24/presentation/basque) | Compiler-aware control-flow recovery; preserve useful gotos when structure cannot be justified |
| [angr Symbion](https://angr.io/blog/angr_symbion/) | Execute startup concretely, capture at a useful boundary, then perform focused symbolic work |
| [Miasm dynamic symbolic execution](https://github.com/cea-sec/miasm/blob/master/miasm/analysis/dse.py) and [dependency analysis](https://github.com/cea-sec/miasm/blob/master/miasm/analysis/depgraph.py) | Follow concrete runs with symbolic input bytes, explicit path constraints and external-effect handlers; expose unresolved dependencies |
| [FLOSS](https://github.com/mandiant/flare-floss/blob/master/doc/theory.md) and [capa](https://github.com/mandiant/capa) | Recover hidden strings and show explainable behavioral hints with supporting locations |
| [Tenet](https://github.com/gaasedelen/tenet) | Indexed navigation through trace occurrences and register/memory changes |
| [Remill](https://github.com/lifting-bits/remill) and [McSema limitations](https://github.com/lifting-bits/mcsema/blob/master/docs/Limitations.md) | Treat instruction semantics, recovered control flow, and execution environment as separate correctness obligations |
| [Hackyboiz VM study](https://hackyboiz.github.io/2025/09/11/banda/LLVM_based_VMP/en/), [Aftermath Themida](https://aftermathlabs.net/blog/09/05/2026/), [Aftermath Tencent VM](https://aftermathlabs.net/blog/31/07/2026/) | Combine VM context, effect tracking, multiple paths, and correct loop joins; retain the scope of every specialization |

Apply these ideas within the chosen architecture. Pin upstream versions for comparisons and retain attribution and applicable licensing information for any reused code or fixtures.

The proposed product contribution is the **evidence-linked repair loop**: from one failed condition, show the static and observed dependencies, the input-byte origin, the assumptions used to generate a candidate, the precise changed bytes, and the fresh native result in one navigable project. Individual ingredients exist elsewhere, including Symbion and Miasm's dynamic symbolic execution. Treat the integrated workflow as a hypothesis to validate with user trials, not as a novelty or superiority claim until measured.

Add a small versioned `InvestigationClaim v1` artifact once the first solve works. It should bind a single user-facing statement (for example, “bytes 4–7 caused this branch” or “this candidate reaches success”) to binary/input hashes, address and trace references, model revision, assumptions, evidence kind, coverage, and invalidation dependencies. Exporting a claim must reproduce its check or state why that check is unavailable. This gives both the UI and CLI one honest contract for explaining results, without building a general theorem prover or claiming whole-program correctness.

## 5. Milestone M0 — Integrate and establish the baseline

**Deliverables**

- Create a launch integration branch from current main; review and integrate the VM foundation and five typed/model/cache commits in dependency order.
- Retain the latest desktop fixes, existing compatibility paths, and private development-document exclusions.
- Rerun workspace, CLI/API/SDK, GUI smoke, typed C compilation, and existing differential tests on the integrated revision.
- Freeze toolchain versions, Triton revision, reference hardware, fixture manifests, binary hashes, and capability-report format.
- Publish internal status as implemented, integrated, verified, or deferred; keep these distinct.

**Gate:** one clean integrated revision reproduces the existing supported behavior. Every earlier supported artifact reader and low-level C workflow remains usable.

## 6. Milestone M1 — Build the shared semantic expression layer

**Deliverables**

- Add `ExpressionIR v1` with explicit bit widths, signed/unsigned comparisons, extension/truncation, extracts/concatenation, arithmetic/bitwise operations, loads/stores, call effects, conditions, phi nodes, and stable expression IDs.
- Preserve byte order, partial-register effects, flag dependencies, undefined outputs, control effects, and instruction-address provenance.
- Model memory by byte ranges and versions with alias sets where justified. Unknown writes and calls invalidate affected facts conservatively.
- Add bounded constant/copy propagation, dead assignment removal, expression folding, and phi simplification. Each pass declares required facts and reports unsupported operations.
- Implement an explicit adapter between supported ExpressionIR operations and Triton bit-vector expressions. Cross-check this boundary on instruction and function fixtures.
- Use stable variable identities separate from rendered names, supporting later split/merge edits and deterministic artifacts.

**Gate:** generated and boundary-value tests cover supported widths, partial registers, flags, aliasing, joins, and loops. Unsupported effects survive all passes. The shared layer produces no stronger fidelity claim than its inputs and assumptions justify.

## 7. Milestone M2 — Deliver typed decompilation and usable type recovery

**Typed C**

- Add `HighLevelCIR v2` with typed expressions, locals, blocks, conditions, loops, switch, labels/gotos, memory operations, calls, returns, and source mappings.
- Lower from FunctionIR and ExpressionIR. Support 8/16/32/64-bit integer behavior, signedness, casts, indexing, pointer arithmetic, and aggregate access within the modeled subset.
- Recover branches and joins first, then natural/nested loops, break/continue, and bounded switch tables. Preserve control flow with gotos for irreducible or unresolved regions.
- Extend fixed SysV direct calls, stack arguments, return recovery, tail calls where established, and indirect calls with justified prototypes. An indirect callee address may remain a function-pointer expression while its target set stays unresolved.
- Emit C11 with explicit helpers where needed for machine arithmetic, shifts, unaligned access, and alias-safe memory. Include type/layout assertions and support code. Check pointer and signed-arithmetic assumptions before choosing idiomatic C.
- Preserve explicit opaque-effect calls in compilable conservative output when their state interface can be represented. Otherwise return a typed-view diagnostic with immediate navigation to existing low-level output.
- Keep compilation, modeled semantic fidelity, differential verification, and rewrite eligibility as separate properties.

**Types and analyst control**

- Evolve to `AnalysisModel v2` for function-pointer types, stable variable overrides, richer evidence, and derived-pointer relationships; support validated migration from v1.
- Propagate offset, width, stride, pointer, and call constraints across bounded call-graph SCCs, including base-plus-offset pointers and recursive structures.
- Record observed object extent as a lower bound. Infer array bounds only with sufficient static, debug, or explicitly scoped evidence; retain stride-only hypotheses separately.
- Keep overlapping fields and competing aliases unresolved unless evidence supports a union or a deliberate analyst interpretation.
- Add **Recover object layout** on a selected pointer: choose scope, preview fields and conflicts, inspect field xrefs, then accept edits.
- Support rename/retype, prototype edits, variable split/merge, undo/redo, and evidence inspection. Analyst assertions do not silently become solver constraints or alias proofs.

This work draws on [Retypd](https://arxiv.org/abs/1603.05495), [Symless](https://github.com/thalium/symless), and [SAILR](https://www.usenix.org/conference/usenixsecurity24/presentation/basque), without requiring their full implementations.

**Gate:** cross-function linked lists, arrays of structures, overlapping aliases, recursion, branches, and loops pass layout/oracle checks. Every emitted typed-C fixture compiles under strict Clang and GCC C11 settings. Functions admitted to the exact-under-model subset pass differential tests.

## 8. Milestone M3 — Make discovery, edits, and artifacts incremental

**Deliverables**

- Replace repeated whole-function indirect-target recovery with a bounded changed-address worklist. Revisit affected blocks, functions, call sites, and summaries; record frontier and stop reason.
- Accept new facts from static analysis, analyst edits, and observed execution with distinct evidence labels. An observed target is evidence for that execution, not a complete target set.
- Preserve address identity through module identity, relative address, load bias, and code version. Changed code bytes invalidate related analysis.
- Generalize artifact dependencies to types, prototypes, functions, callers, options, semantics versions, and engine versions.
- Distinguish name-only rerendering, expression/type relowering, and machine-code rediscovery. Reuse unaffected artifacts after revision changes through validated dependencies.
- Extend existing revision/idempotency checks to remote model editing and server artifact caches. Handle stale writes explicitly and preserve prior evidence.
- Give background jobs progress, cancellation, stale-result rejection, and restart/recovery behavior.

**Gate:** editing one field or prototype invalidates exactly the required artifacts and callers; unaffected functions remain reusable. Stale asynchronous results cannot overwrite newer edits. Bounded rediscovery preserves diagnostics and unresolved edges.

## 9. Milestone M4 — Capture useful execution state and replay inputs

This is the first execution deliverable. It can proceed alongside M1–M3 once M0 establishes common artifact and identity contracts.

**Deliverables**

- Build a local Linux runner with a versioned desktop/CLI protocol, dependency diagnostics, resource budgets, cancellation, and crash reporting.
- Use GDB/MI to run to an input boundary or selected function, pause the process, and capture registers, flags, mappings, module/load addresses, memory pages, and supported thread-local state. Start with single-threaded fixtures.
- Record which mappings/pages are present. Missing memory produces a fetch or an explicit unsupported result; it never silently becomes zero-filled state.
- Define stdin, argv, file bytes, and function-harness inputs, including length, encoding/alphabet constraints, offsets, and origin mappings.
- Prefer capture immediately after input delivery when symbolizing original bytes. Captures after parsing require prefix constraints or a validated mapping back to the original input. An internal-state solution without that mapping is a function witness.
- Record external reads/writes and deterministic environment events needed by the selected scope. Retain time/randomness assumptions and library-summary versions in the recipe.
- Replay candidate inputs in a fresh execution of the original binary, validating the chosen success condition and recording binary/input hashes, output, exit status, and relevant observations.

The architecture follows the capture-and-focus principle demonstrated by [Symbion](https://angr.io/blog/angr_symbion/). Native replay is an observed result for that input and environment; it does not establish global equivalence.

**Gate:** stdin, argv, and file fixtures can be captured, resumed in the supported Triton scope, and replayed reproducibly. PIE addresses resolve correctly. Missing memory, code changes, cancellation, and unsupported thread behavior produce explicit results.

## 10. Milestone M5 — Turn Triton into a guided CTF workflow

**Deliverables**

- Replace the two-register bridge limitation with versioned analysis sessions over captured state or an explicit function harness.
- Add goals for reach/avoid addresses, branch outcomes, return values, memory predicates, and observed output conditions. Let users select goals from C, CFG, or traces.
- Implement bounded libc/syscall summaries for the supported workflows: input, output, byte copying/comparison, string lengths, allocation, and process exit. Define ABI, memory effects, failure behavior, and assumptions for each summary.
- Add seed queues, path deduplication, coverage guidance, per-query limits, and focused exploration of input-dependent conditions.
- Build static and dynamic dependency slices with data and control dependencies. Show unknown aliases/effects and whether a slice is trace-specific or conservative. Incomplete slices can prioritize search but cannot justify silently removing possible behavior.
- Add bounded compatible-state merging at established joins, pure-helper summaries with preconditions, and query caching keyed by expressions and assumptions. Start with simple supported regions and measure the benefit before expanding.
- Use solver APIs that distinguish SAT, UNSAT, UNKNOWN, and timeout. Distinguish bounded search exhaustion from proof of unreachability.
- Present candidates and fresh native replays separately. Keep failed validation inputs and divergence details for debugging.

**Initial budgets to validate at M0**

| Profile | Session wall time | Memory | Seed limit | Instructions per execution | Solver query |
| --- | --- | --- | --- | --- | --- |
| Interactive | 60 seconds | 2 GiB | 256 | 1 million | 2 seconds |
| Deep | 10 minutes | 4 GiB | 4,096 | 10 million | 10 seconds |

Total session time and memory cap every profile. Persist remaining frontiers for explicit continuation.

**Result states:** native-validated candidate, unvalidated candidate, function witness, unsatisfiable query under recorded assumptions, budget exhausted, solver unknown/timeout, unsupported effect, validation mismatch, canceled, and runner error.

**Gate:** users can solve supported checks from the GUI without writing a solver script, export the full recipe, and reproduce the input and validation using the CLI. All analyst-supplied addresses, summaries, constraints, and guidance appear in that recipe.

## 11. Milestone M6 — Help analysts find the interesting logic

**Deliverables**

- Provide unified strings, xrefs, imports, functions, callers/callees, and address search.
- Recover bounded stack-built and decoded strings using candidate selection, caller context, execution, and memory differences. Show where each value was recovered and under which execution or assumptions.
- Add a small explainable rule set for input readers, comparisons, possible decoders, and possible VM dispatchers. Each hint links to its supporting instructions and calls.
- Build chunked traces with indexes for instruction occurrences, input events, register changes, and memory reads/writes; virtualize large lists and graphs.
- Add previous/next writer, last write to this field, input bytes influencing this condition, and comparison of failing/successful runs at the first relevant divergence.
- Label native observations and Triton-derived execution separately. Include syscall-origin memory writes in the event model.
- Build `InvestigationClaim v1` for the first supported failed-condition explanation and replayed candidate. Link each claim to its evidence, assumptions, binary/input identity, and invalidation dependencies. Unknown dependencies remain listed rather than silently excluded.

Use [FLOSS](https://github.com/mandiant/flare-floss/blob/master/doc/theory.md), [capa](https://github.com/mandiant/capa), and [Tenet](https://github.com/gaasedelen/tenet) as design references. Implement the launch subset through Hydir and Triton.

**Gate:** a stripped fixture with encoded messages leads from recovered string to validator, condition, relevant input bytes, and a trace occurrence without address copying between tools.

## 12. Milestone M7 — Complete a bounded VM analysis workflow

**Deliverables**

- Apply recovered layouts to VM context, VPC, virtual registers, stack, and guest memory.
- Extend the existing explorer into guest basic blocks and edges, retaining a host-instruction mapping and unexplored frontier.
- Key exploration by sufficient host/VPC context, decode state, and code version. Separate observed edges, statically established edges, and unresolved transitions.
- Carry symbolic guest data through loop joins; specialize only established bytecode/dispatch constants within their valid scope. Track overlapping memory writes at byte granularity.
- Add guest effect summaries and backward slicing from a selected output/branch. Remove interpreter-local activity only when escape and observable-effect analysis justify it.
- Compare host observations with recovered guest execution over multiple inputs, branches, and loop counts.
- Propose simplifications for supported pure bit-vector expressions. Record original expression, candidate, width, preconditions, and a separate equivalence query. Retain counterexamples and unknown/timeout results.
- Show guest CFG, recovered expressions/C, coverage, and remaining unknowns. Keep region-level claims separate from whole-function claims.

The first guest-graph gate is a first-party VM with loops, a conditional path, bytecode changes across builds, and external memory effects. Commercial protectors follow later. The loop-join and specialization hazards discussed by [Aftermath Labs](https://aftermathlabs.net/blog/31/07/2026/) inform required regressions; multiple-path concerns from [Hackyboiz](https://hackyboiz.github.io/2025/09/11/banda/LLVM_based_VMP/en/) inform coverage reporting.

**Gate:** recover the declared guest scope, match its observable behavior on the test matrix, and complete at least one scoped simplification check. A successful expression check never automatically marks the surrounding binary rewrite-ready.

## 13. Milestone M8 — Make the workbench coherent and distinctive

Implement UI work alongside each milestone, then use this stage for end-to-end integration and polish.

**Required launch experience**

- One project with linked C, disassembly, CFG, calls, types, input bytes, traces, and evidence.
- Selection synchronization, stable back/forward history, keyboard navigation, search, bookmarks, comments, and saved workspace state.
- Editing with preview, validation, undo/redo, persistence, and a clear indication of analysis that is still updating.
- A guided investigation route: open, find input/check, inspect evidence, choose a goal, solve, replay, export.
- Background work remains cancelable. Cached content stays usable during analysis. Errors name the affected operation and offer a concrete next step.
- Capability and fidelity information appears where it changes a user's decision. Detailed internal artifacts remain available to advanced users.

**Differentiation to deliver**

1. **Explain this rejection:** connect a failed condition to field values, input byte ranges, relevant instructions, and recorded assumptions.
2. **Repair this input:** preserve locked bytes, propose a satisfying change, show the changed bytes, and replay the result. A minimum-change claim requires a completed optimization check; otherwise show the best candidate found.
3. **Explain this simplification:** connect a small recovered expression to its host/guest slice and the check supporting it.
4. **Export this investigation:** retain model edits, inputs, goals, guidance, tool versions, budgets, evidence, and replay results in a portable bundle.

**Bounded follow-up experiment:** branch a model interpretation, compare artifacts, and seek an input distinguishing two supported pure expressions. Verify the observation against the original function when possible. General hypothesis solving remains experimental until it passes dedicated gates.

**Gate:** a new user can complete each documented launch workflow without the author intervening or opening an undocumented console.

## 14. Interfaces, compatibility, and repository ownership

| Component | Responsibility |
| --- | --- |
| `hydir-ir`, `hydir-semantics`, `hydir-decompile` | Versioned expressions, semantics, discovery, ABI facts, provenance, structuring inputs |
| `hydir-model` | Models, migrations, DWARF, constraints, layouts, conflicts, edits |
| `hydir-hlc` | High-level CFG/expressions and C11 output |
| `hydir-analysis` | Shared dependencies, slices, summaries, explainable hints |
| `hydir-project` | Revisions, edit history, artifact dependencies, caches, portable projects |
| Local runner and Triton worker | Native capture/replay, execution events, symbolic sessions, budgets; isolated from GUI process |
| `hydir-vm` | Profiles, guest recovery, effects, host/guest mappings, scoped checks |
| CLI/API/SDK/GUI | Consistent operations over the same artifacts and job protocol |

Keep existing `model init|verify|infer|import-dwarf` and `decompile --view typed --model` interfaces. Add command families for capture, trace, slice, solve, replay, check, VM recovery, and bundle export. Every GUI workflow must have a reproducible CLI/SDK equivalent.

Version the following artifacts: `ExpressionIR v1`, `AnalysisModel v2`, `HighLevelCIR v2`, `ExecutionSnapshot`, `ExecutionTrace`, `InputSpec`, `AnalysisRecipe`, `SliceReport`, `SolveReport`, `NativeReplayReport`, `InvestigationClaim`, `GuestCFG`, and `EquivalenceCheck`. New artifact formats start at v1 and specify limits and validation rules.

Use API capability negotiation and additive endpoints for artifact/job access and revision-checked model writes. Preserve old ProgramSpec, CIR, low-level C, model-v1, and HLC-v1 readers through compatible routes or explicit migration. Execution is a local runner service in this release; remote analysis/model editing does not implicitly enable remote binary execution.

Static cache identity includes binary digest, model revision/dependency content, artifact/analysis version, and options. Execution artifacts additionally include snapshot/code identity, input, environment, summaries, engine/solver versions, and constraints. Old traces remain inspectable after edits with their original identity and assumptions.

## 15. Flagship demo and external validation

### One complete ten-minute investigation

Build a distributable stripped ELF challenge containing a cross-function parser, encoded messages, a typed context, and a small virtualized validator. It accepts a binary input file. Publish source and deterministic build instructions after the challenge presentation; use varied build seeds and layouts during development.

| Approximate segment | Visible outcome |
| --- | --- |
| 0–1 minute | Open stripped ELF; run a failing input |
| 1–2 minutes | Recover an encoded message and navigate to the validator |
| 2–3 minutes | Recover/edit an object layout and see C and field xrefs update |
| 3–5 minutes | Capture at an input boundary; explain which bytes influence rejection |
| 5–7 minutes | Show a guest branch/loop and check a simplified expression |
| 7–8 minutes | Generate a candidate and demonstrate success in a fresh original execution |
| 8–10 minutes | Export the investigation and reproduce it through the CLI |

PRISM and the plaintext password fixtures remain tutorials and regression tests. They do not serve as evidence of solving unfamiliar obfuscated programs. Record cold-analysis and cached-demo timings separately. All required live actions must work from the shipped package.

### Independent challenges

Evaluate Google CTF Unbreakable as an external demo candidate, Defcamp r100 as a smoke baseline, Hack.lu OLLVM for obfuscated-expression regression, and Fairlight for environment-sensitive behavior. MarsAnalytica is a later snapshot/VM stretch case. The earlier research inspected binaries and reference scripts; Hydir has not been benchmarked on them in this planning work.

Do not copy reference scripts' handpicked branch addresses into an allegedly automatic workflow. Record manual guidance and time spent preparing each recipe. Use provenance/hash manifests and upstream retrieval where redistribution rights are not established.

## 16. Release acceptance and competitive evaluation

### Correctness and compatibility

- At least 24 fixture families spanning widths/flags, branches, nested loops, switches, arrays/structures, recursive pointers/calls, conflicting aliases, direct/indirect calls, external memory effects, and VM execution.
- Build applicable fixtures with GCC and Clang at O0–O3, with stripped/DWARF and PIE/non-PIE variants. Freeze the supported matrix and explicit exclusions before release scoring.
- Strict-compile every emitted typed-C fixture with both compilers. Compare recovered offsets/layouts against source/DWARF oracles; ambiguous facts must stay unresolved or explicitly asserted.
- Differentially test every admitted exact-function fixture on at least 10,000 inputs plus semantic boundary cases. Compare returns, observable memory, and declared exits; report assumptions and mismatches.
- Test model round-trips/migration, old readers, revision conflicts, idempotency, selective cache invalidation, stale jobs, corrupted artifacts, and binary-digest changes.
- Test solver timeout/unknown/UNSAT distinctions, incomplete memory, unsupported effects, summary mismatches, candidate replay failures, and cancellation. Bounded failures must never appear as proofs.

### Real usefulness

- All three launch workflows pass end to end from a clean installation.
- Twelve development challenges produce verified outcomes; six additional external challenges are frozen before tuning, with at least four producing native-confirmed solutions within the declared ten-minute deep-analysis budget after recipe setup. Report setup effort and failures separately.
- Evaluate selected functions from at least five real utility/program codebases, recording discovery, type accuracy, C compilation, fidelity, and analysis failures even where solver goals do not apply.
- Six external testers attempt each documented workflow; at least five complete each without author intervention. Record time, confusing actions, setup failures, and exported-result reproducibility.

### Product quality

- Clean Windows + WSL2 and Linux installation tests; dependency doctor; resumable setup failures; first-party example projects; offline inspection of exported bundles.
- On the reference machine/workload fixed at M0, target p95 navigation under 100 ms, cached function rendering under 500 ms, and visible cancellation completion within 2 seconds. Time expensive reanalysis separately and keep the interface responsive.
- Test high-DPI layout, keyboard-only operation, project reopening, large function lists, trace paging, and runner/process failure recovery.
- Package pinned dependencies and notices. Document the supported execution/analysis envelope and known limitations.

### Fair comparison

Use matching binaries, hardware, goals, time/memory budgets, and available guidance. Include Ghidra's GUI workflow, angr with angr-management, rev.ng's model/decompiler workflow, and Miasm scripts for relevant tasks. Record tool versions and preparation time; permit each tool its normal strengths.

Measure time to verified answer, manual setup and corrections, successful native replays, type/layout correctness, readable control flow, failures, and resource cost. Keep readability, compilation, and semantic correctness separate. [DecBench](https://github.com/Noelo-Lab/decbench) provides useful evaluation dimensions, but similarity metrics do not establish equivalence.

Publish supported comparisons and reproducible recipes. Any claim that Hydir is faster, easier, or more accurate must identify the task and measurement supporting it.

## 17. Implementation order and expansion after launch

| Sequence | Work | Required predecessor |
| --- | --- | --- |
| 1 | M0 integration and baseline | Current repository |
| 2 | M1 shared expressions; begin M4 runner/capture contracts | M0 |
| 3 | M2 typed flow/types; M3 targeted discovery/cache; finish M4 capture/replay | M1 for semantic consumers; M0 for runner |
| 4 | M5 guided solving; M6 strings/slices/trace navigation | M1 + M4; model/UI foundations as needed |
| 5 | M7 guest CFG/effects/checks | M1 + M2 + execution/slice foundations |
| 6 | M8 complete investigations, packaging, external trials, release gates | Required workflows integrated |

Carry UI and compatibility work with its owning milestone. End each stage with a demonstrable user action, a regression fixture, a capability update, and a documented remaining limitation. Prioritize the next demonstrated blocker to a required workflow.

After launch gates pass, expand in this order:

1. Improve coverage on failed external ELF cases: indirect control flow, dynamic linking, supported library summaries, and richer ABI/type recovery.
2. Add PE64 and the Windows ABI/runner, then specific commercial VM profiles with independent fixtures and evidence scopes.
3. Add broader SIMD/floating-point semantics, C++/Rust/Go type idioms, additional debug formats, and C-header model editing.
4. Extend the checked region-patching path with explicit ABI, memory, exit, and environmental contracts; preserve original binaries and scoped verification artifacts.
5. Add deeper hypothesis comparison, reusable analysis extensions, additional architectures/formats, and collaboration when demand and correctness coverage justify them.

**Next implementation action:** run the experimental replay and named-symbol capture smoke on Linux; fix any GDB/MI, namespace, and PIE failures. Then support a validated address stop in a stripped ELF, move capture to an input-consumption boundary, and connect captured bytes to `InputSpec` origins before Triton resumption. In parallel, extend struct-array and pointer annotations beyond entry-block derivations and add bounded call effects and the remaining supported widths. **First new execution payoff:** explain a failed condition from captured input bytes and replay a working input against the original binary.

**M4 progress (2026-09-23):** `InputSpec v1` and `NativeReplayReport v1` have binary/input digest binding, bounded stdin/argv/file bytes, origin ranges, goals, and validation. The CLI can initialize and verify input specs. An experimental Linux Bubblewrap runner emits explicit matched, mismatched, timeout, output-limit, and runner-error reports. Windows emits an unsupported-host report. A named-symbol GDB/MI snapshot producer now compiles for the Linux target; live Linux replay/capture, input-boundary origin mapping, and the full M4 gate remain open. See [the replay protocol](REPLAY_PROTOCOL.md).

**M4 artifact follow-up:** `ExecutionSnapshot v1` now has bounded mappings, register observations, selected pages, stop/load-bias identity, digest binding, and a sparse-memory reader that errors on missing pages. `hydirctl snapshot verify` validates the artifact. Replay rejects ambiguous Bubblewrap exit values of 128 or more as unverified; CI includes a crash fixture to check that it cannot become a native success.

The bounded GDB/MI record parser handles result, asynchronous, and stream records with nested values. An experimental local session controller now stops a single-threaded process at a named function, records mappings and selected pages, and emits a validated snapshot. It disables GDB init files and auto-loading before the ELF is loaded. Cross-compilation and parser checks pass on Windows; the Linux smoke gate must demonstrate both replay and capture before the capability claim changes. `doctor` keeps `gdb_capture_v1` false pending that gate.
