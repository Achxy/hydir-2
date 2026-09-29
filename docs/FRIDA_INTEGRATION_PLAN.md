# Frida runtime evidence for Hydir

Status: proposed implementation plan, 2026-09-29. This extends the
[lifting-engine plan](LIFTING_ENGINE_PLAN.md); it does not replace the L0-L6
semantic gates. The first release is Linux x86-64 ELF.

## Product decision

Add Frida as an **optional observer of a real execution**. Hydir remains the
application and owns input validation, versioned artifacts, address mapping,
comparison, analysis, and the GUI. Ghidra still exports static P-code and
types. Frida supplies observed block visits, call targets, and selected live
state. Neither a Frida trace nor a Ghidra CFG proves that all paths were found.

This is useful for a CTF function whose indirect target depends on input: an
analyst runs it with one saved input and sees the observed path beside Hydir's
static CFG and Rust/LLVM lift. A target discovered by this run is visibly
tagged **observed for this input**. It is not silently promoted to a proven
static edge.

Frida's Stalker can emit block, call, return, and instruction events on Intel
64. Its documentation warns that per-instruction events produce a great deal
of data, so the default will use block and call events, with bounded
instruction tracing only to narrow a discrepancy. Interceptor can capture
the selected function's entry context. See the [Stalker guide]
(https://frida.re/docs/stalker/), [JavaScript API]
(https://frida.re/docs/javascript-api/), and [Rust bindings]
(https://github.com/frida/frida-rust).

## Reuse and gaps in Hydir

| Existing component | Frida integration |
| --- | --- |
| `hydir-execution::InputSpec` and Bubblewrap runner | Reuse binary/input digest, argv, stdin, staged files, time and output limits. Run the observer and its spawned target in the **same** isolated namespace. First verify that Frida injection works there; never silently run the target outside the runner or change the host's ptrace policy. |
| `ExecutionSnapshot v1` | Reuse sparse register/page and unavailable-state semantics for a selected entry capture. A page that cannot be read stays unavailable. Capture only requested pages within existing bounds. |
| Ghidra snapshot and `PcodeCfgFunctionIr` | Bind observations to the exact binary and optional snapshot hash. Overlay visited blocks and call targets without changing the CFG's incomplete claim. |
| `PcodePathTrace` and interprocedural trace | Compare on the same input once captured registers and memory can be converted to a valid P-code seed. Keep Rust stops distinct from Frida capture errors. |
| `PcodeCapabilityReport v1` | Cross-link observed witnesses in a new artifact; do not change the meaning of the existing static report. |
| CLI, v3 jobs, Python SDK, existing GUI | Offer one Hydir action to observe a selected function, retrieve the artifact, navigate source addresses, and see the first supported discrepancy. No separate Frida UI is required. |

There is **no automatic CPU-register-to-P-code-register mapping today**:
`ExecutionSnapshot` stores names such as `RDI`, while a P-code seed stores
Ghidra register-space byte offsets. The comparison phase must add a bounded,
validated Ghidra register-layout export or equivalent versioned mapping. It
must not guess offsets from one fixture.

## Runtime and dependency boundary

- Add a separate Rust `hydir-frida-observer` helper, compiled only for the
  supported Linux target. Use the upstream `frida` Rust bindings for
  spawn/attach/script lifecycle. A small bundled GumJS agent may collect
  Frida events; it performs no lifting or analysis. Rust validates, bounds,
  normalizes, and compares all messages. Keep the native Frida dependency
  behind an opt-in Cargo feature so `cargo test --workspace` and ordinary
  Hydir releases do not require the devkit. No Python runtime is required.
- Pin one tested `frida` crate and matching Frida core devkit, verify the
  devkit archive digest in packaging/CI, retain upstream notices, and disable
  build-time automatic downloads. Keep ordinary Hydir builds usable without
  the optional devkit. Frida's [Rust installation instructions]
  (https://github.com/frida/frida-rust/blob/main/README.md) require a matching
  native devkit; this is a real packaging cost.
- Do not put Frida in the Ghidra container. The Ghidra worker has a different
  purpose and a restrictive runtime. Frida observes a target process, so its
  helper belongs beside Hydir's bounded native runner.
- Start with spawn-before-resume of a staged, digest-checked ELF. Arbitrary
  PID attach, remote devices, child-process following, Android, and Windows
  follow after the Linux gate. The Rust bindings expose paused spawn, attach,
  and resume, which allows instrumentation before the selected function runs
  ([Device API](https://docs.rs/frida/latest/frida/struct.Device.html)).
- A failure to inject inside the current Bubblewrap profile is an explicit
  feasibility result. Investigate a dedicated isolated helper before adding
  privileges; do not tell users to disable Yama or grant unrestricted ptrace.

## `DynamicTrace v1` contract

Use a new artifact rather than adding dynamic facts to the static Ghidra
snapshot. Bound JSON to 16 MiB and cap events, captured bytes, threads, and
wall time before collection begins.

- Identity: schema version; ELF SHA-256; `InputSpec` SHA-256; selected ELF
  virtual address; optional Ghidra snapshot SHA-256; observer/Frida/agent
  versions and agent digest; full capture options and budgets.
- Mapping: module name, file identity where available, runtime base and ELF
  load bias; each event keeps its runtime address and a normalized ELF virtual
  address only when the containing mapping and instruction bytes validate.
  PIE normalization uses ELF load segments, not a guessed subtraction from a
  displayed module base. Changed runtime code is marked separately.
- Observations: ordered, per-thread block ranges and call/return events with
  source and target where Frida supplies them. The entry/exit state field is
  optional in F1 and carries an explicit `not_requested`, `captured`, or
  `unavailable` status; F2 adds validated registers and bounded memory
  windows. Unknown values stay unknown. A compiled block is not counted as
  executed.
- Status: completed, budget truncation, process fault, timeout, injection
  error, unsupported threads/target, or detached. Record observed event
  counts and any collector loss/gap indication. Even `completed` means only
  this run was observed; path completeness is not asserted.
- Provenance: event IDs link back to captured runtime address and, when
  validated, to Ghidra disassembly, CFG, P-code, and lifted LLVM source IDs.

Default collection follows one thread while the selected function is active.
Nested calls are recorded; recursion requires a depth counter so the observer
does not stop at an inner return. Other threads, a fork, a missing return, or
an unreadable page produce an explicit partial result. The collector batches
events rather than sending a message per instruction. Observation-specific
limits cap block/call events, transferred bytes, and instrumentation time;
they are recorded separately from `InputSpec`'s native replay budget.

## Autonomous implementation sequence

### F0 — Prove the runtime boundary

Build a disposable Linux CI spike using the pinned Rust binding and devkit:
stage the existing PRISM ELF with `InputSpec`, spawn it paused, load the
bundled agent, resume, and collect one function's block/call events **inside
the current Bubblewrap constraints**. Verify that the uninstrumented native
run and observed run agree on exit status and bounded output for two inputs.
Measure event count, runtime overhead, and whether any events are lost.

**Gate:** same-namespace injection succeeds without host sysctl changes or
extra privilege; entry and call addresses normalize through checked ELF
mappings. If it fails, record the exact Frida error and runner configuration,
then prove a narrowly isolated alternative before production integration.
The spike produces a short go/no-go record with the tested Frida/devkit pair,
runner invocation, fixture inputs, and observed event counts.

### F1 — Ship an observed-path artifact

Create `DynamicTrace v1`, its strict parser/validator, the Rust observer, and
`hydirctl observe frida <elf> <input.json> --function <elf-vaddr>` with an
optional existing Ghidra snapshot. Add an asynchronous revision-checked v3
observation job, Python SDK method, and the existing GUI's function view in
the same slice. The GUI highlights observed blocks/calls and lets the user
jump to the corresponding disassembly, CFG, and P-code source. Missing Frida
is explained by `doctor` and the disabled action, while normal lifting works.

**Gate:** stripped and PIE x86-64 fixtures at O0 and O2; two inputs take
different observed branches; a real indirect call target is recorded; wrong
binary/input/snapshot identities, unmapped addresses, timeouts, and event
caps cannot produce a `completed` artifact. Existing GDB and Ghidra gates
remain green.

### F2 — Connect captured state to the Rust lift

Export a bounded Ghidra register layout as a **new versioned artifact** and
validate name, offset, width, aliasing, language ID, and snapshot identity.
Convert only known captured bytes into a `PcodeConcreteState`; leave all
other bytes unknown. Reuse `ExecutionSnapshot` for selected entry state and
the existing P-code path/call executor. Compare visited blocks and calls at
the common address level. If a difference is seen, rerun only the selected
function with a small `exec` event budget to locate the first instruction
boundary; do not claim a P-code-operation boundary from Frida instruction
events alone. Return a versioned comparison artifact with the exact input,
tool versions, first differing address, and both stop reasons.

**Gate:** a matching PRISM path, a deliberately changed arithmetic result,
and a deliberately changed branch target produce the expected match or
first-difference result. Unknown register/memory bytes yield `inconclusive`.
Uninstrumented native replay remains an independent output/status check.

### F3 — Use observations to guide discovery

Feed validated, observed targets to the bounded changed-address worklist in
L4. A target must lie in a verified executable mapping with matching runtime
bytes before it can be offered for targeted Ghidra reanalysis. Store the
original event and input as evidence. Reanalysis may add a candidate edge or
function, but a single run never closes the CFG. Runtime-modified bytes go to
a separately identified runtime-image analysis path; never apply file-backed
P-code to different bytes. A direct Stalker call event may supply its target;
consecutive block visits alone are only a candidate transition. Do not turn
block adjacency into an edge across a call, return, missing event, or
uninstrumented range.

**Gate:** indirect jump/call fixtures reveal the observed target, improve a
subsequent bounded analysis, and still leave unobserved targets unresolved.
A self-modifying fixture is rejected from file-backed target promotion.

### F4 — Release the optional observer

Pin and package the helper/devkit for Linux x86-64; document offline and
unsupported-host behavior, artifact provenance, and upstream notices. Add a
CI job that runs the observer on real fixtures, verifies event budgets and
identity failures, and checks that the non-Frida build and GUI still work.
Expose an opt-in observation action in the demo with an input selector and
source-linked trace. This joins the L6 release gate; it does not block static
lifting on machines without Frida.

## Presentation test

Open one stripped challenge ELF in Hydir. Automatic Ghidra analysis shows an
incomplete indirect branch. Run two saved inputs with **Observe**. The GUI
shows the two different executed paths and the observed target beside the
source-linked Rust P-code/LLVM view. Select one path to compare with Hydir's
bounded lift; if it differs, show the first address and captured input. The
artifact says which facts came from Ghidra, Frida, Rust execution, and native
replay. This is the concrete demo value of the integration.
