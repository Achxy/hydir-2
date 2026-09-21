# HydIR PRISM demo

PRISM is HydIR's presentation binary: one small, symbol-rich Linux x86-64 ELF
whose functions are deliberately shaped to make the product's strongest
capabilities visible. It is a trusted demonstration fixture, not an obfuscated
sample or a security challenge.

## Open the ready-made ELF

From the repository root:

```powershell
cargo run --locked --bin hydir -- --open-local demo/hydir-prism.elf hydir_stage_decision
```

The checked-in [`hydir-prism.elf`](../demo/hydir-prism.elf) is a 3,264-byte
ELF64 executable with 13 named functions. Its SHA-256 is
`4b3d29186ad32957cd12f1f4b581f3cad544903f0c4da152603394cc45ee3bb0`.
HydIR inspects the binary locally on Windows without executing it.

To prepare a patched copy and supporting reports as well, run:

```powershell
.\scripts\launch-prism-demo.cmd
```

The launcher cross-compiles `tests/fixtures/hydir_prism_showcase.S`, derives
the main HydIR artifacts, prepares a separate patched ELF, writes a concise
presenter card, and opens the original in Region Studio. Every run gets a new
directory under `target/hydir-prism/`; the original is never overwritten.

Use `-NoOpen` to prepare artifacts without launching the GUI. Use `-RunTriton`
only when the configured Triton bridge is available.

| Select this function or view | Demonstrates |
| --- | --- |
| `hydir_stage_decision` | Function discovery, bytes and disassembly, branch CFG, native IR stages, low-level C, structured decision C, and RegionSpec evidence. |
| `hydir_stage_stack_mix` | Frame setup, stack-local store and load, physical register state, and instruction provenance. |
| `hydir_stage_call_chain` and `hydir_stage_leaf_add` | Direct call edges, ABI recovery, call graph, and a small symbolic Triton trace. |
| `hydir_stage_loop_sum` and `hydir_stage_bit_gate` | Back-edge recovery, loop control, `TEST` flags, and conditional branches. |
| `hydir_stage_record_parent` | A direct callee and propagated write to the mapped `hydir_prism_counter` global. |
| `hydir_stage_patch_portal` | PatchLang, PatchIR, structural verification, and entry-trampoline placement in a separate ELF. |
| `_start` and Coverage | Program entry, local calls, mapped data, Linux syscalls, and explicit opaque-effect reporting. |

On this fixture, native coverage lifts all 13 discovered functions: seven
have exact native coverage, while six are conservative. In total, 117
instruction occurrences are exact under the modeled semantics and six
`syscall` occurrences remain opaque. Region Studio and C output display the
native low-level C with its fidelity and rewrite status when structured C
path rejects an instruction. In `prism_write_banner`, for example, the
`syscall` at `0x20141c` appears as an explicit opaque effect in native C.
The `prism_write_*` symbols and `_start` are runtime context for the program
graph and coverage views; use `hydir_stage_patch_portal` for the patch flow.

## The six-minute route

### 1. Start with the proof chain

Region Studio opens on `hydir_stage_decision`. The five stage readouts across
the top summarize the proof chain:

```text
ELF bytes -> RegionSpec -> PhysicalRegionIR -> C/PatchIR -> verified ELF copy
```

Open **Contract & safety**. Show the exact address/extent, region SHA-256,
exits, stack evidence, and unresolved facts. The red safety gate is a feature:
HydIR refuses to convert unknown boundary state into invented certainty.

### 2. Make machine state tangible

Select `hydir_stage_stack_mix`, then open **Physical state IR**. Its compact
frame produces an easy-to-read sequence:

- save and establish `rbp`;
- reserve stack space;
- store and reload a typed stack local;
- add the second argument;
- restore the frame and return.

Each row carries exact bytes, typed operation, register/flag effects, memory
class, control effect, and successor addresses.

### 3. Show that HydIR thinks across functions

Press **Analyze global effects**, switch to the program graph, and select
`hydir_stage_record_parent`. HydIR recovers its direct call to
`hydir_stage_record` and propagates the mapped write to
`hydir_prism_counter`. Then select `hydir_stage_call_chain` to show a resolved
SysV scalar call whose return is available to lifting and C generation.

### 4. Deliver the visual payoff: a real trampoline

Select `hydir_stage_patch_portal`, open **C ↔ PatchLang**, and use:

```c
u64 delta = arg0 - arg1;
return delta;
```

Enable both explicit trust assertions and click **Compile + verify plan**.
The original function is intentionally five bytes; the seven-byte replacement
does not fit. HydIR therefore shows:

```text
ENTRY TRAMPOLINE -> NEW RX SEGMENT
```

Expand the byte delta. The entry becomes a relative jump, the replacement is
placed in a new executable segment, and the original/patched hashes remain
distinct. Applying locally always writes a new file.

### 5. Close on evidence, not vibes

Open **Evidence & provenance**. Point out:

- machine and region digests;
- engine identity and statement/address mappings;
- typed PatchIR statements and source ranges;
- original-region match and patched-ELF re-import checks;
- the behavioral gate marked `not_run` until a trusted Linux execution check
  is performed.

That last item is the strongest closing line: HydIR distinguishes structural
proof from behavioral evidence instead of painting every box green.

### 6. Optional bonus symbols

| Symbol | What it demonstrates |
| --- | --- |
| `hydir_stage_loop_sum` | Bounded loop, back-edge, flags, and deterministic C |
| `hydir_stage_bit_gate` | `TEST`-defined flags and a conditional decision |
| `hydir_stage_patch_portal` | PatchLang, PatchIR, native code, trampoline placement |
| `hydir_stage_record_parent` | Direct calls and propagated mapped-global effects |
| `_start` | Linux syscalls, mapped strings/data, and the full program call graph |

## Native story

On Linux x86-64, the unmodified program accepts exactly the four bytes `HYDR`.
The prepared patch changes the portal from identity to subtraction. `_start`
calls it with `72` and `1`, so the patched result is `71` and the same signal
takes the refusal path. That intentional behavior change is separate from the
structural patch verification shown in the GUI.

PRISM demonstrates the supported HydIR contract. It does not claim complete
decompilation of arbitrary binaries, automatic proof of analyst assumptions,
or behavioral validation on a non-Linux host.
