# Ghidra optimization and debug-info matrix

`scripts/check-ghidra-opt-matrix.py` compiles `hydir_password_demo.c` four
ways: O0 and O2, each with DWARF and after stripping. It discovers function
addresses from the unstripped ELF symbols, imports each binary through the
automatic Ghidra worker, and compares raw P-code between each matching pair.
These freestanding ELFs are linked statically so the native debugger enters
the test program without a dynamic-loader startup step.

For `hydir_triton_add2`, it checks two concrete inputs, including 64-bit
wraparound, against Rust P-code execution and compiled image-backed LLVM. On
Linux x86-64 it calls the exact generated ELF under GDB, verifies the selected
code bytes, and compares return values. Rust and LLVM source P-code event
order and instruction visits are compared with each other. For
`hydir_secure_equals`, it checks match, mismatch, and wrong-length paths at
both O0 and O2. The vectorized O2 lift
uses two 16-byte direct RAM reads and Ghidra's `packsswb` user operation.
Hydir executes those reads from fully known guest or file-backed bytes and
implements the 128-bit signed saturation operation in Rust and LLVM. Unknown
memory bytes still stop before a result is written. On Linux the matrix also
checks every selected path against the exact generated ELF under GDB.

`scripts/check-ghidra-call-loop.py` reuses those four ELFs and freshly exports
`hydir_password_score` and its `hydir_mix64` callee. It checks an empty input,
one byte, and a 12-byte phrase at both optimization levels with and without
DWARF. Rust must return the source-level score and take exactly one call per
input byte. A compiled interprocedural LLVM module must return the same score
and emit the same ordered P-code operations, including nested call and return
boundaries. On Linux, GDB checks both function bodies against the snapshots
and executes the same ELF paths. The O2 DWARF case also exercises Hydir's
automatic, demand-driven callee collection.

`scripts/check-ghidra-aggregate-walk.py` builds a separate linked-list ELF
at O0 and O2, with and without DWARF. The selected function follows `next`
pointers and reads integer fields from guest RAM. Empty, one-node, two-node,
and zero-scale paths must return the source result in Rust and compiled LLVM;
their P-code event order and instruction visits must match. Linux GDB checks
the generated ELF and selected code bytes. The DWARF model must recover a
16-byte recursive `Node` with an `i32` field at offset 0 and a self pointer at
offset 8. This fixture tests concrete aggregate access and DWARF layout
import; it does not prove stripped type recovery or typed C for this loop.

Run after building `hydirctl`:

```sh
cargo build --locked -p hydir-cli --bin hydirctl
python3 scripts/check-ghidra-opt-matrix.py
python3 scripts/check-ghidra-call-loop.py
python3 scripts/check-ghidra-aggregate-walk.py
```

On Windows, set `HYDIR_GHIDRA_HOME` to a local Ghidra 12.1.4 installation and
provide Clang, llvm-nm, and llvm-strip. On Linux, the script uses Docker's
pinned Hydir Ghidra worker and also requires GDB. Set `HYDIRCTL_BIN` to use a
nondefault CLI build. The generated binaries, snapshots, traces, LLVM modules,
`report.json` and `call-loop-report.json` are written to
`target/ghidra-opt-matrix/` by default. The separate aggregate gate writes
to `target/ghidra-aggregate-walk/`.

The password matrix covers one source fixture and four selected functions;
the aggregate gate adds a second source fixture. These gates do not
establish whole-program equivalence or general SIMD support. The checked wide
LLVM subset includes extension, basic arithmetic and bitwise operations,
comparisons, shifts, `PIECE`, `SUBPIECE`, and the specifically named 128-bit
`packsswb` user operation. Its lane order and signed saturation follow the
[Intel instruction definition](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf)
and the [Ghidra x86 SLEIGH call](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Processors/x86/data/languages/ia.sinc).
