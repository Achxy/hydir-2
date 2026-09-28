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
code bytes, and compares return values. Rust and LLVM instruction visits are
compared with each other. For `hydir_secure_equals`, it checks match,
mismatch, and wrong-length paths at both O0 and O2. The vectorized O2 lift
uses two 16-byte direct RAM reads and Ghidra's `packsswb` user operation.
Hydir executes those reads from fully known guest or file-backed bytes and
implements the 128-bit signed saturation operation in Rust and LLVM. Unknown
memory bytes still stop before a result is written. On Linux the matrix also
checks every selected path against the exact generated ELF under GDB.

Run after building `hydirctl`:

```sh
cargo build --locked -p hydir-cli --bin hydirctl
python3 scripts/check-ghidra-opt-matrix.py
```

On Windows, set `HYDIR_GHIDRA_HOME` to a local Ghidra 12.1.4 installation and
provide Clang, llvm-nm, and llvm-strip. On Linux, the script uses Docker's
pinned Hydir Ghidra worker and also requires GDB. Set `HYDIRCTL_BIN` to use a
nondefault CLI build. The generated binaries, snapshots, traces, LLVM modules,
and `report.json` are written to `target/ghidra-opt-matrix/` by default.

The matrix covers one source fixture and two selected functions. It does not
establish whole-program equivalence or general SIMD support. The checked wide
LLVM subset includes extension, basic arithmetic and bitwise operations,
comparisons, shifts, `PIECE`, `SUBPIECE`, and the specifically named 128-bit
`packsswb` user operation. Its lane order and signed saturation follow the
[Intel instruction definition](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf)
and the [Ghidra x86 SLEIGH call](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Processors/x86/data/languages/ia.sinc).
