# Ghidra optimization and debug-info matrix

`scripts/check-ghidra-opt-matrix.py` compiles `hydir_password_demo.c` four
ways: O0 and O2, each with DWARF and after stripping. It discovers function
addresses from the unstripped ELF symbols, imports each binary through the
automatic Ghidra worker, and compares raw P-code between each matching pair.

For `hydir_triton_add2`, it checks two concrete inputs, including 64-bit
wraparound, against Rust P-code execution and compiled image-backed LLVM. On
Linux x86-64 it also steps the exact generated ELF under GDB and compares
instruction visits and return values. For `hydir_secure_equals`, it checks
match, mismatch, and wrong-length paths the same way at O0. The O2
wrong-length path returns exactly; O2 match and mismatch currently stop at
explicit unsupported SIMD effects. The report records each stop and never
calls these paths equivalent.

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
establish whole-program equivalence or SIMD support. The optimized comparison
currently exposes a 16-byte direct image operand, wide scalar lowering, and
`CALLOTHER` as separate semantic work for the core.
