# HydIR showcase crackme

`tests/fixtures/hydir_showcase.S` is a small trusted ELF designed for a
video demonstration. Its secret is `HYDR`. It has a visible decision path,
a liftable `hydir_max2` function, direct calls, Linux `read`/`write`/`exit`
syscalls, mapped read-only strings, and a bounded input buffer.

Run the complete local demonstration on Linux x86-64:

```sh
bash scripts/demo-showcase.sh
```

The script demonstrates:

1. Native execution: `HYDR` is accepted and another input is rejected.
2. ELF inspection and conservative call analysis.
3. CFG export, LLVM lifting, and structured scalar C generation for
   `hydir_max2` (`return arg0 >= arg1 ? arg0 : arg1;`).
4. A hash-bound whole-function patch that changes the score function from
   maximum to subtraction; the original secret is then rejected.
5. Whole-executable rebuilding and output comparison for accepted and rejected
   inputs.

This is intentionally a trusted fixture, not a hostile-binary sandbox or a
general VM decompiler. The structured C view is conservative: unrecognized
control-flow shapes fall back to HydIR's explicit CFG/SSA C output. The
VM-style framing is for the story: the next phase can replace the direct
checks with a small bytecode dispatcher while keeping the same observable
lift/verify/rebuild narrative.
