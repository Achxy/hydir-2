# Symbolic exploration with Triton

The optional Triton bridge explores direct paths in a selected x86-64
function and reports symbolic expressions, path conditions, and candidate
models. It requires a Python interpreter with Triton installed. `doctor`
checks whether the configured interpreter can import it.

```bash
export HYDIR_TRITON_PYTHON=/path/to/python-with-triton
cargo run --locked --bin hydirctl -- doctor
cargo run --locked --bin hydirctl -- triton /path/to/program.elf function_name
```

In the workbench, **Run Triton** operates on the selected function. The bottom
console accepts a restricted statement set, one entry at a time. Triton
exploration is separate from the LLVM and native C paths; explored paths do
not establish whole-program equivalence.

[![HydIR disassembly with decoded machine instructions and a docked Triton symbolic result](../../../assets/screenshots/hydir-disassembly-triton.png)](../../../assets/screenshots/hydir-disassembly-triton.png)

*The disassembly view places decoded instructions beside a docked Triton result, so the selected function and its symbolic exploration can be inspected together.*
