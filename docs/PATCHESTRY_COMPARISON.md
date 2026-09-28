# Hydir and Patchestry on the same Ghidra fixtures

This opt-in check compares the **source-addressed high P-code mnemonics** exported by Hydir and [Patchestry](https://github.com/lifting-bits/patchestry). Hydir's semantic lift uses raw instruction P-code, so raw operation counts and LLVM behavior are outside this comparison. Patchestry also inserts synthetic operations; the report lists those separately.

The comparison uses Ghidra 12.1.4 and Patchestry revision `4acddb43de5662de00ba2e239f279159c2dbd609`. Patchestry references `PcodeOp.EXTRACT` and `PcodeOp.INSERT` constants absent from this Ghidra release. The script removes those two classifier cases in a temporary copy of its exporter, checks that neither fixture contains those mnemonics, and leaves the checkout unchanged. This is a compatibility shim for the comparison, not a Hydir runtime dependency.

```sh
git clone https://github.com/lifting-bits/patchestry.git target/references/patchestry
git -C target/references/patchestry checkout 4acddb43de5662de00ba2e239f279159c2dbd609
HYDIR_GHIDRA_HOME=/path/to/ghidra_12.1.4_PUBLIC \
  python3 scripts/compare-patchestry-ghidra.py \
  --patchestry target/references/patchestry
```

On Windows, set `HYDIR_GHIDRA_HOME` in PowerShell and use `python` instead of the shell assignment above. The report, Patchestry exports, and Ghidra logs appear under `target/patchestry-comparison/`. The measured [v1 report](../tests/fixtures/patchestry_comparison_v1.json) is checked in for review. The script fails if the binary digest, Ghidra version, language, selected entry, or function identity differs. High P-code differences appear in the report; pass `--require-agreement` when an exact match is required by a gate.

| Fixture | Hydir high operations | Patchestry source operations | Matched | Difference |
| --- | ---: | ---: | ---: | --- |
| `ghidra_add_zero.elf` / `hydir_add_zero` | 2 | 2 | 2 | None; Patchestry also inserts `BRANCH` and `DECLARE_PARAMETER` |
| `ghidra_choose_calls.elf` / `hydir_choose` | 6 | 6 | 6 | None; Patchestry also inserts `BRANCH` and `DECLARE_PARAMETER` |
| `hydir-prism.elf` / `hydir_stage_bit_gate` | 4 | 4 | 4 | None; Patchestry also inserts `BRANCH` and two `DECLARE_PARAMETER` operations |
| Stripped password ELF / `FUN_002016d0` | 21 | 19 | 18 | Patchestry lacks three `MULTIEQUAL` operations and adds one source-addressed `COPY`; its synthetic operations are listed in the report |

The first three matches show that both exporters identify the same high P-code mnemonics at the same source addresses on small arithmetic, branch, and call fixtures. The stripped memory fixture exposes a real representation difference. This comparison does not prove equivalent dataflow, block edges, types, LLVM output, or machine behavior. Hydir's native and Ghidra execution gates provide separate evidence for the supported semantic slice.
