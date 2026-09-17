# ADR 0004: Allowlisted LLVM pass experiments for trusted fixtures

Status: implemented locally as a partial M3 gate, 2026-09-17.

HydIR uses the pinned Linux development image's LLVM `opt` 14.0.6 to run a
named pass sequence over an actually lifted function. The CLI accepts only
`instcombine`, `sccp`, `simplifycfg`, and `dce`, at most once each; it passes
literal arguments to `opt`, never a shell command or uploaded plugin. A new
experiment directory contains `raw.ll`, canonical `before.ll`, transformed
`after.ll`, and a JSON report with hashes, pipeline, tool version, and LLVM
verification result. It refuses to reuse an existing output directory.

This command requires `--trusted-fixture` because LLVM processes the derived
IR without a hostile-input sandbox. It is not exposed through `hydird` or the
GUI. The demonstration recompiles transformed IR for the scalar function and
compares eight boundary inputs against native execution; this is narrow
behavioral evidence, not a proof for untested paths or a whole-executable
rebuild. A full pass editor and remote operation remain open.
