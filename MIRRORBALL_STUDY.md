# Superset CFG study for HydIR

Source: Huang et al., [*No Bit Left Behind*](https://arxiv.org/html/2609.16423v1),
arXiv:2609.16423v1, submitted 14 September 2026. This note evaluates the
paper's reported method and measurements; HydIR has not reproduced them.

MirrorBall decodes each byte offset of executable sections as a potential
instruction start and dispatches indirect transfers to a translated target
table. Its CFG completeness argument covers internal control-flow edges under
the paper's stated assumptions. The authors separately assume correct
instruction semantics and external-call ABI marshalling. They exclude
self-modifying code, multithreading, and C++ exception unwinding from the
prototype. This separation reinforces HydIR's semantic evidence gate: a
superset CFG cannot by itself prove instruction behavior or call boundaries.

The paper reports completion and matching reference output for twelve
SPECint 2006 programs under its tested workloads, with no completeness claim
outside that suite. Mean block-count expansion is 49.6x, mean output-file
size expansion is 74x, and mean same-ISA runtime slowdown is 3.74x. The
reported AArch64 cross-recompilation mean is 12.33x for all twelve programs.
These are the authors' benchmark results, not HydIR measurements.

HydIR should retain its current candidate/proof split. A superset decoder
could later provide a separate, explicitly labelled whole-program recovery
experiment for unresolved indirect edges. It would require a new IR
representation, target dispatch, ABI handling, and scaling measurements. It
does not establish that a local patch has only one entry or that its live
machine locations and relocations are preserved.

An initial bounded experiment should count valid decoded starts, overlapping
starts, potential indirect targets, generated blocks, output bytes, compile
time, and peak memory for the same ELF corpus as the semantic gate. Its
candidate set must remain separate from trusted lift boundaries. Compare
observed overhead with HydIR's direct-recovery path before deciding whether
to implement a lifted superset CFG.
