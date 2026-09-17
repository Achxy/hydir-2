# ADR 0010: versioned ELF mapping and relocation inventory

Status: accepted for the development checkpoint, 2026-09-18.

`ProgramSpec` v1 contained section and symbol facts but no runtime load
mapping. Version 2 adds ELF `PT_LOAD` file and memory extents, alignment and
permissions, an explicit address space, entry point, imports, and section and
dynamic relocations. The format-specific relocation flags remain visible when
`object` cannot normalize a relocation kind. Dynamic relocation symbol
indices resolve against the dynamic symbol table; resolving them against the
debugging symbol table produced plausible but false names in an initial
inspection and was corrected before this checkpoint.

Inspection rejects excessive sections, load segments, function symbols,
imports, relocations, or metadata-name lengths. A generic System V ELF OSABI
does not prove Linux, so its target field stays `x86_64-unknown-elf`;
explicit Linux and FreeBSD OSABI values are labelled separately. This is an
inventory label, not a promise of a compatible lifting or rebuild backend.

Calls, references and assumptions are typed fields, but the import operation
does not infer them. Their empty arrays are accompanied by `not_attempted`
recovery state. Position-independent image bases, actual LLVM data layout,
runtime load bias, call/reference recovery and analyst assumption persistence
remain unknown or external to the model. `FunctionCfg` remains independently
versioned at v1; a `ProgramSpec` version increment does not rewrite saved
function CFG semantics.
