# HydIR

<img align="right" src="blog/assets/hydir-logo.jpg" alt="HydIR dragon logo" width="170">

HydIR is a framework for binary lifting, analysis, and decompilation in Rust. It works with x86-64 ELF binaries and exposes analysis through a desktop workbench, command-line tools, a Python SDK, and an authenticated service.

The Ghidra-backed pipeline imports source-linked raw P-code for inspecting operations, state effects, and bounded execution traces. The native Rust pipeline provides disassembly, control-flow recovery, static single assignment (SSA), and C generation. Optional Frida and Triton integrations support runtime observation and symbolic exploration.

Analysis results retain their provenance and coverage. Unsupported operations and unresolved behavior remain explicit; bounded checks do not establish whole-program equivalence.

<br clear="all">

## Getting started

Visit the [HydIR wiki](https://hydir.wiki/) for documentation, worked examples, and technical articles. The [first-run guide](https://hydir.wiki/docs/first-run) covers building and running HydIR, and [features and limitations](https://hydir.wiki/features) describes the supported workflows.

To contribute, read the [contribution guide](CONTRIBUTING.md).

## Getting in touch

Use [GitHub issues](https://github.com/Achxy/hydir-2/issues) for questions, bug reports, and feature proposals.

## Citation

To cite HydIR, use [CITATION.cff](CITATION.cff) or the following BibTeX entry:

```bibtex
@software{jayadevan_u_2026_hydir,
  author  = {Achyuth Jayadevan and Siddharth U},
  title   = {HydIR: Ghidra-backed and native binary lifting,
             analysis, and decompilation in Rust},
  year    = {2026},
  version = {0.1.0},
  url     = {https://github.com/Achxy/hydir-2}
}
```

## License

HydIR is licensed under [AGPL-3.0-only](LICENSE).
