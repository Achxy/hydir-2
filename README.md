<h1 align="center">HydIR</h1>

<p align="center">
  <strong>From binary bytes to inspectable behavior.</strong><br>
  Ghidra-backed binary lifting and reverse engineering in Rust.
</p>

<p align="center">
  <a href="https://hydir.wiki/start">Get started</a> ·
  <a href="https://hydir.wiki/guides">Docs</a> ·
  <a href="https://hydir.wiki/blogs">Articles</a> ·
  <a href="https://hydir.wiki/architecture">Architecture</a>
</p>

[![HydIR desktop workbench showing ELF analysis, program inventory, and inspector](assets/screenshots/hydir-elf-overview.png)](https://hydir.wiki/docs/desktop)

HydIR opens x86-64 ELF files and brings disassembly, control flow, raw P-code,
state effects, and C output into one desktop workbench. A native Rust analysis
path, CLI, Python SDK, and authenticated service expose the underlying artifacts.
Unsupported operations and unresolved behavior stay visible in the evidence.

## Run it

With **Rust 1.96+**, clone the repository and open the included PRISM demo:

```bash
git clone https://github.com/Achxy/hydir-2.git
cd hydir-2
cargo run --locked --bin hydirctl -- doctor
cargo run --locked --bin hydir -- --open-local demo/hydir-prism.elf hydir_stage_decision
```

The Ghidra-backed workflow provisions a pinned container on first analysis.
See [first run](https://hydir.wiki/docs/first-run) for setup and CLI examples.

## Explore

| | |
| :--- | :--- |
| **Inspect** | [Desktop workbench](https://hydir.wiki/docs/desktop) · [ELF to C](https://hydir.wiki/docs/native-analysis) |
| **Lift & trace** | [Ghidra / P-code](https://hydir.wiki/docs/ghidra) · [Frida](https://hydir.wiki/docs/frida) · [Triton](https://hydir.wiki/docs/symbolic) |
| **Automate** | [Python SDK](https://hydir.wiki/docs/python-sdk) · [Service API](https://hydir.wiki/docs/service) |
| **Understand** | [Features & limits](https://hydir.wiki/features) · [Technical articles](https://hydir.wiki/blogs) |

---

[AGPL-3.0-only](LICENSE) · [HydIR wiki](https://hydir.wiki/)
