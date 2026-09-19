<h1 align="center">HydIR</h1>

<p align="center">
  <strong>Open an x86-64 ELF, follow a function, and inspect what HydIR can recover.</strong><br>
  A local workbench with CLI tools for the parts that need saved artifacts.
</p>

<p align="center">
  <a href="https://hydir.wiki/">Documentation</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#native-analysis-workbench">Workbench</a> ·
  <a href="#verified-scalar-lift">Evidence</a> ·
  <a href="#symbolic-exploration-with-triton">Triton</a> ·
  <a href="#authenticated-loopback-service">Remote API</a>
</p>

[![HydIR egui workbench with a selected ELF function, its lifted LLVM IR, inspector, diagnostics, and console](assets/screenshots/studio-lift.png)](assets/screenshots/studio-lift.png)

*The native egui workbench analyzing `hydir_max2`: local ELF, machine-byte-derived LLVM IR, and the selected function's scope in one view.*

Start with a function you can name. HydIR shows its bytes and reachable branches, then tries to turn the supported scalar instructions into LLVM IR and C. You can inspect each result in the desktop app or save it with the CLI. Opening a local ELF does not upload it.

The checked-in [`hydir_max2` walkthrough](https://hydir.wiki/articles/max2) shows the whole path on a 16-byte function. For a new binary, expect some paths to stop early: the scalar lift refuses calls, memory operations, partial registers, and semantics it cannot model. HydIR is a workbench for this bounded subset, not a general decompiler.

## Quick start

Clone the repository with its submodules. Rust 1.96 is pinned in [`rust-toolchain.toml`](rust-toolchain.toml), and [`Cargo.lock`](Cargo.lock) fixes the Rust dependency graph. Run the tests, then open the workbench:

```bash
cargo test --locked --workspace
cargo run --locked --bin hydir
```

Open a local binary directly:

```bash
cargo run --locked --bin hydir -- \
  --open-local /path/to/program.elf function_name
```

If you want files you can keep or diff, take one function through the CLI:

```bash
cargo run --locked --bin hydirctl -- inspect /path/to/program.elf
cargo run --locked --bin hydirctl -- cfg /path/to/program.elf function_name
cargo run --locked --bin hydirctl -- lift \
  /path/to/program.elf function_name \
  --assume-u64x2 --output lifted.ll
```

The lift command asks you to assert a two-argument unsigned 64-bit ABI; HydIR does not guess the prototype. The full demo path needs Clang with x86-64 ELF and LLVM IR support. Native execution comparisons require Linux x86-64. On macOS with Docker Desktop:

```bash
bash scripts/demo-linux-docker.sh
```

## Native analysis workbench

The desktop workbench keeps the program tree, analysis views, inspector, and diagnostics visible at once. It can:

- disassemble executable sections with recursive recovery from symbols and entry points
- show uncertain linear-sweep regions and undecodable gaps instead of silently promoting them to functions
- inspect CFG, LLVM IR, scalar C, named pass results, and conservative global effects
- save local names, comments, assumptions, and pane layout in a private SQLite project
- create an authenticated loopback project only through an explicit transfer action
- apply bounded transforms, rebuilds, and scalar patches to new output paths

The disassembly view ties each recovered instruction to its address and bytes. Branches and unsupported regions remain inspectable instead of being silently turned into source code.

[![egui disassembly cutout with decoded instruction addresses and bytes](assets/screenshots/egui-disassembly.webp)](assets/screenshots/egui-disassembly.webp)

Selecting a function fills the inspector with its entry, extent, source, asserted ABI, and recovered CFG scope. These are facts and explicit assumptions about the selected function, not a guessed prototype.

<p align="center"><img src="assets/screenshots/egui-inspector.webp" width="42%" alt="egui inspector cutout showing the selected function's ELF facts, ABI assertion, and CFG count"></p>

Opening a local ELF does not upload it. Credentials are not persisted, remote projects do not reconnect automatically, and the service refuses non-loopback binding.

## Verified scalar lift

After reading one lift, it is fair to ask whether it behaves like the original. The demo scripts answer that question for 20 distinct scalar fixture functions. They emit LLVM IR and C, run the LLVM verifier where the required tools are available, and compare each output path with native execution on 1,008 input pairs.

```bash
bash scripts/demo-local.sh
bash scripts/demo-corpus.sh
```

The scripts save the CFG, LLVM IR, C, and comparison reports, so you can read what was checked. A finite pass says something useful about those fixtures; it does not prove equivalence for arbitrary programs. The UI also keeps failures specific: an unsupported call can stop C generation without discarding an already recovered CFG or LLVM lift.

[![egui C output cutout refusing an unsupported call while retaining other analysis results](assets/screenshots/egui-refusal.webp)](assets/screenshots/egui-refusal.webp)

## Symbolic exploration with Triton

Triton lets you ask a different kind of question: what input could produce a chosen output? HydIR's Triton bridge explores direct paths in a selected x86-64 function and reports symbolic expressions and path conditions. Use a Python interpreter with Triton installed; `doctor` checks whether HydIR can import it.

```bash
export HYDIR_TRITON_PYTHON=/path/to/python-with-triton
cargo run --locked --bin hydirctl -- doctor
cargo run --locked --bin hydirctl -- triton /path/to/program.elf function_name
```

In the workbench, select a function and use **Run Triton**. The bottom console also accepts a small, restricted set of Triton statements, entered one at a time. The [Triton walkthrough](https://hydir.wiki/articles/triton-api) begins with one instruction and shows how to ask for a model. The bridge is separate from the LLVM lift; its explored paths do not establish whole-program equivalence.

## Authenticated loopback service

`hydird` provides revisioned projects, explicit ELF upload, inspection, CFG and global-effect analysis, lift and scalar C artifacts, named pass experiments, annotations, bounded rebuild/patch operations, and durable lift jobs with events and cancellation. The CLI and [Python SDK](sdk/python/README.md) use the same authenticated API. The service does not execute uploaded binaries and will not bind to a non-loopback address.

```bash
# Create an identity once; save the one-time credential in a private 0600 file.
cargo run --locked --bin hydird -- identity create /path/to/hydird.sqlite analyst

# Start the service in a separate terminal.
cargo run --locked --bin hydird -- serve /path/to/hydird.sqlite 127.0.0.1:50051

# Point the CLI at the service and the saved credential.
export HYDIR_ENDPOINT=http://127.0.0.1:50051
export HYDIR_TOKEN_FILE=/private/path/analyst.token
cargo run --locked --bin hydirctl -- remote discover
cargo run --locked --bin hydirctl -- remote create demo unique-request-key
cargo run --locked --bin hydirctl -- remote upload <project-id> <expected-revision> /path/to/program.elf
```

Upload is never implicit: the last command is the transfer boundary. Use the project ID and revision returned by the preceding commands for subsequent `remote inspect`, `cfg`, `lift`, `decompile`, `artifact`, or `job-*` operations. Credential files must not be group- or world-readable.

## Documentation site

The [HydIR wiki](https://hydir.wiki/) is a static site in `blog/`. To preview it
locally with the same clean URLs used on Vercel, run
`python scripts/serve-wiki-site.py` and open `http://127.0.0.1:8765/`.
Run `python scripts/check-wiki-site.py` to check its routes and assets.

## License

HydIR is released under the [GNU Affero General Public License v3.0 only](LICENSE).
