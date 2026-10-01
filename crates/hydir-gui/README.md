# HydIR desktop workbench

The desktop interface follows [iaito](https://github.com/radareorg/iaito)'s compact
reverse engineering workspace: menu bar, seek/history toolbar, image overview,
functions dock, analysis tabs, and bottom console. The dark palette and dock
arrangement reference `MainWindow::restoreDocks`, `Dark.theme`, and the screenshots
at iaito commit `3383cc1d92131211ce752bb37121043ea8445b0e`.

This is a Rust/egui implementation backed by HydIR's existing workers. It does not
embed Qt or radare2. Ghidra, Frida, Triton, native IR, transformations, model editing,
annotations, and verified patching keep their existing backend contracts.

## Run

```sh
cargo build --locked -p hydir-gui -p hydir-cli
cargo run --locked -p hydir-gui -- --open-local /path/to/program.elf
```

Build both executables together: the desktop invokes `hydirctl` beside it for
Ghidra analysis. Opening a local ELF starts headless analysis automatically. The
default worker provisions a pinned Ghidra container and requires running Docker;
set `HYDIR_GHIDRA_HOME` before launching to use a local Ghidra 12.1.4 installation.

Use **File → Open** or drop a local ELF into the window. **Ghidra bridge** in the
toolbar opens runtime status, analysis and cancellation controls. **Ghidra →
P-code / state / traces / LLVM** opens the P-code tab, which is also present in the
default layout. If analysis is unavailable, that tab shows the bridge controls
and setup details directly. Project settings retain investigation recipes, legacy
graph import and remote project operations. Remote upload remains explicit.

## Ghidra and Frida workspaces

The code-first layout follows the cloned iaito `DecompilerWidget.ui` (unwrapped
listing with a compact action bar), `DisassemblyWidget.cpp` (address-linked rows
and context actions), `DebugActions.cpp` (visible debugger controls), and
`MainWindow::restoreDocks` (separate tabbed workspaces).

**Ghidra P-code** opens directly to a full-height, colored listing. Raw P-code,
high P-code, state effects, control flow, traces, LLVM, coverage and metadata have
separate views. Filter the listing, double-click a row for disassembly, or
right-click an operation to inspect its dependency slice in the resizable value
details pane. The function selector and left dock request matching Ghidra exports.
Trace seeds are configured in **Trace → Path & seed** and shared with call tracing,
lift assessment and LLVM across calls. Backend bounds and validation are unchanged.

**Frida** has a default tab, a toolbar button and **Debug → Frida observation**.
Its Session, Events, Rediscovery and Path comparison views retain the existing
observer, seed transfer and reanalysis actions. Observation executes a local ELF
with the Linux x86-64 helper. Windows uses a packaged WSL2 worker; the Session
view checks readiness, offers installation and enables observation only after
the runtime and isolation probes pass. See
[Windows worker setup and packaging](../../integrations/frida/README.md).

## Navigation and panels

- **G** or **Ctrl+L** focuses the address bar. Seek using a hexadecimal address,
  function name, or recovered function ID.
- **Alt+Left / Alt+Right** traverse address history; **Escape** goes back.
- **Ctrl+F** focuses the functions filter. Filter by name or address and click
  a column heading to sort. Right-click a function to choose a destination view.
- **Space** switches between disassembly and graph when no text editor has focus.
- Double-click a branch instruction to follow its target. Context menus provide
  copy, hex navigation, and annotation actions.
- Drag tabs to reorder; middle-click or right-click to close. **Windows → Add tab**
  and the **+** button restore every analysis view.
- Resize dock borders. Double-click a dock title or use its arrow to float/dock
  the panel. **Windows** controls visibility and restores the default layout.
- **Ctrl+S** saves the layout, panel sizes, and recent local file. Presentation
  settings live beside the private workbench database in a `.layout.json` file.

## Data views

Disassembly retains the worker's instruction provenance and undecoded-gap counts.
Hexdump displays the actual imported file bytes and maps virtual addresses only
to file-backed ranges. Strings displays ASCII runs of at least four bytes, capped
at 20,000 entries; extraction does not imply a recovered string type. Sections and
imports come directly from `ProgramSpec`. Search covers functions, decoded
instructions, and extracted strings, with a 1,000-result cap.

Hex and strings data are obtained from the worker's digest-matched imported bytes,
not by rereading a potentially changed file. They are unavailable for remote
projects without local bytes. Opening another binary clears byte views and seek
history.

## Console

The HydIR console offers view/navigation commands with a small set of familiar
iaito aliases; it is not a general radare2 interpreter. Type `?` for its complete
command list. `s` seeks, `s-`/`s+` navigate, `pd`/`agf`/`px`/`pdc` open code views,
and `ii`/`iz`/`iS` open imports, strings, and sections. Up/Down recall commands.
The separate Triton REPL retains the existing restricted Python evaluator.

## Validation

```sh
cargo test --locked -p hydir-gui
cargo build --locked -p hydir-gui
```

The native render smoke test opens a real ELF through the normal worker, selects
a function, then captures fourteen views, including floating panels and a
1024×720 layout. It skips automatic Ghidra startup so it needs no external engine.
Use an isolated database path:

```powershell
$env:HYDIR_LOCAL_DB = "$PWD\target\gui-smoke\workbench.sqlite"
.\target\debug\hydir.exe --render-workbench `
  .\fuzz\corpus\elf_import\max2.elf hydir_max2 .\target\gui-smoke
```

Successful rendering writes `manifest.json` and PNGs. The existing
`--render-ghidra-demo` exercises a real Ghidra installation and captures fifteen
Ghidra/Frida views plus linked disassembly, including a compact-window P-code view.
