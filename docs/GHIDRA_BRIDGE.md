# Ghidra bridge

HydIR now includes an original Ghidra script at
`integrations/ghidra/HydIRExport.java`. It exports a small versioned JSON
interchange file containing:

- discovered functions and entry addresses;
- basic-block addresses and representative mnemonics;
- intra-function CFG edges;
- direct function-call edges.

The script is intended to run in Ghidra's Script Manager or through the
official headless analyzer. Ghidra documents `GhidraScript` use in headless
mode and supports passing script arguments to pre/post scripts.

Example from a Ghidra installation:

```text
analyzeHeadless C:\temp\ghidra-projects HydIRDemo \
  -import C:\path\to\hydir-showcase \
  -scriptPath C:\path\to\hydir\integrations\ghidra \
  -postScript HydIRExport.java C:\temp\hydir-showcase.ghidra.json \
  -deleteProject
```

This bridge is deliberately an export boundary. It does not upload binaries,
execute samples, or embed Ghidra's Java UI into HydIR. To view the result in
HydIR, open the GUI, expand `Ghidra bridge`, enter the JSON path, and press
`Load Ghidra graph`. The Graph tab then exposes a clearly labelled `Ghidra
evidence` view while retaining HydIR's own native facts separately.

Ghidra itself is not copied into this repository; users provide their own
Ghidra installation. The bridge script is separate from HydIR's native
Ghidra-free analysis path.
