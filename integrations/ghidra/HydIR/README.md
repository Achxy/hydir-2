# HydIR for Ghidra 12.1.3

This extension is a thin HydIR client. It does not embed a lifter, decompiler,
or patch compiler in Ghidra. Decompilation, PatchLang compilation, structural
verification, placement, and apply operations run through `hydirctl` and the
same `hydir.v2` service used by the egui workbench.

Requirements:

- Official Ghidra 12.1.3 and its required JDK.
- A local-loopback or TLS `hydird` service, project ID/revision, and private token file.
- `hydirctl` on `PATH`, or its absolute path entered in the provider.

Build with the Ghidra release directory selected explicitly:

```sh
GHIDRA_INSTALL_DIR=/opt/ghidra_12.1.3_PUBLIC ./gradlew buildExtension
```

Install the resulting ZIP through **File → Install Extensions**, enable the
HydIR plugin, then open **Window → HydIR Region Workbench**. Select an address
inside a function, enter the local-loopback or HTTPS endpoint, token file,
project ID, and current revision. The workflow is compile/verify preview first,
then apply to a new ELF path. Existing output files are refused by `hydirctl`.
