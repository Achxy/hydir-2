# Frida on Windows

The Windows release packages a dedicated Linux worker for the existing x86-64
ELF workflow. Frida 17.9.5 is statically linked into the worker; Bubblewrap and
the Linux userland are in `workers/frida/rootfs.tar.gz`. Docker, Python, a Frida
devkit and a separate Ubuntu installation are not required on the analyst's PC.
WSL2 is a Windows prerequisite, installed separately with administrator rights.
This does not add native PE/.exe observation.

## First use

1. If WSL2 is absent, run `wsl --install --no-distribution` in Administrator
   PowerShell and restart if requested by Windows.
2. Extract the entire HydIR Windows release, keeping `workers/frida` beside
   `hydir.exe` and `hydirctl.exe`.
3. Open **Frida**, click **Recheck**, then **Install packaged
   worker**. Installation verifies the rootfs hash and imports `HydIR-Frida-v1`
   under `%LOCALAPPDATA%\HydIR\workers\frida-v1`. Existing distributions and
   existing worker directories are never overwritten or unregistered.
4. Open a local ELF, select an analyzed function, and open **Frida**.
   Click **Run with Frida** to launch the binary without arguments and record the
   selected function when execution reaches it. **Run settings** supplies optional
   arguments (one per line) or an advanced InputSpec JSON file. **Stop** cancels a run.
5. Inspect **Trace**: filter by event type or address, select a row to see event
   details and captured entry registers, or double-click a verified address to
   open disassembly. **Program output** stays below the trace; **Diagnostics**
   explains incomplete runs. The event and output panes can be resized.
6. **Recover targets** plans Ghidra reanalysis from observed indirect flow.
   **Compare P-code** holds the captured-register seed and path comparison actions.
   These views use the same recording and do not require a second Frida run.

The workspace follows iaito's compact debug toolbar, register dock and console
organization. Worker setup is in the **Worker** menu; raw JSON export, clearing
results, and the optional HydIR analysis console are in **Actions**.

The current observer supports inputs supplied through argv and files. Nonempty
stdin inputs are rejected, so use an argv/file-driven ELF for observation; the
interactive PRISM demo requires stdin and is not a Frida observation fixture.

CLI equivalents:

```powershell
.\hydirctl.exe frida-worker status
.\hydirctl.exe frida-worker install
.\hydirctl.exe replay init .\demo.elf --output .\input.json
# Set input.json budget.memory_bytes to at least 1073741824 for Frida injection.
.\hydirctl.exe observe frida .\demo.elf .\input.json --function 0x20137c --output .\trace.json
```

`hydirctl doctor` reports the same Frida readiness. Development builds can set
`HYDIR_FRIDA_WORKER_BUNDLE` to the directory containing the two worker files.
The GUI checks asynchronously and offers an explicit installation action.

## Testing a source checkout

A source checkout does not include the generated Linux rootfs. Installing WSL2
alone does not install the Frida worker. After the **Frida observer gate** workflow
succeeds for this source revision, download its `hydir-frida-wsl-rootfs` artifact
and extract it so `manifest.json` and `rootfs.tar.gz` share a directory. Or build
that directory using the release instructions below.

From the repository root in PowerShell:

```powershell
cargo build --locked -p hydir-cli -p hydir-gui
$env:HYDIR_FRIDA_WORKER_BUNDLE = (Resolve-Path .\frida-worker).Path
.\target\debug\hydirctl.exe frida-worker install
.\target\debug\hydirctl.exe frida-worker status
.\target\debug\hydir.exe --open-local .\demo\hydir-prism.elf
```

Launch the GUI from the same PowerShell session so it inherits the bundle path.
If you have a local Ghidra installation, keep `HYDIR_GHIDRA_HOME` configured as
before. The complete `hydir-windows-x86_64-frida` workflow artifact instead ships
the Windows executables and worker together and needs no bundle-path override.

## Execution boundary

Windows passes bounded ELF/InputSpec bytes through stdin, without translating
paths, mounting host drives, or constructing shell commands. The worker runs as
an unprivileged user. WSL automount and Windows executable interop are disabled
for this distribution. Every target still runs inside the existing Bubblewrap
user, PID, network, IPC and UTS namespaces with resource limits. A failed
isolation probe disables observation. Trace, input, binary and optional Ghidra
snapshot checks remain on the Windows side too.

Each observation has a random job ID; cancellation addresses that job only.
An independent Linux timeout bounds the job if the Windows client disappears.
No operation terminates other WSL distributions. Installed worker state is
retained on a failed readiness probe so it can be diagnosed.

## Building the release

On Linux x86-64, first build and verify the existing Frida release using
`scripts/package-frida-linux.py`. Then, with Docker available:

```sh
python3 scripts/package-frida-windows.py build-rootfs \
  --linux-bundle hydir-linux-x86_64.tar.gz --output frida-worker
```

The rootfs uses a digest-pinned Ubuntu base and the already verified Frida
bundle. It preserves the bundle's license files and the distribution's package
copyright notices. The manifest records the final rootfs SHA-256. Build-time
Ubuntu package updates mean separate rebuilds may produce different rootfs hashes.

Copy `frida-worker` to Windows, then build the desktop release:

```powershell
python scripts/package-frida-windows.py package `
  --worker-dir .\frida-worker --output .\hydir-windows-x86_64.zip
```

The Frida gate workflow produces both the worker artifact and the Windows ZIP.
Package construction and Windows unit tests do not prove WSL execution. Run
`scripts/test-frida-wsl.ps1` on a Windows x86-64 machine with WSL2 to verify a
real ELF observation through the installed worker.

```powershell
.\scripts\test-frida-wsl.ps1 -Hydirctl .\hydirctl.exe `
  -Binary .\demo.elf -InputSpec .\input.json -Function 0x20137c
```
