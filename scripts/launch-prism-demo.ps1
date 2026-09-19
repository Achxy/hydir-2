param(
    [switch]$NoOpen,
    [switch]$RunTriton
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$runDir = Join-Path $repo "target\hydir-prism\run.$stamp"
$elf = Join-Path $runDir "hydir-prism.elf"
$patchedElf = Join-Path $runDir "hydir-prism-patched.elf"
$source = Join-Path $repo "tests\fixtures\hydir_prism_showcase.S"
$hydir = Join-Path $repo "target\debug\hydir.exe"
$hydirctl = Join-Path $repo "target\debug\hydirctl.exe"

New-Item -ItemType Directory -Path $runDir | Out-Null

$clang = (Get-Command clang -ErrorAction Stop).Source
$clangArgs = @(
    "--target=x86_64-unknown-linux-gnu",
    "-nostdlib",
    "-fuse-ld=lld",
    "-no-pie",
    "-Wl,--build-id=none",
    "-Wl,-e,_start",
    $source,
    "-o",
    $elf
)
& $clang @clangArgs
if ($LASTEXITCODE -ne 0) {
    throw "Clang/LLD could not build the PRISM x86-64 ELF."
}

if (-not (Test-Path -LiteralPath $hydirctl)) {
    & cargo build --locked --bin hydirctl
    if ($LASTEXITCODE -ne 0) {
        throw "hydirctl build failed."
    }
}

if (-not $NoOpen -and -not (Test-Path -LiteralPath $hydir)) {
    & cargo build --locked -p hydir-gui --bin hydir
    if ($LASTEXITCODE -ne 0) {
        throw "HydIR GUI build failed."
    }
}

& $hydirctl inspect $elf |
    Set-Content -Encoding utf8 (Join-Path $runDir "program-spec.json")
& $hydirctl analyze $elf |
    Set-Content -Encoding utf8 (Join-Path $runDir "global-effects.json")
& $hydirctl cfg $elf hydir_stage_decision |
    Set-Content -Encoding utf8 (Join-Path $runDir "decision-cfg.json")
& $hydirctl region $elf hydir_stage_decision |
    Set-Content -Encoding utf8 (Join-Path $runDir "decision-region.json")
& $hydirctl decompile-unit $elf hydir_stage_decision --assume-u64x2 `
    --output (Join-Path $runDir "decision-decompilation-unit.json")

$digest = (Get-FileHash -LiteralPath $elf -Algorithm SHA256).Hash.ToLowerInvariant()
$patchDocument = [ordered]@{
    schema_version = 1
    binary_sha256 = $digest
    function_symbol = "hydir_stage_patch_portal"
    prototype = "u64(u64,u64)"
    replacement = "u64 delta = arg0 - arg1;`nreturn delta;"
}
$patchPath = Join-Path $runDir "portal.patch.json"
$patchJson = $patchDocument | ConvertTo-Json
[System.IO.File]::WriteAllText(
    $patchPath,
    $patchJson,
    [System.Text.UTF8Encoding]::new($false)
)
& $hydirctl patch $elf $patchPath --trusted-fixture --assume-u64x2 `
    --assume-entry-only --output $patchedElf |
    Set-Content -Encoding utf8 (Join-Path $runDir "patch-bundle-and-report.json")
if ($LASTEXITCODE -ne 0) {
    throw "HydIR could not compile and apply the prepared PRISM patch."
}

$patchReport = Get-Content -Raw (Join-Path $runDir "patch-bundle-and-report.json") |
    ConvertFrom-Json
$patchedDigest = (Get-FileHash -LiteralPath $patchedElf -Algorithm SHA256).Hash.ToLowerInvariant()
$functionCount = (Get-Content -Raw (Join-Path $runDir "program-spec.json") |
    ConvertFrom-Json).functions.Count

if ($RunTriton) {
    & $hydirctl triton $elf hydir_stage_leaf_add |
        Set-Content -Encoding utf8 (Join-Path $runDir "triton-leaf-add.json")
}

$presenterCard = @"
HYDIR // PRISM PRESENTER CARD
==============================

PRIMARY ELF
  $elf
  SHA-256 $digest
  $functionCount named functions

PATCHED COPY
  $patchedElf
  SHA-256 $patchedDigest
  placement: $($patchReport.patch_bundle.placement_plan.strategy)

THE 6-MINUTE WINNING ROUTE
  1. Region Studio -> hydir_stage_decision
     Show the digest-bound RegionSpec, physical operations, diamond CFG,
     deterministic C, and explicit unresolved boundary facts.

  2. Physical state IR -> hydir_stage_stack_mix
     Point out frame setup, typed stack-local store/load, RSP relation,
     register reads/writes, flags, and exact instruction bytes.

  3. Graph / Global effects -> Analyze global effects
     Select hydir_stage_record_parent and show the direct call plus the
     propagated write to hydir_prism_counter.

  4. C <-> PatchLang -> hydir_stage_patch_portal
     Paste:
       u64 delta = arg0 - arg1;
       return delta;
     Check both explicit assertions and click Compile + verify plan.
     The five-byte function forces an ENTRY TRAMPOLINE -> NEW RX SEGMENT.

  5. Evidence & provenance
     Show old/new hashes, PatchIR statements, exact byte delta, re-import
     evidence, and the honest NOT RUN behavioral gate.

  6. Bonus symbols
     hydir_stage_call_chain  resolved direct-call ABI effects
     hydir_stage_loop_sum    bounded loop / back-edge recovery
     hydir_stage_bit_gate    TEST flags feeding a conditional branch
     _start                  syscalls, mapped strings, full call graph

STORY
  The original accepts the four-byte signal HYDR. The prepared patch changes
  the identity portal into subtraction, so 72 becomes 71 and the signal takes
  the refusal route. HydIR never overwrites the original ELF.
"@
$presenterCard | Set-Content -Encoding utf8 (Join-Path $runDir "PRESENTER_CARD.txt")

Write-Host ""
Write-Host "  HYDIR // PRISM IS READY" -ForegroundColor Yellow
Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  ELF:       $elf" -ForegroundColor Cyan
Write-Host "  Functions: $functionCount" -ForegroundColor Cyan
Write-Host "  Patch:     $($patchReport.patch_bundle.placement_plan.strategy)" -ForegroundColor Green
Write-Host "  Artifacts: $runDir" -ForegroundColor Cyan
Write-Host "  Start at:  hydir_stage_decision" -ForegroundColor Yellow
Write-Host "  Patch at:  hydir_stage_patch_portal" -ForegroundColor Magenta
Write-Host ""

if (-not $NoOpen) {
    Start-Process -FilePath $hydir -WorkingDirectory $repo -ArgumentList @(
        "--open-local", $elf, "hydir_stage_decision"
    )
}
