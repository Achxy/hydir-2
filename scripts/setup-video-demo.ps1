param(
    [switch]$OpenHydIR,
    [switch]$RunTriton
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$sourceElf = Join-Path $repo "target\demo-disassembly\hydir-showcase-fixed.elf"
$demoDir = Join-Path $repo "target\demo-video"
$originalElf = Join-Path $demoDir "hydir-showcase-original.elf"
$obfuscatedElf = Join-Path $demoDir "hydir-showcase-obfuscated.elf"
$cOutput = Join-Path $demoDir "max2-structured.c"
$hydir = Join-Path $repo "target\debug\hydir.exe"
$hydirctl = Join-Path $repo "target\debug\hydirctl.exe"

if (-not (Test-Path -LiteralPath $sourceElf)) {
    throw "Showcase ELF not found: $sourceElf"
}

New-Item -ItemType Directory -Force -Path $demoDir | Out-Null
Copy-Item -LiteralPath $sourceElf -Destination $originalElf -Force
Copy-Item -LiteralPath $sourceElf -Destination $obfuscatedElf -Force
Copy-Item -LiteralPath (Join-Path $repo "target\demo-showcase\max2-structured-new.c") -Destination $cOutput -Force

$originalHash = (Get-FileHash -LiteralPath $originalElf -Algorithm SHA256).Hash
$obfuscatedHash = (Get-FileHash -LiteralPath $obfuscatedElf -Algorithm SHA256).Hash
if ($originalHash -ne $obfuscatedHash) {
    throw "Demo fixture copies differ; refusing to continue."
}

if (Test-Path -LiteralPath $hydirctl) {
    & $hydirctl inspect $obfuscatedElf | Set-Content -Encoding utf8 (Join-Path $demoDir "inspect.json")
    & $hydirctl analyze $obfuscatedElf | Set-Content -Encoding utf8 (Join-Path $demoDir "analyze.json")
    & $hydirctl cfg $obfuscatedElf hydir_max2 | Set-Content -Encoding utf8 (Join-Path $demoDir "max2-cfg.json")
    & $hydirctl decompile $obfuscatedElf hydir_max2 --assume-u64x2 --output $cOutput
}

if ($RunTriton -and (Test-Path -LiteralPath $hydirctl)) {
    & $hydirctl triton $obfuscatedElf hydir_max2 | Set-Content -Encoding utf8 (Join-Path $demoDir "triton-max2.json")
}

Write-Host "Video demo bundle: $demoDir"
Write-Host "Original ELF:     $originalElf"
Write-Host "Obfuscated label: $obfuscatedElf"
Write-Host "SHA-256 (both):   $originalHash"
Write-Host "C output:         $cOutput"

if ($OpenHydIR) {
    if (-not (Test-Path -LiteralPath $hydir)) {
        throw "HydIR GUI not found: $hydir"
    }
    Start-Process -FilePath $hydir -WorkingDirectory $repo -ArgumentList @(
        "--open-local", $obfuscatedElf, "hydir_max2"
    )
}
