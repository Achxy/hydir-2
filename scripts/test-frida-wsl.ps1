param(
    [Parameter(Mandatory=$true)][string]$Hydirctl,
    [Parameter(Mandatory=$true)][string]$Binary,
    [Parameter(Mandatory=$true)][string]$InputSpec,
    [Parameter(Mandatory=$true)][string]$Function
)
$ErrorActionPreference = 'Stop'
$cli = (Resolve-Path -LiteralPath $Hydirctl).Path
$statusJson = & $cli frida-worker status
if ($LASTEXITCODE -ne 0) { throw 'Frida worker status command failed' }
$status = $statusJson | ConvertFrom-Json
if (-not $status.ready -or $status.mode -ne 'wsl2') { throw "WSL2 worker unavailable: $($status.detail)" }

# Exercise binary-safe transport with spaces and Unicode paths on the Windows side.
$resultDirectory = Join-Path ([IO.Path]::GetTempPath()) ('HydIR Frida WSL ' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $resultDirectory | Out-Null
$stagedBinary = Join-Path $resultDirectory 'sample λ.elf'
$stagedInput = Join-Path $resultDirectory 'input λ.json'
$tracePath = Join-Path $resultDirectory 'trace.json'
Copy-Item -LiteralPath $Binary -Destination $stagedBinary
Copy-Item -LiteralPath $InputSpec -Destination $stagedInput
& $cli observe frida $stagedBinary $stagedInput --function $Function --output $tracePath
if ($LASTEXITCODE -ne 0) { throw 'Real WSL Frida observation failed' }
$trace = Get-Content -LiteralPath $tracePath -Raw | ConvertFrom-Json
$binaryHash = (Get-FileHash -LiteralPath $stagedBinary -Algorithm SHA256).Hash.ToLowerInvariant()
if ($trace.binary_sha256 -ne $binaryHash -or $trace.status -ne 'completed' -or $trace.lost_events -ne 0) {
    throw 'Incomplete or mismatched Frida trace'
}
$selected = [Convert]::ToUInt64(($Function -replace '^0x', ''), 16)
$entries = @($trace.events | Where-Object { $_.kind -eq 'entry' -and $_.source.elf_vaddr -eq $selected })
$blocks = @($trace.events | Where-Object { $_.kind -eq 'block' })
if ($entries.Count -eq 0 -or $blocks.Count -eq 0) { throw 'Missing verified function entry or block events' }
Write-Output "Verified WSL2 ELF observation: $($trace.events.Count) events; $tracePath"
