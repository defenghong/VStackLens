param(
    [string]$OutputDir
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$DefaultOutputDir = Join-Path $ProjectRoot "dist\handoff"
$TargetDir = if ($OutputDir) { $OutputDir } else { $DefaultOutputDir }

$items = @(
    @{
        Source = Join-Path $ProjectRoot "dist\installer\VStackLens-Setup-0.2.8.exe"
        Name = "VStackLens-Setup-0.2.8.exe"
    },
    @{
        Source = Join-Path $ProjectRoot "packaging\smoke_installed.ps1"
        Name = "smoke_installed.ps1"
    },
    @{
        Source = Join-Path $ProjectRoot "docs\WINDOWS_SMOKE_TEST.md"
        Name = "WINDOWS_SMOKE_TEST.md"
    },
    @{
        Source = Join-Path $ProjectRoot "docs\REAL_VCENTER_VALIDATION.md"
        Name = "REAL_VCENTER_VALIDATION.md"
    }
)

foreach ($item in $items) {
    if (-not (Test-Path -LiteralPath $item.Source)) {
        throw "Missing handoff input: $($item.Source)"
    }
}

if (Test-Path -LiteralPath $TargetDir) {
    Remove-Item -LiteralPath $TargetDir -Recurse -Force
}
New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null

foreach ($item in $items) {
    Copy-Item -LiteralPath $item.Source -Destination (Join-Path $TargetDir $item.Name) -Force
}

Write-Host "Handoff package ready: $TargetDir"
Get-ChildItem -LiteralPath $TargetDir | Select-Object Name, Length, LastWriteTime
