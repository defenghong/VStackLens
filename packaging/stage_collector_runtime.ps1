param(
    [string]$PowerShellZip,
    [string]$ModuleRoot = "$HOME\Documents\WindowsPowerShell\Modules"
)
# Build-machine only. Customers never download modules or modify PSModulePath.
$ErrorActionPreference = 'Stop'
$root = Join-Path $PSScriptRoot '..\.tools\collector-runtime'
New-Item -ItemType Directory -Force $root | Out-Null
if (-not $PowerShellZip) { $PowerShellZip = Join-Path $root 'PowerShell-7.4.13-win-x64.zip' }
if (-not (Test-Path -LiteralPath $PowerShellZip)) { throw 'Provide the official PowerShell 7.4.13 win-x64 ZIP on the build machine.' }
Expand-Archive -LiteralPath $PowerShellZip -DestinationPath (Join-Path $root 'powershell') -Force
$versions = @{'VMware.Vim'='8.3.0.24145081'; 'VMware.VimAutomation.Sdk'='13.3.0.24145081'; 'VMware.VimAutomation.Common'='13.3.0.24145081'; 'VMware.VimAutomation.Cis.Core'='13.3.0.24145081'; 'VMware.VimAutomation.Core'='13.3.0.24145081'}
foreach ($name in $versions.Keys) {
    $source = Join-Path $ModuleRoot "$name\$($versions[$name])"
    if (-not (Test-Path -LiteralPath $source)) { throw "Required pinned module absent: $name $($versions[$name])" }
    $destination = Join-Path $root "modules\$name"
    New-Item -ItemType Directory -Force $destination | Out-Null
    Copy-Item -LiteralPath $source -Destination $destination -Recurse -Force
}
$files = Get-ChildItem -LiteralPath $root -File -Recurse | Where-Object {$_.Extension -ne '.zip' -and $_.Name -ne 'manifest.json'} | ForEach-Object {
    @{path=[IO.Path]::GetRelativePath((Resolve-Path $root).Path,$_.FullName).Replace('\','/');sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLower();size=$_.Length}
}
@{powershell='7.4.13';powercli='13.3.0.24145081';files=@($files)} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $root 'manifest.json') -Encoding utf8
Write-Output 'Collector runtime staged. Keep vendor notices and EULA files with the modules.'
