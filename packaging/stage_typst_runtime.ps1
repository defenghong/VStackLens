param(
    [Parameter(Mandatory=$true)][string]$RuntimeSource,
    [string]$Destination = (Join-Path $PSScriptRoot '..\.tools\typst')
)
$ErrorActionPreference = 'Stop'
$manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\src\vstacklens\tools\typst-runtime.json') -Raw | ConvertFrom-Json
$sourceRoot = (Resolve-Path -LiteralPath $RuntimeSource).Path
foreach ($entry in $manifest.files.PSObject.Properties) {
    $source = Join-Path $sourceRoot $entry.Name
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Missing registered Typst resource: $($entry.Name)" }
    if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.Value) { throw "Typst resource hash mismatch: $($entry.Name)" }
}
New-Item -ItemType Directory -Path $Destination -Force | Out-Null
foreach ($entry in $manifest.files.PSObject.Properties) {
    $target = Join-Path $Destination $entry.Name
    $source = Join-Path $sourceRoot $entry.Name
    if ([IO.Path]::GetFullPath($target) -ne [IO.Path]::GetFullPath($source)) { Copy-Item -LiteralPath $source -Destination $target }
    if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.Value) { throw "Staged Typst resource hash mismatch: $($entry.Name)" }
}
"Registered Typst $($manifest.version) staged and verified: $Destination"
