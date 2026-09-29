param(
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\VStackLens",
    [string]$DataDir = "$env:LOCALAPPDATA\VStackLens"
)

$ErrorActionPreference = "Stop"

function Assert-PathExists {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Description
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Missing $Description`: $Path"
    }
    Write-Host "OK: $Description -> $Path"
}

function Assert-DirectoryReady {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Description
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "$Description is not a directory: $Path"
    }
    Write-Host "OK: $Description -> $Path"
}

function Assert-NoConflictingMsvcRuntimeVersions {
    param([Parameter(Mandatory = $true)][string]$RootPath)

    $runtimeFiles = @(
        Get-ChildItem -LiteralPath $RootPath -Recurse -File |
            Where-Object { $_.Name -like "VCRUNTIME140*.dll" -or $_.Name -like "MSVCP140*.dll" }
    )
    $scan = @(
        foreach ($runtimeFile in $runtimeFiles) {
            [PSCustomObject]@{
                Path        = $runtimeFile.FullName.Substring($RootPath.Length).TrimStart("\\")
                Name        = $runtimeFile.Name
                FileVersion = $runtimeFile.VersionInfo.FileVersion
            }
        }
    )

    Write-Host "MSVC runtime scan:"
    $scan | Sort-Object Name, Path | Format-Table -AutoSize

    $conflicts = @(
        $scan | Group-Object Name | Where-Object {
            @($_.Group.FileVersion | Sort-Object -Unique).Count -gt 1
        }
    )
    if ($conflicts.Count -gt 0) {
        $details = $conflicts | ForEach-Object {
            "$($_.Name): $((@($_.Group.FileVersion | Sort-Object -Unique)) -join ', ')"
        }
        throw "Conflicting bundled MSVC runtime versions found: $($details -join '; ')"
    }
}

function Assert-NoBundledApiSetStubDlls {
    param([Parameter(Mandatory = $true)][string]$RootPath)

    $bundledUcrt = Join-Path $RootPath "_internal\ucrtbase.dll"
    if (Test-Path -LiteralPath $bundledUcrt) {
        throw "Bundled ucrtbase.dll found: $bundledUcrt"
    }

    $stubFiles = @(
        Get-ChildItem -LiteralPath $RootPath -Recurse -File |
            Where-Object { $_.Name -like "api-ms-win-*.dll" -or $_.Name -like "ext-ms-win-*.dll" }
    )
    if ($stubFiles.Count -eq 0) {
        Write-Host "API Set and UCRT scan: no bundled api-ms-win, ext-ms-win, or ucrtbase.dll found."
        return
    }

    $relativePaths = @(
        $stubFiles | Sort-Object FullName | ForEach-Object {
            $_.FullName.Substring($RootPath.Length).TrimStart("\\")
        }
    )
    throw "Bundled API Set stub DLLs found:`n$($relativePaths -join "`n")"
}

function Invoke-FrozenRuntimeImportCheck {
    param([Parameter(Mandatory = $true)][string]$ExecutablePath)

    $resultPath = Join-Path $env:TEMP "vstacklens-installed-runtime-import-check.json"
    $previousCheckPath = $env:VSTACKLENS_RUNTIME_IMPORT_CHECK_PATH
    Remove-Item -LiteralPath $resultPath -Force -ErrorAction SilentlyContinue
    try {
        $env:VSTACKLENS_RUNTIME_IMPORT_CHECK_PATH = $resultPath
        $process = Start-Process -FilePath $ExecutablePath -PassThru -Wait
        if ($process.ExitCode -ne 0) {
            throw "Frozen runtime import check failed with exit code $($process.ExitCode)."
        }
        if (-not (Test-Path -LiteralPath $resultPath)) {
            throw "Frozen runtime import check did not create its result file: $resultPath"
        }

        $result = Get-Content -LiteralPath $resultPath -Raw -Encoding UTF8 | ConvertFrom-Json
        Write-Host "Frozen runtime import check:"
        $result | ConvertTo-Json -Depth 5
        if (-not $result.frozen -or -not $result.ok) {
            throw "Frozen runtime import check reported failure."
        }
        foreach ($moduleName in "PySide6.QtCore", "PySide6.QtGui", "PySide6.QtWidgets", "vsanapiutils") {
            $check = ($result.checks.PSObject.Properties | Where-Object Name -eq $moduleName).Value
            if ($null -eq $check -or -not $check.ok) {
                throw "Frozen runtime import check failed for $moduleName."
            }
        }
    }
    finally {
        if ($null -eq $previousCheckPath) {
            Remove-Item Env:VSTACKLENS_RUNTIME_IMPORT_CHECK_PATH -ErrorAction SilentlyContinue
        }
        else {
            $env:VSTACKLENS_RUNTIME_IMPORT_CHECK_PATH = $previousCheckPath
        }
        Remove-Item -LiteralPath $resultPath -Force -ErrorAction SilentlyContinue
    }
}

$ExePath = Join-Path $InstallDir "VStackLens.exe"
$InternalDir = Join-Path $InstallDir "_internal"

Assert-PathExists -Path $ExePath -Description "installed executable"
Assert-PathExists -Path $InternalDir -Description "PyInstaller internal directory"
Assert-DirectoryReady -Path $DataDir -Description "runtime data directory"

$requiredResources = @(
    "_internal\vstacklens\db\schema.sql",
    "_internal\vstacklens\defaults\desktop_config.template.json",
    "_internal\vstacklens\reports\templates\report_v2.html.j2",
    "_internal\rulepacks\builtin-vsphere-v1\rulepack.yaml",
    "_internal\rulepacks\builtin-hcl-v1\rulepack.yaml",
    "_internal\rulepacks\upgrade-compat-aliases.yaml",
    "_internal\vsanapiutils.py"
)

foreach ($relativePath in $requiredResources) {
    Assert-PathExists -Path (Join-Path $InstallDir $relativePath) -Description "bundled resource $relativePath"
}

Assert-NoConflictingMsvcRuntimeVersions $InstallDir
Assert-NoBundledApiSetStubDlls $InstallDir
Invoke-FrozenRuntimeImportCheck $ExePath

Write-Host ""
Write-Host "Installed VStackLens bundle smoke check passed."
