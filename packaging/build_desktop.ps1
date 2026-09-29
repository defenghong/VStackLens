param(
    [switch]$SkipInstall,
    [switch]$SkipTests,
    [switch]$SkipRuleValidation,
    [switch]$SkipCompileAll,
    [switch]$SkipSmoke,
    [switch]$SkipGuiSmoke,
    [switch]$NoClean
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$LocalPython = Join-Path $ProjectRoot ".python312\python.exe"
if (Test-Path $VenvPython) {
    $Python = $VenvPython
}
elseif (Test-Path $LocalPython) {
    $Python = $LocalPython
}
else {
    $PythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if ($null -eq $PythonCommand -or $PythonCommand.Source -match "WindowsApps") {
        throw "No usable Python runtime found. Create .venv or install Python 3.12 before building the desktop package."
    }
    $Python = $PythonCommand.Source
}
$SpecPath = Join-Path $ProjectRoot "packaging\pyinstaller\vstacklens-desktop.spec"
$DistDir = Join-Path $ProjectRoot "dist\VStackLens"
$ExePath = Join-Path $DistDir "VStackLens.exe"
$PytestTempDir = Join-Path $ProjectRoot "out\pytest-tmp"

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Command
    )

    Write-Host ""
    Write-Host "==> $Name"
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}

function Assert-PathExists {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path $Path)) {
        throw "Missing expected bundle path: $Path"
    }
}

function Assert-NoConflictingMsvcRuntimeVersions {
    param([Parameter(Mandatory = $true)][string]$RootPath)

    $runtimeFiles = @(
        Get-ChildItem -LiteralPath $RootPath -Recurse -File |
            Where-Object { $_.FullName -notlike "*\collector-runtime\*" -and ($_.Name -like "VCRUNTIME140*.dll" -or $_.Name -like "MSVCP140*.dll") }
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

function Remove-PreviousBundle {
    param([Parameter(Mandatory = $true)][string]$BundlePath)

    if (-not (Test-Path -LiteralPath $BundlePath)) {
        return
    }

    $resolvedBundlePath = (Resolve-Path -LiteralPath $BundlePath).Path
    if ($resolvedBundlePath -ne $BundlePath) {
        throw "Refusing to remove an unexpected bundle path: $resolvedBundlePath"
    }
    Remove-Item -LiteralPath $resolvedBundlePath -Recurse -Force
}

function Remove-PyInstallerBuildArtifacts {
    param([Parameter(Mandatory = $true)][string]$ProjectRoot)

    $buildPath = Join-Path $ProjectRoot "build"
    if (Test-Path -LiteralPath $buildPath) {
        $resolvedBuildPath = (Resolve-Path -LiteralPath $buildPath).Path
        if ($resolvedBuildPath -ne $buildPath) {
            throw "Refusing to remove an unexpected build path: $resolvedBuildPath"
        }
        Remove-Item -LiteralPath $resolvedBuildPath -Recurse -Force
        Write-Host "Removed PyInstaller build directory: $resolvedBuildPath"
    }

    $removedCacheCount = 0
    foreach ($sourcePath in @(
            (Join-Path $ProjectRoot "src"),
            (Join-Path $ProjectRoot "tests")
        )) {
        $cacheDirectories = @(Get-ChildItem -LiteralPath $sourcePath -Directory -Recurse -Force -Filter "__pycache__")
        foreach ($cacheDirectory in $cacheDirectories) {
            Remove-Item -LiteralPath $cacheDirectory.FullName -Recurse -Force
            $removedCacheCount += 1
        }
    }
    Write-Host "Removed Python bytecode cache directories: $removedCacheCount"
}

function Assert-NoBundledApiSetStubDlls {
    param([Parameter(Mandatory = $true)][string]$RootPath)

    $bundledUcrt = Join-Path $RootPath "_internal\ucrtbase.dll"
    if (Test-Path -LiteralPath $bundledUcrt) {
        throw "Bundled ucrtbase.dll found: $bundledUcrt"
    }

    $stubFiles = @(
        Get-ChildItem -LiteralPath $RootPath -Recurse -File |
            Where-Object { $_.FullName -notlike "*\collector-runtime\*" -and ($_.Name -like "api-ms-win-*.dll" -or $_.Name -like "ext-ms-win-*.dll") }
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

function Assert-BundleWasBuiltAfter {
    param(
        [Parameter(Mandatory = $true)][string]$ExecutablePath,
        [Parameter(Mandatory = $true)][datetime]$BuildStartedAt
    )

    Assert-PathExists $ExecutablePath
    $executableWriteTime = (Get-Item -LiteralPath $ExecutablePath).LastWriteTime
    Write-Host "Bundle freshness: build_started=$BuildStartedAt executable_last_write=$executableWriteTime"
    if ($executableWriteTime -le $BuildStartedAt) {
        throw "Bundle executable is stale: build started at $BuildStartedAt but $ExecutablePath was last written at $executableWriteTime"
    }
}

function Invoke-FrozenRuntimeImportCheck {
    param([Parameter(Mandatory = $true)][string]$ExecutablePath)

    $resultPath = Join-Path $env:TEMP "vstacklens-runtime-import-check.json"
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

function Invoke-GuiStartupCheck {
    param([Parameter(Mandatory = $true)][string]$ExecutablePath)

    $process = Start-Process -FilePath $ExecutablePath -PassThru
    try {
        $deadline = (Get-Date).AddSeconds(12)
        do {
            Start-Sleep -Milliseconds 500
            $process.Refresh()
            if ($process.HasExited) {
                throw "GUI startup check failed: process exited with code $($process.ExitCode)."
            }
            if (-not [string]::IsNullOrWhiteSpace($process.MainWindowTitle)) {
                Write-Host "GUI startup check: pid=$($process.Id) title=$($process.MainWindowTitle)"
                return
            }
        } while ((Get-Date) -lt $deadline)

        throw "GUI startup check failed: process remained alive but did not expose a main window title within 12 seconds."
    }
    finally {
        $process.Refresh()
        if (-not $process.HasExited) {
            Stop-Process -Id $process.Id -Force
            $process.WaitForExit()
        }
    }
}

Push-Location $ProjectRoot
try {
    if (-not $SkipInstall) {
        Invoke-Checked "Install packaging dependencies" {
            & $Python -m pip install -c (Join-Path $PSScriptRoot "constraints-windows.txt") -e ".[package,test]"
        }
    }

    if (-not $SkipTests) {
        Invoke-Checked "Run unit tests" {
            New-Item -ItemType Directory -Force $PytestTempDir | Out-Null
            $previousTmp = $env:TMP
            $previousTemp = $env:TEMP
            try {
                $env:TMP = $PytestTempDir
                $env:TEMP = $PytestTempDir
                & $Python -m pytest -q -p no:cacheprovider
            }
            finally {
                $env:TMP = $previousTmp
                $env:TEMP = $previousTemp
            }
        }
    }

    if (-not $SkipRuleValidation) {
        Invoke-Checked "Validate builtin rulepack" {
            & $Python -m vstacklens.cli validate-rules --rulepack ".\rulepacks\builtin-vsphere-v1"
        }
    }

    if (-not $SkipCompileAll) {
        Invoke-Checked "Compile Python sources" {
            & $Python -m compileall src tests
        }
    }

    $buildStartedAt = Get-Date
    Remove-PyInstallerBuildArtifacts $ProjectRoot
    Remove-PreviousBundle $DistDir

    $pyinstallerArgs = @("-m", "PyInstaller", $SpecPath, "--noconfirm")
    if (-not $NoClean) {
        $pyinstallerArgs += "--clean"
    }
    Invoke-Checked "Build PyInstaller onedir bundle" {
        & $Python @pyinstallerArgs
    }

    if (-not $SkipSmoke) {
        Write-Host ""
        Write-Host "==> Smoke check bundled resources"
        Assert-BundleWasBuiltAfter $ExePath $buildStartedAt
        Assert-PathExists (Join-Path $DistDir "_internal\vstacklens\db\schema.sql")
        Assert-PathExists (Join-Path $DistDir "_internal\vstacklens\defaults\desktop_config.template.json")
        Assert-PathExists (Join-Path $DistDir "_internal\vstacklens\assets\icons\vstacklens.ico")
        Assert-PathExists (Join-Path $DistDir "_internal\vstacklens\reports\templates\report_v2.html.j2")
        Assert-PathExists (Join-Path $DistDir "_internal\rulepacks\builtin-vsphere-v1\rulepack.yaml")
        Assert-PathExists (Join-Path $DistDir "_internal\rulepacks\builtin-hcl-v1\rulepack.yaml")
        Assert-PathExists (Join-Path $DistDir "_internal\rulepacks\upgrade-compat-aliases.yaml")
        Assert-PathExists (Join-Path $DistDir "_internal\vsanapiutils.py")
        Assert-PathExists (Join-Path $DistDir "_internal\collector-runtime\powershell\pwsh.exe")
        Assert-PathExists (Join-Path $DistDir "_internal\collector-runtime\manifest.json")
        Assert-PathExists (Join-Path $DistDir "_internal\vstacklens\collection\scripts\collect_esxcli.ps1")
        Assert-NoConflictingMsvcRuntimeVersions $DistDir
        Assert-NoBundledApiSetStubDlls $DistDir
        Invoke-FrozenRuntimeImportCheck $ExePath
        if (-not $SkipGuiSmoke) {
            Invoke-GuiStartupCheck $ExePath
        }

        $rulepackFiles = Get-ChildItem (Join-Path $DistDir "_internal\rulepacks\builtin-vsphere-v1") -Recurse -File
        if ($rulepackFiles.Count -lt 2) {
            throw "Bundled rulepack looks incomplete: found $($rulepackFiles.Count) file(s)."
        }
    }

    Write-Host ""
    Write-Host "Bundle ready: $ExePath"
}
finally {
    Pop-Location
}
