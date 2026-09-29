param(
    [switch]$SkipDesktopBuild,
    [switch]$SkipInstallDependencies,
    [switch]$SkipTests,
    [switch]$SkipRuleValidation,
    [switch]$SkipCompileAll,
    [switch]$SkipSmoke,
    [switch]$SkipGuiSmoke,
    [string]$IsccPath
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$DesktopBuildScript = Join-Path $ProjectRoot "packaging\build_desktop.ps1"
$InstallerSpec = Join-Path $ProjectRoot "packaging\inno\vstacklens.iss"
$ExpectedInstaller = Join-Path $ProjectRoot "dist\installer\VStackLens-Setup-0.2.8.exe"

function Resolve-Iscc {
    param([string]$ExplicitPath)

    if ($ExplicitPath) {
        if (Test-Path $ExplicitPath) {
            return (Resolve-Path $ExplicitPath).Path
        }
        throw "ISCC.exe was not found at: $ExplicitPath"
    }

    $command = Get-Command "iscc.exe" -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $commonPaths = @(
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
    )
    foreach ($path in $commonPaths) {
        if ($path -and (Test-Path $path)) {
            return $path
        }
    }

    throw "Inno Setup 6 compiler was not found. Install Inno Setup 6 or pass -IsccPath C:\Path\To\ISCC.exe."
}

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

Push-Location $ProjectRoot
try {
    if (-not $SkipDesktopBuild) {
        $desktopArgs = @()
        if ($SkipInstallDependencies) { $desktopArgs += "-SkipInstall" }
        if ($SkipTests) { $desktopArgs += "-SkipTests" }
        if ($SkipRuleValidation) { $desktopArgs += "-SkipRuleValidation" }
        if ($SkipCompileAll) { $desktopArgs += "-SkipCompileAll" }
        if ($SkipSmoke) { $desktopArgs += "-SkipSmoke" }
        if ($SkipGuiSmoke) { $desktopArgs += "-SkipGuiSmoke" }

        Invoke-Checked "Build desktop bundle" {
            & $DesktopBuildScript @desktopArgs
        }
    }

    $iscc = Resolve-Iscc $IsccPath
    Invoke-Checked "Build Inno Setup installer" {
        & $iscc $InstallerSpec
    }

    if (-not (Test-Path $ExpectedInstaller)) {
        throw "Installer build finished but expected output was not found: $ExpectedInstaller"
    }

    Write-Host ""
    Write-Host "Installer ready: $ExpectedInstaller"
}
finally {
    Pop-Location
}
