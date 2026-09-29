param(
    [switch]$SkipInstallDependencies,
    [switch]$SkipTests,
    [switch]$SkipRuleValidation,
    [switch]$SkipCompileAll,
    [switch]$SkipSmoke,
    [switch]$SkipInstaller,
    [string]$IsccPath
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$DesktopBuildScript = Join-Path $ProjectRoot "packaging\build_desktop.ps1"
$InstallerBuildScript = Join-Path $ProjectRoot "packaging\build_installer.ps1"

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
    $desktopArgs = @{}
    if ($SkipInstallDependencies) { $desktopArgs.SkipInstall = $true }
    if ($SkipTests) { $desktopArgs.SkipTests = $true }
    if ($SkipRuleValidation) { $desktopArgs.SkipRuleValidation = $true }
    if ($SkipCompileAll) { $desktopArgs.SkipCompileAll = $true }
    if ($SkipSmoke) { $desktopArgs.SkipSmoke = $true }

    Invoke-Checked "Build VStackLens desktop bundle" {
        & $DesktopBuildScript @desktopArgs
    }

    if (-not $SkipInstaller) {
        $installerArgs = @{
            SkipDesktopBuild = $true
            SkipInstallDependencies = $true
            SkipTests = $true
            SkipRuleValidation = $true
            SkipCompileAll = $true
            SkipSmoke = $true
        }
        if ($IsccPath) {
            $installerArgs.IsccPath = $IsccPath
        }

        Invoke-Checked "Build VStackLens installer" {
            & $InstallerBuildScript @installerArgs
        }
    }

    Write-Host ""
    Write-Host "Package build finished."
    Write-Host "Desktop bundle: dist\VStackLens\VStackLens.exe"
    if (-not $SkipInstaller) {
        Write-Host "Installer: dist\installer\VStackLens-Setup-0.2.8.exe"
    }
}
finally {
    Pop-Location
}
