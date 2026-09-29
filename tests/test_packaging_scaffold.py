from __future__ import annotations

import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_pyinstaller_spec_bundles_required_runtime_resources() -> None:
    spec = (ROOT / "packaging" / "pyinstaller" / "vstacklens-desktop.spec").read_text(encoding="utf-8")

    assert "schema.sql" in spec
    assert "defaults" in spec
    assert "desktop_config.template.json" not in spec
    assert "reports\" / \"templates" in spec
    assert "assets" in spec
    assert "vstacklens.ico" in spec
    assert "rulepacks" in spec
    assert "builtin-vsphere-v1" not in spec
    assert "collect_submodules(\"pyVmomi\")" in spec
    assert "find_spec(\"vsanapiutils\")" in spec
    assert "vsanapiutils_spec.origin" in spec
    assert "collect_submodules(\"vsanapiutils\")" in spec
    assert "_root_vcruntime_names" in spec
    assert "vcruntime140.dll" in spec
    assert "vcruntime140_1.dll" in spec
    assert "_api_set_stub_prefixes" in spec
    assert "api-ms-win-" in spec
    assert "ext-ms-win-" in spec
    assert "_codex_runtime_root" in spec
    assert 'os.path.expanduser("~")' in spec
    assert '".cache", "codex-runtimes"' in spec
    assert "os.path.normcase" in spec
    assert "os.path.commonpath" in spec
    assert "_codex_runtime_fallback_names" in spec
    assert "icuuc.dll" in spec
    assert "icudt" in spec
    assert "libcrypto-3-x64.dll" in spec
    assert "libssl-3-x64.dll" in spec
    assert "ucrtbase.dll" in spec
    assert "Excluding bundled binary" in spec
    assert "_exclude_bundle_binary" in spec
    assert "collect_dynamic_libs(\"PySide6\")" not in spec
    assert "collect_data_files(\"PySide6\")" not in spec


def test_project_metadata_declares_package_resources_and_packaging_extra() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    package_data = pyproject["tool"]["setuptools"]["package-data"]["vstacklens"]
    package_extra = pyproject["project"]["optional-dependencies"]["package"]

    assert "db/schema.sql" in package_data
    assert "defaults/*.json" in package_data
    assert "assets/icons/*.ico" in package_data
    assert "reports/templates/*.j2" in package_data
    assert any(dependency.startswith("pyvmomi>=9") for dependency in pyproject["project"]["dependencies"])
    assert any(dependency.startswith("PyInstaller") for dependency in package_extra)
    assert any(dependency.startswith("PySide6-Essentials") for dependency in package_extra)


def test_desktop_build_script_runs_packaging_gate_and_static_smoke() -> None:
    script = (ROOT / "packaging" / "build_desktop.ps1").read_text(encoding="utf-8")

    assert "constraints-windows.txt" in script
    assert "-e \".[package,test]\"" in script
    assert "-m pytest -q" in script
    assert "-m vstacklens.cli validate-rules" in script
    assert "-m compileall src tests" in script
    assert "-m\", \"PyInstaller\"" in script
    assert "VStackLens.exe" in script
    assert "_internal\\vstacklens\\db\\schema.sql" in script
    assert "_internal\\vstacklens\\defaults\\desktop_config.template.json" in script
    assert "_internal\\vstacklens\\assets\\icons\\vstacklens.ico" in script
    assert "_internal\\vstacklens\\reports\\templates\\report_v2.html.j2" in script
    assert "_internal\\rulepacks\\builtin-vsphere-v1\\rulepack.yaml" in script
    assert "_internal\\rulepacks\\builtin-hcl-v1\\rulepack.yaml" in script
    assert "_internal\\rulepacks\\upgrade-compat-aliases.yaml" in script
    assert "_internal\\vsanapiutils.py" in script
    assert "Assert-NoConflictingMsvcRuntimeVersions" in script
    assert "Remove-PyInstallerBuildArtifacts" in script
    assert "Assert-NoBundledApiSetStubDlls" in script
    assert "api-ms-win-*.dll" in script
    assert "ext-ms-win-*.dll" in script
    assert "_internal\\ucrtbase.dll" in script
    assert "VSTACKLENS_RUNTIME_IMPORT_CHECK_PATH" in script
    assert "Remove-PreviousBundle" in script
    assert "Assert-BundleWasBuiltAfter" in script
    assert "Invoke-GuiStartupCheck" in script
    assert "$SkipGuiSmoke" in script


def test_installed_smoke_checks_vsan_sdk_and_all_rulepacks() -> None:
    script = (ROOT / "packaging" / "smoke_installed.ps1").read_text(encoding="utf-8")

    assert "_internal\\vsanapiutils.py" in script
    assert "_internal\\rulepacks\\builtin-hcl-v1\\rulepack.yaml" in script
    assert "Assert-NoConflictingMsvcRuntimeVersions" in script
    assert "Assert-NoBundledApiSetStubDlls" in script
    assert "api-ms-win-*.dll" in script
    assert "ext-ms-win-*.dll" in script
    assert "_internal\\ucrtbase.dll" in script
    assert "VSTACKLENS_RUNTIME_IMPORT_CHECK_PATH" in script
    assert "-Encoding UTF8" in script


def test_inno_installer_scaffold_wraps_offline_desktop_bundle() -> None:
    installer = (ROOT / "packaging" / "inno" / "vstacklens.iss").read_text(encoding="utf-8")

    assert '#define MyAppName "VStackLens"' in installer
    assert 'DefaultDirName={localappdata}\\Programs\\VStackLens' in installer
    assert "PrivilegesRequired=lowest" in installer
    assert 'Source: "{#MySourceDir}\\*"' in installer
    assert 'DestDir: "{app}"' in installer
    assert "[InstallDelete]" in installer
    assert 'Name: "{app}\\_internal\\api-ms-win-*.dll"' in installer
    assert 'Name: "{app}\\_internal\\ext-ms-win-*.dll"' in installer
    assert 'Name: "{app}\\_internal\\VCRUNTIME140.dll"' in installer
    assert 'Name: "{app}\\_internal\\VCRUNTIME140_1.dll"' in installer
    assert 'Name: "{app}\\_internal\\ucrtbase.dll"' in installer
    assert 'Name: "{app}\\_internal\\icuuc.dll"' in installer
    assert 'Name: "{app}\\_internal\\icudt*.dll"' in installer
    assert 'Name: "{app}\\_internal\\libcrypto-3-x64.dll"' in installer
    assert 'Name: "{app}\\_internal\\libssl-3-x64.dll"' in installer
    assert 'Name: "{group}\\VStackLens"' in installer
    assert 'Name: "{autodesktop}\\VStackLens"' in installer
    assert 'Tasks: desktopicon' not in installer
    assert "UninstallDisplayIcon" in installer
    assert "SetupIconFile" in installer
    assert "IconFilename" in installer
    assert "http://" not in installer.lower()
    assert "https://" not in installer.lower()
    assert "service" not in installer.lower()
    assert "scheduled" not in installer.lower()


def test_installer_build_script_compiles_inno_setup_output() -> None:
    script = (ROOT / "packaging" / "build_installer.ps1").read_text(encoding="utf-8")

    assert "packaging\\build_desktop.ps1" in script
    assert "packaging\\inno\\vstacklens.iss" in script
    assert "VStackLens-Setup-0.2.8.exe" in script
    assert "Get-Command \"iscc.exe\"" in script
    assert "Inno Setup 6\\ISCC.exe" in script
    assert "-IsccPath" in script
    assert "$SkipGuiSmoke" in script


def test_top_level_package_build_script_chains_desktop_and_installer_builds() -> None:
    script = (ROOT / "build-package.ps1").read_text(encoding="utf-8")

    assert "packaging\\build_desktop.ps1" in script
    assert "packaging\\build_installer.ps1" in script
    assert "dist\\VStackLens\\VStackLens.exe" in script
    assert "dist\\installer\\VStackLens-Setup-0.2.8.exe" in script
    assert "$SkipInstaller" in script


def test_handoff_build_script_collects_smoke_delivery_files() -> None:
    script = (ROOT / "packaging" / "build_handoff.ps1").read_text(encoding="utf-8")

    assert "dist\\handoff" in script
    assert "VStackLens-Setup-0.2.8.exe" in script
    assert "smoke_installed.ps1" in script
    assert "WINDOWS_SMOKE_TEST.md" in script
    assert "REAL_VCENTER_VALIDATION.md" in script
