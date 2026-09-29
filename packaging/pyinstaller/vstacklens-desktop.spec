# -*- mode: python ; coding: utf-8 -*-

import importlib.util
import os
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules


project_root = Path(SPECPATH).parents[1]
source_root = project_root / "src"

runtime_root = project_root / ".tools" / "collector-runtime"
if not (runtime_root / "powershell" / "pwsh.exe").is_file():
    raise RuntimeError("Bundled collector runtime missing; run packaging/stage_collector_runtime.ps1")

typst_root = project_root / ".tools" / "typst"
typst_executable = typst_root / "typst.exe"
if not typst_executable.is_file():
    raise RuntimeError("Bundled Typst runtime missing; stage .tools/typst/typst.exe before packaging")
for typst_legal_file in (typst_root / "LICENSE", typst_root / "NOTICE"):
    if not typst_legal_file.is_file():
        raise RuntimeError(f"Bundled Typst legal notice missing: {typst_legal_file.name}")

datas = [
    (str(runtime_root / "manifest.json"), "collector-runtime"),
    (str(source_root / "vstacklens" / "collection" / "scripts"), "vstacklens/collection/scripts"),
    (str(project_root / ".tools" / "collector-runtime" / "powershell"), "collector-runtime/powershell"),
    (str(project_root / ".tools" / "collector-runtime" / "modules"), "collector-runtime/modules"),
    (str(source_root / "vstacklens" / "db" / "schema.sql"), "vstacklens/db"),
    (str(source_root / "vstacklens" / "defaults"), "vstacklens/defaults"),
    (str(source_root / "vstacklens" / "reports" / "templates"), "vstacklens/reports/templates"),
    (str(source_root / "vstacklens" / "assets"), "vstacklens/assets"),
    (str(typst_executable), "vstacklens/tools"),
    (str(typst_root / "LICENSE"), "vstacklens/tools"),
    (str(typst_root / "NOTICE"), "vstacklens/tools"),
    (str(project_root / "rulepacks"), "rulepacks"),
]

vsanapiutils_spec = importlib.util.find_spec("vsanapiutils")
if vsanapiutils_spec and vsanapiutils_spec.origin:
    datas.append((vsanapiutils_spec.origin, "."))

icon_path = source_root / "vstacklens" / "assets" / "icons" / "vstacklens.ico"

hiddenimports = collect_submodules("pyVim") + collect_submodules("pyVmomi") + collect_submodules("vsanapiutils")

a = Analysis(
    [str(source_root / "vstacklens" / "desktop" / "__main__.py")],
    pathex=[str(source_root)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

# PyInstaller may collect an older MSVC runtime at the bundle root from Python
# extensions. Qt 6.11 requires the newer runtime shipped beside PySide6.
_root_vcruntime_names = {"vcruntime140.dll", "vcruntime140_1.dll"}
_api_set_stub_prefixes = ("api-ms-win-", "ext-ms-win-")
# The build process PATH is untrusted. Source-path filtering is the primary
# defense; the names below are a fallback for the contaminants seen in practice.
_codex_runtime_root = os.path.normcase(
    os.path.abspath(os.path.join(os.path.expanduser("~"), ".cache", "codex-runtimes"))
)
_codex_runtime_fallback_names = {
    "icuuc.dll",
    "libcrypto-3-x64.dll",
    "libssl-3-x64.dll",
    "ucrtbase.dll",
}


def _is_from_codex_runtime(source_path):
    normalized_source = os.path.normcase(os.path.abspath(str(source_path)))
    try:
        return os.path.commonpath([normalized_source, _codex_runtime_root]) == _codex_runtime_root
    except ValueError:
        return False


def _exclude_bundle_binary(binary):
    destination = str(binary[0]).replace("\\", "/").casefold()
    filename = destination.rsplit("/", 1)[-1]
    source_path = binary[1]

    if destination in _root_vcruntime_names:
        reason = "conflicting root MSVC runtime"
    elif filename.startswith(_api_set_stub_prefixes):
        reason = "bundled Windows API Set stub"
    elif _is_from_codex_runtime(source_path):
        reason = "source is outside the project under the Codex runtime cache"
    elif filename in _codex_runtime_fallback_names or (
        filename.startswith("icudt") and filename.endswith(".dll")
    ):
        reason = "known Codex runtime contaminant (filename fallback)"
    else:
        return False

    print(f"Excluding bundled binary {binary[0]!r} from {source_path!r}: {reason}")
    return True


a.binaries = [
    binary
    for binary in a.binaries
    if not _exclude_bundle_binary(binary)
]

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="VStackLens",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(icon_path),
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="VStackLens",
)
