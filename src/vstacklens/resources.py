from __future__ import annotations

import os
import sys
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parent
REPO_ROOT = PACKAGE_ROOT.parents[1]


def package_resource_path(*relative_parts: str) -> Path:
    """Return a package resource path that also works inside PyInstaller."""

    relative_path = Path(*relative_parts)
    candidates: list[Path] = []
    for root in _override_roots():
        candidates.append(root / "vstacklens" / relative_path)
        candidates.append(root / "src" / "vstacklens" / relative_path)

    bundle_root = _bundle_root()
    if bundle_root:
        candidates.append(bundle_root / "vstacklens" / relative_path)

    candidates.extend(
        [
            PACKAGE_ROOT / relative_path,
            REPO_ROOT / "src" / "vstacklens" / relative_path,
            Path(sys.executable).resolve().parent / "vstacklens" / relative_path,
        ]
    )
    return _first_existing(candidates)


def project_resource_path(*relative_parts: str) -> Path:
    """Return a project-level resource path, such as bundled rulepacks."""

    relative_path = Path(*relative_parts)
    candidates: list[Path] = []
    for root in _override_roots():
        candidates.append(root / relative_path)

    bundle_root = _bundle_root()
    if bundle_root:
        candidates.append(bundle_root / relative_path)

    candidates.extend(
        [
            REPO_ROOT / relative_path,
            PACKAGE_ROOT / relative_path,
            Path(sys.executable).resolve().parent / relative_path,
        ]
    )
    return _first_existing(candidates)


def database_schema_path() -> Path:
    return package_resource_path("db", "schema.sql")


def report_template_dir() -> Path:
    return package_resource_path("reports", "templates")


def bundled_builtin_rulepack_path() -> Path:
    return project_resource_path("rulepacks", "builtin-vsphere-v1")


def bundled_upgrade_alias_template_path() -> Path:
    """Locate the read-only alias template shipped with the application."""

    return project_resource_path("rulepacks", "upgrade-compat-aliases.yaml")


def bundled_builtin_hcl_path(source: str) -> Path:
    """Locate the compressed read-only HCL baseline shipped with the app."""

    names = {"vcg": "vcg-bundle.json.gz", "vsan_hcl": "vsan-all.json.gz"}
    try:
        filename = names[source]
    except KeyError as exc:
        raise ValueError(f"不支持的内置 HCL 来源：{source}") from exc
    return package_resource_path("assets", "hcl", filename)


def bundled_builtin_hcl_manifest_path() -> Path:
    """Locate the integrity manifest for the immutable bundled HCL baseline."""

    return package_resource_path("assets", "hcl", "baseline-manifest.json")


def _override_roots() -> list[Path]:
    roots: list[Path] = []
    for env_name in ("VSTACKLENS_RESOURCE_ROOT", "VSTACKLENS_BUNDLE_ROOT"):
        value = os.environ.get(env_name)
        if value:
            roots.append(Path(value))
    return roots


def _bundle_root() -> Path | None:
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        return Path(meipass)
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return None


def _first_existing(candidates: list[Path]) -> Path:
    unique_candidates = _dedupe(candidates)
    for candidate in unique_candidates:
        if candidate.exists():
            return candidate
    return unique_candidates[0]


def _dedupe(paths: list[Path]) -> list[Path]:
    seen: set[str] = set()
    unique: list[Path] = []
    for path in paths:
        key = os.path.normcase(str(path))
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique
