from __future__ import annotations

import sys
from pathlib import Path

from vstacklens.application.paths import builtin_rulepack_path, ensure_default_upgrade_alias_path
from vstacklens.resources import bundled_upgrade_alias_template_path, database_schema_path, report_template_dir


def test_runtime_resource_paths_resolve_source_resources() -> None:
    assert database_schema_path().exists()
    assert (report_template_dir() / "report_v2.html.j2").exists()
    assert (builtin_rulepack_path() / "rulepack.yaml").exists()


def test_runtime_resource_paths_prefer_pyinstaller_bundle_root(monkeypatch, tmp_path: Path) -> None:
    schema_path = tmp_path / "vstacklens" / "db" / "schema.sql"
    template_dir = tmp_path / "vstacklens" / "reports" / "templates"
    rulepack_dir = tmp_path / "rulepacks" / "builtin-vsphere-v1"
    schema_path.parent.mkdir(parents=True)
    template_dir.mkdir(parents=True)
    rulepack_dir.mkdir(parents=True)
    schema_path.write_text("-- bundled schema", encoding="utf-8")
    (template_dir / "report_v2.html.j2").write_text("<html></html>", encoding="utf-8")
    (rulepack_dir / "rulepack.yaml").write_text("name: builtin-vsphere-v1", encoding="utf-8")

    monkeypatch.delenv("VSTACKLENS_RULEPACK", raising=False)
    monkeypatch.delenv("VSTACKLENS_RESOURCE_ROOT", raising=False)
    monkeypatch.delenv("VSTACKLENS_BUNDLE_ROOT", raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)

    assert database_schema_path() == schema_path
    assert report_template_dir() == template_dir
    assert builtin_rulepack_path() == rulepack_dir


def test_builtin_rulepack_path_keeps_explicit_env_override(monkeypatch, tmp_path: Path) -> None:
    custom_rulepack = tmp_path / "customer-rulepack"

    monkeypatch.setenv("VSTACKLENS_RULEPACK", str(custom_rulepack))

    assert builtin_rulepack_path() == custom_rulepack


def test_upgrade_alias_template_is_copied_once_to_user_data(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    template = bundled_upgrade_alias_template_path()
    assert template.exists()
    alias_path = ensure_default_upgrade_alias_path()
    assert alias_path.read_text(encoding="utf-8") == template.read_text(encoding="utf-8")
    alias_path.write_text("aliases:\n  - collected_model: User-confirmed\n    hcl_model: HCL model\n", encoding="utf-8")
    assert ensure_default_upgrade_alias_path().read_text(encoding="utf-8").startswith("aliases:\n  - collected_model")
