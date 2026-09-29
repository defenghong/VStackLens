from __future__ import annotations

import json

from vstacklens.desktop.__main__ import _run_runtime_import_check


def test_runtime_import_check_writes_all_frozen_dependency_results(monkeypatch, tmp_path) -> None:
    output = tmp_path / "runtime-check.json"
    monkeypatch.setenv("VSTACKLENS_RUNTIME_IMPORT_CHECK_PATH", str(output))

    assert _run_runtime_import_check() is True
    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["ok"] is True
    assert set(result["checks"]) == {
        "PySide6.QtCore",
        "PySide6.QtGui",
        "PySide6.QtWidgets",
        "vsanapiutils",
    }
    assert all(check["ok"] is True for check in result["checks"].values())
    assert result["checks"]["PySide6.QtCore"]["qt_version"]
    assert "vsanapiutils" in str(result["checks"]["vsanapiutils"]["module"]).lower()
