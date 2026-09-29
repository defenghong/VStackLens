from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path

def _run_runtime_import_check() -> bool:
    """Write a frozen-runtime dependency check when explicitly requested."""

    destination = os.environ.get("VSTACKLENS_RUNTIME_IMPORT_CHECK_PATH")
    if not destination:
        return False
    payload: dict[str, object] = {
        "frozen": bool(getattr(sys, "frozen", False)),
        "checks": {},
    }
    checks: dict[str, dict[str, object]] = {}
    for module_name in (
        "PySide6.QtCore",
        "PySide6.QtGui",
        "PySide6.QtWidgets",
        "vsanapiutils",
    ):
        try:
            module = importlib.import_module(module_name)
            checks[module_name] = {"ok": True, "module": str(getattr(module, "__file__", ""))}
            if module_name == "PySide6.QtCore":
                checks[module_name]["qt_version"] = str(module.qVersion())
        except Exception as exc:  # noqa: BLE001 - this branch is an explicit diagnostic.
            checks[module_name] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    if os.environ.get("VSTACKLENS_COLLECTOR_RUNTIME_CHECK") == "1":
        try:
            from vstacklens.collection.powercli_backend import PowerCliBackend
            PowerCliBackend("", "", "", timeout=30).prepare([], probe_only=True)
            checks["PowerCLI"] = {"ok": True, "protocol": "stdin-json", "network_used": False}
        except Exception as exc:
            checks["PowerCLI"] = {"ok": False, "error": type(exc).__name__}
    payload["checks"] = checks
    payload["ok"] = all(check["ok"] for check in checks.values())
    Path(destination).write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return True


if __name__ == "__main__":
    if not _run_runtime_import_check():
        from vstacklens.desktop.app import main

        main()
