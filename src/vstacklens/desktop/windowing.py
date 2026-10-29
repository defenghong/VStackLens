from __future__ import annotations

import ctypes
import sys
from pathlib import Path

from vstacklens.resources import package_resource_path


def app_icon_path() -> Path:
    return package_resource_path("assets", "icons", "vstacklens.ico")


def enable_windows_dark_title_bar(widget: object, *, enabled: bool | None = None) -> None:
    """Request the current theme on native Windows chrome, tolerating failure."""

    if not sys.platform.startswith("win"):
        return
    try:
        hwnd = int(widget.winId())  # type: ignore[attr-defined]
        if enabled is None:
            from vstacklens.desktop.theme import current_theme
            enabled = current_theme() == "dark"
        value = ctypes.c_int(1 if enabled else 0)
        for attribute in (20, 19):
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                ctypes.c_void_p(hwnd),
                ctypes.c_int(attribute),
                ctypes.byref(value),
                ctypes.sizeof(value),
            )
    except Exception:
        return
