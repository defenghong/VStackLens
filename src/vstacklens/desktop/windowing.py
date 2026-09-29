from __future__ import annotations

import ctypes
import sys
from pathlib import Path

from vstacklens.resources import package_resource_path


def app_icon_path() -> Path:
    return package_resource_path("assets", "icons", "vstacklens.ico")


def enable_windows_dark_title_bar(widget: object) -> None:
    """Use the native Windows title bar while requesting dark chrome."""

    if not sys.platform.startswith("win"):
        return
    try:
        hwnd = int(widget.winId())  # type: ignore[attr-defined]
        value = ctypes.c_int(1)
        for attribute in (20, 19):
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                ctypes.c_void_p(hwnd),
                ctypes.c_int(attribute),
                ctypes.byref(value),
                ctypes.sizeof(value),
            )
    except Exception:
        return
