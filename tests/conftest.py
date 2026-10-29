"""Keep Qt's native application alive and release each test's native windows."""
from __future__ import annotations

import gc
import os
import ipaddress
import socket

import pytest


@pytest.fixture(autouse=True)
def word_automation_is_opt_in(monkeypatch):
    """Ordinary tests must never start Office; the live test overrides explicitly."""
    monkeypatch.setenv('VSTACKLENS_WORD_TOC_MODE', 'disabled')


@pytest.fixture(autouse=True)
def offline_network_only(monkeypatch):
    """Allow local test servers and mocks, never a real external environment."""
    original_connect = socket.socket.connect
    original_create_connection = socket.create_connection

    def local_only(address):
        host = str(address[0]) if isinstance(address, tuple) else ""
        if host.casefold() == "localhost":
            return
        try:
            if ipaddress.ip_address(host).is_loopback:
                return
        except ValueError:
            pass
        raise OSError("Offline tests blocked an external network connection")

    def connect(sock, address):
        local_only(address)
        return original_connect(sock, address)

    def create_connection(address, *args, **kwargs):
        local_only(address)
        return original_create_connection(address, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket, "create_connection", create_connection)


@pytest.fixture(scope="session", autouse=True)
def qt_application_lifetime():
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        yield None
        return
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    app = QApplication.instance() or QApplication(["VStackLens-tests", "-platform", "offscreen"])
    app.setQuitOnLastWindowClosed(False)
    yield app
    # The strong reference lives through all test teardown and native callbacks.
    app.processEvents()


@pytest.fixture(autouse=True)
def release_test_windows(qt_application_lifetime, monkeypatch):
    app = qt_application_lifetime
    if app is None:
        yield
        return
    from PySide6.QtCore import QCoreApplication, QEvent, QThread
    from shiboken6 import isValid
    from vstacklens.desktop.tray_runtime import TrayRuntimeMixin
    # General UI tests close windows for cleanup, not to answer a new human dialog.
    # Stage-four tests exercise the actual choice dialog separately.
    monkeypatch.setattr(TrayRuntimeMixin, "_choose_close_action", lambda self: ("exit", False))
    before = {id(widget) for widget in app.topLevelWidgets()}
    yield
    app.processEvents()
    for widget in app.topLevelWidgets():
        if id(widget) in before or not isValid(widget):
            continue
        if hasattr(widget, "_plan_manager") and hasattr(widget, "_begin_exit"):
            widget._begin_exit()
        for thread in widget.findChildren(QThread):
            if thread.isRunning():
                thread.requestInterruption()
                thread.quit()
                if not thread.wait(5000):
                    pytest.fail("GUI test left a live native thread; refusing unsafe destruction")
        widget.close()
        widget.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    app.processEvents()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    gc.collect()
