"""Small isolated login regressions; no VMware, catalogue, or customer database."""
from __future__ import annotations

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QPoint, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QDialog, QLineEdit

from vstacklens.application.auth_service import AuthService
from vstacklens.desktop.app import LoginWindow, configure_chinese_font
from vstacklens.desktop.theme import apply_application_theme


def _settle(app):
    for _ in range(3):
        app.processEvents()
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        QTest.qWait(5)
    app.processEvents()


def _login_window(tmp_path, app, *, theme="light"):
    apply_application_theme(app, theme)
    configure_chinese_font(app)
    auth = AuthService(state_path=tmp_path / "isolated-auth.json")
    window = LoginWindow(auth_service=auth)
    window.show()
    window.activateWindow()
    _settle(app)
    return window, auth


def test_login_failure_keeps_form_stable_and_clears_password(tmp_path, qt_application_lifetime):
    app = qt_application_lifetime
    window, _ = _login_window(tmp_path, app)
    fields = (window.username_input, window.password_input, window.login_button)
    before = [(widget.mapTo(window, QPoint()), widget.size()) for widget in fields]
    window.password_input.setText("synthetic-wrong-password")
    window.login_button.click()
    _settle(app)
    assert not window.authenticated
    assert window.isVisible()
    assert window.error_label.isVisible()
    assert "登录失败" in window.error_label.text()
    assert window.password_input.text() == ""
    assert window.password_input.hasFocus()
    assert [(widget.mapTo(window, QPoint()), widget.size()) for widget in fields] == before


@pytest.mark.parametrize("remember", [True, False], ids=["remember", "do-not-remember"])
def test_login_preserves_authentication_and_username_choice(tmp_path, qt_application_lifetime, remember):
    app = qt_application_lifetime
    window, auth = _login_window(tmp_path, app)
    window.username_input.setText(" admin ")
    window.password_input.setText(AuthService.DEFAULT_PASSWORD)
    window.remember_username.setChecked(remember)
    window.login_button.click()
    _settle(app)
    assert window.authenticated
    assert window.logged_in_username == "admin"
    assert window.result() == QDialog.Accepted
    assert auth.load_saved_username() == ("admin" if remember else "")
    if remember:
        reopened = LoginWindow(auth_service=auth)
        assert reopened.username_input.text() == "admin"
        assert reopened.remember_username.isChecked()


def test_login_password_visibility_and_keyboard_focus(tmp_path, qt_application_lifetime):
    app = qt_application_lifetime
    window, _ = _login_window(tmp_path, app)
    window.password_input.setText("synthetic-display-only")
    assert window.password_input.echoMode() == QLineEdit.Password
    window.password_visibility_action.trigger()
    assert window.password_input.echoMode() == QLineEdit.Normal
    assert window.password_visibility_action.toolTip() == "隐藏密码"
    window.password_visibility_action.trigger()
    assert window.password_input.echoMode() == QLineEdit.Password
    assert window.password_input.text() == "synthetic-display-only"
    window.username_input.setFocus()
    QTest.keyClick(window.username_input, Qt.Key_Return)
    _settle(app)
    assert window.password_input.hasFocus()


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_login_form_is_accessible_in_small_window(tmp_path, qt_application_lifetime, theme):
    app = qt_application_lifetime
    window, _ = _login_window(tmp_path, app, theme=theme)
    assert 320 <= window.username_input.width() <= 340
    window.resize(360, 580)
    _settle(app)
    assert window.width() <= 360
    assert window.height() <= 614
    assert window.username_input.width() == window.password_input.width() == window.login_button.width()
    for widget in (window.username_input, window.password_input, window.remember_username, window.login_button):
        assert widget.isVisible()
        top_left = widget.mapTo(window, QPoint())
        bottom_right = widget.mapTo(window, QPoint(widget.width() - 1, widget.height() - 1))
        assert window.rect().contains(top_left)
        assert window.rect().contains(bottom_right)
