from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QObject, QRect, Qt
from PySide6.QtGui import QColor, QPalette
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QDialog, QLabel

from vstacklens.application import DesktopInspectionConfig, InspectionService
from vstacklens.application.auth_service import AuthService
from vstacklens.application.inspection_service import DashboardData, ModelConfigProfile
from vstacklens.application.upgrade_compat_service import UpgradeCompatService
from vstacklens.db.connection import init_db
from vstacklens.desktop import app as desktop_app, theme
from vstacklens.desktop.app import LoginWindow, MainWindow
from vstacklens.desktop.widgets import RISK_COLORS


MISSING_THEME = object()


class TinyUpgrade(UpgradeCompatService):
    """Schema-only UI fixture: never import or copy the large HCL catalogue."""

    def ensure_isolated_database(self, db_path, *, seed_database_path=None):
        path = Path(db_path)
        init_db(path)
        return path

    def supported_releases(self, *args):
        return ["ESXi 8.0 U3"]

    def hcl_data_status(self, *args):
        return {
            "sources": {
                name: {"available": True, "record_count": 1,
                       "json_updated_time": "2026-10-16", "freshness": "FRESH"}
                for name in ("vcg", "vsan_hcl")
            },
            "message": "仅供主题验证的隔离模拟判据",
            "can_run": True,
            "baseline": {"version": "UI-SIMULATED"},
        }


def sample_dashboard():
    """Three synthetic risk rows for settled Qt rendering, never real results."""
    categories = [
        {"category_id": "theme-fixture-" + level, "priority": level,
         "title": title, "affected_object_count": 1,
         "affected_objects": [{"object_type": "HostSystem", "object_name": "模拟主机-" + level}],
         "remediation_zh": "请根据实际环境核查；此处仅为界面模拟资料。"}
        for level, title in (("P1", "模拟严重问题"), ("P2", "模拟重要隐患"), ("P3", "模拟优化建议"))
    ]
    return DashboardData(
        has_data=True, run_id="run-theme-fixture", customer_name="主题验证模拟客户",
        site_name="隔离模拟环境", vcenter="theme-fixture.example.invalid",
        score=None, health_status="危险", risk_summary={}, health_impact={},
        asset_summary={"Cluster": 1, "ESXi Host": 3, "VM": 6, "Datastore": 2},
        risk_trend=[], top_risks=[], recent_reports=[],
        customer_caliber={"problem_count": 3, "affected_total": 3, "non_report_total": 0,
                          "counts": {"P1": 1, "P2": 1, "P3": 1}, "categories": categories},
        finished_at="2026-10-16T06:00:00Z",
    )


def make_service(root, saved_theme="light", *, with_data=False):
    """Return an isolated service with config/db/auth paths beneath root only.

    ``saved_theme=MISSING_THEME`` omits that JSON field; other values are written
    verbatim to exercise old/invalid configurations. Optional dashboard data is
    in memory. The returned service.theme_test_auth is safe for LoginWindow and
    MainWindow screenshots; no real authentication state or HCL data is read.
    """
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    service = InspectionService(config_path=root / "desktop_config.json", upgrade_compat_service=TinyUpgrade())
    config = DesktopInspectionConfig(
        vcenter="saved-theme.example.invalid", username="synthetic-readonly",
        customer_name="已确认的模拟客户", site_name="隔离模拟站点",
        db_path=root / "desktop.db", report_output_dir=root / "reports",
        ui_theme="light", security_privacy_level="standard",
        model_config_profiles=[ModelConfigProfile(
            profile_id="theme-synthetic", profile_name="已保存模拟模型",
            api_url="https://model.example.invalid/v1", default_model="synthetic-model",
            available_models=["synthetic-model"], is_default=True,
        )],
    )
    service.save_config(config)
    payload = json.loads(service.config_path.read_text(encoding="utf-8"))
    if saved_theme is MISSING_THEME:
        payload.pop("ui_theme")
    else:
        payload["ui_theme"] = saved_theme
    service.config_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    init_db(config.db_path)
    service.theme_test_auth = AuthService(state_path=root / "auth_state.json")
    if with_data:
        data = sample_dashboard()
        service.get_latest_valid_desktop_data = lambda *args, **kwargs: data
    return service


def settle_qt(app=None):
    """Drain Qt's scheduled layout/paint and old cell-widget DeferredDelete."""
    app = app or QApplication.instance()
    for _ in range(3):
        app.processEvents()
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        app.processEvents()
        QTest.qWait(20)
    app.processEvents()


def assert_dashboard_badges_single(window):
    """Each settled dashboard row owns exactly one non-overlapping risk badge."""
    table = window.dashboard_issues
    levels = [row["priority"] for row in window._overview.customer_caliber["categories"][:5]]
    assert table.rowCount() == len(levels)
    assert len([label for label in table.findChildren(QLabel) if label.property("badgeType") == "risk"]) == len(levels)
    rectangles = []
    for row, level in enumerate(levels):
        holder = table.cellWidget(row, 0)
        assert holder is not None
        badges = [label for label in holder.findChildren(QLabel) if label.property("badgeType") == "risk"]
        assert len(badges) == 1
        badge = badges[0]
        assert badge.property("riskLevel") == level
        assert badge.isVisible()
        rectangle = QRect(badge.mapTo(table.viewport(), badge.rect().topLeft()), badge.size())
        assert rectangle.height() > 0 and rectangle.width() > 0
        assert not any(rectangle.intersects(other) for other in rectangles)
        rectangles.append(rectangle)


def _app():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    app = QApplication.instance() or QApplication(["theme-switch-test", "-platform", "offscreen"])
    theme.apply_application_theme(app, "dark")
    return app


def _window(service):
    window = MainWindow(service=service, auth_service=service.theme_test_auth)
    window._plan_timer.stop()
    return window


def _close_window(window):
    window._begin_exit()
    settle_qt()
    assert window._exit_ready and not window._active_workers()


def test_ui_theme_roundtrip_and_missing_or_invalid_fallback(tmp_path):
    service = InspectionService(config_path=tmp_path / "new-user.json", upgrade_compat_service=TinyUpgrade())
    assert DesktopInspectionConfig().ui_theme == "light"
    assert service.load_config().ui_theme == "light"
    for choice in ("dark", "light"):
        cfg = DesktopInspectionConfig(ui_theme=choice, password="synthetic-test-password")
        service.save_config(cfg)
        payload = json.loads(service.config_path.read_text(encoding="utf-8"))
        assert payload["ui_theme"] == choice
        assert "password" not in payload
        assert service.load_config().ui_theme == choice
        assert cfg.normalized().ui_theme == choice
    for invalid in (None, "", "blue", 12, [], {}):
        payload["ui_theme"] = invalid
        service.config_path.write_text(json.dumps(payload), encoding="utf-8")
        assert service.load_config().ui_theme == "light"
        assert DesktopInspectionConfig(ui_theme=invalid).normalized().ui_theme == "light"
    payload.pop("ui_theme")
    service.config_path.write_text(json.dumps(payload), encoding="utf-8")
    assert service.load_config().ui_theme == "light"


def test_invalid_runtime_theme_uses_existing_light_palette():
    app = _app()
    theme.apply_application_theme(app, "invalid-theme")
    assert theme.current_theme() == "light"
    assert theme.COLORS == theme.LIGHT
    assert app.palette().color(QPalette.Window) == QColor(theme.LIGHT["background"])


def test_runtime_switch_updates_existing_windows_and_live_color_references():
    app = _app()
    live_colors = theme.COLORS
    live_status = theme.STATUS_COLORS
    dark_style = theme.current_stylesheet()
    dialog = QDialog()
    dialog.show()
    try:
        theme.apply_application_theme(app, "light")
        settle_qt(app)
        assert theme.COLORS is live_colors
        assert theme.STATUS_COLORS is live_status
        assert live_colors["text"] == theme.LIGHT["text"]
        assert live_status["danger"] == theme.LIGHT["P1"]
        assert RISK_COLORS["P2"] == theme.LIGHT["P2"]
        assert theme.current_stylesheet() != dark_style
        assert dialog.styleSheet() == ""
        assert app.styleSheet() == theme.current_stylesheet()
        assert dialog.palette().color(dialog.backgroundRole()) == QColor(theme.LIGHT["background"])
        assert theme.DARK.keys() == theme.LIGHT.keys()
    finally:
        dialog.close()
        theme.apply_application_theme(app, "dark")


@pytest.mark.parametrize("saved_theme,target_theme", [("dark", "light"), ("light", "dark")])
def test_theme_choice_is_immediate_and_saves_only_already_saved_settings(tmp_path, saved_theme, target_theme):
    app = _app()
    service = make_service(tmp_path, saved_theme)
    window = _window(service)
    try:
        saved = json.loads(service.config_path.read_text(encoding="utf-8"))
        window.customer_input.setText("尚未确认的客户草稿")
        window.vcenter_input.setText("draft-theme.example.invalid")
        window.username_input.setText("unsaved-readonly")
        window.password_input.setText("SYNTHETIC_UNSAVED_PASSWORD")
        window.report_dir_input.set_path_value(str(tmp_path / "unsaved-report-path"))
        window.default_report_dir_input.set_path_value(str(tmp_path / "unsaved-default-path"))
        window.db_path_input.set_path_value(str(tmp_path / "unsaved-database.db"))
        window.privacy_level_combo.setCurrentIndex(window.privacy_level_combo.findData("strict"))
        window.settings_profile_name_input.setText("尚未确认的模型名称")
        window.settings_profile_api_url_input.setText("https://draft-model.example.invalid/v1")
        window.settings_profile_api_key_input.setText("SYNTHETIC_UNSAVED_API_KEY")
        window.settings_profile_timeout_input.setValue(123)
        window.ui_theme_combo.setCurrentIndex(window.ui_theme_combo.findData(target_theme))
        assert theme.current_theme() == target_theme
        persisted = json.loads(service.config_path.read_text(encoding="utf-8"))
        assert persisted == {**saved, "ui_theme": target_theme}
        assert service.load_config().ui_theme == target_theme
        assert window.customer_input.text() == "尚未确认的客户草稿"
        assert window.settings_profile_name_input.text() == "尚未确认的模型名称"
        assert "password" not in persisted
        assert persisted["model_config_profiles"][0]["api_key"] == ""
        assert window._settings_config().ui_theme == target_theme
        settle_qt(app)
        assert app.palette().color(QPalette.Window) == QColor(theme.THEMES[target_theme]["background"])
    finally:
        _close_window(window)


@pytest.mark.parametrize("saved_theme,expected", [
    pytest.param(MISSING_THEME, "light", id="missing"),
    pytest.param("invalid-theme", "light", id="invalid"),
    pytest.param("dark", "dark", id="explicit-dark"),
    pytest.param("light", "light", id="explicit-light"),
])
def test_startup_applies_theme_before_login_construction_and_first_show(tmp_path, monkeypatch, saved_theme, expected):
    app = _app()
    service = make_service(tmp_path, saved_theme)
    events = []

    def observe(stage):
        events.append(stage)
        assert theme.current_theme() == expected
        assert app.palette().color(QPalette.Window) == QColor(theme.THEMES[expected]["background"])

    class StartupLogin:
        def __init__(self):
            observe("login-construction")
            self.authenticated = True
            self.auth_service = service.theme_test_auth
            self.logged_in_username = "synthetic-local-user"

        def exec(self):
            observe("login-first-show")
            return QDialog.Accepted

    class StartupMain:
        def __init__(self, **kwargs):
            observe("main-construction")
            assert kwargs["service"] is service

        def show(self):
            observe("main-first-show")

        def show_default_password_warning_if_needed(self):
            raise AssertionError("Deferred startup warning is outside this ordering test")

    actual_apply = theme.apply_application_theme

    def startup_apply(application, name):
        actual_apply(application, name)
        observe("apply-before-login")

    monkeypatch.setattr(desktop_app, "QApplication", lambda *args: app)
    monkeypatch.setattr(desktop_app, "InspectionService", lambda: service)
    monkeypatch.setattr(service, "initialize_local_workspace", service.load_config)
    monkeypatch.setattr(desktop_app, "configure_runtime_logging", lambda: tmp_path / "startup.log")
    monkeypatch.setattr(desktop_app, "configure_chinese_font", lambda application: None)
    monkeypatch.setattr(desktop_app, "apply_application_theme", startup_apply)
    monkeypatch.setattr(desktop_app, "LoginWindow", StartupLogin)
    monkeypatch.setattr(desktop_app, "MainWindow", StartupMain)
    monkeypatch.setattr(desktop_app.QTimer, "singleShot", lambda *args: None)
    monkeypatch.setattr(app, "exec", lambda: 0)
    monkeypatch.setattr(app, "vstacklens_owns_event_loop", False, raising=False)
    try:
        with pytest.raises(SystemExit) as exit_info:
            desktop_app.main()
        assert exit_info.value.code == 0
        assert events == ["apply-before-login", "login-construction", "login-first-show",
                          "main-construction", "main-first-show"]
    finally:
        app.vstacklens_owns_event_loop = False


def test_login_without_application_stylesheet_defaults_light_before_show(tmp_path):
    app = _app()
    app.setStyleSheet("")
    login = LoginWindow(auth_service=AuthService(state_path=tmp_path / "isolated-auth.json"))
    try:
        assert theme.current_theme() == "light"
        assert app.styleSheet() == theme.current_stylesheet()
        login.show()
        settle_qt(app)
        assert login.palette().color(QPalette.Window) == QColor(theme.LIGHT["background"])
    finally:
        login.close()


@pytest.mark.parametrize("saved_theme,expected", [
    pytest.param(MISSING_THEME, "light", id="missing"),
    pytest.param("invalid-theme", "light", id="invalid"),
    pytest.param("dark", "dark", id="explicit-dark"),
    pytest.param("light", "light", id="explicit-light"),
])
def test_main_window_matches_saved_theme_before_form_loading_and_first_show(tmp_path, monkeypatch, saved_theme, expected):
    app = _app()
    theme.apply_application_theme(app, "light" if expected == "dark" else "dark")
    service = make_service(tmp_path, saved_theme)
    original_load = MainWindow._load_saved_config
    loads = []
    shows = []

    def checked_load(window):
        loads.append(theme.current_theme())
        assert theme.current_theme() == expected
        return original_load(window)

    class FirstShowObserver(QObject):
        def eventFilter(self, watched, event):
            if event.type() == QEvent.Show:
                shows.append((theme.current_theme(), watched.palette().color(QPalette.Window).name()))
            return False

    monkeypatch.setattr(MainWindow, "_load_saved_config", checked_load)
    window = _window(service)
    observer = FirstShowObserver(window)
    window.installEventFilter(observer)
    try:
        assert loads == [expected]
        assert window.ui_theme_combo.currentData() == expected
        window.show()
        settle_qt(app)
        assert shows and all(value == (expected, QColor(theme.THEMES[expected]["background"]).name()) for value in shows)
    finally:
        _close_window(window)


def test_settled_dashboard_refresh_and_theme_roundtrips_have_one_badge_per_row(tmp_path):
    app = _app()
    service = make_service(tmp_path, "light", with_data=True)
    window = _window(service)
    window.resize(1366, 768)
    window.show()
    try:
        for choice in ("light", "dark", "light", "dark", "light"):
            window.ui_theme_combo.setCurrentIndex(window.ui_theme_combo.findData(choice))
            window._refresh_all_data()
            window._refresh_all_data()
            settle_qt(app)
            assert theme.current_theme() == choice
            assert_dashboard_badges_single(window)
    finally:
        _close_window(window)


def test_all_eleven_navigation_items_fit_small_window_without_scroll(tmp_path):
    app = _app()
    service = make_service(tmp_path, "light")
    window = _window(service)
    window.resize(1366, 675)
    window.show()
    try:
        for name in ("dark", "light"):
            theme.apply_application_theme(app, name)
            settle_qt(app)
            assert len([window.nav.item(i) for i in range(window.nav.count()) if window.nav.item(i).data(Qt.UserRole)]) == 11
            assert window.nav.verticalScrollBar().maximum() == 0
            assert window.nav.visualItemRect(window.nav.item(window.nav_rows["license"])).bottom() <= window.nav.viewport().height()
    finally:
        _close_window(window)
