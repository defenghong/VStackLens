"""Home finish checks use one tiny schema-only UI fixture, never HCL or VMware."""
from copy import deepcopy

from PySide6.QtWidgets import QApplication, QBoxLayout
from vstacklens.desktop import theme
from vstacklens.desktop.app import MainWindow
from test_desktop_theme_switch import make_service, sample_dashboard, settle_qt, assert_dashboard_badges_single


def home_window(tmp_path):
    service = make_service(tmp_path, "light", with_data=True)
    window = MainWindow(service=service, auth_service=service.theme_test_auth)
    window._plan_timer.stop(); window.resize(1366, 768); window.show(); settle_qt()
    return window


def close_window(window):
    window._begin_exit(); settle_qt()
    assert window._exit_ready and not window._active_workers()


def test_home_keeps_recorded_totals_and_routes_visible_issue_details(tmp_path):
    window = home_window(tmp_path)
    try:
        assert window.dashboard_problem_total.text() == "3 类问题 · 3 个涉及对象"
        assert [window.risk_metric_labels[key].text() for key in ("P1", "P2", "P3")] == ["1", "1", "1"]
        assert window.dashboard_all_risks.isVisible()
        opened = []
        window._open_risk_center = lambda: opened.append("risk_center")
        window.dashboard_all_risks.click(); window.dashboard_issues.cellDoubleClicked.emit(0, 1)
        assert opened == ["risk_center", "risk_center"]
        assert window.dashboard_task_state.text() == "已有基础结果"
        assert not window.dashboard_standard_report.isEnabled()
        assert window.dashboard_reports_empty.isVisible()
    finally:
        close_window(window)


def test_home_missing_data_stays_unknown_instead_of_zero_or_normal(tmp_path):
    window = home_window(tmp_path)
    try:
        data = deepcopy(sample_dashboard()); data.health_status = "资料不足"
        data.customer_caliber = {}; data.asset_summary = {"VM": None}
        window._populate_dashboard(data); settle_qt()
        assert window.dashboard_problem_total.text() == "— 类问题 · — 个涉及对象"
        assert all(value.text() == "—" for value in window.risk_metric_labels.values())
        assert all(value.text() == "—" for value in window.asset_values.values())
        assert "不能据此判断正常" in window.dashboard_issues_empty.text()
        assert theme.COLORS["subtext"] in window.conclusion_strip.styleSheet()
        assert not window.dashboard_issues.isVisible()
        data.has_data = False; window._populate_dashboard(data); settle_qt()
        assert window.dashboard_stack.currentIndex() == 0
        assert not window.conclusion_card.isVisible()
    finally:
        close_window(window)


def test_home_reflows_summaries_and_settled_refresh_keeps_single_badges(tmp_path):
    window = home_window(tmp_path)
    try:
        assert window.dashboard_task_row.direction() == QBoxLayout.LeftToRight
        assert window.dashboard_metric_row.direction() == QBoxLayout.LeftToRight
        window.resize(1920, 1080); settle_qt()
        assert window.dashboard_task_row.direction() == QBoxLayout.LeftToRight
        assert window.dashboard_metric_row.direction() == QBoxLayout.LeftToRight
        window.resize(1000, 700); settle_qt()
        assert window.dashboard_task_row.direction() == QBoxLayout.TopToBottom
        assert window.dashboard_metric_row.direction() == QBoxLayout.TopToBottom
        for chosen in ("dark", "light", "dark", "light"):
            theme.apply_application_theme(QApplication.instance(), chosen)
            window._populate_dashboard(sample_dashboard()); settle_qt()
            assert_dashboard_badges_single(window)
        assert window.certificate_fold.body.isHidden()
        assert "证书" in window.certificate_fold.toggle.text() and "授权" in window.certificate_fold.toggle.text()
    finally:
        close_window(window)
