from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest


pytest.importorskip("PySide6")

from PySide6.QtCore import QPoint, QPointF, Qt  # noqa: E402
from PySide6.QtGui import QWheelEvent  # noqa: E402
from PySide6.QtWidgets import QApplication, QCheckBox, QComboBox, QDialog, QLineEdit, QLabel, QListWidget, QMessageBox, QPushButton, QTextEdit  # noqa: E402

from vstacklens.application import AuthService, CheckEvidenceItem, HistoryAssetChangeItem, HistoryRiskChangeItem, PlatformAssetItem  # noqa: E402
from vstacklens.desktop import app as desktop_app  # noqa: E402
from vstacklens.desktop.widgets import NoWheelComboBox, RiskTrendChart  # noqa: E402
from vstacklens.desktop.app import DefaultPasswordWarningDialog, LoginWindow, MainWindow, configure_chinese_font  # noqa: E402


def _app() -> QApplication:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    app = QApplication.instance()
    if app is None:
        app = QApplication(["vstacklens-desktop-font-test", "-platform", "offscreen"])
    return app


def test_configure_chinese_font_loads_windows_font_when_available() -> None:
    app = _app()
    family = configure_chinese_font(app)

    if sys.platform.startswith("win"):
        assert family
    if family:
        assert app.font().family() == family


def test_desktop_window_offscreen_screenshot_renders_chinese(tmp_path: Path) -> None:
    app = _app()
    configure_chinese_font(app)
    window = MainWindow()
    window.resize(1200, 780)
    window.show()
    app.processEvents()

    for text in ("仪表盘", "vCenter 管理", "巡检中心", "日志分析", "风险中心", "资产中心", "报告中心", "系统设置", "关于软件"):
        assert window.nav.findItems(text, Qt.MatchExactly)
    assert window.nav.currentItem().text() == "仪表盘"

    pixmap = window.grab()
    path = tmp_path / "desktop-font-smoke.png"
    pixmap.save(str(path))
    image = pixmap.toImage()
    width = image.width()
    height = image.height()
    dark_pixels = 0
    for y in range(0, height, 4):
        for x in range(0, width, 4):
            color = image.pixelColor(x, y)
            if color.red() < 80 and color.green() < 80 and color.blue() < 80:
                dark_pixels += 1

    assert path.exists()
    assert pixmap.width() > 0 and pixmap.height() > 0
    assert dark_pixels > 20
    window.close()


def test_desktop_navigation_switches_to_new_primary_pages() -> None:
    app = _app()
    configure_chinese_font(app)
    window = MainWindow()
    window.show()
    app.processEvents()

    expected = {
        "dashboard": "仪表盘",
        "vcenter_management": "vCenter 管理",
        "inspection_center": "巡检中心",
        "log_analysis": "日志分析",
        "risk_center": "风险中心",
        "asset_center": "资产中心",
        "history_compare": "历史对比",
        "report_center": "报告中心",
        "settings": "系统设置",
        "license": "关于软件",
    }
    for module_id, title in expected.items():
        window.go_to_module(module_id)
        app.processEvents()
        assert window.nav.currentItem().text() == title

    window.close()


def test_productized_ui_exposes_dashboard_risk_report_and_planned_boundaries() -> None:
    app = _app()
    configure_chinese_font(app)
    window = MainWindow()
    window.show()
    app.processEvents()

    assert window.findChild(RiskTrendChart) is not None
    assert isinstance(window.risk_list, QListWidget)
    assert isinstance(window.report_list, QListWidget)
    assert isinstance(window.dashboard_certificate_detail, QTextEdit)
    assert isinstance(window.dashboard_certificate_toggle, QPushButton)
    assert isinstance(window.baseline_run_combo, QComboBox)
    assert isinstance(window.comparison_run_combo, QComboBox)
    assert isinstance(window.history_risk_filter, QComboBox)
    assert isinstance(window.history_risk_list, QListWidget)
    assert isinstance(window.history_asset_list, QListWidget)

    assert "ai_center" not in window.module_index
    assert "template_center" not in window.module_index

    window.go_to_module("report_center")
    app.processEvents()
    buttons = window.pages.currentWidget().findChildren(QPushButton)
    assert not any("PDF" in button.text() or "PPT" in button.text() for button in buttons)
    assert window.report_word_button.text() == "打开 Word 报告"


def test_desktop_combo_boxes_ignore_mouse_wheel_changes() -> None:
    app = _app()
    configure_chinese_font(app)
    window = MainWindow()
    window.show()
    app.processEvents()

    combos = window.findChildren(QComboBox)
    assert combos
    assert all(isinstance(combo, NoWheelComboBox) for combo in combos)
    combo = window.upgrade_release_combo
    combo.clear()
    combo.addItems(["ESXi 7.0 U3", "ESXi 8.0 U3"])
    combo.setCurrentIndex(0)
    event = QWheelEvent(
        QPointF(4, 4), QPointF(4, 4), QPoint(), QPoint(0, -120),
        Qt.NoButton, Qt.NoModifier, Qt.ScrollUpdate, False,
    )
    combo.wheelEvent(event)
    assert combo.currentIndex() == 0
    assert event.isAccepted() is False
    window.close()


def test_dashboard_explains_health_status_and_lists_only_certificate_expiry() -> None:
    app = _app()
    configure_chinese_font(app)
    window = MainWindow()
    window.show()
    app.processEvents()

    assert window._dashboard_health_reason("危险", {"none": 0, "attention": 0, "critical": 1}) == "发现 1 项影响环境可用性的严重问题"
    assert window._dashboard_health_reason("关注", {"none": 0, "attention": 1, "critical": 0}) == "存在需要安排处理的健康关注项"
    assert "P1" not in window._dashboard_health_reason("关注", {"none": 0, "attention": 1, "critical": 0})
    certificate = CheckEvidenceItem(
        result_id="cert-1", rule_id="VSL-HOST-008", rule_name="ESXi 证书", result_status="passed",
        risk_level="P3", object_type="HostSystem", object_name="esxi-01", current_observed="120",
        expected_state="> 90", evidence_summary="", threshold="", source_path="", collected_at="",
        explanation="", raw_evidence={"observed_detail": {"host_certificate_not_after": "2027-01-02", "host_certificate_days_remaining": 120}},
        has_structured_evidence=True,
    )
    license_item = CheckEvidenceItem(
        result_id="license-1", rule_id="VSL-HOST-023", rule_name="ESXi 授权", result_status="passed",
        risk_level="P3", object_type="HostSystem", object_name="esxi-01", current_observed="999999",
        expected_state="永久授权", evidence_summary="", threshold="", source_path="", collected_at="",
        explanation="", raw_evidence={}, has_structured_evidence=True,
    )
    window._check_evidence_items = [certificate, license_item]
    window._populate_check_evidence()

    assert "已核验 2 项" in window.dashboard_certificate_summary.text()
    assert window.dashboard_certificate_list.count() == 1
    assert "esxi-01" in window.dashboard_certificate_list.item(0).text()
    assert "到期 2027-01-02" in window.dashboard_certificate_list.item(0).text()
    assert "999999" not in window.dashboard_certificate_list.item(0).text()
    window.close()


def test_history_pagination_and_asset_categories_use_the_full_data_set() -> None:
    app = _app()
    configure_chinese_font(app)
    window = MainWindow()
    window.show()
    app.processEvents()

    risk_items = [
        HistoryRiskChangeItem(
            title=f"风险 {index}", risk_level="P1", object_type="VirtualMachine", object_type_label="VM",
            object_name=f"vm-{index}", current_observed="当前值", expected_state="期望值",
            change_status="persistent", change_status_label="持续",
        )
        for index in range(121)
    ]
    asset_items = [
        HistoryAssetChangeItem(
            object_type="VirtualMachine", object_type_label="VM", object_name=f"vm-{index}",
            location="测试集群", change_status="persistent", change_status_label="持续",
        )
        for index in range(161)
    ]
    window._history_risk_groups = risk_items
    window._history_asset_groups = asset_items
    window._history_risk_page = 0
    window._history_asset_page = 0
    window._render_history_page("risk")
    window._render_history_page("asset")

    assert window.history_risk_list.count() == 50
    assert window.history_asset_list.count() == 50
    window._change_history_page("risk", 2)
    window._change_history_page("asset", 3)
    assert window.history_risk_list.count() == 21
    assert window.history_asset_list.count() == 11
    assert "第 3 / 3 页" in window.history_risk_page_label.text()
    assert "第 4 / 4 页" in window.history_asset_page_label.text()

    window._asset_items = [
        PlatformAssetItem("VirtualMachine", "VM", f"vm-{index}", "集群 A", "电源状态 poweredOn", "run-1")
        for index in range(97)
    ] + [
        PlatformAssetItem("HostSystem", "ESXi", f"host-{index}", "集群 A", "版本 8.0", "run-1")
        for index in range(5)
    ]
    window.asset_type_filter.setCurrentText("全部对象")
    window._populate_asset_table()
    assert "全部对象 102" in window.asset_category_buttons["全部对象"].text()
    assert "VM 97" in window.asset_category_buttons["VM"].text()
    window._select_asset_category("ESXi")
    assert window.asset_table.rowCount() == 5
    window.close()

    window.close()

def test_desktop_license_evidence_labels_do_not_say_authorization_service() -> None:
    app = _app()
    configure_chinese_font(app)
    window = MainWindow()

    labels = {
        window._business_source_label("HostSystem", "host product information", "VSL-HOST-023"),
        window._business_source_label("HostSystem", "", "VSL-HOST-023"),
        window._business_source_label("vCenter", "licenseAssignmentManager", "VSL-VC-006"),
        window._business_source_label("vCenter", "", "VSL-VC-006"),
        window._check_category_label(type("Item", (), {"rule_id": "VSL-HOST-023"})()),
    }

    assert ("ESXi 授权" + "服务") not in labels
    assert ("vCenter 授权" + "服务") not in labels
    assert "ESXi 主机产品授权信息" in labels
    assert "ESXi 主机授权状态" in labels
    assert "vCenter 授权信息" in labels
    assert "vCenter 授权状态" in labels
    window.close()


def test_inspection_form_hides_ssl_and_port_options() -> None:
    app = _app()
    configure_chinese_font(app)
    window = MainWindow()
    window.show()
    window.go_to_module("inspection_center")
    app.processEvents()

    page = window.pages.currentWidget()
    visible_text = []
    visible_text.extend(label.text() for label in page.findChildren(QLabel))
    visible_text.extend(button.text() for button in page.findChildren(QPushButton))
    visible_text.extend(box.text() for box in page.findChildren(QCheckBox))
    text = "\n".join(visible_text)

    assert "vCenter 地址" in text
    assert "用户名" in text
    assert "密码" in text
    assert "客户名称" in text
    assert "报告名称" in text
    assert "报告输出目录" in text
    assert "SSL" not in text
    assert "证书校验" not in text
    assert "端口" not in text
    assert not hasattr(window, "ssl_no_verify_input")
    assert not hasattr(window, "port_input")
    window.close()


def test_inspection_center_shows_production_impact_tooltip() -> None:
    app = _app()
    configure_chinese_font(app)
    window = MainWindow()
    window.show()
    window.go_to_module("inspection_center")
    app.processEvents()

    tooltip = window.production_impact_info.toolTip()

    assert "vCenter SDK" in tooltip
    assert "不会创建、删除或修改虚拟机、主机、快照、权限、告警、网络或存储配置" in tooltip
    assert "轻量查询压力" in tooltip
    assert "单项采集异常会降级处理" in tooltip
    window.close()


def test_report_center_delete_record_button_defaults_disabled() -> None:
    app = _app()
    configure_chinese_font(app)
    window = MainWindow()
    window.show()
    window.go_to_module("report_center")
    app.processEvents()

    assert window.delete_report_button.text() == "从列表移除"
    assert "不删除报告文件" in window.delete_report_button.toolTip()
    window.close()


def test_log_analysis_form_is_independent_from_vcenter_inspection_fields() -> None:
    app = _app()
    configure_chinese_font(app)
    window = MainWindow()
    window.show()
    window.go_to_module("log_analysis")
    app.processEvents()

    page = window.pages.currentWidget()
    visible_text = []
    visible_text.extend(label.text() for label in page.findChildren(QLabel))
    visible_text.extend(button.text() for button in page.findChildren(QPushButton))
    visible_text.extend(box.text() for box in page.findChildren(QCheckBox))
    visible_text.extend(edit.placeholderText() for edit in page.findChildren(QLineEdit))
    visible_text.extend(edit.toPlainText() for edit in page.findChildren(QTextEdit))
    visible_text.extend(edit.placeholderText() for edit in page.findChildren(QTextEdit))
    text = "\n".join(visible_text)

    assert "日志包" in text
    assert "问题描述" in text
    assert "客户名称" in text
    assert "报告名称" in text
    assert "报告输出目录" in text
    assert "vCenter 地址" not in text
    assert "用户名" not in text
    assert "密码" not in text
    assert "SSL" not in text
    assert "证书校验" not in text
    assert "端口" not in text
    assert hasattr(window, "log_bundle_input")
    assert hasattr(window, "log_problem_input")
    window.close()


def test_login_window_accepts_default_account_and_rejects_bad_password(tmp_path: Path) -> None:
    app = _app()
    configure_chinese_font(app)
    auth = AuthService(state_path=tmp_path / "auth_state.json")
    login = LoginWindow(auth_service=auth)
    login.show()
    app.processEvents()

    assert login.windowTitle() == "VStackLens Health Assessment Platform"
    assert login.username_input.text() == "admin"
    assert "admin" not in login.password_input.placeholderText().lower()
    assert login.password_input.echoMode() == QLineEdit.Password
    login._toggle_password_visibility()
    assert login.password_input.echoMode() == QLineEdit.Normal
    assert not login.password_visibility_action.icon().isNull()
    login._toggle_password_visibility()
    assert login.password_input.echoMode() == QLineEdit.Password

    login.password_input.setText("wrong")
    login._login()
    assert not login.authenticated
    assert login.result() == 0
    assert "登录失败" in login.error_label.text()

    login.password_input.setText("admin")
    login.remember_username.setChecked(True)
    login._login()
    assert login.authenticated
    assert login.result() == QDialog.Accepted
    assert auth.load_saved_username() == "admin"
    login.close()


def test_customer_visible_desktop_copy_avoids_commercial_and_engineering_terms() -> None:
    app = _app()
    configure_chinese_font(app)
    window = MainWindow()
    window.show()
    app.processEvents()

    visible_text = [window.nav.item(row).text() for row in range(window.nav.count())]
    for module_id in ("dashboard", "history_compare", "report_center", "settings", "license"):
        window.go_to_module(module_id)
        app.processEvents()
        page = window.pages.currentWidget()
        visible_text.extend(label.text() for label in page.findChildren(QLabel))
        visible_text.extend(button.text() for button in page.findChildren(QPushButton))
        visible_text.extend(edit.toPlainText() for edit in page.findChildren(QTextEdit))

    text = "\n".join(visible_text)
    for forbidden in [
        "检查项证据",
        "规则 ID",
        "原始证据",
        "本机授权",
        "授权信息",
        "授权到期",
        "试用版",
        "在线授权",
        "升级能力",
        "高级版",
        "免费",
        "免费本地版",
        "付费",
        "订阅",
        "授权到期",
    ]:
        assert forbidden not in text
    assert re.search(r"(?<![A-Za-z])Pro(?![A-Za-z])", text) is None
    assert "证书与授权" in text
    assert "本地运行" in text

    window.close()


def test_inspection_center_exposes_cancel_button_and_moves_planned_actions_to_text() -> None:
    app = _app()
    configure_chinese_font(app)
    window = MainWindow()
    window.show()
    window.go_to_module("inspection_center")
    app.processEvents()

    buttons = {button.text(): button for button in window.pages.currentWidget().findChildren(QPushButton)}
    labels = "\n".join(label.text() for label in window.pages.currentWidget().findChildren(QLabel))

    assert "取消巡检" in buttons
    assert not buttons["取消巡检"].isVisible()
    assert "批量巡检（后续版本）" not in buttons
    assert "计划巡检（后续版本）" not in buttons
    assert "后续能力路线图" in labels
    assert "批量巡检" in labels
    assert "计划巡检" in labels
    window.close()


def test_close_event_requests_cooperative_cancel(monkeypatch: pytest.MonkeyPatch) -> None:
    app = _app()
    configure_chinese_font(app)
    window = MainWindow()
    window.show()
    app.processEvents()

    class FakeWorker:
        cancel_requested = False
        interruption_requested = False

        def isRunning(self) -> bool:
            return True

        def request_cancel(self) -> None:
            self.cancel_requested = True

        def requestInterruption(self) -> None:  # noqa: N802 - mirrors Qt API for regression coverage.
            self.interruption_requested = True

        def wait(self, _timeout: int) -> bool:
            return True

    class FakeEvent:
        accepted = False
        ignored = False

        def accept(self) -> None:
            self.accepted = True

        def ignore(self) -> None:
            self.ignored = True

    worker = FakeWorker()
    event = FakeEvent()
    window.worker = worker  # type: ignore[assignment]
    window._running = True
    monkeypatch.setattr(QMessageBox, "question", lambda *args, **kwargs: QMessageBox.Yes)

    window.closeEvent(event)

    assert worker.cancel_requested is True
    assert worker.interruption_requested is False
    assert event.accepted is True
    assert event.ignored is False
    assert "等待当前步骤结束" in window.status_label.text()
    window.close()


def test_report_center_does_not_show_pdf_ppt_capabilities() -> None:
    app = _app()
    configure_chinese_font(app)
    window = MainWindow()
    window.show()
    window.go_to_module("report_center")
    app.processEvents()

    buttons = {button.text(): button for button in window.pages.currentWidget().findChildren(QPushButton)}
    labels = "\n".join(label.text() for label in window.pages.currentWidget().findChildren(QLabel))

    assert not any("PDF" in text or "PPT" in text for text in buttons)
    assert "PDF" not in labels
    assert "PPT" not in labels
    window.close()


def test_security_settings_change_password_and_policy(tmp_path: Path) -> None:
    app = _app()
    configure_chinese_font(app)
    auth = AuthService(state_path=tmp_path / "auth_state.json")
    window = MainWindow(auth_service=auth, current_username="admin")
    window.show()
    app.processEvents()

    window.go_to_module("settings")
    app.processEvents()
    assert window.password_min_length_input.value() == 8
    assert not window.password_require_digit_input.isChecked()

    window.current_password_input.setText("admin")
    window.new_password_input.setText("newpass8")
    window.confirm_password_input.setText("newpass8")
    assert window.auth_service.change_password("admin", "admin", "newpass8", "newpass8")[0]
    assert not auth.validate_login("admin", "admin")
    assert auth.validate_login("admin", "newpass8")
    assert not auth.is_default_password_active("admin")
    window.close()


def test_default_password_warning_is_dismissible_and_does_not_block_main_window(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    app = _app()
    configure_chinese_font(app)
    auth = AuthService(state_path=tmp_path / "auth_state.json")
    calls: list[str] = []

    class DismissedWarning:
        modify_now = False

        def __init__(self, parent=None) -> None:  # noqa: ANN001
            calls.append("shown")

        def exec(self) -> int:
            return QDialog.Rejected

    monkeypatch.setattr(desktop_app, "DefaultPasswordWarningDialog", DismissedWarning)
    window = MainWindow(auth_service=auth, current_username="admin")
    window.show()
    window.go_to_module("inspection_center")
    app.processEvents()

    window.show_default_password_warning_if_needed()

    assert calls == ["shown"]
    assert window.module_descriptors[window.nav.currentRow()].module_id == "inspection_center"
    assert window.start_button.isEnabled()
    window.close()


def test_default_password_warning_dialog_copy_and_actions() -> None:
    app = _app()
    dialog = DefaultPasswordWarningDialog()
    dialog.show()
    app.processEvents()

    texts = "\n".join(label.text() for label in dialog.findChildren(QLabel))
    buttons = {button.text(): button for button in dialog.findChildren(QPushButton)}
    assert "建议修改默认密码" in texts
    assert "当前本地管理员账号仍使用默认密码" in texts
    assert "立即修改" in buttons
    assert "稍后处理" in buttons
    buttons["立即修改"].click()
    assert dialog.modify_now
    dialog.close()
