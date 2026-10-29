from pathlib import Path
import os
from PySide6.QtCore import Qt
from PySide6.QtGui import QRawFont, QFont
from PySide6.QtWidgets import QApplication, QLabel
from vstacklens.desktop.app import configure_chinese_font
from vstacklens.desktop.theme import TYPOGRAPHY, SIZES, apply_application_theme, COLORS
from vstacklens.desktop.widgets import MetricValueLabel, PageHeader, risk_badge
from vstacklens.desktop.navigation_icons import PATHS, navigation_icon
from test_desktop_layout3a import window_for
import pytest

def test_real_bold_face_and_pixel_size_are_used():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    app = QApplication.instance() or QApplication(["visual-alignment", "-platform", "offscreen"])
    configure_chinese_font(app); apply_application_theme(app, "dark")
    assert app.font().pixelSize() == TYPOGRAPHY["body"]
    for name, size in (("pageTitle", TYPOGRAPHY["page_title"]), ("dashboardHealthValue", TYPOGRAPHY["health"]), ("largeNumber", TYPOGRAPHY["number"])):
        label = QLabel("危险 31"); label.setObjectName(name); label.ensurePolished()
        assert label.font().pixelSize() == size
        assert label.font().weight() == QFont.Bold
        if Path(r"C:\Windows\Fonts\msyhbd.ttc").exists():
            raw = QRawFont.fromFont(label.font())
            assert int.from_bytes(bytes(raw.fontTable("OS/2"))[4:6], "big") >= 700

def test_priority_zero_keeps_size_but_uses_normal_weight_in_both_themes():
    app = QApplication.instance() or QApplication([])
    for theme in ("dark", "light"):
        apply_application_theme(app, theme)
        label = MetricValueLabel("8"); label.setObjectName("metricValue"); label.ensurePolished()
        assert label.font().pixelSize() == TYPOGRAPHY["priority_number"] and label.font().weight() == QFont.Bold
        original_size=label.font().pixelSize()
        label.setText("0"); label.ensurePolished()
        assert label.font().pixelSize() == original_size and label.font().weight() == QFont.Normal
        assert label.palette().color(label.foregroundRole()).name().upper() == COLORS["subtext"]
        sizes = [risk_badge(level).size() for level in ("P1", "P2", "P3")]
        assert all(s.width() == SIZES["badge_width"] and s.height() == SIZES["badge_height"] for s in sizes)
    apply_application_theme(app, "dark")

def test_small_window_navigation_icons_and_inline_subtitle(tmp_path):
    app, window = window_for(tmp_path)
    try:
        window.resize(1366, 696); app.processEvents(); window._resize_navigation(); app.processEvents()
        assert window.nav.verticalScrollBar().maximum() == 0
        assert len(PATHS) == 11
        for index in range(window.nav.count()):
            item = window.nav.item(index)
            if item.data(Qt.UserRole):
                assert not item.icon().isNull()
                assert min(40,SIZES["navigation_compact"]) <= item.sizeHint().height() <= SIZES["navigation_row"]
                assert window.nav.font().pixelSize() == TYPOGRAPHY["navigation"]
        header = PageHeader("首页", "先查看基础结果")
        assert header.title_row.indexOf(header.subtitle_label) == 2
        assert navigation_icon("dashboard", False).pixmap(18,18).toImage() != navigation_icon("dashboard", True).pixmap(18,18).toImage()
        window.go_to_module("risk_center"); app.processEvents()
        assert window.risk_list.horizontalHeader().height() == SIZES["table_header"]
        assert window.risk_list.horizontalScrollBar().maximum() == 0
    finally: window.close()

@pytest.mark.parametrize("size",[(1586,992),(1707,889)])
def test_home_primary_content_and_reports_remain_reachable(tmp_path, size):
    from PySide6.QtWidgets import QScrollArea
    from vstacklens.desktop.app import MainWindow
    from test_desktop_theme_switch import _app, make_service, settle_qt
    app = _app()
    service = make_service(tmp_path, "light", with_data=True)
    window = MainWindow(service=service, auth_service=service.theme_test_auth)
    window._plan_timer.stop(); window.resize(*size); window.show(); settle_qt(app)
    try:
        pane = window.pages.currentWidget()
        assert isinstance(pane, QScrollArea)
        assert pane.horizontalScrollBar().maximum() == 0
        assert pane.viewport().rect().intersects(window.conclusion_card.geometry())
        assert window.dashboard_issues.rowCount() == len(window._overview.customer_caliber["categories"])
        assert window.dashboard_problem_total.values[0].text() == "3"
        assert window.dashboard_problem_total.values[1].text() == "3"
        # Supplementary content may be below the fold; it must remain reachable.
        pane.ensureWidgetVisible(window.dashboard_recent_card)
        settle_qt(app)
        top = window.dashboard_recent_card.mapTo(pane.viewport(), window.dashboard_recent_card.rect().topLeft())
        assert top.y() < pane.viewport().height()
        assert top.y() + window.dashboard_recent_card.height() > 0
        assert window.dashboard_scope_label.font().pixelSize() == TYPOGRAPHY["secondary"]
    finally:
        window._begin_exit(); settle_qt(app)
        assert window._exit_ready and not window._active_workers()


def test_category_unit_uses_current_caliber_objects_without_recounting():
    from vstacklens.desktop.layout3a import Layout3aMixin
    mixed={"affected_object_count":7,"affected_objects":[{"object_type":"HostSystem"},{"object_type":"VirtualMachine"}]}
    assert Layout3aMixin._category_objects(None,mixed)=="7 个对象"
    single={"affected_object_count":9,"affected_objects":[{"object_type":"VirtualMachine"}]}
    assert Layout3aMixin._category_objects(None,single)=="9 台虚拟机"
