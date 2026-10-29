from __future__ import annotations

import os
import pytest

from PySide6.QtWidgets import QApplication, QPushButton, QScrollArea, QHBoxLayout
from PySide6.QtGui import QColor

from vstacklens.desktop.theme import COLORS, DARK, LIGHT, apply_application_theme, current_stylesheet, current_theme, color_with_alpha
from vstacklens.desktop.widgets import MetricValueLabel, SectionCard, risk_badge, status_badge


def _application() -> QApplication:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    app = QApplication.instance() or QApplication(["theme-test", "-platform", "offscreen"])
    apply_application_theme(app, "dark")
    return app


def test_status_text_survives_updates_and_risk_has_its_own_semantics() -> None:
    app = _application()
    status = status_badge("unknown", "等待连接")
    status.setText("连接成功")
    status.setProperty("status", "success")
    status.resize(120, 32)
    status.show()
    app.processEvents()
    assert status.text() == "连接成功"
    assert status.property("badgeType") == "status"
    assert not status.grab().isNull()
    risk = risk_badge("P4")
    assert risk.text() == "优化建议"
    assert risk.property("riskLevel") == "P4"
    assert risk.property("badgeType") == "risk"
    status.close()


def test_metric_zero_style_tracks_refresh_without_changing_values() -> None:
    app = _application()
    metric = MetricValueLabel("0")
    metric.setObjectName("metricValue")
    assert metric.property("zero") is True
    metric.setText("12")
    assert metric.text() == "12"
    assert metric.property("zero") is False
    metric.setText("0")
    assert metric.property("zero") is True
    metric.show()
    app.processEvents()
    assert metric.palette().color(metric.foregroundRole()).name().upper() == COLORS["subtext"]
    metric.close()


def test_dark_is_default_both_palettes_match_and_cards_have_no_shadow() -> None:
    _application()
    assert current_theme() == "dark"
    assert COLORS == DARK
    assert DARK.keys() == LIGHT.keys()
    assert SectionCard("测试卡片").graphicsEffect() is None
    assert "${" not in current_stylesheet()
    assert DARK["danger"] == DARK["P1"]
    assert DARK["warning"] == DARK["P2"]
    translucent = QColor(color_with_alpha("P3", 42))
    assert translucent.isValid()
    assert translucent.alpha() == 42


def test_zero_count_retains_size_and_uses_normal_weight() -> None:
    app = _application()
    metric = MetricValueLabel("12")
    metric.setObjectName("metricValue")
    metric.show()
    app.processEvents()
    normal_size = metric.font().pixelSize(), metric.font().pointSizeF()
    normal_weight = metric.font().weight()
    metric.setText("0")
    app.processEvents()
    assert (metric.font().pixelSize(), metric.font().pointSizeF()) == normal_size
    assert normal_weight == 700
    assert metric.font().weight() == 400
    metric.close()


@pytest.mark.parametrize("theme_name", ("dark", "light"))
def test_risk_labels_use_level_background_and_white_text(theme_name: str) -> None:
    app = _application()
    apply_application_theme(app, theme_name)
    for level in ("P1", "P2", "P3", "P4"):
        badge = risk_badge(level)
        badge.resize(120, 32)
        badge.show()
        app.processEvents()
        assert badge.palette().color(badge.foregroundRole()).name().upper() == COLORS["button_text"]
        # Sample solid interior away from the text and rounded corners.
        assert badge.grab().toImage().pixelColor(5, 16).name().upper() == COLORS[level]
        badge.close()


def test_primary_and_link_text_have_the_requested_colors() -> None:
    app = _application()
    for name, expected in (("primaryButton", "button_text"), ("quietButton", "text")):
        button = QPushButton("测试操作")
        button.setObjectName(name)
        button.show()
        app.processEvents()
        assert button.palette().color(button.foregroundRole()).name().upper() == COLORS[expected]
        button.close()


def test_inspection_small_window_uses_scroll_instead_of_squeezing_fields() -> None:
    from vstacklens.desktop.app import MainWindow
    app = _application()
    window = MainWindow()
    window._open_standard_inspection()
    window.resize(1366, 675)
    window.show()
    app.processEvents()
    page = window.inspection_pages.currentWidget()
    assert isinstance(page, QScrollArea)
    assert page.horizontalScrollBar().maximum() == 0
    assert window.standard_columns.direction() == QHBoxLayout.TopToBottom
    for field in (window.vcenter_input, window.username_input, window.report_title_input):
        assert field.width() >= 240
    for button in (window.open_report_button, window.open_word_button, window.open_pdf_button):
        assert button.width() >= button.sizeHint().width()
    window.close()
