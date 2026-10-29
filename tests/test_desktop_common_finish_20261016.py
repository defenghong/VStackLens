"""Small native-control regressions; no services or customer database."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QButtonGroup, QCheckBox, QRadioButton, QStyle, QStyleOptionButton

from vstacklens.desktop import theme


def _indicator_image(control, element):
    option = QStyleOptionButton()
    control.initStyleOption(option)
    rect = control.style().subElementRect(element, option, control)
    return control.grab(rect).toImage()


def _color_count(image, value):
    color = QColor(value)
    return sum(image.pixelColor(x, y).rgb() == color.rgb()
               for y in range(image.height()) for x in range(image.width()))


def test_checked_indicator_contains_explicit_tick_in_both_themes():
    app = QApplication.instance()
    checkbox = QCheckBox("Remember username")
    checkbox.setChecked(True)
    checkbox.resize(240, 34)
    checkbox.show()
    for choice in ("light", "dark", "light"):
        theme.apply_application_theme(app, choice)
        app.processEvents()
        checked = _indicator_image(checkbox, QStyle.SE_CheckBoxIndicator)
        assert _color_count(checked, theme.COLORS["primary"]) > 30
        # A solid green rectangle cannot satisfy this visible white tick check.
        assert _color_count(checked, theme.COLORS["button_text"]) >= 4
        checkbox.setEnabled(False)
        app.processEvents()
        disabled = _indicator_image(checkbox, QStyle.SE_CheckBoxIndicator)
        assert _color_count(disabled, theme.COLORS["subtext"]) > 30
        assert checked != disabled
        checkbox.setEnabled(True)
    checkbox.close()


def test_theme_switch_preserves_native_check_radio_and_keyboard_behavior():
    app = QApplication.instance()
    theme.apply_application_theme(app, "light")
    installed = app._vstacklens_control_style
    checkbox = QCheckBox("Remember username")
    checkbox.show()
    transitions = []
    checkbox.toggled.connect(transitions.append)
    checkbox.setFocus()
    QTest.keyClick(checkbox, Qt.Key_Space)
    assert checkbox.isChecked()
    group = QButtonGroup()
    first, second = QRadioButton("First"), QRadioButton("Second")
    group.addButton(first)
    group.addButton(second)
    first.setChecked(True)
    for choice in ("dark", "light", "dark", "light"):
        theme.apply_application_theme(app, choice)
        app.processEvents()
        assert app._vstacklens_control_style is installed
        assert checkbox.isChecked() and first.isChecked()
    second.click()
    assert second.isChecked() and not first.isChecked()
    QTest.keyClick(checkbox, Qt.Key_Space)
    assert transitions == [True, False]
    checkbox.setEnabled(False)
    QTest.keyClick(checkbox, Qt.Key_Space)
    assert not checkbox.isChecked()
    checkbox.close()
