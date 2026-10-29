from __future__ import annotations
import time
from pathlib import Path
import pytest

from test_stage3_batch_inspection import setup
from vstacklens.application.inspection_service import DesktopInspectionConfig
from vstacklens.desktop.app import MainWindow, configure_chinese_font
from vstacklens.desktop.tray_runtime import CloseChoiceDialog
from PySide6.QtCore import Qt, QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QDialog, QLineEdit


@pytest.fixture
def window(setup, qt_application_lifetime):
    single, batch, settings, ids, credentials, controls = setup
    single.save_config(DesktopInspectionConfig(db_path=settings.db_path, report_output_dir=settings.report_output_dir, rulepack_path=settings.rulepack_path))
    configure_chinese_font(qt_application_lifetime)
    widget = MainWindow(service=single); widget.batch_service_factory = batch.service_factory
    widget.show(); qt_application_lifetime.processEvents(); widget._open_plans()
    yield widget, setup, qt_application_lifetime
    widget._begin_exit()
    deadline = time.monotonic() + 15
    while not widget._exit_ready and time.monotonic() < deadline:
        qt_application_lifetime.processEvents(); time.sleep(.01)
    assert widget._exit_ready and not widget._active_workers()


def create_plan(window):
    widget, (_, _, _, _, credentials, _), app = window
    widget._new_plan(); widget.plan_name.setText("离线客户含很长名称的每周标准巡检计划" * 3)
    widget.plan_editor_tabs.setCurrentIndex(1); app.processEvents()
    for row in range(widget.plan_targets.rowCount()):
        cell = widget.plan_targets.item(row, 0)
        QTest.mouseClick(widget.plan_targets.viewport(), Qt.LeftButton, pos=widget.plan_targets.visualItemRect(cell).center())
        assert cell.checkState() == Qt.Checked
    widget.plan_frequency.setCurrentIndex(1); widget.plan_weekdays[1].setChecked(True)
    widget.plan_save_button.click(); assert widget._edit_plan_id
    return widget._edit_plan_id


def authorize(window):
    widget, (_, _, _, _, credentials, _), app = window
    for row, env in enumerate(widget._plan_profiles):
        widget.plan_targets.cellWidget(row, 3).setText(credentials[env.environment_id].username)
        widget.plan_targets.cellWidget(row, 4).setText(credentials[env.environment_id].password)
        assert widget.plan_targets.cellWidget(row, 4).echoMode() == QLineEdit.Password
    widget.plan_consent.setChecked(True); widget.plan_authorize_button.click()
    assert all(not widget.plan_targets.cellWidget(r, 4).text() for r in range(widget.plan_targets.rowCount()))


def test_actual_plan_editor_requires_explicit_separate_session_grant(window):
    widget, (_, _, _, _, _, controls), app = window
    sid = create_plan(window)
    widget.password_input.setText("single-form-must-not-be-used")
    widget.plan_authorize_button.click()
    assert sid not in widget._plan_manager._grants
    assert not widget.plan_authorize_button.isEnabled()
    assert "勾选" in widget.plan_editor_status.text()
    authorize(window)
    assert sid in widget._plan_manager._grants
    assert widget.password_input.text() == "single-form-must-not-be-used"
    assert not controls["calls"]
    widget._revoke_plan(); assert not widget._plan_manager._grants


def test_actual_close_choice_dialog_defaults_to_not_remembering(qt_application_lifetime):
    dialog = CloseChoiceDialog(tray_available=True); dialog.show(); qt_application_lifetime.processEvents()
    assert not dialog.remember.isChecked()
    QTest.mouseClick(dialog.tray_button, Qt.LeftButton)
    assert dialog.result() == QDialog.Accepted and dialog.choice == "tray" and not dialog.remember.isChecked()
    dialog.deleteLater()
    second = CloseChoiceDialog(tray_available=False); second.show(); qt_application_lifetime.processEvents()
    assert not second.tray_button.isEnabled()
    second.remember.setChecked(True); QTest.mouseClick(second.exit_button, Qt.LeftButton)
    assert second.choice == "exit" and second.remember.isChecked()
    second.deleteLater()


def test_unsaved_form_change_is_not_silently_authorized(window):
    widget, _, _ = window
    sid = create_plan(window); widget.plan_name.setText("尚未保存的修改")
    authorize(window)
    assert sid not in widget._plan_manager._grants
    assert "先保存" in widget.plan_editor_status.text()


def test_no_tray_never_hides_window_and_does_not_remember_default(window, monkeypatch):
    widget, _, app = window
    monkeypatch.setattr(widget, "_tray_available", lambda: False)
    monkeypatch.setattr(widget, "_choose_close_action", lambda: ("tray", False))
    widget.close(); app.processEvents()
    assert widget.isVisible() and not widget._batch_closing
    assert widget._read_close_choice() == "ask"
    assert "托盘不可用" in widget.status_label.text()


def test_tray_hide_restore_and_pause_keep_runtime_alive(window, monkeypatch):
    widget, _, app = window
    sid = create_plan(window); authorize(window)
    monkeypatch.setattr(widget, "_tray_available", lambda: True)
    monkeypatch.setattr(widget, "_choose_close_action", lambda: ("tray", True))
    widget.close(); app.processEvents()
    assert not widget.isVisible() and widget._plan_timer.isActive()
    assert widget._read_close_choice() == "tray" and sid in widget._plan_manager._grants
    widget._restore_from_tray(); app.processEvents(); assert widget.isVisible()
    # Exercise actions even with an offscreen test platform's unavailable native tray.
    from PySide6.QtGui import QAction
    widget._tray_pause = QAction(widget); widget._tray_status = QAction(widget)
    widget._tray_toggle_plans(); assert widget._plan_manager.paused
    widget._tray_toggle_plans(); assert not widget._plan_manager.paused
    widget.close_choice_combo.setCurrentIndex(widget.close_choice_combo.findData("ask")); widget._save_close_choice()
    assert widget._read_close_choice() == "ask"
    assert "已保存" in widget.close_choice_feedback.text()


def test_qt_planned_execution_preserves_single_form_scope_and_waits_for_exit(window):
    widget, (_, _, settings, ids, credentials, controls), app = window
    sid = create_plan(window); authorize(window)
    widget._plan_timer.stop()
    from test_stage4_scheduled_inspection import Clock
    clock = Clock(); manager = widget._plan_manager
    manager.clock = clock.now; manager.monotonic = clock.monotonic
    manager._last_wall, manager._last_mono = clock.now(), clock.monotonic()
    plan = manager.save_plan(name="实时离线线程验证", environment_ids=ids, settings=settings, local_time="09:00")
    manager.authorize(plan["schedule_id"], credentials, consent=True); manager.tick()
    widget.vcenter_input.setText("single-form-preserved"); widget._environment_id = ids[1]
    controls["behaviors"]["192.0.2.10"] = "block"
    clock.advance(2); widget._plan_timer_tick()
    deadline = time.monotonic() + 12
    while not controls["started"].is_set() and time.monotonic() < deadline:
        app.processEvents(); time.sleep(.01)
    assert controls["started"].is_set() and widget.plan_worker is not None
    assert widget.vcenter_input.text() == "single-form-preserved" and widget._environment_id == ids[1]
    widget._begin_exit()
    while not widget._exit_ready and time.monotonic() < deadline + 10:
        app.processEvents(); time.sleep(.01)
    assert widget._exit_ready and not widget._active_workers()
    assert len(controls["calls"]) == 1 and not manager._grants and not manager.batch._credentials
    before = widget.plan_status.text()
    widget._planned_progress({"unusable": "late-callback"})
    widget._plan_runtime_error("late failure")
    assert widget.plan_status.text() == before


def test_exit_before_queued_callback_cleans_unstarted_plan_without_collection(window):
    widget, (_, _, settings, ids, credentials, controls), app = window
    widget._plan_timer.stop(); manager = widget._plan_manager
    from test_stage4_scheduled_inspection import Clock
    clock = Clock(); manager.clock = clock.now; manager.monotonic = clock.monotonic
    manager._last_wall, manager._last_mono = clock.now(), clock.monotonic()
    plan = manager.save_plan(name="未启动回调", environment_ids=ids, settings=settings)
    manager.authorize(plan["schedule_id"], credentials, consent=True); manager.tick(); clock.advance(2)
    trigger = manager.tick(); assert trigger
    widget._begin_exit(); widget._plan_triggered(trigger); app.processEvents()
    assert widget._exit_ready and widget.plan_worker is None and not controls["calls"]
    assert not manager.batch._credentials and not manager._grants


def test_125_percent_equivalent_editor_has_visible_credential_row_and_consent(window):
    widget, _, app = window
    widget.resize(1093,614); create_plan(window); app.processEvents()
    assert widget.plan_targets.viewport().height() >= widget.plan_targets.rowHeight(0)
    assert widget.plan_targets.columnViewportPosition(4) + widget.plan_targets.columnWidth(4) <= widget.plan_targets.viewport().width() + 3
    assert widget.plan_consent.isVisible() and widget.plan_authorize_button.isVisible()
    assert not widget.plan_authorize_button.isEnabled()
    assert not widget.plan_targets.wordWrap()


def test_unreadable_close_setting_falls_back_to_explicit_choice(window, monkeypatch):
    widget, _, _ = window
    import sqlite3
    from vstacklens.db.schedule_store import ScheduleStore
    monkeypatch.setattr(ScheduleStore, "exists", lambda path: (_ for _ in ()).throw(sqlite3.DatabaseError("offline unreadable settings")))
    assert widget._read_close_choice() == "ask"
    assert "明确选择" in widget.status_label.text()


def test_opening_blank_editor_and_saving_prompts_without_crashing(window):
    widget, _, app = window
    widget.plan_tabs.setCurrentIndex(1); app.processEvents()
    widget.plan_save_button.click()
    assert "计划名称" in widget.plan_editor_status.text()
    assert not widget._plan_manager.store.plans()
