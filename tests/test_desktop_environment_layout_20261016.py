"""Small, database-free regressions for the environment list and on-demand windows."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QWidget, QVBoxLayout, QTableWidget, QHeaderView, QScrollArea

from vstacklens.desktop.environment_archive import EnvironmentArchiveMixin


class ArchiveHarness(EnvironmentArchiveMixin, QWidget):
    def __init__(self, rows, histories=None):
        super().__init__()
        self._running = False
        self._inspection_environment_id = None
        self._archive_selected_id = None
        self.rows = rows
        self.histories = histories or {}
        self.history_queries = []
        self.service = SimpleNamespace(
            list_environment_archives=lambda _db: self.rows,
            list_report_history=self._history_for_environment,
            desktop_report_formats=lambda _db, _run_id: ["HTML"],
            list_environment_customers=lambda _db: [],
        )
        QVBoxLayout(self).addWidget(self._environment_archive_page())
        self._populate_vcenter_center()

    def _history_for_environment(self, _db, *, environment_id):
        self.history_queries.append(environment_id)
        return self.histories.get(environment_id, [])

    def _short_task(self, run_id):
        return run_id

    def _run_status_text(self, status):
        return status

    def _db_path(self):
        return Path("nonexistent-isolated-environment-layout.db")

    def _prepare_table(self, widget):
        widget.setSelectionBehavior(QTableWidget.SelectRows)
        widget.setEditTriggers(QTableWidget.NoEditTriggers)
        widget.verticalHeader().setVisible(False)
        widget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)


def archive_rows(count=40):
    return [SimpleNamespace(environment_id=f"env-{index:02d}", name=f"环境-{index:02d}",
        customer_name="隔离模拟客户", customer_id="customer-only", site_name="模拟站点", address=f"192.0.2.{index + 1}",
        username="offline-only", last_collected_at="", collection_result="尚无巡检记录", report_result="尚无报告",
        enabled=True, task_count=0) for index in range(count)]


def test_environment_list_grows_without_outer_scroll_or_inline_details(qt_application_lifetime):
    app = qt_application_lifetime
    window = ArchiveHarness(archive_rows())
    window.resize(1000, 520); window.show(); app.processEvents()
    small = window.environment_table.height()
    window.resize(1000, 780); app.processEvents()
    assert window.environment_table.height() >= small + 220
    assert window.environment_table.maximumHeight() == 16777215
    assert not isinstance(window.environment_archive_page, QScrollArea)
    assert not window.environment_editor_dialog.isVisible()
    assert not window.environment_history_dialog.isVisible()
    window.close()


def test_sorted_selection_and_scroll_survive_detail_windows_and_refresh(qt_application_lifetime):
    app = qt_application_lifetime
    window = ArchiveHarness(archive_rows())
    window.resize(860, 550); window.show(); app.processEvents()
    table = window.environment_table
    table.sortItems(0, Qt.DescendingOrder)
    table.setCurrentCell(20, 0); table.verticalScrollBar().setValue(11)
    table.horizontalScrollBar().setValue(70); app.processEvents()
    selected = table.item(20, 0).data(Qt.UserRole)
    assert window._selected_environment().environment_id == selected
    state = (table.verticalScrollBar().value(), table.horizontalScrollBar().value(), table.height())
    window._show_environment_history(); app.processEvents()
    assert window.environment_history_dialog.isVisible()
    assert window.environment_history_empty.isVisible()
    window.environment_history_dialog.close(); app.processEvents()
    window._edit_selected_environment(); app.processEvents()
    assert window._archive_edit_id == selected
    window._hide_environment_editor(); app.processEvents()
    assert (table.verticalScrollBar().value(), table.horizontalScrollBar().value(), table.height()) == state
    window._populate_vcenter_center(); app.processEvents()
    assert window._selected_environment().environment_id == selected
    assert table.horizontalHeader().sortIndicatorOrder() == Qt.DescendingOrder
    assert (table.verticalScrollBar().value(), table.horizontalScrollBar().value()) == state[:2]
    window.close()


def test_editor_controls_keep_draft_and_owner_close_hides_windows(qt_application_lifetime):
    app = qt_application_lifetime
    window = ArchiveHarness(archive_rows())
    window.resize(1100, 650); window.show(); app.processEvents()
    window._edit_selected_environment(); app.processEvents()
    editor = window.environment_name_input
    editor.setText("尚未保存的隔离草稿")
    window.environment_username_input.setText("another-offline-account")
    window.resize(900, 540); window._show_environment_history(); app.processEvents()
    window.environment_history_dialog.close(); app.processEvents()
    assert window.environment_name_input is editor
    assert editor.text() == "尚未保存的隔离草稿"
    assert window.environment_username_input.text() == "another-offline-account"
    assert not hasattr(window, "environment_password_input")
    window.close(); app.processEvents()
    assert not window.environment_editor_dialog.isVisible()
    assert not window.environment_history_dialog.isVisible()


def test_empty_archive_keeps_registration_and_disables_selection_actions(qt_application_lifetime):
    window = ArchiveHarness([])
    window.resize(900, 540); window.show(); qt_application_lifetime.processEvents()
    assert window.environment_empty.isVisible()
    assert not window.environment_table.isVisible()
    assert not window.environment_edit_button.isEnabled()
    assert not window.environment_history_button.isEnabled()
    assert all(not control.isEnabled() for control in window.environment_links.values())
    header = window.environment_archive_page.layout().itemAt(0).widget()
    empty_positions = (header.y(), window.environment_edit_button.y())
    assert window.environment_empty.height() > window.environment_archive_page.height() / 2
    assert window.environment_empty.alignment() & Qt.AlignTop
    window.rows = archive_rows(); window._populate_vcenter_center(); qt_application_lifetime.processEvents()
    assert (header.y(), window.environment_edit_button.y()) == empty_positions
    window._edit_environment(None); qt_application_lifetime.processEvents()
    assert window.environment_editor_dialog.isVisible()
    assert window.environment_name_input.isVisible()
    window.close()


def history_rows(rows):
    return {env.environment_id: [SimpleNamespace(run_id=f"mock-task-{env.environment_id}",
        started_at="2026-10-16T00:00:00Z", updated_at="2026-10-16T00:00:00Z", run_status="completed")]
        for env in rows}


def select_environment(window, environment_id):
    table = window.environment_table
    row = next(row for row in range(table.rowCount())
               if table.item(row, 0).data(Qt.UserRole) == environment_id)
    table.setCurrentCell(row, 0)


def assert_history_environment(window, env):
    assert window._selected_environment().environment_id == env.environment_id
    assert window.history_queries[-1] == env.environment_id
    assert window.environment_history_dialog.windowTitle() == f"环境历史任务 · {env.name}"
    assert window.environment_history_scope.text().startswith(
        f"{env.name} · {env.customer_name} / {env.site_name} · {env.address}\n")
    assert window.environment_tasks.rowCount() == 1
    assert window.environment_tasks.item(0, 0).text() == f"mock-task-{env.environment_id}"
    assert window.environment_tasks.item(0, 3).text() == "HTML"


def test_history_follows_selected_environment_without_reopening(qt_application_lifetime):
    app = qt_application_lifetime
    rows = archive_rows(2)
    window = ArchiveHarness(rows, history_rows(rows))
    window.resize(1000, 650); window.show(); app.processEvents()
    select_environment(window, rows[0].environment_id)
    window._show_environment_history(); app.processEvents()
    dialog = window.environment_history_dialog
    assert dialog.isVisible() and not dialog.isModal()
    assert_history_environment(window, rows[0])
    select_environment(window, rows[1].environment_id); app.processEvents()
    assert window.environment_history_dialog is dialog and dialog.isVisible()
    assert_history_environment(window, rows[1])
    window.close()


@pytest.mark.parametrize("same_name,same_address", [(True, False), (False, True), (True, True)],
                         ids=["same-name", "same-address", "same-name-and-address"])
def test_history_identity_uses_stable_id_for_different_customers(qt_application_lifetime, same_name, same_address):
    app = qt_application_lifetime
    rows = archive_rows(2)
    for index, env in enumerate(rows):
        env.customer_id = f"mock-customer-{index}"
        env.customer_name = f"隔离客户-{index}"
        if same_name: env.name = "同名生产环境"
        if same_address: env.address = "192.0.2.250"
    window = ArchiveHarness(rows, history_rows(rows))
    window.resize(1000, 650); window.show(); app.processEvents()
    select_environment(window, rows[0].environment_id)
    window._show_environment_history(); app.processEvents()
    assert_history_environment(window, rows[0])
    select_environment(window, rows[1].environment_id); app.processEvents()
    assert_history_environment(window, rows[1])
    assert rows[0].customer_name not in window.environment_history_scope.text()
    select_environment(window, rows[0].environment_id); app.processEvents()
    assert_history_environment(window, rows[0])
    window.close()


def test_sorted_history_switch_and_reopen_preserve_main_list_state(qt_application_lifetime):
    app = qt_application_lifetime
    rows = archive_rows()
    window = ArchiveHarness(rows, history_rows(rows))
    window.resize(860, 550); window.show(); app.processEvents()
    table = window.environment_table
    table.sortItems(0, Qt.DescendingOrder)
    select_environment(window, rows[20].environment_id)
    table.verticalScrollBar().setValue(11); table.horizontalScrollBar().setValue(70)
    window._show_environment_history(); app.processEvents()
    assert_history_environment(window, rows[20])
    select_environment(window, rows[19].environment_id); app.processEvents()
    assert_history_environment(window, rows[19])
    state = (window._selected_environment().environment_id, table.horizontalHeader().sortIndicatorSection(),
             table.horizontalHeader().sortIndicatorOrder(), table.verticalScrollBar().value(),
             table.horizontalScrollBar().value())
    window.environment_history_dialog.close(); app.processEvents()
    window._show_environment_history(); app.processEvents()
    assert window.environment_history_dialog.isVisible()
    assert_history_environment(window, rows[19])
    assert (window._selected_environment().environment_id, table.horizontalHeader().sortIndicatorSection(),
            table.horizontalHeader().sortIndicatorOrder(), table.verticalScrollBar().value(),
            table.horizontalScrollBar().value()) == state
    window.close()


@pytest.mark.parametrize("clear_mode", ["no-current-item", "empty-archives"])
def test_history_without_current_environment_clears_and_hides_old_display(qt_application_lifetime, clear_mode):
    app = qt_application_lifetime
    rows = archive_rows(2)
    window = ArchiveHarness(rows, history_rows(rows))
    window.resize(1000, 650); window.show(); app.processEvents()
    window._show_environment_history(); app.processEvents()
    assert_history_environment(window, rows[0])
    if clear_mode == "no-current-item":
        window.environment_table.setCurrentCell(-1, -1)
    else:
        window.rows = []; window._populate_vcenter_center()
    app.processEvents()
    assert window._selected_environment() is None
    assert window.environment_history_dialog.windowTitle() == "环境历史任务"
    assert window.environment_history_scope.text() == ""
    assert window.environment_tasks.rowCount() == 0
    assert not window.environment_tasks.isVisible()
    assert not window.environment_history_dialog.isVisible()
    assert not window.environment_history_button.isEnabled()
    window._show_environment_history(); app.processEvents()
    assert not window.environment_history_dialog.isVisible()
    window.close()
