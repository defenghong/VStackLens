"""Product result rows follow settled viewport widths; no live devices or large HCL."""
from copy import deepcopy

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, Qt
from PySide6.QtTest import QTest
from shiboken6 import isValid

from test_product_desktop import product_window
from test_product_management_ui import save_management
from vstacklens.products import store


def settle(app):
    for _ in range(4):
        app.processEvents()
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        QTest.qWait(15)


def seed(db, target_id, product, *, long=False):
    run_id = 'row-height-ui-' + product
    module = save_management(db, target_id, run_id, product)
    if long:
        module['target_name'] = '同一客户管理控制器的长名称-' * 4
        module['checks'][1]['title'] = '管理服务及覆盖限制必须完整保留中文长名称与证据说明，' * 12
        store.save_module(db, run_id, module)
    return run_id, deepcopy(store.load_run(db, run_id))


def assert_current_rows(table):
    assert table.isVisible() and table.viewport().width() > 800
    assert [table.rowHeight(i) for i in range(table.rowCount())] == [
        max(table.verticalHeader().minimumSectionSize(), table.sizeHintForRow(i)) for i in range(table.rowCount())
    ], 'Rows retained a hidden or previous-width height instead of current content height'


@pytest.mark.parametrize('hidden_load', [False, True])
def test_first_avi_results_remeasure_after_page_show(product_window, qt_application_lifetime, hidden_load):
    w, db, ids = product_window
    run_id, original = seed(db, ids['avi'], 'avi')
    w.resize(1366, 768)
    if hidden_load:
        w.go_to_module('dashboard')
        w.product_result_target.setCurrentIndex(w.product_result_target.findData(ids['avi']))
        w._populate_product_result_runs()
        assert not w.product_result_table.isVisible()
    w._show_product_results(target_id=ids['avi'], run_id=run_id)
    settle(qt_application_lifetime)
    assert_current_rows(w.product_result_table)
    assert store.load_run(db, run_id) == original


def test_long_rows_grow_and_shrink_on_real_window_resize(product_window, qt_application_lifetime):
    w, db, ids = product_window
    run_id, original = seed(db, ids['avi'], 'avi', long=True)
    w.resize(1366, 768); w._show_product_results(target_id=ids['avi'], run_id=run_id)
    settle(qt_application_lifetime)
    table = w.product_result_table
    assert_current_rows(table)
    narrow = table.rowHeight(1)
    short = table.rowHeight(0)
    assert narrow > short * 2
    title = table.item(1, 1).text()
    w.resize(1920, 1080); settle(qt_application_lifetime)
    assert_current_rows(table)
    wide = table.rowHeight(1)
    assert short < wide < narrow
    w.resize(1366, 768); settle(qt_application_lifetime)
    assert_current_rows(table)
    assert table.rowHeight(1) == narrow and table.item(1, 1).text() == title
    assert store.load_run(db, run_id) == original


def test_refresh_and_product_switch_preserve_current_check_and_scroll(product_window, qt_application_lifetime):
    w, db, ids = product_window
    avi_run, original = seed(db, ids['avi'], 'avi', long=True)
    nsx_run, _ = seed(db, ids['a'], 'nsx')
    w.resize(1366, 768); w._show_product_results(target_id=ids['avi'], run_id=avi_run)
    settle(qt_application_lifetime)
    table = w.product_result_table
    table.setCurrentCell(2, 1); table.scrollToItem(table.item(2, 1))
    settle(qt_application_lifetime)
    old_scroll = table.verticalScrollBar().value()
    assert old_scroll > 0
    old_label = w.product_result_run.currentText()
    old_target = w.product_result_target.currentData()
    w._populate_product_results(); settle(qt_application_lifetime)
    assert table.currentRow() == 2
    assert table.verticalScrollBar().value() == old_scroll
    assert w.product_result_target.currentData() == old_target
    assert w.product_result_run.currentText() == old_label
    assert '数据不足' in w.product_result_detail.toPlainText()
    assert_current_rows(table)
    w._show_product_results(target_id=ids['a'], run_id=nsx_run); settle(qt_application_lifetime)
    assert_current_rows(table)
    assert all(m['target_id'] == ids['a'] for m, _ in w._product_result_checks)
    w._show_product_results(target_id=ids['avi'], run_id=avi_run); settle(qt_application_lifetime)
    assert_current_rows(table)
    assert all(m['target_id'] == ids['avi'] for m, _ in w._product_result_checks)
    assert store.load_run(db, avi_run) == original


def test_empty_results_do_not_leave_old_rows_or_details(product_window, qt_application_lifetime):
    w, db, ids = product_window
    run_id, _ = seed(db, ids['avi'], 'avi')
    w._show_product_results(target_id=ids['avi'], run_id=run_id); settle(qt_application_lifetime)
    w.product_result_status.setCurrentIndex(w.product_result_status.findData('abnormal'))
    settle(qt_application_lifetime)
    assert w.product_result_table.rowCount() == 0
    assert not w.product_result_detail.toPlainText()
    w.resize(1920, 1080); settle(qt_application_lifetime)
    w.product_result_status.setCurrentIndex(0); settle(qt_application_lifetime)
    assert w.product_result_table.rowCount() == 3
    assert_current_rows(w.product_result_table)


def test_queued_reflow_is_coalesced_and_stops_when_table_is_destroyed(product_window, qt_application_lifetime, monkeypatch):
    w, db, ids = product_window
    run_id, _ = seed(db, ids['avi'], 'avi')
    w._show_product_results(target_id=ids['avi'], run_id=run_id); settle(qt_application_lifetime)
    table = w.product_result_table
    sizer = w._product_result_row_sizer
    calls = []
    original = table.resizeRowsToContents
    def record():
        calls.append(1); original()
    monkeypatch.setattr(table, 'resizeRowsToContents', record)
    for _ in range(20):
        sizer.schedule()
    settle(qt_application_lifetime)
    assert len(calls) == 1
    settle(qt_application_lifetime)
    assert len(calls) == 1, 'A layout update must not create a repeating timer loop'
    sizer.schedule()
    table.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    assert not isValid(table) and not isValid(sizer)
    qt_application_lifetime.processEvents()
    assert len(calls) == 1