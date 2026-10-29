"""Compact sample pages: real Qt geometry, independent credentials, unchanged scope."""
from pathlib import Path
import pytest
from PySide6.QtWidgets import QPushButton
from test_stage4_desktop_runtime import window
from test_stage3_batch_inspection import setup
from vstacklens.application.inspection_service import ReportCenterItem

SIZES=[(1366,768),(1093,614),(1920,1080),(1536,864)]

@pytest.mark.parametrize('size',SIZES)
def test_entries_remain_visible_without_scrolling(window,size):
    w,_,app=window;w.resize(*size);w.go_to_module('inspection_center');w.inspection_pages.setCurrentIndex(0);app.processEvents()
    entry=w.inspection_pages.currentWidget()
    buttons=[b for b in w.findChildren(QPushButton) if b.text() in {'开始标准巡检','进入批量巡检','管理计划巡检'} and b.isVisible()]
    assert len(buttons)==3
    for b in buttons:
        pos=b.mapTo(w,b.rect().topLeft());assert 0<=pos.y() and pos.y()+b.height()<=w.height()
    assert w.nav.parentWidget().width()==204
    assert not w.current_object_label.wordWrap()

@pytest.mark.parametrize('size',SIZES)
def test_target_dialog_never_steals_table_height_or_shows_password(window,size):
    w,_,app=window;w.resize(*size);w._open_batch();app.processEvents();w.batch_targets.setCurrentCell(0,1)
    height=w.batch_targets.viewport().height();assert height>=170
    w.batch_targets.cellWidget(0,5).setText('LOCAL_TEST_ONLY_SECRET')
    w.batch_target_information.toggle.click();app.processEvents()
    assert w.batch_target_information.body.isVisible()
    assert w.batch_targets.viewport().height()==height
    from PySide6.QtWidgets import QLabel
    text=' '.join(x.text() for x in w.batch_target_information.body.findChildren(QLabel))
    assert 'LOCAL_TEST_ONLY_SECRET' not in text
    assert w._batch_profiles[0].address in text
    w.batch_target_information.body.close();app.processEvents()
    assert w.batch_targets.cellWidget(0,5).text()=='LOCAL_TEST_ONLY_SECRET'

@pytest.mark.parametrize('size',SIZES)
def test_report_operations_and_unique_task_ids_fit(window,size,tmp_path,monkeypatch):
    w,_,app=window;w.resize(*size);w.go_to_module('report_center');file=tmp_path/'layout-only.txt';file.write_text('UI fixture')
    monkeypatch.setattr(w.service,'desktop_report_formats',lambda *a:{'HTML':file,'Word':file,'PDF':file})
    items=[ReportCenterItem(run_id=f'unknown-run-{i}-same-suffix',report_path=file,report_dir=tmp_path,payload_path=None,title='长报告标题'*30,customer_name='长客户名称'*10,site_name='长环境名称'*10,assessment_time='2026-10-15T09:00:00+08:00',score=None,risk_summary={},asset_summary={},top_risks=[],history_summary='',status='success',report_type='html_package',path_hint=str(file)) for i in range(24)]
    w._populate_reports(items);w._resize_batch_pages();app.processEvents()
    assert len({w.report_list.item(i,2).text() for i in range(24)})==24
    label=w.report_list.item(0,2).text();w.report_search_input.setText(label);app.processEvents()
    assert w.report_list.rowCount()==1 and w.report_list.item(0,2).text()==label
    w.report_search_input.clear();app.processEvents()
    assert w.report_splitter.widget(1).isHidden()
    assert w.report_list.viewport().height()>=180
    for box in w.report_filter_boxes:assert box.isVisible() and box.width()>=110
    buttons=[b for b in w.findChildren(QPushButton) if b.isVisible() and b.text() in {'打开 HTML','打开 Word','打开 PDF'}]
    assert len(buttons)==3
    for b in buttons:
        pos=b.mapTo(w,b.rect().topLeft());assert pos.y()+b.height()<w.height()
        assert b.width()>=b.fontMetrics().horizontalAdvance(b.text())+12
    assert items[0].title in w.report_title_label.toolTip()
    assert items[0].customer_name in w.report_scope_label.toolTip()
    assert items[0].site_name in w.report_scope_label.toolTip()
    w._toggle_report_details();app.processEvents();assert not w.report_splitter.widget(1).isHidden()
    w._populate_reports([]);app.processEvents()
    assert w.report_center_empty.isVisible()
    assert not any(b.isVisible() for b in buttons)


def test_common_frame_can_visit_other_pages_without_changing_scope(window):
    w,_,app=window;environment=w._environment_id
    for module in ['dashboard','risk_center','asset_center','history_compare','log_analysis','upgrade_compat','settings','license']:
        w.go_to_module(module);app.processEvents();assert w.pages.currentWidget().isVisible()
    assert w._environment_id==environment


def test_empty_batch_offers_archive_without_submission(window,monkeypatch):
    w,_,app=window
    monkeypatch.setattr(w.service,'list_environment_archives',lambda *a:[])
    w._open_batch();app.processEvents()
    assert w.batch_targets.rowCount()==0 and w.batch_empty.isVisible()
    assert not w.batch_start_button.isEnabled()
    assert not w.batch_progress.isVisible()


def test_independent_reports_without_standard_run_id_have_stable_display_numbers():
    from types import SimpleNamespace
    from vstacklens.desktop.layout3a2 import Layout3a2Mixin
    view=SimpleNamespace(_short_task=lambda value:'—')
    a=SimpleNamespace(run_id=None,report_dir=Path('layout-fixture/log-task-a'))
    b=SimpleNamespace(run_id=None,report_dir=Path('layout-fixture/log-task-b'))
    first=Layout3a2Mixin._report_task_label(view,a)
    assert first==Layout3a2Mixin._report_task_label(view,a)
    assert first!=Layout3a2Mixin._report_task_label(view,b)
