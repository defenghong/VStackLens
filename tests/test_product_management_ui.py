"""Management-scope and context regressions; saved fixtures only, no network."""
from copy import deepcopy
from pathlib import Path

import pytest
from PySide6.QtCore import Qt

from test_product_desktop import product_window, saved_module, choose
from vstacklens.application.integrated_inspection import IntegratedInspectionResult
from vstacklens.products import store
from vstacklens.products.model import new_module, make_check, make_source, finish_module
from vstacklens.products.management_scope import mark_management_scope, scope_label, scoped_checks


def save_management(db, target_id, run_id, product):
    target = next(t for t in store.list_targets(db) if t.target_id == target_id)
    module = mark_management_scope(new_module(target))
    checks = ('nsx.version', 'nsx.services', 'nsx.resources') if product == 'nsx' else ('AVI-A1', 'AVI-A2:services', 'AVI-A3')
    module['checks'] = [make_check(check_id, title, status, values=values,
        sources=[make_source('/saved/ui-management-fixture')], verification='fixture')
        for check_id, title, status, values in zip(checks,
            ('管理版本', '管理服务读取失败', '管理资源资料不足'),
            ('normal', 'permission_denied', 'insufficient_data'),
            ({'version': 'fixture'}, {}, {}))]
    module = finish_module(module)
    store.create_run(db, run_id, [target], '管理范围UI离线样本')
    store.save_module(db, run_id, module); store.finish_run(db, run_id, 'partial')
    return module


@pytest.mark.parametrize('product,key', [('nsx', 'a'), ('avi', 'avi')])
def test_new_management_scope_uses_shared_labels_and_keeps_failed_missing_checks(product_window, product, key):
    window, db, ids = product_window
    run_id = 'new-manager-ui-' + product
    module = save_management(db, ids[key], run_id, product)
    original = deepcopy(store.load_run(db, run_id))
    window._show_product_results(target_id=ids[key], run_id=run_id)
    assert window.product_scope_checks[product].text() == scope_label(product)
    assert window.product_result_table.rowCount() == len(scoped_checks(module)) == 3
    assert scope_label(product) in window.product_result_table.item(0, 0).text()
    assert {window.product_result_table.item(row, 2).text() for row in range(3)} == {'正常', '权限不足', '数据不足'}
    window.product_result_table.setCurrentCell(2, 0); window._product_check_selected()
    assert scope_label(product) in window.product_result_detail.toPlainText()
    assert '数据不足' in window.product_result_detail.toPlainText()
    assert store.load_run(db, run_id) == original


@pytest.mark.parametrize('product,key,business_id', [('nsx', 'a', 'nsx.transport'), ('avi', 'avi', 'AVI-B1')])
def test_unmarked_history_keeps_original_business_checks_and_scope(product_window, product, key, business_id):
    window, db, ids = product_window
    target = next(t for t in store.list_targets(db) if t.target_id == ids[key])
    module = new_module(target)
    module['checks'] = [make_check(business_id, '历史业务检查原始记录', 'attention', values={'old': True},
                                  sources=[make_source('/saved/history')], verification='fixture')]
    run_id = 'old-unmarked-ui-' + product
    store.create_run(db, run_id, [target], '旧历史'); store.save_module(db, run_id, finish_module(module)); store.finish_run(db, run_id, 'completed')
    original = deepcopy(store.load_run(db, run_id))
    window._show_product_results(target_id=target.target_id, run_id=run_id)
    assert window.product_result_table.rowCount() == 1
    assert window.product_result_table.item(0, 0).text().startswith(product.upper() + ' · ')
    assert '历史业务检查原始记录' in window.product_result_table.item(0, 1).text()
    assert '历史保存范围' in window.product_result_detail.toPlainText()
    assert store.load_run(db, run_id) == original


def test_invalid_marked_scope_is_diagnostic_not_a_clean_management_result(product_window, monkeypatch):
    window, db, ids = product_window
    run_id = 'corrupt-marked-ui'
    save_management(db, ids['a'], run_id, 'nsx')
    saved = store.load_run(db, run_id)
    invalid = deepcopy(saved)
    invalid['modules'][0]['checks'].append(make_check('nsx.transport', '不应进入新管理范围的旧业务项',
        'normal', values={'transport': 'UP'}, sources=[make_source('/offline/corruption')], verification='fixture'))
    original_loader = store.load_run
    monkeypatch.setattr(store, 'load_run', lambda path, identity: deepcopy(invalid) if identity == run_id else original_loader(path, identity))
    window._show_product_results(target_id=ids['a'], run_id=run_id)
    assert '范围校验失败' in window.product_result_summary.text()
    assert window.product_result_table.rowCount() == 0
    detail = window.product_result_detail.toPlainText()
    assert '范围校验失败' in detail and '原始检查记录' in detail
    assert 'nsx.services' in detail and 'permission_denied' in detail and 'nsx.transport' in detail
    assert original_loader(db, run_id) == saved


def test_completion_and_report_center_require_registration_plus_current_file(product_window, tmp_path, monkeypatch):
    window, db, ids = product_window
    run_id = 'registered-delivery-ui'
    saved_module(db, ids['a'], run_id)
    folder = tmp_path / 'delivery'; folder.mkdir()
    html = folder / 'registered.html'; html.write_text('synthetic UI fixture', encoding='utf-8')
    word = folder / 'registered.docx'; word.write_bytes(b'synthetic UI fixture')
    pdf = folder / 'failed.pdf'; pdf.write_bytes(b'synthetic UI fixture')
    unregistered = folder / 'not-registered.html'; unregistered.write_text('synthetic UI fixture', encoding='utf-8')
    store.save_report(db, run_id, 'html', str(html), 'success')
    store.save_report(db, run_id, 'docx', str(word), 'success')
    store.save_report(db, run_id, 'pdf', str(pdf), 'failed')
    result = IntegratedInspectionResult(run_id, unregistered, folder,
        modules=store.load_run(db, run_id)['modules'], state='completed', docx_path=word, pdf_path=pdf)
    window._product_inspection_completed(result)
    assert window.open_report_button.isEnabled() and window.open_word_button.isEnabled()
    assert not window.open_pdf_button.isEnabled()
    opened = []; monkeypatch.setattr(window, '_open_path_safe', opened.append)
    window.open_report_button.click(); window.open_word_button.click()
    assert opened == [html, word]
    # Simulate external disappearance without deleting a fixture or touching user data.
    original_is_file = Path.is_file
    monkeypatch.setattr(Path, 'is_file', lambda path: False if path == word else original_is_file(path))
    window._product_inspection_completed(result)
    assert not window.open_word_button.isEnabled()
    item = next(item for item in window._report_items if item.run_id == run_id)
    assert window._report_formats(item) == {'HTML': html}
    assert window._word_report_path_for_item(item) is None


def test_report_context_and_history_share_existing_display_label_without_vcenter_result(product_window, tmp_path):
    window, db, ids = product_window
    run_id = 'context-label-ui'
    save_management(db, ids['avi'], run_id, 'avi')
    report = tmp_path / 'context.html'; report.write_text('synthetic UI fixture', encoding='utf-8')
    store.save_report(db, run_id, 'html', str(report), 'success')
    window._refresh_all_data(); window.go_to_module('report_center')
    item = next(item for item in window._report_items if item.run_id == run_id)
    window._populate_reports([item]); window._report_selection_changed(); window._update_current_object_bar()
    label = window._report_task_label(item)
    assert label == window._short_task(run_id) and label != '编号待确认'
    assert '尚无巡检记录' not in window.current_object_label.text()
    assert label in window.current_object_label.text()
    assert scope_label('avi') in window.current_object_label.text()
    window._show_product_results(target_id=ids['avi'], run_id=run_id)
    assert label in window.product_result_run.currentText()
    assert window._display_report_kind(item) == scope_label('avi')


def test_product_context_cannot_override_batch_plan_or_explicit_vcenter_scope(product_window):
    window, db, ids = product_window
    saved_module(db, ids['a'], 'context-priority-ui')
    window._show_product_results(target_id=ids['a'], run_id='context-priority-ui')
    window.inspection_pages.setCurrentIndex(2); window._update_current_object_bar()
    assert '批量标准巡检' in window.current_object_label.text()
    window.inspection_pages.setCurrentIndex(3); window._update_current_object_bar()
    assert '计划标准巡检' in window.current_object_label.text()
    window.product_scope_checks['nsx'].setChecked(False)
    window.product_scope_checks['avi'].setChecked(False)
    window.product_scope_checks['vcenter'].setChecked(True)
    window._select_inspection_environment(ids['vc'])
    window.inspection_pages.setCurrentIndex(1); window._update_current_object_bar()
    assert '旧 VC 档案' in window.current_object_label.text()
    assert '产品档案' not in window.current_object_label.text()
    window._environment_id = ids['vc']; window.go_to_module('asset_center'); window._update_current_object_bar()
    assert '限定环境' in window.current_object_label.text()
    assert '旧 VC 档案' in window.current_object_label.text()


def test_same_vcenter_archive_restores_unconfirmed_site_and_readonly_state(product_window):
    window, _, ids = product_window
    window._select_inspection_environment(ids['vc'])
    window.site_input.setText('未确认站点草稿')
    before = (window.customer_input.text(), window.site_input.text(),
              window.customer_input.isReadOnly(), window.site_input.isReadOnly())
    window.product_scope_checks['nsx'].setChecked(True)
    choose(window, 'nsx', ids['a'])
    window.product_scope_checks['vcenter'].setChecked(False)
    assert window.customer_input.isReadOnly() and window.site_input.isReadOnly()
    window.product_scope_checks['vcenter'].setChecked(True)
    assert (window.customer_input.text(), window.site_input.text(),
            window.customer_input.isReadOnly(), window.site_input.isReadOnly()) == before
