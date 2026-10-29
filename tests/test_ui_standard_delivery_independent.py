"""Independent saved-data Qt review of standard delivery terminal states.

No product callbacks, scanner, report engine, credentials or original evidence
are replaced. The offline producer calls the real service completion projection
against a fresh tiny registry, through the real InspectionWorker signal order.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QMessageBox

from vstacklens.application import AuthService, DesktopInspectionConfig, InspectionProgress, InspectionState
from vstacklens.application.inspection_service import InspectionService, InspectionCancelledError, InspectionRunResult
from vstacklens.db.connection import connect, init_db
from vstacklens.db.repositories import ensure_default_scope, insert_run, insert_report, update_run
from vstacklens.desktop.app import MainWindow, InspectionWorker, configure_chinese_font


CASES = (
    'all-success', 'pdf-word-rejected-html-valid', 'html-rejected-others-valid',
    'all-formats-rejected', 'internal-delivery-error-public-valid', 'cancelled',
    'long-pdf-reason', 'unregistered-pdf-existing-file', 'missing-word-registered-success',
)


class IndependentDeliveryAudit:
    """Reusable by tests and two native screenshots; every case gets a new window."""

    def __init__(self, root, app, patch):
        self.root, self.app = Path(root), app
        self.root.mkdir(parents=True, exist_ok=True)
        configure_chinese_font(app)
        self.service = InspectionService(config_path=self.root / 'config.json')
        def small(path, **kwargs):
            init_db(Path(path)); return Path(path)
        patch.setattr(self.service.upgrade_compat_service, 'ensure_isolated_database', small)
        self.db = self.root / 'synthetic.sqlite'
        init_db(self.db)
        self.service.save_config(DesktopInspectionConfig(
            db_path=self.db, report_output_dir=self.root / 'reports', ui_theme='light'))
        self.window = MainWindow(service=self.service, auth_service=AuthService(self.root / 'auth.json'))
        self.window._plan_timer.stop()
        self.window.resize(1366, 768); self.window.show(); self.window._open_standard_inspection()
        self.dialogs, self.opened, self.events = [], [], []
        patch.setattr(QMessageBox, 'warning', lambda *args: self.dialogs.append('warning') or QMessageBox.Ok)
        patch.setattr(QMessageBox, 'information', lambda *args: self.dialogs.append('information') or QMessageBox.Ok)
        # Never open a real external viewer; record the actual path chosen by the real slot.
        patch.setattr(self.window, '_open_path_safe', self.opened.append)
        self.settle()

    def settle(self):
        for _ in range(3):
            self.app.processEvents(); QTest.qWait(15)

    def observe(self, signal):
        w = self.window
        return {'signal': signal, 'stage': w.stage_label.text(), 'status': w.status_label.text(),
                'progress': w.progress_bar.value(), 'running': w._running,
                'worker_released': w.worker is None,
                'logs_collapsed': w.logs_fold.body.isHidden(),
                'buttons': {'HTML': w.open_report_button.isEnabled(), 'Word': w.open_word_button.isEnabled(),
                            'PDF': w.open_pdf_button.isEnabled(), 'view': w.view_standard_report_button.isEnabled()}}

    def dispatch(self, scenario):
        assert scenario in CASES
        folder = self.root / 'reports'; folder.mkdir(exist_ok=True)
        self.paths = {'HTML': folder / 'index.html', 'Word': folder / 'report.docx', 'PDF': folder / 'report.pdf'}
        self.errors = {}
        if scenario in ('pdf-word-rejected-html-valid', 'all-formats-rejected'):
            self.errors.update({'Word': '离线模拟拒绝Word：格式交付扫描未通过', 'PDF': '离线模拟拒绝PDF：格式交付扫描未通过'})
        if scenario in ('html-rejected-others-valid', 'all-formats-rejected'):
            self.errors['HTML'] = '离线模拟拒绝HTML：格式交付扫描未通过'
        if scenario == 'long-pdf-reason':
            self.errors['PDF'] = '离线模拟长原因PDF：' + '保存数据验证发现格式交付受限，请保留完整诊断原文。' * 24 + '长原因结束标记'
        self.internal = '离线模拟内部证据扫描拒绝：完整工程交付失败' if scenario == 'internal-delivery-error-public-valid' else None
        with connect(self.db) as conn:
            customer, site, vc = ensure_default_scope(conn, 'ui-delivery.invalid', customer_name='隔离模拟客户', site_name='独立Qt完成状态复核')
            self.run_id = insert_run(conn, customer, site, vc, 'manual')
            update_run(conn, self.run_id, 'success', 'success', 100)
            conn.execute('UPDATE inspection_runs SET finished_at=?, risk_summary_json=?, risk_category_summary_json=? WHERE run_id=?',
                         ('2026-10-22T13:00:00+08:00', '{}', '{}', self.run_id))
            for name, path in self.paths.items():
                if not (scenario == 'missing-word-registered-success' and name == 'Word'):
                    path.write_text('offline synthetic UI delivery placeholder; not a rendered customer report', encoding='utf-8')
                if scenario == 'unregistered-pdf-existing-file' and name == 'PDF':
                    continue
                insert_report(conn, self.run_id, customer, site, vc, str(path),
                              status='failed' if name in self.errors else 'success', error=self.errors.get(name),
                              report_type={'HTML': 'html_package', 'Word': 'docx', 'PDF': 'pdf'}[name])
        self.result = None
        def produce(config, *, progress_callback, cancel_requested):
            if scenario == 'cancelled':
                progress_callback(InspectionProgress(state=InspectionState.CANCELLED, run_id=self.run_id,
                    stage='cancelled', percent=57, message='巡检已取消'))
                raise InspectionCancelledError('巡检已取消。')
            self.result = self.service._complete_result(
                self.db, self.run_id, folder, None, progress_callback=progress_callback,
                docx_path=self.paths['Word'], pdf_path=self.paths['PDF'], delivery_error=self.internal)
            assert isinstance(self.result, InspectionRunResult)
            return self.result
        w = self.window
        worker = InspectionWorker(SimpleNamespace(run_vcenter_inspection=produce), self.service.load_config())
        worker.progress.connect(w._inspection_progress)
        worker.progress.connect(lambda progress: self.events.append(self.observe('progress')), Qt.QueuedConnection)
        worker.completed.connect(w._inspection_completed)
        worker.completed.connect(lambda result: self.events.append(self.observe('completed')), Qt.QueuedConnection)
        worker.failed.connect(w._inspection_failed)
        worker.failed.connect(lambda error: self.events.append(self.observe('failed')), Qt.QueuedConnection)
        worker.finished.connect(w._worker_finished)
        worker.finished.connect(lambda: self.events.append(self.observe('finished')), Qt.QueuedConnection)
        w.worker = worker; w._running = True
        worker.start()
        deadline = time.monotonic() + 12
        while w.worker is not None and time.monotonic() < deadline:
            self.app.processEvents(); QTest.qWait(10)
        assert w.worker is None, 'The real worker did not finish normal cleanup; do not terminate it'
        self.settle()
        self.final = self.observe('settled')
        self.final['primary_text'] = '\n'.join((w.stage_label.text(), w.status_label.text(), w.inspection_result_label.text()))
        self.final['full_log'] = w.result_summary.toPlainText()
        self.final['status_word_wrap'] = w.status_label.wordWrap()
        self.final['actual_window_size'] = [w.width(), w.height()]
        self.final['result_type'] = type(self.result).__name__ if self.result is not None else None
        self.final['result_state'] = str(self.result.state) if self.result is not None else None
        self.final['result_stage'] = self.result.stage if self.result is not None else None
        self.final['scenario'] = scenario
        self.final['input_kind'] = 'isolated synthetic registry/files; real service projection and queued Worker signals'
        (self.root / 'observed.json').write_text(json.dumps({'events': self.events, 'final': self.final}, ensure_ascii=False, indent=2), encoding='utf-8')
        return self.final

    def check(self, scenario):
        final = self.final; main = final['primary_text']
        expected = set(self.paths) - set(self.errors)
        if scenario == 'missing-word-registered-success': expected.discard('Word')
        if scenario == 'unregistered-pdf-existing-file': expected.discard('PDF')
        if scenario == 'cancelled': expected.clear()
        assert not self.window._running and self.window.worker is None
        assert not self.dialogs, 'Completion/error state must not automatically create modal dialogs'
        assert {name for name in self.paths if final['buttons'][name]} == expected
        assert final['buttons']['view'] == bool(expected)
        for error in self.errors.values():
            assert error in final['full_log'], 'Full original diagnostics must remain traceable'
        controls={'HTML': self.window.open_report_button, 'Word': self.window.open_word_button, 'PDF': self.window.open_pdf_button}
        for control in controls.values(): control.click()
        assert set(self.opened) == {self.paths[name] for name in expected}
        final['opened_paths'] = [str(p) for p in self.opened]
        final['delivery_actions_verified'] = True
        final['result_errors'] = {name: getattr(self.result, name) if self.result is not None else None
                                  for name in ('html_error', 'docx_error', 'pdf_error', 'delivery_error', 'error')}
        (self.root / 'observed.json').write_text(json.dumps({'events': self.events, 'final': final}, ensure_ascii=False, indent=2), encoding='utf-8')
        if scenario == 'all-success':
            assert '完成' in final['stage'] and '失败' not in main
            assert all(name in final['status'] for name in self.paths)
        elif scenario == 'cancelled':
            assert '取消' in final['stage'] and final['progress'] == 57
            assert '未标记为成功' in final['status']
        else:
            assert '失败' in final['stage'] or '不完整' in final['stage']
            assert '巡检完成，已生成' not in final['status']
            if self.internal:
                assert '内部' in main and '扫描' in main, 'Internal failure reason remains hidden in folded logs'
            elif self.errors:
                assert all(name in main for name in self.errors)
                assert ('受限' if scenario == 'long-pdf-reason' else '扫描') in main, 'Affected formats are visible but their brief reason is still only in folded logs'
            elif scenario == 'unregistered-pdf-existing-file':
                assert 'PDF' in main and '未登记' in main
            elif scenario == 'missing-word-registered-success':
                assert 'Word' in main and ('不存在' in main or '缺失' in main)
            for error in self.errors.values():
                assert error in final['full_log'], 'The full original diagnostic must remain traceable'
        if scenario == 'long-pdf-reason':
            assert final['actual_window_size'] == [1366, 768], 'Long diagnostics forced the window to expand'
            label=self.window.status_label
            assert label.width() <= self.window.pages.width()
        assert [e['signal'] for e in self.events][-1] == 'finished'
        assert any(e['signal'] == ('failed' if scenario == 'cancelled' else 'completed') for e in self.events)

    def close(self):
        self.window._begin_exit(); self.settle()
        assert self.window._exit_ready and not self.window._active_workers()


@pytest.fixture
def independent_delivery(tmp_path, qt_application_lifetime, monkeypatch):
    audit = IndependentDeliveryAudit(tmp_path, qt_application_lifetime, monkeypatch)
    yield audit
    audit.close()


@pytest.mark.parametrize('scenario', CASES)
def test_independent_standard_delivery_terminal_projection(independent_delivery, scenario):
    independent_delivery.dispatch(scenario)
    independent_delivery.check(scenario)