"""Offline synthetic results delivered through real Qt worker signals."""
from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QMessageBox

from test_desktop_theme_switch import make_service
from test_standard_progress_completion import synthetic_run  # noqa: F401 - explicit small orchestration fixture.
from vstacklens.application import DesktopInspectionConfig, InspectionProgress, InspectionState
from vstacklens.application.inspection_service import InspectionCancelledError, InspectionRunResult
from vstacklens.application.connection_probe import ProbeResult
from vstacklens.application.artifact_safety import ArtifactScanFinding
from vstacklens.db.connection import connect
from vstacklens.desktop.app import InspectionWorker, MainWindow, configure_chinese_font


@pytest.fixture
def terminal_window(tmp_path, monkeypatch):
    configure_chinese_font(QApplication.instance())
    service = make_service(tmp_path / "isolated-ui", "light")
    window = MainWindow(service=service, auth_service=service.theme_test_auth)
    monkeypatch.setattr(QMessageBox, "warning", lambda *args: QMessageBox.Ok)
    monkeypatch.setattr(QMessageBox, "information", lambda *args: QMessageBox.Ok)
    yield window
    observed = {
        "input_kind": "offline synthetic; actual MainWindow and queued QThread callbacks",
        "stage": window.stage_label.text(), "status": window.status_label.text(),
        "progress": window.progress_bar.value(), "running": window._running,
        "worker_released": window.worker is None,
        "html_enabled": window.open_report_button.isEnabled(),
        "word_enabled": window.open_word_button.isEnabled(),
        "pdf_enabled": window.open_pdf_button.isEnabled(),
        "view_enabled": window.view_standard_report_button.isEnabled(),
        "summary": window.result_summary.toPlainText(),
    }
    (tmp_path / "qt-observed.json").write_text(json.dumps(observed, ensure_ascii=False, indent=2), encoding="utf-8")


def _result(tmp_path):
    report_dir = tmp_path / "synthetic-delivery"
    report_dir.mkdir()
    html = report_dir / "index.html"
    word = report_dir / "report.docx"
    pdf = report_dir / "report.pdf"
    for path in (html, word, pdf):
        path.write_text("synthetic offline report placeholder", encoding="utf-8")
    return InspectionRunResult("offline-qt-run", html, report_dir, None, None,
                               docx_path=word, pdf_path=pdf)


def _deliver(window, result, *, state=InspectionState.COMPLETED, stage="success", error=None):
    """Use an actual QThread and queued Qt completion/finished callbacks."""
    result.state, result.stage, result.error = state, stage, error
    def run(config, *, progress_callback, cancel_requested):
        progress_callback(InspectionProgress(state=state, run_id=result.run_id,
                                             stage=stage, percent=100,
                                             message="离线模拟终态", error=error))
        return result

    worker = InspectionWorker(SimpleNamespace(run_vcenter_inspection=run), DesktopInspectionConfig())
    worker.progress.connect(window._inspection_progress)
    worker.completed.connect(window._inspection_completed)
    worker.failed.connect(window._inspection_failed)
    worker.finished.connect(window._worker_finished)
    window.worker = worker
    window._running = True
    worker.start()
    deadline = time.monotonic() + 8
    while window.worker is not None and time.monotonic() < deadline:
        QApplication.instance().processEvents()
        QTest.qWait(10)
    assert window.worker is None, "real Qt worker did not finish its normal cleanup"
    assert not window._running
    return window.stage_label.text(), window.status_label.text()


def test_queued_worker_callback_keeps_failed_delivery_visible(terminal_window, tmp_path):
    result = _result(tmp_path)
    result.pdf_error = "PDF 交付扫描未通过：synthetic safety rejection"
    stage, status = _deliver(terminal_window, result, state=InspectionState.FAILED,
                             stage="delivery_failed", error=result.pdf_error)
    assert "部分交付失败" in stage
    assert "PDF" in status
    assert not terminal_window.open_pdf_button.isEnabled()
    assert terminal_window.open_report_button.isEnabled()
    assert terminal_window.open_word_button.isEnabled()
    terminal_window._open_standard_inspection()
    terminal_window.show()
    QApplication.instance().processEvents()
    assert terminal_window.stage_label.parentWidget().grab().save(str(tmp_path / "qt-partial-delivery.png"))


@pytest.mark.parametrize("blocked", ["HTML", "Word", "PDF"])
def test_retained_rejected_file_cannot_be_opened(terminal_window, tmp_path, monkeypatch, blocked):
    result = _result(tmp_path)
    setattr(result, {"HTML": "html_error", "Word": "docx_error", "PDF": "pdf_error"}[blocked],
            f"{blocked} 交付扫描未通过：synthetic credential rejection")
    opened = []
    monkeypatch.setattr(terminal_window, "_open_path_safe", opened.append)
    _deliver(terminal_window, result, state=InspectionState.FAILED, stage="delivery_failed")
    for name, button, callback in (
        ("HTML", terminal_window.open_report_button, terminal_window._open_current_report),
        ("Word", terminal_window.open_word_button, terminal_window._open_current_word_report),
        ("PDF", terminal_window.open_pdf_button, terminal_window._open_current_pdf_report),
    ):
        assert button.isEnabled() == (name != blocked)
        # Call the handler directly as well: disabled buttons are not the safety boundary.
        before = len(opened)
        callback()
        assert len(opened) == before + (name != blocked)
    assert len(opened) == 2
    assert terminal_window.view_standard_report_button.isEnabled()
    assert "synthetic credential rejection" in terminal_window.result_summary.toPlainText()


def test_success_survives_finished_resource_cleanup(terminal_window, tmp_path):
    result = _result(tmp_path)
    stage, status = _deliver(terminal_window, result)
    assert stage == "健康评估完成"
    assert "巡检完成" in status
    assert all(button.isEnabled() for button in (terminal_window.open_report_button,
                                                terminal_window.open_word_button,
                                                terminal_window.open_pdf_button))
    assert terminal_window.progress_bar.value() == 100


def test_failed_terminal_outcome_is_carried_even_with_three_existing_reports(terminal_window, tmp_path):
    result = _result(tmp_path)
    stage, status = _deliver(terminal_window, result, state=InspectionState.FAILED,
                             stage="failed", error="synthetic saved-run verification failure")
    assert stage == "健康评估失败"
    assert "巡检完成" not in status
    assert "synthetic saved-run verification failure" in terminal_window.result_summary.toPlainText()


def test_internal_delivery_error_does_not_disable_valid_customer_reports(terminal_window, tmp_path):
    result = _result(tmp_path)
    result.delivery_error = "内部证据交付失败：synthetic scan rejection"
    stage, status = _deliver(terminal_window, result, state=InspectionState.FAILED, stage="delivery_failed")
    assert "部分交付失败" in stage
    assert terminal_window.view_standard_report_button.isEnabled()
    assert "内部证据交付失败" in terminal_window.result_summary.toPlainText()


def test_no_deliverable_formats_is_failed(terminal_window, tmp_path):
    result = _result(tmp_path)
    result.html_error = result.docx_error = result.pdf_error = "synthetic delivery failure"
    stage, status = _deliver(terminal_window, result, state=InspectionState.FAILED, stage="delivery_failed")
    assert stage == "健康评估失败"
    assert "没有可交付" in status
    assert not terminal_window.view_standard_report_button.isEnabled()


def test_missing_success_report_does_not_claim_complete(terminal_window, tmp_path):
    result = _result(tmp_path)
    result.pdf_path.unlink()
    stage, status = _deliver(terminal_window, result)
    assert "部分交付失败" in stage
    assert "PDF" in status
    assert not terminal_window.open_pdf_button.isEnabled()


def test_cancelled_worker_keeps_cancelled_state_after_finished(terminal_window, tmp_path):
    result = _result(tmp_path)

    def cancel(config, *, progress_callback, cancel_requested):
        progress_callback(InspectionProgress(state=InspectionState.CANCELLED, run_id=result.run_id,
                                             stage="cancelled", percent=58, message="巡检已取消"))
        raise InspectionCancelledError("巡检已取消。")

    worker = InspectionWorker(SimpleNamespace(run_vcenter_inspection=cancel), DesktopInspectionConfig())
    worker.progress.connect(terminal_window._inspection_progress)
    worker.completed.connect(terminal_window._inspection_completed)
    worker.failed.connect(terminal_window._inspection_failed)
    worker.finished.connect(terminal_window._worker_finished)
    terminal_window.worker = worker
    terminal_window._running = True
    worker.start()
    deadline = time.monotonic() + 8
    while terminal_window.worker is not None and time.monotonic() < deadline:
        QApplication.instance().processEvents()
        QTest.qWait(10)
    assert terminal_window.worker is None
    assert terminal_window.stage_label.text() == "巡检已取消"
    assert "未标记为成功" in terminal_window.status_label.text()
    assert terminal_window.progress_bar.value() == 58
    assert not terminal_window.view_standard_report_button.isEnabled()


def test_actual_connection_diagnostic_result_drives_partial_delivery_callback(terminal_window, monkeypatch):
    class FailedCollector:
        def __init__(self, *args, **kwargs):
            pass

        def precheck(self):
            raise TimeoutError("synthetic offline connection timeout")

    monkeypatch.setattr("vstacklens.application.inspection_runner.PyVmomiCollector", FailedCollector)
    monkeypatch.setattr("vstacklens.application.inspection_runner.socket_probe",
                        lambda *args: ProbeResult("failed", "离线模拟连接超时"))
    config = terminal_window.service.load_config()
    config.password = "synthetic-offline-runtime-value"
    result = terminal_window.service.run_vcenter_inspection(config, persist_config=False)
    assert result.state == InspectionState.FAILED
    assert result.pdf_path is None and result.pdf_error
    stage, status = _deliver(terminal_window, result, state=result.state,
                             stage=result.stage, error=result.error)
    assert "部分交付失败" in stage
    assert "PDF" in status
    assert terminal_window.open_report_button.isEnabled()
    assert terminal_window.open_word_button.isEnabled()
    assert not terminal_window.open_pdf_button.isEnabled()


@pytest.mark.parametrize("blocked,report_type", [("HTML", "html_package"), ("Word", "docx"), ("PDF", "pdf")])
def test_runner_scan_rejection_registry_and_qt_agree(terminal_window, synthetic_run, monkeypatch, blocked, report_type):
    state = synthetic_run

    def reject(paths, **kwargs):
        selected = {"HTML": ".html", "Word": ".docx", "PDF": ".pdf"}[blocked]
        return [ArtifactScanFinding(path, "synthetic credential rejection") for path in paths if path.suffix == selected]

    monkeypatch.setattr("vstacklens.application.inspection_runner.scan_artifacts", reject)
    terminal_window.service.runner = state.runner
    config = DesktopInspectionConfig(
        vcenter=state.request.vcenter, username=state.request.username, password=state.request.password,
        db_path=state.request.db_path, rulepack_path=state.request.rulepack_path,
        report_output_dir=state.request.report_dir.parent,
    )
    result = terminal_window.service.run_vcenter_inspection(config, persist_config=False)
    with connect(config.db_path) as conn:
        rows = list(conn.execute("SELECT report_status, file_path FROM reports WHERE run_id=? AND report_type=?",
                                 (result.run_id, report_type)))
    assert rows and all(row["report_status"] == "failed" for row in rows)
    assert any(Path(row["file_path"]).is_file() for row in rows), "synthetic rejected file remains isolated evidence"
    stage, status = _deliver(terminal_window, result, state=result.state, stage=result.stage, error=result.error)
    assert "部分交付失败" in stage
    assert blocked in status
    button = {"HTML": terminal_window.open_report_button, "Word": terminal_window.open_word_button,
              "PDF": terminal_window.open_pdf_button}[blocked]
    assert not button.isEnabled()
