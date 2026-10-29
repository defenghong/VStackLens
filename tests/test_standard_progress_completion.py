"""Offline synthetic orchestration tests; these are not live vCenter evidence."""
from __future__ import annotations

from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

import pytest

from vstacklens.application import DesktopInspectionConfig, InspectionService, InspectionState
from vstacklens.application import inspection_runner as module
from vstacklens.application.artifact_safety import ArtifactScanFinding, UnsafeArtifactError
from vstacklens.application.inspection_runner import InspectionRunner, RunnerCancelledError, VCenterRunRequest
from vstacklens.application.inspection_service import InspectionCancelledError
from vstacklens.db.connection import connect


ROOT = Path(__file__).resolve().parents[1]
RULEPACK = ROOT / "rulepacks" / "builtin-vsphere-v1"


@pytest.fixture
def synthetic_run(monkeypatch, tmp_path):
    state = SimpleNamespace(events=[], phases=[], cancel=False, fail_format=None, context=None)

    class Collector:
        def __init__(self, *args):
            self.cancel_requested = lambda: False

        def precheck(self):
            pass

        def collect(self, context, plan, progress=None):
            return {"objects": [{"object_type": "vCenter", "object_key": "offline-vc",
                                 "object_name": "Offline VC", "properties": {"connected": True}}]}

    request = VCenterRunRequest(
        db_path=tmp_path / "run.db", rulepack_path=RULEPACK,
        report_dir=tmp_path / "reports" / "run-{run_id}",
        docx_out=tmp_path / "reports" / "run-{run_id}" / "report.docx",
        pdf_out=tmp_path / "reports" / "run-{run_id}" / "report.pdf",
        vcenter="offline.invalid", username="reader", password="synthetic-value",
    )
    runner = InspectionRunner(collector_factory=Collector)
    monkeypatch.setattr(runner, "load_registry", lambda path: SimpleNamespace(executable_rules=[], rules=[]))

    def observe(phase):
        state.phases.append(phase)
        assert not any(percent == 100 or stage == "success" for stage, percent in state.events)

    def html_render(self, report, context, output, **kwargs):
        observe("html")
        state.context = context
        if state.fail_format == "html":
            raise OSError("synthetic HTML delivery error")
        output.mkdir(parents=True)
        (output / "data").mkdir()
        (output / "data" / "customer_report_payload.json").write_text("{}", encoding="utf-8")
        path = output / "index.html"
        path.write_text("offline synthetic report", encoding="utf-8")
        return path, None

    def word_render(self, report, output, **kwargs):
        observe("word")
        if state.fail_format == "word":
            raise OSError("synthetic Word delivery error")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("synthetic format placeholder", encoding="utf-8")
        return output, "docx", "Synthetic Word"

    def pdf_render(self, report, output, **kwargs):
        observe("pdf")
        if state.fail_format == "pdf":
            raise OSError("synthetic PDF delivery error")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("synthetic format placeholder", encoding="utf-8")
        return output

    def scan(paths, **kwargs):
        observe("scan")
        return []

    original_diagnostics = module.write_engineering_diagnostics

    def diagnostics(*args, **kwargs):
        observe("diagnostics")
        return original_diagnostics(*args, **kwargs)

    monkeypatch.setattr(module.HtmlReportPackageBuilder, "render", html_render)
    monkeypatch.setattr(module.ReportExportEngine, "render", word_render)
    monkeypatch.setattr(module.PdfReportEngine, "render", pdf_render)
    monkeypatch.setattr(module, "scan_artifacts", scan)
    monkeypatch.setattr(module, "write_engineering_diagnostics", diagnostics)
    state.runner, state.request = runner, request
    return state


def _row(db_path):
    with closing(connect(db_path)) as conn:
        return dict(conn.execute("SELECT * FROM inspection_runs ORDER BY created_at DESC LIMIT 1").fetchone())


def test_runner_completion_follows_all_delivery_scan_registration_and_lease_cleanup(synthetic_run):
    state = synthetic_run

    def progress(stage, percent):
        state.events.append((stage, percent))
        if stage == "success":
            with closing(connect(state.request.db_path)) as conn:
                assert conn.execute("SELECT COUNT(*) FROM inspection_execution_leases").fetchone()[0] == 0
                assert conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0] == 5
                assert conn.execute("SELECT run_status FROM inspection_runs").fetchone()[0] == "success"

    result = state.runner.run_vcenter(state.request, progress=progress)
    assert state.phases == ["html", "word", "pdf", "scan", "diagnostics"]
    assert state.events[-1] == ("success", 100)
    assert sum(percent == 100 for _, percent in state.events) == 1
    assert (result.report_dir / "engineering_diagnostics.md").is_file()
    assert state.context["run"]["run_status"] == "running"
    assert state.context["run"]["current_stage"] == "reporting"
    assert state.context["history_comparison"]["state"] == "single_run"


@pytest.mark.parametrize("failed_format", ["html", "word", "pdf"])
def test_partial_delivery_remains_failed_without_hiding_other_formats(synthetic_run, failed_format):
    state = synthetic_run
    state.fail_format = failed_format
    result = state.runner.run_vcenter(state.request, progress=lambda *event: state.events.append(event))
    assert getattr(result, {"html": "html_error", "word": "docx_error", "pdf": "pdf_error"}[failed_format])
    assert state.phases == ["html", "word", "pdf", "scan", "diagnostics"]
    assert state.events[-1] == ("delivery_failed", 100)
    assert not any(stage == "success" for stage, _ in state.events)
    assert _row(state.request.db_path)["run_status"] == "failed"
    with closing(connect(state.request.db_path)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM reports WHERE report_status = 'failed'").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM reports WHERE report_status = 'success'").fetchone()[0] == 4


@pytest.mark.parametrize("cancel_stage", ["reporting_word", "scanning_reports", "finalizing"])
def test_cancel_persists_non_success_and_releases_execution_lease(synthetic_run, cancel_stage):
    state = synthetic_run

    def progress(stage, percent):
        state.events.append((stage, percent))
        if stage == cancel_stage:
            state.cancel = True

    with pytest.raises(RunnerCancelledError):
        state.runner.run_vcenter(state.request, progress=progress, cancel_requested=lambda: state.cancel)
    row = _row(state.request.db_path)
    assert row["run_status"] == "cancelled"
    assert row["progress_percent"] < 100
    assert not any(stage == "success" or percent == 100 for stage, percent in state.events)
    with closing(connect(state.request.db_path)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM inspection_execution_leases").fetchone()[0] == 0
    assert not list(state.request.report_dir.parent.glob(".vstacklens-*"))


def test_existing_delivery_safety_gate_rejection_cannot_be_reported_as_success(synthetic_run, monkeypatch):
    state = synthetic_run
    def reject(self, report, context, output, **kwargs):
        raise UnsafeArtifactError([ArtifactScanFinding(output / "index.html", "synthetic safety rejection")])
    monkeypatch.setattr(module.HtmlReportPackageBuilder, "render", reject)
    result = state.runner.run_vcenter(state.request, progress=lambda *event: state.events.append(event))
    assert result.html_error
    assert _row(state.request.db_path)["run_status"] == "failed"
    assert not any(stage == "success" for stage, _ in state.events)


@pytest.mark.parametrize("failed_format", [None, "word"])
def test_service_announces_terminal_state_only_after_result_records_are_read(synthetic_run, monkeypatch, tmp_path, failed_format):
    state = synthetic_run
    state.fail_format = failed_format
    service = InspectionService(config_path=tmp_path / "config.json", runner=state.runner)
    config = DesktopInspectionConfig(
        vcenter=state.request.vcenter, username=state.request.username, password=state.request.password,
        db_path=state.request.db_path, rulepack_path=RULEPACK, report_output_dir=tmp_path / "reports",
    )
    original_complete = service._complete_result
    checked = []

    def complete(*args, **kwargs):
        assert service.get_progress(config.db_path, args[1]).state == InspectionState.RUNNING
        assert service.get_progress(config.db_path, args[1]).percent == 99
        checked.append(True)
        return original_complete(*args, **kwargs)

    monkeypatch.setattr(service, "_complete_result", complete)
    events = []
    result = service.run_vcenter_inspection(config, persist_config=False, progress_callback=lambda item: events.append(item))
    assert checked
    assert result.docx_error is not None if failed_format else result.docx_error is None
    assert events[-1].state == (InspectionState.FAILED if failed_format else InspectionState.COMPLETED)
    assert sum(item.percent == 100 for item in events) == 1
    assert not any(item.state == InspectionState.COMPLETED for item in events[:-1])


def test_history_projection_is_rolled_back_when_context_building_raises(synthetic_run, monkeypatch):
    state = synthetic_run
    original = module.ReportContextBuilder.build

    def broken(self, conn, run_id, **kwargs):
        assert conn.execute("SELECT run_status FROM inspection_runs WHERE run_id = ?", (run_id,)).fetchone()[0] == "success"
        raise RuntimeError("synthetic context building error")

    monkeypatch.setattr(module.ReportContextBuilder, "build", broken)
    with pytest.raises(RuntimeError, match="synthetic context"):
        state.runner.run_vcenter(state.request, progress=lambda *event: state.events.append(event))
    assert _row(state.request.db_path)["run_status"] == "failed"
    assert not any(stage == "success" for stage, _ in state.events)
    monkeypatch.setattr(module.ReportContextBuilder, "build", original)


def test_actual_vm_count_is_presented_without_completing_the_run(tmp_path):
    service = InspectionService(config_path=tmp_path / "config.json")
    service._set_progress("building_vm_objects:13/112", 58)
    progress = service.get_progress()
    assert progress.message == "正在采集虚拟机 13/112"
    assert progress.state == InspectionState.RUNNING
    assert progress.percent == 58


@pytest.mark.parametrize("failure", ["result_read", "missing_html", "late_cancel"])
def test_service_result_verification_failure_or_cancel_persists_accurate_state(synthetic_run, monkeypatch, tmp_path, failure):
    state = synthetic_run
    service = InspectionService(config_path=tmp_path / "config.json", runner=state.runner)
    config = DesktopInspectionConfig(
        vcenter=state.request.vcenter, username=state.request.username, password=state.request.password,
        db_path=state.request.db_path, rulepack_path=RULEPACK, report_output_dir=tmp_path / "reports",
    )
    original_complete = service._complete_result
    original_caliber = service.get_customer_caliber

    def complete(*args, **kwargs):
        if failure == "result_read":
            raise OSError("synthetic saved-result read error")
        if failure == "missing_html":
            (Path(args[2]) / "index.html").unlink()
        return original_complete(*args, **kwargs)

    def caliber(*args, **kwargs):
        value = original_caliber(*args, **kwargs)
        if failure == "late_cancel":
            state.cancel = True
        return value

    monkeypatch.setattr(service, "_complete_result", complete)
    monkeypatch.setattr(service, "get_customer_caliber", caliber)
    events = []
    if failure in {"result_read", "late_cancel"}:
        exception = OSError if failure == "result_read" else InspectionCancelledError
        with pytest.raises(exception):
            service.run_vcenter_inspection(config, persist_config=False, progress_callback=events.append,
                                           cancel_requested=lambda: state.cancel)
    else:
        result = service.run_vcenter_inspection(config, persist_config=False, progress_callback=events.append)
        assert result.html_error
    expected = "cancelled" if failure == "late_cancel" else "failed"
    assert _row(state.request.db_path)["run_status"] == expected
    assert all(item.state != InspectionState.COMPLETED for item in events)
