"""Offline synthetic scan-role cases with independent safety expectations."""
from __future__ import annotations

import hashlib
import json
import zipfile
from contextlib import closing
from pathlib import Path

import pymupdf
import pytest
from docx import Document

from test_standard_progress_completion import synthetic_run
from vstacklens.application import DesktopInspectionConfig, InspectionService, InspectionState
from vstacklens.application import inspection_runner as module
from vstacklens.application.artifact_safety import scan_artifacts
from vstacklens.application.inspection_runner import RunnerCancelledError
from vstacklens.reports.report_model import ReportData
from vstacklens.db.connection import connect


def test_internal_original_fields_are_preserved_while_customer_payload_stays_customer(tmp_path):
    internal = tmp_path / "exact-internal.html"
    payload = tmp_path / "customer_report_payload.json"
    original = json.dumps({"level": "P4", "result": "失败", "evidence": "期望值 Traceback TimeoutError",
                           "field_names": ["password", "authorization", "token"], "password": None}, ensure_ascii=False)
    internal.write_text(original, encoding="utf-8")
    payload.write_text(original, encoding="utf-8")
    before = hashlib.sha256(internal.read_bytes()).hexdigest()
    findings = scan_artifacts([internal, payload], engineering_paths={internal})
    assert not [item for item in findings if item.path == internal]
    assert {item.reason for item in findings if item.path == payload} >= {"客户产物包含 P4", "客户产物包含期望值"}
    assert hashlib.sha256(internal.read_bytes()).hexdigest() == before
    assert json.loads(internal.read_text("utf-8"))["result"] == "失败"


@pytest.mark.parametrize("value", ["[synthetic-test-value]", "{synthetic-test-value}"])
def test_internal_nonempty_bracketed_credential_assignment_is_not_treated_as_empty(tmp_path, value):
    path = tmp_path / "internal.txt"
    path.write_text("password=" + value, encoding="utf-8")
    assert any(item.reason == "包含凭据或会话字段" for item in scan_artifacts([path], engineering_paths={path}))


@pytest.mark.parametrize("internal", [False, True])
@pytest.mark.parametrize("kind", ["assignment", "private_key", "known_secret", "url_credential", "unscannable"])
def test_real_sensitive_content_and_unscannable_outputs_are_blocked_for_each_role(tmp_path, internal, kind):
    path = tmp_path / ("sample.bin" if kind == "unscannable" else "sample.txt")
    values = {"assignment": "password=synthetic-credential", "private_key": "-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----",
              "known_secret": "known-synthetic-value", "url_credential": "https://reader:synthetic@example.invalid/", "unscannable": "opaque"}
    path.write_text(values[kind], encoding="utf-8")
    findings = scan_artifacts([path], engineering_paths={path} if internal else set(), secrets=("known-synthetic-value",))
    assert findings
    assert all(item.path == path for item in findings)


@pytest.mark.parametrize("source", ["clean", "page", "metadata", "metadata_credential", "attachment", "xmp", "attachment_name", "xmp_mime", "xmp_format_content", "xmp_mime_secret", "attachment_description", "attachment_description_secret"])
def test_pdf_parser_format_is_distinct_from_page_metadata_and_attachment_content(tmp_path, source):
    path = tmp_path / "report.pdf"
    with pymupdf.open() as document:
        page = document.new_page()
        page.insert_text((40, 50), "PDF forbidden wording" if source == "page" else "P1 health assessment")
        if source == "metadata":
            document.set_metadata({"title": "P4 forbidden wording"})
        elif source == "metadata_credential":
            document.set_metadata({"author": "password=synthetic-credential"})
        elif source == "attachment":
            document.embfile_add("evidence.txt", b"P4 forbidden wording")
        elif source == "xmp":
            document.set_xml_metadata('<x:xmpmeta xmlns:x="adobe:ns:meta/"><password>synthetic-credential</password></x:xmpmeta>')
        elif source == "attachment_name":
            document.embfile_add("known-synthetic-value.txt", b"P1 health assessment")
        elif source in {"attachment_description", "attachment_description_secret"}:
            document.embfile_add("evidence.txt", b"P1 health assessment", desc="P4" if source == "attachment_description" else "known-synthetic-value")
        elif source in {"xmp_mime", "xmp_format_content", "xmp_mime_secret"}:
            value = "P4" if source == "xmp_format_content" else "application/pdf"
            document.set_xml_metadata(f'<x:xmpmeta xmlns:x="adobe:ns:meta/" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:format>{value}</dc:format></x:xmpmeta>')
        document.save(path)
    with pymupdf.open(path) as document:
        assert document.metadata["format"].startswith("PDF ")
        assert not any("PDF" in page.get_text() for page in document) if source != "page" else True
    findings = scan_artifacts([path], secrets=("known-synthetic-value", "application/pdf") if source == "xmp_mime_secret" else ("known-synthetic-value",))
    assert bool(findings) is (source not in {"clean", "xmp_mime"})


def test_customer_zip_cannot_inherit_internal_member_role(tmp_path):
    internal = tmp_path / "full-result.json"
    internal.write_text('{"level":"P4"}', encoding="utf-8")
    archive = tmp_path / "customer.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("customer/index.html", "P4 forbidden wording")
        output.write(internal, "engineering/full-result.json")
    findings = scan_artifacts([internal, archive], engineering_paths={internal})
    assert not [item for item in findings if item.path == internal]
    assert any(item.path == archive and item.reason == "客户产物包含 P4" for item in findings)


@pytest.mark.parametrize("internal", [False, True])
def test_archive_unknown_member_is_unscannable_even_when_another_member_is_clean(tmp_path, internal):
    archive = tmp_path / "report.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("index.html", "P1 health assessment")
        output.writestr("opaque.bin", "password=synthetic-credential")
    assert any(item.reason.startswith("无法扫描") for item in scan_artifacts([archive], engineering_paths={archive} if internal else set()))


def _real_small_formats(state, monkeypatch):
    def word(self, report, output, **kwargs):
        output.parent.mkdir(parents=True, exist_ok=True)
        document = Document()
        document.add_paragraph("P1 health assessment")
        document.save(output)
        return output, "docx", "Synthetic Word"

    def pdf(self, report, output, **kwargs):
        output.parent.mkdir(parents=True, exist_ok=True)
        with pymupdf.open() as document:
            document.new_page().insert_text((40, 50), "P1 health assessment")
            document.save(output)
        return output

    monkeypatch.setattr(module.ReportExportEngine, "render", word)
    monkeypatch.setattr(module.PdfReportEngine, "render", pdf)
    monkeypatch.setattr(module, "scan_artifacts", scan_artifacts)


@pytest.mark.parametrize("failure", ["customer_payload", "missing_word", "internal_json", "engineering_diagnostic", "scanner_exception"])
def test_runner_blocks_only_affected_delivery_and_preserves_other_format_rows(synthetic_run, monkeypatch, failure):
    state = synthetic_run
    _real_small_formats(state, monkeypatch)
    original_html = module.HtmlReportPackageBuilder.render

    if failure == "customer_payload":
        def html(self, report, context, output, **kwargs):
            result = original_html(self, report, context, output, **kwargs)
            (output / "data" / "customer_report_payload.json").write_text('{"message":"P4"}', encoding="utf-8")
            return result
        monkeypatch.setattr(module.HtmlReportPackageBuilder, "render", html)
    elif failure == "missing_word":
        monkeypatch.setattr(module.ReportExportEngine, "render", lambda self, report, output, **kwargs: (output, "docx", "Synthetic Word"))
    elif failure == "internal_json":
        monkeypatch.setattr(ReportData, "write_json",
                            lambda self, output: output.write_text('{"note":"-----BEGIN PRIVATE KEY-----"}', encoding="utf-8"))
    elif failure == "scanner_exception":
        monkeypatch.setattr(module, "scan_artifacts", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("synthetic scanner exception")))
    else:
        monkeypatch.setattr(module, "write_engineering_diagnostics",
                            lambda output, **kwargs: output.write_text("-----BEGIN PRIVATE KEY-----", encoding="utf-8"))

    result = state.runner.run_vcenter(state.request)
    with closing(connect(state.request.db_path)) as connection:
        statuses = {row["report_type"]: row["report_status"] for row in connection.execute("SELECT * FROM reports WHERE run_id=?", (result.run_id,))}
        assert connection.execute("SELECT run_status FROM inspection_runs WHERE run_id=?", (result.run_id,)).fetchone()[0] == "failed"
    if failure == "scanner_exception":
        assert all(statuses[kind] == "failed" for kind in ("html_package", "json", "docx", "pdf"))
        assert not result.report_path.is_file() and result.docx_path is None and result.pdf_path is None
        return
    expected_failed = {"customer_payload": "html_package", "missing_word": "docx", "internal_json": "json", "engineering_diagnostic": "engineering_diagnostics"}[failure]
    assert statuses[expected_failed] == "failed"
    assert all(status == "success" for kind, status in statuses.items() if kind != expected_failed)
    if failure == "customer_payload":
        assert result.html_error and not result.report_path.is_file()
    elif failure == "missing_word":
        assert result.docx_error and result.docx_path is None
    else:
        assert result.delivery_error
    assert result.pdf_path and result.pdf_path.is_file()


def test_service_keeps_internal_delivery_failure_in_result_and_final_progress(synthetic_run, monkeypatch, tmp_path):
    state = synthetic_run
    monkeypatch.setattr(ReportData, "write_json", lambda self, output: output.write_text('{"note":"-----BEGIN PRIVATE KEY-----"}', encoding="utf-8"))
    service = InspectionService(config_path=tmp_path / "config.json", runner=state.runner)
    config = DesktopInspectionConfig(vcenter=state.request.vcenter, username=state.request.username, password=state.request.password,
                                     db_path=state.request.db_path, rulepack_path=state.request.rulepack_path,
                                     report_output_dir=tmp_path / "reports")
    result = service.run_vcenter_inspection(config, persist_config=False)
    assert result.delivery_error
    assert service.get_progress(config.db_path, result.run_id).state == InspectionState.FAILED
    assert service.get_progress().stage == "delivery_failed"
    assert result.report_path.is_file() and result.docx_path and result.pdf_path


def test_cancelling_before_final_scan_never_leaves_successful_report_rows(synthetic_run):
    state = synthetic_run
    def progress(stage, percent):
        if stage == "scanning_reports":
            state.cancel = True
    with pytest.raises(RunnerCancelledError):
        state.runner.run_vcenter(state.request, progress=progress, cancel_requested=lambda: state.cancel)
    with closing(connect(state.request.db_path)) as connection:
        statuses = [row[0] for row in connection.execute("SELECT report_status FROM reports")]
    assert statuses and "success" not in statuses
