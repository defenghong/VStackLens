"""Real offline PDF compilation/publication/reader checks, using tiny product data."""
from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from vstacklens.application.integrated_inspection import IntegratedInspectionRequest, IntegratedInspectionService
from vstacklens.desktop.pdf_reader import PdfReaderDialog
from vstacklens.products import store
from vstacklens.products.model import SessionCredential, finish_module, make_check, make_source, new_module
from vstacklens.products.reporting import build_integrated_report
from vstacklens.reports.pdf_report import PdfReportEngine


RUN_HEX = "0123456789abcdef0123456789abcdef"
RUN_ID = "integrated-" + RUN_HEX


def padded_directory(base: Path, length: int, *, chinese=False) -> Path:
    path = base
    remaining = length - len(str(path.absolute()))
    assert remaining >= 0
    while remaining:
        if remaining == 1:
            path = path.with_name(path.name + "x")
            remaining = 0
        else:
            count = min(45, remaining - 1)
            path /= ("中" if chinese else "p") * count
            remaining -= count + 1
    assert len(str(path.absolute())) == length
    return path


def sample(target, credential=None, **kwargs):
    result = new_module(target)
    result["version"] = "4.2.3.0.0"
    result["verification_level"] = "offline_sample"
    result["checks"] = [make_check("device.version", "离线版本样本", "normal", values={"version": "4.2.3.0.0"},
        sources=[make_source("/api/offline-sample", version_basis="离线合成样本")], verification="offline_sample")]
    return finish_module(result)


@pytest.fixture
def prepared(tmp_path):
    db = tmp_path / "isolated.db"
    store.ensure_product_schema(db)
    identifier = store.save_target(db, product="nsx", name="离线管理器", address="192.0.2.110", customer_name="离线验收客户")
    return db, next(target for target in store.list_targets(db) if target.target_id == identifier)


def request_for(prepared, output):
    db, target = prepared
    return IntegratedInspectionRequest(db, output, [target], {target.target_id: SessionCredential("offline-user", "one-use-private")})


def center_formats(db):
    # Exercise the real report-center projection without constructing unrelated
    # pages or importing the full hardware compatibility catalog.
    from vstacklens.desktop.product_inspection import ProductInspectionMixin
    class Center(ProductInspectionMixin):
        def _db_path(self):
            return db
    center = Center()
    center._product_scope_target_id = None
    center._environment_id = None
    items = center._product_report_items()
    return items, center._integrated_report_formats


@pytest.mark.parametrize("kind,total_length", [("normal", None), ("chinese", 245), ("near_native_limit", 259),
                                               ("previous_failure", 277), ("beyond_previous_failure", 320)])
def test_real_typst_publication_db_report_center_and_builtin_reader(prepared, tmp_path, monkeypatch, qt_application_lifetime, kind, total_length):
    from vstacklens.application import integrated_inspection
    import vstacklens.reports.pdf_report as pdf_module
    monkeypatch.setattr(integrated_inspection, "uuid4", lambda: SimpleNamespace(hex=RUN_HEX))
    suffix = len("/" + RUN_ID + "/inspection-report.pdf")
    base = tmp_path / ("客户 中文交付" if kind == "chinese" else "exports")
    output = padded_directory(base, total_length - suffix, chinese=kind == "chinese") if total_length else base
    commands = []
    native_run = pdf_module.subprocess.run
    def observed_run(command, **kwargs):
        commands.append({"cwd": str(kwargs["cwd"]), "cwd_characters": len(str(kwargs["cwd"])), "compiler": str(command[0])})
        return native_run(command, **kwargs)
    monkeypatch.setattr(pdf_module.subprocess, "run", observed_run)
    result = IntegratedInspectionService(collectors={"nsx": sample}).run(request_for(prepared, output))
    assert result.state == "completed", (result.html_error, result.docx_error, result.pdf_error)
    pdf = result.pdf_path
    assert pdf and pdf.is_file() and pdf.read_bytes().startswith(b"%PDF-")
    if total_length:
        assert len(str(pdf.absolute())) == total_length
    assert commands and commands[0]["cwd_characters"] < 240
    assert not Path(commands[0]["cwd"]).is_relative_to(output)
    saved = store.load_run(prepared[0], result.run_id)
    record = next(row for row in saved["reports"] if row["format"] == "pdf")
    assert record["status"] == "success" and Path(record["path"]) == pdf and not record["error"]
    items, formats = center_formats(prepared[0])
    assert items and formats[result.run_id]["PDF"] == pdf
    viewer = PdfReaderDialog(formats[result.run_id]["PDF"])
    try:
        qt_application_lifetime.processEvents()
        assert viewer.document.page_count >= 1
        assert not viewer.page_image.pixmap().isNull()
        assert viewer.document.load_page(0).get_text().strip()
        assert viewer.page_label.text().startswith("第 1 /")
    finally:
        viewer.close()
        qt_application_lifetime.processEvents()
    assert viewer.document.is_closed
    assert not list(pdf.parent.glob(".vsl-pdf-publish-*"))
    (tmp_path / "path-verification.json").write_text(json.dumps({
        "case": kind, "final_characters": len(str(pdf.absolute())), "final_is_file": pdf.is_file(),
        "db_pdf_state": record["status"], "run_state": saved["state"], "reader_loaded": True,
        "compiler_cwd_characters": commands[0]["cwd_characters"], "remote_requests": 0,
    }, ensure_ascii=False, indent=2), encoding="utf-8")


@pytest.mark.parametrize("failure", ["compiler", "scan"])
def test_pdf_failure_keeps_actual_database_failure_and_partial_delivery(prepared, tmp_path, monkeypatch, failure):
    import vstacklens.reports.pdf_report as pdf_module
    if failure == "compiler":
        monkeypatch.setattr(pdf_module.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=1, stderr="offline compile failure", stdout=""))
    else:
        from vstacklens.application import artifact_safety
        scan = artifact_safety.ensure_artifacts_safe
        def refuse_pdf(paths, **kwargs):
            if any(path.suffix.lower() == ".pdf" for path in paths):
                raise ValueError("offline PDF scanning failure")
            return scan(paths, **kwargs)
        monkeypatch.setattr(artifact_safety, "ensure_artifacts_safe", refuse_pdf)
    result = IntegratedInspectionService(collectors={"nsx": sample}).run(request_for(prepared, tmp_path / "exports"))
    assert result.state == "partial" and result.pdf_path is None and result.pdf_error
    assert result.report_path.is_file() and result.docx_path.is_file()
    assert not (result.report_dir / "inspection-report.pdf").exists()
    saved = store.load_run(prepared[0], result.run_id)
    pdf = next(row for row in saved["reports"] if row["format"] == "pdf")
    assert pdf["status"] == "failed" and not pdf["path"] and pdf["error"]
    assert saved["state"] == "partial" and saved["modules"][0]["delivery_state"] == "partial"
    _, formats = center_formats(prepared[0])
    assert "PDF" not in formats[result.run_id]


@pytest.mark.skipif(os.name != "nt", reason="Windows native path preflight")
@pytest.mark.parametrize("unsafe", ["temporary_directory", "single_component"])
def test_unsupported_paths_are_rejected_before_native_compile(prepared, tmp_path, monkeypatch, unsafe):
    import vstacklens.reports.pdf_report as pdf_module
    _, target = prepared
    report = build_integrated_report("offline-path-rejection", [target], [sample(target)], "离线拒绝检查")
    output = tmp_path / "not-created" / "report.pdf"
    if unsafe == "temporary_directory":
        excessive = padded_directory(tmp_path / "uncreated-temp", 280)
        monkeypatch.setattr(pdf_module.tempfile, "gettempdir", lambda: str(excessive))
        message = "临时目录过长"
    else:
        output = tmp_path / "not-created" / ("x" * 256 + ".pdf")
        message = "单段过长"
    def forbidden(*args, **kwargs):
        pytest.fail("preflight must stop before launching a native process")
    monkeypatch.setattr(pdf_module.subprocess, "run", forbidden)
    with pytest.raises(ValueError, match=message):
        PdfReportEngine().render(report, output)
    assert not output.exists() and not output.parent.exists()


def test_existing_long_path_pdf_is_never_overwritten(prepared, tmp_path):
    _, target = prepared
    output = padded_directory(tmp_path / "existing", 277 - len("/existing.pdf")) / "existing.pdf"
    output.parent.mkdir(parents=True)
    output.write_bytes(b"existing offline customer report")
    report = build_integrated_report("offline-existing-report", [target], [sample(target)], "离线防覆盖")
    with pytest.raises(FileExistsError):
        PdfReportEngine().render(report, output)
    assert output.read_bytes() == b"existing offline customer report"
