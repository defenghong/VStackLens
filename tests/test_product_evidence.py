"""Complete evidence, no-clobber publication, and fail-closed report pairs."""
from __future__ import annotations

import errno
import json
from pathlib import Path

import pytest

from vstacklens.application.artifact_safety import UnsafeArtifactError
from vstacklens.products.model import TargetRef, new_module, make_check, make_source, finish_module
from vstacklens.products.reporting import build_integrated_report
from vstacklens.reports import product_evidence as publication


def report_fixture(value="公开完整观察"):
    target = TargetRef("nsx-evidence-target", "nsx", "isolated-customer", "isolated-site", "离线证据管理器", "192.0.2.110")
    module = new_module(target)
    module["checks"] = [make_check("device.observation", "公开字段", "normal", values={"observed": value},
        sources=[make_source("/api/offline-evidence", version_basis="离线合成样本")], verification="offline_sample")]
    return build_integrated_report("offline-evidence-run", [target], [finish_module(module)], "离线证据发布验证")


def test_complete_original_modules_and_pointer_index_are_published(tmp_path):
    from vstacklens.products.reporting import product_evidence_filename, validate_product_coverage, product_report_view
    report = report_fixture("完整字段" * 1200)
    evidence = publication.write_into_stage(report, tmp_path)
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    assert payload["modules"] == report.product_modules
    assert payload["record_index"] and len(payload["modules"][0]["checks"][0]["values"]["observed"]) == 4800
    assert evidence.name == product_evidence_filename(report)
    validate_product_coverage(report, product_report_view(report), payload)


def test_same_model_formats_reuse_identical_evidence_without_overwriting(tmp_path):
    from vstacklens.products.reporting import product_evidence_filename
    report = report_fixture()
    for name in ("first.txt", "second.txt"):
        with publication.staged_product_file(report, tmp_path / name, overwrite=False) as body:
            body.write_text("离线正文 " + product_evidence_filename(report), encoding="utf-8")
    files = list(tmp_path.glob("inspection-evidence-*.json"))
    assert len(files) == 1
    original = files[0].read_bytes()
    assert all((tmp_path / name).is_file() for name in ("first.txt", "second.txt"))
    publication.write_into_stage(report, tmp_path)
    assert files[0].read_bytes() == original


def test_different_report_observations_never_share_or_replace_evidence(tmp_path):
    reports = [report_fixture(value) for value in ("原报告观察", "新报告观察")]
    for index, report in enumerate(reports):
        with publication.staged_product_file(report, tmp_path / f"report-{index}.txt", overwrite=False) as body:
            body.write_text("离线客户正文", encoding="utf-8")
    files = list(tmp_path.glob("inspection-evidence-*.json"))
    assert len(files) == 2
    values = {json.loads(path.read_text(encoding="utf-8"))["modules"][0]["checks"][0]["values"]["observed"] for path in files}
    assert values == {"原报告观察", "新报告观察"}


def test_body_scan_failure_publishes_neither_body_nor_attachment(tmp_path):
    target = tmp_path / "blocked.txt"
    with pytest.raises(UnsafeArtifactError):
        with publication.staged_product_file(report_fixture(), target, secrets=("private-one-use-value",)) as body:
            body.write_text("private-one-use-value", encoding="utf-8")
    assert not target.exists() and not list(tmp_path.glob("inspection-evidence-*.json"))
    assert not list(tmp_path.glob(".vstacklens-product-*"))


@pytest.mark.parametrize("unsafe", ["private-one-use-value", "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----"])
def test_unsafe_evidence_is_rejected_instead_of_silently_dropping_fields(tmp_path, unsafe):
    report = report_fixture()
    report.product_modules[0]["checks"][0]["values"]["observed"] = unsafe
    with pytest.raises(UnsafeArtifactError):
        publication.write_into_stage(report, tmp_path, secrets=("private-one-use-value",))
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("field", ["licenseKey", "license_keys", "privateKey", "rawResponse", "requestHeaders", "accessToken"])
def test_sensitive_aliases_and_raw_containers_cannot_enter_complete_evidence(tmp_path, field):
    report = report_fixture()
    report.product_modules[0]["checks"][0]["values"][field] = "offline-sensitive-canary"
    with pytest.raises(UnsafeArtifactError):
        publication.write_into_stage(report, tmp_path)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("field", ["licenseKey", "license_keys", "privateKey", "rawResponse"])
def test_new_product_report_entry_refuses_unsafe_aliases_without_editing_input(field):
    from copy import deepcopy
    report = report_fixture()
    modules = deepcopy(report.product_modules)
    modules[0]["checks"][0]["values"][field] = "offline-sensitive-canary"
    original = deepcopy(modules)
    target = TargetRef("nsx-evidence-target", "nsx", "isolated-customer", "isolated-site", "离线证据管理器", "192.0.2.110")
    with pytest.raises(ValueError, match="敏感|投影"):
        build_integrated_report("blocked-report", [target], modules, "离线拒绝验证")
    assert modules == original


def test_existing_conflicting_evidence_is_never_overwritten_or_linked(tmp_path):
    from vstacklens.products.reporting import product_evidence_filename
    report = report_fixture()
    attachment = tmp_path / product_evidence_filename(report)
    attachment.write_bytes(b"existing user evidence must be preserved")
    target = tmp_path / "not-published.txt"
    with pytest.raises(FileExistsError):
        with publication.staged_product_file(report, target, overwrite=False) as body:
            body.write_text("离线客户正文", encoding="utf-8")
    assert attachment.read_bytes() == b"existing user evidence must be preserved"
    assert not target.exists()


def test_existing_report_is_refused_before_rendering(tmp_path):
    target = tmp_path / "existing.txt"
    target.write_text("原有报告", encoding="utf-8")
    called = False
    with pytest.raises(FileExistsError):
        with publication.staged_product_file(report_fixture(), target, overwrite=False):
            called = True
    assert not called and target.read_text(encoding="utf-8") == "原有报告"


def test_existing_product_word_is_preserved_before_export_work(tmp_path, monkeypatch):
    from vstacklens.reports.exporter import ReportExportEngine
    target = tmp_path / "existing.docx"
    target.write_bytes(b"existing user report")
    monkeypatch.setattr(ReportExportEngine, "_render", lambda *args: pytest.fail("must not render over an existing file"))
    with pytest.raises(FileExistsError):
        ReportExportEngine().render(report_fixture(), target)
    assert target.read_bytes() == b"existing user report"
    assert not list(tmp_path.glob("inspection-evidence-*.json"))


def test_direct_product_word_engine_delivers_evidence_and_refuses_old_body(tmp_path):
    from vstacklens.products.reporting import product_evidence_filename
    from vstacklens.reports.docx_report import DocxReportEngine
    report = report_fixture()
    target = tmp_path / "direct.docx"
    assert DocxReportEngine().render(report, target) == target
    assert target.is_file() and (tmp_path / product_evidence_filename(report)).is_file()
    original = target.read_bytes()
    with pytest.raises(FileExistsError):
        DocxReportEngine().render(report, target)
    assert target.read_bytes() == original


def test_missing_coverage_blocks_publication_before_body(tmp_path, monkeypatch):
    from vstacklens.products import reporting
    def reject(*args):
        raise ValueError("离线证据覆盖缺失")
    monkeypatch.setattr(reporting, "validate_product_coverage", reject)
    target = tmp_path / "blocked.txt"
    with pytest.raises(ValueError, match="覆盖缺失"):
        with publication.staged_product_file(report_fixture(), target):
            pytest.fail("body generation must not start")
    assert not target.exists() and not list(tmp_path.glob("inspection-evidence-*.json"))


def test_filesystem_without_links_uses_exclusive_copy_and_preserves_existing(tmp_path, monkeypatch):
    def unsupported(*args, **kwargs):
        raise OSError(errno.ENOTSUP, "isolated filesystem simulation")
    monkeypatch.setattr(publication.os, "link", unsupported)
    target = tmp_path / "body.txt"
    with publication.staged_product_file(report_fixture(), target, overwrite=True) as body:
        body.write_text("离线客户正文", encoding="utf-8")
    assert target.is_file()
    attachment = next(tmp_path.glob("inspection-evidence-*.json"))
    assert json.loads(attachment.read_text(encoding="utf-8"))["modules"]
