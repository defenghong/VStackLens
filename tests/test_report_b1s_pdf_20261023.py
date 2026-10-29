from __future__ import annotations

import subprocess
from datetime import datetime
from pathlib import Path

import pymupdf

from test_pdf_report import _report
from vstacklens.reports.customer_caliber import ensure_report
from vstacklens.reports.pdf_report import PdfReportEngine
from vstacklens.resources import package_resource_path


def _pdf_text(path: Path) -> str:
    with pymupdf.open(path) as document:
        return "\n".join(page.get_text() for page in document).replace("\u200b", "")


def test_snapshot_appendix_preserves_names_times_chain_and_iso_paths() -> None:
    report, context = _report()
    properties = report.asset_inventory["details"]["VirtualMachine"][0]["properties"]
    snapshots = [
        {"name": "before-release", "create_time": "2026-10-20T11:22:33.123456+00:00"},
        {"name": "before-upgrade", "created_at": "2026-10-21T12:34:56+00:00"},
    ]
    paths = ["[NAS-storage] ISO/ubuntu-24.04.4-live-server-amd64.iso", "/usr/lib/vmware/isoimages/windows.iso"]
    properties.update(snapshots=snapshots, snapshot_chain_depth=2, snapshot_age_days_max=3,
                      iso_mounted=True, iso_paths=paths)
    ensure_report(report, context)
    before = report.model_dump(mode="json")

    appendix = PdfReportEngine()._build_payload(report, context)["appendix"]

    snapshot = appendix["snapshot_vms"][0]
    assert snapshot["snapshot_names"].replace("\u200b", "").splitlines() == [item["name"] for item in snapshots]
    assert snapshot["snapshot_created"].replace("\u200b", "").splitlines() == [
        datetime.fromisoformat(snapshots[0]["create_time"]).astimezone().strftime("%Y-%m-%d %H:%M"),
        datetime.fromisoformat(snapshots[1]["created_at"]).astimezone().strftime("%Y-%m-%d %H:%M")]
    assert snapshot["chain_depth"] == 2
    assert appendix["iso_vms"][0]["iso_paths"].replace("\u200b", "") == "、".join(paths)
    assert report.model_dump(mode="json") == before


def test_pdf_field_join_omits_empty_values_but_keeps_zero_false(tmp_path: Path) -> None:
    template = package_resource_path("reports", "templates", "inspection-report.typ").read_text(encoding="utf-8")
    helpers = "\n".join(line for line in template.splitlines()
                        if line.startswith(("#let field-text(", "#let field(", "#let join-fields(")))
    source = tmp_path / "join.typ"
    output = tmp_path / "join.pdf"
    source.write_text(helpers + '\n#join-fields((none, field("Build: ", ""), "", 0, false, "vc.test"))', encoding="utf-8")

    result = subprocess.run([str(PdfReportEngine()._typst_binary()), "compile", str(source), str(output)],
                            capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)

    assert result.returncode == 0, result.stderr
    assert " ".join(_pdf_text(output).split()) == "0 · false · vc.test"


def test_pdf_keeps_object_basis_and_appendix_without_technical_repeat(tmp_path: Path, monkeypatch) -> None:
    report, context = _report()
    report.findings[0].explanation='unique-object-basis-marker'
    from vstacklens.reports import customer_view
    build=customer_view.build_problem_display
    def with_legacy_technical(*args,**kwargs):
        value=build(*args,**kwargs)
        value['technical']={'headers':['Technical duplicate'],'rows':[['duplicate-evidence-marker']]}
        return value
    monkeypatch.setattr(customer_view,'build_problem_display',with_legacy_technical)
    engine = PdfReportEngine()

    output = engine.render(report, tmp_path / "report.pdf", report_context=context)
    text = _pdf_text(output)

    assert "unique-object-basis-marker" in "".join(text.split())
    assert "duplicate-evidence-marker" not in text
    assert "技术明细" not in text
    assert "任务：" not in text
    assert report.report_info.run_id not in text
    assert not any(line.strip().startswith("·") for line in text.splitlines())
