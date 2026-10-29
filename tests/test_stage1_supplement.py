from __future__ import annotations

import json
import sqlite3
from copy import deepcopy

import pytest

from test_stage1_trust import sample
from vstacklens.deep.contracts import DeepEntity
from vstacklens.deep.history import DeepHistoryStore
from vstacklens.deep.service import DeepInspectionService
from vstacklens.reports.customer_caliber import calculate, yaml_rules
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]


def with_metric(dataset, entity_id="store-original"):
    metric = dataset.records[0].model_copy(deep=True)
    metric.entity = DeepEntity(type="Datastore", stable_id=entity_id, display_ref=entity_id)
    metric.record_id = f"metric-{entity_id}"
    metric.metadata = {"rule_id": "STO-DEEP-004"}
    metric.value = 41
    metric.unit = "percent"
    dataset.records.append(metric)
    return dataset


def business_rows(path):
    with sqlite3.connect(path) as conn:
        tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        return {name: sorted(conn.execute(f'SELECT * FROM "{name}"').fetchall(), key=repr) for name in tables}


def analyze(service, dataset, root, name):
    source = dataset.to_json(root / f"{name}.json")
    return service.analyze_dataset(source, root / name)


def test_formal_deep_entry_rejects_modified_duplicate_before_business_writes(tmp_path):
    service = DeepInspectionService()
    original = with_metric(sample(1, {"vm-original": True}))
    analyze(service, original, tmp_path, "original")
    before = business_rows(tmp_path / "deep-history.db")
    changed = with_metric(original.model_copy(deep=True), "store-injected")
    with pytest.raises(ValueError, match="original evidence"):
        analyze(service, changed, tmp_path, "rejected")
    assert business_rows(tmp_path / "deep-history.db") == before
    assert not (tmp_path / "rejected" / "index.html").exists()


@pytest.mark.parametrize("failure", ["analysis", "persistence", "report", "commit"])
def test_formal_deep_entry_rolls_back_all_business_rows_on_failure(tmp_path, monkeypatch, failure):
    service = DeepInspectionService()
    analyze(service, with_metric(sample(1, {"vm-original": True})), tmp_path, "original")
    before = business_rows(tmp_path / "deep-history.db")
    if failure == "analysis":
        def fail_analysis(*_args, **_kwargs):
            raise RuntimeError("injected analysis failure")
        monkeypatch.setattr(service.analyzer, "analyze", fail_analysis)
    elif failure == "persistence":
        archive = DeepHistoryStore._archive_analysis
        def fail_persistence(*args, **kwargs):
            archive(*args, **kwargs)
            raise RuntimeError("injected persistence failure after INSERT")
        monkeypatch.setattr(DeepHistoryStore, "_archive_analysis", staticmethod(fail_persistence))
    elif failure == "report":
        def fail_report(*_args, **_kwargs):
            raise RuntimeError("injected report failure")
        monkeypatch.setattr("vstacklens.deep.service.DeepHtmlReportBuilder.render", fail_report)
    else:
        real_connect = sqlite3.connect
        class CommitFailure(sqlite3.Connection):
            def commit(self):
                raise RuntimeError("injected commit failure")
        def connect_with_commit_failure(*args, **kwargs):
            kwargs["factory"] = CommitFailure
            return real_connect(*args, **kwargs)
        monkeypatch.setattr("vstacklens.deep.history.sqlite3.connect", connect_with_commit_failure)
    with pytest.raises(RuntimeError, match="injected"):
        analyze(service, with_metric(sample(2, {"vm-next": True}), "store-next"), tmp_path, "failed")
    assert business_rows(tmp_path / "deep-history.db") == before
    assert not (tmp_path / "failed" / "index.html").exists()


def passed_capacity():
    return {"rule_id": "VSL-DS-001", "object_type": "Datastore", "object_key": "old-store", "object_name": "old-store",
            "result_status": "passed", "risk_level": None, "current_value": 77, "evidence": {"current_value": 77}}


def test_missing_historical_threshold_preserves_pass_without_current_default():
    original = passed_capacity()
    result = calculate([], records=[original], asset_total=1)
    assert result["problem_count"] == 0
    assert not result["findings"]
    assert result["health"]["assessment_limited"] is True
    assert original["result_status"] == "passed"


def test_current_rule_update_cannot_silently_regrade_old_result(monkeypatch):
    original = {**passed_capacity(), "result_status": "failed", "risk_level": "P3"}
    first = calculate([original], records=[original], asset_total=1)
    rules = deepcopy(yaml_rules())
    rules["VSL-DS-001"]["severity_policy"] = {"type": "fixed", "default_level": "P1"}
    rules["VSL-DS-001"]["report_fields"]["finding_title_zh"] = "NEW RULE TITLE"
    monkeypatch.setattr("vstacklens.reports.customer_caliber.yaml_rules", lambda: rules)
    second = calculate([original], records=[original], asset_total=1)
    assert first["counts"] == second["counts"]
    assert second["counts"]["P3"] == 1


def test_original_rule_and_parameters_are_retained_in_new_standard_evidence():
    from vstacklens.core.context import RunContext
    from vstacklens.inventory.canonical_models import CanonicalObject
    from vstacklens.rules.schema_validator import SchemaValidator
    from vstacklens.rules.executor import RuleExecutor
    from vstacklens.reports.rule_provenance import recorded_rule, snapshot_from
    raw = deepcopy(yaml_rules()["VSL-DS-001"])
    raw["parameters"] = {"old_limit": {"type": "number", "default": 85, "override_allowed": True}}
    raw["condition"]["fail_when"] = "used_percent >= old_limit"
    raw["condition"]["pass_when"] = "used_percent < old_limit"
    rule = SchemaValidator().validate_rule(raw)
    target = CanonicalObject(object_type="Datastore", object_key="old-store", object_name="old-store", object_path="old-store", properties={"used_percent": 77})
    run = RunContext(run_id="offline-old", customer_id="mock", site_id="mock", vcenter_id="mock", db_path=Path("unused.db"))
    result = RuleExecutor()._execute_one(run, rule, target)
    assert result["result_status"] == "passed"
    assert recorded_rule(result)["parameters"]["old_limit"]["default"] == 85
    assert snapshot_from(result)["parameters"]["old_limit"] == 85


@pytest.mark.parametrize("source", ["database", "snapshot"])
def test_historical_consumers_preserve_pass_after_current_rule_update(tmp_path, monkeypatch, source):
    from vstacklens.application.inspection_runner import InspectionRunner, MockRunRequest
    from vstacklens.application.inspection_service import InspectionService
    from vstacklens.application.caliber_reader import load_run
    from vstacklens.db.connection import connect
    from vstacklens.reports.context_builder import ReportContextBuilder
    from vstacklens.reports.report_model import ReportData, ReportDataFactory
    from vstacklens.reports.docx_report import DocxReportEngine
    from vstacklens.reports.html_package import HtmlReportPackageBuilder
    from vstacklens.reports.pdf_report import PdfReportEngine
    db = tmp_path / "isolated.db"
    run = InspectionRunner().run_mock(MockRunRequest(db_path=db, rulepack_path=ROOT / "rulepacks/builtin-vsphere-v1",
        report_dir=tmp_path / "original", fixture_path=ROOT / "tests/fixtures/inventory_pass.json"))
    with connect(db) as conn:
        rows = conn.execute("SELECT result_id,evidence_json FROM rule_results WHERE run_id=? AND rule_id='VSL-DS-001'", (run.run_id,)).fetchall()
        for row in rows:
            evidence = json.loads(row["evidence_json"])
            evidence.pop("rule_snapshot", None)
            evidence["parameters"] = {}
            evidence["current_value"] = 77
            conn.execute("UPDATE rule_results SET result_status='passed',risk_level=NULL,observed_value='77',evidence_json=? WHERE result_id=?", (json.dumps(evidence),row["result_id"]))
        snapshot_row = conn.execute("SELECT file_path FROM reports WHERE run_id=? AND report_type='json'", (run.run_id,)).fetchone()
        snapshot_path = Path(snapshot_row["file_path"])
        model = ReportData.model_validate_json(snapshot_path.read_text(encoding="utf-8"))
        for row in model.caliber_inputs["object_results"]:
            if row["rule_id"] == "VSL-DS-001":
                row.update(result_status="passed", risk_level=None, current_value=77)
                row["evidence"].pop("rule_snapshot", None)
                row["evidence"]["parameters"] = {}
                row["evidence"]["current_value"] = 77
        model.customer_caliber = {}
        model.write_json(snapshot_path)
        if source == "database":
            conn.execute("UPDATE reports SET report_status='unavailable' WHERE run_id=? AND report_type='json'", (run.run_id,))
    before = load_run(db, run.run_id)
    current_rules = deepcopy(yaml_rules())
    current_rules["VSL-DS-001"]["severity_policy"] = {"type": "fixed", "default_level": "P1"}
    current_rules["VSL-DS-001"]["report_fields"]["finding_title_zh"] = "CHANGED CURRENT RULE"
    monkeypatch.setattr("vstacklens.reports.customer_caliber.yaml_rules", lambda: current_rules)
    with connect(db) as conn:
        conn.execute("UPDATE rules SET definition_json=?,risk_level='P1',rule_name='CHANGED CURRENT RULE' WHERE rule_id='VSL-DS-001'", (json.dumps(current_rules["VSL-DS-001"]),))
    checksum = hashlib.sha256(db.read_bytes()).hexdigest()
    after = load_run(db, run.run_id)
    assert after["counts"] == before["counts"]
    assert after["judgment_provenance"]["mode"] == "ORIGINAL_WITH_LIMITS"
    assert all(row["result_status"] == "passed" for row in after["object_results"] if row["rule_id"] == "VSL-DS-001")
    assert not any(row["rule_id"] == "VSL-DS-001" for row in after["findings"])
    with connect(db) as conn:
        context = ReportContextBuilder().build(conn, run.run_id, include_history=False)
    report = ReportDataFactory().from_context(context)
    html = HtmlReportPackageBuilder()._single_page_payload(report, context)
    pdf = PdfReportEngine()._build_payload(report, context)
    word = DocxReportEngine()
    assert report.customer_caliber["counts"] == after["counts"]
    expected = {level: after["counts"][level] for level in ("P1","P2","P3")}
    assert word._risk_counts(report, word._aggregate_risks(report)) == pdf["risk_counts"] == expected
    assert {level: sum(item["level"] == level for item in html["problems"]) for level in expected} == expected
    service = InspectionService(config_path=tmp_path / "config.json")
    assert service.get_dashboard_data(db).risk_summary == after["counts"]
    assert "未按当前规则重新判断" in html["summary"]["judgmentBoundary"]
    assert "未按当前规则重新判断" in pdf["judgment_boundary"]
    assert "未按当前规则重新判断" in report.health_score.explanation
    html_path, _ = HtmlReportPackageBuilder().render(report, context, tmp_path / f"export-{source}")
    assert "未按当前规则重新判断" in html_path.read_text(encoding="utf-8")
    word_path = word.render(report, tmp_path / f"export-{source}.docx")
    from docx import Document
    assert "未按当前规则重新判断" in "\n".join(item.text for item in Document(word_path).paragraphs)
    pdf_path = PdfReportEngine().render(report, tmp_path / f"export-{source}.pdf", report_context=context)
    import pymupdf
    with pymupdf.open(pdf_path) as document:
        assert "未按当前规则重新判断" in "".join(page.get_text() for page in document)
    assert hashlib.sha256(db.read_bytes()).hexdigest() == checksum


def test_explicit_reinterpretation_is_separate_and_marked_in_report_consumers():
    from vstacklens.reports.report_model import ReportDataFactory
    from vstacklens.reports.customer_caliber import reinterpret_report
    from vstacklens.reports.html_package import HtmlReportPackageBuilder
    from vstacklens.reports.pdf_report import PdfReportEngine
    context = {"run": {"run_id":"old-readonly"},"asset_total":1,"result_status_summary":{"passed":1},
               "object_results":[passed_capacity()],"findings":[],"asset_details":{"Datastore":[]}}
    original = ReportDataFactory().from_context(context)
    original_bytes = original.model_dump_json()
    revised = reinterpret_report(original)
    assert original.model_dump_json() == original_bytes
    assert original.customer_caliber["problem_count"] == 0
    assert revised.customer_caliber["problem_count"] == 1
    assert revised.customer_caliber["judgment_provenance"]["mode"] == "EXPLICIT_REINTERPRETATION"
    assert revised.customer_caliber["object_results"][0]["judgment_provenance"]["original_result"]["result_status"] == "passed"
    html = HtmlReportPackageBuilder()._single_page_payload(revised, {})
    pdf = PdfReportEngine()._build_payload(revised, {})
    assert html["summary"]["judgmentMode"] == "EXPLICIT_REINTERPRETATION"
    assert "不能替代原始历史结论" in pdf["judgment_boundary"]
