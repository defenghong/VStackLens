from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from vstacklens.application.caliber_reader import from_snapshot, load_run
from vstacklens.application.inspection_runner import InspectionRunner, MockRunRequest
from vstacklens.application.inspection_service import InspectionService
from vstacklens.db.connection import connect
from vstacklens.reports.context_builder import ReportContextBuilder
from vstacklens.reports.customer_caliber import DENIED_RULES, calculate, category_findings
from vstacklens.reports.docx_report import DocxReportEngine
from vstacklens.reports.html_package import HtmlReportPackageBuilder
from vstacklens.reports.pdf_report import PdfReportEngine
from vstacklens.reports.report_model import ReportDataFactory

ROOT = Path(__file__).resolve().parents[1]


def row(rule, kind, key, level=None, **fields):
    from vstacklens.reports.customer_caliber import yaml_rules
    from vstacklens.reports.rule_provenance import capture_rule
    from vstacklens.rules.safe_expression import SafeExpressionEngine
    definition = yaml_rules().get(rule, {})
    parameters = {name: item.get("default") for name, item in definition.get("parameters", {}).items()}
    context = dict(parameters)
    context[definition.get("evidence_schema", {}).get("current_value_path", "")] = fields.get("current_value")
    if level is None:
        policy = definition.get("severity_policy") or {}
        level = policy.get("default_level", "P3")
        for threshold in policy.get("rules", []):
            try:
                if SafeExpressionEngine().evaluate(threshold["when"], context):
                    level = threshold["level"]
                    break
            except (ValueError, TypeError):
                pass
    evidence = {"rule_snapshot": capture_rule(definition, parameters)} if definition else {}
    return {"rule_id": rule, "object_type": kind, "object_key": key, "object_name": key,
            "risk_level": level, "result_status": "failed", "evidence": evidence, **fields}


def test_merge_only_by_id_and_keep_each_source():
    rows = [row(rule, "VirtualMachine", "vm") for rule in ("VSL-VM-001", "VSL-VM-007", "VSL-VM-022")]
    rows += [row("VSL-DS-013", "Datastore", "ds", title="文字包含快照 snapshot")]
    result = calculate(rows, asset_total=2)
    snap = next(x for x in result["categories"] if x["category_id"] == "VM-SNAPSHOT")
    assert snap["title"] == "虚拟机存在快照" and snap["priority"] == "P2"
    assert snap["affected_object_count"] == 1 and snap["evidence_item_count"] == 3
    assert result["problem_count"] == 2 and result["affected_total"] == 2
    assert all(x["object_type"] == "VirtualMachine" for x in snap["affected_objects"])
    assert len(next(x for x in result["categories"] if x["category_id"] == "DS-THIN-OVERCOMMIT")["affected_objects"]) == 1


def test_mixed_capacity_levels_count_highest_category_but_keep_object_levels():
    rows = [row("VSL-DS-001", "Datastore", "high", current_value=95),
            row("VSL-DS-001", "Datastore", "low", current_value=76)]
    result = calculate(rows, records=rows, asset_total=2)
    assert result["counts"] == {"P1": 1, "P2": 0, "P3": 0, "P4": 0}
    assert {x["object_key"]: x["risk_level"] for x in result["categories"][0]["affected_objects"]} == {"high": "P1", "low": "P3"}
    assert result["affected_total"] == 2
    assert result["affected_counts"] == {"P1": 1, "P2": 0, "P3": 1}


def test_nonreport_reasons_are_disjoint_and_unknown_not_assumed_p3():
    rows = [row("VSL-VM-003", "VirtualMachine", "vm"),
            row("VSL-HOST-015", "HostSystem", "host"), row("UNMAPPED", "VirtualMachine", "vm", "P1")]
    result = calculate(rows, asset_total=2)
    assert result["non_report_counts"] == {"P4": 1, "已定不报": 1, "待映射": 1}
    assert result["problem_count"] == 0 and result["non_report_total"] == 3
    assert not {"VSL-HOST-004", "VSL-HOST-015", "VSL-VM-015", "VSL-DS-018"} & DENIED_RULES
    assert len(DENIED_RULES) == 10


def test_merge_management_and_resources_without_counting_source_as_hidden():
    rows = [row(rule, "HostSystem", "host") for rule in ("VSL-HOST-002", "VSL-HOST-016")]
    rows += [row(rule, "VirtualMachine", "vm") for rule in ("VSL-VM-010", "VSL-VM-011")]
    result = calculate(rows, asset_total=2)
    assert {x["title"] for x in result["categories"]} == {"ESXi 高权限管理服务开启", "虚拟机资源配置需要优化"}
    assert result["problem_count"] == 2 and result["non_report_total"] == 0
    assert result["affected_total"] == 2


def test_missing_capacity_evidence_is_legacy_not_healthy():
    result = calculate([], records=[row("VSL-DS-001", "Datastore", "ds", result_status="passed")], asset_total=1)
    assert result["state"] == "legacy" and result["health"]["label"] == "旧口径"


@pytest.mark.parametrize("fixture", ["inventory_fail.json", "inventory_pass.json"])
def test_all_consumers_use_run_snapshot_without_rewriting_database(tmp_path, fixture):
    db = tmp_path / "inspection.db"
    result = InspectionRunner().run_mock(MockRunRequest(db_path=db, rulepack_path=ROOT / "rulepacks/builtin-vsphere-v1",
        report_dir=tmp_path / "report", fixture_path=ROOT / "tests/fixtures" / fixture))
    before = hashlib.sha256(db.read_bytes()).hexdigest()
    caliber = load_run(db, result.run_id)
    with connect(db) as conn:
        context = ReportContextBuilder().build(conn, result.run_id)
    report = ReportDataFactory().from_context(context)
    html = HtmlReportPackageBuilder()._single_page_payload(report, context)
    pdf = PdfReportEngine()._build_payload(report, context)
    word = DocxReportEngine()
    groups = word._aggregate_risks(report)
    expected = {k: caliber["counts"][k] for k in ("P1", "P2", "P3")}
    assert pdf["risk_counts"] == word._risk_counts(report, groups) == expected
    assert {k: sum(x["level"] == k for x in html["problems"]) for k in expected} == expected
    assert html["report_context"]["customer_caliber"]["affected_total"] == pdf["issue_object_count"] == caliber["affected_total"]
    assert html["summary"]["judgement"] == pdf["conclusion"] == report.health_score.label == caliber["health"]["label"]
    service = InspectionService(config_path=tmp_path / "config.json")
    dashboard = service.get_dashboard_data(db)
    assert dashboard.risk_summary == caliber["counts"]
    assert dashboard.health_status == caliber["health"]["label"]
    cards = service.list_platform_findings(db, result.run_id)
    assert len({x.category_id for x in cards}) == caliber["problem_count"]
    assert not any(x.non_report_reason for x in cards)
    all_cards = service.list_platform_findings(db, result.run_id, include_non_reported=True)
    assert sum(bool(x.non_report_reason) for x in all_cards) == caliber["non_report_total"]
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before


def test_second_run_cannot_erase_first_run_failures(tmp_path):
    db = tmp_path / "inspection.db"
    def run(name):
        return InspectionRunner().run_mock(MockRunRequest(db_path=db, rulepack_path=ROOT / "rulepacks/builtin-vsphere-v1",
            report_dir=tmp_path / name, fixture_path=ROOT / "tests/fixtures/inventory_fail.json"))
    first = run("first")
    before = load_run(db, first.run_id)
    second = run("second")
    after = load_run(db, first.run_id)
    assert before["counts"] == after["counts"] == load_run(db, second.run_id)["counts"]
    assert before["problem_count"] > 0 and before["affected_total"] == after["affected_total"]


def test_old_snapshot_replays_previously_passed_capacity_and_retains_score(tmp_path):
    result = InspectionRunner().run_mock(MockRunRequest(db_path=tmp_path / "db", rulepack_path=ROOT / "rulepacks/builtin-vsphere-v1",
        report_dir=tmp_path / "report", fixture_path=ROOT / "tests/fixtures/inventory_pass.json"))
    with connect(tmp_path / "db") as conn:
        report = ReportDataFactory().from_context(ReportContextBuilder().build(conn, result.run_id))
    score = report.health_score.score
    report.caliber_inputs = {}
    report.asset_inventory["details"]["Datastore"][0]["properties"]["used_percent"] = 77
    caliber = from_snapshot(report)
    assert caliber["state"] == "legacy"
    assert not any(x["category_id"] == "DS-CAPACITY" for x in caliber["categories"])
    assert "未依据资产值补造通过项" in caliber["health"]["explanation"]
    assert report.health_score.score == score
    report.asset_inventory["details"]["Datastore"][0]["properties"].pop("used_percent")
    assert from_snapshot(report)["state"] == "legacy"


@pytest.mark.parametrize("value", [None, False, float("nan"), float("inf")])
def test_invalid_capacity_observation_is_never_a_pass(value):
    result = calculate([], records=[row("VSL-DS-001", "Datastore", "ds", current_value=value, result_status="passed")], asset_total=1)
    assert result["state"] == "legacy"
    assert result["health"]["label"] == "旧口径"


def _bridge_report(summary):
    from vstacklens.reports.report_model import CustomerInfo, EnvironmentSummary, FindingItem, HealthScore, ReportData, ReportInfo, RiskSummary

    _, derived, _ = ReportContextBuilder()._vsan_report_semantics(summary)
    bridge = row("VSL-DS-020", "Datastore", "vsan-store", current_value=1,
                 rule_name="vSAN storage health", title="vSAN 存储健康存在异常", status="open",
                 result_status="not_applicable" if summary["status"] == "not_applicable" else "failed")
    sources = [bridge, *derived]
    return ReportData(
        report_info=ReportInfo(report_id="bridge-test", run_id="bridge-run", generated_at="2026-10-07T10:00:00+08:00"),
        customer_info=CustomerInfo(customer_name="桥接验收样例", site_name="测试站点", vcenter="mock-vcenter.local"),
        environment_summary=EnvironmentSummary(scope_statement="桥接测试", checked_object_total=1, result_status_summary={bridge["result_status"]: 1}),
        health_score=HealthScore(score=90, grade="A", explanation="测试输入"), risk_summary=RiskSummary(),
        asset_inventory={"total": 1, "details": {}, "summary": {}}, vsan_summary=summary,
        findings=[FindingItem(**item) for item in sources],
        caliber_inputs={"findings": sources, "object_results": [bridge]},
    )


def _assert_bridge_hidden_in_all_consumers(report, tmp_path, expected):
    from vstacklens.reports.customer_caliber import ensure_report

    caliber = ensure_report(report)
    html = HtmlReportPackageBuilder()._single_page_payload(report, {})
    pdf = PdfReportEngine()._build_payload(report, {})
    word = DocxReportEngine()
    groups = word._aggregate_risks(report)
    assert caliber["problem_count"] == len(html["problems"]) == pdf["problem_count"] == len(groups) == expected
    assert not any(item["rule_id"] == "VSL-DS-020" for item in caliber["findings"])
    assert not any("VSL-DS-020" in item["source_rule_ids"] for item in caliber["categories"])
    assert not any(group.rule_id == "VSL-DS-020" for group in groups)
    db = tmp_path / "bridge.db"
    db.touch()
    service = InspectionService(config_path=tmp_path / "config.json")
    service.get_customer_caliber = lambda *args: caliber
    cards = service.list_platform_findings(db, "bridge-run")
    assert len({item.category_id for item in cards}) == expected
    assert not any(item.rule_id == "VSL-DS-020" for item in cards)
    assert pdf["risk_counts"] == word._risk_counts(report, groups) == {k: caliber["counts"][k] for k in ("P1", "P2", "P3")}


def test_applicable_vsan_only_counts_derived_categories_not_bridge(tmp_path):
    report = _bridge_report({"status": "collected", "clusters": ["vSAN"], "health_issue_count": 1})
    _assert_bridge_hidden_in_all_consumers(report, tmp_path, 1)
    assert report.customer_caliber["categories"][0]["category_id"] == "VSAN-CLUSTER-HEALTH"
    assert report.customer_caliber["counts"]["P1"] == 1
    assert report.customer_caliber["non_report_total"] == 0


def test_not_applicable_vsan_bridge_is_absent_from_reports_and_main_numbers(tmp_path):
    report = _bridge_report({"status": "not_applicable"})
    _assert_bridge_hidden_in_all_consumers(report, tmp_path, 0)
    assert report.customer_caliber["counts"] == {"P1": 0, "P2": 0, "P3": 0, "P4": 0}


@pytest.mark.parametrize("category_id,level", [
    ("VSAN-CLUSTER-HEALTH", "P1"), ("VSAN-DISK", "P1"),
    ("VSAN-OBJECT-HEALTH", "P1"), ("VSAN-OBJECT-VMDK", "P1"),
    ("VSAN-RESYNC", "P1"), ("VSAN-NETWORK", "P1"),
    ("VSAN-CAPACITY", "P2"), ("VSAN-POLICY", "P2"),
])
def test_eight_vsan_priorities_come_from_bridge_yaml(category_id, level):
    from vstacklens.reports.category_mapping import CATEGORY_DEFINITIONS
    from vstacklens.reports.customer_caliber import rule_grade, yaml_rules
    from vstacklens.rules.schema_validator import SchemaValidator

    raw = yaml_rules()["VSL-DS-020"]
    validated = SchemaValidator().validate_rule(raw)
    assert validated.severity_policy.derived_category_levels[category_id] == level
    assert ReportContextBuilder._yaml_bridge_grade(category_id) == level
    rule_id = CATEGORY_DEFINITIONS[category_id].source_rule_ids[0]
    from vstacklens.reports.rule_provenance import capture_rule
    params = {name: item.get("default") for name, item in raw.get("parameters", {}).items()}
    assert rule_grade({"rule_id": rule_id, "risk_level": None, "grade_source_rule_id": "VSL-DS-020", "rule_snapshot": capture_rule(raw, params)}) == level
    assert rule_grade({"rule_id": rule_id, "risk_level": "P3", "grade_source_rule_id": "VSL-DS-020"}) == "P3"


def test_single_rule_keeps_specific_title_multiple_rules_use_category_title():
    single = calculate([row("VSL-CL-001", "ClusterComputeResource", "cluster")], asset_total=1)
    assert single["categories"][0]["title"] == "集群 HA 未启用"
    two_objects = calculate([row("VSL-HOST-002", "HostSystem", key) for key in ("host1", "host2")], asset_total=2)
    assert two_objects["categories"][0]["title"] == "ESXi 主机 SSH 服务已开启"
    merged = calculate([row(rule, "HostSystem", "host") for rule in ("VSL-HOST-002", "VSL-HOST-016")], asset_total=1)
    assert merged["categories"][0]["title"] == "ESXi 高权限管理服务开启"
    assert merged["problem_count"] == two_objects["problem_count"] == 1


def test_legitimate_tools_and_syslog_text_is_not_reclassified_or_removed():
    title = "业务系统 VMware Tools 与 Syslog 维护提醒"
    html = HtmlReportPackageBuilder()
    pdf = PdfReportEngine()
    assert html._customer_title({"rule_id": "VSL-CL-001", "title": title}) == title
    assert pdf._safe_customer_text(title) == title
    assert pdf._customer_steps(["核查 Syslog 证据", "使用 VMware Tools 完成业务关机"], "VSL-VM-006") == ["核查 Syslog 证据", "使用 VMware Tools 完成业务关机"]


def test_datastore_capacity_details_use_normal_datastore_free_space():
    report = _bridge_report({"status": "not_applicable"})
    from vstacklens.reports.docx_report import RiskGroup
    from vstacklens.reports.report_model import FindingItem

    report.asset_inventory["details"] = {"Datastore": [{"object_name": "store", "properties": {"datastore_free_gb": 24, "used_percent": 76}}]}
    finding = FindingItem(rule_id="VSL-DS-001", rule_name="Datastore used capacity high", status="open", title="Datastore 容量使用率过高", object_type="Datastore", object_name="store", risk_level="P3", current_value=76)
    headers, rows = DocxReportEngine()._detail_table(report, RiskGroup("P3", "存储", finding.title, [finding], finding.rule_id))
    assert headers == ["Datastore", "已用率", "剩余容量", "状态"]
    assert rows[0][1] == "76.0%" and rows[0][2] == "24.0 GB"
