from __future__ import annotations

import copy
from datetime import datetime

import pytest

from vstacklens.reports.docx_report import DocxReportEngine, RiskGroup
from vstacklens.reports.pdf_report import PdfReportEngine
from vstacklens.reports.report_model import (
    CustomerInfo, EnvironmentSummary, FindingItem, HealthScore, ReportData,
    ReportInfo, RiskSummary,
)


def _report(alarms=None, *, count=None, state="collected", finding=True):
    count = len(alarms) if count is None and isinstance(alarms, list) else count
    observed = {"active_red_alarms": alarms, "red_alarm_count": count}
    report = ReportData(
        report_info=ReportInfo(report_id="offline-alarm-report", generated_at="2026-10-22T10:00:00+08:00", run_id="offline-alarms"),
        customer_info=CustomerInfo(customer_name="离线合成", site_name="测试", vcenter="synthetic.invalid"),
        environment_summary=EnvironmentSummary(scope_statement="离线合成告警证据", checked_object_total=1),
        health_score=HealthScore(score=None, grade="", explanation="保留原结论"),
        risk_summary=RiskSummary(P2=1 if count else 0, total=1 if count else 0),
        asset_inventory={"summary": {"vCenter": 1}, "total": 1, "details": {"vCenter": [{
            "object_name": "synthetic.invalid", "object_key": "vc-shared-id",
            "properties": {**copy.deepcopy(observed), "connected": True, "alarm_detail_collection_status": state},
        }]}},
        findings=[FindingItem(
            risk_level="P2", rule_id="VSL-VC-004", rule_name="vCenter 告警状态", title="vCenter 存在红色活动告警",
            object_type="vCenter", object_name="synthetic.invalid", status="open", current_value=count,
            expected_value=0, collected_at="2026-10-22T09:00:00+08:00", observed_detail=copy.deepcopy(observed),
            evidence={"object_key": "vc-shared-id", "observed_detail": copy.deepcopy(observed)},
        )] if finding else [],
    )
    return report


def test_pdf_preserves_each_alarm_object_status_and_source_without_inventing_missing_values():
    report = _report([
        {"alarm_name": "same name", "entity_name": "same display", "entity_moid": "vm-1", "alarm_id": "alarm-1",
         "status": "red", "acknowledged": False, "time": "2026-10-21T23:59:00Z"},
        {"alarm_name": "same name", "entity_name": "same display", "entity_moid": "vm-2", "alarm_id": "alarm-2",
         "status": "yellow", "acknowledged": True, "time": "2026-10-22T00:01:00Z"},
        {"alarm_name": "Backup job status", "entity_name": "Datacenters", "status": "红色"},
    ])
    before = report.model_dump_json()
    rows = PdfReportEngine()._vcenter_alarm_evidence(report)["rows"]
    assert [(x["entity_id"], x["alarm_id"], x["status"], x["acknowledged"], x["time"]) for x in rows] == [
        ("vm-1", "alarm-1", "red", "否（未确认）", datetime.fromisoformat("2026-10-21T23:59:00+00:00").astimezone().strftime("%Y-%m-%d %H:%M")),
        ("vm-2", "alarm-2", "yellow", "是（已确认）", datetime.fromisoformat("2026-10-22T00:01:00+00:00").astimezone().strftime("%Y-%m-%d %H:%M")),
        (None, None, "红色", "未采集", ""),
    ]
    assert [x["source_path"] for x in rows] == [f"findings[0].observed_detail.active_red_alarms[{i}]" for i in range(3)]
    assert report.model_dump_json() == before


@pytest.mark.parametrize("state,alarms,count,expected", [
    ("collected", [], 0, "未发现红色活动告警"),
    ("unavailable", None, None, "不代表没有告警"),
    ("partial", [], 0, "不代表没有告警"),
    ("collected", [], 2, "不代表没有告警"),
])
def test_no_alarms_and_unavailable_are_distinct(state, alarms, count, expected):
    result = PdfReportEngine()._vcenter_alarm_evidence(_report(alarms, count=count, state=state, finding=False))
    assert not result["rows"]
    assert expected in result["notice"]


def test_missing_primary_source_is_not_replaced_by_stale_alternate_alarm_list():
    report = _report(None, count=2, state="partial")
    report.findings[0].evidence["observed_detail"] = {"active_red_alarms": [{"alarm_name": "older snapshot"}]}
    result = PdfReportEngine()._vcenter_alarm_evidence(report)
    assert result["rows"] == []
    assert "不代表没有告警" in result["notice"]


def test_partial_alarm_details_keep_valid_rows_and_limit_inference():
    result = PdfReportEngine()._vcenter_alarm_evidence(_report([
        {"alarm_name": "one", "entity_name": "vm-1", "status": "red"}, None,
    ], count=3))
    assert len(result["rows"]) == 1
    assert result["invalid_entry_count"] == 1
    assert result["collection_status"] == "partial"
    assert "不能将未列出的告警视为不存在" in result["notice"]


def test_long_alarm_names_are_lossless_bounded_fragments_with_state_associations():
    long_name = "很长的活动告警名称-no-space/" * 220
    evidence = PdfReportEngine()._vcenter_alarm_evidence(_report([
        {"alarm_name": long_name, "entity_name": "same object", "status": "red", "acknowledged": False},
        {"alarm_name": "last alarm", "entity_name": "different object", "status": "yellow", "acknowledged": True},
    ]))
    fragments = evidence["render_rows"]
    assert len(fragments) > 2
    reconstructed = "".join(row[0].split("\n（同一告警续段")[0].replace("\u200b", "") for row in fragments[:-1])
    assert reconstructed == long_name
    assert all(row[1:4] == ["same object", "red", "否（未确认）"] for row in fragments[:-1])
    assert fragments[-1][1:4] == ["different object", "yellow", "是（已确认）"]


def test_word_missing_acknowledgement_and_alarm_time_are_not_fabricated():
    report = _report([{"alarm_name": "Backup job status", "entity_name": "Datacenters", "status": "红色"}])
    headers, rows = DocxReportEngine()._vcenter_alarm_table(RiskGroup("P2", "vCenter", "红色活动告警", report.findings))
    assert headers == ["对象", "告警内容", "确认状态", "时间", "状态"]
    assert rows == [["Datacenters", "Backup job status", "未采集", "未采集", "红色"]]


def test_pdf_payload_adds_original_alarm_rows_without_changing_risk_conclusion():
    report = _report([{"alarm_name": "Backup job status", "entity_name": "Datacenters", "status": "红色"}])
    payload = PdfReportEngine()._build_payload(report, {})
    assert payload["alarm_evidence"]["rows"][0]["entity"] == "Datacenters"
    assert payload["alarm_evidence"]["rows"][0]["status"] == "红色"
    assert payload["risk_counts"] == {"P1": 0, "P2": 1, "P3": 0}
