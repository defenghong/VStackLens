from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from pathlib import Path

import pymupdf
import pytest

from test_pdf_report import _report
from vstacklens.reports.customer_caliber import ensure_report
from vstacklens.reports.customer_view import customer_display_facts
from vstacklens.reports.pdf_report import PdfReportEngine
from vstacklens.reports.presentation import customer_check_statistics
from vstacklens.reports.report_model import FindingItem
from test_report_batch2_projection_20261023 import RUN, VC, UUID, asset, result


def _read_pdf(path: Path) -> str:
    with pymupdf.open(path) as document:
        return "\n".join(page.get_text() for page in document).replace("\u200b", "")


def test_pdf_uses_shared_display_facts_without_changing_saved_decisions() -> None:
    report, context = _report()
    details = report.asset_inventory["details"]
    details["ClusterComputeResource"][0]["properties"].update(
        ha_enabled=False, drs_enabled=False, admission_control_enabled=True,
        ha_heartbeat_datastore_count=0, drs_behavior="fullyAutomated")
    details["VirtualMachine"][0]["properties"].update(
        snapshots=[{"name": "keep-full-name", "create_time": "2026-09-20T01:02:03.123456+00:00"}],
        snapshot_chain_depth=1, snapshot_age_days_max=7)
    details["HostSystem"][0]["properties"]["physical_nic_details"] = [
        {"device": "vmnic0", "is_in_use": True, "assessment": "normal", "link_state": "up"}]
    ensure_report(report, context)
    before = deepcopy(report.model_dump(mode="json"))
    expected = customer_display_facts(report)

    payload = PdfReportEngine()._build_payload(report, context)

    assert payload["display_facts"] == expected
    assert payload["problem_count"] == expected["counts"]["problem_count"]
    assert payload["issue_object_count"] == expected["counts"]["affected_total"]
    assert payload["counts"]["snapshot_vms"] == 1
    assert payload["display_facts"]["snapshots"]["threshold_label"] == "7 天及以上"
    assert payload["cluster_details"][0]["admission_control"] == "—"
    assert payload["cluster_details"][0]["heartbeat_summary"] == "—"
    assert payload["cluster_details"][0]["drs_behavior"] == "—"
    assert payload["network"]["pnic_anomaly_count"] == 0
    assert payload["network"]["error_count"] is None
    assert payload["narratives"]["network"] == expected["network"]["summary"]
    assert payload["narratives"]["vsan"] == expected["vsan"]["summary"]
    assert payload["certificates"]["vcenter"]["date_source"] == "按采集日期和保存的剩余天数推算"
    assert payload["certificates"]["hosts"][0]["date_source"] == "ESXi 443 TLS 证书直接读取"
    assert payload["top_vcpu"][0]["display_share_scope"] == expected["top_labels"]["vcpu"]
    assert payload["top_capacity"][0]["display_share_scope"] == expected["top_labels"]["capacity"]
    assert report.model_dump(mode="json") == before


def test_real_pdf_omits_missing_fields_and_association_graph(tmp_path: Path) -> None:
    report, context = _report()
    details = report.asset_inventory["details"]
    details["vCenter"][0]["properties"].clear()
    for field in ("host_certificate_not_after", "host_certificate_days_remaining"):
        details["HostSystem"][0]["properties"].pop(field, None)
    details["ClusterComputeResource"][0]["properties"].update(
        ha_enabled=False, drs_enabled=False, admission_control_enabled=True,
        ha_heartbeat_datastore_count=0, drs_behavior="fullyAutomated")
    details["VirtualMachine"][0]["properties"].update(
        snapshots=[{"name": "full-snapshot-name", "create_time": "2026-09-20T01:02:03.123456+00:00"}],
        snapshot_chain_depth=1, snapshot_age_days_max=7)

    output = PdfReportEngine().render(report, tmp_path / "stage-a.pdf", report_context=context)
    text = _read_pdf(output)
    compact = "".join(text.split())

    # PDF is concise; a non-problem object's full snapshot name/time belongs
    # to the full report appendices, rather than an extra PDF inventory list.
    from vstacklens.reports.document_model import get_document
    from vstacklens.reports.docx_report import DocxReportEngine
    from docx import Document
    full=Document(DocxReportEngine().render(report,tmp_path/'full.docx'))
    full_text=''.join(full.element.xpath('//w:t/text()')).replace('\u200b','')
    assert "full-snapshot-name" in full_text
    expected_time = datetime.fromisoformat("2026-09-20T01:02:03.123456+00:00").astimezone().strftime("%Y-%m-%d %H:%M")
    assert "".join(expected_time.split()) in ''.join(full_text.split())
    assert "2026-09-20T01:02:03.123456+00:00" not in compact
    assert "按对象类型统计发现" not in text
    assert "跨规则重复" not in text
    assert "证书到期信息" not in text
    assert "日期来源" not in text
    assert customer_display_facts(report)['snapshots']['threshold_label']=='7 天及以上'
    assert "含关机虚拟机和模板" in compact
    for placeholder in ("未采集", "未确认", "待确认", "整体正常", "总体正常"):
        assert placeholder not in text


def test_pdf_execution_statistics_use_common_records_without_vsan_summary_additions() -> None:
    report, context = _report()
    context["object_results"] = [
        {"rule_id": "VSL-DS-020", "rule_name": "vSAN 数据存储健康", "object_type": "Datastore",
         "object_key": "ds-1", "object_name": "DS01", "result_status": "passed", "risk_level": "P2"},
        {"rule_id": "VSL-VM-001", "rule_name": "快照保留", "object_type": "VirtualMachine",
         "object_key": "vm-1", "object_name": "app-01", "result_status": "failed", "risk_level": "P2"},
        {"rule_id": "VSL-HOST-019", "rule_name": "物理链路", "object_type": "HostSystem",
         "object_key": "host-1", "object_name": "esxi-01", "result_status": "failed", "risk_level": "P3"},
        {"rule_id": "VSL-VM-005", "rule_name": "内存指标", "object_type": "VirtualMachine",
         "object_key": "vm-2", "object_name": "off-01", "result_status": "not_applicable", "risk_level": "P3"},
    ]
    context["vsan_summary"]["report_categories"] = [
        {"category_id": "derived-health", "title": "vSAN 已验证摘要", "status": "正常"}]
    ensure_report(report, context)
    before_report = deepcopy(report.model_dump(mode="json"))
    before_context = deepcopy(context)
    expected = customer_check_statistics(report, context)

    payload = PdfReportEngine()._build_payload(report, context)

    assert payload["customer_statistics"] == expected
    assert (payload["scope"]["total_checks"], payload["scope"]["passed_checks"],
            payload["scope"]["problem_checks"]) == (3, 1, 2)
    assert sum(row["total"] for row in payload["scope"]["range_rows"]) == 3
    assert sum(row["count"] for row in payload["scope"]["level_distribution"]) == 2
    assert payload["scope"]["summary_text"] == expected["text"]
    assert payload["scope"]["visible_result_counts"] == {"passed": 1, "failed": 2}
    assert payload["scope"]["visible_result_total"] == 3
    assert "vSAN" not in {row["name"] for row in payload["scope"]["range_rows"]}
    assert report.model_dump(mode="json") == before_report
    assert context == before_context


def test_local_problem_appendix_follows_shared_object_keys_without_removing_assets() -> None:
    report, context = _report()
    vm = report.asset_inventory["details"]["VirtualMachine"][0]
    vm["object_key"] = "vm-1"
    vm["properties"].update(vm_on_local_datastore=True, local_datastore_names=["local-01"], is_system_vm=False)
    other = deepcopy(vm)
    other.update(object_key="vm-2", object_name="inventory-template")
    other["properties"]["is_template"] = True
    report.asset_inventory["details"]["VirtualMachine"].append(other)
    report.findings = [FindingItem(
        risk_level="P3", rule_id="VSL-VM-023", rule_name="本地存储", title="虚拟机磁盘存放在本地存储",
        object_type="VirtualMachine", object_name="app-01", status="failed", evidence={"object_key": "vm-1"})]
    ensure_report(report, context)
    before = deepcopy(report.asset_inventory)

    payload = PdfReportEngine()._build_payload(report, context)

    assert [row["name"] for row in payload["appendix"]["local_datastore_vms"]] == ["app-01"]
    assert len(report.asset_inventory["details"]["VirtualMachine"]) == 2
    assert report.asset_inventory == before


def test_local_appendix_excludes_scoped_template_projection_but_retains_raw_inventory() -> None:
    report, context = _report()
    report.report_info.run_id = RUN
    report.asset_inventory["details"]["vCenter"] = [asset("vCenter", UUID)]
    report.asset_inventory["details"]["VirtualMachine"] = [
        asset("VirtualMachine", "normal", is_template=False, is_system_vm=False,
              vm_on_local_datastore=True, local_datastore_names=["local-01"]),
        asset("VirtualMachine", "template", is_template=True, is_system_vm=False,
              vm_on_local_datastore=True, local_datastore_names=["local-01"]),
    ]
    records = [result("VSL-VC-001", "vCenter", UUID),
               result("VSL-VM-023", "VirtualMachine", "normal", "failed"),
               result("VSL-VM-023", "VirtualMachine", "template", "failed")]
    report.caliber_inputs = {"object_results": records, "findings": deepcopy(records[1:])}
    before_assets, before_inputs = deepcopy(report.asset_inventory), deepcopy(report.caliber_inputs)

    payload = PdfReportEngine()._build_payload(report, context)

    assert [row["name"] for row in payload["appendix"]["local_datastore_vms"]] == ["normal"]
    assert {row["name"] for item in payload["problems"] if item["rule_id"] == "VM-LOCAL-DATASTORE"
            for row in item["evidence_rows"]} == {"normal"}
    assert len(report.asset_inventory["details"]["VirtualMachine"]) == 2
    assert report.asset_inventory == before_assets
    assert report.caliber_inputs == before_inputs
    assert report.caliber_inputs["object_results"][2]["result_status"] == "failed"


def test_real_pdf_long_top5_denominators_have_separate_host_lines(tmp_path: Path) -> None:
    report, context = _report()
    host_ip = "192.168.100.100"
    report.asset_inventory["details"]["HostSystem"][0]["object_name"] = host_ip
    report.asset_inventory["details"]["VirtualMachine"][0]["properties"]["host_name"] = host_ip
    output = PdfReportEngine().render(report, tmp_path / "top5-long-scope.pdf", report_context=context)
    from vstacklens.reports.document_model import get_document
    top=[n for s in get_document(report,context)['sections'] if s['kind']=='environment'
         for n in s['blocks'] if n['id'] in {'top_vcpu','top_capacity','top_cpu','top_memory'}]
    assert len(top)==4
    for node in top:
        assert '主机' in node['headers'] and node['notes']
        assert host_ip in ''.join(row['cells'][node['headers'].index('主机')] for row in node['rows'])
        assert all(host_ip not in note for note in node['notes'])
    checked = 0
    with pymupdf.open(output) as document:
        for page in document:
            lines = [("".join(span["text"] for span in line["spans"]), line["bbox"])
                     for block in page.get_text("dict")["blocks"] if "lines" in block for line in block["lines"]]
            for text,bbox in lines:
                if host_ip in text.replace('\u200b',''):
                    assert 0<=bbox[0]<bbox[2]<=page.rect.width and 0<=bbox[1]<bbox[3]<=page.rect.height
                    checked+=1
    assert checked>=4 # All four rankings retain a distinct host column.


@pytest.mark.parametrize("source", ["absent", "unavailable-only", "passed-and-unavailable"])
def test_real_pdf_statistics_require_explicit_results_and_never_claim_all_passed(tmp_path: Path, source: str) -> None:
    report, context = _report()
    records = []
    if source != "absent":
        records.append({"rule_id": "VSL-VM-005", "rule_name": "内存运行指标", "object_type": "VirtualMachine",
                        "object_key": "vm-1", "object_name": "app-01", "result_status": "unavailable", "risk_level": "P2"})
    if source == "passed-and-unavailable":
        records.append({"rule_id": "VSL-DS-020", "rule_name": "vSAN 数据存储健康", "object_type": "Datastore",
                        "object_key": "ds-1", "object_name": "DS01", "result_status": "passed", "risk_level": "P2"})
    report.caliber_inputs["object_results"] = records
    report.environment_summary.result_status_summary = {"unavailable": int(source != "absent")}

    text = _read_pdf(PdfReportEngine().render(report, tmp_path / f"statistics-{source}.pdf", report_context=context))
    compact = "".join(text.split())

    if source == "passed-and-unavailable":
        assert "本次共检查1条，通过1条，未通过0条。" in compact
    else:
        assert "巡检范围结果" not in compact
        assert "明确判定结果条数" not in compact
        assert "各检查范围结果" not in compact
        assert "本次共检查0条" not in compact
    for unsupported_claim in ("全部通过", "已记录的明确结果均通过", "本次没有可展示的检查结果", "仍存在不可用或未覆盖检查"):
        assert unsupported_claim not in compact


@pytest.mark.parametrize("known_zero", [False, True])
def test_real_pdf_vsan_missing_metrics_hide_labels_but_known_zero_is_visible(tmp_path: Path, known_zero: bool) -> None:
    report, context = _report()
    report.vsan_summary = {"status": "collected", "clusters": ["Cluster-A"], "capacity": {}}
    if known_zero:
        report.vsan_summary.update(capacity={"total_gb": 100, "used_gb": 0, "free_gb": 100, "used_percent": 0},
                                   resync_object_count=0, resync_bytes=0)
    context["vsan_summary"] = report.vsan_summary

    text = _read_pdf(PdfReportEngine().render(report, tmp_path / f"vsan-{known_zero}.pdf", report_context=context))
    compact = "".join(text.split())

    if known_zero:
        assert "容量使用率0.0%" in compact
        assert "重同步对象0个" in compact and "重同步数据0.0GB" in compact
    else:
        assert "vSAN容量使用" not in compact
        assert "vSAN重同步" not in compact
        assert "Resync状态" not in compact
