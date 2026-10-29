from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path
from types import SimpleNamespace

from vstacklens.reports.pdf_report import PdfReportEngine
from vstacklens.reports.report_model import (
    CustomerInfo,
    EnvironmentSummary,
    FindingItem,
    HealthScore,
    ReportData,
    ReportInfo,
    RemediationItem,
    RiskSummary,
)


def _report() -> tuple[ReportData, dict]:
    report = ReportData(
        report_info=ReportInfo(report_id="report-pdf", generated_at="2026-09-27T09:00:00+08:00", run_id="run-pdf"),
        customer_info=CustomerInfo(customer_name="安澜", site_name="测试站点", vcenter="vcsa.test.local"),
        environment_summary=EnvironmentSummary(scope_statement="本次巡检", checked_object_total=4),
        health_score=HealthScore(score=95, grade="A", explanation="运行正常"),
        risk_summary=RiskSummary(P2=3, total=3),
        asset_inventory={
            "summary": {"vCenter": 1, "ClusterComputeResource": 1, "HostSystem": 1, "VirtualMachine": 1, "Datastore": 1},
            "total": 5,
            "details": {
                "vCenter": [{"object_name": "vcsa.test.local", "properties": {"certificate_days_remaining": 500}}],
                "ClusterComputeResource": [{
                    "object_name": "Cluster-A",
                    "properties": {"ha_enabled": True, "drs_enabled": True, "maintenance_hosts": []},
                }],
                "HostSystem": [{
                    "object_name": "esxi-01",
                    "properties": {
                        "asset_location": "vcsa.test.local / DC / Cluster-A",
                        "connection_state": "connected",
                        "cpu_usage_avg": 20,
                        "memory_usage_avg": 30,
                        "host_pcpu_count": 16,
                        "host_memory_capacity_mb": 65536,
                        "host_certificate_not_after": "2028-01-01",
                        "host_certificate_days_remaining": 826,
                        "host_license_name": "vSphere Enterprise Plus",
                        "host_license_expiration_date": "永久授权",
                    },
                }],
                "VirtualMachine": [{
                    "object_name": "app-01",
                    "properties": {
                        "asset_location": "vcsa.test.local / DC / Cluster-A / 主机 esxi-01",
                        "power_state": "poweredOn",
                        "snapshots": [],
                        "cpu_usage_mhz": 1250,
                        "memory_usage_mb": 4096,
                        "vcpu_count": 4,
                        "vmdk_inventory": [{"capacity_bytes": 40 * 1024**3}],
                    },
                }],
                "Datastore": [{
                    "object_name": "DS01",
                    "properties": {
                        "used_percent": 72,
                        "datastore_used_gb": 72,
                        "datastore_capacity_gb": 100,
                        "datastore_free_gb": 28,
                        "datastore_cluster_names": ["Cluster-A"],
                    },
                }],
            },
        },
        vsan_summary={
            "status": "collected",
            "clusters": ["Cluster-A"],
            "capacity": {"total_gb": 100, "used_gb": 25, "free_gb": 75, "used_percent": 25},
            "disk_details": [{"host": "esxi-01", "health": "正常"}],
            "physical_disks": [{"name": "naa.test"}],
            "object_count": 100,
            "vmdk_count": 12,
            "resync_object_count": 0,
            "resync_bytes": 0,
        },
        findings=[
            FindingItem(
                risk_level="P2", rule_id="VSL-VM-004", rule_name="CPU Ready", title="虚拟机 CPU Ready 过高",
                object_type="VirtualMachine", object_name="app-01", status="failed",
                consequence="业务负载可能出现响应变慢。", remediation="结合业务峰值复核 vCPU 配置。",
            ),
            FindingItem(
                risk_level="P3", rule_id="VSL-VM-003", rule_name="VMware Tools", title="虚拟机未安装 VMware Tools",
                object_type="VirtualMachine", object_name="app-01", status="failed",
            ),
            FindingItem(
                risk_level="P3", rule_id="VSL-HOST-014", rule_name="Syslog", title="ESXi 主机未配置远程 Syslog",
                object_type="HostSystem", object_name="esxi-01", status="failed",
            ),
        ],
        remediation_plan=[
            RemediationItem(
                risk_level="P2",
                rule_id="VSL-VM-004",
                title="虚拟机 CPU Ready 过高",
                object_count=1,
                owner_role="virtualization_admin",
                effort="medium",
                maintenance_window_required=False,
                verification_method="rerun_rule",
                steps=["结合业务峰值复核 vCPU 配置。"],
            ),
        ],
    )
    context = {
        "run_timing": {"started_at": "2026-09-27T09:00:00+08:00"},
        "vsan_summary": report.vsan_summary,
        "appendix": {"certificate_license_evidence": []},
    }
    return report, context


def test_pdf_payload_uses_report_model_directly_and_filters_excluded_findings() -> None:
    report, context = _report()

    payload = PdfReportEngine()._build_payload(report, context)

    assert payload["problem_count"] == 1
    assert [item["title"] for item in payload["problems"]] == ["虚拟机 CPU Ready 过高"]
    assert payload["counts"]["clusters"] == 1
    assert payload["counts"]["hosts"] == 1
    assert payload["counts"]["vms"] == 1
    assert payload["top_cpu"][0]["display"] == "1.25 GHz"
    assert payload["top_cpu"][0]["host_share_pct"] == 100.0
    assert payload["top_cpu"][0]["host_share_scope"] == "同主机 VM CPU 用量占比"
    assert payload["top_memory"][0]["display"] == "4.0 GB"
    assert payload["top_memory"][0]["host_share_pct"] == 100.0
    assert payload["top_memory"][0]["host_share_scope"] == "同主机 VM 内存用量占比"
    assert payload["top_capacity"][0]["display"] == "40.0 GB"
    assert payload["top_capacity"][0]["host_share_pct"] == 100.0
    assert payload["top_capacity"][0]["host_share_scope"] == "同机已采集 VM 分配容量占比"
    assert payload["top_vcpu"][0]["display"] == "4 vCPU"
    assert payload["top_vcpu"][0]["host_share_pct"] == 100.0
    assert payload["top_vcpu"][0]["host_share_scope"] == "占同主机 VM 配置 vCPU 总数"
    assert payload["problems"][0]["count_label"] == "1 台虚拟机"
    assert payload["vsan"]["no_resync"] is True
    assert payload["scope"]["visible_rule_count"] == 0
    assert payload["network"]["vmkernel_count"] == 0
    assert payload["narratives"]["executive"].startswith("本次覆盖 1 个集群")
    assert "健康评分" not in str(payload)
    assert "VMware Tools" not in payload["narratives"]["scope"]
    assert "Syslog" not in payload["narratives"]["scope"]
    assert all("VMware Tools" not in item["title"] and "Syslog" not in item["title"] for item in payload["problems"])
    assert payload["certificates"]["hosts"][0]["expiry"].startswith("2028-01-01")
    assert payload["certificates"]["vcenter"]["expiry"] == (date(2026, 9, 27) + timedelta(days=500)).isoformat()


def test_pdf_cluster_drs_behavior_uses_chinese_customer_labels() -> None:
    for raw, expected in (
        ("fullyAutomated", "全自动"),
        ("partiallyAutomated", "部分自动化"),
        ("manual", "手动"),
    ):
        report, context = _report()
        report.asset_inventory["details"]["ClusterComputeResource"][0]["properties"]["drs_behavior"] = raw
        payload = PdfReportEngine()._build_payload(report, context)
        assert payload["cluster_details"][0]["drs_behavior"] == expected
    assert "500 天" in payload["certificates"]["vcenter"]["expiry_display"]


def test_pdf_payload_scope_counts_are_p123_only_and_p4_is_not_presented() -> None:
    report, context = _report()
    report.findings.append(FindingItem(
        risk_level="P4", rule_id="VSL-VM-015", rule_name="Hardware version", title="P4 不应展示",
        object_type="VirtualMachine", object_name="app-01", status="failed",
    ))
    report.remediation_plan.append(RemediationItem(
        risk_level="P4", rule_id="VSL-VM-015", title="P4 不应展示", object_count=1,
        owner_role="virtualization_admin", effort="low", maintenance_window_required=False,
        verification_method="manual_check", steps=["仅用于测试"],
    ))
    context["rule_catalog"] = [
        {"rule_id": "VSL-VC-002", "risk_level": "P1", "category": "vcenter"},
        {"rule_id": "VSL-HOST-005", "risk_level": "P1", "category": "host"},
        {"rule_id": "VSL-VM-004", "risk_level": "P2", "category": "vm"},
        {"rule_id": "VSL-VM-015", "risk_level": "P4", "category": "vm"},
    ]
    context["object_results"] = [
        {"rule_id": "VSL-VC-002", "risk_level": "P1", "category": "vcenter", "object_type": "vCenter", "result_status": "passed"},
        {"rule_id": "VSL-HOST-005", "risk_level": "P1", "category": "host", "object_type": "HostSystem", "result_status": "passed"},
        {"rule_id": "VSL-VM-004", "category": "vm", "object_type": "VirtualMachine", "object_name": "app-01", "risk_level": "P2", "result_status": "failed"},
        {"rule_id": "VSL-VM-015", "risk_level": "P4", "category": "vm", "object_type": "VirtualMachine", "result_status": "failed"},
    ]

    payload = PdfReportEngine()._build_payload(report, context)

    assert payload["scope"]["total_checks"] == 3
    assert payload["scope"]["passed_checks"] == 2
    assert payload["scope"]["problem_checks"] == 1
    assert [item["name"] for item in payload["scope"]["range_rows"]] == ["vCenter 管理平台", "ESXi 主机", "虚拟机"]
    assert payload["scope"]["summary_text"] == "本次共检查 3 条，通过 2 条，未通过 1 条。"
    assert payload["optimization_count"] == 0
    assert all(item["level"] in {"P1", "P2", "P3"} for item in payload["problems"])
    assert all(item["title"] != "P4 不应展示" for item in payload["problems"])


def test_pdf_scope_counts_physical_link_checks_by_saved_object_type() -> None:
    report, context = _report()
    context["rule_catalog"] = [
        {"rule_id": "VSL-HOST-019", "risk_level": "P2", "category": "host"},
    ]
    context["object_results"] = [
        {
            "rule_id": "VSL-HOST-019",
            "risk_level": "P2",
            "category": "host",
            "object_type": "HostSystem",
            "result_status": "passed",
        },
    ]

    payload = PdfReportEngine()._build_payload(report, context)

    host_row = next(row for row in payload["scope"]["range_rows"] if row["name"] == "ESXi 主机")
    assert host_row["total"] == 1
    assert host_row["passed"] == 1
    assert host_row["problems"] == 0
    assert not any(row["name"] == "网络" for row in payload["scope"]["range_rows"])


def test_pdf_scope_failure_chart_and_top_five_reconcile_to_failed_total() -> None:
    report, context = _report()
    checks = [
        ("VSL-HOST-001", "检查 A", "host", "HostSystem", "P1", 3),
        ("VSL-VC-001", "检查 B", "vcenter", "vCenter", "P1", 2),
        ("VSL-VM-001", "检查 C", "vm", "VirtualMachine", "P2", 2),
        ("VSL-VM-010", "检查 D", "vm", "VirtualMachine", "P3", 2),
        ("VSL-CL-009", "检查 E", "cluster", "ClusterComputeResource", "P3", 1),
        ("VSL-DS-008", "检查 F", "datastore", "Datastore", "P3", 1),
    ]
    context["rule_catalog"] = [
        {"rule_id": rule_id, "check_name": name, "risk_level": level, "category": category}
        for rule_id, name, category, _object_type, level, _count in checks
    ]
    context["object_results"] = [
        {
            "rule_id": rule_id,
            "check_name": name,
            "risk_level": _level,
            "category": category,
            "object_type": object_type,
            "result_status": "failed",
        }
        for rule_id, name, category, object_type, _level, count in checks
        for _ in range(count)
    ]

    payload = PdfReportEngine()._build_payload(report, context)
    scope = payload["scope"]

    assert scope["problem_checks"] == 11
    assert scope["level_distribution"] == [
        {"level": "P1", "count": 5, "share_pct": 45.5, "share_pct_text": "45.5%"},
        {"level": "P2", "count": 2, "share_pct": 18.2, "share_pct_text": "18.2%"},
        {"level": "P3", "count": 4, "share_pct": 36.4, "share_pct_text": "36.4%"},
    ]
    assert [item["name"] for item in scope["top_failed_checks"]] == [
        "检查 A", "检查 B", "检查 C", "检查 D", "检查 E",
    ]
    assert [item["failed"] for item in scope["top_failed_checks"]] == [3, 2, 2, 2, 1]
    assert sum(item["count"] for item in scope["level_distribution"]) == scope["problem_checks"]
    assert sum(item["failed"] for item in scope["top_failed_checks"]) == 10
    assert not any("RULE-" in str(item) for item in scope["top_failed_checks"])


def test_pdf_zero_failed_results_use_all_passed_state_without_top_five() -> None:
    report, context = _report()
    context["rule_catalog"] = [
        {"rule_id": "VSL-VM-018", "check_name": "虚拟机电源状态", "risk_level": "P3", "category": "vm"},
    ]
    context["object_results"] = [
        {
            "rule_id": "VSL-VM-018",
            "risk_level": "P3",
            "check_name": "虚拟机电源状态",
            "category": "vm",
            "object_type": "VirtualMachine",
            "result_status": "passed",
        },
    ]

    payload = PdfReportEngine()._build_payload(report, context)
    scope = payload["scope"]

    assert scope["problem_checks"] == 0
    assert scope["all_passed"] is True
    assert scope["top_failed_checks"] == []
    assert all(item["count"] == 0 and item["share_pct"] == 0 for item in scope["level_distribution"])
    svg = PdfReportEngine()._scope_level_donut_svg(scope)
    assert 'stroke="#398260"' in svg
    assert 'stroke="#B84545"' not in svg
    assert "全部" in svg and "通过" in svg


def test_pdf_scope_with_no_results_is_not_mislabeled_as_all_passed() -> None:
    report, context = _report()
    context["rule_catalog"] = []
    context["object_results"] = []

    payload = PdfReportEngine()._build_payload(report, context)
    scope = payload["scope"]

    assert scope["no_results"] is True
    assert scope["all_passed"] is False
    assert scope["top_failed_checks"] == []
    svg = PdfReportEngine()._scope_level_donut_svg(scope)
    assert 'stroke="#607387"' in svg
    assert "无检查" in svg and "结果" in svg


def test_pdf_merged_snapshot_issue_keeps_highest_severity_and_deduplicates_vm() -> None:
    report, context = _report()
    report.findings.extend([
        FindingItem(
            risk_level="P1", rule_id="VSL-VM-001", rule_name="超期快照", title="虚拟机存在超期快照",
            object_type="VirtualMachine", object_name="app-01", status="failed",
            object_path="vcsa.test.local / DC / Cluster-A / app-01",
        ),
        FindingItem(
            risk_level="P3", rule_id="VSL-VM-007", rule_name="快照链深度", title="虚拟机快照链过深",
            object_type="VirtualMachine", object_name="app-01", status="failed",
            object_path="vcsa.test.local / DC / Cluster-A / app-01",
        ),
    ])
    report.remediation_plan.extend([
        RemediationItem(risk_level="P1", rule_id="VSL-VM-001", title="虚拟机存在超期快照", object_count=1),
        RemediationItem(risk_level="P3", rule_id="VSL-VM-007", title="虚拟机快照链过深", object_count=1),
    ])
    context["rule_catalog"] = [
        {"rule_id": "VSL-VM-001", "risk_level": "P1", "category": "vm"},
        {"rule_id": "VSL-VM-007", "risk_level": "P3", "category": "vm"},
    ]

    payload = PdfReportEngine()._build_payload(report, context)

    snapshot = [item for item in payload["problems"] if item["title"] == "虚拟机存在快照"]
    assert len(snapshot) == 1
    # Preserve the captured P1 result; today's snapshot policy must not regrade it.
    assert snapshot[0]["level"] == "P1"
    assert snapshot[0]["count"] == 1


def test_pdf_powered_off_problem_notes_excluded_templates_and_sanitizes_service_name() -> None:
    report, context = _report()
    report.asset_inventory["details"]["VirtualMachine"] = [
        {
            "object_name": f"vm-{index:02d}",
            "object_path": f"vcsa.test.local / Cluster-A / vm-{index:02d}",
            "properties": {
                "asset_location": "vcsa.test.local / Cluster-A",
                "power_state": "poweredOff",
                "is_template": index < 6,
                "is_system_vm": False,
                "datastore_names": ["DS01"],
                "local_datastore_names": [],
                "vm_on_local_datastore": False,
                "storage_committed_bytes": 1024**3,
                "vmdk_inventory": [],
                "vcpu_count": 1,
            },
        }
        for index in range(15)
    ]
    report.findings = [FindingItem(
        risk_level="P3", rule_id="VSL-VM-018", rule_name="存在关机的虚拟机",
        title="存在关机的虚拟机", object_type="VirtualMachine", object_name="vm-06", status="failed",
        business_impact="环境中存在关机的虚拟机。",
    )]
    report.remediation_plan = [RemediationItem(
        risk_level="P3", rule_id="VSL-VM-018", title="存在关机的虚拟机", object_count=9,
        owner_role="virtualization_admin", effort="low", maintenance_window_required=False,
        verification_method="manual_check", steps=["停止 TSM-SSH 服务并复核。"],
    )]

    payload = PdfReportEngine()._build_payload(report, context)
    issue = next(item for item in payload["problems"] if item["title"] == "存在关机的虚拟机")

    assert len(payload["appendix"]["powered_off_vms"]) == 9
    assert "另有 6 台关机的模板或系统虚拟机，不计入。" in issue["current"]
    assert "另有 6 台关机的模板或系统虚拟机，不计入。" not in issue["impact"]
    assert "TSM-SSH" not in " ".join(issue["steps"])
    assert any("停止 SSH 服务" in step for step in issue["steps"])


def test_pdf_payload_builds_snapshot_appendices_filters_unused_nics_and_summarizes_disks() -> None:
    report, context = _report()
    host_props = report.asset_inventory["details"]["HostSystem"][0]["properties"]
    host_props.update({
        "physical_nic_details": [
            {"device": "vmnic0", "is_in_use": False, "link_state": "down", "assessment": "unused", "issue_codes": []},
            {
                "device": "vmnic1", "is_in_use": True, "link_state": "down", "assessment": "down",
                "issue_codes": ["link_down"], "portgroup_usage": [{"portgroup": "Management Network", "role": "active"}],
            },
        ],
        "pnic_down_count": 1,
    })
    report.asset_inventory["details"]["VirtualMachine"].extend([
        {
            "object_name": "off-iso-snapshot-local",
            "object_path": "vcsa.test.local / DC / Cluster-A / esxi-01 / off-iso-snapshot-local",
            "properties": {
                "asset_location": "vcsa.test.local / DC / Cluster-A / esxi-01",
                "power_state": "poweredOff",
                "is_template": False,
                "is_system_vm": False,
                "iso_mounted": True,
                "iso_paths": ["[DS01] images/installer.iso"],
                "snapshots": [{"name": "snap-1"}],
                "snapshot_age_days_max": 120,
                "snapshot_chain_depth": 4,
                "datastore_names": ["DS01"],
                "local_datastore_names": ["local-01"],
                "vm_on_local_datastore": True,
                "storage_committed_bytes": 50 * 1024**3,
                "powered_off_days": None,
                "vmdk_inventory": [{"capacity_bytes": 60 * 1024**3}],
                "vmdk_count": 1,
                "vcpu_count": 2,
            },
        },
        {
            "object_name": "vCLS-test",
            "object_path": "vcsa.test.local / DC / Cluster-A / esxi-01 / vCLS-test",
            "properties": {
                "asset_location": "vcsa.test.local / DC / Cluster-A / esxi-01",
                "power_state": "poweredOn",
                "is_system_vm": True,
                "cpu_usage_mhz": 9000,
                "memory_usage_mb": 9000,
                "vcpu_count": 2,
                "vmdk_inventory": [],
                "vmdk_count": 0,
            },
        },
    ])
    report.vsan_summary["disk_details"] = [
        {"host": "esxi-01", "disk_group": "DG1", "role": "容量盘", "device": "naa.normal-1", "health": "正常"},
        {"host": "esxi-01", "disk_group": "DG1", "role": "容量盘", "device": "naa.normal-2", "health": "green"},
        {"host": "esxi-01", "disk_group": "DG1", "role": "缓存盘", "device": "naa.bad-1", "health": "degraded"},
    ]

    payload = PdfReportEngine()._build_payload(report, context)

    assert payload["snapshot_max_age_text"] == "120 天"
    assert payload["snapshot_distribution"] == [{"cluster": "Cluster-A", "count": 1, "bar_pct": 100.0}]
    assert payload["oldest_snapshots"][0]["name"] == "off-iso-snapshot-local"
    assert payload["network"]["pnic_anomaly_count"] == 1
    assert payload["network"]["pnic_anomalies"][0]["device"] == "vmnic1"
    assert payload["network"]["pnic_anomalies"][0]["portgroups"] == "Management Network（活动）"
    assert len(payload["vsan"]["disk_details"]) == 3
    assert {item["device"] for item in payload["vsan"]["disk_details"]} == {"naa.normal-1", "naa.normal-2", "naa.bad-1"}
    assert all(not item["normal_summary"] and item["disk_count"] == 1 for item in payload["vsan"]["disk_details"])
    assert any(not item["normal_summary"] and item["device"] == "naa.bad-1" for item in payload["vsan"]["disk_details"])
    assert payload["appendix"]["iso_vms"][0]["iso_paths"] == "[DS01] images/installer.iso"
    assert len(payload["appendix"]["powered_off_vms"]) == 1
    assert payload["appendix"]["powered_off_days_column"] is False
    assert payload["appendix"]["powered_off_capacity_column"] is True
    assert len(payload["appendix"]["snapshot_vms"]) == 1
    # Inventory evidence alone must not create a customer problem appendix.
    # The VM-023 positive case and scoped template exclusion are covered in
    # test_report_batch2_pdf_20261023.py.
    assert payload["appendix"]["local_datastore_vms"] == []
    assert payload["top_cpu"][0]["name"] == "app-01"


def test_pdf_engine_stages_json_and_publishes_typst_output(tmp_path: Path, monkeypatch) -> None:
    report, context = _report()
    output = tmp_path / "安澜-虚拟化巡检报告-20260927.pdf"
    captured: dict = {}
    engine = PdfReportEngine()
    monkeypatch.setattr(engine, "_typst_binary", lambda: Path("typst.exe"))

    def fake_run(command, **kwargs):
        root = Path(command[command.index("--root") + 1])
        captured["template"] = (root / "document.typ").read_text(encoding="utf-8")
        captured["payload"] = __import__("json").loads((root / "document.json").read_text(encoding="utf-8"))
        import pymupdf
        with pymupdf.open() as pdf:
            pdf.new_page().insert_text((30, 30), "Offline clean report fixture")
            pdf.save(Path(command[-1]))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("vstacklens.reports.pdf_report.subprocess.run", fake_run)
    result = engine.render(report, output, report_context=context)

    assert result == output
    assert output.read_bytes().startswith(b"%PDF-")
    assert "json(\"document.json\")" in captured["template"]
    assert captured["payload"]['counts']['categories'] == 1


def test_pdf_engine_refuses_to_overwrite_existing_file(tmp_path: Path) -> None:
    report, context = _report()
    output = tmp_path / "existing.pdf"
    output.write_bytes(b"keep")

    try:
        PdfReportEngine().render(report, output, report_context=context)
    except FileExistsError:
        pass
    else:
        raise AssertionError("Existing PDF should not be overwritten")
    assert output.read_bytes() == b"keep"
