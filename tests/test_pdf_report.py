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
                risk_level="P2", rule_id="VSL-VM-020", rule_name="CPU Ready", title="虚拟机 CPU Ready 过高",
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
                rule_id="VSL-VM-020",
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
    assert payload["top_cpu"][0]["display"] == "1,250 MHz"
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
    assert "500 天" in payload["certificates"]["vcenter"]["expiry_display"]


def test_pdf_engine_stages_json_and_publishes_typst_output(tmp_path: Path, monkeypatch) -> None:
    report, context = _report()
    output = tmp_path / "安澜-虚拟化巡检报告-20260927.pdf"
    captured: dict = {}
    engine = PdfReportEngine()
    monkeypatch.setattr(engine, "_typst_binary", lambda: Path("typst.exe"))

    def fake_run(command, **kwargs):
        root = Path(command[command.index("--root") + 1])
        captured["template"] = (root / "inspection-report.typ").read_text(encoding="utf-8")
        captured["payload"] = __import__("json").loads((root / "payload.json").read_text(encoding="utf-8"))
        Path(command[-1]).write_bytes(b"%PDF-1.7\nfixture")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("vstacklens.reports.pdf_report.subprocess.run", fake_run)
    result = engine.render(report, output, report_context=context)

    assert result == output
    assert output.read_bytes().startswith(b"%PDF-1.7")
    assert "json(\"payload.json\")" in captured["template"]
    assert captured["payload"]["problem_count"] == 1


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
