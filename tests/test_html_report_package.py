import json
import re
import zipfile
from pathlib import Path

from vstacklens.cli import cmd_run_mock
from vstacklens.db.connection import connect
from vstacklens.reports.context_builder import ReportContextBuilder
from vstacklens.reports.html_assets import SINGLE_PAGE_REPORT_JS
from vstacklens.reports.html_package import HtmlReportPackageBuilder
from vstacklens.reports.report_model import ReportData, ReportDataFactory
from vstacklens.rules.rulepack_loader import RulePackLoader
from vstacklens.rules.schema_validator import SchemaValidator


ROOT = Path(__file__).resolve().parents[1]
RULEPACK = ROOT / "rulepacks" / "builtin-vsphere-v1"
FIXTURE = ROOT / "tests" / "fixtures" / "inventory_fail.json"


def test_run_mock_generates_five_chapter_offline_html_package(tmp_path: Path) -> None:
    report_dir = tmp_path / "report-package"
    args = type(
        "Args",
        (),
        {
            "db": str(tmp_path / "report-package.db"),
            "rulepack": str(RULEPACK),
            "fixture": str(FIXTURE),
            "report_dir": str(report_dir),
            "zip_report": True,
            "html_out": str(tmp_path / "legacy.html"),
            "docx_out": None,
        },
    )()
    cmd_run_mock(args)

    index_path = report_dir / "index.html"
    script_path = report_dir / "assets" / "report.js"
    css_path = report_dir / "assets" / "report.css"
    payload_path = report_dir / "data" / "customer_report_payload.json"
    assert index_path.exists() and script_path.exists() and css_path.exists() and payload_path.exists()
    assert report_dir.with_suffix(".zip").exists()
    index = index_path.read_text(encoding="utf-8")
    script = script_path.read_text(encoding="utf-8")
    css = css_path.read_text(encoding="utf-8")
    payload_text = payload_path.read_text(encoding="utf-8")
    compatibility_payload = json.loads(payload_text)
    embedded_payload = _embedded_payload(index)
    public_data_text = json.dumps(embedded_payload, ensure_ascii=False)
    ids = ("summary", "environment", "issues", "passed", "inventory")
    assert [index.find(f'href="#{section}"') for section in ids] == sorted(index.find(f'href="#{section}"') for section in ids)
    assert all(f'id="{section}" class="report-section"' in index for section in ids)
    assert all(label in index for label in ("总结", "环境", "问题", "已通过的检查", "环境清单"))
    for removed in ("总览", "历史对比", "整改跟踪", "Storage Policy 分类", "免责声明"):
        assert removed not in index + script + css + public_data_text
    for blocked in ("未确认", "缺字段", "不合规", "collected", "Health", "Capacity", "Network", "Resync", "Storage Policy"):
        assert blocked not in index + script + css + public_data_text
    for external in ("http://", "https://", "//cdn"):
        assert external not in index + script + css
    assert embedded_payload["summary"]["judgement"] in {"正常", "需关注"}
    assert set(embedded_payload["inventory"]) == {"hosts", "vms", "stores"}
    assert "rule_id" not in public_data_text and "result_status" not in public_data_text
    assert compatibility_payload["report_context"]["report_info"]["report_title"]


def test_single_page_problem_summary_uses_full_title_and_existing_copy() -> None:
    assert 'return `<tr><td class="problem-risk-${esc(item.level)}">${esc(item.level)}</td><td>${esc(item.title)}' in SINGLE_PAGE_REPORT_JS
    assert "summarySentence(item.current)" in SINGLE_PAGE_REPORT_JS
    assert "summarySentence(item.remediation)" in SINGLE_PAGE_REPORT_JS


def test_single_page_cluster_vm_tables_are_counted_and_collapsed_by_default() -> None:
    assert '<details><summary>虚拟机（${cluster.vms.length}）</summary>' in SINGLE_PAGE_REPORT_JS
    assert '虚拟机名称", "所在主机", "电源状态", "虚拟磁盘容量"' in SINGLE_PAGE_REPORT_JS


def test_single_page_passed_checks_exclude_problem_titles_and_duplicate_labels() -> None:
    builder = HtmlReportPackageBuilder()
    context = {
        "rule_checklist": [
            {"passed": 1, "failed": 0, "rule_name": "重复问题标题"},
            {"passed": 1, "failed": 0, "rule_name": "正常检查"},
            {"passed": 1, "failed": 0, "rule_name": "正常检查"},
            {"passed": 1, "failed": 0, "rule_name": "ESXi 主机 Syslog 配置"},
            {"passed": 1, "failed": 0, "rule_name": "虚拟机 VMware Tools 状态"},
        ],
        "vsan_summary": {
            "report_categories": [
                {"status": "正常", "title": "重复问题标题"},
                {"status": "正常", "title": "vSAN 磁盘健康"},
            ]
        },
    }

    assert builder._single_page_passed_checks(context, {"重复问题标题"}) == ["正常检查", "vSAN 磁盘健康"]


def test_single_page_customer_issues_exclude_vmware_tools_without_mutating_other_findings() -> None:
    builder = HtmlReportPackageBuilder()
    issues = builder._single_page_issues(
        [
            {"rule_id": "VSL-VM-003", "risk_level": "P3", "title": "虚拟机未安装 VMware Tools", "object_type": "VirtualMachine", "object_name": "vm-a"},
            {"rule_id": "VSL-HOST-014", "risk_level": "P3", "title": "ESXi 主机未配置远程 Syslog", "object_type": "HostSystem", "object_name": "esx-a"},
            {"rule_id": "VSL-CL-002", "risk_level": "P3", "title": "集群 DRS 未启用", "object_type": "ClusterComputeResource", "object_name": "Infra_Org"},
        ],
        {"cluster": [{"name": "Infra_Org", "location": "Datacenter / Infra_Org"}], "vm": [{"name": "vm-a", "cluster": "vSAN", "hostName": "esx-a"}]},
    )

    assert [item["title"] for item in issues] == ["集群 DRS 未启用"]


def test_single_page_vsan_summary_issues_include_actionable_items_but_not_storage_policy() -> None:
    builder = HtmlReportPackageBuilder()
    issues = builder._single_page_vsan_summary_issues(
        {
            "health_issues": [
                {
                    "component": "vSAN 集群健康",
                    "summary": "发现 1 项健康异常",
                    "impact": "可能影响集群可用性。",
                    "remediation": "检查健康异常明细并复核。",
                }
            ],
            "report_categories": [
                {"category_id": "VSAN-CAPACITY", "title": "vSAN 容量", "status": "需关注", "conclusion": "使用率 78%"},
                {"category_id": "VSAN-POLICY", "title": "vSAN Storage Policy 合规性", "status": "未确认", "conclusion": "不合规 未采集"},
                {"category_id": "VSAN-DISK", "title": "vSAN 磁盘", "status": "正常", "conclusion": "磁盘正常"},
            ],
        }
    )

    assert [item["title"] for item in issues] == ["vSAN 集群健康", "vSAN 容量"]
    assert issues[0]["impact"] == "可能影响集群可用性。"
    assert all("Storage Policy" not in item["title"] for item in issues)


def test_single_page_summary_narrative_and_issue_level_colors_are_scoped() -> None:
    css = HtmlReportPackageBuilder()._single_page_css()
    summary_start = SINGLE_PAGE_REPORT_JS.index("function renderSummary()")
    summary_end = SINGLE_PAGE_REPORT_JS.index("function renderVsanSummary", summary_start)
    summary_js = SINGLE_PAGE_REPORT_JS[summary_start:summary_end]

    assert "vCenter 环境目前运行正常，但存在以下情况需要处理：" in summary_js
    assert "vCenter 环境目前运行正常，本次未发现需要处理的情况。" in summary_js
    assert "vSAN 集群的配置和当前运行状况正常。" in SINGLE_PAGE_REPORT_JS
    assert "item.impact" in SINGLE_PAGE_REPORT_JS and "item.remediation" in SINGLE_PAGE_REPORT_JS
    assert "item.level" not in summary_js and "最高等级" not in summary_js
    assert 'class="problem-level problem-level-${level}"' in SINGLE_PAGE_REPORT_JS
    assert 'class="problem-block problem-block-${level}"' in SINGLE_PAGE_REPORT_JS
    for tone, color in (("low", "#248453"), ("mid", "#d49a18"), ("high", "#c43c42")):
        assert f".usage-track.storage.{tone} .used {{ background:{color}; }}" in css
    assert ".problem-level-P1 > summary { color:var(--red); }" in css
    assert ".problem-level-P2 > summary { color:var(--amber); }" in css
    assert ".problem-level-P3 > summary { color:var(--blue); }" in css
    assert ".problem-block-P1 { border-left-color:var(--red); }" in css
    assert ".problem-block-P2 { border-left-color:var(--amber); }" in css
    assert ".problem-block-P3 { border-left-color:var(--blue); }" in css


def test_single_page_certificate_dates_group_by_cluster_and_flag_three_months() -> None:
    builder = HtmlReportPackageBuilder()
    certificates = builder._single_page_certificates(
        {"run_timing": {"started_at": "2026-09-24T08:03:23+00:00"}},
        {
            "host": [
                {"name": "esx-a", "cluster": "Infra_Org", "licenseType": "vSphere Enterprise Plus"},
                {"name": "esx-b", "cluster": "vSAN", "licenseType": "vSphere Enterprise Plus"},
            ]
        },
        {"name": "vc.lab.local", "licenseDays": 40000},
        [
            {"category_label": "vCenter 证书状态", "object_name": "vc.lab.local", "current_value_zh": "剩余 609 天"},
            {"category_label": "ESXi 证书状态", "object_name": "esx-a", "current_value_zh": "剩余 1703 天", "explanation_zh": "到期时间为 2031-05-25。"},
            {"category_label": "ESXi 证书状态", "object_name": "esx-b", "current_value_zh": "剩余 89 天"},
        ],
    )

    assert certificates["vcenter"][0]["expiresOn"] == "2028-05-25"
    assert certificates["vcenter"][0]["remainingLabel"] == "1 年及以上"
    assert certificates["clusters"] == [
        {"name": "Infra_Org", "hosts": [{"name": "esx-a", "cluster": "Infra_Org", "expiresOn": "2031-05-25", "remainingDays": 1704, "remainingLabel": "1 年及以上", "imminent": False, "expired": False, "attention": False}]},
        {"name": "vSAN", "hosts": [{"name": "esx-b", "cluster": "vSAN", "expiresOn": "2026-12-22", "remainingDays": 89, "remainingLabel": "3 个月", "imminent": True, "expired": False, "attention": True}]},
    ]
    assert "vCenter 永久授权" in certificates["licenses"]


def test_single_page_certificate_and_problem_markup_has_requested_structure() -> None:
    assert 'class="problem-level problem-level-${level}"' in SINGLE_PAGE_REPORT_JS
    assert 'summary>${level}（${rows.length}）</summary>' in SINGLE_PAGE_REPORT_JS
    assert 'class="problem-item"' in SINGLE_PAGE_REPORT_JS
    assert '["等级", "问题", "数量", "涉及集群", "现状", "建议"]' in SINGLE_PAGE_REPORT_JS
    assert "<h3>巡检信息</h3>" in SINGLE_PAGE_REPORT_JS
    assert '"集群", "类型", "主机数", "HA", "DRS"' in SINGLE_PAGE_REPORT_JS
    css = HtmlReportPackageBuilder()._single_page_css()
    assert ".certificate-alert,.certificate-alert-text { color:var(--red); font-weight:700; }" in css
    assert ".problem-level-P1 > summary { color:var(--red); }" in css
    assert ".problem-level-P2 > summary { color:var(--amber); }" in css
    assert ".problem-level-P3 > summary { color:var(--blue); }" in css


def test_single_page_storage_folds_and_five_column_host_view() -> None:
    host_view = HtmlReportPackageBuilder._single_page_host_view(
        {
            "name": "esx-a",
            "model": "not shown",
            "version": "not shown",
            "connectionState": "connected",
            "maintenanceMode": False,
            "cpuPct": 10.0,
            "memoryPct": 20.0,
        }
    )

    assert host_view == {
        "name": "esx-a",
        "connectionState": "connected",
        "maintenanceMode": False,
        "cpuPct": 10.0,
        "memoryPct": 20.0,
    }
    assert '"健康", "连接", "CPU 使用率", "内存使用率"' in SINGLE_PAGE_REPORT_JS
    assert "cpu < 80 && memory < 80 ? \"正常\" : \"需关注\"" in SINGLE_PAGE_REPORT_JS
    assert 'class="cluster-storage"' in SINGLE_PAGE_REPORT_JS
    assert '${esc(cluster.name)} 数据存储（${num(stores.length)}）</summary>' in SINGLE_PAGE_REPORT_JS
    assert '<summary>vSAN 容量</summary>' in SINGLE_PAGE_REPORT_JS
    assert 'vSAN 磁盘组（${disks.length}）' in SINGLE_PAGE_REPORT_JS
    assert 'vSAN 网络（${adapters.length}）' in SINGLE_PAGE_REPORT_JS
    assert '<summary>vSAN 对象</summary>' in SINGLE_PAGE_REPORT_JS
    assert 'storageContent' not in SINGLE_PAGE_REPORT_JS
    assert 'section("主机", hosts, ["主机名", "健康", "连接", "CPU 使用率", "内存使用率"], hostRows)' in SINGLE_PAGE_REPORT_JS


def _legacy_run_mock_generates_customer_delivery_report_package_and_zip_without_legacy_preview(tmp_path: Path) -> None:
    report_dir = tmp_path / "report-package"
    args = type(
        "Args",
        (),
        {
            "db": str(tmp_path / "report-package.db"),
            "rulepack": str(RULEPACK),
            "fixture": str(FIXTURE),
            "report_dir": str(report_dir),
            "zip_report": True,
            "html_out": str(tmp_path / "legacy.html"),
            "docx_out": None,
        },
    )()

    cmd_run_mock(args)

    assert (report_dir / "index.html").exists()
    assert (report_dir / "assets" / "report.css").exists()
    assert (report_dir / "assets" / "report.js").exists()
    assert (report_dir / "data" / "customer_report_payload.json").exists()
    assert not (report_dir / "data" / "report_context.json").exists()
    assert not (report_dir / "data" / "inspection_results.json").exists()
    assert not (report_dir / "data" / "findings.json").exists()
    assert not (report_dir / "data" / "risk_group_summary.json").exists()
    assert not (report_dir / "data" / "assets.json").exists()
    assert not (report_dir / "data" / "rule_catalog.json").exists()
    assert not (report_dir / "data" / "capability_gaps.json").exists()
    assert not (report_dir / "data" / "unexecuted_rule_groups.json").exists()
    assert not (report_dir / "data" / "run_comparison.json").exists()
    assert not (report_dir / "data" / "inspection_result.json").exists()
    assert report_dir.with_suffix(".zip").exists()
    assert not (tmp_path / "legacy.html").exists()
    assert (tmp_path / "report-package_inspection_result.json").exists()
    with zipfile.ZipFile(report_dir.with_suffix(".zip")) as archive:
        names = set(archive.namelist())
    assert not any(name.endswith("inspection_result.json") for name in names)
    assert not any(name.endswith("inspection_results.json") for name in names)
    assert not any(name.endswith("rule_catalog.json") for name in names)

    index = (report_dir / "index.html").read_text(encoding="utf-8")
    script = (report_dir / "assets" / "report.js").read_text(encoding="utf-8")
    css = (report_dir / "assets" / "report.css").read_text(encoding="utf-8")
    payload_json = (report_dir / "data" / "customer_report_payload.json").read_text(encoding="utf-8")
    stored_payload = json.loads(payload_json)
    embedded_payload = _embedded_payload(index)
    embedded_text = json.dumps(embedded_payload, ensure_ascii=False)
    visible_package_text = index + script + css + embedded_text

    for external_reference in ("http://", "https://", "//cdn", "cdn."):
        assert external_reference not in index
        assert external_reference not in script
        assert external_reference not in css

    assert "VStackLens VMware 虚拟化健康评估报告" in index
    assert ">总览<" in index
    assert ">历史对比<" in index
    assert ">风险问题<" in index
    assert ">附录<" in index
    assert ">整改跟踪<" not in index
    assert ">正常项<" not in index
    assert ">资产清单<" not in index
    for removed_nav in [">巡检明细<", ">规则目录<", ">扩展检查项说明<"]:
        assert removed_nav not in index
    assert "inspection_result.json" not in index

    assert "整体状态" in script
    assert "健康评分" not in script
    assert "问题摘要" in script
    assert "影响对象" in script
    assert "健康评分扣分" not in script
    assert "P4 风险" not in visible_package_text
    assert "高风险数量" not in script
    assert "核验通过率" not in script
    assert "关键检查通过项摘要" not in script
    for removed_metric in [
        "规则目录总数",
        "本次默认执行规则",
        "对象级检查结果",
        "未执行扩展检查项",
        "已批准例外风险",
        "不可判定项",
        "不适用项",
        "对象通过率",
    ]:
        assert removed_metric not in script

    assert "环境规模" in script
    assert "重点关注" in script
    assert "巡检模式" not in script
    assert "规则包版本" not in script
    assert "工具版本" not in script
    assert "采集开始时间" not in script
    assert "采集结束时间" not in script
    assert "vCenter build" not in script

    assert "P1" in script and "P2" in script and "P3" in script
    assert "P4" not in visible_package_text
    assert "((risk.P1 || 0) + (risk.P2 || 0) + (risk.P3 || 0))" in script
    assert "+ (risk.P4 || 0))" not in script
    assert "检查覆盖 / 正常项" in script
    assert "通过对象数" in script
    # vSAN 不可用状态必须转换为客户语义，不能暴露内部枚举。
    assert "Unknown" not in script
    assert "未确认" in script

    assert 'table(["对象类型", "对象名称", "位置"]' in script
    assert "新增风险" in script
    assert "本次未再检出" in script
    assert "持续风险" in script
    assert "重新出现" not in script
    assert "例外风险" not in script
    assert "本次未发现新增风险。" in script
    assert "本次未发现未再检出风险。" in script

    assert "问题与整改" in script
    assert "整改方式" in script
    assert "整改复杂度" in script
    assert "受影响对象与技术证据" in script
    assert "问题说明" in script
    assert "可能影响" in script
    assert "整改建议" in script

    assert "规则 ID" not in script
    assert "期望状态" not in script
    assert "期望值" not in script
    for removed_detail in [
        "可接受例外情况",
        "误报风险说明",
        "例外处理建议",
        "可忽略场景",
        "检查项 ID",
        "预计工作量",
        "验证方式",
        "回退方案",
    ]:
        assert removed_detail not in script

    assert "资产清单" in script
    assert "asset_location || item.object_path" in script
    for removed_appendix in ["例外风险", "规则说明", "扩展检查项说明"]:
        assert removed_appendix not in script

    for token in [
        "Default Customer",
        "Default Site",
        "manual_check",
        "virtualization_admin",
        "network_admin",
        "storage_admin",
        "security_admin",
        "medium",
        "implementation_status",
        "execution_mode",
        "capability_required",
        '"owner_role"',
        '"verification_method"',
    ]:
        assert token not in embedded_text
        assert token not in script
    assert re.search(r"\btrue\b|\bfalse\b", embedded_text, re.IGNORECASE) is None
    assert re.search(r"\btrue\b|\bfalse\b", script, re.IGNORECASE) is None
    assert "??" not in visible_package_text

    assert embedded_payload.keys() == {"report_context", "risk_group_summary", "findings", "certificate_license_evidence", "assets"}
    assert "verification_coverage" in embedded_payload["report_context"]
    assert "rule_pass_rate" not in embedded_payload["report_context"]
    assert "checked_object_total" not in embedded_payload["report_context"]["environment_summary"]
    assert "covered_object_total" in embedded_payload["report_context"]["environment_summary"]
    assert "passed_checks" not in embedded_text
    assert "actionable_checks" not in embedded_text
    assert "检查结果" not in embedded_text
    assert "参考说明" in script
    assert "原始证据" not in script
    assert "证书与授权核验结果" in script
    assert "历史对比摘要" in script
    assert "检查项证据" not in script
    assert "check-evidence-table" in script
    check_evidence = embedded_payload["certificate_license_evidence"]
    assert check_evidence
    for item in check_evidence:
        assert "rule_id" not in item
        assert "rule_name" not in item
        assert "raw_evidence" not in item
        assert "source_path" not in item
        assert "threshold_zh" not in item
        assert "observed_detail_zh" not in item
        assert "expected_detail_zh" not in item
    assert {"passed", "failed", "unavailable"} & {item["result_status"] for item in check_evidence}
    assert embedded_payload["report_context"]["appendix"]["certificate_license_evidence"] == check_evidence
    for technical_text in ["licenseAssignmentManager", "commonName=", "countryName=", "organizationalUnitName="]:
        assert technical_text not in embedded_text
    assert ("ESXi 授权" + "服务") not in embedded_text
    assert ("vCenter 授权" + "服务") not in embedded_text
    assert "ESXi 主机授权状态" in embedded_text
    assert "vCenter 授权状态" in embedded_text
    assert "history_comparison" in embedded_payload["report_context"]
    assert embedded_payload["report_context"]["appendix"]["history_comparison"] == embedded_payload["report_context"]["history_comparison"]
    assert embedded_payload["report_context"]["history_comparison"]["state"] in {"single_run", "ready"}
    packaged_finding = embedded_payload["findings"][0]
    for hidden_field in ["rule_id", "rule_name", "threshold_zh", "source_path", "raw_evidence", "structured_evidence_state"]:
        assert hidden_field not in packaged_finding
    assert packaged_finding["collected_at"]
    assert "critical_pass_summary" not in embedded_payload["report_context"]
    assert embedded_payload["report_context"]["status_summary"].keys() == {"passed", "failed"}
    assert set(embedded_payload["report_context"]["remediation_tracking"].keys()) == {
        "previous_run_id",
        "current_run_id",
        "previous_score",
        "current_score",
        "score_delta",
        "summary",
        "new_findings",
        "resolved_findings",
    }
    assert embedded_payload["report_context"]["remediation_tracking"]["summary"].keys() == {"new", "resolved"}
    assert "inspection_results" not in embedded_payload
    assert "rule_catalog" not in embedded_payload
    assert "capability_gaps" not in embedded_payload
    assert "unexecuted_rule_groups" not in embedded_payload
    assert "exception_findings" not in embedded_payload
    for items in embedded_payload["assets"]["details"].values():
        for item in items:
            assert "asset_location" in item
            assert item["asset_location"]
            assert item["asset_location"] != item["object_name"]

    assert stored_payload == embedded_payload
    stored_check_evidence = stored_payload["report_context"]["appendix"]["certificate_license_evidence"]
    assert stored_check_evidence == check_evidence
    for item in stored_check_evidence:
        assert "rule_id" not in item
        assert "raw_evidence" not in item
    stored_finding = stored_payload["findings"][0]
    for hidden_field in ["rule_id", "rule_name", "threshold_zh", "source_path", "raw_evidence", "structured_evidence_state"]:
        assert hidden_field not in stored_finding
    assert stored_finding["collected_at"]

    with connect(Path(args.db)) as conn:
        run_id = conn.execute("SELECT run_id FROM inspection_runs ORDER BY created_at DESC LIMIT 1").fetchone()["run_id"]
        report_context = ReportContextBuilder().build(conn, run_id)
    rule_catalog = report_context["rule_catalog"]
    inspection_results = report_context["object_results"]
    findings = report_context["findings"]
    run_comparison = report_context["remediation_tracking"]
    risk_groups = report_context["risk_group_summary"]

    assert len(rule_catalog) == 67
    assert len(inspection_results) > len(findings)
    assert all("raw_evidence" in item for item in findings)
    assert any(item.get("source_path") or item.get("threshold") for item in findings)
    assert report_context["rule_catalog_summary"] == {"total": 67, "executable": 67, "implemented": 67}
    assert "critical_pass_summary" not in report_context
    with connect(Path(args.db)) as conn:
        conn.execute(
            """
            INSERT INTO rules (rule_id, rule_name, category, object_type, risk_level, confidence_level, rule_version, enabled, definition_json, created_at, updated_at)
            VALUES ('VSL-OLD-999', 'Old stale rule', 'vcenter', 'vCenter', 'P4', 'low', '1.0.0', 1, '{}', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')
            """
        )
        run_id = conn.execute("SELECT run_id FROM inspection_runs ORDER BY created_at DESC LIMIT 1").fetchone()["run_id"]
        stale_context = ReportContextBuilder().build(conn, run_id)
    assert stale_context["rule_catalog_summary"] == {"total": 67, "executable": 67, "implemented": 67}
    assert "VSL-OLD-999" not in {rule["rule_id"] for rule in stale_context["rule_catalog"]}
    assert report_context["remediation_tracking"]["summary"] == {"new": 0, "existing": 0, "resolved": 0, "reopened": 0, "exception": 0}
    assert run_comparison["summary"] == report_context["remediation_tracking"]["summary"]
    assert run_comparison["current_run"].get("run_status", "") in {"", "success"}
    assert report_context["environment_info"]["vcenter_version"] == "6.7.0"
    assert embedded_payload["report_context"]["customer_info"]["customer_name"] == "未指定客户"
    assert "site_name" not in embedded_payload["report_context"]["customer_info"]
    assert len(risk_groups) > 0

    executed_rule_ids = {item["rule_id"] for item in inspection_results}
    assert {item["rule_id"] for item in rule_catalog} == executed_rule_ids
    assert {"VSL-CL-007", "VSL-HOST-016", "VSL-VM-022"} <= executed_rule_ids
    assert {"VSL-CL-009", "VSL-CL-016", "VSL-VM-016", "VSL-VM-017", "VSL-VM-021"} <= executed_rule_ids
    assert {"VSL-CL-010", "VSL-HOST-014", "VSL-DS-007", "VSL-VM-014", "VSL-SEC-002", "VSL-VC-015"} <= executed_rule_ids
    assert not {"VSL-DS-003", "VSL-VC-003", "VSL-VC-007", "VSL-VSAN-001", "VSL-CAP-002"} & executed_rule_ids
    assert not {"VSL-NET-001", "VSL-NET-005", "VSL-NET-006", "VSL-NET-007", "VSL-NET-008", "VSL-NET-010", "VSL-NET-012"} & executed_rule_ids

    vc_alarm = next(item for item in findings if item["rule_id"] == "VSL-VC-004")
    assert "Host connection and power state" in vc_alarm["fault_detail_zh"]
    assert "esxi-01.lab.local" in vc_alarm["fault_detail_zh"]
    assert "Datastore usage on disk" in vc_alarm["fault_detail_zh"]
    assert "Host connection and power state" in embedded_text
    assert "Datastore usage on disk" in embedded_text

    for item in [*inspection_results, *findings]:
        assert "true" not in str(item.get("current_value_zh", "")).lower()
        assert "false" not in str(item.get("current_value_zh", "")).lower()
        assert "true" not in str(item.get("expected_value_zh", "")).lower()
        assert "false" not in str(item.get("expected_value_zh", "")).lower()

    with connect(Path(args.db)) as conn:
        report_types = {row["report_type"] for row in conn.execute("SELECT report_type FROM reports").fetchall()}
        report_names = {row["report_name"] for row in conn.execute("SELECT report_name FROM reports").fetchall()}
    assert {"html_package", "zip", "json", "engineering_diagnostics"} <= report_types
    assert "html" not in report_types
    assert "VStackLens HTML Preview Report" not in report_names


def test_run_mock_keeps_inspection_db_when_report_dir_is_reused(tmp_path: Path) -> None:
    report_dir = tmp_path / "shared-report-dir"
    report_dir.mkdir()
    db_path = report_dir / "inspection.db"
    stale_file = report_dir / "old-report.html"
    stale_file.write_text("stale", encoding="utf-8")
    args = type(
        "Args",
        (),
        {
            "db": str(db_path),
            "rulepack": str(RULEPACK),
            "fixture": str(FIXTURE),
            "report_dir": str(report_dir),
            "zip_report": True,
            "html_out": None,
            "docx_out": None,
        },
    )()

    cmd_run_mock(args)

    assert db_path.exists()
    generated = next(report_dir.glob("VStackLens-report-*"))
    assert (generated / "index.html").exists()
    assert (generated / "data" / "customer_report_payload.json").exists()
    assert stale_file.read_text(encoding="utf-8") == "stale"
    with zipfile.ZipFile(generated.with_suffix(".zip")) as archive:
        names = set(archive.namelist())
    assert not any(name.endswith("inspection.db") for name in names)


def test_run_mock_uses_customer_name_argument_in_report_payload(tmp_path: Path) -> None:
    report_dir = tmp_path / "named-report-package"
    args = type(
        "Args",
        (),
        {
            "db": str(tmp_path / "named-report.db"),
            "rulepack": str(RULEPACK),
            "fixture": str(FIXTURE),
            "report_dir": str(report_dir),
            "zip_report": False,
            "customer_name": "客户 A",
            "site_name": "生产站点",
            "html_out": None,
            "docx_out": None,
        },
    )()

    cmd_run_mock(args)

    payload = json.loads((report_dir / "data" / "customer_report_payload.json").read_text(encoding="utf-8"))
    embedded_payload = _embedded_payload((report_dir / "index.html").read_text(encoding="utf-8"))
    assert payload["report_context"]["customer_info"]["customer_name"] == "客户 A"
    assert embedded_payload["report_context"]["customer_info"]["customer_name"] == "客户 A"


def test_report_data_factory_maps_legacy_default_customer_placeholder() -> None:
    report = ReportDataFactory().from_context(
        {
            "scope": {
                "customer_name": "默认客户",
                "site_name": "默认站点",
                "vcenter_host": "vcsa.local",
            }
        }
    )

    assert report.customer_info.customer_name == "未指定客户"
    assert report.customer_info.site_name == "未指定站点"


def _minimal_report(asset_inventory: dict | None = None) -> ReportData:
    return ReportData(
        report_info={
            "report_id": "report-html-presentation",
            "generated_at": "2026-06-18T00:00:00+08:00",
            "run_id": "run-html",
        },
        customer_info={"customer_name": "客户 A", "site_name": "生产站点", "vcenter": "vcsa.lab.local"},
        environment_summary={"scope_statement": "HTML 展示口径测试", "checked_object_total": 3},
        health_score={"score": 80, "grade": "B", "explanation": "存在需关注项目"},
        risk_summary={"P1": 0, "P2": 2, "P3": 4, "P4": 0, "total": 6},
        asset_inventory=asset_inventory or {"summary": {}, "details": {}, "total": 0},
    )


def _finding(
    rule_id: str,
    title: str,
    object_type: str,
    object_name: str,
    risk_level: str,
    **extra: object,
) -> dict:
    item = {
        "rule_id": rule_id,
        "rule_name": title,
        "title": title,
        "risk_level": risk_level,
        "object_type": object_type,
        "object_type_label": object_type,
        "object_name": object_name,
        "status": "failed",
        "summary": title,
        "business_impact": title,
        "consequence": title,
        "remediation": "建议确认当前状态并按维护窗口处理。",
        "current_value_zh": extra.pop("current_value_zh", "当前状态：未配置"),
        "expected_value_zh": extra.pop("expected_value_zh", "期望值：按健康基线执行"),
        "evidence_summary_zh": extra.pop("evidence_summary_zh", title),
        "observed_detail_zh": extra.pop("observed_detail_zh", "当前观察值：未配置"),
        "expected_detail_zh": extra.pop("expected_detail_zh", "期望状态：应配置"),
        "recommended_action_zh": extra.pop("recommended_action_zh", "建议确认并处理。"),
        "fault_detail_zh": extra.pop("fault_detail_zh", title),
        "collected_at": "2026-06-18T00:00:00+08:00",
    }
    item.update(extra)
    return item


def _embedded_payload(index: str) -> dict:
    embedded_json = re.search(r'<script id="report-data" type="application/json">(.*?)</script>', index, re.S)
    assert embedded_json
    return json.loads(embedded_json.group(1))


def test_embedded_json_escapes_script_breakout_payload() -> None:
    payload_text = '</script><script>alert(1)</script>'
    page = HtmlReportPackageBuilder()._html(
        {
            "report_context": {
                "report_info": {"report_title": "Security Smoke"},
                "customer_info": {"customer_name": payload_text},
            },
            "findings": [{"title": payload_text}],
        }
    )

    assert page.count("<script") == 2
    assert payload_text not in page
    assert "<script>alert(1)</script>" not in page
    assert "\\u003c/script\\u003e\\u003cscript\\u003ealert(1)\\u003c/script\\u003e" in page
    assert _embedded_payload(page)["report_context"]["customer_info"]["customer_name"] == payload_text


def test_health_html_customer_presentation_filters_and_merges_findings(tmp_path: Path) -> None:
    findings = [
        _finding(
            "VSL-VC-004",
            "vCenter 红色活动告警",
            "vCenter",
            "vcsa.lab.local",
            "P2",
            current_value_zh="2",
            expected_detail_zh="期望状态：红色活动告警数 0 条；建议基线：vCenter 不应存在红色活动告警",
            observed_detail={
                "active_red_alarms": [
                    {"entity_name": "esxi-01.lab.local", "alarm_name": "Host connection", "status": "红色"},
                    {"entity_name": "datastore01", "alarm_name": "Datastore usage on disk", "status": "红色"},
                ]
            },
        ),
        _finding("VSL-HOST-014", "ESXi 主机未配置远程 Syslog", "HostSystem", "esxi-01.lab.local", "P3"),
        _finding("VSL-HOST-015", "ESXi 主机日志与核心转储配置不完整", "HostSystem", "esxi-01.lab.local", "P3"),
        _finding("VSL-VM-030", "虚拟机 CPU/Memory Limit 过高", "VirtualMachine", "vCLS-4c4c4544-004d-3010", "P3"),
        _finding("VSL-VM-031", "虚拟机配置了资源 Limit", "VirtualMachine", "app-01", "P3"),
        _finding(
            "VSL-VM-021",
            "虚拟机存在超期快照",
            "VirtualMachine",
            "app-02",
            "P2",
            observed_detail={"snapshots": [{"snapshot_name": "before-change", "created_at": "2026-06-01", "size_mb": 1536}]},
        ),
        _finding(
            "VSL-VM-022",
            "虚拟机快照链过深",
            "VirtualMachine",
            "app-02",
            "P2",
            observed_detail={"snapshots": [{"snapshot_name": "second-hop", "chain_depth": 3, "size_gb": 2}]},
        ),
        _finding("VSL-VM-040", "VMware Tools 未运行", "VirtualMachine", "app-03", "P3"),
        _finding("VSL-VM-041", "VMware Tools 版本过旧", "VirtualMachine", "app-03", "P3"),
        _finding("VSL-VM-042", "VMware Tools 未安装", "VirtualMachine", "app-03", "P3"),
    ]
    report = _minimal_report(
        {
            "summary": {"VirtualMachine": 3},
            "details": {
                "VirtualMachine": [
                    {"object_type": "VirtualMachine", "object_name": "vCLS-4c4c4544-004d-3010", "object_path": "/vm/vCLS"},
                    {"object_type": "VirtualMachine", "object_name": "app-01", "object_path": "/vm/app-01"},
                ]
            },
            "total": 2,
        }
    )
    context = {
        "findings": findings,
        "result_status_summary": {"passed": 1, "failed": len(findings)},
        "module_summary": [{"object_type": "VirtualMachine", "passed": 1, "failed": len(findings)}],
        "rule_pass_rate": {"rate": 10, "passed_checks": 1, "actionable_checks": len(findings) + 1},
    }

    report_dir = tmp_path / "customer-html"
    HtmlReportPackageBuilder().render(report, context, report_dir)
    index = (report_dir / "index.html").read_text(encoding="utf-8")
    script = (report_dir / "assets" / "report.js").read_text(encoding="utf-8")
    payload_text = (report_dir / "data" / "customer_report_payload.json").read_text(encoding="utf-8")
    payload = json.loads(payload_text)
    visible_text = index + script + payload_text + json.dumps(payload, ensure_ascii=False)
    page_payload = _embedded_payload(index)

    for expected in [
        "当前发现红色活动告警 2 条",
        "告警对象：esxi-01.lab.local",
        "告警名称：Host connection",
        "虚拟机存在快照",
        "资源限制",
    ]:
        assert expected in visible_text
    assert "VMware Tools" not in visible_text
    assert "Syslog" not in visible_text

    for forbidden in [
        "失败",
        "期望状态",
        "期望值",
        "Limit",
        "日志与核心转储配置不完整",
        "虚拟机存在超期快照",
        "虚拟机快照链过深",
        "VMware Tools 未运行",
        "VMware Tools 版本过旧",
    ]:
        assert forbidden not in visible_text

    finding_titles = [item["title"] for item in payload["findings"]]
    assert finding_titles.count("虚拟机存在快照") == 1
    assert not any("VMware Tools" in title or "Syslog" in title for title in finding_titles)
    assert any(item["name"] == "vCLS-4c4c4544-004d-3010" for item in page_payload["inventory"]["vms"])
    assert all(item["name"] != "vCLS-4c4c4544-004d-3010" for problem in page_payload["problems"] for item in problem["objects"])


def test_invalid_ready_history_comparison_is_rendered_as_empty_state() -> None:
    builder = HtmlReportPackageBuilder()
    invalid_ready = {
        "state": "ready",
        "baseline_run_id": "",
        "comparison_run_id": "",
        "summary_text": "新增 78 项、本次未再检出 78 项、持续 0 项。",
        "risk_changes": {"new": [{"title": "A"}], "closed": [{"title": "B"}], "persistent": [{"title": "C"}]},
    }

    page_history = builder._page_history_comparison(invalid_ready)
    customer_history = builder._customer_history_comparison(invalid_ready)

    assert page_history["state"] == "single_run"
    assert page_history["summary_text"] == "暂无历史对比"
    assert page_history["risk_changes"] == {"new": [], "closed": [], "persistent": []}
    assert customer_history["state"] == "single_run"
    assert customer_history["summary_text"] == "暂无历史对比"
    assert customer_history["risk_changes"] == {"new": [], "closed": [], "persistent": []}


def test_customer_visible_check_names_are_neutral_and_titles_are_separate() -> None:
    forbidden_terms = [
        "是否",
        "存在",
        "失败",
        "异常",
        "未启用",
        "未开启",
        "未配置",
        "过高",
        "过低",
        "过旧",
        "过期",
        "不一致",
        "不足",
        "缺失",
        "无最近",
        "不完整",
        "不可访问",
        "降速",
        "断链",
    ]

    rules = [SchemaValidator().validate_rule(raw) for raw in RulePackLoader().load_raw(RULEPACK)]

    assert len(rules) == 67
    for rule in rules:
        check_name = rule.report_fields.check_name_zh
        finding_title = rule.report_fields.finding_title_zh
        assert check_name, f"{rule.rule_id} missing check_name_zh"
        assert finding_title, f"{rule.rule_id} missing finding_title_zh"
        assert not any(term in check_name for term in forbidden_terms), f"{rule.rule_id} has conclusion-like check name: {check_name}"
        assert check_name != finding_title, f"{rule.rule_id} should separate neutral check name and risk title"


def test_customer_value_translation_is_rule_semantic() -> None:
    builder = ReportContextBuilder()

    assert builder._display_value_for_rule(False, "VSL-CL-007") == "未启用"
    assert builder._display_value_for_rule(True, "VSL-HOST-002") == "启用"
    assert builder._display_value_for_rule(False, "VSL-VM-017") == "正常"
    assert builder._display_value_for_rule(True, "VSL-VM-017") == "异常"
    assert builder._display_value_for_rule(0, "VSL-VM-016") == "未发现异常网络连接"
    assert builder._display_value_for_rule(2, "VSL-VM-016") == "发现 2 个异常网络连接"
    assert builder._display_value_for_rule(0, "VSL-VM-021") == "未发现直通或宿主机设备"
    assert builder._display_value_for_rule(1, "VSL-CL-016") == "发现 1 台缺少 vMotion 网络的主机"
    assert builder._display_value_for_detail("cpu_ready_percent", 13.19, {"rule_id": "VSL-VM-004"}) == "13.19%"
    assert (
        builder._display_value_for_detail(
            "current_value",
            13.19,
            {"rule_id": "VSL-VM-004", "current_value_path": "cpu_ready_percent", "current_value": 13.19},
        )
        == "13.19% CPU Ready"
    )
    assert (
        builder._display_value_for_detail(
            "expected_value",
            "< 5",
            {"rule_id": "VSL-VM-004", "current_value_path": "cpu_ready_percent"},
        )
        == "< 5%"
    )
    assert builder._display_value_for_detail("cpu_usage_avg", 72.5, {"rule_id": "VSL-HOST-001"}) == "72.5%"
    assert builder._display_value_for_detail("memory_usage_percent", 81, {"rule_id": "VSL-HOST-001"}) == "81%"
    assert builder._display_value_for_detail("datastore_capacity_gb", 1024, {"rule_id": "VSL-DS-001"}) == "1024.0 GB"
    assert builder._display_value_for_detail("snapshot_size_gb", 2, {"rule_id": "VSL-VM-001"}) == "2.0 GB"
    assert builder._display_value_for_detail("swap_or_balloon_mb", 512, {"rule_id": "VSL-VM-005"}) == "512 MB"
    assert builder._display_value_for_detail("snapshot_age_days", 35, {"rule_id": "VSL-VM-001"}) == "35 天"
    assert builder._display_value_for_detail("red_alarm_count", 2, {"rule_id": "VSL-VC-004"}) == "2 条告警"
    assert builder._display_value_for_detail("task_backlog_count", 3, {"rule_id": "VSL-VC-015"}) == "3 个任务"
    assert builder._display_value_for_detail("host_pcpu_count", 16, {"rule_id": "VSL-HOST-026"}) == "16 个 pCPU"
    assert builder._display_value_for_detail("host_vcpu_allocated", 80, {"rule_id": "VSL-HOST-026"}) == "80 个 vCPU"
    assert builder._display_value_for_detail("host_vcpu_to_pcpu_ratio", 4.5, {"rule_id": "VSL-HOST-026"}) == "4.50:1"
    assert builder._display_value_for_detail("host_memory_allocation_ratio", 1.25, {"rule_id": "VSL-HOST-026"}) == "125.0%"
    assert builder._display_value_for_detail("host_memory_capacity_mb", 65536, {"rule_id": "VSL-HOST-026"}) == "64.0 GB"
    assert builder._display_value_for_detail("vsan_used_percent", 85.2, {"rule_id": "VSL-DS-020"}) == "85.2%"
    assert builder._display_value_for_detail("latency_ms", 8.5, {"rule_id": "VSL-TEST"}) == "8.5 ms"
    assert builder._display_value_for_detail("throughput_mbps", 1000, {"rule_id": "VSL-TEST"}) == "1000 Mbps"
    assert builder._display_value_for_detail("iops", 12500, {"rule_id": "VSL-TEST"}) == "12500 IOPS"
    assert builder._display_value_for_detail("vm_on_local_datastore", True, {"rule_id": "VSL-VM-023"}) == "异常"


def test_cpu_ready_customer_display_uses_metric_units_in_html_payload() -> None:
    item = {
        "rule_id": "VSL-VM-004",
        "rule_name": "虚拟机 CPU Ready 状态",
        "title": "虚拟机 CPU Ready 过高",
        "risk_level": "P2",
        "object_type": "VirtualMachine",
        "object_type_label": "虚拟机",
        "object_name": "WF-知识库业务（win）",
        "status": "open",
        "current_value": 13.19,
        "expected_value": "< 5",
        "current_value_path": "cpu_ready_percent",
        "evidence_summary_zh": "WF-知识库业务（win） 当前值为 13.19，期望值为 < 5。",
        "observed_detail": {"current_value": 13.19, "cpu_ready_percent": 13.19},
        "expected_detail": {"expected_value": "< 5"},
        "recommended_action_zh": "复核虚拟机 vCPU 配置和主机 CPU 调度压力。",
    }

    ReportContextBuilder()._apply_customer_display_fields(item)
    payload_item = HtmlReportPackageBuilder()._clean_customer_item(HtmlReportPackageBuilder()._customer_finding(item))
    payload_text = json.dumps(payload_item, ensure_ascii=False)

    assert "CPU Ready 当前值为 13.19%，建议低于 5%" in payload_item["evidence_summary_zh"]
    assert item["current_value_zh"] == "13.19% CPU Ready"
    assert item["expected_value_zh"] == "< 5%"
    assert "当前值：13.19% CPU Ready" in item["observed_detail_zh"]
    assert "CPU Ready：13.19%" in item["observed_detail_zh"]
    assert "建议状态：< 5%" in item["expected_detail_zh"]
    assert "CPU Ready" in payload_text
    assert "13.19%" in payload_text
    assert "< 5%" in payload_text
    assert "当前值为 13.19，建议状态为 < 5" not in payload_text
    assert "当前值为 13.19，期望值为 < 5" not in payload_text
    assert "CPU 使用率 13.19%" not in payload_text


def test_environment_mismatch_history_comparison_is_never_rendered_as_ready() -> None:
    builder = HtmlReportPackageBuilder()
    mismatch = {
        "state": "environment_mismatch",
        "baseline_run_id": "run-a1",
        "comparison_run_id": "run-b1",
        "baseline_label": "2026-09-01 10:00 · vc-a.example · 健康度 80 · 风险 3 · 优化建议 0",
        "comparison_label": "2026-09-02 10:00 · vc-b.example · 健康度 90 · 风险 0 · 优化建议 0",
        "summary_text": "所选巡检记录属于不同的 vCenter 环境，无法进行历史对比。",
        "score": {"baseline": 80.0, "comparison": 90.0, "delta": 10.0, "direction": "up"},
        "risk_counts": {
            "P1": {"baseline": 3, "comparison": 0, "delta": -3, "direction": "down"},
            "P2": {"baseline": 0, "comparison": 0, "delta": 0, "direction": "same"},
            "P3": {"baseline": 0, "comparison": 0, "delta": 0, "direction": "same"},
        },
        "asset_counts": {
            "vcenter": {"baseline": 1, "comparison": 1, "delta": 0, "direction": "same", "label": "vCenter"},
            "cluster": {"baseline": 0, "comparison": 0, "delta": 0, "direction": "same", "label": "Cluster"},
            "host": {"baseline": 0, "comparison": 0, "delta": 0, "direction": "same", "label": "Host"},
            "datastore": {"baseline": 0, "comparison": 0, "delta": 0, "direction": "same", "label": "Datastore"},
            "vm": {"baseline": 1, "comparison": 2, "delta": 1, "direction": "up", "label": "VM"},
        },
        "risk_changes": {
            "new": [{"title": "快照风险", "risk_level": "P1", "object_name": "app-02"}],
            "closed": [{"title": "主机风险", "risk_level": "P2", "object_name": "esxi-01"}],
            "persistent": [{"title": "持续风险", "risk_level": "P3", "object_name": "app-01"}],
        },
        "asset_changes": {
            "new": [{"object_name": "app-02", "object_type_label": "虚拟机"}],
            "removed": [{"object_name": "esxi-01", "object_type_label": "主机"}],
            "persistent": [{"object_name": "app-01", "object_type_label": "虚拟机"}],
        },
    }

    page_history = builder._page_history_comparison(mismatch)
    customer_history = builder._customer_history_comparison(mismatch)

    for payload in (page_history, customer_history):
        assert payload["state"] == "environment_mismatch"
        assert payload["state"] != "ready"
        assert payload["summary_text"] == "所选巡检记录属于不同的 vCenter 环境，无法进行历史对比。"
        assert payload["risk_changes"] == {"new": [], "closed": [], "persistent": []}
        assert payload["asset_changes"] == {"new": [], "removed": [], "persistent": []}
        assert payload["score"].get("delta") is None
        for level in ("P1", "P2", "P3"):
            assert payload["risk_counts"][level].get("delta") is None
        for key in ("vcenter", "cluster", "host", "datastore", "vm"):
            assert payload["asset_counts"][key].get("delta") is None

    assert page_history["baseline_label"] == ""
    assert "vc-b.example" in page_history["comparison_label"]
    assert "vCenter 环境" in customer_history["summary_text"]

    report_js = builder._js()
    assert 'if (state !== "ready")' in report_js
    assert "暂无可比的历史巡检记录。" in report_js


def test_run_unavailable_history_comparison_is_not_rendered_as_ready() -> None:
    builder = HtmlReportPackageBuilder()
    unavailable = {
        "state": "run_unavailable",
        "baseline_run_id": "",
        "comparison_run_id": "",
        "summary_text": "所选巡检记录不存在、未成功完成或不属于当前 vCenter 环境，无法进行历史对比。",
    }

    page_history = builder._page_history_comparison(unavailable)
    customer_history = builder._customer_history_comparison(unavailable)

    assert page_history["state"] == "run_unavailable"
    assert customer_history["state"] == "run_unavailable"
    assert page_history["risk_changes"] == {"new": [], "closed": [], "persistent": []}
    assert customer_history["asset_changes"] == {"new": [], "removed": [], "persistent": []}
