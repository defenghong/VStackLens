import json
import sqlite3
from pathlib import Path

from vstacklens.cli import cmd_compare_runs, cmd_run_vcenter
from vstacklens.collection.mock_collector import MockCollector
from vstacklens.collection.pyvmomi_collector import PyVmomiCollector, _PerformanceSampler
from vstacklens.collection.planner import CollectionPlanner
from vstacklens.core.context import RunContext
from vstacklens.db.connection import connect, init_db
from vstacklens.db.repositories import (
    calculate_health_score,
    calculate_health_score_breakdown,
    ensure_default_scope,
    finalize_run_summary,
    insert_report,
    insert_rule,
    insert_rule_result,
    insert_run,
    mark_finding_exception,
    update_run,
)
from vstacklens.findings.deduplication import FindingDeduplicator
from vstacklens.inventory.normalizer import InventoryNormalizer
from vstacklens.inventory.snapshot_engine import SnapshotEngine
from vstacklens.reports.context_builder import ReportContextBuilder
from vstacklens.reports.html_report import HtmlReportEngine
from vstacklens.reports.run_compare import RunComparisonBuilder
from vstacklens.reports.report_model import ReportDataFactory
from vstacklens.rules.executor import RuleExecutor
from vstacklens.rules.registry import RuleRegistry
from vstacklens.rules.rulepack_loader import RulePackLoader
from vstacklens.rules.schema_validator import SchemaValidator


ROOT = Path(__file__).resolve().parents[1]
RULEPACK = ROOT / "rulepacks" / "builtin-vsphere-v1"
FIXTURES = ROOT / "tests" / "fixtures"


def load_rules():
    raw_rules = RulePackLoader().load_raw(RULEPACK)
    rules = [SchemaValidator().validate_rule(raw) for raw in raw_rules]
    registry = RuleRegistry()
    registry.register(rules)
    return registry.rules


def load_executable_rules():
    raw_rules = RulePackLoader().load_raw(RULEPACK)
    rules = [SchemaValidator().validate_rule(raw) for raw in raw_rules]
    registry = RuleRegistry()
    registry.register(rules)
    return registry.executable_rules


def extension_rule_ids() -> set[str]:
    raw_rules = RulePackLoader().load_raw(RULEPACK)
    executable_ids = {rule.rule_id for rule in load_executable_rules()}
    return {raw["rule_id"] for raw in raw_rules if raw["rule_id"] not in executable_ids}


def run_fixture(db_path: Path, fixture: Path, out_path: Path, previous_run_id: str | None = None) -> str:
    init_db(db_path)
    rules = load_rules()
    executable_rules = load_executable_rules()
    plan = CollectionPlanner().build(executable_rules)
    with connect(db_path) as conn:
        customer_id, site_id, vcenter_id = ensure_default_scope(conn, "mock-vcenter.local")
        run_id = insert_run(conn, customer_id, site_id, vcenter_id, "manual")
        run = RunContext(run_id=run_id, customer_id=customer_id, site_id=site_id, vcenter_id=vcenter_id, db_path=db_path)
        update_run(conn, run_id, "running", "collecting", 20)
        raw = MockCollector(fixture).collect(run, plan)
        inventory = InventoryNormalizer().normalize(raw)
        SnapshotEngine().write_snapshot(conn, run, inventory)
        for rule in rules:
            insert_rule(conn, rule)
        results = RuleExecutor().execute(run, inventory, executable_rules)
        for result in results:
            insert_rule_result(conn, result)
        FindingDeduplicator().upsert_findings(conn, site_id, results)
        finalize_run_summary(conn, run_id)
        comparison = RunComparisonBuilder().build(conn, previous_run_id, run_id) if previous_run_id else None
        report_context = ReportContextBuilder().build(conn, run_id, comparison=comparison)
        report_data = ReportDataFactory().from_context(report_context)
        json_path = out_path.with_name("inspection_result.json")
        report_data.write_json(json_path)
        insert_report(
            conn,
            run_id,
            customer_id,
            site_id,
            vcenter_id,
            str(json_path),
            "success",
            report_type="json",
            report_name="Inspection Result JSON",
        )
        HtmlReportEngine().render(report_data, out_path)
        insert_report(
            conn,
            run_id,
            customer_id,
            site_id,
            vcenter_id,
            str(out_path),
            "success",
            report_type="html",
            report_name="VStackLens HTML Preview Report",
        )
        update_run(conn, run_id, "success", "success", 100)
    return run_id


def scalar(conn: sqlite3.Connection, sql: str, params: tuple = ()):
    return conn.execute(sql, params).fetchone()[0]


M2A_RULE_IDS = {
    "VSL-CL-007",
    "VSL-CL-013",
    "VSL-HOST-016",
    "VSL-HOST-019",
    "VSL-HOST-020",
    "VSL-NET-004",
    "VSL-VM-010",
    "VSL-VM-011",
    "VSL-VM-012",
    "VSL-VM-015",
    "VSL-VM-022",
}

M2B1_RULE_IDS = {
    "VSL-CL-009",
    "VSL-CL-016",
    "VSL-VM-016",
    "VSL-VM-017",
    "VSL-VM-021",
}

M2E_BACKFILL_RULE_IDS = {
    "VSL-CL-010",
    "VSL-CL-011",
    "VSL-CL-012",
    "VSL-HOST-014",
    "VSL-HOST-015",
    "VSL-DS-007",
    "VSL-DS-008",
    "VSL-DS-013",
    "VSL-DS-018",
    "VSL-VM-007",
    "VSL-VM-009",
    "VSL-VM-013",
    "VSL-VM-014",
    "VSL-SEC-002",
    "VSL-VC-015",
}

M2E2_BACKFILL_RULE_IDS = {
    "VSL-HOST-008",
    "VSL-HOST-013",
    "VSL-HOST-023",
    "VSL-NET-003",
    "VSL-VM-018",
    "VSL-SEC-008",
}

CURRENT_RULE_COUNT = 67
MOCK_FAIL_FINDING_COUNT = 57
MOCK_FAIL_ACTIONABLE_FINDING_COUNT = 36

PROMOTED_RULE_IDS = M2A_RULE_IDS | M2B1_RULE_IDS | M2E_BACKFILL_RULE_IDS | M2E2_BACKFILL_RULE_IDS

DISABLED_NETWORK_TOPOLOGY_RULE_IDS = {
    "VSL-NET-005",
    "VSL-NET-007",
    "VSL-NET-008",
    "VSL-NET-010",
    "VSL-NET-012",
}


def test_builtin_rulepack_contains_only_real_executable_rules() -> None:
    assert len(load_rules()) == CURRENT_RULE_COUNT
    executable_ids = {rule.rule_id for rule in load_executable_rules()}
    all_rule_ids = {rule.rule_id for rule in load_rules()}
    assert len(executable_ids) == CURRENT_RULE_COUNT
    assert executable_ids == all_rule_ids
    assert PROMOTED_RULE_IDS <= executable_ids
    assert not (DISABLED_NETWORK_TOPOLOGY_RULE_IDS & executable_ids)
    assert {"VSL-DS-003", "VSL-VC-003", "VSL-VC-007", "VSL-VSAN-001", "VSL-CAP-002"}.isdisjoint(all_rule_ids)
    for rule in load_rules():
        assert rule.implementation_status.value == "implemented"
        assert rule.execution_mode.value == "default_enabled"


def test_health_score_ignores_p4_without_priority_caps() -> None:
    score = calculate_health_score(
        [
            {"rule_id": "VSL-HOST-002", "risk_level": "P3", "c": 20},
            {"rule_id": "VSL-HOST-004", "risk_level": "P3", "c": 20},
            {"rule_id": "VSL-VM-003", "risk_level": "P4", "c": 20},
            {"rule_id": "VSL-VM-006", "risk_level": "P4", "c": 20},
        ]
    )
    assert score == 91

    breakdown = calculate_health_score_breakdown(
        [
            {"rule_id": "VSL-P1-001", "risk_level": "P1", "c": 3},
            {"rule_id": "VSL-P1-002", "risk_level": "P1", "c": 3},
            {"rule_id": "VSL-P1-003", "risk_level": "P1", "c": 3},
            {"rule_id": "VSL-VM-003", "risk_level": "P4", "c": 100},
        ]
    )
    assert breakdown["score"] == 55
    assert breakdown["levels"]["P4"]["deduction"] == 0


def test_mock_pipeline_persists_summary_report_and_findings(tmp_path: Path) -> None:
    db_path = tmp_path / "m1.db"
    out_path = tmp_path / "report.html"
    run_id = run_fixture(db_path, FIXTURES / "inventory_fail.json", out_path)

    with connect(db_path) as conn:
        run = conn.execute("SELECT * FROM inspection_runs WHERE run_id = ?", (run_id,)).fetchone()
        assert run["run_status"] == "success"
        assert run["current_stage"] == "success"
        assert run["score"] == 15
        assert json.loads(run["risk_summary_json"]) == {"P1": 9, "P2": 11, "P3": 16, "P4": 21}
        assert scalar(conn, "SELECT COUNT(*) FROM reports WHERE run_id = ?", (run_id,)) == 2
        report_types = {
            row["report_type"]
            for row in conn.execute("SELECT report_type FROM reports WHERE run_id = ?", (run_id,)).fetchall()
        }
        assert report_types == {"json", "html"}
        assert scalar(conn, "SELECT COUNT(*) FROM findings WHERE last_seen_run_id = ?", (run_id,)) == MOCK_FAIL_FINDING_COUNT
        assert scalar(conn, "SELECT COUNT(*) FROM rule_results WHERE run_id = ? AND result_status = 'failed'", (run_id,)) == MOCK_FAIL_FINDING_COUNT
        assert scalar(conn, "SELECT COUNT(*) FROM rule_results WHERE run_id = ? AND rule_id IN ('VSL-DS-003', 'VSL-VC-003')", (run_id,)) == 0
        assert scalar(
            conn,
            "SELECT COUNT(*) FROM rule_results WHERE run_id = ? AND rule_id IN ('VSL-NET-005', 'VSL-NET-007', 'VSL-NET-008', 'VSL-NET-010', 'VSL-NET-012')",
            (run_id,),
        ) == 0
        assert extension_rule_ids() == set()
    assert out_path.exists()


def test_finding_exception_is_recorded_and_excluded_from_score(tmp_path: Path) -> None:
    db_path = tmp_path / "exception.db"
    out_path = tmp_path / "exception.html"
    run_id = run_fixture(db_path, FIXTURES / "inventory_fail.json", out_path)

    with connect(db_path) as conn:
        before = conn.execute("SELECT score, risk_summary_json FROM inspection_runs WHERE run_id = ?", (run_id,)).fetchone()
        finding = conn.execute(
            "SELECT finding_id FROM findings WHERE last_seen_run_id = ? AND rule_id = 'VSL-HOST-001'",
            (run_id,),
        ).fetchone()
        mark_finding_exception(
            conn,
            finding["finding_id"],
            reason="专用隔离集群，客户确认不要求在线迁移。",
            owner="virtualization_admin",
            expires_at="2026-12-31",
            approval_note="客户运维负责人批准。",
        )
        finalize_run_summary(conn, run_id)
        after = conn.execute("SELECT score, risk_summary_json FROM inspection_runs WHERE run_id = ?", (run_id,)).fetchone()
        exception = conn.execute("SELECT * FROM finding_exceptions WHERE finding_id = ?", (finding["finding_id"],)).fetchone()
        context = ReportContextBuilder().build(conn, run_id)

    assert before["score"] == 15
    assert json.loads(before["risk_summary_json"]) == {"P1": 9, "P2": 11, "P3": 16, "P4": 21}
    assert after["score"] == 15
    assert json.loads(after["risk_summary_json"]) == {"P1": 8, "P2": 11, "P3": 16, "P4": 21}
    assert exception["exception_reason"] == "专用隔离集群，客户确认不要求在线迁移。"
    assert exception["owner"] == "virtualization_admin"
    assert len(context["exception_findings"]) == 1
    assert context["exception_findings"][0]["exception_reason"] == "专用隔离集群，客户确认不要求在线迁移。"
    assert not any(item["rule_id"] == "VSL-HOST-001" for item in context["findings"])


def test_missing_data_is_unavailable_and_does_not_create_findings(tmp_path: Path) -> None:
    db_path = tmp_path / "missing.db"
    run_id = run_fixture(db_path, FIXTURES / "inventory_missing.json", tmp_path / "missing.html")

    with connect(db_path) as conn:
        assert scalar(conn, "SELECT COUNT(*) FROM rule_results WHERE run_id = ? AND result_status = 'unavailable'", (run_id,)) == 17
        assert scalar(conn, "SELECT COUNT(*) FROM findings WHERE last_seen_run_id = ?", (run_id,)) == 0
        run = conn.execute("SELECT risk_summary_json, score FROM inspection_runs WHERE run_id = ?", (run_id,)).fetchone()
        assert json.loads(run["risk_summary_json"]) == {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
        assert run["score"] == 100


def test_failed_finding_resolves_when_same_object_passes(tmp_path: Path) -> None:
    pass_all = tmp_path / "inventory_pass_all.json"
    inventory = json.loads((FIXTURES / "inventory_pass.json").read_text(encoding="utf-8"))
    inventory["objects"].append(
        {
            "object_type": "HostSystem",
            "object_key": "host-2",
            "object_name": "esxi-02.lab.local",
            "object_path": "Default/mock-vcenter.local/Cluster-01/esxi-02.lab.local",
            "properties": {
                "connection_state": "connected",
                "ssh_running": False,
                "ntp_server_count": 2,
                "lockdown_mode": "lockdownNormal",
                "cpu_usage_avg": 30,
                "memory_usage_avg": 40,
                "esxi_shell_running": False,
                "physical_nic_link_issue_count": 0,
                "storage_path_dead_count": 0,
                "vswitch_uplink_issue_count": 0,
                "vmkernel_mtu_values": [1500],
                "vmotion_vmk_count": 1,
                "management_uplink_count": 2,
            },
        }
    )
    pass_all.write_text(json.dumps(inventory), encoding="utf-8")

    db_path = tmp_path / "lifecycle.db"
    run_fixture(db_path, FIXTURES / "inventory_fail.json", tmp_path / "fail.html")
    run_fixture(db_path, pass_all, tmp_path / "pass.html")

    with connect(db_path) as conn:
        assert scalar(conn, "SELECT COUNT(*) FROM findings WHERE status = 'open'") == 0
        assert scalar(conn, "SELECT COUNT(*) FROM findings WHERE status = 'resolved'") == MOCK_FAIL_FINDING_COUNT


def test_run_comparison_tracks_new_existing_resolved_and_reopened(tmp_path: Path) -> None:
    db_path = tmp_path / "compare.db"
    fail_fixture = FIXTURES / "inventory_fail.json"
    pass_all = tmp_path / "inventory_pass_all.json"
    pass_inventory = json.loads((FIXTURES / "inventory_pass.json").read_text(encoding="utf-8"))
    pass_inventory["objects"].append(
        {
            "object_type": "HostSystem",
            "object_key": "host-2",
            "object_name": "esxi-02.lab.local",
            "object_path": "Default/mock-vcenter.local/Cluster-01/esxi-02.lab.local",
            "properties": {
                "connection_state": "connected",
                "ssh_running": False,
                "ntp_server_count": 2,
                "lockdown_mode": "lockdownNormal",
                "cpu_usage_avg": 30,
                "memory_usage_avg": 40,
                "esxi_shell_running": False,
                "physical_nic_link_issue_count": 0,
                "storage_path_dead_count": 0,
                "vswitch_uplink_issue_count": 0,
                "vmkernel_mtu_values": [1500],
                "vmotion_vmk_count": 1,
                "management_uplink_count": 2,
            },
        }
    )
    pass_all.write_text(json.dumps(pass_inventory), encoding="utf-8")

    mixed_fixture = tmp_path / "inventory_mixed.json"
    mixed_inventory = json.loads(pass_all.read_text(encoding="utf-8"))
    host_1 = next(item for item in mixed_inventory["objects"] if item["object_type"] == "HostSystem" and item["object_key"] == "host-1")
    host_1["properties"]["ssh_running"] = True
    vm_1 = next(item for item in mixed_inventory["objects"] if item["object_type"] == "VirtualMachine")
    vm_2 = json.loads(json.dumps(vm_1))
    vm_2["object_key"] = "vm-2"
    vm_2["object_name"] = "app-02"
    vm_2["object_path"] = "Default/mock-vcenter.local/Cluster-01/app-02"
    vm_2["properties"]["vcpu_count"] = 16
    mixed_inventory["objects"].append(vm_2)
    mixed_fixture.write_text(json.dumps(mixed_inventory), encoding="utf-8")

    run1 = run_fixture(db_path, fail_fixture, tmp_path / "run1.html")
    run2 = run_fixture(db_path, pass_all, tmp_path / "run2.html", previous_run_id=run1)
    run3 = run_fixture(db_path, mixed_fixture, tmp_path / "run3.html", previous_run_id=run2)
    run4 = run_fixture(db_path, mixed_fixture, tmp_path / "run4.html", previous_run_id=run3)

    with connect(db_path) as conn:
        comparison_1_2 = RunComparisonBuilder().build(conn, run1, run2)
        comparison_2_3 = RunComparisonBuilder().build(conn, run2, run3)
        comparison_3_4 = RunComparisonBuilder().build(conn, run3, run4)
        comparison_path = RunComparisonBuilder().write_json(conn, run3, run4, tmp_path / "comparison")
        context = ReportContextBuilder().build(conn, run4, comparison=comparison_3_4)

    assert comparison_1_2["summary"]["resolved"] == MOCK_FAIL_ACTIONABLE_FINDING_COUNT
    assert comparison_1_2["summary"]["new"] == 0
    assert comparison_1_2["summary"]["existing"] == 0

    assert comparison_2_3["summary"]["reopened"] >= 1
    assert comparison_2_3["summary"]["new"] == 0
    assert any(item["rule_id"] == "VSL-HOST-002" for item in comparison_2_3["reopened_findings"])
    assert all(item["rule_id"] != "VSL-VM-012" for item in comparison_2_3["new_findings"])

    assert comparison_3_4["summary"]["existing"] >= 1
    assert comparison_3_4["summary"]["new"] == 0
    assert all(item["occurrence_count"] >= 2 for item in comparison_3_4["existing_findings"])
    assert comparison_path.exists()
    assert context["remediation_tracking"]["summary"]["existing"] == comparison_3_4["summary"]["existing"]


def test_exception_finding_appears_in_run_comparison_and_is_excluded_from_score(tmp_path: Path) -> None:
    db_path = tmp_path / "exception-compare.db"
    run1 = run_fixture(db_path, FIXTURES / "inventory_fail.json", tmp_path / "run1.html")
    run2 = run_fixture(db_path, FIXTURES / "inventory_fail.json", tmp_path / "run2.html", previous_run_id=run1)

    with connect(db_path) as conn:
        before = conn.execute("SELECT risk_summary_json FROM inspection_runs WHERE run_id = ?", (run2,)).fetchone()
        finding = conn.execute(
            "SELECT finding_id FROM findings WHERE last_seen_run_id = ? AND rule_id = 'VSL-HOST-002'",
            (run2,),
        ).fetchone()
        mark_finding_exception(
            conn,
            finding["finding_id"],
            reason="客户已批准保留 SSH 访问用于临时运维窗口。",
            owner="virtualization_admin",
            expires_at="2026-12-31",
            approval_note="整改复核前临时例外。",
        )
        finalize_run_summary(conn, run2)
        after = conn.execute("SELECT risk_summary_json FROM inspection_runs WHERE run_id = ?", (run2,)).fetchone()
        comparison = RunComparisonBuilder().build(conn, run1, run2)

    assert json.loads(before["risk_summary_json"])["P3"] > json.loads(after["risk_summary_json"])["P3"]
    assert comparison["summary"]["exception"] == 1
    assert any(item["rule_id"] == "VSL-HOST-002" for item in comparison["exception_findings"])


def test_compare_runs_cli_generates_report_package_with_tracking_section(tmp_path: Path) -> None:
    db_path = tmp_path / "compare-cli.db"
    run1 = run_fixture(db_path, FIXTURES / "inventory_fail.json", tmp_path / "run1.html")
    run2 = run_fixture(db_path, FIXTURES / "inventory_pass.json", tmp_path / "run2.html", previous_run_id=run1)
    report_dir = tmp_path / "compare-report"
    args = type(
        "Args",
        (),
        {
            "db": str(db_path),
            "previous_run_id": run1,
            "current_run_id": run2,
            "report_dir": str(report_dir),
            "zip_report": True,
        },
    )()

    cmd_compare_runs(args)

    index = (report_dir / "index.html").read_text(encoding="utf-8")
    payload = json.loads((report_dir / "data" / "customer_report_payload.json").read_text(encoding="utf-8"))
    comparison = json.loads((tmp_path / "compare-report_comparison" / "run_comparison.json").read_text(encoding="utf-8"))

    assert (report_dir / "index.html").exists()
    assert report_dir.with_suffix(".zip").exists()
    assert "与上轮巡检相比" in index
    assert "历史对比" not in index
    assert "整改跟踪" not in index
    assert all(f'id="{section}"' in index for section in ("summary", "environment", "issues", "passed", "inventory"))
    assert not (report_dir / "data" / "report_context.json").exists()
    assert not (report_dir / "data" / "run_comparison.json").exists()
    assert comparison["summary"]["resolved"] > 0
    assert payload["summary"]["comparisonText"].startswith("与上轮巡检相比")
    assert "remediation_tracking" not in payload["report_context"]


def test_promoted_rules_have_pass_fail_and_missing_data_semantics(tmp_path: Path) -> None:
    pass_run = run_fixture(tmp_path / "pass.db", FIXTURES / "inventory_pass.json", tmp_path / "pass.html")
    fail_run = run_fixture(tmp_path / "fail.db", FIXTURES / "inventory_fail.json", tmp_path / "fail.html")
    missing_run = run_fixture(tmp_path / "missing-m2a.db", FIXTURES / "inventory_missing.json", tmp_path / "missing-m2a.html")
    missing_m2b1_fixture = tmp_path / "inventory_missing_m2b1.json"
    missing_m2b1 = json.loads((FIXTURES / "inventory_pass.json").read_text(encoding="utf-8"))
    cluster = next(item for item in missing_m2b1["objects"] if item["object_type"] == "ClusterComputeResource")
    vm = next(item for item in missing_m2b1["objects"] if item["object_type"] == "VirtualMachine")
    for field in ("ha_isolation_response", "host_count", "vmotion_enabled_host_count", "cluster_vmotion_missing_host_count"):
        cluster["properties"].pop(field, None)
    for field in ("invalid_network_count", "orphaned_or_inaccessible", "passthrough_device_count"):
        vm["properties"].pop(field, None)
    missing_m2b1_fixture.write_text(json.dumps(missing_m2b1), encoding="utf-8")
    missing_m2b1_run = run_fixture(tmp_path / "missing-m2b1.db", missing_m2b1_fixture, tmp_path / "missing-m2b1.html")

    with connect(tmp_path / "pass.db") as conn:
        statuses = {
            row["rule_id"]: row["result_status"]
            for row in conn.execute(
                f"SELECT rule_id, result_status FROM rule_results WHERE run_id = ? AND rule_id IN ({','.join('?' for _ in PROMOTED_RULE_IDS)})",
                (pass_run, *sorted(PROMOTED_RULE_IDS)),
            )
        }
        assert set(statuses) == PROMOTED_RULE_IDS
        assert set(statuses.values()) == {"passed"}

    with connect(tmp_path / "fail.db") as conn:
        failed_ids = {
            row["rule_id"]
            for row in conn.execute(
                f"SELECT DISTINCT rule_id FROM rule_results WHERE run_id = ? AND result_status = 'failed' AND rule_id IN ({','.join('?' for _ in PROMOTED_RULE_IDS)})",
                (fail_run, *sorted(PROMOTED_RULE_IDS)),
            )
        }
        assert failed_ids == PROMOTED_RULE_IDS

    with connect(tmp_path / "missing-m2a.db") as conn:
        missing_ids = {
            row["rule_id"]
            for row in conn.execute(
                f"SELECT DISTINCT rule_id FROM rule_results WHERE run_id = ? AND result_status = 'unavailable' AND rule_id IN ({','.join('?' for _ in M2A_RULE_IDS)})",
                (missing_run, *sorted(M2A_RULE_IDS)),
            )
        }
        assert missing_ids == {
            "VSL-HOST-016",
            "VSL-HOST-019",
            "VSL-HOST-020",
            "VSL-NET-004",
        }
        assert scalar(conn, "SELECT COUNT(*) FROM findings WHERE last_seen_run_id = ?", (missing_run,)) == 0

    with connect(tmp_path / "missing-m2b1.db") as conn:
        missing_ids = {
            row["rule_id"]
            for row in conn.execute(
                f"SELECT DISTINCT rule_id FROM rule_results WHERE run_id = ? AND result_status = 'unavailable' AND rule_id IN ({','.join('?' for _ in M2B1_RULE_IDS)})",
                (missing_m2b1_run, *sorted(M2B1_RULE_IDS)),
            )
        }
        assert missing_ids == M2B1_RULE_IDS
        assert scalar(conn, "SELECT COUNT(*) FROM findings WHERE last_seen_run_id = ?", (missing_m2b1_run,)) == 0


def test_m2e_backfilled_rules_have_pass_fail_and_missing_data_semantics(tmp_path: Path) -> None:
    pass_run = run_fixture(tmp_path / "m2e-pass.db", FIXTURES / "inventory_pass.json", tmp_path / "m2e-pass.html")
    fail_run = run_fixture(tmp_path / "m2e-fail.db", FIXTURES / "inventory_fail.json", tmp_path / "m2e-fail.html")

    missing_fixture = tmp_path / "inventory_missing_m2e.json"
    missing_inventory = json.loads((FIXTURES / "inventory_pass.json").read_text(encoding="utf-8"))
    for item in missing_inventory["objects"]:
        props = item["properties"]
        for field in (
            "host_cpu_model_distinct_count",
            "host_memory_capacity_skew_ratio",
            "drs_disabled_rule_count",
            "syslog_configured",
            "firewall_default_incoming_blocked",
            "datastore_multipath_issue_count",
            "datastore_active_path_count",
            "thin_provisioning_overcommit_ratio",
            "datastore_filesystem_version",
            "snapshot_chain_depth",
            "nonpersistent_disk_count",
            "numa_affinity_configured",
            "vmware_tools_installed",
            "vcenter_admin_account_count",
            "task_backlog_count",
        ):
            props.pop(field, None)
    missing_fixture.write_text(json.dumps(missing_inventory), encoding="utf-8")
    missing_run = run_fixture(tmp_path / "m2e-missing.db", missing_fixture, tmp_path / "m2e-missing.html")

    with connect(tmp_path / "m2e-pass.db") as conn:
        statuses = {
            row["rule_id"]: row["result_status"]
            for row in conn.execute(
                f"SELECT rule_id, result_status FROM rule_results WHERE run_id = ? AND rule_id IN ({','.join('?' for _ in M2E_BACKFILL_RULE_IDS)})",
                (pass_run, *sorted(M2E_BACKFILL_RULE_IDS)),
            )
        }
        assert set(statuses) == M2E_BACKFILL_RULE_IDS
        assert set(statuses.values()) == {"passed"}

    with connect(tmp_path / "m2e-fail.db") as conn:
        failed_ids = {
            row["rule_id"]
            for row in conn.execute(
                f"SELECT DISTINCT rule_id FROM rule_results WHERE run_id = ? AND result_status = 'failed' AND rule_id IN ({','.join('?' for _ in M2E_BACKFILL_RULE_IDS)})",
                (fail_run, *sorted(M2E_BACKFILL_RULE_IDS)),
            )
        }
        assert failed_ids == M2E_BACKFILL_RULE_IDS

    with connect(tmp_path / "m2e-missing.db") as conn:
        missing_ids = {
            row["rule_id"]
            for row in conn.execute(
                f"SELECT DISTINCT rule_id FROM rule_results WHERE run_id = ? AND result_status = 'unavailable' AND rule_id IN ({','.join('?' for _ in M2E_BACKFILL_RULE_IDS)})",
                (missing_run, *sorted(M2E_BACKFILL_RULE_IDS)),
            )
        }
        assert missing_ids == M2E_BACKFILL_RULE_IDS
        assert scalar(conn, "SELECT COUNT(*) FROM findings WHERE last_seen_run_id = ?", (missing_run,)) == 0


def test_m2e2_backfilled_rules_have_real_semantics_and_customer_values(tmp_path: Path) -> None:
    pass_run = run_fixture(tmp_path / "m2e2-pass.db", FIXTURES / "inventory_pass.json", tmp_path / "m2e2-pass.html")
    fail_run = run_fixture(tmp_path / "m2e2-fail.db", FIXTURES / "inventory_fail.json", tmp_path / "m2e2-fail.html")

    missing_fixture = tmp_path / "inventory_missing_m2e2.json"
    missing_inventory = json.loads((FIXTURES / "inventory_pass.json").read_text(encoding="utf-8"))
    for item in missing_inventory["objects"]:
        props = item["properties"]
        for field in (
            "host_certificate_days_remaining",
            "host_license_assigned",
            "host_license_is_evaluation",
            "host_license_expiration_days",
            "host_log_core_dump_configured",
            "pnic_error_count",
            "powered_off_days",
            "role_permission_inheritance_issue_count",
        ):
            props.pop(field, None)
    missing_fixture.write_text(json.dumps(missing_inventory), encoding="utf-8")
    missing_run = run_fixture(tmp_path / "m2e2-missing.db", missing_fixture, tmp_path / "m2e2-missing.html")

    with connect(tmp_path / "m2e2-pass.db") as conn:
        statuses = {
            row["rule_id"]: row["result_status"]
            for row in conn.execute(
                f"SELECT rule_id, result_status FROM rule_results WHERE run_id = ? AND rule_id IN ({','.join('?' for _ in M2E2_BACKFILL_RULE_IDS)})",
                (pass_run, *sorted(M2E2_BACKFILL_RULE_IDS)),
            )
        }
        assert set(statuses) == M2E2_BACKFILL_RULE_IDS
        assert set(statuses.values()) == {"passed"}
        context = ReportContextBuilder().build(conn, pass_run)
        host_license = next(item for item in context["object_results"] if item["rule_id"] == "VSL-HOST-023")
        assert host_license["current_value_zh"] == "永久授权"
        assert "critical_pass_summary" not in context

    with connect(tmp_path / "m2e2-fail.db") as conn:
        failed_ids = {
            row["rule_id"]
            for row in conn.execute(
                f"SELECT DISTINCT rule_id FROM rule_results WHERE run_id = ? AND result_status = 'failed' AND rule_id IN ({','.join('?' for _ in M2E2_BACKFILL_RULE_IDS)})",
                (fail_run, *sorted(M2E2_BACKFILL_RULE_IDS)),
            )
        }
        assert failed_ids == M2E2_BACKFILL_RULE_IDS
        evidence = {
            row["rule_id"]: json.loads(row["evidence_json"])
            for row in conn.execute(
                """
                SELECT rule_id, evidence_json
                FROM rule_results
                WHERE run_id = ?
                  AND result_status = 'failed'
                  AND rule_id IN ('VSL-HOST-008', 'VSL-HOST-023', 'VSL-NET-003')
                """,
                (fail_run,),
            )
        }
        assert evidence["VSL-HOST-008"]["observed_detail"]["host_certificate_days_remaining"] == 20
        assert evidence["VSL-HOST-023"]["observed_detail"]["host_license_expiration_days"] == 15
        assert evidence["VSL-NET-003"]["observed_detail"]["pnic_error_count"] == 12

    with connect(tmp_path / "m2e2-missing.db") as conn:
        missing_ids = {
            row["rule_id"]
            for row in conn.execute(
                f"SELECT DISTINCT rule_id FROM rule_results WHERE run_id = ? AND result_status = 'unavailable' AND rule_id IN ({','.join('?' for _ in M2E2_BACKFILL_RULE_IDS)})",
                (missing_run, *sorted(M2E2_BACKFILL_RULE_IDS)),
            )
        }
        assert missing_ids == M2E2_BACKFILL_RULE_IDS
        assert scalar(conn, "SELECT COUNT(*) FROM findings WHERE last_seen_run_id = ?", (missing_run,)) == 0


def test_failed_rule_results_include_customer_readable_evidence(tmp_path: Path) -> None:
    fail_run = run_fixture(tmp_path / "evidence.db", FIXTURES / "inventory_fail.json", tmp_path / "evidence.html")
    with connect(tmp_path / "evidence.db") as conn:
        rows = {
            row["rule_id"]: json.loads(row["evidence_json"])
            for row in conn.execute(
                """
                SELECT rule_id, evidence_json
                FROM rule_results
                WHERE run_id = ?
                  AND result_status = 'failed'
                  AND rule_id IN ('VSL-CL-016', 'VSL-HOST-019', 'VSL-VM-012', 'VSL-VM-015')
                """,
                (fail_run,),
            )
        }

    assert rows["VSL-CL-016"]["observed_detail"]["cluster_vmotion_missing_host_count"] == 1
    assert rows["VSL-CL-016"]["observed_detail"]["missing_vmotion_hosts"]
    assert "共 2 台主机" in rows["VSL-CL-016"]["evidence_summary_zh"]
    assert "1 台未配置" in rows["VSL-CL-016"]["evidence_summary_zh"]

    assert rows["VSL-HOST-019"]["observed_detail"]["pnic_down_count"] == 1
    assert rows["VSL-HOST-019"]["observed_detail"]["pnic_degraded_count"] == 0

    assert rows["VSL-VM-012"]["observed_detail"]["vcpu_count"] == 16
    assert rows["VSL-VM-012"]["observed_detail"]["threshold"] == 8

    assert rows["VSL-VM-015"]["observed_detail"]["hardware_version_number"] == 10
    assert rows["VSL-VM-015"]["observed_detail"]["expected_min_version"] == 15


def test_passed_results_also_include_evidence_summary_without_changing_status(tmp_path: Path) -> None:
    pass_run = run_fixture(tmp_path / "passed-evidence.db", FIXTURES / "inventory_pass.json", tmp_path / "passed-evidence.html")
    with connect(tmp_path / "passed-evidence.db") as conn:
        row = conn.execute(
            "SELECT result_status, evidence_json FROM rule_results WHERE run_id = ? AND rule_id = 'VSL-CL-016'",
            (pass_run,),
        ).fetchone()
    evidence = json.loads(row["evidence_json"])
    assert row["result_status"] == "passed"
    assert evidence["evidence_summary_zh"]
    assert evidence["observed_detail"]["cluster_vmotion_missing_host_count"] == 0


def test_run_vcenter_connection_failure_creates_vcenter_connection_finding(monkeypatch, tmp_path: Path) -> None:
    def fail_precheck(self):
        raise RuntimeError("connection refused")

    def collect_must_not_run(self, context, plan):
        raise AssertionError("collect should not run when precheck fails")

    monkeypatch.setattr(PyVmomiCollector, "precheck", fail_precheck)
    monkeypatch.setattr(PyVmomiCollector, "collect", collect_must_not_run)
    args = type(
        "Args",
        (),
        {
            "db": str(tmp_path / "connection-failed.db"),
            "vcenter": "vc-offline.local",
            "username": "administrator@vsphere.local",
            "password": "secret",
            "password_prompt": False,
            "port": 443,
            "ssl_no_verify": True,
            "rulepack": str(RULEPACK),
            "report_dir": str(tmp_path / "connection-failed-package"),
            "zip_report": False,
            "html_out": str(tmp_path / "connection-failed.html"),
            "docx_out": None,
        },
    )()

    cmd_run_vcenter(args)

    with connect(Path(args.db)) as conn:
        run = conn.execute("SELECT run_status, current_stage, score, risk_summary_json FROM inspection_runs").fetchone()
        assert run["run_status"] == "success"
        assert run["current_stage"] == "success"
        assert json.loads(run["risk_summary_json"]) == {"P1": 1, "P2": 0, "P3": 0, "P4": 0}
        result = conn.execute("SELECT rule_id, result_status, risk_level FROM rule_results").fetchone()
        assert dict(result) == {"rule_id": "VSL-VC-001", "result_status": "failed", "risk_level": "P1"}
        assert scalar(conn, "SELECT COUNT(*) FROM findings WHERE rule_id = 'VSL-VC-001' AND status = 'open'") == 1
        report_types = {row["report_type"] for row in conn.execute("SELECT report_type FROM reports").fetchall()}
        assert report_types == {"html_package", "json", "engineering_diagnostics"}
    assert (tmp_path / "connection-failed-package" / "index.html").exists()
    assert not (tmp_path / "connection-failed.html").exists()


def test_pyvmomi_mapper_does_not_fake_alarm_or_performance_values(monkeypatch) -> None:
    collector = PyVmomiCollector("vc.local", "user", "pass")
    monkeypatch.setattr(collector, "_certificate_days_remaining", lambda: 365)
    monkeypatch.setattr(collector, "_license_days_remaining", lambda content: 999999)

    class State:
        overallStatus = "red"
        alarm = type("Alarm", (), {"info": type("Info", (), {"name": "Host connection and power state"})()})()
        entity = type("Entity", (), {"name": "esxi-01.local"})()

    class RootFolder:
        triggeredAlarmState = [State()]

    class About:
        instanceUuid = "vc-uuid"
        version = "8.0.3"
        build = "24091160"

    class Content:
        about = About()
        rootFolder = RootFolder()

    vcenter = collector._vcenter_object(Content())
    assert vcenter["properties"]["red_alarm_count"] == 1
    assert vcenter["properties"]["active_red_alarms"] == [
        {"alarm_name": "Host connection and power state", "entity_name": "esxi-01.local", "status": "红色"}
    ]
    assert vcenter["properties"]["version"] == "8.0.3"
    assert vcenter["properties"]["build"] == "24091160"
    assert vcenter["properties"]["certificate_days_remaining"] == 365
    assert vcenter["properties"]["license_days_remaining"] == 999999

    class Runtime:
        connectionState = "connected"

    class ServiceConfig:
        service = []

    class NtpConfig:
        server = ["ntp1.local"]

    class DateTimeInfo:
        ntpConfig = NtpConfig()

    class Config:
        service = ServiceConfig()
        dateTimeInfo = DateTimeInfo()
        lockdownMode = "lockdownDisabled"

    class Host:
        _moId = "host-1"
        name = "esxi-01.local"
        runtime = Runtime()
        config = Config()

    host = collector._host_object(Host())
    assert host["properties"]["lockdown_mode"] == "disabled"
    assert host["properties"]["cpu_usage_avg"] is None
    assert host["properties"]["memory_usage_avg"] is None

    class Summary:
        name = "ds-01"
        capacity = 100
        freeSpace = 50
        accessible = True

    class DatastoreNoAlarmProperty:
        _moId = "ds-1"
        summary = Summary()
        host = []

        @property
        def triggeredAlarmState(self):
            raise RuntimeError("property unavailable")

    datastore = collector._datastore_object(DatastoreNoAlarmProperty())
    assert datastore["properties"]["alarm_count"] is None


def test_host_certificate_fallback_reads_esxi_443_tls_without_esxi_login(monkeypatch) -> None:
    collector = PyVmomiCollector("vc.local", "vcenter-user", "vcenter-password", ssl_verify=False)
    calls = {}

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

        def settimeout(self, timeout):
            calls["socket_timeout"] = timeout

    class FakeTls:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

        def getpeercert(self, binary_form=False):
            calls["binary_form"] = binary_form
            return b"\x01\x02\xa0"

    class FakeSslContext:
        def wrap_socket(self, sock, server_hostname=None):
            calls["server_hostname"] = server_hostname
            return FakeTls()

    def fake_create_connection(address, timeout):
        calls["address"] = address
        calls["timeout"] = timeout
        return FakeSocket()

    monkeypatch.setattr("vstacklens.collection.pyvmomi_collector.socket.create_connection", fake_create_connection)
    monkeypatch.setattr("vstacklens.collection.pyvmomi_collector.ssl._create_unverified_context", lambda: FakeSslContext())
    monkeypatch.setattr(
        collector,
        "_decode_der_certificate",
        lambda der: {
            "notBefore": "Jun 04 12:00:00 2026 GMT",
            "notAfter": "Jun 04 12:00:00 2099 GMT",
            "subject": ((("commonName", "esxi-01.lab.local"),),),
            "issuer": ((("commonName", "VMware VMCA"),),),
            "subjectAltName": (("DNS", "esxi-01.lab.local"), ("IP Address", "192.168.10.21")),
        },
    )

    result = collector._tls_certificate_info("esxi-01.lab.local", timeout=3)

    assert calls["address"] == ("esxi-01.lab.local", 443)
    assert calls["timeout"] == 3
    assert calls["socket_timeout"] == 3
    assert calls["server_hostname"] == "esxi-01.lab.local"
    assert calls["binary_form"] is True
    assert result["days_remaining"] > 90
    assert result["not_after"] == "2099-06-04"
    assert result["subject"] == "commonName=esxi-01.lab.local"
    assert result["issuer"] == "commonName=VMware VMCA"
    assert result["san"] == ["DNS:esxi-01.lab.local", "IP Address:192.168.10.21"]
    assert result["fingerprint"] == "75:06:59:7B:E1:DB:03:10:B0:72:D9:06:67:14:31:56:6D:CD:17:79:F3:59:B6:72:C7:BD:A3:D6:D9:E7:84:FF"
    assert result["probe_method"] == "ESXi 443 TLS 证书探测"


def test_host_certificate_uses_esxi_tls_fallback_when_vcenter_only_has_thumbprint(monkeypatch) -> None:
    collector = PyVmomiCollector("vc.local", "user", "pass")
    calls = {}

    class SummaryConfig:
        sslThumbprint = "AA:BB"

    class Summary:
        config = SummaryConfig()

    class Host:
        name = "esxi-01.lab.local"
        summary = Summary()
        config = None

    def fake_tls(endpoint):
        calls["endpoint"] = endpoint
        return {
            "days_remaining": 365,
            "not_after": "2027-06-04",
            "subject": "commonName=esxi-01.lab.local",
            "issuer": "commonName=VMware VMCA",
            "fingerprint": "01:02:A0",
            "probe_method": "ESXi 443 TLS 证书探测",
            "probe_status": "已通过 ESXi 443 TLS 证书探测采集到期时间（esxi-01.lab.local）",
        }

    monkeypatch.setattr(collector, "_tls_certificate_info", fake_tls)

    result = collector._host_certificate_info(Host())

    assert calls["endpoint"] == "esxi-01.lab.local"
    assert result["days_remaining"] == 365
    assert result["probe_method"] == "ESXi 443 TLS 证书探测"
    assert "vCenter 未返回" not in result["probe_status"]


def test_pyvmomi_asset_locations_are_hierarchical_and_customer_readable() -> None:
    collector = PyVmomiCollector("vc.local", "user", "pass")

    class Root:
        name = "Datacenters"
        parent = None

    class Datacenter:
        name = "DC-01"
        parent = Root()

    class HostFolder:
        name = "host"
        parent = Datacenter()

    class Cluster:
        _moId = "domain-c1"
        name = "Cluster-01"
        parent = HostFolder()
        host = []
        configurationEx = None

    class Host:
        _moId = "host-1"
        name = "esxi-01.local"
        parent = Cluster()

    class Runtime:
        host = Host()

    class VM:
        name = "app-01"
        parent = type("VmFolder", (), {"name": "vm", "parent": Datacenter()})()
        runtime = Runtime()

    class DatastoreMount:
        key = Host()

    class Datastore:
        name = "ds-01"
        parent = type("DatastoreFolder", (), {"name": "datastore", "parent": Datacenter()})()
        host = [DatastoreMount()]

    cluster_object = collector._cluster_object(Cluster())

    assert cluster_object["object_path"] == "vc.local / DC-01 / Cluster-01"
    assert cluster_object["properties"]["asset_location"] == "vc.local / DC-01"
    assert collector._host_location(Host()) == "vc.local / DC-01 / Cluster-01"
    assert collector._vm_location(VM()) == "vc.local / DC-01 / Cluster-01 / 主机 esxi-01.local"
    assert collector._datastore_location(Datastore()) == "vc.local / DC-01 / 挂载集群 Cluster-01"


def test_pyvmomi_mapper_collects_m2b1_fields_without_fake_defaults() -> None:
    collector = PyVmomiCollector("vc.local", "user", "pass")

    class VmotionConfig:
        nicType = "vmotion"
        selectedVnic = ["vmk1"]

    class VnicManager:
        netConfig = [VmotionConfig()]

    class HostConfig:
        virtualNicManagerInfo = VnicManager()

    class Host:
        config = HostConfig()

    assert collector._cluster_vmotion_enabled_host_count([Host(), Host()]) == 2

    class MissingConfigHost:
        config = None

    assert collector._cluster_vmotion_enabled_host_count([MissingConfigHost()]) is None

    class EthernetCard:
        pass

    class Passthrough:
        pass

    class DeviceNamespace:
        class VirtualEthernetCard(EthernetCard):
            pass

        class VirtualPCIPassthrough(Passthrough):
            pass

    class VmNamespace:
        device = DeviceNamespace()

    class Vim:
        vm = VmNamespace()

    class ValidBacking:
        network = object()

    class InvalidBacking:
        network = None

    valid_nic = DeviceNamespace.VirtualEthernetCard()
    valid_nic.backing = ValidBacking()
    invalid_nic = DeviceNamespace.VirtualEthernetCard()
    invalid_nic.backing = InvalidBacking()
    passthrough = DeviceNamespace.VirtualPCIPassthrough()

    class Hardware:
        device = [valid_nic, invalid_nic, passthrough]

    class Config:
        hardware = Hardware()

    class Runtime:
        connectionState = "inaccessible"

    class VM:
        config = Config()
        runtime = Runtime()

    assert collector._invalid_network_count(VM(), Vim()) == 1
    assert collector._orphaned_or_inaccessible(VM()) is True
    assert collector._passthrough_device_count(VM(), Vim()) == 1

    class MissingHardware:
        device = None

    class MissingConfig:
        hardware = MissingHardware()

    class MissingVM:
        config = MissingConfig()
        runtime = None
        summary = None

    assert collector._invalid_network_count(MissingVM(), Vim()) is None
    assert collector._orphaned_or_inaccessible(MissingVM()) is None
    assert collector._passthrough_device_count(MissingVM(), Vim()) is None


def test_global_alarm_count_sums_all_entities(monkeypatch) -> None:
    collector = PyVmomiCollector("vc.local", "user", "pass")

    class RedState:
        overallStatus = "red"

    class GreenState:
        overallStatus = "green"

    class EntityA:
        triggeredAlarmState = [RedState(), GreenState()]

    class EntityB:
        triggeredAlarmState = [RedState(), RedState()]

    class EntityUnavailable:
        @property
        def triggeredAlarmState(self):
            raise RuntimeError("not readable")

    assert collector._global_red_alarm_count([EntityA(), EntityB(), EntityUnavailable()]) == 3


def test_global_alarm_details_summarize_red_alarm_entity_and_name() -> None:
    collector = PyVmomiCollector("vc.local", "user", "pass")

    class AlarmInfo:
        name = "Datastore usage on disk"

    class Alarm:
        info = AlarmInfo()

    class Entity:
        name = "datastore-prod-01"

    class RedState:
        overallStatus = "red"
        alarm = Alarm()
        entity = Entity()

    class GreenState:
        overallStatus = "green"

    class RootFolder:
        name = "root"
        triggeredAlarmState = [RedState(), GreenState()]

    assert collector._global_red_alarm_details([RootFolder()]) == [
        {"alarm_name": "Datastore usage on disk", "entity_name": "datastore-prod-01", "status": "红色"}
    ]


def test_performance_sampler_normalizes_values_without_pyvmomi_query() -> None:
    plan = CollectionPlanner().build(load_rules())
    sampler = _PerformanceSampler.__new__(_PerformanceSampler)
    sampler.plan = plan
    assert sampler._normalize_percent(4521) == 45.21
    assert sampler._cpu_ready_percent(15000, 300) == 5
    assert sampler._normalize_kb_to_mb(2048) == 2
    assert sampler._swap_or_balloon_mb([(1024, 300, "mem.swapped.average"), (3072, 300, "mem.swapped.average"), (2048, 300, "mem.vmmemctl.average")]) == 4
