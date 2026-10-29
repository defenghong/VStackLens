"""Independent expectations for the 20261018 Manager QA counterexamples.

These fixtures are synthetic and all transports are in memory. They do not
re-execute the historical reproduction script or contact a laboratory target.
"""
from __future__ import annotations

import copy

import pytest

from test_product_nsx import FakeTransport, check, target
from vstacklens.products.management_scope import MANAGEMENT_SCOPE_ID
from vstacklens.products.model import SessionCredential, TargetRef
from vstacklens.products.nsx import collect_nsx
from vstacklens.products.transport import CollectionError


EXPECTED_MANAGER_CHECKS = {
    "nsx.version", "nsx.cluster", "nsx.services", "nsx.resources", "nsx.alarms",
    "nsx.certificates", "nsx.licenses", "nsx.backup", "nsx.dns", "nsx.ntp",
    "nsx.syslog", "nsx.interfaces", "nsx.vcenter",
}
BUSINESS_KEYS = {
    "policy_spec", "transport_nodes", "transport_status", "transport_modules", "transport_resources",
    "tunnels", "uplink_profile", "remote_transport_status", "edge_clusters", "edge_cluster_status",
    "segments", "segment_ports", "port_status", "domains", "groups", "security_policies", "security_rules",
    "gateway_policies", "gateway_rules", "realized_status", "service_definitions", "t0", "t1",
    "t0_state", "t1_state", "t0_static_routes", "t1_static_routes", "t0_locales", "t1_locales",
    "t0_interfaces", "t1_interfaces", "t0_nat", "t1_nat", "t0_nat_rules", "t1_nat_rules", "bgp_neighbors", "bgp_status",
}


class ManagerTransport(FakeTransport):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.created = False
        self.allowed_keys = set()
        self.rejected_calls = []
        self.member_runtime = {}

    def __call__(self, target, credential, routes, **kwargs):
        self.created = True
        self.allowed_keys = set(routes)
        return super().__call__(target, credential, routes, **kwargs)

    def get(self, key, path_params=None, query=None):
        if key not in self.allowed_keys:
            self.rejected_calls.append(key)
            raise AssertionError("A key outside the narrowed Manager allowlist was scheduled")
        if key == "node_runtime" and self.member_runtime:
            self.calls.append((key, path_params or {}, query or {}))
            self.metrics["requests"] += 1
            return copy.deepcopy(self.member_runtime[(path_params or {})["node_id"]])
        return super().get(key, path_params, query)


def collect(fake=None, **kwargs):
    fake = fake or ManagerTransport()
    module = collect_nsx(target(), SessionCredential("admin", "offline-only-credential"), transport_factory=fake, **kwargs)
    return module, fake


def backup_with_cluster(success=True):
    return {"backup_config": {"backup_enabled": True, "backup_schedule": {"hour": 3}},
            "backup_operation_history": {"cluster_backup_statuses": [{"start_time": 1, "end_time": 10, "success": success}]}}


def test_default_manager_scope_schedules_only_manager_sources_before_collection():
    fake = ManagerTransport()
    fake.data["transport_nodes"] = {"results": [{"id": "should-never-be-collected", "node_deployment_info": {"resource_type": "EdgeNode"}}]}
    fake.data["security_policies"] = {"results": [{"id": "should-never-be-collected"}]}
    module, fake = collect(fake)
    assert {row["check_id"] for row in module["checks"]} == EXPECTED_MANAGER_CHECKS
    assert not fake.allowed_keys.intersection(BUSINESS_KEYS)
    assert not {key for key, _, _ in fake.calls}.intersection(BUSINESS_KEYS)
    assert not fake.rejected_calls
    assert module["coverage"]["inspection_scope"]["id"] == "management-v1"
    assert len(module["coverage"]["interface_specifications"]) == 1
    assert module["coverage"]["interface_specifications"][0]["kind"] == "manager"
    assert "should-never-be-collected" not in str(module)
    assert module["verified_pass_count"] == 0


def test_explicit_management_scope_has_same_execution_scope():
    module, fake = collect(inspection_scope=MANAGEMENT_SCOPE_ID)
    assert {row["check_id"] for row in module["checks"]} == EXPECTED_MANAGER_CHECKS
    assert fake.closed and not fake.rejected_calls


@pytest.mark.parametrize("requested", ["legacy", "full", "historical-unscoped", "", "business"])
def test_no_public_full_collection_switch_and_invalid_scope_precedes_transport(requested):
    fake = ManagerTransport()
    with pytest.raises(ValueError):
        collect(fake, inspection_scope=requested)
    assert not fake.created and not fake.calls


@pytest.mark.parametrize("native,lifecycle,expected_status", [
    ("OPEN", "active", "attention"), ("ACKNOWLEDGED", "active", "attention"),
    ("RESOLVED", "cleared", "normal"), ("SUPPRESSED", "unknown", "insufficient_data"),
    ("NEW_NATIVE_STATE", "unknown", "insufficient_data"), (None, "unknown", "insufficient_data"),
])
def test_C1_alarm_lifecycle_keeps_original_state_severity_and_time(native, lifecycle, expected_status):
    fake = ManagerTransport()
    fake.data["alarms"] = {"results": [{"id": "C1", "status": native, "severity": "HIGH",
        "last_reported_time": 1792233561302, "description": "Synthetic lifecycle record"}]}
    module, _ = collect(fake)
    row = check(module, "alarms")
    alarm = module["native_alerts"][0]
    assert (alarm["status"], alarm["severity"], alarm["last_reported_time"]) == (native, "HIGH", 1792233561302)
    assert alarm["lifecycle"] == lifecycle and row["status"] == expected_status
    assert row["values"]["active_count"] == int(lifecycle == "active")
    assert row["values"]["cleared_count"] == int(lifecycle == "cleared")
    assert row["values"]["unknown_state_count"] == int(lifecycle == "unknown")


def test_C1_mixed_active_cleared_unknown_remain_separate_records():
    fake = ManagerTransport()
    fake.data["alarms"] = {"results": [{"id": "active", "status": "OPEN", "severity": "MEDIUM"},
        {"id": "history", "status": "RESOLVED", "severity": "CRITICAL"}, {"id": "unknown", "status": "SUPPRESSED", "severity": "LOW"}]}
    module, _ = collect(fake)
    row = check(module, "alarms")
    assert row["values"]["unresolved_count"] == 1
    assert len(module["native_alerts"]) == 3
    assert row["status"] != "normal"
    assert "P2" not in str(module["native_alerts"])


def test_C4_cluster_success_is_a_component_fact_not_whole_backup_pass():
    fake = ManagerTransport()
    fake.data["backup"] = backup_with_cluster()
    module, _ = collect(fake)
    row = check(module, "backup")
    assert row["status"] == "insufficient_data" and row["completeness"] == "partial"
    assert row["values"]["latest_by_component"]["cluster_backup_statuses"]["success"] is True
    assert row["values"]["component_applicability"]["cluster_backup_statuses"]["state"] == "applicable"
    assert row["values"]["component_applicability"]["node_backup_statuses"]["state"] == "unknown"
    assert row["values"]["component_applicability"]["inventory_backup_statuses"]["state"] == "unknown"
    assert row["values"]["restore_verified"] is False


def test_C4_empty_null_and_missing_history_are_distinct_not_not_applicable():
    fake = ManagerTransport()
    fake.data["backup"] = backup_with_cluster()
    fake.data["backup"]["backup_operation_history"] = {"cluster_backup_statuses": [], "node_backup_statuses": None}
    module, _ = collect(fake)
    row = check(module, "backup")
    assert row["values"]["component_history_input"] == {"cluster_backup_statuses": "empty_list", "node_backup_statuses": "null", "inventory_backup_statuses": "missing"}
    assert row["values"]["missing_applicable_results"] == ["cluster_backup_statuses"]
    assert row["status"] == "insufficient_data" and row["completeness"] == "partial"


def test_C4_three_historical_components_do_not_prove_current_deployment_applicability():
    fake = ManagerTransport()
    fake.data["backup"] = backup_with_cluster()
    history = fake.data["backup"]["backup_operation_history"]
    history.update({"node_backup_statuses": [{"end_time": 20, "success": True}], "inventory_backup_statuses": [{"end_time": 30, "success": True}]})
    module, _ = collect(fake)
    row = check(module, "backup")
    assert row["status"] == "insufficient_data" and row["completeness"] == "partial"
    assert row["values"]["component_applicability"]["node_backup_statuses"]["observed_history"] is True
    assert row["values"]["applicability_review_required"] is True


def test_C4_missing_manager_deployment_type_does_not_invent_component_applicability():
    fake = ManagerTransport()
    fake.data["node"].pop("node_type")
    fake.data["backup"] = backup_with_cluster()
    module, _ = collect(fake)
    row = check(module, "backup")
    assert all(component["state"] == "unknown" for component in row["values"]["component_applicability"].values())
    assert row["status"] == "insufficient_data" and row["completeness"] == "partial"


@pytest.mark.parametrize("native_overall,cluster_success", [("FAILED", True), (None, False)])
def test_C4_native_overall_or_applicable_component_failure_survives_unknown_scope(native_overall, cluster_success):
    fake = ManagerTransport()
    fake.data["backup"] = backup_with_cluster(cluster_success)
    if native_overall is not None:
        fake.data["backup"]["backup_operation_history"]["overall_backup_status"] = native_overall
    module, _ = collect(fake)
    row = check(module, "backup")
    assert row["status"] == "abnormal" and row["completeness"] == "partial"
    assert row["values"]["native_overall_backup_status"] == native_overall


def test_C5_native_stable_plus_manager_down_is_not_a_normal_summary():
    fake = ManagerTransport()
    fake.data["node_runtime"] = {"mgmt_cluster_status": {"status": "DOWN"}}
    module, _ = collect(fake)
    row = check(module, "cluster")
    assert row["status"] == "abnormal"
    assert row["values"]["roles"][0]["status"] == "STABLE"
    assert row["values"]["nodes"][0]["runtime"]["mgmt_cluster_status"]["status"] == "DOWN"
    assert row["values"]["native_role_assessment"] == "normal"
    assert row["values"]["manager_member_assessment"] == "abnormal"
    assert row["values"]["role_member_disagreements"][0]["native_member_values"] == ["DOWN"]


def test_C5_one_failed_member_is_not_hidden_by_another_connected_member():
    fake = ManagerTransport()
    second = copy.deepcopy(fake.data["nodes"]["results"][0]); second["id"] = "manager-02"
    fake.data["nodes"]["results"].append(second); fake.data["nodes"]["result_count"] = 2
    fake.member_runtime = {"manager-01": {"mgmt_cluster_status": {"status": "CONNECTED"}}, "manager-02": {"mgmt_cluster_status": {"status": "DOWN"}}}
    module, _ = collect(fake)
    assert check(module, "cluster")["status"] == "abnormal"
    assert check(module, "cluster")["values"]["actual_deployed_count"] == 2


@pytest.mark.parametrize("runtime", [{}, {"mgmt_cluster_status": {}}, {"mgmt_cluster_status": {"status": "UNRECOGNIZED"}}])
def test_C5_missing_or_unknown_member_state_is_insufficient_not_stable_pass(runtime):
    fake = ManagerTransport(); fake.data["node_runtime"] = runtime
    module, _ = collect(fake)
    row = check(module, "cluster")
    assert row["status"] == "insufficient_data" and row["completeness"] == "partial"
    assert row["values"]["roles"][0]["status"] == "STABLE"


@pytest.mark.parametrize("failed_key,check_id", [("node_runtime", "cluster"), ("backup", "backup"), ("alarms", "alarms")])
def test_permission_failure_does_not_abort_other_manager_checks(failed_key, check_id):
    fake = ManagerTransport(failures={failed_key: CollectionError("permission", "Synthetic HTTP403", http_status=403)})
    module, fake = collect(fake)
    row = check(module, check_id)
    assert row["status"] != "normal"
    assert any(error["http_status"] == 403 for error in row["errors"])
    assert check(module, "dns")["status"] == "normal"
    assert not {key for key, _, _ in fake.calls}.intersection(BUSINESS_KEYS)


def test_management_cancellation_before_collection_sends_no_requests():
    module, fake = collect(cancel_requested=lambda: True)
    assert not fake.calls
    assert module["collection_state"] == "cancelled"
    assert {row["check_id"] for row in module["checks"]} == EXPECTED_MANAGER_CHECKS
    assert all(row["status"] == "cancelled" for row in module["checks"])


def test_management_cancellation_during_member_discovery_stops_new_requests():
    fake = ManagerTransport()
    module, fake = collect(fake, cancel_requested=lambda: len(fake.calls) >= 4)
    assert len(fake.calls) == 4 and module["collection_state"] == "cancelled"
    assert any(row["status"] == "cancelled" for row in module["checks"])
    assert not fake.rejected_calls


def test_C4_missing_enabled_does_not_hide_explicit_native_overall_failure():
    fake = ManagerTransport()
    fake.data["backup"] = {"backup_operation_history": {"overall_backup_status": "FAILED"}}
    module, _ = collect(fake)
    row = check(module, "backup")
    assert row["status"] == "abnormal" and row["completeness"] == "partial"
    assert row["values"]["backup_enabled"] is None and row["values"]["schedule_present"] is None
    assert row["values"]["configuration_data_incomplete"] is True
    assert "无法确认" in row["summary"] and "字段未返回" in row["summary"]
    assert "未配置" not in row["summary"] and "未启用" not in row["summary"]


def test_C4_missing_enabled_does_not_hide_confirmed_cluster_failure():
    fake = ManagerTransport()
    fake.data["backup"] = {"backup_config": {},
        "backup_operation_history": {"cluster_backup_statuses": [{"end_time": 10, "success": False}]}}
    module, _ = collect(fake)
    row = check(module, "backup")
    assert row["status"] == "abnormal" and row["completeness"] == "partial"
    assert row["values"]["latest_by_component"]["cluster_backup_statuses"]["success"] is False
    assert row["values"]["configuration_data_incomplete"] is True
    assert "无法确认启用状态" in row["summary"] and "无法确认是否已配置" in row["summary"]
    assert "未配置" not in row["summary"] and "未启用" not in row["summary"]


def test_missing_schedule_is_unknown_even_when_enabled_was_read():
    fake = ManagerTransport()
    fake.data["backup"] = {"backup_config": {"backup_enabled": True}, "backup_operation_history": {}}
    module, _ = collect(fake)
    row = check(module, "backup")
    assert row["status"] == "insufficient_data" and row["completeness"] == "partial"
    assert row["values"]["schedule_present"] is None
    assert "无法确认是否已配置" in row["summary"] and "未配置" not in row["summary"]


def test_misrouted_avi_target_is_rejected_before_factory_or_io():
    fake = ManagerTransport()
    avi = TargetRef("avi-wrong-target", "avi", "customer-one", "site-one", "AVI", "192.0.2.12")
    with pytest.raises(ValueError):
        collect_nsx(avi, SessionCredential("admin", "offline-only-credential"), transport_factory=fake)
    assert not fake.created and not fake.calls and not fake.rejected_calls
