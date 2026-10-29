"""Execute approved template and disabled-cluster applicability boundaries."""
from __future__ import annotations

from pathlib import Path

import pytest

from vstacklens.core.context import RunContext
from vstacklens.inventory.canonical_models import CanonicalInventory, CanonicalObject
from vstacklens.rules.executor import RuleExecutor
from vstacklens.rules.rulepack_loader import RulePackLoader
from vstacklens.rules.schema_validator import SchemaValidator


RULEPACK = Path(__file__).resolve().parents[1] / "rulepacks" / "builtin-vsphere-v1"
VM_CASES = {
    "VSL-VM-001": ({"snapshot_age_days_max": 7}, {"snapshot_age_days_max": 6}),
    "VSL-VM-002": ({"tools_running": False}, {"tools_running": True}),
    "VSL-VM-003": ({"tools_outdated": True}, {"tools_outdated": False}),
    "VSL-VM-004": ({"cpu_ready_percent": 5}, {"cpu_ready_percent": 4.9}),
    "VSL-VM-005": ({"swap_or_balloon_mb": 512}, {"swap_or_balloon_mb": 511}),
    "VSL-VM-006": ({"iso_mounted": True}, {"iso_mounted": False}),
    "VSL-VM-007": ({"snapshot_chain_depth": 3}, {"snapshot_chain_depth": 2}),
    "VSL-VM-009": (
        {"nonpersistent_disk_count": 1, "disk_provisioning_modes": ["independent_nonpersistent"]},
        {"nonpersistent_disk_count": 0, "disk_provisioning_modes": ["persistent"]},
    ),
    "VSL-VM-010": ({"vm_reservation_too_high": True}, {"vm_reservation_too_high": False}),
    "VSL-VM-011": ({"vm_resource_limit_present": True}, {"vm_resource_limit_present": False}),
    "VSL-VM-012": ({"vcpu_count": 9}, {"vcpu_count": 8}),
    "VSL-VM-013": (
        {"numa_affinity_configured": True, "numa_affinity_nodes": [0]},
        {"numa_affinity_configured": False, "numa_affinity_nodes": []},
    ),
    "VSL-VM-014": (
        {"vmware_tools_installed": False, "tools_install_status": "guestToolsNotInstalled"},
        {"vmware_tools_installed": True, "tools_install_status": "guestToolsCurrent"},
    ),
    "VSL-VM-015": ({"hardware_version_number": 14}, {"hardware_version_number": 15}),
    "VSL-VM-016": ({"invalid_network_count": 1}, {"invalid_network_count": 0}),
    "VSL-VM-017": ({"orphaned_or_inaccessible": True}, {"orphaned_or_inaccessible": False}),
    "VSL-VM-018": ({"power_state": "poweredOff"}, {"power_state": "poweredOn"}),
    "VSL-VM-021": ({"passthrough_device_count": 1}, {"passthrough_device_count": 0}),
    "VSL-VM-022": ({"needs_consolidation": True}, {"needs_consolidation": False}),
    "VSL-VM-023": (
        {"vm_on_local_datastore": True}, {"vm_on_local_datastore": False}
    ),
}
CLUSTER_CASES = {
    "VSL-CL-002": ("ha_enabled", {"admission_control_enabled": False}, {"admission_control_enabled": True}),
    "VSL-CL-009": ("ha_enabled", {"ha_isolation_response": "powerOff"}, {"ha_isolation_response": "none"}),
    "VSL-CL-004": ("drs_enabled", {"drs_behavior": "manual"}, {"drs_behavior": "fullyAutomated"}),
    "VSL-CL-012": ("drs_enabled", {"drs_disabled_rule_count": 1, "drs_disabled_rules": ["rule-1"]},
                   {"drs_disabled_rule_count": 0, "drs_disabled_rules": []}),
}


@pytest.fixture(scope="module")
def rules():
    return {
        raw["rule_id"]: SchemaValidator().validate_rule(raw)
        for raw in RulePackLoader().load_raw(RULEPACK)
    }


def execute(tmp_path, rule, props, *, name="business-vm"):
    run = RunContext("run-batch2-rule-test", "customer-test", "site-test", "vc-test", tmp_path / "unused.db")
    target = CanonicalObject(
        object_type=rule.object_type, object_key="stable-object-1", object_name=name,
        object_path=f"vc-test/{name}", properties=props,
    )
    result = RuleExecutor().execute(run, CanonicalInventory(objects=[target]), [rule])
    assert len(result) == 1
    assert result[0]["error_message"] is None, result[0]
    return result[0]


def vm_properties(updates=None):
    return {
        "power_state": "poweredOn", "is_template": False, "is_system_vm": False,
        "local_datastore_names": ["local-test"], "datastore_names": ["local-test"],
        "local_datastore_collector_source": "test:vm.datastore",
        **(updates or {}),
    }


def test_all_virtual_machine_rules_are_in_executable_matrix(rules):
    assert {key for key, rule in rules.items() if rule.object_type == "VirtualMachine"} == set(VM_CASES)


@pytest.mark.parametrize("rule_id", VM_CASES)
@pytest.mark.parametrize("power_state", ["poweredOn", "poweredOff", "suspended", None])
def test_templates_are_not_applicable_for_every_power_state(tmp_path, rules, rule_id, power_state):
    # Missing check metrics still cannot turn a positively identified template into a risk.
    props = {"is_template": True, "power_state": power_state}
    result = execute(tmp_path, rules[rule_id], props)
    assert result["result_status"] == "not_applicable"
    assert result["risk_level"] is None


@pytest.mark.parametrize("rule_id", VM_CASES)
@pytest.mark.parametrize("case_index,status", [(0, "failed"), (1, "passed")])
def test_ordinary_vm_thresholds_and_results_are_preserved(tmp_path, rules, rule_id, case_index, status):
    rule = rules[rule_id]
    result = execute(tmp_path, rule, vm_properties(VM_CASES[rule_id][case_index]))
    assert result["result_status"] == status
    assert result["risk_level"] == (rule.risk_level.value if status == "failed" else None)


@pytest.mark.parametrize("rule_id", VM_CASES)
def test_missing_template_flag_is_not_inferred_from_name(tmp_path, rules, rule_id):
    props = vm_properties(VM_CASES[rule_id][0])
    props.pop("is_template")
    result = execute(tmp_path, rules[rule_id], props, name="production-template-tpl")
    assert result["result_status"] == ("unavailable" if rule_id == "VSL-VM-018" else "failed")
    assert result["result_status"] != "not_applicable"


@pytest.mark.parametrize("rule_id", ["VSL-VM-004", "VSL-VM-005"])
def test_ordinary_powered_off_performance_rules_keep_existing_applicability(tmp_path, rules, rule_id):
    result = execute(tmp_path, rules[rule_id], vm_properties({"power_state": "poweredOff"}))
    assert result["result_status"] == "not_applicable"


@pytest.mark.parametrize("rule_id", CLUSTER_CASES)
def test_disabled_ha_or_drs_is_not_applicable_even_without_detail_metrics(tmp_path, rules, rule_id):
    flag, _, _ = CLUSTER_CASES[rule_id]
    result = execute(tmp_path, rules[rule_id], {flag: False})
    assert result["result_status"] == "not_applicable"
    assert result["risk_level"] is None


@pytest.mark.parametrize("rule_id", CLUSTER_CASES)
@pytest.mark.parametrize("case_index,status", [(1, "failed"), (2, "passed")])
def test_enabled_ha_or_drs_keeps_existing_results(tmp_path, rules, rule_id, case_index, status):
    case = CLUSTER_CASES[rule_id]
    result = execute(tmp_path, rules[rule_id], {case[0]: True, **case[case_index]})
    assert result["result_status"] == status
    assert result["risk_level"] == (rules[rule_id].risk_level.value if status == "failed" else None)


@pytest.mark.parametrize("rule_id", CLUSTER_CASES)
def test_missing_feature_flag_does_not_infer_disabled_from_cluster_name(tmp_path, rules, rule_id):
    _, failed, _ = CLUSTER_CASES[rule_id]
    result = execute(tmp_path, rules[rule_id], failed, name="HA-DRS-disabled")
    assert result["result_status"] == ("unavailable" if rule_id in {"VSL-CL-002", "VSL-CL-004"} else "failed")


def test_local_storage_rule_keeps_prior_system_exclusion(tmp_path, rules):
    props = vm_properties({"is_system_vm": True, "vm_on_local_datastore": True})
    result = execute(tmp_path, rules["VSL-VM-023"], props, name="stable-system-identity")
    assert result["result_status"] == "not_applicable"
    assert result["risk_level"] is None
