from pathlib import Path

from vstacklens.collection.mock_collector import MockCollector
from vstacklens.collection.planner import CollectionPlanner
from vstacklens.core.context import RunContext
from vstacklens.inventory.normalizer import InventoryNormalizer
from vstacklens.rules.executor import RuleExecutor
from vstacklens.rules.registry import RuleRegistry
from vstacklens.rules.rulepack_loader import RulePackLoader
from vstacklens.rules.schema_validator import SchemaValidator


ROOT = Path(__file__).resolve().parents[1]
RULEPACK = ROOT / "rulepacks" / "builtin-vsphere-v1"


def load_rules():
    raw_rules = RulePackLoader().load_raw(RULEPACK)
    rules = [SchemaValidator().validate_rule(raw) for raw in raw_rules]
    registry = RuleRegistry()
    registry.register(rules)
    return registry.executable_rules


def execute_fixture(fixture: str):
    rules = load_rules()
    run = RunContext(
        run_id="run-test",
        customer_id="customer-test",
        site_id="site-test",
        vcenter_id="vc-test",
        db_path=ROOT / "tests" / "tmp.db",
    )
    plan = CollectionPlanner().build(rules)
    raw = MockCollector(ROOT / "tests" / "fixtures" / fixture).collect(run, plan)
    inventory = InventoryNormalizer().normalize(raw)
    return RuleExecutor().execute(run, inventory, rules)


def execute_raw(raw: dict):
    rules = load_rules()
    run = RunContext(
        run_id="run-test",
        customer_id="customer-test",
        site_id="site-test",
        vcenter_id="vc-test",
        db_path=ROOT / "tests" / "tmp.db",
    )
    inventory = InventoryNormalizer().normalize(raw)
    return RuleExecutor().execute(run, inventory, rules)


def result_for(results: list[dict], rule_id: str, object_name: str) -> dict:
    return next(item for item in results if item["rule_id"] == rule_id and item["object_name"] == object_name)


def _host_resource_raw(cpu_ratio: float | None, memory_ratio: float | None) -> dict:
    return {
        "objects": [
            {
                "object_type": "HostSystem",
                "object_key": "host-1",
                "object_name": "esxi-01",
                "object_path": "vc/esxi-01",
                "properties": {
                    "host_resource_overcommit": bool(
                        (cpu_ratio is not None and cpu_ratio >= 4.0)
                        or (memory_ratio is not None and memory_ratio >= 1.5)
                    ),
                    "host_pcpu_count": 16,
                    "host_memory_capacity_mb": 65536,
                    "host_vcpu_allocated": 64,
                    "host_memory_allocated_mb": 65536,
                    "host_vcpu_to_pcpu_ratio": cpu_ratio,
                    "host_memory_allocation_ratio": memory_ratio,
                    "host_resource_collector_source": "unit-test",
                },
            }
        ]
    }


def test_data_quality_missing_returns_unavailable_not_failed() -> None:
    results = execute_fixture("inventory_missing.json")
    host_connection = [r for r in results if r["rule_id"] == "VSL-HOST-001"][0]
    assert host_connection["result_status"] == "unavailable"
    assert host_connection["risk_level"] is None


def test_pass_when_does_not_default_unknown_to_passed() -> None:
    results = execute_fixture("inventory_missing.json")
    statuses = {r["rule_id"]: r["result_status"] for r in results}
    assert statuses["VSL-HOST-001"] == "unavailable"


def test_host_resource_overcommit_none_ratios_are_unavailable_not_error() -> None:
    cpu_missing = result_for(execute_raw(_host_resource_raw(None, 1.0)), "VSL-HOST-026", "esxi-01")
    memory_missing = result_for(execute_raw(_host_resource_raw(2.0, None)), "VSL-HOST-026", "esxi-01")

    assert cpu_missing["result_status"] == "unavailable"
    assert cpu_missing["error_message"] is None
    assert memory_missing["result_status"] == "unavailable"
    assert memory_missing["error_message"] is None


def test_host_resource_overcommit_valid_ratios_still_pass_and_fail() -> None:
    passed = result_for(execute_raw(_host_resource_raw(2.0, 1.0)), "VSL-HOST-026", "esxi-01")
    failed = result_for(execute_raw(_host_resource_raw(5.0, 1.0)), "VSL-HOST-026", "esxi-01")

    assert passed["result_status"] == "passed"
    assert failed["result_status"] == "failed"


def test_severity_policy_dynamic_datastore_capacity() -> None:
    results = execute_fixture("inventory_fail.json")
    datastore = [r for r in results if r["rule_id"] == "VSL-DS-001"][0]
    assert datastore["result_status"] == "failed"
    assert datastore["risk_level"] == "P1"


def test_powered_off_vm_performance_rules_are_not_applicable() -> None:
    results = execute_fixture("inventory_powered_off_vm_perf.json")
    statuses = {r["rule_id"]: r["result_status"] for r in results if r["object_type"] == "VirtualMachine"}
    assert statuses["VSL-VM-004"] == "not_applicable"
    assert statuses["VSL-VM-005"] == "not_applicable"
    assert statuses["VSL-VM-002"] == "passed"


def test_cpu_ready_customer_display_formatting_does_not_change_rule_semantics() -> None:
    raw = {
        "objects": [
            {
                "object_type": "VirtualMachine",
                "object_key": "vm-cpu-ready",
                "object_name": "WF-知识库业务（win）",
                "object_path": "vc/dc/cluster/WF-知识库业务（win）",
                "properties": {
                    "power_state": "poweredOn",
                    "cpu_ready_percent": 13.19,
                },
            }
        ]
    }

    results = execute_raw(raw)
    result = result_for(results, "VSL-VM-004", "WF-知识库业务（win）")

    assert result["result_status"] == "failed"
    assert result["risk_level"] == "P1"
    assert result["observed_value"] == "13.19"
    assert result["expected_value"] == "< 5"
    assert result["evidence"]["current_value"] == 13.19
    assert result["evidence"]["expected_value"] == "< 5"
    assert result["evidence"]["observed_detail"] == {"current_value": 13.19}
    assert result["evidence"]["expected_detail"] == {"expected_value": "< 5"}


def test_healcheck_backfill_rules_trigger_with_collected_fields() -> None:
    raw = {
        "objects": [
            {
                "object_type": "HostSystem",
                "object_key": "host-1",
                "object_name": "esxi-01",
                "object_path": "vc/dc/cluster/esxi-01",
                "properties": {
                    "portgroup_security_issue_count": 2,
                    "portgroup_security_high_risk_count": 1,
                    "portgroup_security_issues": [
                        {
                            "switch": "vSwitch0",
                            "portgroup": "VM Network",
                            "policy": "混杂模式",
                            "current_value": "已启用",
                            "recommended_value": "禁用",
                            "risk_level": "P2",
                        }
                    ],
                    "portgroup_security_collector_source": "host.config.network.portgroup[].computedPolicy.security",
                    "host_hardware_health_issue_count": 2,
                    "host_hardware_health_red_count": 1,
                    "host_hardware_health_issues": [{"component": "Power Supply 1", "status": "red"}],
                    "hardware_health_collector_source": "host.runtime.healthSystemRuntime.systemHealthInfo.numericSensorInfo[]",
                    "host_power_policy": "Balanced",
                    "host_power_policy_high_performance": False,
                    "power_policy_collector_source": "host.config.powerSystemInfo.currentPolicy",
                    "host_resource_overcommit": True,
                    "host_pcpu_count": 16,
                    "host_memory_capacity_mb": 65536,
                    "host_vcpu_allocated": 80,
                    "host_memory_allocated_mb": 131072,
                    "host_vcpu_to_pcpu_ratio": 5.0,
                    "host_memory_allocation_ratio": 2.0,
                    "host_resource_collector_source": "host.hardware.cpuInfo.numCpuCores, host.vm[].config.hardware.numCPU",
                },
            },
            {
                "object_type": "VirtualMachine",
                "object_key": "vm-1",
                "object_name": "app-01",
                "object_path": "vc/dc/cluster/app-01",
                "properties": {
                    "is_system_vm": False,
                    "vm_on_local_datastore": True,
                    "local_datastore_names": ["local-esxi-01"],
                    "datastore_names": ["local-esxi-01"],
                    "local_datastore_collector_source": "vm.datastore[], datastore.summary.type, datastore.host[]",
                    "guest_os_actual": "Ubuntu Linux (64-bit)",
                    "guest_os_configured": "Microsoft Windows Server 2019",
                    "guest_os_tools_running": True,
                    "guest_os_mismatch": True,
                    "guest_os_collector_source": "vm.guest.guestFullName, vm.config.guestFullName, vm.guest.toolsRunningStatus",
                },
            },
            {
                "object_type": "Datastore",
                "object_key": "ds-vsan",
                "object_name": "vsanDatastore",
                "object_path": "vc/dc/vsanDatastore",
                "properties": {
                    "datastore_is_vsan": True,
                    "vsan_api_status": "collected",
                    "vsan_issue_count": 3,
                    "vsan_capacity_issue": True,
                    "vsan_cluster_enabled": True,
                    "vsan_health_issue_count": 1,
                    "vsan_disk_health_issue_count": 1,
                    "vsan_object_health_issue_count": 0,
                    "vsan_resync_object_count": 1,
                    "vsan_used_percent": 85.2,
                    "vsan_free_gb": 800.0,
                    "datastore_capacity_gb": 5400.0,
                    "vsan_collector_source": "vsanapiutils.GetVsanVcMos",
                    "datastore_cross_cluster_shared": False,
                    "datastore_cluster_count": 1,
                    "datastore_cluster_names": ["Cluster-A"],
                    "datastore_host_count": 4,
                    "datastore_cluster_collector_source": "datastore.host[].key.parent",
                },
            },
            {
                "object_type": "Datastore",
                "object_key": "ds-shared",
                "object_name": "shared-nfs-01",
                "object_path": "vc/dc/shared-nfs-01",
                "properties": {
                    "datastore_is_vsan": False,
                    "vsan_capacity_issue": None,
                    "vsan_used_percent": None,
                    "vsan_free_gb": None,
                    "datastore_capacity_gb": 1024.0,
                    "datastore_cross_cluster_shared": True,
                    "datastore_cluster_count": 2,
                    "datastore_cluster_names": ["Cluster-A", "Cluster-B"],
                    "datastore_host_count": 8,
                    "datastore_cluster_collector_source": "datastore.host[].key.parent",
                },
            },
        ]
    }

    results = execute_raw(raw)

    assert result_for(results, "VSL-HOST-024", "esxi-01")["result_status"] == "failed"
    assert result_for(results, "VSL-HOST-024", "esxi-01")["risk_level"] == "P2"
    assert result_for(results, "VSL-HOST-026", "esxi-01")["result_status"] == "failed"
    assert result_for(results, "VSL-VM-023", "app-01")["result_status"] == "failed"
    assert result_for(results, "VSL-DS-020", "vsanDatastore")["result_status"] == "failed"


def test_healcheck_backfill_rules_treat_missing_fields_as_unavailable() -> None:
    raw = {
        "objects": [
            {"object_type": "HostSystem", "object_key": "host-1", "object_name": "esxi-01", "object_path": "vc/esxi-01", "properties": {}},
            {"object_type": "VirtualMachine", "object_key": "vm-1", "object_name": "app-01", "object_path": "vc/app-01", "properties": {}},
            {"object_type": "Datastore", "object_key": "ds-1", "object_name": "datastore01", "object_path": "vc/datastore01", "properties": {}},
        ]
    }

    results = execute_raw(raw)

    for rule_id in {"VSL-HOST-024", "VSL-HOST-026"}:
        assert result_for(results, rule_id, "esxi-01")["result_status"] == "unavailable"
    for rule_id in {"VSL-VM-023"}:
        assert result_for(results, rule_id, "app-01")["result_status"] == "unavailable"
    for rule_id in {"VSL-DS-020"}:
        assert result_for(results, rule_id, "datastore01")["result_status"] == "unavailable"


def test_healcheck_backfill_vm_rules_exclude_system_vms() -> None:
    raw = {
        "objects": [
            {
                "object_type": "VirtualMachine",
                "object_key": "vm-vcls",
                "object_name": "vCLS-4c4c4544-004d-3010",
                "object_path": "vc/dc/vm/vCLS-4c4c4544-004d-3010",
                "properties": {
                    "is_system_vm": True,
                    "vm_on_local_datastore": True,
                    "local_datastore_names": ["local-esxi-01"],
                    "datastore_names": ["local-esxi-01"],
                    "local_datastore_collector_source": "vm.datastore[], datastore.summary.type, datastore.host[]",
                    "guest_os_actual": "VMware Photon OS",
                    "guest_os_configured": "Other Linux",
                    "guest_os_tools_running": True,
                    "guest_os_mismatch": True,
                    "guest_os_collector_source": "vm.guest.guestFullName, vm.config.guestFullName, vm.guest.toolsRunningStatus",
                },
            }
        ]
    }

    results = execute_raw(raw)

    assert result_for(results, "VSL-VM-023", "vCLS-4c4c4544-004d-3010")["result_status"] == "not_applicable"


def test_healcheck_backfill_vsan_not_collected_is_unavailable_not_failed() -> None:
    raw = {
        "objects": [
            {
                "object_type": "Datastore",
                "object_key": "ds-vsan",
                "object_name": "vsanDatastore",
                "object_path": "vc/dc/vsanDatastore",
                "properties": {
                    "datastore_is_vsan": True,
                    "vsan_api_status": "unsupported",
                    "vsan_issue_count": None,
                    "vsan_capacity_issue": True,
                    "vsan_cluster_enabled": None,
                    "vsan_health_issue_count": None,
                    "vsan_disk_health_issue_count": None,
                    "vsan_object_health_issue_count": None,
                    "vsan_resync_object_count": None,
                    "vsan_used_percent": 86.0,
                    "vsan_free_gb": 120.0,
                    "datastore_capacity_gb": 900.0,
                    "vsan_collector_source": "vsanapiutils.GetVsanVcMos",
                },
            }
        ]
    }

    results = execute_raw(raw)

    assert result_for(results, "VSL-DS-020", "vsanDatastore")["result_status"] == "unavailable"


def test_vsan_rule_treats_unavailable_api_statuses_as_unavailable_even_with_issue_counts() -> None:
    unavailable_statuses = [
        "unsupported",
        "unavailable",
        "not_collected",
        "api_error",
        "ssl_error",
        "method_not_found",
        "permission_denied",
        "timeout",
    ]
    raw = {
        "objects": [
            {
                "object_type": "Datastore",
                "object_key": f"ds-vsan-{status}",
                "object_name": f"vsanDatastore-{status}",
                "object_path": f"vc/dc/vsanDatastore-{status}",
                "properties": {
                    "datastore_is_vsan": True,
                    "vsan_api_status": status,
                    "vsan_collection_error": f"vSAN API unavailable: {status}",
                    "vsan_issue_count": 7,
                    "vsan_capacity_issue": False,
                    "vsan_cluster_enabled": True,
                    "vsan_health_issue_count": 6,
                    "vsan_disk_health_issue_count": 0,
                    "vsan_object_health_issue_count": 1,
                    "vsan_resync_object_count": 0,
                    "vsan_used_percent": 42.0,
                    "vsan_free_gb": 1024.0,
                    "datastore_capacity_gb": 2048.0,
                    "vsan_collector_source": "vsanapiutils.GetVsanVcMos",
                },
            }
            for status in unavailable_statuses
        ]
    }

    results = execute_raw(raw)

    for status in unavailable_statuses:
        result = result_for(results, "VSL-DS-020", f"vsanDatastore-{status}")
        assert result["result_status"] == "unavailable"
        assert result["risk_level"] is None
        assert result["error_message"] is None


def test_vsan_rule_collected_status_still_fails_or_passes_from_issue_count() -> None:
    raw = {
        "objects": [
            {
                "object_type": "Datastore",
                "object_key": "ds-vsan-failed",
                "object_name": "vsanDatastoreFailed",
                "object_path": "vc/dc/vsanDatastoreFailed",
                "properties": {
                    "datastore_is_vsan": True,
                    "vsan_api_status": "collected",
                    "vsan_issue_count": 2,
                    "vsan_capacity_issue": False,
                    "vsan_cluster_enabled": True,
                    "vsan_health_issue_count": 1,
                    "vsan_disk_health_issue_count": 0,
                    "vsan_object_health_issue_count": 1,
                    "vsan_resync_object_count": 0,
                    "vsan_used_percent": 42.0,
                    "vsan_free_gb": 1024.0,
                    "datastore_capacity_gb": 2048.0,
                    "vsan_collector_source": "vsanapiutils.GetVsanVcMos",
                },
            },
            {
                "object_type": "Datastore",
                "object_key": "ds-vsan-passed",
                "object_name": "vsanDatastorePassed",
                "object_path": "vc/dc/vsanDatastorePassed",
                "properties": {
                    "datastore_is_vsan": True,
                    "vsan_api_status": "collected",
                    "vsan_issue_count": 0,
                    "vsan_capacity_issue": False,
                    "vsan_cluster_enabled": True,
                    "vsan_health_issue_count": 0,
                    "vsan_disk_health_issue_count": 0,
                    "vsan_object_health_issue_count": 0,
                    "vsan_resync_object_count": 0,
                    "vsan_used_percent": 42.0,
                    "vsan_free_gb": 1024.0,
                    "datastore_capacity_gb": 2048.0,
                    "vsan_collector_source": "vsanapiutils.GetVsanVcMos",
                },
            },
        ]
    }

    results = execute_raw(raw)

    failed = result_for(results, "VSL-DS-020", "vsanDatastoreFailed")
    passed = result_for(results, "VSL-DS-020", "vsanDatastorePassed")
    assert failed["result_status"] == "failed"
    assert failed["risk_level"] == "P3"
    assert failed["error_message"] is None
    assert passed["result_status"] == "passed"
    assert passed["risk_level"] is None
    assert passed["error_message"] is None
