import json
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from vstacklens.collection.pyvmomi_collector import PyVmomiCollector
from vstacklens.core.context import RunContext
from vstacklens.db.connection import connect, init_db
from vstacklens.db.repositories import (
    ensure_default_scope,
    finalize_run_summary,
    insert_rule,
    insert_rule_result,
    insert_run,
)
from vstacklens.findings.deduplication import FindingDeduplicator
from vstacklens.inventory.normalizer import InventoryNormalizer
from vstacklens.reports.context_builder import ReportContextBuilder
from vstacklens.reports.html_package import HtmlReportPackageBuilder
from vstacklens.reports.report_model import ReportDataFactory
from vstacklens.rules.executor import RuleExecutor
from vstacklens.rules.registry import RuleRegistry
from vstacklens.rules.rulepack_loader import RulePackLoader
from vstacklens.rules.schema_validator import SchemaValidator


ROOT = Path(__file__).resolve().parents[1]
RULEPACK = ROOT / "rulepacks" / "builtin-vsphere-v1"
GB = 1024 * 1024 * 1024


def test_vsan_ssl_context_restores_after_exception() -> None:
    collector = PyVmomiCollector("vc.local", "user", "secret", ssl_verify=False)
    original = ssl._create_default_https_context  # noqa: SLF001

    def fail() -> None:
        assert ssl._create_default_https_context is ssl._create_unverified_context  # noqa: SLF001
        raise RuntimeError("boom")

    try:
        with pytest.raises(RuntimeError, match="boom"):
            collector._with_vsan_ssl_context(fail)
        assert ssl._create_default_https_context is original  # noqa: SLF001
    finally:
        ssl._create_default_https_context = original  # noqa: SLF001


def test_vsan_ssl_context_concurrent_calls_restore_global_context() -> None:
    collector = PyVmomiCollector("vc.local", "user", "secret", ssl_verify=False)
    original = ssl._create_default_https_context  # noqa: SLF001

    def call_vsan(index: int) -> int:
        def inner() -> int:
            assert ssl._create_default_https_context is ssl._create_unverified_context  # noqa: SLF001
            time.sleep(0.02)
            return index

        return collector._with_vsan_ssl_context(inner)

    try:
        with ThreadPoolExecutor(max_workers=4) as executor:
            assert sorted(executor.map(call_vsan, range(8))) == list(range(8))
        assert ssl._create_default_https_context is original  # noqa: SLF001
    finally:
        ssl._create_default_https_context = original  # noqa: SLF001


class FakeVirtualCdrom:
    pass


class FakeVirtualEthernetCard:
    pass


class FakeVirtualPCIPassthrough:
    pass


class FakeVirtualDisk:
    pass


class FakeVim:
    class vm:
        class device:
            VirtualCdrom = FakeVirtualCdrom
            VirtualEthernetCard = FakeVirtualEthernetCard
            VirtualPCIPassthrough = FakeVirtualPCIPassthrough
            VirtualDisk = FakeVirtualDisk

    class dvs:
        class DistributedVirtualPortgroup:
            pass


class FakeDiagnosticSystem:
    def QueryConfig(self):
        return NS(activePartition="mpx.vmhba0:C0:T0:L0:7")


class FakeVsanConfigSystem:
    def VsanClusterGetConfig(self, cluster):
        return NS(enabled=True)


class FakeVsanHealthSystem:
    def VsanQueryVcClusterHealthSummary(self, cluster, fetchFromCache=True):
        return NS(
            checks=[
                NS(testName="Object Compliance", status="yellow", summary="noncompliant object component"),
            ]
        )


class FakeVsanDiskSystem:
    def QueryDiskMappings(self, host):
        return [NS(canonicalName="naa.6000-vsan-disk-01", diskState="red", summary="disk degraded")]


class FakeVsanObjectSystem:
    def QuerySyncingVsanObjectsSummary(self, cluster):
        return NS(totalSyncingObjects=2, totalBytesToSync=2 * GB)


def _load_rules():
    raw_rules = RulePackLoader().load_raw(RULEPACK)
    rules = [SchemaValidator().validate_rule(raw) for raw in raw_rules]
    registry = RuleRegistry()
    registry.register(rules)
    return registry.rules, registry.executable_rules


def _run_context(db_path: Path | None = None) -> RunContext:
    return RunContext(
        run_id="run-healcheck-collector",
        customer_id="customer-test",
        site_id="site-test",
        vcenter_id="vc-test",
        db_path=db_path or ROOT / "tests" / "tmp-healcheck-collector.db",
    )


def _collector() -> PyVmomiCollector:
    return PyVmomiCollector("vcsa.test.local", "administrator", "secret")


def test_alarm_detail_entity_name_timeout_keeps_other_alarm_details() -> None:
    collector = _collector()

    class AlarmInfo:
        name = "Host connection"

    class Alarm:
        info = AlarmInfo()

    class TimeoutEntity:
        _moId = "host-timeout"

        @property
        def name(self):
            raise TimeoutError("The read operation timed out C:\\Users\\admin\\secret token=abc")

    class HealthyEntity:
        name = "esxi-02.lab.local"

    class TimeoutState:
        overallStatus = "red"
        alarm = Alarm()
        entity = TimeoutEntity()

    class HealthyState:
        overallStatus = "red"
        alarm = Alarm()
        entity = HealthyEntity()

    class RootFolder:
        name = "root"
        triggeredAlarmState = [TimeoutState(), HealthyState()]

    details = collector._global_red_alarm_details([RootFolder()])

    assert details is not None
    assert {"alarm_name": "Host connection", "entity_name": "esxi-02.lab.local", "status": "红色"} in details
    assert len(details) == 2
    assert any(item["context"] == "alarm.details.entity.name" for item in collector._collection_warnings)
    assert "C:\\Users" not in json.dumps(collector._collection_warnings, ensure_ascii=False)
    assert "token=abc" not in json.dumps(collector._collection_warnings, ensure_ascii=False)


def test_alarm_detail_all_remote_reads_fail_without_raising() -> None:
    collector = _collector()

    class BrokenEntity:
        @property
        def triggeredAlarmState(self):
            raise TimeoutError("The read operation timed out")

    assert collector._global_red_alarm_count([BrokenEntity()]) is None
    assert collector._global_red_alarm_details([BrokenEntity()]) is None
    assert collector._alarm_collection_status(None, None, collector._collection_warnings) == "unavailable"


def test_alarm_pyvmomi_permission_fault_is_sanitized_and_does_not_abort() -> None:
    collector = _collector()
    no_permission = type("NoPermission", (Exception,), {})

    class FaultedState:
        @property
        def overallStatus(self):
            raise no_permission("session cookie C:\\Users\\admin\\AppData\\Local")

    class RootFolder:
        name = "root"
        triggeredAlarmState = [FaultedState()]

    assert collector._global_red_alarm_count([RootFolder()]) == 0
    assert collector._global_red_alarm_details([RootFolder()]) == []
    warning_text = json.dumps(collector._collection_warnings, ensure_ascii=False)
    assert "NoPermission" in warning_text
    assert "permission_denied" in warning_text
    assert "C:\\Users" not in warning_text
    assert "session cookie" not in warning_text


def _security_policy(**values):
    return NS(security=NS(**values))


def _dvs_bool(value=None, inherited=False):
    return NS(value=value, inherited=inherited)


def _dvs_security_policy(**values):
    return NS(**{name: _dvs_bool(value) for name, value in values.items()})


def _cluster(name: str):
    return NS(_moId=f"domain-{name}", name=name, parent=NS(name="DC1"), host=[], datastore=[])


def _host(name: str, cluster):
    host = NS(_moId=f"host-{name}", name=name, parent=cluster)
    cluster.host.append(host)
    business_vms = [
        NS(
            name=f"app-{index}",
            config=NS(hardware=NS(numCPU=8, memoryMB=16384, device=[])),
        )
        for index in range(8)
    ]
    system_vm = NS(name="vCLS-4c4c4544-004d-3010", config=NS(hardware=NS(numCPU=8, memoryMB=16384, device=[])))
    host.config = NS(
        service=NS(service=[]),
        dateTimeInfo=NS(ntpConfig=NS(server=["10.0.0.10"])),
        network=NS(
            pnic=[],
            vnic=[],
            proxySwitch=[],
            portgroup=[
                NS(
                    key="pg-prod",
                    spec=NS(
                        name="PG-Prod",
                        vswitchName="vSwitch0",
                        policy=_security_policy(allowPromiscuous=False, forgedTransmits=False, macChanges=False),
                    ),
                    computedPolicy=_security_policy(allowPromiscuous=True, forgedTransmits=False, macChanges=True),
                )
            ],
            vswitch=[
                NS(
                    name="vSwitch0",
                    pnic=[],
                    spec=NS(policy=_security_policy(allowPromiscuous=False, forgedTransmits=True, macChanges=False)),
                )
            ],
        ),
        option=[
            NS(key="Syslog.global.logHost", value="udp://syslog.example.local:514"),
            NS(key="VMkernel.Boot.autoCreateDumpFile", value="true"),
        ],
        firewall=NS(defaultPolicy=NS(incomingBlocked=True)),
        certificate=NS(notAfter="2099-01-01T00:00:00Z", subject="CN=esxi", issuer="CN=lab-ca"),
        powerSystemInfo=NS(currentPolicy=NS(shortName="Balanced", key="balanced")),
        product=NS(licenseProductName="VMware vSphere Enterprise Plus"),
    )
    host.configManager = NS(diagnosticSystem=FakeDiagnosticSystem())
    host.runtime = NS(
        connectionState="connected",
        healthSystemRuntime=NS(
            systemHealthInfo=NS(
                numericSensorInfo=[
                    NS(name="Power Supply 1", healthState=NS(key="red", label="Red")),
                    NS(name="Fan 1", healthState=NS(key="yellow", label="Yellow")),
                    NS(name="Temperature", healthState=NS(key="green", label="Green")),
                ]
            )
        ),
    )
    host.hardware = NS(cpuInfo=NS(numCpuCores=8, numCpuThreads=16), memorySize=64 * GB)
    host.summary = NS(config=NS(sslThumbprint="AA:BB"))
    host.vm = [*business_vms, system_vm]
    return host


def _datastore(name: str, datastore_type: str, hosts: list, capacity_gb: int = 100, free_gb: int = 40):
    datastore = NS(
        _moId=f"datastore-{name}",
        parent=NS(name="datastore"),
        summary=NS(
            name=name,
            type=datastore_type,
            capacity=capacity_gb * GB,
            freeSpace=free_gb * GB,
            uncommitted=0,
            accessible=True,
        ),
        info=NS(vmfs=NS(version="6", extent=[])) if datastore_type.casefold() == "vmfs" else NS(),
        host=[NS(key=host) for host in hosts],
        triggeredAlarmState=[],
    )
    for host in hosts:
        cluster = getattr(host, "parent", None)
        if cluster is not None and datastore not in cluster.datastore:
            cluster.datastore.append(datastore)
    return datastore


def _vm(name: str, host, datastores: list, actual_os: str = "Ubuntu Linux (64-bit)"):
    return NS(
        _moId=f"vm-{name}",
        name=name,
        parent=NS(name="vm"),
        runtime=NS(powerState="poweredOn", host=host),
        guest=NS(
            toolsRunningStatus="guestToolsRunning",
            toolsVersionStatus2="guestToolsCurrent",
            guestFullName=actual_os,
        ),
        config=NS(
            guestFullName="Microsoft Windows Server 2019",
            guestId="windows9Server64Guest",
            hardware=NS(numCPU=4, memoryMB=8192, device=[]),
            cpuAllocation=NS(reservation=0, limit=-1),
            memoryAllocation=NS(reservation=0, limit=-1),
            version="vmx-19",
            extraConfig=[],
        ),
        datastore=datastores,
        snapshot=None,
        layoutEx=NS(file=[]),
    )


def _collected_raw_objects():
    collector = _collector()
    cluster_a = _cluster("Cluster-A")
    cluster_b = _cluster("Cluster-B")
    host_a = _host("esxi-01", cluster_a)
    host_b = _host("esxi-02", cluster_b)
    local_ds = _datastore("local-esxi-01", "VMFS", [host_a])
    shared_ds = _datastore("shared-nfs-01", "NFS", [host_a, host_b], capacity_gb=200, free_gb=120)
    vsan_ds = _datastore("vsanDatastore", "vsan", [host_a], capacity_gb=100, free_gb=10)

    mos = {
        "vsan-cluster-config-system": FakeVsanConfigSystem(),
        "vsan-cluster-health-system": FakeVsanHealthSystem(),
        "vsan-disk-management-system": FakeVsanDiskSystem(),
        "vsan-cluster-object-system": FakeVsanObjectSystem(),
    }
    vsan_inventory = {"status": "collected", "clusters": {"Cluster-A": collector._collect_vsan_cluster_summary(cluster_a, mos)}}
    app_vm = _vm("app-01", host_a, [local_ds])
    vcls_vm = _vm("vCLS-4c4c4544-004d-3010", host_a, [local_ds], actual_os="VMware Photon OS")

    return [
        collector._host_object(host_a),
        collector._datastore_object(local_ds),
        collector._datastore_object(shared_ds),
        collector._datastore_object(vsan_ds, vsan_inventory=vsan_inventory),
        collector._vm_object(app_vm, FakeVim),
        collector._vm_object(vcls_vm, FakeVim),
    ]


def test_vm_quickstats_collect_only_cpu_and_consumed_memory_for_pdf() -> None:
    collector = _collector()
    cluster = _cluster("Cluster-QuickStats")
    host = _host("esxi-quickstats", cluster)
    datastore = _datastore("shared-quickstats", "NFS", [host])
    vm = _vm("quickstats-vm", host, [datastore])
    vm.summary = NS(quickStats=NS(overallCpuUsage=1250, hostMemoryUsage=4096))

    properties = collector._vm_object(vm, FakeVim)["properties"]

    assert properties["cpu_usage_mhz"] == 1250
    assert properties["memory_usage_mb"] == 4096
    assert "overallCpuUsage" not in properties
    assert "hostMemoryUsage" not in properties

    vm_without_stats = _vm("quickstats-missing", host, [datastore])
    missing_properties = collector._vm_object(vm_without_stats, FakeVim)["properties"]
    assert missing_properties["cpu_usage_mhz"] is None
    assert missing_properties["memory_usage_mb"] is None


def test_vm_object_collects_template_iso_path_and_committed_storage() -> None:
    collector = _collector()
    cluster = _cluster("Cluster-VM-details")
    host = _host("esxi-vm-details", cluster)
    datastore = _datastore("shared-vm-details", "NFS", [host])
    vm = _vm("vm-details", host, [datastore])
    vm.config.template = True
    cdrom = FakeVim.vm.device.VirtualCdrom()
    cdrom.backing = NS(fileName="[shared-vm-details] images/installer.iso")
    cdrom.connectable = NS(connected=True)
    vm.config.hardware.device = [cdrom]
    vm.summary = NS(storage=NS(committed=12 * GB), quickStats=NS())

    properties = collector._vm_object(vm, FakeVim)["properties"]

    assert properties["is_template"] is True
    assert properties["iso_mounted"] is True
    assert properties["iso_paths"] == ["[shared-vm-details] images/installer.iso"]
    assert properties["storage_committed_bytes"] == 12 * GB


def _sample_host_physical_nics(host):
    network = host.config.network
    network.pnic = [
        NS(device="vmnic0", linkSpeed=NS(speedMb=1000, duplex=True), spec=NS(linkSpeed=None)),
        NS(device="vmnic1", linkSpeed=None, spec=NS(linkSpeed=None)),
        NS(device="vmnic2", linkSpeed=None, spec=NS(linkSpeed=None)),
        NS(device="vmnic3", linkSpeed=None, spec=NS(linkSpeed=None)),
        NS(device="vmnic4", linkSpeed=NS(speedMb=10000, duplex=True), spec=NS(linkSpeed=None)),
        NS(device="vmnic5", linkSpeed=NS(speedMb=10000, duplex=True), spec=NS(linkSpeed=NS(speedMb=10000, duplex=True))),
    ]
    network.vswitch[0].pnic = ["key-vim.host.PhysicalNic-vmnic0"]
    network.proxySwitch = [NS(dvsName="vSAN-vDS", pnic=["key-vim.host.PhysicalNic-vmnic4"])]
    network.opaqueSwitch = [NS(name="NSX-Opaque", pnic=["key-vim.host.PhysicalNic-vmnic5"])]
    return network


def _set_standard_portgroup_usage(network, *, active=(), standby=(), port_type="host"):
    portgroup = network.portgroup[0]
    portgroup.port = [NS(type=port_type)]
    portgroup.computedPolicy = NS(
        nicTeaming=NS(nicOrder=NS(activeNic=list(active), standbyNic=list(standby)))
    )
    if port_type == "host":
        network.vnic = [NS(device="vmk0", spec=NS(portgroup=portgroup.spec.name))]


def test_physical_nic_rule_ignores_down_adapters_without_switch_binding() -> None:
    collector = _collector()
    cluster = _cluster("vSAN")
    raw_hosts = []

    for address in ("192.168.10.64", "192.168.10.67", "192.168.10.68"):
        host = _host(address, cluster)
        network = _sample_host_physical_nics(host)
        raw_host = collector._host_object(host)
        raw_hosts.append(raw_host)
        props = raw_host["properties"]

        assert props["pnic_down_count"] == 0
        assert props["pnic_degraded_count"] == 0
        assert props["physical_nic_link_issue_count"] == 0
        details = {item["device"]: item for item in props["physical_nic_details"]}
        assert len(details) == 6
        for device in ("vmnic1", "vmnic3"):
            assert details[device]["link_state"] == "down"
            assert details[device]["assessment"] == "unused"
            assert details[device]["issue_codes"] == []
        assert details["vmnic0"]["assigned_switches"] == ["vSwitch0"]
        assert details["vmnic4"]["assigned_switches"] == ["vSAN-vDS"]
        assert details["vmnic5"]["assigned_switches"] == ["NSX-Opaque"]
        assert details["vmnic4"]["autonegotiation"] is True

    inventory = InventoryNormalizer().normalize({"objects": raw_hosts})
    _, executable_rules = _load_rules()
    results = RuleExecutor().execute(_run_context(), inventory, executable_rules)
    pnic_results = [item for item in results if item["rule_id"] == "VSL-HOST-019"]
    assert {item["object_name"] for item in pnic_results} == {"192.168.10.64", "192.168.10.67", "192.168.10.68"}
    assert all(item["result_status"] == "passed" for item in pnic_results)


def test_physical_nic_rule_reports_only_bound_down_or_mismatched_links() -> None:
    collector = _collector()
    host = _host("192.168.10.64", _cluster("vSAN"))
    network = _sample_host_physical_nics(host)
    vmnic2 = next(item for item in network.pnic if item.device == "vmnic2")
    vmnic2.linkSpeed = NS(speedMb=1000, duplex=True)
    vmnic2.spec.linkSpeed = NS(speedMb=10000, duplex=True)
    network.vswitch[0].pnic.extend(
        ["key-vim.host.PhysicalNic-vmnic1", "key-vim.host.PhysicalNic-vmnic2"]
    )
    _set_standard_portgroup_usage(network, active=("vmnic1", "vmnic2"))

    props = collector._host_object(host)["properties"]

    assert props["pnic_down_count"] == 1
    assert props["pnic_degraded_count"] == 1
    assert props["physical_nic_link_issue_count"] == 2
    assert props["affected_nics"] == ["vmnic1", "vmnic2"]
    by_device = {item["device"]: item for item in props["link_speed_detail"]}
    assert by_device["vmnic1"]["assigned_switches"] == ["vSwitch0"]
    assert by_device["vmnic1"]["issue_codes"] == ["link_down"]
    assert by_device["vmnic2"]["configured_speed_mb"] == 10000
    assert "speed_mismatch" in by_device["vmnic2"]["issue_codes"]


def test_active_portgroup_uplink_down_is_reported() -> None:
    collector = _collector()
    host = _host("192.168.10.64", _cluster("vSAN"))
    network = _sample_host_physical_nics(host)
    network.vswitch[0].pnic.append("key-vim.host.PhysicalNic-vmnic1")
    _set_standard_portgroup_usage(network, active=("vmnic1",))

    details = {item["device"]: item for item in collector._physical_nic_details(host)}

    assert details["vmnic1"]["is_in_use"] is True
    assert details["vmnic1"]["portgroup_usage"] == [
        {"switch": "vSwitch0", "portgroup": "PG-Prod", "role": "active"}
    ]
    assert details["vmnic1"]["issue_codes"] == ["link_down"]


def test_standby_portgroup_uplink_down_is_reported() -> None:
    collector = _collector()
    host = _host("192.168.10.64", _cluster("vSAN"))
    network = _sample_host_physical_nics(host)
    network.vswitch[0].pnic.append("key-vim.host.PhysicalNic-vmnic1")
    _set_standard_portgroup_usage(network, active=("vmnic0",), standby=("vmnic1",), port_type="virtualMachine")

    details = {item["device"]: item for item in collector._physical_nic_details(host)}

    assert details["vmnic1"]["is_in_use"] is True
    assert details["vmnic1"]["portgroup_usage"][0]["role"] == "standby"
    assert details["vmnic1"]["issue_codes"] == ["link_down"]


def test_bound_uplink_excluded_by_all_portgroup_team_orders_is_not_reported() -> None:
    collector = _collector()
    host = _host("192.168.10.64", _cluster("vSAN"))
    network = _sample_host_physical_nics(host)
    network.vswitch[0].pnic.append("key-vim.host.PhysicalNic-vmnic1")
    _set_standard_portgroup_usage(network, active=("vmnic0",), standby=(), port_type="host")

    details = {item["device"]: item for item in collector._physical_nic_details(host)}
    props = collector._host_object(host)["properties"]

    assert details["vmnic1"]["is_in_use"] is False
    assert details["vmnic1"]["usage_status"] == "unused"
    assert details["vmnic1"]["issue_codes"] == []
    assert props["pnic_down_count"] == 0


def test_portgroup_without_vm_or_vmk_is_not_reported_even_if_it_lists_uplink() -> None:
    collector = _collector()
    host = _host("192.168.10.64", _cluster("vSAN"))
    network = _sample_host_physical_nics(host)
    network.vswitch[0].pnic.append("key-vim.host.PhysicalNic-vmnic1")
    network.portgroup[0].computedPolicy = NS(
        nicTeaming=NS(nicOrder=NS(activeNic=["vmnic1"], standbyNic=[]))
    )
    network.vnic = []
    network.portgroup[0].port = []

    details = {item["device"]: item for item in collector._physical_nic_details(host)}

    assert details["vmnic1"]["is_in_use"] is False
    assert details["vmnic1"]["usage_status"] == "unused"
    assert details["vmnic1"]["issue_codes"] == []


def test_standard_portgroup_inherits_switch_teaming_order() -> None:
    collector = _collector()
    host = _host("192.168.10.64", _cluster("vSAN"))
    network = _sample_host_physical_nics(host)
    network.vswitch[0].pnic.append("key-vim.host.PhysicalNic-vmnic1")
    network.portgroup[0].port = [NS(type="host")]
    network.portgroup[0].computedPolicy = None
    network.portgroup[0].spec.policy.nicTeaming = None
    network.vswitch[0].spec.policy.nicTeaming = NS(
        nicOrder=NS(activeNic=["vmnic1"], standbyNic=[])
    )
    network.vnic = [NS(device="vmk0", spec=NS(portgroup="PG-Prod"))]

    details = {item["device"]: item for item in collector._physical_nic_details(host)}

    assert details["vmnic1"]["is_in_use"] is True
    assert details["vmnic1"]["portgroup_usage"][0]["role"] == "active"
    assert details["vmnic1"]["issue_codes"] == ["link_down"]


def test_distributed_uplink_name_maps_back_to_physical_nic() -> None:
    collector = _collector()
    host = _host("192.168.10.64", _cluster("vSAN"))
    network = _sample_host_physical_nics(host)
    network.vnic = [
        NS(
            device="vmk1",
            spec=NS(distributedVirtualPort=NS(switchUuid="dvs-1", portgroupKey="dvpg-vsan")),
        )
    ]
    dvs = NS(
        uuid="dvs-1",
        name="vSAN-vDS",
        config=NS(defaultPortConfig=NS(uplinkTeamingPolicy=NS(
            uplinkPortOrder=NS(activeUplinkPort=["Uplink 1"], standbyUplinkPort=[])
        ))),
    )
    portgroup = NS(
        key="dvpg-vsan",
        config=NS(
            name="vSAN-PG",
            distributedVirtualSwitch=dvs,
            defaultPortConfig=NS(uplinkTeamingPolicy=NS(
                inherited=False,
                uplinkPortOrder=NS(activeUplinkPort=["Uplink 1"], standbyUplinkPort=[]),
            )),
        ),
        vm=[],
    )
    network.proxySwitch = [
        NS(
            dvsName="vSAN-vDS",
            dvsUuid="dvs-1",
            pnic=[NS(device="vmnic4")],
            uplinkPort=[NS(key="uplink-key-1", value="Uplink 1")],
            spec=NS(backing=NS(pnicSpec=[NS(pnicDevice="vmnic4", uplinkPortKey="uplink-key-1")])),
        )
    ]
    next(item for item in network.pnic if item.device == "vmnic4").linkSpeed = None
    details = {item["device"]: item for item in collector._physical_nic_details(host, [portgroup])}

    assert details["vmnic4"]["is_in_use"] is True
    assert details["vmnic4"]["portgroup_usage"] == [
        {"switch": "vSAN-vDS", "portgroup": "vSAN-PG", "role": "active"}
    ]
    assert details["vmnic4"]["issue_codes"] == ["link_down"]


def test_pyvmomi_collector_maps_healcheck_backfill_sdk_fields() -> None:
    raw_objects = _collected_raw_objects()
    by_name = {item["object_name"]: item["properties"] for item in raw_objects}

    host = by_name["esxi-01"]
    assert host["portgroup_security_issue_count"] == 3
    assert host["portgroup_security_high_risk_count"] == 1
    assert host["portgroup_security_issues"][0]["current_value"] == "已启用"
    assert "host.config.network.portgroup" in host["portgroup_security_collector_source"]
    assert host["host_hardware_health_issue_count"] == 2
    assert host["host_hardware_health_red_count"] == 1
    assert host["hardware_health_collector_source"] == "host.runtime.healthSystemRuntime.systemHealthInfo.numericSensorInfo[]"
    assert host["host_power_policy"] == "Balanced"
    assert host["host_power_policy_high_performance"] is False
    assert host["host_vcpu_allocated"] == 64
    assert host["host_vcpu_to_pcpu_ratio"] == 8.0
    assert host["host_memory_allocated_mb"] == 131072
    assert host["host_memory_allocation_ratio"] == 2.0
    assert host["host_resource_overcommit"] is True

    local = by_name["local-esxi-01"]
    assert local["datastore_is_local"] is True
    assert local["datastore_host_count"] == 1
    assert local["datastore_cluster_names"] == ["Cluster-A"]

    shared = by_name["shared-nfs-01"]
    assert shared["datastore_cross_cluster_shared"] is True
    assert shared["datastore_cluster_names"] == ["Cluster-A", "Cluster-B"]
    assert "datastore.host[].key.parent" in shared["datastore_cluster_collector_source"]

    vsan = by_name["vsanDatastore"]
    assert vsan["datastore_is_vsan"] is True
    assert vsan["vsan_api_status"] == "collected"
    assert vsan["vsan_capacity_issue"] is True
    assert vsan["vsan_cluster_enabled"] is True
    assert vsan["vsan_issue_count"] >= 1
    assert vsan["vsan_resync_object_count"] == 2
    assert "vsanapiutils.GetVsanVcMos" in vsan["vsan_collector_source"]

    vm = by_name["app-01"]
    assert vm["vm_on_local_datastore"] is True
    assert vm["local_datastore_names"] == ["local-esxi-01"]
    assert vm["is_system_vm"] is False
    assert vm["guest_os_tools_running"] is True
    assert vm["guest_os_mismatch"] is True
    assert "vm.guest.guestFullName" in vm["guest_os_collector_source"]

    vcls = by_name["vCLS-4c4c4544-004d-3010"]
    assert vcls["is_system_vm"] is True
    assert vcls["vm_on_local_datastore"] is True


def test_pyvmomi_collector_maps_distributed_portgroup_security_policy() -> None:
    collector = _collector()
    cluster = _cluster("Cluster-A")
    host = _host("esxi-01", cluster)
    host.config.network.portgroup = []
    host.config.network.vswitch = []
    dvs = NS(
        name="DSwitch-Prod",
        config=NS(
            defaultPortConfig=NS(
                securityPolicy=_dvs_security_policy(
                    allowPromiscuous=False,
                    forgedTransmits=False,
                    macChanges=False,
                )
            ),
            host=[NS(config=NS(host=host))],
        ),
    )
    portgroup = NS(
        name="DVPG-Prod",
        config=NS(
            name="DVPG-Prod",
            distributedVirtualSwitch=dvs,
            defaultPortConfig=NS(
                securityPolicy=NS(
                    allowPromiscuous=_dvs_bool(True, inherited=False),
                    forgedTransmits=_dvs_bool(False, inherited=True),
                    macChanges=_dvs_bool(True, inherited=False),
                )
            ),
        ),
    )

    distributed_issues = collector._distributed_portgroup_security_by_host([portgroup])
    raw_host = collector._host_object(host, distributed_portgroup_security_issues=distributed_issues)
    props = raw_host["properties"]

    assert props["portgroup_security_issue_count"] == 2
    assert props["portgroup_security_high_risk_count"] == 1
    assert "vim.dvs.DistributedVirtualPortgroup.config.defaultPortConfig.securityPolicy" in props["portgroup_security_collector_source"]
    assert props["portgroup_security_issues"][0]["scope"] == "distributed_portgroup"
    assert props["portgroup_security_issues"][0]["switch"] == "DSwitch-Prod"
    assert props["portgroup_security_issues"][0]["portgroup"] == "DVPG-Prod"
    assert {item["policy"] for item in props["portgroup_security_issues"]} == {"混杂模式", "MAC Changes"}


def test_pyvmomi_collector_skips_unresolved_inherited_distributed_portgroup_policy() -> None:
    collector = _collector()
    cluster = _cluster("Cluster-A")
    host = _host("esxi-01", cluster)
    host.config.network.portgroup = []
    host.config.network.vswitch = []
    dvs = NS(name="DSwitch-Prod", config=NS(host=[NS(config=NS(host=host))]))
    portgroup = NS(
        name="DVPG-Inherited",
        config=NS(
            name="DVPG-Inherited",
            distributedVirtualSwitch=dvs,
            defaultPortConfig=NS(
                securityPolicy=NS(
                    allowPromiscuous=_dvs_bool(None, inherited=True),
                    forgedTransmits=_dvs_bool(None, inherited=True),
                    macChanges=_dvs_bool(None, inherited=True),
                )
            ),
        ),
    )

    distributed_issues = collector._distributed_portgroup_security_by_host([portgroup])
    raw_host = collector._host_object(host, distributed_portgroup_security_issues=distributed_issues)

    assert distributed_issues == {}
    assert raw_host["properties"]["portgroup_security_issue_count"] == 0


def test_distributed_portgroup_security_fields_flow_to_rules_and_html_payload(tmp_path: Path) -> None:
    collector = _collector()
    cluster = _cluster("Cluster-A")
    host = _host("esxi-01", cluster)
    host.config.network.portgroup = []
    host.config.network.vswitch = []
    dvs = NS(
        name="DSwitch-Prod",
        config=NS(
            defaultPortConfig=NS(
                securityPolicy=_dvs_security_policy(
                    allowPromiscuous=False,
                    forgedTransmits=True,
                    macChanges=False,
                )
            ),
            host=[NS(config=NS(host=host))],
        ),
    )
    portgroup = NS(
        name="DVPG-Prod",
        config=NS(
            name="DVPG-Prod",
            distributedVirtualSwitch=dvs,
            defaultPortConfig=NS(
                securityPolicy=NS(
                    allowPromiscuous=_dvs_bool(True, inherited=False),
                    forgedTransmits=_dvs_bool(None, inherited=True),
                    macChanges=_dvs_bool(False, inherited=False),
                )
            ),
        ),
    )
    distributed_issues = collector._distributed_portgroup_security_by_host([portgroup])
    raw = {"objects": [collector._host_object(host, distributed_portgroup_security_issues=distributed_issues)]}
    inventory = InventoryNormalizer().normalize(raw)
    rules, executable_rules = _load_rules()
    db_path = tmp_path / "dvpg-security.db"
    init_db(db_path)

    with connect(db_path) as conn:
        customer_id, site_id, vcenter_id = ensure_default_scope(conn, "vcsa.test.local")
        run_id = insert_run(conn, customer_id, site_id, vcenter_id, "manual")
        run = RunContext(run_id=run_id, customer_id=customer_id, site_id=site_id, vcenter_id=vcenter_id, db_path=db_path)
        for rule in rules:
            insert_rule(conn, rule)
        results = RuleExecutor().execute(run, inventory, executable_rules)
        for result in results:
            insert_rule_result(conn, result)
        FindingDeduplicator().upsert_findings(conn, site_id, results)
        finalize_run_summary(conn, run_id)
        context = ReportContextBuilder().build(conn, run_id)

    assert all(item["rule_id"] != "VSL-NET-015" for item in context["findings"])


def test_pyvmomi_collector_marks_unsupported_vsan_without_customer_issue_fields() -> None:
    collector = _collector()
    cluster_a = _cluster("Cluster-A")
    host_a = _host("esxi-01", cluster_a)
    vsan_ds = _datastore("vsanDatastore", "vsan", [host_a], capacity_gb=100, free_gb=10)

    raw = collector._datastore_object(
        vsan_ds,
        vsan_inventory={"status": "unsupported", "collection_error": "vSAN API unavailable", "clusters": {}},
    )

    props = raw["properties"]
    assert props["datastore_is_vsan"] is True
    assert props["vsan_capacity_issue"] is True
    assert props["vsan_api_status"] == "unsupported"
    assert props["vsan_issue_count"] is None
    assert props["vsan_collection_error"] == "vSAN API unavailable"


def test_vsan_ssl_failure_uses_no_verify_context_and_is_sanitized(monkeypatch) -> None:
    collector = _collector()
    cluster_a = _cluster("Cluster-A")
    host_a = _host("esxi-01", cluster_a)
    _datastore("vsanDatastore", "vsan", [host_a], capacity_gb=100, free_gb=10)
    observed: dict[str, bool] = {}

    def raise_ssl_error(stub):
        observed["no_verify_context"] = ssl._create_default_https_context is ssl._create_unverified_context  # noqa: SLF001
        raise ssl.SSLError("certificate verify failed C:\\Users\\admin\\AppData\\site-packages token=abc")

    monkeypatch.setitem(sys.modules, "vsanapiutils", NS(GetVsanVcMos=raise_ssl_error))

    inventory = collector._collect_vsan_inventory(NS(_stub=NS()), [cluster_a])
    serialized = json.dumps(inventory, ensure_ascii=False)

    assert observed["no_verify_context"] is True
    assert inventory["status"] == "unavailable"
    assert inventory["collection_error"] == "vSAN API unavailable: ssl_error"
    for forbidden in ["certificate verify failed", "C:\\Users", "site-packages", "token=abc", "SSLError"]:
        assert forbidden not in serialized


def test_unsupported_vsan_collection_does_not_create_customer_finding(tmp_path: Path) -> None:
    collector = _collector()
    cluster_a = _cluster("Cluster-A")
    host_a = _host("esxi-01", cluster_a)
    vsan_ds = _datastore("vsanDatastore", "vsan", [host_a], capacity_gb=100, free_gb=10)
    raw = {
        "objects": [
            collector._datastore_object(
                vsan_ds,
                vsan_inventory={"status": "unsupported", "collection_error": "vSAN API unavailable", "clusters": {}},
            )
        ]
    }
    inventory = InventoryNormalizer().normalize(raw)
    rules, executable_rules = _load_rules()
    db_path = tmp_path / "unsupported-vsan.db"
    init_db(db_path)

    with connect(db_path) as conn:
        customer_id, site_id, vcenter_id = ensure_default_scope(conn, "vcsa.test.local")
        run_id = insert_run(conn, customer_id, site_id, vcenter_id, "manual")
        run = RunContext(run_id=run_id, customer_id=customer_id, site_id=site_id, vcenter_id=vcenter_id, db_path=db_path)
        for rule in rules:
            insert_rule(conn, rule)
        results = RuleExecutor().execute(run, inventory, executable_rules)
        for result in results:
            insert_rule_result(conn, result)
        FindingDeduplicator().upsert_findings(conn, site_id, results)
        finalize_run_summary(conn, run_id)
        context = ReportContextBuilder().build(conn, run_id)

    vsan_result = next(item for item in results if item["rule_id"] == "VSL-DS-020")
    assert vsan_result["result_status"] == "unavailable"
    assert not any(item["rule_id"] == "VSL-DS-020" for item in context["findings"])


def test_unavailable_vsan_collection_does_not_create_customer_finding_or_leak_errors(tmp_path: Path) -> None:
    collector = _collector()
    cluster_a = _cluster("Cluster-A")
    host_a = _host("esxi-01", cluster_a)
    vsan_ds = _datastore("vsanDatastore", "vsan", [host_a], capacity_gb=100, free_gb=10)
    raw = {
        "objects": [
            collector._datastore_object(
                vsan_ds,
                vsan_inventory={"status": "unavailable", "collection_error": "vSAN API unavailable: ssl_error", "clusters": {}},
            )
        ]
    }
    inventory = InventoryNormalizer().normalize(raw)
    rules, executable_rules = _load_rules()
    db_path = tmp_path / "unavailable-vsan.db"
    init_db(db_path)

    with connect(db_path) as conn:
        customer_id, site_id, vcenter_id = ensure_default_scope(conn, "vcsa.test.local")
        run_id = insert_run(conn, customer_id, site_id, vcenter_id, "manual")
        run = RunContext(run_id=run_id, customer_id=customer_id, site_id=site_id, vcenter_id=vcenter_id, db_path=db_path)
        for rule in rules:
            insert_rule(conn, rule)
        results = RuleExecutor().execute(run, inventory, executable_rules)
        for result in results:
            insert_rule_result(conn, result)
        FindingDeduplicator().upsert_findings(conn, site_id, results)
        finalize_run_summary(conn, run_id)
        context = ReportContextBuilder().build(conn, run_id)

    vsan_result = next(item for item in results if item["rule_id"] == "VSL-DS-020")
    assert vsan_result["result_status"] == "unavailable"
    assert not any(item["rule_id"] == "VSL-DS-020" for item in context["findings"])

    report = ReportDataFactory().from_context(context)
    output_dir = tmp_path / "unavailable-vsan-html"
    HtmlReportPackageBuilder().render(report, context, output_dir)
    payload_text = (output_dir / "data" / "customer_report_payload.json").read_text(encoding="utf-8")
    index_text = (output_dir / "index.html").read_text(encoding="utf-8")
    customer_text = payload_text + index_text
    for forbidden in ["TimeoutError", "traceback", "site-packages", "C:\\Users", "D:\\软件开发", "certificate verify failed"]:
        assert forbidden not in customer_text


def test_healcheck_collected_fields_flow_to_rules_and_report_payload(tmp_path: Path) -> None:
    rules, executable_rules = _load_rules()
    raw = {"objects": _collected_raw_objects()}
    inventory = InventoryNormalizer().normalize(raw)
    db_path = tmp_path / "healcheck-backfill.db"
    init_db(db_path)

    with connect(db_path) as conn:
        customer_id, site_id, vcenter_id = ensure_default_scope(conn, "vcsa.test.local")
        run_id = insert_run(conn, customer_id, site_id, vcenter_id, "manual")
        run = RunContext(run_id=run_id, customer_id=customer_id, site_id=site_id, vcenter_id=vcenter_id, db_path=db_path)
        for rule in rules:
            insert_rule(conn, rule)
        results = RuleExecutor().execute(run, inventory, executable_rules)
        for result in results:
            insert_rule_result(conn, result)
        FindingDeduplicator().upsert_findings(conn, site_id, results)
        finalize_run_summary(conn, run_id)
        context = ReportContextBuilder().build(conn, run_id)

    failed = {(item["rule_id"], item["object_name"]): item for item in context["findings"]}
    assert ("VSL-VM-023", "app-01") in failed
    assert ("VSL-HOST-024", "esxi-01") in failed
    assert ("VSL-DS-020", "vsanDatastore") in failed
    assert ("VSL-HOST-026", "esxi-01") in failed

    vsan_detail = failed[("VSL-DS-020", "vsanDatastore")]["observed_detail"]
    assert vsan_detail["vsan_api_status"] == "collected"
    assert vsan_detail["vsan_issue_count"] >= 1
    assert "vsan_collector_source" in vsan_detail

    report = ReportDataFactory().from_context(context)
    output_dir = tmp_path / "html-package"
    HtmlReportPackageBuilder().render(report, context, output_dir)
    payload = json.loads((output_dir / "data" / "customer_report_payload.json").read_text(encoding="utf-8"))
    payload_text = json.dumps(payload, ensure_ascii=False)

    assert "虚拟机运行在本地存储上" in payload_text
    assert "ESXi 主机硬件健康状态异常" in payload_text
    assert "vSAN 存储健康存在异常" in payload_text
    assert "主机资源分配比例偏高" in payload_text
    assert all(item["name"] != "vCLS-4c4c4544-004d-3010" for item in payload["inventory"]["vms"])
    assert "P4" not in payload_text
