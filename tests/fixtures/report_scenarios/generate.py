"""Offline report-layout scenarios evaluated by the unchanged installed rules.

No collector or remote connection is used. Generated reports are deliberately
labelled synthetic and live outside the Git checkout by default.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime,timedelta
from functools import lru_cache
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import sys
import time
from typing import Any
import uuid
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src'))
DEFAULT_OUTPUT = Path('out/report-scenarios')
SOURCE_RUN = 'synthetic-seed'
SOURCE_JSON = Path(__file__).with_name('private-source-not-distributed.json')
SOURCE_SHA256 = 'not-distributed'
SEED_FILE = Path(__file__).with_name('seed.json')
CAPTURED = '2026-01-01T00:00:00+00:00'
MARKER = '合成测试数据'
SCENARIOS = {
    'minimal': {'clusters': 1, 'hosts': 1, 'vms': 10, 'datastores': 2, 'vsan': False},
    'large': {'clusters': 8, 'hosts': 64, 'vms': 1500, 'datastores': 20, 'vsan': True},
    'many_problems': {'clusters': 4, 'hosts': 16, 'vms': 120, 'datastores': 8, 'vsan': True},
    'heterogeneous': {'clusters': 3, 'hosts': 6, 'vms': 60, 'datastores': 4, 'vsan': True, 'esa': True},
    'boundary': {'clusters': 2, 'hosts': 2, 'vms': 20, 'datastores': 4, 'vsan': False},
}

from vstacklens.core.context import RunContext
from vstacklens.db.connection import connect, init_db
from vstacklens.db.repositories import finalize_run_summary, insert_rule, insert_rule_result
from vstacklens.findings.deduplication import FindingDeduplicator
from vstacklens.inventory.canonical_models import CanonicalInventory, CanonicalObject
from vstacklens.inventory.snapshot_engine import SnapshotEngine
from vstacklens.reports.context_builder import ReportContextBuilder
from vstacklens.reports.report_model import ReportDataFactory
from vstacklens.reports.customer_view import get_customer_problem_view, shared_passed_checks
from vstacklens.reports.presentation import customer_check_statistics
from vstacklens.rules.executor import RuleExecutor
from vstacklens.rules.registry import RuleRegistry
from vstacklens.rules.rulepack_loader import RulePackLoader
from vstacklens.rules.schema_validator import SchemaValidator


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _space_guard(output: Path) -> None:
    anchor = output
    while not anchor.exists():
        anchor = anchor.parent
    if shutil.disk_usage(anchor).free < 100 * 1024 ** 3:
        raise RuntimeError('Less than 100 GiB free: synthetic generation stopped')
    if output.resolve().is_relative_to(SOURCE_JSON.parent.resolve()):
        raise ValueError('Synthetic output must not be placed in the real report directory')


@lru_cache(maxsize=1)
def _seed() -> dict[str, Any]:
    """Read a tiny reviewed numeric seed; synthetic cases never read live inputs."""
    prototypes = json.loads(SEED_FILE.read_text('utf-8'))
    if not isinstance(prototypes, dict) or not all(
        isinstance(values, dict) and all(value is None or isinstance(value, (bool, int, float))
                                         for value in values.values())
        for values in prototypes.values()
    ):
        raise ValueError('Bundled seed must contain only numeric, boolean and null facts')
    return {'source_available': False, 'seed_available': True, 'numeric_prototypes': prototypes}


def _rules():
    rules = [SchemaValidator().validate_rule(raw) for raw in RulePackLoader().load_raw(ROOT / 'rulepacks/builtin-vsphere-v1')]
    registry = RuleRegistry()
    registry.register(rules)
    return registry


def _fingerprint() -> str:
    digest = hashlib.sha256()
    for path in (Path(__file__), SEED_FILE):
        digest.update(path.name.encode('utf-8'))
        digest.update(path.read_bytes())
    for path in sorted((ROOT / 'rulepacks/builtin-vsphere-v1/rules').glob('*.yaml')):
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    # Rule/context/model changes can be uncommitted. Hash actual dependency
    # bytes, not just the checkout's HEAD or the rule YAML version strings.
    code = ROOT / 'src/vstacklens'
    dependencies = [code / 'resources.py', code / 'db/schema.sql']
    dependencies.append(code/'collection/license_state.py')
    for name in ('core', 'rules', 'inventory', 'findings', 'db', 'reports'):
        dependencies.extend((code / name).rglob('*.py'))
    for path in sorted(set(dependencies)):
        digest.update(path.relative_to(ROOT).as_posix().encode('utf-8'))
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _base(kind: str) -> dict[str, Any]:
    return dict(_seed()['numeric_prototypes'].get(kind, {}))


def _ip(index: int, subnet: int = 0) -> str:
    # RFC5737 documentation ranges only; indexes never exceed 254 in these sets.
    return f'{("198.51.100", "203.0.113", "192.0.2")[subnet % 3]}.{index % 253 + 1}'


def make_inventory(name: str) -> CanonicalInventory:
    config = SCENARIOS[name]
    tag = 'SYN_' + name.upper()
    clusters = [f'{tag}_集群_{i + 1:02}' for i in range(config['clusters'])]
    hosts = [f'{tag}_ESXi_{i + 1:03}' for i in range(config['hosts'])]
    stores = [f'{tag}_数据存储_{i + 1:02}' for i in range(config['datastores'])]
    target = _ip(239, list(SCENARIOS).index(name))
    root_path = f'{target}/SYN_DATACENTER'
    rows: list[CanonicalObject] = []
    host_cluster = {host: clusters[(i // 2 if name == 'heterogeneous' else i) % len(clusters)] for i, host in enumerate(hosts)}

    def add(kind: str, index: int, label: str, path: str, props: dict[str, Any]) -> None:
        props['synthetic_test_data'] = True
        if kind in {'vCenter','HostSystem'}:
            # Simulate a typed SDK assignment response locally. This is input
            # evidence for the unchanged executor, never an injected rule result.
            from vstacklens.collection.license_state import query_entity_license,fields
            entity=f'{tag}_{kind}_{index:04}';scope=f'{tag}_vCenter_0000'
            now=datetime.fromisoformat(CAPTURED)
            expiry='Never' if kind=='vCenter' else (now+timedelta(days=3650)).isoformat()
            info=SimpleNamespace(name='SYN_VCENTER_LICENSE' if kind=='vCenter' else 'SYN_TERM_LICENSE',editionKey='SYN_ENTERPRISE',
                properties=[SimpleNamespace(key=k,value=v) for k,v in [('ProductName','VMware VirtualCenter Server' if kind=='vCenter' else 'VMware ESX Server'),
                ('ProductVersion',props.get('esxi_version') or props.get('version') or '8.0.3'),('expirationDate',expiry)]])
            assignment=SimpleNamespace(entityId=entity,scope=scope,assignedLicense=info,properties=[])
            def query(*,entityId):
                assert entityId==entity
                return [assignment]
            content=SimpleNamespace(licenseManager=SimpleNamespace(licenseAssignmentManager=SimpleNamespace(QueryAssignedLicenses=query)))
            state=query_entity_license(content,entity,kind,scope,now=now)
            assert state['assigned'] is True and state['expiration_state'] in {'perpetual','dated'}
            props.update(fields(state,host=kind=='HostSystem'))
        rows.append(CanonicalObject(object_type=kind, object_key=f'{tag}_{kind}_{index:04}',
                                    object_name=label, object_path=path, properties=props))

    p = _base('vCenter')
    p.update(asset_location=root_path, connected=True, version='8.0.3', build='24022515', build_current=True,
             red_alarm_count=0, active_red_alarms=[], alarm_detail_collection_status='collected',
             certificate_days_remaining=3650, certificate_not_after='2036-10-19', license_days_remaining=999999,
             vcenter_admin_account_count=1, vcenter_admin_principals=['SYN_ADMIN'], task_backlog_count=0,
             task_backlog_items=[], role_permission_inheritance_issue_count=0,
             role_permission_inheritance_issues=[], collection_mode='synthetic_test',
             collection_mode_label=MARKER, collection_warnings=[], security_warnings=[])
    if name in {'large', 'many_problems'}:
        p.update(red_alarm_count=1, active_red_alarms=[{'alarm_name': 'SYN_备份任务状态', 'entity_name': clusters[0],
                    'entity_type': 'ClusterComputeResource', 'entity_id': f'{tag}_ClusterComputeResource_0000',
                    'alarm_id': f'{tag}_ALARM_1', 'status': 'red', 'acknowledged': False, 'time': CAPTURED}])
    if name == 'many_problems':
        p.update(certificate_days_remaining=-3, certificate_not_after='2026-10-19')
    add('vCenter', 0, f'{tag}_vCenter', root_path, p)

    for i, cluster in enumerate(clusters):
        members = [host for host in hosts if host_cluster[host] == cluster]
        p = _base('ClusterComputeResource')
        versions = ['6.7.0', '7.0.3', '8.0.3'] if name == 'heterogeneous' else ['8.0.3']
        version_index = lambda host: hosts.index(host) // 2 if name == 'heterogeneous' else hosts.index(host)
        distinct = len({versions[version_index(host) % len(versions)] for host in members})
        p.update(asset_location=f'{root_path}/{cluster}', ha_enabled=True, admission_control_enabled=True,
                 drs_enabled=True, drs_behavior='fullyAutomated', host_version_distinct_count=distinct,
                 host_versions=sorted({versions[version_index(host) % len(versions)] for host in members}),
                 cluster_cpu_usage_avg=18.0, evc_enabled=True, evc_mode='intel-skylake',
                 host_cpu_models=['SYN_CPU_MODEL'], host_cpu_model_distinct_count=1,
                 host_memory_capacity_gb_values=[256.0] * len(members), host_memory_capacity_skew_ratio=0,
                 drs_disabled_rule_count=0, drs_disabled_rules=[], ha_heartbeat_datastore_count=2,
                 heartbeat_datastore_names=stores[:2], ha_isolation_response='leavePoweredOn',
                 maintenance_host_count=0, maintenance_hosts=[], host_count=len(members),
                 vmotion_enabled_host_count=len(members), cluster_vmotion_missing_host_count=0,
                 missing_vmotion_hosts=[], vsan_enabled=config['vsan'] and (name != 'heterogeneous' or i == 2))
        if name in {'large', 'many_problems'} and i == 0:
            p.update(ha_enabled=False, drs_enabled=False)
        if name == 'boundary' and i == 0:
            p.update(ha_enabled=False, vm_count=0)
        if name == 'heterogeneous' and hosts[0] in members:
            p.update(maintenance_host_count=1, maintenance_hosts=[hosts[0]])
        add('ClusterComputeResource', i, cluster, f'{root_path}/{cluster}', p)

    for i, host in enumerate(hosts):
        cluster = host_cluster[host]
        host_uses_vsan = config['vsan'] and (name != 'heterogeneous' or cluster == clusters[2])
        p = _base('HostSystem')
        vmk = {'device': 'vmk0', 'ip_address': _ip(i, 1), 'subnet_mask': '255.255.255.0',
               'network_label': 'SYN_STANDARD_MANAGEMENT', 'portgroup': 'SYN_STANDARD_MANAGEMENT',
               'switch': 'SYN_vSwitch0', 'mtu': 1500, 'management': True, 'vmotion': True, 'vsan': False}
        vsan_vmk = {**vmk, 'device': 'vmk1', 'ip_address': _ip(i, 2),
                    'network_label': 'SYN_STANDARD_VSAN', 'portgroup': 'SYN_STANDARD_VSAN', 'vsan': True}
        p.update(asset_location=f'{root_path}/{cluster}', connection_state='connected',
                 esxi_version=['6.7.0', '7.0.3', '8.0.3'][i // 2] if name == 'heterogeneous' else '8.0.3',
                 host_version=['6.7.0', '7.0.3', '8.0.3'][i // 2] if name == 'heterogeneous' else '8.0.3',
                 model='SYN_SERVER_MODEL', host_model='SYN_SERVER_MODEL', build='24022515',
                 ssh_running=False, esxi_shell_running=False, ntp_server_count=2, ntp_servers=['192.0.2.250'],
                 lockdown_mode='normal', cpu_usage_avg=10.0 + i % 8, memory_usage_avg=20.0 + i % 9,
                 syslog_configured=True, syslog_targets=['udp://192.0.2.249:514'],
                 firewall_default_incoming_blocked=True, host_log_core_dump_configured=True,
                 host_log_core_dump_detail={}, pnic_down_count=0, pnic_degraded_count=0, pnic_error_count=0,
                 physical_nic_link_issue_count=0, storage_path_dead_count=0, affected_nics=[],
                 affected_storage_paths=[], physical_nic_details=[{'device': 'vmnic0', 'is_in_use': True,
                 'is_uplink': True, 'assessment': 'up', 'link_state': 'up', 'speed_mbps': 10000,
                 'roles': ['management', 'vmotion'], 'portgroups': ['SYN_STANDARD_MANAGEMENT'], 'issue_codes': []}],
                 vmkernel_mtu_values=[1500], vmotion_vmk_count=1, vmkernel_adapters=[vmk, vsan_vmk] if host_uses_vsan else [vmk],
                 vsan_vmk_adapters=[vsan_vmk] if host_uses_vsan else [],
                 host_certificate_days_remaining=3650, host_certificate_not_after='2036-10-19',
                 host_certificate_subject='CN=SYN_ESXi', host_certificate_issuer='CN=SYN_CA',
                 host_certificate_probe_method='synthetic_fixture', host_certificate_probe_status='collected',
                 host_license_assigned=True, host_license_name='SYN_TERM_LICENSE', host_license_is_evaluation=False,
                 host_license_edition='SYN_ENTERPRISE', pnic_error_detail=[],
                 host_license_expiration_days=3650, host_license_expiration_date='2036-10-19',
                 host_hardware_health_issue_count=0, host_hardware_health_red_count=0, host_hardware_health_issues=[],
                 hardware_health_collector_source='synthetic_fixture', host_resource_collector_source='synthetic_fixture',
                 host_pcpu_count=64, host_memory_capacity_mb=262144, host_vcpu_allocated=128,
                 host_memory_allocated_mb=131072, host_vcpu_to_pcpu_ratio=2.0,
                 host_memory_allocation_ratio=0.5, host_resource_overcommit=False,
                 vsan_enabled=host_uses_vsan, maintenance_mode=False, in_maintenance_mode=False)
        if name in {'large', 'many_problems'}:
            if i % 4 == 0:
                p['ssh_running'] = True
            if i % 3 == 0:
                p.update(host_vcpu_to_pcpu_ratio=4.5, host_vcpu_allocated=288, host_resource_overcommit=True)
            elif i % 3 == 1:
                p.update(host_memory_allocation_ratio=1.28, host_memory_allocated_mb=335544)
            else:
                p.update(host_memory_allocation_ratio=1.88, host_memory_allocated_mb=492830, host_resource_overcommit=True)
        if name == 'many_problems':
            if i == 0:
                p.update(host_certificate_days_remaining=-7, host_certificate_not_after='2026-10-15')
            elif i == 1:
                p.update(cpu_usage_avg=93.0)
        if name == 'heterogeneous':
            # The inventory has ten 2-vCPU guests on each host. Keep the visible
            # configured-vCPU aggregate consistent without changing rule logic.
            p.update(host_vcpu_allocated=20, host_vcpu_to_pcpu_ratio=20 / 64)
            if i == 0:
                p.update(maintenance_mode=True, in_maintenance_mode=True)
            if i == 1:
                p.update(connection_state='disconnected', cpu_usage_avg=None, memory_usage_avg=None)
            if i == 2:
                p.update(host_certificate_not_after=None, host_certificate_days_remaining=None, pnic_error_count=None)
            if i == 3:
                p.update(host_vcpu_to_pcpu_ratio=None, host_memory_allocation_ratio=None,
                         host_resource_overcommit=None)
        add('HostSystem', i, host, f'{root_path}/{cluster}/{host}', p)

    vsan_store_count = config['clusters'] if config['vsan'] and name != 'heterogeneous' else 1 if config['vsan'] else 0
    for i, store in enumerate(stores):
        is_vsan = i < vsan_store_count
        cluster = clusters[2] if name == 'heterogeneous' and is_vsan else clusters[i % len(clusters)]
        members = [host for host in hosts if host_cluster[host] == cluster]
        usage = 30.0 + i % 12
        if name == 'many_problems' and i == 0:
            usage = 94.0
        elif name == 'many_problems' and i == 1:
            usage = 85.0
        total = (len(members) * 3 * 1024.0 if name == 'heterogeneous' else 16384.0) if is_vsan else 2048.0 + i * 100.25
        p = _base('Datastore')
        p.update(asset_location=f'{root_path}/挂载集群 {cluster}', used_percent=usage,
                 accessible=True, free_percent=100 - usage, attached_host_count=len(members),
                 datastore_multipath_applicable=True, datastore_multipath_issue_count=0,
                 datastore_active_path_count=4, datastore_total_path_count=4, datastore_path_issue_detail=[],
                 thin_provisioning_overcommit_ratio=1.0, datastore_filesystem_type='vSAN' if is_vsan else 'VMFS',
                 datastore_filesystem_version=6, datastore_filesystem_legacy=False,
                 datastore_type='vsan' if is_vsan else 'VMFS', datastore_capacity_gb=total,
                 datastore_used_gb=total * usage / 100, datastore_free_gb=total * (100 - usage) / 100,
                 datastore_is_vsan=is_vsan, datastore_is_local=False, datastore_host_names=members,
                 datastore_host_count=len(members), datastore_cluster_names=[cluster],
                 datastore_cluster_count=1, datastore_cross_cluster_shared=False)
        # No vSAN-shaped evidence at all in scenarios that have no vSAN.
        p = {key: value for key, value in p.items() if not key.startswith('vsan_')}
        if is_vsan:
            disks, topology = [], []
            for host in members:
                group = None if config.get('esa') else f'{tag}_GROUP_{hosts.index(host):03}'
                for disk_index in range(3):
                    disk = {'host_name': host, 'host': host, 'device': f'naa.SYN{hosts.index(host):03}{disk_index:02}',
                            'disk_group_uuid': group, 'disk_group': group,
                            'role': 'capacity' if config.get('esa') or disk_index else 'cache',
                            'health': '正常', 'state': 'healthy', 'capacity_gb': 1024.0}
                    disks.append(disk)
                    topology.append(dict(disk))
            p.update(vsan_api_status='collected', vsan_architecture='ESA' if config.get('esa') else 'OSA',
                     vsan_cluster_enabled=True, vsan_cluster_names=[cluster], vsan_used_percent=usage,
                     vsan_free_gb=p['datastore_free_gb'], vsan_issue_count=0,
                     vsan_capacity_issue=False, vsan_collector_source='synthetic_fixture',
                     vsan_health_issue_count=0, vsan_disk_health_issue_count=0, vsan_object_health_issue_count=0,
                     vsan_resync_object_count=0, vsan_resync_bytes=0, vsan_health_issues=[],
                     vsan_disk_health_issues=[], vsan_object_health_issues=[], vsan_physical_disks=disks,
                     vsan_disk_topology=topology, vsan_disk_group_count=None if config.get('esa') else len(members),
                     vsan_cache_disk_count=None if config.get('esa') else len(members),
                     vsan_capacity_disk_count=len(disks) if config.get('esa') else len(members) * 2,
                     vsan_object_count=20 if name == 'heterogeneous' else config['vms'] * 2,
                     vsan_vmdk_count=10 if name == 'heterogeneous' else config['vms'],
                     vsan_native_capacity={'total_capacity_bytes': int(total * 1024 ** 3),
                        'used_capacity_bytes': int(total * usage / 100 * 1024 ** 3),
                        'free_capacity_bytes': int(total * (100 - usage) / 100 * 1024 ** 3)},
                     storage_policy_summary={})
        add('Datastore', i, store, f'{root_path}/{store}', p)

    for i in range(config['vms']):
        host_index = 1 if name == 'boundary' else i % len(hosts)
        host, label = hosts[host_index], f'{tag}_虚拟机_{i + 1:04}'
        cluster = host_cluster[host]
        store = stores[i % len(stores)]
        if name == 'heterogeneous':
            # DS0 is ESA on the 8.0 cluster only. DS1/DS3 belong to the old
            # clusters; DS2 is the 8.0 cluster's standard VMFS datastore.
            store = stores[3] if cluster == clusters[0] else stores[1] if cluster == clusters[1] else stores[0 if (i // len(hosts)) % 2 == 0 else 2]
        if name == 'boundary' and i == 0:
            label += '_极长中文名称_' + '业务归档与灾备验证系统_' * 24 + '_&<>\"\'【】#%+'
        p = _base('VirtualMachine')
        p.update(asset_location=f'{root_path}/{cluster}/主机 {host}', host_name=host,
                 snapshot_age_days_max=0, snapshots=[], snapshot_chain_depth=0, power_state='poweredOn',
                 tools_running=True, tools_outdated=False, vmware_tools_installed=True,
                 tools_install_status='guestToolsInstalled', local_datastore_collector_source='synthetic_fixture',
                 cpu_ready_percent=0.2, swap_or_balloon_mb=0, cpu_usage_mhz=100 + i % 120,
                 memory_usage_mb=256 + i % 256, storage_committed_bytes=20 * 1024 ** 3,
                 iso_mounted=False, iso_paths=[], is_template=False, is_system_vm=False,
                 cpu_reservation_mhz=0, memory_reservation_mb=0, vm_reservation_too_high=False,
                 cpu_limit_mhz=0, memory_limit_mb=0, vm_resource_limit_present=False,
                 vcpu_count=2, thin_disk_count=1, nonpersistent_disk_count=0,
                 disk_provisioning_modes=['thin'], vmdk_count=1,
                 vmdk_inventory=[{'label': 'SYN_DISK_1', 'capacity_bytes': 40 * 1024 ** 3,
                                  'file_name': f'[{store}] SYN_VM_{i:04}/SYN_disk.vmdk'}],
                 numa_affinity_configured=False, numa_affinity_nodes=[], hardware_version='vmx-19',
                 hardware_version_number=19, needs_consolidation=False, invalid_network_count=0,
                 orphaned_or_inaccessible=False, passthrough_device_count=0, powered_off_days=0,
                 datastore_names=[store], local_datastore_names=[], vm_on_local_datastore=False,
                 guest_os_actual='Ubuntu Linux', guest_os_configured='Ubuntu Linux', guest_os_tools_running=True)
        scale = 360 if name == 'large' else 20
        if name in {'large', 'many_problems'}:
            if i < scale:
                p.update(snapshot_age_days_max=30, snapshot_chain_depth=2, snapshots=[
                    {'name': f'{tag}_快照_{i:04}_基线', 'create_time': '2026-09-22T07:01:00+00:00', 'parent': None},
                    {'name': f'{tag}_快照_{i:04}_变更', 'create_time': '2026-10-02T07:01:00+00:00', 'parent': f'{tag}_SNAP_BASE_{i:04}'}])
            elif i < scale * 2:
                p.update(iso_mounted=True, iso_paths=[f'[{stores[-1]}] SYN_ISO/SYN_安装镜像_{i % 4}.iso'])
            elif i < scale * 3:
                p.update(power_state='poweredOff', powered_off_days=120)
            elif i < scale * 3 + (120 if name == 'large' else 20):
                p.update(vm_on_local_datastore=True, local_datastore_names=[store])
            elif i < scale * 3 + (240 if name == 'large' else 40):
                p.update(vm_reservation_too_high=True, cpu_reservation_mhz=3000, memory_reservation_mb=8192)
        if name == 'heterogeneous':
            hardware = [14, 17, 20][host_index // 2]
            p.update(hardware_version=f'vmx-{hardware}', hardware_version_number=hardware)
            if i in {1, 2}:
                p.update(cpu_usage_mhz=None, memory_usage_mb=None,
                         hardware_version=None, hardware_version_number=None)
        if name == 'boundary':
            if i == 0:
                long_path = f'[{stores[-1]}] SYN_超长路径/' + '多级目录和特殊字符_&<>#_/' * 50 + 'SYN_安装镜像.iso'
                p.update(iso_mounted=True, iso_paths=[long_path])
            if i == 1:
                p.update(snapshot_age_days_max=60, snapshot_chain_depth=1,
                         snapshots=[{'name': f'{tag}_真实字面名称_&<>\"\'_2026/9/10 11:11:10',
                                     'create_time': '2026-09-10T03:11:22.427854+00:00', 'parent': None}])
            if i == 19:
                p.update(vm_on_local_datastore=True, local_datastore_names=[store])
        add('VirtualMachine', i, label, f'{root_path}/{cluster}/{label}', p)
    assert all(row.object_key.startswith('SYN_') and row.object_name.startswith('SYN_') for row in rows)
    return CanonicalInventory(objects=rows)


def _build(name: str, directory: Path) -> Path:
    _space_guard(directory)
    directory.mkdir(parents=True, exist_ok=True)
    db = directory / 'scenario.db'
    if db.exists():
        raise FileExistsError('Refuse to overwrite an existing scenario database')
    init_db(db)
    run = RunContext(f'SYN_RUN_{name}', f'SYN_CUSTOMER_{name}', f'SYN_SITE_{name}', f'SYN_VCENTER_{name}', db)
    inventory = make_inventory(name)
    registry = _rules()
    results = RuleExecutor().execute(run, inventory, registry.executable_rules)
    for index, row in enumerate(results):
        row.update(result_id=f'SYN_RESULT_{name}_{index:06}', evaluated_at=CAPTURED, created_at=CAPTURED)
        row['evidence']['collected_at'] = CAPTURED
    target = _ip(239, list(SCENARIOS).index(name))
    with connect(db) as conn:
        conn.execute('INSERT INTO customers VALUES (?,?,?,?,?)', (run.customer_id, f'{MARKER} · {name}', 'active', CAPTURED, CAPTURED))
        conn.execute('INSERT INTO sites VALUES (?,?,?,?,?,?)', (run.site_id, run.customer_id, f'SYN_SITE_{name}', 'active', CAPTURED, CAPTURED))
        conn.execute('INSERT INTO vcenters VALUES (?,?,?,?,?,?,?,?,?,?,?)', (run.vcenter_id, run.customer_id,
                      run.site_id, f'SYN_VCENTER_{name}', target, 443, 'SYN_READONLY', 0, 'active', CAPTURED, CAPTURED))
        conn.execute('''INSERT INTO inspection_runs(run_id,customer_id,site_id,vcenter_id,trigger_type,run_status,current_stage,
                        progress_percent,created_at,updated_at,started_at,finished_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
                     (run.run_id, run.customer_id, run.site_id, run.vcenter_id, 'synthetic_layout_test', 'completed',
                      'completed', 100, CAPTURED, CAPTURED, CAPTURED, CAPTURED))
        SnapshotEngine().write_snapshot(conn, run, inventory)
        for rule in registry.rules:
            insert_rule(conn, rule)
        for row in results:
            insert_rule_result(conn, row)
        FindingDeduplicator().upsert_findings(conn, run.site_id, results)
        finalize_run_summary(conn, run.run_id)
        conn.execute('UPDATE inspection_runs SET updated_at=? WHERE run_id=?', (CAPTURED, run.run_id))
    # sqlite's context manager commits but does not close. Materialize the WAL
    # before opening this finished synthetic snapshot as read-only immutable.
    conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    conn.close()
    return db


def _load_db(name: str, db: Path):
    with sqlite3.connect(db.as_uri() + '?mode=ro&immutable=1', uri=True) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA query_only=ON')
        context = ReportContextBuilder().build(conn, f'SYN_RUN_{name}', include_history=False)
    context['run_timing'] = {'started_at': CAPTURED, 'finished_at': CAPTURED}
    report = ReportDataFactory().from_context(context)
    report.report_info.report_title = f'{MARKER} · {name} · 虚拟化巡检报告'
    report.customer_info.project_name = MARKER
    return report, context


def load_scenario(name: str, output_root: Path | str | None = None, *, frozen_loader_path: Path | str | None = None):
    """Return (ReportData, context), building a versioned isolated cache if needed."""
    if name == 'frozen':
        # Selecting "frozen" is an explicit request for this machine's source;
        # it is never a fallback for one of the five portable synthetic cases.
        frozen_path = Path(frozen_loader_path or os.environ.get('VSTACKLENS_FROZEN_REPORT_LOADER') or
                           r'private-source-not-distributed.py')
        if not frozen_path.is_file():
            raise FileNotFoundError('frozen requires an explicitly available read-only source loader; set frozen_loader_path or VSTACKLENS_FROZEN_REPORT_LOADER')
        spec = importlib.util.spec_from_file_location('report_scenario_frozen_loader',
                    frozen_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.load()
    if name not in SCENARIOS:
        raise ValueError(f'Unknown scenario {name!r}')
    directory = Path(output_root or DEFAULT_OUTPUT).resolve() / name / _fingerprint()[:12]
    _space_guard(directory)
    started = time.perf_counter()
    db = directory / 'scenario.db'
    if not db.is_file():
        _build(name, directory)
    elif not (directory / 'manifest.json').is_file():
        raise RuntimeError('Scenario cache is incomplete or still being built; do not read a partial database')
    else:
        cached = json.loads((directory / 'manifest.json').read_text('utf-8'))
        if cached.get('generator_and_rules_sha256') != _fingerprint():
            raise RuntimeError('Scenario cache fingerprint does not match current generator/seed/rules/code')
        if cached.get('database_sha256') != _sha(db):
            raise RuntimeError('Scenario cache database changed after generation')
    report, context = _load_db(name, db)
    view = get_customer_problem_view(report, context)
    statistics = customer_check_statistics(report, context)
    checklist = shared_passed_checks(report, report.appendix.get('rule_checklist', []), report.vsan_summary)
    manifest = {
        'label': MARKER, 'scenario': name, 'source_run_id': SOURCE_RUN, 'source_json_sha256': SOURCE_SHA256,
        'source_available': _seed()['source_available'], 'generator_and_rules_sha256': _fingerprint(),
        'seed_available': True, 'synthetic_source_dependency': 'bundled seed.json only; real source is not opened',
        'seed_sha256': _sha(SEED_FILE), 'database_sha256': _sha(db),
        'scope': SCENARIOS[name], 'hosts': SCENARIOS[name]['hosts'], 'vms': SCENARIOS[name]['vms'],
        'problem_categories': view.caliber['problem_count'], 'affected_unique_objects': view.caliber['affected_total'],
        'problem_records': sum(x.category['finding_count'] for x in view.categories),
        'checks': {key: statistics[key] for key in ('total', 'passed', 'failed')},
        'passed_checklist_items': len(checklist), 'raw_result_states': context['result_status_summary'],
        'category_objects': {x.display['category_id']: x.display['count'] for x in view.categories},
        'category_levels': {x.display['category_id']: x.display['level'] for x in view.categories},
        'rule_count': len(_rules().executable_rules), 'database_bytes': db.stat().st_size,
        'load_seconds': round(time.perf_counter() - started, 3), 'directory': str(directory),
        'expected_statistics_method': 'Unmodified RuleExecutor + current rulepack + customer P1-P3 projection; no injected result statuses',
        'provenance': 'Reviewed numeric/boolean/null prototypes extracted from frozen run; all identities and structured synthetic facts are generated locally',
    }
    if name == 'minimal':
        assert manifest['checks']['total'] > 0, manifest
        assert manifest['problem_categories'] == manifest['affected_unique_objects'] == manifest['checks']['failed'] == 0, manifest
        assert manifest['checks']['passed'] == manifest['checks']['total'], manifest
        assert manifest['raw_result_states']['unavailable'] == manifest['raw_result_states']['error'] == 0, manifest
    if name == 'large':
        assert manifest['problem_categories'] == 10, manifest
        assert manifest['affected_unique_objects'] > 1000, manifest
        assert manifest['category_objects']['VM-CDROM'] >= 300 and manifest['category_objects']['VM-SNAPSHOT'] >= 300, manifest
    if name == 'many_problems':
        assert {'P1', 'P2', 'P3'} <= set(manifest['category_levels'].values()), manifest
    (directory / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), 'utf-8')
    return report, context


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario', choices=['all', *SCENARIOS], default='all')
    parser.add_argument('--output', type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument('--write-report-json', action='store_true', help='Large data: generated outside Git only')
    args = parser.parse_args()
    names = list(SCENARIOS) if args.scenario == 'all' else [args.scenario]
    for name in names:
        report, _ = load_scenario(name, args.output)
        directory = args.output.resolve() / name / _fingerprint()[:12]
        if args.write_report_json:
            report.write_json(directory / 'inspection_result.synthetic.json')
        manifest = json.loads((directory / 'manifest.json').read_text('utf-8'))
        print(json.dumps(manifest, ensure_ascii=False))


if __name__ == '__main__':
    main()
