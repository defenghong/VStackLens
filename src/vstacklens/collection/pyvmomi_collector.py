from __future__ import annotations

import base64
import json
import ssl
import socket
import tempfile
import re
import hashlib
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable

from vstacklens.collection.collection_plan import CollectionPlan
from vstacklens.core.context import RunContext


VSAN_DATASTORE_USED_WARNING_PERCENT = 80.0
VSAN_DATASTORE_USED_ATTENTION_PERCENT = 75.0
HOST_CPU_OVERCOMMIT_RATIO_WARNING = 4.0
HOST_MEMORY_OVERCOMMIT_RATIO_WARNING = 1.5
LOCAL_DATASTORE_TYPES = {"vmfs"}
SHARED_DATASTORE_TYPES = {"nfs", "nfs41", "vsan", "vvolds"}
VSAN_HEALTH_OK_VALUES = {"", "green", "healthy", "ok", "passed", "normal", "compliant"}
VSAN_HEALTH_UNKNOWN_VALUES = {"unknown", "notavailable", "not_available", "not collected", "not_collected", "skipped"}
VSAN_HEALTH_BAD_TOKENS = {
    "red",
    "yellow",
    "warning",
    "warn",
    "error",
    "failed",
    "fail",
    "unhealthy",
    "degraded",
    "noncompliant",
    "non-compliant",
    "inaccessible",
}
VSAN_DISK_BAD_STATES = {"red", "yellow", "error", "degraded", "failed", "unhealthy", "offline", "absent", "lost", "notmounted"}
SYSTEM_VM_NAME_PATTERNS = (
    re.compile(r"^vCLS(?:-|$)", re.IGNORECASE),
    re.compile(r"^VMware\s+vCLS(?:-|$|\s)", re.IGNORECASE),
)
PORTGROUP_SECURITY_COLLECTOR_SOURCE = (
    "host.config.network.portgroup[].computedPolicy.security, "
    "host.config.network.portgroup[].spec.policy.security, "
    "host.config.network.vswitch[].spec.policy.security, "
    "vim.dvs.DistributedVirtualPortgroup.config.defaultPortConfig.securityPolicy, "
    "vim.DistributedVirtualSwitch.config.defaultPortConfig.securityPolicy"
)
LOCAL_DATASTORE_COLLECTOR_SOURCE = (
    "vm.datastore[], datastore.summary.type, datastore.host[], vm.runtime.host"
)
HARDWARE_HEALTH_COLLECTOR_SOURCE = (
    "host.runtime.healthSystemRuntime.systemHealthInfo.numericSensorInfo[]"
)
POWER_POLICY_COLLECTOR_SOURCE = "host.config.powerSystemInfo.currentPolicy"
DATASTORE_CLUSTER_COLLECTOR_SOURCE = "datastore.host[].key.parent"
HOST_RESOURCE_COLLECTOR_SOURCE = (
    "host.hardware.cpuInfo.numCpuCores, host.hardware.cpuInfo.numCpuThreads, "
    "host.hardware.memorySize, host.vm[].config.hardware.numCPU, "
    "host.vm[].config.hardware.memoryMB"
)
GUEST_OS_COLLECTOR_SOURCE = (
    "vm.guest.guestFullName, vm.config.guestFullName, vm.config.guestId, "
    "vm.guest.toolsRunningStatus"
)
VSAN_COLLECTOR_SOURCE = (
    "datastore.summary.type, datastore.info, datastore.host[].key.parent, "
    "vsanapiutils.GetVsanVcMos, "
    "vim.cluster.VsanVcClusterConfigSystem.VsanClusterGetConfig/GetConfigInfoEx, "
    "vim.cluster.VsanVcClusterHealthSystem.VsanQueryVcClusterHealthSummary/QueryClusterHealthSummary, "
    "vim.cluster.VsanVcDiskManagementSystem.QueryDiskMappings, "
    "vim.cluster.VsanObjectSystem.QuerySyncingVsanObjectsSummary"
)
_VSAN_SSL_CONTEXT_LOCK = threading.RLock()


class PyVmomiCollector:
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 443,
        ssl_verify: bool = False,
        timeout: float = 8.0,
    ) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.ssl_verify = ssl_verify
        self.timeout = timeout
        self.cancel_requested = lambda: False
        self._collection_warnings: list[dict[str, Any]] = []
        self._service_instance: Any | None = None
        self._rest_session_id: str | None = None
        self._rest_policy_cache: dict[str, dict[str, Any]] = {}
        self._rest_policy_names: dict[str, str] = {}
        self._rest_policy_status: dict[str, Any] = {
            "collection_status": "not_collected",
            "source": "vcenter_rest.GET /api/vcenter/vm/{vm}/storage/policy/compliance",
        }
        self._vsan_policy_by_object_uuid: dict[str, dict[str, Any]] = {}

    def collect_vsan_management_inventory(
        self,
        service_instance: Any,
        clusters: list[Any],
        vms: list[Any] | None = None,
    ) -> dict[str, Any]:
        """Collect the bounded, read-only vSAN management view for another pipeline.

        The Deep Inspection collector shares this implementation so its vSAN
        evidence has the same API semantics as the standard inventory path.
        """

        return self._collect_vsan_inventory(
            service_instance,
            clusters,
            vms,
            include_storage_policy=False,
            include_object_inventory=False,
        )

    def precheck(self) -> None:
        try:
            from pyVim.connect import Disconnect, SmartConnect
        except ImportError as exc:
            raise RuntimeError("pyVmomi is not installed. Install with: python -m pip install -e .") from exc

        ssl_context = None
        if not self.ssl_verify:
            ssl_context = ssl._create_unverified_context()  # noqa: SLF001 - explicit customer-configurable option
        service_instance = self._smart_connect(SmartConnect, ssl_context)
        try:
            service_instance.RetrieveContent()
        finally:
            self._rest_session_id = None
            self._rest_policy_cache = {}
            self._rest_policy_names = {}
            self._service_instance = None
            Disconnect(service_instance)

    def collect(
        self,
        context: RunContext,
        plan: CollectionPlan,
        progress: Callable[[str, int], None] | None = None,
    ) -> dict[str, Any]:
        self._collection_warnings = []
        self._rest_session_id = None
        self._rest_policy_cache = {}
        self._rest_policy_names = {}
        self._rest_policy_status = {
            "collection_status": "not_collected",
            "source": "vcenter_rest.GET /api/vcenter/vm/{vm}/storage/policy/compliance",
        }
        self._vsan_policy_by_object_uuid = {}
        try:
            from pyVim.connect import Disconnect, SmartConnect
            from pyVmomi import vim
        except ImportError as exc:
            raise RuntimeError("pyVmomi is not installed. Install with: python -m pip install -e .") from exc

        ssl_context = None
        if not self.ssl_verify:
            ssl_context = ssl._create_unverified_context()  # noqa: SLF001 - explicit customer-configurable option

        service_instance = self._smart_connect(SmartConnect, ssl_context)
        self._service_instance = service_instance
        try:
            content = service_instance.RetrieveContent()
            self._emit_progress(progress, "collecting_environment", 20)
            self._emit_progress(progress, "collecting_clusters", 25)
            clusters = self._collect_view(content, vim.ClusterComputeResource, lambda item: item)
            self._emit_progress(progress, "collecting_hosts", 30)
            hosts = self._collect_view(content, vim.HostSystem, lambda item: item)
            host_license_map = self._host_license_assignments(content, hosts)
            self._emit_progress(progress, "collecting_storage_network", 38)
            datastores = self._collect_view(content, vim.Datastore, lambda item: item)
            distributed_portgroups = self._collect_distributed_portgroups(content, vim)
            try:
                distributed_portgroup_index = self._distributed_portgroup_index(distributed_portgroups)
            except Exception as exc:  # noqa: BLE001 - optional DVS labels must not stop inventory collection
                self._record_collection_warning("distributed_portgroup_labels", exc)
                distributed_portgroup_index = {}
            self._emit_progress(progress, "collecting_vms", 45)
            vms = self._collect_view(content, vim.VirtualMachine, lambda item: item)
            self._emit_progress(progress, "collecting_alarms_permissions", 52)
            perf = _PerformanceSampler(content, plan)
            self._emit_progress(progress, "collecting_permissions", 53)
            role_inheritance_issues = self._role_permission_inheritance_issues(content)
            vsan_inventory = self._collect_vsan_inventory(service_instance, clusters, vms)
            self._vsan_policy_by_object_uuid = self._vsan_policy_index(vsan_inventory)
            vsan_host_ids = {
                str(getattr(host, "_moId", ""))
                for cluster in clusters
                if self._cluster_has_vsan_datastore(cluster)
                for host in (getattr(cluster, "host", []) or [])
            }
            try:
                distributed_portgroup_security = self._distributed_portgroup_security_by_host(distributed_portgroups)
            except Exception as exc:  # noqa: BLE001 - optional DVS enrichment must not abort the inspection
                self._record_collection_warning("distributed_portgroup_security", exc)
                distributed_portgroup_security = {}
            objects: list[dict[str, Any]] = []
            self._emit_progress(progress, "building_vcenter_summary", 54)
            objects.append(
                self._vcenter_object(
                    content,
                    [getattr(content, "rootFolder", None), *clusters, *hosts, *datastores, *vms],
                    role_inheritance_issues=role_inheritance_issues,
                )
            )
            self._emit_progress(progress, "building_cluster_objects", 55)
            for cluster in clusters:
                try:
                    objects.append(self._cluster_object(cluster, perf))
                except Exception as exc:  # noqa: BLE001 - one slow cluster must not abort the inspection.
                    self._record_collection_warning("cluster_object", exc)
                    objects.append(self._failed_inventory_object(cluster, "ClusterComputeResource"))
            self._emit_progress(progress, "building_host_objects", 56)
            for offset in range(0, len(hosts), 10):
                if self.cancel_requested():
                    return {"objects": objects, "collection_status": "cancelled", "collection_warnings": self._collection_warnings}
                for host in hosts[offset:offset + 10]:
                    if self.cancel_requested():
                        return {"objects": objects, "collection_status": "cancelled", "collection_warnings": self._collection_warnings}
                    try:
                        host_object = self._host_object(
                            host,
                            perf,
                        host_license_map.get(str(host._moId)),
                        distributed_portgroup_security,
                        distributed_portgroup_index,
                        distributed_portgroups,
                        )
                        host_object.setdefault("properties", {})["vsan_enabled"] = str(getattr(host, "_moId", "")) in vsan_host_ids
                        objects.append(host_object)
                    except Exception as exc:
                        host_name = str(getattr(host, "name", getattr(host, "_moId", "unknown")))
                        self._record_collection_warning("host:" + host_name, exc)
                        objects.append({"object_type": "HostSystem", "object_key": str(getattr(host, "_moId", host_name)),
                                        "object_name": host_name, "properties": {"collection_status": "failed"}})
            self._emit_progress(progress, "building_storage_objects", 57)
            for datastore in datastores:
                try:
                    objects.append(self._datastore_object(datastore, perf, vsan_inventory))
                except Exception as exc:  # noqa: BLE001 - preserve coverage and mark this object unknown.
                    self._record_collection_warning("datastore_object", exc)
                    objects.append(self._failed_inventory_object(datastore, "Datastore"))
            self._emit_progress(progress, "building_vm_objects", 58)
            vm_total = max(len(vms), 1)
            for index, vm in enumerate(vms, start=1):
                if index == 1 or index == vm_total or index % 50 == 0:
                    percent = 58 + min(1, int(index * 2 / vm_total))
                    self._emit_progress(progress, "building_vm_objects", percent)
                try:
                    objects.append(self._vm_object(vm, vim, perf, content))
                except Exception as exc:  # noqa: BLE001 - preserve the rest of a large VM inventory.
                    self._record_collection_warning("vm_object", exc)
                    objects.append(self._failed_inventory_object(vm, "VirtualMachine"))
            return {"objects": objects, "collection_warnings": self._collection_warnings, "collection_status": "degraded" if self._collection_warnings else "collected"}
        finally:
            self._rest_session_id = None
            self._rest_policy_cache = {}
            self._rest_policy_names = {}
            self._service_instance = None
            Disconnect(service_instance)

    def _emit_progress(self, progress: Callable[[str, int], None] | None, stage: str, percent: int) -> None:
        if progress:
            progress(stage, percent)

    def _failed_inventory_object(self, obj: Any, object_type: str) -> dict[str, Any]:
        object_key = str(self._safe_getattr(obj, "_moId", "unknown", f"{object_type}.moid") or "unknown")
        object_name = str(self._safe_getattr(obj, "name", object_key, f"{object_type}[{object_key}].name") or object_key)
        return {
            "object_type": object_type,
            "object_key": object_key,
            "object_name": object_name,
            "object_path": object_name,
            "properties": {"collection_status": "failed", "data_quality": "unavailable"},
        }

    def _safe_getattr(self, obj: Any, attr: str, default: Any = None, context: str | None = None) -> Any:
        try:
            return getattr(obj, attr, default)
        except Exception as exc:  # noqa: BLE001 - pyVmomi properties can trigger remote reads/faults.
            self._record_collection_warning(context or attr, exc)
            return default

    def _safe_call(self, fn: Callable[..., Any], *args: Any, default: Any = None, context: str | None = None, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except Exception as exc:  # noqa: BLE001 - optional SDK calls must not abort the inspection.
            self._record_collection_warning(context or getattr(fn, "__name__", "pyvmomi_call"), exc)
            return default

    def _safe_sequence(self, value: Any, context: str | None = None) -> list[Any] | None:
        if value is None:
            return None
        try:
            return list(value)
        except Exception as exc:  # noqa: BLE001 - remote arrays can fault while being expanded.
            self._record_collection_warning(context or "pyvmomi_sequence", exc)
            return None

    def _record_collection_warning(self, context: str, exc: Exception) -> None:
        warning = {
            "context": self._safe_warning_context(context),
            "status": self._exception_status(exc),
            "error_type": type(exc).__name__,
            "degraded": True,
        }
        if warning not in self._collection_warnings and len(self._collection_warnings) < 200:
            self._collection_warnings.append(warning)

    def _safe_warning_context(self, value: str) -> str:
        text = str(value or "pyvmomi").replace("\\", "/")
        text = re.sub(r"(?i)(password|passwd|pwd|token|session|cookie|secret|key)=[^,;\s]+", r"\1=***", text)
        return text[:160]

    def _smart_connect(self, smart_connect: Any, ssl_context: ssl.SSLContext | None) -> Any:
        return smart_connect(
            host=self.host, user=self.username, pwd=self.password,
            port=self.port, sslContext=ssl_context,
            httpConnectionTimeout=self.timeout,
        )

    def _collect_view(self, content: Any, vim_type: Any, mapper: Any) -> list[dict[str, Any]]:
        view = content.viewManager.CreateContainerView(content.rootFolder, [vim_type], True)
        try:
            return [mapper(obj) for obj in view.view]
        finally:
            view.Destroy()

    def _collect_distributed_portgroups(self, content: Any, vim: Any) -> list[Any]:
        dvs_namespace = getattr(vim, "dvs", None)
        portgroup_type = getattr(vim, "DistributedVirtualPortgroup", None) or getattr(
            dvs_namespace,
            "DistributedVirtualPortgroup",
            None,
        )
        if portgroup_type is None:
            return []
        try:
            return self._collect_view(content, portgroup_type, lambda item: item)
        except Exception as exc:
            self._record_collection_warning("distributed_portgroups", exc)
            return []

    def _distributed_portgroup_index(self, portgroups: list[Any]) -> dict[tuple[str, str], dict[str, str]]:
        index: dict[tuple[str, str], dict[str, str]] = {}
        for portgroup in portgroups:
            config = self._safe_getattr(portgroup, "config")
            dvs = self._safe_getattr(config, "distributedVirtualSwitch") if config else None
            switch_uuid = str(self._safe_getattr(dvs, "uuid", "") or "").strip()
            portgroup_key = str(self._safe_getattr(portgroup, "key", "") or "").strip()
            if not switch_uuid or not portgroup_key:
                continue
            index[(switch_uuid, portgroup_key)] = {
                "network_label": str(
                    self._safe_getattr(config, "name", None)
                    or self._safe_getattr(portgroup, "name", None)
                    or portgroup_key
                ).strip(),
                "switch": str(self._safe_getattr(dvs, "name", "") or "").strip(),
            }
        return index

    def _entity_name(self, entity: Any) -> str:
        value = self._safe_getattr(entity, "name") or self._safe_getattr(entity, "_moId")
        return str(value).strip() if value is not None else ""

    def _parent_names(self, entity: Any) -> list[str]:
        names: list[str] = []
        current = getattr(entity, "parent", None)
        seen: set[int] = set()
        generic_folders = {"Datacenters", "host", "vm", "datastore", "network"}
        while current is not None and id(current) not in seen and len(names) < 16:
            seen.add(id(current))
            name = self._entity_name(current)
            if name and name not in generic_folders and name != self.host:
                names.append(name)
            current = self._safe_getattr(current, "parent", context="entity.parent")
        return list(reversed(names))

    def _join_location(self, parts: list[str]) -> str:
        cleaned: list[str] = []
        for part in parts:
            text = str(part or "").strip()
            if text and (not cleaned or cleaned[-1] != text):
                cleaned.append(text)
        return " / ".join(cleaned)

    def _inventory_path(self, entity: Any) -> str:
        return self._join_location([self.host, *self._parent_names(entity), self._entity_name(entity)])

    def _asset_location(self, entity: Any, fallback: str | None = None) -> str:
        return self._join_location([self.host, *self._parent_names(entity)]) or fallback or self.host

    def _host_location(self, host: Any) -> str:
        return self._asset_location(host, self.host)

    def _vm_location(self, vm: Any) -> str:
        runtime_host = getattr(getattr(vm, "runtime", None), "host", None)
        if runtime_host is not None:
            host_name = self._entity_name(runtime_host)
            cluster = getattr(runtime_host, "parent", None)
            if cluster is not None:
                return self._join_location(
                    [
                        self.host,
                        *self._parent_names(cluster),
                        self._entity_name(cluster),
                        f"主机 {host_name}" if host_name else "",
                    ]
                )
            if host_name:
                return self._join_location([self.host, f"主机 {host_name}"])
        return self._asset_location(vm, self.host)

    def _datastore_location(self, datastore: Any) -> str:
        base = self._asset_location(datastore, self.host)
        mounts = self._safe_sequence(self._safe_getattr(datastore, "host", [], context="datastore.host"), context="datastore.host") or []
        host_names: list[str] = []
        cluster_names: list[str] = []
        for mount in mounts:
            host = self._safe_getattr(mount, "key", context="datastore.host[].key")
            host_name = self._entity_name(host)
            if host_name and host_name not in host_names:
                host_names.append(host_name)
            cluster_name = self._entity_name(self._safe_getattr(host, "parent", context="datastore.host[].key.parent"))
            if cluster_name and cluster_name not in cluster_names:
                cluster_names.append(cluster_name)
        if cluster_names:
            return self._join_location([base, f"挂载集群 {self._summarize_names(cluster_names)}"])
        if host_names:
            return self._join_location([base, f"挂载主机 {self._summarize_names(host_names)}"])
        return base

    def _summarize_names(self, names: list[str], limit: int = 5) -> str:
        shown = names[:limit]
        suffix = f" 等 {len(names)} 项" if len(names) > limit else ""
        return "、".join(shown) + suffix

    def _vcenter_object(
        self,
        content: Any,
        alarm_entities: list[Any] | None = None,
        role_inheritance_issues: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        about = content.about
        admin_principals = self._vcenter_admin_principals(content)
        task_backlog = self._task_backlog_items(content)
        entities = alarm_entities or [getattr(content, "rootFolder", None)]
        alarm_warning_start = len(self._collection_warnings)
        red_alarm_count = self._global_red_alarm_count(entities)
        active_red_alarms = self._global_red_alarm_details(entities)
        alarm_warnings = self._collection_warnings[alarm_warning_start:]
        return {
            "object_type": "vCenter",
            "object_key": getattr(about, "instanceUuid", self.host),
            "object_name": self.host,
            "object_path": self.host,
            "properties": {
                "asset_location": "vCenter 根对象",
                "connected": True,
                "version": getattr(about, "version", None),
                "build": getattr(about, "build", None),
                "build_current": None,
                "red_alarm_count": red_alarm_count,
                "active_red_alarms": active_red_alarms,
                "alarm_detail_collection_status": self._alarm_collection_status(
                    red_alarm_count,
                    active_red_alarms,
                    alarm_warnings,
                ),
                "collection_warnings": self._collection_warnings,
                "certificate_days_remaining": self._certificate_days_remaining(),
                "license_days_remaining": self._license_days_remaining(content),
                "vcenter_admin_account_count": None if admin_principals is None else len(admin_principals),
                "vcenter_admin_principals": admin_principals,
                "task_backlog_count": None if task_backlog is None else len(task_backlog),
                "task_backlog_items": task_backlog,
                "role_permission_inheritance_issue_count": None
                if role_inheritance_issues is None
                else len(role_inheritance_issues),
                "role_permission_inheritance_issues": role_inheritance_issues,
            },
        }

    def _cluster_object(self, cluster: Any, perf: "_PerformanceSampler | None" = None) -> dict[str, Any]:
        cluster_key = str(self._safe_getattr(cluster, "_moId", "unknown", "cluster.moid"))
        cluster_name = str(self._safe_getattr(cluster, "name", cluster_key, f"cluster[{cluster_key}].name"))
        config = self._safe_getattr(cluster, "configurationEx", None, f"cluster[{cluster_name}].configurationEx")
        das = getattr(config, "dasConfig", None) if config else None
        drs = getattr(config, "drsConfig", None) if config else None
        hosts = self._safe_sequence(self._safe_getattr(cluster, "host", None, f"cluster[{cluster_name}].host"), f"cluster[{cluster_name}].host") or []
        host_count = len(hosts)
        vmotion_enabled_host_count = self._cluster_vmotion_enabled_host_count(hosts)
        missing_vmotion_hosts = self._missing_vmotion_hosts(hosts)
        cluster_vmotion_missing_host_count = (
            None
            if vmotion_enabled_host_count is None or host_count == 0
            else max(0, host_count - vmotion_enabled_host_count)
        )
        evc_mode = self._cluster_evc_mode(cluster, config)
        versions: set[str] = set()
        for host in hosts:
            host_name = str(self._safe_getattr(host, "name", self._safe_getattr(host, "_moId", "unknown")))
            host_config = self._safe_getattr(host, "config", None, f"host[{host_name}].config.product")
            product = self._safe_getattr(host_config, "product", None, f"host[{host_name}].product") if host_config else None
            version = self._safe_getattr(product, "version", None, f"host[{host_name}].product.version") if product else None
            if version:
                versions.add(str(version))
        host_cpu_models = self._host_cpu_models(hosts)
        host_memory_capacity_gb_values = self._host_memory_capacity_gb_values(hosts)
        return {
            "object_type": "ClusterComputeResource",
            "object_key": cluster_key,
            "object_name": cluster_name,
            "object_path": self._inventory_path(cluster),
            "properties": {
                "asset_location": self._asset_location(cluster, self.host),
                "ha_enabled": bool(getattr(das, "enabled", False)),
                "admission_control_enabled": bool(getattr(das, "admissionControlEnabled", False)),
                "drs_enabled": bool(getattr(drs, "enabled", False)),
                "drs_behavior": str(getattr(drs, "defaultVmBehavior", "")),
                "host_version_distinct_count": len({v for v in versions if v}),
                "cluster_cpu_usage_avg": perf.metric(cluster, "cluster_cpu_usage_avg") if perf else None,
                "evc_enabled": None if config is None else bool(evc_mode),
                "evc_mode": evc_mode,
                "host_cpu_models": host_cpu_models,
                "host_cpu_model_distinct_count": None if host_cpu_models is None else len(host_cpu_models),
                "host_memory_capacity_gb_values": host_memory_capacity_gb_values,
                "host_memory_capacity_skew_ratio": self._skew_ratio(host_memory_capacity_gb_values),
                "drs_disabled_rule_count": self._drs_disabled_rule_count(config),
                "drs_disabled_rules": self._drs_disabled_rules(config),
                "ha_heartbeat_datastore_count": self._ha_heartbeat_datastore_count(das),
                "heartbeat_datastore_names": self._ha_heartbeat_datastore_names(das),
                "ha_isolation_response": self._ha_isolation_response(das),
                "maintenance_host_count": self._maintenance_host_count(hosts),
                "maintenance_hosts": self._maintenance_hosts(hosts),
                "host_count": host_count,
                "vmotion_enabled_host_count": vmotion_enabled_host_count,
                "cluster_vmotion_missing_host_count": cluster_vmotion_missing_host_count,
                "missing_vmotion_hosts": missing_vmotion_hosts,
            },
        }

    def _host_object(
        self,
        host: Any,
        perf: "_PerformanceSampler | None" = None,
        license_info: dict[str, Any] | None = None,
        distributed_portgroup_security_issues: dict[str, list[dict[str, Any]]] | None = None,
        distributed_portgroup_index: dict[tuple[str, str], dict[str, str]] | None = None,
        distributed_portgroups: list[Any] | None = None,
    ) -> dict[str, Any]:
        services = getattr(getattr(host, "config", None), "service", None)
        service_list = getattr(services, "service", []) if services else []
        ssh_running = any(getattr(service, "key", "") == "TSM-SSH" and bool(getattr(service, "running", False)) for service in service_list)
        esxi_shell_running = self._service_running(services, "TSM")
        ntp_info = getattr(getattr(host, "config", None), "dateTimeInfo", None)
        ntp_config = getattr(ntp_info, "ntpConfig", None) if ntp_info else None
        ntp_servers = getattr(ntp_config, "server", []) if ntp_config else []
        physical_nic_details = self._physical_nic_details(host, distributed_portgroups)
        pnic_down_count, pnic_degraded_count = self._physical_nic_issue_counts_from_details(physical_nic_details)
        physical_nic_link_issue_count = self._sum_optional_counts(pnic_down_count, pnic_degraded_count)
        nic_detail = self._physical_nic_issue_detail_from_details(physical_nic_details)
        storage_path_detail = self._storage_path_dead_detail(host)
        vmkernel_adapters = self._vmkernel_adapters(host, distributed_portgroup_index)
        vsan_vmk_adapters = self._vsan_vmk_adapters(host, distributed_portgroup_index)
        certificate_info = self._host_certificate_info(host)
        log_core_dump = self._host_log_core_dump_config(host)
        license_info = license_info or self._host_license_from_config(host)
        portgroup_security_issues = self._portgroup_security_issues(host, distributed_portgroup_security_issues)
        hardware_health_issues = self._host_hardware_health_issues(host)
        power_policy = self._host_power_policy(host)
        resource_allocation = self._host_resource_allocation(host)
        return {
            "object_type": "HostSystem",
            "object_key": str(host._moId),
            "object_name": host.name,
            "object_path": self._inventory_path(host),
            "properties": {
                "asset_location": self._host_location(host),
                "connection_state": str(getattr(getattr(host, "runtime", None), "connectionState", "")),
                "ssh_running": ssh_running,
                "ntp_server_count": len(ntp_servers),
                "lockdown_mode": self._normalize_lockdown_mode(getattr(getattr(host, "config", None), "lockdownMode", None)),
                "cpu_usage_avg": perf.metric(host, "cpu_usage_avg") if perf else None,
                "memory_usage_avg": perf.metric(host, "memory_usage_avg") if perf else None,
                "esxi_shell_running": esxi_shell_running,
                "syslog_configured": self._syslog_configured(host),
                "syslog_targets": self._syslog_targets(host),
                "firewall_default_incoming_blocked": self._firewall_default_incoming_blocked(host),
                "host_log_core_dump_configured": log_core_dump.get("configured"),
                "host_log_core_dump_detail": log_core_dump.get("detail"),
                "pnic_down_count": pnic_down_count,
                "pnic_degraded_count": pnic_degraded_count,
                "pnic_error_count": perf.metric(host, "pnic_error_count") if perf else None,
                "pnic_error_detail": perf.metric_detail(host, "pnic_error_count") if perf else [],
                "physical_nic_link_issue_count": physical_nic_link_issue_count,
                "storage_path_dead_count": self._storage_path_dead_count(host),
                "affected_nics": [item["device"] for item in nic_detail],
                "link_speed_detail": nic_detail,
                "physical_nic_details": physical_nic_details,
                "affected_storage_paths": storage_path_detail,
                "uplink_down_count": pnic_down_count,
                "vswitch_uplink_issue_count": physical_nic_link_issue_count,
                "affected_switches": self._affected_switches_for_uplinks(host, [item["device"] for item in nic_detail]),
                "affected_uplinks": [item["device"] for item in nic_detail],
                "vmkernel_mtu_values": self._vmkernel_mtu_values(host),
                "vmotion_vmk_count": self._vmotion_vmk_count(host),
                "vmkernel_adapters": vmkernel_adapters,
                "vsan_vmk_adapters": vsan_vmk_adapters,
                "management_uplink_count": self._management_uplink_count(host),
                "host_certificate_days_remaining": certificate_info.get("days_remaining"),
                "host_certificate_not_after": certificate_info.get("not_after"),
                "host_certificate_subject": certificate_info.get("subject"),
                "host_certificate_issuer": certificate_info.get("issuer"),
                "host_certificate_not_before": certificate_info.get("not_before"),
                "host_certificate_san": certificate_info.get("san"),
                "host_certificate_fingerprint": certificate_info.get("fingerprint"),
                "host_certificate_probe_method": certificate_info.get("probe_method"),
                "host_certificate_probe_status": certificate_info.get("probe_status"),
                "host_license_assigned": license_info.get("host_license_assigned"),
                "host_license_name": license_info.get("host_license_name"),
                "host_license_edition": license_info.get("host_license_edition"),
                "host_license_is_evaluation": license_info.get("host_license_is_evaluation"),
                "host_license_expiration_date": license_info.get("host_license_expiration_date"),
                "host_license_expiration_days": license_info.get("host_license_expiration_days"),
                "host_license_probe_status": license_info.get("host_license_probe_status"),
                "portgroup_security_issue_count": None
                if portgroup_security_issues is None
                else len(portgroup_security_issues),
                "portgroup_security_high_risk_count": None
                if portgroup_security_issues is None
                else sum(1 for item in portgroup_security_issues if item.get("risk_level") == "P2"),
                "portgroup_security_issues": portgroup_security_issues,
                "host_hardware_health_issue_count": None
                if hardware_health_issues is None
                else len(hardware_health_issues),
                "host_hardware_health_red_count": None
                if hardware_health_issues is None
                else sum(1 for item in hardware_health_issues if str(item.get("status", "")).lower() == "red"),
                "host_hardware_health_issues": hardware_health_issues,
                "host_power_policy": power_policy.get("policy"),
                "host_power_policy_high_performance": power_policy.get("high_performance"),
                "host_pcpu_count": resource_allocation.get("pcpu_count"),
                "host_memory_capacity_mb": resource_allocation.get("memory_capacity_mb"),
                "host_vcpu_allocated": resource_allocation.get("vcpu_allocated"),
                "host_memory_allocated_mb": resource_allocation.get("memory_allocated_mb"),
                "host_vcpu_to_pcpu_ratio": resource_allocation.get("vcpu_to_pcpu_ratio"),
                "host_memory_allocation_ratio": resource_allocation.get("memory_allocation_ratio"),
                "host_resource_overcommit": resource_allocation.get("resource_overcommit"),
                "portgroup_security_collector_source": PORTGROUP_SECURITY_COLLECTOR_SOURCE,
                "hardware_health_collector_source": HARDWARE_HEALTH_COLLECTOR_SOURCE,
                "power_policy_collector_source": POWER_POLICY_COLLECTOR_SOURCE,
                "host_resource_collector_source": HOST_RESOURCE_COLLECTOR_SOURCE,
            },
        }

    def _datastore_object(
        self,
        datastore: Any,
        perf: "_PerformanceSampler | None" = None,
        vsan_inventory: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        summary = datastore.summary
        capacity = getattr(summary, "capacity", 0) or 0
        free = getattr(summary, "freeSpace", 0) or 0
        uncommitted = getattr(summary, "uncommitted", None)
        used_percent = round(((capacity - free) / capacity) * 100, 2) if capacity else 0
        free_percent = round((free / capacity) * 100, 2) if capacity else 0
        path_counts = self._datastore_path_state_counts(datastore)
        filesystem_type, filesystem_version = self._datastore_filesystem(datastore)
        host_names = self._datastore_host_names(datastore)
        cluster_names = self._datastore_cluster_names(datastore)
        datastore_type = str(getattr(summary, "type", "") or filesystem_type or "")
        datastore_is_vsan = self._datastore_is_vsan(datastore, datastore_type)
        datastore_is_local = self._datastore_is_local(datastore, datastore_type)
        datastore_cross_cluster_shared = self._datastore_cross_cluster_shared(datastore, datastore_type, cluster_names)
        vsan_capacity_issue = bool(datastore_is_vsan and capacity and used_percent >= VSAN_DATASTORE_USED_WARNING_PERCENT)
        vsan_info = self._vsan_datastore_info(
            datastore_is_vsan,
            cluster_names,
            used_percent,
            self._bytes_to_gb(free),
            self._bytes_to_gb(capacity),
            vsan_capacity_issue,
            vsan_inventory,
        )
        return {
            "object_type": "Datastore",
            "object_key": str(datastore._moId),
            "object_name": summary.name,
            "object_path": self._inventory_path(datastore),
            "properties": {
                "asset_location": self._datastore_location(datastore),
                "used_percent": used_percent,
                "accessible": bool(getattr(summary, "accessible", False)),
                "free_percent": free_percent,
                "latency_avg_ms": perf.metric(datastore, "latency_avg_ms") if perf else None,
                "alarm_count": self._triggered_alarm_count(datastore),
                "attached_host_count": len(self._safe_sequence(self._safe_getattr(datastore, "host", [], context="datastore.host"), context="datastore.host") or []),
                "datastore_multipath_applicable": self._datastore_multipath_applicable(datastore, path_counts),
                "datastore_multipath_issue_count": None if path_counts is None else path_counts["issue_count"],
                "datastore_active_path_count": None if path_counts is None else path_counts["active_count"],
                "datastore_total_path_count": None if path_counts is None else path_counts["total_count"],
                "datastore_path_issue_detail": [] if path_counts is None else path_counts["issue_detail"],
                "thin_provisioning_overcommit_ratio": self._thin_overcommit_ratio(capacity, free, uncommitted),
                "datastore_filesystem_type": filesystem_type,
                "datastore_filesystem_version": filesystem_version,
                "datastore_filesystem_legacy": self._datastore_filesystem_legacy(filesystem_type, filesystem_version),
                "datastore_type": datastore_type or None,
                "datastore_capacity_gb": self._bytes_to_gb(capacity),
                "datastore_free_gb": self._bytes_to_gb(free),
                "datastore_used_gb": self._bytes_to_gb(capacity - free) if capacity else None,
                "datastore_is_vsan": datastore_is_vsan,
                "datastore_is_local": datastore_is_local,
                "datastore_host_names": host_names,
                "datastore_host_count": len(host_names),
                "datastore_cluster_names": cluster_names,
                "datastore_cluster_count": len(cluster_names),
                "datastore_cross_cluster_shared": datastore_cross_cluster_shared,
                "vsan_used_percent": vsan_info.get("vsan_used_percent"),
                "vsan_free_gb": vsan_info.get("vsan_free_gb"),
                "vsan_capacity_issue": vsan_info.get("vsan_capacity_issue"),
                "vsan_capacity_status": vsan_info.get("vsan_capacity_status"),
                "vsan_api_status": vsan_info.get("vsan_api_status"),
                "vsan_collection_error": vsan_info.get("vsan_collection_error"),
                "vsan_cluster_enabled": vsan_info.get("vsan_cluster_enabled"),
                "vsan_cluster_names": vsan_info.get("vsan_cluster_names"),
                "vsan_health_issue_count": vsan_info.get("vsan_health_issue_count"),
                "vsan_disk_health_issue_count": vsan_info.get("vsan_disk_health_issue_count"),
                "vsan_object_health_issue_count": vsan_info.get("vsan_object_health_issue_count"),
                "vsan_resync_object_count": vsan_info.get("vsan_resync_object_count"),
                "vsan_resync_bytes": vsan_info.get("vsan_resync_bytes"),
                "vsan_architecture": vsan_info.get("vsan_architecture"),
                "vsan_disk_group_count": vsan_info.get("vsan_disk_group_count"),
                "vsan_cache_disk_count": vsan_info.get("vsan_cache_disk_count"),
                "vsan_capacity_disk_count": vsan_info.get("vsan_capacity_disk_count"),
                "vsan_disk_topology": vsan_info.get("disk_topology"),
                "vsan_native_capacity": vsan_info.get("native_capacity"),
                "vsan_object_count": vsan_info.get("vsan_object_count"),
                "vsan_vmdk_count": vsan_info.get("vsan_vmdk_count"),
                "vsan_policy_noncompliant_count": vsan_info.get("vsan_policy_noncompliant_count"),
                "vsan_policy_checked_count": vsan_info.get("vsan_policy_checked_count"),
                 "vsan_policy_compliant_count": vsan_info.get("vsan_policy_compliant_count"),
                 "vsan_policy_unknown_count": vsan_info.get("vsan_policy_unknown_count"),
                 "storage_policy_summary": vsan_info.get("storage_policy_summary"),
                 "vsan_issue_count": vsan_info.get("vsan_issue_count"),
                "vsan_health_issues": vsan_info.get("vsan_health_issues"),
                "vsan_disk_health_issues": vsan_info.get("vsan_disk_health_issues"),
                "vsan_object_health_issues": vsan_info.get("vsan_object_health_issues"),
                "vsan_physical_disks": vsan_info.get("vsan_physical_disks"),
                "vsan_collector_source": VSAN_COLLECTOR_SOURCE,
                "local_datastore_collector_source": LOCAL_DATASTORE_COLLECTOR_SOURCE,
                "datastore_cluster_collector_source": DATASTORE_CLUSTER_COLLECTOR_SOURCE,
            },
        }

    def _vm_vmdk_inventory(self, vm: Any, vim: Any) -> list[dict[str, Any]] | None:
        devices = self._vm_devices(vm)
        if devices is None:
            return None
        virtual_disks = [device for device in devices if isinstance(device, vim.vm.device.VirtualDisk)]
        is_vsan_vm = any(
            str(getattr(getattr(getattr(device, "backing", None), "datastore", None), "summary", None) and getattr(getattr(getattr(device, "backing", None), "datastore", None).summary, "type", "") or "").casefold() == "vsan"
            for device in virtual_disks
        )
        compliance = self._rest_storage_policy_compliance(vm) if is_vsan_vm else {"collection_status": "not_applicable", "disks": {}}
        disks = compliance.get("disks") if isinstance(compliance, dict) else {}
        result: list[dict[str, Any]] = []
        for device in virtual_disks:
            backing = getattr(device, "backing", None)
            datastore = getattr(backing, "datastore", None) if backing else None
            capacity_kb = getattr(device, "capacityInKB", None)
            disk_key = str(getattr(device, "key", ""))
            compliance_info = disks.get(disk_key) if isinstance(disks, dict) else None
            result.append({
                "device_key": getattr(device, "key", None),
                "unit_number": getattr(device, "unitNumber", None),
                "label": getattr(getattr(device, "deviceInfo", None), "label", None),
                "capacity_bytes": int(capacity_kb) * 1024 if capacity_kb is not None else None,
                "file_name": getattr(backing, "fileName", None) if backing else None,
                "datastore": getattr(datastore, "name", getattr(datastore, "_moId", None)) if datastore else None,
                "disk_mode": getattr(backing, "diskMode", None) if backing else None,
                "thin_provisioned": getattr(backing, "thinProvisioned", None) if backing else None,
                "eagerly_scrub": getattr(backing, "eagerlyScrub", None) if backing else None,
                "uuid": getattr(backing, "uuid", None) if backing else None,
                "backing_object_id": getattr(backing, "backingObjectId", None) if backing else None,
                 "compatibility_mode": getattr(backing, "compatibilityMode", None) if backing else None,
                 "storage_policy": self._rest_policy_item(compliance_info)
                 or getattr(self, "_vsan_policy_by_object_uuid", {}).get(str(getattr(backing, "backingObjectId", "") or "")),
             })
        return result

    def _rest_policy_item(self, value: Any) -> dict[str, Any] | None:
        if not isinstance(value, dict):
            return None
        policy_id = value.get("policy")
        return {"status": value.get("status"), "policy": policy_id, "policy_name": self._rest_policy_name(policy_id), "check_time": value.get("check_time"), "failure_cause": value.get("failure_cause") or [], "native": dict(value)}

    def _rest_policy_name(self, policy_id: Any) -> str | None:
        if not policy_id:
            return None
        key = str(policy_id)
        if key in self._rest_policy_names:
            return self._rest_policy_names[key]
        try:
            payload = self._rest_get_json("/api/vcenter/storage/policies")
            for item in payload if isinstance(payload, list) else []:
                if str(item.get("policy")) == key:
                    name = str(item.get("name") or "") or key
                    self._rest_policy_names[key] = name
                    return name
        except Exception as exc:  # noqa: BLE001 - ID remains useful if optional lookup is unavailable
            self._record_collection_warning("storage_policy_names", exc)
        self._rest_policy_names[key] = key
        return key

    def _rest_storage_policy_compliance(self, vm: Any) -> dict[str, Any]:
        if self._service_instance is None:
            return {"collection_status": "not_collected", "disks": {}, "source": "vcenter_rest.GET /api/vcenter/vm/{vm}/storage/policy/compliance"}
        vm_id = str(getattr(vm, "_moId", "") or "")
        if not vm_id:
            return {"collection_status": "not_collected", "disks": {}}
        if vm_id in self._rest_policy_cache:
            return self._rest_policy_cache[vm_id]
        try:
            payload = self._rest_get_json(f"/api/vcenter/vm/{urllib.parse.quote(vm_id, safe='')}/storage/policy/compliance")
            normalized = {"collection_status": "collected", "overall_compliance": payload.get("overall_compliance"), "vm_home": self._rest_policy_item(payload.get("vm_home")), "disks": payload.get("disks") if isinstance(payload.get("disks"), dict) else {}, "source": "vcenter_rest.GET /api/vcenter/vm/{vm}/storage/policy/compliance"}
            self._rest_policy_cache[vm_id] = normalized
            self._rest_policy_status = {"collection_status": "collected", "source": normalized["source"]}
            return normalized
        except Exception as exc:  # noqa: BLE001 - policy is an independent module
            status = self._exception_status(exc)
            self._record_collection_warning("storage_policy:" + vm_id, exc)
            normalized = {"collection_status": status, "overall_compliance": None, "vm_home": None, "disks": {}, "source": "vcenter_rest.GET /api/vcenter/vm/{vm}/storage/policy/compliance"}
            self._rest_policy_cache[vm_id] = normalized
            self._rest_policy_status = {"collection_status": status, "source": normalized["source"]}
            return normalized

    def _rest_get_json(self, path: str) -> dict[str, Any]:
        if self._rest_session_id is None:
            token = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            login_request = urllib.request.Request(f"https://{self.host}:{self.port}/api/session", method="POST", headers={"Authorization": f"Basic {token}", "Accept": "application/json"})
            with urllib.request.urlopen(login_request, context=ssl._create_unverified_context() if not self.ssl_verify else None, timeout=self.timeout) as response:
                self._rest_session_id = str(json.loads(response.read().decode("utf-8")))
        request = urllib.request.Request(f"https://{self.host}:{self.port}{path}", headers={"Accept": "application/json", "vmware-api-session-id": self._rest_session_id or ""})
        try:
            with urllib.request.urlopen(request, context=ssl._create_unverified_context() if not self.ssl_verify else None, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                self._rest_session_id = None
            raise

    def _vm_object(self, vm: Any, vim: Any, perf: "_PerformanceSampler | None" = None, content: Any | None = None) -> dict[str, Any]:
        snapshot_age_days_max = self._snapshot_age_days_max(vm)
        snapshot_details = self._snapshot_details(vm)
        guest = getattr(vm, "guest", None)
        runtime = getattr(vm, "runtime", None)
        config = getattr(vm, "config", None)
        devices = getattr(getattr(config, "hardware", None), "device", []) if config else []
        cpu_reservation_mhz = self._resource_reservation(getattr(config, "cpuAllocation", None))
        memory_reservation_mb = self._resource_reservation(getattr(config, "memoryAllocation", None))
        cpu_limit_mhz = self._resource_limit(getattr(config, "cpuAllocation", None))
        memory_limit_mb = self._resource_limit(getattr(config, "memoryAllocation", None))
        hardware = getattr(config, "hardware", None) if config else None
        vcpu_count = getattr(hardware, "numCPU", None) if hardware else None
        memory_configured_mb = getattr(hardware, "memoryMB", None) if hardware else None
        hardware_version = getattr(config, "version", None) if config else None
        snapshot_chain_depth = self._snapshot_chain_depth(vm)
        disk_profile = self._vm_disk_profile(vm, vim)
        vmdk_inventory = self._vm_vmdk_inventory(vm, vim)
        policy_compliance = self._rest_storage_policy_compliance(vm)
        tools_installed, tools_install_status = self._vmware_tools_install_state(guest)
        numa_affinity = self._numa_affinity(vm)
        datastore_profile = self._vm_datastore_profile(vm)
        guest_os_actual = self._vm_guest_os_actual(guest)
        guest_os_configured = self._vm_guest_os_configured(config)
        guest_os_tools_running = str(getattr(guest, "toolsRunningStatus", "")) == "guestToolsRunning"
        quick_stats = getattr(getattr(vm, "summary", None), "quickStats", None)
        cpu_usage_mhz = getattr(quick_stats, "overallCpuUsage", None) if quick_stats else None
        memory_usage_mb = getattr(quick_stats, "hostMemoryUsage", None) if quick_stats else None
        storage_summary = getattr(getattr(vm, "summary", None), "storage", None)
        storage_committed_bytes = getattr(storage_summary, "committed", None) if storage_summary else None
        iso_paths = sorted({
            str(file_name).strip()
            for device in devices
            if isinstance(device, vim.vm.device.VirtualCdrom)
            and getattr(getattr(device, "connectable", None), "connected", False)
            and (file_name := getattr(getattr(device, "backing", None), "fileName", None))
        })
        iso_mounted = bool(iso_paths)
        return {
            "object_type": "VirtualMachine",
            "object_key": str(vm._moId),
            "object_name": vm.name,
            "object_path": self._inventory_path(vm),
            "properties": {
                "asset_location": self._vm_location(vm),
                "snapshot_age_days_max": snapshot_age_days_max,
                "snapshots": snapshot_details,
                "snapshot_chain_depth": snapshot_chain_depth,
                "power_state": str(getattr(runtime, "powerState", "")),
                "tools_running": guest_os_tools_running,
                "tools_outdated": str(getattr(guest, "toolsVersionStatus2", "")) in {"guestToolsNeedUpgrade", "guestToolsSupportedOld"},
                "vmware_tools_installed": tools_installed,
                "tools_install_status": tools_install_status,
                "cpu_ready_percent": perf.metric(vm, "cpu_ready_percent") if perf else None,
                "swap_or_balloon_mb": perf.metric(vm, "swap_or_balloon_mb") if perf else None,
                "cpu_usage_mhz": int(cpu_usage_mhz) if isinstance(cpu_usage_mhz, (int, float)) else None,
                "memory_usage_mb": int(memory_usage_mb) if isinstance(memory_usage_mb, (int, float)) else None,
                "storage_committed_bytes": int(storage_committed_bytes) if isinstance(storage_committed_bytes, (int, float)) else None,
                "iso_mounted": iso_mounted,
                "iso_paths": iso_paths,
                "is_template": bool(config.template) if config is not None and getattr(config, "template", None) is not None else None,
                "cpu_reservation_mhz": cpu_reservation_mhz,
                "memory_reservation_mb": memory_reservation_mb,
                "vm_reservation_too_high": self._vm_reservation_too_high(
                    cpu_reservation_mhz,
                    memory_reservation_mb,
                    vcpu_count,
                    memory_configured_mb,
                ),
                "cpu_limit_mhz": cpu_limit_mhz,
                "memory_limit_mb": memory_limit_mb,
                "vm_resource_limit_present": self._vm_resource_limit_present(cpu_limit_mhz, memory_limit_mb),
                "vcpu_count": vcpu_count,
                "thin_disk_count": None if disk_profile is None else disk_profile["thin_disk_count"],
                "nonpersistent_disk_count": None if disk_profile is None else disk_profile["nonpersistent_disk_count"],
                "disk_provisioning_modes": None if disk_profile is None else disk_profile["disk_provisioning_modes"],
                "vmdk_inventory": vmdk_inventory,
                "vmdk_count": None if vmdk_inventory is None else len(vmdk_inventory),
                "storage_policy_compliance": policy_compliance,
                "storage_policy_collection_status": policy_compliance.get("collection_status"),
                "storage_policy_source": policy_compliance.get("source"),
                "numa_affinity_configured": numa_affinity["configured"],
                "numa_affinity_nodes": numa_affinity["nodes"],
                "hardware_version": hardware_version,
                "hardware_version_number": self._hardware_version_number(hardware_version),
                "needs_consolidation": self._needs_consolidation(runtime),
                "invalid_network_count": self._invalid_network_count(vm, vim),
                "orphaned_or_inaccessible": self._orphaned_or_inaccessible(vm),
                "passthrough_device_count": self._passthrough_device_count(vm, vim),
                "powered_off_days": self._powered_off_days(vm, content),
                "is_system_vm": self._is_system_vm_name(vm.name),
                "datastore_names": datastore_profile.get("datastore_names"),
                "local_datastore_names": datastore_profile.get("local_datastore_names"),
                "vm_on_local_datastore": datastore_profile.get("vm_on_local_datastore"),
                "guest_os_actual": guest_os_actual,
                "guest_os_configured": guest_os_configured,
                "guest_os_tools_running": guest_os_tools_running,
                "guest_os_mismatch": self._guest_os_mismatch(guest_os_actual, guest_os_configured, guest_os_tools_running),
                "guest_os_collector_source": GUEST_OS_COLLECTOR_SOURCE,
                "local_datastore_collector_source": LOCAL_DATASTORE_COLLECTOR_SOURCE,
            },
        }

    def _cluster_evc_mode(self, cluster: Any, config: Any) -> str | None:
        for source in (config, getattr(cluster, "summary", None)):
            value = getattr(source, "evcModeKey", None) or getattr(source, "currentEVCModeKey", None)
            if value:
                return str(value)
        return None

    def _ha_heartbeat_datastore_count(self, das: Any) -> int | None:
        if das is None:
            return None
        datastores = getattr(das, "heartbeatDatastore", None)
        if datastores is None:
            return None
        return len(datastores or [])

    def _ha_heartbeat_datastore_names(self, das: Any) -> list[str] | None:
        if das is None:
            return None
        datastores = getattr(das, "heartbeatDatastore", None)
        if datastores is None:
            return None
        return [str(getattr(datastore, "name", getattr(datastore, "_moId", ""))) for datastore in datastores or []]

    def _ha_isolation_response(self, das: Any) -> str | None:
        if das is None:
            return None
        default_settings = getattr(das, "defaultVmSettings", None)
        response = getattr(default_settings, "isolationResponse", None) if default_settings else None
        return str(response) if response is not None else None

    def _maintenance_host_count(self, hosts: list[Any]) -> int | None:
        if hosts is None:
            return None
        return sum(1 for host in hosts if bool(getattr(getattr(host, "runtime", None), "inMaintenanceMode", False)))

    def _maintenance_hosts(self, hosts: list[Any]) -> list[str] | None:
        if hosts is None:
            return None
        return [
            str(getattr(host, "name", getattr(host, "_moId", "unknown")))
            for host in hosts
            if bool(getattr(getattr(host, "runtime", None), "inMaintenanceMode", False))
        ]

    def _host_cpu_models(self, hosts: list[Any]) -> list[str] | None:
        if hosts is None:
            return None
        models: set[str] = set()
        for host in hosts:
            hardware = getattr(getattr(host, "summary", None), "hardware", None)
            model = getattr(hardware, "cpuModel", None) if hardware else None
            if model:
                models.add(str(model))
        return sorted(models)

    def _host_memory_capacity_gb_values(self, hosts: list[Any]) -> list[int] | None:
        if hosts is None:
            return None
        values: list[int] = []
        for host in hosts:
            hardware = getattr(getattr(host, "summary", None), "hardware", None)
            memory_size = getattr(hardware, "memorySize", None) if hardware else None
            if memory_size is not None:
                values.append(round(int(memory_size) / (1024**3)))
        return values or None

    def _skew_ratio(self, values: list[int] | None) -> float | None:
        if not values:
            return None
        minimum = min(values)
        maximum = max(values)
        if minimum <= 0:
            return None
        return round(((maximum - minimum) / minimum) * 100, 2)

    def _drs_disabled_rule_count(self, config: Any) -> int | None:
        if config is None:
            return None
        rules = getattr(config, "rule", None)
        if rules is None:
            return None
        return sum(1 for rule in rules or [] if getattr(rule, "enabled", None) is False)

    def _drs_disabled_rules(self, config: Any) -> list[str] | None:
        if config is None:
            return None
        rules = getattr(config, "rule", None)
        if rules is None:
            return None
        return [
            str(getattr(rule, "name", getattr(rule, "key", "unnamed")))
            for rule in rules or []
            if getattr(rule, "enabled", None) is False
        ]

    def _cluster_vmotion_enabled_host_count(self, hosts: list[Any]) -> int | None:
        if not hosts:
            return None
        enabled = 0
        for host in hosts:
            vmotion_vmk_count = self._vmotion_vmk_count(host)
            if vmotion_vmk_count is None:
                return None
            if vmotion_vmk_count > 0:
                enabled += 1
        return enabled

    def _missing_vmotion_hosts(self, hosts: list[Any]) -> list[str] | None:
        if not hosts:
            return None
        missing: list[str] = []
        for host in hosts:
            vmotion_vmk_count = self._vmotion_vmk_count(host)
            if vmotion_vmk_count is None:
                return None
            if vmotion_vmk_count < 1:
                missing.append(str(getattr(host, "name", getattr(host, "_moId", "unknown"))))
        return missing

    def _service_running(self, services: Any, key: str) -> bool | None:
        if services is None:
            return None
        service_list = getattr(services, "service", None)
        if service_list is None:
            return None
        return any(getattr(service, "key", "") == key and bool(getattr(service, "running", False)) for service in service_list)

    def _host_advanced_options(self, host: Any) -> dict[str, Any] | None:
        option_values = getattr(getattr(host, "config", None), "option", None)
        if option_values is None:
            option_manager = getattr(getattr(host, "configManager", None), "advancedOption", None)
            if option_manager is None:
                return None
            try:
                option_values = option_manager.QueryOptions()
            except Exception:  # noqa: BLE001 - unavailable option manager should become missing data
                return None
        return {str(getattr(option, "key", "")): getattr(option, "value", None) for option in option_values or []}

    def _syslog_targets(self, host: Any) -> list[str] | None:
        options = self._host_advanced_options(host)
        if options is None:
            return None
        value = options.get("Syslog.global.logHost")
        if value is None:
            return []
        return [item.strip() for item in str(value).replace(";", ",").split(",") if item.strip()]

    def _syslog_configured(self, host: Any) -> bool | None:
        targets = self._syslog_targets(host)
        if targets is None:
            return None
        return bool(targets)

    def _firewall_default_incoming_blocked(self, host: Any) -> bool | None:
        firewall = getattr(getattr(host, "config", None), "firewall", None)
        default_policy = getattr(firewall, "defaultPolicy", None) if firewall else None
        if default_policy is None:
            return None
        value = getattr(default_policy, "incomingBlocked", None)
        return bool(value) if value is not None else None

    def _host_log_core_dump_config(self, host: Any) -> dict[str, Any]:
        syslog_targets = self._syslog_targets(host)
        options = self._host_advanced_options(host)
        if syslog_targets is None or options is None:
            return {"configured": None, "detail": "当前 vCenter 未返回 Syslog 或高级选项字段"}
        log_dir = str(options.get("Syslog.global.logDir") or "").strip()
        persistent_log = bool(syslog_targets) or bool(log_dir and "scratch" not in log_dir.lower())
        core_dump = self._host_core_dump_configured(host)
        if core_dump is None:
            return {
                "configured": None,
                "detail": f"日志目标：{', '.join(syslog_targets) if syslog_targets else log_dir or '未配置'}；当前 vCenter 未返回核心转储配置字段",
            }
        return {
            "configured": bool(persistent_log and core_dump),
            "detail": (
                f"日志目标：{', '.join(syslog_targets) if syslog_targets else log_dir or '未配置'}；"
                f"核心转储：{'已配置' if core_dump else '未配置'}"
            ),
        }

    def _host_core_dump_configured(self, host: Any) -> bool | None:
        diagnostic = getattr(getattr(host, "configManager", None), "diagnosticSystem", None)
        if diagnostic is not None:
            try:
                config = diagnostic.QueryConfig()
            except Exception:  # noqa: BLE001 - diagnostic manager may be unavailable
                config = None
            if config is not None:
                for attr in ("activePartition", "configuredDumpPartition"):
                    value = getattr(config, attr, None)
                    if value:
                        return True
                network = getattr(config, "networkDumpConfig", None)
                if network is not None:
                    enabled = getattr(network, "enabled", None)
                    if enabled is not None:
                        return bool(enabled)
        options = self._host_advanced_options(host)
        if options is None:
            return None
        coredump_keys = [
            "UserVars.CoredumpEnabled",
            "VMkernel.Boot.autoCreateDumpFile",
            "VMkernel.Boot.createDumpFile",
        ]
        values = [options.get(key) for key in coredump_keys if key in options]
        if not values:
            return None
        return any(str(value).strip().lower() in {"1", "true", "yes"} for value in values)

    def _physical_nic_details(
        self,
        host: Any,
        distributed_portgroups: list[Any] | None = None,
    ) -> list[dict[str, Any]] | None:
        network = getattr(getattr(host, "config", None), "network", None)
        if network is None:
            return None
        pnics = getattr(network, "pnic", None)
        if pnics is None:
            return None
        switch_bindings = self._physical_nic_switch_bindings(network)
        usage = self._host_portgroup_usage_context(host, network, distributed_portgroups)
        host_name = str(self._safe_getattr(host, "name", self._safe_getattr(host, "_moId", "host")) or "host")
        details: list[dict[str, Any]] = []
        for pnic in pnics:
            device = str(getattr(pnic, "device", "") or "").strip()
            if not device:
                continue
            link_speed = getattr(pnic, "linkSpeed", None)
            actual_speed_mb = self._pnic_speed_mb(getattr(link_speed, "speedMb", None)) if link_speed else None
            spec = getattr(pnic, "spec", None)
            configured_link_speed = getattr(spec, "linkSpeed", None) if spec else None
            configured_speed_mb = self._pnic_speed_mb(getattr(configured_link_speed, "speedMb", None)) if configured_link_speed else None
            assignments = switch_bindings.get(device, [])
            is_uplink = bool(assignments)
            portgroup_usage: list[dict[str, str]] = []
            unknown_reasons: list[str] = []
            for binding in assignments:
                switch_type = binding.get("type")
                switch_name = binding.get("name", "")
                if switch_type == "standard":
                    if switch_name in usage["unknown_standard_switches"] or "*" in usage["unknown_standard_switches"]:
                        unknown_reasons.append(f"标准交换机 {switch_name} 的端口组使用信息不完整")
                    for key in sorted(usage["used_standard_portgroups"]):
                        if key[0] != switch_name:
                            continue
                        group = usage["standard_portgroups"].get(key)
                        if group is None:
                            unknown_reasons.append(f"标准交换机 {switch_name} 的端口组 {key[1]} 未能解析")
                            continue
                        nic_order = self._effective_standard_nic_order(group, network)
                        role = self._standard_nic_role(device, nic_order)
                        if role in {"active", "standby"}:
                            portgroup_usage.append({"switch": switch_name, "portgroup": key[1], "role": role})
                        elif role is None:
                            unknown_reasons.append(f"标准交换机 {switch_name} 的端口组 {key[1]} teaming 信息不可用")
                elif switch_type == "distributed":
                    switch_uuid = str(binding.get("uuid", "") or "")
                    if switch_uuid in usage["unknown_distributed_switches"] or "*" in usage["unknown_distributed_switches"]:
                        unknown_reasons.append(f"分布式交换机 {switch_name} 的端口组使用信息不完整")
                    for key in sorted(usage["used_distributed_portgroups"]):
                        if key[0] != switch_uuid:
                            continue
                        group = usage["distributed_portgroups"].get(key)
                        if group is None:
                            unknown_reasons.append(f"分布式交换机 {switch_name} 的端口组 {key[1]} 未能解析")
                            continue
                        group_config = self._safe_getattr(group, "config", None)
                        group_name = str(
                            self._safe_getattr(group_config, "name", None)
                            or self._safe_getattr(group, "name", None)
                            or key[1]
                        )
                        uplink_name = binding.get("uplink_name")
                        if not uplink_name:
                            unknown_reasons.append(f"网卡 {device} 无法映射到分布式交换机上行链路名")
                            continue
                        uplink_order = self._effective_distributed_uplink_order(group)
                        role = self._distributed_uplink_role(uplink_name, uplink_order)
                        if role in {"active", "standby"}:
                            portgroup_usage.append({"switch": switch_name, "portgroup": group_name, "role": role})
                        elif role is None:
                            unknown_reasons.append(f"分布式交换机 {switch_name} 的端口组 {key[1]} teaming 信息不可用")
                else:
                    unknown_reasons.append(f"交换机 {switch_name} 的上行链路角色无法核实")

            portgroup_usage = self._dedupe_portgroup_usage(portgroup_usage)
            is_in_use = bool(portgroup_usage)
            usage_status = "in_use" if is_in_use else "unknown" if unknown_reasons else "unused"
            if usage_status == "unknown":
                reason = "; ".join(dict.fromkeys(unknown_reasons))
                self._record_collection_warning(
                    f"physical_nic_usage:{host_name}:{device}:{reason}",
                    RuntimeError("无法确认物理网卡是否被端口组使用"),
                )
            issue_codes: list[str] = []
            if is_in_use and link_speed is None:
                link_state = "down"
                assessment = "down"
                issue_codes.append("link_down")
            elif link_speed is None:
                link_state = "down"
                assessment = "unused" if usage_status == "unused" else "usage_unknown"
            elif not is_in_use:
                link_state = "up"
                assessment = "unused" if usage_status == "unused" else "usage_unknown"
            elif actual_speed_mb is None:
                link_state = "up"
                assessment = "speed_unknown"
            else:
                link_state = "up"
                if actual_speed_mb == 0:
                    issue_codes.append("speed_zero")
                if actual_speed_mb < 1000:
                    issue_codes.append("speed_below_1gbps")
                if configured_speed_mb is not None and actual_speed_mb != configured_speed_mb:
                    issue_codes.append("speed_mismatch")
                assessment = (
                    "speed_mismatch" if "speed_mismatch" in issue_codes
                    else "degraded" if issue_codes
                    else "up"
                )
            details.append(
                {
                    "device": device,
                    "is_uplink": is_uplink,
                    "is_in_use": is_in_use,
                    "usage_status": usage_status,
                    "switch_bindings": assignments,
                    "assigned_switches": [item["name"] for item in assignments],
                    "portgroup_usage": portgroup_usage,
                    "link_state": link_state,
                    "actual_speed_mb": actual_speed_mb,
                    "actual_duplex": getattr(link_speed, "duplex", None) if link_speed else None,
                    "configured_speed_mb": configured_speed_mb,
                    "configured_duplex": getattr(configured_link_speed, "duplex", None) if configured_link_speed else None,
                    "autonegotiation": None if spec is None else configured_link_speed is None,
                    "assessment": assessment,
                    "issue_codes": issue_codes,
                }
            )
        return details

    def _host_portgroup_usage_context(
        self,
        host: Any,
        network: Any,
        distributed_portgroups: list[Any] | None,
    ) -> dict[str, Any]:
        standard_portgroups: dict[tuple[str, str], Any] = {}
        used_standard_portgroups: set[tuple[str, str]] = set()
        unknown_standard_switches: set[str] = set()
        dvs_portgroups: dict[tuple[str, str], Any] = {}
        used_dvs_portgroups: set[tuple[str, str]] = set()
        unknown_dvs_switches: set[str] = set()

        host_vswitches = self._safe_sequence(
            self._safe_getattr(network, "vswitch", None),
            "physical_nic_usage.vswitches",
        )
        standard_switch_names = {
            str(self._safe_getattr(item, "name", "") or "").strip()
            for item in host_vswitches or []
        }
        standard_switch_names.discard("")

        host_proxy_switches = self._safe_sequence(
            self._safe_getattr(network, "proxySwitch", None),
            "physical_nic_usage.proxy_switches",
        )
        dvs_switch_uuids = {
            str(self._safe_getattr(item, "dvsUuid", "") or "").strip()
            for item in host_proxy_switches or []
        }
        dvs_switch_uuids.discard("")

        host_portgroups = self._safe_sequence(
            self._safe_getattr(network, "portgroup", None),
            "physical_nic_usage.standard_portgroups",
        )
        if host_portgroups is None:
            unknown_standard_switches.update(standard_switch_names or {"*"})
            host_portgroups = []
        standard_names: dict[str, list[tuple[str, str]]] = {}
        for portgroup in host_portgroups:
            spec = self._safe_getattr(portgroup, "spec", None)
            name = str(
                self._safe_getattr(spec, "name", None)
                or self._safe_getattr(portgroup, "name", None)
                or ""
            ).strip()
            switch_name = str(
                self._safe_getattr(spec, "vswitchName", None)
                or self._safe_getattr(portgroup, "vswitch", None)
                or ""
            ).strip()
            if not name or not switch_name:
                unknown_standard_switches.add(switch_name or "*")
                continue
            key = (switch_name, name)
            standard_portgroups[key] = portgroup
            standard_names.setdefault(name, []).append(key)
            ports = self._safe_sequence(
                self._safe_getattr(portgroup, "port", None),
                f"physical_nic_usage.standard_portgroup_ports:{switch_name}:{name}",
            )
            for port in ports or []:
                port_type = str(self._safe_getattr(port, "type", "") or "").casefold()
                if port_type in {"host", "virtualmachine"}:
                    used_standard_portgroups.add(key)
                elif port_type == "unknown":
                    unknown_standard_switches.add(switch_name)

        def use_standard_portgroup(name: str | None) -> None:
            portgroup_name = str(name or "").strip()
            if not portgroup_name:
                return
            candidates = standard_names.get(portgroup_name, [])
            if len(candidates) == 1:
                used_standard_portgroups.add(candidates[0])
            elif len(candidates) > 1:
                unknown_standard_switches.update(key[0] for key in candidates)
            else:
                unknown_standard_switches.add("*")

        def use_distributed_portgroup(switch_uuid: Any, portgroup_key: Any) -> None:
            uuid = str(switch_uuid or "").strip()
            key = str(portgroup_key or "").strip()
            if uuid and key:
                used_dvs_portgroups.add((uuid, key))
            else:
                unknown_dvs_switches.add(uuid or "*")

        vnics = self._safe_sequence(
            self._safe_getattr(network, "vnic", None),
            "physical_nic_usage.vmkernel_adapters",
        )
        if vnics is None:
            unknown_standard_switches.update(standard_switch_names or {"*"})
            unknown_dvs_switches.update(dvs_switch_uuids or {"*"})
        else:
            for vnic in vnics:
                spec = self._safe_getattr(vnic, "spec", None)
                distributed_port = self._safe_getattr(spec, "distributedVirtualPort", None) if spec else None
                if distributed_port is not None:
                    use_distributed_portgroup(
                        self._safe_getattr(distributed_port, "switchUuid", None),
                        self._safe_getattr(distributed_port, "portgroupKey", None),
                    )
                else:
                    use_standard_portgroup(
                        self._safe_getattr(spec, "portgroup", None)
                        or self._safe_getattr(vnic, "portgroup", None)
                    )

        host_vms = self._safe_sequence(
            self._safe_getattr(host, "vm", None),
            "physical_nic_usage.host_vms",
        )
        if host_vms is None:
            unknown_standard_switches.update(standard_switch_names or {"*"})
            unknown_dvs_switches.update(dvs_switch_uuids or {"*"})
        else:
            for vm in host_vms:
                config = self._safe_getattr(vm, "config", None)
                hardware = self._safe_getattr(config, "hardware", None) if config else None
                devices = self._safe_sequence(
                    self._safe_getattr(hardware, "device", None) if hardware else None,
                    "physical_nic_usage.vm_network_devices",
                )
                if devices is None:
                    unknown_standard_switches.update(standard_switch_names or {"*"})
                    unknown_dvs_switches.update(dvs_switch_uuids or {"*"})
                    continue
                for device in devices:
                    backing = self._safe_getattr(device, "backing", None)
                    if backing is None:
                        continue
                    distributed_port = self._safe_getattr(backing, "port", None)
                    if distributed_port is not None:
                        use_distributed_portgroup(
                            self._safe_getattr(distributed_port, "switchUuid", None),
                            self._safe_getattr(distributed_port, "portgroupKey", None),
                        )
                        continue
                    network_ref = self._safe_getattr(backing, "network", None)
                    network_name = self._safe_getattr(network_ref, "name", None) if network_ref else None
                    network_name = network_name or self._safe_getattr(backing, "deviceName", None)
                    if network_name:
                        use_standard_portgroup(str(network_name))

        if distributed_portgroups is None:
            unknown_dvs_switches.update(dvs_switch_uuids or {"*"})
            distributed_portgroups = []
        for portgroup in distributed_portgroups:
            config = self._safe_getattr(portgroup, "config", None)
            dvs = self._safe_getattr(config, "distributedVirtualSwitch", None) if config else None
            switch_uuid = str(self._safe_getattr(dvs, "uuid", "") or "").strip()
            portgroup_key = str(self._safe_getattr(portgroup, "key", "") or "").strip()
            if not switch_uuid or not portgroup_key:
                unknown_dvs_switches.add(switch_uuid or "*")
                continue
            key = (switch_uuid, portgroup_key)
            dvs_portgroups[key] = portgroup
            vms = self._safe_sequence(
                self._safe_getattr(portgroup, "vm", None),
                f"physical_nic_usage.distributed_portgroup_vms:{switch_uuid}:{portgroup_key}",
            )
            if vms is None:
                unknown_dvs_switches.add(switch_uuid)
                continue
            for vm in vms:
                runtime = self._safe_getattr(vm, "runtime", None)
                vm_host = self._safe_getattr(runtime, "host", None) if runtime else None
                if self._same_managed_object(vm_host, host):
                    used_dvs_portgroups.add(key)

        known_dvs_keys = set(dvs_portgroups)
        for switch_uuid, portgroup_key in used_dvs_portgroups:
            if (switch_uuid, portgroup_key) not in known_dvs_keys:
                unknown_dvs_switches.add(switch_uuid)

        for switch_uuid in dvs_switch_uuids:
            if not any(key[0] == switch_uuid for key in dvs_portgroups):
                unknown_dvs_switches.add(switch_uuid)

        return {
            "standard_portgroups": standard_portgroups,
            "used_standard_portgroups": used_standard_portgroups,
            "unknown_standard_switches": unknown_standard_switches,
            "distributed_portgroups": dvs_portgroups,
            "used_distributed_portgroups": used_dvs_portgroups,
            "unknown_distributed_switches": unknown_dvs_switches,
        }

    @staticmethod
    def _same_managed_object(left: Any, right: Any) -> bool:
        if left is None or right is None:
            return False
        left_id = getattr(left, "_moId", None)
        right_id = getattr(right, "_moId", None)
        if left_id and right_id:
            return str(left_id) == str(right_id)
        return left is right

    def _effective_standard_nic_order(self, portgroup: Any, network: Any) -> Any | None:
        computed = self._safe_getattr(portgroup, "computedPolicy", None)
        computed_teaming = self._safe_getattr(computed, "nicTeaming", None) if computed else None
        computed_order = self._safe_getattr(computed_teaming, "nicOrder", None) if computed_teaming else None
        if computed_order is not None:
            return computed_order

        spec = self._safe_getattr(portgroup, "spec", None)
        policy = self._safe_getattr(spec, "policy", None) if spec else None
        teaming = self._safe_getattr(policy, "nicTeaming", None) if policy else None
        order = self._safe_getattr(teaming, "nicOrder", None) if teaming else None
        if order is not None:
            return order

        switch_name = str(
            self._safe_getattr(spec, "vswitchName", None)
            or self._safe_getattr(portgroup, "vswitch", None)
            or ""
        ).strip()
        for switch in self._safe_getattr(network, "vswitch", []) or []:
            if str(self._safe_getattr(switch, "name", "") or "").strip() != switch_name:
                continue
            switch_spec = self._safe_getattr(switch, "spec", None)
            switch_policy = self._safe_getattr(switch_spec, "policy", None) if switch_spec else None
            switch_teaming = self._safe_getattr(switch_policy, "nicTeaming", None) if switch_policy else None
            return self._safe_getattr(switch_teaming, "nicOrder", None) if switch_teaming else None
        return None

    def _effective_distributed_uplink_order(self, portgroup: Any) -> Any | None:
        config = self._safe_getattr(portgroup, "config", None)
        port_config = self._safe_getattr(config, "defaultPortConfig", None) if config else None
        policy = self._safe_getattr(port_config, "uplinkTeamingPolicy", None) if port_config else None
        inherited = self._safe_getattr(policy, "inherited", None) if policy else None
        if policy is not None and inherited is False:
            return self._safe_getattr(policy, "uplinkPortOrder", None)
        if policy is not None and inherited is None:
            return None

        dvs = self._safe_getattr(config, "distributedVirtualSwitch", None) if config else None
        dvs_config = self._safe_getattr(dvs, "config", None) if dvs else None
        dvs_port_config = self._safe_getattr(dvs_config, "defaultPortConfig", None) if dvs_config else None
        dvs_policy = self._safe_getattr(dvs_port_config, "uplinkTeamingPolicy", None) if dvs_port_config else None
        return self._safe_getattr(dvs_policy, "uplinkPortOrder", None) if dvs_policy else None

    @staticmethod
    def _standard_nic_role(device: str, nic_order: Any | None) -> str | None:
        if nic_order is None:
            return None
        active = getattr(nic_order, "activeNic", None)
        standby = getattr(nic_order, "standbyNic", None)
        if active is None and standby is None:
            return None
        active_names = {str(item) for item in (active or [])}
        standby_names = {str(item) for item in (standby or [])}
        if device in active_names and device in standby_names:
            return None
        if device in active_names:
            return "active"
        if device in standby_names:
            return "standby"
        return "unused"

    @staticmethod
    def _distributed_uplink_role(uplink_name: str, uplink_order: Any | None) -> str | None:
        if uplink_order is None:
            return None
        active = getattr(uplink_order, "activeUplinkPort", None)
        standby = getattr(uplink_order, "standbyUplinkPort", None)
        if active is None and standby is None:
            return None
        active_names = {str(item) for item in (active or [])}
        standby_names = {str(item) for item in (standby or [])}
        if uplink_name in active_names and uplink_name in standby_names:
            return None
        if uplink_name in active_names:
            return "active"
        if uplink_name in standby_names:
            return "standby"
        return "unused"

    @staticmethod
    def _dedupe_portgroup_usage(values: list[dict[str, str]]) -> list[dict[str, str]]:
        output: list[dict[str, str]] = []
        seen: set[tuple[str, str, str]] = set()
        for item in values:
            key = (item.get("switch", ""), item.get("portgroup", ""), item.get("role", ""))
            if key in seen:
                continue
            seen.add(key)
            output.append(item)
        return output

    @staticmethod
    def _pnic_speed_mb(value: Any) -> int | None:
        if value in (None, ""):
            return None
        try:
            return int(value)
        except (TypeError, ValueError, OverflowError):
            return None

    def _physical_nic_issue_counts(self, host: Any) -> tuple[int | None, int | None]:
        return self._physical_nic_issue_counts_from_details(self._physical_nic_details(host))

    @staticmethod
    def _physical_nic_issue_counts_from_details(
        details: list[dict[str, Any]] | None,
    ) -> tuple[int | None, int | None]:
        if details is None:
            return None, None
        uplinks = [item for item in details if item.get("is_in_use") is True]
        if not uplinks:
            return 0, 0
        if any(item.get("assessment") == "speed_unknown" for item in uplinks):
            return sum(item.get("assessment") == "down" for item in uplinks), None
        down = sum(item.get("assessment") == "down" for item in uplinks)
        degraded = sum(bool(item.get("issue_codes") and "link_down" not in item["issue_codes"]) for item in uplinks)
        return down, degraded

    @staticmethod
    def _physical_nic_issue_detail_from_details(details: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        for item in details or []:
            if item.get("is_in_use") is not True:
                continue
            issue_codes = item.get("issue_codes") or []
            if not issue_codes:
                continue
            output.append(
                {
                    **item,
                    "status": "down" if "link_down" in issue_codes else "degraded",
                    "speed_mb": item.get("actual_speed_mb"),
                }
            )
        return output

    def _physical_nic_issue_detail(self, host: Any) -> list[dict[str, Any]]:
        return self._physical_nic_issue_detail_from_details(self._physical_nic_details(host))

    def _physical_nic_switch_bindings(self, network: Any) -> dict[str, list[dict[str, str]]]:
        bindings: dict[str, list[dict[str, str]]] = {}
        for switch in self._safe_getattr(network, "vswitch", []) or []:
            switch_name = str(self._safe_getattr(switch, "name", None) or "vSwitch")
            for pnic_key in self._safe_getattr(switch, "pnic", []) or []:
                device = self._pnic_name_from_key(pnic_key)
                if device:
                    self._append_pnic_switch_binding(
                        bindings,
                        device,
                        {"type": "standard", "name": switch_name, "uplink_name": device},
                    )

        for switch in self._safe_getattr(network, "proxySwitch", []) or []:
            switch_name = str(
                self._safe_getattr(switch, "dvsName", None)
                or self._safe_getattr(switch, "dvsUuid", None)
                or self._safe_getattr(switch, "key", None)
                or "vDS"
            )
            switch_uuid = str(self._safe_getattr(switch, "dvsUuid", "") or "").strip()
            uplink_names = {
                str(self._safe_getattr(item, "key", "") or ""): str(self._safe_getattr(item, "value", "") or "")
                for item in self._safe_getattr(switch, "uplinkPort", []) or []
                if self._safe_getattr(item, "key", None) and self._safe_getattr(item, "value", None)
            }
            spec = self._safe_getattr(switch, "spec", None)
            backing = self._safe_getattr(spec, "backing", None) if spec else None
            pnic_specs = self._safe_getattr(backing, "pnicSpec", []) if backing else []
            spec_by_device: dict[str, list[tuple[str, str]]] = {}
            for pnic_spec in pnic_specs or []:
                device = str(self._safe_getattr(pnic_spec, "pnicDevice", "") or "").strip()
                uplink_key = str(self._safe_getattr(pnic_spec, "uplinkPortKey", "") or "").strip()
                if device:
                    spec_by_device.setdefault(device, []).append((uplink_key, uplink_names.get(uplink_key, "")))
            devices = {
                device
                for item in self._safe_getattr(switch, "pnic", []) or []
                if (device := self._pnic_name_from_key(item))
            }
            devices.update(spec_by_device)
            for device in sorted(devices):
                mappings = spec_by_device.get(device) or [("", "")]
                for uplink_key, uplink_name in mappings:
                    self._append_pnic_switch_binding(
                        bindings,
                        device,
                        {
                            "type": "distributed",
                            "name": switch_name,
                            "uuid": switch_uuid,
                            "uplink_key": uplink_key,
                            "uplink_name": uplink_name,
                        },
                    )

        for switch in self._safe_getattr(network, "opaqueSwitch", []) or []:
            switch_name = str(
                self._safe_getattr(switch, "name", None)
                or self._safe_getattr(switch, "key", None)
                or "OpaqueSwitch"
            )
            for pnic_key in self._safe_getattr(switch, "pnic", []) or []:
                device = self._pnic_name_from_key(pnic_key)
                if device:
                    self._append_pnic_switch_binding(
                        bindings,
                        device,
                        {"type": "opaque", "name": switch_name},
                    )
        return bindings

    @staticmethod
    def _append_pnic_switch_binding(
        bindings: dict[str, list[dict[str, str]]],
        device: str,
        binding: dict[str, str],
    ) -> None:
        rows = bindings.setdefault(device, [])
        if binding not in rows:
            rows.append(binding)

    def _host_certificate_info(self, host: Any) -> dict[str, Any]:
        candidates: list[tuple[str, Any]] = []
        config = getattr(host, "config", None)
        summary = getattr(host, "summary", None)
        thumbprint = self._first_attr(getattr(summary, "config", None), ["sslThumbprint"]) if summary else None
        if not thumbprint and config:
            thumbprint = self._first_attr(config, ["sslThumbprint"])
        for source_name, source in (
            ("config.certificate", getattr(config, "certificate", None) if config else None),
            ("config.certificateInfo", getattr(config, "certificateInfo", None) if config else None),
            ("summary.config.certificate", getattr(getattr(summary, "config", None), "certificate", None) if summary else None),
            ("summary.config.certificateInfo", getattr(getattr(summary, "config", None), "certificateInfo", None) if summary else None),
        ):
            if source is not None:
                candidates.append((source_name, source))

        for source_name, candidate in candidates:
            not_after = self._first_attr(candidate, ["notAfter", "not_after", "validTo", "expirationDate"])
            parsed = self._parse_datetime(not_after)
            if parsed is None:
                continue
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            subject = self._first_attr(candidate, ["subject", "subjectName", "issuedTo"])
            issuer = self._first_attr(candidate, ["issuer", "issuerName", "issuedBy"])
            return {
                "days_remaining": (parsed.astimezone(UTC) - datetime.now(UTC)).days,
                "not_after": parsed.astimezone(UTC).strftime("%Y-%m-%d"),
                "subject": str(subject) if subject else "",
                "issuer": str(issuer) if issuer else "",
                "fingerprint": str(thumbprint) if thumbprint else "",
                "probe_method": source_name,
                "probe_status": f"已从 {source_name} 采集证书到期时间",
            }

        endpoint = self._host_certificate_endpoint(host)
        if endpoint:
            tls_info = self._tls_certificate_info(endpoint)
            if tls_info.get("days_remaining") is not None:
                return tls_info
            tls_info["fingerprint"] = tls_info.get("fingerprint") or str(thumbprint or "")
            return tls_info

        return {
            "days_remaining": None,
            "not_after": None,
            "subject": None,
            "issuer": None,
            "fingerprint": str(thumbprint) if thumbprint else "",
            "probe_method": "vCenter HostSystem certificate fields",
            "probe_status": "仅发现 sslThumbprint，当前 vCenter 未返回证书到期时间字段，且未发现可用于 TLS 探测的主机管理地址" if thumbprint else "当前 vCenter 未返回主机证书字段，且未发现可用于 TLS 探测的主机管理地址",
        }

    def _first_attr(self, obj: Any, names: list[str]) -> Any:
        if obj is None:
            return None
        for name in names:
            value = getattr(obj, name, None)
            if value is not None:
                return value
        return None

    def _host_certificate_endpoint(self, host: Any) -> str | None:
        for candidate in (
            getattr(host, "name", None),
            self._first_attr(getattr(host, "summary", None), ["managementServerIp"]),
        ):
            endpoint = self._normalize_host_endpoint(candidate)
            if endpoint:
                return endpoint
        network = getattr(getattr(host, "config", None), "network", None)
        for vnic in getattr(network, "vnic", []) or []:
            spec = getattr(vnic, "spec", None)
            ip = getattr(spec, "ip", None) if spec else None
            endpoint = self._normalize_host_endpoint(getattr(ip, "ipAddress", None))
            if endpoint:
                return endpoint
        return None

    def _normalize_host_endpoint(self, value: Any) -> str | None:
        if not value:
            return None
        text = str(value).strip()
        if not text or text.lower() in {"unknown", "localhost"}:
            return None
        if "/" in text:
            text = text.split("/", 1)[0]
        if ":" in text and text.count(":") == 1:
            host_part, port_part = text.rsplit(":", 1)
            if port_part.isdigit():
                text = host_part
        return text.strip("[]") or None

    def _tls_certificate_info(self, endpoint: str, port: int = 443, timeout: float = 5.0) -> dict[str, Any]:
        server_hostname = endpoint if not self._looks_like_ip_address(endpoint) else None
        ssl_context = ssl._create_unverified_context()  # noqa: SLF001 - only reads certificate metadata; no trust validation
        try:
            with socket.create_connection((endpoint, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                with ssl_context.wrap_socket(sock, server_hostname=server_hostname) as tls:
                    der_cert = tls.getpeercert(binary_form=True)
            if not der_cert:
                return self._host_certificate_unavailable(endpoint, "TLS 握手成功但未返回服务端证书")
            decoded = self._decode_der_certificate(der_cert)
            not_after = self._parse_datetime(decoded.get("notAfter"))
            if not_after is None:
                return self._host_certificate_unavailable(endpoint, "TLS 证书未包含可解析的到期时间")
            if not_after.tzinfo is None:
                not_after = not_after.replace(tzinfo=UTC)
            not_before = self._parse_datetime(decoded.get("notBefore"))
            if not_before and not_before.tzinfo is None:
                not_before = not_before.replace(tzinfo=UTC)
            fingerprint = ":".join(re.findall("..", hashlib.sha256(der_cert).hexdigest().upper()))
            return {
                "days_remaining": (not_after.astimezone(UTC) - datetime.now(UTC)).days,
                "not_after": not_after.astimezone(UTC).strftime("%Y-%m-%d"),
                "not_before": not_before.astimezone(UTC).strftime("%Y-%m-%d") if not_before else "",
                "subject": self._certificate_name(decoded.get("subject")),
                "issuer": self._certificate_name(decoded.get("issuer")),
                "san": self._certificate_san(decoded),
                "fingerprint": fingerprint,
                "probe_method": "ESXi 443 TLS 证书探测",
                "probe_status": f"已通过 ESXi 443 TLS 证书探测采集到期时间（{endpoint}）",
            }
        except Exception as exc:  # noqa: BLE001 - collection should continue and rule becomes unavailable
            return self._host_certificate_unavailable(endpoint, f"无法连接 ESXi 443 获取证书：{exc}")

    def _host_certificate_unavailable(self, endpoint: str, reason: str) -> dict[str, Any]:
        return {
            "days_remaining": None,
            "not_after": None,
            "not_before": None,
            "subject": None,
            "issuer": None,
            "san": [],
            "fingerprint": "",
            "probe_method": "ESXi 443 TLS 证书探测",
            "probe_status": f"{reason}；主机：{endpoint}",
        }

    def _decode_der_certificate(self, der_cert: bytes) -> dict[str, Any]:
        pem = ssl.DER_cert_to_PEM_cert(der_cert)
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False, encoding="ascii") as cert_file:
            cert_file.write(pem)
            cert_path = Path(cert_file.name)
        try:
            return ssl._ssl._test_decode_cert(str(cert_path))  # noqa: SLF001 - stdlib has no public DER parser
        finally:
            cert_path.unlink(missing_ok=True)

    def _certificate_name(self, value: Any) -> str:
        if not value:
            return ""
        parts: list[str] = []
        for group in value:
            for key, item_value in group:
                parts.append(f"{key}={item_value}")
        return ", ".join(parts)

    def _certificate_san(self, decoded: dict[str, Any]) -> list[str]:
        return [f"{kind}:{value}" for kind, value in decoded.get("subjectAltName", []) or []]

    def _looks_like_ip_address(self, value: str) -> bool:
        return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value) or ":" in value)

    def _affected_switches_for_uplinks(self, host: Any, affected_devices: list[str]) -> list[str]:
        network = getattr(getattr(host, "config", None), "network", None)
        if network is None:
            return []
        issue_devices = set(affected_devices)
        if not issue_devices:
            return []
        bindings = self._physical_nic_switch_bindings(network)
        return sorted({
            binding["name"]
            for device in issue_devices
            for binding in bindings.get(device, [])
        })

    def _used_physical_nic_names(self, network: Any) -> set[str]:
        return set(self._physical_nic_switch_bindings(network))

    def _pnic_name_from_key(self, value: Any) -> str | None:
        if not value:
            return None
        device = self._safe_getattr(value, "device", None)
        if device:
            return str(device).strip()
        key = self._safe_getattr(value, "key", None)
        text = str(key or value)
        return text.rsplit("-", 1)[-1] if "-" in text else text

    def _storage_path_dead_count(self, host: Any) -> int | None:
        storage = getattr(getattr(host, "config", None), "storageDevice", None)
        multipath = getattr(storage, "multipathInfo", None) if storage else None
        if multipath is None:
            return None
        luns = getattr(multipath, "lun", None)
        if luns is None:
            return None
        dead = 0
        for lun in luns or []:
            for path in getattr(lun, "path", []) or []:
                state = str(getattr(path, "pathState", "")).lower()
                if state in {"dead", "error", "off"}:
                    dead += 1
        return dead

    def _storage_path_dead_detail(self, host: Any) -> list[dict[str, str]]:
        storage = getattr(getattr(host, "config", None), "storageDevice", None)
        multipath = getattr(storage, "multipathInfo", None) if storage else None
        detail: list[dict[str, str]] = []
        for lun in getattr(multipath, "lun", []) or []:
            lun_id = str(getattr(lun, "id", "") or "")
            for path in getattr(lun, "path", []) or []:
                state = str(getattr(path, "pathState", "") or "").lower()
                if state not in {"dead", "error", "off"}:
                    continue
                detail.append(
                    {
                        "adapter": str(getattr(path, "adapter", "") or ""),
                        "lun": lun_id,
                        "target": str(getattr(path, "target", "") or ""),
                        "state": state,
                    }
                )
        return detail

    def _datastore_path_state_counts(self, datastore: Any) -> dict[str, Any] | None:
        disk_names = self._datastore_extent_disk_names(datastore)
        if not disk_names:
            return None
        host_mounts = self._safe_sequence(self._safe_getattr(datastore, "host", None, context="datastore.host"), context="datastore.host")
        if host_mounts is None:
            return None
        active_count = 0
        total_count = 0
        issue_count = 0
        issue_detail: list[dict[str, str]] = []
        matched_lun = False
        for mount in host_mounts or []:
            host = getattr(mount, "key", None)
            storage = getattr(getattr(host, "config", None), "storageDevice", None) if host else None
            multipath = getattr(storage, "multipathInfo", None) if storage else None
            for lun in getattr(multipath, "lun", []) or []:
                lun_id = str(getattr(lun, "id", "") or "")
                if not any(disk_name in lun_id or lun_id in disk_name for disk_name in disk_names):
                    continue
                matched_lun = True
                for path in getattr(lun, "path", []) or []:
                    total_count += 1
                    state = str(getattr(path, "pathState", "") or "").lower()
                    if state == "active":
                        active_count += 1
                    elif state not in {"standby"}:
                        issue_count += 1
                        issue_detail.append(
                            {
                                "host": str(getattr(host, "name", "") or ""),
                                "adapter": str(getattr(path, "adapter", "") or ""),
                                "lun": lun_id,
                                "target": str(getattr(path, "target", "") or ""),
                                "state": state,
                            }
                        )
        if not matched_lun:
            return None
        return {
            "active_count": active_count,
            "total_count": total_count,
            "issue_count": issue_count,
            "issue_detail": issue_detail,
        }

    def _datastore_extent_disk_names(self, datastore: Any) -> set[str]:
        info = getattr(datastore, "info", None)
        vmfs = getattr(info, "vmfs", None) if info else None
        names: set[str] = set()
        for extent in getattr(vmfs, "extent", []) or []:
            disk_name = getattr(extent, "diskName", None)
            if disk_name:
                names.add(str(disk_name))
        return names

    def _datastore_multipath_applicable(self, datastore: Any, path_counts: dict[str, Any] | None) -> bool:
        attached_host_count = len(self._safe_sequence(self._safe_getattr(datastore, "host", [], context="datastore.host"), context="datastore.host") or [])
        if path_counts is None:
            return False
        return attached_host_count > 1

    def _thin_overcommit_ratio(self, capacity: int, free: int, uncommitted: Any) -> float | None:
        if not capacity:
            return None
        if uncommitted is None:
            return None
        provisioned = (capacity - free) + int(uncommitted or 0)
        return round((provisioned / capacity) * 100, 2)

    def _datastore_filesystem(self, datastore: Any) -> tuple[str | None, str | None]:
        info = getattr(datastore, "info", None)
        summary = getattr(datastore, "summary", None)
        datastore_type = getattr(summary, "type", None) if summary else None
        vmfs = getattr(info, "vmfs", None) if info else None
        if vmfs is not None:
            version = getattr(vmfs, "version", None) or getattr(vmfs, "majorVersion", None)
            return "VMFS", str(version) if version is not None else None
        return str(datastore_type) if datastore_type else None, None

    def _datastore_filesystem_legacy(self, filesystem_type: str | None, filesystem_version: str | None) -> bool | None:
        if filesystem_type != "VMFS":
            return False
        if filesystem_version is None:
            return None
        match = re.search(r"\d+", str(filesystem_version))
        if not match:
            return None
        return int(match.group(0)) < 6

    def _vmkernel_mtu_values(self, host: Any) -> list[int] | None:
        network = getattr(getattr(host, "config", None), "network", None)
        vnics = list(getattr(network, "vnic", []) or []) if network else []
        if not network:
            return None
        values: list[int] = []
        for vnic in vnics:
            mtu = getattr(getattr(vnic, "spec", None), "mtu", None)
            if mtu is not None:
                values.append(int(mtu))
        return values

    def _vmotion_vmk_count(self, host: Any) -> int | None:
        host_name = str(self._safe_getattr(host, "name", self._safe_getattr(host, "_moId", "unknown")))
        config = self._safe_getattr(host, "config", None, f"host[{host_name}].config.vmotion")
        manager = self._safe_getattr(config, "virtualNicManagerInfo", None, f"host[{host_name}].virtualNicManagerInfo")
        net_configs = self._safe_getattr(manager, "netConfig", None, f"host[{host_name}].virtualNicManagerInfo.netConfig") if manager else None
        if net_configs is None:
            return None
        for net_config in net_configs or []:
            if str(self._safe_getattr(net_config, "nicType", "")).lower() == "vmotion":
                selected = self._safe_sequence(self._safe_getattr(net_config, "selectedVnic", None), f"host[{host_name}].vmotion.selectedVnic")
                return len(selected) if selected is not None else None
        return 0

    def _vmkernel_adapters(
        self,
        host: Any,
        distributed_portgroup_index: dict[tuple[str, str], dict[str, str]] | None = None,
    ) -> list[dict[str, Any]] | None:
        network = getattr(getattr(host, "config", None), "network", None)
        if network is None:
            return None
        adapters: list[dict[str, Any]] = []
        for vnic in getattr(network, "vnic", []) or []:
            spec = getattr(vnic, "spec", None)
            network_label, switch = self._vmkernel_network_location(
                network,
                vnic,
                distributed_portgroup_index or {},
            )
            adapters.append(
                {
                    "device": str(getattr(vnic, "device", "") or ""),
                    "portgroup": network_label,
                    "network_label": network_label,
                    "switch": switch,
                    "mtu": getattr(spec, "mtu", None),
                    "ip_address": getattr(getattr(spec, "ip", None), "ipAddress", None),
                    "subnet_mask": getattr(getattr(spec, "ip", None), "subnetMask", None),
                }
            )
        return adapters

    def _vmkernel_network_location(
        self,
        network: Any,
        vnic: Any,
        distributed_portgroup_index: dict[tuple[str, str], dict[str, str]],
    ) -> tuple[str, str]:
        spec = self._safe_getattr(vnic, "spec")
        distributed_port = self._safe_getattr(spec, "distributedVirtualPort") if spec else None
        if distributed_port is not None:
            switch_uuid = str(self._safe_getattr(distributed_port, "switchUuid", "") or "").strip()
            portgroup_key = str(self._safe_getattr(distributed_port, "portgroupKey", "") or "").strip()
            mapping = distributed_portgroup_index.get((switch_uuid, portgroup_key), {})
            proxy_switch_name = next(
                (
                    str(self._safe_getattr(proxy_switch, "dvsName", "") or "").strip()
                    for proxy_switch in (self._safe_getattr(network, "proxySwitch", []) or [])
                    if str(self._safe_getattr(proxy_switch, "dvsUuid", "") or "").strip() == switch_uuid
                ),
                "",
            )
            return (
                mapping.get("network_label") or "未解析",
                proxy_switch_name or mapping.get("switch") or "未解析",
            )

        portgroup_name = str(self._safe_getattr(spec, "portgroup", "") or "").strip() if spec else ""
        if not portgroup_name:
            return "未记录", "未记录"
        switch_name = ""
        for portgroup in self._safe_getattr(network, "portgroup", []) or []:
            portgroup_spec = self._safe_getattr(portgroup, "spec")
            if str(self._safe_getattr(portgroup_spec, "name", "") or "").strip() == portgroup_name:
                switch_name = str(self._safe_getattr(portgroup_spec, "vswitchName", "") or "").strip()
                break
        return portgroup_name, switch_name or "未记录"

    def _vsan_vmk_adapters(
        self,
        host: Any,
        distributed_portgroup_index: dict[tuple[str, str], dict[str, str]] | None = None,
    ) -> list[dict[str, Any]] | None:
        """Return only VMkernel adapters selected for the vSAN traffic type."""

        manager = getattr(getattr(host, "config", None), "virtualNicManagerInfo", None)
        net_configs = getattr(manager, "netConfig", None) if manager else None
        network = getattr(getattr(host, "config", None), "network", None)
        if net_configs is None or network is None:
            return None
        selected_devices: set[str] = set()
        vnic_by_reference: dict[str, Any] = {}
        for vnic in getattr(network, "vnic", []) or []:
            for reference in (
                getattr(vnic, "device", None),
                getattr(vnic, "key", None),
                getattr(vnic, "_moId", None),
                str(vnic),
            ):
                if reference:
                    text = str(reference)
                    vnic_by_reference[text] = vnic
                    vnic_by_reference[text.removeprefix("vsan.")] = vnic
        for net_config in net_configs or []:
            if str(getattr(net_config, "nicType", "")).lower() != "vsan":
                continue
            for selected in getattr(net_config, "selectedVnic", []) or []:
                device = getattr(selected, "device", None) or str(selected)
                if device:
                    selected_devices.add(str(device))
        result: list[dict[str, Any]] = []
        host_name = self._entity_name(host)
        for reference in sorted(selected_devices):
            vnic = vnic_by_reference.get(reference) or vnic_by_reference.get(reference.removeprefix("vsan."))
            if vnic is None:
                continue
            device = str(getattr(vnic, "device", "") or "")
            spec = getattr(vnic, "spec", None)
            ip = getattr(spec, "ip", None) if spec else None
            network_label, switch = self._vmkernel_network_location(
                network,
                vnic,
                distributed_portgroup_index or {},
            )
            result.append({
                "host_name": host_name,
                "device": device,
                "ip_address": getattr(ip, "ipAddress", None),
                "subnet_mask": getattr(ip, "subnetMask", None),
                "portgroup": network_label,
                "network_label": network_label,
                "switch": switch,
                "mtu": getattr(spec, "mtu", None) if spec else None,
            })
        return result

    def _management_uplink_count(self, host: Any) -> int | None:
        manager = getattr(getattr(host, "config", None), "virtualNicManagerInfo", None)
        network = getattr(getattr(host, "config", None), "network", None)
        net_configs = getattr(manager, "netConfig", None) if manager else None
        if net_configs is None or network is None:
            return None
        management_devices: set[str] = set()
        for net_config in net_configs or []:
            if str(getattr(net_config, "nicType", "")).lower() != "management":
                continue
            for selected in getattr(net_config, "selectedVnic", []) or []:
                device = getattr(selected, "device", None) or str(selected)
                if device:
                    management_devices.add(str(device))
        if not management_devices:
            return 0

        uplink_counts: list[int] = []
        for vnic in getattr(network, "vnic", []) or []:
            if getattr(vnic, "device", None) not in management_devices:
                continue
            count = self._uplink_count_for_vmk(network, vnic)
            if count is None:
                return None
            uplink_counts.append(count)
        if not uplink_counts:
            return None
        return max(uplink_counts)

    def _uplink_count_for_vmk(self, network: Any, vnic: Any) -> int | None:
        spec = getattr(vnic, "spec", None)
        portgroup = getattr(spec, "portgroup", None)
        if portgroup:
            for group in getattr(network, "portgroup", []) or []:
                group_spec = getattr(group, "spec", None)
                if getattr(group_spec, "name", None) != portgroup:
                    continue
                active = self._active_nics_from_policy(getattr(group, "computedPolicy", None))
                if active is not None:
                    return len(active)
                switch_name = getattr(group_spec, "vswitchName", None)
                for vswitch in getattr(network, "vswitch", []) or []:
                    if getattr(vswitch, "name", None) == switch_name:
                        return len(getattr(vswitch, "pnic", []) or [])
        distributed_port = getattr(spec, "distributedVirtualPort", None)
        switch_uuid = getattr(distributed_port, "switchUuid", None) if distributed_port else None
        if switch_uuid:
            for proxy_switch in getattr(network, "proxySwitch", []) or []:
                if getattr(proxy_switch, "dvsUuid", None) == switch_uuid:
                    return len(getattr(proxy_switch, "pnic", []) or [])
        return None

    def _active_nics_from_policy(self, policy: Any) -> list[str] | None:
        teaming = getattr(policy, "nicTeaming", None) if policy else None
        nic_order = getattr(teaming, "nicOrder", None) if teaming else None
        active = getattr(nic_order, "activeNic", None) if nic_order else None
        if active is None:
            return None
        return list(active or [])

    def _portgroup_security_issues(
        self,
        host: Any,
        distributed_portgroup_security_issues: dict[str, list[dict[str, Any]]] | None = None,
    ) -> list[dict[str, Any]] | None:
        network = getattr(getattr(host, "config", None), "network", None)
        issues: list[dict[str, Any]] = []
        if network is not None:
            for portgroup in getattr(network, "portgroup", []) or []:
                spec = getattr(portgroup, "spec", None)
                switch_name = str(getattr(spec, "vswitchName", "") or "")
                portgroup_name = str(getattr(spec, "name", getattr(portgroup, "key", "portgroup")) or "")
                policy = getattr(portgroup, "computedPolicy", None) or getattr(spec, "policy", None)
                for issue in self._security_policy_issues(policy, switch_name, portgroup_name):
                    issues.append(issue)
            for vswitch in getattr(network, "vswitch", []) or []:
                switch_name = str(getattr(vswitch, "name", "vSwitch") or "vSwitch")
                spec = getattr(vswitch, "spec", None)
                for issue in self._security_policy_issues(getattr(spec, "policy", None), switch_name, switch_name, scope="vSwitch"):
                    issues.append(issue)
        if distributed_portgroup_security_issues:
            for host_key in self._host_match_keys(host):
                for issue in distributed_portgroup_security_issues.get(host_key, []):
                    if issue not in issues:
                        issues.append(dict(issue))
        if network is None and not issues:
            return None
        return issues

    def _distributed_portgroup_security_by_host(self, portgroups: list[Any]) -> dict[str, list[dict[str, Any]]]:
        issues_by_host: dict[str, list[dict[str, Any]]] = {}
        for portgroup in portgroups:
            config = getattr(portgroup, "config", None)
            portgroup_name = str(
                getattr(config, "name", None)
                or getattr(portgroup, "name", None)
                or getattr(portgroup, "key", None)
                or "distributed portgroup"
            )
            dvs = getattr(config, "distributedVirtualSwitch", None) or getattr(portgroup, "distributedVirtualSwitch", None)
            switch_name = self._entity_name(dvs) or "vDS"
            port_config = getattr(config, "defaultPortConfig", None)
            portgroup_policy = getattr(port_config, "securityPolicy", None)
            dvs_port_config = getattr(getattr(dvs, "config", None), "defaultPortConfig", None) if dvs else None
            dvs_policy = getattr(dvs_port_config, "securityPolicy", None)
            issues = self._security_policy_issues(
                portgroup_policy,
                switch_name,
                portgroup_name,
                scope="distributed_portgroup",
                fallback_policy=dvs_policy,
            )
            if not issues:
                continue
            for host in self._distributed_portgroup_hosts(portgroup, dvs):
                for host_key in self._host_match_keys(host):
                    bucket = issues_by_host.setdefault(host_key, [])
                    for issue in issues:
                        if issue not in bucket:
                            bucket.append(dict(issue))
        return issues_by_host

    def _distributed_portgroup_hosts(self, portgroup: Any, dvs: Any) -> list[Any]:
        candidates: list[Any] = []
        for source in (getattr(portgroup, "host", None), getattr(getattr(portgroup, "config", None), "host", None)):
            candidates.extend(list(source or []))
        dvs_config = getattr(dvs, "config", None) if dvs else None
        for source in (getattr(dvs_config, "host", None), getattr(dvs, "host", None) if dvs else None):
            candidates.extend(list(source or []))
        hosts: list[Any] = []
        seen: set[str] = set()
        for candidate in candidates:
            host = self._host_from_dvs_member(candidate)
            if host is None:
                continue
            key = self._entity_key(host)
            if key in seen:
                continue
            seen.add(key)
            hosts.append(host)
        return hosts

    def _host_from_dvs_member(self, member: Any) -> Any | None:
        for container_name in ("config", "runtime"):
            host = getattr(getattr(member, container_name, None), "host", None)
            if host is not None:
                return host
        for attr in ("host", "key"):
            host = getattr(member, attr, None)
            if host is not None:
                return host
        if getattr(member, "name", None) or getattr(member, "_moId", None):
            return member
        return None

    def _host_match_keys(self, host: Any) -> list[str]:
        if isinstance(host, str):
            return [host]
        keys = [self._entity_key(host)]
        moid = getattr(host, "_moId", None)
        name = self._entity_name(host)
        for key in (moid, name):
            text = str(key).strip() if key is not None else ""
            if text and text not in keys:
                keys.append(text)
        return keys

    def _entity_key(self, entity: Any) -> str:
        if isinstance(entity, str):
            return entity.strip()
        value = getattr(entity, "_moId", None) or getattr(entity, "name", None) or str(id(entity))
        return str(value).strip()

    def _security_policy_issues(
        self,
        policy: Any,
        switch_name: str,
        portgroup_name: str,
        *,
        scope: str = "portgroup",
        fallback_policy: Any | None = None,
    ) -> list[dict[str, Any]]:
        security = self._security_policy_object(policy)
        if security is None:
            return []
        fallback_security = self._security_policy_object(fallback_policy)
        checks = [
            ("allowPromiscuous", "混杂模式"),
            ("forgedTransmits", "Forged Transmits"),
            ("macChanges", "MAC Changes"),
        ]
        issues: list[dict[str, Any]] = []
        for attr, label in checks:
            value = self._effective_security_policy_value(security, attr, fallback_security)
            if value is True:
                issues.append(
                    {
                        "switch": switch_name,
                        "portgroup": portgroup_name,
                        "policy": label,
                        "current_value": "已启用",
                        "recommended_value": "禁用",
                        "risk_level": "P2" if attr == "allowPromiscuous" else "P3",
                        "scope": scope,
                    }
                )
        return issues

    def _security_policy_object(self, policy: Any) -> Any | None:
        if policy is None:
            return None
        return getattr(policy, "security", None) or policy

    def _effective_security_policy_value(self, security: Any, attr: str, fallback_security: Any | None = None) -> bool | None:
        value = getattr(security, attr, None)
        inherited = getattr(value, "inherited", None)
        if inherited is True:
            if fallback_security is not None and fallback_security is not security:
                return self._effective_security_policy_value(fallback_security, attr)
            return None
        if hasattr(value, "value"):
            nested_value = getattr(value, "value", None)
            if nested_value is None:
                if fallback_security is not None and fallback_security is not security:
                    return self._effective_security_policy_value(fallback_security, attr)
                return None
            value = nested_value
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            normalized = value.strip().casefold()
            if normalized in {"true", "yes", "1", "enabled"}:
                return True
            if normalized in {"false", "no", "0", "disabled"}:
                return False
        return None

    def _host_hardware_health_issues(self, host: Any) -> list[dict[str, Any]] | None:
        runtime = getattr(host, "runtime", None)
        health = getattr(runtime, "healthSystemRuntime", None) if runtime else None
        system_health = getattr(health, "systemHealthInfo", None) if health else None
        if system_health is None:
            return None
        sensors = list(getattr(system_health, "numericSensorInfo", []) or [])
        issues: list[dict[str, Any]] = []
        for sensor in sensors:
            status = self._sensor_health_status(sensor)
            if status not in {"red", "yellow"}:
                continue
            issues.append(
                {
                    "component": str(
                        getattr(sensor, "name", None)
                        or getattr(sensor, "sensorType", None)
                        or getattr(sensor, "id", None)
                        or "hardware sensor"
                    ),
                    "status": status,
                    "summary": str(getattr(sensor, "healthState", None) or getattr(sensor, "unitModifier", "") or ""),
                }
            )
        return issues

    def _sensor_health_status(self, sensor: Any) -> str:
        candidates = [
            getattr(getattr(sensor, "healthState", None), "key", None),
            getattr(getattr(sensor, "healthState", None), "label", None),
            getattr(sensor, "healthState", None),
            getattr(sensor, "status", None),
        ]
        for value in candidates:
            text = str(value or "").strip().lower()
            if text in {"red", "yellow", "green", "unknown"}:
                return text
        return ""

    def _host_power_policy(self, host: Any) -> dict[str, Any]:
        power_info = getattr(getattr(host, "config", None), "powerSystemInfo", None)
        current = getattr(power_info, "currentPolicy", None) if power_info else None
        if current is None:
            return {"policy": None, "high_performance": None}
        label = str(
            getattr(current, "shortName", None)
            or getattr(current, "name", None)
            or getattr(current, "description", None)
            or getattr(current, "key", "")
            or ""
        ).strip()
        key = str(getattr(current, "key", "") or "").strip().lower()
        normalized = label.casefold()
        high_performance = (
            "high performance" in normalized
            or "static high performance" in normalized
            or "高性能" in label
            or key in {"1", "highperformance", "static"}
        )
        return {"policy": label or key or None, "high_performance": high_performance}

    def _host_resource_allocation(self, host: Any) -> dict[str, Any]:
        hardware = getattr(host, "hardware", None)
        cpu_info = getattr(hardware, "cpuInfo", None) if hardware else None
        pcpu_count = getattr(cpu_info, "numCpuCores", None) or getattr(cpu_info, "numCpuThreads", None)
        memory_size = getattr(hardware, "memorySize", None) if hardware else None
        memory_capacity_mb = int(memory_size / (1024 * 1024)) if memory_size else None
        vcpu_allocated = 0
        memory_allocated_mb = 0
        saw_vm = False
        for vm in getattr(host, "vm", []) or []:
            if self._is_system_vm_name(getattr(vm, "name", "")):
                continue
            config = getattr(vm, "config", None)
            hardware_config = getattr(config, "hardware", None) if config else None
            vcpu = getattr(hardware_config, "numCPU", None) if hardware_config else None
            memory_mb = getattr(hardware_config, "memoryMB", None) if hardware_config else None
            if vcpu is not None:
                vcpu_allocated += int(vcpu)
                saw_vm = True
            if memory_mb is not None:
                memory_allocated_mb += int(memory_mb)
                saw_vm = True
        if pcpu_count is None or memory_capacity_mb is None:
            return {
                "pcpu_count": pcpu_count,
                "memory_capacity_mb": memory_capacity_mb,
                "vcpu_allocated": vcpu_allocated if saw_vm else None,
                "memory_allocated_mb": memory_allocated_mb if saw_vm else None,
                "vcpu_to_pcpu_ratio": None,
                "memory_allocation_ratio": None,
                "resource_overcommit": None,
            }
        cpu_ratio = round(vcpu_allocated / int(pcpu_count), 2) if int(pcpu_count) > 0 else None
        memory_ratio = round(memory_allocated_mb / memory_capacity_mb, 2) if memory_capacity_mb > 0 else None
        overcommit = bool(
            (cpu_ratio is not None and cpu_ratio >= HOST_CPU_OVERCOMMIT_RATIO_WARNING)
            or (memory_ratio is not None and memory_ratio >= HOST_MEMORY_OVERCOMMIT_RATIO_WARNING)
        )
        return {
            "pcpu_count": int(pcpu_count),
            "memory_capacity_mb": memory_capacity_mb,
            "vcpu_allocated": vcpu_allocated,
            "memory_allocated_mb": memory_allocated_mb,
            "vcpu_to_pcpu_ratio": cpu_ratio,
            "memory_allocation_ratio": memory_ratio,
            "resource_overcommit": overcommit,
        }

    def _collect_vsan_inventory(
        self,
        service_instance: Any,
        clusters: list[Any],
        vms: list[Any] | None = None,
        *,
        include_storage_policy: bool = True,
        include_object_inventory: bool = True,
    ) -> dict[str, Any]:
        vsan_clusters = [cluster for cluster in clusters if self._cluster_has_vsan_datastore(cluster)]
        if not vsan_clusters:
            return {"status": "not_applicable", "clusters": {}}
        stub = getattr(service_instance, "_stub", None)
        if stub is None:
            return {
                "status": "unsupported",
                "collection_error": "vSAN API unavailable: unsupported",
                "clusters": {},
            }
        try:
            import vsanapiutils  # type: ignore[import-not-found]
        except ImportError as exc:
            return {"status": "unsupported", "collection_error": self._exception_message(exc), "clusters": {}}
        try:
            vsan_version = self._resolve_vsan_api_version(vsanapiutils)
            try:
                mos = self._with_vsan_ssl_context(vsanapiutils.GetVsanVcMos, stub, version=vsan_version)
            except TypeError as exc:
                # Older bundled helper shims may expose the historical one-
                # argument signature. Keep that compatibility path explicit;
                # the real helper receives the negotiated version above.
                if "version" not in str(exc).lower() and "argument" not in str(exc).lower():
                    raise
                mos = self._with_vsan_ssl_context(vsanapiutils.GetVsanVcMos, stub)
        except Exception as exc:  # noqa: BLE001 - vSAN API availability depends on vCenter/vSAN version
            return {"status": self._exception_status(exc), "collection_error": self._exception_message(exc), "clusters": {}}

        summaries: dict[str, dict[str, Any]] = {}
        for cluster in vsan_clusters:
            name = self._entity_name(cluster)
            if not name:
                continue
            summaries[name] = self._collect_vsan_cluster_summary(
                cluster,
                mos,
                vsan_version,
                include_object_inventory=include_object_inventory,
            )
        storage_policy = (
            self._collect_vsan_storage_policy_status(service_instance, vsan_clusters, vms or [])
            if include_storage_policy
            else {"collection_status": "not_requested", "items": []}
        )
        object_policy = self._policy_summary_from_items(
            [
                item
                for summary in summaries.values()
                for item in (summary.get("storage_policy_summary") or {}).get("items", [])
            ],
            source="vsan_object_api",
            scope="vsan_object",
            coverage="object_only",
            pbm_confirmed=False,
            collection_status="collected",
        )
        effective_policy = storage_policy if self._policy_summary_has_data(storage_policy) else object_policy
        if not self._policy_summary_has_data(effective_policy):
            effective_policy = {
                "collection_status": "not_collected",
                "source": None,
                "scope": "unknown",
                "coverage": "unavailable",
                "pbm_confirmed": False,
                "evidence_count": 0,
                "checked_count": None,
                "compliant_count": None,
                "noncompliant_count": None,
                "unknown_count": None,
                "policy_categories": [],
                "items": [],
            }
        for summary in summaries.values():
            summary["storage_policy_summary"] = effective_policy
            summary["storage_policy_collection_status"] = effective_policy.get("collection_status")
            summary["storage_policy_source"] = effective_policy.get("source")
            summary["vsan_policy_checked_count"] = effective_policy.get("checked_count")
            summary["vsan_policy_compliant_count"] = effective_policy.get("compliant_count")
            summary["vsan_policy_noncompliant_count"] = effective_policy.get("noncompliant_count")
            summary["vsan_policy_unknown_count"] = effective_policy.get("unknown_count")
        return {
            "status": "collected",
            "vsan_api_version": vsan_version,
            "clusters": summaries,
            "storage_policy": storage_policy,
            "effective_storage_policy": effective_policy,
        }

    def _policy_summary_from_items(
        self,
        items: list[dict[str, Any]],
        *,
        source: str,
        scope: str,
        coverage: str,
        pbm_confirmed: bool,
        collection_status: str,
    ) -> dict[str, Any]:
        categories: dict[str, dict[str, Any]] = {}
        for item in items:
            policy_name = str(item.get("policy_name") or "").strip() or None
            policy_uuid = str(item.get("policy_uuid") or item.get("policy_id") or "").strip() or None
            key = policy_uuid or policy_name or "unknown-policy"
            category = categories.setdefault(
                key,
                {
                    "policy_name": policy_name or policy_uuid or "未命名策略",
                    "policy_uuid": policy_uuid,
                    "scope": scope,
                    "evidence_count": 0,
                    "checked_count": 0,
                    "compliant_count": 0,
                    "noncompliant_count": 0,
                    "unknown_count": 0,
                    "not_applicable_count": 0,
                },
            )
            category["evidence_count"] += 1
            status = str(item.get("status") or item.get("compliance_status") or "").casefold().replace("_", "")
            if status == "notapplicable":
                category["not_applicable_count"] += 1
            elif status:
                category["checked_count"] += 1
            if status == "compliant":
                category["compliant_count"] += 1
            elif status in {"noncompliant", "outofdate"}:
                category["noncompliant_count"] += 1
            else:
                category["unknown_count"] += 1
        policy_categories = sorted(
            categories.values(),
            key=lambda item: (str(item.get("policy_name") or ""), str(item.get("policy_uuid") or "")),
        )
        checked_count = sum(int(item["checked_count"]) for item in policy_categories)
        compliant_count = sum(int(item["compliant_count"]) for item in policy_categories)
        noncompliant_count = sum(int(item["noncompliant_count"]) for item in policy_categories)
        unknown_count = sum(int(item["unknown_count"]) for item in policy_categories)
        not_applicable_count = sum(int(item.get("not_applicable_count") or 0) for item in policy_categories)
        return {
            "collection_status": collection_status,
            "source": source,
            "scope": scope,
            "coverage": coverage,
            "pbm_confirmed": bool(pbm_confirmed),
            "evidence_count": len(items),
            "checked_count": checked_count if policy_categories else None,
            "compliant_count": compliant_count if policy_categories else None,
            "noncompliant_count": noncompliant_count if policy_categories else None,
            "unknown_count": unknown_count if policy_categories else None,
            "not_applicable_count": not_applicable_count if policy_categories else None,
            "policy_categories": policy_categories,
            "items": items[:500],
        }

    def _vsan_policy_index(self, vsan_inventory: dict[str, Any]) -> dict[str, dict[str, Any]]:
        index: dict[str, dict[str, Any]] = {}
        for summary in (vsan_inventory.get("clusters") or {}).values():
            for item in summary.get("object_inventory") or []:
                object_uuid = str(item.get("uuid") or "").strip()
                if not object_uuid:
                    continue
                policy_name = item.get("storage_policy_name")
                policy_uuid = item.get("spbm_profile_uuid") or item.get("storage_policy_uuid")
                status = item.get("spbm_compliance_status")
                if not any((policy_name, policy_uuid, status)):
                    continue
                index[object_uuid] = {
                    "status": status,
                    "policy": policy_uuid,
                    "policy_uuid": policy_uuid,
                    "policy_name": policy_name or policy_uuid,
                    "source": "vsan_object_api",
                    "scope": "vsan_object",
                    "coverage": "object_only",
                    "pbm_confirmed": False,
                    "object_uuid": object_uuid,
                }
        return index

    @staticmethod
    def _policy_summary_has_data(summary: dict[str, Any] | None) -> bool:
        if not isinstance(summary, dict):
            return False
        return bool(summary.get("policy_categories") or int(summary.get("evidence_count") or 0) > 0)

    def _resolve_vsan_api_version(self, vsanapiutils: Any) -> str:
        """Use the target's vSAN VMODL version instead of the SDK v3 default."""

        getter = getattr(vsanapiutils, "GetLatestVmodlVersion", None)
        if callable(getter):
            try:
                version = self._with_vsan_ssl_context(getter, self.host, self.port)
                if isinstance(version, str) and version.startswith("vsan.version."):
                    return version
            except Exception as exc:  # noqa: BLE001 - fallback keeps older SDKs usable
                self._record_collection_warning("vsan.vmodl_version", exc)
        return "vsan.version.version10"

    def _collect_vsan_storage_policy_status(self, service_instance: Any, clusters: list[Any], vms: list[Any] | None = None) -> dict[str, Any]:
        """Read cached REST compliance first; PBM is only a compatibility fallback."""

        rest_items: list[dict[str, Any]] = []
        if vms:
            for vm in vms:
                vm_name = str(self._safe_getattr(vm, "name", "") or "")
                vm_datastores = self._safe_sequence(self._safe_getattr(vm, "datastore", None, f"vm[{vm_name}].datastore"), f"vm[{vm_name}].datastore") or []
                is_vsan_vm = any(
                    str(self._safe_getattr(self._safe_getattr(ds, "summary", None, "datastore.summary"), "type", "", "datastore.summary.type") or "").casefold() == "vsan"
                    for ds in vm_datastores
                )
                if not is_vsan_vm:
                    continue
                compliance = self._rest_storage_policy_compliance(vm)
                if compliance.get("collection_status") != "collected":
                    continue
                home = compliance.get("vm_home")
                if isinstance(home, dict) and home.get("status"):
                    rest_items.append({
                        "status": str(home.get("status")),
                        "scope": "vm_home",
                        "vm_name": vm_name,
                        "policy_id": home.get("policy"),
                        "policy_uuid": home.get("policy"),
                        "policy_name": home.get("policy_name"),
                    })
                for disk in (compliance.get("disks") or {}).values():
                    if isinstance(disk, dict) and disk.get("status"):
                        rest_items.append({
                            "status": str(disk.get("status")),
                            "scope": "disk",
                            "vm_name": vm_name,
                            "policy_id": disk.get("policy"),
                            "policy_uuid": disk.get("policy"),
                            "policy_name": disk.get("policy_name"),
                        })
        if rest_items:
            return self._policy_summary_from_items(
                rest_items,
                source="vcenter_rest.GET /api/vcenter/vm/{vm}/storage/policy/compliance",
                scope="vm_home_and_vmdk",
                coverage="full",
                pbm_confirmed=False,
                collection_status="collected",
            )

        source = {
            "transport": "pbm_api",
            "managed_object": "PbmProfileManager/PbmComplianceManager",
            "method": "QueryAssociatedProfile/CheckCompliance",
            "vmodl_version": "pbm.version.version1",
        }
        try:
            from pyVmomi import SoapStubAdapter, pbm

            vcenter_stub = getattr(service_instance, "_stub", None)
            pbm_stub = SoapStubAdapter(
                host=self.host,
                port=self.port,
                path="/pbm/sdk",
                version="pbm.version.version1",
                sslContext=ssl._create_unverified_context() if not self.ssl_verify else None,
                httpConnectionTimeout=self.timeout,
                sessionId=getattr(vcenter_stub, "sessionId", None),
            )
            pbm_content = pbm.ServiceInstance("ServiceInstance", pbm_stub).RetrieveContent()
            profile_manager = pbm_content.profileManager
            compliance_manager = pbm_content.complianceManager
            server_uuid = getattr(getattr(service_instance.RetrieveContent(), "about", None), "instanceUuid", None)
            items: list[dict[str, Any]] = []
            for cluster in clusters:
                for host in getattr(cluster, "host", []) or []:
                    for vm in getattr(host, "vm", []) or []:
                        ref = pbm.ServerObjectRef(objectType="virtualMachine", key=str(getattr(vm, "_moId", "")), serverUuid=server_uuid)
                        profile_ids = profile_manager.QueryAssociatedProfile(entity=ref) or []
                        for profile_id in profile_ids:
                            results = compliance_manager.CheckCompliance(entities=[ref], profile=profile_id) or []
                            for result in results:
                                items.append({
                                    "vm_name": str(getattr(vm, "name", "")),
                                    "entity_id": str(getattr(result, "entity", "")),
                                    "policy_id": str(getattr(profile_id, "uniqueId", "")),
                                    "policy_uuid": str(getattr(profile_id, "uniqueId", "")),
                                    "policy_name": str(getattr(profile_id, "name", "") or ""),
                                    "scope": "vm_home_and_vmdk",
                                    "status": str(getattr(result, "complianceStatus", "unknown")),
                                    "compliance_status": str(getattr(result, "complianceStatus", "unknown")),
                                    "checked_at": self._vsan_scalar(getattr(result, "checkTime", None)),
                                })
            return self._policy_summary_from_items(
                items,
                source="pbm_api:PbmProfileManager/PbmComplianceManager",
                scope="vm_home_and_vmdk",
                coverage="full",
                pbm_confirmed=True,
                collection_status="collected",
            )
        except Exception as exc:  # noqa: BLE001 - policy is an independent module
            self._record_collection_warning("storage_policy", exc)
            return {"collection_status": self._exception_status(exc), "checked_count": None, "compliant_count": None, "noncompliant_count": None, "unknown_count": None, "items": [], "error": self._exception_message(exc), "source": source}

    def _cluster_has_vsan_datastore(self, cluster: Any) -> bool:
        for datastore in getattr(cluster, "datastore", []) or []:
            summary = getattr(datastore, "summary", None)
            datastore_type = str(getattr(summary, "type", "") or "")
            if self._datastore_is_vsan(datastore, datastore_type):
                return True
        return False

    def _collect_vsan_cluster_summary(
        self,
        cluster: Any,
        mos: dict[str, Any],
        vsan_version: str | None = None,
        *,
        include_object_inventory: bool = True,
    ) -> dict[str, Any]:
        api_status = "collected"
        errors: list[str] = []
        config_info = None
        try:
            config_info = self._with_vsan_ssl_context(
                self._query_vsan_cluster_config,
                mos.get("vsan-cluster-config-system"),
                cluster,
            )
        except Exception as exc:  # noqa: BLE001 - record status and suppress customer findings
            api_status = self._exception_status(exc)
            errors.append(self._exception_message(exc))
        cluster_enabled = self._vsan_cluster_enabled(config_info)
        architecture = self._vsan_architecture(config_info)

        health_summary = None
        health_details: list[dict[str, Any]] | None = None
        native_overall_health = None
        native_overall_health_description = None
        native_timestamp = None
        physical_disks: list[dict[str, Any]] | None = None
        try:
            health_summary = self._with_vsan_ssl_context(
                self._query_vsan_health_summary,
                mos.get("vsan-cluster-health-system"),
                cluster,
            )
            native_overall_health = self._field(health_summary, "overallHealth")
            native_overall_health_description = self._field(health_summary, "overallHealthDescription")
            native_timestamp = self._field(health_summary, "timestamp")
            health_details = self._vsan_health_state_details(health_summary)
            physical_disks = self._vsan_physical_disk_details(health_summary)
        except Exception as exc:  # noqa: BLE001
            api_status = self._merge_api_status(api_status, self._exception_status(exc))
            errors.append(self._exception_message(exc))
        health_issues = self._extract_vsan_health_issues(health_summary)
        object_issues = self._extract_vsan_object_issues(health_summary)

        disk_issues: list[dict[str, Any]] | None = []
        disk_inventory: dict[str, Any] = {"disk_group_count": None, "cache_disk_count": None, "capacity_disk_count": None, "disk_topology": None}
        native_capacity = self._query_vsan_space_usage(mos.get("vsan-cluster-space-report-system"), cluster)
        try:
            disk_system = mos.get("vsan-disk-management-system")
            disk_inventory = self._query_vsan_disk_inventory(disk_system, cluster)
            disk_issues = self._with_vsan_ssl_context(
                self._query_vsan_disk_issues,
                disk_system,
                cluster,
            )
        except Exception as exc:  # noqa: BLE001
            api_status = self._merge_api_status(api_status, self._exception_status(exc))
            errors.append(self._exception_message(exc))
            disk_issues = None

        resync_summary: dict[str, Any] | None = None
        object_inventory: dict[str, Any] | None = None
        object_system = mos.get("vsan-cluster-object-system") or mos.get("vsan-object-system")
        if include_object_inventory:
            try:
                object_inventory = self._query_vsan_object_inventory(object_system, cluster)
            except Exception as exc:  # noqa: BLE001 - object inventory is an independent optional module
                api_status = self._merge_api_status(api_status, self._exception_status(exc))
                errors.append(self._exception_message(exc))
        try:
            resync_summary = self._with_vsan_ssl_context(
                self._query_vsan_resync_summary,
                object_system,
                cluster,
            )
        except Exception as exc:  # noqa: BLE001
            api_status = self._merge_api_status(api_status, self._exception_status(exc))
            errors.append(self._exception_message(exc))

        if cluster_enabled is None:
            api_status = self._merge_api_status(api_status, "not_collected")
        if health_issues is None:
            api_status = self._merge_api_status(api_status, "not_collected")
        if disk_issues is None:
            api_status = self._merge_api_status(api_status, "not_collected")
        if resync_summary is None:
            api_status = self._merge_api_status(api_status, "not_collected")

        health_count = None if health_issues is None else len(health_issues)
        disk_count = None if disk_issues is None else len(disk_issues)
        object_count = None if object_issues is None else len(object_issues)
        resync_count = None if resync_summary is None else resync_summary.get("object_count")
        counts = [health_count, disk_count, object_count, resync_count]
        issue_count = None if any(value is None for value in counts) else sum(int(value or 0) for value in counts)
        if issue_count is not None and cluster_enabled is False:
            issue_count += 1
        return {
            "api_status": api_status,
            "collection_error": "; ".join(error for error in errors if error) or None,
            "source": {
                "transport": "vsan_management_api",
                "managed_object": "VsanVcClusterConfigSystem/VsanVcClusterHealthSystem/VsanObjectSystem",
                "vmodl_version": vsan_version,
            },
            "cluster_enabled": cluster_enabled,
            "architecture": architecture,
            "native_overall_health": native_overall_health,
            "native_overall_health_description": native_overall_health_description,
            "native_timestamp": self._vsan_scalar(native_timestamp),
            "health_checks": health_details,
            "physical_disks": physical_disks,
            "health_issue_count": health_count,
            "disk_health_issue_count": disk_count,
            "object_health_issue_count": object_count,
            "resync_object_count": resync_count,
            "resync_bytes": None if resync_summary is None else resync_summary.get("bytes"),
            "issue_count": issue_count,
            "health_issues": health_issues,
            "disk_health_issues": disk_issues,
            "object_health_issues": object_issues,
            **disk_inventory,
            "object_count": (object_inventory or {}).get("object_count") if object_inventory and object_inventory.get("object_count") is not None else self._extract_vsan_object_count(health_summary),
            "object_count_source": (object_inventory or {}).get("object_count_source"),
            "vmdk_count": (object_inventory or {}).get("vmdk_count") if object_inventory and object_inventory.get("vmdk_count") is not None else self._extract_vsan_vmdk_count(health_summary),
            # Do not promote vSAN ObjectInformation's SPBM enrichment to the
            # PBM compliance result used by the standard policy check. The
            # former is retained as cross-evidence; PBM has its own status.
            "policy_noncompliant_count": self._extract_vsan_policy_noncompliant_count(health_summary),
            "vsan_object_spbm_noncompliant_count": (object_inventory or {}).get("policy_noncompliant_count"),
            "storage_policy_summary": (object_inventory or {}).get("storage_policy_summary") or {},
            "storage_policy_collection_status": "not_collected",
            "storage_policy_source": None,
            "native_capacity": native_capacity,
            "object_inventory": (object_inventory or {}).get("objects", []),
            "vmdk_inventory": (object_inventory or {}).get("vmdks", []),
            "object_inventory_status": (object_inventory or {}).get("collection_status", "not_collected"),
            "resync_object_count_source": None if resync_summary is None else resync_summary.get("object_count_source"),
            "resync_bytes_source": None if resync_summary is None else resync_summary.get("bytes_source"),
            "resync_active_object_count": None if resync_summary is None else resync_summary.get("active"),
            "resync_queued_object_count": None if resync_summary is None else resync_summary.get("queued"),
            "resync_suspended_object_count": None if resync_summary is None else resync_summary.get("suspended"),
        }

    def _vsan_scalar(self, value: Any) -> Any:
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        try:
            return value.isoformat()
        except Exception:
            return str(value)

    def _query_vsan_space_usage(self, space_system: Any, cluster: Any) -> dict[str, Any]:
        source = {
            "transport": "vsan_management_api",
            "managed_object": "VsanSpaceReportSystem",
            "method": "QuerySpaceUsage",
        }
        if space_system is None:
            return {"collection_status": "unavailable", "coverage": "basic_datastore", "source": source}
        method = getattr(space_system, "QuerySpaceUsage", None) or getattr(space_system, "VsanQuerySpaceUsage", None)
        if not callable(method):
            return {"collection_status": "unsupported", "coverage": "basic_datastore", "source": source}
        try:
            try:
                usage = method(cluster=cluster, whatifCapacityOnly=False)
            except TypeError:
                usage = method(cluster=cluster)
            total = self._first_int_attr(usage, ("totalCapacityB",), default=None)
            free = self._first_int_attr(usage, ("freeCapacityB",), default=None)
            used = total - free if total is not None and free is not None else None
            threshold = self._field(usage, "capacityHealthThreshold")
            overview = self._field(usage, "spaceOverview")
            detail = self._field(self._field(usage, "spaceDetail"), "spaceUsageByObjectType")
            return {
                "collection_status": "collected",
                "coverage": "native_vsan",
                "source": source,
                "return_type": f"{type(usage).__module__}.{type(usage).__name__}",
                "total_capacity_bytes": total,
                "free_capacity_bytes": free,
                "used_capacity_bytes": used,
                "used_percent": round(used / total * 100, 2) if total else None,
                "capacity_health_threshold": {
                    "warning_bytes": self._first_int_attr(threshold, ("yellowValue",), default=None),
                    "error_bytes": self._first_int_attr(threshold, ("redValue",), default=None),
                    "enabled": self._field(threshold, "enabled"),
                },
                "uncommitted_bytes": self._first_int_attr(usage, ("uncommittedB",), default=None),
                "space_overview": {
                    "physical_used_bytes": self._first_int_attr(overview, ("physicalUsedB",), default=None),
                    "used_bytes": self._first_int_attr(overview, ("usedB",), default=None),
                    "overhead_bytes": self._first_int_attr(overview, ("overheadB",), default=None),
                    "primary_capacity_bytes": self._first_int_attr(overview, ("primaryCapacityB",), default=None),
                    "reserved_capacity_bytes": self._first_int_attr(overview, ("reservedCapacityB",), default=None),
                },
                "space_by_object_type": [
                    {
                        "object_type": self._field(item, "objType", "objTypeExt"),
                        "physical_used_bytes": self._first_int_attr(item, ("physicalUsedB",), default=None),
                        "used_bytes": self._first_int_attr(item, ("usedB",), default=None),
                        "overhead_bytes": self._first_int_attr(item, ("overheadB",), default=None),
                        "primary_capacity_bytes": self._first_int_attr(item, ("primaryCapacityB",), default=None),
                    }
                    for item in detail or []
                ],
                "efficient_capacity": self._vsan_scalar(self._field(usage, "efficientCapacity")),
                "space_efficiency_ratio": self._vsan_scalar(self._field(usage, "spaceEfficiencyRatio")),
            }
        except Exception as exc:  # noqa: BLE001 - native capacity has datastore fallback
            return {
                "collection_status": self._exception_status(exc),
                "coverage": "basic_datastore",
                "collection_error": self._exception_message(exc),
                "source": source,
            }

    def _vsan_health_state_details(self, summary: Any) -> list[dict[str, Any]] | None:
        if summary is None:
            return None
        object_health = self._field(summary, "objectHealth", "object_health")
        details = self._field(object_health, "objectHealthDetail", "object_health_detail")
        if details is None:
            return []
        result: list[dict[str, Any]] = []
        for item in details or []:
            uuids = self._field(item, "objUuids", "objectUuids") or []
            result.append(
                {
                    "health": self._field(item, "health", "status", "state"),
                    "num_objects": self._first_int_attr(item, ("numObjects", "numberOfObjects", "objectCount"), default=None),
                    "object_uuids": [str(uuid) for uuid in list(uuids)[:500]],
                }
            )
        return result

    def _vsan_physical_disk_details(self, summary: Any) -> list[dict[str, Any]] | None:
        if summary is None:
            return None
        host_summaries = self._field(summary, "physicalDisksHealth")
        if host_summaries is None:
            return None
        result: list[dict[str, Any]] = []
        for host_summary in host_summaries or []:
            hostname = self._first_text_attr(host_summary, ("hostname",), default="") or None
            for disk in self._field(host_summary, "disks") or []:
                scsi_disk = self._field(disk, "scsiDisk")
                result.append(
                    {
                        "host": hostname,
                        "name": self._first_text_attr(disk, ("name",), default="") or None,
                        "uuid": self._first_text_attr(disk, ("uuid",), default="") or None,
                        "summary_health": self._first_text_attr(disk, ("summaryHealth",), default="") or None,
                        "operational_health": self._first_text_attr(disk, ("operationalHealth",), default="") or None,
                        "operational_health_description": self._first_text_attr(disk, ("operationalHealthDescription",), default="") or None,
                        "capacity_health": self._first_text_attr(disk, ("capacityHealth",), default="") or None,
                        "capacity_bytes": self._first_int_attr(disk, ("capacity",), default=None),
                        "used_capacity_bytes": self._first_int_attr(disk, ("usedCapacity",), default=None),
                        "in_cmmds": self._field(disk, "inCmmds"),
                        "in_vsi": self._field(disk, "inVsi"),
                        "disk_group_uuid": self._first_text_attr(disk, ("vsanDiskGroupUuid",), default="") or None,
                        "scsi_device": self._first_text_attr(scsi_disk, ("canonicalName", "deviceName"), default="") or None,
                    }
                )
        return result

    def _query_vsan_object_inventory(self, object_system: Any, cluster: Any) -> dict[str, Any]:
        if object_system is None:
            return {"collection_status": "unavailable", "object_count": None, "object_count_source": None, "vmdk_count": None, "policy_noncompliant_count": None, "objects": [], "vmdks": []}
        query = getattr(object_system, "QueryObjectIdentities", None) or getattr(object_system, "queryObjectIdentities", None)
        if not callable(query):
            return {"collection_status": "unsupported", "object_count": None, "object_count_source": None, "vmdk_count": None, "policy_noncompliant_count": None, "objects": [], "vmdks": []}
        try:
            try:
                response = query(cluster=cluster, objUuids=None, objTypes=None, includeHealth=True, includeObjIdentity=True, includeSpaceSummary=False)
            except TypeError:
                response = query(cluster=cluster, includeHealth=True, includeObjIdentity=True)
            identities = self._field(response, "identities") or []
            objects: list[dict[str, Any]] = []
            vmdks: list[dict[str, Any]] = []
            for identity in identities:
                object_uuid = self._field(identity, "uuid", "vsanObjectUuid", "objectUuid")
                object_type = self._field(identity, "type", "objectType")
                item = {
                    "uuid": str(object_uuid) if object_uuid else None,
                    "object_type": str(object_type) if object_type else None,
                    "description": self._field(identity, "description"),
                    "health": self._field(identity, "health", "status"),
                    "vm_instance_uuid": self._field(identity, "vmInstanceUuid"),
                    "storage_policy_name": self._field(identity, "spbmProfileName"),
                    "storage_policy_uuid": self._field(identity, "spbmProfileUuid"),
                }
                objects.append(item)
                if str(object_type or "").casefold() == "vdisk":
                    vmdks.append({
                        "object_uuid": item["uuid"],
                        "vmdk_name": item["description"],
                        "vm_instance_uuid": item["vm_instance_uuid"],
                        "policy_name": item["storage_policy_name"],
                        "policy_uuid": item["storage_policy_uuid"],
                    })
            info_method = (
                getattr(object_system, "VosQueryVsanObjectInformation", None)
                or getattr(object_system, "QueryVsanObjectInformation", None)
                or getattr(object_system, "queryVsanObjectInformation", None)
            )
            compliance_checked = 0
            noncompliant = 0
            unknown = 0
            compliance_status = "unsupported" if not callable(info_method) else "not_collected"
            if callable(info_method) and objects:
                try:
                    from pyVmomi import vim
                    specs = [vim.cluster.VsanObjectQuerySpec(uuid=item["uuid"]) for item in objects if item.get("uuid")]
                    info_items = info_method(cluster=cluster, vsanObjectQuerySpecs=specs) if specs else []
                    compliance_status = "collected"
                    info_by_uuid = {str(self._field(item, "vsanObjectUuid", "uuid")): item for item in info_items or []}
                    for item in objects:
                        info = info_by_uuid.get(str(item.get("uuid")))
                        if info is None:
                            continue
                        item["health"] = self._field(info, "vsanHealth", "health", "status")
                        item["spbm_profile_uuid"] = self._field(info, "spbmProfileUuid") or item.get("storage_policy_uuid")
                        item["policy_attributes"] = self._field(info, "policyAttributes")
                        compliance = self._field(info, "spbmComplianceResult")
                        item["spbm_compliance_status"] = self._field(compliance, "complianceStatus", "status")
                        status = str(item.get("spbm_compliance_status") or "").casefold().replace("_", "")
                        if status:
                            compliance_checked += 1
                        if status in {"noncompliant", "outofdate"}:
                            noncompliant += 1
                        elif status not in {"compliant"}:
                            unknown += 1
                    if compliance_checked == 0:
                        compliance_status = "unavailable"
                except Exception as exc:  # noqa: BLE001 - object identity remains usable when enrichment is unavailable
                    self._record_collection_warning("vsan.object_information", exc)
                    compliance_status = self._exception_status(exc)
            object_by_uuid = {str(item.get("uuid")): item for item in objects if item.get("uuid")}
            for vmdk in vmdks:
                enriched = object_by_uuid.get(str(vmdk.get("object_uuid")))
                if enriched is None:
                    continue
                vmdk["policy_name"] = enriched.get("storage_policy_name")
                vmdk["policy_uuid"] = enriched.get("spbm_profile_uuid") or enriched.get("storage_policy_uuid")
                vmdk["compliance_status"] = enriched.get("spbm_compliance_status")
            policy_items = [
                {
                    "object_uuid": item.get("uuid"),
                    "object_type": item.get("object_type"),
                    "vmdk_name": item.get("description"),
                    "policy_name": item.get("storage_policy_name"),
                    "policy_uuid": item.get("spbm_profile_uuid") or item.get("storage_policy_uuid"),
                    "status": item.get("spbm_compliance_status"),
                }
                for item in objects
                if item.get("storage_policy_name") or item.get("storage_policy_uuid") or item.get("spbm_profile_uuid") or item.get("spbm_compliance_status")
            ]
            object_policy_summary = self._policy_summary_from_items(
                policy_items,
                source="vsan_object_api",
                scope="vsan_object",
                coverage="object_only",
                pbm_confirmed=False,
                collection_status="collected" if policy_items else "not_collected",
            )
            object_policy_summary["compliance_collection_status"] = compliance_status
            return {
                "collection_status": "collected",
                "object_count": len(objects),
                "object_count_source": "VsanObjectSystem.QueryObjectIdentities.identities",
                "vmdk_count": len(vmdks),
                "policy_noncompliant_count": noncompliant if compliance_checked else None,
                "policy_checked_count": compliance_checked if compliance_checked else None,
                "policy_unknown_count": unknown if compliance_checked else None,
                "storage_policy_summary": object_policy_summary,
                "objects": objects,
                "vmdks": vmdks,
            }
        except Exception:
            raise

    def _vsan_architecture(self, config_info: Any) -> str | None:
        if config_info is None:
            return None
        for owner in (config_info, getattr(config_info, "defaultConfig", None), getattr(config_info, "config", None)):
            value = getattr(owner, "vsanEsaEnabled", None) if owner is not None else None
            if value is True:
                return "esa"
            if value is False:
                return "osa"
        return None

    def _query_vsan_disk_inventory(self, disk_system: Any, cluster: Any) -> dict[str, Any]:
        if disk_system is None:
            return {"disk_group_count": None, "cache_disk_count": None, "capacity_disk_count": None, "disk_topology": None}
        topology: list[dict[str, Any]] = []
        readable = False
        for host in getattr(cluster, "host", []) or []:
            try:
                mappings = disk_system.QueryDiskMappings(host=host)
            except TypeError:
                mappings = disk_system.QueryDiskMappings(host)
            if mappings is not None:
                readable = True
            groups = []
            for mapping in self._as_sequence(mappings):
                group = self._disk_group_from_mapping(mapping)
                if group is not None:
                    groups.append(group)
            topology.append({"host": self._entity_name(host), "disk_groups": groups})
        if not readable:
            return {"disk_group_count": None, "cache_disk_count": None, "capacity_disk_count": None, "disk_topology": None}
        all_groups = [group for host in topology for group in host["disk_groups"]]
        return {
            "disk_group_count": len(all_groups),
            "cache_disk_count": sum(1 for group in all_groups if group.get("cache_disk")),
            "capacity_disk_count": sum(len(group.get("capacity_disks") or []) for group in all_groups),
            "disk_topology": topology,
        }

    def _as_sequence(self, value: Any) -> list[Any]:
        if value is None:
            return []
        if isinstance(value, (list, tuple, set)):
            return list(value)
        for key in ("diskMapping", "diskMapInfo", "diskGroup", "diskGroups"):
            nested = self._field(value, key)
            if nested is not None and nested is not value:
                return self._as_sequence(nested)
        return [value]

    def _field(self, value: Any, *names: str) -> Any:
        for name in names:
            if isinstance(value, dict) and name in value:
                return value[name]
            try:
                result = getattr(value, name)
            except Exception:
                continue
            if result is not None:
                return result
        return None

    def _disk_group_from_mapping(self, mapping: Any) -> dict[str, Any] | None:
        group = self._field(mapping, "mapping", "diskMapping", "diskMapInfo", "diskGroup", "group") or mapping
        cache = self._field(group, "ssd", "cacheDisk", "cacheDiskInfo", "cacheDiskUuid", "cacheDiskId")
        capacity = self._field(group, "nonSsd", "capacityDisks", "capacityDisk", "capacityDiskInfo", "capacityDiskUuid", "capacityDiskId")
        cache_value = self._disk_identity(cache)
        capacity_values = [self._disk_identity(item) for item in self._as_sequence(capacity)]
        capacity_values = [item for item in capacity_values if item]
        if not cache_value and not capacity_values:
            return None
        return {"id": self._disk_identity(self._field(group, "uuid", "id", "diskGroupId")) or "未记录", "cache_disk": cache_value, "capacity_disks": capacity_values}

    def _disk_identity(self, value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, (str, int, float)):
            return str(value)
        return str(self._field(value, "canonicalName", "displayName", "name", "uuid", "deviceName", "id") or "")

    def _extract_vsan_object_count(self, summary: Any) -> int | None:
        return self._first_int_attr(summary, ("totalObjects", "objectCount", "totalObjectCount"), default=None)

    def _extract_vsan_vmdk_count(self, summary: Any) -> int | None:
        return self._first_int_attr(summary, ("vmdkCount", "totalVmdks", "totalVMDKs"), default=None)

    def _extract_vsan_policy_noncompliant_count(self, summary: Any) -> int | None:
        return self._first_int_attr(summary, ("nonCompliantObjects", "nonCompliantCount", "noncompliantCount"), default=None)

    def _query_vsan_cluster_config(self, config_system: Any, cluster: Any) -> Any:
        if config_system is None:
            raise RuntimeError("vSAN cluster config system is unavailable")
        for method_name in ("VsanClusterGetConfig", "GetConfigInfoEx"):
            method = getattr(config_system, method_name, None)
            if method is None:
                continue
            try:
                return method(cluster=cluster)
            except TypeError:
                return method(cluster)
        raise RuntimeError("vSAN cluster config method is unavailable")

    def _query_vsan_health_summary(self, health_system: Any, cluster: Any) -> Any:
        if health_system is None:
            raise RuntimeError("vSAN cluster health system is unavailable")
        for method_name in ("VsanQueryVcClusterHealthSummary", "QueryClusterHealthSummary"):
            method = getattr(health_system, method_name, None)
            if method is None:
                continue
            for kwargs in (
                {"cluster": cluster, "fetchFromCache": True},
                {"cluster": cluster},
            ):
                try:
                    return method(**kwargs)
                except TypeError:
                    continue
            try:
                return method(cluster)
            except TypeError:
                continue
        raise RuntimeError("vSAN cluster health summary method is unavailable")

    def _query_vsan_disk_issues(self, disk_system: Any, cluster: Any) -> list[dict[str, Any]]:
        if disk_system is None:
            raise RuntimeError("vSAN disk management system is unavailable")
        issues: list[dict[str, Any]] = []
        for host in getattr(cluster, "host", []) or []:
            try:
                mappings = disk_system.QueryDiskMappings(host=host)
            except TypeError:
                mappings = disk_system.QueryDiskMappings(host)
            for issue in self._extract_vsan_disk_issues(mappings, self._entity_name(host)):
                issues.append(issue)
        return issues

    def _query_vsan_resync_summary(self, object_system: Any, cluster: Any) -> dict[str, Any]:
        if object_system is None:
            raise RuntimeError("vSAN object system is unavailable")
        try:
            summary = object_system.QuerySyncingVsanObjectsSummary(cluster=cluster)
        except TypeError:
            summary = object_system.QuerySyncingVsanObjectsSummary(cluster)
        object_field_names = (
            "totalObjectsToSync",
            "totalSyncingObjects",
            "syncingObjectCount",
            "syncingObjectsCount",
            "objectCount",
            "totalObjects",
        )
        bytes_field_names = (
            "totalBytesToSync",
            "bytesToSync",
            "totalSyncingBytes",
            "syncingBytes",
        )
        recovery = self._field(summary, "syncingObjectRecoveryDetails")
        return {
            "object_count": self._first_int_attr(
                summary,
                object_field_names,
                default=None,
            ),
            "bytes": self._first_int_attr(
                summary,
                bytes_field_names,
                default=None,
            ),
            "object_count_source": next((name for name in object_field_names if self._field(summary, name) is not None), None),
            "bytes_source": next((name for name in bytes_field_names if self._field(summary, name) is not None), None),
            "active": self._first_int_attr(recovery, ("activeObjectsToSync",), default=None),
            "queued": self._first_int_attr(recovery, ("queuedObjectsToSync",), default=None),
            "suspended": self._first_int_attr(recovery, ("suspendedObjectsToSync",), default=None),
        }

    def _vsan_cluster_enabled(self, config_info: Any) -> bool | None:
        if config_info is None:
            return None
        for owner in (config_info, getattr(config_info, "defaultConfig", None), getattr(config_info, "config", None)):
            value = getattr(owner, "enabled", None) if owner is not None else None
            if value is not None:
                return bool(value)
        return None

    def _extract_vsan_health_issues(self, summary: Any) -> list[dict[str, Any]] | None:
        if summary is None:
            return None
        issues: list[dict[str, Any]] = []
        for item in self._walk_public_objects(summary):
            status = self._vsan_status_from_object(item)
            if status is None or not self._is_vsan_bad_status(status):
                continue
            object_count = self._first_int_attr(item, ("numObjects", "num_objects", "objectCount"), default=None)
            if object_count is not None and object_count <= 0:
                continue
            name = self._first_text_attr(
                item,
                ("testName", "name", "label", "title", "id", "testId", "groupName", "groupId"),
                default="vSAN health check",
            )
            issues.append({"component": name, "status": status, "summary": self._short_object_summary(item)})
        return self._dedupe_issue_dicts(issues)

    def _extract_vsan_object_issues(self, summary: Any) -> list[dict[str, Any]] | None:
        health_issues = self._extract_vsan_health_issues(summary)
        if health_issues is None:
            return None
        object_terms = ("object", "component", "compliance", "inaccessible", "对象", "组件", "合规")
        return [
            issue
            for issue in health_issues
            if any(term in f"{issue.get('component', '')} {issue.get('summary', '')}".casefold() for term in object_terms)
        ]

    def _extract_vsan_disk_issues(self, mappings: Any, host_name: str) -> list[dict[str, Any]]:
        issues: list[dict[str, Any]] = []
        for item in self._walk_public_objects(mappings):
            status = self._vsan_status_from_object(item)
            if status is None or not self._is_vsan_disk_bad_status(status):
                continue
            disk_name = self._first_text_attr(
                item,
                ("canonicalName", "displayName", "name", "uuid", "deviceName", "ssdUuid", "diskUuid"),
                default="vSAN disk",
            )
            issues.append(
                {
                    "host": host_name,
                    "disk": disk_name,
                    "status": status,
                    "summary": self._short_object_summary(item),
                }
            )
        return self._dedupe_issue_dicts(issues)

    def _vsan_datastore_info(
        self,
        datastore_is_vsan: bool,
        cluster_names: list[str],
        used_percent: float,
        free_gb: float | None,
        capacity_gb: float | None,
        capacity_issue: bool,
        vsan_inventory: dict[str, Any] | None,
    ) -> dict[str, Any]:
        if not datastore_is_vsan:
            return {
                "vsan_used_percent": None,
                "vsan_free_gb": None,
                "vsan_capacity_issue": None,
                "vsan_api_status": None,
                "vsan_collection_error": None,
                "vsan_cluster_enabled": None,
                "vsan_cluster_names": [],
                "vsan_health_issue_count": None,
                "vsan_disk_health_issue_count": None,
                "vsan_object_health_issue_count": None,
                "vsan_resync_object_count": None,
                "vsan_resync_bytes": None,
                "vsan_issue_count": None,
                "vsan_health_issues": None,
                "vsan_disk_health_issues": None,
                "vsan_object_health_issues": None,
                "vsan_physical_disks": None,
            }
        summaries = (vsan_inventory or {}).get("clusters", {})
        selected = [summaries[name] for name in cluster_names if name in summaries]
        if not selected:
            status = (vsan_inventory or {}).get("status") or "not_collected"
            return {
                "vsan_used_percent": used_percent,
                "vsan_free_gb": free_gb,
                "vsan_capacity_issue": capacity_issue,
                "vsan_api_status": status,
                "vsan_collection_error": (vsan_inventory or {}).get("collection_error") or "vSAN cluster mapping was not collected",
                "vsan_cluster_enabled": None,
                "vsan_cluster_names": cluster_names,
                "vsan_health_issue_count": None,
                "vsan_disk_health_issue_count": None,
                "vsan_object_health_issue_count": None,
                "vsan_resync_object_count": None,
                "vsan_resync_bytes": None,
                "vsan_issue_count": None,
                "vsan_health_issues": None,
                "vsan_disk_health_issues": None,
                "vsan_object_health_issues": None,
                "vsan_physical_disks": None,
            }
        status = "collected"
        errors: list[str] = []
        enabled_values: list[bool] = []
        health_values: list[list[dict[str, Any]] | None] = []
        disk_values: list[list[dict[str, Any]] | None] = []
        object_values: list[list[dict[str, Any]] | None] = []
        resync_values: list[int | None] = []
        resync_byte_values: list[int | None] = []
        physical_disk_values: list[list[dict[str, Any]] | None] = []
        for summary in selected:
            status = self._merge_api_status(status, str(summary.get("api_status") or "not_collected"))
            if summary.get("collection_error"):
                errors.append(str(summary.get("collection_error")))
            if summary.get("cluster_enabled") is not None:
                enabled_values.append(bool(summary.get("cluster_enabled")))
            health_values.append(summary.get("health_issues"))
            disk_values.append(summary.get("disk_health_issues"))
            object_values.append(summary.get("object_health_issues"))
            resync_values.append(summary.get("resync_object_count"))
            resync_byte_values.append(summary.get("resync_bytes"))
            physical_disk_values.append(summary.get("physical_disks"))
        cluster_enabled = all(enabled_values) if enabled_values else None
        health_issues = None if any(value is None for value in health_values) else [issue for values in health_values for issue in (values or [])]
        disk_issues = None if any(value is None for value in disk_values) else [issue for values in disk_values for issue in (values or [])]
        object_issues = None if any(value is None for value in object_values) else [issue for values in object_values for issue in (values or [])]
        resync_count = None if any(value is None for value in resync_values) else sum(int(value or 0) for value in resync_values)
        resync_bytes = None if any(value is None for value in resync_byte_values) else sum(int(value or 0) for value in resync_byte_values)
        physical_disks = None if any(value is None for value in physical_disk_values) else [disk for values in physical_disk_values for disk in (values or [])]
        # Resync is an operational state, not a failure by itself. It is shown
        # in the report but does not create a customer risk until health/object
        # evidence also indicates an abnormal condition.
        # Capacity is owned by the capacity rule; DS-020 is limited to actual
        # vSAN health/object/disk evidence. Resync is intentionally excluded.
        issue_count = None if status != "collected" or cluster_enabled is None or any(value is None for value in (health_issues, disk_issues, object_issues)) else (
            (0 if cluster_enabled is not False else 1) + len(health_issues) + len(disk_issues) + len(object_issues)
        )
        return {
            "vsan_used_percent": used_percent,
            "vsan_free_gb": free_gb,
            "vsan_capacity_issue": capacity_issue,
            "vsan_capacity_status": "high" if used_percent >= VSAN_DATASTORE_USED_WARNING_PERCENT else "attention" if used_percent >= VSAN_DATASTORE_USED_ATTENTION_PERCENT else "normal",
            "vsan_api_status": status,
            "vsan_collection_error": "; ".join(errors) or None,
            "vsan_cluster_enabled": cluster_enabled,
            "vsan_cluster_names": cluster_names,
            "vsan_health_issue_count": None if health_issues is None else len(health_issues),
            "vsan_disk_health_issue_count": None if disk_issues is None else len(disk_issues),
            "vsan_object_health_issue_count": None if object_issues is None else len(object_issues),
            "vsan_resync_object_count": resync_count,
            "vsan_resync_bytes": resync_bytes,
            "vsan_issue_count": issue_count,
            "vsan_health_issues": health_issues,
            "vsan_disk_health_issues": disk_issues,
            "vsan_object_health_issues": object_issues,
            "vsan_physical_disks": physical_disks,
            "vsan_architecture": next((summary.get("architecture") for summary in selected if summary.get("architecture")), None),
            "vsan_disk_group_count": self._sum_summary_numeric(selected, "disk_group_count"),
            "vsan_cache_disk_count": self._sum_summary_numeric(selected, "cache_disk_count"),
            "vsan_capacity_disk_count": self._sum_summary_numeric(selected, "capacity_disk_count"),
            "vsan_object_count": self._sum_summary_numeric(selected, "object_count"),
            "vsan_vmdk_count": self._sum_summary_numeric(selected, "vmdk_count"),
            "vsan_policy_noncompliant_count": self._sum_summary_numeric(selected, "policy_noncompliant_count"),
            "disk_topology": [topology for summary in selected for topology in (summary.get("disk_topology") or [])],
        }

    def _sum_summary_numeric(self, summaries: list[dict[str, Any]], key: str) -> int | None:
        values = [item.get(key) for item in summaries]
        if not values or any(value is None for value in values):
            return None
        return sum(int(value or 0) for value in values)

    def _merge_api_status(self, current: str, candidate: str) -> str:
        priority = {
            "collected": 0,
            "not_collected": 1,
            "unsupported": 2,
            "unavailable": 3,
            "api_error": 4,
            "permission_denied": 5,
        }
        return candidate if priority.get(candidate, 3) > priority.get(current, 3) else current

    def _exception_status(self, exc: Exception) -> str:
        text = f"{type(exc).__name__} {exc}".casefold()
        if "nopermission" in text or "no permission" in text or "permission" in text or "notauthenticated" in text or "securityerror" in text:
            return "permission_denied"
        if isinstance(exc, ImportError):
            return "unsupported"
        if "not supported" in text or "not_supported" in text or "unsupported" in text or "methodnotfound" in text:
            return "unsupported"
        if isinstance(exc, (TimeoutError, socket.timeout)) or "timeout" in text or "timed out" in text:
            return "unavailable"
        if isinstance(exc, (ssl.SSLError, OSError)) or "ssl" in text or "certificate" in text or "unavailable" in text:
            return "unavailable"
        return "api_error"

    def _exception_message(self, exc: Exception) -> str:
        reason = {
            "permission_denied": "permission_denied",
            "unsupported": "unsupported",
            "unavailable": self._unavailable_reason(exc),
            "api_error": "api_error",
        }.get(self._exception_status(exc), "api_error")
        return f"vSAN API unavailable: {reason}"

    def _unavailable_reason(self, exc: Exception) -> str:
        text = f"{type(exc).__name__} {exc}".casefold()
        if isinstance(exc, (TimeoutError, socket.timeout)) or "timeout" in text or "timed out" in text:
            return "timeout"
        if isinstance(exc, ssl.SSLError) or "ssl" in text or "certificate" in text:
            return "ssl_error"
        if isinstance(exc, OSError):
            return "network_error"
        return "unavailable"

    def _with_vsan_ssl_context(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        if self.ssl_verify:
            return fn(*args, **kwargs)
        with _VSAN_SSL_CONTEXT_LOCK:
            previous_context = ssl._create_default_https_context  # noqa: SLF001 - keep vSAN subcalls aligned with ssl_no_verify.
            ssl._create_default_https_context = ssl._create_unverified_context  # noqa: SLF001
            try:
                return fn(*args, **kwargs)
            finally:
                ssl._create_default_https_context = previous_context  # noqa: SLF001

    def _walk_public_objects(self, value: Any, depth: int = 0, seen: set[int] | None = None) -> list[Any]:
        if seen is None:
            seen = set()
        if value is None or depth > 5:
            return []
        if isinstance(value, (str, bytes, int, float, bool)):
            return []
        object_id = id(value)
        if object_id in seen:
            return []
        seen.add(object_id)
        items: list[Any] = []
        if isinstance(value, dict):
            iterable = value.values()
        elif isinstance(value, (list, tuple, set)):
            iterable = value
        else:
            items.append(value)
            iterable = []
            for name in dir(value):
                if name.startswith("_") or name in {"dynamicType", "dynamicProperty"}:
                    continue
                try:
                    attr = getattr(value, name)
                except Exception:  # noqa: BLE001 - pyVmomi properties can be lazy/faulted
                    continue
                if callable(attr):
                    continue
                iterable.append(attr)
        for child in iterable:
            items.extend(self._walk_public_objects(child, depth + 1, seen))
        return items

    def _vsan_status_from_object(self, item: Any) -> str | None:
        for name in (
            "health",
            "healthState",
            "status",
            "state",
            "result",
            "testHealth",
            "overallHealth",
            "complianceStatus",
            "operationalState",
            "diskState",
        ):
            value = getattr(item, name, None)
            text = self._string_status(value)
            if text:
                return text
        return None

    def _string_status(self, value: Any) -> str | None:
        if value is None:
            return None
        for attr in ("key", "label", "value", "name"):
            nested = getattr(value, attr, None)
            if nested is not None and nested is not value:
                text = str(nested).strip()
                if text:
                    return text
        text = str(value).strip()
        return text or None

    def _is_vsan_bad_status(self, status: Any) -> bool:
        normalized = str(status or "").strip().casefold().replace(" ", "")
        if normalized in VSAN_HEALTH_OK_VALUES or normalized in VSAN_HEALTH_UNKNOWN_VALUES:
            return False
        return any(token in normalized for token in VSAN_HEALTH_BAD_TOKENS)

    def _is_vsan_disk_bad_status(self, status: Any) -> bool:
        normalized = str(status or "").strip().casefold().replace(" ", "")
        if normalized in VSAN_HEALTH_OK_VALUES or normalized in VSAN_HEALTH_UNKNOWN_VALUES:
            return False
        return normalized in VSAN_DISK_BAD_STATES or any(token in normalized for token in VSAN_HEALTH_BAD_TOKENS)

    def _first_text_attr(self, item: Any, names: tuple[str, ...], default: str = "") -> str:
        for name in names:
            value = getattr(item, name, None)
            if value is not None:
                text = str(value).strip()
                if text:
                    return text
        return default

    def _first_int_attr(self, item: Any, names: tuple[str, ...], default: int | None = None) -> int | None:
        for name in names:
            value = getattr(item, name, None)
            if value is None:
                continue
            try:
                return int(value)
            except (TypeError, ValueError):
                continue
        return default

    def _short_object_summary(self, item: Any) -> str:
        values: list[str] = []
        for name in ("description", "summary", "detail", "message", "health", "status", "state"):
            value = getattr(item, name, None)
            if value is None:
                continue
            text = str(value).strip()
            if text and text not in values:
                values.append(text)
        return "; ".join(values[:3])

    def _dedupe_issue_dicts(self, issues: list[dict[str, Any]]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        seen: set[tuple[tuple[str, str], ...]] = set()
        for issue in issues:
            key = tuple(sorted((str(k), str(v)) for k, v in issue.items()))
            if key in seen:
                continue
            seen.add(key)
            result.append(issue)
        return result

    def _datastore_host_names(self, datastore: Any) -> list[str]:
        names: list[str] = []
        mounts = self._safe_sequence(self._safe_getattr(datastore, "host", [], context="datastore.host"), context="datastore.host") or []
        for mount in mounts:
            name = self._entity_name(self._safe_getattr(mount, "key", context="datastore.host[].key"))
            if name and name not in names:
                names.append(name)
        return names

    def _datastore_cluster_names(self, datastore: Any) -> list[str]:
        names: list[str] = []
        mounts = self._safe_sequence(self._safe_getattr(datastore, "host", [], context="datastore.host"), context="datastore.host") or []
        for mount in mounts:
            host = self._safe_getattr(mount, "key", context="datastore.host[].key")
            name = self._entity_name(self._safe_getattr(host, "parent", context="datastore.host[].key.parent"))
            if name and name not in names:
                names.append(name)
        return names

    def _datastore_is_vsan(self, datastore: Any, datastore_type: str) -> bool:
        summary_type = str(getattr(getattr(datastore, "summary", None), "type", "") or datastore_type or "")
        return summary_type.casefold() == "vsan"

    def _datastore_is_local(self, datastore: Any, datastore_type: str) -> bool:
        if self._datastore_is_vsan(datastore, datastore_type):
            return False
        normalized_type = datastore_type.casefold()
        if not normalized_type:
            return False
        if normalized_type in SHARED_DATASTORE_TYPES:
            return False
        if normalized_type and normalized_type not in LOCAL_DATASTORE_TYPES:
            return False
        mounts = self._safe_sequence(self._safe_getattr(datastore, "host", [], context="datastore.host"), context="datastore.host") or []
        return len(mounts) <= 1

    def _datastore_cross_cluster_shared(self, datastore: Any, datastore_type: str, cluster_names: list[str]) -> bool:
        if self._datastore_is_vsan(datastore, datastore_type):
            return False
        if datastore_type.casefold() in {"vsan", "vvolds"}:
            return False
        return len(cluster_names) > 1

    def _vm_datastore_profile(self, vm: Any) -> dict[str, Any]:
        datastore_names: list[str] = []
        local_datastore_names: list[str] = []
        datastores = getattr(vm, "datastore", None)
        if datastores is None:
            return {"datastore_names": None, "local_datastore_names": None, "vm_on_local_datastore": None}
        for datastore in datastores or []:
            summary = getattr(datastore, "summary", None)
            name = str(getattr(summary, "name", None) or self._entity_name(datastore))
            if name and name not in datastore_names:
                datastore_names.append(name)
            datastore_type = str(getattr(summary, "type", "") or "")
            if self._datastore_is_local(datastore, datastore_type) and name and name not in local_datastore_names:
                local_datastore_names.append(name)
        return {
            "datastore_names": datastore_names,
            "local_datastore_names": local_datastore_names,
            "vm_on_local_datastore": bool(local_datastore_names),
        }

    def _is_system_vm_name(self, name: Any) -> bool:
        text = str(name or "").strip()
        if not text:
            return False
        return any(pattern.search(text) for pattern in SYSTEM_VM_NAME_PATTERNS)

    def _vm_guest_os_actual(self, guest: Any) -> str | None:
        value = getattr(guest, "guestFullName", None) if guest else None
        return str(value).strip() if value else None

    def _vm_guest_os_configured(self, config: Any) -> str | None:
        if config is None:
            return None
        value = getattr(config, "guestFullName", None) or getattr(config, "guestId", None)
        return str(value).strip() if value else None

    def _guest_os_mismatch(self, actual: str | None, configured: str | None, tools_running: bool) -> bool | None:
        if tools_running is not True:
            return None
        if not actual or not configured:
            return None
        return actual.casefold() != configured.casefold()

    def _bytes_to_gb(self, value: Any) -> float | None:
        if value is None:
            return None
        try:
            return round(float(value) / (1024 * 1024 * 1024), 2)
        except (TypeError, ValueError):
            return None

    def _resource_reservation(self, allocation: Any) -> int | None:
        if allocation is None:
            return None
        value = getattr(allocation, "reservation", None)
        return int(value) if value is not None else None

    def _resource_limit(self, allocation: Any) -> int | None:
        if allocation is None:
            return None
        value = getattr(allocation, "limit", None)
        return int(value) if value is not None else None

    def _vm_reservation_too_high(
        self,
        cpu_reservation_mhz: int | None,
        memory_reservation_mb: int | None,
        vcpu_count: int | None,
        memory_configured_mb: int | None,
    ) -> bool | None:
        if cpu_reservation_mhz is None or memory_reservation_mb is None:
            return None
        cpu_high = bool(vcpu_count and cpu_reservation_mhz >= int(vcpu_count) * 2000)
        memory_high = bool(memory_configured_mb and memory_reservation_mb >= int(memory_configured_mb) * 0.5)
        return cpu_high or memory_high

    def _hardware_version_number(self, version: Any) -> int | None:
        if not version:
            return None
        match = re.search(r"(\d+)$", str(version))
        return int(match.group(1)) if match else None

    def _snapshot_chain_depth(self, vm: Any) -> int | None:
        root_list = getattr(getattr(vm, "snapshot", None), "rootSnapshotList", None)
        if root_list is None:
            return 0

        def depth(nodes: list[Any]) -> int:
            if not nodes:
                return 0
            return max(1 + depth(getattr(node, "childSnapshotList", None) or []) for node in nodes)

        return depth(root_list or [])

    def _vm_disk_profile(self, vm: Any, vim: Any) -> dict[str, Any] | None:
        devices = self._vm_devices(vm)
        if devices is None:
            return None
        thin_count = 0
        nonpersistent_count = 0
        modes: set[str] = set()
        for device in devices:
            if not isinstance(device, vim.vm.device.VirtualDisk):
                continue
            backing = getattr(device, "backing", None)
            thin = getattr(backing, "thinProvisioned", None) if backing else None
            mode = getattr(backing, "diskMode", None) if backing else None
            if thin is True:
                thin_count += 1
                modes.add("thin")
            elif thin is False:
                modes.add("thick")
            if mode:
                modes.add(str(mode))
                if str(mode).lower() == "independent_nonpersistent":
                    nonpersistent_count += 1
        return {
            "thin_disk_count": thin_count,
            "nonpersistent_disk_count": nonpersistent_count,
            "disk_provisioning_modes": sorted(modes),
        }

    def _vmware_tools_install_state(self, guest: Any) -> tuple[bool | None, str | None]:
        if guest is None:
            return None, None
        status = (
            getattr(guest, "toolsVersionStatus2", None)
            or getattr(guest, "toolsStatus", None)
            or getattr(guest, "toolsRunningStatus", None)
        )
        if status is None:
            return None, None
        normalized = str(status)
        if normalized in {"guestToolsNotInstalled", "toolsNotInstalled"}:
            return False, normalized
        if normalized in {"guestToolsRunning", "guestToolsExecutingScripts"}:
            return True, normalized
        if normalized.startswith("guestTools") or normalized.startswith("tools"):
            return True, normalized
        return None, normalized

    def _numa_affinity(self, vm: Any) -> dict[str, Any]:
        config = getattr(vm, "config", None)
        affinity = getattr(config, "numaNodeAffinity", None) if config else None
        nodes = [str(node) for node in affinity or []] if affinity is not None else []
        if nodes:
            return {"configured": True, "nodes": nodes}
        extra_config = getattr(config, "extraConfig", None) if config else None
        for option in extra_config or []:
            key = str(getattr(option, "key", "") or "")
            if key.lower() == "numa.nodeaffinity":
                raw = str(getattr(option, "value", "") or "")
                nodes = [item.strip() for item in raw.split(",") if item.strip()]
                return {"configured": bool(nodes), "nodes": nodes}
        return {"configured": False, "nodes": []}

    def _needs_consolidation(self, runtime: Any) -> bool | None:
        if runtime is None:
            return None
        value = getattr(runtime, "consolidationNeeded", None)
        return bool(value) if value is not None else None

    def _invalid_network_count(self, vm: Any, vim: Any) -> int | None:
        devices = self._vm_devices(vm)
        if devices is None:
            return None
        count = 0
        network_device_seen = False
        for device in devices:
            if not isinstance(device, vim.vm.device.VirtualEthernetCard):
                continue
            network_device_seen = True
            backing = getattr(device, "backing", None)
            if backing is None:
                count += 1
                continue
            if hasattr(backing, "network") and getattr(backing, "network", None) is None:
                count += 1
        return count if network_device_seen else 0

    def _orphaned_or_inaccessible(self, vm: Any) -> bool | None:
        runtime = getattr(vm, "runtime", None)
        state = getattr(runtime, "connectionState", None) if runtime else None
        if state is None:
            summary = getattr(vm, "summary", None)
            summary_runtime = getattr(summary, "runtime", None) if summary else None
            state = getattr(summary_runtime, "connectionState", None) if summary_runtime else None
        if state is None:
            return None
        return str(state).lower() in {"orphaned", "inaccessible", "invalid"}

    def _passthrough_device_count(self, vm: Any, vim: Any) -> int | None:
        devices = self._vm_devices(vm)
        if devices is None:
            return None
        return sum(1 for device in devices if isinstance(device, vim.vm.device.VirtualPCIPassthrough))

    def _vm_devices(self, vm: Any) -> list[Any] | None:
        config = getattr(vm, "config", None)
        hardware = getattr(config, "hardware", None) if config else None
        devices = getattr(hardware, "device", None) if hardware else None
        if devices is None:
            return None
        return list(devices or [])

    def _vm_resource_limit_present(self, cpu_limit_mhz: int | None, memory_limit_mb: int | None) -> bool | None:
        if cpu_limit_mhz is None or memory_limit_mb is None:
            return None
        return cpu_limit_mhz >= 0 or memory_limit_mb >= 0

    def _powered_off_days(self, vm: Any, content: Any | None) -> int | None:
        runtime = getattr(vm, "runtime", None)
        power_state = str(getattr(runtime, "powerState", "") or "")
        if power_state != "poweredOff":
            return 0
        event_time = self._last_powered_off_event_time(vm, content)
        if event_time is None:
            return None
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=UTC)
        return max(0, (datetime.now(UTC) - event_time.astimezone(UTC)).days)

    def _last_powered_off_event_time(self, vm: Any, content: Any | None) -> datetime | None:
        event_manager = getattr(content, "eventManager", None) if content else None
        if event_manager is None:
            return None
        try:
            from pyVmomi import vim

            end = datetime.now(UTC)
            begin = end - timedelta(days=370)
            entity = vim.event.EventFilterSpec.ByEntity(entity=vm, recursion="self")
            time_filter = vim.event.EventFilterSpec.ByTime(beginTime=begin, endTime=end)
            event_filter = vim.event.EventFilterSpec(entity=entity, time=time_filter)
            events = event_manager.QueryEvents(filter=event_filter)
        except Exception:  # noqa: BLE001 - event history can be restricted
            return None
        latest: datetime | None = None
        for event in events or []:
            event_name = type(event).__name__.lower()
            full_text = str(getattr(event, "fullFormattedMessage", "") or "").lower()
            if "poweredoff" not in event_name and "powered off" not in full_text and "power off" not in full_text:
                continue
            created = getattr(event, "createdTime", None)
            if isinstance(created, datetime) and (latest is None or created > latest):
                latest = created
        return latest

    def _sum_optional_counts(self, *values: int | None) -> int | None:
        if any(value is None for value in values):
            return None
        return sum(int(value or 0) for value in values)

    def _snapshot_age_days_max(self, vm: Any) -> int:
        root_list = getattr(getattr(vm, "snapshot", None), "rootSnapshotList", None) or []
        create_times: list[datetime] = []

        def walk(nodes: list[Any]) -> None:
            for node in nodes:
                created = getattr(node, "createTime", None)
                if isinstance(created, datetime):
                    create_times.append(created)
                walk(getattr(node, "childSnapshotList", None) or [])

        walk(root_list)
        if not create_times:
            return 0
        now = datetime.now(UTC)
        ages = []
        for created in create_times:
            if created.tzinfo is None:
                created = created.replace(tzinfo=UTC)
            ages.append(max(0, (now - created.astimezone(UTC)).days))
        return max(ages) if ages else 0

    def _snapshot_details(self, vm: Any) -> list[dict[str, Any]]:
        """Preserve snapshot name/createTime evidence for customer reports."""

        root_list = getattr(getattr(vm, "snapshot", None), "rootSnapshotList", None) or []
        details: list[dict[str, Any]] = []

        def walk(nodes: list[Any], parent: str = "") -> None:
            for node in nodes:
                created = getattr(node, "createTime", None)
                created_text = created.isoformat() if isinstance(created, datetime) else str(created or "")
                name = str(getattr(node, "name", "") or "")
                details.append({
                    "name": name,
                    "create_time": created_text,
                    "parent": parent,
                })
                walk(getattr(node, "childSnapshotList", None) or [], name)

        walk(root_list)
        return details

    def _global_red_alarm_count(self, entities: list[Any]) -> int | None:
        counts: list[int] = []
        for entity in entities:
            try:
                count = self._triggered_alarm_count(entity)
            except Exception as exc:  # noqa: BLE001 - per-object alarm reads must not abort collection.
                self._record_collection_warning("alarm.count", exc)
                count = None
            if count is not None:
                counts.append(count)
        if not counts:
            return None
        return sum(counts)

    def _global_red_alarm_details(self, entities: list[Any]) -> list[dict[str, str]] | None:
        details: list[dict[str, str]] = []
        readable = False
        seen: set[tuple[str, str, str]] = set()
        for entity in entities:
            try:
                entity_details = self._triggered_alarm_details(entity)
            except Exception as exc:  # noqa: BLE001 - keep later entities readable.
                self._record_collection_warning("alarm.details", exc)
                entity_details = None
            if entity_details is None:
                continue
            readable = True
            for item in entity_details:
                key = (item.get("alarm_name", ""), item.get("entity_name", ""), item.get("status", ""))
                if key in seen:
                    continue
                seen.add(key)
                details.append(item)
        if not readable:
            return None
        return details

    def _triggered_alarm_count(self, entity: Any) -> int | None:
        if entity is None:
            return None
        alarm_states = self._safe_getattr(entity, "triggeredAlarmState", None, "alarm.count.triggeredAlarmState")
        alarm_state_items = self._safe_sequence(alarm_states, "alarm.count.triggeredAlarmState")
        if alarm_state_items is None:
            return None
        count = 0
        for state in alarm_state_items:
            status = str(self._safe_getattr(state, "overallStatus", "", "alarm.count.overallStatus") or "").lower()
            if status == "red" or status.endswith(".red"):
                count += 1
        return count

    def _triggered_alarm_details(self, entity: Any) -> list[dict[str, str]] | None:
        if entity is None:
            return None
        alarm_states = self._safe_getattr(entity, "triggeredAlarmState", None, "alarm.details.triggeredAlarmState")
        alarm_state_items = self._safe_sequence(alarm_states, "alarm.details.triggeredAlarmState")
        if alarm_state_items is None:
            return None
        details: list[dict[str, str]] = []
        for state in alarm_state_items:
            try:
                status = str(self._safe_getattr(state, "overallStatus", "", "alarm.details.overallStatus") or "")
                normalized = status.lower()
                if normalized != "red" and not normalized.endswith(".red"):
                    continue
                alarm = self._safe_getattr(state, "alarm", None, "alarm.details.alarm")
                info = self._safe_getattr(alarm, "info", None, "alarm.details.alarm.info") if alarm else None
                alarm_name = (
                    self._safe_getattr(info, "name", None, "alarm.details.alarm.info.name")
                    if info
                    else None
                ) or (
                    self._safe_getattr(alarm, "name", None, "alarm.details.alarm.name")
                    if alarm
                    else None
                ) or "未命名告警"
                alarm_entity = self._safe_getattr(state, "entity", None, "alarm.details.entity") or entity
                entity_name = (
                    self._safe_getattr(alarm_entity, "name", None, "alarm.details.entity.name")
                    or self._safe_getattr(entity, "name", None, "alarm.details.root.name")
                    or self._safe_getattr(alarm_entity, "_moId", "", "alarm.details.entity.moid")
                )
                details.append(
                    {
                        "alarm_name": str(alarm_name),
                        "entity_name": str(entity_name or "未获取"),
                        "status": "红色",
                    }
                )
            except Exception as exc:  # noqa: BLE001 - one bad alarm state must not hide other alarms.
                self._record_collection_warning("alarm.details.state", exc)
        return details

    def _alarm_collection_status(
        self,
        red_alarm_count: int | None,
        active_red_alarms: list[dict[str, str]] | None,
        warnings: list[dict[str, Any]],
    ) -> str:
        if red_alarm_count is None:
            return "unavailable"
        if active_red_alarms is None or warnings:
            return "partial"
        return "collected"

    def _normalize_lockdown_mode(self, value: Any) -> str | None:
        if value is None:
            return None
        raw = str(value)
        if raw in {"disabled", "lockdownDisabled"}:
            return "disabled"
        if raw in {"lockdownNormal", "normal"}:
            return "lockdownNormal"
        if raw in {"lockdownStrict", "strict"}:
            return "lockdownStrict"
        return raw

    def _license_days_remaining(self, content: Any) -> int | None:
        license_manager = getattr(content, "licenseManager", None)
        if license_manager is None:
            return None
        try:
            licenses = getattr(license_manager, "licenses", None) or []
        except Exception:  # noqa: BLE001 - unavailable property should become data_quality missing
            return None
        if not licenses:
            return None
        explicit_days: list[int] = []
        perpetual_seen = False
        for license_info in licenses:
            expiration = self._extract_license_expiration(license_info)
            if expiration is None:
                perpetual_seen = True
                continue
            if expiration.tzinfo is None:
                expiration = expiration.replace(tzinfo=UTC)
            explicit_days.append((expiration.astimezone(UTC) - datetime.now(UTC)).days)
        if explicit_days:
            return min(explicit_days)
        if perpetual_seen:
            return 999999
        return None

    def _host_license_assignments(self, content: Any, hosts: list[Any]) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        license_manager = getattr(content, "licenseManager", None)
        assignment_manager = getattr(license_manager, "licenseAssignmentManager", None) if license_manager else None
        assignments_by_entity: dict[str, Any] = {}
        if assignment_manager is not None:
            try:
                assignments = assignment_manager.QueryAssignedLicenses()
            except Exception:  # noqa: BLE001 - assignment manager may be restricted
                assignments = None
            for assignment in assignments or []:
                entity_id = str(getattr(assignment, "entityId", "") or "")
                if entity_id:
                    assignments_by_entity[entity_id] = assignment

        for host in hosts:
            moid = str(getattr(host, "_moId", "") or "")
            assignment = assignments_by_entity.get(moid)
            if assignment is None:
                fallback = self._host_license_from_config(host)
                fallback["host_license_probe_status"] = (
                    "未在 licenseAssignmentManager 中找到主机授权记录，已尝试读取主机产品信息"
                )
                result[moid] = fallback
                continue
            license_info = getattr(assignment, "assignedLicense", None)
            result[moid] = self._license_info_to_host_fields(license_info, "已从 licenseAssignmentManager 采集授权记录")
        return result

    def _host_license_from_config(self, host: Any) -> dict[str, Any]:
        product = getattr(getattr(host, "config", None), "product", None)
        product_name = getattr(product, "licenseProductName", None) if product else None
        if not product_name:
            return {
                "host_license_assigned": None,
                "host_license_name": None,
                "host_license_edition": None,
                "host_license_is_evaluation": None,
                "host_license_expiration_date": None,
                "host_license_expiration_days": None,
                "host_license_probe_status": "当前 vCenter 未返回主机授权信息字段",
            }
        text = str(product_name)
        return {
            "host_license_assigned": True,
            "host_license_name": text,
            "host_license_edition": self._license_edition_from_text(text),
            "host_license_is_evaluation": "eval" in text.lower() or "evaluation" in text.lower(),
            "host_license_expiration_date": "永久授权",
            "host_license_expiration_days": 999999,
            "host_license_probe_status": "已从主机 product.licenseProductName 采集授权名称，未发现到期字段",
        }

    def _license_info_to_host_fields(self, license_info: Any, probe_status: str) -> dict[str, Any]:
        if license_info is None:
            return {
                "host_license_assigned": False,
                "host_license_name": "未分配",
                "host_license_edition": "",
                "host_license_is_evaluation": False,
                "host_license_expiration_date": None,
                "host_license_expiration_days": None,
                "host_license_probe_status": probe_status,
            }
        name = str(getattr(license_info, "name", "") or getattr(license_info, "licenseKey", "") or "已分配授权")
        edition = self._license_property(license_info, {"edition", "editionkey", "productname", "name"}) or self._license_edition_from_text(name)
        expiration = self._extract_license_expiration(license_info)
        if expiration is None:
            expiration_date = "永久授权"
            expiration_days = 999999
        else:
            if expiration.tzinfo is None:
                expiration = expiration.replace(tzinfo=UTC)
            expiration_utc = expiration.astimezone(UTC)
            expiration_date = expiration_utc.strftime("%Y-%m-%d")
            expiration_days = (expiration_utc - datetime.now(UTC)).days
        lowered = " ".join([name, str(edition or ""), str(self._license_property(license_info, {"feature", "type"}) or "")]).lower()
        return {
            "host_license_assigned": True,
            "host_license_name": name,
            "host_license_edition": str(edition or ""),
            "host_license_is_evaluation": "eval" in lowered or "evaluation" in lowered,
            "host_license_expiration_date": expiration_date,
            "host_license_expiration_days": expiration_days,
            "host_license_probe_status": probe_status,
        }

    def _license_property(self, license_info: Any, keys: set[str]) -> Any:
        for prop in getattr(license_info, "properties", []) or []:
            key = str(getattr(prop, "key", "") or "").lower()
            if key in keys:
                return getattr(prop, "value", None)
        return None

    def _license_edition_from_text(self, value: str) -> str:
        text = value.lower()
        for edition in ("enterprise plus", "enterprise", "standard", "essentials plus", "essentials", "evaluation"):
            if edition in text:
                return edition.title()
        return value

    def _extract_license_expiration(self, license_info: Any) -> datetime | None:
        direct = getattr(license_info, "expirationDate", None)
        if isinstance(direct, datetime):
            return direct
        for prop in getattr(license_info, "properties", []) or []:
            key = str(getattr(prop, "key", "")).lower()
            value = getattr(prop, "value", None)
            if "expir" not in key:
                continue
            if isinstance(value, datetime):
                return value
            parsed = self._parse_datetime(value)
            if parsed:
                return parsed
        return None

    def _certificate_days_remaining(self) -> int | None:
        ssl_context = ssl.create_default_context()
        if not self.ssl_verify:
            ssl_context = ssl._create_unverified_context()  # noqa: SLF001 - explicit customer-configurable option
        try:
            with socket.create_connection((self.host, self.port), timeout=10) as sock:
                with ssl_context.wrap_socket(sock, server_hostname=self.host) as tls:
                    der_cert = tls.getpeercert(binary_form=True)
            if not der_cert:
                return None
            pem = ssl.DER_cert_to_PEM_cert(der_cert)
            with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False, encoding="ascii") as cert_file:
                cert_file.write(pem)
                cert_path = Path(cert_file.name)
            try:
                decoded = ssl._ssl._test_decode_cert(str(cert_path))  # noqa: SLF001 - stdlib has no public DER parser
            finally:
                cert_path.unlink(missing_ok=True)
            not_after = self._parse_datetime(decoded.get("notAfter"))
            if not_after is None:
                return None
            if not_after.tzinfo is None:
                not_after = not_after.replace(tzinfo=UTC)
            return (not_after.astimezone(UTC) - datetime.now(UTC)).days
        except Exception:  # noqa: BLE001 - certificate plugin should not fail inventory collection
            return None

    def _parse_datetime(self, value: Any) -> datetime | None:
        if isinstance(value, datetime):
            return value
        if not value:
            return None
        text = str(value)
        formats = [
            "%b %d %H:%M:%S %Y %Z",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
        ]
        for fmt in formats:
            try:
                parsed = datetime.strptime(text, fmt)
                return parsed.replace(tzinfo=UTC)
            except ValueError:
                continue
        return None

    def _vcenter_admin_principals(self, content: Any) -> list[str] | None:
        authorization = getattr(content, "authorizationManager", None)
        if authorization is None:
            return None
        try:
            roles = getattr(authorization, "roleList", []) or []
            admin_role_ids = {
                int(getattr(role, "roleId"))
                for role in roles
                if str(getattr(role, "name", "")).lower() in {"admin", "administrator", "administrators"}
                or int(getattr(role, "roleId", 0)) == -1
            }
            permissions = authorization.RetrieveAllPermissions()
        except Exception:  # noqa: BLE001 - permission inventory may be restricted
            return None
        principals = {
            str(getattr(permission, "principal", ""))
            for permission in permissions or []
            if getattr(permission, "roleId", None) in admin_role_ids and getattr(permission, "principal", None)
        }
        return sorted(principals)

    def _role_permission_inheritance_issues(self, content: Any) -> list[dict[str, str]] | None:
        authorization = getattr(content, "authorizationManager", None)
        if authorization is None:
            return None
        try:
            roles = getattr(authorization, "roleList", []) or []
            role_names = {int(getattr(role, "roleId")): str(getattr(role, "name", "")) for role in roles}
            permissions = authorization.RetrieveAllPermissions()
        except Exception:  # noqa: BLE001 - permission inventory may be restricted
            return None
        issues: list[dict[str, str]] = []
        for permission in permissions or []:
            role_id = getattr(permission, "roleId", None)
            role_name = role_names.get(int(role_id), "") if role_id is not None else ""
            if not bool(getattr(permission, "propagate", False)):
                continue
            if role_id != -1 and role_name.lower() not in {"admin", "administrator", "administrators"}:
                continue
            entity = getattr(permission, "entity", None)
            entity_name = getattr(entity, "name", None) or getattr(entity, "_moId", "") or "root"
            principal = str(getattr(permission, "principal", "") or "")
            if not principal:
                continue
            issues.append({"principal": principal, "role": role_name or "Administrator", "entity": str(entity_name)})
        return issues

    def _task_backlog_items(self, content: Any) -> list[dict[str, str]] | None:
        task_manager = getattr(content, "taskManager", None)
        if task_manager is None:
            return None
        try:
            tasks = getattr(task_manager, "recentTask", None)
        except Exception:  # noqa: BLE001 - recent task inventory may be unavailable
            return None
        if tasks is None:
            return None
        backlog: list[dict[str, str]] = []
        for task in tasks or []:
            info = getattr(task, "info", None)
            state = str(getattr(info, "state", "") or "")
            if state not in {"queued", "running"}:
                continue
            entity = getattr(info, "entityName", None)
            backlog.append(
                {
                    "name": str(getattr(getattr(info, "description", None), "message", "") or getattr(info, "name", "") or "task"),
                    "state": state,
                    "entity": str(entity or ""),
                }
            )
        return backlog


class _PerformanceSampler:
    METRIC_COUNTERS = {
        "cluster_cpu_usage_avg": ["cpu.usage.average"],
        "cpu_usage_avg": ["cpu.usage.average"],
        "memory_usage_avg": ["mem.usage.average"],
        "latency_avg_ms": ["datastore.totalReadLatency.average", "datastore.totalWriteLatency.average"],
        "cpu_ready_percent": ["cpu.ready.summation"],
        "swap_or_balloon_mb": ["mem.swapped.average", "mem.vmmemctl.average"],
        "pnic_error_count": [
            "net.errorsRx.summation",
            "net.errorsTx.summation",
            "net.droppedRx.summation",
            "net.droppedTx.summation",
        ],
    }

    def __init__(self, content: Any, plan: CollectionPlan) -> None:
        self.perf_manager = getattr(content, "perfManager", None)
        self.plan = plan
        self.counter_ids = self._build_counter_ids()

    def metric(self, entity: Any, canonical_metric: str) -> float | None:
        if self.perf_manager is None:
            return None
        counter_names = self.METRIC_COUNTERS.get(canonical_metric, [])
        counter_ids = [self.counter_ids[name] for name in counter_names if name in self.counter_ids]
        if not counter_ids:
            return None
        window_minutes, minimum_samples = self._sampling(canonical_metric)
        values = self._query(entity, counter_ids, window_minutes)
        if len(values) < minimum_samples:
            return None
        if canonical_metric == "cpu_ready_percent":
            normalized = [self._cpu_ready_percent(value, interval) for value, interval, _ in values]
            return self._round_or_none(normalized)
        if canonical_metric == "swap_or_balloon_mb":
            return self._swap_or_balloon_mb(values)
        if canonical_metric == "pnic_error_count":
            return self._pnic_error_count(values)
        normalized = [self._normalize_percent(value) if self._is_percent_metric(name) else float(value) for value, _, name in values]
        return self._round_or_none(normalized)

    def metric_detail(self, entity: Any, canonical_metric: str) -> list[dict[str, Any]]:
        if self.perf_manager is None or canonical_metric != "pnic_error_count":
            return []
        counter_names = self.METRIC_COUNTERS.get(canonical_metric, [])
        counter_ids = [self.counter_ids[name] for name in counter_names if name in self.counter_ids]
        if not counter_ids:
            return []
        window_minutes, minimum_samples = self._sampling(canonical_metric)
        values = self._query(entity, counter_ids, window_minutes)
        if len(values) < minimum_samples:
            return []
        by_counter: dict[str, float] = {}
        for value, _, counter_name in values:
            by_counter[counter_name] = by_counter.get(counter_name, 0.0) + max(0.0, float(value))
        return [
            {"counter": counter_name, "value": int(total) if float(total).is_integer() else round(total, 2)}
            for counter_name, total in sorted(by_counter.items())
            if total > 0
        ]

    def _build_counter_ids(self) -> dict[str, int]:
        if self.perf_manager is None:
            return {}
        counters = {}
        try:
            perf_counters = self.perf_manager.perfCounter
        except Exception:  # noqa: BLE001 - unavailable performance manager
            return {}
        for counter in perf_counters:
            group = getattr(getattr(counter, "groupInfo", None), "key", None)
            name = getattr(getattr(counter, "nameInfo", None), "key", None)
            rollup = getattr(counter, "rollupType", None)
            key = getattr(counter, "key", None)
            if group and name and rollup and key is not None:
                counters[f"{group}.{name}.{rollup}"] = key
        return counters

    def _sampling(self, canonical_metric: str) -> tuple[int, int]:
        for request in self.plan.performance_metrics:
            if request.metric == canonical_metric:
                return request.window_minutes, request.minimum_samples
        return 60, 3

    def _query(self, entity: Any, counter_ids: list[int], window_minutes: int) -> list[tuple[float, int, str]]:
        from pyVmomi import vim

        end = datetime.now(UTC)
        start = end - timedelta(minutes=window_minutes)
        metrics = [vim.PerformanceManager.MetricId(counterId=counter_id, instance="") for counter_id in counter_ids]
        results = self._query_once(entity, metrics, start, end)
        if not results:
            metrics = [vim.PerformanceManager.MetricId(counterId=counter_id, instance="*") for counter_id in counter_ids]
            results = self._query_once(entity, metrics, start, end)
        return results

    def _query_once(self, entity: Any, metrics: list[Any], start: datetime, end: datetime) -> list[tuple[float, int, str]]:
        from pyVmomi import vim

        spec = vim.PerformanceManager.QuerySpec(entity=entity, metricId=metrics, startTime=start, endTime=end, intervalId=300)
        try:
            entity_metrics = self.perf_manager.QueryPerf(querySpec=[spec])
        except Exception:  # noqa: BLE001 - unavailable metric should become data_quality missing
            return []
        values: list[tuple[float, int, str]] = []
        reverse_counter_ids = {value: key for key, value in self.counter_ids.items()}
        for entity_metric in entity_metrics or []:
            sample_info = getattr(entity_metric, "sampleInfo", []) or []
            intervals = [int(getattr(sample, "interval", 300) or 300) for sample in sample_info]
            for series in getattr(entity_metric, "value", []) or []:
                series_values = list(getattr(series, "value", []) or [])
                counter_id = getattr(getattr(series, "id", None), "counterId", None)
                counter_name = reverse_counter_ids.get(counter_id, "")
                for index, raw_value in enumerate(series_values):
                    interval = intervals[index] if index < len(intervals) else 300
                    values.append((float(raw_value), interval, counter_name))
        return values

    def _is_percent_metric(self, counter_name: str) -> bool:
        return counter_name in {"cpu.usage.average", "mem.usage.average"}

    def _normalize_percent(self, value: float) -> float:
        return value / 100 if value > 100 else value

    def _cpu_ready_percent(self, summation_ms: float, interval_seconds: int) -> float:
        if interval_seconds <= 0:
            return 0
        return (summation_ms / (interval_seconds * 1000)) * 100

    def _normalize_kb_to_mb(self, value: float) -> float:
        return value / 1024

    def _swap_or_balloon_mb(self, values: list[tuple[float, int, str]]) -> float | None:
        by_counter: dict[str, list[float]] = {}
        for value, _, counter_name in values:
            by_counter.setdefault(counter_name, []).append(self._normalize_kb_to_mb(value))
        counter_averages = [sum(counter_values) / len(counter_values) for counter_values in by_counter.values() if counter_values]
        if not counter_averages:
            return None
        return round(sum(counter_averages), 2)

    def _pnic_error_count(self, values: list[tuple[float, int, str]]) -> float | None:
        if not values:
            return None
        total = sum(max(0.0, float(value)) for value, _, _ in values)
        return int(total) if float(total).is_integer() else round(total, 2)

    def _round_or_none(self, values: list[float]) -> float | None:
        if not values:
            return None
        result = sum(values) / len(values)
        return round(result, 2)
