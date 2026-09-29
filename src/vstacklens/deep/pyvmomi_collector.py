from __future__ import annotations

import hashlib
import ctypes
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
from collections import Counter
from datetime import UTC, datetime, timedelta
from math import isfinite
from pathlib import Path
from typing import Any, Callable

from vstacklens.deep.contracts import (
    Capability,
    CapabilityMatrix,
    CapabilityStatus,
    DatasetManifest,
    DatasetRecord,
    DeepDataset,
    DeepEntity,
    DeepSource,
    DeepWindow,
    now_utc_iso,
)
from vstacklens.deep.connection import EsxiHostConnectionInfo
from vstacklens.deep.interfaces import DeepCollectionPolicy, StandardInventorySnapshot
from vstacklens.deep.logs import LOG_CATEGORIES, MAX_LOG_FILE_BYTES, MAX_LOG_FILES, MAX_LOG_LINES_PER_FILE, MAX_LOG_LINES_PER_PAGE, MAX_LOG_LINE_CHARS, MAX_LOG_TOTAL_BYTES, VCENTER_LOG_CATEGORIES, classify_log_fault, correlate_log_records, event_object_references, log_category_for_descriptor, normalize_powercli_logs, parse_log_line_timestamp, unavailable_log_payloads
from vstacklens.deep.policies import default_threshold_registry
from vstacklens.deep.resource_monitor import LatchedResourceGuard, LocalResourceMonitor
from vstacklens.deep.vcenter_rest import VCenterRestReadClient
from vstacklens.deep.hardware_compatibility import esxi_version_to_hcl_release, load_bundled_vcg_index

TASK_REPEAT_THRESHOLD = 3
RESOURCE_GUARD_STATUSES = {"cancelled", "budget_exceeded", "memory_limit_exceeded", "cpu_limit_exceeded"}
MAX_DVS_NETWORK_PROFILES = 256
MAX_RESOURCE_POOLS_PER_CLUSTER = 512
MAX_RESOURCE_POOLS_PER_SESSION = 4096
MAX_RESOURCE_POOL_EVIDENCE = 32
MAX_STORAGE_POLICY_VM_REQUESTS = 256
MAX_STORAGE_POLICY_COMPONENTS = 64
MAX_STORAGE_POLICY_FAILURE_CODES = 8
MAX_DATASTORE_ACCESS_RECORDS = 512
MAX_DATASTORE_MOUNTS_PER_DATASTORE = 64
MAX_DATASTORE_ACCESS_EVIDENCE = 32
MAX_HCL_COMPATIBILITY_DEVICES = 512
HCL_COMPATIBILITY_RISK_STATUSES = {
    "SERVER_NOT_CERTIFIED",
    "NOT_CERTIFIED",
    "DRIVER_NOT_CERTIFIED",
    "DRIVER_VERSION_MISMATCH",
    "DRIVER_VERSION_BELOW_MINIMUM",
    "FIRMWARE_MISMATCH",
}
HCL_COMPATIBILITY_COMPLETE_STATUSES = {"SERVER_CERTIFIED", "CERTIFIED", "CERTIFIED_NO_FIRMWARE_REQUIREMENT", "DRIVER_VERSION_NOT_LATEST"}
STORAGE_POLICY_COMPLIANCE_API = "vcenter_rest.GET /api/vcenter/vm/{vm}/storage/policy/compliance"


def _session_impact_degraded(collection_log: list[dict[str, Any]], event_meta: dict[str, Any], resource_log: dict[str, Any]) -> bool:
    """Mark only session-wide interruption as global degradation.

    A partial source such as DiagnosticManager logs remains scoped to that
    capability; it must not suppress PASS results for unrelated complete data.
    """
    if bool(event_meta.get("degraded")) or bool(resource_log.get("budget_exceeded")):
        return True
    for item in collection_log:
        status = str(item.get("status") or "")
        reason = str(item.get("reason") or "")
        if status in RESOURCE_GUARD_STATUSES or reason in RESOURCE_GUARD_STATUSES or status.startswith("skipped_"):
            return True
    return False


class PyVmomiDeepCollector:
    """Read-only vCenter collector for the Deep Dataset Core path.

    This collector intentionally avoids support bundles, health tests, vmkping,
    configuration changes, and performance-service changes. Historical queries
    are bounded by the collection policy and event records are capped.
    """

    def __init__(self, host: str, username: str, password: str, port: int = 443, ssl_verify: bool = False, cancel_requested: Any = None, host_log_credentials: list[EsxiHostConnectionInfo] | None = None) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.ssl_verify = ssl_verify
        self._event_query_meta: dict[str, Any] = {}
        self._event_rule_ids_by_identity: dict[int, set[str]] = {}
        self.cancel_requested = cancel_requested or (lambda: False)
        self.host_log_credentials = list(host_log_credentials or [])

    def collect(self, snapshot: StandardInventorySnapshot | None = None, policy: DeepCollectionPolicy | None = None) -> DeepDataset:
        policy = policy or DeepCollectionPolicy()
        resource_started = time.perf_counter()
        self._collection_started_at = resource_started
        resource_before = self._resource_snapshot()
        dataset_id = f"ds-real-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
        created_at = now_utc_iso()
        try:
            from pyVim.connect import Disconnect, SmartConnect
            from pyVmomi import vim
        except ImportError as exc:
            raise RuntimeError("pyVmomi is not installed; real Deep collection cannot start") from exc

        ssl_context = None if self.ssl_verify else ssl._create_unverified_context()  # noqa: SLF001
        resource_monitor = LocalResourceMonitor(lambda: self._resource_snapshot(include_network=False), interval_seconds=0.5)
        resource_monitor.start()
        connection_started = now_utc_iso()
        try:
            service_instance = SmartConnect(
                host=self.host,
                user=self.username,
                pwd=self.password,
                port=self.port,
                sslContext=ssl_context,
                httpConnectionTimeout=30,
            )
        except Exception as exc:  # noqa: BLE001 - preserve an explicit local failure Dataset without exposing exception text.
            return self._connection_failure_dataset(
                dataset_id, created_at, policy, resource_before, resource_started, resource_monitor, exc,
                failure_action="connection", failure_started=connection_started,
            )
        connection_finished = now_utc_iso()
        resource_guard = LatchedResourceGuard(
            lambda: self._resource_guard_status(
                time.perf_counter() - resource_started,
                resource_monitor.latest_sample(),
                policy,
                cancelled=self.cancel_requested(),
            )
        )

        records: list[DatasetRecord] = []
        collection_log: list[dict[str, Any]] = [{"action": "connection", "status": "ok", "source": "pyVim.connect.SmartConnect", "started_at": connection_started, "finished_at": connection_finished}]

        def collect_records_phase(action: str, producer: Callable[[], list[DatasetRecord]]) -> list[DatasetRecord]:
            stop_reason = resource_guard()
            if stop_reason:
                collection_log.append({"action": action, "status": "not_requested", "reason": stop_reason, "record_count": 0})
                return []
            phase_records = producer()
            stop_reason = resource_guard()
            collection_log.append({"action": action, "status": "partial" if stop_reason else "ok", "reason": stop_reason, "record_count": len(phase_records)})
            return phase_records

        try:
            try:
                content = service_instance.RetrieveContent()
            except Exception as exc:  # noqa: BLE001 - retrieval failure is a connection-level unavailable result.
                return self._connection_failure_dataset(
                    dataset_id, created_at, policy, resource_before, resource_started, resource_monitor, exc,
                    failure_action="session.content", failure_started=connection_finished,
                    collection_log=collection_log,
                )
            about = getattr(content, "about", None)
            target_info = {
                "vcenter_ref": self.host,
                "api_version": str(getattr(about, "apiVersion", "") or "pyvmomi"),
                "vcenter_version": str(getattr(about, "version", "") or ""),
                "vcenter_build": str(getattr(about, "build", "") or ""),
            }
            hosts = self._view(content, vim.HostSystem)
            vms = self._view(content, vim.VirtualMachine)
            clusters = self._view(content, vim.ClusterComputeResource)
            datastores = self._view(content, vim.Datastore)
            scope = {"hosts": len(hosts), "vms": len(vms), "clusters": len(clusters), "datastores": len(datastores)}
            collection_log.append({"action": "inventory.view", "status": "ok", "counts": scope})

            records.extend(collect_records_phase("lifecycle.certificate", lambda: self._certificate_records(hosts, dataset_id, created_at, resource_guard=resource_guard)))
            records.extend(collect_records_phase("vm.snapshot", lambda: self._snapshot_records(vms, dataset_id, created_at)))
            records.extend(collect_records_phase("cluster.drift", lambda: self._cluster_drift_records(clusters, dataset_id, created_at, resource_guard=resource_guard)))
            records.extend(collect_records_phase("vm.hidden_risk", lambda: self._vm_hidden_risk_records(vms, dataset_id, created_at)))
            guest_os_support_records = collect_records_phase(
                "vm.guest_os_support",
                lambda: self._guest_os_support_records(hosts, vms, dataset_id, created_at, resource_guard=resource_guard, clusters=clusters),
            )
            records.extend(guest_os_support_records)
            guest_os_support_log = next((item for item in reversed(collection_log) if item.get("action") == "vm.guest_os_support"), {})
            guest_os_support_log.update(self._guest_os_support_summary(guest_os_support_records, len(vms)))
            records.extend(collect_records_phase("cluster.hidden_risk", lambda: self._cluster_hidden_risk_records(clusters, dataset_id, created_at)))
            records.extend(collect_records_phase("storage.hidden_risk", lambda: self._storage_hidden_risk_records(hosts, datastores, dataset_id, created_at)))
            records.extend(collect_records_phase("storage.datastore_access", lambda: self._datastore_access_records(datastores, dataset_id, created_at, resource_guard=resource_guard)))
            storage_policy_records = collect_records_phase(
                "storage.policy.compliance",
                lambda: self._storage_policy_compliance_records(vms, dataset_id, created_at, resource_guard=resource_guard),
            )
            records.extend(storage_policy_records)
            storage_policy_summary = next((item for item in storage_policy_records if item.metadata.get("storage_policy_summary")), None)
            storage_policy_log = next((item for item in reversed(collection_log) if item.get("action") == "storage.policy.compliance"), None)
            if storage_policy_summary and storage_policy_log:
                details = storage_policy_summary.value if isinstance(storage_policy_summary.value, dict) else {}
                storage_policy_log.update(
                    {
                        "status": details.get("collection_status", storage_policy_log.get("status")),
                        "api": STORAGE_POLICY_COMPLIANCE_API,
                        "vm_count": len(vms),
                        "requested_vm_count": details.get("requested_vm_count", 0),
                        "collected_vm_count": details.get("collected_vm_count", 0),
                        "failed_vm_count": details.get("failed_vm_count", 0),
                        "not_requested_vm_count": details.get("not_requested_vm_count", 0),
                        "compliance_status_counts": details.get("compliance_status_counts", {}),
                    }
                )
            records.extend(collect_records_phase("network.hidden_risk", lambda: self._network_hidden_risk_records(hosts, dataset_id, created_at, clusters=clusters, content=content, resource_guard=resource_guard)))
            records.extend(collect_records_phase("storage.thin_provision", lambda: self._thin_provision_records(vms, datastores, dataset_id, created_at)))
            records.extend(collect_records_phase("capacity.trend", lambda: self._capacity_trend_records(vms, datastores, dataset_id, created_at)))
            records.extend(collect_records_phase("lifecycle.inventory", lambda: self._lifecycle_records(content, hosts, clusters, dataset_id, created_at)))
            hardware_records = collect_records_phase("hardware.sensors", lambda: self._hardware_sensor_records(hosts, dataset_id, created_at))
            hardware_component_records = collect_records_phase("hardware.components", lambda: self._hardware_component_records(hosts, dataset_id, created_at))
            hardware_compatibility_records = collect_records_phase(
                "hardware.compatibility",
                lambda: self._hardware_compatibility_records(hosts, hardware_component_records, dataset_id, created_at, resource_guard=resource_guard),
            )
            self._update_hardware_compatibility_log(collection_log, hardware_compatibility_records)
            records.extend(hardware_compatibility_records)
            records.extend(hardware_component_records)
            records.extend(hardware_records)
            vsan_management_guard = resource_guard()
            if vsan_management_guard:
                vsan_inventory = {"status": "not_requested", "collection_error": vsan_management_guard, "clusters": {}}
            else:
                vsan_inventory = self._collect_vsan_management_inventory(service_instance, clusters, vms)
            records.extend(self._vsan_records(clusters, datastores, dataset_id, created_at, vsan_inventory))
            vsan_performance_guard = resource_guard()
            if vsan_performance_guard:
                vsan_performance = {"status": "not_requested", "reason": vsan_performance_guard, "supported_metrics": [], "sample_counts": {}}
            else:
                vsan_performance = self._collect_vsan_performance(service_instance, clusters, resource_guard=resource_guard)
            vsan_inventory["performance"] = vsan_performance
            records.extend(self._vsan_performance_records(clusters, dataset_id, created_at, vsan_performance))
            collection_log.append(
                {
                    "action": "vsan.performance",
                    "status": str(vsan_performance.get("status") or "unavailable"),
                    "reason": vsan_performance.get("reason"),
                    "supported_metrics": vsan_performance.get("supported_metrics") or [],
                    "sample_counts": vsan_performance.get("sample_counts") or {},
                }
            )
            collection_log.append(
                {
                    "action": "vsan.management",
                    "status": str(vsan_inventory.get("status") or "not_collected"),
                    "reason": vsan_inventory.get("collection_error"),
                    "cluster_count": len(vsan_inventory.get("clusters") or {}),
                }
            )

            events = self._bounded_events(content, policy, should_stop=resource_guard)
            records.extend(self._history_records(events, hosts, clusters, datastores, dataset_id, created_at, self._event_query_meta, vms=vms, correlation_window_seconds=policy.correlation_window_seconds))
            log_guard = resource_guard()
            if log_guard:
                skipped_source = "DeepCollectionPolicy.resource_guard"
                log_records = normalize_powercli_logs(dataset_id=dataset_id, entity=self._environment_entity(), collected_at=created_at, payloads=[{"key": category, "status": log_guard, "reason": log_guard, "lines": [], "source": skipped_source} for category in VCENTER_LOG_CATEGORIES])
                log_records.extend(record for host in hosts for record in normalize_powercli_logs(dataset_id=dataset_id, entity=self._entity(host, "HostSystem"), collected_at=created_at, payloads=[{"key": category, "status": log_guard, "reason": log_guard, "lines": [], "source": skipped_source} for category in LOG_CATEGORIES]))
                log_state = "skipped_cancelled" if log_guard == "cancelled" else "skipped_budget" if log_guard == "budget_exceeded" else "skipped_resource_limit"
                log_collection = {"action": "logs.history", "status": log_state, "source": skipped_source, "requested_log_days": policy.log_collection_days, "time_window_status": "not_attempted_resource_guard" if policy.log_collection_days is not None else "not_limited", "category_count": len(log_records), "successful_count": 0, "categories": [*LOG_CATEGORIES, *VCENTER_LOG_CATEGORIES], "attempts": [{"source": "resource_guard", "status": log_guard, "rss_bytes": resource_monitor.latest_sample().get("rss_bytes"), "memory_limit_mb": policy.resource_memory_limit_mb, "cpu_percent_of_one_core": resource_monitor.latest_sample().get("cpu_percent_of_one_core"), "cpu_limit_percent": policy.resource_cpu_limit_percent}, {"source": "vim.DiagnosticManager.BrowseDiagnosticLog", "status": "not_attempted", "reason": log_guard}, {"source": "PowerCLI.Get-Log", "status": "not_attempted", "reason": log_guard}, {"source": "vim.DiagnosticManager.DirectESXi", "status": "not_attempted", "reason": log_guard}], "file_read_attempt_count": 0, "max_log_files": policy.max_log_files, "retained_log_bytes": 0, "retained_primary_log_bytes": 0, "retained_fallback_log_bytes": 0, "source_log_bytes_read": 0, "max_log_file_bytes": policy.max_log_file_bytes, "max_log_total_bytes": policy.max_log_total_bytes, "max_log_primary_bytes": policy.max_log_primary_bytes, "max_log_fallback_bytes": policy.max_log_fallback_bytes, "truncated_count": 0, "budget_limited_count": 0}
            else:
                log_records, log_collection = self._collect_historical_logs(content, hosts, dataset_id, created_at, policy, events, resource_guard=resource_guard)
            records.extend(log_records)
            task_guard = resource_guard()
            task_records = [] if task_guard else self._task_history_records(content, dataset_id, created_at)
            records.extend(task_records)
            collection_log.append({"action": "event.history", "status": "degraded" if self._event_query_meta.get("degraded") else "ok", "record_count": len(events), "requested_days": policy.event_history_days, **self._event_query_meta})
            collection_log.append({"action": "task.history", "status": "not_requested" if task_guard else "ok" if task_records else "limited", "reason": task_guard, "record_count": len(task_records), "source": "TaskManager.recentTask"})
            collection_log.append(log_collection)

            capabilities = self._probe_capabilities(
                content,
                hosts,
                datastores[:1],
                events,
                self._event_query_meta,
                vsan_inventory,
                hardware_records + hardware_component_records,
                log_records,
                task_history_status="not_requested" if task_guard else None,
                resource_guard=resource_guard,
            )
            storage_policy_log = next((item for item in reversed(collection_log) if item.get("action") == "storage.policy.compliance"), {})
            capabilities.capabilities.append(self._storage_policy_capability(storage_policy_records, len(vms), storage_policy_log))
            capabilities.capabilities.append(self._guest_os_support_capability(guest_os_support_records, len(vms), guest_os_support_log))
            hardware_compatibility_log = next((item for item in reversed(collection_log) if item.get("action") == "hardware.compatibility"), {})
            capabilities.capabilities.append(self._hardware_compatibility_capability(hardware_compatibility_records, len(hosts), hardware_compatibility_log))
            capability_guard = next((item for item in capabilities.capabilities if item.detected_via == "resource_guard" and item.status == CapabilityStatus.NOT_REQUESTED), None)
            if capability_guard:
                collection_log.append({"action": "capability.probe", "status": "not_requested", "reason": (capability_guard.detail or {}).get("reason")})
            perf_guard = resource_guard()
            perf_records = [] if perf_guard else self._collect_daily_perf(content, datastores[:1], dataset_id, created_at, policy, resource_guard=resource_guard)
            perf_guard = perf_guard or resource_guard()
            records.extend(perf_records)
            collection_log.append({"action": "performance.daily", "status": "skipped_resource_guard" if perf_guard else "ok", "reason": perf_guard, "record_count": len(perf_records)})
            perf_guard = resource_guard()
            if perf_guard:
                enhanced_records = []
                enhanced_capabilities = [Capability(id=cap_id, name=label, status=CapabilityStatus.NOT_REQUESTED, profile="enhanced", detected_via="resource_guard", detail={"reason": perf_guard, "rss_bytes": resource_monitor.latest_sample().get("rss_bytes"), "memory_limit_mb": policy.resource_memory_limit_mb, "cpu_percent_of_one_core": resource_monitor.latest_sample().get("cpu_percent_of_one_core"), "cpu_limit_percent": policy.resource_cpu_limit_percent}) for cap_id, label in (("enhanced.perf.cpu", "CPU Enhanced"), ("enhanced.perf.memory", "Memory Enhanced"), ("enhanced.perf.storage", "Storage Enhanced"), ("enhanced.perf.network", "Network Enhanced"))]
                collection_log.append({"action": "performance.enhanced", "status": "skipped_resource_guard", "reason": perf_guard})
            else:
                enhanced_records, enhanced_capabilities = self._collect_enhanced_perf_records(
                    content,
                    hosts[: policy.max_entities],
                    datastores[: policy.max_entities],
                    dataset_id,
                    created_at,
                    policy,
                    resource_guard=resource_guard,
                )
                unrequested_capability = next((item for item in enhanced_capabilities if item.status == CapabilityStatus.NOT_REQUESTED and item.detected_via in {"resource_guard", "cancel_requested"}), None)
                collection_log.append({"action": "performance.enhanced", "status": "not_requested" if unrequested_capability else "ok", "reason": (unrequested_capability.detail or {}).get("reason") if unrequested_capability else None, "record_count": len(enhanced_records)})
            records.extend(enhanced_records)
            capabilities.capabilities.extend(enhanced_capabilities)
            host_object_aliases = {
                str(getattr(host, "_moId")): self._entity(host, "HostSystem").stable_id
                for host in hosts
                if getattr(host, "_moId", None)
            }
            correlate_log_records(log_records, events, [*task_records, *perf_records, *enhanced_records], window_seconds=policy.correlation_window_seconds, object_id_aliases=host_object_aliases, event_rule_ids=self._event_rule_ids_by_identity)
            peak_resource = resource_monitor.stop()
            resource_log = self._resource_collection_log(resource_before, self._resource_snapshot(), time.perf_counter() - resource_started, policy, peak=peak_resource)
            collection_log.append(resource_log)
            degraded_actions = sum(1 for item in collection_log if item.get("status") in {"degraded", "partial", "not_requested", "skipped_budget", "skipped_resource_limit", "skipped_cancelled"} or str(item.get("status") or "").startswith("skipped_"))
            session_degraded = _session_impact_degraded(collection_log, self._event_query_meta, resource_log)
            if snapshot is not None:
                collection_log.append({"action": "standard.snapshot", "status": "consumed", "snapshot_id": snapshot.snapshot_id})
            manifest = DatasetManifest(
                dataset_id=dataset_id,
                created_at_utc=created_at,
                collector_version="vstacklens-deep/1.0.0-pyvmomi",
                mode="real_read_only",
                target=target_info,
                scope=scope,
                time_windows={"logs": {"requested_days": policy.log_collection_days}, "event": {"requested_days": policy.event_history_days}, "perf": {"requested_days": policy.history_days}},
                anonymization={"enabled": False, "profile": "local_only", "map_location": "not_exported"},
                impact={"profile": policy.impact_level, "budget_seconds": policy.budget_seconds, "degraded": session_degraded},
                collection_status={"planned": len(records), "ok": len(records), "degraded": degraded_actions, "failed": 0},
            )
            return DeepDataset(
                manifest=manifest,
                capability=capabilities,
                records=records,
                collection_log=collection_log,
            )
        finally:
            try:
                resource_monitor.stop()
            finally:
                Disconnect(service_instance)

    def _connection_failure_dataset(
        self,
        dataset_id: str,
        created_at: str,
        policy: DeepCollectionPolicy,
        resource_before: dict[str, Any],
        resource_started: float,
        resource_monitor: LocalResourceMonitor,
        error: Exception,
        *,
        failure_action: str,
        failure_started: str,
        collection_log: list[dict[str, Any]] | None = None,
    ) -> DeepDataset:
        error_name = type(error).__name__
        lowered_name = error_name.casefold()
        failure_status = classify_log_fault(error)
        if failure_status == "error":
            failure_status = "authentication_failed" if any(token in lowered_name for token in ("invalidlogin", "authentication")) else "connection_error"
        finished = now_utc_iso()
        entity = self._environment_entity()
        log_records = normalize_powercli_logs(
            dataset_id=dataset_id,
            entity=entity,
            collected_at=created_at,
            payloads=[{
                "key": "vpxd",
                "status": failure_status,
                "reason": failure_status,
                "lines": [],
                "source": "vCenter.SmartConnect" if failure_action == "connection" else "vCenter.RetrieveContent",
                "started_at": failure_started,
                "finished_at": finished,
            }],
        )
        category_results = [
            {"category": category, "scope": "vcenter", "status": failure_status, "reason": failure_status}
            for category in VCENTER_LOG_CATEGORIES
        ]
        category_results.extend(
            {"category": category, "scope": "esxi_hosts", "status": "not_requested", "reason": "host_inventory_unavailable"}
            for category in LOG_CATEGORIES
        )
        log_collection = {
            "action": "logs.history",
            "status": "unavailable",
            "source": "vCenter connection",
            "requested_log_days": policy.log_collection_days,
            "time_window_status": "not_attempted_connection_unavailable" if policy.log_collection_days is not None else "not_limited",
            "category_count": len(category_results),
            "source_record_count": len(log_records),
            "successful_count": 0,
            "categories": [*LOG_CATEGORIES, *VCENTER_LOG_CATEGORIES],
            "category_results": category_results,
            "attempts": [
                {"source": "vim.DiagnosticManager.QueryDescriptions/BrowseDiagnosticLog", "scope": "vcenter", "status": "not_attempted", "reason": failure_status},
                {"source": "PowerCLI.Get-Log", "scope": "vcenter+esxi_hosts", "status": "not_attempted", "reason": failure_status},
                {"source": "vim.DiagnosticManager.DirectESXi", "scope": "esxi_hosts", "status": "not_attempted", "reason": failure_status},
            ],
            "file_read_attempt_count": 0,
            "max_log_files": policy.max_log_files,
            "retained_log_bytes": 0,
            "source_log_bytes_read": 0,
            "max_log_file_bytes": policy.max_log_file_bytes,
            "max_log_total_bytes": policy.max_log_total_bytes,
            "max_log_primary_bytes": policy.max_log_primary_bytes,
            "max_log_fallback_bytes": policy.max_log_fallback_bytes,
            "truncated_count": 0,
            "budget_limited_count": 0,
        }
        prior_log = list(collection_log or [])
        prior_log.append({"action": failure_action, "status": failure_status, "source": "pyVim.connect.SmartConnect" if failure_action == "connection" else "ServiceInstance.RetrieveContent", "started_at": failure_started, "finished_at": finished, "error_type": error_name})
        prior_log.extend([
            {"action": "inventory.view", "status": "not_requested", "reason": "vcenter_connection_unavailable", "counts": {"hosts": 0, "vms": 0, "clusters": 0, "datastores": 0}},
            {"action": "event.history", "status": "not_requested", "reason": "vcenter_connection_unavailable", "record_count": 0},
            {"action": "task.history", "status": "not_requested", "reason": "vcenter_connection_unavailable", "record_count": 0, "source": "TaskManager.recentTask"},
            log_collection,
        ])
        resource_peak = resource_monitor.stop()
        prior_log.append(self._resource_collection_log(resource_before, self._resource_snapshot(), time.perf_counter() - resource_started, policy, peak=resource_peak))
        reason_detail = {"reason": failure_status, "error_type": error_name}
        capabilities = [
            Capability(id="inventory.current", name="当前清单与配置", status=CapabilityStatus.UNAVAILABLE, profile="core", detected_via="vCenter connection", detail=reason_detail),
            Capability(id="events.history", name="事件历史", status=CapabilityStatus.UNAVAILABLE, profile="core", detected_via="vCenter connection", detail=reason_detail),
            Capability(id="tasks.history", name="任务历史", status=CapabilityStatus.UNAVAILABLE, profile="core", detected_via="vCenter connection", detail={**reason_detail, "historical_window": "recentTask retention"}),
            Capability(id="alarms.current", name="告警状态", status=CapabilityStatus.UNAVAILABLE, profile="core", detected_via="vCenter connection", detail=reason_detail),
            Capability(id="environment.vsphere.version", name="vSphere 环境版本", status=CapabilityStatus.UNAVAILABLE, profile="core", detected_via="vCenter connection", detail=reason_detail),
            Capability(id="lifecycle.license", name="许可证状态", status=CapabilityStatus.UNAVAILABLE, profile="core", detected_via="vCenter connection", detail=reason_detail),
            Capability(id="perf.statslevel.historical", name="历史统计级别", status=CapabilityStatus.NOT_REQUESTED, profile="enhanced", detected_via="vCenter connection", detail=reason_detail),
            Capability(id="perf.query_available_metric", name="可用性能计数器探测", status=CapabilityStatus.NOT_REQUESTED, profile="enhanced", detected_via="vCenter connection", detail=reason_detail),
            *self._vsan_capabilities({"status": "not_requested", "collection_error": failure_status, "clusters": {}, "performance": {"status": "not_requested", "reason": failure_status}}),
            Capability(id="hardware.sensors", name="主机硬件 Sensor", status=CapabilityStatus.NOT_REQUESTED, profile="enhanced", detected_via="vCenter connection", detail=reason_detail),
            *[item.model_copy(update={"status": CapabilityStatus.NOT_REQUESTED, "detected_via": "vCenter connection", "detail": reason_detail}) for item in self._hardware_component_capabilities([])],
            self._log_capability(log_records),
        ]
        resource_action = prior_log[-1]
        degraded_actions = sum(1 for item in prior_log if item.get("status") in {"degraded", "partial", "not_requested", "skipped_budget", "skipped_resource_limit", "skipped_cancelled"} or str(item.get("status") or "").startswith("skipped_"))
        if resource_action.get("budget_exceeded"):
            degraded_actions += 1
        return DeepDataset(
            manifest=DatasetManifest(
                dataset_id=dataset_id,
                created_at_utc=created_at,
                collector_version="vstacklens-deep/1.0.0-pyvmomi",
                mode="real_read_only",
                target={"vcenter_ref": self.host, "api_version": "unavailable", "vcenter_version": "", "vcenter_build": ""},
                scope={"hosts": 0, "vms": 0, "clusters": 0, "datastores": 0},
                time_windows={"logs": {"requested_days": policy.log_collection_days}, "event": {"requested_days": policy.event_history_days}, "perf": {"requested_days": policy.history_days}},
                anonymization={"enabled": False, "profile": "local_only", "map_location": "not_exported"},
                impact={"profile": policy.impact_level, "budget_seconds": policy.budget_seconds, "degraded": True},
                collection_status={"planned": 2, "ok": 1, "degraded": max(1, degraded_actions), "failed": 1},
            ),
            capability=CapabilityMatrix(probed_at_utc=now_utc_iso(), capabilities=capabilities),
            records=log_records,
            collection_log=prior_log,
        )

    @staticmethod
    def _resource_snapshot(include_network: bool = True) -> dict[str, Any]:
        try:
            import psutil

            process = psutil.Process(os.getpid())
            io = process.io_counters()
            cpu = process.cpu_times()
            network = psutil.net_io_counters() if include_network else None
            return {"status": "ok", "cpu_user_sec": float(cpu.user), "cpu_system_sec": float(cpu.system), "rss_bytes": int(process.memory_info().rss), "read_bytes": int(io.read_bytes), "write_bytes": int(io.write_bytes), "network_sent_bytes": int(network.bytes_sent) if network else 0, "network_recv_bytes": int(network.bytes_recv) if network else 0}
        except Exception as exc:  # noqa: BLE001 - resource metrics are optional evidence.
            if os.name != "nt":
                return {"status": "unavailable", "reason": type(exc).__name__}
            try:
                from ctypes import wintypes

                class _FileTime(ctypes.Structure):
                    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]

                class _IoCounters(ctypes.Structure):
                    _fields_ = [("read_ops", ctypes.c_uint64), ("write_ops", ctypes.c_uint64), ("other_ops", ctypes.c_uint64), ("read_bytes", ctypes.c_uint64), ("write_bytes", ctypes.c_uint64), ("other_bytes", ctypes.c_uint64)]

                class _MemoryCounters(ctypes.Structure):
                    _fields_ = [("cb", ctypes.c_uint32), ("page_fault_count", ctypes.c_uint32), ("peak_working_set_size", ctypes.c_size_t), ("working_set_size", ctypes.c_size_t), ("quota_peak_paged_pool_usage", ctypes.c_size_t), ("quota_paged_pool_usage", ctypes.c_size_t), ("quota_peak_non_paged_pool_usage", ctypes.c_size_t), ("quota_non_paged_pool_usage", ctypes.c_size_t), ("pagefile_usage", ctypes.c_size_t), ("peak_pagefile_usage", ctypes.c_size_t), ("private_usage", ctypes.c_size_t)]

                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                psapi = ctypes.WinDLL("psapi", use_last_error=True)
                kernel32.GetCurrentProcess.restype = wintypes.HANDLE
                process_handle = kernel32.GetCurrentProcess()
                creation, exit_time, kernel, user = _FileTime(), _FileTime(), _FileTime(), _FileTime()
                kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE, ctypes.POINTER(_FileTime), ctypes.POINTER(_FileTime), ctypes.POINTER(_FileTime), ctypes.POINTER(_FileTime)]
                kernel32.GetProcessTimes.restype = wintypes.BOOL
                if not kernel32.GetProcessTimes(process_handle, ctypes.byref(creation), ctypes.byref(exit_time), ctypes.byref(kernel), ctypes.byref(user)):
                    raise OSError("GetProcessTimes")
                memory = _MemoryCounters()
                memory.cb = ctypes.sizeof(memory)
                psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(_MemoryCounters), wintypes.DWORD]
                psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
                if not psapi.GetProcessMemoryInfo(process_handle, ctypes.byref(memory), ctypes.sizeof(memory)):
                    raise OSError("GetProcessMemoryInfo")
                io = _IoCounters()
                kernel32.GetProcessIoCounters.argtypes = [wintypes.HANDLE, ctypes.POINTER(_IoCounters)]
                kernel32.GetProcessIoCounters.restype = wintypes.BOOL
                if not kernel32.GetProcessIoCounters(process_handle, ctypes.byref(io)):
                    raise OSError("GetProcessIoCounters")

                def _filetime(value: _FileTime) -> float:
                    return ((int(value.high) << 32) | int(value.low)) / 10_000_000.0

                network_sent, network_recv = PyVmomiDeepCollector._windows_network_bytes() if include_network else (0, 0)
                return {"status": "ok", "cpu_user_sec": _filetime(user), "cpu_system_sec": _filetime(kernel), "rss_bytes": int(memory.working_set_size), "read_bytes": int(io.read_bytes), "write_bytes": int(io.write_bytes), "network_sent_bytes": network_sent, "network_recv_bytes": network_recv, "source": "Windows native process APIs"}
            except Exception as native_exc:  # noqa: BLE001
                return {"status": "unavailable", "reason": f"{type(exc).__name__}+{type(native_exc).__name__}"}

    @staticmethod
    def _windows_network_bytes() -> tuple[int, int]:
        executable = shutil.which("pwsh") or shutil.which("powershell")
        if not executable:
            return 0, 0
        command = "$r=(Get-NetAdapterStatistics | Measure-Object -Property ReceivedBytes -Sum).Sum; $s=(Get-NetAdapterStatistics | Measure-Object -Property SentBytes -Sum).Sum; [pscustomobject]@{received=[int64]$r;sent=[int64]$s}|ConvertTo-Json -Compress"
        result = subprocess.run([executable, "-NoProfile", "-NonInteractive", "-Command", command], capture_output=True, text=True, timeout=10, check=False)
        if result.returncode != 0:
            return 0, 0
        payload = json.loads(result.stdout)
        return int(payload.get("sent") or 0), int(payload.get("received") or 0)

    @staticmethod
    def _resource_collection_log(before: dict[str, Any], after: dict[str, Any], elapsed_sec: float, policy: DeepCollectionPolicy, peak: dict[str, Any] | None = None) -> dict[str, Any]:
        if before.get("status") != "ok" or after.get("status") != "ok":
            return {"action": "resource.usage", "status": "unavailable", "elapsed_sec": round(elapsed_sec, 3), "budget_sec": policy.budget_seconds, "budget_exceeded": elapsed_sec > policy.budget_seconds, "peak": peak or {}, "before": before, "after": after}
        cpu_sec = (after["cpu_user_sec"] + after["cpu_system_sec"]) - (before["cpu_user_sec"] + before["cpu_system_sec"])
        return {"action": "resource.usage", "status": "ok", "elapsed_sec": round(elapsed_sec, 3), "budget_sec": policy.budget_seconds, "budget_exceeded": elapsed_sec > policy.budget_seconds, "cpu_sec": round(max(cpu_sec, 0.0), 3), "cpu_percent_of_one_core": round(max(cpu_sec, 0.0) / elapsed_sec * 100, 2) if elapsed_sec > 0 else 0.0, "rss_before_bytes": before["rss_bytes"], "rss_after_bytes": after["rss_bytes"], "rss_delta_bytes": after["rss_bytes"] - before["rss_bytes"], "disk_read_bytes": max(after["read_bytes"] - before["read_bytes"], 0), "disk_write_bytes": max(after["write_bytes"] - before["write_bytes"], 0), "network_sent_bytes": max(after["network_sent_bytes"] - before["network_sent_bytes"], 0), "network_recv_bytes": max(after["network_recv_bytes"] - before["network_recv_bytes"], 0), "network_scope": "system interface byte counters", "peak": peak or {}}

    @staticmethod
    def _resource_guard_status(elapsed_sec: float, sample: dict[str, Any], policy: DeepCollectionPolicy, *, cancelled: bool = False) -> str | None:
        if cancelled:
            return "cancelled"
        if elapsed_sec >= policy.budget_seconds:
            return "budget_exceeded"
        rss_bytes = sample.get("rss_bytes") if sample.get("status") == "ok" else None
        if rss_bytes is not None and int(rss_bytes) >= int(policy.resource_memory_limit_mb) * 1024 * 1024:
            return "memory_limit_exceeded"
        cpu_percent = sample.get("cpu_percent_of_machine") if sample.get("status") == "ok" else None
        if cpu_percent is not None and float(cpu_percent) >= float(policy.resource_cpu_limit_percent):
            return "cpu_limit_exceeded"
        return None

    def _probe_capabilities(
        self,
        content: Any,
        hosts: list[Any],
        datastores: list[Any],
        events: list[Any],
        event_meta: dict[str, Any] | None = None,
        vsan_inventory: dict[str, Any] | None = None,
        hardware_records: list[DatasetRecord] | None = None,
        log_records: list[DatasetRecord] | None = None,
        task_history_status: str | None = None,
        resource_guard: Callable[[], str | None] | None = None,
    ) -> CapabilityMatrix:
        task_manager = getattr(content, "taskManager", None)
        alarm_manager = getattr(content, "alarmManager", None)
        capabilities = [
            Capability(id="inventory.current", name="当前清单与配置", status=CapabilityStatus.AVAILABLE, profile="core", detected_via="RetrieveContent"),
            Capability(id="events.history", name="事件历史", status=CapabilityStatus.LIMITED if (event_meta or {}).get("degraded") else CapabilityStatus.AVAILABLE, profile="core", detected_via="EventHistoryCollector.ReadNext", detail={"sample_count": len(events), **(event_meta or {})}),
            Capability(id="tasks.history", name="任务历史", status=CapabilityStatus.NOT_REQUESTED if task_history_status == "not_requested" else CapabilityStatus.LIMITED if task_manager is not None else CapabilityStatus.UNAVAILABLE, profile="core", detected_via="content.taskManager.recentTask", detail={"recent_task_available": task_manager is not None, "historical_window": "recentTask retention", "collection_status": task_history_status or ("available" if task_manager is not None else "unavailable")}),
            Capability(id="alarms.current", name="告警状态", status=CapabilityStatus.AVAILABLE if alarm_manager is not None else CapabilityStatus.UNAVAILABLE, profile="core", detected_via="content.alarmManager", detail={"alarm_manager_available": alarm_manager is not None}),
        ]
        about = getattr(content, "about", None)
        capabilities.append(Capability(id="environment.vsphere.version", name="vSphere 环境版本", status=CapabilityStatus.AVAILABLE, profile="core", detected_via="content.about", detail={"version": str(getattr(about, "version", "") or ""), "build": str(getattr(about, "build", "") or ""), "api_version": str(getattr(about, "apiVersion", "") or "")}))
        license_manager = getattr(content, "licenseManager", None)
        license_status = CapabilityStatus.UNAVAILABLE
        license_detail: dict[str, Any] = {}
        if license_manager is not None:
            stop_reason = resource_guard() if resource_guard else None
            if stop_reason:
                license_status = CapabilityStatus.NOT_REQUESTED
                license_detail = {"reason": stop_reason}
            else:
                try:
                    license_detail = {"license_count": len(list(getattr(license_manager, "licenses", []) or []))}
                    license_status = CapabilityStatus.AVAILABLE
                except Exception as exc:  # noqa: BLE001 - permission is a capability result, not a session failure.
                    license_detail = {"error": type(exc).__name__}
        capabilities.append(Capability(id="lifecycle.license", name="许可证状态", status=license_status, profile="core", detected_via="LicenseManager.licenses", detail=license_detail))
        perf_manager = getattr(content, "perfManager", None)
        if perf_manager is None:
            capabilities.append(Capability(id="perf.statslevel.historical", name="历史统计级别", status=CapabilityStatus.UNAVAILABLE, profile="enhanced", detected_via="content.perfManager"))
        else:
            stop_reason = resource_guard() if resource_guard else None
            if stop_reason:
                capabilities.append(Capability(id="perf.statslevel.historical", name="历史统计级别", status=CapabilityStatus.NOT_REQUESTED, profile="enhanced", detected_via="resource_guard", detail={"reason": stop_reason}))
                capabilities.append(Capability(id="perf.query_available_metric", name="可用性能计数器探测", status=CapabilityStatus.NOT_REQUESTED, profile="enhanced", detected_via="resource_guard", detail={"reason": stop_reason, "representative_objects": []}))
            else:
                intervals = {}
                levels = {}
                for item in getattr(perf_manager, "historicalInterval", []) or []:
                    period = int(getattr(item, "samplingPeriod", 0) or 0)
                    intervals[str(period)] = {"length": getattr(item, "length", None), "level": getattr(item, "level", None)}
                    levels[str(period)] = int(getattr(item, "level", 0) or 0)
                level_status = CapabilityStatus.AVAILABLE if any(value >= 2 for value in levels.values()) else CapabilityStatus.LIMITED
                capabilities.append(Capability(id="perf.statslevel.historical", name="历史统计级别", status=level_status, profile="enhanced", detected_via="PerformanceManager.historicalInterval", detail={"intervals": intervals, "level_by_interval": levels}))
                metric_summary = self._available_metric_summary(perf_manager, hosts, datastores, resource_guard=resource_guard)
                metric_status = CapabilityStatus.NOT_REQUESTED if metric_summary.get("status") == "not_requested" else CapabilityStatus.AVAILABLE
                capabilities.append(Capability(id="perf.query_available_metric", name="可用性能计数器探测", status=metric_status, profile="enhanced", detected_via="resource_guard" if metric_status == CapabilityStatus.NOT_REQUESTED else "QueryAvailablePerfMetric", detail=metric_summary))
        capabilities.extend(self._vsan_capabilities(vsan_inventory or {}))
        capabilities.append(self._hardware_sensor_capability(hardware_records or []))
        capabilities.extend(self._hardware_component_capabilities(hardware_records or []))
        capabilities.append(self._log_capability(log_records or []))
        return CapabilityMatrix(probed_at_utc=now_utc_iso(), capabilities=capabilities)

    @staticmethod
    def _log_capability(records: list[DatasetRecord]) -> Capability:
        grouped: dict[tuple[str, str], list[DatasetRecord]] = {}
        source_records = [record for record in records if record.metadata.get("rule_id") == "LOG-DEEP-001"]
        missing_privileges: set[str] = set()
        for record in source_records:
            key = (record.entity.stable_id, str(record.metadata.get("log_category") or "unknown"))
            grouped.setdefault(key, []).append(record)
            privilege_id = str(record.metadata.get("missing_privilege_id") or "").strip()
            if privilege_id:
                missing_privileges.add(privilege_id)
        if not grouped:
            return Capability(id="logs.history", name="历史日志文件", status=CapabilityStatus.UNAVAILABLE, profile="core", detected_via="PowerCLI.Get-Log")
        complete_count = 0
        partial_count = 0
        category_results = []
        for key, group_records in sorted(grouped.items()):
            complete = any(str(record.metadata.get("log_status")) in {"ok", "empty"} and not record.metadata.get("truncated") for record in group_records)
            partial = any(str(record.metadata.get("log_status")) == "partial" or record.metadata.get("truncated") for record in group_records)
            if complete:
                complete_count += 1
                effective_status = "ok" if any(str(record.metadata.get("log_status")) == "ok" and not record.metadata.get("truncated") for record in group_records) else "empty"
            elif partial:
                partial_count += 1
                effective_status = "partial"
            else:
                effective_status = str(group_records[-1].metadata.get("log_status") or "error")
            category_results.append({
                "entity_id": key[0],
                "category": key[1],
                "source_statuses": [str(record.metadata.get("log_status") or "error") for record in group_records],
                "effective_status": effective_status,
                "truncated_source_count": sum(1 for record in group_records if record.metadata.get("truncated")),
            })
        requested_log_days = sorted({int(record.metadata["requested_log_days"]) for record in source_records if record.metadata.get("requested_log_days") is not None})
        window_limited = bool(requested_log_days)
        status = CapabilityStatus.LIMITED if window_limited else CapabilityStatus.AVAILABLE if complete_count == len(grouped) else CapabilityStatus.LIMITED if complete_count or partial_count else CapabilityStatus.UNAVAILABLE
        direct_available = any("DirectESXi" in record.source.collector or "DirectESXi" in record.source.api for record in source_records)
        detected_via = "vim.DiagnosticManager/PowerCLI.Get-Log/DirectESXi" if direct_available else "vim.DiagnosticManager/PowerCLI.Get-Log"
        return Capability(id="logs.history", name="历史日志文件", status=status, profile="core", detected_via=detected_via, detail={"category_count": len(grouped), "source_record_count": len(source_records), "successful_count": complete_count, "partially_successful_count": partial_count, "requested_log_days": requested_log_days[0] if len(requested_log_days) == 1 else requested_log_days or None, "window_limited": window_limited, "missing_privilege_ids": sorted(missing_privileges), "categories": category_results})

    def _hardware_sensor_capability(self, records: list[DatasetRecord]) -> Capability:
        records = [record for record in records if record.metadata.get("rule_id") == "HARD-DEEP-001"]
        if not records:
            return Capability(id="hardware.sensors", name="主机硬件 Sensor", status=CapabilityStatus.UNAVAILABLE, profile="enhanced", detected_via="HostSystem.runtime.healthSystemRuntime")
        unavailable = [record for record in records if record.metadata.get("not_applicable")]
        return Capability(
            id="hardware.sensors",
            name="主机硬件 Sensor",
            status=CapabilityStatus.AVAILABLE if not unavailable else CapabilityStatus.UNAVAILABLE,
            profile="enhanced",
            detected_via="HostSystem.runtime.healthSystemRuntime.systemHealthInfo.numericSensorInfo",
            detail={"host_count": len(records), "unavailable_host_count": len(unavailable)},
        )

    def _hardware_component_capabilities(self, hosts: list[Any]) -> list[Capability]:
        records = [record for record in hosts if isinstance(record, DatasetRecord) and record.metadata.get("rule_id") == "HARD-DEEP-002"]
        counts = {"hardware.disk": sum(int((record.value or {}).get("disk_count") or 0) for record in records), "hardware.hba": sum(int((record.value or {}).get("hba_count") or 0) for record in records), "hardware.nic": sum(int((record.value or {}).get("nic_count") or 0) for record in records)}
        firmware_count = sum(int((record.value or {}).get("firmware_count") or 0) for record in records)
        device_count = sum(int((record.value or {}).get("device_count") or 0) for record in records)
        result = []
        for capability_id, label in (("hardware.disk", "主机物理磁盘"), ("hardware.hba", "主机 HBA"), ("hardware.nic", "主机物理网卡")):
            result.append(Capability(id=capability_id, name=label, status=CapabilityStatus.AVAILABLE if counts[capability_id] > 0 else CapabilityStatus.UNAVAILABLE, profile="enhanced", detected_via="PyVmomiPciCollector._host_devices", detail={"object_count": counts[capability_id], "host_count": len(records)}))
        firmware_status = CapabilityStatus.AVAILABLE if firmware_count > 0 else CapabilityStatus.LIMITED if device_count > 0 else CapabilityStatus.UNAVAILABLE
        result.append(Capability(id="hardware.firmware", name="主机固件与驱动", status=firmware_status, profile="enhanced", detected_via="PyVmomiPciCollector._host_devices", detail={"device_count": device_count, "firmware_count": firmware_count, "reason": "ESXCLI enrichment unavailable" if firmware_count == 0 else "firmware/driver fields captured for a subset of devices"}))
        return result

    @staticmethod
    def _update_hardware_compatibility_log(collection_log: list[dict[str, Any]], records: list[DatasetRecord]) -> None:
        summary = next((item for item in records if item.metadata.get("hardware_compatibility_summary")), None)
        phase_log = next((item for item in reversed(collection_log) if item.get("action") == "hardware.compatibility"), None)
        if summary is None or phase_log is None:
            return
        details = summary.value if isinstance(summary.value, dict) else {}
        phase_log.update(
            {
                "status": details.get("collection_status", phase_log.get("status")),
                "catalog_version": details.get("baseline_version"),
                "freshness": details.get("freshness_status"),
                "target_release_count": details.get("mapped_host_count"),
                "matched_device_count": details.get("evaluated_device_count"),
                "incomplete_device_count": details.get("incomplete_device_count"),
                "incompatible_count": details.get("incompatible_count"),
            }
        )

    @staticmethod
    def _hardware_compatibility_capability(records: list[DatasetRecord], host_count: int, phase_log: dict[str, Any]) -> Capability:
        summary = next((record for record in records if record.metadata.get("hardware_compatibility_summary")), None)
        detail = summary.value if summary and isinstance(summary.value, dict) else {}
        if phase_log.get("status") == "not_requested" and not records:
            status = CapabilityStatus.NOT_REQUESTED
        elif host_count == 0:
            status = CapabilityStatus.NOT_APPLICABLE
        elif detail.get("collection_status") == "unavailable":
            status = CapabilityStatus.UNAVAILABLE
        elif detail.get("collection_status") == "available" and detail.get("coverage_complete") is True:
            status = CapabilityStatus.AVAILABLE
        else:
            status = CapabilityStatus.LIMITED
        return Capability(
            id="hardware.vcg.compatibility",
            name="硬件驱动与固件 VCG 兼容性",
            status=status,
            profile="enhanced",
            detected_via="bundled VCG/HclMatcher",
            detail={
                "baseline_version": detail.get("baseline_version"),
                "json_updated_time": detail.get("hcl_json_updated_time"),
                "freshness_status": detail.get("freshness_status"),
                "host_count": host_count,
                "mapped_host_count": detail.get("mapped_host_count", 0),
                "expected_device_count": detail.get("expected_device_count", 0),
                "evaluated_device_count": detail.get("evaluated_device_count", 0),
                "incomplete_scope_count": detail.get("incomplete_scope_count", 0),
                "incompatible_count": detail.get("incompatible_count", 0),
                "error_type": detail.get("catalog_error_type"),
            },
            affects_rules=["HARD-DEEP-003"],
        )

    def _hardware_component_records(self, hosts: list[Any], dataset_id: str, collected_at: str) -> list[DatasetRecord]:
        from vstacklens.collection.pci_collector import PyVmomiPciCollector

        pci_collector = PyVmomiPciCollector(self.host, self.username, self.password, self.port, self.ssl_verify)
        result: list[DatasetRecord] = []
        for host in hosts:
            config = getattr(host, "config", None)
            try:
                devices, warnings = pci_collector._host_devices_with_warnings(host, collected_at)
            except Exception as exc:  # noqa: BLE001 - one host must not abort the deep run.
                devices, warnings = [], [{"status": type(exc).__name__}]
            category_counts = {"disk": 0, "hba": 0, "nic": 0}
            for device in devices:
                category = str(device.get("category") or "").casefold()
                if category in {"ssd", "hdd", "disk"}:
                    category_counts["disk"] += 1
                elif category in {"controller", "hba"}:
                    category_counts["hba"] += 1
                elif category == "nic":
                    category_counts["nic"] += 1
            firmware_count = sum(1 for device in devices if device.get("firmware_version") or device.get("driver_version"))
            value = {
                "disk_count": category_counts["disk"],
                "hba_count": category_counts["hba"],
                "nic_count": category_counts["nic"],
                "device_count": len(devices),
                "firmware_count": firmware_count,
                "warnings": warnings,
                "devices": devices,
            }
            result.append(self._record(dataset_id, collected_at, "hardware", self._entity(host, "HostSystem"), "HARD-DEEP-002", value, "inventory", False, "host hardware component inventory captured through the PCI collector", not_applicable=config is None))
        return result

    def _hardware_compatibility_records(
        self,
        hosts: list[Any],
        hardware_records: list[DatasetRecord],
        dataset_id: str,
        collected_at: str,
        *,
        resource_guard: Callable[[], str | None] | None = None,
    ) -> list[DatasetRecord]:
        from vstacklens.upgrade_compat.server import match_server_model

        rule_id = "HARD-DEEP-003"
        component_by_host = {record.entity.stable_id: record for record in hardware_records if record.metadata.get("rule_id") == "HARD-DEEP-002"}
        records: list[DatasetRecord] = []
        status_counts: dict[str, int] = {}
        expected_device_count = sum(len((record.value or {}).get("devices") or []) for record in component_by_host.values())
        mapped_host_count = 0
        evaluated_device_count = 0
        incomplete_count = 0
        incomplete_server_count = 0
        incomplete_device_count = 0
        incompatible_count = 0
        skipped_device_count = 0
        stop_reason: str | None = None
        collection_status = "unavailable"
        baseline_version: str | None = None
        json_updated_time: str | None = None
        freshness_status = "UNKNOWN"
        catalog_error_type: str | None = None

        def append_result(entity: DeepEntity, value: dict[str, Any], status: str, summary: str, *, finding: bool, complete: bool, conflict: bool = False) -> None:
            nonlocal incomplete_count, incomplete_server_count, incomplete_device_count, incompatible_count
            status_counts[status] = status_counts.get(status, 0) + 1
            incomplete_count += int(not complete)
            if not complete and value.get("record_type") == "server":
                incomplete_server_count += 1
            elif not complete and value.get("record_type") == "device":
                incomplete_device_count += 1
            incompatible_count += int(finding)
            record = self._record(dataset_id, collected_at, "hardware", entity, rule_id, value, "hcl_status", finding, summary)
            record.source = DeepSource(api="Bundled VCG / HclMatcher", collector="vstacklens.deep.hardware_compatibility", collected_at_utc=collected_at)
            record.raw_pointer = f"hardware/hcl/{entity.stable_id}.ndjson"
            record.window = DeepWindow(start=collected_at, end=collected_at, sample_count=1 if complete else 0, expected_sample_count=1, completeness=1.0 if complete else 0.0)
            record.metadata.update({"coverage_complete": complete, "conflict": conflict, "hcl_status": status})
            records.append(record)

        if not hosts:
            collection_status = "not_applicable"
        else:
            try:
                stop_reason = resource_guard() if resource_guard else None
                if stop_reason:
                    collection_status = "not_requested"
                else:
                    catalog = load_bundled_vcg_index()
                    try:
                        baseline_version = catalog.baseline_version
                        json_updated_time = catalog.json_updated_time
                        freshness_status = str(catalog.freshness.status)
                        if freshness_status != "FRESH":
                            collection_status = "limited"
                            catalog_error_type = "stale_or_unknown_vcg_baseline"
                        else:
                            complete_hardware_inventory = True
                            target_release_by_host: dict[str, str | None] = {}
                            for host in hosts:
                                stop_reason = resource_guard() if resource_guard else None
                                if stop_reason:
                                    collection_status = "not_requested"
                                    complete_hardware_inventory = False
                                    break
                                host_entity = self._entity(host, "HostSystem")
                                product = getattr(getattr(host, "config", None), "product", None)
                                version = str(getattr(product, "version", "") or "") if product else ""
                                build = str(getattr(product, "build", "") or "") if product else ""
                                target_release = esxi_version_to_hcl_release(version, catalog.supported_releases)
                                target_release_by_host[host_entity.stable_id] = target_release
                                mapped_host_count += int(target_release is not None)
                                hardware = getattr(host, "hardware", None)
                                system_info = getattr(hardware, "systemInfo", None) if hardware else None
                                model = str(getattr(system_info, "model", "") or "").strip() if system_info else ""
                                if target_release is None:
                                    complete_hardware_inventory = False
                                    append_result(host_entity, {"record_type": "server", "host": host_entity.display_ref, "esxi_version": version or None, "esxi_build": build or None, "target_release": None, "status": "ESXI_RELEASE_UNMAPPED", "baseline_version": baseline_version}, "ESXI_RELEASE_UNMAPPED", "ESXi 版本无法精确映射到本地 VCG 版本", finding=False, complete=False)
                                else:
                                    server_result = match_server_model(catalog.store, model, target_release)
                                    server_status = str(server_result.status)
                                    server_complete = server_status in {"SERVER_CERTIFIED", "SERVER_NOT_CERTIFIED"}
                                    server_finding = server_status in HCL_COMPATIBILITY_RISK_STATUSES
                                    append_result(
                                        host_entity,
                                        {
                                            "record_type": "server",
                                            "host": host_entity.display_ref,
                                            "server_model": model or None,
                                            "esxi_version": version or None,
                                            "esxi_build": build or None,
                                            "target_release": target_release,
                                            "status": server_status,
                                            "detail": str(server_result.detail or "")[:512],
                                            "vcglink": server_result.vcglink,
                                            "candidate_links": list(server_result.candidate_links[:8]),
                                            "baseline_version": baseline_version,
                                        },
                                        server_status,
                                        str(server_result.detail or "VCG 整机认证结果已采集"),
                                        finding=server_finding,
                                        complete=server_complete,
                                    )
                                    complete_hardware_inventory = complete_hardware_inventory and server_complete

                                component_record = component_by_host.get(host_entity.stable_id)
                                device_list = (component_record.value or {}).get("devices") if component_record and isinstance(component_record.value, dict) else None
                                if not isinstance(device_list, list):
                                    complete_hardware_inventory = False
                                    append_result(host_entity, {"record_type": "device_inventory", "host": host_entity.display_ref, "status": "device_inventory_unavailable"}, "DEVICE_INVENTORY_UNAVAILABLE", "主机设备清单未能关联到 Deep 硬件采集记录", finding=False, complete=False)
                                    continue
                                if not device_list:
                                    complete_hardware_inventory = False
                                for device_index, device in enumerate(device_list):
                                    if device_index >= MAX_HCL_COMPATIBILITY_DEVICES:
                                        skipped_device_count += len(device_list) - device_index
                                        complete_hardware_inventory = False
                                        break
                                    if target_release is None:
                                        skipped_device_count += 1
                                        continue
                                    stop_reason = resource_guard() if resource_guard else None
                                    if stop_reason:
                                        skipped_device_count += len(device_list) - device_index
                                        complete_hardware_inventory = False
                                        break
                                    category = str(device.get("category") or "unknown").casefold()
                                    driver_name = str(device.get("driver_name") or "").strip()
                                    driver_version = str(device.get("driver_version") or "").strip()
                                    firmware_confidence = str(device.get("firmware_confidence") or "").casefold()
                                    firmware_version = str(device.get("firmware_version") or "").strip() if firmware_confidence == "certain" else ""
                                    model_text = str(device.get("model") or device.get("object_name") or "").strip()
                                    device_key = str(device.get("object_key") or f"{category}:{model_text}:{device_index}")
                                    device_stable_id = "hardware:" + hashlib.sha256(f"{host_entity.stable_id}|{device_key}".encode("utf-8")).hexdigest()[:24]
                                    device_entity = DeepEntity(type="HardwareDevice", stable_id=device_stable_id, display_ref=model_text or f"{category} device")
                                    quadruple = tuple(str(device.get(key) or "").strip().casefold() for key in ("vid", "did", "svid", "ssid"))
                                    association_conflict = bool(device.get("association_conflict")) or str(device.get("pci_association_status") or "").casefold() in {"ambiguous", "conflict"}
                                    value: dict[str, Any] = {
                                        "record_type": "device",
                                        "host": host_entity.display_ref,
                                        "category": category,
                                        "model": model_text or None,
                                        "device_key": device_key[:256],
                                        "pci_quadruple": list(quadruple) if all(quadruple) else None,
                                        "driver_name": driver_name or None,
                                        "driver_version": driver_version or None,
                                        "firmware_version": firmware_version or None,
                                        "firmware_confidence": firmware_confidence or None,
                                        "field_sources": list(device.get("field_sources") or [])[:8],
                                        "target_release": target_release,
                                        "baseline_version": baseline_version,
                                    }
                                    if association_conflict:
                                        match_status = "PCI_ASSOCIATION_CONFLICT"
                                        match_detail = "PCI 身份与驱动来源存在关联冲突"
                                        match_link = None
                                        certified_driver_versions: list[str] = []
                                        certified_firmware_versions: list[str] = []
                                        complete = False
                                        finding = False
                                    elif not driver_name or not driver_version:
                                        match_status = "DRIVER_DATA_UNAVAILABLE"
                                        match_detail = "设备驱动名或版本未取得"
                                        match_link = None
                                        certified_driver_versions = []
                                        certified_firmware_versions = []
                                        complete = False
                                        finding = False
                                    elif category in {"controller", "nic"} and not all(quadruple):
                                        match_status = "IDENTIFIER_MISSING"
                                        match_detail = "PCI 四元组不完整，不能进行精确 VCG 匹配"
                                        match_link = None
                                        certified_driver_versions = []
                                        certified_firmware_versions = []
                                        complete = False
                                        finding = False
                                    elif category in {"ssd", "hdd"} and not model_text:
                                        match_status = "MODEL_MISSING"
                                        match_detail = "磁盘型号未取得，不能进行描述型 VCG 匹配"
                                        match_link = None
                                        certified_driver_versions = []
                                        certified_firmware_versions = []
                                        complete = False
                                        finding = False
                                    elif category not in {"controller", "nic", "ssd", "hdd"}:
                                        match_status = "CATEGORY_UNSUPPORTED"
                                        match_detail = "设备类别不在当前 VCG 匹配范围"
                                        match_link = None
                                        certified_driver_versions = []
                                        certified_firmware_versions = []
                                        complete = False
                                        finding = False
                                    else:
                                        match = catalog.matcher.match(
                                            quadruple if category in {"controller", "nic"} else None,
                                            target_release,
                                            driver_name,
                                            driver_version,
                                            firmware_version or None,
                                            model=model_text or None,
                                            category=category,
                                            source="vcg",
                                        )
                                        match_status = str(match.status)
                                        match_detail = str(match.detail or "")[:512]
                                        match_link = match.vcglink
                                        certified_driver_versions = list(match.certified_driver_versions[:16])
                                        certified_firmware_versions = list(match.certified_firmware_versions[:16])
                                        complete = match_status in HCL_COMPATIBILITY_COMPLETE_STATUSES | HCL_COMPATIBILITY_RISK_STATUSES
                                        finding = match_status in HCL_COMPATIBILITY_RISK_STATUSES
                                    value.update(
                                        {
                                            "status": match_status,
                                            "detail": match_detail,
                                            "vcglink": match_link,
                                            "certified_driver_versions": certified_driver_versions,
                                            "certified_firmware_versions": certified_firmware_versions,
                                        }
                                    )
                                    summary_text = match_detail or f"VCG status: {match_status}"
                                    append_result(device_entity, value, match_status, summary_text, finding=finding, complete=complete, conflict=association_conflict)
                                    evaluated_device_count += int(complete or finding)
                                    complete_hardware_inventory = complete_hardware_inventory and complete

                            skipped_hosts = len(hosts) - len(target_release_by_host)
                            if skipped_hosts:
                                stop_reason = stop_reason or "resource_guard"
                                complete_hardware_inventory = False
                            catalog_coverage_complete = complete_hardware_inventory and skipped_device_count == 0 and skipped_hosts == 0
                            collection_status = "available" if catalog_coverage_complete else "limited"
                            freshness_status = str(catalog.freshness.status)
                            freshness_age_days = catalog.freshness.age_days
                            freshness_status = str(catalog.freshness.status)
                            hcl_source_date = catalog.json_updated_time
                    finally:
                        catalog.close()
            except Exception as exc:  # noqa: BLE001 - HCL compatibility is an optional, independent capability.
                catalog_error_type = type(exc).__name__
                collection_status = "limited" if records else "unavailable"

        summary_value = {
            "collection_status": collection_status,
            "host_count": len(hosts),
            "mapped_host_count": mapped_host_count,
            "expected_device_count": expected_device_count,
            "evaluated_device_count": evaluated_device_count,
            "incomplete_scope_count": incomplete_count,
            "incomplete_server_count": incomplete_server_count,
            "incomplete_device_count": incomplete_device_count,
            "incompatible_count": incompatible_count,
            "skipped_device_count": skipped_device_count,
            "server_and_device_status_counts": status_counts,
            "baseline_version": baseline_version,
            "hcl_json_updated_time": hcl_source_date if "hcl_source_date" in locals() else None,
            "freshness_status": freshness_status,
            "freshness_age_days": freshness_age_days if "freshness_age_days" in locals() else None,
            "catalog_error_type": catalog_error_type,
            "coverage_complete": collection_status == "available",
            "target_release_by_host": target_release_by_host if "target_release_by_host" in locals() else {},
        }
        if collection_status == "not_requested":
            summary = f"VCG compatibility evaluation not requested: {stop_reason}"
        elif collection_status == "unavailable":
            summary = f"Bundled VCG compatibility data unavailable ({catalog_error_type or 'unknown'})"
        else:
            summary = f"VCG compatibility: {incompatible_count} confirmed issue(s), {incomplete_count} incomplete scope(s)"
        entity = self._environment_entity()
        summary_record = self._record(dataset_id, collected_at, "hardware", entity, rule_id, summary_value, "hcl_summary", False, summary, not_applicable=not hosts)
        summary_record.source = DeepSource(api="Bundled VCG baseline", collector="vstacklens.deep.hardware_compatibility", collected_at_utc=collected_at)
        summary_record.raw_pointer = "hardware/hcl/summary.ndjson"
        summary_complete = collection_status == "available"
        summary_record.window = DeepWindow(
            start=collected_at,
            end=collected_at,
            sample_count=1 if summary_complete else 0,
            expected_sample_count=1,
            completeness=1.0 if summary_complete else 0.0,
        )
        summary_record.metadata.update({"hardware_compatibility_summary": True, "coverage_complete": summary_complete, "collection_status": collection_status})
        records.append(summary_record)
        return records

    def _vsan_capabilities(self, inventory: dict[str, Any]) -> list[Capability]:
        status = str(inventory.get("status") or "not_collected").casefold()
        summaries = list((inventory.get("clusters") or {}).values())
        is_not_applicable = status == "not_applicable"
        is_not_requested = status == "not_requested"
        base_status = (
            CapabilityStatus.NOT_REQUESTED
            if is_not_requested
            else CapabilityStatus.NOT_APPLICABLE
            if is_not_applicable
            else CapabilityStatus.AVAILABLE
            if status == "collected" and summaries
            else CapabilityStatus.UNAVAILABLE
        )
        detail = {
            "collection_status": status,
            "cluster_count": len(summaries),
            "collection_error": inventory.get("collection_error"),
        }
        result = [
            Capability(
                id="vsan",
                name="vSAN 环境",
                status=base_status,
                profile="core",
                detected_via="vsanapiutils.GetVsanVcMos + datastore applicability",
                detail=detail,
            )
        ]
        families = (
            ("vsan.health.api", "vSAN Health API", "health_issues"),
            ("vsan.object.health", "vSAN Object Health", "object_health_issues"),
            ("vsan.resync", "vSAN Resync", "resync_suspended_object_count"),
            ("vsan.disk_group", "vSAN Disk Group", "disk_health_issues"),
        )
        for capability_id, name, evidence_key in families:
            if is_not_applicable:
                family_status = CapabilityStatus.NOT_APPLICABLE
            elif is_not_requested:
                family_status = CapabilityStatus.NOT_REQUESTED
            elif summaries and all(summary.get(evidence_key) is not None for summary in summaries):
                family_status = CapabilityStatus.AVAILABLE
            else:
                family_status = CapabilityStatus.UNAVAILABLE
            result.append(
                Capability(
                    id=capability_id,
                    name=name,
                    status=family_status,
                    profile="enhanced",
                    detected_via="vSAN Management API",
                    detail={**detail, "evidence_key": evidence_key},
                )
            )
        for capability_id, name in (
            ("vsan.perf.service", "vSAN 性能服务"),
            ("vsan.congestion", "vSAN Congestion"),
            ("vsan.latency", "vSAN Latency"),
        ):
            performance = inventory.get("performance") or {}
            performance_status = str(performance.get("status") or "unavailable")
            if is_not_applicable:
                performance_capability_status = CapabilityStatus.NOT_APPLICABLE
            elif is_not_requested or performance_status == "not_requested":
                performance_capability_status = CapabilityStatus.NOT_REQUESTED
            elif capability_id == "vsan.perf.service":
                performance_capability_status = CapabilityStatus.AVAILABLE if performance_status == "available" else CapabilityStatus.UNAVAILABLE
            elif int((performance.get("sample_counts") or {}).get(capability_id, 0) or 0) > 0:
                performance_capability_status = CapabilityStatus.AVAILABLE
            elif performance_status == "available" and capability_id in set(performance.get("supported_metrics") or []):
                performance_capability_status = CapabilityStatus.LIMITED
            else:
                performance_capability_status = CapabilityStatus.UNAVAILABLE
            result.append(
                Capability(
                    id=capability_id,
                    name=name,
                    status=performance_capability_status,
                    profile="enhanced",
                    detected_via="VsanPerformanceManager.VsanPerfGetSupportedEntityTypes/QueryVsanPerf",
                    detail={**detail, "performance": performance},
                )
            )
        return result

    def _available_metric_summary(self, perf_manager: Any, hosts: list[Any], datastores: list[Any], *, resource_guard: Callable[[], str | None] | None = None) -> dict[str, Any]:
        summary: dict[str, Any] = {"representative_objects": []}
        entities = [*hosts, *datastores]
        for index, entity in enumerate(entities):
            stop_reason = resource_guard() if resource_guard else None
            if stop_reason:
                summary.update({"status": "not_requested", "reason": stop_reason, "remaining_object_count": len(entities) - index})
                break
            try:
                metrics = perf_manager.QueryAvailablePerfMetric(entity=entity, beginTime=datetime.now(UTC) - timedelta(days=1), endTime=datetime.now(UTC)) or []
                summary["representative_objects"].append({"type": type(entity).__name__, "count": len(metrics)})
            except Exception as exc:  # noqa: BLE001 - capability probe records the failure.
                summary["representative_objects"].append({"type": type(entity).__name__, "error": type(exc).__name__})
        return summary

    def _collect_daily_perf(self, content: Any, datastores: list[Any], dataset_id: str, collected_at: str, policy: DeepCollectionPolicy, *, resource_guard: Callable[[], str | None] | None = None) -> list[DatasetRecord]:
        perf_manager = getattr(content, "perfManager", None)
        if perf_manager is None or not datastores:
            return []
        if resource_guard and resource_guard():
            return []
        datastore = datastores[0]
        try:
            available = perf_manager.QueryAvailablePerfMetric(entity=datastore, beginTime=datetime.now(UTC) - timedelta(days=policy.history_days), endTime=datetime.now(UTC)) or []
        except Exception:
            return []
        counter_ids = [item for item in available if str(getattr(item, "instance", "") or "") == ""]
        if not counter_ids:
            return []
        query = None
        for item in counter_ids:
            counter_id = int(getattr(item, "counterId", -1) or -1)
            counter = next((candidate for candidate in getattr(perf_manager, "perfCounter", []) or [] if int(getattr(candidate, "key", -2) or -2) == counter_id), None)
            name = str(getattr(counter, "nameInfo", None) and getattr(getattr(counter, "nameInfo", None), "key", "") or "").lower()
            if "used" in name or "space" in name:
                query = (item, counter, name)
                break
        if query is None:
            return []
        if resource_guard and resource_guard():
            return []
        item, counter, name = query
        try:
            metric = __import__("pyVmomi").vim.PerformanceManager.MetricId(counterId=int(item.counterId), instance="")
            spec = __import__("pyVmomi").vim.PerformanceManager.QuerySpec(entity=datastore, metricId=[metric], intervalId=86400, startTime=datetime.now(UTC) - timedelta(days=policy.history_days), endTime=datetime.now(UTC), format="normal")
            series = perf_manager.QueryPerf(querySpec=[spec]) or []
        except Exception:
            return []
        records: list[DatasetRecord] = []
        for result in series:
            values = list(getattr(result, "value", []) or [])
            samples = list(getattr(result, "sampleInfo", []) or [])
            for index, value in enumerate(values):
                if index >= len(samples):
                    continue
                sample_time = getattr(samples[index], "timestamp", None)
                if sample_time is None:
                    continue
                stamp = sample_time.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
                entity = self._entity(datastore, "Datastore")
                records.append(DatasetRecord(record_id=f"perf-{index}", dataset_id=dataset_id, kind="perf", entity=entity, collected_at_utc=collected_at, source=DeepSource(api="PerformanceManager.QueryPerf", collector="pyvmomi.deep", collected_at_utc=collected_at), selector={"counter": name or "unknown"}, window=DeepWindow(start=stamp, end=stamp, interval_sec=86400, sample_count=1, expected_sample_count=1, completeness=1.0), interval_sec=86400, rollup="average", value=self._json_value(value), unit="counter", raw_pointer=f"perf/{entity.stable_id}.ndjson#{index}", metadata={"rule_id": "CAP-DEEP-001"}))
        return records

    def _collect_enhanced_perf_records(
        self,
        content: Any,
        hosts: list[Any],
        datastores: list[Any],
        dataset_id: str,
        collected_at: str,
        policy: DeepCollectionPolicy,
        *,
        resource_guard: Callable[[], str | None] | None = None,
    ) -> tuple[list[DatasetRecord], list[Capability]]:
        """Collect bounded representative Enhanced counters as Evidence only.

        The first pass intentionally does not create customer Findings. It
        proves that the real environment can expose the counter family and
        preserves the samples for a later, rule-specific Analyzer.
        """

        perf_manager = getattr(content, "perfManager", None)
        if perf_manager is None:
            return [], []
        try:
            from pyVmomi import vim
        except ImportError:
            return [], []
        families = {
            "enhanced.perf.cpu": ("CPU Enhanced", ("cpu.ready", "cpu.costop", "cpu.usage")),
            "enhanced.perf.memory": ("Memory Enhanced", ("mem.vmmemctl", "mem.swapped", "mem.active")),
            "enhanced.perf.storage": ("Storage Enhanced", ("disk.maxtotallatency", "disk.devicelatency", "disk.kernellatency", "disk.numberreadaveraged", "disk.numberwriteaveraged", "disk.read", "disk.write")),
            "enhanced.perf.network": ("Network Enhanced", ("net.received", "net.transmitted", "net.droppedrx", "net.droppedtx", "net.errorsrx", "net.errorstx")),
        }

        def not_requested_capabilities(reason: str, detected_via: str) -> list[Capability]:
            return [
                Capability(
                    id=family_id,
                    name=label,
                    status=CapabilityStatus.NOT_REQUESTED,
                    profile="enhanced",
                    detected_via=detected_via,
                    detail={"reason": reason},
                )
                for family_id, (label, _keywords) in families.items()
            ]

        selected: dict[str, list[tuple[Any, Any, str, str]]] = {key: [] for key in families}
        matched_entities: dict[str, set[str]] = {key: set() for key in families}
        selected_per_entity: dict[str, dict[str, int]] = {key: {} for key in families}
        for entity in [*hosts, *datastores]:
            if self.cancel_requested():
                return [], not_requested_capabilities("cancelled_during_counter_probe", "cancel_requested")
            stop_reason = resource_guard() if resource_guard else None
            if stop_reason:
                return [], not_requested_capabilities(stop_reason, "resource_guard")
            entity_id = str(getattr(entity, "_moId", "") or getattr(entity, "name", ""))
            try:
                available = perf_manager.QueryAvailablePerfMetric(entity=entity, beginTime=datetime.now(UTC) - timedelta(days=1), endTime=datetime.now(UTC)) or []
            except Exception:
                continue
            matches: dict[str, list[tuple[Any, str, str]]] = {key: [] for key in families}
            for item in available:
                counter_id = int(getattr(item, "counterId", -1) or -1)
                counter = next((candidate for candidate in getattr(perf_manager, "perfCounter", []) or [] if int(getattr(candidate, "key", -2) or -2) == counter_id), None)
                if counter is None:
                    continue
                name_info = getattr(counter, "nameInfo", None)
                key_name = str(getattr(name_info, "key", "") or "").lower()
                group_info = getattr(counter, "groupInfo", None)
                group_name = str(getattr(group_info, "key", "") or "").lower()
                full_name = f"{group_name}.{key_name}".strip(".")
                for family_id, (_label, keywords) in families.items():
                    if full_name in keywords:
                        matches[family_id].append((counter, full_name or key_name or "unknown", str(getattr(item, "instance", "") or "")))
            for family_id, matches_for_family in matches.items():
                if matches_for_family:
                    matched_entities[family_id].add(entity_id)
                chosen = selected_per_entity[family_id].setdefault(entity_id, 0)
                for counter, counter_name, instance in matches_for_family:
                    if chosen >= 3:
                        break
                    if any(existing[0] is entity and existing[1].key == counter.key and existing[3] == instance for existing in selected[family_id]):
                        continue
                    selected[family_id].append((entity, counter, counter_name, instance))
                    chosen += 1
                selected_per_entity[family_id][entity_id] = chosen

        records: list[DatasetRecord] = []
        capabilities: list[Capability] = []
        for family_id, (label, _keywords) in families.items():
            if self.cancel_requested():
                return records, not_requested_capabilities("cancelled_during_performance_query", "cancel_requested")
            stop_reason = resource_guard() if resource_guard else None
            if stop_reason:
                return records, not_requested_capabilities(stop_reason, "resource_guard")
            family_records = 0
            matched = len(selected[family_id])
            sampled_entities: set[str] = set()
            for index, (entity, counter, counter_name, instance) in enumerate(selected[family_id]):
                if self.cancel_requested():
                    return records, not_requested_capabilities("cancelled_during_performance_query", "cancel_requested")
                stop_reason = resource_guard() if resource_guard else None
                if stop_reason:
                    return records, not_requested_capabilities(stop_reason, "resource_guard")
                try:
                    metric_id = vim.PerformanceManager.MetricId(counterId=int(getattr(counter, "key", -1) or -1), instance=instance)
                    spec = vim.PerformanceManager.QuerySpec(entity=entity, metricId=[metric_id], intervalId=300, startTime=datetime.now(UTC) - timedelta(days=1), endTime=datetime.now(UTC), format="normal")
                    series = perf_manager.QueryPerf(querySpec=[spec]) or []
                except Exception:
                    continue
                for result in series:
                    samples = list(getattr(result, "sampleInfo", []) or [])
                    if not samples:
                        continue
                    entity_ref = self._entity(entity, type(entity).__name__)
                    for series_index, metric_series in enumerate(list(getattr(result, "value", []) or [])):
                        raw_values = list(getattr(metric_series, "value", []) or [])
                        points = self._enhanced_perf_points(counter_name, raw_values, samples, interval_sec=300)
                        if not points:
                            continue
                        timestamps = [timestamp for timestamp, _value in points]
                        values = [value for _timestamp, value in points]
                        start = min(timestamps).astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
                        end = max(timestamps).astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
                        expected_samples = max(
                            len(values),
                            int((max(timestamps) - min(timestamps)).total_seconds() / 300) + 1,
                        )
                        records.append(
                            DatasetRecord(
                                record_id=f"enhanced-{family_id}-{index}-{series_index}",
                                dataset_id=dataset_id,
                                kind="perf",
                                entity=entity_ref,
                                collected_at_utc=collected_at,
                                source=DeepSource(api="PerformanceManager.QueryPerf", collector="pyvmomi.deep.enhanced", collected_at_utc=collected_at),
                                selector={"counter": counter_name, "instance": instance, "family": family_id},
                                window=DeepWindow(
                                    start=start,
                                    end=end,
                                    interval_sec=300,
                                    sample_count=len(values),
                                    expected_sample_count=expected_samples,
                                    completeness=round(len(values) / expected_samples, 4),
                                ),
                                interval_sec=300,
                                rollup=str(getattr(counter, "rollupType", "") or "raw"),
                                value={
                                    "first": values[0],
                                    "last": values[-1],
                                    "min": min(values),
                                    "max": max(values),
                                    "average": round(sum(values) / len(values), 4),
                                },
                                unit=self._enhanced_perf_unit(counter_name, counter),
                                raw_pointer=f"perf/enhanced/{family_id}.ndjson#{family_records}",
                                metadata={
                                    "enhanced": True,
                                    "family": family_id,
                                    "counter": counter_name,
                                    "counter_unit": str(getattr(getattr(counter, "unitInfo", None), "key", "") or ""),
                                    "sample_values": values,
                                },
                            )
                        )
                        family_records += 1
                        sampled_entities.add(str(getattr(entity, "_moId", "") or getattr(entity, "name", "")))
            expected_entities = matched_entities[family_id]
            status = (
                CapabilityStatus.AVAILABLE
                if expected_entities and sampled_entities == expected_entities
                else CapabilityStatus.LIMITED
                if matched
                else CapabilityStatus.UNAVAILABLE
            )
            capabilities.append(
                Capability(
                    id=family_id,
                    name=label,
                    status=status,
                    profile="enhanced",
                    detected_via="QueryAvailablePerfMetric + QueryPerf",
                    detail={
                        "matched_counters": matched,
                        "sample_series": family_records,
                        "entities_with_counters": len(expected_entities),
                        "entities_with_samples": len(sampled_entities),
                    },
                )
            )
        return records, capabilities

    @staticmethod
    def _enhanced_perf_points(
        counter_name: str,
        raw_values: list[Any],
        samples: list[Any],
        *,
        interval_sec: int,
    ) -> list[tuple[datetime, float]]:
        points: list[tuple[datetime, float]] = []
        for raw_value, sample in zip(raw_values, samples, strict=False):
            timestamp = getattr(sample, "timestamp", None)
            if timestamp is None:
                continue
            try:
                value = float(raw_value)
            except (TypeError, ValueError):
                continue
            if not isfinite(value) or value < 0:
                continue
            if counter_name in {"cpu.ready", "cpu.costop"}:
                value = value / (interval_sec * 10)
            elif counter_name == "cpu.usage":
                value = value / 100
            elif counter_name in {"mem.vmmemctl", "mem.swapped", "mem.swapused"}:
                value = value / 1024
            points.append((timestamp, round(value, 4)))
        return points

    @staticmethod
    def _enhanced_perf_unit(counter_name: str, counter: Any) -> str:
        if counter_name in {"cpu.ready", "cpu.costop"}:
            return "percent"
        if counter_name in {"mem.vmmemctl", "mem.swapped", "mem.swapused"}:
            return "megabyte"
        unit = str(getattr(getattr(counter, "unitInfo", None), "key", "") or "").casefold()
        return {"millisecond": "millisecond", "percent": "percent", "kb": "kilobyte", "kilobytes": "kilobyte"}.get(unit, unit or "counter")

    def _counter_id(self, perf_manager: Any, counter_name: str) -> int:
        for counter in getattr(perf_manager, "perfCounter", []) or []:
            name_info = getattr(counter, "nameInfo", None)
            group_info = getattr(counter, "groupInfo", None)
            full_name = f"{getattr(group_info, 'key', '')}.{getattr(name_info, 'key', '')}".strip(".").lower()
            if full_name == counter_name.lower():
                return int(getattr(counter, "key", -1) or -1)
        return -1

    @staticmethod
    def _json_value(value: Any) -> Any:
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, (list, tuple)):
            return [PyVmomiDeepCollector._json_value(item) for item in value]
        for attribute in ("value", "val"):
            nested = getattr(value, attribute, None)
            if nested is not None and nested is not value:
                return PyVmomiDeepCollector._json_value(nested)
        try:
            return float(value)
        except (TypeError, ValueError):
            return str(value)

    def _bounded_events(self, content: Any, policy: DeepCollectionPolicy, *, should_stop: Callable[[], str | None] | None = None) -> list[Any]:
        manager = getattr(content, "eventManager", None)
        if manager is None:
            self._event_query_meta = {"degraded": True, "reason": "event manager unavailable"}
            return []
        if self.cancel_requested():
            begin = datetime.now(UTC) - timedelta(days=policy.event_history_days)
            end = datetime.now(UTC)
            self._event_query_meta = {"degraded": True, "reason": "cancelled_before_event_query", "window_start": begin.replace(microsecond=0).isoformat().replace("+00:00", "Z"), "window_end": end.replace(microsecond=0).isoformat().replace("+00:00", "Z"), "batches": 0, "collector_cap": policy.max_history_records}
            return []
        begin = datetime.now(UTC) - timedelta(days=policy.event_history_days)
        end = datetime.now(UTC)
        events: list[Any] = []
        stop_reason = should_stop() if should_stop else None
        if stop_reason:
            self._event_query_meta = {"degraded": True, "reason": stop_reason, "window_start": begin.replace(microsecond=0).isoformat().replace("+00:00", "Z"), "window_end": end.replace(microsecond=0).isoformat().replace("+00:00", "Z"), "batches": 0, "collector_cap": policy.max_history_records}
            return events
        try:
            vim = __import__("pyVmomi").vim
            filter_spec = vim.event.EventFilterSpec(time=vim.event.EventFilterSpec.ByTime(beginTime=begin, endTime=end))
            collector = manager.CreateCollectorForEvents(filter_spec)
            batches = 0
            stopped_early = False
            try:
                while len(events) < policy.max_history_records:
                    if self.cancel_requested():
                        self._event_query_meta = {"degraded": True, "reason": "cancelled_during_event_query", "window_start": begin.replace(microsecond=0).isoformat().replace("+00:00", "Z"), "window_end": end.replace(microsecond=0).isoformat().replace("+00:00", "Z"), "batches": batches, "collector_cap": policy.max_history_records}
                        stopped_early = True
                        break
                    stop_reason = should_stop() if should_stop else None
                    if stop_reason:
                        self._event_query_meta = {"degraded": True, "reason": stop_reason, "window_start": begin.replace(microsecond=0).isoformat().replace("+00:00", "Z"), "window_end": end.replace(microsecond=0).isoformat().replace("+00:00", "Z"), "batches": batches, "collector_cap": policy.max_history_records}
                        stopped_early = True
                        break
                    batch_size = min(1000, policy.max_history_records - len(events))
                    reader = getattr(collector, "ReadNext", None) or getattr(collector, "readNext", None)
                    if reader is None:
                        raise RuntimeError("EventHistoryCollector has no ReadNext method")
                    batch = list(reader(batch_size) or [])
                    batches += 1
                    if not batch:
                        break
                    events.extend(batch)
                    if len(batch) < batch_size:
                        break
            finally:
                destroy = getattr(collector, "DestroyCollector", None) or getattr(collector, "destroyCollector", None)
                if destroy:
                    destroy()
            if not stopped_early:
                self._event_query_meta = {"degraded": len(events) >= policy.max_history_records, "window_start": begin.replace(microsecond=0).isoformat().replace("+00:00", "Z"), "window_end": end.replace(microsecond=0).isoformat().replace("+00:00", "Z"), "batches": batches, "collector_cap": policy.max_history_records}
            return events[: policy.max_history_records]
        except Exception as collector_error:
            stop_reason = should_stop() if should_stop else None
            if stop_reason:
                self._event_query_meta = {"degraded": True, "reason": stop_reason, "window_start": begin.replace(microsecond=0).isoformat().replace("+00:00", "Z"), "window_end": end.replace(microsecond=0).isoformat().replace("+00:00", "Z"), "batches": 0, "collector_cap": policy.max_history_records}
                return events[: policy.max_history_records]
            try:
                filter_spec = vim.event.EventFilterSpec(time=vim.event.EventFilterSpec.ByTime(beginTime=begin, endTime=end))
                events = list(manager.QueryEvents(filter=filter_spec) or [])[: policy.max_history_records]
                self._event_query_meta = {"degraded": True, "fallback": "QueryEvents", "reason": type(collector_error).__name__, "window_start": begin.replace(microsecond=0).isoformat().replace("+00:00", "Z"), "window_end": end.replace(microsecond=0).isoformat().replace("+00:00", "Z"), "batches": 1, "collector_cap": policy.max_history_records}
                return events
            except Exception as exc:
                self._event_query_meta = {"degraded": True, "reason": type(exc).__name__, "window_start": begin.replace(microsecond=0).isoformat().replace("+00:00", "Z"), "window_end": end.replace(microsecond=0).isoformat().replace("+00:00", "Z"), "batches": 0, "collector_cap": policy.max_history_records}
                return []
            return []

    def _history_records(self, events: list[Any], hosts: list[Any], clusters: list[Any], datastores: list[Any], dataset_id: str, collected_at: str, event_meta: dict[str, Any] | None = None, *, vms: list[Any] | None = None, correlation_window_seconds: int = 3600) -> list[DatasetRecord]:
        self._event_rule_ids_by_identity = {}
        text_items = [(event, (type(event).__name__ + " " + str(getattr(event, "fullFormattedMessage", "") or "")).lower()) for event in events]
        def token_matches(text: str, token: str) -> bool:
            pattern = rf"\b{re.escape(token)}\b" if len(token) <= 3 else re.escape(token)
            return re.search(pattern, text, flags=re.IGNORECASE) is not None

        groups = {
            "NET-DEEP-001": ["linkstate", "link state", "link down", "link up", "link flap"],
            "NET-DEEP-002": ["network disconnect", "network error", "packet drop", "pnic", "nic error", "link down", "linkstate", "link state", "link flap"],
            "STO-DEEP-001": ["apd", "pdl", "all paths down", "permanent device loss"],
            "STO-DEEP-002": ["storage path", "path failure", "device reset", "vmfs", "storage disconnect"],
            "COMPUTE-DEEP-001": ["vmotion", "relocatevm", "migration"],
            "COMPUTE-DEEP-002": ["vm reset", "vmreset", "poweron failed", "poweroff failed", "power failure", "guest reset"],
            "CL-DEEP-002": ["ha", "isolation", "host connection lost", "host failed", "restart"],
            "CL-DEEP-003": ["drs"],
            "CL-DEEP-006": ["entermaintenance", "enter maintenance", "maintenance mode", "entering maintenance"],
            "CL-DEEP-007": ["alarmstatuschanged", "alarm triggered", "alarm activated", "alarm fired"],
        }

        def event_matches_rule(rule_id: str, tokens: list[str], text: str) -> bool:
            if not any(token_matches(text, token) for token in tokens):
                return False
            if rule_id == "NET-DEEP-002":
                state_signal = token_matches(text, "linkstate") or token_matches(text, "link state")
                other_network_signal = any(token_matches(text, token) for token in tokens if token not in {"linkstate", "link state"})
                link_down = bool(re.search(r"\blink(?:[\s_.:-]*state)?[\s_.:=/-]*(?:is[\s:=/-]*)?down\b", text, flags=re.IGNORECASE))
                if state_signal and not (other_network_signal or link_down):
                    return False
            if rule_id == "COMPUTE-DEEP-001":
                migration_context = any(token_matches(text, token) for token in ("vmotion", "v motion", "relocatevm", "migration"))
                failure_state = bool(re.search(r"\b(?:fail(?:ed|ure)?|error|cancelled|canceled|unsuccessful)\b", text, flags=re.IGNORECASE))
                if not migration_context or not failure_state:
                    return False
            if rule_id == "CL-DEEP-002":
                ha_context = token_matches(text, "ha") or token_matches(text, "high availability")
                failure_state = bool(re.search(r"\b(?:fail(?:ed|ure)?|error|lost|disconnected|not responding|unable)\b", text, flags=re.IGNORECASE))
                restart_state = bool(re.search(r"\b(?:restart(?:ed)?|reboot(?:ed)?)\b", text, flags=re.IGNORECASE))
                explicit_host_loss = bool(re.search(r"\bhost\b.{0,80}\b(?:lost|failed|disconnected|not responding)\b|\b(?:lost|failed|disconnected|not responding)\b.{0,80}\bhost\b", text, flags=re.IGNORECASE))
                explicit_isolation = bool(re.search(r"\b(?:isolated|isolation (?:occurred|detected|lost|failed)|(?:occurred|detected|lost|failed) isolation)\b", text, flags=re.IGNORECASE))
                if not (explicit_host_loss or explicit_isolation or (ha_context and (failure_state or restart_state))):
                    return False
            if rule_id == "CL-DEEP-007":
                if not any(token_matches(text, token) for token in ("red", "yellow", "critical", "triggered", "activated", "fired")):
                    return False
                if any(token_matches(text, token) for token in ("cleared", "green", "normal", "resolved")):
                    return False
            return True

        entities_by_moid: dict[str, DeepEntity] = {}
        entities_by_name: dict[str, dict[str, DeepEntity]] = {}
        for collection, entity_type in ((hosts, "HostSystem"), (vms or [], "VirtualMachine"), (clusters, "ClusterComputeResource"), (datastores, "Datastore")):
            for item in collection:
                entity = self._entity(item, entity_type)
                moid = getattr(item, "_moId", None)
                if moid:
                    entities_by_moid[str(moid).casefold()] = entity
                name_key = str(entity.display_ref or "").casefold()
                if name_key:
                    entities_by_name.setdefault(name_key, {})[entity.stable_id] = entity

        def resolved_event_object_ids(event: Any, *, allow_name_fallback: bool) -> list[DeepEntity]:
            object_ids, object_names = event_object_references(event)
            resolved = {entities_by_moid[object_id].stable_id: entities_by_moid[object_id] for object_id in object_ids if object_id in entities_by_moid}
            if object_ids:
                typed_fields = (("host", "host", "HostSystem"), ("vm", "vm", "VirtualMachine"), ("ds", "datastore", "Datastore"), ("net", "network", "Network"), ("dvs", "dvs", "DistributedVirtualSwitch"), ("computeResource", "computeResource", "ComputeResource"), ("datacenter", "datacenter", "Datacenter"), ("tgw", "tgw", "TransitGateway"), ("entity", "entity", "ManagedEntity"))
                for object_id in object_ids:
                    if object_id in entities_by_moid:
                        continue
                    object_type = None
                    for argument_name, reference_name, candidate_type in typed_fields:
                        argument = getattr(event, argument_name, None)
                        if argument is None:
                            continue
                        reference = getattr(argument, reference_name, None) or argument
                        reference_id = getattr(reference, "_moId", None) or getattr(reference, "value", None)
                        if reference_id and str(reference_id).casefold() == object_id:
                            object_type = candidate_type
                            break
                    event_object_type = getattr(event, "objectType", None)
                    if object_type is None and event_object_type is not None and getattr(event, "objectId", None) and str(getattr(event, "objectId")).casefold() == object_id:
                        object_type = getattr(event_object_type, "_wsdlName", None) or getattr(event_object_type, "__name__", None)
                    object_name = next(iter(sorted(object_names)), object_id)
                    resolved[f"moid:{object_id}"] = DeepEntity(type=str(object_type or "ManagedEntity"), stable_id=f"moid:{object_id}", display_ref=str(object_name))
                return sorted(resolved.values(), key=lambda item: (item.type, item.stable_id))
            if allow_name_fallback:
                by_stable_id: dict[str, DeepEntity] = {}
                for name in object_names:
                    by_stable_id.update(entities_by_name.get(name, {}))
                if len(by_stable_id) == 1:
                    return list(by_stable_id.values())
            return []

        records: list[DatasetRecord] = []
        for rule_id, tokens in groups.items():
            matched = [event for event, text in text_items if event_matches_rule(rule_id, tokens, text)]
            for event in matched:
                self._event_rule_ids_by_identity.setdefault(id(event), set()).add(rule_id)
            record_kind = "task" if rule_id == "COMPUTE-DEEP-001" else "event"
            degraded = bool((event_meta or {}).get("degraded"))
            grouped_events: dict[str, dict[str, Any]] = {}
            for event in matched:
                resolved_entities = resolved_event_object_ids(event, allow_name_fallback=True)
                if not resolved_entities:
                    environment = self._environment_entity()
                    grouped_events.setdefault(environment.stable_id, {"entity": environment, "events": [], "object_resolved": False})["events"].append(event)
                    continue
                for entity in resolved_entities:
                    grouped_events.setdefault(entity.stable_id, {"entity": entity, "events": [], "object_resolved": True})["events"].append(event)
            if not grouped_events:
                environment = self._environment_entity()
                grouped_events[environment.stable_id] = {"entity": environment, "events": [], "object_resolved": True}
            for stable_id, grouped in sorted(grouped_events.items()):
                entity = grouped["entity"]
                grouped_records = grouped["events"]
                event_samples = []
                for event in grouped_records[:20]:
                    sample = self._event_sample(event)
                    sample["rule_ids"] = [rule_id]
                    sample["dataset_pointer"] = f"events/event.ndjson#{rule_id}/{stable_id}"
                    sample["resolved_entities"] = [{"type": item.type, "stable_id": item.stable_id, "display_ref": item.display_ref} for item in resolved_event_object_ids(event, allow_name_fallback=True)]
                    event_samples.append(sample)
                expected_count = max(len(grouped_records), int((event_meta or {}).get("collector_cap") or len(grouped_records))) if degraded else len(grouped_records)
                completeness = 0.0 if degraded or (grouped_records and not grouped["object_resolved"]) else 1.0
                record_suffix = hashlib.sha256(stable_id.encode("utf-8")).hexdigest()[:12]
                records.append(DatasetRecord(record_id=f"history-{rule_id.lower()}-{record_suffix}", dataset_id=dataset_id, kind=record_kind, entity=entity, collected_at_utc=collected_at, source=DeepSource(api="EventManager.QueryEvents", collector="pyvmomi.deep", collected_at_utc=collected_at), selector={"rule_id": rule_id}, window=DeepWindow(start=(event_meta or {}).get("window_start") or (datetime.now(UTC) - timedelta(days=30)).replace(microsecond=0).isoformat().replace("+00:00", "Z"), end=(event_meta or {}).get("window_end") or collected_at, sample_count=len(grouped_records), expected_sample_count=expected_count, completeness=completeness), value=len(grouped_records), unit="count", raw_pointer=f"events/event.ndjson#{rule_id}/{stable_id}", finding=bool(grouped_records) and rule_id != "NET-DEEP-001", summary=f"真实事件窗口内该对象匹配到 {len(grouped_records)} 条相关事件。" if grouped["object_resolved"] else "真实事件命中规则，但无法唯一解析对象身份。", metadata={"rule_id": rule_id, "event_filter": tokens, "event_samples": event_samples, "entity_scope": "resolved_object" if grouped["object_resolved"] else "unresolved_environment_aggregate", "resolved_object_event_count": len(grouped_records) if grouped["object_resolved"] else 0, "unresolved_object_event_count": 0 if grouped["object_resolved"] else len(grouped_records), "collection_degraded": degraded, "degraded_reason": (event_meta or {}).get("reason") if degraded else None}))

        correlation_window_seconds = max(1, int(correlation_window_seconds))
        matched_event_indexes: set[int] = set()
        unresolved_event_indexes: set[int] = set()
        occurrences_by_object: dict[str, dict[tuple[int, str], dict[str, Any]]] = {}
        for event_index, (event, text) in enumerate(text_items):
            timestamp = getattr(event, "createdTime", None) or getattr(event, "time", None)
            matched_rule_ids = []
            for rule_id, tokens in groups.items():
                # NET-DEEP-001 evaluates a sequence across a time window, not a single event.
                # Link state failures enter correlation under NET-DEEP-002 instead.
                if rule_id == "NET-DEEP-001":
                    continue
                if event_matches_rule(rule_id, tokens, text):
                    matched_rule_ids.append(rule_id)
            if not matched_rule_ids:
                continue
            matched_event_indexes.add(event_index)
            if not hasattr(timestamp, "astimezone"):
                unresolved_event_indexes.add(event_index)
                continue
            event_time = timestamp.astimezone(UTC).replace(microsecond=0)
            event_objects: dict[str, DeepEntity] = {}
            for rule_id in matched_rule_ids:
                for entity in resolved_event_object_ids(event, allow_name_fallback=True):
                    event_objects[entity.stable_id] = entity
            if not event_objects:
                unresolved_event_indexes.add(event_index)
                continue
            message = str(getattr(event, "fullFormattedMessage", None) or getattr(event, "message", "") or "")[:240]
            event_key = getattr(event, "key", None)
            for entity in event_objects.values():
                object_occurrences = occurrences_by_object.setdefault(entity.stable_id, {})
                occurrence_key = (event_index, entity.stable_id)
                occurrence = object_occurrences.setdefault(occurrence_key, {"timestamp": event_time, "entity": entity, "rule_ids": set(), "event_key": event_key, "event_type": type(event).__name__, "message": message})
                occurrence["rule_ids"].update(matched_rule_ids)

        event_occurrences = [item for values in occurrences_by_object.values() for item in values.values()]
        event_occurrences.sort(key=lambda item: (item["timestamp"], item["entity"].stable_id))
        clusters: list[dict[str, Any]] = []
        for object_id, occurrences in occurrences_by_object.items():
            ordered = sorted(occurrences.values(), key=lambda item: item["timestamp"])
            current: list[dict[str, Any]] = []

            def append_cluster(items: list[dict[str, Any]]) -> None:
                if len(items) < 2:
                    return
                rule_ids = sorted({rule_id for item in items for rule_id in item["rule_ids"]})
                if len({rule_id.split("-", 1)[0] for rule_id in rule_ids}) < 2:
                    return
                entity = items[0]["entity"]
                clusters.append({"entity_id": entity.stable_id, "entity_type": entity.type, "entity": entity.display_ref, "start": items[0]["timestamp"].isoformat().replace("+00:00", "Z"), "end": items[-1]["timestamp"].isoformat().replace("+00:00", "Z"), "rule_ids": rule_ids, "event_count": len(items), "event_keys": [item["event_key"] for item in items if item["event_key"] is not None], "samples": [item["message"] for item in items[:10] if item["message"]]})

            for occurrence in ordered:
                if current and occurrence["timestamp"] - current[0]["timestamp"] > timedelta(seconds=correlation_window_seconds):
                    append_cluster(current)
                    current = []
                current.append(occurrence)
            append_cluster(current)
        correlation_entity = self._environment_entity()
        resolved_event_count = len({event_index for values in occurrences_by_object.values() for event_index, _object_id in values})
        unresolved_event_count = len(unresolved_event_indexes)
        total_correlated_event_count = len(matched_event_indexes)
        completeness = 0.0 if self.cancel_requested() or ((event_meta or {}).get("degraded")) else (resolved_event_count / total_correlated_event_count if total_correlated_event_count else 1.0)
        event_samples = [{"timestamp": item["timestamp"].isoformat().replace("+00:00", "Z"), "entity_id": item["entity"].stable_id, "entity": item["entity"].display_ref, "rule_ids": sorted(item["rule_ids"]), "event_type": item["event_type"], "event_key": item["event_key"], "message": item["message"]} for item in event_occurrences[:20]]
        records.append(DatasetRecord(record_id="history-cross-domain-correlation", dataset_id=dataset_id, kind="event", entity=correlation_entity, collected_at_utc=collected_at, source=DeepSource(api="EventManager.QueryEvents", collector="pyvmomi.deep.correlation", collected_at_utc=collected_at), selector={"rule_id": "HIST-DEEP-001", "window_hours": round(correlation_window_seconds / 3600, 6), "window_seconds": correlation_window_seconds}, window=DeepWindow(start=(event_meta or {}).get("window_start") or (datetime.now(UTC) - timedelta(days=30)).replace(microsecond=0).isoformat().replace("+00:00", "Z"), end=(event_meta or {}).get("window_end") or collected_at, sample_count=total_correlated_event_count, expected_sample_count=max(total_correlated_event_count, int((event_meta or {}).get("collector_cap") or total_correlated_event_count)) if (event_meta or {}).get("degraded") else total_correlated_event_count, completeness=completeness), value={"cluster_count": len(clusters), "clusters": clusters, "event_count": total_correlated_event_count, "resolved_event_count": resolved_event_count, "unresolved_object_event_count": unresolved_event_count}, unit="count", raw_pointer="events/event.ndjson#cross-domain-correlation", finding=bool(clusters), summary=f"历史事件中按稳定对象发现 {len(clusters)} 个跨域时间关联簇。" if clusters else f"历史事件未形成同一对象的跨域时间关联簇（对象未解析 {unresolved_event_count} 条）。", metadata={"rule_id": "HIST-DEEP-001", "correlation_window_hours": round(correlation_window_seconds / 3600, 6), "correlation_window_seconds": correlation_window_seconds, "unresolved_object_event_count": unresolved_event_count, "source_rule_ids": sorted(groups), "event_samples": event_samples, "collection_degraded": bool((event_meta or {}).get("degraded"))}))
        return records

    @staticmethod
    def _event_sample(event: Any) -> dict[str, Any]:
        timestamp = getattr(event, "createdTime", None) or getattr(event, "time", None)
        object_ids, object_names = event_object_references(event)
        host_argument = getattr(event, "host", None)
        host_name = getattr(host_argument, "name", None) or (host_argument if isinstance(host_argument, str) else None)
        return {
            "timestamp": timestamp.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z") if hasattr(timestamp, "astimezone") else None,
            "event_type": type(event).__name__,
            "event_key": getattr(event, "key", None),
            "entity": next(iter(sorted(object_names)), None),
            "host": str(host_name) if host_name else None,
            "object_ids": sorted(object_ids),
            "object_names": sorted(object_names),
            "message": str(getattr(event, "fullFormattedMessage", None) or getattr(event, "message", "") or "")[:240],
        }

    def _diagnostic_privilege_state(self, content: Any, hosts: list[Any], attempts: list[dict[str, Any]]) -> dict[str, bool] | None:
        authorization = getattr(content, "authorizationManager", None)
        checker = getattr(authorization, "HasUserPrivilegeOnEntities", None) if authorization is not None else None
        root_folder = getattr(content, "rootFolder", None)
        session_manager = getattr(content, "sessionManager", None)
        current_session = getattr(session_manager, "currentSession", None) if session_manager is not None else None
        username = str(getattr(current_session, "userName", "") or "")
        if checker is None or root_folder is None or not username:
            attempts.append({"source": "vim.AuthorizationManager.HasUserPrivilegeOnEntities", "scope": "vcenter+esxi_hosts", "started_at": now_utc_iso(), "finished_at": now_utc_iso(), "status": "not_available"})
            return None
        entities = [root_folder, *hosts]
        started = now_utc_iso()
        try:
            results = list(checker(entities=entities, userName=username, privId=["Global.Diagnostics"]) or [])
        except Exception as exc:  # noqa: BLE001 - permission preflight must fall back to the bounded direct probes.
            attempts.append({"source": "vim.AuthorizationManager.HasUserPrivilegeOnEntities", "scope": "vcenter+esxi_hosts", "started_at": started, "finished_at": now_utc_iso(), "status": "error", "error_type": type(exc).__name__})
            return None
        if len(results) != len(entities):
            attempts.append({"source": "vim.AuthorizationManager.HasUserPrivilegeOnEntities", "scope": "vcenter+esxi_hosts", "started_at": started, "finished_at": now_utc_iso(), "status": "incomplete", "entity_count": len(entities), "result_count": len(results)})
            return None
        privileges_by_moid: dict[str, bool] = {}
        for entity, result in zip(entities, results, strict=True):
            entity_id = str(getattr(entity, "_moId", "") or getattr(entity, "value", "") or "")
            availability = next(
                (
                    item
                    for item in (getattr(result, "privAvailability", []) or [])
                    if str(getattr(item, "privId", "") or "") == "Global.Diagnostics"
                ),
                None,
            )
            if not entity_id or availability is None:
                attempts.append({"source": "vim.AuthorizationManager.HasUserPrivilegeOnEntities", "scope": "vcenter+esxi_hosts", "started_at": started, "finished_at": now_utc_iso(), "status": "incomplete", "entity_count": len(entities), "result_count": len(results)})
                return None
            privileges_by_moid[entity_id] = bool(getattr(availability, "isGranted", False))
        attempts.append(
            {
                "source": "vim.AuthorizationManager.HasUserPrivilegeOnEntities",
                "scope": "vcenter+esxi_hosts",
                "started_at": started,
                "finished_at": now_utc_iso(),
                "status": "ok",
                "privilege_id": "Global.Diagnostics",
                "entity_count": len(entities),
                "granted_count": sum(privileges_by_moid.values()),
                "denied_count": sum(not value for value in privileges_by_moid.values()),
            }
        )
        return privileges_by_moid

    @staticmethod
    def _map_esxi_log_credentials(hosts: list[Any], credentials: list[EsxiHostConnectionInfo]) -> tuple[dict[str, EsxiHostConnectionInfo], dict[str, Any]]:
        """Map workbook credentials only through a unique exact endpoint/name match."""
        mapped: dict[str, EsxiHostConnectionInfo] = {}
        used_rows: set[int] = set()
        ambiguous_host_count = 0
        for host in hosts:
            moid = str(getattr(host, "_moId", "") or "")
            if not moid:
                continue
            identities = {
                str(getattr(host, "name", "") or "").strip().casefold(),
                str(getattr(getattr(getattr(host, "summary", None), "config", None), "name", "") or "").strip().casefold(),
            }
            try:
                network = getattr(getattr(host, "config", None), "network", None)
                for vnic in getattr(network, "vnic", []) or []:
                    address = getattr(getattr(getattr(vnic, "spec", None), "ip", None), "ipAddress", None)
                    if address:
                        identities.add(str(address).strip().casefold())
            except Exception:  # noqa: BLE001 - missing host network data only makes the row unmappable.
                pass
            identities.discard("")
            matches = [credential for credential in credentials if credential.host.strip().casefold() in identities or credential.host_alias.strip().casefold() in identities]
            distinct = {(item.host.casefold(), item.username, item.password, item.port, item.ssl_verify) for item in matches}
            if len(distinct) == 1 and matches:
                mapped[moid] = matches[0]
                used_rows.update(id(item) for item in matches)
            elif len(distinct) > 1:
                ambiguous_host_count += 1
        status = "ok" if mapped and len(mapped) == len(hosts) and not ambiguous_host_count else "partial" if mapped else "unavailable"
        return mapped, {
            "source": "workbook.esxi_host_credentials",
            "scope": "esxi_inventory",
            "status": status,
            "credential_row_count": len(credentials),
            "mapped_host_count": len(mapped),
            "unmapped_host_count": max(0, len(hosts) - len(mapped)),
            "ambiguous_host_count": ambiguous_host_count,
            "unmatched_credential_row_count": max(0, len(credentials) - len(used_rows)),
        }

    def _collect_historical_logs(self, content: Any, hosts: list[Any], dataset_id: str, collected_at: str, policy: DeepCollectionPolicy, events: list[Any], *, resource_guard: Callable[[], str | None] | None = None) -> tuple[list[DatasetRecord], dict[str, Any]]:
        from vstacklens.collection.powercli_backend import BackendUnavailable, PowerCliBackend

        records: list[DatasetRecord] = []
        attempts: list[dict[str, Any]] = []
        fallback_by_host: dict[str, list[str]] = {}
        fallback_vcenter: list[str] = []
        file_budget = {"max_files": max(0, int(policy.max_log_files)), "attempted": 0}
        total_log_cap = max(0, int(policy.max_log_total_bytes))
        primary_log_cap = min(max(0, int(policy.max_log_primary_bytes)), total_log_cap)
        fallback_log_cap = min(max(0, int(policy.max_log_fallback_bytes)), max(0, total_log_cap - primary_log_cap))
        log_cutoff_utc = None
        if policy.log_collection_days is not None:
            collected_datetime = datetime.fromisoformat(str(collected_at).replace("Z", "+00:00"))
            if collected_datetime.tzinfo is None:
                collected_datetime = collected_datetime.replace(tzinfo=UTC)
            log_cutoff_utc = collected_datetime.astimezone(UTC) - timedelta(days=policy.log_collection_days)
        dedupe_records: list[DatasetRecord] = []
        primary_byte_budget: dict[str, Any] = {"max_bytes": primary_log_cap, "used_bytes": 0, "probe_bytes": 0, "dedupe_records": dedupe_records, "log_window_cutoff_utc": log_cutoff_utc, "log_window_days": policy.log_collection_days}
        fallback_byte_budget: dict[str, Any] = {"max_bytes": fallback_log_cap, "used_bytes": 0, "probe_bytes": 0, "dedupe_records": dedupe_records, "log_window_cutoff_utc": log_cutoff_utc, "log_window_days": policy.log_collection_days}
        max_file_bytes = max(0, int(policy.max_log_file_bytes))
        ordered_hosts = sorted(hosts, key=lambda host: (str(getattr(host, "name", "")).casefold(), str(getattr(host, "_moId", ""))))

        def add_limited_records(entity: DeepEntity, categories: list[str], status: str, source: str) -> None:
            if not categories:
                return
            payloads = [{"key": category, "status": status, "reason": status, "lines": [], "source": source} for category in categories]
            records.extend(normalize_powercli_logs(dataset_id=dataset_id, entity=entity, collected_at=collected_at, payloads=payloads, max_file_bytes=max_file_bytes, byte_budget=primary_byte_budget))

        manager = getattr(content, "diagnosticManager", None)
        if manager is None:
            records.extend(normalize_powercli_logs(dataset_id=dataset_id, entity=self._environment_entity(), collected_at=collected_at, payloads=[{"key": "vpxd", "status": "interface_unavailable", "reason": "DiagnosticManager missing from ServiceContent", "source": "vim.DiagnosticManager"}], max_file_bytes=max_file_bytes, byte_budget=primary_byte_budget))
            attempts.append({"source": "vim.DiagnosticManager", "scope": "vcenter", "started_at": now_utc_iso(), "finished_at": now_utc_iso(), "status": "interface_unavailable"})
            fallback_vcenter = list(VCENTER_LOG_CATEGORIES)
            for host in ordered_hosts:
                    fallback_by_host[str(getattr(host, "_moId", ""))] = list(LOG_CATEGORIES)
                    records.extend(normalize_powercli_logs(dataset_id=dataset_id, entity=self._entity(host, "HostSystem"), collected_at=collected_at, payloads=unavailable_log_payloads("interface_unavailable"), max_file_bytes=max_file_bytes, byte_budget=primary_byte_budget))
        else:
            privilege_state = self._diagnostic_privilege_state(content, ordered_hosts, attempts)
            root_folder = getattr(content, "rootFolder", None)
            root_moid = str(getattr(root_folder, "_moId", "") or getattr(root_folder, "value", "") or "") if root_folder is not None else ""
            root_missing_privilege = "Global.Diagnostics" if privilege_state is not None and privilege_state.get(root_moid) is False else None
            global_records, global_attempts, fallback_vcenter = self._read_diagnostic_log_scope(manager, None, self._environment_entity(), VCENTER_LOG_CATEGORIES, dataset_id, collected_at, file_budget=file_budget, byte_budget=primary_byte_budget, max_file_bytes=max_file_bytes, budget_seconds=policy.budget_seconds, resource_guard=resource_guard, preflight_missing_privilege_id=root_missing_privilege)
            records.extend(global_records)
            attempts.extend(global_attempts)
            for host in ordered_hosts:
                entity = self._entity(host, "HostSystem")
                host_id = str(getattr(host, "_moId", ""))
                host_missing_privilege = "Global.Diagnostics" if privilege_state is not None and privilege_state.get(host_id) is False else None
                api_records, api_attempts, retry_categories = self._read_diagnostic_log_scope(manager, host, entity, LOG_CATEGORIES, dataset_id, collected_at, file_budget=file_budget, byte_budget=primary_byte_budget, max_file_bytes=max_file_bytes, budget_seconds=policy.budget_seconds, resource_guard=resource_guard, preflight_missing_privilege_id=host_missing_privilege)
                records.extend(api_records)
                attempts.extend(api_attempts)
                if retry_categories:
                    fallback_by_host[host_id] = retry_categories

        remaining_files = max(0, file_budget["max_files"] - file_budget["attempted"])
        remaining_bytes = max(0, fallback_byte_budget["max_bytes"] - fallback_byte_budget["used_bytes"] - fallback_byte_budget["probe_bytes"])
        selected_by_host: dict[str, list[str]] = {}
        selected_vcenter: list[str] = []
        fallback_not_attempted: dict[str, int] = {}
        for category in fallback_vcenter:
            if remaining_files > 0 and remaining_bytes > 0 and max_file_bytes > 0:
                selected_vcenter.append(category)
                remaining_files -= 1
            else:
                status = "file_limit_reached" if remaining_files <= 0 else "total_size_limit_reached" if remaining_bytes <= 0 else "file_size_limit_reached"
                add_limited_records(self._environment_entity(), [category], status, "DeepCollectionPolicy.log_budget")
                fallback_not_attempted[status] = fallback_not_attempted.get(status, 0) + 1
        for host in ordered_hosts:
            host_id = str(getattr(host, "_moId", ""))
            for category in fallback_by_host.get(host_id, []):
                if remaining_files > 0 and remaining_bytes > 0 and max_file_bytes > 0:
                    selected_by_host.setdefault(host_id, []).append(category)
                    remaining_files -= 1
                else:
                    status = "file_limit_reached" if remaining_files <= 0 else "total_size_limit_reached" if remaining_bytes <= 0 else "file_size_limit_reached"
                    add_limited_records(self._entity(host, "HostSystem"), [category], status, "DeepCollectionPolicy.log_budget")
                    fallback_not_attempted[status] = fallback_not_attempted.get(status, 0) + 1
        for reason, count in sorted(fallback_not_attempted.items()):
            attempts.append({"source": "PowerCLI.Get-Log", "scope": "vcenter+esxi_hosts", "status": "not_attempted", "reason": reason, "category_count": count})
        selected_fallback_count = len(selected_vcenter) + sum(len(categories) for categories in selected_by_host.values())
        fallback_keys = sorted({category for categories in selected_by_host.values() for category in categories})
        fallback_stop_reason = resource_guard() if resource_guard else None
        if selected_fallback_count and fallback_stop_reason:
            attempts.append({"source": "resource_guard", "scope": "vcenter+esxi_hosts", "started_at": now_utc_iso(), "finished_at": now_utc_iso(), "status": fallback_stop_reason, "categories": fallback_keys, "vcenter_categories": selected_vcenter})
            for category in selected_vcenter:
                add_limited_records(self._environment_entity(), [category], fallback_stop_reason, "DeepCollectionPolicy.resource_guard")
            for host in ordered_hosts:
                host_id = str(getattr(host, "_moId", ""))
                add_limited_records(self._entity(host, "HostSystem"), selected_by_host.get(host_id, []), fallback_stop_reason, "DeepCollectionPolicy.resource_guard")
        elif selected_fallback_count and policy.log_collection_days is not None:
            reason = "PowerCLI.Get-Log cannot seek to a requested timestamp; not called to avoid reading unbounded older lines"
            attempts.append({"source": "PowerCLI.Get-Log", "scope": "vcenter+esxi_hosts", "status": "not_attempted", "reason": "time_window_seek_not_supported_by_backend", "details": reason, "category_count": selected_fallback_count})
            for category in selected_vcenter:
                add_limited_records(self._environment_entity(), [category], "time_window_seek_not_supported", "DeepCollectionPolicy.time_window")
            for host in ordered_hosts:
                host_id = str(getattr(host, "_moId", ""))
                add_limited_records(self._entity(host, "HostSystem"), selected_by_host.get(host_id, []), "time_window_seek_not_supported", "DeepCollectionPolicy.time_window")
        elif selected_fallback_count and time.perf_counter() - self._collection_started_at < policy.budget_seconds:
            backend = PowerCliBackend(self.host, self.username, self.password, timeout=min(60, policy.budget_seconds), request_timeout=30, retry_attempts=1, cancel_requested=self.cancel_requested, stop_reason=resource_guard)
            attempt_started = now_utc_iso()
            fallback_hosts = [host for host in ordered_hosts if selected_by_host.get(str(getattr(host, "_moId", "")))]
            try:
                backend.prepare(fallback_hosts, log_keys=fallback_keys, log_keys_by_host=selected_by_host, vcenter_log_keys=selected_vcenter, include_esxcli=False, max_log_files=selected_fallback_count, max_log_file_bytes=max_file_bytes, max_log_total_bytes=remaining_bytes)
                file_budget["attempted"] += int(getattr(backend, "log_file_attempt_count", selected_fallback_count))
            except BackendUnavailable as exc:
                file_budget["attempted"] += selected_fallback_count
                reason = str(exc) or "powercli_unavailable"
                attempts.append({"source": "PowerCLI.Get-Log", "scope": "vcenter+esxi_hosts", "started_at": attempt_started, "finished_at": now_utc_iso(), "status": reason, "host_count": len(fallback_hosts), "fallback_categories": fallback_keys, "vcenter_fallback_categories": selected_vcenter})
                if selected_vcenter:
                    records.extend(normalize_powercli_logs(dataset_id=dataset_id, entity=self._environment_entity(), collected_at=collected_at, payloads=unavailable_log_payloads(reason, tuple(selected_vcenter)), max_file_bytes=max_file_bytes, byte_budget=fallback_byte_budget))
                for host in ordered_hosts:
                    categories = selected_by_host.get(str(getattr(host, "_moId", "")), [])
                    if categories:
                        records.extend(normalize_powercli_logs(dataset_id=dataset_id, entity=self._entity(host, "HostSystem"), collected_at=collected_at, payloads=unavailable_log_payloads(reason, tuple(categories)), max_file_bytes=max_file_bytes, byte_budget=fallback_byte_budget))
            except Exception as exc:  # noqa: BLE001 - log fallback must not abort other collectors.
                file_budget["attempted"] += selected_fallback_count
                reason = classify_log_fault(exc)
                attempts.append({"source": "PowerCLI.Get-Log", "scope": "vcenter+esxi_hosts", "started_at": attempt_started, "finished_at": now_utc_iso(), "status": reason, "host_count": len(fallback_hosts), "fallback_categories": fallback_keys, "vcenter_fallback_categories": selected_vcenter})
                if selected_vcenter:
                    records.extend(normalize_powercli_logs(dataset_id=dataset_id, entity=self._environment_entity(), collected_at=collected_at, payloads=unavailable_log_payloads(reason, tuple(selected_vcenter)), max_file_bytes=max_file_bytes, byte_budget=fallback_byte_budget))
                for host in ordered_hosts:
                    categories = selected_by_host.get(str(getattr(host, "_moId", "")), [])
                    if categories:
                        records.extend(normalize_powercli_logs(dataset_id=dataset_id, entity=self._entity(host, "HostSystem"), collected_at=collected_at, payloads=unavailable_log_payloads(reason, tuple(categories)), max_file_bytes=max_file_bytes, byte_budget=fallback_byte_budget))
            else:
                fallback_record_start = len(records)
                fallback_used_before = int(fallback_byte_budget.get("used_bytes", 0))
                fallback_source_bytes_read = 0
                scope_failures: list[dict[str, str]] = []

                def payload_bytes(payloads: list[dict[str, Any]]) -> int:
                    total = 0
                    for payload in payloads:
                        try:
                            reported = int(payload.get("retained_bytes") or 0)
                        except (TypeError, ValueError):
                            reported = 0
                        if reported:
                            total += reported
                        else:
                            total += sum(len(str(line).encode("utf-8")) for line in payload.get("lines") or [])
                    return total

                if selected_vcenter:
                    try:
                        by_category = {str(item.get("key") or ""): item for item in backend.get_vcenter_logs()}
                        payloads = [by_category.get(category) or {"key": category, "status": "interface_unavailable", "reason": "PowerCLI returned no vCenter log result", "lines": [], "source": "PowerCLI.Get-Log"} for category in selected_vcenter]
                    except Exception as exc:  # noqa: BLE001 - isolate vCenter log decoding from host log results.
                        reason = str(exc) if isinstance(exc, BackendUnavailable) else classify_log_fault(exc)
                        payloads = unavailable_log_payloads(reason, tuple(selected_vcenter))
                        scope_failures.append({"scope": "vcenter", "status": reason})
                    fallback_source_bytes_read += payload_bytes(payloads)
                    records.extend(normalize_powercli_logs(dataset_id=dataset_id, entity=self._environment_entity(), collected_at=collected_at, payloads=payloads, max_file_bytes=max_file_bytes, byte_budget=fallback_byte_budget))
                for host in ordered_hosts:
                    host_id = str(getattr(host, "_moId", ""))
                    categories = selected_by_host.get(host_id, [])
                    if not categories:
                        continue
                    try:
                        payload_by_category = {str(item.get("key") or ""): item for item in backend(host).get_logs()}
                        payloads = [payload_by_category.get(category) or {"key": category, "status": "interface_unavailable", "reason": "PowerCLI returned no log result", "lines": [], "source": "PowerCLI.Get-Log"} for category in categories]
                    except Exception as exc:  # noqa: BLE001 - one host log failure must not skip other hosts.
                        reason = str(exc) if isinstance(exc, BackendUnavailable) else classify_log_fault(exc)
                        payloads = unavailable_log_payloads(reason, tuple(categories))
                        scope_failures.append({"scope": "host", "entity_id": host_id, "status": reason})
                    fallback_source_bytes_read += payload_bytes(payloads)
                    records.extend(normalize_powercli_logs(dataset_id=dataset_id, entity=self._entity(host, "HostSystem"), collected_at=collected_at, payloads=payloads, max_file_bytes=max_file_bytes, byte_budget=fallback_byte_budget))
                fallback_records = records[fallback_record_start:]
                fallback_retained_bytes = int(fallback_byte_budget.get("used_bytes", 0)) - fallback_used_before
                fallback_byte_budget["probe_bytes"] = int(fallback_byte_budget.get("probe_bytes", 0)) + max(0, fallback_source_bytes_read - fallback_retained_bytes)
                status_counts: dict[str, int] = {}
                for record in fallback_records:
                    current_status = str(record.metadata.get("log_status") or "error")
                    status_counts[current_status] = status_counts.get(current_status, 0) + 1
                fallback_status = "permission_denied" if status_counts and sum(status_counts.values()) == status_counts.get("permission_denied", 0) else "ok" if status_counts and sum(count for key, count in status_counts.items() if key in {"ok", "empty"}) == sum(status_counts.values()) and not any(record.metadata.get("truncated") for record in fallback_records) else "partial" if status_counts else "empty"
                attempts.append({"source": "PowerCLI.Get-Log", "scope": "vcenter+esxi_hosts", "started_at": attempt_started, "finished_at": now_utc_iso(), "status": fallback_status, "connection_status": "connected", "host_count": len(fallback_hosts), "fallback_from": "vim.DiagnosticManager", "fallback_categories": fallback_keys, "vcenter_fallback_categories": fallback_vcenter, "result_count": len(fallback_records), "source_bytes_read": fallback_source_bytes_read, "retained_bytes": fallback_retained_bytes, "result_status_counts": status_counts, "scope_failures": scope_failures, "warnings": list(backend.warnings)})
        elif selected_fallback_count:
            attempts.append({"source": "resource_guard", "scope": "vcenter+esxi_hosts", "started_at": now_utc_iso(), "finished_at": now_utc_iso(), "status": "budget_exceeded", "categories": fallback_keys, "vcenter_categories": fallback_vcenter})
            if selected_vcenter:
                records.extend(normalize_powercli_logs(dataset_id=dataset_id, entity=self._environment_entity(), collected_at=collected_at, payloads=unavailable_log_payloads("budget_exceeded", tuple(selected_vcenter)), max_file_bytes=max_file_bytes, byte_budget=fallback_byte_budget))
            for host in ordered_hosts:
                categories = selected_by_host.get(str(getattr(host, "_moId", "")), [])
                if categories:
                    records.extend(normalize_powercli_logs(dataset_id=dataset_id, entity=self._entity(host, "HostSystem"), collected_at=collected_at, payloads=unavailable_log_payloads("budget_exceeded", tuple(categories)), max_file_bytes=max_file_bytes, byte_budget=fallback_byte_budget))

        if not selected_fallback_count and not any(item.get("source") == "PowerCLI.Get-Log" for item in attempts):
            attempts.append({"source": "PowerCLI.Get-Log", "scope": "vcenter+esxi_hosts", "status": "not_attempted", "reason": "no missing or incomplete categories required a fallback read"})

        direct_log_records, direct_log_attempts = self._collect_direct_esxi_log_fallback(
            ordered_hosts,
            records,
            dataset_id,
            collected_at,
            policy,
            file_budget=file_budget,
            byte_budget=fallback_byte_budget,
            max_file_bytes=max_file_bytes,
            resource_guard=resource_guard,
        )
        records.extend(direct_log_records)
        attempts.extend(direct_log_attempts)

        host_object_aliases = {
            str(getattr(host, "_moId")): self._entity(host, "HostSystem").stable_id
            for host in hosts
            if getattr(host, "_moId", None)
        }
        correlate_log_records(records, events, window_seconds=policy.correlation_window_seconds, object_id_aliases=host_object_aliases, event_rule_ids=self._event_rule_ids_by_identity)
        status_by_category: dict[tuple[str, str], list[DatasetRecord]] = {}
        for record in records:
            status_by_category.setdefault((record.entity.stable_id, str(record.metadata.get("log_category") or "unknown")), []).append(record)
        complete_groups = sum(1 for group_records in status_by_category.values() if any(str(record.metadata.get("log_status")) in {"ok", "empty"} and not record.metadata.get("truncated") for record in group_records))
        partial_groups = sum(1 for group_records in status_by_category.values() if not any(str(record.metadata.get("log_status")) in {"ok", "empty"} and not record.metadata.get("truncated") for record in group_records) and any(str(record.metadata.get("log_status")) == "partial" or record.metadata.get("truncated") for record in group_records))
        covered = complete_groups + partial_groups
        category_count = len(status_by_category)
        overall = "ok" if category_count and complete_groups == category_count else "partial" if covered else "unavailable"
        segment_read_count = sum(int(item.get("page_count") or 0) for item in attempts if str(item.get("source", "")).endswith("BrowseDiagnosticLog"))
        primary_bytes = int(primary_byte_budget["used_bytes"])
        fallback_bytes = int(fallback_byte_budget["used_bytes"])
        primary_source_bytes = primary_bytes + int(primary_byte_budget.get("probe_bytes", 0))
        fallback_source_bytes = fallback_bytes + int(fallback_byte_budget.get("probe_bytes", 0))
        window_statuses = Counter(str(item.get("time_window_status")) for item in attempts if item.get("time_window_status"))
        time_window_status = "not_limited" if log_cutoff_utc is None else "complete" if window_statuses and all(value in {"complete", "complete_reached_file_start", "complete_with_unknown_time", "complete_no_recent_rows", "complete_no_log_rows"} for value in window_statuses) else "partial"
        return records, {"action": "logs.history", "status": "partial" if policy.log_collection_days is not None and overall == "ok" else overall, "source": "vim.DiagnosticManager/PowerCLI.Get-Log/DirectESXi", "category_count": category_count, "source_record_count": len(records), "successful_count": complete_groups, "partially_successful_count": partial_groups, "covered_category_count": covered, "requested_log_days": policy.log_collection_days, "log_window_cutoff_utc": log_cutoff_utc.isoformat().replace("+00:00", "Z") if log_cutoff_utc else None, "time_window_status": time_window_status, "time_window_status_counts": dict(window_statuses), "time_unknown_line_count": sum(int(record.metadata.get("time_unknown_line_count") or 0) for record in records), "time_window_excluded_line_count": sum(int(record.metadata.get("time_window_excluded_line_count") or 0) for record in records), "deduplicated_source_line_count": sum(int(record.metadata.get("duplicate_line_count") or 0) for record in records), "missing_privilege_ids": sorted({str(record.metadata.get("missing_privilege_id")) for record in records if record.metadata.get("missing_privilege_id")}), "categories": [*LOG_CATEGORIES, *VCENTER_LOG_CATEGORIES], "attempts": attempts, "file_read_attempt_count": file_budget["attempted"], "segment_read_count": segment_read_count, "max_log_files": file_budget["max_files"], "retained_log_bytes": primary_bytes + fallback_bytes, "source_log_bytes_read": primary_source_bytes + fallback_source_bytes, "retained_primary_log_bytes": primary_bytes, "retained_fallback_log_bytes": fallback_bytes, "source_primary_log_bytes_read": primary_source_bytes, "source_fallback_log_bytes_read": fallback_source_bytes, "max_log_file_bytes": max_file_bytes, "max_log_total_bytes": total_log_cap, "max_log_primary_bytes": primary_log_cap, "max_log_fallback_bytes": fallback_log_cap, "truncated_count": sum(1 for record in records if record.metadata.get("truncated")), "budget_limited_count": sum(1 for record in records if record.metadata.get("log_status") in {"file_limit_reached", "file_size_limit_reached", "total_size_limit_reached"})}

    def _collect_direct_esxi_log_fallback(
        self,
        hosts: list[Any],
        existing_records: list[DatasetRecord],
        dataset_id: str,
        collected_at: str,
        policy: DeepCollectionPolicy,
        *,
        file_budget: dict[str, int],
        byte_budget: dict[str, Any],
        max_file_bytes: int,
        resource_guard: Callable[[], str | None] | None,
    ) -> tuple[list[DatasetRecord], list[dict[str, Any]]]:
        direct_records: list[DatasetRecord] = []
        attempts: list[dict[str, Any]] = []
        if not self.host_log_credentials:
            attempts.append({"source": "workbook.esxi_host_credentials", "scope": "esxi_inventory", "status": "unavailable", "reason": "no per-host credentials supplied"})
            attempts.append({"source": "vim.DiagnosticManager.DirectESXi", "scope": "esxi_hosts", "status": "not_attempted", "reason": "no per-host credentials supplied"})
            return direct_records, attempts
        credential_by_host, mapping_attempt = self._map_esxi_log_credentials(hosts, self.host_log_credentials)
        attempts.append(mapping_attempt)
        if not credential_by_host:
            attempts.append({"source": "vim.DiagnosticManager.DirectESXi", "scope": "esxi_hosts", "status": "not_attempted", "reason": "no workbook host credential row mapped to an inventoried host"})
            return direct_records, attempts

        from pyVim.connect import Disconnect, SmartConnect

        direct_source = "vim.DiagnosticManager.DirectESXi.BrowseDiagnosticLog"
        for host in hosts:
            host_id = str(getattr(host, "_moId", "") or "")
            credential = credential_by_host.get(host_id)
            if credential is None:
                continue
            entity = self._entity(host, "HostSystem")
            already_ok = {
                str(record.metadata.get("log_category") or "")
                for record in existing_records + direct_records
                if record.entity.stable_id == entity.stable_id and record.metadata.get("log_status") in {"ok", "empty"} and not record.metadata.get("truncated")
            }
            categories = tuple(category for category in LOG_CATEGORIES if category not in already_ok)
            attempt_scope = f"direct_esxi:{entity.stable_id}"
            started = now_utc_iso()
            if not categories:
                attempts.append({"source": "vim.DiagnosticManager.DirectESXi", "scope": attempt_scope, "status": "not_needed", "reason": "all host log categories already have non-empty successful records"})
                continue
            if max_file_bytes <= 0 or file_budget["attempted"] >= file_budget["max_files"] or byte_budget["used_bytes"] + int(byte_budget.get("probe_bytes", 0)) >= byte_budget["max_bytes"]:
                status = "file_size_limit_reached" if max_file_bytes <= 0 else "file_limit_reached" if file_budget["attempted"] >= file_budget["max_files"] else "total_size_limit_reached"
                payloads = [{"key": category, "status": status, "reason": status, "lines": [], "source": "DeepCollectionPolicy.log_budget"} for category in categories]
                direct_records.extend(normalize_powercli_logs(dataset_id=dataset_id, entity=entity, collected_at=collected_at, payloads=payloads, max_file_bytes=max_file_bytes, byte_budget=byte_budget))
                attempts.append({"source": "vim.DiagnosticManager.DirectESXi", "scope": attempt_scope, "started_at": started, "finished_at": now_utc_iso(), "status": status, "connection_status": "not_attempted", "category_count": len(categories)})
                continue
            stop_reason = resource_guard() if resource_guard else None
            if stop_reason:
                payloads = [{"key": category, "status": stop_reason, "reason": stop_reason, "lines": [], "source": "DeepCollectionPolicy.resource_guard"} for category in categories]
                direct_records.extend(normalize_powercli_logs(dataset_id=dataset_id, entity=entity, collected_at=collected_at, payloads=payloads, max_file_bytes=max_file_bytes, byte_budget=byte_budget))
                attempts.append({"source": "vim.DiagnosticManager.DirectESXi", "scope": attempt_scope, "started_at": started, "finished_at": now_utc_iso(), "status": stop_reason, "category_count": len(categories)})
                continue
            if time.perf_counter() - self._collection_started_at >= policy.budget_seconds:
                status = "budget_exceeded"
                payloads = [{"key": category, "status": status, "reason": status, "lines": [], "source": "DeepCollectionPolicy.resource_guard"} for category in categories]
                direct_records.extend(normalize_powercli_logs(dataset_id=dataset_id, entity=entity, collected_at=collected_at, payloads=payloads, max_file_bytes=max_file_bytes, byte_budget=byte_budget))
                attempts.append({"source": "vim.DiagnosticManager.DirectESXi", "scope": attempt_scope, "started_at": started, "finished_at": now_utc_iso(), "status": status, "category_count": len(categories)})
                continue

            direct_si = None
            try:
                direct_si = SmartConnect(
                    host=credential.host,
                    user=credential.username,
                    pwd=credential.password,
                    port=credential.port,
                    sslContext=None if credential.ssl_verify else ssl._create_unverified_context(),  # noqa: SLF001
                    httpConnectionTimeout=30,
                )
                direct_content = direct_si.RetrieveContent()
                manager = getattr(direct_content, "diagnosticManager", None)
                if manager is None:
                    payloads = [{"key": category, "status": "interface_unavailable", "reason": "DiagnosticManager missing from direct ESXi ServiceContent", "lines": [], "source": direct_source} for category in categories]
                    direct_records.extend(normalize_powercli_logs(dataset_id=dataset_id, entity=entity, collected_at=collected_at, payloads=payloads, max_file_bytes=max_file_bytes, byte_budget=byte_budget))
                    attempts.append({"source": "vim.DiagnosticManager.DirectESXi", "scope": attempt_scope, "started_at": started, "finished_at": now_utc_iso(), "status": "interface_unavailable", "connection_status": "connected", "category_count": len(categories)})
                    continue

                scoped_records, scoped_attempts, _unused_fallback_categories = self._read_diagnostic_log_scope(
                    manager,
                    None,
                    entity,
                    categories,
                    dataset_id,
                    collected_at,
                    file_budget=file_budget,
                    byte_budget=byte_budget,
                    max_file_bytes=max_file_bytes,
                    budget_seconds=policy.budget_seconds,
                    resource_guard=resource_guard,
                    direct_host_scope=True,
                    attempt_scope=attempt_scope,
                )
                direct_records.extend(scoped_records)
                attempts.extend(scoped_attempts)
                status_counts: dict[str, int] = {}
                for record in scoped_records:
                    status = str(record.metadata.get("log_status") or "error")
                    status_counts[status] = status_counts.get(status, 0) + 1
                successful = sum(status_counts.get(status, 0) for status in ("ok", "empty"))
                partial = status_counts.get("partial", 0)
                if successful == len(categories) and not any(record.metadata.get("truncated") for record in scoped_records):
                    direct_status = "ok"
                elif successful or partial:
                    direct_status = "partial"
                elif status_counts and set(status_counts) == {"permission_denied"}:
                    direct_status = "permission_denied"
                else:
                    direct_status = "unavailable"
                attempts.append({"source": "vim.DiagnosticManager.DirectESXi", "scope": attempt_scope, "started_at": started, "finished_at": now_utc_iso(), "status": direct_status, "connection_status": "connected", "category_count": len(categories), "result_status_counts": status_counts})
            except Exception as exc:  # noqa: BLE001 - one host direct-read failure must not abort other sources.
                status = classify_log_fault(exc)
                privilege_id = str(getattr(exc, "privilegeId", "") or "").strip() or None
                payloads = [
                    {"key": category, "status": status, "reason": status, "lines": [], "source": direct_source, **({"missing_privilege_id": privilege_id} if privilege_id else {})}
                    for category in categories
                ]
                direct_records.extend(normalize_powercli_logs(dataset_id=dataset_id, entity=entity, collected_at=collected_at, payloads=payloads, max_file_bytes=max_file_bytes, byte_budget=byte_budget))
                attempts.append({"source": "vim.DiagnosticManager.DirectESXi", "scope": attempt_scope, "started_at": started, "finished_at": now_utc_iso(), "status": status, "error_type": type(exc).__name__, **({"missing_privilege_id": privilege_id} if privilege_id else {})})
            finally:
                if direct_si is not None:
                    try:
                        Disconnect(direct_si)
                    except Exception:
                        pass
        return direct_records, attempts

    def _browse_diagnostic_log_pages(
        self,
        manager: Any,
        host: Any | None,
        descriptor_key: str,
        *,
        max_file_bytes: int,
        remaining_total_bytes: int,
        budget_seconds: int,
        resource_guard: Callable[[], str | None] | None,
    ) -> dict[str, Any]:
        lines: list[str] = []
        source_line_numbers: list[int] = []
        truncation_reasons: set[str] = set()
        byte_count = 0
        page_count = 0
        returned_line_count = 0
        cursor = 0
        last_line_number: int | None = None
        first_line_number: int | None = None
        pagination_complete = False
        stop_status: str | None = None
        error_status: str | None = None
        error_type: str | None = None
        missing_privilege_id: str | None = None
        duplicate_line_count = 0

        def as_int(value: Any, default: int | None = None) -> int | None:
            try:
                return int(value) if value is not None else default
            except (TypeError, ValueError):
                return default

        while len(lines) < MAX_LOG_LINES_PER_FILE:
            stop_status = resource_guard() if resource_guard else None
            collection_started = getattr(self, "_collection_started_at", None)
            if not stop_status and collection_started is not None and time.perf_counter() - collection_started >= budget_seconds:
                stop_status = "budget_exceeded"
            if stop_status:
                truncation_reasons.add(stop_status)
                break
            if byte_count >= max_file_bytes:
                truncation_reasons.add("file_size_limit")
                break
            if byte_count >= remaining_total_bytes:
                truncation_reasons.add("total_size_limit")
                break

            page_start_requested = cursor
            try:
                kwargs = {"key": descriptor_key, "start": page_start_requested, "lines": MAX_LOG_LINES_PER_PAGE}
                if host is not None:
                    kwargs["host"] = host
                page = manager.BrowseDiagnosticLog(**kwargs)
            except Exception as exc:  # noqa: BLE001 - preserve the API fault class without serializing its raw text.
                error_status = classify_log_fault(exc)
                error_type = type(exc).__name__
                missing_privilege_id = str(getattr(exc, "privilegeId", "") or "").strip() or None
                break

            page_count += 1
            page_lines = [str(value) for value in (getattr(page, "lineText", []) or [])]
            returned_line_count += len(page_lines)
            if not page_lines:
                pagination_complete = True
                break

            page_start = as_int(getattr(page, "lineStart", None), page_start_requested)
            if page_start is None:
                page_start = page_start_requested
            page_end = as_int(getattr(page, "lineEnd", None), page_start + len(page_lines) - 1)
            if page_end is None or page_end < page_start:
                page_end = page_start + len(page_lines) - 1
            if page_end - page_start + 1 != len(page_lines):
                truncation_reasons.add("line_index_range_mismatch")

            if last_line_number is not None:
                expected_start = last_line_number + 1
                if page_start > expected_start:
                    truncation_reasons.add("line_index_gap")

            stop_for_size = False
            for offset, raw_line in enumerate(page_lines):
                source_line_number = page_start + offset
                if last_line_number is not None and source_line_number <= last_line_number:
                    duplicate_line_count += 1
                    continue

                line = raw_line[:MAX_LOG_LINE_CHARS]
                if line != raw_line:
                    truncation_reasons.add("line_character_limit")
                encoded = line.encode("utf-8")
                available_file_bytes = max_file_bytes - byte_count
                available_total_bytes = remaining_total_bytes - byte_count
                available_bytes = min(available_file_bytes, available_total_bytes)
                if len(encoded) > available_bytes:
                    line = encoded[:max(0, available_bytes)].decode("utf-8", errors="ignore")
                    encoded = line.encode("utf-8")
                    reason = "total_size_limit" if available_total_bytes <= available_file_bytes else "file_size_limit"
                    truncation_reasons.add(reason)
                    stop_for_size = True
                if line:
                    lines.append(line)
                    source_line_numbers.append(source_line_number)
                    byte_count += len(encoded)
                    first_line_number = source_line_number if first_line_number is None else first_line_number
                    last_line_number = source_line_number
                if stop_for_size:
                    break
                if len(lines) >= MAX_LOG_LINES_PER_FILE:
                    truncation_reasons.add("line_count_limit")
                    stop_for_size = True
                    break

            if stop_for_size:
                break
            if last_line_number is None or page_end < page_start_requested or page_end < last_line_number:
                truncation_reasons.add("pagination_no_progress")
                break
            next_cursor = page_end + 1
            if next_cursor <= page_start_requested:
                truncation_reasons.add("pagination_no_progress")
                break
            cursor = next_cursor

        if error_status:
            status = "partial" if lines else error_status
            reason = error_status
            if lines:
                truncation_reasons.add(error_status)
        elif stop_status:
            status = "partial" if lines else stop_status
            reason = stop_status
        elif truncation_reasons:
            status = "partial" if lines else "unavailable"
            reason = sorted(truncation_reasons)[0]
        elif pagination_complete:
            status = "ok" if lines else "empty"
            reason = None
        else:
            status = "partial" if lines else "empty"
            reason = "pagination_incomplete"

        return {
            "status": status,
            "reason": reason,
            "lines": lines,
            "source_line_numbers": source_line_numbers,
            "line_start": first_line_number,
            "line_end": last_line_number,
            "page_count": page_count,
            "returned_line_count": returned_line_count,
            "retained_bytes": byte_count,
            "source_bytes_read": byte_count,
            "truncated": bool(truncation_reasons) or not pagination_complete,
            "truncation_reasons": sorted(truncation_reasons),
            "pagination_complete": pagination_complete,
            "duplicate_line_count": duplicate_line_count,
            "error_type": error_type,
            "missing_privilege_id": missing_privilege_id,
        }

    def _browse_diagnostic_log_window_pages(
        self,
        manager: Any,
        host: Any | None,
        descriptor_key: str,
        *,
        cutoff_utc: datetime,
        max_file_bytes: int,
        remaining_total_bytes: int,
        budget_seconds: int,
        resource_guard: Callable[[], str | None] | None,
    ) -> dict[str, Any]:
        """Read backward from the verified log tail and stop once older pages begin."""
        cutoff_utc = cutoff_utc.astimezone(UTC)
        cutoff_epoch = cutoff_utc.timestamp()
        backstep_tolerance_seconds = 5.0
        lines_by_number: dict[int, str] = {}
        source_bytes_read = 0
        retained_bytes = 0
        page_count = 0
        locator_call_count = 0
        scanned_line_count = 0
        out_of_window_line_count = 0
        unknown_time_line_count = 0
        order_violation_count = 0
        truncation_reasons: set[str] = set()
        error_status: str | None = None
        error_type: str | None = None
        missing_privilege_id: str | None = None
        total_line_count: int | None = None
        newer_page_min_timestamp: float | None = None
        window_complete = False
        time_window_status = "time_seek_unavailable"

        def call_browse(start: int, count: int) -> Any:
            kwargs = {"key": descriptor_key, "start": start, "lines": count}
            if host is not None:
                kwargs["host"] = host
            return manager.BrowseDiagnosticLog(**kwargs)

        guard_status = resource_guard() if resource_guard else None
        if guard_status:
            return {
                "status": guard_status, "reason": guard_status, "lines": [], "source_line_numbers": [],
                "truncated": True, "truncation_reasons": [guard_status], "page_count": 0,
                "returned_line_count": 0, "retained_bytes": 0, "source_bytes_read": 0,
                "pagination_complete": False, "time_window_status": "stopped_by_resource_guard",
                "time_window_complete": False, "total_line_count": None, "locator_call_count": 0,
                "scanned_line_count": 0, "out_of_window_line_count": 0, "unknown_time_line_count": 0,
                "order_violation_count": 0,
            }
        if time.perf_counter() - self._collection_started_at >= budget_seconds:
            return {
                "status": "budget_exceeded", "reason": "budget_exceeded", "lines": [], "source_line_numbers": [],
                "truncated": True, "truncation_reasons": ["budget_exceeded"], "page_count": 0,
                "returned_line_count": 0, "retained_bytes": 0, "source_bytes_read": 0,
                "pagination_complete": False, "time_window_status": "stopped_by_time_budget",
                "time_window_complete": False, "total_line_count": None, "locator_call_count": 0,
                "scanned_line_count": 0, "out_of_window_line_count": 0, "unknown_time_line_count": 0,
                "order_violation_count": 0,
            }

        try:
            locator_call_count += 1
            header = call_browse(2_147_483_647, 1)
            header_lines = list(getattr(header, "lineText", []) or [])
            line_start = int(getattr(header, "lineStart", 0) or 0)
            line_end = int(getattr(header, "lineEnd", 0) or 0)
            if header_lines:
                # Some vSphere releases clamp an oversized start to the final row.
                total_line_count = max(line_start, line_end)
                for offset, raw_line in enumerate(header_lines):
                    number = line_start + offset if line_start > 0 else max(1, total_line_count - len(header_lines) + offset + 1)
                    value = str(raw_line)[:MAX_LOG_LINE_CHARS]
                    encoded_size = len(value.encode("utf-8"))
                    timestamp = parse_log_line_timestamp(value)
                    if timestamp is None:
                        unknown_time_line_count += 1
                        lines_by_number[number] = value
                        retained_bytes += encoded_size
                    elif timestamp.timestamp() >= cutoff_epoch:
                        lines_by_number[number] = value
                        retained_bytes += encoded_size
                    else:
                        out_of_window_line_count += 1
                    source_bytes_read += encoded_size
                    scanned_line_count += 1
                if header_lines:
                    page_count += 1
                    returned_line_count += len(header_lines)
                    header_times = [parse_log_line_timestamp(str(line)) for line in header_lines]
                    header_times = [value.timestamp() for value in header_times if value is not None]
                    if header_times:
                        newer_page_min_timestamp = min(header_times)
            elif line_end >= 0 and (line_start == 0 or line_start == line_end + 1):
                # Observed vCenter and ESXi behavior: an empty out-of-range response
                # returns the last line number in lineEnd (lineStart may be 0 or end+1).
                total_line_count = max(line_end, line_start - 1, 0)
            else:
                return {
                    "status": "time_seek_unavailable", "reason": "log_tail_line_count_not_reported", "lines": [],
                    "source_line_numbers": [], "truncated": False, "truncation_reasons": [], "page_count": 0,
                    "returned_line_count": len(header_lines), "retained_bytes": retained_bytes,
                    "source_bytes_read": source_bytes_read, "pagination_complete": False,
                    "time_window_status": "seek_unavailable", "time_window_complete": False,
                    "total_line_count": None, "locator_call_count": locator_call_count,
                    "scanned_line_count": scanned_line_count, "out_of_window_line_count": out_of_window_line_count,
                    "unknown_time_line_count": unknown_time_line_count, "order_violation_count": 0,
                }
        except Exception as exc:  # noqa: BLE001 - a failed tail locator must not trigger a full-file download.
            error_status = classify_log_fault(exc)
            error_type = type(exc).__name__
            missing_privilege_id = str(getattr(exc, "privilegeId", "") or "").strip() or None
            return {
                "status": error_status, "reason": "time_seek_locator_failed", "error_type": error_type,
                "missing_privilege_id": missing_privilege_id, "lines": [], "source_line_numbers": [],
                "truncated": False, "truncation_reasons": [], "page_count": 0, "returned_line_count": 0,
                "retained_bytes": 0, "source_bytes_read": 0, "pagination_complete": False,
                "time_window_status": "seek_unavailable", "time_window_complete": False,
                "total_line_count": None, "locator_call_count": locator_call_count,
                "scanned_line_count": 0, "out_of_window_line_count": 0, "unknown_time_line_count": 0,
                "order_violation_count": 0,
            }

        if total_line_count is None:
            return {
                "status": "time_seek_unavailable", "reason": "log_tail_line_count_not_reported", "lines": [],
                "source_line_numbers": [], "truncated": False, "truncation_reasons": [], "page_count": 0,
                "returned_line_count": 0, "retained_bytes": retained_bytes, "source_bytes_read": source_bytes_read,
                "pagination_complete": False, "time_window_status": "seek_unavailable", "time_window_complete": False,
                "total_line_count": None, "locator_call_count": locator_call_count,
                "scanned_line_count": scanned_line_count, "out_of_window_line_count": out_of_window_line_count,
                "unknown_time_line_count": unknown_time_line_count, "order_violation_count": 0,
            }
        if total_line_count <= 0:
            return {
                "status": "empty", "reason": "empty_log_file", "lines": [], "source_line_numbers": [],
                "truncated": False, "truncation_reasons": [], "page_count": 0, "returned_line_count": 0,
                "retained_bytes": 0, "source_bytes_read": 0, "pagination_complete": True,
                "time_window_status": "complete_no_log_rows", "time_window_complete": True,
                "total_line_count": 0, "locator_call_count": locator_call_count,
                "scanned_line_count": 0, "out_of_window_line_count": 0, "unknown_time_line_count": 0,
                "order_violation_count": 0,
            }

        cursor = max(0, total_line_count - len(header_lines))
        returned_line_count = len(header_lines)
        if cursor < 1:
            window_complete = True
            time_window_status = "complete_with_unknown_time" if unknown_time_line_count else "complete_reached_file_start"
        stop_reason: str | None = None
        while cursor >= 1:
            stop_reason = resource_guard() if resource_guard else None
            if not stop_reason and time.perf_counter() - self._collection_started_at >= budget_seconds:
                stop_reason = "budget_exceeded"
            if stop_reason:
                truncation_reasons.add(stop_reason)
                time_window_status = "stopped_by_resource_guard"
                break
            remaining_source_bytes = min(max_file_bytes - source_bytes_read, remaining_total_bytes - source_bytes_read)
            if remaining_source_bytes <= 0:
                stop_reason = "file_size_limit" if max_file_bytes - source_bytes_read <= 0 else "total_size_limit"
                truncation_reasons.add(stop_reason)
                time_window_status = "budget_limited"
                break
            # Bound bytes per returned row so a tail page cannot overshoot the
            # per-file or shared byte budget. The 7-day path also caps UTF-8 row
            # bytes below the existing character limit.
            line_size_bound = MAX_LOG_LINE_CHARS
            if remaining_source_bytes < line_size_bound:
                stop_reason = "file_size_limit" if max_file_bytes - source_bytes_read <= remaining_total_bytes - source_bytes_read else "total_size_limit"
                truncation_reasons.add(stop_reason)
                time_window_status = "budget_limited"
                break
            safe_page_lines = max(1, remaining_source_bytes // line_size_bound)
            requested_lines = min(MAX_LOG_LINES_PER_PAGE, cursor, safe_page_lines)
            requested_start = cursor - requested_lines + 1
            try:
                page = call_browse(requested_start, requested_lines)
            except Exception as exc:  # noqa: BLE001 - preserve status but never fall back to a full file read.
                error_status = classify_log_fault(exc)
                error_type = type(exc).__name__
                missing_privilege_id = str(getattr(exc, "privilegeId", "") or "").strip() or None
                truncation_reasons.add(error_status)
                time_window_status = "read_failed"
                break
            page_count += 1
            page_lines = [str(value) for value in (getattr(page, "lineText", []) or [])]
            returned_line_count += len(page_lines)
            if not page_lines:
                # A line count inferred from the sentinel must be addressable.
                truncation_reasons.add("line_index_gap")
                time_window_status = "line_range_unavailable"
                break
            page_start = int(getattr(page, "lineStart", requested_start) or requested_start)
            page_end = int(getattr(page, "lineEnd", page_start + len(page_lines) - 1) or (page_start + len(page_lines) - 1))
            if page_end - page_start + 1 != len(page_lines) or page_end != cursor or page_start > requested_start:
                truncation_reasons.add("line_index_range_mismatch")
                time_window_status = "line_range_unreliable"
                break

            page_times: list[float] = []
            page_previous_timestamp: float | None = None
            page_bytes = 0
            page_unknown_count = 0
            page_old_count = 0
            page_recent_count = 0
            for offset, raw_line in enumerate(page_lines):
                source_line_number = page_start + offset
                line = raw_line[:MAX_LOG_LINE_CHARS]
                encoded = line.encode("utf-8")
                if len(encoded) > MAX_LOG_LINE_CHARS:
                    line = encoded[:MAX_LOG_LINE_CHARS].decode("utf-8", errors="ignore")
                    encoded = line.encode("utf-8")
                    truncation_reasons.add("line_byte_limit")
                encoded_size = len(encoded)
                page_bytes += encoded_size
                timestamp = parse_log_line_timestamp(line)
                if timestamp is None:
                    unknown_time_line_count += 1
                    page_unknown_count += 1
                    lines_by_number[source_line_number] = line
                    retained_bytes += encoded_size
                    continue
                stamp = timestamp.timestamp()
                page_times.append(stamp)
                if page_previous_timestamp is not None and stamp < page_previous_timestamp - backstep_tolerance_seconds:
                    order_violation_count += 1
                page_previous_timestamp = stamp
                if stamp >= cutoff_epoch:
                    page_recent_count += 1
                    lines_by_number[source_line_number] = line
                    retained_bytes += encoded_size
                else:
                    page_old_count += 1
                    out_of_window_line_count += 1
            source_bytes_read += page_bytes
            scanned_line_count += len(page_lines)
            if page_times and newer_page_min_timestamp is not None and max(page_times) > newer_page_min_timestamp + backstep_tolerance_seconds:
                order_violation_count += 1
            if page_times:
                newer_page_min_timestamp = min(page_times)
            if order_violation_count:
                truncation_reasons.add("time_order_unreliable")
                time_window_status = "order_unreliable"
                break
            if page_times and max(page_times) < cutoff_epoch - backstep_tolerance_seconds:
                window_complete = True
                time_window_status = "complete_with_unknown_time" if unknown_time_line_count else "complete"
                break
            cursor = page_start - 1
            if cursor < 1:
                window_complete = True
                time_window_status = "complete_with_unknown_time" if unknown_time_line_count else "complete_reached_file_start"
                break
            if page_bytes > remaining_source_bytes:
                stop_reason = "total_size_limit"
                truncation_reasons.add(stop_reason)
                time_window_status = "budget_limited"
                break

        sorted_rows = sorted(lines_by_number.items())
        retained_lines = [line for _line_number, line in sorted_rows]
        retained_line_numbers = [line_number for line_number, _line in sorted_rows]
        if time_window_status == "time_seek_unavailable" and error_status:
            status = error_status
        elif time_window_status == "budget_limited":
            status = "partial" if retained_lines else ("file_size_limit_reached" if stop_reason == "file_size_limit" else "total_size_limit_reached")
        elif time_window_status == "stopped_by_resource_guard":
            status = "partial" if retained_lines else (stop_reason or "budget_exceeded")
        elif time_window_status in {"order_unreliable", "line_range_unavailable", "line_range_unreliable", "read_failed"}:
            status = "partial" if retained_lines else (error_status or "time_window_unavailable")
        elif not retained_lines and window_complete:
            status = "empty"
            time_window_status = "complete_no_recent_rows"
        elif unknown_time_line_count or not window_complete:
            status = "partial" if retained_lines else "time_window_unavailable"
        else:
            status = "ok"
        reason = error_status or stop_reason
        if status == "empty" and reason is None:
            reason = "no log rows matched the requested time window"
        return {
            "status": status,
            "reason": reason,
            "lines": retained_lines,
            "source_line_numbers": retained_line_numbers,
            "line_start": retained_line_numbers[0] if retained_line_numbers else None,
            "line_end": retained_line_numbers[-1] if retained_line_numbers else None,
            "page_count": page_count,
            "locator_call_count": locator_call_count,
            "total_line_count": total_line_count,
            "returned_line_count": returned_line_count,
            "scanned_line_count": scanned_line_count,
            "retained_bytes": retained_bytes,
            "source_bytes_read": source_bytes_read,
            "out_of_window_line_count": out_of_window_line_count,
            "unknown_time_line_count": unknown_time_line_count,
            "order_violation_count": order_violation_count,
            "pagination_complete": window_complete,
            "time_window_complete": window_complete,
            "time_window_status": time_window_status,
            "truncated": bool(truncation_reasons) or not window_complete,
            "truncation_reasons": sorted(truncation_reasons),
            **({"error_type": error_type} if error_type else {}),
            **({"missing_privilege_id": missing_privilege_id} if missing_privilege_id else {}),
        }

    def _read_diagnostic_log_scope(self, manager: Any, host: Any | None, entity: DeepEntity, categories: tuple[str, ...], dataset_id: str, collected_at: str, *, file_budget: dict[str, int] | None = None, byte_budget: dict[str, Any] | None = None, max_file_bytes: int = MAX_LOG_FILE_BYTES, budget_seconds: int = 1800, resource_guard: Callable[[], str | None] | None = None, preflight_missing_privilege_id: str | None = None, direct_host_scope: bool = False, attempt_scope: str | None = None) -> tuple[list[DatasetRecord], list[dict[str, Any]], list[str]]:
        file_budget = file_budget if file_budget is not None else {"max_files": MAX_LOG_FILES, "attempted": 0}
        byte_budget = byte_budget if byte_budget is not None else {"max_bytes": MAX_LOG_TOTAL_BYTES, "used_bytes": 0, "probe_bytes": 0}
        scope = attempt_scope or ("vcenter" if host is None else str(getattr(host, "name", "host")))
        descriptor_scope = "host" if direct_host_scope or host is not None else "vcenter"
        query_source = "vim.DiagnosticManager.DirectESXi.QueryDescriptions" if direct_host_scope else "vim.DiagnosticManager.QueryDescriptions"
        source = "vim.DiagnosticManager.DirectESXi.BrowseDiagnosticLog" if direct_host_scope else "vim.DiagnosticManager.BrowseDiagnosticLog"
        started = now_utc_iso()
        stop_reason = resource_guard() if resource_guard else None
        preflight_skipped = False
        if stop_reason:
            query_status = stop_reason
            descriptors = []
            missing_privilege_id = None
        elif preflight_missing_privilege_id:
            query_status = "permission_denied"
            descriptors = []
            missing_privilege_id = preflight_missing_privilege_id
            preflight_skipped = True
        else:
            try:
                descriptors = list((manager.QueryDescriptions(host=host) if host is not None else manager.QueryDescriptions()) or [])
                descriptors = descriptors[:max(len(categories) * 4, len(categories))]
                query_status = "ok"
                missing_privilege_id = None
            except Exception as exc:  # noqa: BLE001 - permission/interface status is retained per category.
                query_status = classify_log_fault(exc)
                descriptors = []
                missing_privilege_id = str(getattr(exc, "privilegeId", "") or "").strip() or None
        finished = now_utc_iso()
        attempts = [{"source": query_source, "scope": scope, "started_at": started, "finished_at": finished, "status": "not_attempted" if preflight_skipped else query_status, "reason": "effective privilege preflight denied access" if preflight_skipped else None, "descriptor_count": len(descriptors), **({"missing_privilege_id": missing_privilege_id} if missing_privilege_id else {})}]
        confirmed_global_diagnostics_denial = query_status == "permission_denied" and missing_privilege_id == "Global.Diagnostics"
        if confirmed_global_diagnostics_denial and not direct_host_scope:
            attempts.append({"source": "PowerCLI.Get-Log", "scope": scope, "status": "not_attempted", "reason": "required privilege missing for DiagnosticManager log access", "missing_privilege_id": missing_privilege_id})
        descriptor_by_category: dict[str, Any] = {}
        descriptor_category_counts: dict[str, int] = {}
        for descriptor in descriptors:
            category = log_category_for_descriptor(descriptor, scope=descriptor_scope)
            category_key = category or "unclassified"
            descriptor_category_counts[category_key] = descriptor_category_counts.get(category_key, 0) + 1
            if category in categories and category not in descriptor_by_category:
                descriptor_by_category[category] = descriptor
        if attempts:
            attempts[0]["descriptor_category_counts"] = descriptor_category_counts
            attempts[0]["unclassified_descriptor_count"] = descriptor_category_counts.get("unclassified", 0)
        payloads: list[dict[str, Any]] = []
        scope_reserved_bytes = 0
        scope_read_bytes = 0
        fallback_categories: list[str] = []
        for category in categories:
            descriptor = descriptor_by_category.get(category)
            if query_status != "ok":
                payloads.append({"key": category, "status": query_status, "reason": query_status, "lines": [], "source": source, **({"missing_privilege_id": missing_privilege_id} if missing_privilege_id else {})})
                if query_status not in RESOURCE_GUARD_STATUSES and not confirmed_global_diagnostics_denial:
                    fallback_categories.append(category)
                continue
            if descriptor is None:
                payloads.append({"key": category, "status": "no_logs", "reason": "no matching diagnostic log descriptor", "lines": [], "source": source})
                fallback_categories.append(category)
                continue
            if max_file_bytes <= 0:
                payloads.append({"key": category, "status": "file_size_limit_reached", "reason": "max_log_file_bytes", "lines": [], "source": "DeepCollectionPolicy.log_budget"})
                attempts.append({"source": source, "scope": scope, "category": category, "started_at": now_utc_iso(), "finished_at": now_utc_iso(), "status": "file_size_limit_reached"})
                continue
            if file_budget["attempted"] >= file_budget["max_files"]:
                payloads.append({"key": category, "status": "file_limit_reached", "reason": "max_log_files", "lines": [], "source": "DeepCollectionPolicy.log_budget"})
                attempts.append({"source": source, "scope": scope, "category": category, "started_at": now_utc_iso(), "finished_at": now_utc_iso(), "status": "file_limit_reached"})
                continue
            remaining_total_bytes = max(0, int(byte_budget["max_bytes"]) - int(byte_budget["used_bytes"]) - int(byte_budget.get("probe_bytes", 0)) - scope_reserved_bytes)
            if remaining_total_bytes <= 0:
                payloads.append({"key": category, "status": "total_size_limit_reached", "reason": "max_log_total_bytes", "lines": [], "source": "DeepCollectionPolicy.log_budget"})
                attempts.append({"source": source, "scope": scope, "category": category, "started_at": now_utc_iso(), "finished_at": now_utc_iso(), "status": "total_size_limit_reached"})
                if not direct_host_scope:
                    fallback_categories.append(category)
                continue
            stop_reason = resource_guard() if resource_guard else None
            if stop_reason:
                payloads.append({"key": category, "status": stop_reason, "reason": stop_reason, "lines": [], "source": "DeepCollectionPolicy.resource_guard"})
                attempts.append({"source": "resource_guard", "scope": scope, "category": category, "started_at": now_utc_iso(), "finished_at": now_utc_iso(), "status": stop_reason})
                continue
            file_budget["attempted"] += 1
            browse_started = now_utc_iso()
            cutoff_utc = byte_budget.get("log_window_cutoff_utc")
            if cutoff_utc is not None:
                page_result = self._browse_diagnostic_log_window_pages(
                    manager,
                    host,
                    str(descriptor.key),
                    cutoff_utc=cutoff_utc,
                    max_file_bytes=max_file_bytes,
                    remaining_total_bytes=remaining_total_bytes,
                    budget_seconds=budget_seconds,
                    resource_guard=resource_guard,
                )
            else:
                page_result = self._browse_diagnostic_log_pages(
                    manager,
                    host,
                    str(descriptor.key),
                    max_file_bytes=max_file_bytes,
                    remaining_total_bytes=remaining_total_bytes,
                    budget_seconds=budget_seconds,
                    resource_guard=resource_guard,
                )
            page_source_bytes = int(page_result.get("source_bytes_read", page_result["retained_bytes"]))
            scope_reserved_bytes += page_source_bytes
            scope_read_bytes += page_source_bytes
            browse_finished = now_utc_iso()
            browse_privilege_id = page_result.get("missing_privilege_id")
            file_name = str(getattr(descriptor, "fileName", "") or "")
            creator = str(getattr(descriptor, "creator", "") or "")
            payloads.append(
                {
                    "key": category,
                    "status": page_result["status"],
                    "reason": page_result.get("reason"),
                    "lines": page_result["lines"],
                    "source_line_numbers": page_result["source_line_numbers"],
                    "truncated": page_result["truncated"],
                    "truncation_reasons": page_result["truncation_reasons"],
                    "source": source,
                    "file_name": file_name,
                    "creator": creator,
                    "started_at": browse_started,
                    "finished_at": browse_finished,
                    "line_start": page_result.get("line_start"),
                    "line_end": page_result.get("line_end"),
                    "page_count": page_result["page_count"],
                    "pagination_complete": page_result["pagination_complete"],
                    "time_window_status": page_result.get("time_window_status", "not_limited"),
                    "time_window_complete": page_result.get("time_window_complete"),
                    "total_line_count": page_result.get("total_line_count"),
                    "scanned_line_count": page_result.get("scanned_line_count"),
                    "time_window_excluded_line_count": page_result.get("out_of_window_line_count", 0),
                    "out_of_window_line_count": page_result.get("out_of_window_line_count", 0),
                    "unknown_time_line_count": page_result.get("unknown_time_line_count", 0),
                    "source_bytes_read": page_source_bytes,
                    "locator_call_count": page_result.get("locator_call_count", 0),
                    **({"missing_privilege_id": browse_privilege_id} if browse_privilege_id else {}),
                }
            )
            browse_status = str(page_result["status"])
            page_reason = str(page_result.get("reason") or "")
            page_attempt = {
                "source": source,
                "scope": scope,
                "category": category,
                "started_at": browse_started,
                "finished_at": browse_finished,
                "status": browse_status,
                "file_name": file_name,
                "creator": creator,
                "page_count": page_result["page_count"],
                "requested_lines_per_page": MAX_LOG_LINES_PER_PAGE,
                "returned_line_count": page_result["returned_line_count"],
                "retained_line_count": len(page_result["lines"]),
                "retained_bytes": page_result["retained_bytes"],
                "line_start": page_result.get("line_start"),
                "line_end": page_result.get("line_end"),
                "pagination_complete": page_result["pagination_complete"],
                "truncated": page_result["truncated"],
                "truncation_reasons": page_result["truncation_reasons"],
                "duplicate_line_count": page_result.get("duplicate_line_count", 0),
                "source_bytes_read": page_source_bytes,
                "time_window_status": page_result.get("time_window_status", "not_limited"),
                "time_window_complete": page_result.get("time_window_complete"),
                "total_line_count": page_result.get("total_line_count"),
                "scanned_line_count": page_result.get("scanned_line_count"),
                "out_of_window_line_count": page_result.get("out_of_window_line_count", 0),
                "unknown_time_line_count": page_result.get("unknown_time_line_count", 0),
                "locator_call_count": page_result.get("locator_call_count", 0),
            }
            if page_result.get("error_type"):
                page_attempt["error_type"] = page_result["error_type"]
            if browse_privilege_id:
                page_attempt["missing_privilege_id"] = browse_privilege_id
            attempts.append(page_attempt)

            if page_result.get("error_type"):
                if page_reason == "permission_denied" and browse_privilege_id == "Global.Diagnostics" and not direct_host_scope:
                    attempts.append({"source": "PowerCLI.Get-Log", "scope": scope, "category": category, "status": "not_attempted", "reason": "required privilege missing for DiagnosticManager log access", "missing_privilege_id": browse_privilege_id})
                else:
                    fallback_categories.append(category)
            elif browse_status == "empty":
                fallback_categories.append(category)
            elif page_reason in {"pagination_no_progress", "pagination_incomplete", "line_index_gap", "line_index_range_mismatch"}:
                fallback_categories.append(category)
            elif page_result.get("time_window_status") in {"seek_unavailable", "order_unreliable", "line_range_unavailable", "line_range_unreliable", "read_failed", "budget_limited"}:
                fallback_categories.append(category)

        used_before_normalize = int(byte_budget.get("used_bytes", 0))
        records = normalize_powercli_logs(dataset_id=dataset_id, entity=entity, collected_at=collected_at, payloads=payloads, max_file_bytes=max_file_bytes, byte_budget=byte_budget, max_lines=MAX_LOG_LINES_PER_FILE)
        retained_bytes_from_scope = int(byte_budget.get("used_bytes", 0)) - used_before_normalize
        byte_budget["probe_bytes"] = int(byte_budget.get("probe_bytes", 0)) + max(0, scope_read_bytes - retained_bytes_from_scope)
        return records, attempts, fallback_categories

    def _task_history_records(self, content: Any, dataset_id: str, collected_at: str) -> list[DatasetRecord]:
        manager = getattr(content, "taskManager", None)
        if manager is None:
            return []
        try:
            tasks = list(getattr(manager, "recentTask", []) or [])
        except Exception:
            return []
        failed: list[dict[str, Any]] = []
        for task in tasks:
            info = getattr(task, "info", None)
            state = str(getattr(info, "state", "") or "").lower() if info else ""
            if state in {"error", "failed", "failure"}:
                completed = getattr(info, "completeTime", None) or getattr(info, "queueTime", None)
                timestamp = completed.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z") if hasattr(completed, "astimezone") else None
                failed.append(
                    {
                        "name": str(getattr(info, "name", "task") or "task"),
                        "entity": str(getattr(info, "entityName", "") or ""),
                        "timestamp": timestamp,
                    }
                )
        by_name: dict[str, list[dict[str, Any]]] = {}
        buckets: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for item in failed:
            name = item["name"]
            by_name.setdefault(name, []).append(item)
            if item["timestamp"]:
                bucket = str(item["timestamp"])[:13] + ":00:00Z"
                buckets.setdefault((name, bucket), []).append(item)
        repeated = [
            {"task_name": name, "count": len(items), "entities": sorted({item["entity"] for item in items if item["entity"]})}
            for name, items in by_name.items()
            if len(items) >= TASK_REPEAT_THRESHOLD
        ]
        clusters = [
            {"task_name": name, "window_start": bucket, "count": len(items), "entities": sorted({item["entity"] for item in items if item["entity"]})}
            for (name, bucket), items in buckets.items()
            if len(items) >= TASK_REPEAT_THRESHOLD
        ]
        finding = bool(repeated or clusters)
        if finding:
            summary = f"recentTask 保留窗口内发现 {len(failed)} 条失败任务；重复任务类型 {len(repeated)} 个，时间簇 {len(clusters)} 个。"
        elif failed:
            summary = f"recentTask 保留窗口内发现 {len(failed)} 条失败任务，但未达到重复或时间簇阈值。"
        else:
            summary = "recentTask 保留窗口内未发现失败任务。"
        entity = self._environment_entity()
        return [DatasetRecord(record_id="task-history-recent", dataset_id=dataset_id, kind="task", entity=entity, collected_at_utc=collected_at, source=DeepSource(api="TaskManager.recentTask", collector="pyvmomi.deep", collected_at_utc=collected_at), selector={"rule_id": "TASK-DEEP-001"}, window=DeepWindow(start=collected_at, end=collected_at, sample_count=len(tasks), expected_sample_count=len(tasks), completeness=1.0), value={"failed_count": len(failed), "repeated_task_types": repeated, "time_clusters": clusters}, unit="count", raw_pointer="events/task.ndjson#recentTask", finding=finding, summary=summary, metadata={"rule_id": "TASK-DEEP-001", "retention": "recentTask", "repeat_threshold": TASK_REPEAT_THRESHOLD, "failed_tasks": failed})]

    def _certificate_records(self, hosts: list[Any], dataset_id: str, collected_at: str, *, resource_guard: Callable[[], str | None] | None = None) -> list[DatasetRecord]:
        result: list[DatasetRecord] = []
        expiry_window_days = int(default_threshold_registry().get("TH-LIFECYCLE-EXPIRY-WINDOW").value)

        def append_certificate(entity: DeepEntity, cert: Any, source_name: str, status: str) -> None:
            not_after: datetime | None = None
            if isinstance(cert, datetime):
                not_after = cert.replace(tzinfo=UTC) if cert.tzinfo is None else cert.astimezone(UTC)
            elif cert:
                try:
                    parsed = datetime.fromisoformat(str(cert).replace("Z", "+00:00"))
                    not_after = parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
                except (TypeError, ValueError):
                    status = "unavailable"
            days = (not_after.date() - datetime.now(UTC).date()).days if not_after else None
            value = {
                "certificate_status": status if not not_after else "available",
                "not_after_utc": not_after.replace(microsecond=0).isoformat().replace("+00:00", "Z") if not_after else None,
                "days_remaining": days,
                "source": source_name,
            }
            available = not_after is not None
            finding = bool(available and days is not None and days <= expiry_window_days)
            if available:
                summary = f"管理证书剩余 {days} 天" if days is not None and days >= 0 else f"管理证书已过期 {abs(days or 0)} 天"
            elif status == "not_requested":
                summary = "资源保护线触发，管理证书未读取"
            else:
                summary = "管理证书有效期不可读取，不能判为正常"
            record = self._record(dataset_id, collected_at, "config", entity, "SEC-DEEP-003", value, "date", finding, summary)
            record.source = DeepSource(api=source_name, collector="pyvmomi.deep.certificate", collected_at_utc=collected_at)
            record.window = DeepWindow(start=collected_at, end=collected_at, sample_count=1 if available else 0, expected_sample_count=1, completeness=1.0 if available else 0.0)
            record.metadata["coverage_complete"] = available
            record.metadata["certificate_status"] = value["certificate_status"]
            result.append(record)

        # vCenter serves its management certificate separately from ESXi host certificates.
        stop_reason = resource_guard() if resource_guard else None
        if stop_reason:
            append_certificate(self._environment_entity(), None, "vCenter TLS certificate", "not_requested")
        else:
            cert = self._probe_host_tls_not_after(self.host, resource_guard=resource_guard)
            stop_after_probe = resource_guard() if resource_guard else None
            status = "not_requested" if stop_after_probe and cert is None else "available" if cert else "unavailable"
            append_certificate(self._environment_entity(), cert, "vCenter TLS certificate", status)

        for host in hosts:
            entity = self._entity(host, "HostSystem")
            stop_reason = resource_guard() if resource_guard else None
            if stop_reason:
                append_certificate(entity, None, "ESXi host certificate", "not_requested")
                continue
            cert = None
            try:
                cert = (
                    getattr(getattr(getattr(host, "config", None), "certificateInfo", None), "notAfter", None)
                    or getattr(getattr(getattr(host, "config", None), "certificate", None), "notAfter", None)
                )
            except Exception:  # noqa: BLE001 - one host certificate property must not suppress the other host results.
                cert = None
            source_name = "HostSystem.config.certificateInfo"
            if cert is None:
                cert = self._probe_host_tls_not_after(host, resource_guard=resource_guard)
                source_name = "ESXi TLS peer certificate"
            append_certificate(entity, cert, source_name, "available" if cert else "unavailable")
        return result

    def _probe_host_tls_not_after(self, host: Any, *, resource_guard: Callable[[], str | None] | None = None) -> datetime | None:
        endpoints = []
        name = str(getattr(host, "name", "") or (host if isinstance(host, str) else ""))
        if name:
            endpoints.append(name)
        network = getattr(getattr(host, "config", None), "network", None)
        for vnic in getattr(network, "vnic", []) or []:
            ip = getattr(getattr(getattr(vnic, "spec", None), "ip", None), "ipAddress", None)
            if ip:
                endpoints.append(str(ip))
        for endpoint in dict.fromkeys(endpoints):
            if resource_guard and resource_guard():
                return None
            try:
                with socket.create_connection((endpoint, 443), timeout=5):
                    pass
                if resource_guard and resource_guard():
                    return None
                pem = ssl.get_server_certificate((endpoint, 443), timeout=5)
                with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False, encoding="ascii") as handle:
                    handle.write(pem)
                    cert_path = handle.name
                try:
                    decoded = ssl._ssl._test_decode_cert(cert_path)  # noqa: SLF001 - stdlib certificate metadata fallback
                finally:
                    Path(cert_path).unlink(missing_ok=True)
                value = str(decoded.get("notAfter", "") or "")
                if value:
                    return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), UTC)
            except (OSError, ssl.SSLError, ValueError):
                continue
        return None

    def _snapshot_records(self, vms: list[Any], dataset_id: str, collected_at: str) -> list[DatasetRecord]:
        result: list[DatasetRecord] = []
        for vm in vms:
            entity = self._entity(vm, "VirtualMachine")
            snapshots = getattr(getattr(vm, "snapshot", None), "rootSnapshotList", None) or []
            dates = [getattr(item, "createTime", None) for item in self._walk_snapshots(snapshots)]
            dates = [item for item in dates if item is not None]
            age = max((datetime.now(UTC).date() - item.astimezone(UTC).date()).days for item in dates) if dates else 0
            result.append(self._record(dataset_id, collected_at, "config", entity, "VM-DEEP-001", age, "day", age >= 7, f"maximum snapshot age is {age} days", not_applicable=not bool(snapshots)))
            depth = self._snapshot_chain_depth(snapshots)
            threshold = default_threshold_registry().get("TH-SNAPSHOT-CHAIN-DEPTH").value
            result.append(self._record(dataset_id, collected_at, "config", entity, "VM-DEEP-006", depth, "level", bool(depth >= threshold), f"maximum snapshot chain depth is {depth}", not_applicable=not bool(snapshots)))
        return result

    def _snapshot_chain_depth(self, roots: list[Any]) -> int:
        def depth(items: list[Any], parent_depth: int = 0) -> int:
            maximum = parent_depth
            for item in items:
                maximum = max(maximum, depth(getattr(item, "childSnapshotList", []) or [], parent_depth + 1))
            return maximum

        return depth(roots)

    def _cluster_drift_records(
        self,
        clusters: list[Any],
        dataset_id: str,
        collected_at: str,
        *,
        resource_guard: Callable[[], str | None] | None = None,
    ) -> list[DatasetRecord]:
        result: list[DatasetRecord] = []
        for cluster in clusters:
            entity = self._entity(cluster, "ClusterComputeResource")
            cluster_hosts = list(getattr(cluster, "host", []) or [])
            fingerprints: list[dict[str, Any]] = []
            comparable_fields = ("ntp_servers", "dns_domain", "dns_servers", "syslog_configured", "syslog_target_count")
            syslog_target_sets: dict[str, tuple[str, ...]] = {}
            for host in cluster_hosts:
                host_entity = self._entity(host, "HostSystem")
                stop_reason = resource_guard() if resource_guard else None
                if stop_reason:
                    fingerprints.append({"host_id": host_entity.stable_id, "fields": {key: None for key in comparable_fields}, "unavailable_reason": stop_reason})
                    continue
                config = getattr(host, "config", None)
                date_time_info = getattr(config, "dateTimeInfo", None) if config else None
                ntp_config = getattr(date_time_info, "ntpConfig", None) if date_time_info else None
                ntp_servers = None
                if ntp_config is not None:
                    raw_ntp_servers = getattr(ntp_config, "server", []) or []
                    ntp_servers = sorted(
                        {
                            str(getattr(item, "server", item) or "").strip().casefold()
                            for item in raw_ntp_servers
                            if str(getattr(item, "server", item) or "").strip()
                        }
                    )
                network_config = getattr(config, "network", None) if config else None
                dns_config = getattr(network_config, "dnsConfig", None) if network_config else None
                dns_domain = str(getattr(dns_config, "domainName", "") or "").strip().casefold() if dns_config is not None else None
                dns_servers = None
                if dns_config is not None:
                    dns_servers = sorted({str(item).strip().casefold() for item in getattr(dns_config, "address", []) or [] if str(item).strip()})

                syslog_configured: bool | None = None
                syslog_target_count: int | None = None
                option_values = getattr(config, "option", None) if config else None
                if option_values is None:
                    option_manager = getattr(getattr(host, "configManager", None), "advancedOption", None)
                    if option_manager is not None:
                        stop_reason = resource_guard() if resource_guard else None
                        if stop_reason:
                            syslog_configured = None
                        else:
                            try:
                                option_values = option_manager.QueryOptions()
                            except Exception:  # noqa: BLE001 - advanced option access is a scoped coverage result.
                                option_values = None
                if option_values is not None:
                    options = {str(getattr(item, "key", "") or ""): getattr(item, "value", None) for item in option_values or []}
                    if "Syslog.global.logHost" in options:
                        raw_target = str(options.get("Syslog.global.logHost") or "")
                        target_set = tuple(sorted({item.strip().casefold() for item in raw_target.replace(";", ",").split(",") if item.strip()}))
                        syslog_target_sets[host_entity.stable_id] = target_set
                        syslog_configured = bool(target_set)
                        syslog_target_count = len(target_set)

                fingerprints.append(
                    {
                        "host_id": host_entity.stable_id,
                        "fields": {
                            "ntp_servers": ntp_servers,
                            "dns_domain": dns_domain,
                            "dns_servers": dns_servers,
                            "syslog_configured": syslog_configured,
                            "syslog_target_count": syslog_target_count,
                        },
                    }
                )

            differences: list[dict[str, Any]] = []
            known_field_count = 0
            for field_name in comparable_fields:
                observations = [
                    {"host_id": row["host_id"], "value": row["fields"].get(field_name)}
                    for row in fingerprints
                    if row["fields"].get(field_name) is not None
                ]
                known_field_count += len(observations)
                if len(observations) > 1 and len({json.dumps(item["value"], sort_keys=True, ensure_ascii=False, default=str) for item in observations}) > 1:
                    differences.append({"property": field_name, "observations": observations})

            distinct_syslog_target_sets = set(syslog_target_sets.values())
            if len(distinct_syslog_target_sets) > 1:
                differences.append(
                    {
                        "property": "syslog_target_set",
                        "observations": [
                            {
                                "host_id": host_id,
                                "value": {
                                    "configured": bool(targets),
                                    "target_count": len(targets),
                                    "differs_from_peer": True,
                                },
                            }
                            for host_id, targets in sorted(syslog_target_sets.items())
                        ],
                    }
                )

            expected_field_count = len(cluster_hosts) * len(comparable_fields)
            coverage = known_field_count / expected_field_count if expected_field_count else 1.0
            drift = bool(differences)
            unknown_field_count = max(0, expected_field_count - known_field_count)
            if drift:
                summary = f"同一集群内发现 {len(differences)} 项 NTP/DNS/Syslog 状态差异"
            elif unknown_field_count:
                summary = f"未发现已确认差异，但 {unknown_field_count} 个 NTP/DNS/Syslog 字段不可读取"
            else:
                summary = f"已比较 {len(cluster_hosts)} 台主机的 NTP、DNS 和 Syslog 配置状态，未发现差异"
            record = self._record(
                dataset_id,
                collected_at,
                "config",
                entity,
                "CL-DEEP-001",
                {
                    "host_count": len(cluster_hosts),
                    "compared_field_count": known_field_count,
                    "expected_field_count": expected_field_count,
                    "unknown_field_count": unknown_field_count,
                    "differences": differences,
                    "host_fingerprints": fingerprints,
                    "syslog_target_content_included": False,
                },
                "configuration",
                drift,
                summary,
                not_applicable=len(cluster_hosts) < 2,
            )
            record.window = DeepWindow(
                start=collected_at,
                end=collected_at,
                sample_count=known_field_count,
                expected_sample_count=expected_field_count,
                completeness=coverage,
            )
            record.metadata["coverage_complete"] = unknown_field_count == 0
            result.append(record)
        return result

    def _guest_os_support_records(
        self,
        hosts: list[Any],
        vms: list[Any],
        dataset_id: str,
        collected_at: str,
        *,
        resource_guard: Callable[[], str | None] | None = None,
        progress_callback: Callable[[str, int, int], None] | None = None,
        clusters: list[Any] | None = None,
    ) -> list[DatasetRecord]:
        """Compare each VM Guest OS support level with its current compute resource."""
        cache: dict[tuple[str, str, str], dict[str, Any]] = {}
        browser_cache: dict[tuple[str, str], Any | None] = {}
        resource_scopes: dict[str, dict[str, Any]] = {}
        resource_id_by_host: dict[str, str] = {}
        host_entity_by_id: dict[str, DeepEntity] = {}
        records: list[DatasetRecord] = []

        def resource_id(compute: Any) -> str:
            return str(getattr(compute, "_moId", "") or getattr(compute, "name", "") or (id(compute) if compute is not None else ""))

        def register_resource_scope(compute: Any, fallback_host: Any = None) -> str:
            if compute is None:
                return ""
            compute_id = resource_id(compute)
            if compute_id in resource_scopes:
                return compute_id
            try:
                configured_hosts = list(getattr(compute, "host", []) or [])
                if configured_hosts:
                    target_hosts = []
                    for candidate in configured_hosts:
                        host_id = str(getattr(candidate, "_moId", "") or "")
                        if host_id and host_id not in host_entity_by_id:
                            host_entity_by_id[host_id] = self._entity(candidate, "HostSystem")
                        state = str(getattr(getattr(candidate, "runtime", None), "connectionState", "") or "").casefold()
                        if not state or state == "connected":
                            target_hosts.append(candidate)
                        if host_id:
                            resource_id_by_host[host_id] = compute_id
                    targets: list[tuple[Any, bool]] = [(candidate, True) for candidate in target_hosts]
                    expected_host_count = len(configured_hosts)
                    unqueried_host_count = expected_host_count - len(target_hosts)
                elif fallback_host is not None:
                    host_id = str(getattr(fallback_host, "_moId", "") or "")
                    if host_id and host_id not in host_entity_by_id:
                        host_entity_by_id[host_id] = self._entity(fallback_host, "HostSystem")
                    targets = [(fallback_host, True)]
                    expected_host_count = 1
                    unqueried_host_count = 0
                    if host_id:
                        resource_id_by_host[host_id] = compute_id
                else:
                    targets = [(None, False)]
                    expected_host_count = 1
                    unqueried_host_count = 0
                scope = {
                    "compute": compute,
                    "targets": targets,
                    "expected_host_count": expected_host_count,
                    "unqueried_host_count": unqueried_host_count,
                }
            except Exception as exc:  # noqa: BLE001 - an unreadable compute scope is unavailable evidence.
                scope = {
                    "compute": compute,
                    "targets": [],
                    "expected_host_count": max(1, len(getattr(compute, "host", []) or [])) if compute else 1,
                    "unqueried_host_count": 1,
                    "error_type": type(exc).__name__,
                }
            resource_scopes[compute_id] = scope
            return compute_id

        for cluster in clusters or []:
            scope_id = register_resource_scope(cluster)
            for host in getattr(cluster, "host", []) or []:
                host_id = str(getattr(host, "_moId", "") or "")
                if host_id:
                    resource_id_by_host[host_id] = scope_id
        for host in hosts:
            host_id = str(getattr(host, "_moId", "") or "")
            if host_id and host_id not in host_entity_by_id:
                host_entity_by_id[host_id] = self._entity(host, "HostSystem")
            if host_id and host_id not in resource_id_by_host:
                try:
                    compute = getattr(host, "parent", None)
                except Exception:  # noqa: BLE001 - missing parent is handled as an unavailable scope per VM.
                    compute = None
                if compute is not None:
                    resource_id_by_host[host_id] = register_resource_scope(compute, fallback_host=host)

        def read_descriptors(compute: Any, host: Any, hardware_version: str) -> dict[str, Any]:
            compute_id = str(getattr(compute, "_moId", "") or getattr(compute, "name", "") or id(compute)) if compute else ""
            host_id = str(getattr(host, "_moId", "") or "") if host else ""
            key = (compute_id, host_id, hardware_version)
            if key in cache:
                return cache[key]
            stop_reason = resource_guard() if resource_guard else None
            if stop_reason:
                result = {"status": "not_requested", "reason": stop_reason, "error_type": None, "descriptors": {}}
                cache[key] = result
                return result
            browser_key = (compute_id, host_id)
            if browser_key in browser_cache:
                browser = browser_cache[browser_key]
            else:
                try:
                    browser = getattr(compute, "environmentBrowser", None) if compute else None
                    if browser is None and host is not None:
                        browser = getattr(getattr(host, "parent", None), "environmentBrowser", None)
                except Exception as exc:  # noqa: BLE001 - cache scoped ManagedObject property failures as well as method faults.
                    result = {"status": "error", "reason": None, "error_type": type(exc).__name__, "descriptors": {}}
                    cache[key] = result
                    return result
                browser_cache[browser_key] = browser
            if browser is None:
                result = {"status": "unavailable", "reason": "environment_browser_unavailable", "error_type": None, "descriptors": {}}
                cache[key] = result
                return result
            try:
                if host is not None:
                    option = browser.QueryConfigOption(key=hardware_version, host=host)
                else:
                    option = browser.QueryConfigOption(key=hardware_version)
                descriptors: dict[str, dict[str, Any]] = {}
                for item in getattr(option, "guestOSDescriptor", []) or []:
                    guest_id = str(getattr(item, "id", "") or "").casefold()
                    if not guest_id:
                        continue
                    descriptors[guest_id] = {
                        "support_level": str(getattr(item, "supportLevel", "") or "").casefold() or None,
                        "full_name": str(getattr(item, "fullName", "") or "") or None,
                    }
                result = {
                    "status": "ok" if option is not None else "unavailable",
                    "reason": None if option is not None else "config_option_unavailable",
                    "error_type": None,
                    "descriptors": descriptors,
                    "source": "vim.EnvironmentBrowser.QueryConfigOption",
                }
            except Exception as exc:  # noqa: BLE001 - keep host/API failures scoped to this capability.
                result = {"status": "error", "reason": None, "error_type": type(exc).__name__, "descriptors": {}}
            cache[key] = result
            return result

        for vm_index, vm in enumerate(vms, start=1):
            if progress_callback:
                progress_callback("vm_started", vm_index, len(vms))
            if resource_guard and resource_guard():
                break
            entity = self._entity(vm, "VirtualMachine")
            if progress_callback:
                progress_callback("vm_entity_ready", vm_index, len(vms))
            config = getattr(vm, "config", None)
            guest_id = str(getattr(config, "guestId", "") or "").strip()
            hardware_version = str(getattr(config, "version", "") or "").strip()
            runtime = getattr(vm, "runtime", None)
            current_host = getattr(runtime, "host", None) if runtime else None
            current_host_id = str(getattr(current_host, "_moId", "") or "") if current_host else ""
            compute_id = resource_id_by_host.get(current_host_id, "")
            scope = resource_scopes.get(compute_id) if compute_id else None
            compute = scope.get("compute") if scope else None
            if compute is None and current_host is not None:
                try:
                    compute = getattr(current_host, "parent", None)
                except Exception:  # noqa: BLE001 - unresolved parent becomes insufficient evidence.
                    compute = None
                if compute is not None:
                    compute_id = register_resource_scope(compute, fallback_host=current_host)
                    scope = resource_scopes.get(compute_id)
            if compute is None:
                resource_pool = getattr(vm, "resourcePool", None)
                try:
                    compute = getattr(resource_pool, "owner", None) if resource_pool else None
                except Exception:  # noqa: BLE001 - powered-off VM ownership may be unavailable.
                    compute = None
                visited: set[int] = set()
                while compute is not None and id(compute) not in visited and resource_id(compute) not in resource_scopes:
                    visited.add(id(compute))
                    try:
                        compute = getattr(compute, "parent", None)
                    except Exception:  # noqa: BLE001 - stop following an unreadable resource-pool parent.
                        compute = None
                if compute is not None:
                    compute_id = register_resource_scope(compute)
                    scope = resource_scopes.get(compute_id)
            target_pairs = list(scope.get("targets", [])) if scope else []
            expected_host_count = int(scope.get("expected_host_count", 1)) if scope else 1
            unqueried_host_count = int(scope.get("unqueried_host_count", 1)) if scope else 1
            if not guest_id or not hardware_version:
                target_pairs = []
            if progress_callback:
                progress_callback("target_hosts_ready", vm_index, len(vms))

            host_evidence: list[dict[str, Any]] = []
            descriptor_count = 0
            query_error_count = 0
            risk_levels: set[str] = set()
            unknown_support_level_count = 0
            for target_host, host_specific in target_pairs:
                if resource_guard and resource_guard():
                    unqueried_host_count += max(0, len(target_pairs) - len(host_evidence))
                    break
                query = read_descriptors(compute, target_host if host_specific else None, hardware_version)
                row: dict[str, Any] = {
                    "host_id": host_entity_by_id.get(str(getattr(target_host, "_moId", "") or "")).stable_id if target_host is not None and str(getattr(target_host, "_moId", "") or "") in host_entity_by_id else None,
                    "query_status": query.get("status"),
                }
                if query.get("error_type"):
                    row["error_type"] = query["error_type"]
                    query_error_count += 1
                if query.get("reason"):
                    row["reason"] = query["reason"]
                descriptor = (query.get("descriptors") or {}).get(guest_id.casefold()) if guest_id else None
                if descriptor:
                    descriptor_count += 1
                    level = str(descriptor.get("support_level") or "").casefold()
                    row["descriptor_present"] = True
                    row["support_level"] = level or None
                    row["guest_os_name"] = descriptor.get("full_name")
                    if level and level != "supported":
                        risk_levels.add(level)
                    if not level:
                        unknown_support_level_count += 1
                else:
                    row["descriptor_present"] = False
                    if query.get("status") == "ok":
                        row["reason"] = "configured_guest_id_not_listed"
                host_evidence.append(row)

            complete = bool(guest_id and hardware_version and target_pairs) and (
                not unqueried_host_count
                and not query_error_count
                and descriptor_count == expected_host_count
                and unknown_support_level_count == 0
            )
            if not guest_id:
                support_status = "guest_id_unavailable"
                summary = "虚拟机没有可读取的 Guest OS 标识，支持状态无法判断"
            elif not hardware_version:
                support_status = "hardware_version_unavailable"
                summary = "虚拟机硬件版本缺失，支持状态无法判断"
            elif risk_levels:
                support_status = "needs_review"
                summary = "Guest OS 支持级别为 " + ", ".join(sorted(risk_levels)) + "，需要确认兼容性与生命周期"
            elif complete and descriptor_count == expected_host_count and all(
                str(item.get("support_level") or "").casefold() == "supported"
                for row in host_evidence
                for item in [row]
            ):
                support_status = "supported"
                summary = "当前计算资源为配置的 Guest OS 返回 supported 支持级别"
            elif any(row.get("descriptor_present") for row in host_evidence):
                support_status = "partial"
                summary = "Guest OS 支持描述符仅取得部分结果，不能据此判定完整支持"
            elif any(row.get("query_status") == "ok" for row in host_evidence):
                support_status = "not_listed"
                summary = "当前接口未列出配置的 Guest OS 标识；未将缺少描述符解释为不支持"
            else:
                support_status = "unavailable"
                summary = "没有可查询的计算资源或主机范围，Guest OS 支持状态无法判断"

            completeness = descriptor_count / expected_host_count if expected_host_count else 0.0
            record = self._record(
                dataset_id,
                collected_at,
                "config",
                entity,
                "VM-DEEP-008",
                {
                    "guest_id": guest_id or None,
                    "hardware_version": hardware_version or None,
                    "support_status": support_status,
                    "support_levels": sorted(risk_levels) if risk_levels else sorted({str(row.get("support_level")) for row in host_evidence if row.get("support_level")}),
                    "descriptor_count": descriptor_count,
                    "expected_host_count": expected_host_count,
                    "query_error_count": query_error_count,
                    "unqueried_host_count": unqueried_host_count,
                    "hosts": host_evidence,
                },
                "guest_os_support",
                support_status == "needs_review",
                summary,
            )
            record.source = DeepSource(
                api="vim.EnvironmentBrowser.QueryConfigOption",
                collector="pyvmomi.deep.guest_os",
                collected_at_utc=collected_at,
            )
            record.selector.update({"guest_id": guest_id or None, "hardware_version": hardware_version or None})
            record.window = DeepWindow(
                start=collected_at,
                end=collected_at,
                sample_count=descriptor_count,
                expected_sample_count=max(1, expected_host_count),
                completeness=completeness,
            )
            record.metadata.update(
                {
                    "support_status": support_status,
                    "coverage_complete": complete,
                    "query_error_count": query_error_count,
                    "unqueried_host_count": unqueried_host_count,
                }
            )
            records.append(record)
            if progress_callback:
                progress_callback("vm_completed", vm_index, len(vms))

        collection_coverage = len(records) / len(vms) if vms else 1.0
        if collection_coverage < 1.0:
            for record in records:
                record.window.completeness = min(record.window.completeness, collection_coverage)
                record.metadata["coverage_complete"] = False
                record.metadata["uncollected_vm_count"] = len(vms) - len(records)
        queries = list(cache.values())
        self._guest_os_support_collection = {
            "collection_coverage": round(collection_coverage, 4),
            "query_attempt_count": len(queries),
            "query_success_count": sum(item.get("status") == "ok" for item in queries),
            "query_error_count": sum(item.get("status") == "error" for item in queries),
            "query_unavailable_count": sum(item.get("status") == "unavailable" for item in queries),
            "query_not_requested_count": sum(item.get("status") == "not_requested" for item in queries),
            "support_status_counts": dict(Counter(str(record.value.get("support_status") or "unknown") for record in records)),
            "guest_id_not_listed_vm_count": sum(record.metadata.get("support_status") == "not_listed" for record in records),
            "unknown_vm_count": sum(record.metadata.get("support_status") in {"guest_id_unavailable", "hardware_version_unavailable", "partial", "unavailable", "not_listed"} for record in records),
        }
        return records

    def _guest_os_support_summary(self, records: list[DatasetRecord], vm_count: int) -> dict[str, Any]:
        return {
            "vm_count": vm_count,
            "record_count": len(records),
            **getattr(self, "_guest_os_support_collection", {}),
        }

    def _guest_os_support_capability(self, records: list[DatasetRecord], vm_count: int, phase_log: dict[str, Any]) -> Capability:
        detail = {"vm_count": vm_count, "record_count": len(records), **getattr(self, "_guest_os_support_collection", {})}
        if vm_count == 0:
            status = CapabilityStatus.NOT_APPLICABLE
        elif phase_log.get("status") == "not_requested" or (
            phase_log.get("status") == "partial" and detail.get("query_attempt_count", 0) == 0
        ):
            status = CapabilityStatus.NOT_REQUESTED
            detail["reason"] = phase_log.get("reason")
        elif detail.get("query_success_count", 0) == 0:
            status = CapabilityStatus.UNAVAILABLE
        elif detail.get("query_error_count", 0) or detail.get("query_unavailable_count", 0) or detail.get("query_not_requested_count", 0):
            status = CapabilityStatus.LIMITED
        else:
            status = CapabilityStatus.AVAILABLE
        return Capability(
            id="vm.guest_os.support",
            name="Guest OS 支持级别",
            status=status,
            profile="core",
            detected_via="vim.EnvironmentBrowser.QueryConfigOption",
            detail=detail,
            affects_rules=["VM-DEEP-008"],
        )

    def _vm_hidden_risk_records(self, vms: list[Any], dataset_id: str, collected_at: str) -> list[DatasetRecord]:
        result: list[DatasetRecord] = []
        versions = [str(getattr(getattr(vm, "config", None), "version", "") or "") for vm in vms]
        version_counts = {version: versions.count(version) for version in set(versions) if version}
        mainstream_version = max(version_counts, key=version_counts.get) if version_counts else ""
        for vm in vms:
            entity = self._entity(vm, "VirtualMachine")
            runtime = getattr(vm, "runtime", None)
            connection_state = str(getattr(runtime, "connectionState", "") or "").lower()
            result.append(self._record(dataset_id, collected_at, "config", entity, "VM-DEEP-002", connection_state, "state", connection_state in {"orphaned", "inaccessible", "invalid"}, f"VM connection state is {connection_state or 'unknown'}", not_applicable=not bool(connection_state)))
            power_state = str(getattr(runtime, "powerState", "") or "").lower()
            guest = getattr(vm, "guest", None)
            tools_status = str(getattr(guest, "toolsRunningStatus", "") or "").lower()
            tools_version_status = str(getattr(guest, "toolsVersionStatus2", None) or getattr(guest, "toolsVersionStatus", None) or "").lower()
            tools_bad_states = {
                "guesttoolsnotrunning",
                "guesttoolsnotinstalled",
                "guesttoolsneedupgrade",
                "guesttoolssupportedold",
                "guesttoolstoold",
                "guesttoolsblacklisted",
            }
            tools_bad = power_state in {"poweredon", "powered_on"} and (tools_status in tools_bad_states or tools_version_status in tools_bad_states)
            tools_evidence = {
                "running_status": tools_status or None,
                "version_status": tools_version_status or None,
            }
            result.append(self._record(dataset_id, collected_at, "config", entity, "VM-DEEP-003", tools_evidence, "state", tools_bad, f"VMware Tools running={tools_status or 'unknown'}; version={tools_version_status or 'unknown'}", not_applicable=power_state not in {"poweredon", "powered_on"} or not (tools_status or tools_version_status)))
            version = str(getattr(getattr(vm, "config", None), "version", "") or "")
            result.append(self._record(dataset_id, collected_at, "config", entity, "VM-DEEP-004", version, "version", bool(mainstream_version and version and version != mainstream_version), f"virtual hardware version is {version or 'unknown'}; mainstream is {mainstream_version or 'unknown'}", not_applicable=not bool(version or mainstream_version)))
            config = getattr(vm, "config", None)
            cpu_allocation = getattr(config, "cpuAllocation", None) if config else None
            memory_allocation = getattr(config, "memoryAllocation", None) if config else None
            cpu_limit = getattr(cpu_allocation, "limit", None) if cpu_allocation else None
            memory_limit = getattr(memory_allocation, "limit", None) if memory_allocation else None
            cpu_reservation = getattr(cpu_allocation, "reservation", None) if cpu_allocation else None
            memory_reservation = getattr(memory_allocation, "reservation", None) if memory_allocation else None
            cpu_shares = getattr(cpu_allocation, "shares", None) if cpu_allocation else None
            memory_shares = getattr(memory_allocation, "shares", None) if memory_allocation else None
            allocation = {
                "cpu_limit_mhz": cpu_limit,
                "memory_limit_mb": memory_limit,
                "cpu_reservation_mhz": cpu_reservation,
                "memory_reservation_mb": memory_reservation,
                "cpu_shares": {
                    "level": str(getattr(cpu_shares, "level", "") or "") if cpu_shares else None,
                    "shares": getattr(cpu_shares, "shares", None) if cpu_shares else None,
                },
                "memory_shares": {
                    "level": str(getattr(memory_shares, "level", "") or "") if memory_shares else None,
                    "shares": getattr(memory_shares, "shares", None) if memory_shares else None,
                },
            }
            has_limit = any(isinstance(value, (int, float)) and value >= 0 for value in (cpu_limit, memory_limit))
            has_custom_shares = any(
                str(getattr(shares, "level", "") or "").casefold() == "custom"
                for shares in (cpu_shares, memory_shares)
                if shares is not None
            )
            result.append(self._record(dataset_id, collected_at, "config", entity, "VM-DEEP-005", allocation, "configuration", has_limit or has_custom_shares, "VM CPU or memory reservation, limit, or custom shares require review", not_applicable=config is None))
            guest_actual = str(getattr(guest, "guestFullName", "") or "").strip() if guest else ""
            guest_configured = str(getattr(config, "guestFullName", "") or getattr(config, "guestId", "") or "").strip() if config else ""
            tools_running = tools_status == "guesttoolsrunning"
            os_mismatch = bool(guest_actual and guest_configured and tools_running and guest_actual.casefold() != guest_configured.casefold())
            os_evidence = {"configured_guest_os": guest_configured or None, "reported_guest_os": guest_actual or None, "tools_running": tools_running}
            result.append(self._record(dataset_id, collected_at, "config", entity, "VM-DEEP-007", os_evidence, "guest_os", os_mismatch, "configured and guest-reported operating system do not match" if os_mismatch else "guest OS support evidence captured", not_applicable=not (guest_actual and guest_configured and tools_running)))
        return result

    def _cluster_hidden_risk_records(self, clusters: list[Any], dataset_id: str, collected_at: str) -> list[DatasetRecord]:
        result: list[DatasetRecord] = []
        evc_modes: list[str] = []
        resource_pool_counts: list[int] = []
        for cluster in clusters:
            entity = self._entity(cluster, "ClusterComputeResource")
            config = getattr(cluster, "configurationEx", None)
            das = getattr(config, "dasConfig", None) if config else None
            drs = getattr(config, "drsConfig", None) if config else None
            ha_enabled = getattr(das, "enabled", None) if das else None
            admission = getattr(das, "admissionControlEnabled", None) if das else None
            heartbeat_datastores = getattr(das, "heartbeatDatastore", None) if das else None
            heartbeat_count = len(heartbeat_datastores or []) if heartbeat_datastores is not None else None
            heartbeat_policy = str(getattr(das, "hBDatastoreCandidatePolicy", "") or "allFeasibleDsWithUserPreference") if das else ""
            known_heartbeat_policies = {"allFeasibleDs", "allFeasibleDsWithUserPreference", "userSelectedDs"}
            heartbeat_policy_known = heartbeat_policy in known_heartbeat_policies
            explicit_heartbeat_issue = heartbeat_policy == "userSelectedDs" and heartbeat_count is not None and heartbeat_count < 2
            default_vm_settings = getattr(das, "defaultVmSettings", None) if das else None
            configured_isolation = str(getattr(default_vm_settings, "isolationResponse", "") or "") if default_vm_settings else ""
            effective_isolation = configured_isolation or "powerOff"
            vm_isolation_overrides = list(getattr(config, "dasVmConfig", []) or []) if config else []
            vm_none_overrides = sum(
                1
                for override in vm_isolation_overrides
                if str(getattr(getattr(override, "dasSettings", None), "isolationResponse", "") or "").casefold() == "none"
            )
            ha_risk_reasons: list[str] = []
            if ha_enabled is False:
                ha_risk_reasons.append("ha_disabled")
            elif ha_enabled is True and admission is False:
                ha_risk_reasons.append("admission_control_disabled")
            if explicit_heartbeat_issue:
                ha_risk_reasons.append("user_selected_heartbeat_datastores_below_two")
            if configured_isolation.casefold() == "none":
                ha_risk_reasons.append("isolation_response_none")
            if vm_none_overrides:
                ha_risk_reasons.append("vm_isolation_response_none")
            ha_evidence = {
                "ha_enabled": ha_enabled,
                "admission_control": admission,
                "heartbeat_candidate_policy": heartbeat_policy or None,
                "heartbeat_selection_mode": "automatic" if heartbeat_policy != "userSelectedDs" else "user_selected",
                "explicit_heartbeat_datastore_count": heartbeat_count,
                "heartbeat_issue": explicit_heartbeat_issue,
                "configured_isolation_response": configured_isolation or None,
                "effective_isolation_response": effective_isolation,
                "isolation_response_source": "cluster_config" if configured_isolation else "vSphere_default",
                "vm_isolation_response_none_override_count": vm_none_overrides,
                "risk_reasons": ha_risk_reasons,
            }
            ha_record = self._record(
                dataset_id,
                collected_at,
                "config",
                entity,
                "CL-DEEP-004",
                ha_evidence,
                "configuration",
                bool(ha_risk_reasons),
                "HA configuration requires review" if ha_risk_reasons else "HA configuration and effective defaults were captured",
                not_applicable=not bool(das),
            )
            if das:
                required_ha_fields_present = ha_enabled is not None and admission is not None and heartbeat_count is not None and heartbeat_policy_known
                ha_record.window = DeepWindow(
                    start=collected_at,
                    end=collected_at,
                    sample_count=4 if required_ha_fields_present else 0,
                    expected_sample_count=4,
                    completeness=1.0 if required_ha_fields_present else 0.0,
                )
            result.append(ha_record)
            rules = getattr(config, "rule", []) if config else []
            disabled_rules = sum(1 for rule in rules or [] if getattr(rule, "enabled", None) is False)
            drs_enabled = bool(getattr(drs, "enabled", False)) if drs else False
            drs_risk = bool(drs) and (not drs_enabled or disabled_rules > 0)
            result.append(self._record(dataset_id, collected_at, "config", entity, "CL-DEEP-005", {"enabled": drs_enabled, "disabled_rule_count": disabled_rules}, "configuration", drs_risk, "DRS configuration requires review", not_applicable=not bool(drs)))
            summary = getattr(cluster, "summary", None)
            evc_mode = str(getattr(summary, "currentEVCModeKey", "") or getattr(summary, "currentEVCMode", "") or "") if summary else ""
            if evc_mode:
                evc_modes.append(evc_mode)
            pool = getattr(cluster, "resourcePool", None)
            pool_count = len(getattr(pool, "resourcePool", []) or []) if pool else 0
            resource_pool_counts.append(pool_count)
        applicable = bool(evc_modes or resource_pool_counts)
        inconsistent = len(set(evc_modes)) > 1
        result.append(self._record(dataset_id, collected_at, "config", self._environment_entity(), "CL-DEEP-008", {"evc_modes": sorted(set(evc_modes)), "resource_pool_counts": resource_pool_counts, "cluster_count": len(clusters)}, "configuration", inconsistent, "EVC modes differ across clusters; Resource Pool summaries recorded for review" if inconsistent else "EVC and Resource Pool summaries captured", not_applicable=not applicable))
        result.append(self._resource_pool_tree_record(clusters, dataset_id, collected_at))
        return result

    def _resource_pool_tree_record(self, clusters: list[Any], dataset_id: str, collected_at: str) -> DatasetRecord:
        known_statuses = {"green", "yellow", "red"}
        issue_statuses = {"yellow", "red"}
        status_counts = {status: 0 for status in ("green", "yellow", "red", "unknown")}
        cluster_summaries: list[dict[str, Any]] = []
        total_pool_count = 0
        known_pool_count = 0
        coverage_complete = bool(clusters)
        issue_entries: list[dict[str, Any]] = []
        unknown_paths: list[dict[str, str]] = []

        def read_attr(obj: Any, name: str) -> tuple[Any, bool, str | None]:
            try:
                return getattr(obj, name, None), True, None
            except Exception as exc:  # noqa: BLE001 - isolate a property fault to this part of the tree.
                return None, False, type(exc).__name__

        def token(value: Any) -> str:
            if value is None:
                return ""
            return str(value).strip().casefold().rsplit(".", 1)[-1]

        def allocation_summary(pool: Any) -> dict[str, Any]:
            config, config_ok, _ = read_attr(pool, "config")
            summary: dict[str, Any] = {"config_available": bool(config_ok and config)}
            for label, attr, unit in (("cpu", "cpuAllocation", "mhz"), ("memory", "memoryAllocation", "mb")):
                allocation, allocation_ok, _ = read_attr(config, attr) if config else (None, False, None)
                if not allocation_ok or allocation is None:
                    summary[label] = None
                    continue
                values: dict[str, Any] = {"unit": unit}
                for field in ("reservation", "limit"):
                    value, ok, _ = read_attr(allocation, field)
                    try:
                        values[field] = int(value) if ok and value is not None else None
                    except (TypeError, ValueError, OverflowError):
                        values[field] = None
                expandable, expandable_ok, _ = read_attr(allocation, "expandableReservation")
                values["expandable_reservation"] = bool(expandable) if expandable_ok and expandable is not None else None
                shares, shares_ok, _ = read_attr(allocation, "shares")
                level, level_ok, _ = read_attr(shares, "level") if shares_ok and shares else (None, False, None)
                share_value, share_value_ok, _ = read_attr(shares, "shares") if shares_ok and shares else (None, False, None)
                values["shares_level"] = token(level) if level_ok and level is not None else None
                try:
                    values["shares"] = int(share_value) if share_value_ok and share_value is not None else None
                except (TypeError, ValueError, OverflowError):
                    values["shares"] = None
                summary[label] = values
            return summary

        for cluster in clusters:
            cluster_name = str(getattr(cluster, "name", "unknown") or "unknown")
            if total_pool_count >= MAX_RESOURCE_POOLS_PER_SESSION:
                coverage_complete = False
                cluster_summaries.append({"cluster": cluster_name, "root_status": "unknown", "pool_count": 0, "status_counts": {"unknown": 0}, "truncated": True, "error_type": "session_resource_pool_limit"})
                continue
            root, root_ok, root_error = read_attr(cluster, "resourcePool")
            if not root_ok or root is None:
                coverage_complete = False
                cluster_summaries.append({"cluster": cluster_name, "root_status": "unknown", "pool_count": 0, "status_counts": {"unknown": 0}, "truncated": False, "error_type": root_error or "missing_resource_pool_root"})
                continue

            root_name, root_name_ok, _ = read_attr(root, "name")
            root_path = str(root_name or "Resources") if root_name_ok else "Resources"
            stack: list[tuple[Any, str]] = [(root, root_path)]
            visited: set[str] = set()
            pool_rows: list[dict[str, Any]] = []
            local_counts = {status: 0 for status in ("green", "yellow", "red", "unknown")}
            local_complete = True
            truncated = False

            while stack:
                if len(pool_rows) >= MAX_RESOURCE_POOLS_PER_CLUSTER or total_pool_count >= MAX_RESOURCE_POOLS_PER_SESSION:
                    truncated = True
                    local_complete = False
                    break
                pool, path = stack.pop()
                moid, moid_ok, _ = read_attr(pool, "_moId")
                identity = str(moid) if moid_ok and moid else path
                if identity in visited:
                    local_complete = False
                    continue
                visited.add(identity)

                direct_status, direct_ok, direct_error = read_attr(pool, "overallStatus")
                runtime, runtime_ok, runtime_error = read_attr(pool, "runtime")
                legacy_status, legacy_ok, legacy_error = read_attr(runtime, "overallStatus") if runtime_ok and runtime else (None, False, runtime_error)
                direct_token = token(direct_status) if direct_ok else ""
                legacy_token = token(legacy_status) if legacy_ok else ""
                status_conflict = direct_token in known_statuses and legacy_token in known_statuses and direct_token != legacy_token
                if status_conflict:
                    status = "unknown"
                    status_source = "conflicting_overall_status_properties"
                    local_complete = False
                elif direct_token in known_statuses:
                    status = direct_token
                    status_source = "ResourcePool.overallStatus"
                elif legacy_token in known_statuses:
                    status = legacy_token
                    status_source = "ResourcePool.runtime.overallStatus"
                else:
                    status = "unknown"
                    status_source = "unavailable"
                    local_complete = False

                local_counts[status] += 1
                total_pool_count += 1
                if status in known_statuses:
                    known_pool_count += 1
                row: dict[str, Any] = {"path": path, "status": status, "status_source": status_source, "status_conflict": status_conflict}
                if status in issue_statuses:
                    row.update(allocation_summary(pool))
                    issue_entries.append({"cluster": cluster_name, **row})
                elif status == "unknown":
                    if len(unknown_paths) < MAX_RESOURCE_POOL_EVIDENCE:
                        unknown_row = {"cluster": cluster_name, "path": path}
                        if status_conflict:
                            unknown_row["reason"] = "overall_status_properties_disagree"
                            unknown_row["direct_status"] = direct_token or "unknown"
                            unknown_row["runtime_status"] = legacy_token or "unknown"
                        else:
                            unknown_row["reason"] = direct_error or legacy_error or "status_unavailable"
                        unknown_paths.append(unknown_row)
                pool_rows.append(row)

                children, children_ok, children_error = read_attr(pool, "resourcePool")
                if not children_ok or children is None:
                    local_complete = False
                    if len(unknown_paths) < MAX_RESOURCE_POOL_EVIDENCE:
                        unknown_paths.append({"cluster": cluster_name, "path": path, "reason": children_error or "child_list_unavailable"})
                    continue
                try:
                    child_list = list(children)
                except TypeError:
                    local_complete = False
                    continue
                for child in reversed(child_list):
                    child_name, child_name_ok, _ = read_attr(child, "name")
                    suffix = str(child_name or "ResourcePool") if child_name_ok else "ResourcePool"
                    stack.append((child, f"{path}/{suffix}"))

            if truncated:
                if len(unknown_paths) < MAX_RESOURCE_POOL_EVIDENCE:
                    unknown_paths.append({"cluster": cluster_name, "path": "<remaining resource pools>", "reason": "per_cluster_node_limit"})
            for status, count in local_counts.items():
                status_counts[status] += count
            root_row = next((row for row in pool_rows if row["path"] == root_path), None)
            root_status = root_row["status"] if root_row else "unknown"
            if root_status == "unknown":
                local_complete = False
            coverage_complete = coverage_complete and local_complete and not truncated
            cluster_summaries.append(
                {
                    "cluster": cluster_name,
                    "root_status": root_status,
                    "pool_count": len(pool_rows),
                    "status_counts": local_counts,
                    "affected_pool_count": sum(local_counts[status] for status in issue_statuses),
                    "affected_pools": [row for row in pool_rows if row["status"] in issue_statuses][:MAX_RESOURCE_POOL_EVIDENCE],
                    "truncated": truncated,
                }
            )

        finding = bool(issue_entries)
        if finding:
            summary = (
                f"Resource Pool 资源树读取到 {status_counts['red']} 个红色节点状态和 "
                f"{status_counts['yellow']} 个黄色节点状态；示例路径："
                + "；".join(f"{row['cluster']}/{row['path']}={row['status']}" for row in issue_entries[:5])
            )
            if not coverage_complete:
                summary += "。其他部分状态未完整取得，已确认异常仍可复核"
        elif coverage_complete:
            summary = f"已完整检查 {total_pool_count} 个 Resource Pool 节点，资源树状态均为 green"
        else:
            summary = f"未发现已确认异常，但 Resource Pool 状态覆盖不完整：已取得 {known_pool_count}/{total_pool_count} 个节点状态"

        record = self._record(
            dataset_id,
            collected_at,
            "config",
            self._environment_entity(),
            "CL-DEEP-009",
            {
                "cluster_count": len(clusters),
                "resource_pool_count": total_pool_count,
                "known_status_count": known_pool_count,
                "status_counts": status_counts,
                "affected_pool_count": len(issue_entries),
                "affected_pools": issue_entries[:MAX_RESOURCE_POOL_EVIDENCE],
                "additional_affected_pool_count": max(0, len(issue_entries) - MAX_RESOURCE_POOL_EVIDENCE),
                "unknown_pools": unknown_paths[:MAX_RESOURCE_POOL_EVIDENCE],
                "additional_unknown_pool_count": max(0, len(unknown_paths) - MAX_RESOURCE_POOL_EVIDENCE),
                "clusters": cluster_summaries,
                "coverage_complete": coverage_complete,
                "per_cluster_node_limit": MAX_RESOURCE_POOLS_PER_CLUSTER,
                "per_session_node_limit": MAX_RESOURCE_POOLS_PER_SESSION,
            },
            "resource_pool_tree",
            finding,
            summary,
            not_applicable=not clusters,
        )
        expected_status_count = total_pool_count + sum(1 for item in cluster_summaries if item["pool_count"] == 0)
        record.window = DeepWindow(
            start=collected_at,
            end=collected_at,
            sample_count=known_pool_count,
            expected_sample_count=expected_status_count,
            completeness=known_pool_count / expected_status_count if expected_status_count else 0.0,
        )
        record.metadata["coverage_complete"] = coverage_complete
        record.metadata["status_source"] = "ResourcePool.overallStatus (fallback: runtime.overallStatus)"
        return record

    def _storage_hidden_risk_records(self, hosts: list[Any], datastores: list[Any], dataset_id: str, collected_at: str) -> list[DatasetRecord]:
        result: list[DatasetRecord] = []
        for host in hosts:
            entity = self._entity(host, "HostSystem")
            evidence = self._storage_path_evidence(host)
            if evidence is None:
                record = self._record(
                    dataset_id,
                    collected_at,
                    "config",
                    entity,
                    "STO-DEEP-003",
                    {"scope_status": "unavailable", "reason": "multipath_inventory_unavailable"},
                    "storage_path",
                    False,
                    "主机多路径清单不可用，路径健康和冗余状态无法判断",
                )
                record.window = DeepWindow(start=collected_at, end=collected_at, sample_count=0, expected_sample_count=1, completeness=0.0)
                record.metadata["coverage_complete"] = False
                result.append(record)
                continue

            target_luns = list(evidence["target_luns"])
            findings = list(evidence["issues"])
            if not target_luns:
                record = self._record(
                    dataset_id,
                    collected_at,
                    "config",
                    entity,
                    "STO-DEEP-003",
                    evidence,
                    "storage_path",
                    False,
                    "没有发现适用的共享块存储多路径对象；路径冗余检查不适用",
                    not_applicable=True,
                )
                record.metadata["coverage_complete"] = bool(evidence["coverage_complete"])
                result.append(record)
                continue

            finding = bool(findings)
            issue_count = len(findings)
            summary = (
                f"{issue_count} 个共享块设备存在失效路径或可用路径少于 2 条，需要核对多路径冗余"
                if finding
                else f"已检查 {len(target_luns)} 个共享块设备；当前可用路径均不少于 2 条，未发现失效路径"
            )
            record = self._record(dataset_id, collected_at, "config", entity, "STO-DEEP-003", evidence, "storage_path", finding, summary)
            expected_paths = max(1, int(evidence.get("expected_path_count") or 0))
            known_paths = int(evidence.get("known_path_count") or 0)
            record.window = DeepWindow(
                start=collected_at,
                end=collected_at,
                sample_count=known_paths,
                expected_sample_count=expected_paths,
                completeness=min(1.0, known_paths / expected_paths),
            )
            record.metadata["coverage_complete"] = bool(evidence["coverage_complete"])
            result.append(record)
        threshold = default_threshold_registry().get("TH-DATASTORE-USED-PERCENT-HIGH").value
        for datastore in datastores:
            entity = self._entity(datastore, "Datastore")
            summary = getattr(datastore, "summary", None)
            accessible = getattr(summary, "accessible", None) if summary else None
            if accessible is True:
                capacity = float(getattr(summary, "capacity", 0) or 0)
                free = float(getattr(summary, "freeSpace", 0) or 0)
                used = ((capacity - free) / capacity * 100) if capacity > 0 else None
                summary_text = f"datastore used percent is {used:.2f}" if used is not None else "datastore capacity unavailable"
            else:
                used = None
                summary_text = "datastore inaccessible; capacity evidence was not evaluated" if accessible is False else "datastore accessibility is unknown; capacity evidence was not evaluated"
            record = self._record(dataset_id, collected_at, "config", entity, "STO-DEEP-004", used, "percent", bool(used is not None and used >= threshold), summary_text)
            if accessible is not True or used is None:
                record.window = DeepWindow(start=collected_at, end=collected_at, sample_count=0, expected_sample_count=1, completeness=0.0)
                record.metadata["coverage_complete"] = False
            result.append(record)
        return result

    def _datastore_access_records(
        self,
        datastores: list[Any],
        dataset_id: str,
        collected_at: str,
        *,
        resource_guard: Callable[[], str | None] | None = None,
    ) -> list[DatasetRecord]:
        status_counts = {"accessible": 0, "inaccessible": 0, "host_mount_issue": 0, "unknown": 0, "conflict": 0}
        records: list[DatasetRecord] = []
        affected: list[dict[str, Any]] = []
        unknown: list[dict[str, Any]] = []
        complete_count = 0
        skipped_count = 0
        vmfs_count = 0
        vmfs_detail_count = 0

        def read_attr(obj: Any, name: str) -> tuple[Any, bool, str | None]:
            try:
                return getattr(obj, name, None), True, None
            except Exception as exc:  # noqa: BLE001 - one missing mount field must not discard other Datastores.
                return None, False, type(exc).__name__

        def safe_reason(value: Any) -> str | None:
            token = re.sub(r"[^a-z0-9]", "", str(value or "").casefold().rsplit(".", 1)[-1])
            allowed = {"allpathsdownstart", "allpathsdowntimeout", "permanentdeviceloss"}
            return token if token in allowed else "other" if token else None

        for index, datastore in enumerate(datastores):
            if index >= MAX_DATASTORE_ACCESS_RECORDS:
                skipped_count = len(datastores) - index
                break
            stop_reason = resource_guard() if resource_guard else None
            if stop_reason:
                skipped_count = len(datastores) - index
                break

            entity = self._entity(datastore, "Datastore")
            summary, summary_ok, summary_error = read_attr(datastore, "summary")
            datastore_type, type_ok, _ = read_attr(summary, "type") if summary_ok and summary else (None, False, summary_error)
            datastore_type = str(datastore_type or "unknown").casefold() if type_ok else "unknown"
            global_access, access_ok, access_error = read_attr(summary, "accessible") if summary_ok and summary else (None, False, summary_error)
            global_access = global_access if isinstance(global_access, bool) else None
            multiple_host_access, multiple_ok, _ = read_attr(summary, "multipleHostAccess") if summary_ok and summary else (None, False, None)

            raw_mounts, mounts_ok, mounts_error = read_attr(datastore, "host")
            mount_rows: list[dict[str, Any]] = []
            mounted_states: list[bool] = []
            mounted_access_states: list[bool] = []
            local_complete = summary_ok and type_ok and access_ok and global_access is not None and mounts_ok and raw_mounts is not None
            mount_truncated = False
            if mounts_ok and raw_mounts is not None:
                try:
                    mounts = list(raw_mounts)
                except TypeError:
                    mounts = []
                    local_complete = False
                mount_truncated = len(mounts) > MAX_DATASTORE_MOUNTS_PER_DATASTORE
                local_complete = local_complete and not mount_truncated
                for mount in mounts[:MAX_DATASTORE_MOUNTS_PER_DATASTORE]:
                    key, key_ok, _ = read_attr(mount, "key")
                    host_name, host_name_ok, _ = read_attr(key, "name") if key_ok and key else (None, False, None)
                    mount_info, mount_info_ok, mount_info_error = read_attr(mount, "mountInfo")
                    mounted_raw, mounted_ok, _ = read_attr(mount_info, "mounted") if mount_info_ok and mount_info else (None, False, mount_info_error)
                    accessible_raw, mount_access_ok, _ = read_attr(mount_info, "accessible") if mount_info_ok and mount_info else (None, False, mount_info_error)
                    reason, reason_ok, _ = read_attr(mount_info, "inaccessibleReason") if mount_info_ok and mount_info else (None, False, mount_info_error)
                    mounted = True if mounted_ok and mounted_raw is None else mounted_raw if isinstance(mounted_raw, bool) else None
                    mount_access = accessible_raw if isinstance(accessible_raw, bool) else None
                    if mounted is False:
                        state = "not_mounted"
                    elif mount_access is False:
                        state = "inaccessible"
                    elif mount_access is True:
                        state = "accessible"
                    else:
                        state = "unknown"
                        local_complete = False
                    if mounted is not None:
                        mounted_states.append(mounted)
                    if mounted is not False and mount_access is not None:
                        mounted_access_states.append(mount_access)
                    mount_rows.append(
                        {
                            "host": str(host_name)[:128] if host_name_ok and host_name else "unknown",
                            "mounted": mounted,
                            "accessible": mount_access,
                            "state": state,
                            "inaccessible_reason": safe_reason(reason) if reason_ok else None,
                        }
                    )

            if multiple_host_access is True and not mount_rows:
                local_complete = False

            vmfs_detail: dict[str, Any] | None = None
            if datastore_type == "vmfs":
                vmfs_count += 1
                info, info_ok, _ = read_attr(datastore, "info")
                vmfs, vmfs_ok, _ = read_attr(info, "vmfs") if info_ok and info else (None, False, None)
                if vmfs_ok and vmfs is not None:
                    version, version_ok, _ = read_attr(vmfs, "version")
                    major, major_ok, _ = read_attr(vmfs, "majorVersion")
                    extents, extent_ok, _ = read_attr(vmfs, "extent")
                    upgradable, upgradable_ok, _ = read_attr(vmfs, "vmfsUpgradable")
                    try:
                        extent_count = len(extents) if extent_ok and extents is not None else None
                    except TypeError:
                        extent_count = None
                        extent_ok = False
                    try:
                        major_version = int(major) if major_ok and major is not None else None
                    except (TypeError, ValueError, OverflowError):
                        major_version = None
                        major_ok = False
                    vmfs_detail = {
                        "version": str(version)[:32] if version_ok and version else None,
                        "major_version": major_version,
                        "extent_count": extent_count,
                        "upgradable": bool(upgradable) if upgradable_ok and upgradable is not None else None,
                    }
                    vmfs_detail_complete = bool(version_ok and version and extent_ok and extents is not None)
                    vmfs_detail_count += int(vmfs_detail_complete)
                    local_complete = local_complete and vmfs_detail_complete
                else:
                    vmfs_detail = {"version": None, "major_version": None, "extent_count": None, "upgradable": None}
                    local_complete = False

            host_mount_issue = any(value is False for value in mounted_access_states)
            summary_issue = global_access is False
            conflict = (summary_issue and any(value is True for value in mounted_access_states)) or (
                global_access is True and bool(mounted_access_states) and not any(mounted_access_states)
            )
            if conflict:
                state = "conflict"
                local_complete = False
                finding = False
            elif summary_issue:
                state = "inaccessible"
                finding = True
            elif host_mount_issue:
                state = "host_mount_issue"
                finding = True
            elif global_access is True:
                state = "accessible"
                finding = False
            else:
                state = "unknown"
                finding = False
                local_complete = False

            status_counts[state] += 1
            complete_count += int(local_complete)
            value = {
                "datastore_type": datastore_type,
                "summary_accessible": global_access,
                "multiple_host_access": multiple_host_access if multiple_ok and isinstance(multiple_host_access, bool) else None,
                "state": state,
                "host_mount_count": len(mount_rows),
                "mounted_host_count": sum(row["mounted"] is True for row in mount_rows),
                "accessible_mounted_host_count": sum(row["state"] == "accessible" for row in mount_rows),
                "inaccessible_mounted_host_count": sum(row["state"] == "inaccessible" for row in mount_rows),
                "unmounted_host_count": sum(row["state"] == "not_mounted" for row in mount_rows),
                "unknown_mounted_host_count": sum(row["state"] == "unknown" for row in mount_rows),
                "mounts": mount_rows,
                "mounts_truncated": mount_truncated,
                "mounts_read_error_type": mounts_error if not mounts_ok else None,
                "summary_read_error_type": summary_error if not summary_ok else None,
                "accessible_read_error_type": access_error if not access_ok else None,
                "vmfs": vmfs_detail,
                "vmfs_detail_available": vmfs_detail is not None and bool(vmfs_detail.get("version")),
                "coverage_complete": local_complete,
            }
            if finding and len(affected) < MAX_DATASTORE_ACCESS_EVIDENCE:
                affected.append({"datastore": entity.display_ref, "state": state, "inaccessible_mounts": [row for row in mount_rows if row["state"] == "inaccessible"][:MAX_DATASTORE_MOUNTS_PER_DATASTORE]})
            if not local_complete and len(unknown) < MAX_DATASTORE_ACCESS_EVIDENCE:
                unknown.append({"datastore": entity.display_ref, "state": state, "reason": "mount or VMFS detail is incomplete"})

            summary_text = (
                f"Datastore is inaccessible (summary accessible=false)"
                if summary_issue and not conflict
                else f"{value['inaccessible_mounted_host_count']} configured host mount(s) report inaccessible"
                if host_mount_issue and not conflict
                else "Datastore or host mount evidence conflicts"
                if conflict
                else "Datastore accessible status is incomplete"
                if state == "unknown"
                else f"Datastore accessible on reported mounts; type={datastore_type}"
            )
            record = self._record(
                dataset_id,
                collected_at,
                "config",
                entity,
                "STO-DEEP-007",
                value,
                "datastore_access_state",
                finding,
                summary_text,
            )
            record.window = DeepWindow(start=collected_at, end=collected_at, sample_count=1 if local_complete else 0, expected_sample_count=1, completeness=1.0 if local_complete else 0.0)
            record.metadata.update({"coverage_complete": local_complete, "conflict": conflict, "datastore_type": datastore_type})
            records.append(record)

        if skipped_count == 0 and len(datastores) > MAX_DATASTORE_ACCESS_RECORDS:
            skipped_count += len(datastores) - MAX_DATASTORE_ACCESS_RECORDS
        coverage_complete = skipped_count == 0 and complete_count == len(datastores)
        if not datastores:
            collection_status = "not_applicable"
        elif skipped_count:
            collection_status = "limited"
        elif complete_count == len(datastores):
            collection_status = "available"
        elif complete_count:
            collection_status = "limited"
        else:
            collection_status = "unavailable"
        summary = self._record(
            dataset_id,
            collected_at,
            "config",
            self._environment_entity(),
            "STO-DEEP-007",
            {
                "datastore_count": len(datastores),
                "checked_count": len(records),
                "skipped_count": skipped_count,
                "state_counts": status_counts,
                "affected_count": status_counts["inaccessible"] + status_counts["host_mount_issue"],
                "conflict_count": status_counts["conflict"],
                "unknown_count": status_counts["unknown"],
                "affected_datastores": affected,
                "unknown_datastores": unknown,
                "vmfs_datastore_count": vmfs_count,
                "vmfs_detail_available_count": vmfs_detail_count,
                "coverage_complete": coverage_complete,
                "per_session_datastore_limit": MAX_DATASTORE_ACCESS_RECORDS,
            },
            "collection_summary",
            False,
            f"Datastore accessibility: {status_counts['inaccessible']} inaccessible, {status_counts['host_mount_issue']} host-mount issue(s), {status_counts['unknown']} unknown",
            not_applicable=not datastores,
        )
        expected = max(1, len(datastores))
        summary.window = DeepWindow(start=collected_at, end=collected_at, sample_count=complete_count, expected_sample_count=expected, completeness=min(1.0, complete_count / expected))
        summary.metadata.update({"storage_access_summary": True, "coverage_complete": coverage_complete, "not_applicable": not datastores})
        records.append(summary)
        return records

    def _storage_policy_compliance_records(
        self,
        vms: list[Any],
        dataset_id: str,
        collected_at: str,
        *,
        resource_guard: Callable[[], str | None] | None = None,
    ) -> list[DatasetRecord]:
        rule_id = "STO-DEEP-006"
        source = STORAGE_POLICY_COMPLIANCE_API
        known_statuses = {"compliant", "non_compliant", "out_of_date", "unknown", "not_applicable"}
        issue_statuses = {"non_compliant", "out_of_date"}
        status_counts = {status: 0 for status in sorted(known_statuses)}
        records: list[DatasetRecord] = []
        requested_count = 0
        collected_count = 0
        failed_count = 0
        not_requested_count = 0
        no_policy_association_count = 0
        status_complete = True
        global_error_status: str | None = None

        def api_error_status(error: Exception) -> tuple[str, int | None]:
            if isinstance(error, urllib.error.HTTPError):
                code = int(error.code)
                if code == 401:
                    return "authentication_failed", code
                if code == 403:
                    return "permission_denied", code
                if code == 404:
                    return "unsupported", code
                if code in {408, 504}:
                    return "timeout", code
                if code in {429, 500, 502, 503}:
                    return "unavailable", code
                return "error", code
            if isinstance(error, (TimeoutError, socket.timeout)):
                return "timeout", None
            if isinstance(error, urllib.error.URLError):
                reason = getattr(error, "reason", None)
                return ("timeout" if isinstance(reason, (TimeoutError, socket.timeout)) else "unavailable"), None
            return "error", None

        def failed_record(vm: Any, vm_id: str, status: str, error: Exception) -> DatasetRecord:
            entity = self._entity(vm, "VirtualMachine")
            record = self._record(
                dataset_id,
                collected_at,
                "config",
                entity,
                rule_id,
                {"collection_status": status, "error_type": type(error).__name__, "api_status": getattr(error, "code", None)},
                "collection_status",
                False,
                f"Storage Policy 合规状态无法读取（{status}）",
            )
            record.window = DeepWindow(start=collected_at, end=collected_at, sample_count=0, expected_sample_count=1, completeness=0.0)
            record.metadata.update({"collection_status": status, "coverage_complete": False, "vm_ref": str(getattr(vm, "name", "") or "")})
            return record

        if not vms:
            return [
                self._storage_policy_summary_record(
                    dataset_id,
                    collected_at,
                    vm_count=0,
                    requested_count=0,
                    collected_count=0,
                    failed_count=0,
                    not_requested_count=0,
                    no_policy_association_count=0,
                    status_counts=status_counts,
                    coverage_complete=True,
                    collection_status="not_applicable",
                    error_type=None,
                )
            ]

        reader = VCenterRestReadClient(self.host, self.username, self.password, self.port, self.ssl_verify, timeout=30.0)
        try:
            try:
                reader.open()
            except Exception as exc:  # noqa: BLE001 - REST capability failure is independent of pyVmomi collection.
                error_status, _http_code = api_error_status(exc)
                global_error_status = error_status
                failed_count = len(vms)
            else:
                for index, vm in enumerate(vms):
                    if requested_count >= MAX_STORAGE_POLICY_VM_REQUESTS:
                        not_requested_count = len(vms) - index
                        status_complete = False
                        break
                    stop_reason = resource_guard() if resource_guard else None
                    if stop_reason:
                        not_requested_count = len(vms) - index
                        status_complete = False
                        global_error_status = stop_reason
                        break
                    vm_id = str(getattr(vm, "_moId", "") or "")
                    if not vm_id:
                        failed_count += 1
                        status_complete = False
                        records.append(failed_record(vm, vm_id, "missing_vm_identifier", ValueError("missing VirtualMachine identifier")))
                        continue
                    requested_count += 1
                    path = f"/api/vcenter/vm/{urllib.parse.quote(vm_id, safe='')}/storage/policy/compliance"
                    try:
                        payload = reader.get_json(path)
                    except Exception as exc:  # noqa: BLE001 - isolate errors to a VM unless the API/session is globally unavailable.
                        error_status, http_code = api_error_status(exc)
                        failed_count += 1
                        status_complete = False
                        failed = failed_record(vm, vm_id, error_status, exc)
                        failed.value["api_status"] = http_code
                        records.append(failed)
                        if http_code in {401, 404, 408, 500, 502, 503, 504} or error_status in {"authentication_failed", "unsupported", "timeout", "unavailable"}:
                            not_requested_count = len(vms) - index - 1
                            global_error_status = error_status
                            break
                        continue
                    collected_count += 1
                    record = self._storage_policy_result_record(vm, payload, dataset_id, collected_at, known_statuses, issue_statuses)
                    records.append(record)
                    status_counts[str(record.value.get("overall_status") or "unknown")] += 1
                    no_policy_association_count += int(record.value.get("collection_status") == "no_policy_association")
                    status_complete = status_complete and bool(record.metadata.get("coverage_complete"))
        finally:
            reader.close()

        if requested_count + failed_count < len(vms) and not not_requested_count:
            not_requested_count = len(vms) - requested_count - failed_count
        coverage_complete = (
            collected_count == len(vms)
            and failed_count == 0
            and not_requested_count == 0
            and status_complete
        )
        if collected_count == len(vms) and failed_count == 0 and not_requested_count == 0:
            collection_status = "available"
        elif collected_count > 0:
            collection_status = "limited"
        elif requested_count == 0 and not_requested_count > 0:
            collection_status = "not_requested"
        else:
            collection_status = "unavailable"
        records.append(
            self._storage_policy_summary_record(
                dataset_id,
                collected_at,
                vm_count=len(vms),
                requested_count=requested_count,
                collected_count=collected_count,
                failed_count=failed_count,
                not_requested_count=not_requested_count,
                no_policy_association_count=no_policy_association_count,
                status_counts=status_counts,
                coverage_complete=coverage_complete,
                collection_status=collection_status,
                error_type=global_error_status,
            )
        )
        return records

    def _storage_policy_result_record(
        self,
        vm: Any,
        payload: Any,
        dataset_id: str,
        collected_at: str,
        known_statuses: set[str],
        issue_statuses: set[str],
    ) -> DatasetRecord:
        rule_id = "STO-DEEP-006"
        entity = self._entity(vm, "VirtualMachine")
        if payload is None:
            status = "not_applicable"
            value = {"collection_status": "no_policy_association", "overall_status": status, "vm_home": None, "components": [], "component_status_counts": {}}
            coverage_complete = True
            conflict = False
        elif not isinstance(payload, dict):
            status = "unknown"
            value = {"collection_status": "malformed_response", "overall_status": status, "response_type": type(payload).__name__, "components": []}
            coverage_complete = False
            conflict = False
        else:
            status = self._normalize_storage_policy_status(payload.get("overall_compliance"))
            raw_home = payload.get("vm_home")
            raw_disks = payload.get("disks")
            components: list[dict[str, Any]] = []
            component_unknown = False
            truncated = False

            def component(name: str, item: Any) -> dict[str, Any]:
                nonlocal component_unknown
                if not isinstance(item, dict):
                    component_unknown = True
                    return {"component": name, "status": "unknown"}
                component_status = self._normalize_storage_policy_status(item.get("status"))
                component_unknown = component_unknown or component_status == "unknown"
                policy = item.get("policy")
                check_time = item.get("check_time")
                failures = item.get("failure_cause") if isinstance(item.get("failure_cause"), list) else []
                codes = [str(entry.get("id") or "")[:128] for entry in failures[:MAX_STORAGE_POLICY_FAILURE_CODES] if isinstance(entry, dict) and entry.get("id")]
                return {
                    "component": name,
                    "status": component_status,
                    "policy_id": str(policy)[:256] if policy else None,
                    "check_time": str(check_time)[:64] if check_time else None,
                    "failure_cause_count": len(failures),
                    "failure_cause_ids": codes,
                    "failure_cause_ids_truncated": len(failures) > MAX_STORAGE_POLICY_FAILURE_CODES,
                }

            if isinstance(raw_home, dict):
                components.append(component("vm_home", raw_home))
            disk_items = raw_disks if isinstance(raw_disks, dict) else {}
            if "disks" not in payload or not isinstance(raw_disks, dict):
                component_unknown = True
            for disk_id, info in sorted(disk_items.items(), key=lambda item: str(item[0]))[:MAX_STORAGE_POLICY_COMPONENTS]:
                components.append(component(f"disk/{str(disk_id)[:128]}", info))
            if len(disk_items) > MAX_STORAGE_POLICY_COMPONENTS:
                truncated = True

            component_statuses = [item["status"] for item in components]
            recognized_components = [value for value in component_statuses if value in known_statuses]
            conflict = False
            if components and len(recognized_components) == len(components) and status in (known_statuses - {"unknown"}) and not component_unknown:
                if "out_of_date" in recognized_components:
                    expected = "out_of_date"
                elif "non_compliant" in recognized_components:
                    expected = "non_compliant"
                elif "unknown" in recognized_components:
                    expected = "unknown"
                elif "compliant" in recognized_components:
                    expected = "compliant"
                else:
                    expected = "not_applicable"
                conflict = expected != status
            if not components and status not in {"not_applicable", "unknown"}:
                component_unknown = True
            if conflict:
                status = "unknown"
            coverage_complete = status in known_statuses and not component_unknown and not truncated and not conflict
            value = {
                "collection_status": "collected",
                "overall_status": status,
                "reported_overall_status": self._normalize_storage_policy_status(payload.get("overall_compliance")),
                "vm_home_associated": isinstance(raw_home, dict),
                "disk_component_count": len(disk_items),
                "components": components,
                "component_status_counts": {state: component_statuses.count(state) for state in sorted(set(component_statuses))},
                "component_status_conflict": conflict,
                "components_truncated": truncated,
            }

        component_issue = any(item.get("status") in issue_statuses for item in value.get("components", []))
        finding = (status in issue_statuses or component_issue) and not conflict
        if finding:
            components = value.get("components") or []
            affected = [item["component"] for item in components if item.get("status") in issue_statuses]
            summary = f"VM Storage Policy 合规状态为 {status}"
            if affected:
                summary += f"，受影响组件：{', '.join(affected[:8])}"
        elif status == "compliant" and coverage_complete:
            summary = "VM Storage Policy 缓存状态为 compliant"
        elif status == "not_applicable" and coverage_complete:
            summary = "VM Home 和虚拟磁盘没有 Storage Policy 关联"
        elif conflict:
            summary = "VM Storage Policy 总体状态与组件状态冲突，需要复核"
        else:
            summary = "VM Storage Policy 合规状态未知或组件证据不完整"

        record = self._record(
            dataset_id,
            collected_at,
            "config",
            entity,
            rule_id,
            value,
            "compliance_status",
            finding,
            summary,
            not_applicable=status == "not_applicable" and coverage_complete and not conflict,
        )
        record.window = DeepWindow(start=collected_at, end=collected_at, sample_count=1 if coverage_complete else 0, expected_sample_count=1, completeness=1.0 if coverage_complete else 0.0)
        record.metadata.update(
            {
                "collection_status": value.get("collection_status", "collected"),
                "coverage_complete": coverage_complete,
                "conflict": conflict,
                "vm_ref": entity.display_ref,
            }
        )
        return record

    def _storage_policy_summary_record(
        self,
        dataset_id: str,
        collected_at: str,
        *,
        vm_count: int,
        requested_count: int,
        collected_count: int,
        failed_count: int,
        not_requested_count: int,
        no_policy_association_count: int,
        status_counts: dict[str, int],
        coverage_complete: bool,
        collection_status: str,
        error_type: str | None,
    ) -> DatasetRecord:
        applicable_records = [
            status_counts.get(status, 0)
            for status in ("compliant", "non_compliant", "out_of_date", "unknown", "not_applicable")
        ]
        all_not_applicable = vm_count == 0 or (coverage_complete and status_counts.get("not_applicable", 0) == vm_count)
        if collection_status == "not_requested":
            summary = f"Storage Policy 合规数据未请求：{not_requested_count} 台 VM"
        elif collection_status == "unavailable":
            summary = f"Storage Policy 合规 API 不可用：{failed_count} 台 VM 未取得结果"
        elif all_not_applicable:
            summary = f"已检查 {collected_count} 台 VM；{status_counts.get('not_applicable', 0)} 个结果为 NOT_APPLICABLE，其中 {no_policy_association_count} 个 GET 未返回策略关联信息"
        else:
            summary = f"Storage Policy 合规采集 {collected_count}/{vm_count} 台 VM；未取得 {failed_count}，跳过 {not_requested_count}"
        value = {
            "collection_status": collection_status,
            "vm_count": vm_count,
            "requested_vm_count": requested_count,
            "collected_vm_count": collected_count,
            "failed_vm_count": failed_count,
            "not_requested_vm_count": not_requested_count,
            "no_policy_association_vm_count": no_policy_association_count,
            "compliance_status_counts": status_counts,
            "coverage_complete": coverage_complete,
            "global_error_type": error_type,
            "per_session_vm_request_limit": MAX_STORAGE_POLICY_VM_REQUESTS,
        }
        record = self._record(
            dataset_id,
            collected_at,
            "config",
            self._environment_entity(),
            "STO-DEEP-006",
            value,
            "collection_summary",
            False,
            summary,
            not_applicable=all_not_applicable,
        )
        expected = max(1, vm_count)
        record.window = DeepWindow(
            start=collected_at,
            end=collected_at,
            sample_count=collected_count,
            expected_sample_count=expected,
            completeness=min(1.0, collected_count / expected),
        )
        record.metadata.update({"storage_policy_summary": True, "coverage_complete": coverage_complete, "collection_status": collection_status, "not_applicable": all_not_applicable})
        if applicable_records and sum(applicable_records) > vm_count:
            record.metadata["conflict"] = True
            record.metadata["coverage_complete"] = False
        return record

    @staticmethod
    def _normalize_storage_policy_status(value: Any) -> str:
        raw = str(value or "").strip().casefold()
        token = re.sub(r"[^a-z0-9]", "", raw)
        return {
            "compliant": "compliant",
            "noncompliant": "non_compliant",
            "outofdate": "out_of_date",
            "unknown": "unknown",
            "notapplicable": "not_applicable",
        }.get(token, "unknown")

    @staticmethod
    def _storage_policy_capability(records: list[DatasetRecord], vm_count: int, phase_log: dict[str, Any]) -> Capability:
        summary = next((record for record in records if record.metadata.get("storage_policy_summary")), None)
        detail = summary.value if summary and isinstance(summary.value, dict) else {}
        if phase_log.get("status") in {"not_requested", "partial"} and not records:
            status = CapabilityStatus.NOT_REQUESTED
        elif vm_count == 0:
            status = CapabilityStatus.NOT_APPLICABLE
        else:
            collected = int(detail.get("collected_vm_count") or 0)
            failed = int(detail.get("failed_vm_count") or 0)
            if collected >= vm_count and failed == 0:
                status = CapabilityStatus.AVAILABLE
            elif collected > 0:
                status = CapabilityStatus.LIMITED
            elif phase_log.get("status") == "not_requested":
                status = CapabilityStatus.NOT_REQUESTED
            else:
                status = CapabilityStatus.UNAVAILABLE
        return Capability(
            id="storage.policy.compliance",
            name="VM Storage Policy 合规缓存",
            status=status,
            profile="core",
            detected_via=STORAGE_POLICY_COMPLIANCE_API,
            detail={
                "vm_count": vm_count,
                "requested_vm_count": detail.get("requested_vm_count", 0),
                "collected_vm_count": detail.get("collected_vm_count", 0),
                "failed_vm_count": detail.get("failed_vm_count", 0),
                "not_requested_vm_count": detail.get("not_requested_vm_count", vm_count),
                "no_policy_association_vm_count": detail.get("no_policy_association_vm_count", 0),
                "coverage_complete": detail.get("coverage_complete", False),
                "error_type": detail.get("global_error_type"),
            },
            affects_rules=["STO-DEEP-006"],
        )

    def _hardware_sensor_records(self, hosts: list[Any], dataset_id: str, collected_at: str) -> list[DatasetRecord]:
        result: list[DatasetRecord] = []
        for host in hosts:
            sensors = self._hardware_sensor_issues(host)
            entity = self._entity(host, "HostSystem")
            result.append(
                self._record(
                    dataset_id,
                    collected_at,
                    "hardware",
                    entity,
                    "HARD-DEEP-001",
                    {"issue_count": len(sensors or []), "issues": sensors or []},
                    "count",
                    bool(sensors),
                    f"host hardware sensor reports {len(sensors or [])} red or yellow issue(s)" if sensors is not None else "host hardware sensor data unavailable",
                    not_applicable=sensors is None,
                )
            )
        return result

    def _collect_vsan_performance(self, service_instance: Any, clusters: list[Any], *, resource_guard: Callable[[], str | None] | None = None) -> dict[str, Any]:
        stop_reason = resource_guard() if resource_guard else None
        if stop_reason:
            return {"status": "not_requested", "reason": stop_reason, "supported_metrics": [], "sample_counts": {}}
        if self.cancel_requested():
            return {"status": "not_requested", "reason": "cancelled", "supported_metrics": [], "sample_counts": {}}
        vsan_clusters = [
            cluster
            for cluster in clusters
            if any(str(getattr(getattr(ds, "summary", None), "type", "") or "").casefold() == "vsan" for ds in getattr(cluster, "datastore", []) or [])
        ]
        if not vsan_clusters:
            return {"status": "not_applicable", "supported_metrics": [], "sample_counts": {}}
        try:
            from pyVmomi import vim
            import vsanapiutils

            stub = getattr(service_instance, "_stub", None)
            if stub is None:
                return {"status": "unavailable", "reason": "vSAN API stub unavailable", "supported_metrics": [], "sample_counts": {}}
            try:
                mos = vsanapiutils.GetVsanVcMos(stub, version=vsanapiutils.GetLatestVmodlVersion())
            except TypeError:
                mos = vsanapiutils.GetVsanVcMos(stub)
            manager = mos.get("vsan-performance-manager")
            if manager is None:
                return {"status": "unavailable", "reason": "vSAN Performance Manager unavailable", "supported_metrics": [], "sample_counts": {}}
            cluster = vsan_clusters[0]
            entities = manager.VsanPerfGetSupportedEntityTypes(cluster=cluster) or []
            cluster_entity = next((item for item in entities if str(getattr(item, "name", "")) == "cluster-domclient"), None)
            graphs = list(getattr(cluster_entity, "graphs", []) or []) if cluster_entity else []
            supported_metrics: list[str] = []
            graph_labels: dict[str, list[str]] = {}
            for graph in graphs:
                graph_id = str(getattr(graph, "id", "") or "")
                if graph_id.endswith(".latency"):
                    metric_id = "vsan.latency"
                elif graph_id.endswith(".congestion"):
                    metric_id = "vsan.congestion"
                else:
                    continue
                labels = [str(getattr(metric, "label", "") or "") for metric in getattr(graph, "metrics", []) or []]
                labels = [label for label in labels if label]
                if labels:
                    supported_metrics.append(metric_id)
                    graph_labels[metric_id] = labels
            stop_reason = resource_guard() if resource_guard else None
            if stop_reason:
                return {"status": "not_requested", "reason": stop_reason, "supported_metrics": sorted(set(supported_metrics)), "sample_counts": {}}
            nodes = manager.VsanPerfQueryNodeInformation(cluster=cluster) or []
            master_uuid = next((str(getattr(node, "vsanMasterUuid", "") or "") for node in nodes if getattr(node, "isStatsMaster", False)), "")
            stop_reason = resource_guard() if resource_guard else None
            if stop_reason:
                return {"status": "not_requested", "reason": stop_reason, "supported_metrics": sorted(set(supported_metrics)), "sample_counts": {}}
            ranges = manager.VsanPerfQueryTimeRanges(cluster=cluster, querySpec=vim.cluster.VsanPerfTimeRangeQuerySpec()) or []
            if not master_uuid or not ranges:
                return {"status": "available", "supported_metrics": supported_metrics, "sample_counts": {}, "reason": "performance service has no queryable time range"}
            time_range = ranges[-1]
            records: list[dict[str, Any]] = []
            sample_counts: dict[str, int] = {}
            for metric_id, labels in graph_labels.items():
                stop_reason = resource_guard() if resource_guard else None
                if stop_reason:
                    return {"status": "not_requested", "reason": stop_reason, "supported_metrics": sorted(set(supported_metrics)), "sample_counts": sample_counts, "records": records}
                if self.cancel_requested():
                    return {"status": "not_requested", "reason": "cancelled", "supported_metrics": sorted(set(supported_metrics)), "sample_counts": sample_counts, "records": records}
                try:
                    spec = vim.cluster.VsanPerfQuerySpec(
                        entityRefId=f"cluster-domclient:{master_uuid}",
                        labels=labels,
                        startTime=time_range.startTime,
                        endTime=time_range.endTime,
                        interval=300,
                    )
                    output = manager.QueryVsanPerf(querySpecs=[spec], cluster=cluster) or []
                except Exception as exc:  # noqa: BLE001 - empty or unsupported stats are capability evidence.
                    sample_counts[metric_id] = 0
                    continue
                values: list[float] = []
                for entity_metric in output:
                    for series in getattr(entity_metric, "value", []) or []:
                        for raw in getattr(series, "value", []) or []:
                            try:
                                numeric = float(raw)
                            except (TypeError, ValueError):
                                continue
                            if isfinite(numeric):
                                values.append(numeric)
                sample_counts[metric_id] = len(values)
                if values:
                    records.append(
                        {
                            "metric": metric_id,
                            "values": values,
                            "start": str(time_range.startTime),
                            "end": str(time_range.endTime),
                        }
                    )
            return {
                "status": "available",
                "supported_metrics": sorted(set(supported_metrics)),
                "sample_counts": sample_counts,
                "records": records,
                "time_range": {"start": str(time_range.startTime), "end": str(time_range.endTime)},
            }
        except Exception as exc:  # noqa: BLE001 - performance service is optional.
            return {"status": "unavailable", "reason": type(exc).__name__, "supported_metrics": [], "sample_counts": {}}

    def _vsan_performance_records(self, clusters: list[Any], dataset_id: str, collected_at: str, performance: dict[str, Any]) -> list[DatasetRecord]:
        summaries = performance.get("records") or []
        if not summaries or not clusters:
            return []
        entity = self._entity(clusters[0], "ClusterComputeResource")
        rules = {
            "vsan.latency": ("VSAN-DEEP-006", "millisecond", "TH-STORAGE-LATENCY-HIGH"),
            "vsan.congestion": ("VSAN-DEEP-005", "count", "TH-VSAN-CONGESTION-HIGH"),
        }
        records: list[DatasetRecord] = []
        thresholds = default_threshold_registry()
        for item in summaries:
            metric = str(item.get("metric") or "")
            rule_info = rules.get(metric)
            if rule_info is None:
                continue
            rule_id, unit, threshold_id = rule_info
            values = [float(value) for value in item.get("values") or []]
            if not values:
                continue
            threshold = thresholds.get(threshold_id)
            records.append(
                DatasetRecord(
                    record_id=f"vsan-perf-{metric}-{entity.stable_id}",
                    dataset_id=dataset_id,
                    kind="vsan_perf",
                    entity=entity,
                    collected_at_utc=collected_at,
                    source=DeepSource(api="VsanPerformanceManager.QueryVsanPerf", collector="pyvmomi.deep.vsan.performance", collected_at_utc=collected_at),
                    selector={"metric": metric},
                    window=DeepWindow(start=item.get("start") or collected_at, end=item.get("end") or collected_at, interval_sec=300, sample_count=len(values), expected_sample_count=len(values), completeness=1.0),
                    interval_sec=300,
                    value={"first": values[0], "last": values[-1], "min": min(values), "max": max(values), "average": sum(values) / len(values)},
                    unit=unit,
                    raw_pointer=f"vsan/performance/{metric}.ndjson",
                    finding=max(values) >= threshold.value,
                    summary=f"vSAN {metric} sample maximum is {max(values):.2f}{unit}",
                    metadata={"rule_id": rule_id, "metric": metric, "sample_values": values, "threshold_id": threshold_id},
                )
            )
        return records

    @staticmethod
    def _hardware_sensor_issues(host: Any) -> list[dict[str, str]] | None:
        runtime = getattr(host, "runtime", None)
        health = getattr(runtime, "healthSystemRuntime", None) if runtime else None
        system_health = getattr(health, "systemHealthInfo", None) if health else None
        if system_health is None:
            return None
        issues: list[dict[str, str]] = []
        for sensor in getattr(system_health, "numericSensorInfo", []) or []:
            health_state = getattr(sensor, "healthState", None)
            status = str(getattr(health_state, "key", None) or getattr(health_state, "label", None) or health_state or getattr(sensor, "status", "") or "").casefold()
            if status not in {"red", "yellow", "warning", "critical", "degraded"}:
                continue
            issues.append(
                {
                    "sensor": str(getattr(sensor, "name", None) or getattr(sensor, "id", None) or "hardware sensor"),
                    "status": status,
                    "summary": str(
                        getattr(health_state, "summary", None)
                        or getattr(health_state, "label", None)
                        or getattr(sensor, "unitModifier", "")
                        or status
                    ),
                }
            )
        return issues

    def _network_hidden_risk_records(
        self,
        hosts: list[Any],
        dataset_id: str,
        collected_at: str,
        *,
        clusters: list[Any] | None = None,
        content: Any | None = None,
        resource_guard: Callable[[], str | None] | None = None,
    ) -> list[DatasetRecord]:
        result: list[DatasetRecord] = []
        cluster_by_host: dict[str, str] = {}
        for cluster in clusters or []:
            cluster_id = self._entity(cluster, "ClusterComputeResource").stable_id
            for host in getattr(cluster, "host", []) or []:
                host_moid = str(getattr(host, "_moId", "") or "")
                if host_moid:
                    cluster_by_host[host_moid] = cluster_id

        host_signatures: list[dict[str, Any]] = []
        for host in hosts:
            entity = self._entity(host, "HostSystem")
            network = getattr(getattr(host, "config", None), "network", None)
            switches = self._network_uplink_entries(network)
            known_switches = [item for item in switches if item["uplink_count"] is not None]
            single_uplink = [item for item in known_switches if item["uplink_count"] < 2]
            unique_uplinks = sorted({pnic for item in known_switches for pnic in item["uplinks"]})
            uplink_value = {
                "switch_count": len(switches),
                "known_switch_count": len(known_switches),
                "single_or_zero_uplink_switches": single_uplink,
                "unknown_uplink_switches": [item for item in switches if item["uplink_count"] is None],
                "host_unique_uplink_count": len(unique_uplinks),
                "host_unique_uplinks": unique_uplinks,
            }
            uplink_finding = bool(single_uplink)
            uplink_summary = (
                f"{len(single_uplink)} 个 vSwitch/VDS proxy 的已知物理上联少于 2 条"
                if uplink_finding
                else f"已检查 {len(known_switches)} 个 vSwitch/VDS proxy；没有发现单上联网络"
            )
            uplink_record = self._record(
                dataset_id,
                collected_at,
                "config",
                entity,
                "NET-DEEP-003",
                uplink_value,
                "configuration",
                uplink_finding,
                uplink_summary,
                not_applicable=not bool(switches),
            )
            if switches:
                completeness = len(known_switches) / len(switches)
                uplink_record.window = DeepWindow(
                    start=collected_at,
                    end=collected_at,
                    sample_count=len(known_switches),
                    expected_sample_count=len(switches),
                    completeness=completeness,
                )
            result.append(uplink_record)

            host_moid = str(getattr(host, "_moId", "") or "")
            host_signatures.append(
                {
                    "host_id": entity.stable_id,
                    "cluster_id": cluster_by_host.get(host_moid),
                    "signature": self._network_signature(network) if network is not None else None,
                }
            )

        differences, comparable_property_count, compared_cluster_count, compared_host_count = self._network_signature_differences(host_signatures)
        distributed_network_profiles = self._collect_distributed_network_profiles(content, resource_guard=resource_guard)
        network_hosts = sum(1 for item in host_signatures if item.get("signature") is not None)
        expected_hosts = len(hosts)
        completeness = compared_host_count / expected_hosts if expected_hosts else 1.0
        if compared_cluster_count and comparable_property_count == 0:
            completeness = 0.0
        drift_value = {
            "comparison": {
                "host_count": expected_hosts,
                "network_data_host_count": network_hosts,
                "compared_host_count": compared_host_count,
                "same_cluster_count": compared_cluster_count,
                "comparable_network_property_count": comparable_property_count,
                "difference_count": len(differences),
            },
            "differences": differences,
            "host_signatures": host_signatures,
            "distributed_network_profiles": distributed_network_profiles,
        }
        drift_record = self._record(
            dataset_id,
            collected_at,
            "config",
            self._environment_entity(),
            "NET-DEEP-004",
            drift_value,
            "signature",
            bool(differences),
            (
                f"同一集群中发现 {len(differences)} 项共享网络配置差异"
                if differences
                else f"已比较 {comparable_property_count} 项同集群、同名网络属性，未发现差异"
            ),
            not_applicable=compared_cluster_count == 0,
        )
        drift_record.window = DeepWindow(
            start=collected_at,
            end=collected_at,
            sample_count=compared_host_count,
            expected_sample_count=expected_hosts,
            completeness=completeness,
        )
        drift_record.metadata["comparison_scope"] = "same-named standard networks and same-UUID host proxy switches within a cluster"
        result.append(drift_record)
        return result

    @staticmethod
    def _network_uplink_entries(network: Any) -> list[dict[str, Any]]:
        if network is None:
            return []
        result: list[dict[str, Any]] = []
        for switch in getattr(network, "vswitch", []) or []:
            name = str(getattr(switch, "name", "") or getattr(switch, "key", "") or "standard-vSwitch")
            pnic = getattr(switch, "pnic", None)
            uplinks = sorted({str(item).strip() for item in pnic or [] if str(item).strip()}) if pnic is not None else None
            result.append({"type": "vSwitch", "key": name, "uplink_count": len(uplinks) if uplinks is not None else None, "uplinks": uplinks or []})
        for switch in getattr(network, "proxySwitch", []) or []:
            key = str(getattr(switch, "dvsUuid", "") or getattr(switch, "dvsName", "") or getattr(switch, "key", "") or "distributed-vSwitch")
            pnic = getattr(switch, "pnic", None)
            uplinks = sorted({str(item).strip() for item in pnic or [] if str(item).strip()}) if pnic is not None else None
            result.append({"type": "vDS proxy", "key": key, "uplink_count": len(uplinks) if uplinks is not None else None, "uplinks": uplinks or []})
        return sorted(result, key=lambda item: (item["type"], item["key"]))

    def _collect_distributed_network_profiles(
        self,
        content: Any | None,
        *,
        resource_guard: Callable[[], str | None] | None = None,
    ) -> dict[str, Any]:
        if content is None:
            return {"status": "not_requested", "reason": "vCenter content unavailable", "switch_count": 0, "portgroup_count": 0, "switches": [], "portgroups": []}
        stop_reason = resource_guard() if resource_guard else None
        if stop_reason:
            return {"status": "not_requested", "reason": stop_reason, "switch_count": 0, "portgroup_count": 0, "switches": [], "portgroups": []}
        try:
            from pyVmomi import vim

            view = content.viewManager.CreateContainerView(
                content.rootFolder,
                [vim.DistributedVirtualSwitch, vim.dvs.DistributedVirtualPortgroup],
                True,
            )
            try:
                objects = list(view.view or [])
            finally:
                view.Destroy()
        except Exception as exc:  # noqa: BLE001 - preserve an explicit read-only capability state.
            return {"status": "unavailable", "reason": type(exc).__name__, "switch_count": 0, "portgroup_count": 0, "switches": [], "portgroups": []}

        switch_by_moid: dict[str, dict[str, Any]] = {}
        switches: list[dict[str, Any]] = []
        portgroups: list[dict[str, Any]] = []
        truncated = False
        for item in objects:
            type_name = type(item).__name__
            wsdl_name = str(getattr(type(item), "_wsdlName", "") or "")
            if isinstance(item, vim.DistributedVirtualSwitch) or "DistributedVirtualSwitch" in type_name or wsdl_name.endswith("DistributedVirtualSwitch"):
                config = getattr(item, "config", None)
                uuid = str(getattr(item, "uuid", "") or getattr(config, "uuid", "") or "")
                profile = {
                    "uuid": uuid or None,
                    "name": str(getattr(config, "name", "") or getattr(item, "name", "") or ""),
                    "default_vlan": self._distributed_vlan_signature(getattr(getattr(config, "defaultPortConfig", None), "vlan", None)),
                    "default_teaming": self._teaming_policy_signature(getattr(getattr(config, "defaultPortConfig", None), "uplinkTeamingPolicy", None)),
                }
                switch_id = str(getattr(item, "_moId", "") or uuid)
                if switch_id:
                    switch_by_moid[switch_id] = profile
                if len(switches) < MAX_DVS_NETWORK_PROFILES:
                    switches.append(profile)
                else:
                    truncated = True
                continue
            if isinstance(item, vim.dvs.DistributedVirtualPortgroup) or "DistributedVirtualPortgroup" in type_name or wsdl_name.endswith("DistributedVirtualPortgroup"):
                config = getattr(item, "config", None)
                if config is None:
                    continue
                dvs_ref = getattr(config, "distributedVirtualSwitch", None)
                dvs_id = str(getattr(dvs_ref, "_moId", "") or getattr(dvs_ref, "value", "") or "") if dvs_ref else ""
                dvs = switch_by_moid.get(dvs_id, {})
                default = getattr(config, "defaultPortConfig", None)
                profile = {
                    "dvs_uuid": dvs.get("uuid"),
                    "dvs_name": dvs.get("name") or None,
                    "name": str(getattr(config, "name", "") or getattr(item, "name", "") or ""),
                    "vlan": self._distributed_vlan_signature(getattr(default, "vlan", None) if default is not None else None),
                    "teaming": self._teaming_policy_signature(getattr(default, "uplinkTeamingPolicy", None) if default is not None else None),
                }
                if len(portgroups) < MAX_DVS_NETWORK_PROFILES:
                    portgroups.append(profile)
                else:
                    truncated = True
        switches.sort(key=lambda item: (item.get("name") or "", item.get("uuid") or ""))
        portgroups.sort(key=lambda item: (item.get("dvs_name") or "", item.get("name") or ""))
        status = "available" if switches or portgroups else "not_applicable"
        return {
            "status": status,
            "switch_count": sum(1 for item in objects if isinstance(item, vim.DistributedVirtualSwitch) or "DistributedVirtualSwitch" in type(item).__name__),
            "portgroup_count": sum(1 for item in objects if isinstance(item, vim.dvs.DistributedVirtualPortgroup) or "DistributedVirtualPortgroup" in type(item).__name__),
            "switches": switches,
            "portgroups": portgroups,
            "truncated": truncated,
        }

    @staticmethod
    def _distributed_vlan_signature(vlan: Any) -> dict[str, Any] | None:
        if vlan is None:
            return None
        result: dict[str, Any] = {"spec_type": type(vlan).__name__}
        for field in ("vlanId", "pvlanId"):
            raw = getattr(vlan, field, None)
            if raw is None:
                continue
            if isinstance(raw, (list, tuple)):
                result["ranges"] = [
                    {key: getattr(item, key, None) for key in ("start", "end") if getattr(item, key, None) is not None}
                    for item in raw
                ]
            else:
                result[field] = PyVmomiDeepCollector._network_policy_scalar(raw)
        return result

    @staticmethod
    def _network_policy_scalar(value: Any) -> Any:
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, (list, tuple)):
            return [PyVmomiDeepCollector._network_policy_scalar(item) for item in value[:32]]
        if "value" in getattr(type(value), "_propInfo", {}):
            return PyVmomiDeepCollector._network_policy_scalar(getattr(value, "value", None))
        return str(value)

    @staticmethod
    def _teaming_policy_signature(policy: Any) -> dict[str, Any] | None:
        if policy is None:
            return None
        values = {
            "policy": PyVmomiDeepCollector._network_policy_scalar(getattr(policy, "policy", None)),
            "notify_switches": PyVmomiDeepCollector._network_policy_scalar(getattr(policy, "notifySwitches", None)),
            "rolling_order": PyVmomiDeepCollector._network_policy_scalar(getattr(policy, "rollingOrder", None)),
            "reverse_policy": PyVmomiDeepCollector._network_policy_scalar(getattr(policy, "reversePolicy", None)),
        }
        order = getattr(policy, "nicOrder", None) or getattr(policy, "uplinkPortOrder", None)
        if order is not None:
            for source, alternate, target in (
                ("activeNic", "activeUplinkPort", "active_uplink_count"),
                ("standbyNic", "standbyUplinkPort", "standby_uplink_count"),
            ):
                uplinks = getattr(order, source, None)
                if uplinks is None:
                    uplinks = getattr(order, alternate, None)
                if uplinks is not None:
                    values[target] = len(uplinks)
        failure = getattr(policy, "failureCriteria", None)
        if failure is not None:
            criteria = {
                name: PyVmomiDeepCollector._network_policy_scalar(getattr(failure, name, None))
                for name in ("checkBeacon", "checkDuplex", "checkErrorPercent", "checkSpeed", "checkStatus", "speed", "fullDuplex", "percentage")
                if getattr(failure, name, None) is not None
            }
            if criteria:
                values["failure_criteria"] = criteria
        return {key: value for key, value in values.items() if value is not None}

    def _network_signature(self, network: Any) -> dict[str, Any] | None:
        if network is None:
            return None
        signature: dict[str, dict[str, Any]] = {
            "vswitches": {},
            "portgroups": {},
            "vmkernel_nics": {},
            "proxy_switches": {},
        }
        for switch in getattr(network, "vswitch", []) or []:
            name = str(getattr(switch, "name", "") or getattr(switch, "key", "") or "")
            if not name:
                continue
            spec = getattr(switch, "spec", None)
            mtu = getattr(spec, "mtu", None) if spec is not None else None
            if mtu is None:
                mtu = getattr(switch, "mtu", None)
            policy = getattr(spec, "policy", None) if spec is not None else None
            teaming = self._teaming_policy_signature(getattr(policy, "nicTeaming", None) if policy is not None else None)
            signature["vswitches"][name] = {"mtu": mtu, "teaming": teaming}
        for group in getattr(network, "portgroup", []) or []:
            spec = getattr(group, "spec", None)
            if spec is None:
                continue
            name = str(getattr(spec, "name", "") or "")
            switch_name = str(getattr(spec, "vswitchName", "") or "")
            if not name or not switch_name:
                continue
            key = f"{switch_name}/{name}"
            policy = getattr(spec, "policy", None)
            teaming = self._teaming_policy_signature(getattr(policy, "nicTeaming", None) if policy is not None else None)
            signature["portgroups"][key] = {"vlan_id": getattr(spec, "vlanId", None), "teaming": teaming}
        vmkernel_mtus: dict[str, set[int]] = {}
        for vnic in getattr(network, "vnic", []) or []:
            spec = getattr(vnic, "spec", None)
            mtu = getattr(spec, "mtu", None) if spec is not None else None
            if mtu is None:
                continue
            key = str(getattr(vnic, "portgroup", "") or getattr(vnic, "device", "") or "")
            if key:
                vmkernel_mtus.setdefault(key, set()).add(int(mtu))
        signature["vmkernel_nics"] = {key: {"mtu_values": sorted(values)} for key, values in sorted(vmkernel_mtus.items())}
        for switch in getattr(network, "proxySwitch", []) or []:
            key = str(getattr(switch, "dvsUuid", "") or getattr(switch, "dvsName", "") or "")
            if not key:
                continue
            signature["proxy_switches"][key] = {"mtu": getattr(switch, "mtu", None)}
        return signature

    @staticmethod
    def _network_signature_differences(host_signatures: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int, int, int]:
        grouped: dict[str, list[dict[str, Any]]] = {}
        for item in host_signatures:
            cluster_id = str(item.get("cluster_id") or "")
            if cluster_id:
                grouped.setdefault(cluster_id, []).append(item)
        differences: list[dict[str, Any]] = []
        comparable_properties = 0
        compared_clusters = 0
        compared_hosts: set[str] = set()
        for cluster_id, hosts in sorted(grouped.items()):
            if len(hosts) < 2:
                continue
            compared_clusters += 1
            available_hosts = [host for host in hosts if isinstance(host.get("signature"), dict)]
            if len(available_hosts) < 2:
                continue
            compared_hosts.update(str(host["host_id"]) for host in available_hosts)
            network_types = sorted({key for host in available_hosts for key in host["signature"]})
            for network_type in network_types:
                network_keys = sorted({key for host in available_hosts for key in (host["signature"].get(network_type) or {})})
                for network_key in network_keys:
                    observations = [
                        (str(host["host_id"]), host["signature"].get(network_type, {}).get(network_key))
                        for host in available_hosts
                        if network_key in host["signature"].get(network_type, {})
                    ]
                    if not observations:
                        continue
                    if len(observations) < len(available_hosts):
                        comparable_properties += 1
                        differences.append(
                            {
                                "cluster_id": cluster_id,
                                "network_type": network_type,
                                "network_key": network_key,
                                "property": "membership",
                                "present_host_count": len(observations),
                                "cluster_host_count": len(available_hosts),
                                "host_ids": [host_id for host_id, _ in observations],
                            }
                        )
                    if len(observations) < 2:
                        continue
                    fields = sorted({field for _, value in observations if isinstance(value, dict) for field in value})
                    for field in fields:
                        field_values = [(host_id, value[field]) for host_id, value in observations if isinstance(value, dict) and value.get(field) is not None]
                        if len(field_values) < 2:
                            continue
                        comparable_properties += 1
                        canonical = {json.dumps(value, sort_keys=True, ensure_ascii=False, default=str) for _, value in field_values}
                        if len(canonical) > 1:
                            differences.append(
                                {
                                    "cluster_id": cluster_id,
                                    "network_type": network_type,
                                    "network_key": network_key,
                                    "property": field,
                                    "observations": [{"host_id": host_id, "value": value} for host_id, value in field_values],
                                }
                            )
        return differences, comparable_properties, compared_clusters, len(compared_hosts)

    def _thin_provision_records(self, vms: list[Any], datastores: list[Any], dataset_id: str, collected_at: str) -> list[DatasetRecord]:
        virtual_capacity: dict[str, float] = {}
        for vm in vms:
            vm_datastores = {str(getattr(item, "name", "") or "") for item in getattr(vm, "datastore", []) or []}
            disks = [device for device in getattr(getattr(getattr(vm, "config", None), "hardware", None), "device", []) or [] if hasattr(device, "capacityInKB")]
            for disk in disks:
                backing = getattr(disk, "backing", None)
                datastore_name = str(getattr(getattr(backing, "datastore", None), "name", "") or "") if backing else ""
                targets = [datastore_name] if datastore_name else list(vm_datastores) if len(vm_datastores) == 1 else []
                for name in targets:
                    virtual_capacity[name] = virtual_capacity.get(name, 0.0) + float(getattr(disk, "capacityInKB", 0) or 0)
        threshold = default_threshold_registry().get("TH-THIN-PROVISION-RATIO").value
        result: list[DatasetRecord] = []
        for datastore in datastores:
            name = str(getattr(datastore, "name", "") or "")
            capacity = float(getattr(getattr(datastore, "summary", None), "capacity", 0) or 0)
            virtual = virtual_capacity.get(name, 0.0) * 1024
            ratio = virtual / capacity if capacity > 0 else None
            result.append(self._record(dataset_id, collected_at, "config", self._entity(datastore, "Datastore"), "STO-DEEP-005", ratio, "ratio", bool(ratio is not None and ratio >= threshold), f"virtual to physical capacity ratio is {ratio:.2f}" if ratio is not None else "virtual capacity unavailable", not_applicable=ratio is None))
        return result

    def _capacity_trend_records(self, vms: list[Any], datastores: list[Any], dataset_id: str, collected_at: str) -> list[DatasetRecord]:
        environment = self._environment_entity()
        records = [self._record(dataset_id, collected_at, "perf", environment, "CAP-DEEP-002", len(vms), "count", False, f"vCenter inventory contains {len(vms)} virtual machines")]
        ratios: list[float] = []
        for record in self._thin_provision_records(vms, datastores, dataset_id, collected_at):
            try:
                ratio = float(record.value)
            except (TypeError, ValueError):
                continue
            if isfinite(ratio):
                ratios.append(ratio)
        if ratios:
            average = sum(ratios) / len(ratios)
            records.append(self._record(dataset_id, collected_at, "perf", environment, "CAP-DEEP-003", round(average, 4), "ratio", False, f"average thin provision ratio across {len(ratios)} datastores is {average:.2f}"))
        return records

    def _lifecycle_records(self, content: Any, hosts: list[Any], clusters: list[Any], dataset_id: str, collected_at: str) -> list[DatasetRecord]:
        result: list[DatasetRecord] = []
        environment = self._environment_entity()
        license_manager = getattr(content, "licenseManager", None)
        license_records: list[Any] = []
        collection_status = "available"
        error_type: str | None = None
        try:
            if license_manager is None:
                collection_status = "unavailable"
            else:
                license_records = list(getattr(license_manager, "licenses", []) or [])
                if not license_records:
                    collection_status = "empty"
        except Exception as exc:  # noqa: BLE001 - license access is a scoped capability result.
            collection_status = "unavailable"
            error_type = type(exc).__name__

        expiry_window_days = int(default_threshold_registry().get("TH-LIFECYCLE-EXPIRY-WINDOW").value)
        license_items: list[dict[str, Any]] = []
        evaluation = False
        expired_or_soon_count = 0
        used_exceeds_total_count = 0
        unknown_capacity_count = 0
        for item in license_records:
            # Never read or serialize licenseKey; only keep non-secret status fields.
            name = str(getattr(item, "name", "") or "")
            edition = str(getattr(item, "editionKey", "") or "")
            evaluation = evaluation or "eval" in name.casefold() or "evaluation" in name.casefold() or "eval" in edition.casefold()
            expiration = getattr(item, "expirationDate", None)
            expiration_utc: str | None = None
            days_remaining: int | None = None
            if isinstance(expiration, datetime):
                normalized_expiration = expiration.replace(tzinfo=UTC) if expiration.tzinfo is None else expiration.astimezone(UTC)
                expiration_utc = normalized_expiration.replace(microsecond=0).isoformat().replace("+00:00", "Z")
                days_remaining = (normalized_expiration.date() - datetime.now(UTC).date()).days
                if days_remaining <= expiry_window_days:
                    expired_or_soon_count += 1
            used = getattr(item, "used", None)
            total = getattr(item, "total", None)
            try:
                used_value = int(used) if used is not None else None
            except (TypeError, ValueError):
                used_value = None
            try:
                total_value = int(total) if total is not None else None
            except (TypeError, ValueError):
                total_value = None
            cost_unit = str(getattr(item, "costUnit", "") or "").strip() or None
            capacity_known = used_value is not None and total_value is not None and bool(cost_unit)
            over_capacity = bool(capacity_known and total_value is not None and total_value >= 0 and used_value is not None and used_value > total_value)
            capacity_status = "unknown" if not capacity_known else "used_exceeds_total" if over_capacity else "within_capacity"
            if not capacity_known:
                unknown_capacity_count += 1
            if over_capacity:
                used_exceeds_total_count += 1
            license_items.append(
                {
                    "edition": edition or name or None,
                    "cost_unit": cost_unit,
                    "evaluation": "eval" in name.casefold() or "evaluation" in name.casefold() or "eval" in edition.casefold(),
                    "expiration_utc": expiration_utc,
                    "days_remaining": days_remaining,
                    "used": used_value,
                    "total": total_value,
                    "capacity_status": capacity_status,
                    "used_exceeds_total": over_capacity,
                }
            )
        license_finding = bool(evaluation or expired_or_soon_count or used_exceeds_total_count)
        license_value = {
            "collection_status": collection_status,
            "license_count": len(license_items),
            "evaluation_license": evaluation,
            "expiring_or_expired_count": expired_or_soon_count,
            "used_exceeds_total_count": used_exceeds_total_count,
            "capacity_unknown_count": unknown_capacity_count,
            "licenses": license_items,
            "error_type": error_type,
        }
        license_summary = (
            f"评估许可 {int(evaluation)} 项、到期窗口内或已过期许可 {expired_or_soon_count} 项、used 高于 total 的许可条目 {used_exceeds_total_count} 项，容量字段未报告 {unknown_capacity_count} 项；需在许可页面核对"
            if collection_status == "available"
            else "vCenter 许可清单为空或不可读取，未据此判为正常"
        )
        license_record = self._record(
            dataset_id,
            collected_at,
            "config",
            environment,
            "SEC-DEEP-004",
            license_value,
            "state",
            license_finding,
            license_summary,
            not_applicable=license_manager is None,
        )
        license_record.source = DeepSource(api="LicenseManager.licenses", collector="pyvmomi.deep.lifecycle", collected_at_utc=collected_at)
        license_coverage_complete = collection_status == "available" and bool(license_items) and unknown_capacity_count == 0
        license_record.window = DeepWindow(
            start=collected_at,
            end=collected_at,
            sample_count=max(0, len(license_items) - unknown_capacity_count),
            expected_sample_count=max(1, len(license_items)),
            completeness=(len(license_items) - unknown_capacity_count) / max(1, len(license_items)) if license_coverage_complete else 0.0,
        )
        license_record.metadata.update({"collection_status": collection_status, "coverage_complete": license_coverage_complete})
        result.append(license_record)
        for cluster in clusters:
            entity = self._entity(cluster, "ClusterComputeResource")
            versions: list[str] = []
            for host in getattr(cluster, "host", []) or []:
                config = getattr(host, "config", None)
                product = getattr(config, "product", None) if config else None
                version = str(getattr(product, "version", "") or "")
                build = str(getattr(product, "build", "") or "")
                if version or build:
                    versions.append(f"{version}:{build}")
            distinct = sorted(set(versions))
            result.append(self._record(dataset_id, collected_at, "config", entity, "LIFE-DEEP-002", distinct, "version_set", len(distinct) > 1, f"cluster contains {len(distinct)} ESXi version/build combinations", not_applicable=not bool(distinct)))
        return result

    def _collect_vsan_management_inventory(
        self,
        service_instance: Any,
        clusters: list[Any],
        vms: list[Any],
    ) -> dict[str, Any]:
        """Reuse the established standard vSAN collector on this read-only session."""

        from vstacklens.collection.pyvmomi_collector import PyVmomiCollector

        collector = PyVmomiCollector(
            self.host,
            self.username,
            self.password,
            self.port,
            self.ssl_verify,
            timeout=30,
        )
        try:
            return collector.collect_vsan_management_inventory(service_instance, clusters, vms)
        except Exception as exc:  # noqa: BLE001 - a vSAN API failure is a capability result.
            return {
                "status": "error",
                "collection_error": type(exc).__name__,
                "clusters": {},
            }

    def _vsan_records(
        self,
        clusters: list[Any],
        datastores: list[Any],
        dataset_id: str,
        collected_at: str,
        inventory: dict[str, Any],
    ) -> list[DatasetRecord]:
        result: list[DatasetRecord] = []
        threshold = default_threshold_registry().get("TH-VSAN-CAPACITY-HIGH").value
        for datastore in datastores:
            summary = getattr(datastore, "summary", None)
            datastore_type = str(getattr(summary, "type", "") or "").lower() if summary else ""
            if datastore_type != "vsan":
                continue
            capacity = float(getattr(summary, "capacity", 0) or 0)
            free = float(getattr(summary, "freeSpace", 0) or 0)
            used = ((capacity - free) / capacity * 100) if capacity > 0 else None
            result.append(self._record(dataset_id, collected_at, "vsan", self._entity(datastore, "Datastore"), "VSAN-DEEP-001", used, "percent", bool(used is not None and used >= threshold), f"vSAN datastore used percent is {used:.2f}" if used is not None else "vSAN capacity unavailable", not_applicable=used is None))

        cluster_summaries = inventory.get("clusters") or {}
        for cluster in clusters:
            name = str(getattr(cluster, "name", "") or "")
            summary = cluster_summaries.get(name)
            if not isinstance(summary, dict):
                continue
            entity = self._entity(cluster, "ClusterComputeResource")
            source = summary.get("source") if isinstance(summary.get("source"), dict) else {}

            object_issues = summary.get("object_health_issues")
            if isinstance(object_issues, list):
                result.append(
                    self._vsan_management_record(
                        dataset_id,
                        collected_at,
                        entity,
                        "VSAN-DEEP-002",
                        "object_health",
                        {
                            "issue_count": len(object_issues),
                            "issues": object_issues,
                            "overall_health": summary.get("native_overall_health"),
                        },
                        len(object_issues) > 0,
                        f"vSAN Object Health reports {len(object_issues)} issue(s)",
                        source,
                    )
                )

            suspended = summary.get("resync_suspended_object_count")
            if isinstance(suspended, int):
                result.append(
                    self._vsan_management_record(
                        dataset_id,
                        collected_at,
                        entity,
                        "VSAN-DEEP-003",
                        "resync_suspended",
                        {
                            "object_count": summary.get("resync_object_count"),
                            "bytes": summary.get("resync_bytes"),
                            "active_object_count": summary.get("resync_active_object_count"),
                            "queued_object_count": summary.get("resync_queued_object_count"),
                            "suspended_object_count": suspended,
                        },
                        suspended > 0,
                        f"vSAN Resync has {suspended} suspended object(s)",
                        source,
                    )
                )

            disk_issues = summary.get("disk_health_issues")
            if isinstance(disk_issues, list):
                result.append(
                    self._vsan_management_record(
                        dataset_id,
                        collected_at,
                        entity,
                        "VSAN-DEEP-004",
                        "disk_group_health",
                        {
                            "issue_count": len(disk_issues),
                            "issues": disk_issues,
                            "disk_group_count": summary.get("disk_group_count"),
                            "cache_disk_count": summary.get("cache_disk_count"),
                            "capacity_disk_count": summary.get("capacity_disk_count"),
                        },
                        len(disk_issues) > 0,
                        f"vSAN Disk Group health reports {len(disk_issues)} issue(s)",
                        source,
                    )
                )
        return result

    def _vsan_management_record(
        self,
        dataset_id: str,
        collected_at: str,
        entity: DeepEntity,
        rule_id: str,
        metric: str,
        value: dict[str, Any],
        finding: bool,
        summary: str,
        source_detail: dict[str, Any],
    ) -> DatasetRecord:
        managed_object = str(source_detail.get("managed_object") or "vSAN Management API")
        return DatasetRecord(
            record_id=f"{rule_id}-{entity.stable_id}",
            dataset_id=dataset_id,
            kind="vsan",
            entity=entity,
            collected_at_utc=collected_at,
            source=DeepSource(
                api=managed_object,
                collector="pyvmomi.deep.vsan",
                collected_at_utc=collected_at,
            ),
            selector={"rule_id": rule_id, "metric": metric},
            window=DeepWindow(start=collected_at, end=collected_at, sample_count=1, expected_sample_count=1, completeness=1.0),
            value=value,
            unit="count",
            raw_pointer=f"vsan/{entity.stable_id}/{metric}.ndjson",
            finding=finding,
            summary=summary,
            metadata={"rule_id": rule_id, "source": source_detail},
        )

    def _storage_path_evidence(self, host: Any) -> dict[str, Any] | None:
        storage = getattr(getattr(host, "config", None), "storageDevice", None)
        multipath = getattr(storage, "multipathInfo", None) if storage else None
        luns = getattr(multipath, "lun", None) if multipath else None
        if luns is None:
            return None
        bad_states = {"dead", "error", "off", "disabled", "lost"}
        usable_states = {"active", "standby"}
        local_identifiers: set[str] = set()
        for item in getattr(storage, "scsiLun", []) or []:
            if not bool(getattr(item, "localDisk", False)):
                continue
            for attribute in ("key", "uuid", "canonicalName", "displayName", "devicePath"):
                value = str(getattr(item, attribute, "") or "").strip()
                if value:
                    local_identifiers.add(value.casefold())
        target_luns: list[dict[str, Any]] = []
        issues: list[dict[str, Any]] = []
        expected_path_count = 0
        known_path_count = 0
        unknown_path_count = 0
        skipped_local_lun_count = 0
        for lun_index, lun in enumerate(luns or []):
            raw_lun = getattr(lun, "lun", None)
            lun_key = str(
                getattr(lun, "key", None)
                or getattr(lun, "id", None)
                or getattr(raw_lun, "key", None)
                or getattr(raw_lun, "value", None)
                or getattr(raw_lun, "uuid", None)
                or getattr(raw_lun, "canonicalName", None)
                or getattr(raw_lun, "deviceName", None)
                or f"lun-{lun_index}"
            )
            lun_identifiers = {
                str(getattr(lun, attribute, "") or "").strip().casefold()
                for attribute in ("key", "id")
                if getattr(lun, attribute, None)
            }
            if raw_lun is not None:
                lun_identifiers.update(
                    str(getattr(raw_lun, attribute, "") or "").strip().casefold()
                    for attribute in ("key", "value", "uuid", "canonicalName", "displayName", "devicePath")
                    if getattr(raw_lun, attribute, None)
                )
            is_local = bool(getattr(raw_lun, "localDisk", False)) or bool(lun_identifiers & local_identifiers)
            if is_local:
                skipped_local_lun_count += 1
                continue
            raw_paths = getattr(lun, "path", None)
            if raw_paths is None:
                unknown_path_count += 1
                target_luns.append({"lun_ref": lun_key, "status": "path_list_unavailable"})
                continue
            paths = list(raw_paths or [])
            state_counts: Counter[str] = Counter()
            unknown_states = 0
            for path in paths:
                state = str(getattr(path, "pathState", "") or "").casefold()
                if state and state != "unknown":
                    state_counts[state] += 1
                    known_path_count += 1
                else:
                    if state:
                        state_counts[state] += 1
                    unknown_states += 1
                    unknown_path_count += 1
            expected_path_count += len(paths)
            usable_count = sum(state_counts[state] for state in usable_states)
            failed_count = sum(state_counts[state] for state in bad_states)
            row = {
                "lun_ref": lun_key,
                "path_count": len(paths),
                "path_state_counts": dict(sorted(state_counts.items())),
                "usable_path_count": usable_count,
                "failed_path_count": failed_count,
                "unknown_path_count": unknown_states,
            }
            if not paths:
                row["status"] = "no_paths_returned"
                unknown_path_count += 1
            elif failed_count or (usable_count < 2 and unknown_states == 0):
                row["status"] = "redundancy_issue"
                reasons = []
                if failed_count:
                    reasons.append("failed_path")
                if usable_count < 2:
                    reasons.append("fewer_than_two_usable_paths")
                row["risk_reasons"] = reasons
                issues.append({"lun_ref": lun_key, "usable_path_count": usable_count, "failed_path_count": failed_count, "risk_reasons": reasons})
            elif unknown_states:
                row["status"] = "partial_path_state"
            else:
                row["status"] = "redundant"
            target_luns.append(row)
        coverage_complete = unknown_path_count == 0 and all(
            item.get("status") not in {"path_list_unavailable", "no_paths_returned", "partial_path_state"}
            for item in target_luns
        )
        return {
            "scope_status": "evaluated" if target_luns else "no_shared_block_luns",
            "shared_block_lun_count": len(target_luns),
            "local_lun_excluded_count": skipped_local_lun_count,
            "expected_path_count": expected_path_count,
            "known_path_count": known_path_count,
            "unknown_path_count": unknown_path_count,
            "failed_path_count": sum(int(item.get("failed_path_count") or 0) for item in target_luns),
            "single_or_zero_usable_path_count": sum(1 for item in target_luns if item.get("usable_path_count", 0) < 2),
            "issues": issues,
            "target_luns": target_luns,
            "coverage_complete": coverage_complete,
            "usable_path_states": sorted(usable_states),
            "failed_path_states": sorted(bad_states),
        }

    def _record(self, dataset_id: str, collected_at: str, kind: str, entity: DeepEntity, rule_id: str, value: Any, unit: str, finding: bool, summary: str, *, not_applicable: bool = False) -> DatasetRecord:
        return DatasetRecord(record_id=f"{rule_id}-{entity.stable_id}", dataset_id=dataset_id, kind=kind, entity=entity, collected_at_utc=collected_at, source=DeepSource(api="pyVmomi", collector="pyvmomi.deep", collected_at_utc=collected_at), selector={"rule_id": rule_id}, window=DeepWindow(start=collected_at, end=collected_at, sample_count=1, expected_sample_count=1, completeness=1.0), value=value, unit=unit, raw_pointer=f"{kind}/{entity.stable_id}.ndjson", finding=finding, summary=summary, metadata={"rule_id": rule_id, "not_applicable": not_applicable})

    def _view(self, content: Any, vim_type: Any) -> list[Any]:
        view = content.viewManager.CreateContainerView(content.rootFolder, [vim_type], True)
        try:
            return list(view.view)
        finally:
            view.Destroy()

    def _walk_snapshots(self, roots: list[Any]) -> list[Any]:
        result: list[Any] = []
        for item in roots:
            result.append(item)
            result.extend(self._walk_snapshots(getattr(item, "childSnapshotList", []) or []))
        return result

    def _entity(self, obj: Any, object_type: str) -> DeepEntity:
        props = getattr(getattr(obj, "config", None), "instanceUuid", None) or getattr(getattr(obj, "config", None), "uuid", None) or getattr(getattr(obj, "summary", None), "url", None)
        name = str(getattr(obj, "name", "unknown") or "unknown")
        stable = str(props or "")
        if not stable:
            stable = "derived:" + hashlib.sha256(f"{self.host}|{object_type}|{name}".encode("utf-8")).hexdigest()[:24]
        return DeepEntity(type=object_type, stable_id=stable, display_ref=name)

    def _environment_entity(self) -> DeepEntity:
        return DeepEntity(type="vCenter", stable_id="environment:" + hashlib.sha256(self.host.encode("utf-8")).hexdigest()[:24], display_ref=self.host)
