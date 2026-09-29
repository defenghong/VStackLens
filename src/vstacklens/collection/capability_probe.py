from __future__ import annotations

import html
import json
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vstacklens.collection.pyvmomi_collector import PyVmomiCollector


@dataclass(frozen=True)
class ProbeSpec:
    rule_id: str
    field: str
    object_type: str
    title: str
    evaluator: str


@dataclass(frozen=True)
class ProbeObservation:
    object_name: str
    value: Any
    reason: str = ""


M2B_CANDIDATE_SPECS: tuple[ProbeSpec, ...] = (
    ProbeSpec("VSL-DS-007", "multipath_issue_count", "Datastore", "Datastore 多路径状态异常", "datastore_multipath_issue_count"),
    ProbeSpec("VSL-DS-008", "datastore_path_counts", "Datastore", "Datastore 路径数量低于预期", "datastore_path_counts"),
    ProbeSpec("VSL-DS-009", "apd_pdl_event_count", "Datastore", "Datastore APD/PDL 事件", "unsupported_event_history"),
    ProbeSpec("VSL-NET-002", "physical_nic_link_issue_count", "HostSystem", "物理网卡断链或降速", "physical_nic_link_issue_count"),
    ProbeSpec("VSL-NET-003", "nic_error_crc_metric", "HostSystem", "网卡丢包/错误/CRC 指标", "unsupported_performance_metric"),
    ProbeSpec("VSL-NET-005", "portgroup_vlan_ids", "HostSystem", "Port Group VLAN 配置", "portgroup_vlan_ids"),
    ProbeSpec("VSL-NET-012", "teaming_policy_values", "HostSystem", "LACP/Teaming 策略", "teaming_policy_values"),
    ProbeSpec("VSL-NET-013", "dns_servers", "HostSystem", "主机 DNS 配置", "dns_servers"),
    ProbeSpec("VSL-NET-014", "default_gateway", "HostSystem", "主机默认网关", "default_gateway"),
    ProbeSpec("VSL-CL-009", "ha_isolation_response", "ClusterComputeResource", "HA 隔离响应策略", "ha_isolation_response"),
    ProbeSpec("VSL-CL-016", "cluster_vmotion_coverage", "ClusterComputeResource", "集群 vMotion 主机覆盖率", "cluster_vmotion_coverage"),
    ProbeSpec("VSL-VM-016", "invalid_network_count", "VirtualMachine", "VM 异常网络连接", "invalid_network_count"),
    ProbeSpec("VSL-VM-017", "orphaned_or_inaccessible", "VirtualMachine", "VM 孤立或不可访问状态", "orphaned_or_inaccessible"),
    ProbeSpec("VSL-VM-018", "powered_off_days", "VirtualMachine", "VM 长期关机天数", "unsupported_powered_off_history"),
    ProbeSpec("VSL-VM-021", "passthrough_device_count", "VirtualMachine", "VM 宿主机/直通设备", "passthrough_device_count"),
)


class PyVmomiCapabilityProbe:
    def __init__(self, host: str, username: str, password: str, port: int = 443, ssl_verify: bool = False) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.ssl_verify = ssl_verify
        self.collector_helpers = PyVmomiCollector(host, username, password, port, ssl_verify)

    def run(self, specs: tuple[ProbeSpec, ...] = M2B_CANDIDATE_SPECS) -> dict[str, Any]:
        try:
            from pyVim.connect import Disconnect, SmartConnect
            from pyVmomi import vim
        except ImportError as exc:
            raise RuntimeError("pyVmomi is not installed. Install with: python -m pip install -e .") from exc

        ssl_context = None
        if not self.ssl_verify:
            ssl_context = ssl._create_unverified_context()  # noqa: SLF001 - explicit customer-configurable option
        service_instance = SmartConnect(
            host=self.host,
            user=self.username,
            pwd=self.password,
            port=self.port,
            sslContext=ssl_context,
            httpConnectionTimeout=30,
        )
        try:
            content = service_instance.RetrieveContent()
            objects_by_type = {
                "ClusterComputeResource": self._collect_view(content, vim.ClusterComputeResource),
                "HostSystem": self._collect_view(content, vim.HostSystem),
                "Datastore": self._collect_view(content, vim.Datastore),
                "VirtualMachine": self._collect_view(content, vim.VirtualMachine),
            }
            results = [self._probe_spec(spec, objects_by_type, vim) for spec in specs]
            return {
                "generated_at": datetime.now(UTC).isoformat(),
                "vcenter": self.host,
                "candidate_count": len(specs),
                "results": results,
            }
        finally:
            Disconnect(service_instance)

    def _collect_view(self, content: Any, vim_type: Any) -> list[Any]:
        view = content.viewManager.CreateContainerView(content.rootFolder, [vim_type], True)
        try:
            return list(view.view)
        finally:
            view.Destroy()

    def _probe_spec(self, spec: ProbeSpec, objects_by_type: dict[str, list[Any]], vim: Any) -> dict[str, Any]:
        observations: list[ProbeObservation] = []
        for obj in objects_by_type.get(spec.object_type, []):
            try:
                value = getattr(self, f"_eval_{spec.evaluator}")(obj, objects_by_type, vim)
                observations.append(ProbeObservation(self._object_name(obj), value))
            except NotImplementedError as exc:
                observations.append(ProbeObservation(self._object_name(obj), None, str(exc)))
            except Exception as exc:  # noqa: BLE001 - probe should report unstable fields instead of failing the run
                observations.append(ProbeObservation(self._object_name(obj), None, str(exc)))
        return summarize_probe(spec, observations)

    def _object_name(self, obj: Any) -> str:
        return str(getattr(obj, "name", None) or getattr(obj, "_moId", "unknown"))

    def _eval_datastore_multipath_issue_count(self, datastore: Any, objects_by_type: dict[str, list[Any]], vim: Any) -> int | None:
        counts = self._datastore_path_state_counts(datastore)
        if counts is None:
            return None
        return counts["issue_count"]

    def _eval_datastore_path_counts(self, datastore: Any, objects_by_type: dict[str, list[Any]], vim: Any) -> dict[str, int] | None:
        counts = self._datastore_path_state_counts(datastore)
        if counts is None:
            return None
        return {"active_path_count": counts["active_count"], "total_path_count": counts["total_count"]}

    def _datastore_path_state_counts(self, datastore: Any) -> dict[str, int] | None:
        disk_names = self._datastore_extent_disk_names(datastore)
        if not disk_names:
            return None
        host_mounts = getattr(datastore, "host", None)
        if host_mounts is None:
            return None
        active_count = 0
        total_count = 0
        issue_count = 0
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
        if not matched_lun:
            return None
        return {"active_count": active_count, "total_count": total_count, "issue_count": issue_count}

    def _datastore_extent_disk_names(self, datastore: Any) -> set[str]:
        info = getattr(datastore, "info", None)
        vmfs = getattr(info, "vmfs", None) if info else None
        names: set[str] = set()
        for extent in getattr(vmfs, "extent", []) or []:
            disk_name = getattr(extent, "diskName", None)
            if disk_name:
                names.add(str(disk_name))
        return names

    def _eval_physical_nic_link_issue_count(self, host: Any, objects_by_type: dict[str, list[Any]], vim: Any) -> int | None:
        down, degraded = self.collector_helpers._physical_nic_issue_counts(host)
        return self.collector_helpers._sum_optional_counts(down, degraded)

    def _eval_portgroup_vlan_ids(self, host: Any, objects_by_type: dict[str, list[Any]], vim: Any) -> list[int] | None:
        network = getattr(getattr(host, "config", None), "network", None)
        if network is None:
            return None
        vlans: list[int] = []
        for group in getattr(network, "portgroup", []) or []:
            vlan_id = getattr(getattr(group, "spec", None), "vlanId", None)
            if vlan_id is not None:
                vlans.append(int(vlan_id))
        return vlans

    def _eval_teaming_policy_values(self, host: Any, objects_by_type: dict[str, list[Any]], vim: Any) -> list[str] | None:
        network = getattr(getattr(host, "config", None), "network", None)
        if network is None:
            return None
        policies: list[str] = []
        for group in getattr(network, "portgroup", []) or []:
            teaming = getattr(getattr(group, "computedPolicy", None), "nicTeaming", None)
            policy = getattr(teaming, "policy", None) if teaming else None
            if policy:
                policies.append(str(policy))
        for vswitch in getattr(network, "vswitch", []) or []:
            policy = getattr(getattr(getattr(vswitch, "spec", None), "policy", None), "nicTeaming", None)
            policy_name = getattr(policy, "policy", None) if policy else None
            if policy_name:
                policies.append(str(policy_name))
        return policies

    def _eval_dns_servers(self, host: Any, objects_by_type: dict[str, list[Any]], vim: Any) -> list[str] | None:
        network = getattr(getattr(host, "config", None), "network", None)
        dns = getattr(network, "dnsConfig", None) if network else None
        addresses = getattr(dns, "address", None) if dns else None
        if addresses is None:
            return None
        return [str(item) for item in addresses]

    def _eval_default_gateway(self, host: Any, objects_by_type: dict[str, list[Any]], vim: Any) -> str | None:
        network = getattr(getattr(host, "config", None), "network", None)
        route_config = getattr(network, "ipRouteConfig", None) if network else None
        gateway = getattr(route_config, "defaultGateway", None) if route_config else None
        return str(gateway) if gateway else None

    def _eval_ha_isolation_response(self, cluster: Any, objects_by_type: dict[str, list[Any]], vim: Any) -> str | None:
        config = getattr(cluster, "configurationEx", None)
        das = getattr(config, "dasConfig", None) if config else None
        return self.collector_helpers._ha_isolation_response(das)

    def _eval_cluster_vmotion_coverage(self, cluster: Any, objects_by_type: dict[str, list[Any]], vim: Any) -> dict[str, int] | None:
        hosts = list(getattr(cluster, "host", []) or [])
        if not hosts:
            return None
        enabled = 0
        known = 0
        for host in hosts:
            count = self.collector_helpers._vmotion_vmk_count(host)
            if count is None:
                continue
            known += 1
            if count > 0:
                enabled += 1
        if known == 0:
            return None
        return {"host_count": len(hosts), "known_host_count": known, "vmotion_enabled_host_count": enabled}

    def _eval_invalid_network_count(self, vm: Any, objects_by_type: dict[str, list[Any]], vim: Any) -> int | None:
        config = getattr(vm, "config", None)
        devices = getattr(getattr(config, "hardware", None), "device", None) if config else None
        if devices is None:
            return None
        count = 0
        network_device_seen = False
        for device in devices:
            if not isinstance(device, vim.vm.device.VirtualEthernetCard):
                continue
            network_device_seen = True
            backing = getattr(device, "backing", None)
            network = getattr(backing, "network", None)
            if backing is None or network is None:
                count += 1
        return count if network_device_seen else 0

    def _eval_orphaned_or_inaccessible(self, vm: Any, objects_by_type: dict[str, list[Any]], vim: Any) -> bool | None:
        runtime = getattr(vm, "runtime", None)
        state = getattr(runtime, "connectionState", None) if runtime else None
        if state is None:
            summary = getattr(vm, "summary", None)
            runtime_summary = getattr(summary, "runtime", None) if summary else None
            state = getattr(runtime_summary, "connectionState", None) if runtime_summary else None
        if state is None:
            return None
        return str(state).lower() in {"orphaned", "inaccessible", "invalid"}

    def _eval_passthrough_device_count(self, vm: Any, objects_by_type: dict[str, list[Any]], vim: Any) -> int | None:
        config = getattr(vm, "config", None)
        devices = getattr(getattr(config, "hardware", None), "device", None) if config else None
        if devices is None:
            return None
        count = 0
        for device in devices:
            if isinstance(device, vim.vm.device.VirtualPCIPassthrough):
                count += 1
        return count

    def _eval_unsupported_event_history(self, obj: Any, objects_by_type: dict[str, list[Any]], vim: Any) -> None:
        raise NotImplementedError("APD/PDL requires bounded event history query; not enabled in M2-B probe")

    def _eval_unsupported_performance_metric(self, obj: Any, objects_by_type: dict[str, list[Any]], vim: Any) -> None:
        raise NotImplementedError("NIC error/CRC requires PerformanceManager metric sampling; not enabled in M2-B probe")

    def _eval_unsupported_powered_off_history(self, obj: Any, objects_by_type: dict[str, list[Any]], vim: Any) -> None:
        raise NotImplementedError("powered-off duration requires event or lifecycle history; not available from current inventory snapshot")


def summarize_probe(spec: ProbeSpec, observations: list[ProbeObservation]) -> dict[str, Any]:
    object_total = len(observations)
    value_observations = [item for item in observations if item.value is not None]
    value_count = len(value_observations)
    none_count = object_total - value_count
    coverage = round(value_count / object_total, 4) if object_total else 0.0
    reasons = sorted({item.reason for item in observations if item.reason})
    recommendation = "ready_for_default_enabled" if object_total > 0 and coverage >= 0.95 else "unstable"
    if object_total == 0:
        recommendation = "unsupported"
        reasons = ["no target objects found"]
    elif value_count == 0 and reasons and all("not enabled" in reason or "not available" in reason or "requires" in reason for reason in reasons):
        recommendation = "unsupported"
    elif value_count == 0:
        recommendation = "unstable"
    return {
        "rule_id": spec.rule_id,
        "field": spec.field,
        "object_type": spec.object_type,
        "title": spec.title,
        "object_total": object_total,
        "value_count": value_count,
        "none_count": none_count,
        "coverage": coverage,
        "sample_values": [_jsonable(item.value) for item in value_observations[:5]],
        "sample_objects": [item.object_name for item in value_observations[:5]],
        "recommendation": recommendation,
        "unstable_reason": "; ".join(reasons[:3]) if reasons else "",
    }


def write_probe_json(report: dict[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def write_probe_html(report: dict[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = "\n".join(_html_row(item) for item in report.get("results", []))
    content = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>VStackLens M2-B 字段能力探测</title>
  <style>
    body {{ font-family: "Microsoft YaHei", Arial, sans-serif; margin: 28px; color: #1f2937; }}
    h1 {{ font-size: 22px; }}
    .meta {{ color: #4b5563; margin-bottom: 18px; }}
    table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
    th, td {{ border: 1px solid #d1d5db; padding: 8px 10px; text-align: left; vertical-align: top; }}
    th {{ background: #eef2f7; }}
    .ready_for_default_enabled {{ color: #047857; font-weight: 700; }}
    .unstable {{ color: #b45309; font-weight: 700; }}
    .unsupported {{ color: #6b7280; font-weight: 700; }}
  </style>
</head>
<body>
  <h1>VStackLens M2-B 字段能力探测</h1>
  <div class="meta">vCenter: {html.escape(str(report.get("vcenter", "")))} | 生成时间: {html.escape(str(report.get("generated_at", "")))}</div>
  <table>
    <thead>
      <tr><th>规则ID</th><th>字段</th><th>对象类型</th><th>对象数</th><th>有效值</th><th>None</th><th>覆盖率</th><th>样例值</th><th>建议</th><th>原因</th></tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>
"""
    path.write_text(content, encoding="utf-8")
    return path


def _html_row(item: dict[str, Any]) -> str:
    recommendation = str(item.get("recommendation", ""))
    return (
        "<tr>"
        f"<td>{html.escape(str(item.get('rule_id', '')))}</td>"
        f"<td>{html.escape(str(item.get('field', '')))}</td>"
        f"<td>{html.escape(str(item.get('object_type', '')))}</td>"
        f"<td>{html.escape(str(item.get('object_total', '')))}</td>"
        f"<td>{html.escape(str(item.get('value_count', '')))}</td>"
        f"<td>{html.escape(str(item.get('none_count', '')))}</td>"
        f"<td>{html.escape(str(item.get('coverage', '')))}</td>"
        f"<td>{html.escape(json.dumps(item.get('sample_values', []), ensure_ascii=False))}</td>"
        f"<td class=\"{html.escape(recommendation)}\">{html.escape(recommendation)}</td>"
        f"<td>{html.escape(str(item.get('unstable_reason', '')))}</td>"
        "</tr>"
    )


def _jsonable(value: Any) -> Any:
    try:
        json.dumps(value, ensure_ascii=False)
        return value
    except TypeError:
        return str(value)
