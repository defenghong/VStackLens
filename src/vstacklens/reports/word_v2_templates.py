from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import re
from typing import Any, Iterable


@dataclass(frozen=True)
class TableColumn:
    key: str
    label: str


@dataclass
class DetailTable:
    template_key: str
    columns: list[TableColumn]
    rows: list[dict[str, Any]]
    expected_row_count: int

    @property
    def actual_row_count(self) -> int:
        return len(self.rows)


CUSTOMER_TITLES = {
    "VM-CDROM": "虚拟机存在挂载 ISO 镜像",
    "VM-SNAPSHOT": "虚拟机存在快照",
    "CLUSTER-DRS": "集群 DRS 配置问题",
    "CLUSTER-HA": "集群 HA 配置问题",
    "HOST-PNIC": "ESXi 主机物理网卡链路异常",
    "HOST-HARDWARE-HEALTH": "ESXi 主机硬件健康异常",
    "HOST-MANAGEMENT-SERVICE": "ESXi 主机高权限管理服务开启",
    "HOST-TIME-SYNC": "ESXi 主机时间同步异常",
}

TEMPLATE_BY_CATEGORY = {
    "VM-CDROM": "iso_mount",
    "VM-SNAPSHOT": "snapshot",
    "CLUSTER-DRS": "cluster_ha_drs",
    "CLUSTER-HA": "cluster_ha_drs",
    "HOST-PNIC": "physical_nic",
    "HOST-HARDWARE-HEALTH": "hardware_health",
    "HOST-MANAGEMENT-SERVICE": "ssh_shell",
    "HOST-TIME-SYNC": "ntp",
}

ENGINEERING_ORDER = {
    "vCenter": 0,
    "Cluster": 1,
    "Host": 2,
    "Network": 3,
    "Datastore": 4,
    "Virtual Machine": 5,
    "Security": 6,
}

TEMPLATE_ORDER = {
    "cluster_ha_drs": 0,
    "physical_nic": 1,
    "iso_mount": 2,
    "snapshot": 3,
}


def customer_title(category: dict[str, Any]) -> str:
    category_id = str(category.get("category_id") or "")
    return str(category.get("title") or CUSTOMER_TITLES.get(category_id) or "风险项")


def template_key(category: dict[str, Any]) -> str:
    category_id = str(category.get("category_id") or "")
    return TEMPLATE_BY_CATEGORY.get(category_id, "generic_object")


def engineering_sort_key(category: dict[str, Any]) -> tuple[int, int, int, str]:
    level = str(category.get("priority") or category.get("risk_level") or "P3")
    section = str(category.get("section") or "")
    return (
        {"P1": 0, "P2": 1, "P3": 2}.get(level, 9),
        ENGINEERING_ORDER.get(section, 99),
        TEMPLATE_ORDER.get(template_key(category), 99),
        customer_title(category),
    )


def build_detail_table(
    category: dict[str, Any],
    *,
    asset_index: dict[str, dict[str, Any]],
    finding_index: dict[str, list[Any]] | None = None,
) -> DetailTable:
    key = template_key(category)
    objects = [item for item in category.get("affected_objects", []) if isinstance(item, dict)]
    evidence_by_key = _evidence_by_object(category.get("evidence_items") or [])
    rows: list[dict[str, Any]] = []
    for obj in objects:
        finding = _finding_for_template(finding_index or {}, obj, key)
        rows.extend(_build_rows(key, obj, evidence_by_key.get(_object_key(obj)), asset_index, finding))
    rows = [{key: value for key, value in row.items() if value not in (None, "")} for row in rows]
    columns = _columns_for_rows(key, rows)
    expected_key = "affected_object_occurrence_count" if key == "snapshot" else "affected_object_count"
    expected_count = int(category.get(expected_key, len(rows)) or 0)
    if key == "snapshot" and rows:
        expected_count = max(expected_count, len(rows))
    return DetailTable(key, columns, rows, expected_count)


def _build_rows(
    template: str,
    obj: dict[str, Any],
    evidence: dict[str, Any] | None,
    asset_index: dict[str, dict[str, Any]],
    finding: Any | None,
) -> list[dict[str, Any]]:
    evidence = evidence or {}
    name = str(obj.get("object_name") or evidence.get("object_name") or "")
    asset = asset_index.get(_object_key(obj)) or asset_index.get(name.casefold()) or {}
    host = _host_name(asset)
    explanation = _evidence_text(evidence)
    observed = evidence.get("observed_value") or _field(finding, "current_value")
    expected = evidence.get("reference_value") or _field(finding, "expected_value")

    if template == "iso_mount":
        return [{"esxi_host": host, "vm_name": name, "iso_image": _iso_image(finding), "exception": explanation or "存在 ISO 挂载记录"}]
    if template == "snapshot":
        snapshot_rows = _snapshot_rows(finding, name, host)
        return snapshot_rows or [{"esxi_host": host, "vm_name": name, "exception": explanation or "虚拟机存在快照"}]
    if template == "cluster_ha_drs":
        return [{"cluster": name, "current_status": observed, "reference_status": expected, "exception": explanation}]
    if template == "physical_nic":
        return [{"esxi_host": name, "abnormal_count": observed, "exception": explanation}]
    if template == "hardware_health":
        return [{"esxi_host": name, "current_status": observed, "exception": explanation}]
    if template == "ssh_shell":
        return [{"esxi_host": name, "service_status": observed, "exception": explanation}]
    if template == "ntp":
        return [{"esxi_host": name, "sync_status": observed, "exception": explanation}]
    return [{"object_name": name, "object_type": obj.get("object_type"), "exception": explanation or "存在需要关注的状态"}]


def _columns_for_rows(template: str, rows: list[dict[str, Any]]) -> list[TableColumn]:
    definitions = {
        "iso_mount": [
            TableColumn("esxi_host", "ESXi 主机"),
            TableColumn("vm_name", "虚拟机名称"),
            TableColumn("iso_image", "ISO 镜像"),
            TableColumn("exception", "异常说明"),
        ],
        "snapshot": [
            TableColumn("esxi_host", "ESXi 主机"),
            TableColumn("vm_name", "虚拟机名称"),
            TableColumn("snapshot_name", "快照名称"),
            TableColumn("created_at", "创建时间"),
            TableColumn("size_gb", "大小"),
            TableColumn("exception", "异常说明"),
        ],
        "cluster_ha_drs": [
            TableColumn("cluster", "Cluster"),
            TableColumn("current_status", "当前状态"),
            TableColumn("reference_status", "建议状态"),
            TableColumn("exception", "异常说明"),
        ],
        "physical_nic": [
            TableColumn("esxi_host", "ESXi 主机"),
            TableColumn("abnormal_count", "异常数量"),
            TableColumn("exception", "异常说明"),
        ],
        "hardware_health": [
            TableColumn("esxi_host", "ESXi 主机"),
            TableColumn("current_status", "当前状态"),
            TableColumn("exception", "异常说明"),
        ],
        "ssh_shell": [
            TableColumn("esxi_host", "ESXi 主机"),
            TableColumn("service_status", "服务状态"),
            TableColumn("exception", "异常说明"),
        ],
        "ntp": [
            TableColumn("esxi_host", "ESXi 主机"),
            TableColumn("sync_status", "同步状态"),
            TableColumn("exception", "异常说明"),
        ],
        "generic_object": [
            TableColumn("object_name", "对象名称"),
            TableColumn("object_type", "对象类型"),
            TableColumn("exception", "异常说明"),
        ],
    }
    selected = definitions.get(template, definitions["generic_object"])
    if not rows:
        return selected
    return [column for column in selected if any(row.get(column.key) not in (None, "") for row in rows)]


def _evidence_by_object(items: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        key = _object_key(item)
        if key:
            result[key] = item
    return result


def _object_key(item: dict[str, Any]) -> str:
    return str(item.get("object_key") or item.get("object_name") or "").casefold()


def _host_name(asset: dict[str, Any]) -> str:
    location = str(asset.get("asset_location") or "")
    marker = "主机 "
    if marker in location:
        return location.rsplit(marker, 1)[-1].strip()
    return ""


def _evidence_text(evidence: dict[str, Any]) -> str:
    for key in ("public_issue_text", "judgement_text", "explanation", "observed_detail_zh"):
        value = evidence.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def _field(finding: Any | None, key: str) -> Any:
    if finding is None:
        return None
    if isinstance(finding, dict):
        return finding.get(key)
    return getattr(finding, key, None)


def _finding_for_template(finding_index: dict[str, list[Any]], obj: dict[str, Any], template: str) -> Any | None:
    keys = [_object_key(obj), str(obj.get("object_name") or "").casefold()]
    candidates: list[Any] = []
    for key in keys:
        candidates.extend(finding_index.get(key, []))
    if not candidates:
        return None
    keywords = {
        "iso_mount": ("iso", "cd/dvd", "光驱"),
        "snapshot": ("快照", "snapshot"),
        "cluster_ha_drs": ("ha", "drs", "集群"),
        "physical_nic": ("物理网卡", "网卡", "pnic"),
        "hardware_health": ("硬件", "hardware"),
        "ssh_shell": ("ssh", "shell", "管理服务"),
        "ntp": ("时间同步", "ntp"),
    }.get(template, ())
    for finding in candidates:
        title = str(_field(finding, "title") or "").casefold()
        if any(keyword.casefold() in title for keyword in keywords):
            return finding
    return candidates[0]


def _detail_value(finding: Any | None, key: str) -> Any:
    for container_key in ("observed_detail", "raw_evidence", "evidence"):
        container = _field(finding, container_key)
        if isinstance(container, dict) and container.get(key) not in (None, ""):
            return container.get(key)
    return None


def _iso_image(finding: Any | None) -> Any:
    for key in ("iso_image", "iso_path", "file_name", "backing_file", "cdrom_file"):
        value = _detail_value(finding, key)
        if value not in (None, ""):
            return value
    return None


def _snapshot_rows(finding: Any | None, vm_name: str, host: str) -> list[dict[str, Any]]:
    details = _detail_value(finding, "snapshots")
    if isinstance(details, list):
        rows = []
        for item in details:
            if not isinstance(item, dict):
                continue
            rows.append({
                "esxi_host": host,
                "vm_name": vm_name,
                "snapshot_name": item.get("name") or item.get("snapshot_name"),
                "created_at": item.get("create_time") or item.get("created_at"),
                "size_gb": item.get("size_gb") or item.get("snapshot_size_gb"),
            })
        if rows:
            return rows
    text = str(_field(finding, "observed_detail_zh") or "")
    if not text:
        return []
    matches = re.findall(r"快照名称：([^；]+)；创建时间或存在时间：([^；]+)", text)
    return [{"esxi_host": host, "vm_name": vm_name, "snapshot_name": name.strip(), "created_at": created.strip()} for name, created in matches]


__all__ = [
    "CUSTOMER_TITLES",
    "DetailTable",
    "ENGINEERING_ORDER",
    "TEMPLATE_BY_CATEGORY",
    "TEMPLATE_ORDER",
    "TableColumn",
    "build_detail_table",
    "customer_title",
    "engineering_sort_key",
    "template_key",
]
