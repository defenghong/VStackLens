"""Pure local mapping from rule findings to customer report categories.

This module deliberately has no collector or database dependencies.  It is the
single place where the stable customer-facing P1/P2/P3 semantics live.  Rule
packs can remain fine grained; the report model is intentionally coarser.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable


@dataclass(frozen=True, slots=True)
class FindingCategoryDefinition:
    category_id: str
    title_zh: str
    section: str
    priority: str
    source_rule_ids: tuple[str, ...]
    description_zh: str = ""
    impact_scope: str = ""
    potential_impact: str = ""
    remediation_zh: str = ""
    remediation_mode: str = "需评估"
    remediation_effort: str = "中"
    report_visible: bool = True


def _d(category_id: str, title: str, section: str, priority: str, rules: Iterable[str], **kwargs: Any) -> FindingCategoryDefinition:
    return FindingCategoryDefinition(category_id, title, section, priority, tuple(rules), **kwargs)


# The order follows the report sections and is also used for deterministic
# output.  Keep this table explicit: it is the reviewable contract between
# rule packs and customer reports.
_DEFINITIONS = [
    _d("VC-CONNECTIVITY", "vCenter 连通性", "vCenter", "P1", ["VSL-VC-001"]),
    _d("VC-LIFECYCLE", "vCenter 生命周期", "vCenter", "P1", ["VSL-VC-002"]),
    _d("VC-ALARMS", "vCenter 活动告警", "vCenter", "P1", ["VSL-VC-004"]),
    _d("VC-CERTIFICATE", "vCenter 证书问题", "vCenter", "P1", ["VSL-VC-005"]),
    _d("VC-LICENSE", "vCenter License 状态", "vCenter", "P1", ["VSL-VC-006"]),
    _d("VC-TASK-BACKLOG", "vCenter 任务积压", "vCenter", "P2", ["VSL-VC-015"]),
    _d("CLUSTER-HA", "集群 HA 配置问题", "Cluster", "P1", ["VSL-CL-001"]),
    _d("CLUSTER-HA-ADMISSION-CONTROL", "集群 HA 准入控制问题", "Cluster", "P1", ["VSL-CL-002"]),
    _d("CLUSTER-DRS", "集群 DRS 配置问题", "Cluster", "P1", ["VSL-CL-003"]),
    _d("CLUSTER-DRS-AUTOMATION", "集群 DRS 自动化配置", "Cluster", "P2", ["VSL-CL-004"]),
    _d("CLUSTER-CPU", "集群 CPU 使用率问题", "Cluster", "P1", ["VSL-CL-005"]),
    _d("CLUSTER-ESXI-VERSION", "集群 ESXi 版本一致性", "Cluster", "P1", ["VSL-CL-006"]),
    _d("CLUSTER-EVC", "集群 EVC 配置", "Cluster", "P3", ["VSL-CL-007"]),
    _d("CLUSTER-HA-ISOLATION", "集群 HA 隔离响应", "Cluster", "P2", ["VSL-CL-009"]),
    _d("CLUSTER-CPU-CONSISTENCY", "集群 CPU 一致性", "Cluster", "P3", ["VSL-CL-010"]),
    _d("CLUSTER-MEMORY-CONSISTENCY", "集群内存一致性", "Cluster", "P3", ["VSL-CL-011"]),
    _d("CLUSTER-DRS-RULE", "集群 DRS 规则", "Cluster", "P2", ["VSL-CL-012"]),
    _d("CLUSTER-MAINTENANCE-MODE", "集群维护模式主机", "Cluster", "P1", ["VSL-CL-013"]),
    _d("CLUSTER-VMOTION-NETWORK", "集群 vMotion 网络", "Cluster", "P1", ["VSL-CL-016"]),
    _d("HOST-CONNECTION", "ESXi 主机连接状态", "Host", "P1", ["VSL-HOST-001"]),
    _d("HOST-MANAGEMENT-SERVICE", "ESXi 高权限管理服务开启", "Host", "P1", ["VSL-HOST-002", "VSL-HOST-016"]),
    _d("HOST-TIME-SYNC", "ESXi 时间同步问题", "Host", "P1", ["VSL-HOST-003"]),
    _d("HOST-CPU", "ESXi CPU 使用率问题", "Host", "P1", ["VSL-HOST-005"]),
    _d("HOST-MEMORY", "ESXi 内存使用率问题", "Host", "P1", ["VSL-HOST-006"]),
    _d("HOST-CERTIFICATE", "ESXi 证书问题", "Host", "P1", ["VSL-HOST-008"]),
    _d("HOST-PNIC", "ESXi 物理网卡问题", "Host", "P1", ["VSL-HOST-019"]),
    _d("HOST-STORAGE-PATH", "ESXi 存储路径问题", "Host", "P1", ["VSL-HOST-020"]),
    _d("HOST-LICENSE", "ESXi License 状态", "Host", "P1", ["VSL-HOST-023"]),
    _d("HOST-HARDWARE-HEALTH", "ESXi 硬件健康问题", "Host", "P1", ["VSL-HOST-024"]),
    _d("HOST-RESOURCE-ALLOCATION", "ESXi 资源分配需要关注", "Host", "P2", ["VSL-HOST-026"]),
    _d("VM-SNAPSHOT", "虚拟机快照问题", "Virtual Machine", "P2", ["VSL-VM-001", "VSL-VM-007", "VSL-VM-022"]),
    _d("VM-CPU-READY", "虚拟机 CPU Ready 过高", "Virtual Machine", "P1", ["VSL-VM-004"]),
    _d("VM-MEMORY-PRESSURE", "虚拟机存在内存压力", "Virtual Machine", "P1", ["VSL-VM-005"]),
    _d("VM-CDROM", "虚拟机 CD/DVD / ISO 挂载", "Virtual Machine", "P2", ["VSL-VM-006"]),
    _d("VM-NONPERSISTENT-DISK", "虚拟机使用非持久化磁盘", "Virtual Machine", "P3", ["VSL-VM-009"]),
    _d("VM-RESOURCE-CONFIG", "虚拟机资源配置需要优化", "Virtual Machine", "P3", ["VSL-VM-010", "VSL-VM-011", "VSL-VM-012"]),
    _d("VM-NUMA-AFFINITY", "虚拟机配置 NUMA 节点亲和", "Virtual Machine", "P3", ["VSL-VM-013"]),
    _d("VM-NETWORK", "虚拟机网络问题", "Virtual Machine", "P1", ["VSL-VM-016"]),
    _d("VM-INVENTORY-STATE", "虚拟机不可访问或清单异常", "Virtual Machine", "P1", ["VSL-VM-017"]),
    _d("VM-LONG-POWERED-OFF", "长期关机虚拟机", "Virtual Machine", "P3", ["VSL-VM-018"]),
    _d("VM-LOCAL-DATASTORE", "虚拟机运行在本地存储", "Virtual Machine", "P1", ["VSL-VM-023"]),
    _d("DS-CAPACITY", "Datastore 容量使用率过高", "Datastore", "P2", ["VSL-DS-001"]),
    _d("DS-ACCESSIBILITY", "Datastore 可访问性问题", "Datastore", "P1", ["VSL-DS-002"]),
    _d("DS-MOUNT", "Datastore 挂载状态问题", "Datastore", "P3", ["VSL-DS-006"]),
    _d("DS-MULTIPATH", "Datastore 多路径问题", "Datastore", "P2", ["VSL-DS-007"]),
    _d("DS-ACTIVE-PATH", "Datastore 活动路径问题", "Datastore", "P3", ["VSL-DS-008"]),
    _d("DS-THIN-OVERCOMMIT", "Datastore Thin Provisioning 超分", "Datastore", "P2", ["VSL-DS-013"]),
    _d("NET-PNIC-ERROR", "物理网卡错误", "Network", "P1", ["VSL-NET-003"]),
    _d("NET-VMK-MTU", "VMkernel MTU 配置问题", "Network", "P1", ["VSL-NET-004"]),
    _d("SEC-ADMIN-COUNT", "管理员账号数量需要关注", "Security", "P3", ["VSL-SEC-002"]),
    _d("SEC-PERMISSION-INHERITANCE", "权限继承配置需要关注", "Security", "P3", ["VSL-SEC-008"]),
    _d("VSAN-CLUSTER-HEALTH", "vSAN 集群健康状态", "vSAN", "P1", ["VSAN-01", "VSL-VSAN-01"]),
    _d("VSAN-DISK", "vSAN 磁盘与磁盘组", "vSAN", "P1", ["VSAN-02", "VSL-VSAN-02"]),
    _d("VSAN-OBJECT-HEALTH", "vSAN Object 健康状态", "vSAN", "P1", ["VSAN-03", "VSL-VSAN-03"]),
    _d("VSAN-OBJECT-VMDK", "vSAN Object / VMDK 状态", "vSAN", "P1", ["VSAN-04", "VSL-VSAN-04"]),
    _d("VSAN-RESYNC", "vSAN 重同步状态", "vSAN", "P1", ["VSAN-05", "VSL-VSAN-05"]),
    _d("VSAN-NETWORK", "vSAN 网络状态", "vSAN", "P1", ["VSAN-06", "VSL-VSAN-06"]),
    _d("VSAN-CAPACITY", "vSAN 容量使用率", "vSAN", "P2", ["VSAN-07", "VSL-VSAN-07"]),
    _d("VSAN-POLICY", "vSAN Storage Policy 合规性", "vSAN", "P2", ["VSAN-08", "VSL-VSAN-08"]),
]

CATEGORY_DEFINITIONS: dict[str, FindingCategoryDefinition] = {item.category_id: item for item in _DEFINITIONS}
RULE_TO_CATEGORY: dict[str, str] = {
    rule_id: item.category_id for item in _DEFINITIONS for rule_id in item.source_rule_ids
}

HIDDEN_STANDARD_RULES = frozenset({
    "VSL-HOST-004", "VSL-HOST-013", "VSL-HOST-014", "VSL-HOST-015",
    "VSL-VM-002", "VSL-VM-003", "VSL-VM-014", "VSL-VM-015", "VSL-DS-018",
})
PENDING_MAPPING_RULES = frozenset({"VSL-VM-021"})


@dataclass(slots=True)
class CategoryMappingResult:
    categories: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    hidden_findings: list[dict[str, Any]] = field(default_factory=list)
    unmapped_rules: list[str] = field(default_factory=list)
    pending_rules: list[str] = field(default_factory=lambda: sorted(PENDING_MAPPING_RULES))
    affected_object_summary: dict[str, int] = field(default_factory=dict)
    affected_object_occurrence_summary: dict[str, int] = field(default_factory=dict)
    risk_category_summary: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "categories": self.categories,
            "findings": self.findings,
            "hidden_findings": self.hidden_findings,
            "unmapped_rules": self.unmapped_rules,
            "pending_rules": self.pending_rules,
            "affected_object_summary": self.affected_object_summary,
            "affected_object_occurrence_summary": self.affected_object_occurrence_summary,
            "risk_category_summary": self.risk_category_summary,
        }


def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "enabled", "是", "异常"}
    return bool(value)


def _evidence(item: dict[str, Any]) -> dict[str, Any]:
    evidence = item.get("evidence")
    return evidence if isinstance(evidence, dict) else {}


def _lookup(item: dict[str, Any], *names: str) -> Any:
    evidence = _evidence(item)
    detail = evidence.get("observed_detail") if isinstance(evidence.get("observed_detail"), dict) else {}
    for name in names:
        if name in evidence:
            return evidence[name]
        if name in detail:
            return detail[name]
        if name in item and item[name] not in (None, ""):
            return item[name]
    return None


def _stable_object_key(item: dict[str, Any]) -> str:
    evidence = _evidence(item)
    for key in ("instanceUuid", "instance_uuid", "moid", "mo_ref", "object_key", "objectKey"):
        value = _lookup(item, key)
        if value not in (None, ""):
            return str(value)
    return str(item.get("object_key") or item.get("object_name") or "unknown-object")


def _is_cl007_applicable(item: dict[str, Any]) -> bool:
    explicit = _lookup(item, "applicable", "evc_applicable", "cross_generation_migration", "migration_need", "cpu_difference", "cpu_model_difference")
    # A positive finding without an applicability signal is not enough to
    # manufacture an EVC problem; this prevents the classic EVC false positive.
    return explicit is not None and _truthy(explicit)


def _cl009_priority(item: dict[str, Any], vsan_applicable: bool) -> str:
    explicit = _lookup(item, "vsan_cluster", "vsan_enabled", "is_vsan_cluster", "cluster_type")
    if isinstance(explicit, str):
        return "P1" if explicit.lower() in {"vsan", "vSAN".lower(), "true", "enabled", "osa", "esa"} else "P2"
    if explicit is not None:
        return "P1" if _truthy(explicit) else "P2"
    return "P1" if vsan_applicable else "P2"


def _resync_actionable(item: dict[str, Any]) -> bool:
    evidence = _evidence(item)
    count = _lookup(item, "totalObjectsToSync", "totalSyncingObjects", "syncingObjectCount", "resync_count", "object_count")
    markers = ("stalled", "stuck", "health", "availability", "api_error", "error", "inaccessible", "reduced")
    for key in markers:
        value = _lookup(item, key)
        if value in (None, "", 0, False):
            continue
        normalized = str(value).lower()
        if key == "health" and normalized in {"healthy", "ok", "normal", "healthyprogress", "progressing"}:
            continue
        if key != "health" and normalized in {"healthy", "ok", "normal", "false", "0"}:
            continue
        return True
    if isinstance(count, (int, float)):
        # Zero is a normal state.  A positive count is activity and requires
        # an abnormal/stalled marker before it becomes a customer Finding.
        return False
    # Without a count, only an explicit API/collection failure can become an
    # actionable data-gap signal; a missing value alone is not a fault.
    return any(_lookup(item, key) not in (None, "", False) for key in ("api_error", "collection_error", "unavailable"))


def _subreason(item: dict[str, Any]) -> str:
    rule_id = str(item.get("rule_id") or "")
    return {
        "VSL-VM-001": "超期快照",
        "VSL-VM-007": "快照链过深",
        "VSL-VM-022": "Consolidation Needed",
        "VSL-VM-010": "Reservation",
        "VSL-VM-011": "Limit",
        "VSL-VM-012": "vCPU 配置过大",
        "VSL-HOST-002": "SSH",
        "VSL-HOST-016": "ESXi Shell",
    }.get(rule_id, str(item.get("title") or item.get("rule_name") or rule_id))


def map_findings_to_categories(findings: Iterable[dict[str, Any]], *, vsan_applicable: bool = False) -> CategoryMappingResult:
    """Map findings in one O(N) pass and deduplicate objects per category."""
    groups: OrderedDict[str, dict[str, Any]] = OrderedDict()
    mapped: list[dict[str, Any]] = []
    hidden: list[dict[str, Any]] = []
    unmapped: set[str] = set()
    for original in findings:
        item = dict(original)
        rule_id = str(item.get("rule_id") or "")
        if rule_id in HIDDEN_STANDARD_RULES:
            item["report_status"] = "SUPPRESSED"
            hidden.append(item)
            continue
        if rule_id in PENDING_MAPPING_RULES:
            item["report_mapping_status"] = "REPORT_MAPPING_PENDING"
            item["report_status"] = "NEEDS_REVIEW"
            hidden.append(item)
            continue
        # DS-020 is retained only as an internal compatibility bridge.  It
        # must never create a second customer category beside VSAN-01..08.
        if rule_id == "VSL-DS-020":
            item["report_status"] = "INTERNAL_ONLY"
            hidden.append(item)
            continue
        category_id = RULE_TO_CATEGORY.get(rule_id)
        if not category_id:
            unmapped.add(rule_id)
            hidden.append(item)
            continue
        if rule_id == "VSL-DS-020" and vsan_applicable:
            hidden.append(item)
            continue
        if rule_id == "VSL-CL-007" and not _is_cl007_applicable(item):
            item["report_status"] = "DESIGN_EXCEPTION"
            hidden.append(item)
            continue
        if rule_id in {"VSAN-05", "VSL-VSAN-05"} and not _resync_actionable(item):
            item["report_status"] = "DESIGN_EXCEPTION"
            hidden.append(item)
            continue
        definition = CATEGORY_DEFINITIONS[category_id]
        priority = _cl009_priority(item, vsan_applicable) if category_id == "CLUSTER-HA-ISOLATION" else definition.priority
        enriched = dict(item)
        enriched.update({"category_id": category_id, "category_title": definition.title_zh, "risk_level": priority, "report_visible": True, "report_status": "REPORTED"})
        enriched["category_subreason"] = _subreason(item)
        mapped.append(enriched)
        group = groups.setdefault(category_id, {**asdict(definition), "source_rule_ids": list(definition.source_rule_ids), "priority": priority, "affected_objects": [], "subreasons": [], "evidence_items": [], "finding_count": 0, "evidence_item_count": 0, "affected_object_occurrence_count": 0, "_object_keys": set(), "_priorities": set()})
        group["_priorities"].add(priority)
        group["finding_count"] += 1
        group["evidence_item_count"] += 1
        group["affected_object_occurrence_count"] += 1
        if not group.get("description_zh"):
            group["description_zh"] = str(item.get("failed_summary") or item.get("summary") or item.get("evidence_summary_zh") or "")
        if not group.get("potential_impact"):
            group["potential_impact"] = str(item.get("business_impact") or item.get("technical_impact") or item.get("consequence") or "")
        if category_id == "VM-LOCAL-DATASTORE" and not group.get("remediation_zh"):
            group["remediation_zh"] = "结合业务用途、备份和故障恢复要求人工确认，不直接判定必须迁移。"
            group["remediation_mode"] = "需评估"
        elif not group.get("remediation_zh"):
            group["remediation_zh"] = str(item.get("recommended_action_zh") or item.get("remediation") or "")
        if item.get("remediation_effort"):
            group["remediation_effort"] = item.get("remediation_effort")
        if item.get("remediation_mode"):
            group["remediation_mode"] = item.get("remediation_mode")
        object_key = _stable_object_key(item)
        if object_key not in group["_object_keys"]:
            group["_object_keys"].add(object_key)
            group["affected_objects"].append({"object_key": object_key, "object_name": item.get("object_name", ""), "object_type": item.get("object_type", ""), "object_path": item.get("object_path", "")})
        reason = enriched["category_subreason"]
        if reason and reason not in group["subreasons"]:
            group["subreasons"].append(reason)
        object_remediation = str(item.get("recommended_action_zh") or item.get("remediation") or group.get("remediation_zh") or "")
        if str(item.get("object_name") or "").casefold().startswith(("vcls", "vcsa")):
            object_remediation = "系统组件需结合其用途和 VMware 基线人工确认，不直接套用普通业务虚拟机优化建议。"
        group["evidence_items"].append({"object_key": object_key, "object_name": item.get("object_name", ""), "object_type": item.get("object_type", ""), "rule_id": rule_id, "subreason": reason, "current_value": item.get("current_value"), "expected_value": item.get("expected_value"), "explanation": item.get("explanation_zh") or item.get("explanation", ""), "remediation": object_remediation})
    categories: list[dict[str, Any]] = []
    affected_occurrences = {"P1": 0, "P2": 0, "P3": 0}
    global_objects: dict[str, set[str]] = {"P1": set(), "P2": set(), "P3": set()}
    for group in groups.values():
        group.pop("_object_keys", None)
        priorities = group.pop("_priorities", set())
        # Category priority is fixed by metadata, except the documented
        # CL-009 cluster-context case.
        group["priority"] = "P1" if "P1" in priorities else group["priority"]
        group["risk_level"] = group["priority"]
        group["affected_object_count"] = len(group["affected_objects"])
        group["object_count"] = group["affected_object_count"]
        group["title"] = group["title_zh"]
        group["module_name"] = group["section"]
        categories.append(group)
        if group["priority"] in affected_occurrences:
            affected_occurrences[group["priority"]] += int(group.get("affected_object_occurrence_count", 0) or 0)
            global_objects[group["priority"]].update(str(obj.get("object_key") or obj.get("object_name") or "") for obj in group["affected_objects"])
    categories.sort(key=lambda g: ({"P1": 0, "P2": 1, "P3": 2}.get(g["priority"], 9), g["category_id"]))
    summary = {"P1": sum(1 for g in categories if g["priority"] == "P1"), "P2": sum(1 for g in categories if g["priority"] == "P2"), "P3": sum(1 for g in categories if g["priority"] == "P3"), "P4": 0}
    affected = {level: len(keys) for level, keys in global_objects.items()}
    return CategoryMappingResult(categories, mapped, hidden, sorted(unmapped - {""}), sorted(PENDING_MAPPING_RULES), affected, affected_occurrences, summary)


class FindingCategoryMapper:
    """Small compatibility facade used by report builders and tests."""

    def map(self, findings: Iterable[dict[str, Any]], *, vsan_applicable: bool = False) -> CategoryMappingResult:
        return map_findings_to_categories(findings, vsan_applicable=vsan_applicable)

    __call__ = map


def category_catalog() -> list[dict[str, Any]]:
    return [asdict(item) for item in _DEFINITIONS]


def report_category_count() -> int:
    return len(_DEFINITIONS)
