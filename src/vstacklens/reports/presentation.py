from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any


OBJECT_TYPE_LABELS = {
    "vCenter": "vCenter 管理平台",
    "ClusterComputeResource": "集群",
    "HostSystem": "ESXi 主机",
    "Datastore": "数据存储",
    "VirtualMachine": "虚拟机",
    "Network": "网络",
    "Security": "安全合规",
    "Backup": "备份与可恢复性",
    "vSAN": "vSAN",
    "Capacity": "容量与趋势",
}

RULE_CATEGORY_LABELS = {
    "vcenter": "vCenter 管理平台",
    "cluster": "集群",
    "host": "ESXi 主机",
    "datastore": "数据存储",
    "vm": "虚拟机",
    "network": "网络",
    "security": "安全合规",
    "backup": "备份与可恢复性",
    "vsan": "vSAN",
    "capacity": "容量与趋势",
}

MODULE_ORDER = {
    "vcenter": 0,
    "vCenter": 0,
    "ClusterComputeResource": 1,
    "cluster": 1,
    "HostSystem": 2,
    "host": 2,
    "Datastore": 3,
    "datastore": 3,
    "network": 4,
    "Network": 4,
    "VirtualMachine": 5,
    "vm": 5,
    "security": 6,
    "Security": 6,
    "backup": 7,
    "Backup": 7,
    "capacity": 8,
    "Capacity": 8,
    "vsan": 9,
    "vSAN": 9,
}

SEVERITY_ORDER = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}


def count_excluded_powered_off_vms(vm_rows: list[dict[str, Any]]) -> int:
    count = 0
    for row in vm_rows:
        if not isinstance(row, dict):
            continue
        properties = row.get("properties")
        properties = properties if isinstance(properties, dict) else {}
        state = str(properties.get("power_state") or row.get("power_state") or "").casefold()
        is_off = state in {"poweredoff", "powered_off", "off", "关机"}
        is_excluded = properties.get("is_template") is True or properties.get("is_system_vm") is True
        if is_off and is_excluded:
            count += 1
    return count


def powered_off_exclusion_note(count: int) -> str:
    return f"另有 {count} 台关机的模板或系统虚拟机，不计入。" if count > 0 else ""


def append_report_sentence(value: Any, sentence: str) -> str:
    text = str(value or "").strip()
    if not sentence or sentence.casefold() in text.casefold():
        return text
    if not text:
        return sentence
    return text.rstrip("。；;") + "。" + sentence


def object_type_label(value: str | None) -> str:
    return OBJECT_TYPE_LABELS.get(value or "", value or "")


def rule_category_label(value: str | None) -> str:
    return RULE_CATEGORY_LABELS.get(value or "", value or "")


def module_sort_index(value: str | None) -> int:
    return MODULE_ORDER.get(value or "", 99)


def risk_sort_key(item: dict[str, Any]) -> tuple[int, int, str, str]:
    return (
        SEVERITY_ORDER.get(item.get("risk_level"), 99),
        module_sort_index(item.get("category") or item.get("object_type")),
        item.get("rule_id", ""),
        item.get("object_name", ""),
    )


def risk_group_sort_key(item: dict[str, Any]) -> tuple[int, int, int, str]:
    return (
        SEVERITY_ORDER.get(item.get("risk_level"), 99),
        -int(item.get("object_count", 0)),
        module_sort_index(item.get("category") or item.get("object_type")),
        item.get("rule_id", ""),
    )


def build_risk_group_summary(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    samples: dict[tuple[str, str], list[str]] = defaultdict(list)
    for item in findings:
        key = (item.get("rule_id", ""), item.get("risk_level", ""))
        if key not in grouped:
            grouped[key] = {
                "risk_level": item.get("risk_level", ""),
                "rule_id": item.get("rule_id", ""),
                "title": item.get("title") or item.get("rule_name") or item.get("rule_id", ""),
                "category": item.get("category", ""),
                "module_name": item.get("module_name") or rule_category_label(item.get("category")),
                "object_type": item.get("object_type", ""),
                "object_count": 0,
                "summary": item.get("summary", ""),
                "business_impact": item.get("business_impact", ""),
                "technical_impact": item.get("technical_impact", ""),
                "consequence": item.get("consequence", ""),
                "remediation": item.get("remediation", ""),
                "owner_role": item.get("owner_role", ""),
                "maintenance_window_required": bool(item.get("maintenance_window_required", False)),
                "health_impact": item.get("health_impact") or "none",
            }
        grouped[key]["object_count"] += 1
        object_name = item.get("object_name")
        if object_name and object_name not in samples[key] and len(samples[key]) < 5:
            samples[key].append(object_name)
    for key, group in grouped.items():
        group["sample_objects"] = samples[key]
        group["affected_object_count"] = group["object_count"]
    return sorted(grouped.values(), key=risk_group_sort_key)


def build_risk_category_summary(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Count problem categories once per ``rule_id + risk_level``."""

    groups = build_risk_group_summary(findings)
    summary = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    for group in groups:
        level = str(group.get("risk_level") or "")
        if level in summary:
            summary[level] += 1
    return summary


def build_risk_object_summary(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Count affected object findings separately from category counts."""

    summary = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    for item in findings:
        level = str(item.get("risk_level") or "")
        if level in summary:
            summary[level] += 1
    return summary


def build_health_impact_summary(findings: list[dict[str, Any]]) -> dict[str, int]:
    summary = {"none": 0, "attention": 0, "critical": 0}
    for item in findings:
        impact = str(item.get("health_impact") or "none").lower()
        if impact not in summary:
            impact = "none"
        summary[impact] += 1
    return summary


def execution_status(rule: dict[str, Any]) -> tuple[str, str]:
    if rule.get("enabled_in_current_run"):
        return "executed", "已执行"
    if rule.get("implementation_status") == "optional_plugin" or rule.get("execution_mode") == "plugin_required":
        return "optional_plugin", "可选插件"
    if rule.get("implementation_status") == "planned":
        return "planned", "规划中"
    if rule.get("execution_mode") == "disabled_by_default":
        return "disabled_by_default", "默认未启用"
    return "advanced_check", "扩展评估项"


def unexecuted_reason(rule: dict[str, Any]) -> str:
    rule_id = rule.get("rule_id")
    if rule_id == "VSL-DS-003":
        return "高级存储性能检查，当前未默认启用；启用前需确认 Datastore latency 指标可采集。"
    if rule_id == "VSL-VC-003":
        return "离线版本基线检查，待导入离线版本基线库后启用。"
    status_key, _ = execution_status(rule)
    if status_key == "planned":
        return "已纳入规则目录，当前版本规划中；后续补齐采集逻辑后启用。"
    if status_key == "optional_plugin":
        return "需启用对应插件、外部系统集成或离线数据源后执行。"
    if status_key == "disabled_by_default":
        return "默认未启用，需在巡检配置中显式开启后执行。"
    return "扩展评估项，本次未参与实际巡检统计。"


UNEXECUTED_GROUP_META = {
    "disabled_by_default": {
        "title": "默认未启用评估项",
        "description": "规则能力已纳入目录，但当前版本默认不参与执行；后续可在巡检配置中显式开启。",
        "enablement": "确认数据源和适用范围后，在规则配置中启用。",
    },
    "planned": {
        "title": "规划中评估项",
        "description": "已纳入 VStackLens 规则目录，当前版本暂不执行，不参与健康评分和通过率。",
        "enablement": "等待对应采集能力、规则测试和报告证据结构完成后启用。",
    },
    "optional_plugin": {
        "title": "可选插件评估项",
        "description": "需要 vSAN、备份平台、厂商 HCL、离线基线库等外部能力或插件。",
        "enablement": "部署并启用对应插件或导入离线数据源后执行。",
    },
    "advanced_check": {
        "title": "扩展评估项",
        "description": "扩展场景评估，本次未参与实际巡检统计。",
        "enablement": "确认高级采集能力和客户授权范围后启用。",
    },
}


def build_unexecuted_groups(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for rule in rules:
        status_key, status_label = execution_status(rule)
        rule["execution_status"] = status_key
        rule["execution_status_label"] = status_label
        rule["unexecuted_reason"] = "" if status_key == "executed" else unexecuted_reason(rule)
        if status_key != "executed":
            grouped[status_key].append(rule)
    result = []
    for key in ("disabled_by_default", "planned", "optional_plugin", "advanced_check"):
        items = sorted(grouped.get(key, []), key=lambda rule: (module_sort_index(rule.get("category")), rule.get("rule_id", "")))
        if not items:
            continue
        meta = UNEXECUTED_GROUP_META[key]
        result.append(
            {
                "group_key": key,
                "title": meta["title"],
                "description": meta["description"],
                "enablement": meta["enablement"],
                "count": len(items),
                "rules": items,
            }
        )
    return result


def rule_catalog_summary(rules: list[dict[str, Any]]) -> dict[str, int]:
    executable = sum(1 for rule in rules if rule.get("enabled_in_current_run"))
    return {
        "total": len(rules),
        "executable": executable,
        "implemented": len(rules),
    }


def mask_username(username: str | None) -> str:
    if not username:
        return "未采集"
    if "@" in username:
        name, domain = username.split("@", 1)
        visible = name[:4] if len(name) > 4 else name[:2]
        return f"{visible}****@{domain}"
    visible = username[:4] if len(username) > 4 else username[:2]
    return f"{visible}****"
