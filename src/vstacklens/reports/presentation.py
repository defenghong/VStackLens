from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any


def recorded_result_summary(report, context=None) -> dict[str, Any]:
    """Count saved object-result grades, never the current rule catalog's defaults."""
    from vstacklens.reports.customer_caliber import approved_result_projection
    projection = approved_result_projection(report, context)
    rows = projection.get('object_results') or []
    available = (projection.get('source') or {}).get('records_available', bool(rows))
    return _recorded_summary(rows, available=available)


def _recorded_summary(rows: list[dict[str, Any]], *, available: bool | None = None) -> dict[str, Any]:
    from vstacklens.reports.customer_caliber import DENIED_RULES, rule_grade
    counts = {key: 0 for key in ("passed", "failed", "unavailable", "error", "not_applicable")}
    levels = {key: 0 for key in ("P1", "P2", "P3")}
    unknown_grades = 0
    for row in rows:
        if row.get("rule_id") in DENIED_RULES:
            continue
        grade = rule_grade(row)  # saved risk_level, then saved rule evidence only
        status = row.get("result_status")
        if grade in levels and status in counts:
            counts[status] += 1
            if status == "failed": levels[grade] += 1
        elif status == "failed" and not grade:
            unknown_grades += 1
    return {"counts": counts, "failed_levels": levels, "available": bool(rows) if available is None else bool(available), "unknown_grade_results": unknown_grades,
            "source": "保存的当次检查结果等级", "scope": "客户可展示的 P1-P3 检查结果条数；不可用与出错单列，不等于问题类别数或去重对象数"}


def customer_check_statistics(report, context=None) -> dict[str, Any]:
    """One approved P1–P3 execution count for every customer renderer."""
    from vstacklens.reports.customer_caliber import approved_result_projection, DENIED_RULES, rule_grade
    projection = approved_result_projection(report, context)
    rows = projection.get('object_results') or []
    available = (projection.get('source') or {}).get('records_available', bool(rows))
    summary = _recorded_summary(rows, available=available)
    by_type: dict[str, dict[str, Any]] = {}
    by_rule: dict[str, dict[str, Any]] = {}
    for row in rows:
        level = rule_grade(row)
        status = row.get('result_status')
        if row.get('rule_id') in DENIED_RULES or level not in {'P1', 'P2', 'P3'} or status not in {'passed', 'failed'}:
            continue
        kind = str(row.get('object_type') or '')
        rule_id = str(row.get('rule_id') or '')
        type_bucket = by_type.setdefault(kind, {
            'object_type': kind, 'label': object_type_label(kind), 'total': 0, 'passed': 0, 'failed': 0,
            'levels': {key: 0 for key in ('P1', 'P2', 'P3')},
        })
        rule_bucket = by_rule.setdefault(rule_id, {
            'rule_id': rule_id, 'rule_name': str(row.get('check_name') or row.get('rule_name') or rule_id),
            'object_type': kind, 'total': 0, 'passed': 0, 'failed': 0,
            'levels': {key: 0 for key in ('P1', 'P2', 'P3')},
        })
        for bucket in (type_bucket, rule_bucket):
            bucket['total'] += 1
            bucket[status] += 1
            if status == 'failed':
                bucket['levels'][level] += 1
    type_rows = sorted(by_type.values(), key=lambda row: (module_sort_index(row['object_type']), row['object_type']))
    rule_rows = sorted(by_rule.values(), key=lambda row: row['rule_id'])
    top = []
    for row in rule_rows:
        if row['failed']:
            highest = next(level for level in ('P1', 'P2', 'P3') if row['levels'][level])
            top.append({'name': row['rule_name'], 'scope': object_type_label(row['object_type']),
                        'failed': row['failed'], 'highest_level': highest, 'rule_id': row['rule_id']})
    top.sort(key=lambda row: (-row['failed'], SEVERITY_ORDER[row['highest_level']], row['rule_id']))
    passed = summary['counts']['passed']
    failed = summary['counts']['failed']
    total = passed + failed
    return {
        'total': total, 'passed': passed, 'failed': failed,
        'text': f'本次共检查 {total} 条，通过 {passed} 条，未通过 {failed} 条。' if summary['available'] else '',
        'available': summary['available'],
        'levels': summary['failed_levels'], 'by_object_type_rows': type_rows,
        'by_rule_rows': rule_rows, 'top_failed_checks': top[:5],
        'total_label': '检查总数', 'scope_label': '本次检查结果',
    }


def certificate_consistency_notes(report) -> list[str]:
    """Flag contradictory original dates/days without rejudging saved health."""
    from datetime import date
    try: captured = date.fromisoformat(str(report.report_info.generated_at)[:10])
    except ValueError: return []
    notes = []
    for kind, prefix in (("vCenter", ""), ("HostSystem", "host_")):
        for row in (report.asset_inventory.get("details") or {}).get(kind, []):
            p = row.get("properties") or {}
            expiry = p.get(prefix + "certificate_not_after") or p.get(prefix + "certificate_expiration_date")
            days = p.get(prefix + "certificate_days_remaining")
            if expiry and isinstance(days, (float, int)) and not isinstance(days, bool):
                try: difference = (date.fromisoformat(str(expiry)[:10]) - captured).days
                except ValueError: continue
                if abs(difference - days) > 1:
                    notes.append(f"原始证书数据不一致：{row.get('object_name') or kind} 到期日 {str(expiry)[:10]} 与记录的剩余 {days:g} 天不对应；保留原始日期、天数及历史结论，请复核采集口径。")
    return notes


def customer_judgment_metadata(report) -> dict[str, str]:
    """Keep historical/reinterpretation identity separate from collection diagnostics."""
    provenance = (report.customer_caliber or {}).get("judgment_provenance") or {}
    mode = str(provenance.get("mode") or "RECORDED_RESULT")
    boundary = str(provenance.get("limitation") or "") if mode in {"ORIGINAL_WITH_LIMITS", "EXPLICIT_REINTERPRETATION"} else ""
    return {"mode": mode, "boundary": boundary}


def delivery_overview(report) -> dict[str, Any]:
    """Read-only customer opening; use stored caliber, never reinterpret rules."""
    caliber = report.customer_caliber or {}
    counts = dict(report.environment_summary.result_status_summary or {})
    unavailable = int(counts.get("unavailable", 0) or 0)
    errors = int(counts.get("error", 0) or 0)
    limits = []
    if unavailable or errors:
        limits.append(f"本次有 {unavailable} 条检查记录不可用、{errors} 条检查记录出错；未取得证据的部分不能视为正常。")
    if report.health_score.assessment_limited:
        limits.append("检查证据不足，当前结论不代表已完成全部检查；建议补齐采集范围或权限后复核。")
    for item in report.appendix.get("unavailable_rules", []) or []:
        if isinstance(item, dict):
            reason = item.get("reason") or item.get("unavailable_reason") or item.get("message")
            if reason and str(reason) not in limits: limits.append(str(reason))
    provenance = (caliber.get("judgment_provenance") or {}).get("limitation")
    if provenance and provenance not in limits: limits.append(provenance)
    recorded = recorded_result_summary(report)
    if recorded["unknown_grade_results"]:
        limits.append(f"有 {recorded['unknown_grade_results']} 条原始未通过记录的当次等级未保存，不能计入 P1-P3 等级统计；保留原始结论，不能据此确认正常。")
    limits.extend(certificate_consistency_notes(report))
    details = (report.asset_inventory.get("details") or {}).get("vCenter", [])
    if any((x.get("properties") or {}).get("collection_mode") == "connection_failed" for x in details):
        limits.insert(0, "本次连接未成功，未取得环境清单；仅能记录诊断信息，不能据此确认环境实际运行健康。")
    categories = list(caliber.get("categories") or report.problem_categories or [])
    categories.sort(key=lambda x: ({"P1": 0, "P2": 1, "P3": 2}.get(x.get("priority") or x.get("risk_level"), 3), x.get("title", "")))
    priorities = [dict(title=x.get("title", ""), level=x.get("priority") or x.get("risk_level") or "",
                       objects=x.get("affected_object_count", 0), suggestion=x.get("remediation_zh") or x.get("remediation") or "请结合原始证据复核。") for x in categories[:5]]
    from vstacklens.reports.customer_view import customer_category_title, customer_environment_name, customer_wording
    for item, category in zip(priorities, categories[:5]):
        item['title'] = customer_category_title(str(category.get('category_id') or ''), item['title'])
        if category.get('category_id') == 'VM-SNAPSHOT' and any(
            row.get('category_id') == 'VM-SNAPSHOT' and row.get('rule_id') == 'VSL-VM-001'
            for row in caliber.get('findings', [])
        ):
            item['suggestion'] = '保留 7 天及以上的快照需核对业务保留要求；' + item['suggestion']
    for item in priorities:
        item['suggestion'] = customer_wording(item['suggestion'])
    customer_limits = certificate_consistency_notes(report)
    boundary = customer_judgment_metadata(report)["boundary"]
    if boundary and boundary not in customer_limits:
        customer_limits.append(boundary)
    return dict(customer=report.customer_info.customer_name, environment=customer_environment_name(report.customer_info.site_name),
                target=report.customer_info.vcenter, time=report.report_info.generated_at,
                scope=customer_wording(report.environment_summary.scope_statement),
                conclusion=report.overall_status or report.health_score.label,
                explanation=customer_wording(report.health_score.explanation),
                check_counts={key:value for key,value in recorded['counts'].items() if key in {'passed','failed'}} if recorded['available'] else {},
                limitations=customer_limits, priorities=priorities, recorded_results={
                    'available':recorded['available'], 'failed_levels':recorded['failed_levels'],
                    'counts':{key:value for key,value in recorded['counts'].items() if key in {'passed','failed'}}})


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
