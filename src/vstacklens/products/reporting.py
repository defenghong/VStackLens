"""Shared, presentation-only product sections for the existing report engines.

The original module evidence stays in ReportData. Display deduplication requires
an explicit identity, fact, time and measurement convention; names and addresses
never establish identity. Product observations do not change vSphere grades.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any

from vstacklens.reports.report_model import (
    CustomerInfo, EnvironmentSummary, HealthScore, ReportData, ReportInfo, RiskSummary,
)
from vstacklens.products.management_scope import alarm_lifecycle_of, module_scope, scoped_checks


PRODUCT_NAMES = {"vcenter": "VC／vSAN", "nsx": "NSX", "avi": "AVI"}
STATUS_NAMES = {
    "normal": "正常", "abnormal": "异常", "attention": "需要关注",
    "not_deployed": "未部署", "not_applicable": "不适用",
    "permission_denied": "权限不足", "unsupported": "接口不支持",
    "collection_failed": "采集失败", "insufficient_data": "数据不足",
    "cancelled": "已取消",
}
VERIFY_NAMES = {
    "unverified": "待验证", "offline_sample": "离线样本", "offline_replay": "离线重放",
    "live_observed": "现场读取", "live_compared": "现场逐项对照",
    "live_business_verified": "真实业务验收", "live_business": "真实业务验收", "not_validated": "待验证",
}
INVALID_STATUSES = {"permission_denied", "unsupported", "collection_failed", "insufficient_data", "cancelled"}
VERIFIED_LEVELS = {"live_compared", "live_business_verified", "live_business"}
FIELD_NAMES = {
    "state": "状态", "status": "状态", "field_missing": "缺失字段", "name": "名称", "display_name": "名称",
    "id": "标识", "uuid": "UUID", "node_id": "节点标识", "version": "版本", "build": "构建号",
    "enabled": "已启用", "configured": "已配置", "description": "说明", "summary": "说明",
    "count": "数量", "total": "总数", "members": "成员", "nodes": "节点", "servers": "服务器",
    "address": "地址", "ip_address": "IP 地址", "port": "端口", "protocol": "协议",
    "expiry": "到期时间", "expiration_time": "到期时间", "not_after": "有效期至", "not_before": "有效期起",
    "uptime": "运行时间", "cpu_cores": "CPU 核数", "mem_used": "已用内存", "mem_total": "总内存",
    "disk_space_used": "磁盘已用空间", "disk_space_total": "磁盘总空间", "last_success": "最近成功",
    "last_failure": "最近失败", "schedule": "计划", "result": "结果", "certificate": "证书",
    "certificates": "证书", "native_alerts": "原生告警", "severity": "原生严重程度",
}
EXECUTION_NAMES = {"completed": "完成", "partial": "部分完成", "failed": "失败", "running": "执行中",
                   "pending": "等待", "not_run": "未执行", "cancelled": "已取消", "complete": "完整", "diagnostic_only": "仅失败诊断"}
PRODUCT_EVIDENCE_BASENAME = "inspection-evidence"


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _record_ref(target_id: str, kind: str, ordinal: Any, record: Any) -> str:
    value = {"target_id": target_id, "kind": kind, "ordinal": ordinal, "record": record}
    return "E-" + hashlib.sha256(_canonical_bytes(value)).hexdigest()[:12].upper()


def build_product_evidence(report: ReportData) -> dict:
    """Return complete public modules and a lossless index; never write files."""
    modules = deepcopy(report.product_modules)
    index = []
    for mi, module in enumerate(modules):
        target = str(module.get("target_id") or "")
        index.append({"evidence_id": _record_ref(target, "module", 0, module), "product": module.get("product"),
                      "target_id": target, "kind": "module", "ordinal": 0, "pointer": f"/modules/{mi}",
                      "check_id": "", "object_id": "", "collected_at": module.get("completed_at") or module.get("started_at")})
        for kind, field in (("check", "checks"), ("inventory", "inventory"), ("native_alert", "native_alerts")):
            value = module.get(field) or []
            entries = list(enumerate(value)) if isinstance(value, list) else list(value.items()) if isinstance(value, dict) else [(0, value)]
            for ordinal, record in entries:
                token = str(ordinal).replace("~", "~0").replace("/", "~1")
                item = record if isinstance(record, dict) else {}
                index.append({"evidence_id": _record_ref(target, kind, ordinal, record),
                              "product": module.get("product"), "target_id": target, "kind": kind,
                              "ordinal": ordinal, "pointer": f"/modules/{mi}/{field}/{token}",
                              "check_id": item.get("check_id", ""),
                              "object_id": item.get("object_id") or item.get("uuid") or item.get("id") or "",
                              "collected_at": item.get("collected_at") or module.get("completed_at") or module.get("started_at")})
    return {"schema_version": "vstacklens-product-evidence-1", "run_id": report.report_info.run_id,
            "generated_at": report.report_info.generated_at, "customer": report.customer_info.model_dump(),
            "selected_products": list(report.selected_products), "modules": modules, "record_index": index}


def product_evidence_bytes(report: ReportData) -> bytes:
    return _canonical_bytes(build_product_evidence(report))


def product_evidence_filename(report: ReportData) -> str:
    return f"{PRODUCT_EVIDENCE_BASENAME}-{hashlib.sha256(product_evidence_bytes(report)).hexdigest()[:12]}.json"


def validate_product_coverage(report: ReportData, view: dict, evidence: dict) -> dict:
    """Fail closed if a body reference or complete original record is missing."""
    expected = build_product_evidence(report)
    if evidence != expected:
        raise ValueError("工程证据与当次完整模块不一致，禁止发布正文。")
    by_id = {entry["evidence_id"]: entry for entry in evidence["record_index"]}
    if len(by_id) != len(evidence["record_index"]):
        raise ValueError("工程证据编号重复，禁止发布正文。")
    for entry in by_id.values():
        node: Any = evidence
        for token in entry["pointer"].lstrip("/").split("/"):
            token = token.replace("~1", "/").replace("~0", "~")
            node = node[int(token)] if isinstance(node, list) else node[token]
        if entry["evidence_id"] != _record_ref(entry["target_id"], entry["kind"], entry["ordinal"], node):
            raise ValueError("证据索引无法准确定位原始记录。")
    referenced = set()
    check_buckets = set()
    for section in view.get("sections") or []:
        body = section.get("body") or {}
        referenced.update(body.get("evidence_ids") or [])
        check_buckets.update(body.get("check_evidence_ids") or [])
        problem_refs = {ref for item in body.get("concerns") or [] for ref in item.get("evidence_ids") or []}
        problem_refs.update(ref for row in body.get("certificate_rows") or [] if "异常" in row[3] for ref in row[-1].split("、"))
        visible_rows = [row for table in body.get("tables") or [] for row in table.get("rows") or []]
        for mi, module in enumerate(report.product_modules):
            if module.get("target_id") != section.get("target_id"):
                continue
            for ordinal, check in enumerate(module.get("checks") or []):
                if check.get("status") == "abnormal" and _record_ref(str(module.get("target_id")), "check", ordinal, check) not in problem_refs:
                    raise ValueError("正文遗漏了异常检查或其具体对象，禁止发布。")
            refs = {(entry["target_id"], entry["kind"], entry["ordinal"]): entry["evidence_id"] for entry in by_id.values()}
            for affected in _module_attention_objects(module, refs):
                if not any(len(row) >= 4 and row[0] == affected["object"] and row[1] == affected["state"]
                           and affected["evidence_id"] in row[-1].split("、") for row in visible_rows):
                    raise ValueError("正文遗漏了聚合记录中已有原生异常状态的具体对象，禁止发布。")
    if not referenced <= set(by_id):
        raise ValueError("正文包含不存在的工程证据编号。")
    applicable = {entry["evidence_id"] for entry in by_id.values() if entry["kind"] == "check"
                  and any(s.get("target_id") == entry["target_id"] for s in view.get("sections") or [])}
    if applicable != check_buckets:
        raise ValueError("检查记录没有全部归入正文或集中证据目录。")
    return {"original_records": len(by_id), "indexed_records": len(by_id),
            "product_checks": len(applicable), "classified_product_checks": len(check_buckets),
            "body_references_valid": True, "original_modules_equal": True}


class NoValidInspectionData(ValueError):
    """Diagnostic evidence may be retained, but a health report must not publish."""


def _plain(value: Any) -> str:
    if value is None or value == "":
        return "未采集"
    if isinstance(value, bool):
        return "是" if value else "否"
    if isinstance(value, dict):
        return "\n".join(f"{FIELD_NAMES.get(str(k), str(k))}：{_plain(v)}" for k, v in value.items()) or "已读取空对象"
    if isinstance(value, (list, tuple)):
        return "\n".join(f"{index + 1}. {_plain(item)}" for index, item in enumerate(value)) or "已读取空列表"
    return str(value)


def _unique(items: list[Any]) -> list[Any]:
    found: set[str] = set()
    result = []
    for value in items:
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
        if encoded not in found:
            found.add(encoded)
            result.append(deepcopy(value))
    return result


def _segments(text: str, *, characters=850, lines=12) -> list[str]:
    """Bound table cell height without dropping any reading value or evidence."""
    result, pending = [], ""
    for line in str(text).splitlines(keepends=True) or ["未采集"]:
        while len(line) > characters:
            if pending:
                result.append(pending); pending = ""
            result.append(line[:characters]); line = line[characters:]
        if pending and (len(pending) + len(line) > characters or pending.count("\n") >= lines):
            result.append(pending); pending = ""
        pending += line
    if pending:
        result.append(pending)
    return result


def _check_details(check: dict) -> list[dict]:
    values = [
        ("实际状态或值", check["summary"] + "\n" + check["value"]),
        ("采集来源与时间", check["source"] + "\n" + check["time"]),
        ("判断与版本依据", check["judgement"] + " " + check["native_severity"] + "\n" + check["basis"] + "\n" + check["version_basis"]),
        ("验证与完整性", f"{check['verification']} · {check['completeness']} · 原记录 {check['evidence_count']} 条"),
        ("已确认影响", check["impact"]), ("检查限制", check["limits"]), ("下一步核查", check["recommendation"]),
    ]
    return [{"label": label + ("（续）" if index else ""), "text": chunk}
            for label, value in values for index, chunk in enumerate(_segments(value))]


def _valid_check(check: dict) -> bool:
    # A successful API reporting an empty object set is valid evidence of scope.
    # Unsupported/denied/failed records never contribute to healthy coverage.
    return (check.get("status") in STATUS_NAMES and check.get("status") not in INVALID_STATUSES
            and bool(check.get("sources")))


def _legacy_valid(report: ReportData) -> bool:
    if not report.environment_summary.checked_object_total or not (report.asset_inventory or {}).get("total"):
        return False
    for record in ((report.asset_inventory or {}).get("details") or {}).get("vCenter") or []:
        properties = record.get("properties") or {}
        if isinstance(properties.get("properties"), dict):
            properties = properties["properties"]
        if properties.get("connected") is False or properties.get("collection_mode") == "connection_failed":
            return False
    return True


def _trusted_scope(module: dict, check: dict) -> tuple:
    identity = check.get("trusted_identity") or module.get("target_identity") or {}
    customer = str(module.get("customer_id") or "")
    if (isinstance(identity, dict) and identity.get("verified") is True
            and identity.get("canonical_object_id") and customer):
        return customer, str(identity["canonical_object_id"])
    # Even a repeated name/IP within a customer does not establish sameness.
    return customer, str(module.get("target_id") or ""), str(check.get("object_id") or "")


def _dedupe_key(module: dict, check: dict) -> tuple | None:
    sources = check.get("sources") or []
    stamps = sorted({str(s.get("collected_at")) for s in sources if s.get("collected_at")})
    stamp = str(check.get("collected_at") or "") or (stamps[0] if len(stamps) == 1 else "")
    fact = str(check.get("fact_id") or check.get("check_id") or "")
    object_id = str(check.get("object_id") or "")
    scope = _trusted_scope(module, check)
    if not fact or not stamp or not module.get("target_id") or not object_id:
        return None
    # Product and evidence convention distinguish device resources, certificates,
    # native alerts and superficially similar facts from other products.
    return (scope, str(module.get("product")), object_id, fact, stamp,
            str(check.get("unit") or ""), _plain(check.get("measurement_window") or ""),
            str(check.get("judgement") or "PROGRAM"), str(check.get("basis") or ""))


def deduplicate_observations(modules: list[dict]) -> tuple[list[dict], list[dict]]:
    rows: list[dict] = []
    seen: dict[tuple, dict] = {}
    conflicts: list[dict] = []
    for module_index, module in enumerate(modules):
        for check_index, original in enumerate(scoped_checks(module)):
            check = deepcopy(original)
            check.update(product=module.get("product", ""), target_id=module.get("target_id", ""),
                         target_name=module.get("target_name", ""),
                         evidence_records=[{"module_index": module_index, "check_index": check_index,
                                            "target_id": module.get("target_id"), "object_id": check.get("object_id")}],
                         affected_target_ids=[module.get("target_id")])
            key = _dedupe_key(module, original)
            previous = seen.get(key) if key is not None else None
            comparable = ("status", "values", "summary", "native_severity", "completeness", "verification")
            if previous is not None and all(previous.get(k) == check.get(k) for k in comparable):
                previous["sources"] = _unique([*(previous.get("sources") or []), *(check.get("sources") or [])])
                previous["evidence_records"].extend(check["evidence_records"])
                previous["affected_target_ids"] = _unique([*previous["affected_target_ids"], *check["affected_target_ids"]])
                continue
            if previous is not None:
                conflict = {"product": module.get("product"), "target_id": module.get("target_id"),
                            "object_id": check.get("object_id"), "fact_id": check.get("fact_id") or check.get("check_id"),
                            "reason": "相同对象、事实、采集时间和口径存在不同记录；全部保留，需核查。"}
                conflicts.append(conflict)
                check["conflict"] = previous["conflict"] = conflict["reason"]
            rows.append(check)
            if key is not None and previous is None:
                seen[key] = check
    return rows, _unique(conflicts)


def build_integrated_report(run_id, targets, modules, title, *, legacy_report=None) -> ReportData:
    """Compose immutable product sections around the existing vSphere report."""
    from vstacklens.products.model import sanitize_public
    original_modules = deepcopy(modules)
    from vstacklens.products.store import _public as validate_public
    try:
        validated_modules = validate_public(original_modules)
    except ValueError:
        raise ValueError("产品结果含敏感或未投影字段，已阻止报告生成。") from None
    public_modules = sanitize_public(deepcopy(modules))
    if _canonical_bytes(original_modules) != _canonical_bytes(validated_modules):
        raise ValueError("产品结果尚未完全脱敏，已阻止报告生成。")
    if _canonical_bytes(original_modules) != _canonical_bytes(public_modules):
        raise ValueError("输入模块包含未脱敏或非标准公开内容，禁止静默删改证据后发布报告。")
    target_by_id = {t.target_id: t for t in targets}
    for module in public_modules:
        target = target_by_id.get(module.get("target_id"))
        if target:
            module["customer_id"] = target.customer_id
            module["site_id"] = target.site_id
    products = list(dict.fromkeys(str(t.product) for t in targets))
    valid_count = sum(_valid_check(c) for m in public_modules for c in m.get("checks") or [])
    legacy_reports = list(legacy_report) if isinstance(legacy_report, (list, tuple)) else [legacy_report] if legacy_report else []
    legacy_reports = [r for r in legacy_reports if _legacy_valid(r)]
    legacy_valid = bool(legacy_reports)
    if not valid_count and not legacy_valid:
        raise NoValidInspectionData("所选模块均未取得有效检查数据，不能生成健康报告；请查看各目标失败诊断。")
    generated = datetime.now(timezone.utc).isoformat()
    if legacy_reports:
        report = legacy_reports[0].model_copy(deep=True)
        report.report_info.run_id = run_id
        report.report_info.report_id = f"report-{run_id}"
        report.report_info.generated_at = generated
    else:
        customers = list(dict.fromkeys(t.customer_name for t in targets if t.customer_name))
        sites = list(dict.fromkeys(t.site_name for t in targets if t.site_name))
        report = ReportData(
            report_info=ReportInfo(report_id=f"report-{run_id}", run_id=run_id, generated_at=generated),
            customer_info=CustomerInfo(customer_name="、".join(customers) or "未指定客户",
                                       site_name="、".join(sites) or "未指定站点", vcenter="",
                                       project_name="NSX／AVI 巡检"),
            environment_summary=EnvironmentSummary(scope_statement="所选产品管理端及现有业务对象的只读检查",
                                                   checked_object_total=0),
            health_score=HealthScore(score=None, grade="未评分", label="评估受限", assessment_limited=True,
                                     explanation="按产品展示已采集状态和覆盖限制；不计算跨产品健康分数。"),
            risk_summary=RiskSummary(),
        )
    report.report_info.report_title = str(title or "VStackLens 综合巡检报告")
    report.selected_products = products
    report.product_modules = public_modules
    observations, conflicts = deduplicate_observations([m for m in public_modules if m.get("product") != "vcenter"])
    counts = Counter(c.get("status", "insufficient_data") for c in observations)
    verified = sum(c.get("status") == "normal" and c.get("verification") in VERIFIED_LEVELS for c in observations)
    report.integration_summary = {
        "run_id": run_id, "selected_products": products, "valid_observations": valid_count,
        "observation_count": len(observations), "status_counts": dict(counts), "verified_pass": verified,
        "conflicts": conflicts, "legacy_present": legacy_valid,
        "limitations": _unique(["数据读取及配置状态不能证明业务流量已实际生效。",
                                 "离线样本、现场读取和逐项现场对照分别标记；待验收能力不计入检查通过。",
                                 *[str(x) for m in public_modules for x in m.get("limitations") or []]]),
    }
    vc_targets = [t for t in targets if t.product == "vcenter"]
    assessments = []
    for index, legacy in enumerate(legacy_reports):
        explicit_id = legacy.integration_summary.get("legacy_target_id")
        matched = next((t for t in vc_targets if t.target_id == explicit_id), None) if explicit_id else (vc_targets[index] if index < len(vc_targets) else None)
        assessments.append({"target_id": matched.target_id if matched else explicit_id or legacy.report_info.run_id,
                            "target_name": matched.name if matched else legacy.integration_summary.get("legacy_target_name") or legacy.customer_info.vcenter,
                            "legacy_run_id": legacy.report_info.run_id, "score": legacy.health_score.score,
                            "grade": legacy.health_score.grade, "health": legacy.health_score.model_dump(),
                            "history_visible": legacy.history_visible, "report": legacy.model_dump()})
    report.integration_summary["legacy_assessments"] = assessments
    if len(assessments) > 1:
        report.health_score = HealthScore(score=None, grade="分别评估", label="分产品评估", assessment_limited=True,
                                         explanation="各 vCenter 保留各自原始评分和结论，不计算跨目标或跨产品总分。")
        report.integration_summary["score_scope"] = {"kind": "per_vcenter", "target_ids": [r["target_id"] for r in assessments],
                                                     "note": "各 vCenter 分别保留原始评分及结论，不计算跨目标或跨产品总分。"}
    elif assessments:
        report.integration_summary["score_scope"] = {"kind": "single_vcenter", "target_id": assessments[0]["target_id"],
                                                     "note": "本数值仅为该 vCenter 的原始评分，不代表跨产品总分。"}
    else:
        report.integration_summary["score_scope"] = {"kind": "none", "note": "NSX／AVI 不计算健康分数。"}
    observations, conflicts = deduplicate_observations(_section_modules(report))
    report.integration_summary.update(
        observation_count=len(observations), conflicts=conflicts,
        status_counts=dict(Counter(c.get("status", "insufficient_data") for c in observations)),
        verified_pass=sum(c.get("status") == "normal" and c.get("verification") in VERIFIED_LEVELS for c in observations),
    )
    return report


def legacy_assessment_reports(report: ReportData) -> list[tuple[dict, ReportData]]:
    return [(entry, ReportData.model_validate(entry["report"]))
            for entry in report.integration_summary.get("legacy_assessments") or []]


def has_legacy_sections(report: ReportData) -> bool:
    if not report.product_modules and not report.integration_summary:
        return "vcenter" in report.selected_products
    return bool(report.integration_summary.get("legacy_present") and report.integration_summary.get("legacy_assessments"))


def _section_modules(report: ReportData) -> list[dict]:
    successful_ids = {r["target_id"] for r in report.integration_summary.get("legacy_assessments") or []}
    return [m for m in report.product_modules or []
            if m.get("product") != "vcenter" or m.get("target_id") not in successful_ids]


def _table_view(title: str, columns: list[str], rows: list[list[str]], evidence_ids=(), weights=None) -> dict:
    return {"title": title, "columns": columns, "weights": weights or [1] * len(columns),
            "rows": rows, "evidence_ids": _unique(list(evidence_ids))}


def _refs_text(refs) -> str:
    return "、".join(_unique([str(value) for value in refs if value]))


def _named(value: dict, default="未命名对象") -> str:
    for key in ("object_name", "name", "display_name", "server", "ip_address", "address", "host_name", "hostname", "node_name", "service", "interface_id", "ip"):
        item = value.get(key)
        if isinstance(item, (str, int, float)) and str(item).strip() and not re.fullmatch(r"[a-fA-F0-9-]{32,}", str(item)):
            return str(item)
    return default


def _status_text(value: Any) -> str:
    known = {"UP": "运行中", "DOWN": "停止", "running": "运行中", "stopped": "已停止",
             "STABLE": "稳定", "CLUSTER_ACTIVE": "已激活", "CLUSTER_UP_NO_HA": "集群可用（无高可用）",
             "CONNECTED": "已连接", "DISCONNECTED": "已断开", "normal": "读取正常", "attention": "需复核"}
    if isinstance(value, (dict, list)):
        return "详细状态见证据"
    if isinstance(value, bool):
        return _plain(value)
    return f"{value}（{known[str(value)]}）" if str(value) in known else str(value) if value not in (None, "") else "未采集"


def _body_identifier(text: Any) -> str:
    return re.sub(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", "对象标识见证据", str(text))


def _attention_objects(value: Any, default_name: str, ref: str) -> list[dict]:
    """Find explicitly reported non-normal states, not configuration counters.

    This does not assign fault severity or service criticality. A stopped,
    disabled or role-specific service is displayed with its native state and a
    suitability note; it is never silently promoted to a critical fault.
    """
    states = {"DOWN", "FAILED", "FAILURE", "ERROR", "STOPPED", "NOT_RUNNING", "DISCONNECTED", "UNREACHABLE", "DEGRADED", "UNKNOWN", "UNAVAILABLE",
              "UNSTABLE", "UNHEALTHY", "READ_ONLY", "INSTALL_FAILED", "UPGRADE_FAILED",
              "OPER_DOWN", "OPER_FAILED", "CLUSTER_DOWN", "CLUSTER_FAILED", "CLUSTER_INACTIVE", "CLUSTER_UNREACHABLE", "SE_STATE_DOWN", "SERVER_STATE_DOWN"}
    # Explicit runtime fields projected by the adapters. Provenance fields
    # such as origin_status=unknown are configuration metadata, not faults.
    keys = {"state", "status", "runtime_state", "monitor_runtime_state", "connection_status", "connection_state", "health_status", "health", "overall_status",
            "admin_status", "link_status", "registration_status", "compute_manager_status", "inventory_sync_status",
            "mgmt_connection_status", "high_availability_status", "vtep_state", "storage_state", "host_node_deployment_status",
            "mpa_connectivity_status", "lcp_connectivity_status", "mgmt_cluster_status", "control_cluster_status"}
    result = []
    def walk(node, inherited, path):
        if isinstance(node, list):
            for index, item in enumerate(node):
                walk(item, inherited, path + f"/{index}")
            return
        if not isinstance(node, dict):
            return
        name = _named(node, "")
        ip = node.get("ip")
        if not name and isinstance(ip, dict) and ip.get("addr"):
            name = str(ip["addr"]) + (f":{node['port']}" if node.get("port") is not None else "")
        if not name and isinstance(node.get("server"), dict):
            server = node["server"]; ip = server.get("ip")
            if isinstance(ip, dict) and ip.get("addr"):
                name = str(ip["addr"]) + (f":{server['port']}" if server.get("port") is not None else "")
        name = name or inherited
        for key, native in node.items():
            normalized = native.upper().replace(" ", "_") if isinstance(native, str) else ""
            bad_state = key in keys and isinstance(native, str) and (normalized in states or normalized.endswith("_FAILED"))
            bad_health = key in {"is_healthy", "is_server_up", "is_up"} and native is False
            if bad_state or bad_health:
                state = str(native) if bad_state else "原生健康标记为否"
                note = "配置已停用；不据运行停止直接判断故障。" if node.get("enabled") is False or node.get("admin_state") is False else "已有原生状态需复核；角色适用性、关键性及实际业务影响不据此推断。"
                result.append({"object": _body_identifier(name), "state": _body_identifier(_status_text(state)), "note": note,
                               "evidence_id": ref, "source_path": path + "/" + key})
            if isinstance(native, (dict, list)):
                walk(native, name, path + "/" + key)
    walk(value, default_name, "values")
    grouped = {}
    for item in result:
        key = (item["evidence_id"], item["object"], item["source_path"].rsplit("/", 1)[0])
        grouped.setdefault(key, []).append(item)
    combined = []
    labels = {"runtime_state": "服务生命周期", "monitor_runtime_state": "监控生命周期", "health": "原生健康",
              "admin_status": "管理状态", "link_status": "链路状态", "state": "原生状态", "status": "原生状态"}
    for items in grouped.values():
        item = deepcopy(items[0])
        if len(items) > 1:
            item["state"] = "；".join(labels.get(record["source_path"].rsplit("/", 1)[-1], "读取状态") + "：" + record["state"] for record in items)
        item["source_paths"] = [record["source_path"] for record in items]
        combined.append(item)
    return combined


def _module_collection_time(module: dict) -> str:
    """Separate the original run finish from later, preserved source times."""
    base = str(module.get("completed_at") or module.get("started_at") or "未采集")
    def parse(value):
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else None
        except (ValueError, TypeError):
            return None
    later = []
    coverage = module.get("coverage") or {}
    overlay = coverage.get("targeted_overlay") or {}
    supplements = list(overlay.get("supplement_sources") or [])
    for check in module.get("checks") or []:
        for metric in (check.get("values") or {}).get("targeted_metric_evidence") or []:
            if isinstance(metric, dict) and isinstance(metric.get("source"), dict):
                supplements.append(metric["source"])
    # The overlay marker establishes supplementation. Comparing timestamps
    # cannot: original run finishes may be rounded to seconds, and clocks may
    # differ. Ordinary original sources must never be relabelled as new reads.
    for source in supplements:
        value = source.get("collected_at") if isinstance(source, dict) else None
        moment = parse(value)
        if moment is not None:
            later.append((moment, str(value)))
    text = f"原始整体采集完成 {base}"
    if later:
        later.sort(key=lambda pair: pair[0])
        text += f"；补充来源取数 {later[0][1]} 至 {later[-1][1]}"
    return text


def _module_attention_objects(module: dict, refs: dict) -> list[dict]:
    """Preserve each exact source fact, including aggregates without object_id."""
    target = str(module.get("target_id"))
    result = []
    for index, check in enumerate(module.get("checks") or []):
        cid = str(check.get("check_id") or "")
        if cid.startswith("AVI-A5") or cid == "nsx.certificates":
            continue
        result.extend(_attention_objects(check.get("values") or {},
                      str(check.get("object_name") or module.get("target_name") or "未命名目标"), refs[(target, "check", index)]))
    for index, item in _inventory_entries(module):
        if item.get("object_type") in {"certificate", "ssl_profile", "health_monitor"}:
            continue
        values = item.get("values") or item
        result.extend(_attention_objects(values, _named(item, _named(values, "未命名对象")), refs[(target, "inventory", index)]))
    # Only byte-identical facts from the same original source are collapsed.
    # Records from different sources or collection times retain separate refs.
    return _unique(result)


def _brief_values(raw: dict) -> str:
    values = raw.get("values")
    if not isinstance(values, dict):
        return str(raw.get("summary") or _plain(values))
    labels = {**FIELD_NAMES, "product_version": "产品版本", "backup_enabled": "自动备份启用",
              "schedule_present": "备份计划存在", "actual_deployed_count": "实际管理节点数",
              "unresolved_count": "未处理告警", "total_read": "读取记录", "version": "版本",
              "selected_tenant": "所选租户", "automatic_backup_enabled": "自动备份启用",
              "configured_member_count": "配置成员数", "native_status": "原生状态"}
    items = []
    for key, value in values.items():
        if key in labels and value is not None and isinstance(value, (str, int, float, bool)):
            items.append(f"{labels[key]}：{_status_text(value) if key in {'state','status'} else _plain(value)}")
    summary = str(raw.get("summary") or "")
    detail = "；".join(items)
    return (summary + (" " + detail if detail and detail not in summary else "")) if summary else detail or "已读取配置或对象记录，完整字段见工程证据。"


def _alert_lifecycle(product: str, alert: dict) -> tuple[str, str]:
    """Display the saved native lifecycle without regrading its severity."""
    native = alert.get("status") if product == "nsx" else alert.get("state")
    if native is None:
        native = alert.get("native_state")
    state = str(native or "").strip()
    lifecycle = alarm_lifecycle_of(product, alert)
    if lifecycle == "cleared":
        return "cleared", f"已清除（{state}）"
    if lifecycle == "active":
        return "active", f"活动（{state}）"
    return "unknown", f"状态待确认（{state or '未采集'}）"


def _resource_samples(values: dict, owner: str, ref: str) -> list[list[str]]:
    """Keep every returned sample in the shared customer body, not just JSON."""
    rows = []
    for metric in values.get("metrics") or []:
        if not isinstance(metric, dict):
            continue
        metric_id = str(metric.get("metric_id") or "指标名称未采集")
        unit = str(metric.get("unit") or "单位未采集")
        display_unit = "%" if unit.upper() == "PERCENT" else unit
        requested = metric.get("requested_window") or {}
        returned = metric.get("returned_window") or {}
        window = f"请求：{requested.get('start', '未采集')} 至 {requested.get('stop', '未采集')}"
        if requested.get("step") is not None:
            window += f"；间隔 {requested['step']} 秒"
        if returned:
            window += f"；返回窗口：{_plain(returned)}"
        count = metric.get("returned_sample_count")
        missing = metric.get("missing_samples")
        window += f"；返回 {count if count is not None else '未采集'} 个样本；缺样 {missing if missing is not None else '未采集'}"
        if metric.get("rejected_samples"):
            window += f"；拒收 {metric['rejected_samples']} 个样本"
        if metric.get("complete") is not True:
            window += "；窗口不完整，不能据此判断持续负载"
        samples = metric.get("samples") or []
        for sample in samples:
            if not isinstance(sample, dict):
                continue
            value = sample.get("value")
            measured = f"{value} {display_unit}" if value is not None else "未采集"
            rows.append([f"{owner}\n{metric_id}", measured,
                         f"采样：{sample.get('timestamp') or '未采集'}\n{window}", ref])
        if not samples:
            rows.append([f"{owner}\n{metric_id}", "未采集", window + "；没有可用样本，不能按零处理", ref])
    return rows


def _capacity_display(value: Any, unit: str) -> str:
    """Explicit SI kB and IEC KiB conversions; unknown units are not guessed."""
    factors = {"bytes": 1, "B": 1, "kilobytes": 1000, "kB": 1000,
               "KiB": 1024, "MiB": 1024 ** 2, "GiB": 1024 ** 3}
    if value is None:
        return "未采集"
    if not isinstance(value, (int, float)) or isinstance(value, bool) or unit not in factors:
        return f"{value} {unit or '单位未返回'}（未换算）"
    size = value * factors[unit]
    suffix, divisor = ("GiB", 1024 ** 3) if abs(size) >= 1024 ** 3 else ("MiB", 1024 ** 2)
    return f"{size / divisor:.2f} {suffix}"


def _capacity_pair(used: Any, total: Any, unit: str) -> str:
    text = f"{_capacity_display(used, unit)} / {_capacity_display(total, unit)}"
    if isinstance(used, (int, float)) and not isinstance(used, bool) and isinstance(total, (int, float)) and not isinstance(total, bool) and total > 0:
        text += f"；使用率 {used / total * 100:.1f}%"
    return text


def _customer_next_step(raw: dict) -> str:
    saved = str(raw.get("recommendation") or "").strip()
    generic = {"", "结合设备页面与工程证据核对缺项、对象适用性及业务基线。", "结合管理页面核实缺失字段与业务基线。"}
    if saved not in generic:
        return saved
    if raw.get("status") == "permission_denied":
        return "补齐本管理项的读取权限后重新核对。"
    if raw.get("status") == "collection_failed":
        return "按本条读取错误核对接口和连接，再复核该管理项。"
    cid = str(raw.get("check_id") or "")
    if cid in {"AVI-A3", "nsx.resources"}:
        return "结合本目标的窗口样本和分区记录核对资源；缺样先补齐。"
    if cid in {"AVI-A7", "nsx.backup"}:
        return "核对该目标的备份计划及已有成功、失败结果，补齐未确认部分。"
    return "核对本条已指出的缺失字段或原生状态后复查。"


def _inventory_entries(module: dict) -> list[tuple[Any, dict]]:
    value = module.get("inventory") or []
    if isinstance(value, list):
        return [(index, item) for index, item in enumerate(value) if isinstance(item, dict)]
    return [(key, item) for key, item in value.items() if isinstance(item, dict)] if isinstance(value, dict) else []


def _configuration_usage(values: dict) -> str:
    labels = {"management_portal": "管理门户（配置引用）", "management_portal_tls": "管理门户 TLS（配置引用）",
              "management_secure_channel": "管理安全通道（配置引用）", "virtual_service_certificate": "虚拟服务（配置引用）",
              "virtual_service_tls": "虚拟服务 TLS（配置引用）", "pool_tls": "后端池 TLS（配置引用）",
              "pool_health_monitor": "后端池健康检查（配置引用）",
              "portal_configuration": "管理门户（配置引用）", "secure_channel_configuration": "管理安全通道（配置引用）",
              "api": "管理 API（配置引用）", "management_cluster_api": "管理集群 API（配置引用）"}
    result = []
    for usage in values.get("usages") or []:
        if isinstance(usage, dict):
            name = str(usage.get("source_name") or "")
            result.append(labels.get(str(usage.get("usage")), "已记录配置引用") + (f"：{name}" if name else ""))
    for usage in values.get("management_bindings") or []:
        result.append(labels.get(str(usage), "管理配置引用"))
    for binding in values.get("bindings") or []:
        if isinstance(binding, dict):
            result.append(labels.get(str(binding.get("usage")), "管理接口配置引用"))
    return "；".join(_unique(result)) or "当前已采关系中未确认用途；不代表全局未使用。"


def _certificate_rows(module: dict, refs: dict) -> tuple[list[list[str]], list[str]]:
    registry = {}
    target = str(module.get("target_id"))
    records = []
    for index, check in enumerate(module.get("checks") or []):
        cid = str(check.get("check_id") or "")
        if cid.startswith("AVI-A5:"):
            records.append((check.get("values") or {}, check, [refs[(target, "check", index)]]))
        elif cid == "nsx.certificates":
            for value in (check.get("values") or {}).get("certificates") or []:
                records.append((value, check, [refs[(target, "check", index)]]))
    for index, record in _inventory_entries(module):
        if record.get("object_type") == "certificate":
            records.append((record.get("values") or {}, {}, [refs[(target, "inventory", index)]]))
    all_refs = []
    for value, check, record_refs in records:
        if not isinstance(value, dict):
            continue
        identity = value.get("identity") or {}
        x509 = value.get("x509_validity") or {}
        digest = identity.get("certificate_sha256") or x509.get("certificate_sha256") or value.get("certificate_sha256")
        digest = str(digest or "").lower()
        trusted_digest = bool(re.fullmatch(r"[a-f0-9]{64}", digest))
        key = (target, str(value.get("tenant_id") or module.get("selected_tenant") or ""), digest if trusted_digest else str(value.get("uuid") or check.get("object_id") or len(registry)))
        record = registry.setdefault(key, {"names": [], "uses": [], "validity": [], "statuses": [], "refs": []})
        record["names"].append(str(value.get("name") or check.get("object_name") or "管理证书"))
        record["uses"].append(_configuration_usage(value))
        metadata = value.get("metadata") or {}
        starts = x509.get("valid_from") or value.get("valid_from") or metadata.get("not_before")
        expires = x509.get("expires_at") or value.get("expires_at") or metadata.get("not_after")
        def display_time(value):
            if not value: return "未采集"
            try:
                parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                if parsed.tzinfo is not None:
                    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            except (ValueError, TypeError):
                pass
            return str(value)
        record["validity"].append(f"{display_time(starts)} 至 {display_time(expires)}")
        if check:
            record["statuses"].append(STATUS_NAMES.get(check.get("status"), "数据不足"))
        record["refs"].extend(record_refs); all_refs.extend(record_refs)
    rows = []
    for record in registry.values():
        statuses = _unique(record["statuses"])
        rows.append(["；".join(_unique(record["names"])), "；".join(_unique(record["uses"])),
                     "；".join(_unique(record["validity"])), " / ".join(statuses) if len(statuses) <= 1 else "状态记录有差异，需复核：" + " / ".join(statuses),
                     _refs_text(record["refs"])])
    return rows, _unique(all_refs)


def _empty_pool_scope(module: dict) -> bool:
    rows = [c for c in module.get("checks") or [] if c.get("check_id") == "AVI-C5"]
    return bool(rows) and all(c.get("status") == "not_deployed" and c.get("completeness") == "complete"
                              and c.get("sources") and (c.get("values") or {}).get("count") == 0
                              and all(s.get("read_completeness", "complete") == "complete" for s in c["sources"]) for c in rows)


def _build_product_body(module: dict, engineering_rows: list[dict], refs: dict) -> dict:
    target = str(module.get("target_id"))
    scope = module_scope(module)
    checks = list(scoped_checks(module))
    inventory = _inventory_entries(module)
    inventory_by_id = {str(item.get("object_id") or item.get("uuid") or ""): item for _, item in inventory}
    normal, concerns, empty, object_rows, catalogs = [], [], [], [], []
    object_tables = []
    registration_rows = []
    attention_objects = _module_attention_objects(module, refs)
    used_refs, check_refs = [refs[(target, "module", 0)]], []
    catalog_groups: dict[tuple[str, str], dict] = {}
    for index, raw in enumerate(checks):
        ref = refs[(target, "check", index)]
        check_refs.append(ref); used_refs.append(ref)
        cid = str(raw.get("check_id") or "")
        values = raw.get("values") or {}
        status = str(raw.get("status") or "insufficient_data")
        title = re.sub(r"^[ABC]\d+\s*", "", str(raw.get("title") or cid or "检查记录"))
        obj = str(raw.get("object_name") or module.get("target_name") or "未命名目标")
        if cid.startswith("AVI-A5:") or cid == "nsx.certificates" and isinstance(values, dict) and values.get("certificates"):
            if status in {"abnormal", "attention"}:
                concerns.append({"title": title, "object": obj, "status": STATUS_NAMES[status],
                                 "observation": "证书有效期或原生状态需复核，具体日期与用途集中列于证书表。",
                                 "recommendation": "按证据核对证书对象、用途和采集时状态。", "evidence_ids": [ref]})
            continue
        if cid.startswith("AVI-C7:") and status in {"normal", "insufficient_data"}:
            item = inventory_by_id.get(str(raw.get("object_id") or ""), {})
            projected = item.get("values") or values
            state = projected.get("reference_state") or ("unreferenced_in_complete_selected_scope" if _empty_pool_scope(module) else "unknown_partial_scope")
            labels = {"referenced": "已被当前所选业务配置引用", "unreferenced_in_complete_selected_scope": "当前完整所选范围未发现引用", "unknown_partial_scope": "引用范围未完整核实"}
            group = catalog_groups.setdefault(("健康检查配置", state), {"count": 0, "refs": [], "label": labels.get(state, labels["unknown_partial_scope"])})
            group["count"] += 1; group["refs"].append(ref)
            if state == "referenced":
                object_rows.append([obj, "健康检查配置", f"类型：{values.get('type', '未采集')}；目标端口：{values.get('monitor_port', '未采集')}。配置不等于已有探测结果。", ref])
            continue
        if status == "not_deployed":
            if scope is not None:
                registration_rows.append([title, "未登记", _brief_values(raw), ref])
                continue
            empty.append({"title": title, "evidence_ids": [ref]})
            continue
        if (cid in {"nsx.alarms", "AVI-A4"} and module.get("native_alerts")
                and raw.get("completeness") == "complete"
                and status not in {"collection_failed", "permission_denied", "unsupported", "cancelled"}):
            continue
        observation = _brief_values(raw)
        if cid == "AVI-A3" and isinstance(values, dict) and values.get("metrics") == []:
            observation = "本对象所请求窗口未返回资源样本，原因未验证；不能按零处理或据此认定设备无此能力。"
            if values.get("partitions") is None:
                observation += " 内部磁盘分区数据未采集，完整读取来源尚未核实。"
        if cid == "AVI-A8":
            observation += " 本次远程日志来源只覆盖告警日志配置。"
        if cid == "AVI-A2:services" and isinstance(values, dict):
            states = values.get("native_state_counts") or {}
            observation = (f"已读取 {values.get('reported_count',len(values.get('services') or []))} 项原生服务条目；"
                           f"状态分布：{_plain(states)}。关键性和详细实例语义未确认，不能据此确认关键服务全部正常。")
        if cid == "AVI-A2" and isinstance(values, dict):
            cluster = values.get("cluster") or {}
            state = (cluster.get("state") if isinstance(cluster, dict) else None) or values.get("cluster_state") or values.get("state") or values.get("status")
            observation = "原生集群状态：" + _status_text(state)
            if values.get("nodes_count") is not None:
                observation += f"；原生节点数：{values['nodes_count']}"
            observation += "；逐服务读取单独列示，不将集群状态替代服务关键性判断。"
        if status == "normal":
            normal.append([title, obj, observation, ref])
        else:
            concerns.append({"title": title, "object": obj, "status": STATUS_NAMES.get(status, "数据不足"),
                             "observation": observation,
                             "recommendation": _customer_next_step(raw),
                             "evidence_ids": [ref]})
        if isinstance(values, dict):
            if cid == "AVI-A3" and values.get("metrics"):
                metric_rows = _resource_samples(values, obj, ref)
                if metric_rows:
                    object_tables.append(_table_view("Controller 资源采样", ["Controller / 指标", "采样值与单位", "采样窗口与限制", "证据"],
                                                     metric_rows, [ref], [1.8, 1.0, 3.1, 1.3]))
            services = values.get("services")
            if isinstance(services, list) and services and cid != "AVI-A2:services":
                rows = []
                for service in services:
                    if isinstance(service, dict):
                        if _attention_objects(service, _named(service, "未命名服务"), ref):
                            continue
                        rows.append([_named(service, "服务名称未返回"), _status_text(service.get("runtime_state") or service.get("state") or service.get("status")),
                                     "角色适用性需复核" if service.get("role_applicability") == "requires_role_review" else _status_text(service.get("assessment") or "已读取"), ref])
                if rows:
                    object_tables.append(_table_view("管理服务读取摘要", ["服务", "读取状态", "说明", "证据"], rows, [ref], [1.5, 1, 1.5, 1]))
            for node in values.get("nodes") or []:
                if not isinstance(node, dict) or not any(k in node for k in ("mem_used", "mem_total", "cpu_cores", "file_systems")):
                    continue
                units = node.get("units") or {}
                unit = str(units.get("memory_disk_filesystems") or "")
                conversion = ("原接口 kilobytes 按 1000 B 换算；1 MiB=1048576 B，1 GiB=1073741824 B"
                              if unit == "kilobytes" else f"原接口单位 {unit or '未返回'}；仅显式单位换算")
                short_conversion = {"kilobytes": "1 kB=1000 B", "kB": "1 kB=1000 B", "KiB": "1 KiB=1024 B",
                                    "bytes": "1 B", "B": "1 B", "MiB": "1 MiB=1048576 B", "GiB": "1 GiB=1073741824 B"}.get(unit, "单位未确认，不换算")
                object_rows.append([str(module.get("target_name") or "管理设备"), "设备内部资源",
                                    f"CPU核数：{node.get('cpu_cores','未采集')}；内存已用/总量：{_capacity_pair(node.get('mem_used'), node.get('mem_total'), unit)}。{conversion}。", ref])
                disks = []
                for filesystem in node.get("file_systems") or []:
                    if isinstance(filesystem, dict):
                        disks.append([str(filesystem.get("mount") or filesystem.get("file_system") or "未命名分区"),
                                      _capacity_pair(filesystem.get('used'), filesystem.get('total', filesystem.get('size')), unit),
                                      short_conversion, ref])
                if disks:
                    object_tables.append(_table_view("设备内部分区", ["分区", "已用 / 总量 / 使用率", "换算依据", "证据"], disks, [ref], [1.2, 2.3, 1.2, 1.3]))
            if cid == "nsx.security":
                known = {}
                for item in [*(values.get("referenced_groups") or []), *(values.get("service_definitions") or [])]:
                    if isinstance(item, dict):
                        for key in ("id", "path"):
                            if item.get(key):
                                known[str(item[key])] = _named(item, "引用对象")
                def names(items):
                    result = []
                    for item in items or []:
                        text = str(item)
                        last = text.rsplit("/", 1)[-1]
                        result.append("任意" if text == "ANY" else known.get(text) or known.get(last) or ("引用对象见证据" if re.fullmatch(r"[a-fA-F0-9-]{32,}", last) else last))
                    return "、".join(result) or "未采集"
                rules = []
                for policy in values.get("policies") or []:
                    if not isinstance(policy, dict):
                        continue
                    for rule in policy.get("rules") or []:
                        if isinstance(rule, dict):
                            rules.append([f"{_named(policy,'策略')}/{_named(rule,'规则')}",
                                          f"动作：{rule.get('action','未采集')}；" + ("需人工复核" if rule.get("manual_review") else "配置已读取"),
                                          f"源：{names(rule.get('source_groups'))}；目的：{names(rule.get('destination_groups'))}；服务：{names(rule.get('services'))}", ref])
                if rules:
                    object_tables.append(_table_view("安全规则配置与人工复核", ["策略 / 规则", "读取情况", "匹配对象", "证据"], rules, [ref], [1.8, 1.5, 2.5, 1]))
            elif cid in {"nsx.edge", "nsx.segments", "nsx.gateways", "nsx.nat"}:
                objects = []
                for key in ("nodes", "clusters", "segments", "gateways", "rules"):
                    for item in values.get(key) or []:
                        if isinstance(item, dict):
                            runtime = item.get("runtime") or {}
                            runtime = runtime if isinstance(runtime, dict) else {}
                            objects.append([_named(item, _named(item.get("deployment") or {}, "未命名业务对象")),
                                            _status_text(item.get("state") or item.get("status") or runtime.get("status") or runtime.get("node_status")),
                                            "配置与已有状态读取；不据此确认实际转发。", ref])
                if objects:
                    object_tables.append(_table_view(title + "对象", ["对象", "读取状态", "说明", "证据"], objects, [ref], [1.7, 1.3, 2.5, 1]))
    for index, item in inventory:
        ref = refs[(target, "inventory", index)]; used_refs.append(ref)
        kind = str(item.get("object_type") or "对象")
        values = item.get("values") or item
        if kind in {"certificate", "health_monitor"}:
            if kind == "health_monitor":
                state = values.get("reference_state") or ("unreferenced_in_complete_selected_scope" if _empty_pool_scope(module) else "unknown_partial_scope")
                group = catalog_groups.get(("健康检查配置", state))
                if group:
                    group["refs"].append(ref)
            continue
        if kind == "ssl_profile":
            state = values.get("reference_state") or "unknown_partial_scope"
            labels = {"referenced": "已被当前所选配置引用", "unreferenced_in_complete_selected_scope": "当前完整所选范围未发现引用", "unknown_partial_scope": "引用范围未完整核实"}
            group = catalog_groups.setdefault(("TLS 配置", state), {"count": 0, "refs": [], "label": labels.get(state, labels["unknown_partial_scope"])})
            group["count"] += 1; group["refs"].append(ref)
            if state == "referenced":
                object_rows.append([_named(item, _named(values, "TLS 配置")), "已配置引用的 TLS 配置",
                                    _configuration_usage(values) + "；不据此确认实际 TLS 握手采用情况。", ref])
            continue
        if kind == "NSXClusterRoleConfiguration":
            continue
        labels = {"controller_node": "Controller节点", "cloud": "Cloud", "service_engine": "Service Engine", "service_engine_group": "SE组配置",
                  "virtual_service": "虚拟服务", "pool": "后端池", "backend_server": "后端服务器", "NSXManagerNode": "Manager节点", "NSXHostTransportNode": "主机接入对象"}
        name = _named(item, _named(values, "未命名对象"))
        state = values.get("state") or values.get("status") or values.get("runtime_state")
        if not state and isinstance(values.get("native_status"), dict):
            state = values["native_status"].get("state") or values["native_status"].get("status")
        config = values.get("configuration") or {}
        name = name if name != "未命名对象" else _named(config, "未命名对象")
        linked = [c for c in checks if c.get("object_id") and c.get("object_id") == item.get("object_id")]
        detail = _status_text(state) if state else "配置/记录已取得；运行详情见证据。"
        if scope is not None and kind == "cloud":
            detail = "已读取 Cloud 登记配置；不据此判断运行连接状态。"
        if any(c.get("status") == "abnormal" for c in linked):
            detail = "异常；" + detail
        object_rows.append([name, labels.get(kind, "已读取对象"), detail, ref])
    for (kind, state), group in catalog_groups.items():
        catalogs.append([kind, str(group["count"]), group["label"] + "；系统默认属性未确认，不按名称推断。", refs[(target, "module", 0)]])
    certificate_rows, certificate_refs = _certificate_rows(module, refs)
    used_refs.extend(certificate_refs)
    alert_owner = [refs[(target, "check", i)] for i, c in enumerate(checks) if c.get("check_id") in {"nsx.alarms", "AVI-A4"}]
    cleared_alerts = []
    for index, alert in enumerate(module.get("native_alerts") or []):
        ref = refs[(target, "native_alert", index)]; used_refs.append(ref)
        lifecycle, lifecycle_text = _alert_lifecycle(str(module.get("product")), alert)
        severity = str(alert.get("severity") or alert.get("level") or "原生等级未返回")
        description = str(alert.get("description") or alert.get("summary") or alert.get("reason") or alert.get("message") or "原生说明未采集")
        if lifecycle == "cleared":
            cleared_alerts.append([str(alert.get("object_name") or alert.get("obj_name") or module.get("target_name") or "设备对象"),
                                   severity, lifecycle_text, description, ref])
            continue
        concerns.append({"title": "设备原生告警", "object": str(alert.get("object_name") or alert.get("obj_name") or alert.get("node_id") or module.get("target_name") or "设备对象"),
                         "status": severity + " · " + lifecycle_text,
                         "observation": description,
                         "recommendation": str(alert.get("recommendation") or alert.get("recommended_action_description") or alert.get("recommended_action") or
                                               ("先在管理端确认本条告警的生命周期和缺失字段。" if lifecycle == "unknown" else "按本条原生告警建议核查具体对象，处理后复查活动状态。")),
                         "evidence_ids": [ref, *alert_owner]})
    if object_rows:
        object_tables.insert(0, _table_view("已读取设备与对象", ["对象", "类别", "读取情况", "证据"], object_rows,
                                            [ref for row in object_rows for ref in row[-1].split("、")], [1.5, 1, 2.5, 1]))
    if attention_objects:
        object_tables.insert(0, _table_view("需复核状态的具体对象", ["对象", "原生读取状态", "适用性说明", "证据"],
                                            [[item["object"], item["state"], item["note"], item["evidence_id"]] for item in attention_objects],
                                            [item["evidence_id"] for item in attention_objects], [1.7, 1.1, 2.7, 1]))
    tables = []
    if concerns:
        tables.append(_table_view("异常与需复核事项", ["事项与对象", "读取结果与结论", "下一步核查", "证据"],
                                  [[f"{c['status']} · {c['title']}\n{c['object']}", c["observation"], c["recommendation"], _refs_text(c["evidence_ids"])] for c in concerns],
                                  [ref for c in concerns for ref in c["evidence_ids"]], [1.4, 2.8, 1.8, 1]))
    if normal:
        tables.append(_table_view("正常读取摘要", ["检查项", "对象", "读取值摘要", "证据"], normal,
                                  [row[-1] for row in normal], [1.4, 1.2, 3, 1]))
    if certificate_rows:
        tables.append(_table_view("证书有效期与配置用途", ["证书", "配置用途", "采集时有效期", "状态", "证据"], certificate_rows,
                                  certificate_refs, [1.5, 1.7, 2.3, 0.7, 1.1]))
    tables.extend(object_tables)
    if registration_rows:
        tables.append(_table_view("管理登记与适用性", ["检查项", "原生状态", "已读记录", "证据"], registration_rows,
                                  [row[-1] for row in registration_rows], [1.5, 0.9, 3.2, 1.3]))
    if cleared_alerts:
        tables.append(_table_view("已清除告警历史", ["对象", "原生级别", "生命周期", "原生说明", "证据"],
                                  cleared_alerts, [row[-1] for row in cleared_alerts], [1.2, 0.8, 1.4, 2.5, 1.3]))
    if catalogs:
        tables.append(_table_view("配置目录汇总", ["目录", "数量", "适用范围", "证据"], catalogs,
                                  [row[-1] for row in catalogs], [1.3, 0.6, 3.5, 1]))
    conclusion = (f"{scope.label}：检查记录 {len(checks)} 条；需复核事项 {len(concerns)} 条"
                  + ("（含活动或状态未明的原生告警）" if any(_alert_lifecycle(str(module.get('product')), a)[0] != 'cleared' for a in module.get('native_alerts') or []) else "") + "。" if scope else
                  f"本次取得 {len(checks)} 项原始检查记录；正文集中展示需复核事项、正常读取摘要及现有对象。原生等级不换算为P级。")
    body = {"conclusion": conclusion,
            "concerns": concerns, "normal_rows": normal, "empty_business": empty,
            "empty_business_text": ("当前所选范围未部署或未登记：" + "、".join(re.sub(r"^[ABC]\d+\s*", "", item["title"]) for item in empty)
                                    + f"。空对象不验证业务异常识别，完整来源见 {refs[(target, 'module', 0)]}。") if empty else "",
            "tables": tables,
            "object_tables": object_tables, "configuration_catalogs": catalogs, "certificate_rows": certificate_rows,
            "limit_refs": [], "evidence_ids": _unique(used_refs), "check_evidence_ids": _unique(check_refs)}
    # Technical identifiers stay exact in the evidence payload; the customer
    # body uses its evidence reference when no readable alias was collected.
    for table in body["tables"]:
        for row in table["rows"]:
            row[:] = [_body_identifier(value) for value in row]
    for concern in body["concerns"]:
        for key in ("title", "object", "observation", "recommendation"):
            concern[key] = _body_identifier(concern[key])
    return body


def _body_constraints(report: ReportData) -> list[dict]:
    managed = list(report.product_modules)
    if managed and all(module_scope(m) is not None for m in managed) and not has_legacy_sections(report):
        return [{"id": "时点", "title": "判断限制", "text": "结果仅反映采集时点；缺失或读取失败的管理证据仍需补齐，资源样本不代表持续负载。"}]
    return [
        {"id": "范围", "title": "采集范围与缺失数据", "text": "仅覆盖所选目标、租户与实际取得的对象；缺字段、权限或接口问题均不视为正常，详细范围见工程证据。"},
        {"id": "运行", "title": "配置与实际运行", "text": "读取配置和原生状态不能证明转发、拦截或业务访问已实际生效；没有额外发起流量、探测或切换。"},
        {"id": "验收", "title": "功能验证层级", "text": "现场读取、离线样本及离线重放分别保留；现场读取不等于逐项真实业务验收，未验收能力不计入已验证通过。"},
        {"id": "基线", "title": "业务基线", "text": "缺少客户业务基线时仅展示参数，不能统一判断资源阈值、超时、分配算法或冗余数量是否合理。"},
        {"id": "证书", "title": "证书依据与用途", "text": "证书有效期沿用采集时证据；配置引用不等于实际 TLS 呈现，未独立验证证书链、签名或撤销状态。"},
        {"id": "目录", "title": "配置目录与引用", "text": "未发现引用仅指本次采集完整的所选范围，不代表全局未使用；系统默认属性未确认时不按名称推断，配置参数不充当探测结果。"},
    ]


def product_report_view(report: ReportData) -> dict:
    """Build one display contract consumed unchanged by HTML, Word and PDF."""
    evidence = build_product_evidence(report)
    evidence_lookup = {(entry["target_id"], entry["kind"], entry["ordinal"]): entry["evidence_id"] for entry in evidence["record_index"]}
    modules = _section_modules(report)
    observations, conflicts = deduplicate_observations(modules)
    sections = []
    for module in modules:
        checks = [c for c in observations if c.get("target_id") == module.get("target_id")]
        elsewhere = [c for c in observations if module.get("target_id") in c.get("affected_target_ids", []) and c.get("target_id") != module.get("target_id")]
        rows = []
        for check in checks:
            sources = check.get("sources") or []
            times = _unique([s.get("collected_at") for s in sources if s.get("collected_at")])
            basis = str(check.get("basis") or "未提供判断依据，仅展示读取值。")
            limits = [str(x) for x in check.get("limitations") or []]
            if check.get("conflict"):
                limits.append(check["conflict"])
            verification = str(check.get("verification") or "unverified")
            if check.get("status") == "normal" and verification not in VERIFIED_LEVELS:
                limits.append("读取值为正常；该能力尚未完成逐项现场验收，不计入已验证通过。")
            values = deepcopy(check.get("values"))
            if isinstance(values, dict) and values.get("native_alerts") == module.get("native_alerts"):
                values.pop("native_alerts", None)
            rows.append({
                "title": str(check.get("title") or check.get("check_id") or "未命名检查"),
                "object": str(check.get("object_name") or check.get("object_id") or module.get("target_name") or "未记录对象"),
                "status": STATUS_NAMES.get(check.get("status"), "数据不足"),
                "value": _plain(values), "summary": str(check.get("summary") or ""),
                "time": "；".join(str(t) for t in times) or str(check.get("collected_at") or "未采集"),
                "source": "；".join(f"{s.get('method', 'GET')} {s.get('path', '')}" for s in sources) or "未采集",
                "version_basis": "；".join(str(s.get("version_basis") or "未记录") for s in sources) or "未记录",
                "basis": basis, "judgement": "NSX／AVI 原生告警" if "NATIVE" in str(check.get("judgement", "")).upper() else "程序判断／读取值",
                "native_severity": str(check.get("native_severity") or ""),
                "verification": VERIFY_NAMES.get(verification, verification),
                "completeness": EXECUTION_NAMES.get(check.get("completeness"), str(check.get("completeness") or "未记录")),
                "limits": "；".join(_unique(limits)) or "未提供额外限制",
                "recommendation": str(check.get("recommendation") or "按采集来源与设备页面核对；数据不足时补充证据。"),
                "impact": str(check.get("confirmed_impact") or check.get("impact") or "未确认业务影响"),
                "evidence_count": len(check["evidence_records"]),
            })
            rows[-1]["details"] = _check_details(rows[-1])
        native = []
        alert_sources = _unique([s for c in module.get("checks") or []
                                 if c.get("check_id") in {"nsx.alarms", "AVI-A4"}
                                 for s in c.get("sources") or []])
        alert_origin = "；".join(f"{s.get('method', 'GET')} {s.get('path', '')}（采集 {s.get('collected_at', '未采集')}）" for s in alert_sources) or "来源未记录"
        for alert in module.get("native_alerts") or []:
            native.append({"object": str(alert.get("object_name") or alert.get("obj_name") or alert.get("node") or alert.get("node_id") or alert.get("entity_name") or alert.get("id") or "未记录对象"),
                           "severity": str(alert.get("severity") or alert.get("level") or alert.get("native_severity") or "未采集"),
                           "status": str(alert.get("status") or alert.get("state") or "未采集"),
                           "time": "设备原始发生时间：" + str(alert.get("last_reported_time") or alert.get("last_occurrence_time") or alert.get("timestamp") or alert.get("time") or "未采集") + "\n" + alert_origin,
                           "description": str(alert.get("description") or alert.get("summary") or alert.get("message") or alert.get("reason") or "未采集"),
                           "recommendation": str(alert.get("recommendation") or alert.get("recommended_action_description") or alert.get("recommended_action") or "原生建议未采集")})
        security = module.get("transport_security") or {}
        if security.get("mode") == "explicit_lab_unverified" or security.get("allow_untrusted_lab"):
            security_text = "本次未验证对端身份（明确授权的实验自签名连接）"
        elif security.get("peer_identity_verified") is True or security.get("identity_verified") is True:
            security_text = "TLS 证书及主机身份已验证"
        else:
            security_text = "未完成连接身份验证；不能确认对端身份。"
        body = _build_product_body(module, rows, evidence_lookup)
        body["limit_refs"] = [item["id"] for item in _body_constraints(report)]
        sections.append({"product": str(module.get("product")), "product_name": PRODUCT_NAMES.get(module.get("product"), str(module.get("product"))),
                         "target_id": str(module.get("target_id") or ""), "name": str(module.get("target_name") or "未命名目标"),
                         "address": str(module.get("target_address") or "未记录"), "version": str(module.get("version") or "未采集"),
                         "build": str(module.get("build") or "未采集"), "time": _module_collection_time(module),
                         "collection": EXECUTION_NAMES.get(module.get("collection_state"), str(module.get("collection_state") or "未记录")),
                         "analysis": EXECUTION_NAMES.get(module.get("analysis_state"), str(module.get("analysis_state") or "未记录")),
                         "delivery": ("报告编排时纳入本报告；最终格式交付状态见报告中心" if module.get("delivery_state") == "pending"
                                      else EXECUTION_NAMES.get(module.get("delivery_state"), str(module.get("delivery_state") or "未记录"))), "security": security_text,
                         "limits": [*[str(x) for x in module.get("limitations") or []],
                                    *(["本目标与其他目标的相同事实已在首次出现位置展示，原记录及来源保留。"] if elsewhere else [])],
                         "checks": rows, "native_alerts": native,
                         "body": body,
                         "inventory": _inventory_rows(module.get("inventory")),
                         "errors": [_plain(x) for x in module.get("errors") or []]})
    summary = report.integration_summary or {}
    targets = [{"product": m.get("product", ""), "product_name": PRODUCT_NAMES.get(m.get("product"), str(m.get("product"))),
                "target_id": str(m.get("target_id") or ""), "name": str(m.get("target_name") or "未命名目标"),
                "address": str(m.get("target_address") or "未记录"),
                "collection": EXECUTION_NAMES.get(m.get("collection_state"), str(m.get("collection_state") or "未记录")),
                "analysis": EXECUTION_NAMES.get(m.get("analysis_state"), str(m.get("analysis_state") or "未记录")),
                "delivery": "格式交付以报告中心最终记录为准",
                "limits": "检查范围以本节适用性说明及工程证据为准。"}
               for m in report.product_modules or []]
    result = {"title": report.report_info.report_title, "run_id": report.report_info.run_id,
            "customer": report.customer_info.customer_name, "site": report.customer_info.site_name,
            "generated_at": report.report_info.generated_at,
            "has_vcenter": has_legacy_sections(report),
            "scope": "、".join(PRODUCT_NAMES.get(x, x) for x in report.selected_products),
            "targets": targets, "navigation": [f"{t['product_name']} 专项 {t['name']}" for t in targets],
            "sections": sections, "conflicts": conflicts,
            "summary": f"产品检查记录 {len(observations)} 条；已验证通过 {summary.get('verified_pass', 0)} 条。原生告警保留原等级。",
            "constraints": _body_constraints(report),
            "evidence_filename": f"{PRODUCT_EVIDENCE_BASENAME}-{hashlib.sha256(_canonical_bytes(evidence)).hexdigest()[:12]}.json",
            "evidence_index": deepcopy(evidence["record_index"]),
            "limitations": ["完整配置、内部标识、原始状态、取数来源与精确采集时间保存在工程附件；正文 E 编号可逐条回查。",
                            *([str(summary["score_scope"]["note"])] if summary.get("score_scope", {}).get("note") else [])],
            "deduplication": "只合并具有明确对象身份、相同事实、采集时间和口径的重复展示；原记录保留，差异不合并。"}
    management = [module_scope(m) for m in modules]
    if management and all(management) and not has_legacy_sections(report):
        result["scope"] = "、".join(_unique([s.label for s in management]))
        result["summary"] = f"管理检查 {len(observations)} 项；需复核事项与具体对象见下表。"
        result["deduplication"] = ""
        result["limitations"] = []
    result["coverage"] = validate_product_coverage(report, result, evidence)
    return result


def _inventory_rows(inventory: Any) -> list[dict]:
    if not inventory:
        return []
    entries = inventory.items() if isinstance(inventory, dict) else [("对象", inventory)]
    result = []
    for kind, value in entries:
        for item in value if isinstance(value, list) else [value]:
            result.extend({"kind": str(kind) + ("（续）" if index else ""), "detail": chunk}
                          for index, chunk in enumerate(_segments(_plain(item))))
    return result


def ensure_report_has_valid_data(report: ReportData) -> None:
    integrated = bool(report.product_modules or report.integration_summary or report.selected_products != ["vcenter"])
    if integrated and not report.integration_summary.get("valid_observations") and not report.integration_summary.get("legacy_present"):
        raise NoValidInspectionData("所选模块均未取得有效检查数据，禁止生成健康报告。")
