"""One read-only projection of a run's results for desktop and delivery reports."""
from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from functools import lru_cache
import hashlib
import json
from typing import Any

from vstacklens.resources import bundled_builtin_rulepack_path
from vstacklens.rules.rulepack_loader import RulePackLoader
from vstacklens.rules.safe_expression import SafeExpressionEngine
from vstacklens.reports.rule_provenance import recorded_rule, judgment_provenance, capture_rule

VERSION = "customer-caliber-20261013-original-results"
LEVELS = ("P1", "P2", "P3")
INTERNAL_BRIDGE_RULES = frozenset({"VSL-DS-020"})
DENIED_RULES = frozenset({
    "VSL-VM-002", "VSL-VM-003", "VSL-VM-014", "VSL-HOST-014", "VSL-HOST-013",
    "VSL-CL-011", "VSL-HOST-025", "VSL-DS-019", "VSL-VM-024", "VSL-NET-015",
})
REVISED_RULES = frozenset({"VSL-DS-001", "VSL-VM-001", "VSL-VM-007", "VSL-VM-022"})
APPROVED_PROJECTION_VERSION = "approved-applicability-20261023-v1"
_RESULT_STATUSES = ("passed", "failed", "unavailable", "not_applicable", "error")
_document_projection_scope = ContextVar('document_projection_scope', default=None)


@contextmanager
def document_projection_scope(report, context=None):
    """Reuse a read-only projection during one synchronous document build.

    The public API outside this scope still returns an independent deep copy.
    The scope is task-local, never stored globally or shared across reports.
    Renderers only receive the independently copied document, not these rows.
    """
    current=_document_projection_scope.get()
    if current is not None and current[0] is report:
        yield
        return
    # Only top-level result_status / approved_projection are changed by the
    # existing projection algorithm. Trusted document readers do not mutate
    # nested captured evidence; share it for this scope instead of cloning it
    # once per saved check. The public API below retains full isolation.
    projection=_build_approved_projection(report,context,share_evidence=True)
    records,findings,checklist=_projection_inputs(report,context)
    token=_document_projection_scope.set((report,projection,records,findings,checklist))
    try:
        yield
    finally:
        _document_projection_scope.reset(token)


def _projection_digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":"), default=str).encode("utf-8")).hexdigest()


def _projection_inputs(report, context: dict[str, Any] | None):
    """Prefer the preserved source, including an intentionally empty source list."""
    inputs = getattr(report, "caliber_inputs", {}) or {}
    supplied = context or {}
    records = inputs.get("object_results") if "object_results" in inputs else supplied.get("object_results")
    if "findings" in inputs:
        findings = inputs["findings"]
    elif "findings" in supplied:
        findings = supplied["findings"]
    else:
        findings = [row.model_dump() if hasattr(row, "model_dump") else row
                    for row in getattr(report, "findings", [])]
    appendix = getattr(report, "appendix", {}) or {}
    checklist = appendix.get("rule_checklist") if "rule_checklist" in appendix else supplied.get("rule_checklist", [])
    return records, findings or [], checklist or []


def _saved_caliber_matches_source(report, cached: dict[str, Any], context) -> bool:
    """Authenticate a pre-existing saved caliber without recalculating its health."""
    records, findings, _ = _projection_inputs(report, context)
    saved_records = cached.get("object_results")
    if records is None or not isinstance(saved_records, list) or len(saved_records) != len(records):
        return False
    finding_by_identity = {(str(row.get("rule_id")), object_key(row)): row for row in findings}
    generated = {"judgment_provenance", "caliber_evidence_incomplete"}
    for original, saved in zip(records, saved_records):
        expected = {**original, **finding_by_identity.get((str(original.get("rule_id")), object_key(original)), {})}
        if original.get("result_status"):
            expected["result_status"] = original["result_status"]
        if ({key: value for key, value in expected.items() if key not in generated}
                != {key: value for key, value in saved.items() if key not in generated}):
            return False
    return True


def _remember_caliber(report, caliber, source):
    # Private per-ReportData state is not part of the accepted saved conclusion.
    report._customer_caliber_cache = {"source": deepcopy(source), "caliber": caliber}


def approved_result_projection(report, context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return an isolated, approved applicability view; never re-evaluate a rule.

    Original records, findings, evidence and captured rule definitions stay intact.
    Asset names are deliberately absent from the applicability identity.
    """
    source_records, findings, source_checklist = _projection_inputs(report, context)
    current=_document_projection_scope.get()
    if (current is not None and current[0] is report and (not context or
            ((source_records is current[2] or source_records==current[2])
             and (findings is current[3] or findings==current[3])
             and (source_checklist is current[4] or source_checklist==current[4])))):
        return current[1]
    return _build_approved_projection(report,context)


def _build_approved_projection(report,context=None,*,share_evidence=False):
    source_records,findings,source_checklist=_projection_inputs(report,context)
    originals = source_records or []
    run_id = str(getattr(getattr(report, "report_info", None), "run_id", "") or "")
    assets = (getattr(report, "asset_inventory", {}) or {}).get("details", {}) or {}
    limitations = []
    vc_by_uuid: dict[str, set[str]] = {}
    vcenter_ids = set()
    for row in originals:
        if str(row.get("run_id") or "") != run_id or not run_id:
            continue
        vc_id = str(row.get("vcenter_id") or "")
        if vc_id:
            vcenter_ids.add(vc_id)
        if row.get("object_type") == "vCenter" and vc_id and row.get("object_key"):
            vc_by_uuid.setdefault(str(row["object_key"]), set()).add(vc_id)

    asset_index: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    identity_inputs = []
    for kind in ("VirtualMachine", "ClusterComputeResource"):
        for asset in assets.get(kind, []) or []:
            properties = asset.get("properties") or {}
            observations = properties.get("sdk_property_observations") or {}
            asset_run = str(asset.get("run_id") or observations.get("run_id") or "")
            asset_vc = str(asset.get("vcenter_id") or "")
            vc_uuid = str(observations.get("vcenter_instance_uuid") or "")
            asset_type = str(asset.get("object_type") or kind)
            key = str(asset.get("object_key") or "")
            identity_inputs.append({"object_type": asset_type, "object_key": key,
                                    "run_id": asset_run, "vcenter_id": asset_vc,
                                    "vcenter_instance_uuid": vc_uuid,
                                    "is_template": properties.get("is_template"),
                                    "ha_enabled": properties.get("ha_enabled"),
                                    "drs_enabled": properties.get("drs_enabled")})
            asset_runs = {str(value) for value in (asset.get("run_id"), observations.get("run_id")) if value}
            if not run_id or asset_runs != {run_id} or not key or asset_type != kind:
                continue
            mapped_ids = vc_by_uuid.get(vc_uuid, set())
            if asset_vc and vc_uuid and mapped_ids != {asset_vc}:
                continue
            if not asset_vc and len(mapped_ids) == 1:
                asset_vc = next(iter(mapped_ids))
            if not asset_vc or asset_vc not in vcenter_ids:
                continue
            asset_index.setdefault((asset_vc, asset_type, key), []).append(properties)

    records = [dict(row) for row in originals] if share_evidence else deepcopy(originals)
    changes = []
    for position, row in enumerate(records):
        evidence = row.get("evidence") or {}
        identity = (str(row.get("vcenter_id") or ""), str(row.get("object_type") or ""),
                    str(row.get("object_key") or ""))
        if (not run_id or str(row.get("run_id") or "") != run_id
                or (evidence.get("run_id") and evidence["run_id"] != run_id)
                or (evidence.get("vcenter_id") and evidence["vcenter_id"] != identity[0])
                or (evidence.get("object_type") and evidence["object_type"] != identity[1])
                or (evidence.get("object_key") and evidence["object_key"] != identity[2])):
            continue
        matching = asset_index.get(identity, [])
        if len(matching) != 1:
            if len(matching) > 1:
                limitations.append({"reason_code": "AMBIGUOUS_ASSET_IDENTITY", "result_id": row.get("result_id"),
                                    "object_type": identity[1], "object_key": identity[2]})
            continue
        properties = matching[0]
        rule_id = str(row.get("rule_id") or "")
        reason = ""
        asset_evidence = {}
        if identity[1] == "VirtualMachine" and properties.get("is_template") is True:
            reason = "TEMPLATE_NOT_APPLICABLE"
            asset_evidence = {"is_template": True, "source_field": "config.template"}
        elif identity[1] == "ClusterComputeResource":
            if rule_id in {"VSL-CL-002", "VSL-CL-009"} and properties.get("ha_enabled") is False:
                reason, asset_evidence = "HA_DISABLED_NOT_APPLICABLE", {"ha_enabled": False}
            elif rule_id in {"VSL-CL-004", "VSL-CL-012"} and properties.get("drs_enabled") is False:
                reason, asset_evidence = "DRS_DISABLED_NOT_APPLICABLE", {"drs_enabled": False}
        before = row.get("result_status")
        if not reason or before == "not_applicable" or before not in _RESULT_STATUSES:
            continue
        change = {"source_index": position, "result_id": row.get("result_id"), "run_id": run_id,
                  "vcenter_id": identity[0], "object_type": identity[1], "object_key": identity[2],
                  "rule_id": rule_id, "before_status": before, "after_status": "not_applicable",
                  "reason_code": reason, "asset_evidence": asset_evidence}
        row["result_status"] = "not_applicable"
        row["approved_projection"] = {"version": APPROVED_PROJECTION_VERSION,
                                      "original_result_preserved": True, **deepcopy(change)}
        changes.append(change)

    # Recount captured rules from the same projected records; never load today's YAML.
    counts_by_rule: dict[str, Counter] = {}
    first_by_rule = {}
    for row in records:
        rule_id = str(row.get("rule_id") or "")
        if not rule_id:
            continue
        first_by_rule.setdefault(rule_id, row)
        if row.get("result_status") in _RESULT_STATUSES:
            counts_by_rule.setdefault(rule_id, Counter())[row["result_status"]] += 1
    checklist = deepcopy(source_checklist)
    existing_ids = {str(item.get("rule_id") or "") for item in checklist}
    for rule_id, first in first_by_rule.items():
        if rule_id not in existing_ids:
            entry = {"rule_id": rule_id, "rule_name": first.get("rule_name") or first.get("title") or rule_id}
            snapshot = first.get("rule_snapshot") or (first.get("evidence") or {}).get("rule_snapshot")
            if snapshot:
                entry["rule_snapshot"] = deepcopy(snapshot)
            checklist.append(entry)
    if source_records is not None:
        for item in checklist:
            counts = counts_by_rule.get(str(item.get("rule_id") or ""), Counter())
            for status in _RESULT_STATUSES:
                item[status] = counts[status]

    def summary(rows):
        all_counts = Counter(row.get("result_status") for row in rows)
        customer = Counter(row.get("result_status") for row in rows
                           if row.get("rule_id") not in DENIED_RULES and rule_grade(row) in LEVELS)
        return {"all": {key: all_counts[key] for key in _RESULT_STATUSES},
                "customer_p1_p3": {key: customer[key] for key in _RESULT_STATUSES}}

    fingerprint = _projection_digest({"version": APPROVED_PROJECTION_VERSION, "run_id": run_id,
                                      "object_results": originals, "findings": findings,
                                      "checklist": source_checklist, "asset_identity": identity_inputs})
    return {"version": APPROVED_PROJECTION_VERSION,
            "source": {"run_id": run_id, "vcenter_ids": sorted(vcenter_ids),
                       "vcenter_instance_uuids": sorted(vc_by_uuid), "fingerprint": fingerprint,
                       "records_available": bool(source_records)},
            "object_results": records, "rule_checklist": checklist, "changes": changes,
            "summary": {"before": summary(originals), "after": summary(records)}, "limitations": limitations}


@lru_cache(maxsize=1)
def yaml_rules() -> dict[str, dict[str, Any]]:
    return {r["rule_id"]: r for r in RulePackLoader().load_raw(bundled_builtin_rulepack_path())}


def object_key(item: dict[str, Any]) -> tuple[str, str]:
    evidence = item.get("evidence") or {}
    key = item.get("object_key") or evidence.get("object_key") or item.get("object_path") or item.get("object_name")
    return str(item.get("object_type") or ""), str(key or "unknown-object")


def rule_grade(item: dict[str, Any]) -> str:
    source = str(item.get("grade_source_rule_id") or item.get("rule_id") or "")
    level = str(item.get("risk_level") or "")
    if level in (*LEVELS, "P4"):
        return level
    rule = recorded_rule(item)
    if not rule:
        return ""
    policy = rule.get("severity_policy") or {}
    if source in INTERNAL_BRIDGE_RULES and item.get("rule_id") != source:
        from vstacklens.reports.category_mapping import RULE_TO_CATEGORY
        category_id = item.get("category_id") or RULE_TO_CATEGORY.get(str(item.get("rule_id")))
        return str((policy.get("derived_category_levels") or {}).get(category_id) or "")
    if policy.get("type") == "fixed":
        return str(policy.get("default_level") or rule.get("risk_level") or "")
    # This is the actual result of the YAML threshold policy, not category metadata.
    level = str(item.get("risk_level") or "")
    return level if level in (*LEVELS, "P4") else str(policy.get("default_level") or rule.get("risk_level") or "")


def reportable_result(item: dict[str, Any]) -> bool:
    from vstacklens.reports.category_mapping import RULE_TO_CATEGORY
    rule_id = str(item.get("rule_id") or "")
    return rule_id not in DENIED_RULES and rule_id in RULE_TO_CATEGORY and rule_grade(item) in LEVELS


def evaluate_revised(item: dict[str, Any], properties: dict[str, Any], *, reinterpret: bool = False, rules: dict | None = None) -> dict[str, Any]:
    item = deepcopy(item)
    item["judgment_provenance"] = judgment_provenance(item)
    if not reinterpret:
        item["caliber_evidence_incomplete"] = item["judgment_provenance"]["mode"] == "ORIGINAL_WITH_LIMITS"
        if item.get("rule_id") == "VSL-DS-001":
            import math
            value = item.get("current_value", (item.get("evidence") or {}).get("current_value"))
            if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
                item["caliber_evidence_incomplete"] = True
                item["judgment_provenance"]["limitation"] = "当次容量数值缺失或无效；保留原始结果，无法复核判断。"
        return item
    original = deepcopy(item)
    rule = (rules if rules is not None else yaml_rules()).get(str(item.get("rule_id")))
    item["judgment_provenance"] = {"mode": "EXPLICIT_REINTERPRETATION", "original_result_preserved": False,
                                   "source": "明确指定的新规则", "limitation": "按新规则重新判断，不能替代原始历史结论。",
                                   "original_result": original, "used_rule": deepcopy(rule)}
    status = item.get("result_status", "failed")
    if rule is None or (rule.get("condition") or {}).get("type") == "plugin" or status not in {"passed", "failed"}:
        item["caliber_evidence_incomplete"] = True
        item["judgment_provenance"]["limitation"] += " 本条规则没有执行重新判断。"
        return item
    evidence = item.get("evidence") or {}
    path = (rule.get("evidence_schema") or {}).get("current_value_path", "")
    value = item.get("current_value", evidence.get("current_value"))
    context = {**properties, **(evidence.get("parameters") or {})}
    for name, definition in (rule.get("parameters") or {}).items():
        context[name] = definition.get("default")
    item["rule_snapshot"] = capture_rule(rule, {name: context[name] for name in (rule.get("parameters") or {})})
    if path and value is not None:
        if isinstance(value, str):
            import json
            try:
                value = json.loads(value)
            except (ValueError, TypeError):
                pass
        context[path] = value
    import math
    valid_value = context.get(path) is not None and (not isinstance(context[path], (int, float)) or math.isfinite(context[path]))
    if path not in context or not valid_value:
        item["caliber_evidence_incomplete"] = True
        return item
    expression = SafeExpressionEngine()
    try:
        failed = expression.evaluate(str(rule["condition"]["fail_when"]), context)
        passed = expression.evaluate(str(rule["condition"]["pass_when"]), context)
        if not failed and not passed:
            item["caliber_evidence_incomplete"] = True
            return item
        item["result_status"] = "failed" if failed else "passed"
        policy = rule["severity_policy"]
        level = str(policy["default_level"])
        if failed and policy.get("type") == "threshold":
            for threshold in policy.get("rules", []):
                if expression.evaluate(str(threshold["when"]), context):
                    level = str(threshold["level"])
                    break
        item["risk_level"] = level if failed else None
        item["current_value"] = context[path]
        item["expected_value"] = rule["evidence_schema"].get("expected_value")
        item["health_impact"] = rule.get("health_impact", "none")
        if failed:
            item["title"] = rule["report_fields"].get("finding_title_zh", item.get("title", ""))
    except (ValueError, TypeError, KeyError):
        item["caliber_evidence_incomplete"] = True
    return item


def calculate(
    findings: list[dict[str, Any]], *, records: list[dict[str, Any]] | None = None,
    assets: dict[str, list[dict[str, Any]]] | None = None, status_summary: dict[str, int] | None = None,
    asset_total: int = 0, critical_gap_count: int | None = None, run_id: str = "",
    reinterpret: bool = False, rules: dict | None = None,
) -> dict[str, Any]:
    from vstacklens.reports.category_mapping import map_findings_to_categories
    from vstacklens.reports.health_status import assess_health
    lookup = {object_key(row): row.get("properties", {}) for rows in (assets or {}).values() for row in rows}
    originals = {(str(x.get("rule_id")), object_key(x)): x for x in findings}
    source = records if records is not None else findings
    evaluated = []
    result_rows = []
    incomplete = False
    for original in source:
        merged = {**original, **originals.get((str(original.get("rule_id")), object_key(original)), {})}
        if original.get("result_status"):
            merged["result_status"] = original["result_status"]
        merged = evaluate_revised(merged, lookup.get(object_key(merged), {}), reinterpret=reinterpret, rules=rules)
        result_rows.append(merged)
        incomplete = incomplete or bool(merged.get("caliber_evidence_incomplete"))
        if merged.get("result_status", "failed") == "failed" and not merged.get("approved_exception"):
            evaluated.append(merged)
    # Derived vSAN facts remain tied to the YAML bridge rule, never to a category priority.
    for item in findings:
        if item.get("grade_source_rule_id") and not any(x.get("rule_id") == item.get("rule_id") and object_key(x) == object_key(item) for x in evaluated):
            evaluated.append(item)
    mapping = map_findings_to_categories(evaluated)
    impacts = Counter(str(x.get("health_impact") or "none") for x in evaluated if x.get("rule_id") not in INTERNAL_BRIDGE_RULES)
    statuses = dict(status_summary or Counter(str(x.get("result_status", "failed")) for x in source))
    if records is not None:
        statuses = dict(Counter(str(x.get("result_status", "failed")) for x in result_rows))
    health = assess_health(mapping.risk_category_summary, statuses, asset_total, critical_gap_count, dict(impacts))
    excluded = mapping.hidden_findings
    if any(x.get("non_report_reason") == "待映射" for x in excluded):
        health["assessment_limited"] = True
        if health["label"] == "健康":
            health["label"] = "评估受限"
        health["explanation"] = "结论仅针对实际完成判断的检查范围。" + health["explanation"]
    reasons = {name: sum(x.get("non_report_reason") == name for x in excluded) for name in ("P4", "已定不报", "待映射")}
    keys = {object_key(x) for x in mapping.findings}
    complete = not incomplete
    if not complete:
        health = {"label": "旧口径", "assessment_limited": True, "explanation": "缺少当次完整规则或阈值证据；保留原结果，未按当前规则重新判断。"}
    if reinterpret:
        health = {**health, "explanation": "按新规则重新判断，不能替代原始历史结论。" + health["explanation"]}
    return {
        "version": VERSION, "run_id": run_id, "state": "complete" if complete else "legacy",
        "counts": mapping.risk_category_summary, "problem_count": sum(mapping.risk_category_summary.get(k, 0) for k in LEVELS),
        "affected_counts": mapping.affected_object_summary, "affected_total": len(keys),
        "health": health, "categories": mapping.categories, "findings": mapping.findings,
        "non_reported": excluded, "non_report_counts": reasons, "non_report_total": len(excluded),
        "internal_bridges": mapping.internal_bridge_findings,
        "object_results": result_rows, "result_status_summary": statuses,
        "judgment_provenance": {"mode": "EXPLICIT_REINTERPRETATION" if reinterpret else "RECORDED_RESULT" if complete else "ORIGINAL_WITH_LIMITS",
                                "limitation": "按新规则重新判断，不能替代原始历史结论。" if reinterpret else "" if complete else health["explanation"]},
    }


def public_summary(caliber: dict[str, Any]) -> dict[str, Any]:
    summary = {key: deepcopy(caliber.get(key)) for key in ("version", "run_id", "state", "counts", "problem_count", "affected_counts", "affected_total", "health", "judgment_provenance", "result_status_summary")}
    summary["counts"] = {level: int((caliber.get("counts") or {}).get(level, 0)) for level in LEVELS}
    return summary


def ensure_report(report, context: dict[str, Any] | None = None) -> dict[str, Any]:
    cached = getattr(report, "customer_caliber", {})
    projection = approved_result_projection(report, context)
    cached_projection = cached.get("approved_projection") or {}
    has_projection = bool(projection["changes"])
    projection_matches = (
        cached_projection.get("version") == APPROVED_PROJECTION_VERSION
        and (cached_projection.get("source") or {}).get("fingerprint") == projection["source"]["fingerprint"]
    )
    private_cache = getattr(report, "_customer_caliber_cache", None)
    # Runtime identity belongs to a private cache, not to the accepted saved
    # conclusion. An unchanged first read may authenticate its captured rows.
    source_matches = (
        bool(projection["source"]["run_id"])
        and cached.get("run_id") == projection["source"]["run_id"]
        and private_cache is not None
        and private_cache.get("caliber") is cached
        and private_cache.get("source") == projection["source"]
    )
    if (private_cache is None and projection["source"]["run_id"] and cached.get("version") == VERSION
            and cached.get("run_id") == projection["source"]["run_id"]):
        if ((has_projection and projection_matches)
                or (not has_projection and not cached_projection and _saved_caliber_matches_source(report, cached, context))):
            source_matches = True
    explicit_reinterpretation = (cached.get("judgment_provenance") or {}).get("mode") == "EXPLICIT_REINTERPRETATION"
    if cached.get("version") == VERSION and source_matches and (
        explicit_reinterpretation or (has_projection and projection_matches)
        or (not has_projection and not cached_projection)
    ):
        caliber = cached
    else:
        _, findings, _ = _projection_inputs(report, context)
        caliber = calculate(
            findings,
            records=projection["object_results"] if projection["source"]["records_available"] else None,
            assets=report.asset_inventory.get("details", {}),
            status_summary=report.environment_summary.result_status_summary,
            asset_total=int(report.asset_inventory.get("total", 0)),
            critical_gap_count=report.appendix.get("critical_gap_count"), run_id=report.report_info.run_id,
        )
        if has_projection:
            caliber["approved_projection"] = {
                key: deepcopy(projection[key]) for key in ("version", "source", "changes", "summary", "limitations")
            }
            caliber["approved_projection"]["original_result_preserved"] = True
            caliber["approved_projection"]["original_caliber_fingerprint"] = (
                cached_projection.get("original_caliber_fingerprint") or _projection_digest(cached)
            )
            provenance = caliber["judgment_provenance"]
            caliber["judgment_provenance"] = {
                **provenance, "source_mode": provenance["mode"], "mode": "APPROVED_APPLICABILITY_PROJECTION",
                "original_result_preserved": True, "projection_version": APPROVED_PROJECTION_VERSION,
            }
    _remember_caliber(report, caliber, projection["source"])
    report.customer_caliber = caliber
    report.problem_categories = caliber["categories"]
    report.report_presentation["problem_categories"] = caliber["categories"]
    report.report_presentation["overall_status"] = caliber["health"]["label"]
    report.overall_status = caliber["health"]["label"]
    for key in LEVELS:
        setattr(report.risk_summary, key, caliber["counts"][key])
    report.risk_summary.P4 = 0
    report.risk_summary.total = caliber["problem_count"]
    report.risk_summary.affected_objects = caliber["affected_counts"]
    report.risk_category_summary = caliber["counts"]
    report.risk_object_summary = caliber["affected_counts"]
    report.affected_object_summary = caliber["affected_counts"]
    report.risk_distribution = {"by_object_type": dict(Counter(x["object_type"] for x in caliber["findings"])), "by_rule": dict(Counter(x["rule_id"] for x in caliber["findings"]))}
    report.health_score.label = caliber["health"]["label"]
    report.health_score.grade = caliber["health"]["label"]
    report.health_score.assessment_limited = caliber["health"]["assessment_limited"]
    report.health_score.explanation = caliber["health"]["explanation"]
    return caliber


def category_findings(report) -> list[dict[str, Any]]:
    return projected_findings(ensure_report(report))


def reinterpret_report(report, *, rules: dict | None = None):
    """Explicit offline projection on a copy; never replace the saved original."""
    revised = report.model_copy(deep=True)
    inputs = revised.caliber_inputs
    revised.customer_caliber = calculate(inputs.get("findings") or [item.model_dump() for item in revised.findings],
        records=inputs.get("object_results"), assets=revised.asset_inventory.get("details", {}),
        status_summary=revised.environment_summary.result_status_summary,
        asset_total=int(revised.asset_inventory.get("total", 0)), run_id=revised.report_info.run_id,
        reinterpret=True, rules=rules)
    # This explicit path already produced its separate caliber. Authenticate the
    # source before ensure_report attaches it; do not silently undo that action.
    _remember_caliber(revised, revised.customer_caliber, approved_result_projection(revised)["source"])
    ensure_report(revised)
    return revised


def projected_findings(caliber: dict[str, Any]) -> list[dict[str, Any]]:
    output = []
    for group in caliber["categories"]:
        sources = [x for x in caliber["findings"] if x["category_id"] == group["category_id"]]
        for obj in group["affected_objects"]:
            matches = [x for x in sources if object_key(x) == (obj["object_type"], obj["object_key"])]
            if not matches:
                continue
            item = deepcopy(min(matches, key=lambda x: LEVELS.index(x["risk_level"])))
            combined = {}
            for source in reversed(matches):
                detail = source.get("observed_detail") or (source.get("evidence") or {}).get("observed_detail") or {}
                for key, value in detail.items():
                    if isinstance(value, list) and isinstance(combined.get(key), list):
                        combined[key] += [x for x in value if x not in combined[key]]
                    else:
                        combined[key] = deepcopy(value)
            item["observed_detail"] = combined
            item.update(title=group["title"], risk_level=obj["risk_level"], category_priority=group["priority"], source_rule_ids=sorted({x["rule_id"] for x in matches}), source_details=matches)
            output.append(item)
    return output
