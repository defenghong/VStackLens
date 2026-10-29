from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from vstacklens.application.cloud_log_diagnosis import (
    MODEL_PROTOCOL,
    CloudModelClient,
    CloudModelConfig,
    sanitize_cloud_error,
)
from vstacklens.application.paths import default_config_path
from vstacklens.deep.analyzer import DeepAnalysisResult
from vstacklens.deep.contracts import DeepDataset, DeepFinding, EvidenceReference


_SECRET_KEY = re.compile(r"(?i)(password|passwd|pwd|api[_-]?key|authorization|bearer|token|secret|cookie|credential|username|user_name)")
_SECRET_ASSIGNMENT = re.compile(
    r'''(?i)\b(password|passwd|pwd|api[_-]?key|authorization|token|secret|cookie|credential|username|user_name)\b\s*[:=]\s*(?:"(?P<double>[^"]*)"|'(?P<single>[^']*)'|(?P<bare>[^\s,;]+))'''
)
_BEARER = re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]+")
_POSITIVE_HEALTH_CLAIM = re.compile(r"(?i)(?<!未)(?<!并未)(?<!不能)(?<!无法)(?<!尚未)(已修复|已解决|恢复正常|检查通过|没有问题|无风险|正常运行|健康)")
_OBJECT_TOKEN = re.compile(r"(?i)\b(?:vmnic|vmk)\d+\b|\b(?:esx|host|vm)[-_]?[a-z0-9][a-z0-9._-]*\b")


def load_configured_model(
    *,
    enabled: bool,
    profile_id: str | None = None,
    config_path: Path | None = None,
) -> tuple[CloudModelConfig | None, str]:
    """Read the existing desktop model profile without creating or modifying app files."""

    if not enabled:
        return None, "not_enabled"
    path = Path(config_path or default_config_path())
    if not path.is_file():
        return None, "not_configured"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, "configuration_unavailable"
    if not isinstance(payload, dict):
        return None, "configuration_unavailable"
    if str(payload.get("security_privacy_level") or "").strip().lower().replace("_", "-") == "local-only":
        return None, "blocked_by_local_only_policy"

    profiles = payload.get("model_config_profiles")
    if not isinstance(profiles, list):
        return None, "not_configured"
    usable_profiles = [item for item in profiles if isinstance(item, dict)]
    selected: dict[str, Any] | None = None
    if profile_id:
        selected = next((item for item in usable_profiles if str(item.get("profile_id") or "") == profile_id), None)
        if selected is None:
            return None, "profile_not_found"
    else:
        selected = next((item for item in usable_profiles if bool(item.get("is_default"))), None)
        if selected is None and len(usable_profiles) == 1:
            selected = usable_profiles[0]
    if selected is None:
        return None, "not_configured"

    api_url = str(selected.get("api_url") or "").strip()
    api_key = str(selected.get("api_key") or "").strip()
    model_name = str(selected.get("default_model") or "").strip()
    if not api_url or not api_key or not model_name:
        return None, "profile_incomplete"
    return (
        CloudModelConfig(
            provider=str(selected.get("provider") or "").strip(),
            api_url=api_url,
            model_name=model_name,
            api_key=api_key,
            timeout_seconds=int(selected.get("timeout_seconds") or 60),
        ),
        "ready",
    )


class DeepModelAssistant:
    """Optional, evidence-scoped interpretation for rule findings.

    The model may add explanations and read-only follow-up ideas. It cannot change
    deterministic rule status or turn missing evidence into a pass.
    """

    MAX_FINDINGS = 32
    MAX_EVIDENCE_PER_FINDING = 12
    MAX_LOG_EXCERPTS_PER_RECORD = 8
    MAX_EXCERPT_CHARS = 1200

    def analyze(
        self,
        dataset: DeepDataset,
        analysis: DeepAnalysisResult,
        *,
        enabled: bool,
        config: CloudModelConfig | None,
        unavailable_reason: str = "not_configured",
    ) -> dict[str, Any]:
        if not enabled:
            return self._empty_result("not_enabled", "未启用，未向模型服务发送数据。")
        if config is None:
            labels = {
                "blocked_by_local_only_policy": "仅本地隐私策略阻止了模型调用。",
                "profile_incomplete": "选定的模型配置不完整，未发起调用。",
                "profile_not_found": "指定的模型配置不存在，未发起调用。",
                "configuration_unavailable": "无法读取本地模型配置，未发起调用。",
                "not_configured": "未配置模型服务，未发起调用。",
            }
            return self._empty_result(unavailable_reason, labels.get(unavailable_reason, "模型配置不可用，未发起调用。"))

        findings = [item for item in analysis.findings if item.report_visible]
        if not findings:
            return self._empty_result("no_candidate_findings", "本次没有可供模型解释的已形成发现，未发起调用。")

        findings = findings[: self.MAX_FINDINGS]
        records_by_pointer = {record.raw_pointer: record for record in dataset.records if record.raw_pointer}
        client = CloudModelClient(config)
        items: list[dict[str, Any]] = []
        for finding in findings:
            evidence = finding.evidence[: self.MAX_EVIDENCE_PER_FINDING]
            if not evidence:
                items.append(self._item_base(finding, "skipped_no_evidence", []))
                continue
            evidence_payload, alias_to_ref = self._evidence_payload(evidence, records_by_pointer)
            prompt = self._prompt(dataset, finding, evidence_payload)
            result = client.complete_json(prompt)
            if not result.ok or not isinstance(result.content, dict):
                items.append(
                    {
                        **self._item_base(finding, "failed", list(alias_to_ref.values())),
                        "failure_reason": sanitize_cloud_error(result.fallback_reason, config.api_key),
                        "response_received": bool(result.response_received),
                        "elapsed_ms": int(result.elapsed_ms),
                    }
                )
                continue

            validated, reason = self._validate_response(result.content, alias_to_ref, evidence_payload)
            if validated is None:
                items.append(
                    {
                        **self._item_base(finding, "rejected", list(alias_to_ref.values())),
                        "validation_reason": reason,
                        "response_received": bool(result.response_received),
                        "elapsed_ms": int(result.elapsed_ms),
                    }
                )
                continue
            items.append(
                {
                    **self._item_base(finding, "accepted", list(alias_to_ref.values())),
                    "analysis": validated,
                    "response_received": bool(result.response_received),
                    "elapsed_ms": int(result.elapsed_ms),
                }
            )

        accepted = sum(item["status"] == "accepted" for item in items)
        attempted = sum(item["status"] in {"accepted", "rejected", "failed"} for item in items)
        status = "succeeded" if accepted == len(items) else "partial" if accepted else "failed"
        return {
            "status": status,
            "enabled": True,
            "api_call_attempted": attempted > 0,
            "provider": config.provider,
            "model_name": config.model_name,
            "model_protocol": MODEL_PROTOCOL,
            "request_count": attempted,
            "accepted_count": accepted,
            "rejected_count": sum(item["status"] == "rejected" for item in items),
            "failed_count": sum(item["status"] == "failed" for item in items),
            "skipped_count": sum(item["status"].startswith("skipped") for item in items),
            "omitted_finding_count": max(0, len(analysis.findings) - self.MAX_FINDINGS),
            "items": items,
            "status_boundary": "模型输出只补充解释，不改变规则状态；引用仅在其属于本次提供证据时接受。",
        }

    @staticmethod
    def _empty_result(status: str, reason: str) -> dict[str, Any]:
        return {
            "status": status,
            "enabled": status != "not_enabled",
            "api_call_attempted": False,
            "request_count": 0,
            "accepted_count": 0,
            "rejected_count": 0,
            "failed_count": 0,
            "skipped_count": 0,
            "items": [],
            "reason": reason,
            "status_boundary": "模型输出不会改变规则状态；未调用模型不代表检查通过。",
        }

    @staticmethod
    def _item_base(finding: DeepFinding, status: str, evidence_refs: list[str]) -> dict[str, Any]:
        lifecycle_status = str(finding.lifecycle.get("status") or "").upper()
        lifecycle_verification = str(finding.lifecycle.get("verification_status") or "").upper()
        if lifecycle_status == "RESOLVED" and lifecycle_verification == "CONFIRMED_RESOLVED":
            evidence_state = "CONFIRMED_RESOLVED"
        elif lifecycle_verification == "UNVERIFIED":
            evidence_state = "RISK_CLUE_UNVERIFIED"
        elif finding.category.value == "current_risk":
            evidence_state = "CURRENT_AT_COLLECTION"
        else:
            evidence_state = "RISK_CLUE_UNVERIFIED"
        return {
            "finding_id": finding.finding_id,
            "rule_id": finding.rule_id,
            "title": finding.title,
            "category": finding.category.value,
            "status": status,
            "evidence_refs": evidence_refs,
            "evidence_state": evidence_state,
            "deterministic_state": (
                "采集时风险发现"
                if evidence_state == "CURRENT_AT_COLLECTION"
                else "已确认解决"
                if evidence_state == "CONFIRMED_RESOLVED"
                else "历史风险线索，尚未确认解决"
            ),
        }

    def _evidence_payload(
        self,
        evidence: list[EvidenceReference],
        records_by_pointer: dict[str, Any],
    ) -> tuple[list[dict[str, Any]], dict[str, str]]:
        items: list[dict[str, Any]] = []
        alias_to_ref: dict[str, str] = {}
        for index, item in enumerate(evidence, start=1):
            alias = f"E{index:02d}"
            alias_to_ref[alias] = item.ref
            record = records_by_pointer.get(item.raw_pointer)
            payload: dict[str, Any] = {
                "id": alias,
                "reference": item.ref,
                "kind": item.kind,
                "source_api": item.source.api,
                "source_collector": item.source.collector,
                "object": {
                    "type": item.entity.type,
                    "stable_id": item.entity.stable_id,
                    "display_ref": item.entity.display_ref,
                },
                "selector": _safe_value(item.selector),
                "time_window_utc": {
                    "start": item.window.start,
                    "end": item.window.end,
                    "sample_count": item.window.sample_count,
                },
                "raw_pointer": item.raw_pointer,
                "summary": _safe_text(item.value_summary.get("summary") or ""),
            }
            if record is not None:
                payload["record"] = _compact_record(record, self.MAX_LOG_EXCERPTS_PER_RECORD, self.MAX_EXCERPT_CHARS)
            else:
                payload["record"] = {
                    "availability": "source_record_not_present",
                    "value_summary": _compact_value_summary(item.value_summary),
                }
            items.append(payload)
        return items, alias_to_ref

    @staticmethod
    def _prompt(dataset: DeepDataset, finding: DeepFinding, evidence: list[dict[str, Any]]) -> str:
        if finding.category.value == "current_risk":
            collection_state = "这是采集时的规则发现；不可据此判断采集之后仍持续，也不可判断已经修复。"
        elif finding.category.value == "historical_health":
            collection_state = "这是历史健康线索；事件本身不能证明采集时仍存在问题。"
        else:
            collection_state = "这是趋势或历史样本线索；不得把样本趋势外推成故障预测。"
        body = {
            "task": "只解释本条确定性规则结果，并提出可核实的只读核查建议。",
            "rules": [
                "只能使用下方本条对象的证据；不得补造对象、时间、日志行、事件Key或因果关系。",
                "supported_interpretation 必须引用至少一个给定证据编号。",
                "possible_causes 中的每项必须使用可能、待核实等不确定措辞并引用证据；无证据的原因不要写。",
                "缺失证据与只读核查建议可以不带引用，但必须标为尚待核查。",
                "不得输出 PASS、已修复、已解决或整体健康结论；规则状态由代码决定。",
                "仅返回 JSON，字段为 supported_interpretation、evidence_refs、possible_causes、impact、missing_evidence、read_only_checks。",
            ],
            "dataset_id": dataset.dataset_id,
            "collected_at_utc": dataset.manifest.created_at_utc,
            "collection_state": collection_state,
            "finding": {
                "finding_id": finding.finding_id,
                "rule_id": finding.rule_id,
                "title": finding.title,
                "category": finding.category.value,
                "scope": finding.scope.model_dump(mode="json"),
                "fact": _safe_text(finding.fact),
                "finding": _safe_text(finding.finding),
                "confidence_class": finding.confidence_class.value,
                "evidence_sufficiency": finding.evidence_sufficiency,
                "diagnosis_boundary": _safe_text(finding.diagnosis_boundary),
            },
            "evidence": evidence,
            "response_shape": {
                "supported_interpretation": "一句至数句、只复述能被引用证据支持的事实",
                "evidence_refs": ["E01"],
                "possible_causes": [{"text": "可能原因，待核实", "evidence_refs": ["E01"], "confidence": "low|medium"}],
                "impact": {"text": "基于证据的可能影响", "evidence_refs": ["E01"]},
                "missing_evidence": ["仍缺少的证据"],
                "read_only_checks": ["具体只读核查方法"],
            },
        }
        return json.dumps(body, ensure_ascii=False, separators=(",", ":"))

    @staticmethod
    def _validate_response(
        raw: dict[str, Any],
        alias_to_ref: dict[str, str],
        evidence_payload: list[dict[str, Any]],
    ) -> tuple[dict[str, Any] | None, str]:
        allowed_fields = {
            "supported_interpretation",
            "evidence_refs",
            "possible_causes",
            "impact",
            "missing_evidence",
            "read_only_checks",
        }
        if set(raw) - allowed_fields:
            return None, "模型返回了未允许字段，拒绝作为分析结论。"
        context = json.dumps(evidence_payload, ensure_ascii=False)

        def refs(value: Any, *, required: bool) -> list[str] | None:
            if not isinstance(value, list) or (required and not value):
                return None
            result: list[str] = []
            for item in value:
                alias = str(item or "").strip()
                if alias not in alias_to_ref:
                    return None
                result.append(alias_to_ref[alias])
            return result

        interpretation = _safe_text(raw.get("supported_interpretation"))
        base_refs = refs(raw.get("evidence_refs"), required=True)
        if not interpretation or base_refs is None:
            return None, "核心判断缺少可校验的证据引用。"
        if _POSITIVE_HEALTH_CLAIM.search(interpretation):
            return None, "模型输出了不允许的修复或健康结论。"
        if _mentions_unprovided_object(interpretation, context):
            return None, "核心判断提到了本次材料中不存在的设备对象。"

        causes: list[dict[str, Any]] = []
        raw_causes = raw.get("possible_causes", [])
        if not isinstance(raw_causes, list):
            return None, "possible_causes 格式无效。"
        for cause in raw_causes:
            if not isinstance(cause, dict) or set(cause) - {"text", "evidence_refs", "confidence"}:
                return None, "possible_causes 包含无效字段。"
            text = _safe_text(cause.get("text"))
            cause_refs = refs(cause.get("evidence_refs"), required=True)
            if not text or cause_refs is None or not re.search(r"可能|待核实|推测|不排除|不能确认|无法确认|尚需", text):
                return None, "可能原因没有不确定措辞或有效证据引用。"
            if _POSITIVE_HEALTH_CLAIM.search(text) or _mentions_unprovided_object(text, context):
                return None, "可能原因包含未支持的健康结论或对象。"
            confidence = str(cause.get("confidence") or "low").strip().lower()
            if confidence not in {"low", "medium"}:
                return None, "可能原因置信度字段无效。"
            causes.append({"text": text, "evidence_refs": cause_refs, "confidence": confidence})

        impact: dict[str, Any] | None = None
        raw_impact = raw.get("impact")
        if raw_impact:
            if not isinstance(raw_impact, dict) or set(raw_impact) - {"text", "evidence_refs"}:
                return None, "impact 格式无效。"
            impact_text = _safe_text(raw_impact.get("text"))
            impact_refs = refs(raw_impact.get("evidence_refs"), required=bool(impact_text))
            if impact_text and (impact_refs is None or _mentions_unprovided_object(impact_text, context)):
                return None, "影响判断缺少有效证据引用或提到了未知对象。"
            if impact_text:
                impact = {"text": impact_text, "evidence_refs": impact_refs}

        def string_list(name: str) -> list[str] | None:
            value = raw.get(name, [])
            if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                return None
            return [_safe_text(item) for item in value if _safe_text(item)]

        missing = string_list("missing_evidence")
        checks = string_list("read_only_checks")
        if missing is None or checks is None:
            return None, "缺少证据或只读核查建议字段格式无效。"
        return (
            {
                "supported_interpretation": interpretation,
                "evidence_refs": base_refs,
                "possible_causes": causes,
                "impact": impact,
                "missing_evidence": missing,
                "read_only_checks": checks,
            },
            "",
        )


def _compact_record(record: Any, max_log_excerpts: int, max_excerpt_chars: int) -> dict[str, Any]:
    value = record.value
    result: dict[str, Any] = {
        "record_id": record.record_id,
        "kind": record.kind,
        "source_api": record.source.api,
        "entity": {
            "type": record.entity.type,
            "stable_id": record.entity.stable_id,
            "display_ref": record.entity.display_ref,
        },
        "selector": _safe_value(record.selector),
        "time_window_utc": record.window.model_dump(mode="json"),
        "raw_pointer": record.raw_pointer,
        "summary": _safe_text(record.summary),
        "value_summary": _compact_value_summary(value if isinstance(value, dict) else {"value": value}),
    }
    lines = value.get("lines") if isinstance(value, dict) else None
    if isinstance(lines, list):
        line_numbers = record.metadata.get("source_line_numbers")
        related = record.metadata.get("related_event_samples")
        referenced_numbers = {
            int(item["source_line_number"])
            for item in related or []
            if isinstance(item, dict) and str(item.get("source_line_number") or "").isdigit()
        } if isinstance(related, list) else set()
        candidates: list[int] = []
        for index, line in enumerate(lines):
            source_number = line_numbers[index] if isinstance(line_numbers, list) and index < len(line_numbers) else None
            try:
                source_number_int = int(source_number) if source_number is not None else None
            except (TypeError, ValueError):
                source_number_int = None
            text = str(line or "")
            if (source_number_int is not None and source_number_int in referenced_numbers) or re.search(
                r"(?i)\b(error|warn|failed|failure|down|up|apd|pdl|reset|timeout|lost|recovered|ha|vsan|vmotion)\b",
                text,
            ):
                candidates.append(index)
        if not candidates:
            candidates = list(range(min(3, len(lines))))
        excerpts = []
        for index in candidates[:max_log_excerpts]:
            excerpt = {
                "text": _safe_text(str(lines[index])[:max_excerpt_chars]),
                "raw_pointer": record.raw_pointer,
            }
            if isinstance(line_numbers, list) and index < len(line_numbers) and line_numbers[index] is not None:
                excerpt["source_line_number"] = line_numbers[index]
            excerpts.append(excerpt)
        result["log_excerpts"] = excerpts
        result["log_excerpt_truncated"] = len(candidates) > len(excerpts) or len(lines) > len(excerpts)

    related_samples = record.metadata.get("related_event_samples")
    if isinstance(related_samples, list):
        result["related_event_samples"] = [
            _safe_value(
                {
                    key: sample[key]
                    for key in (
                        "timestamp",
                        "event_type",
                        "event_key",
                        "event_source_api",
                        "entity",
                        "host",
                        "matched_object_id",
                        "matched_object",
                        "message",
                        "dataset_pointer",
                        "log_timestamp",
                        "source_line_number",
                        "time_distance_seconds",
                        "matching_categories",
                        "interfaces",
                        "state",
                        "evidence_level",
                    )
                    if key in sample
                }
            )
            for sample in related_samples[:8]
            if isinstance(sample, dict)
        ]
    return result


def _compact_value_summary(value: Any, depth: int = 0) -> Any:
    if depth > 5:
        return "[深度受限]"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in list(value.items())[:32]:
            if _SECRET_KEY.search(str(key)) or str(key).lower() in {"lines", "raw_lines", "raw_text"}:
                continue
            result[str(key)] = _compact_value_summary(item, depth + 1)
        return result
    if isinstance(value, list):
        return [_compact_value_summary(item, depth + 1) for item in value[:8]]
    if isinstance(value, str):
        return _safe_text(value[:1600])
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _safe_text(str(value)[:1600])


def _safe_value(value: Any) -> Any:
    return _compact_value_summary(value)


def _safe_text(value: Any) -> str:
    text = str(value or "")
    text = _BEARER.sub("Bearer [已隐藏]", text)
    text = _SECRET_ASSIGNMENT.sub(lambda match: f"{match.group(1)}=[已隐藏]", text)
    text = re.sub(r"(?i)(https?://)[^/@\s:]+:[^/@\s]+@", r"\1[已隐藏]@", text)
    return text[:4000]


def _mentions_unprovided_object(text: str, evidence_context: str) -> bool:
    seen = {item.casefold() for item in _OBJECT_TOKEN.findall(text)}
    provided = {item.casefold() for item in _OBJECT_TOKEN.findall(evidence_context)}
    return bool(seen - provided)
