from __future__ import annotations

import hashlib
import json
from typing import Any

from vstacklens.deep.contracts import DeepDataset, DeepRuleDefinition, ThresholdRegistry
from vstacklens.deep.policies import default_threshold_registry

ANALYZER_REVISION = "vstacklens-deep-analysis/2.0-stage1"


def fingerprint(payload: Any) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def policy_snapshot(rules: tuple[DeepRuleDefinition, ...], thresholds: ThresholdRegistry) -> dict[str, Any]:
    payload = {"schema_version": "1.1", "analyzer_revision": ANALYZER_REVISION, "rules": [rule.model_dump(mode="json") for rule in rules], "thresholds": thresholds.model_dump(mode="json")}
    return {**payload, "fingerprint": fingerprint(payload)}


def choose_policy(
    dataset: DeepDataset,
    rules: tuple[DeepRuleDefinition, ...] | None,
    thresholds: ThresholdRegistry | None,
) -> tuple[tuple[DeepRuleDefinition, ...], ThresholdRegistry, dict[str, Any]]:
    from vstacklens.deep.analyzer import BUILTIN_DEEP_RULES

    stored = dataset.manifest.analysis_policy
    original_available = bool(stored)
    if stored:
        original_payload = {key: value for key, value in stored.items() if key != "fingerprint"}
        if stored.get("fingerprint") != fingerprint(original_payload):
            raise ValueError("Dataset analysis policy integrity check failed")
        original_rules = tuple(DeepRuleDefinition.model_validate(item) for item in stored["rules"])
        original_thresholds = ThresholdRegistry.model_validate(stored["thresholds"])
    else:
        original_rules, original_thresholds = BUILTIN_DEEP_RULES, default_threshold_registry()
    selected_rules = rules if rules is not None else original_rules
    selected_thresholds = thresholds if thresholds is not None else original_thresholds
    used = policy_snapshot(selected_rules, selected_thresholds)
    unchanged = original_available and used["fingerprint"] == stored["fingerprint"]
    mode = "RECORDED_POLICY" if unchanged else "ENGINE_REINTERPRETATION" if original_available and stored.get("analyzer_revision") != ANALYZER_REVISION else "EXPLICIT_REINTERPRETATION" if original_available else "LEGACY_REINTERPRETATION"
    rule_fingerprints = {}
    for rule in selected_rules:
        threshold_ids = {"TH-EVIDENCE-COMPLETENESS-MIN", rule.threshold_id, rule.analysis_window_threshold_id, rule.forecast_threshold_id} - {None}
        policies = [item.model_dump(mode="json") for item in selected_thresholds.policies if item.id in threshold_ids]
        rule_fingerprints[rule.rule_id] = fingerprint({"rule": rule.model_dump(mode="json"), "thresholds": policies})
    return selected_rules, selected_thresholds, {
        "mode": mode,
        "original_policy_available": original_available,
        "resolution_eligible": unchanged,
        "used_policy": used,
        "rule_fingerprints": rule_fingerprints,
        "boundary": "按 Dataset 保存的当次规则和阈值评估。" if unchanged else "本次按明确记录的现行策略重新判断；不替代历史原始结论，也不据此确认旧问题已解决。",
    }
