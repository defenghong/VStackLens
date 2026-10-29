"""Read the rule evidence captured with a result, never the mutable rule catalog."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from typing import Any


def capture_rule(definition: dict, parameters: dict) -> dict:
    payload = {"schema_version": "1.0", "definition": deepcopy(definition), "parameters": deepcopy(parameters)}
    return {**payload, "sha256": _digest(payload)}


def _digest(payload) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def snapshot_from(item: dict[str, Any]) -> dict:
    evidence = item.get("evidence") or {}
    snapshot = item.get("rule_snapshot") or evidence.get("rule_snapshot") or {}
    if not isinstance(snapshot, dict) or not snapshot:
        return {}
    payload = {key: value for key, value in snapshot.items() if key != "sha256"}
    definition = snapshot.get("definition") or {}
    source = str(item.get("grade_source_rule_id") or item.get("rule_id") or "")
    if snapshot.get("sha256") != _digest(payload) or definition.get("rule_id") != source or not set(definition.get("parameters") or {}).issubset(snapshot.get("parameters") or {}):
        return {}
    return snapshot


def recorded_rule(item: dict) -> dict:
    return snapshot_from(item).get("definition") or {}


def judgment_provenance(item: dict) -> dict:
    snapshot = snapshot_from(item)
    complete = bool(snapshot)
    return {"mode": "RECORDED_RESULT" if complete else "ORIGINAL_WITH_LIMITS", "original_result_preserved": True,
            "rule_version": (snapshot.get("definition") or {}).get("rule_version") or (item.get("evidence") or {}).get("rule_version"),
            "rule_snapshot_sha256": snapshot.get("sha256"),
            "limitation": "" if complete else "缺少当次完整规则或阈值证据；保留原结果，未按当前规则重新判断。"}
