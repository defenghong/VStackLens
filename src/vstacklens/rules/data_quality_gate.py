from __future__ import annotations

from typing import Any
import math

from vstacklens.core.enums import DataQuality
from vstacklens.inventory.canonical_models import CanonicalObject
from vstacklens.rules.schema import RuleDefinition


class DataQualityGate:
    def evaluate(self, rule: RuleDefinition, target: CanonicalObject) -> DataQuality:
        # Plugins own their input contract and return the precise availability state.
        if rule.condition.type == "plugin":
            return DataQuality.COMPLETE
        if rule.rule_id in {"VSL-VC-006", "VSL-HOST-023"}:
            path = "host_license_expiration_days" if rule.object_type == "HostSystem" else "license_days_remaining"
            value = target.properties.get(path)
            if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value)):
                return DataQuality.MISSING
            from vstacklens.collection.license_state import verified_state
            state = verified_state(target.properties, rule.object_type == "HostSystem", target.object_key)
            raw_state = target.properties.get("host_license_evidence" if rule.object_type == "HostSystem" else "license_evidence") or {}
            if isinstance(raw_state, dict) and raw_state.get("schema") == "entity-license-v1" and raw_state.get("query_status") == "permission_denied":
                return DataQuality.PERMISSION_DENIED
            if not state:
                return DataQuality.MISSING
            if state.get("query_status") == "permission_denied":
                return DataQuality.PERMISSION_DENIED
            if state.get("query_status") in {"query_failed", "read_failed"} or state.get("expiration_state") == "read_failed":
                return DataQuality.API_ERROR
            if state.get("assigned") is not True or state.get("expiration_state") not in {"dated", "perpetual"} or state.get("days_remaining") != value:
                return DataQuality.MISSING
            if rule.object_type == "HostSystem" and (
                target.properties.get("host_license_assigned") != state.get("assigned")
                or target.properties.get("host_license_is_evaluation") != state.get("is_evaluation")
            ):
                return DataQuality.MISSING
            if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 999999:
                from vstacklens.collection.license_state import verified_state
                state = verified_state(target.properties, rule.object_type == "HostSystem", target.object_key)
                permanent = state.get("expiration_state") == "perpetual" and state.get("assigned") is True and bool(state.get("perpetual_evidence"))
                dated = state.get("expiration_state") == "dated" and bool(state.get("expiration_at"))
                if not (permanent or dated):
                    return DataQuality.MISSING
        required_paths = self._required_paths(rule)
        for path in required_paths:
            if path not in target.properties or target.properties.get(path) is None:
                return DataQuality.MISSING
        return DataQuality.COMPLETE

    def _required_paths(self, rule: RuleDefinition) -> set[str]:
        paths: set[str] = set()
        current_path = rule.evidence_schema.get("current_value_path")
        if current_path:
            paths.add(str(current_path))
        for api_path in rule.data_source.api_paths:
            if "." not in api_path and ":" not in api_path:
                paths.add(api_path)
        return paths
