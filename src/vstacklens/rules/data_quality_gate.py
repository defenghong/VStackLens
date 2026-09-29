from __future__ import annotations

from typing import Any

from vstacklens.core.enums import DataQuality
from vstacklens.inventory.canonical_models import CanonicalObject
from vstacklens.rules.schema import RuleDefinition


class DataQualityGate:
    def evaluate(self, rule: RuleDefinition, target: CanonicalObject) -> DataQuality:
        # Plugins own their input contract and return the precise availability state.
        if rule.condition.type == "plugin":
            return DataQuality.COMPLETE
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
