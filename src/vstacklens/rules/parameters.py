from __future__ import annotations

from typing import Any

from vstacklens.rules.schema import RuleDefinition


class RuleParameterResolver:
    def resolve(self, rule: RuleDefinition, overrides: dict[str, Any] | None = None) -> dict[str, Any]:
        result: dict[str, Any] = {}
        overrides = overrides or {}
        for name, spec in rule.parameters.items():
            if not isinstance(spec, dict):
                result[name] = spec
                continue
            default = spec.get("default")
            if spec.get("override_allowed") and name in overrides:
                result[name] = self._coerce(overrides[name], spec.get("type"), default)
            else:
                result[name] = default
        return result

    def _coerce(self, value: Any, expected_type: str | None, default: Any) -> Any:
        if expected_type == "number":
            if isinstance(default, int) and not isinstance(default, bool):
                return int(value)
            return float(value)
        if expected_type == "boolean":
            if isinstance(value, bool):
                return value
            return str(value).strip().lower() in {"1", "true", "yes", "y"}
        if expected_type == "string":
            return str(value)
        return value
