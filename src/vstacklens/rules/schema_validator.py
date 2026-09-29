from __future__ import annotations

import re
from typing import Any

from vstacklens.core.enums import RiskLevel
from vstacklens.rules.schema import RuleDefinition
from vstacklens.rules.safe_expression import SafeExpressionEngine


RULE_ID_RE = re.compile(r"^VSL-[A-Z]+-[0-9]{3}$")


class SchemaValidator:
    def validate_rule(self, raw_rule: dict[str, Any]) -> RuleDefinition:
        rule = RuleDefinition.model_validate(raw_rule)
        if not RULE_ID_RE.match(rule.rule_id):
            raise ValueError(f"Invalid rule_id: {rule.rule_id}")
        if rule.condition.type != "plugin" and not rule.condition.fail_when:
            raise ValueError(f"{rule.rule_id}: condition.fail_when is required")
        if rule.condition.type == "plugin" and not rule.condition.plugin_name:
            raise ValueError(f"{rule.rule_id}: condition.plugin_name is required")
        if rule.condition.type != "plugin" and not rule.condition.pass_when and not self._allows_missing_pass_when(rule):
            raise ValueError(f"{rule.rule_id}: condition.pass_when is required")
        if not rule.report_fields.title_zh.strip():
            raise ValueError(f"{rule.rule_id}: report_fields.title_zh is required")
        if not rule.report_fields.summary_zh.strip():
            raise ValueError(f"{rule.rule_id}: report_fields.summary_zh is required")
        if not rule.report_fields.business_impact_zh.strip():
            raise ValueError(f"{rule.rule_id}: report_fields.business_impact_zh is required")
        if not rule.report_fields.technical_impact_zh.strip():
            raise ValueError(f"{rule.rule_id}: report_fields.technical_impact_zh is required")
        if not rule.report_fields.consequence_zh.strip():
            raise ValueError(f"{rule.rule_id}: report_fields.consequence_zh is required")
        if not rule.report_fields.remediation_zh.strip():
            raise ValueError(f"{rule.rule_id}: report_fields.remediation_zh is required")
        if not rule.remediation.steps_zh:
            raise ValueError(f"{rule.rule_id}: remediation.steps_zh must not be empty")
        if not rule.evidence_schema.get("current_value_path"):
            raise ValueError(f"{rule.rule_id}: evidence_schema.current_value_path is required")
        if not rule.data_source.api_paths and rule.data_source.source_domain not in {"plugin", "connection_precheck"}:
            raise ValueError(f"{rule.rule_id}: data_source.api_paths must not be empty")
        self._validate_severity_policy(rule)
        if rule.data_source.source_domain == "performance":
            sampling = rule.data_source.sampling or {}
            if not sampling.get("required"):
                raise ValueError(f"{rule.rule_id}: performance rule requires sampling.required=true")
        if rule.data_source.foreach:
            for key in ("item_name", "source_path"):
                if key not in rule.data_source.foreach:
                    raise ValueError(f"{rule.rule_id}: foreach.{key} is required")
        return rule

    def _allows_missing_pass_when(self, rule: RuleDefinition) -> bool:
        return bool(getattr(rule.condition, "allow_missing_pass_when", False))

    def _validate_severity_policy(self, rule: RuleDefinition) -> None:
        if rule.severity_policy.type == "fixed":
            if rule.severity_policy.default_level not in RiskLevel:
                raise ValueError(f"{rule.rule_id}: invalid severity_policy.default_level")
            return
        if rule.severity_policy.type == "threshold":
            if not rule.severity_policy.rules:
                raise ValueError(f"{rule.rule_id}: threshold severity_policy.rules must not be empty")
            engine = SafeExpressionEngine()
            for item in rule.severity_policy.rules:
                if "when" not in item or "level" not in item:
                    raise ValueError(f"{rule.rule_id}: severity_policy rule requires when and level")
                if item["level"] not in {level.value for level in RiskLevel}:
                    raise ValueError(f"{rule.rule_id}: invalid severity level {item['level']}")
                try:
                    engine.parse(str(item["when"]))
                except Exception as exc:  # noqa: BLE001 - validator should wrap expression errors
                    raise ValueError(f"{rule.rule_id}: invalid severity expression {item['when']}: {exc}") from exc
