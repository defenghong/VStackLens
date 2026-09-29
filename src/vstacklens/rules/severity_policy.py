from __future__ import annotations

from vstacklens.core.enums import RiskLevel
from vstacklens.rules.safe_expression import SafeExpressionEngine
from vstacklens.rules.schema import RuleDefinition


class SeverityPolicyEngine:
    def __init__(self) -> None:
        self.expression = SafeExpressionEngine()

    def resolve(self, rule: RuleDefinition, context: dict) -> RiskLevel:
        if rule.severity_policy.type == "threshold":
            for item in rule.severity_policy.rules:
                if self.expression.evaluate(str(item["when"]), context):
                    return RiskLevel(item["level"])
        return rule.severity_policy.default_level
