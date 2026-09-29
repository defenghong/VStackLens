from __future__ import annotations

from collections import defaultdict

from vstacklens.core.enums import RuleExecutionMode, RuleImplementationStatus
from vstacklens.rules.schema import RuleDefinition


class RuleRegistry:
    def __init__(self) -> None:
        self.rules: list[RuleDefinition] = []
        self.executable_rules: list[RuleDefinition] = []
        self.by_object_type: dict[str, list[RuleDefinition]] = defaultdict(list)

    def register(self, rules: list[RuleDefinition]) -> None:
        self.rules = [rule for rule in rules if rule.enabled]
        self.executable_rules = [rule for rule in self.rules if self.is_default_executable(rule)]
        self.by_object_type.clear()
        for rule in self.executable_rules:
            self.by_object_type[rule.object_type].append(rule)

    def is_default_executable(self, rule: RuleDefinition) -> bool:
        return (
            rule.enabled
            and rule.implementation_status == RuleImplementationStatus.IMPLEMENTED
            and rule.execution_mode == RuleExecutionMode.DEFAULT_ENABLED
        )
