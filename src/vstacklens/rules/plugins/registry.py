from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

from vstacklens.core.enums import RiskLevel
from vstacklens.inventory.canonical_models import CanonicalObject
from vstacklens.rules.schema import RuleDefinition


class RulePlugin(Protocol):
    def execute(
        self,
        rule: RuleDefinition,
        target: CanonicalObject,
        parameters: Mapping[str, Any],
        resolve_risk: Any,
    ) -> dict[str, Any]: ...


class PluginRegistry:
    def __init__(self, plugins: Mapping[str, RulePlugin] | None = None) -> None:
        self._plugins: dict[str, RulePlugin] = dict(plugins or {})

    def register(self, name: str, plugin: RulePlugin) -> None:
        self._plugins[name] = plugin

    def get(self, name: str | None) -> RulePlugin | None:
        if not name:
            return None
        return self._plugins.get(name)
