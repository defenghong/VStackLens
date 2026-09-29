from __future__ import annotations

from typing import Any

from vstacklens.core.context import RunContext
from vstacklens.core.enums import DataQuality, RuleResultStatus
from vstacklens.core.ids import new_id
from vstacklens.core.time import utc_now_iso
from vstacklens.findings.evidence_builder import EvidenceBuilder
from vstacklens.inventory.canonical_models import CanonicalInventory, CanonicalObject
from vstacklens.rules.safe_expression import SafeExpressionEngine
from vstacklens.rules.schema import RuleDefinition
from vstacklens.rules.data_quality_gate import DataQualityGate
from vstacklens.rules.parameters import RuleParameterResolver
from vstacklens.rules.plugins import HclCompatibilityPlugin, PluginRegistry, ServerCompatibilityPlugin, VsanCompatibilityPlugin
from vstacklens.rules.severity_policy import SeverityPolicyEngine


class RuleExecutor:
    def __init__(self, *, hcl_store: Any | None = None, plugin_registry: PluginRegistry | None = None) -> None:
        self.expression = SafeExpressionEngine()
        self.severity = SeverityPolicyEngine()
        self.evidence = EvidenceBuilder()
        self.data_quality = DataQualityGate()
        self.parameters = RuleParameterResolver()
        self.plugins = plugin_registry or PluginRegistry()
        if plugin_registry is None:
            self.plugins.register(HclCompatibilityPlugin.name, HclCompatibilityPlugin(hcl_store))
            self.plugins.register(VsanCompatibilityPlugin.name, VsanCompatibilityPlugin(hcl_store))
            self.plugins.register(ServerCompatibilityPlugin.name, ServerCompatibilityPlugin(hcl_store))

    def execute(self, run: RunContext, inventory: CanonicalInventory, rules: list[RuleDefinition]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for rule in rules:
            for target in inventory.by_type(rule.object_type):
                results.append(self._execute_one(run, rule, target))
        return results

    def _execute_one(self, run: RunContext, rule: RuleDefinition, target: CanonicalObject) -> dict[str, Any]:
        now = utc_now_iso()
        parameters = self.parameters.resolve(rule)
        ctx = dict(target.properties)
        ctx.update(parameters)
        ctx["object"] = target.properties
        try:
            data_quality = self.data_quality.evaluate(rule, target)
            if self._not_applicable(rule, target, ctx):
                status = RuleResultStatus.NOT_APPLICABLE
                risk_level = None
                data_quality = DataQuality.COMPLETE
            elif data_quality in {DataQuality.MISSING, DataQuality.PERMISSION_DENIED, DataQuality.API_ERROR, DataQuality.UNSUPPORTED_VERSION}:
                status = RuleResultStatus.UNAVAILABLE
                risk_level = None
            elif rule.condition.type == "plugin":
                plugin = self.plugins.get(rule.condition.plugin_name)
                if plugin is None:
                    status = RuleResultStatus.ERROR
                    risk_level = None
                    current_value = None
                    expected_value = None
                    evidence = self.evidence.build(run, rule, target, current_value, expected_value, data_quality, parameters)
                    error_message = f"Unknown condition plugin: {rule.condition.plugin_name or '<missing>'}"
                    return self._result(run, rule, target, status, risk_level, current_value, expected_value, evidence, error_message, now)
                plugin_result = plugin.execute(rule, target, parameters, self.severity.resolve)
                status = plugin_result["result_status"]
                risk_level = plugin_result["risk_level"]
                data_quality = plugin_result["data_quality"]
                current_value = plugin_result["observed_value"]
                expected_value = plugin_result["expected_value"]
                evidence = self.evidence.build(run, rule, target, current_value, expected_value, data_quality, parameters)
                evidence.update(plugin_result["evidence"])
                error_message = plugin_result["error_message"]
                return self._result(run, rule, target, status, risk_level, current_value, expected_value, evidence, error_message, now)
            elif rule.condition.unavailable_when and self.expression.evaluate(rule.condition.unavailable_when, ctx):
                status = RuleResultStatus.UNAVAILABLE
                risk_level = None
                data_quality = DataQuality.MISSING
            else:
                failed = bool(rule.condition.fail_when and self.expression.evaluate(rule.condition.fail_when, ctx))
                if failed:
                    status = RuleResultStatus.FAILED
                    risk_level = self.severity.resolve(rule, ctx).value
                elif rule.condition.pass_when and self.expression.evaluate(rule.condition.pass_when, ctx):
                    status = RuleResultStatus.PASSED
                    risk_level = None
                else:
                    status = RuleResultStatus.ERROR
                    risk_level = None
            current_value = self._resolve_current_value(rule, target)
            expected_value = rule.evidence_schema.get("expected_value")
            evidence = self.evidence.build(run, rule, target, current_value, expected_value, data_quality, parameters)
            error_message = "Neither fail_when nor pass_when matched" if status == RuleResultStatus.ERROR else None
        except Exception as exc:  # noqa: BLE001 - M1 stores rule errors as rule_results
            status = RuleResultStatus.ERROR
            risk_level = None
            evidence = {}
            current_value = None
            expected_value = None
            error_message = str(exc)
        return self._result(run, rule, target, status, risk_level, current_value, expected_value, evidence, error_message, now)

    def _result(self, run: RunContext, rule: RuleDefinition, target: CanonicalObject, status: RuleResultStatus, risk_level: str | None, current_value: Any, expected_value: Any, evidence: dict[str, Any], error_message: str | None, now: str) -> dict[str, Any]:
        return {
            "result_id": new_id("rr"),
            "run_id": run.run_id,
            "rule_id": rule.rule_id,
            "customer_id": run.customer_id,
            "vcenter_id": run.vcenter_id,
            "object_type": target.object_type,
            "object_key": target.object_key,
            "object_name": target.object_name,
            "object_path": target.object_path,
            "result_status": status.value,
            "risk_level": risk_level,
            "confidence_level": rule.confidence_level.value,
            "observed_value": str(current_value),
            "expected_value": str(expected_value),
            "evidence": evidence,
            "raw": {},
            "error_message": error_message,
            "evaluated_at": now,
            "created_at": now,
        }

    def _resolve_current_value(self, rule: RuleDefinition, target: CanonicalObject) -> Any:
        path = rule.evidence_schema.get("current_value_path")
        if not path:
            return None
        return target.properties.get(str(path))

    def _not_applicable(self, rule: RuleDefinition, target: CanonicalObject, ctx: dict[str, Any]) -> bool:
        if rule.condition.not_applicable_when and self.expression.evaluate(rule.condition.not_applicable_when, ctx):
            return True
        if rule.object_type != "VirtualMachine":
            return False
        if rule.data_source.source_domain != "performance":
            return False
        return target.properties.get("power_state") != "poweredOn"
