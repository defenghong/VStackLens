from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from vstacklens.core.enums import DataQuality, RuleResultStatus
from vstacklens.hcl.store import HclStore
from vstacklens.inventory.canonical_models import CanonicalObject
from vstacklens.rules.schema import RuleDefinition
from vstacklens.upgrade_compat.vsan import VsanContext, evaluate_vsan_compatibility


class VsanCompatibilityPlugin:
    name = "vsan_compatibility"

    def __init__(self, store: HclStore | None) -> None:
        self.store = store

    def execute(self, rule: RuleDefinition, target: CanonicalObject, parameters: Mapping[str, Any], resolve_risk: Any) -> dict[str, Any]:
        if self.store is None:
            return self._outcome("VSAN_CONTEXT_UNKNOWN", "HCL 数据不可用")
        queue_depth_min = parameters.get("queue_depth_min")
        if not isinstance(queue_depth_min, int):
            return self._outcome("VSAN_CONTEXT_UNKNOWN", "规则未提供 queueDepth 阈值")
        props = target.properties
        context = VsanContext(
            vsan_enabled=props.get("vsan_enabled"),
            vsan_architecture=props.get("vsan_architecture"),
            vsan_disk_layout=props.get("vsan_disk_layout"),
            controller_mode=props.get("controller_mode"),
        )
        result = evaluate_vsan_compatibility(
            self.store,
            quadruple=self._quadruple(props),
            model=self._text_or_none(props.get("model")),
            category=str(props.get("category") or ""),
            driver_name=str(props.get("driver_name") or ""),
            driver_version=str(props.get("driver_version") or ""),
            firmware_version=self._text_or_none(props.get("firmware_version")),
            target_release=str(parameters.get("target_release") or ""),
            context=context,
            check_mode=str(parameters.get("vsan_check_mode", "auto")),
            queue_depth_min=queue_depth_min,
        )
        return {
            "result_status": result.rule_status,
            "risk_level": resolve_risk(rule, {**props, **parameters}).value if result.rule_status.value == "failed" else None,
            "data_quality": result.data_quality,
            "evidence": {"vsan_status": result.status, "vsan_detail": result.detail, "queue_depth": result.queue_depth, "vsan_support": [item.raw for item in result.requirements]},
            "observed_value": result.status,
            "expected_value": "VSAN_CERTIFIED",
            "error_message": None,
        }

    def _outcome(self, status: str, detail: str) -> dict[str, Any]:
        return {"result_status": RuleResultStatus.UNAVAILABLE, "risk_level": None, "data_quality": DataQuality.PARTIAL, "evidence": {"vsan_status": status, "vsan_detail": detail}, "observed_value": status, "expected_value": "VSAN_CERTIFIED", "error_message": None}

    def _quadruple(self, props: Mapping[str, Any]) -> tuple[str, str, str, str] | None:
        values = tuple(self._text_or_none(props.get(name)) for name in ("vid", "did", "svid", "ssid"))
        return values if all(values) else None

    def _text_or_none(self, value: Any) -> str | None:
        text = str(value or "").strip()
        return text or None
