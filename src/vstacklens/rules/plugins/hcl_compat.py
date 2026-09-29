from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from vstacklens.core.enums import DataQuality, RuleResultStatus
from vstacklens.hcl.matcher import HclMatcher
from vstacklens.hcl.store import HclStore
from vstacklens.inventory.canonical_models import CanonicalObject
from vstacklens.rules.schema import RuleDefinition


_STATUS_MAP: dict[str, tuple[RuleResultStatus, DataQuality]] = {
    "CERTIFIED": (RuleResultStatus.PASSED, DataQuality.COMPLETE),
    "CERTIFIED_NO_FIRMWARE_REQUIREMENT": (RuleResultStatus.PASSED, DataQuality.COMPLETE),
    "NOT_CERTIFIED": (RuleResultStatus.FAILED, DataQuality.COMPLETE),
    "DRIVER_NOT_CERTIFIED": (RuleResultStatus.FAILED, DataQuality.COMPLETE),
    "DRIVER_VERSION_MISMATCH": (RuleResultStatus.FAILED, DataQuality.COMPLETE),
    "DRIVER_VERSION_BELOW_MINIMUM": (RuleResultStatus.FAILED, DataQuality.COMPLETE),
    "DRIVER_VERSION_NOT_LATEST": (RuleResultStatus.PASSED, DataQuality.COMPLETE),
    "FIRMWARE_MISMATCH": (RuleResultStatus.FAILED, DataQuality.COMPLETE),
    "DRIVER_VERSION_UNLISTED": (RuleResultStatus.UNAVAILABLE, DataQuality.PARTIAL),
    "FIRMWARE_UNKNOWN": (RuleResultStatus.UNAVAILABLE, DataQuality.PARTIAL),
    "UNKNOWN_DEVICE": (RuleResultStatus.UNAVAILABLE, DataQuality.MISSING),
    "MODEL_NOT_MATCHED": (RuleResultStatus.UNAVAILABLE, DataQuality.PARTIAL),
    "AMBIGUOUS_DEVICE": (RuleResultStatus.UNAVAILABLE, DataQuality.PARTIAL),
    "IDENTIFIER_MISSING": (RuleResultStatus.UNAVAILABLE, DataQuality.MISSING),
}

_PLUGIN_STATUS_MAP: dict[str, tuple[RuleResultStatus, DataQuality]] = {
    "PLUGIN_PARAMETER_MISSING": (RuleResultStatus.UNAVAILABLE, DataQuality.MISSING),
    "PLUGIN_STORE_UNAVAILABLE": (RuleResultStatus.UNAVAILABLE, DataQuality.MISSING),
    "PLUGIN_CATEGORY_INVALID": (RuleResultStatus.ERROR, DataQuality.MISSING),
    "PLUGIN_DRIVER_INFO_MISSING": (RuleResultStatus.UNAVAILABLE, DataQuality.MISSING),
}


class HclCompatibilityPlugin:
    name = "hcl_compatibility"

    def __init__(self, store: HclStore | None) -> None:
        self.store = store

    def execute(
        self,
        rule: RuleDefinition,
        target: CanonicalObject,
        parameters: Mapping[str, Any],
        resolve_risk: Any,
    ) -> dict[str, Any]:
        props = target.properties
        target_release = parameters.get("target_release")
        if not target_release:
            return self._plugin_outcome("PLUGIN_PARAMETER_MISSING", "规则缺少 target_release 参数")
        if self.store is None:
            return self._plugin_outcome("PLUGIN_STORE_UNAVAILABLE", "HCL 数据不可用：未注入 HclStore")

        category = self._text(props.get("category"))
        quadruple = self._quadruple(props)
        model = self._optional_text(props.get("model"))
        if category not in {"controller", "nic", "ssd", "hdd"}:
            return self._plugin_outcome("PLUGIN_CATEGORY_INVALID", "HCL 属性缺失或 category 无效")
        if not self._optional_text(props.get("driver_name")) or not self._optional_text(props.get("driver_version")):
            return self._plugin_outcome("PLUGIN_DRIVER_INFO_MISSING", "HCL 属性缺失：driver_name 和 driver_version 为必需字段")
        try:
            result = HclMatcher(self.store).match(
                quadruple,
                str(target_release),
                self._text(props.get("driver_name")),
                self._text(props.get("driver_version")),
                self._optional_text(props.get("firmware_version")),
                model=model,
                category=category,
            )
            status, data_quality = _STATUS_MAP[result.status]
            evidence = self._evidence(result, category, model, quadruple)
            risk_level = resolve_risk(rule, {**props, **parameters}).value if status == RuleResultStatus.FAILED else None
            return {
                "result_status": status,
                "risk_level": risk_level,
                "data_quality": data_quality,
                "evidence": evidence,
                "observed_value": result.status,
                "expected_value": "CERTIFIED",
                "error_message": None,
            }
        except Exception as exc:  # noqa: BLE001 - an unavailable HCL store is a normal rule outcome
            return self._plugin_outcome("PLUGIN_STORE_UNAVAILABLE", f"HCL 数据不可用：{exc}")

    def _evidence(self, result: Any, category: str, model: str | None, quadruple: tuple[str, str, str, str] | None) -> dict[str, Any]:
        data_version: dict[str, Any] = {}
        candidates: list[dict[str, Any]] = []
        try:
            if self.store:
                version = self.store.latest_data_version()
                if version:
                    data_version = {
                        "data_version_id": version["data_version_id"],
                        "jsonUpdatedTime": version["json_updated_time"],
                        "downloaded_at": version["downloaded_at"],
                        "total_count": version["total_count"],
                    }
                if result.status == "AMBIGUOUS_DEVICE":
                    rows = self.store.get_device(quadruple, category=category) if category not in {"ssd", "hdd"} else self.store.get_device(model=model, category=category)
                    candidates = [
                        {
                            "model": row["model"],
                            "vendor": row["vendor"],
                            "external_id": row["external_id"],
                            "vcglink": row["vcglink"],
                        }
                        for row in rows
                    ]
        except Exception as exc:  # evidence enrichment must not turn a result into an engine error
            data_version = {"error": str(exc)}
        return {
            "hcl_match_status": result.status,
            "hcl_detail": result.detail,
            "hcl_data_version": data_version,
            "certified_driver_versions": result.certified_driver_versions,
            "certified_firmware_versions": result.certified_firmware_versions,
            "supported_releases": result.supported_releases,
            "target_release_supported": result.target_release_supported,
            "higher_supported_releases": result.higher_supported_releases,
            "highest_forward_release": result.highest_forward_release,
            "highest_supported_release": result.highest_supported_release,
            "driver_status_detail": result.driver_status_detail,
            "vcglink": result.vcglink,
            "candidate_links": result.candidate_links,
            "ambiguous_candidates": candidates,
        }

    def _plugin_outcome(self, plugin_status: str, reason: str) -> dict[str, Any]:
        result_status, data_quality = _PLUGIN_STATUS_MAP[plugin_status]
        return {
            "result_status": result_status,
            "risk_level": None,
            "data_quality": data_quality,
            "evidence": {"hcl_match_status": None, "plugin_status": plugin_status, "hcl_detail": reason, "ambiguous_candidates": []},
            "observed_value": None,
            "expected_value": "CERTIFIED",
            "error_message": None,
        }

    def _quadruple(self, props: Mapping[str, Any]) -> tuple[str, str, str, str] | None:
        values = tuple(self._optional_text(props.get(name)) for name in ("vid", "did", "svid", "ssid"))
        return values if all(value is not None for value in values) else None

    def _text(self, value: Any) -> str:
        return "" if value is None else str(value)

    def _optional_text(self, value: Any) -> str | None:
        text = self._text(value).strip()
        return text or None
