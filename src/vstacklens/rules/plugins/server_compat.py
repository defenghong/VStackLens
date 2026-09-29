from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from vstacklens.core.enums import DataQuality, RuleResultStatus
from vstacklens.hcl.store import HclStore
from vstacklens.inventory.canonical_models import CanonicalObject
from vstacklens.rules.schema import RuleDefinition
from vstacklens.upgrade_compat.server import match_server_model


class ServerCompatibilityPlugin:
    name = "server_compatibility"

    def __init__(self, store: HclStore | None) -> None:
        self.store = store

    def execute(self, rule: RuleDefinition, target: CanonicalObject, parameters: Mapping[str, Any], resolve_risk: Any) -> dict[str, Any]:
        if self.store is None:
            return self._outcome("SERVER_UNKNOWN_MODEL", "HCL 数据不可用")
        result = match_server_model(self.store, target.properties.get("smbios_model"), str(parameters.get("target_release") or ""))
        mapping = {
            "SERVER_CERTIFIED": (RuleResultStatus.PASSED, DataQuality.COMPLETE),
            "SERVER_NOT_CERTIFIED": (RuleResultStatus.FAILED, DataQuality.COMPLETE),
            "SERVER_UNKNOWN_MODEL": (RuleResultStatus.UNAVAILABLE, DataQuality.MISSING),
            "SERVER_MODEL_AMBIGUOUS": (RuleResultStatus.UNAVAILABLE, DataQuality.PARTIAL),
        }
        status, quality = mapping[result.status]
        return {"result_status": status, "risk_level": resolve_risk(rule, dict(target.properties)).value if status == RuleResultStatus.FAILED else None, "data_quality": quality, "evidence": {"server_status": result.status, "server_detail": result.detail, "vcglink": result.vcglink}, "observed_value": result.status, "expected_value": "SERVER_CERTIFIED", "error_message": None}

    def _outcome(self, status: str, detail: str) -> dict[str, Any]:
        return {"result_status": RuleResultStatus.UNAVAILABLE, "risk_level": None, "data_quality": DataQuality.MISSING, "evidence": {"server_status": status, "server_detail": detail}, "observed_value": status, "expected_value": "SERVER_CERTIFIED", "error_message": None}
