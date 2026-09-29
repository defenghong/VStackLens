from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Literal

from vstacklens.core.enums import DataQuality, RuleResultStatus
from vstacklens.hcl.matcher import HclMatcher, normalize_driver_version, normalize_firmware_version, explicit_version_range_matches
from vstacklens.hcl.store import HclStore


VsanCheckMode = Literal["auto", "force", "skip"]
VsanStatus = Literal[
    "VSAN_NOT_APPLICABLE",
    "VSAN_CERTIFIED",
    "VSAN_NOT_IN_HCL",
    "VSAN_QUEUE_DEPTH_LOW",
    "VSAN_QUEUE_DEPTH_UNKNOWN",
    "VSAN_MODE_MISMATCH",
    "VSAN_CONTEXT_UNKNOWN",
]

_STATUS_MAP: dict[VsanStatus, tuple[RuleResultStatus, DataQuality]] = {
    "VSAN_NOT_APPLICABLE": (RuleResultStatus.NOT_APPLICABLE, DataQuality.COMPLETE),
    "VSAN_CERTIFIED": (RuleResultStatus.PASSED, DataQuality.COMPLETE),
    "VSAN_NOT_IN_HCL": (RuleResultStatus.UNAVAILABLE, DataQuality.MISSING),
    "VSAN_QUEUE_DEPTH_LOW": (RuleResultStatus.FAILED, DataQuality.COMPLETE),
    "VSAN_QUEUE_DEPTH_UNKNOWN": (RuleResultStatus.UNAVAILABLE, DataQuality.PARTIAL),
    "VSAN_MODE_MISMATCH": (RuleResultStatus.FAILED, DataQuality.COMPLETE),
    "VSAN_CONTEXT_UNKNOWN": (RuleResultStatus.UNAVAILABLE, DataQuality.PARTIAL),
}


@dataclass(frozen=True)
class VsanContext:
    vsan_enabled: bool | None
    vsan_architecture: Literal["osa", "esa"] | None
    vsan_disk_layout: Literal["all_flash", "hybrid"] | None
    controller_mode: Literal["pass_through", "raid"] | None
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class VsanSupportRequirement:
    raw: str
    disk_layout: Literal["all_flash", "hybrid"] | None
    controller_mode: Literal["pass_through", "raid"] | None
    recognized: bool


@dataclass(frozen=True)
class VsanCompatibilityResult:
    status: VsanStatus
    rule_status: RuleResultStatus
    data_quality: DataQuality
    detail: str
    queue_depth: int | None = None
    requirements: tuple[VsanSupportRequirement, ...] = ()


def status_mapping(status: VsanStatus) -> tuple[RuleResultStatus, DataQuality]:
    return _STATUS_MAP[status]


def cluster_vsan_context(vsan_config: Any, vsan_disks: list[Any] | None, *, controller_mode: Literal["pass_through", "raid"] | None = None, collection_error: str | None = None) -> VsanContext:
    """Build a three-state vSAN context without coercing None to False."""
    enabled = _bool_or_none(_get(vsan_config, "enabled", "Enabled"))
    esa = _bool_or_none(_get(vsan_config, "vsanEsaEnabled", "VsanEsaEnabled"))
    if enabled is False:
        return VsanContext(False, None, None, controller_mode, (collection_error,) if collection_error else ())
    if enabled is not True:
        return VsanContext(None, None, None, controller_mode, (collection_error or "vSAN enabled state unavailable",))
    architecture = "esa" if esa is True else "osa" if esa is False else None
    if collection_error:
        return VsanContext(True, architecture, None, controller_mode, (collection_error,))
    layout = vsan_disk_layout(vsan_disks or [])
    return VsanContext(True, architecture, layout, controller_mode)


def vsan_disk_layout(disks: list[Any]) -> Literal["all_flash", "hybrid"] | None:
    """Classify only esxcli vsan storage list records, never all ScsiLun rows."""
    capacity = [item for item in disks if _bool_or_none(_get(item, "isCapacityTier", "IsCapacityTier")) is True]
    if not capacity:
        return None
    return "all_flash" if all(_bool_or_none(_get(item, "isSSD", "IsSSD")) is True for item in capacity) else "hybrid"


def controller_mode_from_drive_type(value: Any) -> Literal["pass_through", "raid"] | None:
    drive_type = str(value or "").strip().casefold()
    if drive_type == "physical":
        return "pass_through"
    if drive_type in {"logical", "unknown"}:
        return "raid"
    return None


def aggregate_controller_mode(devices: list[Any]) -> Literal["pass_through", "raid"] | None:
    modes = {controller_mode_from_drive_type(_get(item, "driveType", "DriveType")) for item in devices}
    if "pass_through" in modes:
        return "pass_through"
    return "raid" if "raid" in modes else None


def parse_vsan_support(value: Any) -> VsanSupportRequirement:
    raw = str(value or "").strip()
    normalized = raw.casefold()
    layout = "all_flash" if normalized.startswith("all flash:") else "hybrid" if normalized.startswith("hybrid:") else None
    mode = "pass_through" if "pass-through" in normalized else "raid" if re.search(r"\braid\s*0\b", normalized) else None
    return VsanSupportRequirement(raw=raw, disk_layout=layout, controller_mode=mode, recognized=layout is not None or mode is not None)


def evaluate_vsan_compatibility(store: HclStore, *, quadruple: tuple[str, str, str, str] | None, model: str | None, category: str, driver_name: str, driver_version: str, firmware_version: str | None, target_release: str, context: VsanContext, queue_depth_min: int, check_mode: VsanCheckMode = "auto") -> VsanCompatibilityResult:
    if check_mode == "skip" or (check_mode == "auto" and context.vsan_enabled is False):
        return _result("VSAN_NOT_APPLICABLE", "vSAN 专项检查未启用")
    if check_mode == "auto" and context.vsan_enabled is None:
        return _result("VSAN_CONTEXT_UNKNOWN", "无法确认集群 vSAN 状态，暂不能确认适用性")
    if context.vsan_disk_layout is None or context.controller_mode is None:
        return _result("VSAN_CONTEXT_UNKNOWN", "vSAN 架构、磁盘布局或控制器模式未采集")

    base = HclMatcher(store).match(quadruple, target_release, driver_name, driver_version, firmware_version, model=model, category=category, source="vsan_hcl")
    if base.status in {"UNKNOWN_DEVICE", "MODEL_NOT_MATCHED", "NOT_CERTIFIED", "DRIVER_NOT_CERTIFIED", "DRIVER_VERSION_MISMATCH", "DRIVER_VERSION_UNLISTED", "DRIVER_VERSION_BELOW_MINIMUM", "IDENTIFIER_MISSING", "AMBIGUOUS_DEVICE"}:
        return _result("VSAN_NOT_IN_HCL", f"vSAN HCL 未认证当前设备组合：{base.status}")
    if base.status == "FIRMWARE_UNKNOWN":
        return _result("VSAN_CONTEXT_UNKNOWN", "缺少可靠固件信息，无法确认 vSAN 认证组合")
    if base.status == "FIRMWARE_MISMATCH":
        return _result("VSAN_MODE_MISMATCH", "当前固件未满足 vSAN 认证组合")
    candidates = store.get_device(model=model, category=category, source="vsan_hcl") if category in {"ssd", "hdd"} else store.get_device(quadruple, category=category, source="vsan_hcl")
    if len(candidates) != 1:
        return _result("VSAN_NOT_IN_HCL", "vSAN HCL 设备标识不唯一或不存在")
    rows = [row for row in store.release_rows(candidates[0]["hcl_device_id"], target_release) if row["driver_name"] == driver_name]
    rows = [row for row in rows if normalize_driver_version(row["driver_version"]) == normalize_driver_version(driver_version) or explicit_version_range_matches(row, "driver", driver_version)]
    rows = [row for row in rows if not row["firmware_version"] or
            (firmware_version and (normalize_firmware_version(row["firmware_version"]) == normalize_firmware_version(firmware_version) or explicit_version_range_matches(row, "firmware", firmware_version)))]
    queue_depths = [_positive_int(row["queue_depth"]) for row in rows]
    declared = [value for value in queue_depths if value is not None]
    if not declared:
        return _result("VSAN_QUEUE_DEPTH_UNKNOWN", "vSAN HCL 未声明 queueDepth")
    if max(declared) < queue_depth_min:
        return _result("VSAN_QUEUE_DEPTH_LOW", f"vSAN HCL queueDepth={max(declared)}，低于规则阈值 {queue_depth_min}", queue_depth=max(declared))
    eligible = [row for row in rows if (_positive_int(row["queue_depth"]) or 0) >= queue_depth_min]
    requirements = tuple(requirement for row in eligible for requirement in _parse_support_json(row["vsan_support_json"]))
    undecidable = False
    for row in eligible:
        row_requirements = _parse_support_json(row["vsan_support_json"])
        recognized = [item for item in row_requirements if item.recognized]
        if not row_requirements or any(_matches(item, context) for item in recognized):
            return _result("VSAN_CERTIFIED", "同一认证组合的固件、队列深度与模式均满足要求", queue_depth=_positive_int(row["queue_depth"]), requirements=tuple(row_requirements))
        if not recognized:
            undecidable = True
    return _result("VSAN_CONTEXT_UNKNOWN" if undecidable else "VSAN_MODE_MISMATCH",
                   "未找到同时满足固件、队列深度和运行模式的认证组合", requirements=requirements)



def _matches(requirement: VsanSupportRequirement, context: VsanContext) -> bool:
    return (requirement.disk_layout is None or requirement.disk_layout == context.vsan_disk_layout) and (requirement.controller_mode is None or requirement.controller_mode == context.controller_mode)


def _result(status: VsanStatus, detail: str, *, queue_depth: int | None = None, requirements: tuple[VsanSupportRequirement, ...] = ()) -> VsanCompatibilityResult:
    rule_status, data_quality = status_mapping(status)
    return VsanCompatibilityResult(status, rule_status, data_quality, detail, queue_depth, requirements)


def _parse_support_json(value: Any) -> list[VsanSupportRequirement]:
    try:
        raw = json.loads(value or "[]")
    except (TypeError, json.JSONDecodeError):
        raw = []
    return [parse_vsan_support(item) for item in raw if str(item or "").strip()]


def _positive_int(value: Any) -> int | None:
    try:
        number = int(str(value))
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def _bool_or_none(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if str(value).strip().casefold() in {"true", "1"}:
        return True
    if str(value).strip().casefold() in {"false", "0"}:
        return False
    return None


def _get(obj: Any, *names: str) -> Any:
    for name in names:
        if isinstance(obj, dict) and name in obj:
            return obj[name]
        try:
            value = getattr(obj, name)
        except (AttributeError, TypeError):
            continue
        return value
    return None
