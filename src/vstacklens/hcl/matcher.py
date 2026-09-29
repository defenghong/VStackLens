from __future__ import annotations

import re
import json
from functools import cmp_to_key
from typing import Any

from .models import MatchResult, MultiSourceMatchResult
from .store import HclStore

_VENDOR_SUFFIX = re.compile(r"\s*-[^\-\s]+(?:\.[^\-\s]+)*\s*$")


def parse_version_segments(value: str) -> tuple[int, ...] | None:
    """Parse a dotted numeric version; alphabetic/build labels are not guessed."""
    text = normalize_driver_version(value)
    if not text or any(not part.isdigit() for part in text.split(".")):
        return None
    try:
        return tuple(int(part) for part in text.split("."))
    except ValueError:
        return None


def compare_driver_versions(left: str, right: str) -> int | None:
    left_parts, right_parts = parse_version_segments(left), parse_version_segments(right)
    if left_parts is None or right_parts is None:
        return None
    width = max(len(left_parts), len(right_parts))
    lhs = left_parts + (0,) * (width - len(left_parts))
    rhs = right_parts + (0,) * (width - len(right_parts))
    return (lhs > rhs) - (lhs < rhs)


def release_version_key(value: str) -> tuple[int, int, int, int, str]:
    match = re.search(r"(?i)(\d+)\.(\d+)(?:\.(\d+))?(?:\s+U(\d+))?", str(value or ""))
    if not match:
        return (10**9, 10**9, 10**9, 10**9, str(value or ""))
    return tuple(int(part or 0) for part in match.groups()[:4]) + (str(value),)


def sort_release_versions(values: list[str] | tuple[str, ...] | set[str]) -> list[str]:
    return sorted({str(value) for value in values if str(value).strip()}, key=release_version_key)


def normalize_driver_version(value: str) -> str:
    text = "".join(str(value).split()).casefold()
    return _VENDOR_SUFFIX.sub("", text)


def normalize_firmware_version(value: str) -> str:
    return "".join(str(value).split()).casefold()



def explicit_version_range_matches(row, field: str, current: str) -> bool:
    """Only machine-readable, source-attributed ranges authorize interpolation.

    Optional imported row schema: compatibility_ranges.{driver,firmware}:
    {min, max?, source}. No ranges are inferred from a list of certified versions.
    """
    try:
        spec = json.loads(row["driver_spec_json"] or "{}")
        bounds = spec.get("compatibility_ranges", {}).get(field, {})
        if not bounds.get("source") or not bounds.get("min"):
            return False
        low = compare_driver_versions(current, str(bounds["min"]))
        if low is None or low < 0:
            return False
        if bounds.get("max"):
            high = compare_driver_versions(current, str(bounds["max"]))
            return high is not None and high <= 0
        return True
    except (KeyError, IndexError, TypeError, ValueError, AttributeError):
        return False

class HclMatcher:
    def __init__(self, store: HclStore):
        self.store = store

    def match(self, quadruple: tuple[str, str, str, str] | None, target_release: str, driver_name: str, driver_version: str, firmware_version: str | None = None, *, model: str | None = None, category: str | None = None, source: str | None = None) -> MatchResult:
        common = dict(source=source or "vsan_hcl", target_release=target_release, device_quadruple=quadruple, driver_name=driver_name, driver_version=driver_version, firmware_version=firmware_version, normalized_driver_version=normalize_driver_version(driver_version))
        is_disk = category in {"ssd", "hdd"}
        if is_disk:
            if not model:
                return MatchResult(status="IDENTIFIER_MISSING", detail="磁盘类设备必须提供 model 标识", **common)
            candidates = self.store.get_device(model=model, category=category, source=source)
        else:
            if quadruple is None or len(quadruple) != 4 or any(part is None or part == "" for part in quadruple):
                return MatchResult(status="IDENTIFIER_MISSING", detail="controller/nic 必须提供完整四元组标识", **common)
            candidates = self.store.get_device(quadruple, category=category, source=source)
        if not candidates:
            status = "MODEL_NOT_MATCHED" if is_disk else "UNKNOWN_DEVICE"
            detail = "磁盘型号未能与 HCL 描述型名称匹配" if is_disk else "设备标识未在 HCL 数据中找到"
            return MatchResult(status=status, detail=detail, **common)
        if len(candidates) > 1:
            results = [self._match_row(row, common) for row in candidates]
            statuses = {result.status for result in results}
            links = list(dict.fromkeys(str(row["vcglink"]) for row in candidates if row["vcglink"]))
            signatures = {(r.status, tuple(r.certified_driver_versions), tuple(r.certified_firmware_versions)) for r in results}
            passing = {"CERTIFIED", "CERTIFIED_NO_FIRMWARE_REQUIREMENT", "DRIVER_VERSION_NOT_LATEST"}
            if len(signatures) > 1 and not all(r.status in passing for r in results):
                return MatchResult(status="AMBIGUOUS_DEVICE", candidate_links=links, detail="多个候选的驱动或固件要求不一致，不能合并为单一处置建议", **common)
            if len(statuses) == 1:
                result = results[0].model_copy(deep=True)
                result.candidate_links = links
                result.detail = f"标识命中 {len(candidates)} 个 HCL 候选，当前驱动与固件组合判定一致：{result.status}"
                return result
            passing = {"CERTIFIED", "CERTIFIED_NO_FIRMWARE_REQUIREMENT", "DRIVER_VERSION_NOT_LATEST"}
            if all(result.status in passing for result in results):
                result = results[0].model_copy(deep=True)
                result.status = "CERTIFIED"
                result.candidate_links = links
                result.detail = f"标识命中 {len(candidates)} 个 HCL 候选，均已完成当前驱动与固件配对校验并认证通过"
                return result
            return MatchResult(status="AMBIGUOUS_DEVICE", candidate_links=links, detail=f"标识命中 {len(candidates)} 个 HCL 设备候选，当前驱动或固件配对的认证结论不一致", **common)
        return self._match_row(candidates[0], common)

    def _match_row(self, row: Any, common: dict[str, Any]) -> MatchResult:
        target_release = str(common["target_release"])
        driver_name = str(common["driver_name"])
        driver_version = str(common["driver_version"])
        firmware_version = common["firmware_version"]
        supported_releases = sort_release_versions(self.store.supported_releases_for_device(row["hcl_device_id"]))
        higher_releases = [release for release in supported_releases if release_version_key(release) > release_version_key(target_release)]
        lower_or_equal = [release for release in supported_releases if release_version_key(release) <= release_version_key(target_release)]
        release_context = dict(
            supported_releases=supported_releases,
            target_release_supported=target_release in supported_releases,
            higher_supported_releases=higher_releases,
            highest_forward_release=higher_releases[-1] if higher_releases else None,
            highest_supported_release=(lower_or_equal[-1] if lower_or_equal else None),
        )
        release_rows = self.store.release_rows(row["hcl_device_id"], target_release)
        if not release_rows:
            return MatchResult(status="NOT_CERTIFIED", vcglink=row["vcglink"], detail="目标版本没有认证记录", **release_context, **common)
        driver_rows = [r for r in release_rows if r["driver_name"] == driver_name]
        if not driver_rows:
            return MatchResult(status="DRIVER_NOT_CERTIFIED", vcglink=row["vcglink"], detail="当前驱动名不在认证列表", **release_context, **common)
        normalized = normalize_driver_version(driver_version)
        version_rows = [r for r in driver_rows if normalize_driver_version(r["driver_version"]) == normalized or explicit_version_range_matches(r, "driver", driver_version)]
        certified_versions = sort_driver_versions([r["driver_version"] for r in driver_rows])
        latest_certified = certified_versions[-1] if certified_versions else None
        if not version_rows:
            parsed_current = parse_version_segments(driver_version)
            parsed_certified = [parse_version_segments(version) for version in certified_versions]
            if parsed_current is None or any(item is None for item in parsed_certified):
                driver_status = "DRIVER_VERSION_MISMATCH"
                driver_detail = "当前驱动版本无法按数字段与认证列表比较"
            else:
                minimum = certified_versions[0]
                maximum = certified_versions[-1]
                if compare_driver_versions(driver_version, minimum) is not None and compare_driver_versions(driver_version, minimum) < 0:
                    driver_status = "DRIVER_VERSION_BELOW_MINIMUM"
                    driver_detail = f"当前驱动低于目标版本认证最低版本 {minimum}"
                elif compare_driver_versions(driver_version, maximum) is not None and compare_driver_versions(driver_version, maximum) < 0:
                    driver_status = "DRIVER_VERSION_UNLISTED"
                    driver_detail = "当前组合未命中本地认证记录，需核对支持范围；不从离散版本推导连续区间"
                else:
                    driver_status = "DRIVER_VERSION_UNLISTED"
                    driver_detail = "当前驱动版本不在目标版本认证列表中"
            return MatchResult(status=driver_status, vcglink=row["vcglink"], certified_driver_versions=certified_versions, detail=driver_detail, driver_status_detail=driver_detail, **release_context, **common)
        certified_firmware = sorted({r["firmware_version"] for r in version_rows if r["firmware_version"] not in (None, "")})
        if not certified_firmware:
            not_latest = latest_certified and compare_driver_versions(driver_version, latest_certified) == -1
            status = "DRIVER_VERSION_NOT_LATEST" if not_latest else "CERTIFIED_NO_FIRMWARE_REQUIREMENT"
            detail = f"当前驱动已达到最低认证版本，但低于最新认证版本 {latest_certified}" if not_latest else "认证记录未声明固件配对要求"
            return MatchResult(status=status, vcglink=row["vcglink"], certified_driver_versions=certified_versions, detail=detail, driver_status_detail=detail if not_latest else None, **release_context, **common)
        if firmware_version is None or str(firmware_version).strip() == "":
            status = "FIRMWARE_UNKNOWN"
        elif any(normalize_firmware_version(firmware_version) == normalize_firmware_version(r["firmware_version"]) or explicit_version_range_matches(r, "firmware", str(firmware_version)) for r in version_rows if r["firmware_version"]):
            status = "CERTIFIED"
        else:
            status = "FIRMWARE_MISMATCH"
        if status == "CERTIFIED" and latest_certified and compare_driver_versions(driver_version, latest_certified) == -1:
            status = "DRIVER_VERSION_NOT_LATEST"
            detail = f"当前驱动已达到最低认证版本，但低于最新认证版本 {latest_certified}；当前固件配对仍满足认证要求"
            return MatchResult(status=status, vcglink=row["vcglink"], certified_driver_versions=certified_versions, certified_firmware_versions=certified_firmware, detail=detail, driver_status_detail=detail, **release_context, **common)
        return MatchResult(status=status, vcglink=row["vcglink"], certified_driver_versions=certified_versions, certified_firmware_versions=certified_firmware, detail=None if status == "CERTIFIED" else "固件版本未完成认证匹配", **release_context, **common)

    def match_sources(self, quadruple: tuple[str, str, str, str] | None, target_release: str, driver_name: str, driver_version: str, firmware_version: str | None = None, *, model: str | None = None, category: str | None = None, sources: tuple[str, ...] = ("vcg", "vsan_hcl")) -> MultiSourceMatchResult:
        """Keep VCG base compatibility and vSAN eligibility as independent results."""
        return MultiSourceMatchResult(results=[
            self.match(quadruple, target_release, driver_name, driver_version, firmware_version, model=model, category=category, source=source)
            for source in sources
        ])


def match_device(store: HclStore, quadruple: tuple[str, str, str, str] | None, target_release: str, driver_name: str, driver_version: str, firmware_version: str | None = None, *, model: str | None = None, category: str | None = None, source: str | None = None) -> MatchResult:
    return HclMatcher(store).match(quadruple, target_release, driver_name, driver_version, firmware_version, model=model, category=category, source=source)


def sort_driver_versions(values: list[str] | tuple[str, ...] | set[str]) -> list[str]:
    """Sort versions numerically while retaining unparsable values deterministically."""
    def compare(left: str, right: str) -> int:
        compared = compare_driver_versions(left, right)
        if compared is not None:
            return compared
        return (str(left) > str(right)) - (str(left) < str(right))
    return sorted({str(value) for value in values if str(value).strip()}, key=cmp_to_key(compare))
