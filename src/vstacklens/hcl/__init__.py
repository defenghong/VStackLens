"""vSAN hardware compatibility data and matching helpers."""

from .matcher import HclMatcher, compare_driver_versions, match_device, normalize_driver_version, normalize_firmware_version, parse_version_segments, sort_release_versions
from .models import DataVersionMeta, FirmwareSpec, HclDevice, MatchResult, MatchStatus, MultiSourceMatchResult
from .sources import JsonHclDataSource, VcgDataSource, VsanHclDataSource
from .store import HclStore

__all__ = [
    "DataVersionMeta",
    "FirmwareSpec",
    "HclDevice",
    "HclMatcher",
    "HclStore",
    "compare_driver_versions",
    "MatchResult",
    "MatchStatus",
    "MultiSourceMatchResult",
    "JsonHclDataSource",
    "VcgDataSource",
    "VsanHclDataSource",
    "match_device",
    "normalize_driver_version",
    "normalize_firmware_version",
    "parse_version_segments",
    "sort_release_versions",
]
