from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class FirmwareSpec(BaseModel):
    firmware: str
    vsan_support: list[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="allow")


class DriverSpec(BaseModel):
    driver_name: str
    driver_version: str
    queue_depth: str | None = None
    driver_type: str | None = None
    component_name: str | None = None
    component_version: str | None = None
    firmwares: list[FirmwareSpec] = Field(default_factory=list)

    model_config = ConfigDict(extra="allow")


class HclRelease(BaseModel):
    release: str
    drivers: list[DriverSpec] = Field(default_factory=list)


class HclDevice(BaseModel):
    id: int | str
    model: str = ""
    vendor: str = ""
    vid: str
    did: str
    svid: str
    ssid: str
    vcglink: str | None = None
    releases: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="allow")

    @property
    def quadruple(self) -> tuple[str, str, str, str]:
        # PCI identifiers are hexadecimal strings; leading zeroes are significant.
        return self.vid, self.did, self.svid, self.ssid


class DataVersionMeta(BaseModel):
    source: str = "vsan_hcl"
    data_version_id: str | None = None
    source_url: str
    downloaded_at: str
    checksum_sha256: str
    json_updated_time: str | None = None
    total_count: int = 0
    supported_releases: list[str] = Field(default_factory=list)


MatchStatus = Literal[
    "UNKNOWN_DEVICE",
    "MODEL_NOT_MATCHED",
    "NOT_CERTIFIED",
    "DRIVER_NOT_CERTIFIED",
    "DRIVER_VERSION_MISMATCH",
    "DRIVER_VERSION_UNLISTED",
    "DRIVER_VERSION_BELOW_MINIMUM",
    "DRIVER_VERSION_NOT_LATEST",
    "CERTIFIED",
    "FIRMWARE_MISMATCH",
    "FIRMWARE_UNKNOWN",
    "AMBIGUOUS_DEVICE",
    "CERTIFIED_NO_FIRMWARE_REQUIREMENT",
    "IDENTIFIER_MISSING",
]


class MatchResult(BaseModel):
    source: str = "vsan_hcl"
    status: MatchStatus
    target_release: str
    device_quadruple: tuple[str, str, str, str] | None
    driver_name: str
    driver_version: str
    firmware_version: str | None = None
    normalized_driver_version: str | None = None
    certified_driver_versions: list[str] = Field(default_factory=list)
    certified_firmware_versions: list[str] = Field(default_factory=list)
    supported_releases: list[str] = Field(default_factory=list)
    target_release_supported: bool = False
    higher_supported_releases: list[str] = Field(default_factory=list)
    highest_forward_release: str | None = None
    highest_supported_release: str | None = None
    driver_status_detail: str | None = None
    vcglink: str | None = None
    candidate_links: list[str] = Field(default_factory=list)
    detail: str | None = None


class MultiSourceMatchResult(BaseModel):
    results: list[MatchResult] = Field(default_factory=list)

    @property
    def by_source(self) -> dict[str, MatchResult]:
        return {result.source: result for result in self.results}
