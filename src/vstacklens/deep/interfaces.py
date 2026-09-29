from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Protocol

from pydantic import BaseModel, Field

from vstacklens.deep.contracts import CapabilityMatrix, DeepDataset
from vstacklens.deep.logs import HARD_MAX_LOG_FALLBACK_BYTES, HARD_MAX_LOG_PRIMARY_BYTES, HARD_MAX_LOG_TOTAL_BYTES, MAX_LOG_FILES, MAX_LOG_FILE_BYTES, MAX_LOG_FALLBACK_BYTES, MAX_LOG_PRIMARY_BYTES, MAX_LOG_TOTAL_BYTES


class StandardInventorySnapshot(BaseModel):
    """Versioned seam consumed by Deep; it deliberately contains no collector code."""

    schema_version: str = "1.0"
    snapshot_id: str
    environment_id: str
    collected_at_utc: str = Field(default_factory=lambda: datetime.now(UTC).isoformat().replace("+00:00", "Z"))
    objects: list[dict[str, Any]] = Field(default_factory=list)
    relations: list[dict[str, Any]] = Field(default_factory=list)


class DeepCollectionPolicy(BaseModel):
    profile: str = "core"
    budget_seconds: int = 1800
    resource_memory_limit_mb: int = 512
    resource_cpu_limit_percent: float = 90.0
    max_log_files: int = Field(default=MAX_LOG_FILES, ge=0, le=MAX_LOG_FILES)
    max_log_file_bytes: int = Field(default=MAX_LOG_FILE_BYTES, ge=0, le=MAX_LOG_FILE_BYTES)
    max_log_total_bytes: int = Field(default=MAX_LOG_TOTAL_BYTES, ge=0, le=HARD_MAX_LOG_TOTAL_BYTES)
    max_log_primary_bytes: int = Field(default=MAX_LOG_PRIMARY_BYTES, ge=0, le=HARD_MAX_LOG_PRIMARY_BYTES)
    max_log_fallback_bytes: int = Field(default=MAX_LOG_FALLBACK_BYTES, ge=0, le=HARD_MAX_LOG_FALLBACK_BYTES)
    log_collection_days: int | None = Field(default=None, ge=1, le=365)
    correlation_window_seconds: int = Field(default=3600, gt=0, le=86_400)
    history_days: int = 30
    event_history_days: int = Field(default=30, ge=1, le=90)
    max_entities: int = 2500
    max_history_records: int = 100_000
    impact_level: str = "moderate"
    allow_heavy: bool = False


class DeepCollector(Protocol):
    def probe_capabilities(self, snapshot: StandardInventorySnapshot) -> CapabilityMatrix:
        ...

    def collect(self, snapshot: StandardInventorySnapshot, policy: DeepCollectionPolicy) -> DeepDataset:
        ...
