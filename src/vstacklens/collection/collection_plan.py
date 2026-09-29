from __future__ import annotations

from pydantic import BaseModel, Field


class PerformanceMetricRequest(BaseModel):
    object_type: str
    metric: str
    window_minutes: int
    minimum_samples: int


class CollectionPlan(BaseModel):
    object_types: set[str] = Field(default_factory=set)
    properties: dict[str, set[str]] = Field(default_factory=dict)
    performance_metrics: list[PerformanceMetricRequest] = Field(default_factory=list)
    plugin_sources: set[str] = Field(default_factory=set)
    permissions_required: set[str] = Field(default_factory=set)
