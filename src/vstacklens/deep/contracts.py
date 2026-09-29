from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class DeepResultStatus(StrEnum):
    PASS = "PASS"
    FINDING = "FINDING"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_EVALUATED = "NOT_EVALUATED"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
    ERROR = "ERROR"


class CapabilityStatus(StrEnum):
    AVAILABLE = "AVAILABLE"
    LIMITED = "LIMITED"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_REQUESTED = "NOT_REQUESTED"
    ERROR = "ERROR"


class ConfidenceClass(StrEnum):
    FACT = "FACT"
    STATISTICAL = "STATISTICAL"
    INFERRED = "INFERRED"


class ScopeType(StrEnum):
    ENTITY = "entity"
    CLUSTER = "cluster"
    ENVIRONMENT = "environment"
    AGGREGATE = "aggregate"


class DeepCategory(StrEnum):
    CURRENT_RISK = "current_risk"
    HISTORICAL_HEALTH = "historical_health"
    TREND = "trend"


class DeepSource(BaseModel):
    model_config = ConfigDict(extra="allow")

    api: str
    collector: str = "vstacklens.deep"
    collected_at_utc: str | None = None


class DeepEntity(BaseModel):
    type: str
    stable_id: str
    display_ref: str = ""

    @field_validator("stable_id")
    @classmethod
    def stable_id_must_not_be_moref(cls, value: str) -> str:
        lowered = value.lower()
        if lowered.startswith(("vm-", "host-", "datastore-")) and value[0:1].islower():
            # Fixture IDs may intentionally use readable stable IDs.  Only the
            # explicitly unstable moref form is rejected here.
            return value
        if lowered.startswith("mo-ref:") or lowered.startswith("moref:"):
            raise ValueError("Deep entity stable_id cannot be a moref")
        return value


class DeepWindow(BaseModel):
    start: str
    end: str
    interval_sec: int | None = None
    sample_count: int = 0
    expected_sample_count: int | None = None
    completeness: float = 1.0

    @field_validator("completeness")
    @classmethod
    def validate_completeness(cls, value: float) -> float:
        if not 0 <= value <= 1:
            raise ValueError("completeness must be between 0 and 1")
        return value


class DatasetRecord(BaseModel):
    model_config = ConfigDict(extra="allow")

    record_id: str
    dataset_id: str
    kind: str
    entity: DeepEntity
    collected_at_utc: str
    source: DeepSource
    selector: dict[str, Any] = Field(default_factory=dict)
    window: DeepWindow
    interval_sec: int | None = None
    rollup: str = ""
    instance: str = ""
    value: Any = None
    unit: str = ""
    raw_pointer: str = ""
    finding: bool = False
    summary: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def synchronize_window(self) -> "DatasetRecord":
        if self.interval_sec is None:
            self.interval_sec = self.window.interval_sec
        return self


class EvidenceReference(BaseModel):
    ref: str
    kind: str
    dataset_id: str
    source: DeepSource
    entity: DeepEntity
    selector: dict[str, Any] = Field(default_factory=dict)
    window: DeepWindow
    interval_sec: int | None = None
    value_summary: dict[str, Any] = Field(default_factory=dict)
    raw_pointer: str = ""
    derivation: list[str] = Field(default_factory=list)


class FindingScope(BaseModel):
    scope_type: ScopeType
    scope_id: str
    dimension_key: str
    member_ids: list[str] = Field(default_factory=list)


class ThresholdPolicy(BaseModel):
    id: str
    value: float
    unit: str
    comparator: str = ">="
    source: str
    reference: str = ""
    rationale: str = ""
    last_reviewed: str = ""
    reviewed_by: str = ""
    overridable: bool = False

    @model_validator(mode="after")
    def validate_source_metadata(self) -> "ThresholdPolicy":
        valid = {"vendor", "vstacklens_engineering", "environment_baseline", "customer_override"}
        if self.source not in valid:
            raise ValueError(f"unsupported threshold source: {self.source}")
        if self.source == "vendor" and not self.reference:
            raise ValueError("vendor threshold requires reference")
        if self.source in {"vstacklens_engineering", "environment_baseline", "customer_override"} and not self.rationale:
            raise ValueError(f"{self.source} threshold requires rationale")
        return self


class ThresholdRegistry(BaseModel):
    policies: list[ThresholdPolicy] = Field(default_factory=list)

    def get(self, threshold_id: str) -> ThresholdPolicy:
        for policy in self.policies:
            if policy.id == threshold_id:
                return policy
        raise KeyError(f"threshold not registered: {threshold_id}")

    def minimum_completeness(self) -> ThresholdPolicy:
        return self.get("TH-EVIDENCE-COMPLETENESS-MIN")


class Capability(BaseModel):
    id: str
    name: str
    status: CapabilityStatus
    profile: str = "core"
    detected_via: str = ""
    detail: dict[str, Any] = Field(default_factory=dict)
    impact: str = ""
    remediable: bool = False
    affects_rules: list[str] = Field(default_factory=list)


class CapabilityMatrix(BaseModel):
    schema_version: str = "1.0"
    probed_at_utc: str
    capabilities: list[Capability] = Field(default_factory=list)

    def get(self, capability_id: str) -> Capability | None:
        return next((item for item in self.capabilities if item.id == capability_id), None)

    def missing(self, required: list[str]) -> list[str]:
        satisfied = {CapabilityStatus.AVAILABLE, CapabilityStatus.LIMITED}
        return [
            capability_id
            for capability_id in required
            if not (self.get(capability_id) and self.get(capability_id).status in satisfied)
        ]


class DatasetManifest(BaseModel):
    schema_version: str = "1.0"
    dataset_id: str
    created_at_utc: str
    collector_version: str = "vstacklens-deep/1.0.0"
    mode: str = "deep_inspection"
    target: dict[str, Any] = Field(default_factory=dict)
    scope: dict[str, int] = Field(default_factory=dict)
    parent_dataset_ids: list[str] = Field(default_factory=list)
    time_windows: dict[str, Any] = Field(default_factory=dict)
    anonymization: dict[str, Any] = Field(default_factory=dict)
    impact: dict[str, Any] = Field(default_factory=dict)
    integrity: dict[str, Any] = Field(default_factory=dict)
    collection_status: dict[str, int] = Field(default_factory=dict)


class DeepDataset(BaseModel):
    schema_version: str = "1.0"
    manifest: DatasetManifest
    capability: CapabilityMatrix
    records: list[DatasetRecord] = Field(default_factory=list)
    collection_log: list[dict[str, Any]] = Field(default_factory=list)

    @property
    def dataset_id(self) -> str:
        return self.manifest.dataset_id

    @classmethod
    def from_json(cls, path: Path) -> "DeepDataset":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.model_validate(payload)

    def to_json(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.model_dump_json(indent=2), encoding="utf-8")
        return path


class DeepRuleDefinition(BaseModel):
    rule_id: str
    rule_version: str = "1.0.0"
    title: str
    category: DeepCategory
    profile: str = "core"
    confidence_class: ConfidenceClass = ConfidenceClass.FACT
    scope_type: ScopeType = ScopeType.ENTITY
    dimension_key: str
    requires: list[str] = Field(default_factory=list)
    required_interval_sec: int | None = None
    minimum_evidence: int = 1
    threshold_id: str | None = None
    analysis_window_threshold_id: str | None = None
    forecast_threshold_id: str | None = None
    record_kind: str = "config"
    signal_selector: dict[str, Any] = Field(default_factory=dict)
    verification_guidance: str = ""
    disconfirming_conditions: list[str] = Field(default_factory=list)
    diagnosis_boundary: str = ""
    impact: str = "medium"
    urgency: str = "planned"
    display_priority: str = "P3"
    analysis_kind: str = "signal"


class DeepFinding(BaseModel):
    schema_version: str = "1.0"
    finding_id: str
    rule_id: str
    rule_version: str
    title: str
    category: DeepCategory
    confidence_class: ConfidenceClass
    scope: FindingScope
    display_priority: str = "P3"
    impact: str = "medium"
    urgency: str = "planned"
    fact: str = ""
    finding: str = ""
    entities: list[DeepEntity] = Field(default_factory=list)
    evidence: list[EvidenceReference] = Field(default_factory=list)
    evidence_sufficiency: str = "SUFFICIENT"
    threshold: ThresholdPolicy | None = None
    disconfirming_conditions: list[str] = Field(default_factory=list)
    verification_guidance: str = ""
    diagnosis_boundary: str = ""
    lifecycle: dict[str, Any] = Field(default_factory=dict)
    report_visible: bool = True

    @model_validator(mode="after")
    def visible_findings_need_verification(self) -> "DeepFinding":
        if self.report_visible and not self.verification_guidance.strip():
            raise ValueError("customer-visible Deep Finding requires verification_guidance")
        return self


class DeepRuleResult(BaseModel):
    rule_id: str
    rule_version: str
    category: DeepCategory
    profile: str
    status: DeepResultStatus
    finding_ids: list[str] = Field(default_factory=list)
    missing_capabilities: list[str] = Field(default_factory=list)
    reason: str = ""
    evidence_refs: list[str] = Field(default_factory=list)
    evaluated_at_utc: str


class DeepAnalysisScope(BaseModel):
    category: DeepCategory
    label: str
    completed_capabilities: list[str] = Field(default_factory=list)
    finding_count: int = 0
    pass_count: int = 0


class DeepReport(BaseModel):
    enabled: bool = True
    analysis_scope: list[DeepAnalysisScope] = Field(default_factory=list)
    pass_summary: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[DeepFinding] = Field(default_factory=list)
    boundary_statement: str = "本报告仅呈现已完成评估并达到证据门槛的可信结论；未形成可信结论的范围不作正常性判断。"
    trend_chain_verified: bool = False
    trend_summary: dict[str, Any] = Field(default_factory=dict)
    trend_summaries: dict[str, Any] = Field(default_factory=dict)


class DeepDiagnosticRecord(BaseModel):
    schema_version: str = "1.0"
    dataset_id: str
    created_at_utc: str
    capability: CapabilityMatrix
    rule_results: list[DeepRuleResult] = Field(default_factory=list)
    collection_log: list[dict[str, Any]] = Field(default_factory=list)
    errors: list[dict[str, Any]] = Field(default_factory=list)
    impact: dict[str, Any] = Field(default_factory=dict)
    integrity: dict[str, Any] = Field(default_factory=dict)


def now_utc_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def finding_id(rule_id: str, scope: FindingScope) -> str:
    if scope.scope_type == ScopeType.AGGREGATE and scope.member_ids:
        scope_key = ",".join(sorted(scope.member_ids))
    else:
        scope_key = scope.scope_id
    raw = f"{rule_id}|{scope.scope_type.value}|{scope_key}|{scope.dimension_key}"
    return "f:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def evidence_ref(record: DatasetRecord, *, derivation: list[str] | None = None) -> EvidenceReference:
    selector = record.selector or {}
    selector_text = ".".join(f"{key}={selector[key]}" for key in sorted(selector)) or "record"
    interval = f"@{record.interval_sec}s" if record.interval_sec else "@snapshot"
    window = f"{record.window.start}..{record.window.end}"
    ref = f"ev:{record.kind}/{record.entity.stable_id}/{selector_text}{interval}/{window}"
    report_value = record.value
    if record.kind == "event" and isinstance(report_value, dict) and isinstance(report_value.get("clusters"), list):
        clusters = report_value["clusters"]
        report_value = {
            **{key: value for key, value in report_value.items() if key != "clusters"},
            "cluster_count": len(clusters),
            "clusters": [
                {key: item[key] for key in ("entity_type", "entity", "start", "end", "rule_ids", "event_count") if key in item}
                for item in clusters[:3]
                if isinstance(item, dict)
            ],
            "omitted_cluster_count": max(0, len(clusters) - 3),
        }

    def compact_samples(key: str, allowed_fields: tuple[str, ...]) -> dict[str, Any]:
        samples = record.metadata.get(key)
        if not isinstance(samples, list):
            return {}
        result: dict[str, Any] = {f"{key}_count": len(samples)}
        result[key] = [
            {field: sample[field] for field in allowed_fields if field in sample}
            if isinstance(sample, dict)
            else sample
            for sample in samples[:3]
        ]
        return result

    event_samples = compact_samples("event_samples", ("timestamp", "event_type", "event_key", "entity", "host", "message", "rule_ids"))
    related_event_samples = compact_samples(
        "related_event_samples",
        (
            "timestamp",
            "event_type",
            "event_key",
            "event_source_api",
            "entity",
            "host",
            "matched_object_id",
            "matched_object",
            "message",
            "rule_ids",
            "dataset_pointer",
            "log_timestamp",
            "log_line_index",
            "source_line_number",
            "time_distance_seconds",
            "matching_categories",
            "interfaces",
            "state",
            "evidence_level",
        ),
    )
    return EvidenceReference(
        ref=ref,
        kind=record.kind,
        dataset_id=record.dataset_id,
        source=record.source,
        entity=record.entity,
        selector=selector,
        window=record.window,
        interval_sec=record.interval_sec,
        value_summary={
            "value": report_value,
            "unit": record.unit,
            "summary": record.summary,
            **{key: record.metadata[key] for key in ("event_filter", "correlation_window_hours", "related_event_count", "related_event_evidence_counts", "related_record_count", "related_record_samples", "time_correlation_window_seconds", "duplicate_count", "duplicate_sources", "duplicate_evidence", "conflict", "conflict_group", "conflict_sources") if key in record.metadata},
            **event_samples,
            **related_event_samples,
        },
        raw_pointer=record.raw_pointer,
        derivation=derivation or [],
    )
