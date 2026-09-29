from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from vstacklens.core.enums import ConfidenceLevel, RiskLevel, RuleExecutionMode, RuleImplementationStatus


class DataSource(BaseModel):
    type: str = "pyvmomi"
    source_domain: str
    api_paths: list[str] = Field(default_factory=list)
    object_path: str | None = None
    foreach: dict[str, Any] | None = None
    sampling: dict[str, Any] | None = None


class Condition(BaseModel):
    type: str
    fail_when: str | None = None
    pass_when: str | None = None
    allow_missing_pass_when: bool = False
    unavailable_when: str | None = None
    not_applicable_when: str | None = None
    plugin_name: str | None = None


class SeverityPolicy(BaseModel):
    type: Literal["fixed", "threshold"] = "fixed"
    default_level: RiskLevel
    rules: list[dict[str, Any]] = Field(default_factory=list)


class ReportFields(BaseModel):
    title_zh: str
    check_name_zh: str = ""
    finding_title_zh: str = ""
    plain_summary_zh: str = ""
    failed_summary_zh: str = ""
    false_positive_notes_zh: str = ""
    exception_guidance_zh: str = ""
    when_to_ignore_zh: str = ""
    summary_zh: str
    business_impact_zh: str
    technical_impact_zh: str
    consequence_zh: str
    remediation_zh: str


class Remediation(BaseModel):
    owner_role: str
    remediation_effort: Literal["low", "medium", "high"]
    maintenance_window_required: bool
    rollback_required: bool
    verification_method: str
    steps_zh: list[str]


class RuleDefinition(BaseModel):
    schema_version: float
    rule_id: str
    rule_name: str
    category: str
    object_type: str
    risk_level: RiskLevel
    # 整改优先级与环境健康影响分离。旧规则缺失时按报告层兼容推导。
    health_impact: Literal["none", "attention", "critical"] | None = None
    confidence_level: ConfidenceLevel
    enabled: bool = True
    rule_version: str
    applicable_versions: list[str]
    implementation_status: RuleImplementationStatus = RuleImplementationStatus.IMPLEMENTED
    execution_mode: RuleExecutionMode = RuleExecutionMode.DEFAULT_ENABLED
    capability_required: list[str] = Field(default_factory=lambda: ["pyvmomi"])
    report_visibility: list[str] = Field(default_factory=lambda: ["show_in_rule_catalog", "show_in_executed_matrix"])
    scoring_eligible: bool = True
    data_source: DataSource
    parameters: dict[str, Any] = Field(default_factory=dict)
    condition: Condition
    severity_policy: SeverityPolicy
    evidence_schema: dict[str, Any]
    report_fields: ReportFields
    remediation: Remediation
    references: list[dict[str, str]] = Field(default_factory=list)
    report: dict[str, Any] = Field(default_factory=dict)
    scoring: dict[str, Any] = Field(default_factory=dict)
