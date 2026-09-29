from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from vstacklens.db.repositories import actionable_risk_total


def _customer_label(value: str | None, fallback: str) -> str:
    if not value or value in {"Default Customer", "Default Site", "默认客户", "默认站点"}:
        return fallback
    return value


class ReportInfo(BaseModel):
    report_id: str
    report_title: str = "VStackLens VMware 虚拟化健康评估报告"
    report_version: str = "M2"
    generated_at: str
    run_id: str
    template_style: str = "business_blue"
    language: str = "zh-CN"


class CustomerInfo(BaseModel):
    customer_name: str
    site_name: str
    project_name: str = "VMware 虚拟化健康评估"
    vcenter: str


class EnvironmentSummary(BaseModel):
    vcenter_version: str | None = None
    vcenter_build: str | None = None
    scope_statement: str
    checked_object_total: int
    result_status_summary: dict[str, int] = Field(default_factory=dict)


class HealthScore(BaseModel):
    label: str = "评估受限"
    assessment_limited: bool = True
    score: float
    grade: str
    explanation: str
    breakdown: dict[str, Any] = Field(default_factory=dict)
    health_impact: dict[str, int] = Field(default_factory=dict)


class RiskSummary(BaseModel):
    P1: int = 0
    P2: int = 0
    P3: int = 0
    P4: int = 0
    total: int = 0
    affected_objects: dict[str, int] = Field(default_factory=dict)


class FindingItem(BaseModel):
    risk_level: str
    health_impact: str = "none"
    rule_id: str
    rule_name: str
    title: str
    object_type: str
    object_name: str
    object_path: str | None = None
    status: str
    current_value: Any = None
    expected_value: Any = None
    current_value_zh: str = ""
    expected_value_zh: str = ""
    business_impact: str = ""
    technical_impact: str = ""
    consequence: str = ""
    remediation: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    threshold: Any = None
    source_path: str = ""
    collected_at: str = ""
    explanation: str = ""
    raw_evidence: dict[str, Any] = Field(default_factory=dict)
    has_structured_evidence: bool = False
    evidence_summary_zh: str = ""
    observed_detail: dict[str, Any] = Field(default_factory=dict)
    expected_detail: dict[str, Any] = Field(default_factory=dict)
    observed_detail_zh: str = ""
    expected_detail_zh: str = ""
    affected_components: list[Any] = Field(default_factory=list)
    affected_components_zh: str = ""
    recommended_action_zh: str = ""
    fault_detail_zh: str = ""
    explanation_zh: str = ""
    threshold_zh: str = ""
    false_positive_notes: str = ""
    exception_guidance: str = ""
    when_to_ignore: str = ""
    exception_reason: str = ""
    exception_owner: str = ""
    exception_expires_at: str = ""
    exception_approval_note: str = ""
    owner_role: str = ""
    remediation_effort: str = ""
    maintenance_window_required: bool = False
    verification_method: str = ""
    remediation_steps: list[str] = Field(default_factory=list)


class RemediationItem(BaseModel):
    risk_level: str
    rule_id: str
    title: str
    object_count: int
    owner_role: str = ""
    effort: str = ""
    maintenance_window_required: bool = False
    verification_method: str = ""
    steps: list[str] = Field(default_factory=list)


class ReportData(BaseModel):
    schema_version: str = "1.0"
    report_info: ReportInfo
    customer_info: CustomerInfo
    environment_summary: EnvironmentSummary
    health_score: HealthScore
    risk_summary: RiskSummary
    risk_distribution: dict[str, Any] = Field(default_factory=dict)
    risk_category_summary: dict[str, int] = Field(default_factory=dict)
    risk_object_summary: dict[str, int] = Field(default_factory=dict)
    affected_object_summary: dict[str, int] = Field(default_factory=dict)
    vsan_summary: dict[str, Any] = Field(default_factory=dict)
    problem_categories: list[dict[str, Any]] = Field(default_factory=list)
    report_presentation: dict[str, Any] = Field(default_factory=dict)
    overall_status: str = ""
    history_visible: bool = False
    asset_inventory: dict[str, Any] = Field(default_factory=dict)
    findings: list[FindingItem] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    remediation_plan: list[RemediationItem] = Field(default_factory=list)
    exception_findings: list[FindingItem] = Field(default_factory=list)
    appendix: dict[str, Any] = Field(default_factory=dict)

    def write_json(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.model_dump_json(indent=2), encoding="utf-8")

    @classmethod
    def json_schema_text(cls) -> str:
        return json.dumps(cls.model_json_schema(), ensure_ascii=False, indent=2)


class ReportDataFactory:
    def from_context(self, context: dict[str, Any]) -> ReportData:
        run = context.get("run", {})
        scope = context.get("scope", {})
        risk = context.get("risk_summary", {})
        executive = context.get("executive_summary", {})
        score_breakdown = context.get("score_breakdown", {})
        environment_info = context.get("environment_info", {})
        score = float(executive.get("score") or 0)
        from vstacklens.reports.health_status import assess_health
        critical_rules = {r.get("rule_id") for r in context.get("rule_catalog", [])
                          if r.get("risk_level") in {"P1", "P2"}
                          and r.get("implementation_status", "implemented") == "implemented"}
        critical_gaps = [r for r in context.get("unavailable_results", []) if r.get("rule_id") in critical_rules]
        health = assess_health(risk, context.get("result_status_summary", {}), context.get("asset_total", 0),
                               len(critical_gaps) if context.get("rule_catalog") else None,
                               context.get("health_impact_summary") if "health_impact_summary" in context else None)
        findings = [FindingItem(**self._finding_payload(item)) for item in context.get("findings", [])]
        exception_findings = [FindingItem(**self._finding_payload(item)) for item in context.get("exception_findings", [])]
        remediation_plan = [RemediationItem(**item) for item in context.get("remediation_plan", [])]
        recommendations = self._recommendations(risk, context.get("unavailable_results", []))
        return ReportData(
            report_info=ReportInfo(
                report_id=f"report-{run.get('run_id', '')}",
                generated_at=run.get("updated_at") or run.get("created_at") or "",
                run_id=run.get("run_id", ""),
            ),
            customer_info=CustomerInfo(
                customer_name=_customer_label(scope.get("customer_name"), "未指定客户"),
                site_name=_customer_label(scope.get("site_name"), "未指定站点"),
                vcenter=scope.get("vcenter_host") or "",
            ),
            environment_summary=EnvironmentSummary(
                vcenter_version=environment_info.get("vcenter_version") or "未采集",
                vcenter_build=environment_info.get("vcenter_build") or "未采集",
                scope_statement="本报告基于当前账号可访问的 vCenter 环境数据生成，展示本次健康评估结果、风险与资产概览。",
                checked_object_total=int(context.get("asset_total", 0)),
                result_status_summary=context.get("result_status_summary", {}),
            ),
            health_score=HealthScore(
                score=score,
                grade=health["label"],
                label=health["label"],
                assessment_limited=health["assessment_limited"],
                explanation=health["explanation"],
                breakdown=score_breakdown,
                health_impact=context.get("health_impact_summary", {}),
            ),
            risk_summary=RiskSummary(
                P1=int(risk.get("P1", 0)),
                P2=int(risk.get("P2", 0)),
                P3=int(risk.get("P3", 0)),
                P4=int(risk.get("P4", 0)),
                total=int(context.get("risk_total", actionable_risk_total(risk))),
                affected_objects=context.get("risk_object_summary", {}),
            ),
            risk_distribution=self._risk_distribution(findings),
            risk_category_summary=context.get("risk_category_summary", risk),
            risk_object_summary=context.get("risk_object_summary", {}),
            affected_object_summary=context.get("risk_object_summary", {}),
            vsan_summary=context.get("vsan_summary", {}),
            problem_categories=list((context.get("report_presentation") or {}).get("problem_categories") or []),
            report_presentation=dict(context.get("report_presentation") or {}),
            overall_status=str((context.get("report_presentation") or {}).get("overall_status") or ""),
            history_visible=str((context.get("history_comparison") or {}).get("state") or "").casefold() == "ready",
            asset_inventory={
                "summary": context.get("asset_summary", {}),
                "details": context.get("asset_details", {}),
                "total": context.get("asset_total", 0),
            },
            findings=findings,
            recommendations=recommendations,
            remediation_plan=remediation_plan,
            exception_findings=exception_findings,
            appendix={
                "unavailable_rules": critical_gaps,
                "critical_gap_count": len(critical_gaps),
                "not_applicable_rules": context.get("not_applicable_summary", []),
                "rule_checklist": context.get("rule_checklist", []),
                "certificate_license_evidence": context.get("certificate_license_evidence", []),
            },
        )

    def _finding_payload(self, item: dict[str, Any]) -> dict[str, Any]:
        return {
            "risk_level": item.get("risk_level", ""),
            "health_impact": item.get("health_impact", "none"),
            "rule_id": item.get("rule_id", ""),
            "rule_name": item.get("rule_name", item.get("rule_id", "")),
            "title": item.get("title", item.get("rule_id", "")),
            "object_type": item.get("object_type", ""),
            "object_name": item.get("object_name", ""),
            "object_path": item.get("object_path"),
            "status": item.get("status", ""),
            "current_value": item.get("current_value"),
            "expected_value": item.get("expected_value"),
            "current_value_zh": item.get("current_value_zh", ""),
            "expected_value_zh": item.get("expected_value_zh", ""),
            "business_impact": item.get("business_impact", ""),
            "technical_impact": item.get("technical_impact", ""),
            "consequence": item.get("consequence", ""),
            "remediation": item.get("remediation", ""),
            "evidence": item.get("evidence", {}),
            "threshold": item.get("threshold"),
            "source_path": item.get("source_path", ""),
            "collected_at": item.get("collected_at", ""),
            "explanation": item.get("explanation", ""),
            "raw_evidence": item.get("raw_evidence", {}),
            "has_structured_evidence": bool(item.get("has_structured_evidence", False)),
            "evidence_summary_zh": item.get("evidence_summary_zh", ""),
            "observed_detail": item.get("observed_detail", {}),
            "expected_detail": item.get("expected_detail", {}),
            "observed_detail_zh": item.get("observed_detail_zh", ""),
            "expected_detail_zh": item.get("expected_detail_zh", ""),
            "affected_components": item.get("affected_components", []),
            "affected_components_zh": item.get("affected_components_zh", ""),
            "recommended_action_zh": item.get("recommended_action_zh", ""),
            "fault_detail_zh": item.get("fault_detail_zh", ""),
            "explanation_zh": item.get("explanation_zh", ""),
            "threshold_zh": item.get("threshold_zh", ""),
            "false_positive_notes": item.get("false_positive_notes", ""),
            "exception_guidance": item.get("exception_guidance", ""),
            "when_to_ignore": item.get("when_to_ignore", ""),
            "exception_reason": item.get("exception_reason", ""),
            "exception_owner": item.get("exception_owner", ""),
            "exception_expires_at": item.get("exception_expires_at", ""),
            "exception_approval_note": item.get("exception_approval_note", ""),
            "owner_role": item.get("owner_role", ""),
            "remediation_effort": item.get("remediation_effort", ""),
            "maintenance_window_required": bool(item.get("maintenance_window_required", False)),
            "verification_method": item.get("verification_method", ""),
            "remediation_steps": item.get("remediation_steps", []),
        }

    def _risk_distribution(self, findings: list[FindingItem]) -> dict[str, Any]:
        by_object_type: dict[str, int] = {}
        by_rule: dict[str, int] = {}
        for item in findings:
            by_object_type[item.object_type] = by_object_type.get(item.object_type, 0) + 1
            by_rule[item.rule_id] = by_rule.get(item.rule_id, 0) + 1
        return {"by_object_type": by_object_type, "by_rule": by_rule}

    def _recommendations(self, risk: dict[str, int], unavailable: list[dict[str, Any]]) -> list[str]:
        result = []
        if risk.get("P1", 0) or risk.get("P2", 0):
            result.append("优先处理 P1/P2 风险，并在整改后复跑巡检确认。")
        if risk.get("P3", 0):
            result.append("将 P3 风险纳入近期维护窗口，按集群、主机、虚拟机分批整改。")
        if unavailable:
            result.append("对数据缺口核查账号权限、性能指标可用性和离线基线数据。")
        if not result:
            result.append("当前未发现高优先级风险，建议保留定期巡检。")
        return result

    def _grade(self, score: float) -> str:
        if score >= 90:
            return "A"
        if score >= 75:
            return "B"
        if score >= 60:
            return "C"
        return "D"

    def _score_explanation(self, score: float, breakdown: dict[str, Any] | None = None) -> str:
        breakdown = breakdown or {}
        levels = breakdown.get("levels") or {}
        p1 = levels.get("P1", {})
        p2 = levels.get("P2", {})
        p3 = levels.get("P3", {})
        parts = [
            "健康评分基于 P1/P2/P3 风险等级、风险类型数量和影响对象范围计算。",
            "优化建议不参与健康评分扣分。",
        ]
        deductions = []
        for level, label, data in (("P1", "P1", p1), ("P2", "P2", p2), ("P3", "P3", p3)):
            deduction = float(data.get("deduction") or 0)
            if deduction:
                deductions.append(f"{label} 扣分 {deduction:g}")
        if deductions:
            parts.append("主要扣分来源：" + "，".join(deductions) + "。")
        caps = breakdown.get("applied_caps") or []
        if caps:
            parts.append("评分门槛：" + "；".join(str(item) for item in caps))
        if score >= 90:
            parts.append("环境整体健康，建议保持定期巡检。")
            return "".join(parts)
        if score >= 75:
            parts.append("环境存在少量风险，建议按优先级整改。")
            return "".join(parts)
        if score >= 60:
            parts.append("环境存在明显风险，需要制定整改计划。")
            return "".join(parts)
        parts.append("环境风险较多，建议优先处理高风险和影响范围较大的问题。")
        return "".join(parts)
