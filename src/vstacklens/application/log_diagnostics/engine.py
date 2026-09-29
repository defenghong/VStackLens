from __future__ import annotations

from collections.abc import Callable
from typing import Any

from vstacklens.application.log_diagnostics.problem_parser import ProblemContext, ProblemParser
from vstacklens.application.log_diagnostics.timeline import TimelineBuilder


DiagnosisBuilder = Callable[[ProblemContext], dict[str, Any]]


class LogDiagnosisEngine:
    """Rule-based entrypoint for customer problem driven log diagnosis."""

    name = "rule_based_log_diagnosis_with_optional_cloud"

    def __init__(self, parser: ProblemParser | None = None, timeline_builder: TimelineBuilder | None = None) -> None:
        self.parser = parser or ProblemParser()
        self.timeline_builder = timeline_builder or TimelineBuilder()

    def prepare(self, problem_description: str) -> ProblemContext:
        return self.parser.parse_context(problem_description)

    def diagnose(self, context: ProblemContext, builders: dict[str, DiagnosisBuilder]) -> dict[str, Any]:
        scenario = context.scenario or "generic_problem_driven_diagnosis"
        builder = builders.get(scenario) or builders["generic_problem_driven_diagnosis"]
        diagnosis = builder(context)
        diagnosis.setdefault("scenario", scenario)
        diagnosis.setdefault("problem_profile", context.profile)
        diagnosis["diagnosis_engine"] = {
            "name": self.name,
            "mode": "rule_based",
            "model_used": False,
            "model_source": "rule_only",
            "model_protocol": "openai_compatible",
            "fallback_reason": "",
        }
        timeline = self.timeline_builder.build(diagnosis)
        if timeline:
            diagnosis["timeline"] = timeline
        return diagnosis
