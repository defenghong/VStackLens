from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_m2e_backlog_assessment_covers_all_removed_rules() -> None:
    backlog = yaml.safe_load((ROOT / "docs" / "internal_rule_backlog.yaml").read_text(encoding="utf-8"))
    assessment = yaml.safe_load((ROOT / "docs" / "m2e_rule_backfill_assessment.yaml").read_text(encoding="utf-8"))

    assert backlog["removed_count"] == 94
    assert len(backlog["removed_rules"]) == 94
    assert assessment["backlog_count"] == 94
    assert len(assessment["evaluations"]) == 94
    assert {item["rule_id"] for item in assessment["evaluations"]} == {item["rule_id"] for item in backlog["removed_rules"]}
    assert assessment["backfill_rule_count"] == 15
    assert assessment["summary"] == {
        "implement_later": 20,
        "duplicate_removed": 10,
        "keep_backlog_external_dependency": 41,
        "can_implement_now": 15,
        "keep_backlog_topology_sensitive": 8,
    }
    assert all(item["assessment_result"] for item in assessment["evaluations"])
    assert all("dependency" in item and "reason" in item for item in assessment["evaluations"])
