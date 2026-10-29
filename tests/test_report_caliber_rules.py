from pathlib import Path

import pytest

from vstacklens.core.context import RunContext
from vstacklens.inventory.normalizer import InventoryNormalizer
from vstacklens.rules.executor import RuleExecutor
from vstacklens.rules.rulepack_loader import RulePackLoader
from vstacklens.rules.schema_validator import SchemaValidator


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    ("used_percent", "expected_status", "expected_level"),
    [(74, "passed", None), (75, "failed", "P3"), (79.9, "failed", "P3"),
     (80, "failed", "P2"), (89.9, "failed", "P2"), (90, "failed", "P1"),
     (100, "failed", "P1")],
)
def test_datastore_capacity_report_caliber_boundaries(tmp_path, used_percent, expected_status, expected_level) -> None:
    raw_rules = RulePackLoader().load_raw(ROOT / "rulepacks" / "builtin-vsphere-v1")
    rule = SchemaValidator().validate_rule(next(item for item in raw_rules if item["rule_id"] == "VSL-DS-001"))
    run = RunContext(run_id="boundary-run", customer_id="sample", site_id="sample", vcenter_id="sample", db_path=tmp_path / "unused.db")
    inventory = InventoryNormalizer().normalize({"objects": [{
        "object_type": "Datastore", "object_key": "ds-boundary", "object_name": "sample-store",
        "object_path": "sample/sample-store", "properties": {"used_percent": used_percent},
    }]})
    result = RuleExecutor().execute(run, inventory, [rule])[0]
    assert result["result_status"] == expected_status
    assert result["risk_level"] == expected_level


@pytest.mark.parametrize("rule_id", ["VSL-VM-001", "VSL-VM-007", "VSL-VM-022"])
def test_three_snapshot_rules_share_fixed_p2(rule_id) -> None:
    rules = RulePackLoader().load_raw(ROOT / "rulepacks" / "builtin-vsphere-v1")
    rule = SchemaValidator().validate_rule(next(item for item in rules if item["rule_id"] == rule_id))
    assert rule.risk_level.value == "P2"
    assert rule.severity_policy.default_level.value == "P2"
    assert rule.severity_policy.type == "fixed"
