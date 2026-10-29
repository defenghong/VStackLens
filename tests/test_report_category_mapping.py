from pathlib import Path

from vstacklens.reports.category_mapping import FindingCategoryMapper, map_findings_to_categories as map_recorded_findings, report_category_count
from vstacklens.reports.customer_caliber import yaml_rules
from vstacklens.reports.rule_provenance import capture_rule
from vstacklens.rules.rulepack_loader import RulePackLoader
from vstacklens.rules.schema_validator import SchemaValidator


ROOT = Path(__file__).resolve().parents[1]


def current_findings(findings):
    """These mapping fixtures represent fresh executions with captured evidence."""
    output = []
    for finding in findings:
        item = dict(finding)
        rule = yaml_rules().get(item.get("grade_source_rule_id") or item.get("rule_id"))
        if rule:
            parameters = {key: value["default"] for key, value in (rule.get("parameters") or {}).items()}
            item["rule_snapshot"] = capture_rule(rule, parameters)
        output.append(item)
    return output


def map_findings_to_categories(findings, **kwargs):
    return map_recorded_findings(current_findings(findings), **kwargs)


def test_snapshot_rules_merge_and_deduplicate_same_vm() -> None:
    findings = [
        {"rule_id": "VSL-VM-001", "object_key": "vm-1", "object_name": "VM-A"},
        {"rule_id": "VSL-VM-007", "object_key": "vm-1", "object_name": "VM-A"},
        {"rule_id": "VSL-VM-022", "object_key": "vm-1", "object_name": "VM-A"},
    ]
    result = map_findings_to_categories(findings)
    category = next(item for item in result.categories if item["category_id"] == "VM-SNAPSHOT")
    assert result.risk_category_summary["P2"] == 1
    assert category["affected_object_count"] == 1
    assert set(category["subreasons"]) == {"超期快照", "快照链过深", "Consolidation Needed"}


def test_snapshot_category_counts_three_objects_once() -> None:
    result = FindingCategoryMapper().map(current_findings([
        {"rule_id": "VSL-VM-001", "object_key": "a", "object_name": "VM-A"},
        {"rule_id": "VSL-VM-007", "object_key": "b", "object_name": "VM-B"},
        {"rule_id": "VSL-VM-022", "object_key": "c", "object_name": "VM-C"},
    ]))
    category = next(item for item in result.categories if item["category_id"] == "VM-SNAPSHOT")
    assert result.risk_category_summary == {"P1": 0, "P2": 1, "P3": 0, "P4": 0}
    assert result.affected_object_summary["P2"] == 3
    assert category["affected_object_count"] == 3


def test_ssh_and_shell_merge_same_host() -> None:
    result = map_findings_to_categories([
        {"rule_id": "VSL-HOST-002", "object_key": "h1", "object_name": "esxi-01"},
        {"rule_id": "VSL-HOST-016", "object_key": "h1", "object_name": "esxi-01"},
    ])
    category = next(item for item in result.categories if item["category_id"] == "HOST-MANAGEMENT-SERVICE")
    assert result.risk_category_summary["P3"] == 1
    assert category["affected_object_count"] == 1
    assert category["subreasons"] == ["SSH", "ESXi Shell"]


def test_resource_rules_merge_but_keep_subreasons() -> None:
    result = map_findings_to_categories([
        {"rule_id": "VSL-VM-010", "object_key": "vm-1", "object_name": "VM-A"},
        {"rule_id": "VSL-VM-011", "object_key": "vm-1", "object_name": "VM-A"},
        {"rule_id": "VSL-VM-012", "object_key": "vm-1", "object_name": "VM-A"},
    ])
    category = next(item for item in result.categories if item["category_id"] == "VM-RESOURCE-CONFIG")
    assert result.risk_category_summary["P3"] == 1
    assert category["affected_object_count"] == 1
    assert set(category["subreasons"]) == {"Reservation", "Limit"}
    assert result.hidden_findings[0]["non_report_reason"] == "P4"


def test_hidden_p4_information_and_pending_rule_are_not_standard_risks() -> None:
    result = map_findings_to_categories([
        {"rule_id": "VSL-VM-015", "object_key": "vm-1", "object_name": "VM-A", "risk_level": "P4"},
        {"rule_id": "VSL-VM-021", "object_key": "vm-1", "object_name": "VM-A", "risk_level": "P1"},
    ])
    assert result.risk_category_summary == {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    assert "VSL-VM-021" in result.pending_rules
    assert not result.categories


def test_context_sensitive_categories_and_threshold_semantics() -> None:
    vsan = map_findings_to_categories([{"rule_id": "VSL-CL-009", "object_key": "c", "object_name": "vSAN-C"}], vsan_applicable=True)
    normal = map_findings_to_categories([{"rule_id": "VSL-CL-009", "object_key": "c", "object_name": "C"}], vsan_applicable=False)
    assert vsan.categories[0]["priority"] == "P3"
    assert normal.categories[0]["priority"] == "P3"
    for value in (5, 10, 15):
        result = map_findings_to_categories([{"rule_id": "VSL-VM-004", "object_key": "vm", "object_name": "VM", "current_value": value, "risk_level": "P1" if value >= 10 else "P2"}])
        assert result.categories[0]["priority"] == ("P1" if value >= 10 else "P2")


def test_vsan_resync_activity_alone_is_not_a_finding_and_ds020_is_bridge() -> None:
    result = map_findings_to_categories([
        {"rule_id": "VSAN-05", "object_key": "cluster", "object_name": "vSAN", "evidence": {"totalObjectsToSync": 2}},
        {"rule_id": "VSL-DS-020", "object_key": "ds", "object_name": "vsanDatastore"},
        {"rule_id": "VSAN-01", "object_key": "cluster", "object_name": "vSAN", "grade_source_rule_id": "VSL-DS-020"},
    ], vsan_applicable=True)
    assert [item["category_id"] for item in result.categories] == ["VSAN-CLUSTER-HEALTH"]


def test_catalog_is_explicit_and_unknown_rules_are_reported() -> None:
    result = map_findings_to_categories([{"rule_id": "VSL-NEW-999", "object_name": "x"}])
    assert report_category_count() >= 50
    assert result.unmapped_rules == ["VSL-NEW-999"]


def test_iso_and_powered_off_rules_are_p3_in_rulepack_and_report_categories() -> None:
    raw_rules = RulePackLoader().load_raw(ROOT / "rulepacks" / "builtin-vsphere-v1")
    rules = [SchemaValidator().validate_rule(raw) for raw in raw_rules]
    levels = {rule.rule_id: rule.risk_level for rule in rules if rule.rule_id in {"VSL-VM-006", "VSL-VM-018"}}
    assert levels == {"VSL-VM-006": "P3", "VSL-VM-018": "P3"}

    for rule_id, category_id in (("VSL-VM-006", "VM-CDROM"), ("VSL-VM-018", "VM-LONG-POWERED-OFF")):
        mapped = FindingCategoryMapper().map(current_findings([{"rule_id": rule_id, "object_key": rule_id, "object_name": rule_id}]))
        category = next(item for item in mapped.categories if item["category_id"] == category_id)
        assert category["priority"] == "P3"


def test_legacy_finding_without_grade_or_rule_evidence_is_not_guessed():
    result = map_recorded_findings([{"rule_id": "VSL-VM-001", "object_name": "old-vm"}])
    assert not result.categories
    assert result.hidden_findings[0]["report_status"] == "NEEDS_REVIEW"
    assert result.hidden_findings[0]["non_report_reason"] == "待映射"


def test_every_enabled_rule_has_customer_disposition() -> None:
    """Each enabled YAML rule is registered, denied, P4, or an internal bridge."""
    from vstacklens.reports.category_mapping import RULE_TO_CATEGORY
    from vstacklens.reports.customer_caliber import DENIED_RULES, INTERNAL_BRIDGE_RULES

    rules = RulePackLoader().load_raw(ROOT / "rulepacks" / "builtin-vsphere-v1")
    missing = [
        f"{rule['rule_id']} | {rule['rule_name']} | {rule['risk_level']}"
        for rule in rules
        if rule.get("enabled")
        and rule["rule_id"] not in RULE_TO_CATEGORY
        and rule["rule_id"] not in DENIED_RULES
        and rule["rule_id"] not in INTERNAL_BRIDGE_RULES
        and rule["risk_level"] != "P4"
    ]
    assert not missing, "启用规则未登记类别、未列入不报清单、不是 P4 且不是内部桥接：\n" + "\n".join(sorted(missing))
