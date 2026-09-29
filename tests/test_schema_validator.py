import copy

import pytest

from vstacklens.rules.rulepack_loader import RulePackLoader
from vstacklens.rules.registry import RuleRegistry
from vstacklens.rules.schema_validator import SchemaValidator


def valid_rule() -> dict:
    return RulePackLoader().load_raw("rulepacks/builtin-vsphere-v1")[0]


def test_schema_validator_accepts_builtin_rules() -> None:
    validator = SchemaValidator()
    for raw in RulePackLoader().load_raw("rulepacks/builtin-vsphere-v1"):
        validator.validate_rule(raw)


def test_rule_registry_filters_default_executable_rules() -> None:
    validator = SchemaValidator()
    rules = [validator.validate_rule(raw) for raw in RulePackLoader().load_raw("rulepacks/builtin-vsphere-v1")]
    registry = RuleRegistry()
    registry.register(rules)

    assert len(registry.rules) == 67
    assert len(registry.executable_rules) == 67
    executable_ids = {rule.rule_id for rule in registry.executable_rules}
    all_rule_ids = {rule.rule_id for rule in registry.rules}
    assert executable_ids == all_rule_ids
    assert {"VSL-DS-003", "VSL-VC-003", "VSL-VC-007", "VSL-VSAN-001", "VSL-CAP-002"}.isdisjoint(all_rule_ids)
    assert {"VSL-NET-001", "VSL-NET-006", "VSL-DS-004", "VSL-DS-005"}.isdisjoint(all_rule_ids)
    assert {"VSL-CL-007", "VSL-HOST-016", "VSL-VM-022", "VSL-DS-007", "VSL-VM-014", "VSL-SEC-002"} <= executable_ids
    assert {"VSL-CL-009", "VSL-CL-016", "VSL-VM-016", "VSL-VM-017", "VSL-VM-021"} <= executable_ids
    assert {"VSL-VM-023", "VSL-HOST-024", "VSL-DS-020", "VSL-HOST-026"} <= executable_ids
    assert {"VSL-CL-008", "VSL-NET-015", "VSL-VM-024", "VSL-HOST-025", "VSL-DS-019"}.isdisjoint(executable_ids)
    for rule in registry.rules:
        assert rule.implementation_status.value == "implemented"
        assert rule.execution_mode.value == "default_enabled"


def test_current_rulepack_has_no_planned_optional_or_disabled_rules() -> None:
    rules = [SchemaValidator().validate_rule(raw) for raw in RulePackLoader().load_raw("rulepacks/builtin-vsphere-v1")]
    assert rules
    for rule in rules:
        assert rule.implementation_status.value not in {"planned", "optional_plugin", "deprecated"}
        assert rule.execution_mode.value not in {"disabled_by_default", "optional_enabled", "plugin_required"}


def test_all_catalog_rules_have_neutral_check_names() -> None:
    validator = SchemaValidator()
    rules = [validator.validate_rule(raw) for raw in RulePackLoader().load_raw("rulepacks/builtin-vsphere-v1")]
    registry = RuleRegistry()
    registry.register(rules)

    forbidden_terms = [
        "是否",
        "存在",
        "失败",
        "异常",
        "未启用",
        "未开启",
        "未配置",
        "过高",
        "过低",
        "过旧",
        "即将过期",
        "不一致",
        "不足",
        "缺失",
        "无最近",
        "不可访问",
        "降速",
        "断链",
    ]

    assert len(registry.rules) == 67
    assert len(registry.executable_rules) == 67
    for rule in registry.rules:
        check_name = rule.report_fields.check_name_zh
        finding_title = rule.report_fields.finding_title_zh
        assert check_name, f"{rule.rule_id} missing check_name_zh"
        assert finding_title, f"{rule.rule_id} missing finding_title_zh"
        assert rule.report_fields.plain_summary_zh, f"{rule.rule_id} missing plain_summary_zh"
        assert rule.report_fields.failed_summary_zh, f"{rule.rule_id} missing failed_summary_zh"
        assert not any(term in check_name for term in forbidden_terms), f"{rule.rule_id} has result-like check name: {check_name}"


def test_m2c_reviewed_rules_have_exception_guidance_and_parameters() -> None:
    validator = SchemaValidator()
    rules = [validator.validate_rule(raw) for raw in RulePackLoader().load_raw("rulepacks/builtin-vsphere-v1")]
    by_id = {rule.rule_id: rule for rule in rules}
    reviewed_ids = {
        "VSL-CL-016",
        "VSL-CL-007",
        "VSL-HOST-002",
        "VSL-HOST-004",
        "VSL-NET-004",
        "VSL-VM-012",
        "VSL-VM-015",
        "VSL-VM-021",
    }

    for rule_id in reviewed_ids:
        fields = by_id[rule_id].report_fields
        assert fields.false_positive_notes_zh, f"{rule_id} missing false_positive_notes_zh"
        assert fields.exception_guidance_zh, f"{rule_id} missing exception_guidance_zh"
        assert fields.when_to_ignore_zh, f"{rule_id} missing when_to_ignore_zh"

    assert by_id["VSL-VM-012"].parameters["max_vcpu_count"]["default"] == 8
    assert by_id["VSL-VM-012"].parameters["max_vcpu_count"]["override_allowed"] is True
    assert "max_vcpu_count" in by_id["VSL-VM-012"].condition.fail_when
    assert by_id["VSL-VM-015"].parameters["min_hardware_version"]["default"] == 15
    assert "min_hardware_version" in by_id["VSL-VM-015"].condition.fail_when
    assert by_id["VSL-VC-005"].parameters["certificate_warning_days"]["default"] == 90
    assert by_id["VSL-VC-005"].parameters["certificate_critical_days"]["default"] == 30


def test_schema_validator_requires_report_fields() -> None:
    raw = copy.deepcopy(valid_rule())
    raw["report_fields"]["business_impact_zh"] = ""
    with pytest.raises(ValueError, match="business_impact_zh"):
        SchemaValidator().validate_rule(raw)


def test_schema_validator_requires_remediation_steps() -> None:
    raw = copy.deepcopy(valid_rule())
    raw["remediation"]["steps_zh"] = []
    with pytest.raises(ValueError, match="steps_zh"):
        SchemaValidator().validate_rule(raw)


def test_schema_validator_requires_current_value_path() -> None:
    raw = copy.deepcopy(valid_rule())
    raw["evidence_schema"].pop("current_value_path")
    with pytest.raises(ValueError, match="current_value_path"):
        SchemaValidator().validate_rule(raw)


def test_condition_allows_missing_pass_when_when_schema_flag_is_enabled() -> None:
    raw = copy.deepcopy(valid_rule())
    raw["condition"].pop("pass_when", None)
    raw["condition"]["allow_missing_pass_when"] = True

    rule = SchemaValidator().validate_rule(raw)

    assert rule.condition.pass_when is None
    assert rule.condition.allow_missing_pass_when is True


def test_condition_requires_pass_when_without_explicit_schema_flag() -> None:
    raw = copy.deepcopy(valid_rule())
    raw["condition"].pop("pass_when", None)

    with pytest.raises(ValueError, match="pass_when"):
        SchemaValidator().validate_rule(raw)


def test_schema_validator_rejects_invalid_severity_policy() -> None:
    raw = copy.deepcopy(valid_rule())
    raw["severity_policy"] = {"type": "threshold", "default_level": "P3", "rules": [{"when": "used_percent >=", "level": "P1"}]}
    with pytest.raises(ValueError, match="invalid severity expression"):
        SchemaValidator().validate_rule(raw)
