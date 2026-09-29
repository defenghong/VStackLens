from __future__ import annotations

from pathlib import Path

from vstacklens.cli import build_parser
from vstacklens.collection.capability_probe import ProbeObservation, ProbeSpec, summarize_probe, write_probe_html, write_probe_json
from vstacklens.rules.registry import RuleRegistry
from vstacklens.rules.rulepack_loader import RulePackLoader
from vstacklens.rules.schema_validator import SchemaValidator


ROOT = Path(__file__).resolve().parents[1]
RULEPACK = ROOT / "rulepacks" / "builtin-vsphere-v1"


M2A_RULE_IDS = {
    "VSL-CL-007",
    "VSL-CL-013",
    "VSL-HOST-016",
    "VSL-HOST-019",
    "VSL-HOST-020",
    "VSL-NET-004",
    "VSL-VM-010",
    "VSL-VM-011",
    "VSL-VM-012",
    "VSL-VM-015",
    "VSL-VM-022",
}

M2B1_RULE_IDS = {
    "VSL-CL-009",
    "VSL-CL-016",
    "VSL-VM-016",
    "VSL-VM-017",
    "VSL-VM-021",
}


def load_registry() -> RuleRegistry:
    rules = [SchemaValidator().validate_rule(raw) for raw in RulePackLoader().load_raw(RULEPACK)]
    registry = RuleRegistry()
    registry.register(rules)
    return registry


def test_promoted_rule_copy_is_customer_ready_and_default_count_is_m2b1() -> None:
    registry = load_registry()
    assert len(registry.rules) == 67
    assert len(registry.executable_rules) == 67
    by_id = {rule.rule_id: rule for rule in registry.rules}
    forbidden = ["目录展示", "后续补齐", "当前版本将该项纳入规则目录", "插件后再进入执行链路"]
    for rule_id in M2A_RULE_IDS | M2B1_RULE_IDS:
        rule = by_id[rule_id]
        text = " ".join(
            [
                rule.report_fields.title_zh,
                rule.report_fields.summary_zh,
                rule.report_fields.business_impact_zh,
                rule.report_fields.technical_impact_zh,
                rule.report_fields.consequence_zh,
                rule.report_fields.remediation_zh,
                " ".join(rule.remediation.steps_zh),
            ]
        )
        assert all(item not in text for item in forbidden), rule_id
        assert rule.remediation.verification_method in {"rerun_rule", "manual_check", "command_check"}
        assert rule.remediation.steps_zh
    for rule_id in {"VSL-NET-005", "VSL-NET-007", "VSL-NET-008", "VSL-NET-010", "VSL-NET-012"}:
        assert rule_id not in by_id


def test_probe_summary_classifies_ready_unstable_and_unsupported() -> None:
    spec = ProbeSpec("VSL-TEST-001", "field", "HostSystem", "测试字段", "test")
    ready = summarize_probe(
        spec,
        [
            ProbeObservation("host-1", 0),
            ProbeObservation("host-2", 1),
        ],
    )
    assert ready["recommendation"] == "ready_for_default_enabled"
    assert ready["coverage"] == 1.0
    assert ready["sample_values"] == [0, 1]

    unstable = summarize_probe(
        spec,
        [
            ProbeObservation("host-1", 0),
            ProbeObservation("host-2", None, "property unavailable"),
        ],
    )
    assert unstable["recommendation"] == "unstable"
    assert unstable["coverage"] == 0.5

    unsupported = summarize_probe(
        spec,
        [
            ProbeObservation("host-1", None, "requires PerformanceManager metric sampling; not enabled in M2-B probe"),
        ],
    )
    assert unsupported["recommendation"] == "unsupported"


def test_probe_writers_and_cli_parser(tmp_path: Path) -> None:
    report = {
        "generated_at": "2026-06-03T00:00:00+00:00",
        "vcenter": "vc.local",
        "candidate_count": 1,
        "results": [
            {
                "rule_id": "VSL-DS-007",
                "field": "multipath_issue_count",
                "object_type": "Datastore",
                "title": "Datastore 多路径状态异常",
                "object_total": 1,
                "value_count": 1,
                "none_count": 0,
                "coverage": 1.0,
                "sample_values": [0],
                "sample_objects": ["ds-1"],
                "recommendation": "ready_for_default_enabled",
                "unstable_reason": "",
            }
        ],
    }
    json_path = write_probe_json(report, tmp_path / "probe-capabilities.json")
    html_path = write_probe_html(report, tmp_path / "probe-capabilities.html")
    assert json_path.exists()
    assert html_path.exists()
    assert "VSL-DS-007" in html_path.read_text(encoding="utf-8")

    parser = build_parser()
    args = parser.parse_args(
        [
            "probe-vcenter-capabilities",
            "--vcenter",
            "vc.local",
            "--username",
            "administrator@vsphere.local",
            "--password",
            "secret",
            "--ssl-no-verify",
        ]
    )
    assert args.vcenter == "vc.local"

    run_probe = parser.parse_args(
        [
            "run-vcenter",
            "--probe-only",
            "--vcenter",
            "vc.local",
            "--username",
            "administrator@vsphere.local",
            "--password",
            "secret",
            "--ssl-no-verify",
        ]
    )
    assert run_probe.probe_only is True
