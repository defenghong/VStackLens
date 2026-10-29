"""Approved applicability is a scoped copy, never a new threshold evaluation."""
from collections import Counter
from copy import deepcopy
from types import SimpleNamespace

import pytest

from vstacklens.reports.customer_caliber import (
    APPROVED_PROJECTION_VERSION, approved_result_projection, calculate, ensure_report, reinterpret_report,
)
from vstacklens.reports.rule_provenance import capture_rule


RUN, VC, UUID = "run-frozen", "vc-stable", "instance-stable"


def result(rule, kind, key, status="passed", grade="P3"):
    definition = {"rule_id": rule, "parameters": {}, "risk_level": grade,
                  "severity_policy": {"type": "fixed", "default_level": grade},
                  "report_fields": {"finding_title_zh": rule}, "rule_version": "saved-only"}
    evidence = {"run_id": RUN, "vcenter_id": VC, "object_type": kind, "object_key": key,
                "rule_snapshot": capture_rule(definition, {})}
    return {"result_id": f"result:{rule}:{key}", "run_id": RUN, "vcenter_id": VC,
            "rule_id": rule, "rule_name": rule, "object_type": kind, "object_key": key,
            "object_name": key, "result_status": status, "risk_level": grade if status == "failed" else None,
            "health_impact": "none", "evidence": evidence}


def asset(kind, key, **properties):
    return {"object_type": kind, "object_key": key, "object_name": key,
            "properties": {"sdk_property_observations": {
                "run_id": RUN, "vcenter_instance_uuid": UUID}, **properties}}


def report():
    records = [result("VSL-VC-001", "vCenter", UUID),
               result("VSL-VM-023", "VirtualMachine", "template", "failed"),
               result("VSL-VM-001", "VirtualMachine", "template"),
               result("VSL-VM-004", "VirtualMachine", "template", "unavailable"),
               result("VSL-VM-015", "VirtualMachine", "template", "failed", "P4"),
               result("VSL-VM-002", "VirtualMachine", "template"),
               result("VSL-VM-023", "VirtualMachine", "normal", "failed"),
               result("VSL-VM-010", "VirtualMachine", "nsx-manager", "failed"),
               result("VSL-VM-023", "VirtualMachine", "vcls", "failed")]
    for rule, grade in (("VSL-CL-002", "P2"), ("VSL-CL-009", "P3"),
                        ("VSL-CL-004", "P4"), ("VSL-CL-012", "P4")):
        records.append(result(rule, "ClusterComputeResource", "off", grade=grade))
        records.append(result(rule, "ClusterComputeResource", "on", grade=grade))
    records += [result("VSL-CL-001", "ClusterComputeResource", "off", "failed", "P2"),
                result("VSL-CL-003", "ClusterComputeResource", "off", "failed")]
    assets = {"vCenter": [asset("vCenter", UUID)],
              "VirtualMachine": [asset("VirtualMachine", "template", is_template=True),
                                 asset("VirtualMachine", "normal", is_template=False),
                                 asset("VirtualMachine", "nsx-manager", is_template=False, is_system_vm=False),
                                 asset("VirtualMachine", "vcls", is_template=False, is_system_vm=True)],
              "ClusterComputeResource": [asset("ClusterComputeResource", "off", ha_enabled=False, drs_enabled=False),
                                         asset("ClusterComputeResource", "on", ha_enabled=True, drs_enabled=True)]}
    findings = deepcopy([row for row in records if row["result_status"] == "failed"])
    checklist = []
    for rule in dict.fromkeys(row["rule_id"] for row in records):
        matching = [row for row in records if row["rule_id"] == rule]
        checklist.append({"rule_id": rule, "rule_name": rule,
                          "rule_snapshot": deepcopy(matching[0]["evidence"]["rule_snapshot"]),
                          **Counter(row["result_status"] for row in matching)})
    calibrated = calculate(findings, records=records, assets=assets, asset_total=7,
                           critical_gap_count=0, run_id=RUN)
    return SimpleNamespace(
        report_info=SimpleNamespace(run_id=RUN),
        caliber_inputs={"object_results": records, "findings": findings},
        findings=deepcopy(findings), asset_inventory={"details": assets, "total": 7},
        appendix={"rule_checklist": checklist, "critical_gap_count": 0}, customer_caliber=calibrated,
        environment_summary=SimpleNamespace(result_status_summary=dict(Counter(row["result_status"] for row in records))),
        risk_summary=SimpleNamespace(), health_score=SimpleNamespace(), report_presentation={},
    )


def by_identity(rows, rule, key):
    return next(row for row in rows if row["rule_id"] == rule and row["object_key"] == key)


def test_projection_is_a_pure_copy_including_saved_rules_and_unavailable_template_results():
    source = report()
    before = deepcopy(source.__dict__)
    projected = approved_result_projection(source)
    assert source.__dict__ == before
    assert projected["version"] == APPROVED_PROJECTION_VERSION
    assert len(projected["changes"]) == 9  # Five template records and four disabled-feature records.
    for original, revised in zip(source.caliber_inputs["object_results"], projected["object_results"]):
        assert original["evidence"] == revised["evidence"]
        assert original["risk_level"] == revised["risk_level"]
        if revised["object_key"] == "template":
            assert revised["result_status"] == "not_applicable"
    projected["object_results"][1]["evidence"]["rule_snapshot"]["sha256"] = "changed-by-consumer"
    assert source.__dict__ == before
    assert approved_result_projection(source)["object_results"][1]["evidence"] == before["caliber_inputs"]["object_results"][1]["evidence"]


def test_only_explicit_template_identity_and_four_approved_cluster_rules_change():
    source = report()
    source.asset_inventory["details"]["VirtualMachine"][1]["object_name"] = "looks-like-a-template-tpl"
    projected = approved_result_projection(source)
    for rule, key in (("VSL-VM-023", "normal"), ("VSL-VM-010", "nsx-manager"),
                      ("VSL-VM-023", "vcls"), ("VSL-CL-001", "off"), ("VSL-CL-003", "off")):
        assert by_identity(projected["object_results"], rule, key)["result_status"] == "failed"
    assert by_identity(projected["object_results"], "VSL-CL-002", "on")["result_status"] == "passed"
    assert by_identity(projected["object_results"], "VSL-CL-009", "on")["result_status"] == "passed"
    check = next(item for item in projected["rule_checklist"] if item["rule_id"] == "VSL-CL-002")
    assert check["passed"] == check["not_applicable"] == 1 and check["failed"] == 0


@pytest.mark.parametrize("mismatch", ["asset-run", "asset-uuid", "asset-conflicting-run", "record-run",
                                      "record-vcenter", "evidence-object", "duplicate-asset"])
def test_scope_mismatch_or_duplicate_identity_cannot_apply_template_projection(mismatch):
    source = report()
    target = source.asset_inventory["details"]["VirtualMachine"][0]
    row = by_identity(source.caliber_inputs["object_results"], "VSL-VM-023", "template")
    if mismatch == "asset-run":
        target["properties"]["sdk_property_observations"]["run_id"] = "another-run"
    elif mismatch == "asset-uuid":
        target["properties"]["sdk_property_observations"]["vcenter_instance_uuid"] = "another-instance"
    elif mismatch == "asset-conflicting-run":
        target["run_id"] = RUN
        target["properties"]["sdk_property_observations"]["run_id"] = "another-run"
    elif mismatch == "record-run":
        row["run_id"] = "another-run"
    elif mismatch == "record-vcenter":
        row["vcenter_id"] = "another-vcenter"
    elif mismatch == "evidence-object":
        row["evidence"]["object_key"] = "another-template"
    else:
        source.asset_inventory["details"]["VirtualMachine"].append(deepcopy(target))
    projected = approved_result_projection(source)
    assert by_identity(projected["object_results"], "VSL-VM-023", "template")["result_status"] == "failed"


@pytest.mark.parametrize("flag", [False, None, "true", 1])
def test_template_requires_a_saved_boolean_true(flag):
    source = report()
    source.asset_inventory["details"]["VirtualMachine"][0]["properties"]["is_template"] = flag
    projected = approved_result_projection(source)
    assert by_identity(projected["object_results"], "VSL-VM-023", "template")["result_status"] == "failed"


def test_existing_na_is_not_a_change_and_returned_checklist_is_independent():
    source = report()
    row = by_identity(source.caliber_inputs["object_results"], "VSL-VM-001", "template")
    row["result_status"] = "not_applicable"
    projected = approved_result_projection(source)
    assert not any(change["result_id"] == row["result_id"] for change in projected["changes"])
    projected["rule_checklist"][0]["rule_snapshot"]["definition"]["rule_version"] = "consumer-change"
    assert source.appendix["rule_checklist"][0]["rule_snapshot"]["definition"]["rule_version"] == "saved-only"


def test_projection_and_ensure_report_never_consult_current_rules_or_threshold_evaluator(monkeypatch):
    source = report()

    def forbidden(*args, **kwargs):
        raise AssertionError("The frozen approved projection must not evaluate today's rules")

    monkeypatch.setattr("vstacklens.reports.customer_caliber.yaml_rules", forbidden)
    monkeypatch.setattr("vstacklens.rules.safe_expression.SafeExpressionEngine.evaluate", forbidden)
    before = deepcopy((source.caliber_inputs, source.findings, source.appendix))
    caliber = ensure_report(source)
    assert (source.caliber_inputs, source.findings, source.appendix) == before
    assert caliber["approved_projection"]["original_result_preserved"] is True
    assert caliber["judgment_provenance"]["mode"] == "APPROVED_APPLICABILITY_PROJECTION"
    assert not any(row["object_key"] == "template" for row in caliber["findings"])


def test_report_local_caliber_cache_is_stable_then_invalidates_on_source_change():
    source = report()
    first = ensure_report(source)
    assert ensure_report(source) is first
    first_fingerprint = first["approved_projection"]["source"]["fingerprint"]
    source.asset_inventory["details"]["VirtualMachine"][0]["properties"]["is_template"] = False
    second = ensure_report(source)
    assert second is not first
    assert second["approved_projection"]["source"]["fingerprint"] != first_fingerprint
    assert any(row["object_key"] == "template" for row in second["findings"])
    independent = report()
    assert ensure_report(independent) is not first


def test_no_applicability_change_reuses_the_saved_caliber_and_empty_inputs_do_not_fall_back():
    source = report()
    source.asset_inventory["details"]["VirtualMachine"][0]["properties"]["is_template"] = False
    off = source.asset_inventory["details"]["ClusterComputeResource"][0]["properties"]
    off.update(ha_enabled=True, drs_enabled=True)
    original = source.customer_caliber
    first = ensure_report(source)
    assert first is original  # Captured rows authenticate this unchanged historical conclusion.
    assert "source_identity" not in first
    assert source._customer_caliber_cache["source"] == approved_result_projection(source)["source"]
    assert ensure_report(source) is first
    source.caliber_inputs["object_results"] = []
    projection = approved_result_projection(source, {"object_results": [result("VSL-VM-023", "VirtualMachine", "template", "failed")]})
    assert projection["object_results"] == []
    assert projection["source"]["records_available"] is False


def unchanged_report():
    source = report()
    source.asset_inventory["details"]["VirtualMachine"][0]["properties"]["is_template"] = False
    source.asset_inventory["details"]["ClusterComputeResource"][0]["properties"].update(
        ha_enabled=True, drs_enabled=True)
    return source


@pytest.mark.parametrize("switch", ["run", "same-run-vcenter", "record-status", "record-evidence",
                                   "finding", "applicability-asset"])
def test_unchanged_cache_is_invalidated_for_every_source_identity_change(switch):
    source = unchanged_report()
    first = ensure_report(source)
    first_source = deepcopy(source._customer_caliber_cache["source"])
    assert "approved_projection" not in first
    assert not approved_result_projection(source)["changes"]
    if switch == "run":
        source.report_info.run_id = "run-next"
        for rows in (source.caliber_inputs["object_results"], source.caliber_inputs["findings"], source.findings):
            for row in rows:
                row["run_id"] = "run-next"
                row["evidence"]["run_id"] = "run-next"
        for rows in source.asset_inventory["details"].values():
            for asset_row in rows:
                asset_row["properties"]["sdk_property_observations"]["run_id"] = "run-next"
    elif switch == "same-run-vcenter":
        for rows in (source.caliber_inputs["object_results"], source.caliber_inputs["findings"], source.findings):
            for row in rows:
                row["vcenter_id"] = "vc-next"
                row["evidence"]["vcenter_id"] = "vc-next"
                if row["object_type"] == "vCenter":
                    row["object_key"] = "instance-next"
                    row["evidence"]["object_key"] = "instance-next"
        for rows in source.asset_inventory["details"].values():
            for asset_row in rows:
                asset_row["properties"]["sdk_property_observations"]["vcenter_instance_uuid"] = "instance-next"
                if asset_row["object_type"] == "vCenter":
                    asset_row["object_key"] = "instance-next"
    elif switch == "record-status":
        by_identity(source.caliber_inputs["object_results"], "VSL-VM-023", "normal")["result_status"] = "passed"
    elif switch == "record-evidence":
        by_identity(source.caliber_inputs["object_results"], "VSL-VM-023", "normal")["evidence"]["collected_at"] = "new-capture"
    elif switch == "finding":
        by_identity(source.caliber_inputs["findings"], "VSL-VM-023", "normal")["business_impact"] = "Changed source explanation"
    elif switch == "applicability-asset":
        source.asset_inventory["details"]["VirtualMachine"][0]["properties"]["is_template"] = None
    preserved = deepcopy((source.caliber_inputs, source.findings, source.appendix))
    second = ensure_report(source)
    assert second is not first
    assert second["run_id"] == source.report_info.run_id
    assert source._customer_caliber_cache["source"] == approved_result_projection(source)["source"]
    assert source._customer_caliber_cache["source"]["fingerprint"] != first_source["fingerprint"]
    assert (source.caliber_inputs, source.findings, source.appendix) == preserved
    assert not approved_result_projection(source)["changes"]
    if switch == "same-run-vcenter":
        assert source._customer_caliber_cache["source"]["vcenter_ids"] == ["vc-next"]
        assert all(row["vcenter_id"] == "vc-next" for row in second["object_results"])
    if switch == "record-status":
        assert by_identity(second["object_results"], "VSL-VM-023", "normal")["result_status"] == "passed"
    assert ensure_report(source) is second


def test_explicit_reinterpretation_is_authenticated_without_being_undone_by_cache_refresh():
    source = unchanged_report()
    source.model_copy = lambda deep: deepcopy(source)
    by_identity(source.caliber_inputs["object_results"], "VSL-VM-023", "normal")["current_value"] = False
    rule = {"rule_id": "VSL-VM-023", "parameters": {}, "risk_level": "P3",
            "severity_policy": {"type": "fixed", "default_level": "P3"},
            "condition": {"type": "safe_expression", "fail_when": "storage_is_local == True",
                          "pass_when": "storage_is_local == False"},
            "evidence_schema": {"current_value_path": "storage_is_local", "expected_value": False},
            "report_fields": {"finding_title_zh": "saved separately"}}
    revised = reinterpret_report(source, rules={"VSL-VM-023": rule})
    caliber = revised.customer_caliber
    assert caliber["judgment_provenance"]["mode"] == "EXPLICIT_REINTERPRETATION"
    assert by_identity(caliber["object_results"], "VSL-VM-023", "normal")["result_status"] == "passed"
    assert revised._customer_caliber_cache["source"] == approved_result_projection(revised)["source"]
    assert ensure_report(revised) is caliber
    assert by_identity(source.caliber_inputs["object_results"], "VSL-VM-023", "normal")["result_status"] == "failed"


@pytest.mark.parametrize("diagnostic", ["asset-total", "critical-gap", "status-summary"])
def test_diagnostic_only_changes_preserve_the_saved_conclusion_without_recalculation(monkeypatch, diagnostic):
    source = unchanged_report()
    original = source.customer_caliber
    original_bytes = deepcopy(original)
    assert ensure_report(source) is original

    def forbidden(*args, **kwargs):
        raise AssertionError("A diagnostic display change must not rejudge a saved conclusion")

    monkeypatch.setattr("vstacklens.reports.customer_caliber.calculate", forbidden)
    if diagnostic == "asset-total":
        source.asset_inventory["total"] = 0
    elif diagnostic == "critical-gap":
        source.appendix["critical_gap_count"] = 100
    else:
        source.environment_summary.result_status_summary = {"unavailable": 500}
    assert ensure_report(source) is original
    assert source.customer_caliber == original_bytes


def test_private_report_cache_does_not_modify_or_serialize_into_saved_caliber():
    from vstacklens.reports.report_model import ReportData

    plain = unchanged_report()
    source = ReportData.model_validate({
        "report_info": {"report_id": "saved", "run_id": RUN, "generated_at": "2026-10-22T00:00:00Z"},
        "customer_info": {"customer_name": "saved", "site_name": "saved", "vcenter": "vc.test"},
        "environment_summary": {"scope_statement": "saved", "checked_object_total": 7,
                                "result_status_summary": plain.environment_summary.result_status_summary},
        "health_score": {"score": 80, "grade": "关注", "explanation": "saved"}, "risk_summary": {},
        "customer_caliber": plain.customer_caliber, "caliber_inputs": plain.caliber_inputs,
        "asset_inventory": plain.asset_inventory, "appendix": plain.appendix,
    })
    before = deepcopy(source.customer_caliber)
    first = source.customer_caliber
    assert ensure_report(source) is first
    assert source.customer_caliber == before
    assert source._customer_caliber_cache["caliber"] is first
    serialized = source.model_dump()
    assert "_customer_caliber_cache" not in serialized
    assert "source_identity" not in serialized["customer_caliber"]
