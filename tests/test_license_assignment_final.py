"""Independent expected outcomes for entity binding, availability and report semantics."""
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace as NS

import pytest

from vstacklens.collection.license_state import query_entity_license, fields
from vstacklens.collection.pyvmomi_collector import PyVmomiCollector
from vstacklens.reports.license_evidence import license_summary, expiry_label

NOW = datetime(2026, 10, 25, 12, tzinfo=UTC)


def license(expiry=..., *, product="VMware ESX Server", edition="esx.standard", name="SYN-LICENSE", extra=()):
    values = [NS(key="ProductName", value=product), NS(key="ProductVersion", value="8.0")]
    if expiry is not ...:
        values.append(NS(key="expirationDate", value=expiry))
    return NS(name=name, editionKey=edition, licenseKey="SYN-DO-NOT-EXPORT-KEY", properties=values + list(extra))


def assignment(info, entity="host-1", scope="vc-A", properties=()):
    return NS(entityId=entity, scope=scope, assignedLicense=info, properties=list(properties))


def content(entries, *, inventory=(), failure=None, uuid="vc-A"):
    class Manager:
        def QueryAssignedLicenses(self, *, entityId):
            if failure:
                raise failure
            return entries(entityId) if callable(entries) else entries
    class LicenseManager:
        licenseAssignmentManager = Manager()
        @property
        def licenses(self):
            raise AssertionError("Inventory must not be read as target assignment")
    return NS(about=NS(instanceUuid=uuid), licenseManager=LicenseManager())


@pytest.mark.parametrize("kind,entity,product", [("HostSystem", "host-1", "VMware ESX Server"), ("vCenter", "vc-A", "VMware VirtualCenter Server")])
@pytest.mark.parametrize("expiry,expected,days", [("Never", "perpetual", 999999), (NOW + timedelta(days=365), "dated", 365),
    (NOW + timedelta(days=15), "dated", 15), (NOW, "dated", 0), (NOW - timedelta(days=1), "dated", -1),
    (..., "unknown", None), (None, "parse_failed", None), ("not-a-date", "parse_failed", None),
    ("999999", "parse_failed", None), (False, "parse_failed", None)])
def test_expiry_matrix_for_both_target_types(kind, entity, product, expiry, expected, days):
    state = query_entity_license(content([assignment(license(expiry, product=product), entity)]), entity, kind, "vc-A", now=NOW)
    assert state["assigned"] is True
    assert state["expiration_state"] == expected
    assert state["days_remaining"] == days
    assert state["name"] == "SYN-LICENSE" and state["product_version"] == "8.0"
    assert "SYN-DO-NOT-EXPORT-KEY" not in str(state)
    projected = fields(state, host=kind == "HostSystem")
    text = license_summary(projected, kind == "HostSystem", entity)
    assert "已分配" in text
    if expected not in {"perpetual", "dated"}:
        assert "无法确认" in text and "永久授权" not in text and "正常" not in text


def test_other_products_and_stock_expirations_never_affect_target():
    entries = [assignment(license(NOW - timedelta(days=1), product="VMware vSAN", edition="vsan.enterprise")),
               assignment(license(NOW + timedelta(days=120)))]
    state = query_entity_license(content(entries), "host-1", "HostSystem", "vc-A", now=NOW)
    assert state["days_remaining"] == 120 and len(state["records"]) == 2


def test_no_assignment_is_not_unknown_or_inventory_fallback():
    state = query_entity_license(content([]), "host-1", "HostSystem", "vc-A", now=NOW)
    assert state["assignment_status"] == "unassigned" and state["assigned"] is False
    assert state["expiration_state"] == "not_assigned" and state["days_remaining"] is None


@pytest.mark.parametrize("error,status", [(PermissionError("SYN-secret-not-to-log"), "permission_denied"),
                                          (TimeoutError("SYN-secret-not-to-log"), "query_failed"),
                                          (RuntimeError("SYN-secret-not-to-log"), "query_failed")])
def test_query_errors_are_unknown_not_unassigned_and_fault_body_is_not_projected(error, status):
    state = query_entity_license(content([], failure=error), "host-1", "HostSystem", "vc-A", now=NOW)
    assert state["query_status"] == status and state["assigned"] is None and state["days_remaining"] is None
    assert state["error_type"] == type(error).__name__
    assert "SYN-secret-not-to-log" not in str(state)


@pytest.mark.parametrize("entity,scope", [("host-2", "vc-A"), ("host-1", "vc-B"), ("same-name-and-IP", "vc-A")])
def test_identity_and_scope_mismatch_never_picks_a_license_by_name(entity, scope):
    state = query_entity_license(content([assignment(license("Never"), entity, scope)]), "host-1", "HostSystem", "vc-A", now=NOW)
    assert state["query_status"] == "identity_mismatch" and state["assigned"] is None


def test_separate_vcenters_same_moid_do_not_reuse_state():
    a = query_entity_license(content([assignment(license("Never"))]), "host-1", "HostSystem", "vc-A", now=NOW)
    b = query_entity_license(content([assignment(license(), scope="vc-B")], uuid="vc-B"), "host-1", "HostSystem", "vc-B", now=NOW)
    assert a["expiration_state"] == "perpetual" and b["expiration_state"] == "unknown"


def test_targets_in_one_vcenter_do_not_mix():
    source = content(lambda key: [assignment(license("Never" if key == "host-1" else NOW + timedelta(days=8)), entity=key)])
    assert query_entity_license(source, "host-1", "HostSystem", "vc-A", now=NOW)["days_remaining"] == 999999
    assert query_entity_license(source, "host-2", "HostSystem", "vc-A", now=NOW)["days_remaining"] == 8


def test_active_evaluation_uses_its_own_expiry():
    info = license(edition="eval")
    evaluation = NS(properties=[NS(key="expirationDate", value=NOW + timedelta(days=6))])
    state = query_entity_license(content([assignment(info, properties=[NS(key="Evaluation", value=evaluation)])]), "host-1", "HostSystem", "vc-A", now=NOW)
    assert state["is_evaluation"] is True and state["days_remaining"] == 6


def test_dormant_evaluation_info_does_not_override_paid_assignment():
    evaluation = NS(properties=[NS(key="expirationDate", value=NOW - timedelta(days=100))])
    state = query_entity_license(content([assignment(license("Never"), properties=[NS(key="Evaluation", value=evaluation)])]), "host-1", "HostSystem", "vc-A", now=NOW)
    assert state["is_evaluation"] is False and state["expiration_state"] == "perpetual"


def test_evaluation_and_perpetual_conflict_is_unknown():
    state = query_entity_license(content([assignment(license("Never", edition="eval"))]), "host-1", "HostSystem", "vc-A", now=NOW)
    assert state["is_evaluation"] is True and state["days_remaining"] is None


@pytest.mark.parametrize("edition", ["eval", "vcEval", "esxEval"])
def test_explicit_evaluation_edition_aliases_do_not_depend_on_display_name(edition):
    state = query_entity_license(content([assignment(license(edition=edition, name="Unrelated display name"))]), "host-1", "HostSystem", "vc-A", now=NOW)
    assert state["is_evaluation"] is True and state["expiration_state"] == "unknown"


def test_incomplete_assignment_is_not_proof_of_no_assignment():
    state = query_entity_license(content([assignment(None)]), "host-1", "HostSystem", "vc-A", now=NOW)
    assert state["query_status"] == "partial" and state["assigned"] is None


def test_conflicting_product_fields_are_unknown_not_unassigned():
    entry = assignment(license("Never"), properties=[NS(key="ProductName", value="VMware vSAN")])
    state = query_entity_license(content([entry]), "host-1", "HostSystem", "vc-A", now=NOW)
    assert state["query_status"] == "partial" and state["assigned"] is None and state["days_remaining"] is None


def test_expiry_field_permission_failure_keeps_known_name_and_assignment():
    class Restricted:
        name = "SYN-KNOWN-NAME"
        editionKey = "esx.standard"
        @property
        def properties(self):
            raise PermissionError("must-not-be-logged")
    entry = assignment(Restricted(), properties=[NS(key="ProductName", value="VMware ESX Server")])
    state = query_entity_license(content([entry]), "host-1", "HostSystem", "vc-A", now=NOW)
    assert state["assigned"] is True and state["name"] == "SYN-KNOWN-NAME"
    assert state["expiration_state"] == "read_failed" and state["days_remaining"] is None
    assert state["query_status"] == "permission_denied" and "must-not-be-logged" not in str(state)


def test_identity_read_failure_is_preserved_on_vcenter_and_host_paths():
    class Restricted:
        @property
        def about(self):
            raise PermissionError("identity denied")
    collector = PyVmomiCollector("offline.invalid", "fixture", "fixture")
    vc = collector._vcenter_license_fields(Restricted())
    host = collector._host_license_assignments(Restricted(), [NS(_moId="host-1", config=None)])["host-1"]
    assert vc["license_evidence"]["query_status"] == "permission_denied"
    assert host["host_license_evidence"]["query_status"] == "permission_denied"


def test_legacy_word_scalar_helpers_never_certify_normal_or_perpetual():
    from vstacklens.reports.docx_report import DocxReportEngine
    engine = DocxReportEngine()
    assert "永久授权" not in engine._license_label(999999)
    assert "正常" not in engine._status_summary(365, 999999)
    assert "正常" not in engine._status_summary(365, 365)


@pytest.mark.parametrize("value", [0, 365, 999999, "999999", False, float("inf")])
@pytest.mark.parametrize("host", [False, True])
def test_unbound_legacy_numbers_cannot_be_used_as_current_assignment_evidence(value, host, rules, tmp_path):
    from vstacklens.core.context import RunContext
    from vstacklens.inventory.normalizer import InventoryNormalizer
    from vstacklens.rules.executor import RuleExecutor
    props = {"host_license_assigned": True, "host_license_is_evaluation": False, "host_license_name": "OLD",
             "host_license_edition": "OLD", "host_license_expiration_date": "永久授权", "host_license_expiration_days": value} if host else {"license_days_remaining": value}
    kind = "HostSystem" if host else "vCenter"
    inventory = InventoryNormalizer().normalize({"objects": [{"object_type": kind, "object_key": "legacy", "object_name": "OLD", "properties": props}]})
    result, = RuleExecutor().execute(RunContext("r", "c", "s", "v", tmp_path / "unused.db"), inventory, [rules["VSL-HOST-023" if host else "VSL-VC-006"]])
    assert result["result_status"] == "unavailable" and result["risk_level"] is None


def test_unknown_product_preserves_relation_but_cannot_certify_expiry():
    info = NS(name="KNOWN-NAME", editionKey="opaque", properties=[])
    state = query_entity_license(content([assignment(info)]), "host-1", "HostSystem", "vc-A", now=NOW)
    assert state["assigned"] is None and state["records"][0]["name"] == "KNOWN-NAME"


def test_unknown_version_product_name_is_not_false_unassigned():
    state = query_entity_license(content([assignment(license("Never", product="VMware new product identifier"))]), "host-1", "HostSystem", "vc-A", now=NOW)
    assert state["assigned"] is None and state["days_remaining"] is None
    assert state["records"][0]["name"] == "SYN-LICENSE"


def test_missing_name_and_type_are_not_filled_with_assignment_or_formal_labels():
    info = NS(name=None, editionKey=None, properties=[NS(key="ProductName", value="VMware ESX Server")])
    state = query_entity_license(content([assignment(info)]), "host-1", "HostSystem", "vc-A", now=NOW)
    assert state["assigned"] is True
    assert state["name"] is None and state["is_evaluation"] is None
    assert state["days_remaining"] is None


def test_partial_and_ambiguous_responses_are_not_successful_expiry():
    assert query_entity_license(content(None), "host-1", "HostSystem", "vc-A", now=NOW)["query_status"] == "partial"
    state = query_entity_license(content([assignment(license("Never")), assignment(license())]), "host-1", "HostSystem", "vc-A", now=NOW)
    assert state["assigned"] is True and state["days_remaining"] is None


def test_config_and_unbound_fallbacks_never_certify_assignment_or_expiry():
    collector = PyVmomiCollector("offline.invalid", "fixture", "fixture")
    host = NS(_moId="host-1", config=NS(product=NS(licenseProductName="VMware ESX Server", licenseProductVersion="8.0")))
    config = collector._host_license_from_config(host)
    raw = collector._license_info_to_host_fields(license("Never"), "fixture")
    for value in [config, raw]:
        assert value["host_license_assigned"] is None and value["host_license_expiration_days"] is None
    assert config["host_license_name"] is None
    assert config["host_license_required_product_name"] == "VMware ESX Server"


def test_config_name_cannot_override_permission_failure():
    collector = PyVmomiCollector("offline.invalid", "fixture", "fixture")
    host = NS(_moId="host-1", config=NS(product=NS(licenseProductName="VMware ESX Server")))
    value = collector._host_license_assignments(content([], failure=PermissionError()), [host])["host-1"]
    assert value["host_license_assigned"] is None and value["host_license_expiration_days"] is None
    assert value["host_license_name"] is None
    assert value["host_license_required_product_name"] == "VMware ESX Server"
    assert value["host_license_evidence"]["query_status"] == "permission_denied"


@pytest.mark.parametrize("host", [False, True])
def test_old_sentinel_and_old_display_string_do_not_prove_perpetual(host):
    prefix = "host_license_" if host else "license_"
    data = {prefix + "expiration_days" if host else "license_days_remaining": 999999,
            prefix + "expiration_date": "永久授权", prefix + "assigned": True}
    assert expiry_label(data, host) == "到期状态无法确认"


@pytest.mark.parametrize("scenario", ["perpetual", "dated", "unknown", "invalid", "unassigned", "legacy"])
def test_shared_document_preserves_each_licensing_object_and_separate_states(scenario):
    from vstacklens.reports.report_model import CustomerInfo, EnvironmentSummary, HealthScore, ReportData, ReportInfo, RiskSummary
    from vstacklens.reports.pdf_report import PdfReportEngine
    from vstacklens.reports.document_model import get_document
    expiry = {"perpetual": "Never", "dated": NOW + timedelta(days=365), "invalid": "bad"}.get(scenario, ...)
    state = query_entity_license(content([] if scenario == "unassigned" else [assignment(license(expiry))]), "host-1", "HostSystem", "vc-A", now=NOW)
    props = fields(state, host=True)
    if scenario == "legacy":
        props = {"host_license_assigned": True, "host_license_name": "LEGACY", "host_license_expiration_date": "永久授权", "host_license_expiration_days": 999999}
    report = ReportData(report_info=ReportInfo(report_id="syn", run_id="syn", generated_at=NOW.isoformat()),
        customer_info=CustomerInfo(customer_name="离线合成", site_name="test", vcenter="synthetic.invalid"),
        environment_summary=EnvironmentSummary(scope_statement="离线授权测试", checked_object_total=2),
        health_score=HealthScore(score=None, grade="", explanation="不推断健康"), risk_summary=RiskSummary(), findings=[],
        asset_inventory={"summary": {"vCenter": 1, "HostSystem": 1}, "details": {
            "vCenter": [{"object_key": "vc-A", "object_name": "VC", "properties": {"connected": True}}],
            "HostSystem": [{"object_key": "host-1", "object_name": "SAME-NAME", "properties": props}]}})
    payload = PdfReportEngine()._build_payload(report, {})
    row, = [x for x in payload["certificates"]["licenses"] if "[host-1]" in x]
    document = get_document(report, {})
    # Later direct human decision: customer environment shows only assignment,
    # name and version; source expiry still checked above and in rule tests.
    tables = [x for x in document["appendices"] if x.get("id") == "licenses"]
    target_rows = [(table, r) for table in tables for r in table["rows"] if "host-1" in r["key"]]
    if scenario == "legacy":
        assert not target_rows  # No modern entity evidence: do not fabricate a current assignment.
        assert "无法确认" in row and "永久授权" not in row
        return
    table, target = target_rows[0]
    cells = dict(zip(table["headers"], target["cells"]))
    assert cells["对象"] == "SAME-NAME"
    assert cells["分配状态"] == ("未分配" if scenario == "unassigned" else "已分配")
    assert not any(word in header for header in table["headers"] for word in ("到期", "有效期"))
    assert not any("永久授权" in str(v) or "正常" in str(v) for v in target["cells"])
    if scenario == "perpetual":
        assert "永久授权" in row and "无法确认" not in row
    elif scenario == "dated":
        assert "2027-10-25" in row and "365 天" in row
    elif scenario == "unassigned":
        assert "未分配" in row and "已过期" not in row
    else:
        assert "无法确认" in row and "永久授权" not in row and "正常" not in row



def test_feature_key_containing_expiry_is_not_a_perpetual_marker():
    state = query_entity_license(content([assignment(license(extra=[NS(key="expiryFeatureDescription", value="perpetual")]))]), "host-1", "HostSystem", "vc-A", now=NOW)
    assert state["expiration_state"] == "unknown" and state["days_remaining"] is None


@pytest.fixture(scope="module")
def rules():
    from pathlib import Path
    from vstacklens.rules.rulepack_loader import RulePackLoader
    from vstacklens.rules.schema_validator import SchemaValidator
    return {r.rule_id: r for r in [SchemaValidator().validate_rule(x) for x in RulePackLoader().load_raw(Path(__file__).parents[1] / "rulepacks/builtin-vsphere-v1")]
            if r.rule_id in {"VSL-VC-006", "VSL-HOST-023"}}


@pytest.mark.parametrize("host", [False, True])
@pytest.mark.parametrize("scenario,expected", [("perpetual", "passed"), ("valid", "passed"), ("near", "failed"),
    ("expired", "failed"), ("missing", "unavailable"), ("invalid", "unavailable"),
    ("permission", "unavailable"), ("query", "unavailable"), ("legacy", "unavailable"), ("unassigned", None)])
def test_original_rule_status_and_evidence_match_source(host, scenario, expected, rules, tmp_path):
    from vstacklens.core.context import RunContext
    from vstacklens.inventory.normalizer import InventoryNormalizer
    from vstacklens.rules.executor import RuleExecutor
    entity = "host-1" if host else "vc-A"
    kind = "HostSystem" if host else "vCenter"
    product = "VMware ESX Server" if host else "VMware VirtualCenter Server"
    values = {"perpetual": "Never", "valid": NOW + timedelta(days=365), "near": NOW + timedelta(days=15),
              "expired": NOW - timedelta(days=1), "missing": ..., "invalid": "bad"}
    error = PermissionError() if scenario == "permission" else TimeoutError() if scenario == "query" else None
    entries = [] if scenario == "unassigned" else [assignment(license(values.get(scenario, ...), product=product), entity)]
    state = query_entity_license(content(entries, failure=error), entity, kind, "vc-A", now=NOW)
    props = fields(state, host=host)
    if scenario == "legacy":
        props = {"host_license_assigned": True, "host_license_name": "OLD", "host_license_edition": "OLD",
                 "host_license_is_evaluation": False, "host_license_expiration_date": "永久授权",
                 "host_license_expiration_days": 999999} if host else {"license_days_remaining": 999999}
    raw = {"objects": [{"object_type": kind, "object_key": entity, "object_name": "SAME-NAME", "properties": props}]}
    inventory = InventoryNormalizer().normalize(raw)
    run = RunContext("offline-license", "customer-fixture", "site-fixture", "vc-A", tmp_path / "unused.db")
    rule = rules["VSL-HOST-023" if host else "VSL-VC-006"]
    result, = RuleExecutor().execute(run, inventory, [rule])
    assert result["result_status"] == (expected or ("failed" if host else "unavailable"))
    if scenario == "unassigned" and host:
        assert result["risk_level"] == "P1"  # Existing first severity clause; no invented expiry.
        assert result["evidence"]["current_value"] is None
    if scenario in {"perpetual", "valid", "near", "expired"}:
        assert result["evidence"]["observed_detail"]["host_license_evidence" if host else "license_evidence"]["entity_id"] == entity
    if result["result_status"] == "unavailable":
        assert "授权有效" not in result["evidence"]["evidence_summary_zh"]
        assert "永久授权" not in result["evidence"]["evidence_summary_zh"]
    if scenario == "permission":
        assert result["evidence"]["data_quality"] == "permission_denied"
    if scenario == "query":
        assert result["evidence"]["data_quality"] == "api_error"


@pytest.mark.parametrize("days,status,risk", [(365, "failed", "P2"), (6, "failed", "P1"), (None, "unavailable", None)])
def test_evaluation_rule_uses_original_risk_policy_without_inventing_expiry(days, status, risk, rules, tmp_path):
    from vstacklens.core.context import RunContext
    from vstacklens.inventory.normalizer import InventoryNormalizer
    from vstacklens.rules.executor import RuleExecutor
    state = query_entity_license(content([assignment(license(NOW + timedelta(days=days) if days is not None else ..., edition="eval"))]), "host-1", "HostSystem", "vc-A", now=NOW)
    inventory = InventoryNormalizer().normalize({"objects": [{"object_type": "HostSystem", "object_key": "host-1", "object_name": "EVAL", "properties": fields(state, host=True)}]})
    run = RunContext("offline-eval", "customer", "site", "vc-A", tmp_path / "unused.db")
    result, = RuleExecutor().execute(run, inventory, [rules["VSL-HOST-023"]])
    assert result["result_status"] == status and result["risk_level"] == risk
    assert result["evidence"]["observed_detail"]["host_license_is_evaluation"] is True
    assert "永久授权" not in result["evidence"]["evidence_summary_zh"]
