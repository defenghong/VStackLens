"""Isolated service/CLI contracts. No target connection or customer DB is used."""
from __future__ import annotations

from contextlib import closing
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

from vstacklens.application.environment_archive import save_archive
from vstacklens.application.execution_guard import execution_lease
from vstacklens.application.integrated_inspection import IntegratedInspectionRequest, IntegratedInspectionService
from vstacklens.application.inspection_service import DesktopInspectionConfig, InspectionProgress, InspectionService, InspectionState
from vstacklens.db.connection import connect, init_db
from vstacklens.db.repositories import insert_run
from vstacklens.products import store
from vstacklens.products.model import SessionCredential, finish_module, make_check, make_source, new_module, sanitize_public
from vstacklens.products.transport import CollectionError


@pytest.fixture
def prepared(tmp_path):
    db = tmp_path / "isolated-integrated.db"
    store.ensure_product_schema(db)
    identifiers = [store.save_target(db, product=product, name="离线 " + product,
                    address=address, customer_name="离线验收客户", site_name="隔离站点")
                   for product, address in (("nsx", "192.0.2.110"), ("avi", "192.0.2.109"))]
    all_targets = {target.target_id: target for target in store.list_targets(db)}
    return db, [all_targets[target_id] for target_id in identifiers]


def request_for(prepared, tmp_path, *, targets=None):
    db, default_targets = prepared
    targets = targets or default_targets
    credentials = {target.target_id: SessionCredential("offline-admin", "offline-private-value-" + target.product)
                   for target in targets}
    return IntegratedInspectionRequest(db, tmp_path / "isolated-output", targets, credentials)


def collected(target, credential=None, **kwargs):
    module = new_module(target)
    from vstacklens.products.management_scope import mark_management_scope
    if target.product in {"nsx", "avi"}:
        mark_management_scope(module)
    module["version"] = "4.2.3.0.0" if target.product == "nsx" else "30.2.5"
    module["verification_level"] = "offline_sample"
    check_id = {"nsx": "nsx.version", "avi": "AVI-A1"}.get(target.product, "device.version")
    module["checks"] = [make_check(check_id, "离线版本样本", "normal", values={"version": module["version"]},
        sources=[make_source("/api/offline-version", version_basis="离线合成样本")], verification="offline_sample")]
    return finish_module(module)


def delivery_stub(self, request, targets, result, legacy_reports, context, secrets, cancelled):
    """Keep most orchestration cases independent of expensive renderers."""
    result.report_path.parent.mkdir(parents=True, exist_ok=True)
    result.report_path.write_text("<html>离线测试</html>", encoding="utf-8")
    result.state = "completed" if all(m["collection_state"] == "completed" for m in result.modules) else "partial"


def test_target_failure_does_not_stop_other_target_and_runtime_credentials_clear(prepared, tmp_path, monkeypatch):
    calls, observed = [], []
    def fail(target, credential, **kwargs):
        calls.append(target.product)
        observed.append(credential)
        raise CollectionError("permission", "离线权限拒绝", http_status=403)
    def ok(target, credential, **kwargs):
        calls.append(target.product)
        observed.append(credential)
        credential.remember_secret("offline-auth-session")
        return collected(target)
    monkeypatch.setattr(IntegratedInspectionService, "_deliver", delivery_stub)
    request = request_for(prepared, tmp_path)
    original_credentials = list(request.credentials.values())
    result = IntegratedInspectionService(collectors={"nsx": fail, "avi": ok}).run(request)
    assert calls == ["nsx", "avi"] and result.state == "partial"
    assert [m["collection_state"] for m in result.modules] == ["failed", "completed"]
    assert result.modules[0]["checks"][0]["status"] == "permission_denied"
    assert result.modules[0]["errors"][0]["http_status"] == 403
    assert result.modules[0]["delivery_state"] == "diagnostic_only"
    assert result.modules[1]["delivery_state"] == "partial"  # stub only publishes HTML
    assert request.credentials == {}
    assert all(not c.username and not c.password and not c.tenant and not c.secret_values for c in original_credentials + observed)
    saved = store.load_run(prepared[0], result.run_id)
    assert saved["state"] == "partial" and len(saved["modules"]) == 2
    with closing(connect(prepared[0])) as conn:
        assert conn.execute("SELECT COUNT(*) FROM inspection_execution_leases").fetchone()[0] == 0


def test_all_failed_creates_only_clean_diagnostic_not_health_report(prepared, tmp_path):
    request = request_for(prepared, tmp_path)
    secret = request.credentials[prepared[1][0].target_id].password
    def fail(target, credential, **kwargs):
        credential.remember_secret("offline-session-private")
        raise CollectionError("timeout", "离线失败 " + secret + " offline-session-private C:\\Users\\private\\trace.log", stage="collection", http_status=504)
    result = IntegratedInspectionService(collectors={"nsx": fail, "avi": fail}).run(request)
    assert result.state == "failed" and result.diagnostic_path.is_file()
    assert not result.report_path.exists() and result.docx_path is result.pdf_path is None
    assert not list(result.report_dir.rglob("*.html"))
    assert not list(result.report_dir.rglob("*.docx")) and not list(result.report_dir.rglob("*.pdf"))
    text = result.diagnostic_path.read_text(encoding="utf-8")
    assert "execution_diagnostic_not_health_report" in text
    assert secret not in text and "offline-session-private" not in text and "C:\\Users\\private" not in text
    saved = store.load_run(prepared[0], result.run_id)
    assert all(row["status"] == "blocked" and not row["path"] for row in saved["reports"] if row["format"] in {"html", "docx", "pdf"})
    assert next(row for row in saved["reports"] if row["format"] == "json")["status"] == "success"
    assert all(m["delivery_state"] == "diagnostic_only" for m in result.modules)
    assert all(m["verified_pass_count"] == 0 for m in result.modules)


@pytest.mark.parametrize("valid,available,errors,state,diagnostic,expected", [
    (False, 3, False, "partial", False, "diagnostic_only"),
    (True, 3, False, "completed", False, "completed"),
    (True, 1, False, "partial", False, "partial"),
    (True, 3, True, "partial", False, "partial"),
    (True, 0, False, "failed", False, "failed"),
    (False, 0, False, "failed", True, "diagnostic_only"),
    (False, 0, False, "cancelled", True, "cancelled"),
])
def test_delivery_is_target_specific_and_requires_real_files(prepared, tmp_path, valid, available, errors, state, diagnostic, expected):
    module = collected(prepared[1][0]) if valid else IntegratedInspectionService._failure_module(
        prepared[1][0], ValueError("离线认证诊断"), False, ())
    paths = [tmp_path / name for name in ("body.html", "body.docx", "body.pdf")]
    for path in paths[:available]:
        path.write_bytes(b"isolated phase-state fixture; not a rendered report")
    diagnosis = tmp_path / "diagnosis.json"
    if diagnostic:
        diagnosis.write_text("{}", encoding="utf-8")
    result = SimpleNamespace(state=state, report_path=paths[0], docx_path=paths[1], pdf_path=paths[2],
        html_error=None, docx_error=None, pdf_error="离线导出错误" if errors else None,
        diagnostic_path=diagnosis if diagnostic else None)
    assert IntegratedInspectionService._target_delivery_state(module, result) == expected


@pytest.mark.parametrize("inventory", [{"nodes": []}, {"services": {}, "nodes": []}, {"nodes": [None, {}], "resource": None}])
def test_empty_inventory_wrappers_do_not_turn_failed_target_into_valid_data(prepared, tmp_path, monkeypatch, inventory):
    def no_data(target, credential, **kwargs):
        module = IntegratedInspectionService._failure_module(target, ValueError("离线未取得数据"), False, ())
        module["inventory"] = inventory
        return finish_module(module)
    monkeypatch.setattr(IntegratedInspectionService, "_deliver", delivery_stub)
    result = IntegratedInspectionService(collectors={"nsx": no_data, "avi": collected}).run(request_for(prepared, tmp_path))
    failed, successful = result.modules
    assert failed["collection_state"] == "failed" and failed["valid_data"] is False
    assert failed["delivery_state"] == "diagnostic_only"
    assert successful["valid_data"] is True


def test_zero_false_and_empty_scope_are_distinct_from_missing_observations(prepared):
    from vstacklens.products.model import has_valid_data
    assert has_valid_data({"inventory": {"cpu_usage": 0, "enabled": False}, "checks": []})
    assert not has_valid_data({"inventory": {"nodes": [], "services": {}}, "checks": []})
    assert has_valid_data({"inventory": {}, "checks": [make_check("empty.scope", "空范围", "not_deployed",
        values={"count": 0}, sources=[make_source("/api/offline-empty-scope")])]})


def test_labelled_secret_in_target_error_remains_clean_and_does_not_abort_next(prepared, tmp_path, monkeypatch):
    calls = []
    def fail(target, credential, **kwargs):
        calls.append(target.product)
        raise RuntimeError("password=" + credential.password + "; license_key=offline-sensitive-key")
    def ok(target, credential, **kwargs):
        calls.append(target.product)
        return collected(target)
    monkeypatch.setattr(IntegratedInspectionService, "_deliver", delivery_stub)
    result = IntegratedInspectionService(collectors={"nsx": fail, "avi": ok}).run(request_for(prepared, tmp_path))
    assert calls == ["nsx", "avi"] and result.state == "partial"
    saved = json.dumps(store.load_run(prepared[0], result.run_id), ensure_ascii=False)
    assert "offline-sensitive-key" not in saved and "offline-private-value-nsx" not in saved


def test_unprepared_database_is_not_created_or_migrated_and_credentials_clear(tmp_path, monkeypatch):
    from vstacklens.products.model import TargetRef
    target = TargetRef("nsx-offline", "nsx", "customer-offline", "site-offline", "离线", "192.0.2.110")
    db = tmp_path / "not-created" / "isolated.db"
    request = IntegratedInspectionRequest(db, tmp_path / "output", [target], {target.target_id: SessionCredential("admin", "one-use-private")})
    credential = request.credentials[target.target_id]
    def forbidden(*args, **kwargs):
        pytest.fail("service must not migrate databases")
    monkeypatch.setattr(store, "ensure_product_schema", forbidden)
    with pytest.raises(ValueError, match="显式准备"):
        IntegratedInspectionService(collectors={}).run(request)
    assert not db.exists() and not db.parent.exists() and not request.report_output_dir.exists()
    assert request.credentials == {} and not credential.password
    init_db(db)
    with closing(sqlite3.connect(db)) as conn:
        before = list(conn.iterdump())
    request = IntegratedInspectionRequest(db, tmp_path / "output", [target], {target.target_id: SessionCredential("admin", "one-use-private")})
    with pytest.raises(ValueError, match="显式准备"):
        IntegratedInspectionService(collectors={}).run(request)
    with closing(sqlite3.connect(db)) as conn:
        assert list(conn.iterdump()) == before


def test_execution_conflict_does_not_touch_busy_target_and_lease_releases(prepared, tmp_path, monkeypatch):
    db, targets = prepared
    calls = []
    def collector(target, credential, **kwargs):
        calls.append(target.target_id)
        return collected(target)
    monkeypatch.setattr(IntegratedInspectionService, "_deliver", delivery_stub)
    with execution_lease(db, targets[0].target_id, targets[0].host, targets[0].port, owner="offline-busy"):
        result = IntegratedInspectionService(collectors={"nsx": collector, "avi": collector}).run(request_for(prepared, tmp_path))
        assert calls == [targets[1].target_id]
        assert result.modules[0]["collection_state"] == "failed"
        with closing(connect(db)) as conn:
            assert {row[0] for row in conn.execute("SELECT DISTINCT owner FROM inspection_execution_leases")} == {"offline-busy"}
    with closing(connect(db)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM inspection_execution_leases").fetchone()[0] == 0


def test_cancel_after_first_target_never_starts_following_or_publishes(prepared, tmp_path):
    calls, stopped = [], {"value": False}
    def collector(target, credential, **kwargs):
        calls.append(target.target_id)
        stopped["value"] = True
        return collected(target)
    result = IntegratedInspectionService(collectors={"nsx": collector, "avi": collector}).run(
        request_for(prepared, tmp_path), cancel_requested=lambda: stopped["value"])
    assert calls == [prepared[1][0].target_id] and result.state == "cancelled"
    assert result.modules[1]["collection_state"] == "cancelled"
    assert not result.report_path.exists() and result.diagnostic_path.is_file()
    reports = store.load_run(prepared[0], result.run_id)["reports"]
    assert all(row["status"] == "cancelled" for row in reports if row["format"] in {"html", "docx", "pdf"})
    assert next(row for row in reports if row["format"] == "json")["status"] == "success"


def test_different_customer_targets_are_rejected_before_collection(prepared, tmp_path):
    db, targets = prepared
    identifier = store.save_target(db, product="avi", name="另一客户 AVI", address="192.0.2.109", customer_name="另一离线客户")
    second = next(t for t in store.list_targets(db) if t.target_id == identifier)
    request = request_for(prepared, tmp_path, targets=[targets[0], second])
    with pytest.raises(ValueError, match="同一客户"):
        IntegratedInspectionService(collectors={}).run(request)
    assert request.credentials == {} and store.list_runs(db) == [] and not request.report_output_dir.exists()


def test_service_executes_canonical_archive_scope_instead_of_caller_display_metadata(prepared, tmp_path, monkeypatch):
    original = prepared[1][0]
    caller_copy = replace(original, customer_name="错误显示客户", site_name="错误显示站点")
    observed = []
    def collector(target, credential, **kwargs):
        observed.append(target)
        return collected(target)
    monkeypatch.setattr(IntegratedInspectionService, "_deliver", delivery_stub)
    result = IntegratedInspectionService(collectors={"nsx": collector}).run(
        request_for(prepared, tmp_path, targets=[caller_copy]))
    assert len(observed) == 1 and observed[0].customer_name == original.customer_name
    assert observed[0].site_name == original.site_name
    saved = store.load_run(prepared[0], result.run_id)
    assert saved["targets"][0]["customer_name"] == observed[0].customer_name
    assert saved["targets"][0]["site_name"] == observed[0].site_name


@pytest.mark.parametrize("malformed", [False, True])
def test_target_start_time_is_actual_start_even_when_adapter_finishes_later_or_is_rejected(prepared, tmp_path, monkeypatch, malformed):
    from vstacklens.application import integrated_inspection as integration
    expected = {target.target_id: f"2026-10-17T00:00:0{index}Z" for index, target in enumerate(prepared[1])}
    starts = []
    def starting_module(target):
        module = new_module(target)
        starts.append(target.target_id)
        # A later fallback module must not replace the first execution start.
        module["started_at"] = expected[target.target_id] if starts.count(target.target_id) == 1 else "2026-10-17T00:00:59Z"
        return module
    def collector(target, credential, **kwargs):
        module = collected(target)
        module["started_at"] = "2026-10-17T00:01:00Z"
        if malformed and target.product == "nsx":
            module["unprojected_adapter_field"] = {"state": "must not persist"}
        return module
    monkeypatch.setattr(integration, "new_module", starting_module)
    monkeypatch.setattr(IntegratedInspectionService, "_deliver", delivery_stub)
    result = IntegratedInspectionService(collectors={"nsx": collector, "avi": collector}).run(request_for(prepared, tmp_path))
    assert {module["target_id"]: module["started_at"] for module in result.modules} == expected
    assert [module["collection_state"] for module in result.modules] == (["failed", "completed"] if malformed else ["completed", "completed"])
    saved = store.load_run(prepared[0], result.run_id)
    assert {module["target_id"]: module["started_at"] for module in saved["modules"]} == expected


@pytest.mark.parametrize("observed_identity,expected_status", [({}, "insufficient_data"), ({"node_id": "different-manager"}, "abnormal")])
def test_registered_identity_missing_or_changed_never_counts_as_verified_pass(prepared, tmp_path, monkeypatch, observed_identity, expected_status):
    db, targets = prepared
    original = targets[0]
    store.save_target(db, target_id=original.target_id, product=original.product, name=original.name,
                      address=original.address, customer_name=original.customer_name, site_name=original.site_name,
                      identity={"node_id": "registered-manager"})
    target = next(item for item in store.list_targets(db) if item.target_id == original.target_id)
    def collector(target, credential, **kwargs):
        module = collected(target)
        assert not module["target_identity"]  # an archive identity must not masquerade as an observed identity
        module["target_identity"] = observed_identity
        module["verification_level"] = "live_compared"
        module["checks"][0]["verification"] = "live_compared"
        return module
    monkeypatch.setattr(IntegratedInspectionService, "_deliver", delivery_stub)
    result = IntegratedInspectionService(collectors={"nsx": collector}).run(request_for(prepared, tmp_path, targets=[target]))
    module = result.modules[0]
    assert module["verification_level"] == "unverified" and module["verified_pass_count"] == 0
    assert all(check["verification"] == "unverified" for check in module["checks"])
    identity_check = next(check for check in module["checks"] if check["check_id"] == "execution.identity")
    assert identity_check["status"] == expected_status
    assert module["errors"][0]["kind"] == "identity_unconfirmed"


def test_vcenter_uses_existing_service_keeps_original_id_history_and_grades(prepared, tmp_path, monkeypatch):
    db, _ = prepared
    vc_id = save_archive(db, name="既有离线 VC", address="192.0.2.11", customer_name="离线验收客户", site_name="隔离站点")
    vc = next(t for t in store.list_targets(db) if t.target_id == vc_id)
    with closing(connect(db)) as conn, conn:
        old_id = insert_run(conn, vc.customer_id, vc.site_id, vc_id, "manual")
        conn.execute("UPDATE inspection_runs SET run_status='success',score=83.5 WHERE run_id=?", (old_id,))
    from vstacklens.reports.context_builder import ReportContextBuilder
    from vstacklens.reports.report_model import ReportDataFactory
    with closing(connect(db)) as conn:
        original_report = ReportDataFactory().from_context(ReportContextBuilder().build(conn, old_id))
    calls, delivered, updates = [], [], []
    class Legacy:
        def run_vcenter_inspection(self, cfg, **kwargs):
            calls.append((cfg, kwargs))
            callback = kwargs["progress_callback"]
            assert callback is not None
            for percent in (-10, 50, 150):
                callback(InspectionProgress(state=InspectionState.RUNNING, run_id=old_id,
                    stage="collecting_inventory", percent=percent,
                    message=f"读取用户 {cfg.username}，认证值 {cfg.password}"))
            return SimpleNamespace(run_id=old_id, score=83.5)
    def delivery(self, request, targets, result, legacy_reports, context, secrets, cancelled):
        delivered.extend(legacy_reports)
        delivery_stub(self, request, targets, result, legacy_reports, context, secrets, cancelled)
    monkeypatch.setattr(IntegratedInspectionService, "_deliver", delivery)
    result = IntegratedInspectionService(legacy_service=Legacy(), collectors={}).run(
        request_for(prepared, tmp_path, targets=[vc]), progress_callback=updates.append)
    assert len(calls) == 1 and calls[0][0].environment_id == vc_id
    assert calls[0][0].ssl_no_verify is False
    assert calls[0][0].report_output_dir == result.report_dir / "vc"
    assert calls[0][1]["persist_config"] is False and calls[0][1]["execution_owner"] == result.run_id
    assert "offline-admin" in calls[0][1]["known_secrets"]
    assert "offline-private-value-vcenter" in calls[0][1]["known_secrets"]
    child_updates = [update for update in updates if update.stage == "vcenter.collecting_inventory"]
    assert [update.percent for update in child_updates] == [5, 37, 70]
    assert all(update.run_id == result.run_id for update in child_updates)
    public_progress = " ".join(update.message for update in updates)
    assert "offline-admin" not in public_progress and "offline-private-value-vcenter" not in public_progress
    assert len(delivered) == 1
    assert delivered[0].health_score == original_report.health_score
    assert delivered[0].risk_summary == original_report.risk_summary
    module = result.modules[0]
    assert module["target_id"] == vc_id and module["checks"][0]["values"]["legacy_run_id"] == old_id
    assert module["checks"][0]["values"]["original_score"] == 83.5
    saved = store.load_run(db, result.run_id)
    assert saved["target_runs"][0]["legacy_run_id"] == old_id
    with closing(connect(db)) as conn:
        assert conn.execute("SELECT vcenter_id,score FROM inspection_runs WHERE run_id=?", (old_id,)).fetchone()[:] == (vc_id, 83.5)
        assert conn.execute("SELECT COUNT(*) FROM product_targets WHERE target_id=?", (vc_id,)).fetchone()[0] == 0


@pytest.mark.parametrize("with_gaps", [False, True])
def test_legacy_coverage_preserves_original_grade_and_records_exact_gaps_without_extrapolating_warnings(prepared, tmp_path, monkeypatch, with_gaps):
    db, _ = prepared
    vc_id = save_archive(db, name="离线覆盖 VC", address="192.0.2.11", customer_name="离线验收客户", site_name="隔离站点")
    vc = next(target for target in store.list_targets(db) if target.target_id == vc_id)
    with closing(connect(db)) as conn, conn:
        legacy_id = insert_run(conn, vc.customer_id, vc.site_id, vc_id, "manual")
        conn.execute("UPDATE inspection_runs SET run_status='success',score=60 WHERE run_id=?", (legacy_id,))
    from vstacklens.reports.context_builder import ReportContextBuilder
    from vstacklens.reports.report_model import ReportDataFactory
    with closing(connect(db)) as conn:
        base_context = ReportContextBuilder().build(conn, legacy_id)
    original_report = ReportDataFactory().from_context(base_context)
    original_report.health_score.score = 60
    original_report.health_score.grade = original_report.health_score.label = "关注"
    original_report.environment_summary.checked_object_total = 131
    original_report.risk_summary.P2 = 3
    original_report.risk_summary.P3 = 7
    original_report.risk_summary.total = 10
    gaps = [{"result_id": "gap-" + str(index), "rule_id": rule_id, "object_type": "HostSystem",
             "object_key": "offline-object-" + str(index), "object_name": "离线对象 " + str(index),
             "result_status": "unavailable", "data_quality": "missing",
             "source_path": "vsphere.sdk." + rule_id, "collected_at": "2026-10-17T00:00:00Z",
             "reason": "read by offline-admin returned insufficient data"}
            for index, rule_id in enumerate(["VSL-DS-013"] * 5 + ["VSL-DS-018"] * 3 + ["VSL-NET-003"] * 5 + ["VSL-VC-006"])] if with_gaps else []
    warnings = [{"context": "storage_policy:VirtualMachine:offline-vm-" + str(index),
                 "error_type": "AttributeError", "status": "api_error", "degraded": True} for index in range(20)] if with_gaps else []
    context = {**base_context, "asset_total": 131,
        "result_status_summary": {"passed": 2176, "failed": 192, "not_applicable": 70,
                                  "unavailable": len(gaps), "error": 0},
        "object_results": gaps, "unavailable_results": gaps,
        "environment_info": {"collection_mode": "sdk", "collection_warnings": warnings}}
    monkeypatch.setattr(ReportContextBuilder, "build", lambda *args, **kwargs: context)
    monkeypatch.setattr(ReportDataFactory, "from_context", lambda *args, **kwargs: original_report.model_copy(deep=True))
    delivered = []
    class Legacy:
        def run_vcenter_inspection(self, cfg, **kwargs):
            assert cfg.environment_id == vc_id and cfg.username in kwargs["known_secrets"]
            return SimpleNamespace(run_id=legacy_id, score=60)
    def delivery(self, request, targets, result, legacy_reports, context, secrets, cancelled):
        delivered.extend(legacy_reports)
        delivery_stub(self, request, targets, result, legacy_reports, context, secrets, cancelled)
    monkeypatch.setattr(IntegratedInspectionService, "_deliver", delivery)
    result = IntegratedInspectionService(legacy_service=Legacy(), collectors={}).run(request_for(prepared, tmp_path, targets=[vc]))
    module = result.modules[0]
    assert module["valid_data"] and result.state == ("partial" if with_gaps else "completed")
    assert module["collection_state"] == module["analysis_state"] == ("partial" if with_gaps else "completed")
    assert delivered[0].health_score == original_report.health_score and delivered[0].risk_summary == original_report.risk_summary
    legacy_check = module["checks"][0]
    assert legacy_check["status"] == "attention" and legacy_check["values"]["original_score"] == 60
    assert legacy_check["values"]["original_grade"] == "关注"
    if with_gaps:
        coverage = next(check for check in module["checks"] if check["check_id"] == "vcenter.legacy_coverage")
        assert coverage["status"] == "insufficient_data" and coverage["completeness"] == legacy_check["completeness"] == "partial"
        values = coverage["values"]
        assert values["rule_result_status_summary"] == context["result_status_summary"]
        assert len(values["unavailable_results"]) == 14
        assert {row["source_path"] for row in values["unavailable_results"]} == {row["source_path"] for row in gaps}
        assert all(row["collected_at"] == "2026-10-17T00:00:00Z" for row in values["unavailable_results"])
        assert values["collection_warning_records_observed"] == 20 and values["collection_warning_total"] is None
        assert all(warning["context_scope"] == "storage_policy" for warning in values["collection_warnings"])
        assert "context.object_results" in coverage["sources"][0]["fields"]
        assert "最多提供 20 条" in " ".join(module["limitations"])
        assert "offline-admin" not in json.dumps(module, ensure_ascii=False)
    else:
        assert not any(check["check_id"] == "vcenter.legacy_coverage" for check in module["checks"])
    saved = store.load_run(db, result.run_id)
    assert saved["modules"][0]["collection_state"] == module["collection_state"]
    with closing(connect(db)) as conn:
        assert conn.execute("SELECT score,run_status FROM inspection_runs WHERE run_id=?", (legacy_id,)).fetchone()[:] == (60.0, "success")


def test_vcenter_connection_diagnostic_is_not_valid_data_and_does_not_mask_valid_nsx(prepared, tmp_path, monkeypatch):
    db, targets = prepared
    vc_id = save_archive(db, name="仅连接诊断的离线 VC", address="192.0.2.11", customer_name="离线验收客户", site_name="隔离站点")
    vc = next(target for target in store.list_targets(db) if target.target_id == vc_id)
    with closing(connect(db)) as conn, conn:
        legacy_id = insert_run(conn, vc.customer_id, vc.site_id, vc_id, "manual")
        conn.execute("UPDATE inspection_runs SET run_status='failed',score=0 WHERE run_id=?", (legacy_id,))
    from vstacklens.reports.context_builder import ReportContextBuilder
    # Old connection diagnostics contain a vCenter-like object. Its existence
    # must not count as a successfully inspected asset.
    fake_context = {"run": {"run_id": legacy_id}, "scope": {"customer_name": vc.customer_name,
                    "site_name": vc.site_name, "vcenter_host": vc.host}, "asset_total": 1,
                    "asset_summary": {"vCenter": 1}, "result_status_summary": {"pass": 1},
                    "environment_info": {"collection_mode": "connection_failed"}}
    monkeypatch.setattr(ReportContextBuilder, "build", lambda *args, **kwargs: fake_context)
    class Legacy:
        def run_vcenter_inspection(self, cfg, **kwargs):
            assert cfg.environment_id == vc_id
            return SimpleNamespace(run_id=legacy_id, score=0)
    request = request_for(prepared, tmp_path, targets=[vc, targets[0]])
    result = IntegratedInspectionService(legacy_service=Legacy(), collectors={"nsx": collected}).run(request)
    assert result.state == "partial", (result.state, result.html_error, result.docx_error, result.pdf_error)
    vc_module, nsx_module = result.modules
    assert vc_module["product"] == "vcenter" and not vc_module["valid_data"]
    assert vc_module["collection_state"] == "failed" and vc_module["verified_pass_count"] == 0
    assert all(check["status"] != "normal" for check in vc_module["checks"])
    assert vc_module["checks"][0]["values"] == {"legacy_run_id": legacy_id, "object_count": 0}
    assert nsx_module["product"] == "nsx" and nsx_module["valid_data"] and nsx_module["collection_state"] == "completed"
    assert result.score is None
    assert result.report_path.is_file() and result.docx_path.is_file() and result.pdf_path.is_file()
    from vstacklens.products.reporting import build_integrated_report, product_report_view
    report = build_integrated_report(result.run_id, request.targets, result.modules, "离线组合诊断验证")
    assert report.integration_summary["legacy_present"] is False
    assert report.integration_summary["legacy_assessments"] == []
    view = product_report_view(report)
    assert view["has_vcenter"] is False  # no empty legacy VC chapters
    failed_section = next(section for section in view["sections"] if section["product"] == "vcenter")
    assert failed_section["checks"] and "连接诊断" in json.dumps(failed_section, ensure_ascii=False)
    for path in (result.report_path, result.docx_path, result.pdf_path):
        assert path.stat().st_size > 0
    import zipfile
    with zipfile.ZipFile(result.docx_path) as archive:
        word = archive.read("word/document.xml").decode("utf-8")
    import fitz
    with fitz.open(result.pdf_path) as pdf:
        pdf_text = "\n".join(page.get_text() for page in pdf)
    assert all("连接诊断" in text and "NSX" in text for text in (result.report_path.read_text(encoding="utf-8"), word, pdf_text))
    saved = store.load_run(db, result.run_id)
    assert saved["target_runs"][0]["legacy_run_id"] == legacy_id
    assert {row["format"] for row in saved["reports"] if row["status"] == "success"} == {"html", "docx", "pdf", "json"}


def test_public_model_removes_avi_camelcase_tokens_and_redacts_error_strings():
    payload = {"accessToken": "private-access", "refreshToken": "private-refresh",
               "AVI-Sessionid": "private-session", "Set-Cookie": "private-cookie",
               "nested": [{"access_token": "private-nested", "public_state": "UP"}],
               "status": "authenticated"}
    assert sanitize_public(payload) == {"nested": [{"public_state": "UP"}], "status": "authenticated"}
    text = "accessToken=private-access; refreshToken=private-refresh; Avi-Sessionid=private-session; password=private-pass; authorization=Bearer abcde12345"
    clean = sanitize_public(text)
    assert all(value not in clean for value in ("private-access", "private-refresh", "private-session", "private-pass", "abcde12345"))
    assert "已隐藏" in clean


def test_legacy_service_request_logging_omits_username_and_password_without_loading_hcl(tmp_path, monkeypatch):
    from vstacklens.application import inspection_service
    from vstacklens.application.inspection_runner import RunnerCancelledError
    logged = []
    class Logger:
        def info(self, message, *args):
            logged.append(message % args if args else message)
        warning = info
        error = info
    class CancellingRunner:
        def run_vcenter(self, request, progress=None, cancel_requested=None):
            assert request.username == "private-vc-username" and request.password == "private-vc-password"
            raise RunnerCancelledError("离线取消，无需采集或加载硬件库。")
    monkeypatch.setattr(inspection_service, "LOGGER", Logger())
    rules = tmp_path / "minimal-unread-rulepack"
    rules.mkdir()
    cfg = DesktopInspectionConfig(vcenter="192.0.2.11", username="private-vc-username", password="private-vc-password",
        customer_name="离线客户", site_name="隔离站点", db_path=tmp_path / "not-created.db",
        report_output_dir=tmp_path / "not-rendered", rulepack_path=rules)
    service = InspectionService(config_path=tmp_path / "not-written-config.json", runner=CancellingRunner())
    with pytest.raises(RunnerCancelledError):
        service.run_vcenter_inspection(cfg, persist_config=False)
    assert logged and any("vCenter inspection requested" in row for row in logged)
    assert "private-vc-username" not in " ".join(logged) and "private-vc-password" not in " ".join(logged)
    assert not cfg.db_path.exists() and not service.config_path.exists() and not cfg.report_output_dir.exists()


def test_cli_requires_explicit_prepare_and_target_ids_with_hidden_runtime_credentials(prepared, tmp_path, monkeypatch, capsys):
    from vstacklens.products import cli
    missing = tmp_path / "cli-missing.db"
    assert cli.main(["--db", str(missing), "list-targets"]) == 0
    assert not missing.exists()
    assert cli.main(["--db", str(missing), "add-target", "--product", "nsx", "--name", "离线", "--address", "192.0.2.2", "--customer", "离线"]) == 3
    assert not missing.exists()
    capsys.readouterr()
    db, targets = prepared
    args = ["--db", str(db), "run", targets[0].target_id, "--output", str(tmp_path / "cli-output")]
    assert cli.main(args) == 3
    assert "--experimental" in capsys.readouterr().err
    observed, hidden_prompts = [], []
    monkeypatch.setattr("builtins.input", lambda _: "offline-admin")
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: hidden_prompts.append(prompt) or "cli-private-password")
    class Service:
        def run(self, request, **kwargs):
            observed.extend(request.credentials.values())
            assert request.targets[0].target_id == targets[0].target_id
            assert observed[0].password == "cli-private-password" and not observed[0].allow_untrusted_lab
            return SimpleNamespace(run_id="integrated-offline-cli", state="failed", modules=[], report_path=None,
                                   docx_path=None, pdf_path=None, diagnostic_path=None)
    monkeypatch.setattr(cli, "IntegratedInspectionService", Service)
    assert cli.main(args + ["--experimental"]) == 3
    output = capsys.readouterr()
    assert hidden_prompts and "cli-private-password" not in output.out + output.err
    assert observed and all(not c.username and not c.password for c in observed)
    assert not (tmp_path / "cli-output").exists()


def test_cli_explicit_preparation_add_and_list_share_stable_product_targets(tmp_path, capsys):
    from vstacklens.products import cli
    db = tmp_path / "cli-explicit.db"
    assert cli.main(["--db", str(db), "prepare-db"]) == 0
    assert json.loads(capsys.readouterr().out)["explicit_schema_preparation"] is True
    identifiers = []
    for product, address in (("nsx", "192.0.2.110"), ("avi", "192.0.2.109"), ("vcenter", "192.0.2.11")):
        assert cli.main(["--db", str(db), "add-target", "--product", product, "--name", "离线 " + product,
                         "--address", address, "--customer", "CLI 离线客户", "--site", "离线站点"]) == 0
        identifiers.append(json.loads(capsys.readouterr().out)["target_id"])
    assert cli.main(["--db", str(db), "list-targets"]) == 0
    records = json.loads(capsys.readouterr().out)
    assert {record["target_id"] for record in records} == set(identifiers)
    assert {record["product"] for record in records} == {"nsx", "avi", "vcenter"}
    assert len({record["customer_id"] for record in records}) == 1
    assert all("username" not in record and "password" not in record for record in records)


def test_cli_rejects_tls_exception_outside_explicit_lab_targets_before_prompt(prepared, tmp_path, monkeypatch, capsys):
    from vstacklens.products import cli
    db, targets = prepared
    def forbidden(*args, **kwargs):
        pytest.fail("invalid TLS target must fail before requesting credentials")
    monkeypatch.setattr("builtins.input", forbidden)
    assert cli.main(["--db", str(db), "run", targets[0].target_id, "--output", str(tmp_path / "output"),
                     "--experimental", "--allow-untrusted-lab", targets[0].target_id]) == 3
    assert "指定 NSX／AVI 实验地址" in capsys.readouterr().err


def test_cli_refuses_echoed_password_fallback_before_any_collection(prepared, tmp_path, monkeypatch, capsys):
    from vstacklens.products import cli
    import warnings
    monkeypatch.setattr("builtins.input", lambda _: "offline-admin")
    def no_tty(prompt):
        warnings.warn("cannot disable echo", cli.getpass.GetPassWarning)
        pytest.fail("getpass fallback must not reach echoed stdin")
    monkeypatch.setattr(cli.getpass, "getpass", no_tty)
    db, targets = prepared
    assert cli.main(["--db", str(db), "run", targets[0].target_id, "--experimental",
                     "--output", str(tmp_path / "output")]) == 3
    assert "不支持隐藏密码输入" in capsys.readouterr().err
    assert not store.list_runs(db) and not (tmp_path / "output").exists()


def test_one_offline_collection_publishes_same_standard_result_in_three_real_formats(prepared, tmp_path):
    """Exercise the production publication/scanning pipeline, never a live API."""
    request = request_for(prepared, tmp_path)
    secrets = [credential.password for credential in request.credentials.values()]
    result = IntegratedInspectionService(collectors={"nsx": collected, "avi": collected}).run(request)
    assert result.state == "completed", (result.state, result.html_error, result.docx_error, result.pdf_error)
    assert result.report_path.is_file() and result.docx_path.is_file() and result.pdf_path.is_file()
    standardized = json.loads((result.report_dir / "inspection-result.json").read_text(encoding="utf-8"))
    assert standardized["modules"] == result.modules
    assert {m["product"] for m in standardized["modules"]} == {"nsx", "avi"}
    assert all(m["verified_pass_count"] == 0 for m in result.modules)
    html = result.report_path.read_text(encoding="utf-8")
    assert "NSX" in html and "AVI" in html
    import zipfile
    with zipfile.ZipFile(result.docx_path) as archive:
        word = archive.read("word/document.xml").decode("utf-8")
    import fitz
    with fitz.open(result.pdf_path) as pdf:
        pdf_text = "\n".join(page.get_text() for page in pdf)
        assert len(pdf) > 0
    assert "NSX" in word and "AVI" in word and "NSX" in pdf_text and "AVI" in pdf_text
    assert all(secret not in html + word + pdf_text + json.dumps(standardized) for secret in secrets)
    saved = store.load_run(prepared[0], result.run_id)
    assert {row["format"] for row in saved["reports"] if row["status"] == "success"} == {"html", "docx", "pdf", "json"}
    json_record = next(row for row in saved["reports"] if row["format"] == "json")
    assert Path(json_record["path"]).is_file()
    assert json.loads(Path(json_record["path"]).read_text(encoding="utf-8"))["modules"] == result.modules
