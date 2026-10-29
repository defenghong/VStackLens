"""Product persistence uses isolated databases and never connects to devices."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sqlite3

import pytest

from vstacklens.application.environment_archive import list_archives, save_archive
from vstacklens.db.connection import connect, init_db
from vstacklens.db.repositories import insert_run
from vstacklens.deep.backup import restore_history_backup
from vstacklens.products.model import finish_module, make_check, make_source, new_module
from vstacklens.products import store


def tables(db):
    with sqlite3.connect(db) as conn:
        return {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def contents(db, selected=None):
    with sqlite3.connect(db) as conn:
        names = selected or tables(db)
        return {name: (conn.execute("SELECT sql FROM sqlite_master WHERE name=?", (name,)).fetchone()[0],
                       conn.execute('SELECT * FROM "' + name + '" ORDER BY rowid').fetchall()) for name in names}


@pytest.fixture
def legacy(tmp_path):
    db = tmp_path / "isolated-products.db"
    init_db(db)
    vc = save_archive(db, name="既有 VC", address="192.0.2.11", customer_name="离线客户 A", site_name="离线站点", username="vc-user")
    with connect(db) as conn:
        row = conn.execute("SELECT * FROM vcenters WHERE vcenter_id=?", (vc,)).fetchone()
        run_id = insert_run(conn, row["customer_id"], row["site_id"], vc, "manual")
        conn.execute("UPDATE inspection_runs SET run_status='success',score=83.5 WHERE run_id=?", (run_id,))
    return db, vc, run_id


@pytest.fixture
def product_db(legacy):
    db, vc, legacy_run = legacy
    store.ensure_product_schema(db)
    nsx = store.save_target(db, product="nsx", name="离线 NSX A", address="192.0.2.110", customer_name="离线客户 A", site_name="离线站点", username="nsx-admin", identity={"node_id": "node-a"})
    avi = store.save_target(db, product="avi", name="离线 AVI A", address="192.0.2.109", customer_name="离线客户 A", site_name="离线站点", username="avi-admin")
    targets = {target.target_id: target for target in store.list_targets(db)}
    return db, targets[vc], targets[nsx], targets[avi], legacy_run


def module(target, status="normal", *, native=False):
    result = new_module(target)
    result["checks"] = [make_check("same-check", "离线公共检查", status,
        values={"current_state": "UP"}, object_id="same-object", sources=[make_source("/api/read-only")],
        native_severity="MEDIUM" if native else "", verification="live_observed")]
    if native:
        result["native_alerts"] = [{"id": "native-alarm-1", "severity": "MEDIUM", "state": "OPEN", "description": "离线原生说明"}]
    return finish_module(result)


def test_explicit_additive_migration_backs_up_and_verifies_restore_without_changing_legacy(legacy, tmp_path):
    db, vc, legacy_run = legacy
    before = contents(db)
    store.ensure_product_schema(db)
    assert store.schema_ready(db)
    assert contents(db, before) == before
    backups = list(tmp_path.glob("*.before-nsx-avi-integration-*.bak"))
    assert len(backups) == 1
    assert contents(backups[0]) == before
    assert contents(backups[0].with_name(backups[0].name + ".restore-verified")) == before
    restored = restore_history_backup(backups[0], tmp_path / "restored-new-file.db")
    assert contents(restored) == before
    assert not store.schema_ready(restored)
    with sqlite3.connect(db) as conn:
        assert conn.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
        assert not conn.execute("PRAGMA foreign_key_check").fetchall()
        assert conn.execute("SELECT vcenter_id,score FROM inspection_runs WHERE run_id=?", (legacy_run,)).fetchone() == (vc, 83.5)
    store.ensure_product_schema(db)
    assert list(tmp_path.glob("*.before-nsx-avi-integration-*.bak")) == backups


def test_migration_stops_before_schema_changes_if_backup_restore_verification_fails(legacy, monkeypatch):
    db, _, _ = legacy
    before = contents(db)
    def fail(*args, **kwargs):
        raise RuntimeError("offline restore verification failed")
    monkeypatch.setattr("vstacklens.deep.backup.restore_history_backup", fail)
    with pytest.raises(RuntimeError, match="restore verification"):
        store.ensure_product_schema(db)
    assert contents(db) == before
    assert not store.schema_ready(db)


def test_readers_do_not_create_or_implicitly_migrate_database(legacy, tmp_path):
    db, _, _ = legacy
    before = contents(db)
    assert not store.schema_ready(db)
    assert store.list_runs(db) == []
    assert store.list_checks(db) == []
    assert store.load_run(db, "missing") is None
    assert len(store.list_targets(db)) == 1
    assert contents(db) == before
    missing = tmp_path / "missing" / "not-created.db"
    assert not store.schema_ready(missing)
    assert store.list_targets(missing) == store.list_runs(missing) == store.list_checks(missing) == []
    assert store.load_run(missing, "missing") is None
    with pytest.raises(ValueError, match="显式初始化"):
        store.save_target(missing, product="nsx", name="离线", address="192.0.2.1", customer_name="离线")
    assert not missing.exists() and not missing.parent.exists()


def test_existing_vcenter_projection_preserves_ids_and_never_enters_product_table(product_db):
    db, vc, nsx, avi, _ = product_db
    assert {target.product for target in store.list_targets(db)} == {"vcenter", "nsx", "avi"}
    assert store.list_targets(db, product="vcenter")[0].target_id == vc.target_id
    assert len(store.list_targets(db, include_vcenter=False)) == 2
    assert [item.environment_id for item in list_archives(db)] == [vc.target_id]
    assert vc.username == "vc-user" and nsx.username == avi.username == ""
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM vcenters").fetchone()[0] == 1
        assert {row[0] for row in conn.execute("SELECT target_id FROM product_targets")} == {nsx.target_id, avi.target_id}
        assert all(row[0] == "" for row in conn.execute("SELECT username FROM product_targets"))
        assert "nsx-admin" not in "\n".join(conn.iterdump())
        assert "avi-admin" not in "\n".join(conn.iterdump())
    with pytest.raises(ValueError, match="现有档案"):
        store.save_target(db, product="vcenter", name="不伪装", address="192.0.2.8", customer_name="离线客户 A")


def test_same_address_across_customers_keeps_targets_checks_runs_and_reports_isolated(product_db, tmp_path):
    db, _, first, _, _ = product_db
    second_id = store.save_target(db, product="nsx", name=first.name, address=first.address, customer_name="离线客户 B", site_name="离线站点", username="another-admin")
    second = next(item for item in store.list_targets(db) if item.target_id == second_id)
    assert first.target_id != second.target_id and first.customer_id != second.customer_id
    for run, target in (("integrated-a", first), ("integrated-b", second)):
        store.create_run(db, run, [target], "离线综合报告")
        store.save_module(db, run, module(target, "attention"))
        store.finish_run(db, run, "completed")
        store.save_report(db, run, "HTML", tmp_path / (run + ".html"), "success")
    assert [row["run_id"] for row in store.list_runs(db, target_id=first.target_id)] == ["integrated-a"]
    assert [row["run_id"] for row in store.list_runs(db, customer_id=second.customer_id)] == ["integrated-b"]
    assert store.list_runs(db, target_id=first.target_id, customer_id=second.customer_id) == []
    assert store.list_checks(db, target_id=first.target_id, customer_id=second.customer_id) == []
    assert store.list_checks(db, target_id="unknown") == []
    assert len(store.list_checks(db, run_id="integrated-a", status="attention")) == 1
    assert store.load_run(db, "integrated-a")["reports"][0]["path"].endswith("integrated-a.html")
    assert store.load_run(db, "integrated-b")["targets"][0]["customer_id"] == second.customer_id


def test_rename_disable_reenable_and_reopen_keep_history_and_snapshots(product_db):
    db, _, target, _, _ = product_db
    store.create_run(db, "before-rename", [target], "离线旧名称")
    store.save_module(db, "before-rename", module(target, "abnormal"))
    store.finish_run(db, "before-rename", "completed")
    renamed = store.save_target(db, product="nsx", target_id=target.target_id, name="改名后 NSX", address=target.address,
        customer_id=target.customer_id, customer_name=target.customer_name, site_name=target.site_name, username=target.username)
    assert renamed == target.target_id
    fresh = next(item for item in store.list_targets(db) if item.target_id == renamed)
    assert fresh.name == "改名后 NSX" and fresh.identity == {"node_id": "node-a"}
    assert store.load_run(db, "before-rename")["targets"][0]["name"] == target.name
    assert store.list_checks(db, run_id="before-rename")[0]["target_name"] == target.name
    store.set_target_enabled(db, renamed, False)
    with pytest.raises(ValueError, match="停用"):
        store.create_run(db, "disabled-run", [fresh], "离线停用")
    store.set_target_enabled(db, renamed, True)
    fresh = next(item for item in store.list_targets(db) if item.target_id == renamed)
    store.create_run(db, "after-rename", [fresh], "离线新名称")
    store.save_module(db, "after-rename", module(fresh, "normal"))
    assert [item["status"] for item in store.list_checks(db, target_id=renamed)] == ["normal", "abnormal"]
    assert len(store.list_runs(db, target_id=renamed)) == 2
    assert store.load_run(db, "disabled-run") is None


def test_scope_change_duplicate_and_unsafe_endpoint_fail_atomically(product_db):
    db, _, target, _, _ = product_db
    before = contents(db)
    with pytest.raises(ValueError, match="其他客户"):
        store.save_target(db, product="nsx", target_id=target.target_id, name=target.name, address=target.address, customer_name="应回滚的新客户")
    assert contents(db) == before
    with pytest.raises(ValueError, match="相同产品地址"):
        store.save_target(db, product="nsx", name="重复", address=target.address, customer_name=target.customer_name, site_name=target.site_name)
    for address in ("http://192.0.2.3", "https://user:private@192.0.2.3", "https://192.0.2.3/api", "https://192.0.2.3?password=x"):
        with pytest.raises(ValueError):
            store.save_target(db, product="avi", name="无效地址", address=address, customer_name="不应新建")
    assert contents(db) == before


def test_task_freezes_and_checks_exact_product_customer_site_and_endpoint(product_db):
    db, vc, nsx, avi, legacy_run = product_db
    store.create_run(db, "composite", [vc, nsx, avi], "离线三产品")
    assert all("username" not in target for target in store.load_run(db, "composite")["targets"])
    with sqlite3.connect(db) as conn:
        assert "vc-user" not in "\n".join(row[0] for row in conn.execute("SELECT target_json FROM integrated_target_runs"))
        assert conn.execute("SELECT username FROM vcenters WHERE vcenter_id=?", (vc.target_id,)).fetchone()[0] == "vc-user"
    with pytest.raises(ValueError, match="已变化"):
        store.create_run(db, "stale-account", [replace(vc, username="another-runtime-user")], "离线")
    with pytest.raises(ValueError, match="重复"):
        store.create_run(db, "duplicates", [nsx, nsx], "离线")
    with pytest.raises(ValueError, match="已变化"):
        store.create_run(db, "stale", [replace(nsx, host="192.0.2.111")], "离线")
    wrong_product = module(nsx)
    wrong_product["product"] = "avi"
    with pytest.raises(ValueError, match="不属于"):
        store.save_module(db, "composite", wrong_product)
    wrong_scope = module(nsx)
    wrong_scope["customer_id"] = "another-customer"
    with pytest.raises(ValueError, match="归属"):
        store.save_module(db, "composite", wrong_scope)
    with pytest.raises(ValueError, match="旧 vCenter"):
        store.save_module(db, "composite", module(nsx), legacy_run_id=legacy_run)
    store.save_module(db, "composite", module(vc), legacy_run_id=legacy_run)
    assert store.load_run(db, "composite")["target_runs"][0]["legacy_run_id"] == legacy_run
    assert len(store.list_checks(db, run_id="composite")) == 1
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT vcenter_id FROM inspection_runs WHERE run_id=?", (legacy_run,)).fetchone()[0] == vc.target_id


@pytest.mark.parametrize("changes", [{"identity": {}}, {"identity": {"node_id": "another-node"}}, {"name": "旧的目标名称"}])
def test_execution_ref_cannot_drop_trusted_identity_or_reuse_stale_name(product_db, changes):
    db, _, target, _, _ = product_db
    with pytest.raises(ValueError, match="已变化"):
        store.create_run(db, "stale-trusted-ref", [replace(target, **changes)], "离线身份校验")
    assert store.load_run(db, "stale-trusted-ref") is None
    canonical = store.create_run(db, "canonical-trusted-ref", [target], "离线身份校验")
    assert canonical[0] == target and canonical[0] is not target
    assert canonical[0].identity == {"node_id": "node-a"}
    assert store.load_run(db, "canonical-trusted-ref")["targets"][0]["identity"] == canonical[0].identity


@pytest.mark.parametrize("sensitive", [
    {"password": "DO-NOT-PERSIST-SECRET"}, {"session_id": "DO-NOT-PERSIST-SECRET"},
    {"nested": {"license_key": "DO-NOT-PERSIST-SECRET"}}, {"authorization": "Basic DO-NOT-PERSIST-SECRET"},
    {"certificate_pem": "DO-NOT-PERSIST-SECRET"}, {"api_key": "DO-NOT-PERSIST-SECRET"},
    {"raw_response": {"safe_looking": "DO-NOT-PERSIST-SECRET"}},
    {"message": "password=DO-NOT-PERSIST-SECRET"},
    {"message": "-----BEGIN CERTIFICATE-----\nDO-NOT-PERSIST-SECRET\n-----END CERTIFICATE-----"},
])
def test_sensitive_fields_or_content_rejected_before_any_results_are_written(product_db, sensitive):
    db, _, target, _, _ = product_db
    store.create_run(db, "secret-guard", [target], "离线保密")
    result = module(target)
    result["checks"][0]["values"] = sensitive
    with pytest.raises(ValueError, match="敏感|认证|证书|原始"):
        store.save_module(db, "secret-guard", result)
    assert store.list_checks(db, run_id="secret-guard") == []
    assert store.load_run(db, "secret-guard")["modules"] == []
    with sqlite3.connect(db) as conn:
        assert "DO-NOT-PERSIST-SECRET" not in "\n".join(conn.iterdump())


def test_public_records_preserve_native_severity_distinct_from_priority_and_hide_local_paths(product_db):
    db, _, target, _, _ = product_db
    store.create_run(db, "native-level", [target], "离线原生等级")
    result = module(target, "attention", native=True)
    result["errors"] = [{"stage": "collection", "type": "timeout", "http_status": 504, "reason": r"offline C:\Private\operator\debug.log"}]
    store.save_module(db, "native-level", result)
    saved = store.load_run(db, "native-level")["modules"][0]
    assert saved["native_alerts"][0]["severity"] == "MEDIUM"
    assert saved["checks"][0]["native_severity"] == "MEDIUM"
    assert "risk_level" not in saved["checks"][0]
    assert "Private" not in saved["errors"][0]["reason"]
    assert saved["verified_pass_count"] == 0
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0


def test_module_replacement_and_report_upsert_keep_atomic_ownership(product_db, tmp_path):
    db, _, nsx, avi, _ = product_db
    store.create_run(db, "product-run", [nsx, avi], "离线组合")
    store.save_module(db, "product-run", module(nsx, "attention"))
    store.save_module(db, "product-run", module(avi, "collection_failed"))
    store.save_module(db, "product-run", module(nsx, "normal"))
    assert len(store.list_checks(db, run_id="product-run")) == 2
    assert store.list_checks(db, target_id=nsx.target_id)[0]["status"] == "normal"
    store.save_report(db, "product-run", "Word", tmp_path / "same.docx", "failed", "offline export failure")
    store.save_report(db, "product-run", "docx", tmp_path / "same.docx", "success")
    store.finish_run(db, "product-run", "partial")
    result = store.load_run(db, "product-run")
    assert result["state"] == "partial" and result["finished_at"]
    assert len(result["reports"]) == 1 and result["reports"][0]["status"] == "success"
    with pytest.raises(ValueError, match="不存在"):
        store.save_report(db, "unrelated-run", "pdf", tmp_path / "unrelated.pdf", "success")
    bad = module(nsx)
    bad["unreviewed_raw_payload"] = {"anything": True}
    with pytest.raises(ValueError, match="未投影"):
        store.save_module(db, "product-run", bad)
    assert len(store.load_run(db, "product-run")["modules"]) == 2
