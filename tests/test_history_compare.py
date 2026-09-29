"""历史对比的 vCenter 环境隔离测试。

这些测试显式创建两个不同的 vcenter_id（vc-a.example / vc-b.example），
用于证明跨环境的两次巡检不会被当作可比记录。
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from vstacklens.application import InspectionService
from vstacklens.db.connection import connect, init_db
from vstacklens.reports.history_compare import (
    STATE_EMPTY,
    STATE_ENVIRONMENT_MISMATCH,
    STATE_READY,
    STATE_RUN_UNAVAILABLE,
    STATE_SINGLE_RUN,
    HistoryComparisonBuilder,
)


CUSTOMER_ID = "cust-env"
SITE_ID = "site-env"
NOW = "2026-09-01T00:00:00+00:00"

UUID_A = "6f2a6d0e-0d1c-4c60-9a34-1f2a0e5b7c01"
UUID_B = "b17c9f5a-72d4-4f0b-a6c1-8e93d2b40f77"


# --------------------------------------------------------------------------
# 测试数据构造
# --------------------------------------------------------------------------


def _add_vcenter(conn: sqlite3.Connection, host: str) -> str:
    vcenter_id = f"vc-{host}"
    conn.execute(
        """
        INSERT INTO vcenters (vcenter_id, customer_id, site_id, name, host, port, username, ssl_verify, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (vcenter_id, CUSTOMER_ID, SITE_ID, host, host, 443, "administrator@vsphere.local", 0, "active", NOW, NOW),
    )
    return vcenter_id


def _add_scope(conn: sqlite3.Connection) -> None:
    conn.execute(
        "INSERT INTO customers (customer_id, customer_name, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        (CUSTOMER_ID, "客户 A", "active", NOW, NOW),
    )
    conn.execute(
        "INSERT INTO sites (site_id, customer_id, site_name, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        (SITE_ID, CUSTOMER_ID, "生产站点", "active", NOW, NOW),
    )


def _add_run(
    conn: sqlite3.Connection,
    run_id: str,
    vcenter_id: str,
    finished_at: str,
    *,
    score: float | None = 80.0,
    risks: dict[str, int] | None = None,
    run_status: str = "success",
) -> str:
    conn.execute(
        """
        INSERT INTO inspection_runs (
          run_id, customer_id, site_id, vcenter_id, trigger_type, run_status, current_stage,
          progress_percent, asset_summary_json, risk_summary_json, score, started_at, finished_at,
          created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            CUSTOMER_ID,
            SITE_ID,
            vcenter_id,
            "manual",
            run_status,
            "success",
            100,
            json.dumps({}),
            json.dumps(risks or {"P1": 0, "P2": 0, "P3": 0, "P4": 0}),
            score,
            finished_at,
            finished_at,
            finished_at,
            finished_at,
        ),
    )
    return run_id


def _add_snapshot(conn: sqlite3.Connection, run_id: str, vcenter_id: str) -> str:
    snapshot_id = f"snap-{run_id}"
    conn.execute(
        """
        INSERT INTO inventory_snapshots (
          snapshot_id, run_id, customer_id, site_id, vcenter_id, snapshot_type, collected_at,
          object_count, summary_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (snapshot_id, run_id, CUSTOMER_ID, SITE_ID, vcenter_id, "full", NOW, 0, json.dumps({}), NOW),
    )
    return snapshot_id


def _add_vcenter_object(conn: sqlite3.Connection, run_id: str, vcenter_id: str, instance_uuid: str) -> None:
    """模拟采集器把 vCenter about.instanceUuid 写入 inventory_objects.object_key。"""
    snapshot_id = _add_snapshot(conn, run_id, vcenter_id)
    conn.execute(
        """
        INSERT INTO inventory_objects (
          object_id, snapshot_id, run_id, customer_id, vcenter_id, object_type, object_key,
          object_name, path, properties_json, raw_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            f"obj-{run_id}-vcenter",
            snapshot_id,
            run_id,
            CUSTOMER_ID,
            vcenter_id,
            "vCenter",
            instance_uuid,
            "vcenter-root",
            "vcenter-root",
            json.dumps({"properties": {"asset_location": "vCenter 根对象"}}),
            json.dumps({}),
            NOW,
        ),
    )


def _add_asset(
    conn: sqlite3.Connection,
    run_id: str,
    vcenter_id: str,
    object_type: str,
    object_key: str,
    object_name: str,
) -> None:
    snapshot_id = f"snap-{run_id}"
    conn.execute(
        """
        INSERT INTO inventory_objects (
          object_id, snapshot_id, run_id, customer_id, vcenter_id, object_type, object_key,
          object_name, path, properties_json, raw_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            f"obj-{run_id}-{object_type}-{object_key}",
            snapshot_id,
            run_id,
            CUSTOMER_ID,
            vcenter_id,
            object_type,
            object_key,
            object_name,
            f"Cluster-1/{object_name}",
            json.dumps({"properties": {"asset_location": "Cluster-1"}}),
            json.dumps({}),
            NOW,
        ),
    )


def _add_rule_result(
    conn: sqlite3.Connection,
    run_id: str,
    vcenter_id: str,
    rule_id: str,
    object_type: str,
    object_key: str,
    object_name: str,
    *,
    risk_level: str = "P1",
    result_status: str = "failed",
) -> None:
    conn.execute(
        """
        INSERT INTO rule_results (
          result_id, run_id, rule_id, customer_id, vcenter_id, object_type, object_key,
          object_name, object_path, result_status, risk_level, confidence_level,
          observed_value, expected_value, evidence_json, raw_json, error_message,
          evaluated_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            f"res-{run_id}-{rule_id}-{object_key}",
            run_id,
            rule_id,
            CUSTOMER_ID,
            vcenter_id,
            object_type,
            object_key,
            object_name,
            f"Cluster-1/{object_name}",
            result_status,
            risk_level,
            "high",
            "当前状态",
            "建议状态",
            json.dumps({"current_value": "当前状态", "expected_value": "建议状态"}),
            json.dumps({}),
            None,
            NOW,
            NOW,
        ),
    )


def _prepare_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "history-compare.db"
    init_db(db_path)
    with connect(db_path) as conn:
        _add_scope(conn)
        _add_vcenter(conn, "vc-a.example")
        _add_vcenter(conn, "vc-b.example")
        conn.commit()
    return db_path


def _build(db_path: Path, baseline_run_id: str | None = None, comparison_run_id: str | None = None) -> dict:
    with connect(db_path) as conn:
        return HistoryComparisonBuilder().build(conn, baseline_run_id, comparison_run_id)


def _add_environment_run(
    db_path: Path,
    run_id: str,
    host: str,
    finished_at: str,
    *,
    score: float = 80.0,
    risks: dict[str, int] | None = None,
    instance_uuid: str = "",
    run_status: str = "success",
) -> str:
    with connect(db_path) as conn:
        vcenter_id = f"vc-{host}"
        _add_run(conn, run_id, vcenter_id, finished_at, score=score, risks=risks, run_status=run_status)
        _add_vcenter_object(conn, run_id, vcenter_id, instance_uuid or f"{host}-instance")
        conn.commit()
    return run_id


def _assert_not_comparable(payload: dict) -> None:
    assert payload["state"] != STATE_READY
    assert payload["summary_text"]
    assert payload["risk_changes"] == {"new": [], "closed": [], "persistent": []}
    assert payload["asset_changes"] == {"new": [], "removed": [], "persistent": []}
    assert payload["score"]["delta"] is None
    for level in ("P1", "P2", "P3"):
        assert payload["risk_counts"][level]["delta"] == 0
        assert payload["risk_counts"][level]["baseline"] == 0
    for key in ("vcenter", "cluster", "host", "datastore", "vm"):
        assert payload["asset_counts"][key]["delta"] == 0


# --------------------------------------------------------------------------
# 场景 1：空数据库
# --------------------------------------------------------------------------


def test_empty_database_returns_empty_state(tmp_path: Path) -> None:
    db_path = _prepare_db(tmp_path)

    payload = _build(db_path)

    assert payload["state"] == STATE_EMPTY
    assert payload["run_options"] == []
    assert payload["summary_text"]


# --------------------------------------------------------------------------
# 场景 2 / 4：两个环境各一次成功巡检
# --------------------------------------------------------------------------


def test_two_environments_one_run_each_is_not_comparable(tmp_path: Path) -> None:
    db_path = _prepare_db(tmp_path)
    _add_environment_run(db_path, "run-a1", "vc-a.example", "2026-09-01T10:00:00+00:00")
    _add_environment_run(db_path, "run-b1", "vc-b.example", "2026-09-02T10:00:00+00:00")

    payload = _build(db_path)

    assert payload["state"] == STATE_SINGLE_RUN
    assert payload["comparison_run_id"] == "run-b1"
    # vCenter B 只有一次巡检，不能用 A 的记录补足第二次巡检。
    assert [option["run_id"] for option in payload["run_options"]] == ["run-b1"]
    _assert_not_comparable(payload)


def test_run_options_never_mix_two_environments(tmp_path: Path) -> None:
    db_path = _prepare_db(tmp_path)
    _add_environment_run(db_path, "run-a1", "vc-a.example", "2026-09-01T10:00:00+00:00")
    _add_environment_run(db_path, "run-a2", "vc-a.example", "2026-09-02T10:00:00+00:00")
    _add_environment_run(db_path, "run-b1", "vc-b.example", "2026-09-03T10:00:00+00:00")

    latest_env = _build(db_path)
    oldest_env = _build(db_path, comparison_run_id="run-a2")
    older_env = _build(db_path, comparison_run_id="run-a1")

    assert [option["run_id"] for option in latest_env["run_options"]] == ["run-b1"]
    assert latest_env["state"] == STATE_SINGLE_RUN
    assert [option["run_id"] for option in oldest_env["run_options"]] == ["run-a2", "run-a1"]
    assert [option["run_id"] for option in older_env["run_options"]] == ["run-a2", "run-a1"]


def test_single_run_environment_does_not_borrow_other_environment(tmp_path: Path) -> None:
    db_path = _prepare_db(tmp_path)
    _add_environment_run(db_path, "run-a1", "vc-a.example", "2026-09-01T10:00:00+00:00")
    _add_environment_run(db_path, "run-a2", "vc-a.example", "2026-09-02T10:00:00+00:00")
    _add_environment_run(db_path, "run-a3", "vc-a.example", "2026-09-03T10:00:00+00:00")
    _add_environment_run(db_path, "run-b1", "vc-b.example", "2026-09-04T10:00:00+00:00")

    payload = _build(db_path)
    anchored = _build(db_path, comparison_run_id="run-b1")

    assert payload["state"] == STATE_SINGLE_RUN
    assert payload["comparison_run_id"] == "run-b1"
    assert [option["run_id"] for option in payload["run_options"]] == ["run-b1"]
    _assert_not_comparable(payload)
    assert anchored["state"] == STATE_SINGLE_RUN
    assert anchored["comparison_run_id"] == "run-b1"
    _assert_not_comparable(anchored)


# --------------------------------------------------------------------------
# 场景 3：同一 vCenter 两次成功巡检
# --------------------------------------------------------------------------


def test_same_vcenter_two_successful_runs_produce_ready_comparison(tmp_path: Path) -> None:
    db_path = _prepare_db(tmp_path)
    vcenter_a = "vc-vc-a.example"
    with connect(db_path) as conn:
        _add_run(conn, "run-a1", vcenter_a, "2026-09-01T10:00:00+00:00", score=80.0, risks={"P1": 2, "P2": 1, "P3": 0, "P4": 0})
        _add_vcenter_object(conn, "run-a1", vcenter_a, UUID_A)
        _add_asset(conn, "run-a1", vcenter_a, "VirtualMachine", "vm-1", "app-01")
        _add_asset(conn, "run-a1", vcenter_a, "HostSystem", "host-1", "esxi-01")
        _add_rule_result(conn, "run-a1", vcenter_a, "VSL-VM-001", "VirtualMachine", "vm-1", "app-01", risk_level="P1")
        _add_rule_result(conn, "run-a1", vcenter_a, "VSL-HOST-002", "HostSystem", "host-2", "esxi-02", risk_level="P2")

        _add_run(conn, "run-a2", vcenter_a, "2026-09-02T10:00:00+00:00", score=90.0, risks={"P1": 1, "P2": 0, "P3": 1, "P4": 0})
        _add_vcenter_object(conn, "run-a2", vcenter_a, UUID_A)
        _add_asset(conn, "run-a2", vcenter_a, "VirtualMachine", "vm-1", "app-01")
        _add_asset(conn, "run-a2", vcenter_a, "VirtualMachine", "vm-2", "app-02")
        _add_rule_result(conn, "run-a2", vcenter_a, "VSL-VM-001", "VirtualMachine", "vm-1", "app-01", risk_level="P1")
        _add_rule_result(conn, "run-a2", vcenter_a, "VSL-VM-007", "VirtualMachine", "vm-2", "app-02", risk_level="P3")
        conn.commit()

    payload = _build(db_path)

    assert payload["state"] == STATE_READY
    assert payload["baseline_run_id"] == "run-a1"
    assert payload["comparison_run_id"] == "run-a2"
    assert payload["score"]["delta"] == 10.0
    assert payload["score"]["baseline"] == 80.0
    assert payload["score"]["comparison"] == 90.0
    assert payload["risk_changes"]["new"] and payload["risk_changes"]["closed"] and payload["risk_changes"]["persistent"]
    assert payload["asset_changes"]["new"] and payload["asset_changes"]["removed"]
    assert payload["summary_text"]
    assert [option["run_id"] for option in payload["run_options"]] == ["run-a2", "run-a1"]
    assert "vc-a.example" in payload["run_options"][0]["label"]
    assert "vc-a.example" in payload["environment_label"]


# --------------------------------------------------------------------------
# 场景 5：显式传入跨环境的 baseline / comparison
# --------------------------------------------------------------------------


def test_explicit_cross_environment_runs_are_environment_mismatch(tmp_path: Path) -> None:
    db_path = _prepare_db(tmp_path)
    _add_environment_run(db_path, "run-a1", "vc-a.example", "2026-09-01T10:00:00+00:00", risks={"P1": 3, "P2": 0, "P3": 0, "P4": 0})
    _add_environment_run(db_path, "run-b1", "vc-b.example", "2026-09-02T10:00:00+00:00", risks={"P1": 0, "P2": 0, "P3": 0, "P4": 0})

    forward = _build(db_path, "run-a1", "run-b1")
    backward = _build(db_path, "run-b1", "run-a1")

    assert forward["state"] == STATE_ENVIRONMENT_MISMATCH
    assert "vCenter 环境" in forward["summary_text"]
    assert forward["summary_text"] == "所选巡检记录属于不同的 vCenter 环境，无法进行历史对比。"
    _assert_not_comparable(forward)

    assert backward["state"] == STATE_ENVIRONMENT_MISMATCH
    assert "vCenter 环境" in backward["summary_text"]
    _assert_not_comparable(backward)


def test_invalid_explicit_run_ids_do_not_fall_back_to_other_environment(tmp_path: Path) -> None:
    db_path = _prepare_db(tmp_path)
    _add_environment_run(db_path, "run-a1", "vc-a.example", "2026-09-01T10:00:00+00:00")
    _add_environment_run(db_path, "run-a2", "vc-a.example", "2026-09-02T10:00:00+00:00")

    unknown = _build(db_path, "run-a1", "run-not-exists")
    unknown_baseline = _build(db_path, "run-not-exists", "run-a2")
    valid_pair = _build(db_path, "run-a1", "run-a2")

    assert unknown["state"] == STATE_RUN_UNAVAILABLE
    _assert_not_comparable(unknown)
    assert unknown["run_options"] == []
    assert unknown_baseline["state"] == STATE_RUN_UNAVAILABLE
    _assert_not_comparable(unknown_baseline)
    assert [option["run_id"] for option in unknown_baseline["run_options"]] == ["run-a2", "run-a1"]
    assert valid_pair["state"] == STATE_READY


def test_failed_or_running_runs_are_not_candidates(tmp_path: Path) -> None:
    db_path = _prepare_db(tmp_path)
    _add_environment_run(db_path, "run-a1", "vc-a.example", "2026-09-01T10:00:00+00:00")
    _add_environment_run(db_path, "run-a2", "vc-a.example", "2026-09-02T10:00:00+00:00", run_status="failed")
    _add_environment_run(db_path, "run-a3", "vc-a.example", "2026-09-03T10:00:00+00:00", run_status="running")
    _add_environment_run(db_path, "run-a4", "vc-a.example", "2026-09-04T10:00:00+00:00", run_status="cancelled")

    payload = _build(db_path)
    failed_anchor = _build(db_path, "run-a1", "run-a2")

    assert payload["state"] == STATE_SINGLE_RUN
    assert payload["comparison_run_id"] == "run-a1"
    assert [option["run_id"] for option in payload["run_options"]] == ["run-a1"]
    _assert_not_comparable(payload)

    assert failed_anchor["state"] == STATE_RUN_UNAVAILABLE
    _assert_not_comparable(failed_anchor)


def test_failed_baseline_run_id_is_rejected(tmp_path: Path) -> None:
    db_path = _prepare_db(tmp_path)
    _add_environment_run(db_path, "run-a1", "vc-a.example", "2026-09-01T10:00:00+00:00")
    _add_environment_run(db_path, "run-a2", "vc-a.example", "2026-09-02T10:00:00+00:00")
    _add_environment_run(db_path, "run-a3", "vc-a.example", "2026-09-03T10:00:00+00:00", run_status="failed")

    payload = _build(db_path, "run-a3", "run-a2")

    assert payload["state"] == STATE_RUN_UNAVAILABLE
    _assert_not_comparable(payload)


def test_run_options_stay_in_environment_when_baseline_is_rejected(tmp_path: Path) -> None:
    db_path = _prepare_db(tmp_path)
    _add_environment_run(db_path, "run-a1", "vc-a.example", "2026-09-01T10:00:00+00:00")
    _add_environment_run(db_path, "run-a2", "vc-a.example", "2026-09-02T10:00:00+00:00")
    _add_environment_run(db_path, "run-b1", "vc-b.example", "2026-09-03T10:00:00+00:00")

    payload = _build(db_path, "run-a1", "run-b1")

    assert payload["state"] == STATE_ENVIRONMENT_MISMATCH
    assert [option["run_id"] for option in payload["run_options"]] == ["run-b1"]
    _assert_not_comparable(payload)


# --------------------------------------------------------------------------
# 第二层校验：vcenter_id 相同但 instanceUuid 不同
# --------------------------------------------------------------------------


def test_same_vcenter_id_with_different_instance_uuid_is_not_comparable(tmp_path: Path) -> None:
    db_path = _prepare_db(tmp_path)
    vcenter_a = "vc-vc-a.example"
    with connect(db_path) as conn:
        _add_run(conn, "run-a1", vcenter_a, "2026-09-01T10:00:00+00:00", score=80.0)
        _add_vcenter_object(conn, "run-a1", vcenter_a, UUID_A)
        _add_run(conn, "run-a2", vcenter_a, "2026-09-02T10:00:00+00:00", score=85.0)
        _add_vcenter_object(conn, "run-a2", vcenter_a, UUID_B)
        conn.commit()

    payload = _build(db_path)

    assert payload["state"] == STATE_ENVIRONMENT_MISMATCH
    _assert_not_comparable(payload)


def test_same_instance_uuid_keeps_comparison_ready(tmp_path: Path) -> None:
    db_path = _prepare_db(tmp_path)
    vcenter_a = "vc-vc-a.example"
    with connect(db_path) as conn:
        _add_run(conn, "run-a1", vcenter_a, "2026-09-01T10:00:00+00:00", score=80.0)
        _add_vcenter_object(conn, "run-a1", vcenter_a, UUID_A)
        _add_run(conn, "run-a2", vcenter_a, "2026-09-02T10:00:00+00:00", score=85.0)
        _add_vcenter_object(conn, "run-a2", vcenter_a, UUID_A)
        conn.commit()

    payload = _build(db_path)

    assert payload["state"] == STATE_READY
    assert payload["score"]["delta"] == 5.0


# --------------------------------------------------------------------------
# 服务层：不可比状态必须完整传递，不得被改写成 ready
# --------------------------------------------------------------------------


def test_service_preserves_environment_mismatch_state(tmp_path: Path) -> None:
    db_path = _prepare_db(tmp_path)
    _add_environment_run(db_path, "run-a1", "vc-a.example", "2026-09-01T10:00:00+00:00", risks={"P1": 3, "P2": 0, "P3": 0, "P4": 0})
    _add_environment_run(db_path, "run-b1", "vc-b.example", "2026-09-02T10:00:00+00:00")

    service = InspectionService(config_path=tmp_path / "desktop_config.json")
    comparison = service.get_history_comparison(db_path, "run-a1", "run-b1")

    assert comparison.state == STATE_ENVIRONMENT_MISMATCH
    assert comparison.state != STATE_READY
    assert comparison.summary_text == "所选巡检记录属于不同的 vCenter 环境，无法进行历史对比。"
    assert comparison.score.delta is None
    assert comparison.risk_changes["new"] == []
    assert comparison.asset_changes["new"] == []
    assert all(comparison.risk_counts[level].delta == 0 for level in ("P1", "P2", "P3"))
    assert all(comparison.asset_counts[key].delta == 0 for key in ("vcenter", "cluster", "host", "datastore", "vm"))
    assert comparison.environment_label


def test_service_summary_does_not_pair_across_environments(tmp_path: Path) -> None:
    db_path = _prepare_db(tmp_path)
    _add_environment_run(db_path, "run-a1", "vc-a.example", "2026-09-01T10:00:00+00:00")
    _add_environment_run(db_path, "run-b1", "vc-b.example", "2026-09-02T10:00:00+00:00")

    service = InspectionService(config_path=tmp_path / "desktop_config.json")
    summary = service.get_history_comparison_summary(db_path)

    assert summary.has_data is False
    assert summary.previous_run_id is None
    assert summary.current_run_id == "run-b1"
