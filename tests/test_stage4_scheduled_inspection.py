from __future__ import annotations
from contextlib import closing
from datetime import datetime, timedelta
import json
from pathlib import Path
import sqlite3
import threading
import time

import pytest

from test_stage3_batch_inspection import setup, SECRETS
from vstacklens.application.scheduled_inspection import ScheduledInspectionService, next_occurrence
from vstacklens.application.batch_inspection import BatchInspectionService, SessionCredential
from vstacklens.application.execution_guard import execution_lease
from vstacklens.core import process_identity
from vstacklens.core.process_identity import ProcessCheck, OwnerState
from vstacklens.db.connection import connect
from vstacklens.db.schedule_store import ScheduleStore
from vstacklens.deep.backup import restore_history_backup


class Clock:
    def __init__(self):
        self.wall = datetime.fromisoformat("2026-10-13T00:59:58+00:00")
        self.mono = 100.0
    def now(self): return self.wall
    def monotonic(self): return self.mono
    def advance(self, seconds): self.wall += timedelta(seconds=seconds); self.mono += seconds
    def jump(self, seconds): self.wall += timedelta(seconds=seconds)


@pytest.fixture
def scheduled(setup):
    single, batch, settings, ids, credentials, controls = setup
    clock = Clock()
    service = ScheduledInspectionService(settings.db_path, batch_manager=batch, clock=clock.now, monotonic=clock.monotonic)
    plan = service.save_plan(name="离线每日计划", environment_ids=ids, settings=settings)
    assert service.tick() is None
    yield service, plan, clock, single, settings, ids, credentials, controls
    if service._active is not None and service._running_trigger is None:
        service.finish_shutdown()
    elif service._running_trigger is None:
        service.finish_shutdown()


def authorize_due(scheduled):
    service, plan, clock, _, _, _, credentials, _ = scheduled
    service.authorize(plan["schedule_id"], credentials, consent=True)
    clock.advance(2)
    return service.tick()


def test_daily_multi_environment_uses_formal_reports_and_private_copies(scheduled, caplog):
    service, plan, clock, single, settings, ids, credentials, controls = scheduled
    single.save_config(single.load_config())
    config_before = single.config_path.read_bytes()
    trigger = authorize_due(scheduled)
    assert trigger and service.tick() is None and service.tick() is None
    result = service.run_trigger(trigger)
    assert result["counts"]["completed"] == 2
    assert service.store.occurrences(plan["schedule_id"])[0]["state"] == "completed"
    assert single.config_path.read_bytes() == config_before
    assert not service.batch._credentials and plan["schedule_id"] in service._grants
    for item in result["items"]:
        assert set(single.desktop_report_formats(settings.db_path, item["run_id"])) == {"HTML", "Word", "PDF"}
    with closing(connect(settings.db_path)) as conn:
        dumped = "\n".join(conn.iterdump())
        assert conn.execute("SELECT COUNT(*) FROM standard_batches").fetchone()[0] == 1
    assert not any(secret in dumped or secret in caplog.text or secret.encode() in config_before for secret in SECRETS)
    import fitz
    from zipfile import ZipFile
    for path in settings.report_output_dir.rglob("*"):
        if not path.is_file(): continue
        if path.suffix == ".docx":
            with ZipFile(path) as archive: text = "\n".join(archive.read(n).decode(errors="replace") for n in archive.namelist() if n.endswith(".xml"))
        elif path.suffix == ".pdf":
            with fitz.open(path) as doc: text = "\n".join(page.get_text() for page in doc)
        elif path.suffix in {".json", ".html", ".log", ".md"}: text = path.read_text(encoding="utf-8")
        else: continue
        assert all(secret not in text for secret in SECRETS)
    service.finish_shutdown()
    assert not service._grants and not service.batch._credentials


def test_no_consent_and_missing_one_environment_cannot_borrow_password(scheduled):
    service, plan, clock, _, _, ids, credentials, controls = scheduled
    with pytest.raises(ValueError, match="主动授权"): service.authorize(plan["schedule_id"], credentials)
    with pytest.raises(ValueError, match="分别填写"): service.authorize(plan["schedule_id"], {ids[0]: credentials[ids[0]]}, consent=True)
    clock.advance(2)
    assert service.tick() is None and not controls["calls"]
    latest = service.store.occurrences(plan["schedule_id"])[0]
    assert latest["state"] == "skipped" and "等待凭据" in latest["reason"]
    assert "等待凭据" in service.readiness(service.store.get(plan["schedule_id"]))


@pytest.mark.parametrize("change", ["name", "customer", "address", "username", "disabled"])
def test_environment_change_stops_schedule_without_reusing_old_authorization(scheduled, change):
    service, plan, clock, single, settings, ids, credentials, controls = scheduled
    service.authorize(plan["schedule_id"], credentials, consent=True)
    if change == "disabled": single.set_environment_enabled(settings.db_path, ids[0], False)
    else:
        args = dict(name="离线环境0", customer_name="离线客户0", address="192.0.2.10", username="offline-0")
        args[{"name": "name", "customer": "customer_name", "address": "address", "username": "username"}[change]] = {"name": "新名称", "customer": "新客户", "address": "192.0.2.20", "username": "new-user"}[change]
        single.save_environment_archive(settings.db_path, environment_id=ids[0], **args)
    clock.advance(2)
    assert service.tick() is None and not controls["calls"]
    assert "变化" in service.store.occurrences(plan["schedule_id"])[0]["reason"]


def test_cross_customer_duplicate_address_blocks_even_authorization(scheduled):
    service, plan, _, single, settings, ids, credentials, controls = scheduled
    single.save_environment_archive(settings.db_path, name="另一个客户相同地址", customer_name="第三客户", address="192.0.2.10", username="other-user")
    with pytest.raises(ValueError, match="重复地址"): service.authorize(plan["schedule_id"], credentials, consent=True)
    assert not controls["calls"]


@pytest.mark.parametrize("unknown", [False, True])
def test_conflicting_or_unknown_lease_skips_without_queuing(scheduled, monkeypatch, unknown):
    service, plan, clock, _, settings, ids, credentials, controls = scheduled
    service.authorize(plan["schedule_id"], credentials, consent=True)
    with execution_lease(settings.db_path, ids[0], "192.0.2.10", 443):
        if unknown: monkeypatch.setattr(process_identity, "_read_process", lambda pid: ProcessCheck(OwnerState.UNKNOWN, "权限不足"))
        with closing(connect(settings.db_path)) as conn: before = [tuple(r) for r in conn.execute("SELECT * FROM inspection_execution_leases")]
        clock.advance(2); assert service.tick() is None
        with closing(connect(settings.db_path)) as conn:
            assert [tuple(r) for r in conn.execute("SELECT * FROM inspection_execution_leases")] == before
            assert conn.execute("SELECT COUNT(*) FROM standard_batches").fetchone()[0] == 0
    assert not controls["calls"]
    assert ("无法确认" if unknown else "其他巡检") in service.store.occurrences(plan["schedule_id"])[0]["reason"]


@pytest.mark.parametrize("jump", [3600, -3600])
def test_clock_jump_does_not_replay_or_catch_up(scheduled, jump):
    service, plan, clock, _, _, _, credentials, controls = scheduled
    service.authorize(plan["schedule_id"], credentials, consent=True)
    clock.jump(jump); assert service.tick() is None
    if jump > 0:
        latest = service.store.occurrences(plan["schedule_id"])[0]
        assert "时钟变化" in latest["reason"]
    assert not controls["calls"]


def test_sleep_gap_and_pause_never_catch_up(scheduled):
    service, plan, clock, _, _, _, credentials, controls = scheduled
    service.authorize(plan["schedule_id"], credentials, consent=True)
    clock.advance(3600); assert service.tick() is None and not controls["calls"]
    assert "未自动补跑" in service.store.occurrences(plan["schedule_id"])[0]["reason"]
    service.paused = True
    next_time = datetime.fromisoformat(service.store.get(plan["schedule_id"])["next_fire_at"])
    clock.wall = next_time - timedelta(seconds=1); service.tick(); clock.advance(1); service.tick()
    assert "暂停" in service.store.occurrences(plan["schedule_id"])[0]["reason"]
    service.paused = False; assert service.tick() is None and not controls["calls"]


def test_multiple_instances_and_unique_slot_cannot_submit_twice(scheduled):
    service, plan, clock, _, settings, _, credentials, controls = scheduled
    other = ScheduledInspectionService(settings.db_path, clock=clock.now, monotonic=clock.monotonic)
    other.authorize(plan["schedule_id"], credentials, consent=True)
    service.authorize(plan["schedule_id"], credentials, consent=True)
    clock.advance(2)
    assert other.tick() is None and other.runtime_reason
    trigger = service.tick(); assert trigger
    assert service.tick() is None
    assert not service.store.claim(plan["schedule_id"], trigger.slot)
    service.run_trigger(trigger)
    assert len(controls["calls"]) == 2
    other.finish_shutdown()


def test_restart_retains_settings_but_waits_for_new_session_authorization(scheduled):
    service, plan, clock, _, settings, _, _, controls = scheduled
    authorize_due(scheduled); service.finish_shutdown()  # Unstarted callback is cancelled safely.
    assert not controls["calls"]
    other = ScheduledInspectionService(settings.db_path, clock=clock.now, monotonic=clock.monotonic)
    assert "等待凭据" in other.readiness(other.store.get(plan["schedule_id"]))
    other.tick(); assert not controls["calls"]
    next_time = datetime.fromisoformat(other.store.get(plan["schedule_id"])["next_fire_at"])
    clock.wall = next_time - timedelta(seconds=1); other.tick(); clock.advance(1); assert other.tick() is None
    assert "等待凭据" in other.store.occurrences(plan["schedule_id"])[0]["reason"]
    other.finish_shutdown()


def test_missed_startup_is_recorded_without_auto_run(scheduled):
    service, plan, clock, _, settings, _, _, controls = scheduled
    service.finish_shutdown(); clock.advance(3600)
    other = ScheduledInspectionService(settings.db_path, clock=clock.now, monotonic=clock.monotonic)
    assert other.tick() is None
    assert "重启" in other.store.occurrences(plan["schedule_id"])[0]["reason"]
    assert not controls["calls"]; other.finish_shutdown()


def test_running_plan_skips_another_due_plan_and_exit_cancels_safely(scheduled):
    service, plan, clock, _, settings, ids, credentials, controls = scheduled
    second = service.save_plan(name="第二计划", environment_ids=ids, settings=settings)
    service.authorize(plan["schedule_id"], credentials, consent=True); service.authorize(second["schedule_id"], credentials, consent=True)
    controls["behaviors"]["192.0.2.10"] = "block"
    clock.advance(2); trigger = service.tick(); assert trigger
    assert service.tick() is None
    assert "仍在运行" in service.store.occurrences(second["schedule_id"])[0]["reason"]
    results = []
    worker = threading.Thread(target=lambda: results.append(service.run_trigger(trigger)))
    worker.start(); assert controls["started"].wait(10)
    with pytest.raises(ValueError, match="已在运行"): service.run_trigger(trigger)
    service.stop(); worker.join(15); assert not worker.is_alive()
    service.finish_shutdown()
    assert len(controls["calls"]) == 1 and not service._grants and not service.batch._credentials
    assert results[0]["counts"]["cancelled"] == 2 and service.tick() is None


def test_plan_edit_revokes_authorization_and_optimistic_revision_blocks_duplicate_edit(scheduled):
    service, plan, _, _, settings, ids, credentials, _ = scheduled
    service.authorize(plan["schedule_id"], credentials, consent=True)
    changed = service.save_plan(name="改过的计划", environment_ids=ids, settings=settings, schedule_id=plan["schedule_id"], expected_revision=plan["revision"])
    assert changed["revision"] == 2 and not service._grants
    with pytest.raises(ValueError, match="其他窗口"):
        service.save_plan(name="旧页面", environment_ids=ids, settings=settings, schedule_id=plan["schedule_id"], expected_revision=1)


def test_weekly_timezone_dst_gap_and_fold_have_one_future_slot():
    weekly = dict(frequency="weekly", weekdays=[2], local_time="09:00", timezone="Asia/Shanghai")
    assert next_occurrence(weekly, datetime.fromisoformat("2026-10-13T00:00:00+00:00")) == "2026-10-14T01:00:00+00:00"
    daily = dict(frequency="daily", weekdays=[], local_time="02:30", timezone="America/New_York")
    assert next_occurrence(daily, datetime.fromisoformat("2026-03-08T00:00:00+00:00")) == "2026-03-09T06:30:00+00:00"
    daily["local_time"] = "01:30"
    assert next_occurrence(daily, datetime.fromisoformat("2026-11-01T05:31:00+00:00")) == "2026-11-02T06:30:00+00:00"


def test_schema_backup_and_restoration_before_creation(setup, tmp_path):
    _, _, settings, _, _, _ = setup
    ScheduleStore(settings.db_path)
    backups = list(settings.db_path.parent.glob("*.before-stage4-schedules-*.bak"))
    assert backups and backups[0].with_name(backups[0].name + ".restore-verified").exists()
    restored = restore_history_backup(backups[0], tmp_path / "again-restored.db")
    with sqlite3.connect(restored) as conn:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert conn.execute("SELECT COUNT(*) FROM vcenters").fetchone()[0] == 2
        assert not conn.execute("SELECT name FROM sqlite_master WHERE name='inspection_schedules'").fetchone()


def test_restore_failure_stops_schedule_schema_migration(setup, monkeypatch):
    _, _, settings, _, _, _ = setup
    import vstacklens.deep.backup as backup
    monkeypatch.setattr(backup, "restore_history_backup", lambda *args: (_ for _ in ()).throw(OSError("offline restore failure")))
    with pytest.raises(OSError): ScheduleStore(settings.db_path)
    with closing(connect(settings.db_path)) as conn:
        assert not conn.execute("SELECT name FROM sqlite_master WHERE name='inspection_schedules'").fetchone()


def test_schedule_does_not_persist_arbitrary_configuration_secrets(scheduled):
    service, _, _, _, settings, ids, _, _ = scheduled
    from vstacklens.application.inspection_service import DesktopInspectionConfig
    before = service.store.plans()
    with pytest.raises(ValueError, match="公开配置"):
        service.save_plan(name="wrong-config", environment_ids=ids, settings=DesktopInspectionConfig(db_path=settings.db_path, password=SECRETS[0]))
    assert service.store.plans() == before


def test_two_real_local_processes_cannot_submit_same_schedule_slot(scheduled):
    import subprocess
    import sys
    service, plan, _, _, settings, _, _, controls = scheduled
    service.finish_shutdown()
    script = Path(__file__).parent / "fixtures" / "stage4_process_probe.py"
    children = []
    try:
        for _ in range(2):
            child = subprocess.Popen([sys.executable, "-u", str(script), str(settings.db_path), plan["schedule_id"]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
            children.append(child)
            assert child.stdout.readline().strip() == "READY"
        for child in children:
            child.stdin.write("GO\n"); child.stdin.flush()
        results = [child.stdout.readline().strip() for child in children]
        assert sorted(results) == ["BLOCKED", "SUBMITTED"]
        with closing(connect(settings.db_path)) as conn:
            assert conn.execute("SELECT COUNT(*) FROM standard_batches").fetchone()[0] == 1
            assert conn.execute("SELECT COUNT(*) FROM schedule_occurrences").fetchone()[0] == 1
            assert "OFFLINE-PROCESS-SECRET-" not in "\n".join(conn.iterdump())
        assert not controls["calls"]
    finally:
        for child in children:
            if child.poll() is None:
                try: child.stdin.write("QUIT\n"); child.stdin.flush()
                except OSError: pass
            child.stdin.close()
            assert child.wait(timeout=20) == 0
            assert child.stdout.readline().strip() == "CLEAN"
            assert not child.stderr.read()


def test_exit_cleanup_still_clears_private_copies_when_metadata_write_fails(scheduled, monkeypatch):
    service, _, _, _, _, _, _, controls = scheduled
    authorize_due(scheduled)
    monkeypatch.setattr(service.store, "outcome", lambda *args, **kwargs: (_ for _ in ()).throw(sqlite3.OperationalError("offline metadata unavailable")))
    with pytest.raises(sqlite3.Error): service.finish_shutdown()
    assert not service._grants and not service.batch._credentials
    assert not controls["calls"] and service.tick() is None


@pytest.mark.parametrize("mode,expected", [("connection", "partial_failed"), ("no_identity", "partial_failed"), ("partial", "partial_failed")])
def test_failed_target_preserves_independent_results_and_continues(scheduled, mode, expected):
    service, plan, _, _, _, _, _, controls = scheduled
    controls["behaviors"]["192.0.2.10"] = mode
    trigger = authorize_due(scheduled); result = service.run_trigger(trigger)
    assert result["items"][1]["state"] == "completed"
    assert service.store.occurrences(plan["schedule_id"])[0]["state"] == expected
    assert not service.batch._credentials


def test_plan_report_failure_is_not_completed(scheduled, monkeypatch):
    service, plan, _, _, _, _, _, _ = scheduled
    from vstacklens.reports.pdf_report import PdfReportEngine
    monkeypatch.setattr(PdfReportEngine, "render", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("offline publish failure")))
    result = service.run_trigger(authorize_due(scheduled))
    assert result["counts"]["partial_failed"] == 2
    assert service.store.occurrences(plan["schedule_id"])[0]["state"] == "partial_failed"


def test_busy_database_never_catches_up_or_blocks_scheduler_loop(scheduled):
    service, plan, clock, _, settings, _, credentials, controls = scheduled
    service.authorize(plan["schedule_id"], credentials, consent=True)
    with closing(connect(settings.db_path)) as writer:
        writer.execute("BEGIN IMMEDIATE")
        clock.advance(2)
        started = time.monotonic(); assert service.tick() is None
        assert time.monotonic() - started < 2
        assert "数据库" in service.readiness(service.store.get(plan["schedule_id"]))
        writer.rollback()
    clock.advance(1); assert service.tick() is None
    assert "数据库" in service.store.occurrences(plan["schedule_id"])[0]["reason"]
    assert not controls["calls"]


def test_clock_backward_after_completed_slot_never_schedules_earlier_dates(scheduled):
    service, plan, clock, _, _, _, _, controls = scheduled
    service.run_trigger(authorize_due(scheduled))
    next_slot = service.store.get(plan["schedule_id"])["next_fire_at"]
    clock.jump(-86400 * 2); assert service.tick() is None
    assert service.store.get(plan["schedule_id"])["next_fire_at"] == next_slot
    clock.advance(2); assert service.tick() is None and len(controls["calls"]) == 2


@pytest.mark.parametrize("unknown", [False, True])
def test_restart_occurrence_does_not_resume_or_mislabel_unknown_process(scheduled, monkeypatch, unknown):
    service, plan, clock, _, settings, _, _, controls = scheduled
    trigger = authorize_due(scheduled)
    service._active = None  # Simulate a lost callback; never invoke the SDK.
    service.stop(); service._grants.clear()
    if service._owns_scheduler:
        from vstacklens.application.execution_guard import release_owner
        release_owner(settings.db_path, service._owner); service._owns_scheduler = False
    with closing(connect(settings.db_path)) as conn, conn:
        conn.execute("UPDATE standard_batches SET owner_pid=1234,owner_identity='1234:1:100'")
        conn.execute("UPDATE inspection_execution_leases SET owner_pid=1234,owner_identity='1234:1:100'")
        conn.execute("UPDATE schedule_occurrences SET owner_pid=1234,owner_identity='1234:1:100'")
        before = "\n".join(conn.iterdump())
    original = process_identity._read_process
    monkeypatch.setattr(process_identity, "_read_process", lambda pid: ProcessCheck(OwnerState.UNKNOWN if unknown else OwnerState.ENDED, "offline ownership evidence") if pid == 1234 else original(pid))
    other = ScheduledInspectionService(settings.db_path, clock=clock.now, monotonic=clock.monotonic)
    if unknown:
        with closing(connect(settings.db_path)) as conn: assert "\n".join(conn.iterdump()) == before
        assert other.store.occurrences(plan["schedule_id"])[0]["state"] == "submitted"
        assert "无法确认" in other.batch.store.snapshot(trigger.batch_id)["recovery_notice"]
    else:
        assert other.store.occurrences(plan["schedule_id"])[0]["state"] == "interrupted"
    assert other.tick() is None and not controls["calls"]
    other.finish_shutdown()
    # Lost original service retains no credentials once we explicitly shut it down.
    service.batch._credentials.clear()
