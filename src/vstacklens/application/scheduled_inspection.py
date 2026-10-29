"""In-process standard scheduling. No daemon, OS scheduler or saved passwords."""
from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, time, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import threading
import time as system_time
from uuid import uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from vstacklens.application.batch_inspection import BatchInspectionService, BatchSettings, SessionCredential, target_snapshot
from vstacklens.application.environment_archive import list_archives
from vstacklens.application.execution_guard import acquire, lease_keys, release_owner
from vstacklens.application.connection_probe import redact_sensitive
from vstacklens.core.process_identity import OwnerState, owner_alive
from vstacklens.db.connection import connect
from vstacklens.db.schedule_store import ScheduleStore

UTC = timezone.utc


def utc(value):
    if value.tzinfo is None:
        raise ValueError("计划时钟必须带时区。")
    return value.astimezone(UTC)


def next_occurrence(plan, after):
    """First future local slot. DST gap skips; a repeated hour uses fold=0 once."""
    after = utc(after)
    zone = ZoneInfo(plan["timezone"])
    hour, minute = map(int, plan["local_time"].split(":"))
    start = after.astimezone(zone).date()
    for days in range(15):
        day = start + timedelta(days=days)
        if plan["frequency"] == "weekly" and day.weekday() not in plan["weekdays"]:
            continue
        local = datetime.combine(day, time(hour, minute), zone)
        candidate = local.astimezone(UTC)
        if candidate.astimezone(zone).replace(tzinfo=None) != local.replace(tzinfo=None):
            continue
        if candidate > after:
            return candidate.isoformat()
    raise ValueError("计划日期无效，无法计算下一次执行。")


@dataclass(frozen=True)
class PlanTrigger:
    schedule_id: str
    slot: str
    batch_id: str


@dataclass
class SessionGrant:
    revision: int
    credentials: dict[str, SessionCredential] = field(repr=False)


class ScheduledInspectionService:
    def __init__(self, db_path, *, batch_manager=None, clock=None, monotonic=None):
        self.store = ScheduleStore(db_path)
        self.batch = batch_manager or BatchInspectionService(Path(db_path))
        self.clock = clock or (lambda: datetime.now(UTC))
        self.monotonic = monotonic or system_time.monotonic
        self._last_wall = utc(self.clock())
        self._last_mono = self.monotonic()
        self._grants = {}
        self._lock = threading.RLock()
        self._tick_lock = threading.Lock()
        self._stop = threading.Event()
        self.paused = False
        self._active = None
        self._running_trigger = None
        self._owner = "scheduler-" + uuid4().hex
        self._owns_scheduler = False
        self._startup = True
        self.runtime_reason = ""
        self._missed = {}
        self._recover_occurrences()

    def _recover_occurrences(self):
        for occurrence in self.store.occurrences():
            if occurrence["state"] not in {"claimed", "submitted", "running"}:
                continue
            if occurrence["batch_id"]:
                result = self.batch.store.snapshot(occurrence["batch_id"])
                if result["state"] in {"completed", "cancelled", "interrupted"}:
                    self._record_result(PlanTrigger(occurrence["schedule_id"], occurrence["slot"], occurrence["batch_id"]), result)
                    continue
            check = owner_alive(occurrence["owner_pid"], occurrence["owner_identity"])
            if check.state is OwnerState.ENDED:
                self.store.outcome(occurrence["schedule_id"], occurrence["slot"], state="interrupted", reason="原进程已结束；中断计划未自动续跑。")

    def save_plan(self, *, name, environment_ids, settings: BatchSettings, frequency="daily", weekdays=(), local_time="09:00", timezone_name="Asia/Shanghai", enabled=True, schedule_id=None, expected_revision=None):
        if self._stop.is_set():
            raise ValueError("软件正在退出，不再修改计划。")
        if not isinstance(settings, BatchSettings):
            raise ValueError("计划仅接受标准批量巡检公开配置，不接受密码或其他配置对象。")
        name = name.strip()
        if not name or len(name) > 200 or frequency not in {"daily", "weekly"}:
            raise ValueError("请填写计划名称，并选择每日或每周。")
        try:
            parsed = time.fromisoformat(local_time)
            if parsed.second or parsed.microsecond or parsed.tzinfo:
                raise ValueError
            ZoneInfo(timezone_name)
        except (ValueError, ZoneInfoNotFoundError):
            raise ValueError("执行时间或时区无效，请填写 HH:MM 与有效时区。") from None
        weekdays = sorted(set(weekdays))
        if any(type(d) is not int or not 0 <= d <= 6 for d in weekdays) or (frequency == "weekly" and not weekdays):
            raise ValueError("每周计划至少选择一天。")
        if Path(settings.db_path).resolve() != self.store.path.resolve():
            raise ValueError("计划与环境档案数据库不一致。")
        ids = list(dict.fromkeys(environment_ids))
        profiles = {p.environment_id: p for p in list_archives(self.store.path)}
        if not ids or any(i not in profiles for i in ids):
            raise ValueError("请从现有环境档案选择目标。")
        targets = [target_snapshot(profiles[i]) for i in ids]
        settings_public = {k: str(getattr(settings, k)) for k in ("db_path", "report_output_dir", "rulepack_path", "report_title")}
        # Never accept a dict of arbitrary execution/config keys or credentials.
        plan = dict(schedule_id=schedule_id or uuid4().hex, name=name, frequency=frequency,
                    weekdays=weekdays, local_time=parsed.strftime("%H:%M"), timezone=timezone_name,
                    enabled=bool(enabled), targets=targets, settings=settings_public)
        plan["next_fire_at"] = next_occurrence(plan, self.clock())
        saved = self.store.save(plan, expected_revision)
        self.revoke(saved["schedule_id"])
        return saved

    def set_enabled(self, schedule_id, enabled):
        plan = self.store.get(schedule_id)
        plan["enabled"] = bool(enabled)
        plan["next_fire_at"] = next_occurrence(plan, self.clock())
        saved = self.store.save(plan, plan["revision"])
        self.revoke(schedule_id)
        return saved

    def _target_reason(self, plan):
        profiles = {p.environment_id: p for p in list_archives(self.store.path)}
        for frozen in plan["targets"]:
            current = profiles.get(frozen["environment_id"])
            if current is None or target_snapshot(current) != frozen:
                return "环境档案资料已变化或移除，请编辑计划并重新确认目标。"
            if not current.enabled:
                return "目标环境档案已停用，未执行。"
            ambiguity = self.batch._ambiguity_reason(current, profiles.values())
            if ambiguity:
                return ambiguity
        return ""

    def authorize(self, schedule_id, credentials, *, consent=False):
        if not consent or self._stop.is_set():
            raise ValueError("请主动授权仅在本次软件运行期间用于此计划。")
        plan = self.store.get(schedule_id)
        reason = self._target_reason(plan)
        if reason:
            raise ValueError(reason)
        private = {}
        public = json.dumps(plan, ensure_ascii=False).casefold()
        for target in plan["targets"]:
            credential = credentials.get(target["environment_id"])
            if not isinstance(credential, SessionCredential) or not credential.username.strip() or not credential.password:
                raise ValueError("请分别填写每个目标环境的会话凭据，不会借用其他密码。")
            if target["username"] and target["username"] != credential.username.strip():
                raise ValueError("会话用户名与环境档案不一致，请重新确认。")
            if credential.password.casefold() in public:
                raise ValueError("凭据与公开计划资料冲突，未授权。")
            private[target["environment_id"]] = SessionCredential(credential.username.strip(), credential.password)
        with self._lock:
            self._grants[schedule_id] = SessionGrant(plan["revision"], private)

    def revoke(self, schedule_id):
        with self._lock:
            self._grants.pop(schedule_id, None)

    def readiness(self, plan):
        if self._stop.is_set():
            return "退出中，计划已停止"
        if not plan["enabled"]:
            return "已停用"
        if self.paused:
            return "计划已暂停；暂停期间不补跑"
        if self.runtime_reason:
            return self.runtime_reason
        pending = self._missed.get((plan["schedule_id"], plan["next_fire_at"]))
        if pending:
            return pending
        reason = self._target_reason(plan)
        if reason:
            return reason
        with self._lock:
            grant = self._grants.get(plan["schedule_id"])
            return "等待执行（本次运行已授权）" if grant and grant.revision == plan["revision"] else "等待凭据（本次运行尚未授权）"

    def _acquire_scheduler(self):
        if self._owns_scheduler:
            return True
        try:
            with closing(connect(self.store.path)) as conn, conn:
                conn.execute("PRAGMA busy_timeout=0")
                conn.execute("BEGIN IMMEDIATE")
                acquire(conn, ["scheduler:standard"], self._owner)
            self._owns_scheduler = True
            self.runtime_reason = ""
            return True
        except (ValueError, RuntimeError, sqlite3.Error) as exc:
            self.runtime_reason = "另一实例正在管理计划、占用无法确认或数据库正忙；本实例未触发。" + ("" if isinstance(exc, sqlite3.Error) else str(exc))
            return False

    def tick(self):
        if self._stop.is_set() or not self._tick_lock.acquire(blocking=False):
            return None
        try:
            now, mono = utc(self.clock()), self.monotonic()
            wall_gap, mono_gap = (now - self._last_wall).total_seconds(), mono - self._last_mono
            discontinuity = wall_gap < 0 or wall_gap > 5 or abs(wall_gap - mono_gap) > 5
            self._last_wall, self._last_mono = now, mono
            if not self._acquire_scheduler():
                return None
            startup, self._startup = self._startup, False
            for plan in self.store.plans():
                if not plan["enabled"]:
                    continue
                slot = plan["next_fire_at"]
                due = datetime.fromisoformat(slot)
                if now < due:
                    if discontinuity and wall_gap >= 0:
                        self.store.advance(plan["schedule_id"], plan["revision"], next_occurrence(plan, now))
                    continue
                reason = self._missed.get((plan["schedule_id"], slot), "")
                if not reason and startup:
                    reason = "软件未运行或重启时已错过计划；未自动补跑。"
                elif not reason and (discontinuity or (now - due).total_seconds() > 5):
                    reason = "休眠、时钟变化或错过执行时间；未自动补跑。"
                elif not reason and self.paused:
                    reason = "计划暂停期间未执行；不会补跑。"
                elif not reason and self._active is not None:
                    reason = "另一个计划任务仍在运行；本次未执行，不堆积任务。"
                reason = reason or self._target_reason(plan)
                with self._lock:
                    grant = self._grants.get(plan["schedule_id"])
                    credentials = dict(grant.credentials) if grant and grant.revision == plan["revision"] else {}
                if not reason and not credentials:
                    reason = "等待凭据：本次软件运行尚未授权，本次未执行。"
                try:
                    claimed = self.store.claim(plan["schedule_id"], slot, state="skipped" if reason else "claimed", reason=reason,
                                               revision=plan["revision"], next_fire_at=next_occurrence(plan, now))
                except sqlite3.OperationalError:
                    self._missed[(plan["schedule_id"], slot)] = "数据库正被运行任务占用；本次未执行，不堆积任务。"
                    continue
                if not claimed or reason:
                    if claimed:
                        self._missed.pop((plan["schedule_id"], slot), None)
                    continue
                self._missed.pop((plan["schedule_id"], slot), None)
                return self._submit(plan, slot, credentials)
            return None
        finally:
            self._tick_lock.release()

    def _submit(self, plan, slot, credentials):
        trigger = None
        try:
            current = self.store.get(plan["schedule_id"])
            if self._stop.is_set() or not current["enabled"] or current["revision"] != plan["revision"]:
                raise ValueError("计划已停用、修改或软件正在退出，未执行。")
            reason = self._target_reason(plan)
            if reason:
                raise ValueError(reason)
            # Read-only reservation rehearsal reuses exactly the formal lease guard.
            with closing(connect(self.store.path)) as conn:
                conn.execute("PRAGMA busy_timeout=0")
                conn.execute("BEGIN IMMEDIATE")
                try:
                    for target in plan["targets"]:
                        acquire(conn, lease_keys(target["environment_id"], target["host"], target["port"]), self._owner)
                finally:
                    conn.rollback()
            settings = BatchSettings(**{k: Path(v) if k in {"db_path", "report_output_dir", "rulepack_path"} else v for k, v in plan["settings"].items()})
            job = self.batch.submit([t["environment_id"] for t in plan["targets"]], credentials, settings,
                                    submission_id=f"schedule:{plan['schedule_id']}:{slot}")
            trigger = PlanTrigger(plan["schedule_id"], slot, job)
            self._active = trigger
            snapshot = self.batch.store.snapshot(job)
            if self._stop.is_set() or snapshot["counts"]["failed"]:
                self.batch.cancel(job)
                self.batch.run(job)  # Only cancellation cleanup; never starts a target.
                self._active = None
                reason = next((i["reason"] for i in snapshot["items"] if i["state"] == "failed"), "软件退出，计划未启动。")
                self.store.outcome(plan["schedule_id"], slot, state="skipped", reason=reason, batch_id=job)
                return None
            self.store.outcome(plan["schedule_id"], slot, state="submitted", batch_id=job)
            return trigger
        except Exception as exc:
            if trigger is not None:
                self.batch.cancel(trigger.batch_id)
                try:
                    self.batch.run(trigger.batch_id)
                finally:
                    self._active = None
            self.store.outcome(plan["schedule_id"], slot, state="skipped", reason=redact_sensitive(str(exc), *(c.password for c in credentials.values())))
            return None

    def _record_result(self, trigger, result):
        counts = result["counts"]
        if counts["interrupted"]:
            state = "interrupted"
        elif counts["cancelled"]:
            state = "cancelled"
        elif counts["failed"] == result["total"]:
            state = "failed"
        elif counts["failed"] or counts["partial_failed"]:
            state = "partial_failed"
        else:
            state = "completed"
        reason = "；".join(i["reason"] for i in result["items"] if i["reason"])
        self.store.outcome(trigger.schedule_id, trigger.slot, state=state, reason=reason, batch_id=trigger.batch_id)

    def run_trigger(self, trigger, progress=None):
        with self._lock:
            if self._active != trigger or self._running_trigger is not None:
                raise ValueError("计划任务不是本会话待执行项或已在运行，不重复执行。")
            self._running_trigger = trigger
        try:
            self.store.outcome(trigger.schedule_id, trigger.slot, state="running", batch_id=trigger.batch_id)
            if self._stop.is_set():
                self.batch.cancel(trigger.batch_id)
            result = self.batch.run(trigger.batch_id, progress)
            self._record_result(trigger, result)
            return result
        except BaseException:
            self.store.outcome(trigger.schedule_id, trigger.slot, state="interrupted", reason="计划任务异常中断，保留原任务证据；未自动重跑。", batch_id=trigger.batch_id)
            raise
        finally:
            with self._lock:
                self._active = None; self._running_trigger = None

    def stop(self):
        self._stop.set()
        if self._active:
            self.batch.cancel(self._active.batch_id)

    def finish_shutdown(self):
        self._stop.set()
        if self._running_trigger is not None or self.batch._executing:
            raise ValueError("当前计划线程尚未安全结束，不允许提前清理会话。")
        try:
            self.stop()
            if self._active:
                # Called only once all native workers have finished. Clean an unstarted callback.
                self.run_trigger(self._active)
        finally:
            with self._lock:
                self._grants.clear()
            self.batch.clear_idle_credentials()
        if self._owns_scheduler:
            release_owner(self.store.path, self._owner)
            self._owns_scheduler = False
