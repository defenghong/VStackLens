"""Only public plan settings and occurrence evidence; no persisted credentials."""
from __future__ import annotations

from contextlib import closing
import json
from pathlib import Path
import threading

from vstacklens.core.process_identity import PROCESS_PID, PROCESS_IDENTITY
from vstacklens.core.time import utc_now_iso
from vstacklens.db.connection import connect
from vstacklens.db.batch_store import ensure_batch_schema
from vstacklens.deep.backup import backup_before_migration

_LOCK = threading.RLock()
SCHEMA = """
CREATE TABLE IF NOT EXISTS inspection_schedules (
 schedule_id TEXT PRIMARY KEY, name TEXT NOT NULL, frequency TEXT NOT NULL,
 weekdays_json TEXT NOT NULL, local_time TEXT NOT NULL, timezone TEXT NOT NULL,
 enabled INTEGER NOT NULL, revision INTEGER NOT NULL, targets_json TEXT NOT NULL,
 settings_json TEXT NOT NULL, next_fire_at TEXT NOT NULL, created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS schedule_occurrences (
 schedule_id TEXT NOT NULL, slot TEXT NOT NULL, state TEXT NOT NULL, reason TEXT NOT NULL,
 batch_id TEXT, owner_pid INTEGER NOT NULL, owner_identity TEXT NOT NULL,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 PRIMARY KEY(schedule_id,slot), FOREIGN KEY(schedule_id) REFERENCES inspection_schedules(schedule_id));
CREATE TABLE IF NOT EXISTS schedule_preferences (name TEXT PRIMARY KEY,value TEXT NOT NULL);
"""


class ScheduleStore:
    def __init__(self, path):
        self.path = Path(path)
        with _LOCK:
            if not self.exists(self.path):
                if self.path.is_file():
                    with closing(connect(self.path)) as conn:
                        if conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchone():
                            backup_before_migration(conn, self.path, purpose="stage4-schedules")
                ensure_batch_schema(self.path)
                with closing(connect(self.path)) as conn:
                    conn.executescript("BEGIN IMMEDIATE;" + SCHEMA + "COMMIT;")

    @staticmethod
    def exists(path):
        if not Path(path).is_file():
            return False
        with closing(connect(Path(path))) as conn:
            names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            return {"inspection_schedules", "schedule_occurrences", "schedule_preferences"} <= names

    @staticmethod
    def _plan(row):
        plan = dict(row)
        for field in ("weekdays", "targets", "settings"):
            plan[field] = json.loads(plan.pop(field + "_json"))
        plan["enabled"] = bool(plan["enabled"])
        return plan

    def plans(self):
        with closing(connect(self.path)) as conn:
            return [self._plan(r) for r in conn.execute("SELECT * FROM inspection_schedules ORDER BY created_at,schedule_id")]

    def get(self, schedule_id):
        with closing(connect(self.path)) as conn:
            row = conn.execute("SELECT * FROM inspection_schedules WHERE schedule_id=?", (schedule_id,)).fetchone()
        if row is None:
            raise ValueError("计划不存在，请刷新后重试。")
        return self._plan(row)

    def save(self, plan, expected_revision=None):
        with closing(connect(self.path)) as conn, conn:
            conn.execute("BEGIN IMMEDIATE")
            old = conn.execute("SELECT revision FROM inspection_schedules WHERE schedule_id=?", (plan["schedule_id"],)).fetchone()
            if old is not None and old[0] != expected_revision:
                raise ValueError("计划已被其他窗口或实例修改，请刷新后重新确认。")
            if old is None and expected_revision is not None:
                raise ValueError("计划不存在，请刷新后重试。")
            stamp = utc_now_iso()
            if old is None:
                conn.execute("INSERT INTO inspection_schedules VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", (
                    plan["schedule_id"], plan["name"], plan["frequency"], json.dumps(plan["weekdays"]),
                    plan["local_time"], plan["timezone"], int(plan["enabled"]), 1,
                    json.dumps(plan["targets"], ensure_ascii=False), json.dumps(plan["settings"], ensure_ascii=False),
                    plan["next_fire_at"], stamp, stamp))
            else:
                conn.execute("UPDATE inspection_schedules SET name=?,frequency=?,weekdays_json=?,local_time=?,timezone=?,enabled=?,revision=revision+1,targets_json=?,settings_json=?,next_fire_at=?,updated_at=? WHERE schedule_id=?", (
                    plan["name"], plan["frequency"], json.dumps(plan["weekdays"]), plan["local_time"],
                    plan["timezone"], int(plan["enabled"]), json.dumps(plan["targets"], ensure_ascii=False),
                    json.dumps(plan["settings"], ensure_ascii=False), plan["next_fire_at"], stamp, plan["schedule_id"]))
        return self.get(plan["schedule_id"])

    def advance(self, schedule_id, revision, next_fire_at):
        with closing(connect(self.path)) as conn, conn:
            conn.execute("UPDATE inspection_schedules SET next_fire_at=? WHERE schedule_id=? AND revision=?", (next_fire_at, schedule_id, revision))

    def claim(self, schedule_id, slot, *, state="claimed", reason="", revision=None, next_fire_at=None):
        with closing(connect(self.path)) as conn, conn:
            conn.execute("PRAGMA busy_timeout=0")
            conn.execute("BEGIN IMMEDIATE")
            if revision is not None:
                current = conn.execute("SELECT revision,enabled,next_fire_at FROM inspection_schedules WHERE schedule_id=?", (schedule_id,)).fetchone()
                if not current or current[0] != revision or not current[1] or current[2] != slot:
                    return False
            cursor = conn.execute("INSERT OR IGNORE INTO schedule_occurrences VALUES (?,?,?,?,?,?,?,?,?)", (
                schedule_id, slot, state, reason, None, PROCESS_PID, PROCESS_IDENTITY, utc_now_iso(), utc_now_iso()))
            if next_fire_at is not None:
                conn.execute("UPDATE inspection_schedules SET next_fire_at=? WHERE schedule_id=? AND revision=?", (next_fire_at, schedule_id, revision))
            return cursor.rowcount == 1

    def outcome(self, schedule_id, slot, *, state, reason="", batch_id=None):
        with closing(connect(self.path)) as conn, conn:
            conn.execute("UPDATE schedule_occurrences SET state=?,reason=?,batch_id=COALESCE(?,batch_id),updated_at=? WHERE schedule_id=? AND slot=?", (state, reason, batch_id, utc_now_iso(), schedule_id, slot))

    def occurrences(self, schedule_id=None):
        with closing(connect(self.path)) as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM schedule_occurrences" + (" WHERE schedule_id=?" if schedule_id else "") + " ORDER BY slot DESC", (schedule_id,) if schedule_id else ())]

    def close_choice(self):
        with closing(connect(self.path)) as conn:
            row = conn.execute("SELECT value FROM schedule_preferences WHERE name='close_choice'").fetchone()
        return row[0] if row and row[0] in {"tray", "exit"} else "ask"

    def set_close_choice(self, value):
        if value not in {"ask", "tray", "exit"}:
            raise ValueError("关闭方式无效。")
        with closing(connect(self.path)) as conn, conn:
            conn.execute("INSERT INTO schedule_preferences VALUES ('close_choice',?) ON CONFLICT(name) DO UPDATE SET value=excluded.value", (value,))
