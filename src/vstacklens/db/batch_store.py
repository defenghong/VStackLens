"""Public batch records only. Credentials never belong to this store."""
from contextlib import closing
from pathlib import Path
import json
import sqlite3
import threading
from vstacklens.db.connection import connect, init_db
from vstacklens.deep.backup import backup_before_migration
from vstacklens.core.process_identity import OwnerState, owner_alive

_SCHEMA_LOCK = threading.RLock()
SCHEMA = """
CREATE TABLE IF NOT EXISTS standard_batches (
 batch_id TEXT PRIMARY KEY, submission_id TEXT UNIQUE NOT NULL, state TEXT NOT NULL,
 settings_json TEXT NOT NULL, owner_pid INTEGER NOT NULL, owner_identity TEXT NOT NULL,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS standard_batch_items (
 batch_id TEXT NOT NULL, ordinal INTEGER NOT NULL, environment_id TEXT NOT NULL,
 target_json TEXT NOT NULL, state TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '',
 run_id TEXT, percent INTEGER NOT NULL DEFAULT 0, collection_state TEXT NOT NULL DEFAULT 'not_started',
 analysis_state TEXT NOT NULL DEFAULT 'not_started', delivery_state TEXT NOT NULL DEFAULT 'not_started',
 identity_state TEXT NOT NULL DEFAULT 'unverified', remote_uuid TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(batch_id,ordinal), FOREIGN KEY(batch_id) REFERENCES standard_batches(batch_id));
CREATE TABLE IF NOT EXISTS inspection_execution_leases (
 lease_key TEXT PRIMARY KEY, owner TEXT NOT NULL, owner_pid INTEGER NOT NULL,
 owner_identity TEXT NOT NULL);
"""


def ensure_batch_schema(path: Path):
    path = Path(path)
    with _SCHEMA_LOCK:
        if path.exists():
            with closing(sqlite3.connect(path)) as conn:
                tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if {"standard_batches", "standard_batch_items", "inspection_execution_leases"} <= tables:
                    return
                if tables:
                    backup_before_migration(conn, path, purpose="stage3-batch")
        init_db(path)
        with closing(connect(path)) as conn:
            conn.executescript("BEGIN IMMEDIATE;" + SCHEMA + "COMMIT;")


class BatchStore:
    def __init__(self, path):
        self.path = Path(path)
        ensure_batch_schema(self.path)
        self._memory = {}
        self._memory_lock = threading.RLock()
        self.recovery_checks = {}

    def recover_interrupted(self):
        checks = {}
        with closing(connect(self.path)) as conn, conn:
            # An active inspection may hold the writer. Unknown/running owners
            # require reads only; the first actual UPDATE starts the transaction.
            for batch in conn.execute("SELECT * FROM standard_batches WHERE state IN ('waiting','running')").fetchall():
                check = owner_alive(batch["owner_pid"], batch["owner_identity"])
                checks[batch["batch_id"]] = check
                if check.state is not OwnerState.ENDED:
                    continue
                conn.execute("UPDATE standard_batch_items SET state='interrupted',reason='程序退出后中断，未自动续跑',collection_state=CASE WHEN state='running' THEN 'unknown' ELSE collection_state END,delivery_state=CASE WHEN state='running' THEN 'unknown' ELSE delivery_state END WHERE batch_id=? AND state IN ('waiting','running')", (batch["batch_id"],))
                conn.execute("UPDATE standard_batches SET state='interrupted' WHERE batch_id=?", (batch["batch_id"],))
                conn.execute("DELETE FROM inspection_execution_leases WHERE owner=? AND owner_pid=? AND owner_identity=?", (batch["batch_id"], batch["owner_pid"], batch["owner_identity"]))
        self.recovery_checks = checks
        return checks

    def snapshot(self, batch_id):
        with closing(connect(self.path)) as conn:
            batch = conn.execute("SELECT * FROM standard_batches WHERE batch_id=?", (batch_id,)).fetchone()
            if not batch:
                raise ValueError("批任务不存在。")
            items = [dict(r) for r in conn.execute("SELECT * FROM standard_batch_items WHERE batch_id=? ORDER BY ordinal", (batch_id,))]
        for item in items:
            item["target"] = json.loads(item.pop("target_json"))
            with self._memory_lock:
                item.update(self._memory.get((batch_id, item["ordinal"]), {}))
        counts = {s: sum(i["state"] == s for i in items) for s in ("waiting", "running", "completed", "partial_failed", "failed", "cancelled", "interrupted")}
        total = len(items)
        terminal = sum(counts[s] for s in ("completed", "partial_failed", "failed", "cancelled", "interrupted"))
        percent = int((terminal + sum(i["percent"] / 100 for i in items if i["state"] == "running")) / total * 100) if total else 100
        result = {"batch_id": batch_id, "db_path": str(self.path), "state": batch["state"], "items": items, "counts": counts, "percent": min(100, percent), "total": total}
        check = self.recovery_checks.get(batch_id)
        if check is not None and check.state is OwnerState.UNKNOWN:
            result["recovery_notice"] = f"无法确认原任务是否结束：{check.reason}；已保留任务状态及执行占用，未自动续跑。"
        return result

    def update_item(self, batch_id, ordinal, **fields):
        with self._memory_lock:
            fields = {**self._memory.pop((batch_id, ordinal), {}), **fields}
        allowed = {"state", "reason", "run_id", "percent", "collection_state", "analysis_state", "delivery_state", "identity_state", "remote_uuid"}
        if not fields or not set(fields) <= allowed:
            raise ValueError("Invalid public batch fields")
        with closing(connect(self.path)) as conn, conn:
            conn.execute("UPDATE standard_batch_items SET " + ",".join(f"{key}=?" for key in fields) + " WHERE batch_id=? AND ordinal=?", (*fields.values(), batch_id, ordinal))

    def stage_item(self, batch_id, ordinal, **fields):
        # The standard runner owns a SQLite write transaction during collection.
        with self._memory_lock:
            self._memory.setdefault((batch_id, ordinal), {}).update(fields)

    def flush(self, batch_id):
        with self._memory_lock:
            ordinals = [ordinal for batch,ordinal in self._memory if batch == batch_id]
        for ordinal in ordinals:
            self.update_item(batch_id, ordinal)

    def update_state(self, batch_id, state):
        with closing(connect(self.path)) as conn, conn:
            conn.execute("UPDATE standard_batches SET state=? WHERE batch_id=?", (state, batch_id))

    def latest(self):
        with closing(connect(self.path)) as conn:
            row = conn.execute("SELECT batch_id FROM standard_batches ORDER BY created_at DESC,rowid DESC LIMIT 1").fetchone()
        return self.snapshot(row[0]) if row else None
