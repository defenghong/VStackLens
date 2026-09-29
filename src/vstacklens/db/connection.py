from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Callable
from contextlib import closing
from pathlib import Path
from typing import TypeVar

from vstacklens.resources import database_schema_path


CONNECT_TIMEOUT_SECONDS = 30.0
BUSY_TIMEOUT_MS = 30000

_INIT_LOCK = threading.RLock()
_INITIALIZED_DBS: set[Path] = set()
T = TypeVar("T")


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=CONNECT_TIMEOUT_SECONDS)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
    return conn


def init_db(db_path: Path, *, force: bool = False) -> None:
    db = Path(db_path).resolve()
    if not force and db in _INITIALIZED_DBS:
        return
    with _INIT_LOCK:
        if not force and db in _INITIALIZED_DBS:
            return
        schema_path = database_schema_path()

        def operation() -> None:
            with closing(connect(db)) as conn, conn:
                conn.execute("PRAGMA journal_mode = WAL")
                conn.executescript(schema_path.read_text(encoding="utf-8"))
                _migrate(conn)

        with_db_retry(operation)
        _INITIALIZED_DBS.add(db)


def is_database_locked_error(exc: BaseException) -> bool:
    if not isinstance(exc, sqlite3.OperationalError):
        return False
    message = str(exc).lower()
    return "database is locked" in message or "database table is locked" in message or "database schema is locked" in message


def with_db_retry(
    operation: Callable[[], T],
    *,
    attempts: int = 10,
    initial_delay: float = 0.2,
    max_delay: float = 5.0,
) -> T:
    delay = initial_delay
    for attempt in range(max(1, attempts)):
        try:
            return operation()
        except sqlite3.OperationalError as exc:
            if not is_database_locked_error(exc) or attempt >= attempts - 1:
                raise
            time.sleep(delay)
            delay = min(max_delay, delay * 2)
    raise RuntimeError("unreachable database retry state")


def _migrate(conn: sqlite3.Connection) -> None:
    run_columns = {row["name"] for row in conn.execute("PRAGMA table_info(inspection_runs)").fetchall()}
    if "risk_category_summary_json" not in run_columns:
        conn.execute("ALTER TABLE inspection_runs ADD COLUMN risk_category_summary_json TEXT")
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(findings)").fetchall()}
    text_columns = (
        "exception_reason",
        "exception_owner",
        "exception_expires_at",
        "exception_approval_note",
        "resolved_run_id",
        "resolved_at",
    )
    for name in text_columns:
        if name not in columns:
            conn.execute(f"ALTER TABLE findings ADD COLUMN {name} TEXT")
    if "occurrence_count" not in columns:
        conn.execute("ALTER TABLE findings ADD COLUMN occurrence_count INTEGER NOT NULL DEFAULT 1")
    if "remediation_status" not in columns:
        conn.execute("ALTER TABLE findings ADD COLUMN remediation_status TEXT NOT NULL DEFAULT 'open'")
    for table, name, definition in (
        ("hcl_data_versions", "source", "TEXT NOT NULL DEFAULT 'vsan_hcl'"),
        ("hcl_devices", "source", "TEXT NOT NULL DEFAULT 'vsan_hcl'"),
        ("hcl_devices", "model_normalized", "TEXT NOT NULL DEFAULT ''"),
        ("hcl_devices", "server_smbios_models_json", "TEXT NOT NULL DEFAULT '[]'"),
        ("hcl_device_releases", "queue_depth", "TEXT"),
        ("hcl_device_releases", "vsan_support_json", "TEXT NOT NULL DEFAULT '[]'"),
    ):
        existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        if name not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_hcl_devices_source_quadruple ON hcl_devices(source, vid, did, svid, ssid)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_hcl_devices_model_normalized ON hcl_devices(category, model_normalized)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS log_analysis_runs (
          log_run_id TEXT PRIMARY KEY,
          customer_name TEXT NOT NULL,
          report_title TEXT NOT NULL,
          support_bundle_path TEXT NOT NULL,
          support_bundle_name TEXT NOT NULL,
          problem_description TEXT NOT NULL,
          run_status TEXT NOT NULL,
          current_stage TEXT,
          progress_percent INTEGER NOT NULL DEFAULT 0,
          summary_json TEXT,
          error_message TEXT,
          started_at TEXT,
          finished_at TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS upgrade_compat_runs (
          run_id TEXT PRIMARY KEY,
          customer_name TEXT NOT NULL,
          report_title TEXT NOT NULL,
          target_release TEXT NOT NULL,
          collection_mode TEXT NOT NULL CHECK(collection_mode IN ('vcenter', 'support_bundle')),
          vcenter_host TEXT,
          bundle_path TEXT,
          vsan_check_mode TEXT NOT NULL CHECK(vsan_check_mode IN ('auto', 'force', 'skip')),
          vcg_data_version_id TEXT,
          vsan_data_version_id TEXT,
          run_status TEXT NOT NULL,
          current_stage TEXT,
          progress_percent INTEGER NOT NULL DEFAULT 0,
          summary_json TEXT,
          error_message TEXT,
          started_at TEXT,
          finished_at TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS upgrade_compat_reports (
          report_id TEXT PRIMARY KEY,
          run_id TEXT NOT NULL,
          report_name TEXT NOT NULL,
          report_type TEXT NOT NULL,
          report_status TEXT NOT NULL,
          file_path TEXT,
          generated_at TEXT,
          error_message TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          FOREIGN KEY(run_id) REFERENCES upgrade_compat_runs(run_id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS log_analysis_reports (
          report_id TEXT PRIMARY KEY,
          log_run_id TEXT NOT NULL,
          report_name TEXT NOT NULL,
          report_type TEXT NOT NULL,
          report_status TEXT NOT NULL,
          file_path TEXT,
          generated_at TEXT,
          error_message TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          FOREIGN KEY(log_run_id) REFERENCES log_analysis_runs(log_run_id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS report_center_ignored_items (
          path_key TEXT PRIMARY KEY,
          created_at TEXT NOT NULL
        )
        """
    )
