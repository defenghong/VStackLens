from __future__ import annotations

import sqlite3
from pathlib import Path
from uuid import uuid4


def _validate(conn: sqlite3.Connection) -> None:
    if conn.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
        raise RuntimeError("Deep history backup integrity check failed")
    if conn.execute("PRAGMA foreign_key_check").fetchall():
        raise RuntimeError("Deep history backup foreign key check failed")


def restore_history_backup(backup: Path, destination: Path) -> Path:
    """Restore to a new file only; never overwrite a live database."""
    destination = Path(destination)
    if destination.exists():
        raise FileExistsError(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(f"{Path(backup).resolve().as_uri()}?mode=ro", uri=True) as source:
        _validate(source)
        with sqlite3.connect(destination) as target:
            source.backup(target)
            _validate(target)
    return destination


def backup_before_migration(conn: sqlite3.Connection, path: Path, *, purpose: str = "stage1") -> Path:
    backup = path.with_name(f"{path.name}.before-{purpose}-{uuid4().hex}.bak")
    with sqlite3.connect(backup) as target:
        conn.backup(target)
        _validate(target)
    # Exercise the same restore API before allowing schema writes.
    restored = backup.with_name(backup.name + ".restore-verified")
    restore_history_backup(backup, restored)
    return backup
