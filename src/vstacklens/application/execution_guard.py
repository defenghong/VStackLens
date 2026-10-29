from contextlib import closing, contextmanager
from pathlib import Path
from uuid import uuid4
import threading
from vstacklens.core.process_identity import PROCESS_PID, PROCESS_IDENTITY, OwnerState, owner_alive
from vstacklens.db.connection import connect
from vstacklens.db.batch_store import ensure_batch_schema

class TargetIdentityError(ValueError):
    pass

def lease_keys(environment_id, host, port):
    keys = [f"endpoint:{host.casefold()}:{port}"]
    if environment_id:
        keys.append(f"environment:{environment_id}")
    return keys

def acquire(conn, keys, owner):
    if not PROCESS_IDENTITY:
        raise RuntimeError("无法可靠识别当前进程，不允许并发巡检。")
    created = []
    for key in keys:
        row = conn.execute("SELECT * FROM inspection_execution_leases WHERE lease_key=?", (key,)).fetchone()
        if row:
            check = owner_alive(row["owner_pid"], row["owner_identity"])
            if check.state is OwnerState.UNKNOWN:
                raise ValueError(f"无法确认原任务是否结束：{check.reason}；已保留执行占用，未启动冲突巡检。")
            if check.state is OwnerState.ENDED:
                conn.execute("DELETE FROM inspection_execution_leases WHERE lease_key=?", (key,))
                row = None
        if row and row["owner"] != owner:
            raise ValueError("该环境或地址已在其他巡检中排队/执行，未重复提交。")
        if not row:
            conn.execute("INSERT INTO inspection_execution_leases VALUES (?,?,?,?)", (key, owner, PROCESS_PID, PROCESS_IDENTITY))
            created.append(key)
    return created

def release_owner(db, owner):
    with closing(connect(Path(db))) as conn, conn:
        conn.execute("DELETE FROM inspection_execution_leases WHERE owner=?", (owner,))

@contextmanager
def execution_lease(db, environment_id, host, port, owner=None):
    ensure_batch_schema(Path(db))
    owner = owner or uuid4().hex
    with closing(connect(Path(db))) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        created = acquire(conn, lease_keys(environment_id, host, port), owner)
    try:
        yield
    finally:
        with closing(connect(Path(db))) as conn, conn:
            for key in created:
                conn.execute("DELETE FROM inspection_execution_leases WHERE lease_key=? AND owner=?", (key, owner))
