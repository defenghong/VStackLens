"""Offline process ownership supplement; never query a VMware environment."""
from contextlib import closing
import ctypes
from ctypes import wintypes
import os
import subprocess
import sys

import pytest

from vstacklens.application import execution_guard as guard
from vstacklens.db import batch_store
from vstacklens.db.connection import connect
from vstacklens.core import process_identity as process
from vstacklens.core.process_identity import OwnerState, ProcessCheck


@pytest.fixture
def ownership_db(tmp_path):
    path = tmp_path / "isolated.db"
    batch_store.ensure_batch_schema(path)
    with closing(connect(path)) as conn, conn:
        for owner, pid, identity in (("old-job", 1234, "1234:1:100"),
                                     ("other-job", 5678, "5678:2:200")):
            conn.execute("INSERT INTO standard_batches VALUES (?,?,?,?,?,?,?,?)",
                         (owner, owner, "running", "{}", pid, identity, "offline", "offline"))
            for ordinal, state in enumerate(("completed", "running", "waiting")):
                conn.execute("INSERT INTO standard_batch_items(batch_id,ordinal,environment_id,target_json,state,run_id) VALUES (?,?,?,?,?,?)",
                             (owner, ordinal, owner, "{}", state, "saved-result" if ordinal == 0 else None))
            conn.execute("INSERT INTO inspection_execution_leases VALUES (?,?,?,?)",
                         ("endpoint:" + owner + ":443", owner, pid, identity))
    return path


def dump(path):
    with closing(connect(path)) as conn:
        return "\n".join(conn.iterdump())


def test_unknown_owner_blocks_lease_without_any_database_change(ownership_db, monkeypatch):
    monkeypatch.setattr(guard, "owner_alive", lambda *args: ProcessCheck(OwnerState.UNKNOWN, "权限不足"))
    before = dump(ownership_db)
    with pytest.raises(ValueError, match="无法确认原任务是否结束"):
        with guard.execution_lease(ownership_db, None, "old-job", 443):
            pytest.fail("A conflicting task was allowed to start")
    assert dump(ownership_db) == before


def test_unknown_owner_recovery_does_not_write_or_release(ownership_db, monkeypatch):
    monkeypatch.setattr(batch_store, "owner_alive", lambda *args: ProcessCheck(OwnerState.UNKNOWN, "查询失败"))
    before = dump(ownership_db)
    store = batch_store.BatchStore(ownership_db)
    store.recover_interrupted()
    assert dump(ownership_db) == before
    assert "无法确认原任务是否结束" in store.snapshot("old-job")["recovery_notice"]


class NativeCall:
    def __init__(self, action):
        self.action = action

    def __call__(self, *args):
        return self.action(*args)


class FakeKernel:
    """Windows API seam: failures are not represented as invented dead PIDs."""
    def __init__(self, mode):
        self.mode = mode
        self.closed = []
        self.enum_calls = 0
        self.OpenProcess = NativeCall(self.open)
        self.GetExitCodeProcess = NativeCall(self.exit_code)
        self.GetProcessTimes = NativeCall(self.times)
        self.CloseHandle = NativeCall(lambda handle: self.closed.append(handle) or 1)
        self.K32EnumProcesses = NativeCall(self.enumerate)

    def open(self, access, inherit, pid):
        assert access == 0x1000 and not inherit
        errors = {"denied": 5, "open_failed": 31, "absent": 87, "invalid_but_present": 87,
                  "enum_failed": 87, "enum_full": 87, "enum_empty": 87, "enum_retry": 87}
        if self.mode in errors:
            ctypes.set_last_error(errors[self.mode])
            return 0
        if self.mode == "query_exception":
            raise OSError("offline query failed")
        return 99

    def exit_code(self, handle, output):
        if self.mode == "exit_failed":
            ctypes.set_last_error(5)
            return 0
        ctypes.cast(output, ctypes.POINTER(wintypes.DWORD))[0] = 0 if self.mode == "ended" else 259
        return 1

    def times(self, handle, creation, *rest):
        if self.mode == "times_failed":
            ctypes.set_last_error(5)
            return 0
        filetime = ctypes.cast(creation, ctypes.POINTER(wintypes.FILETIME)).contents
        filetime.dwHighDateTime, filetime.dwLowDateTime = (0, 0) if self.mode == "empty" else (1, 100)
        return 1

    def enumerate(self, pids, capacity, needed):
        self.enum_calls += 1
        if self.mode == "enum_failed":
            return 0
        output = ctypes.cast(needed, ctypes.POINTER(wintypes.DWORD))
        if self.mode == "enum_empty":
            output[0] = 0
        elif self.mode == "enum_full" or (self.mode == "enum_retry" and self.enum_calls == 1):
            output[0] = capacity
        else:
            if self.mode == "invalid_but_present":
                pids[0], pids[1] = 1234, 5678
                output[0] = 2 * ctypes.sizeof(wintypes.DWORD)
            else:
                pids[0] = 5678
                output[0] = ctypes.sizeof(wintypes.DWORD)
        return 1


UNKNOWN_MODES = ("denied", "open_failed", "query_exception", "exit_failed", "times_failed",
                 "empty", "invalid_but_present", "enum_failed", "enum_full", "enum_empty")


def simulate_windows(monkeypatch, mode):
    kernel = FakeKernel(mode)
    # Run the production reader and its exception policy, only replacing the DLL.
    native_reader = process._windows_process
    monkeypatch.setattr(process, "_windows_process", lambda pid: native_reader(pid, kernel))
    return kernel


@pytest.mark.parametrize("mode", UNKNOWN_MODES)
def test_windows_query_uncertainty_never_means_exit(monkeypatch, mode):
    kernel = simulate_windows(monkeypatch, mode)
    result = process.owner_alive(1234, "1234:1:100")
    assert result.state is OwnerState.UNKNOWN and result.reason
    assert process.process_identity(1234) == ""
    if mode in {"exit_failed", "times_failed", "empty"}:
        assert kernel.closed == [99, 99]
    if mode == "denied":
        assert kernel.enum_calls == 0  # Access denial is not absence evidence.
    with pytest.raises(TypeError):
        bool(result)


@pytest.mark.parametrize("mode", UNKNOWN_MODES)
def test_unknown_windows_query_preserves_history_and_blocks_every_retry(ownership_db, monkeypatch, mode):
    simulate_windows(monkeypatch, mode)
    before = dump(ownership_db)
    for _ in range(2):
        store = batch_store.BatchStore(ownership_db)
        checks = store.recover_interrupted()
        assert checks["old-job"].state is OwnerState.UNKNOWN
        assert store.snapshot("old-job")["state"] == "running"
        assert "无法确认原任务是否结束" in store.snapshot("old-job")["recovery_notice"]
        for requesting_owner in ("new-job", "old-job"):
            with pytest.raises(ValueError, match="无法确认原任务是否结束"):
                with guard.execution_lease(ownership_db, None, "old-job", 443, requesting_owner):
                    pytest.fail("Unknown ownership allowed a task to start")
        assert dump(ownership_db) == before


@pytest.mark.parametrize("mode,identity,expected", [
    ("running", "1234:1:100", OwnerState.RUNNING),
    ("running", "1234:01:00100", OwnerState.RUNNING),
    ("running", "1234:1:99", OwnerState.ENDED),
    ("ended", "1234:1:100", OwnerState.ENDED),
    ("absent", "1234:1:100", OwnerState.ENDED),
    ("enum_retry", "1234:1:100", OwnerState.ENDED),
    ("running", "", OwnerState.UNKNOWN),
    ("running", "bad-identity", OwnerState.UNKNOWN),
    ("running", "5678:1:100", OwnerState.UNKNOWN),
    ("running", "1234:0:0", OwnerState.UNKNOWN),
    ("running", "1234:100", OwnerState.UNKNOWN),
    ("running", None, OwnerState.UNKNOWN),
    ("running", "1234:4294967296:100", OwnerState.UNKNOWN),
    pytest.param("running", "1234:" + "1" * 5000 + ":100", OwnerState.UNKNOWN, id="oversized-identity"),
])
def test_owner_identity_requires_actual_creation_evidence(monkeypatch, mode, identity, expected):
    kernel = simulate_windows(monkeypatch, mode)
    result = process.owner_alive(1234, identity)
    assert result.state is expected
    if mode == "enum_retry":
        assert kernel.enum_calls == 2
    if identity == "1234:1:99":
        assert "复用" in result.reason


@pytest.mark.parametrize("pid", (0, -1, 0x100000000, None, "1234", True))
def test_invalid_pid_is_not_proof_of_exit(pid):
    assert process.owner_alive(pid, "unknown").state is OwnerState.UNKNOWN


@pytest.mark.parametrize("identity", ("", "missing"))
def test_stored_identity_insufficient_keeps_all_records(ownership_db, monkeypatch, identity):
    with closing(connect(ownership_db)) as conn, conn:
        conn.execute("UPDATE standard_batches SET owner_identity=? WHERE batch_id='old-job'", (identity,))
        conn.execute("UPDATE inspection_execution_leases SET owner_identity=? WHERE owner='old-job'", (identity,))
    monkeypatch.setattr(process, "_read_process", lambda pid: ProcessCheck(OwnerState.RUNNING, "running", f"{pid}:{1 if pid == 1234 else 2}:{100 if pid == 1234 else 200}"))
    before = dump(ownership_db)
    store = batch_store.BatchStore(ownership_db)
    assert store.recover_interrupted()["old-job"].state is OwnerState.UNKNOWN
    with pytest.raises(ValueError, match="无法确认原任务是否结束"):
        with guard.execution_lease(ownership_db, None, "old-job", 443):
            pytest.fail("Missing saved creation identity was treated as a reused PID")
    assert dump(ownership_db) == before


def test_empty_observed_identity_cannot_confirm_pid_reuse(monkeypatch):
    monkeypatch.setattr(process, "_read_process", lambda pid: ProcessCheck(OwnerState.RUNNING, "empty identity", ""))
    assert process.owner_alive(1234, "1234:1:100").state is OwnerState.UNKNOWN


def test_normal_running_owner_and_reentrant_lease_are_preserved(ownership_db, monkeypatch):
    monkeypatch.setattr(process, "_read_process", lambda pid: ProcessCheck(OwnerState.RUNNING, "running", f"{pid}:{1 if pid == 1234 else 2}:{100 if pid == 1234 else 200}"))
    before = dump(ownership_db)
    store = batch_store.BatchStore(ownership_db)
    store.recover_interrupted()
    with guard.execution_lease(ownership_db, None, "old-job", 443, "old-job"):
        assert dump(ownership_db) == before
    with pytest.raises(ValueError, match="其他巡检"):
        with guard.execution_lease(ownership_db, None, "old-job", 443):
            pytest.fail("Running owner was ignored")
    assert dump(ownership_db) == before
    assert "recovery_notice" not in store.snapshot("old-job")


@pytest.mark.parametrize("proof", ("exit", "reuse"))
def test_confirmed_original_exit_recovers_only_its_own_records(ownership_db, monkeypatch, proof):
    def observe(pid):
        if pid == 1234:
            if proof == "exit":
                return ProcessCheck(OwnerState.ENDED, "confirmed exit")
            return ProcessCheck(OwnerState.RUNNING, "new creation", "1234:1:101")
        return ProcessCheck(OwnerState.RUNNING, "running", "5678:2:200")
    monkeypatch.setattr(process, "_read_process", observe)
    # Even a lease with the same logical owner but a different live process is protected.
    with closing(connect(ownership_db)) as conn, conn:
        conn.execute("INSERT INTO inspection_execution_leases VALUES ('protected','old-job',5678,'5678:2:200')")
    store = batch_store.BatchStore(ownership_db)
    store.recover_interrupted()
    recovered = store.snapshot("old-job")
    assert recovered["state"] == "interrupted"
    assert [i["state"] for i in recovered["items"]] == ["completed", "interrupted", "interrupted"]
    assert recovered["items"][0]["run_id"] == "saved-result"
    assert store.snapshot("other-job")["state"] == "running"
    with closing(connect(ownership_db)) as conn:
        assert {r["lease_key"] for r in conn.execute("SELECT * FROM inspection_execution_leases")} == {"protected", "endpoint:other-job:443"}
    with guard.execution_lease(ownership_db, None, "old-job", 443):
        pass


@pytest.mark.parametrize("proof", ("exit", "reuse"))
def test_confirmed_stale_lease_can_be_reclaimed_without_recovery(ownership_db, monkeypatch, proof):
    monkeypatch.setattr(process, "_read_process", lambda pid:
                        ProcessCheck(OwnerState.ENDED, "confirmed exit") if proof == "exit"
                        else ProcessCheck(OwnerState.RUNNING, "new creation", "1234:1:101"))
    with guard.execution_lease(ownership_db, None, "old-job", 443, "replacement"):
        with closing(connect(ownership_db)) as conn:
            assert conn.execute("SELECT owner FROM inspection_execution_leases WHERE lease_key='endpoint:old-job:443'").fetchone()[0] == "replacement"
    with closing(connect(ownership_db)) as conn:
        assert conn.execute("SELECT owner FROM inspection_execution_leases").fetchone()[0] == "other-job"


def test_multi_key_conflict_rolls_back_a_prior_stale_cleanup(ownership_db, monkeypatch):
    monkeypatch.setattr(guard, "lease_keys", lambda *args: ["endpoint:old-job:443", "endpoint:other-job:443"])
    monkeypatch.setattr(process, "_read_process", lambda pid:
                        ProcessCheck(OwnerState.ENDED, "confirmed exit") if pid == 1234
                        else ProcessCheck(OwnerState.UNKNOWN, "permission denied"))
    before = dump(ownership_db)
    with pytest.raises(ValueError, match="无法确认原任务是否结束"):
        with guard.execution_lease(ownership_db, None, "old-job", 443):
            pytest.fail("Conflicting second key was acquired")
    assert dump(ownership_db) == before


def test_recovery_query_exception_is_atomic(ownership_db, monkeypatch):
    def fail_second(pid, identity):
        if pid == 1234:
            return ProcessCheck(OwnerState.ENDED, "confirmed exit")
        raise RuntimeError("offline unexpected reader failure")
    monkeypatch.setattr(batch_store, "owner_alive", fail_second)
    before = dump(ownership_db)
    with pytest.raises(RuntimeError):
        batch_store.BatchStore(ownership_db).recover_interrupted()
    assert dump(ownership_db) == before


def test_unknown_recovery_does_not_take_writer_lock_from_running_inspection(ownership_db, monkeypatch):
    store = batch_store.BatchStore(ownership_db)
    before = dump(ownership_db)
    monkeypatch.setattr(batch_store, "owner_alive", lambda *args: ProcessCheck(OwnerState.UNKNOWN, "权限不足"))
    original_connect = batch_store.connect
    def short_timeout(path):
        conn = original_connect(path)
        conn.execute("PRAGMA busy_timeout=10")
        return conn
    monkeypatch.setattr(batch_store, "connect", short_timeout)
    with closing(connect(ownership_db)) as writer:
        writer.execute("BEGIN IMMEDIATE")
        writer.execute("UPDATE standard_batch_items SET reason='uncommitted-running-write' WHERE batch_id='old-job'")
        try:
            assert store.recover_interrupted()["old-job"].state is OwnerState.UNKNOWN
            assert dump(ownership_db) == before
        finally:
            writer.rollback()
    assert dump(ownership_db) == before


def test_native_current_process_and_cooperative_child_exit():
    current = process.owner_alive(os.getpid(), process.PROCESS_IDENTITY)
    assert current.state is OwnerState.RUNNING
    # Local test process waits for EOF, then exits normally; no terminate/kill.
    child = subprocess.Popen([sys.executable, "-c", "import sys; sys.stdin.read()"], stdin=subprocess.PIPE)
    try:
        identity = process.process_identity(child.pid)
        assert identity
        assert process.owner_alive(child.pid, identity).state is OwnerState.RUNNING
    finally:
        child.stdin.close()
        assert child.wait(timeout=10) == 0
    assert process.owner_alive(child.pid, identity).state is OwnerState.ENDED
