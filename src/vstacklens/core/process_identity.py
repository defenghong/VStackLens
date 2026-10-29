"""Read-only, three-state ownership checks. Missing evidence is never death."""
from dataclasses import dataclass
from enum import Enum
import os
import sys
from pathlib import Path


class OwnerState(Enum):
    RUNNING = "running"
    ENDED = "ended"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ProcessCheck:
    state: OwnerState
    reason: str
    identity: str = ""

    def __bool__(self):
        # Force callers to decide explicitly; UNKNOWN must not clear a lease.
        raise TypeError("Use ProcessCheck.state, not a boolean ownership check")


def _windows_pid_absent(kernel, pid):
    """True only after a successful, complete process enumeration."""
    import ctypes
    from ctypes import wintypes

    enum = kernel.K32EnumProcesses
    enum.argtypes = [ctypes.POINTER(wintypes.DWORD), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    enum.restype = wintypes.BOOL
    for size in (1024, 2048, 4096, 8192, 16384, 32768, 65536):
        pids = (wintypes.DWORD * size)()
        needed = wintypes.DWORD()
        capacity = ctypes.sizeof(pids)
        if not enum(pids, capacity, ctypes.byref(needed)):
            return None
        if not needed.value or needed.value > capacity or needed.value % ctypes.sizeof(wintypes.DWORD):
            return None
        if needed.value == capacity:
            continue  # A full buffer does not prove that an absent PID is gone.
        return pid not in pids[:needed.value // ctypes.sizeof(wintypes.DWORD)]
    return None


def _windows_process(pid, kernel=None):
    import ctypes
    from ctypes import wintypes

    if not isinstance(pid, int) or isinstance(pid, bool) or not 0 < pid <= 0xFFFFFFFF:
        return ProcessCheck(OwnerState.UNKNOWN, "原任务 PID 缺失或无效")
    if kernel is None:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
    kernel.GetProcessTimes.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.GetExitCodeProcess.restype = wintypes.BOOL
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        error = ctypes.get_last_error()
        # Do not treat OpenProcess failure alone as proof of process exit.
        if error == 87 and _windows_pid_absent(kernel, pid) is True:
            return ProcessCheck(OwnerState.ENDED, "完整进程列表已确认原 PID 不存在")
        reason = "权限不足" if error == 5 else "打开进程失败"
        return ProcessCheck(OwnerState.UNKNOWN, f"{reason}（Windows 错误 {error}）")
    try:
        code = wintypes.DWORD()
        if not kernel.GetExitCodeProcess(handle, ctypes.byref(code)):
            return ProcessCheck(OwnerState.UNKNOWN, f"进程状态查询失败（Windows 错误 {ctypes.get_last_error()}）")
        if code.value != 259:
            return ProcessCheck(OwnerState.ENDED, "进程句柄已确认原进程结束")
        times = [wintypes.FILETIME() for _ in range(4)]
        if not kernel.GetProcessTimes(handle, *(ctypes.byref(t) for t in times)):
            return ProcessCheck(OwnerState.UNKNOWN, f"进程创建时间查询失败（Windows 错误 {ctypes.get_last_error()}）")
        if not (times[0].dwHighDateTime or times[0].dwLowDateTime):
            return ProcessCheck(OwnerState.UNKNOWN, "进程创建身份为空")
        identity = f"{pid}:{times[0].dwHighDateTime}:{times[0].dwLowDateTime}"
        return ProcessCheck(OwnerState.RUNNING, "进程仍在运行", identity)
    finally:
        kernel.CloseHandle(handle)


def _read_process(pid: int) -> ProcessCheck:
    try:
        if sys.platform == "win32":
            return _windows_process(pid)
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
            return ProcessCheck(OwnerState.UNKNOWN, "原任务 PID 缺失或无效")
        if not Path("/proc").is_dir():
            return ProcessCheck(OwnerState.UNKNOWN, "当前系统没有可靠的进程身份查询接口")
        try:
            raw = Path(f"/proc/{pid}/stat").read_text()
        except FileNotFoundError:
            return ProcessCheck(OwnerState.ENDED, "系统进程记录已确认原 PID 不存在")
        stat = raw.rsplit(")", 1)[1].split()
        if stat[0] in {"Z", "X"}:
            return ProcessCheck(OwnerState.ENDED, "系统进程记录已确认原进程结束")
        identity = f"{pid}:{stat[19]}"
        return ProcessCheck(OwnerState.RUNNING, "进程仍在运行", identity)
    except Exception as exc:
        # A failed read cannot authorize recovery or a new conflicting task.
        return ProcessCheck(OwnerState.UNKNOWN, f"进程身份查询失败（{type(exc).__name__}）")


def process_identity(pid: int) -> str:
    observation = _read_process(pid)
    return observation.identity if observation.state is OwnerState.RUNNING else ""


def _valid_identity(pid, identity):
    if not isinstance(identity, str):
        return False
    parts = identity.split(":")
    if (len(parts) not in {2, 3} or parts[0] != str(pid)
            or not all(len(p) <= 20 and p.isascii() and p.isdigit() for p in parts)):
        return False
    creation = [int(p) for p in parts[1:]]
    limit = 0xFFFFFFFF if len(parts) == 3 else 0xFFFFFFFFFFFFFFFF
    return all(p <= limit for p in creation) and any(creation)


PROCESS_PID = os.getpid()
PROCESS_IDENTITY = process_identity(PROCESS_PID)


def owner_alive(pid: int, identity: str) -> ProcessCheck:
    """Return RUNNING / ENDED / UNKNOWN, never a lossy boolean."""
    observation = _read_process(pid)
    if observation.state is not OwnerState.RUNNING:
        return observation
    if (not _valid_identity(pid, identity) or not _valid_identity(pid, observation.identity)
            or len(identity.split(":")) != len(observation.identity.split(":"))):
        return ProcessCheck(OwnerState.UNKNOWN, "原任务或当前进程的创建身份信息不足")
    if tuple(map(int, observation.identity.split(":"))) == tuple(map(int, identity.split(":"))):
        return ProcessCheck(OwnerState.RUNNING, "原进程仍在运行", identity)
    return ProcessCheck(OwnerState.ENDED, "PID 已被不同创建身份的进程复用", observation.identity)
