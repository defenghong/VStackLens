"""Isolated, read-only PowerCLI bridge. Credentials travel over stdin, never argv."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable


_DLL_DIRECTORY_LOCK = threading.RLock()

@contextmanager
def isolated_child_dll_directory():
    # PyInstaller changes the Windows DLL search directory. Do not inherit it in pwsh.
    with _DLL_DIRECTORY_LOCK:
        if sys.platform == "win32" and getattr(sys, "frozen", False):
            import ctypes
            set_directory = ctypes.WinDLL("kernel32", use_last_error=True).SetDllDirectoryW
            set_directory.argtypes = [ctypes.c_wchar_p]
            set_directory.restype = ctypes.c_int
            if not set_directory(None):
                raise OSError(ctypes.get_last_error(), "Cannot isolate collector DLL search")
            try:
                yield
            finally:
                set_directory(str(getattr(sys, "_MEIPASS", "")))
        else:
            yield

class BackendUnavailable(RuntimeError):
    pass


class PowerCliBackend:
    def __init__(self, server: str, username: str, password: str, *, timeout: float = 180,
                 cancel_requested=None, stop_reason: Callable[[], str | None] | None = None,
                 runtime_dir: Path | None = None, request_timeout: int = 30, retry_attempts: int = 2):
        self.server, self.username, self.password = server, username, password
        self.timeout = timeout
        self.request_timeout = request_timeout
        self.retry_attempts = retry_attempts
        self.cancel_requested = cancel_requested or (lambda: False)
        self.stop_reason = stop_reason or (lambda: None)
        root = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[3]))
        self.runtime_dir = runtime_dir or (root / "collector-runtime" if getattr(sys, "frozen", False)
                                           else root / ".tools" / "collector-runtime")
        self.cache: dict[str, dict[str, Any]] = {}
        self.vcenter_logs: list[dict[str, Any]] = []
        self.warnings: list[dict[str, Any]] = []
        self.log_file_attempt_count = 0

    def get_vcenter_logs(self) -> list[dict[str, Any]]:
        return list(self.vcenter_logs)

    def prepare(self, hosts: list[Any], *, probe_only: bool = False, log_keys: list[str] | None = None, log_keys_by_host: dict[str, list[str]] | None = None, vcenter_log_keys: list[str] | None = None, include_esxcli: bool = True, max_log_files: int | None = None, max_log_file_bytes: int | None = None, max_log_total_bytes: int | None = None) -> None:
        self.cache = {}
        self.vcenter_logs = []
        self.log_file_attempt_count = 0
        executable = self.runtime_dir / "powershell" / "pwsh.exe"
        script = Path(__file__).with_name("scripts") / "collect_esxcli.ps1"
        if not executable.is_file() or not script.is_file():
            raise BackendUnavailable("bundled_collector_runtime_missing")
        request = {"server": self.server, "username": self.username, "password": self.password,
                   "hosts": [{"id": str(h._moId), "name": str(h.name)} for h in hosts],
                   "host_timeout": self.timeout, "probe_only": probe_only, "request_timeout": self.request_timeout, "retry_attempts": self.retry_attempts, "include_esxcli": include_esxcli,
                   "log_keys": list(log_keys if log_keys is not None else ["vmkernel", "hostd", "vpxa", "vobd", "syslog", "vsan"]), "vcenter_log_keys": list(vcenter_log_keys if vcenter_log_keys is not None else ["vpxd"]), "max_log_lines": 200, "max_log_line_chars": 4096}
        if log_keys_by_host is not None:
            request["log_keys_by_host"] = {str(host_id): list(keys) for host_id, keys in log_keys_by_host.items()}
        if max_log_files is not None:
            request["max_log_files"] = max(0, int(max_log_files))
        if max_log_file_bytes is not None:
            request["max_log_file_bytes"] = max(0, int(max_log_file_bytes))
        if max_log_total_bytes is not None:
            request["max_log_total_bytes"] = max(0, int(max_log_total_bytes))
        env = os.environ.copy()
        env["PSModulePath"] = str(self.runtime_dir / "modules") + os.pathsep + str(self.runtime_dir / "powershell" / "Modules")
        env["POWERSHELL_TELEMETRY_OPTOUT"] = "1"
        env.pop("PSModuleAnalysisCachePath", None)
        # Separate native DLL search from the parent PyInstaller application.
        env["PATH"] = str(self.runtime_dir / "powershell") + os.pathsep + str(Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32")
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        with isolated_child_dll_directory():
            process = subprocess.Popen([str(executable), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(script)],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              encoding="utf-8", errors="replace", env=env, creationflags=flags)
        with process:
            deadline = time.monotonic() + self.timeout * max(1, len(hosts))
            data = json.dumps(request, ensure_ascii=True)
            while True:
                try:
                    stdout, _stderr = process.communicate(input=data, timeout=0.25)
                    break
                except subprocess.TimeoutExpired:
                    data = None
                    stop_reason = self.stop_reason()
                    if stop_reason:
                        process.kill()
                        process.communicate()
                        raise BackendUnavailable(stop_reason)
                    if self.cancel_requested() or time.monotonic() >= deadline:
                        process.kill()
                        process.communicate()
                        raise BackendUnavailable("cancelled" if self.cancel_requested() else "esxcli_timeout")
            if process.returncode:
                # Never forward arbitrary PowerShell error text that may contain credentials.
                raise BackendUnavailable("esxcli_backend_failed")
        try:
            payload = json.loads(stdout)
            if payload.get("schema_version") != 1 or not isinstance(payload.get("hosts"), list):
                raise ValueError("schema")
            self.cache = {str(h["id"]): h for h in payload["hosts"]}
            self.vcenter_logs = list(payload.get("vcenter_logs", []) or [])
            self.warnings = payload.get("warnings", [])
            self.log_file_attempt_count = int(payload.get("log_file_attempt_count", 0) or 0)
            names = {str(h._moId): str(h.name) for h in hosts}
            for host_id, result in self.cache.items():
                for command, record in result.get("commands", {}).items():
                    if record.get("status") != "ok":
                        self.warnings.append({"host": names.get(host_id, host_id), "command": command,
                                              "status": str(record.get("status", "command_unavailable"))})
        except (ValueError, KeyError, TypeError) as exc:
            raise BackendUnavailable("esxcli_malformed_response") from exc

    def __call__(self, host: Any):
        data = self.cache.get(str(host._moId))
        if data is None:
            raise BackendUnavailable("esxcli_host_missing")
        return CachedEsxcli(data)


class CachedEsxcli:
    def __init__(self, payload: dict[str, Any]):
        self.payload = payload

    def execute(self, command: str, arguments: dict[str, Any] | None = None):
        args = arguments or {}
        key = command + (":" + str(args.get("nicname", "")) if command == "network.nic.get" else "")
        record = self.payload.get("commands", {}).get(key)
        if not record or record.get("status") != "ok":
            raise BackendUnavailable(str((record or {}).get("status", "command_unavailable")))
        return record.get("data", [])

    def get_logs(self) -> list[dict[str, Any]]:
        return list(self.payload.get("logs", []) or [])
