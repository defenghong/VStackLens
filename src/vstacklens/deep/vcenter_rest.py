from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.request
from typing import Any


class VCenterRestReadClient:
    """Small session-scoped REST reader for Deep Inspection GET operations."""

    def __init__(self, host: str, username: str, password: str, port: int = 443, ssl_verify: bool = False, timeout: float = 30.0) -> None:
        self.host = host.strip("[]")
        self.username = username
        self.password = password
        self.port = int(port)
        self.timeout = float(timeout)
        self._session_id: str | None = None
        self._ssl_context = ssl.create_default_context() if ssl_verify else ssl._create_unverified_context()  # noqa: SLF001
        host_part = f"[{self.host}]" if ":" in self.host else self.host
        self._base_url = f"https://{host_part}:{self.port}"

    def get_json(self, path: str) -> Any:
        if not path.startswith("/api/"):
            raise ValueError("Deep REST reader only accepts vCenter API paths")
        for attempt in range(2):
            self._ensure_session()
            request = urllib.request.Request(
                f"{self._base_url}{path}",
                headers={"Accept": "application/json", "vmware-api-session-id": self._session_id or ""},
                method="GET",
            )
            try:
                with urllib.request.urlopen(request, context=self._ssl_context, timeout=self.timeout) as response:
                    return json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                if exc.code == 401 and attempt == 0:
                    self._session_id = None
                    continue
                raise
        raise RuntimeError("vCenter REST authentication retry was exhausted")

    def open(self) -> None:
        self._ensure_session()

    def close(self) -> None:
        session_id = self._session_id
        self._session_id = None
        if not session_id:
            return
        request = urllib.request.Request(
            f"{self._base_url}/api/session",
            headers={"vmware-api-session-id": session_id},
            method="DELETE",
        )
        try:
            with urllib.request.urlopen(request, context=self._ssl_context, timeout=min(self.timeout, 5.0)):
                pass
        except Exception:  # noqa: BLE001 - session cleanup must not hide the collection result.
            return

    def _ensure_session(self) -> None:
        if self._session_id:
            return
        credential = base64.b64encode(f"{self.username}:{self.password}".encode("utf-8")).decode("ascii")
        request = urllib.request.Request(
            f"{self._base_url}/api/session",
            headers={"Authorization": f"Basic {credential}", "Accept": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, context=self._ssl_context, timeout=self.timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
        if not isinstance(payload, str) or not payload:
            raise ValueError("vCenter REST session response did not contain a session identifier")
        self._session_id = payload
