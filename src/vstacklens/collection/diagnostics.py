from __future__ import annotations

import re
import socket
import ssl
import traceback
from typing import Any


def exception_category(exc: Exception) -> str:
    name = type(exc).__name__.casefold()
    text = f"{name} {exc}".casefold()
    if isinstance(exc, ssl.SSLCertVerificationError) or "certificate verify" in text:
        return "certificate_verification_failed"
    if "nopermission" in name or "no permission" in text or "permission denied" in text:
        return "permission_denied"
    if "invalidlogin" in name or "notauthenticated" in name or "authentication" in name:
        return "authentication_failed"
    if isinstance(exc, ImportError):
        return "dependency_missing"
    if "methodnotfound" in name or "notsupported" in name or "not supported" in text or "unsupported" in text:
        return "unsupported"
    if isinstance(exc, (TimeoutError, socket.timeout)) or "timed out" in text or "timeout" in name:
        return "timeout"
    if isinstance(exc, (ConnectionError, OSError, ssl.SSLError)):
        return "connection_error"
    return "api_error"


def permission_failure(detail: Any) -> bool:
    if isinstance(detail, dict):
        if detail.get("missing_privilege_id") or detail.get("missing_privilege_ids"):
            return True
        return any(permission_failure(value) for value in detail.values())
    if isinstance(detail, list):
        return any(permission_failure(value) for value in detail)
    return isinstance(detail, str) and (detail.casefold() == "permission_denied" or detail.casefold().endswith("nopermission"))


def exception_details(exc: Exception, *, secrets: tuple[str, ...] = (), context: str = "") -> dict[str, Any]:
    def redact(value: str) -> str:
        for secret in sorted((item for item in secrets if item), key=len, reverse=True):
            value = re.sub(re.escape(secret), "[REDACTED]", value, flags=re.IGNORECASE)
        value = re.sub(r"(?i)\bauthorization[\"']?\s*[:=]\s*[\"']?(?:basic|bearer)\s+[^\s,\"';]+", "authorization=[REDACTED]", value)
        value = re.sub(r"(?i)(https?://)[^\s/:]+:[^\s@]+@", r"\1[REDACTED]@", value)
        value = re.sub(r"(?i)\bBearer\s+[^\s,'\";]+", "Bearer [REDACTED]", value)
        value = re.sub(r"(?i)([\"']?\b(?:password|passwd|pwd|token|api[_-]?key|secret|cookie|authorization)\b[\"']?\s*[:=]\s*)(?:[\"'][^\"']*[\"']|[^\s,;\n]+)", r"\1[REDACTED]", value)
        return value

    return {
        "context": redact(context),
        "category": exception_category(exc),
        "error_type": type(exc).__name__,
        "exception_type": f"{type(exc).__module__}.{type(exc).__qualname__}",
        "message": redact(str(exc)),
        "exception_repr": redact(repr(exc)),
        "traceback": redact("".join(traceback.format_exception(exc))),
        "missing_privilege_id": str(getattr(exc, "privilegeId", "") or ""),
    }
