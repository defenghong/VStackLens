"""Public product inspection contracts. Credentials never enter public records."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
from typing import Any
from urllib.parse import urlsplit

PRODUCTS = {"vcenter", "nsx", "avi"}
STATUS_LABELS = {
    "normal": "正常", "abnormal": "异常", "attention": "需关注",
    "not_deployed": "未部署", "not_applicable": "不适用",
    "permission_denied": "权限不足", "unsupported": "接口不支持",
    "collection_failed": "采集失败", "insufficient_data": "数据不足", "cancelled": "已取消",
}
ERROR_STATUSES = {"permission_denied", "unsupported", "collection_failed", "insufficient_data", "cancelled"}
VERIFIED_LEVELS = {"live_compared", "live_business"}
_PRIVATE_KEYS = {"password", "passwd", "passphrase", "secret", "authorization", "cookie", "cookies",
                 "session", "sessionid", "session_id", "session_token", "token", "access_token", "csrftoken",
                 "private_key", "key_passphrase", "license_key", "pem_encoded", "certificate_pem",
                 "raw_response", "request_data", "resource_data", "credentials", "accesstoken", "refreshtoken",
                 "avi_sessionid", "set_cookie"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def sanitize_public(value: Any, secrets=()) -> Any:
    """Final text scrub after adapter field projection; never preserve raw payloads."""
    secret_values = tuple(str(v) for v in secrets if v)
    if isinstance(value, dict):
        clean = {}
        for key, item in value.items():
            name = str(key).casefold().replace("-", "_")
            if name in _PRIVATE_KEYS or name.endswith(("_password", "_private_key", "_license_key", "_passphrase", "_secret")):
                continue
            clean[str(key)] = sanitize_public(item, secret_values)
        return clean
    if isinstance(value, (list, tuple)):
        return [sanitize_public(item, secret_values) for item in value]
    if isinstance(value, str):
        text = value
        for secret in sorted(secret_values, key=len, reverse=True):
            text = text.replace(secret, "[敏感信息已隐藏]")
        text = re.sub(r"-----BEGIN [^-]+-----.*?(?:-----END [^-]+-----|$)", "[证书或密钥内容已隐藏]", text, flags=re.S)
        text = re.sub(r"(?i)\b(?:Basic|Bearer)\s+[A-Za-z0-9+/=_\-.]+", "[认证信息已隐藏]", text)
        text = re.sub(r'''(?i)(\b(?:password|authorization|cookie|(?:avi[-_])?session_?id|csrftoken|license[_ -]?key|private_key|api_key|access_?token|refresh_?token|secret)\b["']?\s*[:=]\s*)(?:["'][^"'\r\n]*["']|[^\s,;}]+)''', "[认证信息已隐藏]", text)
        text = re.sub(r"(?i)(?<![A-Za-z0-9])[A-Z]:[\\/][^\r\n\"<>]{1,500}", "[本机路径已隐藏]", text)
        return text[:8000]
    if value is None or isinstance(value, (int, float, bool)):
        return value
    return sanitize_public(str(value), secret_values)


@dataclass(slots=True)
class TargetRef:
    target_id: str
    product: str
    customer_id: str
    site_id: str
    name: str
    host: str
    port: int = 443
    username: str = ""
    customer_name: str = ""
    site_name: str = ""
    enabled: bool = True
    identity: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.product not in PRODUCTS:
            raise ValueError("不支持的产品类型。")
        parsed = urlsplit(self.host if "://" in self.host else "https://" + self.host)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ValueError("目标地址必须为不含账号和路径的 HTTPS 地址。")
        self.host = parsed.hostname.lower()
        self.port = int(parsed.port or self.port)
        if not 1 <= self.port <= 65535 or any(c.isspace() for c in self.host):
            raise ValueError("目标地址或端口无效。")
        if not self.target_id or not self.customer_id or not self.site_id:
            raise ValueError("目标、客户和站点必须有稳定 ID。")

    @property
    def address(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"https://{host}" + (f":{self.port}" if self.port != 443 else "")

    def to_dict(self) -> dict[str, Any]:
        from dataclasses import asdict
        return asdict(self)


@dataclass(slots=True, repr=False)
class SessionCredential:
    username: str
    password: str
    tenant: str = "admin"
    allow_untrusted_lab: bool = False
    ca_bundle: str | None = None
    _volatile_secrets: list[str] = field(default_factory=list, repr=False)

    def remember_secret(self, value: str):
        if value and value not in self._volatile_secrets:
            self._volatile_secrets.append(value)

    @property
    def secret_values(self) -> tuple[str, ...]:
        # Account names are removed at authentication-field projection. A
        # username may also be a legitimate tenant/role name, so do not apply
        # it as a blanket substring secret to the whole report.
        return tuple(v for v in (self.password, *self._volatile_secrets) if v)

    def clear(self):
        self.username = ""
        self.password = ""
        self.tenant = ""
        self.ca_bundle = None
        self._volatile_secrets.clear()


def make_source(path: str, *, method="GET", version_basis="", fields=(), note="") -> dict:
    return {"method": method, "path": path, "version_basis": version_basis,
            "fields": list(fields), "collected_at": utc_now(), "note": note}


def make_check(check_id, title, status, *, values=None, summary="", sources=None,
               judgement="PROGRAM", basis="", limitations=None, object_id="", object_name="",
               native_severity="", verification="unverified", completeness="complete",
               recommendation="", impact="") -> dict:
    if status not in STATUS_LABELS:
        raise ValueError("未知的产品检查状态。")
    return sanitize_public({
        "check_id": check_id, "title": title, "status": status, "status_label": STATUS_LABELS[status],
        "values": values, "summary": summary, "sources": list(sources or []), "collected_at": utc_now(),
        "judgement": judgement, "basis": basis, "limitations": list(limitations or []),
        "object_id": object_id, "object_name": object_name, "native_severity": native_severity,
        "verification": verification, "completeness": completeness,
        "recommendation": recommendation, "confirmed_impact": impact,
    })


def new_module(target: TargetRef) -> dict:
    return {
        "product": target.product, "target_id": target.target_id, "target_name": target.name,
        "target_address": target.address, "target_identity": {},
        "customer_id": target.customer_id, "site_id": target.site_id,
        "version": "", "build": "", "started_at": utc_now(), "completed_at": None,
        "collection_state": "running", "analysis_state": "pending", "delivery_state": "pending",
        "checks": [], "inventory": [], "native_alerts": [], "limitations": [], "errors": [],
        "request_metrics": {}, "transport_security": {}, "verification_level": "unverified",
        "experimental": target.product in {"nsx", "avi"},
    }


def has_valid_data(module: dict) -> bool:
    def inventory_has_observation(value):
        if isinstance(value, dict):
            return any(inventory_has_observation(item) for item in value.values())
        if isinstance(value, (list, tuple)):
            return any(inventory_has_observation(item) for item in value)
        # Zero and False may be real observations; empty containers are not.
        return value is not None and value != ""
    return any(check.get("status") not in ERROR_STATUSES and check.get("sources")
               for check in module.get("checks", [])) or inventory_has_observation(module.get("inventory"))


def finish_module(module: dict) -> dict:
    from .management_scope import validate_module_scope
    validate_module_scope(module)
    checks = module.get("checks", [])
    counts = Counter(c.get("status", "insufficient_data") for c in checks)
    if module.get("collection_state") != "cancelled":
        module["collection_state"] = "partial" if has_valid_data(module) and (module.get("errors") or any(counts[s] for s in ERROR_STATUSES)) else "completed" if has_valid_data(module) else "failed"
    module["analysis_state"] = "partial" if any(counts[s] for s in ERROR_STATUSES) else "completed" if checks else "not_run"
    module["completed_at"] = utc_now()
    module["status_summary"] = dict(counts)
    module["verified_pass_count"] = sum(c.get("status") == "normal" and c.get("verification") in VERIFIED_LEVELS for c in checks)
    module["observed_normal_count"] = counts["normal"]
    module["valid_data"] = has_valid_data(module)
    return sanitize_public(module)
