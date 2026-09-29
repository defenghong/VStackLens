from __future__ import annotations

import socket
import urllib.parse
from dataclasses import dataclass
from typing import Any


CONNECT_TIMEOUT_SECONDS = 6.0


@dataclass(frozen=True, slots=True)
class VCenterEndpoint:
    original: str
    host: str
    port: int = 443

    @property
    def base_url(self) -> str:
        return f"https://{self.host}:{self.port}" if self.port != 443 else f"https://{self.host}"


@dataclass(frozen=True, slots=True)
class ProbeResult:
    status: str
    message: str
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "success"

    def as_dict(self) -> dict[str, str]:
        return {"status": self.status, "message": self.message, "detail": self.detail}


def normalize_vcenter_address(value: str, default_port: int = 443) -> VCenterEndpoint:
    text = str(value or "").strip()
    if not text:
        raise ValueError("请填写 vCenter 地址。")
    candidate = text if "://" in text else f"https://{text}"
    parsed = urllib.parse.urlparse(candidate)
    host = parsed.hostname or parsed.path.split("/", 1)[0]
    if not host:
        raise ValueError("vCenter 地址格式无效，请输入 IP 或主机名。")
    return VCenterEndpoint(original=text, host=host.strip("[]"), port=parsed.port or default_port or 443)


def friendly_connection_error(error: Any) -> str:
    text = str(error or "")
    lower = text.lower()
    if "10060" in text or "timed out" in lower or "timeout" in lower:
        return "连接 vCenter 超时。请确认当前电脑可以访问 vCenter API，或联系管理员确认 vCenter API 服务可用。"
    if "10061" in text or "connection refused" in lower:
        return "vCenter API 端口无响应。请确认 vCenter 服务已启动，且当前电脑到 vCenter 的 443 端口未被防火墙拦截。"
    if "certificate_verify_failed" in lower or ("ssl" in lower and "certificate" in lower):
        return "vCenter 证书链不受当前电脑信任。本次巡检会在不校验证书模式下重试一次。"
    if "401" in text or "403" in text or "unauthorized" in lower or "forbidden" in lower or "login" in lower or "password" in lower:
        return "用户名或密码错误，或该账号没有 vCenter API 访问权限。"
    if "name or service not known" in lower or "getaddrinfo" in lower or "nodename" in lower:
        return "无法解析 vCenter 地址。请确认输入的是正确的 IP 或主机名。"
    return "已尝试连接 vCenter，但 vSphere SDK 接口无响应。浏览器首页可访问不代表巡检 API 可用。"


def redact_sensitive(value: Any, *secrets: str) -> str:
    text = str(value or "")
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[已隐藏]")
    return text


def socket_probe(host: str, port: int = 443, timeout: float = CONNECT_TIMEOUT_SECONDS) -> ProbeResult:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return ProbeResult("success", f"{host}:{port} 可连接。")
    except Exception as exc:  # noqa: BLE001 - diagnostics must preserve customer-readable failure.
        return ProbeResult("failed", friendly_connection_error(exc), str(exc))


def diagnostic_properties(*, mode: str, port: ProbeResult, sdk: ProbeResult, security_warnings: list[str] | None = None) -> dict[str, Any]:
    return {
        "collection_mode": mode,
        "collection_mode_label": {
            "sdk": "完整 SDK 巡检模式",
            "connection_failed": "连接诊断模式",
        }.get(mode, mode),
        "data_coverage_summary": {
            "sdk": "已通过 vSphere SDK 采集完整巡检数据，现有健康基线照常执行。",
            "connection_failed": "仅生成连接诊断报告，未采集到 vCenter 清单数据。",
        }.get(mode, ""),
        "connection_diagnostics": {
            "port": port.as_dict(),
            "sdk": sdk.as_dict(),
            "suggested_actions": [
                "确认当前电脑可以访问 vCenter 443 端口。",
                "确认账号具备 vCenter API 访问权限。",
                "如果浏览器首页可打开但 SDK 接口无响应，请联系管理员确认 vSphere SDK 服务状态。",
            ],
        },
        "security_warnings": security_warnings or [],
    }


def merge_vcenter_diagnostics(inventory: dict[str, Any], properties: dict[str, Any]) -> dict[str, Any]:
    """Attach collection mode details to the vCenter object without logging credentials."""

    for item in inventory.get("objects", []):
        if item.get("object_type") != "vCenter":
            continue
        item.setdefault("properties", {}).update(properties)
        return inventory
    return inventory
