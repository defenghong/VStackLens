"""Shared license wording; legacy numbers cannot certify permanent entitlement."""
from __future__ import annotations

from typing import Any

from vstacklens.collection.license_state import verified_state


def expiry_label(props: dict[str, Any], host: bool = False, object_key: str | None = None) -> str:
    state = verified_state(props, host, object_key)
    kind = state.get("expiration_state")
    if kind == "perpetual" and state.get("assigned") is True and state.get("perpetual_evidence"):
        return "永久授权（明确到期字段依据）"
    if kind == "dated" and state.get("expiration_at") and state.get("days_remaining") is not None:
        days = state["days_remaining"]
        label = "已过期" if days < 0 else "剩余有效期"
        return f"{state['expiration_date']}；{label} {days} 天"
    if kind == "not_assigned":
        return "未分配，无可判断的到期状态"
    if kind == "parse_failed":
        return "到期状态无法确认（到期字段无法解析）"
    if kind == "read_failed":
        return "到期状态无法确认（字段读取失败）"
    return "到期状态无法确认"


def license_summary(props: dict[str, Any], host: bool = False, object_key: str | None = None) -> str:
    prefix = "host_license_" if host else "license_"
    state = verified_state(props, host, object_key)
    assigned = state.get("assigned") if state else None
    assignment = "已分配" if assigned is True else "未分配" if assigned is False else "分配状态无法确认"
    name = state.get("name") if state else None
    version = (state.get("product_version") or state.get("edition")) if state else None
    parts = [str(v) for v in (name, f"版本 {version}" if version else None, assignment) if v]
    if not state and (props.get(prefix + "name") or props.get(prefix + "edition")):
        parts.append("未绑定参考记录：" + " / ".join(str(v) for v in (props.get(prefix + "name"), props.get(prefix + "edition")) if v))
    if not name and assigned is not False and state.get("records"):
        labels = [str(r.get("name") or "名称未取得") + (f" / {r['edition']}" if r.get("edition") else "")
                  for r in state["records"]]
        parts.append("实体分配记录：" + "、".join(labels))
    if state.get("is_evaluation") is True:
        parts.append("评估授权")
    parts.append(expiry_label(props, host, object_key))
    if state.get("expiration_state") not in {"perpetual", "dated"}:
        reason = state.get("reason") or props.get(prefix + "probe_status")
        if reason:
            parts.append(str(reason))
    return "；".join(parts)
