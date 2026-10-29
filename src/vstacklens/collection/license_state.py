"""Entity-bound license evidence. Inventory and missing expiry never prove validity."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

SCHEMA = "entity-license-v1"
PERPETUAL_DAYS = 999999  # Compatibility only; requires explicit expiry evidence.
EXPIRY_KEYS = {"expirationdate", "expirydate", "expires"}
PRODUCTS = {
    "vCenter": {"vmware virtualcenter server", "vmware vcenter server"},
    "HostSystem": {"vmware esx server", "vmware esxi"},
}
KNOWN_PRODUCTS = set().union(*PRODUCTS.values()) | {"vmware vsan", "vmware vsan server", "vmware nsx"}


def _properties(value: Any) -> list[tuple[str, Any]]:
    return [(str(p.key).casefold(), p.value) for p in (getattr(value, "properties", None) or [])]


def _date(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def expiration_state(info: Any, evaluation: Any = None, *, active_evaluation: bool = False) -> dict[str, Any]:
    """Read explicit expiry fields, without interpreting arbitrary feature labels."""
    values: list[tuple[str, Any]] = []
    try:
        # Legacy adapters may expose this directly; typed LicenseInfo uses properties.
        direct = getattr(info, "expirationDate", None)
        if direct is not None:
            values.append(("LicenseInfo.expirationDate", direct))
        values.extend(("LicenseInfo.properties." + key, val) for key, val in _properties(info) if key in EXPIRY_KEYS)
        if active_evaluation and evaluation is not None:
            values.extend(("LicenseAssignment.properties.Evaluation.properties." + key, val)
                          for key, val in _properties(evaluation) if key in EXPIRY_KEYS)
    except Exception as exc:  # SDK fault bodies can contain a license key; never serialize them.
        return {"state": "read_failed", "error_type": type(exc).__name__, "reason": "到期字段读取失败"}
    if not values:
        return {"state": "unknown", "reason": "未返回可确认到期或永久的明确字段"}
    dates: list[datetime] = []
    permanent: list[dict[str, str]] = []
    for path, value in values:
        if isinstance(value, str) and value.strip().casefold() in {"never", "perpetual", "永久授权"}:
            permanent.append({"source_path": path, "value": value, "meaning": "explicit_no_expiration"})
        else:
            parsed = _date(value)
            if parsed is None:
                return {"state": "parse_failed", "reason": "明确到期字段为空或无法解析", "source_path": path}
            dates.append(parsed)
    if permanent and (dates or active_evaluation):
        return {"state": "unknown", "reason": "永久标记与到期或评估证据冲突"}
    if permanent:
        return {"state": "perpetual", "proof": permanent, "reason": "到期字段明确返回不设到期"}
    return {"state": "dated", "expiration_at": min(dates).isoformat(),
            "source_paths": [p for p, _ in values], "reason": "已取得明确到期时间"}


def _failure(exc: Exception) -> tuple[str, str]:
    name = type(exc).__name__
    return ("permission_denied", "权限不足") if "NoPermission" in name or isinstance(exc, PermissionError) else ("query_failed", "授权查询失败")


def query_entity_license(content: Any, entity_id: str, object_type: str, instance_uuid: str,
                         *, now: datetime | None = None) -> dict[str, Any]:
    """Query precisely one entity in one connected vCenter; no inventory fallback."""
    now = now or datetime.now(UTC)
    state: dict[str, Any] = {
        "schema": SCHEMA, "entity_id": entity_id, "vcenter_instance_uuid": instance_uuid,
        "object_type": object_type, "acquired_at": now.isoformat(),
        "source": "LicenseAssignmentManager.QueryAssignedLicenses(entityId)",
        "assignment_status": "unknown", "assigned": None, "expiration_state": "unknown",
        "is_evaluation": None, "name": None, "edition": None, "product_version": None,
        "expiration_at": None, "expiration_date": None, "days_remaining": None,
        "perpetual_evidence": [], "query_status": "not_queried", "records": [],
    }
    if not entity_id or not instance_uuid:
        return {**state, "query_status": "identity_missing", "reason": "缺少可靠目标实体或 vCenter 身份，未查询库存替代"}
    try:
        manager = getattr(getattr(content, "licenseManager", None), "licenseAssignmentManager", None)
        if manager is None:
            return {**state, "query_status": "unavailable", "reason": "当前接口未提供授权分配管理器"}
        assignments = manager.QueryAssignedLicenses(entityId=entity_id)
        if assignments is None:
            return {**state, "query_status": "partial", "reason": "授权分配查询未返回有效结果"}
        assignments = list(assignments)
    except Exception as exc:
        status, reason = _failure(exc)
        return {**state, "query_status": status, "reason": reason, "error_type": type(exc).__name__}
    state["query_status"] = "success"
    candidates = []
    unknown_product = False
    identity_conflict = False
    partial_assignment = False
    product_conflict = False
    try:
        for assignment in assignments:
            returned_id = str(getattr(assignment, "entityId", "") or "")
            scope = str(getattr(assignment, "scope", "") or "")
            if returned_id != entity_id or (scope and scope != instance_uuid):
                identity_conflict = True
                continue
            info = getattr(assignment, "assignedLicense", None)
            if info is None:
                partial_assignment = True
                continue
            record = {"entity_id": returned_id, "scope": scope, "name": getattr(info, "name", None),
                      "edition": getattr(info, "editionKey", None), "product_names": [], "product_version": None}
            state["records"].append(record)
            assignment_props = _properties(assignment)
            try:
                props = _properties(info)
            except Exception as exc:
                products = [str(v).strip().casefold() for k, v in assignment_props if k == "productname" and v]
                record["product_names"] = products
                record["product_version"] = next((str(v) for k, v in assignment_props if k == "productversion" and v is not None), None)
                known_target = bool(products) and all(p in PRODUCTS[object_type] for p in products)
                status, reason = _failure(exc)
                return {**state, "query_status": status if status == "permission_denied" else "read_failed",
                        "assignment_status": "assigned" if known_target else "unknown",
                        "assigned": True if known_target else None, "name": record["name"],
                        "edition": record["edition"], "product_version": record["product_version"],
                        "expiration_state": "read_failed", "error_type": type(exc).__name__,
                        "reason": reason + "，已取得的名称及实体关系保留"}
            products = [str(v).strip().casefold() for k, v in props + assignment_props if k == "productname" and v]
            record.update(product_names=products, product_version=next((str(v) for k, v in props if k == "productversion" and v is not None), None))
            if not products or any(p not in KNOWN_PRODUCTS for p in products):
                unknown_product = True
                continue
            if any(p not in PRODUCTS[object_type] for p in products):
                if any(p in PRODUCTS[object_type] for p in products):
                    product_conflict = True
                continue
            candidates.append((info, assignment_props, record))
    except Exception as exc:
        return {**state, "query_status": "read_failed", "expiration_state": "read_failed",
                "error_type": type(exc).__name__, "reason": "分配记录或许可证字段读取失败"}
    if product_conflict:
        return {**state, "query_status": "partial", "reason": "分配关系与许可证产品字段矛盾，无法确认目标授权"}
    if partial_assignment:
        return {**state, "query_status": "partial", "reason": "实体分配记录缺少 assignedLicense，不能认定未分配"}
    if identity_conflict:
        return {**state, "query_status": "identity_mismatch", "reason": "分配结果包含目标或环境身份不一致，不能用于判断"}
    if not candidates:
        if unknown_product:
            return {**state, "reason": "已返回实体分配记录，但产品归属信息不足"}
        return {**state, "assignment_status": "unassigned", "assigned": False,
                "expiration_state": "not_assigned", "reason": "查询成功，目标产品没有实际分配的许可证"}
    state.update(assignment_status="assigned", assigned=True)
    if len(candidates) != 1 or unknown_product:
        return {**state, "reason": "目标产品的分配记录不唯一或不完整，无法确认到期状态"}
    info, assignment_props, record = candidates[0]
    state.update(name=record["name"], edition=record["edition"], product_version=record["product_version"])
    try:
        props = _properties(info)
        explicit_type = [str(v).casefold() for k, v in props if k == "licensetype"]
        # Evaluation data can also describe evaluation left on a paid assignment.
        # Presence of that object alone does not mean evaluation is active.
        edition = str(record["edition"] or "").strip().casefold()
        if edition in {"eval", "vceval", "esxeval"} or any(v in {"evaluation", "eval"} for v in explicit_type):
            active_eval = True
        elif edition or any(v in {"perpetual", "subscription", "paid"} for v in explicit_type):
            active_eval = False
        else:
            active_eval = None
        evaluation = next((v for k, v in assignment_props if k == "evaluation"), None)
        expiry = expiration_state(info, evaluation, active_evaluation=active_eval is True)
    except Exception as exc:
        return {**state, "expiration_state": "read_failed", "error_type": type(exc).__name__, "reason": "授权类型读取失败"}
    state.update(is_evaluation=active_eval, expiration_state=expiry["state"], reason=expiry["reason"])
    if expiry.get("error_type"):
        state["error_type"] = expiry["error_type"]
    if expiry["state"] == "perpetual":
        state.update(days_remaining=PERPETUAL_DAYS, expiration_date="永久授权", perpetual_evidence=expiry["proof"])
    elif expiry["state"] == "dated":
        expiration = datetime.fromisoformat(expiry["expiration_at"])
        state.update(expiration_at=expiration.isoformat(), expiration_date=expiration.strftime("%Y-%m-%d"),
                     days_remaining=(expiration - now).days)
    return state


def fields(state: dict[str, Any], *, host: bool = False) -> dict[str, Any]:
    prefix = "host_license_" if host else "license_"
    result = {prefix + name: state.get(source) for name, source in {
        "assigned": "assigned", "name": "name", "edition": "edition", "product_version": "product_version",
        "is_evaluation": "is_evaluation", "expiration_date": "expiration_date", "expiration_at": "expiration_at",
        "assignment_status": "assignment_status", "expiration_state": "expiration_state",
        "perpetual_evidence": "perpetual_evidence", "probe_status": "reason", "evidence": "schema",
    }.items()}
    result[prefix + "evidence"] = state
    result["host_license_expiration_days" if host else "license_days_remaining"] = state.get("days_remaining")
    return result


def verified_state(props: dict[str, Any], host: bool = False, object_key: str | None = None) -> dict[str, Any]:
    prefix = "host_license_" if host else "license_"
    state = props.get(prefix + "evidence")
    if not isinstance(state, dict) or state.get("schema") != SCHEMA or not state.get("entity_id") or not state.get("vcenter_instance_uuid"):
        return {}
    if object_key and state.get("entity_id") != object_key:
        return {}
    if state.get("expiration_state") == "perpetual":
        proof = state.get("perpetual_evidence")
        valid = isinstance(proof, list) and bool(proof) and all(
            isinstance(p, dict) and p.get("meaning") == "explicit_no_expiration"
            and str(p.get("value", "")).strip().casefold() in {"never", "perpetual", "永久授权"}
            and str(p.get("source_path", "")).rsplit(".", 1)[-1].casefold() in EXPIRY_KEYS
            for p in proof
        )
        if not valid:
            return {**state, "expiration_state": "unknown", "days_remaining": None,
                    "reason": "永久标记缺少明确到期字段依据"}
    return state
