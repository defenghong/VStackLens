"""One management scope contract for collection, results and presentation.

An unmarked saved module is historical: never infer a new scope from its date
or product and never rewrite/filter it. New collectors resolve their scope and
route subset before constructing a transport. No business collection switch is
exposed by this round's public entry points.
"""
from __future__ import annotations

from dataclasses import dataclass

MANAGEMENT_SCOPE_ID = "management-v1"
HISTORICAL_SCOPE_ID = "historical-unscoped"
SCOPE_SCHEMA_VERSION = 1

_NSX_CHECKS = frozenset("nsx." + name for name in (
    "version", "cluster", "services", "resources", "alarms", "certificates",
    "licenses", "backup", "dns", "ntp", "syslog", "interfaces", "vcenter"))
_AVI_CHECKS = frozenset("AVI-A" + str(number) for number in range(1, 9)) | {"AVI-C1", "AVI-LOGIN"}
_NSX_ROUTES = frozenset((
    "manager_spec", "node", "cluster", "cluster_status", "nodes", "node_runtime",
    "cluster_certificate", "certificate_details", "node_resources", "local_resources",
    "interfaces", "local_interfaces", "dns", "local_dns", "search_domains", "ntp",
    "ntp_status", "syslog", "syslog_status", "services", "alarms", "licenses", "backup",
    "compute_managers", "compute_status", "compute_state",
    "service_manager", "service_node_mgmt", "service_datastore", "service_nsx_message_bus",
    "service_controller", "service_cluster_manager", "service_cm_inventory", "service_http"))
_AVI_ROUTES = frozenset((
    "version", "tenants", "cluster_runtime", "system", "alerts", "certificate_details",
    "license_status", "license_ledger", "backup_config", "schedulers", "backups",
    "syslog", "controller_metrics", "clouds"))
_EXECUTION = frozenset(("execution.failure", "execution.cancelled", "execution.identity"))


@dataclass(frozen=True, slots=True)
class ManagementScope:
    product: str
    label: str
    check_ids: frozenset[str]
    route_keys: frozenset[str]
    scope_id: str = MANAGEMENT_SCOPE_ID

    def to_dict(self) -> dict:
        return {"id": self.scope_id, "schema_version": SCOPE_SCHEMA_VERSION,
                "product": self.product, "kind": "management", "label": self.label}


_DEFINITIONS = {
    "nsx": ManagementScope("nsx", "NSX Manager 管理巡检", _NSX_CHECKS, _NSX_ROUTES),
    "avi": ManagementScope("avi", "AVI Controller 管理巡检", _AVI_CHECKS, _AVI_ROUTES),
}


def resolve_scope(product: str, requested: str | None = None) -> ManagementScope:
    """Validate before any IO; this round has exactly one collection scope."""
    if product not in _DEFINITIONS:
        raise ValueError("管理巡检范围仅适用于 NSX／AVI。")
    if requested not in (None, MANAGEMENT_SCOPE_ID):
        raise ValueError("本轮仅支持管理端巡检范围。")
    return _DEFINITIONS[product]


def scope_label(product: str) -> str:
    return resolve_scope(product).label


def select_routes(product: str, routes: dict, requested: str | None = None) -> dict:
    scope = resolve_scope(product, requested)
    return {key: route for key, route in routes.items() if key in scope.route_keys}


def mark_management_scope(module: dict, requested: str | None = None) -> dict:
    """Mark only a new collection/diagnostic, never a historical replay."""
    scope = resolve_scope(module.get("product"), requested)
    module.setdefault("coverage", {})["inspection_scope"] = scope.to_dict()
    return module


def module_scope(module: dict) -> ManagementScope | None:
    marker = (module.get("coverage") or {}).get("inspection_scope")
    if marker is None:
        return None
    if not isinstance(marker, dict) or marker.get("id") != MANAGEMENT_SCOPE_ID:
        raise ValueError("无法确认结果的巡检范围。")
    scope = resolve_scope(module.get("product"), marker["id"])
    if marker.get("product") != scope.product or marker.get("schema_version") != SCOPE_SCHEMA_VERSION:
        raise ValueError("巡检范围身份或版本不一致。")
    return scope


def is_management_module(module: dict) -> bool:
    return module_scope(module) is not None


def is_management_check(product: str, check_or_id) -> bool:
    check_id = str(check_or_id.get("check_id", "") if isinstance(check_or_id, dict) else check_or_id)
    base = check_id.split(":", 1)[0]
    return check_id in _EXECUTION or base in resolve_scope(product).check_ids


def validate_module_scope(module: dict) -> None:
    scope = module_scope(module)
    if scope is not None and any(not is_management_check(scope.product, check) for check in module.get("checks") or []):
        # Reject leaks; never silently remove observations to make a result pass.
        raise ValueError("管理巡检结果包含范围外检查，已阻止汇总。")


def scoped_checks(module: dict) -> tuple[dict, ...]:
    """The same check set for all consumers; historical modules stay intact."""
    validate_module_scope(module)
    return tuple(module.get("checks") or [])


def alarm_lifecycle(product: str, native_state) -> str:
    state = str(native_state or "").strip().upper()
    if product == "nsx":
        return "active" if state in {"OPEN", "ACKNOWLEDGED"} else "cleared" if state == "RESOLVED" else "unknown"
    if product == "avi":
        return "active" if state == "ALERT_STATE_ON" else "cleared" if state == "ALERT_STATE_OFF" else "unknown"
    raise ValueError("原生告警生命周期仅适用于 NSX／AVI。")


def alarm_lifecycle_of(product: str, alarm: dict) -> str:
    """Read native fields first, including old saved records without metadata."""
    native = alarm.get("status") if product == "nsx" else alarm.get("state")
    if native is not None:
        return alarm_lifecycle(product, native)
    # New adapters may preserve their explicit native state under this name.
    if alarm.get("native_state") is not None:
        return alarm_lifecycle(product, alarm["native_state"])
    return "unknown"
