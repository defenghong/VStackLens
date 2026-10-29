"""Offline adapter evidence. These samples are never real business acceptance."""
from __future__ import annotations

from copy import deepcopy
import base64
from datetime import datetime, timedelta, timezone
import json

import pytest

from vstacklens.products.avi import CHECK_MATRIX, ROUTES, collect_avi
from vstacklens.products import avi as _avi
from vstacklens.products.model import finish_module, make_check
from vstacklens.products.model import SessionCredential, TargetRef
from vstacklens.products.transport import CollectionError


PRIVATE = "OFFLINE-AVI-PASSWORD-67213"
SESSION = "OFFLINE-AVI-SESSION-55197"
KEY = "OFFLINE-PRIVATE-KEY-11208"
PEM = "-----BEGIN CERTIFICATE-----\nOFFLINE_CERTIFICATE_PAYLOAD\n-----END CERTIFICATE-----"


def structural_certificate(start=b"240101000000Z", end=b"360920095114Z"):
    # Structural DER validity fixture; no cryptographic chain/signature claim.
    def tlv(tag, value):
        size = bytes([len(value)]) if len(value) < 128 else b"\x81" + bytes([len(value)])
        return bytes([tag]) + size + value
    validity = tlv(0x30, tlv(0x17, start) + tlv(0x17, end))
    body = tlv(0x02, b"\x01") + tlv(0x30, b"") + tlv(0x30, b"") + validity
    encoded = base64.b64encode(tlv(0x30, tlv(0x30, body))).decode()
    return "-----BEGIN CERTIFICATE-----\n" + encoded + "\n-----END CERTIFICATE-----"


def target(name="offline-controller", tenant="admin"):
    return TargetRef("target-avi", "avi", "customer-1", "site-1", name, "192.0.2.109")


def basic_data():
    future = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()
    return {
        "version": {"Version": "30.2.5", "build": "offline-build"},
        "tenants": [{"uuid": "admin", "name": "admin"}, {"uuid": "tenant-other", "name": "other"}],
        "cluster_runtime": {"node_info": {"uuid": "node-1", "cluster_uuid": "cluster-1"}, "nodes_count": 1,
                            "node_states": [{"uuid": "node-1", "name": "node", "state": "CLUSTER_ACTIVE", "role": "CLUSTER_LEADER", "up_since": "2026-01-01 00:00:00"}],
                            "cluster_state": {"state": "CLUSTER_UP_NO_HA"}},
        "system": [{"uuid": "system", "dns_configuration": {"server_list": [{"addr": "192.0.2.53"}], "search_domain": "example.invalid"},
                    "ntp_configuration": {"ntp_server_list": [{"addr": "192.0.2.123"}], "ntp_authentication_keys": [{"key": KEY}]},
                    "portal_configuration": {"sslkeyandcertificate_refs": ["/api/sslkeyandcertificate/cert-1"]},
                    "email_configuration": {"auth_password": PRIVATE}, "proxy_configuration": {"password": KEY}}],
        "certificates": [{"uuid": "cert-1", "name": "portal-cert", "key": KEY, "key_passphrase": PRIVATE,
                          "certificate": {"certificate": PEM, "text": PEM, "not_after": future, "subject": {"common_name": "controller.example.invalid"}, "fingerprint": "offline-fingerprint"}}],
        "alerts": [], "license_status": [{"saas_status": {"enabled": False, "expired": True, "public_key": KEY}}],
        "license_ledger": [{"tier_usages": [{"tier": "ENTERPRISE", "usage": {"available": 10, "remaining": 10}}]}],
        "backup_config": [], "schedulers": [], "backups": [], "syslog": [],
        "clouds": [], "cloud_runtime": [], "ses": [], "se_inventory": [], "se_groups": [],
        "virtual_services": [], "vs_inventory": [], "pools": [], "pool_inventory": [], "health_monitors": [], "ssl_profiles": [],
    }


class FakeTransport:
    verification_level = "offline_replay"

    def __init__(self, data, failures=None, incomplete=None, auth_error=None, cancel_requested=None):
        self.data = deepcopy(data)
        self.failures = failures or {}
        self.incomplete = incomplete or {}
        self.auth_error = auth_error
        self.cancel_requested = cancel_requested or (lambda: False)
        self.calls = []
        self.metrics = {"requests": 0}
        self.transport_security = {"peer_identity_verified": False, "mode": "offline_test"}
        self.secret_values = (PRIVATE, SESSION)
        self.closed = False

    def check_cancelled(self):
        if self.cancel_requested():
            raise CollectionError("cancelled", "offline cancel", stage="cancellation")

    def login_avi(self):
        self.calls.append(("POST", "/login"))
        if self.auth_error:
            raise self.auth_error

    def logout_avi(self):
        self.calls.append(("POST", "/logout"))

    def close(self):
        self.closed = True
        self.secret_values = ()

    def get(self, key, path_params=None, query=None):
        self.check_cancelled()
        self.calls.append(("GET", key, deepcopy(path_params), deepcopy(query)))
        self.metrics["requests"] += 1
        if key in self.failures:
            raise self.failures[key]
        value = self.data.get(key, {})
        result = value(query, path_params) if callable(value) else deepcopy(value)
        if key in {"system", "license_status", "license_ledger"} and isinstance(result, list):
            return {"count": len(result), "results": result}
        return result

    def list_pages(self, key, kind="avi", query=None, path_params=None):
        self.check_cancelled()
        self.calls.append(("GET", key, deepcopy(path_params), deepcopy(query)))
        self.metrics["requests"] += 1
        if key in self.failures:
            raise self.failures[key]
        return {"items": deepcopy(self.data.get(key, [])), "complete": key not in self.incomplete,
                "errors": [self.incomplete[key]] if key in self.incomplete else [], "sources": []}


def run(data=None, *, failures=None, incomplete=None, auth_error=None, cancel_requested=None, tenant="admin"):
    """Historical helper regression only; never a public full-collection switch."""
    fake = FakeTransport(data or basic_data(), failures, incomplete, auth_error, cancel_requested)
    cred = SessionCredential("admin", PRIVATE, tenant=tenant)
    cred.remember_secret(SESSION)
    result = _legacy_replay(fake, cred, cancel_requested=cancel_requested)
    return result, fake


def _legacy_replay(fake, credential, *, cancel_requested=None):
    assert type(fake) is FakeTransport  # Pure in-memory fixtures only.
    ctx = _avi._Collection(target(), credential, fake)
    try:
        fake.check_cancelled()
        fake.login_avi()
        if _avi._version_and_scope(ctx):
            _avi._cluster_and_resources(ctx)
            _avi._alarms(ctx)
            _avi._license(ctx)
            _avi._backup(ctx)
            _avi._clouds(ctx)
            _avi._service_engines(ctx)
            systems = ctx.listed("system")
            certificates = _avi._certificate_check(ctx, systems)
            _avi._operations(ctx, systems)
            virtual_services = _avi._vs_and_pools(ctx)
            _avi._monitors_and_tls(ctx, virtual_services, certificates)
            _avi._business_metrics(ctx, virtual_services)
    except CollectionError as exc:
        ctx.error(exc, "version")
        ctx.module["checks"].append(make_check("AVI-LOGIN", "Offline historical authentication", "cancelled" if exc.kind == "cancelled" else "collection_failed", values={}, verification="offline_replay"))
    finally:
        fake.logout_avi()
        ctx.module["request_metrics"] = dict(fake.metrics)
        ctx.module["transport_security"] = dict(fake.transport_security)
        fake.close()
    existing = {c["check_id"].split(":", 1)[0] for c in ctx.module["checks"]}
    cancelled = bool(cancel_requested and cancel_requested())
    for row in CHECK_MATRIX:
        if row["id"] not in existing:
            ctx.module["checks"].append(make_check(row["id"], row["title"], "cancelled" if cancelled else "insufficient_data", values={}, verification="offline_replay"))
    _avi._annotate_usage(ctx)
    _avi._management_gaps(ctx)
    return finish_module(ctx.public(ctx.module))


def check(result, cid):
    return next(c for c in result["checks"] if c["check_id"] == cid)


def business_data():
    data = basic_data()
    data["virtual_services"] = [{"uuid": "vs-1", "name": "app", "enabled": True, "services": [{"port": 443, "enable_ssl": True}],
                                  "vip": [{"ip_address": {"addr": "192.0.2.200"}}], "pool_ref": "/api/pool/pool-1",
                                  "ssl_key_and_certificate_refs": ["/api/sslkeyandcertificate/cert-1"], "ssl_profile_ref": "/api/sslprofile/tls-1",
                                  "tls_ticket_key": [{"aes_key": KEY}]}]
    data["vs_inventory"] = [{"uuid": "vs-1", "runtime": {"oper_status": {"state": "OPER_UP"}}}]
    data["pools"] = [{"uuid": "pool-1", "name": "pool", "enabled": True, "default_server_port": 80, "lb_algorithm": "LB_ALGORITHM_LEAST_CONNECTIONS",
                       "servers": [{"ip": {"addr": "192.0.2.210"}, "port": 80, "enabled": True}, {"ip": {"addr": "192.0.2.211"}, "port": 80, "enabled": False}]}]
    data["pool_inventory"] = [{"uuid": "pool-1", "runtime": {"num_servers": 2, "num_servers_enabled": 1, "num_servers_up": 0,
                                                                "oper_status": {"state": "OPER_DOWN", "reason": ["health check failed"]}}}]
    data["server_runtime"] = {"servers": [{"ip_addr": "192.0.2.210", "port": 80, "oper_status": {"state": "OPER_DOWN", "reason": ["timeout"]}},
                                           {"ip_addr": "192.0.2.211", "port": 80, "oper_status": {"state": "OPER_DOWN"}}]}
    return data


def test_empty_business_and_single_controller_are_observation_not_acceptance():
    result, fake = run()
    assert result["version"] == "30.2.5"
    assert check(result, "AVI-A2")["status"] == "normal"
    assert check(result, "AVI-A2:services")["status"] == "insufficient_data"
    assert check(result, "AVI-A3")["status"] == "insufficient_data"
    for cid in ("AVI-C2", "AVI-C4", "AVI-C5", "AVI-C6", "AVI-C9"):
        assert check(result, cid)["status"] == "not_deployed"
    assert check(result, "AVI-A7")["status"] == "attention"
    assert result["verified_pass_count"] == 0
    assert result["verification_level"] == "offline_replay"
    assert result["coverage"]["tenant_scope"]["checked_tenants"] == ["admin"]
    assert len(result["coverage"]["tenant_scope"]["visible_tenants"]) == 2
    assert fake.closed and fake.calls[-1] == ("POST", "/logout")
    assert not any(c[1] == "vs_metrics" for c in fake.calls)


def test_authentication_failure_stops_reads_and_does_not_claim_empty_or_healthy():
    result, fake = run(auth_error=CollectionError("authentication", "offline denied", http_status=401, stage="login"))
    assert not any(c[0] == "GET" for c in fake.calls)
    assert check(result, "AVI-LOGIN")["status"] == "collection_failed"
    assert all(c["status"] not in {"normal", "not_deployed"} for c in result["checks"])
    assert not result["valid_data"] and fake.closed


@pytest.mark.parametrize("kind,status", [("permission", "permission_denied"), ("unsupported", "unsupported"), ("timeout", "collection_failed"), ("rate_limit", "collection_failed")])
def test_one_failed_interface_does_not_cancel_independent_collections(kind, status):
    result, fake = run(failures={"alerts": CollectionError(kind, "offline", http_status=403 if kind == "permission" else None)})
    assert check(result, "AVI-A4")["status"] == status
    assert check(result, "AVI-A5:cert-1")["status"] == "normal"
    assert check(result, "AVI-A7")["status"] == "attention"
    assert any(c[1] == "pools" for c in fake.calls)
    assert any(e["kind"] == kind and e["source"] == "/api/alert" for e in result["errors"])


def test_partial_empty_inventory_is_not_not_deployed_or_normal():
    result, _ = run(incomplete={"ses": {"kind": "budget", "stage": "pagination", "reason": "offline page budget"}})
    item = check(result, "AVI-C2")
    assert item["status"] == "insufficient_data" and item["completeness"] == "partial"
    assert check(result, "AVI-C4")["status"] == "not_deployed"


def test_native_alarm_severity_and_state_are_retained_without_p_grade():
    data = basic_data()
    data["alerts"] = [{"uuid": "alert-1", "obj_uuid": "node-1", "obj_name": "node", "level": "MEDIUM", "state": "ALERT_STATE_ON", "timestamp": 1700000000,
                       "summary": "native issue", "events": [{"request_data": KEY}]}]
    result, _ = run(data)
    assert check(result, "AVI-A4")["status"] == "attention"
    assert result["native_alerts"][0]["level"] == "MEDIUM"
    assert "P2" not in json.dumps(result)


def test_certificate_expired_expiring_and_unknown_are_not_arbitrary_thresholds():
    data = basic_data()
    expired = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    tomorrow = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    data["certificates"] = [
        {"uuid": "expired", "certificate": {"not_after": expired}},
        {"uuid": "native-warning", "certificate": {"not_after": tomorrow, "expiry_status": "SSL_CERTIFICATE_EXPIRY_WARNING"}},
        {"uuid": "tomorrow-no-warning", "certificate": {"not_after": tomorrow}},
        {"uuid": "unknown", "certificate": {"days_until_expire": 0}},
    ]
    result, _ = run(data)
    assert check(result, "AVI-A5:expired")["status"] == "abnormal"
    assert check(result, "AVI-A5:native-warning")["status"] == "attention"
    assert check(result, "AVI-A5:tomorrow-no-warning")["status"] == "normal"
    assert check(result, "AVI-A5:unknown")["status"] == "insufficient_data"


def test_existing_backup_never_becomes_success_and_disabled_saas_not_failure():
    data = basic_data()
    data["backup_config"] = [{"uuid": "backup-config", "name": "backup", "backup_passphrase": KEY}]
    data["schedulers"] = [{"uuid": "schedule", "enabled": True, "backup_config_ref": "/api/backupconfiguration/backup-config", "scheduler_action": "SCHEDULER_ACTION_BACKUP"}]
    data["backups"] = [{"uuid": "backup-1", "timestamp": "2026-01-01T00:00:00Z", "local_file_url": "/secret-file", "success": True}]
    result, _ = run(data)
    backup = check(result, "AVI-A7")
    assert backup["status"] == "insufficient_data"
    assert backup["values"]["automatic_backup_enabled"] is True
    assert backup["values"]["last_success"] is None and backup["values"]["restore_verified"] is None
    assert check(result, "AVI-A6")["status"] == "insufficient_data"


def test_backend_manual_disable_failure_and_missing_runtime_are_distinct():
    result, _ = run(business_data())
    assert check(result, "AVI-C4:vs-1")["status"] == "normal"
    assert check(result, "AVI-C5:pool-1")["status"] == "abnormal"
    assert check(result, "AVI-C6:pool-1:192.0.2.210:80")["status"] == "abnormal"
    assert check(result, "AVI-C6:pool-1:192.0.2.211:80")["status"] == "not_applicable"
    data = business_data()
    data["pool_inventory"] = []
    data["server_runtime"] = {"unknown_shape": [{"healthy": True}]}
    result, _ = run(data)
    assert check(result, "AVI-C5:pool-1")["status"] == "insufficient_data"
    assert check(result, "AVI-C6:pool-1:192.0.2.210:80")["status"] == "insufficient_data"


def test_health_monitor_configuration_counts_and_raw_request_are_not_probe_results():
    data = basic_data()
    data["health_monitors"] = [{"uuid": "monitor-1", "type": "HEALTH_MONITOR_HTTP", "successful_checks": 3, "failed_checks": 2,
                                "send_interval": 10, "receive_timeout": 4, "authentication": {"password": KEY},
                                "http_monitor": {"http_request": "GET /health?secret=" + KEY + " HTTP/1.1\r\nAuthorization: Bearer " + KEY,
                                                 "http_request_body": KEY, "http_response_code": ["HTTP_2XX"]}}]
    result, _ = run(data)
    monitor = check(result, "AVI-C7:monitor-1")
    assert monitor["status"] == "insufficient_data"
    assert monitor["values"]["http_configuration"]["path"] == "/health"
    assert KEY not in json.dumps(result)


def test_strict_safe_projection_hides_password_sessions_keys_certificates_and_paths():
    data = business_data()
    data["alerts"] = [{"uuid": "alert-1", "level": "MEDIUM", "state": "ALERT_STATE_ON", "summary": PRIVATE + SESSION + " C:\\Users\\private\\token.txt"}]
    result, _ = run(data)
    serialized = json.dumps(result, ensure_ascii=False)
    for secret in (PRIVATE, SESSION, KEY, "OFFLINE_CERTIFICATE_PAYLOAD", "BEGIN CERTIFICATE", "C:\\Users"):
        assert secret not in serialized
    assert "certificate" in serialized and "not_after" in serialized
    assert result["transport_security"]["peer_identity_verified"] is False


def test_external_references_never_cause_requests_or_enter_binding_identity():
    data = business_data()
    data["virtual_services"][0]["pool_ref"] = "https://attacker.invalid/api/pool/stolen"
    data["virtual_services"][0]["ssl_key_and_certificate_refs"] = ["https://user:password@192.0.2.109/api/sslkeyandcertificate/stolen", "//attacker.invalid/api/sslkeyandcertificate/stolen", "/api/sslkeyandcertificate/cert-1"]
    result, fake = run(data)
    values = check(result, "AVI-C4:vs-1")["values"]
    assert values["pool"] is None
    assert values["certificates"] == [{"type": "sslkeyandcertificate", "uuid": "cert-1"}]
    assert "attacker.invalid" not in json.dumps(result)
    assert all(c[1] in ROUTES or c[1] in {"/login", "/logout"} for c in fake.calls)


def test_metrics_are_bounded_have_units_and_do_not_pad_duplicate_or_out_of_window_data():
    data = business_data()

    def metrics(query, _params):
        start = datetime.fromisoformat(query["start"])
        points = [{"timestamp": (start + timedelta(minutes=i)).isoformat(), "value": i} for i in range(12)]
        points += [points[0], {"timestamp": "2000-01-01T00:00:00Z", "value": 20}, {"timestamp": start.isoformat(), "value": float("nan")}]
        return {"start": query["start"], "stop": query["stop"], "step": 60,
                "series": [{"header": {"name": "l4_client.avg_bandwidth"}, "data": points}]}

    data["vs_metrics"] = metrics
    result, fake = run(data)
    item = check(result, "AVI-C9:vs-1")
    metric = item["values"]["metrics"][0]
    assert item["status"] == "insufficient_data"
    assert metric["unit"] == "BITS_PER_SECOND"
    assert metric["returned_sample_count"] == 12 and metric["missing_samples"] == 3
    assert metric["rejected_samples"] == 3 and metric["complete"] is False
    call = next(c for c in fake.calls if c[1] == "vs_metrics")
    assert call[3]["limit"] == 15 and call[3]["step"] == 60 and call[3]["pad_missing_data"] == "false"
    assert (datetime.fromisoformat(call[3]["stop"]) - datetime.fromisoformat(call[3]["start"])).total_seconds() == 900
    json.dumps(result, allow_nan=False)


def test_invalid_payload_and_missing_fields_never_become_healthy():
    data = basic_data()
    data["alerts"] = {"not": "a list"}
    data["certificates"] = [{"uuid": "unknown", "certificate": None}]
    data["cluster_runtime"] = {"node_states": [], "cluster_state": {}}
    result, _ = run(data)
    assert check(result, "AVI-A4")["status"] == "collection_failed"
    assert check(result, "AVI-A5:unknown")["status"] == "insufficient_data"
    assert check(result, "AVI-A2")["status"] == "insufficient_data"
    assert check(result, "AVI-C4")["status"] == "not_deployed"


def test_cancellation_always_closes_session_and_retains_uncollected_matrix():
    result, fake = run(cancel_requested=lambda: True)
    assert fake.closed
    assert all(c["status"] == "cancelled" for c in result["checks"])
    assert {r["id"] for r in CHECK_MATRIX} <= {c["check_id"].split(":", 1)[0] for c in result["checks"]}
    assert not result["valid_data"]


def test_version_mismatch_does_not_interpret_other_version_fields():
    data = basic_data()
    data["version"] = {"Version": "32.1.4"}
    result, fake = run(data)
    assert check(result, "AVI-A1")["status"] == "unsupported"
    assert not any(c[1] == "ses" for c in fake.calls)
    assert all(c["status"] not in {"normal", "not_deployed"} for c in result["checks"])


def test_selected_tenant_is_explicit_and_other_visible_tenants_not_implicitly_checked():
    result, _ = run(tenant="other")
    assert result["coverage"]["tenant_scope"]["checked_tenants"] == ["other"]
    assert result["target_identity"]["tenant_uuid"] == "tenant-other"
    assert all(row["tenant"] == "other" for row in result["inventory"])


def test_failed_backup_config_is_not_reported_as_unconfigured():
    result, _ = run(failures={"backup_config": CollectionError("permission", "offline denied", http_status=403)})
    assert check(result, "AVI-A7")["status"] == "permission_denied"
    assert check(result, "AVI-A7")["summary"] != "未配置自动备份。"


def test_vsvip_and_protocol_references_supply_configuration_not_runtime_proof():
    data = business_data()
    vs = data["virtual_services"][0]
    vs.pop("vip")
    vs.update(vsvip_ref="/api/vsvip/vip-1", application_profile_ref="/api/applicationprofile/app-1", network_profile_ref="/api/networkprofile/net-1")
    data["vsvips"] = [{"uuid": "vip-1", "vip": [{"ip_address": {"addr": "192.0.2.220"}}], "dns_info": [{"fqdn": "app.example.invalid"}]}]
    data["application_profiles"] = [{"uuid": "app-1", "type": "APPLICATION_PROFILE_TYPE_HTTP", "http_profile": {"sensitive": KEY}}]
    data["network_profiles"] = [{"uuid": "net-1", "profile": {"type": "PROTOCOL_TYPE_TCP_PROXY", "tcp_proxy_profile": {"sensitive": KEY}}}]
    result, _ = run(data)
    item = check(result, "AVI-C4:vs-1")
    assert item["values"]["vip"][0]["ip_address"] == "192.0.2.220"
    assert item["values"]["configured_protocol"] == {"application_type": "APPLICATION_PROFILE_TYPE_HTTP", "network_type": "PROTOCOL_TYPE_TCP_PROXY"}
    assert {s["path"] for s in item["sources"]} >= {"/api/vsvip", "/api/applicationprofile", "/api/networkprofile"}
    assert all(s["observations"] and s["collected_at"] for s in item["sources"])
    assert KEY not in json.dumps(result)


def test_se_resources_do_not_replace_runtime_and_internal_partitions_are_not_claimed():
    data = basic_data()
    data["ses"] = [{"uuid": "se-1", "name": "engine", "vcpus": 2, "memory": 4096}]
    data["se_inventory"] = [{"uuid": "se-1", "runtime": {"oper_status": {"state": "OPER_UP"}}}]
    data["se_metrics"] = lambda query, params: {"series": [{"header": {"name": "se_stats.avg_cpu_usage"}, "data": [{"timestamp": query["stop"], "value": 5}]}]}
    result, _ = run(data)
    assert check(result, "AVI-C2:se-1")["status"] == "normal"
    resources = check(result, "AVI-C2:se-1:resources")
    assert resources["status"] == "insufficient_data"
    assert resources["values"]["metrics"][0]["unit"] == "PERCENT"
    assert resources["values"]["metrics"][0]["returned_sample_count"] == 1
    assert "分区" in "".join(resources["limitations"])


def test_constructor_tls_failure_is_safe_structured_failed_module():
    credential = SessionCredential("admin", PRIVATE)

    def denied(*args, **kwargs):
        raise CollectionError("tls", "invalid certificate", stage="validation")

    result = collect_avi(target(), credential, transport_factory=denied)
    assert result["collection_state"] == "failed"
    assert result["errors"][0]["kind"] == "tls"
    assert len(result["checks"]) == len(_avi.management_check_matrix())
    assert not result["valid_data"]


def test_runtime_objects_without_configuration_are_not_misreported_as_undeployed():
    data = basic_data()
    data["se_inventory"] = [{"uuid": "orphan-se", "runtime": {"oper_status": {"state": "OPER_UP"}}}]
    data["vs_inventory"] = [{"unknown_identity": True}]
    data["pool_inventory"] = [{"uuid": "orphan-pool"}]
    result, _ = run(data)
    for cid in ("AVI-C2", "AVI-C4", "AVI-C5"):
        item = check(result, cid)
        assert item["status"] == "insufficient_data"
        assert item["values"]["unmatched_runtime_count"] == 1


def test_per_object_failure_does_not_reclassify_another_engine_as_permission_denied():
    data = basic_data()
    data["ses"] = [{"uuid": "se-1"}, {"uuid": "se-2"}]
    data["se_inventory"] = [{"uuid": uuid, "runtime": {"oper_status": {"state": "OPER_UP"}}} for uuid in ("se-1", "se-2")]

    def metrics(query, params):
        if params["uuid"] == "se-1":
            raise CollectionError("permission", "offline engine denied", http_status=403)
        return {"series": [{"header": {"name": "se_stats.avg_cpu_usage"}, "data": [{"timestamp": query["stop"], "value": 4}]}]}

    data["se_metrics"] = metrics
    result, _ = run(data)
    assert check(result, "AVI-C2:se-1:resources")["status"] == "permission_denied"
    second = check(result, "AVI-C2:se-2:resources")
    assert second["status"] == "insufficient_data" and second["completeness"] == "complete"
    assert second["values"]["metrics"][0]["returned_sample_count"] == 1


def test_verified_singleton_routes_accept_real_shape_without_widening_list_parser():
    data = basic_data()
    for key in ("system", "license_status", "license_ledger"):
        data[key] = data[key][0]
    data["backup_config"] = [{"uuid": "backup-config", "save_local": True}]
    data["schedulers"] = [{"uuid": "backup-schedule", "enabled": True, "backup_config_ref": "/api/backupconfiguration/backup-config", "scheduler_action": "SCHEDULER_ACTION_BACKUP"}]
    data["backups"] = [{"uuid": "backup-1", "timestamp": "2026-10-17T00:00:00Z"}]
    data["se_groups"] = [{"uuid": "default-group", "ha_mode": "HA_MODE_SHARED"}]
    result, fake = run(data)
    operations = check(result, "AVI-A8")
    assert operations["values"]["configuration"][0]["dns_servers"] == ["192.0.2.53"]
    assert check(result, "AVI-A6")["values"]["tier_usage"][0]["tier"] == "ENTERPRISE"
    assert not any(e["source"] in {"/api/systemconfiguration", "/api/licensing/status", "/api/licensing/ledger/details"} for e in result["errors"])
    singleton_calls = [c for c in fake.calls if c[1] in {"system", "license_status", "license_ledger"}]
    assert all("page" not in call[3] and "page_size" not in call[3] for call in singleton_calls)
    # All these endpoint reads succeeded; required check evidence is still
    # missing. Reading a complete object is not a complete inspection item.
    for cid, field in (
        ("AVI-A3", "internal_disk_partitions"),
        ("AVI-A6", "local_license_validity_and_expiration"),
        ("AVI-A7", "last_backup_success_time_and_result"),
        ("AVI-A8", "ntp_synchronization_state"),
        ("AVI-C3:default-group", "actual_redundancy_runtime_state"),
    ):
        item = check(result, cid)
        assert item["status"] == "insufficient_data"
        assert item["completeness"] == "partial"
        assert field in item["values"]["missing_required_fields"]
        assert all(source["read_completeness"] == "complete" for source in item["sources"])
    assert check(result, "AVI-A7")["values"]["last_failure"] is None
    assert check(result, "AVI-C4")["completeness"] == "complete"
    assert check(result, "AVI-A5:cert-1")["completeness"] == "complete"


def test_singleton_compatibility_rejects_error_dicts_and_nonallowlisted_lists():
    data = basic_data()
    data["system"] = {"uuid": "system", "error": "failed"}
    data["license_status"] = {"unexpected": {"healthy": True}}
    data["alerts"] = {"uuid": "not-a-list", "state": "ACTIVE"}
    result, _ = run(data)
    assert check(result, "AVI-A8")["status"] == "collection_failed"
    assert check(result, "AVI-A6")["status"] == "collection_failed"
    assert check(result, "AVI-A4")["status"] == "collection_failed"


def test_backup_reads_without_unsupported_sort_and_orders_only_collected_records():
    data = basic_data()
    data["backups"] = [{"uuid": "old", "timestamp": "2026-01-01T00:00:00Z"}, {"uuid": "unknown", "timestamp": "no-zone"}, {"uuid": "new", "timestamp": "2026-10-17T00:00:00Z"}]
    result, fake = run(data)
    call = next(c for c in fake.calls if c[1] == "backups")
    assert "sort" not in call[3]
    assert [r["uuid"] for r in check(result, "AVI-A7")["values"]["existing_backup_records"]] == ["new", "old", "unknown"]
    assert check(result, "AVI-A7")["values"]["last_success"] is None


def test_live_shape_unzoned_certificates_keep_native_status_without_inventing_utc():
    data = basic_data()
    data["certificates"] = [{"uuid": "cert-1", "status": "SSL_CERTIFICATE_FINISHED", "certificate": {
        "not_before": "1970-01-01 00:00:00", "not_after": "2036-09-20 09:51:14", "days_until_expire": 365,
        "expiry_status": "SSL_CERTIFICATE_GOOD", "fingerprint": "offline-fingerprint", "certificate": PEM}}]
    result, _ = run(data)
    item = check(result, "AVI-A5:cert-1")
    assert item["status"] == "normal" and item["judgement"] == "NATIVE"
    assert item["values"]["metadata"]["not_after"] == "2036-09-20 09:51:14"
    assert item["values"]["metadata"]["days_until_expire"] == 365
    assert item["values"]["date_interpretation"]["timezone"] == "unknown"
    assert item["values"]["date_interpretation"]["independent_utc_validity_check"] is False
    assert item["values"]["management_bindings"] == ["portal_configuration"]
    assert item["verification"] == "offline_replay"
    assert "OFFLINE_CERTIFICATE_PAYLOAD" not in json.dumps(result)


def test_conflicting_native_good_and_expired_utc_date_keep_both_evidence():
    data = basic_data()
    data["certificates"] = [{"uuid": "cert-1", "certificate": {"not_after": "2000-01-01T00:00:00Z", "expiry_status": "SSL_CERTIFICATE_GOOD", "days_until_expire": 3650}}]
    result, _ = run(data)
    item = check(result, "AVI-A5:cert-1")
    assert item["status"] == "abnormal"
    assert item["values"]["metadata"]["expiry_status"] == "SSL_CERTIFICATE_GOOD"
    assert item["values"]["metadata"]["days_until_expire"] == 3650
    assert item["values"]["evidence_differences"][0]["utc_date_evidence"] == "expired"


def test_memory_x509_utc_validity_confirms_unzoned_calendar_without_overwriting_native_days():
    data = basic_data()
    pem = structural_certificate()
    data["certificates"] = [{"uuid": "cert-1", "certificate": {"not_before": "2024-01-01 00:00:00", "not_after": "2036-09-20 09:51:14",
        "days_until_expire": 365, "expiry_status": "SSL_CERTIFICATE_GOOD", "certificate": pem}}]
    result, _ = run(data)
    item = check(result, "AVI-A5:cert-1")
    assert item["status"] == "normal" and item["judgement"] == "PROGRAM"
    assert item["values"]["x509_validity"]["expires_at"] == "2036-09-20T09:51:14+00:00"
    assert len(item["values"]["x509_validity"]["certificate_sha256"]) == 64
    assert item["values"]["date_interpretation"]["timezone"] == "unknown"
    assert item["values"]["date_interpretation"]["utc_evidence_source"] == "x509_der_validity"
    assert item["values"]["metadata"]["not_after"] == "2036-09-20 09:51:14"
    assert item["values"]["metadata"]["days_until_expire"] == 365
    assert any(d["field"] == "days_until_expire" for d in item["values"]["evidence_differences"])
    assert not any(d["field"] in {"not_before", "not_after"} for d in item["values"]["evidence_differences"])
    assert pem not in json.dumps(result) and "BEGIN CERTIFICATE" not in json.dumps(result)


def test_memory_x509_expiry_cannot_be_overridden_by_future_unzoned_native_good():
    data = basic_data()
    pem = structural_certificate(end=b"250101000000Z")
    data["certificates"] = [{"uuid": "cert-1", "certificate": {"not_before": "2024-01-01 00:00:00", "not_after": "2036-09-20 09:51:14",
        "days_until_expire": 3650, "expiry_status": "SSL_CERTIFICATE_GOOD", "certificate": pem}}]
    result, _ = run(data)
    item = check(result, "AVI-A5:cert-1")
    assert item["status"] == "abnormal"
    assert item["values"]["x509_validity"]["expired"] is True
    assert item["values"]["metadata"]["not_after"] == "2036-09-20 09:51:14"
    assert item["values"]["metadata"]["expiry_status"] == "SSL_CERTIFICATE_GOOD"
    assert {d["field"] for d in item["values"]["evidence_differences"]} >= {"not_after", "days_until_expire", "expiry_status"}
    assert "BEGIN CERTIFICATE" not in json.dumps(result)


def test_observed_cluster_service_states_are_projected_without_claiming_criticality():
    data = basic_data()
    data["cluster_runtime"]["service_states"] = [{"name": "apiserver", "state": "CLUSTER_ACTIVE", "roles": ["SERVICE_ROLE_LEADER"],
        "cluster_nodes": [{"name": "node", "ip": {"addr": "192.0.2.109", "type": "V4"}}], "detailed_state": [{}, {}], "private_key": KEY}]
    result, _ = run(data)
    item = check(result, "AVI-A2:services")
    assert item["values"]["reported_count"] == 1 and item["completeness"] == "partial"
    assert "critical_service_role_applicability" in item["values"]["missing_required_fields"]
    assert item["status"] == "insufficient_data" and item["values"]["critical_service_scope_confirmed"] is False
    assert item["values"]["services"][0]["criticality"] == "unknown"
    assert item["values"]["services"][0]["cluster_nodes"][0]["ip"] == "192.0.2.109"
    assert item["sources"][0]["path"] == "/api/cluster/runtime"
    assert item["values"]["management_evidence_gap"]["classification"] == "projection_omission"
    assert item["values"]["management_evidence_gap"]["resolved"] is True
    assert KEY not in json.dumps(result)


def test_metadata_only_metric_reply_is_current_window_evidence_not_unsupported():
    data = basic_data()
    data["controller_metrics"] = lambda query, params: {"metric_id": query["metric_id"], "start": query["start"], "stop": query["stop"], "step": 60, "limit": 15, "entity_uuid": params["uuid"], "metric_entity": "CONTROLLER_METRICS_ENTITY"}
    result, _ = run(data)
    item = check(result, "AVI-A3")
    assert item["values"]["metrics"] == [] and item["status"] == "insufficient_data"
    evidence = item["values"]["metric_response_evidence"][0]
    assert evidence["series_count"] == 0 and evidence["returned_point_count"] == 0
    assert evidence["classification"] == "metadata_only_no_samples_in_requested_window"
    assert evidence["reason_verified"] is False
    assert "controller_resource_samples" in item["values"]["missing_required_fields"]


def reference_data():
    data = business_data()
    data["pools"][0].update(health_monitor_refs=["/api/healthmonitor/hm-used"], ssl_profile_ref="/api/sslprofile/tls-1")
    data["system"][0]["portal_configuration"]["sslprofile_ref"] = "/api/sslprofile/tls-portal"
    data["health_monitors"] = [{"uuid": "hm-used", "name": "System-user-created", "type": "HEALTH_MONITOR_HTTP"}, {"uuid": "hm-unused", "name": "custom-unused", "type": "HEALTH_MONITOR_HTTP"}]
    data["ssl_profiles"] = [{"uuid": "tls-1", "name": "System-business", "type": "SSL_PROFILE_TYPE_APPLICATION"}, {"uuid": "tls-portal", "name": "portal", "type": "SSL_PROFILE_TYPE_SYSTEM"}]
    return data


def test_real_references_not_names_classify_monitor_and_tls_usages():
    result, _ = run(reference_data())
    used = check(result, "AVI-C7:hm-used")["values"]
    unused = check(result, "AVI-C7:hm-unused")["values"]
    assert used["reference_state"] == "referenced" and used["origin_status"] == "unknown"
    assert used["usages"][0]["source_id"] == "pool-1"
    assert used["usages"][0]["usage"] == "pool_health_monitor"
    assert unused["reference_state"] == "unreferenced_in_complete_selected_scope"
    assert unused["origin_status"] == "unknown"
    assert check(result, "AVI-C7:hm-used")["status"] == "insufficient_data"
    profiles = {o["object_id"]: o["values"] for o in result["inventory"] if o["object_type"] == "ssl_profile"}
    assert {u["usage"] for u in profiles["tls-1"]["usages"]} == {"pool_tls", "virtual_service_tls"}
    assert profiles["tls-portal"]["usages"][0]["usage"] == "management_portal"
    assert profiles["tls-portal"]["origin_status"] == "unknown"
    assert profiles["tls-portal"]["type"] == "SSL_PROFILE_TYPE_SYSTEM"
    assert all(u["collected_at"] and u["configuration_only"] is True for p in profiles.values() for u in p["usages"])
    assert check(result, "AVI-C5:pool-1")["values"]["ssl_profile"]["uuid"] == "tls-1"


def test_incomplete_or_rejected_parent_references_never_claim_unused():
    data = reference_data()
    result, _ = run(data, incomplete={"pools": {"kind": "budget", "reason": "offline partial", "stage": "pagination"}})
    assert check(result, "AVI-C7:hm-unused")["values"]["reference_state"] == "unknown_partial_scope"
    assert check(result, "AVI-C7:hm-used")["values"]["usages"][0]["reference_completeness"] == "partial"
    data["pools"][0]["health_monitor_refs"] = ["https://outside.invalid/api/healthmonitor/hm-used"]
    result, fake = run(data)
    assert check(result, "AVI-C7:hm-unused")["values"]["reference_state"] == "unknown_partial_scope"
    assert "pools" in result["coverage"]["reference_scope"]["rejected_parent_source_keys"]
    assert "outside.invalid" not in json.dumps(result)


def test_same_der_certificate_keeps_aliases_and_all_confirmed_configured_usages():
    data = basic_data()
    cert = {"certificate": structural_certificate(), "expiry_status": "SSL_CERTIFICATE_GOOD"}
    data["certificates"] = [{"uuid": "cert-1", "name": "portal", "certificate": cert}, {"uuid": "cert-2", "name": "channel", "certificate": cert}]
    data["system"][0]["secure_channel_configuration"] = {"sslkeyandcertificate_refs": ["/api/sslkeyandcertificate/cert-2"]}
    result, _ = run(data)
    one, two = check(result, "AVI-A5:cert-1"), check(result, "AVI-A5:cert-2")
    assert one["object_id"] == "cert-1" and two["object_id"] == "cert-2"
    assert one["values"]["identity"]["certificate_sha256"] == two["values"]["identity"]["certificate_sha256"]
    assert {a["object_id"] for a in one["values"]["identity"]["aliases"]} == {"cert-1", "cert-2"}
    assert {u["usage"] for u in one["values"]["usages"]} == {"management_portal", "management_secure_channel"}
    assert "BEGIN CERTIFICATE" not in json.dumps(result)


def test_management_gaps_keep_not_implemented_distinct_from_actual_permission_denial():
    result, _ = run()
    gaps = {g["check_id"]: g for g in result["coverage"]["management_data_gaps"]}
    assert gaps["AVI-A3"]["classification"] == "not_implemented"
    assert gaps["AVI-A6"]["source_status"] == "source_unverified"
    assert gaps["AVI-A7"]["source_status"] == "confirmed_sources_do_not_supply_result_fields"
    result, _ = run(failures={"license_status": CollectionError("permission", "offline denied", http_status=403)})
    assert check(result, "AVI-A6")["values"]["management_evidence_gap"]["classification"] == "permission_denied"
