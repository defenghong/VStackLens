"""Independent Controller scope expectations; no device connections or credentials."""
from __future__ import annotations

from copy import deepcopy
import json
import pytest

import test_product_avi as fixtures
from vstacklens.products import avi
from vstacklens.products.management_scope import alarm_lifecycle_of, module_scope
from vstacklens.products.model import SessionCredential
from vstacklens.products.transport import CollectionError, Route


EXPECTED_ROUTES = {"version", "tenants", "cluster_runtime", "system", "alerts", "certificate_details", "license_status", "license_ledger", "backup_config", "schedulers", "backups", "syslog", "controller_metrics", "clouds"}
BUSINESS_ROUTES = {"certificates", "cloud_runtime", "cloud_status", "ses", "se_inventory", "se_groups", "se_group_runtime", "virtual_services", "vs_inventory", "vsvips", "application_profiles", "network_profiles", "pools", "pool_inventory", "server_runtime", "health_monitors", "ssl_profiles", "se_metrics", "vs_metrics"}


class ControllerOnlyTransport(fixtures.FakeTransport):
    def __init__(self, data, routes, **kwargs):
        super().__init__(data, **kwargs)
        self.allowed = set(routes)
        self.attempted = []
        assert self.allowed <= EXPECTED_ROUTES
        assert not self.allowed & BUSINESS_ROUTES

    def get(self, key, path_params=None, query=None):
        self.attempted.append(key)
        assert key in self.allowed
        if key == "certificate_details":
            self.calls.append(("GET", key, deepcopy(path_params), deepcopy(query)))
            if key in self.failures:
                raise self.failures[key]
            override = self.data.get("certificate_item_overrides", {}).get(path_params["uuid"])
            if isinstance(override, dict) and "offline_error_kind" in override:
                raise CollectionError(override["offline_error_kind"], "offline certificate denied", http_status=override.get("offline_http_status"))
            if override is not None:
                return deepcopy(override)
            return deepcopy(next(c for c in self.data["certificates"] if c["uuid"] == path_params["uuid"]))
        return super().get(key, path_params, query)

    def list_pages(self, key, kind="avi", query=None, path_params=None):
        self.attempted.append(key)
        assert key in self.allowed
        return super().list_pages(key, kind, query, path_params)


def manager_run(data=None, **kwargs):
    created = []
    payload = fixtures.basic_data() if data is None else data
    def factory(target, credential, routes, **options):
        transport = ControllerOnlyTransport(payload, routes, **kwargs)
        created.append(transport)
        return transport
    module = avi.collect_avi(fixtures.target(), SessionCredential("offline-user", "OFFLINE-MANAGER-ONLY-KEY"), transport_factory=factory, cancel_requested=kwargs.get("cancel_requested"))
    return module, created[0]


def check(module, cid):
    return next(c for c in module["checks"] if c["check_id"] == cid)


def test_default_controller_acquires_no_business_api_or_placeholder():
    data = fixtures.business_data()
    data["health_monitors"] = [{"uuid": "business-monitor", "name": "business"}]
    data["se_groups"] = [{"uuid": "business-se-group"}]
    module, transport = manager_run(data)
    assert module_scope(module).scope_id == "management-v1"
    assert set(transport.attempted) <= EXPECTED_ROUTES
    assert not set(transport.attempted) & BUSINESS_ROUTES
    assert not any(c["check_id"].startswith(tuple("AVI-C" + str(n) for n in range(2, 10))) for c in module["checks"])
    assert not any(o["object_type"] in {"service_engine", "service_engine_group", "virtual_service", "pool", "health_monitor", "ssl_profile"} for o in module["inventory"])
    assert not any("pool." in f or "virtualservice." in f for f in module["coverage"]["reference_scope"]["relationship_fields"])
    assert module["verified_pass_count"] == 0


@pytest.mark.parametrize("requested", ["legacy", "full", "historical-unscoped", "business-v1"])
def test_nonmanagement_collection_scope_rejected_before_factory_or_login(requested):
    created = []
    def factory(*args, **kwargs):
        created.append(True)
        raise AssertionError("factory must never be reached")
    with pytest.raises(ValueError):
        avi.collect_avi(fixtures.target(), SessionCredential("offline", "offline"), inspection_scope=requested, transport_factory=factory)
    assert not created


@pytest.mark.parametrize("native,lifecycle,status", [("ALERT_STATE_ON", "active", "attention"), ("ALERT_STATE_OFF", "cleared", "normal"), ("UNRECOGNIZED", "unknown", "insufficient_data"), (None, "unknown", "insufficient_data")])
def test_native_alert_lifecycle_preserves_state_level_and_event_time(native, lifecycle, status):
    data = fixtures.basic_data()
    alert = {"uuid": "alert-test", "level": "ALERT_HIGH", "timestamp": 1700000000, "summary": "offline native description"}
    if native is not None:
        alert["state"] = native
    data["alerts"] = [alert]
    module, _ = manager_run(data)
    record = module["native_alerts"][0]
    assert record["lifecycle"] == lifecycle == alarm_lifecycle_of("avi", record)
    assert record.get("state") == native and record["level"] == "ALERT_HIGH" and record["timestamp"] == 1700000000
    assert record["collected_at"]
    assert check(module, "AVI-A4")["status"] == status
    assert check(module, "AVI-A4")["values"]["cleared_count_in_collected"] == (1 if lifecycle == "cleared" else 0)


def test_mixed_alerts_only_active_counts_as_current_and_unknown_not_cleared():
    data = fixtures.basic_data()
    data["alerts"] = [{"uuid": str(i), "state": state, "level": "ALERT_MEDIUM", "timestamp": i} for i, state in enumerate(("ALERT_STATE_ON", "ALERT_STATE_OFF", "OTHER"))]
    module, _ = manager_run(data)
    values = check(module, "AVI-A4")["values"]
    assert values["active_count_in_collected"] == values["cleared_count_in_collected"] == values["unknown_state_count"] == 1
    assert {a["state"] for a in module["native_alerts"]} == {"ALERT_STATE_ON", "ALERT_STATE_OFF", "OTHER"}


def test_permission_and_cancellation_keep_scope_and_do_not_fall_back_to_business():
    module, transport = manager_run(failures={"alerts": CollectionError("permission", "offline denied", http_status=403)})
    assert check(module, "AVI-A4")["status"] == "permission_denied"
    assert "system" in transport.attempted and not set(transport.attempted) & BUSINESS_ROUTES
    module, transport = manager_run(cancel_requested=lambda: True)
    assert transport.closed and not transport.attempted
    assert all(c["status"] == "cancelled" for c in module["checks"])
    assert module_scope(module).scope_id == "management-v1"


def test_authentication_failure_retains_only_management_diagnostics():
    module, transport = manager_run(auth_error=CollectionError("authentication", "offline authentication rejected", http_status=401, stage="login"))
    assert not transport.attempted and transport.closed
    assert check(module, "AVI-LOGIN")["status"] == "collection_failed"
    assert module_scope(module).scope_id == "management-v1"
    assert not any(c["status"] in {"normal", "not_deployed"} for c in module["checks"])


def test_missing_management_fields_remain_partial_without_business_fallback():
    data = fixtures.basic_data()
    data["system"] = {"uuid": "system"}
    data["cluster_runtime"]["service_states"] = [{"name": "registered-without-state"}]
    module, transport = manager_run(data)
    assert check(module, "AVI-A8")["status"] == "insufficient_data"
    assert check(module, "AVI-A8")["completeness"] == "partial"
    service = check(module, "AVI-A2:services")
    assert service["completeness"] == "partial" and service["values"]["native_state_counts"] == {"未返回": 1}
    assert "certificates" not in transport.attempted and not set(transport.attempted) & BUSINESS_ROUTES


def test_manager_certificate_unverified_source_does_not_list_all_certificates(monkeypatch):
    monkeypatch.delitem(avi.ROUTES, "certificate_details", raising=False)
    data = fixtures.basic_data()
    data["certificates"].append({"uuid": "unrelated-business-cert", "name": "business"})
    module, transport = manager_run(data)
    assert "certificates" not in transport.attempted and "certificate_details" not in transport.attempted
    assert check(module, "AVI-A5")["status"] == "insufficient_data"
    assert check(module, "AVI-A5")["values"]["details_source_status"] == "source_unverified"


def test_verified_static_item_reader_only_requests_management_bound_ids(monkeypatch):
    # A route fixture tests item-only enforcement, not real-version support.
    monkeypatch.setitem(avi.ROUTES, "certificate_details", Route("/api/sslkeyandcertificate/{uuid}", "offline verified route fixture", "offline_replay", ("fields",)))
    data = fixtures.basic_data()
    data["certificates"].append({"uuid": "unrelated-business-cert", "name": "business"})
    module, transport = manager_run(data)
    requested = [c[2]["uuid"] for c in transport.calls if c[1] == "certificate_details"]
    assert requested == ["cert-1"] and "certificates" not in transport.attempted
    assert [o["object_id"] for o in module["inventory"] if o["object_type"] == "certificate"] == ["cert-1"]
    assert check(module, "AVI-A5:cert-1")["values"]["reference_scope"]["parent_sources"] == ["system"]


def test_individual_management_certificate_denial_does_not_hide_another_object():
    data = fixtures.basic_data()
    data["certificates"].append({"uuid": "cert-2", "certificate": {"not_after": "2049-01-01T00:00:00Z"}})
    data["system"][0]["secure_channel_configuration"] = {"sslkeyandcertificate_refs": ["/api/sslkeyandcertificate/cert-2"]}
    data["certificate_item_overrides"] = {"cert-1": {"offline_error_kind": "permission", "offline_http_status": 403}}
    module, transport = manager_run(data)
    assert check(module, "AVI-A5:cert-1")["status"] == "permission_denied"
    assert check(module, "AVI-A5:cert-2")["status"] == "normal"
    assert "certificates" not in transport.attempted
    assert "system" in transport.attempted and check(module, "AVI-A8")


def test_wrong_certificate_item_identity_is_not_accepted_or_replaced_from_catalog():
    data = fixtures.basic_data()
    data["certificate_item_overrides"] = {"cert-1": {"uuid": "wrong-object", "certificate": {"not_after": "2049-01-01T00:00:00Z"}}}
    module, transport = manager_run(data)
    item = check(module, "AVI-A5:cert-1")
    assert item["status"] == "collection_failed" and item["completeness"] == "partial"
    assert not any(o["object_type"] == "certificate" for o in module["inventory"])
    assert "certificates" not in transport.attempted


def test_external_management_certificate_reference_is_not_followed_or_replaced():
    data = fixtures.basic_data()
    data["system"][0]["portal_configuration"]["sslkeyandcertificate_refs"] = ["https://outside.invalid/api/sslkeyandcertificate/cert-1"]
    module, transport = manager_run(data)
    assert "certificate_details" not in transport.attempted and "certificates" not in transport.attempted
    assert check(module, "AVI-A5")["status"] == "insufficient_data"
    assert module["coverage"]["reference_scope"]["rejected_parent_source_keys"] == ["system"]


@pytest.mark.parametrize("rejected", [["https://outside.invalid/api/sslkeyandcertificate/cert-2"], "unverified-reference-shape", ["/api/sslkeyandcertificate/cert-1"] * 201])
def test_valid_and_rejected_management_bindings_keep_explicit_partial_coverage(rejected):
    data = fixtures.basic_data()
    data["system"][0]["secure_channel_configuration"] = {"sslkeyandcertificate_refs": rejected}
    module, transport = manager_run(data)
    assert check(module, "AVI-A5:cert-1")["status"] == "normal"
    gap = check(module, "AVI-A5:bindings")
    assert gap["status"] == "insufficient_data" and gap["completeness"] == "partial"
    assert gap["values"]["missing_required_fields"] == ["management_certificate_binding_coverage"]
    certificate = check(module, "AVI-A5:cert-1")["values"]
    assert certificate["reference_scope"]["complete"] is False
    assert all(u["reference_completeness"] == "partial" for u in certificate["usages"])
    requested = [c[2]["uuid"] for c in transport.calls if c[1] == "certificate_details"]
    assert requested == ["cert-1"] and "certificates" not in transport.attempted
    assert "outside.invalid" not in json.dumps(module)


def test_cloud_configuration_only_never_claims_vcenter_connection():
    data = fixtures.basic_data()
    data["clouds"] = [{"uuid": "cloud-test", "name": "configured", "vtype": "CLOUD_VCENTER", "vcenter_configuration": {"password": "SHOULD-NOT-PERSIST"}}]
    module, transport = manager_run(data)
    values = check(module, "AVI-C1")["values"]
    assert values["configured_clouds"][0]["vtype"] == "CLOUD_VCENTER"
    assert values["connection_verified"] is False
    assert not {"cloud_runtime", "cloud_status"} & set(transport.attempted)
    cloud_call = next(c for c in transport.calls if c[1] == "clouds")
    assert cloud_call[3]["fields"] == "uuid,name,vtype,tenant_ref"
    assert check(module, "AVI-C1")["sources"][0]["fields"] == ["uuid", "name", "vtype", "tenant_ref"]
    assert "SHOULD-NOT-PERSIST" not in json.dumps(module)


def test_zero_valid_points_are_missing_samples_even_when_series_record_exists():
    data = fixtures.basic_data()
    data["controller_metrics"] = lambda query, params: {"series": [{"header": {"name": "controller_stats.avg_cpu_usage"}, "data": [{"timestamp": "invalid", "value": 10}]}]}
    module, _ = manager_run(data)
    item = check(module, "AVI-A3")
    assert item["values"]["metrics"] and item["values"]["metrics"][0]["returned_sample_count"] == 0
    assert "controller_resource_samples" in item["values"]["missing_required_fields"]
    assert "已取得" not in item["summary"]


@pytest.mark.parametrize("response,expected", [(None, "no_response_or_request_failed"), ({"other": []}, "unknown_response_shape"), ({"metric_id": "controller_stats.avg_cpu_usage", "start": "2026-01-01T00:00:00Z"}, "metadata_only_no_samples_in_requested_window"), ({"series": []}, "empty_series_in_requested_window"), ({"series": "invalid"}, "unverified_series_shape")])
def test_metric_evidence_does_not_convert_failure_or_unknown_shape_to_empty_data(response, expected):
    assert avi._metric_evidence(response)["classification"] == expected


def test_registered_services_preserve_native_state_without_critical_running_claim():
    data = fixtures.basic_data()
    data["cluster_runtime"]["service_states"] = [{"name": "optional-service", "state": "CLUSTER_ACTIVE", "roles": ["SERVICE_ROLE_LEADER"], "cluster_nodes": []}]
    module, _ = manager_run(data)
    item = check(module, "AVI-A2:services")
    assert item["values"]["services"][0]["state"] == "CLUSTER_ACTIVE"
    assert item["values"]["services"][0]["criticality"] == "unknown"
    assert item["values"]["critical_service_scope_confirmed"] is False
    assert item["completeness"] == "partial" and item["status"] == "insufficient_data"


def test_combined_metric_echo_does_not_hide_valid_named_controller_series():
    data = fixtures.basic_data()
    def reply(query, params):
        return {"metric_id": query["metric_id"], "series": [{"header": {"name": "controller_stats.avg_cpu_usage"}, "data": [{"timestamp": query["stop"], "value": 9.5}]},
                                                            {"header": {"name": "se_stats.avg_cpu_usage"}, "data": [{"timestamp": query["stop"], "value": 99}]}]}
    data["controller_metrics"] = reply
    module, _ = manager_run(data)
    metrics = check(module, "AVI-A3")["values"]["metrics"]
    assert [m["metric_id"] for m in metrics] == ["controller_stats.avg_cpu_usage"]
    assert metrics[0]["samples"][0]["value"] == 9.5


def test_unknown_single_series_object_is_not_promoted_to_valid_samples():
    data = fixtures.basic_data()
    data["controller_metrics"] = lambda query, params: {"series": {"header": {"name": "controller_stats.avg_cpu_usage"}, "data": [{"timestamp": query["stop"], "value": 10}]}}
    module, _ = manager_run(data)
    values = check(module, "AVI-A3")["values"]
    assert values["metrics"] == []
    assert values["metric_response_evidence"][0]["classification"] == "unverified_series_shape"
