from __future__ import annotations

import base64
import copy
import json
import re

import pytest

from vstacklens.products.model import SessionCredential, TargetRef
from vstacklens.products.nsx import CHECK_MATRIX, ROUTES, InstanceSpec, _certificate_dates, _replay_legacy_nsx, collect_nsx
from vstacklens.products.transport import CollectionError, ReadTransport


def target():
    return TargetRef("nsx-target", "nsx", "customer-one", "site-one", "实验NSX", "192.0.2.11")


def _spec(policy=False):
    base = "/policy/api/v1" if policy else "/api/v1"
    paths = {}
    for key, route in ROUTES.items():
        if key.endswith("_spec") or route.path.startswith("/policy/") != policy:
            continue
        path = route.path.removeprefix(base)
        # Template variable names may differ between our allowlist and Swagger.
        path = path.replace("{node_id}", "{cluster-node-id}")
        paths[path] = {"get": {"parameters": [{"name": name, "in": "query"} for name in route.query_parameters]}}
    return {"swagger": "2.0", "basePath": base, "info": {"version": "4.2.3.0.0"}, "paths": paths}


def _tlv(tag, value):
    length = bytes([len(value)]) if len(value) < 128 else b"\x81" + bytes([len(value)])
    return bytes([tag]) + length + value


def cert():
    # Minimal structural X.509 fixture: the adapter reads only the validity TLVs.
    validity = _tlv(0x30, _tlv(0x17, b"240101000000Z") + _tlv(0x17, b"490101000000Z"))
    body = _tlv(0x02, b"\x01") + _tlv(0x30, b"") + _tlv(0x30, b"") + validity
    encoded = base64.b64encode(_tlv(0x30, _tlv(0x30, body))).decode()
    return "-----BEGIN CERTIFICATE-----\n" + encoded + "\n-----END CERTIFICATE-----"


def payloads():
    return {
        "manager_spec": _spec(), "policy_spec": _spec(True),
        "node": {"product_version": "4.2.3.0.0.24866349", "node_uuid": "manager-01", "hostname": "lab-manager", "node_type": "NSX Manager"},
        "cluster": {"cluster_id": "cluster-01"},
        "cluster_status": {"mgmt_cluster_status": {"status": "STABLE", "online_nodes": [{"uuid": "manager-01"}]}},
        "nodes": {"results": [{"id": "manager-01", "display_name": "single-manager", "manager_role": {"api_listen_addr": {"certificate": cert()}}}], "result_count": 1},
        "cluster_certificate": {"certificate_id": ""},
        "node_runtime": {"mgmt_cluster_status": {"mgmt_cluster_status": "CONNECTED"}},
        "node_resources": {"cpu_cores": 4, "mem_total": 12000, "mem_used": 4000, "uptime": 90000,
                           "file_systems": [{"file_system": "/dev/sda", "mount": "/", "total": 100000, "used": 2000}]},
        "services": {"results": [{"service_name": "node-mgmt"}]},
        "service_node_mgmt": {"health": "HEALTHY", "runtime_state": "RUNNING"},
        "alarms": {"results": []},
        "licenses": {"results": [{"description": "Evaluation", "is_expired": False, "license_key": "SHOULD-NOT-PERSIST"}]},
        "backup": {"backup_config": {"backup_enabled": False}},
        "dns": {"name_servers": ["192.0.2.53"]}, "search_domains": {"search_domains": ["lab.invalid"]},
        "ntp": {"service_properties": {"servers": ["192.0.2.123"], "start_on_boot": True}},
        "ntp_status": {"runtime_state": "RUNNING"},
        "syslog": {"results": [{"exporter_name": "central", "server": "192.0.2.50", "port": 514}]},
        "syslog_status": {"runtime_state": "RUNNING"},
        "interfaces": {"results": [{"interface_id": "eth0", "admin_status": "UP", "link_status": "UP", "mtu": 1500,
                                     "interface_alias": [{"ip_address": "192.0.2.11", "ip_configuration": "STATIC"}]}]},
    }


class FakeTransport:
    verification_level = "offline_replay"

    def __init__(self, data=None, failures=None):
        self.data = copy.deepcopy(data or payloads())
        self.failures = failures or {}
        self.calls = []
        self.closed = False
        self.metrics = {"requests": 0}
        self.transport_security = {"mode": "offline_fake", "peer_identity_verified": False}
        self.secret_values = ("test-runtime-password",)

    def __call__(self, target, credential, routes, **kwargs):
        self.cancel_requested = kwargs.get("cancel_requested") or (lambda: False)
        return self

    def check_cancelled(self):
        if self.cancel_requested():
            raise CollectionError("cancelled", "已取消。")

    def get(self, key, path_params=None, query=None):
        self.calls.append((key, path_params or {}, query or {}))
        self.metrics["requests"] += 1
        if key in self.failures:
            raise self.failures[key]
        value = self.data.get(key, {"tunnels": []} if key == "tunnels" else {"results": []})
        return value(query or {}) if callable(value) else copy.deepcopy(value)

    def close(self):
        self.closed = True


def run(fake=None, **kwargs):
    fake = fake or FakeTransport()
    credential = SessionCredential("admin", "test-runtime-password")
    fake(target(), credential, ROUTES, **kwargs)
    result = _replay_legacy_nsx(target(), credential, fake)
    return result, fake


def check(module, key):
    return next(row for row in module["checks"] if row["check_id"] == "nsx." + key)


def test_single_manager_resources_dns_interfaces_and_empty_business_scope():
    result, fake = run()
    assert len(result["checks"]) == len(CHECK_MATRIX) == 20
    assert result["version"] == "4.2.3.0.0.24866349" and result["build"] == "24866349"
    for key in ("cluster", "dns", "interfaces", "certificates"):
        assert check(result, key)["status"] == "normal", (key, check(result, key))
    assert check(result, "resources")["status"] == "attention"
    assert check(result, "resources")["completeness"] == "complete"
    assert check(result, "backup")["status"] == "attention"
    assert check(result, "vcenter")["status"] == "not_deployed"
    assert check(result, "hosts")["status"] == "not_deployed"
    assert check(result, "edge")["status"] == "not_deployed"
    assert result["verified_pass_count"] == 0
    assert check(result, "resources")["verification"] == "offline_replay"
    assert fake.closed
    assert not any("action" in route.path or "?" in route.path for route in ROUTES.values())


def test_static_allowlist_can_be_constructed_without_network():
    transport = ReadTransport(target(), SessionCredential("admin", "hidden"), ROUTES)
    transport.close()


def test_basepath_parameter_refs_and_template_names():
    document = _spec()
    document["parameters"] = {"cursor": {"name": "cursor", "in": "query"}}
    document["paths"]["/alarms"]["get"]["parameters"] = [{"$ref": "#/parameters/cursor"}]
    spec = InstanceSpec(document)
    assert spec.supports(ROUTES["node_resources"])
    assert spec.parameter(ROUTES["alarms"], "cursor")
    assert not spec.parameter(ROUTES["alarms"], "action")
    oas = InstanceSpec({"openapi": "3.0.0", "servers": [{"url": "/api/v1"}], "paths": {"/node": {"get": {}}}})
    assert oas.supports(ROUTES["node"])


@pytest.mark.parametrize("bad", ["not-json", {"swagger": "2.0", "paths": []}, {"swagger": "2.0", "paths": {}, "basePath": "https://other.invalid"}])
def test_invalid_spec_is_parse_failure_and_never_operational_calls(bad):
    fake = FakeTransport()
    fake.data["manager_spec"] = bad
    result, fake = run(fake)
    assert not any(key == "node" for key, _, _ in fake.calls)
    assert check(result, "version")["status"] == "collection_failed"
    assert any(row["kind"] == "invalid_response" for row in result["errors"])


def test_missing_route_is_unsupported_without_guessing_dns_or_any_alternative():
    fake = FakeTransport()
    del fake.data["manager_spec"]["paths"]["/cluster/{cluster-node-id}/node/network/name-servers"]
    result, fake = run(fake)
    assert check(result, "dns")["status"] == "insufficient_data"  # search-domain read still succeeds
    assert any(row["kind"] == "unsupported" for row in check(result, "dns")["errors"])
    assert not any(key == "dns" for key, _, _ in fake.calls)
    assert check(result, "resources")["status"] == "attention"


def test_unknown_alarm_and_interface_and_missing_resource_fields_never_normal():
    fake = FakeTransport()
    fake.data["alarms"] = {"results": [{"severity": "MEDIUM", "description": "test-runtime-password license_key=hidden-value"}]}
    fake.data["interfaces"]["results"][0]["link_status"] = "UNKNOWN"
    fake.data["node_resources"] = {"cpu_cores": 4}
    result, _ = run(fake)
    for key in ("alarms", "interfaces", "resources"):
        assert check(result, key)["status"] == "insufficient_data"
    assert result["native_alerts"][0]["severity"] == "MEDIUM"
    assert "P2" not in json.dumps(result)
    assert "test-runtime-password" not in json.dumps(result)


def test_partial_permission_failure_keeps_unrelated_checks():
    result, _ = run(FakeTransport(failures={"licenses": CollectionError("permission", "读取权限不足。", http_status=403)}))
    assert check(result, "licenses")["status"] == "permission_denied"
    assert check(result, "dns")["status"] == "normal"
    assert check(result, "licenses")["errors"][0]["http_status"] == 403


def test_pagination_partial_rows_survive_and_repeated_cursor_is_incomplete():
    fake = FakeTransport()
    fake.data["alarms"] = lambda query: {"results": [{"id": "alarm-" + (query.get("cursor") or "first"), "status": "OPEN", "severity": "MEDIUM"}], "cursor": "repeat", "result_count": 4}
    result, fake = run(fake)
    assert len(result["native_alerts"]) == 2
    assert check(result, "alarms")["status"] == "attention"
    assert check(result, "alarms")["completeness"] == "partial"
    assert len([key for key, _, _ in fake.calls if key == "alarms"]) == 2


def test_authentication_failure_and_cancellation_stop_new_network_calls():
    fake = FakeTransport(failures={"node": CollectionError("authentication", "身份校验失败。", http_status=401)})
    result, fake = run(fake)
    assert [row[0] for row in fake.calls] == ["manager_spec", "policy_spec", "node"]
    assert check(result, "version")["status"] == "collection_failed"
    cancelled, fake = run(cancel_requested=lambda: True)
    assert not fake.calls
    assert all(row["status"] == "cancelled" for row in cancelled["checks"])


def test_non423_version_stops_after_identity_read_and_keeps_actual_version():
    fake = FakeTransport()
    fake.data["node"]["product_version"] = "4.3.0"
    result, fake = run(fake)
    assert result["version"] == "4.3.0"
    assert check(result, "version")["status"] == "attention"
    assert [row[0] for row in fake.calls] == ["manager_spec", "policy_spec", "node"]


def test_backup_success_missing_is_insufficient_and_components_not_conflated():
    fake = FakeTransport()
    fake.data["backup"] = {"backup_config": {"backup_enabled": True, "backup_schedule": {"hour": 3}},
                           "backup_operation_history": {"cluster_backup_statuses": [{"end_time": 10, "success": True}],
                                                        "node_backup_statuses": [{"end_time": 20}]}}
    result, _ = run(fake)
    row = check(result, "backup")
    assert row["status"] == "insufficient_data"
    assert row["values"]["latest_success"]["component"] == "cluster_backup_statuses"
    assert row["values"]["restore_verified"] is False


def test_certificate_dates_no_pem_or_license_key_in_any_result():
    assert _certificate_dates(cert())["expires_at"].startswith("2049")
    assert re.fullmatch(r"[0-9a-f]{64}", _certificate_dates(cert())["certificate_sha256"])
    result, _ = run()
    text = json.dumps(result, ensure_ascii=False)
    assert "BEGIN CERTIFICATE" not in text
    assert "SHOULD-NOT-PERSIST" not in text
    assert "test-runtime-password" not in text
    assert check(result, "certificates")["sources"]


def test_populated_business_objects_are_projected_and_never_marked_business_verified():
    fake = FakeTransport()
    fake.data["transport_nodes"] = {"results": [{"id": "host-01", "node_deployment_info": {"resource_type": "HostNode"}, "password": "unwanted"}]}
    fake.data["transport_status"] = {"status": "DOWN", "mgmt_connection_status": "DOWN", "node_status": {"software_version": "4.2.3"}}
    fake.data["segments"] = {"results": [{"id": "segment-01", "display_name": "业务网段", "admin_state": "UP"}]}
    fake.data["segment_ports"] = {"results": [{"id": "port-01", "attachment": {"id": "vm-vif", "type": "VIF"}}]}
    fake.data["port_status"] = {"status": "UP"}
    fake.data["realized_status"] = {"consolidated_status": {"consolidated_status": "SUCCESS"}}
    result, fake = run(fake)
    assert check(result, "hosts")["status"] == "abnormal"
    assert check(result, "segments")["status"] == "normal"
    assert check(result, "segments")["verification"] == "offline_replay"
    assert "待真实业务验收" in "".join(check(result, "segments")["limitations"])
    assert "unwanted" not in json.dumps(result)
    assert all(key in ROUTES for key, _, _ in fake.calls)


def test_gateway_nat_firewall_bgp_and_reference_objects_are_covered():
    fake = FakeTransport()
    fake.data.update({
        "t0": {"results": [{"id": "gw-01", "ha_mode": "ACTIVE_STANDBY"}]},
        "t0_state": {"tier0_state": {"state": "in_sync"}},
        "t0_static_routes": {"results": [{"id": "default-route", "network": "0.0.0.0/0", "next_hops": [{"ip_address": "192.0.2.1"}]}]},
        "t0_locales": {"results": [{"id": "locale-01", "edge_cluster_path": "/infra/sites/default/enforcement-points/default/edge-clusters/ec-01"}]},
        "t0_interfaces": {"results": [{"id": "uplink-01", "mtu": 1500}]},
        "bgp_neighbors": {"results": [{"id": "neighbor-01", "neighbor_address": "192.0.2.1", "remote_as_num": "65001"}]},
        "bgp_status": {"results": [{"neighbor_address": "192.0.2.1", "connection_status": "DOWN"}]},
        "t0_nat": {"results": [{"id": "USER"}]},
        "t0_nat_rules": {"results": [{"id": "nat-01", "enabled": True, "action": "SNAT", "source_network": "10.0.0.0/24", "translated_network": "192.0.2.20"}]},
        "domains": {"results": [{"id": "default"}]},
        "groups": {"results": [{"id": "group-01", "expression": [{"resource_type": "IPAddressExpression", "ip_addresses": ["10.0.0.1"]}]}]},
        "security_policies": {"results": [{"id": "dfw-01", "scope": ["ANY"]}]},
        "security_rules": {"results": [{"id": "allow-01", "action": "ALLOW", "disabled": False, "source_groups": ["ANY"], "destination_groups": ["/infra/domains/default/groups/group-01"], "services": ["ANY"]}]},
        "gateway_policies": {"results": [{"id": "gfw-01", "scope": ["/infra/tier-0s/gw-01"]}]},
        "gateway_rules": {"results": []},
        "realized_status": {"consolidated_status": {"consolidated_status": "SUCCESS"}},
    })
    result, fake = run(fake)
    assert check(result, "gateways")["status"] == "abnormal"
    assert check(result, "nat")["status"] == "attention"
    assert check(result, "nat")["values"]["rules"][0]["translated_network"] == "192.0.2.20"
    security = check(result, "security")
    assert security["status"] == "attention"
    assert security["values"]["policies"][0]["rules"][0]["manual_review"] is True
    assert security["values"]["referenced_groups"][0]["expressions"][0]["ip_addresses"] == ["10.0.0.1"]
    assert result["verified_pass_count"] == 0


def test_cluster_bound_certificate_and_duplicate_license_text_are_sanitized():
    fake = FakeTransport()
    fake.data["cluster_certificate"] = {"certificate_id": "cluster-cert-01"}
    fake.data["certificate_details"] = {"id": "cluster-cert-01", "pem_encoded": cert(), "private_key": "RAW-PRIVATE-SECRET"}
    fake.data["licenses"]["results"][0]["description"] = "SHOULD-NOT-PERSIST"
    result, _ = run(fake)
    records = check(result, "certificates")["values"]["certificates"]
    assert any(binding.get("usage") == "management_cluster_api" for row in records for binding in row["bindings"])
    assert "SHOULD-NOT-PERSIST" not in json.dumps(result)
    assert "RAW-PRIVATE-SECRET" not in json.dumps(result)


@pytest.mark.parametrize("kind,status", [("timeout", "collection_failed"), ("unsupported", "unsupported"), ("invalid_response", "collection_failed")])
def test_each_collection_failure_has_its_own_kind_and_does_not_hide_other_data(kind, status):
    result, _ = run(FakeTransport(failures={"licenses": CollectionError(kind, "离线注入故障。", stage="license_read")}))
    assert check(result, "licenses")["status"] == status
    assert check(result, "licenses")["errors"][0]["stage"] == "license_read"
    assert check(result, "dns")["status"] == "normal"


def test_rate_limit_stops_future_calls_and_partial_data_does_not_count_as_verified_pass():
    result, fake = run(FakeTransport(failures={"alarms": CollectionError("rate_limit", "HTTP429", http_status=429)}))
    keys = [key for key, _, _ in fake.calls]
    assert keys[-1] == "alarms"
    assert check(result, "resources")["status"] == "attention"
    assert check(result, "licenses")["status"] == "collection_failed"
    assert result["verified_pass_count"] == 0


def test_offline_replay_marks_checks_and_spec_evidence_is_inside_coverage():
    fake = FakeTransport()
    fake.verification_level = "offline_replay"
    result, _ = run(fake)
    assert result["verification_level"] == "offline_replay"
    assert check(result, "version")["verification"] == "offline_replay"
    assert "interface_specifications" not in result
    assert len(result["coverage"]["interface_specifications"]) == 2
    assert result["verified_pass_count"] == 0


def test_large_spec_download_budget_is_route_local_and_skips_reference_original_failure():
    assert ROUTES["manager_spec"].timeout_seconds == 45
    assert ROUTES["policy_spec"].timeout_seconds == 45
    assert all(route.timeout_seconds is None for key, route in ROUTES.items() if not key.endswith("_spec"))
    fake = FakeTransport(failures={
        "manager_spec": CollectionError("timeout", "Response exceeded total budget", stage="body_download", http_status=200),
        "policy_spec": CollectionError("timeout", "Response exceeded total budget", stage="body_download", http_status=200),
    })
    result, fake = run(fake)
    assert [call[0] for call in fake.calls] == ["manager_spec", "policy_spec"]
    assert len(result["errors"]) == 2
    for spec in result["coverage"]["interface_specifications"]:
        error = spec["errors"][0]
        assert (error["kind"], error["stage"], error["http_status"]) == ("timeout", "body_download", 200)
    row = check(result, "version")
    assert row["status"] == "collection_failed"
    assert row["errors"][0]["stage"] == "specification_dependency"
    assert row["errors"][0]["request_attempted"] is False
    assert not row["sources"][0]["attempted"]


def test_same_leaf_certificate_is_one_validity_fact_with_both_bindings_preserved():
    fake = FakeTransport()
    fake.data["cluster_certificate"] = {"certificate_id": "cluster-cert-01"}
    fake.data["certificate_details"] = {"pem_encoded": cert()}
    result, _ = run(fake)
    row = check(result, "certificates")
    facts = row["values"]["certificates"]
    assert len(facts) == 1
    assert len(facts[0]["bindings"]) == 2
    assert {binding["usage"] for binding in facts[0]["bindings"]} == {"management_cluster_api", "manager_role.api_listen_addr"}
    assert any(binding.get("certificate_id") == "cluster-cert-01" for binding in facts[0]["bindings"])
    assert any(binding.get("node_id") == "manager-01" for binding in facts[0]["bindings"])
    assert any(source["path"] == "/api/v1/cluster/api-certificate" for source in row["sources"])
    assert any(source["path"] == "/api/v1/cluster/nodes" for source in row["sources"])


def test_one_manager_with_separate_controller_role_record_does_not_create_another_appliance():
    fake = FakeTransport()
    manager = fake.data["nodes"]["results"][0]
    fake.data["nodes"] = {"results": [{"id": "logical-controller-01", "resource_type": "ClusterNodeConfig",
        "controller_role": {"control_cluster_listen_addr": {"port": 0, "certificate": ""}}}, manager], "result_count": 2}
    fake.data["cluster_status"] = {"mgmt_cluster_status": {"status": "STABLE", "online_nodes": [{"uuid": "manager-01"}]},
        "control_cluster_status": {"status": "STABLE"},
        "detailed_cluster_status": {"cluster_id": "cluster-01", "overall_status": "STABLE", "groups": []}}
    names = ("manager", "node-mgmt", "datastore", "nsx-message-bus", "controller", "cluster_manager", "cm-inventory", "http")
    fake.data["services"] = {"results": [{"service_name": name} for name in names]}
    for name in names:
        fake.data["service_" + name.replace("-", "_")] = {"runtime_state": "stopped" if name == "nsx-message-bus" else "running"}
    result, fake = run(fake)
    cluster = check(result, "cluster")
    assert cluster["status"] == "normal"
    assert cluster["values"]["actual_deployed_count"] == 1
    assert cluster["values"]["role_configuration_count"] == 2
    assert len(cluster["values"]["role_configurations"]) == 2
    assert cluster["values"]["native_detailed_status"]["overall_status"] == "STABLE"
    assert check(result, "services")["status"] == "attention"
    bus = next(row for row in check(result, "services")["values"]["services"] if row["service"] == "nsx-message-bus")
    assert bus["runtime_state"] == "stopped" and bus["role_applicability"] == "requires_role_review"
    assert check(result, "interfaces")["status"] == "normal"
    assert check(result, "certificates")["status"] == "normal"
    assert check(result, "certificates")["values"]["unparsed_bindings"] == 0
    assert not any(params.get("node_id") == "logical-controller-01" for _, params, _ in fake.calls)
    assert len([row for row in result["inventory"] if row["object_type"] == "NSXManagerNode"]) == 1
    assert len([row for row in result["inventory"] if row["object_type"] == "NSXClusterRoleConfiguration"]) == 1


def test_confirmed_critical_service_failure_is_independent_of_native_cluster_health():
    fake = FakeTransport()
    fake.data["services"] = {"results": [{"service_name": "manager"}]}
    fake.data["service_manager"] = {"runtime_state": "stopped"}
    result, _ = run(fake)
    assert check(result, "cluster")["status"] == "normal"
    assert check(result, "services")["status"] == "abnormal"
    row = check(result, "services")["values"]["services"][0]
    assert row["role_applicability"] == "confirmed_manager_appliance"


def test_complete_empty_syslog_target_list_is_unconfigured_attention_not_unknown():
    fake = FakeTransport()
    fake.data["syslog"] = {"results": [], "result_count": 0}
    result, _ = run(fake)
    row = check(result, "syslog")
    assert row["status"] == "attention"
    assert row["completeness"] == "complete"
    assert row["values"]["remote_logging_configured_for_all_nodes"] is False
    assert row["values"]["nodes"][0]["delivery_confirmed"] is False


def test_security_report_values_only_contain_explicit_references_and_catalog_evidence_survives():
    fake = FakeTransport()
    fake.data.update({
        "domains": {"results": [{"id": "default"}]},
        "security_policies": {"results": [{"id": "policy-01", "scope": ["ANY"]}]},
        "security_rules": {"results": [{"id": "rule-01", "action": "ALLOW", "source_groups": ["/infra/domains/default/groups/group-used"],
            "destination_groups": ["ANY"], "services": ["/infra/services/service-used"]}]},
        "groups": {"results": [{"id": "group-used", "display_name": "same-name", "expression": [{"resource_type": "IPAddressExpression", "ip_addresses": ["10.0.0.1"]}]},
                                {"id": "group-unused", "display_name": "same-name", "expression": []}]},
        "service_definitions": {"results": [{"id": "service-used", "display_name": "same-name", "service_entries": [{"resource_type": "L4PortSetServiceEntry", "l4_protocol": "TCP", "destination_ports": ["443"]}]},
                                             {"id": "service-unused", "display_name": "same-name", "service_entries": []}]},
        "realized_status": {"consolidated_status": {"consolidated_status": "SUCCESS"}},
    })
    result, _ = run(fake)
    row = check(result, "security")
    assert [group["id"] for group in row["values"]["referenced_groups"]] == ["group-used"]
    assert [service["id"] for service in row["values"]["service_definitions"]] == ["service-used"]
    assert {group["id"] for group in row["supporting_records"]["group_catalog"]} == {"group-used", "group-unused"}
    assert {service["id"] for service in row["supporting_records"]["service_catalog"]} == {"service-used", "service-unused"}
    assert "service-unused" not in json.dumps(row["values"])
    assert "group-unused" not in json.dumps(row["values"])


def test_any_security_reference_does_not_expand_catalog():
    groups, services, unresolved = __import__("vstacklens.products.nsx", fromlist=["_Collector"])._Collector._referenced_security_objects(
        [{"scope": ["ANY"], "rules": [{"source_groups": ["ANY"], "destination_groups": ["ANY"], "services": ["ANY"]}]}],
        [{"domain_id": "default", "id": "unrelated"}], [{"id": "HTTP"}])
    assert groups == services == unresolved == []


def test_explicit_nested_reference_is_kept_and_missing_reference_remains_visible():
    groups, services, unresolved = __import__("vstacklens.products.nsx", fromlist=["_Collector"])._Collector._referenced_security_objects(
        [{"scope": [], "rules": [{"source_groups": ["/infra/domains/default/groups/parent"], "services": ["/infra/services/parent-service"]}]}],
        [{"domain_id": "default", "id": "parent", "expressions": [{"paths": ["/infra/domains/default/groups/child", "/infra/domains/default/groups/missing"]}]},
         {"domain_id": "default", "id": "child", "expressions": []}],
        [{"id": "parent-service", "entries": [{"nested_service_path": "/infra/services/child-service"}]}, {"id": "child-service", "entries": []}])
    assert {row["id"] for row in groups} == {"parent", "child"}
    assert {row["id"] for row in services} == {"parent-service", "child-service"}
    assert unresolved == ["/infra/domains/default/groups/missing"]


def test_empty_child_scope_inherits_actual_parent_get_source_and_original_collection_time():
    result, fake = run()
    host_sources = {source["path"]: source for source in check(result, "hosts")["sources"]}
    gateway_sources = {source["path"]: source for source in check(result, "gateways")["sources"]}
    for key, parent_id, parent_sources, paths in (
        ("uplink_tunnels", "nsx.hosts", host_sources, {"/api/v1/transport-nodes"}),
        ("nat", "nsx.gateways", gateway_sources, {"/policy/api/v1/infra/tier-0s", "/policy/api/v1/infra/tier-1s"}),
    ):
        row = check(result, key)
        assert row["status"] == "not_deployed"
        assert {source["path"] for source in row["sources"]} == paths
        for source in row["sources"]:
            assert source["collected_at"] == parent_sources[source["path"]]["collected_at"]
            assert source["method"] == "GET" and source["succeeded"] is True
            assert source["inherited_from_check"] == parent_id
            assert source["dependency_only"] is True and source["child_get_executed"] is False
            assert "未执行子对象GET" in source["note"]
    assert not any(key in {"tunnels", "remote_transport_status", "uplink_profile", "t0_nat", "t1_nat", "t0_nat_rules", "t1_nat_rules"} for key, _, _ in fake.calls)
