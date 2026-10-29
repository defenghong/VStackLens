"""Offline transport safety and completeness checks; never contact a target."""
import base64
import http.client
import json
import socket
import ssl
from urllib.parse import parse_qs

import pytest

from vstacklens.products.model import SessionCredential, TargetRef
from vstacklens.products.transport import CollectionError, ReadTransport, Route


class Response:
    def __init__(self, payload=None, status=200, headers=(), raw=None):
        self.status = status
        self._headers = list(headers)
        self._body = raw if raw is not None else json.dumps(payload if payload is not None else {}).encode()
        self._offset = 0

    def read(self, limit):
        chunk = self._body[self._offset:self._offset + limit]
        self._offset += len(chunk)
        return chunk

    def getheaders(self):
        return self._headers

    def getheader(self, name):
        return next((value for key, value in self._headers if key.lower() == name.lower()), None)


@pytest.fixture
def wire(monkeypatch):
    queued, calls, connections = [], [], []

    class Connection:
        def __init__(self, host, port, *, timeout, context):
            self.host, self.port, self.context = host, port, context
            self.timeout = timeout
            self.closed = False
            connections.append(self)

        def request(self, method, path, *, body, headers):
            calls.append({"host": self.host, "port": self.port, "method": method, "path": path, "body": body, "headers": headers})

        def getresponse(self):
            assert queued, "Unexpected network request in offline test"
            response = queued.pop(0)
            if isinstance(response, BaseException):
                raise response
            return response

        def close(self):
            self.closed = True

    monkeypatch.setattr("vstacklens.products.transport.http.client.HTTPSConnection", Connection)
    return queued, calls, connections


def target(product="nsx", host=None, port=443):
    return TargetRef("target-1", product, "customer-1", "site-1", "lab", host or ("192.0.2.110" if product == "nsx" else "192.0.2.109"), port)


def transport(product="nsx", *, routes=None, credential=None, host=None, port=443, **kwargs):
    t = ReadTransport(target(product, host, port), credential or SessionCredential("admin", "offline-secret"),
                      routes or {"items": Route("/api/items", "Reviewed fixture list", "NSX 4.2.3 / AVI 30.2.5 fixture", ("cursor", "page", "page_size", "fields"))},
                      min_interval=0, **kwargs)
    t._pause = lambda *args, **kw: None
    return t


def avi_login_response():
    return Response({"user": "admin"}, headers=[("Set-Cookie", "sessionid=offline-session; Secure; HttpOnly; Path=/"),
                                                ("Set-Cookie", "csrftoken=offline-csrf; Secure; Path=/")])


def test_strict_tls_and_basic_auth_stay_on_single_target(wire):
    queued, calls, connections = wire
    queued.append(Response({"ready": True}))
    t = transport()
    assert t.get("items") == {"ready": True}
    assert connections[0].context.verify_mode == ssl.CERT_REQUIRED
    assert connections[0].context.check_hostname
    assert calls[0]["headers"]["Authorization"] == "Basic " + base64.b64encode(b"admin:offline-secret").decode()
    assert calls[0]["method"] == "GET"
    assert t.transport_security["peer_identity_verified"] is True
    assert connections[0].closed


def test_tls_failure_has_no_automatic_fallback_or_retry(wire):
    queued, calls, _ = wire
    queued.append(ssl.SSLCertVerificationError("self-signed certificate"))
    t = transport()
    with pytest.raises(CollectionError) as caught:
        t.get("items")
    assert caught.value.kind == "tls"
    assert len(calls) == 1
    assert t.metrics["retries"] == 0
    assert not t.transport_security["peer_identity_verified"]
    assert t.transport_security["tls_verification_enabled"]


@pytest.mark.parametrize("product,host,port,allowed", [
    ("nsx", "192.0.2.110", 443, True), ("avi", "192.0.2.109", 443, True),
    ("avi", "192.0.2.110", 443, False), ("nsx", "192.0.2.109", 443, False),
    ("nsx", "192.0.2.110", 8443, False), ("nsx", "customer.example", 443, False),
])
def test_unverified_tls_is_explicit_and_exact_lab_only(wire, product, host, port, allowed):
    cred = SessionCredential("admin", "offline-secret", allow_untrusted_lab=True)
    if allowed:
        t = transport(product, host=host, port=port, credential=cred)
        assert t._context.verify_mode == ssl.CERT_NONE
        assert t.transport_security["mode"] == "explicit_lab_unverified"
        assert not t.transport_security["peer_identity_verified"]
    else:
        with pytest.raises(CollectionError, match="laboratory"):
            transport(product, host=host, port=port, credential=cred)
    assert wire[1] == []


@pytest.mark.parametrize("path", ["https://other/api/items", "//other/api/items", "/api/../items", "/api/items?action=delete", "/api/%2fitems", "/api/{id.__class__}"])
def test_unreviewable_route_definitions_are_rejected_before_network(wire, path):
    with pytest.raises(CollectionError):
        transport(routes={"items": Route(path, "review")})
    assert wire[1] == []


@pytest.mark.parametrize("params,query", [({"id": "../other"}, None), ({"id": "https://other"}, None),
                                        ({"id": "abc%2fdef"}, None), ({"id": "abc/def"}, None),
                                        ({"unknown": "abc"}, None), ({"id": "abc"}, {"action": "delete"}),
                                        ({"id": "abc"}, {"fields": "foo\r\nAuthorization: secret"})])
def test_path_and_query_injection_rejected(wire, params, query):
    t = transport(routes={"items": Route("/api/items/{id}", "review", query_parameters=("fields",))})
    with pytest.raises(CollectionError):
        t.get("items", path_params=params, query=query)
    assert wire[1] == []


def test_fixed_identifier_route_and_query_encoding(wire):
    wire[0].append(Response({"id": "node-1"}))
    t = transport(routes={"items": Route("/api/items/{node_id}", "review", query_parameters=("fields",))})
    assert t.get("items", {"node_id": "node-1"}, {"fields": "name,status"})["id"] == "node-1"
    assert wire[1][0]["path"] == "/api/items/node-1?fields=name%2Cstatus"


def test_avi_documented_form_cookie_csrf_logout_and_memory_cleanup(wire):
    queued, calls, _ = wire
    queued.extend([avi_login_response(), Response({"results": []}), Response(raw=b"", status=204)])
    cred = SessionCredential("admin", "offline-secret", tenant="tenant-one")
    t = transport("avi", credential=cred)
    with t:
        t.login_avi()
        assert t.get("items") == {"results": []}
    assert [call["method"] for call in calls] == ["POST", "GET", "POST"]
    assert [call["path"] for call in calls] == ["/login", "/api/items", "/logout"]
    assert parse_qs(calls[0]["body"].decode()) == {"username": ["admin"], "password": ["offline-secret"]}
    assert calls[0]["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
    assert "Authorization" not in calls[1]["headers"]
    assert calls[1]["headers"]["X-CSRFToken"] == "offline-csrf"
    assert calls[1]["headers"]["X-Avi-Tenant"] == "tenant-one"
    assert calls[1]["headers"]["Referer"] == "https://192.0.2.109/"
    assert not t._cookies and not t._password and not t.secret_values
    assert {"offline-session", "offline-csrf"} <= set(cred.secret_values)
    t.close()
    assert len(calls) == 3


def test_avi_session_cookies_do_not_cross_transport_or_server_domain(wire):
    queued, calls, _ = wire
    queued.extend([avi_login_response(), Response({}, headers=[("Set-Cookie", "sessionid=foreign; Domain=evil.example")])])
    first = transport("avi")
    first.login_avi()
    first.get("items")
    second = transport("avi")
    assert second._cookies == {}
    with pytest.raises(CollectionError, match="login is required"):
        second.get("items")
    assert first._cookies["sessionid"] == "offline-session"
    assert len(calls) == 2


def test_partial_login_is_logged_out_after_parse_failure(wire):
    wire[0].extend([Response(raw=b"<html>not json</html>", headers=[("Set-Cookie", "sessionid=offline-session; Secure")]), Response(raw=b"", status=204)])
    t = transport("avi")
    with pytest.raises(CollectionError):
        with t:
            t.login_avi()
    assert [call["path"] for call in wire[1]] == ["/login", "/logout"]


def test_avi_logout_reserves_single_cleanup_even_after_cancel_and_budget(wire):
    wire[0].extend([avi_login_response(), Response(raw=b"", status=204)])
    cancelled = [False]
    t = transport("avi", request_budget=1, cancel_requested=lambda: cancelled[0])
    t.login_avi()
    cancelled[0] = True
    t.close()
    assert [call["path"] for call in wire[1]] == ["/login", "/logout"]
    assert t.metrics["cleanup_requests"] == 1


@pytest.mark.parametrize("status,kind", [(401, "authentication"), (429, "rate_limit")])
def test_authentication_and_rate_limit_open_circuit(wire, status, kind):
    wire[0].append(Response({"message": "stop"}, status=status))
    t = transport()
    for _ in range(2):
        with pytest.raises(CollectionError) as caught:
            t.get("items")
        assert caught.value.kind == kind
    assert len(wire[1]) == 1
    assert t.metrics["circuit_open"] == kind


def test_login_403_is_authentication_and_does_not_repeat(wire):
    wire[0].append(Response({"message": "invalid credentials"}, status=403))
    t = transport("avi")
    for _ in range(2):
        with pytest.raises(CollectionError) as caught:
            t.login_avi()
        assert caught.value.kind == "authentication"
    assert len(wire[1]) == 1


def test_get_permission_failure_does_not_prevent_other_reads_and_is_redacted(wire):
    sensitive = "offline-secret"
    raw_message = "denied " + sensitive + " password=another sessionid=sessionvalue C:\\Users\\Someone\\secret.txt"
    wire[0].extend([Response({"error_message": raw_message}, status=403), Response({"ready": True})])
    t = transport()
    with pytest.raises(CollectionError) as caught:
        t.get("items")
    error = caught.value.as_dict()
    assert error["kind"] == "permission" and error["http_status"] == 403
    assert sensitive not in json.dumps(error) and "sessionvalue" not in json.dumps(error) and "Someone" not in json.dumps(error)
    assert t.get("items")["ready"]


def test_nsx_known_403_authentication_rejection_opens_circuit(wire):
    wire[0].append(Response({"error_code": 403, "error_message": "The credentials were incorrect or the account specified has been locked."}, status=403))
    t = transport()
    for _ in range(2):
        with pytest.raises(CollectionError) as caught:
            t.get("items")
        assert caught.value.kind == "authentication" and caught.value.http_status == 403
    assert t.metrics["circuit_open"] == "authentication"
    assert len(wire[1]) == 1


@pytest.mark.parametrize("payload", [{"error_code": 403}, {"error_code": 403, "error_message": "The principal lacks permission to read this object."}])
def test_nsx_ordinary_403_remains_permission_and_other_reads_continue(wire, payload):
    wire[0].extend([Response(payload, status=403), Response({"ready": True})])
    t = transport()
    with pytest.raises(CollectionError) as caught:
        t.get("items")
    assert caught.value.kind == "permission"
    assert t.metrics["circuit_open"] is None
    assert t.get("items")["ready"]


def test_nsx_message_does_not_reclassify_avi_resource_permission(wire):
    wire[0].extend([avi_login_response(), Response({"error_message": "The credentials were incorrect or the account specified has been locked."}, status=403)])
    t = transport("avi")
    t.login_avi()
    with pytest.raises(CollectionError) as caught:
        t.get("items")
    assert caught.value.kind == "permission" and t.metrics["circuit_open"] is None


def test_redirect_never_followed_or_forwarded(wire):
    wire[0].append(Response(status=302, headers=[("Location", "https://evil.example/steal")]))
    t = transport()
    with pytest.raises(CollectionError) as caught:
        t.get("items")
    assert caught.value.http_status == 302
    assert len(wire[1]) == 1
    assert "evil" not in str(caught.value)


def test_invalid_json_preserves_parser_evidence_without_body(wire):
    wire[0].append(Response(raw=b'{"password":"offline-secret", BROKEN'))
    t = transport()
    with pytest.raises(CollectionError) as caught:
        t.get("items")
    error = caught.value.as_dict()
    assert error["stage"] == "parse" and error["kind"] == "invalid_response"
    assert "JSONDecodeError" in error["reason"] and "position=" in error["reason"]
    assert "offline-secret" not in str(error)


def test_single_bounded_retry_for_timeout_and_503_pressure_stops(wire):
    wire[0].extend([socket.timeout(), Response({"ready": True}), Response({}, status=503, headers=[("Retry-After", "600")])])
    t = transport()
    assert t.get("items")["ready"]
    assert t.metrics["retries"] == 1
    with pytest.raises(CollectionError) as caught:
        t.get("items")
    assert caught.value.kind == "rate_limit"
    with pytest.raises(CollectionError):
        t.get("items")
    assert len(wire[1]) == 3


def test_transient_retry_is_finite(wire):
    wire[0].extend([socket.timeout(), socket.timeout()])
    t = transport()
    with pytest.raises(CollectionError) as caught:
        t.get("items")
    assert caught.value.kind == "timeout"
    assert len(wire[1]) == 2 and t.metrics["retries"] == 1


def test_nsx_cursor_pagination_complete_with_sources_and_times(wire):
    wire[0].extend([Response({"results": [{"id": "one"}], "cursor": "next/+", "result_count": 2}),
                    Response({"results": [{"id": "two"}], "result_count": 2})])
    t = transport()
    result = t.list_pages("items")
    assert result["complete"] and not result["errors"]
    assert [item["id"] for item in result["items"]] == ["one", "two"]
    assert len(result["sources"]) == 2 and all(source["collected_at"] for source in result["sources"])
    assert "cursor=next%2F%2B" in wire[1][1]["path"]


def test_partial_failure_retains_prior_records(wire):
    wire[0].extend([Response({"results": [{"id": "one"}], "cursor": "next", "result_count": 2}), Response(status=403)])
    result = transport().list_pages("items")
    assert result["items"] == [{"id": "one"}]
    assert not result["complete"] and result["errors"][0]["kind"] == "permission"


@pytest.mark.parametrize("limit,kwargs", [("request", {"request_budget": 1}), ("page", {"page_budget": 1}), ("record", {"record_budget": 1})])
def test_pagination_budgets_retain_records_without_extra_requests(wire, limit, kwargs):
    wire[0].append(Response({"results": [{"id": "one"}], "cursor": "next", "result_count": 2}))
    result = transport(**kwargs).list_pages("items")
    assert result["items"] == [{"id": "one"}] and not result["complete"]
    assert result["errors"][0]["kind"] == "budget"
    assert len(wire[1]) == 1


def test_repeated_cursor_stops_and_missing_records_not_complete(wire):
    wire[0].extend([Response({"results": [{"id": "one"}], "cursor": "repeat"}), Response({"results": [{"id": "two"}], "cursor": "repeat"})])
    result = transport().list_pages("items")
    assert not result["complete"] and result["errors"][0]["stage"] == "pagination"
    assert len(wire[1]) == 2
    wire[0].append(Response({"results": [], "result_count": 1}))
    result = transport().list_pages("items")
    assert not result["complete"] and "declared" in result["errors"][0]["reason"]


@pytest.mark.parametrize("next_link", ["https://evil.example/api/items?page=2", "http://192.0.2.109/api/items?page=2",
                                       "https://192.0.2.109:8443/api/items?page=2", "/api/other?page=2",
                                       "/api/items?page=2&action=delete", "/api/items?page=2&page=3",
                                       "https://admin:secret@192.0.2.109/api/items?page=2", "/api/items#fragment"])
def test_avi_next_must_be_same_origin_same_allowlisted_resource(wire, next_link):
    wire[0].extend([avi_login_response(), Response({"results": [{"id": "one"}], "next": next_link, "count": 2})])
    t = transport("avi")
    t.login_avi()
    result = t.list_pages("items", kind="avi")
    assert not result["complete"] and len(result["items"]) == 1
    assert result["errors"][0]["kind"] == "invalid_response"
    assert len(wire[1]) == 2


def test_avi_same_origin_pages_are_accepted(wire):
    wire[0].extend([avi_login_response(), Response({"results": [{"id": "one"}], "next": "https://192.0.2.109/api/items?page=2", "count": 2}), Response({"results": [{"id": "two"}], "next": None, "count": 2})])
    t = transport("avi")
    t.login_avi()
    result = t.list_pages("items", kind="avi")
    assert result["complete"] and len(result["items"]) == 2
    assert wire[1][-1]["path"] == "/api/items?page=2"


def test_cancelled_collection_never_requests_or_claims_complete(wire):
    t = transport(cancel_requested=lambda: True)
    result = t.list_pages("items")
    assert not result["complete"] and result["errors"][0]["kind"] == "cancelled"
    assert wire[1] == []


def test_empty_list_is_complete_but_missing_array_is_invalid(wire):
    wire[0].extend([Response({"results": [], "result_count": 0}), Response({})])
    t = transport()
    assert t.list_pages("items")["complete"]
    result = t.list_pages("items")
    assert not result["complete"] and result["errors"][0]["kind"] == "invalid_response"


def test_quoted_secret_keys_embedded_in_error_are_redacted(wire):
    message = 'failure {"license_key":"UNKNOWN-LICENSE", "private_key":"UNKNOWN-PRIVATE", "password":"UNKNOWN-PASSWORD", "accesstoken":"UNKNOWN-ACCESS", "refreshtoken":"UNKNOWN-REFRESH"}'
    wire[0].append(Response({"error_message": message}, status=403))
    with pytest.raises(CollectionError) as caught:
        transport().get("items")
    assert all(value not in caught.value.reason for value in ("UNKNOWN-LICENSE", "UNKNOWN-PRIVATE", "UNKNOWN-PASSWORD", "UNKNOWN-ACCESS", "UNKNOWN-REFRESH"))


def test_cancellation_is_checked_between_body_chunks(wire):
    cancelled = [False]

    class SlowResponse(Response):
        def read(self, limit):
            chunk = super().read(1)
            cancelled[0] = True
            return chunk

    wire[0].append(SlowResponse({"results": []}))
    t = transport(cancel_requested=lambda: cancelled[0])
    with pytest.raises(CollectionError) as caught:
        t.get("items")
    assert caught.value.kind == "cancelled"
    assert t.metrics["response_bytes"] == 1


def test_slow_continuous_body_has_total_time_budget(wire, monkeypatch):
    clock = [1.0]

    class SlowResponse(Response):
        def read(self, limit):
            clock[0] += 0.2
            return b"x"

    monkeypatch.setattr("vstacklens.products.transport.time.monotonic", lambda: clock[0])
    wire[0].extend([SlowResponse(), SlowResponse()])
    t = transport(timeout=0.5)
    with pytest.raises(CollectionError) as caught:
        t.get("items")
    assert caught.value.kind == "timeout"
    assert caught.value.http_status == 200
    assert len(wire[1]) == 2
    assert t.metrics["response_bytes"] < 10


@pytest.mark.parametrize("responses", [
    [Response({"results": [{"id": "one"}, {"id": "two"}], "result_count": 1})],
    [Response({"results": [{"id": "one"}], "cursor": "next", "result_count": 3}), Response({"results": [{"id": "two"}], "result_count": 2})],
    [Response({"results": [{"id": "one"}], "result_count": "1"})],
])
def test_inconsistent_total_does_not_claim_complete(wire, responses):
    wire[0].extend(responses)
    result = transport().list_pages("items")
    assert not result["complete"] and result["items"]
    assert result["errors"][0]["kind"] == "invalid_response"


def test_reviewed_large_spec_timeout_is_route_specific(wire):
    wire[0].extend([Response({"swagger": "2.0"}), Response({"ready": True})])
    t = transport(routes={"manager_spec": Route("/api/v1/spec/openapi/nsx_api.json", "Read local API specification", timeout_seconds=45),
                          "items": Route("/api/items", "Read small status response")})
    t.get("manager_spec")
    t.get("items")
    assert [connection.timeout for connection in wire[2]] == [45, 10]


@pytest.mark.parametrize("timeout", [0, 121, float("nan"), float("inf"), "45"])
def test_route_timeout_is_bounded(wire, timeout):
    with pytest.raises(CollectionError) as caught:
        transport(routes={"items": Route("/api/items", "review", timeout_seconds=timeout)})
    assert caught.value.kind == "budget" and wire[1] == []


def test_avi_hyphenated_session_cookie_is_supported_preferences_are_ignored(wire):
    wire[0].extend([Response({}, headers=[("Set-Cookie", "avi-sessionid=offline-avi-session; Secure; Path=/"),
                                         ("Set-Cookie", "csrftoken=offline-csrf; Secure; Path=/"),
                                         ("Set-Cookie", "display_user=admin; Secure; Path=/")]), Response({})])
    cred = SessionCredential("admin", "offline-secret")
    t = transport("avi", credential=cred)
    t.login_avi()
    t.get("items")
    assert "avi-sessionid=offline-avi-session" in wire[1][1]["headers"]["Cookie"]
    assert "display_user" not in wire[1][1]["headers"]["Cookie"]
    assert "admin" not in cred.secret_values
    assert "offline-avi-session" in cred.secret_values


def test_avi_expired_cookie_values_are_not_registered_as_secrets(wire):
    wire[0].extend([Response({}, headers=[("Set-Cookie", "sessionid=offline-session; Secure"),
                                         ("Set-Cookie", "accesstoken=expired-placeholder; Expires=Thu, 01 Jan 1970 00:00:00 GMT")])])
    cred = SessionCredential("admin", "offline-secret")
    t = transport("avi", credential=cred)
    t.login_avi()
    assert "expired-placeholder" not in cred.secret_values
    assert "accesstoken" not in t._cookies


@pytest.mark.parametrize("location", ["/", "/login", "https://192.0.2.109/"])
def test_avi_fixed_logout_302_with_session_invalidation_is_accepted_without_follow(wire, location):
    wire[0].extend([avi_login_response(), Response(raw=b"<html>redirect</html>", status=302,
                                                 headers=[("Location", location), ("Set-Cookie", "sessionid=removed; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/")])])
    t = transport("avi")
    t.login_avi()
    t.close()
    assert "logout_error" not in t.metrics
    assert t.metrics["logout_state"] == "accepted_logout_redirect"
    assert not t.metrics["logout_server_revocation_verified"]
    assert [call["path"] for call in wire[1]] == ["/login", "/logout"]


@pytest.mark.parametrize("location,invalidate", [("https://evil.example/", True), ("/?return=evil", True),
                                                 ("/api/items", True)])
def test_other_logout_redirects_remain_unconfirmed_and_never_follow(wire, location, invalidate):
    headers = [("Location", location)]
    if invalidate:
        headers.append(("Set-Cookie", "sessionid=removed; Max-Age=0; Path=/"))
    wire[0].extend([avi_login_response(), Response(raw=b"", status=302, headers=headers)])
    t = transport("avi")
    t.login_avi()
    t.close()
    assert t.metrics["logout_error"]["http_status"] == 302
    assert len(wire[1]) == 2 and not t._cookies


def test_observed_avi_placeholder_tokens_are_not_sent_or_scanned_as_secrets(wire):
    wire[0].extend([Response({}, headers=[("Set-Cookie", "avi-sessionid=offline-avi-session; Secure"),
                                         ("Set-Cookie", "sessionid=offline-session; Secure"),
                                         ("Set-Cookie", "csrftoken=offline-csrf; Secure"),
                                         ("Set-Cookie", "accesstoken=None; Secure"),
                                         ("Set-Cookie", "refreshtoken=null; Secure")]),
                    Response({}), Response(raw=b"", status=302, headers=[("Location", "/")])])
    cred = SessionCredential("admin", "offline-secret")
    t = transport("avi", credential=cred)
    with t:
        t.login_avi()
        t.get("items")
    assert "None" not in cred.secret_values and "null" not in cred.secret_values
    assert {"offline-avi-session", "offline-session", "offline-csrf"} <= set(cred.secret_values)
    assert "accesstoken=" not in wire[1][1]["headers"]["Cookie"]
    assert "refreshtoken=" not in wire[1][1]["headers"]["Cookie"]
    assert "logout_error" not in t.metrics and t.metrics["logout_state"] == "accepted_logout_redirect"
    assert [call["path"] for call in wire[1]] == ["/login", "/api/items", "/logout"]


def test_login_body_timeout_still_attempts_logout_after_session_headers(wire, monkeypatch):
    clock = [1.0]

    class SlowLogin(Response):
        def read(self, limit):
            clock[0] += 0.6
            return b"{"

    wire[0].extend([SlowLogin(headers=[("Set-Cookie", "avi-sessionid=offline-avi-session; Secure")]), Response(raw=b"", status=204)])
    monkeypatch.setattr("vstacklens.products.transport.time.monotonic", lambda: clock[0])
    t = transport("avi", timeout=0.5)
    with pytest.raises(CollectionError) as caught:
        with t:
            t.login_avi()
    assert caught.value.kind == "timeout" and caught.value.http_status == 200
    assert [call["path"] for call in wire[1]] == ["/login", "/logout"]


def test_account_hidden_in_http_diagnostics_without_changing_business_tenant(wire):
    account = "private-operator-287"
    payload = {"error_message": f"User {account} cannot read this resource in tenant admin"}
    wire[0].extend([Response(payload, status=403), Response({"tenant": "admin", "roles": ["admin"]})])
    cred = SessionCredential(account, "offline-secret")
    t = transport(credential=cred)
    assert account not in t._http_reason(json.dumps(payload).encode(), 403)
    with pytest.raises(CollectionError) as caught:
        t.get("items")
    assert account not in str(caught.value.as_dict())
    assert t.get("items") == {"tenant": "admin", "roles": ["admin"]}
    assert account not in cred.secret_values and "admin" not in cred.secret_values


@pytest.mark.parametrize("status,expected_kind", [(401, "authentication"), (403, "permission"), (429, "rate_limit")])
@pytest.mark.parametrize("failure", ["timeout", "truncated", "body_budget"])
def test_nontransient_http_body_failure_keeps_status_without_retry(wire, status, expected_kind, failure):
    class BrokenBody(Response):
        def read(self, limit):
            if failure == "timeout":
                raise socket.timeout("offline-secret C:\\Users\\OfflineOperator\\private.txt")
            if failure == "truncated":
                raise http.client.IncompleteRead(b"offline-secret")
            raise CollectionError("budget", "offline-secret response exceeded bounded size", stage="collection")

    wire[0].append(BrokenBody(status=status))
    t = transport()
    with pytest.raises(CollectionError) as caught:
        t.get("items")
    error = caught.value.as_dict()
    assert error["kind"] == expected_kind and error["http_status"] == status
    assert error["stage"] == "collection" and "response body read failed" in error["reason"]
    assert "offline-secret" not in str(error) and "OfflineOperator" not in str(error)
    assert t.metrics["retries"] == 0 and len(wire[1]) == 1
    if status in {401, 429}:
        with pytest.raises(CollectionError) as stopped:
            t.get("items")
        assert stopped.value.kind == expected_kind
        assert t.metrics["circuit_open"] == expected_kind and len(wire[1]) == 1
    else:
        wire[0].append(Response({"ready": True}))
        assert t.get("items")["ready"] is True
        assert t.metrics["circuit_open"] is None and len(wire[1]) == 2
    assert all(connection.closed for connection in wire[2])


@pytest.mark.parametrize("status,expected_kind", [(401, "authentication"), (403, "permission"), (429, "rate_limit")])
def test_nontransient_http_with_readable_body_keeps_original_classification(wire, status, expected_kind):
    wire[0].append(Response({"error_message": "readable native diagnostic"}, status=status))
    t = transport()
    with pytest.raises(CollectionError) as caught:
        t.get("items")
    assert caught.value.kind == expected_kind and caught.value.http_status == status
    assert "readable native diagnostic" in caught.value.reason
    assert "response body read failed" not in caught.value.reason
    assert t.metrics["retries"] == 0 and len(wire[1]) == 1


@pytest.mark.parametrize("status", [401, 403, 429])
def test_cancellation_after_nontransient_headers_remains_cancelled(wire, status):
    cancelled = [False]

    class CancelDuringBody(Response):
        def read(self, limit):
            cancelled[0] = True
            return b"{"

    wire[0].append(CancelDuringBody(status=status))
    t = transport(cancel_requested=lambda: cancelled[0])
    with pytest.raises(CollectionError) as caught:
        t.get("items")
    assert caught.value.kind == "cancelled" and caught.value.http_status == status
    assert caught.value.stage == "cancellation"
    assert len(wire[1]) == 1 and t.metrics["retries"] == 0
    assert all(connection.closed for connection in wire[2])


def test_avi_login_403_body_failure_still_stops_authentication(wire):
    class BrokenLoginBody(Response):
        def read(self, limit):
            raise socket.timeout("offline authentication body timeout")

    wire[0].append(BrokenLoginBody(status=403))
    t = transport("avi")
    for _ in range(2):
        with pytest.raises(CollectionError) as caught:
            t.login_avi()
        assert caught.value.kind == "authentication" and caught.value.http_status == 403
    assert len(wire[1]) == 1 and wire[1][0]["method"] == "POST"
    assert t.metrics["retries"] == 0 and t.metrics["circuit_open"] == "authentication"
