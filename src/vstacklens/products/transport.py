"""Bounded, target-local transport for explicitly reviewed product reads.

GET routes are a code-owned allowlist. The only POSTs are AVI's documented
form login and logout; no generic write/request method is exposed. Responses,
cookies, credentials and CSRF values stay in memory.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import http.client
from http.cookies import SimpleCookie, CookieError
import ipaddress
import json
import math
import re
import socket
import ssl
import string
import time
from typing import Any, Callable, Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit


_MAX_RESPONSE = 32 * 1024 * 1024
_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_LAB_ENDPOINTS = {("nsx", "192.0.2.110", 443), ("avi", "192.0.2.109", 443)}
_AVI_AUTH_COOKIES = {"csrftoken", "sessionid", "avi-sessionid", "accesstoken", "refreshtoken"}
_AVI_SESSION_COOKIES = {"sessionid", "avi-sessionid"}


def _safe_reason(reason: object, secrets: tuple[str, ...] = ()) -> str:
    value = str(reason)
    for secret in sorted((v for v in secrets if v), key=len, reverse=True):
        value = value.replace(secret, "[REDACTED]")
    value = re.sub(r"-----BEGIN [^-]+-----.*?(?:-----END [^-]+-----|$)", "[REDACTED PEM]", value, flags=re.S)
    value = re.sub(r"(?i)[\"']?\b(?:authorization|password|passwd|cookie|cookies|token|access[_-]?token|refresh[_-]?token|sessionid|avi[_-]?sessionid|csrftoken|api[_-]?key|license[_-]?key|private[_-]?key)\b[\"']?\s*[:=]\s*(?:\"[^\"]*\"|'[^']*'|[^\s,;}]+)", "[REDACTED credential]", value)
    value = re.sub(r"(?i)\b(?:Basic|Bearer)\s+[A-Za-z0-9+/=_-]+", "[REDACTED authorization]", value)
    value = re.sub(r"(?i)[A-Z]:[\\/][^\r\n\"<>|]*", "[REDACTED local path]", value)
    value = re.sub(r"/(?:home|Users|root|tmp|var/tmp)/[^\s\"<>]*", "[REDACTED local path]", value)
    return value.replace("\r", " ").replace("\n", " ")[:600]


class CollectionError(Exception):
    """A structured error whose public text never includes a raw response."""

    def __init__(self, kind: str, reason: object, *, http_status: int | None = None, stage: str = "collection"):
        self.kind = kind
        self.reason = _safe_reason(reason)
        self.http_status = http_status
        self.stage = stage
        super().__init__(self.reason)

    def as_dict(self) -> dict:
        return {"kind": self.kind, "reason": self.reason, "http_status": self.http_status, "stage": self.stage}


@dataclass(frozen=True)
class Route:
    path: str
    purpose: str
    version_basis: str = ""
    query_parameters: tuple[str, ...] = ()
    timeout_seconds: float | None = None


class ReadTransport:
    def __init__(self, target, credential, routes: Mapping[str, Route], *, cancel_requested: Callable[[], bool] | None = None,
                 timeout: float = 10.0, request_budget: int = 120, page_budget: int = 20,
                 record_budget: int = 2000, min_interval: float = 0.2):
        self.target = target
        self._host = self._validate_host(target.host)
        self._port = int(target.port)
        if not 1 <= self._port <= 65535:
            raise CollectionError("transport", "Invalid target port", stage="validation")
        self._product = str(target.product).lower()
        if self._product not in {"nsx", "avi"}:
            raise CollectionError("transport", "Transport supports NSX or AVI only", stage="validation")
        self._username = str(credential.username)
        self._password = str(credential.password)
        self._tenant = str(credential.tenant or "admin")
        if any(c in self._username + self._password + self._tenant for c in "\r\n\x00") or ":" in self._username:
            raise CollectionError("authentication", "Invalid credential format", stage="validation")
        if not _SEGMENT.fullmatch(self._tenant):
            raise CollectionError("authentication", "Invalid tenant identifier", stage="validation")
        self._secrets: set[str] = set()
        self._remember_credential_secret = getattr(credential, "remember_secret", None)
        self._remember(self._password)
        self._routes = dict(routes)
        for key, route in self._routes.items():
            if not _NAME.fullmatch(str(key)) or not isinstance(route, Route):
                raise CollectionError("transport", "Invalid allowlist entry", stage="validation")
            self._validate_template(route)
        self._cancel_requested = cancel_requested or (lambda: False)
        self._timeout = float(timeout)
        self._request_budget = int(request_budget)
        self._page_budget = int(page_budget)
        self._record_budget = int(record_budget)
        self._min_interval = float(min_interval)
        if not 0.1 <= self._timeout <= 120 or not 1 <= self._request_budget <= 1000 or not 1 <= self._page_budget <= 100 or not 1 <= self._record_budget <= 100000 or not 0 <= self._min_interval <= 60:
            raise CollectionError("budget", "Invalid bounded collection limits", stage="validation")
        self._cookies: dict[str, str] = {}
        self._csrf = ""
        self._avi_authenticated = False
        self._logout_attempted = False
        self._closed = False
        self._last_request_at: float | None = None
        self._circuit: CollectionError | None = None
        self.metrics = {"requests": 0, "retries": 0, "pages": 0, "records": 0, "response_bytes": 0,
                        "cleanup_requests": 0, "request_budget": self._request_budget,
                        "page_budget": self._page_budget, "record_budget": self._record_budget,
                        "http_status_counts": {}, "circuit_open": None}
        allow_lab = bool(credential.allow_untrusted_lab)
        if allow_lab and (self._product, self._host, self._port) not in _LAB_ENDPOINTS:
            raise CollectionError("tls", "Unverified TLS is authorized only for the two specified laboratory endpoints", stage="validation")
        self._verify_tls = not allow_lab
        self.transport_security = {"tls_verification_enabled": not allow_lab, "tls_verified": False, "peer_identity_verified": False,
                                   "mode": "explicit_lab_unverified" if allow_lab else "strict",
                                   "note": "Explicit laboratory option: peer identity was not verified" if allow_lab else "TLS peer certificate and hostname verification enabled"}
        try:
            self._context = ssl._create_unverified_context() if allow_lab else ssl.create_default_context(cafile=credential.ca_bundle)
        except (OSError, ssl.SSLError, ValueError) as exc:
            raise self._error("tls", f"{type(exc).__name__}: {exc}", stage="tls") from None

    @property
    def secret_values(self) -> tuple[str, ...]:
        """For the final in-memory publication scanner; never serialize this."""
        return tuple(v for v in self._secrets if v)

    def _remember(self, value: str) -> None:
        if value:
            self._secrets.add(value)
            if self._remember_credential_secret:
                self._remember_credential_secret(value)

    @staticmethod
    def _validate_host(value: object) -> str:
        host = str(value).strip().lower()
        if not host or any(c in host for c in "/\\@?#%\r\n\x00"):
            raise CollectionError("transport", "Target must be a hostname or IP address without a URL", stage="validation")
        try:
            return str(ipaddress.ip_address(host.strip("[]")))
        except ValueError:
            if len(host) > 253 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host) or ".." in host:
                raise CollectionError("transport", "Invalid target hostname", stage="validation")
            return host

    @staticmethod
    def _validate_template(route: Route) -> None:
        if not route.purpose or not route.path.startswith("/") or route.path.startswith("//") or any(c in route.path for c in "?#%\\\r\n\x00"):
            raise CollectionError("transport", "Allowlisted route must have a purpose and fixed absolute path", stage="validation")
        try:
            fields = list(string.Formatter().parse(route.path))
        except ValueError:
            raise CollectionError("transport", "Invalid route template", stage="validation") from None
        for _, name, spec, conversion in fields:
            if name is not None and (not _NAME.fullmatch(name) or spec or conversion):
                raise CollectionError("transport", "Only plain named route parameters are allowed", stage="validation")
        literal = re.sub(r"\{[A-Za-z_][A-Za-z0-9_]*\}", "identifier", route.path)
        if any(segment in {".", "..", ""} for segment in literal[1:].split("/")) or not re.fullmatch(r"/[A-Za-z0-9_./:-]+", literal):
            raise CollectionError("transport", "Invalid allowlisted route path", stage="validation")
        if any(not _NAME.fullmatch(p) for p in route.query_parameters):
            raise CollectionError("transport", "Invalid allowlisted query parameter", stage="validation")
        if route.timeout_seconds is not None and (not isinstance(route.timeout_seconds, (int, float)) or not math.isfinite(route.timeout_seconds) or not 0.1 <= route.timeout_seconds <= 120):
            raise CollectionError("budget", "Route timeout must be between 0.1 and 120 seconds", stage="validation")

    def _error(self, kind: str, reason: object, *, http_status: int | None = None, stage: str = "collection") -> CollectionError:
        # Account names are scrubbed from diagnostic text, without altering
        # legitimate tenant/role names returned as collected business values.
        secrets = (*self.secret_values, self._username) if self._username else self.secret_values
        return CollectionError(kind, _safe_reason(reason, secrets), http_status=http_status, stage=stage)

    def check_cancelled(self) -> None:
        if self._cancel_requested():
            raise self._error("cancelled", "Collection cancelled", stage="cancellation")

    def _resolve(self, key: str, path_params: Mapping | None, query: Mapping | None) -> tuple[Route, str, dict]:
        if key not in self._routes:
            raise self._error("unsupported", "Route is not in the reviewed read allowlist", stage="validation")
        route = self._routes[key]
        names = {name for _, name, _, _ in string.Formatter().parse(route.path) if name is not None}
        params = dict(path_params or {})
        if set(params) != names:
            raise self._error("unsupported", "Route parameter names do not match allowlist", stage="validation")
        for value in params.values():
            if not isinstance(value, str) or not _SEGMENT.fullmatch(value) or value in {".", ".."}:
                raise self._error("unsupported", "Invalid route identifier", stage="validation")
        values = dict(query or {})
        if set(values) - set(route.query_parameters):
            raise self._error("unsupported", "Query parameter is not in the reviewed allowlist", stage="validation")
        normalized = {}
        for name, value in values.items():
            if not isinstance(value, (str, bool, int, float)) or isinstance(value, float) and not math.isfinite(value):
                raise self._error("unsupported", "Only finite scalar query values are allowed", stage="validation")
            rendered = str(value).lower() if isinstance(value, bool) else str(value)
            if len(rendered) > 2048 or any(c in rendered for c in "\r\n\x00"):
                raise self._error("unsupported", "Invalid query value", stage="validation")
            if name in {"page", "page_size", "limit"} and (not rendered.isdigit() or not 1 <= int(rendered) <= 2000):
                raise self._error("budget", "Pagination query exceeds bounded range", stage="validation")
            normalized[name] = rendered
        return route, route.path.format(**params), normalized

    def _pause(self, delay: float, *, cleanup: bool = False) -> None:
        end = time.monotonic() + delay
        while time.monotonic() < end:
            if not cleanup:
                self.check_cancelled()
            time.sleep(min(0.05, max(0, end - time.monotonic())))

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json", "User-Agent": "VStackLens-read-inspection/1"}
        if self._product == "nsx":
            encoded = base64.b64encode(f"{self._username}:{self._password}".encode("utf-8")).decode("ascii")
            self._remember(encoded)
            headers["Authorization"] = "Basic " + encoded
        else:
            headers.update({"X-Avi-Version": "30.2.5", "X-Avi-Tenant": self._tenant, "Referer": self._origin + "/"})
            if self._cookies:
                headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in self._cookies.items())
                self._remember(headers["Cookie"])
            if self._csrf:
                headers["X-CSRFToken"] = self._csrf
        return headers

    @property
    def _origin(self) -> str:
        host = f"[{self._host}]" if ":" in self._host else self._host
        return f"https://{host}" + (f":{self._port}" if self._port != 443 else "")

    def _capture_cookies(self, response) -> set[str]:
        invalidated = set()
        if self._product != "avi":
            return invalidated
        for name, header in response.getheaders():
            if name.lower() != "set-cookie":
                continue
            cookie = SimpleCookie()
            try:
                cookie.load(header)
            except CookieError:
                raise self._error("invalid_response", "Invalid session cookie", stage="authentication") from None
            for key, morsel in cookie.items():
                key = key.casefold()
                if key not in _AVI_AUTH_COOKIES or any(c in morsel.value for c in "\r\n\x00;"):
                    continue
                # Even a server-supplied Domain cannot widen this target-local jar.
                if morsel["domain"] and morsel["domain"].lstrip(".").lower() != self._host:
                    continue
                # AVI 30.2.5 returns literal None/null for unavailable access
                # and refresh tokens. These are absent tokens, not secrets;
                # the real session/CSRF values remain strongly scanned.
                placeholder = morsel.value.strip().casefold() in {"none", "null"}
                expired = not morsel.value or placeholder
                if morsel["max-age"]:
                    try:
                        expired = expired or int(morsel["max-age"]) <= 0
                    except ValueError:
                        pass
                if morsel["expires"]:
                    try:
                        expires = parsedate_to_datetime(morsel["expires"])
                        if expires.tzinfo is None:
                            expires = expires.replace(tzinfo=timezone.utc)
                        expired = expired or expires <= datetime.now(timezone.utc)
                    except (TypeError, ValueError, OverflowError):
                        pass
                if expired:
                    invalidated.add(key)
                    self._cookies.pop(key, None)
                    if key == "csrftoken":
                        self._csrf = ""
                    continue
                self._cookies[key] = morsel.value
                self._remember(morsel.value)
                if key == "csrftoken":
                    self._csrf = morsel.value
        return invalidated

    def _fixed_logout_redirect(self, response) -> bool:
        """Acknowledge the observed logout response without following it."""
        location = response.getheader("Location")
        if not isinstance(location, str) or any(c in location for c in "\\\r\n\x00"):
            return False
        try:
            parts = urlsplit(location)
            if parts.fragment or parts.query or parts.username or parts.password or parts.path not in {"/", "/login"}:
                return False
            if parts.scheme or parts.netloc:
                return parts.scheme == "https" and parts.hostname == self._host and (parts.port or 443) == self._port
            return location in {"/", "/login"}
        except ValueError:
            return False

    def _http(self, method: str, path: str, body: bytes | None = None, *, cleanup: bool = False, stage: str = "collection", timeout_seconds: float | None = None) -> Any:
        if self._closed:
            raise self._error("transport", "Transport is closed", stage=stage)
        if not cleanup:
            self.check_cancelled()
            if self._circuit:
                raise self._error(self._circuit.kind, "Further requests stopped after " + self._circuit.kind, http_status=self._circuit.http_status, stage=stage)
        retries = 1 if method == "GET" else 0
        request_timeout = self._timeout if timeout_seconds is None else float(timeout_seconds)
        for attempt in range(retries + 1):
            if not cleanup:
                self.check_cancelled()
                if self.metrics["requests"] - self.metrics["cleanup_requests"] >= self._request_budget:
                    raise self._error("budget", "Request budget exhausted", stage=stage)
            if self._last_request_at is not None:
                self._pause(max(0, self._min_interval - (time.monotonic() - self._last_request_at)), cleanup=cleanup)
            headers = self._headers()
            if body is not None:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            connection = None
            status = None
            transient = False
            try:
                connection = http.client.HTTPSConnection(self._host, self._port, timeout=request_timeout, context=self._context)
                self._last_request_at = time.monotonic()
                self.metrics["requests"] += 1
                if cleanup:
                    self.metrics["cleanup_requests"] += 1
                deadline = time.monotonic() + request_timeout
                connection.request(method, path, body=body, headers=headers)
                response = connection.getresponse()
                if self._verify_tls:
                    self.transport_security["tls_verified"] = True
                    self.transport_security["peer_identity_verified"] = True
                status = int(response.status)
                counts = self.metrics["http_status_counts"]
                counts[str(status)] = counts.get(str(status), 0) + 1
                header_kind = {401: "authentication", 403: "permission", 429: "rate_limit"}.get(status)
                if status == 403 and stage == "authentication":
                    header_kind = "authentication"
                if status in {401, 429} or header_kind == "authentication":
                    # The status already establishes the stop condition. An
                    # unreadable error body must not postpone the circuit or
                    # turn this response into a transient GET retry.
                    self._circuit = self._error(header_kind, f"HTTP {status}", http_status=status, stage=stage)
                    self.metrics["circuit_open"] = header_kind
                invalidated = self._capture_cookies(response)
                if stage == "authentication" and 200 <= status < 300 and self._cookies.keys() & _AVI_SESSION_COOKIES:
                    self._avi_authenticated = True
                try:
                    raw = self._read_body(response, connection, deadline, cleanup=cleanup, stage=stage, timeout_seconds=request_timeout)
                except (CollectionError, OSError, http.client.HTTPException) as exc:
                    if not header_kind or isinstance(exc, CollectionError) and exc.kind == "cancelled":
                        raise
                    detail = f"{exc.kind}: {exc.reason}" if isinstance(exc, CollectionError) else f"{type(exc).__name__}: {exc}"
                    raise self._error(header_kind, f"HTTP {status}; response body read failed: {detail}",
                                      http_status=status, stage=exc.stage if isinstance(exc, CollectionError) else stage) from None
                if len(raw) > _MAX_RESPONSE:
                    raise self._error("budget", "Response size exceeds the 32 MiB in-memory limit", http_status=status, stage=stage)
                if 300 <= status < 400:
                    if self._product == "avi" and method == "POST" and path == "/logout" and stage == "logout" and status == 302 and self._fixed_logout_redirect(response):
                        self.metrics["logout_state"] = "accepted_logout_redirect"
                        self.metrics["logout_server_revocation_verified"] = False
                        self.transport_security["logout_note"] = "The fixed same-origin logout response was accepted without following it; server-side revocation is not actively verified for every session"
                        return None
                    raise self._error("transport", "Redirect refused; credentials remain on the selected target", http_status=status, stage=stage)
                if not 200 <= status < 300:
                    kind = {401: "authentication", 403: "permission", 404: "unsupported", 405: "unsupported", 429: "rate_limit"}.get(status, "transport")
                    if status == 403 and (stage == "authentication" or self._product == "nsx" and self._nsx_auth_rejected(raw)):
                        kind = "authentication"
                    reason = self._http_reason(raw, status)
                    error = self._error(kind, reason, http_status=status, stage=stage)
                    if status in {401, 429} or kind == "authentication":
                        self._circuit = error
                        self.metrics["circuit_open"] = kind
                    if status == 503 and response.getheader("Retry-After"):
                        error = self._error("rate_limit", "Server reported pressure; further collection requests stopped", http_status=status, stage=stage)
                        self._circuit = error
                        self.metrics["circuit_open"] = "rate_limit"
                    transient = status in {408, 500, 502, 503, 504} and self._circuit is None
                    raise error
                if stage == "logout":
                    self.metrics["logout_state"] = "accepted_http_success"
                    self.metrics["logout_server_revocation_verified"] = False
                    return None
                if not raw.strip():
                    if stage == "logout" or stage == "authentication" and self._avi_authenticated:
                        return None
                    raise self._error("invalid_response", "Empty response; no data was collected", http_status=status, stage="parse")
                try:
                    return json.loads(raw.decode("utf-8-sig"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    reason = f"{type(exc).__name__}: {getattr(exc, 'msg', 'invalid UTF-8 JSON')}"
                    if hasattr(exc, "lineno"):
                        reason += f"; line={exc.lineno}, column={exc.colno}, position={exc.pos}"
                    raise self._error("invalid_response", reason, http_status=status, stage="parse") from None
            except (ssl.SSLCertVerificationError, ssl.SSLError) as exc:
                error = self._error("tls", f"{type(exc).__name__}: {exc}", stage="tls")
            except (socket.timeout, TimeoutError) as exc:
                transient = True
                error = self._error("timeout", f"{type(exc).__name__}: request timed out", http_status=status, stage=stage)
            except (OSError, http.client.HTTPException) as exc:
                transient = True
                error = self._error("transport", f"{type(exc).__name__}: {exc}", stage=stage)
            except CollectionError as exc:
                error = self._error(exc.kind, exc.reason, http_status=status, stage=exc.stage) if exc.http_status is None and status is not None else exc
                transient = transient or exc.kind == "timeout"
            finally:
                if connection is not None:
                    connection.close()
            if not transient or attempt >= retries or cleanup:
                raise error from None
            self.metrics["retries"] += 1
            self._pause(0.25 * (attempt + 1))
        raise self._error("transport", "Request did not complete", stage=stage)

    def _read_body(self, response, connection, deadline: float, *, cleanup: bool, stage: str, timeout_seconds: float) -> bytes:
        """Bound total body time as well as bytes; check cancellation per chunk."""
        data = bytearray()
        reader = getattr(response, "read1", response.read)
        while True:
            if not cleanup:
                self.check_cancelled()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise self._error("timeout", "Response exceeded the total request time budget", stage=stage)
            sock = getattr(connection, "sock", None)
            if sock is not None:
                sock.settimeout(max(0.001, min(timeout_seconds, remaining)))
            chunk = reader(min(65536, _MAX_RESPONSE + 1 - len(data)))
            if not chunk:
                return bytes(data)
            self.metrics["response_bytes"] += len(chunk)
            data.extend(chunk)
            if len(data) > _MAX_RESPONSE:
                raise self._error("budget", "Response size exceeds the 32 MiB in-memory limit", stage=stage)

    def _http_reason(self, raw: bytes, status: int) -> str:
        reason = f"HTTP {status}"
        try:
            value = json.loads(raw.decode("utf-8-sig"))
            if isinstance(value, dict):
                for field in ("error_message", "message", "detail", "error"):
                    if isinstance(value.get(field), (str, int)):
                        diagnostic_secrets = (*self.secret_values, self._username) if self._username else self.secret_values
                        reason += ": " + _safe_reason(value[field], diagnostic_secrets)
                        break
        except (ValueError, UnicodeError):
            pass
        return reason

    @staticmethod
    def _nsx_auth_rejected(raw: bytes) -> bool:
        """Identify the observed NSX authentication rejection, in memory only.

        A bare HTTP 403/error_code 403 is also used for object permissions and
        must not stop unrelated reads. Match only the known authentication
        message rather than treating every forbidden response as bad login.
        """
        try:
            value = json.loads(raw.decode("utf-8-sig"))
        except (ValueError, UnicodeError):
            return False
        message = value.get("error_message") if isinstance(value, dict) else None
        if not isinstance(message, str):
            return False
        normalized = " ".join(message.casefold().split()).rstrip(".")
        return normalized == "the credentials were incorrect or the account specified has been locked"

    def get(self, key: str, path_params=None, query=None) -> Any:
        route, path, values = self._resolve(key, path_params, query)
        if self._product == "avi" and not self._avi_authenticated:
            raise self._error("authentication", "AVI session login is required before collection", stage="authentication")
        return self._http("GET", path + ("?" + urlencode(values) if values else ""), timeout_seconds=route.timeout_seconds)

    def login_avi(self) -> None:
        if self._product != "avi":
            raise self._error("authentication", "AVI login is not available for this product", stage="authentication")
        if self._avi_authenticated:
            return
        body = urlencode({"username": self._username, "password": self._password}).encode("utf-8")
        self._remember(body.decode("utf-8"))
        self._http("POST", "/login", body, stage="authentication")
        if not self._cookies.keys() & _AVI_SESSION_COOKIES:
            raise self._error("authentication", "AVI login returned no session cookie", stage="authentication")
        self._avi_authenticated = True

    def logout_avi(self) -> None:
        if self._product != "avi" or not self._avi_authenticated or self._logout_attempted or self._closed:
            return
        self._logout_attempted = True
        try:
            # One reserved cleanup request is allowed even after cancellation,
            # an exhausted read budget or an authentication/rate-limit circuit.
            self._http("POST", "/logout", b"", cleanup=True, stage="logout")
        finally:
            self._avi_authenticated = False
            self._cookies.clear()
            self._csrf = ""

    def _next_avi(self, next_value: Any, expected_path: str, route: Route) -> dict:
        if not isinstance(next_value, str) or len(next_value) > 4096 or any(c in next_value for c in "\\\r\n\x00"):
            raise self._error("invalid_response", "Invalid AVI pagination link", stage="pagination")
        parts = urlsplit(next_value)
        if parts.fragment or parts.username or parts.password:
            raise self._error("invalid_response", "Pagination link contains a forbidden URL component", stage="pagination")
        if parts.scheme or parts.netloc:
            try:
                matches = parts.scheme == "https" and parts.hostname == self._host and (parts.port or 443) == self._port
            except ValueError:
                matches = False
            if not matches:
                raise self._error("invalid_response", "Cross-target pagination link refused", stage="pagination")
        if parts.path not in {"", expected_path} or parts.path.startswith("//"):
            raise self._error("invalid_response", "Pagination link does not match the allowlisted resource", stage="pagination")
        pairs = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True)
        if len({key for key, _ in pairs}) != len(pairs) or any(key not in route.query_parameters for key, _ in pairs):
            raise self._error("invalid_response", "Pagination query is not in the reviewed allowlist", stage="pagination")
        if not pairs:
            raise self._error("invalid_response", "Pagination link has no continuation query", stage="pagination")
        return dict(pairs)

    def list_pages(self, key: str, kind: str = "nsx", query=None, path_params=None) -> dict:
        items, errors, sources = [], [], []
        complete = False
        seen = set()
        values = dict(query or {})
        expected_total = None
        try:
            if kind not in {"nsx", "avi"} or kind != self._product:
                raise self._error("unsupported", "Pagination kind does not match the selected product", stage="pagination")
            route, path, _ = self._resolve(key, path_params, values)
            for _ in range(self._page_budget):
                self.check_cancelled()
                _, _, normalized = self._resolve(key, path_params, values)
                marker = tuple(sorted(normalized.items()))
                if marker in seen:
                    raise self._error("invalid_response", "Repeated pagination cursor or page", stage="pagination")
                seen.add(marker)
                response = self.get(key, path_params=path_params, query=values)
                self.metrics["pages"] += 1
                sources.append({"path": path, "method": "GET", "collected_at": datetime.now(timezone.utc).isoformat(),
                                "version_basis": route.version_basis, "page": len(sources) + 1})
                if not isinstance(response, dict) or not isinstance(response.get("results"), list):
                    raise self._error("invalid_response", "List response has no results array", stage="pagination")
                batch = response["results"]
                if not all(isinstance(item, dict) for item in batch):
                    raise self._error("invalid_response", "List response contains a non-object record", stage="pagination")
                total = response.get("result_count" if kind == "nsx" else "count")
                count_error = ""
                if isinstance(total, int) and not isinstance(total, bool) and total >= 0:
                    if expected_total is None:
                        expected_total = total
                    elif expected_total != total:
                        count_error = "Declared record count changed during collection; coverage cannot be confirmed"
                elif total is not None:
                    count_error = "Declared record count is not a non-negative integer"
                remaining = self._record_budget - self.metrics["records"]
                accepted = batch[:max(0, remaining)]
                items.extend(accepted)
                self.metrics["records"] += len(accepted)
                if len(accepted) < len(batch):
                    raise self._error("budget", "Record budget exhausted; previously collected records retained", stage="pagination")
                if count_error:
                    raise self._error("invalid_response", count_error, stage="pagination")
                continuation = response.get("cursor" if kind == "nsx" else "next")
                if not continuation:
                    if expected_total is not None and len(items) != expected_total:
                        raise self._error("invalid_response", "Collected records do not match the declared record count", stage="pagination")
                    complete = True
                    break
                if self.metrics["records"] >= self._record_budget:
                    raise self._error("budget", "Record budget exhausted; previously collected records retained", stage="pagination")
                if not batch:
                    raise self._error("invalid_response", "Empty page has a continuation; stopping unproductive pagination", stage="pagination")
                if kind == "nsx":
                    if "cursor" not in route.query_parameters or not isinstance(continuation, str):
                        raise self._error("invalid_response", "Unsupported NSX cursor response", stage="pagination")
                    values = {**values, "cursor": continuation}
                else:
                    try:
                        values = self._next_avi(continuation, path, route)
                    except ValueError:
                        raise self._error("invalid_response", "Malformed pagination query", stage="pagination") from None
            else:
                raise self._error("budget", "Page budget exhausted; previously collected records retained", stage="pagination")
        except CollectionError as exc:
            errors.append(exc.as_dict())
        return {"items": items, "complete": complete, "errors": errors, "sources": sources}

    def close(self) -> None:
        if self._closed:
            return
        try:
            self.logout_avi()
        except CollectionError as exc:
            self.metrics["logout_error"] = exc.as_dict()
        finally:
            self._closed = True
            self._cookies.clear()
            self._csrf = ""
            self._username = ""
            self._password = ""
            self._tenant = ""
            self._secrets.clear()
            self._remember_credential_secret = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
