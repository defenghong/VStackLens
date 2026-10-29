"""Bounded NSX 4.2.3 reads and conservative, evidence-bearing checks.

Only the static routes below are callable.  The instance's Manager and Policy
specifications are independent gates; a documentation example is never runtime
proof.  Raw API documents, certificate PEM and licensing secrets stay in memory.
"""
from __future__ import annotations

import re
from typing import Any

from .model import finish_module, make_check, make_source, new_module, sanitize_public
from .certificates import certificate_dates as _certificate_dates
from .management_scope import alarm_lifecycle_of, mark_management_scope, resolve_scope, select_routes
from .transport import CollectionError, ReadTransport, Route


DOC = "https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/4.2.3/"
VERSION_BASIS = "NSX API Guide 4.2.3.0.0 + 当次实例 OpenAPI"
BUSINESS_LIMIT = "实验能力／待真实业务验收；配置和已有状态不证明实际流量、转发或拦截成功。"
NO_THRESHOLD = "没有客户业务基线，不设置统一资源、冗余数量或路由完整性阈值。"


def _route(path, purpose, page=False, parameters=(), timeout=None):
    return Route(path, purpose, VERSION_BASIS, tuple(("cursor",) if page else ()) + tuple(parameters), timeout_seconds=timeout)


# Read semantics were checked against the 4.2.3 guide, not inferred from GET.
# No diagnostics, report creation, refresh, action or arbitrary proxy routes.
ROUTES = {
    "manager_spec": _route("/api/v1/spec/openapi/nsx_api.json", "读取本机 Manager OpenAPI 说明", timeout=45),
    "policy_spec": _route("/api/v1/spec/openapi/nsx_policy_api.json", "读取本机 Policy OpenAPI 说明", timeout=45),
    "node": _route("/api/v1/node", "读取本机版本与身份"),
    "cluster": _route("/api/v1/cluster", "读取集群配置与身份"),
    "cluster_status": _route("/api/v1/cluster/status", "读取集群原生状态"),
    "nodes": _route("/api/v1/cluster/nodes", "读取集群节点配置", True),
    "cluster_certificate": _route("/api/v1/cluster/api-certificate", "读取管理集群当前使用证书ID"),
    "certificate_details": _route("/api/v1/trust-management/certificates/{certificate_id}", "读取已绑定证书，仅内存解析有效期"),
    "node_runtime": _route("/api/v1/cluster/nodes/{node_id}/status", "读取指定管理节点运行状态"),
    "node_resources": _route("/api/v1/cluster/{node_id}/node/status", "读取指定设备内部资源"),
    "local_resources": _route("/api/v1/node/status", "读取当前设备内部资源"),
    "interfaces": _route("/api/v1/cluster/nodes/{node_id}/network/interfaces", "读取指定节点接口", True),
    "local_interfaces": _route("/api/v1/node/network/interfaces", "读取当前设备接口", True),
    "dns": _route("/api/v1/cluster/{node_id}/node/network/name-servers", "读取指定节点DNS配置"),
    "local_dns": _route("/api/v1/node/network/name-servers", "读取当前设备DNS配置"),
    "search_domains": _route("/api/v1/cluster/{node_id}/node/network/search-domains", "读取DNS搜索域"),
    "ntp": _route("/api/v1/cluster/{node_id}/node/services/ntp", "读取NTP配置"),
    "ntp_status": _route("/api/v1/cluster/{node_id}/node/services/ntp/status", "读取已有NTP服务状态"),
    "syslog": _route("/api/v1/cluster/{node_id}/node/services/syslog/exporters", "读取日志目标配置", True),
    "syslog_status": _route("/api/v1/cluster/{node_id}/node/services/syslog/status", "读取已有日志服务状态"),
    "services": _route("/api/v1/cluster/{node_id}/node/services", "读取管理服务清单", True),
    "alarms": _route("/api/v1/alarms", "仅读取既有原生告警", True),
    "licenses": _route("/api/v1/licenses", "读取授权类型与容量，输出剔除密钥", True),
    "backup": _route("/api/v1/cluster/backups/overview", "读取已有备份配置与结果"),
    "compute_managers": _route("/api/v1/fabric/compute-managers", "读取登记清单，不连接所登记系统", True),
    "compute_status": _route("/api/v1/fabric/compute-managers/{compute_id}/status", "读取NSX保存的计算管理器连接状态"),
    "compute_state": _route("/api/v1/fabric/compute-managers/{compute_id}/state", "读取NSX登记实现状态"),
    "transport_nodes": _route("/api/v1/transport-nodes", "读取传输节点部署及配置", True),
    "transport_status": _route("/api/v1/transport-nodes/{transport_id}/status", "读取已有管理控制连接与节点状态"),
    "transport_modules": _route("/api/v1/transport-nodes/{transport_id}/modules", "读取已安装组件与版本（4.2.3仍列出，运行时规格门控）"),
    "transport_resources": _route("/api/v1/transport-nodes/{transport_id}/node/status", "读取Edge设备内部资源"),
    "tunnels": _route("/api/v1/transport-nodes/{transport_id}/tunnels", "读取既有隧道两端与BFD状态", True),
    "uplink_profile": _route("/api/v1/host-switch-profiles/{profile_id}", "读取被引用上联配置的MTU与传输VLAN"),
    "remote_transport_status": _route("/api/v1/transport-nodes/{transport_id}/remote-transport-node-status", "读取已有两端连接状态", True),
    "edge_clusters": _route("/api/v1/edge-clusters", "读取Edge集群配置", True),
    "edge_cluster_status": _route("/api/v1/edge-clusters/{edge_cluster_id}/status", "读取Edge集群与成员状态"),
    "segments": _route("/policy/api/v1/infra/segments", "读取业务网络配置", True),
    "segment_ports": _route("/policy/api/v1/infra/segments/{segment_id}/ports", "读取网络端口与关联对象", True),
    "port_status": _route("/policy/api/v1/infra/segments/{segment_id}/ports/{port_id}/status", "读取端口既有运行状态"),
    "domains": _route("/policy/api/v1/infra/domains", "读取可见安全域", True),
    "groups": _route("/policy/api/v1/infra/domains/{domain_id}/groups", "读取策略引用对象", True),
    "security_policies": _route("/policy/api/v1/infra/domains/{domain_id}/security-policies", "读取安全策略", True),
    "security_rules": _route("/policy/api/v1/infra/domains/{domain_id}/security-policies/{policy_id}/rules", "读取策略规则及作用范围", True),
    "gateway_policies": _route("/policy/api/v1/infra/domains/{domain_id}/gateway-policies", "读取可见安全域的网关防火墙策略", True),
    "gateway_rules": _route("/policy/api/v1/infra/domains/{domain_id}/gateway-policies/{policy_id}/rules", "读取网关防火墙规则", True),
    "realized_status": _route("/policy/api/v1/infra/realized-state/status", "读取既有配置实现状态", parameters=("intent_path",)),
    "service_definitions": _route("/policy/api/v1/infra/services", "读取安全规则服务引用", True),
}
for _service in ("manager", "node-mgmt", "datastore", "nsx-message-bus", "controller", "cluster_manager", "cm-inventory", "http"):
    ROUTES["service_" + _service.replace("-", "_")] = _route("/api/v1/cluster/{node_id}/node/services/" + _service + "/status", "读取固定关键管理服务状态")
for _tier in ("tier-0s", "tier-1s"):
    _key = "t0" if _tier == "tier-0s" else "t1"
    _base = "/policy/api/v1/infra/" + _tier
    ROUTES[_key] = _route(_base, "读取网关配置", True)
    ROUTES[_key + "_state"] = _route(_base + "/{gateway_id}/state", "读取网关已有实现与HA状态")
    ROUTES[_key + "_static_routes"] = _route(_base + "/{gateway_id}/static-routes", "读取已配置静态路由", True)
    ROUTES[_key + "_locales"] = _route(_base + "/{gateway_id}/locale-services", "读取网关地域服务", True)
    ROUTES[_key + "_interfaces"] = _route(_base + "/{gateway_id}/locale-services/{locale_id}/interfaces", "读取网关接口", True)
    ROUTES[_key + "_nat"] = _route(_base + "/{gateway_id}/nat", "读取网关NAT区段", True)
    ROUTES[_key + "_nat_rules"] = _route(_base + "/{gateway_id}/nat/{nat_id}/nat-rules", "读取现有NAT规则", True)
ROUTES["bgp_neighbors"] = _route("/policy/api/v1/infra/tier-0s/{gateway_id}/locale-services/{locale_id}/bgp/neighbors", "读取已配置BGP邻居", True)
ROUTES["bgp_status"] = _route("/policy/api/v1/infra/tier-0s/{gateway_id}/locale-services/{locale_id}/bgp/neighbors/status", "读取已有BGP连接状态", True)


_MATRIX_ROWS = (
    ("version", "A1 版本、构建、身份与可见范围", "node,cluster,nodes", "版本及稳定身份；成功读取仅证明当前账号可见范围"),
    ("cluster", "A2 集群与Manager部署成员", "cluster_status,nodes,node_runtime", "原生角色与Manager成员分别判断后保守汇总；Manager设备只计manager_role记录，控制角色配置不充设备数量"),
    ("services", "A2 Manager关键服务", "services,service_*", "与原生集群健康独立；已核Manager角色的关键服务按生命周期判断，其他停止状态保留适用性复核"),
    ("resources", "A3 设备内部资源与分区", "node_resources,local_resources,node_runtime", "字段完整仅代表采集完整；无阈值或原生资源健康结论时需按业务基线复核，不由快照断言负载健康"),
    ("alarms", "A4 NSX原生告警", "alarms", "原生状态、严重程度和建议，不映射P等级"),
    ("certificates", "A5 管理证书", "nodes,cluster_certificate,certificate_details", "证书有效期与当前UTC比较；不设临近到期天数阈值"),
    ("licenses", "A6 授权、能力与容量", "licenses", "原生过期状态；不输出授权密钥"),
    ("backup", "A7 备份计划与既有结果", "backup", "部署和版本证据限定组件适用性；未知适用性或缺适用结果不作整体正常／完整结论，配置、原生整体状态与各组件历史分别表达"),
    ("dns", "A8 DNS配置", "dns,local_dns,search_domains", "配置不证明解析可用"),
    ("ntp", "A8 NTP配置与服务", "ntp,ntp_status", "服务运行不证明时间同步或服务器可达"),
    ("syslog", "A8 远程日志", "syslog,syslog_status", "配置与本机服务不证明远端收到日志"),
    ("interfaces", "A8 管理网卡", "interfaces,local_interfaces", "逐接口链路状态，不执行主动诊断"),
    ("vcenter", "B1 vCenter登记与已有状态", "compute_managers,compute_status,compute_state", "独立部署未登记是not_deployed，不是Manager异常"),
    ("hosts", "B2 ESXi NSX接入", "transport_nodes,transport_status,transport_modules", "部署、组件与管理控制连接原值；不复写ESXi通用资产"),
    ("uplink_tunnels", "B3 上联与隧道", "transport_nodes,uplink_profile,tunnels,remote_transport_status", "已有端点和两端状态，不发送测试流量"),
    ("segments", "B4 业务网络与端口", "segments,segment_ports,port_status,realized_status", "配置、关联及已有实现状态分别展示"),
    ("edge", "B5 Edge、集群与冗余", "transport_nodes,transport_status,transport_resources,edge_clusters,edge_cluster_status", "逐节点和组状态，不执行切换、不自设冗余数量标准"),
    ("gateways", "B6 网关、路由与BGP", "t0,t1,*_interfaces,*_static_routes,bgp_neighbors,bgp_status,*_state", "没有预期路由清单不判断完整正确"),
    ("nat", "B7 NAT规则", "t0_nat,t1_nat,*_nat_rules", "启停、转换地址端口及关联对象；不证明转发成功"),
    ("security", "B8 安全策略与下发状态", "domains,security_policies,security_rules,groups,service_definitions,realized_status,gateway_policies,gateway_rules", "宽泛放行人工复核，不断言错误或建议删除"),
)
CHECK_MATRIX = [dict(id="nsx." + key, title=title, data=basis, source=source,
                     version_basis=VERSION_BASIS, judgement_basis=basis,
                     limitations=BUSINESS_LIMIT if key in {"hosts", "uplink_tunnels", "segments", "edge", "gateways", "nat", "security"} else NO_THRESHOLD,
                     verification="pending_live_comparison") for key, title, source, basis in _MATRIX_ROWS]


def _dict(value):
    return value if isinstance(value, dict) else {}


def _list(value):
    return value if isinstance(value, list) else []


def _text(value):
    return value if isinstance(value, (str, int, float, bool)) else None


def _pick(value, fields):
    """Explicit field projection; unknown nested objects never pass through."""
    data = _dict(value)
    return {name: data[name] for name in fields if name in data and isinstance(data[name], (str, int, float, bool, type(None)))}


def _strings(value):
    return [item for item in _list(value) if isinstance(item, (str, int, float, bool))]


def _identity(value):
    return _pick(value, ("id", "node_uuid", "uuid", "display_name", "resource_type", "path"))


def _id(value, *names):
    for name in names or ("id", "node_uuid", "uuid"):
        candidate = _dict(value).get(name)
        if isinstance(candidate, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}", candidate) and candidate not in {".", ".."}:
            return candidate
    raise CollectionError("invalid_response", "接口没有返回安全可用的对象ID。")


def _state(values):
    states = [str(value).upper() for value in values if isinstance(value, str) and value]
    bad = {"DOWN", "FAILED", "FAILURE", "ERROR", "UNSTABLE", "STOPPED", "DISCONNECTED", "UNHEALTHY", "UNREACHABLE", "READ_ONLY", "INSTALL_FAILED", "UPGRADE_FAILED"}
    attention = {"DEGRADED", "PARTIAL", "WARNING", "PARTIALLY_CONNECTED", "IN_PROGRESS"}
    good = {"UP", "STABLE", "CONNECTED", "RUNNING", "HEALTHY", "SUCCESS", "SUCCEEDED", "SUCCESSFUL", "REALIZED", "IN_SYNC", "INSTALL_SUCCESSFUL", "NODE_READY", "TRANSPORT_NODE_READY", "ACTIVE", "STANDBY"}
    if any(value in bad or value.endswith("_FAILED") for value in states):
        return "abnormal"
    if any(value in attention for value in states):
        return "attention"
    if not states or any(value is None for value in values) or any(value not in good for value in states):
        return "insufficient_data"
    return "normal"


class InstanceSpec:
    """Strict local document matching for Swagger2 and OpenAPI3 paths."""
    def __init__(self, document):
        if not isinstance(document, dict) or not isinstance(document.get("paths"), dict):
            raise CollectionError("invalid_response", "实例接口说明缺少paths对象。", stage="specification")
        version = document.get("swagger") or document.get("openapi")
        if not isinstance(version, str) or not (version == "2.0" or version.startswith("3.")):
            raise CollectionError("invalid_response", "实例接口说明格式版本无法识别。", stage="specification")
        base = document.get("basePath", "")
        if not isinstance(base, str) or (base and (not base.startswith("/") or "?" in base or "#" in base or ".." in base)):
            raise CollectionError("invalid_response", "实例接口说明basePath不合法。", stage="specification")
        self.document = document
        self.base = base.rstrip("/")
        self.bases = [self.base]
        for server in _list(document.get("servers")):
            url = _dict(server).get("url")
            if isinstance(url, str) and url.startswith("/") and not url.startswith("//") and not any(char in url for char in ("?", "#", "{", "}")) and ".." not in url:
                self.bases.append(url.rstrip("/"))
        self.version = _text(_dict(document.get("info")).get("version"))

    def _resolve(self, value):
        seen = set()
        for _ in range(12):
            if not isinstance(value, dict) or "$ref" not in value:
                return value
            ref = value.get("$ref")
            if not isinstance(ref, str) or not ref.startswith("#/") or ref in seen:
                return None
            seen.add(ref)
            current = self.document
            for token in ref[2:].split("/"):
                current = _dict(current).get(token.replace("~1", "/").replace("~0", "~"))
            value = current
        return None

    def item(self, path):
        def shape(value):
            return re.sub(r"\{[^{}]+\}", "{}", value)
        for key, raw in self.document["paths"].items():
            if not isinstance(key, str):
                continue
            if shape(path) in {shape(key), *(shape(base + key) for base in self.bases)}:
                item = self._resolve(raw)
                if isinstance(item, dict) and isinstance(self._resolve(item.get("get")), dict):
                    return item
        return None

    def supports(self, route):
        return self.item(route.path) is not None

    def parameter(self, route, name):
        item = self.item(route.path)
        if item is None:
            return False
        operation = _dict(self._resolve(item.get("get")))
        for value in _list(item.get("parameters")) + _list(operation.get("parameters")):
            param = _dict(self._resolve(value))
            if param.get("in") == "query" and param.get("name") == name:
                return True
        return False


class _SpecDependencySkipped(CollectionError):
    """A local skip references one original spec failure, never a new request."""
    def __init__(self, domain, error):
        super().__init__(error.kind, "本机接口说明读取失败，后续接口未调用；原始错误见coverage.interface_specifications。",
                         http_status=error.http_status, stage="specification_dependency")
        self.domain = domain

    def as_dict(self):
        return {**super().as_dict(), "dependency": "coverage.interface_specifications." + self.domain, "request_attempted": False}


class _Collector:
    def __init__(self, target, credential, transport, *, management=True):
        self.target, self.credential, self.transport = target, credential, transport
        self.module = new_module(target)
        self.management = management
        if management:
            mark_management_scope(self.module)
        self.specs = {}
        self.spec_errors = {}
        self.sources, self.errors = [], []
        self.nodes, self.tns, self.gateways = [], [], []
        self.role_configurations = []
        self.node_data, self.cluster_data = {}, {}
        self.node_sources = []
        self.uplink_profiles = {}
        self.tns_available = False
        self.gateways_available = False
        self.transport_node_sources = []
        self.gateway_discovery_sources = []
        self.stop_error = None
        self.version_supported = True
        self.page_budget = 20
        self.record_budget = 2000
        self.record_count = 0
        self.successful_reads = 0
        self.hidden_values = []
        self._recorded_errors = set()
        self.security_supporting_records = {}
        self.matrix = {row["id"]: row for row in CHECK_MATRIX}
        self.verification = getattr(transport, "verification_level", "live_observed")
        if self.verification not in {"offline_replay", "live_observed"}:
            self.verification = "live_observed"

    def _error(self, error):
        if not isinstance(error, CollectionError):
            error = CollectionError("invalid_response", "本地解析失败，异常类型：" + type(error).__name__)
        safe = error.as_dict()
        self.errors.append(safe)
        # Dependency skips share the one retained original download/parse
        # failure.  A fatal error reused by later checks is also stored once.
        if not isinstance(error, _SpecDependencySkipped) and error not in self._recorded_errors:
            self.module["errors"].append(safe)
            self._recorded_errors.add(error)
        if error.kind in {"authentication", "rate_limit", "budget", "cancelled"}:
            self.stop_error = error
        return error

    def _get(self, key, params=None, query=None):
        self.transport.check_cancelled()
        if self.stop_error:
            raise self.stop_error
        route = ROUTES[key]
        path = route.path
        for name, value in (params or {}).items():
            path = path.replace("{" + name + "}", str(value))
        source = make_source(path, version_basis=VERSION_BASIS)
        source["object_parameters"] = dict(params or {})
        source["attempted"] = False
        self.sources.append(source)
        if key not in {"manager_spec", "policy_spec"}:
            domain = "policy" if route.path.startswith("/policy/") else "manager"
            if domain not in self.specs:
                source["note"] = "依赖本机接口说明读取失败；本接口未调用，见coverage.interface_specifications。"
                cause = self.spec_errors.get(domain) or CollectionError("invalid_response", "本机对应接口说明未读取。", stage="specification")
                raise _SpecDependencySkipped(domain, cause)
            if not self.specs[domain].supports(route):
                raise CollectionError("unsupported", "本机接口说明未列出该读取接口。", stage="specification")
            if key != "node" and not self.version_supported:
                raise CollectionError("unsupported", "检测版本未在4.2.3首批验证范围，跳过后续采集。", stage="version")
            for name in query or {}:
                if name not in route.query_parameters or not self.specs[domain].parameter(route, name):
                    raise CollectionError("unsupported", "本机接口说明未确认读取参数：" + name, stage="specification")
        source["attempted"] = True
        result = self.transport.get(key, path_params=params or {}, query=query or {})
        source["succeeded"] = True
        return result

    def read(self, key, params=None, query=None):
        try:
            data = self._get(key, params, query)
            if not isinstance(data, dict):
                raise CollectionError("invalid_response", "接口响应不是JSON对象。")
            self._remember_sensitive(data)
            self.successful_reads += 1
            return data
        except Exception as error:
            self._error(error)
            return None

    def _remember_sensitive(self, value, depth=0):
        if depth > 30:
            return
        if isinstance(value, dict):
            for name, item in value.items():
                normalized = str(name).lower().replace("-", "_")
                if normalized in {"password", "passwd", "passphrase", "license_key", "authorization", "cookie", "sessionid", "token", "access_token", "private_key"} and isinstance(item, str) and item:
                    self.hidden_values.append(item)
                    remember = getattr(self.credential, "remember_secret", None)
                    if remember:
                        remember(item)
                elif isinstance(item, (dict, list)):
                    self._remember_sensitive(item, depth + 1)
        elif isinstance(value, list):
            for item in value:
                self._remember_sensitive(item, depth + 1)

    def pages(self, key, params=None, list_field="results"):
        rows, seen, cursor, expected = [], set(), None, None
        for _ in range(self.page_budget):
            page = self.read(key, params, {"cursor": cursor} if cursor else {})
            if page is None:
                return rows
            self.transport.metrics["pages"] = self.transport.metrics.get("pages", 0) + 1
            if not isinstance(page.get(list_field), list) or any(not isinstance(row, dict) for row in page[list_field]):
                self._error(CollectionError("invalid_response", "列表响应" + list_field + "字段缺失或含无效对象。"))
                return rows
            if expected is None and isinstance(page.get("result_count"), int):
                expected = page["result_count"]
            remaining = self.record_budget - self.record_count
            accepted = page[list_field][:max(0, remaining)]
            rows.extend(accepted)
            self.record_count += len(accepted)
            self.transport.metrics["records"] = self.record_count
            if len(accepted) != len(page[list_field]):
                self._error(CollectionError("budget", "全目标记录预算已达上限，保留已取得数据。"))
                return rows
            cursor = page.get("cursor")
            if not cursor:
                if expected is not None and expected != len(rows):
                    self._error(CollectionError("invalid_response", "分页总数与result_count不一致，保留已取得数据。"))
                return rows
            if not isinstance(cursor, str) or cursor in seen:
                self._error(CollectionError("invalid_response", "分页游标无效或重复，停止该列表。"))
                return rows
            seen.add(cursor)
        self._error(CollectionError("budget", "分页预算已达上限，保留已取得数据。"))
        return rows

    def check(self, key, operation):
        self.sources, self.errors = [], []
        self.successful_reads = 0
        try:
            self.transport.check_cancelled()
            values, status, summary = operation()
        except Exception as error:
            self._error(error)
            values, status, summary = {}, "insufficient_data", "检查未取得可判断的数据。"
        if self.errors:
            kinds = {item.get("kind", item.get("type")) for item in self.errors}
            if "cancelled" in kinds:
                status = "cancelled"
            elif not self.successful_reads:
                status = "permission_denied" if kinds <= {"permission"} else "unsupported" if kinds <= {"unsupported"} else "collection_failed"
            elif status not in {"abnormal", "attention"}:
                status = "insufficient_data"
        row = self.matrix["nsx." + key]
        limitations = [row["limitations"]]
        if key in {"dns", "ntp", "syslog", "interfaces"}:
            limitations.append("未主动执行ping、解析、同步或日志发送测试。")
        if self.errors:
            limitations.append("存在接口失败或不完整数据；本项不能作为完整检查通过。")
        result = make_check("nsx." + key, row["title"], status, values=values, summary=summary,
                            sources=self.sources, judgement="NSX_NATIVE" if key == "alarms" else "PROGRAM",
                            basis=row["judgement_basis"], limitations=limitations,
                            verification=self.verification if values else "unverified",
                            completeness="partial" if self.errors or status == "insufficient_data" else "complete",
                            recommendation="结合管理页面核实缺失字段与业务基线。" if status not in {"normal", "not_deployed", "not_applicable"} else "")
        result["errors"] = list(self.errors)
        if key == "security" and self.security_supporting_records:
            result["supporting_records"] = self.security_supporting_records
            if _dict(values).get("unresolved_references"):
                result["completeness"] = "partial"
                result["limitations"].append("部分显式引用未在当次目录中匹配，关联检查不完整。")
        if key == "services" and _dict(values).get("unobserved_expected_services"):
            result["completeness"] = "partial"
        if key == "backup" and (_dict(values).get("applicability_review_required") or _dict(values).get("missing_applicable_results") or _dict(values).get("history_data_incomplete") or _dict(values).get("configuration_data_incomplete")):
            result["completeness"] = "partial"
            result["limitations"].append("组件部署适用范围或适用组件结果未完整核实；仅保留已读取组件的历史事实。")
        self.module["checks"].append(result)

    def load_specs(self):
        documents = (("manager", "manager_spec"),) if self.management else (("manager", "manager_spec"), ("policy", "policy_spec"))
        for domain, key in documents:
            self.sources, self.errors = [], []
            payload = self.read(key)
            try:
                if payload is None:
                    latest = self.errors[-1] if self.errors else {}
                    raise CollectionError(latest.get("kind", "invalid_response"), latest.get("reason", "实例接口说明读取失败。"), http_status=latest.get("http_status"), stage="specification")
                self.specs[domain] = InstanceSpec(payload)
            except CollectionError as error:
                self.spec_errors[domain] = error
                if payload is not None:
                    self._error(error)
            self.module.setdefault("coverage", {}).setdefault("interface_specifications", []).append({"kind": domain, "read": domain in self.specs,
                "version": self.specs[domain].version if domain in self.specs else None, "sources": list(self.sources), "errors": list(self.errors)})

    def version(self):
        data = self.read("node")
        if data is None:
            return {}, "insufficient_data", "版本与账号读取范围无法确认。"
        self.node_data = data
        version = data.get("product_version") or data.get("node_version")
        self.module["version"] = _text(version) or ""
        build = data.get("build_number") or data.get("build")
        if build is None and isinstance(version, str) and re.fullmatch(r"4\.2\.3\.\d+\.\d+\.\d{5,}", version):
            build = version.rsplit(".", 1)[1]
        self.module["build"] = _text(build) or ""
        identity = _pick(data, ("node_uuid", "uuid", "id", "hostname", "fully_qualified_domain_name", "node_type"))
        self.module["target_identity"] = {**_dict(self.module.get("target_identity")), **identity}
        values = {"product_version": _text(version), "build": _text(build), "identity": identity,
                  "account_scope": "当前提供账号成功读取的对象；未读取全角色权限表，不声明全局可见。"}
        if not isinstance(version, str) or not version:
            self.version_supported = False
            return values, "insufficient_data", "响应缺少可识别版本，无法确认版本适用范围。"
        self.version_supported = bool(re.match(r"^4\.2\.3(?:\.|$)", version))
        status = "normal" if self.version_supported and build is not None else "insufficient_data" if self.version_supported else "attention"
        return values, status, "读取到4.2.3版本分支；缺失构建号时保留数据不足。" if self.version_supported else "检测到非首批验证版本，后续读取跳过。"

    def cluster(self):
        self.cluster_data = self.read("cluster_status") or {}
        config = self.read("cluster") or {}
        self.role_configurations = self.pages("nodes")
        # ClusterNodeConfig is a role record, not necessarily an appliance.
        # In the 4.2.3 lab a controller-only UUID and one Manager UUID are
        # separate records.  Do not infer co-location from names or proxies.
        self.nodes, manager_ids = [], set()
        for node in self.role_configurations:
            if not isinstance(node.get("manager_role"), dict):
                continue
            try:
                manager_id = _id(node)
            except CollectionError as error:
                self._error(error)
                continue
            if manager_id not in manager_ids:
                self.nodes.append(node)
                manager_ids.add(manager_id)
        self.node_sources = list(self.sources)
        states, roles, nodes, configurations, member_states = [], [], [], [], []
        for role in ("mgmt_cluster_status", "control_cluster_status"):
            value = _dict(self.cluster_data.get(role))
            if value:
                safe = _pick(value, ("status",))
                safe["role"] = role
                safe["online_nodes"] = [_pick(item, ("uuid", "ip_address", "status")) for item in _list(value.get("online_nodes"))]
                roles.append(safe); states.append(safe.get("status"))
        for node in self.role_configurations:
            record = {**_identity(node), **_pick(node, ("appliance_mgmt_listen_addr", "appliance_management_ip")),
                      "roles": [role for role in ("manager_role", "controller_role") if isinstance(node.get(role), dict)],
                      "manager_appliance_record": isinstance(node.get("manager_role"), dict)}
            configurations.append(record)
        for node in self.nodes:
            nid = _id(node)
            runtime = self.read("node_runtime", {"node_id": nid}) or {}
            safe = {**_identity(node), **_pick(node, ("appliance_mgmt_listen_addr", "appliance_management_ip")), "roles": []}
            for role in ("manager_role", "controller_role"):
                if isinstance(node.get(role), dict):
                    safe["roles"].append(role)
            safe["runtime"] = {key: _pick(runtime.get(key), ("status", "mgmt_cluster_status", "control_cluster_status")) for key in ("mgmt_cluster_status", "control_cluster_status")}
            applicable_roles = ["mgmt_cluster_status"]
            if isinstance(node.get("controller_role"), dict):
                applicable_roles.append("control_cluster_status")
            native_states = [value for role in applicable_roles for value in safe["runtime"][role].values()]
            safe["member_assessment"] = _state(native_states)
            safe["member_state_values"] = native_states
            member_states.append(safe["member_assessment"])
            nodes.append(safe)
        self.module["inventory"].extend({"object_type": "NSXManagerNode", **row} for row in nodes)
        self.module["inventory"].extend({"object_type": "NSXClusterRoleConfiguration", **row} for row in configurations if not row["manager_appliance_record"])
        values = {"cluster_identity": _pick(config, ("cluster_id", "cluster_uuid", "id")), "actual_deployed_count": len(self.nodes),
                  "deployment_count_basis": "distinct manager_role appliance records; controller-only records excluded",
                  "role_configuration_count": len(configurations), "role_configurations": configurations, "roles": roles, "nodes": nodes,
                  "native_detailed_status": _pick(self.cluster_data.get("detailed_cluster_status"), ("cluster_id", "overall_status"))}
        role_assessment = _state(states)
        member_assessment = "abnormal" if "abnormal" in member_states else "attention" if "attention" in member_states else "insufficient_data" if not member_states or "insufficient_data" in member_states else "normal"
        values.update({"native_role_assessment": role_assessment, "manager_member_assessment": member_assessment,
                       "role_member_disagreements": [{"node_id": node.get("id") or node.get("node_uuid"),
                           "native_member_values": node["member_state_values"], "member_assessment": node["member_assessment"],
                           "note": "角色汇总与成员事实不一致，原生角色状态原值保留，不推断共同原因或实际影响。"}
                           for node in nodes if role_assessment == "normal" and node["member_assessment"] != "normal"]})
        if not roles or not nodes:
            return values, "insufficient_data", "集群角色或实际成员数据不足。"
        assessment = "abnormal" if "abnormal" in (role_assessment, member_assessment) else "attention" if "attention" in (role_assessment, member_assessment) else "insufficient_data" if "insufficient_data" in (role_assessment, member_assessment) else "normal"
        summary = "原生角色汇总与Manager成员状态分别保存；至少一个Manager成员接口报告异常，不能概括为正常。" if member_assessment == "abnormal" else "原生角色汇总与Manager成员状态分别保存；成员证据不完整，不能据角色STABLE认定全部正常。" if member_assessment == "insufficient_data" else "原生集群角色健康与Manager成员事实分别展示；控制角色配置不增加Manager设备数，服务状态另项保存。"
        return values, assessment, summary

    def manager_services(self):
        rows, missing_expected, statuses = [], [], []
        manager_required = {"manager", "node-mgmt", "datastore", "http"}
        for node in self.nodes:
            nid = _id(node)
            services = self.pages("services", {"node_id": nid})
            names = {str(row.get("service_name")) for row in services}
            missing_expected.extend({"node_id": nid, "service": name} for name in sorted(manager_required - names))
            for name in ("manager", "node-mgmt", "datastore", "nsx-message-bus", "controller", "cluster_manager", "cm-inventory", "http"):
                if name not in names:
                    continue
                native = self.read("service_" + name.replace("-", "_"), {"node_id": nid}) or {}
                record = {"node_id": nid, "service": name, **_pick(native, ("health", "runtime_state", "monitor_runtime_state"))}
                role_confirmed = name in manager_required or name == "controller" and isinstance(node.get("controller_role"), dict)
                record["role_applicability"] = "confirmed_manager_appliance" if name in manager_required else "confirmed_controller_role_on_same_record" if role_confirmed else "requires_role_review"
                runtime = str(record.get("runtime_state") or "").upper()
                health = record.get("health")
                if isinstance(health, str) and _state([health]) == "abnormal":
                    status = "abnormal"
                    basis = "NSX服务接口原生健康状态明确异常。"
                elif runtime in {"STOPPED", "DOWN", "FAILED", "ERROR"}:
                    status = "abnormal" if role_confirmed else "attention"
                    basis = "已核实角色的关键管理服务报告停止或失败。" if role_confirmed else "原生生命周期为停止；该服务在此版本与角色是否必须运行尚无依据，列适用性人工复核。"
                else:
                    status = _state([record.get("health") or record.get("runtime_state")])
                    basis = "只评价接口返回的服务生命周期／原生健康；不改写原生集群STABLE状态。"
                record.update({"assessment": status, "assessment_basis": basis,
                               "version_basis": DOC + "system_administration_configuration_fabric_nodes_nsx_manager_services.html"})
                rows.append(record); statuses.append(status)
        if any(status == "abnormal" for status in statuses):
            status = "abnormal"
        elif any(status == "attention" for status in statuses):
            status = "attention"
        elif missing_expected or not rows or any(status == "insufficient_data" for status in statuses):
            status = "insufficient_data"
        else:
            status = "normal"
        return {"services": rows, "unobserved_expected_services": missing_expected}, status, "Manager服务独立于集群原生健康；未核适用性的停止服务列关注，不据此宣布集群故障。"

    def _node_ids(self):
        for node in self.nodes:
            yield _id(node)

    def _inherit_empty_scope_sources(self, parent_check, sources):
        for source in sources:
            self.sources.append({**source, "inherited_from_check": parent_check,
                "dependency_only": True, "child_get_executed": False,
                "note": "依赖本轮完整已读的父对象空清单；保留该实际GET来源及原采集时间，本项未执行子对象GET。"})

    def _resources(self, data, *, edge=False):
        data = _dict(data)
        result = _pick(data, ("cpu_cores", "cpu_sockets", "mem_used", "mem_total", "mem_cache", "swap_used", "swap_total", "disk_space_used", "disk_space_total", "uptime", "system_time", "source", "remote_logging_server_configured"))
        result["load_average"] = _strings(data.get("load_average"))
        result["file_systems"] = [_pick(row, ("file_system", "mount", "type", "total", "used")) for row in _list(data.get("file_systems")) if isinstance(row, dict)]
        result["units"] = {"memory_disk_filesystems": "kilobytes", "uptime": "milliseconds", "load_average": "1/5/15 minute averages"}
        if edge:
            result["cpu_usage"] = _pick(data.get("cpu_usage"), ("avg_cpu_core_usage_dpdk", "avg_cpu_core_usage_non_dpdk", "highest_cpu_core_usage_dpdk", "highest_cpu_core_usage_non_dpdk"))
            result["edge_mem_usage"] = _pick(data.get("edge_mem_usage"), ("cache_usage", "datapath_total_usage", "swap_usage", "system_mem_usage"))
            result["units"]["edge_cpu_memory_usage"] = "percent; point-in-time"
        return result

    def resources(self):
        rows = []
        for nid in self._node_ids():
            data = self.read("node_resources", {"node_id": nid})
            if data is None:
                continue
            rows.append({"node_id": nid, **self._resources(data)})
        if not self.nodes:
            data = self.read("local_resources")
            if data is not None:
                rows.append({"scope": "entered_manager_only", **self._resources(data)})
        complete = bool(rows) and all(all(row.get(key) is not None for key in ("cpu_cores", "mem_total", "mem_used", "uptime")) and row["file_systems"] for row in rows)
        return {"nodes": rows, "threshold": None}, "attention" if complete else "insufficient_data", "已读取设备内部资源采样值，业务基线待复核；字段完整不代表负载健康，不依据快照断言长期过载。"

    def alarms(self):
        rows = self.pages("alarms")
        safe = []
        for row in rows:
            record = _pick(row, ("id", "status", "severity", "node_id", "entity_id", "entity_resource_type", "event_type", "event_type_display_name", "feature_name", "description", "recommended_action", "recommended_action_description", "last_reported_time", "first_reported_time", "last_updated_time"))
            record["origin"] = "NSX_NATIVE"
            record["lifecycle"] = alarm_lifecycle_of("nsx", record)
            safe.append(record)
        self.module["native_alerts"] = safe
        active = [row for row in safe if row["lifecycle"] == "active"]
        cleared = [row for row in safe if row["lifecycle"] == "cleared"]
        unknown = [row for row in safe if row["lifecycle"] == "unknown"]
        status = "insufficient_data" if unknown else "attention" if active else "normal"
        return {"total_read": len(rows), "unresolved_count": len(active), "active_count": len(active),
                "cleared_count": len(cleared), "unknown_state_count": len(unknown), "native_alerts": safe}, status, "原生状态、严重程度与时间原值保留；已清除属于历史，未知或屏蔽状态不按已清除处理。"

    def certificates(self):
        self.sources.extend(self.node_sources)
        records, missing = [], 0
        cluster_binding = self.read("cluster_certificate")
        if cluster_binding is not None:
            certificate_id = cluster_binding.get("certificate_id")
            if certificate_id:
                cid = _id(cluster_binding, "certificate_id")
                detail = self.read("certificate_details", {"certificate_id": cid})
                if detail is not None:
                    try:
                        records.append({"certificate_id": cid, "usage": "management_cluster_api", **_certificate_dates(detail.get("pem_encoded"))})
                    except (ValueError, IndexError, UnicodeError):
                        missing += 1
            elif "certificate_id" not in cluster_binding:
                missing += 1
        for node in self.nodes:
            for role in ("manager_role", "controller_role"):
                part = _dict(node.get(role))
                for usage in ("api_listen_addr", "mgmt_cluster_listen_addr", "control_cluster_listen_addr"):
                    listen = _dict(part.get(usage))
                    if not listen:
                        continue
                    try:
                        records.append({"node_id": _id(node), "usage": role + "." + usage, **_certificate_dates(listen.get("certificate"))})
                    except (ValueError, IndexError, UnicodeError):
                        missing += 1
        # The leaf identity comes from DER bytes.  Dates are one fact; every
        # observed use remains attached without merging names or IPs.
        certificate_facts = {}
        for record in records:
            digest = record["certificate_sha256"]
            fact = certificate_facts.setdefault(digest, {
                **_pick(record, ("certificate_sha256", "valid_from", "expires_at", "expired", "not_yet_valid")),
                "bindings": [],
            })
            binding = _pick(record, ("certificate_id", "node_id", "usage"))
            if binding not in fact["bindings"]:
                fact["bindings"].append(binding)
        records = list(certificate_facts.values())
        if not records:
            return {"certificates": [], "unparsed_bindings": missing}, "insufficient_data", "已检查节点接口证书绑定，未取得可解析的有效期。"
        status = "abnormal" if any(row["expired"] or row["not_yet_valid"] for row in records) else "insufficient_data" if missing else "normal"
        return {"certificates": records, "unparsed_bindings": missing, "near_expiry_threshold_days": None, "transport_security": dict(self.transport.transport_security)}, status, "仅展示证书用途和有效期；未验证证书链或设置临近到期阈值。"

    def licenses(self):
        rows = self.pages("licenses")
        safe = [_pick(row, ("description", "license_type", "capacity_type", "is_eval", "is_expired", "expiry", "quantity", "usage", "used_capacity", "capacity")) for row in rows]
        status = "abnormal" if any(row.get("is_expired") is True for row in safe) else "normal" if safe and all(row.get("is_expired") is False for row in safe) else "insufficient_data"
        return {"licenses": safe}, status, "授权能力与容量只显示接口提供字段；密钥已剔除。"

    def backup(self):
        data = self.read("backup")
        if data is None:
            return {}, "insufficient_data", "备份现有状态读取失败。"
        config = _dict(data.get("backup_config")); history = _dict(data.get("backup_operation_history"))
        schedule = _dict(config.get("backup_schedule"))
        schedule_returned = "backup_schedule" in config and isinstance(config.get("backup_schedule"), dict)
        safe_schedule = _pick(schedule, ("resource_type", "hour", "minute", "days_of_week", "interval", "interval_seconds", "enabled"))
        safe_schedule["days_of_week"] = _strings(schedule.get("days_of_week"))
        components = ("cluster_backup_statuses", "node_backup_statuses", "inventory_backup_statuses")
        completed, input_kinds = [], {}
        malformed = not isinstance(data.get("backup_operation_history"), dict)
        for name in components:
            raw = history.get(name)
            input_kinds[name] = "missing" if name not in history else "null" if raw is None else "empty_list" if raw == [] else "list" if isinstance(raw, list) else "invalid_type"
            if input_kinds[name] == "invalid_type":
                malformed = True
            for row in _list(raw):
                if not isinstance(row, dict):
                    malformed = True
                    continue
                safe = _pick(row, ("success", "start_time", "end_time", "error_code"))
                safe["component"] = name
                if isinstance(safe.get("end_time"), (int, float)) and not isinstance(safe["end_time"], bool) and safe["end_time"] > 0:
                    completed.append(safe)
                else:
                    malformed = True
        def time(row):
            value = row.get("end_time")
            return value if isinstance(value, (int, float)) else 0
        completed.sort(key=time, reverse=True)
        successful = [row for row in completed if row.get("success") is True]
        failed = [row for row in completed if row.get("success") is False]
        enabled = config.get("backup_enabled")
        latest = {name: next((row for row in completed if row["component"] == name), None) for name in components}
        manager_confirmed = bool(self.nodes) and str(self.node_data.get("node_type", "")).strip().casefold() == "nsx manager" and bool(re.match(r"^4\.2\.3(?:\.|$)", str(self.module.get("version", ""))))
        applicability = {}
        for name in components:
            confirmed = name == "cluster_backup_statuses" and manager_confirmed
            applicability[name] = {
                "state": "applicable" if confirmed else "unknown",
                "observed_history": bool(_list(history.get(name))),
                "basis": "当前4.2.3 Manager角色及本地Manager站点cluster备份语义。" if confirmed else "4.2.3说明只列该类历史，未提供其对本次部署适用或不适用的判据；有历史也不等于当前部署必需。",
                "version_basis": DOC + "method_GetBackupOverview.html",
            }
        missing_applicable = [name for name in components if applicability[name]["state"] == "applicable" and (latest[name] is None or not isinstance(latest[name].get("success"), bool))]
        applicability_unknown = any(row["state"] == "unknown" for row in applicability.values())
        native_overall = _text(history.get("overall_backup_status"))
        configuration_incomplete = not isinstance(data.get("backup_config"), dict) or not isinstance(enabled, bool) or not schedule_returned
        values = {"backup_enabled": enabled if isinstance(enabled, bool) else None, "schedule_present": bool(schedule) if schedule_returned else None, "schedule": safe_schedule,
                  "latest_success": successful[0] if successful else None, "latest_failure": failed[0] if failed else None,
                  "latest_by_component": latest, "restore_verified": False,
                  "native_overall_backup_status": native_overall, "component_applicability": applicability,
                  "component_history_input": input_kinds, "missing_applicable_results": missing_applicable,
                  "applicability_review_required": applicability_unknown, "history_data_incomplete": malformed or bool(data.get("cursor")),
                  "configuration_data_incomplete": configuration_incomplete,
                  "applicability_deployment": {"version": self.module.get("version"), "manager_node_ids": list(self._node_ids())}}
        applicable_failure = any(latest[name] and latest[name].get("success") is False for name in components if applicability[name]["state"] == "applicable")
        if str(native_overall).upper() == "FAILED" or applicable_failure:
            status = "abnormal"
        elif not isinstance(enabled, bool):
            status = "insufficient_data"
        elif enabled is False:
            status = "attention"
        elif not schedule_returned or not schedule or applicability_unknown or missing_applicable or malformed or data.get("cursor") or not completed:
            status = "insufficient_data"
        else:
            status = "normal"
        details = ["已读原生整体或已确认适用组件报告失败。"] if status == "abnormal" else []
        if not isinstance(data.get("backup_config"), dict):
            details.append("备份配置字段未返回或结构无效，无法确认启用与计划。")
        else:
            details.append("自动备份启用状态明确为关闭。" if enabled is False else "自动备份启用状态为开启。" if enabled is True else "备份启用字段未返回或类型无效，无法确认启用状态。")
            details.append("备份计划字段未返回或无法识别，无法确认是否已配置。" if not schedule_returned else "备份计划返回空对象，无法确认有效计划。" if not schedule else "已读取备份计划。")
        details.append("原生整体状态、已读组件历史与适用性缺口分别保留；不能据单个成功结果判整体正常。")
        summary = "".join(details)
        return values, status, summary

    def dns(self):
        rows = []
        for nid in self._node_ids():
            data = self.read("dns", {"node_id": nid})
            domains = self.read("search_domains", {"node_id": nid})
            if data is not None:
                rows.append({"node_id": nid, "name_servers": _strings(data.get("name_servers")), "search_domains": _strings(_dict(domains).get("search_domains"))})
        if not self.nodes:
            data = self.read("local_dns")
            if data is not None:
                rows.append({"scope": "entered_manager_only", "name_servers": _strings(data.get("name_servers"))})
        status = "normal" if rows and all(row["name_servers"] for row in rows) else "insufficient_data"
        return {"nodes": rows, "resolution_tested": False}, status, "读取Manager实际DNS配置，未测试DNS服务器可达或解析。"

    def _service_config(self, key):
        rows, states = [], []
        for nid in self._node_ids():
            config = self.read(key, {"node_id": nid}) if key == "ntp" else {"results": self.pages("syslog", {"node_id": nid})}
            state = self.read(key + "_status", {"node_id": nid}) or {}
            values = {"node_id": nid, "status": _pick(state, ("health", "runtime_state", "monitor_runtime_state"))}
            states.extend(values["status"].values())
            if key == "ntp":
                prop = _dict(_dict(config).get("service_properties"))
                values.update({"servers": _strings(prop.get("servers")), "start_on_boot": _text(prop.get("start_on_boot")), "synchronization_confirmed": False})
            else:
                values["exporters"] = [_pick(row, ("exporter_name", "server", "server_ip", "port", "protocol", "level", "facility")) for row in _list(_dict(config).get("results"))]
                values["delivery_confirmed"] = False
            rows.append(values)
        configured = bool(rows) and all(row.get("servers") if key == "ntp" else row.get("exporters") for row in rows)
        if key == "syslog" and rows and not self.errors and any(not row["exporters"] for row in rows):
            return {"nodes": rows, "remote_logging_configured_for_all_nodes": False}, "attention", "完整读取到至少一个Manager未配置远程日志目标；请按运维要求复核，未验证日志送达。"
        return {"nodes": rows}, _state(states) if configured else "insufficient_data", "读取已有配置及本机服务状态；不据此宣称远端可用。"

    def interfaces(self):
        rows, states = [], []
        targets = [(nid, "interfaces", {"node_id": nid}) for nid in self._node_ids()] or [("entered_manager_only", "local_interfaces", {})]
        for nid, key, params in targets:
            for interface in self.pages(key, params):
                safe = {"node_id": nid, **_pick(interface, ("interface_id", "admin_status", "link_status", "mtu", "source"))}
                safe["addresses"] = [_pick(alias, ("ip_address", "netmask", "ip_configuration")) for alias in _list(interface.get("interface_alias"))]
                rows.append(safe)
                states.extend((safe.get("admin_status"), safe.get("link_status")))
        status = _state(states)
        if any(not row.get("addresses") or row.get("link_status") is None or row.get("admin_status") is None for row in rows):
            status = "insufficient_data" if status == "normal" else status
        return {"interfaces": rows, "end_to_end_tested": False}, status, "逐接口读取地址、MTU、管理与链路状态；UNKNOWN不计正常。"

    def vcenter(self):
        entries = []
        for row in self.pages("compute_managers"):
            if "vcenter" not in str(row.get("origin_type", "")).lower():
                continue
            cid = _id(row)
            state = self.read("compute_state", {"compute_id": cid}) or {}
            runtime = self.read("compute_status", {"compute_id": cid}) or {}
            entries.append({**_identity(row), **_pick(row, ("origin_type", "server")),
                            "state": _pick(state, ("state", "registration_status")),
                            "runtime": _pick(runtime, ("connection_status", "compute_manager_status", "last_sync_time", "inventory_sync_status"))})
        states = [val for row in entries for part in (row["state"], row["runtime"]) for key, val in part.items() if "status" in key or key == "state"]
        return {"registrations": entries, "connected_to_vcenter": False}, _state(states) if entries else "not_deployed", "NSX登记记录与已有连接同步状态；未登记不作为Manager故障。"

    def _tn_status(self, row):
        tid = _id(row)
        data = self.read("transport_status", {"transport_id": tid}) or {}
        result = _pick(data, ("status", "status_description", "mgmt_connection_status", "high_availability_status", "vtep_state", "storage_state", "last_status_changed_time", "last_aggsvc_heartbeat"))
        for name in ("control_connection_status", "tunnel_status", "pnic_status", "agent_status"):
            result[name] = _pick(data.get(name), ("status", "up_count", "down_count", "degraded_count", "unknown_count"))
        node = _dict(data.get("node_status"))
        result["node_status"] = _pick(node, ("host_node_deployment_status", "software_version", "mpa_connectivity_status", "lcp_connectivity_status", "last_heartbeat_timestamp", "inventory_sync_paused"))
        result["agents"] = [_pick(agent, ("name", "status", "version")) for agent in _list(_dict(data.get("agent_status")).get("agents"))]
        return result

    def hosts(self):
        self.tns = self.pages("transport_nodes")
        self.transport_node_sources = list(self.sources)
        self.tns_available = not self.errors
        rows = []
        for row in self.tns:
            deployment = _dict(row.get("node_deployment_info"))
            if deployment.get("resource_type") != "HostNode":
                continue
            modules = self.read("transport_modules", {"transport_id": _id(row)}) or {}
            safe = {**_identity(row), "deployment": _pick(deployment, ("resource_type", "display_name", "external_id", "os_type", "os_version")), "runtime": self._tn_status(row),
                    "software_modules": [_pick(module, ("module_name", "module_version")) for module in _list(modules.get("software_modules"))]}
            rows.append(safe)
        self.module["inventory"].extend({"object_type": "NSXHostTransportNode", **row} for row in rows)
        states = [row["runtime"].get("status") for row in rows]
        return {"host_transport_nodes": rows}, _state(states) if rows else "not_deployed", "NSX接入状态逐主机展示；通用硬件资产由VC巡检保留。"

    def uplinks(self):
        if not self.tns_available and not self.tns:
            return {}, "insufficient_data", "传输节点清单不可用，不能判断未部署上联或隧道。"
        if not self.tns:
            self._inherit_empty_scope_sources("nsx.hosts", self.transport_node_sources)
            return {"transport_nodes": []}, "not_deployed", "本轮完整传输节点清单为空；依赖父清单，未执行逐节点上联或隧道GET。"
        rows, states = [], []
        for row in self.tns:
            tid = _id(row)
            switches = []
            for switch in _list(_dict(row.get("host_switch_spec")).get("host_switches")):
                safe = _pick(switch, ("host_switch_name", "host_switch_id", "host_switch_mode", "host_switch_type"))
                safe["pnics"] = [_pick(pnic, ("device_name", "uplink_name")) for pnic in _list(switch.get("pnics"))]
                safe["uplinks"] = [_pick(uplink, ("uplink_name", "vds_uplink_name")) for uplink in _list(switch.get("uplinks"))]
                safe["transport_zone_endpoints"] = [_pick(endpoint, ("transport_zone_id", "transport_zone_profile_ids")) for endpoint in _list(switch.get("transport_zone_endpoints"))]
                safe["ip_assignment"] = _pick(switch.get("ip_assignment_spec"), ("resource_type", "ip_pool_id"))
                safe["ip_assignment"]["ip_list"] = _strings(_dict(switch.get("ip_assignment_spec")).get("ip_list"))
                safe["uplink_profiles"] = []
                for profile_ref in _list(switch.get("host_switch_profile_ids")):
                    if _dict(profile_ref).get("key") != "UplinkHostSwitchProfile":
                        continue
                    profile_id = _id(profile_ref, "value")
                    if profile_id not in self.uplink_profiles:
                        self.uplink_profiles[profile_id] = self.read("uplink_profile", {"profile_id": profile_id}) or {}
                    profile = self.uplink_profiles[profile_id]
                    record = {**_identity(profile), **_pick(profile, ("mtu", "transport_vlan"))}
                    record["teaming"] = _pick(profile.get("teaming"), ("policy",))
                    safe["uplink_profiles"].append(record)
                switches.append(safe)
            remote = []
            for peer in self.pages("remote_transport_status", {"transport_id": tid}):
                safe = _pick(peer, ("node_uuid", "node_display_name", "status", "mgmt_connection_status"))
                for name in ("tunnel_status", "control_connection_status", "pnic_status"):
                    safe[name] = _pick(peer.get(name), ("status", "up_count", "down_count", "degraded_count"))
                    states.append(safe[name].get("status"))
                remote.append(safe)
            tunnels = []
            for tunnel in self.pages("tunnels", {"transport_id": tid}, list_field="tunnels"):
                record = _pick(tunnel, ("name", "local_ip", "remote_ip", "remote_node_id", "egress_interface", "encap", "status"))
                record["bfd"] = _pick(tunnel.get("bfd"), ("state", "remote_state", "diagnostic", "remote_diagnostic", "active", "forwarding"))
                tunnels.append(record); states.append(record.get("status"))
            rows.append({"transport_id": tid, "host_switches": switches, "remote_endpoints": remote, "tunnels": tunnels})
        return {"transport_nodes": rows}, _state(states) if rows else "not_deployed", "读取上联与已有对端状态；未主动建立或测试隧道。"

    def _realized(self, intent):
        data = self.read("realized_status", query={"intent_path": intent}) or {}
        return _pick(_dict(data.get("consolidated_status")) or data, ("consolidated_status", "status", "state"))

    def segments(self):
        rows, states = [], []
        for row in self.pages("segments"):
            sid = _id(row)
            safe = {**_identity(row), **_pick(row, ("connectivity_path", "transport_zone_path", "admin_state", "vlan_ids"))}
            safe["vlan_ids"] = _strings(row.get("vlan_ids"))
            safe["subnets"] = [_pick(subnet, ("gateway_address", "network")) for subnet in _list(row.get("subnets"))]
            safe["realization"] = self._realized("/infra/segments/" + sid)
            safe["ports"] = []
            for port in self.pages("segment_ports", {"segment_id": sid}):
                pid = _id(port)
                runtime = self.read("port_status", {"segment_id": sid, "port_id": pid}) or {}
                entry = {**_identity(port), **_pick(port, ("admin_state",)), "attachment": _pick(port.get("attachment"), ("id", "type", "context_id", "app_id", "traffic_tag")), "runtime": _pick(runtime, ("status", "admin_state", "link_status", "status_description"))}
                safe["ports"].append(entry)
                states.append(entry["runtime"].get("status"))
            states.extend(safe["realization"].values())
            rows.append(safe)
        return {"segments": rows}, _state(states) if rows else "not_deployed", "网络、端口关联及实现状态按对象展示；未测试实际业务路径。"

    def edge(self):
        nodes, clusters, states = [], [], []
        for row in self.tns:
            deployment = _dict(row.get("node_deployment_info"))
            if deployment.get("resource_type") != "EdgeNode":
                continue
            tid = _id(row)
            runtime = self._tn_status(row)
            resources = self.read("transport_resources", {"transport_id": tid})
            nodes.append({**_identity(row), **_pick(row, ("maintenance_mode", "is_overridden")), "deployment": _pick(deployment, ("resource_type", "display_name", "deployment_type", "maintenance_mode")), "runtime": runtime, "resources": self._resources(resources, edge=True) if resources is not None else {}})
            states.extend((runtime.get("status"), runtime.get("high_availability_status")))
        for row in self.pages("edge_clusters"):
            eid = _id(row)
            runtime = self.read("edge_cluster_status", {"edge_cluster_id": eid}) or {}
            safe = {**_identity(row), "members": [_pick(member, ("transport_node_id", "member_index")) for member in _list(row.get("members"))], "runtime": _pick(runtime, ("edge_cluster_status", "last_update_timestamp"))}
            safe["member_status"] = [_pick(member, ("transport_node_id", "member_index", "status", "node_status", "high_availability_status")) for member in _list(runtime.get("member_status"))]
            clusters.append(safe); states.append(safe["runtime"].get("edge_cluster_status"))
        status = _state(states) if nodes or clusters else "not_deployed" if self.tns_available else "insufficient_data"
        return {"nodes": nodes, "clusters": clusters}, status, "Edge与HA按实际成员展示；未执行切换或转发测试。"

    def gateways_check(self):
        values, states = [], []
        for tier in ("t0", "t1"):
            start = len(self.sources)
            gateways = self.pages(tier)
            self.gateway_discovery_sources.extend(self.sources[start:])
            for row in gateways:
                gid = _id(row)
                self.gateways.append((tier, gid, row))
                state = self.read(tier + "_state", {"gateway_id": gid}) or {}
                safe = {"tier": tier, **_identity(row), **_pick(row, ("ha_mode", "tier0_path", "failover_mode")), "state": {name: _pick(state.get(name), ("state", "status")) for name in ("tier0_state", "tier1_state")}}
                safe["static_routes"] = [{**_identity(route), **_pick(route, ("network",)), "next_hops": [_pick(hop, ("ip_address", "admin_distance", "scope")) for hop in _list(route.get("next_hops"))]} for route in self.pages(tier + "_static_routes", {"gateway_id": gid})]
                safe["locales"] = []
                for locale in self.pages(tier + "_locales", {"gateway_id": gid}):
                    lid = _id(locale)
                    params = {"gateway_id": gid, "locale_id": lid}
                    entry = {**_identity(locale), **_pick(locale, ("edge_cluster_path", "preferred_edge_paths"))}
                    entry["interfaces"] = [{**_identity(interface), **_pick(interface, ("type", "segment_path", "edge_path", "mtu")), "subnets": [{"ip_addresses": _strings(subnet.get("ip_addresses")), **_pick(subnet, ("prefix_len",))} for subnet in _list(interface.get("subnets"))]} for interface in self.pages(tier + "_interfaces", params)]
                    if tier == "t0":
                        entry["bgp_neighbors"] = [{**_identity(neighbor), **_pick(neighbor, ("neighbor_address", "remote_as_num", "allow_as_in", "keep_alive_time", "hold_down_time"))} for neighbor in self.pages("bgp_neighbors", params)]
                        entry["bgp_status"] = [_pick(neighbor, ("neighbor_address", "remote_as_number", "connection_status", "source_address", "last_updated_timestamp")) for neighbor in self.pages("bgp_status", params)]
                        states.extend(neighbor.get("connection_status") for neighbor in entry["bgp_status"])
                    safe["locales"].append(entry)
                states += [value for part in safe["state"].values() for value in part.values()]
                values.append(safe)
        self.gateways_available = not self.errors
        return {"gateways": values, "expected_route_manifest_provided": False}, _state(states) if values else "not_deployed", "路由与邻居仅按已配置对象核实；缺少预期清单不判断路由完整。"

    def nat(self):
        if not self.gateways_available and not self.gateways:
            return {}, "insufficient_data", "网关清单未完整取得，不能判断未部署NAT。"
        if not self.gateways:
            self._inherit_empty_scope_sources("nsx.gateways", self.gateway_discovery_sources)
            return {"rules": [], "traffic_verified": False}, "not_deployed", "本轮完整Tier-0/Tier-1网关清单为空；依赖父清单，未执行逐网关NAT GET。"
        rows = []
        for tier, gid, _ in self.gateways:
            for section in self.pages(tier + "_nat", {"gateway_id": gid}):
                nid = _id(section)
                for rule in self.pages(tier + "_nat_rules", {"gateway_id": gid, "nat_id": nid}):
                    rows.append({"gateway_id": gid, "tier": tier, "nat_id": nid, **_identity(rule), **_pick(rule, ("enabled", "action", "source_network", "destination_network", "translated_network", "translated_ports", "service", "sequence_number", "firewall_match", "logging"))})
        return {"rules": rows, "traffic_verified": False}, "attention" if rows else "not_deployed", "NAT配置已读取，实际转发未验证，按业务基线人工复核。"

    def _rules(self, rows):
        result = []
        for row in rows:
            safe = {**_identity(row), **_pick(row, ("action", "disabled", "sequence_number", "direction", "logged"))}
            for name in ("source_groups", "destination_groups", "services", "scope"):
                safe[name] = _strings(row.get(name))
            safe["service_entries"] = [_pick(item, ("resource_type", "l4_protocol", "icmp_type", "icmp_code", "protocol_number")) | {"source_ports": _strings(item.get("source_ports")), "destination_ports": _strings(item.get("destination_ports"))} for item in _list(row.get("service_entries")) if isinstance(item, dict)]
            safe["manual_review"] = bool(str(row.get("action", "")).upper() == "ALLOW" and ("ANY" in safe["source_groups"] or "ANY" in safe["destination_groups"]))
            result.append(safe)
        return result

    def security(self):
        policies, groups, services, states = [], [], [], []
        for domain in self.pages("domains"):
            did = _id(domain)
            groups += [{"domain_id": did, **_identity(group), "expressions": [{**_pick(item, ("resource_type", "member_type", "key", "operator", "value", "conjunction_operator")), "ip_addresses": _strings(_dict(item).get("ip_addresses")), "paths": _strings(_dict(item).get("paths"))} for item in _list(group.get("expression"))]} for group in self.pages("groups", {"domain_id": did})]
            for policy in self.pages("security_policies", {"domain_id": did}):
                pid = _id(policy)
                safe = {"domain_id": did, **_identity(policy), **_pick(policy, ("category", "stateful", "tcp_strict", "locked")), "scope": _strings(policy.get("scope")), "realization": self._realized("/infra/domains/" + did + "/security-policies/" + pid)}
                safe["rules"] = self._rules(self.pages("security_rules", {"domain_id": did, "policy_id": pid}))
                policies.append(safe); states.extend(safe["realization"].values())
            for policy in self.pages("gateway_policies", {"domain_id": did}):
                pid = _id(policy)
                safe = {"domain_id": did, "policy_type": "gateway", **_identity(policy), "scope": _strings(policy.get("scope")), "rules": self._rules(self.pages("gateway_rules", {"domain_id": did, "policy_id": pid})), "realization": self._realized("/infra/domains/" + did + "/gateway-policies/" + pid)}
                policies.append(safe); states.extend(safe["realization"].values())
        if policies:
            services = [{**_identity(service), "entries": [_pick(item, ("resource_type", "l4_protocol", "icmp_type", "icmp_code", "protocol_number", "nested_service_path")) | {"destination_ports": _strings(item.get("destination_ports"))} for item in _list(service.get("service_entries")) if isinstance(item, dict)]} for service in self.pages("service_definitions")]
        self.security_supporting_records = {"group_catalog": groups, "service_catalog": services,
            "note": "当次已读安全字段投影目录，供JSON/数据库回查；客户报告仅展示策略实际引用对象。"}
        groups, services, unresolved = self._referenced_security_objects(policies, groups, services)
        status = _state(states) if policies else "not_deployed"
        if unresolved and status == "normal":
            status = "insufficient_data"
        if any(rule["manual_review"] for policy in policies for rule in policy["rules"]) and status == "normal":
            status = "attention"
        return {"policies": policies, "referenced_groups": groups, "service_definitions": services,
                "unresolved_references": unresolved, "dfw_enforcement_tested": False}, status, "配置、引用、下发状态分开；宽泛放行仅供人工复核，不推断流量实际拦截。"

    @staticmethod
    def _referenced_security_objects(policies, groups, services):
        """Associate only exact internal paths containing stable object IDs."""
        def segment(value):
            return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}", value) is not None
        group_index = {"/infra/domains/" + group["domain_id"] + "/groups/" + group["id"]: group for group in groups
                       if segment(group.get("domain_id")) and segment(group.get("id"))}
        service_index = {"/infra/services/" + service["id"]: service for service in services if segment(service.get("id"))}
        references = set()
        for policy in policies:
            references.update(value for value in policy.get("scope", []) if isinstance(value, str) and value != "ANY")
            for rule in policy["rules"]:
                for name in ("source_groups", "destination_groups", "scope", "services"):
                    references.update(value for value in rule.get(name, []) if isinstance(value, str) and value != "ANY")
        selected_groups, selected_services, visited = {}, {}, set()
        pending = sorted(references, reverse=True)
        while pending:
            reference = pending.pop()
            if reference in visited:
                continue
            visited.add(reference)
            if reference in group_index:
                group = group_index[reference]
                selected_groups[reference] = group
                for expression in group.get("expressions", []):
                    pending.extend(path for path in expression.get("paths", []) if isinstance(path, str) and path.startswith("/infra/domains/") and "/groups/" in path and path not in visited)
            elif reference in service_index:
                service = service_index[reference]
                selected_services[reference] = service
                pending.extend(entry["nested_service_path"] for entry in service.get("entries", [])
                               if isinstance(entry.get("nested_service_path"), str) and entry["nested_service_path"].startswith("/infra/services/") and entry["nested_service_path"] not in visited)
        # Gateway/segment/VM scope paths are retained in each policy/rule and
        # are not misrepresented as absent groups or service definitions.
        unresolved = sorted(path for path in visited if (path.startswith("/infra/domains/") and "/groups/" in path or path.startswith("/infra/services/")) and path not in selected_groups and path not in selected_services)
        return [selected_groups[path] for path in sorted(selected_groups)], [selected_services[path] for path in sorted(selected_services)], unresolved

    def run(self):
        self.load_specs()
        operations = (("version", self.version), ("cluster", self.cluster), ("services", self.manager_services), ("resources", self.resources),
                ("alarms", self.alarms), ("certificates", self.certificates), ("licenses", self.licenses), ("backup", self.backup),
                ("dns", self.dns), ("ntp", lambda: self._service_config("ntp")), ("syslog", lambda: self._service_config("syslog")),
                ("interfaces", self.interfaces), ("vcenter", self.vcenter), ("hosts", self.hosts), ("uplink_tunnels", self.uplinks),
                ("segments", self.segments), ("edge", self.edge), ("gateways", self.gateways_check), ("nat", self.nat), ("security", self.security))
        # Select execution before collection; never collect business objects
        # and then hide them from a management result.
        allowed = resolve_scope("nsx").check_ids if self.management else {"nsx." + key for key, _ in operations}
        for key, operation in operations:
            if "nsx." + key not in allowed:
                continue
            self.check(key, operation)
        self.module["limitations"].append(NO_THRESHOLD)
        if not self.management:
            self.module["limitations"].extend([BUSINESS_LIMIT, "跨站点、WAF/入侵防护、容器网络与全面策略冲突分析未纳入完整专项判断。"])
        self.module["request_metrics"] = dict(self.transport.metrics)
        self.module["transport_security"] = dict(self.transport.transport_security)
        self.module["verification_level"] = self.verification
        if self.stop_error and self.stop_error.kind == "cancelled":
            self.module["collection_state"] = "cancelled"
        secrets = tuple(getattr(self.transport, "secret_values", ())) + tuple(self.hidden_values) + (self.credential.password,)
        return sanitize_public(finish_module(self.module), secrets=secrets)


def collect_nsx(target, credential, *, cancel_requested=None, transport_factory=ReadTransport, inspection_scope=None):
    if getattr(target, "product", None) != "nsx":
        raise ValueError("NSX采集器只接受NSX目标。")
    routes = select_routes("nsx", ROUTES, inspection_scope)
    transport = transport_factory(target, credential, routes, cancel_requested=cancel_requested)
    try:
        return _Collector(target, credential, transport).run()
    finally:
        transport.close()


def _replay_legacy_nsx(target, credential, transport):
    """Private compatibility helper for explicit in-memory offline fixtures.

    The public collector has no full/business mode.  Historical fixtures can
    still exercise the retained helpers without widening a new collection.
    """
    if isinstance(transport, ReadTransport) or getattr(transport, "verification_level", None) != "offline_replay":
        raise ValueError("旧范围仅允许明确标记的内存离线重放。")
    try:
        return _Collector(target, credential, transport, management=False).run()
    finally:
        transport.close()
