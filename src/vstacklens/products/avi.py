"""Conservative Avi 30.2.5 inspection through an isolated, read-only session.

Configuration, observed runtime and validation evidence are deliberately separate.
Only explicit scalar projections leave this module; controller responses and
authentication material are never returned for persistence.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import math
import re
from urllib.parse import urlsplit

from .certificates import certificate_dates
from .model import finish_module, make_check, make_source, new_module, sanitize_public
from .management_scope import (
    alarm_lifecycle_of, is_management_check, is_management_module,
    mark_management_scope, resolve_scope, select_routes,
)
from .transport import CollectionError, ReadTransport, Route


API_VERSION = "30.2.5"
DOC = "https://developer.broadcom.com/xapis/vmware-avi-load-balancer/30.2.5/"
_COMMON_QUERY = ("fields", "page", "page_size", "sort", "include_name", "skip_default")
_METRIC_QUERY = ("metric_id", "start", "stop", "step", "limit", "pad_missing_data", "include_statistics", "detailed_header")


def _route(path, purpose, page="", query=_COMMON_QUERY):
    return Route(path, purpose, version_basis=DOC + page, query_parameters=query)


ROUTES = {
    "version": _route("/api/cluster/version", "读取 Controller 版本；官方会话认证读取示例", query=()),
    "tenants": _route("/api/tenant", "列出账号可见租户", "tenant/"),
    "cluster_runtime": Route(
        "/api/cluster/runtime", "读取已有 Controller 集群运行状态，不执行故障切换",
        version_basis="https://knowledge.broadcom.com/external/article/454303/avi-controller-cluster-vip-reachable-but.html (30.2.x；本轮字段兼容性单独记录)",
    ),
    "system": _route("/api/systemconfiguration", "读取 DNS、NTP、管理证书绑定配置", "api/systemconfiguration/get/"),
    "alerts": _route("/api/alert", "读取原生告警，不确认、删除或清除", "api/alert/get/"),
    "certificates": _route("/api/sslkeyandcertificate", "读取证书元数据，不导出私钥或证书全文", "api/sslkeyandcertificate/get/"),
    "certificate_details": Route(
        "/api/sslkeyandcertificate/{uuid}", "读取 system 管理绑定中的单个证书对象",
        version_basis="AVI 30.2.5 vendor provider v30.2.5, commit 9ea1ce771a42a7307f0b6ca872835babc478f22f: "
        "https://github.com/vmware/terraform-provider-avi/blob/9ea1ce771a42a7307f0b6ca872835babc478f22f/avi/resource_avi_sslkeyandcertificate.go#L186-L193 ; "
        "https://github.com/vmware/terraform-provider-avi/blob/9ea1ce771a42a7307f0b6ca872835babc478f22f/avi/utils.go#L382-L424 ; "
        "pinned SDK HTTP GET: https://github.com/vmware/alb-sdk/blob/8f713de2511a27aca90addb30a719a1df46d8412/go/session/avisession.go#L1272-L1274",
        query_parameters=(),
    ),
    "license_status": _route("/api/licensing/status", "读取原生 SaaS 授权状态", "api/licensing/status/get/"),
    "license_ledger": _route("/api/licensing/ledger/details", "读取现有授权容量台账", "api/licensing/ledger/details/get/"),
    "backup_config": _route("/api/backupconfiguration", "读取现有备份配置，不触发备份", "api/backupconfiguration/get/"),
    "schedulers": _route("/api/scheduler", "读取现有计划，不执行计划", "api/scheduler/get/"),
    "backups": _route("/api/backup", "列出现有备份记录，不下载备份", "api/backup/get/"),
    "syslog": _route("/api/alertsyslogconfig", "读取原生告警远程日志目的地配置，不发送测试消息", "alert-syslog-config/"),
    "clouds": _route("/api/cloud", "读取 Cloud 类型及对象引用，不访问对接环境", "cloud/"),
    "cloud_runtime": _route("/api/cloudruntime", "读取已有 Cloud 运行状态", "cloud-runtime/"),
    "cloud_status": _route("/api/cloud/{uuid}/status", "读取现有 Cloud 连接状态", "cloud/", query=()),
    "ses": _route("/api/serviceengine", "读取已有 Service Engine 配置", "service-engine/"),
    "se_inventory": _route("/api/serviceengine-inventory", "读取已有 SE inventory 与运行状态", "api/serviceengine-inventory/get/"),
    "se_groups": _route("/api/serviceenginegroup", "读取 SE 组配置，不重新分配或切换", "service-engine-group/"),
    "se_group_runtime": _route("/api/serviceenginegroup/{uuid}/runtime", "读取 SE 组已有运行状态", "api/serviceenginegroup/uuid/runtime/get/", query=()),
    "virtual_services": _route("/api/virtualservice", "读取 VS 配置及绑定关系，不启停业务", "api/virtualservice/get/"),
    "vs_inventory": _route("/api/virtualservice-inventory", "读取已有 VS 运行状态", "api/virtualservice-inventory/get/"),
    "vsvips": _route("/api/vsvip", "读取 VS 绑定的现有 VIP 配置", "vs-vip/"),
    "application_profiles": _route("/api/applicationprofile", "读取应用协议类型", "application-profile/"),
    "network_profiles": _route("/api/networkprofile", "读取传输协议类型", "network-profile/"),
    "pools": _route("/api/pool", "读取池配置及服务器成员", "pool/"),
    "pool_inventory": _route("/api/pool-inventory", "读取已有池运行与健康成员数量", "api/pool-inventory/get/"),
    "server_runtime": _route("/api/pool/{uuid}/runtime/server", "读取池服务器已有探测结果，不发起探测", "api/pool/uuid/runtime/server/get/", query=()),
    "health_monitors": _route("/api/healthmonitor", "读取既有健康检查配置，不额外探测", "api/healthmonitor/get/"),
    "ssl_profiles": _route("/api/sslprofile", "读取已有 TLS profile 配置", "sslprofile/"),
    "controller_metrics": _route("/api/analytics/metrics/controller/{uuid}", "读取有限时间窗口的已有 Controller 指标", "metrics/", query=_METRIC_QUERY),
    "se_metrics": _route("/api/analytics/metrics/serviceengine/{uuid}", "读取有限时间窗口的已有 SE 指标", "metrics/", query=_METRIC_QUERY),
    "vs_metrics": _route("/api/analytics/metrics/virtualservice/{uuid}", "读取有限时间窗口的已有 VS 指标，不制造流量", "metrics/", query=_METRIC_QUERY),
}


def _matrix(cid, title, data, sources, basis, limitation):
    return {"id": cid, "title": title, "data": data, "source": sources,
            "version_basis": DOC, "judgement_basis": basis, "limitations": limitation,
            "verification": "unverified"}


CHECK_MATRIX = [
    _matrix("AVI-A1", "版本与账号覆盖范围", "版本、构建、可见及实际采集租户", ["version", "tenants"], "设备返回的版本及显式租户选择", "可见租户不等于已采集租户"),
    _matrix("AVI-A2", "集群与关键管理服务", "节点角色、原生集群状态、运行时间", ["cluster_runtime"], "原生状态，不把单节点无 HA 当作故障", "30.2.x 运行态逐字段观察；未取得关键服务即数据不足"),
    _matrix("AVI-A3", "设备内部资源", "Controller 的 CPU、内存与磁盘汇总指标", ["controller_metrics"], "仅展示采样与原生单位，不设置过载阈值", "未取得各分区或长期负载；不能用汇总代替各分区"),
    _matrix("AVI-A4", "原生告警", "对象、原生 level/state、时间、原因", ["alerts"], "原生告警独立保存，不映射 P 等级", "分页截断不能宣称告警总数完整"),
    _matrix("AVI-A5", "管理与业务证书", "证书有效期、使用引用、原生到期状态", ["system", "certificates"], "有效期与采集 UTC 比较；临近到期仅复用原生判断", "不验证撤销服务、不主动诊断；连接身份验证单独保存"),
    _matrix("AVI-A6", "授权与容量", "SaaS 状态、tier 及原生容量台账", ["license_status", "license_ledger"], "只判断接口明确覆盖的授权状态", "SaaS 未启用不能推断本地授权无效；缺少本地授权到期则不足"),
    _matrix("AVI-A7", "备份", "配置、启用计划、既有备份时间", ["backup_config", "schedulers", "backups"], "配置、计划、既有记录分别表达", "backup 对象无结果字段；存在备份不证明成功或恢复已验证"),
    _matrix("AVI-A8", "DNS、NTP 与远程日志", "配置的目的地", ["system", "syslog"], "配置存在只表示已配置", "未主动测试可达性、同步或日志送达；syslog 来源只覆盖告警日志配置"),
    _matrix("AVI-C1", "Cloud 与租户", "Cloud 类型、连接状态、显式租户", ["clouds", "cloud_runtime", "cloud_status"], "配置与原生连接状态分别保存", "只读 Controller，不连接 Cloud 对接环境"),
    _matrix("AVI-C2", "Service Engine", "SE 配置、所属组、已有运行状态及资源采样", ["ses", "se_inventory", "se_metrics"], "按原生运行状态，缺运行态即不足", "空 SE 只验证未部署，不能验收 SE 异常识别；内部磁盘仅有原生disk1指标"),
    _matrix("AVI-C3", "SE 组与冗余", "HA 配置、配置关联成员、运行态", ["se_groups", "se_group_runtime"], "HA 配置不证明冗余可用", "无业务基线不判断冗余数量，不切换"),
    _matrix("AVI-C4", "虚拟服务", "入口、端口、协议、启停及对象关系、运行状态", ["virtual_services", "vs_inventory", "vsvips", "application_profiles", "network_profiles"], "手动停用与运行异常分别表达", "配置存在不证明服务实际可用；空业务待真实验收"),
    _matrix("AVI-C5", "后端池", "成员数、启用数、健康数及算法", ["pools", "pool_inventory"], "原生健康数；算法无统一好坏阈值", "缺少 runtime 不能用配置服务器数代替健康数"),
    _matrix("AVI-C6", "后端服务器", "每个配置成员的启停和已有健康结果", ["pools", "server_runtime"], "手动停用、原生 DOWN 与缺数据分开", "Controller 已有结果，不额外探测；多 SE 结果冲突保留"),
    _matrix("AVI-C7", "健康检查", "类型、端口、HTTP 路径、期望、间隔及超时", ["health_monitors", "server_runtime"], "展示配置及已有探测结果，不制定统一间隔", "successful_checks/failed_checks 是配置次数，不冒充探测成功/失败次数"),
    _matrix("AVI-C8", "业务证书与 TLS", "VS 的证书/SSL profile 引用及域名", ["virtual_services", "certificates", "ssl_profiles"], "到期问题复用证书事实，TLS 配置供复核", "不主动握手业务入口；未确认域名不判断覆盖正确"),
    _matrix("AVI-C9", "既有业务指标", "连接、吞吐、响应时间及错误指标", ["vs_metrics"], "原生单位及实际窗口，保留缺点", "无真实 VS 及业务采样无法验收指标异常识别"),
]


def management_check_matrix():
    """The public collector's matrix is selected before any connection."""
    rows = []
    for row in CHECK_MATRIX:
        if not is_management_check("avi", row["id"]):
            continue
        item = dict(row)
        if row["id"] == "AVI-C1":
            item.update(title="Cloud 登记配置事实", data="所选租户现有 Cloud UUID/name/vtype 配置，不读取连接运行态", source=["clouds"],
                        judgement_basis="只陈述 Cloud 登记类型及所选租户，不据配置判断连接可用。",
                        limitations="不读取 Cloud 运行态，不直接访问 vCenter 或其他对接环境。")
        elif row["id"] == "AVI-A5":
            item.update(title="管理绑定证书", source=["system"] + (["certificate_details"] if "certificate_details" in ROUTES else []),
                        limitations="仅管理绑定对象；单项读取来源未核实或失败时不回退全证书目录。")
        rows.append(item)
    return rows

_FIELDS = {
    "tenants": "uuid,name,local",
    "system": "uuid,dns_configuration,ntp_configuration,portal_configuration,secure_channel_configuration,default_license_tier",
    "alerts": "uuid,name,obj_uuid,obj_name,level,state,summary,reason,timestamp",
    "certificates": "uuid,name,tenant_ref,type,status,certificate",
    "certificate_details": "uuid,name,tenant_ref,type,status,certificate",
    "license_status": "uuid,saas_status,service_update,tenant_uuid",
    "license_ledger": "uuid,tier_usages,se_infos,escrow_infos",
    "backup_config": "uuid,name,save_local,upload_to_remote_host,upload_to_s3,maximum_backups_stored",
    "schedulers": "uuid,name,enabled,backup_config_ref,scheduler_action,frequency,frequency_unit,start_date_time,end_date_time,run_mode",
    "backups": "uuid,timestamp,backup_config_ref,scheduler_ref",
    "syslog": "uuid,name,syslog_servers",
    "clouds": "uuid,name,vtype,tenant_ref,se_group_template_ref",
    "cloud_runtime": "uuid,name,cloud_ref,state,reason",
    "ses": "uuid,name,tenant_ref,cloud_ref,se_group_ref,enable_state,vcpus,memory,resources,vnics",
    "se_inventory": "uuid,config,runtime",
    "se_groups": "uuid,name,tenant_ref,cloud_ref,ha_mode,min_scaleout_per_vs,max_scaleout_per_vs,buffer_se,max_se",
    "virtual_services": "uuid,name,tenant_ref,cloud_ref,enabled,services,vip,vsvip_ref,se_group_ref,pool_ref,pool_group_ref,ssl_key_and_certificate_refs,ssl_profile_ref,vh_domain_name,type,application_profile_ref,network_profile_ref",
    "vs_inventory": "uuid,config,runtime,pools",
    "vsvips": "uuid,name,vip,dns_info",
    "application_profiles": "uuid,name,type",
    "network_profiles": "uuid,name,profile",
    "pools": "uuid,name,tenant_ref,cloud_ref,enabled,servers,lb_algorithm,health_monitor_refs,default_server_port,ssl_profile_ref",
    "pool_inventory": "uuid,config,runtime",
    "health_monitors": "uuid,name,type,monitor_port,send_interval,receive_timeout,successful_checks,failed_checks,http_monitor,https_monitor",
    "ssl_profiles": "uuid,name,type,accepted_versions,accepted_ciphers,cipher_enums,enable_ssl_session_reuse",
}

# The 30.2.5 laboratory returns these code-owned resources as singletons,
# although the public API pages also show collection envelopes. Never apply
# this compatibility rule to an arbitrary list or to an error dictionary.
_SINGLETON_KEYS = {
    "system": {"uuid", "dns_configuration", "ntp_configuration", "portal_configuration", "secure_channel_configuration", "default_license_tier"},
    "license_status": {"uuid", "saas_status", "service_update", "tenant_uuid"},
    "license_ledger": {"uuid", "tier_usages", "se_infos", "escrow_infos"},
}


def _dict(value):
    return value if isinstance(value, dict) else {}


def _rows(value):
    if isinstance(value, list):
        return [x for x in value if isinstance(x, dict)]
    if isinstance(value, dict):
        if isinstance(value.get("results"), list):
            return _rows(value["results"])
        return [value]
    return []


def _scalar(value):
    if isinstance(value, (str, bool, int)):
        return value[:2048] if isinstance(value, str) else value
    if isinstance(value, float) and math.isfinite(value):
        return value
    return None


def _pick(value, fields):
    value = _dict(value)
    return {key: _scalar(value[key]) for key in fields if key in value and _scalar(value[key]) is not None}


def _number(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) else None


def _ip(value):
    if isinstance(value, str):
        return value[:128]
    value = _dict(value)
    return _scalar(value.get("addr")) or _ip(value.get("ip_addr")) if value else None


def _utc(value):
    if isinstance(value, (float, int)) and not isinstance(value, bool):
        try:
            return datetime.fromtimestamp(value, timezone.utc)
        except (ValueError, OverflowError, OSError):
            return None
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed.astimezone(timezone.utc) if parsed.tzinfo else None
        except ValueError:
            return None
    return None


def _identity(value):
    value = _dict(value)
    nested = _dict(value.get("config"))
    raw = value.get("uuid") or nested.get("uuid")
    return raw if isinstance(raw, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", raw) else ""


def _name(value):
    return _scalar(_dict(value).get("name")) or _scalar(_dict(_dict(value).get("config")).get("name")) or _identity(value)


def _oper(value):
    """Project explicit native state; never derive runtime from configuration."""
    value = _dict(value)
    operation = _dict(value.get("oper_status"))
    result = _pick(operation, ("state", "reason_code", "reason_code_string"))
    if isinstance(operation.get("reason"), list):
        result["reason"] = [_scalar(x) for x in operation["reason"][:20] if isinstance(x, str)]
    changed = _dict(operation.get("last_changed_time"))
    if changed:
        result["last_changed_time"] = _pick(changed, ("secs", "usecs"))
    return result


def _oper_result(operation, enabled=None):
    if enabled is False:
        return "not_applicable", "对象被手动停用；保留原生运行状态供核查。"
    state = str(_dict(operation).get("state", "")).upper()
    if state in {"OPER_UP", "UP", "CONNECTED", "CLOUD_STATE_PLACEMENT_READY"}:
        return "normal", "原生运行状态为可用；仅代表本次 Controller 观察。"
    if state in {"OPER_DOWN", "DOWN", "DISCONNECTED", "FAILED", "OPER_FAILED"}:
        return "abnormal", "原生运行状态报告异常；原因见取数值。"
    return "insufficient_data", "未取得可明确解释的运行状态。"


class _Collection:
    def __init__(self, target, credential, transport):
        self.target, self.credential, self.transport = target, credential, transport
        self.module = new_module(target)
        self.verification = getattr(transport, "verification_level", "live_observed")
        if self.verification not in {"live_observed", "offline_replay", "artificial_sample"}:
            self.verification = "unverified"
        self.module["verification_level"] = self.verification
        self.module["inventory"] = []
        self.module["native_alerts"] = []
        self.secrets = tuple(x for x in (credential.password, *getattr(transport, "secret_values", ())) if x)
        self.collections = {}
        self.object_collections = {}
        self.cache = {}
        self.observations = {}
        self.scope = {"selected_tenant": credential.tenant or "admin", "visible_tenants": [], "checked_tenants": [credential.tenant or "admin"]}

    def public(self, value):
        return sanitize_public(value, secrets=tuple(set(self.secrets) | set(getattr(self.transport, "secret_values", ())) | set(getattr(self.credential, "secret_values", ()))))

    def source(self, key, fields=(), *, object_id=""):
        route = ROUTES[key]
        if key == "clouds" and is_management_module(self.module):
            fields = ("uuid", "name", "vtype", "tenant_ref")
        source = make_source(route.path, version_basis=route.version_basis, fields=fields,
                             note="X-Avi-Version=30.2.5；租户=" + self.scope["selected_tenant"])
        observations = self.observations.get(key, [])
        if object_id and any(o.get("object_id") for o in observations):
            observations = [o for o in observations if o.get("object_id") == object_id or object_id.startswith(str(o.get("object_id")) + ":")]
        source["attempted"] = bool(observations)
        source["observations"] = observations
        source["collected_at"] = observations[-1]["collected_at"] if observations else None
        if not observations:
            source["note"] += "；本次未请求或未取得取数记录，此处为候选来源"
        return source

    def error(self, exc, key):
        details = exc.as_dict() if isinstance(exc, CollectionError) else {
            "kind": "invalid_response", "stage": "analysis", "reason": "响应结构无法安全解释", "type": type(exc).__name__}
        details = dict(details, source=ROUTES[key].path)
        self.module["errors"].append(self.public(details))
        return details

    def get(self, key, *, uuid=None, query=None):
        cache_key = (key, uuid)
        if cache_key in self.cache:
            return self.cache[cache_key]
        try:
            self.transport.check_cancelled()
            observed = make_source(ROUTES[key].path.replace("{uuid}", uuid or "{uuid}"), version_basis=ROUTES[key].version_basis)
            observed["object_id"] = uuid or ""
            observed["query"] = query or {}
            self.observations.setdefault(key, []).append(observed)
            result = self.transport.get(key, path_params={"uuid": uuid} if uuid else None, query=query)
            self.cache[cache_key] = result
            self.object_collections[cache_key] = {"complete": True, "errors": []}
            self.collections.setdefault(key, {"complete": True, "errors": []})
            return result
        except CollectionError as exc:
            state = {"complete": False, "errors": [self.error(exc, key)]}
            self.object_collections[cache_key] = state
            prior = self.collections.get(key, {}).get("errors", [])
            self.collections[key] = {"complete": False, "errors": prior + state["errors"]}
            self.cache[cache_key] = None
            return None

    def listed(self, key, *, query=None):
        if key in self.cache:
            return self.cache[key]
        if key in _SINGLETON_KEYS:
            params = {"fields": _FIELDS[key]}
            params.update(query or {})
            raw = self.get(key, query=params)
            if raw is None:
                self.cache[key] = []
                return []
            try:
                if not isinstance(raw, dict):
                    raise CollectionError("invalid_response", "已核实单例读取返回了非对象结构")
                if "results" in raw:
                    items = raw["results"]
                    if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
                        raise CollectionError("invalid_response", "已核实单例的兼容列表结构无效")
                    if raw.get("next") or raw.get("count", len(items)) != len(items):
                        raise CollectionError("invalid_response", "单例兼容响应包含不完整列表，不能视作完整单例")
                elif set(raw) & _SINGLETON_KEYS[key] and not set(raw) & {"error", "error_message", "error_code", "errors"}:
                    items = [raw]
                else:
                    raise CollectionError("invalid_response", "单例未返回已核实字段，不能将任意字典当作有效数据")
                self.cache[key] = items
                return items
            except CollectionError as exc:
                self.collections[key] = {"complete": False, "errors": [self.error(exc, key)]}
                self.cache[key] = []
                return []
        params = {"page_size": 50, "page": 1}
        if key in _FIELDS:
            params["fields"] = _FIELDS[key]
        params.update(query or {})
        try:
            self.transport.check_cancelled()
            observed = make_source(ROUTES[key].path, version_basis=ROUTES[key].version_basis)
            observed["query"] = params
            self.observations[key] = [observed]
            result = self.transport.list_pages(key, kind="avi", query=params)
            if result.get("sources"):
                self.observations[key] = [_pick(s, ("path", "method", "collected_at", "version_basis", "page")) for s in _rows(result["sources"])]
            items = result.get("items")
            if not isinstance(items, list) or any(not isinstance(x, dict) for x in items):
                raise CollectionError("invalid_response", "列表响应缺少对象数组")
            self.collections[key] = {"complete": result.get("complete") is True, "errors": result.get("errors", [])}
            for error in result.get("errors", []):
                self.module["errors"].append(self.public(dict(error, source=ROUTES[key].path)))
            self.cache[key] = items
            return items
        except CollectionError as exc:
            self.collections[key] = {"complete": False, "errors": [self.error(exc, key)]}
            self.cache[key] = []
            return []

    def check(self, cid, title, status, values, keys, *, summary="", limitations=(), object_id="", object_name="", judgement="PROGRAM", basis="", native_severity="", recommendation="", missing_fields=()):
        def state_for(key):
            if object_id and "{uuid}" in ROUTES[key].path:
                matches = [state for (source_key, uuid), state in self.object_collections.items()
                           if source_key == key and uuid and (uuid == object_id or object_id.startswith(uuid + ":"))]
                if matches:
                    return {"complete": all(s["complete"] for s in matches), "errors": [e for s in matches for e in s["errors"]]}
            return self.collections.get(key, {"complete": False, "errors": []})

        states = [state_for(key) for key in keys]
        complete = bool(keys) and all(state["complete"] for state in states)
        errors = [error for state in states for error in state.get("errors", [])]
        if not complete and status in {"normal", "not_deployed", "not_applicable", "insufficient_data"}:
            kinds = {error.get("kind") for error in errors if isinstance(error, dict)}
            status = ("cancelled" if "cancelled" in kinds else "permission_denied" if "permission" in kinds else
                      "unsupported" if "unsupported" in kinds else "collection_failed" if kinds - {"budget"} else "insufficient_data")
        if not complete and not values:
            kinds = {error.get("kind") for error in errors if isinstance(error, dict)}
            if kinds:
                status = "cancelled" if "cancelled" in kinds else "permission_denied" if "permission" in kinds else "unsupported" if "unsupported" in kinds else "collection_failed" if kinds - {"budget"} else "insufficient_data"
        sources = [{**self.source(key, _FIELDS.get(key, "").split(","), object_id=object_id),
                    "read_completeness": "complete" if state["complete"] else "partial"} for key, state in zip(keys, states)]
        if missing_fields:
            # Endpoint/page completion and the required evidence for a check
            # are different facts. Missing evidence is not a new API failure.
            values = {**values, "missing_required_fields": list(missing_fields)}
        check = make_check(cid, title, status, values=self.public(values), summary=summary,
                           sources=sources,
                           judgement=judgement, basis=basis, limitations=list(limitations),
                           object_id=object_id, object_name=object_name, native_severity=native_severity,
                           verification=self.verification, completeness="complete" if complete and not missing_fields else "partial",
                           recommendation=recommendation)
        self.module["checks"].append(self.public(check))

    def ref(self, value, kinds):
        if not isinstance(value, str) or len(value) > 2048:
            return None
        try:
            parts = urlsplit(value)
            if parts.username or parts.password or parts.query:
                return None
            if parts.scheme or parts.netloc:
                if parts.scheme != "https" or parts.hostname != self.target.host or (parts.port or 443) != self.target.port:
                    return None
            match = re.fullmatch(r"/?api/([a-z-]+)/([A-Za-z0-9_-]{1,128})", parts.path)
            if not match or match.group(1) not in kinds:
                return None
            return {"type": match.group(1), "uuid": match.group(2)}
        except ValueError:
            return None

    def refs(self, values, kinds):
        return [ref for value in values[:200] if (ref := self.ref(value, kinds))] if isinstance(values, list) else []

    def inventory(self, kind, obj, values):
        entry = {"product": "avi", "object_type": kind, "object_id": _identity(obj),
                 "object_name": _name(obj), "tenant": self.scope["selected_tenant"], "values": values}
        self.module["inventory"].append(self.public(entry))


def _version_and_scope(ctx):
    version = _dict(ctx.get("version"))
    candidate = version.get("Version") or version.get("version")
    if isinstance(candidate, dict):
        version = candidate
        candidate = version.get("Version") or version.get("version")
    ctx.module["version"] = _scalar(candidate) or ""
    ctx.module["build"] = _scalar(version.get("build") or version.get("build_number") or version.get("Build")) or ""
    tenants = ctx.listed("tenants")
    ctx.scope["visible_tenants"] = [_pick(t, ("uuid", "name", "local")) for t in tenants]
    ctx.module.setdefault("coverage", {})["tenant_scope"] = ctx.scope
    selected = ctx.scope["selected_tenant"]
    selected_match = next((t for t in tenants if selected in {t.get("name"), t.get("uuid")}), None)
    ctx.module["target_identity"] = dict(ctx.module.get("target_identity") or {}, tenant_uuid=_identity(selected_match) if selected_match else "", selected_tenant=selected)
    if any(selected not in {t.get("name"), t.get("uuid")} for t in tenants):
        ctx.module["limitations"].append("仅采集显式选择的租户；其他可见租户未纳入本次检查。")
    status = "normal" if ctx.module["version"].startswith(API_VERSION) else "unsupported" if ctx.module["version"] else "insufficient_data"
    ctx.check("AVI-A1", "版本与账号覆盖范围", status,
              {"version": ctx.module["version"], "build": ctx.module["build"], **ctx.scope}, ["version", "tenants"],
              summary="版本来自 Controller，采集范围限所选租户。", limitations=["登录成功不证明所有接口有权限；构建号未返回时留空。"],
              basis="X-Avi-Version=30.2.5；实际版本与首批版本匹配。")
    return status != "unsupported"


def _service_records(raw):
    services = []
    for service in _rows(_dict(raw).get("service_states"))[:2000]:
        record = _pick(service, ("name", "state"))
        record["roles"] = [_scalar(r) for r in service.get("roles", [])[:20] if isinstance(r, str)] if isinstance(service.get("roles"), list) else []
        record["cluster_nodes"] = [{"name": _scalar(n.get("name")), "ip": _ip(n.get("ip"))} for n in _rows(service.get("cluster_nodes"))[:20]]
        record["detailed_state"] = [_pick(d, ("name", "node_name", "state", "status", "reason", "reason_code")) for d in _rows(service.get("detailed_state"))[:50]]
        record["criticality"] = "unknown"
        services.append(record)
    return services


def _cluster_and_resources(ctx):
    raw = _dict(ctx.get("cluster_runtime"))
    info = _dict(raw.get("node_info"))
    nodes = [_pick(n, ("uuid", "name", "role", "state", "up_since")) for n in _rows(raw.get("node_states"))]
    cluster = _pick(raw.get("cluster_state"), ("state", "up_since", "progress"))
    state = str(cluster.get("state", "")).upper()
    bad_nodes = [n for n in nodes if n.get("state") in {"CLUSTER_INACTIVE", "CLUSTER_FAILED", "CLUSTER_UNREACHABLE", "CLUSTER_DOWN"}]
    status = "abnormal" if bad_nodes or state in {"CLUSTER_DOWN", "CLUSTER_FAILED"} else "normal" if state in {"CLUSTER_UP_NO_HA", "CLUSTER_UP_HA_ACTIVE", "CLUSTER_UP"} and nodes else "insufficient_data"
    ctx.module["target_identity"].update(_pick(info, ("uuid", "cluster_uuid")))
    ctx.check("AVI-A2", "集群运行状态", status,
              {"cluster": cluster, "nodes": nodes, "nodes_count": _number(raw.get("nodes_count")), "critical_services": None}, ["cluster_runtime"],
              summary="展示原生集群状态；逐服务原生数据及适用性另项保存。",
              limitations=["单节点无 HA 按实际部署记录。", "30.2.x 读取来源；本次字段观察不等于 30.2.5 全形态验收。", "关键服务检查数据不足。"],
              judgement="NATIVE", basis="仅解释已明确的原生集群状态。")
    services = _service_records(raw)
    nonactive = [s for s in services if s.get("state") not in {"CLUSTER_ACTIVE", "SERVICE_UP", "UP", "RUNNING"}]
    native_states = {str(s.get("state") or "未返回") for s in services}
    missing_service_fields = ["critical_service_role_applicability"]
    if not services:
        missing_service_fields.append("service_states")
    elif any(not s.get("name") or not s.get("state") for s in services):
        missing_service_fields.append("service_states.name_or_state")
    ctx.check("AVI-A2:services", "管理服务状态与覆盖", "attention" if nonactive else "insufficient_data",
              {"services": services or None, "reported_count": len(services), "native_state_counts": {state: sum(str(s.get("state") or "未返回") == state for s in services) for state in native_states},
               "nonactive_reported_services": nonactive, "critical_service_scope_confirmed": False}, ["cluster_runtime"],
              summary="读取 Controller 原生 service_states；各服务关键性及可选角色适用性尚未确认。" if services else "本次没有取得逐服务状态字段。",
              limitations=["不把所有已登记集群服务当作关键或适用服务。", "原生集群服务声明不能替代操作系统进程及端到端能力验证。"],
              judgement="NATIVE", basis="实际 30.2.5 cluster/runtime.service_states；不以 cluster_state 替代。",
              missing_fields=missing_service_fields)
    for node in nodes:
        ctx.inventory("controller_node", node, node)
    ids = [_identity(n) for n in nodes if _identity(n)] or ([_identity(info)] if _identity(info) else [])
    observed = []
    window = _metric_window()
    for uuid in ids[:3]:
        query = dict(window, metric_id="controller_stats.avg_cpu_usage,controller_stats.avg_mem_usage,controller_stats.avg_disk_usage")
        raw_metrics = ctx.get("controller_metrics", uuid=uuid, query=query)
        observed.extend(_metric_rows(raw_metrics, uuid, query))
    evidence = [_metric_evidence(value) for cache_key, value in ctx.cache.items() if isinstance(cache_key, tuple) and cache_key[0] == "controller_metrics"]
    has_samples = any(metric.get("returned_sample_count", 0) > 0 for metric in observed)
    ctx.check("AVI-A3", "设备内部资源", "insufficient_data", {"metrics": observed, "partitions": None, "requested_window": window, "metric_response_evidence": evidence}, ["controller_metrics"],
              summary="展示已取得的 Controller 资源样本及窗口；尚无各内部磁盘分区及长期过载判断依据。" if has_samples else "本对象请求窗口没有取得有效资源样本；原因见响应证据，未据此认定全局无数据或设备不支持。",
              limitations=["未采到样本不能按零处理。", "磁盘汇总比例不代表所有内部文件系统。", "没有业务基线，不设资源告警阈值。"], basis="AVI 30.2.5 Controller metrics 原生指标和单位。",
              missing_fields=["internal_disk_partitions"] + ([] if has_samples else ["controller_resource_samples"]))


def _alarms(ctx):
    alerts = ctx.listed("alerts")
    for alert in alerts:
        record = _pick(alert, ("uuid", "name", "obj_uuid", "obj_name", "level", "state", "summary", "reason", "timestamp"))
        record["lifecycle"] = alarm_lifecycle_of("avi", alert)
        record["collected_at"] = ctx.source("alerts").get("collected_at")
        ctx.module["native_alerts"].append(ctx.public(record))
    active = [a for a in ctx.module["native_alerts"] if a["lifecycle"] == "active"]
    cleared = [a for a in ctx.module["native_alerts"] if a["lifecycle"] == "cleared"]
    unknown = [a for a in ctx.module["native_alerts"] if a["lifecycle"] == "unknown"]
    counts = {}
    for alert in active:
        level = alert.get("level", "未返回等级")
        counts[level] = counts.get(level, 0) + 1
    ctx.check("AVI-A4", "原生告警", "attention" if active else "insufficient_data" if unknown else "normal",
              {"collected_count": len(alerts), "active_count_in_collected": len(active), "cleared_count_in_collected": len(cleared), "active_by_native_level": counts, "unknown_state_count": len(unknown)}, ["alerts"],
              summary="原生告警按自身状态及级别保留；不转换为 P 等级。", judgement="NATIVE", basis="原生 level/state；只统计明确处于活动状态的已采记录。")


def _certificate_check(ctx, systems, *, certificate_rows=None, source_key="certificates"):
    bindings = []
    for system in systems:
        for location in ("portal_configuration", "secure_channel_configuration"):
            bindings.extend({"location": location, "certificate": ref} for ref in ctx.refs(_dict(system.get(location)).get("sslkeyandcertificate_refs"), {"sslkeyandcertificate"}))
    certificates = ctx.listed("certificates") if certificate_rows is None else certificate_rows
    now = datetime.now(timezone.utc)
    for certificate in certificates:
        native = _dict(certificate.get("certificate"))
        values = _pick(certificate, ("uuid", "name", "type", "status"))
        values["metadata"] = _pick(native, ("not_before", "not_after", "days_until_expire", "expiry_status", "fingerprint", "self_signed", "chain_verified", "signature_algorithm"))
        values["subject_common_name"] = _scalar(_dict(native.get("subject")).get("common_name"))
        values["subject_alt_names"] = [_scalar(s) for s in native.get("subject_alt_names", [])[:100] if isinstance(s, str)] if isinstance(native.get("subject_alt_names"), list) else []
        values["management_bindings"] = [b["location"] for b in bindings if b["certificate"]["uuid"] == _identity(certificate)]
        x509 = {}
        if native.get("certificate"):
            try:
                x509 = certificate_dates(native["certificate"])
            except (ValueError, TypeError, IndexError, UnicodeError):
                pass
        values["x509_validity"] = x509
        expires = _utc(x509.get("expires_at")) or _utc(native.get("not_after"))
        starts = _utc(x509.get("valid_from")) or _utc(native.get("not_before"))
        native_expiry = str(native.get("expiry_status", "")).upper()
        has_unzoned_dates = any(isinstance(native.get(field), str) and native.get(field) and _utc(native[field]) is None for field in ("not_before", "not_after"))
        values["date_interpretation"] = {"timezone": "unknown" if has_unzoned_dates else "explicit_or_not_returned",
                                         "independent_utc_validity_check": bool(expires),
                                         "utc_evidence_source": "x509_der_validity" if x509 else "native_explicit_timezone" if expires else None,
                                         "days_until_expire_semantics": "原生字段语义未核实为剩余有效天数；不用于倒计时，不覆盖日期字符串。"}
        values["evidence_differences"] = []
        if x509:
            values["x509_remaining_days"] = math.floor((expires-now).total_seconds() / 86400)
            for native_field, x509_field in (("not_before", "valid_from"), ("not_after", "expires_at")):
                try:
                    native_date = datetime.fromisoformat(str(native.get(native_field, "")).replace("Z", "+00:00"))
                except ValueError:
                    continue
                actual_date = _utc(x509.get(x509_field))
                # An unzoned native string is compared only as calendar text;
                # it is never silently assigned UTC or used to overrule DER.
                calendar_differs = native_date.replace(tzinfo=None) != actual_date.replace(tzinfo=None)
                instant_differs = native_date.tzinfo is not None and native_date.astimezone(timezone.utc) != actual_date
                if instant_differs or native_date.tzinfo is None and calendar_differs:
                    values["evidence_differences"].append({"field": native_field, "native_value": native.get(native_field), "x509_utc_value": x509[x509_field],
                                                          "comparison": "明确时区的时间不同" if native_date.tzinfo else "日历字段不同；原生时区未知，不将其直接作为同一时区比较"})
            if _number(native.get("days_until_expire")) is not None and native["days_until_expire"] != values["x509_remaining_days"]:
                values["evidence_differences"].append({"field": "days_until_expire", "native_value": native["days_until_expire"], "x509_remaining_days": values["x509_remaining_days"],
                                                      "comparison": "原生字段语义未核实；保留数值差异供核查，不据此判定错误"})
        if native_expiry == "SSL_CERTIFICATE_GOOD" and ((expires and expires <= now) or (starts and starts > now)):
            values["evidence_differences"].append({"field": "expiry_status", "native_value": native_expiry,
                                                  "utc_date_evidence": "expired" if expires and expires <= now else "not_yet_valid"})
        if (expires and expires <= now) or native_expiry == "SSL_CERTIFICATE_EXPIRED":
            status, summary = "abnormal", "证书已到期。"
        elif starts and starts > now:
            status, summary = "abnormal", "证书尚未进入有效期。"
        elif certificate.get("status") == "SSL_CERTIFICATE_PENDING":
            status, summary = "attention", "设备原生证书状态为生成待完成；不能确认可用。"
        elif native_expiry == "SSL_CERTIFICATE_EXPIRY_WARNING":
            status, summary = "attention", "设备原生到期状态要求关注；未另设天数阈值。"
        elif expires and expires > now:
            status, summary = "normal", "采集时证书在有效期内；域名、撤销状态及完整信任链未由此确认。"
        elif native_expiry == "SSL_CERTIFICATE_GOOD":
            status, summary = "normal", "设备原生到期状态为 SSL_CERTIFICATE_GOOD；日期未明确时区，程序未独立确认 UTC 有效期。"
        else:
            status, summary = "insufficient_data", "缺少可解释的证书有效期。"
        ctx.inventory("certificate", certificate, values)
        ctx.check("AVI-A5:" + (_identity(certificate) or str(len(ctx.module["checks"]))), "证书有效期", status, values, [source_key] + (["system"] if is_management_module(ctx.module) else []),
                  object_id=_identity(certificate), object_name=_name(certificate), summary=summary,
                  judgement="NATIVE" if not expires else "PROGRAM",
                  basis="原生 expiry_status 独立保留；优先采用内存解析 X509 DER 的 UTC 有效期，否则只比较明确时区的原生日期。", limitations=["内存解析 X509 有效期不验证签名、证书链或撤销状态。", "连接身份校验结果单独记录。", "不查询外部 OCSP/CRL。", "无时区日期原样保存，days_until_expire 不冒充已核实倒计时。"])
    if not certificates:
        ctx.check("AVI-A5", "管理绑定证书" if is_management_module(ctx.module) else "管理与业务证书", "insufficient_data", {"management_bindings": bindings, "certificate_count": 0}, ["system", source_key],
                  summary="没有取得证书元数据，不能判断管理证书正常。")
    return certificates


def _management_certificates(ctx, systems):
    bindings = []
    binding_coverage = {"accepted_reference_count": 0, "rejected_reference_count": 0, "truncated_reference_count": 0, "invalid_shape_fields": []}
    for system in systems:
        for field in ("portal_configuration", "secure_channel_configuration"):
            configuration = system.get(field)
            if configuration is None:
                continue
            if not isinstance(configuration, dict):
                binding_coverage["invalid_shape_fields"].append(field)
                continue
            raw_refs = configuration.get("sslkeyandcertificate_refs")
            if raw_refs is None:
                continue
            if not isinstance(raw_refs, list):
                binding_coverage["invalid_shape_fields"].append(field + ".sslkeyandcertificate_refs")
                continue
            binding_coverage["truncated_reference_count"] += max(0, len(raw_refs) - 200)
            for raw_ref in raw_refs[:200]:
                ref = ctx.ref(raw_ref, {"sslkeyandcertificate"})
                if ref is None:
                    binding_coverage["rejected_reference_count"] += 1
                else:
                    bindings.append({"usage": field, "certificate_id": ref["uuid"]})
                    binding_coverage["accepted_reference_count"] += 1
    binding_gap = bool(binding_coverage["rejected_reference_count"] or binding_coverage["truncated_reference_count"] or binding_coverage["invalid_shape_fields"])
    ctx.management_binding_coverage_incomplete = binding_gap
    if "certificate_details" not in ROUTES:
        ctx.check("AVI-A5", "管理绑定证书", "insufficient_data", {"management_bindings": bindings, "binding_coverage": binding_coverage, "details_source_status": "source_unverified"}, ["system"],
                  summary="管理配置引用已保留；尚无可回查的同版本单项证书读取依据，未读取全证书目录。",
                  basis="单项读取用途与版本必须先核实，不以新版目录或全量证书列表替代。",
                  missing_fields=["management_bound_certificate_metadata"], limitations=["无法判断管理绑定证书有效期；不据此认定设备不支持。"])
        return []
    rows = []
    expected_ids = list(dict.fromkeys(binding["certificate_id"] for binding in bindings))
    for uuid in expected_ids:
        raw = ctx.get("certificate_details", uuid=uuid)
        if isinstance(raw, dict) and _identity(raw) == uuid:
            rows.append(raw)
        elif raw is not None:
            error = ctx.error(CollectionError("invalid_response", "管理绑定证书单项身份或结构无效"), "certificate_details")
            state = {"complete": False, "errors": [error]}
            ctx.collections["certificate_details"] = state
            ctx.object_collections[("certificate_details", uuid)] = state
    ctx.cache["certificates"] = rows
    if rows:
        _certificate_check(ctx, systems, certificate_rows=rows, source_key="certificate_details")
    if not expected_ids:
        ctx.check("AVI-A5", "管理绑定证书", "insufficient_data", {"management_bindings": bindings, "binding_coverage": binding_coverage, "certificate_count": 0}, ["system"],
                  summary="本次未取得可确认的管理证书绑定，不读取其他证书目录补齐。", missing_fields=["management_bound_certificate_reference"])
    elif binding_gap:
        ctx.check("AVI-A5:bindings", "管理证书绑定覆盖", "insufficient_data", {"binding_coverage": binding_coverage}, ["system"],
                  summary="部分管理证书引用无效、非同源、形态未核实或超过预算；仅已接受绑定对象取得单项观察。",
                  missing_fields=["management_certificate_binding_coverage"], limitations=["不跟随被拒绝引用，不回退全证书目录。", "已取得证书的日期结论不代表管理绑定覆盖完整。"])
    for uuid in expected_ids:
        if uuid not in {_identity(row) for row in rows}:
            ctx.check("AVI-A5:" + uuid, "管理绑定证书", "insufficient_data", {"certificate_id": uuid, "metadata": None}, ["system", "certificate_details"],
                      object_id=uuid, summary="管理绑定证书单项未取得有效元数据；其他管理检查继续。", missing_fields=["management_bound_certificate_metadata"])
    return rows


def _license(ctx):
    statuses = ctx.listed("license_status")
    ledgers = ctx.listed("license_ledger")
    native = [{"saas_status": _pick(s.get("saas_status"), ("connected", "enabled", "expired", "message", "name", "reserve_service_units")),
               "service_units": _pick(_dict(s.get("service_update")).get("service_units"), ("available_service_units", "used_service_units"))} for s in statuses]
    usage = [{"tier": _scalar(t.get("tier")), "usage": _pick(t.get("usage"), ("available", "consumed", "escrow", "remaining"))} for l in ledgers for t in _rows(l.get("tier_usages"))]
    expired = any(s["saas_status"].get("enabled") is True and s["saas_status"].get("expired") is True for s in native)
    ctx.check("AVI-A6", "授权与容量", "abnormal" if expired else "insufficient_data", {"native_status": native, "tier_usage": usage}, ["license_status", "license_ledger"],
              summary="只展示已返回的授权口径；未取得完整本地授权有效期。", judgement="NATIVE",
              basis="SaaS expired 只在明确启用 SaaS 时判定；本地授权不据此推断。", limitations=["SaaS 未启用不等于设备未授权。", "未读取授权密钥。"],
              missing_fields=["local_license_validity_and_expiration"])


def _backup(ctx):
    configs = ctx.listed("backup_config")
    schedules = ctx.listed("schedulers")
    backups = ctx.listed("backups")
    # timestamp is not an accepted server-side sort field on the verified
    # 30.2.5 backup route. Order only the records actually collected in memory.
    backups = sorted(backups, key=lambda b: _utc(b.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    config_ids = {_identity(c) for c in configs if _identity(c)}
    selected = []
    for schedule in schedules:
        ref = ctx.ref(schedule.get("backup_config_ref"), {"backupconfiguration"})
        if ref and (ref["uuid"] in config_ids or "BACKUP" in str(schedule.get("scheduler_action", "")).upper()):
            selected.append(_pick(schedule, ("uuid", "name", "enabled", "scheduler_action", "frequency", "frequency_unit", "start_date_time", "end_date_time", "run_mode")))
    enabled = any(s.get("enabled") is True for s in selected)
    values = {"configuration": [_pick(c, ("uuid", "name", "save_local", "upload_to_remote_host", "upload_to_s3", "maximum_backups_stored")) for c in configs],
              "backup_schedules": selected, "automatic_backup_enabled": enabled if ctx.collections["schedulers"]["complete"] else None,
              "existing_backup_records": [{**_pick(b, ("uuid", "timestamp")), "backup_configuration": ctx.ref(b.get("backup_config_ref"), {"backupconfiguration"}),
                                            "scheduler": ctx.ref(b.get("scheduler_ref"), {"scheduler"})} for b in backups[:50]], "last_success": None, "last_failure": None, "restore_verified": None}
    configuration_complete = ctx.collections["backup_config"]["complete"] and ctx.collections["schedulers"]["complete"]
    ctx.check("AVI-A7", "备份", "attention" if configuration_complete and (not configs or not enabled) else "insufficient_data", values, ["backup_config", "schedulers", "backups"],
              summary="未配置自动备份。" if configuration_complete and (not configs or not enabled) else "已读取的备份配置与记录见取数值；尚不能证明最近备份成功。",
              limitations=["backup 响应没有成功或失败字段。", "未触发备份，未验证恢复。"], basis="备份配置引用、scheduler.enabled 与原生备份记录分别保存。",
              missing_fields=["last_backup_success_time_and_result", "last_backup_failure_time_and_result"])


def _operations(ctx, systems):
    syslogs = ctx.listed("syslog")
    projected = []
    for system in systems:
        dns = _dict(system.get("dns_configuration"))
        ntp = _dict(system.get("ntp_configuration"))
        ntp_ips = [_ip(n) for n in ntp.get("ntp_server_list", [])] if isinstance(ntp.get("ntp_server_list"), list) else []
        ntp_ips += [_ip(n.get("server")) for n in _rows(ntp.get("ntp_servers"))]
        projected.append({"dns_servers": [_ip(s) for s in dns.get("server_list", [])] if isinstance(dns.get("server_list"), list) else [],
                          "dns_search_domain": _scalar(dns.get("search_domain")), "ntp_servers": list(dict.fromkeys(x for x in ntp_ips if x))})
    logs = [{"uuid": _identity(s), "name": _name(s), "servers": [_pick(server, ("syslog_server", "syslog_server_port", "udp", "tls_enable")) for server in _rows(s.get("syslog_servers"))]} for s in syslogs]
    ctx.check("AVI-A8", "DNS、NTP 与远程日志", "insufficient_data", {"configuration": projected, "alert_syslog_configuration": logs}, ["system", "syslog"],
              summary="读取已有配置；未确认 DNS 可用、NTP 已同步或远程日志已送达。", limitations=["远程日志来源只覆盖告警 syslog 配置。", "不发起 DNS/NTP/syslog 测试。"], basis="配置存在仅表示已配置。",
              missing_fields=["dns_operational_state", "ntp_synchronization_state", "remote_logging_delivery_state"])


def _index(items):
    return {_identity(item): item for item in items if _identity(item)}


def _clouds(ctx):
    configs = ctx.listed("clouds")
    runtimes = _index(ctx.listed("cloud_runtime"))
    if not configs:
        ctx.check("AVI-C1", "Cloud 与租户", "not_deployed", {"cloud_count": 0, **ctx.scope}, ["clouds"], summary="所选租户未读取到 Cloud 对象。")
    for config in configs:
        uuid = _identity(config)
        raw = _dict(ctx.get("cloud_status", uuid=uuid)) if uuid else {}
        runtime = _dict(runtimes.get(uuid))
        operation = _oper(raw) or _oper(runtime)
        if not operation and raw.get("state"):
            operation = _pick(raw, ("state", "reason"))
        status, summary = _oper_result(operation)
        values = {"configuration": _pick(config, ("uuid", "name", "vtype")), "native_runtime": _pick(runtime, ("state", "reason")), "native_status": operation}
        ctx.inventory("cloud", config, values)
        ctx.check("AVI-C1:" + (uuid or "missing-id"), "Cloud 连接状态", status, values, ["clouds", "cloud_runtime", "cloud_status"], object_id=uuid, object_name=_name(config),
                  summary=summary, judgement="NATIVE", limitations=["未直接访问 Cloud 对接环境。"])


def _cloud_registration(ctx):
    """A Cloud configuration is a registration fact, never a connection test."""
    rows = ctx.listed("clouds", query={"fields": "uuid,name,vtype,tenant_ref"})
    records = [_pick(row, ("uuid", "name", "vtype")) for row in rows]
    known = all(isinstance(row.get("vtype"), str) and row["vtype"] for row in rows)
    ctx.check("AVI-C1", "Cloud 登记配置事实", "not_applicable" if not rows else "normal" if known else "insufficient_data",
              {"configured_clouds": records, "configured_count": len(records), "connection_verified": False,
               "scope": "仅当前所选租户配置记录"}, ["clouds"],
              summary="已读取所选租户的 Cloud 登记配置事实；不据类型或配置存在推断已连接 vCenter。",
              limitations=["没有连接 vCenter，不读取 Cloud 运行态、SE 或业务目录。"],
              basis="原生 uuid/name/vtype 配置字段；不把已配置当作已连接。",
              missing_fields=[] if known else ["cloud_registration_type"])


def _service_engines(ctx):
    configs = ctx.listed("ses")
    runtime_objects = ctx.listed("se_inventory")
    runtimes = _index(runtime_objects)
    if not configs:
        ctx.check("AVI-C2", "Service Engine", "insufficient_data" if runtime_objects else "not_deployed", {"count": 0, "unmatched_runtime_count": len(runtime_objects)}, ["ses", "se_inventory"],
                  summary="配置与运行对象范围存在差异，不能确认未部署。" if runtime_objects else "所选租户未部署 SE；真实 SE 异常识别待验收。", limitations=["空对象不验证连接异常、资源或承载能力。"])
    for config in configs:
        runtime = _dict(_dict(runtimes.get(_identity(config))).get("runtime"))
        operation = _oper(runtime)
        status, summary = _oper_result(operation)
        values = {"configuration": _pick(config, ("uuid", "name", "enable_state", "vcpus", "memory")),
                  "se_group": ctx.ref(config.get("se_group_ref"), {"serviceenginegroup"}), "runtime": operation,
                  "heartbeat": _pick(runtime.get("hb_status"), ("last_hb_req_sent", "last_hb_resp_recv", "num_hb_misses", "num_outstanding_hb")),
                  "license": _pick(runtime, ("license_state", "licensed_service_cores"))}
        ctx.inventory("service_engine", config, values)
        ctx.check("AVI-C2:" + (_identity(config) or "missing-id"), "Service Engine 运行状态", status, values, ["ses", "se_inventory"],
                  object_id=_identity(config), object_name=_name(config), summary=summary, judgement="NATIVE", limitations=["配置 vCPU/内存不代表实际使用率或内部磁盘。"])
        window = _metric_window()
        metric = ctx.get("se_metrics", uuid=_identity(config), query=dict(window, metric_id="se_stats.avg_cpu_usage,se_stats.avg_mem_usage,se_stats.avg_disk1_usage")) if _identity(config) else None
        ctx.check("AVI-C2:" + (_identity(config) or "missing-id") + ":resources", "Service Engine 资源采样", "insufficient_data",
                  {"metrics": _metric_rows(metric, _identity(config), window), "requested_window": window}, ["se_metrics"],
                  object_id=_identity(config), object_name=_name(config), summary="展示已有 SE 资源样本；没有业务阈值，未判断长期过载。",
                  limitations=["disk1 原生指标不代表已检查各文件系统分区。"])
    groups = ctx.listed("se_groups")
    if not groups:
        ctx.check("AVI-C3", "SE 组与冗余", "not_deployed", {"count": 0}, ["se_groups"], summary="所选租户没有读取到 SE 组。")
    for group in groups:
        uuid = _identity(group)
        raw = _dict(ctx.get("se_group_runtime", uuid=uuid)) if uuid else {}
        members = [_identity(se) for se in configs if ctx.ref(se.get("se_group_ref"), {"serviceenginegroup"}) == {"type": "serviceenginegroup", "uuid": uuid}]
        values = {"configuration": _pick(group, ("uuid", "name", "ha_mode", "min_scaleout_per_vs", "max_scaleout_per_vs", "buffer_se", "max_se")),
                  "configuration_member_ids": members, "native_oper_status": _oper(raw), "actual_redundancy_confirmed": None}
        ctx.inventory("service_engine_group", group, values)
        ctx.check("AVI-C3:" + (uuid or "missing-id"), "SE 组与冗余", "insufficient_data", values, ["se_groups", "se_group_runtime"],
                  object_id=uuid, object_name=_name(group), summary="HA 配置与配置关联成员已读取；当前冗余可用性尚无充分依据。", limitations=["不触发切换；不编造统一 SE 数量标准。"],
                  missing_fields=["actual_redundancy_runtime_state"])


def _vs_and_pools(ctx):
    virtual_services = ctx.listed("virtual_services")
    vs_runtime_objects = ctx.listed("vs_inventory")
    vs_runtime = _index(vs_runtime_objects)
    vsvips = _index(ctx.listed("vsvips")) if virtual_services else {}
    application_profiles = _index(ctx.listed("application_profiles")) if virtual_services else {}
    network_profiles = _index(ctx.listed("network_profiles")) if virtual_services else {}
    pools = ctx.listed("pools")
    pool_runtime_objects = ctx.listed("pool_inventory")
    pool_runtime = _index(pool_runtime_objects)
    for objects, cid, title, keys in ((virtual_services, "AVI-C4", "虚拟服务", ["virtual_services", "vs_inventory"]), (pools, "AVI-C5", "后端池", ["pools", "pool_inventory"])):
        if not objects:
            unmatched = len(vs_runtime_objects) if cid == "AVI-C4" else len(pool_runtime_objects)
            ctx.check(cid, title, "insufficient_data" if unmatched else "not_deployed", {"count": 0, "unmatched_runtime_count": unmatched}, keys,
                      summary="配置与运行对象范围存在差异，不能确认未部署。" if unmatched else "所选租户未读取到业务对象；真实业务状态及故障识别待验收。")
    for vs in virtual_services:
        uuid = _identity(vs)
        runtime = _dict(_dict(vs_runtime.get(uuid)).get("runtime"))
        operation = _oper(runtime)
        status, summary = _oper_result(operation, vs.get("enabled"))
        vip_ref = ctx.ref(vs.get("vsvip_ref"), {"vsvip"})
        application_ref = ctx.ref(vs.get("application_profile_ref"), {"applicationprofile"})
        network_ref = ctx.ref(vs.get("network_profile_ref"), {"networkprofile"})
        bound_vip = _dict(vsvips.get(vip_ref["uuid"])) if vip_ref else {}
        app_profile = _dict(application_profiles.get(application_ref["uuid"])) if application_ref else {}
        net_profile = _dict(network_profiles.get(network_ref["uuid"])) if network_ref else {}
        values = {"configuration": _pick(vs, ("uuid", "name", "enabled", "type")),
                  "services": [_pick(s, ("port", "port_range_end", "enable_ssl", "enable_http2", "protocol")) for s in _rows(vs.get("services"))],
                  "vip": [{"vip_id": _scalar(v.get("vip_id")), "ip_address": _ip(v.get("ip_address")), "enabled": _scalar(v.get("enabled"))} for v in _rows(vs.get("vip") or bound_vip.get("vip"))],
                  "configured_fqdns": [_scalar(v.get("fqdn")) for v in _rows(bound_vip.get("dns_info")) if isinstance(v.get("fqdn"), str)],
                  "application_profile": application_ref, "network_profile": network_ref,
                  "configured_protocol": {"application_type": _scalar(app_profile.get("type")), "network_type": _scalar(_dict(net_profile.get("profile")).get("type"))},
                  "pool": ctx.ref(vs.get("pool_ref"), {"pool"}), "pool_group": ctx.ref(vs.get("pool_group_ref"), {"poolgroup"}),
                  "se_group": ctx.ref(vs.get("se_group_ref"), {"serviceenginegroup"}), "vsvip": vip_ref,
                  "certificates": ctx.refs(vs.get("ssl_key_and_certificate_refs"), {"sslkeyandcertificate"}),
                  "ssl_profile": ctx.ref(vs.get("ssl_profile_ref"), {"sslprofile"}), "runtime": operation,
                  "percent_ses_up": _number(runtime.get("percent_ses_up"))}
        ctx.inventory("virtual_service", vs, values)
        used_keys = ["virtual_services", "vs_inventory"] + (["vsvips"] if vip_ref else []) + (["application_profiles"] if application_ref else []) + (["network_profiles"] if network_ref else [])
        ctx.check("AVI-C4:" + (uuid or "missing-id"), "虚拟服务运行状态", status, values, used_keys,
                  object_id=uuid, object_name=_name(vs), summary=summary, judgement="NATIVE", limitations=["配置存在及原生 UP 不能代替主动业务可用性测试。", "poolgroup 仅记录引用，未展开部署策略；缺失 VIP 或协议字段不能视为已确认。"])
    backend_count = 0
    for pool in pools:
        uuid = _identity(pool)
        runtime = _dict(_dict(pool_runtime.get(uuid)).get("runtime"))
        operation = _oper(runtime)
        status, summary = _oper_result(operation, pool.get("enabled"))
        counts = _pick(runtime, ("num_servers", "num_servers_enabled", "num_servers_up"))
        if pool.get("enabled") is not False and _number(counts.get("num_servers_enabled")) not in {None, 0} and _number(counts.get("num_servers_up")) == 0:
            status, summary = "abnormal", "原生池状态报告有启用成员且健康成员为零。"
        values = {"configuration": _pick(pool, ("uuid", "name", "enabled", "lb_algorithm", "default_server_port")), "runtime": operation, "native_counts": counts,
                  "configured_server_count": len(_rows(pool.get("servers"))), "health_monitors": ctx.refs(pool.get("health_monitor_refs"), {"healthmonitor"}),
                  "ssl_profile": ctx.ref(pool.get("ssl_profile_ref"), {"sslprofile"})}
        ctx.inventory("pool", pool, values)
        ctx.check("AVI-C5:" + (uuid or "missing-id"), "后端池运行状态", status, values, ["pools", "pool_inventory"],
                  object_id=uuid, object_name=_name(pool), summary=summary, judgement="NATIVE", limitations=["分配算法仅展示，未按统一标准判断。"])
        servers = _rows(pool.get("servers"))
        if not servers:
            continue
        raw = ctx.get("server_runtime", uuid=uuid) if uuid else None
        runtime_rows = _server_rows(raw)
        for server in servers:
            backend_count += 1
            ip = _ip(server.get("ip"))
            port = server.get("port", pool.get("default_server_port"))
            matching = [r for r in runtime_rows if _ip(r.get("ip") or r.get("ip_addr")) == ip and r.get("port") == port]
            observed = [_oper(r) for r in matching]
            statuses = {_oper_result(o, server.get("enabled"))[0] for o in observed}
            server_status = "not_applicable" if server.get("enabled") is False or pool.get("enabled") is False else "abnormal" if "abnormal" in statuses else "normal" if statuses == {"normal"} else "insufficient_data"
            entry = {"pool_uuid": uuid, "address": ip, "port": _scalar(port), "enabled": _scalar(server.get("enabled")), "pool_enabled": _scalar(pool.get("enabled")), "observed_runtime": observed,
                     "state_conflict": len({o.get("state") for o in observed if o.get("state")}) > 1}
            sid = f"{uuid}:{ip}:{port}"
            ctx.inventory("backend_server", {"uuid": "", "name": sid}, entry)
            ctx.check("AVI-C6:" + sid, "后端服务器健康状态", server_status, entry, ["pools", "server_runtime"],
                      object_id=sid, object_name=sid, summary="手动停用。" if server.get("enabled") is False else "仅使用 Controller 已有健康结果；未主动探测。",
                      judgement="NATIVE", limitations=["多 SE 结果冲突原样保留；缺结果不按健康处理。"])
    if not backend_count:
        ctx.check("AVI-C6", "后端服务器", "not_deployed", {"configured_member_count": 0}, ["pools"], summary="所选租户未读取到后端成员；后端异常识别待真实场景验收。")
    return virtual_services


def _server_rows(raw):
    if isinstance(raw, list):
        return _rows(raw)
    raw = _dict(raw)
    for key in ("results", "servers", "server_runtime", "server"):
        if isinstance(raw.get(key), list):
            return _rows(raw[key])
    return [raw] if ("ip" in raw or "ip_addr" in raw) and "port" in raw else []


def _http_projection(value):
    value = _dict(value)
    result = _pick(value, ("auth_type", "exact_http_request"))
    request = value.get("http_request")
    if isinstance(request, str):
        # Never persist request headers, query strings, bodies or authentication.
        first = request.splitlines()[0].split() if request.splitlines() else []
        if len(first) >= 2 and re.fullmatch(r"[A-Z]{3,10}", first[0]):
            path = urlsplit(first[1]).path
            if path.startswith("/"):
                result.update(method=first[0], path=path[:1024])
    result["expected_response_codes"] = [_scalar(x) for x in value.get("http_response_code", [])[:20] if isinstance(x, str)] if isinstance(value.get("http_response_code"), list) else []
    return result


def _monitors_and_tls(ctx, virtual_services, certificates):
    monitors = ctx.listed("health_monitors")
    for monitor in monitors:
        values = _pick(monitor, ("uuid", "name", "type", "monitor_port", "send_interval", "receive_timeout", "successful_checks", "failed_checks"))
        values["http_configuration"] = _http_projection(monitor.get("http_monitor") or monitor.get("https_monitor"))
        ctx.inventory("health_monitor", monitor, values)
        ctx.check("AVI-C7:" + (_identity(monitor) or "missing-id"), "健康检查配置", "insufficient_data", values, ["health_monitors"],
                  object_id=_identity(monitor), object_name=_name(monitor), summary="展示探测配置，未执行额外探测；次数参数属于配置。",
                  limitations=["successful_checks/failed_checks 不是已有探测计数。", "间隔和超时缺少业务基线，不判断合理性。"])
    if not monitors:
        ctx.check("AVI-C7", "健康检查配置", "not_deployed", {"count": 0}, ["health_monitors"], summary="所选租户没有读取到健康检查对象。")
    profiles = ctx.listed("ssl_profiles")
    for profile in profiles:
        values = _pick(profile, ("uuid", "name", "type", "accepted_ciphers", "enable_ssl_session_reuse"))
        values["accepted_versions"] = [_pick(v, ("type",)) for v in _rows(profile.get("accepted_versions"))]
        values["cipher_enums"] = [_scalar(x) for x in profile.get("cipher_enums", [])[:100] if isinstance(x, str)] if isinstance(profile.get("cipher_enums"), list) else []
        ctx.inventory("ssl_profile", profile, values)
    bindings = [{"virtual_service_uuid": _identity(vs), "certificates": ctx.refs(vs.get("ssl_key_and_certificate_refs"), {"sslkeyandcertificate"}),
                 "ssl_profile": ctx.ref(vs.get("ssl_profile_ref"), {"sslprofile"}),
                 "configured_domains": [_scalar(x) for x in vs.get("vh_domain_name", [])[:100] if isinstance(x, str)] if isinstance(vs.get("vh_domain_name"), list) else []} for vs in virtual_services]
    ctx.check("AVI-C8", "业务证书与 TLS", "insufficient_data" if virtual_services else "not_deployed", {"bindings": bindings, "profile_count": len(profiles), "certificate_fact_check_prefix": "AVI-A5:"},
              ["virtual_services", "ssl_profiles", "certificates"], summary="证书到期结论复用证书检查；TLS 配置和域名绑定供人工复核。" if virtual_services else "未部署虚拟服务，业务证书绑定与 TLS 故障识别待验收。",
              limitations=["未主动握手业务入口，未验证服务实际采用的 TLS。", "SNI 域名不能替代完整客户预期域名清单。"])


def _metric_window():
    stop = datetime.now(timezone.utc).replace(microsecond=0)
    return {"start": (stop - timedelta(minutes=15)).isoformat(), "stop": stop.isoformat(), "step": 60, "limit": 15, "pad_missing_data": "false"}


_METRIC_UNITS = {"controller_stats.avg_cpu_usage": "PERCENT", "controller_stats.avg_mem_usage": "PERCENT", "controller_stats.avg_disk_usage": "PERCENT",
                 "se_stats.avg_cpu_usage": "PERCENT", "se_stats.avg_mem_usage": "PERCENT", "se_stats.avg_disk1_usage": "PERCENT",
                 "l4_client.max_open_conns": "METRIC_COUNT", "l4_client.avg_bandwidth": "BITS_PER_SECOND", "l7_server.avg_application_response_time": "MILLISECONDS", "l7_client.avg_error_responses": "PER_SECOND"}


def _metric_evidence(value):
    records = _rows(value)
    series = [series for record in records for series in _rows(record.get("series"))]
    metadata_keys = {"metric_id", "start", "stop", "step", "limit", "entity_uuid", "metric_entity", "url"}
    metadata_only = bool(records) and all(set(record) <= metadata_keys and bool(set(record) & {"metric_id", "entity_uuid", "start", "stop"}) for record in records)
    if value is None:
        classification = "no_response_or_request_failed"
    elif any("series" in record and not isinstance(record["series"], list) for record in records):
        classification = "unverified_series_shape"
    elif series:
        classification = "series_returned"
    elif any("series" in record for record in records):
        classification = "empty_series_in_requested_window"
    elif metadata_only:
        classification = "metadata_only_no_samples_in_requested_window"
    else:
        classification = "unknown_response_shape"
    return {"response_type": type(value).__name__, "series_count": len(series),
            "returned_point_count": sum(len(_rows(s.get("data"))) for s in series),
            "classification": classification,
            "reason_verified": False, "scope_note": "仅说明当前对象及请求窗口；不推断全局无资源数据或版本不支持。"}


def _annotate_usage(ctx):
    """Attach only observed configuration references; never infer by names."""
    management = is_management_module(ctx.module)
    object_keys = ("system", "certificates") if management else ("pools", "virtual_services", "system", "certificates", "health_monitors", "ssl_profiles")
    objects = {key: ctx.cache.get(key, []) for key in object_keys}
    objects = {key: value if isinstance(value, list) else [] for key, value in objects.items()}
    tenant_id = ctx.module.get("target_identity", {}).get("tenant_uuid") or ""
    edges, rejected_keys = {}, ({"system"} if management and getattr(ctx, "management_binding_coverage_incomplete", False) else set())

    def add(key, source_type, obj, value, target_type, usage, field):
        values = value if isinstance(value, list) else ([] if value is None else [value])
        observed = getattr(ctx, "reference_observations", {}).get((key, field), ctx.observations.get(key, []))
        moment = observed[-1].get("collected_at") if observed else None
        complete = ctx.collections.get(key, {}).get("complete") is True and key not in rejected_keys
        for raw_ref in values[:200]:
            ref = ctx.ref(raw_ref, {target_type})
            if ref is None:
                rejected_keys.add(key)
                continue
            edge = {"source_type": source_type, "source_id": _identity(obj), "source_name": _name(obj), "target_type": target_type, "target_id": ref["uuid"],
                    "usage": usage, "source_field": field, "source_path": ROUTES[key].path, "tenant_id": tenant_id, "collected_at": moment,
                    "reference_completeness": "complete" if complete else "partial", "configuration_only": True}
            if edge not in edges.setdefault((target_type, ref["uuid"]), []):
                edges[(target_type, ref["uuid"])].append(edge)

    for pool in objects.get("pools", []):
        add("pools", "pool", pool, pool.get("health_monitor_refs"), "healthmonitor", "pool_health_monitor", "health_monitor_refs")
        add("pools", "pool", pool, pool.get("ssl_profile_ref"), "sslprofile", "pool_tls", "ssl_profile_ref")
    for vs in objects.get("virtual_services", []):
        add("virtual_services", "virtualservice", vs, vs.get("ssl_profile_ref"), "sslprofile", "virtual_service_tls", "ssl_profile_ref")
        add("virtual_services", "virtualservice", vs, vs.get("ssl_key_and_certificate_refs"), "sslkeyandcertificate", "virtual_service_certificate", "ssl_key_and_certificate_refs")
    for system in objects["system"]:
        portal = _dict(system.get("portal_configuration"))
        secure = _dict(system.get("secure_channel_configuration"))
        add("system", "systemconfiguration", system, portal.get("sslprofile_ref"), "sslprofile", "management_portal", "portal_configuration.sslprofile_ref")
        add("system", "systemconfiguration", system, portal.get("sslkeyandcertificate_refs"), "sslkeyandcertificate", "management_portal", "portal_configuration.sslkeyandcertificate_refs")
        add("system", "systemconfiguration", system, secure.get("sslkeyandcertificate_refs"), "sslkeyandcertificate", "management_secure_channel", "secure_channel_configuration.sslkeyandcertificate_refs")

    parent_keys = {"healthmonitor": ("pools",), "sslprofile": ("system",) if management else ("pools", "virtual_services", "system"), "sslkeyandcertificate": ("system",) if management else ("virtual_services", "system")}
    kinds = {"health_monitor": "healthmonitor", "ssl_profile": "sslprofile", "certificate": "sslkeyandcertificate"}
    certificate_groups = {}
    for item in ctx.module["inventory"]:
        if item.get("object_type") != "certificate":
            continue
        sha = _dict(_dict(item.get("values")).get("x509_validity")).get("certificate_sha256")
        if isinstance(sha, str) and re.fullmatch(r"[0-9a-fA-F]{64}", sha):
            certificate_groups.setdefault(sha.lower(), []).append(item)
    additions = {}
    for item in ctx.module["inventory"]:
        target_type = kinds.get(item.get("object_type"))
        if not target_type:
            continue
        uuid = item.get("object_id", "")
        keys = parent_keys[target_type]
        complete = all(ctx.collections.get(key, {}).get("complete") is True and key not in rejected_keys for key in keys)
        usages = list(edges.get((target_type, uuid), []))
        values = item.get("values", {})
        extra = {"usages": usages, "reference_state": "referenced" if usages else "unreferenced_in_complete_selected_scope" if complete else "unknown_partial_scope",
                 "origin_status": "unknown", "reference_scope": {"tenant_id": tenant_id, "parent_sources": list(keys), "complete": complete},
                 "reference_scope_limits": ["仅覆盖当前租户管理门户与安全通道配置绑定，不据此验证实际 TLS 呈现。"] if management else ["仅覆盖明确声明的当前租户配置引用；无引用不代表全设备未使用。"]}
        if target_type == "sslkeyandcertificate":
            sha = _dict(values.get("x509_validity")).get("certificate_sha256")
            sha = sha.lower() if isinstance(sha, str) and re.fullmatch(r"[0-9a-fA-F]{64}", sha) else ""
            aliases = certificate_groups.get(sha, [item]) if sha else [item]
            merged = [edge for alias in aliases for edge in edges.get((target_type, alias.get("object_id", "")), [])]
            extra["usages"] = merged
            extra["reference_state"] = "referenced" if merged else extra["reference_state"]
            extra["identity"] = {"certificate_sha256": sha, "identity_basis": "x509_der_sha256" if sha else "target_tenant_object_uuid",
                                 "aliases": [{"object_id": a.get("object_id", ""), "name": a.get("object_name", "")} for a in aliases]}
            extra["reference_scope_limits"].append("未独立验证证书链或撤销状态。" if management else "未展开 PKI/CA 链等引用，不推断 CA 或客户端证书未使用。")
        additions[(target_type, uuid)] = extra
        values.update(ctx.public(extra))
    for check in ctx.module["checks"]:
        prefix = str(check.get("check_id", "")).split(":", 1)[0]
        target_type = {"AVI-A5": "sslkeyandcertificate", "AVI-C7": "healthmonitor"}.get(prefix)
        if target_type and (target_type, check.get("object_id", "")) in additions:
            check["values"].update(ctx.public(additions[(target_type, check["object_id"])]))
    ctx.module.setdefault("coverage", {})["reference_scope"] = {"tenant_id": tenant_id, "rejected_parent_source_keys": sorted(rejected_keys),
        "relationship_fields": (["system.portal_configuration.sslprofile_ref", "system.portal_configuration.sslkeyandcertificate_refs", "system.secure_channel_configuration.sslkeyandcertificate_refs"] if management else ["pool.health_monitor_refs", "pool.ssl_profile_ref", "virtualservice.ssl_profile_ref", "virtualservice.ssl_key_and_certificate_refs", "system.portal_configuration.sslprofile_ref", "system.portal_configuration.sslkeyandcertificate_refs", "system.secure_channel_configuration.sslkeyandcertificate_refs"]),
        "configuration_only": True, "system_origin_marker_verified": False}


def _management_gaps(ctx):
    gaps = []
    for cid, field, reason, source_keys in (
        ("AVI-A2:services", "service_states", "projection_omission", ["cluster_runtime"]),
        ("AVI-A3", "internal_disk_partitions", "not_implemented", ["controller_metrics"]),
        ("AVI-A6", "local_license_validity_and_expiration", "not_implemented", ["license_status", "license_ledger"]),
        ("AVI-A7", "last_backup_success_failure_time_and_result", "not_implemented", ["backup_config", "schedulers", "backups"]),
        *(([("AVI-A5", "management_bound_certificate_metadata", "not_implemented", ["system"])]) if is_management_module(ctx.module) and "certificate_details" not in ROUTES else []),
    ):
        check = next((c for c in ctx.module["checks"] if c["check_id"] == cid), None)
        observed = bool(_dict(check.get("values") if check else {}).get("services")) if field == "service_states" else False
        errors = [e for key in source_keys for e in ctx.collections.get(key, {}).get("errors", [])]
        classification = "permission_denied" if any(e.get("kind") == "permission" for e in errors) else "source_unverified" if field == "service_states" and not observed else reason
        gap = {"check_id": cid, "field": field, "classification": classification, "resolved": observed,
               "source_status": "observed_in_existing_source" if observed else "source_unverified" if field != "last_backup_success_failure_time_and_result" else "confirmed_sources_do_not_supply_result_fields",
               "source_keys": source_keys, "version_basis": [ROUTES[key].version_basis for key in source_keys], "http_error_evidence": errors,
               "note": "原生服务已补投影；关键性与能力仍待验证。" if observed else "不据此认定设备版本不支持或环境未配置；不使用相似字段代替。"}
        gaps.append(gap)
        if check:
            check["values"]["management_evidence_gap"] = ctx.public(gap)
    ctx.module.setdefault("coverage", {})["management_data_gaps"] = ctx.public(gaps)


def _metric_rows(raw, uuid, requested):
    metrics = _rows(raw)
    if isinstance(raw, dict) and isinstance(raw.get("series"), list):
        metrics = [raw]
    output = []
    for metric in metrics:
        mid = metric.get("metric_id")
        # Some Avi responses place metric id in each series header; both shapes
        # are explicit and no unknown counter is accepted.
        series = metric.get("series")
        if not isinstance(series, list):
            continue
        for entry in _rows(series):
            header = _dict(entry.get("header"))
            requested_ids = {value for value in str(requested.get("metric_id", "")).split(",") if value}
            metric_id = next((candidate for candidate in (header.get("metric_id"), header.get("name"), entry.get("metric_id"), mid)
                              if isinstance(candidate, str) and candidate in _METRIC_UNITS and (not requested_ids or candidate in requested_ids)), None)
            if metric_id is None:
                continue
            points = []
            rejected = 0
            timestamps = set()
            start, stop = _utc(requested.get("start")), _utc(requested.get("stop"))
            for point in _rows(entry.get("data"))[:15]:
                moment = _utc(point.get("timestamp"))
                if (value := _number(point.get("value"))) is not None and moment and start and stop and start <= moment <= stop and moment not in timestamps:
                    timestamps.add(moment)
                    points.append({"timestamp": moment.isoformat(), "value": value})
                else:
                    rejected += 1
            points.sort(key=lambda point: point["timestamp"])
            moments = sorted(timestamps)
            regular = all((b-a).total_seconds() == requested["step"] for a, b in zip(moments, moments[1:]))
            output.append({"object_id": uuid, "metric_id": metric_id, "unit": _METRIC_UNITS[metric_id], "requested_window": requested,
                           "returned_window": _pick(metric, ("start", "stop", "step")), "returned_sample_count": len(points), "samples": points,
                           "missing_samples": max(0, 15 - len(points)), "rejected_samples": rejected, "complete": len(points) == 15 and regular and rejected == 0})
    return output


def _business_metrics(ctx, virtual_services):
    if not virtual_services:
        ctx.check("AVI-C9", "既有业务指标", "not_deployed", {"virtual_service_count": 0}, ["virtual_services"], summary="没有虚拟服务，未请求业务指标；指标及故障识别待真实场景验收。")
        return
    window = _metric_window()
    for vs in virtual_services:
        uuid = _identity(vs)
        raw = ctx.get("vs_metrics", uuid=uuid, query=dict(window, metric_id="l4_client.max_open_conns,l4_client.avg_bandwidth,l7_server.avg_application_response_time,l7_client.avg_error_responses")) if uuid else None
        values = {"metrics": _metric_rows(raw, uuid, window), "requested_window": window}
        ctx.check("AVI-C9:" + (uuid or "missing-id"), "虚拟服务既有指标", "insufficient_data", values, ["vs_metrics"],
                  object_id=uuid, object_name=_name(vs), summary="展示已有采样及缺失情况；没有业务基线，不据此编造趋势或过载结论。", limitations=["采样预算是采集限制，不是设备健康阈值。"])


def collect_avi(target, credential, *, cancel_requested=None, transport_factory=ReadTransport, inspection_scope=None):
    """Collect only Controller management data in the explicit shared scope."""
    if target.product != "avi":
        raise ValueError("AVI 采集器只接受 AVI Controller 目标。")
    resolve_scope("avi", inspection_scope)
    routes = select_routes("avi", ROUTES, inspection_scope)
    matrix = management_check_matrix()
    try:
        transport = transport_factory(target, credential, routes, cancel_requested=cancel_requested,
                                      timeout=10.0, request_budget=120, page_budget=20,
                                      record_budget=2000, min_interval=0.5)
    except CollectionError as exc:
        module = mark_management_scope(new_module(target), inspection_scope)
        module["errors"].append(exc.as_dict())
        for row in matrix:
            module["checks"].append(make_check(row["id"], row["title"], "collection_failed", values={}, summary="未能建立受控连接。",
                                               limitations=[row["limitations"]], verification="unverified", completeness="incomplete"))
        return finish_module(sanitize_public(module, secrets=getattr(credential, "secret_values", (credential.password,))))
    ctx = _Collection(target, credential, transport)
    mark_management_scope(ctx.module, inspection_scope)
    try:
        transport.check_cancelled()
        transport.login_avi()
        if _version_and_scope(ctx):
            shared = {"systems": [], "certificates": []}

            def certificate_phase():
                shared["systems"] = ctx.listed("system")
                shared["certificates"] = _management_certificates(ctx, shared["systems"])

            for key, phase in (
                ("cluster_runtime", lambda: _cluster_and_resources(ctx)), ("alerts", lambda: _alarms(ctx)),
                ("license_status", lambda: _license(ctx)), ("backup_config", lambda: _backup(ctx)),
                ("clouds", lambda: _cloud_registration(ctx)),
                ("system", certificate_phase), ("system", lambda: _operations(ctx, shared["systems"])),
            ):
                try:
                    transport.check_cancelled()
                    phase()
                except CollectionError as exc:
                    ctx.error(exc, key)
                    if exc.kind == "cancelled":
                        break
                except Exception as exc:
                    ctx.error(exc, key)
        else:
            ctx.module["limitations"].append("实际版本未匹配首批 30.2.5，未继续解释其他配置及运行字段。")
    except CollectionError as exc:
        details = ctx.error(exc, "version")
        status = "cancelled" if details.get("kind") == "cancelled" else "permission_denied" if details.get("kind") == "permission" else "collection_failed"
        ctx.module["checks"].append(make_check("AVI-LOGIN", "Controller 会话认证", status, summary="未完成会话认证或采集。", values={}, sources=[make_source("/login", method="POST", version_basis=DOC, note="正常会话认证例外")], basis="仅正常认证，不开启 Basic。", verification=ctx.verification))
    except Exception as exc:
        ctx.error(exc, "version")
    finally:
        try:
            transport.logout_avi()
        except CollectionError as exc:
            details = exc.as_dict()
            ctx.module["errors"].append(ctx.public(dict(details, stage="logout", source="/logout")))
        finally:
            ctx.module["request_metrics"] = ctx.public(getattr(transport, "metrics", {}))
            ctx.module["transport_security"] = ctx.public(getattr(transport, "transport_security", {}))
            transport.close()
    existing = {str(c.get("check_id", "")).split(":", 1)[0] for c in ctx.module["checks"]}
    cancelled = bool(cancel_requested and cancel_requested()) or any(e.get("kind") == "cancelled" for e in ctx.module["errors"])
    for row in matrix:
        if row["id"] not in existing:
            ctx.module["checks"].append(make_check(row["id"], row["title"], "cancelled" if cancelled else "insufficient_data", values={},
                                                 summary="本次没有取得足以完成该项判断的数据。", sources=[ctx.source(key) for key in row["source"]],
                                                 basis=row["judgement_basis"], limitations=[row["limitations"]], verification="unverified", completeness="incomplete"))
    ctx.module["limitations"].extend(["本轮仅 Controller 管理范围；live_observed 不等于逐项能力验收。", "配置与原生状态不证明实际使用、网络可达或运行能力。"])
    _annotate_usage(ctx)
    _management_gaps(ctx)
    return finish_module(ctx.public(ctx.module))
