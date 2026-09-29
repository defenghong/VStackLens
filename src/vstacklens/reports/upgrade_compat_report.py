"""Customer-facing, standalone upgrade compatibility reports.

The report builders intentionally present the already-decided payload. They do
not re-run HCL matching or revise its summary counts.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import html
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import parse_qs, urlparse

from vstacklens import __version__
from vstacklens.upgrade_compat.decision import effective_match, BLOCKING


REMEDIATIONS: dict[str, str] = {
    "DRIVER_VERSION_UNLISTED": "当前组合未命中本地认证记录，请核对官方支持范围；不依据版本大小自动放行。",
    "IDENTIFIER_MISSING": "该类别所需的设备标识未采集到。请核查 vCenter 读取权限及采集完整性后重试。",
    "UNKNOWN_DEVICE": "本地 HCL 未找到该设备。请使用设备型号、PCI 标识或 VCG 链接进行人工核对，确认后可维护型号别名表。",
    "MODEL_NOT_MATCHED": "磁盘料号未能自动匹配 HCL 的描述型名称，不等同于不兼容。请根据厂商料号核对后维护型号别名表。",
    "AMBIGUOUS_DEVICE": "该标识对应多个 HCL 候选。请逐一打开候选 VCG 链接，并以实物型号、槽位或子系统 ID 确认。",
    "FIRMWARE_UNKNOWN": "当前固件版本未采集到。请使用 esxcli 或厂商管理工具补采固件版本后复核。",
    "PLUGIN_DRIVER_INFO_MISSING": "驱动信息未采集。请核查 esxcli 访问权限及驱动模块查询结果。",
    "PLUGIN_STORE_UNAVAILABLE": "对应判据数据源尚未导入，不能给出该来源的结论。请先导入 HCL 数据。",
    "VSAN_NOT_IN_HCL": "该设备未认证用于 vSAN；基础兼容性结论仍需单独查看。",
    "VSAN_QUEUE_DEPTH_UNKNOWN": "vSAN HCL 未声明队列深度，无法自动核对该项。请查阅对应 HCL 条目并人工确认。",
    "VSAN_CONTEXT_UNKNOWN": "集群架构、磁盘布局或控制器模式未采集完整。请核查 vSAN 配置和 esxcli 采集权限。",
    "SERVER_MODEL_AMBIGUOUS": "整机型号命中多个且目标版本认证结论不一致。请按候选 VCG 条目核对实际硬件配置。",
}

_STATUS_LABELS = {
    "SERVER_CERTIFIED": "整机已认证", "SERVER_NOT_CERTIFIED": "整机未认证，阻塞升级", "SERVER_MODEL_AMBIGUOUS": "整机型号待确认",
    "CERTIFIED": "已认证", "CERTIFIED_NO_FIRMWARE_REQUIREMENT": "已认证，无固件要求", "DRIVER_VERSION_NOT_LATEST": "达到最低认证版本",
    "DRIVER_VERSION_BELOW_MINIMUM": "驱动低于最低认证版本", "DRIVER_VERSION_MISMATCH": "驱动版本无法匹配认证列表", "DRIVER_NOT_CERTIFIED": "驱动未认证",
    "NOT_CERTIFIED": "设备未认证", "FIRMWARE_MISMATCH": "固件版本不匹配", "FIRMWARE_UNKNOWN": "固件待补采",
    "UNKNOWN_DEVICE": "设备待人工核对", "MODEL_NOT_MATCHED": "型号待人工核对", "AMBIGUOUS_DEVICE": "设备标识存在多个候选",
    "IDENTIFIER_MISSING": "设备标识缺失", "PLUGIN_DRIVER_INFO_MISSING": "驱动信息缺失", "PLUGIN_STORE_UNAVAILABLE": "判据数据不可用",
    "VSAN_NOT_APPLICABLE": "不适用", "VSAN_CERTIFIED": "vSAN 已认证", "VSAN_NOT_IN_HCL": "vSAN 未认证",
    "DRIVER_VERSION_UNLISTED": "当前组合待核对",
    "VSAN_QUEUE_DEPTH_UNKNOWN": "vSAN 队列深度待确认", "VSAN_CONTEXT_UNKNOWN": "vSAN 上下文待确认",
}
_PASSING = {"CERTIFIED", "CERTIFIED_NO_FIRMWARE_REQUIREMENT", "DRIVER_VERSION_NOT_LATEST"}
_BLOCKING = BLOCKING


def remediation_for(status: str) -> str:
    return REMEDIATIONS.get(status, "请结合 HCL 条目、当前版本和现场硬件信息复核。")


def render_upgrade_compat_html(payload: dict[str, Any], report_dir: Path) -> Path:
    from vstacklens.application.artifact_publish import staged_report
    with staged_report(report_dir) as (stage, target):
        _render_upgrade_compat_html(payload, stage)
    return target / "index.html"


def _render_upgrade_compat_html(payload: dict[str, Any], report_dir: Path) -> Path:
    """Build an offline, decision-first report from the immutable judgement payload."""
    report_dir.mkdir(parents=True, exist_ok=True)
    assets, data_dir = report_dir / "assets", report_dir / "data"
    assets.mkdir(exist_ok=True)
    data_dir.mkdir(exist_ok=True)
    view = _report_view(payload)
    (assets / "report.css").write_text(_CSS + _UI_REFRESH_CSS + _UI_TABLE_WIDTHS, encoding="utf-8")
    (assets / "report.js").write_text(_JS, encoding="utf-8")
    (data_dir / "customer_report_payload.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    metadata = payload.get("metadata") or {}
    title = _esc(metadata.get("report_title") or "VStackLens 升级兼容性检查报告")
    summary = view["summary"]
    devices = view["devices"]
    show_vsan = view["show_vsan"]
    device_rows = "".join(_device_row(item, show_vsan, devices) for item in devices) or _empty_row(7 if show_vsan else 6)
    passed_rows = "".join(_passed_row(item) for item in view["passed"]) or "<tr><td colspan=5>本次没有可直接升级的设备项。</td></tr>"
    work_rows = "".join(_work_row(item) for item in view["work_items"]) or "<tr><td colspan=5>无需要升级的驱动工作项。</td></tr>"
    blocked = "".join(_blocked_host_card(item) for item in view["blocked_hosts"]) or "<p class=empty>未发现整机认证阻塞主机。</p>"
    other_servers = _other_server_rows(view["servers"])
    readiness_rows = "".join(_host_readiness_row(item) for item in view["host_readiness"]) or "<tr><td colspan=6>未采集到主机整机判定。</td></tr>"
    host_cards = "".join(_host_summary_card(item, set(view["esxcli_hosts"])) for item in view["host_readiness"]) or "<p class=empty>未采集到主机兼容性结论。</p>"
    uncertain_groups = "".join(_uncertain_group_html(item, devices) for item in view["uncertain_groups"]) or "<p class=empty>没有待人工核对的设备项。</p>"
    warnings = "".join(f"<li>{_esc(_warning_text(item))}</li>" for item in payload.get("collection_warnings") or []) or "<li>无</li>"
    data_versions = "".join(_version_row(name, info) for name, info in (payload.get("data_versions") or {}).items()) or "<tr><td colspan=5>未记录判据数据版本。</td></tr>"
    vsan_header = "<th>vSAN 专项</th>" if show_vsan else ""
    source = _source_esxi_version(payload, view["host_readiness"])
    generated_at = _report_generated_at(metadata)
    integrity = _integrity_html(view)
    bundle_notice = _bundle_boundary_html(metadata)
    bios_notice = _bios_notice_html(view["servers"])
    readiness_counts = _readiness_counts(view["host_readiness"])
    decision_summary = _decision_summary_html(view, readiness_counts)
    data_alert = _data_quality_alert_html(view)
    integrity_nav = '<a href="#data-integrity">数据完整性</a>' if integrity else ""
    prerequisites = _platform_prerequisites_html(metadata, view)

    document = f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title><link rel="stylesheet" href="assets/report.css"></head>
<body><main class="shell">
<!-- THESIS: 先给出升级批次能否推进与责任动作，再展开可追溯的设备证据，拒绝把原始状态码堆成报告。 OWN-WORLD: 深蓝操作面板、白色报告纸面、青绿色通过与琥珀色待办，表格为主。 STORY: 管理者确定批次和风险，工程师按主机、工作项和 HCL 链接复核。 FIRST VIEWPORT: 左侧结论和批次建议，右侧三个决策数字，打印操作固定在页头。 FORM: 面向运维升级窗口的读式决策报告。 -->
<header class="report-header"><div class="brand"><span class="brand-mark">V</span><span>VStackLens</span><span class="brand-separator">/</span><span class="brand-subject">ESXi 升级兼容性检查</span></div><button type="button" class="print-button" onclick="window.print()" title="打印或另存为 PDF">打印 / 导出 PDF</button></header>
{data_alert}
<section class="verdict-panel" id="conclusion"><div class="verdict-copy"><p class="kicker">环境兼容性摘要</p><h1>{title}</h1><div class="report-meta meta-chips"><span>客户：<strong>{_value(metadata.get('customer_name'))}</strong></span><span>目标版本：<strong>{_value(metadata.get('target_release'))}</strong></span><span>采集来源：{_value(metadata.get('collection_source'))}</span></div>{decision_summary}<p class="report-meta">源 ESXi：{_esc(source)}　·　报告生成：{_esc(generated_at)}　·　工具版本：{_esc(__version__)}</p></div><div class="decision-counts"><div class="metric certified"><strong>{readiness_counts['certified']}</strong><span>台整机已认证</span></div><div class="metric already"><strong>{readiness_counts['already_target']}</strong><span>台已在目标版本</span></div><div class="metric ready"><strong>{readiness_counts['ready']}</strong><span>台可升级</span></div><div class="metric blocked"><strong>{readiness_counts['blocked']}</strong><span>台不可升级</span></div></div></section>
<nav class="report-nav" aria-label="报告目录"><a href="#host-overview">主机概览 <b>{int(summary.get('server_total', 0) or 0)}</b></a><a href="#blocked">整机阻塞 <b>{readiness_counts['blocked']}</b></a><a href="#remediation">需处理 <b>{len(view['work_items'])}</b></a><a href="#uncertain">待确认 <b>{int(summary.get('unknown', 0) or 0)}</b></a><a href="#device-detail">设备证据 <b>{int(summary.get('total', 0) or 0)}</b></a>{integrity_nav}<a href="#data-versions">数据质量</a></nav>
{integrity}
{bundle_notice}
{prerequisites}
<section class="report-section host-overview" id="host-overview"><div class="section-heading"><div><p class="kicker">主机级结论</p><h2>主机兼容性概览</h2></div><p>以整机认证与本次设备检查结果共同呈现。设备级通过不单独等同于主机可升级。</p></div><div class="host-summary-grid">{host_cards}</div><details class="host-evidence" id="readiness"><summary>查看主机兼容性证据表</summary><div class="table-scroll"><table class="readiness-table"><caption>主机升级就绪状态</caption><thead><tr><th scope="col">主机</th><th scope="col">当前 ESXi</th><th scope="col">整机型号判定</th><th scope="col">设备判定汇总</th><th scope="col">当前建议</th><th scope="col">认证证据</th></tr></thead><tbody>{readiness_rows}</tbody></table></div></details></section>
<section class="report-section" id="blocked"><div class="section-heading"><div><p class="kicker">Go / no-go</p><h2>受阻主机与整机型号判定</h2></div><p>以下主机没有目标版本的整机认证记录，不建议直接纳入升级批次。</p></div><div class="host-grid">{blocked}</div>{bios_notice}{other_servers}</section>
<section class="report-section" id="remediation"><div class="section-heading"><div><p class="kicker">可执行工作</p><h2>升级前需处理</h2></div><p>将相同处置需求按设备和目标版本归并；端口数量不等于独立工作项数量。</p></div><div class="table-scroll"><table><thead><tr><th>工作项</th><th>当前驱动与目标</th><th>影响范围</th><th>处置建议</th><th>认证支持</th></tr></thead><tbody>{work_rows}</tbody></table></div></section>
<section class="report-section" id="uncertain"><div class="section-heading"><div><p class="kicker">需要补齐证据</p><h2>待人工核对</h2></div><p>待核对不等同于不兼容。每一组均标明原因、受影响范围和下一步动作。</p></div><div class="uncertain-grid">{uncertain_groups}</div></section>
<section class="report-section" id="passed"><div class="section-heading"><div><p class="kicker">已满足基础判据</p><h2>可直接升级 / 已通过</h2></div><p>共 {int(summary.get('passed', 0) or 0)} 项；“达到最低认证版本”表示当前组合可用，并不要求追到认证列表最新版本。</p></div><div class="table-scroll"><table><thead><tr><th>主机</th><th>设备</th><th>当前驱动</th><th>基础兼容性</th><th>向前支持</th></tr></thead><tbody>{passed_rows}</tbody></table></div></section>
<section class="report-section evidence-section" id="device-detail"><div class="detail-heading"><div><p class="kicker">工程复核台账</p><h2>设备兼容性明细</h2><p>设备、驱动、固件、判据结论、处置方向及 HCL 链接保持在同一行。默认收起，打印时自动展开。</p></div></div><details id="device-details"><summary>查看 {int(summary.get('total', 0) or 0)} 个设备判定</summary><div class="detail-body"><div class="filters"><label>主机<select id="host-filter"><option value="">全部主机</option>{_host_options(devices)}</select></label><label>类别<select id="type-filter"><option value="">全部类别</option>{_category_options(devices)}</select></label><label>结论<select id="status-filter"><option value="">全部结论</option><option value="passed">已通过</option><option value="failed">需处理</option><option value="unknown">待确认</option></select></label><div class="filter-shortcuts" aria-label="快捷筛选"><button type="button" data-device-filter="issues">异常优先</button><button type="button" data-device-filter="failed">只看需处理</button><button type="button" data-device-filter="unknown">只看待确认</button><button type="button" data-device-filter="passed">只看已通过</button></div><button type="button" id="reset-filters">显示全部</button><span id="filter-count" aria-live="polite"></span></div><p class="mobile-table-hint">左右滑动可查看全部设备证据列。</p><div class="table-scroll"><table id="device-table"><caption>设备兼容性判定证据台账</caption><thead><tr><th scope="col">主机 / 设备</th><th scope="col">类别</th><th scope="col">基础兼容性</th>{vsan_header}<th scope="col">当前驱动 / 认证要求</th><th scope="col">当前固件</th><th scope="col">下一步</th><th scope="col">匹配依据与 HCL</th></tr></thead><tbody>{device_rows}</tbody></table></div></div></details></section>
<section class="report-section" id="data-versions"><div class="section-heading"><div><p class="kicker">可追溯性</p><h2>判据数据与采集质量</h2></div><p>结论基于本报告记录的 VCG / vSAN HCL 数据版本；字段缺失会被明确标出，不以推测补全。</p></div><div class="table-scroll"><table><thead><tr><th>数据源</th><th>数据生成时间</th><th>导入时间</th><th>记录数</th><th>新鲜度</th></tr></thead><tbody>{data_versions}</tbody></table></div><details><summary>查看采集警告（{len(payload.get('collection_warnings') or [])}）</summary><ul>{warnings}</ul></details></section>
<footer>VStackLens · 升级兼容性检查 · 本报告仅呈现已采集的硬件事实与离线 HCL 判据，无法替代变更前备份、维护窗口和厂商支持确认。</footer>
</main><script src="assets/report.js"></script></body></html>"""
    index = report_dir / "index.html"
    index.write_text(document, encoding="utf-8")
    return index


def build_conclusion_summary(payload: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Compatibility helper for callers that need existing decisions grouped."""
    result: dict[str, list[dict[str, Any]]] = {"blocking": [], "recommended": [], "unknown": [], "passed": []}
    for server in payload.get("server_results") or []:
        code = str(server.get("status") or "")
        entry = {"name": server.get("host") or server.get("model") or "未采集主机", "status": code, "detail": server.get("detail") or ""}
        if code == "SERVER_NOT_CERTIFIED": result["blocking"].append(entry)
        elif code not in {"SERVER_CERTIFIED", ""}: result["unknown"].append(entry)
    for device in payload.get("device_results") or []:
        base, code = _base(device), str(_base(device).get("status") or "")
        entry = {"name": f"{device.get('host') or ''} / {device.get('object_name') or ''}".strip(" /"), "status": code, "detail": base.get("detail") or ""}
        if code in _BLOCKING: result["blocking"].append(entry)
        elif code in _PASSING:
            result["passed"].append(entry)
            if code == "DRIVER_VERSION_NOT_LATEST": result["recommended"].append(entry)
        else: result["unknown"].append(entry)
    return result


def _report_view(payload: dict[str, Any]) -> dict[str, Any]:
    devices = [item for item in (payload.get("device_results") or []) if isinstance(item, dict)]
    servers = [item for item in (payload.get("server_results") or []) if isinstance(item, dict)]
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    blocked_hosts = [item for item in servers if str(item.get("status") or "") == "SERVER_NOT_CERTIFIED"]
    passed = [item for item in devices if str(_base(item).get("status") or "") in _PASSING]
    vsan_statuses = [str((item.get("vsan") or {}).get("status") or "") for item in devices]
    esxcli_hosts = sorted({str(item.get("host") or "") for item in (payload.get("collection_warnings") or []) if isinstance(item, dict) and item.get("status") == "esxcli_unavailable" and item.get("host")})
    return {
        "devices": devices,
        "servers": servers,
        "summary": summary,
        "blocked_hosts": blocked_hosts,
        "passed": passed,
        "work_items": _work_items(devices),
        "host_readiness": _host_readiness(servers, devices, str((payload.get("metadata") or {}).get("target_release") or "")),
        "uncertain_groups": _uncertain_groups(devices),
        "show_vsan": any(status and status != "VSAN_NOT_APPLICABLE" for status in vsan_statuses),
        "esxcli_hosts": esxcli_hosts,
        "firmware_missing": sum(not _present(item.get("firmware_version")) for item in devices),
        "storage_association_warnings": _storage_association_warnings(devices),
    }


def _work_items(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge identical remediation work across ports while preserving each port."""
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for item in devices:
        base = _base(item)
        if str(base.get("status") or "") not in _BLOCKING: continue
        target = _minimum_driver(base) or _latest_driver(base) or str(base.get("target_release") or "")
        groups[(str(item.get("model") or item.get("object_name") or "未采集设备"), str(item.get("driver_name") or "未采集驱动"), target)].append(item)
    rows = []
    for (model, driver_name, target), members in groups.items():
        base = _base(members[0])
        hosts = sorted({str(item.get("host") or "未采集主机") for item in members})
        action = f"将 {driver_name} 升级至不低于 {target}" if _minimum_driver(base) else f"按目标版本 HCL 认证列表升级 {driver_name}"
        rows.append({"model": model, "driver_name": driver_name, "target": target, "devices": members, "hosts": hosts, "base": base, "action": action})
    return sorted(rows, key=lambda item: (item["hosts"], item["model"], item["driver_name"]))


def _host_readiness(servers: list[dict[str, Any]], devices: list[dict[str, Any]], target_release: str) -> list[dict[str, Any]]:
    """Join server and device conclusions so a change owner can decide per host."""

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for device in devices:
        grouped[str(device.get("host") or "未采集主机")].append(device)
    known_hosts = {str(server.get("host") or server.get("model") or "未采集主机") for server in servers}
    known_hosts.update(grouped)
    by_host = {str(server.get("host") or server.get("model") or "未采集主机"): server for server in servers}
    rows: list[dict[str, Any]] = []
    for host in sorted(known_hosts):
        server = by_host.get(host, {})
        host_devices = grouped.get(host, [])
        statuses = [str(_base(device).get("status") or "") for device in host_devices]
        failed = sum(status in _BLOCKING for status in statuses)
        passed = sum(status in _PASSING for status in statuses)
        unknown = max(0, len(host_devices) - failed - passed)
        server_status = str(server.get("status") or "")
        source_release, source_kind = _host_source_release(server, host_devices)
        source_relation = _release_relation(source_release, target_release)
        if source_relation == "same":
            if server_status == "SERVER_NOT_CERTIFIED":
                action = "当前已运行目标版本，但整机认证缺失；纳入风险与支持边界复核。"
                group = "blocked"
            else:
                action = f"已在目标版本，不列为升级对象；仍有 {failed} 项需处理、{unknown} 项待确认。" if failed or unknown else "已在目标版本；不列为升级对象，仅完成合规复核。"
                group = "already"
        elif server_status == "SERVER_NOT_CERTIFIED":
            action = "暂不纳入本批次；先完成整机认证核对或制定例外决策。"
            group = "blocked"
        elif failed:
            action = f"完成 {failed} 项设备处置后复核，再纳入批次。"
            group = "pending"
        elif unknown:
            action = f"补齐 {unknown} 项待确认信息后安排升级。"
            group = "pending"
        elif source_kind == "inferred":
            action = "当前 ESXi 版本仅由 VIB 推断，请核对主机实际版本后再纳入批次。"
            group = "pending"
        elif server_status == "SERVER_CERTIFIED" and host_devices:
            action = "可纳入升级批次；按常规变更前检查执行。"
            group = "ready"
        else:
            action = "缺少整机判据，先补采型号和认证信息。"
            group = "pending"
        rows.append({
            "host": host,
            "server": server,
            "source_release": source_release,
            "source_kind": source_kind,
            "passed": passed,
            "failed": failed,
            "unknown": unknown,
            "action": action,
            "group": group,
        })
    return rows


def _host_source_release(server: dict[str, Any], devices: list[dict[str, Any]]) -> tuple[str | None, str]:
    context = server.get("host_context") if isinstance(server, dict) else {}
    version = context.get("esxi_version") if isinstance(context, dict) else None
    normalized = _normalize_esxi_release(version)
    if normalized:
        return normalized, "direct"
    inferred = _infer_esxi_release_from_vibs(devices)
    return (inferred, "inferred") if inferred else (None, "missing")


def _normalize_esxi_release(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    match = re.search(r"(?:ESXi\s*)?([6-9])\.0(?:\.(\d+)|\s*U(\d+))?", text, re.I)
    if not match:
        return None
    update = match.group(2) or match.group(3)
    return f"ESXi {match.group(1)}.0 U{update}" if update else f"ESXi {match.group(1)}.0"


def _infer_esxi_release_from_vibs(devices: list[dict[str, Any]]) -> str | None:
    """Infer only a unanimous ESXi train from VMware VIB build segments."""

    releases: set[str] = set()
    for device in devices:
        version = str(device.get("driver_version") or "")
        match = re.search(r"(?:^|[._-])([6-9])0([0-9])(?:[._-])", version)
        if match:
            releases.add(f"ESXi {match.group(1)}.0 U{match.group(2)}")
    return next(iter(releases)) if len(releases) == 1 else None


def _release_relation(current: str | None, target: str) -> str:
    current_key, target_key = _release_key(current), _release_key(target)
    if current_key is None or target_key is None:
        return "unknown"
    if current_key == target_key:
        return "same"
    return "below" if current_key < target_key else "above"


def _release_key(value: str | None) -> tuple[int, int] | None:
    match = re.search(r"([6-9])\.0(?:\s*U(\d+))?", str(value or ""), re.I)
    return (int(match.group(1)), int(match.group(2) or 0)) if match else None


def _readiness_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "certified": sum(str(item["server"].get("status") or "") == "SERVER_CERTIFIED" for item in rows),
        "already_target": sum(item["group"] == "already" for item in rows),
        "ready": sum(item["group"] == "ready" for item in rows),
        "blocked": sum(item["group"] == "blocked" for item in rows),
        "pending": sum(item["group"] == "pending" for item in rows),
    }


def _decision_summary_html(view: dict[str, Any], counts: dict[str, int]) -> str:
    summary = view["summary"]
    if counts["blocked"]:
        label, group = "存在不可升级主机", "blocked"
        text = f"{counts['blocked']} 台主机存在兼容性阻塞项，本次不能作为可升级对象纳入批次。"
    elif counts["pending"]:
        label, group = "主机兼容性待确认", "pending"
        text = f"当前没有兼容性阻塞项，但 {counts['pending']} 台主机仍有待确认项，需完成核验后再判断是否可升级。"
    elif counts["ready"]:
        label, group = "存在可升级主机", "ready"
        text = f"{counts['ready']} 台主机在本次检查范围内已通过，可作为升级对象。"
    else:
        label, group = "无待升级主机", "already"
        text = "本次未发现需要从旧版本升级的主机；已在目标版本的主机仅进行兼容性复核。"
    return (
        f'<div class="decision-result {group}"><span class="decision-label">{_esc(label)}</span>'
        f'<p>{_esc(text)}</p></div>'
        f'<div class="device-level-summary"><span>设备级检查</span>'
        f'<button type="button" data-device-filter="failed">! {int(summary.get("failed", 0) or 0)} 需处理</button>'
        f'<button type="button" data-device-filter="unknown">? {int(summary.get("unknown", 0) or 0)} 待确认</button>'
        f'<button type="button" data-device-filter="passed">✓ {int(summary.get("passed", 0) or 0)} 已通过</button></div>'
    )


def _host_summary_card(item: dict[str, Any], quality_warning_hosts: set[str]) -> str:
    server = item["server"]
    host = str(item["host"])
    model = _value(server.get("model")) if isinstance(server, dict) else "未采集型号"
    group = str(item["group"])
    label = {"ready": "可升级", "blocked": "不可升级", "pending": "待确认", "already": "已在目标版本"}.get(group, "待确认")
    status = server.get("status") if isinstance(server, dict) else ""
    data_quality = '<span class="quality-flag">采集质量受限</span>' if host in quality_warning_hosts else ""
    return (
        f'<article class="host-summary-card host-{_esc(group)}" data-host-card="{_esc(host)}">'
        f'<div class="host-card-top"><div><p class="host-name">{_esc(host)}</p><p class="host-model">{_esc(model)}</p></div>'
        f'<span class="host-outcome { _esc(group)}">{_esc(label)}</span></div>'
        f'<div class="host-facts"><div><span>当前 ESXi</span>{_source_release_html(item["source_release"], item["source_kind"])}</div>'
        f'<div><span>整机 HCL</span>{_status_badge(status)}</div></div>'
        f'<div class="host-device-counts"><span><b>{item["failed"]}</b> 需处理</span><span><b>{item["unknown"]}</b> 待确认</span><span><b>{item["passed"]}</b> 已通过</span></div>'
        f'{data_quality}<p class="host-action">{_esc(item["action"])}</p>'
        f'<button type="button" class="host-evidence-button" data-open-host="{_esc(host)}">查看该主机证据</button></article>'
    )


def _data_quality_alert_html(view: dict[str, Any]) -> str:
    hosts = view["esxcli_hosts"]
    storage = view["storage_association_warnings"]
    if not hosts and not storage:
        return ""
    parts = []
    if hosts:
        parts.append(f"{len(hosts)} 台主机无法完成 esxcli 采集，固件字段缺失 {view['firmware_missing']} 项")
    if storage:
        parts.append(f"检测到 {len(storage)} 组疑似重复存储关联")
    return f'<section class="data-quality-alert" role="status"><div><span class="alert-symbol">!</span><div><strong>采集质量提示</strong><p>{_esc("；".join(parts))}。相关兼容性结论以已采集证据为准。</p></div></div><a href="#data-integrity">查看数据完整性</a></section>'


def _uncertain_groups(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group non-blocking uncertainty by its actual recovery action."""

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for device in devices:
        status = str(_base(device).get("status") or "")
        if status not in _PASSING and status not in _BLOCKING:
            grouped[status or "UNCLASSIFIED"].append(device)
    result = []
    for status, members in grouped.items():
        hosts = sorted({str(item.get("host") or "未采集主机") for item in members})
        result.append({"status": status, "members": members, "hosts": hosts})
    return sorted(result, key=lambda item: (-len(item["members"]), item["status"]))


def _storage_association_warnings(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Surface, but never silently merge, suspicious legacy disk/controller mappings."""

    grouped: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for item in devices:
        if str(item.get("category") or "") not in {"ssd", "hdd"}:
            continue
        model = re.sub(r"\s+", " ", str(item.get("model") or item.get("object_name") or "").strip()).casefold()
        firmware = str(item.get("firmware_version") or "").strip().casefold()
        if model and firmware:
            grouped[(str(item.get("host") or ""), str(item.get("category") or ""), model, firmware)].append(item)
    warnings = []
    for (host, category, model, firmware), items in grouped.items():
        drivers = sorted({str(item.get("driver_name") or "未采集") for item in items})
        if len(items) > 1 and len(drivers) > 1:
            warnings.append({"host": host, "category": category, "model": model, "firmware": firmware, "drivers": drivers, "count": len(items)})
    return sorted(warnings, key=lambda item: (item["host"], item["model"]))


def _base(item: dict[str, Any]) -> dict[str, Any]:
    return effective_match(item)


def _minimum_driver(base: dict[str, Any]) -> str:
    versions = base.get("certified_driver_versions") or []
    return str(versions[0]) if versions else ""


def _latest_driver(base: dict[str, Any]) -> str:
    versions = base.get("certified_driver_versions") or []
    return str(versions[-1]) if versions else ""


def _device_row(item: dict[str, Any], show_vsan: bool, all_devices: list[dict[str, Any]]) -> str:
    base, vsan = (item.get("matches") or {}).get("vcg") or {}, item.get("vsan") or {}
    note = ("经别名表匹配；" if item.get("alias_matched") else "") + str(base.get("detail") or "")
    links = list(item.get("candidate_links") or [])
    if base.get("vcglink"):
        links.append(base["vcglink"])
    cross_hint = _cross_driver_hint(item, all_devices)
    link_html = _link_list(dict.fromkeys(links))
    cells = [f"<td>{_esc(_value(item.get('host')))}<br><strong>{_esc(_value(item.get('object_name')))}</strong></td>", f"<td>{_esc(_value(item.get('category')))}</td>", f"<td>{_status_badge(base.get('status'), detailed=True)}<p class=minor>{_esc(_forward_support_text(base))}</p></td>"]
    if show_vsan: cells.append(f"<td>{_status_badge(vsan.get('status'), detailed=True)}</td>")
    cells.extend([f"<td>{_driver_html(item)}</td>", f"<td><span class=version>{_esc(_value(item.get('firmware_version')))}</span></td>", f"<td>{_esc(remediation_for(str(base.get('status') or vsan.get('status') or '')))}</td>", f"<td>{_esc(note) or '本地 HCL 无记录'}{cross_hint}<p class=links>{link_html}</p></td>"])
    return f'<tr data-host="{_esc(item.get("host"))}" data-type="{_esc(item.get("category"))}" data-status="{_status_group(str(base.get("status") or ""))}">' + "".join(cells) + "</tr>"


def _passed_row(item: dict[str, Any]) -> str:
    base = _base(item)
    return f"<tr><td>{_esc(_value(item.get('host')))}</td><td>{_esc(_value(item.get('object_name')))}</td><td>{_driver_html(item)}</td><td>{_status_badge(base.get('status'))}</td><td>{_esc(_forward_support_text(base))}</td></tr>"


def _work_row(item: dict[str, Any]) -> str:
    members = "".join(f"<li>{_esc(_value(device.get('host')))} / {_esc(_value(device.get('object_name')))}（{_esc(_value(device.get('object_key')))}）</li>" for device in item["devices"])
    scope = f"主机：{_esc('、'.join(item['hosts']))}<br>影响 {len(item['devices'])} 个端口/设备<details><summary>查看受影响设备</summary><ul>{members}</ul></details>"
    return f"<tr><td><strong>{_esc(item['model'])}</strong><br><span class=minor>{_esc(item['driver_name'])}</span></td><td>{_esc(_work_driver_text(item))}</td><td>{scope}</td><td>{_esc(item['action'])}</td><td>{_esc(_forward_support_text(item['base']))}</td></tr>"


def _host_readiness_row(item: dict[str, Any]) -> str:
    server = item["server"]
    links = list(server.get("candidate_links") or []) if isinstance(server, dict) else []
    if isinstance(server, dict) and server.get("vcglink"):
        links.append(server["vcglink"])
    evidence = _link_list(dict.fromkeys(links), empty="未提供整机 HCL 链接")
    model = _value(server.get("model")) if isinstance(server, dict) else "未采集"
    status = server.get("status") if isinstance(server, dict) else ""
    devices = f"{item['passed']} 通过 / {item['failed']} 需处理 / {item['unknown']} 待确认"
    current = _source_release_html(item["source_release"], item["source_kind"])
    return f"<tr class=host-{_esc(item['group'])}><td><strong>{_esc(item['host'])}</strong><br><span class=minor>{_esc(model)}</span></td><td>{current}</td><td>{_status_badge(status)}<p class=minor>{_esc(_value(server.get('detail')) if isinstance(server, dict) else '未采集整机判定')}</p></td><td>{_esc(devices)}</td><td>{_esc(item['action'])}</td><td>{evidence}</td></tr>"


def _uncertain_group_html(item: dict[str, Any], all_devices: list[dict[str, Any]]) -> str:
    status = str(item["status"])
    members = item["members"]
    rows = []
    for member in members:
        base = _base(member)
        links = list(member.get("candidate_links") or [])
        if base.get("vcglink"):
            links.append(base["vcglink"])
        rows.append(
            "<tr>"
            f"<td>{_esc(_value(member.get('host')))}</td>"
            f"<td>{_esc(_value(member.get('object_name') or member.get('model')))}</td>"
            f"<td>{_esc(_value(member.get('driver_name')))}<br><span class=minor version>{_esc(_value(member.get('driver_version')))}</span>{_cross_driver_hint(member, all_devices)}</td>"
            f"<td><span class=version>{_esc(_value(member.get('firmware_version')))}</span></td>"
            f"<td>{_link_list(dict.fromkeys(links))}</td>"
            "</tr>"
        )
    remediation = remediation_for(status)
    return f"<details class=uncertain-group><summary>{_status_badge(status)}<span>{len(members)} 项，涉及 {_esc('、'.join(item['hosts']))}</span></summary><div><p>{_esc(remediation)}</p><div class=table-scroll><table><thead><tr><th scope=col>主机</th><th scope=col>设备</th><th scope=col>当前驱动</th><th scope=col>当前固件</th><th scope=col>认证记录</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div></div></details>"


def _blocked_host_card(item: dict[str, Any]) -> str:
    context = item.get("host_context") or {}
    links = _link_list(item.get("candidate_links") or [])
    return f"<article class=host-card><div>{_status_badge(item.get('status'))}<h3>{_esc(_value(item.get('host')))}</h3><p><strong>{_esc(_value(item.get('model')))}</strong></p></div><p>{_esc(_value(item.get('detail')))}</p><dl><dt>CPU</dt><dd>{_esc(_value(context.get('cpu_model')))}</dd><dt>BIOS</dt><dd>{_esc(_value(context.get('bios_version')))}（{_esc(_format_date(context.get('bios_release_date'), date_only=True))}）</dd></dl><p class=minor>处置方向：确认目标版本 VCG 是否有对应整机认证；没有认证记录时，不应将该主机纳入本次 ESXi 升级批次。</p><p class=links>{links}</p></article>"


def _other_server_rows(servers: list[dict[str, Any]]) -> str:
    rows = []
    for server in servers:
        if str(server.get("status") or "") in {"SERVER_NOT_CERTIFIED", "SERVER_CERTIFIED"}:
            continue
        links = _link_list(server.get("candidate_links") or [])
        rows.append(f"<li>{_esc(_value(server.get('host') or server.get('model')))}：{_status_badge(server.get('status'))} {_esc(_value(server.get('detail')))} {links}</li>")
    return f"<details class=other-servers><summary>查看其他整机判定（{len(rows)}）</summary><ul>{''.join(rows)}</ul></details>" if rows else ""


def _integrity_html(view: dict[str, Any]) -> str:
    hosts = view["esxcli_hosts"]
    storage_warnings = view["storage_association_warnings"]
    if not hosts and not storage_warnings:
        return ""
    messages = []
    if hosts:
        messages.append(f'<p>本次采集在 {len(hosts)} 台主机上无法执行 esxcli，设备固件字段缺失 {view["firmware_missing"]} 项。驱动、固件或 vSAN 相关字段缺失时，结论仅基于已采集字段；涉及固件的结论须补采后复核。</p><p class="minor">受影响主机：{_esc("、".join(hosts))}</p>')
    if storage_warnings:
        evidence = "；".join(f'{_esc(item["host"])} / {_esc(item["model"])} / 固件 {_esc(item["firmware"])}：{_esc("、".join(item["drivers"]))}' for item in storage_warnings)
        messages.append(f'<p><strong>检测到 {len(storage_warnings)} 组疑似重复的存储关联。</strong>同一主机、磁盘型号和固件对应了不同驱动，可能来自旧采集的控制器关联错误；报告保留原始证据但不应据此估计精确磁盘数量。请使用修复后的版本重新采集并复跑检查。</p><p class="minor">受影响记录：{evidence}</p>')
    return '<section class="integrity" id="data-integrity"><div><h2>数据完整性声明</h2>' + "".join(messages) + '</div><a href="#device-detail">查看受影响设备明细</a></section>'


def _bundle_boundary_html(metadata: dict[str, Any]) -> str:
    if str(metadata.get("collection_source") or "").casefold() != "support bundle":
        return ""
    return "<section class=integrity><div><h2>离线数据使用边界</h2><p>Support bundle 路径字段完整度低于直连 vCenter；缺失 PCI 四元组、驱动、固件或 vSAN 上下文时仅作辅助判断，不替代现场或 VCG 复核。</p></div></section>"


def _bios_notice_html(servers: list[dict[str, Any]]) -> str:
    text = _bios_notice_text(servers)
    return f"<aside class=bios-notice><strong>BIOS 差异提示：</strong>{_esc(text)}</aside>" if text else ""


def _bios_notice_text(servers: list[dict[str, Any]]) -> str:
    by_model: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for server in servers:
        context = server.get("host_context") or {}
        if _present(context.get("bios_version")): by_model[str(server.get("model") or "未采集型号")].append(server)
    notices = []
    for model, items in by_model.items():
        versions = {str((item.get("host_context") or {}).get("bios_version")) for item in items}
        if len(versions) > 1:
            sorted_items = sorted(items, key=lambda item: str((item.get("host_context") or {}).get("bios_release_date") or ""))
            oldest, newest = sorted_items[0], sorted_items[-1]
            oldest_context = oldest.get("host_context") or {}
            newest_context = newest.get("host_context") or {}
            details = "；".join(f"{_value(item.get('host'))}：{_value((item.get('host_context') or {}).get('bios_version'))} / {_format_date((item.get('host_context') or {}).get('bios_release_date'), date_only=True)}" for item in items)
            notices.append(f"同型号 {model} 的 BIOS 版本存在差异：{details}。其中 {_value(oldest.get('host'))} 的 BIOS（{_value(oldest_context.get('bios_version'))}，{_format_date(oldest_context.get('bios_release_date'), date_only=True)}）早于 {_value(newest.get('host'))} 的 {_value(newest_context.get('bios_version'))}；升级前应评估并统一 BIOS 基线。")
    return " ".join(notices)


def _version_row(name: str, info: Any) -> str:
    info = info if isinstance(info, dict) else {}
    label = info.get("label") or {"vcg": "VCG", "vsan_hcl": "vSAN HCL"}.get(name, name)
    downloaded_at = info.get("downloaded_at")
    raw_datetime = _esc(downloaded_at) if _present(downloaded_at) else ""
    imported = f'<time datetime="{raw_datetime}" title="原始导入时间：{raw_datetime}">{_esc(_format_date(downloaded_at))}</time>' if raw_datetime else "未采集"
    return f"<tr><td>{_esc(label)}</td><td>{_esc(_format_date(info.get('json_updated_time')))}</td><td>{imported}</td><td>{_esc(info.get('record_count') or 0)}</td><td>{_esc(_freshness_label(info.get('freshness')))}</td></tr>"


def _driver_html(item: dict[str, Any]) -> str:
    base, required, latest = _base(item), _minimum_driver(_base(item)), _latest_driver(_base(item))
    qualifier = f"需 &gt;= {_esc(required)}" if required else (f"认证最高 {_esc(latest)}" if latest else "认证版本未提供")
    raw = _value(item.get("driver_version"))
    normalized = _normalized_driver_version(raw)
    raw_detail = f"<span class=minor>原始 VIB：<span class=version>{_esc(raw)}</span></span>" if normalized != raw else ""
    return f"<strong>{_esc(_value(item.get('driver_name')))}</strong><br>当前 <span class=version>{_esc(normalized)}</span><br><span class=minor>{qualifier}</span>{raw_detail}"


def _driver_cell_text(item: dict[str, Any]) -> str:
    base = _base(item)
    required, latest = _minimum_driver(base), _latest_driver(base)
    qualifier = f"需 >= {required}" if required else (f"认证最高 {latest}" if latest else "认证版本未提供")
    return f"{_value(item.get('driver_name'))} | 当前 {_value(item.get('driver_version'))} | {qualifier}"


def _work_driver_text(item: dict[str, Any]) -> str:
    versions = sorted({_value(device.get("driver_version")) for device in item["devices"]})
    target = _minimum_driver(item["base"])
    return f"当前 {' / '.join(versions)}；需 >= {target}" if target else f"当前 {' / '.join(versions)}；按 HCL 认证列表升级"


def _forward_support_text(base: dict[str, Any]) -> str:
    maximum = base.get("highest_forward_release")
    return f"向前最高支持：{maximum}" if maximum else "向前支持：未提供"


def _status_badge(status: Any, *, detailed: bool = False) -> str:
    code = str(status or "")
    code_html = f"<small>{_esc(code)}</small>" if detailed and code else ""
    icon = {"passed": "✓", "failed": "!", "unknown": "?"}[_status_group(code)]
    return f'<span class="status {_status_group(code)}" title="{_esc(code)}"><span class="status-icon" aria-hidden="true">{icon}</span><span><b>{_esc(_status_label(code))}</b>{code_html}</span></span>'


def _status_label(status: Any) -> str:
    code = str(status or "")
    return _STATUS_LABELS.get(code, "待人工核对" if code else "未采集")


def _status_group(status: str) -> str:
    if status in _PASSING or status == "SERVER_CERTIFIED": return "passed"
    if status in _BLOCKING or status == "SERVER_NOT_CERTIFIED": return "failed"
    return "unknown"


def _source_esxi_version(payload: dict[str, Any], readiness: list[dict[str, Any]] | None = None) -> str:
    metadata = payload.get("metadata") or {}
    for key in ("source_release", "source_esxi_version", "current_esxi_version"):
        if _present(metadata.get(key)): return str(metadata[key])
    for server in payload.get("server_results") or []:
        context = server.get("host_context") or {}
        for key in ("esxi_version", "product_version", "source_esxi_version"):
            if _present(context.get(key)): return str(context[key])
    inferred = [item for item in (readiness or []) if item.get("source_release")]
    if not inferred:
        return "未采集"
    releases: dict[str, int] = defaultdict(int)
    inferred_kinds: set[str] = set()
    for item in inferred:
        releases[str(item["source_release"])] += 1
        inferred_kinds.add(str(item["source_kind"]))
    summary = "、".join(f"{release}（{count} 台）" for release, count in sorted(releases.items()))
    suffix = "，由 VIB 构建号推断，待主机版本复核" if inferred_kinds == {"inferred"} else ""
    return summary + suffix


def _report_generated_at(metadata: dict[str, Any]) -> str:
    for key in ("generated_at", "report_generated_at"):
        if _present(metadata.get(key)):
            return _format_date(metadata[key])
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %z")


def _host_options(devices: list[dict[str, Any]]) -> str:
    return "".join(f'<option value="{_esc(host)}">{_esc(host)}</option>' for host in sorted({str(item.get("host") or "") for item in devices if item.get("host")}))


def _category_options(devices: list[dict[str, Any]]) -> str:
    return "".join(f'<option value="{_esc(category)}">{_esc(category)}</option>' for category in sorted({str(item.get("category") or "") for item in devices if item.get("category")}))


def _warning_text(item: Any) -> str:
    if isinstance(item, str): return item
    if isinstance(item, dict): return "；".join(f"{key}={value}" for key, value in item.items())
    return str(item)


def _link(url: Any) -> str:
    text = str(url or "")
    if not text:
        return ""
    parsed = urlparse(text)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return ""
    query = parse_qs(parsed.query)
    product_id = (query.get("productId") or [""])[0]
    program = (query.get("program") or [""])[0]
    label = {"server": "整机", "io": "I/O", "vsanio": "vSAN I/O"}.get(program, "HCL")
    suffix = f" #{product_id}" if product_id else ""
    return f'<a href="{_esc(text)}" target="_blank" rel="noopener">{_esc(label + suffix)}</a>'


def _link_list(urls: Any, *, empty: str = "本地 HCL 无记录") -> str:
    links = " ".join(_link(url) for url in urls if url)
    return links or f'<span class="empty-link">{_esc(empty)}</span>'


def _cross_driver_hint(item: dict[str, Any], all_devices: list[dict[str, Any]]) -> str:
    base = _base(item)
    if str(base.get("status") or "") != "AMBIGUOUS_DEVICE":
        return ""
    driver = str(item.get("driver_name") or "")
    current = str(item.get("driver_version") or "")
    matches = [
        candidate for candidate in all_devices
        if candidate is not item
        and str(candidate.get("driver_name") or "") == driver
        and str(candidate.get("driver_version") or "") == current
        and str(_base(candidate).get("status") or "") == "DRIVER_VERSION_BELOW_MINIMUM"
    ]
    if not matches:
        return ""
    required = _minimum_driver(_base(matches[0]))
    hosts = "、".join(sorted({str(candidate.get("host") or "未采集主机") for candidate in matches}))
    return f'<p class="cross-hint">交叉提示：同驱动 <span class="version">{_esc(driver)} { _esc(current)}</span> 在 { _esc(hosts)} 已判定低于最低认证版本 { _esc(required)}；本条仍须按子系统 ID 确认候选。</p>'


def _source_release_html(release: str | None, kind: str) -> str:
    if not release:
        return '<span class="empty-link">未采集</span>'
    note = "VIB 构建号推断，待复核" if kind == "inferred" else "主机 Config.Product"
    return f'<strong>{_esc(release)}</strong><br><span class="minor">{_esc(note)}</span>'


def _normalized_driver_version(value: str) -> str:
    match = re.match(r"(.+?-\d+vmw)(?:\.\d+){3,}$", value)
    return match.group(1) if match else value


def _format_date(value: Any, *, date_only: bool = False) -> str:
    if not _present(value):
        return "未采集"
    text = str(value).strip()
    parsed: datetime | None = None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = parsedate_to_datetime(text)
        except (TypeError, ValueError):
            return text
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone(timedelta(hours=8)))
    if date_only:
        return parsed.strftime("%Y-%m-%d")
    return parsed.strftime("%Y-%m-%d %H:%M") + (" +08" if parsed.tzinfo is not None else "")


def _freshness_label(value: Any) -> str:
    return {"FRESH": "正常", "WARNING": "需更新", "CRITICAL": "已过期"}.get(str(value or ""), _value(value))


def _platform_prerequisites_html(metadata: dict[str, Any], view: dict[str, Any]) -> str:
    version = _value(metadata.get("vcenter_version"))
    build = _value(metadata.get("vcenter_build"))
    vsan = "本次检测到 vSAN 专项判定；涉及 vSAN 的主机还需以磁盘组、控制器模式和 vSAN HCL 结论作为升级门禁。" if view["show_vsan"] else "本次未检测到需要展示的 vSAN 专项判定。"
    return f'<section class="report-section prerequisites"><div class="section-heading"><div><p class="kicker">变更门禁</p><h2>升级前置条件</h2></div><p>升级 ESXi 前，vCenter 版本需满足目标 ESXi 的管理兼容性要求；本报告不以设备驱动版本替代该项核对。</p></div><dl><dt>当前 vCenter</dt><dd>{_esc(version)}（Build { _esc(build)}）</dd><dt>执行要求</dt><dd>确认 vCenter 版本不低于目标 ESXi 的管理要求，并在变更窗口前完成备份、维护模式和回退方案核对。</dd><dt>vSAN 范围</dt><dd>{_esc(vsan)}</dd></dl></section>'


def _present(value: Any) -> bool:
    return value is not None and str(value).strip() != ""


def _value(value: Any) -> str:
    return str(value).strip() if _present(value) else "未采集"


def _esc(value: Any) -> str:
    return html.escape(str(value or ""), quote=True)


def _empty_row(columns: int) -> str:
    return f"<tr><td colspan={columns}>未采集到可判定设备。</td></tr>"


_CSS = r"""
:root{--canvas:#edf1f5;--paper:#fff;--ink:#182536;--muted:#55677a;--line:#d7e0e8;--blue:#153c63;--blue-deep:#0c2947;--blue-soft:#edf4fa;--teal:#146b52;--teal-soft:#e8f6ef;--red:#a92e35;--red-soft:#fff0f1;--amber:#8b5900;--amber-soft:#fff6e5;--slate:#43566b;--slate-soft:#f0f3f6}*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--canvas);color:var(--ink);font:14px/1.65 "Microsoft YaHei","PingFang SC","Noto Sans CJK SC","Segoe UI",Arial,sans-serif}.shell{max-width:1360px;margin:0 auto;padding:24px 28px 56px}.report-header{display:flex;justify-content:space-between;align-items:center;gap:16px;padding:0 2px 18px}.brand{display:flex;align-items:center;gap:8px;color:var(--blue);font-weight:700}.brand-mark{display:grid;place-items:center;width:28px;height:28px;border-radius:7px;background:var(--blue);color:#fff;font-weight:800}.brand-separator,.brand-subject{color:var(--muted);font-weight:500}.print-button,button{border:1px solid #b9c7d5;border-radius:6px;background:#fff;color:var(--blue);font:inherit;padding:8px 12px;cursor:pointer}.print-button:hover,button:hover{background:var(--blue-soft)}.print-button:focus-visible,button:focus-visible,select:focus-visible,a:focus-visible{outline:3px solid #8fc6ef;outline-offset:2px}.verdict-panel{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:28px;padding:32px;background:var(--blue-deep);color:#fff;border-radius:10px;box-shadow:0 12px 28px rgba(12,41,71,.18)}.kicker{margin:0 0 6px;font-size:12px;font-weight:700;color:#66849f}.verdict-panel .kicker{color:#b9d3ea}.verdict-panel h1{margin:0 0 8px;font-size:29px;line-height:1.3}.report-meta{margin:5px 0;color:#d3e0ec;font-size:13px}.verdict-text{max-width:76ch;margin:18px 0 12px;font-size:16px;line-height:1.8;color:#f5f8fb}.decision-detail{margin:0 0 12px;color:#d3e0ec;font-size:13px}.decision-detail strong{color:#fff}.decision-counts{display:grid;grid-template-columns:repeat(4,minmax(94px,1fr));align-content:center;border-inline-start:1px solid rgba(255,255,255,.22)}.decision-counts div{padding:10px 12px;text-align:center;border-inline-end:1px solid rgba(255,255,255,.22)}.decision-counts div:last-child{border-inline-end:0}.decision-counts strong{display:block;font-size:32px;line-height:1.1;color:#fff}.decision-counts span{display:block;margin-top:5px;color:#c6d8e8;font-size:12px}.report-nav{position:sticky;top:0;z-index:5;display:flex;gap:15px;overflow:auto;padding:14px 0 18px;white-space:nowrap;background:var(--canvas)}.report-nav a{padding:5px 0;color:var(--slate);font-size:13px;text-decoration:none;border-bottom:1px solid transparent}.report-nav a:hover,.report-nav a:focus-visible{color:var(--blue);border-color:var(--blue)}.report-section,.integrity{margin-bottom:18px;padding:24px;background:var(--paper);border-radius:8px;box-shadow:0 2px 8px rgba(18,44,73,.06)}.section-heading{display:grid;gap:7px;margin-bottom:4px}.section-heading h2,.detail-heading h2{margin:0;color:var(--blue);font-size:21px;line-height:1.35}.section-heading>p,.detail-heading>div>p{max-width:76ch;margin:0;color:var(--muted);font-size:13px}.integrity{display:flex;justify-content:space-between;gap:20px;align-items:center;background:var(--amber-soft);border:1px solid #f0d9a1}.integrity h2{margin:0;color:#684600;font-size:17px}.integrity p{margin:5px 0;color:#684600}.integrity a{color:#704a00;white-space:nowrap}.prerequisites dl{display:grid;grid-template-columns:120px minmax(0,1fr);gap:9px 14px;margin:16px 0 0}.prerequisites dt{color:var(--muted);font-weight:700}.prerequisites dd{margin:0}.host-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:12px}.host-card{padding:16px;background:#fffafa;border:1px solid #efc7ca;border-radius:7px}.host-card h3{margin:8px 0 4px;color:#7c252b;font-size:17px}.host-card p{margin:7px 0}.host-card dl{display:grid;grid-template-columns:66px 1fr;gap:4px 10px;margin:11px 0;font-size:13px}.host-card dt{font-weight:700;color:var(--muted)}.host-card dd{margin:0}.bios-notice{margin-top:12px;padding:11px 13px;background:var(--amber-soft);border-radius:6px;color:#684600}table{width:100%;border-collapse:collapse;table-layout:fixed;margin-top:12px}caption{padding:0 0 7px;color:var(--muted);font-size:12px;text-align:left}th,td{padding:10px 11px;border-bottom:1px solid var(--line);vertical-align:top;text-align:left;overflow-wrap:break-word}th{background:#f1f6fa;color:var(--blue);font-size:12px;font-weight:700}tbody tr:nth-child(even){background:#fbfcfd}tbody tr:hover{background:#e5f2fc}.readiness-table{min-width:1000px}.readiness-table th:nth-child(1){width:12%}.readiness-table th:nth-child(2){width:15%}.readiness-table th:nth-child(3){width:22%}.readiness-table th:nth-child(4){width:14%}.readiness-table th:nth-child(5){width:25%}.readiness-table th:nth-child(6){width:12%}.host-blocked td:first-child{box-shadow:inset 3px 0 0 var(--red)}.host-ready td:first-child{box-shadow:inset 3px 0 0 var(--teal)}.host-pending td:first-child{box-shadow:inset 3px 0 0 var(--amber)}.host-already td:first-child{box-shadow:inset 3px 0 0 var(--blue)}.status{display:inline-flex;flex-direction:column;gap:1px;max-width:100%;border-radius:5px;padding:3px 6px;line-height:1.3}.status small{font-family:Consolas,monospace;font-size:10px;font-weight:700;color:currentColor}.status.passed{background:var(--teal-soft);color:#07543e}.status.failed{background:var(--red-soft);color:#8f1f27}.status.unknown{background:var(--amber-soft);color:#704a00}.minor{margin:5px 0 0;color:var(--muted);font-size:12px}.version{font-family:Consolas,"Cascadia Mono",monospace;font-size:.93em;white-space:nowrap}.links{display:flex;flex-wrap:wrap;gap:7px;margin:8px 0 0}.empty-link{color:var(--muted);font-size:12px}.cross-hint{margin:7px 0 0;padding:6px 8px;background:var(--amber-soft);color:#694400;font-size:12px}.uncertain-grid{display:grid;gap:10px}.uncertain-group{border:1px solid var(--line);border-radius:7px;background:#fff}.uncertain-group>summary{display:flex;align-items:center;gap:10px;padding:12px 14px;cursor:pointer;color:var(--blue);font-weight:700}.uncertain-group>div{padding:0 14px 14px}.uncertain-group>div>p{margin:0;color:var(--muted)}details{border:1px solid var(--line);border-radius:7px;background:#fff}details>summary{padding:11px 13px;cursor:pointer;font-weight:700;color:var(--blue)}details ul{margin:0 14px 12px;padding-left:18px}.detail-heading{display:flex;justify-content:space-between;gap:18px;align-items:flex-start}.detail-body{padding:0 13px 13px}.filters{display:flex;gap:12px;align-items:end;flex-wrap:wrap;margin:14px 0}.filters label{display:grid;gap:4px;color:var(--muted);font-size:12px;font-weight:700}select{min-width:170px;padding:7px 8px;border:1px solid #b9c7d5;border-radius:5px;background:#fff;color:var(--ink);font:inherit}#filter-count{padding:7px 0;color:var(--muted);font-size:13px}.table-scroll{overflow:auto}.evidence-section .table-scroll{max-block-size:70vh;border:1px solid var(--line);border-radius:6px}.evidence-section table{min-width:1180px;margin:0}.evidence-section th{position:sticky;top:0;z-index:2}.evidence-section th:first-child,.evidence-section td:first-child{position:sticky;left:0;z-index:1}.evidence-section th:first-child{z-index:3}.evidence-section td:first-child{background:#fff}.evidence-section tbody tr.is-striped td:first-child{background:#fbfcfd}.evidence-section tbody tr:hover td:first-child{background:#e5f2fc}.evidence-section tbody tr.is-striped{background:#fbfcfd}.evidence-section tbody tr:hover{background:#e5f2fc}.evidence-section th:nth-child(1){width:180px}.evidence-section th:nth-child(2){width:72px}.evidence-section th:nth-child(3){width:156px}.evidence-section th:nth-child(4){width:220px}.evidence-section th:nth-child(5){width:128px}.evidence-section th:nth-child(6){width:250px}.evidence-section th:nth-child(7){width:270px}.empty{padding:10px;color:var(--muted);border:1px dashed var(--line);border-radius:6px;background:#fafbfd}a{color:#075d9e;text-decoration:underline;text-underline-offset:2px}footer{padding:10px 4px;color:var(--muted);font-size:12px;text-align:center}@media(max-width:850px){.shell{padding:16px}.verdict-panel{grid-template-columns:1fr;padding:24px}.decision-counts{grid-template-columns:repeat(2,minmax(0,1fr));border-top:1px solid rgba(255,255,255,.22);border-inline-start:0}.decision-counts div:nth-child(2){border-inline-end:0}.section-heading{display:block}.section-heading>p{margin-top:8px}.integrity,.detail-heading{display:block}.integrity a{display:inline-block;margin-top:10px}.host-grid{grid-template-columns:1fr}.report-nav{padding-bottom:14px}.prerequisites dl{grid-template-columns:1fr;gap:2px}.prerequisites dd{margin-bottom:8px}}@media(max-width:520px){.report-header{align-items:flex-start}.brand{flex-wrap:wrap}.print-button{font-size:13px}.verdict-panel h1{font-size:24px}.decision-counts strong{font-size:28px}.decision-counts div{padding:10px 7px}.report-meta,.verdict-text{font-size:13px}th,td{min-width:130px}.evidence-section .table-scroll{max-block-size:65vh}}@media print{@page{size:A4 landscape;margin:10mm}body{background:#fff}.shell{max-width:none;padding:0}.report-header{padding:0 0 12px}.print-button,button,.report-nav,.filters{display:none!important}.verdict-panel{box-shadow:none;break-inside:avoid}.report-section,.integrity{box-shadow:none;border:1px solid #ccd5de;break-inside:auto}.host-card,.uncertain-group,.integrity,tr{break-inside:avoid;page-break-inside:avoid}.report-section{padding:14px}.table-scroll,.evidence-section .table-scroll{max-block-size:none;overflow:visible;border:0}.evidence-section table{min-width:0;font-size:11px}.evidence-section th,.evidence-section th:first-child,.evidence-section td:first-child{position:static}.evidence-section td:first-child,.evidence-section tbody tr.is-striped td:first-child{background:transparent}.version{font-size:.9em}details{display:block!important}details>summary{display:block!important}details:not([open])>*:not(summary){display:block!important}.detail-body{padding:0}a{color:#075d9e;text-decoration:underline}.links{display:flex}footer{margin-top:8px}}
"""


_UI_REFRESH_CSS = r"""
/* Decision-oriented refinement for the offline compatibility report. */
.data-quality-alert{display:flex;justify-content:space-between;gap:18px;align-items:center;margin:0 0 14px;padding:13px 16px;background:#fff5df;border:1px solid #e9cc87;border-radius:8px;color:#6f4900}.data-quality-alert>div{display:flex;gap:11px;align-items:flex-start}.alert-symbol{display:grid;place-items:center;flex:0 0 22px;height:22px;border-radius:50%;background:#8b5900;color:#fff;font-weight:800}.data-quality-alert strong{display:block;font-size:14px}.data-quality-alert p{margin:2px 0 0;font-size:13px}.data-quality-alert a{color:#6f4900;font-weight:700;white-space:nowrap}.verdict-panel{gap:34px}.meta-chips{display:flex;flex-wrap:wrap;gap:7px 14px}.meta-chips span{white-space:nowrap}.decision-result{max-width:72ch;margin:17px 0 12px;padding:12px 14px;background:rgba(255,255,255,.08);border-radius:7px}.decision-result p{margin:4px 0 0;color:#eef5fa;font-size:15px}.decision-label{font-weight:800}.decision-result.blocked .decision-label{color:#ffd2d4}.decision-result.pending .decision-label{color:#ffe1a1}.decision-result.ready .decision-label{color:#bcebd4}.decision-result.already .decision-label{color:#c9ddf1}.device-level-summary{display:flex;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:12px;font-size:13px;color:#d3e0ec}.device-level-summary>span{font-weight:700}.device-level-summary button{padding:4px 8px;border-color:rgba(255,255,255,.35);background:transparent;color:#fff;font-size:12px}.device-level-summary button:hover{background:rgba(255,255,255,.12)}.decision-counts{grid-template-columns:repeat(2,minmax(118px,1fr));gap:1px;background:rgba(255,255,255,.18);border:0;border-radius:7px;overflow:hidden}.decision-counts div{border:0;background:rgba(4,24,43,.2)}.decision-counts .certified strong,.decision-counts .already strong{color:#bcebd4}.decision-counts .ready strong{color:#ffe1a1}.decision-counts .blocked strong{color:#ffd2d4}.report-nav a{display:inline-flex;align-items:center;gap:5px}.report-nav b{display:inline-grid;place-items:center;min-width:18px;height:18px;padding:0 4px;border-radius:9px;background:#dfe8f0;color:#294763;font-size:11px}.host-overview{padding-bottom:22px}.host-summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:10px;margin-top:16px}.host-summary-card{display:flex;flex-direction:column;min-width:0;padding:15px;background:#fff;border:1px solid var(--line);border-radius:8px}.host-card-top{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}.host-name{margin:0;color:var(--blue);font-weight:800}.host-model{margin:2px 0 0;color:var(--muted);font-size:12px}.host-outcome{flex:0 0 auto;padding:3px 7px;border-radius:4px;font-size:12px;font-weight:800}.host-outcome.ready{background:var(--teal-soft);color:#07543e}.host-outcome.already{background:var(--blue-soft);color:#123f68}.host-outcome.pending{background:var(--amber-soft);color:#704a00}.host-outcome.blocked{background:var(--red-soft);color:#8f1f27}.host-facts{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:14px 0 10px;padding:10px 0;border-top:1px solid var(--line);border-bottom:1px solid var(--line)}.host-facts>div{min-width:0}.host-facts>div>span:first-child{display:block;margin-bottom:4px;color:var(--muted);font-size:11px;font-weight:700}.host-facts .status{font-size:11px}.host-device-counts{display:flex;flex-wrap:wrap;gap:7px;margin-bottom:8px;font-size:12px;color:var(--muted)}.host-device-counts b{color:var(--ink)}.quality-flag{align-self:flex-start;margin:1px 0 7px;padding:2px 6px;border-radius:4px;background:var(--amber-soft);color:#704a00;font-size:11px;font-weight:700}.host-action{margin:0 0 11px;color:var(--slate);font-size:12px}.host-evidence-button{align-self:flex-start;margin-top:auto;padding:5px 0;border:0;background:transparent;color:#075d9e;font-size:12px;font-weight:700;text-decoration:underline;text-underline-offset:2px}.host-evidence-button:hover{background:transparent;color:#023e6d}.host-evidence{margin-top:14px}.status{flex-direction:row;align-items:flex-start;gap:5px}.status-icon{display:grid;place-items:center;flex:0 0 15px;height:15px;margin-top:1px;border:1px solid currentColor;border-radius:50%;font-size:10px;font-weight:900}.status small{display:block;margin-top:2px}.filters{gap:9px}.filters button{min-height:34px}.filter-shortcuts{display:flex;flex-wrap:wrap;gap:7px;align-items:end}.filter-shortcuts button{padding:7px 9px;font-size:12px}.filter-shortcuts button.is-active{background:var(--blue);border-color:var(--blue);color:#fff}.evidence-section details[open] .detail-body{padding-top:4px}.evidence-section .table-scroll{max-block-size:68vh}.evidence-section td:nth-child(3),.evidence-section td:nth-child(4){min-width:156px}.evidence-section td:nth-child(7){min-width:260px}.evidence-section .status{white-space:normal}.host-readiness{margin-top:12px}.host-readiness .table-scroll{margin-top:0}.host-readiness[open]>summary{border-bottom:1px solid var(--line)}
@media(max-width:850px){.data-quality-alert{display:block}.data-quality-alert a{display:inline-block;margin-top:8px}.verdict-panel{gap:20px}.device-level-summary{margin-top:12px}.host-summary-grid{grid-template-columns:1fr}.host-facts{grid-template-columns:1fr 1fr}.report-nav{top:0}.decision-counts{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:520px){.data-quality-alert{padding:12px}.data-quality-alert p{font-size:12px}.meta-chips{display:grid;gap:4px}.decision-result{padding:11px}.host-facts{grid-template-columns:1fr}.device-level-summary button{font-size:11px}.report-nav b{display:none}.evidence-section .table-scroll{max-block-size:60vh}}
@media print{.data-quality-alert{display:flex!important;box-shadow:none}.host-summary-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.host-summary-card{break-inside:avoid;page-break-inside:avoid}.device-level-summary,.host-evidence-button,.filter-shortcuts{display:none!important}.host-evidence{display:none!important}.decision-counts{background:#fff;border:1px solid #aab6c2}.decision-counts div{background:#fff}.decision-counts strong{color:#111!important}.status-icon{border-color:#111;color:#111}.status{color:#111!important;background:#fff!important;border:1px solid #777}.status small{color:#333}.data-quality-alert{color:#222;background:#fff;border-color:#777}.data-quality-alert strong,.data-quality-alert p,.data-quality-alert a{color:#222}}
"""


_UI_TABLE_WIDTHS = r"""
section[id]{scroll-margin-top:60px}.host-summary-grid{grid-template-columns:repeat(auto-fit,minmax(290px,1fr))}.evidence-section table{min-width:1400px}.evidence-section th:nth-child(1){width:190px}.evidence-section th:nth-child(2){width:108px}.evidence-section th:nth-child(3){width:185px}.evidence-section th:nth-child(4){width:255px}.evidence-section th:nth-child(5){width:145px}.evidence-section th:nth-child(6){width:280px}.evidence-section th:nth-child(7){width:340px}
.mobile-table-hint{display:none}
@media(max-width:520px){.mobile-table-hint{display:block;margin:10px 0 6px;color:var(--muted);font-size:12px}}
"""


_JS = r"""
(() => {const details=document.getElementById('device-details');const hostFilter=document.getElementById('host-filter');const typeFilter=document.getElementById('type-filter');const statusFilter=document.getElementById('status-filter');const reset=document.getElementById('reset-filters');const count=document.getElementById('filter-count');const rows=[...document.querySelectorAll('#device-table tbody tr')];const quickButtons=[...document.querySelectorAll('[data-device-filter]')];let quickMode='issues';const syncQuick=()=>quickButtons.forEach((button)=>button.classList.toggle('is-active',button.dataset.deviceFilter===quickMode));const applyFilters=()=>{const host=hostFilter?.value||'';const type=typeFilter?.value||'';const status=statusFilter?.value||'';let visible=0;rows.forEach((row)=>{const matchesQuick=quickMode==='all'||quickMode==='issues'?quickMode!=='issues'||row.dataset.status!=='passed':row.dataset.status===quickMode;const show=matchesQuick&&(!host||row.dataset.host===host)&&(!type||row.dataset.type===type)&&(!status||row.dataset.status===status);row.hidden=!show;row.classList.remove('is-striped');if(show){if(visible%2===1)row.classList.add('is-striped');visible+=1;}});if(count)count.textContent=`当前显示 ${visible} / ${rows.length} 项`;syncQuick();};const openEvidence=()=>{if(details)details.open=true;document.getElementById('device-detail')?.scrollIntoView({behavior:'smooth',block:'start'});};quickButtons.forEach((button)=>button.addEventListener('click',()=>{const mode=button.dataset.deviceFilter||'all';quickMode=mode;if(statusFilter)statusFilter.value=mode==='issues'||mode==='all'?'':mode;openEvidence();applyFilters();}));[hostFilter,typeFilter,statusFilter].forEach((control)=>control?.addEventListener('change',()=>{quickMode='all';applyFilters();}));reset?.addEventListener('click',()=>{if(hostFilter)hostFilter.value='';if(typeFilter)typeFilter.value='';if(statusFilter)statusFilter.value='';quickMode='all';applyFilters();});document.querySelectorAll('[data-open-host]').forEach((button)=>button.addEventListener('click',()=>{if(hostFilter)hostFilter.value=button.dataset.openHost||'';if(typeFilter)typeFilter.value='';if(statusFilter)statusFilter.value='';quickMode='issues';openEvidence();applyFilters();}));applyFilters();let printState=null;window.addEventListener('beforeprint',()=>{printState={details:[...document.querySelectorAll('details')].map(d=>[d,d.open]),rows:rows.map(r=>[r,r.hidden])};printState.details.forEach(([d])=>d.open=true);rows.forEach(r=>r.hidden=false);});window.addEventListener('afterprint',()=>{if(printState){printState.details.forEach(([d,open])=>d.open=open);printState.rows.forEach(([r,hidden])=>r.hidden=hidden);printState=null;}});document.documentElement.dataset.ready='true';})();
"""
