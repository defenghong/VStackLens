"""One customer presentation of saved conclusions; no rule re-evaluation."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import date, timedelta
import hashlib
import json
import math
import re
from typing import Any, Callable

from vstacklens.reports.customer_caliber import ensure_report, projected_findings, object_key


@dataclass(frozen=True)
class CustomerProblemCategory:
    category: dict[str, Any]
    source_findings: tuple[dict[str, Any], ...]
    projected_findings: tuple[dict[str, Any], ...]
    display: dict[str, Any]


@dataclass(frozen=True)
class CustomerProblemView:
    fingerprint: str
    caliber: dict[str, Any]
    categories: tuple[CustomerProblemCategory, ...]

    @property
    def projected_findings(self) -> list[dict[str, Any]]:
        # A renderer must not be able to mutate another renderer's input.
        return [deepcopy(row) for entry in self.categories for row in entry.projected_findings]


def get_customer_problem_view(report: Any, context: dict[str, Any] | None = None) -> CustomerProblemView:
    """Project recorded conclusions only; do not reinterpret rules or exceptions."""
    caliber = ensure_report(report, context)
    identity = {key: caliber.get(key) for key in (
        'version', 'run_id', 'categories', 'findings', 'counts', 'affected_counts',
        'affected_total', 'problem_count', 'health')}
    identity['assets'] = report.asset_inventory
    fingerprint = hashlib.sha256(('customer-view-batch3-wording-v1:' + json.dumps(identity, ensure_ascii=False, sort_keys=True, default=str)).encode('utf-8')).hexdigest()
    cached = report._customer_problem_view
    if cached is not None and cached.fingerprint == fingerprint:
        return cached
    projected = projected_findings(caliber)
    categories = tuple(CustomerProblemCategory(
        category=deepcopy(category),
        source_findings=tuple(deepcopy(row) for row in caliber['findings'] if row['category_id'] == category['category_id']),
        projected_findings=tuple(deepcopy(row) for row in projected if row['category_id'] == category['category_id']),
        display=build_problem_display(report, category, [row for row in caliber['findings'] if row['category_id'] == category['category_id']], [row for row in projected if row['category_id'] == category['category_id']]),
    ) for category in caliber['categories'])
    view = CustomerProblemView(fingerprint, caliber, categories)
    report._customer_problem_view = view
    return view


BUSINESS_EFFECT = {
    'VM-SNAPSHOT': '删除时不用关机，合并过程中可能短暂停顿，建议在业务低峰期操作。',
    'CLUSTER-HA': '启用不影响正在运行的虚拟机。',
    'CLUSTER-DRS': '启用不影响正在运行的虚拟机。',
    'HOST-MANAGEMENT-SERVICE': '关闭不影响业务。',
    'VM-CDROM': '确认无用后断开，不影响业务。',
    'VM-RESOURCE-CONFIG': '可在线修改，不用关机。',
    'HOST-RESOURCE-ALLOCATION': '通过迁移调整不用关机；如需缩减虚拟机配置，该虚拟机需要关机。',
    'VM-LOCAL-DATASTORE': '开机的虚拟机可在线迁移；关机的直接迁移，不影响业务。',
    'VM-LONG-POWERED-OFF': '确认无用后清理，不影响业务。',
}
_MISSING = ('未采集', '未提供', '未记录', '证据不足', 'api_error', 'Traceback', '无法获取')

CUSTOMER_IMPACTS = {
    'VC-ALARMS': 'vCenter 存在未处理的严重告警，需确认告警对象的实际状态。',
    'VM-SNAPSHOT': '快照不能替代备份。长期保留会使增量磁盘持续变大，占用存储并降低虚拟机磁盘性能，删除时合并耗时也更长。',
    'CLUSTER-HA': '发生主机故障时，该集群不能通过 vSphere HA 在其他主机自动重启虚拟机。',
    'HOST-MANAGEMENT-SERVICE': 'SSH 远程命令行入口保持开放，需要核对使用必要性和访问权限。',
    'HOST-RESOURCE-ALLOCATION': '分配给虚拟机的 vCPU 或内存多于主机实际资源，业务同时高峰时可能出现资源争用。',
    'VM-LONG-POWERED-OFF': '保留的虚拟机文件仍占用存储，需确认保留用途。',
    'VM-LOCAL-DATASTORE': '所在主机故障时，这些虚拟机无法由 HA 在其他主机上重启；主机维护时需要连同磁盘一起迁移。',
    'VM-RESOURCE-CONFIG': '不合理的预留会占用集群可分配资源，影响其他虚拟机开机和 HA 容量；资源限制会让虚拟机在需要时也拿不到更多资源，导致性能受限。',
    'CLUSTER-DRS': '本集群未通过 DRS 自动均衡工作负载，需要人工评估和安排虚拟机迁移。',
    'VM-CDROM': '虚拟机持续挂载 ISO 时，迁移的目标主机也必须能访问该镜像所在的存储。',
}


def customer_labels() -> dict[str, str]:
    """Shared labels only; never derive a saved result from display wording."""
    from vstacklens.reports.customer_format import percent_text

    return {
        'check_total_label': '检查总数', 'scope_subtitle': '本次检查结果',
        'level_label': '等级', 'basis_label': '判断依据',
        'current_label': '当前值', 'expected_label': '判定标准',
        'alarm_evidence_intro': '以下列出告警内容及其对应对象。',
        **{f'reference_{value}': percent_text(value) for value in (0, 75, 80, 100, 125)},
    }


def customer_failed_levels_text(levels: dict[str, Any]) -> str:
    return '未通过的检查中，' + '、'.join(f'{key} {levels.get(key, 0)} 条' for key in ('P1', 'P2', 'P3')) + '。'


def customer_wording(value: Any) -> str:
    """Apply exact approved prose substitutions, never normalize object names."""
    text = '' if value is None else str(value)
    replacements = {
        '可能影响维护窗口安排': '可能影响主机维护时的迁移安排',
        '维护窗口': '业务低峰期', '复跑巡检规则': '重新巡检', '复跑巡检': '重新巡检',
        '复跑': '重新巡检', '资源限制 配置': '资源限制配置',
        '不合理 资源限制': '不合理的资源限制', '当次等级': '等级',
        '当次判断依据': '判断依据', '当次对象证据': '判断依据',
    }
    for before, after in replacements.items():
        text = text.replace(before, after)
    return text


def customer_prose(value: Any, protected: tuple[str, ...] = ()) -> str:
    """Normalize prose that is explicitly not an object name, path or header."""
    text = '' if value is None else str(value)
    restored = {}
    for name in sorted(set(protected), key=len, reverse=True):
        if name and name in text:
            token = f'\ue000{len(restored)}\ue001'
            restored[token] = name
            text = text.replace(name, token)
    text = customer_text(text).replace('Datastore', '数据存储')
    text = re.sub(r'(?<=[\u4e00-\u9fff])\s+数据存储', '数据存储', text)
    text = re.sub(r'数据存储\s+(?=[\u4e00-\u9fff])', '数据存储', text)
    for token, name in restored.items():
        text = text.replace(token, name)
    return text


def customer_join_nonempty(parts, separator: str = ' · ') -> str:
    """Omit an absent field together with its separator, retaining real 0/False."""
    return separator.join(text for value in parts if value is not None and (text := str(value).strip()))


def customer_category_title(category_id: str, value: Any) -> str:
    """Change an approved display name without touching its saved identity."""
    if category_id == 'VM-LOCAL-DATASTORE':
        return '虚拟机磁盘存放在本地存储'
    return customer_wording(value)


def _known_number(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result if math.isfinite(result) else None


def _saved_date(value: Any) -> date | None:
    try:
        return date.fromisoformat(str(value)[:10])
    except (TypeError, ValueError):
        return None


def _nic_collection_failed(properties: dict[str, Any]) -> bool:
    """An explicit empty NIC list is a value only when its source succeeded."""
    failures = {'failed', 'error', 'api_error', 'missing', 'unavailable', 'permission_denied', 'unsupported'}
    for key in ('physical_nic_collection_status', 'physical_nic_link_collection_status', 'network_collection_status'):
        if str(properties.get(key) or '').casefold() in failures:
            return True
    observations = properties.get('sdk_property_observations') or {}
    if not isinstance(observations, dict):
        return False
    for observation in observations.get('fields') or []:
        if not isinstance(observation, dict):
            continue
        path = str(observation.get('property') or '')
        is_nic_source = path in {'config', 'network', 'physical_nic_details'} or path.startswith('config.network')
        if is_nic_source and (str(observation.get('status') or '').casefold() in failures or observation.get('fault_type')):
            return True
    return False


def customer_display_facts(report: Any) -> dict[str, Any]:
    """Read-only customer labels/facts, preserving all saved result decisions.

    Missing facts stay absent/None rather than becoming zero or a customer
    placeholder. A fresh result is returned so renderers cannot affect each
    other's inputs. No current date, network query or rule evaluation is used.
    """
    caliber = getattr(report, 'customer_caliber', {}) or {}
    inventory = getattr(report, 'asset_inventory', {}) or {}
    details = inventory.get('details') or {}
    vm_rows = details.get('VirtualMachine')
    hosts = details.get('HostSystem') or []
    categories = caliber.get('categories') or getattr(report, 'problem_categories', []) or []
    snapshot_category = next((row for row in categories if row.get('category_id') == 'VM-SNAPSHOT'), {})
    vm_count = None
    if isinstance(vm_rows, list):
        vm_count = sum(
            bool((row.get('properties') or {}).get('snapshots'))
            or (row.get('properties') or {}).get('has_snapshot') is True
            or (_known_number((row.get('properties') or {}).get('snapshot_count')) or 0) > 0
            or (_known_number((row.get('properties') or {}).get('snapshot_chain_depth')) or 0) > 0
            for row in vm_rows if isinstance(row, dict)
        )
    problem_vm_count = snapshot_category.get('affected_object_count')
    if problem_vm_count is None and isinstance(snapshot_category.get('affected_objects'), list):
        problem_vm_count = len({object_key(row) for row in snapshot_category['affected_objects']})
    if not snapshot_category and 'categories' in caliber:
        problem_vm_count = 0
    snapshots = {
        'vm_count': vm_count, 'problem_vm_count': problem_vm_count,
        'overview_label': f'有快照的虚拟机 {vm_count} 台' if vm_count is not None else '',
        'problem_label': f'需处理 {problem_vm_count} 台' if problem_vm_count is not None else '',
        'threshold_label': '7 天及以上',
    }

    captured = _saved_date(getattr(getattr(report, 'report_info', None), 'generated_at', None))
    certificate_evidence = (getattr(report, 'appendix', {}) or {}).get('certificate_license_evidence') or []

    def certificate(row: dict, *, host: bool) -> dict | None:
        props = row.get('properties') or {}
        prefix = 'host_' if host else ''
        kind = 'HostSystem' if host else 'vCenter'
        stable_matches = [entry for entry in certificate_evidence if isinstance(entry, dict)
                          and entry.get('object_type') == kind and row.get('object_key')
                          and entry.get('object_key') == row.get('object_key')]
        if not stable_matches:
            asset_matches = [entry for entry in details.get(kind, [])
                             if entry.get('object_name') == row.get('object_name')]
            if len(asset_matches) == 1:
                stable_matches = [entry for entry in certificate_evidence if isinstance(entry, dict)
                                  and entry.get('object_type') == kind and entry.get('object_name') == row.get('object_name')]
        saved_capture = next((value for entry in stable_matches
                              if (value := _saved_date(entry.get('collected_at'))) is not None), captured)
        days = _known_number(props.get(prefix + 'certificate_days_remaining'))
        direct = _saved_date(props.get(prefix + 'certificate_not_after') or props.get(prefix + 'certificate_expiration_date'))
        if direct is None and days is None:
            return None
        result = {'object_key': str(row.get('object_key') or ''), 'name': str(row.get('object_name') or '')}
        if days is not None:
            result['days'] = int(days) if days.is_integer() else days
        if direct is not None:
            result.update(expiry_date=direct.isoformat(), derived=False,
                          date_source='ESXi 443 TLS 证书直接读取' if host else 'vCenter 证书直接读取')
        elif saved_capture is not None and days is not None:
            try:
                expiry = (saved_capture + timedelta(days=int(days))).isoformat()
            except (OverflowError, ValueError):
                expiry = None
            if expiry:
                result.update(expiry_date=expiry, derived=True,
                              date_source='按采集日期和保存的剩余天数推算')
        return result

    vcenter_rows = details.get('vCenter') or []
    certificates = {
        'vcenter': certificate(vcenter_rows[0], host=False) if len(vcenter_rows) == 1 else None,
        'hosts': [entry for row in hosts if (entry := certificate(row, host=True)) is not None],
    }
    clusters = []
    for row in details.get('ClusterComputeResource') or []:
        props = row.get('properties') or {}
        entry = {'object_key': str(row.get('object_key') or ''), 'name': str(row.get('object_name') or '')}
        for key in ('ha_enabled', 'drs_enabled'):
            if isinstance(props.get(key), bool):
                entry[key] = props[key]
        if props.get('ha_enabled') is False:
            entry.update(admission_control='—', heartbeat_summary='—')
        elif props.get('ha_enabled') is True:
            if isinstance(props.get('admission_control_enabled'), bool):
                entry['admission_control'] = '已启用' if props['admission_control_enabled'] else '未启用'
            heartbeat = _known_number(props.get('ha_heartbeat_datastore_count'))
            if heartbeat is not None:
                names = '、'.join(str(value) for value in props.get('heartbeat_datastore_names') or [] if value)
                entry['heartbeat_summary'] = f'{heartbeat:g} 个' + (f'：{names}' if names else '')
        if props.get('drs_enabled') is False:
            entry['drs_behavior'] = '—'
        elif props.get('drs_enabled') is True:
            behavior = props.get('drs_behavior')
            if behavior in {'fullyAutomated', 'partiallyAutomated', 'manual'}:
                entry['drs_behavior'] = {'fullyAutomated': '全自动', 'partiallyAutomated': '部分自动化', 'manual': '手动'}[behavior]
        if isinstance(props.get('evc_enabled'), bool):
            entry['evc_state'] = '已启用' if props['evc_enabled'] else '未启用'
        clusters.append(entry)

    host_services = []
    for row in hosts:
        props = row.get('properties') or {}
        entry = {'object_key': str(row.get('object_key') or ''), 'name': str(row.get('object_name') or '')}
        for source_key, display_key in (('ssh_running', 'ssh_state'), ('esxi_shell_running', 'shell_state')):
            if isinstance(props.get(source_key), bool):
                entry[display_key] = '运行' if props[source_key] else '未运行'
        if 'ssh_state' in entry:
            entry['ssh_summary'] = f"远程 SSH 服务{entry['ssh_state']}"
        if 'shell_state' in entry:
            entry['shell_summary'] = f"本地 Shell 服务{entry['shell_state']}"
        host_services.append(entry)

    # In-use link health and packet/error counters are separate evidence paths.
    active_link_anomalies = None
    active_rows = []
    complete_links = bool(hosts)
    for row in hosts:
        props = row.get('properties') or {}
        nics = props.get('physical_nic_details')
        if not isinstance(nics, list) or _nic_collection_failed(props):
            complete_links = False
            continue
        for nic in nics:
            if not isinstance(nic, dict):
                complete_links = False
                continue
            in_use = nic.get('is_in_use') is True or ('is_in_use' not in nic and nic.get('is_uplink') is True)
            if not in_use:
                continue
            state = str(nic.get('assessment') or '').casefold()
            link = str(nic.get('link_state') or '').casefold()
            codes = nic.get('issue_codes') or []
            if state not in {'up', 'normal', 'healthy', 'down', 'degraded'} and link not in {'up', 'down'} and not codes:
                complete_links = False
            active_rows.append((str(row.get('object_key') or row.get('object_name') or ''),
                                str(nic.get('device') or ''), bool(codes) or state in {'down', 'degraded'} or link == 'down'))
    if complete_links:
        active_link_anomalies = len({(host, device) for host, device, failed in active_rows if failed})
    error_counts = [_known_number((row.get('properties') or {}).get('pnic_error_count')) for row in hosts]
    error_count = sum(error_counts) if hosts and all(value is not None for value in error_counts) else None
    network_text = []
    if active_link_anomalies is not None:
        network_text.append('在用物理链路未发现异常' if active_link_anomalies == 0 else f'在用物理链路异常 {active_link_anomalies} 条')
    if error_count is not None:
        network_text.append(f'物理网卡错误或丢包计数 {error_count:g} 次')
    network = {'active_link_anomalies': active_link_anomalies, 'error_count': error_count,
               'summary': '；'.join(network_text) + ('。' if network_text else '')}

    saved_vsan = customer_vsan_summary(report)
    items = []

    def item(key: str, label: str, value: Any, text: str) -> None:
        items.append({'key': key, 'label': label, 'value': value, 'text': text})

    disk_rows = saved_vsan.get('disk_details') or []
    disk_issues = _known_number(saved_vsan.get('disk_issue_count'))
    if disk_rows and disk_issues is not None:
        states = [str(row.get('health') or '').casefold() for row in disk_rows if isinstance(row, dict)]
        if len(states) == len(disk_rows) and all(value in {'normal', 'healthy', 'green', 'ok', 'passed', '正常', 'red', 'yellow', 'warning', 'error', 'failed', 'degraded', 'offline', 'absent', 'unhealthy', '异常', '故障'} for value in states):
            item('disks', '物理磁盘', len(disk_rows), f'已核对 {len(disk_rows)} 块物理磁盘，健康异常 {disk_issues:g} 项')
    object_count = _known_number(saved_vsan.get('object_count'))
    object_issues = _known_number(saved_vsan.get('object_issue_count'))
    if object_count is not None and object_issues is not None:
        item('objects', 'vSAN 对象', object_count, f'已识别 {object_count:g} 个 vSAN 对象，健康异常 {object_issues:g} 项')
    capacity = saved_vsan.get('capacity') or {}
    used = _known_number(capacity.get('used_percent'))
    if used is not None:
        from vstacklens.reports.customer_format import percent_text
        item('capacity', '容量使用率', used, f'容量使用率 {percent_text(used)}')
    resync_objects = _known_number(saved_vsan.get('resync_object_count'))
    resync_bytes = _known_number(saved_vsan.get('resync_bytes'))
    if resync_objects is not None and resync_bytes is not None:
        text = '当前无待重同步对象或数据' if resync_objects == 0 and resync_bytes == 0 else f'待重同步对象 {resync_objects:g} 个、数据 {resync_bytes:g} 字节'
        item('resync', '重同步', resync_objects, text)
    vmkernels = (saved_vsan.get('network') or {}).get('vmkernels') or []
    if vmkernels:
        item('network', 'vSAN VMkernel 配置', len(vmkernels), f'已核对 {len(vmkernels)} 条 vSAN VMkernel 接口配置')

    wording = customer_labels()
    if hasattr(report, 'caliber_inputs'):
        from vstacklens.reports.presentation import customer_check_statistics
        wording['failed_levels_text'] = customer_failed_levels_text(customer_check_statistics(report).get('levels') or {})
    return {
        'counts': {'problem_count': caliber.get('problem_count'), 'affected_total': caliber.get('affected_total'),
                   'problem_label': '问题类别', 'affected_label': '受影响对象'},
        'snapshots': snapshots, 'certificates': certificates, 'clusters': clusters, 'host_services': host_services,
        'wording': wording,
        'vsan': {'items': items, 'summary': '；'.join(value['text'] for value in items) + ('。' if items else '')},
        'network': network,
        'top_labels': {
            'cpu': '同主机开机虚拟机 CPU 实际用量占比', 'memory': '同主机开机虚拟机内存实际用量占比',
            'vcpu': '占同主机虚拟机配置 vCPU 总数（含关机虚拟机和模板）',
            'capacity': '占同主机虚拟机 VMDK 配置容量（含关机虚拟机和模板）',
            'actual_note': 'CPU 与内存占比按同一主机开机虚拟机的实际用量合计计算。',
            'configuration_note': '配置总量包含开机、关机虚拟机和模板，不等于运行用量。',
        },
    }


def _management_service_names(sources: list[dict], properties: dict | None = None) -> tuple[str, ...]:
    """Identify the failed service from its saved rule, without re-evaluation."""
    rule_names = {'VSL-HOST-002': 'SSH', 'VSL-HOST-016': 'ESXi Shell'}
    selected = {rule_names[row['rule_id']] for row in sources if row.get('rule_id') in rule_names}
    if not selected and properties:
        selected = {name for field, name in (('ssh_running', 'SSH'), ('esxi_shell_running', 'ESXi Shell'))
                    if properties.get(field) is True}
    return tuple(name for name in ('SSH', 'ESXi Shell') if name in selected) or ('SSH',)


def operation_steps(category_id: str, original_steps: list[str], *, management_services: tuple[str, ...] = ('SSH',)) -> list[str]:
    """Attach impact to the actual operation, before its existing verification."""
    import re
    effect = BUSINESS_EFFECT.get(category_id)
    steps = _unique(customer_prose(value).strip() for value in original_steps if value and value != effect)
    if not effect:
        return steps
    patterns = {
        'CLUSTER-HA': r'启用.*(?:HA|ha)', 'CLUSTER-DRS': r'启用.*(?:DRS|drs)',
        'HOST-MANAGEMENT-SERVICE': r'(?:停止|关闭).*SSH',
        'VM-SNAPSHOT': r'(?:删除|合并).*快照', 'VM-CDROM': r'(?:断开|卸载)',
        'VM-RESOURCE-CONFIG': r'(?:调整.*预留|(?:移除|调整|修改).*(?:资源限制|Limit))',
        'HOST-RESOURCE-ALLOCATION': r'(?:通过|执行|进行).*(?:迁移|回收|扩容)',
        'VM-LOCAL-DATASTORE': r'^(?:完成)?迁移',
        'VM-LONG-POWERED-OFF': r'(?:执行|进行).*(?:归档|下线|删除|清理)',
    }
    defaults = {
        'CLUSTER-HA':'启用 vSphere HA', 'CLUSTER-DRS':'启用 DRS',
        'HOST-MANAGEMENT-SERVICE':'关闭 SSH 服务', 'VM-SNAPSHOT':'删除或合并快照',
        'VM-CDROM':'断开不再使用的 ISO 挂载', 'VM-RESOURCE-CONFIG':'修改预留或 Limit 设置',
        'HOST-RESOURCE-ALLOCATION':'通过迁移调整资源分配', 'VM-LOCAL-DATASTORE':'迁移虚拟机或确认保留例外',
        'VM-LONG-POWERED-OFF':'清理确认无用的关机虚拟机',
    }
    if category_id == 'HOST-MANAGEMENT-SERVICE':
        patterns[category_id] = r'(?:停止|关闭).*(?:' + '|'.join(re.escape(name) for name in management_services) + ')'
        defaults[category_id] = '关闭 ' + ' 和 '.join(management_services) + ' 服务'
    result=[];attached=False
    for step in steps:
        if effect in step:
            result.append(step);attached=True;continue
        if not re.search(patterns[category_id], step, flags=re.IGNORECASE):
            result.append(step);continue
        body=step.rstrip('。；; ')
        if category_id in {'CLUSTER-HA','CLUSTER-DRS','VM-SNAPSHOT'}:
            body=re.sub(r'^(?:建议)?在业务低峰期', '', body)
        verification=re.search(r'(?:并|后)((?:重新巡检|复跑巡检).*)$', body)
        tail=None
        if verification:
            tail=verification.group(1);body=body[:verification.start()].rstrip('。；; ')
        result.append(_period(body)+effect)
        if tail:result.append(_period(tail))
        attached=True
    if not attached:
        # Older saved records can lack operation instructions. Add an explicit
        # approved action, never a free-standing impact sentence after review.
        at=next((i for i,value in enumerate(result) if any(token in value for token in ('重新巡检', '复跑', '复检'))),len(result))
        result.insert(at,_period(defaults[category_id])+effect)
    return _unique(result)


def customer_text(value: Any) -> str:
    """Hide unavailable fragments, never substitute zero/False/normal for them."""
    if value is None:
        return ''
    text = str(value).strip()
    if text.casefold() in {'none','unknown','未确认','未知','未解析','未识别','unavailable'}:
        return ''
    if any(token in text for token in _MISSING):
        return ''
    return customer_wording(text)


def _unique(values):
    return list(dict.fromkeys(value for value in values if value))


def _period(value: str) -> str:
    return value.rstrip('。；;，, ') + '。' if value else ''


def customer_problem_summary(current: str, impact: str, remediation: str) -> str:
    return ' '.join(_period(customer_text(value)) for value in (current, impact, remediation) if customer_text(value))


NSX_MANAGER_RESERVATION_ADVICE = 'NSX Manager 的资源预留由产品部署设定，不建议降低，保持现状即可。'


def _nsx_manager_asset_keys(report: Any) -> set[tuple[str, str]]:
    """Bind known roles, or one user-confirmed conventional asset, by identity.

    Historical runs can lack product-role metadata. The narrowly approved
    name fallback identifies a single asset first; it never joins a finding
    to a different same-named asset or treats a reservation size as identity.
    """
    rows = (report.asset_inventory.get('details') or {}).get('VirtualMachine') or []
    explicit = set()
    conventional = []
    for row in rows:
        key = (str(row.get('object_type') or 'VirtualMachine'), str(row.get('object_key') or ''))
        if not key[1]:
            continue
        props = row.get('properties') or {}
        roles = [str(props.get(field) or '').strip().casefold() for field in
                 ('product_role', 'appliance_role', 'system_vm_role', 'product_type', 'product_name')]
        marked = [value for value in roles if value]
        normalized_roles = [re.sub(r'[\s_-]+', '', value) for value in marked]
        is_manager = any(value in {'nsxmanager', 'nsxtmanager'} for value in normalized_roles)
        is_manager = is_manager or ('manager' in normalized_roles and any(value in {'nsx', 'nsxt'} for value in normalized_roles))
        if is_manager:
            explicit.add(key)
        name = re.sub(r'[\s_-]+', '', str(row.get('object_name') or '').casefold())
        if name in {'nsxmanager', 'nsxtmanager'}:
            # A conflicting saved role blocks the historical name fallback.
            conventional.append((key, bool(marked) and not is_manager))
    if len(conventional) == 1 and not conventional[0][1]:
        explicit.add(conventional[0][0])
    return explicit


def build_problem_display(report, category: dict, sources: list[dict], projected: list[dict]) -> dict:
    """Keep membership/grades; expose the same saved evidence to all formats."""
    category_id = category['category_id']
    display_title = customer_category_title(category_id, category.get('title'))
    first = sources[0] if sources else {}
    assets = {(row.get('object_type', kind), str(row.get('object_key') or '')): row
              for kind, rows in (report.asset_inventory.get('details') or {}).items() for row in rows}
    assets_by_name = {}
    for kind, rows in (report.asset_inventory.get('details') or {}).items():
        for row in rows:
            assets_by_name.setdefault((row.get('object_type') or kind, row.get('object_name')), []).append(row)
    protected_names = tuple(str(row.get('object_name') or '') for row in assets.values()) + tuple(
        str(row.get('object_name') or '') for row in category.get('affected_objects', [])
    ) + tuple(
        str(snapshot.get('name') or '') for row in assets.values()
        for snapshot in (row.get('properties') or {}).get('snapshots') or []
    ) + tuple(str(path) for row in assets.values() for path in (row.get('properties') or {}).get('iso_paths') or [])
    prose = lambda value: customer_prose(value, protected_names)
    nsx_managers = _nsx_manager_asset_keys(report) if category_id == 'VM-RESOURCE-CONFIG' else set()
    management_services = _management_service_names(sources) if category_id == 'HOST-MANAGEMENT-SERVICE' else ()
    services_by_object = {}
    objects = []
    for obj in category['affected_objects']:
        key = (obj['object_type'], str(obj['object_key']))
        asset = assets.get(key, {})
        if not asset:
            candidates = assets_by_name.get((obj['object_type'], obj['object_name']), [])
            if len(candidates) == 1:
                asset = candidates[0]
        props = asset.get('properties') or {}
        evidence = [row for row in category.get('evidence_items', [])
                    if (row.get('object_type'), str(row.get('object_key'))) == key]
        matching = [row for row in sources if object_key(row) == key]
        parts = _unique(prose(row.get('explanation')) for row in evidence)
        rich = _unique(prose(row.get('evidence_summary_zh') or row.get('observed_detail_zh')) for row in matching)
        if rich:
            parts = rich
        if category_id in {'CLUSTER-HA', 'CLUSTER-DRS'}:
            feature = 'vSphere HA' if category_id == 'CLUSTER-HA' else 'DRS'
            parts = [f"{obj['object_name']} 集群未启用 {feature}，建议启用 {feature}。"]
        elif category_id == 'HOST-MANAGEMENT-SERVICE':
            services = _management_service_names(matching or sources, props)
            services_by_object[key] = services
            parts = [f"{obj['object_name']} 的 {name} 服务正在运行；无持续使用需求时，建议停止 {name} 服务。"
                     for name in services]
        elif category_id == 'VM-LONG-POWERED-OFF':
            parts = ['当前电源状态：关机。']
            if props.get('powered_off_days') is not None:
                parts.append(f"已记录关机时长：{props['powered_off_days']} 天。")
        elif category_id == 'VM-RESOURCE-CONFIG':
            parts = []
            for field, label, unit in (
                ('cpu_reservation_mhz', 'CPU 预留', 'MHz'), ('memory_reservation_mb', '内存预留', 'MB'),
                ('cpu_limit_mhz', 'CPU 限制', 'MHz'), ('memory_limit_mb', '内存限制', 'MB')):
                value = props.get(field)
                if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0:
                    parts.append(f'{label}：{value:g} {unit}。')
            if not parts:
                parts = _unique(customer_text(row.get('explanation')) for row in evidence)
        elif category_id == 'VM-CDROM':
            paths = [str(path) for path in props.get('iso_paths', []) if path]
            parts = ['ISO 路径：' + '、'.join(paths)] if paths else parts
        elif category_id == 'VM-SNAPSHOT':
            # Counts of snapshot records belong to the existing detail tables,
            # not the customer problem summary. Keep the saved names/times.
            parts = [re.sub(r'[，；]\s*(?:共|已)采集\s*\d+\s*条快照明细', '', value) for value in parts]
            for snapshot in props.get('snapshots', []) or []:
                from vstacklens.reports.customer_format import local_time_text
                # Snapshot names are original identifiers, not customer prose.
                details = [str(snapshot.get('name') or ''), local_time_text(snapshot.get('create_time'))]
                if any(details):
                    parts.append('快照：' + '；'.join(value for value in details if value))
            if props.get('snapshot_chain_depth') is not None:
                parts.append(f"快照链深度：{props['snapshot_chain_depth']}。")
        elif category_id == 'VC-ALARMS':
            for source in matching:
                for alarm in (source.get('observed_detail') or {}).get('active_red_alarms', []) or []:
                    parts.append('；'.join(f'{label}：{alarm[field]}' for field, label in
                                          [('alarm_name', '告警名称'), ('entity_name', '告警对象'), ('status', '状态')]
                                          if alarm.get(field) is not None))
        advice = _unique(prose(row.get('remediation')) for row in evidence
                         if customer_text(row.get('remediation')) != customer_text(category.get('remediation_zh')))
        if key in nsx_managers and key in assets and any(source.get('rule_id') == 'VSL-VM-010' for source in matching):
            advice = [NSX_MANAGER_RESERVATION_ADVICE]
        # Object-level restrictions are evidence, not an approved exemption.
        basis = '\n'.join(_unique(parts))
        if advice:
            basis += ('\n' if basis else '') + '对象处理要求：' + '；'.join(advice)
        objects.append({'object_type':obj['object_type'], 'object_key':obj['object_key'],
                        'name':obj['object_name'], 'level':obj['risk_level'],
                        'location':customer_text(asset.get('asset_location') or obj.get('object_path')),
                        'basis':basis, 'advice':advice})
    if category_id == 'HOST-MANAGEMENT-SERVICE':
        management_services = tuple(name for name in ('SSH', 'ESXi Shell')
                                    if any(name in services for services in services_by_object.values())) or management_services
    impact = prose(category.get('potential_impact') or first.get('business_impact'))
    remediation = prose(category.get('remediation_zh') or first.get('remediation'))
    plan = next((item for item in report.remediation_plan if item.rule_id in category.get('source_rule_ids', [])), None)
    steps = _unique(prose(step) for step in (first.get('remediation_steps') or (plan.steps if plan else [])))
    current = f"{category['affected_object_count']} 个受影响对象：{display_title}。"
    expected = prose(first.get('expected_detail_zh') or first.get('expected_value_zh'))
    step_groups = []
    names = '、'.join(obj['name'] for obj in objects if obj['name'])
    if category_id in {'CLUSTER-HA', 'CLUSTER-DRS'}:
        feature = 'vSphere HA' if category_id == 'CLUSTER-HA' else 'DRS'
        current = f"{category['affected_object_count']} 个集群未启用 {feature}" + (f'：{names}' if names else '') + '。'
        expected = f'建议启用 {feature}。'
    elif category_id == 'HOST-MANAGEMENT-SERVICE':
        if management_services == ('SSH',):
            current = f"{category['affected_object_count']} 台 ESXi 主机的 SSH 服务正在运行。"
        else:
            current = '；'.join(f"{sum(name in services_by_object[(obj['object_type'], str(obj['object_key']))] for obj in objects)} 台 ESXi 主机的 {name} 服务正在运行"
                               for name in management_services) + '。'
            display_title = 'ESXi Shell 服务已开启' if management_services == ('ESXi Shell',) else 'ESXi 主机管理服务正在运行'
            remediation = '无持续使用需求时停止 ' + ' 和 '.join(management_services) + ' 服务，并将启动策略设为手动或按需启用。'
            steps = _unique(prose(step) for source in sources for step in source.get('remediation_steps', []) or [])
        expected = '无持续使用需求时，建议停止 ' + ' 和 '.join(management_services) + ' 服务。'
    elif category_id == 'HOST-RESOURCE-ALLOCATION':
        current = f"{category['affected_object_count']} 台 ESXi 主机的资源分配比例偏高。"
    elif category_id == 'VM-LOCAL-DATASTORE':
        current = f"{category['affected_object_count']} 台虚拟机的磁盘存放在主机本地数据存储上。"
    if category_id == 'VC-ALARMS':
        values = []
        for source in sources:
            detail = source.get('observed_detail') or {}
            value = detail.get('red_alarm_count', source.get('current_value'))
            if value is None and isinstance(detail.get('active_red_alarms'), list):
                value = len(detail['active_red_alarms'])
            values.append(value)
        known = [value for value in values if isinstance(value, (int,float)) and not isinstance(value,bool)]
        if known:
            alarm_names = _unique(f"{alarm.get('entity_name')} 的“{alarm.get('alarm_name')}”告警" for source in sources
                                  for alarm in (source.get('observed_detail') or {}).get('active_red_alarms', []) or []
                                  if alarm.get('entity_name') and alarm.get('alarm_name'))
            current = f"{sum(known):g} 条红色活动告警" + ('：' + '；'.join(alarm_names) if alarm_names else '') + '。'
        expected = '红色活动告警应为 0 条。'
    elif category_id == 'VM-SNAPSHOT':
        snapshot_facts = customer_display_facts(report)['snapshots']
        current = _period(snapshot_facts['problem_label'])
        if any(source.get('rule_id') == 'VSL-VM-001' for source in sources):
            expected = '保留 7 天及以上的快照需核对业务保留要求。'
            remediation = remediation.removeprefix('保留 7 天及以上的快照需核对业务保留要求；')
    elif category_id == 'VM-LONG-POWERED-OFF':
        current = f"{category['affected_object_count']} 台虚拟机处于关机状态。"
        expected = ''  # This saved rule is not a 90-day duration rule.
        from vstacklens.reports.presentation import count_excluded_powered_off_vms, powered_off_exclusion_note
        note = powered_off_exclusion_note(count_excluded_powered_off_vms((report.asset_inventory.get('details') or {}).get('VirtualMachine', [])))
    elif category_id == 'VM-RESOURCE-CONFIG':
        reservations = sum(any(row.get('rule_id') == 'VSL-VM-010' for row in category.get('evidence_items', []) if row.get('object_key') == obj['object_key']) for obj in objects)
        limits = sum(any(row.get('rule_id') == 'VSL-VM-011' for row in category.get('evidence_items', []) if row.get('object_key') == obj['object_key']) for obj in objects)
        current = f"{len(objects)} 台虚拟机存在资源配置问题：{reservations} 台涉及预留，{limits} 台涉及资源限制。"
        expected = ''
        remediation = '分别核对资源预留和资源限制的业务用途，再按各虚拟机的建议处理。'
        for rule_id, title in (('VSL-VM-010', '预留'), ('VSL-VM-011', '资源限制')):
            rule_steps = _unique(prose(step) for source in sources
                                 if source.get('rule_id') == rule_id for step in source.get('remediation_steps', []) or [])
            if rule_steps:
                step_groups.append({'title': title, 'steps': operation_steps(category_id, rule_steps)})
        steps = [step for group in step_groups for step in group['steps']]
    elif category_id == 'VM-CDROM':
        current = f"{len(objects)} 台虚拟机挂载 ISO 镜像。"
        expected = ''; remediation = '逐台确认 ISO 用途，断开不再需要的光驱挂载。'
    impact = CUSTOMER_IMPACTS.get(category_id, impact)
    if category_id == 'HOST-MANAGEMENT-SERVICE' and 'ESXi Shell' in management_services:
        impacts = {'SSH': CUSTOMER_IMPACTS[category_id],
                   'ESXi Shell': 'ESXi Shell 本地命令行入口保持开放，需要核对使用必要性和访问权限。'}
        impact = ''.join(impacts[name] for name in management_services)
    if category_id == 'VM-LONG-POWERED-OFF' and note:
        current += note
    steps = operation_steps(category_id, steps, management_services=management_services or ('SSH',))
    # Move the established Word customer wording adapter to the shared
    # boundary. Renderers must not independently rewrite the same evidence.
    from vstacklens.reports.docx_report import DocxReportEngine, RiskGroup
    adapter = DocxReportEngine()

    def clean(value: Any) -> str:
        text = str(value or '')
        restored = {}
        for name in sorted(set(protected_names), key=len, reverse=True):
            if name and name in text:
                token = f'\ue000{len(restored)}\ue001'
                restored[token] = name
                text = text.replace(name, token)
        # The legacy adapter can translate "Limit" into a Chinese phrase;
        # apply approved spacing after that translation as well.
        text = customer_prose(adapter._clean(text))
        for token, name in restored.items():
            text = text.replace(token, name)
        return text

    for obj in objects:
        obj['basis'] = clean(obj['basis'])
        obj['advice'] = [clean(value) for value in obj['advice']]
    current = clean(current)
    expected = clean(expected)
    for prefix in ('期望状态：','期望状态:','期望值：','期望值:', '建议状态：', '建议状态:', '建议：'):
        expected = expected.removeprefix(prefix).lstrip()
    impact = clean(impact)
    remediation = clean(remediation)
    steps = _unique(clean(value) for value in steps)
    step_groups = [{'title': group['title'], 'steps': _unique(clean(value) for value in group['steps'])}
                   for group in step_groups]
    technical = None
    required = {'risk_level','rule_id','rule_name','title','object_type','object_name','status'}
    source_rules = {row.get('rule_id') for row in sources}
    mixed_resource = category_id == 'VM-RESOURCE-CONFIG' and {'VSL-VM-010','VSL-VM-011'} <= source_rules
    unambiguous_names = all(obj['name'] for obj in objects) and len({(obj['object_type'],obj['name']) for obj in objects}) == len(objects)
    unambiguous_assets = all(len(assets_by_name.get((obj['object_type'],obj['name']),[])) <= 1 for obj in objects)
    if projected and not mixed_resource and unambiguous_names and unambiguous_assets and all(required <= row.keys() for row in projected):
        # Reuse the established lossless data adapter, not its Word renderer.
        # It is evaluated once here; all formats receive the identical table.
        from vstacklens.reports.report_model import FindingItem
        findings = [FindingItem(**row) for row in projected]
        group = RiskGroup(category['priority'], adapter._classify_finding(findings[0]), category['title'], findings, findings[0].rule_id)
        table = adapter._legacy_detail_table(report, group)
        if table:
            headers, rows = table
            rows = [[str(cell) if i == 0 or headers[i] == '快照名称' else clean(customer_text(cell))
                     for i, cell in enumerate(row)] for row in rows]
            if category_id == 'VM-LOCAL-DATASTORE' and '影响说明' in headers:
                column = headers.index('影响说明')
                for row in rows:
                    row[column] = CUSTOMER_IMPACTS[category_id]
            if headers == ['对象','当前状态','建议']:
                by_name = {obj['name']:obj for obj in objects}
                for row in rows:
                    basis = (by_name.get(row[0]) or {}).get('basis', '')
                    if basis and basis not in row[1]:
                        row[1] = customer_join_nonempty([row[1], basis], separator='\n')
            visible = [i for i in range(len(headers)) if any(row[i] for row in rows)]
            repeated_advice = {i for i,header in enumerate(headers) if header in {'建议','建议处理','建议动作'} and rows and len({row[i] for row in rows}) == 1}
            visible = [i for i in visible if i not in repeated_advice]
            if visible:
                technical = {'headers':[headers[i] for i in visible], 'rows':[[row[i] for i in visible] for row in rows]}
    table_notes = []
    if category_id == 'HOST-MANAGEMENT-SERVICE' and 'ESXi Shell' in management_services:
        technical = {'headers': ['ESXi 主机', '服务', '运行状态'],
                     'rows': [[obj['name'], name, '正在运行'] for obj in objects
                              for name in services_by_object[(obj['object_type'], str(obj['object_key']))]]}
    if technical:
        by_name = {obj['name']:obj for obj in objects}
        if category_id == 'VM-CDROM':
            for row in technical['rows']:
                obj = by_name.get(row[0])
                asset = assets.get((obj['object_type'], str(obj['object_key'])), {}) if obj else {}
                paths = (asset.get('properties') or {}).get('iso_paths') or []
                if paths:
                    if 'ISO 镜像' not in technical['headers']:
                        technical['headers'].append('ISO 镜像')
                        for target in technical['rows']:target.append('')
                    row[technical['headers'].index('ISO 镜像')] = '；'.join(str(path) for path in paths if path)
        elif category_id == 'VM-SNAPSHOT':
            for row in technical['rows']:
                obj = by_name.get(row[0])
                props = (assets.get((obj['object_type'], str(obj['object_key'])), {}).get('properties') or {}) if obj else {}
                values = []
                age = props.get('snapshot_age_days_max')
                depth = props.get('snapshot_chain_depth')
                if age is not None:values.append(f'最长保留：{age:g} 天' if isinstance(age,(int,float)) and not isinstance(age,bool) else f'最长保留：{age} 天')
                if depth is not None:values.append(f'快照链深度：{depth:g}' if isinstance(depth,(int,float)) and not isinstance(depth,bool) else f'快照链深度：{depth}')
                if values:
                    if '创建时间/存在时长' not in technical['headers']:
                        technical['headers'].append('创建时间/存在时长')
                        for target in technical['rows']:target.append('')
                    column = technical['headers'].index('创建时间/存在时长')
                    row[column] = customer_join_nonempty([row[column], '；'.join(values)], separator='；')
        elif category_id == 'VC-ALARMS' and len(objects) == 1:
            for row in technical['rows']:
                row[0] = customer_join_nonempty([objects[0]['name'], row[0]], separator=' / ')
        # Preserve object-specific restrictions once beside the retained table,
        # instead of repeating a second 91-row object/evidence table in Word.
        advice_groups = {}
        for obj in objects:
            advice = tuple(obj['advice'])
            if advice:advice_groups.setdefault(advice, []).append(obj['name'])
        for advice,names in advice_groups.items():
            table_notes.append('对象处理要求（'+'、'.join(names)+'）：'+'；'.join(advice))
    return {'category_id':category_id, 'level':category['priority'], 'title':adapter._clean(display_title),
            'count':category['affected_object_count'], 'current':current, 'expected':expected,
            'impact':impact, 'remediation':remediation, 'steps':steps, 'objects':objects, 'technical':technical,
            'step_groups':step_groups, 'current_label':'当前值', 'expected_label':'判定标准', 'basis_label':'判断依据',
            'table_notes':table_notes, 'summary_text':customer_problem_summary(current, impact, remediation)}


def shared_passed_checks(report, checklist: list[dict], vsan_summary: dict) -> list[dict[str, Any]]:
    """Filter saved grades and denied rules; never infer a grade from a title."""
    from vstacklens.reports.customer_caliber import DENIED_RULES, rule_grade, approved_result_projection
    checklist = approved_result_projection(report).get('rule_checklist') or []
    output = []
    for item in checklist:
        if item.get('rule_id') in DENIED_RULES or rule_grade(item) not in {'P1','P2','P3'}:
            continue
        if not item.get('passed') or any(item.get(key) for key in ('failed','error','unavailable')):
            continue
        label = customer_text(item.get('rule_name'))
        if label:
            output.append({'rule_id':item['rule_id'],'label':label,'level':rule_grade(item),'kind':'executed','display_status':'正常'})
    for item in vsan_summary.get('report_categories', []) or []:
        level = item.get('priority') or item.get('risk_level')
        rule_ids = item.get('source_rule_ids') or []
        if item.get('status') != '正常' or level not in {'P1','P2','P3'} or any(x in DENIED_RULES for x in rule_ids):
            continue
        label = customer_text(item.get('check_name') or item.get('title') or item.get('name'))
        if item.get('category_id') == 'VSAN-NETWORK':
            label = 'vSAN VMkernel 配置核对'
        if label:
            output.append({'rule_id':item.get('category_id') or (rule_ids[0] if rule_ids else label),'label':label,'level':level,'kind':'derived',
                           'display_status':'接口配置已核对' if item.get('category_id') == 'VSAN-NETWORK' else '正常'})
    seen = set(); result = []
    for item in output:
        if item['label'] not in seen:
            seen.add(item['label']);result.append(item)
    return result


def customer_vsan_summary(report) -> dict:
    """Select only saved vSAN-tagged adapters; never assert connectivity."""
    summary = deepcopy(report.vsan_summary or {})
    allowed = {}
    for host in (report.asset_inventory.get('details') or {}).get('HostSystem', []):
        properties = host.get('properties') or {}
        allowed[host.get('object_name')] = {
            str(adapter.get('device') or adapter.get('name') or '')
            for adapter in properties.get('vsan_vmk_adapters', []) or [] if isinstance(adapter, dict)
        }
    network = dict(summary.get('network') or {})
    network['vmkernels'] = [adapter for adapter in network.get('vmkernels', []) or []
                           if str(adapter.get('device') or '') in allowed.get(adapter.get('host_name') or adapter.get('host'), set())]
    summary['network'] = network
    return summary


def public_customer_caliber(caliber: dict) -> dict:
    """Customer counts only; internal run identity and collection failures stay internal."""
    result = {key:deepcopy(caliber[key]) for key in ('version','counts','problem_count','affected_counts','affected_total') if key in caliber}
    if 'counts' in result:
        result['counts'] = {key:value for key,value in result['counts'].items() if key in {'P1','P2','P3'}}
    return result


def customer_environment_name(value: Any) -> str:
    text = str(value or '').strip()
    if text in {'普通VC标准巡检性能核对','VC vSAN 标准巡检性能核对'}:
        return ''
    return text


def group_legacy_html_findings(findings: list[dict[str, Any]], label: Callable[[Any], str]) -> dict:
    """Keep the existing HTML projection intact until step-one parity is approved.

    This temporary adapter lives in the common input layer so renderers no
    longer select problem membership. Step two replaces legacy copy together.
    """
    if any(not item.get('category_id') for item in findings):
        from vstacklens.reports.customer_caliber import calculate
        findings = projected_findings(calculate(findings))
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for item in findings:
        level = str(item.get('category_priority') or item.get('risk_level') or '').upper()
        title = label(item.get('title') or '')
        if item.get('rule_id') == 'VSL-VM-002' and title == '虚拟机未安装 VMware Tools':
            title = '虚拟机 VMware Tools 未运行'
        if level not in {'P1', 'P2', 'P3'} or not title:
            continue
        key = (str(item.get('category_id') or item.get('rule_id') or ''), level, title)
        groups.setdefault(key, []).append(item)
    return groups
