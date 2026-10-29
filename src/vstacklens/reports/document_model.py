"""One read-only customer document: content, ordering, sampling and references.

No renderer decides membership or re-evaluates an inspection.  The PDF consumes
``sections``; Word and HTML additionally consume the same complete appendices.
"""
from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
import hashlib
import json
import math
import re
from typing import Any

from vstacklens.reports.customer_format import CAPACITY_NOTE, capacity_text, capacity_bytes_text, decimal_text, local_time_text, percent_text
from vstacklens.reports.customer_view import get_customer_problem_view, customer_display_facts, shared_passed_checks, customer_text
from vstacklens.reports.presentation import customer_check_statistics, delivery_overview

COLORS = {'P1': '#B3261E', 'P2': '#A15C07', 'P3': '#3F6688'}
NAVY = '#163B63'
INK = '#24364A'
NEUTRAL = '#64748B'
LEVELS = {'P1': 0, 'P2': 1, 'P3': 2}
SECTION_ORDER = ('opening', 'overview', 'problems', 'passed', 'environment', 'appendices')
_EMPTY = {'', '—', '未采集', '不可用', '不适用', '未确认', '待确认', 'None', 'unknown', 'unavailable'}


def _text(value: Any) -> str:
    if value is None:
        return ''
    if isinstance(value, bool):
        return '是' if value else '否'
    return str(value)


def _number(value: Any) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) else None


def _plain(value: Any) -> str:
    return _text(value).replace('\u200b', '')


def _alpha(number: int) -> str:
    value = ''
    while number:
        number, digit = divmod(number - 1, 26)
        value = chr(65 + digit) + value
    return value


def _token(*parts: Any) -> str:
    return hashlib.sha256(json.dumps(parts, ensure_ascii=False, default=str).encode()).hexdigest()[:20]


def _entry(key: str, name: str, cells: list[Any], cluster='', host='', category='', level='', **extra) -> dict:
    return {'id': _token(key, category), 'key': key, 'name': name, 'cells': [_text(v) for v in cells],
            'cluster': cluster or '平台 / 共享', 'host': host or '平台 / 共享', 'category': category,
            'level': level, **extra}


def _table(table_id: str, title: str, headers: list[str], rows: list[dict], *, role='objects', notes=None, **extra) -> dict | None:
    if not rows:
        return None
    # Zero and False are data. Entirely absent metrics are not columns.
    visible = [i for i in range(len(headers)) if any(i < len(r['cells']) and r['cells'][i].strip() not in _EMPTY for r in rows)]
    if not visible:
        return None
    selected_headers = [headers[i] for i in visible]
    weights = [4 if h in {'资源状态','保护与版本配置'} else 3 if h in {'硬件信息','集群 / 主机','网络'} else
               2 if h in {'IP','交换机'} else
               5 if '明细' in h else 3 if any(s in h for s in ('路径', '快照名称', '创建时间', '日期来源', '涉及的问题')) else
               2 if any(s in h for s in ('名称', '虚拟机', '主机', '集群', '设备', '数据存储')) else 1 for h in selected_headers]
    if table_id=='licenses':
        weights=[3 if header=='对象' else weight for header,weight in zip(selected_headers,weights)]
    for column,source_index in enumerate(visible):
        length=max(len(r['cells'][source_index]) for r in rows)
        if selected_headers[column]=='主机' and length>24:
            weights[column]=max(weights[column],4)
        if selected_headers[column] in {'数据存储','集群'} and length>24:
            weights[column]=max(weights[column],3)
        if selected_headers[column]=='集群 / 主机' and length>40:
            weights[column]=max(weights[column],5)
        if any(key in selected_headers[column] for key in ('名称','虚拟机','路径')) and length>120:
            weights[column]=max(weights[column],5)
    return {'id': table_id, 'title': title, 'kind': 'table', 'role': role,
            'headers': selected_headers, 'weights': weights,
            'rows': [{**r, 'id': _token(table_id,r['id']), 'cells': [r['cells'][i] if i < len(r['cells']) else '' for i in visible]} for r in rows],
            'total': len(rows), 'notes': [n for n in notes or [] if n], **extra}


def select_representatives(category_id: str, objects: list[dict], assets: dict) -> tuple[list[dict], str]:
    def properties(obj):
        return (assets.get((obj.get('object_type'), str(obj.get('object_key'))), {}).get('properties') or {})
    def stable(obj):
        return (str(obj.get('name') or ''), str(obj.get('object_key') or ''))
    if category_id == 'VM-SNAPSHOT':
        key = lambda obj: (-(_number(properties(obj).get('snapshot_age_days_max')) or 0), *stable(obj))
        rule = '最长快照保留天数降序；同值按名称、稳定身份'
    elif category_id in {'VM-LONG-POWERED-OFF', 'VM-LOCAL-DATASTORE'}:
        key = lambda obj: (str(obj.get('cluster') or ''), str(obj.get('host') or ''), *stable(obj))
        rule = '集群、主机、名称、稳定身份'
    elif category_id == 'VM-RESOURCE-CONFIG':
        def key(obj):
            p = properties(obj)
            reserved = any((_number(p.get(k)) or 0) > 0 for k in ('cpu_reservation_mhz', 'memory_reservation_mb'))
            return (0 if reserved else 1, *stable(obj))
        rule = '预留在前、资源限制在后；各组按名称、稳定身份'
    elif category_id == 'HOST-RESOURCE-ALLOCATION':
        key = lambda obj: (-max(_number(properties(obj).get('host_vcpu_to_pcpu_ratio')) or _number(properties(obj).get('vcpu_pcpu_ratio')) or 0,
                                _number(properties(obj).get('host_memory_allocation_ratio')) or _number(properties(obj).get('memory_allocation_ratio')) or 0), *stable(obj))
        rule = '分配比值降序；同值按名称、稳定身份'
    else:
        key = stable
        rule = '名称、稳定身份'
    return sorted(objects, key=key)[:5], rule


def get_document(report, context: dict | None = None) -> dict:
    """Return an independent copy, keyed by saved evidence and scope identity."""
    context = context or {}
    fingerprint = _source_fingerprint(report,context)
    cached = report._document_view_cache
    if cached is not None and cached[0] == fingerprint:
        return deepcopy(cached[1])
    from vstacklens.reports.customer_caliber import document_projection_scope
    working=report.model_copy(deep=False)
    working.risk_summary=report.risk_summary.model_copy(deep=True)
    working.health_score=report.health_score.model_copy(deep=True)
    working.report_presentation=dict(report.report_presentation)
    with document_projection_scope(working,context):
        view = get_customer_problem_view(working, context)
        document = _build_document(working, context, view)
    if _source_fingerprint(report,context)!=fingerprint:
        raise RuntimeError('报告源数据在生成期间发生变化，请重新生成。')
    report._document_view_cache = (fingerprint, deepcopy(document))
    return document


def _source_fingerprint(report,context):
    """Content identity without a second in-memory copy of a large run."""
    inputs=report.caliber_inputs or {}
    identity=[report.report_info.model_dump(),report.customer_info.model_dump(),report.asset_inventory,
              report.vsan_summary,report.appendix,inputs,
              [row.model_dump() for row in report.findings],report.environment_summary.model_dump(),
              {key:context.get(key) for key in ('object_results','findings','rule_checklist','history_comparison') if key not in inputs and key not in report.appendix}]
    if (report.customer_caliber.get('judgment_provenance') or {}).get('mode')=='EXPLICIT_REINTERPRETATION':
        identity.append(report.customer_caliber)
    encoder=json.JSONEncoder(ensure_ascii=False,sort_keys=True,default=str)
    digest=hashlib.sha256()
    for part in encoder.iterencode(identity):digest.update(part.encode('utf-8'))
    return digest.hexdigest()


def _build_document(report, context, view) -> dict:
    # Mature, lossless field adaptation is reused once. It does not render or
    # choose any section in this document; all layout selection follows below.
    from vstacklens.reports.pdf_report import PdfReportEngine
    legacy = PdfReportEngine()._build_payload(report, context, _allow_connection_diagnostic=True)
    facts = customer_display_facts(report)
    stats = customer_check_statistics(report, context)
    if stats['total']==0:
        stats={**stats,'text':''} # Unknown / unavailable results are not verified zero checks.
    passed = shared_passed_checks(report, context.get('rule_checklist') or report.appendix.get('rule_checklist', []), report.vsan_summary)
    raw = report.asset_inventory.get('details') or {}
    clusters = raw.get('ClusterComputeResource') or []
    hosts = raw.get('HostSystem') or []
    vms = raw.get('VirtualMachine') or []
    stores = raw.get('Datastore') or []
    from vstacklens.reports.customer_caliber import object_key
    candidates=defaultdict(list)
    for kind,items in raw.items():
        for row in items:candidates[object_key({**row,'object_type':kind})].append(row)
    # The established key normalizer also supports legacy saved records. A
    # duplicate legacy identity is not guessed from its display name.
    assets={key:items[0] for key,items in candidates.items() if len(items)==1}
    cluster_names = {r.get('object_name') for r in clusters if r.get('object_name')}
    host_names = {r.get('object_name') for r in hosts if r.get('object_name')}
    def direct_cluster(row):
        p = row.get('properties') or {}
        explicit = p.get('cluster_name') or row.get('cluster')
        if explicit in cluster_names:
            return explicit
        recorded = [n for n in p.get('datastore_cluster_names') or [] if n in cluster_names]
        if len(recorded)==1:
            return recorded[0]
        parts = [s.strip() for s in str(row.get('asset_location') or row.get('object_path') or p.get('asset_location') or '').split('/')]
        found = [n for n in cluster_names if n in parts]
        return found[0] if len(found) == 1 else ''
    host_clusters = {r.get('object_name'): direct_cluster(r) for r in hosts}
    def placement(row):
        p = row.get('properties') or {}
        host = p.get('host_name') or (row.get('object_name') if row.get('object_type') == 'HostSystem' else '')
        return direct_cluster(row) or host_clusters.get(host, ''), host or ''
    def asset_for(obj):
        return assets.get((obj.get('object_type'), str(obj.get('object_key'))), {})
    def row_id(row, suffix=''):
        return str(row.get('object_key') or _token(row.get('object_name'), row.get('asset_location'))) + suffix
    def locate(row):
        c, h = placement(row)
        return ' / '.join(dict.fromkeys(s for s in (c, h) if s))
    def state(value):
        if value is None or _text(value) in _EMPTY:
            return ''
        return {'poweredOn': '运行', 'poweredOff': '关机', 'suspended': '挂起', 'connected': '已连接',
                'disconnected': '已断开', 'notResponding': '未响应', 'up': '已连接', 'down': '已断开',
                'normal': '正常', 'healthy': '正常', 'green': '正常', 'red': '异常', 'yellow': '需关注',
                'error':'异常','failed':'异常','degraded':'降级','absent':'缺失','offline':'离线','warning':'需关注',
                'capacity': '容量盘', 'cache': '缓存盘'}.get(_text(value), customer_text(value))
    def cell_entry(row, cells, category='环境明细', suffix=''):
        c, h = placement(row)
        return _entry(row_id(row, suffix), row.get('object_name', ''), cells, c, h, category)
    def metric(value, unit=''):
        n = _number(value)
        return (f'{n:g}' + (f' {unit}' if unit else '')) if n is not None else ''
    def committed(p):
        if _number(p.get('storage_committed_bytes')) is not None:
            return capacity_bytes_text(p['storage_committed_bytes'])
        for field in ('storage_committed_gb', 'committed_gb', 'disk_used_gb'):
            if _number(p.get(field)) is not None:
                return capacity_text(p[field])
        return ''

    categories = [deepcopy(x.display) for x in view.categories]
    categories.sort(key=lambda r: (LEVELS.get(r['level'], 9), r['title']))
    known_vsan = bool((legacy.get('vsan') or {}).get('enabled'))
    esa = any(str((r.get('properties') or {}).get('vsan_architecture', '')).upper() == 'ESA' for r in stores)
    if not known_vsan:
        passed = [r for r in passed if 'vsan' not in r['label'].lower()]
    if esa:
        passed = [r for r in passed if '磁盘组' not in r['label']]
    from vstacklens.reports.customer_view import customer_environment_name
    doc = {'version': '4', 'title': customer_environment_name(report.report_info.report_title.strip()) or 'VStackLens 虚拟化巡检报告',
           'customer': report.customer_info.customer_name, 'target': report.customer_info.vcenter,
           'date': local_time_text(report.report_info.generated_at), 'colors': dict(COLORS),
           'navy': NAVY, 'ink': INK, 'neutral': NEUTRAL,
           'counts': {'categories': len(categories), 'objects': view.caliber['affected_total'],
                      'records': sum(x.category['finding_count'] for x in view.categories),
                      'levels': {k: sum(c['level'] == k for c in categories) for k in LEVELS}},
           'statistics': {k: stats[k] for k in ('total', 'passed', 'failed', 'text', 'available')},
           'passed_count': len(passed), 'vsan': known_vsan, 'esa': esa,
           'labels': {'level':'等级','current':'当前值','expected':'判定标准','impact':'影响','remediation':'处理建议'},
           'sections': [], 'appendices': [], 'sorting_rules': {}, 'decisions': []}
    if doc['customer'] in {'未指定客户','默认客户'}:doc['customer']=''
    doc['date_label']='巡检日期：'+doc['date'] if doc['date'] else ''
    doc['header_identity']=doc['title'] if doc['customer'] and doc['title'].startswith(doc['customer']) else ' · '.join(x for x in (doc['customer'],doc['title']) if x)
    def register(table):
        if table is None:
            return None
        table = deepcopy(table)
        table['letter'] = _alpha(len(doc['appendices']) + 1)
        table['anchor'] = 'appendix-' + table['letter']
        doc['appendices'].append(table)
        return table
    index = {r['object_name']: {'categories': set(), 'keys': set()} for r in clusters}
    for category in categories:
        for obj in category['objects']:
            a = asset_for(obj)
            c, _ = placement(a)
            if obj.get('object_type') == 'ClusterComputeResource':
                c = obj['name']
            value = index.setdefault(c or '平台 / 共享', {'categories': set(), 'keys': set()})
            value['categories'].add(category['title'])
            value['keys'].add((obj['object_type'], str(obj['object_key'])))
    index_rows = [_entry('cluster-index:' + n, n, [n, '、'.join(sorted(v['categories'])), len(v['keys'])], n, category='问题索引')
                  for n, v in sorted(index.items())]
    register(_table('cluster-index', '按集群汇总', ['集群', '涉及的问题类别', '对象数'], index_rows))

    problem_nodes = []
    for category in categories:
        category_id = category['category_id']
        from vstacklens.reports.customer_caliber import object_key
        source_entry=next(entry for entry in view.categories if entry.display['category_id']==category_id)
        def object_properties(obj):
            props=dict(asset_for(obj).get('properties') or {})
            fallback_snapshots='snapshots' not in props or props['snapshots'] is None
            snapshot_records=[]
            for source in source_entry.source_findings:
                if object_key(source)!=(obj['object_type'],str(obj['object_key'])):
                    continue
                for detail in (source.get('observed_detail'),source.get('evidence')):
                    if not isinstance(detail,dict):continue
                    if fallback_snapshots:
                        for item in detail.get('snapshots') or []:
                            if isinstance(item,dict) and item not in snapshot_records:snapshot_records.append(deepcopy(item))
                    for key,value in detail.items():
                        if key not in props and value is not None:props[key]=value
            if fallback_snapshots and snapshot_records:props['snapshots']=snapshot_records
            if props.get('snapshots'):
                props['snapshots']=[{**s,'name':s.get('name') or s.get('snapshot_name') or '',
                                     'create_time':s.get('create_time') or s.get('created_at')}
                                    for s in props['snapshots'] if isinstance(s,dict)]
            return props
        objects = [{**o, 'cluster': placement(asset_for(o))[0], 'host': placement(asset_for(o))[1]} for o in category['objects']]
        def problem_cells(obj, full):
            a = asset_for(obj)
            p = object_properties(obj)
            identity = [obj['name'], placement(a)[0] if obj['object_type']=='HostSystem' else locate(a)]
            if category_id == 'VM-SNAPSHOT':
                snaps = p.get('snapshots') or []
                values = [metric(p.get('snapshot_age_days_max'), '天'), metric(p.get('snapshot_chain_depth'))]
                if full:
                    values += ['\n'.join(str(s.get('name') or '') for s in snaps),
                               '\n'.join(local_time_text(s.get('create_time')) for s in snaps)]
                return identity + values
            if category_id == 'VM-CDROM':
                return identity + ['\n'.join(dict.fromkeys(str(s) for s in p.get('iso_paths') or [] if s))]
            if category_id == 'VM-RESOURCE-CONFIG':
                return identity + ['无限制' if 'limit' in k and p.get(k)==-1 else metric(p.get(k), u)
                                   for k, u in [('cpu_reservation_mhz','MHz'),('memory_reservation_mb','MB'),('cpu_limit_mhz','MHz'),('memory_limit_mb','MB')]]
            if category_id == 'HOST-RESOURCE-ALLOCATION':
                cpu=p.get('host_vcpu_to_pcpu_ratio',p.get('vcpu_pcpu_ratio'))
                memory=p.get('host_memory_allocation_ratio',p.get('memory_allocation_ratio'))
                return identity + [decimal_text(cpu,2)+':1' if _number(cpu) is not None else '',
                                   percent_text(float(memory)*100) if _number(memory) is not None else '']
            if category_id == 'VM-LONG-POWERED-OFF':
                return identity + [committed(p), metric(p.get('powered_off_days'), '天')]
            if category_id == 'VM-LOCAL-DATASTORE':
                local = p.get('local_datastore_names') or [name for name in p.get('datastore_names') or [] if any(
                    s.get('object_name') == name and (s.get('properties') or {}).get('is_local') is True for s in stores)]
                return identity + ['、'.join(local), committed(p)]
            if category_id in {'CLUSTER-HA', 'CLUSTER-DRS'}:
                label = 'vSphere HA' if category_id == 'CLUSTER-HA' else 'DRS'
                return identity + [label + ' 未启用']
            if category_id == 'HOST-MANAGEMENT-SERVICE':
                names = []
                if p.get('ssh_running') is True:
                    names.append('SSH 正在运行')
                if p.get('esxi_shell_running') is True:
                    names.append('ESXi Shell 正在运行')
                return identity + ['；'.join(names)]
            if category_id == 'VC-ALARMS':
                evidence = next((entry.source_findings for entry in view.categories if entry.display['category_id']==category_id), ())
                alarms = [a for record in evidence for a in (record.get('observed_detail') or {}).get('active_red_alarms', [])]
                return identity + ['\n'.join(' / '.join(str(a.get(k) or '') for k in ('alarm_name','entity_name')) for a in alarms)]
            if category_id == 'HOST-CONNECTION':
                return identity + [state(p.get('connection_state'))]
            if category_id == 'CLUSTER-MAINTENANCE-MODE':
                members = [h['object_name'] for h in hosts if placement(h)[0]==obj['name'] and
                           ((h.get('properties') or {}).get('maintenance_mode') is True or (h.get('properties') or {}).get('in_maintenance_mode') is True)]
                return identity + ['、'.join(members)]
            if category_id == 'VSAN-CAPACITY':
                return identity + [percent_text((legacy.get('vsan') or {}).get('used_percent'))]
            candidates = {'HOST-CERTIFICATE':[('host_certificate_days_remaining','天')],
                          'VC-CERTIFICATE':[('certificate_days_remaining','天')],
                          'DS-CAPACITY':[('used_percent','%')], 'HOST-CPU':[('cpu_usage_avg','%')],
                          'VM-CPU-READY':[('cpu_ready_percent','%')]}.get(category_id, [])
            values = [percent_text(p[k]) if u == '%' else metric(p[k], u) for k,u in candidates if _number(p.get(k)) is not None]
            saved=[r for r in source_entry.source_findings if object_key(r)==(obj['object_type'],str(obj['object_key']))]
            if not values and candidates:
                unit=candidates[0][1]
                values=[percent_text(r['current_value']) if unit=='%' else metric(r['current_value'],unit)
                        for r in saved if _number(r.get('current_value')) is not None]
            # Existing shared adapter provides the known current value where no
            # inventory scalar exists. It is evidence, never a new judgement.
            if not values:
                basis=customer_text(obj.get('basis'))
                values = ['\n'.join(line for line in basis.splitlines() if not any(term in line for term in ('建议状态为','当前状态为','当前值为')))]
            return identity + ['；'.join(v for v in values if v)]
        headers = {
            'VM-SNAPSHOT': ['对象名称', '集群 / 主机', '最长快照保留', '链深度', '快照名称', '创建时间'],
            'VM-CDROM': ['虚拟机', '集群 / 主机', 'ISO 路径'],
            'VM-RESOURCE-CONFIG': ['虚拟机', '集群 / 主机', 'CPU 预留', '内存预留', 'CPU 限制', '内存限制'],
            'HOST-RESOURCE-ALLOCATION': ['主机', '集群', 'vCPU:pCPU', '内存分配比例'],
            'VM-CPU-READY': ['对象名称','集群 / 主机','CPU 调度等待（CPU Ready）'],
            'VM-LONG-POWERED-OFF': ['虚拟机', '集群 / 主机', '已占用存储', '关机时长'],
            'VM-LOCAL-DATASTORE': ['虚拟机', '集群 / 主机', '本地数据存储', '已占用存储'],
        }.get(category_id, ['对象名称', '集群 / 主机', '关键值'])
        rows = [_entry(str(o['object_key']), o['name'], problem_cells(o, True), o['cluster'], o['host'], category['title'], o['level']) for o in objects]
        full_headers=list(headers)
        technical=category.get('technical') or {}
        if technical.get('headers') and technical.get('rows'):
            # Reuse the already validated saved-evidence adapter. Keep its key
            # observations in this one appendix, never a second technical list.
            by_name=defaultdict(list)
            for position,obj in enumerate(objects):by_name[_plain(obj['name'])].append(position)
            captured=defaultdict(lambda:defaultdict(list));record_lines=defaultdict(list)
            for values in technical['rows']:
                if not values:continue
                positions=by_name.get(_plain(values[0]),[])
                identified=len(positions)==1
                if not identified and len(objects)==1:positions=[0]
                if len(positions)!=1:continue
                record_parts=[]
                for column,header in enumerate(technical['headers']):
                    if column>=len(values) or (column==0 and identified):continue
                    if any(word in header for word in ('建议','影响说明','判断依据','期望','建议状态')) and '限制' not in header and header!='判断与建议':continue
                    if not any(word in header for word in ('对象','Object','VMDK','设备','网卡','交换机','绑定','速率','双工','链路','磁盘','组件',
                        '快照','创建','保留','CPU','内存','存储','Datastore','电源','状态','时间','配置','指标','计数','告警','名称','当前','记录','范围','集群','主机','路径',
                        'Health','说明','限制','判断与建议','授权','许可','期限','到期','剩余')):continue
                    value=_plain(values[column])
                    if not value or value in _EMPTY or any(term in value for term in ('未采集','不可用','未确认','待确认')):continue
                    if any(term in value for term in ('建议状态为','当前状态为','当前值为')):continue
                    if value.startswith('当前：') and '；建议：' in value:continue
                    if value in {'True','False'}:
                        value=({'True':'已应答','False':'尚未应答'} if header=='确认状态' else {'True':'是','False':'否'})[value]
                    if value in {'up','down','poweredOn','poweredOff','connected','disconnected','normal','healthy','green','red','yellow'}:value=state(value)
                    record_parts.append(f'{"记录说明" if header=="判断与建议" else header}：{value}')
                    if value not in captured[header][positions[0]]:captured[header][positions[0]].append(value)
                line='；'.join(record_parts)
                if line and line not in record_lines[positions[0]]:record_lines[positions[0]].append(line)
            multi_records=any(len(lines)>1 for lines in record_lines.values())
            snapshot_has_structured=category_id=='VM-SNAPSHOT' and all(object_properties(o).get('snapshots') for o in objects)
            if multi_records and not snapshot_has_structured:
                detail_label='网卡明细' if any('网卡' in h for h in technical['headers']) else '磁盘明细' if any('磁盘' in h for h in technical['headers']) else '对象明细'
                full_headers.append(detail_label)
                for position,row in enumerate(rows):row['cells'].append('\n'.join(record_lines.get(position,[])))
                captured={}
            elif snapshot_has_structured:
                captured={}
            aliases={'ISO 镜像':'ISO 路径','创建时间/存在时长':'创建时间','当前电源状态':'电源状态','所属集群':'集群 / 主机','Health':'健康状态','判断与建议':'记录说明','说明':'记录说明',
                     '所属主机或集群':'集群 / 主机','Datastore':'本地数据存储'}
            for header,positions in captured.items():
                name=aliases.get(header,header)
                if name in full_headers:
                    column=full_headers.index(name)
                    for position,values in positions.items():
                        if not rows[position]['cells'][column]:rows[position]['cells'][column]='\n'.join(values)
                    continue
                if all(all(value in '\n'.join(rows[position]['cells']) for value in values) for position,values in positions.items()):continue
                flattened={value for values in positions.values() for value in values}
                if len(flattened)==1 and next(iter(flattened)) in category['current']:continue
                full_headers.append(name)
                for position,row in enumerate(rows):row['cells'].append('\n'.join(positions.get(position,[])))
        notes = list(dict.fromkeys(note for o in objects for note in o.get('advice') or []))
        complete = register(_table('problem-' + category_id, category['title'], full_headers, rows, notes=notes))
        representatives, ordering = select_representatives(category_id, objects, assets)
        doc['sorting_rules'][category_id] = ordering
        shown_headers = headers[:4] if category_id == 'VM-SNAPSHOT' else headers
        reps = [_entry(str(o['object_key']), o['name'], problem_cells(o, False), o['cluster'], o['host'], category['title'], o['level']) for o in representatives]
        iso_groups = []
        if category_id == 'VM-CDROM':
            files = defaultdict(set)
            for o in objects:
                for path in object_properties(o).get('iso_paths') or []:
                    if path:
                        files[str(path)].add(str(o['object_key']))
            ordered = sorted(files.items(), key=lambda r: (-len(r[1]), r[0]))
            iso_groups = [{'path': path, 'file': re.split(r'[/\\]', path)[-1], 'count': len(keys), 'keys': sorted(keys)} for path, keys in ordered]
            reps = [_entry(path, path, [re.split(r'[/\\]', path)[-1], len(keys)], category=category['title']) for path, keys in ordered[:5]]
            shown_headers = ['ISO 文件', '挂载台数']
            ordering = 'ISO 文件挂载台数降序；同值按完整文件路径'
            doc['sorting_rules'][category_id] = ordering
        shown = _table('representative-' + category_id, '代表对象' if not iso_groups else 'ISO 文件汇总', shown_headers, reps)
        count = len(objects)
        unit = {'HostSystem':'台主机', 'VirtualMachine':'台虚拟机', 'ClusterComputeResource':'个集群', 'Datastore':'个数据存储'}.get(objects[0]['object_type'] if objects else '', '个对象')
        reference = ''
        if complete and count > 5:
            if category_id == 'VM-CDROM':
                reference = f'共 {count} {unit}，完整列表见 Word / HTML 报告附录 {complete["letter"]}。'
                if len(iso_groups) > 5:
                    reference = f'另有 {len(iso_groups)-5} 个 ISO 文件。' + reference
            else:
                reference = f'共 {count} {unit}，其余 {count-len(representatives)} {unit}见 Word / HTML 报告附录 {complete["letter"]}。'
        problem_nodes.append({'id': category_id, 'title': category['title'], 'level': category['level'],
                              'current': category['current'], 'expected': category['expected'], 'impact': category['impact'],
                              'remediation': category['remediation'], 'steps': category['steps'], 'step_groups': category.get('step_groups') or [],
                              'representative_table': shown, 'representative_keys': [str(o['object_key']) for o in representatives],
                              'objects': count, 'remaining': max(0,count-len(representatives)), 'unit': unit,
                              'iso_groups': iso_groups, 'reference': reference, 'appendix': complete['letter'] if complete else '',
                              'object_notes': notes})
        problem_nodes[-1]['fields']=[{'key':key,'label':doc['labels'][key],'text':category[key]}
                                    for key in ('current','expected','impact','remediation') if category[key]]
        problem_nodes[-1]['render_groups']=[g for g in (category.get('step_groups') or [{'title':'','steps':category['steps']}]) if g.get('steps')]

    # Environment: one full inventory, not repeated under every cluster.
    cluster_rows = []
    for c in sorted(clusters, key=lambda r: str(r.get('object_name'))):
        p = c.get('properties') or {}
        name = c['object_name']
        cluster_rows.append(cell_entry(c, [name, sum(placement(h)[0]==name for h in hosts), sum(placement(v)[0]==name for v in vms),
                             '已启用' if p.get('ha_enabled') is True else '未启用' if p.get('ha_enabled') is False else '',
                             '已启用' if p.get('drs_enabled') is True else '未启用' if p.get('drs_enabled') is False else '']))
    cluster_full = register(_table('clusters', '集群完整清单', ['集群','主机数','虚拟机数','HA','DRS'], cluster_rows))
    cluster_details={_plain(v['name']):v for v in legacy.get('cluster_details') or []}
    if cluster_full:
        cluster_full['headers'].append('保护与版本配置');cluster_full['weights'].append(4)
        for row in cluster_full['rows']:
            v=cluster_details.get(row['name'],{})
            values=[('HA 准入控制',v.get('admission_control')),('HA 心跳数据存储',v.get('heartbeat_summary')),
                    ('DRS 模式',v.get('drs_behavior')),('EVC',v.get('evc_enabled')),('EVC 模式',v.get('evc_mode')),
                    ('vMotion 已启用主机',metric(v.get('vmotion_enabled_hosts'),'台')),('CPU 型号',v.get('cpu_models'))]
            row['cells'].append('\n'.join(f'{label}：{value}' for label,value in values if value not in (None,'')))
    hosts_legacy = {_plain(r['name']): r for r in legacy.get('host_details') or []}
    host_rows = []
    for a in sorted(hosts, key=lambda r: str(r.get('object_name'))):
        p, v = a.get('properties') or {}, hosts_legacy.get(a.get('object_name'), {})
        resource=[('CPU 使用率',percent_text(v.get('cpu_pct'))),('内存使用率',percent_text(v.get('memory_pct'))),
                  ('物理 CPU',metric(v.get('cpu_cores'),'核')),('已分配 vCPU',metric(v.get('allocated_vcpu'))),
                  ('vCPU:pCPU',decimal_text(v['vcpu_pcpu_ratio'],2)+':1' if _number(v.get('vcpu_pcpu_ratio')) is not None else ''),
                  ('内存容量',capacity_text(v.get('memory_capacity_gb'))),('内存分配',capacity_text(v.get('memory_allocated_gb'))),
                  ('内存分配比例',percent_text(v.get('memory_allocation_pct')))]
        hardware=[('CPU 型号',p.get('cpu_model') or p.get('cpu_model_name') or p.get('host_cpu_model')),('硬件异常',metric(v.get('hardware_issue_count'),'项')),
                  ('异常明细',v.get('hardware_issue_summary'))]
        host_rows.append(cell_entry(a,[a['object_name'],placement(a)[0],p.get('version') or p.get('esxi_version'),
                       v.get('connection') or state(p.get('connection_state')),
                       '\n'.join(f'{k}：{x}' for k,x in resource if x), '\n'.join(f'{k}：{x}' for k,x in hardware if x)]))
    host_full = register(_table('hosts','主机完整清单',['主机','集群','版本','连接状态','资源状态','硬件信息'],host_rows))
    vm_rows=[]
    for a in sorted(vms,key=lambda r:str(r.get('object_name'))):
        p=a.get('properties') or {}
        disks=p.get('vmdk_inventory');disk_capacity=''
        if isinstance(disks,list) and all(isinstance(d,dict) and _number(d.get('capacity_bytes')) is not None for d in disks):
            disk_capacity=capacity_bytes_text(sum(d['capacity_bytes'] for d in disks))
        vm_rows.append(cell_entry(a,[a['object_name'],locate(a),state(p.get('power_state')),metric(p.get('vcpu_count') if p.get('vcpu_count') is not None else p.get('num_cpu')),
                                    disk_capacity,committed(p)]))
    register(_table('vms','虚拟机完整清单',['虚拟机','集群 / 主机','电源状态','vCPU','虚拟磁盘容量','已占用存储'],vm_rows))
    store_rows=[]
    for a in sorted(stores,key=lambda r:str(r.get('object_name'))):
        p=a.get('properties') or {}
        store_rows.append(cell_entry(a,[a['object_name'],'、'.join(p.get('datastore_cluster_names') or []),p.get('datastore_type'),capacity_text(p.get('datastore_capacity_gb')),
                         capacity_text(p.get('datastore_used_gb')),capacity_text(p.get('datastore_free_gb')),percent_text(p.get('used_percent'))]))
    store_full=register(_table('stores','数据存储完整清单',['数据存储','集群','类型','总容量','已用容量','可用容量','使用率'],store_rows))
    snapshot_problem_keys={str(o['object_key']) for c in categories if c['category_id']=='VM-SNAPSHOT' for o in c['objects']}
    supplemental=[]
    for a in vms:
        p=a.get('properties') or {}; snaps=p.get('snapshots') or []
        if snaps and str(a.get('object_key')) not in snapshot_problem_keys:
            supplemental.append(cell_entry(a,[a['object_name'],locate(a),'\n'.join(str(s.get('name') or s.get('snapshot_name') or '') for s in snaps),
                                '\n'.join(local_time_text(s.get('create_time') or s.get('created_at')) for s in snaps),metric(p.get('snapshot_age_days_max'),'天')]))
    register(_table('other-snapshots','其他快照资产',['虚拟机','集群 / 主机','快照名称','创建时间','最长保留'],supplemental))
    iso_problem_keys={str(o['object_key']) for c in categories if c['category_id']=='VM-CDROM' for o in c['objects']}
    other_iso=[cell_entry(a,[a['object_name'],locate(a),'\n'.join(str(path) for path in (a.get('properties') or {}).get('iso_paths') or [])])
               for a in vms if str(a.get('object_key')) not in iso_problem_keys and (a.get('properties') or {}).get('iso_paths')]
    register(_table('other-iso','其他 ISO 配置',['虚拟机','集群 / 主机','ISO 路径'],other_iso))
    network=legacy.get('network') or {}
    raw_nics={(a.get('object_name'),n.get('device')):n for a in hosts
              for n in ((a.get('properties') or {}).get('physical_nic_details') or (a.get('properties') or {}).get('link_speed_detail') or []) if isinstance(n,dict)}
    def nic_assessment(v):
        raw=raw_nics.get((v['host'],v.get('device')),{});assessment=v.get('assessment')
        if assessment=='速率未采集':return ''
        if assessment=='正常' and not (str(raw.get('link_state') or '').lower() in {'up','down'} or
                                      str(raw.get('assessment') or '').lower() in {'up','normal','healthy'}):return ''
        return assessment
    from vstacklens.reports.customer_view import customer_vsan_summary
    saved_vsan = customer_vsan_summary(report)
    saved_vmk = {(v.get('host_name') or v.get('host'),v.get('device')):v
                 for v in (saved_vsan.get('network') or {}).get('vmkernels') or []}
    vmk_inventory = {(v['host'],v['device']):dict(v) for v in network.get('vmkernels') or []}
    # Older saved runs can contain a bound vSAN interface in the summary only.
    # Merge that evidence into the single full VMkernel inventory, never infer
    # service membership from a port-group label.
    for identity,v in saved_vmk.items():
        vmk_inventory.setdefault(identity,{'host':identity[0],'device':identity[1],
            'ip':v.get('ip_address') or v.get('ip'),'label':v.get('network_label') or v.get('portgroup'),
            'switch':v.get('switch'),'mtu':v.get('mtu')})
    vmk_rows=[]
    for identity,v in sorted(vmk_inventory.items()):
        saved=saved_vmk.get(identity,{})
        vmk_rows.append(_entry(f"{v['host']}/{v['device']}",v['host'],
            [v['host'],v.get('device'),v.get('ip'),saved.get('subnet_mask') or saved.get('subnet') or v.get('subnet'),
             v.get('label'),v.get('switch'),v.get('mtu')],host_clusters.get(v['host'],''),v['host'],'环境明细'))
    vmk_full=register(_table('vmkernels','VMkernel 完整清单',['主机','接口','IP','子网','网络','交换机','MTU'],vmk_rows))
    pnic_rows=[_entry(f"{v['host']}/{v['device']}",v['host'],[v['host'],v.get('device'),v.get('switch'),state(v.get('link_state')),
                v.get('actual_speed'),v.get('configured_speed'),nic_assessment(v)],
                host_clusters.get(v['host'],''),v['host'],'环境明细') for v in network.get('pnics') or []]
    pnic_full=register(_table('pnics','物理网卡完整清单',['主机','网卡','交换机','链路','实际速率','配置速率','状态'],pnic_rows))
    pnic_issues=[_entry(f"link:{v['host']}/{v['device']}",v['host'],[v['host'],v['device'],v['portgroups'],v['state']],
                    host_clusters.get(v['host'],''),v['host'],'环境明细') for v in network.get('pnic_anomalies') or []]
    pnic_issue_full=register(_table('link-anomalies','在用链路异常完整清单',['主机','网卡','端口组及角色','状态'],pnic_issues))
    certificates=legacy.get('certificates') or {}
    cert_data=([certificates['vcenter']] if certificates.get('vcenter') else [])+list(certificates.get('hosts') or [])
    cert_data=[v for v in cert_data if v.get('expiry') or _number(v.get('remaining_days')) is not None]
    cert_rows=[_entry('certificate:'+str(v.get('object_key') or v['name']),v['name'],[v['name'],v.get('expiry'),metric(v.get('remaining_days'),'天'),v.get('date_source')],host_clusters.get(v['name'],''),v['name'],'环境明细',attention=v.get('attention') is True or v.get('expired') is True) for v in cert_data]
    cert_full=register(_table('certificates','证书完整清单',['名称','到期日','剩余时间','日期来源'],cert_rows))
    # Customer decision: license information shows assignment/name/version.
    # Expiry and query diagnostics stay in the original evidence and rules.
    from vstacklens.collection.license_state import verified_state
    license_rows=[];license_groups=defaultdict(set)
    for kind in ('vCenter','HostSystem'):
        for a in raw.get(kind) or []:
            if not a.get('object_key'):continue
            s=verified_state(a.get('properties') or {},kind=='HostSystem',str(a.get('object_key') or ''))
            assigned='已分配' if s.get('assigned') is True else '未分配' if s.get('assigned') is False else ''
            values=[str(s.get('name') or ''),str(s.get('product_version') or ''),assigned]
            if not any(values):continue
            license_rows.append(cell_entry(a,[a.get('object_name',''),'ESXi' if kind=='HostSystem' else 'vCenter',*values],suffix=':license'))
            license_groups[tuple(values)].add((kind,str(a.get('object_key') or '')))
    license_full=register(_table('licenses','授权分配完整清单',['对象','类型','授权名称','版本','分配状态'],license_rows))
    saved_status=defaultdict(dict)
    from vstacklens.reports.customer_caliber import approved_result_projection
    for r in approved_result_projection(report,context).get('object_results') or []:
        if r.get('object_type')=='HostSystem':
            saved_status[str(r.get('object_key'))][r.get('rule_id')]=r.get('result_status')
    safety_columns=[('SSH','VSL-HOST-002'),('ESXi Shell','VSL-HOST-016'),('NTP','VSL-HOST-003')]
    safety_rows=[]
    for a in sorted(hosts,key=lambda r:str(r.get('object_name'))):
        values=[{'passed':'✓','failed':'×'}.get(saved_status[str(a.get('object_key'))].get(rule),'—') for _,rule in safety_columns]
        safety_rows.append({**cell_entry(a,[a['object_name'],*values]),'fail_count':values.count('×')})
    safety_candidate=_table('security','主机安全基线完整矩阵',['主机',*[c[0] for c in safety_columns]],safety_rows)
    safety_full=register(safety_candidate) if safety_candidate and len(safety_candidate['headers'])>1 else None
    vsan=legacy.get('vsan') or {}
    disks=[]
    if known_vsan:
        disk_inventory = vsan.get('disk_details') or []
        if not disk_inventory and report.vsan_summary.get('disk_topology'):
            from vstacklens.reports.context_builder import ReportContextBuilder
            disk_inventory = ReportContextBuilder()._vsan_disk_details(
                report.vsan_summary['disk_topology'],report.vsan_summary.get('physical_disks'))
        for i,disk in enumerate(disk_inventory):
            cells=[disk.get('host'),disk.get('device'),disk.get('role'),state(disk.get('health'))]
            if not esa:
                cells.insert(2,disk.get('group') or disk.get('disk_group'))
            disks.append(_entry('disk:'+str(i)+':'+str(disk.get('device')),str(disk.get('device') or ''),cells,host_clusters.get(disk.get('host'),''),disk.get('host'),'环境明细',attention=disk.get('health') in ('异常','需关注','red','yellow','error','degraded','failed')))
    disk_full=register(_table('disks','vSAN 物理磁盘完整清单',['主机','设备',*(['磁盘组'] if not esa else []),'角色','状态'],disks))
    observed_objects=[];observed_disks=[]
    saved_clusters=report.vsan_summary.get('clusters') or []
    shared_vsan_cluster=saved_clusters[0] if len(saved_clusters)==1 else ''
    if known_vsan:
        for i,item in enumerate(report.vsan_summary.get('object_issues') or []):
            name=_text(item.get('component') or item.get('object_id') or item.get('name'))
            observed_objects.append(_entry('vsan-object-observation:'+str(i),name,[name,state(item.get('status') or item.get('health')),
                 customer_text(item.get('summary') or item.get('message'))],item.get('cluster') or shared_vsan_cluster,category='环境明细'))
        for i,item in enumerate(report.vsan_summary.get('disk_issues') or []):
            name=_text(item.get('disk') or item.get('device') or item.get('name'));host=_text(item.get('host'))
            observed_disks.append(_entry('vsan-disk-observation:'+str(i),name,[host,name,state(item.get('status') or item.get('health')),
                 customer_text(item.get('summary') or item.get('message'))],host_clusters.get(host) or shared_vsan_cluster,host,category='环境明细'))
    object_observations=register(_table('vsan-object-observations','vSAN 对象状态明细',['对象 / 组件','状态','说明'],observed_objects))
    disk_observations=register(_table('vsan-disk-observations','vSAN 磁盘状态明细',['主机','设备','状态','说明'],observed_disks))

    env=[]
    vc_props=(raw.get('vCenter') or [{}])[0].get('properties') or {}
    vc_identity=[f'vCenter：{report.customer_info.vcenter}' if report.customer_info.vcenter else '',
                 f'版本 {vc_props["version"]}' if vc_props.get('version') else '',
                 f'Build {vc_props["build"]}' if vc_props.get('build') else '',
                 '连接成功' if vc_props.get('connected') is True else '连接失败' if vc_props.get('connected') is False else '']
    identity=[' · '.join(value for value in vc_identity if value),
              (legacy.get('delivery') or {}).get('scope') or '']
    if any(identity):
        env.append({'kind':'paragraph','id':'environment-identity','title':'','text':'；'.join(value for value in identity if value)})
    from vstacklens.reports.presentation import customer_judgment_metadata
    boundary=customer_text(customer_judgment_metadata(report)['boundary'])
    if boundary:
        env.append({'kind':'paragraph','id':'judgment-boundary','title':'','text':boundary})
    comparison=report.appendix.get('history_comparison') or context.get('history_comparison') or {}
    safe_comparison={}
    if comparison.get('state')=='ready' and comparison.get('baseline_run_id') and comparison.get('comparison_run_id'):
        safe_comparison={key:comparison.get(key,'') for key in ('state','baseline_run_id','comparison_run_id','summary_text')}
        safe_comparison['summary_text']=customer_text(safe_comparison['summary_text'])
        if safe_comparison['summary_text']:
            env.append({'kind':'paragraph','id':'saved-comparison','title':'',
                        'text':'与上轮巡检相比，'+safe_comparison['summary_text']})
    def known_count(kind):
        value=(report.asset_inventory.get('summary') or {}).get(kind)
        if _number(value) is not None:return metric(value)
        return str(len(raw[kind])) if isinstance(raw.get(kind),list) else ''
    scale_rows=[_entry('scale','环境规模',[known_count(kind) for kind in
                 ('ClusterComputeResource','HostSystem','VirtualMachine','Datastore')])]
    env.append(_table('scale','资产规模',['集群','主机','虚拟机','数据存储'],scale_rows,role='summary'))
    snapshot_known=bool(vms) and all(isinstance((p:=a.get('properties') or {}).get('snapshots'),list)
                                  or isinstance(p.get('has_snapshot'),bool) or _number(p.get('snapshot_count')) is not None
                                  or _number(p.get('snapshot_chain_depth')) is not None for a in vms)
    if snapshot_known and facts['snapshots']['overview_label']:
        env.append({'kind':'paragraph','id':'snapshot-overview','title':'','text':facts['snapshots']['overview_label']})
    if cluster_rows:
        displayed=cluster_rows if len(cluster_rows)<=10 else cluster_rows[:9]+[_entry('remaining-clusters','其余集群',[f'其余 {len(cluster_rows)-9} 个集群',sum(int(r['cells'][1]) for r in cluster_rows[9:]),sum(int(r['cells'][2]) for r in cluster_rows[9:]),'', ''])]
        node=_table('cluster-summary','集群',['集群','主机数','虚拟机数','HA','DRS'],displayed,role='summary')
        node['kind']='cards' if len(cluster_rows)<=4 else 'table'
        env.append(node)
    # Charts retain the original numeric values and common scale. No averages.
    all_host_metrics=list(legacy.get('host_details') or [])
    hardware_rows=[_entry('hardware:'+v['name'],_plain(v['name']),[_plain(v['name']),metric(v.get('hardware_issue_count'),'项'),v.get('hardware_issue_summary')],
                   host_clusters.get(_plain(v['name']),''),_plain(v['name']),'环境明细') for v in all_host_metrics
                   if (_number(v.get('hardware_issue_count')) or 0)>0]
    if hardware_rows:
        env.append(_table('hardware-attention','需关注的主机硬件',['主机','异常数量','异常明细'],hardware_rows[:10],
                   notes=[f'完整列表见 Word / HTML 报告附录 {host_full["letter"]}。'] if len(hardware_rows)>10 and host_full else []))
    for field,title,threshold in [('cpu_pct','主机 CPU 使用率',80),('memory_pct','主机内存使用率',80),('memory_allocation_pct','主机内存分配比例',100)]:
        known=[r for r in all_host_metrics if _number(r.get(field)) is not None]
        known.sort(key=lambda r:(-r[field],_plain(r['name'])))
        if not known:
            continue
        if len({r[field] for r in known})==1:
            env.append({'kind':'paragraph','id':field,'title':title,'text':f'{len(known)} 台主机的{title.removeprefix("主机")}均为 {percent_text(known[0][field])}。'})
        else:
            maximum=max(100,max(r[field] for r in known))
            axis=math.ceil(maximum/50)*50
            env.append({'kind':'chart','id':field,'title':title,'threshold':threshold,'axis_max':axis,
                        'ticks':[{'value':v,'text':percent_text(v)} for v in range(0,int(axis)+1,50)],
                        'series':[{'name':_plain(r['name']),'value':r[field],'text':percent_text(r[field])} for r in known[:10]],
                        'more':f'其余 {len(known)-10} 台见附录 {host_full["letter"]}。' if len(known)>10 and host_full else ''})
    ranked=sorted([a for a in stores if _number((a.get('properties') or {}).get('used_percent')) is not None],
                  key=lambda a:(-(a['properties']['used_percent']),str(a.get('object_name') or ''),str(a.get('object_key') or '')))[:10]
    if ranked:
        env.append(_table('storage-ranking','数据存储使用率',['数据存储','总容量','已用容量','使用率'],[
            _entry('store-ranking:'+row_id(a),a['object_name'],[a['object_name'],capacity_text(a['properties'].get('datastore_capacity_gb')),
                  capacity_text(a['properties'].get('datastore_used_gb')),percent_text(a['properties']['used_percent'])]) for a in ranked],role='ranking',
            notes=[f'完整列表见 Word / HTML 报告附录 {store_full["letter"]}。'] if store_full and len(store_rows)>len(ranked) else []))
    if known_vsan:
        items=[]
        for label,key in [('总容量','total_display'),('已用容量','used_display'),('可用容量','free_display'),('VMDK','vmdk_count_text')]:
            if vsan.get(key) not in (None,'','—'):
                items.append(_entry('vsan:'+key,label,[label,vsan[key]]))
        if not esa and vsan.get('disk_group_count_text'):
            items.append(_entry('vsan-groups','磁盘组',['磁盘组',vsan['disk_group_count_text']]))
        capacity_item=next((x for x in facts['vsan']['items'] if x['key']=='capacity'),None)
        if capacity_item:
            items.append(_entry('vsan-usage','容量使用率',['容量使用率',percent_text(capacity_item['value'])]))
        for label,key,formatter in [('重同步对象','resync_object_count',lambda x:metric(x,'个')),
                                    ('重同步数据','resync_bytes',capacity_bytes_text)]:
            value=report.vsan_summary.get(key)
            if _number(value) is not None:
                items.append(_entry('vsan-'+key,label,[label,formatter(value)]))
        if items:
            env.append(_table('vsan','vSAN',['项目','当前值'],items,role='summary'))
        if facts.get('vsan',{}).get('summary'):
            env.append({'kind':'paragraph','id':'vsan-checked','title':'vSAN 已检查项目','text':facts['vsan']['summary']})
        for full,observations,table_id in [(object_observations,observed_objects,'vsan-object-attention'),(disk_observations,observed_disks,'vsan-disk-attention')]:
            if full:
                env.append(_table(table_id,full['title'],full['headers'],observations[:10],
                    notes=[f'完整列表见 Word / HTML 报告附录 {full["letter"]}。'] if len(observations)>10 else []))
        abnormal=[r for r in disks if r.get('attention')]
        if abnormal:
            env.append({**_table('disk-attention','需关注的物理磁盘',disk_full['headers'],abnormal[:10]),'reference':f'完整列表见 Word / HTML 报告附录 {disk_full["letter"]}。' if len(abnormal)>10 else ''})
    if network.get('host_uplink_summary'):
        summary=network['host_uplink_summary']
        if isinstance(summary,str) and customer_text(summary):
            env.append({'kind':'paragraph','id':'network-summary','title':'网络','text':customer_text(summary)})
    summaries=[]
    if vmk_full:
        summaries.append(f'{len(vmk_rows)} 个 VMkernel 接口；完整列表见 Word / HTML 报告附录 {vmk_full["letter"]}。')
    if pnic_full:
        summaries.append(f'{len(pnic_rows)} 块物理网卡；完整列表见 Word / HTML 报告附录 {pnic_full["letter"]}。')
    if summaries:
        env.append({'kind':'paragraph','id':'network','title':'网络配置','text':' '.join(summaries)})
    if facts['network'].get('summary'):
        env.append({'kind':'paragraph','id':'network-health','title':'在用链路','text':facts['network']['summary']})
    if pnic_issues:
        env.append(_table('link-attention','需关注的在用链路',['主机','网卡','端口组及角色','状态'],pnic_issues[:10],
                   notes=[f'完整列表见 Word / HTML 报告附录 {pnic_issue_full["letter"]}。'] if len(pnic_issues)>10 else []))
    abnormal_cert=[r for r in cert_rows if r['attention']]
    if abnormal_cert:
        env.append(_table('certificate-attention','需关注的证书',cert_full['headers'],abnormal_cert[:10],notes=[f'完整列表见 Word / HTML 报告附录 {cert_full["letter"]}。'] if len(abnormal_cert)>10 else []))
    elif cert_rows:
        healthy_hosts=[v for v in certificates.get('hosts') or [] if _number(v.get('remaining_days')) is not None and v['remaining_days']>90 and v.get('expiry')]
        if healthy_hosts:
            env.append({'kind':'paragraph','id':'cert-summary','title':'证书','text':f'{len(healthy_hosts)} 台主机的证书剩余均超过 90 天，最近到期日为 {min(v["expiry"] for v in healthy_hosts)}。'})
        if certificates.get('vcenter'):
            v=certificates['vcenter']
            env.append({'kind':'paragraph','id':'vc-cert','title':'vCenter 证书','text':'；'.join(str(x) for x in [v.get('expiry_display'),v.get('date_source')] if x)})
        sources=list(dict.fromkeys(v.get('date_source') for v in certificates.get('hosts') or [] if v.get('date_source')))
        if sources:
            env.append({'kind':'paragraph','id':'host-cert-source','title':'主机证书日期来源','text':'；'.join(sources)})
    if license_full:
        groups=sorted(license_groups.items(),key=lambda item:(-len(item[1]),item[0]))
        env.append(_table('licenses','授权分配信息',['授权名称','版本','分配状态','目标数'],[
            _entry('license-group:'+_token(values),'授权信息',[*values,len(keys)]) for values,keys in groups[:5]],role='summary',
            notes=[f'完整列表见 Word / HTML 报告附录 {license_full["letter"]}。']))
    attention_safety=sorted([r for r in safety_rows if r['fail_count']>0],key=lambda r:(-r['fail_count'],r['name']))
    if safety_full and attention_safety:
        # All-null metric columns are hidden under the higher-priority R1-07.
        cols=[['主机',*[c[0] for c in safety_columns]].index(h) for h in safety_full['headers']]
        chosen=[{**r,'cells':[r['cells'][i] for i in cols]} for r in attention_safety[:10]]
        env.append(_table('security-attention','主机安全基线',safety_full['headers'],chosen,notes=[f'完整列表见 Word / HTML 报告附录 {safety_full["letter"]}。'] if len(attention_safety)>10 else []))
    elif safety_full and all(r['cells'][1:] and all(v=='✓' for v in r['cells'][1:]) for r in safety_full['rows']):
        env.append({'kind':'paragraph','id':'security-summary','title':'主机安全基线','text':f'{len(safety_rows)} 台主机的已检查安全基线项目均通过。'})
    for key,title in [('top_vcpu','vCPU 配置 Top 5'),('top_capacity','VMDK 配置容量 Top 5'),('top_cpu','CPU 实际用量 Top 5'),('top_memory','内存实际用量 Top 5')]:
        rows=list(legacy.get(key) or [])[:5]
        if rows:
            notes=list(dict.fromkeys(r.get('display_share_scope') for r in rows if r.get('display_share_scope')))
            env.append(_table(key,title,['虚拟机','主机','数值','占比'],[
                _entry(key+':'+r['name'],_plain(r['name']),[_plain(r['name']),_plain(r.get('host')),r.get('display'),r.get('host_share_text')],
                       detail=' · '.join(value for value in (('主机：'+_plain(r['host'])) if r.get('host') else '',
                             r.get('display') or '',('占比：'+r['host_share_text']) if r.get('host_share_text') else '') if value)) for r in rows],
                role='ranking',notes=notes,presentation='ranked-cards'))
    capacity_problem=None
    for problem in problem_nodes:
        parts=[field['text'] for field in problem['fields']]
        parts.extend(value for row in (problem['representative_table'] or {}).get('rows',[]) for value in row['cells'])
        if any(re.search(r'\d[\d,.]*\s*(?:GB|TB)\b',value) for value in parts):
            capacity_problem=problem;break
    if capacity_problem is not None:
        capacity_problem['capacity_note']=CAPACITY_NOTE
    elif any(' GB' in str(r) or ' TB' in str(r) for r in env):
        env.insert(1,{'kind':'paragraph','id':'capacity-note','title':'','text':CAPACITY_NOTE})
    env=[node for node in env if node and (node['kind']!='paragraph' or node['text'].strip())]
    health=(view.caliber.get('health') or {}).get('label') or delivery_overview(report)['conclusion']
    if health not in {'危险','关注','存在整改事项','健康','评估受限'}:
        health='评估受限'
    doc['opening']={'conclusion':health,'problem_text':f'{len(categories)} 类问题、{view.caliber["affected_total"]} 个受影响对象',
                    'priorities':[{'title':c['title'],'level':c['level'],'objects':c['count']} for c in categories[:5]],
                    'more':f'另有 {len(categories)-5} 类，见问题总览' if len(categories)>5 else '', 'statistics':stats['text']}
    if categories:
        doc['sections'].append({'id':'overview','title':'问题总览','kind':'overview',
                                'rows':[{'title':c['title'],'level':c['level'],'objects':c['count']} for c in categories],
                                'levels':doc['counts']['levels'],
                                'distribution':{'id':'level-distribution','title':'问题等级分布','kind':'chart','threshold':None,
                                    'axis_max':max(1,len(categories)),
                                    'ticks':[{'value':n,'text':f'{n} 类'} for n in (0,len(categories))],
                                    'series':[{'name':l,'level':l,'value':doc['counts']['levels'][l],
                                               'text':f'{doc["counts"]["levels"][l]} 类'} for l in LEVELS],'more':''}})
        doc['sections'].append({'id':'problems','title':'问题详情','kind':'problems','items':problem_nodes})
    if passed:
        doc['sections'].append({'id':'passed','title':'已通过的检查','kind':'checklist',
                                'items':[{key:value for key,value in item.items() if key!='rule_id'} for item in passed]})
    if env:
        definitions=[('scale-clusters','资产规模与集群',{'environment-identity','judgment-boundary','saved-comparison','scale','cluster-summary','capacity-note','snapshot-overview'}),
                     ('host-resources','主机与资源',{'cpu_pct','memory_pct','memory_allocation_pct','hardware-attention'}),
                     ('storage','数据存储与 vSAN' if known_vsan else '数据存储',{'storage-ranking','vsan','vsan-checked','disk-attention','vsan-object-attention','vsan-disk-attention'}),
                     ('network','网络',{'network','network-summary','network-health','link-attention'}),
                     ('security-certificates','安全与证书',{'certificate-attention','cert-summary','vc-cert','host-cert-source','licenses','security-attention','security-summary'}),
                     ('resource-top','资源 Top 5',{'top_vcpu','top_capacity','top_cpu','top_memory'})]
        groups=[{'id':key,'title':title,'blocks':[n for n in env if n and n['id'] in ids]}
                for key,title,ids in definitions]
        groups=[g for g in groups if g['blocks']]
        doc['sections'].append({'id':'environment','title':'环境详情','kind':'environment','blocks':[n for n in env if n], 'groups':groups})
    doc['navigation']=[{'id':s['id'],'title':s['title'],'level':1} for s in doc['sections']]
    doc['full_navigation']=doc['navigation']+[{'id':a['anchor'],'title':f'附录 {a["letter"]} {a["title"]}','level':1} for a in doc['appendices']]
    doc['decisions'] += ['ISO按文件汇总是R2-07对通用代表对象公式的特例；文件挂载台数不相加冒充去重VM数。',
                         '类别与共享对象可能多重归属；筛选逐组核对源成员并以并集去重，不把关联行数冒充去重对象数。',
                         '安全矩阵全列缺数据按R1-07隐藏；部分未知为R2-12规定的—，不填✓/×。',
                         '小类正文全列与附录保留按R2-06/15优先；正文是关键定位视图，完整清单数据只登记一次。',
                         '其他快照资产只包含问题快照之外的对象，完整保留名称与时间，不重复问题快照清单。']
    # A small compatibility envelope keeps the existing report-center reader
    # working. It contains metadata, never the full result/evidence catalog.
    doc['metadata']={
        'report_context':{
            'report_info':{'report_title':doc['title'],'generated_at':report.report_info.generated_at},
            'customer_info':{'customer_name':doc['customer']},
            'environment_info':{'security_warnings':[]},
            'health_score':{'score':report.health_score.score,'label':doc['opening']['conclusion']},
            'customer_caliber':{'version':view.caliber.get('version'),'state':view.caliber.get('state'),
                'counts':{key:value for key,value in view.caliber.get('counts',{}).items() if key in LEVELS},'problem_count':doc['counts']['categories'],
                'affected_counts':{key:value for key,value in view.caliber.get('affected_counts',{}).items() if key in LEVELS},'affected_total':doc['counts']['objects'],
                'health':{'label':doc['opening']['conclusion'],'assessment_limited':doc['opening']['conclusion']=='评估受限'}}},
        'assets':{'summary':deepcopy(report.asset_inventory.get('summary') or {})},
        'findings':[{'risk_level':c['level'],'title':c['title'],'object_name':''} for c in categories]}
    if boundary:
        doc['metadata'].setdefault('summary',{})['judgmentBoundary']=boundary
    if safe_comparison:
        doc['metadata'].setdefault('summary',{})['comparisonText']='与上轮巡检相比，'+safe_comparison['summary_text']
        doc['metadata']['report_context']['history_comparison']=deepcopy(safe_comparison)
        doc['metadata']['report_context']['appendix']={'history_comparison':deepcopy(safe_comparison)}
    from vstacklens.reports.document_visual import attach_visual
    return attach_visual(doc, legacy, report)
