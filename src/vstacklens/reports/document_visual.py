"""Restore batch-three display fields inside the one shared document.

All business values come from PdfReportEngine._build_payload (7f9653a) or the
already selected batch-four document.  Geometry and display formatting do not
re-evaluate saved checks, reselect representatives, or modify captured evidence.
"""
from copy import deepcopy
import math
import re

from vstacklens.reports.customer_format import capacity_text, capacity_unit, decimal_text, percent_text

EMPTY={'','—','未采集','未记录','不可用','不适用','未确认','待确认','unknown'}
FIELD_SOURCES=[
 ('visual.platform','environment.vcenter_version / vcenter_build','PdfReportEngine._build_payload','V-01/V-14/V-20'),
 ('visual.scope','scope.total_checks / passed_checks / problem_checks / level_distribution','PdfReportEngine._build_payload / presentation.customer_check_statistics','V-04'),
 ('problem.visual.owner/effort/verification','problems.owner/effort/verification','PdfReportEngine._build_payload / _role_label / _effort_label / _verification_label','V-05/V-15'),
 ('cluster.visual','cluster_details / ha_chart / drs_chart','PdfReportEngine._build_payload','V-06'),
 ('visual.host_kpis / allocation_cpu','counts / host_details.vcpu_pcpu_ratio / allocated_vcpu / cpu_cores','PdfReportEngine._build_payload','V-07'),
 ('visual.allocation_memory','host_details.memory_allocation_pct / memory_allocated_gb / memory_capacity_gb','PdfReportEngine._build_payload','V-07'),
 ('ranked_row.visual','top_vcpu / top_capacity / top_cpu / top_memory','PdfReportEngine._build_payload','V-08'),
 ('visual.vm_states / snapshots','counts.powered_on / powered_off / suspended / display_facts.snapshots','PdfReportEngine._build_payload / customer_display_facts','V-09'),
 ('visual.vsan_cards / vsan_charts','vsan / vsan_summary','PdfReportEngine._build_payload / DocxReportEngine._add_vsan_object_chart / _add_vsan_capacity_chart','V-10/V-17'),
 ('document.references','existing reference string / appendix letter / selected totals','document_model._build_document','V-18'),
 ('visual.section_subtitles','wording.scope_subtitle / incumbent page-title subtitles','PdfReportEngine._build_payload / inspection-report.typ::page-title','V-02'),
]

def pdf_page_limit(category_count):
    """User-approved category-based layout budget, independent of sample names."""
    return min(25,20+max(0,int(category_count)-10))

def number(value):
    return float(value) if isinstance(value,(int,float)) and not isinstance(value,bool) and math.isfinite(value) else None

def present(value):
    return value is not None and str(value).strip() not in EMPTY

def count(value):
    return decimal_text(value,0) if number(value) is not None else ''

def format_reference(value,medium):
    """One N/M/X, different delivery-medium wording; no numeric decisions."""
    if not value:return ''
    if medium in ('word','html'):return str(value).replace('Word / HTML 报告附录','附录')
    return re.sub(r'(?<!报告)见附录 ', '见 Word / HTML 报告附录 ',str(value))

def _pairs(values):
    return [{'label':label,'value':str(value)} for label,value in values if present(value)]

def _metric(label,value,detail=''):
    return {'label':label,'value':str(value),'detail':str(detail or '')} if present(value) else None

def attach_visual(document,legacy,report):
    """Attach whitelisted saved fields; preserve all existing semantic nodes."""
    counts=legacy.get('counts') or {};scope=legacy.get('scope') or {}
    env=next((s for s in document['sections'] if s['kind']=='environment'),{})
    blocks={n['id']:n for n in env.get('blocks',[])}
    v={'platform':' · '.join(x for x in (
        'vCenter '+str(legacy['environment']['vcenter_version']) if present((legacy.get('environment') or {}).get('vcenter_version')) else '',
        'Build '+str(legacy['environment']['vcenter_build']) if present((legacy.get('environment') or {}).get('vcenter_build')) else '') if x),
       'scope':{k:deepcopy(scope.get(k)) for k in ('total_checks','passed_checks','problem_checks','level_distribution','all_passed')},
       'host_kpis':[],'asset_kpis':[],'vm_states':[],'snapshots':[],'clusters':{},'cluster_coverage':[],
       'top':{},'storage':{},'vsan_cards':[],'vsan_charts':[],'narratives':{},'group_summaries':{}}
    # Cover summary is the already approved opening facts, not the old asset-scale narrative.
    v['executive']='；'.join(x for x in (document['opening']['problem_text'],document['opening']['statistics']) if x)
    stats=document['statistics']
    v['has_execution_stats']=bool(stats.get('available'))
    v['scope']['pass_percent']=stats['passed']*100/stats['total'] if stats['total'] else None
    v['scope']['pass_percent_text']=percent_text(v['scope']['pass_percent'])
    v['display_title']=document['title'].removeprefix('VStackLens ')
    v['cover_label']=''
    if v['display_title'].startswith('合成测试数据') and v['display_title'].endswith('虚拟化巡检报告'):
        v['cover_label']=v['display_title'][:-len('虚拟化巡检报告')].rstrip()
        v['display_title']='虚拟化巡检报告'
    v['header_identity']=' · '.join(x for x in (document['customer'],'虚拟化巡检报告') if x)
    v['date_label']='巡检日期：'+str(legacy.get('report_date') or document['date'][:10])
    v['section_subtitles']={'overview':(legacy.get('wording') or {}).get('scope_subtitle',''),
        'problems':'按处置优先级列出全部 P1-P3 问题、影响、处理步骤和复核方式',
        'checklist':(legacy.get('wording') or {}).get('scope_subtitle',''),
        'environment':'资产规模与需处理事项分布'}
    from vstacklens.reports.pdf_report import PdfReportEngine
    v['scope_svg']=PdfReportEngine()._scope_level_donut_svg(v['scope'])
    for old,level in (('#B84545','P1'),('#B98220','P2'),('#2F72B7','P3')):
        v['scope_svg']=v['scope_svg'].replace(old,document['colors'][level])
    v['opening_kpis']=[_metric('问题类别',count(document['counts']['categories']),
          ' · '.join(f'{level} {document["counts"]["levels"][level]}' for level in ('P1','P2','P3'))),
        _metric('受影响对象',count(document['counts']['objects'])),
        _metric('检查统计',count(stats['total']),f'通过 {stats["passed"]} · 未通过 {stats["failed"]}') if stats.get('available') else None]
    v['opening_kpis']=[r for r in v['opening_kpis'] if r]
    scale=blocks.get('scale')
    if scale and scale['rows']:
        v['asset_kpis']=[_metric(label,value) for label,value in zip(scale['headers'],scale['rows'][0]['cells']) if present(value)]
    for label,value in (('物理 CPU 核心',count(counts.get('cpu_cores'))),('物理内存',counts.get('memory_total_text')),
                         ('超配主机',legacy.get('overcommit_display'))):
        if present(value):v['host_kpis'].append(_metric(label,value))
    raw=report.asset_inventory.get('details') or {}
    vms=raw.get('VirtualMachine') or []
    if vms and all((r.get('properties') or {}).get('power_state') in {'poweredOn','poweredOff','suspended','powered_on','powered_off'} for r in vms):
        v['vm_states']=[_metric(label,count(counts.get(key))) for label,key in (('开机','powered_on'),('关机','powered_off'),('挂起','suspended')) if number(counts.get(key)) is not None]
        if all(number(counts.get(key)) is not None for key in ('powered_on','powered_off','suspended')):
            v['vm_state_card']={'title':'虚拟机电源状态','total':sum(counts[key] for key in ('powered_on','powered_off','suspended')),
                'segments':[{'label':label,'value':counts[key],'color':color} for label,key,color in
                    [('开机','powered_on','#28785A'),('关机','powered_off','#8CA9BF'),('挂起','suspended','#C5CFD8')]]}
    if 'snapshot-overview' in blocks:
        facts=(legacy.get('display_facts') or {}).get('snapshots') or {}
        v['snapshots']=[_metric('快照概况',facts.get('overview_label'),facts.get('problem_label'))]
        if present(legacy.get('snapshot_max_age_text')):v['snapshots'].append(_metric('保留最久',legacy['snapshot_max_age_text']))
        v['snapshots']=[r for r in v['snapshots'] if r]
    existing_problems={r['rule_id']:r for r in legacy.get('problems') or []}
    for section in document['sections']:
        if section['kind']=='problems':
            for p in section['items']:
                saved=existing_problems.get(p['id'],{})
                p['visual']={'meta':_pairs([('负责角色',saved.get('owner')),('工作量',saved.get('effort')),('复核方式',saved.get('verification'))])}
                p['references']={medium:format_reference(p['reference'],medium) for medium in ('pdf','word','html')}
    details={}
    for r in legacy.get('cluster_details') or []:details.setdefault(r['name'],[]).append(r)
    for row in (blocks.get('cluster-summary') or {}).get('rows',[]):
        matches=details.get(row['name'],[])
        saved=matches[0] if len(matches)==1 else {}
        core=dict(zip(blocks['cluster-summary']['headers'],row['cells']))
        r={'name':row['name'],'summary':' · '.join(x for x in (
          saved.get('kind'),count(saved.get('host_count'))+' 台主机' if number(saved.get('host_count')) is not None else '',
          count(saved.get('vm_count'))+' 台虚拟机' if number(saved.get('vm_count')) is not None else '') if x),
          'features':_pairs([('HA',core.get('HA')),('DRS',core.get('DRS'))]),
          'fields':_pairs([('HA 准入控制',saved.get('admission_control')),('心跳数据存储',saved.get('heartbeat_summary')),
             ('DRS 模式',saved.get('drs_behavior')),('EVC',saved.get('evc_enabled')),('EVC 模式',saved.get('evc_mode')),
             ('vMotion',f'{count(saved["vmotion_enabled_hosts"])}/{count(saved["host_count"])}' if number(saved.get('vmotion_enabled_hosts')) is not None and number(saved.get('host_count')) is not None else ''),
             ('CPU 型号数',count(saved.get('cpu_model_count'))),('内存容量差异',saved.get('memory_skew_text'))]),
          'graphs':[],'host_names':saved.get('host_names') or '', 'cpu_models':saved.get('cpu_models') or ''}
        # Explicit disabled-child dashes are the already approved D06 exception.
        for label,key,parent in [('HA 准入控制','admission_control','ha_enabled'),('心跳数据存储','heartbeat_summary','ha_enabled'),('DRS 模式','drs_behavior','drs_enabled')]:
            if saved.get(parent) is False:
                r['fields']=[f for f in r['fields'] if f['label']!=label]+[{'label':label,'value':'—'}]
        field_order=['HA 准入控制','心跳数据存储','DRS 模式','EVC','EVC 模式','vMotion','CPU 型号数','内存容量差异']
        r['fields'].sort(key=lambda f:field_order.index(f['label']))
        for field,title,text_key in [('cpu_usage_pct','集群 CPU 使用率','cpu_usage_text'),('memory_skew_pct','主机内存容量差异','memory_skew_text')]:
            if number(saved.get(field)) is not None:r['graphs'].append({'title':title,'value':saved[field],'text':saved.get(text_key) or percent_text(saved[field]),'axis_max':100})
        v['clusters'][row['key']]=r
    for key,title in (('ha_chart','HA 启用覆盖'),('drs_chart','DRS 启用覆盖')):
        c=legacy.get(key) or {}
        if number(c.get('value')) is not None and number(c.get('total')) is not None and c['total']>0:
            v['cluster_coverage'].append({'title':title,'text':c.get('note') or '', 'value':c['value'],'total':c['total']})
    host_rows=legacy.get('host_details') or []
    for field,key,title,threshold in [('vcpu_pcpu_ratio','allocation_cpu','主机 vCPU:pCPU',4),
                                      ('memory_allocation_pct','allocation_memory','主机内存分配比例',100)]:
        selected=[r for r in host_rows if number(r.get(field)) is not None]
        selected.sort(key=lambda r:(-r[field],r['name']))
        rows=[]
        for r in selected[:10]:
            if field=='vcpu_pcpu_ratio':
                detail=f'{count(r["allocated_vcpu"])}/{count(r["cpu_cores"])}' if number(r.get('allocated_vcpu')) is not None and number(r.get('cpu_cores')) is not None else ''
                text=decimal_text(r[field],2).rstrip('0').rstrip('.')+':1'
            else:
                detail=f'{decimal_text(r["memory_allocated_gb"])}/{decimal_text(r["memory_capacity_gb"])} GB' if number(r.get('memory_allocated_gb')) is not None and number(r.get('memory_capacity_gb')) is not None else ''
                text=percent_text(r[field])
            rows.append({'name':r['name'],'detail':detail,'value':r[field],'text':text})
        if rows:
            axis=math.ceil(max(threshold,max(r['value'] for r in rows))/ (50 if threshold==100 else 1))*(50 if threshold==100 else 1)
            host_appendix=next((a for a in document['appendices'] if a['id']=='hosts'),None)
            v[key]={'id':key,'title':title,'kind':'chart','threshold':threshold,'axis_max':axis,
               'ticks':[{'value':tick,'text':percent_text(tick) if threshold==100 else f'{tick}:1'} for tick in sorted({0,threshold,axis})],
               'series':rows,'equal_text':f'{len(selected)} 台主机的{title.removeprefix("主机")}均为 {rows[0]["text"]}。' if len({r[field] for r in selected})==1 else '',
               'more':f'其余 {len(selected)-10} 台见 Word / HTML 报告附录 {host_appendix["letter"]}。' if len(selected)>10 and host_appendix else ''}
    for key in ('top_vcpu','top_capacity','top_cpu','top_memory'):
        node=blocks.get(key)
        if not node:continue
        v['top'][key]=[]
        # The canonical ranked node was built from this exact legacy sequence.
        # Position preserves distinct VMs with the same display name.
        for row,r in zip(node['rows'],list(legacy.get(key) or [])[:5],strict=True):
            item={k:deepcopy(r[k]) for k in ('rank','name','host','display','host_share_text','bar_pct') if present(r.get(k))}
            item['meta_text']=' · '.join(x for x in (('主机 '+str(r['host'])) if present(r.get('host')) else '',
                      ('占比 '+str(r['host_share_text'])) if present(r.get('host_share_text')) else '') if x)
            v['top'][key].append(item)
    from vstacklens.reports.document_model import _token
    stores=raw.get('Datastore') or []
    ds={str(r.get('object_key') or _token(r.get('object_name'),r.get('asset_location'))):r for r in stores}
    unit=capacity_unit([(r.get('properties') or {}).get(k) for r in stores for k in ('datastore_used_gb','datastore_free_gb','datastore_capacity_gb')])
    for row in (blocks.get('storage-ranking') or {}).get('rows',[]):
        p=(ds.get(row['key'].removeprefix('store-ranking:'),{}).get('properties') or {})
        v['storage'][row['key']]={'name':row['name'],'usage':number(p.get('used_percent')),'usage_text':percent_text(p.get('used_percent')),
          'clusters':deepcopy(p.get('datastore_cluster_names') or []),
          'capacity_text':' · '.join(label+' '+capacity_text(p[key],unit=unit) for label,key in
             (('已用','datastore_used_gb'),('可用','datastore_free_gb'),('总量','datastore_capacity_gb')) if number(p.get(key)) is not None)}
    if document['vsan']:
        vs=legacy.get('vsan') or {};facts=(legacy.get('display_facts') or {}).get('vsan') or {}
        capacity=next((x for x in facts.get('items',[]) if x.get('key')=='capacity'),None)
        if capacity:v['vsan_cards'].append(_metric('vSAN 容量使用',percent_text(capacity['value']),'总量 '+vs['total_display'] if present(vs.get('total_display')) else ''))
        if vs.get('disk_health_fully_known') and number(vs.get('healthy_disks')) is not None and number(vs.get('disk_count')) is not None:
            v['vsan_cards'].append(_metric('物理盘',count(vs['healthy_disks'])+'/'+count(vs['disk_count'])))
        if number(vs.get('resync_objects')) is not None and number(vs.get('resync_bytes')) is not None:
            from vstacklens.reports.customer_format import capacity_bytes_text
            v['vsan_cards'].append(_metric('重同步',count(vs['resync_objects'])+' 对象 · '+('0 B' if vs['resync_bytes']==0 else capacity_bytes_text(vs['resync_bytes']))))
        summary=report.vsan_summary or {};capacity=summary.get('capacity') or {}
        if all(number(capacity.get(k)) is not None for k in ('total_gb','used_gb','free_gb')):
            v['vsan_charts'].append({'title':'vSAN 容量使用','segments':[{'label':'已用','value':capacity['used_gb']},{'label':'可用','value':capacity['free_gb']}],
                'total':capacity['total_gb'],'text':' · '.join(f'{label} {capacity_text(capacity[key])}' for label,key in [('总量','total_gb'),('已用','used_gb'),('可用','free_gb')])})
            unit=capacity_unit([capacity[k] for k in ('total_gb','used_gb','free_gb')])
            for segment in v['vsan_charts'][-1]['segments']:segment['display']=capacity_text(segment['value'],unit=unit)
        if number(summary.get('object_count')) is not None and number(summary.get('object_issue_count')) is not None:
            v['vsan_charts'].append({'title':'vSAN 对象健康','segments':[{'label':'正常','value':max(summary['object_count']-summary['object_issue_count'],0)},
                {'label':'异常','value':summary['object_issue_count']}], 'total':summary['object_count'], 'text':f'对象 {count(summary["object_count"])} · 异常 {count(summary["object_issue_count"])}'})
            for segment in v['vsan_charts'][-1]['segments']:segment['display']=count(segment['value'])
    # Existing approved text only, including current limited-evidence summaries.
    for key,node in blocks.items():
        if node['kind']=='paragraph':v['narratives'][key]=node['text']
    for group in env.get('groups',[]):
        if group['id'] not in ('network','security-certificates'):continue
        paragraphs={n['id']:n for n in group['blocks'] if n['kind']=='paragraph'}
        if group['id']=='security-certificates':
            parts=[]
            host=paragraphs.get('cert-summary');source=paragraphs.get('host-cert-source');vc=paragraphs.get('vc-cert')
            if host:
                text=host['text'].rstrip('。')
                if source:text+='；日期来源：'+source['text']
                parts.append(text+'。')
            elif source:parts.append(source['title']+'：'+source['text']+'。')
            if vc:parts.append(vc['title']+'：'+vc['text'].rstrip('。')+'。')
            parts.extend(n['text'] for key,n in paragraphs.items() if key not in ('cert-summary','host-cert-source','vc-cert'))
        else:parts=[n['text'] for n in paragraphs.values()]
        text=' '.join(parts)
        v['group_summaries'][group['id']]={'text':text,'references':{
            medium:{'text':format_reference(text,medium)} for medium in ('pdf','word','html')}}
    if raw.get('ClusterComputeResource') and all(isinstance((r.get('properties') or {}).get('ha_enabled'),bool) for r in raw['ClusterComputeResource']):
        if present((legacy.get('narratives') or {}).get('clusters')):v['narratives']['clusters']=legacy['narratives']['clusters']
    if host_rows and all(present(r.get('connection')) and number(r.get('hardware_issue_count')) is not None for r in host_rows):
        if present((legacy.get('narratives') or {}).get('hosts')):v['narratives']['hosts']=legacy['narratives']['hosts']
    document['visual']=v
    for n in [*env.get('blocks',[]),*[v[k] for k in ('allocation_cpu','allocation_memory') if k in v]]:
        n['references']={medium:{'more':format_reference(n.get('more',''),medium),
           'text':format_reference(n.get('text',''),medium),
           'reference':format_reference(n.get('reference',''),medium),
           'notes':[format_reference(x,medium) for x in n.get('notes',[])]} for medium in ('pdf','word','html')}
    return document
