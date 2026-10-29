"""All six saved/synthetic datasets pass the same customer artifact contract."""
from pathlib import Path
import json,os,subprocess
import pytest

from report_document_checks import NAMES, render_case, model_assertions, forbidden_hits, generator


@pytest.fixture(scope='session',params=NAMES)
def scenario_bundle(request,tmp_path_factory):
    if request.param=='frozen':
        loader=Path(os.environ.get('VSTACKLENS_FROZEN_REPORT_LOADER',r'private-source-not-distributed.py'))
        if not loader.exists():pytest.skip('Local frozen customer source is not bundled with portable fixtures')
    reuse=os.environ.get('VSTACKLENS_QA_INPUT_REUSE')
    input_root=Path(reuse)/('document-'+request.param+'0')/'scenario-input' if reuse else None
    replay=os.environ.get('VSTACKLENS_LAYOUT_FACT_REPLAY')
    if replay and request.param!='frozen':
        if Path(replay).is_file():
            selected=json.loads(Path(replay).read_text('utf8'))[request.param]
            return render_case(request.param,tmp_path_factory.mktemp('document-'+request.param),cached_source=Path(selected['database']).parent)
        directory=Path(replay)/('document-'+request.param+'0')/'scenario-input'/request.param
        databases=list(directory.glob('*/scenario.db'))
        assert len(databases)==1,'Explicit fact replay must select one reviewed snapshot'
        return render_case(request.param,tmp_path_factory.mktemp('document-'+request.param),cached_source=databases[0].parent)
    return render_case(request.param,tmp_path_factory.mktemp('document-'+request.param),input_root=input_root)


def test_six_scenario_artifacts_keep_counts_and_complete_appendices(scenario_bundle):
    model_assertions(scenario_bundle)


def test_display_axes_stay_sorted_and_on_one_line(scenario_bundle):
    from report_display_checks import assert_pdf_axes
    assert_pdf_axes(scenario_bundle)
    from report_visual_checks import browser_records
    for browser in browser_records(scenario_bundle):
        for axis in browser['axisGeometry']:
            ticks=axis['ticks']
            assert max(t['top'] for t in ticks)-min(t['top'] for t in ticks)<1,axis
            assert all(b['left']-a['right']>=3 for a,b in zip(ticks,ticks[1:])),axis
            assert all(t['left']>=axis['card_left']-.8 and t['right']<=axis['card_right']+.8 for t in ticks),axis


def test_display_cover_problem_totals_appear_only_in_cards(scenario_bundle):
    from report_display_checks import assert_cover_deduplication
    assert_cover_deduplication(scenario_bundle)
    from report_visual_checks import browser_records
    d=scenario_bundle['document']
    for browser in browser_records(scenario_bundle):
        assert browser['openingDisplay']['problem_count_lines']==0
        assert browser['openingDisplay']['executive']==d['opening']['statistics']
        assert browser['openingDisplay']['kpis']==d['visual']['opening_kpis']


def test_display_word_problem_content_columns_align(scenario_bundle):
    from report_display_checks import assert_word_field_alignment
    assert_word_field_alignment(scenario_bundle)


def test_six_scenario_body_fields_are_present_in_pdf_and_word(scenario_bundle):
    from report_document_checks import compact
    bundle=scenario_bundle;d=bundle['document'];r=bundle['result']
    for section in d['sections']:
        if section['kind']!='problems':continue
        for p in section['items']:
            for field in p['fields']:
                for text in [r['pdf']['text'],r['word_text'],*([r['word']['text']] if r['word'] else [])]:
                    assert compact(field['text']) in compact(text),(r['name'],p['id'],field['key'])
            for group in p['step_groups'] or [{'steps':p['steps']}]:
                for step in group['steps']:
                    assert compact(step) in compact(r['pdf']['text'])
                    assert compact(step) in compact(r['word_text'])


def test_six_scenario_browser_search_filters_and_responsiveness(scenario_bundle):
    root=scenario_bundle['root']
    runtime=Path(os.environ.get('VSTACKLENS_TEST_NODE',r'C:\Users\Public\.cache\codex-runtimes\codex-primary-runtime\dependencies\node'))
    node=runtime/'bin/node.exe'
    if not node.is_file():pytest.skip('Bundled offline browser runtime is not available')
    env=os.environ.copy();env['NODE_PATH']=str(runtime/'node_modules')
    command=[str(node),str(Path(__file__).with_name('report_document_browser.cjs')),str(root)]
    result=subprocess.run(command,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=180)
    assert result.returncode==0,result.stderr[-4000:]
    records=json.loads((root/'browser.json').read_text('utf-8'))
    for r in records:
        assert not forbidden_hits(r['qa']['text'])
        if not scenario_bundle['document']['vsan']:assert 'vsan' not in r['qa']['text'].lower()
        if scenario_bundle['document']['esa']:assert '磁盘组' not in r['qa']['text']
    assert [r['width'] for r in records]==[1440,390]


def test_C01_problem_preamble_through_review_stays_on_one_page(scenario_bundle):
    from report_visual_checks import visual_audit
    a=visual_audit(scenario_bundle)
    for fmt in ('pdf','word'):
        assert not [p for p in a[fmt]['problems'] if p['missing']],a[fmt]['problems']
    from report_pagination_checks import word_preamble_keep_chain
    word_preamble_keep_chain(scenario_bundle)


def test_representative_tables_repeat_headers_with_first_data_row(scenario_bundle):
    from report_pagination_checks import representative_fragments
    bundle=scenario_bundle
    representative_fragments(bundle['root']/'report.pdf',bundle['document'])
    representative_fragments(Path(bundle['result']['word_conversion']['pdf']),bundle['document'],word=True)


def test_pdf_toc_is_single_column_with_indented_problem_entries(scenario_bundle):
    from report_pagination_checks import pdf_toc_rows
    pdf_toc_rows(scenario_bundle['root']/'report.pdf',scenario_bundle['document'])


def test_pdf_half_page_tails_only_when_minimum_three_forces_whole_card(scenario_bundle):
    from report_pagination_checks import chart_pagination_audit
    result=chart_pagination_audit(scenario_bundle)
    assert all(gap['forced_by_minimum_three'] for gap in result['tails']),result['tails']


def test_chart_segments_repeat_titles_scales_and_have_at_least_three_objects(scenario_bundle):
    from report_pagination_checks import chart_pagination_audit
    from report_display_checks import assert_pdf_axes
    result=chart_pagination_audit(scenario_bundle)
    assert result['cards']
    assert_pdf_axes(scenario_bundle)


def test_C02_cover_has_all_components_and_sixty_percent_height(scenario_bundle):
    from report_visual_checks import visual_audit
    a=visual_audit(scenario_bundle)
    for fmt in ('pdf','word'):
        assert a[fmt]['cover']['required_text'],(fmt,a[fmt]['cover'])
        assert a[fmt]['cover']['fraction']>=.6,(fmt,a[fmt]['cover'])


def test_C03_physical_card_rows_fill_width_and_are_equal(scenario_bundle):
    from report_visual_checks import visual_audit
    a=visual_audit(scenario_bundle)
    for fmt in ('pdf','word'):
        assert not [r for r in a[fmt]['card_rows'] if not r['pass']],(fmt,a[fmt]['card_rows'])
    xml=scenario_bundle['word_xml'];ns={'w':'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
    tables=xml.xpath('//w:tbl[w:tblPr/w:tblCaption[@w:val="视觉卡片布局"]]',namespaces=ns)
    for t in tables:
        widths=[int(v) for v in t.xpath('./w:tblGrid/w:gridCol/@w:w',namespaces=ns)]
        if len(widths)>1:
            assert sum(widths)>=481.9*20*.9 and max(widths)-min(widths)<=2,widths
    # Page-boundary checks alone miss text cut at a narrow card's edge.
    # Every existing cluster field must actually appear INSIDE its card.
    import pymupdf
    from report_document_checks import compact
    doc=scenario_bundle['document']
    nodes=[n for s in doc['sections'] if s['kind']=='environment' for n in s['blocks']
           if n['id']=='cluster-summary' and n['kind']=='cards']
    with pymupdf.open(scenario_bundle['root']/'report.pdf') as pdf:
        for node in nodes:
            for row in node['rows']:
                c=doc['visual']['clusters'][row['key']];matches=[]
                for page in pdf:
                    for shape in page.get_drawings():
                        color=shape.get('fill');rect=shape['rect']
                        if not color or rect.height<75 or rect.width<50:continue
                        if max(abs(a-b) for a,b in zip(color,(233/255,238/255,243/255)))>.01:continue
                        text=compact(page.get_text(clip=rect))
                        if text.startswith(compact(c['name'])):matches.append((page.number+1,text))
                assert len(matches)==1,(c['name'],[p for p,_ in matches])
                for field in c['fields']:
                    assert compact(field['label']+'：'+field['value']) in matches[0][1],(c['name'],matches[0][0],field)


def test_C04_no_heading_is_last_content_on_page(scenario_bundle):
    from report_visual_checks import visual_audit
    a=visual_audit(scenario_bundle)
    assert not a['pdf']['orphan_headings'],a['pdf']['orphan_headings']
    assert not a['word']['orphan_headings'],a['word']['orphan_headings']


def test_C05_no_units_touch_following_labels(scenario_bundle):
    from report_visual_checks import visual_audit
    a=visual_audit(scenario_bundle)
    assert not a['pdf']['glued'],a['pdf']['glued']


def test_C06_medium_references_are_real_links(scenario_bundle):
    from report_visual_checks import visual_audit
    import re
    a=visual_audit(scenario_bundle);r=scenario_bundle['result']
    assert not re.search(r'(?<!报告)见附录\s*[A-Z]',r['pdf']['text'])
    assert 'Word / HTML' not in r['word_text']
    assert all(x['exists'] and x['links']>0 for x in a['word_links']),a['word_links']
    from report_visual_checks import browser_records
    records=browser_records(scenario_bundle)
    assert all(link['exists'] and link['clicked'] and link['opened'] and link['visible'] for b in records for link in b['viewAllLinks'])


def test_native_word_problem_and_appendix_headings_are_navigable(scenario_bundle):
    # Word's Navigation pane excludes headings in tables, even if a TOC lists
    # them. Verify the actual saved body paragraphs, not only style names.
    xml=scenario_bundle['word_xml'];ns={'w':'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
    headings=[''.join(p.xpath('.//w:t/text()',namespaces=ns)) for p in
              xml.xpath('./w:body/w:p[w:pPr/w:pStyle]',namespaces=ns)]
    d=scenario_bundle['document']
    for section in d['sections']:
        if section['kind']=='problems':
            for problem in section['items']:assert problem['title'] in headings
    for table in d['appendices']:
        assert f'附录 {table["letter"]} {table["title"]}' in headings


def test_C07_required_visual_components_exist_in_pdf(scenario_bundle):
    if scenario_bundle['result']['name']!='frozen':return
    from report_visual_checks import visual_audit
    a=visual_audit(scenario_bundle);text=scenario_bundle['result']['pdf']['text'].replace('\u200b','')
    for item in ('客户交付报告','执行摘要','问题类别','受影响对象','检查统计','检查解读',
                 '负责角色','工作量','复核方式','HA 启用覆盖','DRS 启用覆盖','主机 vCPU:pCPU',
                 '物理 CPU 核心','物理内存','超配主机','vCPU 配置 Top 5','VMDK 配置容量 Top 5',
                 'CPU 实际用量 Top 5','内存实际用量 Top 5','虚拟机','快照概况','vSAN 容量使用','物理盘','重同步','安全与证书','网络'):
        assert item in text,item
    for hexvalue in ('A15C07','3F6688'):
        target=[int(hexvalue[i:i+2],16)/255 for i in (0,2,4)]
        assert any(max(abs(x-y) for x,y in zip(color,target))<.01 for color in a['donut_stroke_colors']),hexvalue


def test_C08_initial_html_density_and_mobile_overflow(scenario_bundle):
    from report_visual_checks import browser_records,visual_audit
    records=browser_records(scenario_bundle)
    desktop=next(r for r in records if r['width']==1440);mobile=next(r for r in records if r['width']==390)
    assert desktop['firstScreen']['white_ratio']<=.5,desktop['firstScreen']
    assert mobile['qa']['pageWidth']<=391,mobile['qa']['pageWidth']
    assert all(g['occupied']>=.9 and g['equal'] for r in records for g in r['cardGeometry'])
    a=visual_audit(scenario_bundle)
    assert all(gap['justified'] for gap in a['word']['gaps'])


@pytest.mark.parametrize('categories,limit',[(0,20),(10,20),(11,21),(12,22),(15,25),(16,25),(99,25)])
def test_pdf_budget_follows_category_formula(categories,limit):
    from vstacklens.reports.document_visual import pdf_page_limit
    assert pdf_page_limit(categories)==limit


def _sized_report(clusters,hosts):
    from test_pdf_report import _report
    from copy import deepcopy
    report,context=_report();details=report.asset_inventory['details']
    prototype=deepcopy(details['ClusterComputeResource'][0]);details['ClusterComputeResource']=[]
    for i in range(clusters):
        row=deepcopy(prototype);row.update(object_key=f'cluster-synthetic-{i}',object_name=f'合成集群{i}')
        details['ClusterComputeResource'].append(row)
    prototype=deepcopy(details['HostSystem'][0]);details['HostSystem']=[]
    for i in range(hosts):
        row=deepcopy(prototype);row.update(object_key=f'host-synthetic-{i}',object_name=f'合成主机{i}')
        row['properties'].update(cpu_usage_avg=i+1,memory_usage_avg=i+2,cluster_name=f'合成集群{i%clusters}',asset_location=f'合成集群{i%clusters}')
        details['HostSystem'].append(row)
    report._document_view_cache=None
    return report,context


@pytest.mark.parametrize('count,kind',[(4,'cards'),(5,'table')])
def test_cluster_cards_switch_at_four(count,kind):
    from vstacklens.reports.document_model import get_document
    report,context=_sized_report(count,5);document=get_document(report,context)
    node=next(n for s in document['sections'] if s['kind']=='environment' for n in s['blocks'] if n['id']=='cluster-summary')
    assert node['kind']==kind and len(node['rows'])==count


@pytest.mark.parametrize('count',[10,11])
def test_host_charts_stop_at_ten_and_reference_remainder(count):
    from vstacklens.reports.document_model import get_document
    report,context=_sized_report(2,count);document=get_document(report,context)
    node=next(n for s in document['sections'] if s['kind']=='environment' for n in s['blocks'] if n['id']=='cpu_pct')
    assert len(node['series'])==min(10,count)
    assert bool(node['more'])==(count>10)
    assert node['series'][0]['value']==count


@pytest.mark.parametrize('count',[10,11])
def test_object_attention_table_stops_at_ten_without_losing_appendix_rows(count):
    from vstacklens.reports.document_model import get_document
    report,context=_sized_report(2,count);report.findings=[]
    report.caliber_inputs={'object_results':[{'run_id':report.report_info.run_id,'object_type':'HostSystem',
        'object_key':row['object_key'],'object_name':row['object_name'],'rule_id':'VSL-HOST-002',
        'risk_level':'P3','result_status':'failed'} for row in report.asset_inventory['details']['HostSystem']],
        'findings':[],'rule_checklist':[{'rule_id':'VSL-HOST-002','risk_level':'P3','rule_name':'SSH 服务'}]}
    doc=get_document(report,{})
    table=next(n for s in doc['sections'] if s['kind']=='environment' for n in s['blocks'] if n['id']=='security-attention')
    full=next(a for a in doc['appendices'] if a['id']=='security')
    assert len(table['rows'])==min(count,10) and len(full['rows'])==count
    assert bool(table['notes'])==(count>10)


@pytest.mark.parametrize('count',[15,16])
def test_word_short_table_keeps_whole_only_at_fifteen(count,tmp_path,monkeypatch):
    from vstacklens.reports.document_word import WordDocumentWriter
    from vstacklens.reports.docx_report import DocxReportEngine
    from vstacklens.reports.document_model import get_document,_table,_entry
    from report_document_checks import W
    report,context=_sized_report(1,1);writer=WordDocumentWriter(DocxReportEngine(),report,get_document(report,context))
    node=_table('short-boundary','边界短表',['名称','数值'],[_entry(str(i),f'对象{i}',[f'对象{i}',i]) for i in range(count)])
    writer.table(node)
    rows=writer.document.tables[0]._tbl.xpath('./w:tr')[2:]
    kept=sum(bool(row.xpath('./w:tc/w:p/w:pPr/w:keepNext')) for row in rows)
    assert kept==(count-1 if count<=15 else 0)
