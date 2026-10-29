from pathlib import Path
import json,subprocess
import pytest


@pytest.mark.parametrize('count',[5,6,7,8,9,10])
def test_three_row_minimum_and_short_remainder_in_rendered_charts(count,tmp_path):
    from test_report_document_scenarios import _sized_report
    from vstacklens.reports.document_model import get_document
    from vstacklens.reports.document_pdf import pdf_payload
    from vstacklens.reports.pdf_report import PdfReportEngine
    from vstacklens.resources import package_resource_path
    from report_pagination_checks import chart_card_fragments,chart_spacing_deltas
    report,context=_sized_report(1,count)
    for i,host in enumerate(report.asset_inventory['details']['HostSystem']):
        host['object_name']=f'SYN_MINROWS_TRANSPORT_HOST_{i:03d}_'+('TESTNODE_'*5)
    document=get_document(report,context);payload=pdf_payload(document)
    group=next(g for s in payload['sections'] if s['kind']=='environment' for g in s['groups'] if g['id']=='host-resources')
    charts=[n for n in group['blocks'] if n['kind']=='chart' and n['id'] in {'cpu_pct','memory_pct'}]
    assert len(charts)==2 and all(len(g['series'])==count for g in charts)
    template=package_resource_path('reports','templates','customer-document.typ').read_text('utf8').split('// Cover has only approved decision facts')[0]
    template+='\n#let cases=json("chart-cases.json")\n#v(80mm)\n#grid(columns:(1fr,1fr),gutter:4mm,..cases.map(graph))\n'
    (tmp_path/'document.typ').write_text(template,'utf8')
    (tmp_path/'document.json').write_text(json.dumps(payload,ensure_ascii=False),'utf8')
    (tmp_path/'chart-cases.json').write_text(json.dumps(charts,ensure_ascii=False),'utf8')
    output=tmp_path/'charts.pdf';engine=PdfReportEngine()
    command=[str(engine._typst_binary()),'compile','--root',str(tmp_path),'--font-path',r'C:\Windows\Fonts',str(tmp_path/'document.typ'),str(output)]
    result=subprocess.run(command,capture_output=True,text=True,encoding='utf8',errors='replace',timeout=180)
    assert result.returncode==0,result.stderr[-4000:]
    cards=chart_card_fragments(output,document,only_ids={'cpu_pct','memory_pct'})
    assert len(cards)==2
    for card in cards:
        if count==5:assert len(card['fragments'])==1,card
        else:
            assert len(card['fragments'])>=2,card
            assert all(len(p['rows'])>=3 for p in card['fragments']),card
    # A tall reference page allows the unchanged atomic card to render once.
    # Compare geometry, not guessed renderer row heights or hard-coded gaps.
    reference=tmp_path/'reference.pdf'
    source=template.split('\n#let cases=json("chart-cases.json")')[0]
    source+='\n#set page(width:297mm,height:450mm,flipped:false)\n#let cases=json("chart-cases.json")\n#grid(columns:(1fr,1fr),gutter:4mm,..cases.map(graph-whole))\n'
    (tmp_path/'reference.typ').write_text(source,'utf8')
    ref_command=[*command[:-2],str(tmp_path/'reference.typ'),str(reference)]
    ref_run=subprocess.run(ref_command,capture_output=True,text=True,encoding='utf8',errors='replace',timeout=180)
    assert ref_run.returncode==0,ref_run.stderr[-4000:]
    intact=chart_card_fragments(reference,document,only_ids={'cpu_pct','memory_pct'})
    assert chart_spacing_deltas(intact,cards)
