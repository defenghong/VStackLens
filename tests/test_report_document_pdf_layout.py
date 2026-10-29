from copy import deepcopy
from pathlib import Path
import pymupdf


def _background_tracks(page):
    # A restored chart is half-page wide. Identify the actual white track,
    # not a filled foreground segment or the former >200pt full-width layout.
    return [d['rect'] for d in page.get_drawings() if d.get('fill') and min(d['fill'])>.98
            and d['rect'].width>25 and 8<d['rect'].height<15]


def test_allocation_axis_endpoints_align_with_the_actual_track(tmp_path):
    from test_pdf_report import _report
    from vstacklens.reports.pdf_report import PdfReportEngine
    report,context=_report();host=report.asset_inventory['details']['HostSystem'][0]
    host['properties'].update(host_memory_allocation_ratio=1.88)
    other=deepcopy(host);other.update(object_key='axis-host-2',object_name='axis-host-2')
    other['properties']['host_memory_allocation_ratio']=1.28
    report.asset_inventory['details']['HostSystem'].append(other)
    path=PdfReportEngine().render(report,tmp_path/'axis.pdf',report_context=context)
    with pymupdf.open(path) as pdf:
        page=next(p for p in pdf if p.search_for('200.0%'))
        maximum=page.search_for('200.0%')[-1]
        zero=[b for b in page.search_for('0.0%') if abs(b.y0-maximum.y0)<1 and b.x0<maximum.x0][0]
        tracks=[b for b in _background_tracks(page) if b.y1<maximum.y0 and maximum.y0-b.y1<80 and abs(b.x0-zero.x0)<20]
        track=max(tracks,key=lambda box:box.y1)
        assert abs(maximum.x1-track.x1)<1.1,(maximum,track)
        assert abs(zero.x0-track.x0)<1.1,(zero,track)


def test_representative_table_header_stays_with_a_complete_first_row(tmp_path):
    from test_pdf_report import _report
    from vstacklens.reports.pdf_report import PdfReportEngine
    report,context=_report()
    path=PdfReportEngine().render(report,tmp_path/'tail.pdf',report_context=context)
    from vstacklens.reports.document_model import get_document
    from report_pagination_checks import representative_fragments
    assert representative_fragments(path,get_document(report,context))


def test_long_chart_labels_stay_inside_the_label_column(tmp_path):
    from test_pdf_report import _report
    from vstacklens.reports.pdf_report import PdfReportEngine
    from report_document_checks import compact
    report,context=_report();hosts=report.asset_inventory['details']['HostSystem']
    other=deepcopy(hosts[0]);other['object_key']='long-label-host-2'
    other['properties'].update(cpu_usage_avg=42,memory_usage_avg=55,host_memory_allocation_ratio=1.28)
    hosts.append(other)
    for index,host in enumerate(hosts):
        host['object_name']=f'SYN_MANY_PROBLEMS_ESXi_{index:03d}'
    path=PdfReportEngine().render(report,tmp_path/'long-label.pdf',report_context=context)
    found=set()
    with pymupdf.open(path) as pdf:
        for page in pdf:
            tracks=_background_tracks(page)
            spans=[s for b in page.get_text('dict')['blocks'] if 'lines' in b for line in b['lines'] for s in line['spans']]
            for track in tracks:
                containers=[d['rect'] for d in page.get_drawings() if d.get('fill') and
                    max(abs(a-b) for a,b in zip(d['fill'],(233/255,238/255,243/255)))<.008
                    and d['rect'].contains(track) and d['rect'].height>20]
                if not containers:continue
                container=min(containers,key=lambda r:r.get_area())
                labels=[s for s in spans if 'SYN_' in compact(s['text']) and s['bbox'][0]<track.x0
                        and container.contains(pymupdf.Rect(s['bbox']))]
                for span in labels:
                    label=span['bbox']
                    assert label[2]<=track.x0-1,(label,track)
                    found.update(h['object_name'] for h in hosts if compact(h['object_name']) in compact(span['text']))
    assert found=={h['object_name'] for h in hosts},found


def test_visual_execution_statistics_are_hidden_without_saved_results(tmp_path):
    import json,os,subprocess
    from test_pdf_report import _report
    from report_document_checks import json_write,paragraphs_xml
    from vstacklens.reports.pdf_report import PdfReportEngine
    from vstacklens.reports.docx_report import DocxReportEngine
    from vstacklens.reports.html_package import HtmlReportPackageBuilder
    from vstacklens.reports.document_model import get_document
    report,context=_report();document=get_document(report,context)
    assert not document['statistics']['available']
    assert not document['visual']['has_execution_stats']
    assert all(k['label']!='检查统计' for k in document['visual']['opening_kpis'])
    pdf=PdfReportEngine().render(report,tmp_path/'report.pdf',report_context=context)
    word=DocxReportEngine().render(report,tmp_path/'report.docx')
    HtmlReportPackageBuilder().render(report,context,tmp_path/'html',False)
    json_write(tmp_path/'document.json',document)
    with pymupdf.open(pdf) as doc:pdf_text='\n'.join(p.get_text() for p in doc)
    _,word_text=paragraphs_xml(word)
    runtime=Path(os.environ.get('VSTACKLENS_TEST_NODE',r'C:\Users\Public\.cache\codex-runtimes\codex-primary-runtime\dependencies\node'))
    env=os.environ.copy();env['NODE_PATH']=str(runtime/'node_modules')
    run=subprocess.run([str(runtime/'bin/node.exe'),str(Path(__file__).with_name('report_document_browser.cjs')),str(tmp_path)],env=env,capture_output=True,text=True,encoding='utf8',timeout=180)
    assert run.returncode==0,run.stderr[-2000:]
    browser=json.loads((tmp_path/'browser.json').read_text('utf8'))
    for text in [pdf_text,word_text,*[b['qa']['text'] for b in browser]]:
        assert '检查总数' not in text and '通过比例' not in text and '检查统计' not in text
