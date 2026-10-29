"""Offline, artifact-level regression checks for the six report scenarios.

These checks do not connect to VMware.  All generated material belongs to the
caller's temporary directory. Word COM is intentionally not used here.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import time
from zipfile import ZipFile
from lxml import etree
import pymupdf

FORBIDDEN = ('当次等级','个对象存在','当前状态为','建议状态为','复跑','明确判定','。。','明细 明细','GiB',
             '维护窗口','未采集','不可用','未确认','待确认','整体正常','运行用量占比','关联次数')
NAMES = ('frozen','minimal','large','many_problems','heterogeneous','boundary')
EXPECTED = {
    'frozen':(10,71,93,1378,1285,93,35), 'minimal':(0,0,0,156,156,0,43),
    'large':(10,1370,1382,18287,16905,1382,40),
    'many_problems':(15,118,124,1687,1564,123,35),
    'heterogeneous':(2,2,2,843,841,2,43), 'boundary':(4,4,4,305,301,4,39),
}
W={'w':'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}


def compact(text):
    return re.sub(r'\s+','',text.replace('\u200b',''))


def forbidden_hits(text):
    normalized=compact(text)
    return [word for word in FORBIDDEN if compact(word) in normalized]


def json_write(path,value):
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2,default=str),'utf-8')


def evidence_fingerprint(report):
    """Stream the saved inputs instead of doubling a large context in RAM."""
    fields=('caliber_inputs','findings','asset_inventory','vsan_summary','report_info','customer_info')
    result={}
    encoder=json.JSONEncoder(ensure_ascii=False,sort_keys=True,default=lambda x:x.model_dump() if hasattr(x,'model_dump') else str(x))
    for key in fields:
        digest=hashlib.sha256()
        for part in encoder.iterencode(getattr(report,key)):digest.update(part.encode('utf-8'))
        result[key]=digest.hexdigest()
    return result


def generator():
    file=Path(__file__).parent/'fixtures/report_scenarios/generate.py'
    spec=importlib.util.spec_from_file_location('report_scenario_generator',file)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def paragraphs_xml(path):
    with ZipFile(path) as archive:
        document=etree.fromstring(archive.read('word/document.xml'))
        visible=[]
        for name in archive.namelist():
            if name=='word/document.xml' or re.fullmatch(r'word/(?:header|footer)\d+\.xml',name):
                root=etree.fromstring(archive.read(name))
                visible.extend(''.join(p.itertext()) for p in root.xpath('//w:t',namespaces=W))
    return document,'\n'.join(visible)


def inspect_pdf(path,*,word=False):
    pdf=pymupdf.open(path);pages=[];out=[];appendix=None
    for index,page in enumerate(pdf):
        text=page.get_text();spans=[s for b in page.get_text('dict')['blocks'] if 'lines' in b for l in b['lines'] for s in l['spans'] if s['text'].strip()]
        for s in spans:
            x0,y0,x1,y1=s['bbox']
            if min(x0,y0)<-0.8 or x1>page.rect.width+0.8 or y1>page.rect.height+0.8:
                out.append({'page':index+1,'text':s['text'],'bbox':s['bbox']})
        # Heading 1 is 16pt; a TOC entry or repeated table title is not an
        # appendix start. This also works after an actual native TOC update.
        if word and appendix is None and any(s['size']>=15 and re.search(r'附录\s*A\b',s['text']) for s in spans):
            appendix=index+1
        top=51.02 if word else 59.53;bottom=page.rect.height-(51.02 if word else 45.35)
        body=[s for s in spans if s['bbox'][1]>=top and s['bbox'][3]<=bottom]
        last=max((s['bbox'][3] for s in body),default=top)
        geometry=[d['rect'].y1 for d in page.get_drawings() if d['rect'].y0>=top and d['rect'].y1<=bottom
                  and (d['rect'].width>2 or d['rect'].height>2)]
        last=max([last,*geometry])
        pages.append({'page':index+1,'text':text,'content_bottom':round(last,2),
                      'tail_blank_fraction':round(max(0,bottom-last)/(bottom-top),3),
                      'min_size':min((s['size'] for s in spans),default=0),
                      'paragraph_sizes':[s['size'] for s in spans if s['text'].startswith(('当前值：','判定标准：','影响：','处理建议：'))]})
    result={'total':len(pdf),'body':(appendix-1 if appendix else len(pdf)),
            'appendix':len(pdf)-(appendix-1) if appendix else 0,
            'appendix_start':appendix,'outside':out,'pages':pages,'title':pdf.metadata.get('title'),
            'bookmarks':pdf.get_toc(),'text':'\n'.join(p['text'] for p in pages)}
    pdf.close();return result


def convert_word(path,root):
    """Only this candidate, isolated LO profile, timeout, owned-process audit."""
    executable=Path(os.environ.get('VSTACKLENS_TEST_LIBREOFFICE',''))
    if not executable.is_file():
        return {'available':False,'reason':'LibreOffice is not installed; OOXML checks still ran'}
    root.mkdir(parents=True,exist_ok=True);profile=root/'lo-profile';profile.mkdir(exist_ok=True)
    before=hashlib.sha256(path.read_bytes()).hexdigest()
    command=[str(executable),'--headless','-env:UserInstallation='+profile.as_uri(),
             '--convert-to','pdf','--outdir',str(root),str(path)]
    started=time.perf_counter()
    result=subprocess.run(command,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=240,
                          creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    (root/'conversion.log').write_text(result.stdout+'\n'+result.stderr,'utf-8')
    assert result.returncode==0,(result.returncode,result.stderr)
    assert hashlib.sha256(path.read_bytes()).hexdigest()==before,'LO changed candidate Word'
    pdf=root/(path.stem+'.pdf');assert pdf.is_file(),result.stdout
    # A private UserInstallation prevents borrowing a user's existing process.
    query="@(Get-CimInstance Win32_Process -Filter \"Name = 'soffice.exe' OR Name = 'soffice.bin'\" | Where-Object { $_.CommandLine -like '*"+str(profile).replace('\\','*')+"*' } | Select-Object ProcessId,CommandLine) | ConvertTo-Json -Compress"
    remaining=subprocess.run(['powershell','-NoProfile','-Command',query],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=15)
    assert remaining.returncode==0 and remaining.stdout.strip() in ('','[]'),'Owned LibreOffice process remained: '+remaining.stdout
    return {'available':True,'pdf':str(pdf),'command':command,'exit_code':result.returncode,
            'seconds':round(time.perf_counter()-started,3),'owned_processes_after':remaining.stdout.strip(),
            'note':'Word pages are LibreOffice conversion results; Microsoft Word may paginate differently'}


def render_case(name,root,*,cached_source=None,native_word=False,input_root=None):
    from vstacklens.reports.document_model import get_document
    from vstacklens.reports.customer_view import get_customer_problem_view
    from vstacklens.reports.pdf_report import PdfReportEngine
    from vstacklens.reports.docx_report import DocxReportEngine
    from vstacklens.reports.html_package import HtmlReportPackageBuilder
    root=Path(root);root.mkdir(parents=True,exist_ok=True)
    gen=generator()
    if cached_source and name!='frozen':
        # Explicit reviewed input reuse for development, never silently accepted
        # by load_scenario's current-code fingerprint guard.
        database=Path(cached_source)/'scenario.db';manifest=json.loads((database.parent/'manifest.json').read_text('utf-8'))
        assert hashlib.sha256(database.read_bytes()).hexdigest()==manifest['database_sha256']
        report,context=gen._load_db(name,database)
        json_write(root/'input-provenance.json',{'reviewed_cache':str(database),'sha256':manifest['database_sha256'],
            'source_code_fingerprint':manifest['generator_and_rules_sha256'],'mode':'explicit development reuse; final suite generates current fixtures'})
    else:
        report,context=gen.load_scenario(name,Path(input_root) if input_root else root/'scenario-input')
    original=evidence_fingerprint(report);document=get_document(report,context)
    json_write(root/'document.json',document)
    view=get_customer_problem_view(report,context)
    json_write(root/'problem-evidence.json',[{'id':c.display['category_id'],'level':c.display['level'],'objects':c.display['objects'],
                                            'records':c.category['finding_count']} for c in view.categories])
    timings={}
    for label,operation in [('pdf',lambda:PdfReportEngine().render(report,root/'report.pdf',report_context=context)),
                             ('word',lambda:DocxReportEngine().render(report,root/'report.docx')),
                             ('html',lambda:HtmlReportPackageBuilder().render(report,context,root/'html',False))]:
        old=os.environ.get('VSTACKLENS_WORD_TOC_MODE')
        if not native_word:os.environ['VSTACKLENS_WORD_TOC_MODE']='disabled'
        started=time.perf_counter();operation();timings[label]=round(time.perf_counter()-started,3)
        if old is None:os.environ.pop('VSTACKLENS_WORD_TOC_MODE',None)
        else:os.environ['VSTACKLENS_WORD_TOC_MODE']=old
    # ensure_report already applied the approved batch-two applicability
    # projection before this batch. Its derived presentation fields are lazy;
    # evidence, saved records and assets must remain byte-for-byte unchanged.
    after=evidence_fingerprint(report)
    for field in original:
        assert after[field]==original[field],f'Renderer changed source evidence: {field}'
    json_write(root/'source-preservation.json',{'evidence_fields_unchanged':True,
        'sha256':after,
        'projection':'Existing approved-applicability-20261023-v1; no new result decisions'})
    word_root,word_text=paragraphs_xml(root/'report.docx')
    pdf=inspect_pdf(root/'report.pdf');conversion=convert_word(root/'report.docx',root/'word-lo')
    word_pdf=inspect_pdf(Path(conversion['pdf']),word=True) if conversion['available'] else None
    payload=json.loads((root/'html/data/customer_report_payload.json').read_text('utf-8'))['document']
    result={'name':name,'root':str(root),'counts':document['counts'],'statistics':document['statistics'],
            'passed_count':document['passed_count'],'generation_seconds':timings,'pdf':pdf,'word':word_pdf,'word_conversion':conversion,
            'word_text':word_text,'html_bytes':sum(p.stat().st_size for p in (root/'html').rglob('*') if p.is_file())}
    from vstacklens.reports.document_output import document_for_medium
    assert payload==document_for_medium(document,'html'),'HTML selected different shared data'
    json_write(root/'result.json',result)
    return {'result':result,'document':document,'word_xml':word_root,'root':root}


def model_assertions(bundle):
    d=bundle['document'];r=bundle['result'];name=r['name']
    observed=(*[d['counts'][k] for k in ('categories','objects','records')],
              *[d['statistics'][k] for k in ('total','passed','failed')],d['passed_count'])
    assert observed==EXPECTED[name],observed
    ids=[]
    for a in d['appendices']:
        assert a['title'] and a['rows'] and a['headers']
        assert len({r['id'] for r in a['rows']})==len(a['rows'])
        assert all(any(row['cells'][i] not in ('','—','无数据') for row in a['rows']) for i in range(len(a['headers'])))
        ids.extend(row['id'] for row in a['rows'])
    assert len(set(ids))==len(ids)
    assert [a['letter'] for a in d['appendices']]==[chr(65+i) for i in range(len(d['appendices']))]
    for s in d['sections']:
        if s['kind']=='problems':
            for p in s['items']:
                assert len(p['representative_keys'])<=5
                assert p['representative_table'] is None or len(p['representative_table']['rows'])<=5
                a=next(a for a in d['appendices'] if a['letter']==p['appendix'])
                assert len(a['rows'])==p['objects']
                if p['objects']>5:
                    assert p['appendix'] in p['reference']
                    if not p['iso_groups']:
                        assert p['objects']==len(p['representative_keys'])+p['remaining']
                else:assert not p['reference']
                if p['reference'] and r['word']:
                    word_reference=p.get('references',{}).get('word',p['reference'])
                    pages=[page for page in r['word']['pages'] if compact(word_reference) in compact(page['text'])]
                    names=[row['cells'][0] for row in p['representative_table']['rows'] if row['cells'][0]]
                    assert pages and all(any(compact(name) in compact(page['text']) for name in names) for page in pages),p['id']
        if s['kind']=='environment':
            for node in s['blocks']:
                if node['kind']=='table' and node['role']=='objects':assert len(node['rows'])<=10
                if node['kind']=='chart':assert len(node['series'])<=10
    # Visible strings only: private decision notes, trace IDs and sorting rules
    # must not be searched as though customers could read them.
    texts=[r['pdf']['text'],r['word_text']]
    if r['word']:texts.append(r['word']['text'])
    for text in texts:
        assert forbidden_hits(text)==[],forbidden_hits(text)
        assert 'run_' not in text and 'VSL-' not in text
        assert not re.search(r'\b(?:True|False|poweredOn|poweredOff|HostSystem|VirtualMachine)\b',text)
    for source in texts:
        # Totals are now shown in metric cards, not duplicated as one sentence.
        # Their actual glyph values are checked by assert_cover_deduplication.
        assert '问题类别' in source and '受影响对象' in source
        assert compact(d['statistics']['text']) in compact(source)
    assert not r['pdf']['outside'],r['pdf']['outside']
    from vstacklens.reports.document_visual import pdf_page_limit
    assert r['pdf']['total']<=pdf_page_limit(d['counts']['categories']),r['pdf']['total']
    assert r['pdf']['title']==d['title']
    assert r['pdf']['bookmarks']
    assert all(page['min_size']>=9.9 for page in r['pdf']['pages'])
    assert all(abs(size-11)<.1 for page in r['pdf']['pages'] for size in page['paragraph_sizes'])
    references=set(re.findall(r'附录\s*([A-Z]+)',r['pdf']['text'].replace('\u200b','')))
    assert references<={a['letter'] for a in d['appendices']}
    assert '问题总览' not in r['pdf']['pages'][0]['text'] or d['counts']['categories']>5 # only the overflow link may refer to it
    assert '资产规模' not in r['pdf']['pages'][0]['text']
    xml=bundle['word_xml']
    instructions=' '.join(xml.xpath('//w:instrText/text()',namespaces=W))
    assert 'TOC \\o "1-3"' in instructions and '\\h' in instructions
    assert len(xml.xpath('//w:pPr/w:pStyle[starts-with(@w:val,"Heading")]',namespaces=W))>0
    appendix_titles=[''.join(p.xpath('.//w:t/text()',namespaces=W)) for p in xml.xpath('//w:p[w:pPr/w:pStyle[@w:val="Heading1"]]',namespaces=W)]
    assert [v for v in appendix_titles if v.startswith('附录 ')]==['附录 '+a['letter']+' '+a['title'] for a in d['appendices']]
    if r['word']:
        assert r['word']['body']<=r['pdf']['body']+3,(r['word']['body'],r['pdf']['body'])
        assert not r['word']['outside'],r['word']['outside']
        natural_ends={1,r['word']['total'],r['word']['body']}
        from report_visual_checks import gap_audit
        with pymupdf.open(Path(r['word_conversion']['pdf'])) as actual:
            gaps=gap_audit(actual,d,word=True,natural_ends=natural_ends,word_xml=xml)
        assert not [gap for gap in gaps if not gap['justified']],gaps
    if not d['vsan']:
        assert all('vsan' not in text.lower() for text in texts)
    if d['esa']:
        assert all('磁盘组' not in text for text in texts)
    return observed
