"""Physical checks for the three accepted presentation-only follow-ups."""
from pathlib import Path
import json
import pymupdf
from docx import Document
from report_document_checks import compact,W


def charts(document):
    visual=document['visual'];nodes=[visual[k] for k in ('allocation_cpu','allocation_memory') if k in visual]
    nodes += [n for s in document['sections'] if s['kind']=='environment' for g in s['groups']
              if g['id']=='host-resources' for n in g['blocks'] if n['kind']=='chart' and n['id']!='memory_allocation_pct']
    return [g for g in nodes if not g.get('equal_text')]


def assert_pdf_axes(bundle):
    result=[]
    with pymupdf.open(Path(bundle['root'])/'report.pdf') as pdf:
        for chart in charts(bundle['document']):
            candidates=[]
            for page in pdf:
                titles=page.search_for(chart['title'])
                for shape in page.get_drawings():
                    color=shape.get('fill');rect=shape['rect']
                    if not color or max(abs(a-b) for a,b in zip(color,(233/255,238/255,243/255)))>.01:continue
                    if rect.height<25 or not any(rect.contains(t) for t in titles):continue
                    candidates.append((page,rect))
            assert candidates,(chart['id'],'no rendered chart fragments')
            for page,rect in candidates:
                spans=[s for b in page.get_text('dict',clip=rect)['blocks'] for line in b.get('lines',[]) for s in line['spans'] if abs(s['size']-10)<.12]
                ticks=[]
                for tick in sorted(chart['ticks'],key=lambda t:t['value']):
                    matches=[s for s in spans if compact(s['text'])==compact(tick['text'])]
                    assert len(matches)==1,(chart['id'],page.number+1,tick,matches)
                    ticks.append(matches[0])
                assert max(s['bbox'][1] for s in ticks)-min(s['bbox'][1] for s in ticks)<1,(chart['id'],ticks)
                assert all(b['bbox'][0]-a['bbox'][2]>=2 for a,b in zip(ticks,ticks[1:])),(chart['id'],ticks)
                assert all(rect.contains(pymupdf.Rect(t['bbox'])) for t in ticks)
                result.append({'id':chart['id'],'page':page.number+1,'tick_text':[t['text'] for t in ticks],'boxes':[t['bbox'] for t in ticks]})
    return result


def assert_cover_deduplication(bundle):
    d=bundle['document'];r=bundle['result'];phrase=compact(d['opening']['problem_text'])
    assert phrase not in compact(r['pdf']['pages'][0]['text'])
    assert phrase not in compact(r['word']['pages'][0]['text'])
    for key in ('conclusion','statistics'):
        if d['opening'][key]:
            assert compact(d['opening'][key]) in compact(r['pdf']['pages'][0]['text'])
            assert compact(d['opening'][key]) in compact(r['word']['pages'][0]['text'])
    for p in d['opening']['priorities']:
        assert compact(p['title']) in compact(r['pdf']['pages'][0]['text'])
        assert compact(p['title']) in compact(r['word']['pages'][0]['text'])
    for file in (Path(bundle['root'])/'report.pdf',Path(r['word_conversion']['pdf'])):
        with pymupdf.open(file) as pdf:
            page=pdf[0]
            for item in d['visual']['opening_kpis']:
                label=page.search_for(item['label']);assert label,item['label']
                boxes=[shape['rect'] for shape in page.get_drawings() if shape.get('fill') and
                       max(abs(a-b) for a,b in zip(shape['fill'],(233/255,238/255,243/255)))<.01 and
                       any(shape['rect'].contains(x) for x in label)]
                assert boxes,(file,item['label'])
                box=min(boxes,key=lambda b:b.get_area())
                values=[s['text'] for b in page.get_text('dict',clip=box)['blocks'] for line in b.get('lines',[]) for s in line['spans'] if s['size']>=17]
                assert compact(item['value']) in [compact(x) for x in values],(file,item,values)


def assert_word_field_alignment(bundle):
    d=bundle['document'];xml=bundle['word_xml'];root=Path(bundle['root']);word=Document(root/'report.docx')
    expected=word.sections[0].left_margin.pt+63
    paragraphs=xml.xpath('//w:p[w:r/w:t="当前值：" or w:r/w:t="判定标准：" or w:r/w:t="影响：" or w:r/w:t="处理建议："]',namespaces=W)
    expected_count=sum(len(p['fields']) for s in d['sections'] if s['kind']=='problems' for p in s['items'])
    assert len(paragraphs)==expected_count
    for p in paragraphs:
        assert p.xpath('./w:pPr/w:ind/@w:left',namespaces=W)==['1260']
        assert p.xpath('./w:pPr/w:ind/@w:hanging',namespaces=W)==['1260']
        assert p.xpath('./w:pPr/w:tabs/w:tab[@w:val="left"]/@w:pos',namespaces=W)==['1260']
    from report_visual_checks import visual_audit
    positions=visual_audit(bundle)['word']['problems'];observed=[]
    with pymupdf.open(rpath:=Path(bundle['result']['word_conversion']['pdf'])) as pdf:
        for section in d['sections']:
            if section['kind']!='problems':continue
            for p in section['items']:
                at=next(x for x in positions if x['problem']==p['id']);page=pdf[at['page']-1]
                for f in p['fields']:
                    labels=[x for x in page.search_for(f['label']+'：') if x.y0>=at['y']-1]
                    assert labels,(p['id'],f['label'])
                    label=min(labels,key=lambda x:x.y0)
                    prefix=f['text'].splitlines()[0][:8]
                    values=[x for x in page.search_for(prefix) if abs(x.y0-label.y0)<2]
                    assert values,(p['id'],f['label'],prefix)
                    value=min(values,key=lambda x:x.x0)
                    assert abs(value.x0-expected)<1.5,(p['id'],f['label'],value.x0,expected)
                    observed.append({'problem':p['id'],'field':f['label'],'page':at['page'],'content_x':value.x0})
    return observed
