"""Physical-artifact layout checks C-01..C-08, independent of renderer traces."""
from pathlib import Path
from collections import defaultdict
import json,re,os,subprocess
import pymupdf
from lxml import etree
from report_document_checks import compact,W

def _lines(page):
    cache=getattr(page.parent,'_vstacklens_visual_lines',None)
    if cache is None:
        cache={};page.parent._vstacklens_visual_lines=cache
    if page.number in cache:return cache[page.number]
    result=[]
    for b in page.get_text('dict')['blocks']:
        for line in b.get('lines',[]):
            s=[s for s in line['spans'] if s['text'].strip()]
            if s:result.append({'text':''.join(x['text'] for x in s),'size':max(x['size'] for x in s),
                'bbox':(min(x['bbox'][0] for x in s),min(x['bbox'][1] for x in s),max(x['bbox'][2] for x in s),max(x['bbox'][3] for x in s)), 'spans':s})
    cache[page.number]=result
    return result

def _body(page,word):
    top=51.02 if word else 59.53;bottom=page.rect.height-(51.02 if word else 45.35)
    return [r for r in _lines(page) if r['bbox'][1]>=top-1 and r['bbox'][3]<=bottom+1],top,bottom

def problem_positions(pdf,document,*,word=False):
    rows=[];problems=next((s['items'] for s in document['sections'] if s['kind']=='problems'),[])
    for p in problems:
        hits=[]
        for index,page in enumerate(pdf):
            body,_,_=_body(page,word)
            for r in body:
                if r['size']>=12 and compact(p['title']) in compact(r['text']):hits.append((index,r['bbox'][1]))
        # An appendix heading includes its prefix and is >=16pt; choose the
        # actual first problem heading, before the full appendix starts.
        assert hits,('missing problem heading',p['id'])
        page_index,y=min(hits)
        rows.append({'problem':p['id'],'title':p['title'],'page':page_index+1,'y':round(y,2)})
    for p,row in zip(problems,rows):
        page=pdf[row['page']-1];y=row['y']
        end=min((r['y'] for r in rows if r['page']==row['page'] and r['y']>y+.5),default=page.rect.height)
        text=compact(page.get_text(clip=pymupdf.Rect(0,y-.5,page.rect.width,end-.5)))
        missing=[f['key'] for f in p['fields'] if compact(f['text']) not in text]
        missing.extend('step:'+step for g in p['render_groups'] for step in g['steps'] if compact(step) not in text)
        # Only the title-to-review preamble is atomic. Its table may start
        # here or on a later page, with its own repeated header.
        for group in p['render_groups']:
            if group['title'] and compact(group['title']) not in text:missing.append('step group:'+group['title'])
        meta=' · '.join(f['label']+'：'+f['value'] for f in p['visual']['meta'])
        if meta and compact(meta) not in text:missing.append('review metadata')
        steps=[s for g in p['render_groups'] for s in g['steps']]
        tail=meta or (steps[-1] if steps else p['fields'][-1]['text'] if p['fields'] else p['title'])
        lines=[r for r in _lines(page) if r['bbox'][1]>=y-.5 and r['bbox'][3]<end]
        stream='';bounds=[]
        for line in lines:
            start=len(stream);stream+=compact(line['text']);bounds.append((start,len(stream),line['bbox'][3]))
        at=stream.find(compact(tail));bottom=None
        if at>=0:bottom=max(b for start,finish,b in bounds if finish>at and start<at+len(compact(tail)))
        else:missing.append('preamble ending')
        row.update(missing=missing,preamble_bottom=round(bottom,2) if bottom is not None else None)
    return rows

def headings(document):
    names={s['title'] for s in document['sections']}
    for s in document['sections']:
        if s['kind']=='problems':names.update(p['title'] for p in s['items'])
        if s['kind']=='environment':
            names.update(g['title'] for g in s['groups'])
            names.update(n['title'] for n in s['blocks'] if n['title'])
    return names

def heading_orphans(pdf,document,*,word=False):
    wanted={compact(t) for t in headings(document)};bad=[]
    subtitles={compact(t) for t in (document.get('visual',{}).get('section_subtitles') or {}).values() if t}
    for i,page in enumerate(pdf):
        body,_,_=_body(page,word)
        for row in body:
            if row['size']<12 or not any(t in compact(row['text']) for t in wanted):continue
            if not any(r['bbox'][1]>=row['bbox'][3]-.1 and r is not row and compact(r['text']) not in subtitles for r in body):
                bad.append({'page':i+1,'title':row['text']})
    return bad

def gap_audit(pdf,document,*,word=False,natural_ends=(),word_xml=None):
    """Report every >half tail; accept only an actually taller next block."""
    positions=problem_positions(pdf,document,word=word)
    known_titles={compact(t) for t in headings(document)};rows=[]
    for i,page in enumerate(pdf):
        if i+1 in {1,len(pdf),*natural_ends}:continue
        body,top,bottom=_body(page,word)
        if not body:rows.append({'page':i+1,'justified':False,'reason':'empty body'});continue
        last=max(r['bbox'][3] for r in body)
        for draw in page.get_drawings():
            fill=draw.get('fill');color=draw.get('color');rect=draw['rect']
            visible=(fill is not None and min(fill)<.96) or (color is not None and min(color)<.9 and (draw.get('width') or 0)>0)
            if visible and rect.y0>=top and rect.y1<=bottom:last=max(last,rect.y1)
        available=bottom-last;fraction=available/(bottom-top)
        if fraction<=.5:continue
        next_page=pdf[i+1];next_body,nt,nb=_body(next_page,word)
        candidates=[];next_problems=[p for p in positions if p['page']==i+2]
        if next_problems:
            first=min(next_problems,key=lambda p:p['y'])
            if first['preamble_bottom'] is not None:
                candidates.append((first['preamble_bottom']-first['y']+6,'标题至复核方式：'+first['title']))
        if next_body:
            first_y=min(r['bbox'][1] for r in next_body)
            for draw in next_page.get_drawings():
                rect=draw['rect'];fill=draw.get('fill')
                if fill and min(fill)<.96 and rect.width>next_page.rect.width*.23 and rect.y0<=first_y+5 and rect.y1>=first_y+20:
                    candidates.append((rect.height,'下一页同排完整卡片/图表'))
                elif fill and min(fill)<.96 and rect.width>next_page.rect.width*.23 and first_y+5<rect.y0<=first_y+80:
                    above=[r for r in next_body if r['bbox'][3]<rect.y0+.5]
                    subtitles={compact(s) for s in document.get('visual',{}).get('section_subtitles',{}).values() if s}
                    only_heading=above and all(any(t in compact(r['text']) for t in known_titles)
                        or any(compact(r['text']) in s for s in subtitles)
                        or re.fullmatch(r'\d{2}',r['text'].strip()) for r in above)
                    if only_heading:
                        before=0
                        if word and word_xml is not None:
                            for p in word_xml.xpath('//w:p[w:pPr/w:pStyle]',namespaces=W):
                                text=compact(''.join(p.xpath('.//w:t/text()',namespaces=W)))
                                if text and any(text==compact(r['text']) for r in above):
                                    values=p.xpath('./w:pPr/w:spacing/@w:before',namespaces=W)
                                    if values:before=max(before,int(values[0])/20)
                        # A heading's before-spacing is suppressed at a page
                        # top, but is needed when fitting after earlier content.
                        leading=max(0,first_y-nt) if word else 0
                        candidates.append((rect.y1-first_y+leading+before,
                            f'标题及同排完整卡片/图表（段前 {before:g} pt；首行留量 {leading:.2f} pt）'))
        taller=[(h,label) for h,label in candidates if h>available-1]
        rows.append({'page':i+1,'tail_fraction':round(fraction,3),'remaining_pt':round(available,2),
          'justified':bool(taller),'next_block_height_pt':round(max((h for h,_ in taller),default=0),2),
          'reason':max(taller,default=(0,'未找到足够高的后续完整块'))[1]})
    return rows

def _same_color(a,b):return a is not None and len(a)==3 and max(abs(x-y) for x,y in zip(a,b))<.008

def card_rows(pdf):
    groups=[];surface=(233/255,238/255,243/255)
    for i,page in enumerate(pdf):
        rects=[]
        for d in page.get_drawings():
            r=d['rect']
            if _same_color(d.get('fill'),surface) and r.width>page.rect.width*.12 and r.height>22:
                if not any(abs(r.x0+a.x0*-1)<.5 and abs(r.y0-a.y0)<.5 and abs(r.width-a.width)<.5 for a in rects):rects.append(r)
        buckets=[]
        for r in sorted(rects,key=lambda r:(r.y0,r.x0)):
            found=next((g for g in buckets if abs(g[0].y0-r.y0)<2),None)
            if found is None:buckets.append([r])
            else:found.append(r)
        width=page.rect.width-2*(56.69 if page.rect.width<700 else 28.346)
        for g in buckets:
            if len(g)<2:continue
            occupied=sum(r.width for r in g)/width;equal=max(r.width for r in g)-min(r.width for r in g)<2
            groups.append({'page':i+1,'cards':len(g),'occupied':round(occupied,4),'equal_width':equal,
                          'pass':occupied>=.9 and equal})
    return groups

def glued_values(pdf):
    out=[];pattern=re.compile(r'(?:\d[\d,.]*[%％]|(?:GB|TB|MB|GHz|MHz|vCPU))(?=[A-Za-z\u4e00-\u9fff])')
    for i,page in enumerate(pdf):
        for line in _lines(page):
            spans=line['spans'];text=''
            for j,s in enumerate(spans):
                if j and s['bbox'][0]-spans[j-1]['bbox'][2]>.8:text+=' '
                text+=s['text'].replace('\u200b','')
            for m in pattern.finditer(text):out.append({'page':i+1,'text':text,'match':m.group()})
    return out

def word_links(xml,document):
    names=set(xml.xpath('//w:bookmarkStart/@w:name',namespaces=W));out=[]
    for p in next((s['items'] for s in document['sections'] if s['kind']=='problems'),[]):
        if not p['reference']:continue
        anchor='d_appendix_'+p['appendix']
        links=xml.xpath('//w:hyperlink[@w:anchor=$anchor]',namespaces=W,anchor=anchor)
        out.append({'problem':p['id'],'anchor':anchor,'exists':anchor in names,'links':len(links)})
    return out

def visual_audit(bundle):
    if '_visual_audit' in bundle:return bundle['_visual_audit']
    d=bundle['document'];r=bundle['result'];root=Path(bundle['root']);result={}
    for fmt,path,word in [('pdf',root/'report.pdf',False),('word',Path(r['word_conversion']['pdf']),True)]:
        with pymupdf.open(path) as pdf:
            positions=problem_positions(pdf,d,word=word)
            first=r[fmt]['pages'][0];top=51.02 if word else 59.53;bottom=pdf[0].rect.height-(51.02 if word else 45.35)
            cover={'fraction':round((first['content_bottom']-top)/(bottom-top),3),
              'required_text':all(v in pdf[0].get_text() for v in ('客户交付报告','总体结论','问题类别','受影响对象','检查统计'))}
            result[fmt]={'problems':positions,'cover':cover,'card_rows':card_rows(pdf),
              'orphan_headings':heading_orphans(pdf,d,word=word),'glued':glued_values(pdf),
              'gaps':gap_audit(pdf,d,word=word,natural_ends=[r['word']['body']] if word else [],word_xml=bundle['word_xml'] if word else None)}
            if not word:
                colors={tuple(round(x,3) for x in draw.get('color') or ()) for page in pdf for draw in page.get_drawings() if (draw.get('width') or 0)>5}
                result['donut_stroke_colors']=[list(c) for c in colors if c]
    result['word_links']=word_links(bundle['word_xml'],d)
    (root/'visual-checks.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),'utf8')
    bundle['_visual_audit']=result;return result

def browser_records(bundle):
    root=Path(bundle['root']);record=root/'browser.json'
    if not record.is_file():
        runtime=Path(os.environ.get('VSTACKLENS_TEST_NODE',r'C:\Users\Public\.cache\codex-runtimes\codex-primary-runtime\dependencies\node'))
        env=os.environ.copy();env['NODE_PATH']=str(runtime/'node_modules')
        p=subprocess.run([str(runtime/'bin/node.exe'),str(Path(__file__).with_name('report_document_browser.cjs')),str(root)],env=env,capture_output=True,text=True,encoding='utf8',errors='replace',timeout=180)
        assert p.returncode==0,p.stderr[-4000:]
    return json.loads(record.read_text('utf8'))
