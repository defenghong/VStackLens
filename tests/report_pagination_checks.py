"""Check rendered pagination independently of the renderer's estimates."""
from pathlib import Path
from collections import Counter
import json
import pymupdf
from report_document_checks import compact,W
from report_visual_checks import _body,_lines,problem_positions


def representative_fragments(path,document,*,word=False):
    records=[]
    problems=next((s['items'] for s in document['sections'] if s['kind']=='problems'),[])
    with pymupdf.open(path) as pdf:
        positions=problem_positions(pdf,document,word=word)
        for index,(problem,position) in enumerate(zip(problems,positions)):
            table=problem['representative_table']
            if not table:continue
            start=(position['page']-1,position['y'])
            if index+1<len(positions):
                other=positions[index+1];end=(other['page']-1,other['y'])
            else:
                later=[]
                problem_section=next(i for i,s in enumerate(document['sections']) if s['kind']=='problems')
                titles={compact(s['title']) for s in document['sections'][problem_section+1:]}
                for page in pdf:
                    for line in _lines(page):
                        if line['size']>=14.9 and any(t in compact(line['text']) for t in titles):
                            point=(page.number,line['bbox'][1])
                            if point>start:later.append(point)
                end=min(later,default=(len(pdf),0))
            found=set();fragments=[]
            for number in range(start[0],min(end[0]+1,len(pdf))):
                page=pdf[number];_,top,bottom=_body(page,word)
                y0=max(top,start[1]-.5) if number==start[0] else top
                y1=min(bottom,end[1]-.5) if number==end[0] else bottom
                if y1<=y0:continue
                text=compact(page.get_text(clip=pymupdf.Rect(0,y0,page.rect.width,y1)))
                rows=[i for i,r in enumerate(table['rows']) if compact(''.join(r['cells'])) in text]
                header=compact(''.join(table['headers'])) in text
                if rows or header:
                    assert header,(problem['id'],number+1,'data without repeated header')
                    assert rows,(problem['id'],number+1,'header without a complete first data row')
                    assert compact(table['title']) in text,(problem['id'],number+1,'missing table caption')
                    found.update(rows);fragments.append({'page':number+1,'rows':rows,'header':True})
            assert found==set(range(len(table['rows']))),(problem['id'],found,len(table['rows']))
            records.append({'problem':problem['id'],'heading_page':position['page'],'fragments':fragments})
    return records


def pdf_toc_rows(path,document):
    with pymupdf.open(path) as pdf:
        first=document['sections'][0]['title']
        starts=[(page.number,line['bbox'][1]) for page in pdf for line in _lines(page)
                if line['size']>=14.9 and compact(line['text'])==compact(first)]
        assert starts,first
        end=min(starts);lines=[]
        for number in range(1,end[0]+1):
            for line in _lines(pdf[number]):
                if number==end[0] and line['bbox'][1]>=end[1]-.5:continue
                lines.append((number+1,line))
        expected=[]
        for index,section in enumerate(document['sections'],1):
            expected.append((1,f'{index:02d}'+section['title']))
            if section['kind']=='problems':expected.extend((2,p['level']+p['title']) for p in section['items'])
        records=[]
        for level,title in expected:
            matches=[(page,line) for page,line in lines if compact(line['text']).startswith(compact(title))]
            assert len(matches)==1,(title,[(p,l['text']) for p,l in matches])
            page,line=matches[0];records.append({'title':title,'level':level,'page':page,'y':line['bbox'][1],'x':line['bbox'][0]})
        assert [(r['page'],r['y']) for r in records]==sorted((r['page'],r['y']) for r in records),records
        primary=[r['x'] for r in records if r['level']==1]
        assert max(primary)-min(primary)<1,primary
        for row in records:
            if row['level']==2:assert 10<row['x']-min(primary)<35,row
        return records


def pdf_tail_gaps(path):
    gaps=[]
    with pymupdf.open(path) as pdf:
        for number in range(len(pdf)-1):
            page=pdf[number];body,top,bottom=_body(page,False)
            edges=[r['bbox'][3] for r in body]
            for drawing in page.get_drawings():
                rect=drawing['rect'];fill=drawing.get('fill');stroke=drawing.get('color')
                visible=(fill is not None and min(fill)<.96) or (stroke is not None and min(stroke)<.9 and (drawing.get('width') or 0)>0)
                if visible and rect.y0>=top and rect.y1<=bottom:edges.append(rect.y1)
            last=max(edges,default=top);fraction=(bottom-last)/(bottom-top)
            if fraction>.5:gaps.append({'page':number+1,'tail_fraction':fraction,'remaining_pt':bottom-last})
    return gaps


def word_preamble_keep_chain(bundle):
    from docx import Document
    from docx.text.paragraph import Paragraph
    saved=Document(Path(bundle['root'])/'report.docx')
    document=bundle['document'];children=list(saved.element.body)
    def effective(paragraph,attribute):
        value=getattr(paragraph.paragraph_format,attribute)
        if value is not None:return value
        style=paragraph.style;seen=set()
        while style is not None and style.style_id not in seen:
            seen.add(style.style_id);value=getattr(style.paragraph_format,attribute)
            if value is not None:return value
            style=style.base_style
        return False
    problems=next((s['items'] for s in document['sections'] if s['kind']=='problems'),[])
    for problem in problems:
        if not problem['representative_table']:continue
        matches=[i for i,node in enumerate(children) if node.tag=='{'+W['w']+'}p' and
                 node.xpath('./w:pPr/w:pStyle') and compact(''.join(node.xpath('.//w:t/text()')))==compact(problem['title'])]
        assert len(matches)==1,(problem['id'],matches)
        end=next(i for i in range(matches[0]+1,len(children)) if children[i].tag=='{'+W['w']+'}tbl')
        preamble=children[matches[0]:end]
        for index,node in enumerate(preamble):
            paragraph=Paragraph(node,saved._body)
            # Word may fold an explicit property into its inherited style.
            assert effective(paragraph,'keep_together'),(problem['id'],index)
            assert effective(paragraph,'keep_with_next')==(index<len(preamble)-1),(problem['id'],index)
        header=children[end].xpath('./w:tr[w:trPr/w:tblHeader]')
        assert len(header)==2,(problem['id'],'caption and column labels must repeat')
    assert all(int(value)==1 for value in saved.element.xpath('//w:cols/@w:num'))


def _chart_specs(document):
    from report_display_checks import charts
    result=[]
    for chart in charts(document):
        rows=chart['series']
        needles=[compact(r['name']+(' · '+r['detail'] if r.get('detail') else '')+r['text']) for r in rows]
        result.append({'id':chart['id'],'kind':'chart','title':chart['title'],'needles':needles,
                       'values':[r['text'] for r in rows],'ticks':[t['text'] for t in chart['ticks']],'legend':[]})
    for section in document['sections']:
        if section['kind']!='environment':continue
        for group in section['groups']:
            if group['id']!='resource-top':continue
            for node in group['blocks']:
                rows=document['visual']['top'][node['id']]
                result.append({'id':node['id'],'kind':'top','title':node['title'],
                               'needles':[compact(str(r['rank'])+'.'+r['name']+r['meta_text']+r['display']) for r in rows],
                               'values':[r['display'] for r in rows],'ticks':[],'legend':node['notes']})
    return result


def chart_card_fragments(path,document,*,only_ids=None):
    records=[];specs=_chart_specs(document)
    if only_ids is not None:specs=[s for s in specs if s['id'] in only_ids]
    with pymupdf.open(path) as pdf:
        shapes=[]
        for page in pdf:
            for drawing in page.get_drawings():
                fill=drawing.get('fill');rect=drawing['rect']
                if not fill or rect.width<100 or rect.height<20:continue
                if max(abs(a-b) for a,b in zip(fill,(233/255,238/255,243/255)))>.01:continue
                lines=[];spans=[];stream='';offsets=[]
                for block in page.get_text('dict',clip=rect)['blocks']:
                    for line in block.get('lines',[]):
                        text=compact(''.join(s['text'] for s in line['spans']))
                        if not text:continue
                        start=len(stream);stream+=text;offsets.append((start,len(stream),line['bbox']))
                        lines.append(text);spans.extend(line['spans'])
                shapes.append((page.number+1,rect,stream,offsets,spans))
        for spec in specs:
            pieces=[];seen=[]
            for page,rect,text,offsets,spans in shapes:
                row_boxes={}
                for index,needle in enumerate(spec['needles']):
                    at=text.find(needle)
                    if at<0:continue
                    boxes=[b for start,finish,b in offsets if finish>at and start<at+len(needle)]
                    row_boxes[index]=[min(b[0] for b in boxes),min(b[1] for b in boxes),max(b[2] for b in boxes),max(b[3] for b in boxes)]
                title=compact(spec['title']) in text
                if not title and not row_boxes:continue
                assert title,(spec['id'],page,'object rows without repeated title')
                assert row_boxes,(spec['id'],page,'title-only chart fragment')
                assert any(abs(s['size']-12)<.12 and compact(s['text']) in compact(spec['title']) for s in spans if s['text'].strip()),(spec['id'],page,'title size changed')
                axis_boxes=[]
                for tick in spec['ticks']:
                    matches=[s for s in spans if compact(s['text'])==compact(tick) and abs(s['size']-10)<.12]
                    assert len(matches)==1,(spec['id'],page,'missing or duplicated numeric axis',tick)
                    axis_boxes.append(matches[0]['bbox'])
                for legend in spec['legend']:assert compact(legend) in text,(spec['id'],page,'missing legend',legend)
                wanted=Counter(compact(spec['values'][i]) for i in row_boxes)
                actual=Counter(compact(s['text']) for s in spans if abs(s['size']-10.5)<.12)
                assert all(actual[v]>=n for v,n in wanted.items()),(spec['id'],page,'object values or size changed',wanted,actual)
                indexes=sorted(row_boxes);seen.extend(indexes)
                pieces.append({'page':page,'rect':list(rect),'rows':indexes,'row_boxes':row_boxes,'title':True,'axis':spec['ticks'],'axis_boxes':axis_boxes,'legend':spec['legend']})
            assert sorted(seen)==list(range(len(spec['needles']))),(spec['id'],'missing or duplicated objects',seen)
            pieces.sort(key=lambda p:(p['page'],p['rect'][1]))
            assert [i for p in pieces for i in p['rows']]==list(range(len(spec['needles']))),(spec['id'],'object order changed')
            if len(pieces)>1:
                assert all(len(p['rows'])>=3 for p in pieces),(spec['id'],'continuation shorter than three rows',pieces)
            if len(spec['needles'])<6:assert len(pieces)==1,(spec['id'],'too few total rows for two three-row segments')
            records.append({'id':spec['id'],'kind':spec['kind'],'title':spec['title'],'objects':len(spec['needles']),'fragments':pieces})
    return records


def chart_spacing_deltas(reference,actual):
    """Compare real object/header/axis geometry against the intact original card."""
    baseline={c['id']:c for c in reference};deltas=[]
    for card in actual:
        ref=baseline[card['id']];assert len(ref['fragments'])==1,ref
        original=ref['fragments'][0];boxes={int(i):b for i,b in original['row_boxes'].items()}
        first=boxes[min(boxes)];last=boxes[max(boxes)];r=original['rect']
        old_header=first[1]-r[1]
        old_axis=min(b[1] for b in original['axis_boxes'])-last[3]
        old_bottom=r[3]-max(b[3] for b in original['axis_boxes'])
        for piece in card['fragments']:
            found={int(i):b for i,b in piece['row_boxes'].items()};ids=piece['rows'];rect=piece['rect']
            values=[('header',found[ids[0]][1]-rect[1]-old_header),
                    ('axis',min(b[1] for b in piece['axis_boxes'])-found[ids[-1]][3]-old_axis),
                    ('bottom',rect[3]-max(b[3] for b in piece['axis_boxes'])-old_bottom)]
            for index in ids:
                values.append(('row height',found[index][3]-found[index][1]-(boxes[index][3]-boxes[index][1])))
                values.append(('left edge',found[index][0]-rect[0]-(boxes[index][0]-r[0])))
                values.append(('right edge',found[index][2]-rect[0]-(boxes[index][2]-r[0])))
            for i,j in zip(ids,ids[1:]):values.append(('row spacing',found[j][1]-found[i][1]-(boxes[j][1]-boxes[i][1])))
            for kind,value in values:
                assert abs(value)<.12,(card['id'],piece['page'],kind,value)
                deltas.append({'id':card['id'],'page':piece['page'],'kind':kind,'delta_pt':value})
    return deltas


def chart_pagination_audit(bundle):
    if '_chart_pagination_audit' in bundle:return bundle['_chart_pagination_audit']
    path=Path(bundle['root'])/'report.pdf';document=bundle['document']
    cards=chart_card_fragments(path,document);tails=pdf_tail_gaps(path);classified=[]
    with pymupdf.open(path) as pdf:
        for gap in tails:
            number=gap['page'];next_body,_,_=_body(pdf[number],False)
            first_y=min((r['bbox'][1] for r in next_body),default=pdf[number].rect.height)
            causes=[]
            for card in cards:
                if len(card['fragments'])!=1:continue
                fragment=card['fragments'][0]
                if fragment['page']!=number+1 or fragment['rect'][1]>first_y+80:continue
                needed=fragment['rect'][3]-first_y
                if needed<=gap['remaining_pt']+1:continue
                count=card['objects'];minimum=None
                if count>=6:
                    boxes=fragment['row_boxes'];last=max(b[3] for b in boxes.values())
                    footer=fragment['rect'][3]-last
                    minimum=boxes[2][3]-first_y+footer
                forced=count<6 or (minimum is not None and minimum>gap['remaining_pt']+1)
                if forced:causes.append({'id':card['id'],'objects':count,'whole_height':needed,'minimum_three_height':minimum,'reason':'fewer than six total rows' if count<6 else 'three rows and repeated scale do not fit'})
            classified.append({**gap,'forced_by_minimum_three':bool(causes),'causes':causes})
    result={'cards':cards,'tails':classified}
    (Path(bundle['root'])/'chart-pagination.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),'utf8')
    bundle['_chart_pagination_audit']=result;return result
