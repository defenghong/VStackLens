"""Typst adapter for the shared, concise customer document."""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from vstacklens.reports.document_model import get_document
from vstacklens.reports.document_visual import format_reference
from vstacklens.resources import package_resource_path


def _wrap(value):
    value = str(value)
    value = re.sub(r'([/\\_.-])', lambda m: m.group()+'\u200b', value)
    return re.sub(r'([A-Za-z0-9]{8})', lambda m: m.group()+'\u200b', value)


def pdf_payload(document):
    """Only soft-break display strings; the shared source object stays intact."""
    data = deepcopy(document)
    data.pop('appendices', None)
    data.pop('full_navigation', None)
    seen=set()
    for cluster in data.get('visual',{}).get('clusters',{}).values():
        for key in ('name','summary','host_names','cpu_models'):
            if cluster.get(key):cluster[key]=_wrap(cluster[key])
        for field in cluster.get('fields',[]):field['value']=_wrap(field['value'])
    for entries in data.get('visual',{}).get('top',{}).values():
        for entry in entries:
            for key in ('name','host'):
                if key in entry:entry[key]=_wrap(entry[key])
    def visit(value):
        if isinstance(value, dict):
            if id(value) in seen:return
            seen.add(id(value))
            if value.get('kind') in {'table','cards'}:
                for row in value['rows']:
                    row['source_name']=row['name']
                    row['cells'] = [_wrap(v) for v in row['cells']]
                    row['name']=_wrap(row['name'])
                    if 'detail' in row:row['detail']=_wrap(row['detail'])
            if value.get('kind')=='chart':
                for row in value['series']:
                    row['name']=_wrap(row['name'])
            for field in ('reference','more'):
                if field in value and isinstance(value[field],str):value[field]=format_reference(value[field],'pdf')
            if isinstance(value.get('notes'),list):value['notes']=[format_reference(v,'pdf') for v in value['notes']]
            for key, item in value.items():
                if key not in {'rows','sorting_rules','decisions'}:
                    visit(item)
        elif isinstance(value,list):
            for item in value:
                visit(item)
    visit(data)
    return data


def render_document_pdf(engine, report, output_path: Path, *, context=None, secrets=()):
    from vstacklens.products.reporting import ensure_report_has_valid_data
    ensure_report_has_valid_data(report)
    vcenters=(report.asset_inventory.get('details') or {}).get('vCenter') or []
    if vcenters and (vcenters[0].get('properties') or {}).get('connected') is False:
        raise RuntimeError('vCenter 连接未成功，不生成基于空数据的客户 PDF。')
    output_path = Path(output_path)
    if output_path.exists():
        raise FileExistsError(f'拒绝覆盖已有 PDF 报告：{output_path}')
    data = pdf_payload(get_document(report, context))
    typst = engine._typst_binary()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    parent = engine._compilation_parent(output_path, typst)
    with tempfile.TemporaryDirectory(prefix='vsl-document-',dir=parent) as temporary:
        root=Path(temporary)
        shutil.copy2(package_resource_path('reports','templates','customer-document.typ'),root/'document.typ')
        (root/'scope-level-donut.svg').write_text(data['visual']['scope_svg'],'utf-8')
        (root/'document.json').write_text(json.dumps(data,ensure_ascii=False,separators=(',',':')),'utf-8')
        command=[str(typst),'compile','--root',str(root)]
        fonts=Path(os.environ.get('VSTACKLENS_PDF_FONT_DIR',r'C:\Windows\Fonts'))
        if fonts.is_dir():
            command += ['--font-path',str(fonts)]
        command += [str(root/'document.typ'),str(root/'document.pdf')]
        result=subprocess.run(command,cwd=root,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=180)
        if result.returncode or not (root/'document.pdf').is_file():
            raise RuntimeError('PDF 生成失败：'+(result.stderr or result.stdout)[-3500:])
        engine._publish_pdf(root/'document.pdf',output_path,secrets=secrets)
    return output_path
