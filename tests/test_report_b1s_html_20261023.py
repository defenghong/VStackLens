"""Customer HTML regressions for the first-batch supplement."""
import json
import re
from pathlib import Path
import shutil
import subprocess

import pytest
from jinja2 import Environment, FileSystemLoader, select_autoescape

from vstacklens.reports.html_assets import REPORT_JS, SINGLE_PAGE_REPORT_JS


def _javascript_view(data, call):
    """Execute the shipped view functions against a minimal DOM, without I/O."""
    stub = """
      const elements = Object.create(null);
      for (const id of ['summary','products','issues']) {
        elements[id] = {innerHTML:'', querySelector:() => null};
      }
      const document = {
        getElementById:(id) => id === 'report-data' ? {textContent:'{}'} : elements[id] || null,
        createElement:(tag) => ({tagName:tag}),
        head:{appendChild:(item) => {elements[item.id] = item;}}
      };
    """
    functions = SINGLE_PAGE_REPORT_JS.partition('\nif (DATA.legacyReports)')[0]
    # Use the already-installed JS runtime: the browser bundle is evaluated
    # unchanged, including all nested template expressions and scope rules.
    node = shutil.which('node')
    assert node, 'The JavaScript QA runtime is unavailable'
    result = subprocess.run([node, '-'], input=stub + functions + '\nDATA = ' +
                            json.dumps(data, ensure_ascii=False) + ';' + call +
                            '; console.log(JSON.stringify(elements));',
                            text=True, encoding='utf-8', capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@pytest.mark.parametrize('customer,environment,target,expected', [
    ('', '', '192.0.2.111', '192.0.2.111'),
    ('客户甲', '', '192.0.2.111', '客户甲 · 192.0.2.111'),
    ('', '生产环境', '', '生产环境'),
])
def test_summary_omits_separators_for_empty_fields(customer, environment, target, expected):
    output = _javascript_view({'summary':{'delivery':{
        'customer':customer, 'environment':environment, 'target':target,
    }}}, 'renderSummary()')['summary']['innerHTML']
    identity = re.search(r'class="inspection-time">(.*?)<br>', output).group(1)
    assert identity == expected


@pytest.mark.parametrize('product_name,has_vcenter', [('AVI',False),('NSX',False),('AVI',True),('NSX',True)])
def test_product_views_never_render_task_ids_or_empty_field_separators(product_name, has_vcenter):
    view = {
        'scope':product_name, 'customer':'', 'site':'实验室', 'run_id':'run_hidden_123',
        'generated_at':'2026-10-22', 'has_vcenter':has_vcenter,
        'targets':[{'product_name':product_name, 'name':'', 'address':'192.0.2.109'}],
        'sections':[{'product_name':product_name, 'name':'  ', 'address':'192.0.2.109',
                     'version':'  ', 'build':0, 'body':{'tables':[], 'conclusion':'管理状态核对'}}],
    }
    output = _javascript_view({'productReport':view}, 'renderProductSections()')
    text = output['summary']['innerHTML'] + output['products']['innerHTML']
    assert '任务：' not in text and 'run_hidden_123' not in text
    assert '<p>实验室<br>' in text
    assert '<h3>' + product_name + ' 专项</h3>' in text
    assert '192.0.2.109 · Build 0<br>' in text
    assert ' · <' not in text and '> · ' not in text and ' ·  · ' not in text
    assert 'view.run_id' not in SINGLE_PAGE_REPORT_JS
    assert '任务：' not in SINGLE_PAGE_REPORT_JS + REPORT_JS


def test_html_join_keeps_real_zero_and_false():
    result = _javascript_view({}, 'elements.summary.innerHTML = joinFields([null,0,false,"",undefined,"值"])')
    assert result['summary']['innerHTML'] == '0 · false · 值'


def test_reachable_legacy_template_keeps_basis_without_added_technical_table():
    directory = Path(__file__).parents[1] / 'src/vstacklens/reports/templates'
    template = Environment(loader=FileSystemLoader(directory), autoescape=select_autoescape()).get_template('report_v2.html.j2')
    output = template.render(report_info={'report_title':'巡检报告'}, customer_info={}, health_score={},
                             environment_summary={}, asset_inventory={'summary':{}}, risk_summary={},
                             customer_problems=[{'title':'快照', 'level':'P3', 'objects':[
                                 {'name':'vm-1', 'level':'P3', 'basis':'原有证据：快照名称及ISO完整路径'}],
                                 'steps':['删除时不用关机。'],
                                 'technical':{'headers':['新增技术表'], 'rows':[['不应重复渲染']]}}],
                             customer_passed_checks=[])
    assert '原有证据：快照名称及ISO完整路径' in output
    assert '新增技术表' not in output and '不应重复渲染' not in output and '技术明细' not in output
