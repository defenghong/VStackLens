"""Customer HTML consumes shared wording and display-only numeric formatting."""
from copy import deepcopy
import ast
from pathlib import Path
import re

from test_html_report_package import _minimal_report
from test_report_b1s_html_20261023 import _javascript_view
from vstacklens.reports import html_package
from vstacklens.reports.customer_format import CAPACITY_NOTE
from vstacklens.reports.html_assets import SINGLE_PAGE_REPORT_JS
from vstacklens.reports.html_package import HtmlReportPackageBuilder


def test_mixed_capacity_table_keeps_original_numbers_and_half_up_display():
    builder = HtmlReportPackageBuilder()
    source = [{'name':'Data_66','type':'VMFS','totalGb':931.25,'usedGb':125.25,'freeGb':806.0,'usagePct':13.45},
              {'name':'shared','type':'NFS','totalGb':32768.0,'usedGb':12288.0,'usagePct':37.5}]
    before = deepcopy(source)
    rows = builder._single_page_store_views(source)
    assert rows[0]['totalGb'] == 931.25 and rows[0]['usagePct'] == 13.45
    assert rows[0]['totalText'] == '931.3 GB' and rows[0]['usageText'] == '13.5%'
    assert rows[1]['totalText'] == '32,768.0 GB'
    assert source == before
    html = _javascript_view({}, 'elements.summary.innerHTML=table(["名称","类型","总容量","已用容量","使用率"], storageRows(' +
                            __import__('json').dumps(rows, ensure_ascii=False) + '))')['summary']['innerHTML']
    assert '931.3 GB' in html and '13.5%' in html and '931.2 GB' not in html
    assert 'width:13.45%' in html  # Saved usage still drives the graphic, not rounded text.


def test_capacity_unit_is_consistent_within_each_table():
    builder = HtmlReportPackageBuilder()
    stores = builder._single_page_store_views([{'totalGb':32768,'usedGb':2048}, {'totalGb':4096,'usedGb':1024}])
    assert all(row[key].endswith(' TB') for row in stores for key in ('totalText','usedText'))
    mixed_vms = builder._single_page_vm_views([{'diskGb':931.25}, {'diskGb':32768}])
    assert mixed_vms[0]['diskText'] == '931.3 GB' and mixed_vms[1]['diskText'] == '32,768.0 GB'
    large_vms = builder._single_page_vm_views([{'diskGb':1024}, {'diskGb':32768}])
    assert [row['diskText'] for row in large_vms] == ['1.0 TB','32.0 TB']


def test_precise_disk_bytes_are_displayed_without_overwriting_compatibility_number():
    builder = HtmlReportPackageBuilder()
    inventory = {'summary':{'VirtualMachine':1}, 'details':{'VirtualMachine':[{
        'object_name':'vm-2026/9/10 11:11:10', 'properties':{'power_state':'poweredOn',
        'vmdk_inventory':[{'capacity_bytes':int(931.25 * 1024 ** 3)}]}}]}}
    before = deepcopy(inventory)
    records, _, _, _ = builder._single_page_assets(inventory)
    row = builder._single_page_vm_views(records['vm'])[0]
    assert row['diskGb'] == 931.2  # Existing numeric compatibility field is unchanged.
    assert row['diskText'] == '931.3 GB'
    assert row['name'] == 'vm-2026/9/10 11:11:10'
    assert '_diskExactGb' not in row
    assert inventory == before


def test_native_vsan_capacity_keeps_numeric_compatibility_and_exact_display():
    builder = HtmlReportPackageBuilder()
    inventory = {'details':{'Datastore':[{'object_name':'vsanDatastore','properties':{
        'datastore_is_vsan':True, 'datastore_capacity_gb':32192.8, 'datastore_used_gb':3072,
        'datastore_free_gb':29120.8, 'vsan_used_percent':9.55,
        'vsan_native_capacity':{'total_capacity_bytes':int(32192.75 * 1024 ** 3),
                              'used_capacity_bytes':int(3072.25 * 1024 ** 3),
                              'free_capacity_bytes':int(29120.5 * 1024 ** 3)}}}]}}
    records, _, _, _ = builder._single_page_assets(inventory)
    view = builder._single_page_vsan('vSAN', [], records['store'], {'clusters':['vSAN']})
    assert view['totalGb'] == 32192.8 and view['usedGb'] == 3072.2
    assert view['totalText'] == '31.4 TB' and view['usageText'] == '9.6%'
    html = _javascript_view({'environment':{}}, 'elements.summary.innerHTML=renderVsan({vsan:' +
                            __import__('json').dumps(view, ensure_ascii=False) + '})')['summary']['innerHTML']
    assert '总计 31.4 TB' in html and '使用率 9.6%' in html
    assert 'GiB' not in html


def test_html_steps_keep_two_independent_lists_and_object_specific_advice():
    advice = 'NSX Manager 的资源预留由产品部署设定，不建议降低，保持现状即可。'
    payload = {'labels':{'level_label':'等级','basis_label':'判断依据','current_label':'当前值','expected_label':'判定标准'},
               'problems':[{'title':'虚拟机资源配置需要优化','level':'P3', 'current':'8 台虚拟机需要核对资源配置。',
                            'expected':'预留和资源限制符合业务用途。','impact':'资源限制会影响可用资源上限。',
                            'remediation':'分别核对预留和资源限制。',
                            'objects':[{'name':'NSX Manager','level':'P3','location':'Infra_Org','basis':advice}],
                            'steps':['不应重复显示的平铺步骤'],
                            'step_groups':[{'title':'预留','steps':['确认预留用途。','调整预留。']},
                                           {'title':'资源限制','steps':['确认限制用途。','调整限制。']}]}]}
    before = deepcopy(payload)
    html = _javascript_view(payload, 'renderProblems()')['issues']['innerHTML']
    assert html.count('<ol>') == 2 and '<h4>预留</h4><ol>' in html and '<h4>资源限制</h4><ol>' in html
    assert advice in html and '不应重复显示的平铺步骤' not in html
    assert '<strong>当前值：</strong>' in html and '<strong>判定标准：</strong>' in html
    assert '名称 / 等级' in html and '判断依据' in html
    assert payload == before


def test_missing_measurements_remain_hidden_without_fabricated_zero():
    builder = HtmlReportPackageBuilder()
    store = builder._single_page_store_views([{'name':'missing','totalGb':None,'usedGb':None,'usagePct':None}])[0]
    host = builder._single_page_host_view({'name':'host','cpuPct':None,'memoryPct':None})
    assert all(store[key] == '' for key in ('totalText','usedText','usageText','freeUsageText'))
    assert host['cpuPctText'] == '' and host['memoryPctText'] == ''
    assert store['totalGb'] is None and host['cpuPct'] is None


def test_frontend_displays_backend_time_and_capacity_note_once(monkeypatch):
    report = _minimal_report()
    report.asset_inventory = {'total':1, 'summary':{'Datastore':1}, 'details':{'Datastore':[{
        'object_name':'Data_66', 'properties':{'datastore_capacity_gb':931.25,'datastore_used_gb':125.25}}]}}
    monkeypatch.setattr(html_package, 'local_time_text', lambda value: '2026-10-23 17:31' if value else '')
    builder = HtmlReportPackageBuilder()
    payload = builder._single_page_payload(report, {'run':{'started_at':'2026-10-23T09:31:01.123456+00:00'}})
    assert payload['environment']['capacityNote'] == CAPACITY_NOTE
    html = _javascript_view({'summary':{'timeText':'2026-10-23 17:31'},'environment':payload['environment']},
                            'elements.environment={innerHTML:""};renderSummary();renderEnvironment()')
    combined = html['summary']['innerHTML'] + html['environment']['innerHTML']
    assert combined.count(CAPACITY_NOTE) == 1 and '2026-10-23 17:31' in combined
    assert not any(term in combined for term in ('Asia/Shanghai','T09:31','+00:00','GiB'))
    assert 'Intl.DateTimeFormat' not in SINGLE_PAGE_REPORT_JS and 'toLocaleString' not in SINGLE_PAGE_REPORT_JS
    assert 'toFixed(1)' not in SINGLE_PAGE_REPORT_JS  # No competing decimal rounding at display time.


def test_unused_single_page_issues_still_preserves_its_original_name_replacement_branch():
    path = Path(html_package.__file__)
    tree = ast.parse(path.read_text(encoding='utf-8'))
    node = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == '_single_page_issues')
    # Explicit user boundary: this unconnected compatibility branch is not part
    # of batch 3; its existing replacement remains untouched.
    assert any(isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
               and call.func.attr == 'replace' and len(call.args) == 2
               and isinstance(call.args[0], ast.Name) and call.args[0].id == 'name'
               and isinstance(call.args[1], ast.Constant) and call.args[1].value == '该对象'
               for call in ast.walk(node))


def test_inventory_deduplication_ignores_only_added_display_fields():
    payload = {'environment':{'clusters':[{'stores':[{'name':'shared','totalGb':32768,'totalText':'32.0 TB'}]}]},
               'inventory':{'stores':[{'name':'shared','totalGb':32768,'totalText':'32,768.0 GB'},
                                      {'name':'other','totalGb':931.25,'totalText':'931.3 GB'}]}}
    html = _javascript_view(payload, 'elements.inventory={innerHTML:""};renderInventory()')['inventory']['innerHTML']
    assert '931.3 GB' in html and '>other<' in html
    assert '>shared<' not in html and '32,768.0 GB' not in html


def test_reference_percentage_labels_use_shared_one_decimal_text_without_changing_thresholds():
    from vstacklens.reports.customer_view import customer_labels
    payload = {'labels':customer_labels()}
    html = _javascript_view(payload,
        'elements.summary.innerHTML=table(["主机","资源使用","连接","CPU","内存"],hostRows(['
        '{name:"low",cpuPct:79.99,memoryPct:0,cpuPctText:"80.0%",memoryPctText:"0.0%"},'
        '{name:"edge",cpuPct:80,memoryPct:0,cpuPctText:"80.0%",memoryPctText:"0.0%"}]))+'
        'renderVsan({vsan:{usagePct:11.44,usageText:"11.4%",disks:[],adapters:[]}})')['summary']['innerHTML']
    assert '低于80.0%参考线' in html and '达到80.0%参考线' in html
    assert '低于 75.0%' in html and '低于 80.0%' in html and '80.0% 及以上' in html
    visible = re.sub('<[^>]*>', '', html)
    assert not re.search(r'(?<![\d.])(?:75|80)%', visible)
