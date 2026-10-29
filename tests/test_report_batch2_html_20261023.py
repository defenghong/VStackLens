"""Second-batch A: HTML consumes the shared customer facts without rejudging."""
from copy import deepcopy
import json

from test_html_report_package import _minimal_report
from test_report_b1s_html_20261023 import _javascript_view
from vstacklens.reports import customer_view
from vstacklens.reports import presentation
from vstacklens.reports.html_package import HtmlReportPackageBuilder
from vstacklens.reports.html_report import HtmlReportEngine


def _facts():
    return {
        'counts':{'problem_count':10,'affected_total':71,'problem_label':'问题类别','affected_label':'受影响对象'},
        'snapshots':{'vm_count':20,'problem_vm_count':14,'overview_label':'有快照的虚拟机 20 台',
                     'problem_label':'需处理 14 台','threshold_label':'7 天及以上'},
        'certificates':{'vcenter':{'object_key':'vc-1','name':'vc.test','days':0,'expiry_date':'2026-10-22',
                                   'derived':True,'date_source':'按采集日期和保存的剩余天数推算'},
                        'hosts':[{'object_key':'host-1','name':'esxi.test','expiry_date':'2031-05-25',
                                  'derived':False,'date_source':'ESXi 443 TLS 证书直接读取'}]},
        'clusters':[],
        'vsan':{'items':[{'key':'network','label':'vSAN VMkernel 配置','value':3,
                          'text':'已核对 3 条 vSAN VMkernel 接口配置'}],
                'summary':'已核对 3 条 vSAN VMkernel 接口配置。'},
        'network':{'active_link_anomalies':0,'error_count':None,'summary':'在用物理链路异常 0 条。'},
        'top_labels':{},
    }


def _statistics():
    return {'total':1378,'passed':1285,'failed':93,'text':'本次共检查1378项，通过1285项，未通过93项。',
            'by_object_type_rows':[]}


def test_html_payload_uses_shared_facts_and_omits_engineering_warning_metadata(monkeypatch):
    report = _minimal_report()
    customer_view.get_customer_problem_view(report)
    before = report.model_dump()
    facts = _facts()
    monkeypatch.setattr(customer_view, 'customer_display_facts', lambda source: deepcopy(facts))
    monkeypatch.setattr(presentation, 'customer_check_statistics', lambda source, context=None: {
        **_statistics(), 'by_rule_rows':[{'rule_id':'internal-rule-id'}]})
    builder = HtmlReportPackageBuilder()
    monkeypatch.setattr(builder, '_single_page_certificates', lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError('private certificate recalculation')))
    context = {'vcenter_info':{'collection_warning_count':75,'collection_warnings':['internal-warning-secret']},
               'environment_info':{'collection_warning_count':75,'collection_warnings':['internal-warning-secret'],
                                   'connection_diagnostics':{'sdk':{'status':'failed','message':'underlying-exception-secret'},
                                                             'suggested_actions':['internal-diagnostic-action']}}}
    payload = builder._single_page_payload(report, context)
    assert payload['displayFacts'] == facts
    assert payload['environment']['certificates']['vcenter'] == facts['certificates']['vcenter']
    assert payload['environment']['certificates']['hosts'] == facts['certificates']['hosts']
    assert payload['environment']['network']['error_count'] is None
    assert payload['summary']['problemCount'] == 10
    assert payload['summary']['checkStatistics'] == _statistics()
    assert 'internal-rule-id' not in json.dumps(payload)
    intermediate = builder._customer_report_payload(report, context)
    serialized = json.dumps([payload, intermediate], ensure_ascii=False)
    assert all(value not in serialized for value in ('collection_warning_count','collection_warnings','internal-warning-secret',
                                                    'connection_diagnostics','underlying-exception-secret','internal-diagnostic-action'))
    assert report.model_dump() == before


def test_summary_uses_one_shared_statistics_sentence_without_local_recount():
    payload = {'displayFacts':_facts(), 'summary':{'judgement':'关注','checkStatistics':_statistics(),'delivery':{
        'recorded_results':{'available':True,'counts':{'passed':1366,'failed':94},
                            'failed_levels':{'P1':0,'P2':19,'P3':75}},
        'check_counts':{'passed':2251,'failed':194}}}}
    html = _javascript_view(payload, 'renderSummary()')['summary']['innerHTML']
    for value in ('问题类别：10','受影响对象：71',_statistics()['text'],'有快照的虚拟机 20 台'):
        assert value in html
    for value in ('关联','不等于问题类别数','2251','2,251','194','P2 19','P3 75','需处理 14 台','1,366','未通过：94'):
        assert value not in html


def test_prebuilt_html_context_still_prepares_approved_view_before_reading_facts(monkeypatch):
    report = _minimal_report()
    inputs = deepcopy(report.caliber_inputs)
    assets = deepcopy(report.asset_inventory)

    def facts_after_projection(source):
        assert source._customer_problem_view is not None
        return _facts()

    monkeypatch.setattr(customer_view, 'customer_display_facts', facts_after_projection)
    monkeypatch.setattr(presentation, 'customer_check_statistics', lambda source, context=None: _statistics())
    payload = HtmlReportPackageBuilder()._single_page_payload(report, {}, {'report_context':{}})
    assert payload['displayFacts']['counts']['affected_total'] == 71
    assert payload['summary']['checkStatistics']['failed'] == 93
    assert report.caliber_inputs == inputs and report.asset_inventory == assets


def test_certificate_table_shows_saved_source_and_omits_missing_days():
    certificates = _facts()['certificates']
    html = _javascript_view({'environment':{'certificates':certificates}},
                            'elements.summary.innerHTML = renderCertificates(DATA.environment.certificates)')['summary']['innerHTML']
    assert '2026-10-22<br>按采集日期和保存的剩余天数推算' in html
    assert '2031-05-25<br>ESXi 443 TLS 证书直接读取' in html
    assert '0 天' in html
    assert html.count('剩余时间') == 1  # Omitted from the host table with no saved days.
    assert all(value not in html for value in ('未确认','待确认','不可用','无法判断','全部在 1 年以上','证书均未过期'))


def test_empty_certificates_do_not_generate_a_customer_placeholder():
    html = _javascript_view({'environment':{'certificates':{'vcenter':None,'hosts':[]}}},
                            'elements.summary.innerHTML = renderCertificates(DATA.environment.certificates)')['summary']['innerHTML']
    assert html == ''


def test_vsan_summary_uses_only_shared_verified_item_text():
    payload = {'displayFacts':_facts()}
    html = _javascript_view(payload,
                            'elements.summary.innerHTML = renderVsanSummary({vsan:{disks:[{diskState:"正常"}],usagePct:12,syncObjects:0}})')['summary']['innerHTML']
    assert '已核对 3 条 vSAN VMkernel 接口配置' in html
    assert all(value not in html for value in ('整体正常','物理盘状态正常','容量使用率','当前无重同步'))


def test_network_does_not_turn_absent_error_count_into_zero():
    payload = {'environment':{'network':_facts()['network']}}
    html = _javascript_view(payload, 'elements.environment = {innerHTML:""};renderEnvironment()')['environment']['innerHTML']
    assert '在用物理链路异常 0 条。' in html
    assert all(value not in html for value in ('错误或丢包','错误计数','未确认','待确认','不可用'))


def test_legacy_html_uses_the_same_problem_counts_and_snapshot_overview(monkeypatch, tmp_path):
    report = _minimal_report()
    customer_view.get_customer_problem_view(report)
    before = report.model_dump()
    monkeypatch.setattr(customer_view, 'customer_display_facts', lambda source: _facts())
    monkeypatch.setattr(presentation, 'customer_check_statistics', lambda source, context=None: _statistics())
    path = tmp_path / 'legacy.html'
    HtmlReportEngine().render(report, path)
    html = path.read_text(encoding='utf-8')
    assert '问题类别' in html and '>10<' in html
    assert '受影响对象' in html and '>71<' in html
    assert _statistics()['text'] in html
    assert '有快照的虚拟机 20 台' in html
    assert '>91<' not in html and '风险总数' not in html and '关联' not in html
    assert report.model_dump() == before
