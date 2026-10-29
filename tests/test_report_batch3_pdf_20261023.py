from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pymupdf
import pytest

from test_pdf_report import _report
from vstacklens.reports.customer_caliber import ensure_report
from vstacklens.reports.customer_format import CAPACITY_NOTE, local_time_text
from vstacklens.reports.customer_view import customer_labels
from vstacklens.reports.pdf_report import PdfReportEngine
from vstacklens.reports.report_model import FindingItem


def _display_fixture():
    report, context = _report()
    details = report.asset_inventory['details']
    details['Datastore'][0]['object_name'] = 'Data_66'
    details['Datastore'][0]['properties'].update(
        datastore_capacity_gb=931.25, datastore_used_gb=100, datastore_free_gb=831.25)
    other = deepcopy(details['Datastore'][0])
    other['object_name'] = 'large-store'
    other['properties'].update(datastore_capacity_gb=20000, datastore_used_gb=2000, datastore_free_gb=18000)
    details['Datastore'].append(other)
    details['VirtualMachine'][0]['properties'].update(
        snapshots=[{'name': '快照 2026/9/10 11:11:10',
                    'create_time': '2026-09-10T03:11:22.427854+00:00'}],
        snapshot_age_days_max=8, snapshot_chain_depth=1,
        storage_committed_bytes=int(931.25 * 1024**3),
        is_template=False, is_system_vm=False, power_state='poweredOff')
    details['HostSystem'][0]['properties'].update(
        ssh_running=True, esxi_shell_running=False, host_memory_capacity_mb=931.25 * 1024,
        host_memory_allocated_mb=2000 * 1024, host_memory_allocation_ratio=1.1425)
    details['ClusterComputeResource'][0]['properties'].update(evc_enabled=False,
        admission_control_enabled=True, cluster_cpu_usage_avg=25.25,
        host_memory_capacity_skew_ratio=12.25)
    for vsan in (report.vsan_summary, context['vsan_summary']):
        vsan['capacity'].update(total_gb=32192.8, used_gb=3682.5, free_gb=28510.3, used_percent=11.44)
    return report, context


def test_pdf_display_rounding_units_and_local_times_preserve_raw_values():
    report, context = _display_fixture()
    ensure_report(report, context)
    before_report = deepcopy(report.model_dump(mode='json'))
    before_context = deepcopy(context)
    payload = PdfReportEngine()._build_payload(report, context)
    datastore = next(row for row in payload['datastores'] if row['name'] == 'Data_66')
    assert datastore['total_text'] == '931.3 GB'
    assert next(row for row in payload['datastores'] if row['name'] == 'large-store')['total_text'] == '20,000.0 GB'
    assert payload['vsan']['total_gb'] == 32192.8
    assert payload['vsan']['total_display'] == '31.4 TB'
    assert payload['vsan']['used_percent_text'] == '11.4%'
    assert payload['host_details'][0]['memory_capacity_text'] == '931.3'
    assert payload['host_details'][0]['memory_allocation_text'] == '114.3%'
    assert payload['host_details'][0]['security_summary'].startswith('远程 SSH 服务运行；本地 Shell 服务未运行')
    assert payload['cluster_details'][0]['evc_enabled'] == '未启用'
    assert payload['appendix']['snapshot_vms'][0]['snapshot_names'] == '快照 2026/9/10 11:11:10'
    assert payload['appendix']['snapshot_vms'][0]['snapshot_created'] == local_time_text('2026-09-10T03:11:22.427854+00:00')
    assert payload['appendix']['powered_off_vms'][0]['committed_text'] == '931.3 GB'
    assert payload['wording'] == customer_labels()
    assert payload['capacity_note'] == CAPACITY_NOTE
    assert report.model_dump(mode='json') == before_report
    assert context == before_context


def test_pdf_table_uses_tb_only_when_all_table_values_reach_threshold():
    report, context = _display_fixture()
    for row in report.asset_inventory['details']['Datastore']:
        row['properties'].update(datastore_capacity_gb=2048, datastore_used_gb=1024,
                                 datastore_free_gb=1024)
    payload = PdfReportEngine()._build_payload(report, context)
    for row in payload['datastores']:
        assert row['total_text'] == '2.0 TB'
        assert row['used_text'] == '1.0 TB'
        assert row['free_text'] == '1.0 TB'


@pytest.mark.parametrize('value, expected', [(None, ''), (0, '0.0 GB'),
    (931.25 * 1024**3, '931.3 GB'), (1024**4, '1.0 TB')])
def test_pdf_byte_display_uses_common_capacity_helper(value, expected):
    assert PdfReportEngine()._bytes_text(value) == expected


def test_pdf_resource_groups_keep_shared_titles_and_restart_numbering(tmp_path: Path):
    report, context = _display_fixture()
    report.findings = [
        FindingItem(risk_level='P3', rule_id='VSL-VM-010', rule_name='预留', title='资源预留',
            object_type='VirtualMachine', object_name='app-01', status='failed',
            evidence={'object_key': 'vm-1', 'cpu_reservation_mhz': 4000},
            remediation_steps=['识别配置高预留的虚拟机。', '与业务方确认性能保障需求。',
                               '调整 CPU 或内存预留值。', '观察业务性能，并重新巡检。']),
        FindingItem(risk_level='P3', rule_id='VSL-VM-011', rule_name='资源限制', title='资源限制',
            object_type='VirtualMachine', object_name='app-01', status='failed',
            evidence={'object_key': 'vm-1', 'cpu_limit_mhz': 2000},
            remediation_steps=['检查虚拟机 CPU 和内存资源限制配置。', '确认是否为业务限速或测试需求。',
                               '移除或调整不合理的资源限制。', '复核虚拟机性能指标，并重新巡检。'])]
    ensure_report(report, context)
    engine = PdfReportEngine()
    payload = engine._build_payload(report, context)
    resource = next(row for row in payload['problems'] if row['rule_id'] == 'VM-RESOURCE-CONFIG')
    assert [group['title'] for group in resource['step_groups']] == ['预留', '资源限制']
    assert [len(group['steps']) for group in resource['step_groups']] == [4, 4]
    output = engine.render(report, tmp_path / 'batch3.pdf', report_context=context)
    with pymupdf.open(output) as document:
        text = '\n'.join(page.get_text() for page in document).replace('\u200b', '')
    compact = ''.join(text.split())
    assert '1.识别配置高预留的虚拟机。' in compact
    assert '1.检查虚拟机CPU和内存资源限制配置。' in compact
    assert '5.检查虚拟机CPU和内存资源限制配置。' not in compact
    assert '931.3GB' in compact
    assert '31.4TB' in compact
    assert text.count(CAPACITY_NOTE) == 1
    # Batch four removes engineering narration, retaining the existing ranked
    # table and its capacity values instead of repeating a threshold sentence.
    assert '数据存储使用率' in compact
    from vstacklens.reports.document_model import get_document
    environment=next(s for s in get_document(report,context)['sections'] if s['kind']=='environment')
    # One identical host value is a factual sentence, not a comparison chart.
    assert next(n for n in environment['blocks'] if n['id']=='cpu_pct')['kind']=='paragraph'
    assert next(n for n in environment['blocks'] if n['id']=='memory_allocation_pct')['kind']=='paragraph'
    for forbidden in ('当次等级', '个对象存在', '当前状态为', '建议状态为', '复跑', '明确判定',
                      '。。', '明细 明细', 'GiB', '维护窗口', '未采集', '不可用', '未确认', '待确认', '整体正常'):
        assert forbidden not in text


def test_pdf_long_decimal_allocation_label_stays_outside_bar_and_top5_heading_keeps_first_row(tmp_path: Path):
    report, context = _display_fixture()
    vm = report.asset_inventory['details']['VirtualMachine'][0]
    vm['object_name'] = 'top5-visible-first'
    vm['properties'].update(power_state='poweredOn')
    report.asset_inventory['details']['HostSystem'][0]['properties'].update(
        host_memory_allocation_ratio=1.88, host_memory_allocated_mb=1750.75 * 1024)
    from copy import deepcopy
    second=deepcopy(report.asset_inventory['details']['HostSystem'][0]);second['object_name']='esxi-02'
    second['object_key']='synthetic-host-2';second['properties'].update(host_memory_allocation_ratio=1.28)
    report.asset_inventory['details']['HostSystem'].append(second)
    output = PdfReportEngine().render(report, tmp_path / 'space-constraints.pdf', report_context=context)
    found_allocation = False
    first_row_pages = set()
    heading_pages = {}
    with pymupdf.open(output) as document:
        for number, page in enumerate(document):
            lines = [(''.join(span['text'] for span in line['spans']), pymupdf.Rect(line['bbox']))
                     for block in page.get_text('dict')['blocks'] for line in block.get('lines', [])]
            for text, bbox in lines:
                text=text.replace('\u200b','')
                if text == '188.0%':
                    bars = [drawing['rect'] for drawing in page.get_drawings()
                            if drawing.get('fill') is not None
                            and drawing['rect'].width > 10 and drawing['rect'].height < 20
                            and drawing['rect'].y0 < bbox.y1 and drawing['rect'].y1 > bbox.y0
                            and drawing['rect'].x0 < bbox.x0]
                    assert bars, 'Expected the actual allocation chart beside the label'
                    assert max(bar.x1 for bar in bars) + 1 <= bbox.x0, (bbox, bars)
                    found_allocation = True
                if text == 'top5-visible-first' or text == '1. top5-visible-first':
                    first_row_pages.add(number)
                if text in {'CPU 实际用量 Top 5', '内存实际用量 Top 5'}:
                    heading_pages[text] = number
    assert found_allocation
    from vstacklens.reports.document_model import get_document
    allocation=next(n for s in get_document(report,context)['sections'] if s['kind']=='environment'
                    for n in s['blocks'] if n['id']=='memory_allocation_pct')
    assert allocation['axis_max']==200 and allocation['threshold']==100
    assert [r['value'] for r in allocation['series']]==[188,128]
    assert set(heading_pages) == {'CPU 实际用量 Top 5', '内存实际用量 Top 5'}
    assert all(page in first_row_pages for page in heading_pages.values())
