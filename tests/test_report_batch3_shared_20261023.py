"""Batch 3 wording is shared, display-only, and preserves saved identities."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from vstacklens.reports.customer_view import (
    CUSTOMER_IMPACTS, NSX_MANAGER_RESERVATION_ADVICE, build_problem_display,
    customer_display_facts, customer_failed_levels_text, customer_labels,
    customer_prose,
)
from vstacklens.reports.narrative import build_pdf_narratives


def asset(kind, key, name, **properties):
    return {'object_type': kind, 'object_key': key, 'object_name': name, 'properties': properties}


def report(details=None, categories=None):
    return SimpleNamespace(
        asset_inventory={'details': details or {}},
        customer_caliber={'problem_count': 10, 'affected_total': 71, 'categories': categories or []},
        problem_categories=categories or [], vsan_summary={},
        report_info=SimpleNamespace(generated_at='2026-10-22T08:00:00+00:00'),
        appendix={}, remediation_plan=[],
    )


def category(identifier, kind='VirtualMachine', name='original', key='vm1'):
    return {'category_id': identifier, 'title': '保存的原始标题', 'priority': 'P3',
            'affected_object_count': 1, 'source_rule_ids': [], 'evidence_items': [],
            'affected_objects': [{'object_type': kind, 'object_key': key,
                                  'object_name': name, 'risk_level': 'P3'}]}


@pytest.mark.parametrize('identifier', list(CUSTOMER_IMPACTS))
def test_approved_impacts_do_not_change_membership_or_saved_inputs(identifier):
    item = category(identifier)
    source = report(categories=[item])
    before = deepcopy(source.__dict__)
    display = build_problem_display(source, item, [], [])
    assert display['impact'] == CUSTOMER_IMPACTS[identifier]
    assert display['count'] == 1 and display['level'] == 'P3'
    assert display['objects'][0]['object_key'] == 'vm1'
    assert source.__dict__ == before
    assert display['current_label'] == '当前值'
    assert display['expected_label'] == '判定标准'


@pytest.mark.parametrize(('identifier', 'kind', 'expected'), [
    ('CLUSTER-HA', 'ClusterComputeResource', '1 个集群未启用 vSphere HA：original。'),
    ('CLUSTER-DRS', 'ClusterComputeResource', '1 个集群未启用 DRS：original。'),
    ('HOST-MANAGEMENT-SERVICE', 'HostSystem', '1 台 ESXi 主机的 SSH 服务正在运行。'),
    ('HOST-RESOURCE-ALLOCATION', 'HostSystem', '1 台 ESXi 主机的资源分配比例偏高。'),
    ('VM-LOCAL-DATASTORE', 'VirtualMachine', '1 台虚拟机的磁盘存放在主机本地数据存储上。'),
])
def test_specific_fact_sentences_replace_the_generic_template(identifier, kind, expected):
    item = category(identifier, kind)
    display = build_problem_display(report(), item, [], [])
    assert display['current'] == expected
    assert '个对象存在' not in str(display)
    assert '当前状态为' not in str(display) and '建议状态为' not in str(display)


def test_alarm_current_value_and_standard_are_separate_and_include_real_alarm_identity():
    item = category('VC-ALARMS', 'vCenter', 'vc1', 'vc-key')
    sources = [{'rule_id': 'VSL-VC-001', 'current_value': 1, 'observed_detail': {
        'red_alarm_count': 1, 'active_red_alarms': [
            {'alarm_name': 'Backup job status', 'entity_name': 'Datacenters', 'status': 'red'}]}}]
    before = deepcopy(sources)
    display = build_problem_display(report(), item, sources, [])
    assert display['current'] == '1 条红色活动告警：Datacenters 的“Backup job status”告警。'
    assert display['expected'] == '红色活动告警应为 0 条。'
    assert 'Backup job status' not in display['impact']
    assert sources == before


def test_resource_steps_are_grouped_by_saved_rule_not_object_order_and_keep_nsx_advice():
    item = category('VM-RESOURCE-CONFIG', name='NSX-manager')
    sources = [
        {'rule_id': 'VSL-VM-011', 'object_type': 'VirtualMachine', 'object_key': 'vm1', 'remediation_steps': [
            '检查虚拟机 CPU 和内存资源限制 配置。', '确认是否为业务限速或测试需求。',
            '移除或调整不合理 资源限制。', '复核虚拟机性能指标和业务反馈，并复跑巡检规则。']},
        {'rule_id': 'VSL-VM-010', 'object_type': 'VirtualMachine', 'object_key': 'vm1', 'remediation_steps': [
            '识别配置高预留的虚拟机。', '与业务方确认性能保障需求。',
            '调整 CPU 或内存预留值。', '观察业务性能和集群可用资源变化，并复跑巡检规则。']},
    ]
    source = report({'VirtualMachine': [asset('VirtualMachine', 'vm1', 'NSX-manager',
                                             cpu_reservation_mhz=4000, memory_reservation_mb=16384)]})
    before = deepcopy((source.__dict__, sources, item))
    display = build_problem_display(source, item, sources, [])
    assert [group['title'] for group in display['step_groups']] == ['预留', '资源限制']
    assert [len(group['steps']) for group in display['step_groups']] == [4, 4]
    assert display['steps'] == [step for group in display['step_groups'] for step in group['steps']]
    assert display['step_groups'][1]['steps'][2] == '移除或调整不合理的资源限制。可在线修改，不用关机。'
    assert '复跑' not in str(display['steps'])
    assert display['objects'][0]['advice'] == [NSX_MANAGER_RESERVATION_ADVICE]
    assert '4000 MHz' in display['objects'][0]['basis'] and '16384 MB' in display['objects'][0]['basis']
    assert (source.__dict__, sources, item) == before


def test_snapshot_name_and_object_identity_are_not_prose_replacements():
    name = '复跑 Datastore 2026/9/10 11:11:10'
    item = category('VM-SNAPSHOT', name='Datastore-original')
    row = asset('VirtualMachine', 'vm1', 'Datastore-original', snapshots=[{
        'name': name, 'create_time': '2026-09-10T03:11:22.427854+00:00'}])
    source = report({'VirtualMachine': [row]}, [item])
    before = deepcopy(source.__dict__)
    display = build_problem_display(source, item, [{'rule_id': 'VSL-VM-001'}], [])
    assert name in display['objects'][0]['basis']
    assert 'Datastore-original' == display['objects'][0]['name']
    assert '.427854' not in display['objects'][0]['basis'] and '+00:00' not in display['objects'][0]['basis']
    assert '需处理 1 台' in display['current']
    assert source.__dict__ == before


def test_datastore_normalization_only_applies_to_explicit_prose_and_protects_names():
    assert customer_prose('核对本地 Datastore 名称。') == '核对本地数据存储名称。'
    assert customer_prose('虚拟机 Datastore-VM 位于本地 Datastore。', ('Datastore-VM',)) == '虚拟机 Datastore-VM 位于本地数据存储。'
    assert customer_prose('复跑巡检规则。不合理 资源限制。') == '重新巡检。不合理的资源限制。'


def test_zero_link_summary_does_not_invent_missing_error_counts_and_retains_zero_fact():
    row = asset('HostSystem', 'host1', 'host', physical_nic_details=[{
        'device': 'vmnic0', 'is_in_use': True, 'link_state': 'up'}])
    network = customer_display_facts(report({'HostSystem': [row]}))['network']
    assert network == {'active_link_anomalies': 0, 'error_count': None, 'summary': '在用物理链路未发现异常。'}
    assert customer_display_facts(report({'HostSystem': [asset('HostSystem', 'h', 'missing')]}))['network']['summary'] == ''


def test_cluster_and_service_states_use_separate_semantics_and_keep_parent_disabled_dash():
    source = report({'ClusterComputeResource': [
        asset('ClusterComputeResource', 'c1', 'off', ha_enabled=False, drs_enabled=False,
              admission_control_enabled=True, evc_enabled=False),
        asset('ClusterComputeResource', 'c2', 'on', ha_enabled=True, drs_enabled=True,
              admission_control_enabled=True, evc_enabled=True)],
        'HostSystem': [asset('HostSystem', 'h', 'host', ssh_running=True, esxi_shell_running=False)]})
    facts = customer_display_facts(source)
    assert facts['clusters'][0]['admission_control'] == '—'
    assert facts['clusters'][0]['drs_behavior'] == '—'
    assert facts['clusters'][0]['evc_state'] == '未启用'
    assert facts['clusters'][1]['admission_control'] == '已启用'
    assert facts['host_services'][0]['ssh_summary'] == '远程 SSH 服务运行'
    assert facts['host_services'][0]['shell_summary'] == '本地 Shell 服务未运行'
    assert customer_labels()['level_label'] == '等级'
    assert customer_failed_levels_text({'P1': 0, 'P2': 19, 'P3': 74}) == '未通过的检查中，P1 0 条、P2 19 条、P3 74 条。'


def test_customer_narratives_remove_duplicated_punctuation_and_engineering_phrases():
    payload = {'counts': {}, 'risk_counts': {}, 'cluster_details': [
        {'name': 'Infra_Org', 'ha_enabled': False}, {'name': 'vSAN', 'ha_enabled': True}],
        'host_details': [{'overcommit': True, 'hardware_issue_count': 0}], 'connected_host_count': 1,
        'datastores': [{'name': 'Data_66', 'usage': 11.45}], 'problems': [{}],
        'display_facts': {'vsan': {'summary': '已核对 3 条 vSAN VMkernel 接口配置。'}}}
    before = deepcopy(payload)
    text = build_pdf_narratives(payload)
    assert text['clusters'] == '2 个集群中 1 个已启用 HA；尚未启用 HA 的是 Infra_Org。'
    assert text['hosts'].startswith('1 台主机均已连接。')
    assert '11.5%' in text['storage'] and '按使用率阈值' not in text['storage']
    assert '。。' not in str(text)
    assert text['remediation'] == '以下 1 类问题按处理优先级排列，可依照相应建议处理并复查。'
    assert payload == before


def test_reference_percentage_labels_use_shared_one_decimal_display_without_changing_values():
    labels = customer_labels()
    assert labels['reference_0'] == '0.0%'
    assert [labels[f'reference_{value}'] for value in (75, 80, 100, 125)] == ['75.0%', '80.0%', '100.0%', '125.0%']
    assert '80.0% 线用于图示参考' in build_pdf_narratives({})['hosts']


@pytest.mark.parametrize(('rules', 'ssh_running', 'shell_running', 'wanted', 'unwanted'), [
    (['VSL-HOST-002'], True, False, ('SSH',), ('ESXi Shell',)),
    (['VSL-HOST-016'], False, True, ('ESXi Shell',), ('SSH',)),
    (['VSL-HOST-002', 'VSL-HOST-016'], True, True, ('SSH', 'ESXi Shell'), ()),
])
def test_management_service_wording_preserves_the_actual_saved_service(rules, ssh_running, shell_running, wanted, unwanted):
    item = category('HOST-MANAGEMENT-SERVICE', 'HostSystem', 'host-original', 'host1')
    item['title'] = '主机管理服务'
    row = asset('HostSystem', 'host1', 'host-original', ssh_running=ssh_running, esxi_shell_running=shell_running)
    saved = [{'rule_id': rule, 'object_type': 'HostSystem', 'object_key': 'host1',
              'remediation_steps': [f"停止 {'SSH' if rule == 'VSL-HOST-002' else 'ESXi Shell'} 服务。", '重新巡检。']}
             for rule in rules]
    source = report({'HostSystem': [row]}, [item])
    before = deepcopy((source.__dict__, item, saved))
    display = build_problem_display(source, item, saved, [])
    fields = [display['current'], display['expected'], display['impact'], display['remediation'],
              display['objects'][0]['basis'], *display['steps']]
    for name in wanted:
        assert all(name in value for value in fields[:3])
        assert name in display['objects'][0]['basis']
        assert any(name in value and '停止' in value for value in display['steps'])
    for name in unwanted:
        assert all(name not in value for value in fields)
    assert display['count'] == 1 and display['objects'][0]['level'] == 'P3'
    assert (source.__dict__, item, saved) == before


def test_management_services_for_distinct_hosts_do_not_leak_between_objects():
    item = category('HOST-MANAGEMENT-SERVICE', 'HostSystem', 'ssh-host', 'host1')
    item['affected_object_count'] = 2
    item['affected_objects'].append({'object_type': 'HostSystem', 'object_key': 'host2',
                                     'object_name': 'shell-host', 'risk_level': 'P3'})
    rows = [asset('HostSystem', 'host1', 'ssh-host', ssh_running=True, esxi_shell_running=False),
            asset('HostSystem', 'host2', 'shell-host', ssh_running=False, esxi_shell_running=True)]
    saved = [{'rule_id': rule, 'object_type': 'HostSystem', 'object_key': key}
             for rule, key in [('VSL-HOST-002', 'host1'), ('VSL-HOST-016', 'host2')]]
    display = build_problem_display(report({'HostSystem': rows}), item, saved, [])
    assert display['current'] == '1 台 ESXi 主机的 SSH 服务正在运行；1 台 ESXi 主机的 ESXi Shell 服务正在运行。'
    assert 'SSH' in display['objects'][0]['basis'] and 'ESXi Shell' not in display['objects'][0]['basis']
    assert 'ESXi Shell' in display['objects'][1]['basis'] and 'SSH' not in display['objects'][1]['basis']
    assert display['technical']['rows'] == [['ssh-host', 'SSH', '正在运行'], ['shell-host', 'ESXi Shell', '正在运行']]
