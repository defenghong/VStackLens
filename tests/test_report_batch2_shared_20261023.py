"""Shared customer display preserves recorded decisions and unknown values."""
from copy import deepcopy
from types import SimpleNamespace

from vstacklens.reports.customer_view import customer_display_facts, build_problem_display, NSX_MANAGER_RESERVATION_ADVICE


def asset(kind, key, name, **properties):
    return {'object_type': kind, 'object_key': key, 'object_name': name, 'properties': properties}


def report(details=None, *, categories=None, vsan=None):
    return SimpleNamespace(
        asset_inventory={'details': details or {}},
        customer_caliber={'problem_count': 10, 'affected_total': 72, 'categories': categories or []},
        problem_categories=categories or [], vsan_summary=vsan or {},
        report_info=SimpleNamespace(generated_at='2026-10-23T08:00:00+00:00'),
        appendix={}, remediation_plan=[],
    )


def test_display_facts_do_not_change_inputs_or_share_mutable_outputs():
    source = report({'VirtualMachine': [asset('VirtualMachine', 'vm1', 'name', snapshots=[{'name': 's'}])]})
    before = deepcopy(source.__dict__)
    facts = customer_display_facts(source)
    assert source.__dict__ == before
    facts['counts']['problem_count'] = 999
    assert customer_display_facts(source)['counts']['problem_count'] == 10
    assert set(facts['counts']) == {'problem_count', 'affected_total', 'problem_label', 'affected_label'}


def test_snapshot_summary_distinguishes_inventory_from_problem_vm_count():
    source = report({'VirtualMachine': [asset('VirtualMachine', 'vm1', 'a', snapshots=[{}, {}]),
                                       asset('VirtualMachine', 'vm2', 'b', snapshots=[{}])]},
                    categories=[{'category_id': 'VM-SNAPSHOT', 'affected_object_count': 1}])
    snapshot = customer_display_facts(source)['snapshots']
    assert snapshot == {'vm_count': 2, 'problem_vm_count': 1,
                        'overview_label': '有快照的虚拟机 2 台', 'problem_label': '需处理 1 台',
                        'threshold_label': '7 天及以上'}
    assert not any('record' in key for key in snapshot)


def test_missing_snapshot_inventory_is_not_displayed_as_zero():
    assert customer_display_facts(report())['snapshots']['overview_label'] == ''


def test_saved_positive_snapshot_chain_is_evidence_even_without_snapshot_names():
    source = report({'VirtualMachine': [asset('VirtualMachine', 'vm1', 'a', snapshot_chain_depth=1)]})
    assert customer_display_facts(source)['snapshots']['vm_count'] == 1


def test_certificate_dates_show_recorded_source_and_use_capture_not_regeneration_date():
    source = report({'vCenter': [asset('vCenter', 'vc1', 'vc', certificate_days_remaining=10)],
                     'HostSystem': [asset('HostSystem', 'h1', 'host', host_certificate_not_after='2030-01-01',
                                          host_certificate_days_remaining=100)]})
    source.appendix['certificate_license_evidence'] = [
        {'object_type': 'vCenter', 'object_key': 'vc1', 'object_name': 'vc', 'collected_at': '2026-10-22T08:00:00Z'}]
    facts = customer_display_facts(source)['certificates']
    assert facts['vcenter']['expiry_date'] == '2026-11-01'
    assert facts['vcenter']['derived'] is True
    assert facts['vcenter']['date_source'] == '按采集日期和保存的剩余天数推算'
    assert facts['hosts'][0]['expiry_date'] == '2030-01-01'
    assert facts['hosts'][0]['derived'] is False
    assert facts['hosts'][0]['date_source'] == 'ESXi 443 TLS 证书直接读取'


def test_unknown_certificate_fields_are_omitted():
    facts = customer_display_facts(report({'vCenter': [asset('vCenter', 'v1', 'v')],
                                           'HostSystem': [asset('HostSystem', 'h1', 'h', host_certificate_not_after='2030-01-01')]}))
    assert facts['certificates']['vcenter'] is None
    assert 'days' not in facts['certificates']['hosts'][0]


def test_cluster_display_uses_stable_ids_and_preserves_disabled_saved_subsettings():
    source = report({'ClusterComputeResource': [
        asset('ClusterComputeResource', 'c1', 'same', ha_enabled=False, drs_enabled=False,
              admission_control_enabled=True, ha_heartbeat_datastore_count=2, drs_behavior='fullyAutomated'),
        asset('ClusterComputeResource', 'c2', 'same', ha_enabled=True, drs_enabled=True,
              admission_control_enabled=True, ha_heartbeat_datastore_count=2, drs_behavior='fullyAutomated')]})
    before = deepcopy(source.asset_inventory)
    first, second = customer_display_facts(source)['clusters']
    assert first['object_key'] == 'c1' and second['object_key'] == 'c2'
    assert [first[key] for key in ('admission_control', 'heartbeat_summary', 'drs_behavior')] == ['—', '—', '—']
    assert second['admission_control'] == '已启用' and second['heartbeat_summary'] == '2 个' and second['drs_behavior'] == '全自动'
    assert source.asset_inventory == before


def test_link_health_is_independent_of_missing_error_counters():
    source = report({'HostSystem': [asset('HostSystem', 'h1', 'h', pnic_error_count=None,
                    physical_nic_details=[{'device': 'vmnic0', 'is_in_use': True, 'link_state': 'up', 'assessment': 'up'},
                                          {'device': 'vmnic1', 'is_in_use': False, 'link_state': 'down'}])]})
    facts = customer_display_facts(source)['network']
    assert facts == {'active_link_anomalies': 0, 'error_count': None, 'summary': '在用物理链路未发现异常。'}
    assert customer_display_facts(report({'HostSystem': [asset('HostSystem', 'h1', 'h')]}))['network']['summary'] == ''


def test_link_anomalies_keep_same_named_hosts_separate_and_omit_partial_error_total():
    nic = [{'device': 'vmnic0', 'is_in_use': True, 'link_state': 'down', 'assessment': 'down'}]
    source = report({'HostSystem': [asset('HostSystem', 'h1', 'same', physical_nic_details=nic, pnic_error_count=1),
                                   asset('HostSystem', 'h2', 'same', physical_nic_details=nic, pnic_error_count=None)]})
    facts = customer_display_facts(source)['network']
    assert facts['active_link_anomalies'] == 2 and facts['error_count'] is None


def test_vsan_summary_lists_only_evidenced_projects_without_connectivity_or_blanket_health():
    source = report({'HostSystem': [asset('HostSystem', 'h1', 'h', vsan_vmk_adapters=[{'device': 'vmk1'}])]},
                    vsan={'disk_details': [{'health': '正常'}], 'disk_issue_count': 0,
                          'object_count': 5, 'object_issue_count': 0, 'capacity': {'used_percent': 10},
                          'resync_object_count': 0, 'resync_bytes': 0,
                          'network': {'vmkernels': [{'host_name': 'h', 'device': 'vmk0'}, {'host_name': 'h', 'device': 'vmk1'}]},
                          'storage_policy_summary': {}})
    facts = customer_display_facts(source)['vsan']
    assert {row['key'] for row in facts['items']} == {'disks', 'objects', 'capacity', 'resync', 'network'}
    assert '1 条 vSAN VMkernel 接口配置' in facts['summary']
    assert all(word not in facts['summary'] for word in ('整体正常', '连通', '策略正常', '未确认', '不可用'))
    assert customer_display_facts(report())['vsan'] == {'items': [], 'summary': ''}


def test_top_labels_distinguish_configuration_from_running_actual_use():
    labels = customer_display_facts(report())['top_labels']
    assert '开机' in labels['cpu'] and '实际用量' in labels['memory']
    assert '关机虚拟机和模板' in labels['vcpu'] and '关机虚拟机和模板' in labels['capacity']


def test_local_storage_display_title_changes_without_changing_saved_category():
    category = {'category_id': 'VM-LOCAL-DATASTORE', 'title': '虚拟机运行在本地存储',
                'affected_objects': [], 'affected_object_count': 0, 'priority': 'P3'}
    original = deepcopy(category)
    display = build_problem_display(report(), category, [], [])
    assert display['title'] == '虚拟机磁盘存放在本地存储'
    assert '虚拟机运行在本地存储' not in display['current']
    assert category == original


def test_snapshot_display_has_plain_counts_and_threshold_without_reclassifying_chain_evidence():
    category = {'category_id': 'VM-SNAPSHOT', 'title': '虚拟机存在快照',
                'affected_objects': [], 'affected_object_count': 1, 'priority': 'P2'}
    source = report({'VirtualMachine': [asset('VirtualMachine', 'vm1', 'name', snapshots=[{}])]}, categories=[category])
    display = build_problem_display(source, category,
                                    [{'rule_id': 'VSL-VM-001', 'remediation': '核对用途'}, {'rule_id': 'VSL-VM-007'}], [])
    assert display['current'] == '需处理 1 台。'
    assert '7 天及以上' in display['expected'] and '7 天及以上' not in display['remediation']
    assert '快照不能替代备份。' in display['impact'] and '删除时合并耗时也更长。' in display['impact']
    assert source.customer_caliber['problem_count'] == 10


def reservation_display(rows, target_key):
    target = next(row for row in rows if row['object_key'] == target_key)
    obj = {'object_type': 'VirtualMachine', 'object_key': target_key,
           'object_name': target['object_name'], 'risk_level': 'P3'}
    category = {'category_id': 'VM-RESOURCE-CONFIG', 'title': '虚拟机资源配置', 'priority': 'P3',
                'affected_objects': [obj], 'affected_object_count': 1,
                'remediation_zh': '降低不合理预留', 'evidence_items': []}
    source = {'rule_id': 'VSL-VM-010', 'object_type': 'VirtualMachine', 'object_key': target_key,
              'object_name': target['object_name'], 'remediation': '降低不合理预留'}
    return build_problem_display(report({'VirtualMachine': rows}), category, [source], [])


def test_nsx_reservation_keeps_saved_values_and_attaches_exact_object_advice():
    row = asset('VirtualMachine', 'vm1', 'NSX-manager', cpu_reservation_mhz=4000, memory_reservation_mb=16384)
    before = deepcopy(row)
    display = reservation_display([row], 'vm1')
    obj = display['objects'][0]
    assert obj['advice'] == [NSX_MANAGER_RESERVATION_ADVICE]
    assert NSX_MANAGER_RESERVATION_ADVICE in obj['basis']
    assert '4000' in obj['basis'] and '16384' in obj['basis']
    assert '降低不合理预留' not in obj['basis']
    assert row == before and obj['level'] == 'P3'


def test_same_named_nsx_assets_do_not_approve_a_name_based_override():
    rows = [asset('VirtualMachine', 'vm1', 'NSX-manager'), asset('VirtualMachine', 'vm2', 'NSX-manager')]
    assert reservation_display(rows, 'vm1')['objects'][0]['advice'] != [NSX_MANAGER_RESERVATION_ADVICE]
    assert reservation_display(rows, 'vm2')['objects'][0]['advice'] != [NSX_MANAGER_RESERVATION_ADVICE]


def test_nsx_override_does_not_leak_to_another_key_or_conflicting_saved_role():
    rows = [asset('VirtualMachine', 'vm1', 'NSX-manager'), asset('VirtualMachine', 'vm2', 'business')]
    assert reservation_display(rows, 'vm2')['objects'][0]['advice'] != [NSX_MANAGER_RESERVATION_ADVICE]
    conflicting = asset('VirtualMachine', 'vm3', 'NSX-manager', appliance_role='database')
    assert reservation_display([conflicting], 'vm3')['objects'][0]['advice'] != [NSX_MANAGER_RESERVATION_ADVICE]
    explicit = asset('VirtualMachine', 'vm4', 'different', product_role='NSX Manager')
    assert reservation_display([explicit], 'vm4')['objects'][0]['advice'] == [NSX_MANAGER_RESERVATION_ADVICE]


def test_shared_execution_statistics_use_only_approved_p1_p3_actionable_records(monkeypatch):
    from vstacklens.reports.presentation import customer_check_statistics, recorded_result_summary
    records = [
        {'rule_id': 'r1', 'rule_name': 'one', 'object_type': 'HostSystem', 'risk_level': 'P2', 'result_status': 'passed'},
        {'rule_id': 'r1', 'rule_name': 'one', 'object_type': 'HostSystem', 'risk_level': 'P2', 'result_status': 'failed'},
        {'rule_id': 'r2', 'rule_name': 'two', 'object_type': 'VirtualMachine', 'risk_level': 'P3', 'result_status': 'failed'},
        {'rule_id': 'r3', 'object_type': 'VirtualMachine', 'risk_level': 'P4', 'result_status': 'passed'},
        {'rule_id': 'r4', 'object_type': 'HostSystem', 'risk_level': 'P3', 'result_status': 'unavailable'},
        {'rule_id': 'r5', 'object_type': 'VirtualMachine', 'risk_level': 'P3', 'result_status': 'not_applicable'},
        {'rule_id': 'r6', 'object_type': 'HostSystem', 'risk_level': 'P4', 'result_status': 'unavailable'},
    ]
    before = deepcopy(records)
    monkeypatch.setattr('vstacklens.reports.customer_caliber.approved_result_projection', lambda *_: {'object_results': records})
    result = customer_check_statistics(report())
    assert (result['total'], result['passed'], result['failed']) == (3, 1, 2)
    assert result['text'] == '本次共检查 3 条，通过 1 条，未通过 2 条。'
    assert result['levels'] == {'P1': 0, 'P2': 1, 'P3': 1}
    assert sum(row['total'] for row in result['by_object_type_rows']) == 3
    assert sum(row['total'] for row in result['by_rule_rows']) == 3
    assert result['top_failed_checks'][0]['highest_level'] == 'P2'
    assert recorded_result_summary(report())['counts']['unavailable'] == 1
    assert records == before


def test_shared_execution_statistics_hide_absent_data_and_use_projected_passed_checklist(monkeypatch):
    from vstacklens.reports.presentation import customer_check_statistics
    from vstacklens.reports.customer_view import shared_passed_checks
    monkeypatch.setattr('vstacklens.reports.customer_caliber.approved_result_projection', lambda *_: {
        'object_results': [], 'rule_checklist': [
            {'rule_id': 'kept', 'rule_name': 'projected', 'risk_level': 'P3', 'passed': 1},
            {'rule_id': 'removed', 'rule_name': 'not applicable', 'risk_level': 'P3', 'passed': 0, 'not_applicable': 1},
        ]})
    assert customer_check_statistics(report())['text'] == ''
    old = [{'rule_id': 'old', 'rule_name': 'wrong', 'risk_level': 'P3', 'passed': 1}]
    assert [row['label'] for row in shared_passed_checks(report(), old, {})] == ['projected']


def test_missing_saved_results_do_not_borrow_environment_totals_or_publish_zero():
    from test_pdf_report import _report
    from vstacklens.reports.presentation import customer_check_statistics, delivery_overview, recorded_result_summary
    source, _ = _report()
    source.caliber_inputs.pop('object_results', None)
    source.environment_summary.result_status_summary = {'passed': 3, 'unavailable': 2, 'error': 1}
    before = source.model_dump()
    assert recorded_result_summary(source)['available'] is False
    statistics = customer_check_statistics(source)
    assert statistics['available'] is False and statistics['text'] == ''
    assert statistics['by_object_type_rows'] == []
    assert delivery_overview(source)['check_counts'] == {}
    assert source.environment_summary.result_status_summary == {'passed': 3, 'unavailable': 2, 'error': 1}
    assert source.model_dump() == before


def test_empty_saved_result_set_does_not_claim_any_verified_checks():
    from test_pdf_report import _report
    from vstacklens.reports.presentation import customer_check_statistics, delivery_overview, recorded_result_summary
    source, _ = _report()
    source.caliber_inputs['object_results'] = []
    before = source.model_dump()
    assert recorded_result_summary(source)['available'] is False
    statistics = customer_check_statistics(source)
    assert statistics['available'] is False
    assert statistics['text'] == ''
    assert delivery_overview(source)['check_counts'] == {}
    assert source.model_dump() == before


def test_recorded_zero_metric_is_not_missing_or_a_fabricated_zero_check_total():
    from test_pdf_report import _report
    from vstacklens.reports.presentation import customer_check_statistics, delivery_overview
    source, _ = _report()
    source.caliber_inputs['object_results'] = [
        {'rule_id': 'r1', 'object_type': 'HostSystem', 'risk_level': 'P3',
         'result_status': 'passed', 'current_value': 0}]
    before = source.model_dump()
    statistics = customer_check_statistics(source)
    assert statistics['available'] is True
    assert statistics['text'] == '本次共检查 1 条，通过 1 条，未通过 0 条。'
    assert delivery_overview(source)['check_counts'] == {'passed': 1, 'failed': 0}
    assert source.model_dump() == before


def test_empty_nic_inventory_is_known_zero_but_missing_or_failed_source_is_not():
    known_empty = report({'HostSystem': [asset('HostSystem', 'h1', 'h', physical_nic_details=[], pnic_error_count=None)]})
    assert customer_display_facts(known_empty)['network'] == {
        'active_link_anomalies': 0, 'error_count': None, 'summary': '在用物理链路未发现异常。'}
    for values in ({}, {'physical_nic_details': None},
                   {'physical_nic_details': [], 'physical_nic_collection_status': 'api_error'},
                   {'physical_nic_details': [], 'sdk_property_observations': {
                       'fields': [{'property': 'config', 'status': 'failed', 'fault_type': 'NoPermission'}]}}):
        source = report({'HostSystem': [asset('HostSystem', 'h1', 'h', **values)]})
        assert customer_display_facts(source)['network'] == {
            'active_link_anomalies': None, 'error_count': None, 'summary': ''}


def test_error_counter_failure_does_not_turn_known_link_inventory_into_unknown():
    source = report({'HostSystem': [asset('HostSystem', 'h1', 'h', physical_nic_details=[], pnic_error_count=None,
                                          sdk_property_observations={'fields': [
                                              {'property': 'pnic_error_count', 'status': 'failed'}]})]})
    assert customer_display_facts(source)['network'] == {
        'active_link_anomalies': 0, 'error_count': None, 'summary': '在用物理链路未发现异常。'}


def test_saved_eligible_records_take_precedence_over_incompatible_environment_summary():
    from test_pdf_report import _report
    from vstacklens.reports.presentation import customer_check_statistics, delivery_overview
    source, _ = _report()
    source.caliber_inputs['object_results'] = [
        {'rule_id': 'r1', 'rule_name': 'one', 'object_type': 'HostSystem', 'risk_level': 'P3', 'result_status': 'passed'},
        {'rule_id': 'r2', 'rule_name': 'two', 'object_type': 'VirtualMachine', 'risk_level': 'P2', 'result_status': 'failed'},
    ]
    source.environment_summary.result_status_summary = {'passed': 300, 'failed': 100, 'unavailable': 2}
    before = source.model_dump()
    statistics = customer_check_statistics(source)
    assert (statistics['total'], statistics['passed'], statistics['failed']) == (2, 1, 1)
    assert statistics['text'] == '本次共检查 2 条，通过 1 条，未通过 1 条。'
    assert delivery_overview(source)['check_counts'] == {'passed': 1, 'failed': 1}
    assert source.model_dump() == before
