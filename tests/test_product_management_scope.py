"""Independent expectations for the single management scope and history."""
from copy import deepcopy

import pytest

from vstacklens.products.management_scope import (
    MANAGEMENT_SCOPE_ID, alarm_lifecycle, alarm_lifecycle_of, is_management_check,
    is_management_module, mark_management_scope, module_scope, resolve_scope,
    scoped_checks, select_routes,
)
from vstacklens.products.model import TargetRef, finish_module, make_check, new_module


@pytest.mark.parametrize('product,label', [('nsx', 'NSX Manager 管理巡检'), ('avi', 'AVI Controller 管理巡检')])
def test_one_new_scope_and_immutable_definition(product, label):
    scope = resolve_scope(product)
    assert scope.scope_id == MANAGEMENT_SCOPE_ID and scope.label == label
    with pytest.raises((AttributeError, TypeError)):
        scope.scope_id = 'other'
    with pytest.raises(ValueError):
        resolve_scope(product, 'legacy-full')
    with pytest.raises(ValueError):
        resolve_scope(product, 'business')


def test_transport_route_subset_has_no_business_or_policy_discovery():
    fake = {name: object() for name in ('manager_spec', 'policy_spec', 'transport_nodes', 'backup', 'domains', 'clouds',
                                       'ses', 'virtual_services', 'health_monitors', 'certificates', 'certificate_details', 'controller_metrics', 'vs_metrics')}
    assert set(select_routes('nsx', fake)) == {'manager_spec', 'backup', 'certificate_details'}
    assert set(select_routes('avi', fake)) == {'clouds', 'certificate_details', 'controller_metrics'}


@pytest.mark.parametrize('product,good,bad', [('nsx', 'nsx.backup', 'nsx.hosts'), ('avi', 'AVI-A5:bound-cert', 'AVI-C7:template')])
def test_scope_marker_persists_and_rejects_leaks_before_statistics(product, good, bad):
    target = TargetRef('target', product, 'customer', 'site', 'manager', '192.0.2.10')
    module = mark_management_scope(new_module(target))
    module['checks'] = [make_check(good, '管理', 'normal', sources=[{'method': 'GET', 'path': '/offline'}])]
    result = finish_module(module)
    assert module_scope(result).scope_id == MANAGEMENT_SCOPE_ID
    assert result['status_summary'] == {'normal': 1} and is_management_module(result)
    result['checks'].append(make_check(bad, '范围外', 'normal'))
    before = deepcopy(result)
    with pytest.raises(ValueError, match='范围外'):
        finish_module(result)
    assert result == before  # no silent filtering or normal-count repair


def test_unmarked_historical_business_records_remain_byte_semantically_equal():
    historical = {'product': 'avi', 'checks': [{'check_id': 'AVI-C7:system-template', 'status': 'insufficient_data'}],
                  'coverage': {'tenant_scope': {'selected_tenant': 'admin'}}, 'status_summary': {'insufficient_data': 1}}
    before = deepcopy(historical)
    assert module_scope(historical) is None
    assert scoped_checks(historical) == tuple(historical['checks'])
    assert historical == before
    assert is_management_check('avi', 'AVI-C1')  # only a management registration fact in new scope
    assert not is_management_check('avi', 'AVI-C2')


@pytest.mark.parametrize('marker', [{'id': 'unexpected'}, {'id': MANAGEMENT_SCOPE_ID, 'product': 'nsx', 'schema_version': 1},
                                   {'id': MANAGEMENT_SCOPE_ID, 'product': 'avi', 'schema_version': 99}])
def test_unknown_or_mismatched_marker_is_not_silently_treated_as_history(marker):
    with pytest.raises(ValueError):
        module_scope({'product': 'avi', 'coverage': {'inspection_scope': marker}})


@pytest.mark.parametrize('product,state,expected', [
    ('nsx', 'OPEN', 'active'), ('nsx', 'ACKNOWLEDGED', 'active'), ('nsx', 'RESOLVED', 'cleared'),
    ('nsx', 'SUPPRESSED', 'unknown'), ('nsx', None, 'unknown'), ('nsx', 'new-native-enum', 'unknown'),
    ('avi', 'ALERT_STATE_ON', 'active'), ('avi', 'ALERT_STATE_OFF', 'cleared'),
    ('avi', 'new-native-enum', 'unknown'), ('avi', None, 'unknown'),
])
def test_alarm_lifecycle_preserves_native_fields_and_unknown_is_not_cleared(product, state, expected):
    record = {'status' if product == 'nsx' else 'state': state, 'severity': 'native-high', 'time': 'original-time'}
    before = deepcopy(record)
    assert alarm_lifecycle(product, state) == expected
    assert alarm_lifecycle_of(product, record) == expected
    assert record == before


@pytest.mark.parametrize('product', ['nsx', 'avi', 'vcenter'])
def test_new_execution_failure_marker_is_product_bound_and_vcenter_unchanged(product):
    from vstacklens.application.integrated_inspection import IntegratedInspectionService
    target = TargetRef('target', product, 'customer', 'site', 'manager', '192.0.2.10')
    result = IntegratedInspectionService._failure_module(target, RuntimeError('offline failure'), False, ())
    assert is_management_module(result) == (product in {'nsx', 'avi'})
    assert result['checks'][0]['status'] == 'collection_failed'


def test_management_scope_roundtrips_existing_coverage_json_without_migration(tmp_path):
    from vstacklens.products import store
    db = tmp_path / 'isolated.sqlite'
    store.ensure_product_schema(db)
    identifier = store.save_target(db, product='nsx', name='offline manager', address='192.0.2.10', customer_name='offline')
    target = next(t for t in store.list_targets(db) if t.target_id == identifier)
    module = mark_management_scope(new_module(target))
    module['checks'] = [make_check('nsx.version', '版本', 'normal', values={'version': '4.2.3'},
                                  sources=[{'method': 'GET', 'path': '/offline'}])]
    module = finish_module(module)
    store.create_run(db, 'offline-scoped-run', [target], 'offline')
    store.save_module(db, 'offline-scoped-run', module)
    restored = store.load_run(db, 'offline-scoped-run')['modules'][0]
    assert restored['coverage']['inspection_scope'] == module['coverage']['inspection_scope']
    assert restored['status_summary'] == {'normal': 1}


def test_cancelled_new_target_uses_same_manager_scope_without_starting_collector(tmp_path):
    from vstacklens.application.integrated_inspection import IntegratedInspectionRequest, IntegratedInspectionService
    from vstacklens.products import store
    from vstacklens.products.model import SessionCredential
    db = tmp_path / 'cancelled-isolated.sqlite'
    store.ensure_product_schema(db)
    identifier = store.save_target(db, product='avi', name='offline controller', address='192.0.2.11', customer_name='offline')
    target = next(t for t in store.list_targets(db) if t.target_id == identifier)
    def forbidden(*args, **kwargs):
        pytest.fail('cancelled target must not construct a collector')
    credential = SessionCredential('offline-only', 'offline-fixture-password')
    request = IntegratedInspectionRequest(db, tmp_path / 'outputs', [target], {identifier:credential}, experimental=True)
    result = IntegratedInspectionService(collectors={'avi': forbidden}).run(request, cancel_requested=lambda: True)
    saved = store.load_run(db, result.run_id)
    assert result.state == 'cancelled' and module_scope(saved['modules'][0]).product == 'avi'
    assert saved['modules'][0]['status_summary'] == {'cancelled': 1}
    assert not credential.password and not request.credentials


@pytest.mark.parametrize('invalid', ['unmarked', 'tagged_business'])
def test_new_collector_result_requires_declared_management_scope_and_other_target_continues(tmp_path, monkeypatch, invalid):
    from vstacklens.application.integrated_inspection import IntegratedInspectionRequest, IntegratedInspectionService
    from vstacklens.products import store
    from vstacklens.products.model import SessionCredential
    db = tmp_path / 'injected-source-isolated.sqlite'
    store.ensure_product_schema(db)
    targets=[]
    for product, address in [('nsx','192.0.2.10'),('avi','192.0.2.11')]:
        identifier=store.save_target(db,product=product,name=product,address=address,customer_name='offline')
        targets.append(next(t for t in store.list_targets(db) if t.target_id==identifier))
    calls=[]
    def injected(target, credential, **kwargs):
        calls.append(target.product)
        module=new_module(target)
        if target.product=='avi' or invalid=='tagged_business': mark_management_scope(module)
        cid='nsx.hosts' if target.product=='nsx' and invalid=='tagged_business' else 'nsx.version' if target.product=='nsx' else 'AVI-A1'
        module['checks']=[make_check(cid,'offline returned record','normal',values={'version':'offline'},sources=[{'method':'GET','path':'/offline'}])]
        return module
    def no_report(self, request, targets, result, *args): result.state='partial'
    monkeypatch.setattr(IntegratedInspectionService,'_deliver',no_report)
    request=IntegratedInspectionRequest(db,tmp_path/'outputs',targets,{t.target_id:SessionCredential('offline','fixture-only') for t in targets},experimental=True)
    result=IntegratedInspectionService(collectors={'nsx':injected,'avi':injected}).run(request)
    assert calls==['nsx','avi']
    assert result.modules[0]['collection_state']=='failed'
    assert result.modules[0]['status_summary']=={'collection_failed':1}
    assert is_management_module(result.modules[0])
    assert result.modules[1]['collection_state']=='completed'
