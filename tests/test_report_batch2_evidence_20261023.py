import json

import pytest

from vstacklens.application.engineering_diagnostics import write_engineering_diagnostics
from vstacklens.findings.evidence_builder import EvidenceBuilder
from vstacklens.inventory.canonical_models import CanonicalObject
from vstacklens.reports.context_builder import ReportContextBuilder


@pytest.mark.parametrize('count,expected', [(None, '不能比较建议阈值'), (0, '未高于建议值 0'), (2, '高于建议值 0')])
def test_network_error_explanation_requires_a_real_comparable_count(count, expected):
    target = CanonicalObject(object_type='HostSystem', object_key='host-a', object_name='Host A', object_path='lab/host-a')
    result = EvidenceBuilder()._evidence_vsl_net_003(target, {'pnic_error_count': count})
    assert expected in result['evidence_summary_zh']
    assert result['observed_detail']['pnic_error_count'] is count
    if count is None:
        assert '高于建议值' not in result['evidence_summary_zh']


def test_engineering_warning_total_survives_the_preview_limit(tmp_path):
    warnings = [{'context': f'vm-{n}', 'status': 'api_error'} for n in range(75)]
    row = {'object_type': 'vCenter', 'object_name': 'Lab', 'properties_json': json.dumps({'collection_warnings': warnings})}
    environment = ReportContextBuilder()._vcenter_info({'vcenter_host': 'lab.local'}, [row])
    assert environment['collection_warning_count'] == 75
    assert len(environment['collection_warnings']) == 20
    target = tmp_path / 'engineering.md'
    write_engineering_diagnostics(target, run_id='unit-run', vcenter='lab.local', customer_name='Lab', site_name='Lab',
                                 report_dir=tmp_path, db_path=tmp_path / 'test.db', report_context={'environment_info': environment},
                                 report_paths={}, artifact_findings=[])
    content = target.read_text('utf-8')
    assert '采集 warning 数量：75' in content
    assert '展示 10 条' in content
    assert content.count('- warning：') == 10
    assert len(warnings) == 75


def test_legacy_engineering_context_counts_its_complete_list(tmp_path):
    warnings = [{'context': 'one', 'status': 'partial'}]
    target = tmp_path / 'legacy.md'
    write_engineering_diagnostics(target, run_id='unit-run', vcenter='lab.local', customer_name='Lab', site_name='Lab',
                                 report_dir=tmp_path, db_path=tmp_path / 'test.db',
                                 report_context={'environment_info': {'collection_warnings': warnings}}, report_paths={}, artifact_findings=[])
    assert '采集 warning 数量：1' in target.read_text('utf-8')
