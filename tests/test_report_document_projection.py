"""A reference projection must never hide facts or bypass artifact scanning."""
from copy import deepcopy
import pytest

from vstacklens.reports.document_output import document_for_medium


def test_reference_projection_is_pure_and_preserves_all_evidence():
    original={'counts':{'objects':71},'rows':[{'id':'same-name-1','name':'重复名称','secret':'must-reach-safety-scanner'},
        {'id':'same-name-2','name':'重复名称','level':'P2'}],
        'note':{'text':'完整清单见 Word / HTML 报告附录 A。','references':{
            'pdf':{'text':'完整清单见 Word / HTML 报告附录 A。'},
            'word':{'text':'完整清单见 附录 A。'},'html':{'text':'完整清单见 附录 A。'}}}}
    before=deepcopy(original)
    for medium in ('pdf','word','html'):
        projected=document_for_medium(original,medium)
        assert projected['counts']==original['counts']
        assert projected['rows']==original['rows']
        assert projected['note']['text']==original['note']['references'][medium]['text']
        assert 'references' not in projected['note']
        projected['rows'][0]['name']='changed output'
        assert original==before
    with pytest.raises(ValueError):document_for_medium(original,'unknown')
