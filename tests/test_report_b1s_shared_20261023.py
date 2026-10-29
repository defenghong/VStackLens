"""Business impact belongs to the operation, not a post-verification step."""
from copy import deepcopy
import pytest
from vstacklens.reports.customer_view import BUSINESS_EFFECT,operation_steps,customer_wording,customer_join_nonempty

@pytest.mark.parametrize('category,action',[
 ('CLUSTER-HA','在维护窗口启用 vSphere HA'),('CLUSTER-DRS','在维护窗口启用 DRS'),
 ('VM-SNAPSHOT','在维护窗口删除或合并快照并复跑巡检'),
 ('HOST-MANAGEMENT-SERVICE','停止 SSH 服务'),('VM-CDROM','断开虚拟机光驱挂载'),
 ('VM-RESOURCE-CONFIG','调整 CPU 或内存预留值'),
 ('HOST-RESOURCE-ALLOCATION','通过资源回收、迁移或扩容降低超分风险'),
 ('VM-LOCAL-DATASTORE','完成迁移或例外确认后复跑巡检'),
 ('VM-LONG-POWERED-OFF','对无需保留的虚拟机执行归档、下线或删除流程'),
])
def test_impact_is_attached_to_actual_operation_before_review(category,action):
    original=['确认用途',action,'复跑巡检。',BUSINESS_EFFECT[category]]
    before=deepcopy(original)
    result=operation_steps(category,original)
    assert original==before
    assert BUSINESS_EFFECT[category] not in result
    impact_index=next(i for i,step in enumerate(result) if BUSINESS_EFFECT[category] in step)
    assert result[impact_index].index(BUSINESS_EFFECT[category])>0
    assert impact_index < result.index('重新巡检。')
    assert '维护窗口' not in ''.join(result)
    assert operation_steps(category,result)==result

@pytest.mark.parametrize('limit_name',['资源限制','Limit','limit'])
def test_reservation_and_limit_operations_each_carry_the_approved_impact(limit_name):
    result=operation_steps('VM-RESOURCE-CONFIG',['调整 CPU 或内存预留值','观察资源变化并复跑巡检','移除或调整不合理 '+limit_name,'复核性能并复跑巡检'])
    attached=[step for step in result if '可在线修改，不用关机。' in step]
    assert len(attached)==2
    assert '预留' in attached[0] and limit_name in attached[1]
    assert all(step!='可在线修改，不用关机。' for step in result)

def test_only_the_approved_scheduling_words_change():
    assert customer_wording('可能影响维护窗口安排、故障恢复')=='可能影响主机维护时的迁移安排、故障恢复'
    assert customer_wording('建议在维护窗口删除快照')=='建议在业务低峰期删除快照'
    assert customer_wording('阈值4:1，14台，P2')=='阈值4:1，14台，P2'

def test_join_omits_empty_fields_and_preserves_observed_zero_and_false():
    assert customer_join_nonempty(['',None,'  ','192.0.2.111','范围'])=='192.0.2.111 · 范围'
    assert customer_join_nonempty([0,False,'x'])=='0 · False · x'
