"""Task layout integration on tiny schema-only data; no live service or reports."""
from pathlib import Path
import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QScrollArea,QMessageBox
from vstacklens.application import DesktopInspectionConfig,InspectionService,LogAnalysisProgress,UpgradeCompatProgress,UpgradeCompatResult
from vstacklens.application.upgrade_compat_service import UpgradeCompatService
from vstacklens.db.connection import init_db
from vstacklens.desktop.app import MainWindow

class TinyUpgrade(UpgradeCompatService):
    def ensure_isolated_database(self,db_path,*,seed_database_path=None):init_db(Path(db_path));return Path(db_path)
    def supported_releases(self,*a):return ['ESXi 8.0 U3']
    def hcl_data_status(self,*a):return {'sources':{k:{'available':True,'record_count':1,'json_updated_time':'2026-10-16','freshness':'FRESH'} for k in ['vcg','vsan_hcl']},'message':'模拟判据','can_run':True,'baseline':{'version':'UI-SIMULATED'}}

@pytest.fixture
def task_window(tmp_path,qt_application_lifetime,monkeypatch):
    service=InspectionService(config_path=tmp_path/'config.json',upgrade_compat_service=TinyUpgrade());service.save_config(DesktopInspectionConfig(db_path=tmp_path/'ui.db',report_output_dir=tmp_path/'reports'))
    monkeypatch.setattr(QMessageBox,'warning',lambda *a,**k:QMessageBox.Ok)
    w=MainWindow(service=service);w._plan_timer.stop();w.resize(1093,614);w.show();qt_application_lifetime.processEvents()
    yield qt_application_lifetime,w
    w._begin_exit();qt_application_lifetime.processEvents();assert w._exit_ready and not w._active_workers()


def test_log_phases_reuse_inputs_and_keep_privacy_outside_collapsed_config(task_window):
    app,w=task_window;w.go_to_module('log_analysis');app.processEvents()
    assert w.log_workspace.phase=='idle' and w.log_workspace.result.isHidden()
    w.log_customer_input.setText('隔离布局客户');w.log_problem_input.setPlainText('APD 原始判断依据')
    w.log_cloud_enabled_input.setChecked(True);app.processEvents()
    assert w.log_privacy_notice.isVisible()
    w._log_analysis_progress(LogAnalysisProgress(None,'cloud_diagnosing',68,'模拟形成判断'))
    app.processEvents();assert w.log_workspace.config.isHidden() and w.log_workspace.phase=='running'
    assert w.log_privacy_notice.isVisible()
    assert w.log_result_summary.isHidden()
    w.log_result_fold.toggle.click();app.processEvents();assert not w.log_result_summary.isHidden()
    w._log_analysis_progress(LogAnalysisProgress(None,'cloud_diagnosing',68,'模拟重复进度'))
    assert not w.log_result_summary.isHidden()
    w.log_result_fold.toggle.click();w._log_analysis_progress(LogAnalysisProgress(None,'cloud_diagnosing',68,'模拟折叠后进度'))
    assert w.log_result_summary.isHidden()
    w.log_workspace.config_toggle.click();app.processEvents();assert not w.log_workspace.config.isHidden()
    w._log_analysis_progress(LogAnalysisProgress(None,'cloud_diagnosing',69,'模拟继续'))
    assert not w.log_workspace.config.isHidden()
    w._log_analysis_failed('模拟失败：保留证据不足原因');app.processEvents()
    assert w.log_workspace.phase=='failed' and '证据不足' in w.log_result_summary.toPlainText()
    w.log_workspace.config_toggle.click();app.processEvents()
    assert w.log_customer_input.text()=='隔离布局客户' and w.log_problem_input.toPlainText()=='APD 原始判断依据'
    assert len(w.log_workspace.findChildren(QScrollArea))==1


def test_upgrade_states_sources_and_failure_are_accessible(task_window):
    app,w=task_window;w.go_to_module('upgrade_compat');app.processEvents()
    assert w.upgrade_workspace.phase=='idle' and w.upgrade_workspace.result.isHidden()
    w.upgrade_vcenter_input.setText('vcenter.example.invalid');w.upgrade_password_input.setText('SYNTHETIC_SESSION_ONLY')
    w._upgrade_compat_progress(UpgradeCompatProgress(None,'collecting',30,'模拟读取'));app.processEvents()
    assert w.upgrade_workspace.phase=='running' and w.upgrade_workspace.config.isHidden()
    w._upgrade_compat_progress(UpgradeCompatProgress(None,'collecting',31,'模拟继续读取','非终止告警'))
    assert w.upgrade_workspace.phase=='running'
    w._show_upgrade_task_sources();app.processEvents();assert not w.upgrade_criteria_fold.body.isHidden()
    assert not w.upgrade_workspace.config.isHidden() and 'UI-SIMULATED' in w.upgrade_hcl_status_label.text()
    w._upgrade_compat_failed('模拟失败：缺少必须资料');app.processEvents()
    assert w.upgrade_workspace.phase=='failed' and '缺少必须资料' in w.upgrade_failure_text.text()
    w.upgrade_workspace.config_toggle.click();app.processEvents()
    assert w.upgrade_password_input.text()=='SYNTHETIC_SESSION_ONLY'
    result=UpgradeCompatResult('ui',Path('.'),None,None,{'total':1,'passed':0,'failed':0,'unknown':1},[{'category':'nic','object_name':'long-layout-object','matches':{'vcg':{'status':'UNKNOWN','detail':'资料不足'}}}],[],{})
    w._upgrade_compat_completed(result);app.processEvents()
    assert w.upgrade_workspace.phase=='completed' and w.upgrade_outcomes.isVisible()
    assert '无法确定'==w.upgrade_result_tree.topLevelItem(0).child(0).text(2)
    assert len(w.upgrade_workspace.findChildren(QScrollArea))==1


def test_reading_long_results_uses_outer_scroll_not_nested_result_scroll(task_window):
    app,w=task_window;w.go_to_module('log_analysis');w._batch2_log_state('completed','完成')
    w.log_result_summary.setPlainText('\n'.join('完整证据与限制 '+str(i) for i in range(90)))
    for _ in range(5):app.processEvents()
    assert w.log_result_summary.verticalScrollBar().maximum()==0
    assert w.log_workspace.scroll.verticalScrollBar().maximum()>0
    pos=w.log_start_button.mapTo(w,w.log_start_button.rect().topLeft())
    assert pos.y()+w.log_start_button.height()<=w.height()


def test_independent_empty_batch_has_no_residual_running_state(task_window):
    app,w=task_window;w._open_batch();app.processEvents()
    assert w.batch_targets.rowCount()==0 and w.batch_empty.isVisible()
    assert not w.batch_progress.isVisible() and not w.batch_summary.isVisible()


def test_cancelled_upgrade_keeps_already_determined_abnormal_results(task_window):
    app,w=task_window;w.go_to_module('upgrade_compat')
    w._upgrade_compat_progress(UpgradeCompatProgress('ui','cancelled',40,'模拟已请求取消'))
    result=UpgradeCompatResult('ui',Path('.'),None,None,{'total':1,'passed':0,'failed':1,'unknown':0},[{'category':'nic','object_name':'部分结果对象','matches':{'vcg':{'status':'NOT_CERTIFIED','detail':'已判定异常'}}}],[],{},cancelled=True)
    w._upgrade_compat_completed(result);app.processEvents()
    assert w.upgrade_workspace.phase=='cancelled' and w.upgrade_outcomes.isVisible()
    assert w.upgrade_result_tree.topLevelItem(0).child(0).text(2)=='不通过'
    assert '部分结果' in w.upgrade_failure_text.text() and '未检查项目不视为通过' in w.upgrade_failure_text.text()
    assert not w.upgrade_open_html_button.isVisible()
