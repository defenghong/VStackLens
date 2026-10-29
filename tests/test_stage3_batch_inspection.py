from __future__ import annotations
import json
import sqlite3
import threading
import time
from pathlib import Path
import pytest
import yaml
from vstacklens.application.batch_inspection import BatchInspectionService, BatchSettings, SessionCredential
from vstacklens.application.inspection_service import InspectionService, DesktopInspectionConfig
from vstacklens.application.inspection_runner import InspectionRunner, VCenterRunRequest, RunnerCancelledError
from vstacklens.application.execution_guard import execution_lease
from vstacklens.db.connection import connect
from vstacklens.rules.rulepack_loader import RulePackLoader

ROOT=Path(__file__).resolve().parents[1]
SECRETS=("BATCH-TEST-PRIVATE-ALPHA-781", "BATCH-TEST-PRIVATE-BETA-921", "BATCH-TEST-API-KEY-401")

@pytest.fixture
def setup(tmp_path):
    service=InspectionService(config_path=tmp_path/"single-config.json")
    db=tmp_path/"isolated.db"
    ids=[service.save_environment_archive(db,name=f"离线环境{i}",customer_name=f"离线客户{i}",address=f"192.0.2.{10+i}",username=f"offline-{i}") for i in range(2)]
    rules=tmp_path/"ruleset"; (rules/"rules").mkdir(parents=True)
    raw=RulePackLoader().load_raw(ROOT/"rulepacks/builtin-vsphere-v1")
    (rules/"rules/base.yaml").write_text(yaml.safe_dump({"rules":[r for r in raw if r["rule_id"] in {"VSL-VC-001","VSL-HOST-005"}]},allow_unicode=True),encoding="utf-8")
    settings=BatchSettings(db,tmp_path/"reports",rules)
    credentials={env:SessionCredential(f"offline-{i}",SECRETS[i]) for i,env in enumerate(ids)}
    controls={"behaviors":{},"calls":[],"started":threading.Event(),"release":threading.Event()}
    class Backend:
        def __init__(self,host,username,password,*args):
            self.host,self.username,self.password=host,username,password
            self.identity_validator=None;self.cancel_requested=lambda:False
            self.remote=f"00000000-0000-0000-0000-{int(host.rsplit('.',1)[1]):012d}"
        def precheck(self):
            controls["calls"].append((self.host,self.username))
            mode=controls["behaviors"].get(self.host)
            if mode=="connection":raise ConnectionError("offline connection failure")
            if mode=="no_identity":self.remote=""
            if self.identity_validator:self.identity_validator(self.remote)
        def collect(self,context,plan,progress=None):
            mode=controls["behaviors"].get(self.host)
            if self.identity_validator:self.identity_validator(self.remote)
            if mode=="secret_failure":raise RuntimeError("offline error: "+self.password)
            if mode=="block":
                controls["started"].set()
                while not controls["release"].wait(.01):
                    if self.cancel_requested():raise RunnerCancelledError("safe offline cancellation")
            raw={"objects":[{"object_type":"vCenter","object_key":self.remote,"object_name":self.host,"object_path":self.host,"properties":{"connected":True,"note":self.password,"api_key":SECRETS[2]}},
                {"object_type":"HostSystem","object_key":"host-1","object_name":"offline-host","object_path":"offline-host","properties":{"cpu_usage_avg":10 if mode!="partial" else None}}]}
            return raw
    factory=lambda:InspectionService(config_path=service.config_path,runner=InspectionRunner(collector_factory=Backend))
    batch=BatchInspectionService(db,service_factory=factory)
    return service,batch,settings,ids,credentials,controls

def test_formal_batch_generates_three_reports_per_environment_without_single_config_changes(setup):
    single,batch,settings,ids,credentials,control=setup
    single.save_config(DesktopInspectionConfig(vcenter="unchanged-single",db_path=settings.db_path))
    before=single.config_path.read_bytes()
    job=batch.submit(ids,credentials,settings)
    result=batch.run(job)
    assert result["counts"]["completed"]==2 and result["percent"]==100
    assert single.config_path.read_bytes()==before
    assert len({i["run_id"] for i in result["items"]})==2
    for item in result["items"]:
        assert set(single.desktop_report_formats(settings.db_path,item["run_id"]))=={"HTML","Word","PDF"}
        with connect(settings.db_path) as conn:
            row=conn.execute("SELECT customer_id,vcenter_id FROM inspection_runs WHERE run_id=?",(item["run_id"],)).fetchone()
        assert row["vcenter_id"]==item["environment_id"] and row["customer_id"]==item["target"]["customer_id"]
    assert control["calls"]==[("192.0.2.10","offline-0"),("192.0.2.11","offline-1")]
    with connect(settings.db_path) as conn:
        text="\n".join(conn.iterdump())
    for secret in SECRETS:assert secret not in text
    for path in settings.report_output_dir.rglob("*"):
        if not path.is_file():continue
        if path.suffix.lower() in {".html",".json",".md"}:
            for secret in SECRETS:assert secret not in path.read_text(encoding="utf-8")
    assert not batch._credentials

def test_cross_customer_same_address_is_blocked_without_collector_calls(setup):
    single,batch,settings,ids,credentials,control=setup
    single.save_environment_archive(settings.db_path,environment_id=ids[1],name="同地址其他客户",customer_name="离线客户1",address="192.0.2.10",username="offline-1")
    result=batch.run(batch.submit(ids,credentials,settings))
    assert result["counts"]["failed"]==2 and not control["calls"]
    assert all("重复地址" in i["reason"] for i in result["items"])

@pytest.mark.parametrize("mode,expected",[("connection","failed"),("partial","partial_failed"),("no_identity","failed"),("secret_failure","failed")])
def test_one_failed_or_partial_item_does_not_stop_next(setup,mode,expected,caplog):
    _,batch,settings,ids,credentials,control=setup
    control["behaviors"]["192.0.2.10"]=mode
    result=batch.run(batch.submit(ids,credentials,settings))
    assert [i["state"] for i in result["items"]]==[expected,"completed"]
    assert result["percent"]==100 and result["counts"]["completed"]==1
    assert all(s not in caplog.text for s in SECRETS)
    with connect(settings.db_path) as conn:
        dumped="\n".join(conn.iterdump())
    assert all(s not in dumped for s in SECRETS)

def test_report_publish_failure_is_not_all_delivered_and_next_runs(setup,monkeypatch):
    _,batch,settings,ids,credentials,_=setup
    from vstacklens.reports.pdf_report import PdfReportEngine
    original=PdfReportEngine.render
    def failing(self,report,path,**kwargs):
        if ids[0] in str(path):raise OSError("offline publish failure")
        return original(self,report,path,**kwargs)
    monkeypatch.setattr(PdfReportEngine,"render",failing)
    result=batch.run(batch.submit(ids,credentials,settings))
    assert result["items"][0]["state"]=="partial_failed"
    assert result["items"][0]["delivery_state"]=="partial"
    assert result["items"][1]["state"]=="completed"

def test_missing_credentials_disabled_and_target_changed(setup):
    single,batch,settings,ids,credentials,control=setup
    job=batch.submit(ids,{ids[0]:credentials[ids[0]]},settings)
    single.set_environment_enabled(settings.db_path,ids[0],False)
    result=batch.run(job)
    assert result["counts"]["failed"]==2 and not control["calls"]
    assert "凭据" in result["items"][1]["reason"]
    single.set_environment_enabled(settings.db_path,ids[0],True)
    job=batch.submit(ids,credentials,settings)
    single.save_environment_archive(settings.db_path,environment_id=ids[1],name="变更",customer_name="离线客户1",address="192.0.2.12",username="changed-user")
    result=batch.run(job)
    assert result["items"][0]["state"]=="completed"
    assert result["items"][1]["state"]=="failed" and "资料变化" in result["items"][1]["reason"]

def test_duplicate_submit_and_single_environment_reservation(setup):
    _,batch,settings,ids,credentials,_=setup
    job=batch.submit(ids,credentials,settings,submission_id="click-once")
    with pytest.raises(ValueError,match="重复提交"):batch.submit(ids,credentials,settings)
    with pytest.raises(ValueError,match="其他巡检"):
        with execution_lease(settings.db_path,ids[0],"192.0.2.10",443):pass
    batch.cancel(job);batch.run(job)
    with execution_lease(settings.db_path,ids[0],"192.0.2.10",443):pass

def test_cancel_current_safely_never_starts_next(setup):
    _,batch,settings,ids,credentials,control=setup
    control["behaviors"]["192.0.2.10"]="block"
    job=batch.submit(ids,credentials,settings)
    outcomes=[]
    worker=threading.Thread(target=lambda:outcomes.append(batch.run(job)))
    worker.start();assert control["started"].wait(10)
    batch.cancel(job);worker.join(10)
    assert not worker.is_alive()
    assert outcomes[0]["counts"]["cancelled"]==2
    assert outcomes[0]["items"][0]["analysis_state"] != "running"
    assert outcomes[0]["items"][0]["delivery_state"] != "generating"
    assert len(control["calls"])==1

def test_restart_marks_interrupted_without_auto_resume_or_losing_completed_result(setup,monkeypatch):
    _,batch,settings,ids,credentials,control=setup
    job=batch.submit(ids,credentials,settings)
    batch.store.update_item(job,0,state="completed",percent=100,run_id="saved-result")
    batch.store.update_item(job,1,state="running")
    from vstacklens.core import process_identity
    from vstacklens.core.process_identity import OwnerState, ProcessCheck
    # The old PID=0 fixture is invalid/unknown, not proof of a dead process.
    dead_pid,dead_identity=1234,"1234:1:100"
    with connect(settings.db_path) as conn:
        conn.execute("UPDATE standard_batches SET owner_pid=?,owner_identity=? WHERE batch_id=?",(dead_pid,dead_identity,job))
        conn.execute("UPDATE inspection_execution_leases SET owner_pid=?,owner_identity=? WHERE owner=?",(dead_pid,dead_identity,job))
    original_read=process_identity._read_process
    monkeypatch.setattr(process_identity,"_read_process",lambda pid:ProcessCheck(OwnerState.ENDED,"confirmed offline process exit") if pid==dead_pid else original_read(pid))
    restarted=BatchInspectionService(settings.db_path)
    state=restarted.store.snapshot(job)
    assert state["items"][0]["state"]=="completed" and state["items"][0]["run_id"]=="saved-result"
    assert state["items"][1]["state"]=="interrupted"
    assert restarted.run(job)==state and not control["calls"]

@pytest.mark.parametrize("reason", ["权限不足", "进程查询失败", "创建身份为空"])
def test_restart_unknown_owner_blocks_formal_batch_and_manual_without_resume(setup,monkeypatch,reason):
    _,batch,settings,ids,credentials,control=setup
    job=batch.submit(ids,credentials,settings)
    batch.store.update_item(job,0,state="running")
    from vstacklens.core import process_identity
    from vstacklens.core.process_identity import OwnerState,ProcessCheck
    with connect(settings.db_path) as conn:
        before="\n".join(conn.iterdump())
    monkeypatch.setattr(process_identity,"_read_process",lambda pid:ProcessCheck(OwnerState.UNKNOWN,reason))
    restarted=BatchInspectionService(settings.db_path)
    with connect(settings.db_path) as conn:
        assert "\n".join(conn.iterdump())==before
    old=restarted.store.snapshot(job)
    assert old["state"]=="waiting" and old["items"][0]["state"]=="running"
    assert "无法确认原任务是否结束" in old["recovery_notice"]
    assert restarted.run(job)==old and not control["calls"]
    with pytest.raises(ValueError,match="无法确认原任务是否结束"):
        with execution_lease(settings.db_path,ids[0],"192.0.2.10",443):pass
    replacement=restarted.submit(ids,credentials,settings)
    result=restarted.run(replacement)
    assert result["counts"]["failed"]==2 and not control["calls"]
    assert all("无法确认原任务是否结束" in item["reason"] for item in result["items"])
    with connect(settings.db_path) as conn:
        assert all(row["owner"]==job for row in conn.execute("SELECT * FROM inspection_execution_leases"))
    assert restarted.store.snapshot(job)==old

def test_schema_migration_backup_and_restore_are_verified(setup,tmp_path):
    _,batch,settings,_,_,_=setup
    backups=list(settings.db_path.parent.glob("*.before-stage3-batch-*.bak"))
    assert backups and all(p.with_name(p.name+".restore-verified").is_file() for p in backups)
    with sqlite3.connect(backups[0]) as conn:
        assert conn.execute("PRAGMA integrity_check").fetchall()==[("ok",)]
        assert not conn.execute("SELECT name FROM sqlite_master WHERE name='standard_batches'").fetchone()

def test_remote_identity_changed_and_rulepack_changed_are_blocked(setup):
    _,batch,settings,ids,credentials,control=setup
    first=batch.run(batch.submit(ids,credentials,settings))
    with connect(settings.db_path) as conn:
        conn.execute("UPDATE inventory_objects SET object_key='ffffffff-ffff-ffff-ffff-ffffffffffff' WHERE vcenter_id=? AND object_type='vCenter'",(ids[0],))
    result=batch.run(batch.submit(ids,credentials,settings))
    assert result["items"][0]["identity_state"]=="blocked"
    assert result["items"][1]["state"]=="completed"
    job=batch.submit(ids,credentials,settings)
    rulefile=settings.rulepack_path/"rules/base.yaml"
    rulefile.write_text(rulefile.read_text(encoding="utf-8")+"\n# offline changed after submit\n",encoding="utf-8")
    previous=len(control["calls"])
    result=batch.run(job)
    assert result["counts"]["failed"]==2 and len(control["calls"])==previous

def test_manual_running_target_is_not_queued_again(setup):
    _,batch,settings,ids,credentials,_=setup
    with execution_lease(settings.db_path,ids[0],"192.0.2.10",443):
        result=batch.run(batch.submit(ids,credentials,settings))
        assert result["items"][0]["state"]=="failed"
        assert result["items"][1]["state"]=="completed"

def test_migration_restore_failure_stops_schema_changes(tmp_path,monkeypatch):
    service=InspectionService(config_path=tmp_path/"config.json")
    db=tmp_path/"before.db"
    service.save_environment_archive(db,name="原档案",customer_name="原客户",address="192.0.2.5")
    with sqlite3.connect(db) as conn:before=list(conn.iterdump())
    def failed_restore(*_args,**_kwargs):raise RuntimeError("offline restore verification failed")
    monkeypatch.setattr("vstacklens.deep.backup.restore_history_backup",failed_restore)
    with pytest.raises(RuntimeError,match="restore verification"):
        BatchInspectionService(db)
    with sqlite3.connect(db) as conn:assert list(conn.iterdump())==before

def test_progress_callback_failure_releases_leases_and_private_credentials(setup):
    _,batch,settings,ids,credentials,_=setup
    job=batch.submit(ids,credentials,settings)
    def fail_callback(_):raise RuntimeError("offline callback failure")
    with pytest.raises(RuntimeError,match="callback failure"):batch.run(job,fail_callback)
    assert not batch._credentials
    assert batch.store.snapshot(job)["state"]=="interrupted"
    with execution_lease(settings.db_path,ids[0],"192.0.2.10",443):pass

def test_missing_file_is_partial_delivery_not_full_success(setup,monkeypatch):
    _,batch,settings,ids,credentials,_=setup
    original=batch._result_states
    def missing(run_id,secrets):
        with connect(settings.db_path) as conn:
            path=conn.execute("SELECT file_path FROM reports WHERE run_id=? AND report_type='pdf'",(run_id,)).fetchone()[0]
        p=Path(path);p.rename(p.with_name(p.name+".retained"))
        return original(run_id,secrets)
    monkeypatch.setattr(batch,"_result_states",missing)
    result=batch.run(batch.submit(ids,credentials,settings))
    assert result["counts"]["partial_failed"]==2
    assert all(i["delivery_state"]=="partial" for i in result["items"])

def test_actual_qt_batch_entry_preserves_single_editor_and_scope(setup,qt_application_lifetime,monkeypatch):
    single,batch,settings,ids,credentials,control=setup
    single.save_config(DesktopInspectionConfig(db_path=settings.db_path,rulepack_path=settings.rulepack_path,report_output_dir=settings.report_output_dir))
    from vstacklens.desktop.app import MainWindow
    from PySide6.QtCore import Qt
    app=qt_application_lifetime
    window=MainWindow(service=single);window.show();window._open_batch()
    window._batch_manager=batch
    app.processEvents()
    from PySide6.QtTest import QTest
    first_box=window.batch_targets.item(0,0)
    QTest.mouseClick(window.batch_targets.viewport(),Qt.LeftButton,pos=window.batch_targets.visualItemRect(first_box).center())
    assert first_box.checkState()==Qt.Checked
    window.vcenter_input.setText("single-editor-kept");window.password_input.setText("single-session-kept")
    window._environment_id=ids[1]
    for row,e in enumerate(window._batch_profiles):
        window.batch_targets.item(row,0).setCheckState(Qt.Checked)
        window.batch_targets.cellWidget(row,4).setText(credentials[e.environment_id].username)
        window.batch_targets.cellWidget(row,5).setText(credentials[e.environment_id].password)
    window.batch_start_button.click();job=window._current_batch_id
    window.batch_start_button.click()
    deadline=time.monotonic()+20
    while window.batch_worker is not None and time.monotonic()<deadline:
        app.processEvents();time.sleep(.01)
    assert window.batch_worker is None
    assert window._current_batch_id==job
    assert window._batch_snapshot["counts"]["completed"]==2
    assert window.vcenter_input.text()=="single-editor-kept"
    assert window.password_input.text()=="single-session-kept"
    assert window._environment_id==ids[1]
    window.close();app.processEvents()

def test_actual_qt_close_requests_safe_cancel_and_no_next_target(setup,qt_application_lifetime,monkeypatch):
    single,batch,settings,ids,credentials,control=setup
    single.save_config(DesktopInspectionConfig(db_path=settings.db_path,rulepack_path=settings.rulepack_path,report_output_dir=settings.report_output_dir))
    from vstacklens.desktop.app import MainWindow
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QMessageBox
    app=qt_application_lifetime
    original_catalog=single.list_environment_archives
    monkeypatch.setattr(single,"list_environment_archives",lambda db:sorted(original_catalog(db),key=lambda e:e.host))
    window=MainWindow(service=single);window.show();window._open_batch();window._batch_manager=batch
    control["behaviors"]["192.0.2.10"]="block"
    for row,e in enumerate(window._batch_profiles):
        window.batch_targets.item(row,0).setCheckState(Qt.Checked)
        window.batch_targets.cellWidget(row,4).setText(credentials[e.environment_id].username)
        window.batch_targets.cellWidget(row,5).setText(credentials[e.environment_id].password)
    window.batch_start_button.click();job=window._current_batch_id
    assert control["started"].wait(10)
    monkeypatch.setattr(QMessageBox,"question",lambda *_:QMessageBox.Yes)
    window.close()
    assert window._batch_closing and window.isVisible()
    deadline=time.monotonic()+10
    while window.isVisible() and time.monotonic()<deadline:
        app.processEvents();time.sleep(.01)
    assert not window.isVisible() and not window._active_workers()
    assert len(control["calls"])==1
    assert batch.store.snapshot(job)["counts"]["cancelled"]==2
