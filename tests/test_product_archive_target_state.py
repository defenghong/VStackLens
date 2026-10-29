"""Offline target-scoped archive status and history, using small isolated stores."""
from copy import deepcopy
from pathlib import Path
import json

import pytest
from PySide6.QtCore import Qt

from vstacklens.application import AuthService
from vstacklens.application.inspection_service import DesktopInspectionConfig, InspectionService
from vstacklens.desktop.environment_archive import project_product_target_run
from vstacklens.products import store
from vstacklens.products.model import TargetRef, new_module, make_check, make_source

ROOT = Path(__file__).resolve().parents[1]


def target(target_id="nsx-one", product="nsx", customer="customer-one"):
    return TargetRef(target_id, product, customer, "site-one", target_id, "192.0.2.110",
                     customer_name=customer, site_name="离线站点")


def module_for(ref, collection="completed", analysis="completed", delivery="completed", *, valid=True):
    module = new_module(ref)
    module.update(collection_state=collection, analysis_state=analysis, delivery_state=delivery,
                  started_at="2026-10-17T01:00:00+00:00", completed_at="2026-10-17T01:01:00+00:00")
    module["checks"] = [make_check("fixture-status", "离线状态样本", "normal" if valid else "collection_failed",
        values={"state": "UP"} if valid else {}, sources=[make_source("/api/v1/cluster/status")], verification="fixture")]
    return module


def run_for(modules, *, state="partial", reports=()):
    return dict(run_id="offline-composite", state=state, started_at="2026-10-17T00:00:00+00:00",
        finished_at="2026-10-17T09:00:00+00:00", modules=modules, reports=list(reports),
        target_runs=[dict(target_id=m["target_id"], product=m["product"],
            target={"customer_id":m["customer_id"], "name":m["target_name"]},
            **{key:m[key] for key in ("collection_state","analysis_state","delivery_state")}) for m in modules])


def files(tmp_path, *, kinds=("html","docx","pdf"), include_json=True):
    result=[]
    for kind in (*kinds, *(("json",) if include_json else ())):
        path=tmp_path/f"offline-report.{kind}"
        path.write_text("offline fixture",encoding="utf-8")
        result.append(dict(format=kind,status="success",path=str(path)))
    return result


@pytest.mark.parametrize("first_state,second_state",[("completed","failed"),("failed","completed")])
def test_each_target_keeps_its_own_stage_and_time_when_other_target_differs(tmp_path,first_state,second_state):
    refs=[target("nsx-one"),target("avi-two","avi")]
    modules=[module_for(refs[0],first_state,delivery="completed",valid=first_state=="completed"),
             module_for(refs[1],second_state,delivery="completed",valid=second_state=="completed")]
    run=run_for(modules,reports=files(tmp_path))
    for ref,expected in zip(refs,(first_state,second_state)):
        summary=project_product_target_run(run,ref.target_id,product=ref.product,customer_id=ref.customer_id)
        assert summary["collection_state"]==expected
        assert summary["collected_at"]=="2026-10-17T01:01:00+00:00"
        assert summary["collected_at"]!=run["finished_at"]
        if expected=="failed":
            assert summary["delivery_state"]=="diagnostic_only"
            assert "仅失败诊断" in summary["report_text"]
        else:
            assert "交付：完成" in summary["report_text"]


@pytest.mark.parametrize("whole_state,own_state",[("failed","failed"),("cancelled","completed"),("cancelled","cancelled"),("partial","partial")])
def test_failed_cancelled_and_partial_composites_do_not_replace_target_state(tmp_path,whole_state,own_state):
    ref=target();module=module_for(ref,own_state,"partial" if own_state!="completed" else "completed",
        "cancelled" if own_state=="cancelled" else "partial",valid=own_state in {"completed","partial"})
    summary=project_product_target_run(run_for([module],state=whole_state,reports=files(tmp_path,kinds=("html",))),ref.target_id)
    assert summary["collection_state"]==own_state
    assert summary["collection_state"]!=whole_state or own_state==whole_state
    assert not (whole_state=="cancelled" and own_state=="completed" and "采集：已取消" in summary["result_text"])
    if own_state=="failed":assert "仅失败诊断" in summary["report_text"]


@pytest.mark.parametrize("delivery",["diagnostic_only","completed"])
def test_diagnostic_only_is_explicit_and_json_is_not_a_health_report(tmp_path,delivery):
    ref=target();module=module_for(ref,"failed","partial",delivery,valid=False)
    summary=project_product_target_run(run_for([module],state="failed",reports=files(tmp_path,kinds=())),ref.target_id)
    assert summary["delivery_state"]=="diagnostic_only"
    assert summary["health_formats"]==[]
    assert summary["json_available"]
    assert "仅失败诊断" in summary["report_text"] and "失败诊断 JSON" in summary["report_text"]


def test_old_diagnostic_without_json_registration_does_not_guess_file(tmp_path):
    ref=target();module=module_for(ref,"failed","partial","completed",valid=False)
    (tmp_path/"failure-diagnostic.json").write_text("offline fixture",encoding="utf-8")
    summary=project_product_target_run(run_for([module],state="failed"),ref.target_id)
    assert "诊断文件未登记" in summary["report_text"]
    assert not summary["json_available"]


@pytest.mark.parametrize("damage",["missing_module","missing_target","unknown","conflict","identity_conflict"])
def test_missing_unknown_conflicting_evidence_is_never_completed(damage):
    ref=target();run=run_for([module_for(ref)],state="completed")
    if damage=="missing_module":run["modules"]=[]
    elif damage=="missing_target":run["target_runs"]=[]
    elif damage=="unknown":
        run["modules"][0]["collection_state"]="future_state"
        run["target_runs"][0]["collection_state"]="future_state"
    elif damage=="conflict":run["target_runs"][0]["collection_state"]="failed"
    else:run["target_runs"][0]["target"]["customer_id"]="another-customer"
    summary=project_product_target_run(run,ref.target_id,product=ref.product,customer_id=ref.customer_id)
    assert summary["collection_state"] in {"missing","unknown","conflict"}
    assert "采集：完成" not in summary["result_text"]


def test_interrupted_pending_target_does_not_hide_completed_peer():
    refs=[target("finished"),target("unfinished")]
    run=run_for([module_for(refs[0]),module_for(refs[1],"running","pending","pending")],state="interrupted")
    assert project_product_target_run(run,"finished")["collection_state"]=="completed"
    assert project_product_target_run(run,"unfinished")["collection_state"]=="interrupted"


def test_success_record_needs_real_files_and_json_cannot_fill_a_health_format(tmp_path):
    ref=target();reports=files(tmp_path)
    missing=Path(next(r["path"] for r in reports if r["format"]=="pdf"))
    # No deletion is needed: record a different missing path.
    next(r for r in reports if r["format"]=="pdf")["path"]=str(missing.with_name("missing.pdf"))
    summary=project_product_target_run(run_for([module_for(ref)],state="completed",reports=reports),ref.target_id)
    assert summary["health_formats"]==["HTML","Word"]
    assert summary["missing_files"]==["PDF"]
    assert "交付不完整" in summary["report_text"] and "文件缺失：PDF" in summary["report_text"]


@pytest.fixture
def archive_window(tmp_path,qt_application_lifetime,monkeypatch):
    from vstacklens.desktop.app import MainWindow, configure_chinese_font
    from vstacklens.db.connection import init_db
    if not getattr(qt_application_lifetime,"_archive_qa_font_ready",False):
        configure_chinese_font(qt_application_lifetime)
        qt_application_lifetime._archive_qa_font_ready=True
    service=InspectionService(config_path=tmp_path/"config.json")
    def small_compat(db_path,**_kwargs):
        init_db(Path(db_path));return Path(db_path)
    monkeypatch.setattr(service.upgrade_compat_service,"ensure_isolated_database",small_compat)
    db=tmp_path/"isolated.db";store.ensure_product_schema(db)
    ids={}
    for key,product,customer in (("a","nsx","离线客户甲"),("b","avi","离线客户甲"),("other","nsx","离线客户乙")):
        ids[key]=store.save_target(db,product=product,name=key+" 产品目标",customer_name=customer,address="192.0.2.110")
    service.save_config(DesktopInspectionConfig(db_path=db,report_output_dir=tmp_path/"reports",rulepack_path=ROOT/"rulepacks/builtin-vsphere-v1"))
    window=MainWindow(service=service,auth_service=AuthService(tmp_path/"auth.json"));window.show();qt_application_lifetime.processEvents()
    yield window,db,ids,service
    window._begin_exit();qt_application_lifetime.processEvents()


def save_run(db,ids,run_id,states,tmp_path,*,whole_state="partial",kinds=("html","docx","pdf"),json_result=True):
    refs={t.target_id:t for t in store.list_targets(db,include_vcenter=False)}
    store.create_run(db,run_id,[refs[ids[key]] for key in states],"离线目标状态样本")
    for key,state in states.items():
        valid=state in {"completed","partial"}
        module=module_for(refs[ids[key]],state,"completed" if state=="completed" else "partial",
                          "completed" if valid else "diagnostic_only",valid=valid)
        store.save_module(db,run_id,module)
    folder=tmp_path/run_id;folder.mkdir()
    for record in files(folder,kinds=kinds,include_json=json_result):
        store.save_report(db,run_id,record["format"],record["path"],"success")
    store.finish_run(db,run_id,whole_state)


def select_archive(window,target_id):
    row=next(i for i in range(window.environment_table.rowCount()) if window.environment_table.item(i,0).data(Qt.UserRole)==target_id)
    window.environment_table.setCurrentCell(row,0);window._environment_selected()
    return window._selected_environment()


def test_list_history_and_selected_detail_share_target_specific_projection(archive_window,tmp_path):
    window,db,ids,_=archive_window
    save_run(db,ids,"opposite-one",{"a":"failed","b":"completed"},tmp_path)
    window._refresh_all_data()
    for key,expected in (("a","失败"),("b","完成")):
        env=select_archive(window,ids[key])
        assert "采集："+expected in env.collection_result
        assert env.collection_result in window.environment_detail.text()
        assert window.environment_tasks.item(0,2).text()==env.collection_result
        assert window.environment_tasks.item(0,3).text()==env.report_result
        assert env.report_result in window.environment_history_scope.text()
        assert "opposite-one" in window.environment_history_scope.text()
        assert env.last_collected_at=="2026-10-17T01:01:00+00:00"
    assert "仅失败诊断" in next(e for e in window._product_archive_views if e.target_id==ids["a"]).report_result
    save_run(db,ids,"opposite-two",{"a":"completed","b":"failed"},tmp_path)
    window._refresh_all_data()
    assert "采集：完成" in select_archive(window,ids["a"]).collection_result
    assert "采集：失败" in select_archive(window,ids["b"]).collection_result


def test_archive_selection_history_rename_and_reopen_keep_stable_identity(archive_window,tmp_path,qt_application_lifetime):
    from vstacklens.desktop.app import MainWindow
    window,db,ids,service=archive_window
    save_run(db,ids,"a-old",{"a":"completed"},tmp_path,whole_state="completed")
    save_run(db,ids,"a-new",{"a":"failed"},tmp_path,whole_state="failed",kinds=())
    save_run(db,ids,"other-customer",{"other":"completed"},tmp_path,whole_state="completed")
    window._refresh_all_data();select_archive(window,ids["a"])
    window.environment_tasks.setCurrentCell(1,0)
    assert "a-old" in window.environment_history_scope.text()
    window.environment_table.sortItems(0,Qt.DescendingOrder)
    window._refresh_all_data()
    assert window._selected_environment().environment_id==ids["a"]
    assert window.environment_tasks.item(window.environment_tasks.currentRow(),0).data(Qt.UserRole)=="a-old"
    select_archive(window,ids["other"])
    assert window.environment_tasks.rowCount()==1 and "other-customer" in window.environment_history_scope.text()
    assert "a-old" not in window.environment_history_scope.text()
    store.save_target(db,product="nsx",target_id=ids["a"],name="改名后的目标",customer_name="离线客户甲",address="192.0.2.110")
    window._refresh_all_data();select_archive(window,ids["a"])
    assert window._selected_environment().name=="改名后的目标" and window.environment_tasks.rowCount()==2
    window._begin_exit();qt_application_lifetime.processEvents()
    reopened=MainWindow(service=service,auth_service=AuthService(tmp_path/"reopen-auth.json"));reopened.show();qt_application_lifetime.processEvents()
    try:
        select_archive(reopened,ids["a"])
        assert reopened.environment_tasks.rowCount()==2
        assert all("other-customer" not in reopened.environment_tasks.item(row,0).toolTip() for row in range(2))
        assert "仅失败诊断" in reopened._selected_environment().report_result
    finally:
        reopened._begin_exit();qt_application_lifetime.processEvents()


def test_missing_file_is_reflected_in_list_history_and_details(archive_window,tmp_path):
    window,db,ids,_=archive_window
    save_run(db,ids,"missing-health-file",{"a":"completed"},tmp_path,whole_state="completed")
    store.save_report(db,"missing-health-file","pdf",str(tmp_path/"absent.pdf"),"success")
    window._refresh_all_data();env=select_archive(window,ids["a"])
    assert "交付不完整" in env.report_result and "文件缺失：PDF" in env.report_result
    assert window.environment_tasks.item(0,3).text()==env.report_result
    assert env.report_result in window.environment_history_scope.text()


def test_old_failed_target_delivery_is_diagnostic_in_product_results_and_report_details(archive_window,tmp_path):
    from vstacklens.desktop.product_inspection import execution_label
    window,db,ids,_=archive_window
    save_run(db,ids,"old-mixed-completed-delivery",{"a":"failed","b":"completed"},tmp_path)
    saved=store.load_run(db,"old-mixed-completed-delivery")
    old_module=next(module for module in saved["modules"] if module["target_id"]==ids["a"])
    old_module["delivery_state"]="completed"
    store.save_module(db,"old-mixed-completed-delivery",old_module)
    window._show_product_results(target_id=ids["a"],run_id="old-mixed-completed-delivery")
    summary=window.product_result_summary.text()
    assert "仅失败诊断" in summary and "失败诊断 JSON" in summary
    assert "交付：完成" not in summary
    window._refresh_all_data()
    item=next(item for item in window._report_items if item.run_id=="old-mixed-completed-delivery")
    window._product_report_selected(item)
    failed_line=next(line for line in window.report_detail.toPlainText().splitlines() if line.startswith("NSX ·"))
    assert "仅失败诊断" in failed_line and "交付：完成" not in failed_line
    assert "JSON" not in window._report_formats(item)
    assert set(window._report_formats(item))=={"HTML","Word","PDF"}
    assert execution_label("diagnostic_only")=="仅失败诊断"


def test_archive_visual_evidence(archive_window,tmp_path,qt_application_lifetime):
    window,db,ids,_=archive_window
    save_run(db,ids,"visual-opposite",{"a":"failed","b":"completed"},tmp_path)
    window._refresh_all_data();window.go_to_module("vcenter_management");select_archive(window,ids["a"])
    window.resize(1360,696);qt_application_lifetime.processEvents()
    evidence=tmp_path/"evidence-screenshots"
    evidence.mkdir(parents=True,exist_ok=True)
    assert window.grab().save(str(evidence/"target-list-failed-peer-completed.png"))
    window._show_environment_history();qt_application_lifetime.processEvents()
    assert window.environment_history_dialog.grab().save(str(evidence/"target-history-diagnostic-only.png"))
    (evidence/"metadata.json").write_text(json.dumps({"data":"offline fixture only","device_pixel_ratio":window.devicePixelRatio(),"list_size":[window.width(),window.height()],"files":["target-list-failed-peer-completed.png","target-history-diagnostic-only.png"]},ensure_ascii=False,indent=2),encoding="utf-8")


@pytest.mark.parametrize("selected", ["a", "b", "other"])
def test_product_archive_entry_syncs_stable_customer_site_and_top_context(archive_window,selected):
    window,db,ids,_=archive_window
    originals={ref.target_id:ref for ref in store.list_targets(db,include_vcenter=False)}
    for key in ("a","other"):
        ref=originals[ids[key]]
        store.save_target(db,product=ref.product,target_id=ref.target_id,name="同名管理目标",
            customer_id=ref.customer_id,customer_name=ref.customer_name,site_name="站点-"+key,
            address="192.0.2.110")
    window._refresh_all_data()
    env=select_archive(window,ids[selected])
    window._select_product_archive(env)
    assert [ref.target_id for ref in window._selected_product_targets()]==[ids[selected]]
    assert window.customer_input.text()==env.customer_name
    assert window.site_input.text()==env.site_name
    assert window.customer_input.isReadOnly() and window.site_input.isReadOnly()
    assert env.customer_name in window.current_object_label.text()
    assert env.name in window.current_object_label.text()
    assert "手动输入目标" not in window.current_object_label.text()
    assert window._product_scope_target_id==env.environment_id


def test_product_only_customer_is_not_overwritten_by_legacy_vcenter_picker(archive_window):
    window,db,ids,service=archive_window
    legacy_id=service.save_environment_archive(db,name="原 vCenter 档案",customer_name="VC 档案客户",
        site_name="VC 档案站点",address="192.0.2.20",username="offline-user")
    window._refresh_all_data();window._select_inspection_environment(legacy_id)
    env=select_archive(window,ids["a"]);window._select_product_archive(env)
    window._populate_environment_picker()
    assert window.customer_input.text()==env.customer_name and window.site_input.text()==env.site_name
    assert window.customer_input.isReadOnly() and window.site_input.isReadOnly()
    window.product_scope_checks["vcenter"].setChecked(True)
    assert window._inspection_environment_id==legacy_id
    assert window.customer_input.text()=="VC 档案客户"
    assert window.site_input.text()=="VC 档案站点"


def test_product_archive_mixed_and_manual_vcenter_restore_unconfirmed_draft(archive_window):
    window,_,ids,_=archive_window
    window._select_inspection_environment(None)
    window.customer_input.setText("尚未保存的手动客户")
    window.site_input.setText("尚未保存的手动站点")
    env=select_archive(window,ids["a"]);window._select_product_archive(env)
    assert window.customer_input.text()==env.customer_name and window.customer_input.isReadOnly()
    window.product_scope_checks["vcenter"].setChecked(True)
    assert window.customer_input.text()=="尚未保存的手动客户"
    assert window.site_input.text()=="尚未保存的手动站点"
    assert not window.customer_input.isReadOnly() and not window.site_input.isReadOnly()
    window.product_scope_checks["nsx"].setChecked(False)
    window._select_inspection_environment(None)
    assert window.customer_input.text()=="尚未保存的手动客户"
    assert not window.customer_input.isReadOnly()


def test_clear_environment_scope_really_clears_result_filter_without_changing_request(archive_window,tmp_path):
    window,db,ids,_=archive_window
    save_run(db,ids,"scope-a",{"a":"completed"},tmp_path,whole_state="completed")
    save_run(db,ids,"scope-other",{"other":"completed"},tmp_path,whole_state="completed")
    window._refresh_all_data()
    env=select_archive(window,ids["a"]);window._select_product_archive(env)
    window._product_forms["nsx"]["password"].setText("offline-fixture-only")
    window._show_product_results(target_id=ids["a"])
    assert window.product_result_target.currentData()==ids["a"]
    checked={key:value.isChecked() for key,value in window.product_scope_checks.items()}
    window._clear_environment_scope()
    assert window._product_scope_target_id is None and window.product_result_target.currentData() is None
    assert {window.product_result_run.itemData(i) for i in range(window.product_result_run.count())}=={"scope-a","scope-other"}
    assert {key:value.isChecked() for key,value in window.product_scope_checks.items()}==checked
    assert [ref.target_id for ref in window._selected_product_targets()]==[ids["a"]]
    assert window._product_forms["nsx"]["password"].text()=="offline-fixture-only"


def test_product_archive_history_reopen_uses_same_real_task_label_as_report_center(archive_window,tmp_path):
    window,db,ids,_=archive_window
    run_id="old-real-product-task"
    save_run(db,ids,run_id,{"a":"completed"},tmp_path,whole_state="completed")
    window._refresh_all_data();select_archive(window,ids["a"])
    item=next(item for item in window._report_items if item.run_id==run_id)
    expected=window._report_task_label(item)
    assert expected==window._product_task_label(run_id)
    assert "编号待确认" not in expected
    window._show_environment_history()
    assert window.environment_tasks.item(0,0).text()==expected
    assert window.environment_tasks.item(0,0).data(Qt.UserRole)==run_id
    window.environment_history_dialog.close();window._show_environment_history()
    assert window.environment_tasks.item(0,0).text()==expected
    assert window.environment_tasks.item(0,0).data(Qt.UserRole)==run_id
