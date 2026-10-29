from pathlib import Path
import pytest
from PySide6.QtCore import Qt, QThread
from vstacklens.application import AuthService
from vstacklens.application.inspection_service import DesktopInspectionConfig, InspectionService
from vstacklens.products import store
from vstacklens.products.model import new_module, finish_module, make_check, make_source

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def product_window(tmp_path, qt_application_lifetime, monkeypatch):
    from vstacklens.desktop.app import MainWindow
    service = InspectionService(config_path=tmp_path / "config.json")
    # Product UI tests do not require the unrelated full upgrade HCL catalog.
    from vstacklens.db.connection import init_db
    def small_compat(db_path, **_kwargs):
        init_db(Path(db_path)); return Path(db_path)
    monkeypatch.setattr(service.upgrade_compat_service, "ensure_isolated_database", small_compat)
    db = tmp_path / "isolated.db"
    store.ensure_product_schema(db)
    vc = service.save_environment_archive(db, name="旧 VC 档案", customer_name="离线客户甲", address="192.0.2.11")
    a = store.save_target(db, product="nsx", name="NSX 管理器一", customer_name="离线客户甲", address="192.0.2.110")
    b = store.save_target(db, product="nsx", name="NSX 管理器二", customer_name="离线客户甲", address="192.0.2.110")
    avi = store.save_target(db, product="avi", name="AVI 控制器", customer_name="离线客户甲", address="192.0.2.109")
    other = store.save_target(db, product="nsx", name="另一客户同地址", customer_name="离线客户乙", address="192.0.2.110")
    service.save_config(DesktopInspectionConfig(db_path=db, report_output_dir=tmp_path / "reports",
        rulepack_path=ROOT / "rulepacks/builtin-vsphere-v1"))
    window = MainWindow(service=service, auth_service=AuthService(tmp_path / "auth.json"))
    window.show(); qt_application_lifetime.processEvents()
    yield window, db, dict(vc=vc, a=a, b=b, avi=avi, other=other)
    window._begin_exit(); qt_application_lifetime.processEvents()


def choose(window, product, target_id, *, checked=True):
    widget = window._product_forms[product]["targets"]
    item = next(widget.item(i) for i in range(widget.count()) if widget.item(i).data(Qt.UserRole) == target_id)
    widget.setCurrentItem(item)
    item.setCheckState(Qt.Checked if checked else Qt.Unchecked)
    return item


def test_scope_reuses_legacy_and_selectively_shows_connection_tabs(product_window):
    window, db, ids = product_window
    assert window.product_scope_checks["vcenter"].isChecked()
    assert not window._has_product_scope()
    assert window.product_connection_tabs.isTabVisible(0)
    assert not window.product_connection_tabs.isTabVisible(1)
    vcenter_form_height = window.product_connection_tabs.sizeHint().height()
    window.product_scope_checks["vcenter"].setChecked(False)
    window.product_scope_checks["nsx"].setChecked(True)
    assert not window.product_connection_tabs.isTabVisible(0)
    assert window.product_connection_tabs.isTabVisible(1)
    assert window.product_connection_tabs.currentIndex() == 1
    assert window.product_connection_tabs.sizeHint().height() > vcenter_form_height
    assert "NSX" in window.scope_label.text()
    assert {e.environment_id for e in window._environment_archives} == {ids["vc"]}
    assert all(t.product == "vcenter" for t in store.list_targets(db) if t.target_id in {e.environment_id for e in window._environment_archives})


def test_passwords_are_target_isolated_and_lab_tls_is_explicit(product_window):
    window, _, ids = product_window
    window.product_scope_checks["nsx"].setChecked(True)
    fields = window._product_forms["nsx"]
    choose(window, "nsx", ids["a"])
    assert fields["lab"].isEnabled() and not fields["lab"].isChecked()
    fields["username"].setText("lab-user-one"); fields["password"].setText("one-only-session-value")
    fields["lab"].setChecked(True)
    choose(window, "nsx", ids["b"])
    assert not fields["password"].text()
    assert not fields["lab"].isEnabled() and not fields["lab"].isChecked()
    fields["username"].setText("lab-user-two"); fields["password"].setText("two-only-session-value")
    choose(window, "nsx", ids["a"])
    assert fields["password"].text() == "one-only-session-value"
    assert window._product_credentials[ids["b"]].password == "two-only-session-value"
    window._clear_product_credentials()
    assert not fields["password"].text() and not window._product_credentials


def test_changed_target_identity_drops_only_its_runtime_credential(product_window):
    window, db, ids = product_window
    choose(window, "nsx", ids["a"])
    fields = window._product_forms["nsx"]
    fields["password"].setText("runtime-only-secret")
    store.save_target(db, target_id=ids["a"], product="nsx", name="更名保留 ID", customer_name="离线客户甲", address="192.0.2.121")
    window._populate_product_targets()
    assert not fields["password"].text()
    assert not window._product_credentials.get(ids["a"], None) or not window._product_credentials[ids["a"]].password


def test_new_product_archive_is_stable_and_does_not_enter_vcenter_batches(product_window):
    window, db, ids = product_window
    env = next(e for e in window._display_archives if e.environment_id == ids["a"])
    window._edit_environment(env)
    assert window.environment_product_input.currentData() == "nsx"
    assert not window.environment_product_input.isEnabled()
    assert window.environment_username_input.isHidden()
    window.environment_name_input.setText("改名后的 NSX")
    window._save_environment()
    target = next(t for t in store.list_targets(db) if t.target_id == ids["a"])
    assert target.name == "改名后的 NSX"
    assert not target.username
    assert ids["a"] not in {e.environment_id for e in window._environment_archives}
    window._select_product_archive(next(e for e in window._display_archives if e.environment_id == ids["a"]))
    assert not window.product_scope_checks["vcenter"].isChecked()
    assert window._selected_product_targets()[0].target_id == ids["a"]
    assert window._environment_id is None


def saved_module(db, target_id, run_id, *, status="normal", name="基础服务状态"):
    target = next(t for t in store.list_targets(db) if t.target_id == target_id)
    module = new_module(target)
    module["checks"] = [make_check("services", name, status, values={"service":"UP"},
        sources=[make_source("/api/v1/node/services")], basis="设备原生状态", verification="fixture")]
    module = finish_module(module)
    store.create_run(db, run_id, [target], "离线产品任务")
    store.save_module(db, run_id, module); store.finish_run(db, run_id, "completed")
    return target


def test_results_keep_target_history_and_do_not_call_vcenter_query(product_window):
    window, db, ids = product_window
    saved_module(db, ids["a"], "integrated-a")
    saved_module(db, ids["other"], "integrated-b", status="collection_failed", name="同地址不同客户失败")
    window._show_product_results(target_id=ids["a"])
    assert window.inspection_pages.currentIndex() == 4
    assert window.product_result_run.count() == 1
    assert window.product_result_run.currentData() == "integrated-a"
    assert window.product_result_table.rowCount() == 1
    assert window.product_result_table.item(0, 2).text() == "正常"
    assert "fixture" in window.product_result_detail.toPlainText()
    assert window.product_result_table.item(0, 4).text() == "离线样本"
    assert "另一客户" not in window.product_result_detail.toPlainText()
    window.product_result_status.setCurrentIndex(window.product_result_status.findData("collection_failed"))
    assert window.product_result_table.rowCount() == 0


def test_report_center_uses_saved_formats_and_keeps_new_products_out_of_legacy_queries(product_window, tmp_path, monkeypatch):
    window, db, ids = product_window
    saved_module(db, ids["a"], "integrated-report")
    html = tmp_path / "combined" / "index.html"; html.parent.mkdir(); html.write_text("offline fixture", encoding="utf-8")
    word = html.parent / "report.docx"; word.write_bytes(b"offline fixture")
    store.save_report(db, "integrated-report", "html", str(html), "success")
    store.save_report(db, "integrated-report", "docx", str(word), "success")
    window._refresh_all_data()
    item = next(item for item in window._report_items if item.run_id == "integrated-report")
    assert window._report_formats(item) == {"HTML":html,"Word":word}
    assert window._word_report_path_for_item(item) == word
    assert window._display_report_kind(item) == "综合巡检"
    window._populate_reports([item]); window._report_selection_changed()
    assert not window.delete_report_button.isEnabled()
    assert window.report_task_button.isEnabled()
    window._report_view_task()
    assert window.inspection_pages.currentIndex() == 4


def test_missing_schema_read_does_not_create_or_migrate(tmp_path):
    from vstacklens.desktop.product_inspection import product_schema_ready
    missing = tmp_path / "missing.db"
    assert not product_schema_ready(missing)
    assert not missing.exists()
    from vstacklens.db.connection import init_db
    old = tmp_path / "legacy.db"; init_db(old)
    assert not product_schema_ready(old)
    assert not store.schema_ready(old)


def test_worker_redacts_failure_and_clears_request_credentials(tmp_path):
    from types import SimpleNamespace
    from vstacklens.desktop.product_inspection import IntegratedInspectionWorker
    from vstacklens.products.model import SessionCredential
    credential = SessionCredential("runtime-user", "runtime-failure-secret")
    request = SimpleNamespace(credentials={"target":credential})
    class Failing:
        def run(self, request, **kwargs):
            raise RuntimeError("runtime-failure-secret authentication failed")
    worker = IntegratedInspectionWorker(Failing(), request)
    errors=[];worker.failed.connect(errors.append);worker.run()
    assert errors and "runtime-failure-secret" not in errors[0]
    assert credential.password == "" and not request.credentials


def pump(app, condition, seconds=5):
    import time
    deadline=time.monotonic()+seconds
    while not condition() and time.monotonic()<deadline:
        app.processEvents()
        QThread.msleep(5)
    app.processEvents()
    assert condition(), "GUI worker did not complete safely within the test budget"


def test_integrated_lifecycle_blocks_duplicate_runs_cancels_and_restarts(product_window, monkeypatch, qt_application_lifetime, tmp_path):
    from threading import Event
    import vstacklens.application.integrated_inspection as integrated
    window, _, ids = product_window
    calls=[]; gate=Event()
    class FakeService:
        def run(self, request, progress_callback=None, cancel_requested=None):
            calls.append(request)
            gate.wait(3)
            state="cancelled" if cancel_requested() else "completed"
            return integrated.IntegratedInspectionResult("lifecycle-test", tmp_path/"missing.html", tmp_path, state=state)
    monkeypatch.setattr(integrated,"IntegratedInspectionService",lambda **kwargs:FakeService())
    window.product_scope_checks["vcenter"].setChecked(False);window.product_scope_checks["nsx"].setChecked(True)
    choose(window,"nsx",ids["a"])
    fields=window._product_forms["nsx"]
    def prepare():
        fields["username"].setText("runtime-only-user");fields["password"].setText("runtime-only-password")
    prepare();window._start_inspection()
    first=window.worker
    pump(qt_application_lifetime,lambda:len(calls)==1)
    assert window._running and not window.start_button.isEnabled()
    assert not window.product_connection_tabs.isEnabled()
    assert not fields["password"].text() and not fields["username"].text()
    window._start_inspection();assert window.worker is first and len(calls)==1
    window._cancel_inspection();gate.set()
    pump(qt_application_lifetime,lambda:window.worker is None)
    assert window.current_result.state=="cancelled"
    assert not window._running and window.start_button.isEnabled()
    assert not calls[0].credentials
    # A subsequent single run gets a fresh credential map and normal cleanup.
    prepare();window._start_inspection()
    pump(qt_application_lifetime,lambda:window.worker is None)
    assert len(calls)==2 and window.current_result.state=="completed"
    assert not calls[1].credentials


def test_exit_waits_for_integrated_worker_then_clears_private_fields(product_window, monkeypatch, qt_application_lifetime, tmp_path):
    from threading import Event
    import vstacklens.application.integrated_inspection as integrated
    window, _, ids = product_window
    entered=Event();release=Event()
    class FakeService:
        def run(self, request, progress_callback=None, cancel_requested=None):
            entered.set();release.wait(3)
            assert cancel_requested()
            return integrated.IntegratedInspectionResult("exit-test",tmp_path/"missing.html",tmp_path,state="cancelled")
    monkeypatch.setattr(integrated,"IntegratedInspectionService",lambda **kwargs:FakeService())
    window.product_scope_checks["vcenter"].setChecked(False);window.product_scope_checks["avi"].setChecked(True)
    choose(window,"avi",ids["avi"])
    fields=window._product_forms["avi"];fields["username"].setText("runtime-user");fields["password"].setText("runtime-secret")
    window._start_inspection();pump(qt_application_lifetime,entered.is_set)
    window._begin_exit()
    assert window._batch_closing and not window._exit_ready
    assert window.worker is not None and window.worker.isRunning()
    release.set();pump(qt_application_lifetime,lambda:window.worker is None and window._exit_ready)
    assert not fields["password"].text() and not window._product_credentials


def test_cross_customer_selected_targets_are_rejected_before_execution(product_window, monkeypatch):
    import vstacklens.application.integrated_inspection as integrated
    from PySide6.QtWidgets import QMessageBox
    window, _, ids = product_window
    window.product_scope_checks["vcenter"].setChecked(False);window.product_scope_checks["nsx"].setChecked(True)
    for key in ("a","other"):
        choose(window,"nsx",ids[key]);fields=window._product_forms["nsx"]
        fields["username"].setText("runtime-user");fields["password"].setText("runtime-password")
    messages=[];monkeypatch.setattr(QMessageBox,"warning",lambda _parent,_title,text:messages.append(text))
    monkeypatch.setattr(integrated,"IntegratedInspectionService",lambda **kwargs:pytest.fail("must not execute across customers"))
    window._start_inspection()
    assert messages and "同一客户" in messages[0]
    assert window.worker is None and not window._running


def test_vcenter_only_still_constructs_the_existing_worker(product_window, monkeypatch):
    import vstacklens.desktop.app as app_module
    window, _, ids=product_window
    window._select_inspection_environment(ids["vc"]);window.username_input.setText("runtime-vc");window.password_input.setText("runtime-vc-password")
    called=[]
    def existing_worker(service, config):
        called.append(config.environment_id)
        raise RuntimeError("existing-worker-sentinel")
    monkeypatch.setattr(app_module,"InspectionWorker",existing_worker)
    monkeypatch.setattr(window,"_start_product_inspection",lambda:pytest.fail("vCenter-only must retain its existing path"))
    with pytest.raises(RuntimeError,match="existing-worker-sentinel"):
        window._start_inspection()
    assert called==[ids["vc"]]



def test_changing_selected_scope_clears_previous_integrated_result(product_window, tmp_path):
    from vstacklens.application.integrated_inspection import IntegratedInspectionResult
    window, _, ids = product_window
    window.current_result=IntegratedInspectionResult("previous-result",tmp_path/"old.html",tmp_path,state="completed")
    for control in (window.open_report_button,window.open_word_button,window.open_pdf_button,window.open_dir_button):
        control.setEnabled(True)
    window.product_scope_checks["nsx"].setChecked(True)
    assert window.current_result is None
    assert not any(control.isEnabled() for control in (window.open_report_button,window.open_word_button,window.open_pdf_button,window.open_dir_button))



def test_combined_manual_vcenter_keeps_credentials_runtime_only(product_window, monkeypatch, qt_application_lifetime, tmp_path):
    import sqlite3
    import vstacklens.application.integrated_inspection as integrated
    window, db, ids = product_window
    calls=[]
    class FakeService:
        def run(self, request, progress_callback=None, cancel_requested=None):
            target=next(t for t in request.targets if t.product == "vcenter")
            credential=request.credentials[target.target_id]
            assert credential.username == "manual-vcenter-runtime-user"
            assert credential.password == "manual-vcenter-runtime-password"
            calls.append(request)
            return integrated.IntegratedInspectionResult("manual-vcenter-test",tmp_path/"missing.html",tmp_path,state="completed")
    monkeypatch.setattr(integrated,"IntegratedInspectionService",lambda **kwargs:FakeService())
    assert window._inspection_environment_id is None
    window.product_scope_checks["nsx"].setChecked(True)
    window.vcenter_input.setText("192.0.2.12")
    window.customer_input.setText("离线客户甲")
    window.username_input.setText("manual-vcenter-runtime-user")
    window.password_input.setText("manual-vcenter-runtime-password")
    choose(window,"nsx",ids["a"])
    fields=window._product_forms["nsx"]
    fields["username"].setText("manual-nsx-runtime-user")
    fields["password"].setText("manual-nsx-runtime-password")
    window._start_inspection()
    pump(qt_application_lifetime,lambda:window.worker is None)
    assert len(calls)==1 and not calls[0].credentials
    archived=next(e for e in window.service.list_environment_archives(db) if e.host=="192.0.2.12")
    assert archived.username == ""
    with sqlite3.connect(db) as conn:
        persisted="\n".join(conn.iterdump())
    for private_value in ("manual-vcenter-runtime-user","manual-vcenter-runtime-password","manual-nsx-runtime-user","manual-nsx-runtime-password"):
        assert private_value not in persisted
