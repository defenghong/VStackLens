from pathlib import Path
import os
import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QPushButton
from vstacklens.application import DesktopInspectionConfig, InspectionService
from vstacklens.application.inspection_runner import InspectionRunner, MockRunRequest
from vstacklens.desktop.app import MainWindow
from vstacklens.desktop.presentation import local_time, ui_text, object_name

ROOT = Path(__file__).resolve().parents[1]

@pytest.mark.parametrize("value,expected", [
    ("2026-10-08T01:02:03.456789+00:00", "2026-10-08 09:02"),
    ("2026-10-08T23:30:01Z", "2026-10-09 07:30"),
    ("2026-10-08T09:02:03+08:00", "2026-10-08 09:02"),
    (None, "—"),
])
def test_local_timestamp(value, expected):
    assert local_time(value) == expected
    assert ui_text(ui_text(value)) == ui_text(value)

@pytest.mark.parametrize("value,expected", [("ClusterComputeResource", "集群"), ("HostSystem", "ESXi 主机"), ("VirtualMachine", "虚拟机"), ("Datastore", "数据存储"), ("success", "成功"), ("failed", "失败"), ("running", "进行中"), ("vSAN", "vSAN")])
def test_central_names(value, expected):
    assert object_name(value) == expected
    assert ui_text(value) == expected

def window_for(tmp_path):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    app = QApplication.instance() or QApplication(["3a-test", "-platform", "offscreen"])
    service = InspectionService(config_path=tmp_path / "config.json")
    service.save_config(DesktopInspectionConfig(db_path=tmp_path / "data.db", report_output_dir=tmp_path / "reports", rulepack_path=ROOT / "rulepacks/builtin-vsphere-v1"))
    window = MainWindow(service=service); window.show(); app.processEvents()
    return app, window

def test_home_without_records_has_one_action_and_no_empty_tables(tmp_path):
    app, window = window_for(tmp_path)
    try:
        assert window.dashboard_stack.currentIndex() == 0
        buttons = [b for b in window.pages.currentWidget().findChildren(QPushButton) if b.isVisible()]
        assert [b.text() for b in buttons] == ["开始标准巡检"]
        assert not window.dashboard_reports_table.isVisible()
        assert not window.trend_fold.isVisible()
        assert window.current_object_label.text() == "尚无巡检记录"
        for i in range(window.nav.count()):
            if not window.nav.item(i).data(Qt.UserRole): assert not window.nav.item(i).flags() & Qt.ItemIsSelectable
    finally: window.close()

def test_nonreported_link_opens_risk_center_with_filter(tmp_path):
    app, window = window_for(tmp_path)
    try:
        result = InspectionRunner().run_mock(MockRunRequest(db_path=tmp_path / "data.db", report_dir=tmp_path / "reports", rulepack_path=ROOT / "rulepacks/builtin-vsphere-v1", fixture_path=ROOT / "tests/fixtures/inventory_fail.json"))
        window._refresh_all_data(); app.processEvents()
        completed = window.service._complete_result(tmp_path / "data.db", result.run_id, tmp_path / "reports", None)
        window._inspection_completed(completed)
        assert window.start_button.text() == "重新巡检"
        assert window.start_button.objectName() == "outlineButton"
        assert window.view_standard_report_button.objectName() == "primaryButton"
        assert window.standard_summary.layout.itemAt(0).widget().text() == "结果摘要"
        assert "31 类问题" in window.scope_label.text()
        assert "完成时间：" in window.scope_hint.text()
        assert result.run_id not in window.dashboard_scope_label.text()
        assert window.dashboard_scope_label.toolTip() == result.run_id
        assert window.dashboard_non_reported.text().endswith("›")
        assert window.dashboard_non_reported.isEnabled()
        window.dashboard_non_reported.click(); app.processEvents()
        assert window.nav.currentItem().data(Qt.UserRole) == "risk_center"
        assert window.risk_non_reported.isChecked()
        assert len([x for x in window._risk_groups if not x[2]]) == 31
        assert any(x[2] == "P4" for x in window._risk_groups)
        assert window._overview.run_id == result.run_id
        window.go_to_module("log_analysis")
        assert window.current_object_label.text() == "本次无需连接 vCenter"
    finally: window.close()

def test_latest_failed_task_does_not_replace_valid_desktop_scope_or_trend(tmp_path):
    import json
    from tests.license_sdk_evidence import with_declared_license_sources
    from vstacklens.db.connection import connect
    service = InspectionService(config_path=tmp_path / "config.json")
    db = tmp_path / "data.db"
    # A genuinely evaluable synthetic pass run, rather than old scalar-only
    # license inputs which correctly make health assessment limited now.
    raw = json.loads((ROOT / "tests/fixtures/inventory_pass.json").read_text(encoding="utf-8"))
    fixture = tmp_path / "declared-pass.json"
    fixture.write_text(json.dumps(with_declared_license_sources(raw, "pass")), encoding="utf-8")
    def run(folder):
        return InspectionRunner().run_mock(MockRunRequest(db_path=db, report_dir=tmp_path / folder, rulepack_path=ROOT / "rulepacks/builtin-vsphere-v1", fixture_path=fixture))
    valid = run("first")
    invalid = run("second")
    with connect(db) as conn:
        conn.execute("UPDATE inspection_runs SET run_status='failed',updated_at='2099-01-01T00:00:00+00:00' WHERE run_id=?", (invalid.run_id,))
    data = service.get_latest_valid_desktop_data(db)
    assert data.run_id == valid.run_id
    assert [item["run_id"] for item in data.risk_trend] == [valid.run_id]
    assert data.finished_at is not None

def test_internal_name_formatting_is_idempotent():
    text = "ESXi 主机证书即将过期 · HostSystem · 2026-10-08T00:00:01+00:00"
    once = ui_text(text)
    assert once == ui_text(once)
    assert "主机 主机" not in once

def test_display_task_numbers_use_shanghai_day_and_do_not_write(tmp_path):
    import sqlite3
    from vstacklens.desktop.presentation import task_numbers
    db = tmp_path / "numbering.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE inspection_runs (run_id TEXT, created_at TEXT)")
        conn.executemany("INSERT INTO inspection_runs VALUES (?, ?)", [("run_b", "2026-10-08T16:01:00Z"), ("run_a", "2026-10-08T15:59:00Z"), ("run_c", "2026-10-08T17:00:00Z")])
    before = db.read_bytes()
    assert task_numbers(db) == {"run_a": "S-20261008-01", "run_b": "S-20261009-01", "run_c": "S-20261009-02"}
    assert db.read_bytes() == before

def test_current_sentence_uses_supplied_values_units_and_no_fabricated_zero():
    from types import SimpleNamespace
    from vstacklens.desktop.presentation import current_sentence
    item = SimpleNamespace(rule_id="VSL-CL-005", rule_name="集群 CPU 使用率", title="", current_observed="91", expected_state="< 80", raw_evidence={})
    assert current_sentence(item) == "集群 CPU 使用率 91%，建议低于 80%。"
    item.current_observed = ""; item.expected_state = ""
    assert "0" not in current_sentence(item)
    assert "尚无可展示的当前值" in current_sentence(item)
