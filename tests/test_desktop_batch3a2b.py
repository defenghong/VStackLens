from vstacklens.desktop.layout3a2b import LOG_STEPS,log_step
from test_desktop_layout3a import window_for


def test_log_analysis_progress_stages_map_to_four_steps_and_failure_stays(tmp_path):
    expected={"reading_bundle":0,"analyzing_logs":1,"cloud_planning":1,"cloud_diagnosing":2,"rendering_html":3,"rendering_docx":3,"completed":3}
    assert tuple(LOG_STEPS)==("读取日志","整理证据","形成判断","生成报告")
    for stage,index in expected.items():assert log_step(stage,0)==index
    for index in range(4):assert log_step("failed",index)==index


def test_upgrade_collection_radios_preserve_original_service_values(tmp_path):
    app,window=window_for(tmp_path)
    try:
        for radio,value in ((window.upgrade_vcenter_radio,"vcenter"),(window.upgrade_bundle_radio,"support_bundle")):
            radio.setChecked(True);app.processEvents()
            assert radio.isChecked()
            assert window.upgrade_collection_combo.currentData()==value
            assert window._current_upgrade_compat_config().collection_mode==value
    finally:window.close()


def test_about_page_lists_only_implemented_primary_modules(tmp_path):
    app,window=window_for(tmp_path)
    try:
        assert window.about_feature_names==["标准巡检","日志分析","升级兼容性"]
        window.go_to_module("license");app.processEvents()
        from PySide6.QtWidgets import QLabel
        text=" ".join(label.text() for label in window.pages.currentWidget().findChildren(QLabel))
        assert all(name in text for name in ("标准巡检","日志分析","升级兼容性"))
        assert "深度巡检" not in text and "NSX" not in text
    finally:window.close()


def test_log_cloud_privacy_notice_follows_selection_and_local_only_disables_call(tmp_path):
    app,window=window_for(tmp_path)
    try:
        window.go_to_module("log_analysis");app.processEvents()
        window.log_cloud_enabled_input.setChecked(True);app.processEvents()
        assert window.log_privacy_notice.isVisible()
        assert "筛选后的日志证据" in window.log_privacy_notice.text()
        assert "遮蔽敏感字段" in window.log_privacy_notice.text()
        index=window.privacy_level_combo.findData("local-only")
        window.privacy_level_combo.setCurrentIndex(index);app.processEvents()
        assert "仅本地" in window.log_privacy_notice.text()
        assert not window._current_log_analysis_config().cloud_assist_enabled
    finally:window.close()


def test_failed_log_event_keeps_last_rendered_progress_and_marks_current_step(tmp_path):
    from vstacklens.application import LogAnalysisProgress
    app,window=window_for(tmp_path)
    try:
        window._log_analysis_progress(LogAnalysisProgress(None,"cloud_diagnosing",68,"形成判断"))
        window._log_analysis_progress(LogAnalysisProgress(None,"failed",100,"失败"))
        assert window.log_progress_bar.value()==68
        assert window._log_step_index==2
        assert window.log_step_icons[2].property("stepStatus")=="failed"
        assert "68%" in window.log_status_label.text()
    finally:window.close()


def test_server_status_display_uses_existing_server_codes(tmp_path):
    from types import SimpleNamespace
    app,window=window_for(tmp_path)
    try:
        result=SimpleNamespace(device_results=[],server_results=[{"model":"a","status":"SERVER_CERTIFIED"},{"model":"b","status":"SERVER_NOT_CERTIFIED"},{"model":"c","status":"SERVER_UNKNOWN_MODEL"}])
        window._batch2_upgrade_results(result)
        group=window.upgrade_result_tree.topLevelItem(0)
        assert [group.child(i).text(2) for i in range(3)]==["通过","不通过","无法确定"]
    finally:window.close()


def test_upgrade_page_status_distinguishes_running_finished_and_connection_diagnostic(tmp_path):
    from vstacklens.application import UpgradeCompatProgress
    app,window=window_for(tmp_path)
    try:
        assert window.upgrade_stage_label.text()=="等待检查"
        for stage,expected in (("collecting","进行中"),("success","完成"),("cancelled","已取消"),("connection_diagnostic","连接诊断")):
            window._upgrade_compat_progress(UpgradeCompatProgress(None,stage,50,"原阶段说明"))
            assert window.upgrade_stage_label.text()==expected
            assert "原阶段说明" in window.upgrade_status_label.text()
    finally:window.close()


def test_log_empty_result_shrinks_and_expands_for_real_text(tmp_path):
    app,window=window_for(tmp_path)
    try:
        window.go_to_module("log_analysis");app.processEvents()
        window.log_result_summary.clear();app.processEvents()
        assert window.log_result_summary.isHidden() and not window.log_result_empty.isHidden()
        window.log_result_summary.setPlainText("已有分析结果");app.processEvents()
        assert not window.log_result_summary.isHidden() and window.log_result_empty.isHidden()
        from vstacklens.desktop.widgets import StatusBadge
        assert all(not isinstance(label,StatusBadge) for label in window.log_step_labels)
        window._batch2_log_state("cloud_diagnosing")
        assert [x.property("stepStatus") for x in window.log_step_icons]==["success","success","running","unknown"]
    finally:window.close()


def test_settings_entire_header_and_keyboard_toggle_existing_details(tmp_path):
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    app,window=window_for(tmp_path)
    try:
        window.go_to_module("settings");app.processEvents()
        assert len(window.settings_fold_headers)==3
        for header in window.settings_fold_headers:
            assert header.detail.isHidden() and header.toggle.isHidden()
            QTest.mouseClick(header,Qt.LeftButton);app.processEvents()
            assert not header.detail.isHidden()
            header.setFocus();QTest.keyClick(header,Qt.Key_Space);app.processEvents()
            assert header.detail.isHidden()
    finally:window.close()


def test_upgrade_zero_counts_mute_status_without_changing_status_text(tmp_path):
    from vstacklens.desktop.widgets import StatusBadge
    app,window=window_for(tmp_path)
    try:
        card=window.upgrade_metric_pass;badge=card.findChildren(StatusBadge)[0];text=badge.text();state=badge.property("status")
        window._set_upgrade_metric_value(card,0)
        assert badge.property("zero") is True and badge.text()==text and badge.property("status")==state
        from vstacklens.desktop.theme import COLORS
        badge.ensurePolished();assert badge.palette().color(badge.foregroundRole()).name().upper()==COLORS["subtext"]
        window._set_upgrade_metric_value(card,2)
        assert badge.property("zero") is False and badge.text()==text and badge.property("status")==state
    finally:window.close()


def test_about_local_materials_has_three_location_rows_and_log_path_in_details(tmp_path):
    from PySide6.QtWidgets import QLabel,QPushButton
    from vstacklens.desktop.layout3a import FoldSection
    from vstacklens.desktop.widgets import SectionCard
    app,window=window_for(tmp_path)
    try:
        window.go_to_module("license");app.processEvents();page=window.pages.currentWidget()
        local=next(card for card in page.findChildren(SectionCard) if any(label.text()=="本地资料" for label in card.findChildren(QLabel)))
        assert sum(button.text()=="查看位置" for button in local.findChildren(QPushButton))==3
        assert sum(button.text()=="复制日志路径" for button in local.findChildren(QPushButton))==1
        assert not any("vstacklens-desktop.log" in label.text() for label in local.findChildren(QLabel))
        info=next(fold for fold in page.findChildren(FoldSection) if fold.title=="软件信息")
        assert any("vstacklens-desktop.log" in label.text() for label in info.findChildren(QLabel))
    finally:window.close()
