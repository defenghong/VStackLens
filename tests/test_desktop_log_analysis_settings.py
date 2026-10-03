from __future__ import annotations

import os
from pathlib import Path

import pytest


pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication, QCheckBox, QLabel, QPushButton  # noqa: E402
import pymupdf  # noqa: E402

from vstacklens.application import DesktopInspectionConfig, InspectionService, ModelConfigProfile  # noqa: E402
from vstacklens.application.inspection_service import ReportCenterItem  # noqa: E402
from vstacklens.application.cloud_log_diagnosis import CloudModelClient, CloudModelResult  # noqa: E402
from vstacklens.desktop import app as desktop_app  # noqa: E402
from vstacklens.desktop.app import MainWindow, configure_chinese_font  # noqa: E402
from vstacklens.desktop.pdf_reader import PdfReaderDialog  # noqa: E402


def _app() -> QApplication:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    app = QApplication.instance()
    if app is None:
        app = QApplication(["vstacklens-desktop-log-analysis-settings-test", "-platform", "offscreen"])
    return app


def _window_with_config(tmp_path: Path, config: DesktopInspectionConfig) -> MainWindow:
    service = InspectionService(config_path=tmp_path / "desktop_config.json")
    service.save_config(config)
    app = _app()
    configure_chinese_font(app)
    window = MainWindow(service=service)
    window.show()
    app.processEvents()
    return window


def test_log_analysis_page_uses_profile_and_model_selectors_not_api_fields(tmp_path: Path) -> None:
    window = _window_with_config(
        tmp_path,
        DesktopInspectionConfig(
            model_config_profiles=[
                ModelConfigProfile(
                    profile_id="deepseek-prod",
                    profile_name="DeepSeek 生产账号",
                    provider="deepseek",
                    api_url="https://api.deepseek.com/chat/completions",
                    api_key="sk-secret",
                    default_model="deepseek-reasoner",
                    available_models=["deepseek-reasoner", "deepseek-chat"],
                    is_default=True,
                )
            ]
        ),
    )
    app = _app()
    window.go_to_module("log_analysis")
    app.processEvents()

    page = window.pages.currentWidget()
    visible_text = []
    visible_text.extend(label.text() for label in page.findChildren(QLabel))
    visible_text.extend(button.text() for button in page.findChildren(QPushButton))
    visible_text.extend(box.text() for box in page.findChildren(QCheckBox))
    text = "\n".join(visible_text)

    assert "启用大模型辅助分析" in text
    assert "模型配置" in text
    assert "模型" in text
    assert "状态" in text
    assert "API Key" not in text
    assert "API 地址" not in text
    assert "Provider" not in text
    assert "超时" not in text
    assert window.log_model_profile_combo.count() == 1
    assert window.log_model_profile_combo.currentText() == "DeepSeek 生产账号"
    assert window.log_model_input.currentText() == "deepseek-reasoner"
    window.close()


def test_report_center_pdf_button_opens_pdf_file_path(tmp_path: Path, monkeypatch) -> None:
    app = _app()
    window = MainWindow(service=InspectionService(config_path=tmp_path / "desktop_config.json"))
    report_dir = tmp_path / "reports" / "run-1"
    report_dir.mkdir(parents=True)
    html_path = report_dir / "index.html"
    html_path.write_text("<html></html>", encoding="utf-8")
    pdf_path = report_dir / "VStackLens-PDF-Report.pdf"
    pdf_path.write_bytes(b"%PDF-1.4\nfixture")
    item = ReportCenterItem(
        run_id="run-1",
        report_path=html_path,
        report_dir=report_dir,
        payload_path=None,
        title="测试报告",
        customer_name="测试客户",
        site_name="测试站点",
        assessment_time="2026-09-30",
        score=95,
        risk_summary={"P1": 0, "P2": 0, "P3": 0, "P4": 0},
        asset_summary={"Host": 1, "VM": 1, "Datastore": 1},
        top_risks=[],
        history_summary="暂无历史对比",
        status="可查看",
        report_type="HTML · Word · PDF",
        path_hint=str(html_path),
    )
    window._report_items = [item]
    window.report_list.addItem("测试报告")
    window.report_list.setCurrentRow(0)
    assert window._pdf_report_path_for_item(item) == pdf_path
    window._report_selection_changed()
    app.processEvents()
    opened: list[Path] = []
    monkeypatch.setattr(window, "_open_path_safe", lambda path: opened.append(Path(path)))

    assert window.report_pdf_button.isEnabled()
    window.report_pdf_button.click()
    app.processEvents()
    assert opened == [pdf_path]
    window.close()


def test_pdf_reader_renders_pages_and_navigates_without_browser(tmp_path: Path) -> None:
    app = _app()
    pdf_path = tmp_path / "reader-test.pdf"
    document = pymupdf.open()
    document.new_page().insert_text((72, 72), "Page one")
    document.new_page().insert_text((72, 72), "Page two")
    document.save(pdf_path)
    document.close()

    reader = PdfReaderDialog(pdf_path)

    assert reader.page_label.text() == "第 1 / 2 页"
    assert reader.page_image.pixmap() is not None
    reader.next_button.click()
    app.processEvents()
    assert reader.page_label.text() == "第 2 / 2 页"
    reader.close()


def test_settings_page_shows_collapsible_model_and_security_sections(tmp_path: Path) -> None:
    window = _window_with_config(tmp_path, DesktopInspectionConfig())
    app = _app()
    window.go_to_module("settings")
    app.processEvents()

    page = window.pages.currentWidget()
    buttons = [button.text() for button in page.findChildren(QPushButton)]
    labels = [label.text() for label in page.findChildren(QLabel)]
    text = "\n".join(buttons + labels)

    assert "大模型设置" in text
    assert "安全设置" in text
    assert buttons.count("展开配置") >= 2
    assert hasattr(window, "settings_model_profile_combo")
    assert hasattr(window, "privacy_level_combo")
    window.close()


def test_upgrade_compatibility_page_uses_the_isolated_database(tmp_path: Path) -> None:
    primary_db = tmp_path / "inspection.db"
    window = _window_with_config(tmp_path, DesktopInspectionConfig(db_path=primary_db))

    assert window._current_upgrade_compat_config().db_path == tmp_path / "inspection-compat.db"
    assert not hasattr(window, "upgrade_open_word_button")
    assert window.upgrade_open_html_button.text() == "打开 HTML 报告"

    window.close()


def test_log_analysis_page_loads_cached_models_from_system_settings(tmp_path: Path) -> None:
    window = _window_with_config(
        tmp_path,
        DesktopInspectionConfig(
            model_config_profiles=[
                ModelConfigProfile(
                    profile_id="deepseek-prod",
                    profile_name="DeepSeek 生产账号",
                    provider="deepseek",
                    api_url="https://api.deepseek.com/chat/completions",
                    api_key="sk-secret",
                    default_model="deepseek-chat",
                    available_models=["deepseek-reasoner", "deepseek-chat"],
                    connection_status="connected",
                    connection_checked_at="2026-07-09 14:30",
                    is_default=True,
                ),
                ModelConfigProfile(
                    profile_id="local-ollama",
                    profile_name="本地 Ollama",
                    provider="ollama",
                    api_url="http://127.0.0.1:11434/v1/chat/completions",
                    api_key="",
                    default_model="qwen2.5",
                    available_models=["qwen2.5", "llama3.1"],
                ),
            ]
        ),
    )
    app = _app()
    window.go_to_module("log_analysis")
    app.processEvents()

    assert window.log_model_profile_combo.count() == 2
    assert window.log_model_input.currentText() == "deepseek-chat"
    assert "已连接" in window.log_cloud_status_label.text()
    window.log_model_profile_combo.setCurrentIndex(1)
    app.processEvents()
    assert window.log_model_input.currentText() == "qwen2.5"
    window.close()


def test_refresh_model_list_failure_keeps_cached_models(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    window = _window_with_config(
        tmp_path,
        DesktopInspectionConfig(
            model_config_profiles=[
                ModelConfigProfile(
                    profile_id="deepseek-prod",
                    profile_name="DeepSeek 生产账号",
                    provider="deepseek",
                    api_url="https://api.deepseek.com/chat/completions",
                    api_key="sk-secret",
                    default_model="deepseek-reasoner",
                    available_models=["deepseek-reasoner", "deepseek-chat"],
                    is_default=True,
                )
            ]
        ),
    )
    app = _app()
    window.go_to_module("log_analysis")
    app.processEvents()

    def fake_list_models(self) -> CloudModelResult:
        return CloudModelResult(False, fallback_reason="HTTP 500: internal failure")

    monkeypatch.setattr(CloudModelClient, "list_models", fake_list_models)
    window._refresh_log_profile_models()
    app.processEvents()

    assert window.log_model_input.count() >= 2
    assert "deepseek-reasoner" in [window.log_model_input.itemText(i) for i in range(window.log_model_input.count())]
    assert "刷新失败" in window.log_cloud_status_label.text()
    window.close()


def test_local_only_security_policy_disables_cloud_usage(tmp_path: Path) -> None:
    window = _window_with_config(
        tmp_path,
        DesktopInspectionConfig(
            security_privacy_level="local-only",
            model_config_profiles=[
                ModelConfigProfile(
                    profile_id="deepseek-prod",
                    profile_name="DeepSeek 生产账号",
                    provider="deepseek",
                    api_url="https://api.deepseek.com/chat/completions",
                    api_key="sk-secret",
                    default_model="deepseek-reasoner",
                    available_models=["deepseek-reasoner"],
                    connection_status="connected",
                    connection_checked_at="2026-07-09 14:30",
                    is_default=True,
                )
            ],
        ),
    )
    app = _app()
    window.go_to_module("log_analysis")
    app.processEvents()

    assert window.log_cloud_enabled_input.isEnabled() is False
    assert window._current_log_analysis_config().cloud_assist_enabled is False
    window.close()


def test_saved_api_key_is_not_echoed_in_ui_status_or_log_analysis_page(tmp_path: Path) -> None:
    api_key = "sk-secret-value"
    api_url = "https://api.deepseek.com/chat/completions"
    window = _window_with_config(
        tmp_path,
        DesktopInspectionConfig(
            model_config_profiles=[
                ModelConfigProfile(
                    profile_id="deepseek-prod",
                    profile_name="DeepSeek 生产账号",
                    provider="deepseek",
                    api_url=api_url,
                    api_key=api_key,
                    default_model="deepseek-reasoner",
                    available_models=["deepseek-reasoner"],
                    connection_status="connected",
                    connection_checked_at="2026-07-09 14:30",
                    is_default=True,
                )
            ]
        ),
    )
    app = _app()
    window.go_to_module("settings")
    app.processEvents()

    assert window.settings_profile_api_key_input.text() == ""
    assert "已保存" in window.settings_profile_api_key_input.placeholderText()
    assert window.settings_profile_api_key_input.toolTip() == "API Key 将保存在本机配置中用于后续复用，不会写入报告或日志。"
    assert api_key not in window.settings_profile_status_label.text()
    assert api_url not in window.settings_profile_status_label.text()

    window.go_to_module("log_analysis")
    app.processEvents()
    assert api_key not in window.log_cloud_status_label.text()
    assert api_url not in window.log_cloud_status_label.text()
    window.close()


def test_save_settings_message_explains_password_and_api_key_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    window = _window_with_config(tmp_path, DesktopInspectionConfig())
    app = _app()
    window.go_to_module("settings")
    app.processEvents()

    captured: dict[str, str] = {}

    def fake_information(_parent, title: str, message: str) -> None:
        captured["title"] = title
        captured["message"] = message

    monkeypatch.setattr(desktop_app.QMessageBox, "information", fake_information)
    window._save_current_config()

    assert captured["title"] == "配置已保存"
    assert captured["message"] == "配置已保存。登录密码不会写入本地配置文件；模型 API Key 将保存到本机配置档案中用于后续复用。"
    window.close()
