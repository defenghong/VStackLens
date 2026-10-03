from __future__ import annotations

import json
import inspect
import ssl
import zipfile
from pathlib import Path

import pytest
from docx import Document

from vstacklens.application import DesktopInspectionConfig, InspectionService, InspectionState, ModelConfigProfile
from vstacklens.application.inspection_runner import InspectionRunner, RunnerCancelledError
from vstacklens.application.connection_probe import ProbeResult, friendly_connection_error
from vstacklens.application import inspection_service
from vstacklens.application.artifact_safety import sanitize_text, scan_artifacts
from vstacklens.application.paths import builtin_rulepack_path, default_log_dir
from vstacklens.collection.mock_collector import MockCollector
from vstacklens.db.connection import connect
from vstacklens.reports.run_compare import RunComparisonBuilder


ROOT = Path(__file__).resolve().parents[1]
RULEPACK = ROOT / "rulepacks" / "builtin-vsphere-v1"
FIXTURE = ROOT / "tests" / "fixtures" / "inventory_pass.json"
FAIL_FIXTURE = ROOT / "tests" / "fixtures" / "inventory_fail.json"


def _history_comparison_second_fixture() -> dict:
    payload = json.loads(FAIL_FIXTURE.read_text(encoding="utf-8"))
    vm_template = next(obj for obj in payload["objects"] if obj["object_type"] == "VirtualMachine")
    payload["objects"] = [obj for obj in payload["objects"] if obj["object_key"] != vm_template["object_key"]]
    new_vm = json.loads(json.dumps(vm_template, ensure_ascii=False))
    new_vm["object_key"] = "vm-2"
    new_vm["object_name"] = "app-02"
    new_vm["object_path"] = str(new_vm.get("object_path") or "Default/mock-vcenter.local/app-01").replace("app-01", "app-02")
    payload["objects"].append(new_vm)
    return payload


def test_service_validates_and_saves_extensible_config_without_password(tmp_path: Path) -> None:
    service = InspectionService(config_path=tmp_path / "desktop_config.json")
    missing = DesktopInspectionConfig(rulepack_path=RULEPACK)

    errors = service.validate_config(missing)

    assert "请填写 vCenter 地址。" in errors
    assert "请填写 vCenter 用户名。" in errors
    assert "请填写 vCenter 密码。" in errors

    config = DesktopInspectionConfig(
        vcenter="vc.local",
        username="administrator@vsphere.local",
        password="secret",
        customer_name="客户 A",
        site_name="生产站点",
        report_output_dir=tmp_path / "reports",
        db_path=tmp_path / "desktop.db",
        rulepack_path=RULEPACK,
    )
    service.save_config(config)
    saved = (tmp_path / "desktop_config.json").read_text(encoding="utf-8")
    loaded = service.load_config()

    assert "secret" not in saved
    assert loaded.vcenter == "vc.local"
    assert loaded.username == "administrator@vsphere.local"
    assert loaded.password == ""
    assert loaded.report_output_dir == tmp_path / "reports"


def test_service_saves_and_loads_model_profiles_and_privacy_level(tmp_path: Path) -> None:
    service = InspectionService(config_path=tmp_path / "desktop_config.json")
    config = DesktopInspectionConfig(
        report_output_dir=tmp_path / "reports",
        db_path=tmp_path / "desktop.db",
        rulepack_path=RULEPACK,
        model_config_profiles=[
            ModelConfigProfile(
                profile_id="deepseek-prod",
                profile_name="DeepSeek 生产账号",
                provider="deepseek",
                api_url="https://api.deepseek.com/chat/completions",
                api_key="sk-secret-key",
                timeout_seconds=60,
                default_model="deepseek-reasoner",
                available_models=["deepseek-reasoner", "deepseek-chat"],
                connection_status="connected",
                connection_checked_at="2026-07-09 14:30",
                is_default=True,
            ),
            ModelConfigProfile(
                profile_id="ollama-local",
                profile_name="本地 Ollama",
                provider="ollama",
                api_url="http://127.0.0.1:11434/v1/chat/completions",
                api_key="",
                timeout_seconds=30,
                default_model="qwen2.5",
                available_models=["qwen2.5"],
                connection_status="untested",
                connection_checked_at="",
                is_default=False,
            ),
        ],
        security_privacy_level="local-only",
    )

    service.save_config(config)
    loaded = service.load_config()
    payload = json.loads((tmp_path / "desktop_config.json").read_text(encoding="utf-8"))

    assert loaded.security_privacy_level == "local-only"
    assert len(loaded.model_config_profiles) == 2
    assert loaded.model_config_profiles[0].profile_name == "DeepSeek 生产账号"
    assert loaded.model_config_profiles[0].available_models == ["deepseek-reasoner", "deepseek-chat"]
    assert loaded.model_config_profiles[0].api_key == "sk-secret-key"
    assert loaded.model_config_profiles[1].provider == "ollama"
    assert payload["model_config_profiles"][0]["api_key"] == "sk-secret-key"
    assert payload["security_privacy_level"] == "local-only"


def test_load_config_repairs_missing_rulepack_path_to_bundled(monkeypatch, tmp_path: Path) -> None:
    stale_rulepack = tmp_path / "old-install" / "_internal" / "rulepacks" / "builtin-vsphere-v1"
    bundled_rulepack = tmp_path / "dist" / "VStackLens" / "_internal" / "rulepacks" / "builtin-vsphere-v1"
    bundled_rulepack.mkdir(parents=True)
    config_path = tmp_path / "desktop_config.json"
    config_path.write_text(
        json.dumps(
            {
                "vcenter": "vc.local",
                "username": "administrator@vsphere.local",
                "report_output_dir": str(tmp_path / "reports"),
                "db_path": str(tmp_path / "desktop.db"),
                "rulepack_path": str(stale_rulepack),
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(inspection_service, "builtin_rulepack_path", lambda: bundled_rulepack)
    service = InspectionService(config_path=config_path)

    loaded = service.load_config()
    saved = json.loads(config_path.read_text(encoding="utf-8"))

    assert not stale_rulepack.exists()
    assert loaded.rulepack_path == bundled_rulepack
    assert saved["rulepack_path"] == str(bundled_rulepack)


def test_load_config_keeps_existing_custom_rulepack_path(monkeypatch, tmp_path: Path) -> None:
    custom_rulepack = tmp_path / "custom-rulepack"
    custom_rulepack.mkdir()
    bundled_rulepack = tmp_path / "dist" / "VStackLens" / "_internal" / "rulepacks" / "builtin-vsphere-v1"
    bundled_rulepack.mkdir(parents=True)
    config_path = tmp_path / "desktop_config.json"
    config_path.write_text(
        json.dumps(
            {
                "vcenter": "vc.local",
                "username": "administrator@vsphere.local",
                "report_output_dir": str(tmp_path / "reports"),
                "db_path": str(tmp_path / "desktop.db"),
                "rulepack_path": str(custom_rulepack),
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(inspection_service, "builtin_rulepack_path", lambda: bundled_rulepack)
    service = InspectionService(config_path=config_path)

    loaded = service.load_config()
    saved = json.loads(config_path.read_text(encoding="utf-8"))

    assert loaded.rulepack_path == custom_rulepack
    assert saved["rulepack_path"] == str(custom_rulepack)


def test_load_config_recovers_from_corrupt_json_without_password(tmp_path: Path) -> None:
    config_path = tmp_path / "desktop_config.json"
    config_path.write_text('{"vcenter": "vc.local", "password": "secret"', encoding="utf-8")
    service = InspectionService(config_path=config_path)

    loaded = service.load_config()

    assert loaded.vcenter == ""
    assert loaded.password == ""
    saved = config_path.read_text(encoding="utf-8")
    assert "secret" not in saved
    assert "password" not in json.loads(saved)
    backups = list(tmp_path.glob("desktop_config.json.corrupt-*"))
    assert len(backups) == 1
    assert "secret" in backups[0].read_text(encoding="utf-8")


def test_load_config_recovers_from_invalid_field_types(tmp_path: Path) -> None:
    config_path = tmp_path / "desktop_config.json"
    config_path.write_text(
        json.dumps(
            {
                "vcenter": ["vc.local"],
                "username": {"name": "administrator"},
                "port": {"bad": "type"},
                "report_output_dir": ["reports"],
                "db_path": {"db": "path"},
                "rulepack_path": 123,
                "report_title": None,
                "previous_run_id": ["run"],
            }
        ),
        encoding="utf-8",
    )
    service = InspectionService(config_path=config_path)

    loaded = service.load_config()

    assert loaded.vcenter == ""
    assert loaded.username == ""
    assert loaded.port == 443
    assert loaded.report_output_dir == DesktopInspectionConfig().report_output_dir
    assert loaded.db_path == DesktopInspectionConfig().db_path
    assert loaded.report_title == DesktopInspectionConfig().report_title
    assert loaded.previous_run_id is None


def test_run_vcenter_inspection_reports_cancelled_without_success(tmp_path: Path) -> None:
    class CancellingRunner:
        def run_vcenter(self, request, progress=None, cancel_requested=None):  # noqa: ANN001, ANN202
            assert cancel_requested is not None
            if progress:
                progress("run_id:run-cancelled", 0)
                progress("collecting_environment", 20)
            raise RunnerCancelledError("巡检已取消。")

    service = InspectionService(config_path=tmp_path / "desktop_config.json", runner=CancellingRunner())
    progress: list[InspectionState] = []
    config = DesktopInspectionConfig(
        vcenter="vc.local",
        username="administrator@vsphere.local",
        password="secret",
        db_path=tmp_path / "desktop.db",
        report_output_dir=tmp_path / "reports",
        rulepack_path=RULEPACK,
    )

    with pytest.raises(RunnerCancelledError):
        service.run_vcenter_inspection(config, progress_callback=lambda item: progress.append(item.state), cancel_requested=lambda: False)

    assert service.get_progress().state == InspectionState.CANCELLED
    assert service.get_progress().run_id == "run-cancelled"
    assert progress[-1] == InspectionState.CANCELLED


def test_runner_atomic_stage_rolls_back_partial_writes(tmp_path: Path) -> None:
    runner = InspectionRunner()
    db_path = tmp_path / "atomic.db"

    with connect(db_path) as conn:
        conn.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, value TEXT NOT NULL)")

        def fail_after_insert() -> None:
            conn.execute("INSERT INTO items (value) VALUES ('partial')")
            raise RuntimeError("stage failed")

        with pytest.raises(RuntimeError, match="stage failed"):
            runner._atomic_stage(conn, "snapshot_inventory", fail_after_insert)

        assert conn.execute("SELECT COUNT(*) AS c FROM items").fetchone()["c"] == 0

        runner._atomic_stage(conn, "finding_deduplication", lambda: conn.execute("INSERT INTO items (value) VALUES ('done')"))

        assert conn.execute("SELECT value FROM items").fetchone()["value"] == "done"


def test_desktop_defaults_use_local_app_data_and_builtin_rulepack(monkeypatch, tmp_path: Path) -> None:
    local_app_data = tmp_path / "LocalAppData"
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))

    config = DesktopInspectionConfig()
    service = InspectionService()

    assert config.db_path == local_app_data / "VStackLens" / "data" / "vstacklens-desktop.db"
    assert config.report_output_dir == local_app_data / "VStackLens" / "reports"
    assert service.config_path == local_app_data / "VStackLens" / "config" / "desktop_config.json"
    assert config.rulepack_path == builtin_rulepack_path()
    assert config.rulepack_path.exists()
    assert config.port == 443
    assert config.ssl_no_verify is False


def test_desktop_config_defaults_to_simple_vcenter_connection() -> None:
    config = DesktopInspectionConfig(
        vcenter="10.0.0.10",
        username="administrator@vsphere.local",
        password="secret",
        port=9443,
        ssl_no_verify=False,
        rulepack_path=RULEPACK,
    ).normalized()

    assert config.vcenter == "10.0.0.10"
    assert config.port == 443
    assert config.ssl_no_verify is False


def test_first_run_initializes_user_writable_workspace_without_password(monkeypatch, tmp_path: Path) -> None:
    local_app_data = tmp_path / "LocalAppData"
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))
    service = InspectionService()

    config = service.initialize_local_workspace()
    saved = service.config_path.read_text(encoding="utf-8")

    assert config.db_path.parent == local_app_data / "VStackLens" / "data"
    assert config.db_path.parent.exists()
    assert config.report_output_dir == local_app_data / "VStackLens" / "reports"
    assert config.report_output_dir.exists()
    assert default_log_dir() == local_app_data / "VStackLens" / "logs"
    assert default_log_dir().exists()
    assert service.config_path == local_app_data / "VStackLens" / "config" / "desktop_config.json"
    assert service.config_path.exists()
    assert "password" not in saved


def test_inspection_service_does_not_import_cli_private_pipeline() -> None:
    source = inspect.getsource(inspection_service)

    assert "from vstacklens.cli" not in source
    assert "_run_pipeline" not in source
    assert "_load_registry" not in source
    assert "_previous_run_for_args" not in source


def test_artifact_safety_scan_detects_customer_visible_sensitive_terms(tmp_path: Path) -> None:
    report = tmp_path / "index.html"
    payload = tmp_path / "payload.json"
    docx_path = tmp_path / "report.docx"
    zip_path = tmp_path / "report.zip"
    report.write_text("Authorization: Bearer abc123\nP4 P4级 PDF/PPT PDF导出 PPT导出\n期望值：bad\nC:\\Users\\admin\\project", encoding="utf-8")
    payload.write_text('{"status": "失败", "path": "src\\\\vstacklens\\\\application"}', encoding="utf-8")
    document = Document()
    document.add_paragraph("TimeoutError from site-packages")
    document.save(docx_path)
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("index.html", "Traceback\npassword=secret")

    findings = scan_artifacts([report, payload, docx_path, zip_path])
    reasons = "\n".join(item.reason for item in findings)
    sanitized = sanitize_text("password=secret token=abc Authorization: Bearer aaa C:\\Users\\admin\\project D:\\软件开发\\repo\\src\\vstacklens\\x.py traceback")

    assert findings
    for expected in ("Authorization", "P4", "期望值", "失败", "PDF", "本机源码", "TimeoutError", "本机 Python", "traceback", "凭据"):
        assert expected in reasons
    assert "secret" not in sanitized
    assert "token" not in sanitized
    assert "Authorization" not in sanitized
    assert "Bearer" not in sanitized
    assert "C:\\Users" not in sanitized
    assert "D:\\软件开发" not in sanitized
    assert "src\\vstacklens" not in sanitized
    assert "traceback" not in sanitized


def test_artifact_safety_scan_allows_clean_customer_report(tmp_path: Path) -> None:
    report = tmp_path / "index.html"
    report.write_text("P1 风险\nP2 风险\nP3 风险\n建议状态\n未通过\n本次未再检出", encoding="utf-8")

    assert scan_artifacts([report]) == []


def test_engineering_artifact_scan_skips_customer_terms_but_keeps_sensitive_checks(tmp_path: Path) -> None:
    diagnostics = tmp_path / "engineering_diagnostics.md"
    diagnostics.write_text("P4 失败 期望值 password=secret", encoding="utf-8")

    findings = scan_artifacts([diagnostics], engineering_paths={diagnostics})
    reasons = [item.reason for item in findings]

    assert "包含凭据或会话字段" in reasons
    assert not any(reason.startswith("客户产物") for reason in reasons)


def test_service_validates_rulepack_for_desktop_rulepack_page() -> None:
    service = InspectionService()
    result = service.validate_rulepack(RULEPACK)

    assert result.valid
    assert result.rule_count == 67
    assert "评估基线校验通过" in result.message
    assert "67" not in result.message


def test_service_runs_vcenter_pipeline_and_reads_report_history(monkeypatch, tmp_path: Path) -> None:
    class FakeCollector:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def precheck(self) -> None:
            return None

        def collect(self, context, plan, progress=None):
            if progress:
                progress("collecting_clusters", 25)
                progress("collecting_hosts", 30)
                progress("collecting_storage_network", 38)
                progress("collecting_vms", 45)
                progress("collecting_alarms_permissions", 52)
                progress("collecting_permissions", 53)
                progress("building_vcenter_summary", 54)
                progress("building_cluster_objects", 55)
                progress("building_host_objects", 56)
                progress("building_storage_objects", 57)
                progress("building_vm_objects", 58)
            return MockCollector(FAIL_FIXTURE).collect(context, plan)

    monkeypatch.setattr("vstacklens.application.inspection_runner.PyVmomiCollector", FakeCollector)
    service = InspectionService(config_path=tmp_path / "desktop_config.json")
    config = DesktopInspectionConfig(
        vcenter="vc.local",
        username="administrator@vsphere.local",
        password="secret",
        customer_name="客户 A",
        site_name="生产站点",
        report_output_dir=tmp_path / "reports",
        db_path=tmp_path / "desktop.db",
        rulepack_path=RULEPACK,
    )

    progress_stages: list[str] = []
    progress_messages: list[str] = []
    result = service.run_vcenter_inspection(
        config,
        progress_callback=lambda progress: (
            progress_stages.append(progress.stage),
            progress_messages.append(progress.message),
        ),
    )
    history = service.list_report_history(config.db_path)
    progress = service.get_progress(config.db_path, result.run_id)

    assert result.report_path.exists()
    assert (result.report_dir / "data" / "customer_report_payload.json").exists()
    diagnostics_path = result.report_dir / "engineering_diagnostics.md"
    diagnostics_text = diagnostics_path.read_text(encoding="utf-8")
    assert diagnostics_path.exists()
    assert "运行基本信息" in diagnostics_text
    assert "客户报告安全检查摘要" in diagnostics_text
    assert "secret" not in diagnostics_text
    assert "site-packages" not in diagnostics_text
    assert "Traceback" not in diagnostics_text
    assert progress.state == InspectionState.COMPLETED
    assert history
    assert history[0].run_id == result.run_id
    assert history[0].customer_name == "客户 A"
    assert history[0].site_name == "生产站点"
    assert history[0].vcenter == "vc.local"
    assert history[0].report_path == result.report_path
    assert {
        "normalizing",
        "collecting_permissions",
        "building_vm_objects",
        "snapshotting",
        "executing_rules",
        "building_findings",
        "scoring",
        "reporting",
        "success",
    } <= set(progress_stages)
    assert {
        "连接 vCenter",
        "正在采集 ESXi 主机与授权状态",
        "正在核对角色与权限信息",
        "正在整理虚拟机对象",
        "正在执行健康规则",
        "正在生成 HTML 报告",
    } <= set(progress_messages)


def test_certificate_verify_failure_retries_no_verify_once_and_records_warning(monkeypatch, tmp_path: Path) -> None:
    ssl_modes: list[bool] = []

    class CertificateFallbackCollector:
        def __init__(self, host, username, password, port=443, ssl_verify=False, timeout=8.0):  # noqa: ANN001
            self.ssl_verify = ssl_verify

        def precheck(self) -> None:
            ssl_modes.append(self.ssl_verify)
            if self.ssl_verify:
                raise ssl.SSLCertVerificationError("certificate verify failed C:\\Users\\admin\\site-packages token=abc")

        def collect(self, context, plan, progress=None):
            assert self.ssl_verify is False
            return MockCollector(FIXTURE).collect(context, plan)

    monkeypatch.setattr("vstacklens.application.inspection_runner.PyVmomiCollector", CertificateFallbackCollector)
    service = InspectionService(config_path=tmp_path / "desktop_config.json")
    config = DesktopInspectionConfig(
        vcenter="vc.local",
        username="administrator@vsphere.local",
        password="secret",
        customer_name="客户 A",
        site_name="生产站点",
        report_output_dir=tmp_path / "reports",
        db_path=tmp_path / "desktop.db",
        rulepack_path=RULEPACK,
    )

    result = service.run_vcenter_inspection(config)
    payload_text = (result.report_dir / "data" / "customer_report_payload.json").read_text(encoding="utf-8")
    payload = json.loads(payload_text)
    diagnostics_text = (result.report_dir / "engineering_diagnostics.md").read_text(encoding="utf-8")

    assert ssl_modes == [True, False]
    assert result.report_path.exists()
    assert "vCenter 证书未通过可信链校验" not in payload_text
    assert payload["report_context"]["environment_info"]["security_warnings"] == []
    assert "不校验证书模式下继续" in diagnostics_text
    for forbidden in ("secret", "token=abc", "C:\\Users", "site-packages", "Traceback"):
        assert forbidden not in diagnostics_text


def test_certificate_verify_success_does_not_retry_or_warn(monkeypatch, tmp_path: Path) -> None:
    ssl_modes: list[bool] = []

    class VerifiedCollector:
        def __init__(self, host, username, password, port=443, ssl_verify=False, timeout=8.0):  # noqa: ANN001
            self.ssl_verify = ssl_verify

        def precheck(self) -> None:
            ssl_modes.append(self.ssl_verify)

        def collect(self, context, plan, progress=None):
            return MockCollector(FIXTURE).collect(context, plan)

    monkeypatch.setattr("vstacklens.application.inspection_runner.PyVmomiCollector", VerifiedCollector)
    service = InspectionService(config_path=tmp_path / "desktop_config.json")
    config = DesktopInspectionConfig(
        vcenter="vc.local",
        username="administrator@vsphere.local",
        password="secret",
        customer_name="客户 A",
        site_name="生产站点",
        report_output_dir=tmp_path / "reports",
        db_path=tmp_path / "desktop.db",
        rulepack_path=RULEPACK,
    )

    result = service.run_vcenter_inspection(config)
    payload = json.loads((result.report_dir / "data" / "customer_report_payload.json").read_text(encoding="utf-8"))

    assert ssl_modes == [True]
    assert payload["report_context"]["environment_info"]["security_warnings"] == []


def test_auth_failure_does_not_trigger_certificate_no_verify_retry(monkeypatch, tmp_path: Path) -> None:
    ssl_modes: list[bool] = []

    class AuthFailingCollector:
        def __init__(self, host, username, password, port=443, ssl_verify=False, timeout=8.0):  # noqa: ANN001
            self.ssl_verify = ssl_verify

        def precheck(self) -> None:
            ssl_modes.append(self.ssl_verify)
            raise RuntimeError("Login failed: invalid password")

    monkeypatch.setattr("vstacklens.application.inspection_runner.PyVmomiCollector", AuthFailingCollector)
    monkeypatch.setattr(
        "vstacklens.application.inspection_runner.socket_probe",
        lambda host, port: ProbeResult("success", f"{host}:{port} 可连接。"),
    )
    service = InspectionService(config_path=tmp_path / "desktop_config.json")
    config = DesktopInspectionConfig(
        vcenter="vc.local",
        username="administrator@vsphere.local",
        password="wrong",
        customer_name="客户 A",
        site_name="生产站点",
        report_output_dir=tmp_path / "reports",
        db_path=tmp_path / "desktop.db",
        rulepack_path=RULEPACK,
    )

    result = service.run_vcenter_inspection(config)
    payload_text = (result.report_dir / "data" / "customer_report_payload.json").read_text(encoding="utf-8")

    assert ssl_modes == [True]
    assert "用户名或密码错误" not in payload_text
    assert "collection_mode" not in payload_text
    assert "connection_diagnostics" not in payload_text
    assert "wrong" not in payload_text


def test_platform_dashboard_reads_score_risk_and_asset_stats(monkeypatch, tmp_path: Path) -> None:
    class FakeCollector:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def precheck(self) -> None:
            return None

        def collect(self, context, plan):
            return MockCollector(FAIL_FIXTURE).collect(context, plan)

    monkeypatch.setattr("vstacklens.application.inspection_runner.PyVmomiCollector", FakeCollector)
    service = InspectionService(config_path=tmp_path / "desktop_config.json")
    config = DesktopInspectionConfig(
        vcenter="vc.local",
        username="administrator@vsphere.local",
        password="secret",
        customer_name="客户 A",
        site_name="生产站点",
        report_output_dir=tmp_path / "reports",
        db_path=tmp_path / "desktop.db",
        rulepack_path=RULEPACK,
    )
    result = service.run_vcenter_inspection(config)
    assert result.docx_path is not None
    assert result.docx_path.exists()

    dashboard = service.get_dashboard_data(config.db_path)

    assert dashboard.has_data
    assert dashboard.run_id == result.run_id
    assert dashboard.score == result.score
    assert dashboard.risk_summary == result.risk_summary
    assert dashboard.asset_summary["vCenter"] >= 1
    assert dashboard.asset_summary["Cluster"] >= 1
    assert dashboard.asset_summary["ESXi Host"] >= 1
    assert dashboard.asset_summary["Datastore"] >= 1
    assert dashboard.asset_summary["VM"] >= 1
    assert dashboard.top_risks


def test_platform_risk_center_reads_findings(monkeypatch, tmp_path: Path) -> None:
    class FakeCollector:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def precheck(self) -> None:
            return None

        def collect(self, context, plan):
            return MockCollector(FAIL_FIXTURE).collect(context, plan)

    monkeypatch.setattr("vstacklens.application.inspection_runner.PyVmomiCollector", FakeCollector)
    service = InspectionService(config_path=tmp_path / "desktop_config.json")
    config = DesktopInspectionConfig(
        vcenter="vc.local",
        username="administrator@vsphere.local",
        password="secret",
        customer_name="客户 A",
        site_name="生产站点",
        report_output_dir=tmp_path / "reports",
        db_path=tmp_path / "desktop.db",
        rulepack_path=RULEPACK,
    )
    service.run_vcenter_inspection(config)

    findings = service.list_platform_findings(config.db_path)

    assert findings
    assert findings[0].risk_level in {"P1", "P2", "P3", "P4"}
    assert findings[0].title
    assert findings[0].object_name
    assert findings[0].rule_id
    assert findings[0].rule_name
    assert findings[0].collected_at
    assert findings[0].has_structured_evidence is True
    assert findings[0].raw_evidence
    assert any(item.source_path or item.threshold or item.explanation for item in findings)


def test_platform_risk_center_handles_legacy_findings_without_structured_evidence(monkeypatch, tmp_path: Path) -> None:
    class FakeCollector:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def precheck(self) -> None:
            return None

        def collect(self, context, plan):
            return MockCollector(FAIL_FIXTURE).collect(context, plan)

    monkeypatch.setattr("vstacklens.application.inspection_runner.PyVmomiCollector", FakeCollector)
    service = InspectionService(config_path=tmp_path / "desktop_config.json")
    config = DesktopInspectionConfig(
        vcenter="vc.local",
        username="administrator@vsphere.local",
        password="secret",
        customer_name="瀹㈡埛 A",
        site_name="鐢熶骇绔欑偣",
        report_output_dir=tmp_path / "reports",
        db_path=tmp_path / "desktop.db",
        rulepack_path=RULEPACK,
    )
    service.run_vcenter_inspection(config)

    with connect(config.db_path) as conn:
        row = conn.execute(
            """
            SELECT rr.result_id
            FROM findings f
            JOIN rule_results rr ON rr.result_id = f.latest_result_id
            WHERE f.last_seen_run_id = (SELECT run_id FROM inspection_runs ORDER BY created_at DESC LIMIT 1)
            ORDER BY
              CASE f.risk_level WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 WHEN 'P3' THEN 3 WHEN 'P4' THEN 4 ELSE 5 END,
              f.updated_at DESC
            LIMIT 1
            """
        ).fetchone()
        conn.execute(
            """
            UPDATE rule_results
            SET evidence_json = '{}', raw_json = '{}', observed_value = NULL, expected_value = NULL
            WHERE result_id = ?
            """,
            (row["result_id"],),
        )

    legacy_item = service.list_platform_findings(config.db_path)[0]

    assert legacy_item.has_structured_evidence is False
    assert legacy_item.raw_evidence == {}
    assert legacy_item.source_path
    assert legacy_item.explanation == ""


def test_certificate_license_check_evidence_reads_passed_failed_and_unavailable(monkeypatch, tmp_path: Path) -> None:
    class FakeCollector:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def precheck(self) -> None:
            return None

        def collect(self, context, plan):
            return MockCollector(FAIL_FIXTURE).collect(context, plan)

    monkeypatch.setattr("vstacklens.application.inspection_runner.PyVmomiCollector", FakeCollector)
    service = InspectionService(config_path=tmp_path / "desktop_config.json")
    config = DesktopInspectionConfig(
        vcenter="vc.local",
        username="administrator@vsphere.local",
        password="secret",
        customer_name="客户 A",
        site_name="生产站点",
        report_output_dir=tmp_path / "reports",
        db_path=tmp_path / "desktop.db",
        rulepack_path=RULEPACK,
    )
    service.run_vcenter_inspection(config)

    items = service.list_certificate_license_evidence(config.db_path)

    assert items
    assert {item.rule_id for item in items} & {"VSL-VC-005", "VSL-VC-006", "VSL-HOST-008", "VSL-HOST-023"}
    assert {item.result_status for item in items} & {"passed", "failed", "unavailable"}
    assert any(item.has_structured_evidence for item in items)
    assert all(item.rule_name and item.object_name for item in items)
    assert any(item.source_path or item.threshold or item.evidence_summary for item in items)

    with connect(config.db_path) as conn:
        row = conn.execute(
            """
            SELECT result_id
            FROM rule_results
            WHERE run_id = (SELECT run_id FROM inspection_runs ORDER BY created_at DESC LIMIT 1)
              AND rule_id IN ('VSL-VC-005', 'VSL-VC-006', 'VSL-HOST-008', 'VSL-HOST-023')
            LIMIT 1
            """
        ).fetchone()
        conn.execute(
            """
            UPDATE rule_results
            SET evidence_json = '{}', raw_json = '{}', observed_value = NULL, expected_value = NULL
            WHERE result_id = ?
            """,
            (row["result_id"],),
        )

    legacy_item = next(item for item in service.list_certificate_license_evidence(config.db_path) if item.result_id == row["result_id"])

    assert legacy_item.has_structured_evidence is False
    assert legacy_item.raw_evidence == {}
    assert legacy_item.evidence_summary == "未记录"


def test_platform_asset_center_reads_inventory_objects(monkeypatch, tmp_path: Path) -> None:
    class FakeCollector:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def precheck(self) -> None:
            return None

        def collect(self, context, plan):
            return MockCollector(FIXTURE).collect(context, plan)

    monkeypatch.setattr("vstacklens.application.inspection_runner.PyVmomiCollector", FakeCollector)
    service = InspectionService(config_path=tmp_path / "desktop_config.json")
    config = DesktopInspectionConfig(
        vcenter="vc.local",
        username="administrator@vsphere.local",
        password="secret",
        customer_name="客户 A",
        site_name="生产站点",
        report_output_dir=tmp_path / "reports",
        db_path=tmp_path / "desktop.db",
        rulepack_path=RULEPACK,
    )
    service.run_vcenter_inspection(config)

    assets = service.list_platform_assets(config.db_path)
    labels = {item.object_type_label for item in assets}

    assert assets
    assert {"vCenter", "Cluster", "ESXi", "Datastore", "VM"} <= labels
    assert all(item.object_name for item in assets)
    assert all(item.location for item in assets)


def test_service_connection_failure_still_generates_customer_report(monkeypatch, tmp_path: Path) -> None:
    ssl_modes: list[bool] = []

    class FailingCollector:
        def __init__(self, host, username, password, port=443, ssl_verify=False, timeout=8.0):  # noqa: ANN001
            self.ssl_verify = ssl_verify

        def precheck(self) -> None:
            ssl_modes.append(self.ssl_verify)
            raise TimeoutError("[WinError 10060] 连接尝试失败")

    monkeypatch.setattr("vstacklens.application.inspection_runner.PyVmomiCollector", FailingCollector)
    monkeypatch.setattr(
        "vstacklens.application.inspection_runner.socket_probe",
        lambda host, port: ProbeResult("failed", "连接 vCenter 超时。请确认当前电脑可以访问 vCenter API。"),
    )
    service = InspectionService(config_path=tmp_path / "desktop_config.json")
    config = DesktopInspectionConfig(
        vcenter="vc.local",
        username="administrator@vsphere.local",
        password="wrong",
        customer_name="客户 A",
        site_name="生产站点",
        report_output_dir=tmp_path / "reports",
        db_path=tmp_path / "desktop.db",
        rulepack_path=RULEPACK,
    )

    result = service.run_vcenter_inspection(config)
    history = service.list_report_history(config.db_path)
    payload_text = (result.report_dir / "data" / "customer_report_payload.json").read_text(encoding="utf-8")
    payload = json.loads(payload_text)
    env_info = payload["report_context"]["environment_info"]

    assert result.report_path.exists()
    assert history[0].run_status == "success"
    assert history[0].report_path == result.report_path
    assert env_info == {"security_warnings": []}
    assert "连接 vCenter 超时" not in payload_text
    assert "collection_mode" not in payload_text
    assert "wrong" not in payload_text
    assert ssl_modes == [True]


def test_service_sdk_failure_does_not_attempt_rest_and_runs_connection_rule_only(monkeypatch, tmp_path: Path) -> None:
    ssl_modes: list[bool] = []

    class FailingCollector:
        def __init__(self, host, username, password, port=443, ssl_verify=False, timeout=8.0):  # noqa: ANN001
            self.ssl_verify = ssl_verify

        def precheck(self) -> None:
            ssl_modes.append(self.ssl_verify)
            raise RuntimeError("SDK connection failed")

        def collect(self, context, plan):
            raise AssertionError("SDK collect should not run after failed precheck")

    monkeypatch.setattr("vstacklens.application.inspection_runner.PyVmomiCollector", FailingCollector)
    monkeypatch.setattr(
        "vstacklens.application.inspection_runner.socket_probe",
        lambda host, port: ProbeResult("success", f"{host}:{port} 可连接。"),
    )
    service = InspectionService(config_path=tmp_path / "desktop_config.json")
    config = DesktopInspectionConfig(
        vcenter="vc.local",
        username="administrator@vsphere.local",
        password="secret",
        customer_name="客户 A",
        site_name="生产站点",
        report_output_dir=tmp_path / "reports",
        db_path=tmp_path / "desktop.db",
        rulepack_path=RULEPACK,
    )

    result = service.run_vcenter_inspection(config)
    payload_text = (result.report_dir / "data" / "customer_report_payload.json").read_text(encoding="utf-8")
    payload = json.loads(payload_text)
    env_info = payload["report_context"]["environment_info"]
    with connect(config.db_path) as conn:
        rule_results = [
            row["rule_id"]
            for row in conn.execute(
                "SELECT rule_id FROM rule_results WHERE run_id = ? ORDER BY rule_id",
                (result.run_id,),
            ).fetchall()
        ]

    assert env_info == {"security_warnings": []}
    assert rule_results == ["VSL-VC-001"]
    assert "connection_diagnostics" not in payload_text
    assert "collection_mode" not in payload_text
    assert "secret" not in payload_text
    assert ssl_modes == [True]


def test_winerror_10060_is_customer_readable_chinese() -> None:
    message = friendly_connection_error(OSError("[WinError 10060] 连接尝试失败"))

    assert "连接 vCenter 超时" in message
    assert "API" in message


def test_history_comparison_states_and_changes_use_existing_runs(monkeypatch, tmp_path: Path) -> None:
    fixture_payloads = [
        json.loads(FAIL_FIXTURE.read_text(encoding="utf-8")),
        _history_comparison_second_fixture(),
    ]

    class SwitchingCollector:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def precheck(self) -> None:
            return None

        def collect(self, context, plan):
            return fixture_payloads.pop(0)

    monkeypatch.setattr("vstacklens.application.inspection_runner.PyVmomiCollector", SwitchingCollector)
    service = InspectionService(config_path=tmp_path / "desktop_config.json")
    db_path = tmp_path / "desktop.db"

    assert service.get_history_comparison(db_path).state == "empty"

    base = DesktopInspectionConfig(
        vcenter="vc.local",
        username="administrator@vsphere.local",
        password="secret",
        customer_name="客户 A",
        site_name="生产站点",
        report_output_dir=tmp_path / "reports",
        db_path=db_path,
        rulepack_path=RULEPACK,
    )
    first = service.run_vcenter_inspection(base)
    single = service.get_history_comparison(db_path)
    assert single.state == "single_run"
    assert single.comparison_run_id == first.run_id
    assert "当前只有 1 次评估" in single.summary_text

    second = service.run_vcenter_inspection(
        DesktopInspectionConfig(
            vcenter="vc.local",
            username="administrator@vsphere.local",
            password="secret",
            customer_name="客户 A",
            site_name="生产站点",
            report_output_dir=tmp_path / "reports",
            db_path=db_path,
            rulepack_path=RULEPACK,
            compare_latest=True,
        )
    )
    with connect(db_path) as conn:
        conn.execute("UPDATE rule_results SET vcenter_id = ? WHERE run_id = ?", ("vc-recreated-local-row", second.run_id))
        remediation = RunComparisonBuilder().build(conn, first.run_id, second.run_id)

    comparison = service.get_history_comparison(db_path)
    assert comparison.state == "ready"
    assert comparison.baseline_run_id == first.run_id
    assert comparison.comparison_run_id == second.run_id
    assert comparison.score.baseline is not None
    assert comparison.score.comparison is not None
    assert comparison.score.delta == round(float(comparison.score.comparison) - float(comparison.score.baseline), 2)
    assert set(comparison.risk_counts) == {"P1", "P2", "P3"}
    assert any(comparison.risk_changes[key] for key in ("new", "closed", "persistent"))
    assert comparison.risk_changes["new"]
    assert comparison.risk_changes["persistent"]
    assert comparison.asset_changes["persistent"]
    assert comparison.asset_changes["new"] or comparison.asset_changes["removed"]
    assert comparison.summary_text
    current_risk_total = (
        remediation["summary"]["new"]
        + remediation["summary"]["existing"]
        + remediation["summary"]["reopened"]
        + remediation["summary"]["exception"]
    )
    assert remediation["summary"]["existing"] > 0
    assert remediation["summary"]["new"] < current_risk_total

    payload_path = second.report_dir / "data" / "customer_report_payload.json"
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    history = payload["report_context"]["history_comparison"]
    assert history["state"] == "ready"
    assert history["summary_text"]
    assert payload["report_context"]["appendix"]["history_comparison"] == history


def test_history_comparison_isolates_vcenter_environments(monkeypatch, tmp_path: Path) -> None:
    """两个不同 vCenter 各巡检一次时，系统必须明确不可比较，且不产生任何差异结论。"""
    fixture_payloads = [
        json.loads(FAIL_FIXTURE.read_text(encoding="utf-8")),
        _history_comparison_second_fixture(),
        json.loads(FAIL_FIXTURE.read_text(encoding="utf-8")),
    ]

    class SwitchingCollector:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def precheck(self) -> None:
            return None

        def collect(self, context, plan):
            return fixture_payloads.pop(0)

    monkeypatch.setattr("vstacklens.application.inspection_runner.PyVmomiCollector", SwitchingCollector)
    service = InspectionService(config_path=tmp_path / "desktop_config.json")
    db_path = tmp_path / "desktop.db"

    def config(vcenter: str, compare_latest: bool = False) -> DesktopInspectionConfig:
        return DesktopInspectionConfig(
            vcenter=vcenter,
            username="administrator@vsphere.local",
            password="secret",
            customer_name="客户 A",
            site_name="生产站点",
            report_output_dir=tmp_path / "reports",
            db_path=db_path,
            rulepack_path=RULEPACK,
            compare_latest=compare_latest,
        )

    first_a = service.run_vcenter_inspection(config("vc-a.example"))
    second_a = service.run_vcenter_inspection(config("vc-a.example", compare_latest=True))

    same_environment = service.get_history_comparison(db_path)
    assert same_environment.state == "ready"
    assert same_environment.baseline_run_id == first_a.run_id
    assert same_environment.comparison_run_id == second_a.run_id
    assert same_environment.score.delta is not None
    assert "vc-a.example" in same_environment.environment_label

    first_b = service.run_vcenter_inspection(config("vc-b.example", compare_latest=True))

    with connect(db_path) as conn:
        vcenter_ids = {
            row["run_id"]: row["vcenter_id"]
            for row in conn.execute("SELECT run_id, vcenter_id FROM inspection_runs").fetchall()
        }
    assert len({vcenter_ids[first_a.run_id], vcenter_ids[first_b.run_id]}) == 2

    b_only = service.get_history_comparison(db_path)
    assert b_only.state != "ready"
    assert b_only.state == "single_run"
    assert b_only.comparison_run_id == first_b.run_id
    assert [option.run_id for option in b_only.run_options] == [first_b.run_id]
    assert b_only.score.delta is None
    assert b_only.risk_changes["new"] == []
    assert b_only.asset_changes["new"] == [] and b_only.asset_changes["removed"] == []

    crossed = service.get_history_comparison(db_path, first_a.run_id, first_b.run_id)
    assert crossed.state == "environment_mismatch"
    assert crossed.state != "ready"
    assert crossed.summary_text == "所选巡检记录属于不同的 vCenter 环境，无法进行历史对比。"
    assert crossed.score.delta is None
    assert crossed.risk_changes["new"] == []
    assert crossed.risk_changes["closed"] == []
    assert crossed.asset_changes["new"] == []
    assert crossed.asset_changes["removed"] == []
    assert all(crossed.risk_counts[level].delta == 0 for level in ("P1", "P2", "P3"))

    report_payload = json.loads((first_b.report_dir / "data" / "customer_report_payload.json").read_text(encoding="utf-8"))
    assert "history_comparison" not in report_payload["report_context"]
    assert "remediation_tracking" not in report_payload["report_context"]
    assert "历史对比" not in json.dumps(report_payload, ensure_ascii=False)
    assert "整改跟踪" not in json.dumps(report_payload, ensure_ascii=False)


def test_explicit_previous_run_from_other_vcenter_is_ignored(monkeypatch, tmp_path: Path) -> None:
    """显式指定的上一轮巡检如果属于其它 vCenter，视为没有可比历史。"""
    fixture_payloads = [
        json.loads(FAIL_FIXTURE.read_text(encoding="utf-8")),
        json.loads(FAIL_FIXTURE.read_text(encoding="utf-8")),
    ]

    class SwitchingCollector:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def precheck(self) -> None:
            return None

        def collect(self, context, plan):
            return fixture_payloads.pop(0)

    monkeypatch.setattr("vstacklens.application.inspection_runner.PyVmomiCollector", SwitchingCollector)
    service = InspectionService(config_path=tmp_path / "desktop_config.json")
    db_path = tmp_path / "desktop.db"

    def config(vcenter: str) -> DesktopInspectionConfig:
        return DesktopInspectionConfig(
            vcenter=vcenter,
            username="administrator@vsphere.local",
            password="secret",
            customer_name="客户 A",
            site_name="生产站点",
            report_output_dir=tmp_path / "reports",
            db_path=db_path,
            rulepack_path=RULEPACK,
        )

    run_a = service.run_vcenter_inspection(config("vc-a.example"))
    run_b = service.run_vcenter_inspection(config("vc-b.example"))

    with connect(db_path) as conn:
        ignored = InspectionRunner().previous_run_for_args(conn, run_a.run_id, False, run_b.run_id)
        missing = InspectionRunner().previous_run_for_args(conn, "run-not-exists", False, run_b.run_id)

    assert ignored is None
    assert missing is None

    with connect(db_path) as conn:
        same_environment = InspectionRunner().previous_run_for_args(conn, "", True, run_a.run_id)

    assert same_environment is None


def test_report_center_reads_new_old_and_incomplete_report_packages(monkeypatch, tmp_path: Path) -> None:
    class FakeCollector:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def precheck(self) -> None:
            return None

        def collect(self, context, plan):
            return MockCollector(FAIL_FIXTURE).collect(context, plan)

    monkeypatch.setattr("vstacklens.application.inspection_runner.PyVmomiCollector", FakeCollector)
    service = InspectionService(config_path=tmp_path / "desktop_config.json")
    config = DesktopInspectionConfig(
        vcenter="vc.local",
        username="administrator@vsphere.local",
        password="secret",
        customer_name="客户 A",
        site_name="生产站点",
        report_output_dir=tmp_path / "reports",
        db_path=tmp_path / "desktop.db",
        rulepack_path=RULEPACK,
    )
    result = service.run_vcenter_inspection(config)

    old_dir = tmp_path / "reports" / "old-package"
    (old_dir / "data").mkdir(parents=True)
    (old_dir / "index.html").write_text("<html>old</html>", encoding="utf-8")
    (old_dir / "data" / "customer_report_payload.json").write_text(
        json.dumps(
            {
                "report_context": {
                    "report_info": {"report_title": "旧版报告", "generated_at": "2026-01-01T00:00:00+00:00"},
                    "customer_info": {"customer_name": "旧客户", "site_name": "旧站点"},
                    "health_score": {"score": 88},
                    "risk_summary": {"P1": 0, "P2": 1, "P3": 2, "P4": 3},
                },
                "assets": {"summary": {"HostSystem": 2, "VirtualMachine": 8, "Datastore": 3}},
                "findings": [{"risk_level": "P2", "title": "旧风险", "object_name": "old-host"}],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    clean_dir = tmp_path / "reports" / "clean-package"
    (clean_dir / "data").mkdir(parents=True)
    (clean_dir / "index.html").write_text("<html>clean</html>", encoding="utf-8")
    (clean_dir / "data" / "customer_report_payload.json").write_text(
        json.dumps(
            {
                "report_context": {
                    "report_info": {"report_title": "旧版报告", "generated_at": "2026-01-01T00:00:00+00:00"},
                    "customer_info": {"customer_name": "旧客户"},
                    "health_score": {"score": 88},
                    "risk_summary": {"P1": 0, "P2": 1, "P3": 2, "P4": 3},
                },
                "assets": {"summary": {"HostSystem": 2, "VirtualMachine": 8, "Datastore": 3}},
                "findings": [{"risk_level": "P2", "title": "旧风险", "object_name": "old-host"}],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    incomplete_dir = tmp_path / "reports" / "index-only"
    incomplete_dir.mkdir(parents=True)
    (incomplete_dir / "index.html").write_text("<html>index only</html>", encoding="utf-8")

    items = service.list_report_packages(config.db_path, report_root=tmp_path / "reports")
    dirs = {item.report_dir for item in items}

    assert result.report_dir in dirs
    current_items = [item for item in items if item.report_dir == result.report_dir]
    assert len(current_items) == 1
    assert current_items[0].report_type == "HTML · Word · PDF"
    assert current_items[0].report_path == result.report_path
    assert (result.report_dir / "VStackLens-PDF-Report.pdf").is_file()
    assert service._report_item_path_key(current_items[0]) == str(result.report_dir.resolve()).casefold()
    assert old_dir not in dirs
    assert clean_dir in dirs
    assert incomplete_dir in dirs
    old = next(item for item in items if item.report_dir == clean_dir)
    assert old.title == "旧版报告"
    assert old.customer_name == "旧客户"
    assert old.score == 88
    assert old.risk_summary == {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    assert old.asset_summary["Host"] == 2
    incomplete = next(item for item in items if item.report_dir == incomplete_dir)
    assert incomplete.status == "数据不完整"
    assert incomplete.payload_path is None


def test_report_center_ignores_unrelated_word_files_and_persists_list_removal(tmp_path: Path) -> None:
    service = InspectionService(config_path=tmp_path / "desktop_config.json")
    report_root = tmp_path / "reports"
    report_dir = report_root / "recognized-report"
    (report_dir / "data").mkdir(parents=True)
    (report_dir / "index.html").write_text("<html>report</html>", encoding="utf-8")
    (report_dir / "data" / "customer_report_payload.json").write_text(
        json.dumps(
            {
                "report_context": {
                    "report_info": {"report_title": "受控测试报告", "generated_at": "2026-09-05T00:00:00+00:00"},
                    "customer_info": {"customer_name": "测试客户"},
                    "health_score": {},
                    "risk_summary": {},
                },
                "assets": {"summary": {}},
                "findings": [],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    (report_root / "~$临时报告.docx").write_bytes(b"temporary")
    (report_root / "用户会议纪要.docx").write_bytes(b"ordinary-word")
    db_path = tmp_path / "desktop.db"

    items = service.list_report_packages(db_path, report_root=report_root)

    assert [item.report_dir for item in items] == [report_dir]
    assert service.remove_report_center_item(db_path, items[0]) is True
    assert (report_dir / "index.html").exists()
    assert service.list_report_packages(db_path, report_root=report_root) == []


def test_delete_inspection_run_removes_selected_record_and_keeps_other_runs(monkeypatch, tmp_path: Path) -> None:
    class FakeCollector:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def precheck(self) -> None:
            return None

        def collect(self, context, plan):
            return MockCollector(FAIL_FIXTURE).collect(context, plan)

    monkeypatch.setattr("vstacklens.application.inspection_runner.PyVmomiCollector", FakeCollector)
    service = InspectionService(config_path=tmp_path / "desktop_config.json")
    config = DesktopInspectionConfig(
        vcenter="vc.local",
        username="administrator@vsphere.local",
        password="secret",
        customer_name="客户 A",
        site_name="生产站点",
        report_output_dir=tmp_path / "reports",
        db_path=tmp_path / "desktop.db",
        rulepack_path=RULEPACK,
    )
    first = service.run_vcenter_inspection(config)
    second = service.run_vcenter_inspection(config)

    deletion = service.delete_inspection_run(config.db_path, first.run_id, delete_report_files=True, report_output_dir=config.report_output_dir)
    history_ids = {item.run_id for item in service.list_report_history(config.db_path)}
    report_dirs = {item.report_dir for item in service.list_report_packages(config.db_path, report_root=tmp_path / "reports")}

    assert deletion.deleted is True
    assert first.run_id not in history_ids
    assert second.run_id in history_ids
    assert not first.report_dir.exists()
    assert second.report_dir.exists()
    assert first.report_dir not in report_dirs
    assert second.report_dir in report_dirs
    with connect(config.db_path) as conn:
        assert conn.execute("SELECT COUNT(*) AS c FROM inspection_runs WHERE run_id = ?", (first.run_id,)).fetchone()["c"] == 0
        assert conn.execute("SELECT COUNT(*) AS c FROM inspection_runs WHERE run_id = ?", (second.run_id,)).fetchone()["c"] == 1
        assert conn.execute("SELECT COUNT(*) AS c FROM log_analysis_runs").fetchone()["c"] == 0


def test_delete_inspection_run_refuses_to_delete_non_report_root_directory(monkeypatch, tmp_path: Path) -> None:
    class FakeCollector:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def precheck(self) -> None:
            return None

        def collect(self, context, plan):
            return MockCollector(FAIL_FIXTURE).collect(context, plan)

    monkeypatch.setattr("vstacklens.application.inspection_runner.PyVmomiCollector", FakeCollector)
    service = InspectionService(config_path=tmp_path / "desktop_config.json")
    config = DesktopInspectionConfig(
        vcenter="vc.local",
        username="administrator@vsphere.local",
        password="secret",
        customer_name="客户 A",
        site_name="生产站点",
        report_output_dir=tmp_path / "reports",
        db_path=tmp_path / "desktop.db",
        rulepack_path=RULEPACK,
    )
    result = service.run_vcenter_inspection(config)
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    (outside_dir / "index.html").write_text("<html>outside</html>", encoding="utf-8")
    with connect(config.db_path) as conn:
        conn.execute("UPDATE reports SET file_path = ? WHERE run_id = ? AND report_type = 'html_package'", (str(outside_dir / "index.html"), result.run_id))

    deletion = service.delete_inspection_run(config.db_path, result.run_id, delete_report_files=True, report_output_dir=config.report_output_dir)

    assert deletion.deleted is True
    assert "未自动删除" in deletion.message
    assert outside_dir.exists()
    with connect(config.db_path) as conn:
        assert conn.execute("SELECT COUNT(*) AS c FROM inspection_runs WHERE run_id = ?", (result.run_id,)).fetchone()["c"] == 0


def test_report_directory_delete_safety_rejects_root_desktop_project_and_dist(tmp_path: Path) -> None:
    service = InspectionService(config_path=tmp_path / "desktop_config.json")
    allowed = tmp_path / "reports"
    project_root = ROOT
    candidates = [
        Path(Path.cwd().anchor),
        Path.home() / "Desktop",
        project_root,
        project_root / "dist",
        tmp_path,
    ]

    assert service._is_safe_report_delete_dir(allowed / "run-1", [allowed.resolve()], tmp_path / "desktop.db") is True
    for candidate in candidates:
        assert service._is_safe_report_delete_dir(candidate, [allowed.resolve()], tmp_path / "desktop.db") is False


def test_report_center_uses_db_metadata_when_payload_name_is_question_marks(monkeypatch, tmp_path: Path) -> None:
    class FakeCollector:
        def __init__(self, *args, **kwargs):
            pass

        def precheck(self) -> None:
            return None

        def collect(self, context, plan):
            return MockCollector(FAIL_FIXTURE).collect(context, plan)

    monkeypatch.setattr("vstacklens.application.inspection_runner.PyVmomiCollector", FakeCollector)
    service = InspectionService(config_path=tmp_path / "desktop_config.json")
    config = DesktopInspectionConfig(
        vcenter="vc.local",
        username="administrator@vsphere.local",
        password="secret",
        customer_name="客户 A",
        site_name="生产站点",
        report_output_dir=tmp_path / "reports",
        db_path=tmp_path / "desktop.db",
        rulepack_path=RULEPACK,
    )
    result = service.run_vcenter_inspection(config)
    payload_path = result.report_dir / "data" / "customer_report_payload.json"
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    payload["report_context"]["report_info"]["report_title"] = "VStackLens " + ("?" * 5)
    payload["report_context"]["customer_info"]["customer_name"] = "?" * 8
    payload["report_context"]["customer_info"]["site_name"] = "?" * 4
    payload_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    items = service.list_report_packages(config.db_path, report_root=tmp_path / "reports")

    assert result.report_dir not in {item.report_dir for item in items}
