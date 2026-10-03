from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any

from vstacklens.application.cloud_log_diagnosis import DEFAULT_CLOUD_API_URL, DEFAULT_CLOUD_MODEL, DEFAULT_CLOUD_PROVIDER
from vstacklens.application.inspection_runner import InspectionRunner, RunnerCancelledError, VCenterRunRequest
from vstacklens.application.logging_config import get_logger, sensitive_text_summary
from vstacklens.application.log_analysis_service import (
    DEFAULT_LOG_ANALYSIS_TITLE,
    DEFAULT_LOG_CHECK_TITLE,
    LogAnalysisConfig,
    LogAnalysisProgress,
    LogAnalysisResult,
    LogAnalysisService,
    MODEL_ASSISTED_DIAGNOSIS_TITLE,
    MODEL_ASSISTED_TRIAGE_TITLE,
    log_analysis_display_stats,
)
from vstacklens.application.upgrade_compat_service import (
    DEFAULT_UPGRADE_COMPAT_TITLE,
    UpgradeCompatConfig,
    UpgradeCompatProgress,
    UpgradeCompatResult,
    UpgradeCompatService,
)
from vstacklens.application.paths import (
    builtin_rulepack_path,
    default_config_path,
    default_database_path,
    default_log_dir,
    default_report_output_dir,
    upgrade_compat_database_path,
)
from vstacklens.db.connection import connect, init_db, is_database_locked_error
from vstacklens.db.repositories import actionable_risk_total
from vstacklens.reports.history_compare import HistoryComparisonBuilder


LOGGER = get_logger(__name__)


DEFAULT_CUSTOMER_NAME = "未指定客户"
DEFAULT_SITE_NAME = "未指定站点"
DEFAULT_REPORT_TITLE = "VStackLens VMware 虚拟化健康评估报告"
DEFAULT_MODEL_PROFILE_NAME = "默认模型配置"


class InspectionState(StrEnum):
    IDLE = "idle"
    VALIDATING = "validating"
    RUNNING = "running"
    CANCELLING = "cancelling"
    CANCELLED = "cancelled"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(slots=True)
class ModelConfigProfile:
    profile_id: str = "default"
    profile_name: str = DEFAULT_MODEL_PROFILE_NAME
    provider: str = DEFAULT_CLOUD_PROVIDER
    api_url: str = DEFAULT_CLOUD_API_URL
    api_key: str = ""
    timeout_seconds: int = 60
    default_model: str = DEFAULT_CLOUD_MODEL
    available_models: list[str] = field(default_factory=list)
    connection_status: str = "untested"
    connection_checked_at: str = ""
    is_default: bool = False

    def normalized(self) -> "ModelConfigProfile":
        models = [str(item).strip() for item in self.available_models if str(item).strip()]
        default_model = (self.default_model or "").strip()
        if default_model and default_model not in models:
            models.insert(0, default_model)
        return ModelConfigProfile(
            profile_id=(self.profile_id or "default").strip() or "default",
            profile_name=(self.profile_name or DEFAULT_MODEL_PROFILE_NAME).strip() or DEFAULT_MODEL_PROFILE_NAME,
            provider=(self.provider or DEFAULT_CLOUD_PROVIDER).strip() or DEFAULT_CLOUD_PROVIDER,
            api_url=(self.api_url or DEFAULT_CLOUD_API_URL).strip() or DEFAULT_CLOUD_API_URL,
            api_key=self.api_key,
            timeout_seconds=max(5, int(self.timeout_seconds or 60)),
            default_model=default_model or DEFAULT_CLOUD_MODEL,
            available_models=list(dict.fromkeys(models)),
            connection_status=(self.connection_status or "untested").strip() or "untested",
            connection_checked_at=(self.connection_checked_at or "").strip(),
            is_default=bool(self.is_default),
        )


@dataclass(slots=True)
class DesktopInspectionConfig:
    vcenter: str = ""
    username: str = ""
    password: str = ""
    port: int = 443
    ssl_no_verify: bool = False
    customer_name: str = ""
    site_name: str = ""
    report_output_dir: Path = field(default_factory=default_report_output_dir)
    db_path: Path = field(default_factory=default_database_path)
    rulepack_path: Path = field(default_factory=builtin_rulepack_path)
    report_title: str = DEFAULT_REPORT_TITLE
    zip_report: bool = False
    compare_latest: bool = False
    previous_run_id: str | None = None
    model_config_profiles: list[ModelConfigProfile] = field(default_factory=list)
    security_privacy_level: str = "standard"

    def normalized(self) -> "DesktopInspectionConfig":
        profiles = [item.normalized() for item in self.model_config_profiles if isinstance(item, ModelConfigProfile)]
        if profiles and not any(profile.is_default for profile in profiles):
            profiles[0].is_default = True
        return DesktopInspectionConfig(
            vcenter=self.vcenter.strip(),
            username=self.username.strip(),
            password=self.password,
            port=443,
            ssl_no_verify=bool(self.ssl_no_verify),
            customer_name=self.customer_name.strip() or DEFAULT_CUSTOMER_NAME,
            site_name=self.site_name.strip() or DEFAULT_SITE_NAME,
            report_output_dir=Path(self.report_output_dir),
            db_path=Path(self.db_path),
            rulepack_path=Path(self.rulepack_path),
            report_title=self.report_title.strip() or DEFAULT_REPORT_TITLE,
            zip_report=bool(self.zip_report),
            compare_latest=bool(self.compare_latest),
            previous_run_id=self.previous_run_id,
            model_config_profiles=profiles,
            security_privacy_level=(self.security_privacy_level or "standard").strip() or "standard",
        )


@dataclass(slots=True)
class InspectionProgress:
    state: InspectionState = InspectionState.IDLE
    run_id: str | None = None
    stage: str = "idle"
    percent: int = 0
    message: str = "等待巡检"
    error: str | None = None


@dataclass(slots=True)
class InspectionRunResult:
    run_id: str
    report_path: Path
    report_dir: Path
    zip_path: Path | None
    score: float | None
    docx_path: Path | None = None
    docx_error: str | None = None
    risk_summary: dict[str, int] = field(default_factory=dict)
    pdf_path: Path | None = None
    pdf_error: str | None = None
    html_error: str | None = None


class InspectionCancelledError(RuntimeError):
    pass


@dataclass(slots=True)
class ReportHistoryItem:
    run_id: str
    run_status: str
    current_stage: str
    progress_percent: int
    score: float | None
    risk_summary: dict[str, Any]
    customer_name: str
    site_name: str
    vcenter: str
    report_path: Path | None
    generated_at: str | None
    started_at: str | None
    finished_at: str | None
    updated_at: str | None
    error_message: str | None


@dataclass(slots=True)
class RulepackValidationResult:
    rulepack_path: Path
    rule_count: int
    valid: bool
    message: str


@dataclass(slots=True)
class PlatformFindingItem:
    finding_id: str
    rule_id: str
    rule_name: str
    risk_level: str
    title: str
    object_type: str
    object_name: str
    impact: str
    current_observed: str
    expected_state: str
    remediation: str
    evidence_summary: str
    affected_components: list[str]
    fault_detail: str
    threshold: str
    source_path: str
    collected_at: str
    explanation: str
    raw_evidence: dict[str, Any]
    has_structured_evidence: bool
    status: str
    last_seen_at: str


@dataclass(slots=True)
class CheckEvidenceItem:
    result_id: str
    rule_id: str
    rule_name: str
    result_status: str
    risk_level: str
    object_type: str
    object_name: str
    current_observed: str
    expected_state: str
    evidence_summary: str
    threshold: str
    source_path: str
    collected_at: str
    explanation: str
    raw_evidence: dict[str, Any]
    has_structured_evidence: bool


@dataclass(slots=True)
class PlatformAssetItem:
    object_type: str
    object_type_label: str
    object_name: str
    location: str
    detail: str
    run_id: str


@dataclass(slots=True)
class DashboardData:
    has_data: bool
    run_id: str | None
    customer_name: str
    site_name: str
    vcenter: str
    score: float | None
    health_status: str
    risk_summary: dict[str, int]
    health_impact: dict[str, int]
    asset_summary: dict[str, int]
    risk_trend: list[dict[str, Any]]
    top_risks: list[PlatformFindingItem]
    recent_reports: list[ReportHistoryItem]


@dataclass(slots=True)
class CustomerCenterItem:
    customer_name: str
    vcenter_count: int
    host_count: int
    vm_count: int
    latest_score: float | None
    latest_status: str = "unknown"


@dataclass(slots=True)
class VCenterCenterItem:
    name: str
    host: str
    version: str
    build: str
    latest_status: str
    latest_score: float | None


@dataclass(slots=True)
class HistoryComparisonSummary:
    has_data: bool
    previous_run_id: str | None
    current_run_id: str | None
    new_risk_count: int = 0
    existing_risk_count: int = 0
    resolved_risk_count: int = 0


@dataclass(slots=True)
class HistoryRunOption:
    run_id: str
    label: str
    timestamp: str
    score: float | None
    risk_total: int


@dataclass(slots=True)
class HistoryDelta:
    baseline: float | int | None
    comparison: float | int | None
    delta: float | int | None
    direction: str
    label: str = ""


@dataclass(slots=True)
class HistoryRiskChangeItem:
    title: str
    risk_level: str
    object_type: str
    object_type_label: str
    object_name: str
    current_observed: str
    expected_state: str
    change_status: str
    change_status_label: str


@dataclass(slots=True)
class HistoryAssetChangeItem:
    object_type: str
    object_type_label: str
    object_name: str
    location: str
    change_status: str
    change_status_label: str


@dataclass(slots=True)
class HistoryComparison:
    state: str
    run_options: list[HistoryRunOption]
    baseline_run_id: str
    comparison_run_id: str
    baseline_label: str
    comparison_label: str
    baseline_time: str
    comparison_time: str
    score: HistoryDelta
    risk_counts: dict[str, HistoryDelta]
    asset_counts: dict[str, HistoryDelta]
    risk_changes: dict[str, list[HistoryRiskChangeItem]]
    asset_changes: dict[str, list[HistoryAssetChangeItem]]
    summary_text: str
    # 当前对比所限定的 vCenter 环境范围（用于界面提示，不可比状态下同样有值）。
    environment_label: str = ""


@dataclass(slots=True)
class ReportCenterItem:
    run_id: str | None
    report_path: Path | None
    report_dir: Path
    payload_path: Path | None
    title: str
    customer_name: str
    site_name: str
    assessment_time: str
    score: float | str | None
    risk_summary: dict[str, int]
    asset_summary: dict[str, int]
    top_risks: list[str]
    history_summary: str
    status: str
    report_type: str
    path_hint: str


@dataclass(slots=True)
class DeleteInspectionRunResult:
    deleted: bool
    run_id: str
    report_dir: Path | None = None
    message: str = ""


class InspectionService:
    CERTIFICATE_LICENSE_RULE_IDS = ("VSL-VC-005", "VSL-VC-006", "VSL-HOST-008", "VSL-HOST-023")

    """Application service facade for desktop UI and future local clients."""

    def __init__(
        self,
        config_path: Path | None = None,
        runner: InspectionRunner | None = None,
        log_analysis_service: LogAnalysisService | None = None,
        upgrade_compat_service: UpgradeCompatService | None = None,
    ) -> None:
        self.config_path = config_path or default_config_path()
        self.runner = runner or InspectionRunner()
        self.log_analysis_service = log_analysis_service or LogAnalysisService()
        self.upgrade_compat_service = upgrade_compat_service or UpgradeCompatService()
        self._progress = InspectionProgress()

    def initialize_local_workspace(self) -> DesktopInspectionConfig:
        """Create first-run local folders and a password-free default config."""

        from vstacklens.application.collection_settings import CollectionSettings
        CollectionSettings.load()
        config = self.load_config().normalized()
        # An installed upgrade can leave a development-time rulepack path in
        # the saved config. Repair that path automatically so the inspection
        # center does not appear unusable after an upgrade.
        if not config.rulepack_path.exists():
            config.rulepack_path = builtin_rulepack_path()
        for directory in (
            config.db_path.parent,
            config.report_output_dir,
            default_log_dir(),
            self.config_path.parent,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        init_db(config.db_path)
        self.upgrade_compat_service.ensure_isolated_database(
            self.isolated_upgrade_compat_database_path(config.db_path),
            seed_database_path=config.db_path,
        )
        if not self.config_path.exists():
            self.save_config(config)
        LOGGER.info(
            "Workspace initialized config_path=%s db_path=%s report_dir=%s log_dir=%s",
            self.config_path,
            config.db_path,
            config.report_output_dir,
            default_log_dir(),
        )
        return config

    def validate_config(self, config: DesktopInspectionConfig) -> list[str]:
        cfg = config.normalized()
        errors: list[str] = []
        if not cfg.vcenter:
            errors.append("请填写 vCenter 地址。")
        if not cfg.username:
            errors.append("请填写 vCenter 用户名。")
        if not cfg.password:
            errors.append("请填写 vCenter 密码。")
        if cfg.port <= 0 or cfg.port > 65535:
            errors.append("vCenter 端口必须在 1 到 65535 之间。")
        if not cfg.rulepack_path.exists():
            errors.append(f"评估基线目录不存在：{cfg.rulepack_path}")
        return errors

    def validate_log_analysis_config(self, config: LogAnalysisConfig) -> list[str]:
        return self.log_analysis_service.validate_config(config)

    def run_log_analysis(
        self,
        config: LogAnalysisConfig,
        progress_callback: Callable[[LogAnalysisProgress], None] | None = None,
    ) -> LogAnalysisResult:
        cfg = config.normalized()
        bundle_size = cfg.support_bundle_path.stat().st_size if cfg.support_bundle_path.exists() else 0
        LOGGER.info(
            "Desktop log analysis requested bundle_name=%s bundle_size=%s problem=%s output_dir=%s db_path=%s",
            cfg.support_bundle_path.name,
            bundle_size,
            sensitive_text_summary(cfg.problem_description),
            cfg.report_output_dir,
            cfg.db_path,
        )
        try:
            result = self.log_analysis_service.run(cfg, progress_callback=progress_callback)
        except Exception:
            LOGGER.exception("Desktop log analysis failed bundle_name=%s", cfg.support_bundle_path.name)
            raise
        LOGGER.info(
            "Desktop log analysis completed log_run_id=%s html=%s docx=%s",
            result.log_run_id,
            result.html_path,
            result.docx_path,
        )
        return result

    def isolated_upgrade_compat_database_path(self, primary_db_path: Path) -> Path:
        return upgrade_compat_database_path(primary_db_path)

    def upgrade_compat_data_status(self, db_path: Path, *, seed_database_path: Path | None = None) -> dict[str, Any]:
        self.upgrade_compat_service.ensure_isolated_database(db_path, seed_database_path=seed_database_path)
        return self.upgrade_compat_service.hcl_data_status(db_path)

    def supported_upgrade_releases(self, db_path: Path) -> list[str]:
        return self.upgrade_compat_service.supported_releases(db_path)

    def validate_upgrade_compat_config(self, config: UpgradeCompatConfig) -> list[str]:
        return self.upgrade_compat_service.validate_config(config)

    def import_upgrade_hcl_data(
        self,
        *,
        db_path: Path,
        source: str,
        file_path: Path | None = None,
        online: bool = False,
        vcg_client_id: str | None = None,
        vcg_client_secret: str | None = None,
        progress_callback: Callable[[UpgradeCompatProgress], None] | None = None,
        seed_database_path: Path | None = None,
    ) -> dict[str, str]:
        self.upgrade_compat_service.ensure_isolated_database(db_path, seed_database_path=seed_database_path)
        return self.upgrade_compat_service.import_hcl_data(
            db_path=db_path,
            source=source,
            file_path=file_path,
            online=online,
            vcg_client_id=vcg_client_id,
            vcg_client_secret=vcg_client_secret,
            progress_callback=progress_callback,
        )

    def run_upgrade_compat(
        self,
        config: UpgradeCompatConfig,
        progress_callback: Callable[[UpgradeCompatProgress], None] | None = None,
        cancel_requested: Callable[[], bool] | None = None,
    ) -> UpgradeCompatResult:
        self.upgrade_compat_service.ensure_isolated_database(config.db_path)
        return self.upgrade_compat_service.run(config, progress_callback=progress_callback, cancel_requested=cancel_requested)

    def save_config(self, config: DesktopInspectionConfig) -> None:
        cfg = config.normalized()
        payload = asdict(cfg)
        payload.pop("password", None)
        for key in ("report_output_dir", "db_path", "rulepack_path"):
            payload[key] = str(payload[key])
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def load_config(self) -> DesktopInspectionConfig:
        if not self.config_path.exists():
            return DesktopInspectionConfig()
        try:
            payload = json.loads(self.config_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            LOGGER.warning("Desktop config JSON is invalid; backing up corrupt config path=%s", self.config_path)
            config = DesktopInspectionConfig()
            self._backup_corrupt_config("invalid-json")
            self.save_config(config)
            return config
        except OSError:
            LOGGER.exception("Desktop config could not be read; using default config path=%s", self.config_path)
            return DesktopInspectionConfig()
        if not isinstance(payload, dict):
            LOGGER.warning("Desktop config root is not an object; backing up corrupt config path=%s", self.config_path)
            config = DesktopInspectionConfig()
            self._backup_corrupt_config("invalid-root")
            self.save_config(config)
            return config
        config = DesktopInspectionConfig(
            vcenter=self._string_config_value(payload, "vcenter"),
            username=self._string_config_value(payload, "username"),
            password="",
            port=self._int_config_value(payload, "port", 443),
            ssl_no_verify=False,
            customer_name=self._string_config_value(payload, "customer_name"),
            site_name=self._string_config_value(payload, "site_name"),
            report_output_dir=self._path_config_value(payload, "report_output_dir", default_report_output_dir()),
            db_path=self._path_config_value(payload, "db_path", default_database_path()),
            rulepack_path=self._path_config_value(payload, "rulepack_path", builtin_rulepack_path()),
            report_title=self._string_config_value(payload, "report_title", DEFAULT_REPORT_TITLE),
            zip_report=bool(payload.get("zip_report", False)),
            compare_latest=bool(payload.get("compare_latest", False)),
            previous_run_id=self._optional_string_config_value(payload, "previous_run_id"),
            model_config_profiles=self._model_profiles_config_value(payload.get("model_config_profiles")),
            security_privacy_level=self._string_config_value(payload, "security_privacy_level", "standard"),
        )
        repaired = self._repair_missing_rulepack_path(config)
        if repaired != config:
            self.save_config(repaired)
        return repaired

    def _model_profiles_config_value(self, value: Any) -> list[ModelConfigProfile]:
        if not isinstance(value, list):
            return []
        profiles: list[ModelConfigProfile] = []
        for item in value:
            if not isinstance(item, dict):
                continue
            profile = ModelConfigProfile(
                profile_id=self._string_config_value(item, "profile_id", "default"),
                profile_name=self._string_config_value(item, "profile_name", DEFAULT_MODEL_PROFILE_NAME),
                provider=self._string_config_value(item, "provider", DEFAULT_CLOUD_PROVIDER),
                api_url=self._string_config_value(item, "api_url", DEFAULT_CLOUD_API_URL),
                api_key=self._string_config_value(item, "api_key"),
                timeout_seconds=self._int_config_value(item, "timeout_seconds", 60),
                default_model=self._string_config_value(item, "default_model", DEFAULT_CLOUD_MODEL),
                available_models=[str(model).strip() for model in item.get("available_models", []) if str(model).strip()]
                if isinstance(item.get("available_models"), list)
                else [],
                connection_status=self._string_config_value(item, "connection_status", "untested"),
                connection_checked_at=self._string_config_value(item, "connection_checked_at"),
                is_default=bool(item.get("is_default", False)),
            ).normalized()
            profiles.append(profile)
        if profiles and not any(profile.is_default for profile in profiles):
            profiles[0].is_default = True
        return profiles

    def _backup_corrupt_config(self, reason: str) -> Path | None:
        if not self.config_path.exists():
            return None
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = self.config_path.with_name(f"{self.config_path.name}.corrupt-{timestamp}-{reason}")
        counter = 1
        while backup.exists():
            backup = self.config_path.with_name(f"{self.config_path.name}.corrupt-{timestamp}-{reason}-{counter}")
            counter += 1
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(self.config_path), str(backup))
            LOGGER.warning("Backed up corrupt desktop config path=%s backup=%s reason=%s", self.config_path, backup, reason)
            return backup
        except OSError:
            LOGGER.exception("Failed to back up corrupt desktop config path=%s reason=%s", self.config_path, reason)
            return None

    def _string_config_value(self, payload: dict[str, Any], key: str, default: str = "") -> str:
        value = payload.get(key, default)
        if value is None:
            return default
        if isinstance(value, str):
            return value
        LOGGER.warning("Desktop config field has invalid type; using default field=%s", key)
        return default

    def _optional_string_config_value(self, payload: dict[str, Any], key: str) -> str | None:
        value = payload.get(key)
        if value is None:
            return None
        if isinstance(value, str):
            return value
        LOGGER.warning("Desktop config field has invalid type; clearing field=%s", key)
        return None

    def _int_config_value(self, payload: dict[str, Any], key: str, default: int) -> int:
        try:
            return int(payload.get(key) or default)
        except (TypeError, ValueError):
            LOGGER.warning("Desktop config field has invalid type; using default field=%s", key)
            return default

    def _path_config_value(self, payload: dict[str, Any], key: str, default: Path) -> Path:
        value = payload.get(key)
        if isinstance(value, str) and value:
            return Path(value)
        if value in (None, ""):
            return Path(default)
        LOGGER.warning("Desktop config field has invalid type; using default field=%s", key)
        return Path(default)

    def _repair_missing_rulepack_path(self, config: DesktopInspectionConfig) -> DesktopInspectionConfig:
        cfg = config.normalized()
        if cfg.rulepack_path.exists():
            return cfg
        fallback = builtin_rulepack_path()
        if not fallback.exists() or fallback == cfg.rulepack_path:
            return cfg
        LOGGER.warning(
            "Configured rulepack path is missing; falling back to bundled rulepack missing_path=%s fallback=%s",
            cfg.rulepack_path,
            fallback,
        )
        return DesktopInspectionConfig(
            vcenter=cfg.vcenter,
            username=cfg.username,
            password=cfg.password,
            port=cfg.port,
            ssl_no_verify=cfg.ssl_no_verify,
            customer_name=cfg.customer_name,
            site_name=cfg.site_name,
            report_output_dir=cfg.report_output_dir,
            db_path=cfg.db_path,
            rulepack_path=fallback,
            report_title=cfg.report_title,
            zip_report=cfg.zip_report,
            compare_latest=cfg.compare_latest,
            previous_run_id=cfg.previous_run_id,
        )

    def get_progress(self, db_path: Path | None = None, run_id: str | None = None) -> InspectionProgress:
        if db_path and run_id and Path(db_path).exists():
            with connect(Path(db_path)) as conn:
                row = conn.execute(
                    "SELECT run_status, current_stage, progress_percent, error_message FROM inspection_runs WHERE run_id = ?",
                    (run_id,),
                ).fetchone()
            if row:
                self._progress = InspectionProgress(
                    state=self._state_from_run_status(row["run_status"]),
                    run_id=run_id,
                    stage=row["current_stage"] or "",
                    percent=int(row["progress_percent"] or 0),
                    message=self._stage_label(row["current_stage"] or row["run_status"]),
                    error=row["error_message"],
                )
        return self._progress

    def run_vcenter_inspection(
        self,
        config: DesktopInspectionConfig,
        progress_callback: Callable[[InspectionProgress], None] | None = None,
        cancel_requested: Callable[[], bool] | None = None,
    ) -> InspectionRunResult:
        cfg = config.normalized()
        LOGGER.info(
            "vCenter inspection requested vcenter=%s username=%s ssl_no_verify=%s db_path=%s report_dir=%s",
            cfg.vcenter,
            cfg.username,
            cfg.ssl_no_verify,
            cfg.db_path,
            cfg.report_output_dir,
        )
        errors = self.validate_config(cfg)
        if errors:
            LOGGER.warning("vCenter inspection validation failed vcenter=%s error_count=%s", cfg.vcenter, len(errors))
            self._progress = InspectionProgress(
                state=InspectionState.FAILED,
                stage="validating",
                percent=100,
                message="配置校验失败",
                error="；".join(errors),
            )
            self._emit_progress(progress_callback)
            raise ValueError(self._progress.error)

        self.save_config(cfg)
        self._progress = InspectionProgress(state=InspectionState.VALIDATING, stage="loading_rules", percent=5, message="加载健康基线")
        self._emit_progress(progress_callback)
        self._raise_if_cancelled(cancel_requested)
        request = VCenterRunRequest(
            db_path=cfg.db_path,
            rulepack_path=cfg.rulepack_path,
            report_dir=self._report_dir(cfg),
            report_title=cfg.report_title,
            customer_name=cfg.customer_name,
            site_name=cfg.site_name,
            zip_report=cfg.zip_report,
            previous_run_id=cfg.previous_run_id,
            compare_latest=cfg.compare_latest,
            docx_out=self._docx_report_path(cfg),
            pdf_out=self._pdf_report_path(cfg),
            vcenter=cfg.vcenter,
            username=cfg.username,
            password=cfg.password,
            port=cfg.port,
            ssl_no_verify=cfg.ssl_no_verify,
        )
        try:
            LOGGER.info("vCenter inspection connecting vcenter=%s ssl_no_verify=%s", cfg.vcenter, cfg.ssl_no_verify)
            result = self.runner.run_vcenter(
                request,
                progress=lambda stage, percent: self._set_progress(stage, percent, progress_callback, cancel_requested),
                cancel_requested=cancel_requested,
            )
            self._raise_if_cancelled(cancel_requested)
            completed = self._complete_result(
                cfg.db_path,
                result.run_id,
                result.report_dir,
                result.zip_path,
                progress_callback,
                docx_path=result.docx_path,
                docx_error=result.docx_error,
                pdf_path=result.pdf_path,
                pdf_error=result.pdf_error,
                html_error=result.html_error,
            )
            LOGGER.info(
                "vCenter inspection completed run_id=%s report=%s docx=%s pdf=%s",
                completed.run_id,
                completed.report_path,
                completed.docx_path,
                completed.pdf_path,
            )
            return completed
        except (InspectionCancelledError, RunnerCancelledError) as exc:
            LOGGER.info("vCenter inspection cancelled vcenter=%s run_id=%s stage=%s", cfg.vcenter, self._progress.run_id, self._progress.stage)
            self._progress = InspectionProgress(
                state=InspectionState.CANCELLED,
                run_id=self._progress.run_id,
                stage="cancelled",
                percent=100,
                message="巡检已取消",
                error=str(exc),
            )
            self._emit_progress(progress_callback)
            raise
        except Exception as exc:
            LOGGER.exception("vCenter inspection failed vcenter=%s stage=%s", cfg.vcenter, self._progress.stage)
            self._progress = InspectionProgress(
                state=InspectionState.FAILED,
                run_id=self._progress.run_id,
                stage=self._progress.stage,
                percent=100,
                message="巡检失败",
                error=str(exc),
            )
            self._emit_progress(progress_callback)
            raise

    def list_report_history(self, db_path: Path, limit: int = 50) -> list[ReportHistoryItem]:
        db = Path(db_path)
        if not db.exists():
            return []
        with connect(db) as conn:
            rows = conn.execute(
                """
                SELECT r.run_id, r.run_status, r.current_stage, r.progress_percent, r.score,
                       r.risk_summary_json, r.risk_category_summary_json, r.started_at, r.finished_at, r.updated_at, r.error_message,
                       c.customer_name, s.site_name, v.host AS vcenter_host,
                       rep.file_path AS report_path, rep.generated_at
                FROM inspection_runs r
                JOIN customers c ON c.customer_id = r.customer_id
                JOIN sites s ON s.site_id = r.site_id
                JOIN vcenters v ON v.vcenter_id = r.vcenter_id
                LEFT JOIN reports rep
                  ON rep.report_id = (
                    SELECT rep2.report_id
                    FROM reports rep2
                    WHERE rep2.run_id = r.run_id
                      AND rep2.report_type = 'html_package'
                      AND rep2.report_status = 'success'
                      AND rep2.file_path IS NOT NULL
                    ORDER BY COALESCE(rep2.generated_at, rep2.updated_at, rep2.created_at) DESC
                    LIMIT 1
                  )
                ORDER BY COALESCE(rep.generated_at, r.updated_at, r.created_at) DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        result: list[ReportHistoryItem] = []
        for row in rows:
            risk_summary = self._risk_summary_from_json(row["risk_category_summary_json"] or row["risk_summary_json"])
            report_path = Path(row["report_path"]) if row["report_path"] else None
            result.append(
                ReportHistoryItem(
                    run_id=row["run_id"],
                    run_status=row["run_status"],
                    current_stage=row["current_stage"] or "",
                    progress_percent=int(row["progress_percent"] or 0),
                    score=row["score"],
                    risk_summary=risk_summary,
                    customer_name=row["customer_name"],
                    site_name=row["site_name"],
                    vcenter=row["vcenter_host"],
                    report_path=report_path,
                    generated_at=row["generated_at"],
                    started_at=row["started_at"],
                    finished_at=row["finished_at"],
                    updated_at=row["updated_at"],
                    error_message=row["error_message"],
                )
            )
        return result

    def delete_inspection_run(
        self,
        db_path: Path,
        run_id: str,
        *,
        delete_report_files: bool = True,
        report_output_dir: Path | None = None,
    ) -> DeleteInspectionRunResult:
        db = Path(db_path)
        if not db.exists():
            return DeleteInspectionRunResult(False, run_id, message="本地数据库不存在，无法删除巡检记录。")
        report_dir: Path | None = None
        report_dir_safe = False
        try:
            with connect(db) as conn:
                row = conn.execute("SELECT run_id FROM inspection_runs WHERE run_id = ?", (run_id,)).fetchone()
                if not row:
                    return DeleteInspectionRunResult(False, run_id, message="未找到该健康巡检记录，可能已被删除。")
                report_rows = conn.execute(
                    "SELECT file_path FROM reports WHERE run_id = ? AND file_path IS NOT NULL",
                    (run_id,),
                ).fetchall()
                report_dir = self._report_dir_from_report_rows([Path(item["file_path"]) for item in report_rows])
                allowed_roots = self._safe_report_delete_roots(report_output_dir, db)
                report_dir_safe = bool(report_dir and self._is_safe_report_delete_dir(report_dir, allowed_roots, db))
                conn.execute("DELETE FROM reports WHERE run_id = ?", (run_id,))
                conn.execute(
                    """
                    DELETE FROM finding_exceptions
                    WHERE finding_id IN (
                      SELECT finding_id
                      FROM findings
                      WHERE latest_result_id IN (SELECT result_id FROM rule_results WHERE run_id = ?)
                    )
                    """,
                    (run_id,),
                )
                conn.execute(
                    """
                    DELETE FROM findings
                    WHERE latest_result_id IN (SELECT result_id FROM rule_results WHERE run_id = ?)
                    """,
                    (run_id,),
                )
                conn.execute("UPDATE findings SET first_seen_run_id = last_seen_run_id WHERE first_seen_run_id = ?", (run_id,))
                conn.execute("UPDATE findings SET resolved_run_id = NULL, resolved_at = NULL WHERE resolved_run_id = ?", (run_id,))
                conn.execute("DELETE FROM rule_results WHERE run_id = ?", (run_id,))
                conn.execute("DELETE FROM inventory_objects WHERE run_id = ?", (run_id,))
                conn.execute("DELETE FROM inventory_snapshots WHERE run_id = ?", (run_id,))
                conn.execute("DELETE FROM inspection_runs WHERE run_id = ?", (run_id,))
        except sqlite3.Error:
            LOGGER.exception("Failed to delete health inspection run run_id=%s db=%s", run_id, db)
            return DeleteInspectionRunResult(False, run_id, report_dir, "删除巡检记录失败，请确认本地数据库未被其他程序占用后重试。")
        if delete_report_files and report_dir and report_dir.exists():
            if not report_dir_safe:
                LOGGER.warning("Skipped unsafe report directory deletion run_id=%s report_dir=%s", run_id, report_dir)
                return DeleteInspectionRunResult(
                    True,
                    run_id,
                    report_dir,
                    "巡检记录已删除，但报告目录未自动删除，请手动确认后清理。",
                )
            try:
                self._remove_report_dir(report_dir)
            except OSError:
                LOGGER.exception("Failed to delete health inspection report directory run_id=%s report_dir=%s", run_id, report_dir)
                return DeleteInspectionRunResult(
                    True,
                    run_id,
                    report_dir,
                    "巡检记录已删除，但报告目录删除失败。请确认报告文件未被打开后手工清理。",
                )
        return DeleteInspectionRunResult(True, run_id, report_dir, "巡检记录已删除。")

    def _report_dir_from_report_rows(self, paths: list[Path]) -> Path | None:
        for path in paths:
            if path.name.lower() == "index.html":
                return path.parent
        for path in paths:
            if path.suffix.lower() == ".docx":
                return path.parent
        return None

    def _remove_report_dir(self, report_dir: Path) -> None:
        root = report_dir.resolve()
        if root == Path(root.anchor):
            raise OSError("Refuse to delete filesystem root")
        shutil.rmtree(root)

    def _safe_report_delete_roots(self, report_output_dir: Path | None, db_path: Path) -> list[Path]:
        candidates: list[Path] = []
        if report_output_dir:
            candidates.append(Path(report_output_dir))
        try:
            candidates.append(self.load_config().normalized().report_output_dir)
        except Exception:  # noqa: BLE001 - deletion safety should fall back to built-in defaults.
            pass
        candidates.append(default_report_output_dir())

        roots: list[Path] = []
        forbidden = self._forbidden_delete_dirs(db_path)
        for candidate in candidates:
            resolved = Path(candidate).expanduser().resolve()
            if resolved in roots:
                continue
            if any(resolved == item for item in forbidden):
                continue
            roots.append(resolved)
        return roots

    def _is_safe_report_delete_dir(self, report_dir: Path, allowed_roots: list[Path], db_path: Path) -> bool:
        target = Path(report_dir).expanduser().resolve()
        forbidden = self._forbidden_delete_dirs(db_path)
        if target == Path(target.anchor):
            return False
        if any(target == item for item in forbidden):
            return False
        return any(target != root and self._path_is_relative_to(target, root) for root in allowed_roots)

    def _forbidden_delete_dirs(self, db_path: Path) -> list[Path]:
        project_root = Path(__file__).resolve().parents[3]
        forbidden = [
            Path(Path.cwd().anchor).resolve(),
            Path.home().joinpath("Desktop").resolve(),
            project_root.resolve(),
            project_root.joinpath("dist").resolve(),
            default_config_path().parent.resolve(),
            Path(db_path).expanduser().resolve().parent,
        ]
        return forbidden

    def _path_is_relative_to(self, path: Path, parent: Path) -> bool:
        try:
            path.relative_to(parent)
            return True
        except ValueError:
            return False

    def _report_history_item_for_run(self, db_path: Path, run_id: str) -> ReportHistoryItem | None:
        if not run_id:
            return None
        for item in self.list_report_history(Path(db_path), limit=200):
            if item.run_id == run_id:
                return item
        return None

    def validate_rulepack(self, rulepack_path: Path) -> RulepackValidationResult:
        from vstacklens.rules.rulepack_loader import RulePackLoader
        from vstacklens.rules.schema_validator import SchemaValidator

        path = Path(rulepack_path)
        try:
            raw_rules = RulePackLoader().load_raw(path)
            validator = SchemaValidator()
            for raw_rule in raw_rules:
                validator.validate_rule(raw_rule)
        except Exception as exc:  # noqa: BLE001 - rulepack validation should report a concise UI message.
            return RulepackValidationResult(
                rulepack_path=path,
                rule_count=0,
                valid=False,
                message=f"评估基线校验失败：{exc}",
            )
        return RulepackValidationResult(
            rulepack_path=path,
            rule_count=len(raw_rules),
            valid=True,
            message="评估基线校验通过，当前基线可用于巡检。",
        )

    def get_dashboard_data(self, db_path: Path) -> DashboardData:
        db = Path(db_path)
        default = DashboardData(
            has_data=False,
            run_id=None,
            customer_name="未选择客户",
            site_name="未选择站点",
            vcenter="未连接",
            score=None,
            health_status="暂无数据",
            risk_summary={"P1": 0, "P2": 0, "P3": 0, "P4": 0},
            health_impact={"none": 0, "attention": 0, "critical": 0},
            asset_summary={"vCenter": 0, "Cluster": 0, "ESXi Host": 0, "Datastore": 0, "VM": 0},
            risk_trend=[],
            top_risks=[],
            recent_reports=[],
        )
        if not db.exists():
            return default
        try:
            with connect(db) as conn:
                run = self._latest_run_row(conn)
                if not run:
                    return default
                risk_summary = self._risk_summary_from_json(run["risk_category_summary_json"] or run["risk_summary_json"])
                assets = self._asset_summary_for_run(conn, run["run_id"])
                trend = self._risk_trend(conn)
                top_risks = self.list_platform_findings(db, run["run_id"])[:10]
                health_impact = self._health_impact_for_run(conn, run["run_id"])
            return DashboardData(
                has_data=True,
                run_id=run["run_id"],
                customer_name=run["customer_name"] or "",
                site_name=run["site_name"] or "",
                vcenter=run["vcenter_host"] or "",
                score=run["score"],
                health_status=self._health_status(run["score"], risk_summary, health_impact),
                risk_summary=risk_summary,
                health_impact=health_impact,
                asset_summary=assets,
                risk_trend=trend,
                top_risks=top_risks,
                recent_reports=self.list_report_history(db, limit=8),
            )
        except sqlite3.Error:
            return default

    def list_platform_findings(self, db_path: Path, run_id: str | None = None) -> list[PlatformFindingItem]:
        db = Path(db_path)
        if not db.exists():
            return []
        try:
            with connect(db) as conn:
                target_run_id = run_id or self._latest_run_id(conn)
                if not target_run_id:
                    return []
                rows = conn.execute(
                    """
                    SELECT f.*, rr.evidence_json, rr.observed_value, rr.expected_value, rr.raw_json, rr.evaluated_at, rr.object_path, r.rule_name, r.definition_json
                    FROM findings f
                    JOIN rule_results rr ON rr.result_id = f.latest_result_id
                    LEFT JOIN rules r ON r.rule_id = f.rule_id
                    WHERE f.last_seen_run_id = ? AND f.status != 'exception'
                      AND f.risk_level IN ('P1', 'P2', 'P3')
                    ORDER BY
                      CASE f.risk_level WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 WHEN 'P3' THEN 3 WHEN 'P4' THEN 4 ELSE 5 END,
                      f.updated_at DESC
                    """,
                    (target_run_id,),
                ).fetchall()
        except sqlite3.Error:
            return []
        return [self._platform_finding_from_row(row) for row in rows]

    def list_certificate_license_evidence(self, db_path: Path, run_id: str | None = None) -> list[CheckEvidenceItem]:
        db = Path(db_path)
        if not db.exists():
            return []
        try:
            with connect(db) as conn:
                target_run_id = run_id or self._latest_run_id(conn)
                if not target_run_id:
                    return []
                placeholders = ",".join("?" for _ in self.CERTIFICATE_LICENSE_RULE_IDS)
                rows = conn.execute(
                    f"""
                    SELECT rr.*, r.rule_name, r.definition_json
                    FROM rule_results rr
                    LEFT JOIN rules r ON r.rule_id = rr.rule_id
                    WHERE rr.run_id = ? AND rr.rule_id IN ({placeholders})
                    ORDER BY
                      CASE rr.rule_id
                        WHEN 'VSL-VC-005' THEN 1
                        WHEN 'VSL-VC-006' THEN 2
                        WHEN 'VSL-HOST-008' THEN 3
                        WHEN 'VSL-HOST-023' THEN 4
                        ELSE 5
                      END,
                      rr.object_type,
                      rr.object_name
                    """,
                    (target_run_id, *self.CERTIFICATE_LICENSE_RULE_IDS),
                ).fetchall()
        except sqlite3.Error:
            return []
        return [self._check_evidence_from_row(row) for row in rows]

    def list_platform_assets(self, db_path: Path, run_id: str | None = None) -> list[PlatformAssetItem]:
        db = Path(db_path)
        if not db.exists():
            return []
        try:
            with connect(db) as conn:
                target_run_id = run_id or self._latest_run_id(conn)
                if not target_run_id:
                    return []
                rows = conn.execute(
                    """
                    SELECT object_type, object_name, path, properties_json, run_id
                    FROM inventory_objects
                    WHERE run_id = ?
                    ORDER BY object_type, object_name
                    """,
                    (target_run_id,),
                ).fetchall()
        except sqlite3.Error:
            return []
        return [self._platform_asset_from_row(row) for row in rows]

    def list_customer_summaries(self, db_path: Path) -> list[CustomerCenterItem]:
        db = Path(db_path)
        if not db.exists():
            return []
        try:
            with connect(db) as conn:
                customers = conn.execute(
                    """
                    SELECT
                      COALESCE(NULLIF(TRIM(c.customer_name), ''), ?) AS customer_name,
                      COUNT(DISTINCT v.vcenter_id) AS vcenter_count,
                      MAX(COALESCE(c.updated_at, c.created_at)) AS latest_customer_at
                    FROM customers c
                    LEFT JOIN vcenters v ON v.customer_id = c.customer_id
                    GROUP BY COALESCE(NULLIF(TRIM(c.customer_name), ''), ?)
                    ORDER BY latest_customer_at DESC
                    """,
                    (DEFAULT_CUSTOMER_NAME, DEFAULT_CUSTOMER_NAME),
                ).fetchall()
                result: list[CustomerCenterItem] = []
                for customer in customers:
                    customer_name = self._display_metadata(customer["customer_name"], "", DEFAULT_CUSTOMER_NAME)
                    run = conn.execute(
                        """
                        SELECT r.run_id, r.score, r.run_status
                        FROM inspection_runs r
                        JOIN customers c ON c.customer_id = r.customer_id
                        WHERE COALESCE(NULLIF(TRIM(c.customer_name), ''), ?) = ?
                        ORDER BY COALESCE(finished_at, updated_at, created_at) DESC
                        LIMIT 1
                        """,
                        (DEFAULT_CUSTOMER_NAME, customer_name),
                    ).fetchone()
                    host_count = vm_count = 0
                    latest_score = run["score"] if run else None
                    if run:
                        counts = {
                            row["object_type"]: row["c"]
                            for row in conn.execute(
                                "SELECT object_type, COUNT(*) AS c FROM inventory_objects WHERE run_id = ? GROUP BY object_type",
                                (run["run_id"],),
                            ).fetchall()
                        }
                        host_count = int(counts.get("HostSystem", 0))
                        vm_count = int(counts.get("VirtualMachine", 0))
                    result.append(
                        CustomerCenterItem(
                            customer_name=customer_name,
                            vcenter_count=int(customer["vcenter_count"] or 0),
                            host_count=host_count,
                            vm_count=vm_count,
                            latest_score=latest_score,
                            latest_status=run["run_status"] if run else "unknown",
                        )
                    )
                return result
        except sqlite3.Error:
            return []

    def list_vcenter_summaries(self, db_path: Path) -> list[VCenterCenterItem]:
        db = Path(db_path)
        if not db.exists():
            return []
        try:
            with connect(db) as conn:
                vcenters = conn.execute("SELECT * FROM vcenters ORDER BY updated_at DESC").fetchall()
                result: list[VCenterCenterItem] = []
                for vc in vcenters:
                    run = conn.execute(
                        """
                        SELECT run_id, run_status, score
                        FROM inspection_runs
                        WHERE vcenter_id = ?
                        ORDER BY COALESCE(finished_at, updated_at, created_at) DESC
                        LIMIT 1
                        """,
                        (vc["vcenter_id"],),
                    ).fetchone()
                    version = build = "未记录"
                    if run:
                        obj = conn.execute(
                            """
                            SELECT properties_json
                            FROM inventory_objects
                            WHERE run_id = ? AND object_type = 'vCenter'
                            LIMIT 1
                            """,
                            (run["run_id"],),
                        ).fetchone()
                        if obj:
                            props = self._asset_properties(obj["properties_json"])
                            version = str(props.get("version") or "未记录")
                            build = str(props.get("build") or props.get("build_number") or "未记录")
                    result.append(
                        VCenterCenterItem(
                            name=vc["name"],
                            host=vc["host"],
                            version=version,
                            build=build,
                            latest_status=run["run_status"] if run else vc["status"],
                            latest_score=run["score"] if run else None,
                        )
                    )
                return result
        except sqlite3.Error:
            return []

    def get_history_comparison_summary(self, db_path: Path) -> HistoryComparisonSummary:
        db = Path(db_path)
        if not db.exists():
            return HistoryComparisonSummary(has_data=False, previous_run_id=None, current_run_id=None)
        try:
            with connect(db) as conn:
                # 与历史对比构建器使用同一套环境隔离规则：只在同一 vCenter 环境内配对。
                payload = HistoryComparisonBuilder().build(conn)
                if str(payload.get("state") or "empty") != "ready":
                    current_run_id = str(payload.get("comparison_run_id") or "") or None
                    return HistoryComparisonSummary(has_data=False, previous_run_id=None, current_run_id=current_run_id)
                current_run_id = str(payload.get("comparison_run_id") or "")
                previous_run_id = str(payload.get("baseline_run_id") or "")
                current = self._finding_keys_for_run(conn, current_run_id)
                previous = self._finding_keys_for_run(conn, previous_run_id)
                resolved = conn.execute("SELECT COUNT(*) AS c FROM findings WHERE resolved_run_id = ?", (current_run_id,)).fetchone()
                return HistoryComparisonSummary(
                    has_data=True,
                    previous_run_id=previous_run_id,
                    current_run_id=current_run_id,
                    new_risk_count=len(current - previous),
                    existing_risk_count=len(current & previous),
                    resolved_risk_count=int(resolved["c"] or 0) if resolved else 0,
                )
        except sqlite3.Error:
            return HistoryComparisonSummary(has_data=False, previous_run_id=None, current_run_id=None)

    def get_history_comparison(
        self,
        db_path: Path,
        baseline_run_id: str | None = None,
        comparison_run_id: str | None = None,
    ) -> HistoryComparison:
        db = Path(db_path)
        if not db.exists():
            return self._history_comparison_from_dict(
                {
                    "state": "empty",
                    "run_options": [],
                    "summary_text": "暂无评估数据，完成首次评估后可查看历史趋势。",
                }
            )
        try:
            with connect(db) as conn:
                payload = HistoryComparisonBuilder().build(conn, baseline_run_id, comparison_run_id)
        except sqlite3.Error:
            payload = {
                "state": "empty",
                "run_options": [],
                "summary_text": "暂无评估数据，完成首次评估后可查看历史趋势。",
            }
        return self._history_comparison_from_dict(payload)

    def list_report_packages(
        self,
        db_path: Path,
        report_root: Path | None = None,
        limit: int = 80,
        compat_db_path: Path | None = None,
    ) -> list[ReportCenterItem]:
        packages: dict[tuple[str, str], ReportCenterItem] = {}
        ignored_paths = self._ignored_report_path_keys(db_path)
        try:
            history_rows = self.list_report_history(db_path, limit=limit)
        except sqlite3.Error:
            history_rows = []
        history_by_run = {row.run_id: row for row in history_rows}
        for row in history_rows:
            if row.report_path:
                item = self._report_center_item(row.report_path, db_item=row, report_type="html_package")
                if self._report_center_item_visible(item):
                    packages[self._report_item_key(item)] = item

        roots = [Path(report_root)] if report_root else []
        configured_root = Path(report_root or default_report_output_dir())
        if configured_root not in roots:
            roots.append(configured_root)
        if Path(db_path).exists():
            try:
                with connect(Path(db_path)) as conn:
                    try:
                        db_reports = conn.execute(
                            """
                            SELECT file_path, report_type, run_id
                            FROM reports
                            WHERE report_type IN ('html_package', 'docx', 'pdf')
                              AND report_status = 'success'
                              AND file_path IS NOT NULL
                            ORDER BY COALESCE(generated_at, updated_at, created_at) DESC
                            LIMIT ?
                            """,
                            (limit,),
                        ).fetchall()
                    except sqlite3.Error:
                        db_reports = []
                    for row in db_reports:
                        report = Path(row["file_path"])
                        if self._is_log_analysis_artifact_path(report):
                            continue
                        item = self._report_center_item(report, db_item=history_by_run.get(str(row["run_id"] or "")), report_type=row["report_type"])
                        if self._report_center_item_visible(item):
                            packages[self._report_item_key(item)] = item
                        roots.append(report.parent if report.name.lower() != "index.html" else report.parent)
                    for item in self._log_analysis_report_items(conn, limit=limit):
                        if self._report_center_item_visible(item):
                            packages[self._report_item_key(item)] = item
                            roots.append(item.report_dir)
            except sqlite3.Error as exc:
                if is_database_locked_error(exc):
                    LOGGER.warning("Report center database read skipped because database is busy db_path=%s", db_path)
                else:
                    LOGGER.exception("Report center database read failed db_path=%s", db_path)

        compatibility_db = Path(compat_db_path) if compat_db_path else Path(db_path)
        if compatibility_db.exists():
            try:
                with connect(compatibility_db) as conn:
                    for item in self._upgrade_compat_report_items(conn, limit=limit):
                        packages[self._report_item_key(item)] = item
                        roots.append(item.report_dir)
            except sqlite3.Error as exc:
                if is_database_locked_error(exc):
                    LOGGER.warning("Compatibility report database read skipped because database is busy db_path=%s", compatibility_db)
                else:
                    LOGGER.exception("Compatibility report database read failed db_path=%s", compatibility_db)

        for root in roots:
            if not root.exists():
                continue
            candidates: list[Path] = []
            if (root / "index.html").exists():
                candidates.append(root / "index.html")
            candidates.extend(root.rglob("index.html"))
            for index_path in candidates:
                if self._is_log_analysis_artifact_path(index_path) or self._is_upgrade_compat_artifact_path(index_path):
                    continue
                item = self._report_center_item(index_path, report_type="html_package")
                if self._report_center_item_visible(item):
                    packages.setdefault(self._report_item_key(item), item)
            for docx_path in root.rglob("*.docx"):
                if docx_path.name.startswith("~$") or not self._is_report_docx_candidate(docx_path):
                    continue
                if self._is_log_analysis_artifact_path(docx_path) or self._is_upgrade_compat_artifact_path(docx_path):
                    continue
                item = self._report_center_item(docx_path, report_type="docx")
                if self._report_center_item_visible(item):
                    packages.setdefault(self._report_item_key(item), item)
            for pdf_path in root.rglob("*.pdf"):
                if not self._is_report_pdf_candidate(pdf_path):
                    continue
                if self._is_log_analysis_artifact_path(pdf_path) or self._is_upgrade_compat_artifact_path(pdf_path):
                    continue
                item = self._report_center_item(pdf_path, report_type="pdf")
                if self._report_center_item_visible(item):
                    packages.setdefault(self._report_item_key(item), item)

        grouped = self._merge_health_report_formats(packages.values())
        result = [item for item in grouped if self._report_item_path_key(item) not in ignored_paths]
        result.sort(key=lambda item: item.assessment_time or str(item.report_dir.stat().st_mtime if item.report_dir.exists() else ""), reverse=True)
        return result[:limit]

    def _log_analysis_report_items(self, conn: sqlite3.Connection, limit: int = 80) -> list[ReportCenterItem]:
        try:
            rows = conn.execute(
                """
                SELECT rep.file_path, rep.report_name, rep.report_type, rep.report_status, rep.generated_at,
                       run.log_run_id, run.customer_name, run.report_title,
                       run.support_bundle_name, run.problem_description, run.summary_json,
                       run.finished_at, run.updated_at
                FROM log_analysis_reports rep
                JOIN log_analysis_runs run ON run.log_run_id = rep.log_run_id
                WHERE rep.report_type IN ('log_analysis_html', 'log_analysis_docx')
                  AND rep.report_status = 'success'
                  AND rep.file_path IS NOT NULL
                ORDER BY COALESCE(rep.generated_at, rep.updated_at, rep.created_at) DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        except sqlite3.Error:
            return []
        result: list[ReportCenterItem] = []
        for row in rows:
            path = Path(row["file_path"])
            report_dir = path.parent if path.suffix.lower() == ".docx" or path.name.lower() == "index.html" else path
            payload_path = report_dir / "log_analysis_payload.json"
            payload = self._read_report_payload(payload_path) if payload_path.exists() else {}
            summary = self._log_analysis_summary(row["summary_json"], payload)
            findings = payload.get("findings", []) if isinstance(payload, dict) else []
            diagnosis = payload.get("diagnosis", {}) if isinstance(payload, dict) else {}
            metadata = payload.get("metadata", {}) if isinstance(payload, dict) and isinstance(payload.get("metadata"), dict) else {}
            model_quality = self._log_analysis_model_quality(diagnosis)
            stats = log_analysis_display_stats(summary, diagnosis, findings)
            if model_quality == "accepted":
                title = str(row["report_name"] or metadata.get("report_title") or MODEL_ASSISTED_DIAGNOSIS_TITLE)
            elif model_quality == "downgraded":
                title = str(row["report_name"] or metadata.get("report_title") or MODEL_ASSISTED_TRIAGE_TITLE)
            else:
                title = DEFAULT_LOG_CHECK_TITLE
            result.append(
                ReportCenterItem(
                    run_id=None,
                    report_path=path if path.exists() else None,
                    report_dir=report_dir,
                    payload_path=payload_path if payload_path.exists() else None,
                    title=title,
                    customer_name=str(row["customer_name"] or DEFAULT_CUSTOMER_NAME),
                    site_name=str(row["support_bundle_name"] or "日志包"),
                    assessment_time=str(row["generated_at"] or row["finished_at"] or row["updated_at"] or "暂无数据"),
                    score="不适用",
                    risk_summary={"P1": 0, "P2": 0, "P3": 0, "P4": 0},
                    asset_summary={
                        "Host": 0,
                        "VM": 0,
                        "Datastore": 0,
                        "LogFile": stats["log_files"],
                        "Evidence": stats["key_evidence"],
                        "Supplemental": stats["missing_materials"],
                        "Recommendation": stats["recommendations"],
                    },
                    top_risks=self._log_analysis_top_lines(str(row["problem_description"] or ""), diagnosis, findings, model_quality),
                    history_summary="独立日志分析，不参与健康巡检历史对比。",
                    status="可查看" if path.exists() else "文件缺失",
                    report_type=self._log_analysis_report_type_label(str(row["report_type"]), model_quality),
                    path_hint=str(path if path.exists() else report_dir),
                )
            )
        return result

    def _upgrade_compat_report_items(self, conn: sqlite3.Connection, limit: int = 80) -> list[ReportCenterItem]:
        try:
            rows = conn.execute(
                """
                SELECT rep.file_path, rep.report_name, rep.report_type, rep.generated_at,
                       run.run_id, run.customer_name, run.report_title, run.target_release,
                       run.collection_mode, run.vcenter_host, run.summary_json,
                       run.finished_at, run.updated_at
                FROM upgrade_compat_reports rep
                JOIN upgrade_compat_runs run ON run.run_id = rep.run_id
                WHERE rep.report_type = 'upgrade_compat_html'
                  AND rep.report_status = 'success'
                  AND rep.file_path IS NOT NULL
                ORDER BY COALESCE(rep.generated_at, rep.updated_at, rep.created_at) DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        except sqlite3.Error:
            return []
        result: list[ReportCenterItem] = []
        for row in rows:
            path = Path(row["file_path"])
            report_dir = path.parent if path.suffix.lower() == ".docx" or path.name.lower() == "index.html" else path
            payload_path = report_dir / "data" / "customer_report_payload.json"
            payload = self._read_report_payload(payload_path) if payload_path.exists() else {}
            metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
            summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else self._json_dict(row["summary_json"]).get("summary", {})
            if not isinstance(summary, dict):
                summary = {}
            device_results = payload.get("device_results") if isinstance(payload.get("device_results"), list) else []
            server_results = payload.get("server_results") if isinstance(payload.get("server_results"), list) else []
            failed = int(summary.get("failed", 0) or 0)
            blocked = int(summary.get("server_blocked", 0) or 0)
            unknown = int(summary.get("unknown", 0) or 0)
            top_lines = self._upgrade_compat_top_lines(device_results, server_results)
            result.append(
                ReportCenterItem(
                    run_id=None,
                    report_path=path if path.exists() else None,
                    report_dir=report_dir,
                    payload_path=payload_path if payload_path.exists() else None,
                    title=str(metadata.get("report_title") or row["report_title"] or DEFAULT_UPGRADE_COMPAT_TITLE),
                    customer_name=str(metadata.get("customer_name") or row["customer_name"] or DEFAULT_CUSTOMER_NAME),
                    site_name=f"{row['target_release']} · {'直连 vCenter' if row['collection_mode'] == 'vcenter' else 'support bundle'}",
                    assessment_time=str(row["generated_at"] or row["finished_at"] or row["updated_at"] or "暂无数据"),
                    score="不适用",
                    risk_summary={"P1": failed + blocked, "P2": unknown, "P3": 0, "P4": 0},
                    asset_summary={"Host": int(summary.get("server_total", len(server_results)) or 0), "Device": int(summary.get("total", len(device_results)) or 0), "Passed": int(summary.get("passed", 0) or 0), "Failed": failed, "Unknown": unknown},
                    top_risks=top_lines,
                    history_summary="独立升级兼容性检查，不参与健康巡检历史对比。",
                    status="可查看" if path.exists() else "文件缺失",
                    report_type=self._upgrade_compat_report_type_label(str(row["report_type"])),
                    path_hint=str(path if path.exists() else report_dir),
                )
            )
        return result

    @staticmethod
    def _json_dict(value: str | None) -> dict[str, Any]:
        try:
            decoded = json.loads(value or "{}")
        except json.JSONDecodeError:
            return {}
        return decoded if isinstance(decoded, dict) else {}

    @staticmethod
    def _upgrade_compat_report_type_label(report_type: str) -> str:
        return {"upgrade_compat_html": "升级兼容性 HTML 报告"}.get(report_type, report_type)

    @staticmethod
    def _upgrade_compat_top_lines(devices: list[Any], servers: list[Any]) -> list[str]:
        blocking = {"NOT_CERTIFIED", "DRIVER_NOT_CERTIFIED", "DRIVER_VERSION_BELOW_MINIMUM", "DRIVER_VERSION_MISMATCH", "FIRMWARE_MISMATCH"}
        lines: list[str] = []
        for server in servers:
            if isinstance(server, dict) and server.get("status") == "SERVER_NOT_CERTIFIED":
                lines.append(f"整机：{server.get('host') or server.get('model') or '未采集'} 未认证")
        for device in devices:
            if not isinstance(device, dict):
                continue
            status = ((device.get("matches") or {}).get("vcg") or {}).get("status")
            if status in blocking:
                lines.append(f"设备：{device.get('host') or ''} / {device.get('object_name') or '未采集'} · {status}")
            if len(lines) >= 5:
                break
        return lines or ["未发现基础兼容性阻塞项。"]

    def _log_analysis_model_quality(self, diagnosis: dict[str, Any]) -> str:
        engine = diagnosis.get("diagnosis_engine") if isinstance(diagnosis, dict) else None
        if not isinstance(engine, dict) or engine.get("model_used") is not True:
            return ""
        return str(engine.get("model_quality") or "").strip().lower()

    def _log_analysis_report_type_label(self, report_type: str, model_quality: str) -> str:
        if model_quality == "accepted":
            prefix = "模型辅助诊断"
        elif model_quality == "downgraded":
            prefix = "模型辅助粗排查"
        else:
            prefix = "日志粗排查"
        return {
            "log_analysis_html": f"{prefix} HTML 报告",
            "log_analysis_docx": f"{prefix} Word 报告",
        }.get(report_type, report_type)

    def _log_analysis_top_lines(
        self,
        problem_description: str,
        diagnosis: dict[str, Any],
        findings: list[dict[str, Any]],
        model_quality: str,
    ) -> list[str]:
        lines: list[str] = []
        if problem_description.strip():
            lines.append(f"客户问题：{problem_description.strip()}")
        if isinstance(diagnosis, dict):
            if model_quality in {"accepted", "downgraded"}:
                title = str(diagnosis.get("title") or diagnosis.get("diagnosis_title") or "").strip()
                judgement = str(diagnosis.get("current_judgement") or diagnosis.get("conclusion") or "").strip()
                if title:
                    lines.append(title)
                if judgement:
                    lines.append(judgement)
            else:
                for item in diagnosis.get("evidence_chain") or []:
                    if not isinstance(item, dict):
                        continue
                    message = str(item.get("message") or item.get("event") or "").strip()
                    if message:
                        lines.append(f"日志线索：{message}")
                    if len(lines) >= 5:
                        break
        if len(lines) < 2:
            for item in findings:
                if not isinstance(item, dict):
                    continue
                title = str(item.get("title") or item.get("description") or "").strip()
                if title:
                    lines.append(f"观察项：{title}")
                if len(lines) >= 5:
                    break
        return lines[:5] or ["日志粗排查报告"]

    def _log_analysis_summary(self, summary_json: str | None, payload: dict[str, Any]) -> dict[str, Any]:
        merged: dict[str, Any] = {}
        try:
            summary = json.loads(summary_json or "{}")
        except json.JSONDecodeError:
            summary = {}
        if isinstance(summary, dict):
            merged.update(summary)
        if isinstance(payload, dict) and isinstance(payload.get("summary"), dict):
            merged.update(payload["summary"])
        return merged

    def _is_log_analysis_artifact_path(self, path: Path) -> bool:
        report_dir = path.parent if path.name.lower() == "index.html" or path.suffix.lower() == ".docx" else path
        return (report_dir / "log_analysis_payload.json").exists()

    def _is_upgrade_compat_artifact_path(self, path: Path) -> bool:
        report_dir = path.parent if path.name.lower() == "index.html" or path.suffix.lower() == ".docx" else path
        return (report_dir / "data" / "customer_report_payload.json").exists() and report_dir.name.startswith("upgrade-compat-")

    def _history_comparison_from_dict(self, payload: dict[str, Any]) -> HistoryComparison:
        def delta(data: dict[str, Any] | None, label: str = "") -> HistoryDelta:
            data = data or {}
            return HistoryDelta(
                baseline=data.get("baseline"),
                comparison=data.get("comparison"),
                delta=data.get("delta"),
                direction=str(data.get("direction") or "same"),
                label=label or str(data.get("label") or ""),
            )

        risk_counts = {
            level: delta((payload.get("risk_counts") or {}).get(level), level)
            for level in ("P1", "P2", "P3")
        }
        asset_counts = {
            key: delta((payload.get("asset_counts") or {}).get(key), ((payload.get("asset_counts") or {}).get(key) or {}).get("label", key))
            for key in ("vcenter", "cluster", "host", "datastore", "vm")
        }
        risk_changes = {
            key: [
                HistoryRiskChangeItem(
                    title=str(item.get("title") or "未命名风险"),
                    risk_level=str(item.get("risk_level") or ""),
                    object_type=str(item.get("object_type") or ""),
                    object_type_label=str(item.get("object_type_label") or item.get("object_type") or ""),
                    object_name=str(item.get("object_name") or "未记录"),
                    current_observed=str(item.get("current_observed") or "未记录"),
                    expected_state=str(item.get("expected_state") or "按健康评估基线执行"),
                    change_status=str(item.get("change_status") or key),
                    change_status_label=str(item.get("change_status_label") or {"new": "新增", "closed": "本次未再检出", "persistent": "持续"}.get(key, key)),
                )
                for item in (payload.get("risk_changes") or {}).get(key, [])
            ]
            for key in ("new", "closed", "persistent")
        }
        asset_changes = {
            key: [
                HistoryAssetChangeItem(
                    object_type=str(item.get("object_type") or ""),
                    object_type_label=str(item.get("object_type_label") or item.get("object_type") or ""),
                    object_name=str(item.get("object_name") or "未记录"),
                    location=str(item.get("location") or "未记录"),
                    change_status=str(item.get("change_status") or key),
                    change_status_label=str(item.get("change_status_label") or {"new": "新增", "removed": "删除", "persistent": "持续"}.get(key, key)),
                )
                for item in (payload.get("asset_changes") or {}).get(key, [])
            ]
            for key in ("new", "removed", "persistent")
        }
        return HistoryComparison(
            state=str(payload.get("state") or "empty"),
            run_options=[
                HistoryRunOption(
                    run_id=str(item.get("run_id") or ""),
                    label=str(item.get("label") or ""),
                    timestamp=str(item.get("timestamp") or ""),
                    score=item.get("score"),
                    risk_total=int(item.get("risk_total") or 0),
                )
                for item in payload.get("run_options", [])
            ],
            baseline_run_id=str(payload.get("baseline_run_id") or ""),
            comparison_run_id=str(payload.get("comparison_run_id") or ""),
            baseline_label=str(payload.get("baseline_label") or ""),
            comparison_label=str(payload.get("comparison_label") or ""),
            baseline_time=str(payload.get("baseline_time") or ""),
            comparison_time=str(payload.get("comparison_time") or ""),
            score=delta(payload.get("score"), "健康评分"),
            risk_counts=risk_counts,
            asset_counts=asset_counts,
            risk_changes=risk_changes,
            asset_changes=asset_changes,
            summary_text=str(payload.get("summary_text") or "暂无历史对比数据。"),
            environment_label=str(payload.get("environment_label") or ""),
        )

    def _report_center_item(self, report_path: Path, db_item: ReportHistoryItem | None = None, report_type: str | None = None) -> ReportCenterItem:
        path = Path(report_path)
        is_docx = (report_type == "docx") or path.suffix.lower() == ".docx"
        is_pdf = (report_type == "pdf") or path.suffix.lower() == ".pdf"
        report_dir = path.parent if path.name.lower() == "index.html" or is_docx or is_pdf else path
        index_path = report_dir / "index.html"
        payload_path = report_dir / "data" / "customer_report_payload.json"
        payload = self._read_report_payload(payload_path) if payload_path.exists() else {}
        context = payload.get("report_context", {}) if isinstance(payload, dict) else {}
        report_info = context.get("report_info", {}) if isinstance(context, dict) else {}
        customer_info = context.get("customer_info", {}) if isinstance(context, dict) else {}
        run_timing = context.get("run_timing", {}) if isinstance(context, dict) else {}
        health = context.get("health_score", {}) if isinstance(context, dict) else {}
        risks = self._report_risk_summary(context.get("risk_summary", {}) if isinstance(context, dict) else {}, db_item)
        assets = self._report_asset_summary(payload)
        title = self._display_metadata(report_info.get("report_title"), "", DEFAULT_REPORT_TITLE)
        customer = self._display_metadata(
            customer_info.get("customer_name"),
            db_item.customer_name if db_item else "",
            DEFAULT_CUSTOMER_NAME,
        )
        site = self._display_metadata(
            customer_info.get("site_name"),
            db_item.site_name if db_item else "",
            "暂无数据",
        )
        assessment_time = str(
            run_timing.get("finished_at")
            or report_info.get("generated_at")
            or (db_item.generated_at if db_item else "")
            or (db_item.updated_at if db_item else "")
            or "暂无数据"
        )
        score = health.get("score")
        if score in (None, "") and db_item:
            score = db_item.score
        history = context.get("history_comparison", {}) if isinstance(context, dict) else {}
        history_summary = "暂无历史对比"
        if isinstance(history, dict) and history.get("state") == "ready" and history.get("baseline_run_id") and history.get("comparison_run_id"):
            history_summary = str(history.get("summary_text") or "已生成历史对比摘要")
        elif isinstance(history, dict) and history.get("state") in {"environment_mismatch", "run_unavailable"}:
            # 跨 vCenter 环境或所选记录不可用时，只透出明确的不可比提示。
            history_summary = str(history.get("summary_text") or "暂无可比的历史巡检记录")
        visible_path = path if is_docx or is_pdf else index_path
        status = "可查看" if visible_path.exists() and (payload or is_docx or is_pdf) else "数据不完整" if visible_path.exists() else "文件缺失"
        return ReportCenterItem(
            run_id=db_item.run_id if db_item else None,
            report_path=visible_path if visible_path.exists() else None,
            report_dir=report_dir,
            payload_path=payload_path if payload_path.exists() else None,
            title=title,
            customer_name=customer,
            site_name=site,
            assessment_time=assessment_time,
            score=score if score not in ("", None) else "暂无数据",
            risk_summary=risks,
            asset_summary=assets,
            top_risks=self._report_top_risks(payload),
            history_summary=history_summary,
            status=status,
            report_type=self._report_type_label("docx" if is_docx else "pdf" if is_pdf else (report_type or "html_package")),
            path_hint=str(visible_path if visible_path.exists() else report_dir),
        )

    def _report_item_key(self, item: ReportCenterItem) -> tuple[str, str]:
        path = item.report_path or item.report_dir
        return (str(path).lower(), item.report_type)

    @staticmethod
    def _merge_health_report_formats(items: Iterable[ReportCenterItem]) -> list[ReportCenterItem]:
        """Present HTML, Word, and PDF exports from one health run as a single task."""
        grouped: dict[Path, list[ReportCenterItem]] = {}
        standalone: list[ReportCenterItem] = []
        for item in items:
            if item.report_type in {"HTML 报告包", "Word 报告", "PDF 报告"}:
                grouped.setdefault(item.report_dir, []).append(item)
            else:
                standalone.append(item)
        merged: list[ReportCenterItem] = []
        for members in grouped.values():
            html_item = next((item for item in members if item.report_type == "HTML 报告包"), None)
            word_item = next((item for item in members if item.report_type == "Word 报告"), None)
            pdf_item = next((item for item in members if item.report_type == "PDF 报告"), None)
            primary = html_item or word_item or pdf_item
            if primary is None:
                continue
            formats = [
                label for label, item in (
                    ("HTML", html_item),
                    ("Word", word_item),
                    ("PDF", pdf_item),
                ) if item is not None
            ]
            if len(formats) > 1:
                primary.report_type = " · ".join(formats)
                preferred = html_item or word_item or pdf_item
                primary.report_path = preferred.report_path
                primary.path_hint = str(preferred.report_path or primary.report_dir)
            merged.append(primary)
        return [*standalone, *merged]

    @staticmethod
    def _report_item_path_key(item: ReportCenterItem) -> str:
        return str(item.report_dir.resolve(strict=False)).casefold()

    @staticmethod
    def _is_report_docx_candidate(path: Path) -> bool:
        """Only discover Word files that carry a VStackLens report package marker."""
        report_dir = path.parent
        return (report_dir / "index.html").exists() and (
            (report_dir / "data" / "customer_report_payload.json").exists()
            or (report_dir / "log_analysis_payload.json").exists()
        )

    @staticmethod
    def _is_report_pdf_candidate(path: Path) -> bool:
        return Path(path).name.lower() == "vstacklens-pdf-report.pdf" and Path(path).is_file()

    def _ignored_report_path_keys(self, db_path: Path) -> set[str]:
        db = Path(db_path)
        if not db.exists():
            return set()
        try:
            with connect(db) as conn, conn:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS report_center_ignored_items (path_key TEXT PRIMARY KEY, created_at TEXT NOT NULL)"
                )
                return {str(row["path_key"]) for row in conn.execute("SELECT path_key FROM report_center_ignored_items").fetchall()}
        except sqlite3.Error:
            return set()

    def remove_report_center_item(self, db_path: Path, item: ReportCenterItem) -> bool:
        """Hide one report-center entry without deleting files, runs, or snapshots."""
        db = Path(db_path)
        init_db(db)
        try:
            with connect(db) as conn, conn:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS report_center_ignored_items (path_key TEXT PRIMARY KEY, created_at TEXT NOT NULL)"
                )
                conn.execute(
                    "INSERT OR REPLACE INTO report_center_ignored_items(path_key, created_at) VALUES (?, ?)",
                    (self._report_item_path_key(item), datetime.now(timezone.utc).isoformat()),
                )
            return True
        except sqlite3.Error:
            return False

    def _report_type_label(self, report_type: str) -> str:
        return {
            "html_package": "HTML 报告包",
            "html": "HTML 报告",
            "docx": "Word 报告",
            "pdf": "PDF 报告",
            "log_analysis_html": "日志分析 HTML 报告",
            "log_analysis_docx": "日志分析 Word 报告",
            "json": "数据文件",
            "zip": "ZIP 报告包",
        }.get(report_type, report_type)

    def _read_report_payload(self, payload_path: Path) -> dict[str, Any]:
        try:
            payload = json.loads(payload_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return payload if isinstance(payload, dict) else {}

    def _report_center_item_visible(self, item: ReportCenterItem) -> bool:
        if not item.payload_path or not item.payload_path.exists():
            return True
        try:
            payload_text = item.payload_path.read_text(encoding="utf-8")
            payload = json.loads(payload_text)
        except (OSError, json.JSONDecodeError):
            return True

        forbidden_visible_terms = (
            "????",
            "P4 风险",
            "site_name",
            "站点名称",
            "规则 ID",
            "规则包",
            "source_path",
            "raw evidence",
            "rule_results",
        )
        if any(term in payload_text for term in forbidden_visible_terms):
            return False

        context = payload.get("report_context", {}) if isinstance(payload, dict) else {}
        report_info = context.get("report_info", {}) if isinstance(context, dict) else {}
        customer_info = context.get("customer_info", {}) if isinstance(context, dict) else {}
        report_title = str(report_info.get("report_title") or "").strip()
        customer_name = str(customer_info.get("customer_name") or "").strip()
        if self._is_placeholder_metadata(report_title) or self._is_placeholder_metadata(customer_name):
            return False
        return True

    def _display_metadata(self, primary: Any, fallback: Any, default: str) -> str:
        primary_text = "" if primary is None else str(primary).strip()
        fallback_text = "" if fallback is None else str(fallback).strip()
        if primary_text and not self._is_placeholder_metadata(primary_text):
            return primary_text
        if fallback_text and not self._is_placeholder_metadata(fallback_text):
            return fallback_text
        return default

    def _is_placeholder_metadata(self, value: str) -> bool:
        text = value.strip()
        return bool(text) and ("??" in text or all(ch == "?" for ch in text))

    def _report_risk_summary(self, summary: dict[str, Any], db_item: ReportHistoryItem | None = None) -> dict[str, int]:
        fallback = db_item.risk_summary if db_item else {}
        source = summary or fallback or {}
        return {level: int(source.get(level, 0) or 0) for level in ("P1", "P2", "P3", "P4")}

    def _report_asset_summary(self, payload: dict[str, Any]) -> dict[str, int]:
        summary = ((payload.get("assets") or {}).get("summary") or {}) if isinstance(payload, dict) else {}
        return {
            "vCenter": int(summary.get("vCenter", 0) or summary.get("vcenter", 0) or 0),
            "Cluster": int(summary.get("ClusterComputeResource", 0) or summary.get("Cluster", 0) or summary.get("cluster", 0) or 0),
            "Host": int(summary.get("HostSystem", 0) or summary.get("Host", 0) or summary.get("host", 0) or 0),
            "Datastore": int(summary.get("Datastore", 0) or summary.get("datastore", 0) or 0),
            "VM": int(summary.get("VirtualMachine", 0) or summary.get("VM", 0) or summary.get("vm", 0) or 0),
        }

    def _report_top_risks(self, payload: dict[str, Any], limit: int = 5) -> list[str]:
        findings = payload.get("findings", []) if isinstance(payload, dict) else []
        if not isinstance(findings, list):
            return []
        result = []
        for item in findings[:limit]:
            if not isinstance(item, dict):
                continue
            if str(item.get("risk_level") or "") not in {"P1", "P2", "P3"}:
                continue
            title = str(item.get("title") or "未命名风险")
            level = str(item.get("risk_level") or "")
            obj = str(item.get("object_name") or "")
            result.append(f"{level} · {title} · {obj}".strip(" ·"))
        return result

    def open_report(self, report_path: Path) -> None:
        self._open_path(report_path)

    def open_report_dir(self, report_dir: Path) -> None:
        self._open_path(report_dir)

    def _complete_result(
        self,
        db_path: Path,
        run_id: str,
        report_dir: Path,
        zip_path: Path | None,
        progress_callback: Callable[[InspectionProgress], None] | None = None,
        docx_path: Path | None = None,
        docx_error: str | None = None,
        pdf_path: Path | None = None,
        pdf_error: str | None = None,
        html_error: str | None = None,
    ) -> InspectionRunResult:
        with connect(db_path) as conn:
            row = conn.execute("SELECT score, risk_summary_json, risk_category_summary_json FROM inspection_runs WHERE run_id = ?", (run_id,)).fetchone()
            html_row = conn.execute(
                """
                SELECT file_path, report_status, error_message
                FROM reports
                WHERE run_id = ? AND report_type = 'html_package'
                ORDER BY COALESCE(generated_at, updated_at, created_at) DESC
                LIMIT 1
                """,
                (run_id,),
            ).fetchone()
            docx_row = conn.execute(
                """
                SELECT file_path, report_status, error_message
                FROM reports
                WHERE run_id = ? AND report_type = 'docx'
                ORDER BY COALESCE(generated_at, updated_at, created_at) DESC
                LIMIT 1
                """,
                (run_id,),
            ).fetchone()
            pdf_row = conn.execute(
                """
                SELECT file_path, report_status, error_message
                FROM reports
                WHERE run_id = ? AND report_type = 'pdf'
                ORDER BY COALESCE(generated_at, updated_at, created_at) DESC
                LIMIT 1
                """,
                (run_id,),
            ).fetchone()
        if docx_row:
            if not docx_path and docx_row["report_status"] == "success" and docx_row["file_path"]:
                docx_path = Path(docx_row["file_path"])
            if not docx_error and docx_row["report_status"] != "success":
                docx_error = docx_row["error_message"] or "Word 报告未生成。"
        if pdf_row:
            if not pdf_path and pdf_row["report_status"] == "success" and pdf_row["file_path"]:
                pdf_path = Path(pdf_row["file_path"])
            if not pdf_error and pdf_row["report_status"] != "success":
                pdf_error = pdf_row["error_message"] or "PDF 报告未生成。"
        if html_row and not html_error and html_row["report_status"] != "success":
            html_error = html_row["error_message"] or "HTML 报告未生成。"
        risk_summary = self._risk_summary_from_json((row["risk_category_summary_json"] or row["risk_summary_json"]) if row else "{}")
        result = InspectionRunResult(
            run_id=run_id,
            report_path=report_dir / "index.html",
            report_dir=report_dir,
            zip_path=zip_path,
            score=row["score"] if row else None,
            docx_path=docx_path,
            docx_error=docx_error,
            risk_summary=risk_summary,
            pdf_path=pdf_path,
            pdf_error=pdf_error,
            html_error=html_error,
        )
        self._progress = InspectionProgress(
            state=InspectionState.COMPLETED,
            run_id=run_id,
            stage="success",
            percent=100,
            message="巡检完成",
        )
        self._emit_progress(progress_callback)
        return result

    def _set_progress(
        self,
        stage: str,
        percent: int,
        progress_callback: Callable[[InspectionProgress], None] | None = None,
        cancel_requested: Callable[[], bool] | None = None,
    ) -> None:
        LOGGER.info("vCenter inspection progress stage=%s percent=%s run_id=%s", stage, percent, self._progress.run_id)
        if stage.startswith("run_id:"):
            self._progress = InspectionProgress(
                state=InspectionState.RUNNING,
                run_id=stage.split(":", 1)[1],
                stage="pending",
                percent=percent,
                message=self._stage_label("pending"),
            )
            self._emit_progress(progress_callback)
            self._raise_if_cancelled(cancel_requested)
            return
        state = InspectionState.COMPLETED if stage == "success" else InspectionState.RUNNING
        if stage == "failed":
            state = InspectionState.FAILED
        if stage == "cancelled":
            state = InspectionState.CANCELLED
        self._progress = InspectionProgress(
            state=state,
            run_id=self._progress.run_id,
            stage=stage,
            percent=percent,
            message=self._stage_label(stage),
        )
        self._emit_progress(progress_callback)
        self._raise_if_cancelled(cancel_requested)

    def _raise_if_cancelled(self, cancel_requested: Callable[[], bool] | None) -> None:
        if cancel_requested and cancel_requested():
            raise InspectionCancelledError("巡检已取消。")

    def _emit_progress(self, progress_callback: Callable[[InspectionProgress], None] | None = None) -> None:
        if progress_callback:
            progress_callback(self._progress)

    def _report_dir(self, config: DesktopInspectionConfig) -> Path:
        return Path(config.report_output_dir) / f"{self._safe_name(config.vcenter)}_{{run_id}}"

    def _docx_report_path(self, config: DesktopInspectionConfig) -> Path:
        return self._report_dir(config) / "VStackLens-Word-Report.docx"

    def _pdf_report_path(self, config: DesktopInspectionConfig) -> Path:
        return self._report_dir(config) / "VStackLens-PDF-Report.pdf"

    def _safe_name(self, value: str) -> str:
        return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value) or "vcenter"

    def _latest_run_row(self, conn: sqlite3.Connection) -> sqlite3.Row | None:
        return conn.execute(
            """
            SELECT r.*, c.customer_name, s.site_name, v.host AS vcenter_host
            FROM inspection_runs r
            JOIN customers c ON c.customer_id = r.customer_id
            JOIN sites s ON s.site_id = r.site_id
            JOIN vcenters v ON v.vcenter_id = r.vcenter_id
            ORDER BY COALESCE(r.finished_at, r.updated_at, r.created_at) DESC
            LIMIT 1
            """
        ).fetchone()

    def _latest_run_id(self, conn: sqlite3.Connection) -> str | None:
        row = conn.execute(
            """
            SELECT run_id
            FROM inspection_runs
            ORDER BY COALESCE(finished_at, updated_at, created_at) DESC
            LIMIT 1
            """
        ).fetchone()
        return row["run_id"] if row else None

    def _risk_summary_from_json(self, value: str | None) -> dict[str, int]:
        payload = json.loads(value or "{}")
        return {level: int(payload.get(level, 0) or 0) for level in ("P1", "P2", "P3", "P4")}

    def _asset_summary_for_run(self, conn: sqlite3.Connection, run_id: str) -> dict[str, int]:
        labels = {
            "vCenter": "vCenter",
            "ClusterComputeResource": "Cluster",
            "HostSystem": "ESXi Host",
            "Datastore": "Datastore",
            "VirtualMachine": "VM",
        }
        result = {"vCenter": 0, "Cluster": 0, "ESXi Host": 0, "Datastore": 0, "VM": 0}
        rows = conn.execute("SELECT object_type, COUNT(*) AS c FROM inventory_objects WHERE run_id = ? GROUP BY object_type", (run_id,)).fetchall()
        for row in rows:
            label = labels.get(row["object_type"])
            if label:
                result[label] = int(row["c"] or 0)
        return result

    def _risk_trend(self, conn: sqlite3.Connection, limit: int = 30) -> list[dict[str, Any]]:
        rows = conn.execute(
            """
            SELECT run_id, score, risk_summary_json, risk_category_summary_json, COALESCE(finished_at, updated_at, created_at) AS ts
            FROM inspection_runs
            ORDER BY COALESCE(finished_at, updated_at, created_at) DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        trend: list[dict[str, Any]] = []
        for row in reversed(rows):
            risk = self._risk_summary_from_json(row["risk_category_summary_json"] or row["risk_summary_json"])
            trend.append(
                {
                    "run_id": row["run_id"],
                    "timestamp": row["ts"],
                    "score": row["score"],
                    "risk_total": actionable_risk_total(risk),
                    "optimization_total": int(risk.get("P4", 0) or 0),
                }
            )
        return trend

    def _health_status(self, score: float | None, risk_summary: dict[str, int], health_impact: dict[str, int] | None = None) -> str:
        if score is None:
            return "评估受限"
        from vstacklens.reports.health_status import assess_health
        return assess_health(risk_summary, {"passed": 1}, 1, health_impact=health_impact)["label"]

    def _health_impact_for_run(self, conn: sqlite3.Connection, run_id: str) -> dict[str, int]:
        rows = conn.execute(
            """
            SELECT f.rule_id, f.risk_level, r.definition_json, rr.evidence_json
            FROM findings f
            LEFT JOIN rules r ON r.rule_id = f.rule_id
            LEFT JOIN rule_results rr ON rr.result_id = f.latest_result_id
            WHERE f.last_seen_run_id = ? AND f.status != 'exception'
            """,
            (run_id,),
        ).fetchall()
        summary = {"none": 0, "attention": 0, "critical": 0}
        for row in rows:
            definition = self._json(row["definition_json"])
            impact = definition.get("health_impact")
            evidence_text = json.dumps(self._json(row["evidence_json"]), ensure_ascii=False).lower()
            if row["rule_id"] == "VSL-DS-020" and any(token in evidence_text for token in ("inaccessible", "reduced availability", "critical", "不可访问", "降级可用")):
                impact = "critical"
            if impact not in summary:
                impact = "none"
            summary[impact] += 1
        return summary

    def _platform_finding_from_row(self, row: sqlite3.Row) -> PlatformFindingItem:
        definition = self._json(row["definition_json"] if "definition_json" in row.keys() else None)
        evidence = self._json(row["evidence_json"] if "evidence_json" in row.keys() else None)
        raw_evidence = self._json(row["raw_json"] if "raw_json" in row.keys() else None)
        report_fields = definition.get("report_fields", {})
        source_path = evidence.get("source_path") or evidence.get("api_path") or self._rule_source_path(definition)
        threshold = self._evidence_threshold(evidence, definition)
        collected_at = evidence.get("collected_at") or (row["evaluated_at"] if "evaluated_at" in row.keys() else "") or row["last_seen_at"]
        explanation = evidence.get("explanation") or evidence.get("evidence_summary_zh") or ""
        has_structured = any(
            value not in (None, "", {}, [])
            for value in (
                raw_evidence,
                evidence.get("source_path"),
                evidence.get("api_path"),
                evidence.get("current_value"),
                row["observed_value"] if "observed_value" in row.keys() else None,
                explanation,
                evidence.get("observed_detail"),
                evidence.get("expected_detail"),
            )
        )
        remediation = report_fields.get("remediation_zh") or ""
        affected = evidence.get("affected_components") or []
        if not isinstance(affected, list):
            affected = [str(affected)]
        return PlatformFindingItem(
            finding_id=row["finding_id"],
            rule_id=row["rule_id"],
            rule_name=report_fields.get("check_name_zh") or report_fields.get("title_zh") or row["rule_name"] or row["rule_id"],
            risk_level=row["risk_level"],
            title=report_fields.get("finding_title_zh") or report_fields.get("title_zh") or row["title"],
            object_type=row["object_type"],
            object_name=row["object_name"],
            impact=report_fields.get("business_impact_zh") or report_fields.get("summary_zh") or "",
            current_observed=self._display_value(evidence.get("current_value_zh") or evidence.get("current_value") or row["observed_value"]),
            expected_state=self._display_value(evidence.get("expected_value_zh") or evidence.get("expected_value") or row["expected_value"]),
            remediation=remediation,
            evidence_summary=self._display_value(evidence.get("evidence_summary_zh")),
            affected_components=[str(item) for item in affected],
            fault_detail=self._display_value(evidence.get("fault_detail")) if evidence.get("fault_detail") else "",
            threshold=self._display_value(threshold) if threshold not in (None, "", {}, []) else "",
            source_path=self._display_value(source_path) if source_path else "",
            collected_at=str(collected_at or ""),
            explanation=self._display_value(explanation) if explanation else "",
            raw_evidence=self._audit_evidence(raw_evidence, evidence),
            has_structured_evidence=has_structured,
            status=row["status"],
            last_seen_at=row["last_seen_at"],
        )

    def _check_evidence_from_row(self, row: sqlite3.Row) -> CheckEvidenceItem:
        definition = self._json(row["definition_json"] if "definition_json" in row.keys() else None)
        evidence = self._json(row["evidence_json"] if "evidence_json" in row.keys() else None)
        raw_evidence = self._json(row["raw_json"] if "raw_json" in row.keys() else None)
        report_fields = definition.get("report_fields", {})
        source_path = evidence.get("source_path") or evidence.get("api_path") or self._rule_source_path(definition)
        threshold = self._evidence_threshold(evidence, definition)
        collected_at = evidence.get("collected_at") or (row["evaluated_at"] if "evaluated_at" in row.keys() else "") or ""
        explanation = evidence.get("explanation") or evidence.get("evidence_summary_zh") or ""
        has_structured = any(
            value not in (None, "", {}, [])
            for value in (
                raw_evidence,
                evidence.get("source_path"),
                evidence.get("api_path"),
                evidence.get("current_value"),
                row["observed_value"] if "observed_value" in row.keys() else None,
                explanation,
                evidence.get("observed_detail"),
                evidence.get("expected_detail"),
            )
        )
        rule_name = report_fields.get("check_name_zh") or report_fields.get("title_zh") or row["rule_name"] or row["rule_id"]
        return CheckEvidenceItem(
            result_id=row["result_id"],
            rule_id=row["rule_id"],
            rule_name=rule_name,
            result_status=row["result_status"],
            risk_level=row["risk_level"],
            object_type=row["object_type"],
            object_name=row["object_name"],
            current_observed=self._display_value(evidence.get("current_value_zh") or evidence.get("current_value") or row["observed_value"]),
            expected_state=self._display_value(evidence.get("expected_value_zh") or evidence.get("expected_value") or row["expected_value"]),
            evidence_summary=self._display_value(evidence.get("evidence_summary_zh") or row["error_message"]),
            threshold=self._display_value(threshold) if threshold not in (None, "", {}, []) else "",
            source_path=self._display_value(source_path) if source_path else "",
            collected_at=str(collected_at or ""),
            explanation=self._display_value(explanation) if explanation else "",
            raw_evidence=self._audit_evidence(raw_evidence, evidence),
            has_structured_evidence=has_structured,
        )

    def _json(self, value: str | None) -> dict[str, Any]:
        if not value:
            return {}
        try:
            payload = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return payload if isinstance(payload, dict) else {}

    def _rule_source_path(self, definition: dict[str, Any]) -> str:
        data_source = definition.get("data_source", {})
        paths = data_source.get("api_paths") or []
        if isinstance(paths, list):
            return ", ".join(str(path) for path in paths if path)
        return str(paths or "")

    def _evidence_threshold(self, evidence: dict[str, Any], definition: dict[str, Any]) -> Any:
        for container_name in ("observed_detail", "expected_detail", "parameters"):
            container = evidence.get(container_name)
            if not isinstance(container, dict):
                continue
            for key, value in container.items():
                key_text = str(key).lower()
                if "threshold" in key_text or key_text.startswith("max_") or key_text.startswith("min_") or key_text.startswith("expected_min"):
                    return value
        expected = evidence.get("expected_value")
        if expected not in (None, "", {}, []):
            return expected
        return definition.get("evidence_schema", {}).get("expected_value")

    def _audit_evidence(self, raw_evidence: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
        if raw_evidence:
            return raw_evidence
        audit = {
            "observed_detail": evidence.get("observed_detail", {}),
            "expected_detail": evidence.get("expected_detail", {}),
            "affected_components": evidence.get("affected_components", []),
        }
        return {key: value for key, value in audit.items() if value not in (None, "", {}, [])}

    def _display_value(self, value: Any) -> str:
        if value is None or value == "":
            return "未记录"
        if isinstance(value, bool):
            return "是" if value else "否"
        if isinstance(value, (int, float)):
            return str(value)
        if isinstance(value, list):
            return "、".join(self._display_value(item) for item in value) or "未记录"
        if isinstance(value, dict):
            return self._display_dict(value)
        text = str(value).strip()
        if not text:
            return "未记录"
        lowered = text.lower()
        if lowered == "true":
            return "是"
        if lowered == "false":
            return "否"
        if lowered in {"none", "null"}:
            return "未记录"
        if lowered in {"green", "gray"}:
            return "正常"
        if lowered in {"yellow", "red"}:
            return "异常"
        if lowered in {"poweredon", "powered_on"}:
            return "已开机"
        if lowered in {"poweredoff", "powered_off"}:
            return "已关机"
        if text[:1] in "[{":
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, dict):
                return self._display_dict(parsed)
            if isinstance(parsed, list):
                return self._display_value(parsed)
        return re.sub(r"\btrue\b|\bfalse\b", lambda match: "是" if match.group(0).lower() == "true" else "否", text, flags=re.IGNORECASE)

    def _display_dict(self, value: dict[str, Any]) -> str:
        if not value:
            return "未记录"
        labels = {
            "current": "当前",
            "expected": "期望",
            "status": "状态",
            "name": "名称",
            "object": "对象",
            "host": "主机",
            "cluster": "集群",
            "count": "数量",
        }
        parts = []
        for key, item in value.items():
            label = labels.get(str(key), str(key).replace("_", " "))
            parts.append(f"{label}: {self._display_value(item)}")
        return "；".join(parts)

    def _platform_asset_from_row(self, row: sqlite3.Row) -> PlatformAssetItem:
        properties = self._asset_properties(row["properties_json"])
        path = str(row["path"] or "")
        location = str(properties.get("asset_location") or self._fallback_asset_location(row["object_type"], row["object_name"], path))
        return PlatformAssetItem(
            object_type=row["object_type"],
            object_type_label=self._object_type_label(row["object_type"]),
            object_name=row["object_name"],
            location=location,
            detail=self._asset_detail(row["object_type"], properties),
            run_id=row["run_id"],
        )

    def _asset_properties(self, raw: str | None) -> dict[str, Any]:
        payload = json.loads(raw or "{}")
        props = payload.get("properties", payload)
        return props if isinstance(props, dict) else {}

    def _fallback_asset_location(self, object_type: str, object_name: str, path: str) -> str:
        if object_type == "vCenter":
            return "vCenter 根对象"
        clean = path.strip()
        name = object_name.strip()
        if clean and clean != name:
            parts = [part.strip() for part in clean.replace("\\", "/").split("/") if part.strip()]
            if len(parts) > 1 and parts[-1] == name:
                return " / ".join(parts[:-1])
            return clean
        return "层级未记录"

    def _asset_detail(self, object_type: str, properties: dict[str, Any]) -> str:
        if object_type == "vCenter":
            version = properties.get("version") or "未记录"
            return f"版本 {version}"
        if object_type == "HostSystem":
            cpu = properties.get("cpu_usage_percent")
            memory = properties.get("memory_usage_percent")
            parts = []
            if cpu is not None:
                parts.append(f"CPU {cpu}%")
            if memory is not None:
                parts.append(f"内存 {memory}%")
            return "，".join(parts) if parts else "主机属性已采集"
        if object_type == "Datastore":
            usage = properties.get("datastore_usage_percent")
            return f"容量使用率 {usage}%" if usage is not None else "数据存储属性已采集"
        if object_type == "VirtualMachine":
            power = properties.get("power_state") or "未记录"
            return f"电源状态 {power}"
        if object_type == "ClusterComputeResource":
            ha = properties.get("ha_enabled")
            drs = properties.get("drs_enabled")
            parts = []
            if ha is not None:
                parts.append("HA 启用" if ha else "HA 未启用")
            if drs is not None:
                parts.append("DRS 启用" if drs else "DRS 未启用")
            return "，".join(parts) if parts else "集群属性已采集"
        return "属性已采集"

    def _object_type_label(self, object_type: str) -> str:
        return {
            "vCenter": "vCenter",
            "ClusterComputeResource": "Cluster",
            "HostSystem": "ESXi",
            "Datastore": "Datastore",
            "VirtualMachine": "VM",
        }.get(object_type, object_type)

    def _finding_keys_for_run(self, conn: sqlite3.Connection, run_id: str) -> set[str]:
        rows = conn.execute(
            """
            SELECT finding_key
            FROM findings
            WHERE last_seen_run_id = ?
              AND status != 'exception'
              AND risk_level IN ('P1', 'P2', 'P3')
            """,
            (run_id,),
        ).fetchall()
        return {row["finding_key"] for row in rows}

    def _open_path(self, path: Path) -> None:
        target = Path(path)
        if not target.exists():
            raise FileNotFoundError(f"路径不存在：{target}")
        if sys.platform.startswith("win"):
            os.startfile(str(target))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(target)])
        else:
            subprocess.Popen(["xdg-open", str(target)])

    def _state_from_run_status(self, status: str) -> InspectionState:
        if status == "success":
            return InspectionState.COMPLETED
        if status == "cancelled":
            return InspectionState.CANCELLED
        if status == "failed":
            return InspectionState.FAILED
        if status in {"pending", "running"}:
            return InspectionState.RUNNING
        return InspectionState.IDLE

    def _stage_label(self, stage: str | None) -> str:
        labels = {
            "idle": "等待巡检",
            "pending": "等待启动",
            "loading_rules": "加载健康基线",
            "validating_rules": "校验规则包",
            "planning_collection": "生成采集计划",
            "prechecking": "连接 vCenter",
            "collecting": "采集 vCenter 数据",
            "collecting_environment": "vCenter 登录成功，开始读取环境信息",
            "collecting_clusters": "正在采集数据中心与集群信息",
            "collecting_hosts": "正在采集 ESXi 主机与授权状态",
            "collecting_storage_network": "正在采集存储与网络信息",
            "collecting_vms": "正在采集虚拟机信息",
            "collecting_alarms_permissions": "正在采集告警、任务与权限信息",
            "collecting_permissions": "正在核对角色与权限信息",
            "building_vcenter_summary": "正在整理 vCenter 汇总信息",
            "building_cluster_objects": "正在整理集群对象",
            "building_host_objects": "正在整理 ESXi 主机对象",
            "building_storage_objects": "正在整理存储对象",
            "building_vm_objects": "正在整理虚拟机对象",
            "normalizing": "正在整理资产数据",
            "snapshotting": "保存资产快照",
            "executing_rules": "正在执行健康规则",
            "building_findings": "正在生成风险结果",
            "scoring": "正在计算健康评分",
            "reporting": "正在生成 HTML 报告",
            "success": "巡检完成",
            "failed": "巡检失败",
            "cancelling": "正在取消巡检",
            "cancelled": "巡检已取消",
        }
        return labels.get(stage or "", stage or "")
