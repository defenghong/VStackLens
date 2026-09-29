from __future__ import annotations

import json
import io
import re
import tarfile
import tempfile
import zipfile
from collections import Counter
from collections.abc import Callable
from contextlib import closing, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from vstacklens.application.logging_config import get_logger, sensitive_text_summary
from vstacklens.application.paths import default_database_path, default_report_output_dir
from vstacklens.application.cloud_log_diagnosis import (
    DEFAULT_CLOUD_API_URL,
    DEFAULT_CLOUD_MODEL,
    DEFAULT_CLOUD_PROVIDER,
    MODEL_PROTOCOL,
    CloudModelClient,
    CloudModelConfig,
    sanitize_cloud_error,
)
from vstacklens.application.log_diagnostics import EvidenceExtractor, LogDiagnosisEngine
from vstacklens.application.log_diagnostics.scenarios import scenario_title
from vstacklens.core.ids import new_id
from vstacklens.core.time import utc_now_iso
from vstacklens.db.connection import connect, init_db, with_db_retry
from vstacklens.reports.log_analysis_report import render_log_analysis_docx, render_log_analysis_html


LOGGER = get_logger(__name__)

_SENSITIVE_KV_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|access_token|refresh_token|api_key|sessionId|session|token|secret|cookie)\s*=\s*([^\s;&,]+)"
)
_AUTH_BEARER_RE = re.compile(r"(?i)(Authorization\s*:\s*Bearer\s+)[^\s,;]+")
_BEARER_RE = re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]+")
_BASIC_RE = re.compile(r"(?i)\b(Basic\s+)[A-Za-z0-9._~+/=-]+")
_WINDOWS_LOCAL_PATH_RE = re.compile(r"(?i)\b[A-Z]:\\[^\s\"'<>|]+")
_SOURCE_PATH_RE = re.compile(r"(?i)\bsrc[\\/]+vstacklens[^\s\"'<>|]*")
_SITE_PACKAGES_RE = re.compile(r"(?i)\bsite-packages[\\/][^\s\"'<>|]*")
_ARP_IP_CONFLICT_RE = re.compile(
    r"arp:\s*(?P<mac>[0-9a-f:]{17})\s+is using my IP address\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+on\s+(?P<vmk>vmk\d+)\b",
    re.I,
)
_LOCAL_PATH_MARKERS = (
    r"D:\日志",
    r"D:\LOG",
    r"C:\Users",
    r"D:",
    "src\\vstacklens",
    "src/vstacklens",
    "site-packages",
)


MODEL_ASSISTED_DIAGNOSIS_TITLE = "VStackLens 模型辅助日志诊断报告"
MODEL_ASSISTED_TRIAGE_TITLE = "VStackLens 模型辅助粗排查报告"


class _NestedArchiveLimitError(RuntimeError):
    """Raised when a nested archive exceeds local safety limits."""


def _redact_sensitive_log_text(text: str) -> str:
    redacted = _AUTH_BEARER_RE.sub(r"\1***", text)
    redacted = _BEARER_RE.sub(r"\1***", redacted)
    redacted = _BASIC_RE.sub(r"\1***", redacted)
    return _SENSITIVE_KV_RE.sub(lambda match: f"{match.group(1)}=***", redacted)


def _redact_local_path_text(text: str) -> str:
    def replace_windows_path(match: re.Match[str]) -> str:
        raw = match.group(0)
        filename = Path(raw).name or "path"
        return f"<local>\\{filename}"

    redacted = _WINDOWS_LOCAL_PATH_RE.sub(replace_windows_path, text)
    redacted = _SOURCE_PATH_RE.sub("<source>", redacted)
    redacted = _SITE_PACKAGES_RE.sub("<python-package>", redacted)
    return redacted


def _sanitize_report_text(text: str) -> str:
    return _redact_local_path_text(_redact_sensitive_log_text(text))


def _count_items(value: Any) -> int:
    if isinstance(value, list | tuple | set):
        return len(value)
    if isinstance(value, dict):
        return len(value)
    if value in (None, "", False):
        return 0
    return 1


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _diagnosis_evidence_section_count(diagnosis: dict[str, Any]) -> int:
    total = 0
    sections = diagnosis.get("evidence_sections", [])
    if not isinstance(sections, list):
        return 0
    for section in sections:
        if isinstance(section, dict):
            total += _count_items(section.get("excerpts"))
    return total


def _diagnosis_log_file_count(diagnosis: dict[str, Any]) -> int:
    value = _safe_int(diagnosis.get("log_files") or diagnosis.get("log_file_count"))
    if value > 0:
        return value

    files: set[str] = set()
    for item in diagnosis.get("evidence_chain") or []:
        if isinstance(item, dict):
            file_path = str(item.get("file") or "").strip()
            if file_path and "未提取" not in file_path and "未明确" not in file_path:
                files.add(file_path)
    for section in diagnosis.get("evidence_sections") or []:
        if not isinstance(section, dict):
            continue
        file_path = str(section.get("log_file") or "").strip()
        if file_path and "未提取" not in file_path and "未明确" not in file_path:
            files.add(file_path)
        for excerpt in section.get("excerpts") or []:
            if not isinstance(excerpt, dict):
                continue
            file_path = str(excerpt.get("file") or "").strip()
            if file_path and "未提取" not in file_path and "未明确" not in file_path:
                files.add(file_path)
    return len(files)


def _diagnosis_model_used(diagnosis: dict[str, Any] | None) -> bool:
    if not isinstance(diagnosis, dict):
        return False
    engine = diagnosis.get("diagnosis_engine")
    return isinstance(engine, dict) and engine.get("model_used") is True


def log_analysis_display_stats(
    summary: dict[str, Any] | None,
    diagnosis: dict[str, Any] | None = None,
    findings: list[dict[str, Any]] | None = None,
) -> dict[str, int]:
    """Return customer-facing log-analysis counters with V3 diagnosis fallbacks."""

    summary = summary if isinstance(summary, dict) else {}
    diagnosis = diagnosis if isinstance(diagnosis, dict) else {}
    findings = findings if isinstance(findings, list) else []

    log_files = _safe_int(summary.get("log_files") or summary.get("log_file_count") or summary.get("LogFile"))
    if log_files <= 0:
        log_files = _diagnosis_log_file_count(diagnosis)

    key_evidence = _safe_int(diagnosis.get("key_evidence_count"))
    if key_evidence <= 0:
        key_evidence = _count_items(diagnosis.get("evidence_chain"))
    if key_evidence <= 0:
        key_evidence = _diagnosis_evidence_section_count(diagnosis)
    if key_evidence <= 0:
        key_evidence = _safe_int(summary.get("diagnosis_evidence_count") or summary.get("evidence_count") or summary.get("Evidence"))

    missing_materials = _count_items(diagnosis.get("missing_materials"))
    if missing_materials <= 0:
        missing_materials = _count_items(diagnosis.get("supplemental_info"))
    if missing_materials <= 0:
        missing_materials = _safe_int(summary.get("missing_materials_count") or summary.get("Supplemental"))

    cannot_confirm = _count_items(diagnosis.get("what_cannot_be_confirmed"))
    if cannot_confirm <= 0:
        cannot_confirm = _count_items(diagnosis.get("cannot_confirm_items"))

    recommendations = _count_items(diagnosis.get("recommended_next_steps"))
    if recommendations <= 0:
        recommendations = _count_items(diagnosis.get("handling_recommendations"))
    if recommendations <= 0:
        recommendations = _safe_int(summary.get("recommendation_count") or summary.get("Recommendation"))
    if recommendations <= 0 and diagnosis:
        recommendations = missing_materials + cannot_confirm
    if recommendations <= 0 and not diagnosis:
        recommendations = len(findings)

    return {
        "log_files": log_files,
        "key_evidence": key_evidence,
        "missing_materials": missing_materials,
        "recommendations": recommendations,
    }


DEFAULT_LOG_ANALYSIS_TITLE = "VMware 日志分析报告"
DEFAULT_LOG_CHECK_TITLE = "VStackLens 日志粗排查报告"
MODEL_ANALYSIS_FAILURE_TITLE = "模型分析失败诊断信息"


class LogAnalysisCloudRequiredError(RuntimeError):
    """Raised when strict cloud log analysis cannot produce a customer report."""


@dataclass(slots=True)
class LogAnalysisConfig:
    support_bundle_path: Path | str = ""
    problem_description: str = ""
    customer_name: str = ""
    report_title: str = DEFAULT_LOG_ANALYSIS_TITLE
    report_output_dir: Path = field(default_factory=default_report_output_dir)
    db_path: Path = field(default_factory=default_database_path)
    cloud_assist_enabled: bool = False
    cloud_provider: str = DEFAULT_CLOUD_PROVIDER
    cloud_api_url: str = DEFAULT_CLOUD_API_URL
    cloud_model_name: str = DEFAULT_CLOUD_MODEL
    cloud_api_key: str = ""
    cloud_timeout_seconds: int = 60
    cloud_require_accepted_result: bool = False

    def normalized(self) -> "LogAnalysisConfig":
        return LogAnalysisConfig(
            support_bundle_path=Path(str(self.support_bundle_path).strip()),
            problem_description=self.problem_description.strip(),
            customer_name=self.customer_name.strip() or "未指定客户",
            report_title=self.report_title.strip() or DEFAULT_LOG_ANALYSIS_TITLE,
            report_output_dir=Path(self.report_output_dir),
            db_path=Path(self.db_path),
            cloud_assist_enabled=bool(self.cloud_assist_enabled),
            cloud_provider=(self.cloud_provider or DEFAULT_CLOUD_PROVIDER).strip() or DEFAULT_CLOUD_PROVIDER,
            cloud_api_url=(self.cloud_api_url or DEFAULT_CLOUD_API_URL).strip() or DEFAULT_CLOUD_API_URL,
            cloud_model_name=(self.cloud_model_name or DEFAULT_CLOUD_MODEL).strip() or DEFAULT_CLOUD_MODEL,
            cloud_api_key=(self.cloud_api_key or "").strip(),
            cloud_timeout_seconds=max(5, int(self.cloud_timeout_seconds or 60)),
            cloud_require_accepted_result=bool(self.cloud_require_accepted_result),
        )


@dataclass(slots=True)
class LogAnalysisProgress:
    run_id: str | None
    stage: str
    percent: int
    message: str
    error: str | None = None


@dataclass(slots=True)
class LogAnalysisResult:
    log_run_id: str
    report_dir: Path
    html_path: Path
    docx_path: Path
    summary: dict[str, Any]
    findings: list[dict[str, Any]]
    diagnosis: dict[str, Any] = field(default_factory=dict)


class LogAnalysisService:
    """Analyze an imported VMware support bundle as a standalone workflow."""

    def __init__(self, diagnosis_engine: LogDiagnosisEngine | None = None) -> None:
        self.diagnosis_engine = diagnosis_engine or LogDiagnosisEngine()

    LOG_HINTS = (
        "vpxd",
        "vmkernel",
        "hostd",
        "vobd",
        "vmksummary",
        "syslog",
        "messages",
        "vmware",
        "vsan",
        "esxupdate",
        "auth",
    )
    TEXT_SUFFIXES = (".log", ".txt", ".out", ".err")
    NESTED_ARCHIVE_SUFFIXES = (".tgz", ".tar.gz", ".tar", ".zip")
    READ_LIMIT_BYTES = 384 * 1024
    SNAPSHOT_READ_LIMIT_BYTES = 16 * 1024 * 1024
    SNAPSHOT_DESCRIPTOR_LIMIT_BYTES = 1024 * 1024
    MIGRATION_READ_LIMIT_BYTES = 16 * 1024 * 1024
    PROBLEM_READ_LIMIT_BYTES = 16 * 1024 * 1024
    MAX_LOG_FILES = 80
    MAX_ARCHIVE_FILES = 5000
    MAX_EVIDENCE_PER_FINDING = 10
    MAX_PROBLEM_SOURCES = 160
    MAX_PROBLEM_EVIDENCE = 30
    CLOUD_FORENSIC_MAX_INDEX_ENTRIES = 220
    CLOUD_FORENSIC_MAX_SNIPPETS = 36
    CLOUD_FORENSIC_CONTEXT_LINES = 30
    CLOUD_FORENSIC_READ_LIMIT_BYTES = 16 * 1024 * 1024
    CLOUD_FORENSIC_MAX_REQUESTS = 24
    MAX_NESTED_ARCHIVE_DEPTH = 5
    MAX_NESTED_ARCHIVE_MEMBERS = 6000
    MAX_NESTED_TAR_MEMBERS = 6000
    LARGE_TAR_MEMBER_BYTES = 128 * 1024 * 1024
    LARGE_NESTED_ARCHIVE_BYTES = 512 * 1024 * 1024
    NESTED_ARCHIVE_SPOOL_BYTES = 8 * 1024 * 1024
    STATIC_REFERENCE_FILENAMES = EvidenceExtractor.STATIC_REFERENCE_FILENAMES
    STATIC_REFERENCE_PATH_TERMS = EvidenceExtractor.STATIC_REFERENCE_PATH_TERMS
    NOISY_PROBLEM_SOURCE_TERMS = (
        "/commands/vsi_traverse",
        "/json/",
        "python_usrlibvmwarevm-support",
        "device-driver-list",
        "ipmi",
        "usb",
        "pci",
    )

    PATTERNS = (
        {
            "key": "timeout",
            "severity": "中",
            "category": "连接与响应",
            "title": "日志中出现连接超时或响应等待异常",
            "regex": re.compile(r"\b(timeout|timed out|connection refused|connection reset|no route to host)\b", re.I),
            "impact": "可能与管理网络连通性、服务响应或临时资源压力有关。",
            "recommendation": "建议结合问题发生时间检查管理网络连通性、vCenter/ESXi 管理服务状态和相关防火墙策略。",
        },
        {
            "key": "auth",
            "severity": "中",
            "category": "认证与权限",
            "title": "日志中出现认证或权限相关异常",
            "regex": re.compile(r"\b(authentication failed|permission denied|not authorized|invalid login|sso|token)\b", re.I),
            "impact": "可能影响管理登录、自动化任务或组件间调用。",
            "recommendation": "建议复核相关账号权限、SSO 状态和问题时间窗口内的登录失败记录。",
        },
        {
            "key": "storage",
            "severity": "高",
            "category": "存储",
            "title": "日志中出现存储路径、容量或设备访问异常",
            "regex": re.compile(r"\b(apd|pdl|datastore|no space left|out of space|naa\.|scsi|hba|latency)\b", re.I),
            "impact": "可能影响虚拟机 I/O、快照操作或数据存储可用性。",
            "recommendation": "建议结合存储阵列、SAN 交换机和 ESXi 设备路径状态进一步核查。",
        },
        {
            "key": "network",
            "severity": "中",
            "category": "网络",
            "title": "日志中出现网络链路或虚拟交换相关异常",
            "regex": re.compile(r"\b(vmnic|link down|link up|packet loss|dropped|vds|dvport|network unreachable)\b", re.I),
            "impact": "可能影响管理网络、vMotion、存储网络或业务虚拟机通信。",
            "recommendation": "建议结合交换机端口、物理网卡状态和虚拟交换配置进行交叉确认。",
        },
        {
            "key": "service",
            "severity": "高",
            "category": "服务状态",
            "title": "日志中出现 VMware 管理服务异常",
            "regex": re.compile(r"\b(crash|panic|core dump|service.*failed|failed to start|watchdog|backtrace|exception)\b", re.I),
            "impact": "可能导致管理服务不稳定、任务失败或组件功能异常。",
            "recommendation": "建议核对问题时间点的服务重启、core dump 和相关组件版本补丁状态。",
        },
        {
            "key": "certificate",
            "severity": "中",
            "category": "证书",
            "title": "日志中出现证书或 TLS 相关异常",
            "regex": re.compile(r"\b(certificate|ssl|tls|handshake|x509|thumbprint)\b", re.I),
            "impact": "可能影响组件信任关系、管理登录或 API 调用。",
            "recommendation": "建议复核证书有效期、信任链和近期证书替换记录。",
        },
        {
            "key": "snapshot",
            "severity": "中",
            "category": "虚拟机",
            "title": "日志中出现快照或虚拟机操作异常",
            "regex": re.compile(r"\b(snapshot|consolidat|vmdk|disk chain|vmx)\b", re.I),
            "impact": "可能影响虚拟机快照清理、备份恢复或磁盘链一致性。",
            "recommendation": "建议结合备份任务、快照链状态和虚拟机事件进一步分析。",
        },
        {
            "key": "vsan",
            "severity": "高",
            "category": "vSAN",
            "title": "日志中出现 vSAN 相关异常",
            "regex": re.compile(r"\b(vsan|clomd|cmmds|dom owner|absent|degraded)\b", re.I),
            "impact": "可能影响 vSAN 对象健康、组件同步或存储策略合规性。",
            "recommendation": "建议结合 vSAN Skyline Health、对象健康状态和磁盘组状态继续核查。",
        },
    )

    def validate_config(self, config: LogAnalysisConfig) -> list[str]:
        support_bundle_text = str(config.support_bundle_path).strip()
        cfg = config.normalized()
        errors: list[str] = []
        if not support_bundle_text:
            errors.append("请导入 VMware support bundle 日志包。")
        elif not cfg.support_bundle_path.exists():
            errors.append(f"日志包不存在：{cfg.support_bundle_path}")
        elif not cfg.support_bundle_path.is_file():
            errors.append(f"日志包路径不是文件：{cfg.support_bundle_path}")
        elif cfg.support_bundle_path.suffix.lower() != ".zip":
            errors.append("当前版本仅支持 ZIP 格式的 VMware support bundle 日志包。")
        elif not zipfile.is_zipfile(cfg.support_bundle_path):
            errors.append("日志包不是有效的 ZIP 文件。")
        if not cfg.problem_description:
            errors.append("请填写问题描述，便于按现象和时间窗口聚焦分析。")
        if cfg.cloud_assist_enabled:
            if not cfg.cloud_api_url:
                errors.append("启用云端模型辅助分析时，请填写 API 地址。")
            if not cfg.cloud_model_name:
                errors.append("启用云端模型辅助分析时，请填写模型名称。")
            if not cfg.cloud_api_key:
                errors.append("启用云端模型辅助分析时，请填写 API Key。")
        return errors

    def run(
        self,
        config: LogAnalysisConfig,
        progress_callback: Callable[[LogAnalysisProgress], None] | None = None,
    ) -> LogAnalysisResult:
        cfg = config.normalized()
        errors = self.validate_config(cfg)
        if errors:
            raise ValueError("\n".join(errors))

        init_db(cfg.db_path)
        now = utc_now_iso()
        log_run_id = new_id("logrun")
        report_dir = cfg.report_output_dir / f"log-analysis-{log_run_id[-8:]}"
        html_path = report_dir / "index.html"
        docx_path = report_dir / "VStackLens-Log-Analysis-Report.docx"
        bundle_size = cfg.support_bundle_path.stat().st_size if cfg.support_bundle_path.exists() else 0

        LOGGER.info(
            "Log analysis start log_run_id=%s bundle_name=%s bundle_size=%s problem=%s output_dir=%s db_path=%s",
            log_run_id,
            cfg.support_bundle_path.name,
            bundle_size,
            sensitive_text_summary(cfg.problem_description),
            report_dir,
            cfg.db_path,
        )

        try:
            self._emit(progress_callback, log_run_id, "started", 5, "创建日志分析任务")
            self._insert_run_row(cfg, log_run_id, now)
            self._emit(progress_callback, log_run_id, "reading_bundle", 20, "读取 support bundle 文件清单")
            LOGGER.info("Log analysis reading bundle log_run_id=%s", log_run_id)
            payload = self._build_payload(cfg, log_run_id, progress_callback)
            summary = payload.get("summary", {}) if isinstance(payload.get("summary"), dict) else {}
            diagnosis = payload.get("diagnosis", {}) if isinstance(payload.get("diagnosis"), dict) else {}
            LOGGER.info(
                "Log analysis payload ready log_run_id=%s total_files=%s log_files=%s scenario=%s key_evidence=%s",
                log_run_id,
                summary.get("total_files"),
                summary.get("log_files"),
                diagnosis.get("scenario") or "generic",
                diagnosis.get("key_evidence_count") or summary.get("diagnosis_evidence_count") or summary.get("evidence_count"),
            )
            self._emit(progress_callback, log_run_id, "analyzing_logs", 55, "分析日志关键特征")
            report_dir.mkdir(parents=True, exist_ok=True)
            cloud_failure_reason = self._cloud_assist_failure_reason(payload)
            if cloud_failure_reason:
                self._record_cloud_assist_failure(payload, cloud_failure_reason, strict=cfg.cloud_require_accepted_result)
            (report_dir / "log_analysis_payload.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            if isinstance(payload.get("diagnosis"), dict):
                (report_dir / "diagnosis.json").write_text(
                    json.dumps(payload["diagnosis"], ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
            if cloud_failure_reason:
                self._write_model_analysis_failure_debug(report_dir, log_run_id, payload, cloud_failure_reason)
                if cfg.cloud_require_accepted_result:
                    raise LogAnalysisCloudRequiredError(cloud_failure_reason)
            self._emit(progress_callback, log_run_id, "rendering_html", 75, "生成 HTML 日志分析报告")
            LOGGER.info("Log analysis render HTML start log_run_id=%s output_dir=%s", log_run_id, report_dir)
            html_path = render_log_analysis_html(payload, report_dir)
            self._emit(progress_callback, log_run_id, "rendering_docx", 88, "生成 Word 日志分析报告")
            LOGGER.info("Log analysis render Word start log_run_id=%s docx_path=%s", log_run_id, docx_path)
            docx_path = render_log_analysis_docx(payload, docx_path)
            finished_at = utc_now_iso()
            self._mark_run_success(cfg, log_run_id, payload, html_path, docx_path, finished_at)
            LOGGER.info("Log analysis database write success log_run_id=%s", log_run_id)
            self._emit(progress_callback, log_run_id, "success", 100, "日志分析完成")
            return LogAnalysisResult(
                log_run_id=log_run_id,
                report_dir=report_dir,
                html_path=html_path,
                docx_path=docx_path,
                summary=payload.get("summary", {}),
                findings=payload.get("findings", []),
                diagnosis=payload.get("diagnosis", {}),
            )
        except Exception as exc:
            message = f"日志分析失败：{exc}"
            LOGGER.exception("Log analysis failed log_run_id=%s error_type=%s", log_run_id, type(exc).__name__)
            try:
                self._mark_run_failed(cfg, log_run_id, message)
                LOGGER.info("Log analysis failure state written log_run_id=%s", log_run_id)
            except Exception:
                LOGGER.exception("Log analysis failure state write failed log_run_id=%s", log_run_id)
            self._emit(progress_callback, log_run_id, "failed", 100, "日志分析失败", error=message)
            raise

    def _build_payload(
        self,
        cfg: LogAnalysisConfig,
        log_run_id: str,
        progress_callback: Callable[[LogAnalysisProgress], None] | None = None,
    ) -> dict[str, Any]:
        files: list[dict[str, Any]] = []
        evidence_by_key: dict[str, list[dict[str, Any]]] = {str(pattern["key"]): [] for pattern in self.PATTERNS}
        log_file_count = 0
        scanned_log_files = 0
        files_truncated = False
        problem_context = self.diagnosis_engine.prepare(cfg.problem_description)
        problem_profile = problem_context.profile
        scenario = problem_context.scenario
        with zipfile.ZipFile(cfg.support_bundle_path) as zf:
            infos = [item for item in zf.infolist() if not item.is_dir()]
            for info in infos:
                if len(files) >= self.MAX_ARCHIVE_FILES:
                    files_truncated = True
                    break
                if self._is_nested_archive(info.filename):
                    if self._should_skip_large_nested_archive(info, scenario):
                        files_truncated = True
                        files.append(
                            {
                                "path": info.filename,
                                "size": info.file_size,
                                "size_label": self._size_label(info.file_size),
                                "is_log": False,
                            }
                        )
                        continue
                    nested = self._scan_nested_archive(zf, info, files, evidence_by_key, scanned_log_files)
                    log_file_count += nested["log_file_count"]
                    scanned_log_files = nested["scanned_log_files"]
                    files_truncated = files_truncated or nested["files_truncated"]
                    continue
                is_log = self._is_log_file(info.filename)
                if is_log:
                    log_file_count += 1
                    if scanned_log_files < self.MAX_LOG_FILES:
                        text = self._read_zip_text_sample(zf, info)
                        self._collect_evidence(info.filename, text, evidence_by_key)
                        scanned_log_files += 1
                files.append(
                    {
                        "path": info.filename,
                        "size": info.file_size,
                        "size_label": self._size_label(info.file_size),
                        "is_log": is_log,
                    }
                )

        findings = self._findings_from_evidence(evidence_by_key, cfg.problem_description)
        category_counts = Counter(item["category"] for item in findings)
        evidence_count = sum(len(item.get("evidence", [])) for item in findings)
        summary = {
            "total_files": len(files),
            "log_files": log_file_count,
            "evidence_count": evidence_count,
            "finding_count": len(findings),
            "categories": dict(category_counts),
            "files_truncated": files_truncated,
        }
        generated_at = utc_now_iso()
        recommendations = self._recommendations(findings)
        diagnosis = self.diagnosis_engine.diagnose(
            problem_context,
            {
                "snapshot_consolidation_failure": lambda context: self._build_snapshot_diagnosis(
                    cfg.support_bundle_path,
                    context.problem_description,
                    findings,
                ),
                "vm_migration_network_loss": lambda context: self._build_migration_network_diagnosis(
                    cfg.support_bundle_path,
                    context.problem_description,
                    findings,
                    context.profile,
                ),
                "generic_problem_driven_diagnosis": lambda context: self._build_generic_problem_diagnosis(
                    cfg.support_bundle_path,
                    context.problem_description,
                    findings,
                    context.profile,
                ),
            },
        )
        if diagnosis:
            self._apply_cloud_assist(cfg, diagnosis, findings, summary, progress_callback, log_run_id)
        if diagnosis:
            summary["diagnosis_scenario"] = diagnosis.get("scenario")
            summary["diagnosis_title"] = diagnosis.get("title")
            summary["diagnosis_evidence_count"] = diagnosis.get("key_evidence_count", 0)
            diagnosis_log_files = _diagnosis_log_file_count(diagnosis)
            if diagnosis_log_files > 0 and log_file_count <= 0:
                summary["log_files"] = diagnosis_log_files
                summary["diagnosis_log_file_count"] = diagnosis_log_files

        report_title = self._report_title_for_diagnosis(cfg, diagnosis)
        payload = {
            "metadata": {
                "log_run_id": log_run_id,
                "customer_name": cfg.customer_name,
                "report_title": report_title,
                "support_bundle_name": cfg.support_bundle_path.name,
                "support_bundle_display_name": f"<local>\\{cfg.support_bundle_path.name}",
                "support_bundle_path": f"<local>\\{cfg.support_bundle_path.name}",
                "problem_description": cfg.problem_description,
                "generated_at": generated_at,
                "workflow": "standalone_log_analysis",
            },
            "summary": summary,
            "findings": findings,
            "recommendations": recommendations,
            "files": files,
        }
        if diagnosis:
            payload["diagnosis"] = diagnosis
        return self._sanitize_payload_for_reports(payload)

    def _cloud_assist_failure_reason(self, payload: dict[str, Any]) -> str:
        diagnosis = payload.get("diagnosis") if isinstance(payload.get("diagnosis"), dict) else {}
        engine = diagnosis.get("diagnosis_engine") if isinstance(diagnosis.get("diagnosis_engine"), dict) else {}
        if not engine.get("cloud_assist_enabled"):
            return ""
        quality = str(engine.get("model_quality") or "").strip().lower()
        cloud_status = str(engine.get("cloud_status") or "").strip()
        if quality == "accepted" and cloud_status == "accepted":
            return ""

        reason = str(
            engine.get("fallback_reason")
            or engine.get("model_quality_reason")
            or engine.get("cloud_status_label")
            or "未能生成满足质量要求的模型诊断结果。"
        ).strip()
        if quality == "downgraded" or cloud_status == "responded_downgraded":
            return f"大模型分析失败：模型输出未达到客户诊断报告质量要求：{reason}"
        if quality == "rejected" or cloud_status == "responded_rejected" or bool(engine.get("api_response_received")):
            return f"大模型分析失败：云端 API 已响应但输出未通过质量校验：{reason}"
        if quality == "failed" or cloud_status == "request_failed" or bool(engine.get("api_call_attempted")):
            return f"大模型分析失败：云端 API 未调用成功：{reason}"
        return f"大模型分析失败：未能确认云端模型调用状态：{reason}"

    def _record_cloud_assist_failure(self, payload: dict[str, Any], failure_reason: str, *, strict: bool) -> None:
        diagnosis = payload.get("diagnosis") if isinstance(payload.get("diagnosis"), dict) else {}
        engine = diagnosis.get("diagnosis_engine") if isinstance(diagnosis.get("diagnosis_engine"), dict) else {}
        cloud_status = str(engine.get("cloud_status") or "unknown")
        cloud_quality = str(engine.get("model_quality") or "failed")
        metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
        metadata.update(
            {
                "cloud_assist_status": cloud_status,
                "cloud_assist_quality": cloud_quality,
                "cloud_assist_failure_reason": failure_reason,
                "debug_notice": failure_reason,
            }
        )
        if strict:
            metadata.update(
                {
                    "report_title": MODEL_ANALYSIS_FAILURE_TITLE,
                    "analysis_status": "model_analysis_failed",
                    "debug_title": MODEL_ANALYSIS_FAILURE_TITLE,
                }
            )
        else:
            metadata.setdefault("analysis_status", "completed")
        payload["metadata"] = metadata
        summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
        summary["cloud_assist_status"] = cloud_status
        summary["cloud_assist_quality"] = cloud_quality
        summary["cloud_assist_failed"] = True
        summary["cloud_assist_failure_reason"] = failure_reason
        if strict:
            summary["model_analysis_failed"] = True
            summary["model_analysis_failure_reason"] = failure_reason
        payload["summary"] = summary
        if diagnosis:
            diagnosis["cloud_assist_status"] = cloud_status
            diagnosis["cloud_assist_quality"] = cloud_quality
            diagnosis["cloud_assist_failed"] = True
            diagnosis["cloud_assist_failure_reason"] = failure_reason
            if strict:
                diagnosis["model_analysis_failed"] = True
                diagnosis["model_analysis_failure_reason"] = failure_reason
            payload["diagnosis"] = diagnosis

    def _write_model_analysis_failure_debug(
        self,
        report_dir: Path,
        log_run_id: str,
        payload: dict[str, Any],
        failure_reason: str,
    ) -> None:
        diagnosis = payload.get("diagnosis") if isinstance(payload.get("diagnosis"), dict) else {}
        engine = diagnosis.get("diagnosis_engine") if isinstance(diagnosis.get("diagnosis_engine"), dict) else {}
        debug_payload = {
            "title": MODEL_ANALYSIS_FAILURE_TITLE,
            "log_run_id": log_run_id,
            "failure_reason": failure_reason,
            "diagnosis_engine": engine,
            "diagnosis_json": "diagnosis.json",
            "payload_json": "log_analysis_payload.json",
        }
        (report_dir / "model_analysis_failure_debug.json").write_text(
            json.dumps(debug_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def _report_title_for_diagnosis(self, cfg: LogAnalysisConfig, diagnosis: dict[str, Any] | None) -> str:
        if not isinstance(diagnosis, dict):
            return DEFAULT_LOG_CHECK_TITLE
        engine = diagnosis.get("diagnosis_engine") if isinstance(diagnosis.get("diagnosis_engine"), dict) else {}
        report_mode = str(engine.get("customer_report_mode") or "").strip().lower()
        if report_mode == "cloud_assisted":
            return MODEL_ASSISTED_DIAGNOSIS_TITLE
        return DEFAULT_LOG_CHECK_TITLE

    def _apply_cloud_assist(
        self,
        cfg: LogAnalysisConfig,
        diagnosis: dict[str, Any],
        findings: list[dict[str, Any]],
        summary: dict[str, Any],
        progress_callback: Callable[[LogAnalysisProgress], None] | None = None,
        log_run_id: str | None = None,
    ) -> None:
        engine = diagnosis.get("diagnosis_engine") if isinstance(diagnosis.get("diagnosis_engine"), dict) else {}
        engine.update(
            {
                "name": "rule_based_log_diagnosis_with_optional_cloud",
                "mode": "rule_based",
                "model_used": False,
                "model_source": "rule_only",
                "cloud_provider": cfg.cloud_provider,
                "model_name": cfg.cloud_model_name,
                "model_protocol": MODEL_PROTOCOL,
                "model_quality": "",
                "model_quality_reason": "",
                "fallback_reason": "",
                "cloud_assist_enabled": bool(cfg.cloud_assist_enabled),
                "customer_report_mode": "rule_based",
                "api_call_attempted": False,
                "api_response_received": False,
                "cloud_status": "not_enabled" if not cfg.cloud_assist_enabled else "not_called",
                "cloud_status_label": "未启用云端模型" if not cfg.cloud_assist_enabled else "已启用云端模型，尚未发起调用",
            }
        )
        diagnosis["diagnosis_engine"] = engine

        if not cfg.cloud_assist_enabled:
            return

        cloud_config = CloudModelConfig(
            provider=cfg.cloud_provider,
            api_url=cfg.cloud_api_url,
            model_name=cfg.cloud_model_name,
            api_key=cfg.cloud_api_key,
            timeout_seconds=cfg.cloud_timeout_seconds,
        )
        forensic = self._build_cloud_forensic_material(cfg.support_bundle_path, cfg.problem_description, diagnosis, findings, summary)
        planning_prompt = self._build_cloud_forensic_planning_prompt(cfg, diagnosis, forensic)
        client = CloudModelClient(cloud_config)
        self._emit(progress_callback, log_run_id, "cloud_planning", 60, "正在调用云端模型规划日志取证范围")
        LOGGER.info(
            "Cloud forensic planning requested provider=%s model=%s scenario=%s prompt=%s",
            cloud_config.provider,
            cloud_config.model_name,
            diagnosis.get("scenario"),
            sensitive_text_summary(planning_prompt),
        )
        plan_result = client.complete_json(planning_prompt)
        if not plan_result.ok or not plan_result.content:
            fallback_reason = sanitize_cloud_error(plan_result.fallback_reason, cfg.cloud_api_key)
            response_received = bool(getattr(plan_result, "response_received", False))
            engine.update(
                {
                    "mode": "cloud_rejected" if response_received else "rule_based",
                    "model_used": response_received,
                    "model_source": "cloud" if response_received else "rule_only",
                    "cloud_provider": cloud_config.provider,
                    "model_name": cloud_config.model_name,
                    "model_protocol": MODEL_PROTOCOL,
                    "model_quality": "rejected" if response_received else "failed",
                    "model_quality_reason": fallback_reason,
                    "fallback_reason": fallback_reason,
                    "api_call_attempted": True,
                    "api_response_received": response_received,
                    "customer_report_mode": "rule_based",
                    "cloud_status": "responded_rejected" if response_received else "request_failed",
                    "cloud_status_label": "云端 API 已响应，但取证规划输出不可用" if response_received else "云端 API 未调用成功",
                }
            )
            diagnosis["diagnosis_engine"] = engine
            LOGGER.warning(
                "Cloud forensic planning failed provider=%s model=%s scenario=%s reason=%s",
                cloud_config.provider,
                cloud_config.model_name,
                diagnosis.get("scenario"),
                fallback_reason,
            )
            return

        requests = self._extract_cloud_forensic_requests(plan_result.content, forensic)
        snippets = self._extract_cloud_requested_snippets(cfg.support_bundle_path, requests, forensic)
        final_prompt = self._build_cloud_forensic_diagnosis_prompt(cfg, diagnosis, forensic, requests, snippets)
        self._emit(progress_callback, log_run_id, "cloud_diagnosing", 68, "正在调用云端模型进行日志判断")
        LOGGER.info(
            "Cloud log diagnosis requested provider=%s model=%s scenario=%s snippets=%s prompt=%s",
            cloud_config.provider,
            cloud_config.model_name,
            diagnosis.get("scenario"),
            len(snippets),
            sensitive_text_summary(final_prompt),
        )
        result = client.diagnose(final_prompt)
        if result.ok and result.content:
            quality = self._evaluate_cloud_diagnosis(cfg, diagnosis, result.content, forensic=forensic, snippets=snippets)
            response_received = bool(getattr(result, "response_received", False) or result.ok)
            if quality["quality"] == "accepted":
                self._merge_cloud_diagnosis(diagnosis, quality["content"], quality["quality"])
            self._record_cloud_output_metadata(diagnosis, quality["content"])
            diagnosis["cloud_forensic_rounds"] = 2
            diagnosis["cloud_requested_evidence"] = self._sanitize_payload_for_reports(requests)
            diagnosis["cloud_extracted_evidence"] = self._sanitize_payload_for_reports(snippets[: self.CLOUD_FORENSIC_MAX_SNIPPETS])
            diagnosis["candidate_strong_evidence"] = forensic.get("candidate_strong_evidence", [])
            diagnosis["analysis_scope"] = forensic.get("analysis_scope", {})
            engine.update(
                {
                    "mode": "cloud_assisted" if quality["quality"] == "accepted" else "cloud_triage" if quality["quality"] == "downgraded" else "cloud_rejected",
                    "model_used": True,
                    "model_source": "cloud",
                    "cloud_provider": cloud_config.provider,
                    "model_name": cloud_config.model_name,
                    "model_protocol": MODEL_PROTOCOL,
                    "model_quality": quality["quality"],
                    "model_quality_reason": quality["reason"],
                    "fallback_reason": "" if quality["quality"] != "rejected" else quality["reason"],
                    "api_call_attempted": True,
                    "api_response_received": response_received,
                    "customer_report_mode": "cloud_assisted" if quality["quality"] == "accepted" else "rule_based",
                    "cloud_status": {
                        "accepted": "accepted",
                        "downgraded": "responded_downgraded",
                        "rejected": "responded_rejected",
                    }.get(quality["quality"], "responded_rejected"),
                    "cloud_status_label": {
                        "accepted": "云端 API 已响应并被接受",
                        "downgraded": "云端 API 已响应，已降级为模型辅助粗排查",
                        "rejected": "云端 API 已响应，但模型输出未通过质量门禁",
                    }.get(quality["quality"], "云端 API 已响应，但模型输出未通过质量门禁"),
                }
            )
            diagnosis["diagnosis_engine"] = engine
            LOGGER.info(
                "Cloud log diagnosis completed provider=%s model=%s scenario=%s quality=%s reason=%s elapsed_ms=%s",
                cloud_config.provider,
                cloud_config.model_name,
                diagnosis.get("scenario"),
                quality["quality"],
                quality["reason"],
                result.elapsed_ms,
            )
            return

        fallback_reason = sanitize_cloud_error(result.fallback_reason, cfg.cloud_api_key)
        response_received = bool(getattr(result, "response_received", False))
        engine.update(
            {
                "mode": "cloud_rejected" if response_received else "rule_based",
                "model_used": response_received,
                "model_source": "cloud" if response_received else "rule_only",
                "cloud_provider": cloud_config.provider,
                "model_name": cloud_config.model_name,
                "model_protocol": MODEL_PROTOCOL,
                "model_quality": "rejected" if response_received else "failed",
                "model_quality_reason": fallback_reason,
                "fallback_reason": fallback_reason,
                "api_call_attempted": True,
                "api_response_received": response_received,
                "customer_report_mode": "rule_based",
                "cloud_status": "responded_rejected" if response_received else "request_failed",
                "cloud_status_label": "云端 API 已响应，但模型输出未通过质量门禁" if response_received else "云端 API 未调用成功",
            }
        )
        diagnosis["diagnosis_engine"] = engine
        LOGGER.warning(
            "Cloud log diagnosis failed provider=%s model=%s scenario=%s reason=%s",
            cloud_config.provider,
            cloud_config.model_name,
            diagnosis.get("scenario"),
            fallback_reason,
        )

    def _build_cloud_forensic_material(
        self,
        support_bundle_path: Path,
        problem_description: str,
        diagnosis: dict[str, Any],
        findings: list[dict[str, Any]],
        summary: dict[str, Any],
    ) -> dict[str, Any]:
        problem_profile = diagnosis.get("problem_profile") if isinstance(diagnosis.get("problem_profile"), dict) else {}
        keywords = self._cloud_forensic_keywords(problem_description, problem_profile)
        stats: dict[str, Any] = {
            "total_files_seen": 0,
            "eligible_files_seen": 0,
            "indexed_files": 0,
            "log_files_indexed": 0,
            "snippets_limit": self.CLOUD_FORENSIC_MAX_SNIPPETS,
            "context_lines": self.CLOUD_FORENSIC_CONTEXT_LINES,
            "read_limit_bytes": self.CLOUD_FORENSIC_READ_LIMIT_BYTES,
            "truncated": False,
        }
        sources: list[dict[str, Any]] = []
        try:
            with zipfile.ZipFile(support_bundle_path) as zf:
                self._collect_cloud_forensic_from_zip(zf, "", keywords, sources, stats)
        except (OSError, zipfile.BadZipFile):
            stats["truncated"] = True

        sources = self._rank_cloud_sources(sources)
        prompt_sources = sources[: self.CLOUD_FORENSIC_MAX_INDEX_ENTRIES]
        index = [self._cloud_index_entry(source) for source in prompt_sources]
        stats["indexed_files"] = len(index)
        stats["log_files_indexed"] = sum(1 for item in index if item.get("is_log"))

        candidate_strong_evidence = self._cloud_candidate_strong_evidence(sources)
        local_rule_evidence = self._cloud_local_candidate_evidence(diagnosis, findings)
        analysis_scope = {
            "support_bundle_name": support_bundle_path.name,
            "total_files": summary.get("total_files"),
            "log_files": summary.get("log_files"),
            "files_truncated": bool(summary.get("files_truncated") or stats.get("truncated")),
            "indexed_files": len(index),
            "eligible_files_seen": stats.get("eligible_files_seen"),
            "scan_limits": {
                "max_index_entries": self.CLOUD_FORENSIC_MAX_INDEX_ENTRIES,
                "max_requests": self.CLOUD_FORENSIC_MAX_REQUESTS,
                "max_snippets": self.CLOUD_FORENSIC_MAX_SNIPPETS,
                "context_lines": self.CLOUD_FORENSIC_CONTEXT_LINES,
                "read_limit_bytes": self.CLOUD_FORENSIC_READ_LIMIT_BYTES,
            },
        }
        return {
            "index": index,
            "sources": sources,
            "keywords": keywords,
            "candidate_strong_evidence": candidate_strong_evidence,
            "local_rule_candidate_evidence": local_rule_evidence,
            "analysis_scope": analysis_scope,
        }

    def _build_cloud_forensic_planning_prompt(
        self,
        cfg: LogAnalysisConfig,
        diagnosis: dict[str, Any],
        forensic: dict[str, Any],
    ) -> str:
        prompt_payload = {
            "customer_problem": cfg.problem_description,
            "scenario": diagnosis.get("scenario"),
            "problem_profile": diagnosis.get("problem_profile") or {},
            "analysis_scope": forensic.get("analysis_scope") or {},
            "log_directory_index": forensic.get("index") or [],
            "initial_keywords": forensic.get("keywords") or [],
            "candidate_strong_evidence": forensic.get("candidate_strong_evidence") or [],
            "local_rule_candidate_evidence": forensic.get("local_rule_candidate_evidence") or [],
            "output_schema": {
                "requests": [
                    {
                        "file": "建议查看的日志文件路径，可为空",
                        "component": "vmkernel / hostd / vpxa / vpxd / vmware.log / net-dvs / esxcli network / vsan / storage 等",
                        "keywords": ["需要检索的关键词"],
                        "time_window": "可选时间窗口",
                        "context_lines": "建议上下文行数，默认由本地限制控制",
                        "reason": "为什么需要该日志片段",
                    }
                ],
                "stop_reason": "如果当前目录索引已足够或证据不足，请说明需要补充哪些材料。",
            },
        }
        text = json.dumps(self._sanitize_payload_for_reports(prompt_payload), ensure_ascii=False, indent=2)
        instructions = """
你正在执行 VMware support bundle 的模型驱动取证规划，不是报告润色。
请先阅读客户问题、日志目录索引、初步关键词摘要和本地规则候选线索，然后返回下一步需要查看的日志文件、关键词、时间窗口或上下文范围。
网络问题不要只看 net-dvs 输出；应优先考虑 vmkernel、vmkwarning、hostd、vpxa、vpxd、syslog、vmware.log、DVS/portgroup/uplink/VLAN/MTU/teaming/failover 相关日志或配置。
如果候选线索中存在 ARP/IP 冲突、虚拟网卡断开/重连、vMotion/migrate/relocate、dvPort/portgroup/VLAN/uplink 异常，请围绕这些线索请求补充片段。
只输出 JSON 对象，不要 Markdown，不要包含 API Key、本机绝对路径、源码路径、Python 路径或 SQLite 路径。
""".strip()
        return _sanitize_report_text(f"{instructions}\n\n输入材料：\n{text}")

    def _extract_cloud_forensic_requests(self, plan: dict[str, Any], forensic: dict[str, Any]) -> list[dict[str, Any]]:
        raw_items: list[Any] = []
        for key in ("requests", "evidence_requests", "log_requests", "requested_logs", "files"):
            value = plan.get(key) if isinstance(plan, dict) else None
            if isinstance(value, list):
                raw_items.extend(value)
            elif isinstance(value, dict):
                raw_items.extend(value.values())
            elif isinstance(value, str) and value.strip():
                raw_items.append(value)

        requests: list[dict[str, Any]] = []
        for item in raw_items:
            request = self._normalize_cloud_request(item)
            if request:
                requests.append(request)
            if len(requests) >= self.CLOUD_FORENSIC_MAX_REQUESTS:
                break

        if not requests:
            requests = self._default_cloud_forensic_requests(forensic)

        deduped: list[dict[str, Any]] = []
        seen: set[tuple[str, str, tuple[str, ...]]] = set()
        for request in requests:
            keywords = tuple(sorted(str(item).lower() for item in request.get("keywords") or [] if str(item).strip()))
            key = (str(request.get("file") or "").lower(), str(request.get("component") or "").lower(), keywords)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(request)
            if len(deduped) >= self.CLOUD_FORENSIC_MAX_REQUESTS:
                break
        return deduped

    def _extract_cloud_requested_snippets(
        self,
        support_bundle_path: Path,
        requests: list[dict[str, Any]],
        forensic: dict[str, Any],
    ) -> list[dict[str, Any]]:
        del support_bundle_path
        sources = [item for item in forensic.get("sources") or [] if isinstance(item, dict)]
        snippets: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        for request in requests[: self.CLOUD_FORENSIC_MAX_REQUESTS]:
            matched_sources = self._match_cloud_request_sources(request, sources)
            for source in matched_sources:
                for snippet in self._cloud_snippets_from_source(source, request):
                    key = (
                        str(snippet.get("file") or ""),
                        str(snippet.get("location") or ""),
                        str(snippet.get("message") or "")[:160],
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    snippets.append(snippet)
                    if len(snippets) >= self.CLOUD_FORENSIC_MAX_SNIPPETS:
                        return snippets
        if not snippets:
            for request in self._default_cloud_forensic_requests(forensic):
                for source in self._match_cloud_request_sources(request, sources):
                    for snippet in self._cloud_snippets_from_source(source, request):
                        key = (
                            str(snippet.get("file") or ""),
                            str(snippet.get("location") or ""),
                            str(snippet.get("message") or "")[:160],
                        )
                        if key in seen:
                            continue
                        seen.add(key)
                        snippets.append(snippet)
                        if len(snippets) >= self.CLOUD_FORENSIC_MAX_SNIPPETS:
                            return snippets
        return snippets

    def _build_cloud_forensic_diagnosis_prompt(
        self,
        cfg: LogAnalysisConfig,
        diagnosis: dict[str, Any],
        forensic: dict[str, Any],
        requests: list[dict[str, Any]],
        snippets: list[dict[str, Any]],
    ) -> str:
        prompt_payload = {
            "customer_problem": cfg.problem_description,
            "scenario": diagnosis.get("scenario"),
            "problem_profile": diagnosis.get("problem_profile") or {},
            "rule_based_boundary": {
                "current_judgement": diagnosis.get("current_judgement") or diagnosis.get("conclusion"),
                "confidence": diagnosis.get("confidence"),
                "can_confirm": diagnosis.get("what_can_be_confirmed") or diagnosis.get("confirmed_items"),
                "cannot_confirm": diagnosis.get("what_cannot_be_confirmed") or diagnosis.get("cannot_confirm_items"),
                "missing_materials": diagnosis.get("missing_materials") or diagnosis.get("supplemental_info"),
            },
            "analysis_scope": forensic.get("analysis_scope") or {},
            "candidate_strong_evidence": forensic.get("candidate_strong_evidence") or [],
            "model_requested_evidence": requests,
            "extracted_log_snippets": snippets[: self.CLOUD_FORENSIC_MAX_SNIPPETS],
            "output_schema": {
                "mode": "diagnosis 或 triage。证据不足必须输出 triage。",
                "can_determine_root_cause": "true 或 false。不能仅凭推测写 true。",
                "confidence": "高/中/低",
                "current_judgement": "先说能确认的日志事实，再说明与客户问题的关系，再说更倾向的排查方向，最后说明 support bundle 的判断边界。",
                "most_likely_cause": "如果不能确认根因，请写保守排查方向或空字符串。",
                "likely_causes": ["可能原因方向"],
                "evidence_chain": [
                    {
                        "strength": "强/中/弱",
                        "file": "日志文件",
                        "location": "位置或行号",
                        "message": "日志摘录",
                        "relevance": "该证据如何支撑或限制判断",
                    }
                ],
                "evidence_reasoning": ["证据链解释"],
                "can_confirm": ["当前能够确认"],
                "cannot_confirm": ["当前不能确认"],
                "missing_materials": ["需要客户补充的信息"],
                "recommended_actions": ["建议处理方向"],
                "evidence_quality": "strong / medium / weak / insufficient",
                "overclaiming_risk": "说明过度判断风险",
            },
        }
        text = json.dumps(self._sanitize_payload_for_reports(prompt_payload), ensure_ascii=False, indent=2)
        instructions = """
你是 VMware support bundle 日志诊断辅助判断器，不是报告润色器。
你必须基于提取日志片段和候选强证据做判断，不能编造日志中不存在的对象、时间、错误、动作或根因。
请区分强证据、中证据和弱证据，并解释这些证据能支持什么、不能支持什么。
如果证据不足，输出 mode=triage，明确不能仅凭当前 support bundle 确认最终根因，并列出缺失材料。
如果输出 mode=diagnosis，必须引用具体日志证据。每条 evidence_chain 必须包含 file、location、message、relevance。
如果客户问题是网络类，且候选强证据中存在 ARP/IP 冲突，请不要忽略该证据；需要说明 vmk、IP、MAC、主机和重复次数能支持什么、不能支持什么。
不要使用绝对化措辞，不要写“已经确认根因”除非证据链完整。不要输出“AI 根因分析”“大模型判断”。
不要输出 API Key、Authorization、Bearer token、token、password、cookie、session、本机绝对路径、源码路径、Python 路径或 SQLite 路径。
只输出一个 JSON 对象，不要 Markdown，不要解释性前后缀。
""".strip()
        return _sanitize_report_text(f"{instructions}\n\n输入材料：\n{text}")

    def _collect_cloud_forensic_from_zip(
        self,
        zf: zipfile.ZipFile,
        prefix: str,
        keywords: list[str],
        sources: list[dict[str, Any]],
        stats: dict[str, Any],
        depth: int = 0,
    ) -> None:
        if depth >= self.MAX_NESTED_ARCHIVE_DEPTH:
            stats["truncated"] = True
            return
        for info in zf.infolist():
            if stats.get("total_files_seen", 0) >= self.MAX_ARCHIVE_FILES:
                stats["truncated"] = True
                return
            if info.is_dir():
                continue
            stats["total_files_seen"] = int(stats.get("total_files_seen", 0)) + 1
            display_path = f"{prefix}{info.filename}"
            lower_name = info.filename.lower()
            if self._is_nested_archive(info.filename):
                try:
                    if lower_name.endswith(".zip"):
                        with self._open_nested_zipfile(zf, info) as nested_zip:
                            self._collect_cloud_forensic_from_zip(nested_zip, f"{display_path}!", keywords, sources, stats, depth=depth + 1)
                    else:
                        with zf.open(info) as nested_stream:
                            self._collect_cloud_forensic_from_tar(nested_stream, f"{display_path}!", keywords, sources, stats)
                except (OSError, zipfile.BadZipFile, tarfile.TarError, _NestedArchiveLimitError):
                    stats["truncated"] = True
                    continue
                continue
            self._add_cloud_forensic_source(display_path, info.file_size, keywords, sources, stats, lambda: self._read_cloud_zip_text(zf, info))

    def _collect_cloud_forensic_from_tar(
        self,
        stream: Any,
        prefix: str,
        keywords: list[str],
        sources: list[dict[str, Any]],
        stats: dict[str, Any],
    ) -> None:
        with tarfile.open(fileobj=stream, mode="r|*") as tar:
            for visited, member in enumerate(tar, start=1):
                if visited > self.MAX_NESTED_ARCHIVE_MEMBERS:
                    stats["truncated"] = True
                    return
                if not member.isfile():
                    continue
                stats["total_files_seen"] = int(stats.get("total_files_seen", 0)) + 1
                display_path = f"{prefix}{member.name}"

                def read_member() -> str:
                    return self._read_tar_member_text(tar, member, self.CLOUD_FORENSIC_READ_LIMIT_BYTES)

                self._add_cloud_forensic_source(display_path, member.size, keywords, sources, stats, read_member)

    def _add_cloud_forensic_source(
        self,
        display_path: str,
        size: int,
        keywords: list[str],
        sources: list[dict[str, Any]],
        stats: dict[str, Any],
        read_text: Callable[[], str],
    ) -> None:
        component = self._cloud_component(display_path)
        is_log = self._is_log_file(display_path)
        if not component and not is_log:
            return
        if self._is_reference_material_file(display_path):
            return
        stats["eligible_files_seen"] = int(stats.get("eligible_files_seen", 0)) + 1
        if size > self.CLOUD_FORENSIC_READ_LIMIT_BYTES and component not in {"vmkernel", "vmkwarning", "hostd", "vpxa", "vpxd"}:
            text = ""
            truncated = True
        else:
            text = _redact_sensitive_log_text(read_text())
            truncated = size > self.CLOUD_FORENSIC_READ_LIMIT_BYTES
        if not text and len(sources) >= self.CLOUD_FORENSIC_MAX_INDEX_ENTRIES:
            return
        entry = {
            "path": self._customer_log_path(display_path),
            "archive_path": display_path,
            "name": Path(display_path.replace("\\", "/")).name,
            "size": size,
            "size_label": self._size_label(size),
            "component": component or "text",
            "is_log": is_log,
            "host": self._infer_host_from_path(display_path),
            "host_management_ip": self._infer_ip_from_path(display_path),
            "time_range": self._cloud_time_range(text),
            "keyword_hits": self._cloud_keyword_hits(text, keywords),
            "text": text,
            "truncated": truncated,
        }
        entry["keyword_total"] = sum(int(value) for value in entry["keyword_hits"].values())
        entry["has_arp_conflict"] = bool(_ARP_IP_CONFLICT_RE.search(text))
        sources.append(entry)

    def _read_cloud_zip_text(self, zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> str:
        with zf.open(info) as fh:
            return self._decode_text(fh.read(min(info.file_size, self.CLOUD_FORENSIC_READ_LIMIT_BYTES)))

    def _cloud_component(self, path: str) -> str:
        lower_path = path.lower().replace("\\", "/")
        name = Path(lower_path).name
        if name.startswith("vmkernel") or "/vmkernel" in lower_path:
            return "vmkernel"
        if name.startswith("vmkwarning") or "/vmkwarning" in lower_path:
            return "vmkwarning"
        if name.startswith("hostd") or "/hostd" in lower_path:
            return "hostd"
        if name.startswith("vpxa") or "/vpxa" in lower_path:
            return "vpxa"
        if name.startswith("vpxd") or "/vpxd" in lower_path:
            return "vpxd"
        if name.startswith("syslog") or name == "messages" or "/syslog" in lower_path:
            return "syslog"
        if name.startswith("vmware") and ".log" in name:
            return "vmware.log"
        if "net-dvs" in lower_path or "net_dvs" in lower_path:
            return "net-dvs"
        if "esxcli" in lower_path and "network" in lower_path:
            return "esxcli network"
        if any(term in lower_path for term in ("vmnic", "uplink", "portgroup", "dvport", "vlan", "teaming", "failover")):
            return "network"
        if any(term in lower_path for term in ("vsan", "clomd", "cmmds", "dom")):
            return "vSAN"
        if any(term in lower_path for term in ("snapshot", "vmdk", "vmx", "vmsd")):
            return "snapshot"
        if any(term in lower_path for term in ("storage", "scsi", "naa", "hba", "datastore")):
            return "storage"
        return ""

    def _cloud_forensic_keywords(self, problem_description: str, problem_profile: dict[str, Any]) -> list[str]:
        keywords = [
            "arp",
            "duplicate",
            "using my IP address",
            "vmk",
            "vmnic",
            "link down",
            "link up",
            "disconnected",
            "disconnect",
            "timeout",
            "dropped",
            "VLAN",
            "portgroup",
            "dvPort",
            "uplink",
            "migrate",
            "migration",
            "vmotion",
            "relocate",
            "reconfigure",
            "connectable",
            "backing",
        ]
        for value in list(problem_profile.get("objects") or []) + list(problem_profile.get("actions") or []) + list(problem_profile.get("symptoms") or []):
            text = str(value).strip()
            if text:
                keywords.append(text)
        keywords.extend(re.findall(r"[A-Za-z0-9_.:-]{3,}", problem_description))
        return list(dict.fromkeys(keyword for keyword in keywords if keyword))

    def _cloud_keyword_hits(self, text: str, keywords: list[str]) -> dict[str, int]:
        if not text:
            return {}
        lower = text.lower()
        hits: dict[str, int] = {}
        for keyword in keywords:
            key = str(keyword).strip()
            if not key:
                continue
            count = lower.count(key.lower())
            if count > 0:
                hits[key] = min(count, 9999)
            if len(hits) >= 12:
                break
        return hits

    def _cloud_time_range(self, text: str) -> dict[str, str]:
        if not text:
            return {}
        matches = re.findall(r"\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b", text)
        if not matches:
            matches = re.findall(r"\b\d{4}-\d{2}-\d{2}\b", text)
        if not matches:
            return {}
        return {"first": matches[0], "last": matches[-1]}

    def _rank_cloud_sources(self, sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
        def score(item: dict[str, Any]) -> tuple[int, int, int, str]:
            component = str(item.get("component") or "")
            priority = {
                "vmkernel": 0,
                "vmkwarning": 1,
                "hostd": 2,
                "vpxa": 3,
                "vpxd": 4,
                "vmware.log": 5,
                "syslog": 6,
                "esxcli network": 7,
                "net-dvs": 8,
                "network": 9,
            }.get(component, 20)
            keyword_total = int(item.get("keyword_total") or 0)
            has_arp = 0 if item.get("has_arp_conflict") else 1
            return (has_arp, priority, -keyword_total, str(item.get("path") or ""))

        return sorted(sources, key=score)

    def _cloud_index_entry(self, source: dict[str, Any]) -> dict[str, Any]:
        return {
            "file": source.get("path"),
            "name": source.get("name"),
            "size": source.get("size"),
            "size_label": source.get("size_label"),
            "file_type": source.get("component"),
            "component": source.get("component"),
            "is_log": source.get("is_log"),
            "host": source.get("host"),
            "host_management_ip": source.get("host_management_ip"),
            "time_range": source.get("time_range"),
            "keyword_hits": source.get("keyword_hits"),
            "truncated": source.get("truncated"),
        }

    def _cloud_candidate_strong_evidence(self, sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
        aggregated: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        for source in sources:
            file_path = str(source.get("path") or "")
            if self._is_reference_material_file(file_path):
                continue
            text = str(source.get("text") or "")
            for line_no, line in enumerate(text.splitlines(), start=1):
                match = _ARP_IP_CONFLICT_RE.search(line)
                if not match:
                    continue
                vmk = match.group("vmk")
                ip = match.group("ip")
                mac = match.group("mac").lower()
                host = str(source.get("host") or "") or self._infer_host_from_path(str(source.get("archive_path") or ""))
                key = (host, vmk, ip, mac)
                item = aggregated.setdefault(
                    key,
                    {
                        "type": "ARP/IP 冲突",
                        "strength": "强",
                        "host": host or "当前日志包未明确识别",
                        "host_management_ip": source.get("host_management_ip") or self._infer_ip_from_path(str(source.get("archive_path") or "")),
                        "vmkernel_interface": vmk,
                        "conflict_ip": ip,
                        "conflict_mac": mac,
                        "count": 0,
                        "files": [],
                        "examples": [],
                        "summary": "",
                    },
                )
                item["count"] = int(item.get("count") or 0) + 1
                if file_path not in item["files"]:
                    item["files"].append(file_path)
                if len(item["examples"]) < 5:
                    item["examples"].append(
                        {
                            "file": file_path,
                            "location": f"line {line_no}",
                            "message": self._trim_line(line, limit=360),
                            "relevance": "VMkernel 层面检测到本机 VMkernel IP 被其他 MAC 使用，属于 ARP/IP 冲突强候选线索。",
                            "strength": "强",
                        }
                    )
        results: list[dict[str, Any]] = []
        for item in aggregated.values():
            item["summary"] = (
                f"主机 {item.get('host')} 的 {item.get('vmkernel_interface')} 接口检测到 IP {item.get('conflict_ip')} "
                f"被 MAC {item.get('conflict_mac')} 使用，出现 {item.get('count')} 次。"
            )
            results.append(item)
        return sorted(results, key=lambda item: int(item.get("count") or 0), reverse=True)[:10]

    def _cloud_local_candidate_evidence(self, diagnosis: dict[str, Any], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for item in diagnosis.get("evidence_chain") or []:
            if isinstance(item, dict) and not self._is_reference_material_file(str(item.get("file") or "")):
                rows.append(
                    {
                        "strength": item.get("strength") or item.get("level"),
                        "file": item.get("file"),
                        "location": item.get("location"),
                        "message": item.get("message"),
                        "relevance": item.get("relevance"),
                    }
                )
            if len(rows) >= 12:
                return rows
        for finding in findings[:6]:
            for evidence in finding.get("evidence") or []:
                if not isinstance(evidence, dict) or self._is_reference_material_file(str(evidence.get("file") or "")):
                    continue
                rows.append(
                    {
                        "strength": evidence.get("strength") or evidence.get("level") or finding.get("severity"),
                        "file": evidence.get("file"),
                        "location": evidence.get("location"),
                        "message": evidence.get("message"),
                        "relevance": finding.get("title"),
                    }
                )
                if len(rows) >= 12:
                    return rows
        return rows

    def _normalize_cloud_request(self, item: Any) -> dict[str, Any] | None:
        if isinstance(item, str):
            text = item.strip()
            if not text:
                return None
            return {"file": text, "component": "", "keywords": [], "time_window": "", "context_lines": self.CLOUD_FORENSIC_CONTEXT_LINES, "reason": "模型请求查看该文件。"}
        if not isinstance(item, dict):
            return None
        keywords: list[str] = []
        for key in ("keywords", "keyword", "terms", "search_terms"):
            value = item.get(key)
            if isinstance(value, list):
                keywords.extend(str(term).strip() for term in value if str(term).strip())
            elif isinstance(value, str) and value.strip():
                keywords.extend(part.strip() for part in re.split(r"[,，;；\n]", value) if part.strip())
        file_value = str(item.get("file") or item.get("path") or item.get("log_file") or "").strip()
        component = str(item.get("component") or item.get("file_type") or "").strip()
        if not file_value and not component and not keywords:
            return None
        return {
            "file": _sanitize_report_text(file_value),
            "component": _sanitize_report_text(component),
            "keywords": list(dict.fromkeys(_sanitize_report_text(keyword) for keyword in keywords if keyword)),
            "time_window": _sanitize_report_text(str(item.get("time_window") or item.get("time") or "").strip()),
            "context_lines": min(50, max(5, _safe_int(item.get("context_lines") or self.CLOUD_FORENSIC_CONTEXT_LINES))),
            "reason": _sanitize_report_text(str(item.get("reason") or "").strip()),
        }

    def _default_cloud_forensic_requests(self, forensic: dict[str, Any]) -> list[dict[str, Any]]:
        requests: list[dict[str, Any]] = []
        for candidate in forensic.get("candidate_strong_evidence") or []:
            if not isinstance(candidate, dict):
                continue
            keywords = [
                "arp",
                "using my IP address",
                str(candidate.get("vmkernel_interface") or ""),
                str(candidate.get("conflict_ip") or ""),
                str(candidate.get("conflict_mac") or ""),
            ]
            for file_path in candidate.get("files") or []:
                requests.append(
                    {
                        "file": file_path,
                        "component": "vmkernel",
                        "keywords": [item for item in keywords if item],
                        "time_window": "",
                        "context_lines": self.CLOUD_FORENSIC_CONTEXT_LINES,
                        "reason": "候选强证据显示该日志中存在 ARP/IP 冲突线索。",
                    }
                )
        default_keywords = list(forensic.get("keywords") or [])[:16]
        for item in forensic.get("index") or []:
            if not isinstance(item, dict):
                continue
            component = str(item.get("component") or "")
            if component not in {"vmkernel", "vmkwarning", "hostd", "vpxa", "vpxd", "vmware.log", "syslog", "esxcli network", "network", "net-dvs"}:
                continue
            requests.append(
                {
                    "file": item.get("file"),
                    "component": component,
                    "keywords": default_keywords,
                    "time_window": "",
                    "context_lines": self.CLOUD_FORENSIC_CONTEXT_LINES,
                    "reason": "按客户问题和日志索引补充关键组件上下文。",
                }
            )
            if len(requests) >= self.CLOUD_FORENSIC_MAX_REQUESTS:
                break
        return requests[: self.CLOUD_FORENSIC_MAX_REQUESTS]

    def _match_cloud_request_sources(self, request: dict[str, Any], sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
        file_filter = str(request.get("file") or "").lower().replace("\\", "/")
        component_filter = str(request.get("component") or "").lower()
        keyword_filters = [str(item).lower() for item in request.get("keywords") or [] if str(item).strip()]
        matched: list[dict[str, Any]] = []
        for source in sources:
            path = str(source.get("path") or "").lower().replace("\\", "/")
            archive_path = str(source.get("archive_path") or "").lower().replace("\\", "/")
            component = str(source.get("component") or "").lower()
            text = str(source.get("text") or "").lower()
            if file_filter and file_filter not in path and file_filter not in archive_path and Path(file_filter).name not in path:
                continue
            if component_filter and component_filter not in component and component not in component_filter:
                continue
            if not file_filter and not component_filter and keyword_filters and not any(keyword in text or keyword in path for keyword in keyword_filters):
                continue
            if text:
                matched.append(source)
            if len(matched) >= 8:
                break
        return matched

    def _cloud_snippets_from_source(self, source: dict[str, Any], request: dict[str, Any]) -> list[dict[str, Any]]:
        text = str(source.get("text") or "")
        if not text:
            return []
        keywords = [str(item).strip() for item in request.get("keywords") or [] if str(item).strip()]
        if not keywords:
            keywords = list((source.get("keyword_hits") or {}).keys())[:8]
        if not keywords:
            keywords = ["error", "failed", "warning", "disconnect", "timeout", "arp"]
        regexes = [re.compile(re.escape(keyword), re.I) for keyword in keywords if keyword]
        context_lines = min(50, max(5, _safe_int(request.get("context_lines") or self.CLOUD_FORENSIC_CONTEXT_LINES)))
        lines = text.splitlines()
        snippets: list[dict[str, Any]] = []
        for index, line in enumerate(lines):
            if not line.strip():
                continue
            if regexes and not any(regex.search(line) for regex in regexes):
                continue
            start = max(0, index - context_lines)
            end = min(len(lines), index + context_lines + 1)
            excerpt_lines = [self._trim_line(item, limit=260) for item in lines[start:end] if item.strip()]
            message = "\n".join(excerpt_lines)
            if len(message) > 1800:
                message = message[:1799] + "…"
            snippets.append(
                {
                    "strength": "强" if _ARP_IP_CONFLICT_RE.search(line) else self._line_level(line),
                    "file": source.get("path"),
                    "location": f"lines {start + 1}-{end}",
                    "component": source.get("component"),
                    "keywords": keywords[:8],
                    "message": message,
                    "relevance": str(request.get("reason") or "模型请求补充查看该日志上下文。"),
                }
            )
            if len(snippets) >= 3:
                break
        return snippets

    def _infer_ip_from_path(self, path: str) -> str:
        match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", path)
        return match.group(0) if match else ""

    def _build_cloud_prompt(
        self,
        cfg: LogAnalysisConfig,
        diagnosis: dict[str, Any],
        findings: list[dict[str, Any]],
        summary: dict[str, Any],
    ) -> str:
        compact_evidence: list[dict[str, Any]] = []
        for item in diagnosis.get("evidence_chain") or []:
            if not isinstance(item, dict):
                continue
            compact_evidence.append(
                {
                    "file": item.get("file"),
                    "location": item.get("location"),
                    "message": item.get("message"),
                    "relevance": item.get("relevance"),
                    "strength": item.get("strength") or item.get("level"),
                }
            )
            if len(compact_evidence) >= 20:
                break

        if not compact_evidence:
            for finding in findings[:8]:
                if not isinstance(finding, dict):
                    continue
                for evidence in finding.get("evidence") or []:
                    if not isinstance(evidence, dict):
                        continue
                    compact_evidence.append(
                        {
                            "file": evidence.get("file"),
                            "location": evidence.get("location"),
                            "message": evidence.get("message"),
                            "relevance": finding.get("title"),
                            "strength": finding.get("severity"),
                        }
                    )
                    if len(compact_evidence) >= 20:
                        break
                if len(compact_evidence) >= 20:
                    break

        evidence_profile = self._diagnosis_evidence_profile(diagnosis)
        prompt_payload = {
            "customer_problem": cfg.problem_description,
            "problem_profile": diagnosis.get("problem_profile") or {},
            "rule_diagnosis": {
                "scenario": diagnosis.get("scenario"),
                "title": diagnosis.get("title") or diagnosis.get("diagnosis_title"),
                "current_judgement": diagnosis.get("current_judgement") or diagnosis.get("conclusion"),
                "confidence": diagnosis.get("confidence"),
                "affected_objects": diagnosis.get("affected_objects"),
                "what_can_be_confirmed": diagnosis.get("what_can_be_confirmed") or diagnosis.get("confirmed_items"),
                "what_cannot_be_confirmed": diagnosis.get("what_cannot_be_confirmed") or diagnosis.get("cannot_confirm_items"),
                "missing_materials": diagnosis.get("missing_materials") or diagnosis.get("supplemental_info"),
                "recommended_next_steps": diagnosis.get("recommended_next_steps") or diagnosis.get("handling_recommendations"),
            },
            "summary": {
                "total_files": summary.get("total_files"),
                "log_files": summary.get("log_files"),
                "key_evidence_count": diagnosis.get("key_evidence_count") or summary.get("diagnosis_evidence_count"),
                "evidence_profile": evidence_profile,
            },
            "filtered_evidence": compact_evidence,
            "output_schema": {
                "mode": "diagnosis 或 triage。只有强/中证据足够支撑时才能输出 diagnosis；弱证据或证据不足必须输出 triage。",
                "can_determine_root_cause": "true 或 false。不能仅凭推测写 true。",
                "confidence": "高/中/低",
                "current_judgement": "至少 50 个中文字符。先说日志能确认的事实，再说明与客户问题的关系，再说明更倾向的排查方向，最后说明判断边界。",
                "most_likely_cause": "如果不能确认根因，请写空字符串或保守排查方向。",
                "likely_causes": ["可能原因方向"],
                "evidence_reasoning": ["逐条说明证据为什么支持或不支持判断，不能只重复证据标题。"],
                "can_confirm": ["当前能够确认"],
                "cannot_confirm": ["当前不能确认"],
                "missing_materials": ["需要客户补充的信息"],
                "recommended_actions": ["建议处理方向"],
                "evidence_quality": "strong / medium / weak / insufficient",
                "overclaiming_risk": "说明是否存在过度判断风险以及原因",
            },
        }
        text = json.dumps(self._sanitize_payload_for_reports(prompt_payload), ensure_ascii=False, indent=2)
        instructions = """
你是 VMware support bundle 日志诊断辅助判断器，不是报告润色器。
你只能基于输入中提供的客户问题、规则诊断摘要和筛选后的日志证据做判断，不能编造日志中不存在的事件、对象、时间、错误码或根因。

请先判断证据是否足以支撑根因：
- 强证据：明确 error / failed / timeout / disconnected / link down / blocked / reset；虚拟网卡 connect / disconnect / backing 变化；dvPort blocked / port unavailable / uplink down；vMotion / migration 失败或异常；与客户对象和故障时间高度匹配的错误日志。
- 中证据：vCenter task/event 中的迁移、重配置、网络变更记录；DVS、端口组、VLAN、MTU、teaming、failover 配置变化；物理网卡状态变化但未明确对应客户对象；与问题领域相关但时间或对象不完全匹配的事件。
- 弱证据：静态配置、普通计数器、没有时间关联的 VLAN / 端口组信息、只命中泛化关键词但没有错误、动作、对象关联的行。

如果只有弱证据或证据不足，必须输出 mode=triage，can_determine_root_cause=false，不得输出完整诊断结论。
如果有强/中证据且能够形成对象、动作/症状、时间线、结果的证据链，才允许输出 mode=diagnosis。
不要使用绝对化措辞，不要吓客户，不要说“已经确认根因”除非证据链足够完整。
不要输出源码路径、本机路径、SQLite 路径、Python 路径、API Key、token、cookie、Authorization 等敏感信息。
不要返回“建议围绕时间窗口、对象和组件状态进一步核对”这类空泛结论，除非同时说明具体缺少什么材料、为什么当前证据不足。
请只输出一个 JSON 对象，不要 Markdown，不要解释性前后缀。
""".strip()
        return _sanitize_report_text(f"{instructions}\n\n输入材料：\n{text}")

    def _evaluate_cloud_diagnosis(
        self,
        cfg: LogAnalysisConfig,
        diagnosis: dict[str, Any],
        cloud: dict[str, Any],
        *,
        forensic: dict[str, Any] | None = None,
        snippets: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        forensic = forensic or {}
        snippets = snippets or []
        sanitized = self._sanitize_payload_for_reports(cloud)
        if not isinstance(sanitized, dict):
            return {"quality": "rejected", "reason": "模型返回内容不是 JSON 对象", "content": {}}

        reasons: list[str] = []
        model_evidence, invalid_evidence_count = self._normalize_cloud_evidence_chain(sanitized.get("evidence_chain"))
        sanitized["evidence_chain"] = model_evidence
        current = str(sanitized.get("current_judgement") or "").strip()
        mode = str(sanitized.get("mode") or "").strip().lower()
        evidence_quality = str(sanitized.get("evidence_quality") or "").strip().lower()
        can_root = sanitized.get("can_determine_root_cause")
        evidence_profile = self._diagnosis_evidence_profile({"evidence_chain": model_evidence})
        strong_count = int(evidence_profile.get("strong", 0))
        medium_count = int(evidence_profile.get("medium", 0))
        evidence_count = int(evidence_profile.get("total", 0))
        profile_quality = self._evidence_quality_from_profile(evidence_profile)
        candidate_strong = [item for item in forensic.get("candidate_strong_evidence") or [] if isinstance(item, dict)]
        arp_candidates = [item for item in candidate_strong if "arp" in str(item.get("type") or "").lower() or "ARP/IP" in str(item.get("type") or "")]
        has_arp_candidate = bool(arp_candidates)
        network_problem = self._is_cloud_network_problem(cfg, diagnosis)

        if invalid_evidence_count > 0:
            reasons.append("模型证据链字段不完整或引用了静态资料文件")
        if evidence_quality not in {"strong", "medium", "weak", "insufficient"}:
            evidence_quality = profile_quality
            sanitized["evidence_quality"] = evidence_quality
        elif profile_quality in {"weak", "insufficient"} and evidence_quality in {"strong", "medium"}:
            evidence_quality = profile_quality
            sanitized["evidence_quality"] = evidence_quality
            reasons.append("模型证据质量与具体证据链不匹配")

        if mode not in {"diagnosis", "triage"}:
            mode = "diagnosis" if evidence_quality in {"strong", "medium"} else "triage"
            sanitized["mode"] = mode
            reasons.append("模型未明确输出 mode，已按证据质量补齐")

        if self._is_generic_model_judgement(current):
            reasons.append("current_judgement 过于泛化")

        if self._contains_forbidden_model_output(sanitized, cfg.cloud_api_key):
            return {"quality": "rejected", "reason": "模型输出包含敏感信息或本机路径", "content": {}}

        reasoning = self._cloud_string_list(sanitized.get("evidence_reasoning"))
        cannot_confirm = self._cloud_string_list(sanitized.get("cannot_confirm"))
        missing = self._cloud_string_list(sanitized.get("missing_materials"))
        if not reasoning or self._reasoning_is_shallow(reasoning):
            reasons.append("evidence_reasoning 缺少有效推理")
        if not cannot_confirm:
            reasons.append("缺少当前不能确认内容")
        if not missing:
            reasons.append("缺少需要补充材料")

        has_medium_or_strong = strong_count > 0 or medium_count > 0
        has_specific_evidence = evidence_count >= 2 or (evidence_count == 1 and strong_count >= 1)
        if evidence_profile.get("static_only"):
            reasons.append("模型证据链仅来自静态资料文件，不能作为现场异常证据")
        if network_problem and has_arp_candidate and not self._cloud_output_covers_arp_candidates(sanitized, arp_candidates):
            reasons.append("网络问题存在 ARP/IP 冲突强候选但模型输出未引用")
        if mode == "diagnosis" and (not has_medium_or_strong or not has_specific_evidence or evidence_quality in {"weak", "insufficient"}):
            sanitized["mode"] = "triage"
            sanitized["can_determine_root_cause"] = False
            reasons.append("模型输出 diagnosis 但具体证据链不足")
        if can_root is True and (not has_medium_or_strong or evidence_count <= 0 or evidence_quality in {"weak", "insufficient"}):
            sanitized["can_determine_root_cause"] = False
            sanitized["mode"] = "triage"
            reasons.append("模型声称可确认根因但证据链不足")
        if evidence_count <= 0:
            sanitized["mode"] = "triage"
            sanitized["can_determine_root_cause"] = False
            reasons.append("当前没有可用证据链")

        if sanitized.get("mode") == "diagnosis" and not reasons and has_medium_or_strong and has_specific_evidence:
            sanitized["confidence"] = str(sanitized.get("confidence") or diagnosis.get("confidence") or "中")
            return {"quality": "accepted", "reason": "模型输出通过质量门禁", "content": sanitized}

        if sanitized.get("mode") == "triage" or reasons:
            self._ensure_cloud_triage_boundaries(sanitized, diagnosis, reasons)
            return {
                "quality": "downgraded",
                "reason": "；".join(dict.fromkeys(reasons)) or "证据不足，按粗排查报告处理",
                "content": sanitized,
            }

        return {"quality": "rejected", "reason": "模型输出质量不足", "content": {}}

    def _merge_cloud_diagnosis(self, diagnosis: dict[str, Any], cloud: dict[str, Any], quality: str) -> None:
        current = str(cloud.get("current_judgement") or "").strip()
        if current:
            diagnosis["current_judgement"] = _sanitize_report_text(current)
            diagnosis["conclusion"] = diagnosis["current_judgement"]
        if quality == "downgraded":
            diagnosis["fully_determine_text"] = "否，当前证据不足，不能仅凭当前 support bundle 确认最终根因。"
            diagnosis["can_fully_determine"] = False
            diagnosis["model_triage_notice"] = "当前模型输出已按证据质量降级为模型辅助粗排查，报告仅提供排查方向和证据边界。"
        elif isinstance(cloud.get("can_determine_root_cause"), bool):
            diagnosis["can_fully_determine"] = bool(cloud.get("can_determine_root_cause"))
            diagnosis["fully_determine_text"] = (
                "是，当前模型引用的日志证据链足以支持该判断。"
                if diagnosis["can_fully_determine"]
                else "否，当前 support bundle 尚不能单独证明最终根因。"
            )

        likely_causes = self._cloud_string_list(cloud.get("likely_causes"))
        if not likely_causes:
            likely_causes = self._cloud_string_list(cloud.get("most_likely_cause"))
        if likely_causes:
            diagnosis["likely_direction"] = likely_causes

        evidence_reasoning = self._cloud_string_list(cloud.get("evidence_reasoning"))
        if evidence_reasoning:
            diagnosis["evidence_reasoning"] = evidence_reasoning

        model_evidence, _ = self._normalize_cloud_evidence_chain(cloud.get("evidence_chain"))
        if model_evidence:
            diagnosis["evidence_chain"] = model_evidence
            diagnosis["key_evidence_count"] = len(model_evidence)
            diagnosis["evidence_sections"] = [
                {
                    "title": "模型引用的关键日志证据",
                    "log_file": self._first_file(model_evidence),
                    "excerpts": model_evidence,
                    "judgement": "模型基于上述日志证据进行综合判断，报告仍保留当前 support bundle 的判断边界。",
                }
            ]

        can_confirm = self._cloud_string_list(cloud.get("can_confirm"))
        if can_confirm:
            diagnosis["what_can_be_confirmed"] = can_confirm
            diagnosis["confirmed_items"] = can_confirm

        cannot_confirm = self._cloud_string_list(cloud.get("cannot_confirm"))
        if cannot_confirm:
            diagnosis["what_cannot_be_confirmed"] = cannot_confirm
            diagnosis["cannot_confirm_items"] = cannot_confirm

        missing = self._cloud_string_list(cloud.get("missing_materials"))
        if missing:
            diagnosis["missing_materials"] = missing
            diagnosis["supplemental_info"] = missing

        recommendations = self._cloud_string_list(cloud.get("recommended_actions"))
        if recommendations:
            diagnosis["recommended_next_steps"] = recommendations
            diagnosis["handling_recommendations"] = recommendations

        confidence = str(cloud.get("confidence") or "").strip()
        if confidence in {"低", "中", "高"}:
            diagnosis["confidence"] = confidence
        mode = str(cloud.get("mode") or "").strip()
        if mode:
            diagnosis["model_output_mode"] = mode
        evidence_quality = str(cloud.get("evidence_quality") or "").strip()
        if evidence_quality:
            diagnosis["model_evidence_quality"] = evidence_quality
        risk = str(cloud.get("overclaiming_risk") or "").strip()
        if risk:
            diagnosis["model_overclaiming_risk"] = _sanitize_report_text(risk)

    def _record_cloud_output_metadata(self, diagnosis: dict[str, Any], cloud: dict[str, Any]) -> None:
        mode = str(cloud.get("mode") or "").strip()
        if mode:
            diagnosis["model_output_mode"] = mode
        evidence_quality = str(cloud.get("evidence_quality") or "").strip()
        if evidence_quality:
            diagnosis["model_evidence_quality"] = evidence_quality
        risk = str(cloud.get("overclaiming_risk") or "").strip()
        if risk:
            diagnosis["model_overclaiming_risk"] = _sanitize_report_text(risk)

    def _normalize_cloud_evidence_chain(self, value: Any) -> tuple[list[dict[str, Any]], int]:
        if not isinstance(value, list):
            return [], 0
        rows: list[dict[str, Any]] = []
        invalid = 0
        for item in value:
            if not isinstance(item, dict):
                invalid += 1
                continue
            file_path = _sanitize_report_text(str(item.get("file") or item.get("log_file") or "").strip())
            location = _sanitize_report_text(str(item.get("location") or item.get("line") or "").strip())
            message = _sanitize_report_text(str(item.get("message") or item.get("excerpt") or "").strip())
            relevance = _sanitize_report_text(str(item.get("relevance") or item.get("reason") or "").strip())
            if not (file_path and location and message and relevance):
                invalid += 1
                continue
            if self._is_reference_material_file(file_path):
                invalid += 1
                continue
            rows.append(
                {
                    "strength": _sanitize_report_text(str(item.get("strength") or item.get("level") or "中").strip()),
                    "file": file_path,
                    "location": location,
                    "message": self._trim_line(message, limit=1200),
                    "relevance": relevance,
                }
            )
        return rows, invalid

    def _is_cloud_network_problem(self, cfg: LogAnalysisConfig, diagnosis: dict[str, Any]) -> bool:
        affected = diagnosis.get("affected_objects") if isinstance(diagnosis.get("affected_objects"), dict) else {}
        domains = " ".join(str(item) for item in affected.get("domains", []) if str(item).strip())
        text = f"{cfg.problem_description} {diagnosis.get('scenario') or ''} {domains}".lower()
        return any(token in text for token in ("网络", "虚拟网卡", "vmnic", "vmk", "arp", "ip 冲突", "ip冲突", "vlan", "portgroup", "迁移"))

    def _cloud_output_covers_arp_candidates(self, cloud: dict[str, Any], candidates: list[dict[str, Any]]) -> bool:
        text = json.dumps(cloud, ensure_ascii=False).lower()
        for candidate in candidates:
            vmk = str(candidate.get("vmkernel_interface") or "").lower()
            ip = str(candidate.get("conflict_ip") or "").lower()
            mac = str(candidate.get("conflict_mac") or "").lower()
            required = [token for token in (vmk, ip, mac) if token]
            if required and all(token in text for token in required):
                return True
        return False

    def _cloud_string_list(self, value: Any) -> list[str]:
        if isinstance(value, list):
            return [_sanitize_report_text(str(item).strip()) for item in value if str(item).strip()]
        if isinstance(value, str) and value.strip():
            return [_sanitize_report_text(value.strip())]
        return []

    def _diagnosis_evidence_profile(self, diagnosis: dict[str, Any]) -> dict[str, Any]:
        rows: list[dict[str, Any]] = []
        if isinstance(diagnosis.get("evidence_chain"), list):
            rows.extend(item for item in diagnosis["evidence_chain"] if isinstance(item, dict))
        for section in diagnosis.get("evidence_sections") or []:
            if not isinstance(section, dict):
                continue
            for excerpt in section.get("excerpts") or []:
                if isinstance(excerpt, dict):
                    item = dict(excerpt)
                    item.setdefault("file", section.get("log_file"))
                    item.setdefault("strength", excerpt.get("level") or section.get("level"))
                    rows.append(item)

        counts = Counter(self._normalize_evidence_strength(item.get("strength") or item.get("level")) for item in rows)
        source_files = sorted(
            {
                str(item.get("file") or "").strip()
                for item in rows
                if str(item.get("file") or "").strip()
            }
        )
        static_markers = ("vmkfstools", "dump-vmdk", "vmkerrcode", "usb.ids", "pci.ids", "secpolicytools")
        static_sources = [item for item in source_files if any(marker in item.lower() for marker in static_markers)]
        return {
            "total": len(rows),
            "strong": counts.get("strong", 0),
            "medium": counts.get("medium", 0),
            "weak": counts.get("weak", 0),
            "source_count": len(source_files),
            "source_files": source_files[:12],
            "static_source_count": len(static_sources),
            "static_only": bool(rows) and len(static_sources) == len(source_files),
        }

    def _normalize_evidence_strength(self, value: Any) -> str:
        text = str(value or "").strip().lower()
        if any(token in text for token in ("强", "高", "strong", "high", "direct", "直接")):
            return "strong"
        if any(token in text for token in ("中", "medium", "moderate", "关联")):
            return "medium"
        return "weak"

    def _evidence_quality_from_profile(self, profile: dict[str, Any]) -> str:
        if int(profile.get("strong", 0) or 0) > 0:
            return "strong"
        if int(profile.get("medium", 0) or 0) > 0:
            return "medium"
        if int(profile.get("weak", 0) or 0) > 0:
            return "weak"
        return "insufficient"

    def _is_generic_model_judgement(self, text: str) -> bool:
        normalized = re.sub(r"\s+", "", text or "")
        if len(normalized) < 30:
            return True
        generic_phrases = (
            "当前日志线索与客户问题存在关联",
            "建议优先围绕时间窗口",
            "问题对象和关键组件状态进一步核对",
            "需要进一步分析",
            "发现相关日志",
            "当前日志包中能找到运行痕迹",
        )
        return any(phrase in normalized for phrase in generic_phrases)

    def _reasoning_is_shallow(self, items: list[str]) -> bool:
        meaningful = 0
        for item in items:
            text = re.sub(r"\s+", "", item)
            if len(text) >= 24 and any(token in text for token in ("因为", "因此", "说明", "但", "不能", "支撑", "不足", "关联")):
                meaningful += 1
        return meaningful <= 0

    def _contains_forbidden_model_output(self, value: Any, api_key: str = "") -> bool:
        text = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
        if api_key and api_key in text:
            return True
        lowered = text.lower()
        return any(marker.lower() in lowered for marker in _LOCAL_PATH_MARKERS)

    def _ensure_cloud_triage_boundaries(self, cloud: dict[str, Any], diagnosis: dict[str, Any], reasons: list[str]) -> None:
        cloud["mode"] = "triage"
        cloud["can_determine_root_cause"] = False
        cloud["confidence"] = str(cloud.get("confidence") or "低")
        judgement = str(cloud.get("current_judgement") or diagnosis.get("current_judgement") or "").strip()
        boundary = "当前证据不足，不能仅凭当前 support bundle 确认最终根因。"
        if boundary not in judgement:
            judgement = f"{judgement} {boundary}".strip()
        cloud["current_judgement"] = judgement or boundary
        cannot_confirm = self._cloud_string_list(cloud.get("cannot_confirm"))
        if not cannot_confirm:
            cannot_confirm = self._cloud_string_list(diagnosis.get("what_cannot_be_confirmed") or diagnosis.get("cannot_confirm_items"))
        if not cannot_confirm:
            cannot_confirm = ["当前日志包尚未形成对象、动作/症状、时间线和结果闭环，不能确认最终根因。"]
        if reasons and not any("证据" in item for item in cannot_confirm):
            cannot_confirm.insert(0, f"模型输出已降级：{'；'.join(dict.fromkeys(reasons))}。")
        cloud["cannot_confirm"] = cannot_confirm
        missing = self._cloud_string_list(cloud.get("missing_materials"))
        if not missing:
            missing = self._cloud_string_list(diagnosis.get("missing_materials") or diagnosis.get("supplemental_info"))
        if not missing:
            missing = ["故障发生准确时间点", "相关 vCenter Task/Event 记录", "现场对象配置和运行状态截图"]
        cloud["missing_materials"] = missing

    def _sanitize_payload_for_reports(self, value: Any) -> Any:
        if isinstance(value, str):
            return _sanitize_report_text(value)
        if isinstance(value, dict):
            return {key: self._sanitize_payload_for_reports(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._sanitize_payload_for_reports(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self._sanitize_payload_for_reports(item) for item in value)
        return value

    def _detect_problem_scenario(self, problem_description: str) -> str | None:
        return self.diagnosis_engine.parser.detect_scenario(problem_description)

    def _parse_problem_description(self, problem_description: str) -> dict[str, Any]:
        return self.diagnosis_engine.parser.parse(problem_description)

    def _build_generic_problem_diagnosis(
        self,
        support_bundle_path: Path,
        problem_description: str,
        findings: list[dict[str, Any]],
        problem_profile: dict[str, Any],
    ) -> dict[str, Any]:
        sources = self._collect_problem_sources(support_bundle_path, problem_profile)
        evidence_chain = self._extract_problem_evidence(sources, problem_profile)
        confidence, confidence_reason = self._generic_confidence(evidence_chain, problem_profile)
        domains = [str(item) for item in problem_profile.get("domains", []) if str(item).strip()]
        domain_text = " / ".join(domains) if domains else "未知"
        primary_object = str(problem_profile.get("primary_object") or "当前问题描述未明确提供")
        likely_direction = self._likely_directions(problem_profile)
        missing_materials = self._missing_materials(problem_profile)
        confirmed_items = self._generic_confirmed_items(problem_profile, evidence_chain)
        cannot_confirm_items = self._generic_cannot_confirm_items(problem_profile)
        recommendations = self._generic_recommendations(problem_profile)

        if evidence_chain:
            conclusion = (
                f"本次报告围绕客户问题“{problem_description}”进行分析。当前日志包中提取到 {len(evidence_chain)} 条与"
                f"{domain_text}方向相关的日志或配置线索，但尚未形成“对象 + 动作/症状 + 时间线 + 结果”的完整根因证据链。"
                "因此当前不能仅凭该 support bundle 完全确认最终原因。"
            )
        else:
            conclusion = (
                f"本次报告围绕客户问题“{problem_description}”进行分析。当前日志包尚未提取到足以直接支撑该现象的关键证据，"
                "不能仅凭该 support bundle 完全确认最终原因。"
            )

        title = "客户问题驱动日志诊断报告"
        if {"迁移", "网络"}.issubset(set(domains)):
            title = "在线迁移后虚拟机网络不通诊断报告"

        return {
            "scenario": "generic_problem_driven_diagnosis",
            "title": scenario_title("generic_problem_driven_diagnosis", title),
            "diagnosis_title": scenario_title("generic_problem_driven_diagnosis", title),
            "customer_question": problem_description,
            "problem_summary": f"客户描述对象 {primary_object} 出现 {domain_text} 相关问题。",
            "problem_profile": problem_profile,
            "affected_objects": {
                "primary_object": primary_object,
                "objects": list(problem_profile.get("objects") or []),
                "domains": domains,
                "actions": list(problem_profile.get("actions") or []),
                "symptoms": list(problem_profile.get("symptoms") or []),
                "time_hints": list(problem_profile.get("time_hints") or []),
            },
            "likely_direction": likely_direction,
            "confidence": confidence,
            "confidence_reason": confidence_reason,
            "conclusion": conclusion,
            "current_judgement": self._generic_current_judgement(problem_profile, confidence),
            "can_fully_determine": False,
            "fully_determine_text": "否，当前日志包无法完全确认最终根因。",
            "missing_materials": missing_materials[:10],
            "key_evidence_count": len(evidence_chain),
            "evidence_chain": evidence_chain,
            "evidence_sections": [
                {
                    "title": "与客户问题相关的日志证据",
                    "log_file": self._first_file(evidence_chain),
                    "excerpts": evidence_chain,
                    "judgement": confidence_reason,
                }
            ],
            "what_can_be_confirmed": confirmed_items,
            "what_cannot_be_confirmed": cannot_confirm_items,
            "confirmed_items": confirmed_items,
            "cannot_confirm_items": cannot_confirm_items,
            "supplemental_info": missing_materials,
            "handling_recommendations": recommendations,
            "recommended_next_steps": recommendations,
            "other_observations": self._generic_other_observations(findings),
        }

    def _build_snapshot_diagnosis(
        self,
        support_bundle_path: Path,
        problem_description: str,
        findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        sources = self._collect_snapshot_sources(support_bundle_path)
        vmx_entries = self._snapshot_vmx_entries(sources.get("vmx", []))
        vmsd_entries = self._snapshot_vmsd_entries(sources.get("vmsd", []))
        primary_vmx = self._choose_primary_vmx(vmx_entries, vmsd_entries)
        primary_vmsd = self._choose_primary_vmsd(vmsd_entries, primary_vmx)
        vmware_logs = self._snapshot_related_vmware_logs(sources.get("vmware_logs", []), primary_vmx)

        vm_name = str((primary_vmx or {}).get("display_name") or self._infer_vm_name_from_sources(sources) or "当前日志包未明确识别")
        vmx_path = str((primary_vmx or {}).get("path") or "当前日志包未明确识别")
        snapshot_disks = list((primary_vmx or {}).get("snapshot_disks") or [])
        vmdk_chain = self._snapshot_vmdk_chain(sources.get("vmdk", []), snapshot_disks, vm_name)

        power_cancel = self._matching_source_lines(
            vmware_logs,
            (
                r'softPowerOff\s*=\s*"TRUE"',
                r"Issuing power-off request",
                r"SnapshotVMX_ConsolidateCancel",
                r"Requesting snapshot consolidate cancel",
            ),
            max_total=8,
        )
        combine_cancel = self._matching_source_lines(
            vmware_logs,
            (
                r"Canceling vmfs combine",
                r"Operation was cancelled \(33\)",
                r"Cancelling in-progress online consolidate",
                r"Snapshot consolidate complete: Cancelled \(34\)",
                r"Cancelled \(34\)",
            ),
            max_total=8,
        )
        powered_off = self._matching_source_lines(
            vmware_logs,
            (r"Transitioned vmx/execState/val to poweredOff",),
            max_total=4,
        )
        need_consolidate = self._matching_source_lines(
            [primary_vmsd] if primary_vmsd else sources.get("vmsd", []),
            (r"snapshot\.needConsolidate\s*=\s*\"?TRUE\"?", r"snapshot\.lastUID"),
            max_total=6,
        )
        snapshot_top_disk = self._matching_source_lines(
            [primary_vmx] if primary_vmx else sources.get("vmx", []),
            (r"displayName\s*=", r"scsi\d+:\d+\.fileName\s*=", r"-000\d+\.vmdk"),
            max_total=10,
        )
        task_timeout = self._matching_source_lines(
            sources.get("task_logs", []),
            (
                r"removeAllSnapshots",
                r"Timed out waiting for task",
                r"No taskinfo property updates",
                r"vim\.VirtualMachine\.removeAllSnapshots",
            ),
            max_total=8,
        )

        chain_excerpts = list(vmdk_chain.get("excerpts", []))
        chain_status = str(vmdk_chain.get("status") or "unknown")
        chain_judgement = (
            "从 support bundle 中的 VMDK 描述符看，CID / parentCID 是连续匹配的，当前没有看到 VMDK 描述符层面的明显断链证据。"
            if chain_status == "continuous"
            else "当前日志包中的 VMDK 描述符证据不足，无法仅凭该日志包确认快照链是否完整。"
        )
        if chain_status == "broken":
            chain_judgement = "发现 VMDK 描述符链可能异常，需要结合现场 vmkfstools 检查和备份状态进一步人工确认。"

        evidence_sections = [
            {
                "title": "虚拟机在关机过程中触发取消快照整合",
                "log_file": self._first_file(power_cancel),
                "excerpts": power_cancel,
                "judgement": "该时间点虚拟机正在执行关机，同时 VMX 明确请求取消 snapshot consolidate。" if power_cancel else "当前日志包未提取到完整的关机触发取消整合证据。",
            },
            {
                "title": "合并动作被取消，不是正常完成",
                "log_file": self._first_file(combine_cancel),
                "excerpts": combine_cancel,
                "judgement": "日志中明确出现合并或 online consolidate 被取消的记录，说明快照合并/整合未正常完成。" if combine_cancel else "当前日志包未提取到完整的合并取消证据。",
            },
            {
                "title": "虚拟机之后进入 poweredOff",
                "log_file": self._first_file(powered_off),
                "excerpts": powered_off,
                "judgement": "虚拟机是在快照合并被取消之后进入 poweredOff 状态，关机过程与取消快照整合存在直接时间关联。" if powered_off else "当前日志包未提取到 poweredOff 状态转换记录。",
            },
            {
                "title": "当前仍标记需要快照整合",
                "log_file": self._first_file(need_consolidate),
                "excerpts": need_consolidate,
                "judgement": "虚拟机配置仍标记 needConsolidate=TRUE，说明上一次合并没有彻底完成。" if need_consolidate else "当前日志包未提取到 needConsolidate=TRUE 配置证据。",
            },
            {
                "title": "当前仍挂载快照链顶层磁盘",
                "log_file": self._first_file(snapshot_top_disk),
                "excerpts": snapshot_top_disk,
                "judgement": "虚拟机磁盘仍指向 -00000x.vmdk 快照链顶层，该状态与需要整合一致。" if snapshot_disks else "当前日志包未提取到仍挂载 -00000x.vmdk 的磁盘配置。",
            },
            {
                "title": "vCenter / ESXi 侧 removeAllSnapshots 任务长期无更新",
                "log_file": self._first_file(task_timeout),
                "excerpts": task_timeout,
                "judgement": "removeAllSnapshots 任务长时间没有 taskinfo 更新，说明 host/vCenter 侧任务状态存在异常等待或卡住迹象。" if task_timeout else "当前日志包未提取到 removeAllSnapshots 长时间无更新证据。",
            },
            {
                "title": "VMDK 描述符链是否存在断链证据",
                "log_file": self._first_file(chain_excerpts),
                "excerpts": chain_excerpts,
                "judgement": chain_judgement,
            },
        ]

        key_evidence_count = sum(len(section.get("excerpts", [])) for section in evidence_sections)
        has_direct_cause = bool(power_cancel and combine_cancel)
        has_need_consolidate = bool(need_consolidate)
        has_snapshot_disk = bool(snapshot_disks)
        snapshot_disk_label = self._snapshot_disk_label(snapshot_disks)
        if has_direct_cause:
            conclusion = (
                f"当前日志显示 {vm_name} 存在 snapshot consolidate / removeAllSnapshots 相关任务记录，"
                "并出现 Operation was cancelled、SnapshotVMX_ConsolidateCancel 或 VM 状态变化等任务中断线索。"
            )
            if has_need_consolidate:
                conclusion += "同时，当前日志包显示虚拟机仍保留 snapshot.needConsolidate=TRUE。"
            if has_snapshot_disk:
                conclusion += f"同时，{snapshot_disk_label} 仍指向 -00000x.vmdk 快照链顶层。"
            conclusion += "因此当前更倾向于优先排查整合任务被中断、VM 状态变化、备份任务占用或文件锁方向。当前 support bundle 尚不能单独证明最终根因。"
        else:
            conclusion = (
                "当前日志包中发现快照整合失败或快照链残留相关证据，但尚未形成完整证据链。"
                "当前更倾向于优先排查整合任务状态、备份任务占用、文件锁或快照链状态方向，仍需补充 vCenter 任务事件、快照管理器截图和现场磁盘链检查结果后继续判断。"
            )

        current_judgement = (
            f"当前日志显示 {vm_name} 存在 snapshot.needConsolidate 状态，并出现 consolidate / removeAllSnapshots 相关任务记录。"
            "日志中同时可以看到 Operation was cancelled、SnapshotVMX_ConsolidateCancel 或 VM 状态变化等线索，"
            "说明快照整合过程存在被中断或未正常完成的迹象。结合客户描述“快照整合失败”，当前更倾向于优先排查整合任务被中断、"
            "VM 状态变化、备份任务占用或文件锁方向。"
            if has_direct_cause or has_need_consolidate or has_snapshot_disk
            else "当前证据可以说明快照整合存在取消、残留或任务等待异常线索，但仍不足以单独确认完整原因链。"
        )
        if chain_status == "continuous":
            current_judgement += "从当前可见 VMDK descriptor 看，CID / parentCID 连续，暂未发现明显磁盘链断裂证据，不能直接判断为 VMDK 链损坏。"
        elif chain_status == "broken":
            current_judgement += "当前可见 VMDK descriptor 存在 CID / parentCID 不匹配线索，需要结合现场 vmkfstools 检查继续确认。"
        else:
            current_judgement += "当前 support bundle 中的 VMDK descriptor 证据不足，无法单独确认磁盘链是否完整。"
        current_judgement += "当前 support bundle 尚不能单独证明最终根因。"

        confirmed_items = self._snapshot_confirmed_items(
            vm_name=vm_name,
            power_cancel=power_cancel,
            combine_cancel=combine_cancel,
            need_consolidate=need_consolidate,
            snapshot_disks=snapshot_disks,
            task_timeout=task_timeout,
            chain_status=chain_status,
        )
        cannot_confirm_items = [
            "最初快照合并为什么耗时很长或进入长时间等待。",
            "当前 vSAN 对象实时健康状态是否完全正常。",
            "vCenter UI 任务状态和 vpxd 侧任务上下文是否还有额外异常。",
            "当前现场快照链是否已经被后续人工操作改变。",
        ]
        supplemental_info = [
            "vCenter 任务和事件截图，包含 removeAllSnapshots / consolidate 任务状态。",
            "虚拟机“快照管理器”截图。",
            "虚拟机“需要整合”告警截图。",
            "vCenter vpxd.log 对应时间段。",
            "ESXi 上执行 vim-cmd vimsvc/task_list 的输出。",
            "ESXi 上执行 vim-cmd vmsvc/snapshot.get <vmid> 的输出。",
            "ESXi 上执行 vmkfstools -e <当前 -00000x.vmdk 路径> 的输出。",
            "当前 vSAN Health / Object Health 截图。",
            "Datastore 剩余空间截图。",
        ]
        handling_recommendations = [
            "建议优先确认当前 VM 是否仍提示需要整合，并核对快照管理器中是否仍有快照残留。",
            "建议先确认备份状态、vSAN 对象健康和 datastore 剩余空间，再安排业务低峰窗口处理。",
            "建议由具备 VMware 运维经验的人员执行快照整合或磁盘链路检查，避免直接删除快照文件或手工修改描述符。",
            "如现场仍存在任务卡住，建议先收集 vCenter 任务事件和 ESXi task_list 输出，再决定是否重试整合或升级处理。",
        ]

        return {
            "scenario": "snapshot_consolidation_failure",
            "title": scenario_title("snapshot_consolidation_failure", "快照整合失败诊断报告"),
            "customer_question": problem_description,
            "conclusion": conclusion,
            "can_fully_determine": False,
            "fully_determine_text": "否，当前日志包无法完全确认现场最终状态。",
            "missing_materials": supplemental_info[:5],
            "key_evidence_count": key_evidence_count,
            "affected_objects": {
                "vm_name": vm_name,
                "vmx_path": vmx_path,
                "snapshot_disks": snapshot_disks,
                "vmdk_chain_files": [item.get("file") for item in vmdk_chain.get("descriptors", [])],
                "datastore_paths": self._snapshot_datastore_paths(snapshot_disks),
            },
            "evidence_sections": evidence_sections,
            "current_judgement": current_judgement,
            "accurate_judgement": current_judgement,
            "likely_direction": [
                "整合任务被中断或取消",
                "VM 状态变化对 online consolidate 的影响",
                "备份任务占用或文件锁",
                "VMDK 描述符链和 vSAN 对象健康状态",
            ],
            "confirmed_items": confirmed_items,
            "cannot_confirm_items": cannot_confirm_items,
            "supplemental_info": supplemental_info,
            "handling_recommendations": handling_recommendations,
            "other_observations": self._snapshot_other_observations(findings),
        }

    def _collect_snapshot_sources(self, support_bundle_path: Path) -> dict[str, list[dict[str, Any]]]:
        sources: dict[str, list[dict[str, Any]]] = {
            "vmware_logs": [],
            "task_logs": [],
            "vmx": [],
            "vmsd": [],
            "vmdk": [],
        }
        try:
            with zipfile.ZipFile(support_bundle_path) as zf:
                self._collect_snapshot_from_zip(zf, "", sources)
        except (OSError, zipfile.BadZipFile):
            return sources
        return sources

    def _collect_snapshot_from_zip(
        self,
        zf: zipfile.ZipFile,
        prefix: str,
        sources: dict[str, list[dict[str, Any]]],
        depth: int = 0,
    ) -> None:
        if depth >= self.MAX_NESTED_ARCHIVE_DEPTH:
            return
        for visited, info in enumerate(zf.infolist(), start=1):
            if visited > self.MAX_NESTED_ARCHIVE_MEMBERS:
                return
            if info.is_dir():
                continue
            display_path = f"{prefix}{info.filename}"
            lower_name = info.filename.lower()
            if self._is_nested_archive(info.filename):
                try:
                    if lower_name.endswith(".zip"):
                        with self._open_nested_zipfile(zf, info) as nested_zip:
                            self._collect_snapshot_from_zip(nested_zip, f"{display_path}!", sources, depth=depth + 1)
                    else:
                        with zf.open(info) as nested_stream:
                            self._collect_snapshot_from_tar(nested_stream, f"{display_path}!", sources)
                except (OSError, zipfile.BadZipFile, tarfile.TarError, _NestedArchiveLimitError):
                    continue
                continue
            kind = self._snapshot_file_kind(info.filename, info.file_size)
            if not kind:
                continue
            try:
                text = self._read_snapshot_zip_text(zf, info, kind)
            except OSError:
                continue
            self._add_snapshot_source(sources, kind, display_path, info.file_size, text)

    def _collect_snapshot_from_tar(self, stream: Any, prefix: str, sources: dict[str, list[dict[str, Any]]]) -> None:
        with tarfile.open(fileobj=stream, mode="r|*") as tar:
            for visited, member in enumerate(tar, start=1):
                if visited > self.MAX_NESTED_ARCHIVE_MEMBERS:
                    return
                if not member.isfile():
                    continue
                display_path = f"{prefix}{member.name}"
                kind = self._snapshot_file_kind(member.name, member.size)
                if not kind:
                    continue
                limit = self._snapshot_read_limit(kind, member.size)
                text = self._read_tar_member_text(tar, member, limit)
                if not text:
                    continue
                self._add_snapshot_source(sources, kind, display_path, member.size, text)

    def _snapshot_file_kind(self, path: str, size: int) -> str | None:
        name = Path(path).name.lower()
        if name.startswith("vmware") and name.endswith(".log"):
            return "vmware_logs"
        if (name.startswith("vpxa") or name.startswith("vpxd")) and ".log" in name:
            return "task_logs"
        if name.endswith(".vmx"):
            return "vmx"
        if name.endswith(".vmsd"):
            return "vmsd"
        if name.endswith(".vmdk") and not name.endswith("-flat.vmdk") and not name.endswith("-ctk.vmdk") and size <= self.SNAPSHOT_DESCRIPTOR_LIMIT_BYTES:
            return "vmdk"
        return None

    def _snapshot_read_limit(self, kind: str, size: int) -> int:
        if kind in {"vmx", "vmsd", "vmdk"}:
            return min(size, self.SNAPSHOT_DESCRIPTOR_LIMIT_BYTES)
        return min(size, self.SNAPSHOT_READ_LIMIT_BYTES)

    def _read_snapshot_zip_text(self, zf: zipfile.ZipFile, info: zipfile.ZipInfo, kind: str) -> str:
        with zf.open(info) as fh:
            data = fh.read(self._snapshot_read_limit(kind, info.file_size))
        return self._decode_text(data)

    def _add_snapshot_source(self, sources: dict[str, list[dict[str, Any]]], kind: str, path: str, size: int, text: str) -> None:
        sources[kind].append(
            {
                "path": self._customer_log_path(path),
                "archive_path": path,
                "size": size,
                "text": text,
            }
        )

    def _snapshot_vmx_entries(self, sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        for source in sources:
            text = str(source.get("text") or "")
            display_name = self._config_value(text, "displayName")
            disks = []
            for match in re.finditer(r'(?im)^\s*(scsi\d+:\d+\.fileName)\s*=\s*"([^"]+\.vmdk)"', text):
                disks.append(
                    {
                        "controller": match.group(1),
                        "file": match.group(2),
                    "is_snapshot": self._is_snapshot_vmdk_name(match.group(2)),
                }
            )
            entries.append(
                {
                    **source,
                    "display_name": display_name,
                    "disks": disks,
                    "snapshot_disks": [disk for disk in disks if disk.get("is_snapshot")],
                }
            )
        return entries

    def _snapshot_vmsd_entries(self, sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        for source in sources:
            text = str(source.get("text") or "")
            entries.append(
                {
                    **source,
                    "need_consolidate": bool(re.search(r'(?im)^\s*snapshot\.needConsolidate\s*=\s*"?TRUE"?', text)),
                    "last_uid": self._config_value(text, "snapshot.lastUID"),
                }
            )
        return entries

    def _choose_primary_vmx(self, vmx_entries: list[dict[str, Any]], vmsd_entries: list[dict[str, Any]]) -> dict[str, Any] | None:
        if not vmx_entries:
            return None
        need_dirs = {self._customer_dir(str(item.get("path") or "")) for item in vmsd_entries if item.get("need_consolidate")}

        def score(item: dict[str, Any]) -> tuple[int, int, str]:
            item_dir = self._customer_dir(str(item.get("path") or ""))
            return (
                1 if item_dir in need_dirs else 0,
                len(item.get("snapshot_disks") or []),
                str(item.get("display_name") or item.get("path") or ""),
            )

        return sorted(vmx_entries, key=score, reverse=True)[0]

    def _choose_primary_vmsd(self, vmsd_entries: list[dict[str, Any]], primary_vmx: dict[str, Any] | None) -> dict[str, Any] | None:
        if not vmsd_entries:
            return None
        if primary_vmx:
            vmx_dir = self._customer_dir(str(primary_vmx.get("path") or ""))
            for item in vmsd_entries:
                if self._customer_dir(str(item.get("path") or "")) == vmx_dir:
                    return item
        need_items = [item for item in vmsd_entries if item.get("need_consolidate")]
        return need_items[0] if need_items else vmsd_entries[0]

    def _snapshot_related_vmware_logs(self, sources: list[dict[str, Any]], primary_vmx: dict[str, Any] | None) -> list[dict[str, Any]]:
        if not primary_vmx:
            return sources
        vmx_dir = self._customer_dir(str(primary_vmx.get("path") or ""))
        related = [source for source in sources if self._customer_dir(str(source.get("path") or "")) == vmx_dir]
        return related or sources

    def _snapshot_vmdk_chain(
        self,
        sources: list[dict[str, Any]],
        snapshot_disks: list[dict[str, Any]],
        vm_name: str,
    ) -> dict[str, Any]:
        descriptors = [self._parse_vmdk_descriptor(item) for item in sources]
        descriptors = [item for item in descriptors if item.get("cid") or item.get("parent_cid")]
        roots = {self._vmdk_chain_root(str(item.get("file") or "")) for item in snapshot_disks}
        roots = {root for root in roots if root}
        if vm_name and vm_name != "当前日志包未明确识别":
            roots.add(self._vmdk_chain_root(f"{vm_name}.vmdk"))
        if roots:
            descriptors = [item for item in descriptors if self._vmdk_chain_root(str(item.get("name") or "")) in roots]
        descriptors.sort(key=lambda item: (self._vmdk_snapshot_index(str(item.get("name") or "")), str(item.get("name") or "")))
        if not descriptors:
            return {"status": "unknown", "descriptors": [], "excerpts": []}

        by_name = {str(item.get("name") or ""): item for item in descriptors}
        issues = []
        for item in descriptors:
            parent_hint = str(item.get("parent_file") or "")
            parent_cid = str(item.get("parent_cid") or "")
            if not parent_hint or parent_cid.lower() == "ffffffff":
                continue
            parent = by_name.get(Path(parent_hint).name)
            if not parent:
                issues.append(f"{item.get('name')} 未在日志包中找到父描述符 {parent_hint}")
                continue
            if str(parent.get("cid") or "").lower() != parent_cid.lower():
                issues.append(f"{item.get('name')} 的 parentCID 与父盘 CID 不匹配")

        excerpts = []
        for item in descriptors[:8]:
            parts = [f"{item.get('name')}: CID={item.get('cid') or '未记录'}", f"parentCID={item.get('parent_cid') or '未记录'}"]
            if item.get("parent_file"):
                parts.append(f'parentFileNameHint="{item.get("parent_file")}"')
            excerpts.append(
                {
                    "file": item.get("file"),
                    "location": "descriptor",
                    "level": "提示",
                    "message": "; ".join(parts),
                }
            )
        status = "broken" if issues else "continuous"
        return {"status": status, "descriptors": descriptors, "excerpts": excerpts, "issues": issues}

    def _parse_vmdk_descriptor(self, source: dict[str, Any]) -> dict[str, Any]:
        text = str(source.get("text") or "")
        name = Path(str(source.get("path") or "")).name
        cid = self._descriptor_value(text, "CID")
        parent_cid = self._descriptor_value(text, "parentCID")
        parent_file = self._descriptor_value(text, "parentFileNameHint")
        return {
            "file": source.get("path"),
            "name": name,
            "cid": cid,
            "parent_cid": parent_cid,
            "parent_file": parent_file,
        }

    def _descriptor_value(self, text: str, key: str) -> str:
        match = re.search(rf'(?im)^\s*{re.escape(key)}\s*=\s*"?(.*?)"?\s*$', text)
        return match.group(1).strip() if match else ""

    def _matching_source_lines(self, sources: list[dict[str, Any]], patterns: tuple[str, ...], max_total: int = 8) -> list[dict[str, str]]:
        regexes = [re.compile(pattern, re.I) for pattern in patterns]
        results: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for source in sources:
            text = str(source.get("text") or "")
            file_path = str(source.get("path") or "")
            for line_no, line in enumerate(text.splitlines(), start=1):
                if not line.strip():
                    continue
                if not any(regex.search(line) for regex in regexes):
                    continue
                message = self._trim_line(line, limit=320)
                dedupe_key = (file_path, message)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                results.append(
                    {
                        "file": file_path,
                        "location": f"line {line_no}",
                        "level": self._line_level(line),
                        "message": message,
                    }
                )
                if len(results) >= max_total:
                    return results
        return results

    def _snapshot_confirmed_items(
        self,
        *,
        vm_name: str,
        power_cancel: list[dict[str, str]],
        combine_cancel: list[dict[str, str]],
        need_consolidate: list[dict[str, str]],
        snapshot_disks: list[dict[str, Any]],
        task_timeout: list[dict[str, str]],
        chain_status: str,
    ) -> list[str]:
        items = [f"目标 VM 是 {vm_name}。" if vm_name != "当前日志包未明确识别" else "当前日志包包含快照整合相关证据，但目标 VM 名称仍需结合现场确认。"]
        if power_cancel:
            items.append("失败发生在关机过程中，日志显示关机动作触发取消 snapshot consolidate。")
        if combine_cancel:
            items.append("合并 / 整合被明确取消，日志出现 Operation was cancelled (33) / Cancelled (34) 等证据。")
        if need_consolidate:
            items.append("当前 VM 仍需要快照整合，配置中存在 snapshot.needConsolidate=TRUE。")
        if snapshot_disks:
            items.append(f"{self._snapshot_disk_label(snapshot_disks)} 仍在 -00000x.vmdk 快照链上。")
        if task_timeout:
            items.append("vpxa / vpxd 中 removeAllSnapshots 任务长期无更新，任务状态存在异常等待或卡住迹象。")
        if chain_status == "continuous":
            items.append("当前没有看到 VMDK 描述符层面的明显断链证据。")
        elif chain_status == "broken":
            items.append("VMDK 描述符链可能异常，需要进一步人工确认。")
        return items

    def _snapshot_other_observations(self, findings: list[dict[str, Any]]) -> list[dict[str, str]]:
        observations = []
        for item in findings:
            title = str(item.get("title") or "")
            if "快照" in title or "虚拟机操作" in title:
                continue
            observations.append(
                {
                    "severity": str(item.get("severity") or "提示"),
                    "category": str(item.get("category") or "日志"),
                    "title": title or str(item.get("description") or "日志观察项"),
                    "recommendation": str(item.get("recommendation") or "建议结合业务影响进一步核查。"),
                }
            )
            if len(observations) >= 5:
                break
        return observations

    def _collect_problem_sources(self, support_bundle_path: Path, problem_profile: dict[str, Any]) -> list[dict[str, Any]]:
        sources: list[dict[str, Any]] = []
        try:
            with zipfile.ZipFile(support_bundle_path) as zf:
                self._collect_problem_sources_from_zip(zf, "", problem_profile, sources)
        except (OSError, zipfile.BadZipFile):
            return sources
        return sources[: self.MAX_PROBLEM_SOURCES]

    def _collect_problem_sources_from_zip(
        self,
        zf: zipfile.ZipFile,
        prefix: str,
        problem_profile: dict[str, Any],
        sources: list[dict[str, Any]],
        depth: int = 0,
    ) -> None:
        if depth >= self.MAX_NESTED_ARCHIVE_DEPTH:
            return
        visited = 0
        for info in zf.infolist():
            visited += 1
            if visited > self.MAX_NESTED_ARCHIVE_MEMBERS:
                return
            if len(sources) >= self.MAX_PROBLEM_SOURCES:
                return
            if info.is_dir():
                continue
            display_path = f"{prefix}{info.filename}"
            lower_name = info.filename.lower()
            if self._is_nested_archive(info.filename):
                try:
                    if lower_name.endswith(".zip"):
                        with self._open_nested_zipfile(zf, info) as nested_zip:
                            self._collect_problem_sources_from_zip(nested_zip, f"{display_path}!", problem_profile, sources, depth=depth + 1)
                    else:
                        with zf.open(info) as nested_stream:
                            self._collect_problem_sources_from_tar(nested_stream, f"{display_path}!", problem_profile, sources)
                except (OSError, zipfile.BadZipFile, tarfile.TarError, _NestedArchiveLimitError):
                    continue
                continue
            kind = self._problem_source_kind(info.filename, info.file_size, problem_profile)
            if not kind:
                continue
            try:
                with zf.open(info) as fh:
                    text = self._decode_text(fh.read(min(info.file_size, self.PROBLEM_READ_LIMIT_BYTES)))
            except OSError:
                continue
            sources.append({"path": self._customer_log_path(display_path), "archive_path": display_path, "kind": kind, "size": info.file_size, "text": text})

    def _collect_problem_sources_from_tar(
        self,
        stream: Any,
        prefix: str,
        problem_profile: dict[str, Any],
        sources: list[dict[str, Any]],
    ) -> None:
        with tarfile.open(fileobj=stream, mode="r|*") as tar:
            for visited, member in enumerate(tar, start=1):
                if visited > self.MAX_NESTED_ARCHIVE_MEMBERS:
                    return
                if len(sources) >= self.MAX_PROBLEM_SOURCES:
                    return
                if not member.isfile():
                    continue
                if self._should_stop_problem_tar_scan(member, sources):
                    return
                display_path = f"{prefix}{member.name}"
                kind = self._problem_source_kind(member.name, member.size, problem_profile)
                if not kind:
                    continue
                text = self._read_tar_member_text(tar, member, self.PROBLEM_READ_LIMIT_BYTES)
                if not text:
                    continue
                sources.append({"path": self._customer_log_path(display_path), "archive_path": display_path, "kind": kind, "size": member.size, "text": text})

    def _problem_source_kind(self, path: str, size: int, problem_profile: dict[str, Any]) -> str | None:
        if self._is_reference_material_file(path):
            return None
        name = Path(path).name.lower()
        lower_path = path.lower().replace("\\", "/")
        if self._is_noisy_problem_source(lower_path):
            return None
        if size > self.PROBLEM_READ_LIMIT_BYTES and not name.endswith((".vmx", ".vmsd")):
            return None
        domains = {str(item) for item in problem_profile.get("domains", [])}
        if name.endswith((".vmx", ".vmsd")):
            return "vm_config"
        runtime_logs = ("vmware.log", "vmkernel.log", "hostd.log", "vpxa.log", "vpxd.log", "vobd.log", "syslog.log", "messages")
        if name in runtime_logs or any(name.startswith(prefix) and ".log" in name for prefix in ("vmware", "vmkernel", "hostd", "vpxa", "vpxd", "vobd", "syslog")):
            return "runtime_log"
        command_terms = self._domain_source_terms(domains)
        if ("/commands/" in lower_path or lower_path.startswith("commands/")) and name.endswith(self.TEXT_SUFFIXES) and any(term in lower_path for term in command_terms):
            return "command_output"
        if name.endswith(self.TEXT_SUFFIXES) and any(term in lower_path for term in command_terms):
            return "domain_text"
        return None

    def _domain_source_terms(self, domains: set[str]) -> tuple[str, ...]:
        terms = {"vmkernel", "hostd", "vpxa", "vpxd", "vobd", "syslog", "messages"}
        if {"迁移", "网络", "虚拟网卡"} & domains:
            terms.update({"network", "esxcfg-info", "dvs", "vds", "dvport", "portgroup", "port_group", "vmnic", "uplink", "vlan", "teaming", "failover", "ethernet"})
        if {"快照", "虚拟机"} & domains:
            terms.update({"vmware", "vmx", "vmsd", "snapshot", "vmdk", "task"})
        if {"认证", "证书"} & domains:
            terms.update({"sso", "sts", "lookupsvc", "identity", "certificate", "ssl", "tls", "vmon"})
        if {"存储", "vSAN"} & domains:
            terms.update({"storage", "vsan", "clomd", "cmmds", "vsanmgmtd", "scsi", "hba", "naa", "datastore"})
        if "服务状态" in domains:
            terms.update({"vmon", "service", "watchdog", "core", "crash"})
        return tuple(sorted(terms))

    def _extract_problem_evidence(self, sources: list[dict[str, Any]], problem_profile: dict[str, Any]) -> list[dict[str, Any]]:
        keywords = self._problem_evidence_keywords(problem_profile)
        objects = [str(item).lower() for item in problem_profile.get("objects", []) if str(item).strip()]
        action_terms = [str(item).lower() for item in problem_profile.get("actions", []) + problem_profile.get("symptoms", []) if str(item).strip()]
        evidence: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for source in sources:
            source_path = str(source.get("path") or "")
            if self._is_reference_material_file(source_path):
                continue
            for line_no, line in enumerate(str(source.get("text") or "").splitlines(), start=1):
                clean = line.strip()
                if not clean:
                    continue
                lower_line = clean.lower()
                object_hit = any(obj and obj in lower_line for obj in objects)
                keyword_hits = [keyword for keyword in keywords if keyword.lower() in lower_line]
                error_hit = bool(re.search(r"\b(error|failed|failure|timeout|timed out|disconnected|disconnect|cancelled|unreachable|reset|link down|dropped|no route)\b", lower_line, re.I))
                action_hit = any(term and term.lower() in lower_line for term in action_terms)
                if not (object_hit or keyword_hits or error_hit):
                    continue
                strength, reason = self._evidence_strength(object_hit, action_hit, error_hit, keyword_hits)
                message = self._trim_line(clean, limit=360)
                key = (source_path, message)
                if key in seen:
                    continue
                seen.add(key)
                evidence.append(
                    {
                        "file": source_path,
                        "location": f"line {line_no}",
                        "level": self._line_level(clean),
                        "message": message,
                        "relevance": reason,
                        "strength": strength,
                    }
                )
                if len(evidence) >= self.MAX_PROBLEM_EVIDENCE:
                    return self._rank_problem_evidence(evidence)
        return self._rank_problem_evidence(evidence)

    def _problem_evidence_keywords(self, problem_profile: dict[str, Any]) -> list[str]:
        keywords: list[str] = []
        domains = {str(item) for item in problem_profile.get("domains", [])}
        for value in list(problem_profile.get("objects") or []) + list(problem_profile.get("actions") or []) + list(problem_profile.get("symptoms") or []):
            text = str(value).strip()
            if text:
                keywords.append(text)
        if "迁移" in domains:
            keywords.extend(["vMotion", "vmotion", "migrate", "migration", "relocate", "Relocate", "Migrate"])
        if "网络" in domains or "虚拟网卡" in domains:
            keywords.extend(["ethernet", "vmxnet3", "connectable", "connected", "disconnect", "reconnect", "networkName", "dvPort", "dvport", "portgroup", "VLAN", "uplink", "vmnic", "link down", "dropped", "unreachable"])
        if "存储" in domains:
            keywords.extend(["datastore", "naa.", "scsi", "hba", "APD", "PDL", "latency"])
        if "vSAN" in domains:
            keywords.extend(["vsan", "clomd", "cmmds", "dom owner", "absent", "degraded"])
        if "认证" in domains:
            keywords.extend(["authentication", "permission", "SSO", "STS", "token", "login"])
        if "证书" in domains:
            keywords.extend(["certificate", "SSL", "TLS", "x509", "thumbprint"])
        return list(dict.fromkeys(keywords))

    def _evidence_strength(self, object_hit: bool, action_hit: bool, error_hit: bool, keyword_hits: list[str]) -> tuple[str, str]:
        if object_hit and (action_hit or error_hit):
            return "强", "同时包含问题对象和动作/症状或明确异常，和客户问题关联度较高。"
        if object_hit:
            return "中", "包含问题对象，但还缺少明确失败动作或结果。"
        if error_hit and keyword_hits:
            return "中", "包含问题领域异常，但未直接出现问题对象。"
        return "弱", "仅包含泛化关键词，不能单独支撑确定性结论。"

    def _rank_problem_evidence(self, evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
        strength_order = {"强": 0, "中": 1, "弱": 2}
        return sorted(evidence, key=lambda item: (strength_order.get(str(item.get("strength")), 9), str(item.get("file")), str(item.get("location"))))[: self.MAX_PROBLEM_EVIDENCE]

    def _generic_confidence(self, evidence_chain: list[dict[str, Any]], problem_profile: dict[str, Any]) -> tuple[str, str]:
        strengths = Counter(str(item.get("strength") or "弱") for item in evidence_chain)
        has_object = bool(problem_profile.get("objects"))
        has_time = bool(problem_profile.get("time_hints"))
        if strengths.get("强", 0) >= 3 and has_object and has_time:
            return "高", "证据链中多次同时出现问题对象、动作/症状和明确异常，并且客户描述提供了时间线。"
        if strengths.get("强", 0) or (strengths.get("中", 0) >= 2 and has_object):
            return "中", "当前能看到对象或问题领域相关线索，但缺少完整时间线、任务事件或关键上下文。"
        return "低", "当前只能确认日志包中存在有限相关线索，不能支撑确定性根因结论。"

    def _likely_directions(self, problem_profile: dict[str, Any]) -> list[str]:
        domains = {str(item) for item in problem_profile.get("domains", [])}
        directions: list[str] = []
        if "迁移" in domains:
            directions.append("vMotion / 迁移任务时间线")
        if "虚拟网卡" in domains:
            directions.append("虚拟网卡连接状态、断开 / 重连和 backing 变化")
        if "网络" in domains:
            directions.extend(["端口组 / VLAN / DVS 端口状态", "目标主机物理上行链路和 teaming/failover", "Guest OS 内部网卡、IP 和路由状态"])
        if "存储" in domains:
            directions.extend(["Datastore 容量和设备路径状态", "存储阵列 / SAN 交换机侧事件"])
        if "vSAN" in domains:
            directions.append("vSAN Health、对象状态和组件同步状态")
        if "认证" in domains:
            directions.append("SSO / STS / 权限和登录失败时间线")
        if "证书" in domains:
            directions.append("证书有效期、信任链和 TLS 握手")
        if not directions:
            directions.append("结合问题对象、发生时间和对应组件日志继续聚焦分析")
        return list(dict.fromkeys(directions))

    def _missing_materials(self, problem_profile: dict[str, Any]) -> list[str]:
        domains = {str(item) for item in problem_profile.get("domains", [])}
        missing = ["故障发生准确时间和恢复时间。"]
        if {"迁移", "网络", "虚拟网卡"} & domains:
            missing.extend(
                [
                    "vCenter 任务和事件截图。",
                    "受影响虚拟机事件页截图。",
                    "虚拟网卡配置截图，包括端口组、连接状态、启动时连接。",
                    "迁移前源主机和迁移后目标主机。",
                    "端口组、VLAN、VDS 端口状态截图。",
                    "目标主机物理上行链路、VLAN trunk、teaming/failover 状态。",
                    "Guest OS 内部 IP、路由、网卡状态。",
                    "对应时间段 vpxd.log、hostd.log、vpxa.log、vmkernel.log、vmware.log。",
                ]
            )
        if {"存储", "vSAN"} & domains:
            missing.extend(["存储 / vSAN Health 截图。", "对应时间段 vmkernel.log、vobd.log、clomd.log、cmmds.log。"])
        if {"认证", "证书"} & domains:
            missing.extend(["对应时间段 vpxd.log、sso/sts/lookupsvc 日志。", "证书状态和登录失败截图。"])
        if not problem_profile.get("objects"):
            missing.append("受影响对象名称，例如虚拟机名、主机名、IP、Datastore 或服务名。")
        return list(dict.fromkeys(missing))

    def _generic_confirmed_items(self, problem_profile: dict[str, Any], evidence_chain: list[dict[str, Any]]) -> list[str]:
        domains = " / ".join(str(item) for item in problem_profile.get("domains", []) if str(item).strip()) or "未知"
        primary_object = str(problem_profile.get("primary_object") or "当前问题描述未明确提供")
        items = [f"客户问题涉及领域为 {domains}。"]
        if primary_object != "当前问题描述未明确提供":
            items.insert(0, f"客户问题中识别到的主要对象为 {primary_object}。")
        if problem_profile.get("time_hints"):
            items.append(f"客户问题中包含时间线索：{'、'.join(str(item) for item in problem_profile.get('time_hints', []))}。")
        else:
            items.append("客户问题中未提供明确故障时间。")
        if evidence_chain:
            strong_count = sum(1 for item in evidence_chain if item.get("strength") == "强")
            medium_count = sum(1 for item in evidence_chain if item.get("strength") == "中")
            items.append(f"当前日志包提取到 {len(evidence_chain)} 条相关线索，其中强证据 {strong_count} 条，中等证据 {medium_count} 条。")
        else:
            items.append("当前日志包未提取到足以直接支撑该现象的关键证据。")
        items.append("静态错误码字典、硬件 ID 字典和帮助文本不会作为现场异常证据。")
        return items

    def _generic_cannot_confirm_items(self, problem_profile: dict[str, Any]) -> list[str]:
        domains = {str(item) for item in problem_profile.get("domains", [])}
        items = [
            "问题发生的完整时间线和恢复时间。",
            "客户侧看到的业务现象是否与日志中的组件事件严格对应。",
        ]
        if {"迁移", "网络", "虚拟网卡"} & domains:
            items.extend(
                [
                    "是否能证明迁移动作直接导致网络不通。",
                    "虚拟网卡是否发生 disconnect / connect / backing / port 变化。",
                    "迁移后 dvPort / portgroup / VLAN 是否正确。",
                    "目标主机物理上行链路和 Guest OS 内部网卡状态是否正常。",
                ]
            )
        return list(dict.fromkeys(items))

    def _generic_current_judgement(self, problem_profile: dict[str, Any], confidence: str) -> str:
        domains = {str(item) for item in problem_profile.get("domains", [])}
        if {"迁移", "网络"} <= domains or {"网络", "虚拟网卡"} <= domains:
            return (
                "当前更适合沿 vMotion / 迁移任务时间线、虚拟网卡连接状态、端口组 / VLAN / DVS 端口、"
                "目标主机物理上行链路以及 Guest OS 内部网卡状态继续排查。"
            )
        if confidence == "低":
            return "当前证据不足，只能作为初步观察，不能直接给出根因判断。"
        return "当前已提取到部分相关线索，但仍需补齐时间线和现场状态后再形成最终判断。"

    def _generic_recommendations(self, problem_profile: dict[str, Any]) -> list[str]:
        directions = self._likely_directions(problem_profile)
        recommendations = [f"建议优先核对{direction}。" for direction in directions[:5]]
        recommendations.append("建议把日志证据与故障发生时间、变更记录和客户侧现象进行交叉确认。")
        recommendations.append("在证据链不完整前，建议避免仅凭单条弱证据下结论。")
        return list(dict.fromkeys(recommendations))

    def _generic_other_observations(self, findings: list[dict[str, Any]]) -> list[dict[str, str]]:
        observations = []
        for item in findings:
            observations.append(
                {
                    "severity": str(item.get("severity") or "提示"),
                    "category": str(item.get("category") or "日志"),
                    "title": str(item.get("title") or item.get("description") or "日志观察项"),
                    "recommendation": str(item.get("recommendation") or "建议结合业务影响进一步核查。"),
                }
            )
            if len(observations) >= 8:
                break
        return observations

    def _build_migration_network_diagnosis(
        self,
        support_bundle_path: Path,
        problem_description: str,
        findings: list[dict[str, Any]],
        problem_profile: dict[str, Any],
    ) -> dict[str, Any]:
        sources = self._collect_migration_network_sources(support_bundle_path)
        all_sources = sources.get("runtime_logs", []) + sources.get("vm_configs", []) + sources.get("network_configs", [])
        vm_name = self._infer_problem_vm_name(problem_description) or self._infer_migration_vm_name_from_sources(all_sources) or "当前日志包未明确识别"
        vmx_entries = self._migration_vmx_entries(sources.get("vm_configs", []), vm_name)
        primary_vmx = self._choose_migration_vmx(vmx_entries, vm_name)

        vm_related_sources = self._migration_related_sources(all_sources, vm_name)
        migration_events = self._matching_source_lines(
            vm_related_sources or all_sources,
            (
                r"\bvMotion\b",
                r"\bvmotion\b",
                r"\bmigrate\b",
                r"\bMigrate\b",
                r"\bRelocate\b",
                r"\brelocate\b",
                r"\bMigration\b",
                r"\bmigration\b",
                r"migrate-",
                r"vmotion-",
            ),
            max_total=10,
        )
        nic_changes = self._matching_source_lines(
            vm_related_sources or all_sources,
            (
                r"ethernet\d+",
                r"vmxnet3",
                r"connectable",
                r"connected",
                r"startConnected",
                r"disconnect",
                r"reconnect",
                r"backing",
                r"networkName",
            ),
            max_total=10,
        )
        port_changes = self._matching_source_lines(
            vm_related_sources or all_sources,
            (
                r"dvport",
                r"dvPort",
                r"portgroup",
                r"port group",
                r"DVS",
                r"DistributedVirtualPort",
                r"VLAN",
                r"uplink",
                r"vmnic",
                r"teaming",
                r"failover",
            ),
            max_total=10,
        )
        transport_events = self._matching_source_lines(
            vm_related_sources or all_sources,
            (
                r"\bVigor\b",
                r"\bvigor\b",
                r"VigorTransport",
                r"\btransport\b",
                r"disconnect",
                r"reconnect",
                r"state transition",
                r"VM state",
                r"power state",
            ),
            max_total=10,
        )
        network_issues = self._matching_source_lines(
            sources.get("runtime_logs", []) + sources.get("network_configs", []),
            (
                r"link down",
                r"link up",
                r"packet drop",
                r"dropped",
                r"blocked",
                r"VLAN mismatch",
                r"port blocked",
                r"no route",
                r"unreachable",
                r"timeout",
                r"reset",
                r"disconnected",
            ),
            max_total=10,
        )
        vm_mentions = self._matching_source_lines(all_sources, (re.escape(vm_name),), max_total=8) if vm_name != "当前日志包未明确识别" else []

        has_migration = bool(migration_events)
        has_nic_or_port = bool(nic_changes or port_changes)
        has_network_path_issue = bool(network_issues)
        has_vm_trace = bool(vm_mentions or primary_vmx)
        if has_migration and has_nic_or_port:
            conclusion = (
                f"客户反馈 {vm_name} 在线迁移后网络不通，重连虚拟网卡后恢复。当前现象更倾向于优先排查虚拟网卡连接状态、"
                "网络 backing、分布式端口绑定、目标主机网络路径或 Guest OS 网卡状态刷新方向。"
                "当前 support bundle 中尚未形成完整证据链，不能仅凭当前日志包确认最终根因。"
            )
            current_judgement = (
                f"当前日志显示 {vm_name} 在相关时间段存在 vMotion / 迁移过程，迁移任务本身显示完成；"
                "同时日志中出现 Vigor transport 断开、重连、VM 状态切换及网络 / 端口相关线索。"
                "结合客户描述“迁移后网络不通，重连虚拟网卡恢复”，当前更倾向于优先排查迁移后虚拟网卡连接状态刷新、"
                "目标主机网络路径、端口组 / DVS 绑定或 Guest OS 网卡状态未及时恢复方向。"
                "当前 support bundle 尚不能单独证明最终根因，不能仅凭当前日志包确认最终根因。"
            )
        elif has_network_path_issue:
            conclusion = (
                f"客户反馈 {vm_name} 在线迁移后网络不通，重连虚拟网卡后恢复。当前日志包发现网络链路、端口、VLAN 或上行链路相关线索，"
                "但尚未能把这些线索与该 VM 的迁移任务直接串成完整证据链，不能仅凭当前日志包确认最终根因。"
            )
            current_judgement = (
                "结合客户描述“迁移后网络不通，重连虚拟网卡恢复”，当前日志更倾向于优先排查目标主机侧网络路径、"
                "端口组 / VLAN、分布式端口或上行链路方向；但缺少迁移任务与虚拟网卡状态变化闭环，"
                "当前 support bundle 尚不能单独证明最终根因。"
            )
        elif has_vm_trace:
            conclusion = (
                f"客户反馈 {vm_name} 在线迁移后网络不通，重连虚拟网卡后恢复。当前日志包能识别问题虚拟机或相关配置，"
                "但缺少迁移任务、虚拟网卡断连、DVS 端口变化等关键证据，暂不能确认迁移后网络不通的直接原因。"
            )
            current_judgement = (
                f"当前日志包能识别问题虚拟机 {vm_name}，但缺少迁移任务、虚拟网卡断连、DVS 端口变化等关键证据。"
                "结合客户描述“迁移后网络不通，重连虚拟网卡恢复”，目前只能把虚拟网卡连接状态、端口组 / DVS 绑定、"
                "目标主机网络路径或 Guest OS 网卡状态刷新列为优先排查方向，当前 support bundle 尚不能单独证明最终根因。"
            )
        else:
            conclusion = (
                f"客户反馈 {vm_name} 在线迁移后网络不通，重连虚拟网卡后恢复。当前 support bundle 中尚未形成完整证据链，"
                "不能仅凭当前日志包确认最终根因。"
            )
            current_judgement = (
                "当前日志包缺少可直接关联该 VM、迁移任务和虚拟网卡状态变化的关键证据。"
                "结合客户描述“迁移后网络不通，重连虚拟网卡恢复”，建议优先补齐迁移事件、vNIC 连接状态、"
                "端口组 / DVS、目标主机网络路径和 Guest OS 网卡状态材料；当前 support bundle 尚不能单独证明最终根因。"
            )

        evidence_sections = [
            {
                "title": "vMotion / 迁移 / Relocate 相关事件",
                "log_file": self._first_file(migration_events),
                "excerpts": migration_events,
                "judgement": "当前日志包提取到迁移相关线索。" if migration_events else "当前日志包未提取到可直接关联该 VM 的迁移任务事件。",
            },
            {
                "title": "虚拟网卡连接状态或 backing 变化",
                "log_file": self._first_file(nic_changes),
                "excerpts": nic_changes,
                "judgement": "当前日志包提取到虚拟网卡连接状态或 backing 相关线索。" if nic_changes else "当前日志包未提取到虚拟网卡断开、重连或 backing 变化的直接证据。",
            },
            {
                "title": "Vigor transport 断开、重连或 VM 状态切换线索",
                "log_file": self._first_file(transport_events),
                "excerpts": transport_events,
                "judgement": "当前日志包提取到 Vigor transport、断开重连或 VM 状态切换相关线索。" if transport_events else "当前日志包未提取到 Vigor transport 或 VM 状态切换的直接证据。",
            },
            {
                "title": "分布式端口、端口组、VLAN 或上行链路线索",
                "log_file": self._first_file(port_changes),
                "excerpts": port_changes,
                "judgement": "当前日志包提取到端口组、dvPort、VLAN 或上行链路相关线索。" if port_changes else "当前日志包未提取到端口组、dvPort、VLAN 或上行链路变化的直接证据。",
            },
            {
                "title": "网络链路或连通性异常线索",
                "log_file": self._first_file(network_issues),
                "excerpts": network_issues,
                "judgement": "当前日志包提取到网络链路或连通性相关线索。" if network_issues else "当前日志包未提取到可作为现场异常的网络链路证据。",
            },
            {
                "title": "问题 VM 相关日志或配置线索",
                "log_file": self._first_file(vm_mentions),
                "excerpts": vm_mentions,
                "judgement": "当前日志包能定位到问题 VM 的相关痕迹。" if has_vm_trace else "当前日志包未提取到足够的问题 VM 相关痕迹。",
            },
        ]

        supplemental_info = [
            "故障发生时间点和重连虚拟网卡的操作时间。",
            "迁移任务截图或 vCenter Task/Event 记录，过滤 esx-host-01，覆盖迁移前后时间段。",
            "esx-host-01 虚拟机“事件”页截图。",
            "迁移前源主机和迁移后目标主机名称。",
            "VM 迁移前后的端口组、分布式端口、VLAN 信息。",
            "重连虚拟网卡前后的 vNIC connect 状态截图，包括“已连接”和“启动时连接”。",
            "故障时 Guest OS 内网卡状态、IP、路由、ARP、网关连通性截图或命令输出。",
            "源 / 目标主机的物理网卡、VLAN trunk、端口组配置截图。",
            "如涉及 DVS，补充分布式交换机 dvPort、vmkernel、uplink 状态截图或命令输出。",
            "对应时间段 vpxd.log、hostd.log、vpxa.log、vmkernel.log、vmware.log。",
        ]
        confirmed_items = [
            f"客户描述的问题对象为 {vm_name}。",
            "通用网络错误码字典、硬件 ID 字典和静态清单不能作为现场异常证据。",
            "当前是否存在迁移任务和网卡状态变化，仍需要结合 vCenter 任务事件和 VM 日志进一步确认。",
        ]
        if has_vm_trace:
            confirmed_items.insert(1, f"当前日志包中能找到 {vm_name} 相关配置或运行痕迹。")
        cannot_confirm_items = [
            "迁移发生的准确时间点。",
            "源主机和目标主机。",
            "迁移前后 VM 网卡连接状态是否变化。",
            "迁移后 VM 连接到的 dvPort / portgroup / VLAN 是否正确。",
            "目标主机物理上行链路、VLAN trunk、teaming/failover 是否正常。",
            "Guest OS 内部网卡是否发生链路刷新、IP 丢失、网关 / 路由异常。",
            "重连虚拟网卡的具体操作时间和对应事件。",
        ]
        handling_recommendations = [
            "建议优先确认迁移任务时间线和源 / 目标主机。",
            "建议核对目标主机上端口组、VLAN、物理上行链路和 teaming/failover 是否与源主机一致。",
            f"建议核对 {vm_name} 虚拟网卡是否仍连接到正确端口组，并启用“已连接/启动时连接”。",
            "如果重连网卡后恢复，建议重点排查虚拟网卡连接状态刷新、DVS 端口绑定、目标主机网络路径和 Guest OS 网卡状态。",
            "建议避免在证据不足时直接执行高风险变更，先补齐任务事件和网络路径证据。",
        ]

        key_evidence_count = sum(len(section.get("excerpts", [])) for section in evidence_sections)
        evidence_chain = self._migration_evidence_chain(evidence_sections)
        confidence = "中" if has_migration and (has_nic_or_port or has_network_path_issue) else "低"
        confidence_reason = (
            "当前能看到迁移、虚拟网卡或网络路径相关线索，但缺少完整任务事件、源目标主机和 Guest OS 状态闭环。"
            if confidence == "中"
            else "当前只能确认日志包中存在有限相关线索，不能支撑确定性根因结论。"
        )
        domains = list(dict.fromkeys(["迁移", "网络", "虚拟网卡"] + [str(item) for item in problem_profile.get("domains", [])]))
        actions = list(dict.fromkeys([str(item) for item in problem_profile.get("actions", [])] or ["迁移", "重连"]))
        symptoms = list(dict.fromkeys([str(item) for item in problem_profile.get("symptoms", [])] or ["网络不通"]))
        time_hints = list(problem_profile.get("time_hints") or [])
        return {
            "scenario": "vm_migration_network_loss",
            "title": scenario_title("vm_migration_network_loss", "在线迁移后虚拟机网络不通诊断报告"),
            "diagnosis_title": scenario_title("vm_migration_network_loss", "在线迁移后虚拟机网络不通诊断报告"),
            "customer_question": problem_description,
            "problem_summary": f"客户描述 {vm_name} 在线迁移后网络不通，重连虚拟网卡后恢复。",
            "problem_profile": problem_profile,
            "conclusion": conclusion,
            "can_fully_determine": False,
            "fully_determine_text": "否，当前不能仅凭该 support bundle 完全确认迁移后网络不通的最终根因，不能仅凭当前日志包确认最终根因。",
            "missing_materials": supplemental_info,
            "key_evidence_count": key_evidence_count,
            "affected_objects": {
                "primary_object": vm_name,
                "objects": [item for item in list(problem_profile.get("objects") or [vm_name]) if item],
                "domains": domains,
                "actions": actions,
                "symptoms": symptoms,
                "time_hints": time_hints,
                "vm_name": vm_name,
                "vmx_path": str((primary_vmx or {}).get("path") or "当前日志包未明确识别"),
                "host": self._infer_host_from_path(str((primary_vmx or {}).get("archive_path") or (primary_vmx or {}).get("path") or "")) or "当前日志包未明确识别",
                "network_adapters": list((primary_vmx or {}).get("network_adapters") or []),
                "source_host": "需要结合 vCenter 任务事件确认",
                "target_host": "需要结合 vCenter 任务事件确认",
            },
            "likely_direction": [
                "vMotion / 迁移任务时间线",
                "虚拟网卡连接状态、断开 / 重连和 backing 变化",
                "端口组 / VLAN / DVS 端口状态",
                "目标主机物理上行链路和 teaming/failover",
                "Guest OS 内部网卡、IP 和路由状态",
            ],
            "confidence": confidence,
            "confidence_reason": confidence_reason,
            "evidence_chain": evidence_chain,
            "evidence_sections": evidence_sections,
            "current_judgement": current_judgement,
            "what_can_be_confirmed": confirmed_items,
            "what_cannot_be_confirmed": cannot_confirm_items,
            "confirmed_items": confirmed_items,
            "cannot_confirm_items": cannot_confirm_items,
            "supplemental_info": supplemental_info,
            "recommended_next_steps": handling_recommendations,
            "handling_recommendations": handling_recommendations,
            "other_observations": self._migration_other_observations(findings),
        }

    def _migration_evidence_chain(self, evidence_sections: list[dict[str, Any]]) -> list[dict[str, Any]]:
        evidence: list[dict[str, Any]] = []
        for section in evidence_sections:
            title = str(section.get("title") or "")
            for item in section.get("excerpts", []) or []:
                if not isinstance(item, dict):
                    continue
                file_path = str(item.get("file") or "")
                if self._is_reference_material_file(file_path):
                    continue
                evidence.append(
                    {
                        "strength": "中",
                        "file": file_path,
                        "location": str(item.get("location") or ""),
                        "level": str(item.get("level") or ""),
                        "message": str(item.get("message") or ""),
                        "relevance": f"该日志摘录属于“{title}”，与客户描述的迁移后网络异常方向相关。",
                    }
                )
                if len(evidence) >= self.MAX_PROBLEM_EVIDENCE:
                    return evidence
        return evidence

    def _collect_migration_network_sources(self, support_bundle_path: Path) -> dict[str, list[dict[str, Any]]]:
        sources: dict[str, list[dict[str, Any]]] = {
            "runtime_logs": [],
            "vm_configs": [],
            "network_configs": [],
        }
        try:
            with zipfile.ZipFile(support_bundle_path) as zf:
                self._collect_migration_from_zip(zf, "", sources)
        except (OSError, zipfile.BadZipFile):
            return sources
        return sources

    def _collect_migration_from_zip(
        self,
        zf: zipfile.ZipFile,
        prefix: str,
        sources: dict[str, list[dict[str, Any]]],
        depth: int = 0,
    ) -> None:
        if depth >= self.MAX_NESTED_ARCHIVE_DEPTH:
            return
        for visited, info in enumerate(zf.infolist(), start=1):
            if visited > self.MAX_NESTED_ARCHIVE_MEMBERS:
                return
            if info.is_dir():
                continue
            display_path = f"{prefix}{info.filename}"
            lower_name = info.filename.lower()
            if self._is_nested_archive(info.filename):
                try:
                    if lower_name.endswith(".zip"):
                        with self._open_nested_zipfile(zf, info) as nested_zip:
                            self._collect_migration_from_zip(nested_zip, f"{display_path}!", sources, depth=depth + 1)
                    else:
                        with zf.open(info) as nested_stream:
                            self._collect_migration_from_tar(nested_stream, f"{display_path}!", sources)
                except (OSError, zipfile.BadZipFile, tarfile.TarError, _NestedArchiveLimitError):
                    continue
                continue
            kind = self._migration_source_kind(info.filename, info.file_size)
            if not kind:
                continue
            try:
                text = self._read_migration_zip_text(zf, info)
            except OSError:
                continue
            self._add_migration_source(sources, kind, display_path, info.file_size, text)

    def _collect_migration_from_tar(self, stream: Any, prefix: str, sources: dict[str, list[dict[str, Any]]]) -> None:
        with tarfile.open(fileobj=stream, mode="r|*") as tar:
            for visited, member in enumerate(tar, start=1):
                if visited > self.MAX_NESTED_ARCHIVE_MEMBERS:
                    return
                if not member.isfile():
                    continue
                display_path = f"{prefix}{member.name}"
                kind = self._migration_source_kind(member.name, member.size)
                if not kind:
                    continue
                text = self._read_tar_member_text(tar, member, self.MIGRATION_READ_LIMIT_BYTES)
                if not text:
                    continue
                self._add_migration_source(sources, kind, display_path, member.size, text)

    def _migration_source_kind(self, path: str, size: int) -> str | None:
        if self._is_reference_material_file(path):
            return None
        name = Path(path).name.lower()
        lower_path = path.lower().replace("\\", "/")
        if size > self.MIGRATION_READ_LIMIT_BYTES and not name.endswith(".vmx"):
            return None
        if name.endswith(".vmx"):
            return "vm_configs"
        runtime_log_names = ("vmware.log", "vmkernel.log", "hostd.log", "vpxa.log", "vpxd.log", "vobd.log", "syslog.log", "messages")
        if name in runtime_log_names or any(name.startswith(prefix) and ".log" in name for prefix in ("vmware", "vmkernel", "hostd", "vpxa", "vpxd", "vobd", "syslog")):
            return "runtime_logs"
        command_terms = ("esxcfg-info", "esxcli", "localcli", "network", "dvs", "portgroup", "port_group", "vmnic", "uplink", "vlan", "teaming", "failover")
        if ("/commands/" in lower_path or lower_path.startswith("commands/")) and name.endswith(self.TEXT_SUFFIXES) and any(term in lower_path for term in command_terms):
            return "network_configs"
        return None

    def _read_migration_zip_text(self, zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> str:
        with zf.open(info) as fh:
            data = fh.read(min(info.file_size, self.MIGRATION_READ_LIMIT_BYTES))
        return self._decode_text(data)

    def _add_migration_source(self, sources: dict[str, list[dict[str, Any]]], kind: str, path: str, size: int, text: str) -> None:
        sources[kind].append(
            {
                "path": self._customer_log_path(path),
                "archive_path": path,
                "size": size,
                "text": text,
            }
        )

    def _migration_vmx_entries(self, sources: list[dict[str, Any]], vm_name: str) -> list[dict[str, Any]]:
        entries = []
        for source in sources:
            text = str(source.get("text") or "")
            nics: dict[str, dict[str, str]] = {}
            for match in re.finditer(r'(?im)^\s*(ethernet\d+)\.([A-Za-z0-9_.-]+)\s*=\s*"?(.*?)"?\s*$', text):
                adapter = match.group(1)
                key = match.group(2)
                value = match.group(3).strip()
                nics.setdefault(adapter, {"adapter": adapter})[key] = value
            network_adapters = []
            for adapter, values in sorted(nics.items()):
                network_adapters.append(
                    {
                        "adapter": adapter,
                        "network": values.get("networkName") or values.get("distributedVirtualPort.portgroupKey") or "未记录",
                        "connected": values.get("connectable.connected") or values.get("connected") or "未记录",
                        "start_connected": values.get("connectable.startConnected") or values.get("startConnected") or "未记录",
                        "device": values.get("virtualDev") or "未记录",
                    }
                )
            entries.append(
                {
                    **source,
                    "display_name": self._config_value(text, "displayName"),
                    "network_adapters": network_adapters,
                    "matches_problem_vm": self._source_mentions_vm(source, vm_name),
                }
            )
        return entries

    def _choose_migration_vmx(self, vmx_entries: list[dict[str, Any]], vm_name: str) -> dict[str, Any] | None:
        if not vmx_entries:
            return None

        def score(item: dict[str, Any]) -> tuple[int, int, str]:
            return (
                1 if item.get("matches_problem_vm") else 0,
                len(item.get("network_adapters") or []),
                str(item.get("display_name") or item.get("path") or ""),
            )

        return sorted(vmx_entries, key=score, reverse=True)[0]

    def _migration_related_sources(self, sources: list[dict[str, Any]], vm_name: str) -> list[dict[str, Any]]:
        if not vm_name or vm_name == "当前日志包未明确识别":
            return []
        related = [source for source in sources if self._source_mentions_vm(source, vm_name)]
        return related

    def _source_mentions_vm(self, source: dict[str, Any], vm_name: str) -> bool:
        if not vm_name or vm_name == "当前日志包未明确识别":
            return False
        needle = vm_name.lower()
        return needle in str(source.get("path") or "").lower() or needle in str(source.get("archive_path") or "").lower() or needle in str(source.get("text") or "").lower()

    def _infer_problem_vm_name(self, problem_description: str) -> str:
        candidates = re.findall(r"[A-Za-z][A-Za-z0-9_.-]{2,}", problem_description)
        stop_words = {
            "vmware",
            "vmotion",
            "migrate",
            "relocate",
            "migration",
            "network",
            "dvport",
            "portgroup",
            "vlan",
            "guest",
        }
        for candidate in candidates:
            if candidate.lower() not in stop_words:
                return candidate.strip(".,;:，。；：")
        return ""

    def _infer_migration_vm_name_from_sources(self, sources: list[dict[str, Any]]) -> str:
        for source in sources:
            display_name = self._config_value(str(source.get("text") or ""), "displayName")
            if display_name:
                return display_name
        return ""

    def _infer_host_from_path(self, path: str) -> str:
        normalized = path.replace("\\", "/")
        match = re.search(r"(?:^|[!/])([^/!]+)/(?:var|vmfs|etc|commands)/", normalized)
        if match:
            return match.group(1)
        return ""

    def _migration_other_observations(self, findings: list[dict[str, Any]]) -> list[dict[str, str]]:
        observations = []
        for item in findings:
            observations.append(
                {
                    "severity": str(item.get("severity") or "提示"),
                    "category": str(item.get("category") or "日志"),
                    "title": str(item.get("title") or item.get("description") or "日志观察项"),
                    "recommendation": str(item.get("recommendation") or "建议结合业务影响进一步核查。"),
                }
            )
            if len(observations) >= 5:
                break
        return observations

    def _config_value(self, text: str, key: str) -> str:
        match = re.search(rf'(?im)^\s*{re.escape(key)}\s*=\s*"?(.*?)"?\s*$', text)
        return match.group(1).strip() if match else ""

    def _first_file(self, excerpts: list[dict[str, Any]]) -> str:
        return str((excerpts[0] if excerpts else {}).get("file") or "当前日志包未提取到对应文件")

    def _infer_vm_name_from_sources(self, sources: dict[str, list[dict[str, Any]]]) -> str:
        for source in sources.get("vmdk", []):
            name = Path(str(source.get("path") or "")).name
            if self._is_snapshot_vmdk_name(name):
                return self._vmdk_chain_root(name)
        return ""

    def _snapshot_disk_label(self, snapshot_disks: list[dict[str, Any]]) -> str:
        if not snapshot_disks:
            return "部分磁盘"
        first = snapshot_disks[0]
        return f"{first.get('controller') or '磁盘'}"

    def _snapshot_datastore_paths(self, snapshot_disks: list[dict[str, Any]]) -> list[str]:
        paths = []
        for disk in snapshot_disks:
            file_path = str(disk.get("file") or "")
            marker = "/vmfs/volumes/"
            if file_path.startswith(marker):
                parts = file_path.split("/")
                if len(parts) >= 4:
                    paths.append("/".join(parts[:4]))
        return list(dict.fromkeys(paths))

    def _vmdk_chain_root(self, filename: str) -> str:
        name = Path(filename).name
        if self._is_snapshot_vmdk_name(name):
            name = re.sub(r"-(\d{6,})(?=\.vmdk$)", "", name, flags=re.I)
        return name.removesuffix(".vmdk")

    def _vmdk_snapshot_index(self, filename: str) -> int:
        match = re.search(r"-(\d{6,})\.vmdk$", filename, re.I)
        return int(match.group(1)) if match else 0

    def _customer_dir(self, path: str) -> str:
        normalized = path.replace("\\", "/")
        if "/" not in normalized:
            return ""
        return normalized.rsplit("/", 1)[0]

    def _customer_log_path(self, path: str) -> str:
        normalized = path.replace("\\", "/")
        if "!" in normalized:
            normalized = normalized.split("!", 1)[1]
        for marker in ("/vmfs/", "/var/", "/etc/"):
            index = normalized.find(marker)
            if index >= 0:
                return normalized[index:]
        parts = normalized.split("/")
        for marker in ("vmfs", "var", "etc"):
            if marker in parts:
                index = parts.index(marker)
                return "/" + "/".join(parts[index:])
        return Path(normalized).name

    def _findings_from_evidence(self, evidence_by_key: dict[str, list[dict[str, Any]]], problem_description: str) -> list[dict[str, Any]]:
        problem_tokens = self._problem_tokens(problem_description)
        findings: list[dict[str, Any]] = []
        for pattern in self.PATTERNS:
            evidence = evidence_by_key.get(str(pattern["key"]), [])
            if not evidence:
                continue
            problem_boost = any(token and token in str(pattern["title"]).lower() for token in problem_tokens)
            findings.append(
                {
                    "severity": pattern["severity"],
                    "category": pattern["category"],
                    "title": pattern["title"],
                    "description": f"检测到 {len(evidence)} 条相关日志证据。{pattern['impact']}",
                    "recommendation": pattern["recommendation"],
                    "problem_related": problem_boost,
                    "evidence": evidence,
                }
            )
        severity_order = {"高": 0, "中": 1, "低": 2}
        findings.sort(key=lambda item: (0 if item.get("problem_related") else 1, severity_order.get(str(item.get("severity")), 9), str(item.get("category"))))
        return findings

    def _recommendations(self, findings: list[dict[str, Any]]) -> list[str]:
        if not findings:
            return [
                "建议补充问题发生时间窗口、受影响对象和现象截图，以便继续聚焦分析。",
                "建议保留原始 support bundle，避免重复导出导致时间窗口发生偏移。",
            ]
        result = []
        for item in findings[:5]:
            result.append(str(item.get("recommendation") or "建议结合业务影响进一步核查。"))
        result.append("建议将日志证据与问题发生时间、变更记录和业务影响范围进行交叉确认。")
        return list(dict.fromkeys(result))

    def _insert_log_report(self, conn, log_run_id: str, report_name: str, report_type: str, path: Path, status: str, error: str | None = None) -> None:
        now = utc_now_iso()
        conn.execute(
            """
            INSERT INTO log_analysis_reports (
              report_id, log_run_id, report_name, report_type, report_status,
              file_path, generated_at, error_message, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                new_id("logrep"),
                log_run_id,
                report_name,
                report_type,
                status,
                str(path),
                now if status == "success" else None,
                error,
                now,
                now,
            ),
        )

    def _insert_run_row(self, cfg: LogAnalysisConfig, log_run_id: str, started_at: str) -> None:
        def operation() -> None:
            with connect(cfg.db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO log_analysis_runs (
                      log_run_id, customer_name, report_title, support_bundle_path,
                      support_bundle_name, problem_description, run_status,
                      current_stage, progress_percent, started_at, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        log_run_id,
                        cfg.customer_name,
                        cfg.report_title,
                        str(cfg.support_bundle_path),
                        cfg.support_bundle_path.name,
                        cfg.problem_description,
                        "running",
                        "started",
                        5,
                        started_at,
                        started_at,
                        started_at,
                    ),
                )

        with_db_retry(operation)

    def _mark_run_success(
        self,
        cfg: LogAnalysisConfig,
        log_run_id: str,
        payload: dict[str, Any],
        html_path: Path,
        docx_path: Path,
        finished_at: str,
    ) -> None:
        def operation() -> None:
            with connect(cfg.db_path) as conn:
                conn.execute(
                    """
                    UPDATE log_analysis_runs
                    SET run_status = 'success', current_stage = 'success', progress_percent = 100,
                        summary_json = ?, finished_at = ?, updated_at = ?
                    WHERE log_run_id = ?
                    """,
                    (json.dumps(payload.get("summary", {}), ensure_ascii=False), finished_at, finished_at, log_run_id),
                )
                meta = payload.get("metadata", {}) if isinstance(payload.get("metadata"), dict) else {}
                report_name = str(meta.get("report_title") or cfg.report_title or DEFAULT_LOG_CHECK_TITLE)
                self._insert_log_report(conn, log_run_id, report_name, "log_analysis_html", html_path, "success")
                self._insert_log_report(conn, log_run_id, report_name, "log_analysis_docx", docx_path, "success")

        with_db_retry(operation)

    def _mark_run_failed(self, cfg: LogAnalysisConfig, log_run_id: str, message: str) -> None:
        def operation() -> None:
            finished_at = utc_now_iso()
            with connect(cfg.db_path) as conn:
                conn.execute(
                    """
                    UPDATE log_analysis_runs
                    SET run_status = 'failed', current_stage = 'failed', progress_percent = 100,
                        error_message = ?, finished_at = ?, updated_at = ?
                    WHERE log_run_id = ?
                    """,
                    (message, finished_at, finished_at, log_run_id),
                )

        with_db_retry(operation)

    def _emit(
        self,
        progress_callback: Callable[[LogAnalysisProgress], None] | None,
        run_id: str | None,
        stage: str,
        percent: int,
        message: str,
        error: str | None = None,
    ) -> None:
        if progress_callback:
            progress_callback(LogAnalysisProgress(run_id=run_id, stage=stage, percent=percent, message=message, error=error))

    def _is_log_file(self, path: str) -> bool:
        if self._is_reference_material_file(path):
            return False
        name = Path(path).name.lower()
        lower_path = path.lower()
        return name.endswith(self.TEXT_SUFFIXES) or any(hint in lower_path for hint in self.LOG_HINTS)

    def _is_reference_material_file(self, path: str) -> bool:
        return EvidenceExtractor.is_reference_material_file(path)

    def _is_noisy_problem_source(self, lower_path: str) -> bool:
        normalized = lower_path.replace("\\", "/")
        if self._is_reference_material_file(normalized):
            return True
        return any(term in normalized for term in self.NOISY_PROBLEM_SOURCE_TERMS)

    def _should_skip_large_nested_archive(self, info: zipfile.ZipInfo, scenario: str | None) -> bool:
        if info.file_size <= self.LARGE_NESTED_ARCHIVE_BYTES:
            return False
        # Snapshot and migration/network diagnosis have their own focused collectors.
        # Avoid loading very large nested archives during the broad file-list scan.
        return scenario in {"snapshot_consolidation_failure", "vm_migration_network_loss", None}

    def _should_stop_problem_tar_scan(self, member: tarfile.TarInfo, sources: list[dict[str, Any]]) -> bool:
        if len(sources) >= self.MAX_PROBLEM_SOURCES:
            return True
        if member.size > self.LARGE_TAR_MEMBER_BYTES and sources:
            return True
        return False

    def _is_nested_archive(self, path: str) -> bool:
        lower_path = path.lower()
        return any(lower_path.endswith(suffix) for suffix in self.NESTED_ARCHIVE_SUFFIXES)

    def _scan_nested_archive(
        self,
        zf: zipfile.ZipFile,
        info: zipfile.ZipInfo,
        files: list[dict[str, Any]],
        evidence_by_key: dict[str, list[dict[str, Any]]],
        scanned_log_files: int,
    ) -> dict[str, Any]:
        lower_name = info.filename.lower()
        if lower_name.endswith(".zip"):
            return self._scan_nested_zip(zf, info, files, evidence_by_key, scanned_log_files)
        return self._scan_nested_tar(zf, info, files, evidence_by_key, scanned_log_files)

    def _scan_nested_zip(
        self,
        zf: zipfile.ZipFile,
        info: zipfile.ZipInfo,
        files: list[dict[str, Any]],
        evidence_by_key: dict[str, list[dict[str, Any]]],
        scanned_log_files: int,
    ) -> dict[str, Any]:
        log_file_count = 0
        files_truncated = False
        try:
            with self._open_nested_zipfile(zf, info) as nested_zip:
                for visited, nested_info in enumerate(nested_zip.infolist(), start=1):
                    if visited > self.MAX_NESTED_ARCHIVE_MEMBERS:
                        files_truncated = True
                        break
                    if nested_info.is_dir():
                        continue
                    if len(files) >= self.MAX_ARCHIVE_FILES:
                        files_truncated = True
                        break
                    display_path = f"{info.filename}!{nested_info.filename}"
                    is_log = self._is_log_file(nested_info.filename)
                    if is_log:
                        log_file_count += 1
                        if scanned_log_files < self.MAX_LOG_FILES:
                            text = self._read_zip_text_sample(nested_zip, nested_info)
                            self._collect_evidence(display_path, text, evidence_by_key)
                            scanned_log_files += 1
                    files.append(
                        {
                            "path": display_path,
                            "size": nested_info.file_size,
                            "size_label": self._size_label(nested_info.file_size),
                            "is_log": is_log,
                        }
                    )
        except (OSError, zipfile.BadZipFile, _NestedArchiveLimitError):
            files_truncated = True
            files.append(
                {
                    "path": info.filename,
                    "size": info.file_size,
                    "size_label": self._size_label(info.file_size),
                    "is_log": False,
                }
            )
        return {"log_file_count": log_file_count, "scanned_log_files": scanned_log_files, "files_truncated": files_truncated}

    def _scan_nested_tar(
        self,
        zf: zipfile.ZipFile,
        info: zipfile.ZipInfo,
        files: list[dict[str, Any]],
        evidence_by_key: dict[str, list[dict[str, Any]]],
        scanned_log_files: int,
    ) -> dict[str, Any]:
        log_file_count = 0
        files_truncated = False
        try:
            if info.file_size > self.LARGE_NESTED_ARCHIVE_BYTES:
                raise _NestedArchiveLimitError("nested tar archive exceeds size limit")
            with zf.open(info) as nested_stream:
                with tarfile.open(fileobj=nested_stream, mode="r|*") as tar:
                    for visited, member in enumerate(tar, start=1):
                        if visited > self.MAX_NESTED_ARCHIVE_MEMBERS:
                            files_truncated = True
                            break
                        if not member.isfile():
                            continue
                        if len(files) >= self.MAX_ARCHIVE_FILES:
                            files_truncated = True
                            break
                        display_path = f"{info.filename}!{member.name}"
                        is_log = self._is_log_file(member.name)
                        if is_log:
                            log_file_count += 1
                            if scanned_log_files < self.MAX_LOG_FILES:
                                text = self._read_tar_member_text(tar, member, self.READ_LIMIT_BYTES)
                                if text:
                                    self._collect_evidence(display_path, text, evidence_by_key)
                                    scanned_log_files += 1
                        files.append(
                            {
                                "path": display_path,
                                "size": member.size,
                                "size_label": self._size_label(member.size),
                                "is_log": is_log,
                            }
                        )
        except (OSError, tarfile.TarError, _NestedArchiveLimitError):
            files_truncated = True
            files.append(
                {
                    "path": info.filename,
                    "size": info.file_size,
                    "size_label": self._size_label(info.file_size),
                    "is_log": False,
                }
            )
        return {"log_file_count": log_file_count, "scanned_log_files": scanned_log_files, "files_truncated": files_truncated}

    def _collect_evidence(self, file_path: str, text: str, evidence_by_key: dict[str, list[dict[str, Any]]]) -> None:
        if self._is_reference_material_file(file_path):
            return
        for line_no, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            for pattern in self.PATTERNS:
                if len(evidence_by_key[str(pattern["key"])]) >= self.MAX_EVIDENCE_PER_FINDING:
                    continue
                match = pattern["regex"].search(line)
                if match:
                    evidence_by_key[str(pattern["key"])].append(
                        {
                            "file": file_path,
                            "location": f"line {line_no}",
                            "level": self._line_level(line),
                            "message": self._trim_line(line),
                        }
                    )

    def _read_zip_text_sample(self, zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> str:
        with zf.open(info) as fh:
            data = fh.read(min(info.file_size, self.READ_LIMIT_BYTES))
        return self._decode_text(data)

    def _decode_text(self, data: bytes) -> str:
        utf_candidates = ("utf-8", "utf-8-sig")
        for encoding in utf_candidates:
            try:
                return data.decode(encoding)
            except (LookupError, UnicodeDecodeError):
                continue

        east_asian_candidates = ("gb18030", "cp932", "shift_jis", "euc_jp", "euc_kr")
        decoded_candidates: list[tuple[int, int, str]] = []
        for index, encoding in enumerate(east_asian_candidates):
            try:
                text = data.decode(encoding)
            except (LookupError, UnicodeDecodeError):
                continue
            decoded_candidates.append((self._decoded_text_score(text), -index, text))
        if decoded_candidates:
            return max(decoded_candidates)[2]

        for encoding in (*utf_candidates, *east_asian_candidates):
            try:
                return data.decode(encoding, errors="replace")
            except LookupError:
                continue
        return data.decode("latin-1", errors="replace")

    def _decoded_text_score(self, text: str) -> int:
        score = 0
        for char in text:
            code = ord(char)
            if 0x3040 <= code <= 0x30ff or 0xff66 <= code <= 0xff9d:
                score += 4
            elif 0xac00 <= code <= 0xd7af:
                score += 3
            elif 0x4e00 <= code <= 0x9fff:
                score += 1
            elif char.isascii() and (char.isalnum() or char.isspace() or char in "._:-/\\[](){}=,;!?'\""):
                score += 1
            elif char == "\ufffd":
                score -= 5
        return score

    def _is_snapshot_vmdk_name(self, filename: str) -> bool:
        return bool(re.search(r"-(\d{6,})\.vmdk$", Path(filename).name, re.I))

    def _read_tar_member_text(self, tar: tarfile.TarFile, member: tarfile.TarInfo, limit: int) -> str:
        if member.size > self.LARGE_TAR_MEMBER_BYTES:
            return ""
        try:
            extracted = tar.extractfile(member)
        except (OSError, tarfile.TarError, ValueError):
            return ""
        if extracted is None:
            return ""
        with closing(extracted):
            try:
                data = extracted.read(min(member.size, limit))
            except (OSError, tarfile.TarError, EOFError, ValueError):
                return ""
        return self._decode_text(data)

    @contextmanager
    def _open_nested_zipfile(self, zf: zipfile.ZipFile, info: zipfile.ZipInfo):
        if info.file_size > self.LARGE_NESTED_ARCHIVE_BYTES:
            raise _NestedArchiveLimitError("nested zip archive exceeds size limit")
        with zf.open(info) as nested_stream:
            with tempfile.SpooledTemporaryFile(max_size=self.NESTED_ARCHIVE_SPOOL_BYTES) as temp_file:
                self._copy_stream_with_limit(nested_stream, temp_file, self.LARGE_NESTED_ARCHIVE_BYTES)
                temp_file.seek(0)
                with zipfile.ZipFile(temp_file) as nested_zip:
                    yield nested_zip

    def _copy_stream_with_limit(self, stream: Any, target: Any, limit: int) -> int:
        total = 0
        chunk_size = 1024 * 1024
        while True:
            chunk = stream.read(chunk_size)
            if not chunk:
                return total
            total += len(chunk)
            if total > limit:
                raise _NestedArchiveLimitError("nested archive read limit exceeded")
            target.write(chunk)

    def _line_level(self, line: str) -> str:
        lower = line.lower()
        if any(token in lower for token in ("panic", "fatal", "critical", "crash", "error")):
            return "错误"
        if any(token in lower for token in ("warn", "warning", "timeout", "failed")):
            return "告警"
        return "提示"

    def _problem_tokens(self, problem_description: str) -> set[str]:
        tokens = {token.lower() for token in re.findall(r"[A-Za-z0-9_./-]{3,}", problem_description)}
        zh_tokens = {"登录", "存储", "网络", "快照", "证书", "授权", "超时", "告警", "宕机", "卡顿", "vSAN"}
        return tokens | {token.lower() for token in zh_tokens if token in problem_description}

    def _trim_line(self, line: str, limit: int = 240) -> str:
        value = re.sub(r"\s+", " ", line).strip()
        return value if len(value) <= limit else value[: limit - 1] + "…"

    def _size_label(self, value: int) -> str:
        if value >= 1024 * 1024:
            return f"{value / 1024 / 1024:.1f} MB"
        if value >= 1024:
            return f"{value / 1024:.1f} KB"
        return f"{value} B"
