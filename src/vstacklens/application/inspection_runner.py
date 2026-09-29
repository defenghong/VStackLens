from __future__ import annotations

import inspect
import ssl
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from vstacklens.application.connection_probe import (
    ProbeResult,
    diagnostic_properties,
    friendly_connection_error,
    merge_vcenter_diagnostics,
    normalize_vcenter_address,
    redact_sensitive,
    socket_probe,
)
from vstacklens.collection.mock_collector import MockCollector
from vstacklens.collection.planner import CollectionPlanner
from vstacklens.collection.pyvmomi_collector import PyVmomiCollector
from vstacklens.core.context import RunContext
from vstacklens.db.connection import connect, init_db
from vstacklens.db.repositories import (
    ensure_default_scope,
    finalize_run_summary,
    insert_report,
    insert_rule,
    insert_rule_result,
    insert_run,
    update_run,
)
from vstacklens.findings.deduplication import FindingDeduplicator
from vstacklens.inventory.normalizer import InventoryNormalizer
from vstacklens.inventory.snapshot_engine import SnapshotEngine
from vstacklens.application.artifact_safety import scan_artifacts
from vstacklens.application.engineering_diagnostics import write_engineering_diagnostics
from vstacklens.reports.context_builder import ReportContextBuilder
from vstacklens.reports.exporter import ReportExportEngine
from vstacklens.reports.history_compare import HistoryComparisonBuilder
from vstacklens.reports.html_package import HtmlReportPackageBuilder
from vstacklens.reports.pdf_report import PdfReportEngine
from vstacklens.reports.report_model import ReportDataFactory
from vstacklens.reports.run_compare import RunComparisonBuilder
from vstacklens.rules.executor import RuleExecutor
from vstacklens.rules.registry import RuleRegistry
from vstacklens.rules.rulepack_loader import RulePackLoader
from vstacklens.rules.schema import RuleDefinition
from vstacklens.rules.schema_validator import SchemaValidator


ProgressCallback = Callable[[str, int], None]
CancelCallback = Callable[[], bool]
DEFAULT_REPORT_TITLE = "VStackLens VMware 虚拟化健康评估报告"


class RunnerCancelledError(RuntimeError):
    pass


@dataclass(slots=True)
class InspectionRunPaths:
    report_dir: Path
    html_out: Path | None = None
    docx_out: Path | None = None
    pdf_out: Path | None = None


@dataclass(slots=True)
class InspectionRunRequest:
    db_path: Path
    rulepack_path: Path
    report_dir: Path
    report_title: str | None = None
    customer_name: str | None = None
    site_name: str | None = None
    zip_report: bool = False
    previous_run_id: str | None = None
    compare_latest: bool = False
    html_out: Path | None = None
    docx_out: Path | None = None
    pdf_out: Path | None = None


@dataclass(slots=True)
class VCenterRunRequest(InspectionRunRequest):
    vcenter: str = ""
    username: str = ""
    password: str = ""
    port: int = 443
    ssl_no_verify: bool = False


@dataclass(slots=True)
class MockRunRequest(InspectionRunRequest):
    fixture_path: Path = Path()
    vcenter: str = "mock-vcenter.local"


@dataclass(slots=True)
class RunnerResult:
    run_id: str
    report_path: Path
    report_dir: Path
    zip_path: Path | None
    docx_path: Path | None = None
    docx_error: str | None = None
    pdf_path: Path | None = None
    pdf_error: str | None = None


CERTIFICATE_DOWNGRADE_WARNING = "vCenter 证书未通过可信链校验，本次巡检已在不校验证书模式下继续完成。建议后续为 vCenter 配置受信任证书，以提升连接安全性。"


class InspectionRunner:
    def load_registry(self, rulepack: Path) -> RuleRegistry:
        loader = RulePackLoader()
        validator = SchemaValidator()
        raw_rules = loader.load_raw(rulepack)
        rules = [validator.validate_rule(raw) for raw in raw_rules]
        registry = RuleRegistry()
        registry.register(rules)
        return registry

    def connection_failure_inventory(
        self,
        vcenter_host: str,
        error: str,
        diagnostics: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "objects": [
                {
                    "object_type": "vCenter",
                    "object_key": vcenter_host,
                    "object_name": vcenter_host,
                    "object_path": vcenter_host,
                    "properties": {
                        "asset_location": "vCenter 根对象",
                        "connected": False,
                        "connection_error": error,
                        **(diagnostics or {}),
                    },
                }
            ]
        }

    def previous_run_for_args(
        self,
        conn: Any,
        previous_run_id: str | None,
        compare_latest: bool,
        current_run_id: str,
    ) -> str | None:
        if previous_run_id:
            # 显式指定的上一轮巡检也必须属于同一个 vCenter 环境，否则视为没有可比历史。
            return previous_run_id if self._same_vcenter_environment(conn, previous_run_id, current_run_id) else None
        if compare_latest:
            return RunComparisonBuilder().latest_successful_previous_run(conn, current_run_id)
        return None

    def _same_vcenter_environment(self, conn: Any, left_run_id: str, right_run_id: str) -> bool:
        rows = conn.execute(
            "SELECT run_id, vcenter_id FROM inspection_runs WHERE run_id IN (?, ?)",
            (left_run_id, right_run_id),
        ).fetchall()
        mapping = {row["run_id"]: str(row["vcenter_id"] or "") for row in rows}
        left = mapping.get(left_run_id)
        right = mapping.get(right_run_id)
        if not left or not right:
            return False
        return left == right

    def run_mock(self, request: MockRunRequest, progress: ProgressCallback | None = None) -> RunnerResult:
        db = Path(request.db_path)
        init_db(db)
        registry = self.load_registry(Path(request.rulepack_path))
        plan = CollectionPlanner().build(registry.executable_rules)
        with connect(db) as conn:
            customer_id, site_id, vcenter_id = ensure_default_scope(
                conn,
                request.vcenter,
                customer_name=request.customer_name,
                site_name=request.site_name,
            )
            run_id = insert_run(conn, customer_id, site_id, vcenter_id, "manual")
            run = RunContext(run_id=run_id, customer_id=customer_id, site_id=site_id, vcenter_id=vcenter_id, db_path=db)
            stage = "loading_rules"
            try:
                if progress:
                    progress(f"run_id:{run_id}", 0)
                self._set_stage(conn, run_id, "loading_rules", 5, progress)
                self._set_stage(conn, run_id, "validating_rules", 10, progress)
                self._set_stage(conn, run_id, "planning_collection", 15, progress)
                self._set_stage(conn, run_id, "prechecking", 18, progress)
                self._set_stage(conn, run_id, "collecting", 20, progress)
                raw = MockCollector(Path(request.fixture_path)).collect(run, plan)
                return self.run_pipeline(
                    conn,
                    db,
                    run,
                    site_id,
                    raw,
                    registry.executable_rules,
                    registry.rules,
                    self._run_paths(request, run_id),
                    report_title=request.report_title,
                    zip_report=request.zip_report,
                    previous_run_id=request.previous_run_id,
                    progress=progress,
                )
            except Exception as exc:
                update_run(conn, run_id, "failed", stage, 100, str(exc)[:1000])
                if progress:
                    progress("failed", 100)
                raise

    def run_vcenter(
        self,
        request: VCenterRunRequest,
        progress: ProgressCallback | None = None,
        cancel_requested: CancelCallback | None = None,
    ) -> RunnerResult:
        db = Path(request.db_path)
        init_db(db)
        registry = self.load_registry(Path(request.rulepack_path))
        plan = CollectionPlanner().build(registry.executable_rules)
        endpoint = normalize_vcenter_address(request.vcenter, request.port)
        with connect(db) as conn:
            customer_id, site_id, vcenter_id = ensure_default_scope(
                conn,
                endpoint.host,
                request.username,
                customer_name=request.customer_name,
                site_name=request.site_name,
            )
            run_id = insert_run(conn, customer_id, site_id, vcenter_id, "manual")
            run = RunContext(run_id=run_id, customer_id=customer_id, site_id=site_id, vcenter_id=vcenter_id, db_path=db)
            stage = "loading_rules"
            try:
                self._raise_if_cancelled(conn, run_id, progress, cancel_requested)
                if progress:
                    progress(f"run_id:{run_id}", 0)
                self._set_stage(conn, run_id, "loading_rules", 5, progress, cancel_requested)
                self._set_stage(conn, run_id, "validating_rules", 10, progress, cancel_requested)
                self._set_stage(conn, run_id, "planning_collection", 15, progress, cancel_requested)
                self._set_stage(conn, run_id, "prechecking", 18, progress, cancel_requested)
                port_probe = ProbeResult("skipped", "SDK 连接检测已启动，端口检测将在失败诊断时执行。")
                collector = PyVmomiCollector(
                    endpoint.host,
                    request.username,
                    request.password,
                    endpoint.port,
                    not request.ssl_no_verify,
                )
                security_warnings: list[str] = []
                try:
                    self._raise_if_cancelled(conn, run_id, progress, cancel_requested)
                    collector.precheck()
                except Exception as exc:  # noqa: BLE001 - connection failure remains a customer report finding.
                    if not request.ssl_no_verify and self._is_certificate_verification_error(exc):
                        retry_collector = PyVmomiCollector(
                            endpoint.host,
                            request.username,
                            request.password,
                            endpoint.port,
                            False,
                        )
                        try:
                            retry_collector.precheck()
                        except Exception as retry_exc:  # noqa: BLE001 - retry failure becomes a connection diagnostic.
                            raw, executable_rules = self._connection_failure_after_sdk_failure(
                                request,
                                registry,
                                endpoint.host,
                                endpoint.port,
                                port_probe,
                                retry_exc,
                            )
                            previous_run_id = self.previous_run_for_args(conn, request.previous_run_id, request.compare_latest, run_id)
                            return self.run_pipeline(
                                conn,
                                db,
                                run,
                                site_id,
                                raw,
                                executable_rules,
                                registry.rules,
                                self._run_paths(request, run_id),
                                report_title=request.report_title,
                                zip_report=request.zip_report,
                                previous_run_id=previous_run_id,
                                progress=progress,
                                cancel_requested=cancel_requested,
                                secrets=(request.password,),
                            )
                        collector = retry_collector
                        security_warnings.append(CERTIFICATE_DOWNGRADE_WARNING)
                    else:
                        raw, executable_rules = self._connection_failure_after_sdk_failure(
                            request,
                            registry,
                            endpoint.host,
                            endpoint.port,
                            port_probe,
                            exc,
                        )
                        previous_run_id = self.previous_run_for_args(conn, request.previous_run_id, request.compare_latest, run_id)
                        return self.run_pipeline(
                            conn,
                            db,
                            run,
                            site_id,
                            raw,
                            executable_rules,
                            registry.rules,
                            self._run_paths(request, run_id),
                            report_title=request.report_title,
                            zip_report=request.zip_report,
                            previous_run_id=previous_run_id,
                            progress=progress,
                            cancel_requested=cancel_requested,
                            secrets=(request.password,),
                        )
                self._set_stage(conn, run_id, "collecting_environment", 20, progress, cancel_requested)
                if isinstance(collector, PyVmomiCollector):
                    collector.cancel_requested = cancel_requested or (lambda: False)
                raw = self._collect_with_progress(collector, run, plan, progress)
                self._raise_if_cancelled(conn, run_id, progress, cancel_requested)
                raw = merge_vcenter_diagnostics(
                    raw,
                    diagnostic_properties(
                        mode="sdk",
                        port=ProbeResult("success", f"{endpoint.host}:{endpoint.port} 已通过 SDK 连接。"),
                        sdk=ProbeResult("success", "已通过 vSphere SDK 完成连接检测。"),
                        security_warnings=security_warnings,
                    ),
                )
                previous_run_id = self.previous_run_for_args(conn, request.previous_run_id, request.compare_latest, run_id)
                return self.run_pipeline(
                    conn,
                    db,
                    run,
                    site_id,
                    raw,
                    registry.executable_rules,
                    registry.rules,
                    self._run_paths(request, run_id),
                    report_title=request.report_title,
                    zip_report=request.zip_report,
                    previous_run_id=previous_run_id,
                    progress=progress,
                    cancel_requested=cancel_requested,
                    secrets=(request.password,),
                )
            except RunnerCancelledError:
                raise
            except Exception as exc:
                update_run(conn, run_id, "failed", stage, 100, str(exc)[:1000])
                if progress:
                    progress("failed", 100)
                raise

    def _connection_failure_after_sdk_failure(
        self,
        request: VCenterRunRequest,
        registry: RuleRegistry,
        vcenter_host: str,
        port: int,
        port_probe: ProbeResult,
        sdk_error: Exception,
    ) -> tuple[dict[str, Any], list[RuleDefinition]]:
        if port_probe.status == "skipped":
            port_probe = socket_probe(vcenter_host, port)
        sdk_probe = ProbeResult("failed", friendly_connection_error(sdk_error), redact_sensitive(sdk_error, request.password))
        diagnostics = diagnostic_properties(mode="connection_failed", port=port_probe, sdk=sdk_probe)
        raw = self.connection_failure_inventory(vcenter_host, sdk_probe.message, diagnostics)
        connection_rule = [rule for rule in registry.rules if rule.rule_id == "VSL-VC-001"]
        return raw, connection_rule

    def _is_certificate_verification_error(self, exc: Exception) -> bool:
        if isinstance(exc, ssl.SSLCertVerificationError):
            return True
        text = f"{type(exc).__name__} {exc}".lower()
        return any(token in text for token in ("certificate_verify_failed", "certificate verify failed", "self signed certificate", "unable to get local issuer certificate"))

    def run_pipeline(
        self,
        conn: Any,
        db: Path,
        run: RunContext,
        site_id: str,
        raw: dict[str, Any],
        executable_rules: list[RuleDefinition],
        catalog_rules: list[RuleDefinition],
        paths: InspectionRunPaths,
        report_title: str | None = None,
        zip_report: bool = False,
        previous_run_id: str | None = None,
        progress: ProgressCallback | None = None,
        cancel_requested: CancelCallback | None = None,
        secrets: tuple[str, ...] = (),
    ) -> RunnerResult:
        self._set_stage(conn, run.run_id, "normalizing", 60, progress, cancel_requested)
        inventory = InventoryNormalizer().normalize(raw)
        self._set_stage(conn, run.run_id, "snapshotting", 62, progress, cancel_requested)
        self._atomic_stage(conn, "snapshot_inventory", lambda: SnapshotEngine().write_snapshot(conn, run, inventory))
        for rule in catalog_rules:
            insert_rule(conn, rule)
        self._set_stage(conn, run.run_id, "executing_rules", 70, progress, cancel_requested)
        results = RuleExecutor().execute(run, inventory, executable_rules)
        for result in results:
            insert_rule_result(conn, result)
        self._set_stage(conn, run.run_id, "building_findings", 80, progress, cancel_requested)
        self._atomic_stage(conn, "finding_deduplication", lambda: FindingDeduplicator().upsert_findings(conn, site_id, results))
        self._set_stage(conn, run.run_id, "scoring", 82, progress, cancel_requested)
        finalize_run_summary(conn, run.run_id)
        self._set_stage(conn, run.run_id, "reporting", 90, progress, cancel_requested)
        update_run(conn, run.run_id, "success", "success", 100)
        if progress:
            progress("success", 100)

        comparison = RunComparisonBuilder().build(conn, previous_run_id, run.run_id) if previous_run_id else None
        report_context = ReportContextBuilder().build(conn, run.run_id, comparison=comparison)
        if previous_run_id:
            report_context["history_comparison"] = HistoryComparisonBuilder().build(conn, previous_run_id, run.run_id)
        report_data = ReportDataFactory().from_context(report_context)
        report_data.report_info.report_title = (report_title or "").strip() or DEFAULT_REPORT_TITLE
        index_path, zip_path = HtmlReportPackageBuilder().render(report_data, report_context, paths.report_dir, zip_package=zip_report)
        paths = replace(paths, report_dir=index_path.parent)
        insert_report(
            conn,
            run.run_id,
            run.customer_id,
            site_id,
            run.vcenter_id,
            str(index_path),
            "success",
            report_type="html_package",
            report_name=report_data.report_info.report_title,
        )
        if zip_path:
            insert_report(
                conn,
                run.run_id,
                run.customer_id,
                site_id,
                run.vcenter_id,
                str(zip_path),
                "success",
                report_type="zip",
                report_name="VStackLens Zip Report Package",
            )
        json_path = paths.report_dir.parent / f"{paths.report_dir.name}_inspection_result.json"
        report_data.write_json(json_path)
        insert_report(conn, run.run_id, run.customer_id, site_id, run.vcenter_id, str(json_path), "success", report_type="json", report_name="Inspection Result JSON")
        docx_path: Path | None = None
        docx_error: str | None = None
        if paths.docx_out:
            try:
                rendered_path, report_type, report_name = ReportExportEngine().render(report_data, paths.docx_out)
                docx_path = rendered_path
                insert_report(conn, run.run_id, run.customer_id, site_id, run.vcenter_id, str(rendered_path), "success", report_type=report_type, report_name=report_name)
            except Exception as exc:  # noqa: BLE001 - Word is an optional delivery artifact; HTML remains primary.
                docx_error = f"Word 报告生成失败：{exc}"
                insert_report(
                    conn,
                    run.run_id,
                    run.customer_id,
                    site_id,
                    run.vcenter_id,
                    str(paths.docx_out),
                    "failed",
                    error=docx_error,
                    report_type="docx",
                    report_name="VStackLens Word Report",
                )
        pdf_path: Path | None = None
        pdf_error: str | None = None
        if paths.pdf_out:
            try:
                pdf_path = PdfReportEngine().render(report_data, paths.pdf_out, report_context=report_context)
                insert_report(
                    conn,
                    run.run_id,
                    run.customer_id,
                    site_id,
                    run.vcenter_id,
                    str(pdf_path),
                    "success",
                    report_type="pdf",
                    report_name="VStackLens PDF Report",
                )
            except Exception as exc:  # noqa: BLE001 - PDF is an optional delivery artifact; HTML remains primary.
                pdf_error = f"PDF 报告生成失败：{exc}"
                insert_report(
                    conn,
                    run.run_id,
                    run.customer_id,
                    site_id,
                    run.vcenter_id,
                    str(paths.pdf_out),
                    "failed",
                    error=pdf_error,
                    report_type="pdf",
                    report_name="VStackLens PDF Report",
                )
        payload_path = paths.report_dir / "data" / "customer_report_payload.json"
        engineering_path = paths.report_dir / "engineering_diagnostics.md"
        scan_paths = [index_path, payload_path, json_path]
        if zip_path:
            scan_paths.append(zip_path)
        if docx_path:
            scan_paths.append(docx_path)
        if pdf_path:
            scan_paths.append(pdf_path)
        artifact_findings = scan_artifacts(scan_paths)
        write_engineering_diagnostics(
            engineering_path,
            run_id=run.run_id,
            vcenter=str(report_context.get("environment_info", {}).get("vcenter_address") or ""),
            customer_name=str(report_context.get("customer_info", {}).get("customer_name") or ""),
            site_name=str(report_context.get("customer_info", {}).get("site_name") or ""),
            report_dir=paths.report_dir,
            db_path=db,
            report_context=report_context,
            report_paths={
                "HTML": index_path,
                "Word": docx_path,
                "PDF": pdf_path,
                "JSON": json_path,
                "客户载荷": payload_path,
            },
            artifact_findings=artifact_findings,
            secrets=secrets,
        )
        insert_report(
            conn,
            run.run_id,
            run.customer_id,
            site_id,
            run.vcenter_id,
            str(engineering_path),
            "success",
            report_type="engineering_diagnostics",
            report_name="Engineering Diagnostics Markdown",
        )
        return RunnerResult(
            run_id=run.run_id,
            report_path=index_path,
            report_dir=paths.report_dir,
            zip_path=zip_path,
            docx_path=docx_path,
            docx_error=docx_error,
            pdf_path=pdf_path,
            pdf_error=pdf_error,
        )

    def _atomic_stage(self, conn: Any, name: str, operation: Callable[[], Any]) -> Any:
        savepoint = f"sp_{name}"
        conn.execute(f"SAVEPOINT {savepoint}")
        try:
            result = operation()
        except Exception:
            conn.execute(f"ROLLBACK TO {savepoint}")
            conn.execute(f"RELEASE {savepoint}")
            raise
        conn.execute(f"RELEASE {savepoint}")
        return result

    def _set_stage(
        self,
        conn: Any,
        run_id: str,
        stage: str,
        percent: int,
        progress: ProgressCallback | None = None,
        cancel_requested: CancelCallback | None = None,
    ) -> None:
        self._raise_if_cancelled(conn, run_id, progress, cancel_requested)
        update_run(conn, run_id, "running", stage, percent)
        if progress:
            progress(stage, percent)
        self._raise_if_cancelled(conn, run_id, progress, cancel_requested)

    def _raise_if_cancelled(
        self,
        conn: Any,
        run_id: str,
        progress: ProgressCallback | None,
        cancel_requested: CancelCallback | None,
    ) -> None:
        if not cancel_requested or not cancel_requested():
            return
        update_run(conn, run_id, "cancelled", "cancelled", 100, "巡检已取消。")
        if progress:
            progress("cancelled", 100)
        raise RunnerCancelledError("巡检已取消。")

    def _collect_with_progress(
        self,
        collector: Any,
        run: RunContext,
        plan: Any,
        progress: ProgressCallback | None,
    ) -> dict[str, Any]:
        try:
            accepts_progress = "progress" in inspect.signature(collector.collect).parameters
        except (TypeError, ValueError):
            accepts_progress = False
        if accepts_progress:
            return collector.collect(run, plan, progress=progress)
        return collector.collect(run, plan)

    def _run_paths(self, request: InspectionRunRequest, run_id: str) -> InspectionRunPaths:
        report_dir = self._resolve_report_dir(request.report_dir, run_id)
        return InspectionRunPaths(
            report_dir=report_dir,
            html_out=self._resolve_report_path(request.html_out, run_id),
            docx_out=self._resolve_report_path(request.docx_out, run_id),
            pdf_out=self._resolve_report_path(request.pdf_out, run_id),
        )

    def _resolve_report_dir(self, report_dir: Path, run_id: str) -> Path:
        text = str(report_dir)
        if "{run_id}" in text:
            return Path(text.replace("{run_id}", run_id))
        return report_dir

    def _resolve_report_path(self, report_path: Path | None, run_id: str) -> Path | None:
        if report_path is None:
            return None
        text = str(report_path)
        if "{run_id}" in text:
            return Path(text.replace("{run_id}", run_id))
        return report_path
