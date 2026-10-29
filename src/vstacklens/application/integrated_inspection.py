"""Single-run product orchestration; legacy vCenter work keeps its own IDs."""
from __future__ import annotations

from contextlib import closing
from copy import deepcopy
from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Callable, Any
from uuid import uuid4

from vstacklens.application.execution_guard import execution_lease
from vstacklens.application.inspection_service import (
    DesktopInspectionConfig, InspectionProgress, InspectionState, InspectionService,
)
from vstacklens.application.paths import builtin_rulepack_path
from vstacklens.products.model import (TargetRef, SessionCredential, make_check, make_source,
                                      new_module, finish_module, sanitize_public, has_valid_data)
from vstacklens.products import store


@dataclass(slots=True)
class IntegratedInspectionRequest:
    db_path: Path
    report_output_dir: Path
    targets: list[TargetRef]
    credentials: dict[str, SessionCredential] = field(repr=False)
    report_title: str = "VStackLens 综合巡检报告"
    rulepack_path: Path | None = None
    experimental: bool = True


@dataclass(slots=True)
class IntegratedInspectionResult:
    run_id: str
    report_path: Path
    report_dir: Path
    modules: list[dict] = field(default_factory=list)
    state: str = "failed"
    docx_path: Path | None = None
    pdf_path: Path | None = None
    zip_path: Path | None = None
    score: float | None = None
    risk_summary: dict = field(default_factory=dict)
    customer_caliber: dict = field(default_factory=dict)
    html_error: str | None = None
    docx_error: str | None = None
    pdf_error: str | None = None
    diagnostic_path: Path | None = None


class IntegratedInspectionService:
    def __init__(self, legacy_service=None, collectors=None):
        self.legacy_service = legacy_service
        self.collectors = collectors

    def run(self, request, progress_callback=None, cancel_requested=None):
        cancelled = cancel_requested or (lambda: False)
        targets = deepcopy(list(request.targets))
        credentials = {key: SessionCredential(value.username, value.password, value.tenant,
                           value.allow_untrusted_lab, value.ca_bundle) for key, value in request.credentials.items()}
        run_id = "integrated-" + uuid4().hex
        run_dir = Path(request.report_output_dir) / run_id
        result = IntegratedInspectionResult(run_id, run_dir / "report" / "index.html", run_dir)
        legacy_reports, contexts, legacy_ids = [], [], {}
        created = False

        def secrets():
            return tuple(dict.fromkeys(v for credential in credentials.values() for v in credential.secret_values if v))

        def progress(stage, percent, message, state=InspectionState.RUNNING):
            if progress_callback:
                progress_callback(InspectionProgress(state=state, run_id=run_id, stage=stage,
                                                    percent=percent, message=message))

        try:
            if not targets or len({t.target_id for t in targets}) != len(targets):
                raise ValueError("请选择不重复的巡检目标。")
            if not request.experimental and any(t.product in {"nsx", "avi"} for t in targets):
                raise ValueError("NSX／AVI 业务能力仍待真实验收，请明确启用实验单次巡检。")
            if not store.schema_ready(request.db_path):
                raise ValueError("产品档案结构尚未显式准备；请先在所选数据库上完成备份和结构准备。")
            if any(not credentials.get(t.target_id) or not credentials[t.target_id].username or not credentials[t.target_id].password for t in targets):
                raise ValueError("请为每个所选目标分别提供本次账号和密码。")
            targets = store.create_run(request.db_path, run_id, targets, request.report_title)
            created = True
            collectors = self.collectors
            if collectors is None:
                from vstacklens.products.nsx import collect_nsx
                from vstacklens.products.avi import collect_avi
                collectors = {"nsx": collect_nsx, "avi": collect_avi}
            for ordinal, target in enumerate(targets):
                credential = credentials[target.target_id]
                module = new_module(target)
                if target.product in {"nsx", "avi"}:
                    from vstacklens.products.management_scope import mark_management_scope
                    mark_management_scope(module)
                target_started_at = module["started_at"]
                if cancelled():
                    module["collection_state"] = "cancelled"
                    module["checks"] = [make_check("execution.cancelled", "目标执行", "cancelled", summary="任务取消，未开始该目标采集。")]
                else:
                    progress("collecting_" + target.product, 5 + int(65 * ordinal / len(targets)), f"正在读取 {target.name}（{ordinal + 1}/{len(targets)}）")
                    try:
                        with execution_lease(request.db_path, target.target_id, target.host, target.port, owner=run_id):
                            if target.product == "vcenter":
                                def child_progress(update):
                                    fraction = max(0, min(100, update.percent)) / 100
                                    message = sanitize_public(update.message, (*secrets(), credential.username))
                                    progress("vcenter." + update.stage,
                                             5 + int(65 * (ordinal + fraction) / len(targets)), message)
                                module, report, context, legacy_id = self._collect_vcenter(
                                    target, credential, request, run_dir, run_id, cancelled, child_progress, secrets())
                                legacy_ids[target.target_id] = legacy_id
                                if report is not None:
                                    report.integration_summary = {"legacy_target_id": target.target_id, "legacy_target_name": target.name}
                                    legacy_reports.append(report)
                                    contexts.append(context)
                            else:
                                module = collectors[target.product](target, credential, cancel_requested=cancelled)
                                from vstacklens.products.management_scope import module_scope, validate_module_scope
                                scope = module_scope(module)
                                if scope is None or scope.product != target.product:
                                    raise ValueError("新采集结果缺少匹配的管理巡检范围标识。")
                                validate_module_scope(module)
                            self._check_identity(target, module)
                    except Exception as exc:
                        module = self._failure_module(target, exc, cancelled(), (*secrets(), credential.username))
                module["started_at"] = target_started_at
                try:
                    module = finish_module(sanitize_public(module, secrets()))
                    store.save_module(request.db_path, run_id, module, legacy_run_id=legacy_ids.get(target.target_id))
                except Exception:
                    # A malformed/unsafe adapter result is a target failure;
                    # persist only a fresh diagnostic, then continue others.
                    module = self._failure_module(target, ValueError("该目标结果未通过结构或安全检查，已阻止其持久化。"), cancelled(), secrets())
                    module["started_at"] = target_started_at
                    store.save_module(request.db_path, run_id, module, legacy_run_id=legacy_ids.get(target.target_id))
                result.modules.append(module)
            if cancelled() or any(m.get("collection_state") == "cancelled" for m in result.modules):
                result.state = "cancelled"
                for kind in ("html", "docx", "pdf"):
                    store.save_report(request.db_path, run_id, kind, "", "cancelled", "任务已取消，未发布健康报告。")
                self._diagnostic(request, result, secrets())
            else:
                progress("building_integrated_report", 75, "正在汇总所选产品结果和覆盖限制。")
                self._deliver(request, targets, result, legacy_reports, contexts[0] if contexts else {}, secrets(), cancelled)
            for module in result.modules:
                module["delivery_state"] = self._target_delivery_state(module, result)
                store.save_module(request.db_path, run_id, module, legacy_run_id=legacy_ids.get(module["target_id"]))
            standard_result = self._publish_result(result, secrets())
            store.save_report(request.db_path, run_id, "json", standard_result, "success")
            if result.diagnostic_path:
                self._diagnostic(request, result, secrets())
            store.finish_run(request.db_path, run_id, result.state)
            progress(result.state, 100, "综合巡检已结束；请按各产品状态和验证层级查看结果。",
                     InspectionState.CANCELLED if result.state == "cancelled" else InspectionState.FAILED if result.state == "failed" else InspectionState.COMPLETED)
            return result
        except Exception:
            if created:
                store.finish_run(request.db_path, run_id, "cancelled" if cancelled() else "failed")
            raise
        finally:
            for credential in credentials.values():
                credential.clear()
            for credential in request.credentials.values():
                credential.clear()
            request.credentials.clear()

    @staticmethod
    def _target_delivery_state(module, result):
        """A shared report may deliver only this target's failure diagnosis."""
        if result.state == "cancelled":
            return "cancelled"
        files = (result.report_path, result.docx_path, result.pdf_path)
        available = sum(bool(path and Path(path).is_file()) for path in files)
        if not has_valid_data(module):
            diagnostic = result.diagnostic_path
            return "diagnostic_only" if available or diagnostic and Path(diagnostic).is_file() else "failed"
        errors = (result.html_error, result.docx_error, result.pdf_error)
        return "completed" if available == 3 and not any(errors) else "partial" if available else "failed"

    def _collect_vcenter(self, target, credential, request, run_dir, owner, cancelled, progress_callback, known_secrets):
        from vstacklens.db.connection import connect
        from vstacklens.reports.context_builder import ReportContextBuilder
        from vstacklens.reports.report_model import ReportDataFactory
        service = self.legacy_service or InspectionService(config_path=run_dir / ".unused-config.json")
        if credential.allow_untrusted_lab:
            raise ValueError("本轮实验自签名证书授权仅适用于指定 NSX／AVI 地址，不适用于 vCenter。")
        cfg = DesktopInspectionConfig(vcenter=target.address, username=credential.username,
            password=credential.password, customer_name=target.customer_name, site_name=target.site_name,
            environment_id=target.target_id, db_path=Path(request.db_path),
            # The legacy pipeline already creates a unique run directory.
            # Avoid repeating target UUIDs in Windows native export paths.
            report_output_dir=run_dir / "vc",
            rulepack_path=request.rulepack_path or builtin_rulepack_path(), report_title=request.report_title,
            ssl_no_verify=False)
        legacy = service.run_vcenter_inspection(cfg, progress_callback=progress_callback, cancel_requested=cancelled,
                    persist_config=False, execution_owner=owner,
                    known_secrets=tuple(dict.fromkeys((*known_secrets, credential.username))))
        with closing(connect(Path(request.db_path))) as conn:
            context = ReportContextBuilder().build(conn, legacy.run_id)
        report = ReportDataFactory().from_context(context)
        module = new_module(target)
        module["version"] = report.environment_summary.vcenter_version or ""
        module["build"] = report.environment_summary.vcenter_build or ""
        info = context.get("environment_info") or {}
        if info.get("collection_mode") == "connection_failed":
            module["checks"] = [make_check("vcenter.legacy", "VC／vSAN 原有巡检", "collection_failed",
                values={"legacy_run_id": legacy.run_id, "object_count": 0},
                summary="原有 VC／vSAN 流程只取得连接诊断，未取得有效清单。",
                sources=[make_source("local-inspection-run:" + legacy.run_id, method="LOCAL_READ")],
                limitations=["连接诊断对象不计为有效资产或检查通过。"], verification="unverified")]
            module["errors"] = [{"kind": "legacy_connection_failed", "stage": "collection", "http_status": None,
                                 "reason": "旧流程仅保存连接诊断，详见对应子任务。"}]
            return finish_module(module), None, context, legacy.run_id
        objects = report.environment_summary.checked_object_total
        status = "attention" if report.risk_summary.total else "normal" if objects else "insufficient_data"
        module["checks"] = [make_check("vcenter.legacy", "VC／vSAN 原有巡检", status,
            values={"legacy_run_id": legacy.run_id, "object_count": objects,
                    "original_score": legacy.score, "original_grade": report.health_score.grade},
            summary="沿用原有 VC／vSAN 的检查、等级和历史口径。",
            sources=[make_source("local-inspection-run:" + legacy.run_id, method="LOCAL_READ", version_basis="既有已验收 VC／vSAN 引擎")],
            verification="live_observed", basis="原有 VC／vSAN 规则，不与新产品计算总分。")]
        module["limitations"] = ["VC／vSAN 检查能力与覆盖范围沿用原任务证据。"]
        # Legacy run success describes execution; its rule/data gaps must still
        # reach the integrated module without changing legacy scores or grades.
        counts = {key: int((context.get("result_status_summary") or {}).get(key) or 0)
                  for key in ("passed", "failed", "not_applicable", "unavailable", "error")}
        rows = context.get("object_results") or context.get("unavailable_results") or []
        gaps = []
        for row in rows:
            if not isinstance(row, dict) or row.get("result_status") not in {"unavailable", "error"}:
                continue
            gaps.append({
                "result_id": row.get("result_id", ""), "rule_id": row.get("rule_id", ""),
                "object_type": row.get("object_type", ""), "object_key": row.get("object_key", ""),
                "object_name": row.get("object_name", ""), "result_status": row.get("result_status", ""),
                "data_quality": row.get("data_quality", ""),
                "source_path": row.get("source_path") or row.get("api_path") or "未记录",
                "collected_at": row.get("collected_at") or row.get("evaluated_at") or "",
                "reason": row.get("reason") or row.get("error_message") or "未提供缺口原因",
            })
        warnings = [item for item in info.get("collection_warnings") or [] if isinstance(item, dict)]
        degraded = any(item.get("degraded") is True or item.get("status") in {"api_error", "error", "unavailable"}
                       for item in warnings)
        if counts["unavailable"] or counts["error"] or gaps or degraded:
            summary = (f"已读取 {objects} 个对象；规则执行中 {counts['unavailable']} 条数据不可用、"
                       f"{counts['error']} 条执行错误；当前报告上下文另可见 {len(warnings)} 条采集警告。")
            limits = ["规则缺口与采集警告属于不同口径，不能相加或据此认定同一根因。",
                      "原报告上下文最多提供 20 条采集警告，可见条数不代表全部警告数量。",
                      "保留原 VC／vSAN 分数与等级；本项只表达当次数据完整性。"]
            coverage = sanitize_public({"legacy_run_id": legacy.run_id, "object_count": objects,
                "rule_result_status_summary": counts, "unavailable_results": gaps,
                "collection_warning_records_observed": len(warnings), "collection_warning_total": None,
                "collection_warnings": [{"context_scope": str(item.get("context") or "").split(":", 1)[0],
                                         "status": item.get("status"), "error_type": item.get("error_type"),
                                         "degraded": item.get("degraded")} for item in warnings],
                "legacy_assessment_limited": report.health_score.assessment_limited},
                (*known_secrets, credential.username))
            module["checks"][0]["completeness"] = "partial"
            module["checks"][0]["limitations"].append("存在当次数据缺口，详见 VC／vSAN 数据覆盖检查。")
            module["checks"].append(make_check("vcenter.legacy_coverage", "VC／vSAN 数据覆盖", "insufficient_data",
                values=coverage, summary=summary, completeness="partial", limitations=limits,
                sources=[make_source("local-inspection-run:" + legacy.run_id, method="LOCAL_READ",
                    fields=("context.result_status_summary", "context.object_results",
                            "context.unavailable_results", "context.environment_info.collection_warnings"),
                    version_basis="既有 VC／vSAN 当次报告上下文")],
                verification="live_observed", basis="当次原有规则结果及已有采集警告，不重新判级或评分。"))
            module["limitations"].extend([summary, *limits])
        return finish_module(module), report, context, legacy.run_id

    @staticmethod
    def _check_identity(target, module):
        observed = module.get("target_identity") or {}
        missing = [key for key in target.identity if key not in observed]
        changed = [key for key, expected in target.identity.items() if key in observed and observed[key] != expected]
        if missing or changed:
            reason = "本次未取得已登记的可信身份字段。" if missing else "本次读取的设备身份与档案不一致。"
            module.setdefault("errors", []).append({"kind": "identity_unconfirmed", "stage": "identity", "http_status": None, "reason": reason})
            module.setdefault("checks", []).append(make_check("execution.identity", "目标身份核对",
                "insufficient_data" if missing else "abnormal", summary=reason,
                values={"missing_fields": missing, "changed_fields": changed, "observed_identity": observed},
                limitations=["未建立可信身份关联，不能与历史对象合并或据此确认业务能力。"], completeness="identity_unconfirmed"))
            module.setdefault("limitations", []).append(reason)
            module["verification_level"] = "unverified"
            for item in module.get("checks", []):
                item["verification"] = "unverified"

    @staticmethod
    def _failure_module(target, exc, cancelled, secrets):
        from vstacklens.products.transport import CollectionError
        module = new_module(target)
        if target.product in {"nsx", "avi"}:
            from vstacklens.products.management_scope import mark_management_scope
            mark_management_scope(module)
        error = exc.as_dict() if isinstance(exc, CollectionError) else {"kind": type(exc).__name__, "reason": str(exc), "stage": "target_execution", "http_status": None}
        error = sanitize_public(error, secrets)
        kind = error.get("kind")
        status = "cancelled" if cancelled or kind == "cancelled" else "permission_denied" if kind == "permission" else "unsupported" if kind == "unsupported" else "collection_failed"
        module["collection_state"] = "cancelled" if status == "cancelled" else "failed"
        module["errors"] = [error]
        module["checks"] = [make_check("execution.failure", "目标执行", status, summary=error.get("reason", "目标未完成。"), limitations=["该目标失败不表示其他目标失败。"])]
        return finish_module(module)

    def _deliver(self, request, targets, result, legacy_reports, context, secrets, cancelled):
        from vstacklens.products.reporting import build_integrated_report, NoValidInspectionData
        from vstacklens.reports.html_package import HtmlReportPackageBuilder
        from vstacklens.reports.exporter import ReportExportEngine
        from vstacklens.reports.pdf_report import PdfReportEngine
        try:
            report = build_integrated_report(result.run_id, targets, result.modules, request.report_title,
                                             legacy_report=legacy_reports or None)
        except NoValidInspectionData as exc:
            result.html_error = result.docx_error = result.pdf_error = str(exc)
            result.state = "failed"
            for kind in ("html", "docx", "pdf"):
                store.save_report(request.db_path, result.run_id, kind, "", "blocked", str(exc))
            self._diagnostic(request, result, secrets)
            return
        result.report_dir.mkdir(parents=True, exist_ok=True)
        exports = [
            ("html", lambda: HtmlReportPackageBuilder().render(report, context, result.report_dir / "report", secrets=secrets)[0]),
            ("docx", lambda: ReportExportEngine().render(report, result.report_dir / "inspection-report.docx", secrets=secrets)[0]),
            ("pdf", lambda: PdfReportEngine().render(report, result.report_dir / "inspection-report.pdf", report_context=context, secrets=secrets)),
        ]
        for kind, render in exports:
            if cancelled():
                result.state = "cancelled"
                store.save_report(request.db_path, result.run_id, kind, "", "cancelled", "交付前收到取消请求。")
                continue
            try:
                path = render()
                setattr(result, "report_path" if kind == "html" else kind + "_path", path)
                store.save_report(request.db_path, result.run_id, kind, path, "success")
            except Exception as exc:
                reason = sanitize_public(f"{type(exc).__name__}: {exc}", secrets)
                setattr(result, kind + "_error", reason)
                store.save_report(request.db_path, result.run_id, kind, "", "failed", reason)
        if result.state != "cancelled":
            collection_complete = all(m.get("collection_state") == "completed" for m in result.modules)
            published = sum(p is not None and p.is_file() for p in (result.report_path, result.docx_path, result.pdf_path))
            result.state = "completed" if collection_complete and published == 3 else "partial" if published else "failed"
        if len(legacy_reports) == 1:
            result.score = legacy_reports[0].health_score.score
            result.risk_summary = legacy_reports[0].risk_summary.model_dump()

    @staticmethod
    def _publish_result(result, secrets):
        from vstacklens.application.artifact_publish import staged_file
        result.report_dir.mkdir(parents=True, exist_ok=True)
        destination = result.report_dir / "inspection-result.json"
        with staged_file(destination, secrets=secrets) as stage:
            stage.write_text(json.dumps(sanitize_public({"run_id": result.run_id, "state": result.state,
                "material_type": "inspection_result" if any(has_valid_data(m) for m in result.modules) else "execution_diagnostic_not_health_report",
                "modules": result.modules}, secrets), ensure_ascii=False, indent=2), encoding="utf-8")
        return destination

    @staticmethod
    def _diagnostic(request, result, secrets):
        from vstacklens.application.artifact_publish import staged_file
        result.report_dir.mkdir(parents=True, exist_ok=True)
        path = result.report_dir / "failure-diagnostic.json"
        with staged_file(path, secrets=secrets) as stage:
            stage.write_text(json.dumps(sanitize_public({"run_id": result.run_id, "state": result.state,
                "material_type": "execution_diagnostic_not_health_report", "modules": result.modules}, secrets), ensure_ascii=False, indent=2), encoding="utf-8")
        result.diagnostic_path = path
