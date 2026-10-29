from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from datetime import UTC, datetime
from uuid import uuid4
from tempfile import TemporaryDirectory
import os

from vstacklens.deep.analyzer import DeepAnalysisResult, DeepAnalyzer
from vstacklens.deep.contracts import DeepDataset, ThresholdRegistry
from vstacklens.deep.dataset import DeepDatasetWriter, DeepDiagnosticRecordStore
from vstacklens.deep.report import DeepHtmlReportBuilder, DeepWordReportBuilder
from vstacklens.deep.connection import _workbook_connection_secrets, load_esxi_host_connections_from_workbook, load_vcenter_connection_from_workbook
from vstacklens.deep.interfaces import DeepCollectionPolicy
from vstacklens.deep.logs import validate_log_event_references
from vstacklens.deep.pyvmomi_collector import PyVmomiDeepCollector
from vstacklens.deep.history import DeepHistoryStore
from vstacklens.deep.merge import merge_records
from vstacklens.deep.model_assistant import DeepModelAssistant
from vstacklens.deep.offline_package import DeepOfflineEvidencePackager
from vstacklens.deep.redaction import redact_dataset_credentials
from vstacklens.application.cloud_log_diagnosis import CloudModelConfig


@dataclass(slots=True)
class DeepRunResult:
    dataset_id: str
    report_dir: Path
    html_path: Path
    docx_path: Path | None
    diagnostic_path: Path
    analysis: DeepAnalysisResult
    offline_evidence_zip: Path | None = None
    model_analysis_status: str = "not_enabled"
    offline_evidence_package_status: str = "not_requested"


class DeepInspectionService:
    def __init__(self, analyzer: DeepAnalyzer | None = None) -> None:
        self.analyzer = analyzer or DeepAnalyzer()

    def analyze_dataset(
        self,
        dataset_path: Path,
        report_dir: Path,
        *,
        docx_out: Path | None = None,
        thresholds: ThresholdRegistry | None = None,
        model_config: CloudModelConfig | None = None,
        model_enabled: bool = False,
        model_unavailable_reason: str = "not_configured",
    ) -> DeepRunResult:
        dataset = DeepDataset.from_json(Path(dataset_path))
        return self._analyze_dataset_object(
            dataset,
            report_dir,
            docx_out=docx_out,
            thresholds=thresholds,
            model_config=model_config,
            model_enabled=model_enabled,
            model_unavailable_reason=model_unavailable_reason,
        )

    def collect_and_analyze_vcenter(
        self,
        workbook_path: Path,
        report_dir: Path,
        *,
        docx_out: Path | None = None,
        policy: DeepCollectionPolicy | None = None,
        cancel_requested=None,
        model_config: CloudModelConfig | None = None,
        model_enabled: bool = False,
        model_unavailable_reason: str = "not_configured",
    ) -> DeepRunResult:
        workbook_path = Path(workbook_path)
        connection = load_vcenter_connection_from_workbook(workbook_path)
        esxi_host_connections = load_esxi_host_connections_from_workbook(workbook_path)
        redaction_usernames, redaction_passwords = _workbook_connection_secrets(workbook_path)
        dataset = PyVmomiDeepCollector(
            connection.host,
            connection.username,
            connection.password,
            connection.port,
            connection.ssl_verify,
            cancel_requested=cancel_requested,
            host_log_credentials=esxi_host_connections,
        ).collect(policy=policy or DeepCollectionPolicy())
        dataset = redact_dataset_credentials(dataset, usernames=redaction_usernames, passwords=redaction_passwords)
        return self._analyze_dataset_object(
            dataset,
            report_dir,
            dataset_json_out=Path(report_dir).parent / f"{Path(report_dir).name}.dataset.json",
            docx_out=docx_out,
            model_config=model_config,
            model_enabled=model_enabled,
            model_unavailable_reason=model_unavailable_reason,
            known_secrets=[*redaction_usernames, *redaction_passwords],
        )

    def replay_datasets(
        self,
        dataset_paths: list[Path],
        report_dir: Path,
        *,
        docx_out: Path | None = None,
        thresholds: ThresholdRegistry | None = None,
        model_config: CloudModelConfig | None = None,
        model_enabled: bool = False,
        model_unavailable_reason: str = "not_configured",
    ) -> list[DeepRunResult]:
        """Replay immutable Dataset files in manifest time order through one history store."""
        ordered = sorted((Path(path) for path in dataset_paths), key=lambda path: DeepDataset.from_json(path).manifest.created_at_utc)
        results: list[DeepRunResult] = []
        for index, dataset_path in enumerate(ordered, start=1):
            dataset = DeepDataset.from_json(dataset_path)
            run_dir = Path(report_dir) / f"{index:03d}-{dataset.dataset_id}"
            run_docx = Path(docx_out) if docx_out and index == len(ordered) else None
            results.append(
                self._analyze_dataset_object(
                    dataset,
                    run_dir,
                    docx_out=run_docx,
                    thresholds=thresholds,
                    model_config=model_config if index == len(ordered) else None,
                    model_enabled=model_enabled and index == len(ordered),
                    model_unavailable_reason=model_unavailable_reason,
                    create_offline_package=index == len(ordered),
                )
            )
        return results

    def _analyze_dataset_object(self, dataset: DeepDataset, report_dir: Path, **kwargs) -> DeepRunResult:
        """One validated business transaction; deliver files only after it commits."""
        dataset = dataset.model_copy(deep=True)
        pointer_validation = validate_log_event_references(dataset)
        report_dir = Path(report_dir)
        history = DeepHistoryStore(report_dir.parent / "deep-history.db")
        target = report_dir if not report_dir.exists() else report_dir.with_name(f"{report_dir.name}-review-{uuid4().hex[:8]}")
        dataset_target = target.parent / f"{target.name}.deep-dataset-{dataset.dataset_id}"
        if dataset_target.exists():
            dataset_target = dataset_target.with_name(f"{dataset_target.name}-{uuid4().hex[:8]}")
        final_docx = Path(kwargs["docx_out"]) if kwargs.get("docx_out") else None
        final_json = Path(kwargs["dataset_json_out"]) if kwargs.get("dataset_json_out") else None
        for key, path in (("docx_out", final_docx), ("dataset_json_out", final_json)):
            if path and path.exists():
                changed = path.with_name(f"{path.stem}-{uuid4().hex[:8]}{path.suffix}")
                if key == "docx_out":
                    final_docx = changed
                else:
                    final_json = changed
        report_dir.parent.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(prefix=".vstacklens-deep-stage-", dir=report_dir.parent) as temporary:
            root = Path(temporary)
            staged_kwargs = dict(kwargs)
            staged_kwargs["docx_out"] = root / final_docx.name if final_docx else None
            staged_kwargs["dataset_json_out"] = root / final_json.name if final_json else None
            with history.transaction(dataset):
                result = self._analyze_dataset_object_impl(dataset, root / target.name, **staged_kwargs,
                    history=history, persisted_dataset_path=dataset_target, pointer_validation=pointer_validation)
            moves = [(root / target.name, target)]
            for source in root.iterdir():
                if source == root / target.name:
                    continue
                destination = final_docx if final_docx and source.name == final_docx.name else final_json if final_json and source.name == final_json.name else dataset_target if source.is_dir() and ".deep-dataset-" in source.name else target.parent / source.name
                if destination.exists():
                    destination = destination.with_name(f"{destination.stem}-{uuid4().hex[:8]}{destination.suffix}")
                moves.append((source, destination))
            locations = {}
            for source, destination in moves:
                destination.parent.mkdir(parents=True, exist_ok=True)
                os.rename(source, destination)
                locations[source] = destination
            result.report_dir = target
            result.html_path = target / result.html_path.name
            result.docx_path = final_docx
            result.diagnostic_path = locations[result.diagnostic_path]
            if result.offline_evidence_zip:
                result.offline_evidence_zip = locations[result.offline_evidence_zip]
            return result

    def _analyze_dataset_object_impl(
        self,
        dataset: DeepDataset,
        report_dir: Path,
        *,
        docx_out: Path | None = None,
        thresholds: ThresholdRegistry | None = None,
        model_config: CloudModelConfig | None = None,
        model_enabled: bool = False,
        model_unavailable_reason: str = "not_configured",
        known_secrets: list[str] | tuple[str, ...] = (),
        create_offline_package: bool = True,
        dataset_json_out: Path | None = None,
        history: DeepHistoryStore,
        persisted_dataset_path: Path,
        pointer_validation: dict,
    ) -> DeepRunResult:
        report_dir = Path(report_dir)
        report_dir.mkdir(parents=True, exist_ok=True)
        event_pointer_validation = pointer_validation
        if dataset_json_out:
            dataset.to_json(Path(dataset_json_out))
        environment_id = str(dataset.manifest.target.get("vcenter_ref") or "unknown")
        history.record_metric_observations(dataset)
        historical_metric_records = [
            *history.metric_records(
                environment_id,
                metric_id="datastore.used_percent",
                rule_id="CAP-DEEP-001",
                as_of=dataset.manifest.created_at_utc,
                as_of_dataset_id=dataset.dataset_id,
            ),
            *history.metric_records(
                environment_id,
                metric_id="vsan.used_percent",
                rule_id="VSAN-TREND-001",
                as_of=dataset.manifest.created_at_utc,
                as_of_dataset_id=dataset.dataset_id,
            ),
            *history.metric_records(
                environment_id,
                metric_id="vm.count",
                rule_id="CAP-DEEP-002",
                as_of=dataset.manifest.created_at_utc,
                as_of_dataset_id=dataset.dataset_id,
            ),
            *history.metric_records(
                environment_id,
                metric_id="thin_provision.ratio",
                rule_id="CAP-DEEP-003",
                as_of=dataset.manifest.created_at_utc,
                as_of_dataset_id=dataset.dataset_id,
            ),
        ]
        analysis_dataset = dataset.model_copy(deep=True)
        anchor = datetime.fromisoformat(dataset.manifest.created_at_utc.replace("Z", "+00:00")).astimezone(UTC)
        analysis_dataset.records = [record for record in analysis_dataset.records if not record.metadata.get("history") or datetime.fromisoformat(record.collected_at_utc.replace("Z", "+00:00")).astimezone(UTC) <= anchor]
        analysis_dataset.records.extend(historical_metric_records)
        analysis_dataset.records, merge_log = merge_records(analysis_dataset.records)
        analysis_dataset.collection_log.append(merge_log)
        analysis = self.analyzer.analyze(analysis_dataset, thresholds=thresholds)
        dataset_dir = report_dir.parent / f"{report_dir.name}.deep-dataset-{dataset.dataset_id}"
        if dataset_dir.exists():
            dataset_dir = dataset_dir.with_name(f"{dataset_dir.name}-{uuid4().hex[:8]}")
        DeepDatasetWriter().write(dataset, dataset_dir, supplemental_records=historical_metric_records)
        lifecycles = history.record(dataset, analysis, persisted_dataset_path)
        analysis.diagnostic.finding_lifecycle_history = history.lifecycle_snapshot(environment_id, as_of=dataset.manifest.created_at_utc, as_of_dataset_id=dataset.dataset_id)
        trend_summaries = {str(days): history.trend_summary(environment_id, window_days=days, as_of=dataset.manifest.created_at_utc, as_of_dataset_id=dataset.dataset_id) for days in (30, 90)}
        trend_summary = trend_summaries["90"]
        analysis.report.trend_summary = trend_summary
        analysis.report.trend_summaries = trend_summaries
        analysis.diagnostic.collection_log.append({"action": "history.trend", "status": "ready" if any(item.get("state") == "READY" for item in trend_summaries.values()) else "insufficient_data", "windows": trend_summaries})
        if any(item.get("state") == "READY" for item in trend_summaries.values()) and not any(item.category.value == "trend" for item in analysis.report.analysis_scope):
            from vstacklens.deep.contracts import DeepAnalysisScope, DeepCategory

            analysis.report.analysis_scope.append(DeepAnalysisScope(category=DeepCategory.TREND, label="趋势", completed_capabilities=["history"], finding_count=0, pass_count=0))
        for finding in analysis.findings:
            if finding.finding_id in lifecycles:
                finding.lifecycle = lifecycles[finding.finding_id]
        for finding in analysis.report.findings:
            if finding.finding_id in lifecycles:
                finding.lifecycle = lifecycles[finding.finding_id]
        model_analysis = DeepModelAssistant().analyze(
            dataset,
            analysis,
            enabled=model_enabled,
            config=model_config,
            unavailable_reason=model_unavailable_reason,
        )
        analysis.diagnostic.model_analysis = model_analysis
        analysis.diagnostic.collection_log.append(
            {
                "action": "deep.model_analysis",
                "status": model_analysis.get("status", "unknown"),
                "source": model_analysis.get("provider", "local_only"),
                "request_count": model_analysis.get("request_count", 0),
                "accepted_count": model_analysis.get("accepted_count", 0),
                "reason": model_analysis.get("reason", ""),
            }
        )
        analysis.diagnostic.collection_log.append(
            {
                "action": "evidence.log_event_pointer_validation",
                "status": event_pointer_validation.get("status", "unknown"),
                "source": "local_dataset",
                **event_pointer_validation,
            }
        )
        html_path = DeepHtmlReportBuilder().render(analysis.report, report_dir / "index.html", dataset)
        docx_path = DeepWordReportBuilder().render(analysis.report, Path(docx_out), dataset) if docx_out else None
        diagnostic_path = DeepDiagnosticRecordStore().write(analysis.diagnostic, report_dir.parent / f"{report_dir.name}.deep-diagnostic.json")
        package_path: Path | None = None
        package_status = "not_requested" if not create_offline_package else "failed"
        if create_offline_package:
            try:
                package_secrets = [*known_secrets]
                if model_config and model_config.api_key:
                    package_secrets.append(model_config.api_key)
                package_path = DeepOfflineEvidencePackager().build(
                    dataset,
                    analysis,
                    report_dir.parent,
                    supplemental_records=historical_metric_records,
                    model_analysis=model_analysis,
                    known_secrets=package_secrets,
                )
                package_status = "created"
            except Exception as exc:  # noqa: BLE001 - preserve the completed analysis and record package failure.
                analysis.diagnostic.collection_log.append(
                    {
                        "action": "deep.offline_evidence_package",
                        "status": "error",
                        "source": "local",
                        "reason": type(exc).__name__,
                    }
                )
            else:
                analysis.diagnostic.collection_log.append(
                    {
                        "action": "deep.offline_evidence_package",
                        "status": "created",
                        "source": "local",
                        "reason": "",
                        "artifact_name": package_path.name,
                    }
                )
        diagnostic_path = DeepDiagnosticRecordStore().write(
            analysis.diagnostic,
            report_dir.parent / f"{report_dir.name}.deep-diagnostic.json",
        )
        return DeepRunResult(
            dataset.dataset_id,
            report_dir,
            html_path,
            docx_path,
            diagnostic_path,
            analysis,
            offline_evidence_zip=package_path,
            model_analysis_status=str(model_analysis.get("status") or "unknown"),
            offline_evidence_package_status=package_status,
        )
