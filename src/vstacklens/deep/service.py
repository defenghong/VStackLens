from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from vstacklens.deep.analyzer import BUILTIN_DEEP_RULES, DeepAnalysisResult, DeepAnalyzer
from vstacklens.deep.contracts import DeepDataset, ThresholdRegistry
from vstacklens.deep.dataset import DeepDatasetWriter, DeepDiagnosticRecordStore
from vstacklens.deep.policies import default_threshold_registry
from vstacklens.deep.report import DeepHtmlReportBuilder, DeepWordReportBuilder
from vstacklens.deep.connection import _workbook_connection_secrets, load_esxi_host_connections_from_workbook, load_vcenter_connection_from_workbook
from vstacklens.deep.interfaces import DeepCollectionPolicy
from vstacklens.deep.pyvmomi_collector import PyVmomiDeepCollector
from vstacklens.deep.history import DeepHistoryStore
from vstacklens.deep.merge import merge_records
from vstacklens.deep.redaction import redact_dataset_credentials


@dataclass(slots=True)
class DeepRunResult:
    dataset_id: str
    report_dir: Path
    html_path: Path
    docx_path: Path | None
    diagnostic_path: Path
    analysis: DeepAnalysisResult


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
    ) -> DeepRunResult:
        dataset = DeepDataset.from_json(Path(dataset_path))
        return self._analyze_dataset_object(dataset, report_dir, docx_out=docx_out, thresholds=thresholds)

    def collect_and_analyze_vcenter(
        self,
        workbook_path: Path,
        report_dir: Path,
        *,
        docx_out: Path | None = None,
        policy: DeepCollectionPolicy | None = None,
        cancel_requested=None,
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
        dataset_json = Path(report_dir).parent / f"{Path(report_dir).name}.dataset.json"
        dataset.to_json(dataset_json)
        return self._analyze_dataset_object(dataset, report_dir, docx_out=docx_out)

    def replay_datasets(
        self,
        dataset_paths: list[Path],
        report_dir: Path,
        *,
        docx_out: Path | None = None,
        thresholds: ThresholdRegistry | None = None,
    ) -> list[DeepRunResult]:
        """Replay immutable Dataset files in manifest time order through one history store."""
        ordered = sorted((Path(path) for path in dataset_paths), key=lambda path: DeepDataset.from_json(path).manifest.created_at_utc)
        results: list[DeepRunResult] = []
        for index, dataset_path in enumerate(ordered, start=1):
            dataset = DeepDataset.from_json(dataset_path)
            run_dir = Path(report_dir) / f"{index:03d}-{dataset.dataset_id}"
            run_docx = Path(docx_out) if docx_out and index == len(ordered) else None
            results.append(self._analyze_dataset_object(dataset, run_dir, docx_out=run_docx, thresholds=thresholds))
        return results

    def _analyze_dataset_object(self, dataset: DeepDataset, report_dir: Path, *, docx_out: Path | None = None, thresholds: ThresholdRegistry | None = None) -> DeepRunResult:
        report_dir = Path(report_dir)
        report_dir.mkdir(parents=True, exist_ok=True)
        history = DeepHistoryStore(report_dir.parent / "deep-history.db")
        environment_id = str(dataset.manifest.target.get("vcenter_ref") or "unknown")
        history.record_metric_observations(dataset)
        historical_metric_records = [
            *history.metric_records(
                environment_id,
                metric_id="datastore.used_percent",
                rule_id="CAP-DEEP-001",
            ),
            *history.metric_records(
                environment_id,
                metric_id="vsan.used_percent",
                rule_id="VSAN-TREND-001",
            ),
            *history.metric_records(
                environment_id,
                metric_id="vm.count",
                rule_id="CAP-DEEP-002",
            ),
            *history.metric_records(
                environment_id,
                metric_id="thin_provision.ratio",
                rule_id="CAP-DEEP-003",
            ),
        ]
        analysis_dataset = dataset.model_copy(deep=True)
        analysis_dataset.records.extend(historical_metric_records)
        analysis_dataset.records, merge_log = merge_records(analysis_dataset.records)
        analysis_dataset.collection_log.append(merge_log)
        analysis = self.analyzer.analyze(analysis_dataset, rules=BUILTIN_DEEP_RULES, thresholds=thresholds or default_threshold_registry())
        dataset_dir = report_dir.parent / f"{report_dir.name}.deep-dataset-{dataset.dataset_id}"
        DeepDatasetWriter().write(dataset, dataset_dir, supplemental_records=historical_metric_records)
        lifecycles = history.record(dataset, analysis, dataset_dir)
        trend_summaries = {str(days): history.trend_summary(environment_id, window_days=days) for days in (30, 90)}
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
        html_path = DeepHtmlReportBuilder().render(analysis.report, report_dir / "index.html", dataset)
        docx_path = DeepWordReportBuilder().render(analysis.report, Path(docx_out), dataset) if docx_out else None
        diagnostic_path = DeepDiagnosticRecordStore().write(analysis.diagnostic, report_dir.parent / f"{report_dir.name}.deep-diagnostic.json")
        return DeepRunResult(dataset.dataset_id, report_dir, html_path, docx_path, diagnostic_path, analysis)
