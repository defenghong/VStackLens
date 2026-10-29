from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any
from uuid import uuid4

from vstacklens.deep.analyzer import DeepAnalysisResult
from vstacklens.deep.contracts import DatasetRecord, DeepDataset, DeepEntity, DeepSource, DeepWindow, now_utc_iso
from vstacklens.deep.backup import backup_before_migration
from vstacklens.deep.provenance import fingerprint


_CAPACITY_METRICS = {
    ("STO-DEEP-004", "config"): ("datastore.used_percent", "CAP-DEEP-001"),
    ("VSAN-DEEP-001", "vsan"): ("vsan.used_percent", "VSAN-TREND-001"),
    ("CAP-DEEP-002", "perf"): ("vm.count", "CAP-DEEP-002"),
    ("CAP-DEEP-003", "perf"): ("thin_provision.ratio", "CAP-DEEP-003"),
}


class DeepHistoryStore:
    """Persist Dataset/Finding metadata while keeping raw Dataset files immutable."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._transaction_connection: sqlite3.Connection | None = None
        self._init()

    @contextmanager
    def _connection(self):
        if self._transaction_connection is not None:
            yield self._transaction_connection
        else:
            with closing(sqlite3.connect(self.path)) as conn, conn:
                yield conn

    @contextmanager
    def transaction(self, dataset: DeepDataset):
        """Validate under the write lock before any service business writes."""
        if self._transaction_connection is not None:
            raise RuntimeError("Nested Deep history transaction")
        with closing(sqlite3.connect(self.path)) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                self._validate_dataset_identity(conn, dataset)
                self._transaction_connection = conn
                yield self
                conn.commit()
            except BaseException:
                conn.rollback()
                raise
            finally:
                self._transaction_connection = None

    @staticmethod
    def _validate_dataset_identity(conn, dataset):
        environment_id = str(dataset.manifest.target.get("vcenter_ref") or "unknown")
        canonical = conn.execute("SELECT analysis_id, lifecycle_json, input_sha256 FROM deep_analysis_runs WHERE dataset_id=? AND canonical=1", (dataset.dataset_id,)).fetchone()
        existing = conn.execute("SELECT environment_id, created_at_utc FROM deep_datasets WHERE dataset_id=?", (dataset.dataset_id,)).fetchone()
        if existing and (existing[0] != environment_id or existing[1] != dataset.manifest.created_at_utc):
            raise ValueError("Dataset identifier was reused for a different environment or collection time")
        if canonical and canonical[2] != fingerprint(dataset.model_dump(mode="json")):
            raise ValueError("Dataset identifier was reused for different original evidence")
        if existing and not canonical:
            raise ValueError("Historical Dataset has no original evidence fingerprint; append under the same ID is not verifiable")
        return canonical, existing

    def _init(self) -> None:
        with sqlite3.connect(self.path) as conn:
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            self.migration_backup = backup_before_migration(conn, self.path) if "deep_datasets" in tables and "deep_analysis_runs" not in tables else None
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS deep_datasets (
                  dataset_id TEXT PRIMARY KEY,
                  environment_id TEXT NOT NULL,
                  created_at_utc TEXT NOT NULL,
                  dataset_path TEXT,
                  manifest_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS deep_finding_history (
                  finding_id TEXT PRIMARY KEY,
                  environment_id TEXT NOT NULL,
                  rule_id TEXT NOT NULL,
                  first_seen_dataset TEXT NOT NULL,
                  last_seen_dataset TEXT NOT NULL,
                  occurrence_count INTEGER NOT NULL,
                  status TEXT NOT NULL,
                  lifecycle_json TEXT NOT NULL,
                  updated_at_utc TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS deep_finding_observations (
                  dataset_id TEXT NOT NULL,
                  finding_id TEXT NOT NULL,
                  observed_at_utc TEXT NOT NULL,
                  payload_json TEXT NOT NULL,
                  PRIMARY KEY(dataset_id, finding_id)
                );
                CREATE TABLE IF NOT EXISTS deep_rule_evaluations (
                  dataset_id TEXT NOT NULL,
                  environment_id TEXT NOT NULL,
                  rule_id TEXT NOT NULL,
                  status TEXT NOT NULL,
                  PRIMARY KEY(dataset_id, rule_id)
                );
                CREATE TABLE IF NOT EXISTS deep_metric_observations (
                  dataset_id TEXT NOT NULL,
                  environment_id TEXT NOT NULL,
                  metric_id TEXT NOT NULL,
                  rule_id TEXT NOT NULL,
                  entity_id TEXT NOT NULL,
                  entity_type TEXT NOT NULL,
                  entity_ref TEXT NOT NULL,
                  observed_at_utc TEXT NOT NULL,
                  value REAL NOT NULL,
                  unit TEXT NOT NULL,
                  PRIMARY KEY(dataset_id, metric_id, entity_id)
                );
                CREATE TABLE IF NOT EXISTS deep_metric_backfill (
                  dataset_id TEXT PRIMARY KEY,
                  completed_at_utc TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS deep_analysis_runs (
                  analysis_id TEXT PRIMARY KEY,
                  dataset_id TEXT NOT NULL,
                  environment_id TEXT NOT NULL,
                  dataset_created_at_utc TEXT NOT NULL,
                  analyzed_at_utc TEXT NOT NULL,
                  canonical INTEGER NOT NULL,
                  input_sha256 TEXT NOT NULL,
                  provenance_json TEXT NOT NULL,
                  analysis_json TEXT NOT NULL,
                  lifecycle_json TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS deep_analysis_canonical
                  ON deep_analysis_runs(dataset_id) WHERE canonical = 1;
                """
            )

    def record_metric_observations(self, dataset: DeepDataset) -> None:
        """Persist stable current-capacity measurements without changing the Dataset."""

        environment_id = str(dataset.manifest.target.get("vcenter_ref") or "unknown")
        with self._connection() as conn:
            self._validate_dataset_identity(conn, dataset)
            self._record_metric_observations(conn, dataset, environment_id)

    def record(self, dataset: DeepDataset, analysis: DeepAnalysisResult, dataset_path: Path | None = None) -> dict[str, dict[str, Any]]:
        environment_id = str(dataset.manifest.target.get("vcenter_ref") or "unknown")
        now = now_utc_iso()
        provenance = analysis.diagnostic.analysis_provenance
        current_ids = {finding.finding_id for finding in analysis.findings}
        rule_statuses = {
            result.rule_id: str(getattr(result.status, "value", result.status)).upper()
            for result in analysis.rule_results
        }
        with self._connection() as conn:
            if self._transaction_connection is None:
                conn.execute("BEGIN IMMEDIATE")
            canonical, legacy_existing = self._validate_dataset_identity(conn, dataset)
            if canonical or legacy_existing:
                states = json.loads(canonical[1]) if canonical else self._snapshot_at(conn, environment_id, dataset.manifest.created_at_utc)
                provenance["history_write"] = "REANALYSIS_ONLY"
                provenance["original_analysis_id"] = canonical[0] if canonical else "LEGACY_ORIGINAL_NOT_ARCHIVED"
                self._archive_analysis(conn, dataset, analysis, states, canonical=False)
                return {item["finding_id"]: item for item in states if item["finding_id"] in current_ids}
            states = self._snapshot_at(conn, environment_id, dataset.manifest.created_at_utc)
            state_index = {item["finding_id"]: item for item in states}
            conn.execute(
                "INSERT OR IGNORE INTO deep_datasets(dataset_id, environment_id, created_at_utc, dataset_path, manifest_json) VALUES (?, ?, ?, ?, ?)",
                (dataset.dataset_id, environment_id, dataset.manifest.created_at_utc, str(dataset_path or ""), dataset.manifest.model_dump_json()),
            )
            for rule_id, status in rule_statuses.items():
                conn.execute(
                    "INSERT OR IGNORE INTO deep_rule_evaluations(dataset_id, environment_id, rule_id, status) VALUES (?, ?, ?, ?)",
                    (dataset.dataset_id, environment_id, rule_id, status),
                )
            self._record_metric_observations(conn, dataset, environment_id)
            for finding in analysis.findings:
                existing = state_index.get(finding.finding_id, {})
                lifecycle = {
                    **existing,
                    "finding_id": finding.finding_id,
                    "rule_id": finding.rule_id,
                    "status": "OPEN",
                    "verification_status": "CONFIRMED",
                    "verification_label": "本次确认问题仍存在",
                    "first_seen_dataset": existing.get("first_seen_dataset", dataset.dataset_id),
                    "last_seen_dataset": dataset.dataset_id,
                    "occurrence_count": int(existing.get("occurrence_count", 0)) + 1,
                    "original_finding": existing.get("original_finding", finding.model_dump(mode="json")),
                    "last_observed_finding": finding.model_dump(mode="json"),
                    "original_rule_fingerprint": existing.get("original_rule_fingerprint", provenance.get("rule_fingerprints", {}).get(finding.rule_id, "") if provenance.get("resolution_eligible") else ""),
                }
                lifecycle.pop("resolved_dataset", None)
                state_index[finding.finding_id] = lifecycle
                conn.execute(
                    "INSERT OR IGNORE INTO deep_finding_observations(dataset_id, finding_id, observed_at_utc, payload_json) VALUES (?, ?, ?, ?)",
                    (dataset.dataset_id, finding.finding_id, dataset.manifest.created_at_utc, finding.model_dump_json()),
                )
            for finding_id, lifecycle in state_index.items():
                if finding_id in current_ids or lifecycle.get("status") != "OPEN":
                    continue
                reason, evidence = self._verification(dataset, analysis, lifecycle)
                if reason == "CONFIRMED_RESOLVED":
                    lifecycle.update({
                        "status": "RESOLVED",
                        "verification_status": "CONFIRMED_RESOLVED",
                        "verification_label": "原对象已复检并确认解决",
                        "resolved_dataset": dataset.dataset_id,
                        "resolution_evidence": evidence,
                    })
                else:
                    lifecycle.update({
                        "status": "OPEN",
                        "verification_status": "UNVERIFIED",
                        "verification_dataset": dataset.dataset_id,
                        "verification_reason": reason,
                        "verification_label": {"OBJECT_ABSENT": "对象缺席，不能确认解决", "INSUFFICIENT_DATA": "数据不足", "PERMISSION_DENIED": "权限失败", "POLICY_CHANGED": "判断口径变化，尚未按原口径复核", "ORIGINAL_POLICY_MISSING": "缺少历史判断口径，尚未验证解决", "HISTORICAL_NOT_REPEATED": "当前窗口未再触发，不能确认历史问题已解决", "ERROR": "复检出错"}.get(reason, "未复检"),
                    })
            states = list(state_index.values())
            self._archive_analysis(conn, dataset, analysis, states, canonical=True)
            newer = conn.execute("SELECT 1 FROM deep_datasets WHERE environment_id = ? AND julianday(created_at_utc) > julianday(?) LIMIT 1", (environment_id, dataset.manifest.created_at_utc)).fetchone()
            if not newer:
                for lifecycle in states:
                    conn.execute(
                        "INSERT OR REPLACE INTO deep_finding_history VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (lifecycle["finding_id"], environment_id, lifecycle["rule_id"], lifecycle["first_seen_dataset"], lifecycle["last_seen_dataset"], lifecycle["occurrence_count"], lifecycle["status"], json.dumps(lifecycle, ensure_ascii=False), now),
                    )
        return {item["finding_id"]: item for item in states if item["finding_id"] in current_ids}

    @staticmethod
    def _archive_analysis(conn, dataset, analysis, states, *, canonical):
        provenance = analysis.diagnostic.analysis_provenance
        conn.execute("INSERT INTO deep_analysis_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (
            uuid4().hex, dataset.dataset_id, str(dataset.manifest.target.get("vcenter_ref") or "unknown"),
            dataset.manifest.created_at_utc, now_utc_iso(), int(canonical), fingerprint(dataset.model_dump(mode="json")),
            json.dumps(provenance, ensure_ascii=False),
            json.dumps({"rule_results": [item.model_dump(mode="json") for item in analysis.rule_results], "findings": [item.model_dump(mode="json") for item in analysis.findings]}, ensure_ascii=False),
            json.dumps(states, ensure_ascii=False),
        ))

    @staticmethod
    def _verification(dataset, analysis, lifecycle):
        from vstacklens.collection.diagnostics import permission_failure
        rule_id = lifecycle["rule_id"]
        result = next((item for item in analysis.rule_results if item.rule_id == rule_id), None)
        if result is None:
            return "NOT_RECHECKED", []
        caps = [dataset.capability.get(item) for item in result.missing_capabilities]
        if any(cap and permission_failure(cap.detail) for cap in caps):
            return "PERMISSION_DENIED", []
        if result.missing_capabilities:
            return "NOT_RECHECKED", []
        original = lifecycle.get("last_observed_finding") or lifecycle.get("original_finding") or {}
        scope = original.get("scope") or {}
        ids = set(scope.get("member_ids") or [scope.get("scope_id")]) - {None, ""}
        matches = [item for item in result.object_results if item.scope.dimension_key == scope.get("dimension_key") and item.scope.scope_type.value == scope.get("scope_type") and set(item.scope.member_ids or [item.scope.scope_id]) <= ids]
        checked_ids = {entity_id for item in matches for entity_id in item.scope.member_ids or [item.scope.scope_id]}
        if not ids or ids - checked_ids:
            inventory_ids = {record.entity.stable_id for record in dataset.records}
            return ("NOT_RECHECKED" if ids and ids <= inventory_ids else "OBJECT_ABSENT"), []
        if any(item.reason == "permission_denied" for item in matches):
            return "PERMISSION_DENIED", []
        if any(item.status.value == "ERROR" for item in matches):
            return "ERROR", []
        if any(item.status.value == "INSUFFICIENT_DATA" for item in matches):
            return "INSUFFICIENT_DATA", []
        if any(item.status.value != "PASS" or not item.evidence_refs for item in matches):
            return "NOT_RECHECKED", []
        provenance = analysis.diagnostic.analysis_provenance
        if not lifecycle.get("original_rule_fingerprint"):
            return "ORIGINAL_POLICY_MISSING", []
        if not provenance.get("resolution_eligible"):
            return ("POLICY_CHANGED" if provenance.get("original_policy_available") else "ORIGINAL_POLICY_MISSING"), []
        if lifecycle["original_rule_fingerprint"] != provenance.get("rule_fingerprints", {}).get(rule_id):
            return "POLICY_CHANGED", []
        if original.get("category") != "current_risk":
            return "HISTORICAL_NOT_REPEATED", []
        return "CONFIRMED_RESOLVED", [item.model_dump(mode="json") for item in matches]

    @staticmethod
    def _snapshot_at(conn, environment_id, as_of=None, dataset_id=None):
        if dataset_id:
            exact = conn.execute("SELECT lifecycle_json FROM deep_analysis_runs WHERE dataset_id=? AND environment_id=? AND canonical=1 AND (? IS NULL OR julianday(dataset_created_at_utc)<=julianday(?))", (dataset_id, environment_id, as_of, as_of)).fetchone()
            if exact:
                return json.loads(exact[0])
        row = conn.execute(
            "SELECT lifecycle_json FROM deep_analysis_runs WHERE environment_id=? AND canonical=1 "
            "AND (? IS NULL OR julianday(dataset_created_at_utc) <= julianday(?)) ORDER BY julianday(dataset_created_at_utc) DESC, rowid DESC LIMIT 1",
            (environment_id, as_of, as_of),
        ).fetchone()
        if row:
            return json.loads(row[0])
        # Legacy aggregate PASS never proves that the original object was checked.
        boundary = conn.execute("SELECT rowid FROM deep_datasets WHERE dataset_id=? AND environment_id=?", (dataset_id, environment_id)).fetchone()
        boundary_row = boundary[0] if boundary else -1
        rows = conn.execute(
            "SELECT o.finding_id, o.dataset_id, o.payload_json FROM deep_finding_observations o JOIN deep_datasets d ON d.dataset_id=o.dataset_id "
            "WHERE d.environment_id=? AND (? IS NULL OR julianday(d.created_at_utc)<=julianday(?)) "
            "AND (? IS NULL OR julianday(d.created_at_utc)<julianday(?) OR d.rowid<=?) ORDER BY julianday(d.created_at_utc), o.rowid",
            (environment_id, as_of, as_of, dataset_id, as_of, boundary_row),
        ).fetchall()
        states = {}
        for finding_id, dataset_id, payload in rows:
            finding = json.loads(payload)
            previous = states.get(finding_id, {})
            states[finding_id] = {"finding_id": finding_id, "rule_id": finding["rule_id"], "status": "OPEN", "verification_status": "UNVERIFIED", "verification_reason": "LEGACY_OBJECT_VERIFICATION_MISSING", "verification_label": "旧记录缺少原对象复检证据", "first_seen_dataset": previous.get("first_seen_dataset", dataset_id), "last_seen_dataset": dataset_id, "occurrence_count": previous.get("occurrence_count", 0) + 1, "original_finding": previous.get("original_finding", finding), "last_observed_finding": finding}
        return list(states.values())

    def lifecycle_snapshot(self, environment_id: str, *, resolved_limit: int = 250, as_of: str | None = None, as_of_dataset_id: str | None = None) -> dict[str, Any]:
        """Return bounded open/resolved finding history for diagnostics and offline review."""

        limit = max(0, min(1000, int(resolved_limit)))
        with self._connection() as conn:
            states = self._snapshot_at(conn, environment_id, as_of, as_of_dataset_id)
        open_rows = [item for item in states if item["status"] == "OPEN"]
        resolved_rows = [item for item in states if item["status"] == "RESOLVED"]
        resolved_count = len(resolved_rows)
        entries = [*open_rows, *resolved_rows[:limit]]
        return {
            "status_counts": {"OPEN": len(open_rows), "RESOLVED": resolved_count},
            "entries": entries,
            "omitted_resolved_count": max(0, resolved_count - limit),
            "as_of": as_of,
            "resolution_boundary": "RESOLVED requires PASS evidence for every original object under the same recorded rule and thresholds. Missing objects, permission failures, incomplete evidence, unevaluated rules and reinterpretation remain unverified.",
        }

    def metric_records(
        self,
        environment_id: str,
        *,
        metric_id: str,
        rule_id: str,
        window_days: int = 90,
        as_of: str | None = None,
        as_of_dataset_id: str | None = None,
    ) -> list[DatasetRecord]:
        """Return per-entity historical measurements as read-only trend evidence."""

        with self._connection() as conn:
            self._backfill_metric_observations(conn)
            boundary = conn.execute("SELECT rowid FROM deep_datasets WHERE dataset_id=? AND environment_id=?", (as_of_dataset_id, environment_id)).fetchone()
            boundary_row = boundary[0] if boundary else -1
            all_rows = conn.execute(
                "SELECT observed_at_utc FROM deep_metric_observations WHERE environment_id = ? AND metric_id = ? "
                "AND (? IS NULL OR julianday(observed_at_utc) <= julianday(?)) ORDER BY julianday(observed_at_utc)",
                (environment_id, metric_id, as_of, as_of),
            ).fetchall()
            if not all_rows:
                return []
            anchor = datetime.fromisoformat(str(as_of or all_rows[-1][0]).replace("Z", "+00:00")).astimezone(UTC)
            cutoff = anchor - timedelta(days=window_days)
            rows = conn.execute(
                """
                SELECT m.dataset_id, entity_id, entity_type, entity_ref, observed_at_utc, value, unit
                FROM deep_metric_observations m LEFT JOIN deep_datasets d ON d.dataset_id=m.dataset_id
                WHERE m.environment_id = ? AND metric_id = ? AND julianday(observed_at_utc) >= julianday(?)
                  AND julianday(observed_at_utc) <= julianday(?)
                  AND (d.dataset_id IS NULL OR julianday(d.created_at_utc) <= julianday(?))
                  AND (? IS NULL OR m.dataset_id = ? OR (d.rowid IS NOT NULL AND (julianday(d.created_at_utc) < julianday(?) OR d.rowid <= ?)))
                ORDER BY entity_id, julianday(observed_at_utc)
                """,
                (environment_id, metric_id, cutoff.isoformat(), anchor.isoformat(), anchor.isoformat(), as_of_dataset_id, as_of_dataset_id, anchor.isoformat(), boundary_row),
            ).fetchall()
        daily_rows: dict[tuple[str, str], tuple[Any, ...]] = {}
        for row in rows:
            day = datetime.fromisoformat(str(row[4]).replace("Z", "+00:00")).astimezone(UTC).date().isoformat()
            daily_rows[(str(row[1]), day)] = row
        return [
            DatasetRecord(
                record_id=f"history-{metric_id}-{row[0]}-{row[1]}",
                dataset_id=str(row[0]),
                kind="perf",
                entity=DeepEntity(type=str(row[2]), stable_id=str(row[1]), display_ref=str(row[3])),
                collected_at_utc=str(row[4]),
                source=DeepSource(api="DeepHistoryStore", collector="vstacklens.deep.history", collected_at_utc=str(row[4])),
                selector={"counter": metric_id},
                window=DeepWindow(start=str(row[4]), end=str(row[4]), interval_sec=86400, sample_count=1, expected_sample_count=1, completeness=1.0),
                interval_sec=86400,
                rollup="snapshot",
                value=float(row[5]),
                unit=str(row[6]),
                raw_pointer=f"history/metrics/{metric_id}.ndjson#{row[0]}",
                metadata={"rule_id": rule_id, "history": True, "metric_id": metric_id},
            )
            for row in sorted(daily_rows.values(), key=lambda item: (str(item[1]), str(item[4])))
        ]

    def _record_metric_observations(self, conn: sqlite3.Connection, dataset: DeepDataset, environment_id: str) -> None:
        for record in dataset.records:
            if record.metadata.get("history"):
                continue
            metric = _CAPACITY_METRICS.get((str(record.metadata.get("rule_id") or ""), record.kind))
            if metric is None:
                continue
            try:
                value = float(record.value)
            except (TypeError, ValueError):
                continue
            metric_id, rule_id = metric
            conn.execute(
                """
                INSERT OR IGNORE INTO deep_metric_observations(
                  dataset_id, environment_id, metric_id, rule_id, entity_id, entity_type,
                  entity_ref, observed_at_utc, value, unit
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    dataset.dataset_id,
                    environment_id,
                    metric_id,
                    rule_id,
                    record.entity.stable_id,
                    record.entity.type,
                    record.entity.display_ref,
                    record.collected_at_utc,
                    value,
                    record.unit,
                ),
            )

    def _backfill_metric_observations(self, conn: sqlite3.Connection) -> None:
        rows = conn.execute(
            """
            SELECT d.dataset_id, d.environment_id, d.dataset_path
            FROM deep_datasets AS d
            LEFT JOIN deep_metric_backfill AS b ON b.dataset_id = d.dataset_id
            WHERE d.dataset_path != '' AND b.dataset_id IS NULL
            """
        ).fetchall()
        for dataset_id, environment_id, dataset_path in rows:
            root = Path(str(dataset_path))
            for relative in (Path("config") / "config.ndjson", Path("vsan") / "vsan.ndjson"):
                source = root / relative
                if not source.exists():
                    continue
                for line in source.read_text(encoding="utf-8").splitlines():
                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    metadata = payload.get("metadata") or {}
                    metric = _CAPACITY_METRICS.get((str(metadata.get("rule_id") or ""), str(payload.get("kind") or "")))
                    entity = payload.get("entity") or {}
                    if metric is None or not entity.get("stable_id"):
                        continue
                    try:
                        value = float(payload.get("value"))
                    except (TypeError, ValueError):
                        continue
                    metric_id, rule_id = metric
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO deep_metric_observations(
                          dataset_id, environment_id, metric_id, rule_id, entity_id, entity_type,
                          entity_ref, observed_at_utc, value, unit
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            str(dataset_id),
                            str(environment_id),
                            metric_id,
                            rule_id,
                            str(entity["stable_id"]),
                            str(entity.get("type") or "Datastore"),
                            str(entity.get("display_ref") or ""),
                            str(payload.get("collected_at_utc") or ""),
                            value,
                            str(payload.get("unit") or "percent"),
                        ),
                    )
            conn.execute(
                "INSERT OR IGNORE INTO deep_metric_backfill(dataset_id, completed_at_utc) VALUES (?, ?)",
                (str(dataset_id), now_utc_iso()),
            )

    def trend_summary(self, environment_id: str, *, window_days: int = 90, as_of: str | None = None, as_of_dataset_id: str | None = None) -> dict[str, Any]:
        with self._connection() as conn:
            boundary = conn.execute("SELECT rowid FROM deep_datasets WHERE dataset_id=? AND environment_id=?", (as_of_dataset_id, environment_id)).fetchone()
            boundary_row = boundary[0] if boundary else -1
            all_rows = conn.execute(
                "SELECT dataset_id, created_at_utc FROM deep_datasets WHERE environment_id = ? "
                "AND (? IS NULL OR julianday(created_at_utc) <= julianday(?)) "
                "AND (? IS NULL OR dataset_id=? OR julianday(created_at_utc)<julianday(?) OR rowid<=?) ORDER BY julianday(created_at_utc), rowid",
                (environment_id, as_of, as_of, as_of_dataset_id, as_of_dataset_id, as_of, boundary_row),
            ).fetchall()
            if not all_rows:
                return {"state": "INSUFFICIENT_DATA", "dataset_count": 0, "window_days": window_days}
            anchor = datetime.fromisoformat(str(as_of or all_rows[-1][1]).replace("Z", "+00:00")).astimezone(UTC)
            cutoff = anchor - timedelta(days=window_days)
            rows = [row for row in all_rows if datetime.fromisoformat(str(row[1]).replace("Z", "+00:00")).astimezone(UTC) >= cutoff]
            if len(rows) < 2:
                return {"state": "INSUFFICIENT_DATA", "dataset_count": len(rows), "window_days": window_days, "coverage_days": 0.0}
            datasets = [row[0] for row in rows]
            coverage_days = (datetime.fromisoformat(str(rows[-1][1]).replace("Z", "+00:00")).astimezone(UTC) - datetime.fromisoformat(str(rows[0][1]).replace("Z", "+00:00")).astimezone(UTC)).total_seconds() / 86400
            if coverage_days + 1 < window_days:
                return {
                    "state": "INSUFFICIENT_DATA",
                    "dataset_count": len(rows),
                    "window_days": window_days,
                    "coverage_days": round(coverage_days, 2),
                    "reason": "time coverage is shorter than the requested trend window",
                }
            observations: dict[str, set[str]] = {}
            for dataset_id in datasets:
                observations[dataset_id] = {
                    str(item[0])
                    for item in conn.execute("SELECT finding_id FROM deep_finding_observations WHERE dataset_id = ?", (dataset_id,)).fetchall()
                }
            baseline_id, current_id = datasets[0], datasets[-1]
            baseline_findings = observations[baseline_id]
            current_findings = observations[current_id]
            absent_from_current = baseline_findings - current_findings
            states = self._snapshot_at(conn, environment_id, str(rows[-1][1]), current_id)
            verified_resolved = {item["finding_id"] for item in states if item.get("verification_status") == "CONFIRMED_RESOLVED"}
            unverified_findings = {
                item["finding_id"] for item in states if item["status"] == "OPEN" and item["finding_id"] not in current_findings
            } | (absent_from_current - verified_resolved)
            resolved_findings = absent_from_current & verified_resolved
            return {
                "state": "READY",
                "window_days": window_days,
                "coverage_days": round(coverage_days, 2),
                "dataset_count": len(rows),
                "baseline_dataset_id": baseline_id,
                "current_dataset_id": current_id,
                "baseline_created_at_utc": rows[0][1],
                "current_created_at_utc": rows[-1][1],
                "finding_count_baseline": len(baseline_findings),
                "finding_count_current": len(current_findings),
                "finding_count_delta": len(current_findings) - len(baseline_findings),
                "new_finding_count": len(current_findings - baseline_findings),
                "resolved_finding_count": len(resolved_findings),
                "persistent_finding_count": len(current_findings & baseline_findings),
                "unverified_finding_count": len(unverified_findings),
                "comparison_complete": not unverified_findings,
            }
