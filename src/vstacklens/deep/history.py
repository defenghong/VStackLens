from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from vstacklens.deep.analyzer import DeepAnalysisResult
from vstacklens.deep.contracts import DatasetRecord, DeepDataset, DeepEntity, DeepSource, DeepWindow, now_utc_iso


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
        self._init()

    def _init(self) -> None:
        with sqlite3.connect(self.path) as conn:
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
                """
            )

    def record_metric_observations(self, dataset: DeepDataset) -> None:
        """Persist stable current-capacity measurements without changing the Dataset."""

        environment_id = str(dataset.manifest.target.get("vcenter_ref") or "unknown")
        with sqlite3.connect(self.path) as conn:
            self._record_metric_observations(conn, dataset, environment_id)
            conn.commit()

    def record(self, dataset: DeepDataset, analysis: DeepAnalysisResult, dataset_path: Path | None = None) -> dict[str, dict[str, Any]]:
        environment_id = str(dataset.manifest.target.get("vcenter_ref") or "unknown")
        now = now_utc_iso()
        lifecycles: dict[str, dict[str, Any]] = {}
        current_ids = {finding.finding_id for finding in analysis.findings}
        rule_statuses = {
            result.rule_id: str(getattr(result.status, "value", result.status)).upper()
            for result in analysis.rule_results
        }
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO deep_datasets(dataset_id, environment_id, created_at_utc, dataset_path, manifest_json) VALUES (?, ?, ?, ?, ?)",
                (dataset.dataset_id, environment_id, dataset.manifest.created_at_utc, str(dataset_path or ""), dataset.manifest.model_dump_json()),
            )
            for rule_id, status in rule_statuses.items():
                conn.execute(
                    "INSERT OR REPLACE INTO deep_rule_evaluations(dataset_id, environment_id, rule_id, status) VALUES (?, ?, ?, ?)",
                    (dataset.dataset_id, environment_id, rule_id, status),
                )
            self._record_metric_observations(conn, dataset, environment_id)
            for finding in analysis.findings:
                existing = conn.execute("SELECT first_seen_dataset, occurrence_count FROM deep_finding_history WHERE finding_id = ?", (finding.finding_id,)).fetchone()
                if existing is None:
                    first_seen = dataset.dataset_id
                    count = 1
                else:
                    first_seen = existing[0]
                    observed = conn.execute("SELECT 1 FROM deep_finding_observations WHERE dataset_id = ? AND finding_id = ?", (dataset.dataset_id, finding.finding_id)).fetchone()
                    count = int(existing[1]) if observed else int(existing[1]) + 1
                lifecycle = {
                    "status": "OPEN",
                    "verification_status": "CONFIRMED",
                    "first_seen_dataset": first_seen,
                    "last_seen_dataset": dataset.dataset_id,
                    "occurrence_count": count,
                }
                conn.execute(
                    "INSERT OR REPLACE INTO deep_finding_history(finding_id, environment_id, rule_id, first_seen_dataset, last_seen_dataset, occurrence_count, status, lifecycle_json, updated_at_utc) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (finding.finding_id, environment_id, finding.rule_id, first_seen, dataset.dataset_id, count, "OPEN", json.dumps(lifecycle, ensure_ascii=False), now),
                )
                conn.execute(
                    "INSERT OR IGNORE INTO deep_finding_observations(dataset_id, finding_id, observed_at_utc, payload_json) VALUES (?, ?, ?, ?)",
                    (dataset.dataset_id, finding.finding_id, now, finding.model_dump_json()),
                )
                lifecycles[finding.finding_id] = lifecycle
            rows = conn.execute("SELECT finding_id, rule_id, lifecycle_json FROM deep_finding_history WHERE environment_id = ? AND status = 'OPEN'", (environment_id,)).fetchall()
            for finding_id, rule_id, lifecycle_json in rows:
                if finding_id in current_ids:
                    continue
                lifecycle = json.loads(lifecycle_json)
                rule_status = rule_statuses.get(str(rule_id))
                if rule_status == "PASS":
                    lifecycle.update({
                        "status": "RESOLVED",
                        "verification_status": "CONFIRMED_RESOLVED",
                        "resolved_dataset": dataset.dataset_id,
                    })
                    conn.execute(
                        "UPDATE deep_finding_history SET status = 'RESOLVED', lifecycle_json = ?, last_seen_dataset = ?, updated_at_utc = ? WHERE finding_id = ?",
                        (json.dumps(lifecycle, ensure_ascii=False), dataset.dataset_id, now, finding_id),
                    )
                else:
                    lifecycle.update({
                        "status": "OPEN",
                        "verification_status": "UNVERIFIED",
                        "verification_dataset": dataset.dataset_id,
                        "verification_reason": rule_status or "RULE_NOT_EVALUATED",
                    })
                    conn.execute(
                        "UPDATE deep_finding_history SET lifecycle_json = ?, updated_at_utc = ? WHERE finding_id = ?",
                        (json.dumps(lifecycle, ensure_ascii=False), now, finding_id),
                    )
            conn.commit()
        return lifecycles

    def metric_records(
        self,
        environment_id: str,
        *,
        metric_id: str,
        rule_id: str,
        window_days: int = 90,
    ) -> list[DatasetRecord]:
        """Return per-entity historical measurements as read-only trend evidence."""

        with sqlite3.connect(self.path) as conn:
            self._backfill_metric_observations(conn)
            all_rows = conn.execute(
                "SELECT observed_at_utc FROM deep_metric_observations WHERE environment_id = ? AND metric_id = ? ORDER BY observed_at_utc",
                (environment_id, metric_id),
            ).fetchall()
            if not all_rows:
                return []
            anchor = datetime.fromisoformat(str(all_rows[-1][0]).replace("Z", "+00:00")).astimezone(UTC)
            cutoff = anchor - timedelta(days=window_days)
            rows = conn.execute(
                """
                SELECT dataset_id, entity_id, entity_type, entity_ref, observed_at_utc, value, unit
                FROM deep_metric_observations
                WHERE environment_id = ? AND metric_id = ? AND observed_at_utc >= ?
                ORDER BY entity_id, observed_at_utc
                """,
                (environment_id, metric_id, cutoff.replace(microsecond=0).isoformat().replace("+00:00", "Z")),
            ).fetchall()
            conn.commit()
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

    def trend_summary(self, environment_id: str, *, window_days: int = 90) -> dict[str, Any]:
        with sqlite3.connect(self.path) as conn:
            all_rows = conn.execute(
                "SELECT dataset_id, created_at_utc FROM deep_datasets WHERE environment_id = ? ORDER BY created_at_utc",
                (environment_id,),
            ).fetchall()
            if not all_rows:
                return {"state": "INSUFFICIENT_DATA", "dataset_count": 0, "window_days": window_days}
            anchor = datetime.fromisoformat(str(all_rows[-1][1]).replace("Z", "+00:00")).astimezone(UTC)
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
            current_rule_statuses = {
                str(row[0]): str(row[1]).upper()
                for row in conn.execute(
                    "SELECT rule_id, status FROM deep_rule_evaluations WHERE dataset_id = ?",
                    (current_id,),
                ).fetchall()
            }
            absent_from_current = baseline_findings - current_findings
            open_findings = conn.execute(
                "SELECT finding_id, rule_id FROM deep_finding_history WHERE environment_id = ? AND status = 'OPEN'",
                (environment_id,),
            ).fetchall()
            unverified_findings = {
                str(finding_id)
                for finding_id, rule_id in open_findings
                if finding_id not in current_findings
                and current_rule_statuses.get(str(rule_id)) != "PASS"
            }
            resolved_findings = absent_from_current - unverified_findings
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
