from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from vstacklens.deep.contracts import DatasetRecord, DeepDataset, DeepDiagnosticRecord


class DeepDatasetWriter:
    """Persist the portable Deep Dataset layout without exposing diagnostics."""

    def write(
        self,
        dataset: DeepDataset,
        root: Path,
        *,
        supplemental_records: list[DatasetRecord] | None = None,
    ) -> Path:
        root = Path(root)
        root.mkdir(parents=True, exist_ok=True)
        for directory in ("inventory", "config", "perf", "events", "logs", "vsan", "optional", "anonymization"):
            (root / directory).mkdir(exist_ok=True)
        if supplemental_records:
            (root / "history" / "metrics").mkdir(parents=True, exist_ok=True)
        self._write_json(root / "manifest.json", dataset.manifest.model_dump(mode="json"))
        self._write_json(root / "capability.json", dataset.capability.model_dump(mode="json"))
        self._write_ndjson(root / "collection_log.ndjson", dataset.collection_log)

        grouped: dict[str, list[dict[str, Any]]] = {}
        for record in dataset.records:
            grouped.setdefault(record.kind, []).append(record.model_dump(mode="json"))
        for kind, records in grouped.items():
            folder = {
                "config": "config",
                "event": "events",
                "task": "events",
                "alarm": "events",
                "log": "logs",
                "perf": "perf",
                "vsan_health": "vsan",
                "vsan_perf": "vsan",
                "inventory": "inventory",
            }.get(kind, "optional")
            self._write_ndjson(root / folder / f"{kind}.ndjson", records)

        historical_metrics: dict[str, list[dict[str, Any]]] = {}
        for record in supplemental_records or []:
            metric_id = str(record.metadata.get("metric_id") or record.selector.get("counter") or "unknown")
            historical_metrics.setdefault(metric_id, []).append(record.model_dump(mode="json"))
        for metric_id, records in historical_metrics.items():
            safe_metric_id = "".join(char if char.isalnum() or char in "._-" else "_" for char in metric_id)
            self._write_ndjson(root / "history" / "metrics" / f"{safe_metric_id}.ndjson", records)

        files = {}
        for path in sorted(root.rglob("*")):
            if path.is_file() and path.name != "manifest.json":
                files[str(path.relative_to(root)).replace("\\", "/")] = self._sha256(path)
        manifest = dataset.manifest.model_copy(deep=True)
        manifest.integrity = {"algorithm": "sha256", "files": files}
        self._write_json(root / "manifest.json", manifest.model_dump(mode="json"))
        return root

    @staticmethod
    def _write_json(path: Path, payload: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    @staticmethod
    def _write_ndjson(path: Path, rows: list[dict[str, Any]]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()


class DeepDiagnosticRecordStore:
    """Store full diagnostics beside, rather than inside, customer report HTML."""

    def write(self, record: DeepDiagnosticRecord, path: Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(record.model_dump_json(indent=2), encoding="utf-8")
        return path
