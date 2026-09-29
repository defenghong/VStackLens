from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from typing import Any

from vstacklens.deep.contracts import DatasetRecord


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _base_key(record: DatasetRecord) -> tuple[str, str, str, str, str]:
    return (record.kind, record.entity.stable_id, _canonical(record.selector), record.window.start, record.window.end)


def _content_key(record: DatasetRecord) -> str:
    payload = _canonical({"value": record.value, "unit": record.unit, "summary": record.summary, "finding": record.finding})
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def merge_records(records: list[DatasetRecord]) -> tuple[list[DatasetRecord], dict[str, Any]]:
    """Deduplicate identical evidence while preserving cross-source conflicts."""
    by_base: dict[tuple[str, str, str, str, str], list[DatasetRecord]] = defaultdict(list)
    for record in records:
        by_base[_base_key(record)].append(record)
    merged: list[DatasetRecord] = []
    duplicate_count = 0
    conflict_count = 0
    conflicts: list[dict[str, Any]] = []
    for base_key, group in by_base.items():
        by_content: dict[str, list[DatasetRecord]] = defaultdict(list)
        for record in group:
            by_content[_content_key(record)].append(record)
        for content_group in by_content.values():
            canonical = content_group[0].model_copy(deep=True)
            if len(content_group) > 1:
                duplicate_count += len(content_group) - 1
                canonical.metadata = {
                    **canonical.metadata,
                    "duplicate_count": len(content_group) - 1,
                    "duplicate_sources": [item.source.api for item in content_group],
                    "duplicate_evidence": [{"source": item.source.api, "record_id": item.record_id, "raw_pointer": item.raw_pointer} for item in content_group],
                }
            merged.append(canonical)
        if len(by_content) > 1:
            conflict_count += 1
            conflict_id = hashlib.sha256(_canonical(base_key).encode("utf-8")).hexdigest()[:16]
            conflict_records = merged[-sum(len(items) for items in by_content.values()):]
            conflicts.append({"conflict_group": conflict_id, "kind": base_key[0], "entity_id": base_key[1], "source_records": [{"source": item.source.api, "record_id": item.record_id, "raw_pointer": item.raw_pointer, "content_hash": _content_key(item)} for item in conflict_records]})
            for item in conflict_records:
                item.metadata = {**item.metadata, "conflict": True, "conflict_group": conflict_id, "conflict_sources": [entry.source.api for entry in group]}
    return merged, {"action": "evidence.merge", "status": "ok", "input_count": len(records), "output_count": len(merged), "duplicate_count": duplicate_count, "conflict_count": conflict_count, "conflicts": conflicts}
