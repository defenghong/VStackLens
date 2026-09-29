from __future__ import annotations

import json
import sqlite3
import hashlib
from pathlib import Path
from typing import Any


class RunComparisonBuilder:
    def build(self, conn: sqlite3.Connection, previous_run_id: str | None, current_run_id: str) -> dict[str, Any]:
        current_run = self._run(conn, current_run_id)
        previous_run = self._run(conn, previous_run_id) if previous_run_id else None
        current = self._failed_results(conn, current_run_id)
        previous = self._failed_results(conn, previous_run_id) if previous_run_id else {}
        previous = self._refresh_lifecycle_fields(conn, previous)
        current_keys = set(current)
        previous_keys = set(previous)
        current_passed_keys = self._passed_keys(conn, current_run_id)

        new_keys = current_keys - previous_keys
        existing_keys = current_keys & previous_keys
        resolved_keys = {key for key in previous_keys - current_keys if key in current_passed_keys or previous[key].get("resolved_run_id") == current_run_id}
        reopened_keys = {key for key in current_keys - previous_keys if current[key].get("status") == "reopened"}
        exception_keys = {key for key in current_keys if current[key].get("status") == "exception"}

        existing_keys -= reopened_keys | exception_keys
        new_keys -= reopened_keys | exception_keys

        previous_score = previous_run.get("score") if previous_run else None
        current_score = current_run.get("score")
        score_delta = None if previous_score is None or current_score is None else round(float(current_score) - float(previous_score), 2)
        return {
            "previous_run_id": previous_run_id or "",
            "current_run_id": current_run_id,
            "previous_run": previous_run,
            "current_run": current_run,
            "previous_score": previous_score,
            "current_score": current_score,
            "score_delta": score_delta,
            "summary": {
                "new": len(new_keys),
                "existing": len(existing_keys),
                "resolved": len(resolved_keys),
                "reopened": len(reopened_keys),
                "exception": len(exception_keys),
            },
            "new_findings": self._items(current, new_keys),
            "existing_findings": self._items(current, existing_keys),
            "resolved_findings": self._items(previous, resolved_keys, status_override="resolved"),
            "reopened_findings": self._items(current, reopened_keys),
            "exception_findings": self._items(current, exception_keys),
        }

    def latest_successful_previous_run(self, conn: sqlite3.Connection, current_run_id: str) -> str | None:
        current = self._run(conn, current_run_id)
        row = conn.execute(
            """
            SELECT run_id
            FROM inspection_runs
            WHERE customer_id = ?
              AND site_id = ?
              AND vcenter_id = ?
              AND run_status = 'success'
              AND run_id != ?
              AND COALESCE(finished_at, updated_at, created_at) < COALESCE(?, ?, ?)
            ORDER BY COALESCE(finished_at, updated_at, created_at) DESC
            LIMIT 1
            """,
            (
                current["customer_id"],
                current["site_id"],
                current["vcenter_id"],
                current_run_id,
                current.get("finished_at"),
                current.get("updated_at"),
                current.get("created_at"),
            ),
        ).fetchone()
        return row["run_id"] if row else None

    def write_json(self, conn: sqlite3.Connection, previous_run_id: str | None, current_run_id: str, output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        payload = self.build(conn, previous_run_id, current_run_id)
        path = output_dir / "run_comparison.json"
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    def _run(self, conn: sqlite3.Connection, run_id: str | None) -> dict[str, Any]:
        if not run_id:
            return {}
        row = conn.execute("SELECT * FROM inspection_runs WHERE run_id = ?", (run_id,)).fetchone()
        return dict(row) if row else {}

    def _failed_results(self, conn: sqlite3.Connection, run_id: str | None) -> dict[str, dict[str, Any]]:
        if not run_id:
            return {}
        rows = conn.execute(
            """
            SELECT rr.*, r.definition_json, r.rule_name
            FROM rule_results rr
            LEFT JOIN rules r ON r.rule_id = rr.rule_id
            WHERE rr.run_id = ? AND rr.result_status = 'failed'
              AND rr.risk_level IN ('P1', 'P2', 'P3')
            ORDER BY rr.risk_level, rr.rule_id, rr.object_name
            """,
            (run_id,),
        ).fetchall()
        result_rows = [dict(row) for row in rows]
        lifecycle_keys = [self._legacy_finding_key(row) for row in result_rows]
        finding_map = self._finding_map(conn, lifecycle_keys)
        return {
            self._finding_key(row): self._finding_item(row, finding_map.get(self._legacy_finding_key(row)))
            for row in result_rows
        }

    def _passed_keys(self, conn: sqlite3.Connection, run_id: str | None) -> set[str]:
        if not run_id:
            return set()
        rows = conn.execute(
            """
            SELECT rule_id, object_type, object_key, object_name
            FROM rule_results
            WHERE run_id = ? AND result_status = 'passed'
            """,
            (run_id,),
        ).fetchall()
        return {self._finding_key(dict(row)) for row in rows}

    def _finding_map(self, conn: sqlite3.Connection, keys: list[str]) -> dict[str, dict[str, Any]]:
        if not keys:
            return {}
        placeholders = ",".join("?" for _ in keys)
        rows = conn.execute(f"SELECT * FROM findings WHERE finding_key IN ({placeholders})", tuple(keys)).fetchall()
        return {row["finding_key"]: dict(row) for row in rows}

    def _finding_item(self, result_row: dict[str, Any], finding: dict[str, Any] | None) -> dict[str, Any]:
        definition = self._json(result_row.get("definition_json"))
        report_fields = definition.get("report_fields", {})
        title = report_fields.get("finding_title_zh") or report_fields.get("title_zh") or result_row.get("rule_name") or result_row["rule_id"]
        finding = finding or {}
        return {
            "finding_key": self._finding_key(result_row),
            "lifecycle_finding_key": self._legacy_finding_key(result_row),
            "finding_id": finding.get("finding_id", ""),
            "rule_id": result_row["rule_id"],
            "title": title,
            "risk_level": result_row.get("risk_level") or finding.get("risk_level", ""),
            "status": finding.get("status", "open"),
            "object_type": result_row["object_type"],
            "object_key": result_row["object_key"],
            "object_name": result_row["object_name"],
            "object_path": result_row.get("object_path"),
            "first_seen_run_id": finding.get("first_seen_run_id") or result_row["run_id"],
            "first_seen_at": finding.get("first_seen_at") or result_row.get("evaluated_at"),
            "last_seen_run_id": finding.get("last_seen_run_id") or result_row["run_id"],
            "last_seen_at": finding.get("last_seen_at") or result_row.get("evaluated_at"),
            "resolved_run_id": finding.get("resolved_run_id"),
            "resolved_at": finding.get("resolved_at"),
            "occurrence_count": finding.get("occurrence_count", 1),
            "exception_reason": finding.get("exception_reason") or "",
            "exception_owner": finding.get("exception_owner") or "",
            "exception_expires_at": finding.get("exception_expires_at") or "",
            "exception_approval_note": finding.get("exception_approval_note") or "",
        }

    def _items(self, source: dict[str, dict[str, Any]], keys: set[str], status_override: str | None = None) -> list[dict[str, Any]]:
        result = []
        for key in sorted(keys, key=lambda item: (source[item].get("risk_level", ""), source[item].get("rule_id", ""), source[item].get("object_name", ""))):
            item = dict(source[key])
            if status_override:
                item["change_status"] = status_override
            else:
                item["change_status"] = item.get("status", "")
            result.append(item)
        return result

    def _refresh_lifecycle_fields(self, conn: sqlite3.Connection, items: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
        if not items:
            return items
        lifecycle_keys = [str(item.get("lifecycle_finding_key") or key) for key, item in items.items()]
        finding_map = self._finding_map(conn, lifecycle_keys)
        refreshed = {}
        for key, item in items.items():
            updated = dict(item)
            finding = finding_map.get(str(item.get("lifecycle_finding_key") or key), {})
            for field in (
                "finding_id",
                "status",
                "first_seen_run_id",
                "first_seen_at",
                "last_seen_run_id",
                "last_seen_at",
                "resolved_run_id",
                "resolved_at",
                "occurrence_count",
                "exception_reason",
                "exception_owner",
                "exception_expires_at",
                "exception_approval_note",
            ):
                if field in finding:
                    updated[field] = finding[field]
            refreshed[key] = updated
        return refreshed

    def _json(self, value: str | None) -> dict[str, Any]:
        if not value:
            return {}
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return {}

    def _finding_key(self, row: dict[str, Any]) -> str:
        rule_id = self._normalize_key_part(row.get("rule_id"))
        object_type = self._normalize_key_part(row.get("object_type"))
        object_key = self._normalize_key_part(row.get("object_key"))
        object_identity = object_key or self._normalize_key_part(row.get("object_name"))
        raw = f"{rule_id}|{object_type}|{object_identity}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _legacy_finding_key(self, row: dict[str, Any]) -> str:
        raw = f"{row.get('vcenter_id', '')}|{row['rule_id']}|{row['object_type']}|{row.get('object_key', '')}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _normalize_key_part(self, value: Any) -> str:
        return str(value or "").strip().lower()
