from __future__ import annotations

import hashlib
import sqlite3

from vstacklens.core.enums import RuleResultStatus
from vstacklens.core.ids import new_id
from vstacklens.core.time import utc_now_iso


class FindingDeduplicator:
    def upsert_findings(self, conn: sqlite3.Connection, site_id: str, results: list[dict]) -> None:
        now = utc_now_iso()
        seen_failed_keys: set[str] = set()
        for result in results:
            if result["result_status"] != RuleResultStatus.FAILED.value:
                continue
            key = self._finding_key(result)
            seen_failed_keys.add(key)
            existing = conn.execute("SELECT finding_id, status FROM findings WHERE finding_key = ?", (key,)).fetchone()
            if existing:
                self._update_existing(conn, result, key, existing["status"], now)
            else:
                self._insert_new(conn, site_id, result, key, now)
        self._resolve_absent_findings(conn, results, seen_failed_keys, now)

    def _update_existing(self, conn: sqlite3.Connection, result: dict, key: str, current_status: str, now: str) -> None:
        status = "reopened" if current_status == "resolved" else current_status
        conn.execute(
            """
            UPDATE findings
            SET latest_result_id = ?, risk_level = ?, confidence_level = ?,
                status = ?, last_seen_run_id = ?, last_seen_at = ?,
                resolved_run_id = NULL, resolved_at = NULL,
                occurrence_count = occurrence_count + 1,
                remediation_status = CASE
                  WHEN ? = 'exception' THEN remediation_status
                  ELSE 'open'
                END,
                updated_at = ?
            WHERE finding_key = ?
            """,
            (
                result["result_id"],
                result["risk_level"],
                result["confidence_level"],
                status,
                result["run_id"],
                now,
                current_status,
                now,
                key,
            ),
        )

    def _insert_new(self, conn: sqlite3.Connection, site_id: str, result: dict, key: str, now: str) -> None:
        conn.execute(
            """
            INSERT INTO findings (
              finding_id, finding_key, customer_id, site_id, vcenter_id, rule_id,
              latest_result_id, object_type, object_key, object_name, title,
              risk_level, confidence_level, status, occurrence_count, remediation_status,
              first_seen_run_id, first_seen_at, last_seen_run_id, last_seen_at,
              created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                new_id("find"),
                key,
                result["customer_id"],
                site_id,
                result["vcenter_id"],
                result["rule_id"],
                result["result_id"],
                result["object_type"],
                result["object_key"],
                result["object_name"],
                result["rule_id"],
                result["risk_level"],
                result["confidence_level"],
                "open",
                1,
                "open",
                result["run_id"],
                now,
                result["run_id"],
                now,
                now,
                now,
            ),
        )

    def _resolve_absent_findings(self, conn: sqlite3.Connection, results: list[dict], seen_failed_keys: set[str], now: str) -> None:
        scoped_keys = {self._finding_key(result) for result in results if result["result_status"] == RuleResultStatus.PASSED.value}
        for key in scoped_keys - seen_failed_keys:
            conn.execute(
                """
                UPDATE findings
                SET status = 'resolved',
                    resolved_run_id = ?,
                    resolved_at = ?,
                    remediation_status = 'resolved',
                    updated_at = ?
                WHERE finding_key = ? AND status IN ('open', 'in_progress', 'reopened', 'exception')
                """,
                (self._run_id_for_key(results), now, now, key),
            )

    def _run_id_for_key(self, results: list[dict]) -> str:
        return results[0]["run_id"] if results else ""

    def _finding_key(self, result: dict) -> str:
        raw = f"{result['vcenter_id']}|{result['rule_id']}|{result['object_type']}|{result['object_key']}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()
