from __future__ import annotations

import json
import sqlite3
from typing import Any

from vstacklens.core.ids import new_id
from vstacklens.core.time import utc_now_iso


def ensure_default_scope(
    conn: sqlite3.Connection,
    vcenter_host: str,
    username: str | None = None,
    customer_name: str | None = None,
    site_name: str | None = None,
) -> tuple[str, str, str]:
    now = utc_now_iso()
    customer_name = customer_name or "未指定客户"
    site_name = site_name or "未指定站点"
    customer = conn.execute("SELECT customer_id FROM customers WHERE customer_name = ?", (customer_name,)).fetchone()
    if customer:
        customer_id = customer["customer_id"]
    else:
        customer_id = new_id("cus")
        conn.execute(
            "INSERT INTO customers VALUES (?, ?, ?, ?, ?)",
            (customer_id, customer_name, "active", now, now),
        )

    site = conn.execute("SELECT site_id FROM sites WHERE customer_id = ? AND site_name = ?", (customer_id, site_name)).fetchone()
    if site:
        site_id = site["site_id"]
    else:
        site_id = new_id("site")
        conn.execute(
            "INSERT INTO sites VALUES (?, ?, ?, ?, ?, ?)",
            (site_id, customer_id, site_name, "active", now, now),
        )

    vcenter = conn.execute("SELECT vcenter_id FROM vcenters WHERE site_id = ? AND host = ?", (site_id, vcenter_host)).fetchone()
    if vcenter:
        vcenter_id = vcenter["vcenter_id"]
    else:
        vcenter_id = new_id("vc")
        conn.execute(
            "INSERT INTO vcenters VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (vcenter_id, customer_id, site_id, vcenter_host, vcenter_host, 443, username, 0, "active", now, now),
        )
    return customer_id, site_id, vcenter_id


def insert_run(conn: sqlite3.Connection, customer_id: str, site_id: str, vcenter_id: str, trigger_type: str) -> str:
    now = utc_now_iso()
    run_id = new_id("run")
    conn.execute(
        """
        INSERT INTO inspection_runs (
          run_id, customer_id, site_id, vcenter_id, trigger_type, run_status,
          current_stage, progress_percent, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (run_id, customer_id, site_id, vcenter_id, trigger_type, "pending", "pending", 0, now, now),
    )
    return run_id


def update_run(conn: sqlite3.Connection, run_id: str, status: str, stage: str, progress: int = 0, error: str | None = None) -> None:
    conn.execute(
        """
        UPDATE inspection_runs
        SET run_status = ?, current_stage = ?, progress_percent = ?, error_message = ?, updated_at = ?
        WHERE run_id = ?
        """,
        (status, stage, progress, error, utc_now_iso(), run_id),
    )


def finalize_run_summary(conn: sqlite3.Connection, run_id: str) -> None:
    rows = conn.execute(
        "SELECT risk_level, COUNT(*) c FROM findings WHERE last_seen_run_id = ? AND status != 'exception' GROUP BY risk_level",
        (run_id,),
    ).fetchall()
    summary = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    for row in rows:
        if row["risk_level"] in summary:
            summary[row["risk_level"]] = row["c"]
    finding_rows = conn.execute(
        """
        SELECT rule_id, risk_level, COUNT(*) c
        FROM findings
        WHERE last_seen_run_id = ? AND status != 'exception'
        GROUP BY rule_id, risk_level
        """,
        (run_id,),
    ).fetchall()
    category_summary = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    for row in finding_rows:
        level = row["risk_level"]
        if level in category_summary:
            category_summary[level] += 1
    score = calculate_health_score([dict(row) for row in finding_rows], apply_legacy_caps=False)
    conn.execute(
        "UPDATE inspection_runs SET risk_summary_json = ?, risk_category_summary_json = ?, score = ?, updated_at = ? WHERE run_id = ?",
        (json.dumps(summary, ensure_ascii=False), json.dumps(category_summary, ensure_ascii=False), score, utc_now_iso(), run_id),
    )


def actionable_risk_total(risk_summary: dict[str, Any]) -> int:
    return sum(int(risk_summary.get(level, 0) or 0) for level in ("P1", "P2", "P3"))


def calculate_health_score(finding_groups: list[dict[str, Any]], *, apply_legacy_caps: bool = False) -> float:
    return float(calculate_health_score_breakdown(finding_groups, apply_legacy_caps=apply_legacy_caps)["score"])


def calculate_health_score_breakdown(
    finding_groups: list[dict[str, Any]],
    *,
    apply_legacy_caps: bool = False,
) -> dict[str, Any]:
    policies = {
        "P1": {"base": 12.0, "extra": 1.5, "per_type_extra_cap": 6.0, "level_cap": 45.0},
        "P2": {"base": 6.0, "extra": 0.7, "per_type_extra_cap": 3.0, "level_cap": 25.0},
        "P3": {"base": 3.0, "extra": 0.35, "per_type_extra_cap": 1.5, "level_cap": 15.0},
    }
    levels: dict[str, dict[str, Any]] = {
        level: {"risk_types": 0, "affected_objects": 0, "raw_deduction": 0.0, "deduction": 0.0, "cap": policy["level_cap"]}
        for level, policy in policies.items()
    }
    levels["P4"] = {"risk_types": 0, "affected_objects": 0, "raw_deduction": 0.0, "deduction": 0.0, "cap": 0.0}

    for group in finding_groups:
        level = group.get("risk_level")
        count = int(group.get("c", 0))
        if count <= 0 or level not in levels:
            continue
        levels[level]["risk_types"] += 1
        levels[level]["affected_objects"] += count
        policy = policies.get(level)
        if not policy:
            continue
        extra = min(max(count - 1, 0) * policy["extra"], policy["per_type_extra_cap"])
        levels[level]["raw_deduction"] += policy["base"] + extra

    for level, policy in policies.items():
        levels[level]["raw_deduction"] = round(levels[level]["raw_deduction"], 2)
        levels[level]["deduction"] = round(min(levels[level]["raw_deduction"], policy["level_cap"]), 2)

    levels["P4"]["note"] = "优化建议不参与健康评分扣分。"
    total_deduction = round(sum(levels[level]["deduction"] for level in ("P1", "P2", "P3")), 2)
    score = max(0.0, 100.0 - total_deduction)
    applied_caps: list[str] = []
    if apply_legacy_caps:
        if levels["P1"]["risk_types"] > 0 and score > 69:
            score = 69.0
            applied_caps.append("存在 P1 风险时，最终评分最高不超过 69。")
        if levels["P1"]["risk_types"] >= 3 and score > 49:
            score = 49.0
            applied_caps.append("P1 风险类型达到 3 类及以上时，最终评分最高不超过 49。")
        if levels["P2"]["risk_types"] >= 5 and score > 79:
            score = 79.0
            applied_caps.append("P2 风险类型达到 5 类及以上时，最终评分最高不超过 79。")

    return {
        "score": round(score, 2),
        "base_score": 100,
        "total_deduction": total_deduction,
        "levels": levels,
        "applied_caps": applied_caps,
        "basis": "健康评分基于 P1/P2/P3 整改优先级、问题类别数量和影响对象范围计算；整改优先级不直接决定环境健康等级。",
        "p4_policy": "优化建议不参与健康评分扣分。",
    }


def insert_report(
    conn: sqlite3.Connection,
    run_id: str,
    customer_id: str,
    site_id: str,
    vcenter_id: str,
    file_path: str,
    status: str = "success",
    error: str | None = None,
    report_type: str = "html",
    report_name: str | None = None,
) -> None:
    now = utc_now_iso()
    conn.execute(
        """
        INSERT INTO reports (
          report_id, run_id, customer_id, site_id, vcenter_id, report_name,
          report_type, report_status, file_path, generated_at, error_message,
          created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            new_id("rep"),
            run_id,
            customer_id,
            site_id,
            vcenter_id,
            report_name or f"VStackLens {report_type.upper()} Report",
            report_type,
            status,
            file_path,
            now if status == "success" else None,
            error,
            now,
            now,
        ),
    )


def mark_finding_exception(
    conn: sqlite3.Connection,
    finding_id: str,
    reason: str,
    owner: str,
    expires_at: str,
    approval_note: str | None = None,
) -> None:
    now = utc_now_iso()
    finding = conn.execute("SELECT * FROM findings WHERE finding_id = ?", (finding_id,)).fetchone()
    if not finding:
        raise ValueError(f"Finding not found: {finding_id}")
    conn.execute(
        """
        UPDATE findings
        SET status = 'exception',
            exception_reason = ?,
            exception_owner = ?,
            exception_expires_at = ?,
            exception_approval_note = ?,
            updated_at = ?
        WHERE finding_id = ?
        """,
        (reason, owner, expires_at, approval_note, now, finding_id),
    )
    conn.execute(
        """
        INSERT INTO finding_exceptions (
          exception_id, finding_id, finding_key, customer_id, site_id, vcenter_id,
          rule_id, object_type, object_key, exception_reason, owner, expires_at,
          approval_note, status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            new_id("ex"),
            finding_id,
            finding["finding_key"],
            finding["customer_id"],
            finding["site_id"],
            finding["vcenter_id"],
            finding["rule_id"],
            finding["object_type"],
            finding["object_key"],
            reason,
            owner,
            expires_at,
            approval_note,
            "active",
            now,
            now,
        ),
    )


def remove_finding_exception(conn: sqlite3.Connection, finding_id: str) -> None:
    now = utc_now_iso()
    finding = conn.execute("SELECT finding_id FROM findings WHERE finding_id = ?", (finding_id,)).fetchone()
    if not finding:
        raise ValueError(f"Finding not found: {finding_id}")
    conn.execute(
        """
        UPDATE findings
        SET status = 'open',
            exception_reason = NULL,
            exception_owner = NULL,
            exception_expires_at = NULL,
            exception_approval_note = NULL,
            remediation_status = 'open',
            updated_at = ?
        WHERE finding_id = ? AND status = 'exception'
        """,
        (now, finding_id),
    )
    conn.execute(
        """
        UPDATE finding_exceptions
        SET status = 'removed', updated_at = ?
        WHERE finding_id = ? AND status = 'active'
        """,
        (now, finding_id),
    )


def insert_rule(conn: sqlite3.Connection, rule: Any) -> None:
    now = utc_now_iso()
    conn.execute(
        """
        INSERT OR REPLACE INTO rules (
          rule_id, rule_name, category, object_type, risk_level, confidence_level,
          rule_version, enabled, definition_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            rule.rule_id,
            rule.rule_name,
            rule.category,
            rule.object_type,
            rule.risk_level.value if hasattr(rule.risk_level, "value") else rule.risk_level,
            rule.confidence_level.value if hasattr(rule.confidence_level, "value") else rule.confidence_level,
            rule.rule_version,
            1 if rule.enabled else 0,
            rule.model_dump_json(),
            now,
            now,
        ),
    )


def insert_rule_result(conn: sqlite3.Connection, result: dict[str, Any]) -> None:
    conn.execute(
        """
        INSERT INTO rule_results (
          result_id, run_id, rule_id, customer_id, vcenter_id, object_type,
          object_key, object_name, object_path, result_status, risk_level,
          confidence_level, observed_value, expected_value, evidence_json,
          raw_json, error_message, evaluated_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            result["result_id"],
            result["run_id"],
            result["rule_id"],
            result["customer_id"],
            result["vcenter_id"],
            result["object_type"],
            result["object_key"],
            result["object_name"],
            result.get("object_path"),
            result["result_status"],
            result.get("risk_level"),
            result.get("confidence_level"),
            result.get("observed_value"),
            result.get("expected_value"),
            json.dumps(result.get("evidence", {}), ensure_ascii=False),
            json.dumps(result.get("raw", {}), ensure_ascii=False),
            result.get("error_message"),
            result["evaluated_at"],
            result["created_at"],
        ),
    )
