"""Read-only, run-scoped access to the shared customer report projection."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sqlite3

from vstacklens.reports.customer_caliber import VERSION, calculate, ensure_report, yaml_rules


def legacy_summary(counts=None) -> dict:
    return {"version": "legacy", "state": "legacy", "counts": counts or {}, "problem_count": None,
            "affected_counts": {}, "affected_total": None, "health": {"label": "旧口径", "assessment_limited": True,
            "explanation": "缺少当次完整证据，保留原口径，未按零风险处理。"},
            "categories": [], "findings": [], "non_reported": [], "non_report_counts": {}, "non_report_total": None}


def from_snapshot(model) -> dict:
    """Replay stored observations, never today's certificate ages or latest findings."""
    if model.caliber_inputs.get("object_results"):
        model.customer_caliber = {}
        return ensure_report(model)
    original = model.caliber_inputs.get("findings") or [x.model_dump() for x in model.findings]
    expected_failed = int(model.environment_summary.result_status_summary.get("failed", 0))
    source_ids = {(x.get("rule_id"), str((x.get("evidence") or {}).get("object_key") or x.get("object_path") or x.get("object_name"))) for x in original if not x.get("grade_source_rule_id")}
    if len(source_ids) < expected_failed:
        return legacy_summary(model.risk_category_summary)
    records = deepcopy(original)
    for row in records:
        row["result_status"] = "failed"
    if not model.environment_summary.result_status_summary:
        return legacy_summary(model.risk_category_summary)
    result = calculate(original, records=None, assets=model.asset_inventory.get("details", {}),
                     status_summary=model.environment_summary.result_status_summary,
                     asset_total=int(model.asset_inventory.get("total", 0)),
                     critical_gap_count=model.appendix.get("critical_gap_count"), run_id=model.report_info.run_id)
    result["state"] = "legacy"
    result["health"] = {"label": "旧口径", "assessment_limited": True, "explanation": "缺少完整的逐项原始结果；保留已保存结论，未依据资产值补造通过项或按当前规则重新判断。"}
    return result


def load_run(db_path: Path, run_id: str) -> dict:
    """Never migrate, checkpoint, update scores, or overwrite historical files."""
    from vstacklens.reports.context_builder import ReportContextBuilder
    from vstacklens.reports.report_model import ReportData, ReportDataFactory
    db = Path(db_path)
    if not db.exists() or not run_id:
        return legacy_summary()
    try:
        with sqlite3.connect(db.resolve().as_uri() + "?mode=ro", uri=True) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only=ON")
            return load_connection(conn, run_id)
    except (sqlite3.Error, ValueError, OSError, TypeError):
        return legacy_summary()


def load_connection(conn: sqlite3.Connection, run_id: str) -> dict:
    """Project this connection's run snapshot, including an unpublished report transaction."""
    from vstacklens.reports.context_builder import ReportContextBuilder
    from vstacklens.reports.report_model import ReportData, ReportDataFactory
    run = conn.execute("SELECT * FROM inspection_runs WHERE run_id=?", (run_id,)).fetchone()
    if run is None:
        return legacy_summary()
    cached = json.loads(run["risk_category_summary_json"] or run["risk_summary_json"] or "{}")
    snapshots = conn.execute("SELECT file_path FROM reports WHERE run_id=? AND report_type='json' AND report_status='success'", (run_id,)).fetchall()
    for snapshot in snapshots:
        path = Path(snapshot["file_path"] or "")
        if not path.is_file():
            continue
        try:
            model = ReportData.model_validate_json(path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            continue
        if model.report_info.run_id == run_id:
            frozen = from_snapshot(model)
            if frozen.get("object_results") or model.caliber_inputs.get("findings") or model.findings or frozen["state"] == "complete":
                return frozen
    rows = conn.execute("SELECT COUNT(*) FROM rule_results WHERE run_id=?", (run_id,)).fetchone()[0]
    assets = conn.execute("SELECT COUNT(*) FROM inventory_objects WHERE run_id=?", (run_id,)).fetchone()[0]
    if rows and assets:
        context = ReportContextBuilder().build(conn, run_id, include_history=False)
        return ReportDataFactory().from_context(context).customer_caliber
    return legacy_summary(cached)
