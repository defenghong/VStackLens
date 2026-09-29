from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

from vstacklens.db.repositories import actionable_risk_total


RISK_LEVELS = ("P1", "P2", "P3")
OPTIMIZATION_LEVEL = "P4"

# 历史对比状态。除 ready 之外的任何状态都不得渲染评分差异、风险变化或资产变化。
STATE_EMPTY = "empty"
STATE_SINGLE_RUN = "single_run"
STATE_READY = "ready"
# 两条记录来自不同 vCenter 环境：属于不可比状态，必须明确提示而不是展示差异。
STATE_ENVIRONMENT_MISMATCH = "environment_mismatch"
# 传入的 run_id 不存在、未成功完成：不得静默回退到其它环境。
STATE_RUN_UNAVAILABLE = "run_unavailable"

SUMMARY_EMPTY = "暂无评估数据，完成首次评估后可查看历史趋势。"
SUMMARY_SINGLE_RUN = "当前只有 1 次评估，完成第二次评估后可生成历史对比。"
SUMMARY_ENVIRONMENT_MISMATCH = "所选巡检记录属于不同的 vCenter 环境，无法进行历史对比。"
SUMMARY_RUN_UNAVAILABLE = "所选巡检记录不存在、未成功完成或不属于当前 vCenter 环境，无法进行历史对比。"

# 采集器把 vCenter about.instanceUuid 作为 vCenter inventory object 的 object_key 保存，
# 因此可以在不引入数据库迁移的前提下做第二层环境身份校验。
INSTANCE_UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

ASSET_TYPES = {
    "vcenter": ("vCenter", "vCenter"),
    "cluster": ("ClusterComputeResource", "Cluster"),
    "host": ("HostSystem", "Host"),
    "datastore": ("Datastore", "Datastore"),
    "vm": ("VirtualMachine", "VM"),
}

OBJECT_TYPE_LABELS = {
    "vCenter": "vCenter",
    "ClusterComputeResource": "Cluster",
    "HostSystem": "ESXi",
    "Datastore": "Datastore",
    "VirtualMachine": "VM",
}


class HistoryComparisonBuilder:
    """Build a customer-facing comparison from existing run snapshots.

    只有同一个 vCenter 环境的两次成功健康巡检之间才允许对比：
    ``inspection_runs.vcenter_id`` 是强制隔离边界，当两次巡检都能取到采集到的
    vCenter instanceUuid 时再做一次环境身份校验。环境一致性校验集中在本类内部，
    桌面页面、HTML 报告和其它调用者都受同样约束。
    """

    def build(
        self,
        conn: sqlite3.Connection,
        baseline_run_id: str | None = None,
        comparison_run_id: str | None = None,
    ) -> dict[str, Any]:
        latest = self._latest_successful_run(conn)
        if latest is None:
            return self._empty(STATE_EMPTY, SUMMARY_EMPTY, [])

        comparison = latest
        if comparison_run_id:
            resolved = self._successful_run(conn, comparison_run_id)
            if resolved is None:
                # 显式传入的记录不存在、失败或未完成：不得回退到其它环境的记录。
                return self._empty(STATE_RUN_UNAVAILABLE, SUMMARY_RUN_UNAVAILABLE, [])
            comparison = resolved

        # 环境范围锚点：后续所有候选记录都只来自该记录的 vcenter_id。
        environment_runs = self._successful_runs(conn, str(comparison["vcenter_id"] or ""))
        options = [self._run_option(conn, row) for row in environment_runs]
        environment_label = self._environment_label(comparison)

        baseline = None
        if baseline_run_id:
            baseline = self._successful_run(conn, baseline_run_id)
            if baseline is None:
                return self._non_comparable(
                    conn, STATE_RUN_UNAVAILABLE, SUMMARY_RUN_UNAVAILABLE, options, environment_label, comparison
                )
            if not self._same_environment(conn, baseline, comparison):
                return self._non_comparable(
                    conn,
                    STATE_ENVIRONMENT_MISMATCH,
                    SUMMARY_ENVIRONMENT_MISMATCH,
                    options,
                    environment_label,
                    comparison,
                    baseline,
                )

        if len(environment_runs) < 2:
            return self._single_run(conn, comparison, options, environment_label)

        if baseline is None or baseline["run_id"] == comparison["run_id"]:
            baseline = self._previous_run_for(conn, environment_runs, comparison)
        if baseline is None or baseline["run_id"] == comparison["run_id"]:
            return self._single_run(conn, comparison, options, environment_label)
        if not self._same_environment(conn, baseline, comparison):
            return self._non_comparable(
                conn,
                STATE_ENVIRONMENT_MISMATCH,
                SUMMARY_ENVIRONMENT_MISMATCH,
                options,
                environment_label,
                comparison,
                baseline,
            )

        baseline_risks = self._risk_counts(conn, baseline["run_id"])
        comparison_risks = self._risk_counts(conn, comparison["run_id"])
        baseline_assets = self._asset_counts(conn, baseline["run_id"])
        comparison_assets = self._asset_counts(conn, comparison["run_id"])
        risk_changes = self._risk_changes(conn, baseline["run_id"], comparison["run_id"])
        asset_changes = self._asset_changes(conn, baseline["run_id"], comparison["run_id"])
        score = self._delta_metric(baseline["score"], comparison["score"])
        total_delta = actionable_risk_total(comparison_risks) - actionable_risk_total(baseline_risks)
        summary_text = self._summary_text(score.get("delta"), total_delta, risk_changes)
        return {
            "state": STATE_READY,
            "run_options": options,
            "environment_label": environment_label,
            "baseline_run_id": baseline["run_id"],
            "comparison_run_id": comparison["run_id"],
            "baseline_label": self._run_label(conn, baseline),
            "comparison_label": self._run_label(conn, comparison),
            "baseline_time": self._run_time(baseline),
            "comparison_time": self._run_time(comparison),
            "score": score,
            "risk_counts": {
                level: self._count_delta(baseline_risks.get(level, 0), comparison_risks.get(level, 0))
                for level in RISK_LEVELS
            },
            "asset_counts": {
                key: {
                    **self._count_delta(baseline_assets.get(key, 0), comparison_assets.get(key, 0)),
                    "label": label,
                }
                for key, (_, label) in ASSET_TYPES.items()
            },
            "risk_changes": risk_changes,
            "asset_changes": asset_changes,
            "summary_text": summary_text,
        }

    def _single_run(
        self,
        conn: sqlite3.Connection,
        run_row: sqlite3.Row,
        options: list[dict[str, Any]],
        environment_label: str,
    ) -> dict[str, Any]:
        """当前环境只有一次成功巡检：不得拿其它环境的记录补足第二次巡检。"""
        return {
            **self._empty(STATE_SINGLE_RUN, SUMMARY_SINGLE_RUN, options),
            "environment_label": environment_label,
            "comparison_run_id": run_row["run_id"],
            "comparison_label": self._run_label(conn, run_row),
            "comparison_time": self._run_time(run_row),
        }

    def _non_comparable(
        self,
        conn: sqlite3.Connection,
        state: str,
        summary_text: str,
        options: list[dict[str, Any]],
        environment_label: str,
        comparison: sqlite3.Row | None = None,
        baseline: sqlite3.Row | None = None,
    ) -> dict[str, Any]:
        """构造不可比状态：不返回 ready，也不产生任何差异数据。"""
        payload = {
            **self._empty(state, summary_text, options),
            "environment_label": environment_label,
        }
        if comparison is not None:
            payload["comparison_run_id"] = comparison["run_id"]
            payload["comparison_label"] = self._run_label(conn, comparison)
            payload["comparison_time"] = self._run_time(comparison)
        if baseline is not None:
            payload["baseline_run_id"] = baseline["run_id"]
            payload["baseline_label"] = self._run_label(conn, baseline)
            payload["baseline_time"] = self._run_time(baseline)
        return payload

    def _empty(self, state: str, summary_text: str, options: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "state": state,
            "run_options": options,
            "environment_label": "",
            "baseline_run_id": "",
            "comparison_run_id": "",
            "baseline_label": "",
            "comparison_label": "",
            "baseline_time": "",
            "comparison_time": "",
            "score": {"baseline": None, "comparison": None, "delta": None, "direction": "same"},
            "risk_counts": {level: self._count_delta(0, 0) for level in RISK_LEVELS},
            "asset_counts": {
                key: {**self._count_delta(0, 0), "label": label} for key, (_, label) in ASSET_TYPES.items()
            },
            "risk_changes": {"new": [], "closed": [], "persistent": []},
            "asset_changes": {"new": [], "removed": [], "persistent": []},
            "summary_text": summary_text,
        }

    def _successful_runs(
        self,
        conn: sqlite3.Connection,
        vcenter_id: str | None = None,
        run_id: str | None = None,
        limit: int | None = None,
    ) -> list[sqlite3.Row]:
        """成功完成的健康巡检记录。

        ``vcenter_id`` 是强制隔离边界；只有做"库里是否存在成功巡检"的存在性判断时
        才允许传 None。日志分析和升级兼容性检查另外存放在独立数据表中，天然不参与
        健康巡检历史对比。
        """
        conditions = ["LOWER(r.run_status) IN ('success', 'completed')"]
        params: list[Any] = []
        if vcenter_id is not None:
            conditions.append("r.vcenter_id = ?")
            params.append(vcenter_id)
        if run_id is not None:
            conditions.append("r.run_id = ?")
            params.append(run_id)
        sql = f"""
            SELECT r.*, c.customer_name, s.site_name, v.host AS vcenter_host, v.name AS vcenter_name
            FROM inspection_runs r
            JOIN customers c ON c.customer_id = r.customer_id
            JOIN sites s ON s.site_id = r.site_id
            JOIN vcenters v ON v.vcenter_id = r.vcenter_id
            WHERE {' AND '.join(conditions)}
            ORDER BY COALESCE(r.finished_at, r.updated_at, r.created_at) DESC
        """
        if limit is not None:
            sql += f" LIMIT {int(limit)}"
        return conn.execute(sql, tuple(params)).fetchall()

    def _latest_successful_run(self, conn: sqlite3.Connection) -> sqlite3.Row | None:
        rows = self._successful_runs(conn, limit=1)
        return rows[0] if rows else None

    def _successful_run(self, conn: sqlite3.Connection, run_id: str | None) -> sqlite3.Row | None:
        if not run_id:
            return None
        rows = self._successful_runs(conn, run_id=str(run_id), limit=1)
        return rows[0] if rows else None

    def _previous_run_for(
        self,
        conn: sqlite3.Connection,
        runs: list[sqlite3.Row],
        comparison: sqlite3.Row,
    ) -> sqlite3.Row | None:
        comparison_time = self._run_time(comparison)
        for row in runs:
            if row["run_id"] == comparison["run_id"]:
                continue
            if self._run_time(row) <= comparison_time:
                return row
        return next((row for row in runs if row["run_id"] != comparison["run_id"]), None)

    def _run_option(self, conn: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
        risks = self._risk_counts(conn, row["run_id"])
        return {
            "run_id": row["run_id"],
            "label": self._run_label(conn, row),
            "timestamp": self._run_time(row),
            "score": row["score"],
            "risk_total": actionable_risk_total(risks),
            "optimization_total": int(risks.get(OPTIMIZATION_LEVEL, 0) or 0),
            "vcenter_host": self._row_text(row, "vcenter_host"),
            "vcenter_name": self._row_text(row, "vcenter_name"),
        }

    def _run_label(self, conn: sqlite3.Connection, row: sqlite3.Row) -> str:
        """标签至少包含巡检时间、vCenter 环境和风险数，便于识别记录来源。"""
        time_text = self._format_time(self._run_time(row))
        environment = self._row_text(row, "vcenter_host") or self._row_text(row, "vcenter_name")
        risks = self._risk_counts(conn, row["run_id"])
        score = "--" if row["score"] is None else row["score"]
        prefix = f"{time_text} · {environment}" if environment else time_text
        return f"{prefix} · 健康度 {score} · 风险 {actionable_risk_total(risks)} · 优化建议 {int(risks.get(OPTIMIZATION_LEVEL, 0) or 0)}"

    def _environment_label(self, row: sqlite3.Row) -> str:
        host = self._row_text(row, "vcenter_host")
        name = self._row_text(row, "vcenter_name")
        if host and name and name != host:
            return f"{host}（{name}）"
        return host or name or "未记录 vCenter 环境"

    def _same_environment(
        self,
        conn: sqlite3.Connection,
        left: sqlite3.Row,
        right: sqlite3.Row,
    ) -> bool:
        """判断两条巡检是否属于同一个 vCenter 环境。

        vCenter 地址变化但 instanceUuid 相同的候选情况只做记录，不在此处合并
        vcenters 表（需要独立的迁移设计）。
        """
        if str(left["vcenter_id"] or "") != str(right["vcenter_id"] or ""):
            return False
        left_uuid = self._instance_uuid(conn, left["run_id"])
        right_uuid = self._instance_uuid(conn, right["run_id"])
        if not self._is_instance_uuid(left_uuid) or not self._is_instance_uuid(right_uuid):
            # 任一侧没有可靠的 instanceUuid 时，保留 vcenter_id 这一层边界。
            return True
        return left_uuid.lower() == right_uuid.lower()

    def _instance_uuid(self, conn: sqlite3.Connection, run_id: str) -> str:
        row = conn.execute(
            """
            SELECT object_key
            FROM inventory_objects
            WHERE run_id = ? AND object_type = 'vCenter'
              AND object_key IS NOT NULL AND TRIM(object_key) != ''
            ORDER BY LENGTH(object_key) DESC, object_key
            LIMIT 1
            """,
            (run_id,),
        ).fetchone()
        return str(row["object_key"]).strip() if row else ""

    def _is_instance_uuid(self, value: str) -> bool:
        return bool(INSTANCE_UUID_PATTERN.match(str(value or "").strip()))

    def _row_text(self, row: sqlite3.Row, key: str) -> str:
        try:
            if key not in row.keys():
                return ""
            return str(row[key] or "").strip()
        except (AttributeError, IndexError, TypeError):
            return ""

    def _run_time(self, row: sqlite3.Row | dict[str, Any]) -> str:
        return str(row["finished_at"] or row["updated_at"] or row["created_at"] or "")

    def _format_time(self, value: str) -> str:
        if not value:
            return "时间未记录"
        text = value.replace("T", " ").replace("+00:00", "")
        return text[:16]

    def _risk_counts(self, conn: sqlite3.Connection, run_id: str) -> dict[str, int]:
        run = conn.execute("SELECT risk_summary_json, risk_category_summary_json FROM inspection_runs WHERE run_id = ?", (run_id,)).fetchone()
        payload = self._json((run["risk_category_summary_json"] or run["risk_summary_json"]) if run else None)
        if payload:
            result = {level: int(payload.get(level, 0) or 0) for level in RISK_LEVELS}
            result[OPTIMIZATION_LEVEL] = int(payload.get(OPTIMIZATION_LEVEL, 0) or 0)
            return result
        rows = conn.execute(
            """
            SELECT risk_level, COUNT(*) AS c
            FROM rule_results
            WHERE run_id = ? AND result_status = 'failed'
            GROUP BY risk_level
            """,
            (run_id,),
        ).fetchall()
        counts = {level: 0 for level in (*RISK_LEVELS, OPTIMIZATION_LEVEL)}
        for row in rows:
            if row["risk_level"] in counts:
                counts[row["risk_level"]] = int(row["c"] or 0)
        return counts

    def _asset_counts(self, conn: sqlite3.Connection, run_id: str) -> dict[str, int]:
        rows = conn.execute(
            "SELECT object_type, COUNT(*) AS c FROM inventory_objects WHERE run_id = ? GROUP BY object_type",
            (run_id,),
        ).fetchall()
        grouped = {row["object_type"]: int(row["c"] or 0) for row in rows}
        return {key: grouped.get(object_type, 0) for key, (object_type, _) in ASSET_TYPES.items()}

    def _risk_changes(self, conn: sqlite3.Connection, baseline_run_id: str, comparison_run_id: str) -> dict[str, list[dict[str, Any]]]:
        baseline = self._failed_risk_map(conn, baseline_run_id)
        comparison = self._failed_risk_map(conn, comparison_run_id)
        baseline_keys = set(baseline)
        comparison_keys = set(comparison)
        return {
            "new": self._change_items(comparison, comparison_keys - baseline_keys, "新增"),
            "closed": self._change_items(baseline, baseline_keys - comparison_keys, "本次未再检出"),
            "persistent": self._change_items(comparison, baseline_keys & comparison_keys, "持续"),
        }

    def _failed_risk_map(self, conn: sqlite3.Connection, run_id: str) -> dict[str, dict[str, Any]]:
        rows = conn.execute(
            """
            SELECT rr.*, r.rule_name, r.definition_json
            FROM rule_results rr
            LEFT JOIN rules r ON r.rule_id = rr.rule_id
            WHERE rr.run_id = ? AND rr.result_status = 'failed'
              AND rr.risk_level IN ('P1', 'P2', 'P3')
            ORDER BY rr.risk_level, rr.object_type, rr.object_name
            """,
            (run_id,),
        ).fetchall()
        result: dict[str, dict[str, Any]] = {}
        for row in rows:
            item = self._risk_item(row)
            result[item["match_key"]] = item
        return result

    def _risk_item(self, row: sqlite3.Row) -> dict[str, Any]:
        definition = self._json(row["definition_json"] if "definition_json" in row.keys() else None)
        evidence = self._json(row["evidence_json"] if "evidence_json" in row.keys() else None)
        report_fields = definition.get("report_fields", {})
        title = report_fields.get("finding_title_zh") or report_fields.get("title_zh") or row["rule_name"] or "未命名风险"
        current = evidence.get("current_value_zh") or evidence.get("current_value") or row["observed_value"]
        expected = evidence.get("expected_value_zh") or evidence.get("expected_value") or row["expected_value"]
        return {
            "match_key": self._risk_key(row),
            "title": title,
            "risk_level": row["risk_level"] or "",
            "object_type": row["object_type"],
            "object_type_label": OBJECT_TYPE_LABELS.get(row["object_type"], row["object_type"]),
            "object_name": row["object_name"],
            "current_observed": self._display_value(current),
            "expected_state": self._display_value(expected),
        }

    def _risk_key(self, row: sqlite3.Row) -> str:
        rule_id = self._normalize_key_part(row["rule_id"])
        object_type = self._normalize_key_part(row["object_type"])
        object_key = self._normalize_key_part(row["object_key"])
        if object_key:
            return f"{rule_id}|{object_type}|{object_key}"
        return f"{rule_id}|{object_type}|{self._normalize_key_part(row['object_name'])}"

    def _change_items(self, source: dict[str, dict[str, Any]], keys: set[str], label: str) -> list[dict[str, Any]]:
        status_key = {"新增": "new", "本次未再检出": "closed", "持续": "persistent"}.get(label, "")
        result = []
        for key in sorted(keys, key=lambda item: (source[item].get("risk_level", ""), source[item].get("title", ""), source[item].get("object_name", ""))):
            item = dict(source[key])
            item.pop("match_key", None)
            item["change_status"] = status_key
            item["change_status_label"] = label
            result.append(item)
        return result

    def _asset_changes(self, conn: sqlite3.Connection, baseline_run_id: str, comparison_run_id: str) -> dict[str, list[dict[str, Any]]]:
        baseline = self._asset_map(conn, baseline_run_id)
        comparison = self._asset_map(conn, comparison_run_id)
        baseline_keys = set(baseline)
        comparison_keys = set(comparison)
        return {
            "new": self._asset_change_items(comparison, comparison_keys - baseline_keys, "新增"),
            "removed": self._asset_change_items(baseline, baseline_keys - comparison_keys, "删除"),
            "persistent": self._asset_change_items(comparison, baseline_keys & comparison_keys, "持续"),
        }

    def _asset_map(self, conn: sqlite3.Connection, run_id: str) -> dict[str, dict[str, Any]]:
        rows = conn.execute(
            """
            SELECT object_type, object_key, object_name, path, properties_json
            FROM inventory_objects
            WHERE run_id = ?
            ORDER BY object_type, object_name
            """,
            (run_id,),
        ).fetchall()
        result: dict[str, dict[str, Any]] = {}
        for row in rows:
            item = self._asset_item(row)
            result[item["match_key"]] = item
        return result

    def _asset_item(self, row: sqlite3.Row) -> dict[str, Any]:
        props = self._asset_properties(row["properties_json"])
        location = props.get("asset_location") or self._asset_location(row["path"], row["object_name"], row["object_type"])
        return {
            "match_key": self._asset_key(row),
            "object_type": row["object_type"],
            "object_type_label": OBJECT_TYPE_LABELS.get(row["object_type"], row["object_type"]),
            "object_name": row["object_name"],
            "location": str(location or "未记录"),
        }

    def _asset_key(self, row: sqlite3.Row) -> str:
        object_type = self._normalize_key_part(row["object_type"])
        object_key = self._normalize_key_part(row["object_key"])
        if object_key:
            return f"{object_type}|{object_key}"
        return f"{object_type}|{self._normalize_key_part(row['object_name'])}"

    def _normalize_key_part(self, value: Any) -> str:
        return str(value or "").strip().lower()

    def _asset_change_items(self, source: dict[str, dict[str, Any]], keys: set[str], label: str) -> list[dict[str, Any]]:
        status_key = {"新增": "new", "删除": "removed", "持续": "persistent"}.get(label, "")
        result = []
        for key in sorted(keys, key=lambda item: (source[item].get("object_type", ""), source[item].get("object_name", ""))):
            item = dict(source[key])
            item.pop("match_key", None)
            item["change_status"] = status_key
            item["change_status_label"] = label
            result.append(item)
        return result

    def _asset_properties(self, raw: str | None) -> dict[str, Any]:
        payload = self._json(raw)
        props = payload.get("properties", payload)
        return props if isinstance(props, dict) else {}

    def _asset_location(self, path: str | None, object_name: str, object_type: str) -> str:
        if object_type == "vCenter":
            return "vCenter 根对象"
        clean = str(path or "").strip()
        name = str(object_name or "").strip()
        if clean and clean != name:
            parts = [part.strip() for part in clean.replace("\\", "/").split("/") if part.strip()]
            if len(parts) > 1 and parts[-1] == name:
                return " / ".join(parts[:-1])
            return clean
        return "层级未记录"

    def _delta_metric(self, baseline: Any, comparison: Any) -> dict[str, Any]:
        if baseline is None or comparison is None:
            return {"baseline": baseline, "comparison": comparison, "delta": None, "direction": "same"}
        delta = round(float(comparison) - float(baseline), 2)
        return {
            "baseline": baseline,
            "comparison": comparison,
            "delta": delta,
            "direction": "up" if delta > 0 else "down" if delta < 0 else "same",
        }

    def _count_delta(self, baseline: int, comparison: int) -> dict[str, Any]:
        delta = int(comparison or 0) - int(baseline or 0)
        return {
            "baseline": int(baseline or 0),
            "comparison": int(comparison or 0),
            "delta": delta,
            "direction": "up" if delta > 0 else "down" if delta < 0 else "same",
        }

    def _summary_text(self, score_delta: Any, risk_total_delta: int, risk_changes: dict[str, list[dict[str, Any]]]) -> str:
        parts = []
        if score_delta is None:
            parts.append("健康评分暂无可比变化")
        elif score_delta > 0:
            parts.append(f"健康评分提升 {score_delta}")
        elif score_delta < 0:
            parts.append(f"健康评分下降 {abs(score_delta)}")
        else:
            parts.append("健康评分无变化")
        if risk_total_delta > 0:
            parts.append(f"风险总数增加 {risk_total_delta}")
        elif risk_total_delta < 0:
            parts.append(f"风险总数减少 {abs(risk_total_delta)}")
        else:
            parts.append("风险总数无变化")
        parts.append(f"新增 {len(risk_changes['new'])} 项、本次未再检出 {len(risk_changes['closed'])} 项、持续 {len(risk_changes['persistent'])} 项")
        return "；".join(parts) + "。"

    def _display_value(self, value: Any) -> str:
        if value in (None, "", {}, []):
            return "未记录"
        if isinstance(value, bool):
            return "是" if value else "否"
        if isinstance(value, (int, float)):
            return str(value)
        if isinstance(value, list):
            return "、".join(self._display_value(item) for item in value) or "未记录"
        if isinstance(value, dict):
            return "；".join(f"{key}: {self._display_value(item)}" for key, item in value.items()) or "未记录"
        text = str(value).strip()
        if not text:
            return "未记录"
        lowered = text.lower()
        if lowered == "true":
            return "是"
        if lowered == "false":
            return "否"
        if lowered in {"none", "null"}:
            return "未记录"
        return text

    def _json(self, value: str | None) -> dict[str, Any]:
        if not value:
            return {}
        try:
            payload = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return payload if isinstance(payload, dict) else {}