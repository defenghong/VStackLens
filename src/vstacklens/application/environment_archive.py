"""Environment profiles backed by the existing customers/sites/vcenters tables."""
from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
import sqlite3
import json
from urllib.parse import urlparse

from vstacklens.application.connection_probe import normalize_vcenter_address
from vstacklens.core.ids import new_id
from vstacklens.core.time import utc_now_iso
from vstacklens.db.connection import connect, init_db


@dataclass(slots=True)
class EnvironmentArchiveItem:
    environment_id: str
    name: str
    customer_id: str
    customer_name: str
    site_id: str
    site_name: str
    host: str
    port: int
    username: str
    ssl_verify: bool
    enabled: bool
    latest_run_id: str = ""
    latest_status: str = "never"
    last_collected_at: str = ""
    collection_result: str = "尚无巡检记录"
    task_count: int = 0
    available_formats: list[str] = field(default_factory=list)
    report_result: str = "尚无报告"

    @property
    def address(self):
        host = f"[{self.host}]" if ":" in self.host else self.host
        return host if self.port == 443 else f"{host}:{self.port}"


def list_customers(db: Path) -> list[dict]:
    if not Path(db).is_file():
        return []
    with closing(connect(Path(db))) as conn:
        return [dict(row) for row in conn.execute("SELECT customer_id,customer_name FROM customers ORDER BY customer_name,customer_id")]


def _diagnostic_details(conn, run_id):
    for row in conn.execute("SELECT properties_json FROM inventory_objects WHERE run_id=? AND object_type='vCenter'", (run_id,)):
        try:
            props = json.loads(row[0] or "{}")
            props = props.get("properties", props)
            if props.get("collection_mode") == "connection_failed":
                return (props.get("connection_diagnostics") or {}).get("sdk") or {"message": "接口检查未成功"}
        except (ValueError, TypeError, AttributeError):
            continue
    return {}


def list_archives(db: Path) -> list[EnvironmentArchiveItem]:
    if not Path(db).is_file():
        return []
    with closing(connect(Path(db))) as conn:
        rows = conn.execute("""SELECT v.*,c.customer_name,s.site_name FROM vcenters v
            JOIN customers c ON c.customer_id=v.customer_id JOIN sites s ON s.site_id=v.site_id
            ORDER BY v.updated_at DESC,v.vcenter_id""").fetchall()
        result = []
        for row in rows:
            env = EnvironmentArchiveItem(row["vcenter_id"], row["name"], row["customer_id"], row["customer_name"],
                row["site_id"], row["site_name"], row["host"], row["port"], row["username"] or "", bool(row["ssl_verify"]), row["status"] == "active")
            env.task_count = conn.execute("SELECT COUNT(*) FROM inspection_runs WHERE vcenter_id=?", (env.environment_id,)).fetchone()[0]
            snapshots = conn.execute("SELECT run_id,collected_at FROM inventory_snapshots WHERE vcenter_id=? AND object_count>0 ORDER BY collected_at DESC", (env.environment_id,)).fetchall()
            env.last_collected_at = next((s["collected_at"] for s in snapshots if not _diagnostic_details(conn, s["run_id"])), "")
            run = conn.execute("SELECT * FROM inspection_runs WHERE vcenter_id=? ORDER BY COALESCE(started_at,created_at) DESC,rowid DESC LIMIT 1", (env.environment_id,)).fetchone()
            if run:
                env.latest_run_id, env.latest_status = run["run_id"], run["run_status"]
                counts = {r["result_status"]: r["c"] for r in conn.execute("SELECT result_status,COUNT(*) c FROM rule_results WHERE run_id=? GROUP BY result_status", (env.latest_run_id,))}
                gaps = counts.get("unavailable", 0) + counts.get("error", 0)
                env.collection_result = {"failed": "最近任务失败", "cancelled": "最近任务已取消", "running": "采集中", "pending": "等待执行"}.get(env.latest_status, "部分采集" if gaps else "采集完成" if counts else "未获得检查结果")
                if gaps:
                    env.collection_result += f"（{counts.get('unavailable',0)} 项不可用，{counts.get('error',0)} 项异常）"
                diagnostic_only = _diagnostic_details(conn, env.latest_run_id)
                if diagnostic_only:
                    env.collection_result = "未采集到清单（仅诊断）：" + str(diagnostic_only.get("message") or "接口检查未成功")
                labels = {"html_package": "HTML", "docx": "Word", "pdf": "PDF"}
                reports = conn.execute("SELECT report_type,report_status,file_path FROM reports WHERE run_id=?", (env.latest_run_id,)).fetchall()
                env.available_formats = [label for kind, label in labels.items() if any(r["report_type"] == kind and r["report_status"] == "success" and r["file_path"] and Path(r["file_path"]).is_file() for r in reports)]
                env.report_result = " · ".join(env.available_formats) or "最近任务报告不可用"
                if diagnostic_only and env.available_formats:
                    env.report_result += "（连接诊断报告）"
                if any(r["report_type"] in labels and (r["report_status"] != "success" or not r["file_path"] or not Path(r["file_path"]).is_file()) for r in reports):
                    env.report_result += "（部分报告失败或文件缺失）"
            result.append(env)
        return result


def save_archive(db: Path, *, name: str, address: str, customer_name: str, site_name: str = "未指定站点",
                 customer_id: str | None = None, environment_id: str | None = None, username: str = "") -> str:
    name, customer_name, site_name = name.strip(), customer_name.strip(), site_name.strip() or "未指定站点"
    if not name or not customer_name:
        raise ValueError("请填写环境名称和客户归属。")
    parsed = urlparse(address if "://" in address else "https://" + address)
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.scheme != "https" or parsed.path not in ("", "/"):
        raise ValueError("地址只能填写 IP、主机名或 HTTPS 地址，不得包含账号、密码或其他参数。")
    endpoint = normalize_vcenter_address(address)
    if any(char.isspace() for char in endpoint.host) or "\\" in endpoint.host:
        raise ValueError("vCenter 地址包含无效字符。")
    if not 1 <= endpoint.port <= 65535:
        raise ValueError("vCenter 端口无效。")
    db = Path(db)
    if not db.exists():
        init_db(db)
    with closing(connect(db)) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        previous = conn.execute("SELECT * FROM vcenters WHERE vcenter_id=?", (environment_id,)).fetchone() if environment_id else None
        if environment_id and previous is None:
            raise ValueError("环境档案不存在，请刷新后重试。")
        if customer_id:
            customer = conn.execute("SELECT customer_id FROM customers WHERE customer_id=?", (customer_id,)).fetchone()
            if not customer:
                raise ValueError("所选客户不存在。")
        else:
            customers = conn.execute("SELECT customer_id FROM customers WHERE customer_name=?", (customer_name,)).fetchall()
            if len(customers) > 1:
                raise ValueError("存在同名客户，请选择具体客户。")
            customer_id = customers[0][0] if customers else new_id("cus")
            if not customers:
                now = utc_now_iso()
                conn.execute("INSERT INTO customers VALUES (?,?,?,?,?)", (customer_id, customer_name, "active", now, now))
        site = conn.execute("SELECT site_id FROM sites WHERE customer_id=? AND site_name=?", (customer_id, site_name)).fetchone()
        site_id = site[0] if site else new_id("site")
        now = utc_now_iso()
        if not site:
            conn.execute("INSERT INTO sites VALUES (?,?,?,?,?,?)", (site_id, customer_id, site_name, "active", now, now))
        duplicate = conn.execute("SELECT vcenter_id FROM vcenters WHERE customer_id=? AND site_id=? AND LOWER(host)=LOWER(?) AND port=? AND vcenter_id!=?", (customer_id, site_id, endpoint.host, endpoint.port, environment_id or "")).fetchone()
        if duplicate:
            raise ValueError("该客户和站点已有相同地址的环境，请编辑原档案，不会自动合并。")
        if previous:
            conn.execute("UPDATE vcenters SET name=?,customer_id=?,site_id=?,host=?,port=?,username=?,updated_at=? WHERE vcenter_id=?", (name, customer_id, site_id, endpoint.host, endpoint.port, username.strip(), now, environment_id))
        else:
            environment_id = new_id("vc")
            conn.execute("INSERT INTO vcenters VALUES (?,?,?,?,?,?,?,?,?,?,?)", (environment_id, customer_id, site_id, name, endpoint.host, endpoint.port, username.strip(), 1, "active", now, now))
    return environment_id


def set_enabled(db: Path, environment_id: str, enabled: bool):
    with closing(connect(Path(db))) as conn, conn:
        changed = conn.execute("UPDATE vcenters SET status=?,updated_at=? WHERE vcenter_id=?", ("active" if enabled else "disabled", utc_now_iso(), environment_id))
        if changed.rowcount != 1:
            raise ValueError("环境档案不存在。")


def run_ids(db: Path, environment_id: str) -> set[str]:
    if not Path(db).exists():
        return set()
    with closing(connect(Path(db))) as conn:
        return {row[0] for row in conn.execute("SELECT run_id FROM inspection_runs WHERE vcenter_id=?", (environment_id,))}
