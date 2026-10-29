"""Explicit, additive persistence for product targets and integrated inspections.

The original vCenter tables and IDs retain their meaning. Reading this module or
querying it never migrates a database; callers explicitly opt in through
``ensure_product_schema`` after choosing the intended database.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
from dataclasses import asdict, is_dataclass
import json
from pathlib import Path
import re
import sqlite3
import threading
from urllib.parse import urlsplit

from vstacklens.core.ids import new_id
from vstacklens.core.time import utc_now_iso
from vstacklens.db.connection import connect, init_db
from vstacklens.deep.backup import backup_before_migration
from vstacklens.products.model import TargetRef, sanitize_public


_LOCK = threading.RLock()
_TABLES = {"product_targets", "integrated_runs", "integrated_target_runs", "product_checks", "integrated_reports"}
_PRODUCTS = {"nsx", "avi"}
_STATUSES = {"normal", "abnormal", "attention", "not_deployed", "not_applicable", "permission_denied", "unsupported", "collection_failed", "insufficient_data", "cancelled"}
_SENSITIVE_KEYS = {"password", "passwords", "passwd", "pwd", "passphrase", "keypassphrase", "secret", "secrets", "secretvalues", "credentials", "authorization", "proxyauthorization", "cookie", "cookies", "setcookie", "session", "sessionid", "sessiontoken", "csrftoken", "accesstoken", "refreshtoken", "token", "apikey", "licensekey", "licensekeys", "privatekey", "pem", "certificatepem", "pemencoded", "certificatechain", "raw", "rawjson", "rawresponse", "rawevidence", "payload", "requestdata", "resourcedata", "requestheaders", "responseheaders"}
_MODULE_FIELDS = {"product", "target_id", "target_name", "target_address", "target_identity", "customer_id", "site_id", "version", "build", "started_at", "completed_at", "collection_state", "analysis_state", "delivery_state", "checks", "inventory", "native_alerts", "limitations", "errors", "request_metrics", "transport_security", "verification_level", "status_summary", "verification_summary", "verified_pass", "verified_pass_count", "valid_check_count", "summary", "counts", "coverage", "completeness", "check_counts", "experimental", "observed_normal_count", "valid_data"}
_SECRET_TEXT = re.compile(r"-----BEGIN [^-]*(?:PRIVATE KEY|CERTIFICATE)|(?:authorization\s*[:=]\s*(?:basic|bearer)\s+\S+)|(?:\b(?:password|passwd|api_key|license_key|session_id|access_token)\s*[:=]\s*\S+)", re.IGNORECASE)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS product_targets (
 target_id TEXT PRIMARY KEY, product TEXT NOT NULL CHECK(product IN ('nsx','avi')),
 customer_id TEXT NOT NULL REFERENCES customers(customer_id),
 site_id TEXT NOT NULL REFERENCES sites(site_id), name TEXT NOT NULL,
 host TEXT NOT NULL, port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
 username TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1,
 identity_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_product_target_endpoint
 ON product_targets(customer_id,site_id,product,host COLLATE NOCASE,port);
CREATE TABLE IF NOT EXISTS integrated_runs (
 run_id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(customer_id),
 site_id TEXT REFERENCES sites(site_id), title TEXT NOT NULL,
 state TEXT NOT NULL DEFAULT 'running', started_at TEXT NOT NULL,
 finished_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS integrated_target_runs (
 run_id TEXT NOT NULL REFERENCES integrated_runs(run_id), target_id TEXT NOT NULL,
 product TEXT NOT NULL CHECK(product IN ('vcenter','nsx','avi')), ordinal INTEGER NOT NULL,
 target_json TEXT NOT NULL, module_json TEXT NOT NULL DEFAULT '{}',
 legacy_run_id TEXT REFERENCES inspection_runs(run_id),
 collection_state TEXT NOT NULL DEFAULT 'not_started',
 analysis_state TEXT NOT NULL DEFAULT 'not_started',
 delivery_state TEXT NOT NULL DEFAULT 'not_started', updated_at TEXT NOT NULL,
 PRIMARY KEY(run_id,target_id), UNIQUE(run_id,ordinal)
);
CREATE INDEX IF NOT EXISTS idx_integrated_target_history ON integrated_target_runs(target_id,run_id);
CREATE TABLE IF NOT EXISTS product_checks (
 run_id TEXT NOT NULL, target_id TEXT NOT NULL, ordinal INTEGER NOT NULL,
 check_id TEXT NOT NULL, status TEXT NOT NULL, check_json TEXT NOT NULL,
 PRIMARY KEY(run_id,target_id,ordinal),
 FOREIGN KEY(run_id,target_id) REFERENCES integrated_target_runs(run_id,target_id)
);
CREATE TABLE IF NOT EXISTS integrated_reports (
 run_id TEXT NOT NULL REFERENCES integrated_runs(run_id), format TEXT NOT NULL,
 path TEXT NOT NULL DEFAULT '', status TEXT NOT NULL, error TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(run_id,format)
);
"""


@contextmanager
def _read(db):
    """Opening a missing database through a query must not create it."""
    with closing(sqlite3.connect(Path(db).resolve().as_uri() + "?mode=ro", uri=True)) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        yield conn


def _tables(conn):
    return {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def _require_schema(conn):
    if not _TABLES <= _tables(conn):
        raise ValueError("综合巡检存储尚未显式初始化，请先对选定数据库执行 ensure_product_schema。")


def schema_ready(db):
    if not Path(db).is_file():
        return False
    with _read(db) as conn:
        return _TABLES <= _tables(conn)


@contextmanager
def _write(db):
    if not schema_ready(db):
        raise ValueError("综合巡检存储尚未显式初始化，请先对选定数据库执行 ensure_product_schema。")
    with closing(connect(Path(db))) as conn, conn:
        yield conn


def ensure_product_schema(db):
    """Migrate only the explicitly supplied database after a verified backup.

    Existing tables, vCenter IDs and history are never rewritten. The backup and
    its restore-verified companion are retained beside the selected database.
    """
    path = Path(db)
    with _LOCK:
        if path.exists():
            with closing(sqlite3.connect(path)) as conn:
                tables = _tables(conn)
                if _TABLES <= tables:
                    return
                if tables and not {"customers", "sites", "vcenters", "inspection_runs"} <= tables:
                    raise ValueError("选定文件不是兼容的 VStackLens 数据库，未修改其结构。")
                backup_before_migration(conn, path, purpose="nsx-avi-integration")
            if not tables:
                init_db(path)
        else:
            init_db(path)
        with closing(connect(path)) as conn:
            conn.executescript("BEGIN IMMEDIATE;" + _SCHEMA + "COMMIT;")


def _public(value):
    """Reject accidental raw/secret fields before sanitizing printable values."""
    def reject(item, depth=0):
        if depth > 32:
            raise ValueError("公共巡检数据嵌套过深，未持久化。")
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ValueError("公共巡检数据字段名无效，未持久化。")
                normalized = re.sub(r"[^a-z0-9]", "", key.casefold())
                if normalized in _SENSITIVE_KEYS or normalized.endswith(("password", "privatekey", "licensekey", "passphrase", "secret", "token")):
                    raise ValueError("检测到敏感或原始响应字段，未持久化。")
                reject(child, depth + 1)
        elif isinstance(item, (list, tuple)):
            for child in item:
                reject(child, depth + 1)
        elif isinstance(item, str):
            if _SECRET_TEXT.search(item):
                raise ValueError("检测到认证信息或完整证书内容，未持久化。")
        elif item is not None and not isinstance(item, (bool, int, float)):
            raise ValueError("公共巡检数据包含未投影对象，未持久化。")
    reject(value)
    result = sanitize_public(value)
    json.dumps(result, ensure_ascii=False, allow_nan=False)
    return result


def _json(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))


def _endpoint(address):
    if not isinstance(address, str) or not address.strip():
        raise ValueError("请填写产品管理地址。")
    parsed = urlsplit(address.strip() if "://" in address else "https://" + address.strip())
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        raise ValueError("管理地址只允许 HTTPS 主机和端口，不得包含账号、路径或参数。")
    try:
        host, port = parsed.hostname, parsed.port or 443
    except ValueError:
        raise ValueError("管理端口无效。") from None
    if not host or not 1 <= port <= 65535 or any(char.isspace() or char in "\\/%" for char in host):
        raise ValueError("产品管理地址无效。")
    return host.casefold(), port


def _target(row, *, vcenter=False):
    return TargetRef(target_id=row["vcenter_id"] if vcenter else row["target_id"], product="vcenter" if vcenter else row["product"],
        customer_id=row["customer_id"], site_id=row["site_id"], name=row["name"], host=row["host"], port=row["port"],
        username=row["username"] or "", customer_name=row["customer_name"], site_name=row["site_name"],
        enabled=row["status"] == "active" if vcenter else bool(row["enabled"]),
        identity={} if vcenter else json.loads(row["identity_json"] or "{}"))


def _targets(conn, *, product=None, customer_id=None, include_vcenter=True):
    tables = _tables(conn)
    result = []
    if "product_targets" in tables and product != "vcenter":
        rows = conn.execute("""SELECT p.*,c.customer_name,s.site_name FROM product_targets p
            JOIN customers c ON c.customer_id=p.customer_id JOIN sites s ON s.site_id=p.site_id
            WHERE (? IS NULL OR p.product=?) AND (? IS NULL OR p.customer_id=?) ORDER BY p.updated_at DESC,p.target_id""", (product, product, customer_id, customer_id))
        result.extend(_target(row) for row in rows)
    if include_vcenter and product in (None, "vcenter") and "vcenters" in tables:
        rows = conn.execute("""SELECT v.*,c.customer_name,s.site_name FROM vcenters v
            JOIN customers c ON c.customer_id=v.customer_id JOIN sites s ON s.site_id=v.site_id
            WHERE (? IS NULL OR v.customer_id=?) ORDER BY v.updated_at DESC,v.vcenter_id""", (customer_id, customer_id))
        result.extend(_target(row, vcenter=True) for row in rows)
    return result


def list_targets(db, *, product=None, customer_id=None, include_vcenter=True):
    if product is not None and product not in _PRODUCTS | {"vcenter"}:
        raise ValueError("未知产品类型。")
    if not Path(db).is_file():
        return []
    with _read(db) as conn:
        return _targets(conn, product=product, customer_id=customer_id, include_vcenter=include_vcenter)


def save_target(db, *, product, name, address, customer_name, site_name="未指定站点", customer_id=None, target_id=None, username="", identity=None):
    if product not in _PRODUCTS:
        raise ValueError("新产品档案仅支持 NSX 或 AVI，vCenter 使用现有档案入口。")
    name, customer_name, site_name = name.strip(), customer_name.strip(), site_name.strip() or "未指定站点"
    if not name or not customer_name:
        raise ValueError("请填写目标名称和客户归属。")
    host, port = _endpoint(address)
    clean_identity = _public(identity) if identity is not None else None
    if clean_identity is not None and not isinstance(clean_identity, dict):
        raise ValueError("目标身份信息必须是公共字段对象。")
    with _write(db) as conn:
        _require_schema(conn)
        conn.execute("BEGIN IMMEDIATE")
        previous = conn.execute("SELECT * FROM product_targets WHERE target_id=?", (target_id,)).fetchone() if target_id else None
        if target_id and previous is None:
            raise ValueError("产品目标档案不存在。")
        if previous and previous["product"] != product:
            raise ValueError("不能更改已有目标的产品类型。")
        if customer_id:
            customer = conn.execute("SELECT customer_id FROM customers WHERE customer_id=?", (customer_id,)).fetchone()
            if not customer:
                raise ValueError("所选客户不存在。")
        else:
            rows = conn.execute("SELECT customer_id FROM customers WHERE customer_name=?", (customer_name,)).fetchall()
            if len(rows) > 1:
                raise ValueError("存在同名客户，请选择具体客户。")
            customer_id = rows[0][0] if rows else new_id("cus")
            if not rows:
                now = utc_now_iso()
                conn.execute("INSERT INTO customers VALUES (?,?,?,?,?)", (customer_id, customer_name, "active", now, now))
        if previous and previous["customer_id"] != customer_id:
            raise ValueError("不能把已有目标移至其他客户；请为另一客户建立独立档案。")
        site = conn.execute("SELECT site_id FROM sites WHERE customer_id=? AND site_name=?", (customer_id, site_name)).fetchone()
        site_id, now = (site[0] if site else new_id("site")), utc_now_iso()
        if not site:
            conn.execute("INSERT INTO sites VALUES (?,?,?,?,?,?)", (site_id, customer_id, site_name, "active", now, now))
        duplicate = conn.execute("SELECT target_id FROM product_targets WHERE customer_id=? AND site_id=? AND product=? AND host=? COLLATE NOCASE AND port=? AND target_id!=?", (customer_id, site_id, product, host, port, target_id or "")).fetchone()
        if duplicate:
            raise ValueError("该客户和站点已有相同产品地址，请编辑原档案，不会自动合并。")
        if previous:
            clean_identity = clean_identity if clean_identity is not None else json.loads(previous["identity_json"])
            conn.execute("UPDATE product_targets SET name=?,site_id=?,host=?,port=?,username=?,identity_json=?,updated_at=? WHERE target_id=?", (name, site_id, host, port, "", _json(clean_identity), now, target_id))
        else:
            target_id = new_id(product)
            conn.execute("INSERT INTO product_targets(target_id,product,customer_id,site_id,name,host,port,username,enabled,identity_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (target_id, product, customer_id, site_id, name, host, port, "", 1, _json(clean_identity or {}), now, now))
    return target_id


def set_target_enabled(db, target_id, enabled):
    with _write(db) as conn:
        _require_schema(conn)
        result = conn.execute("UPDATE product_targets SET enabled=?,updated_at=? WHERE target_id=?", (int(bool(enabled)), utc_now_iso(), target_id))
        if result.rowcount != 1:
            raise ValueError("产品目标档案不存在，vCenter 使用原有档案入口。")


def _snapshot(target):
    if not is_dataclass(target):
        raise ValueError("目标必须使用 TargetRef。")
    fields = {key: value for key, value in asdict(target).items() if key in {"target_id", "product", "customer_id", "site_id", "name", "host", "port", "customer_name", "site_name", "enabled", "identity"}}
    return _public(fields)


def create_run(db, run_id, targets, title):
    targets = list(targets)
    if not run_id or not targets or len({target.target_id for target in targets}) != len(targets):
        raise ValueError("综合任务需要唯一任务标识和不重复的产品目标。")
    with _write(db) as conn:
        _require_schema(conn)
        conn.execute("BEGIN IMMEDIATE")
        canonical = {target.target_id: target for target in _targets(conn)}
        snapshots = []
        for target in targets:
            current = canonical.get(target.target_id)
            if not current or not current.enabled:
                raise ValueError("所选目标不存在或已停用。")
            if any(getattr(current, key) != getattr(target, key) for key in ("product", "customer_id", "site_id", "name", "host", "port", "username", "identity")):
                raise ValueError("所选目标档案已变化，请刷新后重新选择。")
            snapshots.append(_snapshot(current))
        if len({target["customer_id"] for target in snapshots}) != 1:
            raise ValueError("同一综合任务必须属于同一客户，请分别执行不同客户的巡检。")
        site_ids, now = {target["site_id"] for target in snapshots}, utc_now_iso()
        conn.execute("INSERT INTO integrated_runs(run_id,customer_id,site_id,title,state,started_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)", (run_id, snapshots[0]["customer_id"], next(iter(site_ids)) if len(site_ids) == 1 else None, str(_public(str(title))), "running", now, now, now))
        for ordinal, target in enumerate(snapshots):
            conn.execute("INSERT INTO integrated_target_runs(run_id,target_id,product,ordinal,target_json,updated_at) VALUES (?,?,?,?,?,?)", (run_id, target["target_id"], target["product"], ordinal, _json(target), now))
    # Execution may use the same canonical refs whose public snapshots were
    # frozen, rather than reusing caller-supplied mutable metadata.
    return [canonical[target.target_id] for target in targets]


def save_module(db, run_id, module, legacy_run_id=None):
    if not isinstance(module, dict) or set(module) - _MODULE_FIELDS:
        raise ValueError("产品模块包含未投影字段，未持久化。")
    clean = _public(module)
    checks = clean.get("checks", [])
    if not isinstance(checks, list) or any(not isinstance(check, dict) or not check.get("check_id") or check.get("status") not in _STATUSES for check in checks):
        raise ValueError("产品检查记录格式或结果状态无效。")
    with _write(db) as conn:
        _require_schema(conn)
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM integrated_target_runs WHERE run_id=? AND target_id=?", (run_id, clean.get("target_id"))).fetchone()
        if not row or row["product"] != clean.get("product"):
            raise ValueError("产品模块不属于所选任务和目标。")
        target = json.loads(row["target_json"])
        if any(clean.get(key, target[key]) != target[key] for key in ("customer_id", "site_id")):
            raise ValueError("产品模块的客户或站点归属与任务快照不一致。")
        if legacy_run_id:
            legacy = conn.execute("SELECT vcenter_id,customer_id,site_id FROM inspection_runs WHERE run_id=?", (legacy_run_id,)).fetchone()
            if row["product"] != "vcenter" or not legacy or any(legacy[key] != target[target_key] for key, target_key in (("vcenter_id", "target_id"), ("customer_id", "customer_id"), ("site_id", "site_id"))):
                raise ValueError("旧 vCenter 任务不属于当前产品目标，未建立历史关联。")
        clean["target_name"] = target["name"]
        now = utc_now_iso()
        conn.execute("UPDATE integrated_target_runs SET module_json=?,legacy_run_id=?,collection_state=?,analysis_state=?,delivery_state=?,updated_at=? WHERE run_id=? AND target_id=?", (_json(clean), legacy_run_id, clean.get("collection_state", "not_started"), clean.get("analysis_state", "not_started"), clean.get("delivery_state", "not_started"), now, run_id, row["target_id"]))
        conn.execute("DELETE FROM product_checks WHERE run_id=? AND target_id=?", (run_id, row["target_id"]))
        for ordinal, check in enumerate(checks):
            conn.execute("INSERT INTO product_checks(run_id,target_id,ordinal,check_id,status,check_json) VALUES (?,?,?,?,?,?)", (run_id, row["target_id"], ordinal, check["check_id"], check["status"], _json(check)))


def finish_run(db, run_id, state):
    if state not in {"completed", "partial", "partial_failed", "failed", "cancelled", "interrupted", "success"}:
        raise ValueError("综合任务结束状态无效。")
    with _write(db) as conn:
        _require_schema(conn)
        now = utc_now_iso()
        if conn.execute("UPDATE integrated_runs SET state=?,finished_at=?,updated_at=? WHERE run_id=?", (state, now, now, run_id)).rowcount != 1:
            raise ValueError("综合任务不存在。")


def save_report(db, run_id, format, path, status, error=""):
    kind = {"word": "docx", "html_package": "html"}.get(str(format).casefold(), str(format).casefold())
    if kind not in {"html", "docx", "pdf", "json"} or status not in {"success", "failed", "blocked", "cancelled"}:
        raise ValueError("综合报告格式或交付状态无效。")
    public_error = _public(str(error))
    with _write(db) as conn:
        _require_schema(conn)
        if not conn.execute("SELECT 1 FROM integrated_runs WHERE run_id=?", (run_id,)).fetchone():
            raise ValueError("综合报告对应任务不存在。")
        now = utc_now_iso()
        conn.execute("INSERT INTO integrated_reports(run_id,format,path,status,error,created_at,updated_at) VALUES (?,?,?,?,?,?,?) ON CONFLICT(run_id,format) DO UPDATE SET path=excluded.path,status=excluded.status,error=excluded.error,updated_at=excluded.updated_at", (run_id, kind, str(path or ""), status, public_error, now, now))


def list_runs(db, *, target_id=None, customer_id=None):
    if not Path(db).is_file():
        return []
    with _read(db) as conn:
        if "integrated_runs" not in _tables(conn):
            return []
        rows = conn.execute("""SELECT r.* FROM integrated_runs r WHERE (? IS NULL OR r.customer_id=?)
            AND (? IS NULL OR EXISTS(SELECT 1 FROM integrated_target_runs t WHERE t.run_id=r.run_id AND t.target_id=?))
            ORDER BY r.created_at DESC,r.rowid DESC""", (customer_id, customer_id, target_id, target_id)).fetchall()
        return [dict(row) for row in rows]


def load_run(db, run_id):
    if not Path(db).is_file():
        return None
    with _read(db) as conn:
        if "integrated_runs" not in _tables(conn):
            return None
        row = conn.execute("SELECT * FROM integrated_runs WHERE run_id=?", (run_id,)).fetchone()
        if not row:
            return None
        result = dict(row)
        target_runs = conn.execute("SELECT * FROM integrated_target_runs WHERE run_id=? ORDER BY ordinal", (run_id,)).fetchall()
        result["targets"] = [json.loads(target["target_json"]) for target in target_runs]
        result["modules"] = []
        result["target_runs"] = []
        for target in target_runs:
            item = dict(target)
            module = json.loads(item.pop("module_json"))
            item["target"] = json.loads(item.pop("target_json"))
            if module:
                result["modules"].append(module)
            result["target_runs"].append(item)
        result["reports"] = [dict(report) for report in conn.execute("SELECT * FROM integrated_reports WHERE run_id=? ORDER BY format", (run_id,))]
        return result


def list_checks(db, *, target_id=None, customer_id=None, run_id=None, status=None):
    if status is not None and status not in _STATUSES:
        raise ValueError("未知检查状态。")
    if not Path(db).is_file():
        return []
    with _read(db) as conn:
        if "product_checks" not in _tables(conn):
            return []
        rows = conn.execute("""SELECT c.*,r.customer_id,t.product,t.target_json FROM product_checks c
            JOIN integrated_runs r ON r.run_id=c.run_id
            JOIN integrated_target_runs t ON t.run_id=c.run_id AND t.target_id=c.target_id
            WHERE (? IS NULL OR c.target_id=?) AND (? IS NULL OR r.customer_id=?)
            AND (? IS NULL OR c.run_id=?) AND (? IS NULL OR c.status=?)
            ORDER BY r.created_at DESC,r.rowid DESC,t.ordinal,c.ordinal""", (target_id, target_id, customer_id, customer_id, run_id, run_id, status, status)).fetchall()
        result = []
        for row in rows:
            check = json.loads(row["check_json"])
            target = json.loads(row["target_json"])
            check.update(run_id=row["run_id"], target_id=row["target_id"], customer_id=row["customer_id"], site_id=target["site_id"], product=row["product"], target_name=target["name"])
            result.append(check)
        return result
