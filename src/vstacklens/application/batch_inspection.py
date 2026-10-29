"""Serial standard inspections; public durable records and private session credentials."""
from __future__ import annotations
from contextlib import closing
from dataclasses import dataclass, field, asdict
from pathlib import Path
from uuid import uuid4
import hashlib
import json
import re
import threading

from vstacklens.application.inspection_service import InspectionService, DesktopInspectionConfig, InspectionCancelledError
from vstacklens.application.inspection_runner import RunnerCancelledError
from vstacklens.application.environment_archive import list_archives
from vstacklens.application.execution_guard import acquire, lease_keys, release_owner, TargetIdentityError
from vstacklens.application.connection_probe import redact_sensitive
from vstacklens.application.artifact_safety import ensure_artifacts_safe
from vstacklens.core.time import utc_now_iso
from vstacklens.core.process_identity import PROCESS_PID, PROCESS_IDENTITY
from vstacklens.db.connection import connect
from vstacklens.db.batch_store import BatchStore

UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
TERMINAL = {"completed", "partial_failed", "failed", "cancelled", "interrupted"}

@dataclass(frozen=True)
class SessionCredential:
    username: str
    password: str = field(repr=False)

@dataclass(frozen=True)
class BatchSettings:
    db_path: Path
    report_output_dir: Path
    rulepack_path: Path
    report_title: str = "VStackLens VMware 虚拟化健康评估报告"

def rulepack_fingerprint(path):
    files = sorted(Path(path).rglob("*.yaml"))
    if not files:
        raise ValueError("巡检规则包缺失，不能提交。")
    digest = hashlib.sha256()
    for p in files:
        digest.update(str(p.relative_to(path)).encode()); digest.update(p.read_bytes())
    return digest.hexdigest()

def target_snapshot(env):
    return {k: getattr(env, k) for k in ("environment_id", "name", "customer_id", "customer_name", "site_id", "site_name", "host", "port", "username", "ssl_verify", "enabled")}

def historic_identity(db, env_id):
    with closing(connect(Path(db))) as conn:
        rows = conn.execute("SELECT o.object_key FROM inventory_objects o JOIN inspection_runs r ON r.run_id=o.run_id WHERE o.vcenter_id=? AND o.object_type='vCenter' AND r.run_status='success' ORDER BY r.created_at DESC", (env_id,)).fetchall()
    return next((row[0].lower() for row in rows if UUID.fullmatch(row[0])), "")

class BatchInspectionService:
    def __init__(self, db_path: Path, *, service_factory=None):
        self.store = BatchStore(db_path)
        self.store.recover_interrupted()
        self.service_factory = service_factory or InspectionService
        self._lock = threading.RLock()
        self._credentials = {}
        self._cancel = {}
        self._executing = set()
        self._active = None

    def submit(self, environment_ids, credentials, settings: BatchSettings, *, submission_id=None):
        ids = list(dict.fromkeys(environment_ids))
        if not ids:
            raise ValueError("请至少选择一个环境。")
        if Path(settings.db_path).resolve() != self.store.path.resolve():
            raise ValueError("环境档案和任务数据库不一致。")
        with self._lock:
            if self._active and self.store.snapshot(self._active)["state"] in {"waiting", "running"}:
                raise ValueError("批任务尚未结束，不能重复提交。")
            profiles = {e.environment_id: e for e in list_archives(self.store.path)}
            if any(i not in profiles for i in ids):
                raise ValueError("所选环境已不存在，请重新选择。")
            frozen_settings = {k: str(v) for k,v in asdict(settings).items()}
            frozen_settings["rulepack_sha256"] = rulepack_fingerprint(settings.rulepack_path)
            public_targets = [target_snapshot(profiles[i]) for i in ids]
            private = {i: SessionCredential(credentials[i].username.strip(), credentials[i].password) for i in ids if i in credentials}
            # Refuse secrets that collide with public task material rather than persisting them.
            public_text = json.dumps([frozen_settings, public_targets], ensure_ascii=False)
            if any(c.password and c.password.casefold() in public_text.casefold() for c in private.values()):
                raise ValueError("凭据与公开任务资料冲突，未保存任务；请重新确认凭据。")
            batch_id, submission_id = uuid4().hex, submission_id or uuid4().hex
            with closing(connect(self.store.path)) as conn, conn:
                conn.execute("BEGIN IMMEDIATE")
                existing = conn.execute("SELECT batch_id FROM standard_batches WHERE submission_id=?", (submission_id,)).fetchone()
                if existing:
                    return existing[0]
                conn.execute("INSERT INTO standard_batches VALUES (?,?,?,?,?,?,?,?)", (batch_id, submission_id, "waiting", json.dumps(frozen_settings, ensure_ascii=False), PROCESS_PID, PROCESS_IDENTITY, utc_now_iso(), utc_now_iso()))
                for ordinal, target in enumerate(public_targets):
                    env, credential = profiles[target["environment_id"]], private.get(target["environment_id"])
                    reason = self._ambiguity_reason(env, profiles.values())
                    if not env.enabled:
                        reason = "档案已停用，未启动"
                    elif not credential or not credential.username or not credential.password:
                        reason = "缺少该环境的会话凭据，请单独填写后重新提交"
                    elif env.username and env.username != credential.username:
                        reason = "会话用户名与档案不一致，请重新确认"
                    target["expected_uuid"] = historic_identity(self.store.path, env.environment_id)
                    target["session_username"] = credential.username if credential else ""
                    if not reason:
                        conn.execute("SAVEPOINT reserve_item")
                        try:
                            acquire(conn, lease_keys(env.environment_id, env.host, env.port), batch_id)
                        except ValueError as exc:
                            conn.execute("ROLLBACK TO reserve_item"); reason = str(exc)
                        finally:
                            conn.execute("RELEASE reserve_item")
                    conn.execute("INSERT INTO standard_batch_items(batch_id,ordinal,environment_id,target_json,state,reason) VALUES (?,?,?,?,?,?)", (batch_id, ordinal, env.environment_id, json.dumps(target, ensure_ascii=False), "failed" if reason else "waiting", reason))
            self._credentials[batch_id] = private
            self._cancel[batch_id] = threading.Event()
            self._active = batch_id
            return batch_id

    @staticmethod
    def _ambiguity_reason(env, profiles):
        if any(p.customer_id != env.customer_id and p.host.casefold() == env.host.casefold() and p.port == env.port for p in profiles):
            return "跨客户重复地址，远端归属无法确认；未批量执行，请先核对档案"
        return ""

    def cancel(self, batch_id):
        with self._lock:
            event = self._cancel.get(batch_id)
            if event:
                event.set()
                for item in self.store.snapshot(batch_id)["items"]:
                    if item["state"] == "waiting":
                        self.store.stage_item(batch_id, item["ordinal"], state="cancelled", reason="已取消，未启动下一项")
            return self.store.snapshot(batch_id)

    def clear_idle_credentials(self):
        """Exit-only memory cleanup; never clear credentials of an executing job."""
        with self._lock:
            if self._executing:
                raise ValueError("批任务仍在执行，不能提前清理会话凭据。")
            self._credentials.clear(); self._cancel.clear(); self._active = None

    def run(self, batch_id, progress=None):
        with self._lock:
            if batch_id in self._executing:
                raise ValueError("批任务已在执行，不能重复运行。")
            if batch_id not in self._credentials:
                # Never resume a durable snapshot without its original private session.
                return self.store.snapshot(batch_id)
            self._executing.add(batch_id)
            event = self._cancel[batch_id]
            private = self._credentials[batch_id]
            secrets = tuple(c.password for c in private.values() if c.password)
        def emit():
            if progress:
                progress(self.store.snapshot(batch_id))
        try:
            self.store.update_state(batch_id, "running"); emit()
            with closing(connect(self.store.path)) as conn:
                settings = json.loads(conn.execute("SELECT settings_json FROM standard_batches WHERE batch_id=?", (batch_id,)).fetchone()[0])
            for item in self.store.snapshot(batch_id)["items"]:
                ordinal, target = item["ordinal"], item["target"]
                with self._lock:
                    if event.is_set():
                        self.cancel(batch_id); break
                    if item["state"] != "waiting":
                        continue
                    self.store.update_item(batch_id, ordinal, state="running", reason="", collection_state="running")
                emit()
                try:
                    profiles = {e.environment_id: e for e in list_archives(self.store.path)}
                    env = profiles.get(target["environment_id"])
                    if not env or any(target[k] != getattr(env, k) for k in target_snapshot(env)):
                        raise ValueError("排队后档案资料变化或停用，已停止该项，请重新确认")
                    ambiguous = self._ambiguity_reason(env, profiles.values())
                    if ambiguous:
                        raise TargetIdentityError(ambiguous)
                    if rulepack_fingerprint(Path(settings["rulepack_path"])) != settings["rulepack_sha256"]:
                        raise ValueError("排队后规则包变化，请重新确认任务")
                    credential = private[env.environment_id]
                    service = self.service_factory()
                    config = DesktopInspectionConfig(db_path=self.store.path, rulepack_path=Path(settings["rulepack_path"]),
                        report_output_dir=Path(settings["report_output_dir"]) / ("batch-" + batch_id) / (f"{ordinal:03d}-" + env.environment_id),
                        report_title=settings["report_title"], environment_id=env.environment_id, vcenter=env.address,
                        username=credential.username, password=credential.password, customer_name=env.customer_name, site_name=env.site_name)
                    def identity(remote_uuid):
                        if event.is_set():
                            raise RunnerCancelledError("批任务已取消")
                        if not UUID.fullmatch(remote_uuid) or target["expected_uuid"] and remote_uuid.lower() != target["expected_uuid"]:
                            raise TargetIdentityError("远端 UUID 缺失或与历史目标不一致，未继续采集")
                        with closing(connect(self.store.path)) as conn:
                            conflict = conn.execute("SELECT 1 FROM inventory_objects WHERE object_type='vCenter' AND LOWER(object_key)=? AND customer_id!=? LIMIT 1", (remote_uuid.lower(), env.customer_id)).fetchone()
                        if conflict:
                            raise TargetIdentityError("远端 UUID 已关联其他客户，归属无法确认，未继续采集")
                        self.store.stage_item(batch_id, ordinal, identity_state="matched" if target["expected_uuid"] else "observed", remote_uuid=remote_uuid.lower())
                    def on_progress(p):
                        fields = {"percent": min(99, int(p.percent))}
                        if p.run_id:
                            fields["run_id"] = p.run_id
                        if p.stage in {"normalizing", "snapshotting", "executing_rules", "scoring", "building_findings", "reporting", "success"}:
                            identity_state = self.store.snapshot(batch_id)["items"][ordinal]["identity_state"]
                            fields["collection_state"] = "failed" if identity_state == "unverified" else "complete"
                            fields["analysis_state"] = "running"
                        if p.stage in {"reporting", "success"}:
                            fields["analysis_state"] = "complete"
                            fields["delivery_state"] = "generating"
                        self.store.stage_item(batch_id, ordinal, **fields); emit()
                    result = service.run_vcenter_inspection(config, on_progress, event.is_set, persist_config=False,
                        execution_owner=batch_id, identity_validator=identity, known_secrets=secrets)
                    states = self._result_states(result.run_id, secrets)
                    self.store.update_item(batch_id, ordinal, run_id=result.run_id, percent=100, **states)
                except (InspectionCancelledError, RunnerCancelledError):
                    current = self.store.snapshot(batch_id)["items"][ordinal]
                    stages = {k: current[k] if current[k] in {"complete", "partial", "failed"} else "cancelled" for k in ("collection_state", "analysis_state", "delivery_state")}
                    if current["run_id"]:
                        final = self._result_states(current["run_id"], secrets)
                        for k in stages:
                            if final[k] in {"complete", "partial"}:
                                stages[k] = final[k]
                    self.store.update_item(batch_id, ordinal, state="cancelled", reason="当前任务已安全取消", percent=100, **stages)
                    event.set()
                except Exception as exc:
                    self.store.update_item(batch_id, ordinal, state="failed", reason=redact_sensitive(exc, *secrets), percent=100,
                        identity_state="blocked" if isinstance(exc, TargetIdentityError) else self.store.snapshot(batch_id)["items"][ordinal]["identity_state"],
                        **self._failure_states(batch_id, ordinal))
                emit()
            if event.is_set():
                self.cancel(batch_id)
            self.store.flush(batch_id)
            self.store.update_state(batch_id, "cancelled" if event.is_set() else "completed")
            emit(); return self.store.snapshot(batch_id)
        except BaseException:
            for item in self.store.snapshot(batch_id)["items"]:
                if item["state"] in {"waiting", "running"}:
                    self.store.stage_item(batch_id, item["ordinal"], state="interrupted", reason="批任务异常中断，未启动后续项")
            self.store.flush(batch_id)
            self.store.update_state(batch_id, "interrupted")
            raise
        finally:
            try:
                self.store.flush(batch_id)
            finally:
                try:
                    release_owner(self.store.path, batch_id)
                finally:
                    with self._lock:
                        self._credentials.pop(batch_id, None); self._cancel.pop(batch_id, None)
                        self._executing.discard(batch_id)

    def _failure_states(self, batch_id, ordinal):
        item = self.store.snapshot(batch_id)["items"][ordinal]
        if not item["run_id"]:
            return {"collection_state": "not_started", "analysis_state": "not_started", "delivery_state": "not_started"}
        with closing(connect(self.store.path)) as conn:
            collected = conn.execute("SELECT 1 FROM inventory_snapshots WHERE run_id=?", (item["run_id"],)).fetchone()
            analyzed = conn.execute("SELECT 1 FROM rule_results WHERE run_id=?", (item["run_id"],)).fetchone()
        return {"collection_state": "complete" if collected else "failed", "analysis_state": "complete" if analyzed else "not_started", "delivery_state": "failed" if analyzed else "not_started"}

    def _result_states(self, run_id, secrets):
        with closing(connect(self.store.path)) as conn:
            rows = conn.execute("SELECT result_status FROM rule_results WHERE run_id=?", (run_id,)).fetchall()
            center = conn.execute("SELECT properties_json FROM inventory_objects WHERE run_id=? AND object_type='vCenter' LIMIT 1", (run_id,)).fetchone()
            reports = conn.execute("SELECT * FROM reports WHERE run_id=? AND report_type IN ('html_package','docx','pdf')", (run_id,)).fetchall()
        props = json.loads(center[0]) if center else {}
        props = props.get("properties", props)
        diagnostic = props.get("collection_mode") == "connection_failed"
        partial = any(r[0] in {"unavailable", "error"} for r in rows)
        delivered = []
        for kind in ("html_package", "docx", "pdf"):
            record = next((r for r in reports if r["report_type"] == kind), None)
            if record and record["report_status"] == "success" and record["file_path"] and Path(record["file_path"]).is_file():
                try:
                    ensure_artifacts_safe([Path(record["file_path"])], secrets=secrets)
                    delivered.append(kind)
                except Exception:
                    pass
        collection = "failed" if diagnostic else "partial" if partial else "complete" if rows else "unknown"
        delivery = "complete" if len(delivered) == 3 else "partial" if delivered else "failed"
        state = "failed" if diagnostic or not rows else "completed" if collection == delivery == "complete" else "partial_failed"
        return {"state": state, "collection_state": collection, "analysis_state": "complete" if rows else "unavailable", "delivery_state": delivery,
                "reason": "仅有连接诊断，未采集清单" if diagnostic else "部分检查不可用或部分报告未成功交付" if state != "completed" else ""}
