"""Standalone application service for ESXi upgrade compatibility checks."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import threading
from collections.abc import Callable
from contextlib import closing
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from enum import Enum
from pathlib import Path, PurePath
from time import perf_counter, sleep
from typing import Any, Literal

from vstacklens.collection.collection_plan import CollectionPlan
from vstacklens.collection.pci_collector import PyVmomiPciCollector, SupportBundlePciCollector
from vstacklens.application.paths import (
    default_hcl_download_dir,
    default_report_output_dir,
    ensure_default_upgrade_alias_path,
    upgrade_compat_database_path,
)
from vstacklens.resources import bundled_builtin_hcl_manifest_path, bundled_builtin_hcl_path
from vstacklens.core.context import RunContext
from vstacklens.core.ids import new_id
from vstacklens.core.time import utc_now_iso
from vstacklens.db.connection import connect, init_db, with_db_retry
from vstacklens.hcl.downloader import download_all_json, download_vcg_bundle
from vstacklens.hcl.freshness import assess_freshness
from vstacklens.hcl.matcher import HclMatcher, release_version_key
from vstacklens.hcl.sources import VcgDataSource, VsanHclDataSource
from vstacklens.hcl.store import HclStore
from vstacklens.inventory.normalizer import InventoryNormalizer
from vstacklens.reports.upgrade_compat_report import render_upgrade_compat_html
from vstacklens.upgrade_compat.aliases import load_aliases, resolve_alias
from vstacklens.upgrade_compat.server import match_server_model
from vstacklens.upgrade_compat.vsan import VsanContext, evaluate_vsan_compatibility


DEFAULT_UPGRADE_COMPAT_TITLE = "VStackLens 升级兼容性检查报告"
CollectionMode = Literal["vcenter", "support_bundle"]
VsanCheckMode = Literal["auto", "force", "skip"]
_COMPAT_STORAGE_LOCK = threading.RLock()


@dataclass(slots=True)
class UpgradeCompatConfig:
    collection_mode: CollectionMode = "vcenter"
    target_release: str = ""
    vsan_check_mode: VsanCheckMode = "auto"
    customer_name: str = ""
    report_title: str = DEFAULT_UPGRADE_COMPAT_TITLE
    report_dir: Path | str = field(default_factory=default_report_output_dir)
    db_path: Path | str = field(default_factory=upgrade_compat_database_path)
    vcenter_host: str = ""
    username: str = ""
    password: str = ""
    ssl_verify: bool = False
    bundle_path: Path | str = ""
    alias_path: Path | str | None = None

    def normalized(self) -> "UpgradeCompatConfig":
        return UpgradeCompatConfig(
            collection_mode=self.collection_mode,
            target_release=self.target_release.strip(), vsan_check_mode=self.vsan_check_mode,
            customer_name=self.customer_name.strip() or "未指定客户", report_title=self.report_title.strip() or DEFAULT_UPGRADE_COMPAT_TITLE,
            report_dir=Path(self.report_dir), db_path=Path(self.db_path), vcenter_host=self.vcenter_host.strip(),
            username=self.username.strip(), password=self.password, ssl_verify=bool(self.ssl_verify), bundle_path=Path(str(self.bundle_path).strip()) if str(self.bundle_path).strip() else Path(),
            alias_path=Path(self.alias_path) if self.alias_path else ensure_default_upgrade_alias_path(),
        )


@dataclass(frozen=True, slots=True)
class UpgradeCompatProgress:
    run_id: str | None
    stage: str
    percent: int
    message: str
    error: str | None = None


@dataclass(slots=True)
class UpgradeCompatResult:
    run_id: str
    report_dir: Path
    html_path: Path | None
    docx_path: Path | None
    summary: dict[str, Any]
    device_results: list[dict[str, Any]]
    server_results: list[dict[str, Any]]
    data_versions: dict[str, dict[str, Any]]
    collection_warnings: list[Any] = field(default_factory=list)
    connection_diagnostic: str | None = None
    timings_seconds: dict[str, float] = field(default_factory=dict)
    cancelled: bool = False


class UpgradeCompatService:
    def __init__(self, collector_factory: Callable[[UpgradeCompatConfig], Any] | None = None) -> None:
        self.collector_factory = collector_factory or self._default_collector

    def ensure_isolated_database(
        self,
        db_path: Path | str,
        *,
        seed_database_path: Path | str | None = None,
    ) -> Path:
        """Provision and validate the compatibility database without touching later primary writes."""

        target = Path(db_path)
        seed = Path(seed_database_path) if seed_database_path else None
        with _COMPAT_STORAGE_LOCK:
            if target.exists() and self._database_is_healthy(target):
                init_db(target, force=True)
            else:
                if target.exists():
                    self._quarantine_database(target)
                if seed and seed.exists() and self._database_is_healthy(seed):
                    self._copy_database(seed, target)
                else:
                    init_db(target, force=True)
                init_db(target, force=True)
            self.ensure_builtin_hcl_data(target)
            self._validate_compat_database(target, required_sources=("vcg", "vsan_hcl"))
        return target

    def import_hcl_data(self, *, db_path: Path | str, source: str, file_path: Path | str | None = None, online: bool = False, vcg_client_id: str | None = None, vcg_client_secret: str | None = None, progress_callback: Callable[[UpgradeCompatProgress], None] | None = None) -> dict[str, str]:
        db_path = Path(db_path)
        init_db(db_path)
        sources = ("vcg", "vsan_hcl") if source == "both" else ("vcg" if source == "vcg" else "vsan_hcl",)
        candidate = self._candidate_database_path(db_path)
        with _COMPAT_STORAGE_LOCK:
            self._copy_database(db_path, candidate)
            try:
                imported = self._import_hcl_into_candidate(
                    candidate,
                    sources=sources,
                    source=source,
                    file_path=file_path,
                    online=online,
                    vcg_client_id=vcg_client_id,
                    vcg_client_secret=vcg_client_secret,
                    progress_callback=progress_callback,
                )
                self._validate_compat_database(candidate, required_sources=sources)
                self._activate_candidate_database(candidate, db_path)
            except Exception:
                for suffix in ("", "-wal", "-shm"):
                    candidate.with_name(candidate.name + suffix).unlink(missing_ok=True)
                raise
        self._emit(progress_callback, None, "imported_hcl", 100, "HCL 判据数据导入完成")
        return imported

    def ensure_builtin_hcl_data(self, db_path: Path | str) -> dict[str, str]:
        """Seed missing HCL sources from the bundled baseline without overwriting local updates."""

        db_path = Path(db_path)
        self.builtin_baseline_status()
        init_db(db_path)
        imported: dict[str, str] = {}
        with closing(connect(db_path)) as conn, conn:
            store = HclStore(conn)
            for source, datasource_type in (("vcg", VcgDataSource), ("vsan_hcl", VsanHclDataSource)):
                if store.latest_data_version(source=source) is not None:
                    continue
                path = bundled_builtin_hcl_path(source)
                if not path.exists():
                    continue
                imported[source] = store.ingest_source(datasource_type(path))
        return imported

    def builtin_baseline_status(self) -> dict[str, Any]:
        """Verify the immutable packaged baseline before it is used for recovery."""

        manifest_path = bundled_builtin_hcl_manifest_path()
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError("内置 HCL 基线清单不可用，无法执行兼容性数据恢复。") from exc
        sources = manifest.get("sources") if isinstance(manifest, dict) else None
        if not isinstance(sources, dict):
            raise RuntimeError("内置 HCL 基线清单格式无效，无法执行兼容性数据恢复。")
        verified: dict[str, str] = {}
        for source in ("vcg", "vsan_hcl"):
            item = sources.get(source)
            expected = str(item.get("sha256") or "").casefold() if isinstance(item, dict) else ""
            path = bundled_builtin_hcl_path(source)
            if len(expected) != 64 or not path.exists():
                raise RuntimeError(f"内置 {source} HCL 基线缺失或清单不完整，无法执行兼容性数据恢复。")
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual != expected:
                raise RuntimeError(f"内置 {source} HCL 基线完整性校验失败，已拒绝使用该文件。")
            verified[source] = actual
        return {
            "version": str(manifest.get("baseline_version") or "未标记版本"),
            "verified": True,
            "sources": verified,
        }

    def _import_hcl_into_candidate(
        self,
        candidate: Path,
        *,
        sources: tuple[str, ...],
        source: str,
        file_path: Path | str | None,
        online: bool,
        vcg_client_id: str | None,
        vcg_client_secret: str | None,
        progress_callback: Callable[[UpgradeCompatProgress], None] | None,
    ) -> dict[str, str]:
        imported: dict[str, str] = {}
        for index, name in enumerate(sources, start=1):
            self._emit(progress_callback, None, "importing_hcl", int((index - 1) / len(sources) * 80), f"校验并导入 {name} 判据数据")
            if online:
                destination = default_hcl_download_dir() / ("vcg-bundle.json" if name == "vcg" else "vsan-all.json")
                destination.parent.mkdir(parents=True, exist_ok=True)
                if name == "vcg":
                    client_id = vcg_client_id or os.getenv("VSTACKLENS_VCG_CLIENT_ID", "")
                    client_secret = vcg_client_secret or os.getenv("VSTACKLENS_VCG_CLIENT_SECRET", "")
                    if not client_id or not client_secret:
                        raise ValueError("在线导入 VCG 需要 VSTACKLENS_VCG_CLIENT_ID 和 VSTACKLENS_VCG_CLIENT_SECRET。")
                    payload, _metadata = download_vcg_bundle(client_id, client_secret)
                    destination.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
                    datasource = VcgDataSource(destination)
                else:
                    download_all_json(destination)
                    datasource = VsanHclDataSource(destination)
            else:
                selected = self._local_source_path(file_path, name, source)
                datasource = VcgDataSource(selected) if name == "vcg" else VsanHclDataSource(selected)
            with closing(connect(candidate)) as conn, conn:
                imported[name] = HclStore(conn).ingest_source(datasource)
        return imported

    @staticmethod
    def _database_is_healthy(db_path: Path) -> bool:
        conn: sqlite3.Connection | None = None
        try:
            conn = sqlite3.connect(db_path, timeout=5.0)
            row = conn.execute("PRAGMA quick_check(1)").fetchone()
            return bool(row and row[0] == "ok")
        except sqlite3.Error:
            return False
        finally:
            if conn is not None:
                conn.close()

    def _validate_compat_database(self, db_path: Path, *, required_sources: tuple[str, ...]) -> None:
        if not self._database_is_healthy(db_path):
            raise RuntimeError("兼容性数据库完整性校验失败，未启用本次更新。")
        with closing(connect(db_path)) as conn, conn:
            store = HclStore(conn)
            for source in required_sources:
                row = store.latest_data_version(source=source)
                if row is None or not str(row["checksum_sha256"] or "").strip() or int(row["total_count"] or 0) <= 0:
                    raise RuntimeError(f"{source} HCL 数据校验未通过，未启用本次更新。")

    @staticmethod
    def _candidate_database_path(target: Path) -> Path:
        return target.with_name(f"{target.stem}.next-{new_id('db')}{target.suffix or '.db'}")

    @staticmethod
    def _copy_database(source: Path, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.unlink(missing_ok=True)
        source_conn = sqlite3.connect(source, timeout=30.0)
        destination_conn = sqlite3.connect(destination, timeout=30.0)
        try:
            source_conn.backup(destination_conn)
        finally:
            destination_conn.close()
            source_conn.close()

    @staticmethod
    def _activate_candidate_database(candidate: Path, target: Path) -> None:
        # The candidate is a checkpointed SQLite backup. Old WAL sidecars must
        # not be replayed against its replacement database. Windows can retain
        # a just-closed SQLite handle briefly, so retry the all-or-nothing swap.
        last_error: PermissionError | None = None
        for attempt in range(10):
            try:
                for suffix in ("-wal", "-shm"):
                    target.with_name(target.name + suffix).unlink(missing_ok=True)
                os.replace(candidate, target)
                return
            except PermissionError as exc:
                last_error = exc
                if attempt == 9:
                    break
                sleep(0.05 * (attempt + 1))
        assert last_error is not None
        raise last_error

    @staticmethod
    def _quarantine_database(target: Path) -> None:
        stamp = datetime.now().strftime("%Y%m%d%H%M%S")
        for suffix in ("", "-wal", "-shm"):
            current = target.with_name(target.name + suffix)
            if current.exists():
                quarantine = target.with_name(f"{target.name}.corrupt-{stamp}{suffix}")
                shutil.move(str(current), str(quarantine))

    def hcl_data_status(self, db_path: Path | str) -> dict[str, Any]:
        baseline = self.builtin_baseline_status()
        init_db(Path(db_path))
        with closing(connect(Path(db_path))) as conn, conn:
            store = HclStore(conn)
            result: dict[str, dict[str, Any]] = {}
            for source, label in (("vcg", "VCG"), ("vsan_hcl", "vSAN HCL")):
                row = store.latest_data_version(source=source)
                if row is None:
                    result[source] = {"label": label, "available": False, "data_version_id": None, "json_updated_time": None, "downloaded_at": None, "record_count": 0, "freshness": "UNKNOWN"}
                    continue
                fresh = assess_freshness(row["json_updated_time"] or row["downloaded_at"])
                result[source] = {"label": label, "available": True, "data_version_id": row["data_version_id"], "json_updated_time": row["json_updated_time"], "downloaded_at": row["downloaded_at"], "record_count": row["total_count"], "freshness": fresh.status, "age_days": fresh.age_days}
        vcg, vsan = result["vcg"]["available"], result["vsan_hcl"]["available"]
        if not vcg and not vsan: message = "VCG 和 vSAN HCL 均未导入，当前不能进行任何升级兼容性判定。"
        elif vsan and not vcg: message = "仅导入 vSAN HCL：可核对 vSAN 专项设备，但普通网卡和基础兼容性会大量显示无法确定。"
        elif vcg and not vsan: message = "仅导入 VCG：可进行基础兼容性判定，但 vSAN 专项兼容性不可用。"
        else: message = "VCG 与 vSAN HCL 均已导入，可进行基础和 vSAN 专项判定。"
        return {"sources": result, "message": message, "can_run": vcg or vsan, "baseline": baseline}

    def supported_releases(self, db_path: Path | str) -> list[str]:
        init_db(Path(db_path))
        with closing(connect(Path(db_path))) as conn, conn:
            store = HclStore(conn)
            releases = set(store.supported_releases(source="vcg")) | set(store.supported_releases(source="vsan_hcl"))
            return sorted(
                (str(value) for value in releases if str(value).strip()),
                key=lambda value: (release_version_key(value)[0] < 10**9, release_version_key(value)),
                reverse=True,
            )

    def validate_config(self, config: UpgradeCompatConfig) -> list[str]:
        raw = config
        cfg = config.normalized()
        errors: list[str] = []
        if raw.collection_mode not in {"vcenter", "support_bundle"}: errors.append("采集方式必须是 vcenter 或 support_bundle。")
        if raw.vsan_check_mode not in {"auto", "force", "skip"}: errors.append("vSAN 检查方式必须是 auto、force 或 skip。")
        releases = self.supported_releases(cfg.db_path)
        if not releases: errors.append("尚未导入 HCL 数据，无法读取目标 ESXi 版本列表。")
        elif cfg.target_release not in releases: errors.append(f"目标版本不在已导入 HCL 数据的支持列表中：{cfg.target_release}")
        if cfg.collection_mode == "vcenter":
            if not cfg.vcenter_host: errors.append("vCenter 模式需要填写 vCenter 地址。")
            if not cfg.username: errors.append("vCenter 模式需要填写用户名。")
            if not cfg.password: errors.append("vCenter 模式需要填写密码。")
        elif not str(raw.bundle_path).strip() or not cfg.bundle_path.exists(): errors.append("support bundle 模式需要选择存在的包文件。")
        return errors

    def run(
        self,
        config: UpgradeCompatConfig,
        progress_callback: Callable[[UpgradeCompatProgress], None] | None = None,
        cancel_requested: Callable[[], bool] | None = None,
    ) -> UpgradeCompatResult:
        cfg = config.normalized()
        errors = self.validate_config(config)
        if errors: raise ValueError("\n".join(errors))
        init_db(cfg.db_path)
        run_id, started = new_id("ucrun"), utc_now_iso()
        status = self.hcl_data_status(cfg.db_path)
        versions = status["sources"]
        self._insert_run(cfg, run_id, started, versions)
        cancelled = lambda warnings, devices=None, servers=None, timings=None: self._cancelled_result(
            cfg, run_id, versions, warnings, devices or [], servers or [], timings or {}, progress_callback
        )
        if self._is_cancel_requested(cancel_requested):
            return cancelled([])
        self._emit(progress_callback, run_id, "collecting", 10, "采集硬件与驱动信息")
        timings: dict[str, float] = {}
        try:
            collector = self.collector_factory(cfg)
            if isinstance(collector, PyVmomiPciCollector):
                collector.cancel_requested = cancel_requested or (lambda: False)
                collector.batch_progress = lambda done, total: self._emit(progress_callback, run_id, "collecting", 10 + int(20 * done / max(total, 1)), f"采集第 {done // 10 + 1} 批（每批最多 10 台），已处理 {done}/{total} 台")
            began = perf_counter()
            collected = collector.collect(RunContext(run_id, "upgrade_compat", "upgrade_compat", cfg.vcenter_host or "support_bundle", cfg.db_path), CollectionPlan())
            timings["collection"] = round(perf_counter() - began, 4)
        except Exception as exc:  # collector implementations must not crash this independent workflow.
            collected = {"objects": [], "collection_warnings": [{"status": "connection_failed", "error": type(exc).__name__}], "source": cfg.collection_mode}
        warnings = list(collected.get("collection_warnings") or [])
        if self._is_cancel_requested(cancel_requested):
            return cancelled(warnings, timings=timings)
        if any(isinstance(item, dict) and item.get("status") == "connection_failed" for item in warnings):
            diagnostic = "无法连接 vCenter 或凭据验证失败。请核对地址、账号、网络连通性、证书设置和最少只读权限。"
            result = UpgradeCompatResult(run_id, cfg.report_dir, None, None, {"total": 0, "passed": 0, "failed": 0, "unknown": 0}, [], [], versions, warnings, diagnostic, timings)
            self._finish_run(cfg.db_path, result, "connection_diagnostic", diagnostic)
            self._emit(progress_callback, run_id, "connection_diagnostic", 100, diagnostic, diagnostic)
            return result
        self._emit(progress_callback, run_id, "normalizing", 35, "归一化采集结果")
        normalizer = InventoryNormalizer()
        inventory = normalizer.normalize_pci_records(collected.get("objects") or [], source=collected.get("source"), collected_at=collected.get("collected_at"))
        hosts = normalizer.normalize_host_records(collected.get("host_records") or [])
        aliases, alias_warnings = load_aliases(cfg.alias_path)
        warnings.extend(alias_warnings)
        if self._is_cancel_requested(cancel_requested):
            return cancelled(warnings, timings=timings)
        self._emit(progress_callback, run_id, "evaluating", 50, "按设备执行双源兼容性判定")
        with closing(connect(cfg.db_path)) as conn, conn:
            store = HclStore(conn)
            matcher = HclMatcher(store)
            device_results: list[dict[str, Any]] = []
            for item in inventory.objects:
                if self._is_cancel_requested(cancel_requested):
                    return cancelled(warnings, device_results, timings=timings)
                device_results.append(self._evaluate_device(matcher, store, item, cfg, aliases))
            server_results: list[dict[str, Any]] = []
            for host in hosts.objects:
                if self._is_cancel_requested(cancel_requested):
                    return cancelled(warnings, device_results, server_results, timings)
                server_results.append(self._server_dict(match_server_model(store, host.properties.get("smbios_model"), cfg.target_release), host))
        summary = self._summary(device_results, server_results)
        payload = _jsonable({"metadata": {
            "customer_name": cfg.customer_name,
            "report_title": cfg.report_title,
            "target_release": cfg.target_release,
            "collection_source": "直连 vCenter" if cfg.collection_mode == "vcenter" else "support bundle",
            "vcenter_version": collected.get("vcenter_version"),
            "vcenter_build": collected.get("vcenter_build"),
        }, "data_versions": versions, "summary": summary, "device_results": device_results, "server_results": server_results, "collection_warnings": warnings})
        assert_json_serializable(payload)
        if self._is_cancel_requested(cancel_requested):
            return cancelled(warnings, device_results, server_results, timings)
        self._emit(progress_callback, run_id, "reporting", 82, "生成独立 HTML 升级兼容性报告")
        report_dir = Path(cfg.report_dir) / f"upgrade-compat-{run_id[-8:]}"
        html_path = render_upgrade_compat_html(payload, report_dir)
        report_dir = html_path.parent
        result = UpgradeCompatResult(run_id, report_dir, html_path, None, summary, device_results, server_results, versions, warnings, None, timings)
        self._finish_run(cfg.db_path, result, "success", None)
        self._emit(progress_callback, run_id, "success", 100, "升级兼容性检查完成")
        return result

    def _cancelled_result(
        self,
        cfg: UpgradeCompatConfig,
        run_id: str,
        versions: dict[str, dict[str, Any]],
        warnings: list[Any],
        devices: list[dict[str, Any]],
        servers: list[dict[str, Any]],
        timings: dict[str, float],
        progress_callback: Callable[[UpgradeCompatProgress], None] | None,
    ) -> UpgradeCompatResult:
        summary = self._summary(devices, servers)
        result = UpgradeCompatResult(run_id, Path(cfg.report_dir), None, None, summary, devices, servers, versions, warnings, None, timings, True)
        self._finish_run(cfg.db_path, result, "cancelled", "用户取消升级兼容性检查")
        self._emit(progress_callback, run_id, "cancelled", 100, "升级兼容性检查已取消")
        return result

    @staticmethod
    def _is_cancel_requested(callback: Callable[[], bool] | None) -> bool:
        try:
            return bool(callback and callback())
        except Exception:
            return False

    def _evaluate_device(self, matcher: HclMatcher, store: HclStore, item: Any, cfg: UpgradeCompatConfig, aliases: list[Any]) -> dict[str, Any]:
        prop = item.properties
        category = str(prop.get("category") or "")
        quad = tuple(prop.get(name) for name in ("vid", "did", "svid", "ssid"))
        quadruple = quad if all(value not in (None, "") for value in quad) else None
        model = prop.get("model")
        driver_name, driver_version = str(prop.get("driver_name") or ""), str(prop.get("driver_version") or "")
        firmware = prop.get("firmware_version")
        if prop.get("firmware_confidence") in {"low", "unknown"}:
            firmware = None
        sources = matcher.match_sources(quadruple, cfg.target_release, driver_name, driver_version, firmware, model=model, category=category)
        matches = {result.source: _jsonable(result) for result in sources.results}
        alias_matched, links = False, []
        alias_models: dict[str, str] = {}
        if category in {"ssd", "hdd"}:
            for source, current in list(matches.items()):
                if current.get("status") not in {"UNKNOWN_DEVICE", "MODEL_NOT_MATCHED"}: continue
                alias = resolve_alias(aliases, model, source=source, category=category)
                if alias and alias.hcl_model:
                    alternative = matcher.match(quadruple, cfg.target_release, driver_name, driver_version, firmware, model=alias.hcl_model, category=category, source=source)
                    matches[source] = _jsonable(alternative)
                    matches[source]["detail"] = (matches[source].get("detail") or "") + "；经别名表匹配"
                    alias_matched = True
                    alias_models[source] = alias.hcl_model
        if store.latest_data_version(source="vcg") is None:
            matches["vcg"] = {"source": "vcg", "status": "PLUGIN_STORE_UNAVAILABLE", "detail": "VCG 判据数据未导入"}
        if store.latest_data_version(source="vsan_hcl") is None:
            matches["vsan_hcl"] = {"source": "vsan_hcl", "status": "PLUGIN_STORE_UNAVAILABLE", "detail": "vSAN HCL 判据数据未导入"}
        context = VsanContext(prop.get("vsan_enabled"), prop.get("vsan_architecture"), prop.get("vsan_disk_layout"), prop.get("controller_mode"))
        vsan = evaluate_vsan_compatibility(store, quadruple=quadruple, model=alias_models.get("vsan_hcl", model), category=category, driver_name=driver_name, driver_version=driver_version, firmware_version=firmware, target_release=cfg.target_release, context=context, queue_depth_min=256, check_mode=cfg.vsan_check_mode)
        vsan_payload = _jsonable(vsan)
        if store.latest_data_version(source="vsan_hcl") is None:
            vsan_payload = {"status": "PLUGIN_STORE_UNAVAILABLE", "detail": "vSAN HCL 判据数据未导入"}
        if not driver_name or not driver_version:
            for match in matches.values():
                match.update(status="PLUGIN_DRIVER_INFO_MISSING", detail="缺少当前驱动信息，暂不能确认认证组合")
        if prop.get("association_conflict"):
            for match in matches.values():
                match.update(status="AMBIGUOUS_DEVICE", detail="采集来源的驱动或固件信息冲突，请先核对设备关联")
        for match in matches.values():
            if match.get("vcglink"): links.append(match["vcglink"])
            links.extend(match.get("candidate_links") or [])
        return {"object_key": item.object_key, "object_name": item.object_name, "host": item.object_path, "category": category, "model": model, "driver_name": driver_name or None, "driver_version": driver_version or None, "firmware_version": prop.get("firmware_version"), "firmware_raw": prop.get("firmware_raw"), "firmware_confidence": prop.get("firmware_confidence"), "field_sources": prop.get("field_sources"), "pci_address": prop.get("pci_address"), "pci_association_status": prop.get("pci_association_status"), "matches": matches, "vsan": vsan_payload, "alias_matched": alias_matched, "candidate_links": list(dict.fromkeys(links))}

    def _default_collector(self, cfg: UpgradeCompatConfig) -> Any:
        if cfg.collection_mode != "vcenter":
            return SupportBundlePciCollector(cfg.bundle_path)
        from vstacklens.collection.powercli_backend import PowerCliBackend
        from vstacklens.application.collection_settings import CollectionSettings
        settings = CollectionSettings.load()
        backend = PowerCliBackend(cfg.vcenter_host, cfg.username, cfg.password, timeout=settings.host_timeout, request_timeout=settings.request_timeout, retry_attempts=settings.retry_attempts)
        return PyVmomiPciCollector(cfg.vcenter_host, cfg.username, cfg.password, ssl_verify=False, timeout=settings.request_timeout, esxcli_provider=backend)

    def _local_source_path(self, file_path: Path | str | None, source: str, requested: str) -> Path:
        if not file_path: raise ValueError("本地导入需要 --file。")
        path = Path(file_path)
        if requested != "both": return path
        if not path.is_dir(): raise ValueError("--source both 的本地导入需要提供包含 vcg-bundle.json 和 vsan-all.json 的目录。")
        expected = "vcg-bundle.json" if source == "vcg" else "vsan-all.json"
        candidate = path / expected
        if candidate.exists():
            return candidate
        compressed = path / f"{expected}.gz"
        if compressed.exists():
            return compressed
        return candidate

    def _insert_run(self, cfg: UpgradeCompatConfig, run_id: str, now: str, versions: dict[str, Any]) -> None:
        with closing(connect(cfg.db_path)) as conn, conn:
            conn.execute("INSERT INTO upgrade_compat_runs (run_id, customer_name, report_title, target_release, collection_mode, vcenter_host, bundle_path, vsan_check_mode, vcg_data_version_id, vsan_data_version_id, run_status, current_stage, progress_percent, started_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'running', 'collecting', 10, ?, ?, ?)", (run_id, cfg.customer_name, cfg.report_title, cfg.target_release, cfg.collection_mode, cfg.vcenter_host or None, str(cfg.bundle_path) if cfg.collection_mode == "support_bundle" else None, cfg.vsan_check_mode, versions["vcg"]["data_version_id"], versions["vsan_hcl"]["data_version_id"], now, now, now))

    def _finish_run(self, db_path: Path, result: UpgradeCompatResult, status: str, error: str | None) -> None:
        now = utc_now_iso()
        payload = _jsonable({"summary": result.summary, "data_versions": result.data_versions, "collection_warnings": result.collection_warnings, "timings_seconds": result.timings_seconds})
        assert_json_serializable(payload)
        with closing(connect(db_path)) as conn, conn:
            conn.execute("UPDATE upgrade_compat_runs SET run_status = ?, current_stage = ?, progress_percent = 100, summary_json = ?, error_message = ?, finished_at = ?, updated_at = ? WHERE run_id = ?", (status, status, json.dumps(payload, ensure_ascii=False), error, now, now, result.run_id))
            if status == "success":
                if result.html_path:
                    conn.execute("INSERT INTO upgrade_compat_reports (report_id, run_id, report_name, report_type, report_status, file_path, generated_at, created_at, updated_at) VALUES (?, ?, ?, 'upgrade_compat_html', 'success', ?, ?, ?, ?)", (new_id("ucrep"), result.run_id, "HTML 报告", str(result.html_path), now, now, now))

    def _summary(self, devices: list[dict[str, Any]], servers: list[dict[str, Any]]) -> dict[str, Any]:
        passing = {"CERTIFIED", "CERTIFIED_NO_FIRMWARE_REQUIREMENT", "DRIVER_VERSION_NOT_LATEST"}
        failed = {"NOT_CERTIFIED", "DRIVER_NOT_CERTIFIED", "DRIVER_VERSION_BELOW_MINIMUM", "DRIVER_VERSION_MISMATCH", "FIRMWARE_MISMATCH"}
        from vstacklens.upgrade_compat.decision import effective_match, BLOCKING
        failed = BLOCKING
        base_statuses = [str(effective_match(item).get("status") or "") for item in devices]
        return {"total": len(devices), "passed": sum(value in passing for value in base_statuses), "failed": sum(value in failed for value in base_statuses), "unknown": sum(value not in passing | failed for value in base_statuses), "server_total": len(servers), "server_blocked": sum(item.get("status") == "SERVER_NOT_CERTIFIED" for item in servers)}

    def _server_dict(self, result: Any, host: Any) -> dict[str, Any]:
        payload = _jsonable(result)
        payload["host"] = host.object_name
        payload["host_context"] = _jsonable({
            key: host.properties.get(key)
            for key in (
                "bios_version", "bios_release_date", "cpu_model", "cpu_sockets",
                "cpu_cores", "cpu_threads", "memory_bytes", "uptime_seconds", "esxi_version",
                "esxi_build", "host_context_source",
            )
        })
        return payload
    def _emit(self, callback: Callable[[UpgradeCompatProgress], None] | None, run_id: str | None, stage: str, percent: int, message: str, error: str | None = None) -> None:
        if callback: callback(UpgradeCompatProgress(run_id, stage, percent, message, error))


def _jsonable(value: Any) -> Any:
    """Convert judgement results into JSON-safe primitives.

    pyVmomi hands back real ``datetime`` objects (for example
    ``biosInfo.releaseDate``), so every branch that reaches the report payload
    has to normalise them; letting one through breaks ``json.dumps`` far away
    from the field that caused it.
    """
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if hasattr(value, "model_dump"):
        return _jsonable(value.model_dump())
    if is_dataclass(value): return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, dict): return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)): return [_jsonable(item) for item in value]
    if isinstance(value, (datetime, date, time)): return value.isoformat()
    if isinstance(value, timedelta): return value.total_seconds()
    if isinstance(value, Decimal): return float(value)
    if isinstance(value, PurePath): return str(value)
    if isinstance(value, Enum): return _jsonable(value.value)
    if isinstance(value, (bytes, bytearray)): return value.decode("utf-8", "replace")
    # Unknown type: degrade to text instead of failing report generation, but
    # keep the type visible so the source can be fixed.
    return f"{value} <unserialized {type(value).__name__}>"


def assert_json_serializable(payload: Any, path: str = "payload") -> None:
    """Raise with the offending field path instead of a bare TypeError."""
    if payload is None or isinstance(payload, (str, bool, int, float)):
        return
    if isinstance(payload, dict):
        for key, item in payload.items():
            assert_json_serializable(item, f"{path}.{key}")
        return
    if isinstance(payload, (list, tuple)):
        for index, item in enumerate(payload):
            assert_json_serializable(item, f"{path}[{index}]")
        return
    raise TypeError(f"{path} is not JSON serializable: {type(payload).__name__} = {payload!r}")
