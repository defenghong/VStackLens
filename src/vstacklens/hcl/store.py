from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Mapping
from typing import Any, Protocol

from vstacklens.core.ids import new_id
from vstacklens.core.time import utc_now_iso

from .models import DataVersionMeta
from .sources import JsonHclDataSource


class HclDataSource(Protocol):
    source: str
    def load(self) -> Mapping[str, Any]: ...


class HclStore:
    """SQLite-backed store for independent vSAN HCL and Broadcom VCG records."""

    def __init__(self, connection: sqlite3.Connection):
        self.conn = connection
        self.conn.row_factory = sqlite3.Row

    def ingest_source(self, source: HclDataSource) -> str:
        payload = source.load()
        metadata = source.metadata(payload) if hasattr(source, "metadata") else None
        return self.ingest(payload, metadata=metadata, source=getattr(source, "source", "vsan_hcl"))

    def ingest(self, payload: Mapping[str, Any], metadata: DataVersionMeta | None = None, *, source: str | None = None) -> str:
        inferred_source = source or (metadata.source if metadata else None) or ("vcg" if "iodevices" in payload else "vsan_hcl")
        now = utc_now_iso()
        metadata = metadata or self._default_metadata(payload, inferred_source, now)
        # A checksum-derived id makes a local re-import genuinely idempotent.
        version_id = metadata.data_version_id or f"hclver-{inferred_source}-{metadata.checksum_sha256[:24]}"
        downloaded = metadata.downloaded_at
        self.conn.execute(
            "INSERT OR REPLACE INTO hcl_data_versions (data_version_id, source_url, downloaded_at, json_updated_time, total_count, checksum_sha256, supported_releases_json, source, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (version_id, metadata.source_url, downloaded, metadata.json_updated_time, metadata.total_count, metadata.checksum_sha256, json.dumps(metadata.supported_releases), inferred_source, now),
        )
        if inferred_source == "vcg":
            self._ingest_vcg(payload, version_id, now)
        else:
            self._ingest_vsan(payload, version_id, now)
        self.conn.commit()
        return version_id

    def _default_metadata(self, payload: Mapping[str, Any], source: str, now: str) -> DataVersionMeta:
        releases = payload.get("supportedReleases") or [item.get("releaseVersion") for item in payload.get("releases", []) if isinstance(item, dict)]
        data = payload.get("data") or {}
        total = int(payload.get("totalCount") or sum(len(value) for value in data.values() if isinstance(value, list)))
        metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
        return DataVersionMeta(source=source, source_url="unknown", downloaded_at=now, checksum_sha256="", json_updated_time=payload.get("jsonUpdatedTime") or metadata.get("jsonUpdatedTime"), total_count=total, supported_releases=[str(value) for value in releases if value])

    def _ingest_vsan(self, payload: Mapping[str, Any], version_id: str, now: str) -> None:
        for category, records in (payload.get("data") or {}).items():
            if not isinstance(records, list):
                continue
            for raw in records:
                if not isinstance(raw, dict):
                    continue
                device_id = self._insert_device(version_id, "vsan_hcl", category, raw.get("id"), raw.get("model"), raw.get("vendor"), raw.get("vid"), raw.get("did"), raw.get("svid"), raw.get("ssid"), raw.get("vcglink"), now)
                for release, drivers in (raw.get("releases") or {}).items():
                    if not isinstance(drivers, dict):
                        continue
                    for driver_name, versions in drivers.items():
                        if driver_name == "vsanSupport" or not isinstance(versions, dict):
                            continue
                        for driver_version, spec in versions.items():
                            if not isinstance(spec, dict):
                                continue
                            queue_depth = spec.get("queueDepth")
                            vsan_support = spec.get("vsanSupport", drivers.get("vsanSupport", []))
                            firmwares = [item.get("firmware") for item in spec.get("firmwares", []) if isinstance(item, dict) and item.get("firmware") is not None]
                            self._insert_release_rows(device_id, str(release), str(driver_name), str(driver_version), firmwares, spec, queue_depth, vsan_support, now)

    def _ingest_vcg(self, payload: Mapping[str, Any], version_id: str, now: str) -> None:
        for raw in payload.get("iodevices", []) or []:
            if not isinstance(raw, dict):
                continue
            category = _vcg_category(raw.get("deviceTypeName"))
            device_id = self._insert_device(version_id, "vcg", category, raw.get("productId"), raw.get("modelName"), raw.get("manufacturer") or raw.get("partner"), raw.get("vid"), raw.get("did"), raw.get("svid"), raw.get("ssid"), raw.get("vcgLink"), now)
            for supported in raw.get("supportedReleases", []) or []:
                if not isinstance(supported, dict) or not supported.get("releaseVersion"):
                    continue
                for feature in supported.get("certFeatures", []) or []:
                    if not isinstance(feature, dict) or not feature.get("driverName") or feature.get("driverVersion") is None:
                        continue
                    firmware = feature.get("firmware")
                    self._insert_release_rows(device_id, str(supported["releaseVersion"]), str(feature["driverName"]), str(feature["driverVersion"]), [firmware] if firmware is not None else [], feature, None, [], now)
        for raw in payload.get("server", []) or []:
            if not isinstance(raw, dict):
                continue
            device_id = self._insert_device(version_id, "vcg", "server", raw.get("productId"), raw.get("modelName"), raw.get("manufacturer") or raw.get("partner"), "", "", "", "", raw.get("vcgLink"), now, server_smbios_models=raw.get("SMBiosModel"))
            for supported in raw.get("supportedReleases", []) or []:
                if not isinstance(supported, dict) or not supported.get("releaseVersion"):
                    continue
                for feature in supported.get("certFeatures", []) or []:
                    if isinstance(feature, dict) and feature.get("bios"):
                        self._insert_release_rows(device_id, str(supported["releaseVersion"]), "bios", str(feature["bios"]), [], feature, None, [], now)

    def _insert_device(self, version_id: str, source: str, category: str, external_id: Any, model: Any, vendor: Any, vid: Any, did: Any, svid: Any, ssid: Any, vcglink: Any, now: str, server_smbios_models: Any = None) -> str:
        device_id = f"{version_id}:{category}:{external_id}"
        values = [str(value or "").strip().casefold() for value in (vid, did, svid, ssid)]
        model_text = str(model or "")
        self.conn.execute(
            "INSERT OR REPLACE INTO hcl_devices (hcl_device_id, data_version_id, category, external_id, model, vendor, vid, did, svid, ssid, source, model_normalized, server_smbios_models_json, vcglink, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (device_id, version_id, category, str(external_id or ""), model_text, str(vendor or ""), *values, source, _normalize_model(model_text), json.dumps(server_smbios_models if isinstance(server_smbios_models, list) else []), vcglink, now),
        )
        self.conn.execute("DELETE FROM hcl_device_releases WHERE hcl_device_id = ?", (device_id,))
        return device_id

    def _insert_release_rows(self, device_id: str, release: str, name: str, version: str, firmwares: list[Any], spec: Mapping[str, Any], queue_depth: Any, vsan_support: Any, now: str) -> None:
        normalized = [_firmware_or_none(value) for value in firmwares]
        for firmware in normalized or [None]:
            self.conn.execute(
                "INSERT INTO hcl_device_releases (hcl_device_id, release, driver_name, driver_version, firmware_version, driver_spec_json, queue_depth, vsan_support_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (device_id, release, name, version, firmware, json.dumps(spec), None if queue_depth is None else str(queue_depth), json.dumps(vsan_support if isinstance(vsan_support, list) else []), now),
            )

    def supported_releases(self, *, source: str | None = None) -> list[str]:
        sql = "SELECT supported_releases_json FROM hcl_data_versions"
        params: list[Any] = []
        if source:
            sql += " WHERE source = ?"
            params.append(source)
        row = self.conn.execute(sql + " ORDER BY created_at DESC LIMIT 1", params).fetchone()
        return list(json.loads(row[0] or "[]")) if row else []

    def get_device(self, quadruple: tuple[str, str, str, str] | None = None, *, model: str | None = None, category: str | None = None, source: str | None = None) -> list[sqlite3.Row]:
        clauses: list[str] = []
        params: list[Any] = []
        if quadruple is not None:
            values = tuple(str(value or "").strip().casefold() for value in quadruple)
            clauses.append("vid = ? AND did = ? AND svid = ? AND ssid = ?")
            params.extend(values)
        normalized = _normalize_model(model) if model is not None else ""
        if model is not None:
            if not normalized:
                return []
            clauses.append("model_normalized <> ''")
        if not clauses:
            raise ValueError("quadruple or model is required")
        sql = "SELECT * FROM hcl_devices WHERE (" + " AND ".join(clauses) + ")"
        if category:
            sql += " AND category = ?"
            params.append(category)
        if source:
            sql += " AND source = ?"
            params.append(source)
        rows = self.conn.execute(sql + " ORDER BY rowid", params).fetchall()
        return rows if model is None else [row for row in rows if normalized in row["model_normalized"]]

    def release_rows(self, hcl_device_id: str, release: str) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM hcl_device_releases WHERE hcl_device_id = ? AND release = ?", (hcl_device_id, release)).fetchall()

    def supported_releases_for_device(self, hcl_device_id: str) -> list[str]:
        rows = self.conn.execute(
            "SELECT DISTINCT release FROM hcl_device_releases WHERE hcl_device_id = ?",
            (hcl_device_id,),
        ).fetchall()
        return [str(row[0]) for row in rows if str(row[0] or "").strip()]

    def get_server_models(self, smbios_model: str, *, source: str = "vcg") -> list[sqlite3.Row]:
        normalized = _normalize_model(smbios_model)
        if not normalized:
            return []
        rows = self.conn.execute("SELECT * FROM hcl_devices WHERE category = 'server' AND source = ?", (source,)).fetchall()
        return [
            row for row in rows
            if normalized == _normalize_model(row["model"])
            or normalized in {_normalize_model(item) for item in json.loads(row["server_smbios_models_json"] or "[]")}
        ]

    def latest_data_version(self, *, source: str | None = None) -> sqlite3.Row | None:
        sql = "SELECT * FROM hcl_data_versions"
        return self.conn.execute(sql + (" WHERE source = ?" if source else "") + " ORDER BY created_at DESC LIMIT 1", (source,) if source else ()).fetchone()


def _normalize_model(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").strip().casefold())


def _firmware_or_none(value: Any) -> str | None:
    text = str(value or "").strip()
    return None if not text or text.casefold() in {"n/a", "na"} else text


def _vcg_category(device_type: Any) -> str:
    text = str(device_type or "").casefold()
    if "network" in text or "fcoe" in text or "iscsi" in text:
        return "nic"
    if any(token in text for token in ("raid", "sas", "sata", "fc", "scsi")):
        return "controller"
    if "nvme" in text:
        return "ssd"
    return "io_device"
