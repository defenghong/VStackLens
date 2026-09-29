from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from typing import Any

from vstacklens.hcl.freshness import FreshnessResult, assess_freshness
from vstacklens.hcl.matcher import HclMatcher
from vstacklens.hcl.sources import VcgDataSource
from vstacklens.hcl.store import HclStore


_HCL_MEMORY_SCHEMA = """
CREATE TABLE hcl_data_versions (
  data_version_id TEXT PRIMARY KEY,
  source_url TEXT NOT NULL,
  downloaded_at TEXT NOT NULL,
  json_updated_time TEXT,
  total_count INTEGER NOT NULL DEFAULT 0,
  checksum_sha256 TEXT NOT NULL,
  supported_releases_json TEXT NOT NULL DEFAULT '[]',
  source TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE hcl_devices (
  hcl_device_id TEXT PRIMARY KEY,
  data_version_id TEXT NOT NULL,
  category TEXT NOT NULL,
  external_id TEXT NOT NULL,
  model TEXT NOT NULL,
  vendor TEXT NOT NULL,
  vid TEXT NOT NULL,
  did TEXT NOT NULL,
  svid TEXT NOT NULL,
  ssid TEXT NOT NULL,
  source TEXT NOT NULL,
  model_normalized TEXT NOT NULL DEFAULT '',
  server_smbios_models_json TEXT NOT NULL DEFAULT '[]',
  vcglink TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_hcl_devices_source_quadruple ON hcl_devices(source, vid, did, svid, ssid);
CREATE INDEX idx_hcl_devices_model_normalized ON hcl_devices(category, model_normalized);
CREATE TABLE hcl_device_releases (
  hcl_device_id TEXT NOT NULL,
  release TEXT NOT NULL,
  driver_name TEXT NOT NULL,
  driver_version TEXT NOT NULL,
  firmware_version TEXT,
  driver_spec_json TEXT NOT NULL DEFAULT '{}',
  queue_depth TEXT,
  vsan_support_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL
);
CREATE INDEX idx_hcl_releases_quadruple ON hcl_device_releases(hcl_device_id, release, driver_name, driver_version, firmware_version);
"""


@dataclass
class BundledVcgIndex:
    connection: sqlite3.Connection
    store: HclStore
    matcher: HclMatcher
    data_version_id: str
    baseline_version: str
    json_updated_time: str | None
    checksum_sha256: str
    freshness: FreshnessResult
    supported_releases: tuple[str, ...]

    def close(self) -> None:
        self.connection.close()


def load_bundled_vcg_index() -> BundledVcgIndex:
    """Load the packaged VCG baseline into a private, ephemeral SQLite index."""

    from vstacklens.resources import bundled_builtin_hcl_manifest_path, bundled_builtin_hcl_path

    manifest = json.loads(bundled_builtin_hcl_manifest_path().read_text(encoding="utf-8"))
    source_manifest = (manifest.get("sources") or {}).get("vcg")
    if not isinstance(source_manifest, dict):
        raise ValueError("bundled VCG manifest entry is missing")
    source_path = bundled_builtin_hcl_path("vcg")
    if not source_path.is_file():
        raise FileNotFoundError("bundled VCG snapshot is missing")
    if str(source_manifest.get("filename") or "") != source_path.name:
        raise ValueError("bundled VCG filename does not match its manifest")
    digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
    expected_digest = str(source_manifest.get("sha256") or "").strip().casefold()
    if not expected_digest or digest.casefold() != expected_digest:
        raise ValueError("bundled VCG checksum does not match its manifest")

    source = VcgDataSource(source_path)
    payload = source.load()
    metadata = source.metadata(payload)
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.executescript(_HCL_MEMORY_SCHEMA)
        store = HclStore(connection)
        data_version_id = store.ingest(payload, metadata=metadata, source="vcg")
        releases = tuple(store.supported_releases(source="vcg"))
        if not releases:
            raise ValueError("bundled VCG snapshot has no supported releases")
        return BundledVcgIndex(
            connection=connection,
            store=store,
            matcher=HclMatcher(store),
            data_version_id=data_version_id,
            baseline_version=str(manifest.get("baseline_version") or "unknown"),
            json_updated_time=metadata.json_updated_time,
            checksum_sha256=digest,
            freshness=assess_freshness(metadata.json_updated_time),
            supported_releases=releases,
        )
    except Exception:
        connection.close()
        raise


def esxi_version_to_hcl_release(version: str, supported_releases: tuple[str, ...] | list[str]) -> str | None:
    """Map numeric ESXi 7/8 update versions only when the exact HCL label exists."""

    match = re.fullmatch(r"\s*(\d+)\.(\d+)\.(\d+)\s*", str(version or ""))
    if not match:
        return None
    major, minor, update = (int(part) for part in match.groups())
    if major in {7, 8}:
        release = f"ESXi {major}.{minor}" if update == 0 else f"ESXi {major}.{minor} U{update}"
    elif major >= 9 and update == 0:
        release = f"ESXi {major}.{minor}"
    else:
        return None
    return release if release in set(supported_releases) else None
