from __future__ import annotations

import hashlib
import gzip
import json
from pathlib import Path
from typing import Any, Mapping

from vstacklens.core.time import utc_now_iso

from .models import DataVersionMeta


def _file_metadata(path: Path, payload: Mapping[str, Any], source: str, total_count: int, releases: list[str]) -> DataVersionMeta:
    body = path.read_bytes()
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    updated = payload.get("jsonUpdatedTime") or metadata.get("jsonUpdatedTime")
    return DataVersionMeta(
        source=source,
        source_url=str(path),
        downloaded_at=utc_now_iso(),
        checksum_sha256=hashlib.sha256(body).hexdigest(),
        json_updated_time=updated,
        total_count=total_count,
        supported_releases=releases,
    )


class JsonHclDataSource:
    """Simple local JSON source retained for existing callers and tests."""

    source = "vsan_hcl"

    def __init__(self, path: Path | str):
        self.path = Path(path)

    def load(self) -> Mapping[str, Any]:
        if self.path.suffix.casefold() == ".gz":
            with gzip.open(self.path, "rt", encoding="utf-8") as stream:
                return json.load(stream)
        return json.loads(self.path.read_text(encoding="utf-8"))


class VsanHclDataSource(JsonHclDataSource):
    source = "vsan_hcl"

    def metadata(self, payload: Mapping[str, Any] | None = None) -> DataVersionMeta:
        payload = payload or self.load()
        data = payload.get("data") or {}
        total = sum(len(items) for items in data.values() if isinstance(items, list))
        return _file_metadata(self.path, payload, self.source, total, list(payload.get("supportedReleases") or []))


class VcgDataSource(JsonHclDataSource):
    source = "vcg"

    def metadata(self, payload: Mapping[str, Any] | None = None) -> DataVersionMeta:
        payload = payload or self.load()
        releases = [str(item.get("releaseVersion")) for item in payload.get("releases", []) if isinstance(item, dict) and item.get("releaseVersion")]
        total = sum(len(payload.get(name) or []) for name in ("iodevices", "server", "cpuseries", "addons"))
        metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
        return _file_metadata(self.path, payload, self.source, total, releases)
