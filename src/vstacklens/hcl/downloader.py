from __future__ import annotations

import hashlib
import gzip
import json
import urllib.request
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from vstacklens.core.ids import new_id
from vstacklens.core.time import utc_now_iso

ENDPOINTS = (
    "https://partnerweb.vmware.com/service/vsan/all.json",
    "https://vvs.broadcom.com/service/vsan/all.json",
)


@dataclass(frozen=True)
class DownloadResult:
    payload: dict
    metadata: object
    path: Path


def default_hcl_path(base_dir: Path | None = None) -> Path:
    return (base_dir or Path("data")) / "hcl" / "all.json"


def download_all_json(
    destination: Path | None = None,
    *,
    endpoints: tuple[str, ...] = ENDPOINTS,
    timeout: float = 60.0,
    opener: Callable = urllib.request.urlopen,
) -> DownloadResult:
    """Download the HCL document, trying endpoints in order and recording provenance."""
    errors: list[str] = []
    body: bytes | None = None
    source_url = ""
    for url in endpoints:
        try:
            with opener(url, timeout=timeout) as response:
                body = response.read()
            source_url = url
            break
        except Exception as exc:  # endpoint fallback is intentionally broad
            errors.append(f"{url}: {exc}")
    if body is None:
        raise RuntimeError("Unable to download HCL data: " + "; ".join(errors))
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Downloaded HCL document is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("Downloaded HCL document must be a JSON object")
    path = destination or default_hcl_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    from .models import DataVersionMeta

    metadata = DataVersionMeta(
        data_version_id=new_id("hclver"),
        source_url=source_url,
        downloaded_at=utc_now_iso(),
        checksum_sha256=hashlib.sha256(body).hexdigest(),
        json_updated_time=payload.get("jsonUpdatedTime"),
        total_count=int(payload.get("totalCount") or 0),
        supported_releases=list(payload.get("supportedReleases") or []),
    )
    return DownloadResult(payload=payload, metadata=metadata, path=path)


download = download_all_json


VCG_TOKEN_URL = "https://auth.esp.vmware.com/api/auth/v1/tokens"
VCG_BUNDLE_URL = "https://vvs.esp.vmware.com/v1/compatible/vcg/bundles/all?format=gz"


def download_vcg_bundle(
    client_id: str,
    client_secret: str,
    *,
    timeout: float = 600.0,
    opener: Callable = urllib.request.urlopen,
) -> tuple[dict, "DataVersionMeta"]:
    """Download VCG with caller-supplied credentials; credentials are never persisted."""
    form = urllib.parse.urlencode({"client_id": client_id, "client_secret": client_secret, "grant_type": "client_credentials"}).encode()
    request = urllib.request.Request(VCG_TOKEN_URL, data=form, headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
    with opener(request, timeout=timeout) as response:
        token_response = json.loads(response.read().decode("utf-8"))
    token = token_response.get("access_token")
    if not token:
        raise ValueError("VCG token response does not contain access_token")
    attempts: tuple[Mapping[str, str], ...] = (
        {"X-Vmw-Esp-Client": str(token), "Authorization": f"Bearer {token}"},
        {"X-Vmw-Esp-Client": str(token)},
        {"Authorization": f"Bearer {token}"},
    )
    errors: list[str] = []
    body: bytes | None = None
    for headers in attempts:
        try:
            with opener(urllib.request.Request(VCG_BUNDLE_URL, headers=dict(headers)), timeout=timeout) as response:
                body = response.read()
            break
        except Exception as exc:  # header fallbacks are required by the VCG endpoint behavior.
            errors.append(str(exc))
    if body is None:
        raise RuntimeError("Unable to download VCG bundle: " + "; ".join(errors))
    try:
        payload = json.loads(gzip.decompress(body).decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Downloaded VCG bundle is not valid gzip JSON") from exc
    from .models import DataVersionMeta

    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    releases = [str(item["releaseVersion"]) for item in payload.get("releases", []) if isinstance(item, dict) and item.get("releaseVersion")]
    return payload, DataVersionMeta(
        source="vcg",
        data_version_id=new_id("hclver"),
        source_url=VCG_BUNDLE_URL,
        downloaded_at=utc_now_iso(),
        checksum_sha256=hashlib.sha256(body).hexdigest(),
        json_updated_time=metadata.get("jsonUpdatedTime"),
        total_count=len(payload.get("iodevices") or []) + len(payload.get("server") or []),
        supported_releases=releases,
    )
