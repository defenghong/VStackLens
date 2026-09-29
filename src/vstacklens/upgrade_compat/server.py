from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from vstacklens.hcl.store import HclStore, _normalize_model


ServerStatus = Literal["SERVER_CERTIFIED", "SERVER_NOT_CERTIFIED", "SERVER_UNKNOWN_MODEL", "SERVER_MODEL_AMBIGUOUS"]


@dataclass(frozen=True)
class ServerCompatibilityResult:
    status: ServerStatus
    detail: str
    model: str
    vcglink: str | None = None
    candidate_links: tuple[str, ...] = ()


def match_server_model(store: HclStore, model: str | None, target_release: str) -> ServerCompatibilityResult:
    raw_model = str(model or "").strip()
    normalized = _normalize_model(raw_model)
    if not normalized:
        return ServerCompatibilityResult("SERVER_UNKNOWN_MODEL", "主机 SMBiosModel 未采集", raw_model)
    candidates = store.get_server_models(raw_model, source="vcg")
    if not candidates:
        return ServerCompatibilityResult("SERVER_UNKNOWN_MODEL", "VCG server 类别未找到主机型号", raw_model)
    # get_server_models already favors exact SMBIOS/model equality; retain only
    # exact matches here so near-name models cannot produce a false positive.
    exact = [row for row in candidates if normalized == _normalize_model(row["model"]) or normalized in {_normalize_model(item) for item in _smbios_models(row)}]
    candidates = exact or candidates
    links = tuple(str(row["vcglink"]) for row in candidates if row["vcglink"])
    certified_values = {bool(store.release_rows(row["hcl_device_id"], target_release)) for row in candidates}
    if len(certified_values) > 1:
        return ServerCompatibilityResult("SERVER_MODEL_AMBIGUOUS", f"精确型号命中 {len(candidates)} 个 VCG 条目，目标版本认证结论不一致", raw_model, candidate_links=links)
    certified = certified_values == {True}
    return ServerCompatibilityResult(
        "SERVER_CERTIFIED" if certified else "SERVER_NOT_CERTIFIED",
        "目标版本存在整机认证记录" if certified else "目标版本没有整机认证记录",
        raw_model,
        links[0] if links else None,
        links,
    )


def _smbios_models(row) -> list[str]:
    import json
    try:
        value = json.loads(row["server_smbios_models_json"] or "[]")
    except (TypeError, ValueError):
        value = []
    return value if isinstance(value, list) else []
