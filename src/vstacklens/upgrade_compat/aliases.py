"""Optional, externally maintained aliases for HCL model names."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class ModelAlias:
    collected_model: str
    hcl_model: str | None = None
    product_id: str | None = None
    source: str | None = None
    category: str | None = None
    note: str | None = None


def load_aliases(path: Path | None) -> tuple[list[ModelAlias], list[str]]:
    if path is None or not path.exists():
        return [], []
    try:
        raw: Any = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    except (OSError, yaml.YAMLError) as exc:
        return [], [f"型号别名表无法读取，已忽略：{type(exc).__name__}"]
    rows = raw.get("aliases", []) if isinstance(raw, dict) else raw
    if not isinstance(rows, list):
        return [], ["型号别名表格式错误，已忽略：aliases 必须是列表"]
    aliases: list[ModelAlias] = []
    warnings: list[str] = []
    for index, item in enumerate(rows):
        if not isinstance(item, dict) or not str(item.get("collected_model") or "").strip():
            warnings.append(f"型号别名表第 {index + 1} 项格式错误，已忽略")
            continue
        if not item.get("hcl_model") and item.get("product_id") is None:
            warnings.append(f"型号别名表第 {index + 1} 项缺少 hcl_model 或 product_id，已忽略")
            continue
        aliases.append(ModelAlias(
            collected_model=str(item["collected_model"]).strip(),
            hcl_model=str(item["hcl_model"]).strip() if item.get("hcl_model") else None,
            product_id=str(item["product_id"]).strip() if item.get("product_id") is not None else None,
            source=str(item["source"]).strip() if item.get("source") else None,
            category=str(item["category"]).strip() if item.get("category") else None,
            note=str(item["note"]).strip() if item.get("note") else None,
        ))
    return aliases, warnings


def resolve_alias(aliases: list[ModelAlias], model: str | None, *, source: str, category: str) -> ModelAlias | None:
    raw = str(model or "").strip().casefold()
    for alias in aliases:
        if alias.collected_model.casefold() != raw:
            continue
        if alias.source and alias.source != source:
            continue
        if alias.category and alias.category != category:
            continue
        return alias
    return None
