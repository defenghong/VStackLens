from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class RunContext:
    run_id: str
    customer_id: str
    site_id: str
    vcenter_id: str
    db_path: Path
    collector_version: str = "0.2.0"


@dataclass(frozen=True)
class RuleExecutionContext:
    run: RunContext
    inventory: Any
    rules: list[Any]
