from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class RulePackLoader:
    def load_raw(self, rulepack: Path | str) -> list[dict[str, Any]]:
        rulepack = Path(rulepack)
        rules_dir = rulepack / "rules"
        raw_rules: list[dict[str, Any]] = []
        for path in sorted(rules_dir.glob("*.yaml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if isinstance(data, dict) and "rules" in data:
                raw_rules.extend(data["rules"])
            elif isinstance(data, list):
                raw_rules.extend(data)
            elif isinstance(data, dict) and "rule_id" in data:
                raw_rules.append(data)
        return raw_rules
