from __future__ import annotations

import json
from pathlib import Path

from vstacklens.collection.collection_plan import CollectionPlan
from vstacklens.core.context import RunContext


class MockCollector:
    def __init__(self, fixture_path: Path) -> None:
        self.fixture_path = fixture_path

    def collect(self, context: RunContext, plan: CollectionPlan) -> dict:
        return json.loads(self.fixture_path.read_text(encoding="utf-8"))
