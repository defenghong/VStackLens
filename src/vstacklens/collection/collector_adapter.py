from __future__ import annotations

from typing import Protocol

from vstacklens.collection.collection_plan import CollectionPlan
from vstacklens.core.context import RunContext


class CollectorAdapter(Protocol):
    def collect(self, context: RunContext, plan: CollectionPlan) -> dict:
        ...
