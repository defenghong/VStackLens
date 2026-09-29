from __future__ import annotations

from vstacklens.application.log_diagnostics.scenarios.generic import GenericProblemScenario
from vstacklens.application.log_diagnostics.scenarios.snapshot_consolidation import SnapshotConsolidationScenario
from vstacklens.application.log_diagnostics.scenarios.vm_migration_network import VmMigrationNetworkScenario

SCENARIO_METADATA = {
    GenericProblemScenario.scenario_id: {"title": GenericProblemScenario.title},
    SnapshotConsolidationScenario.scenario_id: {"title": SnapshotConsolidationScenario.title},
    VmMigrationNetworkScenario.scenario_id: {"title": VmMigrationNetworkScenario.title},
}


def scenario_title(scenario_id: str | None, fallback: str) -> str:
    if not scenario_id:
        return fallback
    metadata = SCENARIO_METADATA.get(scenario_id, {})
    return str(metadata.get("title") or fallback)

__all__ = [
    "GenericProblemScenario",
    "SCENARIO_METADATA",
    "SnapshotConsolidationScenario",
    "VmMigrationNetworkScenario",
    "scenario_title",
]
