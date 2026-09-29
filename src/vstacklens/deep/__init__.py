"""Deep Inspection contracts, dataset analysis, and customer report helpers."""

from vstacklens.deep.analyzer import DeepAnalyzer, TrendAnalyzer
from vstacklens.deep.adapter import StandardSnapshotAdapter
from vstacklens.deep.contracts import (
    CapabilityMatrix,
    DeepDataset,
    DeepFinding,
    DeepRuleDefinition,
    DeepRuleResult,
    DeepResultStatus,
    ThresholdRegistry,
)

__all__ = [
    "CapabilityMatrix",
    "DeepAnalyzer",
    "StandardSnapshotAdapter",
    "DeepDataset",
    "DeepFinding",
    "DeepRuleDefinition",
    "DeepRuleResult",
    "DeepResultStatus",
    "ThresholdRegistry",
    "TrendAnalyzer",
]
