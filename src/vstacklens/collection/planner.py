from __future__ import annotations

from vstacklens.collection.collection_plan import CollectionPlan, PerformanceMetricRequest
from vstacklens.rules.schema import RuleDefinition


class CollectionPlanner:
    def build(self, rules: list[RuleDefinition]) -> CollectionPlan:
        plan = CollectionPlan()
        for rule in rules:
            plan.object_types.add(rule.object_type)
            plan.properties.setdefault(rule.object_type, set()).update(rule.data_source.api_paths)
            if rule.data_source.source_domain == "performance":
                sampling = rule.data_source.sampling or {}
                for metric in rule.data_source.api_paths:
                    plan.performance_metrics.append(
                        PerformanceMetricRequest(
                            object_type=rule.object_type,
                            metric=metric,
                            window_minutes=int(sampling.get("window_minutes", 60)),
                            minimum_samples=int(sampling.get("minimum_samples", 3)),
                        )
                    )
                plan.permissions_required.add("performance_read")
            elif rule.data_source.source_domain == "alarm":
                plan.permissions_required.add("alarm_read")
            elif rule.data_source.source_domain == "config":
                plan.permissions_required.add("inventory_read")
            elif rule.data_source.source_domain == "runtime":
                plan.permissions_required.add("inventory_read")
            elif rule.data_source.source_domain in {"certificate", "plugin"}:
                plan.plugin_sources.add(rule.data_source.type)
        return plan
