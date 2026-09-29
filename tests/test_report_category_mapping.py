from vstacklens.reports.category_mapping import FindingCategoryMapper, map_findings_to_categories, report_category_count


def test_snapshot_rules_merge_and_deduplicate_same_vm() -> None:
    findings = [
        {"rule_id": "VSL-VM-001", "object_key": "vm-1", "object_name": "VM-A"},
        {"rule_id": "VSL-VM-007", "object_key": "vm-1", "object_name": "VM-A"},
        {"rule_id": "VSL-VM-022", "object_key": "vm-1", "object_name": "VM-A"},
    ]
    result = map_findings_to_categories(findings)
    category = next(item for item in result.categories if item["category_id"] == "VM-SNAPSHOT")
    assert result.risk_category_summary["P2"] == 1
    assert category["affected_object_count"] == 1
    assert set(category["subreasons"]) == {"超期快照", "快照链过深", "Consolidation Needed"}


def test_snapshot_category_counts_three_objects_once() -> None:
    result = FindingCategoryMapper().map([
        {"rule_id": "VSL-VM-001", "object_key": "a", "object_name": "VM-A"},
        {"rule_id": "VSL-VM-007", "object_key": "b", "object_name": "VM-B"},
        {"rule_id": "VSL-VM-022", "object_key": "c", "object_name": "VM-C"},
    ])
    category = next(item for item in result.categories if item["category_id"] == "VM-SNAPSHOT")
    assert result.risk_category_summary == {"P1": 0, "P2": 1, "P3": 0, "P4": 0}
    assert result.affected_object_summary["P2"] == 3
    assert category["affected_object_count"] == 3


def test_ssh_and_shell_merge_same_host() -> None:
    result = map_findings_to_categories([
        {"rule_id": "VSL-HOST-002", "object_key": "h1", "object_name": "esxi-01"},
        {"rule_id": "VSL-HOST-016", "object_key": "h1", "object_name": "esxi-01"},
    ])
    category = next(item for item in result.categories if item["category_id"] == "HOST-MANAGEMENT-SERVICE")
    assert result.risk_category_summary["P1"] == 1
    assert category["affected_object_count"] == 1
    assert category["subreasons"] == ["SSH", "ESXi Shell"]


def test_resource_rules_merge_but_keep_subreasons() -> None:
    result = map_findings_to_categories([
        {"rule_id": "VSL-VM-010", "object_key": "vm-1", "object_name": "VM-A"},
        {"rule_id": "VSL-VM-011", "object_key": "vm-1", "object_name": "VM-A"},
        {"rule_id": "VSL-VM-012", "object_key": "vm-1", "object_name": "VM-A"},
    ])
    category = next(item for item in result.categories if item["category_id"] == "VM-RESOURCE-CONFIG")
    assert result.risk_category_summary["P3"] == 1
    assert category["affected_object_count"] == 1
    assert set(category["subreasons"]) == {"Reservation", "Limit", "vCPU 配置过大"}


def test_hidden_p4_information_and_pending_rule_are_not_standard_risks() -> None:
    result = map_findings_to_categories([
        {"rule_id": "VSL-VM-015", "object_key": "vm-1", "object_name": "VM-A", "risk_level": "P4"},
        {"rule_id": "VSL-VM-021", "object_key": "vm-1", "object_name": "VM-A", "risk_level": "P1"},
    ])
    assert result.risk_category_summary == {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    assert "VSL-VM-021" in result.pending_rules
    assert not result.categories


def test_context_sensitive_categories_and_threshold_semantics() -> None:
    vsan = map_findings_to_categories([{"rule_id": "VSL-CL-009", "object_key": "c", "object_name": "vSAN-C"}], vsan_applicable=True)
    normal = map_findings_to_categories([{"rule_id": "VSL-CL-009", "object_key": "c", "object_name": "C"}], vsan_applicable=False)
    assert vsan.categories[0]["priority"] == "P1"
    assert normal.categories[0]["priority"] == "P2"
    for value in (5, 10, 15):
        result = map_findings_to_categories([{"rule_id": "VSL-VM-004", "object_key": "vm", "object_name": "VM", "current_value": value}])
        assert result.categories[0]["priority"] == "P1"


def test_vsan_resync_activity_alone_is_not_a_finding_and_ds020_is_bridge() -> None:
    result = map_findings_to_categories([
        {"rule_id": "VSAN-05", "object_key": "cluster", "object_name": "vSAN", "evidence": {"totalObjectsToSync": 2}},
        {"rule_id": "VSL-DS-020", "object_key": "ds", "object_name": "vsanDatastore"},
        {"rule_id": "VSAN-01", "object_key": "cluster", "object_name": "vSAN"},
    ], vsan_applicable=True)
    assert [item["category_id"] for item in result.categories] == ["VSAN-CLUSTER-HEALTH"]


def test_catalog_is_explicit_and_unknown_rules_are_reported() -> None:
    result = map_findings_to_categories([{"rule_id": "VSL-NEW-999", "object_name": "x"}])
    assert report_category_count() >= 50
    assert result.unmapped_rules == ["VSL-NEW-999"]
