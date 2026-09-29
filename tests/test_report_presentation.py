from vstacklens.reports.presentation import (
    build_risk_group_summary,
    execution_status,
    mask_username,
    object_type_label,
    rule_catalog_summary,
    rule_category_label,
)


def test_module_label_mappings_are_customer_readable() -> None:
    assert object_type_label("HostSystem") == "ESXi 主机"
    assert object_type_label("VirtualMachine") == "虚拟机"
    assert rule_category_label("security") == "安全合规"
    assert rule_category_label("capacity") == "容量与趋势"


def test_risk_group_summary_sorts_by_severity_count_and_module() -> None:
    findings = [
        {"risk_level": "P3", "rule_id": "VSL-VM-001", "title": "VM risk", "category": "vm", "object_name": "vm-1"},
        {"risk_level": "P2", "rule_id": "VSL-HOST-001", "title": "Host risk", "category": "host", "object_name": "h1"},
        {"risk_level": "P2", "rule_id": "VSL-HOST-001", "title": "Host risk", "category": "host", "object_name": "h2"},
        {"risk_level": "P2", "rule_id": "VSL-VC-004", "title": "VC risk", "category": "vcenter", "object_name": "vc"},
    ]

    grouped = build_risk_group_summary(findings)

    assert [item["rule_id"] for item in grouped] == ["VSL-HOST-001", "VSL-VC-004", "VSL-VM-001"]
    assert grouped[0]["object_count"] == 2
    assert grouped[0]["sample_objects"] == ["h1", "h2"]


def test_current_customer_rule_catalog_has_no_unexecuted_groups() -> None:
    rules = [
        {"rule_id": "VSL-HOST-001", "rule_name": "Host connection", "enabled_in_current_run": True, "implementation_status": "implemented", "execution_mode": "default_enabled", "category": "host"},
        {"rule_id": "VSL-VM-001", "rule_name": "VM snapshot", "enabled_in_current_run": True, "implementation_status": "implemented", "execution_mode": "default_enabled", "category": "vm"},
    ]

    assert [execution_status(rule) for rule in rules] == [("executed", "已执行"), ("executed", "已执行")]
    assert rule_catalog_summary(rules) == {"total": 2, "executable": 2, "implemented": 2}


def test_mask_username() -> None:
    assert mask_username("administrator@vsphere.local") == "admi****@vsphere.local"
    assert mask_username("root") == "ro****"
    assert mask_username(None) == "未采集"
