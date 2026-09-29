from __future__ import annotations

from vstacklens.desktop.modules import inspection_capabilities, primary_modules


def test_desktop_primary_module_registry_matches_m3b_platform_tree() -> None:
    module_ids = [module.module_id for module in primary_modules()]

    assert module_ids == [
        "dashboard",
        "vcenter_management",
        "inspection_center",
        "log_analysis",
        "upgrade_compat",
        "risk_center",
        "asset_center",
        "history_compare",
        "report_center",
        "settings",
        "license",
    ]


def test_specialty_domains_are_not_primary_modules() -> None:
    module_ids = {module.module_id for module in primary_modules()}

    assert {"performance", "capacity", "network", "storage", "security", "backup"}.isdisjoint(module_ids)


def test_log_analysis_is_primary_module_but_not_vcenter_inspection_capability() -> None:
    modules = {module.module_id: module for module in primary_modules()}
    capabilities = {capability.capability_id for capability in inspection_capabilities()}

    assert modules["log_analysis"].module_name == "日志分析"
    assert "support bundle" in modules["log_analysis"].description
    assert "log_analysis" not in capabilities


def test_upgrade_compat_is_adjacent_to_log_analysis() -> None:
    module_ids = [module.module_id for module in primary_modules()]
    assert module_ids.index("upgrade_compat") == module_ids.index("log_analysis") + 1


def test_data_center_modules_are_scoped_to_local_inspection_records() -> None:
    modules = {module.module_id: module.description for module in primary_modules()}

    assert "已完成巡检记录" in modules["vcenter_management"]
    assert "当前巡检结果" in modules["risk_center"]
    assert "最新巡检资产快照" in modules["asset_center"]
    assert "本机 SQLite" in modules["history_compare"]


def test_inspection_center_capabilities_expose_real_and_planned_boundaries() -> None:
    capabilities = {capability.capability_id: capability for capability in inspection_capabilities()}

    assert capabilities["virtual_health"].status == "enabled"
    assert capabilities["batch_assessment"].status == "planned"
    assert capabilities["scheduled_assessment"].status == "planned"
    assert capabilities["report_export"].status == "enabled"
    assert capabilities["report_export"].capability_name == "Word 报告导出"
    assert "pdf_ppt_export" not in capabilities
