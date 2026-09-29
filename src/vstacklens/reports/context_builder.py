from __future__ import annotations

import json
import re
import sqlite3
from collections import Counter, defaultdict
from typing import Any

from vstacklens.db.repositories import actionable_risk_total, calculate_health_score_breakdown
from vstacklens.reports.presentation import (
    build_health_impact_summary,
    build_risk_category_summary,
    build_risk_object_summary,
    build_risk_group_summary,
    execution_status,
    mask_username,
    object_type_label,
    risk_sort_key,
    rule_catalog_summary,
    rule_category_label,
    unexecuted_reason,
)
from vstacklens.reports.history_compare import HistoryComparisonBuilder
from vstacklens.reports.category_mapping import CATEGORY_DEFINITIONS, map_findings_to_categories

OWNER_ROLE_LABELS = {
    "virtualization_admin": "虚拟化管理员",
    "storage_admin": "存储管理员",
    "network_admin": "网络管理员",
    "security_admin": "安全管理员",
    "backup_admin": "备份管理员",
}

EFFORT_LABELS = {"low": "低", "medium": "中", "high": "高"}

VERIFICATION_LABELS = {
    "rerun_rule": "复跑巡检确认",
    "manual_check": "人工复核",
    "command_check": "命令或工具复核",
}

DATA_QUALITY_LABELS = {
    "complete": "数据完整",
    "missing": "数据缺失",
    "permission_denied": "权限不足",
    "api_error": "采集失败",
    "not_applicable": "不适用",
}

VALUE_LABELS = {
    "True": "启用",
    "False": "未启用",
    "true": "启用",
    "false": "未启用",
    "enabled": "启用",
    "disabled": "未启用",
    "connected": "已连接",
    "disconnected": "已断开",
    "notResponding": "无响应",
    "poweredOn": "开机",
    "poweredOff": "关机",
    "suspended": "挂起",
    "lockdownDisabled": "未启用",
    "lockdownNormal": "普通锁定模式",
    "lockdownStrict": "严格锁定模式",
    "fullyAutomated": "全自动",
    "manual": "手动",
    "none": "不执行隔离动作",
    "leavePoweredOn": "保持开机",
    "powerOff": "关闭电源",
    "shutdown": "关闭客户机",
}

FEATURE_STATE_RULE_IDS = {
    "VSL-CL-001",
    "VSL-CL-002",
    "VSL-CL-007",
    "VSL-HOST-002",
    "VSL-HOST-004",
    "VSL-HOST-016",
    "VSL-HOST-014",
    "VSL-HOST-015",
    "VSL-VM-014",
}

NORMAL_ABNORMAL_RULE_IDS = {"VSL-VM-017", "VSL-DS-018", "VSL-VM-013"}

CERTIFICATE_LICENSE_RULE_IDS = {"VSL-VC-005", "VSL-VC-006", "VSL-HOST-008", "VSL-HOST-023"}

COUNT_VALUE_RULES = {
    "VSL-CL-016": ("缺少 vMotion 网络的主机", "台"),
    "VSL-NET-006": ("vMotion VMkernel 网卡", "个"),
    "VSL-VM-016": ("异常网络连接", "个"),
    "VSL-VM-021": ("直通或宿主机设备", "个"),
    "VSL-CL-010": ("CPU 型号", "种"),
    "VSL-CL-012": ("停用 DRS 规则", "条"),
    "VSL-DS-007": ("异常存储路径", "条"),
    "VSL-DS-008": ("活动存储路径", "条"),
    "VSL-VM-007": ("快照链深度", "层"),
    "VSL-VM-009": ("非持久化磁盘", "块"),
    "VSL-SEC-002": ("管理员权限主体", "个"),
    "VSL-VC-015": ("运行中或排队任务", "个"),
    "VSL-NET-003": ("物理网卡错误或丢包计数", "次"),
    "VSL-SEC-008": ("管理员级继承权限主体", "个"),
    "VSL-NET-015": ("端口组、vSwitch 或 vDS 安全策略项", "项"),
    "VSL-HOST-024": ("硬件健康异常组件", "项"),
}

FIELD_VALUE_HINTS = {
    "evc_enabled": ("feature", ""),
    "orphaned_or_inaccessible": ("normal_abnormal", ""),
    "invalid_network_count": ("finding_count", "异常网络连接"),
    "passthrough_device_count": ("finding_count", "直通或宿主机设备"),
    "cluster_vmotion_missing_host_count": ("finding_count_with_unit", "缺少 vMotion 网络的主机|台"),
    "vmotion_enabled_host_count": ("count_with_unit", "台"),
    "host_count": ("count_with_unit", "台"),
    "maintenance_host_count": ("count_with_unit", "台"),
    "ha_heartbeat_datastore_count": ("count_with_unit", "个"),
    "pnic_down_count": ("count_with_unit", "个"),
    "pnic_degraded_count": ("count_with_unit", "个"),
    "physical_nic_link_issue_count": ("count_with_unit", "个"),
    "storage_path_dead_count": ("count_with_unit", "条"),
    "vswitch_uplink_issue_count": ("count_with_unit", "条"),
    "vmotion_vmk_count": ("count_with_unit", "个"),
    "vcpu_count": ("count_with_unit", "个 vCPU"),
    "threshold": ("count_with_unit", "个"),
    "cpu_ready_percent": ("cpu_ready_percent", ""),
    "cpu_usage_avg": ("percent", ""),
    "cluster_cpu_usage_avg": ("percent", ""),
    "cpu_usage_percent": ("percent", ""),
    "memory_usage_avg": ("percent", ""),
    "cluster_memory_usage_avg": ("percent", ""),
    "memory_usage_percent": ("percent", ""),
    "hardware_version_number": ("version_number", ""),
    "expected_min_version": ("version_number", ""),
    "red_alarm_count": ("count_with_unit", "条告警"),
    "active_red_alarm_count": ("count_with_unit", "条告警"),
    "host_cpu_model_distinct_count": ("count_with_unit", "种"),
    "host_memory_capacity_skew_ratio": ("percent", ""),
    "max_memory_skew_ratio": ("percent", ""),
    "drs_disabled_rule_count": ("count_with_unit", "条"),
    "syslog_configured": ("feature", ""),
    "firewall_default_incoming_blocked": ("feature", ""),
    "datastore_multipath_issue_count": ("count_with_unit", "条"),
    "datastore_active_path_count": ("count_with_unit", "条"),
    "datastore_total_path_count": ("count_with_unit", "条"),
    "thin_provisioning_overcommit_ratio": ("percent", ""),
    "max_thin_overcommit_ratio": ("percent", ""),
    "datastore_filesystem_legacy": ("normal_abnormal", ""),
    "snapshot_chain_depth": ("count_with_unit", "层"),
    "max_snapshot_chain_depth": ("count_with_unit", "层"),
    "nonpersistent_disk_count": ("count_with_unit", "块"),
    "numa_affinity_configured": ("normal_abnormal", ""),
    "vmware_tools_installed": ("feature", ""),
    "vcenter_admin_account_count": ("count_with_unit", "个"),
    "max_vcenter_admin_accounts": ("count_with_unit", "个"),
    "task_backlog_count": ("count_with_unit", "个任务"),
    "max_task_backlog_count": ("count_with_unit", "个任务"),
    "host_certificate_days_remaining": ("days_remaining", ""),
    "host_certificate_warning_days": ("count_with_unit", "天"),
    "host_certificate_critical_days": ("count_with_unit", "天"),
    "host_license_assigned": ("assigned", ""),
    "host_license_is_evaluation": ("evaluation", ""),
    "host_license_expiration_days": ("license_days", ""),
    "host_log_core_dump_configured": ("complete_incomplete", ""),
    "pnic_error_count": ("count_with_unit", "次"),
    "max_pnic_error_count": ("count_with_unit", "次"),
    "powered_off_days": ("count_with_unit", "天"),
    "max_powered_off_days": ("count_with_unit", "天"),
    "role_permission_inheritance_issue_count": ("count_with_unit", "个"),
    "max_inherited_admin_permissions": ("count_with_unit", "个"),
    "portgroup_security_issue_count": ("count_with_unit", "项"),
    "portgroup_security_high_risk_count": ("count_with_unit", "项"),
    "host_hardware_health_issue_count": ("count_with_unit", "项"),
    "host_hardware_health_red_count": ("count_with_unit", "项"),
    "host_power_policy_high_performance": ("feature", ""),
    "host_pcpu_count": ("count_with_unit", "个 pCPU"),
    "host_memory_capacity_mb": ("mb_as_gb", ""),
    "host_vcpu_allocated": ("count_with_unit", "个 vCPU"),
    "host_memory_allocated_mb": ("mb_as_gb", ""),
    "host_vcpu_to_pcpu_ratio": ("ratio", ""),
    "host_memory_allocation_ratio": ("ratio_percent", ""),
    "host_resource_overcommit": ("normal_abnormal", ""),
    "datastore_capacity_gb": ("gb", ""),
    "datastore_free_gb": ("gb", ""),
    "datastore_used_gb": ("gb", ""),
    "datastore_used_percent": ("percent", ""),
    "used_percent": ("percent", ""),
    "capacity_used_percent": ("percent", ""),
    "snapshot_size_gb": ("gb", ""),
    "disk_size_gb": ("gb", ""),
    "datastore_is_vsan": ("yes_no", ""),
    "datastore_is_local": ("yes_no", ""),
    "datastore_host_count": ("count_with_unit", "台"),
    "datastore_cluster_count": ("count_with_unit", "个"),
    "datastore_cross_cluster_shared": ("normal_abnormal", ""),
    "vsan_api_status": ("collection_status", ""),
    "vsan_issue_count": ("count_with_unit", "项"),
    "vsan_health_issue_count": ("count_with_unit", "项"),
    "vsan_disk_health_issue_count": ("count_with_unit", "项"),
    "vsan_object_health_issue_count": ("count_with_unit", "项"),
    "vsan_resync_object_count": ("count_with_unit", "个"),
    "vsan_resync_bytes": ("bytes_as_gb", ""),
    "vsan_used_percent": ("percent", ""),
    "vsan_free_gb": ("gb", ""),
    "swap_or_balloon_mb": ("mb", ""),
    "ballooned_memory_mb": ("mb", ""),
    "swapped_memory_mb": ("mb", ""),
    "snapshot_age_days": ("count_with_unit", "天"),
    "snapshot_age_days_max": ("count_with_unit", "天"),
    "certificate_days_remaining": ("days_remaining", ""),
    "days_remaining": ("count_with_unit", "天"),
    "age_days": ("count_with_unit", "天"),
    "object_count": ("count_with_unit", "个"),
    "issue_count": ("count_with_unit", "项"),
    "latency_ms": ("ms", ""),
    "response_time_ms": ("ms", ""),
    "throughput_mbps": ("mbps", ""),
    "iops": ("iops", ""),
    "vsan_capacity_issue": ("normal_abnormal", ""),
    "vsan_cluster_enabled": ("feature", ""),
    "vm_on_local_datastore": ("normal_abnormal", ""),
    "guest_os_tools_running": ("feature", ""),
    "guest_os_mismatch": ("normal_abnormal", ""),
    "is_system_vm": ("yes_no", ""),
}

DETAIL_LABELS = {
    "current_value": "当前值",
    "expected_value": "建议状态",
    "cluster_name": "集群",
    "host_name": "主机",
    "vm_name": "虚拟机",
    "host_count": "主机总数",
    "vmotion_enabled_host_count": "已配置 vMotion 主机数",
    "cluster_vmotion_missing_host_count": "缺少 vMotion 主机数",
    "missing_vmotion_hosts": "缺少 vMotion 的主机",
    "evc_enabled": "EVC 状态",
    "evc_mode": "EVC 模式",
    "host_cpu_models": "主机 CPU 型号",
    "ha_heartbeat_datastore_count": "HA 心跳数据存储数量",
    "heartbeat_datastore_names": "HA 心跳数据存储",
    "maintenance_host_count": "维护模式主机数",
    "maintenance_hosts": "维护模式主机",
    "pnic_down_count": "断开物理网卡数",
    "pnic_degraded_count": "降级物理网卡数",
    "physical_nic_link_issue_count": "链路异常网卡数",
    "affected_nics": "受影响物理网卡",
    "link_speed_detail": "链路速率详情",
    "storage_path_dead_count": "异常存储路径数",
    "affected_storage_paths": "受影响存储路径",
    "vswitch_uplink_issue_count": "上行链路异常数",
    "affected_switches": "受影响交换机",
    "affected_uplinks": "受影响上行链路",
    "vmotion_vmk_count": "vMotion VMkernel 网卡数",
    "vmkernel_adapters": "VMkernel 网卡",
    "vcpu_count": "vCPU 数量",
    "threshold": "阈值",
    "power_state": "电源状态",
    "cpu_ready_percent": "CPU Ready",
    "hardware_version": "虚拟硬件版本",
    "hardware_version_number": "虚拟硬件版本号",
    "expected_min_version": "建议最低版本",
    "expected_policy": "建议基线",
    "expected_min_count": "建议最小数量",
    "expected_link_state": "建议链路状态",
    "expected_path_state": "建议路径状态",
    "expected_service": "建议服务配置",
    "red_alarm_count": "红色活动告警数",
    "active_red_alarms": "红色活动告警",
    "alarm_name": "告警名称",
    "entity_name": "告警对象",
    "status": "状态",
    "host_cpu_model_distinct_count": "CPU 型号数量",
    "host_memory_capacity_skew_ratio": "内存容量差异比例",
    "host_memory_capacity_gb_values": "主机内存容量",
    "max_memory_skew_ratio": "建议差异阈值",
    "drs_disabled_rule_count": "停用 DRS 规则数量",
    "drs_disabled_rules": "停用 DRS 规则",
    "syslog_configured": "Syslog 配置状态",
    "syslog_targets": "Syslog 目标",
    "firewall_default_incoming_blocked": "防火墙默认入站策略",
    "datastore_name": "数据存储",
    "datastore_multipath_issue_count": "异常存储路径数量",
    "datastore_path_issue_detail": "异常存储路径详情",
    "datastore_active_path_count": "活动路径数量",
    "datastore_total_path_count": "总路径数量",
    "min_datastore_active_paths": "建议活动路径数量",
    "thin_provisioning_overcommit_ratio": "Thin Provisioning 超分比例",
    "max_thin_overcommit_ratio": "建议超分阈值",
    "datastore_filesystem_type": "文件系统类型",
    "datastore_filesystem_version": "文件系统版本",
    "snapshot_chain_depth": "快照链深度",
    "max_snapshot_chain_depth": "建议最大快照链深度",
    "nonpersistent_disk_count": "非持久化磁盘数量",
    "disk_provisioning_modes": "磁盘置备模式",
    "numa_affinity_configured": "NUMA 亲和配置",
    "numa_affinity_nodes": "NUMA 节点",
    "vmware_tools_installed": "VMware Tools 安装状态",
    "tools_install_status": "Tools 状态",
    "vcenter_admin_account_count": "管理员权限主体数量",
    "vcenter_admin_principals": "管理员权限主体",
    "max_vcenter_admin_accounts": "建议管理员主体数量",
    "task_backlog_count": "任务积压数量",
    "task_backlog_items": "任务积压详情",
    "max_task_backlog_count": "建议任务积压阈值",
    "host_certificate_days_remaining": "证书剩余有效期",
    "host_certificate_not_after": "证书到期时间",
    "host_certificate_subject": "证书主体",
    "host_certificate_issuer": "证书签发者",
    "host_certificate_not_before": "证书生效时间",
    "host_certificate_san": "证书 SAN",
    "host_certificate_fingerprint": "证书指纹",
    "host_certificate_probe_method": "证书探测方式",
    "host_certificate_probe_status": "证书字段探测结果",
    "host_certificate_warning_days": "证书预警阈值",
    "host_license_assigned": "授权分配状态",
    "host_license_name": "授权名称",
    "host_license_edition": "授权版本",
    "host_license_is_evaluation": "评估版状态",
    "host_license_expiration_date": "授权到期时间",
    "host_license_expiration_days": "授权剩余有效期",
    "host_license_probe_status": "授权字段探测结果",
    "host_log_core_dump_configured": "日志与核心转储配置",
    "host_log_core_dump_detail": "日志与核心转储详情",
    "pnic_error_count": "物理网卡错误或丢包计数",
    "pnic_error_detail": "物理网卡错误计数详情",
    "max_pnic_error_count": "建议错误计数阈值",
    "powered_off_days": "关机持续时间",
    "max_powered_off_days": "建议最大关机持续时间",
    "role_permission_inheritance_issue_count": "管理员级继承权限主体数量",
    "role_permission_inheritance_issues": "管理员级继承权限详情",
    "max_inherited_admin_permissions": "建议继承权限主体阈值",
    "portgroup_security_issue_count": "安全策略命中数量",
    "portgroup_security_high_risk_count": "高风险策略命中数量",
    "portgroup_security_issues": "安全策略命中详情",
    "host_hardware_health_issue_count": "硬件健康异常数量",
    "host_hardware_health_red_count": "红色硬件健康数量",
    "host_hardware_health_issues": "硬件健康异常详情",
    "host_power_policy": "当前电源策略",
    "host_power_policy_high_performance": "高性能策略状态",
    "host_pcpu_count": "物理 CPU 核数",
    "host_memory_capacity_mb": "物理内存容量",
    "host_vcpu_allocated": "已分配 vCPU 数量",
    "host_memory_allocated_mb": "已分配内存",
    "host_vcpu_to_pcpu_ratio": "vCPU:pCPU 比例",
    "host_memory_allocation_ratio": "内存分配比例",
    "host_resource_overcommit": "资源分配状态",
    "datastore_type": "Datastore 类型",
    "datastore_capacity_gb": "总容量",
    "datastore_free_gb": "剩余容量",
    "datastore_used_gb": "已用容量",
    "datastore_is_vsan": "vSAN Datastore",
    "datastore_is_local": "本地 Datastore",
    "datastore_host_names": "关联主机",
    "datastore_host_count": "关联主机数",
    "datastore_cluster_names": "关联集群",
    "datastore_cluster_count": "关联集群数",
    "datastore_cross_cluster_shared": "跨集群共享状态",
    "datastore_cluster_collector_source": "采集来源",
    "local_datastore_collector_source": "采集来源",
    "vsan_api_status": "vSAN API 采集状态",
    "vsan_collection_error": "vSAN 采集说明",
    "vsan_cluster_enabled": "vSAN 集群状态",
    "vsan_cluster_names": "vSAN 关联集群",
    "vsan_issue_count": "vSAN 关注项数量",
    "vsan_health_issue_count": "vSAN 健康异常数量",
    "vsan_disk_health_issue_count": "vSAN 磁盘异常数量",
    "vsan_object_health_issue_count": "vSAN 对象异常数量",
    "vsan_resync_object_count": "vSAN 重同步对象数",
    "vsan_resync_bytes": "vSAN 待同步数据量",
    "vsan_health_issues": "vSAN 健康异常详情",
    "vsan_disk_health_issues": "vSAN 磁盘异常详情",
    "vsan_object_health_issues": "vSAN 对象异常详情",
    "vsan_collector_source": "采集来源",
    "vsan_used_percent": "vSAN 已用率",
    "vsan_free_gb": "vSAN 剩余容量",
    "vsan_capacity_issue": "vSAN 容量状态",
    "datastore_names": "Datastore",
    "local_datastore_names": "本地 Datastore",
    "vm_on_local_datastore": "本地存储运行状态",
    "guest_os_actual": "实际操作系统",
    "guest_os_configured": "配置操作系统",
    "guest_os_tools_running": "VMware Tools 运行状态",
    "guest_os_mismatch": "操作系统配置状态",
    "guest_os_collector_source": "采集来源",
    "portgroup_security_collector_source": "采集来源",
    "hardware_health_collector_source": "采集来源",
    "power_policy_collector_source": "采集来源",
    "host_resource_collector_source": "采集来源",
    "recommended_policy": "建议",
    "recommended_value": "建议值",
    "scope": "范围",
    "switch": "交换机/vDS",
    "portgroup": "端口组",
    "policy": "策略项",
    "component": "组件",
    "summary": "摘要",
    "is_system_vm": "系统默认虚拟机",
    "principal": "授权主体",
    "role": "角色",
    "counter": "计数器",
    "value": "数值",
    "name": "名称",
    "entity": "对象",
    "state": "状态",
    "host": "主机",
    "adapter": "适配器",
    "lun": "LUN",
    "target": "目标端口",
}


class ReportContextBuilder:
    def build(self, conn: sqlite3.Connection, run_id: str, comparison: dict[str, Any] | None = None) -> dict:
        run = conn.execute("SELECT * FROM inspection_runs WHERE run_id = ?", (run_id,)).fetchone()
        customer = conn.execute(
            """
            SELECT c.customer_name, s.site_name, v.name AS vcenter_name, v.host AS vcenter_host, v.username AS vcenter_username
            FROM inspection_runs r
            JOIN customers c ON c.customer_id = r.customer_id
            JOIN sites s ON s.site_id = r.site_id
            JOIN vcenters v ON v.vcenter_id = r.vcenter_id
            WHERE r.run_id = ?
            """,
            (run_id,),
        ).fetchone()
        objects = conn.execute("SELECT object_type, COUNT(*) c FROM inventory_objects WHERE run_id = ? GROUP BY object_type", (run_id,)).fetchall()
        inventory_objects = conn.execute(
            """
            SELECT object_type, object_key, object_name, path, properties_json
            FROM inventory_objects
            WHERE run_id = ?
            ORDER BY object_type, object_name
            """,
            (run_id,),
        ).fetchall()
        findings = conn.execute(
            """
            SELECT f.*, rr.observed_value, rr.expected_value, rr.evidence_json, rr.raw_json, rr.evaluated_at, rr.object_path, r.rule_name, r.definition_json
            FROM findings f
            JOIN rule_results rr ON rr.result_id = f.latest_result_id
            LEFT JOIN rules r ON r.rule_id = f.rule_id
            WHERE f.last_seen_run_id = ? AND f.status != 'exception'
            ORDER BY f.risk_level, f.rule_id, f.object_name
            """,
            (run_id,),
        ).fetchall()
        exception_findings = conn.execute(
            """
            SELECT f.*, rr.observed_value, rr.expected_value, rr.evidence_json, rr.raw_json, rr.evaluated_at, rr.object_path, r.rule_name, r.definition_json
            FROM findings f
            JOIN rule_results rr ON rr.result_id = f.latest_result_id
            LEFT JOIN rules r ON r.rule_id = f.rule_id
            WHERE f.last_seen_run_id = ? AND f.status = 'exception'
            ORDER BY f.risk_level, f.rule_id, f.object_name
            """,
            (run_id,),
        ).fetchall()
        unavailable = conn.execute(
            """
            SELECT rr.*, r.rule_name, r.definition_json
            FROM rule_results rr
            LEFT JOIN rules r ON r.rule_id = rr.rule_id
            WHERE rr.run_id = ? AND rr.result_status = 'unavailable'
            ORDER BY rr.rule_id, rr.object_type, rr.object_name
            """,
            (run_id,),
        ).fetchall()
        not_applicable = conn.execute(
            """
            SELECT rr.rule_id, rr.object_type, COUNT(*) c, r.rule_name
            FROM rule_results rr
            LEFT JOIN rules r ON r.rule_id = rr.rule_id
            WHERE rr.run_id = ? AND rr.result_status = 'not_applicable'
            GROUP BY rr.rule_id, rr.object_type, r.rule_name
            ORDER BY rr.rule_id
            """,
            (run_id,),
        ).fetchall()
        object_results = conn.execute(
            """
            SELECT rr.*, r.rule_name, r.definition_json
            FROM rule_results rr
            LEFT JOIN rules r ON r.rule_id = rr.rule_id
            WHERE rr.run_id = ?
            ORDER BY rr.object_type, rr.object_name, rr.rule_id
            """,
            (run_id,),
        ).fetchall()
        rules = conn.execute(
            """
            SELECT DISTINCT r.rule_id, r.rule_name, r.category, r.object_type,
                   r.risk_level, r.confidence_level, r.definition_json
            FROM rule_results rr
            JOIN rules r ON r.rule_id = rr.rule_id
            WHERE rr.run_id = ?
            ORDER BY r.rule_id
            """,
            (run_id,),
        ).fetchall()
        result_status_summary = conn.execute(
            "SELECT result_status, COUNT(*) c FROM rule_results WHERE run_id = ? GROUP BY result_status",
            (run_id,),
        ).fetchall()
        rule_checklist = conn.execute(
            """
            SELECT rr.rule_id, r.rule_name, r.definition_json, rr.result_status, COUNT(*) c
            FROM rule_results rr
            LEFT JOIN rules r ON r.rule_id = rr.rule_id
            WHERE rr.run_id = ?
            GROUP BY rr.rule_id, r.rule_name, r.definition_json, rr.result_status
            ORDER BY rr.rule_id, rr.result_status
            """,
            (run_id,),
        ).fetchall()
        findings_list = [self._finding_row(row) for row in findings]
        exception_list = [self._finding_row(row) for row in exception_findings]
        exception_list = sorted(exception_list, key=risk_sort_key)
        unavailable_list = [self._rule_result_row(row) for row in unavailable]
        asset_summary = {row["object_type"]: row["c"] for row in objects}
        object_result_list = [self._object_result_row(row) for row in object_results]
        certificate_license_evidence = self._certificate_license_evidence(object_result_list)
        status_summary = self._status_summary(result_status_summary)
        rule_catalog = [self._rule_catalog_row(row) for row in rules]
        scope = dict(customer) if customer else {}
        vcenter_info = self._vcenter_info(scope, inventory_objects)
        vsan_summary = self._vsan_summary(inventory_objects)
        vsan_categories, vsan_findings, vsan_mapping = self._vsan_report_semantics(vsan_summary)
        findings_list.extend(vsan_findings)
        findings_list = sorted(findings_list, key=risk_sort_key)
        risk_summary = self._risk_summary(findings_list)
        risk_object_summary = build_risk_object_summary(findings_list)
        health_impact_summary = build_health_impact_summary(findings_list)
        score_breakdown = self._score_breakdown(findings_list)
        # 当前报告的 run_id 是 vCenter 环境范围锚点：即使没有上一轮记录，
        # 历史对比也只在该 run_id 所属 vcenter_id 内查找，不会借用其它环境的数据。
        history_comparison = HistoryComparisonBuilder().build(
            conn,
            (comparison or {}).get("previous_run_id") if comparison else None,
            run_id,
        )
        return {
            "run": dict(run) if run else {},
            "scope": scope,
            "environment_info": vcenter_info,
            "asset_summary": asset_summary,
            "asset_details": self._asset_details(inventory_objects, vcenter_info.get("vcenter_address") or vcenter_info.get("vcenter_name")),
            "asset_total": sum(asset_summary.values()),
            "risk_category_summary": risk_summary,
            "risk_object_summary": risk_object_summary,
            "health_impact_summary": health_impact_summary,
            "vsan_summary": {**vsan_summary, "report_categories": vsan_categories},
            "report_presentation": {
                "problem_categories": vsan_mapping.categories,
                "risk_category_summary": vsan_mapping.risk_category_summary,
                "affected_object_summary": vsan_mapping.affected_object_summary,
            },
            "findings": findings_list,
            "exception_findings": exception_list,
            "remediation_tracking": comparison or self._empty_comparison(run_id),
            "history_comparison": history_comparison,
            "risk_group_summary": build_risk_group_summary(findings_list),
            "object_results": object_result_list,
            "object_pass_rate": self._object_pass_rate(object_result_list),
            "rule_pass_rate": self._rule_pass_rate(object_result_list),
            "module_summary": self._module_summary(object_result_list),
            "risk_summary": risk_summary,
            "risk_total": actionable_risk_total(risk_summary),
            "optimization_total": int(risk_summary.get("P4", 0) or 0),
            "score_breakdown": score_breakdown,
            "result_status_summary": status_summary,
            "unavailable_results": unavailable_list,
            "not_applicable_summary": [dict(row) for row in not_applicable],
            "certificate_license_evidence": certificate_license_evidence,
            "rule_catalog": rule_catalog,
            "rule_catalog_summary": self._rule_catalog_summary(rule_catalog),
            "remediation_plan": self._remediation_plan(findings_list),
            "top_risks": findings_list[:10],
            "rule_checklist": self._rule_checklist(rule_checklist),
            "executive_summary": self._executive_summary(dict(run) if run else {}, risk_summary, asset_summary, status_summary),
        }

    def _empty_comparison(self, run_id: str) -> dict[str, Any]:
        return {
            "previous_run_id": "",
            "current_run_id": run_id,
            "previous_run": {},
            "current_run": {},
            "previous_score": None,
            "current_score": None,
            "score_delta": None,
            "summary": {"new": 0, "existing": 0, "resolved": 0, "reopened": 0, "exception": 0},
            "new_findings": [],
            "existing_findings": [],
            "resolved_findings": [],
            "reopened_findings": [],
            "exception_findings": [],
        }

    def _risk_summary(self, findings: list[dict[str, Any]]) -> dict:
        return build_risk_category_summary(findings)

    def _score_breakdown(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        grouped: dict[tuple[str, str], int] = defaultdict(int)
        for item in findings:
            grouped[(item.get("rule_id", ""), item.get("risk_level", ""))] += 1
        return calculate_health_score_breakdown(
            [
                {"rule_id": rule_id, "risk_level": risk_level, "c": count}
                for (rule_id, risk_level), count in grouped.items()
            ],
            apply_legacy_caps=False,
        )

    def _vsan_summary(self, inventory_rows: list[sqlite3.Row]) -> dict[str, Any]:
        """Aggregate vSAN evidence once for HTML, Word and dashboard consumers."""

        records: list[dict[str, Any]] = []
        for row in inventory_rows:
            properties = self._json(row["properties_json"])
            if isinstance(properties.get("properties"), dict):
                properties = properties["properties"]
            if not properties.get("datastore_is_vsan") and not properties.get("vsan_cluster_enabled") and not properties.get("vsan_api_status") and not properties.get("vsan_enabled"):
                continue
            records.append({"object_name": row["object_name"], "object_type": row["object_type"], **properties})
        if not records or not any(item.get("datastore_is_vsan") for item in records):
            return {"status": "not_applicable", "architecture": None, "clusters": [], "host_count": 0, "disk_group_count": None, "cache_disk_count": None, "capacity_disk_count": None, "object_count": None, "vmdk_count": None, "policy_noncompliant_count": None, "resync_object_count": None, "resync_bytes": None, "network": {"status": "unknown", "vmkernels": []}, "capacity": {"status": "unknown", "used_percent": None, "thresholds": {"normal_lt": 75, "attention_lt": 80, "high_gte": 80}}}
        cluster_names = sorted({name for item in records for name in (item.get("vsan_cluster_names") or []) if name})
        vsan_items = [item for item in records if item.get("datastore_is_vsan")]
        vsan_host_names = {
            str(name)
            for item in vsan_items
            for name in (item.get("datastore_host_names") or [])
            if name
        }
        statuses = [str(item.get("vsan_api_status") or "not_collected") for item in vsan_items]
        status = "unavailable" if any(value in {"unavailable", "api_error", "permission_denied", "unsupported"} for value in statuses) else "collected" if any(value == "collected" for value in statuses) else "unknown"
        health_issues = [issue for item in vsan_items for issue in (item.get("vsan_health_issues") or [])]
        disk_issues = [issue for item in vsan_items for issue in (item.get("vsan_disk_health_issues") or [])]
        object_issues = [issue for item in vsan_items for issue in (item.get("vsan_object_health_issues") or [])]
        used_values = [item.get("vsan_used_percent") for item in vsan_items if isinstance(item.get("vsan_used_percent"), (int, float))]
        used = max(used_values) if used_values else None
        capacity_status = "unknown" if used is None else "high" if used >= 80 else "attention" if used >= 75 else "normal"
        architecture = next((item.get("vsan_architecture") for item in vsan_items if item.get("vsan_architecture")), None)
        vmkernels: list[dict[str, Any]] = []
        network_cross_validation = {"path_count": 2, "checked": 0, "recovered_labels": 0, "mismatches": 0}
        for item in records:
            if item.get("object_type") != "HostSystem" or (vsan_host_names and str(item.get("object_name") or "") not in vsan_host_names):
                continue
            host_name = str(item.get("object_name") or "")
            primary = [dict(adapter) for adapter in item.get("vmkernel_adapters") or [] if isinstance(adapter, dict)]
            secondary = [dict(adapter) for adapter in item.get("vsan_vmk_adapters") or [] if isinstance(adapter, dict)]
            secondary_by_device = {str(adapter.get("device") or ""): adapter for adapter in secondary if adapter.get("device")}
            if primary:
                for adapter in primary:
                    device = str(adapter.get("device") or "")
                    counterpart = secondary_by_device.get(device)
                    if counterpart:
                        network_cross_validation["checked"] += 1
                        primary_label = str(adapter.get("network_label") or adapter.get("portgroup") or "").strip()
                        secondary_label = str(counterpart.get("network_label") or counterpart.get("portgroup") or "").strip()
                        if not primary_label and secondary_label:
                            adapter["network_label"] = secondary_label
                            adapter["portgroup"] = counterpart.get("portgroup") or secondary_label
                            network_cross_validation["recovered_labels"] += 1
                        elif primary_label and secondary_label and primary_label != secondary_label:
                            network_cross_validation["mismatches"] += 1
                    vmkernels.append({"host_name": host_name, **adapter})
            else:
                vmkernels.extend({"host_name": host_name, **adapter} for adapter in secondary)
        physical_disk_values = [item.get("vsan_physical_disks") for item in vsan_items]
        physical_disks = (
            None
            if not physical_disk_values or any(value is None for value in physical_disk_values)
            else [disk for disks in physical_disk_values for disk in (disks or [])]
        )
        topology = [entry for item in vsan_items for entry in (item.get("vsan_disk_topology") or [])]
        disk_details = self._vsan_disk_details(topology, physical_disks)
        storage_policy_summary = next((item.get("storage_policy_summary") for item in vsan_items if item.get("storage_policy_summary")), {})
        total_gb = None
        used_gb = None
        free_gb = None
        for item in vsan_items:
            native = item.get("vsan_native_capacity") or item.get("native_capacity") or {}
            native_total = native.get("total_capacity_bytes") if isinstance(native, dict) else None
            native_used = native.get("used_capacity_bytes") if isinstance(native, dict) else None
            native_free = native.get("free_capacity_bytes") if isinstance(native, dict) else None
            if isinstance(native_total, (int, float)):
                total_gb = float(native_total) / (1024 ** 3)
                used_gb = float(native_used) / (1024 ** 3) if isinstance(native_used, (int, float)) else None
                free_gb = float(native_free) / (1024 ** 3) if isinstance(native_free, (int, float)) else None
                break
            if isinstance(item.get("datastore_capacity_gb"), (int, float)):
                total_gb = float(item["datastore_capacity_gb"])
                used_gb = float(item.get("datastore_used_gb")) if isinstance(item.get("datastore_used_gb"), (int, float)) else None
                free_gb = float(item.get("datastore_free_gb")) if isinstance(item.get("datastore_free_gb"), (int, float)) else None
                break
        vmkernel_status = "collected" if vmkernels else "unknown"
        return {
            "status": status,
            "architecture": architecture,
            "clusters": cluster_names,
            "host_count": len({name for item in vsan_items for name in (item.get("datastore_host_names") or []) if name}),
            "disk_group_count": self._sum_numeric(vsan_items, "vsan_disk_group_count"),
            "cache_disk_count": self._sum_numeric(vsan_items, "vsan_cache_disk_count"),
            "capacity_disk_count": self._sum_numeric(vsan_items, "vsan_capacity_disk_count"),
            "object_count": self._first_numeric(vsan_items, "vsan_object_count"),
            "vmdk_count": self._first_numeric(vsan_items, "vsan_vmdk_count"),
            "policy_noncompliant_count": self._first_numeric(vsan_items, "vsan_policy_noncompliant_count"),
            "resync_object_count": self._sum_numeric(vsan_items, "vsan_resync_object_count"),
            "resync_bytes": self._sum_numeric(vsan_items, "vsan_resync_bytes"),
            "health_issue_count": None if not vsan_items or any(item.get("vsan_health_issues") is None for item in vsan_items) else len(health_issues),
            "disk_issue_count": None if not vsan_items or any(item.get("vsan_disk_health_issues") is None for item in vsan_items) else len(disk_issues),
            "object_issue_count": None if not vsan_items or any(item.get("vsan_object_health_issues") is None for item in vsan_items) else len(object_issues),
            "health_issues": health_issues[:50],
            "disk_issues": disk_issues[:50],
            "object_issues": object_issues[:50],
            "physical_disks": physical_disks,
            "disk_topology": topology,
            "disk_details": disk_details,
            "storage_policy_summary": storage_policy_summary,
            "network": {"status": vmkernel_status, "vmkernels": vmkernels[:100], "cross_validation": network_cross_validation},
            "capacity": {
                "status": capacity_status,
                "used_percent": used,
                "total_gb": total_gb,
                "used_gb": used_gb,
                "free_gb": free_gb,
                "thresholds": {"normal_lt": 75, "attention_lt": 80, "high_gte": 80},
            },
        }

    def _vsan_disk_details(self, topology: list[dict[str, Any]], physical_disks: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
        index: dict[tuple[str, str], dict[str, Any]] = {}
        for disk in physical_disks or []:
            host = str(disk.get("host") or "")
            for identity in (disk.get("name"), disk.get("scsi_device"), disk.get("uuid")):
                if identity:
                    index[(host, str(identity).casefold())] = disk
        rows: list[dict[str, Any]] = []
        for host_item in sorted(topology or [], key=lambda item: str(item.get("host") or "")):
            host = str(host_item.get("host") or "未记录")
            for group_number, group in enumerate(host_item.get("disk_groups") or [], start=1):
                group_name = f"磁盘组 {group_number}"
                devices = [("缓存盘", group.get("cache_disk")), *(('容量盘', item) for item in group.get("capacity_disks") or [])]
                for role, device in devices:
                    if not device:
                        continue
                    disk = index.get((host, str(device).casefold()))
                    values = [str((disk or {}).get(key) or "").casefold() for key in ("summary_health", "operational_health", "capacity_health")]
                    bad = {"red", "yellow", "error", "failed", "unhealthy", "offline", "absent", "lost", "degraded"}
                    health = "异常" if any(value in bad for value in values) else "正常" if disk and any(value in {"green", "healthy", "ok", "normal"} for value in values) else "未确认"
                    rows.append({"host": host, "disk_group": group_name, "role": role, "device": str(device), "health": health})
        return rows

    def _vsan_report_semantics(self, summary: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], Any]:
        categories: list[dict[str, Any]] = []
        candidate_findings: list[dict[str, Any]] = []
        applicable = summary.get("status") != "not_applicable"
        if not applicable:
            from vstacklens.reports.category_mapping import CategoryMappingResult
            return categories, candidate_findings, CategoryMappingResult()

        health_count = summary.get("health_issue_count")
        disk_count = summary.get("disk_issue_count")
        object_count = summary.get("object_count")
        object_issue_count = summary.get("object_issue_count")
        resync_count = summary.get("resync_object_count")
        resync_bytes = summary.get("resync_bytes")
        network_rows = (summary.get("network") or {}).get("vmkernels") or []
        network_missing = sum(
            1
            for item in network_rows
            if not item.get("ip_address")
            or str(item.get("network_label") or item.get("portgroup") or "").strip() in {"", "未记录", "未解析"}
        )
        capacity = summary.get("capacity") or {}
        policy = summary.get("storage_policy_summary") or {}
        policy_available = bool(policy.get("policy_categories")) or (
            isinstance(policy.get("checked_count"), (int, float)) and policy["checked_count"] > 0
        )
        disk_details = summary.get("disk_details") or []
        disks_confirmed = bool(disk_details) and all(item.get("health") == "正常" for item in disk_details)

        checks = [
            ("VSAN-CLUSTER-HEALTH", "需关注" if isinstance(health_count, (int, float)) and health_count > 0 else "正常" if health_count == 0 else "未确认", f"健康异常 {health_count if health_count is not None else '未采集'} 项"),
            ("VSAN-DISK", "需关注" if isinstance(disk_count, (int, float)) and disk_count > 0 else "正常" if disk_count == 0 and disks_confirmed else "未确认", f"磁盘异常 {disk_count if disk_count is not None else '未采集'} 项"),
            ("VSAN-OBJECT-HEALTH", "需关注" if isinstance(object_issue_count, (int, float)) and object_issue_count > 0 else "正常" if object_issue_count == 0 else "未确认", f"对象异常 {object_issue_count if object_issue_count is not None else '未采集'} 项"),
            ("VSAN-OBJECT-VMDK", "正常" if object_count is not None and summary.get("vmdk_count") is not None and object_issue_count == 0 else "需关注" if object_issue_count and object_issue_count > 0 else "未确认", f"Object {object_count if object_count is not None else '未采集'}；VMDK {summary.get('vmdk_count') if summary.get('vmdk_count') is not None else '未采集'}"),
            ("VSAN-RESYNC", "正常" if resync_count is not None and resync_bytes is not None else "未确认", f"重同步对象 {resync_count if resync_count is not None else '未采集'}；数据 {resync_bytes if resync_bytes is not None else '未采集'}"),
            ("VSAN-NETWORK", "正常" if network_rows and network_missing == 0 else "未确认", f"VMkernel {len(network_rows)} 条；缺字段 {network_missing} 条"),
            ("VSAN-CAPACITY", "需关注" if capacity.get("status") in {"attention", "high"} else "正常" if capacity.get("status") == "normal" else "未确认", f"使用率 {capacity.get('used_percent') if capacity.get('used_percent') is not None else '未采集'}%"),
            ("VSAN-POLICY", "需关注" if policy_available and (summary.get("policy_noncompliant_count") or 0) > 0 else "正常" if policy_available else "未确认", f"不合规 {summary.get('policy_noncompliant_count') if policy_available else '未采集'}"),
        ]
        for category_id, status, detail in checks:
            definition = CATEGORY_DEFINITIONS[category_id]
            categories.append({"category_id": category_id, "title": definition.title_zh, "risk_level": definition.priority, "status": status, "conclusion": detail})
            if status != "需关注":
                continue
            candidate_findings.append({
                "rule_id": definition.source_rule_ids[0],
                "rule_name": definition.title_zh,
                "title": definition.title_zh,
                "object_type": "vSAN",
                "object_name": (summary.get("clusters") or ["vSAN"])[0],
                "object_path": (summary.get("clusters") or ["vSAN"])[0],
                "status": "open",
                "current_value": detail,
                "current_value_zh": detail,
                "expected_value_zh": "正常",
                "risk_level": definition.priority,
                "category": "vSAN",
                "module_name": "vSAN",
                "health_impact": "attention",
                "evidence_summary_zh": detail,
                "business_impact": definition.potential_impact,
                "remediation": definition.remediation_zh,
                "recommended_action_zh": definition.remediation_zh,
                "owner_role": "",
                "remediation_effort": "",
                "maintenance_window_required": False,
                "verification_method": "",
                "remediation_steps": [],
                "observed_detail": {"vsan_category": category_id, "conclusion": detail},
            })
        mapping = map_findings_to_categories(candidate_findings, vsan_applicable=True)
        return categories, mapping.findings, mapping

    def _sum_numeric(self, records: list[dict[str, Any]], key: str) -> int | None:
        values = [item.get(key) for item in records]
        if not values or any(value is None for value in values):
            return None
        return sum(int(value or 0) for value in values)

    def _first_numeric(self, records: list[dict[str, Any]], key: str) -> int | None:
        for item in records:
            if isinstance(item.get(key), (int, float)):
                return int(item[key])
        return None

    def _status_summary(self, rows: list[sqlite3.Row]) -> dict[str, int]:
        summary = {"passed": 0, "failed": 0, "unavailable": 0, "not_applicable": 0, "error": 0}
        for row in rows:
            if row["result_status"] in summary:
                summary[row["result_status"]] = row["c"]
        return summary

    def _finding_row(self, row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        definition = self._json(item.pop("definition_json", None))
        evidence = self._json(item.pop("evidence_json", None))
        raw_evidence = self._json(item.pop("raw_json", None))
        report_fields = definition.get("report_fields", {})
        remediation = definition.get("remediation", {})
        evidence_schema = definition.get("evidence_schema", {})
        fallback_name = item.get("rule_name") or item["rule_id"]
        check_name = report_fields.get("check_name_zh") or report_fields.get("title_zh") or fallback_name
        finding_title = report_fields.get("finding_title_zh") or report_fields.get("title_zh") or fallback_name
        plain_summary = report_fields.get("plain_summary_zh") or report_fields.get("summary_zh") or ""
        failed_summary = report_fields.get("failed_summary_zh") or report_fields.get("summary_zh") or ""
        item["rule_name"] = check_name
        item["check_name"] = check_name
        item["finding_title"] = finding_title
        item["category"] = definition.get("category", "")
        item["health_impact"] = self._health_impact(definition, item)
        item["module_name"] = rule_category_label(item["category"]) or object_type_label(item.get("object_type"))
        item["object_type_label"] = object_type_label(item.get("object_type"))
        item["title"] = finding_title
        item["summary"] = failed_summary
        item["plain_summary"] = plain_summary
        item["failed_summary"] = failed_summary
        item["false_positive_notes"] = report_fields.get("false_positive_notes_zh") or ""
        item["exception_guidance"] = report_fields.get("exception_guidance_zh") or ""
        item["when_to_ignore"] = report_fields.get("when_to_ignore_zh") or ""
        item["business_impact"] = report_fields.get("business_impact_zh") or ""
        item["technical_impact"] = report_fields.get("technical_impact_zh") or ""
        item["consequence"] = report_fields.get("consequence_zh") or ""
        item["remediation"] = report_fields.get("remediation_zh") or ""
        item["owner_role"] = remediation.get("owner_role", "")
        item["remediation_effort"] = remediation.get("remediation_effort", "")
        item["maintenance_window_required"] = remediation.get("maintenance_window_required", False)
        item["verification_method"] = remediation.get("verification_method", "")
        item["remediation_steps"] = remediation.get("steps_zh", [])
        item["evidence"] = evidence
        item["current_value"] = evidence.get("current_value", item.get("observed_value"))
        item["expected_value"] = evidence.get("expected_value", item.get("expected_value"))
        item["current_value_path"] = evidence_schema.get("current_value_path", "")
        item["data_quality"] = evidence.get("data_quality", "")
        item["api_path"] = evidence.get("api_path", "")
        item["source_path"] = evidence.get("source_path") or evidence.get("api_path") or self._rule_source_path(definition)
        item["threshold"] = self._evidence_threshold(evidence, definition)
        item["collected_at"] = evidence.get("collected_at") or item.get("evaluated_at") or item.get("last_seen_at") or ""
        item["explanation"] = evidence.get("explanation") or evidence.get("evidence_summary_zh", "")
        item["raw_evidence"] = raw_evidence or self._audit_evidence(evidence)
        item["has_structured_evidence"] = self._has_structured_evidence(item)
        item["evidence_summary_zh"] = evidence.get("evidence_summary_zh", "")
        item["observed_detail"] = evidence.get("observed_detail", {})
        item["expected_detail"] = evidence.get("expected_detail", {})
        item["affected_components"] = evidence.get("affected_components", [])
        item["recommended_action_zh"] = evidence.get("recommended_action_zh", "")
        item["fault_detail"] = evidence.get("fault_detail", "")
        item["exception_reason"] = item.get("exception_reason") or ""
        item["exception_owner"] = item.get("exception_owner") or ""
        item["exception_expires_at"] = item.get("exception_expires_at") or ""
        item["exception_approval_note"] = item.get("exception_approval_note") or ""
        self._apply_customer_display_fields(item)
        item["threshold_zh"] = self._display_value_for_item(item, "threshold") if item.get("threshold") not in (None, "", {}, []) else ""
        item["source_path_zh"] = item.get("source_path") or ""
        item["collected_at_zh"] = item.get("collected_at") or ""
        item["explanation_zh"] = self._customer_text_with_units(item.get("explanation") or "", item) if item.get("explanation") else ""
        return item

    def _health_impact(self, definition: dict[str, Any], item: dict[str, Any]) -> str:
        explicit = definition.get("health_impact") or (definition.get("report_fields", {}) or {}).get("health_impact")
        if explicit in {"none", "attention", "critical"}:
            return explicit
        rule_id = str(item.get("rule_id") or "")
        if rule_id in {"VSL-VC-001", "VSL-DS-020"}:
            return "critical"
        return "attention" if str(item.get("risk_level") or "") in {"P1", "P2"} else "none"

    def _object_result_row(self, row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        definition = self._json(item.pop("definition_json", None))
        evidence = self._json(item.pop("evidence_json", None))
        raw_evidence = self._json(item.pop("raw_json", None))
        report_fields = definition.get("report_fields", {})
        remediation = definition.get("remediation", {})
        evidence_schema = definition.get("evidence_schema", {})
        fallback_name = item.get("rule_name") or item["rule_id"]
        check_name = report_fields.get("check_name_zh") or report_fields.get("title_zh") or fallback_name
        item["rule_name"] = check_name
        item["check_name"] = check_name
        item["category"] = definition.get("category", "")
        item["module_name"] = rule_category_label(item["category"]) or object_type_label(item.get("object_type"))
        item["object_type_label"] = object_type_label(item.get("object_type"))
        item["title"] = item["rule_name"]
        item["summary"] = report_fields.get("plain_summary_zh") or report_fields.get("summary_zh") or ""
        item["false_positive_notes"] = report_fields.get("false_positive_notes_zh") or ""
        item["exception_guidance"] = report_fields.get("exception_guidance_zh") or ""
        item["when_to_ignore"] = report_fields.get("when_to_ignore_zh") or ""
        item["business_impact"] = report_fields.get("business_impact_zh") or ""
        item["technical_impact"] = report_fields.get("technical_impact_zh") or ""
        item["consequence"] = report_fields.get("consequence_zh") or ""
        item["remediation"] = report_fields.get("remediation_zh") or ""
        item["verification_method"] = remediation.get("verification_method", "")
        item["rollback_required"] = remediation.get("rollback_required", False)
        item["remediation_steps"] = remediation.get("steps_zh", [])
        item["current_value"] = evidence.get("current_value", item.get("observed_value"))
        item["expected_value"] = evidence.get("expected_value", item.get("expected_value"))
        item["current_value_path"] = evidence_schema.get("current_value_path", "")
        item["evidence"] = evidence
        item["api_path"] = evidence.get("api_path", "")
        item["source_path"] = evidence.get("source_path") or evidence.get("api_path") or self._rule_source_path(definition)
        item["threshold"] = self._evidence_threshold(evidence, definition)
        item["collected_at"] = evidence.get("collected_at") or item.get("evaluated_at") or ""
        item["explanation"] = evidence.get("explanation") or evidence.get("evidence_summary_zh", "")
        item["raw_evidence"] = raw_evidence or self._audit_evidence(evidence)
        item["has_structured_evidence"] = self._has_structured_evidence(item)
        item["data_quality"] = evidence.get("data_quality", "")
        item["evidence_summary_zh"] = evidence.get("evidence_summary_zh", "")
        item["observed_detail"] = evidence.get("observed_detail", {})
        item["expected_detail"] = evidence.get("expected_detail", {})
        item["affected_components"] = evidence.get("affected_components", [])
        item["recommended_action_zh"] = evidence.get("recommended_action_zh", "")
        item["fault_detail"] = evidence.get("fault_detail", "")
        item["reason"] = item.get("error_message") or self._unavailable_reason(item) if item.get("result_status") == "unavailable" else ""
        self._apply_customer_display_fields(item)
        item["threshold_zh"] = self._display_value_for_item(item, "threshold") if item.get("threshold") not in (None, "", {}, []) else ""
        item["source_path_zh"] = item.get("source_path") or ""
        item["collected_at_zh"] = item.get("collected_at") or ""
        item["explanation_zh"] = self._customer_text_with_units(item.get("explanation") or "", item) if item.get("explanation") else ""
        return item

    def _rule_catalog_row(self, row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        definition = self._json(item.pop("definition_json", None))
        report_fields = definition.get("report_fields", {})
        data_source = definition.get("data_source", {})
        sampling = data_source.get("sampling") or {}
        evidence_schema = definition.get("evidence_schema", {})
        severity_policy = definition.get("severity_policy", {})
        fallback_name = item.get("rule_name") or item["rule_id"]
        item["rule_name"] = report_fields.get("check_name_zh") or report_fields.get("title_zh") or fallback_name
        item["check_name"] = item["rule_name"]
        item["finding_title"] = report_fields.get("finding_title_zh") or report_fields.get("title_zh") or fallback_name
        item["category_label"] = rule_category_label(item.get("category"))
        item["object_type_label"] = object_type_label(item.get("object_type"))
        item["summary"] = report_fields.get("plain_summary_zh") or report_fields.get("summary_zh") or ""
        item["false_positive_notes"] = report_fields.get("false_positive_notes_zh") or ""
        item["exception_guidance"] = report_fields.get("exception_guidance_zh") or ""
        item["when_to_ignore"] = report_fields.get("when_to_ignore_zh") or ""
        item["threshold"] = evidence_schema.get("expected_value")
        item["data_source"] = data_source.get("type", "")
        item["source_domain"] = data_source.get("source_domain", "")
        item["api_paths"] = data_source.get("api_paths", [])
        item["requires_performance_sampling"] = bool(sampling.get("required"))
        item["sampling"] = sampling
        item["severity_policy"] = severity_policy
        item["implementation_status"] = definition.get("implementation_status", "implemented")
        item["execution_mode"] = definition.get("execution_mode", "default_enabled")
        item["capability_required"] = definition.get("capability_required", ["pyvmomi"])
        item["report_visibility"] = definition.get("report_visibility", ["show_in_rule_catalog", "show_in_executed_matrix"])
        item["scoring_eligible"] = bool(definition.get("scoring_eligible", True))
        item["enabled_in_current_run"] = self._enabled_in_current_run(item)
        status_key, status_label = execution_status(item)
        item["execution_status"] = status_key
        item["execution_status_label"] = status_label
        item["unexecuted_reason"] = "" if status_key == "executed" else unexecuted_reason(item)
        item["capability_gap_reason"] = item["unexecuted_reason"]
        item["scoring_eligible_label"] = "参与" if item["scoring_eligible"] else "不参与"
        return item

    def _rule_result_row(self, row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        definition = self._json(item.pop("definition_json", None))
        evidence = self._json(item.pop("evidence_json", None))
        report_fields = definition.get("report_fields", {})
        fallback_name = item.get("rule_name") or item["rule_id"]
        item["rule_name"] = report_fields.get("check_name_zh") or report_fields.get("title_zh") or fallback_name
        item["title"] = item["rule_name"]
        item["evidence"] = evidence
        item["data_quality"] = evidence.get("data_quality", "")
        item["api_path"] = evidence.get("api_path", "")
        item["reason"] = item.get("error_message") or self._unavailable_reason(item)
        return item

    def _remediation_plan(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        grouped: dict[tuple[str, str], dict[str, Any]] = {}
        for item in findings:
            key = (item["rule_id"], item["risk_level"])
            if key not in grouped:
                grouped[key] = {
                    "risk_level": item["risk_level"],
                    "rule_id": item["rule_id"],
                    "title": item["title"],
                    "object_count": 0,
                    "owner_role": item["owner_role"],
                    "effort": item["remediation_effort"],
                    "maintenance_window_required": item["maintenance_window_required"],
                    "verification_method": item["verification_method"],
                    "steps": item["remediation_steps"],
                }
            grouped[key]["object_count"] += 1
        return list(grouped.values())

    def _rule_checklist(self, rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
        grouped: dict[str, dict[str, Any]] = defaultdict(lambda: {"rule_id": "", "rule_name": "", "counts": Counter()})
        for row in rows:
            rule_id = row["rule_id"]
            definition = self._json(row["definition_json"]) if "definition_json" in row.keys() else {}
            report_fields = definition.get("report_fields", {})
            grouped[rule_id]["rule_id"] = rule_id
            grouped[rule_id]["rule_name"] = report_fields.get("check_name_zh") or report_fields.get("title_zh") or row["rule_name"] or rule_id
            grouped[rule_id]["counts"][row["result_status"]] += row["c"]
        result = []
        for item in grouped.values():
            counts = item["counts"]
            result.append(
                {
                    "rule_id": item["rule_id"],
                    "rule_name": item["rule_name"],
                    "failed": counts.get("failed", 0),
                    "passed": counts.get("passed", 0),
                    "unavailable": counts.get("unavailable", 0),
                    "not_applicable": counts.get("not_applicable", 0),
                    "error": counts.get("error", 0),
                }
            )
        return result

    def _certificate_license_evidence(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        result = []
        for item in rows:
            if item.get("rule_id") not in CERTIFICATE_LICENSE_RULE_IDS:
                continue
            raw_evidence = item.get("raw_evidence") or self._audit_evidence(item.get("evidence", {}))
            result.append(
                {
                    "rule_id": item.get("rule_id", ""),
                    "rule_name": item.get("rule_name", item.get("rule_id", "")),
                    "result_status": item.get("result_status", ""),
                    "result_status_label": self._status_label(item.get("result_status", "")),
                    "risk_level": item.get("risk_level", ""),
                    "object_type": item.get("object_type", ""),
                    "object_type_label": item.get("object_type_label", item.get("object_type", "")),
                    "object_name": item.get("object_name", ""),
                    "current_value_zh": item.get("current_value_zh", ""),
                    "expected_value_zh": item.get("expected_value_zh", ""),
                    "evidence_summary_zh": item.get("evidence_summary_zh", ""),
                    "observed_detail_zh": item.get("observed_detail_zh", ""),
                    "expected_detail_zh": item.get("expected_detail_zh", ""),
                    "threshold_zh": item.get("threshold_zh", ""),
                    "source_path": item.get("source_path", ""),
                    "collected_at": item.get("collected_at", ""),
                    "explanation_zh": item.get("explanation_zh", ""),
                    "raw_evidence": raw_evidence,
                    "structured_evidence_state": "structured" if item.get("has_structured_evidence") else "fallback",
                }
            )
        return sorted(
            result,
            key=lambda item: (
                ["VSL-VC-005", "VSL-VC-006", "VSL-HOST-008", "VSL-HOST-023"].index(item["rule_id"])
                if item["rule_id"] in CERTIFICATE_LICENSE_RULE_IDS
                else 99,
                item["object_type"],
                item["object_name"],
            ),
        )

    def _status_label(self, status: str) -> str:
        return {
            "passed": "通过",
            "failed": "风险命中",
            "unavailable": "不可用",
            "error": "执行异常",
            "not_applicable": "不适用",
        }.get(status, status or "未知")

    def _executive_summary(self, run: dict[str, Any], risk_summary: dict[str, int], asset_summary: dict[str, int], status_summary: dict[str, int]) -> dict[str, Any]:
        p1_p2 = risk_summary.get("P1", 0) + risk_summary.get("P2", 0)
        if p1_p2:
            priority = "建议优先处理 P1/P2 风险，并在整改后复跑巡检确认。"
        elif risk_summary.get("P3", 0):
            priority = "当前主要为中风险和优化建议，建议纳入近期维护计划。"
        else:
            priority = "当前未发现高优先级风险，建议保留定期巡检。"
        return {
            "score": run.get("score"),
            "asset_total": sum(asset_summary.values()),
            "risk_total": actionable_risk_total(risk_summary),
            "optimization_total": int(risk_summary.get("P4", 0) or 0),
            "critical_high_total": p1_p2,
            "unavailable_total": status_summary.get("unavailable", 0),
            "not_applicable_total": status_summary.get("not_applicable", 0),
            "priority": priority,
        }

    def _asset_details(self, rows: list[sqlite3.Row], vcenter_name: str | None = None) -> dict[str, list[dict[str, Any]]]:
        details: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in rows:
            item = dict(row)
            properties = self._json(item.pop("properties_json", None))
            item["properties"] = properties.get("properties", properties)
            item["object_path"] = item.pop("path")
            item["asset_location"] = item["properties"].get("asset_location") or self._fallback_asset_location(item, vcenter_name)
            details[item["object_type"]].append(item)
        return dict(details)

    def _fallback_asset_location(self, item: dict[str, Any], vcenter_name: str | None = None) -> str:
        path = str(item.get("object_path") or "").strip()
        name = str(item.get("object_name") or "").strip()
        if path and path != name:
            parts = [part.strip() for part in path.replace("\\", "/").split("/") if part.strip()]
            if len(parts) > 1 and parts[-1] == name:
                return " / ".join(parts[:-1])
            return path
        object_type = item.get("object_type")
        if object_type == "vCenter":
            return "vCenter 根对象"
        base = str(vcenter_name or "").strip()
        return f"vCenter {base} / 层级未记录" if base else "vCenter / 层级未记录"

    def _object_pass_rate(self, rows: list[dict[str, Any]]) -> dict[str, Any]:
        grouped: dict[tuple[str, str], Counter] = defaultdict(Counter)
        for row in rows:
            grouped[(row["object_type"], row["object_key"])][row["result_status"]] += 1
        total = len(grouped)
        passed_objects = sum(1 for counts in grouped.values() if counts.get("failed", 0) == 0 and counts.get("error", 0) == 0 and counts.get("unavailable", 0) == 0)
        return {
            "total_objects": total,
            "passed_objects": passed_objects,
            "attention_objects": total - passed_objects,
            "rate": round((passed_objects / total) * 100, 2) if total else 100.0,
        }

    def _rule_pass_rate(self, rows: list[dict[str, Any]]) -> dict[str, Any]:
        actionable = [row for row in rows if row["result_status"] in {"passed", "failed"}]
        passed = sum(1 for row in actionable if row["result_status"] == "passed")
        return {
            "total_checks": len(rows),
            "actionable_checks": len(actionable),
            "passed_checks": passed,
            "rate": round((passed / len(actionable)) * 100, 2) if actionable else 100.0,
        }

    def _module_summary(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        grouped: dict[str, Counter] = defaultdict(Counter)
        for row in rows:
            grouped[row["object_type"]][row["result_status"]] += 1
        result = []
        order = ["vCenter", "ClusterComputeResource", "HostSystem", "Datastore", "VirtualMachine"]
        for object_type in order:
            counts = grouped.get(object_type, Counter())
            total = sum(counts.values())
            result.append(
                {
                    "object_type": object_type,
                    "module_name": self._module_name(object_type),
                    "total": total,
                    "passed": counts.get("passed", 0),
                    "failed": counts.get("failed", 0),
                    "unavailable": counts.get("unavailable", 0),
                    "not_applicable": counts.get("not_applicable", 0),
                    "error": counts.get("error", 0),
                    "pass_rate": round((counts.get("passed", 0) / total) * 100, 2) if total else 100.0,
                }
            )
        return result

    def _module_name(self, object_type: str) -> str:
        label = object_type_label(object_type)
        return f"{label}检查结果" if label else object_type

    def _rule_catalog_summary(self, rules: list[dict[str, Any]]) -> dict[str, int]:
        return rule_catalog_summary(rules)

    def _enabled_in_current_run(self, item: dict[str, Any]) -> bool:
        return item.get("implementation_status") == "implemented" and item.get("execution_mode") == "default_enabled"

    def _capability_gap_reason(self, item: dict[str, Any]) -> str:
        return unexecuted_reason(item) if not item.get("enabled_in_current_run") else ""

    def _vcenter_info(self, scope: dict[str, Any], inventory_rows: list[sqlite3.Row]) -> dict[str, Any]:
        properties: dict[str, Any] = {}
        object_name = scope.get("vcenter_name") or scope.get("vcenter_host") or ""
        for row in inventory_rows:
            if row["object_type"] != "vCenter":
                continue
            object_name = row["object_name"] or object_name
            raw = self._json(row["properties_json"])
            properties = raw.get("properties", raw)
            break
        diagnostics = properties.get("connection_diagnostics")
        if not isinstance(diagnostics, dict):
            diagnostics = {}
        collection_warnings = properties.get("collection_warnings")
        if not isinstance(collection_warnings, list):
            collection_warnings = []
        return {
            "vcenter_address": scope.get("vcenter_host") or "",
            "vcenter_name": object_name or scope.get("vcenter_host") or "未采集",
            "vcenter_version": properties.get("version") or "未采集",
            "vcenter_build": properties.get("build") or properties.get("build_number") or "未采集",
            "collector_username": mask_username(scope.get("vcenter_username")),
            "collection_mode": properties.get("collection_mode") or "sdk",
            "collection_mode_label": properties.get("collection_mode_label") or "完整 SDK 巡检模式",
            "data_coverage_summary": properties.get("data_coverage_summary") or "按当前巡检结果展示数据覆盖范围。",
            "connection_diagnostics": diagnostics,
            "security_warnings": properties.get("security_warnings") if isinstance(properties.get("security_warnings"), list) else [],
            "collection_warnings": collection_warnings[:20],
        }

    def _unavailable_reason(self, item: dict[str, Any]) -> str:
        data_quality = item.get("data_quality") or "missing"
        if data_quality == "missing":
            return "数据源未返回该指标或当前版本/对象不支持该指标"
        if data_quality == "permission_denied":
            return "当前账号权限不足"
        if data_quality == "api_error":
            return "API 采集失败"
        return "规则数据不可判定"

    def _json(self, value: str | None) -> dict[str, Any]:
        if not value:
            return {}
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return {}

    def _rule_source_path(self, definition: dict[str, Any]) -> str:
        data_source = definition.get("data_source", {})
        paths = data_source.get("api_paths") or []
        if isinstance(paths, list):
            return ", ".join(str(path) for path in paths if path)
        return str(paths or "")

    def _evidence_threshold(self, evidence: dict[str, Any], definition: dict[str, Any]) -> Any:
        for container_name in ("observed_detail", "expected_detail", "parameters"):
            container = evidence.get(container_name)
            if not isinstance(container, dict):
                continue
            for key, value in container.items():
                key_text = str(key).lower()
                if "threshold" in key_text or key_text.startswith("max_") or key_text.startswith("min_") or key_text.startswith("expected_min"):
                    return value
        expected = evidence.get("expected_value")
        if expected not in (None, "", {}, []):
            return expected
        return definition.get("evidence_schema", {}).get("expected_value")

    def _audit_evidence(self, evidence: dict[str, Any]) -> dict[str, Any]:
        audit = {
            "observed_detail": evidence.get("observed_detail", {}),
            "expected_detail": evidence.get("expected_detail", {}),
            "affected_components": evidence.get("affected_components", []),
        }
        return {key: value for key, value in audit.items() if value not in (None, "", {}, [])}

    def _has_structured_evidence(self, item: dict[str, Any]) -> bool:
        return any(
            item.get(key) not in (None, "", {}, [])
            for key in (
                "raw_evidence",
                "current_value",
                "expected_value",
                "api_path",
                "explanation",
                "observed_detail",
                "expected_detail",
            )
        )

    def _apply_customer_display_fields(self, item: dict[str, Any]) -> None:
        item["owner_role_label"] = OWNER_ROLE_LABELS.get(item.get("owner_role"), item.get("owner_role") or "未指定")
        item["remediation_effort_label"] = EFFORT_LABELS.get(item.get("remediation_effort"), item.get("remediation_effort") or "未评估")
        item["maintenance_window_label"] = "需要" if item.get("maintenance_window_required") else "通常不需要"
        item["verification_method_label"] = VERIFICATION_LABELS.get(item.get("verification_method"), item.get("verification_method") or "复核确认")
        item["rollback_required_label"] = "需要" if item.get("rollback_required") else "通常不需要"
        item["data_quality_label"] = DATA_QUALITY_LABELS.get(item.get("data_quality"), item.get("data_quality") or "未说明")
        item["current_value_zh"] = self._display_value_for_item(item, "current_value")
        item["expected_value_zh"] = self._display_value_for_item(item, "expected_value")
        item["evidence_summary_zh"] = self._customer_text_with_units(item.get("evidence_summary_zh") or "", item)
        item["observed_detail_zh"] = self._detail_text(item.get("observed_detail"), item)
        item["expected_detail_zh"] = self._detail_text(item.get("expected_detail"), item)
        item["affected_components_zh"] = self._component_text(item.get("affected_components"), item.get("object_name"))
        if item.get("recommended_action_zh"):
            item["recommended_action_zh"] = self._customer_text_with_units(item.get("recommended_action_zh"), item)
        item["fault_detail_zh"] = self._detail_text(item.get("fault_detail"), item) if item.get("fault_detail") else self._fallback_fault_detail(item)

    def _display_value(self, value: Any) -> str:
        if value is None:
            return "未采集"
        if isinstance(value, (list, tuple, set)):
            return "、".join(self._display_value(item) for item in value) if value else "无"
        if isinstance(value, dict):
            return self._detail_text(value)
        if value in VALUE_LABELS:
            return VALUE_LABELS[value]
        if isinstance(value, bool):
            return "是" if value else "否"
        return self._normalize_text(str(value))

    def _display_value_for_item(self, item: dict[str, Any], field_name: str) -> str:
        semantic_key = self._semantic_key_for_item(item, field_name)
        if semantic_key:
            display_value = self._display_value_for_semantic_key(item.get(field_name), semantic_key, field_name)
            if display_value is not None:
                return display_value
        return self._display_value_for_rule(item.get(field_name), item.get("rule_id", ""), field_name)

    def _display_value_for_rule(self, value: Any, rule_id: str, field_name: str = "") -> str:
        if value is None:
            return "未采集"
        if isinstance(value, (list, tuple, set)):
            return "、".join(self._display_value_for_rule(item, rule_id, field_name) for item in value) if value else "无"
        if isinstance(value, dict):
            return self._detail_text(value, {"rule_id": rule_id})
        if rule_id in NORMAL_ABNORMAL_RULE_IDS and isinstance(value, bool):
            return "异常" if value else "正常"
        if rule_id in FEATURE_STATE_RULE_IDS and isinstance(value, bool):
            return "启用" if value else "未启用"
        if rule_id in COUNT_VALUE_RULES and isinstance(value, (int, float)):
            label, unit = COUNT_VALUE_RULES[rule_id]
            number = int(value) if float(value).is_integer() else value
            return f"未发现{label}" if number == 0 else f"发现 {number} {unit}{label}"
        if rule_id in {"VSL-VC-006", "VSL-HOST-023"} and isinstance(value, (int, float)):
            if value >= 999999:
                return "永久授权"
            number = int(value) if float(value).is_integer() else value
            return f"剩余 {number} 天"
        if rule_id in {"VSL-VC-005", "VSL-HOST-008"} and isinstance(value, (int, float)):
            number = int(value) if float(value).is_integer() else value
            return f"剩余 {number} 天"
        if rule_id == "VSL-HOST-013" and isinstance(value, bool):
            return "完整" if value else "不完整"
        if isinstance(value, bool):
            return "是" if value else "否"
        if value in VALUE_LABELS:
            return VALUE_LABELS[value]
        return self._normalize_text(str(value))

    def _display_value_for_detail(self, key: str, value: Any, item: dict[str, Any] | None = None) -> str:
        rule_id = item.get("rule_id", "") if item else ""
        if key in {"current_value", "expected_value"}:
            semantic_key = self._semantic_key_for_item(item or {}, key)
            if semantic_key:
                display_value = self._display_value_for_semantic_key(value, semantic_key, key)
                if display_value is not None:
                    return display_value
            return self._display_value_for_rule(value, rule_id, key)
        semantic_display = self._display_value_for_semantic_key(value, key, key)
        if semantic_display is not None:
            return semantic_display
        hint = FIELD_VALUE_HINTS.get(key)
        if hint:
            hint_type, hint_value = hint
            if hint_type == "feature" and isinstance(value, bool):
                return "启用" if value else "未启用"
            if hint_type == "normal_abnormal" and isinstance(value, bool):
                return "异常" if value else "正常"
            if hint_type == "finding_count" and isinstance(value, (int, float)):
                number = int(value) if float(value).is_integer() else value
                return f"未发现{hint_value}" if number == 0 else f"发现 {number} 个{hint_value}"
            if hint_type == "finding_count_with_unit" and isinstance(value, (int, float)):
                label, unit = hint_value.split("|", 1)
                number = int(value) if float(value).is_integer() else value
                return f"未发现{label}" if number == 0 else f"发现 {number} {unit}{label}"
            if hint_type == "count_with_unit" and isinstance(value, (int, float)):
                number = int(value) if float(value).is_integer() else value
                return f"{number} {hint_value}"
            if hint_type == "version_number" and isinstance(value, (int, float)):
                number = int(value) if float(value).is_integer() else value
                return f"vmx-{number}"
            if hint_type == "percent" and isinstance(value, (int, float)):
                number = int(value) if float(value).is_integer() else value
                return f"{number}%"
            if hint_type == "ratio" and isinstance(value, (int, float)):
                return f"{float(value):.2f}:1"
            if hint_type == "ratio_percent" and isinstance(value, (int, float)):
                return f"{float(value) * 100:.1f}%"
            if hint_type == "gb" and isinstance(value, (int, float)):
                return f"{float(value):.1f} GB"
            if hint_type == "mb" and isinstance(value, (int, float)):
                number = int(value) if float(value).is_integer() else value
                return f"{number} MB"
            if hint_type == "mb_as_gb" and isinstance(value, (int, float)):
                return f"{float(value) / 1024:.1f} GB"
            if hint_type == "bytes_as_gb" and isinstance(value, (int, float)):
                return f"{float(value) / (1024 * 1024 * 1024):.1f} GB"
            if hint_type == "yes_no" and isinstance(value, bool):
                return "是" if value else "否"
            if hint_type == "collection_status":
                status_labels = {
                    "collected": "已采集",
                    "not_collected": "未采集",
                    "not_applicable": "不适用",
                    "unsupported": "当前环境不支持",
                    "permission_denied": "权限不足",
                    "api_error": "采集失败",
                }
                return status_labels.get(str(value), self._normalize_text(str(value)))
            if hint_type == "days_remaining" and isinstance(value, (int, float)):
                number = int(value) if float(value).is_integer() else value
                return f"剩余 {number} 天"
            if hint_type == "license_days" and isinstance(value, (int, float)):
                if value >= 999999:
                    return "永久授权"
                number = int(value) if float(value).is_integer() else value
                return f"剩余 {number} 天"
            if hint_type == "assigned" and isinstance(value, bool):
                return "已分配" if value else "未分配"
            if hint_type == "evaluation" and isinstance(value, bool):
                return "评估版" if value else "正式授权"
            if hint_type == "complete_incomplete" and isinstance(value, bool):
                return "完整" if value else "不完整"
        return self._display_value_for_rule(value, rule_id, key)

    def _semantic_key_for_item(self, item: dict[str, Any], field_name: str) -> str:
        if not item:
            return field_name if self._field_hint(field_name) else ""
        if field_name not in {"current_value", "expected_value", "threshold"}:
            return field_name if self._field_hint(field_name) else ""
        current_path = str(item.get("current_value_path") or "").strip()
        if current_path and self._field_hint(current_path):
            return current_path
        evidence = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
        schema_path = str(evidence.get("current_value_path") or "").strip() if evidence else ""
        if schema_path and self._field_hint(schema_path):
            return schema_path
        observed = item.get("observed_detail") if isinstance(item.get("observed_detail"), dict) else {}
        if observed:
            for key, value in observed.items():
                if self._field_hint(str(key)) and self._same_value(value, item.get("current_value")):
                    return str(key)
            if len(observed) == 1:
                key = next(iter(observed))
                if self._field_hint(str(key)):
                    return str(key)
        return ""

    def _field_hint(self, key: str) -> tuple[str, str] | None:
        if not key:
            return None
        if key in FIELD_VALUE_HINTS:
            return FIELD_VALUE_HINTS[key]
        if key.endswith("_percent"):
            return ("percent", "")
        if key.endswith("_gb"):
            return ("gb", "")
        if key.endswith("_mb"):
            return ("mb", "")
        if key.endswith("_ms"):
            return ("ms", "")
        if key.endswith("_mbps"):
            return ("mbps", "")
        if key == "iops" or key.endswith("_iops"):
            return ("iops", "")
        if key.endswith("_days"):
            return ("count_with_unit", "天")
        if key.endswith("_count"):
            return ("count_with_unit", "个")
        return None

    def _display_value_for_semantic_key(self, value: Any, key: str, field_name: str = "") -> str | None:
        hint = self._field_hint(key)
        if not hint:
            return None
        hint_type, hint_value = hint
        if hint_type == "cpu_ready_percent":
            percent = self._format_value_with_unit(value, "%")
            if field_name == "current_value" and percent != "未采集":
                return f"{percent} CPU Ready"
            return percent
        if hint_type == "percent":
            return self._format_value_with_unit(value, "%")
        if hint_type == "gb":
            return self._format_numeric_unit(value, "GB", decimals=1)
        if hint_type == "mb":
            return self._format_numeric_unit(value, "MB")
        if hint_type == "ms":
            return self._format_numeric_unit(value, "ms")
        if hint_type == "mbps":
            return self._format_numeric_unit(value, "Mbps")
        if hint_type == "iops":
            return self._format_numeric_unit(value, "IOPS")
        if hint_type == "count_with_unit":
            return self._format_numeric_unit(value, hint_value)
        if hint_type == "feature" and isinstance(value, bool):
            return "启用" if value else "未启用"
        if hint_type == "normal_abnormal" and isinstance(value, bool):
            return "异常" if value else "正常"
        if hint_type == "finding_count" and isinstance(value, (int, float)):
            number = self._format_number(value)
            return f"未发现{hint_value}" if float(value) == 0 else f"发现 {number} 个{hint_value}"
        if hint_type == "finding_count_with_unit" and isinstance(value, (int, float)):
            label, unit = hint_value.split("|", 1)
            number = self._format_number(value)
            return f"未发现{label}" if float(value) == 0 else f"发现 {number} {unit}{label}"
        if hint_type == "version_number" and isinstance(value, (int, float)):
            return f"vmx-{self._format_number(value)}"
        if hint_type == "ratio" and isinstance(value, (int, float)):
            return f"{float(value):.2f}:1"
        if hint_type == "ratio_percent" and isinstance(value, (int, float)):
            return f"{float(value) * 100:.1f}%"
        if hint_type == "mb_as_gb" and isinstance(value, (int, float)):
            return f"{float(value) / 1024:.1f} GB"
        if hint_type == "bytes_as_gb" and isinstance(value, (int, float)):
            return f"{float(value) / (1024 * 1024 * 1024):.1f} GB"
        if hint_type == "yes_no" and isinstance(value, bool):
            return "是" if value else "否"
        if hint_type == "collection_status":
            status_labels = {
                "collected": "已采集",
                "not_collected": "未采集",
                "not_applicable": "不适用",
                "unsupported": "当前环境不支持",
                "permission_denied": "权限不足",
                "api_error": "采集失败",
            }
            return status_labels.get(str(value), self._normalize_text(str(value)))
        if hint_type == "days_remaining" and isinstance(value, (int, float)):
            return f"剩余 {self._format_number(value)} 天"
        if hint_type == "license_days" and isinstance(value, (int, float)):
            if value >= 999999:
                return "永久授权"
            return f"剩余 {self._format_number(value)} 天"
        if hint_type == "assigned" and isinstance(value, bool):
            return "已分配" if value else "未分配"
        if hint_type == "evaluation" and isinstance(value, bool):
            return "评估版" if value else "正式授权"
        if hint_type == "complete_incomplete" and isinstance(value, bool):
            return "完整" if value else "不完整"
        return None

    def _format_value_with_unit(self, value: Any, unit: str) -> str:
        if value is None or value == "":
            return "未采集"
        if isinstance(value, bool):
            return "是" if value else "否"
        if isinstance(value, (int, float)):
            return f"{self._format_number(value)}{unit}"
        text = self._normalize_text(str(value)).strip()
        if not text or text.lower() in {"none", "null"}:
            return "未采集"
        if unit and unit in text:
            return text
        comparison = re.match(r"^(<=|>=|<|>|≤|≥)\s*(-?\d+(?:\.\d+)?)$", text)
        if comparison:
            return f"{comparison.group(1)} {self._format_number(comparison.group(2))}{unit}"
        numeric = re.match(r"^-?\d+(?:\.\d+)?$", text)
        if numeric:
            return f"{self._format_number(text)}{unit}"
        return text

    def _format_numeric_unit(self, value: Any, unit: str, decimals: int | None = None) -> str:
        if value is None or value == "":
            return "未采集"
        if isinstance(value, (int, float)):
            if decimals is None:
                number = self._format_number(value)
            else:
                number = f"{float(value):.{decimals}f}"
            return f"{number} {unit}".strip()
        text = self._normalize_text(str(value)).strip()
        if not text or text.lower() in {"none", "null"}:
            return "未采集"
        if unit and unit in text:
            return text
        comparison = re.match(r"^(<=|>=|<|>|≤|≥)\s*(-?\d+(?:\.\d+)?)$", text)
        if comparison:
            return f"{comparison.group(1)} {self._format_number(comparison.group(2))} {unit}".strip()
        numeric = re.match(r"^-?\d+(?:\.\d+)?$", text)
        if numeric:
            return f"{self._format_number(text)} {unit}".strip()
        return text

    def _format_number(self, value: Any) -> str:
        try:
            number = float(value)
        except (TypeError, ValueError):
            return self._normalize_text(str(value))
        if number.is_integer():
            return str(int(number))
        return f"{number:.2f}".rstrip("0").rstrip(".")

    def _same_value(self, left: Any, right: Any) -> bool:
        if left == right:
            return True
        try:
            return float(left) == float(right)
        except (TypeError, ValueError):
            return False

    def _customer_text_with_units(self, value: Any, item: dict[str, Any]) -> str:
        text = self._normalize_text("" if value is None else str(value))
        text = text.replace("期望状态", "建议状态").replace("期望值", "建议状态")
        if self._semantic_key_for_item(item, "current_value") == "cpu_ready_percent" and self._is_generic_current_expected_text(text):
            return self._cpu_ready_summary(item)
        return text

    def _is_generic_current_expected_text(self, text: str) -> bool:
        return "当前值" in text and ("建议状态" in text or "期望" in text)

    def _cpu_ready_summary(self, item: dict[str, Any]) -> str:
        object_name = item.get("object_name") or "虚拟机"
        current = self._display_value_for_semantic_key(item.get("current_value"), "cpu_ready_percent", "observed_value") or "未采集"
        expected = self._display_value_for_semantic_key(item.get("expected_value"), "cpu_ready_percent", "expected_value") or "未采集"
        return f"{object_name} 存在 CPU 调度等待偏高，CPU Ready 当前值为 {current}，建议{self._threshold_phrase(expected)}。"

    def _threshold_phrase(self, value: str) -> str:
        text = value.strip()
        if text.startswith("< "):
            return f"低于 {text[2:]}"
        if text.startswith("<"):
            return f"低于 {text[1:].strip()}"
        if text.startswith("≤ "):
            return f"不高于 {text[2:]}"
        if text.startswith("≤"):
            return f"不高于 {text[1:].strip()}"
        return text

    def _normalize_text(self, value: str) -> str:
        replacements = {
            " True": " 启用",
            " False": " 未启用",
            " true": " 启用",
            " false": " 未启用",
            "True": "启用",
            "False": "未启用",
            "manual_check": "人工复核",
            "rerun_rule": "复跑巡检确认",
            "command_check": "命令或工具复核",
            "virtualization_admin": "虚拟化管理员",
            "storage_admin": "存储管理员",
            "network_admin": "网络管理员",
            "security_admin": "安全管理员",
            "medium": "中",
        }
        result = value
        for old, new in replacements.items():
            result = result.replace(old, new)
        return result

    def _detail_text(self, value: Any, item: dict[str, Any] | None = None) -> str:
        if not value:
            return "未列出"
        if isinstance(value, (str, int, float, bool)) or value is None:
            return self._display_value_for_rule(value, item.get("rule_id", "") if item else "")
        if isinstance(value, list):
            return "；".join(self._detail_text(entry, item) for entry in value) if value else "未列出"
        if isinstance(value, dict):
            parts = []
            for key, raw_value in value.items():
                label = DETAIL_LABELS.get(key)
                if not label:
                    continue
                parts.append(f"{label}：{self._display_value_for_detail(key, raw_value, item)}")
            return "；".join(parts) if parts else "未列出"
        return self._normalize_text(str(value))

    def _component_text(self, value: Any, fallback: str | None = None) -> str:
        if not value:
            return "无"
        if isinstance(value, list):
            parts = []
            for item in value:
                if isinstance(item, dict):
                    parts.append(
                        self._display_value(
                            item.get("device")
                            or item.get("name")
                            or item.get("lun")
                            or item.get("adapter")
                            or item.get("target")
                            or item
                        )
                    )
                else:
                    parts.append(self._display_value(item))
            return "、".join(part for part in parts if part) or "无"
        return self._display_value(value)

    def _fallback_fault_detail(self, item: dict[str, Any]) -> str:
        summary = item.get("evidence_summary_zh") or ""
        if summary:
            return self._normalize_text(summary)
        observed = self._detail_text(item.get("observed_detail"), item)
        if observed and observed != "未列出":
            return observed
        object_name = item.get("object_name") or "风险对象"
        title = item.get("title") or item.get("rule_name") or "风险项"
        return f"{object_name} 触发 {title}，请结合证据摘要和整改建议复核。"
