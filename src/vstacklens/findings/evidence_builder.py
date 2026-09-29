from __future__ import annotations

from typing import Any

from vstacklens.core.context import RunContext
from vstacklens.core.enums import DataQuality
from vstacklens.core.time import utc_now_iso
from vstacklens.inventory.canonical_models import CanonicalObject
from vstacklens.rules.schema import RuleDefinition


class EvidenceBuilder:
    def build(
        self,
        run: RunContext,
        rule: RuleDefinition,
        target: CanonicalObject,
        current_value: Any,
        expected_value: Any,
        data_quality: DataQuality = DataQuality.COMPLETE,
        parameters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        parameters = parameters or {}
        evidence = {
            "run_id": run.run_id,
            "vcenter_id": run.vcenter_id,
            "rule_id": rule.rule_id,
            "rule_version": rule.rule_version,
            "object_type": target.object_type,
            "object_key": target.object_key,
            "object_name": target.object_name,
            "object_path": target.object_path,
            "current_value": current_value,
            "expected_value": expected_value,
            "api_path": ", ".join(rule.data_source.api_paths),
            "collected_at": utc_now_iso(),
            "collector_version": run.collector_version,
            "data_quality": data_quality.value,
            "raw_ref": target.raw_ref,
            "confidence_level": rule.confidence_level.value,
            "confidence_reason": "规则基于归一化资产字段和受限表达式执行",
            "parameters": parameters,
        }
        evidence.update(self._enriched(rule, target, current_value, expected_value, parameters))
        return evidence

    def _enriched(self, rule: RuleDefinition, target: CanonicalObject, current_value: Any, expected_value: Any, parameters: dict[str, Any]) -> dict[str, Any]:
        props = {**target.properties, **parameters}
        handler = getattr(self, f"_evidence_{rule.rule_id.lower().replace('-', '_')}", None)
        if handler:
            return handler(target, props)
        return {
            "evidence_summary_zh": f"{target.object_name} 当前值为 {self._text(current_value)}，期望值为 {self._text(expected_value)}。",
            "observed_detail": {"current_value": current_value},
            "expected_detail": {"expected_value": expected_value},
            "affected_components": [],
            "recommended_action_zh": rule.report_fields.remediation_zh,
        }

    def _evidence_vsl_vc_004(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        count = props.get("red_alarm_count")
        alarms = props.get("active_red_alarms") or []
        affected = [self._alarm_component(item) for item in alarms if self._alarm_component(item)]
        detail = self._alarm_detail_text(alarms)
        return {
            "evidence_summary_zh": f"vCenter 当前存在 {count} 条红色活动告警，需要确认告警对象和根因。",
            "observed_detail": {
                "red_alarm_count": count,
                "active_red_alarms": alarms,
            },
            "expected_detail": {"red_alarm_count": 0, "expected_policy": "vCenter 不应存在红色活动告警。"},
            "affected_components": affected,
            "recommended_action_zh": "逐项打开红色告警，确认对象状态和根因，恢复后清理已解决告警并复跑巡检。",
            "fault_detail": detail,
        }

    def _evidence_vsl_cl_016(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        host_count = props.get("host_count")
        enabled = props.get("vmotion_enabled_host_count")
        missing_count = props.get("cluster_vmotion_missing_host_count")
        missing_hosts = props.get("missing_vmotion_hosts") or []
        return {
            "evidence_summary_zh": f"集群 {target.object_name} 共 {host_count} 台主机，其中 {missing_count} 台未配置可用 vMotion VMkernel 网络。",
            "observed_detail": {
                "cluster_name": target.object_name,
                "host_count": host_count,
                "vmotion_enabled_host_count": enabled,
                "cluster_vmotion_missing_host_count": missing_count,
                "missing_vmotion_hosts": missing_hosts,
            },
            "expected_detail": {"cluster_vmotion_missing_host_count": 0, "expected_policy": "所有主机至少配置 1 个启用 vMotion 服务的 VMkernel 网卡。"},
            "affected_components": missing_hosts,
            "recommended_action_zh": "为缺少 vMotion 的主机补齐 VMkernel 适配器，并验证跨主机 vMotion。",
        }

    def _evidence_vsl_cl_007(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        evc_enabled = props.get("evc_enabled")
        evc_mode = props.get("evc_mode")
        return {
            "evidence_summary_zh": "集群未启用 EVC，后续不同代际 CPU 主机之间迁移兼容性可能受限。"
            if evc_enabled is False
            else f"集群 EVC 当前模式为 {self._text(evc_mode)}。",
            "observed_detail": {
                "cluster_name": target.object_name,
                "evc_enabled": evc_enabled,
                "evc_mode": evc_mode,
                "host_cpu_models": props.get("host_cpu_models") or [],
            },
            "expected_detail": {"expected_policy": "按集群硬件兼容策略启用 EVC，并保持集群内 EVC 模式一致。"},
            "affected_components": [target.object_name] if evc_enabled is False else [],
            "recommended_action_zh": "评估集群 CPU 代际和业务兼容性后启用合适的 EVC 模式。",
        }

    def _evidence_vsl_cl_008(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        count = props.get("ha_heartbeat_datastore_count")
        return {
            "evidence_summary_zh": f"集群 {target.object_name} 当前 HA 心跳 Datastore 数量为 {count}，低于建议值 2。",
            "observed_detail": {
                "cluster_name": target.object_name,
                "ha_heartbeat_datastore_count": count,
                "heartbeat_datastore_names": props.get("heartbeat_datastore_names") or [],
            },
            "expected_detail": {"expected_min_count": 2},
            "affected_components": [target.object_name],
            "recommended_action_zh": "为集群配置至少 2 个合适的 HA 心跳 Datastore，并确认多数主机可见。",
        }

    def _evidence_vsl_cl_013(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        count = props.get("maintenance_host_count")
        hosts = props.get("maintenance_hosts") or []
        return {
            "evidence_summary_zh": f"集群 {target.object_name} 内存在 {count} 台主机仍处于维护模式。",
            "observed_detail": {"cluster_name": target.object_name, "maintenance_host_count": count, "maintenance_hosts": hosts},
            "expected_detail": {"maintenance_host_count": 0},
            "affected_components": hosts,
            "recommended_action_zh": "确认维护任务是否完成，完成后将相关主机退出维护模式并复跑巡检。",
        }

    def _evidence_vsl_host_019(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        count = props.get("physical_nic_link_issue_count")
        nics = props.get("affected_nics") or []
        return {
            "evidence_summary_zh": f"主机 {target.object_name} 存在 {count} 个物理网卡链路异常。",
            "observed_detail": {
                "host_name": target.object_name,
                "pnic_down_count": props.get("pnic_down_count"),
                "pnic_degraded_count": props.get("pnic_degraded_count"),
                "physical_nic_link_issue_count": count,
                "affected_nics": nics,
                "link_speed_detail": props.get("link_speed_detail") or [],
                "physical_nic_details": props.get("physical_nic_details") or [],
                "affected_switches": props.get("affected_switches") or [],
                "affected_uplinks": props.get("affected_uplinks") or [],
            },
            "expected_detail": {"physical_nic_link_issue_count": 0, "expected_link_state": "所有承载业务的物理上行链路应为 up 且速率不低于 1Gbps。"},
            "affected_components": nics or [target.object_name],
            "recommended_action_zh": "检查异常 vmnic 的物理链路、交换机端口、模块和速率协商状态。",
        }

    def _evidence_vsl_host_020(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        paths = props.get("affected_storage_paths") or []
        return {
            "evidence_summary_zh": "主机存在异常存储路径，可能降低存储访问冗余。",
            "observed_detail": {"host_name": target.object_name, "storage_path_dead_count": props.get("storage_path_dead_count"), "affected_storage_paths": paths},
            "expected_detail": {"storage_path_dead_count": 0, "expected_path_state": "存储路径不应处于 dead、error 或 off 状态。"},
            "affected_components": [item.get("lun") or item.get("adapter") or target.object_name for item in paths] or [target.object_name],
            "recommended_action_zh": "检查 HBA、SAN 交换机、目标端口和多路径状态，恢复异常路径后复跑巡检。",
        }

    def _evidence_vsl_net_001(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        uplinks = props.get("affected_uplinks") or []
        return {
            "evidence_summary_zh": "主机存在 vSwitch/vDS 上行链路异常，可能影响其承载网络。",
            "observed_detail": {
                "host_name": target.object_name,
                "vswitch_uplink_issue_count": props.get("vswitch_uplink_issue_count"),
                "affected_switches": props.get("affected_switches") or [],
                "affected_uplinks": uplinks,
            },
            "expected_detail": {"vswitch_uplink_issue_count": 0},
            "affected_components": uplinks or [target.object_name],
            "recommended_action_zh": "检查对应交换机上行、物理网卡链路和端口绑定关系，恢复网络冗余。",
        }

    def _evidence_vsl_net_006(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        return {
            "evidence_summary_zh": "主机未发现启用 vMotion 服务的 VMkernel 网卡。",
            "observed_detail": {
                "host_name": target.object_name,
                "vmotion_vmk_count": props.get("vmotion_vmk_count"),
                "vmkernel_adapters": props.get("vmkernel_adapters") or [],
            },
            "expected_detail": {"expected_service": "至少 1 个 VMkernel 网卡启用 vMotion 服务。"},
            "affected_components": [target.object_name],
            "recommended_action_zh": "为主机创建或启用 vMotion VMkernel 网卡，并验证 vMotion 连通性。",
        }

    @staticmethod
    def _snapshot_evidence_details(props: dict[str, Any]) -> list[dict[str, Any]]:
        snapshots = props.get("snapshots") or []
        details = []
        for snapshot in snapshots:
            if not isinstance(snapshot, dict):
                continue
            details.append(
                {
                    "name": snapshot.get("name") or snapshot.get("snapshot_name"),
                    "create_time": snapshot.get("create_time") or snapshot.get("created_at"),
                    "parent": snapshot.get("parent"),
                }
            )
        return details

    def _evidence_vsl_vm_001(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        details = self._snapshot_evidence_details(props)
        age = props.get("snapshot_age_days_max")
        return {
            "evidence_summary_zh": f"虚拟机 {target.object_name} 最长快照保留约 {self._text(age)} 天，共采集 {len(details)} 条快照明细。",
            "observed_detail": {"vm_name": target.object_name, "snapshot_age_days_max": age, "snapshots": details},
            "expected_detail": {"snapshot_age_days_max": "< 7", "expected_policy": "无业务保留要求的快照应在维护窗口删除或合并。"},
            "affected_components": [target.object_name],
            "recommended_action_zh": "确认快照用途、创建时间和业务保留要求；无保留必要时在维护窗口删除或合并。",
        }

    def _evidence_vsl_vm_012(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        vcpu_count = props.get("vcpu_count")
        max_vcpu_count = props.get("max_vcpu_count") or 8
        return {
            "evidence_summary_zh": f"虚拟机 {target.object_name} 配置 {vcpu_count} vCPU，高于当前阈值 {max_vcpu_count}，可能增加调度等待风险。",
            "observed_detail": {
                "vm_name": target.object_name,
                "vcpu_count": vcpu_count,
                "threshold": max_vcpu_count,
                "power_state": props.get("power_state"),
                "cpu_ready_percent": props.get("cpu_ready_percent"),
            },
            "expected_detail": {"threshold": max_vcpu_count, "expected_policy": f"普通虚拟机 vCPU 数量建议不超过 {max_vcpu_count}，超大规格需结合业务压测确认。"},
            "affected_components": [target.object_name],
            "recommended_action_zh": "复核业务 CPU 使用率和 CPU Ready，必要时下调 vCPU 数量并观察性能。",
        }

    def _evidence_vsl_vm_015(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        version = props.get("hardware_version")
        number = props.get("hardware_version_number")
        min_version = props.get("min_hardware_version") or 15
        current = self._text(version) if version else f"vmx-{self._text(number)}"
        return {
            "evidence_summary_zh": f"虚拟机硬件版本 {current} 低于建议基线 vmx-{min_version}。",
            "observed_detail": {"vm_name": target.object_name, "hardware_version": version, "hardware_version_number": number, "expected_min_version": min_version},
            "expected_detail": {"expected_min_version": min_version, "expected_policy": f"虚拟硬件版本建议不低于 vmx-{min_version}，升级前需确认客户机兼容性。"},
            "affected_components": [target.object_name],
            "recommended_action_zh": "在确认操作系统和业务兼容后，规划维护窗口升级虚拟硬件版本。",
        }

    def _evidence_vsl_cl_010(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        models = props.get("host_cpu_models") or []
        count = props.get("host_cpu_model_distinct_count")
        return {
            "evidence_summary_zh": f"集群 {target.object_name} 内识别到 {count} 种主机 CPU 型号。",
            "observed_detail": {"cluster_name": target.object_name, "host_cpu_model_distinct_count": count, "host_cpu_models": models},
            "expected_detail": {"host_cpu_model_distinct_count": 1, "expected_policy": "同一集群建议保持 CPU 型号一致，或通过 EVC 统一兼容基线。"},
            "affected_components": models or [target.object_name],
            "recommended_action_zh": "核对 EVC 模式和硬件扩容计划，必要时统一 CPU 兼容基线。",
        }

    def _evidence_vsl_cl_011(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        ratio = props.get("host_memory_capacity_skew_ratio")
        values = props.get("host_memory_capacity_gb_values") or []
        threshold = props.get("max_memory_skew_ratio") or 50
        return {
            "evidence_summary_zh": f"集群 {target.object_name} 主机内存容量差异比例为 {self._text(ratio)}%，高于建议阈值 {threshold}%。",
            "observed_detail": {"cluster_name": target.object_name, "host_memory_capacity_skew_ratio": ratio, "host_memory_capacity_gb_values": values},
            "expected_detail": {"max_memory_skew_ratio": threshold, "expected_policy": "同一集群内主机内存容量差异建议控制在阈值内。"},
            "affected_components": [f"{item} GB" for item in values] or [target.object_name],
            "recommended_action_zh": "结合 HA/DRS 容量评估，规划主机规格统一或业务分组。",
        }

    def _evidence_vsl_cl_012(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        count = props.get("drs_disabled_rule_count")
        rules = props.get("drs_disabled_rules") or []
        return {
            "evidence_summary_zh": f"集群 {target.object_name} 存在 {count} 条已停用 DRS 规则。",
            "observed_detail": {"cluster_name": target.object_name, "drs_disabled_rule_count": count, "drs_disabled_rules": rules},
            "expected_detail": {"drs_disabled_rule_count": 0, "expected_policy": "DRS 规则应保持有效或清理无效历史规则。"},
            "affected_components": rules or [target.object_name],
            "recommended_action_zh": "复核停用规则的业务意义，启用仍需使用的规则或清理无效规则。",
        }

    def _evidence_vsl_host_014(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        targets = props.get("syslog_targets") or []
        return {
            "evidence_summary_zh": f"主机 {target.object_name} 未配置远程 Syslog 目标。",
            "observed_detail": {"host_name": target.object_name, "syslog_configured": props.get("syslog_configured"), "syslog_targets": targets},
            "expected_detail": {"syslog_configured": True, "expected_policy": "ESXi 主机应配置企业统一 Syslog 目标。"},
            "affected_components": [target.object_name],
            "recommended_action_zh": "配置 Syslog.global.logHost，并验证日志平台能收到 ESXi 日志。",
        }

    def _evidence_vsl_host_015(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        return {
            "evidence_summary_zh": f"主机 {target.object_name} 防火墙默认入站策略未设置为阻断。",
            "observed_detail": {"host_name": target.object_name, "firewall_default_incoming_blocked": props.get("firewall_default_incoming_blocked")},
            "expected_detail": {"firewall_default_incoming_blocked": True, "expected_policy": "ESXi 防火墙默认入站策略建议为阻断，仅开放必要服务。"},
            "affected_components": [target.object_name],
            "recommended_action_zh": "复核必要服务规则后，将默认入站策略调整为阻断。",
        }

    def _evidence_vsl_ds_007(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        issues = props.get("datastore_multipath_issue_count")
        detail = props.get("datastore_path_issue_detail") or []
        return {
            "evidence_summary_zh": f"数据存储 {target.object_name} 存在 {issues} 条异常存储路径。",
            "observed_detail": {"datastore_name": target.object_name, "datastore_multipath_issue_count": issues, "datastore_path_issue_detail": detail},
            "expected_detail": {"datastore_multipath_issue_count": 0, "expected_policy": "存储路径不应处于 dead、error 或 off 状态。"},
            "affected_components": [self._path_component(item) for item in detail] or [target.object_name],
            "recommended_action_zh": "检查 HBA、SAN 交换机、存储目标端口和多路径策略，恢复异常路径后复查。",
            "fault_detail": self._path_detail_text(detail),
        }

    def _evidence_vsl_ds_008(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        count = props.get("datastore_active_path_count")
        threshold = props.get("min_datastore_active_paths") or 2
        return {
            "evidence_summary_zh": f"数据存储 {target.object_name} 当前活动路径数量为 {count}，低于建议值 {threshold}。",
            "observed_detail": {"datastore_name": target.object_name, "datastore_active_path_count": count, "datastore_total_path_count": props.get("datastore_total_path_count")},
            "expected_detail": {"min_datastore_active_paths": threshold, "expected_policy": "共享 VMFS 数据存储建议保留至少两条活动路径。"},
            "affected_components": [target.object_name],
            "recommended_action_zh": "补齐主机到存储的链路、分区和多路径配置。",
        }

    def _evidence_vsl_ds_013(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        ratio = props.get("thin_provisioning_overcommit_ratio")
        threshold = props.get("max_thin_overcommit_ratio") or 150
        return {
            "evidence_summary_zh": f"数据存储 {target.object_name} Thin Provisioning 超分比例为 {self._text(ratio)}%，高于建议阈值 {threshold}%。",
            "observed_detail": {"datastore_name": target.object_name, "thin_provisioning_overcommit_ratio": ratio},
            "expected_detail": {"max_thin_overcommit_ratio": threshold, "expected_policy": "Thin Provisioning 超分比例应控制在容量管理阈值内。"},
            "affected_components": [target.object_name],
            "recommended_action_zh": "清理无效空间、迁移虚拟机或扩容数据存储，并配置容量告警。",
        }

    def _evidence_vsl_ds_018(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        version = props.get("datastore_filesystem_version")
        fs_type = props.get("datastore_filesystem_type")
        return {
            "evidence_summary_zh": f"数据存储 {target.object_name} 文件系统为 {self._text(fs_type)} {self._text(version)}，低于当前建议基线。",
            "observed_detail": {"datastore_name": target.object_name, "datastore_filesystem_type": fs_type, "datastore_filesystem_version": version},
            "expected_detail": {"expected_policy": "VMFS 数据存储建议使用 VMFS 6 或更高的当前基线。"},
            "affected_components": [target.object_name],
            "recommended_action_zh": "规划新建当前基线数据存储，并通过迁移逐步替换旧版文件系统。",
        }

    def _evidence_vsl_vm_007(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        depth = props.get("snapshot_chain_depth")
        threshold = props.get("max_snapshot_chain_depth") or 2
        snapshots = self._snapshot_evidence_details(props)
        return {
            "evidence_summary_zh": f"虚拟机 {target.object_name} 快照链深度为 {depth}，高于建议阈值 {threshold}；已采集 {len(snapshots)} 条快照明细。",
            "observed_detail": {"vm_name": target.object_name, "snapshot_chain_depth": depth, "snapshots": snapshots},
            "expected_detail": {"max_snapshot_chain_depth": threshold, "expected_policy": "快照链深度建议控制在阈值内，并及时合并无用快照。"},
            "affected_components": [target.object_name],
            "recommended_action_zh": "确认快照用途后删除或合并无用快照，并观察数据存储空间。",
        }

    def _evidence_vsl_vm_009(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        count = props.get("nonpersistent_disk_count")
        modes = props.get("disk_provisioning_modes") or []
        return {
            "evidence_summary_zh": f"虚拟机 {target.object_name} 存在 {count} 块非持久化磁盘。",
            "observed_detail": {"vm_name": target.object_name, "nonpersistent_disk_count": count, "disk_provisioning_modes": modes},
            "expected_detail": {"nonpersistent_disk_count": 0, "expected_policy": "业务数据盘不应使用非持久化磁盘模式。"},
            "affected_components": modes or [target.object_name],
            "recommended_action_zh": "核对磁盘用途，业务数据盘应调整为持久化模式并验证应用数据。",
        }

    def _evidence_vsl_vm_013(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        nodes = props.get("numa_affinity_nodes") or []
        return {
            "evidence_summary_zh": f"虚拟机 {target.object_name} 配置了 NUMA 节点亲和。",
            "observed_detail": {"vm_name": target.object_name, "numa_affinity_configured": props.get("numa_affinity_configured"), "numa_affinity_nodes": nodes},
            "expected_detail": {"numa_affinity_configured": False, "expected_policy": "无明确性能依据时不建议固定 NUMA 节点。"},
            "affected_components": nodes or [target.object_name],
            "recommended_action_zh": "复核 NUMA 亲和配置的必要性，无明确性能依据时建议移除。",
        }

    def _evidence_vsl_vm_014(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        status = props.get("tools_install_status")
        return {
            "evidence_summary_zh": f"虚拟机 {target.object_name} 未安装 VMware Tools 或 open-vm-tools。",
            "observed_detail": {"vm_name": target.object_name, "vmware_tools_installed": props.get("vmware_tools_installed"), "tools_install_status": status},
            "expected_detail": {"vmware_tools_installed": True, "expected_policy": "支持的客户机应安装 VMware Tools 或 open-vm-tools。"},
            "affected_components": [target.object_name],
            "recommended_action_zh": "为支持的客户机安装 VMware Tools 或 open-vm-tools，并验证 Tools 状态。",
        }

    def _evidence_vsl_sec_002(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        count = props.get("vcenter_admin_account_count")
        principals = props.get("vcenter_admin_principals") or []
        threshold = props.get("max_vcenter_admin_accounts") or 5
        return {
            "evidence_summary_zh": f"vCenter 当前识别到 {count} 个管理员权限主体，高于建议阈值 {threshold}。",
            "observed_detail": {"vcenter_admin_account_count": count, "vcenter_admin_principals": principals},
            "expected_detail": {"max_vcenter_admin_accounts": threshold, "expected_policy": "管理员权限应按最小权限原则控制数量。"},
            "affected_components": principals or [target.object_name],
            "recommended_action_zh": "复核管理员权限分配，移除不必要账号，优先使用职责分离的角色和组。",
        }

    def _evidence_vsl_vc_015(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        count = props.get("task_backlog_count")
        items = props.get("task_backlog_items") or []
        threshold = props.get("max_task_backlog_count") or 20
        return {
            "evidence_summary_zh": f"vCenter 当前运行中或排队任务数量为 {count}，高于建议阈值 {threshold}。",
            "observed_detail": {"task_backlog_count": count, "task_backlog_items": items},
            "expected_detail": {"max_task_backlog_count": threshold, "expected_policy": "运行中或排队任务数量应保持在可管理范围内。"},
            "affected_components": [item.get("entity") or item.get("name") or target.object_name for item in items] or [target.object_name],
            "recommended_action_zh": "查看积压任务详情，确认是否为计划内批量操作；异常任务需定位对象和相关服务状态。",
            "fault_detail": self._task_detail_text(items),
        }

    def _evidence_vsl_host_008(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        days = props.get("host_certificate_days_remaining")
        not_after = props.get("host_certificate_not_after")
        subject = props.get("host_certificate_subject") or "未采集"
        issuer = props.get("host_certificate_issuer") or "未采集"
        fingerprint = props.get("host_certificate_fingerprint") or "未采集"
        probe_method = props.get("host_certificate_probe_method") or "未采集"
        threshold = props.get("host_certificate_warning_days") or 90
        return {
            "evidence_summary_zh": f"主机 {target.object_name} 证书剩余有效期为 {self._text(days)} 天，到期时间为 {self._text(not_after)}。",
            "observed_detail": {
                "host_name": target.object_name,
                "host_certificate_days_remaining": days,
                "host_certificate_not_after": not_after,
                "host_certificate_subject": subject,
                "host_certificate_issuer": issuer,
                "host_certificate_fingerprint": fingerprint,
                "host_certificate_probe_method": probe_method,
                "host_certificate_probe_status": props.get("host_certificate_probe_status"),
            },
            "expected_detail": {"host_certificate_warning_days": threshold, "expected_policy": f"ESXi 主机证书剩余有效期应大于 {threshold} 天。"},
            "affected_components": [target.object_name],
            "recommended_action_zh": "在证书到期前更新 ESXi 主机证书，并确认 vCenter 与主机连接正常。",
            "fault_detail": f"主机：{target.object_name}；主体：{subject}；签发者：{issuer}；到期时间：{self._text(not_after)}；剩余天数：{self._text(days)}；指纹：{fingerprint}；探测方式：{probe_method}",
        }

    def _evidence_vsl_host_023(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        assigned = props.get("host_license_assigned")
        evaluation = props.get("host_license_is_evaluation")
        days = props.get("host_license_expiration_days")
        expiration_date = props.get("host_license_expiration_date")
        license_name = props.get("host_license_name") or "未采集"
        edition = props.get("host_license_edition") or "未采集"
        state = "未分配 License" if assigned is False else "评估版 License" if evaluation is True else "授权有效"
        if isinstance(days, (int, float)) and days >= 999999:
            remaining = "永久授权"
        elif days is None:
            remaining = "未采集"
        else:
            remaining = f"剩余 {days} 天"
        return {
            "evidence_summary_zh": f"主机 {target.object_name} 当前 License 状态为{state}，{remaining}。",
            "observed_detail": {
                "host_name": target.object_name,
                "host_license_assigned": assigned,
                "host_license_name": license_name,
                "host_license_edition": edition,
                "host_license_is_evaluation": evaluation,
                "host_license_expiration_date": expiration_date,
                "host_license_expiration_days": days,
                "host_license_probe_status": props.get("host_license_probe_status"),
            },
            "expected_detail": {"expected_policy": "ESXi 主机应分配正式有效 License，且剩余有效期大于 90 天或为永久授权。"},
            "affected_components": [target.object_name],
            "recommended_action_zh": "导入并分配正式有效 License，确认授权状态正常后复跑巡检。",
            "fault_detail": f"主机：{target.object_name}；授权名称：{license_name}；版本：{edition}；状态：{state}；到期：{self._text(expiration_date)}；{remaining}",
        }

    def _evidence_vsl_host_013(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        configured = props.get("host_log_core_dump_configured")
        detail = props.get("host_log_core_dump_detail") or "未采集到配置详情"
        return {
            "evidence_summary_zh": f"主机 {target.object_name} 日志与核心转储配置状态为{'完整' if configured else '不完整'}。",
            "observed_detail": {"host_name": target.object_name, "host_log_core_dump_configured": configured, "host_log_core_dump_detail": detail},
            "expected_detail": {"host_log_core_dump_configured": True, "expected_policy": "ESXi 主机应配置远程或持久化日志，并配置可用核心转储目标。"},
            "affected_components": [target.object_name],
            "recommended_action_zh": "补齐 Syslog 或持久化日志目录，并确认核心转储目标可用。",
            "fault_detail": f"主机：{target.object_name}；{detail}",
        }

    def _evidence_vsl_net_003(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        count = props.get("pnic_error_count")
        detail = props.get("pnic_error_detail") or []
        threshold = props.get("max_pnic_error_count") or 0
        return {
            "evidence_summary_zh": f"主机 {target.object_name} 物理网卡错误或丢包计数为 {self._text(count)}，高于建议值 {threshold}。",
            "observed_detail": {"host_name": target.object_name, "pnic_error_count": count, "pnic_error_detail": detail},
            "expected_detail": {"max_pnic_error_count": threshold, "expected_policy": "物理网卡错误和丢包计数应保持为 0 或不持续增长。"},
            "affected_components": [item.get("counter") or target.object_name for item in detail] or [target.object_name],
            "recommended_action_zh": "检查物理网卡、线缆、模块和交换机端口，修复后观察计数是否继续增长。",
            "fault_detail": self._counter_detail_text(detail, target.object_name, count),
        }

    def _evidence_vsl_vm_018(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        days = props.get("powered_off_days")
        threshold = props.get("max_powered_off_days") or 90
        power_state = props.get("power_state")
        return {
            "evidence_summary_zh": f"虚拟机 {target.object_name} 当前电源状态为 {self._text(power_state)}，关机持续时间为 {self._text(days)} 天。",
            "observed_detail": {"vm_name": target.object_name, "power_state": power_state, "powered_off_days": days},
            "expected_detail": {"max_powered_off_days": threshold, "expected_policy": f"虚拟机关机持续时间建议不超过 {threshold} 天，超过后应确认保留必要性。"},
            "affected_components": [target.object_name],
            "recommended_action_zh": "联系业务确认保留必要性，无需保留的虚拟机按流程归档或删除。",
            "fault_detail": f"虚拟机：{target.object_name}；电源状态：{self._text(power_state)}；关机持续时间：{self._text(days)} 天；阈值：{threshold} 天",
        }

    def _evidence_vsl_sec_008(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        count = props.get("role_permission_inheritance_issue_count")
        issues = props.get("role_permission_inheritance_issues") or []
        threshold = props.get("max_inherited_admin_permissions") or 3
        return {
            "evidence_summary_zh": f"vCenter 管理员级继承权限主体数量为 {self._text(count)}，高于建议阈值 {threshold}。",
            "observed_detail": {"role_permission_inheritance_issue_count": count, "role_permission_inheritance_issues": issues},
            "expected_detail": {"max_inherited_admin_permissions": threshold, "expected_policy": "管理员级继承权限应按最小权限原则控制数量和范围。"},
            "affected_components": [item.get("principal") or target.object_name for item in issues] or [target.object_name],
            "recommended_action_zh": "复核管理员级权限继承关系，移除不必要的继承授权或改用更细粒度角色。",
            "fault_detail": self._permission_detail_text(issues),
        }

    def _evidence_vsl_net_015(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        issues = props.get("portgroup_security_issues") or []
        count = props.get("portgroup_security_issue_count")
        return {
            "evidence_summary_zh": f"主机 {target.object_name} 发现 {self._text(count)} 项端口组、vSwitch 或 vDS 安全策略需要复核。",
            "observed_detail": {
                "host_name": target.object_name,
                "portgroup_security_issue_count": count,
                "portgroup_security_high_risk_count": props.get("portgroup_security_high_risk_count"),
                "portgroup_security_issues": issues,
                "portgroup_security_collector_source": props.get("portgroup_security_collector_source"),
            },
            "expected_detail": {"recommended_policy": "混杂模式、Forged Transmits 和 MAC Changes 非必要场景建议保持禁用。"},
            "affected_components": [
                " / ".join(
                    str(issue.get(key) or "")
                    for key in ("switch", "portgroup", "policy")
                    if issue.get(key)
                )
                for issue in issues
            ]
            or [target.object_name],
            "recommended_action_zh": "核对命中的端口组、vSwitch 或 vDS 用途，非抓包、网络虚拟设备或厂商明确要求场景建议关闭放宽的安全策略。",
            "fault_detail": self._security_policy_detail_text(issues),
        }

    def _evidence_vsl_vm_023(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        local_datastores = props.get("local_datastore_names") or []
        return {
            "evidence_summary_zh": f"虚拟机 {target.object_name} 位于本地 Datastore：{self._join_values(local_datastores)}。",
            "observed_detail": {
                "vm_name": target.object_name,
                "datastore_names": props.get("datastore_names") or [],
                "local_datastore_names": local_datastores,
                "vm_on_local_datastore": props.get("vm_on_local_datastore"),
                "local_datastore_collector_source": props.get("local_datastore_collector_source"),
            },
            "expected_detail": {"recommended_policy": "业务虚拟机建议放置在符合规划的共享或业务 Datastore 上。"},
            "affected_components": [target.object_name, *[str(item) for item in local_datastores]],
            "recommended_action_zh": "确认该虚拟机业务等级和本地存储使用原因，必要时迁移到共享 Datastore，并复核备份、迁移和故障恢复策略。",
        }

    def _evidence_vsl_host_024(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        issues = props.get("host_hardware_health_issues") or []
        count = props.get("host_hardware_health_issue_count")
        return {
            "evidence_summary_zh": f"主机 {target.object_name} 发现 {self._text(count)} 项硬件健康状态异常。",
            "observed_detail": {
                "host_name": target.object_name,
                "host_hardware_health_issue_count": count,
                "host_hardware_health_red_count": props.get("host_hardware_health_red_count"),
                "host_hardware_health_issues": issues,
                "hardware_health_collector_source": props.get("hardware_health_collector_source"),
            },
            "expected_detail": {"recommended_policy": "硬件传感器和硬件健康摘要应保持 Green 或正常状态。"},
            "affected_components": [str(item.get("component") or target.object_name) for item in issues] or [target.object_name],
            "recommended_action_zh": "结合 iDRAC、iLO、XClarity 等硬件管理平台复核传感器状态，必要时联系厂商处理。",
            "fault_detail": self._hardware_health_detail_text(issues),
        }

    def _evidence_vsl_ds_020(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        used_percent = props.get("vsan_used_percent")
        free_gb = props.get("vsan_free_gb")
        capacity_gb = props.get("datastore_capacity_gb")
        issue_count = props.get("vsan_issue_count")
        return {
            "evidence_summary_zh": (
                f"vSAN Datastore {target.object_name} 采集到 {self._text(issue_count)} 项 vSAN 健康关注项，"
                f"已用率 {self._percent_text(used_percent)}，剩余容量 {self._gb_text(free_gb)}。"
            ),
            "observed_detail": {
                "datastore_name": target.object_name,
                "datastore_is_vsan": props.get("datastore_is_vsan"),
                "vsan_api_status": props.get("vsan_api_status"),
                "vsan_collection_error": props.get("vsan_collection_error"),
                "vsan_cluster_enabled": props.get("vsan_cluster_enabled"),
                "vsan_issue_count": issue_count,
                "vsan_health_issue_count": props.get("vsan_health_issue_count"),
                "vsan_disk_health_issue_count": props.get("vsan_disk_health_issue_count"),
                "vsan_object_health_issue_count": props.get("vsan_object_health_issue_count"),
                "vsan_resync_object_count": props.get("vsan_resync_object_count"),
                "vsan_resync_bytes": props.get("vsan_resync_bytes"),
                "vsan_used_percent": used_percent,
                "vsan_free_gb": free_gb,
                "datastore_capacity_gb": capacity_gb,
                "vsan_capacity_issue": props.get("vsan_capacity_issue"),
                "vsan_cluster_names": props.get("vsan_cluster_names") or [],
                "vsan_health_issues": props.get("vsan_health_issues") or [],
                "vsan_disk_health_issues": props.get("vsan_disk_health_issues") or [],
                "vsan_object_health_issues": props.get("vsan_object_health_issues") or [],
                "vsan_collector_source": props.get("vsan_collector_source"),
            },
            "expected_detail": {"recommended_policy": "vSAN Datastore 容量、集群启用状态、磁盘、对象和重同步状态应保持健康，无活动异常项。"},
            "affected_components": [target.object_name],
            "recommended_action_zh": "结合 vSAN Skyline Health、对象合规、磁盘组和重同步任务复核异常来源，必要时清理数据、迁移负载、修复磁盘组或规划扩容。",
        }

    def _evidence_vsl_vm_024(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        actual = props.get("guest_os_actual")
        configured = props.get("guest_os_configured")
        return {
            "evidence_summary_zh": (
                f"虚拟机 {target.object_name} 实际操作系统为 {self._text(actual)}，"
                f"配置操作系统为 {self._text(configured)}。"
            ),
            "observed_detail": {
                "vm_name": target.object_name,
                "guest_os_actual": actual,
                "guest_os_configured": configured,
                "guest_os_tools_running": props.get("guest_os_tools_running"),
                "guest_os_mismatch": props.get("guest_os_mismatch"),
                "guest_os_collector_source": props.get("guest_os_collector_source"),
            },
            "expected_detail": {"recommended_policy": "虚拟机配置 OS 应与客户机实际操作系统保持一致。"},
            "affected_components": [target.object_name],
            "recommended_action_zh": "核对实际操作系统和业务归属，必要时在维护窗口修正虚拟机客户机操作系统配置并复查 VMware Tools 状态。",
        }

    def _evidence_vsl_host_025(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        policy = props.get("host_power_policy")
        return {
            "evidence_summary_zh": f"主机 {target.object_name} 当前电源策略为 {self._text(policy)}。",
            "observed_detail": {
                "host_name": target.object_name,
                "host_power_policy": policy,
                "host_power_policy_high_performance": props.get("host_power_policy_high_performance"),
                "power_policy_collector_source": props.get("power_policy_collector_source"),
            },
            "expected_detail": {"recommended_policy": "生产主机建议采用符合客户性能要求的高性能电源策略。"},
            "affected_components": [target.object_name],
            "recommended_action_zh": "结合客户性能策略和业务负载确认是否需要调整为高性能电源策略，调整后观察业务表现。",
        }

    def _evidence_vsl_ds_019(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        clusters = props.get("datastore_cluster_names") or []
        return {
            "evidence_summary_zh": (
                f"Datastore {target.object_name} 被 {self._text(props.get('datastore_cluster_count'))} 个集群挂载："
                f"{self._join_values(clusters)}。"
            ),
            "observed_detail": {
                "datastore_name": target.object_name,
                "datastore_cross_cluster_shared": props.get("datastore_cross_cluster_shared"),
                "datastore_cluster_count": props.get("datastore_cluster_count"),
                "datastore_cluster_names": clusters,
                "datastore_host_count": props.get("datastore_host_count"),
                "datastore_host_names": props.get("datastore_host_names") or [],
                "datastore_is_vsan": props.get("datastore_is_vsan"),
                "datastore_cluster_collector_source": props.get("datastore_cluster_collector_source"),
            },
            "expected_detail": {"recommended_policy": "跨集群共享 Datastore 应有明确规划、访问边界和变更记录。"},
            "affected_components": [target.object_name, *[str(item) for item in clusters]],
            "recommended_action_zh": "结合存储规划确认该 Datastore 的共享范围是否符合设计，必要时补充访问控制、命名或例外说明。",
        }

    def _evidence_vsl_host_026(self, target: CanonicalObject, props: dict[str, Any]) -> dict[str, Any]:
        cpu_ratio = props.get("host_vcpu_to_pcpu_ratio")
        memory_ratio = props.get("host_memory_allocation_ratio")
        return {
            "evidence_summary_zh": (
                f"主机 {target.object_name} vCPU:pCPU 比例为 {self._ratio_text(cpu_ratio)}，"
                f"内存分配比例为 {self._percent_text(None if memory_ratio is None else float(memory_ratio) * 100)}。"
            ),
            "observed_detail": {
                "host_name": target.object_name,
                "host_pcpu_count": props.get("host_pcpu_count"),
                "host_memory_capacity_mb": props.get("host_memory_capacity_mb"),
                "host_vcpu_allocated": props.get("host_vcpu_allocated"),
                "host_memory_allocated_mb": props.get("host_memory_allocated_mb"),
                "host_vcpu_to_pcpu_ratio": cpu_ratio,
                "host_memory_allocation_ratio": memory_ratio,
                "host_resource_overcommit": props.get("host_resource_overcommit"),
                "host_resource_collector_source": props.get("host_resource_collector_source"),
            },
            "expected_detail": {
                "recommended_policy": (
                    f"建议结合 CPU Ready、内存 balloon/swap 和业务峰值确认容量，"
                    f"当前观察阈值为 vCPU:pCPU {props.get('host_cpu_overcommit_ratio_warning') or 4}:1、"
                    f"内存分配比例 {props.get('host_memory_overcommit_ratio_warning') or 1.5}。"
                )
            },
            "affected_components": [target.object_name],
            "recommended_action_zh": "结合性能指标和容量增长计划评估是否需要回收、迁移或扩容，避免资源争用影响高峰期业务。",
        }

    def _text(self, value: Any) -> str:
        if value is None:
            return "未采集"
        return str(value)

    def _alarm_component(self, alarm: dict[str, Any]) -> str:
        entity = alarm.get("entity_name") or ""
        name = alarm.get("alarm_name") or ""
        if entity and name:
            return f"{entity}（{name}）"
        return entity or name

    def _alarm_detail_text(self, alarms: list[dict[str, Any]]) -> str:
        if not alarms:
            return "当前采集到红色告警数量，但未返回具体告警名称，请在 vCenter 告警视图中逐项核查。"
        lines = []
        for alarm in alarms:
            name = alarm.get("alarm_name") or "未命名告警"
            entity = alarm.get("entity_name") or "未采集对象"
            status = alarm.get("status") or "红色"
            lines.append(f"{name}，对象：{entity}，状态：{status}")
        return "；".join(lines)

    def _path_component(self, path: dict[str, Any]) -> str:
        return " / ".join(str(path.get(key) or "") for key in ("host", "adapter", "lun", "target") if path.get(key))

    def _path_detail_text(self, paths: list[dict[str, Any]]) -> str:
        if not paths:
            return "当前未列出具体异常路径，请在主机存储路径视图中复核。"
        lines = []
        for path in paths:
            lines.append(
                f"主机：{path.get('host') or '未采集'}，适配器：{path.get('adapter') or '未采集'}，"
                f"LUN：{path.get('lun') or '未采集'}，目标：{path.get('target') or '未采集'}，状态：{path.get('state') or '未采集'}"
            )
        return "；".join(lines)

    def _task_detail_text(self, tasks: list[dict[str, Any]]) -> str:
        if not tasks:
            return "当前仅采集到任务数量，未列出具体任务。"
        return "；".join(
            f"任务：{item.get('name') or '未命名'}，对象：{item.get('entity') or '未采集'}，状态：{item.get('state') or '未采集'}"
            for item in tasks
        )

    def _counter_detail_text(self, detail: list[dict[str, Any]], object_name: str, count: Any) -> str:
        if not detail:
            return f"主机：{object_name}；物理网卡错误或丢包计数：{self._text(count)}。"
        return "；".join(f"{item.get('counter') or '计数器'}：{item.get('value')}" for item in detail)

    def _permission_detail_text(self, issues: list[dict[str, Any]]) -> str:
        if not issues:
            return "当前仅采集到继承权限数量，未列出具体授权主体。"
        return "；".join(
            f"主体：{item.get('principal') or '未采集'}，角色：{item.get('role') or '未采集'}，继承对象：{item.get('entity') or '未采集'}"
            for item in issues
        )

    def _join_values(self, values: list[Any]) -> str:
        return "、".join(str(value) for value in values if value not in (None, "")) or "未采集"

    def _percent_text(self, value: Any) -> str:
        if value is None or value == "":
            return "未采集"
        try:
            return f"{float(value):.1f}%"
        except (TypeError, ValueError):
            return self._text(value)

    def _gb_text(self, value: Any) -> str:
        if value is None or value == "":
            return "未采集"
        try:
            return f"{float(value):.1f} GB"
        except (TypeError, ValueError):
            return self._text(value)

    def _ratio_text(self, value: Any) -> str:
        if value is None or value == "":
            return "未采集"
        try:
            return f"{float(value):.2f}:1"
        except (TypeError, ValueError):
            return self._text(value)

    def _security_policy_detail_text(self, issues: list[dict[str, Any]]) -> str:
        if not issues:
            return "当前仅采集到安全策略命中数量，未列出具体端口组。"
        return "；".join(
            f"交换机/vDS：{item.get('switch') or '未采集'}，端口组：{item.get('portgroup') or '未采集'}，"
            f"策略项：{item.get('policy') or '未采集'}，当前状态：{item.get('current_value') or '未采集'}"
            for item in issues
        )

    def _hardware_health_detail_text(self, issues: list[dict[str, Any]]) -> str:
        if not issues:
            return "当前仅采集到硬件健康异常数量，未列出具体传感器。"
        return "；".join(
            f"组件：{item.get('component') or '未采集'}，状态：{item.get('status') or '未采集'}"
            for item in issues
        )
