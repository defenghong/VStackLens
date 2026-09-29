from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from math import isfinite
from typing import Any

from vstacklens.deep.contracts import (
    CapabilityStatus,
    DeepAnalysisScope,
    DeepCategory,
    DeepDataset,
    DeepDiagnosticRecord,
    DeepFinding,
    DeepReport,
    DeepResultStatus,
    DeepRuleDefinition,
    DeepRuleResult,
    DeepSource,
    DeepWindow,
    DatasetRecord,
    FindingScope,
    ScopeType,
    ThresholdRegistry,
    evidence_ref,
    finding_id,
    now_utc_iso,
)

CATEGORY_LABELS = {
    DeepCategory.CURRENT_RISK: "当前隐患",
    DeepCategory.HISTORICAL_HEALTH: "历史健康",
    DeepCategory.TREND: "趋势",
}


BUILTIN_DEEP_RULES: tuple[DeepRuleDefinition, ...] = (
    DeepRuleDefinition(
        rule_id="SEC-DEEP-003",
        title="vCenter 或 ESXi 管理证书到期风险",
        category=DeepCategory.CURRENT_RISK,
        dimension_key="certificate_expiry",
        record_kind="config",
        threshold_id="TH-LIFECYCLE-EXPIRY-WINDOW",
        analysis_kind="certificate_expiry",
        verification_guidance="在 vSphere Client 的 vCenter 与主机证书页面核对有效期至字段，并确认是否已有自动轮换或退役安排。",
        disconfirming_conditions=["客户已有自动化证书轮换流程", "受影响主机将在到期前退役"],
        diagnosis_boundary="VMware 侧 TLS 端点或主机证书字段显示管理证书有效期；本次未获取外部 CA 或客户证书轮换系统状态，因此不对轮换流程本身作结论。读取失败时不判证书正常。",
        impact="medium",
        urgency="planned",
        display_priority="P2",
    ),
    DeepRuleDefinition(
        rule_id="VM-DEEP-001",
        title="虚拟机存在老化快照",
        category=DeepCategory.CURRENT_RISK,
        dimension_key="snapshot_age",
        record_kind="config",
        verification_guidance="在 vSphere Client 中核对虚拟机快照名称、创建时间、父子关系和业务保留要求，再决定是否需要合并或删除。",
        disconfirming_conditions=["快照有明确的业务保留期限", "虚拟机属于厂商设备且删除快照不受支持"],
        diagnosis_boundary="VMware 侧证据显示快照存在及其年龄；本次未获取业务变更单，因此不判断该快照是否仍有业务用途。",
        display_priority="P2",
    ),
    DeepRuleDefinition(
        rule_id="SEC-DEEP-004",
        title="许可证到期或容量状态需要复核",
        category=DeepCategory.CURRENT_RISK,
        dimension_key="license_state",
        record_kind="config",
        threshold_id="TH-LIFECYCLE-EXPIRY-WINDOW",
        analysis_kind="license_state",
        requires=["lifecycle.license"],
        verification_guidance="在 vCenter 的管理许可页面核对许可证类型、已用/总容量和有效期，并与客户购买及续期记录确认。",
        disconfirming_conditions=["许可证由集中授权平台统一管理且本次快照未包含其状态"],
        diagnosis_boundary="本次仅依据 vCenter 可读取的许可证数量、评估状态、到期日和已用/总容量；不读取或输出许可证密钥，也不判断采购合同或外部授权平台状态。许可证读取失败、空结果或字段不全不会判为正常。",
        display_priority="P3",
    ),
    DeepRuleDefinition(
        rule_id="LIFE-DEEP-002",
        title="ESXi 版本或 Build 漂移",
        category=DeepCategory.CURRENT_RISK,
        dimension_key="esxi_version_build_drift",
        scope_type=ScopeType.CLUSTER,
        record_kind="config",
        verification_guidance="在集群主机清单中核对 ESXi 版本和 Build，确认差异是否由滚动升级窗口或兼容性要求造成。",
        disconfirming_conditions=["差异来自已批准的滚动升级窗口", "集群包含明确隔离的硬件代际或兼容性边界"],
        diagnosis_boundary="VMware 侧主机版本/Build 不一致；本次未执行升级兼容性校验，也不替代 HCL/固件驱动验证。",
        display_priority="P2",
    ),
    DeepRuleDefinition(
        rule_id="CL-DEEP-001",
        title="集群主机基础配置存在漂移",
        category=DeepCategory.CURRENT_RISK,
        dimension_key="cluster_config_drift",
        scope_type=ScopeType.CLUSTER,
        record_kind="config",
        analysis_kind="host_config_drift",
        verification_guidance="在集群内逐台主机核对 NTP、DNS 和已配置的 Syslog 目标状态；MTU、VLAN、Teaming、上联和 Datastore 可见性分别查看网络及存储证据。",
        disconfirming_conditions=["差异由明确的网络分区或维护窗口设计导致", "集群并非同一业务配置边界"],
        diagnosis_boundary="VMware 侧只读属性显示同一集群内 NTP、DNS 或 Syslog 配置状态不一致；Syslog 目标内容不会写入此证据。本次未获取外部交换机和运维变更记录。",
        display_priority="P2",
    ),
    DeepRuleDefinition(
        rule_id="VM-DEEP-002",
        title="虚拟机孤立或不可访问",
        category=DeepCategory.CURRENT_RISK,
        dimension_key="vm_connection_state",
        record_kind="config",
        verification_guidance="在 vSphere Client 中核对虚拟机连接状态、所在主机、Datastore 和最近任务，确认是否为暂时维护或真实孤立/不可访问。",
        disconfirming_conditions=["虚拟机处于计划内维护或迁移窗口", "对象已计划退役但尚未从清单移除"],
        diagnosis_boundary="VMware 侧当前连接状态显示孤立或不可访问；本次未获取业务系统可用性和存储阵列侧日志。",
        display_priority="P1",
    ),
    DeepRuleDefinition(
        rule_id="VM-DEEP-003",
        title="VMware Tools 未运行或状态异常",
        category=DeepCategory.CURRENT_RISK,
        dimension_key="vmware_tools_state",
        record_kind="config",
        verification_guidance="在 vSphere Client 中核对 VMware Tools 运行状态、版本和客户机电源状态，并在客户机内确认服务是否正常。",
        disconfirming_conditions=["客户机不支持 VMware Tools", "虚拟机为临时、测试或厂商设备且已登记例外"],
        diagnosis_boundary="VMware 侧客户机状态显示 Tools 未运行或版本状态异常；本次未进入客户机操作系统验证服务。",
        display_priority="P3",
    ),
    DeepRuleDefinition(
        rule_id="VM-DEEP-004",
        title="虚拟硬件版本漂移",
        category=DeepCategory.CURRENT_RISK,
        dimension_key="vm_hardware_version_drift",
        record_kind="config",
        verification_guidance="在同一集群或业务范围内核对虚拟硬件版本，确认低版本虚拟机是否受兼容性、驱动或迁移策略约束。",
        disconfirming_conditions=["低版本由厂商设备或旧客户机兼容性要求保留", "升级计划已明确排期"],
        diagnosis_boundary="VMware 侧清单显示虚拟硬件版本与环境主流版本不同；本次未判断业务应用兼容性。",
        display_priority="P3",
    ),
    DeepRuleDefinition(
        rule_id="VM-DEEP-006",
        title="虚拟机快照链过深",
        category=DeepCategory.CURRENT_RISK,
        dimension_key="snapshot_chain_depth",
        record_kind="config",
        threshold_id="TH-SNAPSHOT-CHAIN-DEPTH",
        verification_guidance="在 vSphere Client 中展开快照树核对父子层级、创建时间和业务保留要求，确认是否需要合并或重建快照链。",
        disconfirming_conditions=["快照链深度由受支持的备份产品维护", "业务变更窗口明确要求暂时保留链结构"],
        diagnosis_boundary="VMware 侧快照树显示链深度；本次未获取备份系统任务和业务保留策略。",
        display_priority="P2",
    ),
    DeepRuleDefinition(
        rule_id="VM-DEEP-005",
        title="VM Reservation Limit 或 Shares 需复核",
        category=DeepCategory.CURRENT_RISK,
        dimension_key="vm_resource_limit",
        record_kind="config",
        verification_guidance="在虚拟机资源设置中核对 CPU/内存 Limit、Reservation 和 Shares，确认限制是否有明确业务或治理依据。",
        disconfirming_conditions=["Limit 或自定义 Shares 由应用性能隔离策略明确设置", "对象属于厂商设备或已登记资源治理例外"],
        diagnosis_boundary="VMware 侧配置显示显式资源 Limit 或自定义 Shares；Reservation 数值作为复核证据记录，本规则不单凭 Reservation 非零判定异常。",
        display_priority="P2",
    ),
    DeepRuleDefinition(
        rule_id="VM-DEEP-007",
        title="Guest OS 配置与客户机报告不一致",
        category=DeepCategory.CURRENT_RISK,
        dimension_key="guest_os_config_mismatch",
        record_kind="config",
        verification_guidance="在 vSphere Client 中核对虚拟机配置的 Guest OS 类型，并在客户机内确认实际操作系统及 VMware Tools 上报状态。",
        disconfirming_conditions=["Guest OS 在采集期间刚发生升级或重装", "客户机 Tools 清单尚未刷新"],
        diagnosis_boundary="VMware 配置与运行中客户机通过 Tools 报告的名称不一致；本次未判断 Guest OS 版本是否仍受 ESXi 目标版本支持。",
        display_priority="P2",
    ),
    DeepRuleDefinition(
        rule_id="VM-DEEP-008",
        title="Guest OS 支持级别需要复核",
        category=DeepCategory.CURRENT_RISK,
        dimension_key="guest_os_support_level",
        requires=["vm.guest_os.support"],
        record_kind="config",
        analysis_kind="guest_os_support",
        verification_guidance="在 vSphere Client 的虚拟机兼容性信息中核对 Guest OS 标识及支持级别，并与当前 ESXi 主机或集群支持的 Guest OS 描述符比较。",
        disconfirming_conditions=["Guest OS 标识对应的受支持版本与客户机实际安装版本不同", "该虚拟机有已批准的旧版操作系统例外"],
        diagnosis_boundary="依据 vCenter EnvironmentBrowser 针对当前虚拟硬件版本返回的 GuestOsDescriptor.supportLevel；不登录客户机，也不替代操作系统厂商生命周期核验。未列出或接口读取失败时保留证据不足，不推断为不支持。",
        impact="medium",
        urgency="planned",
        display_priority="P2",
    ),
    DeepRuleDefinition(
        rule_id="CL-DEEP-004",
        title="HA 当前配置风险",
        category=DeepCategory.CURRENT_RISK,
        dimension_key="ha_configuration_risk",
        record_kind="config",
        verification_guidance="在集群 HA 配置中核对 Admission Control、心跳 Datastore 数量和隔离响应，并结合业务故障切换要求复核。",
        disconfirming_conditions=["集群为测试环境且 HA 明确关闭", "Admission Control 由外部变更流程管理"],
        diagnosis_boundary="VMware 侧集群配置显示 HA 风险项；本次未执行故障切换测试，也未改变 HA 配置。",
        display_priority="P1",
    ),
    DeepRuleDefinition(
        rule_id="CL-DEEP-005",
        title="DRS 当前配置风险",
        category=DeepCategory.CURRENT_RISK,
        dimension_key="drs_configuration_risk",
        record_kind="config",
        verification_guidance="在集群 DRS 配置中核对自动化级别、启用状态和已禁用规则，确认是否与资源调度策略一致。",
        disconfirming_conditions=["DRS 关闭或规则禁用有明确变更单", "集群业务要求人工调度"],
        diagnosis_boundary="VMware 侧集群配置显示 DRS 风险项；本次未执行迁移或资源压力测试。",
        display_priority="P2",
    ),
    DeepRuleDefinition(
        rule_id="STO-DEEP-003",
        title="当前存储路径异常",
        category=DeepCategory.CURRENT_RISK,
        dimension_key="storage_path_current_issue",
        record_kind="config",
        analysis_kind="storage_path",
        verification_guidance="在主机存储设备和多路径视图中核对异常路径、LUN、HBA 和目标端口，并与 SAN/阵列状态交叉确认。",
        disconfirming_conditions=["异常路径属于已退役设备", "维护窗口内路径暂时下线"],
        diagnosis_boundary="VMware 侧当前多路径状态显示异常路径或共享块设备仅有一条可用路径；本次未获取阵列和 SAN Fabric 侧状态。",
        display_priority="P1",
    ),
    DeepRuleDefinition(
        rule_id="CL-DEEP-008",
        title="EVC 与 Resource Pool 一致性",
        category=DeepCategory.CURRENT_RISK,
        scope_type=ScopeType.AGGREGATE,
        dimension_key="evc_resource_pool_consistency",
        record_kind="config",
        verification_guidance="在各集群 Summary/EVC 配置和 Resource Pool 树中核对 EVC 模式、资源池数量、Reservation/Limit 与业务资源治理策略。",
        disconfirming_conditions=["集群属于不同业务代际且 EVC 差异已登记", "资源池差异由明确的资源隔离策略导致"],
        diagnosis_boundary="本次只读取 vCenter 集群配置和资源池摘要；未执行 EVC 变更、资源池重配置或业务压测。",
        display_priority="P2",
    ),
    DeepRuleDefinition(
        rule_id="CL-DEEP-009",
        title="Resource Pool 资源树状态异常",
        category=DeepCategory.CURRENT_RISK,
        scope_type=ScopeType.AGGREGATE,
        dimension_key="resource_pool_tree_state",
        record_kind="config",
        analysis_kind="resource_pool",
        verification_guidance="在 vSphere Client 的集群 Resource Pools 树中检查红色 inconsistent 或黄色 overcommitted 状态，逐层核对 CPU/内存 Reservation、Limit、Expandable Reservation，并结合主机不可用/维护记录确认资源树是否仍可满足保证值。",
        disconfirming_conditions=["黄色状态由已知的临时主机维护或资源丢失造成，且容量恢复计划已确认"],
        diagnosis_boundary="仅依据 vCenter Resource Pool 资源树状态及读取到的配置摘要；红色表示资源树不一致并会禁用 DRS，黄色表示部分 Reservation 不再有保证。本次未刷新运行时统计、执行资源压力或电源操作，也不判断业务是否已受影响。",
        impact="high",
        urgency="planned",
        display_priority="P1",
    ),
    DeepRuleDefinition(
        rule_id="STO-DEEP-004",
        title="Datastore 容量达到高水位",
        category=DeepCategory.CURRENT_RISK,
        dimension_key="datastore_used_percent_high",
        record_kind="config",
        threshold_id="TH-DATASTORE-USED-PERCENT-HIGH",
        analysis_kind="datastore_capacity",
        verification_guidance="在 vSphere Client 中核对 Datastore 总容量、已用空间、快照和 Thin Provision 分配，并结合扩容计划复核。",
        disconfirming_conditions=["近期已完成扩容但 vCenter 尚未刷新", "使用率由可清理的临时数据造成"],
        diagnosis_boundary="VMware 侧 Datastore 容量达到注册阈值；本次未获取阵列容量池和业务增长计划。",
        display_priority="P2",
    ),
    DeepRuleDefinition(
        rule_id="NET-DEEP-003",
        title="主机上联冗余不足",
        category=DeepCategory.CURRENT_RISK,
        dimension_key="host_uplink_redundancy",
        record_kind="config",
        verification_guidance="在主机 vSwitch/vDS 和物理交换机端口中核对承载业务的上联数量、绑定关系和故障切换策略。",
        disconfirming_conditions=["该主机或网络仅设计单上联", "单上联已登记风险接受和维护计划"],
        diagnosis_boundary="VMware 侧网络配置显示业务上联冗余不足；本次未获取交换机端口和物理链路状态。",
        display_priority="P2",
    ),
    DeepRuleDefinition(
        rule_id="NET-DEEP-004",
        title="网络 MTU VLAN 或 Teaming 配置漂移",
        category=DeepCategory.CURRENT_RISK,
        dimension_key="network_configuration_drift",
        scope_type=ScopeType.ENVIRONMENT,
        record_kind="config",
        verification_guidance="按主机、VMkernel、Port Group 和上联交换机逐项核对 MTU、VLAN、Teaming/LACP 配置，确认差异是否为设计要求。",
        disconfirming_conditions=["不同网络平面采用不同 MTU/VLAN 设计", "差异属于已批准的网络分区方案"],
        diagnosis_boundary="VMware 侧网络配置出现跨主机差异；本次未获取交换机端口配置作为最终依据。",
        display_priority="P2",
    ),
    DeepRuleDefinition(
        rule_id="STO-DEEP-005",
        title="Thin Provision 超配风险",
        category=DeepCategory.CURRENT_RISK,
        dimension_key="thin_provision_ratio",
        scope_type=ScopeType.ENVIRONMENT,
        record_kind="config",
        threshold_id="TH-THIN-PROVISION-RATIO",
        verification_guidance="核对 Datastore 物理容量、VM 虚拟磁盘容量、Thin 状态、快照和实际增长计划，确认超配是否受控。",
        disconfirming_conditions=["客户有明确 Thin Provision 容量治理和告警机制", "虚拟容量包含已计划迁移或即将回收的数据"],
        diagnosis_boundary="VMware 侧清单计算出虚拟容量与物理容量的比例；本次未获取阵列侧精简配置和回收策略。",
        display_priority="P2",
    ),
    DeepRuleDefinition(
        rule_id="STO-DEEP-006",
        title="虚拟机 Storage Policy 合规异常",
        category=DeepCategory.CURRENT_RISK,
        scope_type=ScopeType.AGGREGATE,
        dimension_key="storage_policy_compliance",
        profile="core",
        requires=["storage.policy.compliance"],
        record_kind="config",
        analysis_kind="storage_policy",
        verification_guidance="在 vSphere Client 的 VM Storage Policies Compliance 页面按虚拟机、VM Home 和虚拟磁盘核对策略、最近检查时间与不合规原因，并确认策略修改是否已应用。",
        disconfirming_conditions=["缓存状态与最近一次策略检查之间发生了策略或存储拓扑变更", "VM 或磁盘未关联 Storage Policy，且这符合环境设计"],
        diagnosis_boundary="仅使用 vCenter 缓存的只读合规结果；本次不触发重新计算，不判断阵列或存储提供程序本身的健康。未知、过期或冲突状态不解释为合规。",
        impact="medium",
        urgency="planned",
        display_priority="P2",
    ),
    DeepRuleDefinition(
        rule_id="STO-DEEP-007",
        title="Datastore 或 VMFS 访问异常",
        category=DeepCategory.CURRENT_RISK,
        scope_type=ScopeType.AGGREGATE,
        dimension_key="datastore_accessibility",
        record_kind="config",
        analysis_kind="datastore_access",
        verification_guidance="在 vSphere Client 中核对 Datastore 的 Accessible 状态及各已配置主机的 Mount 信息；对 VMFS 卷进一步核对文件系统版本和 Extent 数，并与 ESXi 存储路径及阵列侧状态交叉复核。",
        disconfirming_conditions=["主机挂载处于已批准的维护或卸载状态", "异常为短暂路径故障且后续只读采样已恢复"],
        diagnosis_boundary="依据 vCenter DatastoreSummary.accessible 和已返回的 HostMountInfo；聚合可访问状态为 true 不代表每台主机都可访问。本次未刷新 Datastore 状态、重扫 HBA、执行存储测试或读取阵列/SAN 状态。",
        impact="high",
        urgency="planned",
        display_priority="P1",
    ),
    DeepRuleDefinition(
        rule_id="HARD-DEEP-001",
        title="主机硬件 Sensor 异常",
        category=DeepCategory.CURRENT_RISK,
        profile="enhanced",
        dimension_key="host_hardware_sensor_issue",
        requires=["hardware.sensors"],
        record_kind="hardware",
        verification_guidance="在 vSphere Host Hardware Status 或服务器带外管理界面核对异常 Sensor、部件状态和告警时间。",
        disconfirming_conditions=["Sensor 告警已经在带外管理界面恢复且 vCenter 状态未刷新", "该传感器属于退役或未承载业务的硬件组件"],
        diagnosis_boundary="VMware 侧硬件 Sensor 报告红色或黄色状态；本次未读取 iDRAC/iLO 或执行硬件诊断。",
        display_priority="P1",
    ),
    DeepRuleDefinition(
        rule_id="HARD-DEEP-003",
        title="主机硬件驱动或固件缺少目标版本认证",
        category=DeepCategory.CURRENT_RISK,
        profile="enhanced",
        scope_type=ScopeType.AGGREGATE,
        dimension_key="hardware_hcl_compatibility",
        requires=["hardware.vcg.compatibility"],
        record_kind="hardware",
        analysis_kind="hardware_compatibility",
        verification_guidance="在 Broadcom Compatibility Guide 中按当前 ESXi Update、服务器型号和 PCI 四元组核对设备认证条目，再逐项复核驱动名、驱动版本及要求的固件配对。",
        disconfirming_conditions=["设备处于兼容指南未收录但已由 OEM 单独认证的支持组合", "当前硬件身份或驱动信息在采集期间发生变化"],
        diagnosis_boundary="仅按随软件打包且校验通过的本地 VCG 基线匹配；不下载外部目录、不执行 ESXCLI 或硬件测试。未命中、标识模糊、版本无法映射或数据过旧时不判兼容，也不判不兼容。",
        impact="high",
        urgency="planned",
        display_priority="P1",
    ),
    DeepRuleDefinition(
        rule_id="NET-DEEP-001",
        title="vmnic Link Flap 历史",
        category=DeepCategory.HISTORICAL_HEALTH,
        dimension_key="vmnic_link_flap",
        record_kind="event",
        threshold_id="TH-NET-LINK-FLAP-STATE-CHANGES",
        analysis_window_threshold_id="TH-NET-LINK-FLAP-WINDOW-SECONDS",
        analysis_kind="network_link_flap",
        verification_guidance="在 vCenter 事件中按主机和 vmnic 核对 down/up 事件时间，并与交换机端口、光模块和维护记录交叉确认。",
        disconfirming_conditions=["事件发生在已知维护窗口", "事件对象为测试或未承载业务的链路"],
        diagnosis_boundary="VMware 侧事件显示链路状态反复变化；本次未获取交换机端口和物理层日志。",
        display_priority="P2",
    ),
    DeepRuleDefinition(
        rule_id="STO-DEEP-001",
        title="APD / PDL 历史事件",
        category=DeepCategory.HISTORICAL_HEALTH,
        dimension_key="apd_pdl_history",
        record_kind="event",
        verification_guidance="在 vCenter 事件中核对 APD/PDL 事件时间、受影响 Datastore 和主机，并与阵列及 SAN Fabric 同时段记录核对。",
        disconfirming_conditions=["事件来自已退役或测试 Datastore", "事件发生在计划内存储维护窗口"],
        diagnosis_boundary="VMware 侧事件显示路径或设备访问异常；本次未获取阵列控制器和 SAN Fabric 证据。",
        display_priority="P1",
    ),
    DeepRuleDefinition(
        rule_id="COMPUTE-DEEP-001",
        title="vMotion 失败模式",
        category=DeepCategory.HISTORICAL_HEALTH,
        dimension_key="vmotion_failure_pattern",
        record_kind="task",
        verification_guidance="在 vCenter 任务与事件中核对失败任务、源/目标主机、时间和错误文本，并复核对应网络、存储及兼容性配置。",
        disconfirming_conditions=["失败任务属于用户取消或测试迁移", "失败发生在已知维护窗口"],
        diagnosis_boundary="VMware 侧任务记录显示 vMotion 失败模式；本次未获取业务调度系统和网络设备侧记录。",
        display_priority="P2",
    ),
    DeepRuleDefinition(
        rule_id="COMPUTE-DEEP-002",
        title="VM Reset 或电源失败历史",
        category=DeepCategory.HISTORICAL_HEALTH,
        dimension_key="vm_reset_power_failure_history",
        record_kind="event",
        verification_guidance="在 vCenter 事件中核对 VM Reset、开关机失败、Guest Reset 的时间、对象和触发原因，并与业务变更记录交叉确认。",
        disconfirming_conditions=["事件发生在计划内维护或测试窗口", "虚拟机属于临时或未承载业务的对象"],
        diagnosis_boundary="VMware 侧事件显示 VM 重置或电源操作失败；本次未获取客户机操作系统和业务日志。",
        display_priority="P1",
    ),
    DeepRuleDefinition(
        rule_id="TASK-DEEP-001",
        title="重复失败任务模式",
        category=DeepCategory.HISTORICAL_HEALTH,
        dimension_key="failed_task_pattern",
        record_kind="task",
        verification_guidance="在 vCenter 任务与事件中按任务类型、对象、错误文本和时间窗口核对失败聚类，排除用户取消和计划内维护。",
        disconfirming_conditions=["失败任务属于用户主动取消", "失败任务发生在已知维护窗口或测试迁移"],
        diagnosis_boundary="VMware 侧任务/事件显示重复失败模式；本次未获取业务调度系统和下游设备日志。",
        display_priority="P2",
    ),
    DeepRuleDefinition(
        rule_id="CL-DEEP-002",
        title="HA 隔离或重启历史",
        category=DeepCategory.HISTORICAL_HEALTH,
        dimension_key="ha_isolation_restart_history",
        record_kind="event",
        verification_guidance="在 vCenter 事件中核对 HA 隔离、主机连接丢失和 VM 重启事件的时间、主机及受影响虚拟机，并与维护记录交叉确认。",
        disconfirming_conditions=["事件发生在计划内主机维护", "受影响 VM 属于测试或临时业务"],
        diagnosis_boundary="VMware 侧事件显示 HA/主机连接或重启现象；本次未获取物理电源、交换机和业务侧日志。",
        display_priority="P1",
    ),
    DeepRuleDefinition(
        rule_id="CL-DEEP-003",
        title="DRS 异常历史",
        category=DeepCategory.HISTORICAL_HEALTH,
        dimension_key="drs_history",
        record_kind="event",
        verification_guidance="在 vCenter 事件和任务中核对 DRS 推荐、迁移失败、规则冲突和集群资源调度异常的时间与对象。",
        disconfirming_conditions=["事件来自临时关闭 DRS 的维护窗口", "迁移由人工取消且无重复模式"],
        diagnosis_boundary="VMware 侧事件显示 DRS 相关异常；本次未获取业务调度策略和网络/存储设备侧证据。",
        display_priority="P2",
    ),
    DeepRuleDefinition(
        rule_id="CL-DEEP-006",
        title="主机进入维护模式历史",
        category=DeepCategory.HISTORICAL_HEALTH,
        dimension_key="host_maintenance_history",
        record_kind="event",
        verification_guidance="在 vCenter 事件和任务中核对主机进入/退出维护模式的时间、触发对象和迁移结果，并与维护窗口核对。",
        disconfirming_conditions=["事件完全落在已批准维护窗口", "主机为临时或测试节点"],
        diagnosis_boundary="VMware 侧事件显示主机维护模式变化；本次未判断维护计划是否按变更流程批准。",
        display_priority="P2",
    ),
    DeepRuleDefinition(
        rule_id="CL-DEEP-007",
        title="Alarm 状态变化历史",
        category=DeepCategory.HISTORICAL_HEALTH,
        dimension_key="alarm_status_history",
        record_kind="event",
        verification_guidance="在 vCenter Alarm 事件中核对触发对象、告警定义、状态变化时间和清除条件，并确认是否有重复触发。",
        disconfirming_conditions=["告警来自测试规则或已停用对象", "状态变化发生在已知维护窗口"],
        diagnosis_boundary="VMware 侧事件显示 Alarm 状态变化；本次未获取外部监控平台和告警通知链路。",
        display_priority="P2",
    ),
    DeepRuleDefinition(
        rule_id="HIST-DEEP-001",
        title="跨域异常时间关联",
        category=DeepCategory.HISTORICAL_HEALTH,
        dimension_key="cross_domain_event_correlation",
        record_kind="event",
        scope_type=ScopeType.AGGREGATE,
        verification_guidance="在 vCenter 事件、任务和受影响对象时间线中核对同一小时内的网络、存储、计算或集群异常，并与变更窗口、交换机及阵列日志交叉确认。",
        disconfirming_conditions=["相关事件落在已批准维护或压测窗口", "不同事件属于无关对象且没有共同时间或因果线索"],
        diagnosis_boundary="本规则只关联 vCenter 侧历史事件时间窗，不证明物理网络、存储阵列或业务系统之间的因果关系。",
        display_priority="P1",
    ),
    DeepRuleDefinition(
        rule_id="STO-DEEP-002",
        title="Storage Path 或 VMFS 异常历史",
        category=DeepCategory.HISTORICAL_HEALTH,
        dimension_key="storage_path_failure_history",
        record_kind="event",
        verification_guidance="在 vCenter 事件中核对受影响主机、Datastore、路径或设备重置事件，并与 SAN Fabric、阵列和 HBA 同时段记录交叉确认。",
        disconfirming_conditions=["事件发生在计划内存储维护", "Datastore 或设备已退役"],
        diagnosis_boundary="VMware 侧事件显示存储路径、设备重置或 VMFS 访问异常；本次未获取阵列和 SAN Fabric 证据。",
        display_priority="P1",
    ),
    DeepRuleDefinition(
        rule_id="NET-DEEP-002",
        title="网络断连或网卡错误历史",
        category=DeepCategory.HISTORICAL_HEALTH,
        dimension_key="network_disconnect_error_history",
        record_kind="event",
        verification_guidance="在 vCenter 事件中按主机、vmnic、端口组和时间核对网络断连、丢包或网卡错误事件，并与交换机端口和光模块记录交叉确认。",
        disconfirming_conditions=["事件发生在计划内网络维护", "链路未承载生产业务"],
        diagnosis_boundary="VMware 侧事件显示网络断连或网卡错误；本次未获取交换机端口、光模块和物理链路日志。",
        display_priority="P2",
    ),
    DeepRuleDefinition(
        rule_id="CAP-DEEP-001",
        title="数据存储容量增长趋势",
        category=DeepCategory.TREND,
        confidence_class="STATISTICAL",
        scope_type=ScopeType.ENTITY,
        dimension_key="datastore_used_percent_daily_growth",
        record_kind="perf",
        signal_selector={"counter": "datastore.used_percent"},
        threshold_id="TH-TREND-DAILY-GROWTH",
        forecast_threshold_id="TH-DATASTORE-USED-PERCENT-HIGH",
        analysis_kind="trend",
        required_interval_sec=86400,
        minimum_evidence=3,
        verification_guidance="在 vSphere Client 或存储监控中核对同一 Datastore 的历史使用率，确认采样窗口、增长速率和近期扩容/迁移计划。",
        disconfirming_conditions=["期间存在大规模临时数据或迁移", "采样窗口跨越已完成的容量治理动作"],
        diagnosis_boundary="VMware 侧历史数据支持容量增长趋势判断；本次未获取阵列侧容量池和业务数据增长计划。",
        display_priority="P2",
    ),
    DeepRuleDefinition(
        rule_id="CAP-DEEP-002",
        title="虚拟机数量增长趋势",
        category=DeepCategory.TREND,
        confidence_class="STATISTICAL",
        scope_type=ScopeType.AGGREGATE,
        dimension_key="vm_count_daily_growth",
        record_kind="perf",
        signal_selector={"counter": "vm.count"},
        threshold_id="TH-VM-COUNT-DAILY-GROWTH",
        analysis_kind="trend",
        required_interval_sec=86400,
        minimum_evidence=3,
        verification_guidance="在 vCenter 清单和容量规划中核对虚拟机数量历史、批量创建/删除操作、许可和资源容量变化。",
        disconfirming_conditions=["样本窗口包含一次性项目上线或批量清理", "虚拟机为临时测试对象"],
        diagnosis_boundary="vCenter 清单快照支持虚拟机数量增长趋势判断；本次未获取业务上线计划和许可采购计划。",
        display_priority="P2",
    ),
    DeepRuleDefinition(
        rule_id="CAP-DEEP-003",
        title="Thin Provision 比例增长趋势",
        category=DeepCategory.TREND,
        confidence_class="STATISTICAL",
        scope_type=ScopeType.AGGREGATE,
        dimension_key="thin_provision_ratio_daily_growth",
        record_kind="perf",
        signal_selector={"counter": "thin_provision.ratio"},
        threshold_id="TH-THIN-PROVISION-GROWTH",
        analysis_kind="trend",
        required_interval_sec=86400,
        minimum_evidence=3,
        verification_guidance="在 Datastore 容量和虚拟磁盘明细中核对虚拟容量、物理容量、快照及业务增长计划。",
        disconfirming_conditions=["窗口内存在一次性虚拟磁盘扩容或快照清理", "比例变化来自 Datastore 迁移或容量刷新延迟"],
        diagnosis_boundary="VMware 清单和 Datastore 容量支持 Thin Provision 比例趋势判断；本次未获取阵列精简池和业务数据生命周期策略。",
        display_priority="P2",
    ),
    DeepRuleDefinition(
        rule_id="ENHANCED-CPU-001",
        title="CPU Ready 持续偏高",
        category=DeepCategory.TREND,
        profile="enhanced",
        confidence_class="STATISTICAL",
        scope_type=ScopeType.ENTITY,
        dimension_key="cpu_ready_high",
        requires=["enhanced.perf.cpu"],
        required_interval_sec=300,
        minimum_evidence=6,
        threshold_id="TH-CPU-READY-HIGH",
        record_kind="perf",
        signal_selector={"family": "enhanced.perf.cpu", "counter": "cpu.ready"},
        verification_guidance="在 vSphere 性能图表中按主机或集群核对 CPU Ready 时间窗口、采样粒度和工作负载变化。",
        disconfirming_conditions=["窗口内存在计划内 CPU 超配或批处理", "指标来自短暂迁移或启动尖峰"],
        diagnosis_boundary="VMware 性能计数器支持 CPU Ready 趋势判断；本次未获取客户机应用线程和业务调度数据。",
        display_priority="P2",
        analysis_kind="performance",
    ),
    DeepRuleDefinition(
        rule_id="ENHANCED-CPU-002",
        title="Host CPU Usage 持续偏高",
        category=DeepCategory.TREND,
        profile="enhanced",
        confidence_class="STATISTICAL",
        scope_type=ScopeType.ENTITY,
        dimension_key="cpu_usage_high",
        requires=["enhanced.perf.cpu"],
        required_interval_sec=300,
        minimum_evidence=6,
        threshold_id="TH-CPU-USAGE-HIGH",
        record_kind="perf",
        signal_selector={"family": "enhanced.perf.cpu", "counter": "cpu.usage"},
        verification_guidance="在 vSphere 性能图表中按主机核对 CPU Usage、Ready、Co-stop 的五分钟样本，并与并发工作负载和维护任务关联。",
        disconfirming_conditions=["窗口内存在计划内压测、备份或批处理", "高使用率由短时迁移尖峰造成"],
        diagnosis_boundary="主机 CPU Usage 连续达到阈值；本次未获取客户机进程和业务响应时间。",
        display_priority="P2",
        analysis_kind="performance",
    ),
    DeepRuleDefinition(
        rule_id="ENHANCED-CPU-003",
        title="CPU Co-stop 持续偏高",
        category=DeepCategory.TREND,
        profile="enhanced",
        confidence_class="STATISTICAL",
        scope_type=ScopeType.ENTITY,
        dimension_key="cpu_costop_high",
        requires=["enhanced.perf.cpu"],
        required_interval_sec=300,
        minimum_evidence=6,
        threshold_id="TH-CPU-COSTOP-HIGH",
        record_kind="perf",
        signal_selector={"family": "enhanced.perf.cpu", "counter": "cpu.costop"},
        verification_guidance="在 vSphere 性能图表中核对 Co-stop 五分钟样本，并检查虚拟机 vCPU 数量、主机 CPU Ready 和同窗口负载。",
        disconfirming_conditions=["Co-stop 只在 VM 启动或短时快照操作期间升高", "指标样本窗口跨越 vMotion 或资源池变更"],
        diagnosis_boundary="VMware 性能计数器显示 vCPU 联合调度等待持续达到阈值；本次未进行应用性能测试。",
        display_priority="P2",
        analysis_kind="performance",
    ),
    DeepRuleDefinition(
        rule_id="ENHANCED-STO-001",
        title="Storage Latency 持续偏高",
        category=DeepCategory.TREND,
        profile="enhanced",
        confidence_class="STATISTICAL",
        scope_type=ScopeType.ENTITY,
        dimension_key="storage_latency_high",
        requires=["enhanced.perf.storage"],
        required_interval_sec=300,
        minimum_evidence=6,
        threshold_id="TH-STORAGE-LATENCY-HIGH",
        record_kind="perf",
        signal_selector={"family": "enhanced.perf.storage", "counter": "disk.maxtotallatency"},
        verification_guidance="在 vSphere 性能图表中核对 Datastore/设备延迟、队列、IOPS 和同窗口的路径状态。",
        disconfirming_conditions=["窗口内存在计划内存储维护", "高延迟来自单个短时批处理任务"],
        diagnosis_boundary="VMware 性能计数器支持存储延迟趋势判断；本次未获取阵列控制器和 SAN Fabric 性能数据。",
        display_priority="P2",
        analysis_kind="performance",
    ),
    DeepRuleDefinition(
        rule_id="ENHANCED-MEM-001",
        title="Memory Balloon 持续偏高",
        category=DeepCategory.TREND,
        profile="enhanced",
        confidence_class="STATISTICAL",
        scope_type=ScopeType.ENTITY,
        dimension_key="memory_balloon_high",
        requires=["enhanced.perf.memory"],
        required_interval_sec=300,
        minimum_evidence=6,
        threshold_id="TH-MEMORY-BALLOON-HIGH",
        record_kind="perf",
        signal_selector={"family": "enhanced.perf.memory", "counter": "mem.vmmemctl"},
        verification_guidance="在 vSphere 性能图表中按主机核对 Memory Balloon、Swap 和 Active Memory 的时间窗口及对应工作负载。",
        disconfirming_conditions=["Ballooning 发生在计划内压测或维护窗口", "Host 内存回收已在同一窗口后恢复"],
        diagnosis_boundary="VMware 性能计数器支持 Balloon 压力判断；本次未采集客户机应用内存、NUMA 和宿主机外部负载。",
        display_priority="P2",
        analysis_kind="performance",
    ),
    DeepRuleDefinition(
        rule_id="VSAN-DEEP-001",
        title="vSAN 容量达到高水位",
        category=DeepCategory.CURRENT_RISK,
        profile="core",
        scope_type=ScopeType.ENTITY,
        dimension_key="vsan_capacity_high",
        requires=["vsan"],
        threshold_id="TH-VSAN-CAPACITY-HIGH",
        record_kind="vsan",
        signal_selector={"metric": "used_percent"},
        verification_guidance="在 vSphere vSAN Capacity 视图中核对总容量、已用容量、可用容量和 Resync 占用，并结合扩容计划复核。",
        disconfirming_conditions=["近期已完成扩容但统计尚未刷新", "使用率包含可清理的临时数据"],
        diagnosis_boundary="VMware/vSAN 侧容量数据达到注册阈值；本次未获取底层容量池和业务增长计划。",
        display_priority="P2",
    ),
    DeepRuleDefinition(
        rule_id="VSAN-DEEP-002",
        title="vSAN Object Health 异常",
        category=DeepCategory.CURRENT_RISK,
        profile="enhanced",
        dimension_key="vsan_object_health",
        requires=["vsan.object.health"],
        record_kind="vsan",
        signal_selector={"metric": "object_health"},
        verification_guidance="在 vSAN Skyline Health/Object Health 中核对异常对象、组件状态、故障域和修复建议。",
        disconfirming_conditions=["对象属于已退役或测试资源", "Health API 返回的是历史缓存状态"],
        diagnosis_boundary="vSAN API 侧对象健康状态异常；本次未执行修复、重建或主动 Health Test。",
        display_priority="P1",
    ),
    DeepRuleDefinition(
        rule_id="VSAN-DEEP-003",
        title="vSAN Resync 已暂停",
        category=DeepCategory.CURRENT_RISK,
        profile="enhanced",
        dimension_key="vsan_resync_suspended",
        requires=["vsan.resync"],
        record_kind="vsan",
        signal_selector={"metric": "resync_suspended"},
        verification_guidance="在 vSAN Resync 视图中核对暂停对象、剩余字节、预计完成时间和阻塞原因；仅暂停状态才支持本 Finding。",
        disconfirming_conditions=["暂停对象已在本次采集后恢复", "暂停由已确认的计划内维护窗口触发"],
        diagnosis_boundary="vSAN API 侧显示暂停的 Resync 对象；正常进行中的 Resync 仅保留为内部证据，不生成客户风险。",
        display_priority="P2",
    ),
    DeepRuleDefinition(
        rule_id="VSAN-DEEP-004",
        title="vSAN Disk Group 状态异常",
        category=DeepCategory.CURRENT_RISK,
        profile="enhanced",
        dimension_key="vsan_disk_group",
        requires=["vsan.disk_group"],
        record_kind="vsan",
        signal_selector={"metric": "disk_group"},
        verification_guidance="在 vSAN Disk Management 中核对每台主机的 Disk Group、缓存盘、容量盘和状态。",
        disconfirming_conditions=["主机处于计划内维护模式", "磁盘组状态来自尚未刷新完成的任务"],
        diagnosis_boundary="vSAN API 侧磁盘组映射或状态异常；本次未执行磁盘组重建或设备操作。",
        display_priority="P1",
    ),
    DeepRuleDefinition(
        rule_id="VSAN-TREND-001",
        title="vSAN 容量增长趋势",
        category=DeepCategory.TREND,
        profile="enhanced",
        confidence_class="STATISTICAL",
        scope_type=ScopeType.ENTITY,
        dimension_key="vsan_used_percent_daily_growth",
        requires=["vsan"],
        required_interval_sec=86400,
        minimum_evidence=3,
        threshold_id="TH-TREND-DAILY-GROWTH",
        forecast_threshold_id="TH-VSAN-CAPACITY-HIGH",
        record_kind="perf",
        signal_selector={"counter": "vsan.used_percent"},
        verification_guidance="在 vSphere vSAN Capacity 视图中核对相同 vSAN Datastore 的使用率历史、扩容和数据迁移时间线。",
        disconfirming_conditions=["采样窗口内存在计划内扩容或大规模数据迁移", "增长来自可回收的临时对象或快照"],
        diagnosis_boundary="vSAN 容量快照支持使用率趋势判断；本次未获取底层容量池和业务数据增长计划。",
        display_priority="P2",
        analysis_kind="trend",
    ),
    DeepRuleDefinition(
        rule_id="VSAN-DEEP-005",
        title="vSAN Congestion 异常",
        category=DeepCategory.CURRENT_RISK,
        profile="enhanced",
        dimension_key="vsan_congestion",
        requires=["vsan.congestion"],
        threshold_id="TH-VSAN-CONGESTION-HIGH",
        record_kind="vsan_perf",
        signal_selector={"metric": "vsan.congestion"},
        verification_guidance="在 vSAN Performance Service 中核对 Congestion、磁盘组延迟、IOPS、Resync 和同窗口工作负载。",
        disconfirming_conditions=["样本来自计划内压测或短时迁移", "Congestion 只在单个短时采样点出现"],
        diagnosis_boundary="vSAN Performance Service 样本显示 Congestion；本次未执行性能服务配置或工作负载调整。",
        display_priority="P1",
    ),
    DeepRuleDefinition(
        rule_id="VSAN-DEEP-006",
        title="vSAN Latency 异常",
        category=DeepCategory.TREND,
        profile="enhanced",
        confidence_class="STATISTICAL",
        dimension_key="vsan_latency",
        requires=["vsan.latency"],
        threshold_id="TH-STORAGE-LATENCY-HIGH",
        record_kind="vsan_perf",
        signal_selector={"metric": "vsan.latency"},
        verification_guidance="在 vSAN Performance Service 中核对读写延迟、IOPS、Congestion、磁盘组和同窗口 Resync。",
        disconfirming_conditions=["延迟来自单个短时批处理或维护窗口", "性能服务样本窗口不完整"],
        diagnosis_boundary="vSAN Performance Service 样本支持延迟判断；本次未获取阵列控制器和 SAN Fabric 性能数据。",
        display_priority="P2",
    ),
)


@dataclass(slots=True)
class DeepAnalysisResult:
    report: DeepReport
    diagnostic: DeepDiagnosticRecord
    rule_results: list[DeepRuleResult]
    findings: list[DeepFinding]


class TrendAnalyzer:
    """Small deterministic trend engine used by Core and Enhanced datasets."""

    def analyze(
        self,
        dataset: DeepDataset,
        rule: DeepRuleDefinition,
        thresholds: ThresholdRegistry,
    ) -> tuple[DeepRuleResult, list[DeepFinding]]:
        records = self._matching_records(dataset, rule)
        now = now_utc_iso()
        if not records:
            return self._insufficient(rule, "趋势样本不足", now), []
        groups = self._entity_groups(records, rule)
        findings: list[DeepFinding] = []
        statuses: list[DeepResultStatus] = []
        refs: list[str] = []
        insufficient_reasons: list[str] = []
        for group_records in groups:
            result, finding = self._analyze_group(dataset, rule, thresholds, group_records, now)
            statuses.append(result.status)
            refs.extend(result.evidence_refs)
            if result.reason:
                insufficient_reasons.append(result.reason)
            if finding:
                findings.append(finding)
        status = (
            DeepResultStatus.FINDING
            if any(item == DeepResultStatus.FINDING for item in statuses)
            else DeepResultStatus.INSUFFICIENT_DATA
            if any(item == DeepResultStatus.INSUFFICIENT_DATA for item in statuses)
            else DeepResultStatus.PASS
        )
        return DeepRuleResult(
            rule_id=rule.rule_id,
            rule_version=rule.rule_version,
            category=rule.category,
            profile=rule.profile,
            status=status,
            finding_ids=[item.finding_id for item in findings],
            evidence_refs=refs,
            reason="; ".join(sorted(set(insufficient_reasons))) if status == DeepResultStatus.INSUFFICIENT_DATA else "",
            evaluated_at_utc=now,
        ), findings

    def _analyze_group(
        self,
        dataset: DeepDataset,
        rule: DeepRuleDefinition,
        thresholds: ThresholdRegistry,
        records: list[DatasetRecord],
        now: str,
    ) -> tuple[DeepRuleResult, DeepFinding | None]:
        if len(records) < rule.minimum_evidence:
            return self._insufficient(rule, "趋势样本不足", now), None
        completeness_threshold = thresholds.minimum_completeness().value
        if any(record.window.completeness < completeness_threshold for record in records):
            return self._insufficient(rule, "趋势样本完整度低于配置阈值", now), None
        points = self._numeric_points(records)
        if len(points) < rule.minimum_evidence:
            return self._insufficient(rule, "趋势样本缺少可计算数值", now), None
        slope = self._slope_per_day(points)
        threshold = thresholds.get(rule.threshold_id or "")
        triggered = self._compare(slope, threshold.comparator, threshold.value)
        forecast = self._forecast_sentence(rule, thresholds, current_value=points[-1][1], slope=slope)
        refs = [evidence_ref(record) for record in records]
        derived_record = DatasetRecord(
            record_id=f"derived-{rule.rule_id.lower()}-{records[-1].entity.stable_id}",
            dataset_id=dataset.dataset_id,
            kind="derived",
            entity=records[-1].entity,
            collected_at_utc=now,
            source=DeepSource(api="TrendAnalyzer", collector="vstacklens.deep.trend", collected_at_utc=now),
            selector={"rule_id": rule.rule_id, "metric": "slope_per_day"},
            window=DeepWindow(
                start=records[0].window.start,
                end=records[-1].window.end,
                interval_sec=rule.required_interval_sec,
                sample_count=len(records),
                expected_sample_count=len(records),
                completeness=min(record.window.completeness for record in records),
            ),
            interval_sec=rule.required_interval_sec,
            value=round(slope, 4),
            unit=threshold.unit,
            raw_pointer="derived/trend.ndjson",
            summary=f"按 {len(records)} 个样本计算的每日增长率",
        )
        derived_ref = evidence_ref(derived_record, derivation=[item.ref for item in refs])
        scope = self._scope(rule, records)
        refs.append(derived_ref)
        result_status = DeepResultStatus.FINDING if triggered else DeepResultStatus.PASS
        result = DeepRuleResult(
            rule_id=rule.rule_id,
            rule_version=rule.rule_version,
            category=rule.category,
            profile=rule.profile,
            status=result_status,
            finding_ids=[finding_id(rule.rule_id, scope)] if triggered else [],
            evidence_refs=[item.ref for item in refs],
            evaluated_at_utc=now,
        )
        if not triggered:
            return result, None
        finding = DeepFinding(
            finding_id=finding_id(rule.rule_id, scope),
            rule_id=rule.rule_id,
            rule_version=rule.rule_version,
            title=rule.title,
            category=rule.category,
            confidence_class=rule.confidence_class,
            scope=scope,
            display_priority=rule.display_priority,
            impact=rule.impact,
            urgency=rule.urgency,
             fact=f"历史样本显示 {rule.title} 每日变化约 {slope:.2f}{self._unit_label(threshold.unit)}。{forecast}",
            finding=f"按当前样本趋势，{rule.title}显示持续增长迹象，需要结合容量计划复核。",
            entities=[record.entity for record in records[-1:]],
            evidence=refs,
            evidence_sufficiency="SUFFICIENT",
            threshold=threshold,
            disconfirming_conditions=rule.disconfirming_conditions,
            verification_guidance=rule.verification_guidance,
            diagnosis_boundary=rule.diagnosis_boundary,
            lifecycle={"status": "OPEN", "first_seen_dataset": dataset.dataset_id, "last_seen_dataset": dataset.dataset_id, "occurrence_count": 1},
        )
        return result, finding

    @staticmethod
    def _entity_groups(records: list[DatasetRecord], rule: DeepRuleDefinition) -> list[list[DatasetRecord]]:
        if rule.scope_type != ScopeType.ENTITY:
            return [records]
        groups: dict[str, list[DatasetRecord]] = {}
        for record in records:
            groups.setdefault(record.entity.stable_id, []).append(record)
        return [sorted(items, key=lambda item: item.window.end) for _entity_id, items in sorted(groups.items())]

    def _matching_records(self, dataset: DeepDataset, rule: DeepRuleDefinition) -> list[DatasetRecord]:
        return sorted(
            [
                record
                for record in dataset.records
                if record.kind == rule.record_kind
                and record.metadata.get("rule_id", rule.rule_id) == rule.rule_id
                and all(record.selector.get(key) == value for key, value in rule.signal_selector.items())
            ],
            key=lambda item: item.window.end,
        )

    def _numeric_points(self, records: list[DatasetRecord]) -> list[tuple[float, float]]:
        first = self._to_datetime(records[0].window.end)
        points: list[tuple[float, float]] = []
        for record in records:
            try:
                value = float(record.value)
            except (TypeError, ValueError):
                continue
            if not isfinite(value):
                continue
            age = (self._to_datetime(record.window.end) - first).total_seconds() / 86400
            points.append((age, value))
        return points

    def _slope_per_day(self, points: list[tuple[float, float]]) -> float:
        mean_x = sum(item[0] for item in points) / len(points)
        mean_y = sum(item[1] for item in points) / len(points)
        denominator = sum((item[0] - mean_x) ** 2 for item in points)
        if denominator == 0:
            return 0.0
        return sum((x - mean_x) * (y - mean_y) for x, y in points) / denominator

    def _scope(self, rule: DeepRuleDefinition, records: list[DatasetRecord]) -> FindingScope:
        ids = sorted({record.entity.stable_id for record in records})
        scope_id = ids[0] if rule.scope_type != ScopeType.AGGREGATE else "aggregate:" + ",".join(ids)
        return FindingScope(scope_type=rule.scope_type, scope_id=scope_id, dimension_key=rule.dimension_key, member_ids=ids)

    @staticmethod
    def _unit_label(unit: str) -> str:
        return {"percent_per_day": "%/day", "count_per_day": " 个/天", "ratio_per_day": " ratio/day"}.get(unit, f" {unit}" if unit else "")

    def _forecast_sentence(self, rule: DeepRuleDefinition, thresholds: ThresholdRegistry, *, current_value: float, slope: float) -> str:
        if not rule.forecast_threshold_id or slope <= 0:
            return ""
        target = thresholds.get(rule.forecast_threshold_id)
        remaining = target.value - current_value
        if remaining <= 0:
            return f" 当前值已达到 {target.value:.2f}{self._unit_label(target.unit)} 高水位。"
        days = remaining / slope
        return f" 按当前斜率估算，约 {days:.0f} 天达到 {target.value:.2f}{self._unit_label(target.unit)} 高水位。"

    def _insufficient(self, rule: DeepRuleDefinition, reason: str, now: str) -> DeepRuleResult:
        return DeepRuleResult(rule_id=rule.rule_id, rule_version=rule.rule_version, category=rule.category, profile=rule.profile, status=DeepResultStatus.INSUFFICIENT_DATA, reason=reason, evaluated_at_utc=now)

    @staticmethod
    def _compare(value: float, comparator: str, threshold: float) -> bool:
        return {">=": value >= threshold, ">": value > threshold, "<=": value <= threshold, "<": value < threshold, "==": value == threshold}.get(comparator, False)

    @staticmethod
    def _to_datetime(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


class PerformanceAnalyzer:
    def analyze(self, dataset: DeepDataset, rule: DeepRuleDefinition, thresholds: ThresholdRegistry) -> tuple[DeepRuleResult, list[DeepFinding]]:
        now = now_utc_iso()
        records = sorted(
            [
                record
                for record in dataset.records
                if record.kind == rule.record_kind
                and record.metadata.get("enhanced") is True
                and all(record.selector.get(key) == value for key, value in rule.signal_selector.items())
            ],
            key=lambda item: item.window.end,
        )
        if not records:
            return self._insufficient(rule, "enhanced performance records are unavailable", now), []
        groups: dict[str, list[DatasetRecord]] = {}
        for record in records:
            groups.setdefault(record.entity.stable_id, []).append(record)
        findings: list[DeepFinding] = []
        statuses: list[DeepResultStatus] = []
        refs: list[str] = []
        reasons: list[str] = []
        for entity_records in groups.values():
            result, finding = self._analyze_entity(dataset, rule, thresholds, entity_records, now)
            statuses.append(result.status)
            refs.extend(result.evidence_refs)
            if result.reason:
                reasons.append(result.reason)
            if finding:
                findings.append(finding)
        if any(status == DeepResultStatus.FINDING for status in statuses):
            status = DeepResultStatus.FINDING
        elif any(status == DeepResultStatus.INSUFFICIENT_DATA for status in statuses):
            status = DeepResultStatus.INSUFFICIENT_DATA
        else:
            status = DeepResultStatus.PASS
        return DeepRuleResult(
            rule_id=rule.rule_id,
            rule_version=rule.rule_version,
            category=rule.category,
            profile=rule.profile,
            status=status,
            finding_ids=[item.finding_id for item in findings],
            evidence_refs=refs,
            reason="; ".join(sorted(set(reasons))) if status == DeepResultStatus.INSUFFICIENT_DATA else "",
            evaluated_at_utc=now,
        ), findings

    def _analyze_entity(
        self,
        dataset: DeepDataset,
        rule: DeepRuleDefinition,
        thresholds: ThresholdRegistry,
        records: list[DatasetRecord],
        now: str,
    ) -> tuple[DeepRuleResult, DeepFinding | None]:
        completeness_threshold = thresholds.minimum_completeness().value
        total_samples = sum(int(record.window.sample_count or 0) for record in records)
        if not records or total_samples < rule.minimum_evidence or any(record.window.completeness < completeness_threshold for record in records):
            return self._insufficient(rule, "enhanced performance samples do not satisfy the configured minimum", now), None
        threshold = thresholds.get(rule.threshold_id or "")
        values = [value for record in records for value in self._sample_values(record)]
        if not values:
            return DeepRuleResult(rule_id=rule.rule_id, rule_version=rule.rule_version, category=rule.category, profile=rule.profile, status=DeepResultStatus.INSUFFICIENT_DATA, reason="enhanced performance values are unavailable", evaluated_at_utc=now), None
        breach_count = sum(1 for value in values if self._compare(value, threshold.comparator, threshold.value))
        triggered = breach_count >= rule.minimum_evidence
        evidence = [evidence_ref(record) for record in records]
        scope = FindingScope(scope_type=rule.scope_type, scope_id=records[-1].entity.stable_id, dimension_key=rule.dimension_key, member_ids=[records[-1].entity.stable_id])
        result = DeepRuleResult(rule_id=rule.rule_id, rule_version=rule.rule_version, category=rule.category, profile=rule.profile, status=DeepResultStatus.FINDING if triggered else DeepResultStatus.PASS, finding_ids=[finding_id(rule.rule_id, scope)] if triggered else [], evidence_refs=[item.ref for item in evidence], evaluated_at_utc=now)
        if not triggered:
            return result, None
        finding = DeepFinding(finding_id=finding_id(rule.rule_id, scope), rule_id=rule.rule_id, rule_version=rule.rule_version, title=rule.title, category=rule.category, confidence_class=rule.confidence_class, scope=scope, display_priority=rule.display_priority, impact=rule.impact, urgency=rule.urgency, fact=f"Enhanced 性能样本最大值达到 {max(values):.2f}{self._unit_label(threshold.unit)}，其中 {breach_count}/{len(values)} 个样本达到阈值。", finding=f"Enhanced 性能数据支持持续异常趋势判断，需要结合工作负载和下游设备复核。", entities=[records[-1].entity], evidence=evidence, evidence_sufficiency="SUFFICIENT", threshold=threshold, disconfirming_conditions=rule.disconfirming_conditions, verification_guidance=rule.verification_guidance, diagnosis_boundary=rule.diagnosis_boundary, lifecycle={"status": "OPEN", "first_seen_dataset": dataset.dataset_id, "last_seen_dataset": dataset.dataset_id, "occurrence_count": 1})
        return result, finding

    @staticmethod
    def _insufficient(rule: DeepRuleDefinition, reason: str, now: str) -> DeepRuleResult:
        return DeepRuleResult(
            rule_id=rule.rule_id,
            rule_version=rule.rule_version,
            category=rule.category,
            profile=rule.profile,
            status=DeepResultStatus.INSUFFICIENT_DATA,
            reason=reason,
            evaluated_at_utc=now,
        )

    def _sample_values(self, record: DatasetRecord) -> list[float]:
        raw_samples = record.metadata.get("sample_values")
        candidates = raw_samples if isinstance(raw_samples, list) else [record.value]
        values: list[float] = []
        for candidate in candidates:
            value = self._maximum_value(candidate)
            if value is not None:
                values.append(value)
        return values

    @staticmethod
    def _unit_label(unit: str) -> str:
        return {"percent": "%", "millisecond": " ms", "megabyte": " MB"}.get(unit, f" {unit}" if unit else "")

    @staticmethod
    def _maximum_value(value: Any) -> float | None:
        if isinstance(value, dict):
            value = value.get("max", value.get("last"))
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _compare(value: float, comparator: str, threshold: float) -> bool:
        return {">=": value >= threshold, ">": value > threshold, "<=": value <= threshold, "<": value < threshold, "==": value == threshold}.get(comparator, False)

    def _matching_records(self, dataset: DeepDataset, rule: DeepRuleDefinition) -> list[DatasetRecord]:
        return sorted(
            [
                record
                for record in dataset.records
                if record.kind == rule.record_kind
                and record.metadata.get("rule_id", rule.rule_id) == rule.rule_id
                and all(record.selector.get(key) == value for key, value in rule.signal_selector.items())
            ],
            key=lambda item: item.window.end,
        )

    def _numeric_points(self, records: list[DatasetRecord]) -> list[tuple[float, float]]:
        first = self._to_datetime(records[0].window.end)
        points: list[tuple[float, float]] = []
        for record in records:
            try:
                value = float(record.value)
            except (TypeError, ValueError):
                continue
            if not isfinite(value):
                continue
            age = (self._to_datetime(record.window.end) - first).total_seconds() / 86400
            points.append((age, value))
        return points

    def _slope_per_day(self, points: list[tuple[float, float]]) -> float:
        mean_x = sum(item[0] for item in points) / len(points)
        mean_y = sum(item[1] for item in points) / len(points)
        denominator = sum((item[0] - mean_x) ** 2 for item in points)
        if denominator == 0:
            return 0.0
        return sum((x - mean_x) * (y - mean_y) for x, y in points) / denominator

    def _scope(self, rule: DeepRuleDefinition, records: list[DatasetRecord]) -> FindingScope:
        ids = sorted({record.entity.stable_id for record in records})
        scope_id = ids[0] if rule.scope_type != ScopeType.AGGREGATE else "aggregate:" + ",".join(ids)
        return FindingScope(scope_type=rule.scope_type, scope_id=scope_id, dimension_key=rule.dimension_key, member_ids=ids)

    def _insufficient(self, rule: DeepRuleDefinition, reason: str, now: str) -> DeepRuleResult:
        return DeepRuleResult(
            rule_id=rule.rule_id,
            rule_version=rule.rule_version,
            category=rule.category,
            profile=rule.profile,
            status=DeepResultStatus.INSUFFICIENT_DATA,
            reason=reason,
            evaluated_at_utc=now,
        )

    @staticmethod
    def _compare(value: float, comparator: str, threshold: float) -> bool:
        return {">=": value >= threshold, ">": value > threshold, "<=": value <= threshold, "<": value < threshold, "==": value == threshold}.get(comparator, False)

    @staticmethod
    def _to_datetime(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


class DeepAnalyzer:
    def __init__(self, *, trend_analyzer: TrendAnalyzer | None = None, performance_analyzer: PerformanceAnalyzer | None = None) -> None:
        self.trend_analyzer = trend_analyzer or TrendAnalyzer()
        self.performance_analyzer = performance_analyzer or PerformanceAnalyzer()

    def analyze(
        self,
        dataset: DeepDataset,
        rules: tuple[DeepRuleDefinition, ...] = BUILTIN_DEEP_RULES,
        thresholds: ThresholdRegistry | None = None,
    ) -> DeepAnalysisResult:
        from vstacklens.deep.policies import default_threshold_registry

        registry = thresholds or default_threshold_registry()
        results: list[DeepRuleResult] = []
        findings: list[DeepFinding] = []
        for rule in rules:
            result, finding = self._evaluate_rule(dataset, rule, registry)
            if result.status == DeepResultStatus.PASS and self._manifest_degradation_affects_rule(dataset, rule):
                result = result.model_copy(
                    update={
                        "status": DeepResultStatus.INSUFFICIENT_DATA,
                        "reason": self._manifest_degradation_reason(dataset, rule),
                    }
                )
            results.append(result)
            if isinstance(finding, list):
                findings.extend(finding)
            elif finding:
                findings.append(finding)
        report = self._build_report(results, findings)
        diagnostic = DeepDiagnosticRecord(
            dataset_id=dataset.dataset_id,
            created_at_utc=now_utc_iso(),
            capability=dataset.capability,
            rule_results=results,
            collection_log=dataset.collection_log,
            errors=[{"rule_id": item.rule_id, "reason": item.reason} for item in results if item.status == DeepResultStatus.ERROR],
            impact=dataset.manifest.impact,
            integrity=dataset.manifest.integrity,
        )
        return DeepAnalysisResult(report=report, diagnostic=diagnostic, rule_results=results, findings=findings)

    @staticmethod
    def _manifest_degradation_affects_rule(dataset: DeepDataset, rule: DeepRuleDefinition) -> bool:
        if not bool((dataset.manifest.impact or {}).get("degraded")):
            return False
        actions = dataset.collection_log or []
        guard_statuses = {"cancelled", "budget_exceeded", "memory_limit_exceeded", "cpu_limit_exceeded"}
        if any(
            str(item.get("status") or "") in guard_statuses
            or str(item.get("reason") or "") in guard_statuses
            or str(item.get("status") or "").startswith("skipped_")
            for item in actions
        ):
            return True
        event_history_limited = any(
            item.get("action") == "event.history"
            and (item.get("status") == "degraded" or bool(item.get("degraded")))
            for item in actions
        )
        if event_history_limited:
            return rule.record_kind == "event" or rule.analysis_kind == "network_link_flap" or rule.rule_id == "HIST-DEEP-001"
        # An unexplained session-wide degraded flag remains conservative.
        return True

    @staticmethod
    def _manifest_degradation_reason(dataset: DeepDataset, rule: DeepRuleDefinition) -> str:
        for item in dataset.collection_log or []:
            if item.get("action") == "event.history" and (item.get("status") == "degraded" or bool(item.get("degraded"))):
                return "EventHistory was incomplete; a complete historical event pass cannot be established" if rule.record_kind == "event" else "an unrelated historical event source was incomplete; this rule must be verified against its own evidence"
        return "collection was degraded; a complete pass cannot be established"

    def _evaluate_rule(self, dataset: DeepDataset, rule: DeepRuleDefinition, thresholds: ThresholdRegistry) -> tuple[DeepRuleResult, DeepFinding | list[DeepFinding] | None]:
        now = now_utc_iso()
        if rule.analysis_kind == "storage_policy" and dataset.manifest.scope.get("vms") == 0:
            return DeepRuleResult(
                rule_id=rule.rule_id,
                rule_version=rule.rule_version,
                category=rule.category,
                profile=rule.profile,
                status=DeepResultStatus.NOT_APPLICABLE,
                reason="当前环境没有虚拟机可评估 Storage Policy 合规",
                evaluated_at_utc=now,
            ), None
        if rule.analysis_kind == "hardware_compatibility" and dataset.manifest.scope.get("hosts") == 0:
            return DeepRuleResult(
                rule_id=rule.rule_id,
                rule_version=rule.rule_version,
                category=rule.category,
                profile=rule.profile,
                status=DeepResultStatus.NOT_APPLICABLE,
                reason="当前环境没有 ESXi 主机可评估硬件兼容性",
                evaluated_at_utc=now,
            ), None
        missing = dataset.capability.missing(rule.requires)
        if missing:
            return DeepRuleResult(
                rule_id=rule.rule_id,
                rule_version=rule.rule_version,
                category=rule.category,
                profile=rule.profile,
                status=DeepResultStatus.NOT_EVALUATED,
                missing_capabilities=missing,
                reason="required capability is not available",
                evaluated_at_utc=now,
            ), None
        if rule.analysis_kind == "network_link_flap":
            return self._evaluate_network_link_flap_rule(dataset, rule, thresholds, now)
        if rule.analysis_kind in {"resource_pool", "storage_policy", "datastore_capacity", "datastore_access", "hardware_compatibility", "guest_os_support", "storage_path", "certificate_expiry", "license_state", "host_config_drift"}:
            return self._evaluate_partial_signal_rule(dataset, rule, thresholds, now)
        if rule.analysis_kind == "trend":
            return self.trend_analyzer.analyze(dataset, rule, thresholds)
        if rule.analysis_kind == "performance":
            return self.performance_analyzer.analyze(dataset, rule, thresholds)
        records = sorted(
            [record for record in dataset.records if record.metadata.get("rule_id", rule.rule_id) == rule.rule_id and record.kind == rule.record_kind],
            key=lambda item: item.collected_at_utc,
        )
        if not records:
            return DeepRuleResult(
                rule_id=rule.rule_id,
                rule_version=rule.rule_version,
                category=rule.category,
                profile=rule.profile,
                status=DeepResultStatus.INSUFFICIENT_DATA,
                reason="no dataset records matched the rule",
                evaluated_at_utc=now,
            ), None
        minimum = thresholds.minimum_completeness().value
        if len(records) < rule.minimum_evidence or any(record.window.completeness < minimum for record in records):
            return DeepRuleResult(
                rule_id=rule.rule_id,
                rule_version=rule.rule_version,
                category=rule.category,
                profile=rule.profile,
                status=DeepResultStatus.INSUFFICIENT_DATA,
                reason="evidence does not satisfy the configured minimum",
                evaluated_at_utc=now,
            ), None
        conflicting = [record for record in records if record.metadata.get("conflict")]
        if conflicting:
            refs = [evidence_ref(record) for record in conflicting]
            return DeepRuleResult(
                rule_id=rule.rule_id,
                rule_version=rule.rule_version,
                category=rule.category,
                profile=rule.profile,
                status=DeepResultStatus.INSUFFICIENT_DATA,
                evidence_refs=[item.ref for item in refs],
                reason=f"conflicting evidence across sources ({len(conflicting)} records)",
                evaluated_at_utc=now,
            ), None
        if all(record.metadata.get("not_applicable") for record in records):
            return DeepRuleResult(
                rule_id=rule.rule_id,
                rule_version=rule.rule_version,
                category=rule.category,
                profile=rule.profile,
                status=DeepResultStatus.NOT_APPLICABLE,
                reason="environment does not contain the applicable object",
                evaluated_at_utc=now,
            ), None
        matched = [record for record in records if record.finding]
        scope = self._scope(rule, records)
        refs = [evidence_ref(record) for record in matched or records]
        result = DeepRuleResult(
            rule_id=rule.rule_id,
            rule_version=rule.rule_version,
            category=rule.category,
            profile=rule.profile,
            status=DeepResultStatus.FINDING if matched else DeepResultStatus.PASS,
            finding_ids=[finding_id(rule.rule_id, scope)] if matched else [],
            evidence_refs=[item.ref for item in refs],
            evaluated_at_utc=now,
        )
        if not matched:
            return result, None
        finding = DeepFinding(
            finding_id=finding_id(rule.rule_id, scope),
            rule_id=rule.rule_id,
            rule_version=rule.rule_version,
            title=rule.title,
            category=rule.category,
            confidence_class=rule.confidence_class,
            scope=scope,
            display_priority=rule.display_priority,
            impact=rule.impact,
            urgency=rule.urgency,
            fact=matched[0].summary or f"发现 {len(matched)} 条与规则匹配的证据。",
            finding=matched[0].summary or rule.title,
            entities=[record.entity for record in matched],
            evidence=refs,
            threshold=thresholds.get(rule.threshold_id) if rule.threshold_id else None,
            disconfirming_conditions=rule.disconfirming_conditions,
            verification_guidance=rule.verification_guidance,
            diagnosis_boundary=rule.diagnosis_boundary,
            lifecycle={"status": "OPEN", "first_seen_dataset": dataset.dataset_id, "last_seen_dataset": dataset.dataset_id, "occurrence_count": 1},
        )
        return result, finding

    def _evaluate_network_link_flap_rule(
        self,
        dataset: DeepDataset,
        rule: DeepRuleDefinition,
        thresholds: ThresholdRegistry,
        now: str,
    ) -> tuple[DeepRuleResult, DeepFinding | list[DeepFinding] | None]:
        all_records = [
            record
            for record in dataset.records
            if record.kind == rule.record_kind and record.metadata.get("rule_id", rule.rule_id) == rule.rule_id
        ]
        if not all_records:
            return DeepRuleResult(
                rule_id=rule.rule_id,
                rule_version=rule.rule_version,
                category=rule.category,
                profile=rule.profile,
                status=DeepResultStatus.INSUFFICIENT_DATA,
                reason="没有取得可评估的 vmnic link-state 事件记录",
                evaluated_at_utc=now,
            ), None
        host_records = [record for record in all_records if record.entity.type == "HostSystem"]
        if host_records:
            records = host_records
        elif any(int(record.window.sample_count or 0) > 0 for record in all_records):
            return DeepRuleResult(
                rule_id=rule.rule_id,
                rule_version=rule.rule_version,
                category=rule.category,
                profile=rule.profile,
                status=DeepResultStatus.INSUFFICIENT_DATA,
                evidence_refs=[evidence_ref(record).ref for record in all_records],
                reason="link-state 事件未关联到可确认的 ESXi 主机对象",
                evaluated_at_utc=now,
            ), None
        else:
            records = all_records

        changes_required = max(1, int(thresholds.get(rule.threshold_id or "").value))
        window_seconds = max(1, int(thresholds.get(rule.analysis_window_threshold_id or "").value))
        completeness_floor = thresholds.minimum_completeness().value
        incomplete = False
        unparsed_candidates = False
        confirmed: list[tuple[DatasetRecord, list[tuple[str, int]]]] = []
        host_sample_keys = {
            (str(sample.get("timestamp") or ""), str(sample.get("event_key") or ""), str(sample.get("message") or ""))
            for record in records
            for sample in record.metadata.get("event_samples", [])
            if isinstance(sample, dict)
        }
        all_sample_keys = {
            (str(sample.get("timestamp") or ""), str(sample.get("event_key") or ""), str(sample.get("message") or ""))
            for record in all_records
            for sample in record.metadata.get("event_samples", [])
            if isinstance(sample, dict)
        }
        if all_sample_keys - host_sample_keys:
            incomplete = True
            unparsed_candidates = True

        nic_pattern = re.compile(r"\b(vmnic\d+)\b", re.IGNORECASE)
        state_pattern = re.compile(
            r"\blink(?:[\s_.:-]*state)?[\s_.:=/-]*(?:is[\s:=/-]*)?(up|down)\b",
            re.IGNORECASE,
        )
        explicit_flap_pattern = re.compile(r"\blink[\s_.:-]*flapp(?:ing|ed)?\b", re.IGNORECASE)

        for record in records:
            if record.metadata.get("conflict"):
                incomplete = True
                continue
            if record.window.completeness < completeness_floor or record.metadata.get("collection_degraded"):
                incomplete = True
            samples = record.metadata.get("event_samples")
            if not isinstance(samples, list):
                incomplete = True
                unparsed_candidates = True
                continue
            if int(record.window.sample_count or 0) > len(samples):
                incomplete = True

            observations: dict[str, dict[tuple[str, str, str], tuple[datetime, str]]] = {}
            explicit_flap_nics: set[str] = set()
            for sample in samples:
                if not isinstance(sample, dict):
                    incomplete = True
                    unparsed_candidates = True
                    continue
                message = str(sample.get("message") or "")
                message_lower = message.casefold()
                nic_ids = {match.group(1).casefold() for match in nic_pattern.finditer(message)}
                state_matches = {match.group(1).casefold() for match in state_pattern.finditer(message)}
                explicit_flap = bool(explicit_flap_pattern.search(message))
                if explicit_flap and nic_ids:
                    explicit_flap_nics.update(nic_ids)
                if not nic_ids:
                    if any(token in message_lower for token in ("linkstate", "link state", "link down", "link up", "flapping", "vmnic")):
                        unparsed_candidates = True
                    continue
                if len(nic_ids) != 1 or len(state_matches) != 1:
                    unparsed_candidates = True
                    continue
                if not sample.get("timestamp"):
                    unparsed_candidates = True
                    continue
                try:
                    timestamp = datetime.fromisoformat(str(sample["timestamp"]).replace("Z", "+00:00")).astimezone(UTC)
                except (TypeError, ValueError):
                    unparsed_candidates = True
                    continue
                nic = next(iter(nic_ids))
                state = next(iter(state_matches))
                normalized_message = " ".join(message_lower.split())
                observation_key = (timestamp.isoformat(), state, normalized_message)
                # Different event keys can describe the same object, instant, and state message.
                observations.setdefault(nic, {}).setdefault(observation_key, (timestamp, state))

            matched_nics: list[tuple[str, int]] = []
            for nic, keyed_observations in observations.items():
                if nic in explicit_flap_nics:
                    matched_nics.append((nic, changes_required))
                    continue
                ordered = sorted(keyed_observations.values(), key=lambda item: (item[0], item[1]))
                for start in range(len(ordered)):
                    first_time, prior_state = ordered[start]
                    changes = 0
                    for event_time, state in ordered[start + 1 :]:
                        if (event_time - first_time).total_seconds() > window_seconds:
                            break
                        if state != prior_state:
                            changes += 1
                            prior_state = state
                            if changes >= changes_required:
                                matched_nics.append((nic, changes))
                                break
                    if any(item[0] == nic for item in matched_nics):
                        break
            if matched_nics:
                confirmed.append((record, matched_nics))

        evidence_records = [record for record, _matches in confirmed] if confirmed else records
        refs = [evidence_ref(record) for record in evidence_records]
        findings: list[DeepFinding] = []
        finding_ids: list[str] = []
        for record, matches in confirmed:
            scope = self._scope(rule, [record])
            identifier = finding_id(rule.rule_id, scope)
            finding_ids.append(identifier)
            nic_details = ", ".join(f"{nic}（{count} 次状态转换）" for nic, count in matches)
            finding_refs = [evidence_ref(record)]
            findings.append(
                DeepFinding(
                    finding_id=identifier,
                    rule_id=rule.rule_id,
                    rule_version=rule.rule_version,
                    title=rule.title,
                    category=rule.category,
                    confidence_class=rule.confidence_class,
                    scope=scope,
                    display_priority=rule.display_priority,
                    impact=rule.impact,
                    urgency=rule.urgency,
                    fact=f"{nic_details} 在 {window_seconds} 秒窗口内达到 link-state 转换阈值 {changes_required}。",
                    finding="检测到同一 vmnic 在短时间内反复经历 up/down 状态转换。",
                    entities=[record.entity],
                    evidence=finding_refs,
                    threshold=thresholds.get(rule.threshold_id or ""),
                    disconfirming_conditions=rule.disconfirming_conditions,
                    verification_guidance=rule.verification_guidance,
                    diagnosis_boundary=rule.diagnosis_boundary,
                    lifecycle={"status": "OPEN", "first_seen_dataset": dataset.dataset_id, "last_seen_dataset": dataset.dataset_id, "occurrence_count": 1},
                )
            )

        if findings:
            status = DeepResultStatus.FINDING
            reason = "已保留达到 link-flap 阈值的主机；部分窗口或事件样本不完整" if incomplete else ""
        elif incomplete or unparsed_candidates:
            status = DeepResultStatus.INSUFFICIENT_DATA
            reason = "link-state 事件覆盖不完整或候选记录无法解析，不能判定没有链路抖动"
        else:
            status = DeepResultStatus.PASS
            reason = "完整事件窗口内未发现达到重复 up/down 转换阈值的 vmnic"
        result = DeepRuleResult(
            rule_id=rule.rule_id,
            rule_version=rule.rule_version,
            category=rule.category,
            profile=rule.profile,
            status=status,
            finding_ids=sorted(set(finding_ids)),
            evidence_refs=[item.ref for item in refs],
            reason=reason,
            evaluated_at_utc=now,
        )
        if not findings:
            return result, None
        return result, findings

    def _evaluate_partial_signal_rule(
        self,
        dataset: DeepDataset,
        rule: DeepRuleDefinition,
        thresholds: ThresholdRegistry,
        now: str,
    ) -> tuple[DeepRuleResult, DeepFinding | None]:
        records = [
            record
            for record in dataset.records
            if record.kind == rule.record_kind and record.metadata.get("rule_id", rule.rule_id) == rule.rule_id
        ]
        if not records:
            return DeepRuleResult(
                rule_id=rule.rule_id,
                rule_version=rule.rule_version,
                category=rule.category,
                profile=rule.profile,
                status=DeepResultStatus.INSUFFICIENT_DATA,
                reason=f"{rule.title}证据未采集",
                evaluated_at_utc=now,
            ), None
        if all(record.metadata.get("not_applicable") for record in records) and not any(record.metadata.get("conflict") for record in records):
            return DeepRuleResult(
                rule_id=rule.rule_id,
                rule_version=rule.rule_version,
                category=rule.category,
                profile=rule.profile,
                status=DeepResultStatus.NOT_APPLICABLE,
                reason=f"{rule.title}不适用于当前对象",
                evaluated_at_utc=now,
            ), None

        conflicts = [record for record in records if record.metadata.get("conflict")]
        matched = [record for record in records if record.finding and not record.metadata.get("conflict")]
        minimum = thresholds.minimum_completeness().value
        incomplete = any(
            record.metadata.get("conflict")
            or record.window.completeness < minimum
            or not bool(record.metadata.get("coverage_complete", True))
            for record in records
        )
        if not matched and incomplete:
            refs = [evidence_ref(record) for record in conflicts or records]
            reason = (
                f"conflicting evidence across sources ({len(conflicts)} records); {rule.title} coverage is incomplete"
                if conflicts
                else f"没有发现已确认异常，但 {rule.title}覆盖不完整或证据冲突"
            )
            return DeepRuleResult(
                rule_id=rule.rule_id,
                rule_version=rule.rule_version,
                category=rule.category,
                profile=rule.profile,
                status=DeepResultStatus.INSUFFICIENT_DATA,
                evidence_refs=[item.ref for item in refs],
                reason=reason,
                evaluated_at_utc=now,
            ), None

        evidence_records = matched or records
        if matched and incomplete:
            evidence_records = [
                *matched,
                *[record for record in records if record.metadata.get("storage_policy_summary") or record.metadata.get("conflict")],
            ]
        refs = [evidence_ref(record) for record in evidence_records]
        scope = self._scope(rule, matched or records)
        status = DeepResultStatus.FINDING if matched else DeepResultStatus.PASS
        reason = f"已发现明确异常；{rule.title}其他范围仍有未取得状态或证据冲突" if matched and incomplete else ""
        result = DeepRuleResult(
            rule_id=rule.rule_id,
            rule_version=rule.rule_version,
            category=rule.category,
            profile=rule.profile,
            status=status,
            finding_ids=[finding_id(rule.rule_id, scope)] if matched else [],
            evidence_refs=[item.ref for item in refs],
            reason=reason,
            evaluated_at_utc=now,
        )
        if not matched:
            return result, None
        first = matched[0]
        finding = DeepFinding(
            finding_id=finding_id(rule.rule_id, scope),
            rule_id=rule.rule_id,
            rule_version=rule.rule_version,
            title=rule.title,
            category=rule.category,
            confidence_class=rule.confidence_class,
            scope=scope,
            display_priority=rule.display_priority,
            impact=rule.impact,
            urgency=rule.urgency,
            fact=first.summary or rule.title,
            finding=first.summary or rule.title,
            entities=[record.entity for record in matched],
            evidence=refs,
            evidence_sufficiency="SUFFICIENT",
            disconfirming_conditions=rule.disconfirming_conditions,
            verification_guidance=rule.verification_guidance,
            diagnosis_boundary=rule.diagnosis_boundary,
            lifecycle={"status": "OPEN", "first_seen_dataset": dataset.dataset_id, "last_seen_dataset": dataset.dataset_id, "occurrence_count": 1},
        )
        return result, finding

    def _scope(self, rule: DeepRuleDefinition, records: list[DatasetRecord]) -> FindingScope:
        ids = sorted({record.entity.stable_id for record in records})
        scope_id = ids[0] if rule.scope_type != ScopeType.AGGREGATE else "aggregate:" + ",".join(ids)
        return FindingScope(scope_type=rule.scope_type, scope_id=scope_id, dimension_key=rule.dimension_key, member_ids=ids)

    def _build_report(self, results: list[DeepRuleResult], findings: list[DeepFinding]) -> DeepReport:
        pass_counter = Counter((item.category.value, item.profile) for item in results if item.status == DeepResultStatus.PASS)
        scopes: list[DeepAnalysisScope] = []
        for category in DeepCategory:
            completed = [item for item in results if item.category == category and item.status in {DeepResultStatus.PASS, DeepResultStatus.FINDING}]
            if not completed:
                continue
            scopes.append(
                DeepAnalysisScope(
                    category=category,
                    label=CATEGORY_LABELS[category],
                    completed_capabilities=sorted({item.profile for item in completed}),
                    finding_count=sum(len(item.finding_ids) for item in completed),
                    pass_count=sum(item.status == DeepResultStatus.PASS for item in completed),
                )
            )
        pass_summary = [
            {"category": category, "profile": profile, "passed": count}
            for (category, profile), count in sorted(pass_counter.items())
        ]
        return DeepReport(
            analysis_scope=scopes,
            pass_summary=pass_summary,
            findings=[item for item in findings if item.report_visible and item.evidence_sufficiency == "SUFFICIENT"],
            trend_chain_verified=any(item.category == DeepCategory.TREND and item.confidence_class.value == "STATISTICAL" for item in findings),
        )
