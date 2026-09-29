from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ModuleDescriptor:
    module_id: str
    module_name: str
    description: str
    status: str
    icon_name: str = ""


@dataclass(frozen=True, slots=True)
class CapabilityDescriptor:
    capability_id: str
    capability_name: str
    description: str
    status: str


def primary_modules() -> list[ModuleDescriptor]:
    return [
        ModuleDescriptor("dashboard", "仪表盘", "查看当前环境状态、风险摘要、资产概况、证书与授权状态和最近报告。", "available", "DB"),
        ModuleDescriptor("vcenter_management", "vCenter 管理", "基于已完成巡检记录查看本机保存的 vCenter 对象和最近健康状态。", "available", "VC"),
        ModuleDescriptor("inspection_center", "巡检中心", "输入 vCenter 地址、用户名和密码后发起本地虚拟化健康评估。", "available", "IN"),
        ModuleDescriptor("log_analysis", "日志分析", "导入 VMware support bundle 日志包并填写问题描述，生成独立日志分析报告。", "available", "LG"),
        ModuleDescriptor("upgrade_compat", "升级兼容性", "选择目标 ESXi 版本后连接 vCenter 或导入 support bundle，基于本地 HCL 数据判定硬件、驱动和固件兼容性。", "available", "UC"),
        ModuleDescriptor("risk_center", "风险中心", "基于当前巡检结果按等级、对象和关键字查看风险条目。", "available", "RK"),
        ModuleDescriptor("asset_center", "资产中心", "基于最新巡检资产快照展示对象清单和归属关系。", "available", "AS"),
        ModuleDescriptor("history_compare", "历史对比", "基于本机 SQLite 中的多次巡检记录对比风险和资产变化。", "available", "HC"),
        ModuleDescriptor("report_center", "报告中心", "查看和管理本工具生成的巡检、日志分析和升级兼容性报告。", "available", "RP"),
        ModuleDescriptor("settings", "系统设置", "维护本机数据库和报告目录。", "available", "ST"),
        ModuleDescriptor("license", "关于软件", "查看软件版本、本地运行状态和数据目录信息。", "available", "AB"),
    ]


def inspection_capabilities() -> list[CapabilityDescriptor]:
    return [
        CapabilityDescriptor("virtual_health", "虚拟化健康评估", "输入 vCenter 地址、用户名和密码后，本地完成配置、性能、容量、网络、存储、安全评估。", "enabled"),
        CapabilityDescriptor("batch_assessment", "批量巡检", "多 vCenter 批量评估将在后续版本启用。", "planned"),
        CapabilityDescriptor("scheduled_assessment", "计划巡检", "本地计划任务能力将在后续版本启用。", "planned"),
        CapabilityDescriptor("report_export", "Word 报告导出", "巡检完成后可生成离线 Word .docx 报告。", "enabled"),
    ]
