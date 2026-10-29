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
        ModuleDescriptor("dashboard", "首页", "查看当前环境状态、风险摘要、资产概况、证书与授权状态和最近报告。", "available", "DB"),
        ModuleDescriptor("vcenter_management", "环境档案", "登记客户环境与巡检目标，查看采集记录，并进入该环境的资产、风险、历史和报告。", "available", "VC"),
        ModuleDescriptor("inspection_center", "巡检中心", "输入 vCenter 地址、用户名和密码后发起本地虚拟化健康评估。", "available", "IN"),
        ModuleDescriptor("risk_center", "风险中心", "基于当前巡检结果按等级、对象和关键字查看风险条目。", "available", "RK"),
        ModuleDescriptor("asset_center", "资产中心", "基于最新巡检资产快照展示对象清单和归属关系。", "available", "AS"),
        ModuleDescriptor("history_compare", "历史对比", "基于本机 SQLite 中的多次巡检记录对比风险和资产变化。", "available", "HC"),
        ModuleDescriptor("report_center", "报告中心", "查看和管理本工具生成的巡检、日志分析和升级兼容性报告。", "available", "RP"),
        ModuleDescriptor("log_analysis", "日志分析", "导入 VMware support bundle 日志包并填写问题描述，生成独立日志分析报告。", "available", "LG"),
        ModuleDescriptor("upgrade_compat", "升级兼容性", "选择目标 ESXi 版本后连接 vCenter 或导入 support bundle，基于本地 HCL 数据判定硬件、驱动和固件兼容性。", "available", "UC"),
        ModuleDescriptor("settings", "系统设置", "维护本机数据库和报告目录。", "available", "ST"),
        ModuleDescriptor("license", "关于软件", "查看软件版本、本地运行状态和数据目录信息。", "available", "AB"),
    ]


def inspection_capabilities() -> list[CapabilityDescriptor]:
    return [
        CapabilityDescriptor("virtual_health", "虚拟化健康评估", "输入 vCenter 地址、用户名和密码后，本地完成配置、性能、容量、网络、存储、安全评估。", "enabled"),
        CapabilityDescriptor("batch_assessment", "批量标准巡检", "从环境档案选择多个目标，使用独立会话凭据串行执行并分别交付报告。", "enabled"),
        CapabilityDescriptor("scheduled_assessment", "计划标准巡检", "软件运行期间按每日或每周计划执行；本次会话明确授权凭据，错过不补跑，退出后停止。", "enabled"),
        CapabilityDescriptor("report_export", "Word 报告导出", "巡检完成后可生成离线 Word .docx 报告。", "enabled"),
    ]
