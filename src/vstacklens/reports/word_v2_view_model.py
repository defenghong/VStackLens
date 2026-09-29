from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Sequence

from vstacklens.reports.report_model import ReportData
from vstacklens.reports.word_v2_templates import (
    DetailTable,
    TableColumn,
    build_detail_table,
    customer_title,
    engineering_sort_key,
    template_key,
)


STAGE1_CATEGORY_IDS = ("CLUSTER-DRS", "HOST-PNIC", "VM-CDROM", "VM-SNAPSHOT")


@dataclass
class CoverView:
    customer_name: str
    report_title: str
    inspection_date: str
    report_version: str
    generated_at: str


@dataclass
class RiskDefinitionView:
    level: str
    definition: str


@dataclass
class OverviewView:
    scope_rows: list[dict[str, Any]]
    resource_scale: list[list[Any]]
    risk_definitions: list[RiskDefinitionView]
    evaluation_statements: list[str]


@dataclass
class RiskSummaryRow:
    serial_no: int
    level: str
    title: str
    object_type: str
    affected_object_count: int


@dataclass
class ResultAnalysisView:
    risk_rows: list[RiskSummaryRow]
    risk_distribution: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class RiskItemView:
    display_id: str
    level: str
    title: str
    problem: str
    recommendation: str
    template_key: str
    detail_table: DetailTable
    affected_object_count: int
    source_category_id: str = ""


@dataclass
class VsanView:
    applicable: bool
    basic_rows: list[list[Any]]
    conclusion: str
    object_health_text: str
    resync_text: str
    capacity_rows: list[list[Any]]
    detail_tables: list[DetailTable] = field(default_factory=list)


@dataclass
class ConclusionView:
    vsphere_status: str
    vsphere_items: list[str]
    vsan_status: str
    vsan_items: list[str]


@dataclass
class WordV2ViewModel:
    cover: CoverView
    toc_sections: list[str]
    overview: OverviewView
    result_analysis: ResultAnalysisView
    risk_items: list[RiskItemView]
    vsan: VsanView
    conclusion: ConclusionView
    validation_errors: list[str] = field(default_factory=list)


class WordV2ViewModelBuilder:
    """Build the stage-one customer-facing Word model without judging data."""

    def __init__(self, *, category_ids: Sequence[str] | None = None) -> None:
        self.category_ids = set(category_ids) if category_ids is not None else None

    def build(self, report: ReportData) -> WordV2ViewModel:
        categories = self._categories(report)
        asset_index = self._asset_index(report)
        finding_index = self._finding_index(report)
        risk_items = self._risk_items(categories, asset_index, finding_index)
        validation_errors = self._validate_risks(risk_items)
        vsan = self._vsan_view(report)
        overview = self._overview(report, risk_items)
        result_analysis = self._result_analysis(risk_items)
        conclusion = self._conclusion(report, risk_items, vsan)
        return WordV2ViewModel(
            cover=self._cover(report),
            toc_sections=self._toc_sections(),
            overview=overview,
            result_analysis=result_analysis,
            risk_items=risk_items,
            vsan=vsan,
            conclusion=conclusion,
            validation_errors=validation_errors,
        )

    def _cover(self, report: ReportData) -> CoverView:
        generated = str(report.report_info.generated_at or "未采集")
        return CoverView(
            customer_name=str(report.customer_info.customer_name or "未指定客户"),
            report_title="虚拟化平台健康巡检报告",
            inspection_date=generated[:10] if generated else "未采集",
            report_version=str(report.report_info.report_version or "V1.0"),
            generated_at=generated.replace("T", " ").split("+", 1)[0],
        )

    def _toc_sections(self) -> list[str]:
        return [
            "1. 巡检概况",
            "2. 巡检结果总体分析",
            "3. 风险项详细说明及优化建议",
            "4. vSAN 专项巡检",
            "6. 巡检结论与建议",
        ]

    def _overview(self, report: ReportData, risks: list[RiskItemView]) -> OverviewView:
        scale = self._environment_scale(report)
        vcenters = self._asset_details(report, "vCenter")
        if not vcenters:
            vcenters = [{"object_name": report.customer_info.vcenter or "未采集", "properties": {}}]
        scope_rows = []
        for index, item in enumerate(vcenters, start=1):
            props = item.get("properties") or {}
            scope_rows.append({
                "serial_no": index,
                "vcenter_name": props.get("vcenter_name") or item.get("vcenter_name") or (report.report_presentation or {}).get("vcenter_name") or "未采集",
                "management_address": props.get("management_address") or report.customer_info.vcenter or item.get("object_name") or "未采集",
                "esxi_host_count": scale["host"],
                "datastore_count": scale["datastore"],
                "vm_count": scale["vm"],
            })
        counts = self._risk_counts(risks)
        domains = self._risk_domains(risks)
        statements = [
            f"本次巡检共识别 {sum(counts.values())} 类风险，其中 P1 {counts['P1']} 类、P2 {counts['P2']} 类、P3 {counts['P3']} 类。",
            "当前环境具备持续运行基础，但集群配置、主机状态及虚拟机治理方面存在需要处理的风险。" if risks else "本次选定的巡检范围内未发现需要列入风险详情的异常。",
            f"当前主要风险集中在{'、'.join(domains[:3])}。" if domains else "当前未形成需要单独归类的风险集中方向。",
            "建议优先处理 P1 风险，再结合维护窗口处理 P2/P3 项目。" if counts["P1"] else "建议结合维护窗口处理 P2/P3 项目。",
        ]
        resource_scale = [
            ["vCenter 数量", scale["vcenter"], "ESXi 主机数量", scale["host"]],
            ["Cluster 数量", scale["cluster"], "虚拟机数量", scale["vm"]],
            ["Datastore 数量", scale["datastore"], "vSAN 集群数量", scale["vsan_cluster"]],
        ]
        definitions = [
            RiskDefinitionView("P1", "需要优先处理或确认的风险"),
            RiskDefinitionView("P2", "建议规划整改的问题"),
            RiskDefinitionView("P3", "优化建议或持续治理事项"),
        ]
        return OverviewView(scope_rows, resource_scale, definitions, statements)

    def _result_analysis(self, risks: list[RiskItemView]) -> ResultAnalysisView:
        rows = [
            RiskSummaryRow(index, risk.level, risk.title, self._risk_object_type(risk), risk.affected_object_count)
            for index, risk in enumerate(risks, start=1)
        ]
        return ResultAnalysisView(rows)

    def _risk_items(self, categories: list[dict[str, Any]], asset_index: dict[str, dict[str, Any]], finding_index: dict[str, Any]) -> list[RiskItemView]:
        selected = sorted(categories, key=engineering_sort_key)
        result: list[RiskItemView] = []
        for index, category in enumerate(selected, start=1):
            category_id = str(category.get("category_id") or "")
            key = template_key(category)
            detail_table = build_detail_table(category, asset_index=asset_index, finding_index=finding_index)
            result.append(RiskItemView(
                display_id=f"3.{index}",
                level=str(category.get("priority") or category.get("risk_level") or "P3"),
                title=customer_title(category),
                problem=self._problem_text(category, key),
                recommendation=str(category.get("remediation") or category.get("remediation_zh") or self._default_recommendation(key)),
                template_key=key,
                detail_table=detail_table,
                affected_object_count=int(category.get("affected_object_count", len(category.get("affected_objects") or [])) or 0),
                source_category_id=category_id,
            ))
        return result

    def _problem_text(self, category: dict[str, Any], key: str) -> str:
        text = str(category.get("description") or category.get("summary") or "").strip()
        if text:
            return text
        return {
            "iso_mount": "经检查，当前环境存在挂载 ISO 镜像的虚拟机。",
            "snapshot": "经检查，当前环境存在保留快照的虚拟机。",
            "cluster_ha_drs": "经检查，部分集群 HA 或 DRS 配置未按预期启用。",
            "physical_nic": "经检查，部分 ESXi 主机物理网卡链路状态异常。",
        }.get(key, "经检查，当前对象存在需要关注的状态。")

    def _default_recommendation(self, key: str) -> str:
        return {
            "iso_mount": "建议核实 ISO 挂载用途，如无特殊使用需求，断开虚拟光驱并移除无效挂载。",
            "snapshot": "建议结合业务需求确认快照用途，对无保留必要的快照进行整合或删除。",
            "cluster_ha_drs": "建议结合授权、业务连续性和集群资源情况核对 HA/DRS 配置。",
            "physical_nic": "建议核对物理网卡、光模块、交换机端口、VLAN 及 Teaming 配置。",
        }.get(key, "建议结合受影响对象和技术证据安排处理。")

    def _vsan_view(self, report: ReportData) -> VsanView:
        summary = report.vsan_summary or {}
        presentation = (report.report_presentation or {}).get("vsan") or {}
        applicable = bool(summary.get("applicable")) or str(summary.get("applicability") or "").casefold() == "applicable" or str(presentation.get("applicable") or "").casefold() in {"yes", "true"}
        if not applicable:
            return VsanView(False, [], "本次环境未识别 vSAN 集群，未执行 vSAN 专项检查。", "未执行 vSAN 对象健康检查。", "未执行 vSAN Resync 检查。", [])
        capacity = summary.get("capacity") or {}
        rows = [
            ["架构", summary.get("architecture") or "未采集"],
            ["主机数", summary.get("host_count")],
            ["磁盘组", summary.get("disk_group_count")],
            ["缓存盘", summary.get("cache_disk_count")],
            ["容量盘", summary.get("capacity_disk_count")],
            ["对象数量", summary.get("object_count")],
            ["VMDK 对象", summary.get("vmdk_count")],
            ["当前 Resync", summary.get("resync_object_count")],
            ["vSAN 网络", self._network_status(summary)],
            ["容量总计", self._with_unit(capacity.get("total_gb"), "GB")],
            ["已用容量", self._with_unit(capacity.get("used_gb"), "GB")],
            ["容量使用率", self._with_unit(capacity.get("used_percent"), "%")],
        ]
        status = summary.get("health_status")
        conclusion = (
            "经本次巡检，当前 vSAN 集群整体运行正常，未发现对象不可访问、磁盘健康异常或正在进行的重同步任务，当前容量水位处于合理范围。"
            if status == "healthy"
            else "经本次巡检，当前 vSAN 环境存在需要关注的状态，具体结果见本章实际数据。"
        )
        detail_tables = []
        topology = summary.get("disk_topology") or []
        physical_disks = summary.get("physical_disks")
        physical_index: dict[tuple[str, str], dict[str, Any]] = {}
        for disk in physical_disks or []:
            host = str(disk.get("host") or "")
            for identity in (disk.get("name"), disk.get("scsi_device"), disk.get("uuid")):
                if identity:
                    physical_index[(host, str(identity).casefold())] = disk
        disk_rows = []
        for item in topology:
            host = str(item.get("host") or "")
            for group_index, group in enumerate(item.get("disk_groups") or [], start=1):
                group_name = str(group.get("id") or "").strip()
                if not group_name or group_name == "未记录":
                    group_name = f"磁盘组 {group_index}"
                devices = [("缓存盘", group.get("cache_disk")), *( ("容量盘", name) for name in (group.get("capacity_disks") or []) )]
                for role, device in devices:
                    if not device:
                        continue
                    disk = physical_index.get((host, str(device).casefold()))
                    health_values = [str((disk or {}).get(key) or "").casefold() for key in ("summary_health", "operational_health", "capacity_health")]
                    bad_values = {"red", "yellow", "error", "failed", "unhealthy", "offline", "absent", "lost", "degraded"}
                    if any(value in bad_values for value in health_values):
                        health_label = "异常"
                    elif disk and any(value in {"green", "healthy", "ok", "normal"} for value in health_values):
                        health_label = "正常"
                    else:
                        health_label = "未确认"
                    member = "已加入 vSAN" if disk and disk.get("in_cmmds") is True and disk.get("in_vsi") is True else "未确认"
                    capacity_bytes = (disk or {}).get("capacity_bytes")
                    disk_capacity = self._with_unit(round(float(capacity_bytes) / (1024 ** 3), 1), "GB") if capacity_bytes else "未采集"
                    disk_rows.append({
                        "host": host,
                        "disk_group": group_name,
                        "role": role,
                        "device": str(device),
                        "health": health_label,
                        "capacity": disk_capacity,
                        "membership": member,
                    })
        if disk_rows:
            detail_tables.append(DetailTable(
                "vsan_disk_details",
                [
                    TableColumn("host", "ESXi 主机"),
                    TableColumn("disk_group", "磁盘组"),
                    TableColumn("role", "磁盘角色"),
                    TableColumn("device", "设备名称"),
                    TableColumn("health", "健康状态"),
                    TableColumn("capacity", "容量"),
                    TableColumn("membership", "vSAN 状态"),
                ],
                disk_rows,
                len(disk_rows),
            ))

        vmkernel_rows = [
            {
                "host": item.get("host_name") or item.get("host") or "未记录",
                "device": item.get("device") or "未记录",
                "ip": item.get("ip_address") or "未记录",
                "subnet": item.get("subnet_mask") or "未记录",
                "network_label": item.get("network_label") or item.get("portgroup") or "未记录",
                "mtu": item.get("mtu") if item.get("mtu") is not None else "未记录",
            }
            for item in (summary.get("network") or {}).get("vmkernels") or []
            if isinstance(item, dict)
        ]
        if vmkernel_rows:
            detail_tables.append(DetailTable(
                "vsan_vmk_network",
                [
                    TableColumn("host", "主机"),
                    TableColumn("device", "设备"),
                    TableColumn("ip", "IP"),
                    TableColumn("subnet", "子网"),
                    TableColumn("network_label", "Network Label"),
                    TableColumn("mtu", "MTU"),
                ],
                vmkernel_rows,
                len(vmkernel_rows),
            ))
        object_issues = summary.get("object_issues") or []
        object_health_text = "未发现对象不可访问或异常状态对象。" if not object_issues else f"发现 {len(object_issues)} 个对象健康异常，具体对象见明细。"
        resync_count = summary.get("resync_object_count")
        resync_text = "当前未能确认 Resync 状态。" if resync_count is None else "当前无正在进行的 vSAN Resync 任务。" if resync_count == 0 else f"当前有 {resync_count} 个对象正在进行 Resync。"
        capacity_rows = [
            ["总容量", self._with_unit(capacity.get("total_gb"), "GB")],
            ["已用容量", self._with_unit(capacity.get("used_gb"), "GB")],
            ["可用容量", self._with_unit(capacity.get("free_gb"), "GB")],
            ["容量使用率", self._with_unit(capacity.get("used_percent"), "%")],
        ]
        return VsanView(True, rows, conclusion, object_health_text, resync_text, capacity_rows, detail_tables)

    def _network_status(self, summary: dict[str, Any]) -> str:
        network = summary.get("network") or {}
        status = network.get("status")
        vmkernel_count = len(network.get("vmkernels") or [])
        if status == "collected":
            return f"已采集，{vmkernel_count} 条 VMkernel"
        return "未确认"

    def _conclusion(self, report: ReportData, risks: list[RiskItemView], vsan: VsanView) -> ConclusionView:
        vsphere_items = [f"{risk.title}，建议{risk.recommendation.rstrip('。')}。" for risk in risks]
        vsphere_status = "存在需要关注的风险" if risks else "整体运行正常"
        vsan_status = "正常" if vsan.applicable and "整体运行正常" in vsan.conclusion else "需要关注"
        vsan_items = [vsan.conclusion]
        return ConclusionView(vsphere_status, vsphere_items, vsan_status, vsan_items)

    def _categories(self, report: ReportData) -> list[dict[str, Any]]:
        categories = list((report.report_presentation or {}).get("problem_categories") or report.problem_categories or [])
        if self.category_ids is not None:
            categories = [item for item in categories if str(item.get("category_id") or "") in self.category_ids]
        return [item for item in categories if str(item.get("priority") or item.get("risk_level") or "") in {"P1", "P2", "P3"}]

    def _asset_index(self, report: ReportData) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        details = (report.asset_inventory or {}).get("details") or {}
        for items in details.values():
            for item in items or []:
                if not isinstance(item, dict):
                    continue
                keys = [item.get("object_key"), item.get("object_name")]
                for key in keys:
                    if key not in (None, ""):
                        result[str(key).casefold()] = item
        return result

    def _finding_index(self, report: ReportData) -> dict[str, list[Any]]:
        result: dict[str, list[Any]] = {}
        for finding in report.findings or []:
            name = str(getattr(finding, "object_name", "") or "")
            if name:
                result.setdefault(name.casefold(), []).append(finding)
        return result

    def _asset_details(self, report: ReportData, key: str) -> list[dict[str, Any]]:
        return list(((report.asset_inventory or {}).get("details") or {}).get(key) or [])

    def _environment_scale(self, report: ReportData) -> dict[str, int]:
        presentation = report.report_presentation or {}
        source = presentation.get("environment_scale") or {}
        summary = (report.asset_inventory or {}).get("summary") or {}
        return {
            "vcenter": int(source.get("vcenter", summary.get("vCenter", 0)) or 0),
            "datacenter": int(source.get("datacenter", summary.get("Datacenter", 0)) or 0),
            "cluster": int(source.get("cluster", summary.get("ClusterComputeResource", 0)) or 0),
            "host": int(source.get("host", summary.get("HostSystem", 0)) or 0),
            "vm": int(source.get("vm", summary.get("VirtualMachine", 0)) or 0),
            "datastore": int(source.get("datastore", summary.get("Datastore", 0)) or 0),
            "vsan_cluster": int(source.get("vsan_cluster", 0) or 0),
        }

    def _risk_counts(self, risks: Iterable[RiskItemView]) -> dict[str, int]:
        counts = {"P1": 0, "P2": 0, "P3": 0}
        for risk in risks:
            if risk.level in counts:
                counts[risk.level] += 1
        return counts

    def _risk_domains(self, risks: list[RiskItemView]) -> list[str]:
        domains: list[str] = []
        for risk in risks:
            domain = {
                "cluster_ha_drs": "集群配置",
                "physical_nic": "主机网络",
                "iso_mount": "虚拟机介质管理",
                "snapshot": "虚拟机快照治理",
            }.get(risk.template_key, "平台配置")
            if domain not in domains:
                domains.append(domain)
        return domains

    def _risk_object_type(self, risk: RiskItemView) -> str:
        return {
            "iso_mount": "虚拟机",
            "snapshot": "虚拟机",
            "cluster_ha_drs": "Cluster",
            "physical_nic": "ESXi 主机",
            "hardware_health": "ESXi 主机",
        }.get(risk.template_key, "对象")

    def _validate_risks(self, risks: list[RiskItemView]) -> list[str]:
        errors = []
        for risk in risks:
            table = risk.detail_table
            if table.expected_row_count != table.actual_row_count:
                errors.append(f"{risk.source_category_id}: expected {table.expected_row_count}, got {table.actual_row_count}")
            if not table.rows:
                errors.append(f"{risk.source_category_id}: empty detail table")
        return errors

    def _with_unit(self, value: Any, unit: str) -> str:
        if value in (None, ""):
            return "未采集"
        return f"{value}{unit}"


__all__ = [
    "STAGE1_CATEGORY_IDS",
    "ConclusionView",
    "CoverView",
    "OverviewView",
    "ResultAnalysisView",
    "RiskItemView",
    "RiskSummaryRow",
    "VsanView",
    "WordV2ViewModel",
    "WordV2ViewModelBuilder",
]
