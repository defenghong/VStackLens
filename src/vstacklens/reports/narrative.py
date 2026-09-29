"""Deterministic, presentation-only interpretations for customer PDF pages."""

from __future__ import annotations

from typing import Any


def build_pdf_narratives(payload: dict[str, Any]) -> dict[str, str]:
    """Build short interpretations from already-collected report facts.

    This module deliberately makes no health/risk decisions. It only describes
    counts and states that have already been classified by the report payload.
    """
    counts = payload.get("counts") or {}
    risks = payload.get("risk_counts") or {}
    affected = payload.get("affected_counts") or {}
    scope = payload.get("scope") or {}
    overview = payload.get("overview") or {}
    clusters = payload.get("cluster_details") or []
    hosts = payload.get("host_details") or []
    datastores = payload.get("datastores") or []
    vsan = payload.get("vsan") or {}
    network = payload.get("network") or {}
    security = payload.get("security") or {}
    certificates = payload.get("certificates") or {}
    actionable = payload.get("problems") or []
    optimizations = payload.get("optimizations") or []

    p1, p2, p3 = (int(risks.get(key) or 0) for key in ("P1", "P2", "P3"))
    total = p1 + p2 + p3
    executive = (
        f"本次覆盖 {counts.get('clusters', 0)} 个集群、{counts.get('hosts', 0)} 台主机、"
        f"{counts.get('vms', 0)} 台虚拟机及 {counts.get('datastores', 0)} 个存储。"
        f"过滤指定不展示的检查项后，共有 {total} 项需要处理（P1 {p1}、P2 {p2}、P3 {p3}），"
        f"对应 {sum(int(affected.get(key) or 0) for key in ('P1', 'P2', 'P3'))} 个受影响对象。"
    )
    if vsan.get("enabled"):
        executive += (
            f"vSAN 容量使用 {vsan.get('used_percent_text', '未采集')}；"
            f"本次重同步对象 {vsan.get('resync_objects_text', '未采集')}。"
        )
    else:
        executive += "本次未发现已启用且成功采集的 vSAN 集群数据。"

    vm_total = int(counts.get("vms") or 0)
    on = int(counts.get("powered_on") or 0)
    highest = overview.get("highest_category") or "未见可排序的风险类别"
    scope_text = (
        f"本次包含 {scope.get('visible_rule_count', 0)} 条可展示规则，"
        f"可见结果 {scope.get('visible_result_total', 0)} 条；其中不可用 {scope.get('unavailable_total', 0)} 条、"
        f"不适用 {scope.get('not_applicable_total', 0)} 条。"
        "不可用表示本次缺少足够证据，不等同于通过；不适用按对象类型或配置条件排除。"
    )

    cluster_enabled = sum(item.get("ha_enabled") is True for item in clusters)
    cluster_missing_hb = sum(
        item.get("ha_enabled") is True and item.get("heartbeat_count") == 0
        for item in clusters
    )
    cluster_text = (
        f"{len(clusters)} 个集群中 {cluster_enabled} 个已启用 HA；"
        f"其中 {cluster_missing_hb} 个启用 HA 的集群未配置心跳数据存储。"
        "下方同时列出准入控制、隔离响应、DRS、EVC 与 vMotion 状态，便于按集群定位配置差异。"
    )

    connected = sum(item.get("connection") == "已连接" for item in hosts)
    hw_issues = sum(int(item.get("hardware_issue_count") or 0) for item in hosts if item.get("hardware_issue_count") is not None)
    host_text = (
        f"{len(hosts)} 台主机中 {connected} 台处于已连接状态；硬件异常汇总 {hw_issues} 项。"
        "CPU 与内存使用率采用采集时点值，80% 仅作为图示参考线，不替代持续性能分析。"
    )

    overcommit = sum(item.get("overcommit") is True for item in hosts)
    unknown_overcommit = sum(item.get("overcommit") is None for item in hosts)
    capacity_text = (
        f"主机资源表列出物理核心、已分配 vCPU、内存容量与分配比例；当前 {overcommit} 台记录为超配，"
        f"{unknown_overcommit} 台状态未采集。Top 5 展示 vCPU 配置数和虚拟磁盘配置容量；"
        "容量占比是同主机已采集 VMDK 配置容量占比，不代表实际 datastore 占用。"
    )

    known_stores = [item for item in datastores if item.get("usage") is not None]
    max_store = max(known_stores, key=lambda item: item["usage"], default=None)
    store_text = (
        f"共列出 {len(datastores)} 个数据存储，其中 {len(known_stores)} 个有可用容量使用率。"
        + (
            f"使用率最高的是 {max_store['name']}（{max_store['usage']:.1f}%）。"
            if max_store else "当前没有可用于比较的容量使用率。"
        )
        + "每条容量条同时标注已用、可用比例与总容量，数值口径来自本次采集。"
    )

    vsan_text = (
        f"vSAN 覆盖 {len(vsan.get('clusters') or [])} 个集群、{vsan.get('disk_group_count_text', '未采集')} 个磁盘组；"
        f"物理盘 {vsan.get('disk_count_text', '未采集')} 块，已确认正常 {vsan.get('healthy_disks_text', '未采集')} 块。"
        f"对象 {vsan.get('object_count_text', '未采集')} 个、VMDK {vsan.get('vmdk_count_text', '未采集')} 个；"
        f"{('当前无待重同步对象或数据。' if vsan.get('no_resync') else '重同步状态按已采集字段展示；未返回的字段不推断为零。')}"
    )
    if vsan.get("storage_policy_status") in {"api_error", "unavailable", "permission_denied", "unsupported"}:
        policy_counts = vsan.get("storage_policy_vm_counts") or {}
        vsan_text += (
            f"存储策略查询有 {policy_counts.get('api_error', 0)} 台虚拟机返回 API 错误，"
            f"{policy_counts.get('collected', 0)} 台返回结果；未成功返回的对象不推断为合规。"
        )
    policy_counts = vsan.get("storage_policy_vm_counts") or {}
    storage_vsan_text = (
        f"共列出 {len(datastores)} 个数据存储，使用率最高 {max_store['usage']:.1f}%。"
        if max_store else f"共列出 {len(datastores)} 个数据存储，本次未取得可比较的使用率。"
    )
    if vsan.get("enabled"):
        storage_vsan_text += (
            f" vSAN 总量 {vsan.get('total_display', '未采集')} GB、已用 {vsan.get('used_display', '未采集')} GB"
            f"（{vsan.get('used_percent_text', '未采集')}），对象 {vsan.get('object_count_text', '未采集')} 个、"
            f"VMDK {vsan.get('vmdk_count_text', '未采集')} 个，物理盘 {vsan.get('healthy_disks_text', '未采集')}/{vsan.get('disk_count_text', '未采集')} 块正常。"
        )
    else:
        storage_vsan_text += " 本次没有采集到可确认的 vSAN 集群数据。"
    storage_vsan_text += (
        f" 重同步为 {vsan.get('resync_summary_text', '未采集')}。"
        + (
            f"存储策略有 {policy_counts.get('api_error', 0)} 台虚拟机 API 错误、{policy_counts.get('collected', 0)} 台返回结果，"
            "错误对象不推断为合规。"
            if vsan.get("storage_policy_failure") else ""
        )
    )

    network_text = (
        f"采集到 {network.get('vmkernel_count', 0)} 个 VMkernel 适配器和 {network.get('pnic_detail_count', 0)} 条物理网卡异常明细；"
        f"链路中断 {network.get('pnic_down_count', 0)} 块，分布在 {network.get('pnic_down_host_count', 0)} 台主机，"
        f"速率或协商异常 {network.get('pnic_degraded_count', 0)} 块。链路中断依据主机级 pnic_down_count，"
        "实际/配置速率未采集时不以速率字段推断链路状态。"
    )

    cert_hosts = certificates.get("hosts") or []
    expiring = sum(bool(item.get("attention")) or bool(item.get("expired")) for item in cert_hosts)
    security_text = (
        f"主机安全基线统计覆盖 {len(hosts)} 台主机：SSH 运行 {security.get('ssh_running', 0)} 台，"
        f"ESXi Shell 运行 {security.get('shell_running', 0)} 台，配置 NTP {security.get('ntp_configured', 0)} 台，"
        f"端口组策略命中 {security.get('portgroup_issues', 0)} 项。"
        f"当前证书信息中有 {expiring} 台主机到期或剩余不超过 90 天；未采集到期日的对象单独标示。"
    )
    network_security_text = (
        f"本次采集 {network.get('vmkernel_count', 0)} 个 VMkernel 和 {network.get('pnic_detail_count', 0)} 条物理网卡异常明细；"
        f"{network.get('pnic_down_count', 0)} 块断链分布在 {network.get('pnic_down_host_count', 0)} 台主机，判定依据为主机级 pnic_down_count，速率字段未采集不参与判定。"
        f"安全基线覆盖 {len(hosts)} 台主机，端口组策略命中 {security.get('portgroup_issues', 0)} 项；"
        f"已列出 vCenter 与 {len(cert_hosts)} 台主机证书到期信息。"
    )

    remediation_text = (
        f"处置清单包含 {len(actionable)} 项需处理事项和 {len(optimizations)} 项优化建议。"
        "每项保留责任角色、工作量、维护窗口要求、完整步骤和复核方式；建议按 P1、P2、P3 顺序安排。"
    )
    optimization_text = (
        f"另有 {len(optimizations)} 类优化建议，涉及 {sum(int(item.get('count') or 0) for item in optimizations)} 个对象。"
        "这些项目与需处理事项分开列示，不并入 P1-P3 项数。"
    )
    storage_vsan_text = (
        f"共列出 {len(datastores)} 个数据存储，{len(known_stores)} 个有使用率；"
        + (f"最高为 {max_store['name']}（{max_store['usage']:.1f}%）。" if max_store else "本次未取得可比较的容量使用率。")
        + (
            f"vSAN 总容量 {vsan.get('total_display', '未采集')} GB、已用 {vsan.get('used_display', '未采集')} GB"
            f"（{vsan.get('used_percent_text', '未采集')}），对象/VMDK {vsan.get('object_count_text', '未采集')}/{vsan.get('vmdk_count_text', '未采集')}，"
            f"{vsan.get('healthy_disks_text', '未采集')}/{vsan.get('disk_count_text', '未采集')} 块物理盘正常。"
            if vsan.get("enabled") else "本次没有采集到可确认的 vSAN 集群数据。"
        )
        + f"重同步：{vsan.get('resync_summary_text', '未采集')}。"
    )
    if vsan.get("storage_policy_failure"):
        policy_counts = vsan.get("storage_policy_vm_counts") or {}
        storage_vsan_text += (
            f"存储策略查询有 {policy_counts.get('api_error', 0)} 台虚拟机 API 错误、"
            f"{policy_counts.get('collected', 0)} 台返回结果；错误对象不推断为合规。"
        )

    return {
        "executive": executive,
        "scope": scope_text,
        "overview": (
            f"虚拟机开机 {on}/{vm_total} 台；需处理事项中 P1 {p1} 项、P2 {p2} 项、P3 {p3} 项。"
            f"当前数量最多的风险类别为“{highest}”；此处为规则输出数量统计。"
        ),
        "clusters": cluster_text,
        "hosts": host_text,
        "host_resources": (
            host_text
            + f"主机资源配置中 {overcommit} 台记录为超配；主机 CPU/内存使用率是采集时点值，80% 线仅作定位参考。"
            + "Top 5 使用已采集 vCPU 数和 VMDK 配置容量；没有可靠 quickStats 时不代用其他指标。"
        ),
        "capacity": capacity_text,
        "storage": store_text,
        "storage_vsan": storage_vsan_text,
        "storage_vsan": storage_vsan_text,
        "vsan": vsan_text,
        "network": network_text,
        "security": security_text,
        "network_security": network_security_text,
        "remediation": remediation_text,
        "optimizations": optimization_text,
    }
