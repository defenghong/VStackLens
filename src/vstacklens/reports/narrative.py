"""Deterministic, presentation-only interpretations for customer PDF pages."""

from __future__ import annotations

from typing import Any

from vstacklens.reports.customer_format import percent_text


def build_pdf_narratives(payload: dict[str, Any]) -> dict[str, str]:
    """Build short interpretations from already-collected report facts.

    This module deliberately makes no health/risk decisions. It only describes
    counts and states that have already been classified by the report payload.
    """
    counts = payload.get("counts") or {}
    risks = payload.get("risk_counts") or {}
    scope = payload.get("scope") or {}
    clusters = payload.get("cluster_details") or []
    hosts = payload.get("host_details") or []
    datastores = payload.get("datastores") or []
    vsan = payload.get("vsan") or {}
    network = payload.get("network") or {}
    security = payload.get("security") or {}
    certificates = payload.get("certificates") or {}
    problems = payload.get("problems") or []
    display = payload.get("display_facts") or {}

    p1, p2, p3 = (int(risks.get(key) or 0) for key in ("P1", "P2", "P3"))
    executive = (
        f"本次覆盖 {counts.get('clusters', 0)} 个集群、{counts.get('hosts', 0)} 台主机、"
        f"{counts.get('vms', 0)} 台虚拟机及 {counts.get('datastores', 0)} 个存储。"
        f"发现 {len(problems)} 项需处理事项，其中 P1 {p1} 项、P2 {p2} 项、P3 {p3} 项。"
    )
    if payload.get("health_conclusion"):
        executive += f"健康结论：{payload['health_conclusion']}。"
    if vsan.get("enabled") and vsan.get("used_percent") is not None:
        executive += f"vSAN 容量使用率为 {percent_text(vsan['used_percent'])}。"
    if vsan.get("enabled") and vsan.get("no_resync"):
        executive += "当前无待重同步对象或数据。"

    scope_text = str(scope.get("summary_text") or "")
    cluster_enabled = sum(item.get("ha_enabled") is True for item in clusters)
    cluster_text = f"{len(clusters)} 个集群中 {cluster_enabled} 个已启用 HA。"
    disabled_clusters = [str(item.get('name') or '') for item in clusters if item.get('ha_enabled') is False]
    if disabled_clusters and all(disabled_clusters):
        cluster_text = cluster_text.rstrip('。') + '；尚未启用 HA 的是 ' + '、'.join(disabled_clusters) + '。'
    connected = payload.get("connected_host_count")
    known_hardware = [item.get("hardware_issue_count") for item in hosts if item.get("hardware_issue_count") is not None]
    host_text = (f"{len(hosts)} 台主机均已连接。" if connected == len(hosts) and hosts
                 else f"{len(hosts)} 台主机中 {connected} 台已连接。") if connected is not None else ""
    if len(known_hardware) == len(hosts) and hosts:
        host_text += f"硬件异常合计 {sum(int(value) for value in known_hardware)} 项。"
    host_text += f"CPU 与内存使用率为巡检时点值，{percent_text(80)} 线用于图示参考。"

    overcommit = sum(item.get("overcommit") is True for item in hosts)
    capacity_text = (
        "主机资源表列出容量与资源分配情况。"
        + (f"{overcommit} 台主机的资源分配比例偏高，建议结合实际负载评估。" if hosts and all(item.get("overcommit") is not None for item in hosts) else "")
        + "“资源分配与 Top 5”展示配置量；“虚拟机实际资源用量 Top 5”仅在取得实际用量时展示。"
    )
    max_store = max(datastores, key=lambda item: item.get("usage") or 0, default=None)
    store_text = f"本页列出 {len(datastores)} 个数据存储。"
    if max_store and max_store.get("usage") is not None:
        store_text = store_text.rstrip('。') + f"，{max_store['name']} 的使用率最高，为 {percent_text(max_store['usage'])}。"

    vsan_parts = []
    if vsan.get("enabled"):
        if vsan.get("total_display"):
            vsan_parts.append(f"vSAN 总容量 {vsan['total_display']}")
        if vsan.get("used_display") and vsan.get("used_percent_text"):
            vsan_parts.append(f"已用 {vsan['used_display']}（{vsan['used_percent_text']}）")
        if vsan.get("object_count") is not None:
            vsan_parts.append(f"对象 {vsan['object_count']:.0f} 个")
        if vsan.get("vmdk_count") is not None:
            vsan_parts.append(f"VMDK {vsan['vmdk_count']:.0f} 个")
        if vsan.get("no_resync"):
            vsan_parts.append("当前无待重同步对象或数据")
    vsan_text = (display.get("vsan") or {}).get("summary", "；".join(vsan_parts))
    storage_vsan_text = store_text + (' ' + vsan_text.rstrip('。') + '。' if vsan_text else "")

    network_text = (display.get("network") or {}).get("summary", "")
    cert_hosts = certificates.get("hosts") or []
    expiring = sum(bool(item.get("attention")) or bool(item.get("expired")) for item in cert_hosts)
    security_text = (
        f"安全基线覆盖 {len(hosts)} 台主机。"
        f"证书已到期或将在 90 天内到期的主机为 {expiring} 台。"
    )
    network_security_text = network_text + security_text
    remediation_text = f"以下 {len(problems)} 类问题按处理优先级排列，可依照相应建议处理并复查。"

    return {
        "executive": executive,
        "scope": scope_text,
        "overview": f"虚拟机开机 {counts.get('powered_on', 0)}/{counts.get('vms', 0)} 台；发现 P1 {p1} 项、P2 {p2} 项、P3 {p3} 项。",
        "clusters": cluster_text,
        "hosts": host_text,
        "host_resources": host_text + capacity_text,
        "capacity": capacity_text,
        "storage": store_text,
        "storage_vsan": storage_vsan_text,
        "vsan": vsan_text,
        "network": network_text,
        "security": security_text,
        "network_security": network_security_text,
        "remediation": remediation_text,
        "optimizations": "",
    }
