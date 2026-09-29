from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

from vstacklens.reports.report_model import ReportData
from vstacklens.reports.narrative import build_pdf_narratives
from vstacklens.resources import package_resource_path, project_resource_path


class PdfReportEngine:
    """Render the customer PDF from the same report model and HTML issue payload."""

    def render(
        self,
        report: ReportData,
        output_path: Path,
        *,
        report_context: dict[str, Any] | None = None,
    ) -> Path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if output_path.exists():
            raise FileExistsError(f"拒绝覆盖已有 PDF 报告：{output_path}")
        template = package_resource_path("reports", "templates", "inspection-report.typ")
        if not template.is_file():
            raise RuntimeError(f"PDF 模板不存在：{template}")
        typst = self._typst_binary()
        payload = self._build_payload(report, report_context or {})

        with tempfile.TemporaryDirectory(prefix=".vstacklens-pdf-", dir=output_path.parent) as temporary_dir:
            root = Path(temporary_dir)
            staged_template = root / "inspection-report.typ"
            staged_pdf = root / "inspection-report.pdf"
            shutil.copy2(template, staged_template)
            (root / "payload.json").write_text(
                json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
                encoding="utf-8",
            )
            command = [
                str(typst),
                "compile",
                "--root",
                str(root),
                str(staged_template),
                str(staged_pdf),
            ]
            font_dir = Path(os.environ.get("VSTACKLENS_PDF_FONT_DIR", r"C:\Windows\Fonts"))
            if font_dir.is_dir():
                command[2:2] = ["--font-path", str(font_dir)]
            result = subprocess.run(
                command,
                cwd=root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=180,
                check=False,
            )
            if result.returncode != 0 or not staged_pdf.is_file():
                diagnostic = (result.stderr or result.stdout or "Typst 未生成 PDF。").strip()
                raise RuntimeError(f"PDF 生成失败：{diagnostic[-3000:]}")
            if output_path.exists():
                raise FileExistsError(f"PDF 目标在生成期间已出现，未覆盖：{output_path}")
            staged_pdf.rename(output_path)
        return output_path

    def _typst_binary(self) -> Path:
        configured = os.environ.get("VSTACKLENS_TYPST_BIN", "").strip()
        candidates = [
            Path(configured) if configured else None,
            package_resource_path("tools", "typst.exe"),
            project_resource_path(".tools", "typst", "typst.exe"),
            Path(__file__).resolve().parents[3] / ".tools" / "typst" / "typst.exe",
        ]
        for candidate in candidates:
            if candidate is not None and candidate.is_file():
                return candidate
        on_path = shutil.which("typst") or shutil.which("typst.exe")
        if on_path:
            return Path(on_path)
        raise RuntimeError("未找到 Typst 编译器；源码运行请配置 VSTACKLENS_TYPST_BIN，安装包需内置 typst.exe。")

    def _build_payload(self, report: ReportData, report_context: dict[str, Any]) -> dict[str, Any]:
        inventory = report.asset_inventory or {}
        details = inventory.get("details") or {}
        vcenter_row = self._first_record(details, "vCenter")
        if self._properties(vcenter_row).get("connected") is False:
            raise RuntimeError("vCenter 连接未成功，不生成基于空数据的客户 PDF。")
        clusters_raw = self._records(details, "ClusterComputeResource")
        hosts_raw = self._records(details, "HostSystem")
        vms_raw = self._records(details, "VirtualMachine")
        hosts_by_name = {str(item.get("object_name") or ""): self._properties(item) for item in hosts_raw}
        vms_by_name = {str(item.get("object_name") or ""): self._properties(item) for item in vms_raw}
        vsan = report.vsan_summary or report_context.get("vsan_summary") or {}
        records, vcenter_record = self._report_asset_views(details)
        clusters = records.get("cluster", [])
        host_records = records.get("host", [])
        vm_records = records.get("vm", [])
        datastore_records = records.get("store", [])
        cluster_names = [str(item.get("name") or "") for item in clusters if item.get("name")]
        vsan_cluster_names = {str(name) for name in (vsan.get("clusters") or []) if name}

        cluster_props = {
            str(item.get("object_name") or ""): self._properties(item)
            for item in clusters_raw
        }
        cluster_vms: dict[str, list[dict[str, Any]]] = {name: [] for name in cluster_names}
        unknown_cluster_vms: list[dict[str, Any]] = []
        vm_state_counts = {"powered_on": 0, "powered_off": 0, "suspended": 0}
        snapshot_vm_count = 0
        vm_total = len(vm_records)
        top_cpu: list[dict[str, Any]] = []
        top_memory: list[dict[str, Any]] = []
        top_capacity: list[dict[str, Any]] = []
        top_vcpu: list[dict[str, Any]] = []
        host_usage_totals = {
            "cpu": {},
            "memory": {},
            "capacity": {},
            "vcpu": {},
        }

        def accumulate_host_usage(resource: str, host: str, value: float | None) -> None:
            bucket = host_usage_totals[resource].setdefault(
                host,
                {"expected": 0, "available": 0, "total": 0.0},
            )
            bucket["expected"] += 1
            if value is not None and value >= 0:
                bucket["available"] += 1
                bucket["total"] += value

        for vm in vm_records:
            name = str(vm.get("name") or "")
            props = vms_by_name.get(name, {})
            state = self._power_state(vm.get("powerState") or props.get("power_state"))
            if state == "powered_on":
                vm_state_counts["powered_on"] += 1
            elif state == "powered_off":
                vm_state_counts["powered_off"] += 1
            elif state == "suspended":
                vm_state_counts["suspended"] += 1
            if self._has_snapshot(props):
                snapshot_vm_count += 1
            cluster_name = str(vm.get("cluster") or "未归类")
            vm_entry = {
                "name": name,
                "host": str(vm.get("hostName") or "未记录"),
                "state": state,
                "has_snapshot": self._has_snapshot(props),
            }
            if cluster_name in cluster_vms:
                cluster_vms[cluster_name].append(vm_entry)
            else:
                unknown_cluster_vms.append(vm_entry)

            cpu = self._number(props.get("cpu_usage_mhz"))
            memory_mb = self._number(props.get("memory_usage_mb"))
            host_key = vm_entry["host"]
            has_host = bool(host_key and host_key != "未记录")
            if state == "powered_on" and has_host:
                accumulate_host_usage("cpu", host_key, cpu)
                accumulate_host_usage("memory", host_key, memory_mb)
            if state == "powered_on" and cpu is not None:
                top_cpu.append({"name": name, "host": vm_entry["host"], "value": round(cpu), "display": f"{cpu:,.0f} MHz"})
            if state == "powered_on" and memory_mb is not None:
                memory_gb = memory_mb / 1024
                top_memory.append({"name": name, "host": vm_entry["host"], "value": memory_mb, "display": f"{memory_gb:,.1f} GB"})
            disk_gb = self._number(vm.get("diskGb"))
            if has_host:
                accumulate_host_usage("capacity", host_key, disk_gb)
            if disk_gb is not None:
                top_capacity.append({"name": name, "host": vm_entry["host"], "value": disk_gb, "display": f"{disk_gb:,.1f} GB"})
            vcpu_count = self._number(props.get("vcpu_count"))
            if has_host:
                accumulate_host_usage("vcpu", host_key, vcpu_count)
            if vcpu_count is not None:
                top_vcpu.append({
                    "name": name,
                    "host": vm_entry["host"],
                    "value": int(vcpu_count),
                    "display": f"{int(vcpu_count)} vCPU",
                })

        for name, items in cluster_vms.items():
            items.sort(key=lambda item: item["name"].casefold())
        if unknown_cluster_vms:
            cluster_vms["未归类"] = sorted(unknown_cluster_vms, key=lambda item: item["name"].casefold())
        top_cpu.sort(key=lambda item: item["value"], reverse=True)
        top_memory.sort(key=lambda item: item["value"], reverse=True)
        top_capacity.sort(key=lambda item: item["value"], reverse=True)
        top_vcpu.sort(key=lambda item: (-item["value"], item["name"].casefold()))
        for rows, resource_key, share_scope in (
            (top_cpu, "cpu", "同主机 VM CPU 用量占比"),
            (top_memory, "memory", "同主机 VM 内存用量占比"),
            (top_capacity, "capacity", "同机已采集 VM 分配容量占比"),
            (top_vcpu, "vcpu", "占同主机 VM 配置 vCPU 总数"),
        ):
            for item in rows:
                host_usage = host_usage_totals[resource_key].get(item["host"], {})
                complete = (
                    host_usage.get("expected", 0) > 0
                    and host_usage.get("available", 0) == host_usage.get("expected", 0)
                )
                denominator = host_usage.get("total") if complete or resource_key == "capacity" else None
                item["host_share_scope"] = share_scope
                item["host_share_pct"] = (
                    round(item["value"] * 100 / denominator, 1)
                    if denominator is not None and denominator > 0
                    else None
                )
        for rows in (top_cpu, top_memory, top_capacity):
            maximum = max((item["value"] for item in rows), default=0)
            for item in rows:
                item["bar_pct"] = round(item["value"] * 100 / maximum, 1) if maximum > 0 else 0
        max_vcpu = max((item["value"] for item in top_vcpu), default=0)
        for item in top_vcpu:
            item["bar_pct"] = round(item["value"] * 100 / max_vcpu, 1) if max_vcpu else 0

        enabled_ha = [name for name in cluster_names if cluster_props.get(name, {}).get("ha_enabled") is True]
        enabled_drs = [name for name in cluster_names if cluster_props.get(name, {}).get("drs_enabled") is True]
        total_clusters = len(cluster_names)

        hosts: list[dict[str, Any]] = []
        host_cores = 0
        host_memory_total_mb = 0
        host_core_values = 0
        host_memory_values = 0
        maintenance_names = {
            str(name)
            for item in clusters_raw
            for name in (self._properties(item).get("maintenance_hosts") or [])
            if name
        }
        for host in host_records:
            name = str(host.get("name") or "")
            props = hosts_by_name.get(name, {})
            cluster_name = str(host.get("cluster") or "未归类")
            cpu_pct = self._number(host.get("cpuPct"))
            memory_pct = self._number(host.get("memoryPct"))
            if cpu_pct is not None and memory_pct is not None:
                health = "正常" if cpu_pct < 80 and memory_pct < 80 else "需关注"
            elif (cpu_pct is not None and cpu_pct >= 80) or (memory_pct is not None and memory_pct >= 80):
                health = "需关注"
            else:
                health = "数据未采集"
            connection = self._connection_state(host.get("connectionState"), host.get("maintenanceMode"), name in maintenance_names)
            hosts.append({
                "cluster": cluster_name,
                "name": name,
                "health": health,
                "connection": connection,
                "cpu_pct": cpu_pct,
                "memory_pct": memory_pct,
                "cpu": self._percent_text(cpu_pct),
                "memory": self._percent_text(memory_pct),
            })
            cores = self._number(props.get("host_pcpu_count"))
            memory_mb = self._number(props.get("host_memory_capacity_mb"))
            if cores is not None:
                host_cores += int(cores)
                host_core_values += 1
            if memory_mb is not None:
                host_memory_total_mb += memory_mb
                host_memory_values += 1
        hosts.sort(key=lambda item: (item["cluster"].casefold(), item["name"].casefold()))

        cluster_vm_summary = []
        for cluster_name, items in cluster_vms.items():
            cluster_vm_summary.append({
                "cluster": cluster_name,
                "total": len(items),
                "powered_on": sum(item["state"] == "powered_on" for item in items),
                "powered_off": sum(item["state"] == "powered_off" for item in items),
                "suspended": sum(item["state"] == "suspended" for item in items),
                "snapshots": sum(bool(item["has_snapshot"]) for item in items),
            })

        datastores = []
        for item in datastore_records:
            usage = self._number(item.get("usagePct"))
            datastores.append({
                "name": str(item.get("name") or "未命名数据存储"),
                "type": "vSAN" if str(item.get("type") or "").casefold() == "vsan" else str(item.get("type") or "未采集"),
                "clusters": list(item.get("clusters") or []),
                "usage": usage,
                "usage_text": self._percent_text(usage),
                "used_text": self._capacity_text(item.get("usedGb")),
                "free_text": self._capacity_text(item.get("freeGb")),
                "total_text": self._capacity_text(item.get("totalGb")),
            })
        datastores.sort(key=lambda item: (item["usage"] is None, -(item["usage"] or 0), item["name"].casefold()))
        datastore_type_counts: dict[str, int] = {}
        for store in datastores:
            datastore_type_counts[store["type"]] = datastore_type_counts.get(store["type"], 0) + 1
        datastore_type_rows = [
            {"type": key, "count": count}
            for key, count in sorted(datastore_type_counts.items(), key=lambda pair: (-pair[1], pair[0].casefold()))
        ]

        capacity = vsan.get("capacity") or {}
        vdisk_details = [item for item in (vsan.get("disk_details") or []) if isinstance(item, dict)]
        physical_disks = vsan.get("physical_disks")
        disk_count = len(vdisk_details) if vdisk_details else (len(physical_disks) if isinstance(physical_disks, list) else None)
        disk_healthy = sum(str(item.get("health") or "") == "正常" for item in vdisk_details) if vdisk_details else None
        resync_objects = self._number(vsan.get("resync_object_count"))
        resync_bytes = self._number(vsan.get("resync_bytes"))
        no_resync = resync_objects == 0 and resync_bytes == 0
        has_vsan = str(vsan.get("status") or "") != "not_applicable" and bool(vsan.get("clusters") or vsan.get("disk_details") or vsan.get("capacity", {}).get("total_gb"))
        disk_rows = [
            {
                "host": str(item.get("host") or "未记录"),
                "group": str(item.get("disk_group") or "未记录"),
                "role": str(item.get("role") or "未记录"),
                "device": str(item.get("device") or "未记录"),
                "health": str(item.get("health") or "未确认"),
            }
            for item in vdisk_details
        ]
        disk_rows.sort(key=lambda item: (item["host"].casefold(), item["group"].casefold(), item["role"].casefold(), item["device"].casefold()))
        cluster_views = []
        cluster_details = []
        vm_summary_by_cluster = {str(item.get("cluster") or ""): item for item in cluster_vm_summary}
        hosts_by_cluster: dict[str, list[dict[str, Any]]] = {}
        for host in hosts:
            hosts_by_cluster.setdefault(host["cluster"], []).append(host)
        for cluster in clusters:
            name = str(cluster.get("name") or "未命名集群")
            props = cluster_props.get(name, {})
            vm_summary = vm_summary_by_cluster.get(name, {})
            cluster_views.append({
                "name": name,
                "kind": "vSAN 集群" if name in vsan_cluster_names else "普通集群",
                "host_count": len(hosts_by_cluster.get(name, [])),
                "vm_count": int(vm_summary.get("total", 0)),
                "host_names": "、".join(item["name"] for item in hosts_by_cluster.get(name, [])),
                "powered_on": int(vm_summary.get("powered_on", 0)),
                "powered_off": int(vm_summary.get("powered_off", 0)),
                "suspended": int(vm_summary.get("suspended", 0)),
                "ha": "已启用" if props.get("ha_enabled") is True else "未启用" if props.get("ha_enabled") is False else "未采集",
                "drs": "已启用" if props.get("drs_enabled") is True else "未启用" if props.get("drs_enabled") is False else "未采集",
            })
            heartbeat_count = self._number(props.get("ha_heartbeat_datastore_count"))
            heartbeat_names = self._safe_list_text(props.get("heartbeat_datastore_names"))
            heartbeat_summary = (
                "未采集" if heartbeat_count is None
                else f"{int(heartbeat_count)} 个（未配置）" if heartbeat_count == 0
                else f"{int(heartbeat_count)} 个" + (f"：{heartbeat_names}" if heartbeat_names else "")
            )
            cluster_details.append({
                "name": name,
                "kind": "vSAN" if name in vsan_cluster_names else "普通",
                "host_count": len(hosts_by_cluster.get(name, [])),
                "host_names": "、".join(item["name"] for item in hosts_by_cluster.get(name, [])),
                "vm_count": int(vm_summary.get("total", 0)),
                "powered_on": int(vm_summary.get("powered_on", 0)),
                "powered_off": int(vm_summary.get("powered_off", 0)),
                "suspended": int(vm_summary.get("suspended", 0)),
                "ha_enabled": props.get("ha_enabled"),
                "admission_control": self._bool_label(props.get("admission_control_enabled")),
                "heartbeat_count": heartbeat_count,
                "heartbeat_names": heartbeat_names,
                "heartbeat_summary": heartbeat_summary,
                "isolation_response": self._safe_customer_text(props.get("ha_isolation_response")) or "未采集",
                "drs_enabled": props.get("drs_enabled"),
                "drs_behavior": self._safe_customer_text(props.get("drs_behavior")) or "未采集",
                "drs_disabled_rule_count": self._number(props.get("drs_disabled_rule_count")),
                "drs_disabled_rules": self._safe_list_text(props.get("drs_disabled_rules")),
                "evc_enabled": self._bool_label(props.get("evc_enabled")),
                "evc_mode": self._safe_customer_text(props.get("evc_mode")) or "未采集",
                "vmotion_enabled_hosts": self._number(props.get("vmotion_enabled_host_count")),
                "vmotion_missing_hosts": self._safe_list_text(props.get("missing_vmotion_hosts")),
                "cpu_usage_pct": self._number(props.get("cluster_cpu_usage_avg")),
                "cpu_model_count": self._number(props.get("host_cpu_model_distinct_count")),
                "cpu_models": self._safe_list_text(props.get("host_cpu_models")),
                "memory_skew_pct": self._number(props.get("host_memory_capacity_skew_ratio")),
                "maintenance_hosts": self._safe_list_text(props.get("maintenance_hosts")),
            })

        run_timing = report_context.get("run_timing") or {}
        run_metadata = report_context.get("run") or {}
        capture_date = self._date_text(
            run_timing.get("started_at")
            or run_metadata.get("started_at")
            or run_metadata.get("created_at")
            or report.report_info.generated_at
        )
        as_of = date.fromisoformat(capture_date)
        certificate_evidence = report_context.get("certificate_license_evidence") or (
            report.appendix.get("certificate_license_evidence") if isinstance(report.appendix, dict) else []
        ) or []
        certificate_evidence = [item for item in certificate_evidence if isinstance(item, dict)]
        vcenter_props = self._properties(vcenter_row)
        vcenter_cert_evidence = next(
            (item for item in certificate_evidence if item.get("rule_id") == "VSL-VC-005"),
            {},
        )
        vcenter_days = self._number(vcenter_props.get("certificate_days_remaining"))
        if vcenter_days is None:
            vcenter_days = self._number(vcenter_record.get("certificateDays"))
        if vcenter_days is None:
            vcenter_days = self._evidence_number(vcenter_cert_evidence)
        vcenter_direct_expiry = str(
            vcenter_props.get("certificate_not_after")
            or vcenter_props.get("certificate_expiration_date")
            or vcenter_record.get("certificateDate")
            or ""
        ).strip()[:10]
        vcenter_expiry = vcenter_direct_expiry
        if not vcenter_expiry and vcenter_days is not None:
            vcenter_expiry = (as_of + timedelta(days=int(vcenter_days))).isoformat()
        vcenter_expiry_display = (
            f"{vcenter_expiry}（剩余 {int(vcenter_days)} 天）"
            if vcenter_expiry and vcenter_days is not None
            else vcenter_expiry or "未采集"
        )
        certificate_hosts = []
        known_host_certs: list[dict[str, Any]] = []
        for host in hosts:
            host_props = hosts_by_name.get(host["name"], {})
            direct_expiry = str(host_props.get("host_certificate_not_after") or "").strip()[:10]
            days = self._number(host_props.get("host_certificate_days_remaining"))
            expiry_date = direct_expiry
            if not expiry_date and days is not None:
                expiry_date = (as_of + timedelta(days=int(days))).isoformat()
            expiry = f"{expiry_date}（剩余 {int(days)} 天）" if expiry_date and days is not None else (expiry_date or "未采集")
            status = self._certificate_status(days)
            entry = {
                "cluster": host["cluster"],
                "host": host["name"],
                "expiry": expiry,
                "status": status,
                "remaining_days": days,
                "attention": days is not None and 0 < days <= 90,
                "expired": days is not None and days <= 0,
                "expiry_known": bool(expiry_date),
            }
            certificate_hosts.append(entry)
            if days is not None or direct_expiry:
                known_host_certs.append(entry)
        certificate_hosts.sort(key=lambda item: (item["cluster"].casefold(), item["host"].casefold()))
        vcenter_count = int(bool(vcenter_days is not None or vcenter_direct_expiry or vcenter_cert_evidence))
        licenses = sorted({
            f"{self._text(self._properties(item).get('host_license_name'))} / {self._text(self._properties(item).get('host_license_expiration_date'))}"
            for item in hosts_raw
            if self._properties(item).get("host_license_name")
        })
        vcenter_license_evidence = next(
            (item for item in certificate_evidence if item.get("rule_id") == "VSL-VC-006"),
            {},
        )
        vcenter_license_text = str(vcenter_license_evidence.get("current_value_zh") or "").strip()
        if vcenter_license_text:
            licenses = sorted(set(licenses) | {f"vCenter：{vcenter_license_text}"})

        host_details = []
        for host in hosts:
            props = hosts_by_name.get(host["name"], {})
            pnic_rows = [item for item in (props.get("physical_nic_details") or []) if isinstance(item, dict)]
            vmk_rows = [item for item in (props.get("vmkernel_adapters") or []) if isinstance(item, dict)]
            security_rows = [item for item in (props.get("portgroup_security_issues") or []) if isinstance(item, dict)]
            hardware_rows = [item for item in (props.get("host_hardware_health_issues") or []) if isinstance(item, dict)]
            hardware_issue_labels = [
                self._safe_customer_text(item.get("name") or item.get("description") or item.get("status") or "硬件状态异常")
                for item in hardware_rows
            ]
            portgroup_issue_labels = [
                self._safe_customer_text(
                    f"{item.get('portgroup') or item.get('switch') or '端口组未记录'}："
                    f"{item.get('policy') or '策略项未记录'}（{item.get('current_value') or '未记录'} → "
                    f"{item.get('recommended_value') or '未记录'}）"
                )
                for item in security_rows
            ]
            memory_capacity = self._number(props.get("host_memory_capacity_mb"))
            memory_allocated = self._number(props.get("host_memory_allocated_mb"))
            host_details.append({
                "name": host["name"],
                "cluster": host["cluster"],
                "connection": host["connection"],
                "cpu_pct": host["cpu_pct"],
                "memory_pct": host["memory_pct"],
                "cpu_cores": self._number(props.get("host_pcpu_count")),
                "allocated_vcpu": self._number(props.get("host_vcpu_allocated")),
                "vcpu_pcpu_ratio": self._number(props.get("host_vcpu_to_pcpu_ratio")),
                "memory_capacity_gb": round(memory_capacity / 1024, 1) if memory_capacity is not None else None,
                "memory_allocated_gb": round(memory_allocated / 1024, 1) if memory_allocated is not None else None,
                "memory_allocation_pct": (
                    round(self._number(props.get("host_memory_allocation_ratio")) * 100, 1)
                    if self._number(props.get("host_memory_allocation_ratio")) is not None else None
                ),
                "overcommit": props.get("host_resource_overcommit") if isinstance(props.get("host_resource_overcommit"), bool) else None,
                "hardware_issue_count": self._number(props.get("host_hardware_health_issue_count")),
                "hardware_red_count": self._number(props.get("host_hardware_health_red_count")),
                "hardware_issues": hardware_rows,
                "hardware_issue_labels": [item for item in hardware_issue_labels if item],
                "hardware_issue_summary": "、".join(item for item in hardware_issue_labels if item),
                "power_policy": self._safe_customer_text(props.get("host_power_policy")) or "未采集",
                "power_policy_high_performance": props.get("host_power_policy_high_performance"),
                "pnic_down_count": self._number(props.get("pnic_down_count")),
                "pnic_degraded_count": self._number(props.get("pnic_degraded_count")),
                "pnic_error_count": self._number(props.get("pnic_error_count")),
                "pnic_rows": pnic_rows,
                "vmkernel_adapters": vmk_rows,
                "ssh": self._bool_label(props.get("ssh_running")),
                "esxi_shell": self._bool_label(props.get("esxi_shell_running")),
                "lockdown": self._safe_customer_text(props.get("lockdown_mode")) or "未采集",
                "ntp_server_count": self._number(props.get("ntp_server_count")),
                "firewall_default_blocked": self._bool_label(props.get("firewall_default_incoming_blocked")),
                "portgroup_security_count": self._number(props.get("portgroup_security_issue_count")),
                "portgroup_security_high_count": self._number(props.get("portgroup_security_high_risk_count")),
                "portgroup_security_issues": security_rows,
                "portgroup_security_labels": [item for item in portgroup_issue_labels if item],
                "portgroup_security_summary": "；".join(item for item in portgroup_issue_labels if item),
                "vmotion_vmk_count": self._number(props.get("vmotion_vmk_count")),
                "vsan_vmk_adapters": [item for item in (props.get("vsan_vmk_adapters") or []) if isinstance(item, dict)],
            })

        excluded_rule_ids = {"VSL-VM-002", "VSL-VM-014", "VSL-VM-003", "VSL-HOST-014"}
        filtered_findings = []
        for finding in report.findings:
            item = self._as_dict(finding)
            if self._excluded_report_item(item, excluded_rule_ids):
                continue
            filtered_findings.append(item)
        findings_by_rule: dict[str, list[dict[str, Any]]] = {}
        for item in filtered_findings:
            findings_by_rule.setdefault(str(item.get("rule_id") or ""), []).append(item)

        problems: list[dict[str, Any]] = []
        optimizations: list[dict[str, Any]] = []
        for remediation in report.remediation_plan:
            item = self._as_dict(remediation)
            if self._excluded_report_item(item, excluded_rule_ids) and str(item.get("rule_id") or "") != "VSL-VM-015":
                continue
            rule_id = str(item.get("rule_id") or "")
            level = str(item.get("risk_level") or "")
            if level not in {"P1", "P2", "P3", "P4"}:
                continue
            linked_findings = findings_by_rule.get(rule_id, [])
            object_types = {str(finding.get("object_type") or "") for finding in linked_findings}
            unit = self._finding_count_unit(rule_id, object_types)
            cluster_names_for_item = set()
            for finding in linked_findings:
                object_path = str(finding.get("object_path") or "")
                for cluster_name in cluster_names:
                    if cluster_name and cluster_name in object_path:
                        cluster_names_for_item.add(cluster_name)
            if not cluster_names_for_item and rule_id.startswith("VSL-VC-"):
                cluster_names_for_item.add("vCenter 管理平台")
            steps = self._customer_steps(item.get("steps") or [], rule_id)
            impact = next((
                self._safe_customer_text(
                    finding.get("business_impact")
                    or finding.get("consequence")
                    or finding.get("technical_impact")
                )
                for finding in linked_findings
                if finding.get("business_impact") or finding.get("consequence") or finding.get("technical_impact")
            ), "")
            plan_item = {
                "level": level,
                "title": self._safe_customer_text(item.get("title")) or "环境核查建议",
                "count": int(item.get("object_count") or 0),
                "count_label": f"{int(item.get('object_count') or 0)} {unit}",
                "clusters": "、".join(sorted(cluster_names_for_item, key=str.casefold)) or "未记录",
                "impact": impact or "本项由现有巡检规则列出，建议结合业务情况复核。",
                "remediation": "；".join(steps) or "按变更流程核实并复查。",
                "steps": steps,
                "owner": self._role_label(item.get("owner_role")),
                "effort": self._effort_label(item.get("effort")),
                "maintenance_window_required": bool(item.get("maintenance_window_required")),
                "verification": self._verification_label(item.get("verification_method")),
                "rule_id": rule_id,
            }
            (optimizations if level == "P4" else problems).append(plan_item)

        risk_counts = {level: sum(item["level"] == level for item in problems) for level in ("P1", "P2", "P3")}
        all_plan_counts = {level: sum(item["level"] == level for item in [*problems, *optimizations]) for level in ("P1", "P2", "P3", "P4")}
        affected_counts = {
            level: sum(item["count"] for item in [*problems, *optimizations] if item["level"] == level)
            for level in ("P1", "P2", "P3", "P4")
        }
        issue_count = len(problems)
        optimization_count = len(optimizations)
        issue_object_count = sum(affected_counts[level] for level in ("P1", "P2", "P3"))
        problems.sort(key=lambda item: ({"P1": 0, "P2": 1, "P3": 2}.get(item["level"], 9), item["title"].casefold()))
        optimizations.sort(key=lambda item: item["title"].casefold())
        object_type_counts: dict[str, int] = {}
        for finding in filtered_findings:
            object_type = str(finding.get("object_type") or "其他")
            object_type_counts[object_type] = object_type_counts.get(object_type, 0) + 1
        object_type_rows = [
            {"name": key, "count": value}
            for key, value in sorted(object_type_counts.items(), key=lambda pair: (-pair[1], pair[0].casefold()))
        ]
        category_counts: dict[str, int] = {}
        for item in [*problems, *optimizations]:
            category_counts[item["title"]] = category_counts.get(item["title"], 0) + 1
        highest_category = max(category_counts, key=category_counts.get) if category_counts else None
        category_rows = [
            {"title": item["title"], "level": item["level"], "objects": item["count"]}
            for item in problems
        ]
        category_rows.sort(key=lambda item: (-item["objects"], {"P1": 0, "P2": 1, "P3": 2, "P4": 3}.get(item["level"], 9), item["title"].casefold()))
        max_issue_category_objects = max((item["objects"] for item in category_rows), default=1)

        rule_source = report_context.get("rule_checklist") or (
            report.appendix.get("rule_checklist", []) if isinstance(report.appendix, dict) else []
        ) or []
        rule_checklist = [
            self._as_dict(item) for item in rule_source
            if isinstance(item, dict) and not self._excluded_report_item(self._as_dict(item), excluded_rule_ids)
        ]
        rule_checklist = [
            {**item,
             "rule_id": str(item.get("rule_id") or ""),
             "rule_name": self._safe_customer_text(item.get("rule_name") or item.get("title")) or "未命名规则"}
            for item in rule_checklist
        ]
        visible_result_counts = {
            key: sum(int(item.get(key) or 0) for item in rule_checklist)
            for key in ("passed", "failed", "unavailable", "not_applicable", "error")
        }
        unavailable_source = report_context.get("unavailable_results") or (
            report.appendix.get("unavailable_rules", []) if isinstance(report.appendix, dict) else []
        ) or []
        unavailable_groups: dict[tuple[str, str, str], int] = {}
        for raw in unavailable_source:
            item = self._as_dict(raw)
            if self._excluded_report_item(item, excluded_rule_ids):
                continue
            rid = str(item.get("rule_id") or "未记录")
            name = self._safe_customer_text(item.get("rule_name") or item.get("title")) or rid
            evidence = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
            api_path = self._safe_customer_text(item.get("api_path") or evidence.get("api_path"))
            data_quality = self._safe_customer_text(item.get("data_quality") or evidence.get("data_quality"))
            reason = self._safe_customer_text(item.get("reason") or item.get("unavailable_reason") or item.get("message"))
            if api_path and data_quality:
                reason = f"未返回字段 {api_path}（{data_quality}）"
            elif api_path and not reason:
                reason = f"未返回字段 {api_path}"
            reason = reason or "缺少必要证据"
            key = (rid, name, reason)
            unavailable_groups[key] = unavailable_groups.get(key, 0) + 1
        unavailable_rows = [
            {"rule_id": key[0], "name": key[1], "reason": key[2], "count": count}
            for key, count in sorted(unavailable_groups.items(), key=lambda pair: (-pair[1], pair[0][0]))
        ]
        not_applicable_source = report_context.get("not_applicable_summary") or (
            report.appendix.get("not_applicable_rules", []) if isinstance(report.appendix, dict) else []
        ) or []
        not_applicable_rows = []
        for item in not_applicable_source:
            row = self._as_dict(item)
            if self._excluded_report_item(row, excluded_rule_ids):
                continue
            applicability_reasons = {
                "VSL-DS-007": "当前数据存储不满足多路径检查条件（如非共享 VMFS）",
                "VSL-DS-008": "当前数据存储不满足活动路径计数检查条件",
                "VSL-DS-020": "对象不是 vSAN 数据存储，不适用 vSAN 健康检查",
                "VSL-VM-004": "虚拟机未运行，无法采集 CPU Ready 运行时指标",
                "VSL-VM-005": "虚拟机未运行，无法采集内存压力运行时指标",
                "VSL-VM-023": "vCLS 或系统虚拟机按规则不纳入此项检查",
            }
            not_applicable_rows.append({
                "rule_id": str(row.get("rule_id") or "未记录"),
                "name": self._safe_customer_text(row.get("rule_name") or row.get("title")) or "未命名规则",
                "object_type": self._safe_customer_text(row.get("object_type")) or "对象",
                "count": int(row.get("count", row.get("c", 0)) or 0),
                "reason": self._safe_customer_text(row.get("reason") or row.get("reason_zh")) or applicability_reasons.get(str(row.get("rule_id") or ""), "不满足该项适用条件"),
            })
        unavailable_total = sum(item["count"] for item in unavailable_rows)
        not_applicable_total = sum(item["count"] for item in not_applicable_rows)

        all_pnics = []
        all_vmkernels = []
        for host in host_details:
            nic_rows = host["pnic_rows"]
            if not nic_rows:
                host_props = hosts_by_name.get(host["name"], {})
                nic_rows = [item for item in (host_props.get("link_speed_detail") or []) if isinstance(item, dict)]
            affected_nics = set(hosts_by_name.get(host["name"], {}).get("affected_nics") or [])
            for nic in nic_rows:
                uplink = nic.get("is_uplink") is True or str(nic.get("device") or "") in affected_nics
                assessment = str(nic.get("assessment") or "")
                link_state = str(nic.get("link_state") or ("down" if nic.get("status") == "down" else "unknown"))
                if not uplink:
                    status = "未承担上行" if link_state != "down" else "未连接（未承担上行）"
                elif link_state == "down" or assessment == "down":
                    status = "链路中断"
                elif assessment in {"degraded", "speed_mismatch", "speed_zero", "speed_below_1gbps"}:
                    status = "速率异常"
                elif assessment == "speed_unknown":
                    status = "速率未采集"
                else:
                    status = "正常"
                all_pnics.append({
                    "host": host["name"], "device": str(nic.get("device") or "未记录"),
                    "switch": self._safe_list_text(nic.get("assigned_switches") or nic.get("switch_bindings")) or "未绑定",
                    "uplink": uplink, "link_state": link_state,
                    "actual_speed": self._speed_text(nic.get("actual_speed_mb")),
                    "configured_speed": self._speed_text(nic.get("configured_speed_mb")),
                    "assessment": status,
                    "assessment_basis": "主机级 pnic_down_count" if status == "链路中断" and link_state == "down" else "链路状态/速率明细",
                })
            for vmk in host["vmkernel_adapters"]:
                all_vmkernels.append(self._vmkernel_row(host["name"], vmk))
        if not all_vmkernels:
            for vmk in (vsan.get("network") or {}).get("vmkernels") or []:
                if isinstance(vmk, dict):
                    all_vmkernels.append(self._vmkernel_row(str(vmk.get("host_name") or "未记录"), vmk))
        seen_vmk = set()
        vmkernel_rows = []
        for item in all_vmkernels:
            key = (item["host"], item["device"], item["ip"])
            if key not in seen_vmk:
                seen_vmk.add(key)
                vmkernel_rows.append(item)
        vmkernel_rows.sort(key=lambda item: (item["host"].casefold(), item["device"].casefold()))
        all_pnics.sort(key=lambda item: (item["host"].casefold(), item["device"].casefold()))
        network = {
            "vmkernel_count": len(vm_kernel_rows := vmkernel_rows),
            "vmkernels": vm_kernel_rows,
            "pnic_count": len(all_pnics),
            "pnics": all_pnics,
            "pnic_down_count": sum(int(host.get("pnic_down_count") or 0) for host in host_details),
            "pnic_degraded_count": sum(int(host.get("pnic_degraded_count") or 0) for host in host_details),
            "pnic_down_host_count": sum((host.get("pnic_down_count") or 0) > 0 for host in host_details),
            "pnic_detail_count": len(all_pnics),
            "pnic_details_are_partial": any(not host["pnic_rows"] and hosts_by_name.get(host["name"], {}).get("link_speed_detail") for host in host_details),
            "host_uplink_summary": [
                {"host": host["name"], "down": int(host.get("pnic_down_count") or 0), "degraded": int(host.get("pnic_degraded_count") or 0)}
                for host in host_details
            ],
        }

        disk_group_map: dict[tuple[str, str], dict[str, Any]] = {}
        for disk in disk_rows:
            key = (disk["host"], disk["group"])
            group = disk_group_map.setdefault(key, {"host": key[0], "name": key[1], "cache": 0, "capacity": 0, "healthy": 0, "disks": []})
            role = disk["role"].casefold()
            group["cache"] += int("cache" in role or "缓存" in role)
            group["capacity"] += int("capacity" in role or "容量" in role)
            group["healthy"] += int(disk["health"] == "正常")
            group["disks"].append(disk)
        disk_groups = sorted(disk_group_map.values(), key=lambda item: (item["host"].casefold(), item["name"].casefold()))
        policy_summary = vsan.get("storage_policy_summary") or {}
        policy_status = str(policy_summary.get("status") or policy_summary.get("api_status") or "unknown") if isinstance(policy_summary, dict) else "unknown"
        policy_vm_counts = {"collected": 0, "api_error": 0, "other": 0}
        for vm_row in vms_raw:
            vm_props = self._properties(vm_row)
            collection_status = str(vm_props.get("storage_policy_collection_status") or "other")
            if collection_status not in policy_vm_counts:
                collection_status = "other"
            policy_vm_counts[collection_status] += 1
        if policy_status == "unknown" and policy_vm_counts["api_error"]:
            policy_status = "api_error"
        datastore_usage_rows = [item for item in datastores if item.get("usage") is not None]
        highest_datastore = max(datastore_usage_rows, key=lambda item: item["usage"], default=None)
        host_property_rows = [hosts_by_name.get(item["name"], {}) for item in host_details]
        connected_host_count = sum(item.get("connection") == "已连接" for item in host_details)
        hardware_issue_total = sum(
            int(item["hardware_issue_count"] or 0)
            for item in host_details
            if item.get("hardware_issue_count") is not None
        )
        overcommit_host_count = sum(item.get("overcommit") is True for item in host_details)
        vmotion_host_total = sum((item.get("vmotion_vmk_count") or 0) > 0 for item in host_details if item.get("vmotion_vmk_count") is not None)
        security = {
            "ssh_running": sum(item.get("ssh_running") is True for item in host_property_rows),
            "shell_running": sum(item.get("esxi_shell_running") is True for item in host_property_rows),
            "ntp_configured": sum((self._number(item.get("ntp_server_count")) or 0) > 0 for item in host_property_rows),
            "firewall_blocked": sum(item.get("firewall_default_incoming_blocked") is True for item in host_property_rows),
            "lockdown_enabled": sum(
                str(item.get("lockdown_mode") or "").casefold() not in {"", "disabled", "lockdowndisabled", "未启用"}
                for item in host_property_rows
            ),
            "portgroup_issues": sum(int(item.get("portgroup_security_issue_count") or 0) for item in host_property_rows if item.get("portgroup_security_issue_count") is not None),
            "portgroup_details": [
                {
                    "host": host["name"],
                    "switch": self._safe_customer_text(issue.get("switch")) or "未记录",
                    "portgroup": self._safe_customer_text(issue.get("portgroup")) or "未记录",
                    "setting": self._safe_customer_text(issue.get("policy")) or "未记录",
                    "current": self._safe_customer_text(issue.get("current_value")) or "未记录",
                    "recommended": self._safe_customer_text(issue.get("recommended_value")) or "未记录",
                }
                for host in host_details
                for issue in host["portgroup_security_issues"]
            ],
        }
        optimization_object_count = sum(int(item.get("count") or 0) for item in optimizations)

        context_statuses = report.environment_summary.result_status_summary or {}
        scope_payload = {
            "visible_rule_count": len(rule_checklist),
            "visible_result_counts": visible_result_counts,
            "visible_result_total": sum(visible_result_counts.values()),
            "unavailable_total": unavailable_total,
            "unavailable_rows": unavailable_rows,
            "not_applicable_total": not_applicable_total,
            "not_applicable_rows": not_applicable_rows,
            "raw_result_statuses": {str(key): int(value or 0) for key, value in context_statuses.items()},
            "checked_object_total": report.environment_summary.checked_object_total,
            "rule_checklist": rule_checklist,
        }
        payload = {
            "customer_name": report.customer_info.customer_name or "未指定客户",
            "run_id": report.report_info.run_id,
            "report_date": capture_date,
            "capture_date": capture_date,
            "conclusion": f"需关注，本次发现 {issue_count} 项需要处理" if issue_count else "运行正常",
            "reporter": "VStackLens",
            "problem_count": issue_count,
            "optimization_count": optimization_count,
            "risk_counts": risk_counts,
            "affected_counts": affected_counts,
            "issue_object_count": issue_object_count,
            "optimization_object_count": optimization_object_count,
            "connected_host_count": connected_host_count,
            "hardware_issue_total": hardware_issue_total,
            "overcommit_host_count": overcommit_host_count,
            "vmotion_host_total": vmotion_host_total,
            "security": security,
            "datastore_usage_known": len(datastore_usage_rows),
            "highest_datastore_usage": self._percent_text(highest_datastore.get("usage") if highest_datastore else None),
            "highest_datastore_pct": self._number(highest_datastore.get("usage")) if highest_datastore else 0,
            "filtered_finding_count": len(filtered_findings),
            "findings_by_object_type": object_type_rows,
            "category_rows": category_rows,
            "max_issue_category_objects": max_issue_category_objects,
            "scope": scope_payload,
            "overview": {"highest_category": highest_category, "vm_state_counts": vm_state_counts},
            "counts": {
                "clusters": len(clusters),
                "hosts": len(host_records),
                "vms": vm_total,
                "datastores": len(datastore_records),
                "vcenter": 1 if vcenter_row else 0,
                "cpu_cores": host_cores if host_core_values else None,
                "memory_total_gb": round(host_memory_total_mb / 1024, 1) if host_memory_values else None,
                "powered_on": vm_state_counts["powered_on"],
                "powered_off": vm_state_counts["powered_off"],
                "suspended": vm_state_counts["suspended"],
                "snapshot_vms": snapshot_vm_count,
            },
            "ha_chart": {
                "value": len(enabled_ha),
                "total": total_clusters,
                "note": self._cluster_feature_note(cluster_names, enabled_ha, "HA"),
            },
            "drs_chart": {
                "value": len(enabled_drs),
                "total": total_clusters,
                "note": self._cluster_feature_note(cluster_names, enabled_drs, "DRS"),
            },
            "hosts": hosts,
            "host_details": host_details,
            "cluster_cards": cluster_views,
            "cluster_details": cluster_details,
            "cluster_vms": cluster_vm_summary,
            "datastores": datastores,
            "datastore_type_rows": datastore_type_rows,
            "network": network,
            "disk_groups": disk_groups,
            "certificates": {
                "vcenter": {
                    "name": str(vcenter_record.get("name") or "vCenter"),
                    "expiry": vcenter_expiry,
                    "expiry_display": vcenter_expiry_display,
                    "remaining_days": vcenter_days,
                    "status": self._certificate_status(vcenter_days),
                    "expiry_known": bool(vcenter_direct_expiry),
                },
                "vcenter_count": vcenter_count,
                "hosts": certificate_hosts,
                "known_host_count": len(known_host_certs),
                "licenses": licenses,
                "summary": self._certificate_summary(vcenter_count, vcenter_days, known_host_certs, len(hosts)),
            },
            "vsan": {
                "enabled": has_vsan,
                "clusters": list(vsan.get("clusters") or []),
                "total_gb": self._number(capacity.get("total_gb")),
                "total_display": self._gb_number_text(capacity.get("total_gb")),
                "used_gb": self._number(capacity.get("used_gb")),
                "used_display": self._gb_number_text(capacity.get("used_gb")),
                "free_gb": self._number(capacity.get("free_gb")),
                "free_display": self._gb_number_text(capacity.get("free_gb")),
                "used_percent": self._number(capacity.get("used_percent")),
                "disk_count": disk_count,
                "healthy_disks": disk_healthy,
                "disk_details": disk_rows,
                "disk_group_count": self._number(vsan.get("disk_group_count")),
                "cache_disk_count": self._number(vsan.get("cache_disk_count")),
                "capacity_disk_count": self._number(vsan.get("capacity_disk_count")),
                "object_count": self._number(vsan.get("object_count")),
                "vmdk_count": self._number(vsan.get("vmdk_count")),
                "resync_objects": resync_objects,
                "resync_bytes": resync_bytes,
                "no_resync": no_resync,
                "resync_eta_seconds": 0 if no_resync else None,
                "planned_resync_count": 0 if no_resync else None,
                "storage_policy_summary": policy_summary,
                "storage_policy_status": policy_status,
                "storage_policy_failure": policy_status in {"api_error", "unavailable", "permission_denied", "unsupported"},
                "storage_policy_vm_counts": policy_vm_counts,
                "health_issue_count": self._number(vsan.get("health_issue_count")),
                "disk_issue_count": self._number(vsan.get("disk_issue_count")),
                "object_issue_count": self._number(vsan.get("object_issue_count")),
                "used_percent_text": self._percent_text(capacity.get("used_percent")),
                "resync_objects_text": "0" if no_resync else self._number_text(resync_objects),
                "resync_bytes_text": "0 B" if no_resync else self._bytes_text(resync_bytes),
                "resync_eta_text": "0 秒" if no_resync else "未采集",
                "planned_resync_text": "0" if no_resync else "未采集",
                "resync_summary_text": (
                    f"正在重同步对象 {('0' if no_resync else self._number_text(resync_objects))} · "
                    f"待重同步数据 {('0 B' if no_resync else self._bytes_text(resync_bytes))} · "
                    f"预计完成 {('0 秒' if no_resync else '未采集')} · "
                    f"计划重同步 {('0' if no_resync else '未采集')}"
                ),
                "disk_group_count_text": self._number_text(vsan.get("disk_group_count")),
                "disk_count_text": self._number_text(disk_count),
                "healthy_disks_text": self._number_text(disk_healthy),
                "object_count_text": self._number_text(vsan.get("object_count")),
                "vmdk_count_text": self._number_text(vsan.get("vmdk_count")),
            },
            "vm_donut": {
                "powered_on": vm_state_counts["powered_on"],
                "not_running": vm_total - vm_state_counts["powered_on"],
                "powered_off": vm_state_counts["powered_off"],
                "suspended": vm_state_counts["suspended"],
                "non_running_label": "关机" if vm_state_counts["suspended"] == 0 else "非开机",
            },
            "top_cpu": top_cpu[:5],
            "top_memory": top_memory[:5],
            "top_capacity": top_capacity[:5],
            "top_vcpu": top_vcpu[:5],
            "problems": problems,
            "optimizations": optimizations,
            "environment": {
                "vcenter_version": report.environment_summary.vcenter_version or "未采集",
                "vcenter_build": report.environment_summary.vcenter_build or "未采集",
                "checked_object_total": report.environment_summary.checked_object_total,
            },
        }
        payload["narratives"] = build_pdf_narratives(payload)
        return payload

    def _report_asset_views(
        self,
        details: dict[str, Any],
    ) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
        """Normalize ReportData.asset_inventory for this PDF without consulting HTML internals."""
        cluster_rows = self._records(details, "ClusterComputeResource")
        host_rows = self._records(details, "HostSystem")
        vm_rows = self._records(details, "VirtualMachine")
        datastore_rows = self._records(details, "Datastore")
        vcenter_row = self._first_record(details, "vCenter")

        cluster_names = [str(item.get("object_name") or "") for item in cluster_rows if item.get("object_name")]
        host_names = [str(item.get("object_name") or "") for item in host_rows if item.get("object_name")]
        clusters = [{"name": str(item.get("object_name") or ""), **item} for item in cluster_rows]
        host_cluster: dict[str, str] = {}
        hosts = []
        for item in host_rows:
            name = str(item.get("object_name") or "")
            props = self._properties(item)
            path = self._asset_path(item)
            cluster = self._match_path_name(path, cluster_names) or str(props.get("cluster_name") or "未归类")
            host_cluster[name] = cluster
            hosts.append({
                "name": name,
                "cluster": cluster,
                "cpuPct": props.get("cpu_usage_avg"),
                "memoryPct": props.get("memory_usage_avg"),
                "connectionState": props.get("connection_state"),
                "maintenanceMode": props.get("in_maintenance_mode", props.get("maintenance_mode")),
                **item,
            })

        vms = []
        for item in vm_rows:
            props = self._properties(item)
            path = self._asset_path(item)
            host_name = str(props.get("host_name") or props.get("hostName") or "")
            if not host_name or host_name not in host_names:
                host_name = self._match_path_name(path, host_names) or "未记录"
            cluster = self._match_path_name(path, cluster_names) or host_cluster.get(host_name, "未归类")
            vms.append({
                "name": str(item.get("object_name") or ""),
                "hostName": host_name,
                "cluster": cluster,
                "powerState": props.get("power_state"),
                "diskGb": self._vm_allocated_capacity_gb(props),
                **item,
            })

        datastores = []
        for item in datastore_rows:
            props = self._properties(item)
            clusters_for_store = props.get("datastore_cluster_names") or []
            if not clusters_for_store:
                path = self._asset_path(item)
                clusters_for_store = [name for name in cluster_names if name and name.casefold() in path.casefold()]
            datastores.append({
                "name": str(item.get("object_name") or "未命名数据存储"),
                "type": props.get("datastore_type"),
                "clusters": list(clusters_for_store) if isinstance(clusters_for_store, (list, tuple)) else [],
                "usagePct": props.get("used_percent"),
                "usedGb": props.get("datastore_used_gb"),
                "freeGb": props.get("datastore_free_gb"),
                "totalGb": props.get("datastore_capacity_gb"),
                **item,
            })

        vcenter_props = self._properties(vcenter_row)
        vcenter_record = {
            "name": str(vcenter_row.get("object_name") or "vCenter"),
            "certificateDays": vcenter_props.get("certificate_days_remaining"),
            "certificateDate": vcenter_props.get("certificate_not_after") or vcenter_props.get("certificate_expiration_date"),
            "connected": vcenter_props.get("connected"),
        }
        return {"cluster": clusters, "host": hosts, "vm": vms, "store": datastores}, vcenter_record

    def _asset_path(self, item: dict[str, Any]) -> str:
        props = self._properties(item)
        return str(props.get("asset_location") or item.get("object_path") or item.get("path") or "")

    def _match_path_name(self, path: str, candidates: list[str]) -> str | None:
        folded = path.casefold()
        matches = [name for name in candidates if name and name.casefold() in folded]
        return max(matches, key=len) if matches else None

    def _vm_allocated_capacity_gb(self, props: dict[str, Any]) -> float | None:
        disks = props.get("vmdk_inventory")
        if isinstance(disks, list):
            if not disks:
                return 0.0 if self._number(props.get("vmdk_count")) == 0 else None
            capacities = [self._number(item.get("capacity_bytes")) for item in disks if isinstance(item, dict)]
            if len(capacities) != len(disks) or any(value is None or value < 0 for value in capacities):
                return None
            return sum(capacities) / (1024**3)
        return None

    def _records(self, details: dict[str, Any], object_type: str) -> list[dict[str, Any]]:
        value = details.get(object_type) or []
        return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []

    def _as_dict(self, item: Any) -> dict[str, Any]:
        if isinstance(item, dict):
            return item
        dump = getattr(item, "model_dump", None)
        if callable(dump):
            value = dump()
            return value if isinstance(value, dict) else {}
        return {}

    def _excluded_report_item(self, item: dict[str, Any], excluded_rule_ids: set[str]) -> bool:
        if str(item.get("rule_id") or "") in excluded_rule_ids:
            return True
        text_parts = [
            item.get(key)
            for key in (
                "title", "rule_name", "rule_id", "description", "reason",
                "unavailable_reason", "message", "current_value_zh", "expected_value_zh",
            )
        ]
        steps = item.get("steps") or []
        text_parts.extend(steps if isinstance(steps, (list, tuple)) else [steps])
        text = " ".join(str(value or "") for value in text_parts).casefold()
        return "syslog" in text or "vmware tools" in text

    def _safe_customer_text(self, value: Any) -> str:
        text = str(value or "").strip()
        folded = text.casefold()
        if "syslog" in folded or "vmware tools" in folded:
            return ""
        return text

    def _finding_count_unit(self, rule_id: str, object_types: set[str]) -> str:
        if rule_id == "VSL-HOST-019":
            return "台主机"
        for object_type, unit in (
            ("HostSystem", "台主机"),
            ("VirtualMachine", "台虚拟机"),
            ("ClusterComputeResource", "个集群"),
            ("Datastore", "个数据存储"),
            ("vCenter", "个 vCenter"),
        ):
            if object_type in object_types:
                return unit
        return "个对象"

    def _customer_steps(self, steps: Any, rule_id: str) -> list[str]:
        if not isinstance(steps, (list, tuple)):
            return []
        output = []
        for step in steps:
            text = str(step or "").strip()
            folded = text.casefold()
            if "syslog" in folded or "vmware tools" in folded:
                if rule_id == "VSL-VM-015":
                    text = "核对客户机操作系统与目标虚拟硬件版本的兼容性，并在维护前完成备份。"
                else:
                    continue
            if text:
                output.append(text)
        return output

    def _role_label(self, value: Any) -> str:
        labels = {
            "virtualization_admin": "虚拟化管理员",
            "storage_admin": "存储管理员",
            "network_admin": "网络管理员",
            "security_admin": "安全管理员",
            "backup_admin": "备份管理员",
        }
        text = str(value or "").strip()
        return labels.get(text, text or "相关管理员")

    def _effort_label(self, value: Any) -> str:
        labels = {"low": "低", "medium": "中", "high": "高"}
        text = str(value or "").strip().casefold()
        return labels.get(text, "未记录")

    def _verification_label(self, value: Any) -> str:
        labels = {
            "rerun_rule": "复跑对应检查",
            "manual_check": "人工复核",
            "command_check": "命令或工具复核",
        }
        text = str(value or "").strip()
        return labels.get(text, text or "复核状态并记录结果")

    def _evidence_number(self, item: dict[str, Any]) -> float | None:
        for container in (item.get("raw_evidence"), item.get("evidence")):
            if not isinstance(container, dict):
                continue
            observed = container.get("observed_detail") or container.get("observed") or {}
            if isinstance(observed, dict):
                for key in ("current_value", "certificate_days_remaining", "days_remaining"):
                    value = self._number(observed.get(key))
                    if value is not None:
                        return value
            for key in ("current_value", "observed_value"):
                value = self._number(container.get(key))
                if value is not None:
                    return value
        return self._number(item.get("current_value"))

    def _bool_label(self, value: Any) -> str:
        if value is True:
            return "是"
        if value is False:
            return "否"
        return "未采集"

    def _safe_list_text(self, value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, (list, tuple, set)):
            values = [self._safe_customer_text(item) for item in value]
            return "、".join(item for item in values if item)
        return self._safe_customer_text(value)

    def _number_text(self, value: Any) -> str:
        number = self._number(value)
        if number is None:
            return "未采集"
        return f"{number:,.0f}" if number.is_integer() else f"{number:,.1f}"

    def _speed_text(self, value: Any) -> str:
        number = self._number(value)
        if number is None:
            return "未采集"
        if number >= 1000:
            return f"{number / 1000:g} Gbit/s"
        return f"{number:g} Mbit/s"

    def _bytes_text(self, value: Any) -> str:
        number = self._number(value)
        if number is None:
            return "未采集"
        if number >= 1024**3:
            return f"{number / (1024**3):,.1f} GB"
        if number >= 1024**2:
            return f"{number / (1024**2):,.1f} MB"
        return f"{number:,.0f} B"

    def _vmkernel_row(self, host_name: str, item: dict[str, Any]) -> dict[str, Any]:
        label = item.get("network_label") or item.get("portgroup")
        return {
            "host": host_name,
            "device": self._safe_customer_text(item.get("device")) or "未记录",
            "ip": self._safe_customer_text(item.get("ip_address") or item.get("ip")) or "未记录",
            "subnet": self._safe_customer_text(item.get("subnet_mask") or item.get("subnet")) or "未记录",
            "label": self._safe_customer_text(label) or "未记录",
            "switch": self._safe_customer_text(item.get("switch")) or "未记录",
            "mtu": self._number_text(item.get("mtu")),
        }

    def _first_record(self, details: dict[str, Any], object_type: str) -> dict[str, Any]:
        rows = self._records(details, object_type)
        return rows[0] if rows else {}

    def _properties(self, item: dict[str, Any]) -> dict[str, Any]:
        value = item.get("properties") or {}
        return value if isinstance(value, dict) else {}

    def _number(self, value: Any) -> float | None:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        return float(value)

    def _power_state(self, value: Any) -> str:
        text = str(value or "").strip().casefold()
        if text in {"poweredon", "开机", "on", "运行"}:
            return "powered_on"
        if text in {"poweredoff", "关机", "off"}:
            return "powered_off"
        if text in {"suspended", "挂起"}:
            return "suspended"
        return "unknown"

    def _has_snapshot(self, props: dict[str, Any]) -> bool:
        snapshots = props.get("snapshots") or []
        return bool(snapshots) or bool(self._number(props.get("snapshot_chain_depth")) or 0)

    def _connection_state(self, value: Any, maintenance: Any, listed_maintenance: bool) -> str:
        text = str(value or "").casefold()
        if maintenance is True or listed_maintenance:
            return "维护模式"
        if text == "connected":
            return "已连接"
        if text in {"notresponding", "disconnected", "not_responding"}:
            return "未响应"
        return "未采集"

    def _percent_text(self, value: Any) -> str:
        number = self._number(value)
        return "未采集" if number is None else f"{number:.1f}%"

    def _capacity_text(self, value: Any) -> str:
        number = self._number(value)
        return "未采集" if number is None else f"{number:,.1f} GB"

    def _gb_number_text(self, value: Any) -> str:
        number = self._number(value)
        if number is None:
            return "未采集"
        return f"{number:,.1f}" if number % 1 else f"{number:,.0f}"

    def _text(self, value: Any) -> str:
        text = str(value or "").strip()
        return text or "未采集"

    def _cluster_feature_note(self, clusters: list[str], enabled: list[str], feature: str) -> str:
        if not clusters:
            return "未采集到集群信息"
        if len(clusters) == 2:
            enabled_names = [name for name in clusters if name in enabled]
            disabled_names = [name for name in clusters if name not in enabled]
            enabled_text = "、".join(enabled_names) or "无"
            disabled_text = "、".join(disabled_names) or "无"
            return f"{feature} 启用：{enabled_text}；未启用：{disabled_text}"
        return f"已启用 {len(enabled)}/{len(clusters)} 个集群"

    def _certificate_status(self, days: float | None) -> str:
        if days is None:
            return "到期日未采集"
        if days <= 0:
            return "已过期"
        if days <= 90:
            return "即将过期"
        return "正常"

    def _certificate_summary(
        self,
        vcenter_count: int,
        vcenter_days: float | None,
        hosts: list[dict[str, Any]],
        host_total: int,
    ) -> str:
        parts = []
        all_remaining = [self._number(item.get("remaining_days")) for item in hosts]
        if vcenter_days is not None:
            all_remaining.append(vcenter_days)
        known_remaining = [value for value in all_remaining if value is not None]
        if vcenter_count and len(hosts) == host_total and len(known_remaining) == host_total + 1 and all(value >= 365 for value in known_remaining):
            return f"本次检查 {vcenter_count} 个 vCenter 证书、{host_total} 个 ESXi 主机证书，均在 1 年以上到期；到期日按巡检日期与剩余天数计算。"
        if vcenter_count:
            parts.append(f"本次检查 {vcenter_count} 个 vCenter 证书" + (f"，到期日 {int(vcenter_days)} 天后" if vcenter_days is not None else ""))
        if hosts:
            soon = sum(bool(item.get("attention")) for item in hosts)
            exact_dates = sum(bool(item.get("expiry_known")) for item in hosts)
            parts.append(f"{host_total} 台 ESXi 主机中 {exact_dates} 台有到期日，{len(hosts)} 台已采集剩余天数，其中 {soon} 台需关注")
        elif host_total:
            parts.append(f"ESXi 主机证书到期信息未采集（主机 {host_total} 台）")
        return "；".join(parts) or "证书到期信息未采集"

    def _date_text(self, value: Any) -> str:
        text = str(value or "").strip()
        if not text:
            return datetime.now().astimezone().strftime("%Y-%m-%d")
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone().strftime("%Y-%m-%d")
        except ValueError:
            return text[:10]
