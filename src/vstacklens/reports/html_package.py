from __future__ import annotations

import json
import math
import os
import uuid
import re
import shutil
import zipfile
from datetime import date, timedelta
from html import escape
from pathlib import Path
from typing import Any

from vstacklens.db.repositories import actionable_risk_total
from vstacklens.reports.presentation import append_report_sentence, count_excluded_powered_off_vms, powered_off_exclusion_note
from vstacklens.reports.html_assets import REPORT_JS, SINGLE_PAGE_REPORT_JS
from vstacklens.reports.report_model import ReportData


TOOLS_HTML_RECOMMENDATION = (
    "安装 VMware Tools / open-vm-tools 后，vCenter 可以更准确获取客户机状态、IP、心跳和运行信息；"
    "支持优雅关机/重启；改善驱动、性能和运维管理能力；"
    "不安装可能导致客户机状态不准确、优雅关机能力受限、监控/备份/自动化能力受限。"
    "如果是厂商虚拟设备不支持、短期临时 VM、离线/关机 VM、或业务明确不允许安装，可以作为例外记录，不作为普通问题反复提示。"
)

SNAPSHOT_HTML_IMPACT = "长期保留快照会占用存储，可能影响虚拟机性能，增加备份、迁移、快照合并风险。"

# 这些状态本身就已经是"不可比"的结论，必须原样保留，不能被改写成 ready，
# 也不能只退化成 single_run 而丢失跨环境提示。
NON_COMPARABLE_HISTORY_STATES = {"empty", "single_run", "environment_mismatch", "run_unavailable"}


class HtmlReportPackageBuilder:
    def render(self, report: ReportData, context: dict[str, Any], output_dir: Path, zip_package: bool = False) -> tuple[Path, Path | None]:
        from vstacklens.application.artifact_publish import staged_report
        output_dir = Path(output_dir)
        if zip_package and output_dir.with_suffix(".zip").exists() and not output_dir.exists():
            output_dir = output_dir.with_name(output_dir.name + "-" + uuid.uuid4().hex[:10])
        with staged_report(output_dir) as (stage, target):
            (stage / "assets").mkdir()
            (stage / "data").mkdir()
            customer_payload = self._customer_report_payload(report, context)
            page_payload = self._single_page_payload(report, context, customer_payload)
            self._write_json(stage / "data" / "customer_report_payload.json", page_payload)
            (stage / "assets" / "report.css").write_text(self._single_page_css(), encoding="utf-8")
            (stage / "assets" / "report.js").write_text(SINGLE_PAGE_REPORT_JS, encoding="utf-8")
            (stage / "index.html").write_text(self._html(page_payload), encoding="utf-8")
            if zip_package:
                with zipfile.ZipFile(stage / "report.zip", "w", compression=zipfile.ZIP_DEFLATED) as archive:
                    for path in stage.rglob("*"):
                        if path.is_file() and path.name != "report.zip":
                            archive.write(path, Path(target.name) / path.relative_to(stage))
        zip_path = target.with_suffix(".zip") if zip_package else None
        if zip_path:
            # Same-volume rename on Windows refuses an existing destination.
            # ZIP content was fully generated before the report directory was published.
            if zip_path.exists():
                raise FileExistsError("Refusing to overwrite an existing report ZIP")
            os.rename(target / "report.zip", zip_path)
        return target / "index.html", zip_path

    def _single_page_payload(self, report: ReportData, context: dict[str, Any], customer_data: dict[str, Any] | None = None) -> dict[str, Any]:
        customer_data = customer_data or self._customer_report_payload(report, context)
        report_context = customer_data.get("report_context", {})
        report_model = report.model_dump()
        asset_inventory = report_model.get("asset_inventory") or {}
        records, asset_summary, datacenter_name, vcenter_record = self._single_page_assets(asset_inventory)
        vsan_summary = report_context.get("vsan_summary") or {}
        vsan_cluster_names = [str(name) for name in vsan_summary.get("clusters") or [] if name]
        clusters = []
        cluster_records = records.get("cluster", [])
        for name in dict.fromkeys([item["name"] for item in cluster_records] + vsan_cluster_names):
            cluster_asset = next((item for item in cluster_records if item["name"] == name), {})
            hosts = [item for item in records.get("host", []) if item.get("cluster") == name]
            vms = [item for item in records.get("vm", []) if item.get("cluster") == name]
            stores = [item for item in records.get("store", []) if name in item.get("clusters", [])]
            is_vsan = name in vsan_cluster_names or any(item.get("isVsan") for item in stores)
            clusters.append({
                "name": name,
                "kind": "vSAN 集群" if is_vsan else "普通集群",
                "ha": cluster_asset.get("ha", ""),
                "drs": cluster_asset.get("drs", ""),
                "hosts": [self._single_page_host_view(item) for item in hosts],
                "vms": [self._single_page_vm_view(item) for item in vms],
                "stores": [self._single_page_store_view(item) for item in stores],
                "vsan": self._single_page_vsan(name, hosts, stores, vsan_summary) if is_vsan else None,
            })

        powered_off_note = powered_off_exclusion_note(
            count_excluded_powered_off_vms((asset_inventory.get("details") or {}).get("VirtualMachine", []))
        )
        issues = self._single_page_issues(
            customer_data.get("findings", []),
            records,
            powered_off_note=powered_off_note,
        )
        visible_risk_counts = {level: sum(item["level"] == level for item in issues) for level in ("P1", "P2", "P3")}
        priority = next((level for level in ("P1", "P2", "P3") if visible_risk_counts[level] > 0), "")
        timing = report_context.get("run_timing") or {}
        identity = self._single_page_identity(report_context, datacenter_name, vcenter_record, records)
        certificates = self._single_page_certificates(report_context, records, vcenter_record)
        report_info = report_model.get("report_info") or {}
        customer_info = report_model.get("customer_info") or {}
        scale = [
            {"label": "集群", "count": asset_summary.get("ClusterComputeResource", 0)},
            {"label": "ESXi 主机", "count": asset_summary.get("HostSystem", 0)},
            {"label": "虚拟机", "count": asset_summary.get("VirtualMachine", 0)},
            {"label": "数据存储", "count": asset_summary.get("Datastore", 0)},
        ]
        passed_checks = self._single_page_passed_checks(report_context, {item["title"] for item in issues})
        payload = {
            "title": "VStackLens 虚拟化巡检报告",
            "summary": {
                "startedAt": timing.get("started_at") or "",
                "finishedAt": timing.get("finished_at") or "",
                "judgement": "需关注" if issues else "正常",
                "problemCount": len(issues),
                "highestLevel": priority,
            },
            "environment": {"identity": identity, "certificates": certificates, "scale": scale, "clusters": clusters},
            "problems": issues,
            "passedChecks": passed_checks,
            "inventory": {
                "hosts": [self._single_page_host_view(item) for item in records.get("host", [])],
                "vms": [self._single_page_vm_view(item) for item in records.get("vm", [])],
                "stores": [self._single_page_store_view(item) for item in records.get("store", [])],
            },
            "assets": {"summary": asset_summary},
            "findings": [
                {"risk_level": issue["level"], "title": issue["title"], "object_name": (issue.get("objects") or [{}])[0].get("name", "")}
                for issue in issues
            ],
            "report_context": {
                "report_info": {
                    "report_title": "VStackLens 虚拟化巡检报告",
                    "generated_at": timing.get("finished_at") or report_info.get("generated_at", ""),
                },
                "customer_info": {
                    "customer_name": customer_info.get("customer_name", ""),
                },
                "run_timing": {"started_at": timing.get("started_at", ""), "finished_at": timing.get("finished_at", "")},
                "risk_summary": {**visible_risk_counts, "total": len(issues)},
                "environment_info": {"security_warnings": []},
                "environment_summary": {"covered_object_total": int(asset_inventory.get("total", 0) or 0)},
            },
        }
        comparison = report_context.get("history_comparison") or {}
        if comparison.get("state") == "ready" and comparison.get("baseline_run_id") and comparison.get("comparison_run_id"):
            safe_comparison = {
                "state": "ready",
                "baseline_run_id": comparison.get("baseline_run_id", ""),
                "comparison_run_id": comparison.get("comparison_run_id", ""),
                "summary_text": self._single_page_label(comparison.get("summary_text") or ""),
            }
            payload["summary"]["comparisonText"] = "与上轮巡检相比，" + safe_comparison["summary_text"]
            payload["report_context"]["history_comparison"] = safe_comparison
            payload["report_context"]["appendix"] = {"history_comparison": safe_comparison}
        return payload

    @staticmethod
    def _single_page_host_view(item: dict[str, Any]) -> dict[str, Any]:
        return {key: item.get(key) for key in ("name", "connectionState", "maintenanceMode", "cpuPct", "memoryPct")}

    @staticmethod
    def _single_page_vm_view(item: dict[str, Any]) -> dict[str, Any]:
        return {key: item.get(key) for key in ("name", "hostName", "powerState", "diskGb")}

    @staticmethod
    def _single_page_store_view(item: dict[str, Any]) -> dict[str, Any]:
        return {key: item.get(key) for key in ("name", "type", "totalGb", "usedGb", "freeGb", "usagePct")}

    def _single_page_assets(self, asset_inventory: dict[str, Any]) -> tuple[dict[str, list[dict[str, Any]]], dict[str, int], str, dict[str, Any]]:
        type_names = {
            "ClusterComputeResource": "cluster",
            "HostSystem": "host",
            "VirtualMachine": "vm",
            "Datastore": "store",
            "vCenter": "vcenter",
        }
        source_details = asset_inventory.get("details") or {}
        cluster_names = {
            str(item.get("object_name") or "")
            for item in source_details.get("ClusterComputeResource", [])
            if item.get("object_name")
        }
        records: dict[str, list[dict[str, Any]]] = {kind: [] for kind in type_names.values()}
        datacenter_name = ""
        for object_type, kind in type_names.items():
            for item in source_details.get(object_type, []) or []:
                properties = item.get("properties") or {}
                if isinstance(properties.get("properties"), dict):
                    properties = properties["properties"]
                name = str(item.get("object_name") or "")
                path = str(item.get("object_path") or "")
                location = str(properties.get("asset_location") or item.get("asset_location") or "")
                path_parts = [part.strip() for part in re.split(r"[/\\]", path) if part.strip()]
                if not datacenter_name and len(path_parts) >= 3 and path_parts[0] == str(item.get("object_name") or ""):
                    datacenter_name = path_parts[1]
                if not datacenter_name and len(path_parts) >= 3:
                    datacenter_name = path_parts[1]
                if not datacenter_name and len(path_parts) >= 2 and object_type == "ClusterComputeResource":
                    datacenter_name = path_parts[-2]

                location_parts = [part.strip() for part in re.split(r"[/\\]", location) if part.strip()]
                cluster = next((part for part in location_parts if part in cluster_names), "")
                if object_type == "ClusterComputeResource":
                    cluster = name
                if object_type == "Datastore":
                    datastore_clusters = properties.get("datastore_cluster_names") or []
                    if isinstance(datastore_clusters, str):
                        datastore_clusters = [datastore_clusters]
                    datastore_clusters = [str(value) for value in datastore_clusters if str(value) in cluster_names]
                    if not datastore_clusters:
                        match = re.search(r"挂载集群\s+([^/\\]+)", location)
                        if match and match.group(1).strip() in cluster_names:
                            datastore_clusters = [match.group(1).strip()]
                    if cluster and cluster not in datastore_clusters:
                        datastore_clusters.append(cluster)
                else:
                    datastore_clusters = [cluster] if cluster else []

                host_name = ""
                host_match = re.search(r"主机\s+([^/\\]+)\s*$", location)
                if host_match:
                    host_name = host_match.group(1).strip()
                elif object_type == "HostSystem":
                    host_name = name
                elif properties.get("host_name"):
                    host_name = str(properties.get("host_name"))

                record: dict[str, Any] = {
                    "kind": kind,
                    "name": name,
                    "location": location,
                    "cluster": cluster,
                    "clusters": datastore_clusters,
                }
                if object_type == "ClusterComputeResource":
                    record["ha"] = self._single_page_enabled(properties.get("ha_enabled"))
                    record["drs"] = self._single_page_enabled(properties.get("drs_enabled"))
                elif object_type == "HostSystem":
                    record["model"] = self._first_present(properties, ("host_model", "hardware_model", "model_name", "model"))
                    record["version"] = self._first_present(properties, ("esxi_version", "product_version", "host_version", "version"))
                    record["cpuPct"] = self._single_page_number(properties.get("cpu_usage_avg"))
                    record["memoryPct"] = self._single_page_number(properties.get("memory_usage_avg"))
                    record["connectionState"] = self._first_present(properties, ("connection_state", "runtime_connection_state", "host_connection_state"))
                    maintenance = properties.get("in_maintenance_mode", properties.get("maintenance_mode", False))
                    record["maintenanceMode"] = maintenance is True or str(maintenance).strip().casefold() in {"true", "1", "yes"}
                    record["certificateDate"] = str(properties.get("host_certificate_not_after") or "")
                    record["certificateDays"] = self._single_page_number(properties.get("host_certificate_days_remaining"))
                    record["licenseType"] = self._single_page_license(properties.get("host_license_name"), properties.get("host_license_expiration_date"))
                elif object_type == "VirtualMachine":
                    record["hostName"] = host_name
                    record["powerState"] = self._single_page_power_state(properties.get("power_state"))
                    disks = properties.get("vmdk_inventory") or []
                    disk_bytes = [self._single_page_number(disk.get("capacity_bytes")) for disk in disks if isinstance(disk, dict)]
                    disk_bytes = [value for value in disk_bytes if value is not None]
                    record["diskGb"] = round(sum(disk_bytes) / (1024 ** 3), 1) if disk_bytes else None
                elif object_type == "Datastore":
                    record["type"] = self._single_page_store_type(properties.get("datastore_type"))
                    record["totalGb"] = self._single_page_number(properties.get("datastore_capacity_gb"))
                    record["usedGb"] = self._single_page_number(properties.get("datastore_used_gb"))
                    record["freeGb"] = self._single_page_number(properties.get("datastore_free_gb"))
                    record["usagePct"] = self._single_page_number(properties.get("used_percent"))
                    record["isVsan"] = bool(properties.get("datastore_is_vsan"))
                    native = properties.get("vsan_native_capacity") or {}
                    native_total = native.get("total_capacity_bytes") if isinstance(native, dict) else None
                    native_used = native.get("used_capacity_bytes") if isinstance(native, dict) else None
                    native_free = native.get("free_capacity_bytes") if isinstance(native, dict) else None
                    record["vsan"] = {
                        "totalGb": self._bytes_to_gb(native_total) if native_total is not None else self._single_page_number(properties.get("datastore_capacity_gb")),
                        "usedGb": self._bytes_to_gb(native_used) if native_used is not None else self._single_page_number(properties.get("datastore_used_gb")),
                        "freeGb": self._bytes_to_gb(native_free) if native_free is not None else self._single_page_number(properties.get("datastore_free_gb")),
                        "usagePct": self._single_page_number(properties.get("vsan_used_percent")) if properties.get("vsan_used_percent") is not None else self._single_page_number(properties.get("used_percent")),
                        "objects": self._single_page_number(properties.get("vsan_object_count")),
                        "vmdks": self._single_page_number(properties.get("vsan_vmdk_count")),
                        "syncObjects": self._single_page_number(properties.get("vsan_resync_object_count")),
                        "syncGb": self._bytes_to_gb(properties.get("vsan_resync_bytes")),
                        "architecture": self._single_page_label(properties.get("vsan_architecture") or ""),
                    }
                elif object_type == "vCenter":
                    record["version"] = str(properties.get("version") or "")
                    record["build"] = str(properties.get("build") or properties.get("build_number") or "")
                    record["certificateDate"] = self._first_present(properties, ("certificate_not_after", "certificate_expiration_date", "certificate_expiry_date"))
                    record["certificateDays"] = self._single_page_number(properties.get("certificate_days_remaining"))
                    record["licenseDays"] = self._single_page_number(properties.get("license_days_remaining"))
                records[kind].append(record)

        counts = asset_inventory.get("summary") or {}
        asset_summary = {key: int(counts.get(key, 0) or 0) for key in type_names}
        vcenter_record = records.get("vcenter", [{}])[0] if records.get("vcenter") else {}
        return records, asset_summary, datacenter_name, vcenter_record

    def _single_page_vsan(self, cluster_name: str, hosts: list[dict[str, Any]], stores: list[dict[str, Any]], summary: dict[str, Any]) -> dict[str, Any] | None:
        summary_clusters = [str(name) for name in summary.get("clusters") or []]
        is_vsan = cluster_name in summary_clusters or any(item.get("isVsan") for item in stores)
        if not is_vsan:
            return None
        host_names = {item.get("name") for item in hosts}
        source_disks = summary.get("disk_details") or []
        disks = [
            {
                "host": self._single_page_label(item.get("host") or ""),
                "group": self._single_page_label(item.get("disk_group") or ""),
                "role": self._single_page_label(item.get("role") or ""),
                "device": self._single_page_label(item.get("device") or ""),
                "diskState": self._single_page_label(item.get("health") or ""),
            }
            for item in source_disks
            if not host_names or item.get("host") in host_names
        ]
        source_adapters = (summary.get("network") or {}).get("vmkernels") or []
        adapters = [
            {
                "host": self._single_page_label(item.get("host_name") or item.get("host") or ""),
                "device": self._single_page_label(item.get("device") or ""),
                "ip": self._single_page_label(item.get("ip_address") or ""),
                "subnet": self._single_page_label(item.get("subnet_mask") or ""),
                "label": self._single_page_label(item.get("network_label") or item.get("portgroup") or ""),
                "mtu": self._single_page_number(item.get("mtu")),
            }
            for item in source_adapters
            if not host_names or (item.get("host_name") or item.get("host")) in host_names
        ]
        per_cluster = next((item.get("vsan") or {} for item in stores if item.get("isVsan")), {})
        aggregate_capacity = summary.get("capacity") or {}
        for target, aggregate in (("totalGb", "total_gb"), ("usedGb", "used_gb"), ("freeGb", "free_gb"), ("usagePct", "used_percent")):
            if per_cluster.get(target) is None:
                per_cluster[target] = self._single_page_number(aggregate_capacity.get(aggregate))
        for target, source in (("objects", "object_count"), ("vmdks", "vmdk_count"), ("syncObjects", "resync_object_count")):
            if per_cluster.get(target) is None:
                per_cluster[target] = self._single_page_number(summary.get(source))
        if per_cluster.get("syncGb") is None:
            per_cluster["syncGb"] = self._bytes_to_gb(summary.get("resync_bytes"))
        per_cluster["disks"] = disks
        per_cluster["adapters"] = adapters
        per_cluster["issues"] = self._single_page_vsan_summary_issues(summary)
        return {key: per_cluster.get(key) for key in ("totalGb", "usedGb", "freeGb", "usagePct", "objects", "vmdks", "syncObjects", "syncGb", "disks", "adapters", "issues")}

    def _single_page_vsan_summary_issues(self, summary: dict[str, Any]) -> list[dict[str, str]]:
        issues: list[dict[str, str]] = []
        actionable_statuses = {"需关注", "异常", "故障", "不健康", "严重", "warning", "red", "yellow", "error", "failed", "unhealthy", "degraded", "offline"}

        def add_issue(title: Any, current: Any, impact: Any = "", remediation: Any = "") -> None:
            clean_title = self._single_page_label(title or "vSAN 检查项")
            clean_current = self._single_page_label(current or clean_title)
            signature = (clean_title.casefold(), clean_current.casefold())
            if not clean_title or any((item["title"].casefold(), item["current"].casefold()) == signature for item in issues):
                return
            issues.append({
                "title": clean_title,
                "current": clean_current,
                "impact": self._single_page_label(impact or ""),
                "remediation": self._single_page_label(remediation or ""),
            })

        issue_sources = (
            ("health_issues", "vSAN 集群健康"),
            ("disk_issues", "vSAN 磁盘状态"),
            ("object_issues", "vSAN 对象状态"),
        )
        for source_key, fallback_title in issue_sources:
            for item in summary.get(source_key) or []:
                title = item.get("title") or item.get("component") or item.get("host") or item.get("disk") or fallback_title
                current = item.get("current") or item.get("summary") or item.get("conclusion") or item.get("status")
                impact = item.get("impact") or item.get("business_impact") or item.get("consequence")
                remediation = item.get("remediation") or item.get("recommended_action") or item.get("recommendation")
                add_issue(title, current, impact, remediation)

        for item in summary.get("report_categories") or []:
            title = str(item.get("title") or "")
            if re.search(r"storage\s*policy|存储策略", title, re.IGNORECASE):
                continue
            status = str(item.get("status") or "").strip().casefold()
            if status not in actionable_statuses:
                continue
            current = item.get("conclusion") or item.get("summary") or item.get("status")
            add_issue(title, current, item.get("impact") or item.get("business_impact"), item.get("remediation") or item.get("recommendation"))
        return issues

    def _single_page_identity(self, report_context: dict[str, Any], datacenter_name: str, vcenter_record: dict[str, Any], records: dict[str, list[dict[str, Any]]]) -> list[dict[str, str]]:
        env_info = report_context.get("environment_info") or {}
        rows: list[dict[str, str]] = []
        def add(label: str, value: Any) -> None:
            if value is not None and str(value).strip():
                rows.append({"label": label, "value": str(value)})
        address = env_info.get("vcenter_address") or env_info.get("vcenter") or vcenter_record.get("name")
        add("vCenter 名称", env_info.get("vcenter_name") or vcenter_record.get("name"))
        add("管理地址", address)
        version = vcenter_record.get("version") or env_info.get("vcenter_version")
        build = vcenter_record.get("build") or env_info.get("vcenter_build")
        version_build = " / ".join(str(value) for value in (version, build) if value)
        add("版本与 Build", version_build)
        add("数据中心", datacenter_name)
        timing = report_context.get("run_timing") or {}
        start = timing.get("started_at") or ""
        finish = timing.get("finished_at") or ""
        if start or finish:
            add("巡检时间", self._single_page_date(start or finish))
        return rows

    def _single_page_certificates(
        self,
        report_context: dict[str, Any],
        records: dict[str, list[dict[str, Any]]],
        vcenter_record: dict[str, Any],
        certificate_evidence: list[dict[str, Any]] | None = None,
        license_fallback: list[str] | None = None,
    ) -> dict[str, Any]:
        timing = report_context.get("run_timing") or {}
        report_info = report_context.get("report_info") or {}
        as_of = self._single_page_certificate_date(timing.get("started_at") or report_info.get("generated_at"))
        if as_of is None:
            return {"vcenter": [], "clusters": [], "licenses": []}

        if certificate_evidence is None:
            appendix = report_context.get("appendix") or {}
            certificate_evidence = report_context.get("certificate_license_evidence") or appendix.get("certificate_license_evidence") or []
        certificate_evidence = [item for item in certificate_evidence if isinstance(item, dict) and self._is_certificate_evidence(item)]

        def matching_evidence(name: str, kind: str) -> dict[str, Any]:
            matches = []
            for item in certificate_evidence:
                evidence_name = str(item.get("object_name") or "")
                category = str(item.get("category_label") or item.get("object_type_label") or "")
                is_vcenter = "vcenter" in category.casefold()
                if evidence_name == name and ((kind == "vcenter" and is_vcenter) or (kind == "host" and not is_vcenter)):
                    matches.append(item)
            return matches[0] if matches else {}

        def make_entry(name: str, kind: str, cluster_name: str, record: dict[str, Any]) -> dict[str, Any] | None:
            evidence = matching_evidence(name, kind)
            evidence_text = " ".join(str(evidence.get(key) or "") for key in ("current_value_zh", "explanation_zh", "current_value", "explanation"))
            direct_date = next((self._single_page_certificate_date(value) for value in (
                record.get("certificateDate"), evidence.get("certificate_not_after"), evidence_text,
            ) if self._single_page_certificate_date(value) is not None), None)
            days = self._single_page_certificate_days(evidence, record)
            if direct_date is not None:
                expires = direct_date
            elif days is not None:
                expires = as_of + timedelta(days=days)
            else:
                return None
            remaining = (expires - as_of).days
            expired = remaining <= 0
            imminent = 0 < remaining <= 90
            if expired:
                remaining_label = "已过期"
            elif remaining <= 180:
                remaining_label = "3 个月"
            elif remaining <= 270:
                remaining_label = "6 个月"
            elif remaining < 365:
                remaining_label = "9 个月"
            else:
                remaining_label = "1 年及以上"
            return {
                "name": name,
                "cluster": cluster_name,
                "expiresOn": expires.isoformat(),
                "remainingDays": remaining,
                "remainingLabel": remaining_label,
                "imminent": imminent,
                "expired": expired,
                "attention": imminent or expired,
            }

        vcenter_name = str(vcenter_record.get("name") or "")
        if not vcenter_name:
            vcenter_evidence = next((item for item in certificate_evidence if "vcenter" in str(item.get("category_label") or item.get("object_type_label") or "").casefold()), {})
            vcenter_name = str(vcenter_evidence.get("object_name") or "")
        vcenter_items = []
        if vcenter_name:
            entry = make_entry(vcenter_name, "vcenter", "", vcenter_record)
            if entry:
                vcenter_items.append(entry)

        cluster_hosts: dict[str, list[dict[str, Any]]] = {}
        for host in records.get("host", []):
            name = str(host.get("name") or "")
            cluster_name = str(host.get("cluster") or "")
            if not name or not cluster_name:
                continue
            entry = make_entry(name, "host", cluster_name, host)
            if entry:
                cluster_hosts.setdefault(cluster_name, []).append(entry)

        licenses = sorted({str(item.get("licenseType")) for item in records.get("host", []) if item.get("licenseType")})
        if vcenter_record.get("licenseDays") is not None and vcenter_record["licenseDays"] > 36500:
            licenses.append("vCenter 永久授权")
        licenses.extend(str(value) for value in license_fallback or [] if value)
        return {
            "vcenter": vcenter_items,
            "clusters": [{"name": name, "hosts": hosts} for name, hosts in cluster_hosts.items()],
            "licenses": list(dict.fromkeys(licenses)),
        }

    @staticmethod
    def _is_certificate_evidence(item: dict[str, Any]) -> bool:
        label = " ".join(str(item.get(key) or "") for key in ("category_label", "object_type_label", "rule_name"))
        return "证书" in label or "certificate" in label.casefold()

    @staticmethod
    def _single_page_certificate_date(value: Any) -> date | None:
        match = re.search(r"(\d{4}-\d{2}-\d{2})", str(value or ""))
        if not match:
            return None
        try:
            return date.fromisoformat(match.group(1))
        except ValueError:
            return None

    @staticmethod
    def _single_page_certificate_days(evidence: dict[str, Any], record: dict[str, Any]) -> int | None:
        for key in ("remaining_days", "certificate_days_remaining", "certificateDays"):
            value = evidence.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                return int(value)
        for key in ("certificateDays", "certificate_days_remaining"):
            value = record.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                return int(value)
        text = " ".join(str(evidence.get(key) or "") for key in ("current_value_zh", "explanation_zh", "current_value", "explanation"))
        match = re.search(r"(?:剩余|有效期为)?\s*(-?\d+)\s*天", text)
        if not match:
            return None
        days = int(match.group(1))
        return -days if "已过期" in text and days > 0 else days

    def _single_page_issues(
        self,
        findings: list[dict[str, Any]],
        records: dict[str, list[dict[str, Any]]],
        *,
        powered_off_note: str = "",
    ) -> list[dict[str, Any]]:
        groups: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
        for item in findings:
            level = str(item.get("risk_level") or "").upper()
            title = self._single_page_label(item.get("title") or "")
            if item.get("rule_id") == "VSL-VM-002" and title == "虚拟机未安装 VMware Tools":
                title = "虚拟机 VMware Tools 未运行"
            if level not in {"P1", "P2", "P3"} or not title:
                continue
            key = (str(item.get("rule_id") or ""), level, title)
            groups.setdefault(key, []).append(item)

        assets_by_key: dict[tuple[str, str], dict[str, Any]] = {}
        kind_by_type = {
            "HostSystem": "host", "ESXi 主机": "host", "ESXi 主机核验结果": "host",
            "VirtualMachine": "vm", "虚拟机": "vm", "虚拟机核验结果": "vm",
            "ClusterComputeResource": "cluster", "集群": "cluster", "集群核验结果": "cluster",
            "Datastore": "store", "数据存储": "store", "数据存储核验结果": "store",
            "vCenter": "vcenter", "vCenter 管理平台": "vcenter", "vCenter 管理平台核验结果": "vcenter",
        }
        for kind, items in records.items():
            for item in items:
                assets_by_key[(kind, item.get("name", ""))] = item

        output = []
        for (_rule_id, level, title), items in groups.items():
            objects = []
            seen = set()
            for finding in items:
                name = str(finding.get("object_name") or "").strip()
                object_kind = kind_by_type.get(str(finding.get("object_type") or "")) or kind_by_type.get(str(finding.get("object_type_label") or ""))
                asset = assets_by_key.get((object_kind, name), {}) if object_kind else {}
                key = (object_kind or "", name)
                if not name or key in seen:
                    continue
                seen.add(key)
                location = ""
                if object_kind == "vm":
                    location = " / ".join(value for value in (asset.get("cluster"), f"主机 {asset.get('hostName')}" if asset.get("hostName") else "") if value)
                elif object_kind == "host":
                    location = asset.get("cluster") or ""
                elif object_kind == "cluster":
                    location = asset.get("location") or name
                elif object_kind == "store":
                    location = "、".join(asset.get("clusters") or [])
                elif object_kind == "vcenter":
                    location = "vCenter 管理平台"
                objects.append({"name": name, "location": self._single_page_label(location)})
            objects.sort(key=lambda item: (item["name"], item["location"]))
            copy = self._single_page_problem_copy(title, len(objects), items)
            if _rule_id == "VSL-VM-018" and powered_off_note:
                copy["current"] = append_report_sentence(copy.get("current"), powered_off_note)
            output.append({"level": level, "title": title, "objects": objects, **copy})
        level_order = {"P1": 0, "P2": 1, "P3": 2}
        visible = [item for item in output if not any(hidden in item["title"].casefold() for hidden in ("vmware tools", "syslog"))]
        return sorted(visible, key=lambda item: (level_order.get(item["level"], 9), item["title"], len(item["objects"])))

    def _single_page_problem_copy(self, title: str, count: int, findings: list[dict[str, Any]]) -> dict[str, str]:
        if "快照" in title:
            ages = [self._single_page_number(item.get("snapshot_age_days_max")) for item in findings]
            ages = [value for value in ages if value is not None]
            oldest = max(ages) if ages else None
            current = f"{count} 台虚拟机仍保留快照" + (f"，最长约 {self._single_page_format_number(oldest)} 天" if oldest is not None else "") + "。"
            examples = []
            for item in findings:
                for entry in self._snapshot_entries(item):
                    name = self._first_text(entry, ("name", "snapshot_name", "快照名称"), "")
                    created = self._snapshot_time_label(entry)
                    example = self._single_page_label(name)
                    date = self._single_page_date(created)
                    if date and not re.search(r"\d{4}[/\-]\d{1,2}[/\-]\d{1,2}", example):
                        example = f"{example}（{date}）" if example else date
                    if example and example not in examples:
                        examples.append(example)
            if examples:
                current += " 快照示例：" + "、".join(examples[:2]) + "。"
            expected = "快照应在业务用途或维护周期结束后及时清理。"
            impact = "长期保留快照会占用存储空间，并增加备份、迁移和快照合并风险。"
            remediation = "确认快照用途与保留期限；无业务依赖后，在维护窗口删除或合并，并复查快照列表与存储空间。"
        elif "物理网卡链路异常" in title:
            current = f"{count} 台主机存在物理网卡链路异常。"
            expected = "承载业务的物理上行链路应保持连接，并满足链路冗余要求。"
            impact = "可能降低网络冗余与性能，影响虚拟机迁移或存储访问。"
            remediation = "检查物理链路、交换机端口、光模块和速率协商；恢复后确认主机链路状态与冗余。"
        elif "红色活动告警" in title:
            alarms = []
            for item in findings:
                observed = item.get("observed_detail") or {}
                if isinstance(observed, dict):
                    alarms.extend(observed.get("active_red_alarms") or [])
            count_match = re.search(r"红色活动告警\s*(\d+)\s*条", " ".join(str(item.get("observed_detail_zh") or "") for item in findings))
            alarm_count = len(alarms) or (int(count_match.group(1)) if count_match else count)
            details = []
            for alarm in alarms:
                if not isinstance(alarm, dict):
                    continue
                entity = self._single_page_label(alarm.get("entity_name") or "")
                alarm_name = self._single_page_label(alarm.get("alarm_name") or "")
                detail = "；".join(value for value in (f"告警对象：{entity}" if entity else "", f"告警名称：{alarm_name}" if alarm_name else "") if value)
                if detail and detail not in details:
                    details.append(detail)
            current = f"当前发现红色活动告警 {alarm_count} 条。"
            if details:
                current = f"当前发现红色活动告警 {alarm_count} 条：" + "；".join(details) + "。"
            expected = "活动告警应经确认和处置后恢复正常。"
            impact = "若未及时处理，告警对应的故障可能持续或扩大。"
            remediation = "打开告警详情确认对象与根因，完成处置后确认告警清除并重新巡检。"
        elif "HA 未启用" in title:
            current = f"{count} 个集群未启用主机故障恢复保护。"
            expected = "业务集群应按高可用要求启用主机故障恢复保护。"
            impact = "主机故障时，虚拟机自动恢复能力受限。"
            remediation = "评估集群容量与故障策略后启用 HA，并验证集群保护状态。"
        elif "资源分配比例偏高" in title:
            current = f"{count} 台主机的资源分配比例达到巡检关注条件。"
            expected = "资源分配应与物理容量和实际业务负载相匹配。"
            impact = "资源余量紧张时可能造成性能下降，并影响维护和新增业务。"
            remediation = "结合业务峰值与性能指标评估容量，按需迁移或扩容，完成后复核主机资源压力。"
        elif "预留过高" in title:
            current = f"{count} 台虚拟机的资源预留配置触发关注条件。"
            expected = "资源预留应符合虚拟机业务级别的实际需求。"
            impact = "预留过高会减少集群可分配资源，影响虚拟机调度或启动。"
            remediation = "核实业务预留需求，调整不必要的 CPU 或内存预留，再确认虚拟机可正常调度和启动。"
        elif "VMware Tools 未运行" in title:
            current = f"{count} 台虚拟机中的客户机管理工具未运行。"
            expected = "已安装的客户机管理工具应保持运行。"
            impact = "客户机运行状态与管理信息可能无法及时更新，远程关机等管理能力会受限。"
            remediation = "确认客户机兼容性，启动或修复 VMware Tools / open-vm-tools 服务，再确认工具运行状态。"
        elif "未安装 VMware Tools" in title:
            current = f"{count} 台虚拟机未安装客户机管理工具。"
            expected = "受支持的虚拟机应安装并运行相应客户机工具。"
            impact = "客户机状态、IP 与心跳信息可能不准确，优雅关机及监控能力会受限。"
            remediation = "在维护窗口安装或升级 VMware Tools / open-vm-tools，随后确认工具正常运行。"
        elif "本地存储" in title:
            current = f"当前有 {count} 台虚拟机的磁盘文件位于主机本地存储。"
            expected = "需要主机故障迁移能力的业务虚拟机应使用共享存储。"
            impact = "主机故障后，本地存储上的虚拟机可能无法在其他主机恢复。"
            remediation = "确认本地存储使用原因，必要时迁移到共享存储，并复核备份与故障恢复策略。"
        elif "DRS 未启用" in title:
            current = f"{count} 个集群未启用负载自动均衡。"
            expected = "需要负载自动均衡的集群应启用 DRS。"
            impact = "负载不均衡时可能增加性能差异和人工调度工作。"
            remediation = "检查资源池与虚拟机规则后启用 DRS，并复核自动化级别和负载分布。"
        else:
            current = next((safe for item in findings if (safe := self._single_page_safe_detail(item.get("observed_detail_zh") or item.get("current_value_zh")))), "")
            expected = next((safe for item in findings if (safe := self._single_page_safe_detail(item.get("expected_detail_zh") or item.get("expected_value_zh")))), "")
            impact = next((safe for item in findings if (safe := self._single_page_safe_detail(item.get("summary") or item.get("business_impact") or item.get("explanation_zh")))), "")
            remediation = next((safe for item in findings if (safe := self._single_page_safe_detail(item.get("recommended_action_zh") or item.get("remediation")))), "")
            current = current or f"{count} 个对象存在需要处理的配置或状态问题。"
            expected = expected or "相关对象应符合业务规划并处于正常状态。"
            impact = impact or "未处理可能影响业务运行稳定性或资源调度。"
            remediation = remediation or "按问题对象逐项核实配置并完成处理，随后复查对应状态。"
        return {"current": current, "expected": expected, "impact": impact, "remediation": remediation}

    def _single_page_safe_detail(self, value: Any) -> str:
        text = self._single_page_label(value or "")
        if not text:
            return ""
        blocked = ("未确认", "缺字段", "不合规", "未采集", "collected", "not_collected", "unavailable", "unsupported", "permission_denied", "guestToolsNotInstalled", "采集来源", "source_path", "rule_id", "vsan_")
        replacements = (
            ("当前观察值：", ""), ("当前值：", ""), ("期望状态：", ""), ("建议状态：", ""),
            ("期望值：", ""), ("当前状态：", ""), ("状态：down", "状态：断开"), ("状态：up", "状态：连接正常"),
            ("Datastore：", "数据存储："),
        )
        parts = []
        for part in re.split(r"[；;]", text):
            part = part.strip()
            if not part or any(token.casefold() in part.casefold() for token in blocked):
                continue
            for old, new in replacements:
                part = part.replace(old, new)
            if part and part not in parts:
                parts.append(part)
        return "；".join(parts[:5])

    def _single_page_passed_checks(self, report_context: dict[str, Any], problem_titles: set[str] | None = None) -> list[str]:
        passed: list[str] = []
        problem_titles = {str(title).strip().casefold() for title in problem_titles or set()}
        blocked = ("未确认", "缺字段", "不合规", "未采集", "collected", "health", "capacity", "network", "resync", "storage policy", "syslog", "vmware tools")
        for item in report_context.get("rule_checklist", []) or []:
            count = self._single_page_number(item.get("passed")) or 0
            if count <= 0 or any(self._single_page_number(item.get(key)) for key in ("failed", "unavailable", "error")):
                continue
            label = self._single_page_label(item.get("rule_name") or "")
            if not label or label.strip().casefold() in problem_titles or any(word in label.casefold() for word in blocked):
                continue
            if label not in passed:
                passed.append(label)
        vsan = report_context.get("vsan_summary") or {}
        for item in vsan.get("report_categories", []) or []:
            if item.get("status") != "正常":
                continue
            label = self._single_page_label(item.get("title") or "")
            if label and label.strip().casefold() not in problem_titles and not any(word in label.casefold() for word in blocked) and label not in passed:
                passed.append(label)
        return passed

    @staticmethod
    def _single_page_enabled(value: Any) -> str:
        if value is True:
            return "已启用"
        if value is False:
            return "未启用"
        return ""

    @staticmethod
    def _single_page_number(value: Any) -> float | None:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        return float(value)

    @staticmethod
    def _single_page_format_number(value: Any) -> str:
        number = float(value)
        return f"{number:,.1f}".rstrip("0").rstrip(".") if number % 1 else f"{number:,.0f}"

    @staticmethod
    def _single_page_date(value: Any) -> str:
        match = re.match(r"^(\d{4})[-/](\d{1,2})[-/](\d{1,2})", str(value or ""))
        return f"{int(match.group(1)):04d}-{int(match.group(2)):02d}-{int(match.group(3)):02d}" if match else ""

    @classmethod
    def _bytes_to_gb(cls, value: Any) -> float | None:
        number = cls._single_page_number(value)
        return round(number / (1024 ** 3), 1) if number is not None else None

    @staticmethod
    def _first_present(properties: dict[str, Any], keys: tuple[str, ...]) -> str:
        for key in keys:
            value = properties.get(key)
            if value is not None and str(value).strip():
                return str(value)
        return ""

    @staticmethod
    def _single_page_power_state(value: Any) -> str:
        return {"poweredOn": "运行", "poweredOff": "关机", "suspended": "挂起"}.get(str(value or ""), "")

    @staticmethod
    def _single_page_store_type(value: Any) -> str:
        label = str(value or "")
        if label.casefold() == "vsan":
            return "vSAN"
        return label

    @staticmethod
    def _single_page_license(name: Any, expiry: Any) -> str:
        parts = [str(value).strip() for value in (name, expiry) if value is not None and str(value).strip()]
        return f"{parts[0]}（{'、'.join(parts[1:])}）" if len(parts) > 1 else (parts[0] if parts else "")

    @staticmethod
    def _single_page_label(value: Any) -> str:
        text = "" if value is None else str(value)
        replacements = (
            (r"(?i)\bManagement Network\b", "管理网络"),
            (r"(?i)\bStorage Policy\b", "存储策略"),
            (r"(?i)\bObject\b", "对象"),
            (r"(?i)\bHealth\b", "健康"),
            (r"(?i)\bCapacity\b", "容量"),
            (r"(?i)\bNetwork\b", "网络"),
            (r"(?i)\bResync\b", "重同步"),
        )
        for pattern, replacement in replacements:
            text = re.sub(pattern, replacement, text)
        return text

    def _is_preserved_sqlite_file(self, path: Path) -> bool:
        name = path.name.lower()
        return name in {"inspection.db", "inspection.db-wal", "inspection.db-shm", "inspection.db-journal"}

    def _package_data(self, report: ReportData, context: dict[str, Any]) -> dict[str, Any]:
        report_dict = report.model_dump()
        rule_catalog = context.get("rule_catalog", [])
        return {
            "report_context": {
                "schema_version": "1.0",
                "report_info": report_dict["report_info"],
                "customer_info": report_dict["customer_info"],
                "environment_summary": report_dict["environment_summary"],
                "environment_info": context.get("environment_info", {}),
                "health_score": report_dict["health_score"],
                "score_breakdown": context.get("score_breakdown", report_dict["health_score"].get("breakdown", {})),
                "risk_summary": report_dict["risk_summary"],
                "risk_category_summary": context.get("risk_category_summary", report_dict.get("risk_category_summary", {})),
                "risk_object_summary": context.get("risk_object_summary", report_dict.get("risk_object_summary", {})),
                "health_impact_summary": context.get("health_impact_summary", report_dict.get("health_score", {}).get("health_impact", {})),
                "vsan_summary": context.get("vsan_summary", report_dict.get("vsan_summary", {})),
                "risk_distribution": report_dict["risk_distribution"],
                "recommendations": report_dict["recommendations"],
                "run_timing": self._run_timing(context.get("run", {})),
                "result_status_summary": context.get("result_status_summary", {}),
                "object_pass_rate": context.get("object_pass_rate", {}),
                "rule_pass_rate": context.get("rule_pass_rate", {}),
                "module_summary": context.get("module_summary", []),
                "rule_catalog_summary": context.get("rule_catalog_summary", {}),
                "risk_group_summary": context.get("risk_group_summary", []),
                "rule_checklist": context.get("rule_checklist", []),
                "exception_summary": {"total": len(context.get("exception_findings", []))},
                "remediation_tracking": context.get("remediation_tracking", {}),
                "history_comparison": context.get("history_comparison", {}),
                "appendix": {
                    "certificate_license_evidence": context.get("certificate_license_evidence", []),
                    "history_comparison": context.get("history_comparison", {}),
                },
            },
            "inspection_results": context.get("object_results", []),
            "findings": context.get("findings", report_dict["findings"]),
            "exception_findings": context.get("exception_findings", report_dict["exception_findings"]),
            "risk_group_summary": context.get("risk_group_summary", []),
            "assets": report_dict["asset_inventory"],
            "rule_catalog": rule_catalog,
            "run_comparison": context.get("remediation_tracking", {}),
        }

    def _customer_report_payload(self, report: ReportData, context: dict[str, Any]) -> dict[str, Any]:
        raw = self._package_data(report, context)
        rule_catalog = [self._customer_rule(rule) for rule in raw["rule_catalog"]]
        findings = self._customer_visible_findings([self._customer_finding(item) for item in raw["findings"]])
        risk_group_summary = self._risk_groups_from_findings(findings)
        visible_risk = {level: sum(1 for group in risk_group_summary if group.get("risk_level") == level) for level in ("P1", "P2", "P3")}
        visible_objects = {level: sum(1 for item in findings if item.get("risk_level") == level) for level in ("P1", "P2", "P3")}
        run_comparison = self._customer_comparison(raw["run_comparison"])
        report_context = dict(raw["report_context"])
        report_context["risk_group_summary"] = risk_group_summary
        report_context["risk_summary"] = {**report_context.get("risk_summary", {}), **visible_risk, "total": sum(visible_risk.values())}
        report_context["remediation_tracking"] = run_comparison
        report_context["history_comparison"] = self._customer_history_comparison(report_context.get("history_comparison", {}))
        report_context["risk_category_summary"] = visible_risk
        report_context["risk_object_summary"] = visible_objects
        report_context["health_impact_summary"] = raw["report_context"].get("health_impact_summary", {})
        report_context["vsan_summary"] = raw["report_context"].get("vsan_summary", {})
        appendix = dict(report_context.get("appendix", {}))
        appendix["certificate_license_evidence"] = [
            self._customer_check_evidence(item) for item in appendix.get("certificate_license_evidence", [])
        ]
        appendix["history_comparison"] = report_context["history_comparison"]
        report_context["appendix"] = appendix
        return {
            "report_context": report_context,
            "inspection_results": [self._customer_result(item) for item in raw["inspection_results"]],
            "findings": findings,
            "exception_findings": [self._clean_customer_item(self._customer_finding(item)) for item in raw["exception_findings"]],
            "risk_group_summary": risk_group_summary,
            "assets": self._customer_assets(raw["assets"]),
            "rule_catalog": rule_catalog,
            "run_comparison": run_comparison,
        }

    def _page_payload(self, data: dict[str, Any]) -> dict[str, Any]:
        context = data.get("report_context", {})
        appendix = context.get("appendix", {})
        environment_info = context.get("environment_info", {})
        environment_summary = context.get("environment_summary", {})
        status_summary = context.get("result_status_summary", {})
        risk_summary = context.get("risk_summary", {})
        rule_pass_rate = context.get("rule_pass_rate", {})
        return {
            "report_context": {
                "report_info": {
                    "report_title": context.get("report_info", {}).get("report_title", ""),
                    "generated_at": context.get("report_info", {}).get("generated_at", ""),
                },
                "customer_info": {
                    "customer_name": context.get("customer_info", {}).get("customer_name", ""),
                },
                "environment_info": {
                    "vcenter": environment_info.get("vcenter_address")
                    or environment_info.get("vcenter_name")
                    or context.get("customer_info", {}).get("vcenter", ""),
                    "vcenter_version": self._version_build(environment_info),
                    "collection_mode": environment_info.get("collection_mode", ""),
                    "collection_mode_label": environment_info.get("collection_mode_label", ""),
                    "data_coverage_summary": environment_info.get("data_coverage_summary", ""),
                    "security_warnings": [],
                    "connection_diagnostics": self._page_connection_diagnostics(
                        environment_info.get("connection_diagnostics", {})
                    ),
                },
                "environment_summary": {
                    "covered_object_total": environment_summary.get("checked_object_total")
                    or data.get("assets", {}).get("total", 0),
                },
                "run_timing": context.get("run_timing", {}),
                "health_score": {
                    "label": context.get("health_score", {}).get("label", "评估受限"),
                    "explanation": context.get("health_score", {}).get("explanation", ""),
                },
                "risk_summary": {
                    "P1": risk_summary.get("P1", 0),
                    "P2": risk_summary.get("P2", 0),
                    "P3": risk_summary.get("P3", 0),
                    "total": actionable_risk_total(risk_summary),
                    "optimization_total": 0,
                },
                "risk_category_summary": context.get("risk_category_summary", {}),
                "risk_object_summary": context.get("risk_object_summary", {}),
                "health_impact_summary": context.get("health_impact_summary", {}),
                "vsan_summary": context.get("vsan_summary", {}),
                "status_summary": {
                    "passed": status_summary.get("passed", 0),
                    "failed": status_summary.get("failed", 0),
                },
                "verification_coverage": {
                    "rate": rule_pass_rate.get("rate", 0),
                    "verified_items": rule_pass_rate.get("passed_checks", 0),
                    "reviewed_items": rule_pass_rate.get("actionable_checks", 0),
                },
                "module_summary": [
                    {
                        "module_name": self._page_module_name(item),
                        "coverage_total": item.get("passed", 0) + item.get("failed", 0),
                        "passed": item.get("passed", 0),
                        "failed": item.get("failed", 0),
                        "pass_rate": self._pass_rate(item.get("passed", 0), item.get("failed", 0)),
                    }
                    for item in context.get("module_summary", [])
                ],
                "remediation_tracking": self._page_comparison(data.get("run_comparison", {})),
                "history_comparison": self._page_history_comparison(context.get("history_comparison", {})),
                "appendix": {
                    "certificate_license_evidence": [
                        self._page_check_evidence(item) for item in appendix.get("certificate_license_evidence", [])
                    ],
                    "history_comparison": self._page_history_comparison(context.get("history_comparison", {})),
                },
            },
            "risk_group_summary": [
                self._page_risk_group(item)
                for item in data.get("risk_group_summary", [])
                if item.get("risk_level") in {"P1", "P2", "P3"}
            ],
            "findings": [self._page_finding(item) for item in data.get("findings", []) if item.get("risk_level") in {"P1", "P2", "P3"}],
            "certificate_license_evidence": [self._page_check_evidence(item) for item in appendix.get("certificate_license_evidence", [])],
            "assets": data.get("assets", {}),
        }

    def _page_module_name(self, item: dict[str, Any]) -> str:
        object_type = item.get("object_type", "")
        labels = {
            "vCenter": "vCenter 管理平台核验结果",
            "ClusterComputeResource": "集群核验结果",
            "HostSystem": "ESXi 主机核验结果",
            "Datastore": "数据存储核验结果",
            "VirtualMachine": "虚拟机核验结果",
        }
        if object_type in labels:
            return labels[object_type]
        name = str(item.get("module_name", ""))
        return name.replace("检查结果", "核验结果")

    def _without_customer_hidden_risk_levels(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: self._without_customer_hidden_risk_levels(nested)
                for key, nested in value.items()
                if str(key).upper() not in {"P4"} and str(key).casefold() != "p4_policy"
            }
        if isinstance(value, list):
            return [self._without_customer_hidden_risk_levels(item) for item in value]
        if isinstance(value, str):
            return self._clean_customer_text(value)
        return value

    def _page_risk_group(self, item: dict[str, Any]) -> dict[str, Any]:
        return {
            "risk_level": item.get("risk_level", ""),
            "title": self._clean_customer_text(item.get("title", "")),
            "summary": self._clean_customer_text(item.get("consequence") or item.get("business_impact") or item.get("summary", "")),
            "remediation": self._clean_customer_text(item.get("remediation", "")),
        }

    def _page_finding(self, item: dict[str, Any]) -> dict[str, Any]:
        return {
            "title": self._clean_customer_text(item.get("title", "")),
            "risk_level": item.get("risk_level", ""),
            "object_type_label": self._clean_customer_text(item.get("object_type_label", "")),
            "object_name": self._clean_customer_text(item.get("object_name", "")),
            "summary": self._clean_customer_text(item.get("consequence") or item.get("business_impact") or item.get("summary", "")),
            "remediation": self._clean_customer_text(item.get("remediation", "")),
            "evidence_summary_zh": self._page_visible_text(item.get("evidence_summary_zh", "")),
            "observed_detail_zh": self._page_visible_text(item.get("observed_detail_zh", "")),
            "expected_detail_zh": self._page_visible_text(item.get("expected_detail_zh", "")),
            "affected_components_zh": self._page_visible_text(item.get("affected_components_zh", "") or ""),
            "recommended_action_zh": self._clean_customer_text(item.get("recommended_action_zh", "")),
            "fault_detail_zh": self._page_visible_text(item.get("fault_detail_zh", "")),
            "business_source_label": self._business_source_label(item),
            "collected_at": item.get("collected_at", ""),
            "explanation_zh": self._page_visible_text(item.get("explanation_zh", "")),
        }

    def _page_check_evidence(self, item: dict[str, Any]) -> dict[str, Any]:
        return {
            "result_status": item.get("result_status", ""),
            "result_status_label": self._clean_customer_text(item.get("result_status_label", "")),
            "object_type_label": self._clean_customer_text(item.get("object_type_label", "")),
            "object_name": self._clean_customer_text(item.get("object_name", "")),
            "current_value_zh": self._clean_customer_text(item.get("current_value_zh", "")),
            "expected_value_zh": self._clean_customer_text(item.get("expected_value_zh", "")),
            "evidence_summary_zh": self._page_visible_text(item.get("evidence_summary_zh", "")),
            "category_label": self._check_category_label(item),
            "business_source_label": self._business_source_label(item),
            "collected_at": item.get("collected_at", ""),
            "explanation_zh": self._page_visible_text(item.get("explanation_zh", "")),
        }

    def _page_visible_text(self, value: Any) -> str:
        text = "" if value is None else str(value)
        if not text:
            return ""
        replacements = {
            "licenseAssignmentManager": "vCenter 授权信息",
            "host product information": "ESXi 主机产品授权信息",
        }
        for old, new in replacements.items():
            text = text.replace(old, new)
        segments = [segment.strip() for segment in re.split(r"[；;]", text) if segment.strip()]
        blocked_fragments = (
            "commonName=",
            "countryName=",
            "stateOrProvinceName=",
            "localityName=",
            "organizationName=",
            "organizationalUnitName=",
            "emailAddress=",
            "domainComponent=",
            "证书主体：",
            "证书签发者：",
            "证书指纹：",
            "授权字段探测结果：",
            "证书字段探测结果：",
            "API",
        )
        visible_segments = [segment for segment in segments if not any(fragment in segment for fragment in blocked_fragments)]
        visible = "；".join(visible_segments) if visible_segments else text
        return self._clean_customer_text(visible)

    def _customer_visible_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        base = [
            item
            for item in findings
            if str(item.get("risk_level", "")).upper() in {"P1", "P2", "P3"} and not self._is_default_vm_item(item)
        ]
        syslog_hosts = {
            self._object_key(item.get("object_name"))
            for item in base
            if self._is_remote_syslog_item(item)
        }
        visible: list[dict[str, Any]] = []
        snapshot_items: dict[str, list[dict[str, Any]]] = {}
        tools_items: dict[str, list[dict[str, Any]]] = {}

        for item in base:
            if self._is_tools_item(item):
                tools_items.setdefault(self._object_key(item.get("object_name")), []).append(item)
                continue
            if self._is_snapshot_item(item):
                snapshot_items.setdefault(self._object_key(item.get("object_name")), []).append(item)
                continue
            if self._is_log_core_dump_item(item):
                if self._object_key(item.get("object_name")) in syslog_hosts:
                    continue
                visible.append(self._normalize_syslog_item(item))
                continue
            if self._is_remote_syslog_item(item):
                visible.append(self._normalize_syslog_item(item))
                continue
            visible.append(self._normalize_alarm_item(item))

        for items in snapshot_items.values():
            visible.append(self._merged_snapshot_item(items))
        for items in tools_items.values():
            visible.append(self._merged_tools_item(items))

        return sorted((self._clean_customer_item(item) for item in visible), key=self._finding_sort_key)

    def _risk_groups_from_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        groups: dict[tuple[str, str], dict[str, Any]] = {}
        for item in findings:
            level = str(item.get("risk_level", "")).upper()
            title = self._clean_customer_text(item.get("title", ""))
            rule_id = str(item.get("rule_id") or "")
            if level not in {"P1", "P2", "P3"} or not title:
                continue
            key = (rule_id, level)
            group = groups.setdefault(
                key,
                {
                    "risk_level": level,
                    "rule_id": rule_id,
                    "title": title,
                    "object_count": 0,
                    "sample_objects": [],
                    "summary": self._clean_customer_text(
                        item.get("consequence") or item.get("business_impact") or item.get("summary", "")
                    ),
                    "remediation": self._clean_customer_text(item.get("recommended_action_zh") or item.get("remediation", "")),
                },
            )
            group["object_count"] += 1
            object_name = self._clean_customer_text(item.get("object_name", ""))
            if object_name and object_name not in group["sample_objects"]:
                group["sample_objects"].append(object_name)
        return sorted(groups.values(), key=lambda item: ({"P1": 0, "P2": 1, "P3": 2}.get(item["risk_level"], 9), item["title"]))

    def _clean_customer_item(self, item: dict[str, Any]) -> dict[str, Any]:
        cleaned = dict(item)
        for key, value in list(cleaned.items()):
            if isinstance(value, str):
                cleaned[key] = self._clean_customer_text(value)
        if self._is_red_alarm_item(cleaned):
            cleaned = self._normalize_alarm_item(cleaned)
        return cleaned

    def _clean_customer_text(self, value: Any) -> str:
        text = "" if value is None else str(value)
        if not text:
            return ""
        replacements = {
            "TSM-SSH": "SSH",
            "VM 配置资源限制 Limit": "VM 配置资源限制",
            "虚拟机配置了资源 Limit": "虚拟机配置了资源限制",
            "CPU/Memory limit": "CPU/内存资源限制",
            "CPU/Memory Limit": "CPU/内存资源限制",
            "CPU/内存 Limit": "CPU/内存资源限制",
            "CPU 和内存 Limit": "CPU 和内存资源限制",
            "CPU 或内存 Limit": "CPU 或内存资源限制",
            "CPU Limit": "CPU 资源限制",
            "CPU limit": "CPU 资源限制",
            "Memory Limit": "内存资源限制",
            "memory limit": "内存资源限制",
            "当前观察值": "当前状态",
            "期望状态": "建议状态",
            "期望值": "建议状态",
            "建议基线": "建议",
            "失败": "未通过",
            "P4级": "优化建议",
            "P4 风险": "优化建议",
            "P4": "优化建议",
        }
        for old, new in replacements.items():
            text = text.replace(old, new)
        regex_replacements = (
            (re.compile(r"(?i)\bCPU\s*/\s*Memory\s+limits?\b"), "CPU/内存资源限制"),
            (re.compile(r"(?i)\bCPU\s+limits?\b"), "CPU 资源限制"),
            (re.compile(r"(?i)\bmemory\s+limits?\b"), "内存资源限制"),
            (re.compile(r"(?i)\bresource\s+limits?\b"), "资源限制"),
            (re.compile(r"(?i)\blimits?\b"), "资源限制"),
        )
        for pattern, replacement in regex_replacements:
            text = pattern.sub(replacement, text)
        return text

    def _customer_title(self, item: dict[str, Any]) -> str:
        if self._is_snapshot_item(item):
            return "虚拟机存在快照"
        if self._is_tools_item(item):
            return "虚拟机未安装 VMware Tools"
        if self._is_remote_syslog_item(item) or self._is_log_core_dump_item(item):
            return "ESXi 主机未配置远程 Syslog"
        return self._clean_customer_text(item.get("title", ""))

    def _normalize_alarm_item(self, item: dict[str, Any]) -> dict[str, Any]:
        if not self._is_red_alarm_item(item):
            return item
        normalized = dict(item)
        detail = self._red_alarm_detail(item)
        normalized["observed_detail_zh"] = detail
        normalized["fault_detail_zh"] = detail
        normalized["evidence_summary_zh"] = detail
        normalized["expected_detail_zh"] = ""
        normalized["recommended_action_zh"] = self._clean_customer_text(
            normalized.get("recommended_action_zh") or "建议在 vCenter 中查看告警详情，确认告警对象、触发原因和处理状态。"
        )
        return normalized

    def _red_alarm_detail(self, item: dict[str, Any]) -> str:
        alarms = self._red_alarm_entries(item)
        count = len(alarms) or self._safe_int(item.get("current_value_zh")) or self._safe_int(item.get("current_value")) or 0
        if count <= 0:
            count = 1 if alarms else 0
        prefix = f"当前发现红色活动告警 {count} 条"
        if not alarms:
            return f"{prefix}，建议在 vCenter 中查看告警详情并确认处理。"
        details = []
        for alarm in alarms[:10]:
            obj = self._first_text(alarm, ("entity_name", "object_name", "entity", "target", "name"), "未采集")
            name = self._first_text(alarm, ("alarm_name", "alarm", "definition_name", "name", "description"), "未采集")
            status = self._first_text(alarm, ("status", "overall_status", "color", "severity"), "红色")
            details.append(f"告警对象：{obj}；告警名称：{name}；状态：{status}")
        return f"{prefix}：" + "；".join(details)

    def _red_alarm_entries(self, item: dict[str, Any]) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        for source in self._evidence_sources(item):
            for key in ("active_red_alarms", "red_alarms", "alarms", "alarm_details"):
                value = source.get(key) if isinstance(source, dict) else None
                if isinstance(value, list):
                    entries.extend(entry for entry in value if isinstance(entry, dict))
                elif isinstance(value, dict):
                    entries.append(value)
        return entries

    def _normalize_syslog_item(self, item: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(item)
        normalized["title"] = "ESXi 主机未配置远程 Syslog"
        normalized["summary"] = "远程 Syslog 未配置会影响故障追溯和审计证据留存。"
        normalized["business_impact"] = normalized["summary"]
        normalized["remediation"] = "建议为 ESXi 主机配置企业统一 Syslog 服务，并在配置后复查日志转发状态。"
        normalized["recommended_action_zh"] = normalized["remediation"]
        normalized["observed_detail_zh"] = "当前状态：未配置远程 Syslog"
        normalized["expected_detail_zh"] = ""
        return normalized

    def _merged_snapshot_item(self, items: list[dict[str, Any]]) -> dict[str, Any]:
        base = dict(items[0])
        base["title"] = "虚拟机存在快照"
        base["summary"] = SNAPSHOT_HTML_IMPACT
        base["business_impact"] = SNAPSHOT_HTML_IMPACT
        base["consequence"] = SNAPSHOT_HTML_IMPACT
        base["remediation"] = "建议确认快照用途和保留时间；确认无业务保留要求后，在维护窗口删除或合并快照。"
        base["recommended_action_zh"] = base["remediation"]
        base["evidence_summary_zh"] = "当前发现该虚拟机存在快照，建议结合变更窗口确认是否仍需保留。"
        base["observed_detail_zh"] = self._snapshot_observed_text(items)
        base["expected_detail_zh"] = ""
        base["fault_detail_zh"] = base["observed_detail_zh"]
        base["risk_level"] = self._risk_level_for_items(items)
        return base

    def _snapshot_observed_text(self, items: list[dict[str, Any]]) -> str:
        vm_name = self._clean_customer_text(items[0].get("object_name", "")) or "对象待确认"
        entries: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in items:
            for entry in self._snapshot_entries(item):
                signature = json.dumps(entry, ensure_ascii=False, sort_keys=True, default=str)
                if signature not in seen:
                    seen.add(signature)
                    entries.append(entry)
        parts = [f"虚拟机名称：{vm_name}"]
        has_time = False
        for entry in entries[:5]:
            fields: list[str] = []
            name = self._first_text(entry, ("name", "snapshot_name", "快照名称"), "")
            created = self._snapshot_time_label(entry)
            depth = self._first_text(entry, ("chain_depth", "snapshot_chain_depth", "depth", "快照链深度"), "")
            if name:
                fields.append(f"快照名称：{name}")
            if created != "未采集":
                fields.append(f"创建时间或存在时间：{created}")
                has_time = True
            if depth:
                fields.append(f"快照链深度：{depth}")
            if fields:
                parts.append("；".join(fields))
        if len(entries) > 5:
            parts.append(f"共有 {len(entries)} 条快照明细，此处展示前 5 条")
        if not has_time:
            ages = [age for item in items if (age := self._snapshot_age_days(item)) is not None]
            if ages:
                parts.append(f"快照最长保留时间：约 {max(ages):g} 天")
        if len(parts) == 1:
            parts.append("快照已检出，明细待补充")
        parts.append(f"影响说明：{SNAPSHOT_HTML_IMPACT}")
        return "；".join(parts)

    def _snapshot_entries(self, item: dict[str, Any]) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        evidence = item.get("evidence")
        sources = [item, *self._evidence_sources(item)]
        if isinstance(evidence, dict):
            sources.extend([evidence, *self._evidence_sources(evidence)])
        for source in sources:
            for key in ("snapshots", "snapshot_detail", "snapshot_details", "snapshot"):
                value = source.get(key)
                if isinstance(value, list):
                    entries.extend(entry for entry in value if isinstance(entry, dict))
                elif isinstance(value, dict):
                    entries.append(value)
        return entries

    def _snapshot_age_days(self, item: dict[str, Any]) -> float | None:
        """Read only evidence known to represent age; depth/size are not days."""
        evidence = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
        sources = [item, evidence, *self._evidence_sources(item), *self._evidence_sources(evidence)]
        age_keys = ("snapshot_age_days_max", "snapshot_age_days")
        values = [source[key] for source in sources for key in age_keys if key in source]
        known_age_rule = item.get("rule_id") == "VSL-VM-001" or evidence.get("rule_id") == "VSL-VM-001"
        known_age_path = any(source.get(key) in age_keys for source in sources
                             for key in ("source_path", "api_path", "current_value_path")
                             if isinstance(source.get(key), str))
        if known_age_rule or known_age_path:
            values.extend(source.get("current_value") for source in sources)
        for value in values:
            if isinstance(value, bool):
                continue
            numeric = self._safe_float(value)
            if numeric is not None and math.isfinite(numeric) and numeric >= 0:
                return numeric
        return None

    def _snapshot_time_label(self, entry: dict[str, Any]) -> str:
        for key in ("create_time", "created_at", "creation_time", "created", "time"):
            value = entry.get(key)
            if value:
                return self._clean_customer_text(value)
        for key in ("age_days", "retain_days", "retention_days", "days"):
            value = entry.get(key)
            if value not in (None, ""):
                return f"约 {value} 天"
        return "未采集"

    def _snapshot_size_label(self, entry: dict[str, Any]) -> str:
        for key in ("size_gb", "used_gb"):
            value = entry.get(key)
            if value not in (None, ""):
                numeric = self._safe_float(value)
                return self._format_size(numeric * 1024 * 1024 * 1024) if numeric is not None else self._clean_customer_text(value)
        for key in ("size_mb", "used_mb"):
            value = entry.get(key)
            if value not in (None, ""):
                numeric = self._safe_float(value)
                return self._format_size(numeric * 1024 * 1024) if numeric is not None else self._clean_customer_text(value)
        for key in ("size_bytes", "used_bytes"):
            value = entry.get(key)
            if value not in (None, ""):
                numeric = self._safe_float(value)
                return self._format_size(numeric) if numeric is not None else self._clean_customer_text(value)
        for key in ("size", "capacity", "snapshot_size"):
            value = entry.get(key)
            if value not in (None, ""):
                if isinstance(value, (int, float)):
                    return self._format_size(float(value) * 1024 * 1024)
                return self._clean_customer_text(value)
        return "未采集"

    def _merged_tools_item(self, items: list[dict[str, Any]]) -> dict[str, Any]:
        chosen = min(items, key=self._tools_priority)
        base = dict(chosen)
        base["title"] = "虚拟机未安装 VMware Tools"
        base["summary"] = TOOLS_HTML_RECOMMENDATION
        base["business_impact"] = TOOLS_HTML_RECOMMENDATION
        base["consequence"] = TOOLS_HTML_RECOMMENDATION
        base["remediation"] = TOOLS_HTML_RECOMMENDATION
        base["recommended_action_zh"] = TOOLS_HTML_RECOMMENDATION
        base["evidence_summary_zh"] = "当前发现该虚拟机 VMware Tools 状态需要安装或修复。"
        base["observed_detail_zh"] = f"虚拟机名称：{self._clean_customer_text(base.get('object_name', '')) or '未采集'}；当前状态：{self._tools_status_text(chosen)}"
        base["expected_detail_zh"] = ""
        base["fault_detail_zh"] = base["observed_detail_zh"]
        base["risk_level"] = self._risk_level_for_items(items)
        return base

    def _tools_status_text(self, item: dict[str, Any]) -> str:
        text = self._item_text(item).casefold()
        if "未安装" in text or "not installed" in text or "install state" in text:
            return "未安装"
        if "未运行" in text or "not running" in text or "notrunning" in text:
            return "未运行"
        if "版本过旧" in text or "outdated" in text or "upgrade" in text:
            return "版本过旧"
        value = self._clean_customer_text(item.get("current_value_zh") or item.get("current_value") or "")
        return value or "未采集"

    def _tools_priority(self, item: dict[str, Any]) -> int:
        text = self._item_text(item).casefold()
        if "未安装" in text or "not installed" in text or "install state" in text:
            return 0
        if "未运行" in text or "not running" in text or "notrunning" in text:
            return 1
        if "版本过旧" in text or "outdated" in text or "upgrade" in text:
            return 2
        return 3

    def _is_default_vm_item(self, item: dict[str, Any]) -> bool:
        object_type = str(item.get("object_type") or item.get("object_type_label") or "")
        return (object_type in {"VirtualMachine", "虚拟机", "VM"} or "虚拟机" in object_type or not object_type) and self._is_default_vm_name(item.get("object_name", ""))

    def _is_default_vm_name(self, value: Any) -> bool:
        text = self._clean_customer_text(value).strip()
        if not text:
            return False
        for candidate in [text, *re.split(r"[\\/]", text)]:
            name = candidate.strip().casefold()
            if name.startswith("vcls") or name.startswith("vmware vcls"):
                return True
        return False

    def _is_remote_syslog_item(self, item: dict[str, Any]) -> bool:
        text = self._item_text(item)
        return "syslog" in text.casefold() and not self._is_log_core_dump_text(text)

    def _is_log_core_dump_item(self, item: dict[str, Any]) -> bool:
        return self._is_log_core_dump_text(self._item_text(item))

    def _is_log_core_dump_text(self, text: str) -> bool:
        lowered = text.casefold()
        return any(keyword in lowered for keyword in ("core dump", "coredump")) or any(
            keyword in text for keyword in ("核心转储", "日志与核心转储", "转储配置不完整", "日志转储配置不完整", "远程转发日志")
        )

    def _is_snapshot_item(self, item: dict[str, Any]) -> bool:
        text = self._item_text(item)
        return "快照" in text or "snapshot" in text.casefold()

    def _is_tools_item(self, item: dict[str, Any]) -> bool:
        rule_id = self._clean_customer_text(item.get("rule_id", "")).upper()
        if rule_id in {"VSL-VM-002", "VSL-VM-003", "VSL-VM-014"}:
            return True
        if rule_id == "VSL-VM-024":
            return False
        text = self._item_text(item).casefold()
        if "vmware tools" not in text and "tools" not in text:
            return False
        return any(
            keyword in text
            for keyword in (
                "未安装",
                "not installed",
                "install state",
                "未运行",
                "not running",
                "notrunning",
                "版本过旧",
                "outdated",
                "upgrade",
                "tools_running",
                "tools_outdated",
                "vmware_tools_installed",
            )
        )

    def _is_red_alarm_item(self, item: dict[str, Any]) -> bool:
        text = self._item_text(item)
        lowered = text.casefold()
        return ("red" in lowered or "红色" in text) and ("alarm" in lowered or "告警" in text)

    def _evidence_sources(self, item: dict[str, Any]) -> list[dict[str, Any]]:
        sources: list[dict[str, Any]] = []
        for key in ("observed_detail", "raw_evidence"):
            value = item.get(key)
            if isinstance(value, dict):
                sources.append(value)
                nested = value.get("observed_detail")
                if isinstance(nested, dict):
                    sources.append(nested)
        return sources

    def _item_text(self, item: dict[str, Any]) -> str:
        parts: list[str] = []
        for key in (
            "rule_id",
            "rule_name",
            "title",
            "object_type",
            "object_type_label",
            "object_name",
            "summary",
            "business_impact",
            "consequence",
            "remediation",
            "current_value_zh",
            "expected_value_zh",
            "evidence_summary_zh",
            "observed_detail_zh",
            "fault_detail_zh",
            "recommended_action_zh",
        ):
            value = item.get(key)
            if value not in (None, ""):
                parts.append(str(value))
        for key in ("observed_detail", "raw_evidence"):
            value = item.get(key)
            if value:
                parts.append(json.dumps(value, ensure_ascii=False, default=str))
        return " ".join(parts)

    def _risk_level_for_items(self, items: list[dict[str, Any]], default: str = "P3") -> str:
        order = {"P1": 0, "P2": 1, "P3": 2}
        levels = [str(item.get("risk_level", "")).upper() for item in items if str(item.get("risk_level", "")).upper() in order]
        return min(levels, key=lambda level: order[level]) if levels else default

    def _finding_sort_key(self, item: dict[str, Any]) -> tuple[int, str, str]:
        return (
            {"P1": 0, "P2": 1, "P3": 2}.get(str(item.get("risk_level", "")).upper(), 9),
            self._clean_customer_text(item.get("title", "")),
            self._clean_customer_text(item.get("object_name", "")),
        )

    def _object_key(self, value: Any) -> str:
        return self._clean_customer_text(value).strip().casefold()

    def _first_text(self, values: dict[str, Any], keys: tuple[str, ...], fallback: str) -> str:
        for key in keys:
            value = values.get(key)
            if value not in (None, ""):
                return self._clean_customer_text(value)
        return fallback

    def _safe_int(self, value: Any) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    def _safe_float(self, value: Any) -> float | None:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def _format_size(self, bytes_value: float) -> str:
        if bytes_value >= 1024 * 1024 * 1024:
            return f"{bytes_value / 1024 / 1024 / 1024:.2f} GB"
        return f"{bytes_value / 1024 / 1024:.0f} MB"

    def _page_comparison(self, comparison: dict[str, Any]) -> dict[str, Any]:
        return {
            "previous_run_id": comparison.get("previous_run_id", ""),
            "current_run_id": comparison.get("current_run_id", ""),
            "previous_score": comparison.get("previous_score"),
            "current_score": comparison.get("current_score"),
            "score_delta": comparison.get("score_delta"),
            "summary": {
                "new": comparison.get("summary", {}).get("new", 0),
                "resolved": comparison.get("summary", {}).get("resolved", 0),
            },
            "new_findings": [
                self._page_comparison_item(item)
                for item in comparison.get("new_findings", [])
                if not self._is_default_vm_item(item)
            ],
            "resolved_findings": [
                self._page_comparison_item(item)
                for item in comparison.get("resolved_findings", [])
                if not self._is_default_vm_item(item)
            ],
        }

    def _page_comparison_item(self, item: dict[str, Any]) -> dict[str, Any]:
        return {
            "title": self._customer_title(item),
            "risk_level": item.get("risk_level", ""),
            "object_name": self._clean_customer_text(item.get("object_name", "")),
        }

    def _page_history_comparison(self, comparison: dict[str, Any]) -> dict[str, Any]:
        comparison = comparison or {}
        state = str(comparison.get("state") or "empty")
        baseline_run_id = str(comparison.get("baseline_run_id") or "")
        comparison_run_id = str(comparison.get("comparison_run_id") or "")
        if state != "ready" or not baseline_run_id or not comparison_run_id:
            summary_text = "暂无历史对比" if state == "ready" else comparison.get("summary_text") or "暂无历史对比"
            return {
                "state": state if state in NON_COMPARABLE_HISTORY_STATES else "single_run",
                "baseline_label": "",
                "comparison_label": comparison.get("comparison_label", ""),
                "score": self._page_delta({}),
                "risk_counts": {level: self._page_delta({}) for level in ("P1", "P2", "P3")},
                "asset_counts": {
                    key: {**self._page_delta({}), "label": key}
                    for key in ("vcenter", "cluster", "host", "datastore", "vm")
                },
                "risk_changes": {"new": [], "closed": [], "persistent": []},
                "asset_changes": {"new": [], "removed": [], "persistent": []},
                "summary_text": summary_text,
            }
        return {
            "state": state,
            "baseline_run_id": baseline_run_id,
            "comparison_run_id": comparison_run_id,
            "baseline_label": comparison.get("baseline_label", ""),
            "comparison_label": comparison.get("comparison_label", ""),
            "score": self._page_delta(comparison.get("score", {})),
            "risk_counts": {
                level: self._page_delta((comparison.get("risk_counts") or {}).get(level, {}))
                for level in ("P1", "P2", "P3")
            },
            "asset_counts": {
                key: {
                    **self._page_delta((comparison.get("asset_counts") or {}).get(key, {})),
                    "label": ((comparison.get("asset_counts") or {}).get(key, {}) or {}).get("label", key),
                }
                for key in ("vcenter", "cluster", "host", "datastore", "vm")
            },
            "risk_changes": {
                "new": [
                    self._page_history_risk_item(item)
                    for item in (comparison.get("risk_changes") or {}).get("new", [])[:10]
                    if not self._is_default_vm_item(item)
                ],
                "closed": [
                    self._page_history_risk_item(item)
                    for item in (comparison.get("risk_changes") or {}).get("closed", [])[:10]
                    if not self._is_default_vm_item(item)
                ],
                "persistent": [
                    self._page_history_risk_item(item)
                    for item in (comparison.get("risk_changes") or {}).get("persistent", [])[:10]
                    if not self._is_default_vm_item(item)
                ],
            },
            "asset_changes": {
                "new": [self._page_history_asset_item(item) for item in (comparison.get("asset_changes") or {}).get("new", [])[:10]],
                "removed": [self._page_history_asset_item(item) for item in (comparison.get("asset_changes") or {}).get("removed", [])[:10]],
                "persistent": [
                    self._page_history_asset_item(item) for item in (comparison.get("asset_changes") or {}).get("persistent", [])[:10]
                ],
            },
            "summary_text": comparison.get("summary_text", ""),
        }

    def _page_delta(self, item: dict[str, Any]) -> dict[str, Any]:
        item = item or {}
        return {
            "baseline": item.get("baseline"),
            "comparison": item.get("comparison"),
            "delta": item.get("delta"),
            "direction": item.get("direction", "same"),
        }

    def _page_history_risk_item(self, item: dict[str, Any]) -> dict[str, Any]:
        return {
            "title": self._customer_title(item),
            "risk_level": item.get("risk_level", ""),
            "object_type_label": self._clean_customer_text(item.get("object_type_label", item.get("object_type", ""))),
            "object_name": self._clean_customer_text(item.get("object_name", "")),
            "current_observed": self._clean_customer_text(item.get("current_observed", "")),
            "expected_state": self._clean_customer_text(item.get("expected_state", "")),
            "change_status_label": self._clean_customer_text(item.get("change_status_label", "")),
        }

    def _page_history_asset_item(self, item: dict[str, Any]) -> dict[str, Any]:
        return {
            "object_type_label": item.get("object_type_label", item.get("object_type", "")),
            "object_name": item.get("object_name", ""),
            "location": item.get("location", ""),
            "change_status_label": item.get("change_status_label", ""),
        }

    def _version_build(self, environment_info: dict[str, Any]) -> str:
        version = environment_info.get("vcenter_version") or ""
        build = environment_info.get("vcenter_build") or ""
        if version and build:
            return f"{version}-{build}"
        return version or build or ""

    def _page_connection_diagnostics(self, diagnostics: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(diagnostics, dict):
            return {}
        safe: dict[str, Any] = {}
        for key in ("port", "sdk"):
            value = diagnostics.get(key)
            if isinstance(value, dict):
                safe[key] = {
                    "status": value.get("status", ""),
                    "message": value.get("message", ""),
                }
        actions = diagnostics.get("suggested_actions")
        if isinstance(actions, list):
            safe["suggested_actions"] = [str(item) for item in actions if item]
        return safe

    def _pass_rate(self, passed: int, failed: int) -> float:
        total = passed + failed
        return round((passed / total) * 100, 2) if total else 100.0

    def _customer_result(self, item: dict[str, Any]) -> dict[str, Any]:
        return {
            "rule_id": item.get("rule_id", ""),
            "rule_name": item.get("rule_name", ""),
            "object_type": item.get("object_type", ""),
            "object_type_label": item.get("object_type_label", item.get("object_type", "")),
            "object_name": item.get("object_name", ""),
            "result_status": item.get("result_status", ""),
            "risk_level": item.get("risk_level", ""),
            "current_value_zh": item.get("current_value_zh", ""),
            "expected_value_zh": item.get("expected_value_zh", ""),
            "data_quality_label": item.get("data_quality_label", ""),
            "evidence_summary_zh": item.get("evidence_summary_zh", ""),
            "observed_detail_zh": item.get("observed_detail_zh", ""),
            "expected_detail_zh": item.get("expected_detail_zh", ""),
            "affected_components_zh": item.get("affected_components_zh", ""),
            "recommended_action_zh": item.get("recommended_action_zh", ""),
            "fault_detail_zh": item.get("fault_detail_zh", ""),
            "remediation": item.get("remediation", ""),
            "summary": item.get("summary", ""),
        }

    def _customer_finding(self, item: dict[str, Any]) -> dict[str, Any]:
        return {
            "snapshot_age_days_max": self._snapshot_age_days(item),
            "finding_id": item.get("finding_id", ""),
            "rule_id": item.get("rule_id", ""),
            "rule_name": item.get("rule_name", ""),
            "title": item.get("title", ""),
            "risk_level": item.get("risk_level", ""),
            "object_type": item.get("object_type", ""),
            "object_type_label": item.get("object_type_label", item.get("object_type", "")),
            "object_name": item.get("object_name", ""),
            "summary": item.get("summary", ""),
            "business_impact": item.get("business_impact", ""),
            "technical_impact": item.get("technical_impact", ""),
            "consequence": item.get("consequence", ""),
            "remediation": item.get("remediation", ""),
            "owner_label": item.get("owner_role_label", ""),
            "effort_label": item.get("remediation_effort_label", ""),
            "maintenance_window_label": item.get("maintenance_window_label", ""),
            "verification_label": item.get("verification_method_label", ""),
            "current_value_zh": item.get("current_value_zh", ""),
            "expected_value_zh": item.get("expected_value_zh", ""),
            "data_quality_label": item.get("data_quality_label", ""),
            "evidence_summary_zh": item.get("evidence_summary_zh", ""),
            "observed_detail_zh": item.get("observed_detail_zh", ""),
            "expected_detail_zh": item.get("expected_detail_zh", ""),
            "affected_components_zh": item.get("affected_components_zh", ""),
            "recommended_action_zh": item.get("recommended_action_zh", ""),
            "fault_detail_zh": item.get("fault_detail_zh", ""),
            "threshold": item.get("threshold"),
            "threshold_zh": item.get("threshold_zh", ""),
            "source_path": item.get("source_path", ""),
            "collected_at": item.get("collected_at", ""),
            "explanation": item.get("explanation", ""),
            "explanation_zh": item.get("explanation_zh", ""),
            "raw_evidence": self._safe_evidence(item.get("raw_evidence", {})),
            "observed_detail": self._safe_evidence(item.get("observed_detail", {})),
            "structured_evidence_state": self._state_label(item.get("has_structured_evidence", False)),
            "false_positive_notes": item.get("false_positive_notes", ""),
            "exception_guidance": item.get("exception_guidance", ""),
            "when_to_ignore": item.get("when_to_ignore", ""),
            "exception_reason": item.get("exception_reason", ""),
            "exception_owner": item.get("exception_owner", ""),
            "exception_expires_at": item.get("exception_expires_at", ""),
        }

    def _customer_check_evidence(self, item: dict[str, Any]) -> dict[str, Any]:
        return {
            "rule_id": item.get("rule_id", ""),
            "rule_name": item.get("rule_name", ""),
            "result_status": item.get("result_status", ""),
            "result_status_label": item.get("result_status_label", ""),
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
            "raw_evidence": self._safe_evidence(item.get("raw_evidence", {})),
            "structured_evidence_state": item.get("structured_evidence_state", "fallback"),
        }

    def _safe_evidence(self, value: Any) -> Any:
        if value is None:
            return ""
        if isinstance(value, bool):
            return "yes" if value else "no"
        if isinstance(value, (str, int, float)):
            return value
        if isinstance(value, list):
            return [self._safe_evidence(item) for item in value]
        if isinstance(value, dict):
            blocked = {
                "implementation_status",
                "execution_mode",
                "capability_required",
                "collector_version",
                "confidence_reason",
                "raw_ref",
            }
            return {str(key): self._safe_evidence(item) for key, item in value.items() if str(key) not in blocked}
        return str(value)

    def _state_label(self, value: Any) -> str:
        return "structured" if value else "fallback"

    def _customer_risk_group(self, item: dict[str, Any]) -> dict[str, Any]:
        return {
            "risk_level": item.get("risk_level", ""),
            "rule_id": item.get("rule_id", ""),
            "title": item.get("title", ""),
            "module_name": item.get("module_name", ""),
            "object_count": item.get("object_count", 0),
            "sample_objects": item.get("sample_objects", []),
            "summary": item.get("summary", ""),
            "business_impact": item.get("business_impact", ""),
            "consequence": item.get("consequence", ""),
            "remediation": item.get("remediation", ""),
            "owner_label": item.get("owner_role_label", ""),
            "maintenance_window_label": item.get("maintenance_window_label", ""),
        }

    def _customer_rule(self, item: dict[str, Any]) -> dict[str, Any]:
        return {
            "rule_id": item.get("rule_id", ""),
            "rule_name": item.get("rule_name", ""),
            "category": item.get("category", ""),
            "category_label": item.get("category_label", ""),
            "object_type_label": item.get("object_type_label", ""),
            "risk_level": item.get("risk_level", ""),
            "summary": item.get("summary", ""),
            "execution_status": item.get("execution_status", ""),
            "execution_status_label": item.get("execution_status_label", ""),
            "unexecuted_reason": item.get("unexecuted_reason", ""),
            "scoring_eligible_label": item.get("scoring_eligible_label", ""),
        }

    def _customer_unexecuted_group(self, group: dict[str, Any]) -> dict[str, Any]:
        return {
            "group_key": group.get("group_key", ""),
            "title": group.get("title", ""),
            "description": group.get("description", ""),
            "enablement": group.get("enablement", ""),
            "count": group.get("count", 0),
            "rules": [self._customer_rule(rule) for rule in group.get("rules", [])],
        }

    def _customer_assets(self, assets: dict[str, Any]) -> dict[str, Any]:
        details = {}
        for object_type, items in assets.get("details", {}).items():
            details[object_type] = [
                {
                    "object_type": item.get("object_type", object_type),
                    "object_name": item.get("object_name", ""),
                    "object_path": item.get("object_path", ""),
                    "asset_location": item.get("asset_location") or item.get("object_path", ""),
                }
                for item in items
                if not (object_type == "VirtualMachine" and self._is_default_vm_name(item.get("object_name", "")))
            ]
        return {"summary": assets.get("summary", {}), "details": details, "total": assets.get("total", 0)}

    def _customer_comparison(self, comparison: dict[str, Any]) -> dict[str, Any]:
        current_run = dict(comparison.get("current_run", {}))
        if current_run:
            current_run["run_status"] = "success"
            current_run["current_stage"] = "success"
        return {
            "previous_run_id": comparison.get("previous_run_id", ""),
            "current_run_id": comparison.get("current_run_id", ""),
            "previous_run": self._customer_run(comparison.get("previous_run", {})),
            "current_run": self._customer_run(current_run),
            "previous_score": comparison.get("previous_score"),
            "current_score": comparison.get("current_score"),
            "score_delta": comparison.get("score_delta"),
            "summary": comparison.get("summary", {}),
            "new_findings": [self._customer_comparison_item(item) for item in comparison.get("new_findings", [])],
            "existing_findings": [self._customer_comparison_item(item) for item in comparison.get("existing_findings", [])],
            "resolved_findings": [self._customer_comparison_item(item) for item in comparison.get("resolved_findings", [])],
            "reopened_findings": [self._customer_comparison_item(item) for item in comparison.get("reopened_findings", [])],
            "exception_findings": [self._customer_comparison_item(item) for item in comparison.get("exception_findings", [])],
        }

    def _customer_run(self, run: dict[str, Any]) -> dict[str, Any]:
        return {
            "run_id": run.get("run_id", ""),
            "run_status": run.get("run_status", ""),
            "current_stage": run.get("current_stage", ""),
            "score": run.get("score"),
            "created_at": run.get("created_at", ""),
            "updated_at": run.get("updated_at", ""),
            "finished_at": run.get("finished_at", ""),
        }

    def _customer_comparison_item(self, item: dict[str, Any]) -> dict[str, Any]:
        return {
            "rule_id": item.get("rule_id", ""),
            "title": item.get("title", ""),
            "risk_level": item.get("risk_level", ""),
            "object_name": item.get("object_name", ""),
            "first_seen_at": item.get("first_seen_at", ""),
            "resolved_at": item.get("resolved_at", ""),
            "occurrence_count": item.get("occurrence_count", 1),
            "exception_reason": item.get("exception_reason", ""),
            "exception_owner": item.get("exception_owner", ""),
            "exception_expires_at": item.get("exception_expires_at", ""),
            "change_status": item.get("change_status", item.get("status", "")),
        }

    def _customer_history_comparison(self, comparison: dict[str, Any]) -> dict[str, Any]:
        comparison = comparison or {}
        state = str(comparison.get("state") or "empty")
        baseline_run_id = str(comparison.get("baseline_run_id") or "")
        comparison_run_id = str(comparison.get("comparison_run_id") or "")
        if state != "ready" or not baseline_run_id or not comparison_run_id:
            summary_text = "暂无历史对比" if state == "ready" else comparison.get("summary_text") or "暂无历史对比"
            return {
                "state": state if state in NON_COMPARABLE_HISTORY_STATES else "single_run",
                "run_options": [
                    {
                        "run_id": item.get("run_id", ""),
                        "label": item.get("label", ""),
                        "timestamp": item.get("timestamp", ""),
                        "score": item.get("score"),
                        "risk_total": item.get("risk_total", 0),
                    }
                    for item in comparison.get("run_options", [])
                    if isinstance(item, dict)
                ],
                "baseline_run_id": "",
                "comparison_run_id": comparison_run_id,
                "baseline_label": "",
                "comparison_label": comparison.get("comparison_label", ""),
                "baseline_time": "",
                "comparison_time": comparison.get("comparison_time", ""),
                "score": {},
                "risk_counts": {level: {} for level in ("P1", "P2", "P3")},
                "asset_counts": {key: {} for key in ("vcenter", "cluster", "host", "datastore", "vm")},
                "risk_changes": {"new": [], "closed": [], "persistent": []},
                "asset_changes": {"new": [], "removed": [], "persistent": []},
                "summary_text": summary_text,
            }
        return {
            "state": state,
            "run_options": [
                {
                    "run_id": item.get("run_id", ""),
                    "label": item.get("label", ""),
                    "timestamp": item.get("timestamp", ""),
                    "score": item.get("score"),
                    "risk_total": item.get("risk_total", 0),
                }
                for item in comparison.get("run_options", [])
                if isinstance(item, dict)
            ],
            "baseline_run_id": comparison.get("baseline_run_id", ""),
            "comparison_run_id": comparison.get("comparison_run_id", ""),
            "baseline_label": comparison.get("baseline_label", ""),
            "comparison_label": comparison.get("comparison_label", ""),
            "baseline_time": comparison.get("baseline_time", ""),
            "comparison_time": comparison.get("comparison_time", ""),
            "score": comparison.get("score", {}),
            "risk_counts": {
                level: (comparison.get("risk_counts") or {}).get(level, {})
                for level in ("P1", "P2", "P3")
            },
            "asset_counts": {
                key: (comparison.get("asset_counts") or {}).get(key, {})
                for key in ("vcenter", "cluster", "host", "datastore", "vm")
            },
            "risk_changes": {
                "new": [self._customer_history_risk_item(item) for item in (comparison.get("risk_changes") or {}).get("new", [])],
                "closed": [self._customer_history_risk_item(item) for item in (comparison.get("risk_changes") or {}).get("closed", [])],
                "persistent": [
                    self._customer_history_risk_item(item) for item in (comparison.get("risk_changes") or {}).get("persistent", [])
                ],
            },
            "asset_changes": {
                "new": [self._customer_history_asset_item(item) for item in (comparison.get("asset_changes") or {}).get("new", [])],
                "removed": [
                    self._customer_history_asset_item(item) for item in (comparison.get("asset_changes") or {}).get("removed", [])
                ],
                "persistent": [
                    self._customer_history_asset_item(item) for item in (comparison.get("asset_changes") or {}).get("persistent", [])
                ],
            },
            "summary_text": comparison.get("summary_text", ""),
        }

    def _customer_history_risk_item(self, item: dict[str, Any]) -> dict[str, Any]:
        return {
            "title": item.get("title", ""),
            "risk_level": item.get("risk_level", ""),
            "object_type": item.get("object_type", ""),
            "object_type_label": item.get("object_type_label", item.get("object_type", "")),
            "object_name": item.get("object_name", ""),
            "current_observed": item.get("current_observed", ""),
            "expected_state": item.get("expected_state", ""),
            "change_status": item.get("change_status", ""),
            "change_status_label": item.get("change_status_label", ""),
        }

    def _customer_history_asset_item(self, item: dict[str, Any]) -> dict[str, Any]:
        return {
            "object_type": item.get("object_type", ""),
            "object_type_label": item.get("object_type_label", item.get("object_type", "")),
            "object_name": item.get("object_name", ""),
            "location": item.get("location", ""),
            "change_status": item.get("change_status", ""),
            "change_status_label": item.get("change_status_label", ""),
        }

    def _business_source_label(self, item: dict[str, Any]) -> str:
        object_type = str(item.get("object_type_label") or item.get("object_type") or "")
        text = f"{object_type} {item.get('source_path', '')} {item.get('rule_id', '')}".lower()
        if "licenseassignmentmanager" in text:
            return "vCenter 授权信息"
        if "host product information" in text:
            return "ESXi 主机产品授权信息"
        if "host" in text and ("license" in text or "023" in text):
            return "ESXi 主机授权状态"
        if "host" in text and ("certificate" in text or "008" in text):
            return "ESXi 证书信息"
        if "license" in text or "006" in text:
            return "vCenter 授权状态"
        if "certificate" in text or "005" in text:
            return "vCenter 证书信息"
        if object_type in {"Datastore", "数据存储"} or "数据存储" in object_type:
            return "数据存储运行状态"
        if object_type in {"HostSystem", "ESXi"} or "ESXi" in object_type:
            return "ESXi 主机运行状态"
        if object_type in {"VirtualMachine", "VM"} or "虚拟机" in object_type:
            return "虚拟机运行状态"
        if object_type in {"ClusterComputeResource", "Cluster"} or "集群" in object_type:
            return "集群配置状态"
        if "vcenter" in object_type.lower():
            return "vCenter 管理平台"
        return "环境采集数据"

    def _check_category_label(self, item: dict[str, Any]) -> str:
        rule_id = str(item.get("rule_id") or "")
        if rule_id == "VSL-VC-005":
            return "vCenter 证书状态"
        if rule_id == "VSL-VC-006":
            return "vCenter 授权状态"
        if rule_id == "VSL-HOST-008":
            return "ESXi 证书状态"
        if rule_id == "VSL-HOST-023":
            return "ESXi 主机授权状态"
        return "环境核验结果"

    def _run_timing(self, run: dict[str, Any]) -> dict[str, str]:
        return {
            "started_at": run.get("started_at") or run.get("created_at") or "",
            "finished_at": run.get("finished_at") or run.get("updated_at") or run.get("created_at") or "",
        }

    def _write_json(self, path: Path, payload: Any) -> None:
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def _json_for_script(self, payload: Any) -> str:
        return (
            json.dumps(payload, ensure_ascii=False)
            .replace("&", "\\u0026")
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
        )

    def _html(self, data: dict[str, Any]) -> str:
        embedded = self._json_for_script(data)
        safe_title = escape(str(data.get("title") or "VStackLens 虚拟化巡检报告"))
        return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{safe_title}</title>
  <link rel="stylesheet" href="assets/report.css">
</head>
<body>
  <div class="shell">
    <header class="report-header">
      <div class="brand"><span class="brand-mark">V</span><h1>{safe_title}</h1></div>
      <button class="print-button" type="button" onclick="window.print()">打印</button>
    </header>

    <nav class="report-nav" aria-label="报告目录">
      <a href="#summary">总结</a>
      <a href="#environment">环境</a>
      <a href="#issues">问题</a>
      <a href="#passed">已通过的检查</a>
      <a href="#inventory">环境清单</a>
    </nav>

    <main class="report-content">
      <section id="summary" class="report-section"></section>
      <section id="environment" class="report-section"></section>
      <section id="issues" class="report-section"></section>
      <section id="passed" class="report-section"></section>
      <section id="inventory" class="report-section"></section>
    </main>
  </div>
  <script id="report-data" type="application/json">{embedded}</script>
  <script src="assets/report.js"></script>
</body>
</html>
"""

    def _css(self) -> str:
        return """
:root {
  --bg: #f6f8fb;
  --panel: #ffffff;
  --ink: #111827;
  --muted: #6b7280;
  --line: #d7dde8;
  --blue: #1f4d78;
  --blue-dark: #0b2545;
  --red: #9b1c1c;
  --orange: #b45309;
  --mid: #1d4ed8;
  --gray: #475569;
  --green: #167044;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink); font-family: "Microsoft YaHei", "Segoe UI", Arial, sans-serif; }
.shell { max-width: 1440px; margin: 0 auto; padding: 24px 28px 48px; }
.topbar { display: flex; align-items: flex-end; justify-content: space-between; gap: 24px; margin-bottom: 16px; }
.eyebrow { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .06em; }
h1 { margin: 3px 0 0; font-size: 28px; color: var(--blue-dark); }
h2 { margin: 0 0 14px; font-size: 20px; color: var(--blue-dark); }
h3 { margin: 18px 0 10px; font-size: 15px; color: var(--blue); }
.top-actions { display: flex; align-items: center; gap: 10px; }
button, .top-actions a { border: 1px solid var(--line); background: #fff; color: var(--blue-dark); padding: 8px 11px; border-radius: 4px; font-size: 13px; text-decoration: none; cursor: pointer; }
button:hover, .top-actions a:hover { background: #eef4fb; }
.nav { position: sticky; top: 0; z-index: 5; display: flex; gap: 6px; flex-wrap: wrap; padding: 10px; background: rgba(246,248,251,.96); border: 1px solid var(--line); border-radius: 6px; margin-bottom: 18px; }
.nav a { color: var(--blue-dark); text-decoration: none; font-size: 13px; padding: 7px 10px; border-radius: 4px; }
.nav a:hover { background: #e8eef5; }
.nav a.active { background: #dbeafe; color: var(--blue-dark); font-weight: 700; }
.section { background: var(--panel); border: 1px solid var(--line); border-radius: 6px; padding: 18px; margin-bottom: 16px; }
.report-module { display: none; }
.report-module.active { display: block; }
#vsan { scroll-margin-top: 100px; }
.executive-panel, .tracking-summary { display: grid; grid-template-columns: 1fr 180px; gap: 18px; align-items: center; border: 1px solid var(--line); border-left: 5px solid var(--blue); background: #f8fafc; border-radius: 6px; padding: 18px; margin-bottom: 14px; }
.conclusion { margin: 6px 0 0; font-size: 18px; line-height: 1.7; color: var(--blue-dark); font-weight: 650; }
.conclusion.small { font-size: 16px; }
.priority-strip { margin-top: 12px; display: inline-flex; gap: 10px; align-items: center; border: 1px solid var(--line); background: #fff; border-radius: 999px; padding: 7px 12px; }
.priority-strip span { color: var(--muted); font-size: 12px; }
.score-dial, .score-change { justify-self: end; width: 150px; height: 150px; border-radius: 50%; border: 10px solid #dbeafe; background: #fff; display: flex; flex-direction: column; align-items: center; justify-content: center; color: var(--blue-dark); }
.score-dial[data-health="健康"] {color:#166534;border-color:#bbf7d0}
.score-dial[data-health="正常"] {color:#1d4ed8;border-color:#bfdbfe}
.score-dial[data-health="关注"] {color:#92400e;border-color:#fde68a}
.score-dial[data-health="危险"] {color:#991b1b;border-color:#fecaca}
.score-dial[data-health="评估受限"] {color:#475569;border-color:#cbd5e1}
.score-dial span, .score-change span { font-size: 38px; font-weight: 800; line-height: 1; }
.score-dial small, .score-change small { margin-top: 8px; color: var(--muted); }
.overview-columns, .tracking-columns { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; margin-top: 14px; }
.overview-columns section, .tracking-columns section { border: 1px solid var(--line); background: #fbfcfe; border-radius: 6px; padding: 12px; }
.risk-distribution, .scope-pills { display: flex; flex-wrap: wrap; gap: 8px; }
.risk-distribution span, .scope-pills span { border: 1px solid var(--line); background: #fff; border-radius: 999px; padding: 7px 11px; font-size: 13px; font-weight: 700; }
.risk-group { margin-top: 14px; }
.risk-card-list { display: grid; gap: 12px; }
.compact-list { grid-template-columns: repeat(2, minmax(0, 1fr)); }
.risk-card { border: 1px solid var(--line); background: #fff; border-radius: 6px; padding: 14px; }
.risk-card-P1 { border-left: 5px solid var(--red); }
.risk-card-P2 { border-left: 5px solid var(--orange); }
.risk-card-P3 { border-left: 5px solid var(--mid); }
.risk-card-head { display: grid; grid-template-columns: auto 1fr; gap: 10px; align-items: start; margin-bottom: 10px; }
.risk-card h3 { margin: 0 0 4px; color: var(--blue-dark); }
.subtle { color: var(--muted); font-size: 12px; }
.risk-badge { display: inline-flex; min-width: 42px; justify-content: center; border: 1px solid currentColor; border-radius: 999px; padding: 4px 8px; font-weight: 800; background: #fff; }
.risk-badge-P1 { color: var(--red); background: #fff1f2; border-color: #fecdd3; }
.risk-badge-P2 { color: var(--orange); background: #fff7ed; border-color: #fed7aa; }
.risk-badge-P3 { color: var(--mid); background: #eff6ff; border-color: #bfdbfe; }
.risk-card-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
.risk-card-grid div { background: #f8fafc; border: 1px solid var(--line); border-radius: 5px; padding: 9px; }
.risk-card-grid span { display: block; color: var(--muted); font-size: 12px; margin-bottom: 4px; }
.risk-card-grid p { margin: 0; line-height: 1.55; }
.empty-note { border: 1px dashed var(--line); background: #fbfcfe; color: var(--muted); border-radius: 6px; padding: 12px; }
.compact-kv { margin-top: 8px; }
.mode-notice { border: 1px solid #f5c86a; border-left: 5px solid #d97706; background: #fffbeb; border-radius: 6px; padding: 12px 14px; margin-top: 12px; color: #334155; }
.mode-notice p { margin: 6px 0 0; }
.mode-notice ul { margin: 8px 0 0 18px; padding: 0; }
.diagnostic-kv { background: #fff; }
.grid { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 12px; }
.overview-grid { grid-template-columns: repeat(6, minmax(0, 1fr)); }
.grid.vsan-summary-grid { grid-template-columns: repeat(6, minmax(0, 1fr)); }
.card { border: 1px solid var(--line); background: #fbfcfe; border-radius: 6px; padding: 12px; min-height: 82px; }
.card.compact { min-height: 70px; }
.label { color: var(--muted); font-size: 12px; }
.value { margin-top: 6px; font-size: 24px; font-weight: 700; color: var(--blue-dark); }
.kv { display: grid; grid-template-columns: 170px 1fr; border-top: 1px solid var(--line); }
.kv div { padding: 9px 10px; border-bottom: 1px solid var(--line); }
.kv div:nth-child(odd) { background: #f3f6fb; color: #334155; font-weight: 600; }
.tabs { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 12px; }
.tab { border: 1px solid var(--line); background: #fff; border-radius: 4px; padding: 8px 10px; cursor: pointer; }
.tab.active { background: var(--blue-dark); color: #fff; border-color: var(--blue-dark); }
.toolbar { display: flex; flex-wrap: wrap; gap: 10px; margin: 10px 0 12px; }
.toolbar input, .toolbar select { border: 1px solid var(--line); border-radius: 4px; padding: 8px 10px; min-width: 180px; }
.toolbar input { min-width: 260px; }
table { width: 100%; border-collapse: collapse; table-layout: fixed; margin: 10px 0 16px; }
th, td { border: 1px solid var(--line); padding: 10px 12px; font-size: 12.5px; line-height: 1.6; vertical-align: top; word-break: break-word; }
th { background: #e8eef5; color: var(--blue-dark); text-align: left; }
.risk-summary-table { table-layout: fixed; width: 100%; }
.risk-summary-table th, .risk-summary-table td { vertical-align: top; line-height: 1.55; padding: 10px 12px; overflow-wrap: anywhere; word-break: normal; }
.risk-summary-table th:nth-child(1), .risk-summary-table td:nth-child(1) { width: 64px; white-space: nowrap; text-align: center; }
.risk-summary-table th:nth-child(2), .risk-summary-table td:nth-child(2) { width: 22%; }
.risk-summary-table th:nth-child(3), .risk-summary-table td:nth-child(3), .risk-summary-table th:nth-child(4), .risk-summary-table td:nth-child(4) { width: 36%; }
.vsan-checks-table th:nth-child(1), .vsan-checks-table td:nth-child(1) { width: 19%; }
.vsan-checks-table th:nth-child(2), .vsan-checks-table td:nth-child(2) { width: 8%; }
.vsan-checks-table th:nth-child(3), .vsan-checks-table td:nth-child(3) { width: 15%; }
.vsan-checks-table th:nth-child(4), .vsan-checks-table td:nth-child(4) { width: 58%; }
.vsan-disk-table th:nth-child(1), .vsan-disk-table td:nth-child(1) { width: 16%; }
.vsan-disk-table th:nth-child(2), .vsan-disk-table td:nth-child(2) { width: 11%; }
.vsan-disk-table th:nth-child(3), .vsan-disk-table td:nth-child(3) { width: 12%; }
.vsan-disk-table th:nth-child(4), .vsan-disk-table td:nth-child(4) { width: 44%; }
.vsan-disk-table th:nth-child(5), .vsan-disk-table td:nth-child(5) { width: 17%; }
.vsan-vmk-table th:nth-child(1), .vsan-vmk-table td:nth-child(1) { width: 17%; }
.vsan-vmk-table th:nth-child(2), .vsan-vmk-table td:nth-child(2) { width: 8%; }
.vsan-vmk-table th:nth-child(3), .vsan-vmk-table td:nth-child(3) { width: 15%; }
.vsan-vmk-table th:nth-child(4), .vsan-vmk-table td:nth-child(4) { width: 15%; }
.vsan-vmk-table th:nth-child(5), .vsan-vmk-table td:nth-child(5) { width: 33%; }
.vsan-vmk-table th:nth-child(6), .vsan-vmk-table td:nth-child(6) { width: 12%; }
.vsan-table-scroll { min-width: 0; }
.risk-level-cell { text-align: center; }
.status-passed { color: var(--green); font-weight: 700; }
.status-failed { color: var(--red); font-weight: 700; }
.status-unavailable { color: var(--orange); font-weight: 700; }
.status-not_applicable { color: var(--gray); font-weight: 700; }
.status-error { color: var(--red); font-weight: 700; }
.risk-P1 { color: var(--red); font-weight: 700; }
.risk-P2 { color: var(--orange); font-weight: 700; }
.risk-P3 { color: var(--mid); font-weight: 700; }
.pill { display: inline-block; border: 1px solid var(--line); border-radius: 999px; padding: 2px 8px; background: #fff; font-size: 12px; }
.note { border-left: 4px solid var(--blue); background: #f8fafc; padding: 10px 12px; margin: 10px 0 12px; color: #334155; }
.section > button, .section details + button { margin-top: 12px; }
details { border: 1px solid var(--line); border-radius: 5px; margin: 8px 0; background: #fff; }
summary { cursor: pointer; padding: 10px 12px; font-weight: 700; color: var(--blue-dark); }
details .body { padding: 0 12px 12px; }
pre { white-space: pre-wrap; margin: 0; font-family: Consolas, "Microsoft YaHei", monospace; font-size: 12px; }
.evidence-kv { margin-bottom: 12px; }
.audit-kv pre { word-break: break-word; line-height: 1.5; color: #334155; }
@media (max-width: 1100px) { .grid { grid-template-columns: repeat(3, 1fr); } .grid.vsan-summary-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); } .topbar { align-items: flex-start; flex-direction: column; } .compact-list, .overview-columns, .tracking-columns { grid-template-columns: 1fr; } }
@media (max-width: 900px) { .risk-summary-table, .risk-summary-table thead, .risk-summary-table tbody, .risk-summary-table tr, .risk-summary-table th, .risk-summary-table td { display: block; width: 100% !important; } .risk-summary-table thead { display: none; } .risk-summary-table tr { border: 1px solid var(--line); border-radius: 6px; margin-bottom: 10px; background: #fff; } .risk-summary-table td { border: 0; border-bottom: 1px solid var(--line); text-align: left; } .risk-summary-table td:last-child { border-bottom: 0; } .risk-summary-table td:nth-child(1) { text-align: left; } }
@media (max-width: 720px) { .shell { padding: 16px; } .grid { grid-template-columns: repeat(2, 1fr); } .grid.vsan-summary-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } #vsan .vsan-table-scroll { max-width: 100%; overflow-x: auto; -webkit-overflow-scrolling: touch; } #vsan .vsan-checks-table { min-width: 640px; } #vsan .vsan-disk-table { min-width: 720px; } #vsan .vsan-vmk-table { min-width: 820px; } #vsan { scroll-margin-top: 120px; } .kv { grid-template-columns: 1fr; } .executive-panel, .tracking-summary { grid-template-columns: 1fr; } .score-dial, .score-change { justify-self: start; } .risk-card-grid { grid-template-columns: 1fr; } }
@media print { .nav, .top-actions, .toolbar { display: none; } body { background: #fff; } .shell { max-width: none; padding: 0; } .report-module { display: block !important; break-inside: avoid; } }
"""

    def _single_page_css(self) -> str:
        return """
:root { --ink:#172b40; --muted:#52677b; --line:#d6e0e9; --paper:#fff; --canvas:#eef2f6; --blue:#173f68; --blue-soft:#eaf2f9; --green:#177245; --green-soft:#e8f5ed; --amber:#8a5a00; --amber-soft:#fff4d6; --red:#ad3038; --red-soft:#fff0f1; }
* { box-sizing:border-box; }
html { scroll-behavior:smooth; scroll-padding-top:90px; }
body { margin:0; background:var(--canvas); color:var(--ink); font:14px/1.65 "Microsoft YaHei","PingFang SC","Noto Sans CJK SC","Segoe UI",Arial,sans-serif; }
button,a,summary { font:inherit; }
a:focus-visible,button:focus-visible,summary:focus-visible { outline:3px solid #79b5e2; outline-offset:2px; }
.shell { max-width:1480px; margin:0 auto; padding:22px 26px 48px; }
.report-header { display:flex; align-items:center; justify-content:space-between; gap:16px; padding:0 2px 16px; }
.brand { display:flex; align-items:center; gap:12px; min-width:0; }
.brand-mark { display:grid; place-items:center; width:34px; height:34px; flex:none; border-radius:8px; background:var(--blue); color:#fff; font-size:18px; font-weight:800; }
.brand h1 { margin:0; color:var(--blue); font-size:22px; line-height:1.35; }
.print-button { border:1px solid #bdcbd8; border-radius:6px; padding:7px 12px; background:#fff; color:var(--blue); cursor:pointer; }
.print-button:hover { background:var(--blue-soft); }
.report-nav { position:sticky; top:0; z-index:10; display:flex; flex-wrap:wrap; gap:6px; padding:8px; margin:0 0 18px; border:1px solid var(--line); border-radius:8px; background:rgba(248,250,252,.97); box-shadow:0 5px 15px rgba(23,43,64,.08); }
.report-nav a { display:inline-flex; align-items:center; min-height:38px; padding:7px 12px; border-radius:5px; color:var(--blue); text-decoration:none; font-weight:650; }
.report-nav a:hover,.report-nav a:focus-visible { background:var(--blue-soft); }
.report-content { display:grid; gap:18px; }
.report-section { min-width:0; padding:22px; border:1px solid var(--line); border-radius:9px; background:var(--paper); scroll-margin-top:90px; }
.report-section > h2 { margin:0 0 18px; color:var(--blue); font-size:23px; line-height:1.35; }
.report-section h3 { margin:20px 0 9px; color:var(--blue); font-size:17px; }
.report-section h4 { margin:18px 0 8px; color:#28445f; font-size:15px; }
.report-section h5 { margin:15px 0 7px; color:#28445f; font-size:14px; }
.summary-panel { padding:18px 20px; border:1px solid #cedbe7; border-radius:8px; background:#f8fafc; }
.inspection-time { margin:0 0 10px; color:var(--muted); }
.judgement { margin:0; font-size:19px; font-weight:750; }
.judgement.normal { color:var(--green); }
.judgement.attention { color:var(--amber); }
.summary-vcenter { margin-top:6px; }
.summary-vsan { margin:16px 0 0; padding-top:12px; border-top:1px solid #e3eaf0; }
.certificate-block { margin:16px 0 22px; padding-top:13px; border-top:1px solid var(--line); }
.certificate-block > h3 { margin-top:0; }
.certificate-conclusion,.certificate-license { margin:8px 0; }
.certificate-alert,.certificate-alert-text { color:var(--red); font-weight:700; }
.certificate-details { margin:8px 0; }
.certificate-table { table-layout:fixed; }
.certificate-table th:nth-child(1),.certificate-table td:nth-child(1) { width:42%; }
.certificate-table th:nth-child(2),.certificate-table td:nth-child(2) { width:27%; }
.certificate-table th:nth-child(3),.certificate-table td:nth-child(3) { width:31%; }
.prior-comparison { margin:12px 0 0; padding-top:10px; border-top:1px solid #e3eaf0; }
.summary-issues { display:grid; gap:4px; margin:15px 0 0; padding:0; list-style:none; }
.summary-issues li { display:grid; grid-template-columns:30px minmax(0,1fr); gap:8px; padding:7px 0; border-top:1px solid #e3eaf0; }
.plain-line { margin:10px 0; }
.cluster-block { margin-top:22px; padding-top:16px; border-top:1px solid var(--line); }
.cluster-block > h3 { display:flex; align-items:baseline; justify-content:space-between; gap:12px; margin-top:0; }
.cluster-facts { margin-top:8px; }
.vsan-details { margin-top:17px; padding-top:13px; border-top:1px solid #dbe5ec; }
.vsan-usage { max-width:900px; }
.usage-track { display:flex; width:100%; height:14px; overflow:hidden; border:1px solid #cad5df; border-radius:999px; background:#eef2f6; }
.usage-track .used { display:block; height:100%; min-width:0; }
.usage-track .free { display:block; height:100%; flex:1; background:#dfe6ed; }
.usage-track.storage.low .used { background:#248453; }
.usage-track.storage.mid .used { background:#d49a18; }
.usage-track.storage.high .used { background:#c43c42; }
.usage-track.vsan-usage-bar.low .used { background:#248453; }
.usage-track.vsan-usage-bar.mid .used { background:#d49a18; }
.usage-track.vsan-usage-bar.high .used { background:#c43c42; }
.usage-values { margin-top:5px; color:#344c63; font-size:13px; }
.threshold-note { margin:7px 0 0; color:var(--muted); font-size:12px; }
.usage-cell { min-width:120px; }
.usage-cell .usage-track { height:10px; }
.usage-cell > span { display:block; margin-top:3px; font-variant-numeric:tabular-nums; }
.table-scroll { max-width:100%; overflow-x:auto; -webkit-overflow-scrolling:touch; }
table { width:100%; border-collapse:collapse; margin:8px 0 15px; table-layout:auto; }
th,td { padding:8px 10px; border:1px solid var(--line); text-align:left; vertical-align:top; overflow-wrap:anywhere; }
th { background:#eaf0f5; color:#203e5b; font-weight:700; }
tbody tr:nth-child(even) { background:#f8fafc; }
.environment-scale,.cluster-facts { table-layout:fixed; }
.environment-scale th,.environment-scale td { width:25%; text-align:center; }
.cluster-facts th { white-space:nowrap; }
.cluster-facts th:nth-child(1),.cluster-facts td:nth-child(1) { width:22%; }
.cluster-facts th:nth-child(2),.cluster-facts td:nth-child(2) { width:22%; }
.cluster-facts th:nth-child(3),.cluster-facts td:nth-child(3) { width:12%; text-align:center; }
.cluster-facts th:nth-child(4),.cluster-facts td:nth-child(4),.cluster-facts th:nth-child(5),.cluster-facts td:nth-child(5) { width:22%; }
.problem-summary { table-layout:fixed; }
.problem-summary th:nth-child(1),.problem-summary td:nth-child(1) { width:7%; white-space:nowrap; }
.problem-summary th:nth-child(2),.problem-summary td:nth-child(2) { width:18%; }
.problem-summary th:nth-child(3),.problem-summary td:nth-child(3) { width:7%; text-align:center; }
.problem-summary th:nth-child(4),.problem-summary td:nth-child(4) { width:13%; }
.problem-summary th:nth-child(5),.problem-summary td:nth-child(5),.problem-summary th:nth-child(6),.problem-summary td:nth-child(6) { width:27.5%; }
.problem-summary .problem-risk-P1 { color:var(--red); font-weight:700; }
.problem-summary .problem-risk-P2 { color:var(--amber); font-weight:700; }
.problem-summary .problem-risk-P3 { color:var(--blue); font-weight:700; }
.problem-level { margin:14px 0; }
.problem-level > summary { font-size:16px; }
.problem-level-P1 > summary { color:var(--red); }
.problem-level-P2 > summary { color:var(--amber); }
.problem-level-P3 > summary { color:var(--blue); }
.problem-item { margin:8px 12px; }
.problem-item > summary { padding:9px 12px; }
.problem-block { padding:12px 10px 16px; border-left:4px solid var(--line); border-bottom:1px solid var(--line); }
.problem-item > .problem-block { margin:0 12px 12px; }
.problem-block-P1 { border-left-color:var(--red); }
.problem-block-P2 { border-left-color:var(--amber); }
.problem-block-P3 { border-left-color:var(--blue); }
.problem-block h4 { margin-top:0; }
.problem-block p { margin:8px 0; }
.field-block { margin:9px 0; }
.field-block > strong { display:block; margin-bottom:5px; }
details { margin:9px 0; border:1px solid var(--line); border-radius:7px; background:#fff; }
summary { padding:10px 12px; color:var(--blue); font-weight:700; cursor:pointer; }
details > .table-scroll { padding:0 10px 6px; }
.compact-table { max-width:560px; }
@media (max-width:900px) { .shell { padding:16px; } .report-section { padding:17px; } .brand h1 { font-size:19px; } }
@media (max-width:600px) { .shell { padding:10px; } .report-header { align-items:flex-start; } .brand h1 { font-size:17px; } .report-nav { gap:3px; padding:5px; } .report-nav a { min-height:34px; padding:6px 8px; font-size:13px; } .report-section { padding:14px 12px; } .report-section > h2 { font-size:20px; } table { min-width:640px; } .problem-summary { min-width:920px; } .cluster-facts { min-width:720px; } .environment-scale { min-width:640px; } .certificate-table { min-width:640px; } }
@media print { body { background:#fff; } .shell { max-width:none; padding:0; } .report-header { padding:0 0 12px; } .report-nav,.print-button { display:none!important; } .report-content { display:block; } .report-section { margin:0 0 12px; padding:12px; border:0; border-radius:0; break-inside:auto; } .cluster-block,.problem-block,tr { break-inside:avoid; page-break-inside:avoid; } .table-scroll { overflow:visible; } details,details:not([open]) > :not(summary) { display:block!important; } details > summary { display:block!important; } a { color:inherit; text-decoration:none; } }
"""

    def _js(self) -> str:
        return REPORT_JS
