from __future__ import annotations

from vstacklens.reports.license_evidence import license_summary

import json
import hashlib
import math
import re
import os
import shutil
import subprocess
import tempfile
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

from vstacklens.reports.report_model import ReportData
from vstacklens.reports.customer_format import (
    CAPACITY_NOTE, capacity_bytes_text, capacity_text, capacity_unit, decimal_text, local_time_text, percent_text,
)
from vstacklens.reports.narrative import build_pdf_narratives
from vstacklens.reports.presentation import append_report_sentence, count_excluded_powered_off_vms, powered_off_exclusion_note, customer_judgment_metadata
from vstacklens.resources import package_resource_path, project_resource_path


class PdfReportEngine:
    """Render the customer PDF from the same report model and HTML issue payload."""

    def render(
        self,
        report: ReportData,
        output_path: Path,
        *,
        report_context: dict[str, Any] | None = None,
        secrets: tuple[str, ...] = (),
    ) -> Path:
        if not report.product_modules:
            from vstacklens.reports.document_pdf import render_document_pdf
            return render_document_pdf(self, report, output_path, context=report_context, secrets=secrets)
        from vstacklens.products.reporting import ensure_report_has_valid_data
        from vstacklens.reports.product_evidence import staged_product_file
        ensure_report_has_valid_data(report)
        output_path = Path(output_path)
        if output_path.exists():
            raise FileExistsError("拒绝覆盖已有 PDF 报告，请选择新的输出文件。")
        self._compilation_parent(output_path, self._typst_binary())
        with staged_product_file(report, output_path, secrets=secrets, overwrite=False) as stage:
            self._render(report, stage, report_context=report_context, secrets=secrets)
        return output_path

    def _render(
        self,
        report: ReportData,
        output_path: Path,
        *,
        report_context: dict[str, Any] | None = None,
        secrets: tuple[str, ...] = (),
    ) -> Path:
        from vstacklens.products.reporting import ensure_report_has_valid_data
        ensure_report_has_valid_data(report)
        output_path = Path(output_path)
        if output_path.exists():
            raise FileExistsError(f"拒绝覆盖已有 PDF 报告：{output_path}")
        template = package_resource_path("reports", "templates", "inspection-report.typ")
        if not template.is_file():
            raise RuntimeError(f"PDF 模板不存在：{template}")
        typst = self._typst_binary()
        payload = self._build_payload(report, report_context or {})
        work_parent = self._compilation_parent(output_path, typst)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # CreateProcess cwd and native compiler file APIs have different path
        # limits from Python file operations. Never compile below a deep export
        # destination; the caller's final report path is preserved unchanged.
        with tempfile.TemporaryDirectory(prefix="vsl-pdf-", dir=work_parent) as temporary_dir:
            root = Path(temporary_dir)
            staged_template = root / "inspection-report.typ"
            staged_pdf = root / "inspection-report.pdf"
            shutil.copy2(template, staged_template)
            (root / "scope_level_donut.svg").write_text(
                self._scope_level_donut_svg(payload["scope"]),
                encoding="utf-8",
            )
            for index, assessment in enumerate(payload.get("legacy_reports") or []):
                chart_name = f"scope-level-donut-{index}.svg"
                (root / chart_name).write_text(self._scope_level_donut_svg(assessment["scope"]), encoding="utf-8")
                assessment["scope_donut_file"] = chart_name
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
            self._publish_pdf(staged_pdf, output_path, secrets=secrets)
        return output_path

    @staticmethod
    def _compilation_parent(output_path: Path, typst: Path) -> Path:
        work_parent = Path(tempfile.gettempdir()).absolute()
        if os.name == "nt":
            units = lambda value: len(str(value).encode("utf-16-le")) // 2
            absolute_output = output_path.absolute()
            if any(units(part) > 255 for part in absolute_output.parts):
                raise ValueError("PDF 输出目录或文件名单段过长，尚未开始编译；请改用较短的目录和文件名。")
            # Reserve room for the random work directory and the longest fixed
            # staging filename. This preflight rejects an unsafe TEMP before a
            # native process starts, rather than failing late with WinError 267.
            longest_staged = "scope-level-donut-999999.svg"
            if units(work_parent) + 1 + len("vsl-pdf-") + 16 + 1 + len(longest_staged) >= 260:
                raise ValueError("PDF 临时目录过长，尚未开始编译；请将 TEMP／TMP 指向较短的本机目录后重试。")
            if units(typst.absolute()) >= 260:
                raise ValueError("PDF 编译器路径过长，尚未开始编译；请使用较短目录中的已登记离线运行时。")
        return work_parent

    @staticmethod
    def _publish_pdf(staged_pdf: Path, output_path: Path, *, secrets=()) -> None:
        from vstacklens.application.artifact_safety import ensure_artifacts_safe
        # The compiler scratch directory may be on another volume. Copy into a
        # private destination-volume stage, then scan the exact bytes that will
        # publish. A native rename on Windows refuses an existing destination.
        with tempfile.TemporaryDirectory(prefix=".vsl-pdf-publish-", dir=output_path.parent) as temporary:
            candidate = Path(temporary) / "report.pdf"
            shutil.copyfile(staged_pdf, candidate)
            ensure_artifacts_safe([candidate], secrets=secrets)
            if output_path.exists():
                raise FileExistsError(f"PDF 目标在生成期间已出现，未覆盖：{output_path}")
            if os.name == "nt":
                candidate.rename(output_path)
            else:
                # POSIX rename replaces a competing file; link publishes
                # atomically with no overwrite and the stage is then removed.
                os.link(candidate, output_path)

    def _scope_level_donut_svg(self, scope: dict[str, Any]) -> str:
        size = 220
        center = size / 2
        radius = 73
        stroke_width = 38
        circumference = 2 * math.pi * radius
        total = int(scope.get("problem_checks") or 0)
        all_passed = bool(scope.get("all_passed"))
        track_color = "#E4F0E9" if all_passed else "#F0F3F6"
        circles = [
            f'<circle cx="{center}" cy="{center}" r="{radius}" fill="none" '
            f'stroke="{track_color}" stroke-width="{stroke_width}"/>'
        ]
        if total == 0:
            empty_color = "#398260" if all_passed else "#607387"
            circles.append(
                f'<circle cx="{center}" cy="{center}" r="{radius}" fill="none" '
                f'stroke="{empty_color}" stroke-width="{stroke_width}"/>'
            )
            center_label = ("全部", "通过") if all_passed else (("无未通过", "仍有限制") if scope.get("total_checks") else ("无检查", "结果"))
            center_text = (
                f'<text x="110" y="103" text-anchor="middle" font-family="Microsoft YaHei, sans-serif" '
                f'font-size="19" font-weight="700" fill="{empty_color}">{center_label[0]}</text>'
                f'<text x="110" y="128" text-anchor="middle" font-family="Microsoft YaHei, sans-serif" '
                f'font-size="19" font-weight="700" fill="{empty_color}">{center_label[1]}</text>'
            )
        else:
            colors = {"P1": "#B84545", "P2": "#B98220", "P3": "#2F72B7"}
            offset = 0.0
            for row in scope.get("level_distribution") or []:
                level = str(row.get("level") or "")
                count = int(row.get("count") or 0)
                if count <= 0 or level not in colors:
                    continue
                # The registered Typst SVG->PDF path drops dashed-circle
                # clipping. Explicit arc geometry retains every nonzero share.
                if count == total:
                    circles.append(f'<circle cx="{center}" cy="{center}" r="{radius}" fill="none" stroke="{colors[level]}" stroke-width="{stroke_width}"/>')
                else:
                    start = -math.pi / 2 + offset
                    angle = 2 * math.pi * count / total
                    end = start + angle
                    x1, y1 = center + radius * math.cos(start), center + radius * math.sin(start)
                    x2, y2 = center + radius * math.cos(end), center + radius * math.sin(end)
                    circles.append(f'<path d="M {x1:.6f} {y1:.6f} A {radius} {radius} 0 {int(count * 2 > total)} 1 {x2:.6f} {y2:.6f}" fill="none" stroke="{colors[level]}" stroke-width="{stroke_width}"/>')
                offset += 2 * math.pi * count / total
            center_text = (
                f'<text x="110" y="105" text-anchor="middle" font-family="Microsoft YaHei, sans-serif" '
                f'font-size="31" font-weight="700" fill="#163B63">{total}</text>'
                '<text x="110" y="130" text-anchor="middle" font-family="Microsoft YaHei, sans-serif" '
                'font-size="19" fill="#607387">条</text>'
            )
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" '
            f'viewBox="0 0 {size} {size}">' + "".join(circles) + center_text + "</svg>"
        )

    def _typst_binary(self) -> Path:
        manifest = json.loads(package_resource_path("tools", "typst-runtime.json").read_text(encoding="utf-8"))
        configured = os.environ.get("VSTACKLENS_TYPST_BIN", "").strip()
        candidates = [
            Path(configured) if configured else None,
            package_resource_path("tools", "typst.exe"),
            project_resource_path(".tools", "typst", "typst.exe"),
            Path(__file__).resolve().parents[3] / ".tools" / "typst" / "typst.exe",
        ]
        for candidate in candidates:
            if candidate is not None and candidate.is_file():
                if hashlib.sha256(candidate.read_bytes()).hexdigest() != manifest["files"]["typst.exe"]:
                    raise RuntimeError("Typst 编译器与已登记版本不符；请使用 packaging/stage_typst_runtime.ps1 校验并准备登记的离线运行时。")
                return candidate
        raise RuntimeError("未找到登记的 Typst 编译器；请使用 packaging/stage_typst_runtime.ps1 准备离线运行时。")

    def _build_payload(self, report: ReportData, report_context: dict[str, Any], *, _allow_connection_diagnostic: bool = False) -> dict[str, Any]:
        from vstacklens.reports.customer_view import customer_labels
        from vstacklens.products.reporting import legacy_assessment_reports, has_legacy_sections
        assessments = legacy_assessment_reports(report)
        if len(assessments) > 1:
            view = self._pdf_product_view(report)
            legacy_payloads = []
            for metadata, original in assessments:
                payload = self._build_payload(original, {})
                payload["vcenter_target_name"] = metadata["target_name"]
                payload["vcenter_target_id"] = metadata["target_id"]
                legacy_payloads.append(payload)
            return {"wording": customer_labels(), "has_vcenter": True, "legacy_reports": legacy_payloads, "product_report": view,
                    "customer_name": view["customer"], "report_date": view["generated_at"][:10],
                    "capture_date": view["generated_at"][:10], "scope": {}}
        if report.product_modules and not has_legacy_sections(report):
            view = self._pdf_product_view(report)
            return {"wording": customer_labels(), "has_vcenter": False, "product_report": view, "customer_name": view["customer"],
                    "report_date": view["generated_at"][:10], "capture_date": view["generated_at"][:10],
                    "scope": {}}
        from vstacklens.reports.customer_view import get_customer_problem_view, customer_display_facts
        shared_problems = get_customer_problem_view(report, report_context)
        display_facts = customer_display_facts(report)
        caliber = shared_problems.caliber
        inventory = report.asset_inventory or {}
        details = inventory.get("details") or {}
        vcenter_row = self._first_record(details, "vCenter")
        if self._properties(vcenter_row).get("connected") is False and not _allow_connection_diagnostic:
            raise RuntimeError("vCenter 连接未成功，不生成基于空数据的客户 PDF。")
        clusters_raw = self._records(details, "ClusterComputeResource")
        hosts_raw = self._records(details, "HostSystem")
        vms_raw = self._records(details, "VirtualMachine")
        powered_off_note = powered_off_exclusion_note(count_excluded_powered_off_vms(vms_raw))
        hosts_by_name = {str(item.get("object_name") or ""): self._properties(item) for item in hosts_raw}
        vms_by_name = {str(item.get("object_name") or ""): self._properties(item) for item in vms_raw}
        from vstacklens.reports.customer_view import customer_vsan_summary
        vsan = customer_vsan_summary(report)
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
        snapshot_records: list[dict[str, Any]] = []
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
            has_snapshot = self._has_snapshot(props)
            vm_entry = {
                "name": name,
                "host": str(vm.get("hostName") or "未记录"),
                "cluster": cluster_name,
                "state": state,
                "has_snapshot": has_snapshot,
                "snapshot_age_days_max": self._number(props.get("snapshot_age_days_max")),
                "snapshot_chain_depth": self._number(props.get("snapshot_chain_depth")),
            }
            if has_snapshot:
                snapshot_records.append({
                    "name": name,
                    "cluster": cluster_name,
                    "age_days": vm_entry["snapshot_age_days_max"],
                    "chain_depth": vm_entry["snapshot_chain_depth"],
                })
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
            if state == "powered_on" and not props.get("is_system_vm") and cpu is not None:
                top_cpu.append({"name": name, "host": vm_entry["host"], "value": cpu, "display": f"{cpu / 1000:,.2f} GHz"})
            if state == "powered_on" and not props.get("is_system_vm") and memory_mb is not None:
                memory_gb = memory_mb / 1024
                top_memory.append({"name": name, "host": vm_entry["host"], "value": memory_mb, "display": capacity_text(memory_gb)})
            disk_gb = self._number(vm.get("diskGb"))
            if has_host:
                accumulate_host_usage("capacity", host_key, disk_gb)
            if disk_gb is not None:
                top_capacity.append({"name": name, "host": vm_entry["host"], "value": disk_gb, "display": capacity_text(disk_gb)})
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
        snapshot_distribution = [
            {"cluster": name, "count": sum(bool(item["has_snapshot"]) for item in items)}
            for name, items in cluster_vms.items()
            if sum(bool(item["has_snapshot"]) for item in items) > 0
        ]
        snapshot_distribution.sort(key=lambda item: (-item["count"], item["cluster"].casefold()))
        max_snapshot_cluster_count = max((item["count"] for item in snapshot_distribution), default=1)
        for item in snapshot_distribution:
            item["bar_pct"] = round(item["count"] * 100 / max_snapshot_cluster_count, 1)
        known_snapshot_ages = [item["age_days"] for item in snapshot_records if item["age_days"] is not None]
        oldest_snapshots = sorted(
            (item for item in snapshot_records if item["age_days"] is not None),
            key=lambda item: (-item["age_days"], item["name"].casefold()),
        )[:5]
        for item in oldest_snapshots:
            item["age_text"] = self._days_text(item["age_days"])
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
                # Keep the existing internal scope metadata stable; customer
                # wording is supplied by the common presentation facts.
                item["host_share_scope"] = share_scope
                item["display_share_scope"] = display_facts["top_labels"][resource_key]
                item["host_share_text"] = percent_text(item["value"] * 100 / denominator
                                                       if denominator is not None and denominator > 0 else None)
                item["host_share_pct"] = (
                    round(item["value"] * 100 / denominator, 1)
                    if denominator is not None and denominator > 0
                    else None
                )
        for rows in (top_cpu, top_memory, top_capacity):
            maximum = max((item["value"] for item in rows), default=0)
            for item in rows:
                item["bar_pct"] = round(item["value"] * 100 / maximum, 1) if maximum > 0 else 0
        for rows in (top_cpu[:5], top_memory[:5], top_capacity[:5], top_vcpu[:5]):
            for rank, item in enumerate(rows, start=1):
                item["rank"] = rank
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
        known_host_memory = [item for item in hosts if item["memory_pct"] is not None]
        highest_host_memory = max(known_host_memory, key=lambda item: item["memory_pct"], default=None)

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

        datastore_capacity_unit = capacity_unit([item.get(key) for item in datastore_records
                                                 for key in ("usedGb", "freeGb", "totalGb")])
        datastores = []
        for item in datastore_records:
            usage = self._number(item.get("usagePct"))
            datastores.append({
                "name": str(item.get("name") or "未命名数据存储"),
                "type": "vSAN" if str(item.get("type") or "").casefold() == "vsan" else self._safe_customer_text(item.get("type")),
                "clusters": list(item.get("clusters") or []),
                "usage": usage,
                "usage_text": self._percent_text(usage),
                "used_text": capacity_text(item.get("usedGb"), unit=datastore_capacity_unit),
                "free_text": capacity_text(item.get("freeGb"), unit=datastore_capacity_unit),
                "total_text": capacity_text(item.get("totalGb"), unit=datastore_capacity_unit),
            })
        datastores.sort(key=lambda item: (item["usage"] is None, -(item["usage"] or 0), item["name"].casefold()))
        usage_known_stores = [
            item for item in datastores
            if item.get("usage") is not None
        ]
        top_ten_stores = usage_known_stores[:10]
        selected_store_names = {
            item["name"] for item in top_ten_stores
        } | {
            item["name"] for item in usage_known_stores if item["usage"] >= 75
        }
        datastore_display = [item for item in usage_known_stores if item["name"] in selected_store_names]
        datastore_omitted = [item for item in datastores if item["name"] not in selected_store_names]
        datastore_omitted_max_usage = max(
            (item["usage"] for item in datastore_omitted if item.get("usage") is not None),
            default=None,
        )
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
        healthy_tokens = {"normal", "healthy", "green", "ok", "passed", "正常"}
        unhealthy_tokens = {"red", "yellow", "warning", "error", "failed", "degraded", "offline", "absent", "unhealthy", "异常", "故障"}
        known_disk_states = [
            str(item.get("health") or "").strip().casefold()
            for item in vdisk_details
            if str(item.get("health") or "").strip().casefold() in healthy_tokens | unhealthy_tokens
        ]
        all_disk_states_known = bool(vdisk_details) and len(known_disk_states) == len(vdisk_details)
        disk_healthy = sum(state in healthy_tokens for state in known_disk_states) if all_disk_states_known else None
        resync_objects = self._number(vsan.get("resync_object_count"))
        resync_bytes = self._number(vsan.get("resync_bytes"))
        no_resync = resync_objects == 0 and resync_bytes == 0
        has_vsan = str(vsan.get("status") or "") != "not_applicable" and bool(vsan.get("clusters") or vsan.get("disk_details") or vsan.get("capacity", {}).get("total_gb"))
        disk_rows = [{
            "host": str(item.get("host") or ""), "group": str(item.get("disk_group") or ""),
            "role": str(item.get("role") or ""), "device": str(item.get("device") or ""),
            "health": self._disk_health_label(str(item.get("health") or "")),
            "disk_count": 1, "normal_summary": False,
        } for item in vdisk_details]
        disk_rows.sort(key=lambda item: (item["host"].casefold(),item["group"].casefold(),item["role"].casefold(),item["device"].casefold()))
        cluster_views = []
        cluster_details = []
        vm_summary_by_cluster = {str(item.get("cluster") or ""): item for item in cluster_vm_summary}
        hosts_by_cluster: dict[str, list[dict[str, Any]]] = {}
        for host in hosts:
            hosts_by_cluster.setdefault(host["cluster"], []).append(host)
        for cluster in clusters:
            name = str(cluster.get("name") or "未命名集群")
            props = cluster_props.get(name, {})
            cluster_matches = [item for item in display_facts["clusters"]
                               if str(item.get("object_key") or "") == str(cluster.get("object_key") or "")
                               and item.get("object_key")]
            if not cluster_matches:
                cluster_matches = [item for item in display_facts["clusters"] if item.get("name") == name]
            cluster_display = cluster_matches[0] if len(cluster_matches) == 1 else {}
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
                "ha": "已启用" if props.get("ha_enabled") is True else "未启用" if props.get("ha_enabled") is False else "",
                "drs": "已启用" if props.get("drs_enabled") is True else "未启用" if props.get("drs_enabled") is False else "",
            })
            heartbeat_count = self._number(props.get("ha_heartbeat_datastore_count"))
            heartbeat_names = self._safe_list_text(props.get("heartbeat_datastore_names"))
            heartbeat_summary = "" if heartbeat_count is None else f"{int(heartbeat_count)} 个" + (f"：{heartbeat_names}" if heartbeat_names else "")
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
                "admission_control": cluster_display.get("admission_control", ""),
                "heartbeat_count": heartbeat_count,
                "heartbeat_names": heartbeat_names,
                "heartbeat_summary": cluster_display.get("heartbeat_summary", ""),
                "isolation_response": self._safe_customer_text(props.get("ha_isolation_response")),
                "drs_enabled": props.get("drs_enabled"),
                "drs_behavior": cluster_display.get("drs_behavior", ""),
                "drs_disabled_rule_count": self._number(props.get("drs_disabled_rule_count")),
                "drs_disabled_rules": self._safe_list_text(props.get("drs_disabled_rules")),
                "evc_enabled": self._bool_label(props.get("evc_enabled")),
                "evc_mode": self._safe_customer_text(props.get("evc_mode")),
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
            else vcenter_expiry or ""
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
            if not expiry_date and days is None:
                continue
            expiry = f"{expiry_date}（剩余 {int(days)} 天）" if expiry_date and days is not None else expiry_date
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
        licenses = [
            f"{self._text(item.get('object_name'))} [{self._text(item.get('object_key'))}]："
            + license_summary(self._properties(item), True, str(item.get("object_key") or ""))
            for item in hosts_raw
        ]
        for item in self._records(details, "vCenter"):
            licenses.append(
                f"vCenter {self._text(item.get('object_name'))} [{self._text(item.get('object_key'))}]："
                + license_summary(self._properties(item), False, str(item.get("object_key") or ""))
            )

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
                "power_policy": self._power_policy_label(props.get("host_power_policy")),
                "power_policy_high_performance": props.get("host_power_policy_high_performance"),
                "pnic_down_count": self._number(props.get("pnic_down_count")),
                "pnic_degraded_count": self._number(props.get("pnic_degraded_count")),
                "pnic_error_count": self._number(props.get("pnic_error_count")),
                "pnic_rows": pnic_rows,
                "vmkernel_adapters": vmk_rows,
                "ssh": self._bool_label(props.get("ssh_running")),
                "esxi_shell": self._bool_label(props.get("esxi_shell_running")),
                "lockdown": self._lockdown_label(props.get("lockdown_mode")),
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
        hardware_issue_column = bool(host_details) and all(item.get("hardware_issue_count") is not None for item in host_details)
        power_policy_column = bool(host_details) and all(bool(item.get("power_policy")) for item in host_details)
        for host in host_details:
            props = hosts_by_name.get(host["name"], {})
            security_parts = []
            if props.get("ssh_running") is True or props.get("ssh_running") is False:
                security_parts.append("远程 SSH " + ("已启用" if props["ssh_running"] else "未启用"))
            if props.get("esxi_shell_running") is True or props.get("esxi_shell_running") is False:
                security_parts.append("本地 Shell " + ("已启用" if props["esxi_shell_running"] else "未启用"))
            ntp_count = self._number(props.get("ntp_server_count"))
            if ntp_count is not None:
                security_parts.append(f"时间同步服务器 {int(ntp_count)} 个")
            firewall_state = self._bool_label(props.get("firewall_default_incoming_blocked"))
            if firewall_state:
                security_parts.append("默认入站防火墙规则 " + ("已阻止" if firewall_state == "是" else "未阻止"))
            if host.get("lockdown"):
                security_parts.append("锁定模式 " + host["lockdown"])
            host["security_summary"] = "；".join(security_parts)

        from vstacklens.reports.customer_caliber import DENIED_RULES, object_key as saved_object_key
        excluded_rule_ids = DENIED_RULES
        filtered_findings = shared_problems.projected_findings
        problems: list[dict[str, Any]] = []
        optimizations: list[dict[str, Any]] = []
        for entry in shared_problems.categories:
            item = entry.display
            first = entry.source_findings[0]
            object_types = {obj["object_type"] for obj in item["objects"]}
            unit = self._finding_count_unit(first.get("rule_id", ""), object_types)
            problems.append({
                "level": item["level"], "title": item["title"], "count": item["count"],
                "count_label": f"{item['count']} {unit}", "clusters": "",
                "current": item["current"], "impact": item["impact"],
                "remediation": item["remediation"], "steps": item["steps"],
                "expected": item.get("expected", ""),
                "step_groups": item.get("step_groups", []),
                "steps_numbered": [f"{i + 1}. {step}" for i, step in enumerate(item["steps"])],
                "owner": self._role_label(first.get("owner_role")),
                "effort": self._effort_label(first.get("remediation_effort")),
                "verification": self._verification_label(first.get("verification_method")),
                "rule_id": item["category_id"], "objects": entry.category["affected_objects"],
                "evidence_rows": [{"name": self._break_long_tokens(obj["name"]), "level": obj["level"],
                                   "scope": self._break_long_tokens(obj["location"]), "basis": self._break_long_tokens(obj["basis"]),
                                   "object_key": obj["object_key"]} for obj in item["objects"]],
                "basis": [obj["basis"] for obj in item["objects"]],
                "technical": {"headers":item["technical"]["headers"],
                              "rows":[[self._break_long_tokens(cell) for cell in row] for row in item["technical"]["rows"]]} if item["technical"] else None,
            })
        risk_counts = {level: sum(item["level"] == level for item in problems) for level in ("P1", "P2", "P3")}
        all_plan_counts = {level: sum(item["level"] == level for item in problems) for level in ("P1", "P2", "P3")}
        affected_counts = caliber["affected_counts"]
        issue_count = len(problems)
        optimization_count = 0
        issue_object_count = caliber["affected_total"]
        problems.sort(key=lambda item: ({"P1": 0, "P2": 1, "P3": 2}.get(item["level"], 9), item["title"].casefold()))
        optimizations.clear()
        object_type_counts: dict[str, int] = {}
        for finding in filtered_findings:
            object_type = str(finding.get("object_type") or "其他")
            object_type_counts[object_type] = object_type_counts.get(object_type, 0) + 1
        object_type_rows = [
            {"name": self._object_type_label(key), "count": value}
            for key, value in sorted(object_type_counts.items(), key=lambda pair: (-pair[1], pair[0].casefold()))
        ]
        category_counts: dict[str, int] = {}
        for item in problems:
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
        from vstacklens.reports.presentation import customer_check_statistics
        statistics = customer_check_statistics(report, report_context)
        scope_rows = []
        for row in statistics["by_object_type_rows"]:
            highest = next((level for level in ("P1", "P2", "P3") if row["levels"].get(level, 0)), "")
            scope_rows.append({"name": row["label"], "total": row["total"], "passed": row["passed"],
                               "problems": row["failed"], "highest_level": highest,
                               "pass_rate": round(row["passed"] * 100 / row["total"], 1) if row["total"] else 0,
                               "pass_rate_text": percent_text(row["passed"] * 100 / row["total"] if row["total"] else 0)})
        scope_total_checks = statistics["total"]
        scope_passed_checks = statistics["passed"]
        scope_problem_checks = statistics["failed"]
        failed_level_counts = {level: sum(row["levels"].get(level, 0) for row in statistics["by_object_type_rows"])
                               for level in ("P1", "P2", "P3")}
        if sum(failed_level_counts.values()) != scope_problem_checks:
            raise RuntimeError("未通过检查结果等级统计与共同巡检汇总不一致。")
        level_distribution = [{"level": level, "count": failed_level_counts[level],
                               "share_pct": round(failed_level_counts[level] * 100 / scope_problem_checks, 1)
                               if scope_problem_checks else 0.0,
                               "share_pct_text": percent_text(failed_level_counts[level] * 100 / scope_problem_checks
                                                              if scope_problem_checks else 0)} for level in ("P1", "P2", "P3")]
        top_failed_checks = [{"name": row["name"], "scope": row["scope"], "level": row["highest_level"],
                              "failed": row["failed"]} for row in statistics["top_failed_checks"]]
        scope_summary_text = statistics["text"]
        visible_result_counts = {"passed": statistics["passed"], "failed": statistics["failed"]}
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
                row = self._vmkernel_row(host["name"], vmk)
                if row["host"] and row["device"] and row["ip"] and row["label"] and row["switch"] and row["mtu"]:
                    all_vmkernels.append(row)
        if not all_vmkernels:
            for vmk in (vsan.get("network") or {}).get("vmkernels") or []:
                if isinstance(vmk, dict):
                    row = self._vmkernel_row(str(vmk.get("host_name") or ""), vmk)
                    if row["host"] and row["device"] and row["ip"] and row["label"] and row["switch"] and row["mtu"]:
                        all_vmkernels.append(row)
        seen_vmk = set()
        vmkernel_rows = []
        for item in all_vmkernels:
            key = (item["host"], item["device"], item["ip"])
            if key not in seen_vmk:
                seen_vmk.add(key)
                vmkernel_rows.append(item)
        vmkernel_rows.sort(key=lambda item: (item["host"].casefold(), item["device"].casefold()))
        all_pnics.sort(key=lambda item: (item["host"].casefold(), item["device"].casefold()))
        pnic_anomalies = []
        for host in host_details:
            for nic in host["pnic_rows"]:
                if nic.get("is_in_use") is not True:
                    continue
                issue_codes = {str(code).casefold() for code in (nic.get("issue_codes") or [])}
                assessment = str(nic.get("assessment") or "").casefold()
                link_state = str(nic.get("link_state") or "").casefold()
                if link_state == "down" or assessment == "down" or "link_down" in issue_codes:
                    current_state = "链路断开"
                elif assessment in {"degraded", "speed_mismatch", "speed_zero", "speed_below_1gbps"} or issue_codes.intersection({"speed_mismatch", "speed_zero", "speed_below_1gbps"}):
                    current_state = self._pnic_state_label(assessment, issue_codes)
                else:
                    continue
                usage = [item for item in (nic.get("portgroup_usage") or []) if isinstance(item, dict)]
                portgroup_labels = []
                for item in usage:
                    role = {"active": "活动", "standby": "备用"}.get(str(item.get("role") or "").casefold())
                    name = str(item.get("portgroup") or "").strip()
                    if role and name:
                        portgroup_labels.append(f"{name}（{role}）")
                if not portgroup_labels:
                    continue
                pnic_anomalies.append({
                    "host": host["name"],
                    "device": str(nic.get("device") or ""),
                    "portgroups": "、".join(sorted(set(portgroup_labels), key=str.casefold)),
                    "state": current_state,
                })
        pnic_anomalies.sort(key=lambda item: (item["host"].casefold(), item["device"].casefold()))
        network = {
            "vmkernel_count": len(vm_kernel_rows := vmkernel_rows),
            "vmkernels": vm_kernel_rows,
            "pnic_count": len(all_pnics),
            "pnics": all_pnics,
            "pnic_down_count": sum(int(host.get("pnic_down_count") or 0) for host in host_details),
            "pnic_degraded_count": sum(int(host.get("pnic_degraded_count") or 0) for host in host_details),
            "pnic_down_host_count": sum((host.get("pnic_down_count") or 0) > 0 for host in host_details),
            "pnic_detail_count": len(all_pnics),
            "pnic_anomalies": pnic_anomalies,
            "pnic_anomaly_count": len(pnic_anomalies),
            "pnic_details_are_partial": any(not host["pnic_rows"] and hosts_by_name.get(host["name"], {}).get("link_speed_detail") for host in host_details),
            "host_uplink_summary": [
                {"host": host["name"], "down": int(host.get("pnic_down_count") or 0), "degraded": int(host.get("pnic_degraded_count") or 0)}
                for host in host_details
            ],
        }

        disk_group_map: dict[tuple[str, str], dict[str, Any]] = {}
        for disk in vdisk_details:
            host_name = str(disk.get("host") or "").strip()
            group_name = str(disk.get("disk_group") or "").strip()
            raw_health = str(disk.get("health") or "").strip().casefold()
            role_name = str(disk.get("role") or "").strip()
            if not host_name or not group_name or raw_health not in healthy_tokens | unhealthy_tokens:
                continue
            key = (host_name, group_name)
            group = disk_group_map.setdefault(key, {"host": key[0], "name": key[1], "cache": 0, "capacity": 0, "healthy": 0, "disks": []})
            role = role_name.casefold()
            group["cache"] += int("cache" in role or "缓存" in role)
            group["capacity"] += int("capacity" in role or "容量" in role)
            group["healthy"] += int(raw_health in healthy_tokens)
            group["disks"].append(disk)
        disk_groups = sorted(disk_group_map.values(), key=lambda item: (item["host"].casefold(), item["name"].casefold()))
        for group in disk_groups:
            group["health_known"] = any(item.get("key") == "disks" for item in display_facts["vsan"]["items"])
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
        # Maintenance is a display state; it must not erase a recorded connection.
        connected_host_count = sum(str(item.get("connection_state") or "").casefold() == "connected" for item in host_property_rows)
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
        }
        appendix_iso_vms = []
        appendix_powered_off_vms = []
        appendix_snapshot_vms = []
        appendix_local_datastore_vms = []
        local_problem_keys = {saved_object_key(obj) for entry in shared_problems.categories
                              if entry.display["category_id"] == "VM-LOCAL-DATASTORE"
                              for obj in entry.display["objects"]}
        for vm in vm_records:
            props = self._properties(vm)
            name = str(vm.get("name") or vm.get("object_name") or "").strip()
            host_name = str(vm.get("hostName") or "").strip()
            cluster_name = str(vm.get("cluster") or "").strip()
            if not name:
                continue
            datastore_names = props.get("datastore_names") or []
            if not isinstance(datastore_names, (list, tuple)):
                datastore_names = []
            local_names = props.get("local_datastore_names") or []
            if not isinstance(local_names, (list, tuple)):
                local_names = []
            iso_paths = props.get("iso_paths") or []
            if not isinstance(iso_paths, (list, tuple)):
                iso_paths = []
            if props.get("iso_mounted") is True:
                appendix_iso_vms.append({
                    "name": name,
                    "host": host_name,
                    "iso_paths": self._break_long_tokens("、".join(str(item) for item in iso_paths if str(item).strip())),
                })
            state = self._power_state(vm.get("powerState") or props.get("power_state"))
            is_template = props.get("is_template")
            is_system_vm = props.get("is_system_vm")
            committed_bytes = self._number(props.get("storage_committed_bytes"))
            committed_gb = round(committed_bytes / (1024**3), 1) if committed_bytes is not None and committed_bytes >= 0 else None
            off_days = self._number(props.get("powered_off_days"))
            if state == "powered_off" and is_template is False and is_system_vm is False:
                appendix_powered_off_vms.append({
                    "name": name,
                    "host": host_name,
                    "datastores": "、".join(str(item) for item in datastore_names if str(item).strip()),
                    "committed_gb": committed_gb,
                    "committed_display_value": committed_bytes / (1024**3) if committed_bytes is not None and committed_bytes >= 0 else None,
                    "off_days": off_days,
                })
            if self._has_snapshot(props):
                snapshot_names: list[str] = []
                snapshot_created: list[str] = []
                saved_snapshots = props.get("snapshots") or props.get("snapshot_detail") or []
                if isinstance(saved_snapshots, (list, tuple)):
                    for snapshot in saved_snapshots:
                        if not isinstance(snapshot, dict):
                            continue
                        snapshot_names.append(str(snapshot.get("name") or snapshot.get("snapshot_name") or "").strip())
                        snapshot_created.append(local_time_text(
                            snapshot.get("create_time") or snapshot.get("created_at") or snapshot.get("creation_time")
                        ))
                appendix_snapshot_vms.append({
                    "name": name,
                    "cluster": cluster_name,
                    "host": host_name,
                    "age_days": self._number(props.get("snapshot_age_days_max")),
                    "chain_depth": self._number(props.get("snapshot_chain_depth")),
                    "snapshot_names": self._break_long_tokens("\n".join(snapshot_names)),
                    "snapshot_created": self._break_long_tokens("\n".join(snapshot_created)),
                })
            if saved_object_key({"object_type": "VirtualMachine", **vm}) in local_problem_keys:
                appendix_local_datastore_vms.append({
                    "name": name,
                    "host": host_name,
                    "datastores": "、".join(str(item) for item in local_names if str(item).strip()),
                    "committed_gb": committed_gb,
                    "committed_display_value": committed_bytes / (1024**3) if committed_bytes is not None and committed_bytes >= 0 else None,
                })
        for rows in (appendix_iso_vms, appendix_powered_off_vms, appendix_snapshot_vms, appendix_local_datastore_vms):
            rows.sort(key=lambda item: str(item.get("name") or "").casefold())
        appendix = {
            "iso_vms": appendix_iso_vms,
            "powered_off_vms": appendix_powered_off_vms,
            "powered_off_days_column": bool(appendix_powered_off_vms) and all(item["off_days"] is not None for item in appendix_powered_off_vms),
            "powered_off_capacity_column": bool(appendix_powered_off_vms) and all(item["committed_gb"] is not None for item in appendix_powered_off_vms),
            "snapshot_vms": appendix_snapshot_vms,
            "snapshot_age_column": bool(appendix_snapshot_vms) and all(item["age_days"] is not None for item in appendix_snapshot_vms),
            "local_datastore_vms": appendix_local_datastore_vms,
            "local_datastore_capacity_column": bool(appendix_local_datastore_vms) and all(item["committed_gb"] is not None for item in appendix_local_datastore_vms),
        }
        optimization_object_count = sum(int(item.get("count") or 0) for item in optimizations)

        context_statuses = report.environment_summary.result_status_summary or {}
        scope_payload = {
            "visible_rule_count": len(statistics["by_rule_rows"]),
            "visible_result_counts": visible_result_counts,
            "visible_result_total": statistics["total"],
            "unavailable_total": unavailable_total,
            "unavailable_rows": unavailable_rows,
            "not_applicable_total": not_applicable_total,
            "not_applicable_rows": not_applicable_rows,
            "raw_result_statuses": {str(key): int(value or 0) for key, value in context_statuses.items()},
            "checked_object_total": report.environment_summary.checked_object_total,
            "range_rows": scope_rows,
            "total_checks": scope_total_checks,
            "passed_checks": scope_passed_checks,
            "problem_checks": scope_problem_checks,
            "level_distribution": level_distribution,
            "top_failed_checks": top_failed_checks,
            "all_passed": scope_problem_checks == 0 and scope_total_checks > 0 and not (unavailable_total or context_statuses.get("unavailable") or context_statuses.get("error")),
            "no_results": scope_total_checks == 0,
            "summary_text": scope_summary_text,
            "rule_checklist": rule_checklist,
        }
        payload = {
            "wording": customer_labels(),
            "customer_statistics": statistics,
            "display_facts": display_facts,
            "customer_name": report.customer_info.customer_name or "未指定客户",
            "run_id": report.report_info.run_id,
            "report_date": capture_date,
            "capture_date": capture_date,
            "conclusion": caliber["health"]["label"],
            "judgment_boundary": customer_judgment_metadata(report)["boundary"],
            "reporter": "VStackLens",
            "problem_count": issue_count,
            "optimization_count": optimization_count,
            "risk_counts": risk_counts,
            "health_conclusion": caliber["health"]["label"],
            "customer_caliber": {"version": caliber["version"], "counts": caliber["counts"], "affected_counts": caliber["affected_counts"], "affected_total": caliber["affected_total"], "health": caliber["health"]},
            "affected_counts": affected_counts,
            "issue_object_count": issue_object_count,
            "optimization_object_count": optimization_object_count,
            "connected_host_count": connected_host_count,
            "hardware_issue_total": hardware_issue_total,
            "hardware_issue_column": hardware_issue_column,
            "power_policy_column": power_policy_column,
            "overcommit_host_count": overcommit_host_count,
            "overcommit_display": str(overcommit_host_count) + "/" + str(len(host_details)) if host_details and all(x.get("overcommit") is not None for x in host_details) else "",
            "vmotion_host_total": vmotion_host_total,
            "security": security,
            "datastore_usage_known": len(datastore_usage_rows),
            "highest_datastore_usage": self._percent_text(highest_datastore.get("usage") if highest_datastore else None),
            "highest_datastore_pct": self._number(highest_datastore.get("usage")) if highest_datastore else 0,
            "highest_host_memory_name": highest_host_memory["name"] if highest_host_memory else "",
            "highest_host_memory_pct": highest_host_memory["memory_pct"] if highest_host_memory else None,
            "datastore_omitted_count": len(datastore_omitted),
            "datastore_omitted_max_usage": self._percent_text(datastore_omitted_max_usage),
            "filtered_finding_count": len(filtered_findings),
            "findings_by_object_type": object_type_rows,
            "category_rows": category_rows,
            "max_issue_category_objects": max_issue_category_objects,
            "scope": scope_payload,
            "overview": {"highest_category": highest_category, "vm_state_counts": vm_state_counts},
            "alarm_evidence": self._vcenter_alarm_evidence(report),
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
                "snapshot_vms": display_facts["snapshots"]["vm_count"],
                "snapshot_max_age_days": max(known_snapshot_ages) if known_snapshot_ages else None,
            },
            "snapshot_distribution": snapshot_distribution,
            "oldest_snapshots": oldest_snapshots,
            "snapshot_max_age_text": self._days_text(max(known_snapshot_ages) if known_snapshot_ages else None),
            "highest_memory_host": highest_host_memory["name"] if highest_host_memory else "",
            "highest_memory_pct": highest_host_memory["memory_pct"] if highest_host_memory else None,
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
            "host_security_present": any(bool(item.get("security_summary")) for item in host_details),
            "cluster_cards": cluster_views,
            "cluster_details": cluster_details,
            "cluster_vms": cluster_vm_summary,
            "datastores": datastore_display,
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
                "summary_metrics_available": all(self._number(value) is not None for value in (
                    capacity.get("total_gb"), capacity.get("used_gb"), capacity.get("used_percent"),
                    vsan.get("object_count"), vsan.get("vmdk_count"),
                )),
                "clusters": list(vsan.get("clusters") or []),
                "vmkernel_interfaces": [f"{adapter.get('host_name') or adapter.get('host')} / {adapter.get('device')}" for adapter in (vsan.get("network") or {}).get("vmkernels", [])],
                "total_gb": self._number(capacity.get("total_gb")),
                "total_display": capacity_text(capacity.get("total_gb")),
                "used_gb": self._number(capacity.get("used_gb")),
                "used_display": capacity_text(capacity.get("used_gb")),
                "free_gb": self._number(capacity.get("free_gb")),
                "free_display": capacity_text(capacity.get("free_gb")),
                "used_percent": self._number(capacity.get("used_percent")),
                "disk_count": disk_count,
                "healthy_disks": disk_healthy,
                "disk_details": disk_rows,
                "disk_health_fully_known": all_disk_states_known,
                "disk_group_count": self._number(vsan.get("disk_group_count")),
                "cache_disk_count": self._number(vsan.get("cache_disk_count")),
                "capacity_disk_count": self._number(vsan.get("capacity_disk_count")),
                "object_count": self._number(vsan.get("object_count")),
                "vmdk_count": self._number(vsan.get("vmdk_count")),
                "resync_objects": resync_objects,
                "resync_bytes": resync_bytes,
                "no_resync": no_resync,
                "resync_eta_seconds": self._number(vsan.get("resync_eta_seconds")),
                "planned_resync_count": self._number(vsan.get("planned_resync_count")),
                "storage_policy_summary": policy_summary,
                "storage_policy_status": policy_status,
                "storage_policy_failure": policy_status in {"api_error", "unavailable", "permission_denied", "unsupported"},
                "storage_policy_vm_counts": policy_vm_counts,
                "health_issue_count": self._number(vsan.get("health_issue_count")),
                "disk_issue_count": self._number(vsan.get("disk_issue_count")),
                "object_issue_count": self._number(vsan.get("object_issue_count")),
                "used_percent_text": self._percent_text(capacity.get("used_percent")),
                "resync_objects_text": "0" if no_resync else self._number_text(resync_objects),
                "resync_bytes_text": self._bytes_text(0 if no_resync else resync_bytes),
                "resync_eta_text": f"{vsan['resync_eta_seconds']} 秒" if vsan.get("resync_eta_seconds") is not None else "",
                "planned_resync_text": "0" if no_resync else "",
                "resync_summary_text": (
                    "当前无待重同步对象或数据" if no_resync else
                    " · ".join(part for part in [
                        f"重同步对象 {self._number_text(resync_objects)} 个" if resync_objects is not None else "",
                        f"待重同步数据 {self._bytes_text(resync_bytes)}" if resync_bytes is not None else "",
                    ] if part)
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
            "optimizations": [],
            "appendix": appendix,
            "environment": {
                "vcenter_version": report.environment_summary.vcenter_version or "",
                "vcenter_build": report.environment_summary.vcenter_build or "",
                "checked_object_total": report.environment_summary.checked_object_total,
            },
        }
        def certificate_display(entry: dict[str, Any] | None) -> dict[str, Any]:
            entry = entry or {}
            expiry = entry.get("expiry_date", "")
            days = entry.get("days")
            return {"name": entry.get("name", ""), "host": entry.get("name", ""),
                    "object_key": entry.get("object_key", ""), "expiry": expiry,
                    "expiry_display": f"{expiry}（剩余 {int(days)} 天）" if expiry and days is not None else expiry,
                    "remaining_days": days, "date_source": entry.get("date_source", ""),
                    "derived": entry.get("derived", False), "expiry_known": bool(expiry),
                    "status": self._certificate_status(days),
                    "attention": days is not None and 0 < days <= 90,
                    "expired": days is not None and days <= 0}
        payload["certificates"]["vcenter"] = certificate_display(display_facts["certificates"].get("vcenter"))
        payload["certificates"]["hosts"] = [certificate_display(entry) for entry in display_facts["certificates"]["hosts"]]
        payload["certificates"]["summary"] = ""
        payload["problem_count"] = display_facts["counts"]["problem_count"]
        payload["issue_object_count"] = display_facts["counts"]["affected_total"]
        network["pnic_anomaly_count"] = display_facts["network"].get("active_link_anomalies")
        network["error_count"] = display_facts["network"].get("error_count")
        self._customer_display_fields(payload, hosts_by_name, host_memory_total_mb if host_memory_values else None)
        payload["narratives"] = build_pdf_narratives(payload)
        vmk_complete = bool(host_property_rows) and all(isinstance(x.get("vmkernel_adapters"), list) for x in host_property_rows)
        network["vmkernel_display"] = str(network["vmkernel_count"]) if vmk_complete or network["vmkernel_count"] else ""
        network["pnic_anomaly_display"] = str(network["pnic_anomaly_count"]) + " 条" if network["pnic_anomaly_count"] is not None else ""
        payload["narratives"]["network"] = display_facts["network"]["summary"]
        payload["narratives"]["network_security"] = payload["narratives"]["network"] + payload["narratives"]["security"]
        from vstacklens.reports.presentation import delivery_overview
        payload["delivery"] = delivery_overview(report)
        from vstacklens.reports.presentation import recorded_result_summary
        payload["recorded_results"] = recorded_result_summary(report, report_context)
        payload["has_vcenter"] = True
        if report.product_modules:
            payload["product_report"] = self._pdf_product_view(report)
            if len(assessments) == 1:
                payload["vcenter_target_name"] = assessments[0][0]["target_name"]
                payload["vcenter_target_id"] = assessments[0][0]["target_id"]
        else:
            payload["product_report"] = None
        return payload

    def _customer_display_fields(self, payload: dict[str, Any], host_properties: dict[str, Any], total_memory_mb: float | None) -> None:
        """Attach shared, rounded display strings while preserving calculation values."""
        payload["capacity_note"] = CAPACITY_NOTE
        payload["highest_host_memory_text"] = percent_text(payload.get("highest_host_memory_pct"))
        payload["counts"]["memory_total_text"] = capacity_text(total_memory_mb / 1024 if total_memory_mb is not None else None)
        for host in payload["host_details"]:
            props = host_properties.get(host["name"], {})
            host["cpu_pct_text"] = percent_text(host.get("cpu_pct"))
            host["memory_pct_text"] = percent_text(host.get("memory_pct"))
            allocation = self._number(props.get("host_memory_allocation_ratio"))
            host["memory_allocation_text"] = percent_text(allocation * 100 if allocation is not None else None)
        memory_values = [self._number(host_properties.get(host["name"], {}).get("host_memory_capacity_mb"))
                         for host in payload["host_details"]]
        host_unit = capacity_unit([value / 1024 for value in memory_values if value is not None])
        payload["host_memory_unit"] = host_unit
        allocation_values = [self._number(host_properties.get(host["name"], {}).get(key))
                             for host in payload["host_details"]
                             for key in ("host_memory_allocated_mb", "host_memory_capacity_mb")]
        allocation_unit = capacity_unit([value / 1024 for value in allocation_values if value is not None])
        for host in payload["host_details"]:
            props = host_properties.get(host["name"], {})
            cap = self._number(props.get("host_memory_capacity_mb"))
            allocated = self._number(props.get("host_memory_allocated_mb"))
            host["memory_capacity_text"] = capacity_text(cap / 1024 if cap is not None else None,
                                                         unit=host_unit, with_unit=False)
            host["memory_allocation_capacity_text"] = (
                capacity_text(allocated / 1024, unit=allocation_unit, with_unit=False) + "/"
                + capacity_text(cap / 1024, unit=allocation_unit)
                if allocated is not None and cap is not None else "")
        services = payload["display_facts"].get("host_services", [])
        for host in payload["host_details"]:
            matches = [row for row in services if row.get("name") == host["name"]]
            if len(matches) == 1:
                host["ssh"] = matches[0].get("ssh_state", "")
                host["esxi_shell"] = matches[0].get("shell_state", "")
                summary_parts = host["security_summary"].split("；")
                host["security_summary"] = "；".join(
                    matches[0].get("ssh_summary", part) if part.startswith("远程 SSH ") else
                    matches[0].get("shell_summary", part) if part.startswith("本地 Shell ") else part
                    for part in summary_parts if part)
        for cluster in payload["cluster_details"]:
            cluster["cpu_usage_text"] = percent_text(cluster.get("cpu_usage_pct"))
            cluster["memory_skew_text"] = percent_text(cluster.get("memory_skew_pct"))
            matches = [row for row in payload["display_facts"]["clusters"] if row.get("name") == cluster["name"]]
            if len(matches) == 1:
                cluster["evc_enabled"] = matches[0].get("evc_state", cluster["evc_enabled"])
        for key in ("top_cpu", "top_memory", "top_capacity", "top_vcpu"):
            rows = payload[key]
            unit = capacity_unit([row["value"] / 1024 if key == "top_memory" else row["value"] for row in rows])
            for row in rows:
                row.setdefault("host_share_text", percent_text(row.get("host_share_pct")))
                if key in {"top_memory", "top_capacity"}:
                    row["display"] = capacity_text(row["value"] / 1024 if key == "top_memory" else row["value"], unit=unit)
        for key in ("powered_off_vms", "local_datastore_vms"):
            rows = payload["appendix"][key]
            unit = capacity_unit([row.get("committed_display_value") for row in rows])
            for row in rows:
                row["committed_text"] = capacity_text(row.get("committed_display_value"), unit=unit)

    def _vcenter_alarm_evidence(self, report: ReportData) -> dict[str, Any]:
        """Project one original alarm list, preserving its row associations.

        Finding evidence and inventory are alternate snapshots, not additional
        alarms. Never infer an alarm's entity, acknowledgement or trigger time
        from its containing vCenter finding or the report generation time.
        """
        sources = []
        for index, finding in enumerate(report.findings):
            if finding.rule_id != "VSL-VC-004":
                continue
            for suffix, value in (
                ("observed_detail", finding.observed_detail),
                ("evidence.observed_detail", finding.evidence.get("observed_detail")),
                ("raw_evidence.observed_detail", finding.raw_evidence.get("observed_detail")),
            ):
                if isinstance(value, dict):
                    sources.append((f"findings[{index}].{suffix}", value))
        details = (report.asset_inventory or {}).get("details") or {}
        inventory_rows = self._records(details, "vCenter")
        for index, record in enumerate(inventory_rows):
            sources.append((f"asset_inventory.details.vCenter[{index}].properties", self._properties(record)))

        selected_path, selected, alarms = "", {}, None
        for path, source in sources:
            for key in ("active_red_alarms", "red_alarms", "alarms", "alarm_details"):
                if key in source:
                    selected_path, selected, alarms = path + "." + key, source, source[key]
                    break
            if selected_path:
                break
        rows = []
        invalid_count = 0
        for index, alarm in enumerate(alarms if isinstance(alarms, list) else []):
            if not isinstance(alarm, dict):
                invalid_count += 1
                continue
            def field(*keys):
                for key in keys:
                    if key in alarm and alarm[key] is not None and alarm[key] != "":
                        return alarm[key]
                return None
            acknowledgement = field("acknowledged", "acknowledgement", "acknowledgment")
            acknowledgement = ("是（已确认）" if acknowledgement else "否（未确认）") if isinstance(acknowledgement, bool) else acknowledgement
            entity_id = field("entity_id", "entity_moid", "object_key", "object_id")
            alarm_id = field("alarm_id", "alarm_moid", "key")
            rows.append({
                "alarm": str(field("alarm_name", "name", "definition_name") or "未采集"),
                "entity": str(field("entity_name", "object_name", "target") or "未采集"),
                "status": str(field("status", "overall_status", "overallStatus", "color", "severity") or "未采集"),
                "acknowledged": str(acknowledgement) if acknowledgement is not None else "未采集",
                "time": local_time_text(field("time", "created_time", "triggered_time")),
                "entity_id": str(entity_id) if entity_id is not None else None,
                "alarm_id": str(alarm_id) if alarm_id is not None else None,
                "source_path": f"{selected_path}[{index}]",
            })
        metadata = next((source for _, source in reversed(sources) if "alarm_detail_collection_status" in source), selected)
        collection_status = str(metadata.get("alarm_detail_collection_status") or "unavailable")
        count = selected.get("red_alarm_count", metadata.get("red_alarm_count"))
        complete_empty = isinstance(alarms, list) and not alarms and count == 0 and collection_status == "collected"
        if invalid_count or (isinstance(count, (int, float)) and count != len(rows)):
            collection_status = "partial"
            complete_empty = False
        if complete_empty:
            notice = "本次已读取活动告警，未发现红色活动告警。"
        elif rows:
            notice = "以下逐条保留源告警与对象的对应关系；未采集字段不据此推断。"
            if collection_status != "collected" or invalid_count:
                notice += "告警明细读取受限或不完整，不能将未列出的告警视为不存在。"
        else:
            notice = "未取得可核对的活动告警明细；读取缺失或受限，不代表没有告警。"
        return {"rows": rows, "render_rows": self._alarm_render_rows(rows),
                "collection_status": collection_status, "reported_count": count,
                "invalid_entry_count": invalid_count, "notice": notice, "source_path": selected_path}

    def _alarm_render_rows(self, rows: list[dict[str, Any]]) -> list[list[str]]:
        """Bound tall alarm rows losslessly and repeat their short state cells."""
        result = []
        weights = (1.8, 1.3, 0.6, 0.8, 1.2)
        for row in rows:
            values = [row["alarm"] + ("\n告警 ID：" + row["alarm_id"] if row["alarm_id"] else ""),
                      row["entity"] + ("\n对象 ID：" + row["entity_id"] if row["entity_id"] else ""),
                      row["status"], row["acknowledged"], row["time"]]
            parts = [self._product_cell_parts(value, (297 - 20) * 72 / 25.4 * weights[index] / sum(weights) - 10)
                     for index, value in enumerate(values)]
            for fragment in range(max(map(len, parts), default=1)):
                cells = [items[fragment] if fragment < len(items) else items[0] if len(items) == 1
                         else "（本字段已在前段列完）" for items in parts]
                if fragment:
                    cells[0] += f"\n（同一告警续段 {fragment + 1}）"
                result.append([re.sub(r"\S{17,}", lambda match: "\u200b".join(match.group(0)[i:i + 16]
                               for i in range(0, len(match.group(0)), 16)), value) for value in cells])
        return result

    @staticmethod
    def _break_long_tokens(value: str) -> str:
        # Presentation-only break opportunities; every original character stays.
        # The source ReportData and stored object evidence remain byte-for-byte.
        return re.sub(r"\S{28,}", lambda match: "\u200b".join(match.group(0)[i:i + 24]
                                                               for i in range(0, len(match.group(0)), 24)), str(value))

    def _pdf_product_view(self, report: ReportData) -> dict[str, Any]:
        from vstacklens.products.reporting import product_report_view
        view = product_report_view(report)
        def cell(value, weight=1, total=1):
            # This template is A4 landscape with 10 mm side margins and 5 pt
            # cell insets. Bound an unbreakable piece by the actual column,
            # using a full-width 10.5 pt glyph as the conservative estimate.
            # Existing vCenter/ISO presentation and public evidence are not
            # changed. Only this derived product PDF view receives soft breaks.
            column_points = (297 - 20) * 72 / 25.4 * weight / total - 10
            size = max(4, min(24, int(column_points / 10.5)))
            return re.sub(r"\S{" + str(size + 1) + r",}",
                          lambda match: "\u200b".join(match.group(0)[i:i + size]
                              for i in range(0, len(match.group(0)), size)), str(value))
        for target in view.get("targets") or []:
            for field, weight in (("name", 1), ("address", 1), ("limits", 2)):
                if target.get(field):
                    target[field] = cell(target[field], weight, 4)
        view["navigation"] = [cell(item) for item in view.get("navigation") or []]
        for section in view["sections"]:
            section["name"] = cell(section["name"])
            for alert in section["native_alerts"]:
                alert["time"] = self._break_long_tokens(alert["time"])
            body = section.get("body") or {}
            for table in body.get("tables") or []:
                weights = table.get("weights") or [1] * len(table["columns"])
                total = sum(weights)
                rows = []
                for row in table.get("rows") or []:
                    parts = [self._product_cell_parts(str(value),
                                (297 - 20) * 72 / 25.4 * weights[i] / total - 10)
                             for i, value in enumerate(row)]
                    for fragment in range(max(map(len, parts), default=1)):
                        values = [items[fragment] if fragment < len(items)
                                  else items[0] if len(items) == 1 else "（本字段已在前段列完）"
                                  for items in parts]
                        if fragment:
                            values[0] += f"\n（同一对象续段 {fragment + 1}）"
                        rows.append([cell(value, weights[i], total) for i, value in enumerate(values)])
                table["rows"] = rows
            for field in ("empty_business_text", "conclusion"):
                if body.get(field):
                    body[field] = self._break_long_tokens(str(body[field]))
        return view

    @staticmethod
    def _product_cell_parts(value: str, width_points: float) -> list[str]:
        """Bound derived table fragments without discarding even whitespace.

        Product and alarm tables repeat short identity/evidence cells for each
        fragment, allowing page breaks between bounded rows.
        This is a layout estimate, never a substitute for rendered geometry QA.
        """
        line_units = max(24, int(width_points / 5.25))
        budget = line_units * 12
        parts = []
        while value:
            units, boundary = 0, 0
            for index, char in enumerate(value):
                units += line_units if char == "\n" else 0 if char == "\u200b" else 1 if ord(char) < 128 else 2
                if units > budget:
                    cut = boundary if boundary > index // 2 else index
                    parts.append(value[:cut])
                    value = value[cut:]
                    break
                if char.isspace():
                    boundary = index + 1
            else:
                parts.append(value)
                value = ""
        return parts or [""]

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
        from vstacklens.reports.customer_caliber import reportable_result
        return not reportable_result(item)

    def _safe_customer_text(self, value: Any) -> str:
        from vstacklens.reports.customer_view import customer_wording
        text = str(value or "").strip()
        text = text.replace("TSM-SSH", "SSH")
        folded = text.casefold()
        if folded in {"未采集", "未确认", "待确认", "未记录", "未知", "missing", "not collected", "not_collected", "unknown", "none"}:
            return ""
        return customer_wording(text)

    def _scope_range_name(self, category: Any, object_type: Any) -> str:
        category_key = str(category or "").strip().casefold().replace("_", "-")
        category_labels = {
            "vcenter": "vCenter",
            "cluster": "集群",
            "host": "ESXi 主机",
            "vm": "虚拟机",
            "virtual-machine": "虚拟机",
            "datastore": "数据存储",
            "network": "网络",
            "vsan": "vSAN",
        }
        if category_key in category_labels:
            return category_labels[category_key]
        return self._object_type_label(str(object_type or ""))

    def _object_type_label(self, value: Any) -> str:
        return {
            "vCenter": "vCenter",
            "ClusterComputeResource": "集群",
            "HostSystem": "ESXi 主机",
            "VirtualMachine": "虚拟机",
            "Datastore": "数据存储",
            "vSAN": "vSAN",
            "Network": "网络",
        }.get(str(value or ""), self._safe_customer_text(value))

    def _pnic_state_label(self, assessment: str, issue_codes: set[str]) -> str:
        if "speed_zero" in issue_codes or assessment == "speed_zero":
            return "速率为 0"
        if "speed_mismatch" in issue_codes or assessment == "speed_mismatch":
            return "速率不匹配"
        if "speed_below_1gbps" in issue_codes or assessment == "speed_below_1gbps":
            return "速率低于 1 Gbit/s"
        return "速率异常"

    def _disk_health_label(self, value: Any) -> str:
        text = str(value or "").strip().casefold()
        if text in {"red", "failed", "error", "offline", "absent", "lost", "unhealthy"}:
            return "故障"
        if text in {"yellow", "warning", "degraded"}:
            return "需关注"
        return self._safe_customer_text(value)

    def _power_policy_label(self, value: Any) -> str:
        text = str(value or "").strip().casefold().replace("_", "")
        return {
            "dynamic": "均衡",
            "balanced": "均衡",
            "highperformance": "高性能",
            "lowpower": "节能",
        }.get(text, self._safe_customer_text(value))

    def _drs_behavior_label(self, value: Any) -> str:
        text = str(value or "").strip().casefold()
        return {
            "fullyautomated": "全自动",
            "partiallyautomated": "部分自动化",
            "manual": "手动",
        }.get(text, self._safe_customer_text(value))

    def _lockdown_label(self, value: Any) -> str:
        text = str(value or "").strip().casefold()
        return {
            "disabled": "未启用",
            "lockdowndisabled": "未启用",
            "lockdownnormal": "正常模式",
            "lockdownstrict": "严格模式",
        }.get(text, self._safe_customer_text(value))

    def _security_policy_label(self, value: Any) -> str:
        text = str(value or "").strip()
        labels = {
            "Forged Transmits": "伪传输（Forged Transmits）",
            "MAC Address Changes": "MAC 地址更改（MAC Address Changes）",
            "Promiscuous Mode": "混杂模式（Promiscuous Mode）",
        }
        return labels.get(text, self._safe_customer_text(value))

    def _security_value_label(self, value: Any) -> str:
        text = str(value or "").strip()
        return {
            "accept": "允许",
            "reject": "拒绝",
            "true": "启用",
            "false": "禁用",
            "enabled": "启用",
            "disabled": "禁用",
            "allow": "允许",
            "deny": "拒绝",
        }.get(text.casefold(), self._safe_customer_text(value))

    def _days_text(self, value: Any) -> str:
        number = self._number(value)
        if number is None or number < 0:
            return ""
        return f"{number:,.0f} 天"

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
            text = str(step or "").strip().replace("TSM-SSH", "SSH")
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
        return labels.get(text, "")

    def _verification_label(self, value: Any) -> str:
        labels = {
            "rerun_rule": "重新巡检",
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
        return ""

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
            return ""
        return f"{number:,.0f}" if number.is_integer() else f"{number:,.1f}"

    def _speed_text(self, value: Any) -> str:
        number = self._number(value)
        if number is None:
            return ""
        if number >= 1000:
            return f"{number / 1000:g} Gbit/s"
        return f"{number:g} Mbit/s"

    def _bytes_text(self, value: Any) -> str:
        return capacity_bytes_text(value)

    def _vmkernel_row(self, host_name: str, item: dict[str, Any]) -> dict[str, Any]:
        label = item.get("network_label") or item.get("portgroup")
        return {
            "host": host_name,
            "device": self._safe_customer_text(item.get("device")),
            "ip": self._safe_customer_text(item.get("ip_address") or item.get("ip")),
            "subnet": self._safe_customer_text(item.get("subnet_mask") or item.get("subnet")),
            "label": self._safe_customer_text(label),
            "switch": self._safe_customer_text(item.get("switch")),
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
        return ""

    def _percent_text(self, value: Any) -> str:
        number = self._number(value)
        return percent_text(number)

    def _capacity_text(self, value: Any) -> str:
        number = self._number(value)
        return capacity_text(number)

    def _gb_number_text(self, value: Any) -> str:
        number = self._number(value)
        if number is None:
            return ""
        return decimal_text(number, grouping=True)

    def _text(self, value: Any) -> str:
        text = str(value or "").strip()
        return self._safe_customer_text(text)

    def _cluster_feature_note(self, clusters: list[str], enabled: list[str], feature: str) -> str:
        if not clusters:
            return ""
        if len(clusters) == 2:
            enabled_names = [name for name in clusters if name in enabled]
            disabled_names = [name for name in clusters if name not in enabled]
            enabled_text = "、".join(enabled_names) or "无"
            disabled_text = "、".join(disabled_names) or "无"
            return f"{feature} 启用：{enabled_text}；未启用：{disabled_text}"
        return f"已启用 {len(enabled)}/{len(clusters)} 个集群"

    def _certificate_status(self, days: float | None) -> str:
        if days is None:
            return ""
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
        return "；".join(parts)

    def _date_text(self, value: Any) -> str:
        text = str(value or "").strip()
        if not text:
            return datetime.now().astimezone().strftime("%Y-%m-%d")
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone().strftime("%Y-%m-%d")
        except ValueError:
            return text[:10]
