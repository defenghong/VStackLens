from __future__ import annotations

from pathlib import Path
from typing import Any

from vstacklens.application.artifact_safety import ArtifactScanFinding, sanitize_text, summarize_scan_findings


def write_engineering_diagnostics(
    output_path: Path,
    *,
    run_id: str,
    vcenter: str,
    customer_name: str,
    site_name: str,
    report_dir: Path,
    db_path: Path,
    report_context: dict[str, Any],
    report_paths: dict[str, Path | None],
    artifact_findings: list[ArtifactScanFinding],
    secrets: tuple[str, ...] = (),
) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    environment = report_context.get("environment_info", {}) if isinstance(report_context, dict) else {}
    status_summary = report_context.get("result_status_summary", {}) if isinstance(report_context, dict) else {}
    appendix = report_context.get("appendix", {}) if isinstance(report_context, dict) else {}
    unavailable_rules = appendix.get("unavailable_rules", []) if isinstance(appendix, dict) else []
    diagnostics = environment.get("connection_diagnostics", {}) if isinstance(environment, dict) else {}
    security_warnings = environment.get("security_warnings", []) if isinstance(environment, dict) else []
    collection_warnings = environment.get("collection_warnings", []) if isinstance(environment, dict) else []

    lines = [
        "# VStackLens 工程诊断",
        "",
        "## 运行基本信息",
        f"- 运行 ID：{sanitize_text(run_id, *secrets)}",
        f"- vCenter：{sanitize_text(vcenter, *secrets)}",
        f"- 客户/站点：{sanitize_text(customer_name, *secrets)} / {sanitize_text(site_name, *secrets)}",
        f"- 报告目录：{sanitize_text(report_dir.name, *secrets)}",
        f"- 数据库：{sanitize_text(db_path.name, *secrets)}",
        "",
        "## 采集阶段摘要",
        f"- 采集模式：{sanitize_text(environment.get('collection_mode_label') or environment.get('collection_mode') or '未记录', *secrets)}",
        f"- 数据覆盖：{sanitize_text(environment.get('data_coverage_summary') or '未记录', *secrets)}",
    ]
    for warning in security_warnings:
        lines.append(f"- 安全提示：{sanitize_text(warning, *secrets)}")
    lines.append(f"- 采集 warning 数量：{len(collection_warnings)}")
    for warning in collection_warnings[:10]:
        if isinstance(warning, dict):
            lines.append(
                "- warning："
                f"{sanitize_text(warning.get('context') or 'pyvmomi', *secrets)} / "
                f"{sanitize_text(warning.get('status') or 'partial', *secrets)}"
            )
    if diagnostics:
        port = diagnostics.get("port", {}) if isinstance(diagnostics, dict) else {}
        sdk = diagnostics.get("sdk", {}) if isinstance(diagnostics, dict) else {}
        lines.extend(
            [
                f"- 端口检测：{sanitize_text(port.get('status', '未记录'), *secrets)} / {sanitize_text(port.get('message', ''), *secrets)}",
                f"- SDK 检测：{sanitize_text(sdk.get('status', '未记录'), *secrets)} / {sanitize_text(sdk.get('message', ''), *secrets)}",
            ]
        )
    else:
        lines.append("- SDK 检测：已进入常规采集流程。")

    lines.extend(
        [
            "",
            "## 规则执行摘要",
            f"- passed：{int(status_summary.get('passed', 0) or 0)}",
            f"- failed：{int(status_summary.get('failed', 0) or 0)}",
            f"- unavailable：{int(status_summary.get('unavailable', 0) or 0)}",
            f"- not_applicable：{int(status_summary.get('not_applicable', 0) or 0)}",
            f"- error：{int(status_summary.get('error', 0) or 0)}",
        ]
    )
    if unavailable_rules:
        reasons: dict[str, int] = {}
        for item in unavailable_rules:
            if not isinstance(item, dict):
                continue
            reason = sanitize_text(item.get("reason") or item.get("status") or "未记录", *secrets)
            reasons[reason] = reasons.get(reason, 0) + 1
        lines.append("- unavailable/not_collected 原因聚合：")
        for reason, count in sorted(reasons.items(), key=lambda row: row[0]):
            lines.append(f"  - {reason}：{count}")

    lines.extend(["", "## 报告生成摘要"])
    for name, path in report_paths.items():
        lines.append(f"- {name}：{sanitize_text(path.name if path else '未生成', *secrets)}")

    lines.extend(["", "## 客户报告安全检查摘要"])
    if artifact_findings:
        for finding in summarize_scan_findings(artifact_findings):
            lines.append(f"- {sanitize_text(finding['file'], *secrets)}：{sanitize_text(finding['reason'], *secrets)}")
    else:
        lines.append("- 未发现敏感字段、底层异常、本机路径或客户报告不当词。")

    lines.extend(["", "## 故障排查提示"])
    connection_mode = str(environment.get("collection_mode") or "")
    if connection_mode == "connection_failed":
        sdk = diagnostics.get("sdk", {}) if isinstance(diagnostics, dict) else {}
        lines.append(f"- 连接未完成：{sanitize_text(sdk.get('message') or '请检查网络、账号、权限和 vCenter API 状态。', *secrets)}")
    elif security_warnings:
        lines.append("- 证书可信链未通过，巡检已自动降级为不校验证书模式继续。建议后续配置受信任证书。")
    else:
        lines.append("- 本次未记录连接阻断类问题。")

    text = sanitize_text("\n".join(lines) + "\n", *secrets)
    output_path.write_text(text, encoding="utf-8")
    return output_path
