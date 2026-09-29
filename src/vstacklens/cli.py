from __future__ import annotations

import argparse
import getpass
import json
from pathlib import Path

from vstacklens.application.inspection_runner import InspectionRunner, MockRunRequest, VCenterRunRequest
from vstacklens.collection.capability_probe import PyVmomiCapabilityProbe, write_probe_html, write_probe_json
from vstacklens.db.connection import connect, init_db
from vstacklens.db.repositories import (
    finalize_run_summary,
    mark_finding_exception,
    remove_finding_exception,
)
from vstacklens.reports.context_builder import ReportContextBuilder
from vstacklens.reports.html_package import HtmlReportPackageBuilder
from vstacklens.reports.report_model import ReportDataFactory
from vstacklens.reports.run_compare import RunComparisonBuilder
from vstacklens.rules.rulepack_loader import RulePackLoader
from vstacklens.rules.schema_validator import SchemaValidator
from vstacklens.application.upgrade_compat_service import UpgradeCompatConfig, UpgradeCompatService
from vstacklens.deep.service import DeepInspectionService
from vstacklens.deep.interfaces import DeepCollectionPolicy


def cmd_init_db(args: argparse.Namespace) -> None:
    init_db(Path(args.db))
    print(f"Initialized database: {args.db}")


def cmd_validate_rules(args: argparse.Namespace) -> None:
    loader = RulePackLoader()
    validator = SchemaValidator()
    raw_rules = loader.load_raw(Path(args.rulepack))
    valid_count = 0
    for raw in raw_rules:
        validator.validate_rule(raw)
        valid_count += 1
    print(f"Validated rules: {valid_count}")


def cmd_run_mock(args: argparse.Namespace) -> None:
    db = Path(args.db)
    rulepack = Path(args.rulepack)
    fixture = Path(args.fixture)
    report_dir = Path(args.report_dir)
    html_target = getattr(args, "html_out", None) or getattr(args, "out", None)
    html_out = Path(html_target) if html_target else None
    docx_out = Path(args.docx_out) if getattr(args, "docx_out", None) else None
    pdf_out = Path(args.pdf_out) if getattr(args, "pdf_out", None) else None
    result = InspectionRunner().run_mock(
        MockRunRequest(
            db_path=db,
            rulepack_path=rulepack,
            report_dir=report_dir,
            report_title=getattr(args, "report_title", None),
            customer_name=getattr(args, "customer_name", None),
            site_name=getattr(args, "site_name", None),
            zip_report=args.zip_report,
            previous_run_id=getattr(args, "previous_run_id", None),
            html_out=html_out,
            docx_out=docx_out,
            pdf_out=pdf_out,
            fixture_path=fixture,
        )
    )
    print(f"Run completed. Report package: {result.report_path}")
    if result.docx_path:
        print(f"Word report: {result.docx_path}")
    elif result.docx_error:
        print(result.docx_error)
    if result.pdf_path:
        print(f"PDF report: {result.pdf_path}")
    elif result.pdf_error:
        print(result.pdf_error)


def cmd_run_vcenter(args: argparse.Namespace) -> None:
    password = getpass.getpass("vCenter password: ") if args.password_prompt else args.password
    if not password:
        raise SystemExit("--password or --password-prompt is required")
    if getattr(args, "probe_only", False):
        cmd_probe_vcenter_capabilities(args)
        return
    if not args.db or not args.rulepack:
        raise SystemExit("--db and --rulepack are required for run-vcenter")
    db = Path(args.db)
    rulepack = Path(args.rulepack)
    report_dir = Path(args.report_dir)
    html_target = getattr(args, "html_out", None) or getattr(args, "out", None)
    html_out = Path(html_target) if html_target else None
    docx_out = Path(args.docx_out) if getattr(args, "docx_out", None) else None
    pdf_out = Path(args.pdf_out) if getattr(args, "pdf_out", None) else None
    result = InspectionRunner().run_vcenter(
        VCenterRunRequest(
            db_path=db,
            rulepack_path=rulepack,
            report_dir=report_dir,
            report_title=getattr(args, "report_title", None),
            customer_name=getattr(args, "customer_name", None),
            site_name=getattr(args, "site_name", None),
            zip_report=args.zip_report,
            previous_run_id=getattr(args, "previous_run_id", None),
            compare_latest=getattr(args, "compare_latest", False),
            html_out=html_out,
            docx_out=docx_out,
            pdf_out=pdf_out,
            vcenter=args.vcenter,
            username=args.username,
            password=password,
            port=args.port,
            ssl_no_verify=args.ssl_no_verify,
        )
    )
    print(f"Run completed. Report package: {result.report_path}")
    if result.docx_path:
        print(f"Word report: {result.docx_path}")
    elif result.docx_error:
        print(result.docx_error)
    if result.pdf_path:
        print(f"PDF report: {result.pdf_path}")
    elif result.pdf_error:
        print(result.pdf_error)


def cmd_probe_vcenter_capabilities(args: argparse.Namespace) -> None:
    password = getpass.getpass("vCenter password: ") if args.password_prompt else args.password
    if not password:
        raise SystemExit("--password or --password-prompt is required")
    json_out = Path(getattr(args, "json_out", None) or "data/probe-capabilities.json")
    html_out_arg = getattr(args, "html_out", None)
    html_out = Path(html_out_arg) if html_out_arg else None
    probe = PyVmomiCapabilityProbe(args.vcenter, args.username, password, args.port, not args.ssl_no_verify)
    report = probe.run()
    write_probe_json(report, json_out)
    if html_out:
        write_probe_html(report, html_out)
    print(f"Probe completed. JSON: {json_out}")
    if html_out:
        print(f"Probe HTML: {html_out}")


def cmd_compare_runs(args: argparse.Namespace) -> None:
    output_dir = Path(args.report_dir)
    with connect(Path(args.db)) as conn:
        comparison = RunComparisonBuilder().build(conn, args.previous_run_id, args.current_run_id)
        report_context = ReportContextBuilder().build(conn, args.current_run_id, comparison=comparison)
        report_data = ReportDataFactory().from_context(report_context)
        HtmlReportPackageBuilder().render(report_data, report_context, output_dir, zip_package=getattr(args, "zip_report", False))
        output = RunComparisonBuilder().write_json(conn, args.previous_run_id, args.current_run_id, output_dir.parent / f"{output_dir.name}_comparison")
    print(f"Run comparison report package: {output_dir / 'index.html'}")
    print(f"Run comparison JSON: {output}")


def cmd_add_exception(args: argparse.Namespace) -> None:
    with connect(Path(args.db)) as conn:
        mark_finding_exception(conn, args.finding_id, args.reason, args.owner, args.expires_at, args.approval_note)
        finding = conn.execute("SELECT last_seen_run_id FROM findings WHERE finding_id = ?", (args.finding_id,)).fetchone()
        if finding:
            finalize_run_summary(conn, finding["last_seen_run_id"])
    print(f"Exception added: {args.finding_id}")


def cmd_list_exceptions(args: argparse.Namespace) -> None:
    with connect(Path(args.db)) as conn:
        rows = conn.execute(
            """
            SELECT f.finding_id, f.rule_id, f.object_name, f.risk_level,
                   f.exception_reason, f.exception_owner, f.exception_expires_at,
                   f.exception_approval_note
            FROM findings f
            WHERE f.status = 'exception'
            ORDER BY f.exception_expires_at, f.rule_id, f.object_name
            """
        ).fetchall()
    for row in rows:
        print(
            f"{row['finding_id']} | {row['risk_level']} | {row['rule_id']} | {row['object_name']} | "
            f"{row['exception_owner']} | {row['exception_expires_at']} | {row['exception_reason']}"
        )


def cmd_remove_exception(args: argparse.Namespace) -> None:
    with connect(Path(args.db)) as conn:
        finding = conn.execute("SELECT last_seen_run_id FROM findings WHERE finding_id = ?", (args.finding_id,)).fetchone()
        remove_finding_exception(conn, args.finding_id)
        if finding:
            finalize_run_summary(conn, finding["last_seen_run_id"])
    print(f"Exception removed: {args.finding_id}")


def cmd_desktop(args: argparse.Namespace) -> None:
    from vstacklens.desktop.app import main as desktop_main

    desktop_main()


def cmd_import_hcl_data(args: argparse.Namespace) -> None:
    result = UpgradeCompatService().import_hcl_data(
        db_path=Path(args.db), source=args.source, file_path=args.file, online=args.online,
    )
    for source, version_id in result.items():
        print(f"Imported {source}: {version_id}")


def cmd_hcl_data_status(args: argparse.Namespace) -> None:
    status = UpgradeCompatService().hcl_data_status(Path(args.db))
    print(status["message"])
    for source, item in status["sources"].items():
        print(f"{source}: version={item['data_version_id'] or '未导入'} updated={item['json_updated_time'] or '未记录'} downloaded={item['downloaded_at'] or '未导入'} records={item['record_count']} freshness={item['freshness']}")


def cmd_run_upgrade_compat(args: argparse.Namespace) -> None:
    password = getpass.getpass("vCenter password: ") if args.password_prompt else ""
    mode = "support_bundle" if args.support_bundle else "vcenter"
    cfg = UpgradeCompatConfig(
        collection_mode=mode, target_release=args.target_release, vsan_check_mode=args.vsan_check,
        customer_name=args.customer_name or "", report_title=args.report_title or "", report_dir=Path(args.report_dir), db_path=Path(args.db),
        vcenter_host=args.vcenter or "", username=args.username or "", password=password, ssl_verify=not args.ssl_no_verify,
        bundle_path=Path(args.support_bundle) if args.support_bundle else "",
    )
    service = UpgradeCompatService()
    errors = service.validate_config(cfg)
    if errors:
        raise SystemExit("\n".join(errors))
    result = service.run(cfg, progress_callback=lambda item: print(f"{item.percent}% {item.message}"))
    if result.connection_diagnostic:
        print(f"连接诊断：{result.connection_diagnostic}")
        return
    print(f"兼容性检查完成：{result.run_id}")
    print(f"HTML 报告：{result.html_path}")


def cmd_run_deep_dataset(args: argparse.Namespace) -> None:
    """Run the read-only Deep Analyzer against a portable Dataset or fixture."""

    result = DeepInspectionService().analyze_dataset(
        Path(args.dataset),
        Path(args.report_dir),
        docx_out=Path(args.docx_out) if args.docx_out else None,
    )
    print(f"Deep analysis completed. HTML report: {result.html_path}")
    print(f"Deep diagnostic record: {result.diagnostic_path}")
    if result.docx_path:
        print(f"Word report: {result.docx_path}")


def cmd_run_deep_replay(args: argparse.Namespace) -> None:
    results = DeepInspectionService().replay_datasets([Path(item) for item in args.dataset], Path(args.report_dir), docx_out=Path(args.docx_out) if args.docx_out else None)
    if not results:
        raise SystemExit("至少需要一个 Dataset")
    print(f"Deep replay completed: {len(results)} datasets")
    print(f"Latest HTML report: {results[-1].html_path}")
    print(f"History database: {Path(args.report_dir) / 'deep-history.db'}")
    trend_log = next((item for item in results[-1].analysis.diagnostic.collection_log if item.get("action") == "history.trend"), None)
    if trend_log:
        print(f"Trend readiness: {json.dumps(trend_log.get('windows', {}), ensure_ascii=False)}")
    if results[-1].docx_path:
        print(f"Latest Word report: {results[-1].docx_path}")


def cmd_run_deep_vcenter(args: argparse.Namespace) -> None:
    """Run the real vCenter Deep Core collector with the workbook's primary account, using read-only operations."""

    result = DeepInspectionService().collect_and_analyze_vcenter(
        Path(args.connection_workbook),
        Path(args.report_dir),
        docx_out=Path(args.docx_out) if args.docx_out else None,
        policy=DeepCollectionPolicy(budget_seconds=args.resource_budget_seconds, resource_memory_limit_mb=args.resource_memory_limit_mb, resource_cpu_limit_percent=args.resource_cpu_limit_percent, correlation_window_seconds=args.correlation_window_seconds, event_history_days=args.event_history_days, max_log_total_bytes=args.max_log_total_mib * 1024 * 1024, max_log_primary_bytes=args.max_log_primary_mib * 1024 * 1024, max_log_fallback_bytes=args.max_log_fallback_mib * 1024 * 1024, log_collection_days=getattr(args, "log_days", None)),
    )
    connection_failure = next(
        (
            item
            for item in result.analysis.diagnostic.collection_log
            if item.get("action") in {"connection", "session.content"} and item.get("status") not in {"ok", "connected"}
        ),
        None,
    )
    if connection_failure:
        print(f"Deep vCenter read-only collection unavailable ({connection_failure.get('status')}). HTML report: {result.html_path}")
    elif bool((result.analysis.diagnostic.impact or {}).get("degraded")):
        print(f"Deep vCenter read-only session completed with degraded coverage. HTML report: {result.html_path}")
    else:
        print(f"Deep vCenter read-only session completed. HTML report: {result.html_path}")
    print(f"Deep Dataset JSON: {result.report_dir.parent / (result.report_dir.name + '.dataset.json')}")
    print(f"Deep diagnostic record: {result.diagnostic_path}")
    if result.docx_path:
        print(f"Word report: {result.docx_path}")
    if connection_failure:
        raise SystemExit(2)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vstacklens")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init-db")
    init.add_argument("--db", required=True)
    init.set_defaults(func=cmd_init_db)

    validate = sub.add_parser("validate-rules")
    validate.add_argument("--rulepack", required=True)
    validate.set_defaults(func=cmd_validate_rules)

    run_mock = sub.add_parser("run-mock")
    run_mock.add_argument("--db", required=True)
    run_mock.add_argument("--rulepack", required=True)
    run_mock.add_argument("--fixture", required=True)
    run_mock.add_argument("--report-dir", default="out\\report-package")
    run_mock.add_argument("--zip-report", action="store_true")
    run_mock.add_argument("--report-title")
    run_mock.add_argument("--customer-name")
    run_mock.add_argument("--site-name")
    run_mock.add_argument("--previous-run-id")
    run_mock.add_argument("--out")
    run_mock.add_argument("--html-out")
    run_mock.add_argument("--docx-out")
    run_mock.add_argument("--pdf-out")
    run_mock.set_defaults(func=cmd_run_mock)

    run_vcenter = sub.add_parser("run-vcenter")
    run_vcenter.add_argument("--db")
    run_vcenter.add_argument("--vcenter", required=True)
    run_vcenter.add_argument("--username", required=True)
    run_vcenter.add_argument("--password")
    run_vcenter.add_argument("--password-prompt", action="store_true")
    run_vcenter.add_argument("--port", type=int, default=443)
    run_vcenter.add_argument("--ssl-no-verify", action="store_true")
    run_vcenter.add_argument("--rulepack")
    run_vcenter.add_argument("--report-dir", default="out\\report-package")
    run_vcenter.add_argument("--zip-report", action="store_true")
    run_vcenter.add_argument("--report-title")
    run_vcenter.add_argument("--customer-name")
    run_vcenter.add_argument("--site-name")
    run_vcenter.add_argument("--compare-latest", action="store_true")
    run_vcenter.add_argument("--previous-run-id")
    run_vcenter.add_argument("--out")
    run_vcenter.add_argument("--html-out")
    run_vcenter.add_argument("--docx-out")
    run_vcenter.add_argument("--pdf-out")
    run_vcenter.add_argument("--probe-only", action="store_true")
    run_vcenter.add_argument("--json-out")
    run_vcenter.set_defaults(func=cmd_run_vcenter)

    compare_runs = sub.add_parser("compare-runs")
    compare_runs.add_argument("--db", required=True)
    compare_runs.add_argument("--previous-run-id", required=True)
    compare_runs.add_argument("--current-run-id", required=True)
    compare_runs.add_argument("--report-dir", required=True)
    compare_runs.add_argument("--zip-report", action="store_true")
    compare_runs.set_defaults(func=cmd_compare_runs)

    add_exception = sub.add_parser("add-exception")
    add_exception.add_argument("--db", required=True)
    add_exception.add_argument("--finding-id", required=True)
    add_exception.add_argument("--reason", required=True)
    add_exception.add_argument("--owner", required=True)
    add_exception.add_argument("--expires-at", required=True)
    add_exception.add_argument("--approval-note")
    add_exception.set_defaults(func=cmd_add_exception)

    list_exceptions = sub.add_parser("list-exceptions")
    list_exceptions.add_argument("--db", required=True)
    list_exceptions.set_defaults(func=cmd_list_exceptions)

    remove_exception = sub.add_parser("remove-exception")
    remove_exception.add_argument("--db", required=True)
    remove_exception.add_argument("--finding-id", required=True)
    remove_exception.set_defaults(func=cmd_remove_exception)

    probe_vcenter = sub.add_parser("probe-vcenter-capabilities")
    probe_vcenter.add_argument("--vcenter", required=True)
    probe_vcenter.add_argument("--username", required=True)
    probe_vcenter.add_argument("--password")
    probe_vcenter.add_argument("--password-prompt", action="store_true")
    probe_vcenter.add_argument("--port", type=int, default=443)
    probe_vcenter.add_argument("--ssl-no-verify", action="store_true")
    probe_vcenter.add_argument("--json-out", default="data/probe-capabilities.json")
    probe_vcenter.add_argument("--html-out")
    probe_vcenter.set_defaults(func=cmd_probe_vcenter_capabilities)

    import_hcl = sub.add_parser("import-hcl-data", help="导入本地 HCL JSON，或在线下载后导入。")
    import_hcl.add_argument("--source", choices=("vcg", "vsan", "both"), required=True)
    import_hcl.add_argument("--file", help="本地 JSON；source=both 时为含 vcg-bundle.json 与 vsan-all.json 的目录")
    import_hcl.add_argument("--online", action="store_true", help="在线下载；VCG 凭据从环境变量读取")
    import_hcl.add_argument("--db", required=True)
    import_hcl.set_defaults(func=cmd_import_hcl_data)

    data_status = sub.add_parser("hcl-data-status", help="显示 VCG 与 vSAN HCL 的版本、时间、数量和新鲜度。")
    data_status.add_argument("--db", required=True)
    data_status.set_defaults(func=cmd_hcl_data_status)

    upgrade = sub.add_parser("run-upgrade-compat", help="连接 vCenter 或导入 support bundle，执行独立升级兼容性检查。")
    upgrade.add_argument("--db", required=True)
    upgrade.add_argument("--target-release", required=True)
    upgrade.add_argument("--vsan-check", choices=("auto", "force", "skip"), default="auto")
    upgrade.add_argument("--customer-name")
    upgrade.add_argument("--report-title")
    upgrade.add_argument("--report-dir", default="out")
    source_group = upgrade.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--vcenter", help="vCenter 地址，适用于直连采集")
    source_group.add_argument("--support-bundle", help="VMware support bundle，适用于离线采集")
    upgrade.add_argument("--username", help="直连 vCenter 时的用户名")
    upgrade.add_argument("--password-prompt", action="store_true", help="交互提示 vCenter 密码，不接收命令行明文密码")
    upgrade.add_argument("--ssl-no-verify", action="store_true", help="直连时忽略自签名证书")
    upgrade.set_defaults(func=cmd_run_upgrade_compat)

    deep = sub.add_parser("run-deep-dataset", help="对 Deep Dataset 或 fixture 执行只读分析并生成客户报告。")
    deep.add_argument("--dataset", required=True, help="Deep Dataset JSON 或 fixture 文件")
    deep.add_argument("--report-dir", default="out\\deep-report")
    deep.add_argument("--docx-out")
    deep.set_defaults(func=cmd_run_deep_dataset)

    deep_replay = sub.add_parser("run-deep-replay", help="按 Dataset manifest 时间顺序重放多个 Deep Dataset 并更新历史趋势。")
    deep_replay.add_argument("--dataset", action="append", required=True, help="Dataset JSON；可重复传入多个文件")
    deep_replay.add_argument("--report-dir", default="out\\deep-replay")
    deep_replay.add_argument("--docx-out")
    deep_replay.set_defaults(func=cmd_run_deep_replay)

    deep_vcenter = sub.add_parser("run-deep-vcenter", help="对真实 vCenter 执行只读 Deep Core 采集并生成报告。")
    deep_vcenter.add_argument("--connection-workbook", required=True, help="包含主 vCenter 连接行及主机日志凭据的工作簿")
    deep_vcenter.add_argument("--report-dir", default="out\\deep-vcenter-report")
    deep_vcenter.add_argument("--docx-out")
    deep_vcenter.add_argument("--resource-budget-seconds", type=int, default=1800)
    deep_vcenter.add_argument("--resource-memory-limit-mb", type=int, default=512)
    deep_vcenter.add_argument("--resource-cpu-limit-percent", type=float, default=90.0, help="当本机进程 CPU 占整机逻辑 CPU 百分比达到该值时暂停可选采集")
    deep_vcenter.add_argument("--max-log-total-mib", type=int, default=16, choices=range(21), metavar="0..20", help="本次 Deep 日志总预算（MiB），默认 16，内部验收上限 20 MiB")
    deep_vcenter.add_argument("--max-log-primary-mib", type=int, default=12, choices=range(16), metavar="0..15", help="vCenter DiagnosticManager 主来源预算（MiB），默认 12，内部验收上限 15 MiB")
    deep_vcenter.add_argument("--max-log-fallback-mib", type=int, default=4, choices=range(6), metavar="0..5", help="PowerCLI 与直连 ESXi 共用备用预算（MiB），默认 4，内部验收上限 5 MiB")
    deep_vcenter.add_argument("--log-days", type=int, choices=range(1, 366), metavar="DAYS", help="仅限定期望采集的最近日志天数（1–365）；不传则尽可能读取可提供日志，不改变事件或性能历史范围")
    deep_vcenter.add_argument("--correlation-window-seconds", type=int, default=3600, help="历史日志、事件、任务和性能证据的同对象关联窗口（1 至 86400 秒）")
    deep_vcenter.add_argument("--event-history-days", type=int, default=30, metavar="DAYS", help="EventManager 历史查询窗口（1 至 90 天）；不扩大性能数据查询窗口")
    deep_vcenter.set_defaults(func=cmd_run_deep_vcenter)

    desktop = sub.add_parser("desktop")
    desktop.set_defaults(func=cmd_desktop)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
