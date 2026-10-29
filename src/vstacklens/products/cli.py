"""Explicit single-run product entry point; passwords exist only for this run.

Example: python -m vstacklens.products.cli --db isolated.db prepare-db
"""
from __future__ import annotations

import argparse
import getpass
import json
from pathlib import Path
import signal
import sys
import threading
import warnings

from vstacklens.application.integrated_inspection import (
    IntegratedInspectionRequest, IntegratedInspectionService,
)
from vstacklens.products import store
from vstacklens.products.model import SessionCredential, sanitize_public


def _parser():
    parser = argparse.ArgumentParser(description="VStackLens 实验单次综合巡检；不会自动准备数据库。")
    parser.add_argument("--db", type=Path, required=True, help="明确选择的数据库；请先使用隔离库验收")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("prepare-db", help="显式备份、验证恢复并添加产品结构")
    add = commands.add_parser("add-target", help="新增独立产品档案，不保存运行凭据")
    add.add_argument("--product", choices=("vcenter", "nsx", "avi"), required=True)
    add.add_argument("--name", required=True)
    add.add_argument("--address", required=True)
    add.add_argument("--customer", required=True)
    add.add_argument("--site", default="未指定站点")
    add.add_argument("--customer-id")
    listing = commands.add_parser("list-targets", help="只读列出稳定目标 ID")
    listing.add_argument("--product", choices=("vcenter", "nsx", "avi"))
    listing.add_argument("--customer-id")
    run = commands.add_parser("run", help="按明确目标 ID 执行一次巡检；不会加入批量或计划")
    run.add_argument("target_ids", nargs="+")
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--title", default="VStackLens 综合巡检报告")
    run.add_argument("--experimental", action="store_true", help="明确使用待真实业务验收的 NSX／AVI 实验能力")
    run.add_argument("--allow-untrusted-lab", action="append", default=[], metavar="TARGET_ID",
                     help="仅对指定目标明确接受实验自签名证书，可重复；传输层只允许两个授权实验地址")
    return parser


def _emit(value, *, error=False):
    print(json.dumps(sanitize_public(value), ensure_ascii=False), file=sys.stderr if error else sys.stdout)


def _hidden_password(prompt):
    # getpass otherwise falls back to echoed stdin in a redirected terminal.
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            return getpass.getpass(prompt)
        except getpass.GetPassWarning:
            raise ValueError("当前终端不支持隐藏密码输入，请在本机交互终端重新运行。") from None


def _run(args):
    if not store.schema_ready(args.db):
        raise ValueError("产品结构尚未显式准备，请先对选定隔离库执行 prepare-db。")
    if len(set(args.target_ids)) != len(args.target_ids):
        raise ValueError("目标 ID 重复，请分别选择一次。")
    known = {target.target_id: target for target in store.list_targets(args.db)}
    if any(target_id not in known for target_id in args.target_ids):
        raise ValueError("所选目标不存在，请先 list-targets 并使用稳定 ID。")
    targets = [known[target_id] for target_id in args.target_ids]
    if any(not target.enabled for target in targets):
        raise ValueError("所选目标已停用，请先检查环境档案。")
    if len({target.customer_id for target in targets}) != 1:
        raise ValueError("一次综合巡检只能选择同一客户的目标。")
    if any(target.product in {"nsx", "avi"} for target in targets) and not args.experimental:
        raise ValueError("NSX／AVI 业务能力仍待真实验收，请明确使用 --experimental。")
    lab_ids = set(args.allow_untrusted_lab)
    if not lab_ids <= set(args.target_ids):
        raise ValueError("实验 TLS 选项只能指定本次选择的目标 ID。")
    for target in targets:
        if target.target_id in lab_ids and (target.product, target.host, target.port) not in {
            ("nsx", "192.0.2.110", 443), ("avi", "192.0.2.109", 443),
        }:
            raise ValueError("接受未验证证书仅授权给指定 NSX／AVI 实验地址，不能用于此目标。")
    credentials = {}
    known_secrets = []
    cancelled = threading.Event()
    previous_handler = None
    handler_installed = threading.current_thread() is threading.main_thread()
    try:
        for target in targets:
            username = input(f"{target.name} ({target.product}) 本次用户名：").strip()
            password = _hidden_password(f"{target.name} 本次密码（隐藏输入）：")
            known_secrets.append(password)
            credentials[target.target_id] = SessionCredential(
                username, password, allow_untrusted_lab=target.target_id in lab_ids,
            )
            if target.product == "avi":
                credentials[target.target_id].tenant = input(f"{target.name} 租户 [admin]：").strip() or "admin"
        if handler_installed:
            previous_handler = signal.signal(signal.SIGINT, lambda *_: cancelled.set())
        result = IntegratedInspectionService().run(
            IntegratedInspectionRequest(args.db, args.output, targets, credentials,
                                        report_title=args.title, experimental=args.experimental),
            cancel_requested=cancelled.is_set,
        )
        _emit({"run_id": result.run_id, "state": result.state,
               "modules": [{"target_id": module["target_id"], "product": module["product"],
                            "collection_state": module.get("collection_state"),
                            "analysis_state": module.get("analysis_state"),
                            "delivery_state": module.get("delivery_state"),
                            "verification_level": module.get("verification_level"),
                            "status_summary": module.get("status_summary", {})} for module in result.modules],
               "published": {"html": bool(result.report_path and result.report_path.is_file()),
                             "docx": bool(result.docx_path and result.docx_path.is_file()),
                             "pdf": bool(result.pdf_path and result.pdf_path.is_file())},
               "diagnostic_available": bool(result.diagnostic_path and result.diagnostic_path.is_file())})
        return {"completed": 0, "partial": 2, "cancelled": 130}.get(result.state, 3)
    except Exception as exc:
        # Keep the secret values only until this one error has been redacted.
        _emit(sanitize_public({"state": "failed", "error_type": type(exc).__name__,
                               "reason": str(exc)}, known_secrets), error=True)
        return 3
    finally:
        if handler_installed and previous_handler is not None:
            signal.signal(signal.SIGINT, previous_handler)
        for credential in credentials.values():
            credential.clear()
        credentials.clear()
        known_secrets.clear()


def main(argv=None):
    args = _parser().parse_args(argv)
    try:
        if args.command == "prepare-db":
            store.ensure_product_schema(args.db)
            _emit({"state": "ready", "explicit_schema_preparation": True})
        elif args.command == "list-targets":
            _emit([{"target_id": target.target_id, "product": target.product,
                    "customer_id": target.customer_id, "customer": target.customer_name,
                    "site_id": target.site_id, "site": target.site_name, "name": target.name,
                    "address": target.address, "enabled": target.enabled}
                   for target in store.list_targets(args.db, product=args.product, customer_id=args.customer_id)])
        elif args.command == "add-target":
            if not store.schema_ready(args.db):
                raise ValueError("产品结构尚未显式准备，请先对选定隔离库执行 prepare-db。")
            arguments = dict(name=args.name, address=args.address, customer_name=args.customer,
                             site_name=args.site, customer_id=args.customer_id)
            if args.product == "vcenter":
                from vstacklens.application.environment_archive import save_archive
                target_id = save_archive(args.db, **arguments)
            else:
                target_id = store.save_target(args.db, product=args.product, **arguments)
            _emit({"target_id": target_id, "product": args.product})
        else:
            return _run(args)
        return 0
    except KeyboardInterrupt:
        _emit({"state": "cancelled", "reason": "用户取消，本次运行凭据已清理。"}, error=True)
        return 130
    except Exception as exc:
        _emit({"state": "failed", "error_type": type(exc).__name__, "reason": str(exc)}, error=True)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
