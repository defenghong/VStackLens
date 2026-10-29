"""Product selection and results inside the existing warm desktop workbench.

Operate: select explicit archived targets, enter one target's credentials at a
 time, and inspect saved evidence. Existing vCenter-only execution stays intact.
"""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import json
import hashlib
import sqlite3
import os

from PySide6.QtCore import Qt, QThread, Signal, QObject, QEvent, QTimer
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QLineEdit, QLabel,
    QCheckBox, QTabWidget, QListWidget, QListWidgetItem, QTextEdit,
    QTableWidgetItem, QMessageBox, QSplitter,
)

from vstacklens.application.connection_probe import redact_sensitive
from vstacklens.desktop.layout3a import button, page_layout, table, fill_table
from vstacklens.desktop.presentation import local_time, ui_text
from vstacklens.desktop.widgets import NoWheelComboBox, muted_label
from vstacklens.products.model import SessionCredential
from vstacklens.products.management_scope import scope_label, module_scope, scoped_checks, MANAGEMENT_SCOPE_ID, SCOPE_SCHEMA_VERSION

class _ProductResultRowSizer(QObject):
    """Coalesce row sizing until this result table has its visible column widths."""

    def __init__(self, table):
        super().__init__(table)
        self._table = table
        self._scroll_value = None
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._resize_visible_rows)
        table.installEventFilter(self)
        table.viewport().installEventFilter(self)
        table.horizontalHeader().sectionResized.connect(self.schedule)

    def schedule(self, *_args, scroll_value=None):
        if scroll_value is not None:
            self._scroll_value = scroll_value
        self._timer.start(0)

    def eventFilter(self, watched, event):
        if event.type() in (QEvent.Show, QEvent.Resize):
            self.schedule()
        return super().eventFilter(watched, event)

    def _resize_visible_rows(self):
        table = self._table
        if not table.isVisible():
            return
        bar = table.verticalScrollBar()
        position = bar.value() if self._scroll_value is None else self._scroll_value
        self._scroll_value = None
        table.resizeRowsToContents()
        bar.setValue(min(position, bar.maximum()))


PRODUCT_NAMES = {"vcenter": "vCenter / vSAN", "nsx": scope_label("nsx"), "avi": scope_label("avi")}
LEGACY_PRODUCT_NAMES = {"vcenter": "vCenter / vSAN", "nsx": "NSX", "avi": "AVI"}
STATUS_NAMES = {
    "normal": "正常", "abnormal": "异常", "attention": "需要关注",
    "not_deployed": "未部署", "not_applicable": "不适用",
    "permission_denied": "权限不足", "unsupported": "接口不支持",
    "collection_failed": "采集失败", "insufficient_data": "数据不足",
    "cancelled": "已取消",
}
LAB_HOSTS = {"nsx": "192.0.2.110", "avi": "192.0.2.109"}
VERIFICATION_NAMES = {
    "fixture": "离线样本", "simulated": "模拟样本", "offline_replay": "离线重放",
    "unverified": "未验证", "live_observed": "本次读取（未逐项对照）",
    "live_compared": "实验环境已对照", "lab_live": "实验环境实测",
    "pending_live_comparison": "待实验环境对照", "live_business_validated": "业务场景已验证",
}
COMPLETENESS_NAMES = {"complete": "完整", "partial": "部分数据", "incomplete": "不完整", "missing": "缺失"}


def product_result_name(module):
    """Marked results use the published scope; unmarked history keeps its name."""
    product = module.get("product", "")
    try:
        scope = module_scope(module) if product in {"nsx", "avi"} else None
    except ValueError:
        return LEGACY_PRODUCT_NAMES.get(product, product) + "（范围待确认）"
    return scope.label if scope else LEGACY_PRODUCT_NAMES.get(product, product)


def verification_label(value):
    return VERIFICATION_NAMES.get(value, "未确认验证层级")


def execution_label(value):
    return {"pending": "待处理", "not_started": "未开始", "not_run": "未执行", "completed": "完成",
            "partial": "部分完成", "failed": "失败", "cancelled": "已取消", "running": "进行中",
            "diagnostic_only": "仅失败诊断"}.get(value, ui_text(value))


def product_schema_ready(db_path):
    """Opening a page never creates or migrates a database."""
    from vstacklens.products.store import schema_ready
    try:
        return schema_ready(db_path)
    except (sqlite3.Error, OSError):
        return False


class IntegratedInspectionWorker(QThread):
    progress = Signal(object)
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, service, request):
        super().__init__()
        self.service = service
        self.request = request

    def request_cancel(self):
        self.requestInterruption()

    def run(self):
        secrets = tuple(c.password for c in self.request.credentials.values() if c.password)
        try:
            result = self.service.run(self.request, progress_callback=self.progress.emit,
                                      cancel_requested=self.isInterruptionRequested)
            self.completed.emit(result)
        except Exception as exc:  # Keep errors local and credentials out of Qt signals.
            self.failed.emit(redact_sensitive(exc, *secrets))
        finally:
            for credential in self.request.credentials.values():
                credential.clear()
            self.request.credentials.clear()


class ProductConnectionTabs(QTabWidget):
    """Hidden product forms do not stretch the current vCenter editor."""
    def sizeHint(self):
        hint = super().sizeHint()
        current = self.currentWidget()
        if current is not None:
            hint.setHeight(current.sizeHint().height() + self.tabBar().sizeHint().height() + 4)
        return hint

    def minimumSizeHint(self):
        hint = super().minimumSizeHint()
        current = self.currentWidget()
        if current is not None:
            hint.setHeight(current.minimumSizeHint().height() + self.tabBar().minimumSizeHint().height() + 4)
        return hint


class ProductInspectionMixin:
    def _product_task_label(self, run_id):
        """Reuse the report center's stable display label, never allocate IDs."""
        if not run_id or not product_schema_ready(self._db_path()):
            return None
        from vstacklens.products import store
        if any(row["run_id"] == run_id for row in store.list_runs(self._db_path())):
            return "任务 · " + hashlib.sha256(str(run_id).encode()).hexdigest()[:8]
        return None

    def _available_product_reports(self, run_id, run=None):
        """Only a successful registration and an existing file enable delivery."""
        from vstacklens.products import store
        if run is None:
            run = store.load_run(self._db_path(), run_id) if run_id and product_schema_ready(self._db_path()) else None
        formats = {}
        for report in (run or {}).get("reports", []):
            label = {"html": "HTML", "docx": "Word", "pdf": "PDF"}.get(str(report.get("format", "")).lower())
            path = Path(report.get("path") or "")
            if label and report.get("status") == "success" and path.is_file():
                formats[label] = path
        return formats

    def _sync_product_customer_context(self):
        """Display checked archive identities without consuming the VC draft."""
        if not hasattr(self, "customer_input") or not hasattr(self, "product_scope_checks"):
            return
        product_only = self._has_product_scope() and not self.product_scope_checks["vcenter"].isChecked()
        saved = getattr(self, "_product_customer_draft", None)
        legacy_id = getattr(self, "_inspection_environment_id", None)
        if product_only:
            if saved is None:
                saved = dict(customer=self.customer_input.text(), site=self.site_input.text(),
                             customer_tip=self.customer_input.toolTip(), site_tip=self.site_input.toolTip(),
                             customer_placeholder=self.customer_input.placeholderText(),
                             customer_readonly=self.customer_input.isReadOnly(), site_readonly=self.site_input.isReadOnly(),
                             environment_id=legacy_id)
                self._product_customer_draft = saved
            elif saved["environment_id"] != legacy_id:
                # A VC selection changed underneath the product-only overlay.
                # Keep the original manual draft/tips, not the overlaid product fields.
                env = next((e for e in getattr(self, "_environment_archives", []) if e.environment_id == legacy_id), None)
                saved = {**saved, "environment_id": legacy_id, "customer_readonly": bool(env)}
                if env:
                    saved.update(customer=env.customer_name, site=env.site_name)
                self._product_customer_draft = saved
            targets = self._selected_product_targets()
            customers = {t.customer_id for t in targets}
            if len(customers) == 1:
                self.customer_input.setText(targets[0].customer_name)
                self.site_input.setText(" / ".join(dict.fromkeys(t.site_name for t in targets)))
            elif targets:
                self.customer_input.setText("多个客户，请调整目标")
                self.site_input.clear()
            else:
                self.customer_input.clear(); self.site_input.clear()
            tip = "客户及站点由勾选的产品档案确定；修改归属请到环境档案。"
            self.customer_input.setReadOnly(True); self.site_input.setReadOnly(True)
            self.customer_input.setPlaceholderText("选择产品目标后显示档案客户")
            self.customer_input.setToolTip(tip); self.site_input.setToolTip(tip)
        elif saved is not None:
            env = next((e for e in getattr(self, "_environment_archives", []) if e.environment_id == legacy_id), None)
            same_legacy = saved["environment_id"] == legacy_id
            self.customer_input.setText(saved["customer"] if same_legacy or not env else env.customer_name)
            self.site_input.setText(saved["site"] if same_legacy or not env else env.site_name)
            self.customer_input.setReadOnly(saved["customer_readonly"] if same_legacy else bool(env))
            self.site_input.setReadOnly(saved["site_readonly"])
            self.customer_input.setPlaceholderText(saved["customer_placeholder"])
            self.customer_input.setToolTip(saved["customer_tip"]); self.site_input.setToolTip(saved["site_tip"])
            self._product_customer_draft = None

    def _product_snapshot_name(self, run, target):
        product = target.get("product", "")
        module = next((m for m in run.get("modules", []) if m.get("target_id") == target.get("target_id") and m.get("product") == product), {"product": product})
        return product_result_name(module)

    def _product_run_kind(self, run):
        modules = run.get("modules", [])
        scopes = []
        for module in modules:
            if module.get("product") not in {"nsx", "avi"}:
                return "综合巡检"
            try:
                scope = module_scope(module)
                scoped_checks(module)
            except ValueError:
                return "范围待核对"
            if scope is None:
                return "综合巡检"
            scopes.append(scope)
        if len(scopes) == 1:
            return scopes[0].label
        return "管理端综合巡检" if scopes else "综合巡检"

    def _product_context_text(self):
        """Read current or frozen product identities for the common context bar."""
        if not product_schema_ready(self._db_path()):
            return None
        from vstacklens.products import store
        active = getattr(self, "_active_module", "")
        if active not in {"dashboard", "report_center", "inspection_center"}:
            return None
        if active == "inspection_center" and (self.inspection_pages.currentIndex() not in {1, 4}
                or self.inspection_pages.currentIndex() == 1 and not self._has_product_scope()):
            return None
        if active == "inspection_center" and self.inspection_pages.currentIndex() == 1 and self._has_product_scope():
            targets = self._selected_product_targets()
            parts = [f"{PRODUCT_NAMES[t.product]} · {t.customer_name} / {t.site_name} · {t.name} · {t.host}" for t in targets]
            if self.product_scope_checks["vcenter"].isChecked():
                parts.insert(0, f"vCenter · {self.customer_input.text()} / {self.site_input.text()} · {self.vcenter_input.text() or '待填写目标'}")
            return "本次巡检目标：" + ("；".join(parts) or "尚未勾选产品档案")
        run = None
        target_id = getattr(self, "_product_scope_target_id", None)
        if active == "inspection_center" and self.inspection_pages.currentIndex() == 4:
            run_id = self.product_result_run.currentData()
            run = store.load_run(self._db_path(), run_id) if run_id else None
            if not run:
                return "产品结果 · 当前范围尚无巡检记录"
        elif active == "report_center":
            item = self._selected_report_item()
            if self._is_product_report_item(item):
                run = self._integrated_report_runs.get(item.run_id)
            elif item is not None:
                return None
        if run:
            targets = [t for t in run.get("targets", []) if not target_id or t.get("target_id") == target_id]
            parts = [f"{self._product_snapshot_name(run, t)} · {t.get('customer_name', '—')} / {t.get('site_name', '—')} · {t.get('name', '—')} · {t.get('host', '—')}" for t in targets]
            return f"{self._short_task(run.get('run_id'))} · " + ("；".join(parts) or "目标记录不足")
        if target_id:
            target = next((t for t in store.list_targets(self._db_path(), include_vcenter=False) if t.target_id == target_id), None)
            if target:
                return f"产品档案：{PRODUCT_NAMES.get(target.product, target.product)} · {target.customer_name} / {target.site_name} · {target.name} · {target.host}"
        if not getattr(getattr(self, "_overview", None), "has_data", False):
            runs = store.list_runs(self._db_path())
            if runs:
                latest = store.load_run(self._db_path(), runs[0]["run_id"])
                targets = (latest or {}).get("targets", [])
                parts = [f"{self._product_snapshot_name(latest, t)} · {t.get('customer_name', '—')} / {t.get('name', '—')}" for t in targets]
                return f"最近产品巡检：{self._short_task(runs[0]['run_id'])} · " + ("；".join(parts) or "目标记录不足")
        return None

    def _build_product_scope(self, card, vcenter_form):
        self._product_credentials = {}
        self._product_targets = []
        self._product_forms = {}
        self._product_loaded_ids = {"nsx": None, "avi": None}
        self._product_form_loading = False
        self._product_result_run_id = None
        self._product_scope_target_id = None
        self._integrated_report_runs = {}
        self._integrated_report_formats = {}
        scope = QHBoxLayout()
        scope.addWidget(QLabel("巡检范围"))
        self.product_scope_checks = {}
        for product, title in PRODUCT_NAMES.items():
            control = QCheckBox(title)
            control.setChecked(product == "vcenter")
            control.toggled.connect(self._product_scope_changed)
            self.product_scope_checks[product] = control
            scope.addWidget(control)
        scope.addStretch(1)
        card.layout.addLayout(scope)
        self.product_connection_tabs = ProductConnectionTabs()
        self.product_connection_tabs.currentChanged.connect(lambda _index: self.product_connection_tabs.updateGeometry())
        self.product_connection_tabs.setDocumentMode(True)
        legacy = QWidget(); legacy.setLayout(vcenter_form)
        self.product_connection_tabs.addTab(legacy, "vCenter / vSAN")
        for product in ("nsx", "avi"):
            panel = QWidget(); layout = QVBoxLayout(panel)
            layout.setContentsMargins(0, 8, 0, 0)
            targets = QListWidget(); targets.setMinimumHeight(64); targets.setMaximumHeight(104)
            targets.setSelectionMode(QListWidget.SingleSelection)
            targets.itemChanged.connect(lambda item, p=product: self._product_target_checked(p, item))
            targets.currentItemChanged.connect(lambda current, previous, p=product: self._product_target_changed(p, current, previous))
            layout.addWidget(muted_label("勾选本次目标，点选一行填写该目标的连接凭据。"))
            layout.addWidget(targets)
            fields = QFormLayout()
            address = QLineEdit(); address.setReadOnly(True); address.setPlaceholderText("先在环境档案登记目标")
            username = QLineEdit(); password = QLineEdit(); password.setEchoMode(QLineEdit.Password)
            password.setPlaceholderText("仅本次运行，按目标独立保存于内存")
            tenant = QLineEdit("admin")
            for title, field in (("地址", address), ("用户名", username), ("密码", password)):
                fields.addRow(title, field)
            if product == "avi":
                fields.addRow("租户", tenant)
            else:
                tenant.hide()
            lab = QCheckBox("实验连接：接受此目标的自签名证书")
            lab.setToolTip("仅授权的 NSX .110 或 AVI .109 实验地址可用；本次不验证对端身份。")
            lab.setEnabled(False)
            fields.addRow("", lab)
            layout.addLayout(fields)
            layout.addWidget(button("登记产品目标", lambda checked=False, p=product: self._open_product_registration(p)))
            self._product_forms[product] = dict(targets=targets, address=address, username=username,
                                                 password=password, tenant=tenant, lab=lab)
            for field in (username, password, tenant):
                field.textChanged.connect(lambda _text, p=product: self._remember_product_credential(p))
            lab.toggled.connect(lambda _checked, p=product: self._remember_product_credential(p))
            self.product_connection_tabs.addTab(panel, PRODUCT_NAMES[product])
            self.product_connection_tabs.setTabVisible(self.product_connection_tabs.count() - 1, False)
        card.layout.addWidget(self.product_connection_tabs)
        self.product_experimental_hint = muted_label("NSX / AVI 为实验能力；本次运行不会进入批量或计划巡检。")
        self.product_experimental_hint.hide(); card.layout.addWidget(self.product_experimental_hint)

    def _product_scope_changed(self, *_args):
        self._reset_product_current_result()
        if not hasattr(self, "product_connection_tabs"):
            return
        products = list(PRODUCT_NAMES)
        for index, product in enumerate(products):
            self.product_connection_tabs.setTabVisible(index, self.product_scope_checks[product].isChecked())
        selected = [i for i, p in enumerate(products) if self.product_scope_checks[p].isChecked()]
        if selected and not self.product_connection_tabs.isTabVisible(self.product_connection_tabs.currentIndex()):
            self.product_connection_tabs.setCurrentIndex(selected[0])
        self.product_experimental_hint.setVisible(any(self.product_scope_checks[p].isChecked() for p in ("nsx", "avi")))
        self._sync_product_customer_context()
        if hasattr(self, "scope_label"):
            self._update_task_summary()
        if hasattr(self, "current_object_label"):
            self._update_current_object_bar()

    def _reset_product_current_result(self):
        if self._running or not hasattr(getattr(self, "current_result", None), "modules"):
            return
        self.current_result = None
        self._standard_presentation()
        for control in (self.open_report_button, self.open_word_button, self.open_pdf_button, self.open_dir_button):
            control.setEnabled(False)

    def _has_product_scope(self):
        return any(control.isChecked() for key, control in getattr(self, "product_scope_checks", {}).items() if key != "vcenter")

    def _open_product_registration(self, product):
        self.go_to_module("vcenter_management")
        self._edit_environment(None)
        self.environment_product_input.setCurrentIndex(self.environment_product_input.findData(product))

    def _remember_product_credential(self, product):
        if self._product_form_loading:
            return
        target_id = self._product_loaded_ids.get(product)
        if not target_id:
            return
        fields = self._product_forms[product]
        old = self._product_credentials.pop(target_id, None)
        if old:
            old.clear()
        self._product_credentials[target_id] = SessionCredential(
            username=fields["username"].text(), password=fields["password"].text(),
            tenant=fields["tenant"].text() or "admin", allow_untrusted_lab=fields["lab"].isChecked(),
        )

    def _product_target_changed(self, product, current, previous):
        self._remember_product_credential(product)
        target_id = current.data(Qt.UserRole) if current else None
        self._product_loaded_ids[product] = target_id
        target = next((t for t in self._product_targets if t.target_id == target_id), None)
        fields = self._product_forms[product]
        saved = self._product_credentials.get(target_id)
        self._product_form_loading = True
        try:
            fields["address"].setText((f"{target.host}:{target.port}" if target.port != 443 else target.host) if target else "")
            fields["username"].setText(saved.username if saved else target.username if target else "")
            fields["password"].setText(saved.password if saved else "")
            fields["tenant"].setText(saved.tenant if saved else "admin")
            allowed = bool(target and target.host == LAB_HOSTS[product] and target.port == 443)
            fields["lab"].setEnabled(allowed and not self._running)
            fields["lab"].setChecked(bool(allowed and saved and saved.allow_untrusted_lab))
        finally:
            self._product_form_loading = False
        self._sync_product_customer_context()
        if hasattr(self, "current_object_label"):
            self._update_current_object_bar()

    def _product_target_checked(self, product, item):
        if self._product_form_loading:
            return
        self._reset_product_current_result()
        if item.checkState() != Qt.Checked:
            target_id = item.data(Qt.UserRole)
            credential = self._product_credentials.pop(target_id, None)
            if credential:
                credential.clear()
            if self._product_loaded_ids.get(product) == target_id:
                self._product_forms[product]["password"].clear()
        self._sync_product_customer_context()
        if hasattr(self, "scope_label"):
            self._update_task_summary()
        if hasattr(self, "current_object_label"):
            self._update_current_object_bar()

    def _clear_product_credentials(self):
        self._product_form_loading = True
        try:
            for credential in getattr(self, "_product_credentials", {}).values():
                credential.clear()
            self._product_credentials = {}
            for fields in getattr(self, "_product_forms", {}).values():
                fields["password"].clear()
                fields["username"].clear()
                fields["tenant"].setText("admin")
                fields["lab"].setChecked(False)
        finally:
            self._product_form_loading = False

    def _set_product_controls_running(self, running):
        for control in self.product_scope_checks.values():
            control.setEnabled(not running)
        self.product_connection_tabs.setEnabled(not running)
        if not running:
            for product, fields in self._product_forms.items():
                target = next((t for t in self._product_targets if t.target_id == self._product_loaded_ids.get(product)), None)
                fields["lab"].setEnabled(bool(target and target.host == LAB_HOSTS[product] and target.port == 443))

    def _populate_product_targets(self):
        if not hasattr(self, "_product_forms"):
            return
        from vstacklens.products import store
        old_targets = {t.target_id: (t.customer_id, t.site_id, t.host, t.port, t.username) for t in self._product_targets}
        targets = store.list_targets(self._db_path(), include_vcenter=False) if product_schema_ready(self._db_path()) else []
        targets = [t for t in targets if t.enabled and t.product in {"nsx", "avi"}]
        for target_id, credential in list(self._product_credentials.items()):
            target = next((t for t in targets if t.target_id == target_id), None)
            if not target or old_targets.get(target_id) != (target.customer_id, target.site_id, target.host, target.port, target.username):
                credential.clear(); self._product_credentials.pop(target_id, None)
                if target_id in self._product_loaded_ids.values():
                    self._product_form_loading = True
                    for p, loaded in self._product_loaded_ids.items():
                        if loaded == target_id:
                            self._product_forms[p]["password"].clear()
                    self._product_form_loading = False
        self._product_targets = targets
        for product, fields in self._product_forms.items():
            widget = fields["targets"]
            checked = {widget.item(i).data(Qt.UserRole) for i in range(widget.count()) if widget.item(i).checkState() == Qt.Checked}
            current = self._product_loaded_ids.get(product)
            widget.blockSignals(True); widget.clear()
            for target in targets:
                if target.product != product:
                    continue
                item = QListWidgetItem(f"{target.customer_name} / {target.name} · {target.host}")
                item.setData(Qt.UserRole, target.target_id)
                item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                item.setCheckState(Qt.Checked if target.target_id in checked else Qt.Unchecked)
                item.setToolTip(f"{target.name} · {target.host}\n{target.customer_name} / {target.site_name}\n{target.target_id}")
                widget.addItem(item)
                if target.target_id == current:
                    widget.setCurrentItem(item)
            if widget.currentRow() < 0 and widget.count():
                widget.setCurrentRow(0)
            widget.blockSignals(False)
            self._product_target_changed(product, widget.currentItem(), None)
        self._populate_product_result_targets()

    def _selected_product_targets(self):
        selected = set()
        for product, fields in self._product_forms.items():
            if not self.product_scope_checks[product].isChecked():
                continue
            widget = fields["targets"]
            selected.update(widget.item(i).data(Qt.UserRole) for i in range(widget.count()) if widget.item(i).checkState() == Qt.Checked)
        return [t for t in self._product_targets if t.target_id in selected]

    def _start_product_inspection(self):
        if self.worker is not None or self._running or self._batch_closing:
            return
        from vstacklens.application.integrated_inspection import IntegratedInspectionRequest, IntegratedInspectionService
        from vstacklens.products import store
        if not product_schema_ready(self._db_path()):
            QMessageBox.warning(self, "产品档案尚未启用", "请先在环境档案中点击“启用产品档案”。该操作会保存恢复副本并验证新增结构。")
            return
        for product in self._product_forms:
            self._remember_product_credential(product)
        targets = self._selected_product_targets()
        errors = []
        for product in ("nsx", "avi"):
            if self.product_scope_checks[product].isChecked() and not any(t.product == product for t in targets):
                errors.append(f"请勾选至少一个 {PRODUCT_NAMES[product]} 目标。")
        cfg = self._current_config()
        if self.product_scope_checks["vcenter"].isChecked():
            errors.extend(self.service.validate_config(cfg))
            if not errors:
                env_id = self._inspection_environment_id
                if not env_id:
                    env_id = self.service.save_environment_archive(self._db_path(), name=cfg.vcenter,
                        customer_name=cfg.customer_name, site_name=cfg.site_name, address=cfg.vcenter, username="")
                target = next((t for t in store.list_targets(self._db_path()) if t.product == "vcenter" and t.target_id == env_id), None)
                if target:
                    targets.insert(0, target)
                else:
                    errors.append("当前 vCenter 档案不可用，请重新选择。")
        customers = {t.customer_id for t in targets}
        if len(customers) > 1:
            errors.append("一份综合巡检报告只能选择同一客户的目标；请调整勾选范围。")
        credentials = {}
        for target in targets:
            credential = SessionCredential(cfg.username, cfg.password) if target.product == "vcenter" else self._product_credentials.get(target.target_id)
            if not credential or not credential.username.strip() or not credential.password:
                errors.append(f"请填写 {PRODUCT_NAMES[target.product]} · {target.name} 的用户名和密码。")
            elif credential:
                credentials[target.target_id] = replace(credential)
        if errors:
            for credential in credentials.values():
                credential.clear()
            QMessageBox.warning(self, "巡检资料未完成", "\n".join(errors)); return
        request = IntegratedInspectionRequest(db_path=self._db_path(), report_output_dir=cfg.report_output_dir,
            targets=targets, credentials=credentials, report_title=self.report_title_input.text().strip() or "综合巡检报告",
            rulepack_path=cfg.rulepack_path, experimental=True)
        self.current_result = None
        self._standard_presentation()
        self._running = True
        self.start_button.setEnabled(False)
        self.cancel_inspection_button.setEnabled(True); self.cancel_inspection_button.show()
        for control in (self.open_report_button, self.open_word_button, self.open_pdf_button, self.open_dir_button):
            control.setEnabled(False)
        self.inspection_environment_combo.setEnabled(False)
        self._set_product_controls_running(True)
        self.progress_bar.setValue(0); self.stage_label.setText("准备综合巡检")
        self.status_label.setText("各目标独立采集；当前 NSX / AVI 能力按实验状态记录。")
        self.result_summary.clear()
        self.worker = IntegratedInspectionWorker(IntegratedInspectionService(legacy_service=self.service), request)
        self.worker.progress.connect(self._inspection_progress)
        self.worker.completed.connect(self._product_inspection_completed)
        self.worker.failed.connect(self._inspection_failed)
        self.worker.finished.connect(self._worker_finished)
        self._clear_product_credentials(); self.password_input.clear()
        self.worker.start()

    def _product_inspection_completed(self, result):
        self.current_result = result
        self._product_result_run_id = result.run_id
        self.progress_bar.setValue(100)
        self.stage_label.setText("巡检已取消" if result.state == "cancelled" else "综合巡检已结束")
        self.status_label.setText("各产品的执行、数据完整性和验证层级见产品结果；未验证能力不计为通过。")
        formats = self._available_product_reports(result.run_id)
        self.open_report_button.setEnabled("HTML" in formats)
        self.open_word_button.setEnabled("Word" in formats)
        self.open_pdf_button.setEnabled("PDF" in formats)
        self.open_dir_button.setEnabled(result.report_dir.is_dir())
        self.cancel_inspection_button.setEnabled(False); self.cancel_inspection_button.hide()
        self.view_standard_report_button.setEnabled(any(c.isEnabled() for c in (self.open_report_button, self.open_word_button, self.open_pdf_button)))
        lines = [f"任务：{result.run_id}"]
        for module in result.modules:
            lines.append(f"{product_result_name(module)} · {module['target_name']}：采集 {execution_label(module['collection_state'])} / 分析 {execution_label(module['analysis_state'])} / 交付 {execution_label(module['delivery_state'])}")
        for name in ("html_error", "docx_error", "pdf_error"):
            if getattr(result, name, ""):
                lines.append(getattr(result, name))
        self.result_summary.append("\n".join(lines))
        self.scope_label.setText("\n".join(lines[:len(result.modules) + 1]))
        self.scope_hint.setText("不计算跨产品总分；请核对每项来源、时间与覆盖限制。")
        self.standard_summary.layout.itemAt(0).widget().setText("结果摘要")
        self._refresh_all_data()
        self._populate_product_results()

    def _product_results_page(self):
        page, layout = page_layout("产品结果")
        layout.addWidget(muted_label("NSX / AVI 与综合任务的已保存证据；历史记录不代表实时状态。"))
        filters = QHBoxLayout()
        self.product_result_target = NoWheelComboBox(); self.product_result_target.addItem("全部产品目标", None)
        self.product_result_target.currentIndexChanged.connect(self._populate_product_result_runs)
        self.product_result_run = NoWheelComboBox(); self.product_result_run.currentIndexChanged.connect(self._populate_product_results)
        self.product_result_status = NoWheelComboBox(); self.product_result_status.addItem("全部结论", None)
        for value, label in STATUS_NAMES.items():
            self.product_result_status.addItem(label, value)
        self.product_result_status.currentIndexChanged.connect(self._populate_product_results)
        filters.addWidget(self.product_result_target, 2); filters.addWidget(self.product_result_run, 2); filters.addWidget(self.product_result_status)
        filters.addWidget(button("刷新结果", self._populate_product_result_runs)); layout.addLayout(filters)
        self.product_result_summary = muted_label("尚无产品巡检记录。选择范围和产品目标，完成单次巡检后在此回查。")
        layout.addWidget(self.product_result_summary)
        self.product_result_table = table(self, ["产品 / 目标", "检查项", "结论", "采集时间", "验证层级"])
        self._product_result_row_sizer = _ProductResultRowSizer(self.product_result_table)
        self.product_result_table.currentCellChanged.connect(self._product_check_selected)
        self.product_result_detail = QTextEdit(); self.product_result_detail.setReadOnly(True)
        splitter = QSplitter(Qt.Vertical); splitter.addWidget(self.product_result_table); splitter.addWidget(self.product_result_detail)
        splitter.setSizes([360, 180]); layout.addWidget(splitter, 1)
        return page

    def _populate_product_result_targets(self):
        if not hasattr(self, "product_result_target"):
            return
        control = self.product_result_target; old = self._product_scope_target_id or control.currentData()
        control.blockSignals(True); control.clear(); control.addItem("全部产品目标", None)
        from vstacklens.products import store
        targets = store.list_targets(self._db_path(), include_vcenter=False) if product_schema_ready(self._db_path()) else []
        for target in targets:
            control.addItem(f"{PRODUCT_NAMES.get(target.product, target.product)} · {target.customer_name} / {target.name}", target.target_id)
        control.setCurrentIndex(max(0, control.findData(old))); control.blockSignals(False)
        self._populate_product_result_runs()

    def _populate_product_result_runs(self, *_args):
        if not hasattr(self, "product_result_run"):
            return
        from vstacklens.products import store
        target_id = self.product_result_target.currentData()
        self._product_scope_target_id = target_id
        rows = store.list_runs(self._db_path(), target_id=target_id) if product_schema_ready(self._db_path()) else []
        control = self.product_result_run; old = self._product_result_run_id or control.currentData()
        control.blockSignals(True); control.clear()
        for row in rows:
            run_id = row["run_id"]
            control.addItem(f"{local_time(row.get('started_at', ''))} · {self._short_task(run_id)}", run_id)
            control.setItemData(control.count() - 1, run_id, Qt.ToolTipRole)
        control.setCurrentIndex(max(0, control.findData(old)) if rows else -1)
        control.blockSignals(False); self._populate_product_results()

    def _populate_product_results(self, *_args):
        if not hasattr(self, "product_result_table"):
            return
        from vstacklens.products import store
        run_id = self.product_result_run.currentData()
        table = self.product_result_table
        old_checks = getattr(self, "_product_result_checks", [])
        old_row = table.currentRow()
        same_run = getattr(self, "_product_result_displayed_run_id", None) == run_id
        old_key = (old_checks[old_row][0]["target_id"], old_checks[old_row][1]["check_id"]) if same_run and 0 <= old_row < len(old_checks) else None
        old_scroll = table.verticalScrollBar().value()
        self._product_result_run_id = run_id
        self._product_result_displayed_run_id = run_id
        run = store.load_run(self._db_path(), run_id) if run_id and product_schema_ready(self._db_path()) else None
        selected = self.product_result_target.currentData()
        status = self.product_result_status.currentData()
        checks = []
        modules = []
        scope_errors = []
        if run:
            modules = [m for m in run.get("modules", []) if not selected or m["target_id"] == selected]
            for module in modules:
                try:
                    module_checks = scoped_checks(module)
                except ValueError as exc:
                    scope_errors.append((module, str(exc)))
                    continue
                for check in module_checks:
                    if not status or check["status"] == status:
                        checks.append((module, check))
        self._product_result_scope_errors = scope_errors
        self._product_result_checks = checks
        self.product_result_table.blockSignals(True)
        fill_table(self.product_result_table, [[f"{product_result_name(m)} · {m['target_name']}", c["title"],
                    STATUS_NAMES.get(c["status"], c["status"]), local_time(c.get("collected_at", m.get("completed_at", ""))),
                    verification_label(c.get("verification", "unverified"))] for m, c in checks])
        self.product_result_table.setMinimumHeight(120); self.product_result_table.setMaximumHeight(16777215)
        self.product_result_table.blockSignals(False)
        self.product_result_summary.setText("\n".join(self._product_target_summary_lines(run, modules)) or "尚无该范围的产品结果；未取得数据不能视为正常。")
        selected_row = next((row for row, (module, check) in enumerate(checks)
                             if (module["target_id"], check["check_id"]) == old_key), None)
        if checks:
            self.product_result_table.setCurrentCell(selected_row if selected_row is not None else 0, 0)
        self._product_result_row_sizer.schedule(scroll_value=old_scroll if selected_row is not None else 0)
        self._product_check_selected()
        if hasattr(self, "current_object_label"):
            self._update_current_object_bar()

    def _product_check_selected(self, *_args):
        row = self.product_result_table.currentRow()
        checks = getattr(self, "_product_result_checks", [])
        if not 0 <= row < len(checks):
            scope_errors = getattr(self, "_product_result_scope_errors", [])
            if scope_errors:
                self.product_result_detail.setPlainText("\n\n".join(
                    f"范围校验失败：{message}\n目标：{module.get('target_name', '—')}\n原始检查记录（未改写）：\n" + json.dumps(module.get("checks", []), ensure_ascii=False, indent=2)
                    for module, message in scope_errors))
            else:
                self.product_result_detail.clear()
            return
        module, check = checks[row]
        sources = check.get("sources", [])
        scope = module_scope(module) if module.get("product") in {"nsx", "avi"} else None
        scope_text = scope.label if scope else "历史保存范围"
        self.product_result_detail.setPlainText("\n".join([
            f"巡检范围：{scope_text}",
            f"对象：{check.get('object_name') or module['target_name']}",
            f"结论：{STATUS_NAMES.get(check['status'], check['status'])} · {check.get('summary', '')}",
            f"来源类别：{'NSX / AVI 原生告警' if check.get('judgement') == 'NATIVE' else '程序判断 / 读取值'}",
            f"判断依据：{check.get('basis', '') or '仅展示读取值'}",
            f"采集数据：{json.dumps(check.get('values', {}), ensure_ascii=False, indent=2)}",
            f"采集来源：{json.dumps(sources, ensure_ascii=False, indent=2)}",
            f"完整性：{COMPLETENESS_NAMES.get(check.get('completeness'), '未记录')}；验证层级：{verification_label(check.get('verification', 'unverified'))}（{check.get('verification', 'unverified')}）",
            f"限制：{'；'.join(check.get('limitations', [])) or '未记录'}",
            f"模块采集错误：{json.dumps(module.get('errors', []), ensure_ascii=False)}",
            f"连接身份验证：{json.dumps(module.get('transport_security', {}), ensure_ascii=False)}",
            f"原生告警（独立记录原级别）：{json.dumps(module.get('native_alerts', []), ensure_ascii=False, indent=2)}",
            f"建议：{check.get('recommendation', '')}",
        ]))

    def _show_product_results(self, target_id=None, run_id=None):
        self._product_scope_target_id = target_id
        self._product_result_run_id = run_id
        self._populate_product_result_targets()
        self.go_to_module("inspection_center")
        self.inspection_pages.setCurrentIndex(4)
        self._environment_id = None
        self._update_current_object_bar()

    def _product_report_items(self):
        from vstacklens.application.inspection_service import ReportCenterItem
        from vstacklens.products import store
        self._integrated_report_runs = {}; self._integrated_report_formats = {}
        if not product_schema_ready(self._db_path()):
            return []
        rows = store.list_runs(self._db_path(), target_id=self._product_scope_target_id) if self._product_scope_target_id else store.list_runs(self._db_path())
        result = []
        for row in rows[:80]:
            run = store.load_run(self._db_path(), row["run_id"])
            if not run:
                continue
            targets = run.get("targets", [])
            if self._environment_id and not any(t.get("target_id") == self._environment_id for t in targets):
                continue
            formats = self._available_product_reports(row["run_id"], run)
            if not formats:
                continue
            run_id = row["run_id"]; self._integrated_report_runs[run_id] = run
            self._integrated_report_formats[run_id] = formats
            first = formats.get("HTML") or next(iter(formats.values()))
            customers = {t.get("customer_name", "") for t in targets}
            sites = {t.get("site_name", "") for t in targets}
            result.append(ReportCenterItem(run_id=run_id, report_path=first, report_dir=Path(os.path.commonpath([str(path.parent) for path in formats.values()])),
                payload_path=None, title=run.get("title", row.get("title", "综合巡检报告")),
                customer_name=" / ".join(sorted(customers)), site_name=" / ".join(sorted(sites)),
                assessment_time=run.get("finished_at") or run.get("started_at", ""),
                score=None, risk_summary={}, asset_summary={}, top_risks=[], history_summary="各产品状态与验证层级独立记录；无跨产品总分。",
                status=run.get("state", ""), report_type=self._product_run_kind(run), path_hint=str(first)))
        return result

    def _is_product_report_item(self, item):
        return bool(item and item.run_id in getattr(self, "_integrated_report_runs", {}))

    def _product_target_summary_lines(self, run, modules):
        from vstacklens.desktop.environment_archive import project_product_target_run
        lines = []
        for module in modules:
            try:
                scoped_checks(module)
            except ValueError as exc:
                lines.append(f"{product_result_name(module)} · {module.get('target_name', '—')}：范围校验失败，{exc} 原始记录保留供核对。")
                continue
            summary = project_product_target_run(run, module["target_id"], product=module.get("product", ""),
                                                 customer_id=module.get("customer_id", ""))
            lines.append(f"{product_result_name(module)} · {module['target_name']}："
                         + summary["result_text"] + "；" + summary["report_text"])
        return lines

    def _product_report_selected(self, item):
        run = self._integrated_report_runs[item.run_id]
        self.report_detail.setPlainText("\n".join([f"任务：{self._short_task(item.run_id)}", f"完整任务 ID：{item.run_id}", f"综合任务状态：{execution_label(run.get('state', ''))}（不替代各目标阶段）",
            *self._product_target_summary_lines(run, run.get("modules", [])),
            "巡检范围按当次保存元数据展示；各目标阶段独立核对。",
        ]))
        self.delete_report_button.setEnabled(False)
        self.open_selected_report_button.setEnabled(bool(item.report_path and item.report_path.is_file()))
        self.open_selected_dir_button.setEnabled(item.report_dir.is_dir())
        self.report_copy_path_button.setEnabled(True)
        if hasattr(self, "current_object_label"):
            self._update_current_object_bar()


    def _merge_product_report_items(self, legacy_items):
        integrated = self._product_report_items()
        child_ids = {t.get("legacy_run_id") for run in self._integrated_report_runs.values() for t in run.get("target_runs", []) if t.get("legacy_run_id")}
        items = [item for item in legacy_items if item.run_id not in child_ids]
        return sorted(items + integrated, key=lambda item: item.assessment_time or "", reverse=True)

    def _begin_exit(self):
        self._clear_product_credentials()
        return super()._begin_exit()
