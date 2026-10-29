"""Environment entry surface, extending the incumbent PySide6 workbench.

Operate: register/select a customer environment, then enter its existing results.
Preserve the theme and sidebar; keep the list primary and open details on demand.
"""
from PySide6.QtCore import Qt, QTimer, QObject, QEvent
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QFormLayout, QLineEdit, QLabel, QPushButton, QHeaderView, QComboBox, QSizePolicy, QDialog, QScrollArea, QTableWidgetItem

from vstacklens.desktop.widgets import PageHeader, SectionCard, NoWheelComboBox, muted_label
from vstacklens.desktop.layout3a import table, fill_table, button
from vstacklens.desktop.presentation import local_time
from vstacklens.desktop.theme import SIZES


_PRODUCT_PHASE_LABELS = {
    "completed": "完成", "partial": "部分完成", "failed": "失败",
    "cancelled": "已取消", "interrupted": "已中断", "running": "进行中",
    "pending": "待处理", "not_started": "未开始", "not_run": "未执行",
    "diagnostic_only": "仅失败诊断", "missing": "记录不足", "conflict": "记录不一致",
    "unknown": "状态未知",
}
_PRODUCT_HEALTH_FORMATS = {"html": "HTML", "docx": "Word", "pdf": "PDF"}


def project_product_target_run(run, target_id, *, product="", customer_id=""):
    """Project one frozen target's evidence without borrowing another target's state."""
    from vstacklens.products.model import has_valid_data
    run = run if isinstance(run, dict) else {}
    target_rows = [row for row in (run.get("target_runs") or []) if isinstance(row, dict) and row.get("target_id") == target_id]
    modules = [module for module in (run.get("modules") or []) if isinstance(module, dict) and module.get("target_id") == target_id]
    row = target_rows[0] if len(target_rows) == 1 else {}
    module = modules[0] if len(modules) == 1 else {}
    snapshot = row.get("target") if isinstance(row.get("target"), dict) else {}
    issues = []
    if len(target_rows) != 1 or len(modules) != 1:
        issues.append("缺少唯一的本目标阶段记录或模块记录。")
    identity_conflict = bool(
        (product and (row.get("product", product) != product or module.get("product", product) != product))
        or (customer_id and (snapshot.get("customer_id", customer_id) != customer_id or module.get("customer_id", customer_id) != customer_id))
    )
    if identity_conflict:
        issues.append("目标身份或客户归属记录不一致，未采用其他目标的结果。")
    phases = {}
    for phase in ("collection", "analysis", "delivery"):
        key = phase + "_state"
        recorded, embedded = row.get(key), module.get(key)
        if identity_conflict or len(target_rows) > 1 or len(modules) > 1:
            state = "conflict"
        elif not row or not module or not recorded or not embedded:
            state = "missing"
        elif recorded != embedded:
            state = "conflict"
            issues.append({"collection": "采集", "analysis": "分析", "delivery": "交付"}[phase] + "的目标记录与模块记录不一致。")
        elif recorded not in _PRODUCT_PHASE_LABELS:
            state = "unknown"
            issues.append("存在无法识别的目标阶段，未按完成处理。")
        elif run.get("state") == "interrupted" and recorded in {"running", "pending", "not_started", "not_run"}:
            state = "interrupted"
        else:
            state = recorded
        phases[phase] = state
    try:
        valid_data = bool(module and not identity_conflict and has_valid_data(module))
    except (AttributeError, TypeError, ValueError):
        valid_data = False
        issues.append("本目标检查数据结构不完整，未确认取得有效数据。")
    only_diagnostic = bool(module and not valid_data)
    if only_diagnostic and phases["delivery"] in {"completed", "partial"}:
        phases["delivery"] = "diagnostic_only"
        issues.append("该目标未取得有效检查数据，旧交付完成记录仅按失败诊断展示。")

    reports = run.get("reports", []) if row and not identity_conflict else []
    health_records = {kind: [record for record in reports if str(record.get("format", "")).casefold() == kind]
                      for kind in _PRODUCT_HEALTH_FORMATS}
    formats, missing_files, unavailable = [], [], []
    for kind, records in health_records.items():
        label = _PRODUCT_HEALTH_FORMATS[kind]
        present = False
        for record in records:
            if record.get("status") != "success":
                continue
            try:
                exists = bool(record.get("path")) and Path(record["path"]).is_file()
            except (OSError, ValueError, TypeError):
                exists = False
            if exists:
                present = True
            else:
                missing_files.append(label)
        if present:
            formats.append(label)
        else:
            unavailable.append(label)
    json_records = [record for record in reports if str(record.get("format", "")).casefold() == "json"]
    json_available = False
    for record in json_records:
        try:
            if record.get("status") == "success" and record.get("path") and Path(record["path"]).is_file():
                json_available = True
        except (OSError, ValueError, TypeError):
            pass
    json_text = ("失败诊断 JSON" if only_diagnostic else "结构化结果 JSON") if json_available else (
        "JSON 文件缺失或未交付" if json_records else "诊断文件未登记" if only_diagnostic else "结构化结果未登记")
    delivery_label = _PRODUCT_PHASE_LABELS[phases["delivery"]]
    if phases["delivery"] == "completed" and unavailable:
        delivery_label = "交付不完整（记录为完成）"
        issues.append("已登记交付完成，但健康报告格式缺失或文件不可用。")
    if only_diagnostic:
        report_text = "仅失败诊断；" + json_text
        if formats:
            report_text += "；综合报告含本目标失败范围"
    elif formats:
        report_text = " · ".join(formats) + "；" + json_text
    else:
        report_text = "无可用健康报告；" + json_text
    if missing_files:
        report_text += "；文件缺失：" + "/".join(dict.fromkeys(missing_files))
    result_text = "采集：" + _PRODUCT_PHASE_LABELS[phases["collection"]] + "；分析：" + _PRODUCT_PHASE_LABELS[phases["analysis"]]
    report_text = "交付：" + delivery_label + "；" + report_text
    if only_diagnostic:
        result_text += "（无有效检查数据）"
    collected_at = (module.get("completed_at") or module.get("started_at")) if module and not identity_conflict else None
    detail = [result_text, report_text]
    if run.get("run_id"):
        detail.append("任务：" + str(run["run_id"]))
    if module.get("target_name"):
        detail.append("当次目标名称：" + str(module["target_name"]))
    if run.get("state"):
        detail.append("综合任务：" + _PRODUCT_PHASE_LABELS.get(run["state"], "其他状态") + "（不替代本目标阶段）")
    detail.extend(dict.fromkeys(issues))
    return {"run_id": run.get("run_id", ""), "target_id": target_id, "collection_state": phases["collection"],
            "analysis_state": phases["analysis"], "delivery_state": phases["delivery"], "valid_data": valid_data,
            "collected_at": collected_at, "result_text": result_text, "report_text": report_text,
            "health_formats": formats, "missing_files": list(dict.fromkeys(missing_files)),
            "json_available": json_available, "detail_text": "\n".join(detail)}


class _ArchiveWindowGuard(QObject):
    """Hide owned detail windows when the workbench actually hides or exits."""
    def eventFilter(self, owner, event):
        if event.type() == QEvent.Hide:
            for name in ("environment_editor_dialog", "environment_history_dialog"):
                dialog = getattr(owner, name, None)
                if dialog is not None:
                    dialog.hide()
        return False


class EnvironmentArchiveMixin:
    def _environment_archive_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(SIZES["page_margin"], SIZES["page_top"], SIZES["page_margin"], SIZES["card_padding"])
        layout.setSpacing(SIZES["section_gap"])
        header = PageHeader("环境档案", "历史结果不代表当前实时在线。")
        register = button("登记环境", lambda: self._edit_environment(None), primary=True)
        header.add_action(register)
        self.product_schema_button = button("启用产品档案", self._enable_product_archive)
        header.add_action(self.product_schema_button); layout.addWidget(header)
        toolbar = QHBoxLayout()
        self.environment_edit_button = button("编辑资料", self._edit_selected_environment)
        self.environment_toggle_button = button("停用档案", self._toggle_environment)
        self.environment_history_button = button("历史任务", self._show_environment_history)
        for control in (self.environment_edit_button, self.environment_toggle_button, self.environment_history_button):
            toolbar.addWidget(control)
        toolbar.addStretch(1); layout.addLayout(toolbar)
        actions = QHBoxLayout()
        self.environment_links = {}
        for title, module in (("开始巡检", "inspection_center"), ("查看资产", "asset_center"), ("查看风险", "risk_center"), ("历史任务 / 对比", "history_compare"), ("查看报告", "report_center")):
            control = button(title, lambda checked=False, target=module: self._enter_selected_environment(target))
            actions.addWidget(control); self.environment_links[module] = control
        actions.addStretch(1); layout.addLayout(actions)
        self.environment_detail = muted_label("")
        layout.addWidget(self.environment_detail)
        self.environment_empty = muted_label("尚无环境档案。可以先登记环境，完成巡检后会自动关联采集、任务和报告。")
        self.environment_empty.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        layout.addWidget(self.environment_empty, 1)
        self.environment_table = table(self, ["环境名称", "客户 / 站点", "产品 / 地址", "最近采集", "最近结果", "最近任务报告", "档案"])
        self.environment_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        for column, width in enumerate((185, 155, 155, 150, 155, 175, 82)):
            self.environment_table.setColumnWidth(column, width)
        self.environment_table.currentCellChanged.connect(self._environment_selected)
        self.environment_table.setWordWrap(False)
        self.environment_table.setTextElideMode(Qt.ElideRight)
        self.environment_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.environment_table.horizontalHeader().setSortIndicator(-1, Qt.AscendingOrder)
        self.environment_table.setSortingEnabled(True)
        layout.addWidget(self.environment_table, 1)
        self.environment_history_dialog = QDialog(self)
        self.environment_history_dialog.setWindowTitle("环境历史任务")
        history = QVBoxLayout(self.environment_history_dialog)
        self.environment_history_scope = muted_label("")
        history.addWidget(self.environment_history_scope)
        self.environment_history_empty = muted_label("该环境尚无历史任务。")
        history.addWidget(self.environment_history_empty)
        self.environment_tasks = table(self, ["历史任务", "时间", "执行结果", "可用格式"])
        self._product_history_selection = {}
        self._product_history_rows = {}
        self._product_history_target_id = None
        self.environment_tasks.currentCellChanged.connect(self._product_history_selected)
        self.environment_tasks.setTextElideMode(Qt.ElideRight)
        self.environment_tasks.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        history.addWidget(self.environment_tasks, 1)
        history_close = QHBoxLayout(); history_close.addStretch(1)
        history_close.addWidget(button("关闭", self.environment_history_dialog.close)); history.addLayout(history_close)
        self.environment_editor_dialog = QDialog(self)
        self.environment_editor_dialog.setWindowTitle("环境资料")
        editor_layout = QVBoxLayout(self.environment_editor_dialog)
        self.environment_scroll = QScrollArea()
        self.environment_scroll.setWidgetResizable(True)
        self.environment_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.environment_scroll.setFrameShape(QScrollArea.NoFrame)
        editor_layout.addWidget(self.environment_scroll)
        self.environment_editor = SectionCard("环境资料")
        form = QFormLayout()
        self.environment_product_input = NoWheelComboBox()
        for key, title in (("vcenter", "vCenter / vSAN"), ("nsx", "NSX（实验）"), ("avi", "AVI（实验）")):
            self.environment_product_input.addItem(title, key)
        form.addRow("产品类型", self.environment_product_input)
        self.environment_name_input = QLineEdit()
        self.environment_customer_input = NoWheelComboBox(); self.environment_customer_input.setEditable(True)
        self.environment_customer_input.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.environment_customer_input.setMinimumContentsLength(12)
        self.environment_customer_input.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Fixed)
        self.environment_site_input = QLineEdit()
        self.environment_address_input = QLineEdit(); self.environment_address_input.setPlaceholderText("IP、主机名，可填写 HTTPS 端口")
        self.environment_username_input = QLineEdit(); self.environment_username_input.setPlaceholderText("可选；密码只在巡检时填写")
        for label, field in (("环境名称", self.environment_name_input), ("客户归属", self.environment_customer_input), ("站点", self.environment_site_input), ("管理地址", self.environment_address_input), ("连接用户名", self.environment_username_input)):
            form.addRow(label, field)
        self.environment_archive_form = form
        self.environment_product_input.currentIndexChanged.connect(self._environment_product_changed)
        self.environment_editor.layout.addLayout(form)
        self.environment_editor.layout.addWidget(muted_label("不保存密码。更改当前客户归属不改写历史报告中的原客户信息。停用仅禁止新巡检，历史数据不删除。"))
        self.environment_error = muted_label(""); self.environment_error.setObjectName("validationError")
        self.environment_editor.layout.addWidget(self.environment_error)
        save_row = QHBoxLayout(); save = button("保存资料", self._save_environment, primary=True)
        save.setProperty("keepInPanel", True); save_row.addWidget(save)
        save_row.addWidget(button("取消编辑", self._hide_environment_editor)); save_row.addStretch(1)
        self.environment_editor.layout.addLayout(save_row); self.environment_editor.hide()
        self.environment_scroll.setWidget(self.environment_editor)
        self.environment_editor_dialog.finished.connect(lambda _result: self.environment_editor.hide())
        self.environment_archive_page = page
        self._environment_window_guard = _ArchiveWindowGuard(self)
        self.installEventFilter(self._environment_window_guard)
        return page

    def _environment_dialog_size(self, dialog, width, height):
        available = self.screen().availableGeometry() if self.screen() else self.geometry()
        dialog.resize(min(width, max(320, self.width() - 48), available.width() - 32),
                      min(height, max(280, self.height() - 64), available.height() - 64))

    def _show_environment_history(self):
        self._environment_selected()
        if self._selected_environment() is None:
            return
        self._environment_dialog_size(self.environment_history_dialog, 980, 560)
        self.environment_history_dialog.show(); self.environment_history_dialog.raise_()

    def _hide_environment_editor(self):
        self.environment_editor.hide(); self.environment_editor_dialog.hide()

    def _populate_vcenter_center(self):
        selected = getattr(self, "_archive_selected_id", None)
        vertical = self.environment_table.verticalScrollBar().value()
        horizontal = self.environment_table.horizontalScrollBar().value()
        header = self.environment_table.horizontalHeader()
        sort_column, sort_order = header.sortIndicatorSection(), header.sortIndicatorOrder()
        self._environment_archives = self.service.list_environment_archives(self._db_path())
        self._product_archive_views = self._product_archive_rows()
        self._display_archives = self._environment_archives + self._product_archive_views
        from vstacklens.products.store import schema_ready
        self.product_schema_button.setVisible(not schema_ready(self._db_path()))
        self._archive_updating = True
        self.environment_table.setSortingEnabled(False)
        rows = [[e.name, f"{e.customer_name} / {e.site_name}", f"{getattr(e, 'product', 'vcenter').upper()} · {e.address}",
                 local_time(e.last_collected_at) if e.last_collected_at else "未记录采集",
                 e.collection_result, e.report_result, "启用" if e.enabled else "已停用"]
                for e in self._display_archives]
        self.environment_table.setRowCount(len(rows))
        for row, values in enumerate(rows):
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
                self.environment_table.setItem(row, column, item)
        self.environment_table.resizeRowsToContents()
        self.environment_table.setMinimumHeight(120); self.environment_table.setMaximumHeight(16777215)
        for row, env in enumerate(self._display_archives):
            self.environment_table.item(row, 0).setData(Qt.UserRole, env.environment_id)
            for column in range(self.environment_table.columnCount()):
                self.environment_table.item(row, column).setToolTip(self.environment_table.item(row, column).text())
            if getattr(env, "product_run_summary", None):
                for column in (3, 4, 5):
                    self.environment_table.item(row, column).setToolTip(env.product_run_summary["detail_text"])
        self.environment_table.setSortingEnabled(True)
        if sort_column >= 0:
            self.environment_table.sortItems(sort_column, sort_order)
        self.environment_empty.setVisible(not self._display_archives)
        self.environment_table.setVisible(bool(self._display_archives))
        index = next((row for row in range(self.environment_table.rowCount())
                      if self.environment_table.item(row, 0).data(Qt.UserRole) == selected), 0)
        if self._display_archives:
            self.environment_table.setCurrentCell(index, 0)
        self.environment_table.verticalScrollBar().setValue(vertical)
        self.environment_table.horizontalScrollBar().setValue(horizontal)
        self._archive_updating = False
        self._environment_selected()
        self._populate_environment_picker()

    def _selected_environment(self):
        item = self.environment_table.item(self.environment_table.currentRow(), 0)
        environment_id = item.data(Qt.UserRole) if item else None
        return next((env for env in getattr(self, "_display_archives", []) if env.environment_id == environment_id), None)

    def _environment_selected(self, *_args):
        if getattr(self, "_archive_updating", False):
            return
        env = self._selected_environment()
        self._archive_selected_id = env.environment_id if env else None
        for control in (self.environment_edit_button, self.environment_toggle_button, self.environment_history_button, *self.environment_links.values()):
            control.setEnabled(bool(env))
        if not env:
            self._product_history_target_id = None
            self._product_history_rows = {}
            self.environment_history_dialog.setWindowTitle("环境历史任务")
            self.environment_tasks.setRowCount(0)
            self.environment_history_dialog.hide()
            self.environment_detail.setText(""); self.environment_tasks.hide(); self.environment_history_empty.show(); self.environment_history_scope.clear(); return
        self.environment_history_dialog.setWindowTitle(f"环境历史任务 · {env.name}")
        self.environment_toggle_button.setText("停用档案" if env.enabled else "启用档案")
        self.environment_links["inspection_center"].setEnabled(env.enabled and not self._running)
        self.environment_links["asset_center"].setText("查看资产")
        self.environment_links["risk_center"].setText("查看风险")
        self.environment_detail.setText(f"{env.name} · {env.customer_name} · {env.task_count} 次历史任务")
        self.environment_detail.setToolTip(f"{env.name} · {env.customer_name} / {env.site_name} · {env.address}\n实时连接未检测；停用档案仍可查看所有历史结果。")
        self.environment_history_scope.setText(f"{env.name} · {env.customer_name} / {env.site_name} · {env.address}\n以下为已保存历史记录，不代表当前实时在线；停用档案仍可查看历史。")
        if getattr(env, "product", "vcenter") != "vcenter":
            detail = getattr(env, "product_run_summary", {})
            if detail:
                self.environment_detail.setText(self.environment_detail.text() + "\n" + detail["result_text"] + "\n" + detail["report_text"])
                self.environment_detail.setToolTip(self.environment_detail.toolTip() + "\n" + detail["detail_text"])
            self._populate_product_archive_history(env)
            return
        self._product_history_target_id = None
        histories = self.service.list_report_history(self._db_path(), environment_id=env.environment_id)
        fill_table(self.environment_tasks, [[self._short_task(r.run_id), local_time(r.started_at or r.updated_at), self._run_status_text(r.run_status), " · ".join(self.service.desktop_report_formats(self._db_path(), r.run_id)) or "无可用报告"] for r in histories])
        self.environment_tasks.setMinimumHeight(100); self.environment_tasks.setMaximumHeight(16777215)
        for row in range(self.environment_tasks.rowCount()):
            for column in range(self.environment_tasks.columnCount()):
                item = self.environment_tasks.item(row, column); item.setToolTip(item.text())
        self.environment_history_empty.setVisible(not histories)
        self.environment_tasks.setVisible(bool(histories))

    def _edit_selected_environment(self):
        self._edit_environment(self._selected_environment())

    def _edit_environment(self, env):
        self._archive_edit_id = env.environment_id if env else None
        self._archive_edit_product = getattr(env, "product", "vcenter") if env else "vcenter"
        self.environment_product_input.setCurrentIndex(self.environment_product_input.findData(self._archive_edit_product))
        self.environment_product_input.setEnabled(env is None)
        customers = self.service.list_environment_customers(self._db_path()) if self._db_path().exists() else []
        self.environment_customer_input.clear()
        for c in customers:
            self.environment_customer_input.addItem(c["customer_name"], c["customer_id"])
        if env:
            self.environment_customer_input.setCurrentIndex(self.environment_customer_input.findData(env.customer_id))
        else:
            self.environment_customer_input.setCurrentIndex(-1)
        self.environment_name_input.setText(env.name if env else "")
        self.environment_site_input.setText(env.site_name if env else "未指定站点")
        self.environment_address_input.setText(env.address if env else "")
        self.environment_username_input.setText(env.username if env else "")
        self.environment_error.clear(); self.environment_editor.show()
        self._environment_dialog_size(self.environment_editor_dialog, 600, 540)
        self.environment_editor_dialog.show(); self.environment_editor_dialog.raise_(); self.environment_name_input.setFocus()
        QTimer.singleShot(0, self._ensure_environment_editor_visible)

    def _ensure_environment_editor_visible(self):
        from shiboken6 import isValid
        if isValid(self.environment_scroll) and isValid(self.environment_editor) and self.environment_editor.isVisible():
            self.environment_scroll.ensureWidgetVisible(self.environment_editor)

    def _save_environment(self):
        active_ids = {t.target_id for t in getattr(getattr(self.worker, "request", None), "targets", [])}
        if self._running and (self._archive_edit_id == self._inspection_environment_id or self._archive_edit_id in active_ids):
            self.environment_error.setText("该环境正在巡检，请任务结束后再修改资料。"); return
        combo = self.environment_customer_input
        customer_id = combo.currentData() if combo.currentIndex() >= 0 and combo.currentText() == combo.itemText(combo.currentIndex()) else None
        try:
            product = self.environment_product_input.currentData()
            if product != "vcenter":
                from vstacklens.products.store import save_target, schema_ready
                if not schema_ready(self._db_path()):
                    raise ValueError("请先关闭编辑并点击“启用产品档案”，以保存恢复副本并验证新增结构。")
                self._archive_selected_id = save_target(self._db_path(), product=product, target_id=self._archive_edit_id,
                    name=self.environment_name_input.text(), customer_id=customer_id, customer_name=combo.currentText(),
                    site_name=self.environment_site_input.text(), address=self.environment_address_input.text(),
                    username="")
                self._hide_environment_editor(); self._refresh_all_data()
                return
            self._archive_selected_id = self.service.save_environment_archive(self._db_path(),
                environment_id=self._archive_edit_id, name=self.environment_name_input.text(),
                customer_id=customer_id, customer_name=combo.currentText(), site_name=self.environment_site_input.text(),
                address=self.environment_address_input.text(), username=self.environment_username_input.text())
        except (ValueError, OSError, sqlite3.Error) as exc:
            self.environment_error.setText(str(exc)); return
        self._hide_environment_editor(); self._refresh_all_data()

    def _toggle_environment(self):
        env = self._selected_environment()
        if env:
            active_ids = {t.target_id for t in getattr(getattr(self.worker, "request", None), "targets", [])}
            if self._running and env.environment_id in active_ids:
                self.environment_detail.setText("该目标正在巡检，请任务结束后再修改档案状态。")
                return
            try:
                if getattr(env, "product", "vcenter") != "vcenter":
                    from vstacklens.products.store import set_target_enabled
                    set_target_enabled(self._db_path(), env.environment_id, not env.enabled)
                else:
                    self.service.set_environment_enabled(self._db_path(), env.environment_id, not env.enabled)
            except (ValueError, OSError, sqlite3.Error) as exc:
                self.environment_detail.setText(f"档案状态未能保存：{exc}。请刷新后重试。"); return
            self._refresh_all_data()

    def _enter_selected_environment(self, module):
        env = self._selected_environment()
        if env and getattr(env, "product", "vcenter") != "vcenter":
            if module == "inspection_center":
                self._select_product_archive(env)
            elif module == "report_center":
                self._product_scope_target_id = env.environment_id
                self._environment_id = None
                self._refresh_all_data(); self.go_to_module("report_center")
            else:
                self._show_product_results(target_id=env.environment_id)
            return
        if env:
            self._product_scope_target_id = None
            if self._environment_id != env.environment_id:
                self.risk_keyword_input.clear(); self.asset_search_input.clear()
                self._risk_exact_asset = None
            self._environment_id = env.environment_id
            if module == "inspection_center":
                self._select_inspection_environment(env.environment_id)
            self._refresh_all_data()
            self.go_to_module(module)
            if module == "inspection_center":
                self.inspection_pages.setCurrentIndex(1)

    def _view_data(self):
        return self._scope_overview if getattr(self, "_environment_id", None) else getattr(self, "_overview", None)

    def _clear_environment_scope(self):
        self._environment_id = None
        self._product_scope_target_id = None
        if hasattr(self, "product_result_target"):
            control = self.product_result_target
            blocked = control.blockSignals(True)
            control.setCurrentIndex(max(0, control.findData(None)))
            control.blockSignals(blocked)
        self._refresh_all_data()

    def _populate_environment_picker(self):
        if not hasattr(self, "inspection_environment_combo"):
            return
        combo = self.inspection_environment_combo
        combo.setEnabled(not self._running)
        selected = getattr(self, "_inspection_environment_id", None)
        if selected and not any(e.enabled and e.environment_id == selected for e in self._environment_archives):
            self._inspection_environment_id = None; selected = None; self.password_input.clear()
            self.vcenter_input.setReadOnly(False); self.customer_input.setReadOnly(False)
        combo.blockSignals(True); combo.clear(); combo.addItem("手动输入（沿用原单环境巡检）", None)
        for env in self._environment_archives:
            if env.enabled:
                combo.addItem(f"{env.customer_name} / {env.name} · {env.address}", env.environment_id)
        combo.setCurrentIndex(max(0, combo.findData(selected)))
        combo.blockSignals(False)
        env = next((e for e in self._environment_archives if e.environment_id == selected), None)
        if env:
            self.site_input.setText(env.site_name)
            self.customer_input.setText(env.customer_name)
        if env and getattr(self, "_inspection_profile_signature", None) != self._profile_signature(env):
            self._select_inspection_environment(selected)
        if hasattr(self, "_sync_product_customer_context"):
            self._sync_product_customer_context()

    @staticmethod
    def _profile_signature(env):
        return (env.environment_id, env.customer_id, env.host, env.port, env.username)

    def _select_inspection_environment(self, environment_id):
        if self._running:
            self.inspection_environment_combo.blockSignals(True)
            self.inspection_environment_combo.setCurrentIndex(max(0, self.inspection_environment_combo.findData(self._inspection_environment_id)))
            self.inspection_environment_combo.blockSignals(False)
            return
        previous = getattr(self, "_inspection_environment_id", None)
        self._inspection_environment_id = environment_id
        env = next((e for e in self._environment_archives if e.environment_id == environment_id), None)
        signature = self._profile_signature(env) if env else None
        if previous != environment_id or signature != getattr(self, "_inspection_profile_signature", None):
            self.password_input.clear()  # Never reuse another environment's password.
        self._inspection_profile_signature = signature
        self.vcenter_input.setReadOnly(bool(env)); self.customer_input.setReadOnly(bool(env))
        if env:
            self.vcenter_input.setText(env.address); self.username_input.setText(env.username)
            self.customer_input.setText(env.customer_name); self.site_input.setText(env.site_name)
        if signature != getattr(self, "_previous_inspection_signature", None):
            self.current_result = None
            self._standard_presentation()
            for control in (self.open_report_button, self.open_word_button, self.open_pdf_button, self.open_dir_button):
                control.setEnabled(False)
        self._previous_inspection_signature = signature
        self.inspection_environment_combo.blockSignals(True)
        self.inspection_environment_combo.setCurrentIndex(max(0, self.inspection_environment_combo.findData(environment_id)))
        self.inspection_environment_combo.blockSignals(False)
        if hasattr(self, "_sync_product_customer_context"):
            self._sync_product_customer_context()
        if getattr(self, "_active_module", "") == "inspection_center":
            changed_scope = self._environment_id != environment_id
            self._environment_id = environment_id
            if changed_scope:
                self._refresh_all_data()
            self._update_current_object_bar()


    def _enable_product_archive(self):
        from vstacklens.products.store import ensure_product_schema
        from PySide6.QtWidgets import QMessageBox
        answer = QMessageBox.question(self, "启用 NSX / AVI 产品档案", "将对当前设置中选定的数据库保存恢复副本并验证新增结构。原 vCenter 历史不改写。继续启用？", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if answer != QMessageBox.Yes:
            return
        try:
            ensure_product_schema(self._db_path())
        except (ValueError, OSError, sqlite3.Error):
            QMessageBox.warning(self, "产品档案未启用", "选定数据库准备失败；未开始产品巡检。请检查数据库状态和本轮恢复记录。")
            return
        self._refresh_all_data()

    def _product_archive_rows(self):
        from vstacklens.products import store
        if not store.schema_ready(self._db_path()):
            return []
        rows = []
        for target in store.list_targets(self._db_path(), include_vcenter=False):
            runs = store.list_runs(self._db_path(), target_id=target.target_id)
            last = runs[0] if runs else {}
            summary = self._product_archive_run_summary(target, last) if last else None
            rows.append(SimpleNamespace(environment_id=target.target_id, product=target.product,
                target_id=target.target_id, name=target.name, customer_id=target.customer_id,
                customer_name=target.customer_name, site_id=target.site_id, site_name=target.site_name,
                address=target.host if target.port == 443 else f"{target.host}:{target.port}",
                host=target.host, port=target.port, username=target.username, enabled=target.enabled,
                last_collected_at=summary["collected_at"] if summary else None,
                collection_result=summary["result_text"] if summary else "尚无巡检",
                report_result=summary["report_text"] if summary else "尚无交付",
                product_run_summary=summary, task_count=len(runs)))
        return rows

    def _product_archive_run_summary(self, target, run):
        from vstacklens.products import store
        try:
            saved = store.load_run(self._db_path(), run["run_id"])
        except (ValueError, OSError, sqlite3.Error):
            saved = None
        summary = project_product_target_run(saved or {"run_id": run["run_id"]},
            getattr(target, "target_id", getattr(target, "environment_id", "")),
            product=target.product, customer_id=target.customer_id)
        if saved is None:
            summary["detail_text"] += "\n当次目标记录无法读取，未按完成处理。"
        return summary

    def _populate_product_archive_history(self, env):
        from vstacklens.products import store
        histories = store.list_runs(self._db_path(), target_id=env.environment_id)
        self._product_history_target_id = env.environment_id
        self._product_history_rows = {run["run_id"]: self._product_archive_run_summary(env, run) for run in histories}
        selected = self._product_history_selection.get(env.environment_id)
        self.environment_tasks.blockSignals(True)
        fill_table(self.environment_tasks, [[self._short_task(run["run_id"]),
            local_time(self._product_history_rows[run["run_id"]]["collected_at"]) if self._product_history_rows[run["run_id"]]["collected_at"] else "未记录目标采集",
            self._product_history_rows[run["run_id"]]["result_text"], self._product_history_rows[run["run_id"]]["report_text"]] for run in histories])
        for row, run in enumerate(histories):
            self.environment_tasks.item(row, 0).setData(Qt.UserRole, run["run_id"])
            for column in range(self.environment_tasks.columnCount()):
                self.environment_tasks.item(row, column).setToolTip(self._product_history_rows[run["run_id"]]["detail_text"])
        if histories:
            row = next((index for index, run in enumerate(histories) if run["run_id"] == selected), 0)
            self.environment_tasks.setCurrentCell(row, 0)
        self.environment_tasks.blockSignals(False)
        self.environment_tasks.setMinimumHeight(100); self.environment_tasks.setMaximumHeight(16777215)
        self.environment_tasks.setVisible(bool(histories)); self.environment_history_empty.setVisible(not histories)
        self.environment_links["asset_center"].setText("查看产品对象")
        self.environment_links["risk_center"].setText("查看产品结果")
        self._product_history_selected()

    def _product_history_selected(self, *_args):
        env = self._selected_environment()
        if not env or getattr(env, "product", "vcenter") == "vcenter" or env.environment_id != self._product_history_target_id:
            return
        item = self.environment_tasks.item(self.environment_tasks.currentRow(), 0)
        run_id = item.data(Qt.UserRole) if item else None
        summary = self._product_history_rows.get(run_id)
        if not summary:
            return
        self._product_history_selection[env.environment_id] = run_id
        text = f"{env.name} · {env.customer_name} / {env.site_name} · {env.address}\n以下为已保存历史记录，不代表当前实时在线。\n" + summary["detail_text"]
        self.environment_history_scope.setText(text)
        self.environment_history_scope.setToolTip(text)

    def _select_product_archive(self, env):
        if self._running:
            return
        self._environment_id = None
        self._product_scope_target_id = env.environment_id
        self._populate_product_targets()
        for product, checkbox in self.product_scope_checks.items():
            checkbox.setChecked(product == env.product)
        widget = self._product_forms[env.product]["targets"]
        for index in range(widget.count()):
            item = widget.item(index)
            item.setCheckState(Qt.Checked if item.data(Qt.UserRole) == env.environment_id else Qt.Unchecked)
            if item.data(Qt.UserRole) == env.environment_id:
                widget.setCurrentItem(item)
        self.go_to_module("inspection_center"); self.inspection_pages.setCurrentIndex(1)
        if hasattr(self, "_sync_product_customer_context"):
            self._sync_product_customer_context()
        self._update_task_summary()
        self._update_current_object_bar()


    def _environment_product_changed(self, *_args):
        legacy = self.environment_product_input.currentData() == "vcenter"
        self.environment_username_input.setVisible(legacy)
        label = self.environment_archive_form.labelForField(self.environment_username_input)
        if label:
            label.setVisible(legacy)
        if not legacy:
            self.environment_username_input.clear()
