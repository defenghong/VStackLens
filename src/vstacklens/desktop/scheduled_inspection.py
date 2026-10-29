"""Operate: extend the existing Qt inspection workspace, not its visual identity.

Plan list first; editing and explicit memory-only authorization stay together.
Pinned actions and scrollable details keep long names usable at 125% scaling.
No metrics dashboard, new report template or hidden credential reuse.
"""
from pathlib import Path
import sqlite3

from PySide6.QtCore import QThread, QTime, QTimer, Signal, Qt
from shiboken6 import isValid
from PySide6.QtWidgets import QCheckBox, QFormLayout, QHBoxLayout, QHeaderView, QLineEdit, QTabWidget, QTimeEdit, QWidget, QVBoxLayout

from vstacklens.application.batch_inspection import BatchInspectionService, BatchSettings, SessionCredential
from vstacklens.application.scheduled_inspection import ScheduledInspectionService
from vstacklens.db.schedule_store import ScheduleStore
from vstacklens.desktop.batch_inspection import SelectionDelegate, LABELS
from vstacklens.desktop.layout3a import button, table, fill_table, page_layout
from vstacklens.desktop.widgets import muted_label, NoWheelComboBox as QComboBox

PLAN_STATES = {**LABELS, "claimed": "触发确认中", "submitted": "已提交", "skipped": "未执行"}


class PlanTickWorker(QThread):
    triggered = Signal(object)
    failed = Signal(str)
    def __init__(self, service, parent=None):
        super().__init__(parent); self.service = service
    def request_cancel(self):
        self.service.stop()
    def run(self):
        try:
            self.triggered.emit(self.service.tick())
        except Exception:
            self.failed.emit("计划检查未成功，未绕过保护启动；请检查本地数据库与计划设置。")


class PlannedBatchWorker(QThread):
    progress = Signal(object)
    completed = Signal(object)
    failed = Signal(str)
    def __init__(self, service, trigger, parent=None):
        super().__init__(parent); self.service = service; self.trigger = trigger
    def request_cancel(self):
        self.service.stop()
    def run(self):
        try:
            self.completed.emit(self.service.run_trigger(self.trigger, self.progress.emit))
        except Exception:
            self.failed.emit("计划任务异常结束，请查看已保留的任务证据；不自动重试。")


class ScheduledInspectionMixin:
    def _schedule_page(self):
        page, layout = page_layout("计划标准巡检")
        self.plan_page_header = layout.itemAt(0).widget()
        self.plan_description = muted_label("仅软件运行时执行；每日或每周、多环境串行。错过不补跑，重启后等待重新授权凭据。")
        layout.addWidget(self.plan_description)
        actions = QHBoxLayout(); self.plan_actions=[]
        for text, callback in (("返回巡检中心", lambda: self.inspection_pages.setCurrentIndex(0)),
                               ("新建计划", self._new_plan), ("编辑所选计划", self._edit_plan),
                               ("启用 / 停用", self._toggle_plan), ("查看最近结果", self._view_plan_result)):
            control=button(text, callback);actions.addWidget(control);self.plan_actions.append(control)
        actions.addStretch(1); layout.addLayout(actions)
        self.plan_status = muted_label("尚无计划。创建后，请分别填写并授权本次运行的会话凭据。")
        layout.addWidget(self.plan_status)
        self.plan_tabs = QTabWidget()
        self.plan_list = table(self, ["计划 / 状态", "目标客户与环境", "时间 / 时区 / 下次", "最近结果 / 当前条件"])
        self.plan_list.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        for i, width in enumerate((160, 190, 180, 230)):
            self.plan_list.setColumnWidth(i, width)
        self.plan_tabs.addTab(self.plan_list, "计划列表")
        editor = QWidget(); editor_layout = QVBoxLayout(editor)
        self.plan_editor_tabs = QTabWidget(); editor_layout.addWidget(self.plan_editor_tabs, 1)
        body = QWidget(); edit_layout = QVBoxLayout(body)
        form = QFormLayout()
        self.plan_name = QLineEdit(); form.addRow("计划名称", self.plan_name)
        self.plan_frequency = QComboBox(); self.plan_frequency.addItem("每日", "daily"); self.plan_frequency.addItem("每周", "weekly")
        self.plan_weekdays = []
        day_row = QHBoxLayout(); day_row.addWidget(self.plan_frequency)
        for i, text in enumerate(("一", "二", "三", "四", "五", "六", "日")):
            check = QCheckBox("周" + text); check.setEnabled(False); self.plan_weekdays.append(check); day_row.addWidget(check)
        self.plan_frequency.currentIndexChanged.connect(lambda: [c.setEnabled(self.plan_frequency.currentData() == "weekly") for c in self.plan_weekdays])
        form.addRow("频率 / 星期", day_row)
        self.plan_time = QTimeEdit(QTime(9, 0)); self.plan_time.setDisplayFormat("HH:mm")
        self.plan_zone = QComboBox(); self.plan_zone.setEditable(True); self.plan_zone.addItems(["Asia/Shanghai", "UTC", "Asia/Hong_Kong", "Europe/London", "America/New_York"])
        times = QHBoxLayout(); times.addWidget(self.plan_time); times.addWidget(self.plan_zone, 1); form.addRow("当地时间 / 时区", times)
        self.plan_enabled = QCheckBox("启用此计划"); self.plan_enabled.setChecked(True); form.addRow("计划状态", self.plan_enabled)
        edit_layout.addLayout(form)
        self.plan_editor_scroll = self._scroll_page(body)
        self.plan_editor_tabs.addTab(self.plan_editor_scroll, "时间与频率")
        targets_page = QWidget(); targets_layout = QVBoxLayout(targets_page);targets_layout.setContentsMargins(0,0,0,0)
        self.plan_targets_hint = muted_label("会话用户名与密码独立填写，不借用单环境密码。")
        self.plan_targets_hint.setVisible(False)
        self.plan_targets = table(self, ["选择", "客户 / 环境", "地址 / 档案", "会话用户名", "会话密码"])
        self.plan_targets.setWordWrap(False)
        self.plan_targets.setToolTip(self.plan_targets_hint.text())
        self.plan_targets.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        for i, width in enumerate((80, 250, 190, 185, 185)):
            self.plan_targets.setColumnWidth(i, width)
        self.plan_targets.setItemDelegateForColumn(0, SelectionDelegate(self.plan_targets)); targets_layout.addWidget(self.plan_targets, 1)
        self.plan_target_information=self._target_information(self.plan_targets,lambda:getattr(self,"_plan_profiles",[])); targets_layout.addWidget(self.plan_target_information)
        self.plan_editor_tabs.addTab(targets_page, "目标与会话凭据")
        self.plan_editor_tabs.currentChanged.connect(lambda: QTimer.singleShot(0, self._resize_plan_columns))
        self.plan_consent = QCheckBox("仅授权本次软件运行期间用于此计划；退出清除，重启需重新提供。")
        editor_layout.addWidget(self.plan_consent)
        save_actions = QHBoxLayout()
        self.plan_save_button = button("保存计划设置", self._save_plan, primary=True); self.plan_save_button.setProperty("keepInPanel", True); save_actions.addWidget(self.plan_save_button)
        self.plan_authorize_button = button("授权本次运行", self._authorize_plan); self.plan_authorize_button.setEnabled(False); save_actions.addWidget(self.plan_authorize_button)
        self.plan_consent.toggled.connect(lambda checked: self.plan_authorize_button.setEnabled(checked and bool(self._edit_plan_id) and not getattr(self, "_batch_closing", False)))
        save_actions.addWidget(button("清除本计划授权", self._revoke_plan)); save_actions.addStretch(1)
        editor_layout.addLayout(save_actions)
        self.plan_editor_status = muted_label("先保存计划，再主动授权。不使用单环境表单或已结束批任务的密码。")
        editor_layout.addWidget(self.plan_editor_status)
        self.plan_tabs.addTab(editor, "编辑与会话授权")
        self.plan_results = table(self, ["客户 / 环境", "状态", "采集", "分析", "交付", "说明", "报告"])
        self.plan_results.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        for i, width in enumerate((240, 120, 120, 120, 120, 280, 150)):
            self.plan_results.setColumnWidth(i, width)
        self.plan_tabs.addTab(self.plan_results, "最近结果")
        self.plan_tabs.currentChanged.connect(self._plan_tab_changed)
        layout.addWidget(self.plan_tabs, 1)
        self._edit_plan_id = None; self._edit_plan_revision = None
        self._plan_profiles = []
        return page

    def _plan_tab_changed(self, index):
        self.plan_page_header.setVisible(index != 1)
        self.plan_description.setVisible(index != 1)
        self.plan_status.setVisible(index != 1)
        for control in self.plan_actions[1:]: control.setVisible(index != 1)
        QTimer.singleShot(0, self._resize_plan_columns)

    def _start_plan_runtime(self):
        self._plan_manager = None; self.plan_worker = None; self.plan_tick_worker = None
        self._plan_timer = QTimer(self); self._plan_timer.timeout.connect(self._plan_timer_tick); self._plan_timer.start(1000)

    def _plan_service(self, create=True):
        path = self._db_path().resolve()
        manager = self._plan_manager
        if manager and manager.store.path.resolve() != path:
            if self.plan_worker and self.plan_worker.isRunning() or self.plan_tick_worker and self.plan_tick_worker.isRunning():
                raise ValueError("计划任务运行中不能切换数据库。")
            manager.finish_shutdown(); self._plan_manager = None; manager = None
        if manager is None:
            if not create and not ScheduleStore.exists(path):
                return None
            batch = BatchInspectionService(path, service_factory=getattr(self, "batch_service_factory", None))
            manager = ScheduledInspectionService(path, batch_manager=batch); self._plan_manager = manager
        return manager

    def _open_plans(self):
        self.go_to_module("inspection_center"); self.inspection_pages.setCurrentIndex(3)
        self._update_current_object_bar()
        try:
            self._plan_service(); self._reload_plans()
        except (ValueError, OSError, sqlite3.Error):
            self.plan_status.setText("无法读取计划，请检查本地数据库。")

    def _reload_plans(self):
        manager = self._plan_service()
        selected = self._selected_plan_id()
        self._plans = manager.store.plans()
        rows = []
        for plan in self._plans:
            occurrences = manager.store.occurrences(plan["schedule_id"])
            last = occurrences[0] if occurrences else {}
            days = "每日" if plan["frequency"] == "daily" else "每周 " + "、".join("一二三四五六日"[i] for i in plan["weekdays"])
            rows.append([plan["name"] + ("\n启用" if plan["enabled"] else "\n停用"),
                         "\n".join(t["customer_name"] + " / " + t["name"] for t in plan["targets"]),
                         f"{days} {plan['local_time']}\n{plan['timezone']}\n下次：{self._plan_local_time(plan)}",
                         (PLAN_STATES.get(last.get("state"), "尚无执行记录") + "\n" + last.get("reason", "") + "\n" + manager.readiness(plan)).strip()])
        fill_table(self.plan_list, rows); self._unbound_plan_table(self.plan_list)
        for row, plan in enumerate(self._plans):
            self.plan_list.item(row, 0).setData(Qt.UserRole, plan["schedule_id"])
            for col in range(self.plan_list.columnCount()):
                self.plan_list.item(row, col).setToolTip(self.plan_list.item(row, col).text())
            if selected == plan["schedule_id"]:
                self.plan_list.selectRow(row)
        if not self._plans:
            self.plan_status.setText("尚无计划。点击“新建计划”选择环境并设置时间。")
        elif not self.plan_worker:
            self.plan_status.setText("计划仅在软件运行期间执行；请核对每项当前条件，等待凭据不等于已执行。")
        self._resize_plan_columns()

    def _resize_plan_columns(self):
        width = max(600, self.plan_list.viewport().width() - 2)
        self.plan_list.horizontalHeader().setStretchLastSection(False)
        for i, share in enumerate((.21, .25, .25, .29)):
            self.plan_list.setColumnWidth(i, round(width * share))
        self.plan_list.resizeRowsToContents()
        target_width = max(540, self.plan_targets.viewport().width() - 2)
        self.plan_targets.horizontalHeader().setStretchLastSection(False)
        self.plan_targets.setColumnWidth(0, 70)
        for i, share in enumerate((.32, .22, .23, .23), 1):
            self.plan_targets.setColumnWidth(i, round((target_width - 70) * share))
        self.plan_targets.resizeRowsToContents()

    @staticmethod
    def _plan_local_time(plan):
        from datetime import datetime
        from zoneinfo import ZoneInfo
        return datetime.fromisoformat(plan["next_fire_at"]).astimezone(ZoneInfo(plan["timezone"])).strftime("%Y-%m-%d %H:%M") if plan["enabled"] else "已停用"

    @staticmethod
    def _unbound_plan_table(widget):
        widget.setMinimumHeight(160); widget.setMaximumHeight(16777215)

    def _selected_plan_id(self):
        row = self.plan_list.currentRow()
        return self.plan_list.item(row, 0).data(Qt.UserRole) if row >= 0 else None

    def _new_plan(self):
        self._edit_plan_id = None; self._edit_plan_revision = None
        self.plan_name.clear(); self.plan_enabled.setChecked(True); self.plan_frequency.setCurrentIndex(0)
        self.plan_time.setTime(QTime(9, 0)); self.plan_zone.setCurrentText("Asia/Shanghai")
        for i, check in enumerate(self.plan_weekdays): check.setChecked(i == 0)
        self._populate_plan_targets([]); self.plan_consent.setChecked(False)
        self.plan_tabs.setCurrentIndex(1); self.plan_editor_tabs.setCurrentIndex(0); self.plan_editor_status.setText("选择目标后保存设置，再填写凭据并主动授权。")

    def _populate_plan_targets(self, selected):
        self._plan_profiles = self.service.list_environment_archives(self._db_path())
        fill_table(self.plan_targets, [["", e.customer_name + "\n" + e.name, e.address + ("\n启用" if e.enabled else "\n停用"), "", ""] for e in self._plan_profiles])
        self._unbound_plan_table(self.plan_targets)
        self.plan_targets.setMinimumHeight(80)
        for row, env in enumerate(self._plan_profiles):
            cell = self.plan_targets.item(row, 0); cell.setFlags(cell.flags() | Qt.ItemIsUserCheckable); cell.setCheckState(Qt.Checked if env.environment_id in selected else Qt.Unchecked)
            if not env.enabled and env.environment_id not in selected: cell.setFlags(cell.flags() & ~Qt.ItemIsEnabled)
            username = QLineEdit(env.username); password = QLineEdit(); password.setEchoMode(QLineEdit.Password); password.setPlaceholderText("本计划专用会话")
            self.plan_targets.setCellWidget(row, 3, username); self.plan_targets.setCellWidget(row, 4, password)
            for column in (1, 2): self.plan_targets.item(row, column).setToolTip(self.plan_targets.item(row, column).text())

    def _edit_plan(self):
        sid = self._selected_plan_id()
        if not sid:
            self.plan_status.setText("请先选择一个计划。"); return
        plan = self._plan_service().store.get(sid)
        self._edit_plan_id = sid; self._edit_plan_revision = plan["revision"]
        self.plan_name.setText(plan["name"]); self.plan_enabled.setChecked(plan["enabled"])
        self.plan_frequency.setCurrentIndex(self.plan_frequency.findData(plan["frequency"])); self.plan_zone.setCurrentText(plan["timezone"])
        self.plan_time.setTime(QTime.fromString(plan["local_time"], "HH:mm"))
        for i, check in enumerate(self.plan_weekdays): check.setChecked(i in plan["weekdays"])
        self._populate_plan_targets([t["environment_id"] for t in plan["targets"]]); self.plan_consent.setChecked(False)
        self.plan_tabs.setCurrentIndex(1); self.plan_editor_status.setText("修改设置后旧授权失效，需主动重新授权。")
        self.plan_editor_tabs.setCurrentIndex(0)

    def _save_plan(self):
        try:
            ids = [e.environment_id for row, e in enumerate(self._plan_profiles) if self.plan_targets.item(row, 0).checkState() == Qt.Checked]
            plan = self._plan_service().save_plan(name=self.plan_name.text(), environment_ids=ids,
                settings=BatchSettings(self._db_path(), Path(self.default_report_dir_input.path_value()), Path(self.rulepack_path_input.path_value())),
                frequency=self.plan_frequency.currentData(), weekdays=[i for i, c in enumerate(self.plan_weekdays) if c.isChecked()],
                local_time=self.plan_time.time().toString("HH:mm"), timezone_name=self.plan_zone.currentText(), enabled=self.plan_enabled.isChecked(),
                schedule_id=self._edit_plan_id, expected_revision=self._edit_plan_revision)
            self._edit_plan_id, self._edit_plan_revision = plan["schedule_id"], plan["revision"]
            self._clear_plan_passwords(); self.plan_consent.setChecked(False)
            self.plan_editor_status.setText("设置已保存；请填写独立凭据，勾选本次授权后再点击授权。")
            self._reload_plans()
        except (ValueError, OSError, sqlite3.Error) as exc:
            self.plan_editor_status.setText(str(exc))

    def _authorize_plan(self):
        try:
            if not self._edit_plan_id:
                raise ValueError("请先保存计划。")
            plan = self._plan_service().store.get(self._edit_plan_id)
            ids = [e.environment_id for row, e in enumerate(self._plan_profiles) if self.plan_targets.item(row, 0).checkState() == Qt.Checked]
            draft = (self.plan_name.text().strip(), self.plan_frequency.currentData(),
                     [i for i, c in enumerate(self.plan_weekdays) if c.isChecked()],
                     self.plan_time.time().toString("HH:mm"), self.plan_zone.currentText(), self.plan_enabled.isChecked(), ids)
            saved = (plan["name"], plan["frequency"], plan["weekdays"], plan["local_time"], plan["timezone"], plan["enabled"], [t["environment_id"] for t in plan["targets"]])
            if draft != saved or self._edit_plan_revision != plan["revision"]:
                raise ValueError("表单或计划已变化，请先保存设置再授权。")
            credentials = {e.environment_id: SessionCredential(self.plan_targets.cellWidget(row, 3).text(), self.plan_targets.cellWidget(row, 4).text())
                           for row, e in enumerate(self._plan_profiles) if self.plan_targets.item(row, 0).checkState() == Qt.Checked}
            self._plan_service().authorize(self._edit_plan_id, credentials, consent=self.plan_consent.isChecked())
            self._clear_plan_passwords(); self.plan_consent.setChecked(False)
            self.plan_editor_status.setText("已授权本次软件运行；退出时清除。每次批任务结束仅清理该任务副本。")
            self._reload_plans()
        except (ValueError, OSError, sqlite3.Error) as exc:
            self._clear_plan_passwords(); self.plan_consent.setChecked(False)
            self.plan_editor_status.setText(str(exc))

    def _clear_plan_passwords(self):
        for row in range(self.plan_targets.rowCount()):
            self.plan_targets.cellWidget(row, 4).clear()

    def _revoke_plan(self):
        if self._edit_plan_id:
            self._plan_service().revoke(self._edit_plan_id)
        self._clear_plan_passwords(); self.plan_consent.setChecked(False)
        self.plan_editor_status.setText("本计划的会话授权已清除。")

    def _toggle_plan(self):
        sid = self._selected_plan_id()
        if sid:
            plan = self._plan_service().store.get(sid); self._plan_service().set_enabled(sid, not plan["enabled"]); self._reload_plans()

    def _view_plan_result(self):
        sid = self._selected_plan_id()
        records = self._plan_service().store.occurrences(sid) if sid else []
        last = records[0] if records else {}
        if not last.get("batch_id"):
            self.plan_status.setText(last.get("reason") or "该计划尚无巡检结果或报告。"); return
        snapshot = self._plan_service().batch.store.snapshot(last["batch_id"])
        fill_table(self.plan_results, [[i["target"]["customer_name"] + "\n" + i["target"]["name"], LABELS.get(i["state"], i["state"]), LABELS.get(i["collection_state"], i["collection_state"]), LABELS.get(i["analysis_state"], i["analysis_state"]), LABELS.get(i["delivery_state"], i["delivery_state"]), i["reason"], ""] for i in snapshot["items"]])
        self._unbound_plan_table(self.plan_results)
        for row, item in enumerate(snapshot["items"]):
            control = button("查看报告", lambda checked=False, run_id=item["run_id"], db=snapshot["db_path"]: self._batch_open_report(run_id, db))
            control.setEnabled(bool(item["run_id"] and self.service.desktop_report_formats(Path(snapshot["db_path"]), item["run_id"])))
            self.plan_results.setCellWidget(row, 6, control)
        self.plan_tabs.setCurrentIndex(2)

    def _plan_timer_tick(self):
        # A finished native run may still have its GUI notification queued.
        # Keep its ownership until that specific callback completes cleanup.
        if getattr(self, "_batch_closing", False) or self.plan_tick_worker is not None: return
        try:
            manager = self._plan_service(create=False)
            if not manager: return
            worker = PlanTickWorker(manager, self)
            self.plan_tick_worker = worker
            worker.triggered.connect(self._plan_triggered)
            worker.failed.connect(self._plan_runtime_error)
            worker.finished.connect(lambda source=worker: self._plan_tick_finished(source), Qt.QueuedConnection)
            worker.start()
        except (ValueError, OSError, sqlite3.Error):
            self._plan_runtime_error("计划未触发，请检查本地数据库。")

    def _plan_triggered(self, trigger):
        if getattr(self, "_batch_closing", False) or trigger is None: return
        if self.plan_worker is not None:
            return
        self.plan_worker = PlannedBatchWorker(self._plan_manager, trigger, self)
        self.plan_worker.progress.connect(self._planned_progress); self.plan_worker.completed.connect(self._planned_progress)
        self.plan_worker.failed.connect(self._plan_runtime_error); self.plan_worker.finished.connect(self._planned_finished)
        self.plan_worker.start()

    def _planned_progress(self, snapshot):
        if getattr(self, "_batch_closing", False): return
        self._planned_snapshot = snapshot
        self.plan_status.setText(f"计划任务已结束 {sum(snapshot['counts'][s] for s in ('completed','partial_failed','failed','cancelled','interrupted'))}/{snapshot['total']}；进度不等于全部交付成功。")
        if hasattr(self, "_tray_status"): self._tray_status.setText("计划巡检运行中" if snapshot["state"] == "running" else "计划巡检已结束")

    def _plan_runtime_error(self, message):
        if not getattr(self, "_batch_closing", False): self.plan_status.setText(message)

    def _plan_tick_finished(self, worker):
        if not isValid(worker): return  # A stale delivery cannot affect a newer worker.
        if not worker.wait(0):
            QTimer.singleShot(10, self, lambda: self._plan_tick_finished(worker))
            return
        is_current = self.plan_tick_worker is worker
        if is_current: self.plan_tick_worker = None
        worker.deleteLater()
        if is_current and not getattr(self, "_batch_closing", False) and self.inspection_pages.currentIndex() == 3:
            self._reload_plans()

    def _planned_finished(self):
        worker = self.plan_worker; self.plan_worker = None
        if worker: worker.deleteLater()
        if not getattr(self, "_batch_closing", False):
            self.plan_status.setText("计划任务已结束；请分别查看完成、部分失败、失败和报告交付状态。")
