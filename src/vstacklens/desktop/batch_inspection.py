"""THESIS: select independent environments and see outcomes, not success-only progress.
OWN-WORLD: existing Qt tables, dark/light theme, green action buttons and Chinese type.
STORY: choose targets, enter separate session credentials, submit once, inspect each result.
FIRST VIEWPORT: selection, credentials, submit/cancel, aggregate state and per-item outcomes.
FORM: scoped native workbench extension; no new visual world or concept seed.
"""
from pathlib import Path
import sqlite3
from PySide6.QtCore import Qt, QThread, Signal, QTimer, QEvent, QRect
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QHeaderView, QProgressBar, QPushButton, QMessageBox, QTabWidget, QStyledItemDelegate, QStyle, QLabel, QScrollArea, QFrame, QDialog
from PySide6.QtGui import QPainter, QColor, QPen
from vstacklens.application.batch_inspection import BatchInspectionService, BatchSettings, SessionCredential
from vstacklens.desktop.layout3a import page_layout, table, button, fill_table
from vstacklens.desktop.widgets import muted_label
from vstacklens.desktop.theme import COLORS

LABELS = {"waiting":"等待", "running":"运行", "completed":"完成", "partial_failed":"部分失败", "failed":"失败", "cancelled":"取消", "interrupted":"中断", "complete":"完成", "partial":"部分", "not_started":"未开始", "unavailable":"不可用", "unknown":"未确认", "generating":"生成中"}

class SelectionDelegate(QStyledItemDelegate):
    def editorEvent(self,event,model,option,index):
        if not index.flags() & Qt.ItemIsEnabled or not index.flags() & Qt.ItemIsUserCheckable:
            return False
        hit=QRect(option.rect.center().x()-9,option.rect.center().y()-9,18,18)
        click=event.type()==QEvent.MouseButtonRelease and event.button()==Qt.LeftButton and hit.contains(event.position().toPoint())
        key=event.type()==QEvent.KeyPress and event.key() in (Qt.Key_Space,Qt.Key_Select)
        if click or key:
            state=Qt.Unchecked.value if index.data(Qt.CheckStateRole) in (Qt.Checked,Qt.Checked.value) else Qt.Checked.value
            return model.setData(index,state,Qt.CheckStateRole)
        return False
    def paint(self,painter,option,index):
        painter.save()
        size=18;x=option.rect.center().x()-size//2;y=option.rect.center().y()-size//2
        painter.setPen(QPen(QColor(COLORS["subtext"]),1));painter.setBrush(QColor(COLORS["surface"]))
        painter.drawRect(x,y,size,size)
        if index.data(Qt.CheckStateRole) in (Qt.Checked, Qt.Checked.value):
            painter.setPen(QPen(QColor(COLORS["text"]),2));painter.drawLine(x+3,y+9,x+7,y+13);painter.drawLine(x+7,y+13,x+15,y+4)
        painter.restore()

class BatchWorker(QThread):
    progress = Signal(object)
    completed = Signal(object)
    failed = Signal(str)
    def __init__(self, service, batch_id, parent=None):
        super().__init__(parent); self.service=service; self.batch_id=batch_id
    def request_cancel(self):
        self.service.cancel(self.batch_id)
    def run(self):
        try:
            self.completed.emit(self.service.run(self.batch_id, self.progress.emit))
        except Exception:
            # No raw exception/locals containing credentials enters Qt logs.
            self.failed.emit("批任务运行异常，后续项未继续；请查看任务记录。")

class BatchInspectionMixin:
    def _target_information(self, targets, profiles):
        if targets is getattr(self,"batch_targets",None):
            container=QWidget();row=QHBoxLayout(container);row.setContentsMargins(0,0,0,0)
            details=QLabel();details.setWordWrap(True);details.setTextFormat(Qt.PlainText);details.setTextInteractionFlags(Qt.TextSelectableByMouse|Qt.TextSelectableByKeyboard)
            dialog=QDialog(self);dialog.setWindowTitle("完整目标信息");dialog.resize(520,260);body=QVBoxLayout(dialog);body.addWidget(details,1);body.addWidget(button("关闭",dialog.close))
            def update(*args):
                rows=profiles();index=targets.currentRow()
                if 0<=index<len(rows):
                    env=rows[index];details.setText(f"客户：{env.customer_name}\n环境：{env.name}\n地址：{env.address}\n档案：{'启用' if env.enabled else '停用'}")
                else:details.setText("选择一行查看完整客户、环境和地址；不显示会话凭据。")
            def show():update();dialog.show();dialog.raise_();dialog.activateWindow()
            targets.currentCellChanged.connect(update);container.toggle=button("完整目标信息",show);container.body=dialog
            row.addWidget(muted_label("每行使用独立会话凭据；完整名称可悬停查看。"),1);row.addWidget(container.toggle)
            return container
        from vstacklens.desktop.layout3a import FoldSection
        details=QLabel("选择一行查看完整客户、环境和地址；不显示会话凭据。")
        details.setWordWrap(True); details.setTextFormat(Qt.PlainText)
        details.setTextInteractionFlags(Qt.TextSelectableByMouse|Qt.TextSelectableByKeyboard)
        def update(*args):
            rows=profiles(); row=targets.currentRow()
            if 0 <= row < len(rows):
                env=rows[row]
                details.setText(f"客户：{env.customer_name}\n环境：{env.name}\n地址：{env.address}  ·  档案：{'启用' if env.enabled else '停用'}")
            else: details.setText("选择一行查看完整客户、环境和地址；不显示会话凭据。")
        targets.currentCellChanged.connect(update)
        scroll=QScrollArea();scroll.setWidgetResizable(True);scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidget(details);scroll.setMinimumHeight(70);scroll.setMaximumHeight(88)
        return FoldSection("完整目标信息",scroll)

    def _batch_page(self):
        page, layout = page_layout("批量标准巡检")
        layout.addWidget(muted_label("串行执行；各环境使用独立会话凭据。跨客户重复地址或远端身份不明时阻断，不借用单环境密码。"))
        actions=QHBoxLayout()
        actions.addWidget(button("返回巡检中心",lambda:self.inspection_pages.setCurrentIndex(0)))
        self.batch_refresh_button=button("刷新环境",self._populate_batch_targets)
        actions.addWidget(self.batch_refresh_button)
        self.batch_start_button=button("提交批量巡检",self._start_batch,primary=True)
        actions.addWidget(self.batch_start_button)
        self.batch_cancel_button=button("取消批任务",self._cancel_batch); self.batch_cancel_button.setEnabled(False)
        actions.addWidget(self.batch_cancel_button); actions.addStretch(1); layout.addLayout(actions)
        self.batch_error=muted_label(""); layout.addWidget(self.batch_error)
        self.batch_progress=QProgressBar();self.batch_progress.setRange(0,100);self.batch_progress.hide();layout.addWidget(self.batch_progress)
        self.batch_summary=muted_label("尚未提交；完成进度不等于全部交付成功。");self.batch_summary.hide();layout.addWidget(self.batch_summary)
        self.batch_empty=QWidget();empty=QHBoxLayout(self.batch_empty);empty.setContentsMargins(0,0,0,0)
        empty.addWidget(muted_label("尚无环境档案，请先建立巡检目标。"),1);empty.addWidget(button("打开环境档案",lambda:self.go_to_module("vcenter_management")));self.batch_empty.hide();layout.addWidget(self.batch_empty)
        self.batch_tabs=QTabWidget()
        self.batch_targets=table(self,["选择","客户 / 环境","地址","档案","用户名（会话）","密码（会话）"])
        self.batch_targets.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.batch_targets.setWordWrap(False);self.batch_targets.setTextElideMode(Qt.ElideRight)
        for i in (0,3):
            self.batch_targets.horizontalHeader().setSectionResizeMode(i,QHeaderView.Fixed);self.batch_targets.setColumnWidth(i,56)
        self.batch_targets.setItemDelegateForColumn(0,SelectionDelegate(self.batch_targets))
        targets_page=QWidget(); targets_layout=QVBoxLayout(targets_page); targets_layout.setContentsMargins(0,0,0,0)
        targets_layout.addWidget(self.batch_targets,1)
        self.batch_target_information=self._target_information(self.batch_targets,lambda:getattr(self,"_batch_profiles",[]));targets_layout.addWidget(self.batch_target_information)
        self.batch_tabs.addTab(targets_page,"目标与会话凭据")
        self.batch_results=table(self,["客户 / 环境","状态","采集","分析","交付","说明","报告"])
        self.batch_results.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        for i,w in enumerate((200,120,120,120,120,220,150)):self.batch_results.setColumnWidth(i,w)
        self.batch_tabs.addTab(self.batch_results,"进度与结果");self.batch_tabs.setTabVisible(1,False)
        for widget in (self.batch_targets,self.batch_results):
            widget.setMinimumHeight(140);widget.setMaximumHeight(16777215)
        self.batch_targets.setMinimumHeight(80)
        layout.addWidget(self.batch_tabs,1)
        return page

    def _batch_service(self):
        path=self._db_path().resolve()
        manager=getattr(self,"_batch_manager",None)
        if manager is None or manager.store.path.resolve()!=path:
            if getattr(self,"batch_worker",None) and self.batch_worker.isRunning():
                raise ValueError("批任务执行中不能切换数据库。")
            factory=getattr(self,"batch_service_factory",None)
            self._batch_manager=BatchInspectionService(path,service_factory=factory)
        return self._batch_manager

    def _open_batch(self):
        self.go_to_module("inspection_center");self.inspection_pages.setCurrentIndex(2)
        self._update_current_object_bar()
        self._populate_batch_targets()
        self.batch_tabs.setCurrentIndex(0)
        try:
            latest=self._batch_service().store.latest()
            if latest:self._batch_progress_changed(latest)
        except (ValueError,OSError,sqlite3.Error):
            self.batch_error.setText("无法读取批任务，请检查本地数据库。")

    def _populate_batch_targets(self):
        if getattr(self,"batch_worker",None) and self.batch_worker.isRunning():return
        self._batch_profiles=self.service.list_environment_archives(self._db_path())
        fill_table(self.batch_targets,[["",f"{e.customer_name} / {e.name}",e.address,"启用" if e.enabled else "停用","",""] for e in self._batch_profiles])
        for row,e in enumerate(self._batch_profiles):
            select=self.batch_targets.item(row,0);select.setFlags(select.flags()|Qt.ItemIsUserCheckable);select.setCheckState(Qt.Unchecked);select.setData(Qt.UserRole,e.environment_id)
            if not e.enabled:select.setFlags(select.flags()&~Qt.ItemIsEnabled)
            username=QLineEdit(e.username);password=QLineEdit();password.setEchoMode(QLineEdit.Password);password.setPlaceholderText("仅当前会话")
            self.batch_targets.setCellWidget(row,4,username);self.batch_targets.setCellWidget(row,5,password)
            self.batch_targets.item(row,1).setToolTip(f"{e.customer_name} / {e.name}")
        self.batch_empty.setVisible(not self._batch_profiles);self.batch_start_button.setEnabled(bool(self._batch_profiles))
        self.batch_targets.resizeRowsToContents()
        self.batch_targets.setMinimumHeight(140);self.batch_targets.setMaximumHeight(16777215)

    def _start_batch(self):
        if getattr(self,"_batch_closing",False) or getattr(self,"batch_worker",None) and self.batch_worker.isRunning():return
        ids=[];credentials={}
        for row,e in enumerate(getattr(self,"_batch_profiles",[])):
            if self.batch_targets.item(row,0).checkState()!=Qt.Checked:continue
            ids.append(e.environment_id)
            credentials[e.environment_id]=SessionCredential(self.batch_targets.cellWidget(row,4).text(),self.batch_targets.cellWidget(row,5).text())
        try:
            manager=self._batch_service()
            settings=BatchSettings(self._db_path(),Path(self.default_report_dir_input.path_value()),Path(self.rulepack_path_input.path_value()))
            batch_id=manager.submit(ids,credentials,settings)
        except (ValueError,OSError,sqlite3.Error) as exc:
            self.batch_error.setText(str(exc));return
        self.batch_error.clear();self._current_batch_id=batch_id
        self.batch_tabs.setTabVisible(1,True);self.batch_tabs.setCurrentIndex(1)
        self.batch_start_button.setEnabled(False);self.batch_refresh_button.setEnabled(False);self.batch_cancel_button.setEnabled(True);self.batch_targets.setEnabled(False)
        for row in range(self.batch_targets.rowCount()):self.batch_targets.cellWidget(row,5).clear()
        self.batch_worker=BatchWorker(manager,batch_id,self)
        self.batch_worker.progress.connect(self._batch_progress_changed);self.batch_worker.completed.connect(self._batch_progress_changed)
        self.batch_worker.failed.connect(self.batch_error.setText);self.batch_worker.finished.connect(self._batch_worker_finished)
        self._batch_progress_changed(manager.store.snapshot(batch_id));self.batch_worker.start()

    def _cancel_batch(self):
        worker=getattr(self,"batch_worker",None)
        if worker and worker.isRunning():
            worker.request_cancel();self.batch_cancel_button.setEnabled(False)
            self._batch_progress_changed(worker.service.store.snapshot(worker.batch_id))
            self.batch_summary.setText(self.batch_summary.text()+"\n已请求取消，等待当前步骤结束；不会启动下一项。")

    def _batch_progress_changed(self,snapshot):
        if getattr(self,"_batch_closing",False):return
        self._batch_snapshot=snapshot;self.batch_progress.setValue(snapshot["percent"]);self.batch_progress.setVisible(snapshot.get("state") in {"running","waiting","cancelling"});self.batch_summary.show();self.batch_tabs.setTabVisible(1,True)
        counts=snapshot["counts"]
        self.batch_summary.setText(f"已结束 {sum(counts[s] for s in ('completed','partial_failed','failed','cancelled','interrupted'))}/{snapshot['total']}；"+" · ".join(f"{LABELS[s]} {counts[s]}" for s in ('completed','partial_failed','failed','cancelled','interrupted')))
        fill_table(self.batch_results,[[f"{i['target']['customer_name']}\n{i['target']['name']}",LABELS.get(i['state'],i['state']),LABELS.get(i['collection_state'],i['collection_state']),LABELS.get(i['analysis_state'],i['analysis_state']),LABELS.get(i['delivery_state'],i['delivery_state']),i['reason'],""] for i in snapshot["items"]])
        self.batch_results.setMinimumHeight(140);self.batch_results.setMaximumHeight(16777215)
        for row,item in enumerate(snapshot["items"]):
            for column in range(6):
                self.batch_results.item(row,column).setToolTip(self.batch_results.item(row,column).text())
            control=button("查看报告",lambda checked=False,run_id=item["run_id"],db=snapshot["db_path"]:self._batch_open_report(run_id,db))
            control.setEnabled(bool(item["run_id"] and self.service.desktop_report_formats(Path(snapshot["db_path"]),item["run_id"])))
            self.batch_results.setCellWidget(row,6,control)

    def _batch_open_report(self,run_id,db_path=None):
        # Open this run's own directory, never overwrite the result browsing scope.
        formats=self.service.desktop_report_formats(Path(db_path) if db_path else self._db_path(),run_id)
        if formats:self._open_path_safe(next(iter(formats.values())).parent)

    def _batch_worker_finished(self):
        worker=self.batch_worker;self.batch_worker=None
        if worker:worker.deleteLater()
        if getattr(self,"_batch_closing",False):return
        self.batch_start_button.setEnabled(True);self.batch_refresh_button.setEnabled(True);self.batch_cancel_button.setEnabled(False);self.batch_targets.setEnabled(True)

    def _active_workers(self):
        return [w for name in ("batch_worker","worker","log_worker","upgrade_worker","upgrade_hcl_import_worker","cloud_test_worker") if (w:=getattr(self,name,None)) is not None and w.isRunning()]

    def _safe_close(self,event):
        workers=self._active_workers()
        if not workers:
            event.accept();return
        if not getattr(self,"_batch_closing",False):
            reply=QMessageBox.question(self,"任务仍在运行","停止后续批量任务，并等待当前任务安全结束后退出？",QMessageBox.Yes|QMessageBox.No,QMessageBox.No)
            if reply!=QMessageBox.Yes:event.ignore();return
            self._batch_closing=True
            self.status_label.setText("已请求取消，等待当前步骤结束后退出。")
            self.batch_start_button.setEnabled(False);self.start_button.setEnabled(False)
            for worker in workers:
                cancel=getattr(worker,"request_cancel",None)
                if cancel:cancel()
            self.batch_summary.setText("正在安全结束运行任务；停止启动下一项，结束后退出。")
            self._close_timer=QTimer(self);self._close_timer.timeout.connect(self._finish_safe_close);self._close_timer.start(200)
        event.ignore()

    def _finish_safe_close(self):
        if not self._active_workers():
            self._close_timer.stop();self.close()
