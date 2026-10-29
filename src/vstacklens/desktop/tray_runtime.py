"""Window close is a choice; actual exit waits for cooperative worker completion."""
import sqlite3
from PySide6.QtCore import QTimer
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import QApplication, QCheckBox, QDialog, QHBoxLayout, QLabel, QMenu, QPushButton, QSystemTrayIcon, QVBoxLayout

from vstacklens.db.schedule_store import ScheduleStore
from vstacklens.desktop.layout3a import button
from vstacklens.desktop.widgets import SectionCard, muted_label, NoWheelComboBox as QComboBox
from vstacklens.desktop.windowing import app_icon_path


class CloseChoiceDialog(QDialog):
    def __init__(self, parent=None, *, tray_available=True):
        super().__init__(parent); self.setWindowTitle("关闭 VStackLens"); self.choice = None
        layout = QVBoxLayout(self)
        label = QLabel("最小化到托盘会继续当前任务和计划；真正退出会停止计划，并等待运行任务安全结束。")
        label.setWordWrap(True); layout.addWidget(label)
        self.remember = QCheckBox("记住我的选择（可在设置中修改）"); self.remember.setChecked(False); layout.addWidget(self.remember)
        self.tray_button = QPushButton("最小化到托盘，继续运行"); self.tray_button.setEnabled(tray_available)
        self.exit_button = QPushButton("退出软件，停止计划巡检")
        layout.addWidget(self.tray_button); layout.addWidget(self.exit_button)
        if not tray_available: layout.addWidget(QLabel("系统托盘不可用，不能隐藏窗口；可取消关闭或退出软件。"))
        cancel = QPushButton("取消关闭"); layout.addWidget(cancel)
        self.tray_button.clicked.connect(lambda: self._choose("tray")); self.exit_button.clicked.connect(lambda: self._choose("exit")); cancel.clicked.connect(self.reject)
        self.setMinimumWidth(460)
    def _choose(self, choice):
        self.choice = choice; self.accept()


class TrayRuntimeMixin:
    def _initialize_tray(self):
        self._tray = None; self._exit_ready = False
        if not QSystemTrayIcon.isSystemTrayAvailable(): return
        self._tray = QSystemTrayIcon(QIcon(str(app_icon_path())), self)
        self._tray.setToolTip("VStackLens · 运行中")
        menu = QMenu(self)
        self._tray_status = QAction("软件运行中；仅运行期间执行计划", menu); self._tray_status.setEnabled(False); menu.addAction(self._tray_status)
        menu.addAction("恢复窗口", self._restore_from_tray)
        menu.addAction("查看计划与运行状态", self._tray_open_plans)
        self._tray_pause = menu.addAction("暂停计划", self._tray_toggle_plans)
        menu.addSeparator(); menu.addAction("退出软件，停止计划巡检", self._begin_exit)
        self._tray.setContextMenu(menu)
        menu.aboutToShow.connect(self._update_tray_status)
        self._tray.activated.connect(lambda reason: self._restore_from_tray() if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick) else None)
        self._tray.show()

    def _tray_available(self):
        return self._tray is not None and QSystemTrayIcon.isSystemTrayAvailable() and self._tray.isVisible()

    def _restore_from_tray(self):
        self.showNormal(); self.raise_(); self.activateWindow()

    def _tray_open_plans(self):
        self._restore_from_tray(); self._open_plans()
        self._update_tray_status()
        self.plan_status.setText(self._tray_status.text())

    def _update_tray_status(self):
        if self._batch_closing:
            self._tray_status.setText("正在安全退出，计划已停止；等待当前步骤结束。")
            return
        names = [text for name, text in (("worker", "标准巡检"), ("batch_worker", "手动批量"), ("plan_worker", "计划巡检"), ("log_worker", "日志分析"), ("upgrade_worker", "升级检查")) if (w := getattr(self, name, None)) is not None and w.isRunning()]
        manager = getattr(self, "_plan_manager", None)
        plan_state = "计划暂停" if manager and manager.paused else "计划运行期间有效"
        self._tray_status.setText(("运行中：" + "、".join(names) if names else "当前无运行任务") + "；" + plan_state)

    def _tray_toggle_plans(self):
        manager = self._plan_service()
        manager.paused = not manager.paused
        self._tray_pause.setText("恢复计划" if manager.paused else "暂停计划")
        self._tray_status.setText("计划已暂停；当前任务继续，错过不补跑" if manager.paused else "计划已恢复；错过不补跑")
        self._reload_plans()

    def _read_close_choice(self):
        try:
            return ScheduleStore(self._db_path()).close_choice() if ScheduleStore.exists(self._db_path()) else "ask"
        except (OSError, sqlite3.Error):
            self.status_label.setText("关闭设置读取失败，本次仍需明确选择；不会自动隐藏窗口。")
            return "ask"

    def _choose_close_action(self):
        dialog = CloseChoiceDialog(self, tray_available=self._tray_available())
        result = dialog.exec()
        choice = dialog.choice if result == QDialog.Accepted else None
        remember = dialog.remember.isChecked()
        dialog.deleteLater()
        return choice, remember

    def _close_preference_card(self):
        card = SectionCard("关闭窗口与计划巡检")
        card.layout.addWidget(muted_label("默认每次询问；只有主动记住或修改设置才保存选择。真正退出后停止计划，不启动系统后台服务。"))
        row = QHBoxLayout(); self.close_choice_combo = QComboBox()
        for text, value in (("每次询问", "ask"), ("最小化到托盘，继续运行", "tray"), ("退出软件，停止计划巡检", "exit")):
            self.close_choice_combo.addItem(text, value)
        row.addWidget(self.close_choice_combo, 1); row.addWidget(button("保存关闭选择", self._save_close_choice)); card.layout.addLayout(row)
        self.close_choice_feedback = muted_label(""); card.layout.addWidget(self.close_choice_feedback)
        return card

    def _save_close_choice(self):
        ScheduleStore(self._db_path()).set_close_choice(self.close_choice_combo.currentData())
        self.close_choice_feedback.setText("关闭选择已保存：" + self.close_choice_combo.currentText())

    def _active_workers(self):
        workers = super()._active_workers()
        # Check workers remain managed until their GUI cleanup clears the owner,
        # including the short gap after run() ends but finished is still queued.
        return workers + [w for name in ("plan_worker", "plan_tick_worker") if (w := getattr(self, name, None)) is not None and (name == "plan_tick_worker" or w.isRunning())]

    def _safe_close(self, event):
        if self._exit_ready:
            event.accept(); return
        if self._batch_closing:
            event.ignore(); return
        choice = self._read_close_choice()
        remember = False
        if choice == "tray" and not self._tray_available(): choice = "ask"
        if choice == "ask": choice, remember = self._choose_close_action()
        if not choice:
            event.ignore(); return
        if choice == "tray":
            if not self._tray_available():
                self.status_label.setText("系统托盘不可用，窗口保持可见；请重新选择退出或取消关闭。")
                self._restore_from_tray(); event.ignore(); return
            if remember: ScheduleStore(self._db_path()).set_close_choice("tray")
            QApplication.instance().setQuitOnLastWindowClosed(False)
            self.hide(); event.ignore(); return
        if remember: ScheduleStore(self._db_path()).set_close_choice("exit")
        self._begin_exit()
        if self._exit_ready: event.accept()
        else: event.ignore()

    def _begin_exit(self):
        if self._batch_closing: return
        self._batch_closing = True
        if hasattr(self, "_plan_timer"): self._plan_timer.stop()
        if self._plan_manager:
            try: self._plan_manager.stop()
            except (OSError, sqlite3.Error): self._exit_persistence_error = True
        self.status_label.setText("已停止计划，等待当前步骤结束后退出。")
        if hasattr(self, "_tray_status"): self._tray_status.setText("正在安全退出，计划已停止；等待当前步骤结束。")
        self.start_button.setEnabled(False); self.batch_start_button.setEnabled(False)
        self.plan_save_button.setEnabled(False); self.plan_authorize_button.setEnabled(False)
        for worker in self._active_workers():
            cancel = getattr(worker, "request_cancel", None)
            if cancel:
                try: cancel()
                except (OSError, sqlite3.Error): self._exit_persistence_error = True
        self._close_timer = QTimer(self); self._close_timer.timeout.connect(self._finish_safe_close); self._close_timer.start(100)
        self._finish_safe_close()

    def _finish_safe_close(self):
        if not self._batch_closing or self._active_workers(): return
        if self._plan_manager:
            try: self._plan_manager.finish_shutdown()
            except ValueError:
                self.status_label.setText("任务仍在安全结束中，保留会话并继续等待，不强制退出。")
                return
            except (OSError, sqlite3.Error):
                self._exit_persistence_error = True
                self.status_label.setText("任务已安全停止；退出记录未能写入，保留占用供重启核对，不宣称交付成功。")
        if getattr(self, "_batch_manager", None): self._batch_manager.clear_idle_credentials()
        self._close_timer.stop()
        self._clear_plan_passwords()
        for name in ("password_input", "upgrade_password_input", "current_password_input", "new_password_input", "confirm_password_input", "settings_profile_api_key_input"):
            field = getattr(self, name, None)
            if field: field.clear()
        for row in range(self.batch_targets.rowCount()): self.batch_targets.cellWidget(row, 5).clear()
        if self._tray: self._tray.hide()
        self._exit_ready = True
        self.close()
        # Tests own a shared QApplication; never terminate an unrelated embedding app.
        if getattr(QApplication.instance(), "vstacklens_owns_event_loop", False): QApplication.instance().quit()
