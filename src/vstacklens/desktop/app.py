from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from vstacklens.application import (
    AuthService,
    DashboardData,
    DEFAULT_CUSTOMER_NAME,
    DEFAULT_LOG_ANALYSIS_TITLE,
    DEFAULT_LOG_CHECK_TITLE,
    DEFAULT_REPORT_TITLE,
    DEFAULT_SITE_NAME,
    DesktopInspectionConfig,
    CheckEvidenceItem,
    HistoryAssetChangeItem,
    HistoryComparison,
    HistoryRiskChangeItem,
    InspectionProgress,
    InspectionRunResult,
    InspectionService,
    InspectionState,
    LogAnalysisConfig,
    LogAnalysisProgress,
    LogAnalysisResult,
    DEFAULT_UPGRADE_COMPAT_TITLE,
    UpgradeCompatConfig,
    UpgradeCompatProgress,
    UpgradeCompatResult,
    PlatformAssetItem,
    PlatformFindingItem,
    ModelConfigProfile,
    ReportCenterItem,
    ReportHistoryItem,
    log_analysis_display_stats,
)
from vstacklens.application.cloud_log_diagnosis import (
    DEFAULT_CLOUD_API_URL,
    DEFAULT_CLOUD_MODEL,
    DEFAULT_CLOUD_PROVIDER,
    CloudModelClient,
    CloudModelConfig,
    sanitize_cloud_error,
)
from vstacklens.application.logging_config import (
APP_VERSION,
    configure_runtime_logging,
    get_logger,
    runtime_log_path,
    runtime_mode,
)
from vstacklens.desktop.modules import ModuleDescriptor, inspection_capabilities, primary_modules
from vstacklens.desktop.theme import APP_STYLE
from vstacklens.desktop.topology import ProductLogo
from vstacklens.desktop.windowing import app_icon_path, enable_windows_dark_title_bar
from vstacklens.desktop.widgets import EmptyState, InfoCard, MetricCard, NoWheelComboBox, PageHeader, PathLineEdit, RiskTrendChart, SectionCard, muted_label, risk_badge, status_badge
from vstacklens.db.repositories import actionable_risk_total


try:
    from PySide6.QtCore import QSize, Qt, QThread, QTimer, Signal
    from PySide6.QtGui import QAction, QColor, QFont, QFontDatabase, QIcon, QPainter, QPen, QPixmap
    from PySide6.QtWidgets import (
        QApplication,
        QCheckBox,
        QComboBox,
        QDialog,
        QFileDialog,
        QFormLayout,
        QFrame,
        QGridLayout,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QListWidget,
        QListWidgetItem,
        QMainWindow,
        QMessageBox,
        QProgressBar,
        QPushButton,
        QScrollArea,
        QSpinBox,
        QSplitter,
        QStackedWidget,
        QTableWidget,
        QTableWidgetItem,
        QTabWidget,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )
except ImportError as exc:  # pragma: no cover - exercised only when launching the desktop UI.
    raise SystemExit("PySide6 未安装。请先安装 PySide6 后再启动桌面客户端。") from exc


LOGGER = get_logger(__name__)
PRODUCTION_IMPACT_TOOLTIP = (
    "本工具通过 vCenter SDK 读取清单、配置、告警和性能数据，不会创建、删除或修改虚拟机、主机、快照、权限、告警、网络或存储配置。"
    "巡检过程会对 vCenter 产生轻量查询压力，大型环境建议在非业务高峰期执行。"
    "单项采集异常会降级处理，不中断整体巡检。"
)
FRIENDLY_DB_LOCK_ERROR = "本地数据库暂时被占用，请稍后重试。如多次出现，请关闭并重新打开软件。"


def friendly_error_message(error: str) -> str:
    lower = (error or "").lower()
    if "database is locked" in lower or "database table is locked" in lower or "database schema is locked" in lower:
        return FRIENDLY_DB_LOCK_ERROR
    return error


def password_visibility_icon(*, visible: bool) -> QIcon:
    """Create the small offline eye icon used by the password field action."""
    pixmap = QPixmap(22, 22)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setPen(QPen(QColor("#9FBCE0"), 1.8))
    painter.setBrush(Qt.NoBrush)
    painter.drawEllipse(3, 7, 16, 10)
    painter.setBrush(QColor("#9FBCE0"))
    painter.setPen(Qt.NoPen)
    painter.drawEllipse(9, 10, 4, 4)
    if visible:
        painter.setPen(QPen(QColor("#9FBCE0"), 1.8))
        painter.drawLine(4, 4, 18, 18)
    painter.end()
    return QIcon(pixmap)


def configure_chinese_font(app: QApplication) -> str | None:
    font_candidates = [
        Path(r"C:\Windows\Fonts\msyh.ttc"),
        Path(r"C:\Windows\Fonts\simsun.ttc"),
        Path(r"C:\Windows\Fonts\simhei.ttf"),
        Path(r"C:\Windows\Fonts\Deng.ttf"),
    ]
    for font_path in font_candidates:
        if not font_path.exists():
            continue
        font_id = QFontDatabase.addApplicationFont(str(font_path))
        if font_id < 0:
            continue
        families = QFontDatabase.applicationFontFamilies(font_id)
        if families:
            family = families[0]
            app.setFont(QFont(family, 9))
            print(f"Loaded Chinese UI font: {family} ({font_path})")
            return family
    print("Warning: no Chinese UI font could be loaded; using Qt default font.")
    return None


class LoginWindow(QDialog):
    def __init__(self, auth_service: AuthService | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.auth_service = auth_service or AuthService()
        self.authenticated = False
        self.logged_in_username = ""
        self.setWindowTitle("VStackLens Health Assessment Platform")
        self.setWindowIcon(QIcon(str(app_icon_path())))
        self.resize(600, 700)
        self.setMinimumSize(520, 620)
        self.setObjectName("loginWindow")
        self.setStyleSheet(APP_STYLE)
        enable_windows_dark_title_bar(self)

        root = QVBoxLayout(self)
        root.setContentsMargins(60, 44, 60, 36)
        root.setSpacing(0)
        root.addStretch(1)
        form = QWidget()
        form.setMaximumWidth(430)
        form_layout = QVBoxLayout(form)
        form_layout.setContentsMargins(0, 0, 0, 0)
        form_layout.setSpacing(12)

        logo = ProductLogo()
        logo.setFixedSize(88, 72)
        title = QLabel("VStackLens")
        title.setObjectName("loginTitle")
        title.setAlignment(Qt.AlignCenter)
        self.username_input = QLineEdit()
        self.username_input.setObjectName("loginInput")
        self.username_input.setPlaceholderText("输入用户名")
        self.username_input.setMinimumHeight(52)
        saved_username = self.auth_service.load_saved_username() or AuthService.DEFAULT_USERNAME
        if saved_username:
            self.username_input.setText(saved_username)
        self.password_input = QLineEdit()
        self.password_input.setObjectName("loginInput")
        self.password_input.setMinimumHeight(52)
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("请输入本地密码")
        self.password_input.returnPressed.connect(self._login)
        self.password_visibility_action = QAction(password_visibility_icon(visible=False), "", self.password_input)
        self.password_input.addAction(self.password_visibility_action, QLineEdit.TrailingPosition)
        self.password_visibility_action.setToolTip("显示密码")
        self.password_visibility_action.triggered.connect(self._toggle_password_visibility)
        self.remember_username = QCheckBox("记住用户名")
        self.remember_username.setChecked(bool(saved_username))
        self.error_label = QLabel("")
        self.error_label.setObjectName("loginError")
        self.error_label.setWordWrap(True)
        self.error_label.hide()

        self.login_button = QPushButton("登录")
        self.login_button.setObjectName("loginPrimaryButton")
        self.login_button.setMinimumHeight(54)
        self.login_button.setDefault(True)
        self.login_button.clicked.connect(self._login)

        username_label = QLabel("用户名")
        username_label.setObjectName("loginFieldLabel")
        password_label = QLabel("密码")
        password_label.setObjectName("loginFieldLabel")
        form_layout.addWidget(logo, alignment=Qt.AlignHCenter)
        form_layout.addSpacing(8)
        form_layout.addWidget(title)
        form_layout.addSpacing(40)
        form_layout.addWidget(username_label)
        form_layout.addWidget(self.username_input)
        form_layout.addSpacing(10)
        form_layout.addWidget(password_label)
        form_layout.addWidget(self.password_input)
        form_layout.addSpacing(8)
        form_layout.addWidget(self.remember_username)
        form_layout.addWidget(self.error_label)
        form_layout.addSpacing(12)
        form_layout.addWidget(self.login_button)
        form_layout.addSpacing(36)
        footer = muted_label(f"版本 {APP_VERSION}")
        footer.setAlignment(Qt.AlignCenter)
        form_layout.addWidget(footer)
        root.addWidget(form, alignment=Qt.AlignHCenter)
        root.addStretch(1)
        self.setTabOrder(self.username_input, self.password_input)
        self.setTabOrder(self.password_input, self.remember_username)
        self.setTabOrder(self.remember_username, self.login_button)
        self.username_input.returnPressed.connect(self.password_input.setFocus)

    def _toggle_password_visibility(self) -> None:
        visible = self.password_input.echoMode() == QLineEdit.Normal
        self.password_input.setEchoMode(QLineEdit.Password if visible else QLineEdit.Normal)
        self.password_visibility_action.setIcon(password_visibility_icon(visible=not visible))
        self.password_visibility_action.setToolTip("显示密码" if visible else "隐藏密码")

    def _login(self) -> None:
        username = self.username_input.text()
        password = self.password_input.text()
        if not self.auth_service.validate_login(username, password):
            self.error_label.setText("登录失败：本地用户名或密码不正确。")
            self.error_label.show()
            self.password_input.clear()
            self.password_input.setFocus()
            return
        self.auth_service.save_saved_username(username if self.remember_username.isChecked() else "")
        self.logged_in_username = username.strip()
        self.authenticated = True
        self.accept()


class DefaultPasswordWarningDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("建议修改默认密码")
        self.setWindowIcon(QIcon(str(app_icon_path())))
        self.setStyleSheet(APP_STYLE)
        self.resize(420, 220)
        enable_windows_dark_title_bar(self)
        self.modify_now = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 22)
        layout.setSpacing(14)
        title = QLabel("建议修改默认密码")
        title.setObjectName("sectionTitle")
        body = QLabel("当前本地管理员账号仍使用默认密码。为避免未授权访问，建议立即修改。")
        body.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(body)
        layout.addStretch(1)
        row = QHBoxLayout()
        row.addStretch(1)
        later = QPushButton("稍后处理")
        later.clicked.connect(self.reject)
        now = QPushButton("立即修改")
        now.setObjectName("primaryButton")
        now.clicked.connect(self._accept_modify)
        row.addWidget(later)
        row.addWidget(now)
        layout.addLayout(row)

    def _accept_modify(self) -> None:
        self.modify_now = True
        self.accept()


class InspectionWorker(QThread):
    progress = Signal(object)
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, service: InspectionService, config: DesktopInspectionConfig) -> None:
        super().__init__()
        self.service = service
        self.config = config
        self._cancel_requested = False

    def request_cancel(self) -> None:
        self._cancel_requested = True

    def cancel_requested(self) -> bool:
        return self._cancel_requested

    def run(self) -> None:
        try:
            self.completed.emit(
                self.service.run_vcenter_inspection(
                    self.config,
                    progress_callback=self.progress.emit,
                    cancel_requested=self.cancel_requested,
                )
            )
        except Exception as exc:  # noqa: BLE001 - surface all service errors to desktop users.
            LOGGER.exception("Desktop inspection worker failed")
            self.failed.emit(str(exc))


class LogAnalysisWorker(QThread):
    progress = Signal(object)
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, service: InspectionService, config: LogAnalysisConfig) -> None:
        super().__init__()
        self.service = service
        self.config = config

    def run(self) -> None:
        try:
            self.completed.emit(self.service.run_log_analysis(self.config, progress_callback=self.progress.emit))
        except Exception as exc:  # noqa: BLE001 - surface all service errors to desktop users.
            LOGGER.exception("Desktop log analysis worker failed")
            self.failed.emit(str(exc))


class UpgradeCompatWorker(QThread):
    progress = Signal(object)
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, service: InspectionService, config: UpgradeCompatConfig) -> None:
        super().__init__()
        self.service = service
        self.config = config
        self._cancel_requested = False

    def request_cancel(self) -> None:
        self._cancel_requested = True

    def run(self) -> None:
        try:
            self.completed.emit(self.service.run_upgrade_compat(self.config, progress_callback=self.progress.emit, cancel_requested=lambda: self._cancel_requested))
        except Exception as exc:  # noqa: BLE001 - show application errors in the result panel.
            LOGGER.exception("Desktop upgrade compatibility worker failed")
            self.failed.emit(str(exc))


class UpgradeHclImportWorker(QThread):
    progress = Signal(object)
    completed = Signal(object)
    failed = Signal(str)

    def __init__(
        self,
        service: InspectionService,
        *,
        db_path: Path,
        source: str,
        file_path: Path | None,
        online: bool,
        vcg_client_id: str,
        vcg_client_secret: str,
    ) -> None:
        super().__init__()
        self.service = service
        self.db_path = db_path
        self.source = source
        self.file_path = file_path
        self.online = online
        self.vcg_client_id = vcg_client_id
        self.vcg_client_secret = vcg_client_secret

    def run(self) -> None:
        try:
            result = self.service.import_upgrade_hcl_data(
                db_path=self.db_path,
                source=self.source,
                file_path=self.file_path,
                online=self.online,
                vcg_client_id=self.vcg_client_id or None,
                vcg_client_secret=self.vcg_client_secret or None,
                progress_callback=self.progress.emit,
            )
            self.completed.emit(result)
        except Exception as exc:  # noqa: BLE001 - report a recoverable local import error in the UI.
            LOGGER.exception("Desktop HCL import failed")
            self.failed.emit(str(exc))


class CloudConnectionTestWorker(QThread):
    completed = Signal(object)

    def __init__(self, config: CloudModelConfig) -> None:
        super().__init__()
        self.config = config

    def run(self) -> None:
        try:
            self.completed.emit(CloudModelClient(self.config).test_connection())
        except Exception as exc:  # noqa: BLE001 - keep UI resilient.
            LOGGER.exception("Desktop cloud connection test failed")
            self.completed.emit(type("CloudTestFailure", (), {"ok": False, "fallback_reason": sanitize_cloud_error(exc, self.config.api_key), "elapsed_ms": 0})())


class MainWindow(QMainWindow):
    def __init__(self, service: InspectionService | None = None, auth_service: AuthService | None = None, current_username: str | None = None) -> None:
        super().__init__()
        self.service = service or InspectionService()
        self.auth_service = auth_service or AuthService()
        self.current_username = current_username or AuthService.DEFAULT_USERNAME
        self.worker: InspectionWorker | None = None
        self.log_worker: LogAnalysisWorker | None = None
        self.upgrade_worker: UpgradeCompatWorker | None = None
        self.upgrade_hcl_import_worker: UpgradeHclImportWorker | None = None
        self.cloud_test_worker: CloudConnectionTestWorker | None = None
        self._cloud_connection_test_ok = False
        self._cloud_connection_test_fingerprint = ""
        self._model_profile_form_loading = False
        self._model_profiles: list[ModelConfigProfile] = []
        self._running = False
        self.current_result: InspectionRunResult | None = None
        self.current_log_result: LogAnalysisResult | None = None
        self.current_upgrade_result: UpgradeCompatResult | None = None
        self.module_descriptors = primary_modules()
        self.module_index = {item.module_id: index for index, item in enumerate(self.module_descriptors)}
        self._risk_items: list[PlatformFindingItem] = []
        self._asset_items: list[PlatformAssetItem] = []
        self._check_evidence_items: list[CheckEvidenceItem] = []
        self._history_comparison: HistoryComparison | None = None
        self._history_combo_updating = False
        self._report_items: list[ReportCenterItem] = []

        self.setWindowTitle("VStackLens Health Assessment Platform")
        self.setWindowIcon(QIcon(str(app_icon_path())))
        self.resize(1360, 860)
        self.setMinimumSize(1280, 800)
        self.setStyleSheet(APP_STYLE)
        enable_windows_dark_title_bar(self)

        self.nav = QListWidget()
        self.nav.setObjectName("moduleNav")
        for module in self.module_descriptors:
            item = QListWidgetItem(module.module_name)
            item.setData(Qt.UserRole, module.module_id)
            self.nav.addItem(item)
        self.nav.currentRowChanged.connect(self._switch_page)

        self.pages = QStackedWidget()
        self.pages.addWidget(self._dashboard_page())
        self.pages.addWidget(self._vcenter_management_page())
        self.pages.addWidget(self._inspection_center_page())
        self.pages.addWidget(self._log_analysis_page())
        self.pages.addWidget(self._upgrade_compat_page())
        self.pages.addWidget(self._risk_center_page())
        self.pages.addWidget(self._asset_center_page())
        self.pages.addWidget(self._history_compare_page())
        self.pages.addWidget(self._report_center_page())
        self.pages.addWidget(self._settings_page())
        self.pages.addWidget(self._license_page())

        root = QWidget()
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        root_layout.addWidget(self._top_bar())
        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        body.addWidget(self._sidebar())
        body.addWidget(self.pages, 1)
        root_layout.addLayout(body, 1)
        self.setCentralWidget(root)

        self._load_saved_config()
        self.go_to_module("dashboard")
        self._refresh_all_data()

    def _top_bar(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("topBar")
        frame.setFixedHeight(60)
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(20, 0, 24, 0)
        title = QLabel("VStackLens")
        title.setObjectName("brandTitle")
        subtitle = QLabel("Health Assessment Platform")
        subtitle.setObjectName("topSubtitle")
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addStretch(1)
        layout.addWidget(status_badge("available", "本地运行"))
        return frame

    def _sidebar(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("sidebar")
        frame.setFixedWidth(218)
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 16, 14, 16)
        layout.setSpacing(10)
        layout.addWidget(muted_label("导航"))
        layout.addWidget(self.nav, 1)
        layout.addWidget(muted_label("本地运行"), alignment=Qt.AlignCenter)
        return frame

    def _scroll_page(self, content: QWidget) -> QScrollArea:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setWidget(content)
        return scroll

    def _dashboard_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 22, 24, 24)
        layout.setSpacing(12)
        layout.addWidget(PageHeader("仪表盘"))

        top = QHBoxLayout()
        top.setSpacing(10)
        score_card = SectionCard("环境状态")
        score_card.setMinimumHeight(142)
        self.dashboard_health_badge = status_badge("unknown", "等待首次评估")
        self.dashboard_health_value = QLabel("等待首次评估")
        self.dashboard_health_value.setObjectName("dashboardHealthValue")
        self.dashboard_scope_label = muted_label("等待选择评估范围")
        self.dashboard_health_badge.hide()
        score_card.layout.addWidget(self.dashboard_health_value)
        score_card.layout.addWidget(self.dashboard_scope_label)
        top.addWidget(score_card, 2, alignment=Qt.AlignTop)
        self.risk_metric_labels: dict[str, QLabel] = {}
        self.risk_metric_cards: list[SectionCard] = []
        risk_overview = QWidget()
        risk_grid = QHBoxLayout(risk_overview)
        risk_grid.setContentsMargins(0, 0, 0, 0)
        risk_grid.setSpacing(10)
        self.risk_waiting_card = EmptyState("风险统计", "完成评估后展示 P1 / P2 / P3 风险与优化建议分布。", button_text="去巡检中心", on_click=lambda: self.go_to_module("inspection_center"))
        risk_grid.addWidget(self.risk_waiting_card)
        for index, level in enumerate(("P1", "P2", "P3", "P4")):
            card = SectionCard("优化建议" if level == "P4" else f"{level} 风险")
            card.setMinimumHeight(112)
            value = QLabel("0")
            value.setObjectName("metricValue")
            self.risk_metric_labels[level] = value
            card.layout.addWidget(value)
            card.setToolTip(f"点击左侧风险中心可查看全部 {level} 风险。")
            risk_grid.addWidget(card, 1)
            self.risk_metric_cards.append(card)
        top.addWidget(risk_overview, 5)
        layout.addLayout(top)

        self.asset_metric_row = QHBoxLayout()
        self.asset_metric_row.setSpacing(10)
        self.asset_metric_cards: dict[str, QLabel] = {}
        self.asset_metric_widgets: list[SectionCard] = []
        self.asset_waiting_card = EmptyState("资产概览", "完成评估后展示 vCenter / Cluster / Host / Datastore / VM。", button_text="去巡检中心", on_click=lambda: self.go_to_module("inspection_center"))
        self.asset_metric_row.addWidget(self.asset_waiting_card)
        for label, subtitle in (
            ("vCenter", "管理入口"),
            ("Cluster", "集群覆盖"),
            ("ESXi Host", "主机资源"),
            ("Datastore", "存储域"),
            ("VM", "业务负载"),
        ):
            card = SectionCard(label)
            card.setMinimumHeight(94)
            value = QLabel("0")
            value.setObjectName("smallMetricValue")
            self.asset_metric_cards[label] = value
            card.layout.addWidget(value)
            card.layout.addWidget(muted_label(subtitle))
            self.asset_metric_row.addWidget(card, 1)
            self.asset_metric_widgets.append(card)
        layout.addLayout(self.asset_metric_row)

        bottom = QGridLayout()
        bottom.setSpacing(12)
        self.trend_card = SectionCard("风险趋势")
        self.trend_text = muted_label("暂无历史数据。")
        self.trend_chart = RiskTrendChart()
        self.trend_card.layout.addWidget(self.trend_chart)
        self.trend_card.layout.addWidget(self.trend_text)
        self.certificate_summary_card = SectionCard("证书与授权")
        self.dashboard_certificate_summary = muted_label("完成巡检后展示证书和授权核验状态。")
        self.dashboard_certificate_list = QListWidget()
        self.dashboard_certificate_list.setObjectName("moduleNav")
        self.dashboard_certificate_list.setMaximumHeight(166)
        self.dashboard_certificate_list.setSpacing(4)
        self.dashboard_certificate_list.setWordWrap(True)
        self.dashboard_certificate_detail = QTextEdit()
        self.dashboard_certificate_detail.setReadOnly(True)
        self.dashboard_certificate_detail.setMaximumHeight(150)
        self.dashboard_certificate_detail.hide()
        self.dashboard_certificate_toggle = QPushButton("查看核验明细")
        self.dashboard_certificate_toggle.setObjectName("quietButton")
        self.dashboard_certificate_toggle.clicked.connect(self._toggle_certificate_detail)
        self.dashboard_certificate_toggle.setEnabled(False)
        self.certificate_summary_card.layout.addWidget(self.dashboard_certificate_summary)
        self.certificate_summary_card.layout.addWidget(self.dashboard_certificate_list)
        self.certificate_summary_card.layout.addWidget(self.dashboard_certificate_toggle, alignment=Qt.AlignLeft)
        self.certificate_summary_card.layout.addWidget(self.dashboard_certificate_detail)
        self.recent_report_card = SectionCard("最近报告")
        self.dashboard_reports_empty = EmptyState("暂无评估数据", "完成首次健康评估后，将展示健康状态、风险、资产和报告。", button_text="去巡检中心", on_click=lambda: self.go_to_module("inspection_center"))
        self.dashboard_reports_table = self._new_history_table(6, compact=True)
        self.recent_report_card.layout.addWidget(self.dashboard_reports_empty)
        self.recent_report_card.layout.addWidget(self.dashboard_reports_table)
        bottom.addWidget(self.trend_card, 0, 0)
        bottom.addWidget(self.certificate_summary_card, 0, 1)
        bottom.addWidget(self.recent_report_card, 1, 0, 1, 2)
        layout.addLayout(bottom)
        layout.addStretch(1)
        return self._scroll_page(page)

    def _vcenter_management_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 22, 24, 24)
        layout.setSpacing(16)
        layout.addWidget(PageHeader("vCenter 管理", "基于已完成巡检记录查看本机保存的 vCenter 对象和最近健康状态。"))
        self.vcenter_stack = QStackedWidget()
        self.vcenter_empty = self._centered_empty_panel()
        vcenter_data = QWidget()
        vcenter_data_layout = QVBoxLayout(vcenter_data)
        vcenter_data_layout.setContentsMargins(0, 0, 0, 0)
        self.vcenter_cards = QGridLayout()
        self.vcenter_cards.setSpacing(14)
        vcenter_data_layout.addLayout(self.vcenter_cards)
        vcenter_data_layout.addStretch(1)
        self.vcenter_stack.addWidget(self.vcenter_empty)
        self.vcenter_stack.addWidget(vcenter_data)
        layout.addWidget(self.vcenter_stack, 1)
        layout.addStretch(1)
        return self._scroll_page(page)

    def _inspection_center_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 22, 24, 24)
        layout.setSpacing(16)
        header_row = QHBoxLayout()
        header_row.addWidget(PageHeader("巡检中心", "发起虚拟化健康评估，实时跟踪阶段进度并生成 HTML 报告。"), 1)
        self.production_impact_info = QLabel("i")
        self.production_impact_info.setObjectName("productionImpactInfo")
        self.production_impact_info.setAlignment(Qt.AlignCenter)
        self.production_impact_info.setToolTip(PRODUCTION_IMPACT_TOOLTIP)
        self.production_impact_info.setFixedSize(22, 22)
        header_row.addWidget(self.production_impact_info, alignment=Qt.AlignTop)
        layout.addLayout(header_row)
        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self._inspection_tree_panel())
        splitter.addWidget(self._inspection_config_panel())
        splitter.addWidget(self._inspection_log_panel())
        splitter.setSizes([260, 560, 360])
        layout.addWidget(splitter, 1)
        return page

    def _inspection_tree_panel(self) -> QWidget:
        card = SectionCard("客户 / vCenter")
        self.scope_label = QLabel("暂无已记录 vCenter")
        self.scope_label.setWordWrap(True)
        self.scope_hint = EmptyState("暂无评估数据", "完成首次健康评估后，将展示健康状态、风险、资产和报告。")
        card.layout.addWidget(self.scope_label)
        card.layout.addWidget(self.scope_hint)
        card.layout.addStretch(1)
        return card

    def _inspection_config_panel(self) -> QWidget:
        card = SectionCard("巡检任务配置")
        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignRight)
        form.setVerticalSpacing(8)
        form.setHorizontalSpacing(12)
        self.vcenter_input = QLineEdit()
        self.vcenter_input.setPlaceholderText("请输入 vCenter IP 或 FQDN")
        self.username_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.customer_input = QLineEdit()
        self.customer_input.setPlaceholderText(DEFAULT_CUSTOMER_NAME)
        self.report_title_input = QLineEdit()
        self.report_title_input.setPlaceholderText(DEFAULT_REPORT_TITLE)
        self.site_input = QLineEdit()
        self.report_dir_input = PathLineEdit()
        browse_report = QPushButton("选择目录")
        browse_report.clicked.connect(self._choose_report_dir)
        report_dir_row = QWidget()
        report_dir_layout = QHBoxLayout(report_dir_row)
        report_dir_layout.setContentsMargins(0, 0, 0, 0)
        report_dir_layout.addWidget(self.report_dir_input, 1)
        report_dir_layout.addWidget(browse_report)
        form.addRow("vCenter 地址", self.vcenter_input)
        form.addRow("用户名", self.username_input)
        form.addRow("密码", self.password_input)
        form.addRow("客户名称", self.customer_input)
        form.addRow("报告名称", self.report_title_input)
        form.addRow("报告输出目录", report_dir_row)
        card.layout.addLayout(form)
        row = QHBoxLayout()
        self.start_button = QPushButton("立即健康评估")
        self.start_button.setObjectName("primaryButton")
        self.start_button.clicked.connect(self._start_inspection)
        self.cancel_inspection_button = QPushButton("取消巡检")
        self.cancel_inspection_button.setEnabled(False)
        self.cancel_inspection_button.hide()
        self.cancel_inspection_button.clicked.connect(self._cancel_inspection)
        row.addWidget(self.start_button)
        row.addWidget(self.cancel_inspection_button)
        row.addStretch(1)
        card.layout.addLayout(row)
        roadmap = muted_label("后续能力路线图：批量巡检、计划巡检将在后续版本开放，当前核心操作区仅提供单 vCenter 健康评估。")
        roadmap.setWordWrap(True)
        card.layout.addWidget(roadmap)
        card.layout.addStretch(1)
        return card

    def _inspection_log_panel(self) -> QWidget:
        card = SectionCard("实时日志")
        self.stage_label = QLabel("等待健康评估")
        self.stage_label.setObjectName("sectionTitle")
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.status_label = muted_label("填写 vCenter 信息后即可启动。")
        self.result_summary = QTextEdit()
        self.result_summary.setReadOnly(True)
        self.result_summary.setMinimumHeight(180)
        self.result_summary.setPlaceholderText("等待开始评估")
        self.open_report_button = QPushButton("打开 HTML 报告")
        self.open_report_button.setEnabled(False)
        self.open_report_button.clicked.connect(self._open_current_report)
        self.open_word_button = QPushButton("打开 Word 报告")
        self.open_word_button.setEnabled(False)
        self.open_word_button.clicked.connect(self._open_current_word_report)
        self.open_pdf_button = QPushButton("打开 PDF 报告")
        self.open_pdf_button.setEnabled(False)
        self.open_pdf_button.clicked.connect(self._open_current_pdf_report)
        self.open_dir_button = QPushButton("打开报告目录")
        self.open_dir_button.setEnabled(False)
        self.open_dir_button.clicked.connect(self._open_current_report_dir)
        row = QHBoxLayout()
        row.addWidget(self.open_report_button)
        row.addWidget(self.open_word_button)
        row.addWidget(self.open_pdf_button)
        row.addWidget(self.open_dir_button)
        card.layout.addWidget(self.stage_label)
        card.layout.addWidget(self.progress_bar)
        card.layout.addWidget(self.status_label)
        card.layout.addWidget(self.result_summary, 1)
        card.layout.addLayout(row)
        return card

    def _log_analysis_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 22, 24, 24)
        layout.setSpacing(16)
        layout.addWidget(PageHeader("日志分析", "导入 VMware support bundle 日志包并填写问题描述，生成独立 HTML / Word 日志分析报告。"))
        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self._log_analysis_config_panel())
        splitter.addWidget(self._log_analysis_result_panel())
        splitter.setSizes([650, 430])
        layout.addWidget(splitter, 1)
        return page

    def _log_analysis_config_panel(self) -> QWidget:
        card = SectionCard("日志分析输入")
        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignRight)
        form.setVerticalSpacing(8)
        form.setHorizontalSpacing(12)

        self.log_bundle_input = PathLineEdit()
        browse_bundle = QPushButton("选择日志包")
        browse_bundle.clicked.connect(self._choose_log_bundle)
        bundle_row = QWidget()
        bundle_layout = QHBoxLayout(bundle_row)
        bundle_layout.setContentsMargins(0, 0, 0, 0)
        bundle_layout.addWidget(self.log_bundle_input, 1)
        bundle_layout.addWidget(browse_bundle)

        self.log_problem_input = QTextEdit()
        self.log_problem_input.setMinimumHeight(140)
        self.log_problem_input.setPlaceholderText("请描述故障现象、发生时间、影响对象或已观察到的报错。")
        self.log_customer_input = QLineEdit()
        self.log_customer_input.setPlaceholderText(DEFAULT_CUSTOMER_NAME)
        self.log_report_title_input = QLineEdit()
        self.log_report_title_input.setPlaceholderText(DEFAULT_LOG_ANALYSIS_TITLE)
        self.log_report_dir_input = PathLineEdit()
        browse_output = QPushButton("选择目录")
        browse_output.clicked.connect(self._choose_log_report_dir)
        output_row = QWidget()
        output_layout = QHBoxLayout(output_row)
        output_layout.setContentsMargins(0, 0, 0, 0)
        output_layout.addWidget(self.log_report_dir_input, 1)
        output_layout.addWidget(browse_output)

        form.addRow("日志包路径", bundle_row)
        form.addRow("问题描述", self.log_problem_input)
        form.addRow("客户名称", self.log_customer_input)
        form.addRow("报告名称", self.log_report_title_input)
        form.addRow("报告输出目录", output_row)
        card.layout.addLayout(form)

        cloud_form = QFormLayout()
        cloud_form.setLabelAlignment(Qt.AlignRight)
        cloud_form.setVerticalSpacing(8)
        cloud_form.setHorizontalSpacing(12)
        self.log_cloud_enabled_input = QCheckBox("启用大模型辅助分析")
        self.log_cloud_enabled_input.setChecked(False)
        self.log_cloud_enabled_input.toggled.connect(self._log_cloud_selection_changed)
        self.log_model_profile_combo = NoWheelComboBox()
        self.log_model_profile_combo.currentIndexChanged.connect(self._log_cloud_selection_changed)
        self.log_model_input = NoWheelComboBox()
        self.log_model_input.currentIndexChanged.connect(self._log_cloud_selection_changed)
        self.log_refresh_models_button = QPushButton("刷新")
        self.log_refresh_models_button.clicked.connect(self._refresh_log_profile_models)
        self.log_cloud_status_label = muted_label("未测试")
        model_row = QWidget()
        model_layout = QHBoxLayout(model_row)
        model_layout.setContentsMargins(0, 0, 0, 0)
        model_layout.addWidget(self.log_model_input, 1)
        model_layout.addWidget(self.log_refresh_models_button)
        cloud_form.addRow("", self.log_cloud_enabled_input)
        cloud_form.addRow("模型配置", self.log_model_profile_combo)
        cloud_form.addRow("模型", model_row)
        cloud_form.addRow("状态", self.log_cloud_status_label)
        card.layout.addWidget(QLabel("大模型辅助分析"))
        card.layout.addLayout(cloud_form)

        row = QHBoxLayout()
        self.log_start_button = QPushButton("开始日志分析")
        self.log_start_button.setObjectName("primaryButton")
        self.log_start_button.clicked.connect(self._start_log_analysis)
        row.addWidget(self.log_start_button)
        row.addStretch(1)
        card.layout.addLayout(row)
        card.layout.addWidget(muted_label("日志分析是独立功能，仅基于导入的 support bundle 生成报告，不写入健康巡检结果。"))
        card.layout.addStretch(1)
        return card

    def _log_analysis_result_panel(self) -> QWidget:
        card = SectionCard("日志分析结果")
        self.log_stage_label = QLabel("等待日志分析")
        self.log_stage_label.setObjectName("sectionTitle")
        self.log_progress_bar = QProgressBar()
        self.log_progress_bar.setRange(0, 100)
        self.log_status_label = muted_label("导入日志包并填写问题描述后即可启动。")
        self.log_result_summary = QTextEdit()
        self.log_result_summary.setReadOnly(True)
        self.log_result_summary.setMinimumHeight(260)
        self.log_result_summary.setPlaceholderText("等待开始日志分析")
        self.open_log_html_button = QPushButton("打开 HTML 日志报告")
        self.open_log_html_button.setEnabled(False)
        self.open_log_html_button.clicked.connect(self._open_current_log_html_report)
        self.open_log_word_button = QPushButton("打开 Word 日志报告")
        self.open_log_word_button.setEnabled(False)
        self.open_log_word_button.clicked.connect(self._open_current_log_word_report)
        self.open_log_dir_button = QPushButton("打开报告目录")
        self.open_log_dir_button.setEnabled(False)
        self.open_log_dir_button.clicked.connect(self._open_current_log_report_dir)
        row = QHBoxLayout()
        row.addWidget(self.open_log_html_button)
        row.addWidget(self.open_log_word_button)
        row.addWidget(self.open_log_dir_button)
        card.layout.addWidget(self.log_stage_label)
        card.layout.addWidget(self.log_progress_bar)
        card.layout.addWidget(self.log_status_label)
        card.layout.addWidget(self.log_result_summary, 1)
        card.layout.addLayout(row)
        return card

    def _upgrade_compat_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 22, 24, 24)
        layout.setSpacing(16)
        layout.addWidget(PageHeader("升级兼容性", "按目标 ESXi 版本检查整机、基础设备和 vSAN 专项兼容性，结果独立于健康巡检。"))
        status_row = QWidget()
        status_layout = QHBoxLayout(status_row)
        status_layout.setContentsMargins(0, 0, 0, 0)
        self.upgrade_vcg_badge = status_badge("unknown", "VCG 未导入")
        self.upgrade_vsan_badge = status_badge("unknown", "vSAN HCL 未导入")
        status_layout.addWidget(self.upgrade_vcg_badge)
        status_layout.addWidget(self.upgrade_vsan_badge)
        status_layout.addStretch(1)
        self.upgrade_hcl_status_label = muted_label("正在读取 VCG / vSAN HCL 数据状态。")
        layout.addWidget(status_row)
        layout.addWidget(self.upgrade_hcl_status_label)
        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self._upgrade_compat_config_panel())
        splitter.addWidget(self._upgrade_compat_result_panel())
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(8)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([500, 760])
        layout.addWidget(splitter, 1)
        return page

    def _upgrade_compat_config_panel(self) -> QWidget:
        card = SectionCard("升级兼容性输入")
        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignRight)
        form.setVerticalSpacing(8)
        form.setHorizontalSpacing(12)
        self.upgrade_collection_combo = NoWheelComboBox()
        self.upgrade_collection_combo.addItem("连接 vCenter（推荐）", "vcenter")
        self.upgrade_collection_combo.addItem("导入 support bundle", "support_bundle")
        self.upgrade_collection_combo.currentIndexChanged.connect(self._upgrade_collection_changed)
        self.upgrade_release_combo = NoWheelComboBox()
        self.upgrade_release_combo.setEditable(True)
        self.upgrade_release_combo.lineEdit().setPlaceholderText("选择或输入目标版本（如 ESXi 8.0 U3）")
        self.upgrade_release_combo.setMinimumHeight(34)
        self.upgrade_release_combo.setMinimumWidth(260)
        self.upgrade_release_combo.setMinimumContentsLength(18)
        self.upgrade_release_combo.setToolTip("目标版本来自已导入的 HCL 数据。")
        self.upgrade_vsan_combo = NoWheelComboBox()
        self.upgrade_vsan_combo.addItem("自动（跟随集群配置）", "auto")
        self.upgrade_vsan_combo.addItem("强制包含", "force")
        self.upgrade_vsan_combo.addItem("强制跳过", "skip")
        self.upgrade_vsan_combo.setToolTip("自动适用于已有 vSAN 集群；强制包含用于评估未来组建 vSAN；强制跳过只检查基础升级兼容性。")
        self.upgrade_vcenter_input = QLineEdit()
        self.upgrade_vcenter_input.setPlaceholderText("vCenter 地址或主机名")
        self.upgrade_username_input = QLineEdit()
        self.upgrade_username_input.setPlaceholderText("只读账号即可")
        self.upgrade_password_input = QLineEdit()
        self.upgrade_password_input.setEchoMode(QLineEdit.Password)
        self.upgrade_password_input.setPlaceholderText("不会写入报告")
        self.upgrade_bundle_input = PathLineEdit()
        choose_bundle = QPushButton("选择文件")
        choose_bundle.clicked.connect(self._choose_upgrade_bundle)
        bundle_row = QWidget()
        bundle_layout = QHBoxLayout(bundle_row)
        bundle_layout.setContentsMargins(0, 0, 0, 0)
        bundle_layout.addWidget(self.upgrade_bundle_input, 1)
        bundle_layout.addWidget(choose_bundle)
        self.upgrade_customer_input = QLineEdit()
        self.upgrade_report_title_input = QLineEdit()
        self.upgrade_report_dir_input = PathLineEdit()
        choose_dir = QPushButton("选择目录")
        choose_dir.clicked.connect(self._choose_upgrade_report_dir)
        report_row = QWidget()
        report_layout = QHBoxLayout(report_row)
        report_layout.setContentsMargins(0, 0, 0, 0)
        report_layout.addWidget(self.upgrade_report_dir_input, 1)
        report_layout.addWidget(choose_dir)
        self.upgrade_hcl_source_combo = NoWheelComboBox()
        self.upgrade_hcl_source_combo.addItem("VCG + vSAN HCL", "both")
        self.upgrade_hcl_source_combo.addItem("仅 VCG", "vcg")
        self.upgrade_hcl_source_combo.addItem("仅 vSAN HCL", "vsan")
        self.upgrade_hcl_source_combo.currentIndexChanged.connect(self._upgrade_hcl_import_options_changed)
        self.upgrade_hcl_mode_combo = NoWheelComboBox()
        self.upgrade_hcl_mode_combo.addItem("本地文件导入 / 更新", "local")
        self.upgrade_hcl_mode_combo.currentIndexChanged.connect(self._upgrade_hcl_import_options_changed)
        self.upgrade_hcl_path_input = PathLineEdit()
        self.upgrade_hcl_choose_button = QPushButton("选择文件")
        self.upgrade_hcl_choose_button.clicked.connect(self._choose_upgrade_hcl_source)
        hcl_path_row = QWidget()
        hcl_path_layout = QHBoxLayout(hcl_path_row)
        hcl_path_layout.setContentsMargins(0, 0, 0, 0)
        hcl_path_layout.addWidget(self.upgrade_hcl_path_input, 1)
        hcl_path_layout.addWidget(self.upgrade_hcl_choose_button)
        self.upgrade_hcl_vcg_id_input = QLineEdit()
        self.upgrade_hcl_vcg_id_input.setPlaceholderText("在线下载已关闭")
        self.upgrade_hcl_vcg_secret_input = QLineEdit()
        self.upgrade_hcl_vcg_secret_input.setEchoMode(QLineEdit.Password)
        self.upgrade_hcl_vcg_secret_input.setPlaceholderText("在线下载已关闭")
        self.upgrade_hcl_import_button = QPushButton("导入 / 更新 HCL 数据")
        self.upgrade_hcl_import_button.clicked.connect(self._start_upgrade_hcl_import)
        self.upgrade_hcl_import_status = muted_label("软件已内置 VCG 与 vSAN HCL 基线；如需更新，可从本地导入 JSON 或 JSON.GZ 文件。")
        self.upgrade_hcl_import_status.setWordWrap(True)
        for field in (
            self.upgrade_collection_combo, self.upgrade_release_combo, self.upgrade_vsan_combo,
            self.upgrade_vcenter_input, self.upgrade_username_input, self.upgrade_password_input,
            self.upgrade_bundle_input, self.upgrade_customer_input, self.upgrade_report_title_input,
            self.upgrade_report_dir_input, self.upgrade_hcl_source_combo, self.upgrade_hcl_mode_combo,
        ):
            field.setMinimumHeight(34)
        form.addRow("采集方式", self.upgrade_collection_combo)
        form.addRow(QLabel("HCL 数据（已内置）"))
        form.addRow("HCL 数据源", self.upgrade_hcl_source_combo)
        form.addRow("导入方式", self.upgrade_hcl_mode_combo)
        form.addRow("本地 HCL 文件", hcl_path_row)
        form.addRow("HCL 数据操作", self.upgrade_hcl_import_button)
        form.addRow("", self.upgrade_hcl_import_status)
        form.addRow(QLabel("升级检查参数"))
        form.addRow("目标 ESXi 版本", self.upgrade_release_combo)
        form.addRow("vSAN 检查", self.upgrade_vsan_combo)
        form.addRow("vCenter 地址", self.upgrade_vcenter_input)
        form.addRow("用户名", self.upgrade_username_input)
        form.addRow("密码", self.upgrade_password_input)
        form.addRow("support bundle", bundle_row)
        form.addRow("客户名称", self.upgrade_customer_input)
        form.addRow("报告名称", self.upgrade_report_title_input)
        form.addRow("报告输出目录", report_row)
        self.upgrade_form = form
        form.setVerticalSpacing(11)
        form.setHorizontalSpacing(16)
        form.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)
        card.layout.addLayout(form)
        self.upgrade_start_button = QPushButton("开始升级兼容性检查")
        self.upgrade_start_button.setObjectName("primaryButton")
        self.upgrade_start_button.clicked.connect(self._start_upgrade_compat)
        self.upgrade_cancel_button = QPushButton("取消")
        self.upgrade_cancel_button.setEnabled(False)
        self.upgrade_cancel_button.clicked.connect(self._cancel_upgrade_compat)
        row = QHBoxLayout()
        row.addWidget(self.upgrade_start_button)
        row.addWidget(self.upgrade_cancel_button)
        row.addStretch(1)
        card.layout.addLayout(row)
        card.layout.addWidget(muted_label("两种采集方式共享同一套归一化、VCG、vSAN HCL 和报告逻辑。"))
        card.layout.addStretch(1)
        self._upgrade_collection_changed(0)
        self._upgrade_hcl_import_options_changed()
        self.upgrade_form.setRowVisible(self.upgrade_hcl_mode_combo, False)
        self.upgrade_form.setRowVisible(self.upgrade_hcl_vcg_id_input, False)
        self.upgrade_form.setRowVisible(self.upgrade_hcl_vcg_secret_input, False)
        scroll = QScrollArea()
        scroll.setObjectName("upgradeConfigScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setWidget(card)
        return scroll

    def _upgrade_compat_result_panel(self) -> QWidget:
        card = SectionCard("升级兼容性结果")
        self.upgrade_stage_label = QLabel("等待升级兼容性检查")
        self.upgrade_stage_label.setObjectName("sectionTitle")
        self.upgrade_progress_bar = QProgressBar()
        self.upgrade_progress_bar.setRange(0, 100)
        self.upgrade_status_label = muted_label("导入 HCL 数据并填写检查条件后即可启动。")
        metrics = QGridLayout()
        metrics.setHorizontalSpacing(10)
        metrics.setVerticalSpacing(10)
        self.upgrade_metric_total = MetricCard("设备总数", "0")
        self.upgrade_metric_pass = MetricCard("通过", "0", status="success")
        self.upgrade_metric_fail = MetricCard("不通过", "0", status="danger")
        self.upgrade_metric_unknown = MetricCard("无法确定", "0", status="warning")
        for index, widget in enumerate((self.upgrade_metric_total, self.upgrade_metric_pass, self.upgrade_metric_fail, self.upgrade_metric_unknown)):
            widget.setMinimumHeight(92)
            metrics.addWidget(widget, index // 2, index % 2)
        metrics.setColumnStretch(0, 1)
        metrics.setColumnStretch(1, 1)
        self.upgrade_server_summary = QTextEdit()
        self.upgrade_server_summary.setReadOnly(True)
        self.upgrade_server_summary.setMinimumHeight(72)
        self.upgrade_server_summary.setMaximumHeight(120)
        self.upgrade_device_table = QTableWidget(0, 5)
        self.upgrade_device_table.setHorizontalHeaderLabels(["设备", "类别", "VCG 基础", "vSAN 专项", "处置建议"])
        self._prepare_table(self.upgrade_device_table)
        self.upgrade_device_table.setWordWrap(True)
        self.upgrade_device_table.setMinimumHeight(220)
        header = self.upgrade_device_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.Stretch)
        self.upgrade_result_summary = QTextEdit()
        self.upgrade_result_summary.setReadOnly(True)
        self.upgrade_result_summary.setMinimumHeight(84)
        self.upgrade_result_summary.setMaximumHeight(150)
        self.upgrade_open_html_button = QPushButton("打开 HTML 报告")
        self.upgrade_open_html_button.setEnabled(False)
        self.upgrade_open_html_button.clicked.connect(self._open_current_upgrade_html_report)
        card.layout.addWidget(self.upgrade_stage_label)
        card.layout.addWidget(self.upgrade_progress_bar)
        card.layout.addWidget(self.upgrade_status_label)
        card.layout.addLayout(metrics)
        card.layout.addWidget(QLabel("整机型号判定"))
        card.layout.addWidget(self.upgrade_server_summary)
        card.layout.addWidget(self.upgrade_device_table, 1)
        card.layout.addWidget(self.upgrade_result_summary)
        buttons = QHBoxLayout()
        buttons.addWidget(self.upgrade_open_html_button)
        card.layout.addLayout(buttons)
        scroll = QScrollArea()
        scroll.setObjectName("upgradeResultScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setWidget(card)
        return scroll

    def _risk_center_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 22, 24, 24)
        layout.setSpacing(14)
        layout.addWidget(PageHeader("风险中心", "基于当前巡检结果聚合风险条目，支持等级、对象类型和关键字筛选。"))
        filters = QHBoxLayout()
        self.risk_level_filter = NoWheelComboBox()
        self.risk_level_filter.addItems(["全部等级", "P1", "P2", "P3"])
        self.risk_type_filter = NoWheelComboBox()
        self.risk_type_filter.addItems(["全部对象", "vCenter", "ClusterComputeResource", "HostSystem", "Datastore", "VirtualMachine"])
        self.risk_keyword_input = QLineEdit()
        self.risk_keyword_input.setPlaceholderText("关键字")
        for widget in (self.risk_level_filter, self.risk_type_filter, self.risk_keyword_input):
            if isinstance(widget, QLineEdit):
                widget.textChanged.connect(self._populate_risk_table)
            else:
                widget.currentIndexChanged.connect(self._populate_risk_table)
            filters.addWidget(widget)
        filters.addStretch(1)
        layout.addLayout(filters)
        self.risk_empty = self._centered_empty_panel()
        splitter = QSplitter(Qt.Horizontal)
        self.risk_list = QListWidget()
        self.risk_list.setObjectName("moduleNav")
        self.risk_list.setSpacing(8)
        self.risk_list.setMinimumWidth(520)
        self.risk_list.currentRowChanged.connect(self._risk_selection_changed)
        self.risk_detail_card = SectionCard("风险详情")
        self.risk_detail = QTextEdit()
        self.risk_detail.setReadOnly(True)
        self.risk_detail_card.layout.addWidget(self.risk_detail, 1)
        splitter.addWidget(self.risk_list)
        splitter.addWidget(self.risk_detail_card)
        splitter.setSizes([560, 420])
        self.risk_splitter = splitter
        layout.addWidget(self.risk_empty, 1)
        layout.addWidget(splitter, 1)
        return page

    def _asset_center_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 22, 24, 24)
        layout.setSpacing(14)
        layout.addWidget(PageHeader("资产中心", "基于最新巡检资产快照展示 vCenter、Cluster、ESXi、Datastore 和 VM。"))
        filters = QHBoxLayout()
        self.asset_type_filter = NoWheelComboBox()
        self.asset_type_filter.addItems(["全部对象", "vCenter", "Cluster", "ESXi", "Datastore", "VM"])
        self.asset_type_filter.hide()
        self.asset_search_input = QLineEdit()
        self.asset_search_input.setPlaceholderText("搜索对象名称或位置")
        self.asset_sort_filter = NoWheelComboBox()
        self.asset_sort_filter.addItems(["按名称", "按对象类型", "按位置"])
        self.asset_type_filter.currentIndexChanged.connect(self._populate_asset_table)
        self.asset_search_input.textChanged.connect(self._populate_asset_table)
        self.asset_sort_filter.currentIndexChanged.connect(self._populate_asset_table)
        self.asset_category_bar = QHBoxLayout()
        self.asset_category_bar.setSpacing(7)
        self.asset_category_buttons: dict[str, QPushButton] = {}
        filters.addLayout(self.asset_category_bar, 1)
        filters.addWidget(self.asset_search_input)
        filters.addWidget(self.asset_sort_filter)
        layout.addLayout(filters)
        self.asset_empty = self._centered_empty_panel()
        self.asset_table = QTableWidget(0, 4)
        self.asset_table.setHorizontalHeaderLabels(["对象类型", "对象名称", "位置", "关键属性"])
        self._prepare_table(self.asset_table)
        self.asset_table.currentCellChanged.connect(self._asset_selection_changed)
        self.asset_detail = QTextEdit()
        self.asset_detail.setReadOnly(True)
        self.asset_detail.setMinimumWidth(320)
        self.asset_splitter = QSplitter(Qt.Horizontal)
        self.asset_splitter.addWidget(self.asset_table)
        self.asset_splitter.addWidget(self.asset_detail)
        self.asset_splitter.setSizes([860, 360])
        layout.addWidget(self.asset_empty, 1)
        layout.addWidget(self.asset_splitter, 1)
        return page

    def _history_compare_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 22, 24, 24)
        layout.setSpacing(10)
        layout.addWidget(PageHeader("历史对比", "对比两次可比评估之间的风险和资产变化。"))

        selector = SectionCard()
        selector.setFixedHeight(82)
        selector_row = QHBoxLayout()
        selector_row.setSpacing(12)
        self.baseline_run_combo = NoWheelComboBox()
        self.comparison_run_combo = NoWheelComboBox()
        self.baseline_run_combo.setMinimumHeight(36)
        self.comparison_run_combo.setMinimumHeight(36)
        self.baseline_run_combo.currentIndexChanged.connect(self._history_combo_changed)
        self.comparison_run_combo.currentIndexChanged.connect(self._history_combo_changed)
        selector_row.addWidget(QLabel("基准评估"))
        selector_row.addWidget(self.baseline_run_combo, 1)
        selector_row.addWidget(QLabel("对比评估"))
        selector_row.addWidget(self.comparison_run_combo, 1)
        selector.layout.addLayout(selector_row)
        self.history_summary_label = muted_label("完成两次以上评估后，将展示风险变化和资产变化。")
        selector.layout.addWidget(self.history_summary_label)
        layout.addWidget(selector)

        self.history_empty = SectionCard("历史对比状态")
        self.history_empty_text = muted_label("当前只有 1 次评估，完成第二次评估后可生成历史对比。")
        self.history_empty.layout.addWidget(self.history_empty_text)
        layout.addWidget(self.history_empty)

        self.history_content = QWidget()
        content_layout = QVBoxLayout(self.history_content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(14)
        self.history_metric_grid = QGridLayout()
        self.history_metric_grid.setSpacing(8)
        self.history_metric_labels: dict[str, QLabel] = {}
        self.history_metric_subtitles: dict[str, QLabel] = {}
        for index, key in enumerate(("P1", "P2", "P3", "host", "vm", "datastore")):
            card = SectionCard({"host": "ESXi", "vm": "VM", "datastore": "Datastore"}.get(key, f"{key} 风险"))
            card.setFixedHeight(118)
            value = QLabel("--")
            value.setObjectName("metricValue")
            subtitle = muted_label("无变化")
            self.history_metric_labels[key] = value
            self.history_metric_subtitles[key] = subtitle
            card.layout.addWidget(value)
            card.layout.addWidget(subtitle)
            self.history_metric_grid.addWidget(card, 0, index)
        content_layout.addLayout(self.history_metric_grid)

        self.history_tabs = QTabWidget()
        risk_card = SectionCard("风险变化")
        risk_filter_row = QHBoxLayout()
        self.history_risk_filter = NoWheelComboBox()
        self.history_risk_filter.addItems(["全部", "新增", "本次未再检出", "持续"])
        self.history_risk_filter.currentIndexChanged.connect(self._history_risk_filter_changed)
        risk_filter_row.addWidget(QLabel("筛选"))
        risk_filter_row.addWidget(self.history_risk_filter)
        risk_filter_row.addStretch(1)
        risk_card.layout.addLayout(risk_filter_row)
        self.history_risk_list = QListWidget()
        self.history_risk_list.setObjectName("moduleNav")
        self.history_risk_list.setSpacing(1)
        risk_card.layout.addWidget(self.history_risk_list)
        self.history_risk_page_label = muted_label("")
        self.history_risk_prev = QPushButton("上一页")
        self.history_risk_next = QPushButton("下一页")
        self.history_risk_prev.clicked.connect(lambda: self._change_history_page("risk", -1))
        self.history_risk_next.clicked.connect(lambda: self._change_history_page("risk", 1))
        risk_pager = QHBoxLayout()
        risk_pager.addWidget(self.history_risk_page_label, 1)
        risk_pager.addWidget(self.history_risk_prev)
        risk_pager.addWidget(self.history_risk_next)
        risk_card.layout.addLayout(risk_pager)

        asset_card = SectionCard("资产变化")
        self.history_asset_list = QListWidget()
        self.history_asset_list.setObjectName("moduleNav")
        self.history_asset_list.setSpacing(1)
        asset_card.layout.addWidget(self.history_asset_list)
        self.history_asset_page_label = muted_label("")
        self.history_asset_prev = QPushButton("上一页")
        self.history_asset_next = QPushButton("下一页")
        self.history_asset_prev.clicked.connect(lambda: self._change_history_page("asset", -1))
        self.history_asset_next.clicked.connect(lambda: self._change_history_page("asset", 1))
        asset_pager = QHBoxLayout()
        asset_pager.addWidget(self.history_asset_page_label, 1)
        asset_pager.addWidget(self.history_asset_prev)
        asset_pager.addWidget(self.history_asset_next)
        asset_card.layout.addLayout(asset_pager)
        self.history_tabs.addTab(risk_card, "风险变化")
        self.history_tabs.addTab(asset_card, "资产变化")
        self.history_tabs.setMinimumHeight(460)
        content_layout.addWidget(self.history_tabs, 1)
        layout.addWidget(self.history_content, 1)
        return self._scroll_page(page)

    def _report_center_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 22, 24, 24)
        layout.setSpacing(14)
        layout.addWidget(PageHeader("报告中心", "查看本工具生成的巡检、日志分析和升级兼容性报告。"))
        splitter = QSplitter(Qt.Horizontal)
        self.report_center_table = self._new_history_table(50, compact=True)
        self.report_center_table.hide()
        self.report_list = QListWidget()
        self.report_list.setObjectName("moduleNav")
        self.report_list.setSpacing(8)
        self.report_list.currentRowChanged.connect(self._report_selection_changed)
        self.report_center_empty = self._centered_empty_panel()
        self.report_detail = QTextEdit()
        self.report_detail.setReadOnly(True)
        splitter.addWidget(self.report_list)
        right = SectionCard("报告摘要 / 预览")
        right.layout.addWidget(self.report_detail)
        open_row = QHBoxLayout()
        self.open_selected_report_button = QPushButton("打开报告")
        self.open_selected_report_button.clicked.connect(self._open_selected_history_report)
        self.open_selected_dir_button = QPushButton("打开报告目录")
        self.open_selected_dir_button.clicked.connect(self._open_selected_history_dir)
        self.report_copy_path_button = QPushButton("复制报告路径")
        self.report_copy_path_button.clicked.connect(self._copy_selected_report_path)
        self.report_word_button = QPushButton("打开 Word 报告")
        self.report_word_button.clicked.connect(self._open_selected_word_report)
        self.report_pdf_button = QPushButton("打开 PDF 报告")
        self.report_pdf_button.clicked.connect(self._open_selected_pdf_report)
        self.delete_report_button = QPushButton("从列表移除")
        self.delete_report_button.clicked.connect(self._remove_selected_report)
        self.delete_report_button.setToolTip("仅从报告中心隐藏选中项，不删除报告文件、巡检记录或资产快照。")
        for button in (self.report_word_button, self.report_pdf_button, self.delete_report_button):
            button.setEnabled(False)
        open_row.addWidget(self.open_selected_report_button)
        open_row.addWidget(self.open_selected_dir_button)
        open_row.addWidget(self.report_copy_path_button)
        open_row.addWidget(self.report_word_button)
        open_row.addWidget(self.report_pdf_button)
        open_row.addWidget(self.delete_report_button)
        right.layout.addLayout(open_row)
        roadmap = muted_label("“从列表移除”不会删除文件；仅已识别为本工具产物的报告会出现在此处。")
        roadmap.setWordWrap(True)
        right.layout.addWidget(roadmap)
        splitter.addWidget(right)
        splitter.setSizes([720, 360])
        self.report_splitter = splitter
        layout.addWidget(self.report_center_empty, 1)
        layout.addWidget(splitter, 1)
        return page

    def _planned_page(self, title: str, message: str) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 22, 24, 24)
        layout.setSpacing(16)
        layout.addWidget(PageHeader(title, "后续版本能力预留。"))
        card = SectionCard("能力预留")
        card.layout.addWidget(status_badge("planned", "后续版本"))
        card.layout.addWidget(muted_label(message))
        card.layout.addWidget(muted_label("当前版本暂未启用 AI、SMTP 或自定义模板运行能力。Word 报告已在报告中心提供。"))
        disabled = QPushButton("功能入口（后续版本）")
        disabled.setEnabled(False)
        card.layout.addWidget(disabled, alignment=Qt.AlignLeft)
        layout.addWidget(card)
        layout.addStretch(1)
        return self._scroll_page(page)

    def _baseline_center_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 22, 24, 24)
        layout.setSpacing(16)
        layout.addWidget(PageHeader("健康基线", "查看本地 vSphere 健康评估基线状态。"))
        card = SectionCard("当前评估基线")
        self.rulepack_status_label = QLabel("可用")
        form = QFormLayout()
        form.addRow("当前基线", QLabel("内置 vSphere 健康评估基线"))
        form.addRow("运行方式", QLabel("本地离线运行"))
        form.addRow("状态", self.rulepack_status_label)
        card.layout.addLayout(form)
        validate = QPushButton("校验评估基线")
        validate.setObjectName("primaryButton")
        validate.clicked.connect(self._validate_rulepack)
        self.rulepack_validation_result = QTextEdit()
        self.rulepack_validation_result.setReadOnly(True)
        self.rulepack_validation_result.setMinimumHeight(120)
        card.layout.addWidget(validate, alignment=Qt.AlignLeft)
        card.layout.addWidget(self.rulepack_validation_result)
        layout.addWidget(card)

        evidence_card = SectionCard("证书与授权核验")
        evidence_card.layout.addWidget(muted_label("展示 vCenter / ESXi 证书与 VMware 授权状态，便于确认环境关键状态已被核对。"))
        self.check_evidence_empty = EmptyState("暂无核验结果", "完成巡检后展示 vCenter / ESXi 证书与 VMware 授权状态。")
        self.check_evidence_list = QListWidget()
        self.check_evidence_list.setObjectName("moduleNav")
        self.check_evidence_list.setSpacing(8)
        self.check_evidence_list.currentRowChanged.connect(self._check_evidence_selection_changed)
        self.check_evidence_detail = QTextEdit()
        self.check_evidence_detail.setReadOnly(True)
        evidence_splitter = QSplitter(Qt.Horizontal)
        evidence_splitter.addWidget(self.check_evidence_list)
        evidence_splitter.addWidget(self.check_evidence_detail)
        evidence_splitter.setSizes([520, 620])
        self.check_evidence_splitter = evidence_splitter
        evidence_card.layout.addWidget(self.check_evidence_empty)
        evidence_card.layout.addWidget(evidence_splitter, 1)
        layout.addWidget(evidence_card, 1)
        layout.addStretch(1)
        return self._scroll_page(page)

    def _settings_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 22, 24, 24)
        layout.setSpacing(16)
        layout.addWidget(PageHeader("系统设置", "保存本地数据库、报告目录和日志分析模型配置档案。"))
        card = SectionCard("本机配置")
        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignRight)
        self.db_path_input = PathLineEdit()
        self.default_report_dir_input = PathLineEdit()
        self.rulepack_path_input = PathLineEdit()
        form.addRow("数据库路径", self._path_row(self.db_path_input, self._choose_db_path, "选择数据库"))
        form.addRow("报告输出目录", self._path_row(self.default_report_dir_input, self._choose_default_report_dir, "选择目录"))
        card.layout.addLayout(form)
        save = QPushButton("保存配置")
        save.setObjectName("primaryButton")
        save.clicked.connect(self._save_current_config)
        card.layout.addWidget(save, alignment=Qt.AlignLeft)
        layout.addWidget(card)

        rule_card = SectionCard("本地规则与数据")
        rule_form = QFormLayout()
        self.rulepack_status_label = QLabel("未校验")
        rule_form.addRow("规则包路径", self._path_row(self.rulepack_path_input, self._choose_rulepack_path, "选择规则包"))
        rule_form.addRow("当前状态", self.rulepack_status_label)
        rule_card.layout.addLayout(rule_form)
        validate = QPushButton("校验本地规则")
        validate.clicked.connect(self._validate_rulepack)
        self.rulepack_validation_result = QTextEdit()
        self.rulepack_validation_result.setReadOnly(True)
        self.rulepack_validation_result.setMaximumHeight(116)
        self.rulepack_validation_result.setPlaceholderText("校验结果会显示在此处。")
        self.rulepack_validation_result.hide()
        rule_card.layout.addWidget(validate, alignment=Qt.AlignLeft)
        rule_card.layout.addWidget(self.rulepack_validation_result)
        layout.addWidget(rule_card)

        model_settings, self.model_settings_summary_label, self.model_settings_toggle_button, model_detail = self._expandable_section(
            "大模型设置",
            "未配置",
        )
        model_form = QFormLayout()
        model_form.setLabelAlignment(Qt.AlignRight)
        model_form.setVerticalSpacing(8)
        model_form.setHorizontalSpacing(12)
        self.settings_model_profile_combo = NoWheelComboBox()
        self.settings_model_profile_combo.currentIndexChanged.connect(self._settings_profile_changed)
        add_profile = QPushButton("新增")
        add_profile.clicked.connect(self._add_model_profile)
        delete_profile = QPushButton("删除")
        delete_profile.clicked.connect(self._delete_model_profile)
        profile_row = QWidget()
        profile_layout = QHBoxLayout(profile_row)
        profile_layout.setContentsMargins(0, 0, 0, 0)
        profile_layout.addWidget(self.settings_model_profile_combo, 1)
        profile_layout.addWidget(add_profile)
        profile_layout.addWidget(delete_profile)
        self.settings_profile_name_input = QLineEdit()
        self.settings_profile_provider_combo = NoWheelComboBox()
        self.settings_profile_provider_combo.addItem("DeepSeek", DEFAULT_CLOUD_PROVIDER)
        self.settings_profile_provider_combo.addItem("OpenAI Compatible", "openai_compatible")
        self.settings_profile_provider_combo.addItem("本地 Ollama", "ollama")
        self.settings_profile_provider_combo.currentIndexChanged.connect(self._profile_form_changed)
        self.settings_profile_api_url_input = QLineEdit()
        self.settings_profile_api_url_input.textChanged.connect(self._profile_form_changed)
        self.settings_profile_api_key_input = QLineEdit()
        self.settings_profile_api_key_input.setEchoMode(QLineEdit.Password)
        self.settings_profile_api_key_input.setToolTip("API Key 将保存在本机配置中用于后续复用，不会写入报告或日志。")
        self.settings_profile_api_key_input.textChanged.connect(self._profile_form_changed)
        self.settings_profile_timeout_input = QSpinBox()
        self.settings_profile_timeout_input.setRange(5, 300)
        self.settings_profile_timeout_input.setSuffix(" 秒")
        self.settings_profile_timeout_input.valueChanged.connect(self._profile_form_changed)
        self.settings_profile_default_model_combo = NoWheelComboBox()
        self.settings_profile_default_model_combo.setEditable(True)
        self.settings_profile_default_model_combo.currentIndexChanged.connect(self._profile_form_changed)
        self.settings_profile_default_model_combo.editTextChanged.connect(self._profile_form_changed)
        self.settings_profile_name_input.textChanged.connect(self._profile_form_changed)
        refresh_models = QPushButton("刷新模型列表")
        refresh_models.clicked.connect(self._refresh_settings_profile_models)
        self.settings_test_connection_button = QPushButton("测试连接")
        self.settings_test_connection_button.clicked.connect(self._test_cloud_connection)
        set_default = QPushButton("设为默认配置")
        set_default.clicked.connect(self._set_default_model_profile)
        save_model = QPushButton("保存")
        save_model.clicked.connect(self._save_current_config)
        self.settings_profile_status_label = muted_label("未测试")
        self.settings_profile_status_label.setToolTip("")
        model_select_row = QWidget()
        model_select_layout = QHBoxLayout(model_select_row)
        model_select_layout.setContentsMargins(0, 0, 0, 0)
        model_select_layout.addWidget(self.settings_profile_default_model_combo, 1)
        model_select_layout.addWidget(refresh_models)
        action_row = QWidget()
        action_layout = QHBoxLayout(action_row)
        action_layout.setContentsMargins(0, 0, 0, 0)
        action_layout.addWidget(self.settings_test_connection_button)
        action_layout.addWidget(set_default)
        action_layout.addWidget(save_model)
        action_layout.addStretch(1)
        model_form.addRow("配置档案", profile_row)
        model_form.addRow("配置名称", self.settings_profile_name_input)
        model_form.addRow("Provider", self.settings_profile_provider_combo)
        model_form.addRow("API 地址", self.settings_profile_api_url_input)
        model_form.addRow("API Key", self.settings_profile_api_key_input)
        model_form.addRow("", muted_label("API Key 将保存在本机配置中用于后续复用，不会写入报告或日志。"))
        model_form.addRow("超时", self.settings_profile_timeout_input)
        model_form.addRow("模型", model_select_row)
        model_form.addRow("状态", self.settings_profile_status_label)
        model_detail.layout().addLayout(model_form)
        model_detail.layout().addWidget(action_row)
        layout.addWidget(model_settings)

        security, self.security_summary_label, self.security_toggle_button, security_detail = self._expandable_section(
            "安全设置",
            "标准脱敏",
        )
        security_detail.layout().addWidget(muted_label("管理本地管理员密码、日志分析隐私级别和后续密码复杂度要求。"))
        security_form = QFormLayout()
        security_form.setLabelAlignment(Qt.AlignRight)
        self.privacy_level_combo = NoWheelComboBox()
        self.privacy_level_combo.addItem("标准脱敏", "standard")
        self.privacy_level_combo.addItem("严格脱敏", "strict")
        self.privacy_level_combo.addItem("仅本地", "local-only")
        security_form.addRow("隐私级别", self.privacy_level_combo)
        security_detail.layout().addLayout(security_form)
        password_form = QFormLayout()
        password_form.setLabelAlignment(Qt.AlignRight)
        self.current_password_input = QLineEdit()
        self.current_password_input.setEchoMode(QLineEdit.Password)
        self.current_password_input.setPlaceholderText("请输入当前密码")
        self.new_password_input = QLineEdit()
        self.new_password_input.setEchoMode(QLineEdit.Password)
        self.new_password_input.setPlaceholderText("请输入新密码")
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.Password)
        self.confirm_password_input.setPlaceholderText("再次输入新密码")
        password_form.addRow("当前密码", self.current_password_input)
        password_form.addRow("新密码", self.new_password_input)
        password_form.addRow("确认新密码", self.confirm_password_input)
        security_detail.layout().addLayout(password_form)
        change_password = QPushButton("修改密码")
        change_password.setObjectName("primaryButton")
        change_password.clicked.connect(self._change_local_password)
        security_detail.layout().addWidget(change_password, alignment=Qt.AlignLeft)

        policy_form = QFormLayout()
        policy_form.setLabelAlignment(Qt.AlignRight)
        self.password_min_length_input = QSpinBox()
        self.password_min_length_input.setRange(1, 128)
        self.password_require_digit_input = QCheckBox("要求包含数字")
        self.password_require_mixed_case_input = QCheckBox("要求同时包含大写和小写字母")
        self.password_require_special_input = QCheckBox("要求包含特殊字符")
        policy_form.addRow("最小长度", self.password_min_length_input)
        policy_form.addRow("数字", self.password_require_digit_input)
        policy_form.addRow("大小写", self.password_require_mixed_case_input)
        policy_form.addRow("特殊字符", self.password_require_special_input)
        security_detail.layout().addLayout(policy_form)
        save_policy = QPushButton("保存密码策略")
        save_policy.clicked.connect(self._save_password_policy)
        security_detail.layout().addWidget(save_policy, alignment=Qt.AlignLeft)
        layout.addWidget(security)
        layout.addStretch(1)
        return self._scroll_page(page)

    def _license_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 22, 24, 24)
        layout.setSpacing(16)
        layout.addWidget(PageHeader("关于软件", "查看软件版本、本地运行状态和数据目录信息。"))
        card = SectionCard("软件信息")
        form = QFormLayout()
        form.addRow("运行状态", QLabel(self.auth_service.get_app_status().label))
        form.addRow("软件版本", QLabel(APP_VERSION))
        form.addRow("运行模式", QLabel(runtime_mode()))
        form.addRow("运行日志", QLabel(str(runtime_log_path())))
        form.addRow("设备标识", QLabel("待生成"))
        form.addRow("使用限制", QLabel("无限制"))
        card.layout.addLayout(form)
        log_actions = QHBoxLayout()
        open_logs = QPushButton("打开日志目录")
        open_logs.clicked.connect(self._open_runtime_log_dir)
        copy_log_path = QPushButton("复制日志路径")
        copy_log_path.clicked.connect(self._copy_runtime_log_path)
        log_actions.addWidget(open_logs)
        log_actions.addWidget(copy_log_path)
        log_actions.addStretch(1)
        card.layout.addLayout(log_actions)
        layout.addWidget(card)
        layout.addStretch(1)
        return self._scroll_page(page)

    def _path_row(self, line_edit: QLineEdit, callback, button_text: str) -> QWidget:
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        button = QPushButton(button_text)
        button.clicked.connect(callback)
        layout.addWidget(line_edit, 1)
        layout.addWidget(button)
        return row

    def _centered_empty_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 24, 0, 0)
        layout.addStretch(1)
        row = QHBoxLayout()
        row.addStretch(1)
        row.addWidget(
            EmptyState(
                "暂无评估数据",
                "完成首次健康评估后，将展示健康状态、风险、资产和报告。",
                button_text="去巡检中心",
                on_click=lambda: self.go_to_module("inspection_center"),
            )
        )
        row.addStretch(1)
        layout.addLayout(row)
        layout.addStretch(3)
        return panel

    def _new_history_table(self, limit: int, compact: bool = False) -> QTableWidget:
        columns = ["时间", "客户", "vCenter", "状态", "评分", "风险"] if compact else ["时间", "客户", "vCenter", "状态", "评分", "风险", "报告路径"]
        table = QTableWidget(0, len(columns))
        table.setProperty("historyLimit", limit)
        table.setHorizontalHeaderLabels(columns)
        self._prepare_table(table)
        if compact:
            table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        return table

    def _prepare_table(self, table: QTableWidget) -> None:
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)

    def _module(self, module_id: str) -> ModuleDescriptor:
        return self.module_descriptors[self.module_index[module_id]]

    def _switch_page(self, index: int) -> None:
        self.pages.setCurrentIndex(index)
        page = self.pages.currentWidget()
        if isinstance(page, QScrollArea):
            page.verticalScrollBar().setValue(0)
        self._refresh_all_data()

    def go_to_module(self, module_id: str) -> None:
        self.nav.setCurrentRow(self.module_index[module_id])

    def _open_risk_center(self, risk_level: str | None = None) -> None:
        self.go_to_module("risk_center")
        if risk_level and hasattr(self, "risk_level_filter"):
            self.risk_level_filter.setCurrentText(risk_level)
            self._populate_risk_table()

    @staticmethod
    def _dashboard_health_status_key(label: str) -> str:
        text = label.strip()
        if text in {"健康", "正常"}:
            return "success"
        if text in {"关注", "需要关注", "评估受限", "历史状态未记录"}:
            return "warning"
        if text in {"危险", "高风险", "异常"}:
            return "danger"
        return "unknown"

    def _toggle_certificate_detail(self) -> None:
        if not self.dashboard_certificate_toggle.isEnabled():
            return
        shown = not self.dashboard_certificate_detail.isVisible()
        self.dashboard_certificate_detail.setVisible(shown)
        self.dashboard_certificate_toggle.setText("收起核验明细" if shown else "查看核验明细")

    def _load_saved_config(self) -> None:
        cfg = self.service.load_config()
        self.vcenter_input.setText(cfg.vcenter)
        self.username_input.setText(cfg.username)
        self.customer_input.setText(cfg.customer_name or DEFAULT_CUSTOMER_NAME)
        self.report_title_input.setText(cfg.report_title or DEFAULT_REPORT_TITLE)
        self.site_input.setText(DEFAULT_SITE_NAME)
        self.report_dir_input.set_path_value(str(cfg.report_output_dir))
        self.log_customer_input.setText(cfg.customer_name or DEFAULT_CUSTOMER_NAME)
        self.log_report_title_input.setText(DEFAULT_LOG_ANALYSIS_TITLE)
        self.log_report_dir_input.set_path_value(str(cfg.report_output_dir))
        self.upgrade_customer_input.setText(cfg.customer_name or DEFAULT_CUSTOMER_NAME)
        self.upgrade_report_title_input.setText(DEFAULT_UPGRADE_COMPAT_TITLE)
        self.upgrade_report_dir_input.set_path_value(str(cfg.report_output_dir))
        self.log_cloud_enabled_input.setChecked(False)
        self._model_profiles = [item.normalized() for item in cfg.model_config_profiles]
        self._cloud_connection_test_ok = False
        self._cloud_connection_test_fingerprint = ""
        self.default_report_dir_input.set_path_value(str(cfg.report_output_dir))
        self.db_path_input.set_path_value(str(cfg.db_path))
        self.rulepack_path_input.set_path_value(str(cfg.rulepack_path))
        self.privacy_level_combo.setCurrentIndex(max(0, self.privacy_level_combo.findData(cfg.security_privacy_level)))
        self._reload_settings_profiles()
        self._reload_log_analysis_profiles()
        self._refresh_security_summary()
        self._load_security_settings()
        self._refresh_upgrade_hcl_status()

    def _current_config(self) -> DesktopInspectionConfig:
        report_dir_text = self.report_dir_input.path_value() or self.default_report_dir_input.path_value()
        return DesktopInspectionConfig(
            vcenter=self.vcenter_input.text(),
            username=self.username_input.text(),
            password=self.password_input.text(),
            port=443,
            ssl_no_verify=False,
            customer_name=self.customer_input.text(),
            site_name=DEFAULT_SITE_NAME,
            report_title=self.report_title_input.text(),
            report_output_dir=Path(report_dir_text or DesktopInspectionConfig().report_output_dir),
            db_path=Path(self.db_path_input.path_value() or DesktopInspectionConfig().db_path),
            rulepack_path=Path(self.rulepack_path_input.path_value() or DesktopInspectionConfig().rulepack_path),
        )

    def _settings_config(self) -> DesktopInspectionConfig:
        cfg = self._current_config()
        self._sync_current_profile_to_state()
        return DesktopInspectionConfig(
            vcenter=cfg.vcenter,
            username=cfg.username,
            password=cfg.password,
            port=443,
            ssl_no_verify=False,
            customer_name=cfg.customer_name,
            site_name=DEFAULT_SITE_NAME,
            report_title=cfg.report_title,
            report_output_dir=Path(self.default_report_dir_input.path_value() or cfg.report_output_dir),
            db_path=cfg.db_path,
            rulepack_path=cfg.rulepack_path,
            model_config_profiles=[item.normalized() for item in self._model_profiles],
            security_privacy_level=str(self.privacy_level_combo.currentData() or "standard"),
        )

    def _current_log_analysis_config(self) -> LogAnalysisConfig:
        report_dir_text = self.log_report_dir_input.path_value() or self.default_report_dir_input.path_value()
        selected_profile = self._selected_log_profile()
        cloud_enabled = self.log_cloud_enabled_input.isChecked()
        local_only = self._current_privacy_level() == "local-only"
        if local_only or selected_profile is None or not selected_profile.api_key.strip() or not selected_profile.api_url.strip():
            cloud_enabled = False
        selected_model = self.log_model_input.currentData() or self.log_model_input.currentText() or (selected_profile.default_model if selected_profile else "")
        return LogAnalysisConfig(
            support_bundle_path=Path(self.log_bundle_input.path_value() or ""),
            problem_description=self.log_problem_input.toPlainText(),
            customer_name=self.log_customer_input.text(),
            report_title=self.log_report_title_input.text(),
            report_output_dir=Path(report_dir_text or DesktopInspectionConfig().report_output_dir),
            db_path=Path(self.db_path_input.path_value() or DesktopInspectionConfig().db_path),
            cloud_assist_enabled=cloud_enabled,
            cloud_provider=selected_profile.provider if selected_profile else DEFAULT_CLOUD_PROVIDER,
            cloud_api_url=selected_profile.api_url if selected_profile else "",
            cloud_model_name=str(selected_model or ""),
            cloud_api_key=selected_profile.api_key if selected_profile else "",
            cloud_timeout_seconds=selected_profile.timeout_seconds if selected_profile else 60,
        )

    def _current_upgrade_compat_config(self) -> UpgradeCompatConfig:
        report_dir = self.upgrade_report_dir_input.path_value() or self.default_report_dir_input.path_value() or "out"
        mode = str(self.upgrade_collection_combo.currentData() or "vcenter")
        return UpgradeCompatConfig(
            collection_mode=mode,
            target_release=str(self.upgrade_release_combo.currentData() or self.upgrade_release_combo.currentText() or ""),
            vsan_check_mode=str(self.upgrade_vsan_combo.currentData() or "auto"),
            customer_name=self.upgrade_customer_input.text(), report_title=self.upgrade_report_title_input.text(),
            report_dir=Path(report_dir), db_path=self._compat_db_path(), vcenter_host=self.upgrade_vcenter_input.text(),
            username=self.upgrade_username_input.text(), password=self.upgrade_password_input.text(), ssl_verify=False,
            bundle_path=Path(self.upgrade_bundle_input.path_value() or ""),
        )

    def _upgrade_collection_changed(self, _index: int) -> None:
        if not hasattr(self, "upgrade_form"):
            return
        vcenter_mode = str(self.upgrade_collection_combo.currentData() or "vcenter") == "vcenter"
        for widget in (self.upgrade_vcenter_input, self.upgrade_username_input, self.upgrade_password_input):
            self.upgrade_form.setRowVisible(widget, vcenter_mode)
        self.upgrade_form.setRowVisible(self.upgrade_bundle_input.parentWidget(), not vcenter_mode)

    def _upgrade_hcl_import_options_changed(self, _index: int | None = None) -> None:
        if not hasattr(self, "upgrade_hcl_mode_combo"):
            return
        online = str(self.upgrade_hcl_mode_combo.currentData() or "local") == "online"
        source = str(self.upgrade_hcl_source_combo.currentData() or "both")
        needs_vcg_credentials = online and source in {"vcg", "both"}
        self.upgrade_form.setRowVisible(self.upgrade_hcl_path_input.parentWidget(), not online)
        self.upgrade_form.setRowVisible(self.upgrade_hcl_vcg_id_input, needs_vcg_credentials)
        self.upgrade_form.setRowVisible(self.upgrade_hcl_vcg_secret_input, needs_vcg_credentials)
        self.upgrade_hcl_choose_button.setEnabled(not online)
        self.upgrade_hcl_path_input.setEnabled(not online)
        if online:
            self.upgrade_hcl_import_status.setText("在线下载会写入本机应用数据目录；VCG 凭据仅用于本次下载，不会保存。")
        elif source == "both":
            self.upgrade_hcl_import_status.setText("请选择包含 vcg-bundle.json 和 vsan-all.json 的目录。")
        else:
            self.upgrade_hcl_import_status.setText("请选择对应来源导出的 JSON 文件。")

    def _choose_upgrade_hcl_source(self) -> None:
        source = str(self.upgrade_hcl_source_combo.currentData() or "both")
        if source == "both":
            path = QFileDialog.getExistingDirectory(self, "选择包含 VCG 与 vSAN HCL JSON 的目录", self.upgrade_hcl_path_input.path_value() or ".")
        else:
            path, _ = QFileDialog.getOpenFileName(self, "选择 HCL JSON 文件", self.upgrade_hcl_path_input.path_value() or ".", "HCL JSON (*.json *.json.gz);;所有文件 (*)")
        if path:
            self.upgrade_hcl_path_input.set_path_value(path)

    def _start_upgrade_hcl_import(self) -> None:
        if self.upgrade_hcl_import_worker is not None:
            return
        source = str(self.upgrade_hcl_source_combo.currentData() or "both")
        online = str(self.upgrade_hcl_mode_combo.currentData() or "local") == "online"
        selected_text = self.upgrade_hcl_path_input.path_value().strip()
        if not online and not selected_text:
            QMessageBox.warning(self, "HCL 数据导入", "请选择本地 HCL JSON 文件或目录。")
            return
        if online and source in {"vcg", "both"} and (not self.upgrade_hcl_vcg_id_input.text().strip() or not self.upgrade_hcl_vcg_secret_input.text()):
            QMessageBox.warning(self, "HCL 数据导入", "在线下载 VCG 需要填写 Client ID 和 Client Secret。")
            return
        self.upgrade_hcl_import_button.setEnabled(False)
        self.upgrade_start_button.setEnabled(False)
        self.upgrade_cancel_button.setEnabled(True)
        self.upgrade_hcl_import_status.setText("正在导入 HCL 判据数据，请稍候。")
        self.upgrade_hcl_import_worker = UpgradeHclImportWorker(
            self.service,
            db_path=self._compat_db_path(),
            source=source,
            file_path=Path(selected_text) if selected_text else None,
            online=online,
            vcg_client_id=self.upgrade_hcl_vcg_id_input.text().strip(),
            vcg_client_secret=self.upgrade_hcl_vcg_secret_input.text(),
        )
        self.upgrade_hcl_import_worker.progress.connect(self._upgrade_hcl_import_progress)
        self.upgrade_hcl_import_worker.completed.connect(self._upgrade_hcl_import_completed)
        self.upgrade_hcl_import_worker.failed.connect(self._upgrade_hcl_import_failed)
        self.upgrade_hcl_import_worker.finished.connect(self._upgrade_hcl_import_finished)
        self.upgrade_hcl_import_worker.start()

    def _upgrade_hcl_import_progress(self, progress: UpgradeCompatProgress) -> None:
        self.upgrade_hcl_import_status.setText(f"{progress.percent}% {progress.message}")

    def _upgrade_hcl_import_completed(self, imported: dict[str, str]) -> None:
        self.upgrade_hcl_vcg_secret_input.clear()
        self.upgrade_hcl_import_status.setText("HCL 判据数据已导入：" + "、".join(sorted(imported)))
        self._refresh_upgrade_hcl_status()

    def _upgrade_hcl_import_failed(self, error: str) -> None:
        self.upgrade_hcl_import_status.setText("HCL 数据导入失败：" + friendly_error_message(error))
        QMessageBox.warning(self, "HCL 数据导入失败", friendly_error_message(error))

    def _upgrade_hcl_import_finished(self) -> None:
        if self.upgrade_hcl_import_worker is not None:
            self.upgrade_hcl_import_worker.deleteLater()
            self.upgrade_hcl_import_worker = None
        self.upgrade_hcl_import_button.setEnabled(True)
        self._refresh_upgrade_hcl_status()

    def _refresh_upgrade_hcl_status(self) -> None:
        if not hasattr(self, "upgrade_release_combo"):
            return
        try:
            state = self.service.upgrade_compat_data_status(
                self._compat_db_path(),
                seed_database_path=self._db_path(),
            )
        except Exception as exc:  # local DB state must not prevent the desktop shell from loading.
            self.upgrade_hcl_status_label.setText(f"无法读取 HCL 数据状态：{exc}")
            return
        sources = state["sources"]
        self._set_upgrade_status_badge(self.upgrade_vcg_badge, "VCG", sources["vcg"])
        self._set_upgrade_status_badge(self.upgrade_vsan_badge, "vSAN HCL", sources["vsan_hcl"])
        baseline = state.get("baseline") or {}
        baseline_version = str(baseline.get("version") or "未标记版本")
        self.upgrade_hcl_status_label.setText(
            f"{state['message']} 兼容性库已与巡检库隔离；内置基线 {baseline_version} 完整性已校验。"
        )
        current = self.upgrade_release_combo.currentData() or self.upgrade_release_combo.currentText()
        releases = self.service.supported_upgrade_releases(self._compat_db_path())
        self.upgrade_release_combo.blockSignals(True)
        self.upgrade_release_combo.clear()
        for release in releases:
            self.upgrade_release_combo.addItem(release, release)
        if current:
            index = self.upgrade_release_combo.findData(current)
            if index >= 0: self.upgrade_release_combo.setCurrentIndex(index)
        elif releases:
            preferred = next((item for item in ("ESXi 8.0 U3", "ESXi 8.0 U2") if item in releases), releases[0])
            self.upgrade_release_combo.setCurrentIndex(self.upgrade_release_combo.findData(preferred))
        self.upgrade_release_combo.blockSignals(False)
        self.upgrade_release_combo.setEnabled(True)
        self.upgrade_start_button.setEnabled(bool(state["can_run"]))
        if not releases:
            self.upgrade_release_combo.setToolTip("请使用本页的“导入 / 更新 HCL 数据”完成首次导入。")

    def _set_upgrade_status_badge(self, badge: QLabel, label: str, item: dict[str, object]) -> None:
        fresh = str(item.get("freshness") or "UNKNOWN")
        badge.setProperty("status", {"FRESH": "success", "WARNING": "warning", "CRITICAL": "danger"}.get(fresh, "unknown"))
        if not item.get("available"):
            badge.setText(f"{label} 未导入")
        else:
            freshness = {"FRESH": "正常", "WARNING": "需更新", "CRITICAL": "已过期"}.get(fresh, "未知")
            badge.setText(f"{label} · {item.get('record_count', 0)} 条 · {freshness}")
            badge.setToolTip(f"最近更新：{item.get('json_updated_time') or '未记录'}")
        badge.style().unpolish(badge)
        badge.style().polish(badge)

    def _current_cloud_model_config(self) -> CloudModelConfig:
        self._sync_current_profile_to_state()
        profile = self._selected_settings_profile()
        return CloudModelConfig(
            provider=profile.provider if profile else DEFAULT_CLOUD_PROVIDER,
            api_url=profile.api_url if profile else DEFAULT_CLOUD_API_URL,
            model_name=profile.default_model if profile else DEFAULT_CLOUD_MODEL,
            api_key=profile.api_key if profile else "",
            timeout_seconds=profile.timeout_seconds if profile else 60,
        )

    def _cloud_config_fingerprint(self, config: CloudModelConfig | None = None) -> str:
        cfg = (config or self._current_cloud_model_config()).normalized()
        material = json.dumps(
            {
                "provider": cfg.provider,
                "api_url": cfg.api_url,
                "model_name": cfg.model_name,
                "api_key": cfg.api_key,
                "timeout_seconds": cfg.timeout_seconds,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def _cloud_config_changed(self, *_args: object) -> None:
        self._cloud_connection_test_ok = False
        self._cloud_connection_test_fingerprint = ""
        if not hasattr(self, "log_cloud_status_label"):
            return
        self._refresh_settings_model_summary()
        self._reload_log_analysis_profiles()

    def _test_cloud_connection(self) -> None:
        self._sync_current_profile_to_state()
        profile = self._selected_settings_profile()
        if profile is None:
            return
        config = self._current_cloud_model_config().normalized()
        if not config.api_url:
            self._cloud_connection_test_ok = False
            self.settings_profile_status_label.setText("未连接")
            self.settings_profile_status_label.setToolTip("请填写 API 地址。")
            return
        if not config.model_name:
            self._cloud_connection_test_ok = False
            self.settings_profile_status_label.setText("未连接")
            self.settings_profile_status_label.setToolTip("请填写模型名称。")
            return
        if not config.api_key:
            self._cloud_connection_test_ok = False
            self.settings_profile_status_label.setText("未连接")
            self.settings_profile_status_label.setToolTip("请填写 API Key。")
            return
        self.settings_test_connection_button.setEnabled(False)
        self.settings_profile_status_label.setText("未测试")
        self.settings_profile_status_label.setToolTip("正在测试模型连接。")
        self.cloud_test_worker = CloudConnectionTestWorker(config)
        self.cloud_test_worker.completed.connect(self._cloud_connection_test_completed)
        self.cloud_test_worker.finished.connect(self._cloud_connection_test_finished)
        self.cloud_test_worker.start()

    def _cloud_connection_test_completed(self, result: object) -> None:
        ok = bool(getattr(result, "ok", False))
        profile = self._selected_settings_profile()
        if profile is None:
            return
        timestamp = self._now_status_timestamp()
        if ok:
            self._cloud_connection_test_ok = True
            self._cloud_connection_test_fingerprint = self._cloud_config_fingerprint()
            profile.connection_status = "connected"
            profile.connection_checked_at = timestamp
            self.settings_profile_status_label.setText(self._format_profile_status(profile))
            self.settings_profile_status_label.setToolTip("")
            self._refresh_settings_model_summary()
            self._reload_log_analysis_profiles()
            self._persist_settings_config()
            return
        self._cloud_connection_test_ok = False
        self._cloud_connection_test_fingerprint = ""
        profile.connection_status = "disconnected"
        profile.connection_checked_at = timestamp
        reason = sanitize_cloud_error(getattr(result, "fallback_reason", "连接失败"), profile.api_key)
        self.settings_profile_status_label.setText(self._format_profile_status(profile))
        self.settings_profile_status_label.setToolTip(reason)
        self._refresh_settings_model_summary()
        self._reload_log_analysis_profiles()
        self._persist_settings_config()

    def _cloud_connection_test_finished(self) -> None:
        if hasattr(self, "settings_test_connection_button"):
            self.settings_test_connection_button.setEnabled(True)
        if self.cloud_test_worker is not None:
            self.cloud_test_worker.deleteLater()
            self.cloud_test_worker = None

    def _expandable_section(self, title: str, summary_text: str) -> tuple[SectionCard, QLabel, QPushButton, QWidget]:
        card = SectionCard(title)
        summary = muted_label(summary_text)
        toggle = QPushButton("展开配置")
        toggle.setProperty("expandToggle", True)
        detail = QWidget()
        detail_layout = QVBoxLayout(detail)
        detail_layout.setContentsMargins(0, 6, 0, 0)
        detail_layout.setSpacing(10)
        detail.setVisible(False)
        row = QHBoxLayout()
        row.addWidget(summary, 1)
        row.addWidget(toggle)
        card.layout.addLayout(row)

        def on_toggle() -> None:
            expanded = not detail.isVisible()
            detail.setVisible(expanded)
            toggle.setText("收起配置" if expanded else "展开配置")

        toggle.clicked.connect(on_toggle)
        card.layout.addWidget(detail)
        return card, summary, toggle, detail

    def _ensure_model_profiles(self) -> None:
        if self._model_profiles:
            return
        self._model_profiles = [
            ModelConfigProfile(
                profile_id="default",
                profile_name="默认模型配置",
                provider=DEFAULT_CLOUD_PROVIDER,
                api_url=DEFAULT_CLOUD_API_URL,
                default_model=DEFAULT_CLOUD_MODEL,
                available_models=[DEFAULT_CLOUD_MODEL],
                is_default=True,
            ).normalized()
        ]

    def _format_status_timestamp(self, value: str) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        if "T" in text:
            text = text.replace("T", " ")
        return text[:16]

    def _now_status_timestamp(self) -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M")

    def _format_profile_status(self, profile: ModelConfigProfile | None) -> str:
        if profile is None:
            return "未测试"
        timestamp = self._format_status_timestamp(profile.connection_checked_at)
        status = profile.connection_status
        if status == "connected":
            return f"已连接 · {timestamp}" if timestamp else "已连接"
        if status == "refresh_failed":
            return f"刷新失败 · {timestamp}" if timestamp else "刷新失败"
        if status == "disconnected":
            return f"未连接 · {timestamp}" if timestamp else "未连接"
        return f"未测试 · {timestamp}" if timestamp else "未测试"

    def _current_privacy_level(self) -> str:
        if not hasattr(self, "privacy_level_combo"):
            return "standard"
        return str(self.privacy_level_combo.currentData() or "standard")

    def _selected_settings_profile(self) -> ModelConfigProfile | None:
        index = self.settings_model_profile_combo.currentIndex() if hasattr(self, "settings_model_profile_combo") else -1
        if 0 <= index < len(self._model_profiles):
            return self._model_profiles[index]
        return None

    def _selected_log_profile(self) -> ModelConfigProfile | None:
        profile_id = str(self.log_model_profile_combo.currentData() or "") if hasattr(self, "log_model_profile_combo") else ""
        for profile in self._model_profiles:
            if profile.profile_id == profile_id:
                return profile
        return None

    def _sync_current_profile_to_state(self) -> None:
        if self._model_profile_form_loading or not hasattr(self, "settings_model_profile_combo"):
            return
        index = self.settings_model_profile_combo.currentIndex()
        if not (0 <= index < len(self._model_profiles)):
            return
        current = self._model_profiles[index]
        api_key_text = self.settings_profile_api_key_input.text().strip()
        self._model_profiles[index] = ModelConfigProfile(
            profile_id=current.profile_id,
            profile_name=self.settings_profile_name_input.text().strip() or current.profile_name,
            provider=str(self.settings_profile_provider_combo.currentData() or DEFAULT_CLOUD_PROVIDER),
            api_url=self.settings_profile_api_url_input.text().strip() or current.api_url,
            api_key=api_key_text if api_key_text else current.api_key,
            timeout_seconds=self.settings_profile_timeout_input.value(),
            default_model=self.settings_profile_default_model_combo.currentText().strip() or current.default_model,
            available_models=list(current.available_models),
            connection_status=current.connection_status,
            connection_checked_at=current.connection_checked_at,
            is_default=current.is_default,
        ).normalized()

    def _load_profile_to_form(self, profile: ModelConfigProfile | None) -> None:
        self._model_profile_form_loading = True
        try:
            if profile is None:
                self.settings_profile_name_input.clear()
                self.settings_profile_provider_combo.setCurrentIndex(0)
                self.settings_profile_api_url_input.clear()
                self.settings_profile_api_key_input.clear()
                self.settings_profile_api_key_input.setPlaceholderText("未保存")
                self.settings_profile_timeout_input.setValue(60)
                self.settings_profile_default_model_combo.clear()
                self.settings_profile_status_label.setText("未测试")
                self.settings_profile_status_label.setToolTip("")
                return
            self.settings_profile_name_input.setText(profile.profile_name)
            self.settings_profile_provider_combo.setCurrentIndex(max(0, self.settings_profile_provider_combo.findData(profile.provider)))
            self.settings_profile_api_url_input.setText(profile.api_url)
            self.settings_profile_api_key_input.clear()
            self.settings_profile_api_key_input.setPlaceholderText("已保存，留空则不修改" if profile.api_key else "请输入 API Key")
            self.settings_profile_timeout_input.setValue(profile.timeout_seconds)
            self._populate_model_combo(self.settings_profile_default_model_combo, profile.available_models, profile.default_model)
            self.settings_profile_status_label.setText(self._format_profile_status(profile))
            self.settings_profile_status_label.setToolTip("")
        finally:
            self._model_profile_form_loading = False

    def _populate_model_combo(self, combo: QComboBox, models: list[str], selected: str) -> None:
        combo.blockSignals(True)
        combo.clear()
        values = [item for item in models if item]
        if selected and selected not in values:
            values.insert(0, selected)
        for item in dict.fromkeys(values):
            combo.addItem(item, item)
        if combo.isEditable():
            combo.setEditText(selected or (values[0] if values else ""))
        else:
            combo.setCurrentIndex(max(0, combo.findData(selected))) if values else combo.setCurrentIndex(-1)
        combo.blockSignals(False)

    def _reload_settings_profiles(self) -> None:
        self._ensure_model_profiles()
        selected_id = str(self.settings_model_profile_combo.currentData() or "") if hasattr(self, "settings_model_profile_combo") else ""
        self.settings_model_profile_combo.blockSignals(True)
        self.settings_model_profile_combo.clear()
        for profile in self._model_profiles:
            self.settings_model_profile_combo.addItem(profile.profile_name, profile.profile_id)
        target_id = selected_id or next((item.profile_id for item in self._model_profiles if item.is_default), self._model_profiles[0].profile_id)
        self.settings_model_profile_combo.setCurrentIndex(max(0, self.settings_model_profile_combo.findData(target_id)))
        self.settings_model_profile_combo.blockSignals(False)
        self._load_profile_to_form(self._selected_settings_profile())
        self._refresh_settings_model_summary()

    def _reload_log_analysis_profiles(self) -> None:
        self._ensure_model_profiles()
        selected_id = str(self.log_model_profile_combo.currentData() or "") if hasattr(self, "log_model_profile_combo") else ""
        self.log_model_profile_combo.blockSignals(True)
        self.log_model_profile_combo.clear()
        for profile in self._model_profiles:
            self.log_model_profile_combo.addItem(profile.profile_name, profile.profile_id)
        target_id = selected_id or next((item.profile_id for item in self._model_profiles if item.is_default), self._model_profiles[0].profile_id)
        self.log_model_profile_combo.setCurrentIndex(max(0, self.log_model_profile_combo.findData(target_id)))
        self.log_model_profile_combo.blockSignals(False)
        self._log_cloud_selection_changed()

    def _refresh_settings_model_summary(self) -> None:
        profile = next((item for item in self._model_profiles if item.is_default), self._selected_settings_profile())
        if profile is None:
            self.model_settings_summary_label.setText("未配置")
            return
        summary = f"{profile.profile_name} / {profile.default_model or '未设置模型'}\n{self._format_profile_status(profile)}"
        self.model_settings_summary_label.setText(summary)

    def _refresh_security_summary(self) -> None:
        label = {
            "standard": "标准脱敏",
            "strict": "严格脱敏",
            "local-only": "仅本地",
        }.get(self._current_privacy_level(), "标准脱敏")
        self.security_summary_label.setText(label)

    def _settings_profile_changed(self, _index: int) -> None:
        self._load_profile_to_form(self._selected_settings_profile())

    def _profile_form_changed(self, *_args: object) -> None:
        if self._model_profile_form_loading:
            return
        self._sync_current_profile_to_state()
        self._refresh_settings_model_summary()
        self._reload_log_analysis_profiles()

    def _add_model_profile(self) -> None:
        self._sync_current_profile_to_state()
        next_index = len(self._model_profiles) + 1
        profile = ModelConfigProfile(
            profile_id=f"profile-{next_index}",
            profile_name=f"模型配置 {next_index}",
            provider=DEFAULT_CLOUD_PROVIDER,
            api_url=DEFAULT_CLOUD_API_URL,
            default_model=DEFAULT_CLOUD_MODEL,
            available_models=[DEFAULT_CLOUD_MODEL],
            is_default=not self._model_profiles,
        ).normalized()
        self._model_profiles.append(profile)
        self._reload_settings_profiles()
        self.settings_model_profile_combo.setCurrentIndex(len(self._model_profiles) - 1)

    def _delete_model_profile(self) -> None:
        if not self._model_profiles:
            return
        index = self.settings_model_profile_combo.currentIndex()
        if not (0 <= index < len(self._model_profiles)):
            return
        deleted_default = self._model_profiles[index].is_default
        del self._model_profiles[index]
        if not self._model_profiles:
            self._ensure_model_profiles()
        if deleted_default and self._model_profiles:
            self._model_profiles[0].is_default = True
        self._reload_settings_profiles()
        self._reload_log_analysis_profiles()

    def _set_default_model_profile(self) -> None:
        index = self.settings_model_profile_combo.currentIndex()
        if not (0 <= index < len(self._model_profiles)):
            return
        self._sync_current_profile_to_state()
        for profile_index, profile in enumerate(self._model_profiles):
            profile.is_default = profile_index == index
        self._refresh_settings_model_summary()
        self._reload_log_analysis_profiles()

    def _persist_settings_config(self) -> None:
        cfg = self._settings_config()
        self.service.save_config(cfg)
        self.report_dir_input.set_path_value(str(cfg.report_output_dir))

    def _log_cloud_selection_changed(self, *_args: object) -> None:
        profile = self._selected_log_profile()
        selected_model = str(self.log_model_input.currentData() or self.log_model_input.currentText() or "")
        if profile and selected_model not in profile.available_models:
            selected_model = profile.default_model
        self._populate_model_combo(self.log_model_input, profile.available_models if profile else [], selected_model or (profile.default_model if profile else ""))
        self.log_refresh_models_button.setEnabled(profile is not None)
        status_text = self._format_profile_status(profile)
        if self._current_privacy_level() == "local-only":
            self.log_cloud_enabled_input.setChecked(False)
            self.log_cloud_enabled_input.setEnabled(False)
            self.log_cloud_status_label.setText(status_text if status_text != "未测试" else "未连接")
            self.log_cloud_status_label.setToolTip("当前安全策略为仅本地，日志分析不会发起云端模型调用。")
            return
        self.log_cloud_enabled_input.setEnabled(True)
        self.log_cloud_status_label.setToolTip("")
        self.log_cloud_status_label.setText(status_text)

    def _refresh_profile_models(self, profile: ModelConfigProfile) -> tuple[bool, str]:
        config = CloudModelConfig(
            provider=profile.provider,
            api_url=profile.api_url,
            model_name=profile.default_model,
            api_key=profile.api_key,
            timeout_seconds=profile.timeout_seconds,
        )
        result = CloudModelClient(config).list_models()
        timestamp = self._now_status_timestamp()
        if result.ok and isinstance(result.content, dict):
            models = [str(item).strip() for item in result.content.get("models", []) if str(item).strip()]
            if models:
                profile.available_models = list(dict.fromkeys(models))
                if profile.default_model not in profile.available_models:
                    profile.default_model = profile.available_models[0]
                profile.connection_status = "connected"
                profile.connection_checked_at = timestamp
                return True, ""
        profile.connection_status = "refresh_failed"
        profile.connection_checked_at = timestamp
        return False, sanitize_cloud_error(result.fallback_reason, profile.api_key)

    def _refresh_settings_profile_models(self) -> None:
        self._sync_current_profile_to_state()
        profile = self._selected_settings_profile()
        if profile is None:
            return
        ok, reason = self._refresh_profile_models(profile)
        self._load_profile_to_form(profile)
        self._refresh_settings_model_summary()
        self._reload_log_analysis_profiles()
        self._persist_settings_config()
        if reason:
            self.settings_profile_status_label.setToolTip(reason)
        if ok:
            self.settings_profile_status_label.setText(self._format_profile_status(profile))

    def _refresh_log_profile_models(self) -> None:
        profile = self._selected_log_profile()
        if profile is None:
            return
        ok, reason = self._refresh_profile_models(profile)
        self._reload_settings_profiles()
        self._reload_log_analysis_profiles()
        self._persist_settings_config()
        if reason:
            self.log_cloud_status_label.setToolTip(reason)
        elif ok:
            self.log_cloud_status_label.setToolTip("")

    def _save_current_config(self) -> None:
        try:
            self._persist_settings_config()
            cfg = self._settings_config()
            self._refresh_settings_model_summary()
            self._refresh_security_summary()
            self._reload_log_analysis_profiles()
            QMessageBox.information(
                self,
                "配置已保存",
                "配置已保存。登录密码不会写入本地配置文件；模型 API Key 将保存到本机配置档案中用于后续复用。",
            )
        except Exception as exc:
            QMessageBox.warning(self, "保存失败", str(exc))

    def _load_security_settings(self) -> None:
        if not hasattr(self, "password_min_length_input"):
            return
        policy = self.auth_service.get_password_policy()
        self.password_min_length_input.setValue(policy.min_length)
        self.password_require_digit_input.setChecked(policy.require_digit)
        self.password_require_mixed_case_input.setChecked(policy.require_mixed_case)
        self.password_require_special_input.setChecked(policy.require_special)

    def _save_password_policy(self) -> None:
        try:
            self.auth_service.update_password_policy(
                min_length=self.password_min_length_input.value(),
                require_digit=self.password_require_digit_input.isChecked(),
                require_mixed_case=self.password_require_mixed_case_input.isChecked(),
                require_special=self.password_require_special_input.isChecked(),
            )
            QMessageBox.information(self, "策略已保存", "密码复杂度设置已保存，将在后续修改密码时生效。")
        except Exception:
            QMessageBox.warning(self, "保存失败", "密码复杂度设置保存失败，请检查本地数据目录权限。")

    def _change_local_password(self) -> bool:
        ok, message = self.auth_service.change_password(
            self.current_username,
            self.current_password_input.text(),
            self.new_password_input.text(),
            self.confirm_password_input.text(),
        )
        if not ok:
            QMessageBox.warning(self, "修改失败", message)
            return False
        self.current_password_input.clear()
        self.new_password_input.clear()
        self.confirm_password_input.clear()
        QMessageBox.information(self, "修改成功", message)
        return True

    def show_default_password_warning_if_needed(self) -> None:
        if not self.auth_service.is_default_password_active(self.current_username):
            return
        dialog = DefaultPasswordWarningDialog(self)
        result = dialog.exec()
        if result == QDialog.Accepted and dialog.modify_now:
            self.go_to_module("settings")
            self.current_password_input.setFocus()

    def _start_inspection(self) -> None:
        cfg = self._current_config()
        errors = self.service.validate_config(cfg)
        if errors:
            QMessageBox.warning(self, "配置校验失败", "\n".join(errors))
            return
        self.current_result = None
        self.start_button.setEnabled(False)
        self.cancel_inspection_button.setEnabled(True)
        self.cancel_inspection_button.show()
        self.open_report_button.setEnabled(False)
        self.open_word_button.setEnabled(False)
        self.open_pdf_button.setEnabled(False)
        self.open_dir_button.setEnabled(False)
        self.result_summary.clear()
        self.progress_bar.setValue(0)
        self.stage_label.setText("准备启动")
        self.status_label.setText("正在初始化健康评估任务。")
        self.result_summary.setText("等待开始评估\n准备启动健康评估任务。")
        self.worker = InspectionWorker(self.service, cfg)
        self.worker.progress.connect(self._inspection_progress)
        self.worker.completed.connect(self._inspection_completed)
        self.worker.failed.connect(self._inspection_failed)
        self.worker.finished.connect(self._worker_finished)
        self._running = True
        self.worker.start()

    def _cancel_inspection(self) -> None:
        if not self.worker or not self._running:
            return
        self.cancel_inspection_button.setEnabled(False)
        self.stage_label.setText("正在取消巡检")
        self.status_label.setText("已请求取消，正在等待当前可中断步骤结束。")
        self.result_summary.setText("已请求取消当前健康评估。底层采集若正在执行，将在下一个可中断点结束。")
        self.worker.request_cancel()

    def _inspection_completed(self, result: InspectionRunResult) -> None:
        self._running = False
        self.current_result = result
        self.start_button.setEnabled(True)
        self.cancel_inspection_button.setEnabled(False)
        self.cancel_inspection_button.hide()
        self.open_report_button.setEnabled(result.report_path.exists())
        self.open_word_button.setEnabled(bool(result.docx_path and result.docx_path.exists()))
        self.open_pdf_button.setEnabled(bool(result.pdf_path and result.pdf_path.exists()))
        self.open_dir_button.setEnabled(True)
        self.progress_bar.setValue(100)
        self.stage_label.setText("健康评估完成")
        generated = []
        if result.report_path.exists():
            generated.append("HTML 报告包")
        if result.pdf_path and result.pdf_path.exists():
            generated.append("PDF 报告")
        if result.docx_path and result.docx_path.exists():
            generated.append("Word 报告")
        self.status_label.setText("巡检完成，已生成" + "、".join(generated) + "。" if generated else "巡检完成，但报告文件均未生成。")
        risk_total = actionable_risk_total(result.risk_summary)
        optimization_total = int(result.risk_summary.get("P4", 0) or 0)
        summary_lines = [
            f"任务 ID：{result.run_id}",
            f"健康状态：{self.service._health_status(result.score, result.risk_summary)}",
            f"风险总数：{risk_total}",
            f"优化建议：{optimization_total}",
        ]
        if result.report_path.exists():
            summary_lines.append(f"HTML 报告：{result.report_path}")
        elif result.html_error:
            summary_lines.append(result.html_error)
        if result.docx_path:
            summary_lines.append(f"Word 报告：{result.docx_path}")
        elif result.docx_error:
            summary_lines.append(result.docx_error)
        if result.pdf_path:
            summary_lines.append(f"PDF 报告：{result.pdf_path}")
        elif result.pdf_error:
            summary_lines.append(result.pdf_error)
        self.result_summary.setText(
            "\n".join(summary_lines)
        )
        self._refresh_all_data()

    def _inspection_failed(self, error: str) -> None:
        message = friendly_error_message(error)
        self._running = False
        self.start_button.setEnabled(True)
        self.cancel_inspection_button.setEnabled(False)
        self.cancel_inspection_button.hide()
        self.open_word_button.setEnabled(False)
        self.open_pdf_button.setEnabled(False)
        self.progress_bar.setValue(100)
        if "取消" in message:
            self.stage_label.setText("巡检已取消")
            self.status_label.setText("当前健康评估已取消，未标记为成功。")
        else:
            self.stage_label.setText("健康评估失败")
            self.status_label.setText("请检查连接、账号或采集条件。")
        self.result_summary.setText(message)
        if "取消" not in message:
            QMessageBox.warning(self, "健康评估失败", message)
        self._refresh_all_data()

    def _inspection_progress(self, progress: InspectionProgress) -> None:
        self.progress_bar.setValue(progress.percent)
        self.stage_label.setText(progress.message)
        self.status_label.setText(f"当前阶段：{progress.message}，进度 {progress.percent}%")
        if progress.state in {InspectionState.CANCELLED, InspectionState.CANCELLING}:
            self.cancel_inspection_button.setEnabled(False)
        self._append_progress_log(progress)
        if progress.error:
            self.result_summary.setText(friendly_error_message(progress.error))

    def _worker_finished(self) -> None:
        if self.worker is not None:
            self.worker.deleteLater()
            self.worker = None

    def _start_log_analysis(self) -> None:
        cfg = self._current_log_analysis_config()
        errors = self.service.validate_log_analysis_config(cfg)
        if errors:
            QMessageBox.warning(self, "日志分析校验失败", "\n".join(errors))
            return
        if self.log_cloud_enabled_input.isChecked() and not cfg.cloud_assist_enabled:
            if self._current_privacy_level() == "local-only":
                self.log_result_summary.setText("当前安全策略为仅本地，已自动切换为本地规则分析。")
            else:
                self.log_result_summary.setText("当前模型配置档案未配置完整或尚未保存，已自动切换为本地规则分析。")
        self.current_log_result = None
        self.log_start_button.setEnabled(False)
        self.open_log_html_button.setEnabled(False)
        self.open_log_word_button.setEnabled(False)
        self.open_log_dir_button.setEnabled(False)
        self.log_result_summary.clear()
        self.log_progress_bar.setValue(0)
        self.log_stage_label.setText("准备日志分析")
        self.log_status_label.setText("正在读取日志包。")
        self.log_result_summary.setText("0% 准备日志分析")
        self.log_worker = LogAnalysisWorker(self.service, cfg)
        self.log_worker.progress.connect(self._log_analysis_progress)
        self.log_worker.completed.connect(self._log_analysis_completed)
        self.log_worker.failed.connect(self._log_analysis_failed)
        self.log_worker.finished.connect(self._log_worker_finished)
        self.log_worker.start()

    def _start_upgrade_compat(self) -> None:
        cfg = self._current_upgrade_compat_config()
        errors = self.service.validate_upgrade_compat_config(cfg)
        if errors:
            QMessageBox.warning(self, "升级兼容性校验失败", "\n".join(errors))
            return
        self.current_upgrade_result = None
        self.upgrade_start_button.setEnabled(False)
        self.upgrade_open_html_button.setEnabled(False)
        self.upgrade_progress_bar.setValue(0)
        self.upgrade_stage_label.setText("准备升级兼容性检查")
        self.upgrade_status_label.setText("正在采集硬件与驱动信息。")
        self.upgrade_result_summary.setText("0% 准备升级兼容性检查")
        self.upgrade_worker = UpgradeCompatWorker(self.service, cfg)
        self.upgrade_worker.progress.connect(self._upgrade_compat_progress)
        self.upgrade_worker.completed.connect(self._upgrade_compat_completed)
        self.upgrade_worker.failed.connect(self._upgrade_compat_failed)
        self.upgrade_worker.finished.connect(self._upgrade_worker_finished)
        self.upgrade_worker.start()

    def _cancel_upgrade_compat(self) -> None:
        if self.upgrade_worker is not None:
            self.upgrade_worker.request_cancel()
            self.upgrade_cancel_button.setEnabled(False)
            self.upgrade_status_label.setText("已请求取消，将在当前读取步骤完成后停止。")

    def _upgrade_compat_progress(self, progress: UpgradeCompatProgress) -> None:
        self.upgrade_progress_bar.setValue(progress.percent)
        self.upgrade_stage_label.setText(progress.message)
        self.upgrade_status_label.setText(f"当前阶段：{progress.message}，进度 {progress.percent}%")
        line = f"{progress.percent}% {progress.message}"
        if line not in self.upgrade_result_summary.toPlainText(): self.upgrade_result_summary.append(line)
        if progress.error: self.upgrade_result_summary.setText(friendly_error_message(progress.error))

    def _upgrade_compat_completed(self, result: UpgradeCompatResult) -> None:
        self.current_upgrade_result = result
        self.upgrade_start_button.setEnabled(True)
        self.upgrade_cancel_button.setEnabled(False)
        self.upgrade_open_html_button.setEnabled(bool(result.html_path and result.html_path.exists()))
        self.upgrade_progress_bar.setValue(100)
        self.upgrade_stage_label.setText("升级兼容性检查已取消" if result.cancelled else ("升级兼容性检查完成" if not result.connection_diagnostic else "连接诊断完成"))
        self.upgrade_status_label.setText("已取消，未生成报告。" if result.cancelled else (result.connection_diagnostic or "独立 HTML 升级兼容性报告已生成。"))
        if result.connection_diagnostic:
            for metric_card in (self.upgrade_metric_total, self.upgrade_metric_pass, self.upgrade_metric_fail, self.upgrade_metric_unknown):
                self._set_upgrade_metric_value(metric_card, "—")
            self.upgrade_server_summary.setText("尚未建立 vCenter 连接，未执行设备和整机兼容性判定。")
        else:
            self._set_upgrade_metric_value(self.upgrade_metric_total, result.summary.get("total", 0))
            self._set_upgrade_metric_value(self.upgrade_metric_pass, result.summary.get("passed", 0))
            self._set_upgrade_metric_value(self.upgrade_metric_fail, result.summary.get("failed", 0))
            self._set_upgrade_metric_value(self.upgrade_metric_unknown, result.summary.get("unknown", 0))
            self.upgrade_server_summary.setText("\n".join(f"{item.get('model') or '未采集'}：{item.get('status')} · {item.get('detail')}" for item in result.server_results) or "未采集到主机 SMBiosModel。")
        self.upgrade_device_table.setRowCount(0)
        for item in result.device_results:
            row = self.upgrade_device_table.rowCount()
            self.upgrade_device_table.insertRow(row)
            matches = item.get("matches") or {}
            values = [item.get("object_name"), item.get("category"), (matches.get("vcg") or {}).get("status"), (item.get("vsan") or {}).get("status"), (matches.get("vcg") or {}).get("detail") or (item.get("vsan") or {}).get("detail") or ""]
            for column, value in enumerate(values): self.upgrade_device_table.setItem(row, column, QTableWidgetItem(str(value or "")))
        lines = [f"任务 ID：{result.run_id}"]
        if result.connection_diagnostic:
            lines.append(f"连接诊断：{result.connection_diagnostic}")
            lines.append("设备判定：未执行（连接未建立）")
        else:
            lines.append(f"设备：{result.summary.get('total', 0)} · 通过：{result.summary.get('passed', 0)} · 不通过：{result.summary.get('failed', 0)} · 无法确定：{result.summary.get('unknown', 0)}")
        if result.html_path: lines.append(f"HTML 报告：{result.html_path}")
        if result.collection_warnings: lines.append(f"采集警告：{len(result.collection_warnings)} 项")
        self.upgrade_result_summary.setText("\n".join(lines))
        self._refresh_upgrade_hcl_status()

    def _upgrade_compat_failed(self, error: str) -> None:
        self.upgrade_start_button.setEnabled(True)
        self.upgrade_cancel_button.setEnabled(False)
        self.upgrade_progress_bar.setValue(100)
        self.upgrade_stage_label.setText("升级兼容性检查失败")
        self.upgrade_status_label.setText("请检查 HCL 数据、采集路径和本地目录权限。")
        self.upgrade_result_summary.setText(friendly_error_message(error))
        QMessageBox.warning(self, "升级兼容性检查失败", friendly_error_message(error))

    def _upgrade_worker_finished(self) -> None:
        if self.upgrade_worker is not None:
            self.upgrade_worker.deleteLater()
            self.upgrade_worker = None
        self.upgrade_cancel_button.setEnabled(False)

    def _set_upgrade_metric_value(self, card: MetricCard, value: object) -> None:
        label = next((item for item in card.findChildren(QLabel) if item.objectName() == "metricValue"), None)
        if label is not None: label.setText(str(value))

    def _log_analysis_completed(self, result: LogAnalysisResult) -> None:
        self.current_log_result = result
        self.log_start_button.setEnabled(True)
        self.open_log_html_button.setEnabled(result.html_path.exists())
        self.open_log_word_button.setEnabled(result.docx_path.exists())
        self.open_log_dir_button.setEnabled(result.report_dir.exists())
        self.log_progress_bar.setValue(100)
        self.log_stage_label.setText("日志分析完成")
        engine = result.diagnosis.get("diagnosis_engine") if isinstance(result.diagnosis, dict) else {}
        model_quality = str(engine.get("model_quality") or "").strip().lower() if isinstance(engine, dict) else ""
        customer_report_mode = str(engine.get("customer_report_mode") or "rule_based").strip().lower() if isinstance(engine, dict) else "rule_based"
        fallback_reason = str(engine.get("fallback_reason") or "").strip() if isinstance(engine, dict) else ""
        api_call_attempted = bool(engine.get("api_call_attempted")) if isinstance(engine, dict) else False
        api_response_received = bool(engine.get("api_response_received")) if isinstance(engine, dict) else False
        if model_quality == "accepted" and customer_report_mode == "cloud_assisted":
            mode_line = "报告模式：云端模型辅助诊断"
            self.log_status_label.setText("独立 HTML / Word 日志分析报告已生成。")
        elif model_quality in {"downgraded", "rejected", "failed"}:
            mode_line = "报告模式：本地规则分析报告"
            self.log_status_label.setText("云端辅助未达到客户报告标准，本次生成的是本地规则分析报告。")
        elif fallback_reason:
            mode_line = "报告模式：离线日志粗排查（云端模型输出未通过质量门禁）"
            self.log_status_label.setText("云端模型未调用成功，本次生成的是本地规则分析报告。")
        else:
            mode_line = "报告模式：离线日志粗排查"
            self.log_status_label.setText("独立 HTML / Word 日志粗排查报告已生成。")
        model_used = bool(engine.get("model_used")) if isinstance(engine, dict) else False
        model_source = str(engine.get("model_source") or "rule_only") if isinstance(engine, dict) else "rule_only"
        cloud_provider = str(engine.get("cloud_provider") or "") if isinstance(engine, dict) else ""
        cloud_model = str(engine.get("model_name") or "") if isinstance(engine, dict) else ""
        cloud_target = " / ".join(part for part in (cloud_provider, cloud_model) if part) or "未指定模型"
        model_status_line = "模型调用状态：未启用云端模型，使用离线日志粗排查"
        if model_used and model_source == "cloud" and model_quality == "accepted":
            model_status_line = f"模型调用状态：云端 API 已响应并被接受（{cloud_target}）"
        elif model_used and model_source == "cloud" and model_quality == "downgraded":
            model_status_line = f"模型调用状态：云端 API 已响应，已降级为模型辅助粗排查（{cloud_target}）"
        elif api_response_received or (model_used and model_source == "cloud"):
            model_status_line = f"模型调用状态：云端 API 已响应，但模型输出未通过质量门禁（{cloud_target}）"
        elif api_call_attempted or fallback_reason:
            model_status_line = f"模型调用状态：云端 API 未调用成功（{cloud_target}）"
        stats = log_analysis_display_stats(result.summary, result.diagnosis, result.findings)
        lines = [
            f"任务 ID：{result.log_run_id}",
            mode_line,
            model_status_line,
            f"日志文件：{stats['log_files']}",
            f"关键证据：{stats['key_evidence']}",
            f"待补充材料：{stats['missing_materials']}",
            f"建议处理项：{stats['recommendations']}",
            f"HTML 报告：{result.html_path}",
            f"Word 报告：{result.docx_path}",
        ]
        if fallback_reason:
            lines.insert(3, f"模型状态说明：{fallback_reason}")
        if model_quality == "downgraded":
            lines.insert(2, "当前证据不足，不能仅凭当前 support bundle 确认最终根因。")
        elif model_quality == "rejected":
            lines.insert(2, "云端 API 已响应，但模型输出未通过质量门禁，本次生成的是日志粗排查报告。")
        elif fallback_reason:
            lines.insert(2, "云端模型未调用成功，本次生成的是日志粗排查报告。")
        self.log_result_summary.setText("\n".join(lines))
        self._refresh_all_data()

    def _log_analysis_failed(self, error: str) -> None:
        message = friendly_error_message(error)
        self.log_start_button.setEnabled(True)
        self.open_log_html_button.setEnabled(False)
        self.open_log_word_button.setEnabled(False)
        self.open_log_dir_button.setEnabled(False)
        self.log_progress_bar.setValue(100)
        self.log_stage_label.setText("日志分析失败")
        if "大模型分析失败" in message or "模型输出未通过" in message:
            self.log_status_label.setText("大模型分析失败，未生成客户 HTML / Word 报告。")
        else:
            self.log_status_label.setText("请检查日志包格式、本地目录权限或稍后重试。")
        self.log_result_summary.setText(message)
        QMessageBox.warning(self, "日志分析失败", message)
        self._refresh_all_data()

    def _log_analysis_progress(self, progress: LogAnalysisProgress) -> None:
        self.log_progress_bar.setValue(progress.percent)
        self.log_stage_label.setText(progress.message)
        self.log_status_label.setText(f"当前阶段：{progress.message}，进度 {progress.percent}%")
        line = f"{progress.percent}% {progress.message}"
        if line not in self.log_result_summary.toPlainText():
            self.log_result_summary.append(line)
        if progress.error:
            self.log_result_summary.setText(friendly_error_message(progress.error))

    def _log_worker_finished(self) -> None:
        if self.log_worker is not None:
            self.log_worker.deleteLater()
            self.log_worker = None

    def _append_progress_log(self, progress: InspectionProgress) -> None:
        stage_text = progress.message.strip()
        if not stage_text:
            return
        existing = self.result_summary.toPlainText()
        line = f"{progress.percent}% {stage_text}"
        if line not in existing:
            self.result_summary.append(line)

    def _db_path(self) -> Path:
        text = getattr(self, "db_path_input", None)
        return Path(text.path_value() if text and text.path_value() else DesktopInspectionConfig().db_path)

    def _compat_db_path(self) -> Path:
        return self.service.isolated_upgrade_compat_database_path(self._db_path())

    def _refresh_all_data(self) -> None:
        db_path = self._db_path()
        dashboard = self.service.get_dashboard_data(db_path)
        self._populate_dashboard(dashboard)
        history_rows = self.service.list_report_history(db_path)
        self._populate_history_table(self.dashboard_reports_table, history_rows[:6])
        report_root = Path(self.default_report_dir_input.path_value() or self.report_dir_input.path_value() or DesktopInspectionConfig().report_output_dir)
        self._populate_reports(
            self.service.list_report_packages(
                db_path,
                report_root=report_root,
                compat_db_path=self._compat_db_path(),
            )
        )
        self._risk_items = self.service.list_platform_findings(db_path, dashboard.run_id)
        self._asset_items = self.service.list_platform_assets(db_path, dashboard.run_id)
        self._check_evidence_items = self.service.list_certificate_license_evidence(db_path, dashboard.run_id)
        self._populate_risk_table()
        self._populate_asset_table()
        self._populate_check_evidence()
        self._populate_vcenter_center()
        self._populate_history_compare()

    def _populate_dashboard(self, data: DashboardData) -> None:
        health_status = str(data.health_status or "评估受限")
        self.dashboard_health_value.setText(health_status)
        self.dashboard_health_badge.setText(health_status)
        self.dashboard_health_badge.setProperty("status", self._dashboard_health_status_key(health_status))
        self.dashboard_health_badge.style().unpolish(self.dashboard_health_badge)
        self.dashboard_health_badge.style().polish(self.dashboard_health_badge)
        if not data.has_data:
            self.dashboard_health_value.setText("等待首次评估")
            self.dashboard_health_badge.setText("等待首次评估")
            self.dashboard_scope_label.setText("暂无评估范围 · 完成首次健康评估后进入平台首页")
            self.risk_waiting_card.show()
            self.asset_waiting_card.show()
            for card in self.risk_metric_cards:
                card.hide()
            for card in self.asset_metric_widgets:
                card.hide()
            self.trend_text.setText("完成首次健康评估后，将展示过去 30 天风险趋势。")
            self.trend_chart.set_data([])
            self.dashboard_certificate_summary.setText("本次尚无证书或授权核验数据。完成巡检后在此展示。")
            self.dashboard_certificate_detail.clear()
            self.dashboard_certificate_detail.hide()
            self.dashboard_certificate_toggle.setEnabled(False)
            self.dashboard_reports_empty.show()
            self.dashboard_reports_table.hide()
            self.scope_label.hide()
            self.scope_hint.show()
            return
        self.risk_waiting_card.hide()
        self.asset_waiting_card.hide()
        for card in self.risk_metric_cards:
            card.show()
        for card in self.asset_metric_widgets:
            card.show()
        for level, label in self.risk_metric_labels.items():
            label.setText(str(data.risk_summary.get(level, 0)))
        for name, label in self.asset_metric_cards.items():
            label.setText(str(data.asset_summary.get(name, 0)))
        if data.risk_trend:
            last = data.risk_trend[-1]
            self.trend_text.setText(
                f"最近 {len(data.risk_trend)} 次评估，最新风险总数 {last.get('risk_total', 0)}，"
                f"优化建议 {last.get('optimization_total', 0)}。"
            )
        else:
            self.trend_text.setText("暂无历史数据。完成评估后将展示过去 30 次风险趋势。")
        self.trend_chart.set_data(data.risk_trend)
        self._populate_history_table(self.dashboard_reports_table, data.recent_reports[:6])
        self.dashboard_reports_empty.setVisible(not bool(data.recent_reports))
        self.dashboard_reports_table.setVisible(bool(data.recent_reports))
        self.scope_hint.hide()
        self.scope_label.show()
        self.scope_label.setText(f"{data.customer_name}\n{data.vcenter}")
        self.dashboard_scope_label.setText(
            f"{self._dashboard_health_reason(data.health_status, data.health_impact)}\n{data.customer_name} · {data.vcenter}"
        )

    @staticmethod
    def _dashboard_health_reason(status: str, health_impact: dict[str, int]) -> str:
        if status == "危险":
            return f"发现 {int(health_impact.get('critical', 0) or 0)} 项影响环境可用性的严重问题"
        if status == "关注":
            return "存在需要安排处理的健康关注项"
        if status == "正常":
            return "存在一般维护问题，当前未发现严重健康影响"
        if status == "评估受限":
            return "关键检查覆盖受限，当前结论仅基于已确认数据"
        return "本次必要检查未发现需处理的运行风险"

    def _populate_reports(self, rows: list[ReportCenterItem]) -> None:
        self._report_items = rows[:80]
        self._populate_report_list(rows[:50])
        has_reports = bool(rows)
        self.report_center_empty.setVisible(not has_reports)
        self.report_splitter.setVisible(has_reports)
        if not has_reports:
            self.report_detail.setText("暂无报告。完成健康评估或日志分析后，将展示报告摘要和打开入口。")
            self.open_selected_report_button.setEnabled(False)
            self.open_selected_dir_button.setEnabled(False)
            self.report_copy_path_button.setEnabled(False)
            self.report_word_button.setEnabled(False)
            self.report_pdf_button.setEnabled(False)
            self.delete_report_button.setEnabled(False)
        elif self.report_list.currentRow() < 0:
            self.report_list.setCurrentRow(0)

    def _populate_report_list(self, rows: list[ReportCenterItem]) -> None:
        if not hasattr(self, "report_list"):
            return
        self.report_list.blockSignals(True)
        self.report_list.clear()
        for index, item in enumerate(rows):
            if self._is_log_report_item(item):
                assets = item.asset_summary
                text = "\n".join(
                    [
                        item.title or DEFAULT_LOG_ANALYSIS_TITLE,
                        f"客户 {item.customer_name or DEFAULT_CUSTOMER_NAME} · {item.report_type}",
                        f"日志文件 {assets.get('LogFile', 0)} · 关键证据 {assets.get('Evidence', 0)} · 建议处理项 {assets.get('Recommendation', 0)} · {item.status}",
                        item.assessment_time or "暂无分析时间",
                    ]
                )
            elif self._is_upgrade_report_item(item):
                assets = item.asset_summary
                text = "\n".join(
                    [
                        item.title or DEFAULT_UPGRADE_COMPAT_TITLE,
                        f"客户 {item.customer_name or DEFAULT_CUSTOMER_NAME} · {item.report_type}",
                        f"目标 {item.site_name} · 设备 {assets.get('Device', 0)} · 通过 {assets.get('Passed', 0)} · 阻塞 {assets.get('Failed', 0)} · 待核对 {assets.get('Unknown', 0)} · {item.status}",
                        item.assessment_time or "暂无检查时间",
                    ]
                )
            else:
                risk_total = actionable_risk_total(item.risk_summary)
                optimization_total = int(item.risk_summary.get("P4", 0) or 0)
                assets = item.asset_summary
                text = "\n".join(
                    [
                        item.title or DEFAULT_REPORT_TITLE,
                        f"客户 {item.customer_name or DEFAULT_CUSTOMER_NAME} · {item.report_type}",
                        f"健康状态 {self.service._health_status(item.score if isinstance(item.score, (int, float)) else None, item.risk_summary)} · 风险 {risk_total} · 优化建议 {optimization_total} · {item.status}",
                        f"Host {assets.get('Host', 0)} · VM {assets.get('VM', 0)} · Datastore {assets.get('Datastore', 0)}",
                        item.assessment_time or "暂无评估时间",
                    ]
                )
            entry = QListWidgetItem(text)
            entry.setData(Qt.UserRole, index)
            entry.setSizeHint(QSize(360, 124))
            self.report_list.addItem(entry)
        self.report_list.blockSignals(False)

    def _populate_history_table(self, table: QTableWidget, rows: list[ReportHistoryItem]) -> None:
        table.setRowCount(len(rows))
        for index, item in enumerate(rows):
            risk_total = actionable_risk_total(item.risk_summary)
            values = [
                item.generated_at or item.updated_at or "",
                item.customer_name,
                item.vcenter,
                item.run_status,
                self.service._health_status(item.score, item.risk_summary) if hasattr(item, "risk_summary") else "查看报告",
                str(risk_total),
            ]
            if table.columnCount() > 6:
                values.append(str(item.report_path or ""))
            for column, value in enumerate(values):
                cell = QTableWidgetItem(value)
                cell.setData(Qt.UserRole, str(item.report_path or ""))
                table.setItem(index, column, cell)
        table.resizeColumnsToContents()
        if table.columnCount() > 6:
            table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        elif table.columnCount() > 2:
            table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)

    def _populate_risk_table(self) -> None:
        if not hasattr(self, "risk_list"):
            return
        if not self._risk_items:
            self.risk_empty.show()
            self.risk_splitter.hide()
            self.risk_detail.setText("暂无风险数据。")
            return
        self.risk_empty.hide()
        self.risk_splitter.show()
        level = self.risk_level_filter.currentText()
        object_type = self.risk_type_filter.currentText()
        keyword = self.risk_keyword_input.text().strip().lower()
        rows = []
        for item in self._risk_items:
            if level != "全部等级" and item.risk_level != level:
                continue
            if object_type != "全部对象" and item.object_type != object_type:
                continue
            haystack = f"{item.title} {item.object_name} {item.impact} {item.remediation}".lower()
            if keyword and keyword not in haystack:
                continue
            rows.append(item)
        self._filtered_risk_items = rows
        self.risk_list.blockSignals(True)
        self.risk_list.clear()
        for row, item in enumerate(rows):
            entry = QListWidgetItem()
            entry.setData(Qt.UserRole, row)
            entry.setSizeHint(QSize(420, 84))
            self.risk_list.addItem(entry)
            card = QFrame()
            card.setObjectName("sectionCard")
            card_layout = QHBoxLayout(card)
            card_layout.setContentsMargins(12, 10, 12, 10)
            card_layout.setSpacing(10)
            card_layout.addWidget(risk_badge(item.risk_level))
            text = QLabel(f"{item.title}\n{item.object_type} · {item.object_name}\n{self._risk_status_text(item.status)}")
            text.setWordWrap(True)
            card_layout.addWidget(text, 1)
            self.risk_list.setItemWidget(entry, card)
        self.risk_list.blockSignals(False)
        if rows:
            self.risk_list.setCurrentRow(0)
            self._show_risk_detail(rows[0])
        else:
            self.risk_detail.setText("暂无符合筛选条件的风险。")

    def _risk_selection_changed(self, *_args) -> None:
        row = self.risk_list.currentRow()
        if row < 0:
            return
        rows = getattr(self, "_filtered_risk_items", [])
        if row >= len(rows):
            return
        self._show_risk_detail(rows[row])

    def _show_risk_detail(self, item: PlatformFindingItem) -> None:
        affected = "、".join(item.affected_components) if item.affected_components else "无"
        source = self._business_source_label(item.object_type, item.source_path)
        self.risk_detail.setText(
            "\n".join(
                [
                    f"风险名称：{item.title}",
                    f"风险等级：{item.risk_level}",
                    f"影响对象：{item.object_name}",
                    "",
                    f"当前观察值：{item.current_observed or '未记录'}",
                    f"建议基线：{item.expected_state or '按健康评估基线执行'}",
                    f"数据来源：{source}",
                    f"发现时间：{item.collected_at or item.last_seen_at or '未记录'}",
                    "",
                    f"影响说明：{item.impact or '未记录'}",
                    f"整改建议：{item.remediation or '未记录'}",
                    f"参考说明：{item.explanation or item.evidence_summary or '已根据采集到的环境状态完成判断。'}",
                    f"受影响组件：{affected}",
                ]
            )
        )

    def _format_raw_evidence(self, raw: dict[str, Any]) -> str:
        if not raw:
            return "当前未提供结构化依据"
        try:
            return json.dumps(self._safe_evidence_value(raw), ensure_ascii=False, indent=2)
        except TypeError:
            return str(raw)

    def _safe_evidence_value(self, value: Any) -> Any:
        if isinstance(value, bool):
            return "是" if value else "否"
        if isinstance(value, list):
            return [self._safe_evidence_value(item) for item in value]
        if isinstance(value, dict):
            blocked = {
                "implementation_status",
                "execution_mode",
                "capability_required",
                "collector_version",
                "confidence_reason",
                "raw_ref",
            }
            return {str(key): self._safe_evidence_value(item) for key, item in value.items() if str(key) not in blocked}
        return value

    def _risk_status_text(self, status: str) -> str:
        return {
            "open": "待整改",
            "resolved": "已解决",
            "exception": "已例外",
            "reopened": "重新出现",
        }.get(status, "待跟进")

    def _populate_check_evidence(self) -> None:
        if not hasattr(self, "dashboard_certificate_summary"):
            return
        if not self._check_evidence_items:
            self.dashboard_certificate_summary.setText("本次评估未形成证书或授权核验记录；该区域保持评估受限，不按正常处理。")
            self.dashboard_certificate_list.clear()
            self.dashboard_certificate_list.hide()
            self.dashboard_certificate_detail.setText("暂无核验明细。")
            self.dashboard_certificate_detail.hide()
            self.dashboard_certificate_toggle.setEnabled(False)
            self.dashboard_certificate_toggle.setText("查看核验明细")
            return
        counts = {"success": 0, "warning": 0, "danger": 0}
        details: list[str] = []
        ordered_items = sorted(
            self._check_evidence_items,
            key=lambda item: {"danger": 0, "warning": 1, "success": 2}.get(self._check_status_key(item.result_status), 3),
        )
        for item in self._check_evidence_items:
            key = self._check_status_key(item.result_status)
            if key == "success":
                counts["success"] += 1
            elif key == "danger":
                counts["danger"] += 1
            else:
                counts["warning"] += 1
            details.append(
                "\n".join(
                    [
                        f"{self._check_category_label(item)} · {self._check_status_text(item.result_status)}",
                        f"对象：{item.object_type} · {item.object_name}",
                        f"当前状态：{item.current_observed or '未记录'}",
                        f"来源：{self._business_source_label(item.object_type, item.source_path, item.rule_id)} · 采集时间：{item.collected_at or '未记录'}",
                    ]
                )
            )
        self.dashboard_certificate_summary.setText(
            f"已核验 {len(self._check_evidence_items)} 项：{counts['success']} 项正常，{counts['warning']} 项需关注，{counts['danger']} 项异常。"
        )
        certificate_items = [item for item in ordered_items if item.rule_id in {"VSL-VC-005", "VSL-HOST-008"}]
        self.dashboard_certificate_list.clear()
        for item in certificate_items[:6]:
            observed = item.raw_evidence.get("observed_detail", {}) if isinstance(item.raw_evidence, dict) else {}
            expires_on = str(observed.get("host_certificate_not_after") or "")
            remaining = observed.get("host_certificate_days_remaining")
            if not expires_on and item.rule_id == "VSL-VC-005":
                remaining = item.current_observed
            expiry_text = f"到期 {expires_on}" if expires_on else (f"剩余 {remaining} 天（到期日未采集）" if remaining not in (None, "", "未记录") else "到期日未采集")
            label = f"{item.object_name} · {self._check_status_text(item.result_status)}\n{expiry_text}"
            entry = QListWidgetItem(label)
            entry.setSizeHint(QSize(280, 52))
            self.dashboard_certificate_list.addItem(entry)
        self.dashboard_certificate_list.setVisible(self.dashboard_certificate_list.count() > 0)
        self.dashboard_certificate_detail.setText("\n\n".join(details))
        self.dashboard_certificate_toggle.setEnabled(True)

    def _check_evidence_selection_changed(self, *_args) -> None:
        row = self.check_evidence_list.currentRow()
        if row < 0 or row >= len(self._check_evidence_items):
            return
        self._show_check_evidence_detail(self._check_evidence_items[row])

    def _show_check_evidence_detail(self, item: CheckEvidenceItem) -> None:
        source = self._business_source_label(item.object_type, item.source_path, item.rule_id)
        self.check_evidence_detail.setText(
            "\n".join(
                [
                    f"核验类别：{self._check_category_label(item)}",
                    f"状态：{self._check_status_text(item.result_status)}",
                    f"对象类型：{item.object_type}",
                    f"对象名称：{item.object_name}",
                    "",
                    f"当前状态：{item.current_observed or '未记录'}",
                    f"建议状态：{item.expected_state or '按健康评估基线执行'}",
                    f"数据来源：{source}",
                    f"采集时间：{item.collected_at or '未记录'}",
                    f"说明：{item.explanation or item.evidence_summary or '已根据采集到的环境状态完成核验。'}",
                ]
            )
        )

    def _check_category_label(self, item: CheckEvidenceItem) -> str:
        if item.rule_id in {"VSL-VC-005"}:
            return "vCenter 证书状态"
        if item.rule_id in {"VSL-VC-006"}:
            return "vCenter 授权状态"
        if item.rule_id in {"VSL-HOST-008"}:
            return "ESXi 证书状态"
        if item.rule_id in {"VSL-HOST-023"}:
            return "ESXi 主机授权状态"
        return "环境核验结果"

    def _business_source_label(self, object_type: str, source_path: str = "", rule_id: str = "") -> str:
        text = f"{object_type} {source_path} {rule_id}".lower()
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
        if object_type == "Datastore":
            return "数据存储运行状态"
        if object_type == "HostSystem":
            return "ESXi 主机运行状态"
        if object_type == "VirtualMachine":
            return "虚拟机运行状态"
        if object_type == "ClusterComputeResource":
            return "集群配置状态"
        if object_type == "vCenter":
            return "vCenter 管理平台"
        return "环境采集数据"

    def _check_status_key(self, status: str) -> str:
        return {
            "passed": "success",
            "failed": "danger",
            "unavailable": "warning",
            "error": "danger",
            "not_applicable": "planned",
        }.get(status, "planned")

    def _check_status_text(self, status: str) -> str:
        return {
            "passed": "通过",
            "failed": "风险命中",
            "unavailable": "不可用",
            "error": "执行异常",
            "not_applicable": "不适用",
        }.get(status, status or "未知")

    def _populate_asset_table(self) -> None:
        if not hasattr(self, "asset_table"):
            return
        if not self._asset_items:
            self.asset_empty.show()
            self.asset_splitter.hide()
            return
        self.asset_empty.hide()
        self.asset_splitter.show()
        self._refresh_asset_category_buttons()
        selected = self.asset_type_filter.currentText()
        keyword = self.asset_search_input.text().strip().lower()
        rows = []
        for item in self._asset_items:
            if selected != "全部对象" and item.object_type_label != selected:
                continue
            haystack = f"{item.object_name} {item.location} {item.detail}".lower()
            if keyword and keyword not in haystack:
                continue
            rows.append(item)
        sort_name = self.asset_sort_filter.currentText()
        if sort_name == "按对象类型":
            rows.sort(key=lambda item: (item.object_type_label, item.object_name.casefold()))
        elif sort_name == "按位置":
            rows.sort(key=lambda item: (item.location.casefold(), item.object_name.casefold()))
        else:
            rows.sort(key=lambda item: item.object_name.casefold())
        self._asset_display_rows = rows
        headers = self._asset_headers(selected)
        self.asset_table.setHorizontalHeaderLabels(headers)
        self.asset_table.setRowCount(len(rows))
        for row, item in enumerate(rows):
            values = self._asset_row_values(item, selected)
            for col, value in enumerate(values):
                self.asset_table.setItem(row, col, QTableWidgetItem(value))
        self.asset_table.resizeColumnsToContents()
        self.asset_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        if rows:
            self.asset_table.setCurrentCell(0, 0)
            self._show_asset_detail(rows[0])
        else:
            self.asset_detail.setText("暂无符合筛选条件的资产。")

    def _refresh_asset_category_buttons(self) -> None:
        counts = {"全部对象": len(self._asset_items)}
        for item in self._asset_items:
            counts[item.object_type_label] = counts.get(item.object_type_label, 0) + 1
        labels = ["全部对象", "vCenter", "Cluster", "ESXi", "Datastore", "VM"]
        for label in labels:
            button = self.asset_category_buttons.get(label)
            if button is None:
                button = QPushButton()
                button.clicked.connect(lambda _checked=False, selected=label: self._select_asset_category(selected))
                self.asset_category_buttons[label] = button
                self.asset_category_bar.addWidget(button)
            button.setText(f"{label} {counts.get(label, 0)}")
            button.setProperty("active", label == self.asset_type_filter.currentText())
            button.style().unpolish(button)
            button.style().polish(button)

    def _select_asset_category(self, selected: str) -> None:
        self.asset_type_filter.setCurrentText(selected)
        self._populate_asset_table()

    @staticmethod
    def _asset_headers(selected: str) -> list[str]:
        if selected == "ESXi":
            return ["ESXi 主机", "集群 / 位置", "型号与版本", "连接状态 / 来源"]
        if selected == "VM":
            return ["虚拟机", "所属主机 / 集群", "电源状态", "其他属性"]
        if selected == "Datastore":
            return ["数据存储", "归属范围", "类型 / 容量 / 使用率", "其他属性"]
        if selected == "Cluster":
            return ["集群", "归属范围", "主机数 / HA / DRS", "其他属性"]
        if selected == "vCenter":
            return ["vCenter", "地址 / 位置", "版本", "最近采集"]
        return ["对象类型", "对象名称", "位置", "关键属性"]

    def _asset_row_values(self, item: PlatformAssetItem, selected: str) -> list[str]:
        detail = self._friendly_asset_detail(item.detail)
        if selected == "VM":
            return [item.object_name, item.location, self._power_state_text(detail), detail]
        if selected in {"ESXi", "Datastore", "Cluster", "vCenter"}:
            return [item.object_name, item.location, detail, f"采集记录 {item.run_id}"]
        return [item.object_type_label, item.object_name, item.location, detail]

    @staticmethod
    def _friendly_asset_detail(detail: str) -> str:
        return str(detail or "未记录").replace("poweredOn", "已开机").replace("poweredOff", "已关机").replace("suspended", "已挂起")

    def _power_state_text(self, detail: str) -> str:
        if "已开机" in detail:
            return "已开机"
        if "已关机" in detail:
            return "已关机"
        if "已挂起" in detail:
            return "已挂起"
        return "未记录"

    def _asset_selection_changed(self, row: int, *_args) -> None:
        rows = getattr(self, "_asset_display_rows", [])
        if 0 <= row < len(rows):
            self._show_asset_detail(rows[row])

    def _show_asset_detail(self, item: PlatformAssetItem) -> None:
        self.asset_detail.setText(
            "\n".join(
                [
                    f"对象类型：{item.object_type_label}",
                    f"对象名称：{item.object_name}",
                    f"完整位置：{item.location or '未记录'}",
                    f"属性：{self._friendly_asset_detail(item.detail)}",
                    f"数据来源：巡检记录 {item.run_id}",
                ]
            )
        )

    def _populate_vcenter_center(self) -> None:
        self._clear_layout(self.vcenter_cards)
        rows = self.service.list_vcenter_summaries(self._db_path())
        if not rows:
            self.vcenter_stack.setCurrentIndex(0)
            return
        self.vcenter_stack.setCurrentIndex(1)
        for index, item in enumerate(rows):
            card = InfoCard(
                item.host,
                "已纳入健康评估平台的 vCenter 对象。",
                status=self._status_badge_key(item.latest_status, item.latest_score),
                details=[
                    ("名称", item.name),
                    ("版本", item.version),
                    ("Build", item.build),
                    ("连接状态", self._connection_status_text(item.latest_status)),
                    ("健康状态", self._health_label(item.latest_score)),

                ],
                button_text="查看资产入口",
                on_click=lambda: self.go_to_module("asset_center"),
            )
            self.vcenter_cards.addWidget(card, index // 3, index % 3)

    def _status_badge_key(self, status: str, score: float | None = None) -> str:
        lowered = (status or "").lower()
        if lowered == "success":
            return "success"
        if lowered in {"failed", "error"}:
            return "danger"
        if lowered in {"running", "pending"}:
            return "info"
        if lowered in {"offline", "disabled"}:
            return "offline"
        return "unknown"

    def _run_status_text(self, status: str) -> str:
        return {
            "success": "评估完成",
            "failed": "评估失败",
            "running": "评估中",
            "pending": "等待执行",
        }.get(status or "", "未知")

    def _connection_status_text(self, status: str) -> str:
        return "在线" if status == "success" else "异常" if status == "failed" else "未知"

    def _health_label(self, score: float | None) -> str:
        # Historical numeric scores are not a health-state classifier.
        return "查看最近报告" if score is not None else "评估受限"

    def _populate_history_compare(self) -> None:
        comparison = self.service.get_history_comparison(self._db_path())
        self._history_comparison = comparison
        self._populate_history_options(comparison)
        self._render_history_comparison(comparison)

    def _populate_history_options(self, comparison: HistoryComparison) -> None:
        """下拉选项只包含当前 vCenter 环境的记录，避免跨环境任意组合两条巡检。"""
        if not hasattr(self, "baseline_run_combo"):
            return
        self._history_combo_updating = True
        for combo in (self.baseline_run_combo, self.comparison_run_combo):
            combo.blockSignals(True)
            combo.clear()
            for option in comparison.run_options:
                combo.addItem(self._history_option_label(option), option.run_id)
            combo.blockSignals(False)

        def select(combo: QComboBox, run_id: str) -> None:
            if not run_id:
                return
            for index in range(combo.count()):
                if combo.itemData(index) == run_id:
                    combo.setCurrentIndex(index)
                    return

        select(self.baseline_run_combo, comparison.baseline_run_id)
        select(self.comparison_run_combo, comparison.comparison_run_id)
        self._history_combo_updating = False

    def _history_combo_changed(self) -> None:
        if self._history_combo_updating:
            return
        baseline = self.baseline_run_combo.currentData()
        comparison = self.comparison_run_combo.currentData()
        payload = self.service.get_history_comparison(self._db_path(), str(baseline or ""), str(comparison or ""))
        self._history_comparison = payload
        self._render_history_comparison(payload)

    @staticmethod
    def _history_option_label(option) -> str:
        """选项文字包含巡检时间、vCenter 环境、健康度和风险数，便于识别记录来源。"""
        label = str(getattr(option, "label", "") or "").strip()
        if label:
            return label
        stamp = str(getattr(option, "timestamp", "") or "").replace("T", " ")[:16] or "未命名评估"
        return f"{stamp} · 风险 {getattr(option, 'risk_total', 0)}"

    @staticmethod
    def _history_summary_without_score(text: str) -> str:
        parts = [part.strip() for part in str(text or "").split("；")]
        filtered = [part for part in parts if "健康评分" not in part and "评分" not in part]
        return "；".join(filtered) or "已选择两次评估，可查看风险和资产变化。"

    @staticmethod
    def _history_scope_text(comparison: HistoryComparison) -> str:
        scope = str(getattr(comparison, "environment_label", "") or "").strip()
        return f"对比范围：{scope}" if scope else ""

    def _render_history_comparison(self, comparison: HistoryComparison) -> None:
        summary_text = self._history_summary_without_score(comparison.summary_text)
        scope_text = self._history_scope_text(comparison)
        if scope_text and comparison.state != "empty":
            summary_text = f"{scope_text}；{summary_text}"
        self.history_summary_label.setText(summary_text)
        if comparison.state == "empty":
            self.history_empty_text.setText("暂无评估数据，完成首次评估后可查看历史趋势。")
            self.history_empty.show()
            self.history_content.hide()
            return
        if comparison.state != "ready":
            # single_run / environment_mismatch / run_unavailable：只展示明确提示，不渲染任何差异。
            self.history_empty_text.setText(str(comparison.summary_text or "暂无可比的历史巡检记录。"))
            self.history_empty.show()
            self.history_content.hide()
            return

        self.history_empty.hide()
        self.history_content.show()
        metric_map = {
            "P1": (comparison.risk_counts.get("P1"), "count"),
            "P2": (comparison.risk_counts.get("P2"), "count"),
            "P3": (comparison.risk_counts.get("P3"), "count"),
            "host": (comparison.asset_counts.get("host"), "count"),
            "vm": (comparison.asset_counts.get("vm"), "count"),
            "datastore": (comparison.asset_counts.get("datastore"), "count"),
        }
        for key, (delta, mode) in metric_map.items():
            if delta is None:
                self.history_metric_labels[key].setText("--")
                self.history_metric_subtitles[key].setText("无对比")
                continue
            self.history_metric_labels[key].setText(self._history_metric_text(delta))
            self.history_metric_subtitles[key].setText(self._delta_text(delta, mode))
        self._populate_history_risk_changes()
        self._populate_history_asset_changes()

    def _history_metric_text(self, delta) -> str:
        baseline = "--" if delta.baseline in (None, "") else str(delta.baseline)
        comparison = "--" if delta.comparison in (None, "") else str(delta.comparison)
        return f"{baseline} → {comparison}"

    def _delta_text(self, delta, mode: str = "count") -> str:
        value = delta.delta
        if value in (None, ""):
            return "无对比"
        try:
            number = float(value)
        except (TypeError, ValueError):
            return str(value)
        if number == 0:
            return "无变化"
        shown = int(abs(number)) if float(abs(number)).is_integer() else round(abs(number), 2)
        return f"增加 {shown}" if number > 0 else f"减少 {shown}"

    def _populate_history_risk_changes(self) -> None:
        if not hasattr(self, "history_risk_list"):
            return
        self.history_risk_list.clear()
        comparison = self._history_comparison
        if comparison is None or comparison.state != "ready":
            return
        selected = self.history_risk_filter.currentText()
        groups = []
        if selected in {"全部", "新增"}:
            groups.extend(comparison.risk_changes.get("new", []))
        if selected in {"全部", "本次未再检出"}:
            groups.extend(comparison.risk_changes.get("closed", []))
        if selected in {"全部", "持续"}:
            groups.extend(comparison.risk_changes.get("persistent", []))
        self._history_risk_groups = groups
        if not groups:
            entry = QListWidgetItem("暂无符合筛选条件的风险变化。")
            entry.setSizeHint(QSize(420, 52))
            self.history_risk_list.addItem(entry)
            return
        self._render_history_page("risk")

    def _history_risk_filter_changed(self) -> None:
        self._history_risk_page = 0
        self._populate_history_risk_changes()

    def _change_history_page(self, category: str, delta: int) -> None:
        name = f"_history_{category}_page"
        current = int(getattr(self, name, 0) or 0)
        setattr(self, name, max(0, current + delta))
        self._render_history_page(category)

    def _render_history_page(self, category: str) -> None:
        groups = list(getattr(self, f"_history_{category}_groups", []))
        list_widget = self.history_risk_list if category == "risk" else self.history_asset_list
        label = self.history_risk_page_label if category == "risk" else self.history_asset_page_label
        previous = self.history_risk_prev if category == "risk" else self.history_asset_prev
        following = self.history_risk_next if category == "risk" else self.history_asset_next
        list_widget.clear()
        page_size = 50
        pages = max(1, (len(groups) + page_size - 1) // page_size)
        page_name = f"_history_{category}_page"
        page = min(max(0, int(getattr(self, page_name, 0) or 0)), pages - 1)
        setattr(self, page_name, page)
        label.setText(f"共 {len(groups)} 项 · 第 {page + 1} / {pages} 页")
        previous.setEnabled(page > 0)
        following.setEnabled(page < pages - 1)
        for item in groups[page * page_size : (page + 1) * page_size]:
            if category == "risk":
                self._add_history_risk_item(item)
            else:
                self._add_history_asset_item(item)

    def _add_history_risk_item(self, item: HistoryRiskChangeItem) -> None:
        entry = QListWidgetItem()
        entry.setSizeHint(QSize(480, 58))
        self.history_risk_list.addItem(entry)
        card = QFrame()
        card.setObjectName("historyRow")
        layout = QHBoxLayout(card)
        layout.setContentsMargins(10, 6, 10, 6)
        layout.setSpacing(12)
        change = QLabel(item.change_status_label)
        change.setObjectName("historyChange")
        change.setFixedWidth(92)
        layout.addWidget(change)
        layout.addWidget(risk_badge(item.risk_level))
        title = QLabel(item.title)
        title.setObjectName("historyIssue")
        title.setWordWrap(False)
        layout.addWidget(title, 3)
        target = QLabel(f"{item.object_type_label} · {item.object_name}")
        target.setObjectName("mutedText")
        target.setWordWrap(False)
        layout.addWidget(target, 2)
        self.history_risk_list.setItemWidget(entry, card)

    def _populate_history_asset_changes(self) -> None:
        if not hasattr(self, "history_asset_list"):
            return
        self.history_asset_list.clear()
        comparison = self._history_comparison
        if comparison is None or comparison.state != "ready":
            return
        groups = []
        for key in ("new", "removed", "persistent"):
            groups.extend(comparison.asset_changes.get(key, []))
        self._history_asset_groups = groups
        if not groups:
            entry = QListWidgetItem("暂无资产变化。")
            entry.setSizeHint(QSize(420, 52))
            self.history_asset_list.addItem(entry)
            return
        self._render_history_page("asset")

    def _add_history_asset_item(self, item: HistoryAssetChangeItem) -> None:
        entry = QListWidgetItem()
        entry.setSizeHint(QSize(420, 56))
        self.history_asset_list.addItem(entry)
        card = QFrame()
        card.setObjectName("historyRow")
        layout = QHBoxLayout(card)
        layout.setContentsMargins(10, 6, 10, 6)
        layout.setSpacing(12)
        layout.addWidget(status_badge(self._history_asset_status_key(item.change_status), item.change_status_label))
        body = QLabel(f"{item.object_type_label} · {item.object_name}")
        body.setWordWrap(False)
        layout.addWidget(body, 2)
        location = QLabel(item.location or "未记录")
        location.setObjectName("mutedText")
        layout.addWidget(location, 3)
        self.history_asset_list.setItemWidget(entry, card)

    def _history_asset_status_key(self, status: str) -> str:
        return {"new": "success", "removed": "warning", "persistent": "info"}.get(status, "info")

    def _report_selection_changed(self) -> None:
        item = self._selected_report_item()
        if item is None:
            self.report_detail.setText("请选择左侧报告。")
            self.open_selected_report_button.setEnabled(False)
            self.open_selected_dir_button.setEnabled(False)
            self.report_copy_path_button.setEnabled(False)
            self.report_word_button.setEnabled(False)
            self.report_pdf_button.setEnabled(False)
            self.delete_report_button.setEnabled(False)
            return
        self.open_selected_report_button.setEnabled(bool(item.report_path))
        self.open_selected_report_button.setText("打开报告")
        self.open_selected_dir_button.setEnabled(item.report_dir.exists())
        self.report_copy_path_button.setEnabled(True)
        self.report_word_button.setEnabled(self._word_report_path_for_item(item) is not None)
        self.report_pdf_button.setEnabled(self._pdf_report_path_for_item(item) is not None)
        self.delete_report_button.setEnabled(True)
        if self._is_log_report_item(item):
            assets = item.asset_summary
            findings = "\n".join(f"- {text}" for text in item.top_risks[:5]) or "- 暂无诊断摘要"
            self.report_detail.setText(
                "\n".join(
                    [
                        f"报告标题：{item.title}",
                        f"客户名称：{item.customer_name}",
                        f"分析时间：{item.assessment_time or '暂无数据'}",
                        f"报告状态：{item.status}",
                        f"报告格式：{item.report_type}",
                        "",
                        f"日志文件：{assets.get('LogFile', 0)}",
                        f"关键证据：{assets.get('Evidence', 0)}",
                        f"待补充材料：{assets.get('Supplemental', 0)}",
                        f"建议处理项：{assets.get('Recommendation', 0)}",
                        "",
                        "诊断摘要：",
                        findings,
                        "",
                        f"说明：{item.history_summary}",
                        f"完整报告路径：{item.report_path or item.report_dir}",
                    ]
                )
            )
            return
        if self._is_upgrade_report_item(item):
            assets = item.asset_summary
            findings = "\n".join(f"- {text}" for text in item.top_risks[:5]) or "- 未发现阻塞项"
            self.report_detail.setText(
                "\n".join(
                    [
                        f"报告标题：{item.title}",
                        f"客户名称：{item.customer_name}",
                        f"检查范围：{item.site_name}",
                        f"检查时间：{item.assessment_time or '暂无数据'}",
                        f"报告状态：{item.status}",
                        f"报告格式：{item.report_type}",
                        "",
                        f"主机：{assets.get('Host', 0)} · 设备：{assets.get('Device', 0)} · 通过：{assets.get('Passed', 0)} · 阻塞：{assets.get('Failed', 0)} · 待核对：{assets.get('Unknown', 0)}",
                        "",
                        "阻塞与重点项：",
                        findings,
                        "",
                        f"说明：{item.history_summary}",
                        f"完整报告路径：{item.report_path or item.report_dir}",
                    ]
                )
            )
            return
        risk_total = actionable_risk_total(item.risk_summary)
        risks = " · ".join(f"{level} {item.risk_summary.get(level, 0)}" for level in ("P1", "P2", "P3"))
        optimization_total = int(item.risk_summary.get("P4", 0) or 0)
        assets = item.asset_summary
        top_risks = "\n".join(f"- {text}" for text in item.top_risks[:5]) or "- 暂无 TOP 风险"
        self.report_detail.setText(
            "\n".join(
                [
                    f"报告标题：{item.title}",
                    f"客户名称：{item.customer_name}",
                    f"评估时间：{item.assessment_time or '暂无数据'}",
                    f"报告状态：{item.status}",
                    f"报告格式：{item.report_type}",
                    "",
                    f"健康状态：{self.service._health_status(item.score if isinstance(item.score, (int, float)) else None, item.risk_summary)}",
                    f"风险摘要：{risks} · 总计 {risk_total} · 优化建议 {optimization_total}",
                    f"资产摘要：Host {assets.get('Host', 0)} · VM {assets.get('VM', 0)} · Datastore {assets.get('Datastore', 0)}",
                    "",
                    "TOP 风险：",
                    top_risks,
                    "",
                    f"历史对比摘要：{item.history_summary or '暂无历史对比摘要'}",
                    f"完整报告路径：{item.report_path or item.report_dir}",
                ]
            )
        )

    def _clear_layout(self, layout) -> None:
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()

    def _validate_rulepack(self) -> None:
        result = self.service.validate_rulepack(Path(self.rulepack_path_input.path_value() or DesktopInspectionConfig().rulepack_path))
        self.rulepack_status_label.setText("可用" if result.valid else "校验失败")
        self.rulepack_validation_result.setText(result.message)
        self.rulepack_validation_result.show()

    def _open_current_report(self) -> None:
        if not self.current_result:
            return
        if self.current_result.report_path.exists():
            self._open_path_safe(self.current_result.report_path)
            return
        QMessageBox.information(self, "HTML 报告未生成", self.current_result.html_error or "当前巡检未生成 HTML 报告。")

    def _open_current_word_report(self) -> None:
        if not self.current_result:
            return
        if self.current_result.docx_path and self.current_result.docx_path.exists():
            self._open_path_safe(self.current_result.docx_path)
            return
        QMessageBox.information(self, "Word 报告未生成", self.current_result.docx_error or "当前巡检未生成 Word 报告。")

    def _open_current_pdf_report(self) -> None:
        if not self.current_result:
            return
        if self.current_result.pdf_path and self.current_result.pdf_path.exists():
            self._open_path_safe(self.current_result.pdf_path)
            return
        QMessageBox.information(self, "PDF 报告未生成", self.current_result.pdf_error or "当前巡检未生成 PDF 报告。")

    def _open_current_report_dir(self) -> None:
        if self.current_result:
            self._open_path_safe(self.current_result.report_dir)

    def _open_current_log_html_report(self) -> None:
        if self.current_log_result:
            self._open_path_safe(self.current_log_result.html_path)

    def _open_current_log_word_report(self) -> None:
        if self.current_log_result:
            self._open_path_safe(self.current_log_result.docx_path)

    def _open_current_log_report_dir(self) -> None:
        if self.current_log_result:
            self._open_path_safe(self.current_log_result.report_dir)

    def _open_current_upgrade_html_report(self) -> None:
        if self.current_upgrade_result and self.current_upgrade_result.html_path:
            self._open_path_safe(self.current_upgrade_result.html_path)

    def _open_selected_history_report(self) -> None:
        item = self._selected_report_item()
        if item and item.report_path:
            self._open_path_safe(item.report_path)

    def _open_selected_word_report(self) -> None:
        item = self._selected_report_item()
        word_path = self._word_report_path_for_item(item) if item else None
        if word_path:
            self._open_path_safe(word_path)
            return
        QMessageBox.information(self, "Word 报告未生成", "当前报告目录中没有可打开的 Word 报告。")

    def _open_selected_pdf_report(self) -> None:
        item = self._selected_report_item()
        pdf_path = self._pdf_report_path_for_item(item) if item else None
        if pdf_path:
            self._open_path_safe(pdf_path)
            return
        QMessageBox.information(self, "PDF 报告未生成", "当前报告目录中没有可打开的 PDF 报告。")

    def _open_selected_history_dir(self) -> None:
        item = self._selected_report_item()
        if item:
            self._open_path_safe(item.report_dir)

    def _copy_selected_report_path(self) -> None:
        item = self._selected_report_item()
        if not item:
            return
        QApplication.clipboard().setText(str(item.report_path or item.report_dir))

    def _delete_selected_inspection_run(self) -> None:
        item = self._selected_report_item()
        if not item or not item.run_id or self._is_log_report_item(item):
            QMessageBox.information(self, "无法删除", "请选择一条健康巡检记录。日志分析报告不在此处删除。")
            return
        reply = QMessageBox.question(
            self,
            "删除巡检记录",
            "确认删除选中的健康巡检记录及对应报告目录？此操作不会删除程序、配置或其他巡检记录。",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        report_root = Path(self.default_report_dir_input.path_value() or self.report_dir_input.path_value() or DesktopInspectionConfig().report_output_dir)
        result = self.service.delete_inspection_run(self._db_path(), item.run_id, delete_report_files=True, report_output_dir=report_root)
        if result.deleted:
            QMessageBox.information(self, "删除完成", result.message)
            self._refresh_all_data()
            return
        QMessageBox.warning(self, "删除失败", result.message)

    def _remove_selected_report(self) -> None:
        item = self._selected_report_item()
        if item is None:
            return
        reply = QMessageBox.question(
            self,
            "从报告中心移除",
            "此操作仅隐藏当前报告中心条目，不会删除报告文件、巡检记录、风险历史或资产快照。确认移除吗？",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        if self.service.remove_report_center_item(self._db_path(), item):
            self._refresh_all_data()
            return
        QMessageBox.warning(self, "移除失败", "未能保存报告中心的隐藏状态，请稍后重试。")

    def _selected_report_item(self) -> ReportCenterItem | None:
        row = self.report_list.currentRow() if hasattr(self, "report_list") else -1
        if row < 0 or row >= len(self._report_items):
            return None
        return self._report_items[row]

    def _word_report_path_for_item(self, item: ReportCenterItem | None) -> Path | None:
        if item is None:
            return None
        if item.report_path and item.report_path.suffix.lower() == ".docx" and item.report_path.exists():
            return item.report_path
        for candidate in self._report_items:
            if candidate.report_path and candidate.report_path.suffix.lower() == ".docx" and candidate.report_dir == item.report_dir and candidate.report_path.exists():
                return candidate.report_path
        for candidate in item.report_dir.glob("*.docx"):
            if candidate.exists():
                return candidate
        return None

    def _pdf_report_path_for_item(self, item: ReportCenterItem | None) -> Path | None:
        if item is None:
            return None
        if item.report_path and item.report_path.suffix.lower() == ".pdf" and item.report_path.exists():
            return item.report_path
        for candidate in self._report_items:
            if candidate.report_path and candidate.report_path.suffix.lower() == ".pdf" and candidate.report_dir == item.report_dir and candidate.report_path.exists():
                return candidate.report_path
        direct = item.report_dir / "VStackLens-PDF-Report.pdf"
        return direct if direct.is_file() else None

    def _is_log_report_item(self, item: ReportCenterItem) -> bool:
        return item.report_type in {
            "日志分析 HTML 报告",
            "日志分析 Word 报告",
            "日志排查 HTML 报告",
            "日志排查 Word 报告",
            "日志粗排查 HTML 报告",
            "日志粗排查 Word 报告",
        }

    def _is_upgrade_report_item(self, item: ReportCenterItem) -> bool:
        return item.report_type == "升级兼容性 HTML 报告"

    def _selected_report_path(self, table: QTableWidget) -> Path | None:
        row = table.currentRow()
        if row < 0:
            return None
        item = table.item(row, min(5, table.columnCount() - 1))
        if item and item.data(Qt.UserRole):
            return Path(item.data(Qt.UserRole))
        if table.columnCount() > 6:
            item = table.item(row, 6)
            if item and item.text():
                return Path(item.text())
        return None

    def _open_path_safe(self, path: Path | None) -> None:
        if path is None:
            return
        try:
            target = Path(path)
            if target.is_dir():
                self.service.open_report_dir(target)
            elif target.suffix.casefold() == ".pdf":
                from vstacklens.desktop.pdf_reader import PdfReaderDialog

                PdfReaderDialog(target, self).exec()
            else:
                self.service.open_report(target)
        except Exception as exc:
            QMessageBox.warning(self, "打开失败", str(exc))

    def _open_runtime_log_dir(self) -> None:
        self._open_path_safe(runtime_log_path().parent)

    def _copy_runtime_log_path(self) -> None:
        QApplication.clipboard().setText(str(runtime_log_path()))
        QMessageBox.information(self, "日志路径", "日志路径已复制到剪贴板。")

    def _choose_report_dir(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "选择报告输出目录", self.report_dir_input.path_value() or ".")
        if path:
            self.report_dir_input.set_path_value(path)

    def _choose_log_bundle(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "选择 VMware support bundle 日志包", ".", "ZIP 日志包 (*.zip);;所有文件 (*)")
        if path:
            self.log_bundle_input.set_path_value(path)

    def _choose_log_report_dir(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "选择日志分析报告输出目录", self.log_report_dir_input.path_value() or ".")
        if path:
            self.log_report_dir_input.set_path_value(path)

    def _choose_upgrade_bundle(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "选择 VMware support bundle", ".", "Support bundle (*.zip *.tgz *.tar *.gz);;所有文件 (*)")
        if path:
            self.upgrade_bundle_input.set_path_value(path)

    def _choose_upgrade_report_dir(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "选择升级兼容性报告输出目录", self.upgrade_report_dir_input.path_value() or ".")
        if path:
            self.upgrade_report_dir_input.set_path_value(path)

    def _choose_default_report_dir(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "选择默认报告输出目录", self.default_report_dir_input.path_value() or ".")
        if path:
            self.default_report_dir_input.set_path_value(path)

    def _choose_rulepack_path(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "选择本地规则包目录", self.rulepack_path_input.path_value() or ".")
        if path:
            self.rulepack_path_input.set_path_value(path)

    def _choose_db_path(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            "选择 SQLite 数据库",
            self.db_path_input.path_value() or str(DesktopInspectionConfig().db_path),
            "SQLite DB (*.db);;All Files (*)",
        )
        if path:
            self.db_path_input.set_path_value(path)

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt override name.
        if self._running and self.worker is not None and self.worker.isRunning():
            reply = QMessageBox.question(
                self,
                "健康评估仍在运行",
                "健康评估任务仍在运行。关闭窗口可能中断当前桌面会话，确认关闭吗？",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if reply != QMessageBox.Yes:
                event.ignore()
                return
            self.status_label.setText("已请求取消，正在等待当前步骤结束。")
            self.stage_label.setText("正在取消巡检")
            self.worker.request_cancel()
            if not self.worker.wait(3000):
                event.ignore()
                return
        event.accept()


def main() -> None:
    log_path = configure_runtime_logging()
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon(str(app_icon_path())))
    configure_chinese_font(app)
    service = InspectionService()
    config = service.initialize_local_workspace()
    LOGGER.info(
        "Desktop startup version=%s config_path=%s db_path=%s report_dir=%s log_path=%s runtime_mode=%s executable=%s",
        APP_VERSION,
        service.config_path,
        config.db_path,
        config.report_output_dir,
        log_path,
        runtime_mode(),
        sys.executable,
    )
    login = LoginWindow()
    if login.exec() != QDialog.Accepted or not login.authenticated:
        sys.exit(0)
    window = MainWindow(service=service, auth_service=login.auth_service, current_username=login.logged_in_username)
    window.show()
    QTimer.singleShot(0, window.show_default_password_warning_if_needed)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
