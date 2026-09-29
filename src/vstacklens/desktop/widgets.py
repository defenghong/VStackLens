from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen, QWheelEvent
from PySide6.QtWidgets import QComboBox, QFrame, QGraphicsDropShadowEffect, QGridLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QSizePolicy, QVBoxLayout, QWidget


STATUS_LABELS = {
    "available": "可用",
    "enabled": "已启用",
    "planned": "预留",
    "global": "入口",
    "success": "成功",
    "failed": "失败",
    "offline": "离线",
    "unknown": "未知",
    "danger": "异常",
    "warning": "关注",
    "info": "信息",
}

RISK_COLORS = {
    "P1": "#EF4444",
    "P2": "#F59E0B",
    "P3": "#3B82F6",
    "P4": "#9CA3AF",
}


def _apply_card_shadow(widget: QWidget) -> None:
    shadow = QGraphicsDropShadowEffect(widget)
    shadow.setBlurRadius(18)
    shadow.setOffset(0, 4)
    shadow.setColor(QColor(0, 0, 0, 52))
    widget.setGraphicsEffect(shadow)


def status_badge(status: str, text: str | None = None) -> QLabel:
    label = QLabel(text or STATUS_LABELS.get(status, status))
    label.setProperty("badge", True)
    label.setProperty("status", status)
    label.setAlignment(Qt.AlignCenter)
    return label


def muted_label(text: str, *, word_wrap: bool = True) -> QLabel:
    label = QLabel(text)
    label.setObjectName("mutedText")
    label.setWordWrap(word_wrap)
    return label


class NoWheelComboBox(QComboBox):
    """Require an explicit click or keyboard action to change a selection."""

    def wheelEvent(self, event: QWheelEvent) -> None:  # noqa: N802 - Qt override name.
        event.ignore()


class PageHeader(QWidget):
    def __init__(self, title: str, subtitle: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5)
        title_label = QLabel(title)
        title_label.setObjectName("pageTitle")
        layout.addWidget(title_label)
        if subtitle:
            subtitle_label = QLabel(subtitle)
            subtitle_label.setObjectName("pageSubtitle")
            subtitle_label.setWordWrap(True)
            layout.addWidget(subtitle_label)


class SectionCard(QFrame):
    def __init__(self, title: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("sectionCard")
        _apply_card_shadow(self)
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(18, 16, 18, 18)
        self.layout.setSpacing(12)
        self.layout.setAlignment(Qt.AlignTop)
        if title:
            title_label = QLabel(title)
            title_label.setObjectName("sectionTitle")
            self.layout.addWidget(title_label)


class InfoCard(QFrame):
    def __init__(
        self,
        title: str,
        description: str = "",
        *,
        status: str | None = None,
        details: list[tuple[str, str]] | None = None,
        button_text: str | None = None,
        on_click: Callable[[], None] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("moduleCard")
        _apply_card_shadow(self)
        self._on_click = on_click
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        top = QHBoxLayout()
        title_label = QLabel(title)
        title_label.setObjectName("cardTitle")
        top.addWidget(title_label, 1)
        if status:
            top.addWidget(status_badge(status))
        layout.addLayout(top)

        if description:
            desc = QLabel(description)
            desc.setObjectName("cardDescription")
            desc.setWordWrap(True)
            layout.addWidget(desc)

        if details:
            grid = QGridLayout()
            grid.setHorizontalSpacing(12)
            grid.setVerticalSpacing(6)
            for row, (name, value) in enumerate(details):
                key = QLabel(name)
                key.setObjectName("mutedText")
                val = QLabel(value)
                val.setWordWrap(True)
                grid.addWidget(key, row, 0)
                grid.addWidget(val, row, 1)
            grid.setColumnStretch(1, 1)
            layout.addLayout(grid)

        layout.addStretch(1)
        if button_text:
            button = QPushButton(button_text)
            button.setObjectName("primaryButton")
            if on_click:
                button.clicked.connect(on_click)
            layout.addWidget(button, alignment=Qt.AlignRight)

    def mousePressEvent(self, event) -> None:  # noqa: N802 - Qt override name.
        if self._on_click and event.button() == Qt.LeftButton:
            self._on_click()
        super().mousePressEvent(event)


class MetricCard(QFrame):
    def __init__(self, title: str, value: str, subtitle: str = "", status: str | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("sectionCard")
        _apply_card_shadow(self)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(8)
        top = QHBoxLayout()
        title_label = QLabel(title)
        title_label.setObjectName("mutedText")
        top.addWidget(title_label, 1)
        if status:
            top.addWidget(status_badge(status))
        layout.addLayout(top)
        value_label = QLabel(value)
        value_label.setObjectName("metricValue")
        layout.addWidget(value_label)
        if subtitle:
            layout.addWidget(muted_label(subtitle))
        layout.addStretch(1)


class EmptyState(QFrame):
    def __init__(
        self,
        title: str,
        description: str,
        *,
        button_text: str | None = None,
        on_click: Callable[[], None] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("sectionCard")
        _apply_card_shadow(self)
        self.setMinimumSize(360, 150)
        self.setMaximumWidth(560)
        self.setMaximumHeight(220)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(10)
        title_label = QLabel(title)
        title_label.setObjectName("sectionTitle")
        desc = muted_label(description)
        layout.addWidget(title_label)
        layout.addWidget(desc)
        if button_text:
            button = QPushButton(button_text)
            button.setObjectName("primaryButton")
            if on_click:
                button.clicked.connect(on_click)
            layout.addWidget(button, alignment=Qt.AlignLeft)
        layout.addStretch(1)


class PathLineEdit(QLineEdit):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._full_value = ""

    def set_path_value(self, value: str) -> None:
        self._full_value = value
        self.setToolTip(value)
        self._show_elided()

    def path_value(self) -> str:
        if self.hasFocus():
            return self.text()
        return self._full_value or self.text()

    def focusInEvent(self, event) -> None:  # noqa: N802 - Qt override name.
        if self._full_value:
            self.setText(self._full_value)
        super().focusInEvent(event)

    def focusOutEvent(self, event) -> None:  # noqa: N802 - Qt override name.
        self._full_value = self.text()
        self.setToolTip(self._full_value)
        self._show_elided()
        super().focusOutEvent(event)

    def resizeEvent(self, event) -> None:  # noqa: N802 - Qt override name.
        super().resizeEvent(event)
        if not self.hasFocus():
            self._show_elided()

    def _show_elided(self) -> None:
        if not self._full_value:
            self.setText("")
            return
        text = self.fontMetrics().elidedText(self._full_value, Qt.ElideMiddle, max(40, self.width() - 16))
        self.setText(text)


class HealthScoreRing(QWidget):
    def __init__(self, score: float | None = None, status: str = "暂无数据", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.score = score
        self.status = status
        self.setMinimumSize(300, 300)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

    def set_score(self, score: float | None, status: str) -> None:
        self.score = score
        self.status = status
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802 - Qt override name.
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        side = max(180, min(self.width(), self.height()) - 40)
        x = (self.width() - side) / 2
        y = (self.height() - side) / 2
        rect = QRectF(x, y, side, side)
        painter.setPen(QPen(QColor("#1F2937"), 22, Qt.SolidLine, Qt.RoundCap))
        painter.drawArc(rect, 0, 360 * 16)
        score = max(0, min(100, float(self.score or 0)))
        color = QColor({"健康": "#10B981", "正常": "#3B82F6", "关注": "#F59E0B", "危险": "#EF4444"}.get(self.status, "#64748B"))
        if self.score is None:
            color = QColor("#3B82F6")
        painter.setPen(QPen(color, 22, Qt.SolidLine, Qt.RoundCap))
        painter.drawArc(rect, 90 * 16, -360 * 16)
        painter.setPen(QColor("#F3F4F6"))
        value_font = QFont(painter.font())
        value_font.setPointSize(28)
        value_font.setBold(True)
        painter.setFont(value_font)
        value = self.status
        painter.drawText(rect.adjusted(0, -18, 0, 0), Qt.AlignCenter, value)
        painter.setPen(QColor("#9CA3AF"))
        status_font = QFont(painter.font())
        status_font.setPointSize(12)
        status_font.setBold(False)
        painter.setFont(status_font)
        painter.drawText(rect.adjusted(0, side * 0.24, 0, 0), Qt.AlignCenter, "环境健康状态")


class RiskTrendChart(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._points: list[dict] = []
        self.setMinimumHeight(190)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

    def set_data(self, points: list[dict]) -> None:
        self._points = points
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802 - Qt override name.
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        area = self.rect().adjusted(12, 12, -12, -28)
        painter.setPen(QPen(QColor("#1F2937"), 1))
        for step in range(5):
            y = area.top() + area.height() * step / 4
            painter.drawLine(area.left(), int(y), area.right(), int(y))
        painter.setPen(QColor("#9CA3AF"))
        painter.drawText(self.rect().adjusted(12, self.height() - 24, -12, 0), Qt.AlignLeft, "过去 30 天风险趋势")
        if not self._points:
            painter.setPen(QColor("#9CA3AF"))
            painter.drawText(area, Qt.AlignCenter, "暂无趋势数据")
            return
        values = [int(item.get("risk_total") or 0) for item in self._points]
        maximum = max(max(values), 1)
        if len(values) == 1:
            values = [values[0], values[0]]
        chart_points: list[QPointF] = []
        for index, value in enumerate(values):
            x = area.left() + (area.width() * index / max(1, len(values) - 1))
            y = area.bottom() - (area.height() * value / maximum)
            chart_points.append(QPointF(x, y))
        fill_path = QPainterPath()
        fill_path.moveTo(chart_points[0].x(), area.bottom())
        for point in chart_points:
            fill_path.lineTo(point)
        fill_path.lineTo(chart_points[-1].x(), area.bottom())
        fill_path.closeSubpath()
        painter.fillPath(fill_path, QColor(59, 130, 246, 42))
        line_path = QPainterPath(chart_points[0])
        for point in chart_points[1:]:
            line_path.lineTo(point)
        painter.setPen(QPen(QColor("#3B82F6"), 3, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
        painter.drawPath(line_path)
        painter.setBrush(QColor("#10B981"))
        painter.setPen(QPen(QColor("#0B1220"), 2))
        for point in chart_points:
            painter.drawEllipse(point, 4, 4)


def risk_badge(level: str) -> QLabel:
    label = QLabel("优化建议" if level == "P4" else level)
    label.setProperty("badge", True)
    status = "danger" if level == "P1" else "warning" if level == "P2" else "info" if level == "P3" else "global"
    label.setProperty("status", status)
    label.setAlignment(Qt.AlignCenter)
    return label
