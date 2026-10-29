from __future__ import annotations

from collections.abc import Callable, Mapping

from vstacklens.desktop.theme import COLORS, STATUS_COLORS, color_with_alpha, TYPOGRAPHY, SIZES

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen, QWheelEvent, QBrush
from PySide6.QtWidgets import QApplication, QComboBox, QFrame, QGridLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QSizePolicy, QVBoxLayout, QWidget, QStyledItemDelegate, QStyleOptionViewItem, QStyle, QProxyStyle, QStyleFactory


class CommonControlStyle(QProxyStyle):
    """Keep Qt's controls and input behavior, with theme-aware indicators."""

    def drawPrimitive(self, element, option, painter, widget=None):
        if element not in (QStyle.PE_IndicatorCheckBox, QStyle.PE_IndicatorRadioButton):
            return super().drawPrimitive(element, option, painter, widget)
        enabled = bool(option.state & QStyle.State_Enabled)
        selected = bool(option.state & (QStyle.State_On | QStyle.State_NoChange))
        color = COLORS["primary"] if enabled and selected else COLORS["subtext"]
        # Paint in logical coordinates; Qt scales these paths for the display.
        edge = min(option.rect.width(), option.rect.height(), 17)
        rect = QRectF(option.rect.center().x() - edge / 2 + .5,
                      option.rect.center().y() - edge / 2 + .5, edge - 1, edge - 1)
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(QPen(QColor(color), 1.25))
        if element == QStyle.PE_IndicatorCheckBox:
            painter.setBrush(QColor(color if selected else COLORS["surface"]))
            painter.drawRoundedRect(rect, 2, 2)
            if selected:
                painter.setPen(QPen(QColor(COLORS["button_text"]), 1.8, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
                if option.state & QStyle.State_NoChange:
                    painter.drawLine(rect.topLeft() + QPointF(4, 8), rect.topLeft() + QPointF(12, 8))
                else:
                    path = QPainterPath(rect.topLeft() + QPointF(3.5, 8))
                    path.lineTo(rect.topLeft() + QPointF(6.7, 11.2))
                    path.lineTo(rect.topLeft() + QPointF(12.5, 4.7))
                    painter.drawPath(path)
        else:
            painter.setBrush(QColor(COLORS["surface"]))
            painter.drawEllipse(rect)
            if selected:
                painter.setPen(Qt.NoPen)
                painter.setBrush(QColor(color))
                painter.drawEllipse(rect.center(), 4, 4)
        painter.restore()


def ensure_common_control_style(app):
    """Install once, without giving the proxy ownership of QApplication.style()."""
    if getattr(app, "_vstacklens_control_style", None) is not None:
        return
    # A newly created base belongs only to the proxy. Passing app.style() here
    # would transfer Qt's existing global style and risk deleting it on teardown.
    base = QStyleFactory.create(app.style().objectName())
    if base is None:
        base = QStyleFactory.create("Fusion")
    app._vstacklens_control_style = CommonControlStyle(base)
    app.setStyle(app._vstacklens_control_style)

class RowSeparatorDelegate(QStyledItemDelegate):
    def paint(self, painter, option, index):
        flat_option = QStyleOptionViewItem(option)
        self.initStyleOption(flat_option,index)
        if flat_option.state & QStyle.State_Selected:
            painter.fillRect(option.rect,QColor(COLORS["selection"]))
            flat_option.backgroundBrush=QBrush(QColor(COLORS["selection"]))
        flat_option.state &= ~(QStyle.State_HasFocus | QStyle.State_Selected)
        flat_option.rect = option.rect.adjusted(SIZES["cell_padding"],0,-SIZES["cell_padding"],0)
        style=option.widget.style() if option.widget else QApplication.style()
        painter.save();painter.setClipRect(option.rect,Qt.IntersectClip)
        style.drawControl(QStyle.CE_ItemViewItem,flat_option,painter,option.widget);painter.restore()
        painter.save(); painter.setPen(QPen(QColor(COLORS["border"]), 1))
        painter.drawLine(option.rect.bottomLeft(), option.rect.bottomRight()); painter.restore()

    def sizeHint(self, option, index):
        padded = QStyleOptionViewItem(option)
        padded.rect=option.rect.adjusted(SIZES["cell_padding"],0,-SIZES["cell_padding"],0)
        return super().sizeHint(padded,index)


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

class RiskColors(Mapping):
    def __getitem__(self, level):
        if level not in ("P1", "P2", "P3", "P4"):
            raise KeyError(level)
        return COLORS[level]

    def __iter__(self):
        return iter(("P1", "P2", "P3", "P4"))

    def __len__(self):
        return 4


RISK_COLORS = RiskColors()


class StatusBadge(QLabel):
    """Paint a small status dot without changing the underlying status text."""

    def __init__(self, text: str) -> None:
        super().__init__(text)
        self.setContentsMargins(12, 0, 0, 0)

    def paintEvent(self, event) -> None:
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(COLORS["subtext"] if self.property("zero") else STATUS_COLORS.get(self.property("status"), COLORS["subtext"])))
        painter.drawEllipse(QPointF(5, self.height() / 2), SIZES["status_dot_radius"], SIZES["status_dot_radius"])


class MetricValueLabel(QLabel):
    """Keep zero counts visually quiet, including after data refreshes."""

    def __init__(self, text: str = "") -> None:
        super().__init__()
        self.setText(text)

    def setText(self, text: str) -> None:
        super().setText(text)
        self.setProperty("zero", text.strip() in {"0", "0.0", "+0", "-0"})
        self.style().unpolish(self)
        self.style().polish(self)



def status_badge(status: str, text: str | None = None) -> QLabel:
    label = StatusBadge(text or STATUS_LABELS.get(status, status))
    label.setProperty("badgeType", "status")
    label.setProperty("badge", True)
    label.setProperty("status", status)
    label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
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

    def paintEvent(self, event):
        super().paintEvent(event)
        painter=QPainter(self); painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(QPen(QColor(COLORS["text"]), 1.5))
        x=self.width()-17; y=self.height()/2
        painter.drawLine(QPointF(x-4,y-2),QPointF(x,y+2)); painter.drawLine(QPointF(x,y+2),QPointF(x+4,y-2))


class PageHeader(QWidget):
    def __init__(self, title: str, subtitle: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5)
        title_label = QLabel(title)
        title_label.setObjectName("pageTitle")
        self.title_row = QHBoxLayout()
        self.title_row.setSpacing(SIZES["card_gap"])
        self.title_strip=QFrame(); self.title_strip.setObjectName("titleStrip")
        self.title_strip.setFixedSize(SIZES["title_strip_width"],SIZES["title_strip_height"])
        self.title_row.addWidget(self.title_strip,alignment=Qt.AlignVCenter)
        self.title_label = title_label
        self.title_row.addWidget(title_label, alignment=Qt.AlignBaseline)
        self.subtitle_label = QLabel(subtitle)
        self.subtitle_label.setObjectName("pageSubtitle")
        self.subtitle_label.setWordWrap(True)
        self.subtitle_label.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self.subtitle_label.setVisible(bool(subtitle))
        self.title_row.addWidget(self.subtitle_label, 1, Qt.AlignBaseline)
        self.title_row.addStretch(1)
        layout.addLayout(self.title_row)

    def set_subtitle(self, text):
        self.subtitle_label.setText(text); self.subtitle_label.setVisible(bool(text))

    def add_action(self, action):
        self.title_row.addWidget(action)


class SectionCard(QFrame):
    def __init__(self, title: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("sectionCard")
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(*([SIZES["card_padding"]] * 4))
        self.layout.setSpacing(SIZES["card_gap"])
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
        self._on_click = on_click
        layout = QVBoxLayout(self)
        layout.setContentsMargins(*([SIZES["card_padding"]] * 4))
        layout.setSpacing(SIZES["card_gap"])

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
            button.setObjectName("secondaryButton")
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
        layout = QVBoxLayout(self)
        layout.setContentsMargins(*([SIZES["card_padding"]] * 4))
        layout.setSpacing(SIZES["card_gap"])
        top = QHBoxLayout()
        title_label = QLabel(title)
        title_label.setObjectName("mutedText")
        top.addWidget(title_label, 1)
        if status:
            top.addWidget(status_badge(status))
        layout.addLayout(top)
        value_label = MetricValueLabel(value)
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
        self.setMinimumSize(360, 150)
        self.setMaximumWidth(560)
        self.setMaximumHeight(220)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(*([SIZES["card_padding"]] * 4))
        layout.setSpacing(SIZES["card_gap"])
        title_label = QLabel(title)
        title_label.setObjectName("sectionTitle")
        desc = muted_label(description)
        layout.addWidget(title_label)
        layout.addWidget(desc)
        if button_text:
            button = QPushButton(button_text)
            button.setObjectName("secondaryButton")
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
        painter.setPen(QPen(QColor(COLORS["border"]), 22, Qt.SolidLine, Qt.RoundCap))
        painter.drawArc(rect, 0, 360 * 16)
        score = max(0, min(100, float(self.score or 0)))
        color = QColor({"健康": COLORS["success"], "正常": COLORS["P3"], "关注": COLORS["warning"], "危险": COLORS["danger"]}.get(self.status, COLORS["subtext"]))
        if self.score is None:
            color = QColor(COLORS["P3"])
        painter.setPen(QPen(color, 22, Qt.SolidLine, Qt.RoundCap))
        painter.drawArc(rect, 90 * 16, -360 * 16)
        painter.setPen(QColor(COLORS["text"]))
        value_font = QFont(painter.font())
        value_font.setPixelSize(TYPOGRAPHY["health"])
        value_font.setBold(True)
        painter.setFont(value_font)
        value = self.status
        painter.drawText(rect.adjusted(0, -18, 0, 0), Qt.AlignCenter, value)
        painter.setPen(QColor(COLORS["subtext"]))
        status_font = QFont(painter.font())
        status_font.setPixelSize(TYPOGRAPHY["secondary"])
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
        painter.setPen(QPen(QColor(COLORS["border"]), 1))
        for step in range(5):
            y = area.top() + area.height() * step / 4
            painter.drawLine(area.left(), int(y), area.right(), int(y))
        painter.setPen(QColor(COLORS["subtext"]))
        painter.drawText(self.rect().adjusted(12, self.height() - 24, -12, 0), Qt.AlignLeft, "过去 30 天风险趋势")
        if not self._points:
            painter.setPen(QColor(COLORS["subtext"]))
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
        painter.fillPath(fill_path, QColor(color_with_alpha("P3", 42)))
        line_path = QPainterPath(chart_points[0])
        for point in chart_points[1:]:
            line_path.lineTo(point)
        painter.setPen(QPen(QColor(COLORS["P3"]), 3, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
        painter.drawPath(line_path)
        painter.setBrush(QColor(COLORS["success"]))
        painter.setPen(QPen(QColor(COLORS["background"]), 2))
        for point in chart_points:
            painter.drawEllipse(point, 4, 4)


def risk_badge(level: str) -> QLabel:
    label = QLabel("优化建议" if level == "P4" else level)
    label.setProperty("badge", True)
    label.setProperty("badgeType", "risk")
    label.setProperty("riskLevel", level)
    status = "danger" if level == "P1" else "warning" if level == "P2" else "info" if level == "P3" else "global"
    label.setProperty("status", status)
    label.setAlignment(Qt.AlignCenter)
    label.setFixedSize(SIZES["badge_width"] if level != "P4" else SIZES["badge_width"] + 36, SIZES["badge_height"])
    return label

class NumberSummary(QWidget):
    """Two supplied customer-caliber totals, without deriving new counts."""
    def __init__(self):
        super().__init__()
        self.setObjectName("numberSummary")
        layout = QHBoxLayout(self); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(SIZES["number_group_gap"])
        self.values = []
        self.groups=[];self.captions=[]
        for caption in ("类问题", "个涉及对象"):
            wrapper=QWidget(); wrapper.setObjectName("inlineNumberGroup");wrapper.setSizePolicy(QSizePolicy.Maximum,QSizePolicy.Preferred)
            group = QHBoxLayout(wrapper); group.setContentsMargins(0,0,0,0); group.setSpacing(SIZES["number_pair_gap"])
            value = QLabel("—"); value.setObjectName("largeNumber")
            label = QLabel(caption); label.setObjectName("numberCaption")
            value.setSizePolicy(QSizePolicy.Maximum,QSizePolicy.Preferred);label.setSizePolicy(QSizePolicy.Maximum,QSizePolicy.Preferred)
            group.addWidget(value, alignment=Qt.AlignBaseline); group.addWidget(label, alignment=Qt.AlignBaseline)
            layout.addWidget(wrapper); self.values.append(value);self.captions.append(label);self.groups.append(wrapper)
        layout.addStretch(1)

    def set_counts(self, problems, objects):
        for label, value in zip(self.values, (problems, objects)): label.setText("—" if value is None or value == "" else str(value))

    def text(self):
        return f"{self.values[0].text()} 类问题 · {self.values[1].text()} 个涉及对象"


class ElidingLabel(QLabel):
    """One visible line; the original text remains selectable and in its tooltip."""
    def __init__(self, text="", parent=None):
        super().__init__(text,parent)
        self.setMinimumWidth(0);self.setSizePolicy(QSizePolicy.Ignored,QSizePolicy.Preferred)
    def setText(self,text):
        super().setText(text)
        from PySide6.QtGui import QTextDocument
        doc=QTextDocument();doc.setHtml(text)
        self.setToolTip(doc.toPlainText())
        self.update()
    def paintEvent(self,event):
        from PySide6.QtGui import QTextDocument
        doc=QTextDocument();doc.setHtml(self.text())
        painter=QPainter(self);painter.setPen(self.palette().windowText().color());painter.setFont(self.font())
        painter.drawText(self.contentsRect(),Qt.AlignLeft|Qt.AlignVCenter,self.fontMetrics().elidedText(doc.toPlainText(),Qt.ElideRight,self.contentsRect().width()))
