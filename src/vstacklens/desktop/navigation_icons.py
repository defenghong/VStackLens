"""Theme-aware navigation line icons drawn from bundled SVG strings."""
from PySide6.QtCore import Qt, QRectF
from PySide6.QtGui import QColor, QIcon, QPainter, QPixmap, QFont, QFontMetrics
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import QStyledItemDelegate, QStyle
from vstacklens.desktop.theme import COLORS, TYPOGRAPHY, SIZES

PATHS = {
    "dashboard": '<path d="M3 11 12 3l9 8M5 10v11h5v-7h4v7h5V10"/>',
    "vcenter_management": '<rect x="3" y="3" width="18" height="7" rx="1"/><rect x="3" y="14" width="18" height="7" rx="1"/><path d="M6 6h1m-1 11h1M15 6h3m-3 11h3"/>',
    "inspection_center": '<path d="M9 5H4v16h16V5h-5M8 12l3 3 5-6"/><rect x="9" y="2" width="6" height="5" rx="1"/>',
    "risk_center": '<path d="M12 3 2 21h20L12 3Zm0 6v5m0 3v1"/>',
    "asset_center": '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 4 18 4 18 0V5M3 12c0 4 18 4 18 0"/>',
    "history_compare": '<path d="M4 21V12m8 9V3m8 18V8"/>',
    "report_center": '<path d="M4 2h10l6 6v14H4V2Zm10 0v6h6M8 12h8m-8 4h8"/>',
    "log_analysis": '<circle cx="10" cy="10" r="7"/><path d="m15 15 7 7"/>',
    "upgrade_compat": '<path d="M15 3a6 6 0 0 0-8 8l-5 6a3 3 0 0 0 5 5l6-6a6 6 0 0 0 8-8l-5 5-4-4 3-6Z"/>',
    "settings": '<path d="m9 2-1 4-4 1-2 4 3 3-1 4 4 3 4-2 4 2 4-3-1-4 3-3-2-4-4-1-1-4H9Z"/><circle cx="12" cy="12" r="3"/>',
    "license": '<circle cx="12" cy="12" r="10"/><path d="M12 10v8m0-12v1"/>',
}

def navigation_icon(module, selected=False, size=None):
    size = size or SIZES["navigation_icon"]
    color = COLORS["text" if selected else "subtext"]
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">{PATHS[module]}</svg>'
    pixmap = QPixmap(size * 2, size * 2); pixmap.setDevicePixelRatio(2); pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap); QSvgRenderer(svg.encode()).render(painter, QRectF(0, 0, size, size)); painter.end()
    return QIcon(pixmap)

def group_geometry(font, first=False):
    font = QFont(font); font.setPixelSize(TYPOGRAPHY["navigation_group"])
    text_height = QFontMetrics(font).height()
    line_y = None if first else SIZES["navigation_line_top_gap"]
    text_top = 4 if first else SIZES["navigation_line_top_gap"] + 9
    return font, line_y, text_top, text_height, text_top + text_height + 4

class NavigationDelegate(QStyledItemDelegate):
    def paint(self, painter, option, index):
        module = index.data(Qt.UserRole)
        if not module:
            if not index.data(Qt.DisplayRole):return
            first = index.data(Qt.DisplayRole) == "主要工作"
            font, line_y, text_top, text_height, _ = group_geometry(option.font, first)
            painter.save()
            if line_y is not None:
                painter.setPen(QColor(COLORS["divider"]))
                y = option.rect.top() + line_y
                painter.drawLine(option.rect.left(), y, option.rect.right(), y)
            painter.setFont(font); painter.setPen(QColor(COLORS["subtext"]))
            rect = QRectF(option.rect.left(), option.rect.top()+text_top, option.rect.width(), text_height)
            painter.drawText(rect, Qt.AlignLeft | Qt.AlignTop, str(index.data(Qt.DisplayRole)))
            painter.restore()
            return
        selected = bool(option.state & QStyle.State_Selected)
        painter.save(); painter.setRenderHint(QPainter.Antialiasing)
        if selected or option.state & QStyle.State_MouseOver:
            painter.setPen(Qt.NoPen); painter.setBrush(QColor(COLORS["selection" if selected else "hover"]))
            painter.drawRoundedRect(option.rect, 2, 2)
        size = SIZES["navigation_icon"]; icon_x = option.rect.x() + 12
        icon = index.data(Qt.DecorationRole)
        if icon: icon.paint(painter, icon_x, option.rect.y()+(option.rect.height()-size)//2, size, size)
        font = option.font; font.setPixelSize(TYPOGRAPHY["navigation"]); font.setBold(selected)
        painter.setFont(font); painter.setPen(QColor(COLORS["text"]))
        rect = option.rect.adjusted(12 + size + SIZES["navigation_icon_gap"], 0, -6, 0)
        painter.drawText(rect, Qt.AlignLeft | Qt.AlignVCenter, str(index.data(Qt.DisplayRole)))
        painter.restore()
