from __future__ import annotations

from vstacklens.desktop.theme import COLORS, color_with_alpha

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import QWidget


class ProductLogo(QWidget):
    """Compact layered-resource mark used by the local desktop login."""

    def paintEvent(self, event) -> None:  # noqa: N802 - Qt override name.
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        width = max(self.width(), 1)
        height = max(self.height(), 1)
        center_x = width / 2
        top = max(4.0, (height - 64) / 2)
        for offset, color in (
            (0.0, QColor(COLORS["subtext"])),
            (12.0, QColor(COLORS["subtext"])),
            (24.0, QColor(COLORS["subtext"])),
        ):
            rect = QRectF(center_x - 34 + offset * 0.18, top + offset, 68, 19)
            painter.setBrush(QColor(color_with_alpha("subtext", 0)))
            painter.setPen(QPen(color, 2))
            painter.drawRoundedRect(rect, 2, 2)
            painter.setPen(QPen(color, 1))
            painter.drawLine(rect.left() + 12, rect.center().y(), rect.right() - 12, rect.center().y())
        aperture = QRectF(center_x - 14, top + 15, 28, 28)
        painter.setBrush(QColor(COLORS["background"]))
        painter.setPen(QPen(QColor(COLORS["subtext"]), 2.5))
        painter.drawEllipse(aperture)
        painter.setBrush(QColor(COLORS["subtext"]))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(QRectF(center_x - 4, top + 25, 8, 8))
        painter.end()
