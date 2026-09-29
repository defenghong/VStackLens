from __future__ import annotations

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
            (0.0, QColor("#2867D8")),
            (12.0, QColor("#3F80F2")),
            (24.0, QColor("#64A0FF")),
        ):
            rect = QRectF(center_x - 34 + offset * 0.18, top + offset, 68, 19)
            painter.setBrush(QColor(color.red(), color.green(), color.blue(), 34))
            painter.setPen(QPen(color, 2))
            painter.drawRoundedRect(rect, 6, 6)
            painter.setPen(QPen(color, 1))
            painter.drawLine(rect.left() + 12, rect.center().y(), rect.right() - 12, rect.center().y())
        aperture = QRectF(center_x - 14, top + 15, 28, 28)
        painter.setBrush(QColor("#0C1626"))
        painter.setPen(QPen(QColor("#31C48D"), 2.5))
        painter.drawEllipse(aperture)
        painter.setBrush(QColor("#31C48D"))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(QRectF(center_x - 4, top + 25, 8, 8))
        painter.end()
