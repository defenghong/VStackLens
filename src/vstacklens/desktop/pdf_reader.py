from __future__ import annotations

from pathlib import Path

import pymupdf
from PySide6.QtCore import Qt
from PySide6.QtGui import QImage, QPixmap
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
)


class PdfReaderDialog(QDialog):
    """Small read-only PDF viewer for customer reports, independent of browser associations."""

    def __init__(self, pdf_path: Path, parent=None) -> None:
        super().__init__(parent)
        self.pdf_path = Path(pdf_path)
        self.document = pymupdf.open(self.pdf_path)
        if self.document.page_count < 1:
            self.document.close()
            raise ValueError("PDF 报告没有可显示的页面。")
        self.page_index = 0
        self.zoom = 1.25
        self.setWindowTitle(f"PDF 阅读器 - {self.pdf_path.name}")
        self.resize(1120, 860)

        root = QVBoxLayout(self)
        toolbar = QHBoxLayout()
        self.previous_button = QPushButton("上一页")
        self.next_button = QPushButton("下一页")
        self.page_label = QLabel()
        self.page_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.zoom_out_button = QPushButton("缩小")
        self.zoom_in_button = QPushButton("放大")
        self.previous_button.clicked.connect(lambda: self._change_page(-1))
        self.next_button.clicked.connect(lambda: self._change_page(1))
        self.zoom_out_button.clicked.connect(lambda: self._change_zoom(-0.15))
        self.zoom_in_button.clicked.connect(lambda: self._change_zoom(0.15))
        for widget in (self.previous_button, self.next_button, self.page_label):
            toolbar.addWidget(widget)
        toolbar.addStretch(1)
        toolbar.addWidget(self.zoom_out_button)
        toolbar.addWidget(self.zoom_in_button)
        root.addLayout(toolbar)

        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(False)
        self.scroll_area.setAlignment(Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop)
        self.page_image = QLabel()
        self.page_image.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.scroll_area.setWidget(self.page_image)
        root.addWidget(self.scroll_area, 1)
        self._render_page()

    def _change_page(self, offset: int) -> None:
        self.page_index = min(max(self.page_index + offset, 0), self.document.page_count - 1)
        self._render_page()

    def _change_zoom(self, delta: float) -> None:
        self.zoom = min(max(self.zoom + delta, 0.65), 2.5)
        self._render_page()

    def _render_page(self) -> None:
        page = self.document.load_page(self.page_index)
        pixmap = page.get_pixmap(matrix=pymupdf.Matrix(self.zoom, self.zoom), alpha=False)
        image = QImage(
            pixmap.samples,
            pixmap.width,
            pixmap.height,
            pixmap.stride,
            QImage.Format.Format_RGB888,
        ).copy()
        self.page_image.setPixmap(QPixmap.fromImage(image))
        self.page_image.adjustSize()
        self.page_label.setText(f"第 {self.page_index + 1} / {self.document.page_count} 页")
        self.previous_button.setEnabled(self.page_index > 0)
        self.next_button.setEnabled(self.page_index < self.document.page_count - 1)
        self.scroll_area.verticalScrollBar().setValue(0)
        self.scroll_area.horizontalScrollBar().setValue(0)

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt override name
        self.document.close()
        super().closeEvent(event)
