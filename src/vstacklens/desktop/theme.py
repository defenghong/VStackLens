from __future__ import annotations


COLORS = {
    "background": "#0B1220",
    "surface": "#111827",
    "surface_alt": "#0F172A",
    "border": "#1F2937",
    "text": "#F3F4F6",
    "subtext": "#9CA3AF",
    "primary": "#3B82F6",
    "success": "#10B981",
    "warning": "#F59E0B",
    "danger": "#EF4444",
}


APP_STYLE = """
QMainWindow, QWidget {
    background: #0B1220;
    color: #F3F4F6;
}
QDialog#loginWindow {
    background: #091423;
}
QLabel, QCheckBox {
    background: transparent;
}
QFrame#topBar {
    background: #0F172A;
    border-bottom: 1px solid #1F2937;
}
QFrame#sidebar {
    background: #0F172A;
    border-right: 1px solid #1F2937;
}
QLabel#brandTitle {
    color: #F3F4F6;
    font-size: 20px;
    font-weight: 800;
}
QLabel#brandSubtitle, QLabel#topSubtitle {
    color: #9CA3AF;
    font-size: 12px;
}
QListWidget#moduleNav {
    background: #0F172A;
    border: none;
    outline: none;
    color: #CBD5E1;
    padding: 6px;
}
QListWidget#moduleNav::item {
    min-height: 34px;
    padding: 7px 10px;
    border-radius: 7px;
}
QListWidget#moduleNav::item:selected {
    background: #1D4ED8;
    color: #FFFFFF;
}
QListWidget#moduleNav::item:hover:!selected {
    background: #1F2937;
}
QScrollArea {
    background: transparent;
    border: none;
}
QScrollBar:vertical {
    background: #0B1220;
    width: 12px;
    margin: 4px 2px;
    border-radius: 6px;
}
QScrollBar::handle:vertical {
    background: #475569;
    min-height: 42px;
    border-radius: 6px;
}
QScrollBar::handle:vertical:hover { background: #64748B; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }
QScrollBar:horizontal {
    background: #0B1220;
    height: 12px;
    margin: 2px 4px;
    border-radius: 6px;
}
QScrollBar::handle:horizontal {
    background: #475569;
    min-width: 42px;
    border-radius: 6px;
}
QScrollBar::handle:horizontal:hover { background: #64748B; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal { background: transparent; }
QFrame#pageCard, QFrame#infoCard, QFrame#sectionCard, QFrame#moduleCard {
    background: #111827;
    border: 1px solid #1F2937;
    border-radius: 12px;
}
QFrame#historyRow {
    background: #101B2D;
    border: 0;
    border-bottom: 1px solid #1F3046;
    border-radius: 0;
}
QFrame#historyRow:hover { background: #15233A; }
QLabel#historyChange { color: #AABBD0; font-size: 12px; }
QLabel#historyIssue { color: #E5EDF7; font-size: 13px; font-weight: 700; }
QFrame#moduleCard:hover {
    border-color: #3B82F6;
}
QLabel#pageTitle {
    font-size: 24px;
    font-weight: 800;
    color: #F3F4F6;
}
QLabel#pageSubtitle {
    color: #9CA3AF;
    font-size: 12px;
}
QLabel#sectionTitle {
    font-size: 16px;
    font-weight: 700;
    color: #F3F4F6;
}
QLabel#productionImpactInfo {
    background: rgba(59, 130, 246, 0.16);
    border: 1px solid #3B82F6;
    border-radius: 11px;
    color: #93C5FD;
    font-weight: 800;
}
QLabel#cardTitle {
    font-size: 15px;
    font-weight: 700;
    color: #F3F4F6;
}
QLabel#metricValue {
    font-size: 26px;
    font-weight: 800;
    color: #F3F4F6;
}
QLabel#heroMetricValue {
    font-size: 40px;
    font-weight: 900;
    color: #F3F4F6;
}
QLabel#dashboardHealthValue {
    font-size: 28px;
    font-weight: 800;
    color: #F3F4F6;
}
QLabel#previewNotice {
    color: #93C5FD;
    font-size: 12px;
    font-weight: 700;
}
QLabel#assetCount {
    color: #CBD5E1;
    font-size: 12px;
    font-weight: 700;
}
QLabel#smallMetricValue {
    font-size: 22px;
    font-weight: 800;
    color: #F3F4F6;
}
QLabel#loginError {
    color: #EF4444;
}
QLabel#loginTitle {
    color: #F3F4F6;
    font-size: 32px;
    font-weight: 800;
    letter-spacing: 0.2px;
}
QLabel#loginFieldLabel {
    color: #CBD5E1;
    font-size: 13px;
    font-weight: 700;
}
QLineEdit#loginInput {
    background: #0D1829;
    border: 1px solid #385577;
    border-radius: 10px;
    padding: 0 15px;
    font-size: 15px;
}
QLineEdit#loginInput:focus {
    border: 1px solid #4F8CFF;
    background: #0E1B2E;
}
QPushButton#loginPrimaryButton {
    background: #4F8CFF;
    color: #FFFFFF;
    border: 0;
    border-radius: 10px;
    font-size: 16px;
    font-weight: 800;
}
QPushButton#loginPrimaryButton:hover { background: #3F80F2; }
QPushButton#loginPrimaryButton:pressed { background: #2867D8; }
QLabel#mutedText, QLabel#cardDescription {
    color: #9CA3AF;
}
QLabel[badge="true"] {
    border-radius: 10px;
    padding: 3px 9px;
    font-size: 12px;
    font-weight: 700;
}
QLabel[status="available"], QLabel[status="enabled"], QLabel[status="success"] {
    background: rgba(16, 185, 129, 0.16);
    color: #10B981;
}
QLabel[status="planned"], QLabel[status="warning"] {
    background: rgba(245, 158, 11, 0.16);
    color: #F59E0B;
}
QLabel[status="global"], QLabel[status="info"] {
    background: rgba(59, 130, 246, 0.16);
    color: #60A5FA;
}
QLabel[status="failed"], QLabel[status="danger"] {
    background: rgba(239, 68, 68, 0.16);
    color: #EF4444;
}
QLabel[status="offline"], QLabel[status="unknown"] {
    background: rgba(156, 163, 175, 0.14);
    color: #9CA3AF;
}
QPushButton {
    background: #111827;
    border: 1px solid #374151;
    border-radius: 7px;
    padding: 7px 14px;
    color: #F3F4F6;
}
QPushButton:hover {
    background: #1F2937;
    border-color: #3B82F6;
}
QPushButton:disabled {
    color: #6B7280;
    background: #111827;
    border-color: #1F2937;
}
QPushButton#primaryButton {
    background: #3B82F6;
    color: #FFFFFF;
    border-color: #3B82F6;
    font-weight: 700;
}
QPushButton#primaryButton:hover {
    background: #2563EB;
}
QPushButton#quietButton {
    border: 0;
    background: transparent;
    color: #93C5FD;
    padding: 4px 2px;
    text-align: left;
}
QPushButton#quietButton:hover { color: #DBEAFE; }
QLineEdit, QSpinBox, QTextEdit, QTableWidget, QComboBox {
    background: #0B1220;
    border: 1px solid #374151;
    border-radius: 8px;
    padding: 7px;
    color: #F3F4F6;
}
QLineEdit:focus, QSpinBox:focus, QTextEdit:focus {
    border-color: #3B82F6;
}
QLineEdit::placeholder {
    color: #6B7280;
}
QTableWidget {
    gridline-color: #1F2937;
    selection-background-color: #1D4ED8;
    selection-color: #FFFFFF;
    alternate-background-color: #0F172A;
}
QHeaderView::section {
    background: #111827;
    color: #9CA3AF;
    border: none;
    border-right: 1px solid #1F2937;
    border-bottom: 1px solid #1F2937;
    padding: 8px;
    font-weight: 700;
}
QProgressBar {
    border: 1px solid #374151;
    border-radius: 7px;
    background: #0B1220;
    height: 20px;
    color: #F3F4F6;
    text-align: center;
}
QProgressBar::chunk {
    background: #3B82F6;
    border-radius: 6px;
}
QCheckBox {
    spacing: 8px;
    color: #F3F4F6;
}
QTabWidget::pane { border: 1px solid #1F2937; border-radius: 10px; top: -1px; }
QTabBar::tab { background: #0F172A; color: #94A3B8; padding: 8px 14px; margin-right: 3px; border-top-left-radius: 8px; border-top-right-radius: 8px; }
QTabBar::tab:selected { background: #1E293B; color: #FFFFFF; }
QPushButton[active="true"] { background: #1D4ED8; border-color: #2563EB; color: #FFFFFF; font-weight: 700; }
"""
