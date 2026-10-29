from __future__ import annotations

from string import Template

TYPOGRAPHY = {
    "body": 14, "secondary": 13, "table_header": 14, "page_title": 25,
    "page_subtitle": 13, "section_title": 18, "health": 28, "number": 36,
    "priority_number": 25, "risk_badge": 13, "navigation": 14,
    "navigation_group": 12, "context_value": 14, "risk_title": 25,
    "detail_heading": 17, "button": 14, "asset_number": 21, "table_body":14,
}
SIZES = {
    "page_margin": 16, "card_padding": 12, "card_gap": 8,
    "navigation_row": 40, "navigation_compact": 34, "navigation_group": 12,
    "navigation_icon": 20, "navigation_icon_gap": 12, "context_height": 36,
    "table_header": 30, "table_row": 34, "cell_padding": 10,
    "primary_button": 34, "secondary_button": 34, "input": 34,
    "badge_width": 48, "badge_height": 28, "detail_gap": 20,
    "sidebar": 204, "top_bar": 40, "page_top": 10, "title_strip_width": 4,
    "title_strip_height": 24, "home_gap": 2, "home_top": 4, "home_bottom": 24,
    "conclusion_height": 140, "conclusion_divider": 96, "task_icon": 38,
    "task_height": 104, "section_gap": 4, "field_padding_y": 4,
    "primary_padding_x": 20, "navigation_group_later": 38, "navigation_group_compact": 28,
    "brand_font": 19, "brand_subtitle": 13, "cell_icon_margin": 8,
    "issues_grade_share":0.07,"issues_title_share":0.22,"issues_objects_share":0.15,
    "number_pair_gap":8,"number_group_gap":32,"asset_pair_gap":8,"asset_group_gap":24,
    "recent_time_width":180,"examples_value_share":0.56,
    "page_tabs_height":36,"key_value_row":34,"asset_row":38,"risk_row":56,
    "detail_panel_padding":18,"nav_separator_gap":12,"nav_separator_width":1,
    "filter_combo_width":164,"filter_arrow_gap":12,"table_change_width":150,
    "status_dot_radius":3,"report_file_row":36,"compact_filter_threshold":760,"change_marker_height":28,
    "batch2_problem_height":112,"batch2_action_height":50,"batch2_step_icon":52,
    "batch2_upgrade_config_height":432,"batch2_card_icon":32,"batch2_fold_height":96,
    "batch2_logo_size":108,"batch2_result_height":208,"batch2_step_icon_radius":26,"navigation_line_top_gap":8,"step_outline_width":2,"step_connector_width":1,"mode_radio_size":16,"mode_radio_gap":10,"mode_radio_dot":4,"fold_arrow":20,
    "asset_table_shares":(.28,.25,.18,.15),"report_table_shares":(.22,.18,.27),"history_table_shares":(.12,.075,.27,.24,.20),
}


DARK = {
    "background": "#14161C", "surface": "#1B1E26", "border": "#2A2D36",
    "text": "#E5E7EB", "subtext": "#8B96A8",
    "primary": "#2F6E5E", "primary_hover": "#255A4C",
    "P1": "#C0392B", "P2": "#B7791F", "P3": "#5B7FA6", "P4": "#6B7280",
    "success": "#4A9B6E", "button_text": "#FFFFFF",
    "selection": "#2A2D36", "hover": "#2A2D36",
    "divider":"#596271",
}
LIGHT = {
    "background": "#F6F4EF", "surface": "#FFFFFF", "border": "#E6E1D8",
    "text": "#24211C", "subtext": "#6B655B",
    "primary": "#2F6E5E", "primary_hover": "#255A4C",
    "P1": "#B3261E", "P2": "#A15C07", "P3": "#3F6688", "P4": "#6B655B",
    "success": "#3F7D4E", "button_text": "#FFFFFF",
    "selection": "#EAE6DD", "hover": "#EFECE5",
    "divider":"#B7AFA3",
}
for palette in (DARK, LIGHT):
    palette.update(surface_alt=palette["surface"], danger=palette["P1"], warning=palette["P2"])
    palette.update(scrollbar=palette["subtext"], scrollbar_hover=palette["subtext"])
DARK.update(change_new="#58AD9D",change_closed="#B4B4B4",change_persistent="#B39ACB")
LIGHT.update(change_new="#297C70",change_closed="#686868",change_persistent="#76608C")
LIGHT.update(scrollbar="#CAC5BB", scrollbar_hover="#A9A396")
DARK["sidebar"] = DARK["surface"]
LIGHT["sidebar"] = LIGHT["background"]

THEMES = {"dark": DARK, "light": LIGHT}
_current_theme = "light"
# Keep these mappings stable so imported references in painters stay live.
COLORS = dict(LIGHT)
STATUS_COLORS: dict[str, str] = {}


def current_theme() -> str:
    return _current_theme


def set_theme(name: str) -> str:
    global _current_theme, APP_STYLE
    _current_theme = name if name in THEMES else "light"
    COLORS.clear()
    COLORS.update(THEMES[_current_theme])
    STATUS_COLORS.clear()
    STATUS_COLORS.update({
        "available": COLORS["success"], "enabled": COLORS["success"], "success": COLORS["success"],
        "planned": COLORS["warning"], "warning": COLORS["warning"],
        "global": COLORS["P3"], "info": COLORS["P3"],
        "failed": COLORS["danger"], "danger": COLORS["danger"],
        "offline": COLORS["subtext"], "unknown": COLORS["subtext"],
        "running": COLORS["P3"], "cancelled": COLORS["subtext"],
        "change_new":COLORS["change_new"],"change_closed":COLORS["change_closed"],"change_persistent":COLORS["change_persistent"],
    })
    APP_STYLE = current_stylesheet()
    return APP_STYLE


def color_with_alpha(role: str, alpha: int) -> str:
    """Return Qt's ARGB notation for a translucent palette color."""
    return f"#{alpha:02x}{COLORS[role].lstrip('#')}"


_STYLE_TEMPLATE = Template("""
QMainWindow, QWidget {
    background: ${background};
    color: ${text};
    font-size: ${font_body}px;
}
QDialog#loginWindow {
    background: ${background};
}
QLabel, QCheckBox {
    background: transparent;
}
QFrame#topBar {
    background: ${surface};
    border-bottom: 1px solid ${border};
}
QFrame#sidebar {
    background: ${sidebar};
    border-right: 1px solid ${border};
}
QLabel#brandTitle {
    color: ${text};
    font-size: ${size_brand_font}px;
    font-weight: 700;
}
QLabel#brandSubtitle, QLabel#topSubtitle {
    color: ${subtext};
    font-size: ${size_brand_subtitle}px;
}
QListWidget#moduleNav {
    background: ${surface};
    border: none;
    outline: none;
    color: ${text};
    padding: 6px;
}
QListWidget#moduleNav::item {
    min-height: 34px;
    padding: 7px 10px;
    border-radius: 2px;
}
QListWidget#moduleNav::item:selected {
    background: ${selection};
    color: ${text};
    font-weight: 700;
}
QListWidget#moduleNav::item:hover:!selected {
    background: ${hover};
}
QScrollArea {
    background: transparent;
    border: none;
}
QScrollBar:vertical {
    background: ${background};
    width: 12px;
    margin: 4px 2px;
    border-radius: 2px;
}
QScrollBar::handle:vertical {
    background: ${scrollbar};
    min-height: 42px;
    border-radius: 2px;
}
QScrollBar::handle:vertical:hover { background: ${scrollbar_hover}; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }
QScrollBar:horizontal {
    background: ${background};
    height: 12px;
    margin: 2px 4px;
    border-radius: 2px;
}
QScrollBar::handle:horizontal {
    background: ${scrollbar};
    min-width: 42px;
    border-radius: 2px;
}
QScrollBar::handle:horizontal:hover { background: ${scrollbar_hover}; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal { background: transparent; }
QFrame#pageCard, QFrame#infoCard, QFrame#sectionCard, QFrame#moduleCard, QFrame#homeCompactCard {
    background: ${surface};
    border: 1px solid ${border};
    border-radius: 2px;
}
QFrame#historyRow {
    background: ${surface};
    border: 0;
    border-bottom: 1px solid ${border};
    border-radius: 0;
}
QFrame#historyRow:hover { background: ${hover}; }
QLabel#historyChange { color: ${subtext}; font-size: 12px; }
QLabel#historyIssue { color: ${text}; font-size: 13px; font-weight: 700; }
QFrame#moduleCard:hover {
    border-color: ${subtext};
}
QFrame#batch2CardHeader { background: transparent; border: none; }
QFrame#batch2CardHeader:focus { border: 1px dotted ${subtext}; }
QLabel#batch2StateBadge { border: 1px solid ${border}; border-radius: 2px; padding: 4px 8px; }
QLabel#batch2RunState { font-size: ${font_health}px; font-weight: 700; color: ${text}; }
QFrame#batch2StepIcon { border: 2px solid ${border}; border-radius: ${size_batch2_step_icon_radius}px; background: ${surface}; }
QFrame#batch2StepIcon[stepStatus="running"] { border-color: ${success}; }
QFrame#batch2StepIcon[stepStatus="success"] { border-color: ${success}; background: ${selection}; }
QFrame#batch2StepIcon[stepStatus="failed"] { border-color: ${P1}; background: ${surface}; }
QLabel[stepStatus="running"], QLabel[stepStatus="success"] { color: ${primary}; }
QLabel[stepStatus="failed"] { color: ${P1}; }
QLabel#pageTitle {
    font-size: ${font_page_title}px;
    font-weight: 700;
    color: ${text};
}
QLabel#pageSubtitle {
    color: ${subtext};
    font-size: ${font_page_subtitle}px;
}
QLabel#sectionTitle {
    font-size: ${font_section_title}px;
    font-weight: 700;
    color: ${text};
}
QLabel#productionImpactInfo {
    background: ${surface};
    border: 1px solid ${subtext};
    border-radius: 2px;
    color: ${P3};
    font-weight: 800;
}
QLabel#cardTitle {
    font-size: ${font_section_title}px;
    font-weight: 700;
    color: ${text};
}
QLabel#metricValue {
    font-size: ${font_priority_number}px;
    font-weight: 700;
    color: ${text};
}
QLabel#heroMetricValue {
    font-size: 40px;
    font-weight: 900;
    color: ${text};
}
QLabel#dashboardHealthValue {
    font-size: ${font_health}px;
    font-weight: 700;
    color: ${text};
}
QLabel#previewNotice {
    color: ${P3};
    font-size: 12px;
    font-weight: 700;
}
QLabel#assetCount {
    color: ${text};
    font-size: ${font_asset_number}px;
    font-weight: 700;
}
QLabel#smallMetricValue {
    font-size: ${font_priority_number}px;
    font-weight: 700;
    color: ${text};
}
QLabel#loginError {
    color: ${danger};
}
QLabel#loginTitle {
    color: ${text};
    font-size: 28px;
    font-weight: 700;
}
QLabel#loginSubtitle { color: ${text}; font-size: ${font_body}px; }
QLabel#loginAccountHint, QLabel#loginVersion { color: ${subtext}; font-size: ${font_secondary}px; }
QLabel#loginFieldLabel {
    color: ${text};
    font-size: ${font_body}px;
    font-weight: 700;
}
QLineEdit#loginInput {
    background: ${surface};
    border: 1px solid ${border};
    border-radius: 2px;
    min-height: ${size_input_content}px;
    padding: ${size_field_padding_y}px 12px;
    font-size: ${font_body}px;
}
QLineEdit#loginInput:focus {
    border: 1px solid ${primary};
    background: ${surface};
}
QPushButton#loginPrimaryButton {
    background: ${primary};
    color: ${button_text};
    border: 1px solid ${primary};
    border-radius: 2px;
    font-size: ${font_button}px;
    font-weight: 700;
}
QPushButton#loginPrimaryButton:hover { background: ${primary_hover}; border-color: ${primary_hover}; }
QPushButton#loginPrimaryButton:pressed { background: ${primary_hover}; border-color: ${primary_hover}; }
QLabel#mutedText, QLabel#cardDescription {
    color: ${subtext};
    font-size: ${font_secondary}px;
}
QLabel[badgeType="risk"] {
    border-radius: 2px;
    padding: 3px 10px;
    font-size: ${font_risk_badge}px;
    font-weight: 700;
}
QLabel[badgeType="status"][status="available"], QLabel[badgeType="status"][status="enabled"], QLabel[badgeType="status"][status="success"] {
    background: transparent;
    color: ${success};
}
QLabel[badgeType="status"][status="planned"], QLabel[badgeType="status"][status="warning"] {
    background: transparent;
    color: ${warning};
}
QLabel[badgeType="status"][status="global"], QLabel[badgeType="status"][status="info"] {
    background: transparent;
    color: ${P3};
}
QLabel[badgeType="status"][status="failed"], QLabel[badgeType="status"][status="danger"] {
    background: transparent;
    color: ${danger};
}
QLabel[badgeType="status"][status="offline"], QLabel[badgeType="status"][status="unknown"] {
    background: transparent;
    color: ${subtext};
}
QPushButton {
    background: ${surface};
    border: 1px solid ${border};
    border-radius: 2px;
    min-height: ${size_secondary_button_content}px;
    padding: 0 16px;
    font-size: ${font_button}px;
    color: ${text};
}
QPushButton:hover {
    background: ${hover};
    border-color: ${subtext};
}
QPushButton:disabled {
    color: ${subtext};
    background: ${surface};
    border-color: ${border};
}
QPushButton#primaryButton {
    background: ${primary};
    color: ${button_text};
    border-color: ${primary};
    font-weight: 700;
    min-height: ${size_primary_button_content}px;
    padding: 0 20px;
}
QPushButton#primaryButton:hover {
    background: ${primary_hover};
    border-color: ${primary_hover};
}
QPushButton#quietButton {
    border: 0;
    background: transparent;
    color: ${text};
    padding: 4px 2px;
    text-align: left;
    min-height: 22px;
}
QPushButton#quietButton:hover { color: ${text}; text-decoration: underline; }
QLineEdit, QSpinBox, QTextEdit, QTableWidget, QTreeWidget, QComboBox {
    background: ${background};
    border: 1px solid ${border};
    border-radius: 2px;
    padding: 6px;
    color: ${text};
}
QLineEdit:focus, QSpinBox:focus, QTextEdit:focus {
    border-color: ${primary};
}
QComboBox:focus { border-color: ${primary}; }
QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled, QTextEdit:disabled {
    color: ${subtext}; background: ${background}; border-color: ${border};
}
QLineEdit::placeholder {
    color: ${subtext};
}
QLineEdit, QComboBox, QSpinBox { min-height: ${size_input_content}px; padding: ${size_field_padding_y}px 12px; font-size: ${font_body}px; }
QComboBox::drop-down { border: none; background: transparent; width: 24px; }
QComboBox::down-arrow { image: none; width: 0; height: 0; }
QComboBox { padding-right:36px; }
QTableWidget::item { padding: 0 ${size_cell_padding}px; }
QTableWidget, QTreeWidget {
    background: ${surface};
    font-size: ${font_table_body}px;
    gridline-color: ${border};
    selection-background-color: ${selection};
    selection-color: ${text};
    alternate-background-color: ${surface};
}
QHeaderView::section {
    background: ${surface};
    color: ${subtext};
    border: none;
    border-bottom: 1px solid ${border};
    padding: 0 ${size_cell_padding}px;
    font-size: ${font_table_header}px;
    font-weight: 700;
}
QHeaderView::section:checked { color: ${text}; }
QProgressBar {
    border: 1px solid ${border};
    border-radius: 2px;
    background: ${background};
    height: 20px;
    color: ${text};
    text-align: center;
}
QProgressBar::chunk {
    background: ${P3};
    border-radius: 2px;
}
QCheckBox, QRadioButton {
    spacing: 8px;
    color: ${text};
}
QCheckBox::indicator, QRadioButton::indicator { width: 17px; height: 17px; }
QCheckBox:disabled, QRadioButton:disabled { color: ${subtext}; }
QTableWidget[cardTable="true"] { border: none; padding: 0; }
QTableWidget[cardTable="true"] QHeaderView::section { border-right: none; }
QTreeWidget[cardTable="true"] { border: none; padding: 0; }
QFrame#conclusionDivider { background: ${divider}; border: none; }
QFrame#assetOverview { background: ${surface}; border: none; border-radius: 2px; }
QFrame#flatSection { background: transparent; border: none; }
QWidget#homeSummaryBody, QWidget#loginBrand { background: transparent; }
QFrame#titleStrip { background: ${primary}; border: none; }
QTabWidget::pane { border: 1px solid ${border}; border-radius: 2px; top: -1px; }
QTabBar::tab { background: ${surface}; color: ${subtext}; padding: 8px 14px; margin-right: 3px; border-top-left-radius: 2px; border-top-right-radius: 2px; }
QTabBar::tab:selected { background: ${selection}; color: ${text}; }
QTabWidget[pageTabs="true"]::pane { border: none; }
QTabWidget[pageTabs="true"] QTabBar::tab { background: transparent; border: none; border-bottom:2px solid transparent; border-radius:0; padding:10px 24px; }
QTabWidget[pageTabs="true"] QTabBar::tab:selected { background:transparent; border-bottom:2px solid ${primary}; font-weight:700; }
QPushButton[assetTab="true"] { border:none; border-bottom:2px solid transparent; background:transparent; padding:0 20px; }
QPushButton[assetTab="true"][active="true"] { border-bottom:2px solid ${primary}; background:transparent; font-weight:700; }
QPushButton[active="true"] { background: ${selection}; border-color: ${subtext}; color: ${text}; font-weight: 700; }

QLabel[badgeType="status"] { background: transparent; border: none; padding: 3px 2px; font-size: ${font_secondary}px; }
QLabel[badgeType="risk"][riskLevel="P1"] { color: ${button_text}; border: none; background: ${P1}; }
QLabel[badgeType="risk"][riskLevel="P2"] { color: ${button_text}; border: none; background: ${P2}; }
QLabel[badgeType="risk"][riskLevel="P3"] { color: ${button_text}; border: none; background: ${P3}; }
QLabel[badgeType="risk"][riskLevel="P4"] { color: ${button_text}; border: none; background: ${P4}; }
QLabel#metricValue[zero="true"], QLabel#smallMetricValue[zero="true"], QLabel[zero="true"], QLabel[badgeType="status"][zero="true"] { color: ${subtext}; }
QLabel#metricValue[zero="true"], QLabel#smallMetricValue[zero="true"] { font-weight: 400; }
QLabel#largeNumber { font-size: ${font_number}px; font-weight: 700; }
QLabel#numberCaption { font-size: ${font_body}px; font-weight: 400; }
QLabel#riskDetailTitle { font-size: ${font_risk_title}px; font-weight: 700; }
QLabel#detailHeading { font-size: ${font_detail_heading}px; font-weight: 700; }
QLabel#capabilityCheck { color:${primary}; font-size:${font_body}px; font-weight:700; }
QLabel#detailBody { font-size: ${font_body}px; color: ${text}; }
QLabel#contextObject { font-size: ${font_context_value}px; }
QPushButton:focus { border: 1px solid ${primary}; }
QPushButton#primaryButton:focus, QPushButton#loginPrimaryButton:focus { border-color: ${primary}; }
QPushButton#primaryButton:hover:focus, QPushButton#loginPrimaryButton:hover:focus { border-color: ${primary_hover}; }
QPushButton#primaryButton:disabled, QPushButton#loginPrimaryButton:disabled { background: ${surface}; border: 1px solid ${border}; color: ${subtext}; }
QPushButton#quietButton:disabled { color: ${subtext}; }
QListWidget#moduleNav[navigation="true"] { background: ${sidebar}; }
QListWidget#moduleNav[navigation="true"]::item { min-height: 26px; padding: 4px 10px; }
QListWidget#moduleNav[navigation="true"]::item:disabled { min-height: 0; padding: 0; color: ${subtext}; }
QLineEdit, QComboBox { background: ${surface}; }
QFrame#contextBar { border-bottom: 1px solid ${border}; }
QListWidget#issueList { background: ${surface}; border: 1px solid ${border}; }
QListWidget#issueList::item { border-bottom: 1px solid ${border}; }
QListWidget#issueList::item:selected { background: ${selection}; }
QWidget#issueRow { background: transparent; }
QWidget#badgeCell { background: transparent; }
QWidget#numberSummary, QWidget#inlineNumberGroup { background: transparent; }
QComboBox QAbstractItemView { background: ${surface}; color: ${text}; border: 1px solid ${border}; selection-background-color: ${selection}; selection-color: ${text}; }
QToolTip { background: ${surface}; color: ${text}; border: 1px solid ${border}; padding: 4px; }

""")


def current_stylesheet() -> str:
    parameters = {**COLORS, **{f"font_{key}": value for key, value in TYPOGRAPHY.items()},
                  **{f"size_{key}": value for key, value in SIZES.items()}}
    parameters.update(size_primary_button_content=SIZES["primary_button"]-2, size_secondary_button_content=SIZES["secondary_button"]-2)
    parameters.update(size_input_content=SIZES["input"]-2-2*SIZES["field_padding_y"])
    return _STYLE_TEMPLATE.substitute(parameters)


def apply_application_theme(app, name: str) -> None:
    """Update existing windows, native palettes, and every custom painter."""
    from PySide6.QtCore import QObject, QEvent, Qt
    from PySide6.QtGui import QColor, QPalette
    from PySide6.QtWidgets import QWidget
    from vstacklens.desktop.windowing import enable_windows_dark_title_bar
    from vstacklens.desktop.widgets import ensure_common_control_style

    ensure_common_control_style(app)

    requested = name if name in THEMES else "light"
    if (
        requested == current_theme()
        and hasattr(app, "_vstacklens_theme_filter")
        and app.styleSheet() == current_stylesheet()
    ):
        return
    windows=list(app.topLevelWidgets())
    previous=[(window,window.updatesEnabled()) for window in windows]
    for window,_ in previous:window.setUpdatesEnabled(False)
    app.setOverrideCursor(Qt.WaitCursor)
    try:
        _apply_theme_palette(app,name,windows)
    finally:
        for window,enabled in previous:
            window.setUpdatesEnabled(enabled)
            if enabled:QWidget.update(window)
        app.restoreOverrideCursor()

def _apply_theme_palette(app,name,windows):
    from PySide6.QtCore import QObject,QEvent
    from PySide6.QtGui import QColor,QPalette
    from PySide6.QtWidgets import QWidget
    from vstacklens.desktop.windowing import enable_windows_dark_title_bar
    style = set_theme(name)
    palette = QPalette()
    for role, key in (
        (QPalette.Window, "background"), (QPalette.WindowText, "text"),
        (QPalette.Base, "background"), (QPalette.AlternateBase, "surface"),
        (QPalette.Text, "text"), (QPalette.Button, "surface"),
        (QPalette.ButtonText, "text"), (QPalette.Highlight, "selection"),
        (QPalette.HighlightedText, "text"), (QPalette.ToolTipBase, "surface"),
        (QPalette.ToolTipText, "text"), (QPalette.PlaceholderText, "subtext"),
    ):
        palette.setColor(role, QColor(COLORS[key]))
    for role in (QPalette.WindowText, QPalette.Text, QPalette.ButtonText):
        palette.setColor(QPalette.Disabled, role, QColor(COLORS["subtext"]))
    app.setPalette(palette)
    app.setStyleSheet(style)
    if not hasattr(app, "_vstacklens_theme_filter"):
        class WindowThemeFilter(QObject):
            def eventFilter(self, watched, event):
                if event.type() == QEvent.Show and isinstance(watched, QWidget) and watched.isWindow():
                    enable_windows_dark_title_bar(watched, enabled=current_theme() == "dark")
                return False
        app._vstacklens_theme_filter = WindowThemeFilter(app)
        app.installEventFilter(app._vstacklens_theme_filter)
    for window in windows:
        enable_windows_dark_title_bar(window, enabled=current_theme() == "dark")
        refresh = getattr(window, "_refresh_theme_icons", None)
        if refresh:
            refresh()
    for widget in app.allWidgets():
        QWidget.update(widget)


APP_STYLE = ""
set_theme("light")
