"""Risk layout regression with in-memory identities; no VMware, database or report."""
from types import SimpleNamespace

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QScrollArea, QTableWidget, QVBoxLayout, QWidget

from vstacklens.desktop.layout3a import Layout3aMixin
from vstacklens.desktop.theme import apply_application_theme


class RiskHarness(Layout3aMixin, QWidget):
    def __init__(self):
        super().__init__()
        self._task_numbers = {"run_layout": "S-20261016-01"}
        self._risk_items = []
        categories = []
        for index in range(40):
            category_id = f"category-{index:02d}"
            title = f"问题 {index:02d}：具有很长名称的测试类别与对象身份"
            categories.append({"category_id": category_id, "title": title, "priority": "P2", "affected_object_count": 1})
            self._risk_items.append(SimpleNamespace(category_id=category_id, non_report_reason="", title=title,
                object_name=f"主机-{index:02d}-完整长名称", object_type="HostSystem", current_observed="" if index == 15 else "91",
                expected_state="< 80", rule_name=title, rule_id="VSL-HOST-005", raw_evidence={}, status="INSUFFICIENT_DATA" if index == 15 else "open",
                remediation="保留原有建议及完整证据", risk_level="P2"))
        self.data = SimpleNamespace(run_id="run_layout", finished_at="2026-10-16T00:00:00Z", recent_reports=[], has_data=True,
            customer_caliber={"problem_count": 40, "affected_total": 40, "counts": {"P1": 0, "P2": 40, "P3": 0}, "categories": categories})
        layout = QVBoxLayout(self); layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._risk_center_page()); self._populate_risk_table()

    def _view_data(self): return self.data
    def _refresh_risk_items(self): self._populate_risk_table()
    def _show_latest_standard_report(self): pass
    def _engineer_risk_detail(self, item): self.risk_detail.setPlainText(item.object_name)
    def _prepare_table(self, table):
        table.setEditTriggers(QTableWidget.NoEditTriggers); table.setSelectionBehavior(QTableWidget.SelectRows)
        table.verticalHeader().setVisible(False)
    def _scroll_page(self, content):
        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setWidget(content)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff); return scroll
    def _clear_layout(self, layout):
        while layout.count():
            child = layout.takeAt(0)
            if child.widget(): child.widget().deleteLater()


def harness():
    app = QApplication.instance() or QApplication([]); apply_application_theme(app, "dark")
    window = RiskHarness(); window.resize(1240, 700); window.show(); app.processEvents()
    return app, window


def test_risk_detail_is_optional_and_moves_without_changing_list_state():
    app, window = harness()
    try:
        assert window.risk_detail_side.isHidden()
        assert not window.risk_detail_dialog.isVisible()
        assert window.risk_list.height() > 400
        window.risk_list.setCurrentCell(15, 1); window.risk_list.selectRow(15)
        window.risk_list.verticalScrollBar().setValue(12)
        selected = window.risk_list.item(window.risk_list.currentRow(), 1).text(); scroll = window.risk_list.verticalScrollBar().value()
        window._open_risk_details(); app.processEvents()
        assert window.risk_detail_side.isVisible()
        assert not window.risk_evidence_hint.isHidden()
        assert "不能据此判断正常" in window.risk_evidence_hint.text()
        assert window.risk_title.toolTip() == selected
        window.resize(840, 700); app.processEvents()
        assert window.risk_detail_dialog.isVisible()
        assert window.risk_details_scroll.parentWidget() is window.risk_detail_dialog
        assert window.risk_detail_side.isHidden()
        assert window.risk_list.item(window.risk_list.currentRow(), 1).text() == selected
        assert window.risk_list.verticalScrollBar().value() == scroll
        window.risk_detail_dialog.reject(); app.processEvents()
        assert not window._risk_detail_open
        assert window.risk_list.item(window.risk_list.currentRow(), 1).text() == selected
        assert window.risk_list.verticalScrollBar().value() == scroll
    finally: window.close()


def test_risk_refresh_preserves_filter_sort_selection_scroll_and_full_identity():
    app, window = harness()
    try:
        window.risk_keyword_input.setText("问题")
        window.risk_list.setSortingEnabled(True); window.risk_list.sortItems(1, Qt.DescendingOrder)
        window.risk_list.setCurrentCell(17, 1); window.risk_list.selectRow(17)
        selected = window.risk_list.item(window.risk_list.currentRow(), 1).text()
        window.risk_list.verticalScrollBar().setValue(15)
        scroll = window.risk_list.verticalScrollBar().value()
        window._populate_risk_table(); app.processEvents()
        assert window.risk_keyword_input.text() == "问题"
        assert window.risk_list.horizontalHeader().sortIndicatorOrder() == Qt.DescendingOrder
        assert window.risk_list.item(window.risk_list.currentRow(), 1).text() == selected
        assert window.risk_list.item(window.risk_list.currentRow(), 1).toolTip() == selected
        assert window.risk_list.verticalScrollBar().value() == scroll
        window._open_risk_details(); app.processEvents()
        window.data = SimpleNamespace(**{**vars(window.data), "run_id": "run_other"})
        window._populate_risk_table(); app.processEvents()
        assert not window._risk_detail_open
    finally: window.close()


def test_empty_risk_results_close_old_details_and_do_not_claim_normal():
    app, window = harness()
    try:
        window._open_risk_details(); app.processEvents()
        window.data = None; window._risk_items = []; window._populate_risk_table(); app.processEvents()
        assert window.risk_empty.text() == "尚无巡检记录"
        assert not window.risk_open_detail_button.isEnabled()
        assert not window._risk_detail_open
        assert not window.risk_detail_dialog.isVisible()
        assert window.risk_list.rowCount() == 0
    finally: window.close()
