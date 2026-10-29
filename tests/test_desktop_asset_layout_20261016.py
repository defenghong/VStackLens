"""Focused asset layout checks: no application boot, database, HCL or network."""
import os
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtCore import Qt,QPoint
from PySide6.QtWidgets import QApplication,QWidget,QVBoxLayout,QScrollArea,QAbstractItemView,QStyleOptionViewItem

from vstacklens.desktop.layout3a2 import Layout3a2Mixin,clear_children
from vstacklens.desktop.widgets import RowSeparatorDelegate


class AssetPage(QWidget,Layout3a2Mixin):
    def __init__(self,records):
        super().__init__()
        self._asset_items=[SimpleNamespace(object_type=r["object_type"],object_type_label={"HostSystem":"ESXi","VirtualMachine":"VM"}[r["object_type"]],object_name=r["object_name"],location=r["path"],detail="已记录资产",run_id="run-isolated") for r in records]
        self.page=self._asset_center_page();QVBoxLayout(self).addWidget(self.page)
        self.resize(1020,600);self._populate_asset_table();self.show()
    def _prepare_table(self,table):
        table.setItemDelegate(RowSeparatorDelegate(table));table.setSelectionBehavior(QAbstractItemView.SelectRows);table.setEditTriggers(QAbstractItemView.NoEditTriggers);table.verticalHeader().hide()
    def _scroll_page(self,content):
        scroll=QScrollArea();scroll.setWidgetResizable(True);scroll.setWidget(content);return scroll
    def _view_data(self):return SimpleNamespace(run_id="run-isolated",finished_at="2026-10-16T10:00:00+08:00")
    def _short_task(self,run_id):return "S-20261016-01"
    def _db_path(self):return None
    def _clear_layout(self,layout):clear_children(layout)
    def _select_asset_category(self,key):self.asset_type_filter.setCurrentText(key);self._populate_asset_table()
    def _asset_selection_changed(self,row,*args):
        if 0<=row<len(getattr(self,"_asset_display_rows",[])):self._show_asset_detail(self._asset_display_rows[row])


def asset_page(monkeypatch,*,count=80):
    import vstacklens.desktop.layout3a2 as module
    app=QApplication.instance() or QApplication([])
    records=[{"object_type":"HostSystem","object_name":f"host-{i:03d}-long-name","path":f"cluster-{79-i:03d}/host-{i:03d}","properties":{"cluster_name":"cluster","connection_state":"connected","host_version":"8.0","vm_count":1}} for i in range(count)]
    records.append({"object_type":"VirtualMachine","object_name":"vm-off","path":"cluster/vm","properties":{"host_name":"host-000-long-name","power_state":"poweredOff"}})
    monkeypatch.setattr(module,"inventory",lambda *_:records)
    window=AssetPage(records);app.processEvents()
    return app,window


def test_status_draws_once_and_keeps_searchable_copyable_text(monkeypatch):
    app,window=asset_page(monkeypatch,count=2)
    try:
        cell=window.asset_table.item(0,2);option=QStyleOptionViewItem()
        window.asset_table.itemDelegateForColumn(2).initStyleOption(option,window.asset_table.model().index(0,2))
        assert cell.text()=="已连接" and option.text==""
        assert window.asset_table.cellWidget(0,2).text()=="已连接"
        window.asset_table.selectRow(0);window.asset_copy_action.trigger()
        assert "已连接" in QApplication.clipboard().text()
        window.asset_search_input.setText("已连接");assert window.asset_table.rowCount()==2
        window.asset_search_input.clear();window._select_asset_category("VM")
        assert window.asset_table.item(0,2).text()=="关机"
        assert window.asset_table.cellWidget(0,2).text()=="关机"
    finally:window.asset_detail_dialog.close();window.close()


def test_detail_window_does_not_shrink_table_or_lose_selection_scroll(monkeypatch):
    app,window=asset_page(monkeypatch)
    try:
        window.asset_table.setCurrentCell(35,0);window.asset_table.verticalScrollBar().setValue(25);app.processEvents()
        before=(window.asset_table.height(),window.asset_table.currentRow(),window.asset_table.verticalScrollBar().value())
        window.asset_detail_open_button.click();app.processEvents()
        assert window.asset_detail_dialog.isVisible()
        assert window.asset_table.height()==before[0] and before[0]>250
        window.asset_detail_dialog.close();app.processEvents()
        assert (window.asset_table.height(),window.asset_table.currentRow(),window.asset_table.verticalScrollBar().value())==before
        assert window.asset_table.item(35,0).text() in window.asset_detail_name.text()
    finally:window.asset_detail_dialog.close();window.close()


def test_filter_sort_and_refresh_retain_identity_not_row_number(monkeypatch):
    app,window=asset_page(monkeypatch)
    try:
        window.asset_search_input.setText("host");window.asset_table.setCurrentCell(35,0)
        identity=window.asset_table.item(35,0).data(Qt.UserRole)
        window.asset_sort_filter.setCurrentText("按位置");app.processEvents()
        row=window.asset_table.currentRow()
        assert window.asset_table.item(row,0).data(Qt.UserRole)==identity and row!=35
        window.asset_table.verticalScrollBar().setValue(18);app.processEvents()
        position=window.asset_table.verticalScrollBar().value();window._populate_asset_table();app.processEvents()
        assert window.asset_search_input.text()=="host" and window.asset_sort_filter.currentText()=="按位置"
        assert window.asset_table.item(window.asset_table.currentRow(),0).data(Qt.UserRole)==identity
        assert window.asset_table.verticalScrollBar().value()==position
    finally:window.asset_detail_dialog.close();window.close()


def test_empty_and_no_match_hide_stale_detail(monkeypatch):
    app,window=asset_page(monkeypatch,count=2)
    try:
        top_controls=(window.asset_category_buttons["ESXi"],window.asset_search_input)
        before=tuple(control.mapTo(window.page,QPoint()).y() for control in top_controls)
        window._asset_open_detail();app.processEvents();assert window.asset_detail_dialog.isVisible()
        window.asset_search_input.setText("not-in-this-inventory");app.processEvents()
        assert tuple(control.mapTo(window.page,QPoint()).y() for control in top_controls)==before
        assert not window.asset_detail_dialog.isVisible() and not window.asset_detail_open_button.isEnabled()
        assert "没有匹配" in window.asset_empty.text()
        window._asset_items=[];window._populate_asset_table();app.processEvents()
        assert window.asset_empty.text()=="尚无有效巡检资产" and not window.asset_splitter.isVisible()
        assert tuple(control.mapTo(window.page,QPoint()).y() for control in top_controls)==before
    finally:window.asset_detail_dialog.close();window.close()


def test_duplicate_names_keep_record_state_and_existing_stable_id(monkeypatch):
    import vstacklens.desktop.layout3a2 as module
    app=QApplication.instance() or QApplication([])
    records=[{"object_type":"VirtualMachine","object_key":"vm-101","object_name":"shared-name","path":"z-cluster/shared-name","properties":{"power_state":"poweredOn"}},{"object_type":"VirtualMachine","object_key":"vm-102","object_name":"shared-name","path":"a-cluster/shared-name","properties":{"power_state":"poweredOff"}}]
    monkeypatch.setattr(module,"inventory",lambda *_:records)
    window=AssetPage(records)
    try:
        window._select_asset_category("VM");app.processEvents()
        assert window.asset_table.item(0,2).text()=="运行中"
        assert window.asset_table.item(1,2).text()=="关机"
        window.asset_table.setCurrentCell(0,0)
        assert window.asset_table.item(0,0).data(Qt.UserRole)==("run-isolated","VirtualMachine","vm-101")
        window.asset_sort_filter.setCurrentText("按位置");app.processEvents()
        assert window.asset_table.currentRow()==1
        assert window.asset_table.item(1,0).data(Qt.UserRole)==("run-isolated","VirtualMachine","vm-101")
        window._populate_asset_table();app.processEvents()
        assert window.asset_table.item(window.asset_table.currentRow(),0).data(Qt.UserRole)==("run-isolated","VirtualMachine","vm-101")
    finally:window.asset_detail_dialog.close();window.close()


def test_asset_detail_hides_with_owner_or_page_without_changing_table_state(monkeypatch):
    app,window=asset_page(monkeypatch,count=2)
    try:
        window.asset_table.setCurrentCell(1,0)
        for hide in (window.hide,window.page.hide,window.close):
            window.show();window.page.show();window._asset_open_detail();app.processEvents()
            assert window.asset_detail_dialog.isVisible()
            hide();app.processEvents()
            assert not window.asset_detail_dialog.isVisible()
            assert window.asset_table.currentRow()==1
    finally:window.asset_detail_dialog.close();window.close()
