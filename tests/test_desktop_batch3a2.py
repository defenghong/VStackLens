from pathlib import Path
from types import SimpleNamespace
import pytest
from PySide6.QtWidgets import QApplication
from vstacklens.desktop.presentation import history_change
from vstacklens.desktop.presentation import power_state,metadata_text
from vstacklens.desktop.data3a2 import asset_fields
from vstacklens.desktop.app import LoginWindow,DefaultPasswordWarningDialog
from vstacklens.desktop.theme import apply_application_theme
from test_desktop_layout3a import window_for

@pytest.mark.parametrize("kind,labels",[("HostSystem",["所属集群","ESXi 版本","CPU","内存"]),("VirtualMachine",["所属主机","所属集群","CPU","内存","电源状态"]),("Datastore",["归属集群","存储类型","容量使用率","可访问"]),("ClusterComputeResource",["主机数","HA","DRS","CPU 使用率"])])
def test_asset_detail_fields_missing_is_dash_and_existing_fields_remain(kind,labels):
    item=SimpleNamespace(object_type=kind,object_name="demo",location="existing location",detail="existing detail")
    fields=asset_fields(item,{})
    assert [key for key,_ in fields[:len(labels)]]==labels
    assert all(value=="—" for _,value in fields[:len(labels)])
    assert ("完整位置","existing location") in fields and ("已有属性摘要","existing detail") in fields

@pytest.mark.parametrize("value,expected",[("new","新增"),("closed","本次未再发现"),("persistent","持续"),("removed","本次未再发现")])
def test_change_markers_keep_closed_distinct_from_resolved_health(value,expected):assert history_change(value)==expected

def test_application_styles_precede_window_show_and_switch_restores_updates(tmp_path):
    app,window=window_for(tmp_path)
    login=LoginWindow();warning=DefaultPasswordWarningDialog()
    try:
        for selected in ("light","dark"):
            apply_application_theme(app,selected);app.processEvents()
            assert app.styleSheet()
            for item in (window,login,warning):
                assert item.styleSheet()=="" and item.updatesEnabled()
            assert QApplication.overrideCursor() is None
    finally:window.close();login.close();warning.close()

def test_four_asset_pages_bind_current_inventory_and_keep_missing_fields(tmp_path):
    from vstacklens.application import PlatformAssetItem
    app,window=window_for(tmp_path)
    try:
        window._asset_items=[PlatformAssetItem(kind,label,label,"known location","known detail","") for kind,label in (("HostSystem","ESXi"),("VirtualMachine","VM"),("Datastore","Datastore"),("ClusterComputeResource","Cluster"))]
        for selected,required in (("ESXi","ESXi 版本"),("VM","电源状态"),("Datastore","容量使用率"),("Cluster","主机数")):
            window._select_asset_category(selected);app.processEvents()
            assert window.asset_table.rowCount()==1
            assert (required,"—") in window.asset_key_fields
            assert "known location" in window.asset_detail.toPlainText()
    finally:window.close()

@pytest.mark.parametrize("value,label",[("poweredOn","运行中"),("poweredOff","关机"),("suspended","挂起"),("connected","—"),(None,"—")])
def test_vm_power_mapping_does_not_use_connection_state(value,label):assert power_state(value)==label

@pytest.mark.parametrize("value",["未指定站点","未指定客户","未填写客户","未指定环境",None])
def test_system_metadata_placeholders_are_displayed_as_dash(value):assert metadata_text(value)=="—"

def test_host_to_vm_switch_removes_old_connection_badge_and_empty_subtables(tmp_path,monkeypatch):
    from vstacklens.application import PlatformAssetItem
    import vstacklens.desktop.layout3a2 as module
    records=[{"object_type":"HostSystem","object_name":"host","path":"p","properties":{"connection_state":"connected"}},{"object_type":"VirtualMachine","object_name":"vm","path":"p","properties":{"power_state":"poweredOff","connection_state":"connected"}}]
    monkeypatch.setattr(module,"inventory",lambda *args:records)
    app,window=window_for(tmp_path)
    try:
        window._asset_items=[PlatformAssetItem("HostSystem","ESXi","host","p","detail","") ,PlatformAssetItem("VirtualMachine","VM","vm","p","detail","")]
        window._select_asset_category("ESXi");assert window.asset_table.cellWidget(0,2).text()=="已连接"
        window._select_asset_category("VM");assert window.asset_table.cellWidget(0,2).text()=="关机"
        assert ("电源状态","关机") in window.asset_key_fields
        window._select_asset_category("ESXi");app.processEvents()
        assert window.asset_network_table.isHidden() and window.asset_children_table.isHidden()
        assert "本次巡检没有记录" in window.asset_network_empty.text()
        assert "未采集" not in window.asset_network_empty.text()
    finally:window.close()

def test_recorded_paths_resolve_cluster_and_host_without_guessing():
    from vstacklens.desktop.data3a2 import normalize_inventory
    records=[{"object_type":"ClusterComputeResource","object_name":"C","path":"vc/DC/C","properties":{}},{"object_type":"HostSystem","object_name":"H","path":"vc/DC/C/H","properties":{"asset_location":"vc/DC/C"}},{"object_type":"VirtualMachine","object_name":"V","path":"vc/DC/V","properties":{"asset_location":"vc / DC / C / 主机 H"}}]
    normalize_inventory(records)
    assert records[1]["properties"]["cluster_name"]=="C"
    assert records[2]["properties"]["host_name"]=="H" and records[2]["properties"]["cluster_name"]=="C"
    fields=asset_fields(SimpleNamespace(object_type="VirtualMachine",object_name="v",location="l",detail="d"),{"memory_usage_mb":0})
    assert ("内存","—") in fields

@pytest.mark.parametrize("compact",[False,True])
def test_navigation_group_line_above_text_in_both_modes(tmp_path,compact):
    from vstacklens.desktop.navigation_icons import group_geometry
    from vstacklens.desktop.theme import SIZES
    from PySide6.QtCore import Qt
    app,window=window_for(tmp_path)
    try:
        window.resize(1366,675 if compact else 1200);window.show();app.processEvents();window._resize_navigation();app.processEvents()
        for i in range(window.nav.count()):
            item=window.nav.item(i)
            if item.data(Qt.UserRole) or item is window.nav_spacer:continue
            _,line,top,height,minimum=group_geometry(item.font(),item.text()=="主要工作")
            assert item.sizeHint().height()>=minimum
            if line is not None:assert top-line>=8
            else:assert item.text()=="主要工作"
        assert all(window.nav.item(i).sizeHint().height()>=40 for i in range(window.nav.count()) if window.nav.item(i).data(Qt.UserRole))
    finally:window.close()


def test_empty_columns_restore_when_any_row_has_value():
    from PySide6.QtWidgets import QTableWidget
    from vstacklens.desktop.layout3a2 import populate_table,hide_empty_columns
    app=QApplication.instance() or QApplication([]);table=QTableWidget(0,2)
    populate_table(table,[["H","—"]]);hide_empty_columns(table,[["H","—"]]);assert table.isColumnHidden(1)
    populate_table(table,[["H","—"],["H2","8.0"]]);hide_empty_columns(table,[["H","—"],["H2","8.0"]]);assert not table.isColumnHidden(1);assert table.item(0,1).text()=="—"
    table.close()


def test_vm_count_uses_mapped_host_and_nic_uses_collector_link_state():
    from vstacklens.desktop.data3a2 import normalize_inventory,nic_link_state
    records=[{"object_type":"HostSystem","object_name":"H","path":"H","properties":{}},{"object_type":"VirtualMachine","object_name":"V","path":"V","properties":{"host_name":"H"}}]
    normalize_inventory(records);assert records[0]["properties"]["vm_count"]==1
    assert nic_link_state({"link_state":"up"})=="链路正常"
    assert nic_link_state({"link_state":"down"})=="链路断开"
    assert nic_link_state({"device":"vmnic0"})=="—"


def test_child_column_uses_all_records_including_collapsed_rows(tmp_path):
    from vstacklens.application import PlatformAssetItem
    app,window=window_for(tmp_path)
    try:
        window._selected_asset=PlatformAssetItem('HostSystem','ESXi','H','p','d','')
        window._asset_children_expanded=False
        window._asset_children=[{'object_name':name,'object_type':'VirtualMachine','properties':props} for name,props in [('a',{}),('b',{}),('c',{'power_state':'poweredOn'})]]
        window._asset_fill_children()
        assert window.asset_children_table.rowCount()==2
        assert not window.asset_children_table.isColumnHidden(1)
        assert window.asset_children_table.item(0,1).text()=='—'
    finally:window.close()
