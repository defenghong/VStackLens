from __future__ import annotations
import json
from pathlib import Path
from types import SimpleNamespace as NS
from collections import UserDict
import pytest
from vstacklens.collection.pci_collector import PyVmomiPciCollector, _safe_getattr, _as_record_list
from vstacklens.collection.powercli_backend import CachedEsxcli
from vstacklens.reports.html_package import HtmlReportPackageBuilder

FIXTURE = Path(__file__).parent / "fixtures/powercli_json_real_slice.json"

@pytest.mark.parametrize("value", [dict(Name="vmnic0"), UserDict(Name="vmnic0"), NS(Name="vmnic0")])
def test_safe_field_reader_supports_mapping_and_object(value):
    assert _safe_getattr(value,"Name") == "vmnic0"
    assert _safe_getattr(value,"absent","fallback") == "fallback"

def test_field_reader_does_not_mask_mapping_values_with_dict_methods():
    assert _safe_getattr({"items":0,"Name":None,"Link":False},"items") == 0
    assert _safe_getattr({"Name":None},"Name","fallback") is None
    assert _safe_getattr({"Link":False},"Link",True) is False

def test_faulting_vmomi_property_still_degrades():
    class Fault:
        @property
        def Name(self): raise RuntimeError("NoPermission")
    assert _safe_getattr(Fault(),"Name","fallback") == "fallback"
    assert _safe_getattr(None,"Name") is None

def test_real_powercli_json_reaches_nested_nic_and_hba_firmware():
    payload=json.loads(FIXTURE.read_text(encoding="utf-8"))
    nic=payload["commands"]["network.nic.list"]["data"][0]
    host=NS(name="lab-host",config=NS(network=NS(pnic=[NS(device="vmnic0",pci=nic["PCIDevice"])])))
    collector=PyVmomiPciCollector("offline","unused","unused",esxcli_provider=lambda _:CachedEsxcli(payload))
    pci=[NS(id="0000:18:00.0"),NS(id="0000:3c:00.0")]
    records,warnings,_=collector._esxcli_enrichment(host,pci,{})
    assert not warnings
    assert records["0000:18:00.0"]["esxcli_name"] == "vmnic0"
    assert records["0000:18:00.0"]["driver_version"] == "1.4.11.7"
    assert records["0000:18:00.0"]["firmware_raw"] == "1.67.0:0x80000d38:18.0.16"
    assert records["0000:3c:00.0"]["driver_name"] == "lsi_msgpt3"
    assert records["0000:3c:00.0"]["firmware_version"] == "16.17.01.00"
    assert records["_unmatched"] == []

def test_single_nic_record_does_not_turn_array_property_into_records():
    row={"Name":"vmnic0","DriverInfo":{"Version":"1.0"},"AdvertisedLinkModes":["Auto","1000BaseT/Full"]}
    assert _as_record_list(row) == [row]
    assert _as_record_list({"items":[row]}) == [row]


def finding(rule="VSL-VM-001", value=109, **kw):
    return {"rule_id":rule,"rule_name":"snapshot rule","title":"虚拟机存在超期快照","object_type":"VirtualMachine","object_name":"lab-vm","risk_level":"P1", "current_value":value,"observed_detail":{"current_value":value}, **kw}

def render_text(item):
    builder=HtmlReportPackageBuilder()
    return builder._customer_visible_findings([builder._customer_finding(item)])[0]["observed_detail_zh"]

def test_snapshot_age_survives_actual_customer_projection():
    text=render_text(finding())
    assert "最长保留时间：约 109 天" in text
    assert "未采集" not in text
    assert "快照名称" not in text and "占用大小" not in text

@pytest.mark.parametrize("value,expected",[(0,"0"),("109","109"),(1.5,"1.5")])
def test_snapshot_age_accepts_zero_and_valid_numeric_values(value,expected):
    assert f"约 {expected} 天" in render_text(finding(value=value))

@pytest.mark.parametrize("value",[None,"",-1,float("nan"),float("inf"),True,"unknown"])
def test_invalid_snapshot_age_not_invented(value):
    text=render_text(finding(value=value))
    assert " 天" not in text
    assert "明细待补充" in text
    assert "未采集" not in text

def test_snapshot_depth_cannot_be_rendered_as_age():
    text=render_text(finding(rule="VSL-VM-007",value=4))
    assert "4 天" not in text

def test_explicit_snapshot_age_path_supports_other_rule_id():
    item=finding(rule="CUSTOM-SNAP",source_path="snapshot_age_days_max",value=44)
    assert "44 天" in render_text(item)

def test_structured_snapshot_fields_preserved_and_deduplicated():
    detail={"snapshots":[{"name":"before-change","age_days":7,"size_gb":2,"chain_depth":3}]}
    item=finding(observed_detail=detail,raw_evidence={"observed_detail":detail})
    text=render_text(item)
    assert text.count("快照名称：before-change") == 1
    assert "约 7 天" in text and "快照占用大小" not in text and "快照链深度：3" in text
    assert "109 天" not in text

def test_multiple_snapshot_rules_do_not_convert_other_metrics_to_days():
    b=HtmlReportPackageBuilder()
    items=[b._customer_finding(finding()),b._customer_finding(finding(rule="VSL-VM-007",value=200))]
    text=b._merged_snapshot_item(items)["observed_detail_zh"]
    assert "109 天" in text and "200 天" not in text


def test_json_enrichment_source_conflict_does_not_abort_host():
    payload=json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload["commands"]["storage.core.adapter.list"]["data"]=[]
    host=NS(name="lab-host", hardware=NS(pciDevice=[NS(id="0000:18:00.0",classId=0x0200,vendorId=0x8086,deviceId=1,subVendorId=1,subDeviceId=1,deviceName="NIC")]),
            config=NS(network=NS(pnic=[NS(device="vmnic0",pci="0000:18:00.0",driver="igbn",driverVersion="1.0")]),storageDevice=NS(scsiLun=[],hostBusAdapter=[])))
    collector=PyVmomiPciCollector("offline","unused","unused",esxcli_provider=lambda _:CachedEsxcli(payload))
    records,warnings=collector._host_devices_with_warnings(host,"now")
    assert len(records)==1
    assert records[0]["driver_version"]=="1.4.11.7"
    assert records[0]["association_conflict"] is True
    assert any(w["status"]=="field_source_conflict" for w in warnings)
