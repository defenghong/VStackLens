from __future__ import annotations
import json
from pathlib import Path
import time
from types import SimpleNamespace as NS
import pytest

from vstacklens.application.artifact_publish import staged_report
from vstacklens.application.collection_settings import CollectionSettings
from vstacklens.collection.powercli_backend import PowerCliBackend, CachedEsxcli, BackendUnavailable
from vstacklens.hcl.matcher import HclMatcher
from vstacklens.reports.health_status import assess_health
from vstacklens.reports.upgrade_compat_report import _link, _host_readiness, render_upgrade_compat_html
from vstacklens.upgrade_compat.decision import effective_match

class Store:
    def get_device(self, *a, **k): return [{"hcl_device_id": "one", "vcglink": None}]
    def supported_releases_for_device(self, *a): return ["ESXi 8.0 U3"]
    def release_rows(self, *a):
        return [dict(driver_name="drv", driver_version=v, firmware_version="10.0") for v in ("1.0", "3.0")]

@pytest.mark.parametrize("version", ["2.0", "4.0"])
def test_unlisted_driver_never_passes_without_firmware(version):
    result = HclMatcher(Store()).match(("1", "2", "3", "4"), "ESXi 8.0 U3", "drv", version, None)
    assert result.status == "DRIVER_VERSION_UNLISTED"

@pytest.mark.parametrize("firmware,expected", [(None,"FIRMWARE_UNKNOWN"),("9.0","FIRMWARE_MISMATCH"),("10.0","CERTIFIED")])
def test_exact_driver_still_requires_same_firmware(firmware, expected):
    result = HclMatcher(Store()).match(("1", "2", "3", "4"), "ESXi 8.0 U3", "drv", "3.0", firmware)
    assert result.status == expected

@pytest.mark.parametrize("risk,label", [({},"健康"),({"P3":1},"正常"),({"P2":1},"关注"),({"P1":1},"危险")])
def test_health_labels_do_not_depend_on_numeric_scores(risk,label):
    assert assess_health(risk,{"passed":10},2)["label"] == label

def test_optional_gap_does_not_make_healthy_report_unavailable():
    assert assess_health({}, {"passed":10,"unavailable":99}, 2, 0)["label"] == "健康"

def test_critical_gap_cannot_be_healthy():
    assert assess_health({}, {"passed":10,"unavailable":1}, 2, 1)["label"] == "评估受限"

def test_existing_customer_files_never_deleted(tmp_path):
    parent=tmp_path/"customer"; parent.mkdir()
    document=parent/"contract.txt"; document.write_text("keep")
    with staged_report(parent) as (stage, target):
        (stage/"index.html").write_text("complete")
        assert not target.exists()
    assert document.read_text() == "keep"
    assert (target/"index.html").read_text() == "complete"

def test_failed_report_is_not_published(tmp_path):
    dest=tmp_path/"new"
    with pytest.raises(RuntimeError):
        with staged_report(dest) as (stage,target):
            (stage/"partial").write_text("bad")
            raise RuntimeError("render failed")
    assert not dest.exists()
    assert not list(tmp_path.glob(".vstacklens-stage-*"))

@pytest.mark.parametrize("url", ["javascript:alert(1)","data:text/html,test","file:///c:/secret","//example.test"])
def test_report_links_reject_non_web_protocols(url):
    assert _link(url) == ""

def test_vsan_failure_propagates_without_overwriting_evidence():
    d={"matches":{"vcg":{"status":"CERTIFIED"}}, "vsan":{"status":"VSAN_MODE_MISMATCH"}}
    assert effective_match(d)["status"] == "VSAN_MODE_MISMATCH"
    assert d["matches"]["vcg"]["status"] == "CERTIFIED"
    hosts=_host_readiness([{"host":"h","status":"SERVER_CERTIFIED"}], [{"host":"h",**d}], "ESXi 8.0 U3")
    assert hosts[0]["group"] != "ready"

def test_server_without_devices_is_not_upgrade_ready():
    assert _host_readiness([{"host":"h","status":"SERVER_CERTIFIED"}],[],"ESXi 8.0 U3")[0]["group"] != "ready"

def test_cached_command_failure_is_not_empty_success():
    adapter=CachedEsxcli({"commands":{"network.nic.list":{"status":"permission_denied","data":[]}}})
    with pytest.raises(BackendUnavailable): adapter.execute("network.nic.list")

def test_cached_nic_query_uses_explicit_nic_identity():
    adapter=CachedEsxcli({"commands":{"network.nic.get:vmnic0":{"status":"ok","data":[{"Driver":"x"}]}}})
    assert adapter.execute("network.nic.get", {"nicname":"vmnic0"}) == [{"Driver":"x"}]
    with pytest.raises(BackendUnavailable): adapter.execute("network.nic.get", {"nicname":"vmnic1"})

def test_backend_missing_runtime_fails_explicitly(tmp_path):
    with pytest.raises(BackendUnavailable,match="runtime_missing"):
        PowerCliBackend("vc","u","p",runtime_dir=tmp_path).prepare([])

def test_settings_created_without_credentials_and_bad_values_safe(tmp_path):
    path=tmp_path/"config.json"
    assert CollectionSettings.load(path).batch_size == 10
    assert "password" not in path.read_text()
    path.write_text('{"batch_size":200,"host_timeout":-1}')
    cfg=CollectionSettings.load(path)
    assert cfg.batch_size == 10 and cfg.host_timeout == 180
    path.write_text("broken")
    assert CollectionSettings.load(path).request_timeout == 30
    assert path.read_text() == "broken"

def test_default_factory_injects_backend(monkeypatch, tmp_path):
    from vstacklens.application.upgrade_compat_service import UpgradeCompatService, UpgradeCompatConfig
    monkeypatch.setenv("LOCALAPPDATA",str(tmp_path))
    c=UpgradeCompatService()._default_collector(UpgradeCompatConfig(vcenter_host="vc",username="u",password="secret"))
    assert isinstance(c.esxcli_provider, PowerCliBackend)

def test_report_print_restores_interactive_state(tmp_path):
    p=render_upgrade_compat_html({"metadata":{},"device_results":[],"server_results":[]},tmp_path/"report")
    script=(p.parent/"assets/report.js").read_text(encoding="utf-8")
    assert "beforeprint" in script and "afterprint" in script
    assert "rows.forEach(r=>r.hidden=false)" in script


def test_explicit_attributed_range_includes_intermediate_pair():
    class RangeStore(Store):
        def release_rows(self, *args):
            return [dict(driver_name="drv", driver_version="1.0", firmware_version="10.0",
                         driver_spec_json=json.dumps({"compatibility_ranges": {
                             "driver":{"min":"1.0","max":"3.0","source":"vendor document"},
                             "firmware":{"min":"10.0","max":"12.0","source":"vendor document"}}}))]
    matcher=HclMatcher(RangeStore())
    common=(("1","2","3","4"),"ESXi 8.0 U3","drv")
    assert matcher.match(*common,"2.0","11.0").status == "CERTIFIED"
    assert matcher.match(*common,"2.0",None).status == "FIRMWARE_UNKNOWN"
    assert matcher.match(*common,"4.0","11.0").status == "DRIVER_VERSION_UNLISTED"

def test_unattributed_range_never_authorizes_pass():
    from vstacklens.hcl.matcher import explicit_version_range_matches
    row={"driver_spec_json":json.dumps({"compatibility_ranges":{"driver":{"min":"1.0"}}})}
    assert not explicit_version_range_matches(row,"driver","2.0")

@pytest.mark.parametrize("count", [5, 10, 11, 200])
def test_collection_batches_and_failed_hosts_are_preserved(monkeypatch, count):
    import pyVim.connect
    from vstacklens.collection.pci_collector import PyVmomiPciCollector
    from vstacklens.collection.collection_plan import CollectionPlan
    class Backend:
        warnings=[]
        batches=[]
        def prepare(self, hosts): self.batches.append(len(hosts))
    backend=Backend(); backend.batches=[]
    hosts=[NS(name=f"h{i}",_moId=f"host-{i}") for i in range(count)]
    c=PyVmomiPciCollector("vc","u","p",esxcli_provider=backend)
    c._collect_view=lambda *_: hosts
    def read_host(host, stamp):
        if host.name == "h1": raise TimeoutError()
        return [{"host":host.name}]
    c._host_devices=read_host
    monkeypatch.setattr(pyVim.connect,"SmartConnect",lambda **kw:NS(RetrieveContent=lambda:NS(about=NS(version="8.0",build="1"))))
    monkeypatch.setattr(pyVim.connect,"Disconnect",lambda *_:None)
    data=c.collect(None,CollectionPlan())
    assert sum(backend.batches) == count and max(backend.batches) <= 10
    assert len(data["objects"]) == count-1
    assert any(w.get("host")=="h1" for w in data["collection_warnings"])
    assert any(h.get("host")=="h1" for h in data["host_records"])

def test_bridge_credentials_only_in_stdin(monkeypatch,tmp_path):
    import vstacklens.collection.powercli_backend as module
    (tmp_path/"powershell").mkdir(); (tmp_path/"powershell/pwsh.exe").touch()
    seen={}
    class Process:
        returncode=0
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def communicate(self,input=None,timeout=None):
            seen["request"]=json.loads(input)
            return '{"schema_version":1,"hosts":[],"warnings":[],"log_file_attempt_count":2}', ''
    def popen(args,**kw):
        seen["args"]=args; seen["env"]=kw["env"]; return Process()
    monkeypatch.setattr(module.subprocess,"Popen",popen)
    backend=PowerCliBackend("vc","user","SECRET-WITH-QUOTES-;",runtime_dir=tmp_path)
    backend.prepare([NS(_moId="host-1",name="esx-1")], log_keys_by_host={"host-1":["hostd"]}, vcenter_log_keys=[], max_log_files=2, max_log_file_bytes=1024, max_log_total_bytes=2048)
    assert seen["request"]["password"] == "SECRET-WITH-QUOTES-;"
    assert seen["request"]["log_keys_by_host"] == {"host-1":["hostd"]}
    assert seen["request"]["vcenter_log_keys"] == []
    assert seen["request"]["max_log_files"] == 2
    assert seen["request"]["max_log_file_bytes"] == 1024
    assert seen["request"]["max_log_total_bytes"] == 2048
    assert backend.log_file_attempt_count == 2
    assert "SECRET-WITH-QUOTES-;" not in str(seen["args"])+str(seen["env"])
    assert "-NonInteractive" in seen["args"]

@pytest.mark.parametrize(("cancel_requested", "timeout", "expected"), [(True, 30, "cancelled"), (False, 0.001, "timeout")])
def test_powercli_child_is_terminated_on_cancel_or_timeout(monkeypatch, tmp_path, cancel_requested, timeout, expected):
    import vstacklens.collection.powercli_backend as module
    (tmp_path/"powershell").mkdir(); (tmp_path/"powershell/pwsh.exe").touch()
    state = {"killed": False, "communicate_calls": 0}

    class Process:
        returncode = None
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def communicate(self, input=None, timeout=None):
            state["communicate_calls"] += 1
            if state["killed"]:
                return "", ""
            time.sleep(0.02)
            raise module.subprocess.TimeoutExpired("pwsh", timeout)
        def kill(self):
            state["killed"] = True

    monkeypatch.setattr(module.subprocess, "Popen", lambda *args, **kwargs: Process())
    backend = PowerCliBackend("vc", "u", "p", runtime_dir=tmp_path, timeout=timeout, cancel_requested=lambda: cancel_requested)
    with pytest.raises(BackendUnavailable, match=expected):
        backend.prepare([])
    assert state["killed"] is True
    assert state["communicate_calls"] == 2


def test_powercli_child_is_terminated_on_resource_guard(monkeypatch, tmp_path):
    import vstacklens.collection.powercli_backend as module
    (tmp_path / "powershell").mkdir()
    (tmp_path / "powershell/pwsh.exe").touch()
    state = {"killed": False, "communicate_calls": 0}

    class Process:
        returncode = None

        def __enter__(self): return self
        def __exit__(self, *args): pass

        def communicate(self, input=None, timeout=None):
            state["communicate_calls"] += 1
            if state["killed"]:
                return "", ""
            time.sleep(0.02)
            raise module.subprocess.TimeoutExpired("pwsh", timeout)

        def kill(self):
            state["killed"] = True

    monkeypatch.setattr(module.subprocess, "Popen", lambda *args, **kwargs: Process())
    backend = PowerCliBackend("vc", "u", "p", runtime_dir=tmp_path, stop_reason=lambda: "memory_limit_exceeded")
    with pytest.raises(BackendUnavailable, match="memory_limit_exceeded"):
        backend.prepare([])
    assert state["killed"] is True
    assert state["communicate_calls"] == 2

def test_print_and_xss_payload_preserved_as_text(tmp_path):
    payload={"metadata":{"report_title":"<script>alert(99)</script>"},"server_results":[],"device_results":[]}
    text=render_upgrade_compat_html(payload,tmp_path/"xss").read_text(encoding="utf-8")
    assert '<script>alert(99)</script>' not in text
    assert '&lt;script&gt;alert(99)&lt;/script&gt;' in text


def test_pnic_order_cannot_assign_driver_to_unrelated_pci_device():
    from vstacklens.collection.pci_collector import PyVmomiPciCollector
    pci=lambda address:NS(id=address,classId=0x0200,vendorId=0x8086,deviceId=1,subVendorId=1,subDeviceId=1,deviceName="NIC")
    host=NS(name="h",hardware=NS(pciDevice=[pci("0000:01:00.0"),pci("0000:02:00.0")]),
            config=NS(network=NS(pnic=[NS(pci="0000:02:00.0",driver="second",driverVersion="2.0"),NS(pci="0000:01:00.0",driver="first",driverVersion="1.0")]),storageDevice=NS(scsiLun=[])))
    rows=PyVmomiPciCollector("vc","u","p")._host_devices(host,"now")
    assert [r["driver_name"] for r in rows] == ["first","second"]
    assert rows[0]["object_key"].endswith("0000:01:00.0")
