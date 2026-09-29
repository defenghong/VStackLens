from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace as NS

from vstacklens.collection.pci_collector import PyVmomiPciCollector, SupportBundlePciCollector
from vstacklens.collection.collection_plan import CollectionPlan
from vstacklens.core.context import RunContext
from vstacklens.core.enums import DataQuality, RuleResultStatus
from vstacklens.db.connection import init_db
from vstacklens.hcl.matcher import HclMatcher, compare_driver_versions, sort_release_versions
from vstacklens.hcl.sources import VcgDataSource
from vstacklens.hcl.store import HclStore
from vstacklens.reports.upgrade_compat_report import build_conclusion_summary, render_upgrade_compat_html
from vstacklens.rules.plugins.hcl_compat import _STATUS_MAP


def _store(tmp_path: Path, releases: list[str], versions: list[str]) -> HclStore:
    db = tmp_path / "phase9.db"
    init_db(db, force=True)
    target = {"releaseVersion": "ESXi 8.0 U3", "certFeatures": [{"driverName": "i40en", "driverVersion": version} for version in versions]}
    forward = [{"releaseVersion": release, "certFeatures": [{"driverName": "i40en", "driverVersion": versions[0]}]} for release in releases if release != "ESXi 8.0 U3"]
    payload = {"releases": [{"releaseVersion": release} for release in releases], "iodevices": [{
        "productId": 9, "modelName": "Real X722", "deviceTypeName": "Network", "vid": "8086", "did": "1572", "svid": "1028", "ssid": "0001", "vcgLink": "https://example.test/9", "supportedReleases": ([target] if "ESXi 8.0 U3" in releases else []) + forward,
    }], "server": []}
    fixture = tmp_path / "vcg.json"
    fixture.write_text(json.dumps(payload), encoding="utf-8")
    conn = sqlite3.connect(db)
    store = HclStore(conn)
    store.ingest_source(VcgDataSource(fixture))
    return store


def test_numeric_driver_version_comparison_handles_shd_counterexamples() -> None:
    assert compare_driver_versions("17.00.13.00", "7.718.02.00") == 1
    assert compare_driver_versions("1.11.1.32", "2.4.2.0") == -1
    assert compare_driver_versions("2.4.2.0", "2.3.4.0") == 1
    assert compare_driver_versions("4.1.9.0", "4.1.15.0") == -1
    assert compare_driver_versions("2.4.2", "2.4.2.0") == 0
    assert compare_driver_versions("abc-xyz", "2.4.2.0") is None


def test_driver_statuses_distinguish_blocking_optional_and_uncomparable(tmp_path: Path) -> None:
    versions = ["2.4.2.0", "2.3.4.0", "2.2.7.0", "2.2.4.0"]
    matcher = HclMatcher(_store(tmp_path, ["ESXi 8.0 U3"], versions))
    common = (("8086", "1572", "1028", "0001"), "ESXi 8.0 U3", "i40en")
    assert matcher.match(*common, "1.11.1.32", "anything", category="nic").status == "DRIVER_VERSION_BELOW_MINIMUM"
    assert matcher.match(*common, "2.3.4.0", "anything", category="nic").status == "DRIVER_VERSION_NOT_LATEST"
    assert matcher.match(*common, "abc-xyz", "anything", category="nic").status == "DRIVER_VERSION_MISMATCH"
    assert _STATUS_MAP["DRIVER_VERSION_BELOW_MINIMUM"] == (RuleResultStatus.FAILED, DataQuality.COMPLETE)
    assert _STATUS_MAP["DRIVER_VERSION_NOT_LATEST"] == (RuleResultStatus.PASSED, DataQuality.COMPLETE)


def test_forward_support_is_sorted_and_reports_previous_ceiling(tmp_path: Path) -> None:
    releases = ["ESXi 9.0", "ESXi 8.0 U2", "ESXi 7.0 U3", "ESXi 8.0", "ESXi 8.0 U3"]
    assert sort_release_versions(releases) == ["ESXi 7.0 U3", "ESXi 8.0", "ESXi 8.0 U2", "ESXi 8.0 U3", "ESXi 9.0"]
    store = _store(tmp_path, ["ESXi 7.0 U3", "ESXi 8.0", "ESXi 8.0 U1", "ESXi 8.0 U2"], ["2.4.2.0"])
    result = HclMatcher(store).match(("8086", "1572", "1028", "0001"), "ESXi 8.0 U3", "i40en", "2.4.2.0", "x", category="nic", source="vcg")
    assert result.status == "NOT_CERTIFIED"
    assert result.supported_releases == ["ESXi 7.0 U3", "ESXi 8.0", "ESXi 8.0 U1", "ESXi 8.0 U2"]
    assert result.target_release_supported is False
    assert result.highest_supported_release == "ESXi 8.0 U2"
    assert result.higher_supported_releases == []


def test_empty_device_release_history_is_an_empty_list(tmp_path: Path) -> None:
    db = tmp_path / "empty.db"
    init_db(db, force=True)
    store = HclStore(sqlite3.connect(db))
    assert store.supported_releases_for_device("not-found") == []


def test_summary_groups_existing_results_without_reclassifying_them(tmp_path: Path) -> None:
    payload = {
        "server_results": [{"host": "esxi-1", "model": "Server", "status": "SERVER_NOT_CERTIFIED", "detail": "no", "candidate_links": []}],
        "device_results": [
            {"object_key": "a", "host": "esxi-1", "object_name": "X722", "matches": {"vcg": {"status": "DRIVER_VERSION_BELOW_MINIMUM", "detail": "low"}}, "vsan": {"status": "VSAN_CERTIFIED"}},
            {"object_key": "b", "host": "esxi-1", "object_name": "X710", "matches": {"vcg": {"status": "DRIVER_VERSION_NOT_LATEST", "detail": "optional"}}, "vsan": {"status": "VSAN_CERTIFIED"}},
            {"object_key": "c", "host": "esxi-1", "object_name": "Disk", "matches": {"vcg": {"status": "UNKNOWN_DEVICE", "detail": "manual"}}, "vsan": {"status": "VSAN_CONTEXT_UNKNOWN", "detail": "context missing"}},
        ],
    }
    groups = build_conclusion_summary(payload)
    assert len(groups["blocking"]) == 2
    assert [item["name"] for item in groups["recommended"]] == ["esxi-1 / X710"]
    assert len(groups["unknown"]) == 1
    payload.update({"metadata": {}, "data_versions": {}, "collection_warnings": []})
    index = render_upgrade_compat_html(payload, tmp_path / "report")
    text = index.read_text(encoding="utf-8")
    assert "升级前需处理" in text and "可直接升级 / 已通过" in text
    assert "驱动低于最低认证版本" in text
    assert "设备待人工核对" in text


def test_report_renders_empty_tier_and_missing_host_context_in_html(tmp_path: Path) -> None:
    payload = {
        "metadata": {"report_title": "Phase 9", "target_release": "ESXi 8.0 U3"},
        "data_versions": {}, "collection_warnings": [], "device_results": [],
        "server_results": [{"host": "esxi-01", "model": "Server", "status": "SERVER_CERTIFIED", "detail": "ok", "host_context": {}}],
    }
    html_path = render_upgrade_compat_html(payload, tmp_path / "html")
    html = html_path.read_text(encoding="utf-8")
    assert "台整机已认证" in html
    assert "未发现整机认证阻塞主机" in html
    assert "查看 0 个设备判定" in html
    assert "主机兼容性概览" in html and "受阻主机与整机型号判定" in html


def test_direct_collection_preserves_host_context_and_missing_fields_stay_none(tmp_path: Path) -> None:
    class Esxcli:
        def execute(self, command, _arguments):
            return {"storage.san.sas.list": [], "storage.san.fc.list": [], "storage.core.adapter.list": [], "network.nic.list": [], "software.vib.list": [], "storage.core.device.list": [], "vsan.storage.list": []}[command]
    host = NS(name="esxi-01", hardware=NS(pciDevice=[], systemInfo=NS(model="Model"), biosInfo=NS(biosVersion="BIOS-2", releaseDate="2020-01-02"), cpuInfo=NS(model="CPU", numCpuPackages=2, numCpuCores=32, numCpuThreads=64), cpuPkg=[NS(), NS()], memorySize=128 * 1024**3), summary=NS(quickStats=NS(uptime=93784), hardware=NS(cpuModel="CPU")), config=NS(network=NS(pnic=[]), storageDevice=NS(hostBusAdapter=[], scsiLun=[])), configManager=NS(kernelModuleSystem=NS(QueryModules=lambda: [])), parent=NS(name="Cluster", configurationEx=NS(vsanConfigInfo=NS(enabled=False))))
    collector = PyVmomiPciCollector("vc", "u", "p", esxcli_provider=lambda _host: Esxcli())
    collector._host_devices(host, "now")
    row = collector._host_records[0]
    assert row["bios_version"] == "BIOS-2" and row["cpu_sockets"] == 2 and row["memory_bytes"] == 128 * 1024**3
    assert row["uptime_seconds"] == 93784
    assert row.get("nonexistent") is None


def test_support_bundle_collection_has_no_invented_host_context(tmp_path: Path) -> None:
    result = SupportBundlePciCollector(tmp_path / "missing-bundle.tgz").collect(
        RunContext("phase9", "upgrade", "upgrade", "bundle", tmp_path / "phase9.db"),
        CollectionPlan(),
    )
    assert result.get("host_records", []) == []
    assert result["collection_warnings"][0]["status"] == "bundle_read_failed"
