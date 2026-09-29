from __future__ import annotations

from lxml import html as lxml_html
from pathlib import Path

from vstacklens.reports.upgrade_compat_report import REMEDIATIONS, render_upgrade_compat_html


def test_html_report_keeps_dual_source_results_and_all_ambiguous_links(tmp_path: Path) -> None:
    payload = {
        "metadata": {"report_title": "升级报告", "customer_name": "测试", "target_release": "ESXi 8.0 U3", "collection_source": "support bundle"},
        "data_versions": {"vcg": {"label": "VCG", "json_updated_time": "2026-08-01", "downloaded_at": "2026-08-23", "record_count": 3, "freshness": "FRESH"}, "vsan_hcl": {"label": "vSAN HCL", "json_updated_time": "2026-08-01", "downloaded_at": "2026-08-23", "record_count": 3, "freshness": "FRESH"}},
        "server_results": [{"model": "Server", "status": "SERVER_MODEL_AMBIGUOUS", "detail": "不一致", "candidate_links": ["https://example.test/s1", "https://example.test/s2"]}],
        "device_results": [{"object_name": "Disk", "host": "esxi-01", "category": "ssd", "driver_name": None, "firmware_version": None, "matches": {"vcg": {"status": "AMBIGUOUS_DEVICE", "vcglink": "https://example.test/1"}, "vsan_hcl": {"status": "VSAN_NOT_IN_HCL", "vcglink": "https://example.test/2"}}, "vsan": {"status": "VSAN_NOT_IN_HCL", "detail": "not in hcl"}, "candidate_links": ["https://example.test/1", "https://example.test/2"], "alias_matched": False}],
        "collection_warnings": [],
    }
    index = render_upgrade_compat_html(payload, tmp_path / "report-package")
    text = index.read_text(encoding="utf-8")
    assert text.index("整机型号判定") < text.index("设备兼容性明细")
    assert "VCG" in text and "vSAN HCL" in text
    for url in ("https://example.test/1", "https://example.test/2", "https://example.test/s1", "https://example.test/s2"):
        assert url in text
    assert "离线数据使用边界" in text
    assert "Support bundle 路径字段完整度低于直连 vCenter" in text


def test_required_unknown_statuses_have_distinct_remediations() -> None:
    assert len(REMEDIATIONS) >= 10
    assert len(set(REMEDIATIONS.values())) == len(REMEDIATIONS)


def test_report_never_emits_a_truncated_integrity_link_and_prints_all_details(tmp_path: Path) -> None:
    payload = {
        "metadata": {"target_release": "ESXi 8.0 U3"},
        "summary": {"server_total": 1},
        "server_results": [{"host": "esxi-01", "model": "Server", "status": "SERVER_CERTIFIED", "host_context": {}}],
        "device_results": [],
        "collection_warnings": [{"host": "esxi-01", "status": "esxcli_unavailable"}],
        "data_versions": {},
    }
    text = render_upgrade_compat_html(payload, tmp_path / "report").read_text(encoding="utf-8")

    document = lxml_html.fromstring(text)
    assert document.xpath('//*[@id="readiness"]')
    assert document.xpath('//section[@id="data-integrity"]//a[@href="#device-detail"]')
    assert 'href=\n' not in text
    assert 'details:not([open])>*:not(summary){display:block!important}' in (tmp_path / "report" / "assets" / "report.css").read_text(encoding="utf-8")


def test_report_marks_unanimous_vib_source_version_as_inferred_and_avoids_false_upgrade_ready(tmp_path: Path) -> None:
    devices = [{
        "host": "esxi-01", "object_name": "I350", "category": "nic", "driver_name": "igbn",
        "driver_version": "1.5.2.0-1vmw.803.0.0.24022510", "matches": {"vcg": {"status": "CERTIFIED"}},
    }]
    payload = {
        "metadata": {"target_release": "ESXi 8.0 U3"},
        "summary": {"server_total": 1, "passed": 1, "failed": 0, "unknown": 0},
        "server_results": [{"host": "esxi-01", "model": "Server", "status": "SERVER_CERTIFIED", "host_context": {}}],
        "device_results": devices,
        "collection_warnings": [],
        "data_versions": {},
    }
    text = render_upgrade_compat_html(payload, tmp_path / "report").read_text(encoding="utf-8")

    assert "ESXi 8.0 U3" in text
    assert "VIB 构建号推断，待复核" in text
    assert "已在目标版本；不列为升级对象" in text
    assert ">0</strong><span>台可升级</span>" in text


def test_ambiguous_driver_shows_cross_host_minimum_version_hint(tmp_path: Path) -> None:
    devices = [
        {"host": "esxi-01", "object_name": "I350", "category": "nic", "driver_name": "igbn", "driver_version": "1.4.11.7", "matches": {"vcg": {"status": "DRIVER_VERSION_BELOW_MINIMUM", "certified_driver_versions": ["1.5.2.0"]}}},
        {"host": "esxi-02", "object_name": "I350 rNDC", "category": "nic", "driver_name": "igbn", "driver_version": "1.4.11.7", "matches": {"vcg": {"status": "AMBIGUOUS_DEVICE"}}},
    ]
    payload = {"metadata": {"target_release": "ESXi 8.0 U3"}, "summary": {"server_total": 2}, "server_results": [], "device_results": devices, "collection_warnings": [], "data_versions": {}}
    text = render_upgrade_compat_html(payload, tmp_path / "report").read_text(encoding="utf-8")

    assert "交叉提示：同驱动" in text
    assert "esxi-01 已判定低于最低认证版本 1.5.2.0" in text


def test_report_flags_conflicting_legacy_storage_associations_without_dropping_evidence(tmp_path: Path) -> None:
    devices = [
        {"host": "esxi-01", "object_name": "Disk", "model": "MZILT1T6HAJQ0D3", "category": "ssd", "driver_name": "lsi_msgpt3", "driver_version": "17.0", "firmware_version": "DWF8", "matches": {"vcg": {"status": "MODEL_NOT_MATCHED"}}},
        {"host": "esxi-01", "object_name": "Disk", "model": "MZILT1T6HAJQ0D3", "category": "ssd", "driver_name": "vmw_ahci", "driver_version": "2.0", "firmware_version": "DWF8", "matches": {"vcg": {"status": "MODEL_NOT_MATCHED"}}},
    ]
    payload = {"metadata": {"target_release": "ESXi 8.0 U3"}, "summary": {"server_total": 1}, "server_results": [], "device_results": devices, "collection_warnings": [], "data_versions": {}}
    text = render_upgrade_compat_html(payload, tmp_path / "report").read_text(encoding="utf-8")

    assert "检测到 1 组疑似重复的存储关联" in text
    assert "报告保留原始证据但不应据此估计精确磁盘数量" in text
    assert "mzilt1t6hajq0d3" in text


def test_upgrade_report_uses_payload_summary_and_keeps_driver_and_firmware_separate(tmp_path: Path) -> None:
    devices = [
        {
            "object_key": f"esxi-01:pci:{slot}", "host": "esxi-01", "object_name": "I350", "model": "I350", "category": "nic",
            "driver_name": "igbn", "driver_version": "1.4.11.7", "firmware_version": "1.67.0:0x80000fb5:18.8.9",
            "matches": {"vcg": {"status": "DRIVER_VERSION_BELOW_MINIMUM", "certified_driver_versions": ["1.5.2.0", "1.12.0.0"], "highest_forward_release": "ESXi 9.1"}},
            "vsan": {"status": "VSAN_NOT_APPLICABLE"},
        }
        for slot in (97, 98)
    ]
    devices.append(
        {
            "object_key": "esxi-02:pci:20", "host": "esxi-02", "object_name": "BCM5720", "model": "BCM5720", "category": "nic",
            "driver_name": "ntg3", "driver_version": "4.1.15.0-4vmw", "firmware_version": None,
            "matches": {"vcg": {"status": "DRIVER_VERSION_NOT_LATEST", "certified_driver_versions": ["4.1.9.0", "4.1.16.0"], "highest_forward_release": "ESXi 9.1"}},
            "vsan": {"status": "VSAN_NOT_APPLICABLE"},
        }
    )
    payload = {
        "metadata": {"target_release": "ESXi 8.0 U3", "generated_at": "2026-09-01T12:00:00+08:00"},
        "summary": {"total": 58, "passed": 17, "failed": 8, "unknown": 33, "server_total": 5, "server_blocked": 2},
        "server_results": [{"host": "esxi-01", "model": "Server", "status": "SERVER_NOT_CERTIFIED", "detail": "no"}],
        "device_results": devices,
        "collection_warnings": [{"host": "esxi-01", "status": "esxcli_unavailable"}],
        "data_versions": {},
    }
    index = render_upgrade_compat_html(payload, tmp_path / "package")
    text = index.read_text(encoding="utf-8")
    assert ">✓ 17 已通过</button>" in text
    assert ">! 8 需处理</button>" in text
    assert ">? 33 待确认</button>" in text
    assert "主机兼容性概览" in text
    assert "采集质量提示" in text
    assert "host-summary-card" in text
    assert "data-open-host" in text
    assert "data-device-filter=\"issues\"" in text
    assert "左右滑动可查看全部设备证据列" in text
    assert "当前 1.4.11.7" in text
    assert "1.67.0:0x80000fb5:18.8.9" in text
    assert "需 &gt;= 1.5.2.0" in text
    assert "影响 2 个端口/设备" in text
    assert "可直接升级 / 已通过" in text
    assert "<th scope=\"col\">vSAN 专项</th>" not in text
    assert "当前 1.4.11.7" in text
    assert "1.67.0:0x80000fb5:18.8.9" in text
