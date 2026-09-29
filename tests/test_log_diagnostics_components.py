from __future__ import annotations

import zipfile

from vstacklens.application import LogAnalysisConfig
from vstacklens.application.log_analysis_service import LogAnalysisCloudRequiredError, LogAnalysisService
from vstacklens.application.log_diagnostics.problem_parser import ProblemParser
from vstacklens.application.log_diagnostics.scenarios import scenario_title
from vstacklens.application.log_diagnostics.timeline import TimelineBuilder
from vstacklens.reports.log_analysis_report import _esc


def test_timeline_builder_sorts_mixed_datetime_formats() -> None:
    diagnosis = {
        "evidence_chain": [
            {"file": "a.log", "location": "line 1", "message": "2024-01-01T12:00:00Z first"},
            {"file": "b.log", "location": "line 2", "message": "2024/01/01 12:00:01 second"},
            {"file": "c.log", "location": "line 3", "message": "12:34:56 local-time"},
            {"file": "d.log", "location": "line 4", "message": "12:34:56.123 local-time-ms"},
            {"file": "e.log", "location": "line 5", "message": "2024-01-01T12:00:00+05:00 timezone-shift"},
            {"file": "f.log", "location": "line 6", "message": "2024-01-01 12:00:02 third"},
            {"file": "g.log", "location": "line 7", "message": "not-a-time fallback"},
        ]
    }

    timeline = TimelineBuilder().build(diagnosis, max_events=10)

    assert [item["event"] for item in timeline] == [
        "2024-01-01T12:00:00+05:00 timezone-shift",
        "2024-01-01T12:00:00Z first",
        "2024/01/01 12:00:01 second",
        "2024-01-01 12:00:02 third",
        "12:34:56 local-time",
        "12:34:56.123 local-time-ms",
    ]


def test_problem_parser_filters_object_noise_and_keeps_real_objects() -> None:
    profile = ProblemParser().parse(
        "After network failed for esx-host-01 on vmnic3 and vmk2, host 10.240.3.20 could not reach naa.6000 and SQL-0001-000001.vmdk."
    )

    assert profile["primary_object"] == "esx-host-01"
    assert "the" not in profile["objects"]
    assert "after" not in profile["objects"]
    assert "failed" not in profile["objects"]
    assert "network" not in profile["objects"]
    assert "esx-host-01" in profile["objects"]
    assert "vmnic3" in profile["objects"]
    assert "vmk2" in profile["objects"]
    assert "10.240.3.20" in profile["objects"]
    assert "naa.6000" in profile["objects"]
    assert "SQL-0001-000001.vmdk" in profile["objects"]


def test_problem_parser_domain_boundary_avoids_substring_noise() -> None:
    parser = ProblemParser()

    noisy = parser.parse("The descending order failed after maintenance.")
    assert "存储" not in noisy["domains"]

    storage = parser.parse("SCSI path to naa.6000 is unreachable on vmhba64.")
    assert "存储" in storage["domains"]

    vsan = parser.parse("vSAN clomd cmmds reports degraded objects.")
    assert "vSAN" in vsan["domains"]


def test_html_escape_preserves_zero_and_false_values() -> None:
    assert _esc(0) == "0"
    assert _esc(False) == "False"
    assert _esc(None) == ""
    assert _esc("<tag>") == "&lt;tag&gt;"


def test_rank_cloud_sources_uses_precomputed_fields_without_scanning_text() -> None:
    service = LogAnalysisService()
    sources = [
        {"component": "network", "keyword_total": 10, "has_arp_conflict": False, "path": "b.log", "text": object()},
        {"component": "vmkernel", "keyword_total": 1, "has_arp_conflict": True, "path": "a.log", "text": object()},
    ]

    ranked = service._rank_cloud_sources(sources)

    assert [item["path"] for item in ranked] == ["a.log", "b.log"]


def test_scenario_registry_exposes_titles_without_rewiring_dispatch() -> None:
    assert scenario_title("snapshot_consolidation_failure", "fallback") == "快照整合失败诊断报告"
    assert scenario_title("vm_migration_network_loss", "fallback") == "在线迁移后虚拟机网络不通诊断报告"
    assert scenario_title("unknown", "fallback") == "fallback"


def test_cloud_strict_mode_still_raises_on_downgraded_quality(monkeypatch, tmp_path) -> None:
    from vstacklens.application.cloud_log_diagnosis import CloudModelClient, CloudModelResult

    bundle = tmp_path / "vmware-support.zip"
    with zipfile.ZipFile(bundle, "w") as archive:
        archive.writestr("manifest.txt", "support bundle manifest")

    def fake_complete_json(self, prompt):
        return CloudModelResult(True, content={"requests": []}, response_received=True)

    def fake_diagnose(self, prompt):
        return CloudModelResult(
            True,
            content={
                "mode": "diagnosis",
                "current_judgement": "当前日志线索与客户问题存在关联，建议进一步核对。",
                "likely_causes": ["继续核对"],
                "evidence_chain": [],
                "evidence_reasoning": [],
                "cannot_confirm": ["不能确认根因"],
                "missing_materials": ["缺少更多材料"],
            },
            response_received=True,
        )

    monkeypatch.setattr(CloudModelClient, "complete_json", fake_complete_json)
    monkeypatch.setattr(CloudModelClient, "diagnose", fake_diagnose)

    try:
        LogAnalysisService().run(
            LogAnalysisConfig(
                support_bundle_path=bundle,
                problem_description="客户反馈业务虚拟机偶发网络不通，需要分析日志。",
                db_path=tmp_path / "log-analysis.db",
                report_output_dir=tmp_path / "reports",
                cloud_assist_enabled=True,
                cloud_require_accepted_result=True,
                cloud_api_key="sk-secret-api-key",
            )
        )
    except LogAnalysisCloudRequiredError:
        return

    raise AssertionError("strict cloud mode should raise when cloud output is downgraded")
