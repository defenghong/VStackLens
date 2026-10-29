from __future__ import annotations

import json
import zipfile
from pathlib import Path

from vstacklens.application.cloud_log_diagnosis import CloudModelConfig, CloudModelResult
from vstacklens.deep.analyzer import DeepAnalyzer
from vstacklens.deep.contracts import DeepDataset, DeepSource, DeepWindow, DatasetRecord
from vstacklens.deep.model_assistant import DeepModelAssistant, load_configured_model
from vstacklens.deep.offline_package import DeepOfflineEvidencePackager
from vstacklens.deep.logs import validate_log_event_references


FIXTURE = Path(__file__).parent / "fixtures" / "deep_dataset_trend.json"


def _analysis():
    dataset = DeepDataset.from_json(FIXTURE)
    analysis = DeepAnalyzer().analyze(dataset)
    analysis.findings = analysis.findings[:1]
    return dataset, analysis


def test_deep_model_assist_is_off_by_default_and_local_only_blocks_calls(tmp_path: Path) -> None:
    settings = tmp_path / "desktop_config.json"
    settings.write_text(
        json.dumps(
            {
                "security_privacy_level": "local-only",
                "model_config_profiles": [
                    {
                        "profile_id": "lab",
                        "provider": "configured-provider",
                        "api_url": "https://model.example/v1/chat/completions",
                        "default_model": "configured-model",
                        "api_key": "configured-secret",
                        "is_default": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    disabled, disabled_state = load_configured_model(enabled=False, config_path=settings)
    blocked, blocked_state = load_configured_model(enabled=True, config_path=settings)

    assert disabled is None and disabled_state == "not_enabled"
    assert blocked is None and blocked_state == "blocked_by_local_only_policy"


def test_deep_model_assist_reports_unconfigured_without_calling_a_service(tmp_path: Path) -> None:
    missing_path = tmp_path / "missing-config.json"
    config, state = load_configured_model(enabled=True, config_path=missing_path)
    dataset, analysis = _analysis()
    result = DeepModelAssistant().analyze(
        dataset,
        analysis,
        enabled=True,
        config=config,
        unavailable_reason=state,
    )

    assert config is None
    assert state == "not_configured"
    assert result["status"] == "not_configured"
    assert result["api_call_attempted"] is False
    assert result["request_count"] == 0


def test_deep_model_assist_uses_scoped_evidence_and_accepts_only_real_refs(monkeypatch) -> None:
    dataset, analysis = _analysis()
    prompts: list[str] = []

    class FakeClient:
        def __init__(self, config: CloudModelConfig) -> None:
            assert config.provider == "customer-provider"

        def complete_json(self, prompt: str) -> CloudModelResult:
            prompts.append(prompt)
            body = json.loads(prompt)
            assert len(body["evidence"]) >= 1
            assert len(body["finding"]["scope"]) > 0
            return CloudModelResult(
                True,
                content={
                    "supported_interpretation": "给定证据支持这条规则的采集时事实。",
                    "evidence_refs": ["E01"],
                    "possible_causes": [
                        {
                            "text": "该差异可能与计划内变更有关，仍待核实。",
                            "evidence_refs": ["E01"],
                            "confidence": "low",
                        }
                    ],
                    "impact": {"text": "影响需要结合对象用途核实。", "evidence_refs": ["E01"]},
                    "missing_evidence": ["尚缺变更窗口记录。"],
                    "read_only_checks": ["只读核对 vCenter 中对应对象的当前配置。"],
                },
                response_received=True,
            )

    import vstacklens.deep.model_assistant as module

    monkeypatch.setattr(module, "CloudModelClient", FakeClient)
    result = DeepModelAssistant().analyze(
        dataset,
        analysis,
        enabled=True,
        config=CloudModelConfig(provider="customer-provider", api_url="https://model.example", model_name="m", api_key="key"),
    )

    assert len(prompts) == 1
    assert result["status"] == "succeeded"
    assert result["api_call_attempted"] is True
    assert result["items"][0]["status"] == "accepted"
    assert result["items"][0]["analysis"]["evidence_refs"][0].startswith("ev:")
    assert "key" not in json.dumps(result)


def test_deep_model_assist_rejects_unknown_evidence_references_and_health_claims(monkeypatch) -> None:
    dataset, analysis = _analysis()

    class FakeClient:
        def __init__(self, _config: CloudModelConfig) -> None:
            pass

        def complete_json(self, _prompt: str) -> CloudModelResult:
            return CloudModelResult(
                True,
                content={
                    "supported_interpretation": "检查通过，环境正常运行。",
                    "evidence_refs": ["E999"],
                    "possible_causes": [],
                    "missing_evidence": [],
                    "read_only_checks": [],
                },
                response_received=True,
            )

    import vstacklens.deep.model_assistant as module

    monkeypatch.setattr(module, "CloudModelClient", FakeClient)
    result = DeepModelAssistant().analyze(
        dataset,
        analysis,
        enabled=True,
        config=CloudModelConfig(api_url="https://model.example", model_name="m", api_key="synthetic-secret"),
    )

    assert result["status"] == "failed"
    assert result["rejected_count"] == 1
    assert result["items"][0]["status"] == "rejected"
    assert "synthetic-secret" not in json.dumps(result)


def test_deep_model_assist_rejects_a_health_claim_even_with_an_existing_reference(monkeypatch) -> None:
    dataset, analysis = _analysis()

    class FakeClient:
        def __init__(self, _config: CloudModelConfig) -> None:
            pass

        def complete_json(self, _prompt: str) -> CloudModelResult:
            return CloudModelResult(
                True,
                content={
                    "supported_interpretation": "当前环境检查通过，运行正常。",
                    "evidence_refs": ["E01"],
                    "possible_causes": [],
                    "missing_evidence": [],
                    "read_only_checks": [],
                },
                response_received=True,
            )

    import vstacklens.deep.model_assistant as module

    monkeypatch.setattr(module, "CloudModelClient", FakeClient)
    result = DeepModelAssistant().analyze(
        dataset,
        analysis,
        enabled=True,
        config=CloudModelConfig(api_url="https://model.example", model_name="m", api_key="key"),
    )

    assert result["rejected_count"] == 1
    assert "健康结论" in result["items"][0]["validation_reason"]


def test_deep_model_failure_is_recorded_without_provider_switch(monkeypatch) -> None:
    dataset, analysis = _analysis()
    calls: list[str] = []

    class FakeClient:
        def __init__(self, config: CloudModelConfig) -> None:
            calls.append(config.provider)

        def complete_json(self, _prompt: str) -> CloudModelResult:
            return CloudModelResult(False, fallback_reason="HTTP 401: invalid", response_received=False)

    import vstacklens.deep.model_assistant as module

    monkeypatch.setattr(module, "CloudModelClient", FakeClient)
    result = DeepModelAssistant().analyze(
        dataset,
        analysis,
        enabled=True,
        config=CloudModelConfig(provider="only-this-provider", api_url="https://model.example", model_name="m", api_key="key"),
    )

    assert calls == ["only-this-provider"]
    assert result["status"] == "failed"
    assert result["failed_count"] == 1
    assert result["items"][0]["failure_reason"]


def test_model_failure_keeps_an_offline_evidence_zip(tmp_path: Path, monkeypatch) -> None:
    source_dataset = DeepDataset.from_json(FIXTURE)
    input_path = tmp_path / "source.dataset.json"
    input_path.write_text(source_dataset.model_dump_json(indent=2), encoding="utf-8")
    calls: list[str] = []

    class FakeClient:
        def __init__(self, config: CloudModelConfig) -> None:
            calls.append(config.provider)

        def complete_json(self, _prompt: str) -> CloudModelResult:
            return CloudModelResult(False, fallback_reason="configured endpoint unavailable")

    import vstacklens.deep.model_assistant as module

    monkeypatch.setattr(module, "CloudModelClient", FakeClient)
    from vstacklens.deep.service import DeepInspectionService

    run = DeepInspectionService().analyze_dataset(
        input_path,
        tmp_path / "report",
        model_enabled=True,
        model_config=CloudModelConfig(
            provider="customer-endpoint",
            api_url="https://model.example/v1/chat/completions",
            model_name="customer-model",
            api_key="synthetic-api-key",
        ),
    )

    assert calls and set(calls) == {"customer-endpoint"}
    assert run.model_analysis_status == "failed"
    assert run.offline_evidence_package_status == "created"
    assert run.offline_evidence_zip and run.offline_evidence_zip.is_file()
    with zipfile.ZipFile(run.offline_evidence_zip) as archive:
        model_analysis = json.loads(archive.read("model-analysis.json"))
        assert model_analysis["status"] == "failed"
        assert b"synthetic-api-key" not in b"\n".join(archive.read(name) for name in archive.namelist())


def test_local_evidence_zip_contains_full_dataset_and_prompt_without_secrets(tmp_path: Path) -> None:
    dataset, analysis = _analysis()
    dataset.records[0].summary += " username=synthetic-user password=synthetic-password owner=SYNTHETIC-USER"
    dataset.records[0].metadata["root_status"] = "green"
    timestamp = dataset.manifest.created_at_utc
    dataset.records.append(
        DatasetRecord(
            record_id="test-log",
            dataset_id=dataset.dataset_id,
            kind="log",
            entity=dataset.records[0].entity,
            collected_at_utc=timestamp,
            source=DeepSource(api="fixture.log.read", collector="test"),
            selector={"category": "vmkernel"},
            window=DeepWindow(start=timestamp, end=timestamp, sample_count=1),
            value={"status": "ok", "lines": ["2026-01-01T00:00:00Z error synthetic-value=visible"]},
            raw_pointer="logs/log.ndjson#fixture/vmkernel",
            metadata={"source_line_numbers": [42]},
        )
    )
    analysis = DeepAnalyzer().analyze(dataset)
    archive_path = DeepOfflineEvidencePackager().build(
        dataset,
        analysis,
        tmp_path,
        known_secrets=["synthetic-user", "synthetic-password", "synthetic-model-key", "root"],
        project_checks={"focused_tests": "passed", "full_suite": "passed"},
    )

    assert archive_path.exists()
    with zipfile.ZipFile(archive_path) as archive:
        assert archive.testzip() is None
        names = set(archive.namelist())
        assert "dataset.json" in names
        assert "deep-diagnostic.json" in names
        assert "rule-evidence-matrix.json" in names
        assert "analysis-scope.json" in names
        assert "ANALYSIS-PROMPT.md" in names
        assert "FILE-LIST.txt" in names
        assert any(name.endswith("/logs/log.ndjson") for name in names)
        assert "evidence/derived/trend.ndjson" in names
        combined = b"\n".join(archive.read(name) for name in names if not name.endswith("/"))
        assert b"synthetic-user" not in combined
        assert b"synthetic-password" not in combined
        assert b"SYNTHETIC-USER" not in combined
        assert b"synthetic-model-key" not in combined
        checks = json.loads(archive.read("code-check-results.json"))
        assert checks["package_secret_scan"] == "passed"
        assert checks["derived_evidence_record_count"] >= 1
        assert checks["rule_evidence_reference_check"]["status"] == "passed"
        assert checks["rule_evidence_reference_check"]["unresolved_reference_count"] == 0
        assert checks["project_code_checks"]["focused_tests"] == "passed"


def test_event_pointer_requires_same_saved_event_key_time_and_object() -> None:
    dataset = DeepDataset.from_json(FIXTURE)
    entity = dataset.records[0].entity
    timestamp = "2026-01-01T00:00:00Z"
    event_pointer = "events/event.ndjson#fixture/host-a"
    dataset.records.extend(
        [
            DatasetRecord(
                record_id="event-aggregate",
                dataset_id=dataset.dataset_id,
                kind="event",
                entity=entity,
                collected_at_utc=timestamp,
                source=DeepSource(api="EventManager.QueryEvents", collector="test"),
                selector={"rule_id": "fixture"},
                window=DeepWindow(start=timestamp, end=timestamp, sample_count=1),
                value=1,
                raw_pointer=event_pointer,
                metadata={
                    "event_samples": [
                        {
                            "event_key": 77,
                            "timestamp": timestamp,
                            "resolved_entities": [{"stable_id": entity.stable_id}],
                        }
                    ]
                },
            ),
            DatasetRecord(
                record_id="event-linked-log",
                dataset_id=dataset.dataset_id,
                kind="log",
                entity=entity,
                collected_at_utc=timestamp,
                source=DeepSource(api="ESXi.vobd", collector="test"),
                selector={"category": "vobd"},
                window=DeepWindow(start=timestamp, end=timestamp, sample_count=1),
                value={"lines": ["2026-01-01T00:00:00Z vmnic1 linkstate down"]},
                raw_pointer="logs/log.ndjson#host-a/vobd",
                metadata={
                    "source_line_ranges": [
                        {
                            "record_line_start": 1,
                            "record_line_end": 1,
                            "source_line_start": 40,
                            "source_line_end": 40,
                        }
                    ],
                    "related_event_samples": [
                        {
                            "timestamp": timestamp,
                            "event_key": 77,
                            "dataset_pointer": event_pointer,
                            "matched_object_id": entity.stable_id,
                            "log_line_index": 1,
                            "source_line_number": 40,
                        },
                        {
                            "timestamp": timestamp,
                            "event_key": 78,
                            "dataset_pointer": event_pointer,
                            "matched_object_id": entity.stable_id,
                            "log_line_index": 1,
                            "source_line_number": 40,
                        },
                    ],
                },
            ),
        ]
    )

    result = validate_log_event_references(dataset)
    samples = dataset.records[-1].metadata["related_event_samples"]

    assert result["verified_pointer_count"] == 1
    assert result["removed_unverified_pointer_count"] == 1
    assert result["verified_source_line_count"] == 2
    assert samples[0]["dataset_pointer"] == event_pointer
    assert samples[0]["event_source_api"] == "EventManager.QueryEvents"
    assert "dataset_pointer" not in samples[1]
    assert samples[1]["dataset_pointer_validation"] == "removed_not_event_specific"
