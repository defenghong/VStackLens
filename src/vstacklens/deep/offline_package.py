from __future__ import annotations

import hashlib
import json
import re
import tempfile
import zipfile
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vstacklens.deep.analyzer import BUILTIN_DEEP_RULES, DeepAnalysisResult
from vstacklens.deep.contracts import DatasetRecord, DeepDataset, EvidenceReference, evidence_ref
from vstacklens.deep.dataset import DeepDatasetWriter


_SECRET_KEY = re.compile(r"(?i)(password|passwd|pwd|api[_-]?key|authorization|bearer|token|secret|cookie|credential|username|user_name)")
_SECRET_ASSIGNMENT = re.compile(
    r'''(?i)\b(password|passwd|pwd|api[_-]?key|authorization|token|secret|cookie|credential|username|user_name)\b\s*[:=]\s*(?:"(?P<double>[^"]*)"|'(?P<single>[^']*)'|(?P<bare>[^\s,;]+))'''
)
_BEARER = re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]+")


class DeepOfflineEvidencePackager:
    """Build a local, reviewable package from the exact Dataset and analysis result."""

    def build(
        self,
        dataset: DeepDataset,
        analysis: DeepAnalysisResult,
        output_dir: Path,
        *,
        supplemental_records: list[DatasetRecord] | None = None,
        model_analysis: dict[str, Any] | None = None,
        known_secrets: list[str] | tuple[str, ...] = (),
        project_checks: dict[str, Any] | None = None,
    ) -> Path:
        safe_dataset = _sanitize_tree(dataset.model_dump(mode="json"), known_secrets)
        safe_dataset = DeepDataset.model_validate(safe_dataset)
        safe_supplemental_records = [
            DatasetRecord.model_validate(_sanitize_tree(item.model_dump(mode="json"), known_secrets))
            for item in supplemental_records or []
        ]
        safe_diagnostic = _sanitize_tree(analysis.diagnostic.model_dump(mode="json"), known_secrets)
        safe_report = _sanitize_tree(analysis.report.model_dump(mode="json"), known_secrets)
        safe_model_analysis = _sanitize_tree(model_analysis or {}, known_secrets)
        derived_evidence = [
            _sanitize_tree(item.model_dump(mode="json"), known_secrets)
            for rule in analysis.rule_results
            for item in rule.derived_evidence
        ]
        matrix = self._rule_matrix(safe_dataset, analysis, safe_supplemental_records)
        scope = self._scope_summary(safe_dataset, safe_diagnostic, safe_supplemental_records)

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        package_path = _unique_path(output_dir / f"deep-evidence-{safe_dataset.dataset_id}.zip")
        with tempfile.TemporaryDirectory(prefix="vstacklens-deep-package-") as temp_text:
            stage = Path(temp_text)
            (stage / "evidence").mkdir()
            (stage / "dataset.json").write_text(
                json.dumps(safe_dataset.model_dump(mode="json"), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            (stage / "deep-diagnostic.json").write_text(
                json.dumps(safe_diagnostic, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            (stage / "deep-report-payload.json").write_text(
                json.dumps(safe_report, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            (stage / "model-analysis.json").write_text(
                json.dumps(safe_model_analysis, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            (stage / "analysis-scope.json").write_text(
                json.dumps(_sanitize_tree(scope, known_secrets), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            (stage / "rule-evidence-matrix.json").write_text(
                json.dumps(_sanitize_tree(matrix, known_secrets), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            evidence_root = stage / "evidence" / "portable-dataset"
            DeepDatasetWriter().write(safe_dataset, evidence_root, supplemental_records=safe_supplemental_records)
            if derived_evidence:
                derived_path = stage / "evidence" / "derived" / "trend.ndjson"
                derived_path.parent.mkdir(parents=True, exist_ok=True)
                derived_path.write_text(
                    "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in derived_evidence),
                    encoding="utf-8",
                )
            integrity_check = _check_reference_integrity(safe_dataset, analysis, safe_supplemental_records)
            correlation_check = _check_log_event_references(safe_dataset)
            base_checks = {
                "dataset_schema_validation": "passed",
                "portable_dataset_written": evidence_root.is_dir(),
                "rule_evidence_reference_check": integrity_check,
                "log_event_reference_check": correlation_check,
                "dataset_record_count": len(safe_dataset.records),
                "derived_evidence_record_count": len(derived_evidence),
                "project_code_checks": project_checks or {
                    "state": "not_embedded",
                    "reason": "运行期证据包不代替开发阶段的定向测试和项目全量测试结果。",
                },
                "package_secret_scan": "pending",
            }
            (stage / "code-check-results.json").write_text(
                json.dumps(_sanitize_tree(base_checks, known_secrets), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            (stage / "README.md").write_text(
                _readme(safe_dataset, scope, safe_model_analysis),
                encoding="utf-8",
            )
            (stage / "ANALYSIS-PROMPT.md").write_text(_analysis_prompt(), encoding="utf-8")

            secret_hits = _scan_secret_material(stage, known_secrets)
            if secret_hits:
                raise ValueError("Deep evidence package contains credential-like material; package was not created.")
            checks_path = stage / "code-check-results.json"
            checks = json.loads(checks_path.read_text(encoding="utf-8"))
            checks["package_secret_scan"] = "passed"
            checks_path.write_text(json.dumps(checks, ensure_ascii=False, indent=2), encoding="utf-8")

            files: list[dict[str, Any]] = []
            for path in sorted(stage.rglob("*")):
                if not path.is_file():
                    continue
                relative = path.relative_to(stage).as_posix()
                data = path.read_bytes()
                files.append({"path": relative, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
            manifest = {
                "schema_version": 1,
                "artifact_type": "local_deep_inspection_evidence",
                "dataset_id": safe_dataset.dataset_id,
                "created_at_utc": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                "upload_performed": False,
                "credentials_included": False,
                "actual_record_count": len(safe_dataset.records),
                "files": files,
            }
            (stage / "package-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
            file_list = ["文件清单（文件大小 / SHA-256）", ""]
            file_list.extend(f"{item['path']}  {item['bytes']} bytes  {item['sha256']}" for item in files)
            (stage / "FILE-LIST.txt").write_text("\n".join(file_list) + "\n", encoding="utf-8")
            with zipfile.ZipFile(package_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
                for path in sorted(stage.rglob("*")):
                    if path.is_file():
                        archive.write(path, path.relative_to(stage).as_posix())
        with zipfile.ZipFile(package_path) as archive:
            bad_member = archive.testzip()
            if bad_member:
                package_path.unlink(missing_ok=True)
                raise ValueError("Deep evidence package ZIP validation failed.")
        return package_path

    @staticmethod
    def _rule_matrix(
        dataset: DeepDataset,
        analysis: DeepAnalysisResult,
        supplemental_records: list[DatasetRecord] | None = None,
    ) -> dict[str, Any]:
        from vstacklens.deep.contracts import DeepRuleDefinition
        policy = analysis.diagnostic.analysis_provenance.get("used_policy") or {}
        rules_by_id = {item["rule_id"]: DeepRuleDefinition.model_validate(item) for item in policy.get("rules", [])}
        records_by_ref: dict[str, Any] = {}
        derived_by_ref: dict[str, EvidenceReference] = {}
        for record in [*dataset.records, *(supplemental_records or [])]:
            try:
                ref = evidence_ref(record).ref
            except Exception:  # noqa: BLE001 - one malformed record must not erase the rest of the matrix.
                continue
            records_by_ref.setdefault(ref, record)
        for result in analysis.rule_results:
            for evidence in result.derived_evidence:
                derived_by_ref.setdefault(evidence.ref, evidence)

        rows: list[dict[str, Any]] = []
        for result in analysis.rule_results:
            rule = rules_by_id.get(result.rule_id)
            actual: list[dict[str, Any]] = []
            missing_pointers: list[str] = []
            for ref in result.evidence_refs:
                record = records_by_ref.get(ref)
                if record is None:
                    derived = derived_by_ref.get(ref)
                    if derived is None:
                        missing_pointers.append(ref)
                        continue
                    actual.append(
                        {
                            "evidence_ref": ref,
                            "kind": derived.kind,
                            "source_api": derived.source.api,
                            "object": derived.entity.display_ref or derived.entity.stable_id,
                            "time_window_utc": {
                                "start": derived.window.start,
                                "end": derived.window.end,
                                "sample_count": derived.window.sample_count,
                            },
                            "raw_pointer": derived.raw_pointer,
                            "derived": True,
                            "derivation": list(derived.derivation),
                        }
                    )
                    continue
                actual.append(
                    {
                        "evidence_ref": ref,
                        "kind": record.kind,
                        "source_api": record.source.api,
                        "object": record.entity.display_ref or record.entity.stable_id,
                        "time_window_utc": {
                            "start": record.window.start,
                            "end": record.window.end,
                            "sample_count": record.window.sample_count,
                        },
                        "raw_pointer": record.raw_pointer,
                    }
                )
            status = result.status.value
            if status == "FINDING" and result.category.value == "current_risk":
                interpretation = "采集时的规则触发证据；只反映此 Dataset 的采集时点。"
                evidence_state = "CURRENT_AT_COLLECTION"
            elif status == "FINDING":
                interpretation = "历史或趋势风险线索；不能单独证明采集时仍持续。"
                evidence_state = "RISK_CLUE_UNVERIFIED"
            elif status == "PASS":
                interpretation = "本规则在当前输入范围内未触发；不代表未覆盖范围正常。"
                evidence_state = "NOT_TRIGGERED_IN_SCOPE"
            elif status in {"INSUFFICIENT_DATA", "NOT_EVALUATED", "ERROR"}:
                interpretation = "无法判断；缺失或失败状态不能解释为正常。"
                evidence_state = "UNABLE_TO_JUDGE"
            elif status == "NOT_APPLICABLE":
                interpretation = "仅表示本规则对当前环境不适用，需查看能力和环境条件。"
                evidence_state = "NOT_APPLICABLE"
            else:
                interpretation = "保留规则原始状态，不扩展为总体健康结论。"
                evidence_state = "UNABLE_TO_JUDGE"
            rows.append(
                {
                    "check_id": result.rule_id,
                    "check_title": rule.title if rule else result.rule_id,
                    "rule_version": result.rule_version,
                    "rule_definition_source": "ANALYSIS_USED_POLICY" if rule else "UNAVAILABLE",
                    "rule_definition": rule.model_dump(mode="json") if rule else None,
                    "object_evaluations": [item.model_dump(mode="json") for item in result.object_results],
                    "category": result.category.value,
                    "required_data": {
                        "record_kind": rule.record_kind if rule else None,
                        "capabilities": list(rule.requires) if rule else [],
                        "analysis_kind": rule.analysis_kind if rule else None,
                    },
                    "actual_data": actual,
                    "actual_evidence_ref_count": len(result.evidence_refs),
                    "unresolved_evidence_refs": missing_pointers,
                    "analysis_result": status,
                    "evidence_state": evidence_state,
                    "analysis_interpretation": interpretation,
                    "missing_capabilities": list(result.missing_capabilities),
                    "reason": result.reason,
                }
            )
        return {
            "source_dataset_id": dataset.dataset_id,
            "analysis_provenance": analysis.diagnostic.analysis_provenance,
            "check_count": len(rows),
            "checks": rows,
            "legend": {
                "FINDING": "触发证据存在；依据 category 区分采集时风险或历史/趋势线索。",
                "PASS": "只表示该规则在本次输入范围内未触发。",
                "INSUFFICIENT_DATA": "数据不满足规则的证据门槛，不是健康结论。",
                "NOT_EVALUATED": "本次没有执行该规则。",
                "UNAVAILABLE": "来源接口、权限或版本不支持，具体原因见能力和采集记录。",
            },
        }

    @staticmethod
    def _scope_summary(
        dataset: DeepDataset,
        diagnostic: dict[str, Any],
        supplemental_records: list[DatasetRecord] | None = None,
    ) -> dict[str, Any]:
        kind_counts = Counter(record.kind for record in dataset.records)
        supplemental_kind_counts = Counter(record.kind for record in supplemental_records or [])
        windows: dict[str, dict[str, Any]] = {}
        log_windows: dict[str, dict[str, Any]] = {}
        correlation_levels: Counter[str] = Counter()
        correlation_sample_count = 0
        for record in [*dataset.records, *(supplemental_records or [])]:
            if record.window.sample_count <= 0:
                continue
            if record.kind == "log":
                category = str(record.selector.get("category") or record.metadata.get("log_category") or "unknown")
                key = f"{category} | {record.entity.display_ref or record.entity.stable_id}"
                _extend_window(log_windows, key, record.window.start, record.window.end, record.window.sample_count)
                for level, count in (record.metadata.get("related_event_evidence_counts") or {}).items():
                    correlation_levels[str(level)] += int(count or 0)
                samples = record.metadata.get("related_event_samples")
                if isinstance(samples, list):
                    correlation_sample_count += len(samples)
            _extend_window(windows, record.kind, record.window.start, record.window.end, record.window.sample_count)

        capability_rows = [
            {
                "id": item.id,
                "name": item.name,
                "status": item.status.value,
                "detected_via": item.detected_via,
                "detail": _sanitize_tree(item.detail),
                "affects_rules": list(item.affects_rules),
            }
            for item in dataset.capability.capabilities
        ]
        actions = diagnostic.get("collection_log", []) if isinstance(diagnostic, dict) else []
        return {
            "dataset_id": dataset.dataset_id,
            "collected_at_utc": dataset.manifest.created_at_utc,
            "target_scope": _sanitize_tree(dataset.manifest.scope),
            "time_windows": _sanitize_tree(dataset.manifest.time_windows),
            "record_counts_by_kind": dict(sorted(kind_counts.items())),
            "supplemental_history_record_counts_by_kind": dict(sorted(supplemental_kind_counts.items())),
            "observed_sample_windows_by_kind": windows,
            "observed_sample_windows_by_log_category_and_object": log_windows,
            "log_event_correlation": {
                "evidence_level_counts": dict(sorted(correlation_levels.items())),
                "saved_related_event_sample_count": correlation_sample_count,
            },
            "note_on_time_ranges": "这些是已取得样本的起止时间，不表示中间连续覆盖。",
            "capabilities": capability_rows,
            "finding_lifecycle_history": _sanitize_tree(diagnostic.get("finding_lifecycle_history") or {}),
            "collection_actions": [
                {
                    "action": item.get("action"),
                    "status": item.get("status"),
                    "source": item.get("source"),
                    "reason": item.get("reason") or item.get("detail") or "",
                }
                for item in actions
                if isinstance(item, dict)
            ],
        }


def _extend_window(target: dict[str, dict[str, Any]], key: str, start: str, end: str, samples: int) -> None:
    row = target.setdefault(
        key,
        {"start_utc": start, "end_utc": end, "sample_count": 0, "continuity": "unknown"},
    )
    if start < row["start_utc"]:
        row["start_utc"] = start
    if end > row["end_utc"]:
        row["end_utc"] = end
    row["sample_count"] += int(samples or 0)


def _check_reference_integrity(
    dataset: DeepDataset,
    analysis: DeepAnalysisResult,
    supplemental_records: list[DatasetRecord] | None = None,
) -> dict[str, Any]:
    available = set()
    for record in [*dataset.records, *(supplemental_records or [])]:
        try:
            available.add(evidence_ref(record).ref)
        except Exception:  # noqa: BLE001
            continue
    requested = [ref for rule in analysis.rule_results for ref in rule.evidence_refs]
    derived_evidence = [item for rule in analysis.rule_results for item in rule.derived_evidence]
    derived_refs = {item.ref for item in derived_evidence}
    unresolved = sorted(set(requested) - available - derived_refs)
    derived_inputs = [ref for item in derived_evidence for ref in item.derivation]
    unresolved_derived_inputs = sorted(set(derived_inputs) - available)
    return {
        "requested_reference_count": len(requested),
        "resolved_reference_count": len(requested) - len(unresolved),
        "unresolved_reference_count": len(unresolved),
        "unresolved_references": unresolved[:100],
        "derived_evidence_count": len(derived_evidence),
        "derived_provenance_reference_count": len(derived_inputs),
        "unresolved_derived_provenance_count": len(unresolved_derived_inputs),
        "unresolved_derived_provenance": unresolved_derived_inputs[:100],
        "status": "passed" if not unresolved and not unresolved_derived_inputs else "partial",
    }


def _check_log_event_references(dataset: DeepDataset) -> dict[str, Any]:
    event_records = {
        record.raw_pointer: record
        for record in dataset.records
        if record.kind == "event" and record.raw_pointer
    }
    sample_count = 0
    pointerless_count = 0
    pointer_resolved_count = 0
    exact_event_sample_resolved_count = 0
    unresolved_pointers: list[str] = []
    source_line_reference_count = 0
    source_line_resolved_count = 0
    for log_record in dataset.records:
        if log_record.kind != "log":
            continue
        samples = log_record.metadata.get("related_event_samples")
        if not isinstance(samples, list):
            continue
        line_numbers = {
            int(value)
            for value in (log_record.metadata.get("source_line_numbers") or [])
            if str(value).isdigit()
        }
        for sample in samples:
            if not isinstance(sample, dict):
                continue
            sample_count += 1
            source_line = sample.get("source_line_number")
            if source_line is not None:
                source_line_reference_count += 1
                if _source_line_reference_resolves(log_record, sample, line_numbers):
                    source_line_resolved_count += 1
            pointer = str(sample.get("dataset_pointer") or "")
            if not pointer:
                pointerless_count += 1
                continue
            event_record = event_records.get(pointer)
            if event_record is None:
                unresolved_pointers.append(pointer)
                continue
            pointer_resolved_count += 1
            sample_event_key = str(sample.get("event_key") or "")
            sample_timestamp = _normalized_timestamp(sample.get("timestamp"))
            event_samples = event_record.metadata.get("event_samples")
            if not isinstance(event_samples, list):
                continue
            for event_sample in event_samples:
                if not isinstance(event_sample, dict):
                    continue
                if str(event_sample.get("event_key") or "") != sample_event_key:
                    continue
                if _normalized_timestamp(event_sample.get("timestamp")) != sample_timestamp:
                    continue
                exact_event_sample_resolved_count += 1
                break
    unresolved_unique = sorted(set(unresolved_pointers))
    if unresolved_unique or pointerless_count:
        status = "partial"
    elif sample_count and exact_event_sample_resolved_count + pointerless_count < sample_count:
        status = "partial"
    else:
        status = "passed"
    return {
        "status": status,
        "saved_related_event_sample_count": sample_count,
        "pointerless_count": pointerless_count,
        "pointer_resolved_to_dataset_event_record_count": pointer_resolved_count,
        "exact_event_key_and_time_match_count": exact_event_sample_resolved_count,
        "source_line_reference_count": source_line_reference_count,
        "source_line_resolved_count": source_line_resolved_count,
        "unresolved_dataset_pointers": unresolved_unique[:100],
        "note": "A pointer is considered event-specific only when the target event Dataset record contains the same Event Key and timestamp. Pointerless samples remain explicit and are not assigned a substitute location.",
    }


def _source_line_reference_resolves(record: DatasetRecord, sample: dict[str, Any], known_lines: set[int]) -> bool:
    try:
        wanted = int(sample.get("source_line_number"))
    except (TypeError, ValueError):
        return False
    if wanted in known_lines:
        return True
    try:
        line_index = int(sample.get("log_line_index"))
    except (TypeError, ValueError):
        return False
    ranges = record.metadata.get("source_line_ranges")
    if not isinstance(ranges, list):
        return False
    for item in ranges:
        if not isinstance(item, dict):
            continue
        try:
            record_start = int(item["record_line_start"])
            record_end = int(item["record_line_end"])
            source_start = int(item["source_line_start"])
        except (KeyError, TypeError, ValueError):
            continue
        if record_start <= line_index <= record_end:
            return source_start + line_index - record_start == wanted
    return False


def _normalized_timestamp(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    except ValueError:
        return text


def _sanitize_tree(value: Any, known_secrets: list[str] | tuple[str, ...] = ()) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _sanitize_tree(item, known_secrets)
            for key, item in value.items()
            if not _SECRET_KEY.search(str(key))
        }
    if isinstance(value, list):
        return [_sanitize_tree(item, known_secrets) for item in value]
    if isinstance(value, tuple):
        return [_sanitize_tree(item, known_secrets) for item in value]
    if isinstance(value, str):
        text = value
        for secret in known_secrets:
            if secret:
                text = re.sub(re.escape(secret), "[已隐藏]", text, flags=re.IGNORECASE)
        text = _BEARER.sub("Bearer [已隐藏]", text)
        text = _SECRET_ASSIGNMENT.sub(lambda match: f"{match.group(1)}=[已隐藏]", text)
        text = re.sub(r"(?i)(https?://)[^/@\s:]+:[^/@\s]+@", r"\1[已隐藏]@", text)
        return text
    return value


def _scan_secret_material(root: Path, known_secrets: list[str] | tuple[str, ...]) -> list[str]:
    matches: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            matches.append(path.name)
            continue
        if path.suffix.lower() == ".json":
            try:
                candidates = list(_string_values(json.loads(text)))
            except json.JSONDecodeError:
                candidates = [text]
        elif path.suffix.lower() == ".ndjson":
            try:
                candidates = [
                    value
                    for line in text.splitlines()
                    for value in _string_values(json.loads(line))
                ]
            except json.JSONDecodeError:
                candidates = [text]
        else:
            candidates = [text]
        if any(
            secret and secret.casefold() in candidate.casefold()
            for secret in known_secrets
            for candidate in candidates
        ):
            matches.append(path.name)
            continue
        redaction_markers = {"[已隐藏]", "[redacted]", "***"}
        assignment_leak = False
        bearer_leak = False
        for candidate in candidates:
            if _BEARER.search(candidate):
                bearer_leak = True
            for match in _SECRET_ASSIGNMENT.finditer(candidate):
                value = next(
                    (match.group(name) for name in ("double", "single", "bare") if match.group(name) is not None),
                    "",
                )
                cleaned_value = value.strip().strip("\"'").strip()
                if cleaned_value and cleaned_value.casefold() not in redaction_markers:
                    assignment_leak = True
                    break
        if bearer_leak or assignment_leak:
            matches.append(path.name)
    return matches


def _string_values(value: Any):
    if isinstance(value, dict):
        for child in value.values():
            yield from _string_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _string_values(child)
    elif isinstance(value, str):
        yield value


def _unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    for index in range(2, 10000):
        candidate = path.with_name(f"{path.stem}-{index}{path.suffix}")
        if not candidate.exists():
            return candidate
    raise RuntimeError("Could not allocate a unique Deep evidence package name.")


def _readme(dataset: DeepDataset, scope: dict[str, Any], model_analysis: dict[str, Any]) -> str:
    model_status = str(model_analysis.get("status") or "not_run")
    counts = ", ".join(f"{key}: {value}" for key, value in scope["record_counts_by_kind"].items()) or "无记录"
    gaps = [
        item for item in scope.get("capabilities", [])
        if item.get("status") not in {"AVAILABLE", "NOT_APPLICABLE"}
    ]
    gap_lines = [
        f"- {item.get('name') or item.get('id')}: {item.get('status')}（影响规则：{', '.join(item.get('affects_rules') or []) or '未标明'}）"
        for item in gaps
    ] or ["- 当前能力矩阵没有标记为 LIMITED、UNAVAILABLE 或 ERROR 的项。"]
    return "\n".join(
        [
            "# Deep 巡检本地证据包",
            "",
            "本 ZIP 在本机生成；生成过程没有上传数据。客户可自行决定是否、向谁提交。",
            "",
            "## 数据范围",
            "",
            f"- Dataset：{dataset.dataset_id}",
            f"- 采集时间：{dataset.manifest.created_at_utc}",
            f"- 对象范围：{json.dumps(scope.get('target_scope') or {}, ensure_ascii=False)}",
            f"- 记录类型与数量：{counts}",
            "- 日志、事件、任务和性能时间段按类别及对象分别列于 analysis-scope.json；起止时间不表示连续覆盖。",
            "",
            "## 文件说明",
            "",
            "- dataset.json：可重放的 Deep Dataset。",
            "- evidence/portable-dataset/：按对象类别拆分的完整证据文件；日志正文保留以便复查。",
            "- evidence/derived/trend.ndjson：代码计算的趋势证据及其输入引用；可沿 derivation 回到原始 Dataset/历史指标记录。",
            "- deep-diagnostic.json：能力状态、规则状态、采集动作及错误摘要。",
            "- deep-diagnostic.json 中的 finding_lifecycle_history：采集时风险、未核实的旧问题和有 PASS 证据确认解决的问题分别保留。",
            "- deep-report-payload.json：本次代码分析产生的结构化发现。",
            "- analysis-scope.json：实际对象范围、记录数量、日志类型时间段、能力和采集状态。",
            "- rule-evidence-matrix.json：每项检查需要的数据、实际证据引用、规则状态及未判断原因。",
            f"- model-analysis.json：按本地启用配置执行的模型补充分析状态为 {model_status}；其中引用已校验为本次提供的证据编号。",
            "- code-check-results.json：Dataset、证据引用和 ZIP 完整性检查；项目测试结果若已提供会单独列出。",
            "- ANALYSIS-PROMPT.md：可直接提交给其他模型的分析说明。",
            "- package-manifest.json 与 FILE-LIST.txt：文件大小和 SHA-256 清单。",
            "",
            "## 已知能力限制",
            "",
            *gap_lines,
            "",
            "未采集或不能判断的项不代表正常。模型解释不会改变代码计算的规则状态。",
            "Evidence 引用指向包内 Dataset 或真实原始指针；无法回查的引用会在矩阵中标记。",
            "",
        ]
    )


def _analysis_prompt() -> str:
    return """# 可直接提交的分析提示词

请基于本 ZIP 的 Deep Dataset、deep-report-payload.json、deep-diagnostic.json、analysis-scope.json 和 rule-evidence-matrix.json 进行独立复核。

要求：

1. 先读 README.md 与 analysis-scope.json，确认环境范围、采集时间、各类数据的真实覆盖范围和采集限制。
2. 不要把 PASS 扩展成环境整体健康；INSUFFICIENT_DATA、NOT_EVALUATED、UNAVAILABLE、部分采集和没有关联证据都不能解释为正常。
3. 将结论分为采集时仍有证据的问题、风险线索或待核实、已确认解决、无法判断。没有修复证据时，不要把旧问题标成已解决。
4. 每项判断列出对象、采集时状态、事实、实际 Evidence 引用、时间、来源、潜在影响、仍缺少的证据和下一步只读核查方法。
5. 仅在对象、时间和具体事件特征共同支持时关联日志、事件、任务和性能；不要按相同关键词或仅按时间接近推断同因。
6. 不创建文件、行号、Event Key、设备别名、时间戳或数据中不存在的事实。无法验证的内容应标为假设或未知。
7. 压缩包含有实际采集日志正文。不要复述无关敏感内容；不得猜测密码或认证信息。
8. 不要承诺预测全部故障或保证不会发生数据丢失。

请先列出证据覆盖和缺口，再按检查类别给出结论，最后列出优先的只读复核步骤。
"""
