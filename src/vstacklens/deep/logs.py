from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from vstacklens.deep.contracts import DatasetRecord, DeepEntity, DeepSource, DeepWindow


LOG_CATEGORIES = ("vmkernel", "hostd", "vpxa", "vobd", "syslog", "vsan", "ha")
VCENTER_LOG_CATEGORIES = ("vpxd",)
MAX_LOG_LINES_PER_PAGE = 200
MAX_LOG_LINE_CHARS = 4096
MAX_LOG_FILES = 64
MAX_LOG_FILE_BYTES = 1024 * 1024
MAX_LOG_TOTAL_BYTES = 16 * 1024 * 1024
MAX_LOG_PRIMARY_BYTES = 12 * 1024 * 1024
MAX_LOG_FALLBACK_BYTES = 4 * 1024 * 1024
HARD_MAX_LOG_TOTAL_BYTES = 20 * 1024 * 1024
HARD_MAX_LOG_PRIMARY_BYTES = 15 * 1024 * 1024
HARD_MAX_LOG_FALLBACK_BYTES = 5 * 1024 * 1024
# UTF-8 log lines retain at least one byte, so the existing per-file byte cap
# also provides a hard upper bound on retained line count.
MAX_LOG_LINES_PER_FILE = MAX_LOG_FILE_BYTES

_MARKERS = {
    "error": re.compile(r"\b(error|failed|failure|panic|exception)\b", re.IGNORECASE),
    "timeout": re.compile(r"\b(timeout|timed out)\b", re.IGNORECASE),
    "storage": re.compile(r"\b(apd|pdl|vmfs|device reset|path failure|storage disconnect)\b", re.IGNORECASE),
    "network": re.compile(r"\b(link down|linkstate|packet drop|nic error|pnic|uplink)\b", re.IGNORECASE),
    "performance": re.compile(r"\b(latency|congestion|queue|iops|throughput|drop)\b", re.IGNORECASE),
    "ha": re.compile(r"\b(fdm|failover|host unavailable|not protected|isolation)\b", re.IGNORECASE),
}
_SEMANTIC_PATTERNS = {
    "network": re.compile(r"\b(network|pnic|vmnic\d+|uplink|linkstate|link state|link (?:is )?(?:down|up)|packet drop|nic error)\b", re.IGNORECASE),
    "storage": re.compile(r"\b(apd|pdl|all paths down|permanent device loss|device reset|path failure|storage disconnect|vmfs|datastore path)\b", re.IGNORECASE),
    "performance": re.compile(r"\b(cpu ready|cpu usage|co-stop|balloon|swap|latency|congestion|queue|iops|throughput|packet drop)\b", re.IGNORECASE),
    "ha": re.compile(r"fdm|vSphere HA|ha failover|failover|host unavailable|host connection lost|host failed|isolation|not protected|ha restart", re.IGNORECASE),
    "compute": re.compile(r"\b(vmotion|v motion|migration|relocatevm|vm reset|guest reset|poweron failed|poweroff failed|vm restart)\b", re.IGNORECASE),
    "drs": re.compile(r"\b(drs|resource scheduling|migration recommendation)\b", re.IGNORECASE),
    "maintenance": re.compile(r"\b(entermaintenance|enter maintenance|maintenance mode)\b", re.IGNORECASE),
    "alarm": re.compile(r"alarmstatuschanged|\balarm\b|\b(triggered|activated|fired)\b", re.IGNORECASE),
}
_ISO_TIMESTAMP = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)")
_NETWORK_INTERFACE = re.compile(r"\b(?:vmnic|vmk)\d+\b", re.IGNORECASE)
_NETWORK_STATE_CONTEXT = re.compile(
    r"\b(?:link(?:state|\s+state)?|vmnic\d+|pnic\d*)\b.{0,80}?\b(down|up|lost|inactive|disconnected|restored|recovered|active|connected)\b",
    re.IGNORECASE,
)


def _network_signal_details(text: str) -> tuple[set[str], set[str]]:
    interfaces = {value.casefold() for value in _NETWORK_INTERFACE.findall(text)}
    states: set[str] = set()
    for match in _NETWORK_STATE_CONTEXT.finditer(text):
        token = match.group(1).casefold()
        states.add("down" if token in {"down", "lost", "inactive", "disconnected"} else "up")
    return interfaces, states


def _specific_signal_compatible(left_text: str, right_text: str, categories: set[str]) -> bool:
    """Reject coarse-category matches that contradict explicit network details."""
    if "network" not in categories:
        return True
    left_interfaces, left_states = _network_signal_details(left_text)
    right_interfaces, right_states = _network_signal_details(right_text)
    if left_interfaces and right_interfaces and not left_interfaces.intersection(right_interfaces):
        return False
    return not (left_states and right_states and not left_states.intersection(right_states))


def _preferred_event_rule_ids(rule_ids: set[str], categories: set[str]) -> list[str]:
    preferred_prefixes = {
        "network": ("NET-DEEP-002", "NET-DEEP-001", "ENHANCED-NET"),
        "storage": ("STO-DEEP-", "VSAN-DEEP-", "ENHANCED-STO"),
        "compute": ("COMPUTE-DEEP-",),
        "ha": ("CL-DEEP-002",),
        "drs": ("CL-DEEP-003",),
        "maintenance": ("CL-DEEP-006",),
        "alarm": ("CL-DEEP-007",),
    }
    for category in sorted(categories):
        for prefix in preferred_prefixes.get(category, ()):
            matches = sorted(rule_id for rule_id in rule_ids if rule_id.startswith(prefix))
            if matches:
                return matches
    return sorted(rule_ids)


def _semantic_categories(text: str, rule_id: str = "") -> set[str]:
    categories = {category for category, pattern in _SEMANTIC_PATTERNS.items() if pattern.search(text)}
    rule = str(rule_id or "").upper()
    if rule.startswith("NET-DEEP-") or "ENHANCED-NET" in rule:
        categories.add("network")
    if rule.startswith("STO-DEEP-") or rule.startswith("VSAN-DEEP-") or "ENHANCED-STO" in rule:
        categories.add("storage")
    if rule.startswith("COMPUTE-DEEP-"):
        categories.add("compute")
    if rule == "CL-DEEP-002":
        categories.add("ha")
    elif rule == "CL-DEEP-003":
        categories.add("drs")
    elif rule == "CL-DEEP-006":
        categories.add("maintenance")
    elif rule == "CL-DEEP-007":
        categories.add("alarm")
    if rule.startswith("ENHANCED-CPU-") or rule.startswith("ENHANCED-MEM-"):
        categories.add("performance")
    return categories


def _timestamp_epoch(value: str) -> float:
    timestamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    return timestamp.astimezone(UTC).timestamp()


def _timestamp_utc_iso(value: str) -> str:
    timestamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    return timestamp.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def classify_log_lines(lines: list[str]) -> dict[str, Any]:
    marker_counts: dict[str, int] = {key: 0 for key in _MARKERS}
    for line in lines:
        for key, pattern in _MARKERS.items():
            if pattern.search(line):
                marker_counts[key] += 1
    return {"line_count": len(lines), "marker_counts": marker_counts, "marked_line_count": sum(1 for value in marker_counts.values() if value)}


def log_category_for_descriptor(descriptor: Any, *, scope: str) -> str | None:
    info = getattr(descriptor, "info", None)
    text = " ".join(str(value or "") for value in (getattr(descriptor, "key", ""), getattr(descriptor, "fileName", ""), getattr(descriptor, "creator", ""), getattr(info, "label", ""), getattr(info, "summary", "")))
    lowered = text.casefold()
    if scope == "vcenter":
        return "vpxd" if any(item in lowered for item in ("vpxd", "vcenter server", "virtualcenter server")) else None
    if "fdm" in lowered or "fault domain manager" in lowered:
        return "ha"
    for category in ("vmkernel", "hostd", "vpxa", "vobd", "vsan", "syslog"):
        if category in lowered or (category == "syslog" and any(item in lowered for item in ("messages", "syslog"))):
            return category
    return None


def classify_log_fault(error: Exception) -> str:
    name = type(error).__name__.casefold()
    detail = str(getattr(error, "msg", "") or "").casefold()
    text = f"{name} {detail}"
    if "nopermission" in text or "permission" in text or "privilege" in text or "denied" in text:
        return "permission_denied"
    if "cannotaccessfile" in text or "file not found" in text or "nosuchfile" in text:
        return "file_unavailable"
    if "timeout" in text or "timed out" in text:
        return "timeout"
    if "invalidargument" in text or "unknown key" in text:
        return "interface_unavailable"
    return "error"


def timestamp_range(lines: list[str], fallback: str) -> tuple[str, str]:
    values: list[str] = []
    for line in lines:
        match = _ISO_TIMESTAMP.search(line)
        if not match:
            continue
        raw = match.group(1)
        if re.search(r"[+-]\d{4}$", raw):
            raw = raw[:-5] + raw[-5:-2] + ":" + raw[-2:]
        try:
            timestamp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=UTC)
            values.append(timestamp.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"))
        except ValueError:
            continue
    return (values[0], values[-1]) if values else (fallback, fallback)


def parse_log_line_timestamp(line: str) -> datetime | None:
    """Parse the first supported timestamp in a log line as aware UTC time."""
    match = _ISO_TIMESTAMP.search(str(line))
    if not match:
        return None
    raw = match.group(1)
    if re.search(r"[+-]\d{4}$", raw):
        raw = raw[:-5] + raw[-5:-2] + ":" + raw[-2:]
    try:
        value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _truncate_utf8(value: str, max_bytes: int) -> str:
    if max_bytes <= 0:
        return ""
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value
    return encoded[:max_bytes].decode("utf-8", errors="ignore")


def _compact_source_line_numbers(line_numbers: list[int | None]) -> list[dict[str, int]]:
    ranges: list[dict[str, int]] = []
    for record_line_number, source_line_number in enumerate(line_numbers, start=1):
        if source_line_number is None:
            continue
        source_line_number = int(source_line_number)
        if (
            ranges
            and record_line_number == ranges[-1]["record_line_end"] + 1
            and source_line_number == ranges[-1]["source_line_end"] + 1
        ):
            ranges[-1]["record_line_end"] = record_line_number
            ranges[-1]["source_line_end"] = source_line_number
        else:
            ranges.append(
                {
                    "record_line_start": record_line_number,
                    "record_line_end": record_line_number,
                    "source_line_start": source_line_number,
                    "source_line_end": source_line_number,
                }
            )
    return ranges


def _is_duplicate_source_line(
    prior_records: list[DatasetRecord],
    *,
    entity_id: str,
    category: str,
    source_line_number: int,
    line: str,
) -> bool:
    """Deduplicate only when object, category, source row, and content all agree."""
    for record in prior_records:
        if record.entity.stable_id != entity_id or str(record.metadata.get("log_category") or "") != category:
            continue
        prior_lines = list((record.value or {}).get("lines") or [])
        for line_range in record.metadata.get("source_line_ranges") or []:
            source_start = int(line_range.get("source_line_start") or 0)
            source_end = int(line_range.get("source_line_end") or -1)
            if not source_start <= source_line_number <= source_end:
                continue
            record_start = int(line_range.get("record_line_start") or 1)
            prior_index = record_start + source_line_number - source_start - 1
            if 0 <= prior_index < len(prior_lines) and prior_lines[prior_index] == line:
                return True
    return False


def normalize_powercli_logs(
    *,
    dataset_id: str,
    entity: DeepEntity,
    collected_at: str,
    payloads: list[dict[str, Any]],
    max_file_bytes: int = MAX_LOG_FILE_BYTES,
    byte_budget: dict[str, Any] | None = None,
    max_lines: int = MAX_LOG_LINES_PER_FILE,
    log_window_cutoff_utc: datetime | None = None,
    log_window_days: int | None = None,
) -> list[DatasetRecord]:
    records: list[DatasetRecord] = []
    budget = byte_budget if byte_budget is not None else {"used_bytes": 0, "probe_bytes": 0, "max_bytes": MAX_LOG_TOTAL_BYTES}
    dedupe_records = budget.setdefault("dedupe_records", [])
    log_window_cutoff_utc = log_window_cutoff_utc or budget.get("log_window_cutoff_utc")
    log_window_days = log_window_days or budget.get("log_window_days")
    max_total_bytes = max(0, int(budget.get("max_bytes", MAX_LOG_TOTAL_BYTES)))
    max_file_bytes = max(0, int(max_file_bytes))
    for payload in payloads:
        category = str(payload.get("key") or payload.get("category") or "unknown")
        status = str(payload.get("status") or "error")
        source_name = str(payload.get("source") or "PowerCLI.Get-Log")
        source_tag = "powercli" if "PowerCLI" in source_name else "diagnostic_api" if "DiagnosticManager" in source_name else "other"
        raw_lines = [str(line) for line in payload.get("lines") or []]
        source_input_bytes = sum(len(line.encode("utf-8")) for line in raw_lines)
        payload_line_numbers = payload.get("source_line_numbers")
        if not isinstance(payload_line_numbers, (list, tuple)):
            payload_line_numbers = []
        payload_line_start = payload.get("line_start")
        try:
            payload_line_start = int(payload_line_start) if payload_line_start is not None else None
        except (TypeError, ValueError):
            payload_line_start = None
        source_line_numbers: list[int | None] = []
        for raw_index in range(len(raw_lines)):
            try:
                line_number = int(payload_line_numbers[raw_index]) if raw_index < len(payload_line_numbers) and payload_line_numbers[raw_index] is not None else None
            except (TypeError, ValueError):
                line_number = None
            if line_number is None and payload_line_start is not None:
                line_number = payload_line_start + raw_index
            source_line_numbers.append(line_number)
        filtered_lines: list[str] = []
        filtered_line_numbers: list[int | None] = []
        time_window_excluded_line_count = 0
        time_unknown_line_count = 0
        for raw_index, line in enumerate(raw_lines):
            timestamp = parse_log_line_timestamp(line)
            if log_window_cutoff_utc is not None and timestamp is not None and timestamp < log_window_cutoff_utc:
                time_window_excluded_line_count += 1
                continue
            if timestamp is None:
                time_unknown_line_count += 1
            filtered_lines.append(line)
            filtered_line_numbers.append(source_line_numbers[raw_index])
        try:
            time_window_excluded_line_count += max(0, int(payload.get("time_window_excluded_line_count") or 0))
        except (TypeError, ValueError):
            pass
        raw_lines = filtered_lines
        payload_line_numbers = filtered_line_numbers
        payload_line_start = None
        lines: list[str] = []
        stored_line_numbers: list[int | None] = []
        truncated = bool(payload.get("truncated"))
        truncation_reasons: set[str] = set()
        if payload.get("truncation_reason"):
            truncation_reasons.add(str(payload["truncation_reason"]))
        for reason in payload.get("truncation_reasons") or []:
            if reason:
                truncation_reasons.add(str(reason))
        file_bytes = 0
        remaining_total_bytes = max(0, max_total_bytes - int(budget.get("used_bytes", 0)) - int(budget.get("probe_bytes", 0)))
        file_byte_limit = min(max_file_bytes, remaining_total_bytes)
        max_retained_lines = max(0, min(int(max_lines), MAX_LOG_LINES_PER_FILE, max_file_bytes, remaining_total_bytes))
        limited_lines = raw_lines[:max_retained_lines]
        duplicate_line_count = 0
        for raw_index, line in enumerate(limited_lines):
            value = line[:MAX_LOG_LINE_CHARS]
            if value != line:
                truncated = True
                truncation_reasons.add("line_character_limit")
            source_line_number: int | None = None
            if raw_index < len(payload_line_numbers):
                try:
                    source_line_number = int(payload_line_numbers[raw_index])
                except (TypeError, ValueError):
                    source_line_number = None
            elif payload_line_start is not None:
                source_line_number = payload_line_start + raw_index
            if source_line_number is not None and _is_duplicate_source_line(
                dedupe_records,
                entity_id=entity.stable_id,
                category=category,
                source_line_number=source_line_number,
                line=value,
            ):
                duplicate_line_count += 1
                continue
            remaining_file_bytes = file_byte_limit - file_bytes
            if remaining_file_bytes <= 0:
                truncated = True
                truncation_reasons.add("total_size_limit" if remaining_total_bytes <= 0 else "file_size_limit")
                break
            encoded_size = len(value.encode("utf-8"))
            if encoded_size > remaining_file_bytes:
                value = _truncate_utf8(value, remaining_file_bytes)
                encoded_size = len(value.encode("utf-8"))
                truncated = True
                truncation_reasons.add("total_size_limit" if remaining_total_bytes <= remaining_file_bytes else "file_size_limit")
            if value:
                lines.append(value)
                stored_line_numbers.append(source_line_number)
                file_bytes += encoded_size
                budget["used_bytes"] = int(budget.get("used_bytes", 0)) + encoded_size
            if len(lines) < len(limited_lines) and file_bytes >= file_byte_limit:
                truncated = True
                truncation_reasons.add("total_size_limit" if remaining_total_bytes <= file_byte_limit else "file_size_limit")
                break
        if len(raw_lines) > max_retained_lines:
            truncated = True
            truncation_reasons.add("line_count_limit")
        summary = classify_log_lines(lines)
        status_reason = payload.get("reason")
        if log_window_cutoff_utc is not None and raw_lines and not lines and time_window_excluded_line_count and status in {"ok", "empty"}:
            status = "empty"
            status_reason = "no entries in the requested log time window"
        if log_window_cutoff_utc is not None and time_unknown_line_count and status in {"ok", "empty"}:
            status = "partial"
            status_reason = "timestamp_unparseable_in_requested_window"
        inferred_start, inferred_end = timestamp_range(lines, collected_at)
        window_start = str(payload.get("window_start") or inferred_start)
        window_end = str(payload.get("window_end") or inferred_end)
        retained_unknown_time_line_count = sum(1 for line in lines if parse_log_line_timestamp(line) is None)
        expected_sample_count = max(0, min(len(raw_lines), max_retained_lines) - duplicate_line_count)
        completeness = (len(lines) / expected_sample_count) if expected_sample_count else (1.0 if status == "empty" else 0.0)
        record = DatasetRecord(
                record_id=f"log-{entity.stable_id}-{category}-{source_tag}",
                dataset_id=dataset_id,
                kind="log",
                entity=entity,
                collected_at_utc=collected_at,
                source=DeepSource(api=source_name, collector="vstacklens.deep.logs", collected_at_utc=collected_at),
                selector={"category": category, "source_status": status},
                window=DeepWindow(start=window_start, end=window_end, sample_count=len(lines), expected_sample_count=expected_sample_count, completeness=completeness),
                value={"status": status, "reason": status_reason, "lines": lines, "truncated": truncated, "source_file": payload.get("file_name"), "source_creator": payload.get("creator"), **summary},
                unit="line",
                raw_pointer=f"logs/log.ndjson#{entity.stable_id}/{category}/{source_tag}",
                summary=f"{category} 日志状态为 {status}，读取 {len(lines)} 行" + ("，已截断" if truncated else "。"),
                metadata={
                    "rule_id": "LOG-DEEP-001",
                    "log_category": category,
                    "log_status": status,
                    "truncated": truncated,
                    "truncation_reasons": sorted(truncation_reasons),
                    "retained_bytes": file_bytes,
                    "source_bytes_read": source_input_bytes,
                    "duplicate_line_count": duplicate_line_count,
                    "requested_log_days": log_window_days,
                    "log_window_cutoff_utc": log_window_cutoff_utc.isoformat().replace("+00:00", "Z") if log_window_cutoff_utc else None,
                    "time_window_status": payload.get("time_window_status") or ("no_recent_rows_in_source_sample" if log_window_cutoff_utc and raw_lines and not lines and time_window_excluded_line_count else "window_filtered" if log_window_cutoff_utc else "not_limited"),
                    "time_window_excluded_line_count": time_window_excluded_line_count,
                    "time_unknown_line_count": retained_unknown_time_line_count,
                    "time_unknown_candidate_line_count": time_unknown_line_count,
                    "source_status": status_reason,
                    "missing_privilege_id": payload.get("missing_privilege_id"),
                    "attempt_started_at": payload.get("started_at"),
                    "attempt_finished_at": payload.get("finished_at"),
                    "line_start": payload.get("line_start"),
                    "line_end": payload.get("line_end"),
                    "page_count": payload.get("page_count"),
                    "pagination_complete": payload.get("pagination_complete"),
                    "source_line_ranges": _compact_source_line_numbers(stored_line_numbers),
                    "time_source": "line_timestamp" if lines and inferred_start != collected_at else "collection_time_or_unparsed_line",
                },
            )
        records.append(record)
        dedupe_records.append(record)
    return records


def unavailable_log_payloads(reason: str, categories: tuple[str, ...] = LOG_CATEGORIES) -> list[dict[str, Any]]:
    return [{"key": category, "status": reason, "reason": reason, "lines": [], "truncated": False, "source": "PowerCLI.Get-Log"} for category in categories]


def event_object_references(event: Any) -> tuple[set[str], set[str]]:
    def safe_getattr(value: Any, name: str) -> Any:
        if isinstance(value, dict):
            return value.get(name)
        try:
            return getattr(value, name, None)
        except Exception:  # noqa: BLE001 - event references may point to deleted ManagedObjects.
            return None

    object_ids: set[str] = set()
    object_names: set[str] = set()
    typed_refs = (
        ("entity", "entity"),
        ("datacenter", "datacenter"),
        ("computeResource", "computeResource"),
        ("host", "host"),
        ("vm", "vm"),
        ("ds", "datastore"),
        ("net", "network"),
        ("dvs", "dvs"),
        ("tgw", "tgw"),
    )
    for argument_name, reference_name in typed_refs:
        argument = safe_getattr(event, argument_name)
        if argument is None:
            continue
        if isinstance(argument, str):
            object_names.add(argument.casefold())
            continue
        argument_id = (
            safe_getattr(argument, "_moId")
            or safe_getattr(argument, "value")
            or safe_getattr(argument, "stable_id")
            or safe_getattr(argument, "object_id")
            or safe_getattr(argument, "entity_id")
        )
        if argument_id:
            object_ids.add(str(argument_id).casefold())
            continue
        name = safe_getattr(argument, "name")
        if name:
            object_names.add(str(name).casefold())
        reference = safe_getattr(argument, reference_name) or argument
        reference_id = (
            safe_getattr(reference, "_moId")
            or safe_getattr(reference, "value")
            or safe_getattr(reference, "stable_id")
            or safe_getattr(reference, "object_id")
            or safe_getattr(reference, "entity_id")
        )
        if reference_id:
            object_ids.add(str(reference_id).casefold())
        else:
            reference_name_value = safe_getattr(reference, "name")
            if reference_name_value:
                object_names.add(str(reference_name_value).casefold())
    for attribute in ("objectId", "objectName"):
        value = safe_getattr(event, attribute)
        if value:
            if attribute == "objectId":
                object_ids.add(str(value).casefold())
            else:
                object_names.add(str(value).casefold())
    if isinstance(event, dict):
        object_ids.update(str(value).casefold() for value in (event.get("object_ids") or []) if value)
        object_names.update(str(value).casefold() for value in (event.get("object_names") or []) if value)
        for value in event.get("resolved_entities") or []:
            if isinstance(value, dict):
                identity = value.get("stable_id") or value.get("object_id") or value.get("entity_id") or value.get("_moId")
                name = value.get("display_ref") or value.get("object_name") or value.get("name")
                if identity:
                    object_ids.add(str(identity).casefold())
                if name:
                    object_names.add(str(name).casefold())
            elif value:
                object_ids.add(str(value).casefold())
        for key in ("entity_id", "stable_id", "object_id"):
            if event.get(key):
                object_ids.add(str(event[key]).casefold())
        for key in ("entity_name", "display_ref"):
            if event.get(key):
                object_names.add(str(event[key]).casefold())
    return object_ids, object_names


def correlate_log_records(
    records: list[DatasetRecord],
    events: list[Any],
    related_records: list[DatasetRecord] | None = None,
    *,
    window_seconds: int = 3600,
    object_id_aliases: dict[str, str] | None = None,
    event_rule_ids: dict[int, set[str]] | None = None,
) -> None:
    aliases = {str(source).casefold(): str(target).casefold() for source, target in (object_id_aliases or {}).items()}
    stable_ids_by_display: dict[str, set[str]] = {}
    for record in records:
        stable_id = str(record.entity.stable_id or "").casefold()
        display_ref = str(record.entity.display_ref or "").casefold()
        if stable_id and display_ref:
            stable_ids_by_display.setdefault(display_ref, set()).add(stable_id)
    event_items: list[dict[str, Any]] = []
    for event in events:
        if isinstance(event, dict):
            timestamp = event.get("createdTime") or event.get("time") or event.get("timestamp")
            event_type = str(event.get("event_type") or event.get("type") or "vSphere Event")
            message = str(event.get("fullFormattedMessage") or event.get("message") or "")
            event_key = event.get("key", event.get("event_key"))
            event_pointer = event.get("dataset_pointer") or event.get("raw_pointer")
            event_dataset_pointers = event.get("dataset_pointers") or {}
            event_source_api = str(event.get("source_api") or "EventManager.QueryEvents")
            host_argument = event.get("host")
            matched_rule_ids = {str(value) for value in event.get("rule_ids") or [] if value}
            if event.get("rule_id"):
                matched_rule_ids.add(str(event["rule_id"]))
            matched_rule_ids.update((event_rule_ids or {}).get(id(event), set()))
        else:
            timestamp = getattr(event, "createdTime", None) or getattr(event, "time", None)
            event_type = type(event).__name__
            message = str(getattr(event, "fullFormattedMessage", None) or getattr(event, "message", "") or "")
            event_key = getattr(event, "key", None)
            event_pointer = getattr(event, "dataset_pointer", None) or getattr(event, "raw_pointer", None)
            event_dataset_pointers = {}
            event_source_api = "EventManager.QueryEvents"
            host_argument = getattr(event, "host", None)
            matched_rule_ids = set((event_rule_ids or {}).get(id(event), set()))
        if hasattr(timestamp, "timestamp"):
            normalized_timestamp = timestamp.astimezone(UTC).isoformat().replace("+00:00", "Z")
            event_epoch = timestamp.astimezone(UTC).timestamp()
        else:
            try:
                event_epoch = _timestamp_epoch(str(timestamp))
                normalized_timestamp = _timestamp_utc_iso(str(timestamp))
            except (TypeError, ValueError):
                continue
        object_ids, object_names = event_object_references(event)
        canonical_object_ids = sorted({aliases.get(value, value) for value in object_ids})
        event_interfaces, event_states = _network_signal_details(f"{event_type} {message}")
        host_name = (host_argument.get("name") if isinstance(host_argument, dict) else getattr(host_argument, "name", None)) or (host_argument if isinstance(host_argument, str) else None)
        event_items.append({
            "timestamp": normalized_timestamp,
            "epoch": event_epoch,
            "event_type": event_type,
            "event_key": event_key,
            "dataset_pointer": event_pointer,
            "event_source_api": event_source_api,
            "object": next(iter(sorted(object_names)), None),
            "host": str(host_name) if host_name else None,
            "object_ids": canonical_object_ids,
            "object_names": sorted(object_names),
            "message": message[:240],
            "rule_ids": sorted(matched_rule_ids),
            "interfaces": sorted(event_interfaces),
            "states": sorted(event_states),
            "semantic_categories": sorted(
                _semantic_categories(f"{event_type} {message}")
                | set().union(*(_semantic_categories("", rule_id=rule_id) for rule_id in matched_rule_ids))
                if matched_rule_ids
                else _semantic_categories(f"{event_type} {message}")
            ),
        })
    for record in records:
        lines = list((record.value or {}).get("lines") or [])
        stable_id = str(record.entity.stable_id or "").casefold()
        display_ref = str(record.entity.display_ref or "").casefold()
        log_observations: list[tuple[float, set[str], str, int, int | None, str, set[str], set[str]]] = []
        source_line_numbers = record.metadata.get("source_line_numbers") or []
        if not isinstance(source_line_numbers, (list, tuple)):
            source_line_numbers = [source_line_numbers]
        source_line_ranges = record.metadata.get("source_line_ranges") or []
        for line_index, line in enumerate(lines, start=1):
            match = _ISO_TIMESTAMP.search(line)
            if match:
                try:
                    source_line_number = source_line_numbers[line_index - 1] if line_index <= len(source_line_numbers) else None
                    if source_line_number is None:
                        for line_range in source_line_ranges:
                            range_start = int(line_range.get("record_line_start", 0))
                            range_end = int(line_range.get("record_line_end", -1))
                            if range_start <= line_index <= range_end:
                                source_line_number = int(line_range["source_line_start"]) + line_index - range_start
                                break
                    if source_line_number is not None:
                        source_line_number = int(source_line_number)
                    log_observations.append(
                        (
                            _timestamp_epoch(match.group(1)),
                            _semantic_categories(line),
                            _timestamp_utc_iso(match.group(1)),
                            line_index,
                            source_line_number,
                            line,
                            *_network_signal_details(line),
                        )
                    )
                except (TypeError, ValueError):
                    continue
        related: list[dict[str, Any]] = []
        for item in event_items:
            try:
                event_epoch = _timestamp_epoch(item["timestamp"])
            except ValueError:
                continue
            if item["object_ids"]:
                object_matches = stable_id in item["object_ids"]
            else:
                possible_ids = stable_ids_by_display.get(display_ref, set()) if display_ref else set()
                object_matches = bool(stable_id and len(possible_ids) == 1 and stable_id in possible_ids and display_ref in item["object_names"])
            if not object_matches:
                continue
            event_categories = set(item.get("semantic_categories") or [])
            matches = []
            for log_epoch, log_categories, log_timestamp, line_index, source_line_number, log_text, log_interfaces, log_states in log_observations:
                common_categories = event_categories & log_categories
                if (
                    abs(event_epoch - log_epoch) <= window_seconds
                    and common_categories
                    and _specific_signal_compatible(log_text, item["message"], common_categories)
                ):
                    shared_interfaces = sorted(set(item.get("interfaces") or []) & log_interfaces)
                    shared_states = sorted(set(item.get("states") or []) & log_states)
                    specificity = int(bool(shared_interfaces)) + int(bool(shared_states))
                    matches.append((specificity, abs(event_epoch - log_epoch), sorted(common_categories), log_timestamp, line_index, source_line_number, shared_interfaces, shared_states))
            if matches:
                specificity, distance, matching_categories, log_timestamp, line_index, source_line_number, shared_interfaces, shared_states = min(
                    matches,
                    key=lambda match: (-match[0], match[1], match[2]),
                )
                related_item = {key: value for key, value in item.items() if key not in {"epoch", "object_ids", "object_names", "semantic_categories", "interfaces", "states"}}
                related_item["object_ids"] = list(item["object_ids"])
                related_item["matched_object_id"] = record.entity.stable_id
                related_item["matched_object"] = record.entity.display_ref
                object_pointers = (
                    event_dataset_pointers.get(record.entity.stable_id)
                    or event_dataset_pointers.get(stable_id)
                    or {}
                )
                pointer_rule_ids = _preferred_event_rule_ids(set(item.get("rule_ids") or []), set(matching_categories))
                if isinstance(object_pointers, dict):
                    related_item["dataset_pointer"] = next(
                        (object_pointers[rule_id] for rule_id in pointer_rule_ids if object_pointers.get(rule_id)),
                        related_item.get("dataset_pointer"),
                    )
                else:
                    related_item["dataset_pointer"] = object_pointers or related_item.get("dataset_pointer")
                evidence_level = (
                    "same_object_time_category_interface_state"
                    if "network" in matching_categories and shared_interfaces and shared_states
                    else "same_object_time_category_interface"
                    if "network" in matching_categories and shared_interfaces
                    else "same_object_time_category"
                )
                related.append({
                    **related_item,
                    "log_timestamp": log_timestamp,
                    "log_line_index": line_index,
                    **({"source_line_number": source_line_number} if source_line_number is not None else {}),
                    "time_distance_seconds": round(distance, 3),
                    "matching_categories": matching_categories,
                    "evidence_level": evidence_level,
                    "interfaces": shared_interfaces,
                    "state": shared_states[0] if len(shared_states) == 1 else ("mixed" if shared_states else ""),
                })
        evidence_priority = {
            "same_object_time_category_interface_state": 0,
            "same_object_time_category_interface": 1,
            "same_object_time_category": 2,
        }
        related.sort(key=lambda item: (evidence_priority.get(str(item.get("evidence_level")), 3), float(item.get("time_distance_seconds") or 0)))
        record.metadata["related_event_count"] = len(related)
        record.metadata["related_event_samples"] = related[:10]
        record.metadata["related_event_evidence_counts"] = {
            level: sum(1 for item in related if item.get("evidence_level") == level)
            for level in evidence_priority
            if any(item.get("evidence_level") == level for item in related)
        }
        related_dataset_refs: list[dict[str, Any]] = []
        for candidate in related_records or []:
            candidate_stable_id = str(candidate.entity.stable_id or "").casefold()
            if not stable_id or candidate_stable_id != stable_id:
                continue
            try:
                interval = sorted((_timestamp_epoch(candidate.window.start), _timestamp_epoch(candidate.window.end)))
            except (AttributeError, TypeError, ValueError):
                continue
            interval_start, interval_end = interval
            selector = candidate.selector or {}
            selector_text = " ".join(str(value) for value in selector.values() if isinstance(value, (str, int, float)))
            rule_id = str((candidate.metadata or {}).get("rule_id") or "")
            candidate_categories = _semantic_categories(f"{candidate.summary} {selector_text}", rule_id=rule_id)
            candidate_text = f"{candidate.summary} {selector_text}"
            matches: list[tuple[float, list[str], str, int]] = []
            for log_epoch, log_categories, log_timestamp, line_index, source_line_number, log_text, _log_interfaces, _log_states in log_observations:
                if log_epoch < interval_start:
                    distance = interval_start - log_epoch
                elif log_epoch > interval_end:
                    distance = log_epoch - interval_end
                else:
                    distance = 0.0
                common_categories = sorted(candidate_categories & log_categories)
                if (
                    distance <= window_seconds
                    and common_categories
                    and _specific_signal_compatible(log_text, candidate_text, set(common_categories))
                ):
                    matches.append((distance, common_categories, log_timestamp, line_index, source_line_number))
            if matches:
                distance, matching_categories, log_timestamp, line_index, source_line_number = min(matches, key=lambda match: (match[0], match[1]))
                related_dataset_refs.append({"record_id": candidate.record_id, "kind": candidate.kind, "source": candidate.source.api, "timestamp": candidate.window.end, "window_start": candidate.window.start, "window_end": candidate.window.end, "log_timestamp": log_timestamp, "log_line_index": line_index, **({"source_line_number": source_line_number} if source_line_number is not None else {}), "time_distance_seconds": round(distance, 3), "matching_categories": matching_categories, "summary": candidate.summary})
        record.metadata["related_record_count"] = len(related_dataset_refs)
        record.metadata["related_record_samples"] = related_dataset_refs[:10]
        record.metadata["time_correlation_window_seconds"] = window_seconds
