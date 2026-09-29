from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any


class TimelineBuilder:
    """Build a compact event timeline from diagnosis evidence."""

    _TIME_ONLY_BASE = datetime(2000, 1, 1)

    TIMESTAMP_RE = re.compile(
        r"(?P<time>\d{4}[-/]\d{2}[-/]\d{2}[T ][0-9:.]+(?:Z|[+-]\d{2}:?\d{2})?|\d{2}:\d{2}:\d{2}(?:\.\d+)?)"
    )

    def build(self, diagnosis: dict[str, Any], max_events: int = 12) -> list[dict[str, str]]:
        candidates: list[dict[str, Any]] = []
        evidence_chain = diagnosis.get("evidence_chain")
        if isinstance(evidence_chain, list):
            candidates.extend(item for item in evidence_chain if isinstance(item, dict))
        evidence_sections = diagnosis.get("evidence_sections")
        if isinstance(evidence_sections, list):
            for section in evidence_sections:
                if not isinstance(section, dict):
                    continue
                section_title = str(section.get("title") or "")
                for item in section.get("excerpts", []) or []:
                    if isinstance(item, dict):
                        candidates.append({**item, "relevance": item.get("relevance") or section_title})

        events: list[dict[str, str]] = []
        seen: set[tuple[str, str, str]] = set()
        for item in candidates:
            message = str(item.get("message") or "").strip()
            match = self.TIMESTAMP_RE.search(message)
            if not match:
                continue
            event = {
                "time": match.group("time"),
                "file": str(item.get("file") or ""),
                "location": str(item.get("location") or ""),
                "event": self._trim(message),
                "relevance": str(item.get("relevance") or ""),
            }
            key = (event["time"], event["file"], event["event"])
            if key in seen:
                continue
            seen.add(key)
            events.append(event)

        events.sort(key=lambda item: self._sort_key(str(item.get("time") or "")))
        return events[:max_events]

    def _sort_key(self, time_text: str) -> tuple[int, datetime, str]:
        text = time_text.strip()
        if not text:
            return (2, self._TIME_ONLY_BASE, "")

        parsed = self._parse_datetime(text)
        if parsed is not None:
            if parsed.tzinfo is not None:
                parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
            return (0, parsed, text)

        parsed_time = self._parse_time_only(text)
        if parsed_time is not None:
            return (1, parsed_time, text)

        return (2, self._TIME_ONLY_BASE, text)

    def _parse_datetime(self, text: str) -> datetime | None:
        normalized = text.strip()
        if "/" in normalized:
            normalized = normalized.replace("/", "-")
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(normalized)
        except ValueError:
            pass
        for pattern in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M",
        ):
            try:
                return datetime.strptime(normalized, pattern)
            except ValueError:
                continue
        return None

    def _parse_time_only(self, text: str) -> datetime | None:
        normalized = text.strip()
        for pattern in ("%H:%M:%S.%f", "%H:%M:%S", "%H:%M"):
            try:
                parsed = datetime.strptime(normalized, pattern)
                return self._TIME_ONLY_BASE.replace(
                    hour=parsed.hour,
                    minute=parsed.minute,
                    second=parsed.second,
                    microsecond=parsed.microsecond,
                )
            except ValueError:
                continue
        return None

    def _trim(self, value: str, limit: int = 220) -> str:
        compact = re.sub(r"\s+", " ", value).strip()
        return compact if len(compact) <= limit else compact[: limit - 1] + "…"
