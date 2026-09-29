from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime


@dataclass(frozen=True)
class FreshnessResult:
    status: str
    age_days: float | None
    warning: bool
    critical: bool
    updated_at: datetime | None


def parse_updated_time(value: str | datetime | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        result = value
    else:
        text = value.strip()
        result = None
        for parser in (
            lambda: datetime.fromisoformat(text.replace("Z", "+00:00")),
            lambda: datetime.strptime(text, "%B %d, %Y, %I:%M %p UTC").replace(tzinfo=timezone.utc),
            lambda: parsedate_to_datetime(text),
        ):
            try:
                result = parser()
                break
            except (TypeError, ValueError, OverflowError):
                continue
        if result is None:
            return None
    return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result.astimezone(timezone.utc)


def assess_freshness(updated_at: str | datetime | None, *, now: datetime | None = None) -> FreshnessResult:
    parsed = parse_updated_time(updated_at)
    if parsed is None:
        return FreshnessResult("UNKNOWN", None, False, False, None)
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    age = max(0.0, (current - parsed).total_seconds() / 86400)
    if age > 90:
        status = "CRITICAL"
    elif age > 60:
        status = "WARNING"
    else:
        status = "FRESH"
    return FreshnessResult(status, age, status == "WARNING", status == "CRITICAL", parsed)


evaluate_freshness = assess_freshness
