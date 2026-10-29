"""Display-only customer formatting; saved measurements and decisions stay intact."""
from __future__ import annotations

from datetime import date, datetime, tzinfo
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP, localcontext
import re
from typing import Any, Iterable


CAPACITY_NOTE = '容量按 1 GB = 1024³ 字节计算，与 vCenter 界面一致。'


def _decimal(value: Any) -> Decimal | None:
    if value is None or isinstance(value, bool) or value == '':
        return None
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return None
    return result if result.is_finite() else None


def decimal_text(value: Any, places: int = 1, grouping: bool = False) -> str:
    """Round at the display boundary, identically in every output format."""
    number = _decimal(value)
    if number is None:
        return ''
    with localcontext() as context:
        context.prec = max(28, len(number.as_tuple().digits) + abs(number.adjusted()) + places + 3)
        number = number.quantize(Decimal(1).scaleb(-places), rounding=ROUND_HALF_UP)
    if number == 0:
        number = abs(number)
    return format(number, (',' if grouping else '') + f'.{places}f')


def percent_text(value: Any) -> str:
    text = decimal_text(value)
    return text + '%' if text else ''


def capacity_unit(values_gb: Iterable[Any]) -> str:
    """Keep a mixed table in GB; use TB only when every known cell is >=1024 GB."""
    known = [number for value in values_gb if (number := _decimal(value)) is not None]
    return 'TB' if known and all(number >= 1024 for number in known) else 'GB'


def capacity_text(value_gb: Any, unit: str | None = None, with_unit: bool = True) -> str:
    """Input is the software's binary GB convention, never decimal SI gigabytes."""
    number = _decimal(value_gb)
    if number is None:
        return ''
    chosen = unit or ('TB' if number >= 1024 else 'GB')
    if chosen not in {'GB', 'TB'}:
        raise ValueError('Capacity display unit must be GB or TB')
    if chosen == 'TB':
        number /= 1024
    text = decimal_text(number, grouping=True)
    return f'{text} {chosen}' if with_unit else text


def capacity_bytes_text(value: Any, unit: str | None = None, with_unit: bool = True) -> str:
    number = _decimal(value)
    return capacity_text(number / (1024 ** 3), unit=unit, with_unit=with_unit) if number is not None else ''


def local_time_text(value: Any, *, timezone: tzinfo | None = None) -> str:
    """Use the executing machine's local zone; date-only facts remain dates.

    ``timezone`` is an explicit presentation override for portable zone tests.
    Naive saved datetimes have no evidence of a source offset, so they are kept
    as local wall-clock times rather than silently reinterpreted as UTC.
    """
    if value is None or value == '':
        return ''
    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, date):
        return value.isoformat()
    else:
        text = str(value).strip()
        if re.fullmatch(r'\d{4}-\d{2}-\d{2}', text):
            try:
                return date.fromisoformat(text).isoformat()
            except ValueError:
                return ''
        try:
            moment = datetime.fromisoformat(text.replace('Z', '+00:00'))
        except (ValueError, TypeError):
            return ''
    if moment.tzinfo is not None:
        moment = moment.astimezone(timezone)
    return moment.strftime('%Y-%m-%d %H:%M')
