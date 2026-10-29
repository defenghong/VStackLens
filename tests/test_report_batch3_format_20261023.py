from datetime import date, datetime, timedelta, timezone
from decimal import Decimal

import pytest

from vstacklens.reports.customer_format import (
    capacity_bytes_text, capacity_text, capacity_unit, decimal_text,
    local_time_text, percent_text,
)


def test_shared_rounding_preserves_input_and_half_up():
    original = Decimal('931.25')
    assert capacity_text(original) == '931.3 GB'
    assert original == Decimal('931.25')
    assert decimal_text('11.45') == '11.5'
    assert percent_text('11.44') == '11.4%'
    assert percent_text(0) == '0.0%'
    assert capacity_text(150) == '150.0 GB'
    assert capacity_text('-0.001') == '0.0 GB'


def test_capacity_units_are_selected_per_table_without_hiding_small_cells():
    assert capacity_unit([931.25, 1024, 32192.75]) == 'GB'
    assert capacity_unit([2048, 3072, None]) == 'TB'
    assert capacity_unit([2048, 0]) == 'GB'
    assert capacity_text('32192.75') == '31.4 TB'
    assert capacity_text('32192.75', unit='GB') == '32,192.8 GB'
    assert capacity_text(2048, unit='TB', with_unit=False) == '2.0'
    assert capacity_bytes_text(1024 ** 3) == '1.0 GB'


@pytest.mark.parametrize('value', [None, '', True, False, 'nan', 'Infinity', float('nan'), 'not-a-number'])
def test_missing_measurements_never_become_zero(value):
    assert decimal_text(value) == ''
    assert percent_text(value) == ''
    assert capacity_text(value) == ''


def test_time_uses_requested_zone_or_machine_zone_without_exposing_offset():
    value = '2026-09-10T03:11:22.427854+00:00'
    assert local_time_text(value, timezone=timezone(timedelta(hours=8))) == '2026-09-10 11:11'
    assert local_time_text(value, timezone=timezone(timedelta(hours=-5))) == '2026-09-09 22:11'
    assert local_time_text(value) == datetime.fromisoformat(value).astimezone().strftime('%Y-%m-%d %H:%M')
    assert local_time_text('2031-05-25') == '2031-05-25'
    assert local_time_text(date(2031, 5, 25)) == '2031-05-25'
    assert local_time_text('2026-10-22T14:57:12.123456') == '2026-10-22 14:57'
    assert local_time_text('not-a-date') == ''
