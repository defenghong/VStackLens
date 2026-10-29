"""Independent unit/window expectations for actual SDK performance samples."""
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace as NS

import pytest
from pyVmomi import vim

from vstacklens.collection.pyvmomi_collector import _PerformanceSampler
from vstacklens.collection.collection_plan import CollectionPlan, PerformanceMetricRequest

START = datetime(2026, 10, 22, 0, 0, tzinfo=UTC)
END = START + timedelta(hours=1)

def sampler_with(values, samples):
    seen = []
    def query(*, querySpec):
        seen.extend(querySpec)
        return [NS(sampleInfo=samples, value=[NS(id=NS(counterId=1, instance=""), value=values)])]
    sampler = _PerformanceSampler.__new__(_PerformanceSampler)
    sampler.perf_manager = NS(QueryPerf=query)
    sampler.counter_ids = {"cpu.usage.average": 1}
    sampler.plan = CollectionPlan(performance_metrics=[PerformanceMetricRequest(
        object_type="HostSystem", metric="cpu_usage_avg", window_minutes=60, minimum_samples=3)])
    return sampler, seen

def samples_for(count):
    return [NS(timestamp=START + timedelta(minutes=5*(i+1)), interval=300) for i in range(count)]

@pytest.mark.parametrize("raw,expected", [(0,0), (1,.01), (50,.5), (100,1), (200,2), (4521,45.21)])
def test_sdk_percent_fixed_point_has_no_low_load_exception(raw, expected):
    sampler = _PerformanceSampler.__new__(_PerformanceSampler)
    assert sampler._normalize_percent(raw) == expected

def test_raw_query_uses_real_sample_interval_and_keeps_zero():
    samples = samples_for(3)
    samples[1].interval = 600
    sampler, seen = sampler_with([0,50,100], samples)
    result = sampler._query_once(vim.HostSystem("host-frozen"), [vim.PerformanceManager.MetricId(counterId=1, instance="")], START, END)
    assert result == [(0,300,"cpu.usage.average"), (50,600,"cpu.usage.average"), (100,300,"cpu.usage.average")]
    assert seen[0].startTime == START and seen[0].endTime == END
    assert seen[0].intervalId == 300

def test_invalid_values_never_become_zero_or_sufficient_samples():
    sampler, _ = sampler_with([-1,0,50,float("nan"),float("inf"),None,"unavailable"], samples_for(7))
    query = lambda entity, counters, window: sampler._query_once(entity, [vim.PerformanceManager.MetricId(counterId=1, instance="")], START, END)
    sampler._query = query
    assert sampler.metric(vim.HostSystem("host-frozen"), "cpu_usage_avg") is None
    assert query(vim.HostSystem("host-frozen"), [1], 60) == [(0,300,"cpu.usage.average"),(50,300,"cpu.usage.average")]
    assert sampler._sampling("cpu_usage_avg") == (60,3)

@pytest.mark.parametrize("bad_sample", [NS(timestamp=START+timedelta(minutes=5),interval=None),
    NS(timestamp=START+timedelta(minutes=5),interval=0), NS(timestamp=None,interval=300),
    NS(timestamp=(START+timedelta(minutes=5)).replace(tzinfo=None),interval=300),
    NS(timestamp=START,interval=300), NS(timestamp=END+timedelta(seconds=1),interval=300)])
def test_unknown_or_outside_sample_window_is_not_a_fabricated_interval(bad_sample):
    sampler, _ = sampler_with([25], [bad_sample])
    assert sampler._query_once(vim.HostSystem("host-frozen"), [], START, END) == []

def test_unpaired_values_are_missing_while_end_boundary_is_inclusive():
    sampler, _ = sampler_with([100,200], [NS(timestamp=END,interval=300)])
    assert sampler._query_once(vim.HostSystem("host-frozen"), [], START, END) == [(100,300,"cpu.usage.average")]

def test_same_fixed_window_independent_percent_recompute():
    raw = [1,50,100]
    sampler, _ = sampler_with(raw, samples_for(3))
    sampler._query = lambda entity, counters, window: sampler._query_once(entity, [], START, END)
    expected = round(sum(raw) / len(raw) / 100, 2)
    assert expected == .5
    assert sampler.metric(vim.HostSystem("host-frozen"), "cpu_usage_avg") == expected
