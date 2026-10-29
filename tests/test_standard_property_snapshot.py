"""Offline synthetic SDK contracts; no captured or live vCenter responses."""
from __future__ import annotations

from collections import Counter
from types import SimpleNamespace

import pytest
from pyVmomi import vim, vmodl
from pyVmomi.SoapAdapter import SoapStubAdapter

from vstacklens.collection.property_snapshot import (
    PropertySnapshot,
    SnapshotCancelledError,
    SnapshotClosedError,
    begin_scope,
)


class SyntheticSoapStub(SoapStubAdapter):
    """Keep the real SDK wrapper contract without opening a connection."""

    def __init__(self):
        super().__init__(host="127.0.0.1", version="vim.version.version9")
        self.values = {}
        self.calls = Counter()
        self.methods = {}

    def set(self, obj, path, value):
        self.values[(type(obj), obj._GetMoId(), obj._GetServerGuid(), path)] = value

    def InvokeMethod(self, mo, info, args, outerStub=None):
        if info.wsdlName == "Fetch":
            path = args[0]
            key = (type(mo), mo._GetMoId(), mo._GetServerGuid(), path)
            self.calls[(mo._GetMoId(), path)] += 1
            value = self.values[key]
            if callable(value):
                value = value()
        else:
            self.calls[(mo._GetMoId(), info.wsdlName)] += 1
            value = self.methods[info.wsdlName](*args)
        if isinstance(value, Exception):
            if outerStub is not None:
                return 500, value
            raise value
        if outerStub is not None:
            return 200, outerStub._clone(value)
        return value


def scope(raw=None, paths=None, **kwargs):
    return PropertySnapshot(raw or SyntheticSoapStub(), cache_paths_by_type=paths or {
        vim.VirtualMachine: ("name", "config", "datastore", "snapshot", "parent"),
        vim.HostSystem: ("name", "config"),
        vim.Datastore: ("name", "summary"),
    }, **kwargs)


def content(obj, values=None, missing=None):
    pc = vmodl.query.PropertyCollector
    return pc.ObjectContent(
        obj=obj,
        propSet=[vmodl.DynamicProperty(name=key, val=value)
                 for key, value in (values or {}).items()],
        missingSet=[pc.MissingProperty(
            path=path, fault=vmodl.LocalizedMethodFault(fault=fault))
            for path, fault in (missing or {}).items()],
    )


def page(*contents, token=None):
    result = vmodl.query.PropertyCollector.RetrieveResult()
    result.objects = list(contents)
    result.token = token
    return result


class SyntheticPropertyCollector:
    def __init__(self, pages):
        self.pages = iter(pages)
        self.specs = []
        self.tokens = []
        self.cancelled = []

    def _next(self):
        result = next(self.pages)
        if isinstance(result, Exception):
            raise result
        return result

    def RetrievePropertiesEx(self, specs, options):
        self.specs.append((specs, options))
        return self._next()

    def ContinueRetrievePropertiesEx(self, token):
        self.tokens.append(token)
        return self._next()

    def CancelRetrievePropertiesEx(self, token):
        self.cancelled.append(token)


def test_bulk_complete_reverse_order_matches_identity_and_retains_types():
    raw = SyntheticSoapStub()
    a, b = vim.VirtualMachine("vm-1", raw), vim.VirtualMachine("vm-2", raw)
    snap = scope(raw)
    collector = SyntheticPropertyCollector([page(
        content(b, {"name": "second"}), content(a, {"name": "first"}))])
    snap.prefetch(collector, [a, b], {vim.VirtualMachine: ("name",)})
    assert snap.bind(a).name == "first"
    assert snap.bind(b).name == "second"
    assert isinstance(snap.bind(a), vim.VirtualMachine)
    assert raw.calls == {}
    assert collector.specs[0][0][0].propSet[0].pathSet == ["name"]
    assert collector.specs[0][1].maxObjects == 32
    assert snap.counters["cache_hits"] == 2
    assert all(item["source"] == "property_collector" for item in snap.observations)


def test_property_collector_paging_preserves_all_successful_fields():
    raw = SyntheticSoapStub()
    a, b = vim.VirtualMachine("vm-1", raw), vim.VirtualMachine("vm-2", raw)
    snap = scope(raw)
    pc = SyntheticPropertyCollector([
        page(content(a, {"name": "a"}), token="cursor"),
        page(content(b, {"name": "b"})),
    ])
    snap.prefetch(pc, [a, b], {vim.VirtualMachine: ("name",)})
    assert [snap.bind(obj).name for obj in (a, b)] == ["a", "b"]
    assert pc.tokens == ["cursor"]
    assert not pc.cancelled
    assert snap.counters["fallback_properties"] == 0


def test_object_batches_and_requested_properties_are_bounded():
    raw = SyntheticSoapStub()
    objects = [vim.VirtualMachine(f"vm-{n}", raw) for n in range(65)]
    pc = SyntheticPropertyCollector([
        page(*(content(obj, {"name": obj._GetMoId()}) for obj in objects[start:start + 32]))
        for start in (0, 32, 64)
    ])
    snap = scope(raw)
    snap.prefetch(pc, objects, {vim.VirtualMachine: ("name",)})
    assert [len(specs[0].objectSet) for specs, _ in pc.specs] == [32, 32, 1]
    assert all(options.maxObjects == 32 for _, options in pc.specs)
    assert [snap.bind(obj).name for obj in objects] == [obj._GetMoId() for obj in objects]


def test_partial_return_only_missing_object_and_field_use_sdk_fallback():
    raw = SyntheticSoapStub()
    a, b = vim.VirtualMachine("vm-1", raw), vim.VirtualMachine("vm-2", raw)
    raw.set(a, "config", vim.vm.ConfigInfo(name="config-a"))
    raw.set(b, "name", "b-fallback")
    raw.set(b, "config", vim.vm.ConfigInfo(name="config-b"))
    snap = scope(raw)
    pc = SyntheticPropertyCollector([page(content(a, {"name": "a"}))])
    snap.prefetch(pc, [a, b], {vim.VirtualMachine: ("name", "config")})
    assert snap.bind(a).name == "a"
    assert snap.bind(a).config.name == "config-a"
    assert snap.bind(b).name == "b-fallback"
    assert snap.bind(b).config.name == "config-b"
    assert raw.calls == {("vm-1", "config"): 1, ("vm-2", "name"): 1, ("vm-2", "config"): 1}
    assert snap.counters["fallback_properties"] == 3


@pytest.mark.parametrize("fault", [vim.fault.NoPermission(), TimeoutError("synthetic timeout")])
def test_batch_failure_preserves_real_accessor_fault_and_never_caches_it(fault):
    raw = SyntheticSoapStub()
    obj = vim.VirtualMachine("vm-1", raw)
    raw.set(obj, "name", fault)
    warnings = []
    snap = scope(raw, warning=warnings.append)
    pc = SyntheticPropertyCollector([fault])
    snap.prefetch(pc, [obj], {vim.VirtualMachine: ("name",)})
    for _ in range(2):
        with pytest.raises(type(fault)) as error:
            _ = snap.bind(obj).name
        assert error.value is fault
    assert raw.calls[("vm-1", "name")] == 2
    assert snap.counters["cached_properties"] == 0
    assert warnings[0]["fault_type"] == type(fault).__name__
    assert all("synthetic timeout" not in str(item) for item in warnings)


def test_single_object_permission_fault_does_not_clear_other_objects():
    raw = SyntheticSoapStub()
    a, b = vim.VirtualMachine("vm-1", raw), vim.VirtualMachine("vm-2", raw)
    fault = vim.fault.NoPermission(privilegeId="synthetic-privilege")
    raw.set(b, "name", fault)
    warnings = []
    snap = scope(raw, warning=warnings.append)
    pc = SyntheticPropertyCollector([page(content(a, {"name": "a"}),
                                           content(b, missing={"name": fault}))])
    snap.prefetch(pc, [a, b], {vim.VirtualMachine: ("name",)})
    assert snap.bind(a).name == "a"
    with pytest.raises(vim.fault.NoPermission):
        _ = snap.bind(b).name
    assert warnings[0]["fault_type"] == "vim.fault.NoPermission"
    assert "synthetic-privilege" not in str(warnings)


def test_missing_property_never_infers_an_empty_value():
    raw = SyntheticSoapStub()
    obj = vim.VirtualMachine("vm-1", raw)
    raw.set(obj, "datastore", [vim.Datastore("ds-1", raw)])
    snap = scope(raw)
    snap.prefetch(SyntheticPropertyCollector([page(content(obj))]), [obj],
                  {vim.VirtualMachine: ("datastore",)})
    result = snap.bind(obj).datastore
    assert [item._GetMoId() for item in result] == ["ds-1"]
    assert result[0]._GetStub() is snap
    assert raw.calls[("vm-1", "datastore")] == 1


def test_later_page_timeout_retains_successes_and_cancels_cursor():
    raw = SyntheticSoapStub()
    a, b = vim.VirtualMachine("vm-1", raw), vim.VirtualMachine("vm-2", raw)
    raw.set(b, "name", "b-fallback")
    snap = scope(raw)
    pc = SyntheticPropertyCollector([
        page(content(a, {"name": "a"}), token="cursor"), TimeoutError("private response")])
    snap.prefetch(pc, [a, b], {vim.VirtualMachine: ("name",)})
    assert snap.bind(a).name == "a"
    assert snap.bind(b).name == "b-fallback"
    assert pc.cancelled == ["cursor"]
    assert snap.counters["batch_faults"] == 1
    assert snap.counters["fallback_properties"] == 1


@pytest.mark.parametrize("last", [None, "repeat"])
def test_truncation_and_repeated_token_preserve_fields_and_stop(last):
    raw = SyntheticSoapStub()
    a, b = vim.VirtualMachine("vm-1", raw), vim.VirtualMachine("vm-2", raw)
    raw.set(b, "name", "b-fallback")
    warnings = []
    snap = scope(raw, warning=warnings.append)
    tail = None if last is None else page(content(a, {"name": "a"}), token="cursor")
    pc = SyntheticPropertyCollector([page(content(a, {"name": "a"}), token="cursor"), tail])
    snap.prefetch(pc, [a, b], {vim.VirtualMachine: ("name",)})
    assert snap.bind(a).name == "a"
    assert snap.bind(b).name == "b-fallback"
    assert pc.tokens == ["cursor"]
    assert pc.cancelled == ["cursor"]
    assert snap.counters["truncated_retrievals"] == 1
    assert warnings[-1]["event"] in {"empty_retrieval_page", "repeated_continuation_token"}


@pytest.mark.parametrize("path,value", [("snapshot", None), ("datastore", []), ("name", "")])
def test_confirmed_null_empty_values_are_successful_cache_entries(path, value):
    raw = SyntheticSoapStub()
    obj = vim.VirtualMachine("vm-1", raw)
    snap = scope(raw)
    snap.prefetch(SyntheticPropertyCollector([page(content(obj, {path: value}))]), [obj],
                  {vim.VirtualMachine: (path,)})
    assert getattr(snap.bind(obj), path) == value
    assert getattr(snap.bind(obj), path) == value
    assert not raw.calls
    assert snap.observations[0]["status"] == "success"


def test_true_zero_is_not_confused_with_missing_or_error():
    raw = SyntheticSoapStub()
    obj = vim.Datastore("ds-1", raw)
    snap = scope(raw)
    summary = vim.Datastore.Summary(capacity=0, freeSpace=0, accessible=False)
    snap.prefetch(SyntheticPropertyCollector([page(content(obj, {"summary": summary}))]),
                  [obj], {vim.Datastore: ("summary",)})
    result = snap.bind(obj).summary
    assert result.capacity == 0 and result.freeSpace == 0 and result.accessible is False
    assert not raw.calls


def test_identical_names_addresses_and_moids_are_isolated_by_session_and_scope():
    raw_a, raw_b = SyntheticSoapStub(), SyntheticSoapStub()
    a, b = vim.VirtualMachine("vm-1", raw_a), vim.VirtualMachine("vm-1", raw_b)
    raw_a.set(a, "config", vim.vm.ConfigInfo(name="same", annotation="environment-a"))
    raw_b.set(b, "config", vim.vm.ConfigInfo(name="same", annotation="environment-b"))
    first, second = scope(raw_a), scope(raw_b)
    assert first.bind(a).config.annotation == "environment-a"
    assert second.bind(b).config.annotation == "environment-b"
    with pytest.raises(ValueError):
        first.bind(b)
    # New task using the very same raw adapter does not reuse the earlier value.
    raw_a.set(a, "config", vim.vm.ConfigInfo(name="same", annotation="next-task"))
    third = scope(raw_a)
    assert third.bind(a).config.annotation == "next-task"
    assert first.bind(a).config.annotation == "environment-a"


def test_server_guid_and_sdk_type_are_part_of_the_stable_identity():
    raw = SyntheticSoapStub()
    first, second = (vim.VirtualMachine("same", raw, serverGuid=guid) for guid in ("a", "b"))
    host = vim.HostSystem("same", raw, serverGuid="a")
    snap = scope(raw)
    pc = SyntheticPropertyCollector([
        page(content(second, {"name": "vm-b"}), content(first, {"name": "vm-a"})),
        page(content(host, {"name": "host-a"})),
    ])
    snap.prefetch(pc, [first, second, host], {vim.VirtualMachine: ("name",), vim.HostSystem: ("name",)})
    assert [snap.bind(obj).name for obj in (first, second, host)] == ["vm-a", "vm-b", "host-a"]


def test_unrequested_and_foreign_returned_objects_cannot_poison_a_cache():
    raw, foreign = SyntheticSoapStub(), SyntheticSoapStub()
    obj, other, alien = (vim.VirtualMachine("vm-1", raw), vim.VirtualMachine("vm-2", raw),
                         vim.VirtualMachine("vm-1", foreign))
    raw.set(obj, "name", "correct")
    warnings = []
    snap = scope(raw, warning=warnings.append)
    snap.prefetch(SyntheticPropertyCollector([page(content(other, {"name": "other"}),
                                                content(alien, {"name": "foreign"}))]),
                  [obj], {vim.VirtualMachine: ("name",)})
    assert snap.bind(obj).name == "correct"
    assert len(warnings) == 2


def test_mutable_data_and_nested_references_are_cloned_without_cloning_stubs():
    raw = SyntheticSoapStub()
    obj = vim.VirtualMachine("vm-1", raw)
    ds = vim.Datastore("ds-1", raw)
    config = vim.vm.ConfigInfo(name="vm", extraConfig=[vim.option.OptionValue(key="k", value="before")])
    raw.set(obj, "config", config)
    raw.set(obj, "datastore", [ds])
    raw.set(ds, "name", "datastore")
    snap = scope(raw)
    vm = snap.bind(obj)
    value = vm.config
    value.name = "changed"
    value.extraConfig[0].value = "changed"
    assert vm.config.name == "vm"
    assert vm.config.extraConfig[0].value == "before"
    config.name = "source-mutated-after-fetch"
    assert vm.config.name == "vm"
    refs = vm.datastore
    assert refs[0]._GetStub() is snap
    assert refs[0].name == "datastore"
    refs.clear()
    assert len(vm.datastore) == 1
    assert raw.calls[("vm-1", "config")] == 1
    assert raw.calls[("ds-1", "name")] == 1


def test_foreign_service_reference_keeps_its_original_stub_and_is_not_prefetched():
    raw, foreign = SyntheticSoapStub(), SyntheticSoapStub()
    foreign.path = "/vsanHealth"
    obj = vim.VirtualMachine("vm-1", raw)
    folder = vim.Folder("group-1", foreign)
    raw.set(obj, "parent", folder)
    snap = scope(raw)
    assert snap.bind(obj).parent._GetStub() is foreign
    assert snap.bind(obj).parent._GetMoId() == "group-1"
    warnings = []
    another = scope(raw, warning=warnings.append)
    pc = SyntheticPropertyCollector([])
    another.prefetch(pc, [folder], {vim.Folder: ("name",)})
    assert not pc.specs
    assert warnings[0]["event"] == "foreign_object_not_prefetched"


def test_session_cookie_or_target_change_invalidates_previous_observation():
    raw = SyntheticSoapStub()
    obj = vim.VirtualMachine("vm-1", raw)
    raw.set(obj, "name", "before")
    snap = scope(raw)
    vm = snap.bind(obj)
    assert vm.name == "before"
    raw.set(obj, "name", "after")
    raw.cookie = "synthetic-new-session"
    assert vm.name == "after"
    raw.set(obj, "name", "new-target")
    raw.host = "127.0.0.2"
    assert vm.name == "new-target"
    assert snap.counters["session_invalidations"] == 2
    assert "synthetic-new-session" not in str(snap.observations)


def test_close_invalidates_cache_and_rejects_late_remote_access():
    raw = SyntheticSoapStub()
    obj = vim.VirtualMachine("vm-1", raw)
    raw.set(obj, "name", "cached")
    snap = scope(raw)
    vm = snap.bind(obj)
    assert vm.name == "cached"
    snap.close()
    assert snap.counters["cached_properties"] == 0
    with pytest.raises(SnapshotClosedError):
        _ = vm.name
    assert raw.calls[("vm-1", "name")] == 1


def test_context_manager_closes_scope_on_an_exception():
    snap = scope()
    with pytest.raises(ValueError):
        with snap:
            raise ValueError("synthetic")
    assert snap.counters["closed"] is True


def test_cancellation_releases_active_cursor_and_does_not_read_next_page():
    raw = SyntheticSoapStub()
    obj = vim.VirtualMachine("vm-1", raw)
    cancelled = False

    class CancellingCollector(SyntheticPropertyCollector):
        def RetrievePropertiesEx(self, specs, options):
            nonlocal cancelled
            result = super().RetrievePropertiesEx(specs, options)
            cancelled = True
            return result

    snap = scope(raw, cancelled=lambda: cancelled)
    pc = CancellingCollector([page(content(obj, {"name": "not-consumed"}), token="cursor")])
    with pytest.raises(SnapshotCancelledError):
        snap.prefetch(pc, [obj], {vim.VirtualMachine: ("name",)})
    assert pc.tokens == []
    assert pc.cancelled == ["cursor"]
    assert snap.counters["cached_properties"] == 0


def test_cancellation_releases_cursor_using_raw_sdk_collector_without_reconnect():
    raw = SyntheticSoapStub()
    obj = vim.VirtualMachine("vm-1", raw)
    cancelled = False

    def retrieve(*args):
        nonlocal cancelled
        cancelled = True
        return page(content(obj, {"name": "not-consumed"}), token="cursor")

    tokens = []
    raw.methods["RetrievePropertiesEx"] = retrieve
    raw.methods["CancelRetrievePropertiesEx"] = lambda token: tokens.append(token)
    snap = scope(raw, cancelled=lambda: cancelled)
    pc = vmodl.query.PropertyCollector("propertyCollector", snap)
    with pytest.raises(SnapshotCancelledError):
        snap.prefetch(pc, [obj], {vim.VirtualMachine: ("name",)})
    assert tokens == ["cursor"]
    assert raw.calls[("propertyCollector", "CancelRetrievePropertiesEx")] == 1


def test_retry_after_a_failed_accessor_can_succeed_and_then_cache():
    raw = SyntheticSoapStub()
    obj = vim.VirtualMachine("vm-1", raw)
    raw.set(obj, "name", vim.fault.NoPermission())
    snap = scope(raw)
    vm = snap.bind(obj)
    with pytest.raises(vim.fault.NoPermission):
        _ = vm.name
    raw.set(obj, "name", "permission-now-present")
    assert vm.name == "permission-now-present"
    assert vm.name == "permission-now-present"
    assert raw.calls[("vm-1", "name")] == 2
    assert [entry["status"] for entry in snap.observations] == ["failed", "success"]


def test_nonwhitelisted_runtime_is_always_live_and_historical_window_is_unchanged():
    raw = SyntheticSoapStub()
    obj = vim.VirtualMachine("vm-1", raw)
    runtime = vim.vm.RuntimeInfo(powerState="poweredOn")
    raw.set(obj, "runtime", runtime)
    snap = scope(raw)
    vm = snap.bind(obj)
    assert vm.runtime.powerState == "poweredOn"
    runtime.powerState = "poweredOff"
    assert vm.runtime.powerState == "poweredOff"
    assert raw.calls[("vm-1", "runtime")] == 2
    # QueryPerf is a method, so its exact spec (metric/unit/window/maxSample)
    # passes through without any property-cache substitution or changes.
    start, end = "2026-10-22T01:00:00Z", "2026-10-22T02:00:00Z"
    from datetime import datetime
    spec = vim.PerformanceManager.QuerySpec(
        entity=vm, metricId=[vim.PerformanceManager.MetricId(counterId=1, instance="*")],
        startTime=datetime.fromisoformat(start), endTime=datetime.fromisoformat(end),
        intervalId=300, maxSample=12)
    captured = []
    raw.methods["QueryPerf"] = lambda querySpec: captured.extend(querySpec) or []
    manager = vim.PerformanceManager("PerfMgr", snap)
    assert manager.QueryPerf([spec]) == []
    assert captured[0] is spec
    assert captured[0].intervalId == 300 and captured[0].maxSample == 12
    assert captured[0].startTime == datetime.fromisoformat(start)
    assert captured[0].endTime == datetime.fromisoformat(end)


def test_cache_capacity_bypass_keeps_correct_accessor_results():
    raw = SyntheticSoapStub()
    a, b = vim.VirtualMachine("vm-1", raw), vim.VirtualMachine("vm-2", raw)
    raw.set(a, "name", "a")
    raw.set(b, "name", "b")
    snap = scope(raw, max_cached_properties=1)
    assert snap.bind(a).name == "a"
    assert snap.bind(b).name == "b"
    assert snap.bind(b).name == "b"
    assert snap.counters["cached_properties"] == 1
    assert raw.calls[("vm-2", "name")] == 2


def test_duplicate_requested_object_is_not_queried_twice():
    raw = SyntheticSoapStub()
    obj = vim.VirtualMachine("vm-1", raw)
    snap = scope(raw)
    pc = SyntheticPropertyCollector([page(content(obj, {"name": "a"}))])
    snap.prefetch(pc, [obj, snap.bind(obj)], {vim.VirtualMachine: ("name",)})
    assert len(pc.specs[0][0][0].objectSet) == 1
    snap.prefetch(pc, [obj], {vim.VirtualMachine: ("name",)})
    assert len(pc.specs) == 1


def test_conflicting_missing_and_returned_property_requires_fallback():
    raw = SyntheticSoapStub()
    obj = vim.VirtualMachine("vm-1", raw)
    raw.set(obj, "name", "fallback")
    snap = scope(raw)
    pc = SyntheticPropertyCollector([page(content(obj, {"name": "inconsistent"},
                                                {"name": vim.fault.NoPermission()}))])
    snap.prefetch(pc, [obj], {vim.VirtualMachine: ("name",)})
    assert snap.bind(obj).name == "fallback"
    assert snap.counters["fallback_properties"] == 1


def test_observation_timestamp_does_not_change_on_cache_hit_and_is_not_mutable():
    raw = SyntheticSoapStub()
    obj = vim.VirtualMachine("vm-1", raw)
    raw.set(obj, "name", "a")
    snap = scope(raw)
    assert snap.bind(obj).name == "a"
    observed = snap.observations
    original = observed[0]["acquired_at"]
    observed[0]["acquired_at"] = "polluted"
    assert snap.bind(obj).name == "a"
    assert snap.observations[0]["acquired_at"] == original
    assert len(snap.observations) == 1


def test_unsupported_session_adapter_is_left_unmodified_and_no_global_patch():
    wrapper = SimpleNamespace(soapStub=SyntheticSoapStub())
    assert begin_scope(wrapper, cache_paths_by_type={}) is None
    raw = SyntheticSoapStub()
    original = type(raw).InvokeAccessor
    first = begin_scope(raw, cache_paths_by_type={vim.VirtualMachine: ("name",)})
    assert isinstance(first, PropertySnapshot)
    assert type(raw).InvokeAccessor is original
    with pytest.raises(TypeError):
        PropertySnapshot(wrapper, cache_paths_by_type={})


def test_vsan_soap_service_stub_is_not_automatically_decorated():
    raw = SyntheticSoapStub()
    raw.path = "/vsanHealth"
    assert begin_scope(raw, cache_paths_by_type={}) is None
    with pytest.raises(TypeError):
        PropertySnapshot(raw, cache_paths_by_type={})


@pytest.mark.parametrize("size", [0, 33])
def test_invalid_batch_size_is_rejected(size):
    with pytest.raises(ValueError):
        scope(batch_size=size)


def test_nested_projection_cannot_masquerade_as_complete_parent_property():
    with pytest.raises(ValueError):
        scope(paths={vim.VirtualMachine: ("config.hardware",)})
