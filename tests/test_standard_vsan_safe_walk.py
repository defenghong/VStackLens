"""Offline synthetic SDK responses; these fixtures are not live vCenter data."""

from __future__ import annotations

from types import SimpleNamespace as NS

import pytest
from pyVmomi import vim, vmodl

from vstacklens.collection.pyvmomi_collector import PyVmomiCollector


class AccessTrapStub:
    version = "vim.version.version12"
    path = "/vsanHealth"

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []

    def InvokeAccessor(self, obj, info):  # noqa: N802 - SDK interface
        self.calls.append((type(obj).__name__, obj._moId, info.name))
        raise vmodl.fault.ManagedObjectNotFound(obj=obj)


@pytest.fixture
def collector() -> PyVmomiCollector:
    return object.__new__(PyVmomiCollector)


@pytest.fixture
def sdk_health_tree():
    stub = AccessTrapStub()
    cluster = vim.ClusterComputeResource("domain-c7", stub)
    host = vim.HostSystem("host-7", stub)
    test = vim.cluster.VsanClusterHealthTest(
        testId="object-accessibility",
        testName="Object accessibility",
        testHealth="red",
        testDescription="Synthetic object accessibility failure",
    )
    group = vim.cluster.VsanClusterHealthGroup(
        groupId="data", groupName="Data", groupHealth="red", groupTests=[test],
    )
    summary = vim.cluster.VsanClusterHealthSummary(
        cluster=cluster,
        overallHealth="yellow",
        overallHealthDescription="Synthetic health warning",
        groups=[group],
        objectHealth=vim.host.VsanObjectOverallHealth(objectHealthDetail=[
            vim.host.VsanObjectHealth(health="inaccessible", numObjects=2, objUuids=["obj-a", "obj-b"]),
            vim.host.VsanObjectHealth(health="inaccessible", numObjects=0, objUuids=[]),
        ]),
    )
    # A declared SDK field that contains host references, not a fake attribute.
    summary.clusterStatus = vim.cluster.VsanClusterHealthSystemStatusResult()
    # Different SDK releases expose host references in different result nodes.
    # The explicit local record also checks transport/test-double compatibility.
    return NS(summary=summary, host=host), stub, test


def test_managed_references_keep_identity_without_remote_expansion(collector, sdk_health_tree):
    tree, stub, test = sdk_health_tree
    nodes = collector._walk_public_objects(tree)

    assert any(node is tree.host for node in nodes)
    assert any(node is tree.summary.cluster for node in nodes)
    assert any(node is test for node in nodes)
    assert tree.host._moId == "host-7"
    assert tree.summary.cluster._moId == "domain-c7"
    assert tree.host._stub is stub
    assert tree.summary.cluster._stub is stub
    assert collector._vsan_status_from_object(tree.host) is None
    assert collector._vsan_status_from_object(tree.summary.cluster) is None
    assert stub.calls == []


def test_sdk_health_findings_and_object_evidence_preserved(collector, sdk_health_tree):
    tree, stub, _ = sdk_health_tree
    issues = collector._extract_vsan_health_issues(tree.summary)

    assert issues == [
        {"component": "vSAN health check", "status": "yellow", "summary": ""},
        {"component": "Object accessibility", "status": "red", "summary": ""},
        {"component": "vSAN health check", "status": "inaccessible", "summary": "inaccessible"},
    ]
    assert collector._vsan_health_state_details(tree.summary) == [
        {"health": "inaccessible", "num_objects": 2, "object_uuids": ["obj-a", "obj-b"]},
        {"health": "inaccessible", "num_objects": 0, "object_uuids": []},
    ]
    assert collector._extract_vsan_object_issues(tree.summary) == [
        {"component": "Object accessibility", "status": "red", "summary": ""},
        {"component": "vSAN health check", "status": "inaccessible", "summary": "inaccessible"},
    ]
    assert stub.calls == []


def test_sdk_disk_mapping_retains_disk_identity_and_abnormal_state(collector):
    cache = vim.host.ScsiDisk(canonicalName="naa.cache", uuid="cache-uuid", operationalState=["ok"])
    capacity = vim.host.ScsiDisk(
        canonicalName="naa.capacity", uuid="capacity-uuid", operationalState=["error"],
        capacity=vim.host.DiskDimensions.Lba(blockSize=512, block=4096),
    )
    mapping = vim.vsan.host.DiskMapInfoEx(
        mapping=vim.vsan.host.DiskMapping(ssd=cache, nonSsd=[capacity]), isMounted=True,
    )

    nodes = collector._walk_public_objects([mapping])

    assert mapping.mapping in nodes
    assert cache in nodes
    assert capacity in nodes
    assert capacity.uuid == "capacity-uuid"
    assert capacity.capacity.blockSize == 512
    assert capacity.capacity.block == 4096
    assert collector._extract_vsan_disk_issues([mapping], "esxi-synthetic") == [{
        "host": "esxi-synthetic", "disk": "naa.capacity", "status": "['error']", "summary": "",
    }]


def test_local_records_do_not_evaluate_unrelated_properties(collector):
    class LocalRecord:
        def __init__(self):
            self.children = NS(testName="Local warning", testHealth="yellow")

        @property
        def unrelated_remote_property(self):
            raise AssertionError("A local record's descriptors are not response fields")

    assert collector._extract_vsan_health_issues(LocalRecord()) == [{
        "component": "Local warning", "status": "yellow", "summary": "",
    }]


def test_declared_dataobject_read_failure_is_not_swallowed(collector):
    class BrokenSdkResponse(vim.cluster.VsanClusterHealthSummary):
        def __getattribute__(self, name):
            if name == "groups":
                raise vim.fault.NoPermission(privilegeId="System.Read")
            return super().__getattribute__(name)

    with pytest.raises(vim.fault.NoPermission):
        collector._walk_public_objects(BrokenSdkResponse())


@pytest.mark.parametrize("status,count,expected", [
    (None, None, []), ("inaccessible", 0, []),
    ("inaccessible", None, [{"component": "objects", "status": "inaccessible", "summary": "inaccessible"}]),
    ("inaccessible", 2, [{"component": "objects", "status": "inaccessible", "summary": "inaccessible"}]),
    ("unknown", 2, []),
])
def test_missing_unknown_zero_and_abnormal_counts_keep_original_meaning(collector, status, count, expected):
    assert collector._extract_vsan_health_issues(NS(name="objects", health=status, numObjects=count)) == expected


def test_none_cycle_and_shared_child_keep_existing_traversal_boundaries(collector):
    child = NS(name="warning", health="yellow")
    tree = NS(children=[child, child])
    tree.cycle = tree
    assert collector._extract_vsan_health_issues(None) is None
    assert collector._vsan_object_issues_from_health_issues(None) is None
    assert collector._walk_public_objects(tree).count(child) == 1
    assert collector._extract_vsan_health_issues(tree) == [{
        "component": "warning", "status": "yellow", "summary": "yellow",
    }]


def test_object_issue_derivation_reuses_health_results_without_mutating_them(collector, sdk_health_tree):
    tree, _, _ = sdk_health_tree
    issues = collector._extract_vsan_health_issues(tree.summary)
    before = [dict(issue) for issue in issues]
    expected = [
        {"component": "Object accessibility", "status": "red", "summary": ""},
        {"component": "vSAN health check", "status": "inaccessible", "summary": "inaccessible"},
    ]

    objects = collector._vsan_object_issues_from_health_issues(issues)
    assert objects == expected
    objects[0]["status"] = "modified by a downstream consumer"
    assert issues == before


def test_managed_reference_is_not_dereferenced_as_a_nested_status(collector):
    stub = AccessTrapStub()
    host = vim.HostSystem("host-7", stub)
    assert collector._string_status(host) is None
    assert collector._vsan_status_from_object(NS(health=host)) is None
    assert stub.calls == []


def test_cluster_summary_scans_health_response_once(collector, sdk_health_tree, monkeypatch):
    tree, stub, _ = sdk_health_tree
    health_reads = []
    original = collector._extract_vsan_health_issues

    def extract_health(summary):
        health_reads.append(summary)
        return original(summary)

    monkeypatch.setattr(collector, "_with_vsan_ssl_context", lambda fn, *args: fn(*args))
    monkeypatch.setattr(collector, "_query_vsan_cluster_config", lambda *args: NS(enabled=True))
    monkeypatch.setattr(collector, "_query_vsan_health_summary", lambda *args: tree.summary)
    monkeypatch.setattr(collector, "_query_vsan_disk_inventory", lambda *args: {})
    monkeypatch.setattr(collector, "_query_vsan_disk_issues", lambda *args: [])
    monkeypatch.setattr(collector, "_query_vsan_space_usage", lambda *args: {})
    monkeypatch.setattr(collector, "_query_vsan_resync_summary", lambda *args: {"object_count": 0, "bytes": 0})
    monkeypatch.setattr(collector, "_extract_vsan_health_issues", extract_health)

    result = collector._collect_vsan_cluster_summary(NS(), {}, include_object_inventory=False)

    assert len(health_reads) == 1
    assert result["health_issue_count"] == 3
    assert result["object_health_issue_count"] == 2
    assert result["api_status"] == "collected"
    assert stub.calls == []


@pytest.mark.parametrize("fault,expected_status,reason", [
    (vim.fault.NoPermission(privilegeId="System.Read"), "permission_denied", "permission_denied"),
    (TimeoutError("synthetic health query timeout"), "unavailable", "timeout"),
])
def test_real_health_query_exceptions_keep_unavailable_evidence(
    collector, monkeypatch, fault, expected_status, reason,
):
    def fail_health(*args):
        raise fault

    warnings = []
    monkeypatch.setattr(collector, "_record_collection_warning", lambda context, error: warnings.append((context, error)))
    monkeypatch.setattr(collector, "_with_vsan_ssl_context", lambda fn, *args: fn(*args))
    monkeypatch.setattr(collector, "_query_vsan_cluster_config", lambda *args: NS(enabled=True))
    monkeypatch.setattr(collector, "_query_vsan_health_summary", fail_health)
    monkeypatch.setattr(collector, "_query_vsan_disk_inventory", lambda *args: {})
    monkeypatch.setattr(collector, "_query_vsan_disk_issues", lambda *args: [])
    monkeypatch.setattr(collector, "_query_vsan_space_usage", lambda *args: {})
    monkeypatch.setattr(collector, "_query_vsan_resync_summary", lambda *args: {"object_count": 0, "bytes": 0})

    result = collector._collect_vsan_cluster_summary(NS(), {}, include_object_inventory=False)

    assert result["api_status"] == expected_status
    assert result["health_issues"] is None
    assert result["object_health_issues"] is None
    assert result["health_issue_count"] is None
    assert result["issue_count"] is None
    assert result["collection_error"] == f"vSAN API unavailable: {reason}"
    assert warnings == [("vsan.optional_api", fault)]
