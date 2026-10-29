from copy import deepcopy
import json
from pathlib import Path

import pytest

from tests.license_sdk_evidence import with_declared_license_sources

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize("name,profile", [("inventory_pass.json", "pass"), ("inventory_fail.json", "fail")])
def test_explicit_sdk_evidence_preserves_all_original_business_fields(name, profile):
    path = FIXTURES / name
    before_bytes = path.read_bytes()
    raw = json.loads(before_bytes)
    original = deepcopy(raw)
    after = with_declared_license_sources(raw, profile)
    assert raw == original and path.read_bytes() == before_bytes
    for left, right in zip(raw["objects"], after["objects"]):
        assert left.keys() == right.keys()
        for key in left:
            if key != "properties":
                assert left[key] == right[key]
        for key, value in left["properties"].items():
            if key != "host_license_probe_status":
                assert right["properties"][key] == value


@pytest.mark.parametrize("key", ["host_license_assigned", "host_license_name", "host_license_edition",
                                 "host_license_is_evaluation", "host_license_expiration_days", "host_license_expiration_date"])
def test_missing_canonical_license_field_is_never_repaired_by_fixture_adapter(key):
    raw = json.loads((FIXTURES / "inventory_pass.json").read_text("utf-8"))
    host = next(o for o in raw["objects"] if o["object_type"] == "HostSystem")
    host["properties"].pop(key)
    after = with_declared_license_sources(raw, "pass")
    result = next(o for o in after["objects"] if o["object_type"] == "HostSystem")
    assert key not in result["properties"] and "host_license_evidence" not in result["properties"]


@pytest.mark.parametrize("days", [None, 0, 15, 365, "999999", False])
def test_deliberately_changed_scalar_is_not_replaced_with_declared_positive_profile(days):
    raw = json.loads((FIXTURES / "inventory_pass.json").read_text("utf-8"))
    host = next(o for o in raw["objects"] if o["object_type"] == "HostSystem")
    host["properties"]["host_license_expiration_days"] = days
    after = with_declared_license_sources(raw, "pass")
    result = next(o for o in after["objects"] if o["object_type"] == "HostSystem")
    assert result["properties"]["host_license_expiration_days"] == days
    assert "host_license_evidence" not in result["properties"]


def test_perpetual_evidence_is_explicit_field_not_old_numeric_inference():
    raw = json.loads((FIXTURES / "inventory_pass.json").read_text("utf-8"))
    after = with_declared_license_sources(raw, "pass")
    host = next(o for o in after["objects"] if o["object_type"] == "HostSystem")
    state = host["properties"]["host_license_evidence"]
    assert state["assigned"] is True and state["entity_id"] == host["object_key"]
    assert state["perpetual_evidence"] == [{"source_path": "LicenseInfo.properties.expirationdate", "value": "Never", "meaning": "explicit_no_expiration"}]
