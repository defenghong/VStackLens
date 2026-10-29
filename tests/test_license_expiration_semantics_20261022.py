from datetime import UTC, datetime
from types import SimpleNamespace as NS

import pytest

import vstacklens.collection.pyvmomi_collector as collector_module
from vstacklens.collection.pyvmomi_collector import PyVmomiCollector


NOW = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)


class FrozenDatetimeMeta(type):
    def __instancecheck__(cls, instance):
        return isinstance(instance, datetime)


class FrozenDatetime(datetime, metaclass=FrozenDatetimeMeta):
    @classmethod
    def now(cls, tz=None):
        return NOW if tz is not None else NOW.replace(tzinfo=None)


@pytest.fixture
def collector(monkeypatch):
    monkeypatch.setattr(collector_module, "datetime", FrozenDatetime)
    return PyVmomiCollector("offline.invalid", "fixture-user", "fixture-secret")


def license_info(value=..., *, name="Fixture license"):
    properties = [] if value is ... else [NS(key="expirationDate", value=value)]
    return NS(name=name, properties=properties)


def content(*licenses, kind="vCenter"):
    product = "VMware VirtualCenter Server" if kind == "vCenter" else "VMware ESX Server"
    entity = "vc-fixture" if kind == "vCenter" else "host-1"
    # These are explicit entity assignments, not a stock inventory.
    entries = [NS(entityId=entity, scope="vc-fixture", assignedLicense=lic,
                  properties=[NS(key="ProductName", value=product)]) for lic in licenses]
    return NS(about=NS(instanceUuid="vc-fixture"),
              licenseManager=NS(licenseAssignmentManager=NS(QueryAssignedLicenses=lambda **kw: entries)))


def host_fields(collector, item):
    return collector._host_license_assignments(content(item, kind="HostSystem"), [NS(_moId="host-1", config=None)])["host-1"]


@pytest.mark.parametrize("value", [None, "", "not-a-date", "999999", 0, False])
def test_unusable_expiration_never_becomes_permanent(collector, value):
    assert collector._license_days_remaining(content(license_info(value))) is None
    host = host_fields(collector, license_info(value))
    assert host["host_license_expiration_date"] is None
    assert host["host_license_expiration_days"] is None


def test_missing_expiration_never_becomes_permanent(collector):
    assert collector._license_days_remaining(content(license_info())) is None
    host = host_fields(collector, license_info())
    assert host["host_license_expiration_date"] is None
    assert host["host_license_expiration_days"] is None


@pytest.mark.parametrize("value", ["Never", "perpetual", "永久授权"])
def test_explicit_permanent_marker_keeps_legacy_sentinel(collector, value):
    assert collector._license_days_remaining(content(license_info(value))) == 999999
    host = host_fields(collector, license_info(value))
    assert host["host_license_expiration_date"] == "永久授权"
    assert host["host_license_expiration_days"] == 999999


@pytest.mark.parametrize(
    ("value", "days"),
    [
        (datetime(2026, 11, 21, 12, tzinfo=UTC), 30),
        (FrozenDatetime(2026, 11, 21, 12, tzinfo=UTC), 30),
        ("2026-11-21T12:00:00Z", 30),
        ("2026-11-21T20:00:00+08:00", 30),
        ("2026-10-21T12:00:00Z", -1),
    ],
)
def test_explicit_expiration_is_preserved(collector, value, days):
    assert collector._license_days_remaining(content(license_info(value))) == days
    host = host_fields(collector, license_info(value))
    assert host["host_license_expiration_days"] == days
    assert host["host_license_expiration_date"] == ("2026-10-21" if days == -1 else "2026-11-21")


def test_top_level_expiration_string_supported_without_new_remote_read(collector):
    item = NS(expirationDate="2026-11-21T12:00:00Z", properties=[])
    assert collector._license_days_remaining(content(item)) == 30


def test_mixed_known_expirations_keep_nearest(collector):
    items = [license_info("Never"), license_info("2026-12-21T12:00:00Z"), license_info("2026-11-21T12:00:00Z")]
    assert collector._license_days_remaining(content(*items)) is None


def test_explicit_perpetual_plus_unknown_cannot_claim_perpetual(collector):
    assert collector._license_days_remaining(content(license_info("Never"), license_info())) is None


@pytest.mark.parametrize("unknown_first", [False, True])
@pytest.mark.parametrize(
    ("known", "days"),
    [("2026-10-21T12:00:00Z", -1), ("2026-11-21T12:00:00Z", 30), ("2027-10-22T12:00:00Z", 365)],
)
def test_unknown_entry_does_not_hide_a_known_deadline(collector, known, days, unknown_first):
    entries = [license_info(known), license_info()]
    if unknown_first:
        entries.reverse()
    # Ambiguous multiple same-product assignments cannot certify target expiry.
    assert collector._license_days_remaining(content(*entries)) is None


def test_conflicting_permanent_and_date_is_unknown(collector):
    item = NS(properties=[NS(key="expirationDate", value="Never"), NS(key="expires", value="2026-11-21T12:00:00Z")])
    assert collector._license_days_remaining(content(item)) is None


def test_expiration_read_permission_failure_is_unknown(collector):
    class Restricted:
        name = "Fixture license"

        @property
        def properties(self):
            raise PermissionError("fixture denied")

    assert collector._license_days_remaining(content(Restricted())) is None
    assert host_fields(collector, Restricted())["host_license_expiration_days"] is None
    assert collector._collection_diagnostics


def test_manager_read_permission_failure_is_unknown(collector):
    class Restricted:
        @property
        def licenseManager(self):
            raise PermissionError("fixture denied")

    assert collector._license_days_remaining(Restricted()) is None
    assert collector._collection_diagnostics


@pytest.mark.parametrize("licenses", [[], [None]])
def test_zero_valid_license_is_unknown(collector, licenses):
    assert collector._license_days_remaining(content(*licenses)) is None


def test_evaluation_name_alone_does_not_prove_perpetual(collector):
    item = license_info(name="Product Evaluation")
    assert collector._license_days_remaining(content(item)) is None


def test_host_product_name_fallback_keeps_expiration_unknown(collector):
    host = NS(config=NS(product=NS(licenseProductName="VMware vSphere Enterprise Plus")))
    fields = collector._host_license_from_config(host)
    assert fields["host_license_name"] is None
    assert fields["host_license_required_product_name"] == "VMware vSphere Enterprise Plus"
    assert fields["host_license_expiration_date"] is None
    assert fields["host_license_expiration_days"] is None


def test_missing_display_name_never_projects_raw_license_key(collector):
    item = license_info("Never", name="")
    item.licenseKey = "SYNTHETIC-LICENSE-SECRET"
    fields = host_fields(collector, item)
    assert fields["host_license_name"] == item.name
    assert item.licenseKey not in str(fields)


def test_real_sdk_typed_license_properties_remain_supported(collector):
    from pyVmomi import vim

    item = vim.LicenseManager.LicenseInfo(
        name="Fixture SDK license",
        properties=[vim.KeyAnyValue(key="expirationDate", value=datetime(2026, 11, 21, 12, tzinfo=UTC))],
    )
    assert collector._license_days_remaining(content(item)) == 30
