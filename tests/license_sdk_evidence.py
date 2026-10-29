"""Explicit offline SDK assignment samples for legacy integration fixtures.

No license kind is inferred from an old numeric sentinel. Each profile declares
the source record independently. Missing/modified canonical fields are left
untouched so a negative or missing-data test is never silently repaired.
"""
from copy import deepcopy
from datetime import UTC, datetime
from types import SimpleNamespace as NS

from pyVmomi import vim

from vstacklens.collection.license_state import fields, query_entity_license

OBSERVED_AT = datetime(2026, 6, 4, tzinfo=UTC)
PROFILES = {
    "pass": {
        "vc-1": ("SYN vCenter Standard", "Standard", "2027-06-04T00:00:00Z", False),
        "host-1": ("VMware vSphere Enterprise Plus", "Enterprise Plus", "Never", False),
    },
    "fail": {
        "vc-1": ("SYN vCenter Standard", "Standard", "2026-06-19T00:00:00Z", False),
        "host-1": ("VMware vSphere Evaluation License", "Evaluation", "2026-06-19T00:00:00Z", True),
        "host-2": ("VMware vSphere Enterprise Plus", "Enterprise Plus", "Never", False),
    },
}
HOST_FIELDS = {"host_license_assigned", "host_license_name", "host_license_edition", "host_license_is_evaluation",
               "host_license_expiration_date", "host_license_expiration_days"}


def with_declared_license_sources(raw, profile):
    """Add provenance only when all previously declared business values agree."""
    result = deepcopy(raw)
    declarations = PROFILES[profile]
    vc, = [o for o in result["objects"] if o["object_type"] == "vCenter"]
    scope = vc["object_key"]  # Explicit synthetic About.instanceUuid, not name/IP.
    for obj in result["objects"]:
        host = obj["object_type"] == "HostSystem"
        if obj["object_type"] not in {"HostSystem", "vCenter"} or obj["object_key"] not in declarations:
            continue
        props = obj["properties"]
        required = HOST_FIELDS if host else {"license_days_remaining"}
        if any(k not in props or props[k] is None for k in required):
            continue
        name, edition, expiry, evaluation = declarations[obj["object_key"]]
        product = "VMware ESX Server" if host else "VMware VirtualCenter Server"
        values = [vim.KeyAnyValue(key="ProductName", value=product), vim.KeyAnyValue(key="ProductVersion", value="8.0"),
                  vim.KeyAnyValue(key="expirationDate", value=expiry)]
        if evaluation:
            values.append(vim.KeyAnyValue(key="LicenseType", value="evaluation"))
        info = vim.LicenseManager.LicenseInfo(name=name, editionKey=edition, properties=values)
        record = vim.LicenseAssignmentManager.LicenseAssignment(entityId=obj["object_key"], scope=scope, assignedLicense=info)
        def query(*, entityId):
            assert entityId == record.entityId
            return [record]
        content = NS(licenseManager=NS(licenseAssignmentManager=NS(QueryAssignedLicenses=query)))
        state = query_entity_license(content, obj["object_key"], obj["object_type"], scope, now=OBSERVED_AT)
        bound = fields(state, host=host)
        # Check, never overwrite a deliberate mutation with the profile's value.
        if any(props[k] != bound[k] for k in required):
            continue
        props.update(bound)
    return result
