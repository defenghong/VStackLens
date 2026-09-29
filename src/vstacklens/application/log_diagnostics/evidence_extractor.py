from __future__ import annotations

from pathlib import Path


class EvidenceExtractor:
    """Shared evidence filtering rules for support-bundle diagnosis."""

    STATIC_REFERENCE_FILENAMES = frozenset(
        {
            "vmkerrcode_-l.txt",
            "usb.ids",
            "pci.ids",
            "secpolicytools_-d.txt",
            "schema-store-1-dump.txt",
        }
    )
    STATIC_REFERENCE_PATH_TERMS = (
        "schema-store",
        "schemastoreschema",
        "sqlite3_etcvmware",
        "/etc/vmware/schema",
        "/etc/vmware/pci.ids",
        "/etc/vmware/usb.ids",
    )

    @classmethod
    def is_reference_material_file(cls, path: str) -> bool:
        normalized = path.lower().replace("\\", "/")
        name = Path(normalized).name
        if name in cls.STATIC_REFERENCE_FILENAMES:
            return True
        if any(term in normalized for term in cls.STATIC_REFERENCE_PATH_TERMS):
            return True
        if normalized.endswith("/etc/vmware/usb.ids") or normalized.endswith("/etc/vmware/pci.ids"):
            return True
        if normalized.endswith("/commands/vmkerrcode_-l.txt") or normalized.endswith("/commands/secpolicytools_-d.txt"):
            return True
        return False
