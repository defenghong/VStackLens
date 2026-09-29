from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Iterable

from vstacklens.inventory.canonical_models import CanonicalInventory, CanonicalObject

PCI_CATEGORIES = {"controller", "nic", "ssd", "hdd"}
PCI_QUADRUPLE_FIELDS = ("vid", "did", "svid", "ssid")
PCI_REQUIRED_FIELDS = ("category", "driver_name", "driver_version")


class InventoryNormalizer:
    def normalize(self, raw: dict) -> CanonicalInventory:
        objects = [
            CanonicalObject(
                object_type=item["object_type"],
                object_key=item["object_key"],
                object_name=item["object_name"],
                object_path=item.get("object_path", item["object_name"]),
                properties=item.get("properties", {}),
                raw_ref=item.get("raw_ref"),
            )
            for item in raw.get("objects", [])
        ]
        return CanonicalInventory(objects=objects)

    def normalize_pci_records(
        self,
        records: Iterable[dict[str, Any]],
        *,
        source: str | None = None,
        collected_at: str | None = None,
    ) -> CanonicalInventory:
        """Normalize either collector's PCI records into the phase-two contract.

        Category cannot be repaired at this layer: records without one of the four
        contract values are omitted so a bad collector cannot masquerade as a valid
        rule input. Other missing fields remain ``None`` and are intentionally kept.
        """
        timestamp = collected_at or datetime.now(UTC).isoformat()
        objects: list[CanonicalObject] = []
        for index, record in enumerate(records):
            category = record.get("category")
            if category not in PCI_CATEGORIES:
                continue
            properties = dict(record.get("properties") or {})
            # Keep the complete phase-two shape even when a collector cannot
            # provide an optional or path-specific field. ``None`` is the
            # missing-data signal consumed by the plugin layer.
            for field in PCI_REQUIRED_FIELDS + PCI_QUADRUPLE_FIELDS + (
                "model", "firmware_version", "pci_address", "pci_association_status", "association_conflict",
                "firmware_raw", "firmware_candidate", "firmware_confidence", "field_sources",
                "drive_type", "raid_level", "physical_drive_count", "drive_type_source",
                "vsan_enabled", "vsan_architecture", "vsan_disk_layout", "controller_mode",
            ):
                if field not in properties:
                    properties[field] = record.get(field)
            properties["source"] = properties.get("source") or source or record.get("source") or "unknown"
            properties["collected_at"] = properties.get("collected_at") or timestamp
            object_key = str(record.get("object_key") or self._pci_object_key(record, index))
            object_name = str(record.get("object_name") or record.get("model") or object_key)
            objects.append(
                CanonicalObject(
                    object_type="HostPciDevice",
                    object_key=object_key,
                    object_name=object_name,
                    object_path=str(record.get("object_path") or object_name),
                    properties=properties,
                    raw_ref=record.get("raw_ref"),
                )
            )
        return CanonicalInventory(objects=objects)

    def normalize_host_records(self, records: Iterable[dict[str, Any]]) -> CanonicalInventory:
        """Create HostSystem canonical objects for stage-six server checks."""
        objects: list[CanonicalObject] = []
        for index, record in enumerate(records):
            model = record.get("smbios_model") or record.get("model")
            key = str(record.get("object_key") or record.get("host") or f"host:{index}")
            objects.append(CanonicalObject(
                object_type="HostSystem",
                object_key=key,
                object_name=str(record.get("object_name") or record.get("host") or model or key),
                object_path=str(record.get("object_path") or record.get("cluster") or key),
                properties={
                    "smbios_model": model,
                    "cluster": record.get("cluster"),
                    "vsan_enabled": record.get("vsan_enabled"),
                    "bios_version": record.get("bios_version"),
                    "bios_release_date": record.get("bios_release_date"),
                    "cpu_model": record.get("cpu_model"),
                    "cpu_sockets": record.get("cpu_sockets"),
                    "cpu_cores": record.get("cpu_cores"),
                    "cpu_threads": record.get("cpu_threads"),
                    "memory_bytes": record.get("memory_bytes"),
                    "uptime_seconds": record.get("uptime_seconds"),
                    "esxi_version": record.get("esxi_version"),
                    "esxi_build": record.get("esxi_build"),
                    "host_context_source": record.get("host_context_source") or record.get("source") or "unknown",
                },
            ))
        return CanonicalInventory(objects=objects)

    def _pci_object_key(self, record: dict[str, Any], index: int) -> str:
        quadruple = ":".join(str(record.get(field) or "") for field in PCI_QUADRUPLE_FIELDS)
        model = str(record.get("model") or "")
        return f"{record.get('host') or 'host'}:{record.get('category')}:{quadruple}:{model}:{index}"
