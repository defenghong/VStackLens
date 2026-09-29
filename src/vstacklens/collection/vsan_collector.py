from __future__ import annotations

from typing import Any

from vstacklens.upgrade_compat.vsan import VsanContext, cluster_vsan_context


def collect_vsan_storage(esxcli: Any) -> list[Any]:
    """Read-only wrapper for ``esxcli vsan storage list``."""
    return list(_call(esxcli, "vsan.storage.list") or [])


def collect_storage_devices(esxcli: Any) -> list[Any]:
    """Read-only wrapper for ``esxcli storage core device list``."""
    return list(_call(esxcli, "storage.core.device.list") or [])


def collect_cluster_vsan_context(cluster: Any, *, esxcli: Any | None = None, controller_mode: str | None = None) -> VsanContext:
    config_ex = _get(cluster, "configurationEx", "ConfigurationEx")
    config = _get(config_ex, "vsanConfigInfo", "VsanConfigInfo")
    disks = collect_vsan_storage(esxcli) if esxcli is not None else None
    error = None if esxcli is not None or _get(config, "enabled", "Enabled") is False else "vSAN storage list unavailable"
    return cluster_vsan_context(config, disks, controller_mode=controller_mode, collection_error=error)


def enrich_drive_types(luns: list[Any], devices: list[Any]) -> list[dict[str, Any]]:
    """Attach direct ESXi DriveType evidence to ScsiLun-like records."""
    by_device = {}
    for device in devices:
        key = _text(_get(device, "device", "Device"))
        model = _text(_get(device, "model", "Model"))
        if key:
            by_device[key.casefold()] = device
        if model:
            by_device.setdefault(model.casefold(), device)
    output = []
    for lun in luns:
        canonical = _text(_get(lun, "canonicalName", "CanonicalName"))
        model = _text(_get(lun, "model", "Model"))
        source = by_device.get(canonical.casefold()) or by_device.get(model.casefold())
        output.append({
            "drive_type": _none_text(_get(source, "driveType", "DriveType")) if source else None,
            "raid_level": _none_text(_get(source, "raidLevel", "RAIDLevel")) if source else None,
            "physical_drive_count": _number_or_none(_get(source, "numberofPhysicalDrives", "NumberofPhysicalDrives")) if source else None,
            "drive_type_source": "storage.core.device.list" if source else None,
        })
    return output


def _call(esxcli: Any, command: str) -> Any:
    for name in ("execute", "Execute", "invoke", "Invoke"):
        method = getattr(esxcli, name, None)
        if callable(method):
            try:
                return method(command, {})
            except TypeError:
                return method(command)
    current = esxcli
    for part in command.split("."):
        current = getattr(current, part)
    invoke = getattr(current, "Invoke", None) or getattr(current, "invoke", None)
    if not callable(invoke):
        raise RuntimeError(f"esxcli command unavailable: {command}")
    return invoke({})


def _get(obj: Any, *names: str) -> Any:
    for name in names:
        if obj is None:
            return None
        if isinstance(obj, dict) and name in obj:
            return obj[name]
        try:
            return getattr(obj, name)
        except AttributeError:
            pass
    return None


def _text(value: Any) -> str:
    return str(value or "").strip()


def _none_text(value: Any) -> str | None:
    text = _text(value)
    return text or None


def _number_or_none(value: Any) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None
