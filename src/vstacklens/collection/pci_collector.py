from __future__ import annotations

import re
import ssl
import socket
import time
import tarfile
import zipfile
from collections.abc import Mapping
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from vstacklens.collection.collection_plan import CollectionPlan
from vstacklens.core.context import RunContext
from vstacklens.collection.vsan_collector import enrich_drive_types
from vstacklens.upgrade_compat.vsan import aggregate_controller_mode, cluster_vsan_context


PCI_ID_FIELDS = ("vid", "did", "svid", "ssid")
_CLASS_NETWORK = {0x02}
_CLASS_STORAGE = {0x01}
_PCI_ADDRESS = re.compile(r"(?i)(?:\()?(?:(?P<domain>[0-9a-f]{4}):)?(?P<bus>[0-9a-f]{2}):(?P<slot>[0-9a-f]{2})\.(?P<function>[0-9a-f])(?:\))?")


def normalize_pci_id(value: Any) -> str | None:
    """Convert pyVmomi's signed 16-bit IDs to lowercase four-digit hex."""
    if value is None or value == "":
        return None
    number = _parse_number(value)
    if number is None:
        return None
    return f"{number & 0xFFFF:04x}"


def normalize_pci_address(value: Any) -> str | None:
    """Return domain:bus:slot.function without collapsing multifunction devices."""
    text = _text_or_none(value)
    if not text:
        return None
    # Storage adapter descriptions include the address in parentheses, while
    # HostPciDevice.Id and Pnic.pci contain the address itself.
    match = _PCI_ADDRESS.search(text.strip())
    if not match:
        return None
    return f"{match.group('domain') or '0000'}:{match.group('bus')}:{match.group('slot')}.{match.group('function')}".lower()


def _parse_number(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        if isinstance(value, str):
            text = value.strip()
            try:
                return int(text, 0)
            except ValueError:
                return int(text, 16)
        return int(value)
    except (TypeError, ValueError):
        return None


def describe_pci_collection_capabilities() -> list[dict[str, str]]:
    """Static capability record used when no live vCenter is available."""
    return [
        {"field": "PCI 四元组", "direct_available": "是", "source": "host.hardware.pciDevice[].vendorId/deviceId/subVendorId/subDeviceId", "note": "short 需按有符号 16 位转换"},
        {"field": "category", "direct_available": "部分", "source": "host.hardware.pciDevice[].classId/deviceClass; host.config.storageDevice.scsiLun[]", "note": "未知类别不产出对象"},
        {"field": "model", "direct_available": "部分", "source": "pciDevice.deviceName/name; scsiLun.model/displayName/deviceName", "note": "依 SDK 对象属性而定"},
        {"field": "driver_name", "direct_available": "部分", "source": "host.config.network.pnic[].driver；host.config.storageDevice.hostBusAdapter[].driver", "note": "PCI 对象本身不保证 driverName"},
        {"field": "driver_version", "direct_available": "不确定", "source": "pnic[].driverVersion（ESXi 8+）；kernelModuleSystem.QueryModules()", "note": "QueryModules 不可用时保留 None"},
        {"field": "firmware_version", "direct_available": "不确定", "source": "host.config.network.pnic[].firmwareVersion", "note": "HBA/控制器 SDK 不保证该属性；拿不到保留 None"},
    ]


def classify_pci_device(device: Any) -> str | None:
    value = getattr(device, "classId", None)
    if value is None:
        value = getattr(device, "deviceClass", None)
    class_id = _parse_number(value)
    if class_id is None:
        return None
    class_id = (class_id >> 8) if class_id > 0xFF else class_id
    if class_id in _CLASS_NETWORK:
        return "nic"
    if class_id in _CLASS_STORAGE:
        return "controller"
    return None


def classify_storage_lun(lun: Any) -> str | None:
    model = " ".join(str(getattr(lun, field, "") or "") for field in ("model", "displayName", "deviceName")).lower()
    is_ssd = getattr(lun, "ssd", None)
    if isinstance(is_ssd, str):
        is_ssd = is_ssd.strip().lower() in {"true", "yes", "1", "ssd"}
    if is_ssd is True or "ssd" in model:
        return "ssd"
    if is_ssd is False or model:
        return "hdd"
    return None


def _safe_getattr(obj: Any, name: str, default: Any = None) -> Any:
    try:
        if isinstance(obj, Mapping):
            return obj.get(name, default)
        return getattr(obj, name, default)
    except Exception:  # noqa: BLE001 - remote pyVmomi properties can fault.
        return default


def _firmware_result(raw: Any, *, candidate: str | None = None, confidence: str = "certain") -> dict[str, Any]:
    text = _text_or_none(raw)
    if text is None:
        return {"firmware_version": None, "firmware_raw": None, "firmware_candidate": None, "firmware_confidence": None}
    return {"firmware_version": candidate if confidence == "certain" and candidate else text, "firmware_raw": text, "firmware_candidate": candidate, "firmware_confidence": confidence}


def _parse_lsi_msgpt3(value: Any) -> dict[str, Any]:
    text = _text_or_none(value)
    match = re.search(r"(?i)firmware\s+package\s+version\s*:\s*([^\s]+)", text or "")
    return _firmware_result(text, candidate=match.group(1) if match else None, confidence="certain" if match else "unknown")


def _parse_intel_comma(value: Any) -> dict[str, Any]:
    text = _text_or_none(value)
    candidate = text.rsplit(",", 1)[-1].strip() if text and "," in text else None
    return _firmware_result(text, candidate=candidate if candidate and re.fullmatch(r"\d+(?:\.\d+)+", candidate) else None, confidence="low")


def _parse_intel_colon(value: Any) -> dict[str, Any]:
    text = _text_or_none(value)
    candidate = text.rsplit(":", 1)[-1].strip() if text and ":" in text else None
    return _firmware_result(text, candidate=candidate if candidate and re.fullmatch(r"\d+(?:\.\d+)+", candidate) else None, confidence="low")


def _parse_raw_certain(value: Any) -> dict[str, Any]:
    return _firmware_result(value, confidence="certain")


def _parse_raw_uncertain(value: Any) -> dict[str, Any]:
    return _firmware_result(value, confidence="unknown")


FIRMWARE_PARSERS = {
    "lsi_mr3": _parse_raw_certain,
    "lsi_msgpt3": _parse_lsi_msgpt3,
    "nmlx5_core": _parse_raw_certain,
    "ntg3": _parse_raw_uncertain,
    "ixgben": _parse_intel_comma,
    "igbn": _parse_intel_colon,
}


def parse_firmware(driver_name: Any, value: Any) -> dict[str, Any]:
    """Dispatch firmware parsing by driver while preserving unknown captured values."""
    parser = FIRMWARE_PARSERS.get(str(driver_name or "").strip())
    return parser(value) if parser else _parse_raw_uncertain(value)


class PyVmomiPciCollector:
    """Collect host PCI/storage devices without requiring an ESXi shell session."""

    def __init__(self, host: str, username: str, password: str, port: int = 443, ssl_verify: bool = False, timeout: float = 8.0, esxcli_provider: Any = None) -> None:
        self.host, self.username, self.password = host, username, password
        self.port, self.ssl_verify, self.timeout = port, ssl_verify, timeout
        self.esxcli_provider = esxcli_provider
        self.cancel_requested = lambda: False
        self.batch_progress = None
        self._host_timings: dict[str, dict[str, float]] = {}
        self._host_records: list[dict[str, Any]] = []

    def collect(self, context: RunContext, plan: CollectionPlan) -> dict[str, Any]:
        collected_at = datetime.now(UTC).isoformat()
        warnings: list[dict[str, str]] = []
        objects: list[dict[str, Any]] = []
        self._host_records = []
        timings: dict[str, dict[str, float]] = {}
        try:
            from pyVim.connect import Disconnect, SmartConnect
            from pyVmomi import vim
        except ImportError as exc:
            return {"objects": [], "collection_status": "unavailable", "collection_warnings": [{"status": "missing_dependency", "error": str(exc)}]}
        ssl_context = None if self.ssl_verify else ssl._create_unverified_context()  # noqa: SLF001
        service_instance = None
        about = None
        try:
            service_instance = SmartConnect(host=self.host, user=self.username, pwd=self.password, port=self.port, sslContext=ssl_context, httpConnectionTimeout=self.timeout)
            content = service_instance.RetrieveContent()
            about = _safe_getattr(content, "about")
            hosts = self._collect_view(content, getattr(vim, "HostSystem", None))
            for host_index, host in enumerate(hosts):
                if self.cancel_requested():
                    warnings.append({"status": "cancelled"})
                    break
                if host_index % 10 == 0:
                    batch = hosts[host_index:host_index + 10]
                    if self.batch_progress:
                        self.batch_progress(host_index, len(hosts))
                    if hasattr(self.esxcli_provider, "prepare"):
                        self.esxcli_provider.cancel_requested = self.cancel_requested
                        try:
                            self.esxcli_provider.prepare(batch)
                            warnings.extend(self.esxcli_provider.warnings)
                        except Exception as exc:
                            warnings.append({"status": "esxcli_backend_unavailable", "error": str(exc) if type(exc).__name__ == "BackendUnavailable" else type(exc).__name__, "batch": host_index // 10 + 1})
                try:
                    if "_host_devices" in self.__dict__:
                        host_objects = self._host_devices(host, collected_at)
                        host_warnings = []
                    else:
                        host_objects, host_warnings = self._host_devices_with_warnings(host, collected_at)
                    objects.extend(host_objects)
                    warnings.extend(host_warnings)
                    host_name = str(_safe_getattr(host, "name", "unknown"))
                    if host_name in self._host_timings:
                        timings[host_name] = self._host_timings[host_name]
                except Exception as exc:  # noqa: BLE001 - one host must not abort the batch.
                    warnings.append({"host": str(_safe_getattr(host, "name", "unknown")), "status": "collection_failed", "error": type(exc).__name__})
                    self._host_records.append({"host": str(_safe_getattr(host, "name", "unknown")), "smbios_model": None, "collection_status": "failed"})
        except Exception as exc:  # noqa: BLE001 - connection/auth/API failures degrade the run.
            warnings.append({"host": self.host, "status": "connection_failed", "error": type(exc).__name__})
        finally:
            if service_instance is not None:
                try:
                    from pyVim.connect import Disconnect
                    Disconnect(service_instance)
                except Exception:
                    pass
        warnings.extend(self._cluster_context_warnings())
        return {
            "objects": objects,
            "host_records": self._host_records,
            "collection_status": "degraded" if warnings else "collected",
            "collection_warnings": warnings,
            "source": "vcenter",
            "collected_at": collected_at,
            "host_timings_seconds": timings,
            "vcenter_version": _safe_getattr(about, "version") if service_instance is not None else None,
            "vcenter_build": _safe_getattr(about, "build") if service_instance is not None else None,
        }

    def _collect_view(self, content: Any, vim_type: Any) -> list[Any]:
        if vim_type is None:
            return []
        view = content.viewManager.CreateContainerView(content.rootFolder, [vim_type], True)
        try:
            return list(view.view)
        finally:
            view.Destroy()

    def _host_devices(self, host: Any, collected_at: str) -> list[dict[str, Any]]:
        records, _warnings = self._host_devices_with_warnings(host, collected_at)
        return records

    def _host_devices_with_warnings(self, host: Any, collected_at: str) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
        warnings: list[dict[str, str]] = []
        host_name = str(_safe_getattr(host, "name", None) or _safe_getattr(host, "_moId", "host"))
        hardware = _safe_getattr(host, "hardware")
        pci_devices = _safe_getattr(hardware, "pciDevice", []) or []
        module_versions = self._query_kernel_modules(host)
        network_info = self._network_driver_info(host, module_versions)
        hba_info = self._hba_driver_info(host, module_versions)
        esxcli_info, esxcli_warnings, timings = self._esxcli_enrichment(host, pci_devices, module_versions)
        unmatched_adapters = esxcli_info.pop("_unmatched", [])
        storage_devices = esxcli_info.pop("_storage_devices", [])
        vsan_storage = esxcli_info.pop("_vsan_storage", [])
        vsan_unavailable = esxcli_info.pop("_vsan_storage_unavailable", False)
        cluster = _safe_getattr(host, "parent")
        vsan_config = _safe_getattr(_safe_getattr(cluster, "configurationEx"), "vsanConfigInfo")
        vsan_context = cluster_vsan_context(vsan_config, vsan_storage, controller_mode=aggregate_controller_mode(storage_devices), collection_error="esxcli vsan storage list unavailable" if vsan_unavailable else None)
        system_info = _safe_getattr(hardware, "systemInfo")
        bios_info = _safe_getattr(hardware, "biosInfo")
        cpu_info = _safe_getattr(hardware, "cpuInfo")
        quick_stats = _safe_getattr(_safe_getattr(host, "summary"), "quickStats")
        cpu_packages = _safe_getattr(hardware, "cpuPkg", []) or []
        product = _safe_getattr(_safe_getattr(host, "config"), "product")
        self._host_records.append({
            "host": host_name,
            "cluster": _safe_getattr(cluster, "name"),
            "smbios_model": _safe_getattr(system_info, "model"),
            "bios_version": _safe_getattr(bios_info, "biosVersion") or _safe_getattr(bios_info, "version"),
            "bios_release_date": _safe_getattr(bios_info, "releaseDate") or _safe_getattr(bios_info, "date"),
            "cpu_model": _safe_getattr(cpu_info, "model") or _safe_getattr(_safe_getattr(_safe_getattr(host, "summary"), "hardware"), "cpuModel"),
            "cpu_sockets": _safe_getattr(cpu_info, "numCpuPackages") or (len(cpu_packages) if cpu_packages else None),
            "cpu_cores": _safe_getattr(cpu_info, "numCpuCores"),
            "cpu_threads": _safe_getattr(cpu_info, "numCpuThreads"),
            "memory_bytes": _safe_getattr(hardware, "memorySize"),
            "uptime_seconds": _safe_getattr(quick_stats, "uptime"),
            "esxi_version": _safe_getattr(product, "version"),
            "esxi_build": _safe_getattr(product, "build"),
            "host_context_source": "vcenter",
            "vsan_enabled": vsan_context.vsan_enabled,
            "vsan_architecture": vsan_context.vsan_architecture,
            "vsan_disk_layout": vsan_context.vsan_disk_layout,
        })
        result: list[dict[str, Any]] = []
        nic_index = 0
        for index, device in enumerate(pci_devices):
            category = classify_pci_device(device)
            if category is None:
                continue
            quad = {field: normalize_pci_id(_safe_getattr(device, source)) for field, source in zip(PCI_ID_FIELDS, ("vendorId", "deviceId", "subVendorId", "subDeviceId"))}
            model = _safe_getattr(device, "deviceName") or _safe_getattr(device, "name")
            pci_address = normalize_pci_address(_safe_getattr(device, "id") or _safe_getattr(device, "Id"))
            observations = network_info if category == "nic" else hba_info
            candidates = [entry for entry in observations if pci_address and entry.get("pci_address") == pci_address]
            info = candidates[0] if len(candidates) == 1 else {}
            if len(candidates) > 1:
                warnings.append({"host": host_name, "status": "pci_association_conflict", "pci_address": pci_address})
            enriched = esxcli_info.pop(pci_address, {}) if pci_address else {}
            merged = dict(info)
            for key, value in enriched.items():
                if value is not None and value != "":
                    if key in {"driver_name", "driver_version", "firmware_version"} and info.get(key) and info[key] != value:
                        warnings.append({"host": host_name, "status": "field_source_conflict", "field": key, "pci_address": pci_address})
                        merged["association_conflict"] = True
                    merged[key] = value
            result.append({"object_key": f"{host_name}:pci:{pci_address or index}", "object_name": str(model or f"PCI device {index}"), "object_path": host_name, "host": host_name, "category": category, "model": enriched.get("model") or model, **quad, "driver_name": merged.get("driver_name"), "driver_version": merged.get("driver_version"), "firmware_version": merged.get("firmware_version"), "firmware_raw": merged.get("firmware_raw"), "firmware_candidate": merged.get("firmware_candidate"), "firmware_confidence": merged.get("firmware_confidence"), "field_sources": merged.get("field_sources", ["host.hardware.pciDevice"]), "association_conflict": merged.get("association_conflict", False), "pci_address": pci_address, "pci_association_status": merged.get("pci_association_status", "not_collected"), **self._vsan_properties(vsan_context), "source": "vcenter", "collected_at": collected_at})
        for index, adapter in enumerate(unmatched_adapters):
            category = adapter.get("category", "controller")
            result.append({"object_key": f"{host_name}:adapter-unmatched:{index}", "object_name": str(adapter.get("esxcli_name") or f"storage adapter {index}"), "object_path": host_name, "host": host_name, "category": category, "model": adapter.get("model"), "vid": None, "did": None, "svid": None, "ssid": None, "driver_name": adapter.get("driver_name"), "driver_version": adapter.get("driver_version"), "firmware_version": adapter.get("firmware_version"), "firmware_raw": adapter.get("firmware_raw"), "firmware_candidate": adapter.get("firmware_candidate"), "firmware_confidence": adapter.get("firmware_confidence"), "field_sources": adapter.get("field_sources"), "pci_address": adapter.get("pci_address"), "pci_association_status": adapter.get("pci_association_status"), **self._vsan_properties(vsan_context), "source": "vcenter", "collected_at": collected_at})
        storage = _safe_getattr(_safe_getattr(host, "config"), "storageDevice")
        drive_type_info = enrich_drive_types(
            list(_safe_getattr(storage, "scsiLun", []) or []),
            storage_devices,
        )
        hba_models = [str(info.get("model") or "") for info in hba_info if info.get("model")]
        hba_by_lun_key = self._hba_info_by_lun_key(storage, hba_info)
        excluded = 0
        non_disk_excluded = 0
        for index, lun in enumerate(_safe_getattr(storage, "scsiLun", []) or []):
            evidence = drive_type_info[index] if index < len(drive_type_info) else {}
            drive_type = evidence.get("drive_type")
            exclude_non_disk, _reason = self._should_exclude_non_disk_lun(lun, drive_type)
            if exclude_non_disk:
                non_disk_excluded += 1
                continue
            if drive_type in {"logical", "unknown"} or (drive_type is None and self._is_raid_logical_volume(lun, hba_models)):
                excluded += 1
                continue
            category = classify_storage_lun(lun)
            if category is None:
                continue
            model = _safe_getattr(lun, "model") or _safe_getattr(lun, "displayName") or _safe_getattr(lun, "deviceName")
            lun_key = _safe_getattr(lun, "key") or _safe_getattr(lun, "Key")
            info = hba_by_lun_key.get(str(lun_key), {}) if lun_key else {}
            firmware = _text_or_none(_safe_getattr(lun, "revision") or _safe_getattr(lun, "Revision"))
            result.append({"object_key": f"{host_name}:lun:{index}", "object_name": str(model or f"storage device {index}"), "object_path": host_name, "host": host_name, "category": category, "model": model, "vid": None, "did": None, "svid": None, "ssid": None, "driver_name": info.get("driver_name"), "driver_version": info.get("driver_version"), "firmware_version": firmware, "firmware_raw": firmware, "firmware_confidence": "certain" if firmware else None, "field_sources": ["ScsiLun.Revision"], "pci_association_status": "not_applicable", "drive_type": drive_type, "raid_level": evidence.get("raid_level"), "physical_drive_count": evidence.get("physical_drive_count"), "drive_type_source": evidence.get("drive_type_source"), **self._vsan_properties(vsan_context), "source": "vcenter", "collected_at": collected_at})
        if excluded:
            warnings.append({"host": host_name, "status": "raid_logical_volume_excluded", "count": str(excluded), "reason": "ScsiLun 与 RAID/HBA 控制器型号及服务器厂商特征匹配"})
        if non_disk_excluded:
            warnings.append({"host": host_name, "status": "non_disk_lun_excluded", "count": str(non_disk_excluded), "reason": "ScsiLun 设备类型或虚拟介质标识表明其不是物理磁盘"})
        warnings.extend(esxcli_warnings)
        self._host_timings[host_name] = timings
        return result, warnings

    def _query_kernel_modules(self, host: Any) -> dict[str, str]:
        """Return exact module-name to version mappings; failures are optional."""
        config_manager = _safe_getattr(host, "configManager")
        system = _safe_getattr(config_manager, "kernelModuleSystem")
        query = _safe_getattr(system, "QueryModules")
        if not callable(query):
            return {}
        try:
            modules = query() or []
        except Exception:
            return {}
        versions: dict[str, str] = {}
        for module in modules:
            name = _safe_getattr(module, "name") or _safe_getattr(module, "moduleName")
            version = _safe_getattr(module, "version")
            if name and version and str(version).strip():
                versions[str(name).strip()] = str(version).strip()
        return versions

    def _network_driver_info(self, host: Any, modules: dict[str, str]) -> list[dict[str, Any]]:
        cards = _safe_getattr(_safe_getattr(_safe_getattr(host, "config"), "network"), "pnic") or []
        result = []
        for card in cards:
            driver = _safe_getattr(card, "driver")
            direct_version = _safe_getattr(card, "driverVersion")
            firmware = parse_nic_firmware_version(_safe_getattr(card, "firmwareVersion"))
            result.append({"pci_address": normalize_pci_address(_safe_getattr(card, "pci")), "pci_association_status": "matched" if _safe_getattr(card, "pci") else "not_collected", "field_sources": ["HostSystem.Config.Network.Pnic", "KernelModuleSystem.QueryModules"], "driver_name": driver, "driver_version": _text_or_none(direct_version) or modules.get(str(driver).strip()) if driver else None, "firmware_version": firmware})
        return result

    def _hba_driver_info(self, host: Any, modules: dict[str, str]) -> list[dict[str, Any]]:
        adapters = _safe_getattr(_safe_getattr(_safe_getattr(host, "config"), "storageDevice"), "hostBusAdapter") or []
        result = []
        for adapter in adapters:
            driver = _safe_getattr(adapter, "driver")
            result.append({
                "pci_address": normalize_pci_address(_safe_getattr(adapter, "pci")),
                "adapter_key": str(_safe_getattr(adapter, "key") or _safe_getattr(adapter, "Key") or ""),
                "lun_keys": {str(_safe_getattr(lun, "key") or _safe_getattr(lun, "Key") or lun) for lun in (_safe_getattr(adapter, "scsiLun") or _safe_getattr(adapter, "ScsiLun") or [])},
                "model": _safe_getattr(adapter, "model"),
                "driver_name": driver,
                "driver_version": modules.get(str(driver).strip()) if driver else None,
                "firmware_version": None,
            })
        return result

    @staticmethod
    def _hba_info_by_lun_key(storage: Any, hba_info: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        """Associate a disk only with the adapter that explicitly exposes its LUN key."""

        result: dict[str, dict[str, Any]] = {}
        for info in hba_info:
            for lun_key in info.get("lun_keys") or set():
                if lun_key:
                    result[str(lun_key)] = info
        return result

    def _esxcli_enrichment(self, host: Any, pci_devices: list[Any], modules: dict[str, str]) -> tuple[dict[str, dict[str, Any]], list[dict[str, str]], dict[str, float]]:
        """Read-only esxcli enrichment keyed by the complete PCI address."""
        host_name = str(_safe_getattr(host, "name", "unknown"))
        timings: dict[str, float] = {}
        esxcli = self._get_esxcli(host)
        if esxcli is None:
            return {}, [{"host": host_name, "status": "esxcli_unavailable"}], timings

        def call(command: str, arguments: dict[str, Any] | None = None) -> list[Any]:
            started = time.perf_counter()
            try:
                return _as_record_list(self._esxcli_call(esxcli, command, arguments))
            except Exception as exc:  # individual read-only paths can be unavailable by privilege or ESXi version
                warnings.append({"host": host_name, "status": "esxcli_command_failed", "command": command, "error": type(exc).__name__})
                return []
            finally:
                timings[command] = round(time.perf_counter() - started, 6)

        warnings: list[dict[str, str]] = []
        sas = call("storage.san.sas.list")
        fc = call("storage.san.fc.list")
        adapters = call("storage.core.adapter.list")
        nics = call("network.nic.list")
        vibs = call("software.vib.list")
        # This path is unavailable on some older esxcli adapters; DriveType
        # enrichment is optional and must not turn a successful batch into a
        # command failure warning.
        try:
            storage_devices = _as_record_list(self._esxcli_call(esxcli, "storage.core.device.list", {}))
        except Exception:
            storage_devices = []
        vib_versions = {
            str(_safe_getattr(vib, "name") or _safe_getattr(vib, "Name") or "").replace("-", "_"): _text_or_none(_safe_getattr(vib, "version") or _safe_getattr(vib, "Version"))
            for vib in vibs
        }
        pci_map = {normalize_pci_address(_safe_getattr(device, "id") or _safe_getattr(device, "Id")): device for device in pci_devices}
        pci_map.pop(None, None)
        records: dict[str, dict[str, Any]] = {}
        unmatched: list[dict[str, Any]] = []
        sas_by_name = {str(_safe_getattr(item, "deviceName") or _safe_getattr(item, "DeviceName") or ""): item for item in sas}
        fc_by_name = {str(_safe_getattr(item, "adapter") or _safe_getattr(item, "Adapter") or ""): item for item in fc}
        for adapter in adapters:
            name = str(_safe_getattr(adapter, "hBAName") or _safe_getattr(adapter, "HBAName") or "")
            address = normalize_pci_address(_safe_getattr(adapter, "description") or _safe_getattr(adapter, "Description"))
            detail = sas_by_name.get(name) or fc_by_name.get(name)
            driver = _text_or_none(_safe_getattr(detail, "driverName") or _safe_getattr(detail, "DriverName")) if detail else _text_or_none(_safe_getattr(adapter, "driver") or _safe_getattr(adapter, "Driver"))
            version = _text_or_none(_safe_getattr(detail, "driverVersion") or _safe_getattr(detail, "DriverVersion")) if detail else None
            version = version or modules.get(str(driver).strip()) if driver else None
            version = version or vib_versions.get(str(driver).replace("-", "_")) if driver else None
            parsed = parse_firmware(driver, _safe_getattr(detail, "firmwareVersion") or _safe_getattr(detail, "FirmwareVersion") if detail else None)
            status = "matched" if address and address in pci_map else "pci_not_found" if address else "pci_address_unparsed"
            record = {"category": "controller", "driver_name": driver, "driver_version": version, "model": _text_or_none(_safe_getattr(detail, "modelDescription") or _safe_getattr(detail, "ModelDescription")) if detail else None, **parsed, "field_sources": ["storage.san.sas.list" if name in sas_by_name else "storage.san.fc.list" if name in fc_by_name else "storage.core.adapter.list"], "pci_association_status": status, "esxcli_name": name}
            if address and address in pci_map:
                records[address] = record
            else:
                record["pci_address"] = address
                unmatched.append(record)
                warnings.append({"host": host_name, "status": status, "device": name, "source": "storage.core.adapter.list"})
        nic_started = time.perf_counter()
        pnic_by_name = {str(_safe_getattr(card, "device") or _safe_getattr(card, "Device") or ""): card for card in (_safe_getattr(_safe_getattr(_safe_getattr(host, "config"), "network"), "pnic") or [])}
        for nic in nics:
            name = str(_safe_getattr(nic, "name") or _safe_getattr(nic, "Name") or "")
            details = call("network.nic.get", {"nicname": name})
            detail = details[0] if details else None
            driver_info = _safe_getattr(detail, "driverInfo") or _safe_getattr(detail, "DriverInfo")
            driver = _text_or_none(_safe_getattr(driver_info, "driver") or _safe_getattr(driver_info, "Driver") or _safe_getattr(nic, "driver") or _safe_getattr(nic, "Driver"))
            version = _text_or_none(_safe_getattr(driver_info, "version") or _safe_getattr(driver_info, "Version")) or (modules.get(str(driver).strip()) if driver else None) or (vib_versions.get(str(driver).replace("-", "_")) if driver else None)
            pnic = pnic_by_name.get(name)
            address = normalize_pci_address(_safe_getattr(pnic, "pci") or _safe_getattr(pnic, "Pci"))
            parsed = parse_firmware(driver, _safe_getattr(driver_info, "firmwareVersion") or _safe_getattr(driver_info, "FirmwareVersion"))
            status = "matched" if address and address in pci_map else "pci_not_found" if address else "pnic_pci_unparsed" if pnic else "pnic_not_found"
            if address and address in pci_map:
                records[address] = {"driver_name": driver, "driver_version": version, **parsed, "field_sources": ["network.nic.get"], "pci_association_status": status, "esxcli_name": name}
            else:
                unmatched.append({"category": "nic", "driver_name": driver, "driver_version": version, **parsed, "field_sources": ["network.nic.get"], "pci_association_status": status, "esxcli_name": name, "pci_address": address, "model": None})
                warnings.append({"host": host_name, "status": status, "device": name, "source": "network.nic.get"})
        timings["network.nic.get"] = round(time.perf_counter() - nic_started, 6)
        records["_unmatched"] = unmatched
        records["_storage_devices"] = storage_devices
        vsan_started = time.perf_counter()
        try:
            records["_vsan_storage"] = _as_record_list(self._esxcli_call(esxcli, "vsan.storage.list", {}))
        except Exception:
            records["_vsan_storage"] = []
            records["_vsan_storage_unavailable"] = True
        finally:
            timings["vsan.storage.list"] = round(time.perf_counter() - vsan_started, 6)
        return records, warnings, timings

    def _vsan_properties(self, context: Any) -> dict[str, Any]:
        return {"vsan_enabled": context.vsan_enabled, "vsan_architecture": context.vsan_architecture, "vsan_disk_layout": context.vsan_disk_layout, "controller_mode": context.controller_mode}

    def _cluster_context_warnings(self) -> list[dict[str, str]]:
        by_cluster: dict[str, set[tuple[Any, Any, Any]]] = {}
        for record in self._host_records:
            cluster = str(record.get("cluster") or "")
            if cluster:
                by_cluster.setdefault(cluster, set()).add((record.get("vsan_enabled"), record.get("vsan_architecture"), record.get("vsan_disk_layout")))
        return [
            {"cluster": cluster, "status": "vsan_context_inconsistent", "reason": "同一集群主机返回不同 vSAN 上下文；保留每台主机原始值，不推断统一值"}
            for cluster, contexts in by_cluster.items() if len(contexts) > 1
        ]

    def _get_esxcli(self, host: Any) -> Any:
        if callable(self.esxcli_provider):
            try:
                return self.esxcli_provider(host)
            except Exception:
                return None
        return _safe_getattr(_safe_getattr(host, "configManager"), "esxcli")

    def _esxcli_call(self, esxcli: Any, command: str, arguments: dict[str, Any] | None = None) -> Any:
        """Support the pyVmomi EsxCLI Execute API and a small injectable test adapter."""
        for method_name in ("execute", "Execute", "invoke", "Invoke"):
            method = _safe_getattr(esxcli, method_name)
            if callable(method):
                try:
                    return method(command, arguments or {})
                except TypeError:
                    return method(command)
        current = esxcli
        for part in command.split("."):
            current = _safe_getattr(current, part)
        invoke = _safe_getattr(current, "Invoke") or _safe_getattr(current, "invoke")
        if not callable(invoke):
            raise RuntimeError(f"EsxCLI command unavailable: {command}")
        return invoke(arguments or {})

    def _match_controller_info(self, model: Any, infos: list[dict[str, Any]], index: int) -> dict[str, Any]:
        return self._match_storage_info(model, infos, index)

    def _match_storage_info(self, model: Any, infos: list[dict[str, Any]], index: int) -> dict[str, Any]:
        # Kept for adapter API compatibility; positional/model-only inference is unsafe.
        return {}

    def _is_raid_logical_volume(self, lun: Any, hba_models: list[str]) -> bool:
        model = str(_safe_getattr(lun, "model", "") or _safe_getattr(lun, "displayName", "") or "").strip()
        vendor = str(_safe_getattr(lun, "vendor", "") or "").strip().lower()
        device_type = str(_safe_getattr(lun, "deviceType", "") or "").strip().lower()
        canonical = str(_safe_getattr(lun, "canonicalName", "") or _safe_getattr(lun, "CanonicalName", "") or "").lower()
        revision = str(_safe_getattr(lun, "revision", "") or _safe_getattr(lun, "Revision", "") or "").strip().lower()
        boss_name = "dellboss_vd" in canonical or "boss_vd" in canonical
        boss_firmware = bool(re.fullmatch(r"\d{2}-\d+", revision))
        if device_type == "disk" and boss_name and boss_firmware:
            return True
        if not model or not hba_models:
            return False
        normalized_model = re.sub(r"[^a-z0-9]", "", model.lower())
        same_controller = any(normalized_model and normalized_model in re.sub(r"[^a-z0-9]", "", candidate.lower()) or re.sub(r"[^a-z0-9]", "", candidate.lower()) in normalized_model for candidate in hba_models if candidate)
        vendor_server = any(word in vendor for word in ("dell", "hpe", "hp", "lenovo", "ibm", "supermicro"))
        raid_hint = any(word in model.lower() for word in ("perc", "raid", "smart array", "megaraid", "mr3", "sas raid"))
        return device_type == "disk" and same_controller and vendor_server and raid_hint

    def _should_exclude_non_disk_lun(self, lun: Any, drive_type: Any) -> tuple[bool, str | None]:
        """Exclude structural non-disk and virtual-media LUNs before HCL matching."""

        device_type = str(_safe_getattr(lun, "deviceType") or _safe_getattr(lun, "DeviceType") or "").strip().casefold()
        if device_type and device_type not in {"disk", "direct access", "direct-access"}:
            return True, "device_type"
        vendor = str(_safe_getattr(lun, "vendor") or _safe_getattr(lun, "Vendor") or "").strip().casefold()
        model = str(_safe_getattr(lun, "model") or _safe_getattr(lun, "displayName") or _safe_getattr(lun, "deviceName") or "").strip().casefold()
        canonical = str(_safe_getattr(lun, "canonicalName") or _safe_getattr(lun, "CanonicalName") or "").strip().casefold()
        virtual_media = ("idrac" in vendor or "idrac" in model or "virtual media" in model) and (canonical.startswith("mpx.") or "virtual" in canonical)
        console_virtual_media = model == "console" and "dell" in vendor and canonical.startswith("mpx.")
        if drive_type in {"logical", "unknown"} and (virtual_media or console_virtual_media):
            return True, "virtual_media"
        return False, None


def _text_or_none(value: Any) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text or None


def _as_record_list(value: Any) -> list[Any]:
    """Normalize pyVmomi esxcli return shapes without iterating mapping keys."""

    if value is None:
        return []
    if isinstance(value, Mapping):
        # Unwrap only a dedicated single-key record envelope. A NIC record itself
        # can contain list-valued properties (AdvertisedLinkModes, SupportedPorts).
        if len(value) == 1:
            for key in ("items", "Items", "records", "Records", "data", "Data"):
                nested = value.get(key)
                if isinstance(nested, (list, tuple)):
                    return list(nested)
        return [value]
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def parse_nic_firmware_version(value: Any) -> str | None:
    """Normalize common ESXi NIC firmware values while retaining unknown formats."""
    text = _text_or_none(value)
    if not text:
        return None
    if "," in text:
        candidate = text.rsplit(",", 1)[-1].strip()
        if re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", candidate):
            return candidate
    if re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", text):
        return text
    return text


class SupportBundlePciCollector:
    """Stream selected commands from zip/tar/tgz support bundles into PCI records."""

    TARGET_HINTS = ("commands/", "command/", "esxcli", "lspci", "pci", "vib", "nic", "storage")

    def __init__(self, bundle_path: Path | str) -> None:
        self.bundle_path = Path(bundle_path)

    def collect(self, context: RunContext, plan: CollectionPlan) -> dict[str, Any]:
        collected_at = datetime.now(UTC).isoformat()
        records: list[dict[str, Any]] = []
        extracted: list[str] = []
        warnings: list[dict[str, str]] = []
        try:
            for name, payload in self._iter_target_files():
                extracted.append(name)
                text = payload.decode("utf-8", errors="replace")
                records.extend(self._parse_file(name, text))
        except (OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
            warnings.append({"status": "bundle_read_failed", "error": type(exc).__name__})
        return {"objects": records, "collection_status": "degraded" if warnings else "collected", "collection_warnings": warnings, "source": "support_bundle", "collected_at": collected_at, "extracted_files": extracted}

    def _iter_target_files(self) -> Iterable[tuple[str, bytes]]:
        suffix = self.bundle_path.name.lower()
        if suffix.endswith((".zip", ".jar")):
            with zipfile.ZipFile(self.bundle_path) as archive:
                for info in archive.infolist():
                    if info.is_dir() or not self._wanted(info.filename):
                        continue
                    with archive.open(info) as stream:
                        yield info.filename, stream.read(4 * 1024 * 1024)
            return
        with tarfile.open(self.bundle_path, mode="r|*") as archive:
            for member in archive:
                if not member.isfile() or not self._wanted(member.name):
                    continue
                extracted = archive.extractfile(member)
                if extracted is None:
                    continue
                with closing(extracted):
                    yield member.name, extracted.read(4 * 1024 * 1024)

    def _wanted(self, name: str) -> bool:
        lower = name.replace("\\", "/").lower()
        return any(token in lower for token in self.TARGET_HINTS)

    def _parse_file(self, name: str, text: str) -> list[dict[str, Any]]:
        lower = name.lower()
        version = self._detect_esxi_version(text)
        if "vib" in lower:
            return self._parse_vibs(text, version)
        if "nic" in lower:
            return self._parse_nics(text, version)
        if "pci" in lower or "lspci" in lower:
            return self._parse_pci_for_version(text, version)
        if "storage" in lower or "scsi" in lower:
            return self._parse_storage_for_version(text, version)
        return self._parse_pci_for_version(text, version)

    def _detect_esxi_version(self, text: str) -> str:
        match = re.search(r"(?:VMware ESXi|Version)\s*[-:]?\s*(6\.7|7\.0|8\.0)", text, re.I)
        return match.group(1) if match else "unknown"

    def _parse_pci_for_version(self, text: str, version: str) -> list[dict[str, Any]]:
        # Keep version-specific entry points so new command layouts can be
        # added independently; current layouts share the tolerant parser.
        parser = {
            "6.7": self._parse_pci_esxi67,
            "7.0": self._parse_pci_esxi70,
            "8.0": self._parse_pci_esxi80,
        }.get(version, self._parse_pci_unknown)
        return parser(text)

    def _parse_pci_esxi67(self, text: str) -> list[dict[str, Any]]:
        return self._parse_pci(text)

    def _parse_pci_esxi70(self, text: str) -> list[dict[str, Any]]:
        return self._parse_pci(text)

    def _parse_pci_esxi80(self, text: str) -> list[dict[str, Any]]:
        return self._parse_pci(text)

    def _parse_pci_unknown(self, text: str) -> list[dict[str, Any]]:
        return self._parse_pci(text)

    def _parse_pci(self, text: str) -> list[dict[str, Any]]:
        result = []
        pattern = re.compile(r"(?P<vid>[0-9a-fA-F]{4})[:/](?P<did>[0-9a-fA-F]{4}).*?(?:class|classid)\s*[:=]\s*(?P<class>[0-9a-fA-Fx]+)", re.I)
        for index, match in enumerate(pattern.finditer(text)):
            category = classify_pci_class_text(match.group("class"))
            if category is None:
                continue
            result.append({"object_key": f"bundle:pci:{index}", "object_name": f"PCI {match.group('vid')}:{match.group('did')}", "category": category, "vid": match.group("vid").lower(), "did": match.group("did").lower(), "svid": None, "ssid": None, "model": None, "driver_name": None, "driver_version": None, "firmware_version": None})
        return result

    def _parse_nics(self, text: str, version: str = "unknown") -> list[dict[str, Any]]:
        records = self._parse_pci_for_version(text, version)
        for record in records:
            record["category"] = "nic"
        return records

    def _parse_storage_for_version(self, text: str, version: str) -> list[dict[str, Any]]:
        parser = {
            "6.7": self._parse_storage,
            "7.0": self._parse_storage,
            "8.0": self._parse_storage,
        }.get(version, self._parse_storage)
        return parser(text, version)

    def _parse_storage(self, text: str, version: str = "unknown") -> list[dict[str, Any]]:
        result = []
        for index, line in enumerate(text.splitlines()):
            if not line.strip() or not re.search(r"(naa\.|eui\.|t10\.|model|display name)", line, re.I):
                continue
            model = line.split(":", 1)[-1].strip() if ":" in line else line.strip()
            result.append({"object_key": f"bundle:{version}:lun:{index}", "object_name": model, "category": "ssd" if "ssd" in line.lower() else "hdd", "model": model, "vid": None, "did": None, "svid": None, "ssid": None, "driver_name": None, "driver_version": None, "firmware_version": None})
        return result

    def _parse_vibs(self, text: str, version: str = "unknown") -> list[dict[str, Any]]:
        return []


def classify_pci_class_text(value: str) -> str | None:
    number = _parse_number(value)
    if number is None:
        return None
    base = number >> 8 if number > 0xFF else number
    return "nic" if base == 0x02 else "controller" if base == 0x01 else None
