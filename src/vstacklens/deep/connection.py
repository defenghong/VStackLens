from __future__ import annotations

import re
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True, repr=False)
class VCenterConnectionInfo:
    host: str
    username: str
    password: str
    port: int = 443
    ssl_verify: bool = False


@dataclass(slots=True, repr=False)
class EsxiHostConnectionInfo:
    """One workbook-provided ESXi endpoint credential; never serialize or log this object."""

    host_alias: str
    host: str
    username: str
    password: str
    port: int = 443
    ssl_verify: bool = False


def load_vcenter_connection_from_workbook(path: Path) -> VCenterConnectionInfo:
    """Read the explicitly designated primary vCenter row without logging credentials."""

    rows = _first_sheet_rows(path)
    normalized_rows = [{str(key): str(value or "") for key, value in row.items()} for row in rows]
    primary = next((item for item in normalized_rows if item.get("D", "").strip().lower() == "vcenter"), None)
    if primary is None:
        raise ValueError("no vCenter connection row found in workbook")
    host = primary.get("E", "").strip()
    username = primary.get("F", "").strip()
    password = primary.get("G", "")
    if not host or not username or not password:
        raise ValueError("primary vCenter connection row is missing required fields")
    return VCenterConnectionInfo(host=host, username=username, password=password)


def load_esxi_host_connections_from_workbook(path: Path) -> list[EsxiHostConnectionInfo]:
    """Read explicit per-host workbook credentials without exposing any values."""

    rows = _first_sheet_rows(path)
    result: list[EsxiHostConnectionInfo] = []
    for row in rows:
        alias = str(row.get("D", "") or "").strip()
        endpoint = str(row.get("E", "") or "").strip()
        username = str(row.get("F", "") or "").strip()
        password = str(row.get("G", "") or "")
        if not alias.casefold().startswith("esxi") or not endpoint or not username or not password:
            continue
        if any(character.isspace() for character in endpoint):
            continue
        result.append(EsxiHostConnectionInfo(host_alias=alias, host=endpoint, username=username, password=password))
        if len(result) >= 64:
            break
    return result


def _workbook_connection_secrets(path: Path) -> tuple[list[str], list[str]]:
    """Return connection-table usernames/passwords for in-memory output redaction only."""
    rows = _first_sheet_rows(path)
    primary = next((row for row in rows if str(row.get("D", "")).strip().casefold() == "vcenter"), None)
    primary_host = str((primary or {}).get("E", "") or "").strip()
    usernames: set[str] = set()
    passwords: set[str] = set()
    for row in rows:
        alias = str(row.get("D", "") or "").strip()
        endpoint = str(row.get("E", "") or "").strip()
        is_primary_or_same_endpoint = bool(primary and (row is primary or (primary_host and endpoint == primary_host)))
        is_host_row = alias.casefold().startswith("esxi") and endpoint and not any(character.isspace() for character in endpoint)
        if not (is_primary_or_same_endpoint or is_host_row):
            continue
        username = str(row.get("F", "") or "").strip()
        password = str(row.get("G", "") or "")
        if username:
            usernames.add(username)
        if password:
            passwords.add(password)
    return sorted(usernames), sorted(passwords)


def _first_sheet_rows(path: Path) -> list[dict[str, str]]:
    """Read the first worksheet's stored cell values without printing them."""

    path = Path(path)
    namespace = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    relationships_namespace = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    with zipfile.ZipFile(path) as workbook:
        shared_strings = _shared_strings(workbook, namespace)
        workbook_xml = ET.fromstring(workbook.read("xl/workbook.xml"))
        rels = ET.fromstring(workbook.read("xl/_rels/workbook.xml.rels"))
        relation_map = {item.attrib["Id"]: item.attrib["Target"] for item in rels}
        sheet = workbook_xml.find("m:sheets/m:sheet", namespace)
        if sheet is None:
            raise ValueError("connection workbook has no worksheet")
        relation_id = sheet.attrib[f"{{{relationships_namespace}}}id"]
        target = relation_map[relation_id]
        target = target if target.startswith("xl/") else "xl/" + target.lstrip("/")
        worksheet = ET.fromstring(workbook.read(target))
        return _rows(worksheet, shared_strings, namespace)


def _shared_strings(workbook: zipfile.ZipFile, namespace: dict[str, str]) -> list[str]:
    if "xl/sharedStrings.xml" not in workbook.namelist():
        return []
    root = ET.fromstring(workbook.read("xl/sharedStrings.xml"))
    return [
        "".join(item.text or "" for item in shared_item.iter("{http://schemas.openxmlformats.org/spreadsheetml/2006/main}t"))
        for shared_item in root.findall("m:si", namespace)
    ]


def _rows(worksheet: ET.Element, shared_strings: list[str], namespace: dict[str, str]) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for row in worksheet.findall(".//m:sheetData/m:row", namespace):
        values: dict[str, str] = {}
        for cell in row.findall("m:c", namespace):
            reference = cell.attrib.get("r", "")
            match = re.match(r"[A-Z]+", reference)
            if not match:
                continue
            value_node = cell.find("m:v", namespace)
            value = "" if value_node is None else value_node.text or ""
            if cell.attrib.get("t") == "s" and value:
                value = shared_strings[int(value)]
            values[match.group(0)] = value
        result.append(values)
    return result
