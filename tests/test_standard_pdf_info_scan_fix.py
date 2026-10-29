"""Synthetic PDF Info values are scanned, including custom and indirect fields."""
from __future__ import annotations

import hashlib

import pymupdf
import pytest

from vstacklens.application import artifact_safety as module


def _pdf_bytes(case):
    with pymupdf.open() as document:
        document.new_page().insert_text((40, 50), "P1 health assessment")
        if case == "missing_info":
            return document.tobytes()
        document.set_metadata({"title": "P1 health assessment"})
        info_xref = int(document.xref_get_key(-1, "Info")[1].split()[0])
        direct_values = {
            "standard_credential": ("Title", pymupdf.get_pdf_str("password=synthetic-credential")),
            "custom_credential": ("SyntheticExtra", pymupdf.get_pdf_str("password=synthetic-credential")),
            "custom_known_secret": ("SyntheticExtra", pymupdf.get_pdf_str("known-synthetic-value")),
            "hex_string": ("SyntheticExtra", "<" + b"api_key=synthetic-credential".hex() + ">"),
            "utf16_string": ("SyntheticExtra", "<FEFF" + "access_token=synthetic-credential".encode("utf-16-be").hex() + ">"),
            "credential_key": ("api_key", pymupdf.get_pdf_str("synthetic-credential")),
            "null": ("api_key", "null"),
            "empty": ("api_key", pymupdf.get_pdf_str("")),
            "redacted": ("api_key", pymupdf.get_pdf_str("[REDACTED]")),
            "zero": ("api_key", "0"),
            "false": ("api_key", "false"),
            "normal": ("SyntheticExtra", pymupdf.get_pdf_str("Source evidence available")),
            "customer_wording": ("SyntheticExtra", pymupdf.get_pdf_str("P4")),
            "stored_format_wording": ("format", pymupdf.get_pdf_str("PDF custom wording")),
            "text_budget": ("SyntheticExtra", pymupdf.get_pdf_str("x" * 256)),
        }
        if case in direct_values:
            document.xref_set_key(info_xref, *direct_values[case])
        elif case == "direct_info":
            document.xref_set_key(-1, "Info", "<< /Title (P1 health assessment) /api_key (synthetic-credential) >>")
        elif case == "nested_array":
            document.xref_set_key(info_xref, "SyntheticExtra", "[ << /access_token (synthetic-credential) >> ]")
        elif case in {"indirect_string", "cycle", "stream"}:
            indirect = document.get_new_xref()
            document.update_object(indirect, pymupdf.get_pdf_str("password=synthetic-credential") if case == "indirect_string" else "<< >>")
            document.xref_set_key(info_xref, "SyntheticExtra", f"{indirect} 0 R")
            if case == "cycle":
                document.xref_set_key(indirect, "Loop", f"{info_xref} 0 R")
            elif case == "stream":
                document.update_stream(indirect, b"password=synthetic-credential")
        elif case == "depth":
            document.xref_set_key(info_xref, "SyntheticExtra", "<< /Nested " * 10 + "(clean)" + " >>" * 10)
        elif case == "node_budget":
            document.xref_set_key(info_xref, "SyntheticExtra", "<< " + " ".join(f"/Field{i} (clean)" for i in range(520)) + " >>")
        elif case == "non_dict_info":
            document.xref_set_key(-1, "Info", "(unknown representation)")
        else:
            raise AssertionError(case)
        return document.tobytes()


def _scan(tmp_path, case, internal, *, secrets=()):
    path = tmp_path / "synthetic.pdf"
    path.write_bytes(_pdf_bytes(case))
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    findings = module.scan_artifacts([path], engineering_paths={path} if internal else set(), secrets=secrets)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before
    return findings


@pytest.mark.parametrize("internal", (False, True))
@pytest.mark.parametrize("case", ("standard_credential", "custom_credential", "custom_known_secret", "hex_string", "utf16_string", "credential_key", "zero", "false", "direct_info", "nested_array", "indirect_string"))
def test_actual_info_values_block_for_each_role(tmp_path, internal, case):
    findings = _scan(tmp_path, case, internal, secrets=("known-synthetic-value",))
    assert findings
    assert not any(item.reason.startswith("无法扫描") for item in findings)
    assert any("会话凭据" in item.reason if case == "custom_known_secret" else "凭据或会话字段" in item.reason for item in findings)


@pytest.mark.parametrize("internal", (False, True))
@pytest.mark.parametrize("case", ("missing_info", "normal", "null", "empty", "redacted"))
def test_missing_normal_and_confirmed_empty_info_are_safe(tmp_path, internal, case):
    assert _scan(tmp_path, case, internal) == []


@pytest.mark.parametrize("internal", (False, True))
@pytest.mark.parametrize("case", ("cycle", "stream", "depth", "node_budget", "non_dict_info", "text_budget"))
def test_unsupported_or_unbounded_info_is_unscannable_not_safe(tmp_path, monkeypatch, internal, case):
    if case == "text_budget":
        monkeypatch.setattr(module, "PDF_INFO_TEXT_LIMIT", 128)
    assert any(item.reason.startswith("无法扫描") for item in _scan(tmp_path, case, internal))


@pytest.mark.parametrize("case", ("customer_wording", "stored_format_wording"))
def test_actual_custom_wording_is_not_confused_with_parser_generated_format(tmp_path, case):
    assert _scan(tmp_path, case, False)
    assert _scan(tmp_path, case, True) == []
