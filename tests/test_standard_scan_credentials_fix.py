"""Offline synthetic counterexamples for shared credentials and risk wording."""
from __future__ import annotations

import json
import zipfile

import pymupdf
import pytest

from vstacklens.application.artifact_safety import scan_artifacts


ALIASES = ("password", "passwd", "pwd", "api_key", "api-key", "apikey",
           "access_token", "access-token", "accesstoken", "token", "cookie", "session", "secret", "authorization")


def _scan(path, *, internal=False, secrets=()):
    return scan_artifacts([path], engineering_paths={path} if internal else set(), secrets=secrets)


@pytest.mark.parametrize("alias", ALIASES)
@pytest.mark.parametrize("kind", ("assignment", "json", "xml"))
def test_nonempty_credential_alias_is_blocked_equally_for_both_roles(tmp_path, alias, kind):
    path = tmp_path / ("evidence.json" if kind == "json" else "evidence.txt")
    value = "synthetic-credential"
    content = {"assignment": f"{alias}={value}", "json": json.dumps({alias: value}),
               "xml": f"<{alias}>{value}</{alias}>"}[kind]
    path.write_text(content, encoding="utf-8")
    for internal in (False, True):
        assert _scan(path, internal=internal), (alias, kind, internal)


@pytest.mark.parametrize("internal", (False, True))
@pytest.mark.parametrize("value", (None, "", "[REDACTED]", "[redacted_credential]", "[已隐藏]", "[敏感字段已隐藏]", [], {}))
def test_confirmed_empty_or_explicit_redaction_is_not_a_nonempty_credential(tmp_path, internal, value):
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps({name: value for name in ALIASES}, ensure_ascii=False), encoding="utf-8")
    assert _scan(path, internal=internal) == []


@pytest.mark.parametrize("internal", (False, True))
@pytest.mark.parametrize("content", ("password=", 'password=""', "password=null", "password=None", "api_key=[REDACTED]",
                                     "<password></password>", "<password>null</password>", "<api_key>[已隐藏]</api_key>"))
def test_empty_assignments_and_xml_redactions_are_not_secret_values(tmp_path, internal, content):
    path = tmp_path / "evidence.txt"
    path.write_text(content, encoding="utf-8")
    assert _scan(path, internal=internal) == []


@pytest.mark.parametrize("internal", (False, True))
@pytest.mark.parametrize("value", (0, False, "[synthetic-credential]", "{synthetic-credential}"))
def test_zero_false_and_nonempty_brackets_are_not_treated_as_missing_credentials(tmp_path, internal, value):
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps({"api_key": value}), encoding="utf-8")
    assert _scan(path, internal=internal)


def test_internal_field_names_preserve_original_evidence_without_values(tmp_path):
    path = tmp_path / "internal.json"
    content = json.dumps({"fields": ALIASES, "status": "失败", "level": "P4", "detail": "期望值 TimeoutError"}, ensure_ascii=False)
    path.write_text(content, encoding="utf-8")
    assert _scan(path, internal=True) == []
    assert path.read_text("utf-8") == content


@pytest.mark.parametrize("suffix", (".html", ".json"))
def test_accurate_failure_consequence_is_deliverable_but_added_credential_is_blocked(tmp_path, suffix):
    path = tmp_path / ("customer" + suffix)
    wording = "可能导致 vMotion 迁移或 HA 故障切换失败"
    def write(value):
        path.write_text(json.dumps({"risk": value}, ensure_ascii=False) if suffix == ".json" else value, encoding="utf-8")
    write(wording)
    assert _scan(path) == []
    write(wording + " api_key=synthetic-credential")
    assert any("凭据" in item.reason for item in _scan(path))


@pytest.mark.parametrize("content", ("P4", "期望值", "期望状态", "Traceback", "TimeoutError", "PDF/PPT"))
def test_other_customer_wording_and_diagnostic_guards_remain_effective(tmp_path, content):
    path = tmp_path / "customer.html"
    path.write_text(content, encoding="utf-8")
    assert _scan(path)


@pytest.mark.parametrize("internal", (False, True))
@pytest.mark.parametrize("source", ("bearer", "authorization", "url", "pem", "known_secret", "zip_json", "pdf_metadata", "pdf_attachment", "pdf_xmp", "unscannable"))
def test_existing_sensitive_channels_and_unscannable_formats_still_block(tmp_path, internal, source):
    path = tmp_path / ("evidence.zip" if source == "zip_json" else "evidence.pdf" if source.startswith("pdf_") else "evidence.bin" if source == "unscannable" else "evidence.txt")
    values = {"bearer": "Bearer synthetic-credential", "authorization": "Authorization: Basic c3ludGhldGlj",
              "url": "https://reader:synthetic-credential@example.invalid/", "pem": "-----BEGIN PRIVATE KEY-----",
              "known_secret": "known-synthetic-value", "unscannable": "opaque"}
    if source == "zip_json":
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("evidence.json", '{"access_token":"synthetic-credential"}')
    elif source.startswith("pdf_"):
        with pymupdf.open() as document:
            document.new_page().insert_text((30, 30), "P1 health assessment")
            if source == "pdf_metadata":
                document.set_metadata({"author": "api_key=synthetic-credential"})
            elif source == "pdf_attachment":
                document.embfile_add("evidence.json", b'{"access_token":"synthetic-credential"}')
            else:
                document.set_xml_metadata('<x:xmpmeta xmlns:x="adobe:ns:meta/"><api_key>synthetic-credential</api_key></x:xmpmeta>')
            document.save(path)
    else:
        path.write_text(values[source], encoding="utf-8")
    assert _scan(path, internal=internal, secrets=("known-synthetic-value",))
