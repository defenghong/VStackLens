from __future__ import annotations

import json
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from docx import Document


SENSITIVE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)\bauthorization\b\s*[:=]\s*[^\s,;]+"), "包含 Authorization 敏感字段"),
    (re.compile(r"(?i)\bauthorization\b(?!\s*[:=])"), "包含 Authorization 敏感字段"),
    (re.compile(r"(?i)\bbearer\s+[a-z0-9._\-]+"), "包含 Bearer token"),
    (re.compile(r"(?i)\b(password|passwd|pwd|token|cookie|session|secret)\b\s*[:=]\s*[^,\s;]+"), "包含凭据或会话字段"),
    (re.compile(r"(?i)\b(password|passwd|pwd|token|cookie|session|secret)\b(?!\s*[:=])"), "包含敏感字段名"),
    (re.compile(r"(?i)\btraceback\b"), "包含底层 traceback"),
    (re.compile(r"(?i)\bTimeoutError\b"), "包含底层 TimeoutError"),
    (re.compile(r"(?i)\bsite-packages\b"), "包含本机 Python 路径"),
    (re.compile(r"(?i)[A-Z]:\\Users\\[^\s\"'<>|]*"), "包含本机用户目录路径"),
    (re.compile(r"D:\\软件开发(?:\\|$)[^\s\"'<>|]*"), "包含本机源码路径"),
    (re.compile(r"(?i)src\\+vstacklens"), "包含本机源码相对路径"),
)

CUSTOMER_FORBIDDEN_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)\bP4\b"), "客户产物包含 P4"),
    (re.compile(r"(?i)P4\s*级"), "客户产物包含 P4级"),
    (re.compile(r"期望值"), "客户产物包含期望值"),
    (re.compile(r"期望状态"), "客户产物包含期望状态"),
    (re.compile(r"失败"), "客户产物包含失败"),
    (re.compile(r"(?i)\bPDF\s*/\s*PPT\b"), "客户产物包含 PDF/PPT"),
    (re.compile(r"(?i)\bPDF\b"), "客户产物包含 PDF"),
    (re.compile(r"(?i)\bPPT\b"), "客户产物包含 PPT"),
    (re.compile(r"(?i)PDF\s*导出"), "客户产物包含 PDF导出"),
    (re.compile(r"(?i)PPT\s*导出"), "客户产物包含 PPT导出"),
)


@dataclass(frozen=True, slots=True)
class ArtifactScanFinding:
    path: Path
    reason: str


def sanitize_text(value: Any, *secrets: str) -> str:
    text = str(value or "")
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[已隐藏]")
    text = re.sub(r"(?i)authorization\s*:\s*bearer\s+[^,\s;]+", "[敏感字段已隐藏]", text)
    text = re.sub(r"(?i)\b(password|passwd|pwd|token|authorization|cookie|session|secret)\b\s*[:=]\s*[^,\s;]+", "[敏感字段已隐藏]", text)
    text = re.sub(r"(?i)bearer\s+[a-z0-9._\-]+", "[敏感字段已隐藏]", text)
    text = re.sub(r"(?i)\b(password|passwd|pwd|token|authorization|cookie|session|secret)\b", "[敏感字段已隐藏]", text)
    text = re.sub(r"(?i)[A-Z]:\\Users\\[^\s;\"'<>|]+", "[本机路径已隐藏]", text)
    text = re.sub(r"(?i)[A-Z]:\\[^\s;\"'<>|]*(?:site-packages|codex_extracted|软件开发)[^\s;\"'<>|]*", "[本机路径已隐藏]", text)
    text = re.sub(r"(?i)\bsrc\\+vstacklens[^\s;\"'<>|]*", "[本机路径已隐藏]", text)
    text = re.sub(r"(?i)\btraceback\b", "异常摘要", text)
    text = re.sub(r"(?i)\bTimeoutError\b", "连接超时", text)
    return text[:4000]


def scan_artifacts(paths: list[Path], *, engineering_paths: set[Path] | None = None) -> list[ArtifactScanFinding]:
    engineering_paths = {path.resolve() for path in engineering_paths or set()}
    findings: list[ArtifactScanFinding] = []
    for path in paths:
        if not path or not path.exists() or path.is_dir():
            continue
        text = _artifact_text(path)
        if not text:
            continue
        resolved = path.resolve()
        matched_reasons: set[str] = set()
        for pattern, reason in SENSITIVE_PATTERNS:
            if pattern.search(text):
                matched_reasons.add(reason)
        if resolved in engineering_paths:
            findings.extend(ArtifactScanFinding(path, reason) for reason in sorted(matched_reasons))
            continue
        for pattern, reason in CUSTOMER_FORBIDDEN_PATTERNS:
            if pattern.search(text):
                matched_reasons.add(reason)
        findings.extend(ArtifactScanFinding(path, reason) for reason in sorted(matched_reasons))
    return findings


def _artifact_text(path: Path) -> str:
    suffix = path.suffix.lower()
    try:
        if suffix == ".docx":
            return "\n".join(paragraph.text for paragraph in Document(path).paragraphs) + "\n" + _docx_table_text(path)
        if suffix in {".json", ".md", ".html", ".txt", ".log"}:
            return path.read_text(encoding="utf-8", errors="ignore")
        if suffix == ".zip":
            return _zip_text(path)
    except Exception:
        return ""
    return ""


def _docx_table_text(path: Path) -> str:
    try:
        document = Document(path)
    except Exception:
        return ""
    return "\n".join(cell.text for table in document.tables for row in table.rows for cell in row.cells)


def _zip_text(path: Path) -> str:
    chunks: list[str] = []
    try:
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                if not name.lower().endswith((".html", ".json", ".xml", ".txt", ".md")):
                    continue
                chunks.append(archive.read(name).decode("utf-8", errors="ignore"))
    except Exception:
        return ""
    return "\n".join(chunks)


def summarize_scan_findings(findings: list[ArtifactScanFinding]) -> list[dict[str, str]]:
    return [{"file": finding.path.name, "reason": finding.reason} for finding in findings]


def json_summary(value: Any) -> str:
    return sanitize_text(json.dumps(value, ensure_ascii=False, indent=2))
