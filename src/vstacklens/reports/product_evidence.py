"""Publish complete product evidence with the existing report engines."""
from __future__ import annotations

from contextlib import contextmanager
import errno
import os
from pathlib import Path
import re
import tempfile

from vstacklens.application.artifact_safety import (
    ArtifactScanFinding, UnsafeArtifactError, ensure_artifacts_safe,
)


def _evidence_content(report, *, secrets=()):
    if not report.product_modules:
        return None
    from vstacklens.products.model import sanitize_public
    from vstacklens.products.reporting import (
        build_product_evidence, product_evidence_bytes, product_evidence_filename,
        product_report_view, validate_product_coverage,
    )
    evidence = build_product_evidence(report)
    validate_product_coverage(report, product_report_view(report), evidence)
    filename = product_evidence_filename(report)
    if not re.fullmatch(r"inspection-evidence-[0-9a-f]{12}\.json", filename):
        raise ValueError("工程证据附件名称无效，已阻止交付。")
    # Reuse the product persistence contract's recursive normalized-key gate.
    # It also rejects camelCase/plural aliases and raw response containers;
    # this validation performs no database access or migration.
    from vstacklens.products.store import _public as validate_public
    try:
        checked = validate_public(evidence)
    except ValueError:
        raise UnsafeArtifactError([ArtifactScanFinding(Path(filename), "工程证据包含敏感或未投影字段")]) from None
    if checked != evidence:
        raise UnsafeArtifactError([ArtifactScanFinding(Path(filename), "工程证据尚未完全脱敏")])
    # Never silently discard an unsafe field from an evidence attachment.
    if sanitize_public(evidence, secrets) != evidence:
        raise UnsafeArtifactError([ArtifactScanFinding(Path(filename), "工程证据包含未脱敏字段或本次凭据")])
    return filename, product_evidence_bytes(report)


def write_into_stage(report, stage_dir: Path, *, secrets=()) -> Path | None:
    """Write and scan complete evidence inside an unpublished report stage."""
    content = _evidence_content(report, secrets=secrets)
    if content is None:
        return None
    filename, data = content
    path = Path(stage_dir) / filename
    if path.exists():
        if not path.is_file() or path.read_bytes() != data:
            raise FileExistsError("同名工程证据内容不一致，已阻止覆盖。")
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(data)
    ensure_artifacts_safe([path], secrets=tuple(secrets))
    return path


def _same_evidence(stage: Path, destination: Path, *, secrets=()):
    if not destination.is_file() or destination.read_bytes() != stage.read_bytes():
        raise FileExistsError("已有工程证据内容与本报告不一致，未覆盖已有文件。")
    ensure_artifacts_safe([destination], secrets=tuple(secrets))


def _publish_evidence(stage: Path, destination: Path, *, secrets=()):
    """Never overwrite evidence belonging to an earlier report."""
    if destination.exists():
        _same_evidence(stage, destination, secrets=secrets)
        return
    try:
        # The stage is on the destination volume. A hard link provides an
        # atomic no-replace operation on supported local filesystems.
        os.link(stage, destination)
        return
    except FileExistsError:
        _same_evidence(stage, destination, secrets=secrets)
        return
    except OSError as error:
        if error.errno not in {errno.EPERM, errno.EACCES, errno.ENOTSUP, errno.EXDEV, errno.EINVAL}:
            raise
    # Filesystems without hard links still get an exclusive, fully scanned
    # copy before a body can publish. An interrupted copy cannot expose a body
    # whose referenced attachment is incomplete; a later attempt fails closed.
    try:
        with destination.open("xb") as stream:
            stream.write(stage.read_bytes())
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        _same_evidence(stage, destination, secrets=secrets)
        return
    _same_evidence(stage, destination, secrets=secrets)


@contextmanager
def staged_product_file(report, destination: Path, *, secrets=(), overwrite=True):
    """Scan body and attachment before publishing either customer report."""
    destination = Path(destination)
    if not overwrite and destination.exists():
        raise FileExistsError("拒绝覆盖已有报告，请选择新的输出文件。")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".vstacklens-product-", dir=destination.parent) as folder:
        stage_dir = Path(folder)
        stage = stage_dir / destination.name
        evidence = write_into_stage(report, stage_dir, secrets=secrets)
        yield stage
        ensure_artifacts_safe([stage, *([evidence] if evidence else [])], secrets=tuple(secrets))
        if not overwrite and destination.exists():
            raise FileExistsError("生成期间目标报告已出现，未覆盖已有文件。")
        if evidence:
            _publish_evidence(evidence, destination.parent / evidence.name, secrets=secrets)
        if overwrite:
            os.replace(stage, destination)
        elif os.name == "nt":
            # Windows rename refuses an existing target, including a race.
            os.rename(stage, destination)
        else:
            os.link(stage, destination)
