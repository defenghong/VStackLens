"""Publish complete new report directories, never clear a customer directory."""
from __future__ import annotations
import os
import shutil
import tempfile
import uuid
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def staged_report(destination: Path):
    destination = Path(destination).absolute()
    if destination.exists():
        if not destination.is_dir():
            raise ValueError("Report destination must be a directory")
        # Existing directories belong to the user; all previous reports remain intact.
        destination = destination / ("VStackLens-report-" + uuid.uuid4().hex[:12])
    destination.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".vstacklens-stage-", dir=destination.parent))
    try:
        yield stage, destination
        os.rename(stage, destination)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
