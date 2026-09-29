from __future__ import annotations

import hashlib
import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from vstacklens import __version__
from vstacklens.application.paths import default_log_dir


# Customer-visible desktop surfaces must use the package version rather than a
# duplicate hard-coded value.
APP_VERSION = __version__
LOG_FILE_NAME = "vstacklens-desktop.log"
MAX_LOG_BYTES = 5 * 1024 * 1024
BACKUP_COUNT = 5
LOGGER_NAME = "vstacklens"


def runtime_log_path(log_dir: Path | None = None) -> Path:
    return Path(log_dir or default_log_dir()) / LOG_FILE_NAME


def configure_runtime_logging(log_dir: Path | None = None) -> Path:
    log_path = runtime_log_path(log_dir)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    resolved = log_path.resolve()
    for handler in logger.handlers:
        if isinstance(handler, RotatingFileHandler) and Path(handler.baseFilename).resolve() == resolved:
            return log_path
    handler = RotatingFileHandler(
        log_path,
        maxBytes=MAX_LOG_BYTES,
        backupCount=BACKUP_COUNT,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s"))
    logger.addHandler(handler)
    return log_path


def get_logger(name: str) -> logging.Logger:
    if name.startswith(LOGGER_NAME):
        return logging.getLogger(name)
    return logging.getLogger(f"{LOGGER_NAME}.{name}")


def runtime_mode() -> str:
    return "pyinstaller" if getattr(sys, "frozen", False) else "python"


def sensitive_text_summary(text: str, *, preview_chars: int = 0) -> str:
    normalized = text or ""
    digest = hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest()[:12]
    if preview_chars <= 0:
        return f"length={len(normalized)}, sha256_12={digest}"
    preview = normalized[:preview_chars].replace("\r", " ").replace("\n", " ")
    return f"length={len(normalized)}, sha256_12={digest}, preview={preview!r}"
