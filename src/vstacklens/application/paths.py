from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

from vstacklens.resources import bundled_builtin_rulepack_path, bundled_upgrade_alias_template_path


APP_NAME = "VStackLens"


def app_data_dir() -> Path:
    """Return the per-user local application data directory."""

    if sys.platform.startswith("win"):
        base = os.environ.get("LOCALAPPDATA")
        if base:
            return Path(base) / APP_NAME
        return Path.home() / "AppData" / "Local" / APP_NAME
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / APP_NAME


def default_database_path() -> Path:
    return app_data_dir() / "data" / "vstacklens-desktop.db"


def upgrade_compat_database_path(primary_database_path: Path | str | None = None) -> Path:
    """Return the isolated database paired with a health-inspection database."""

    primary = Path(primary_database_path) if primary_database_path else default_database_path()
    suffix = primary.suffix or ".db"
    return primary.with_name(f"{primary.stem}-compat{suffix}")


def default_report_output_dir() -> Path:
    return app_data_dir() / "reports"


def default_log_dir() -> Path:
    return app_data_dir() / "logs"


def default_config_path() -> Path:
    return app_data_dir() / "config" / "desktop_config.json"


def default_upgrade_alias_path() -> Path:
    """Return the editable per-user upgrade compatibility alias table path."""

    return app_data_dir() / "config" / "upgrade-compat-aliases.yaml"


def ensure_default_upgrade_alias_path() -> Path:
    """Create the user alias table from the bundled template exactly once."""

    destination = default_upgrade_alias_path()
    if destination.exists():
        return destination
    template = bundled_upgrade_alias_template_path()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if template.exists():
        shutil.copyfile(template, destination)
    else:
        destination.write_text("aliases: []\n", encoding="utf-8")
    return destination


def default_hcl_download_dir() -> Path:
    return app_data_dir() / "hcl"


def builtin_rulepack_path() -> Path:
    """Locate the bundled builtin rulepack without relying on current cwd."""

    env_path = os.environ.get("VSTACKLENS_RULEPACK")
    if env_path:
        return Path(env_path)
    return bundled_builtin_rulepack_path()
