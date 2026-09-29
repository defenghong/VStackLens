"""Automatically provisioned local settings; customers need not edit environment variables."""
from dataclasses import dataclass, asdict
import json
from pathlib import Path
from vstacklens.application.paths import app_data_dir

@dataclass(frozen=True)
class CollectionSettings:
    batch_size: int = 10
    request_timeout: int = 30
    host_timeout: int = 180
    retry_attempts: int = 2

    @classmethod
    def load(cls, path: Path | None = None):
        path = path or app_data_dir() / "config" / "collection_settings.json"
        defaults = cls()
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            try:
                with path.open("x", encoding="utf-8") as stream:
                    json.dump(asdict(defaults), stream, ensure_ascii=False, indent=2)
            except FileExistsError:
                pass
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            # Batch size is a fixed product contract, not a customer tuning requirement.
            def bounded(key, lo, hi):
                item = value.get(key, getattr(defaults, key))
                return item if type(item) is int and lo <= item <= hi else getattr(defaults, key)
            return cls(10, bounded("request_timeout", 5, 120), bounded("host_timeout", 30, 600), bounded("retry_attempts", 1, 3))
        except (ValueError, TypeError, AttributeError):
            # Preserve damaged input for diagnosis, and use safe defaults in memory.
            return defaults
