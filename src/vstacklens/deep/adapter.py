from __future__ import annotations

import hashlib
from typing import Any

from vstacklens.deep.interfaces import StandardInventorySnapshot
from vstacklens.inventory.canonical_models import CanonicalInventory


class StandardSnapshotAdapter:
    """Experimental adapter from Standard inventory to the Deep contract."""

    def from_canonical_inventory(
        self,
        inventory: CanonicalInventory,
        *,
        snapshot_id: str,
        environment_id: str,
    ) -> StandardInventorySnapshot:
        objects: list[dict[str, Any]] = []
        for item in inventory.objects:
            props = dict(item.properties)
            stable_id = next(
                (
                    str(props[key])
                    for key in ("stable_id", "instance_uuid", "hardware_uuid", "uuid")
                    if props.get(key)
                ),
                "",
            )
            stable_id_quality = "source"
            if not stable_id:
                # Never use a moref as a cross-scan identity.  The fallback is
                # deterministic and explicitly marked as derived so lifecycle
                # code can choose not to compare it across environments.
                stable_id = "derived:" + hashlib.sha256(
                    f"{environment_id}|{item.object_type}|{item.object_name}|{item.object_path}".encode("utf-8")
                ).hexdigest()[:24]
                stable_id_quality = "derived"
            objects.append(
                {
                    "entity": {
                        "type": item.object_type,
                        "stable_id": stable_id,
                        "display_ref": item.object_name,
                    },
                    "object_path": item.object_path,
                    "properties": props,
                    "stable_id_quality": stable_id_quality,
                }
            )
        return StandardInventorySnapshot(
            snapshot_id=snapshot_id,
            environment_id=environment_id,
            objects=objects,
        )
