from __future__ import annotations

import json
import sqlite3

from vstacklens.core.context import RunContext
from vstacklens.core.ids import new_id
from vstacklens.core.time import utc_now_iso
from vstacklens.inventory.canonical_models import CanonicalInventory


class SnapshotEngine:
    def write_snapshot(self, conn: sqlite3.Connection, context: RunContext, inventory: CanonicalInventory) -> str:
        now = utc_now_iso()
        snapshot_id = new_id("snap")
        conn.execute(
            "INSERT INTO inventory_snapshots VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                snapshot_id,
                context.run_id,
                context.customer_id,
                context.site_id,
                context.vcenter_id,
                "full",
                now,
                len(inventory.objects),
                json.dumps({"object_count": len(inventory.objects)}, ensure_ascii=False),
                now,
            ),
        )
        for obj in inventory.objects:
            conn.execute(
                """
                INSERT INTO inventory_objects (
                  object_id, snapshot_id, run_id, customer_id, vcenter_id,
                  object_type, object_key, object_name, path, properties_json,
                  raw_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    new_id("obj"),
                    snapshot_id,
                    context.run_id,
                    context.customer_id,
                    context.vcenter_id,
                    obj.object_type,
                    obj.object_key,
                    obj.object_name,
                    obj.object_path,
                    obj.model_dump_json(),
                    None,
                    now,
                ),
            )
        return snapshot_id
