from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class CanonicalObject(BaseModel):
    object_type: str
    object_key: str
    object_name: str
    object_path: str
    properties: dict[str, Any] = Field(default_factory=dict)
    raw_ref: str | None = None


class CanonicalInventory(BaseModel):
    objects: list[CanonicalObject] = Field(default_factory=list)

    def by_type(self, object_type: str) -> list[CanonicalObject]:
        return [obj for obj in self.objects if obj.object_type == object_type]
