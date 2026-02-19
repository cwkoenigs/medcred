"""Domain models for medcred."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_id() -> str:
    return str(uuid.uuid4())


class Credential(BaseModel):
    """A single stored credential."""

    id: str = Field(default_factory=_new_id)
    name: str
    username: Optional[str] = None
    password: Optional[str] = None
    url: Optional[str] = None
    notes: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

    def touch(self) -> None:
        """Update *updated_at* to now."""
        self.updated_at = _utcnow()


class Vault(BaseModel):
    """Top-level container for all credentials."""

    version: str = "1"
    credentials: dict[str, Credential] = Field(default_factory=dict)
