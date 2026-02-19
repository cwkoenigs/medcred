"""Tests for medcred.models."""

import time
from datetime import timezone

from medcred.models import Credential, Vault


def test_credential_defaults():
    c = Credential(name="test")
    assert c.id
    assert c.name == "test"
    assert c.username is None
    assert c.password is None
    assert c.tags == []
    assert c.created_at.tzinfo == timezone.utc
    assert c.updated_at.tzinfo == timezone.utc


def test_credential_touch_updates_timestamp():
    c = Credential(name="test")
    before = c.updated_at
    time.sleep(0.01)
    c.touch()
    assert c.updated_at > before


def test_credential_ids_are_unique():
    ids = {Credential(name="x").id for _ in range(100)}
    assert len(ids) == 100


def test_vault_defaults():
    v = Vault()
    assert v.version == "1"
    assert v.credentials == {}


def test_vault_serialisation_roundtrip():
    v = Vault()
    c = Credential(name="github", username="alice", password="s3cret")
    v.credentials[c.id] = c

    json_str = v.model_dump_json()
    v2 = Vault.model_validate_json(json_str)

    assert len(v2.credentials) == 1
    loaded = list(v2.credentials.values())[0]
    assert loaded.name == "github"
    assert loaded.password == "s3cret"
