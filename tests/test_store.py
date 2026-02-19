"""Tests for medcred.store."""

import pytest

from medcred.models import Credential, Vault
from medcred.store import BadVaultError, VaultStore


def _store(tmp_path, name="vault.mc") -> VaultStore:
    return VaultStore(tmp_path / name)


# ---------------------------------------------------------------------------
# Init / exists
# ---------------------------------------------------------------------------


def test_new_store_does_not_exist(tmp_path):
    assert not _store(tmp_path).exists()


def test_init_creates_file(tmp_path):
    store = _store(tmp_path)
    store.init("password")
    assert store.exists()


def test_init_sets_restricted_permissions(tmp_path):
    import stat

    store = _store(tmp_path)
    store.init("password")
    mode = store.path.stat().st_mode & 0o777
    assert mode == 0o600


# ---------------------------------------------------------------------------
# Round-trip load/save
# ---------------------------------------------------------------------------


def test_load_empty_vault(tmp_path):
    store = _store(tmp_path)
    store.init("pw")
    vault = store.load("pw")
    assert isinstance(vault, Vault)
    assert vault.credentials == {}


def test_wrong_password_raises_valueerror(tmp_path):
    store = _store(tmp_path)
    store.init("correct")
    with pytest.raises(ValueError):
        store.load("wrong")


def test_add_and_reload_credential(tmp_path):
    store = _store(tmp_path)
    store.init("pw")
    vault = store.load("pw")

    cred = Credential(
        name="github",
        username="alice@example.com",
        password="s3cret",
        url="https://github.com",
        tags=["dev"],
    )
    vault.credentials[cred.id] = cred
    store.save(vault, "pw")

    vault2 = store.load("pw")
    assert len(vault2.credentials) == 1
    loaded = list(vault2.credentials.values())[0]
    assert loaded.name == "github"
    assert loaded.username == "alice@example.com"
    assert loaded.password == "s3cret"
    assert loaded.url == "https://github.com"
    assert loaded.tags == ["dev"]


def test_multiple_credentials_persist(tmp_path):
    store = _store(tmp_path)
    store.init("pw")
    vault = store.load("pw")

    for i in range(5):
        c = Credential(name=f"cred-{i}", password=f"pass-{i}")
        vault.credentials[c.id] = c

    store.save(vault, "pw")
    vault2 = store.load("pw")
    assert len(vault2.credentials) == 5


def test_overwrite_existing_vault(tmp_path):
    store = _store(tmp_path)
    store.init("pw1")
    store.init("pw2")  # new password
    vault = store.load("pw2")
    assert isinstance(vault, Vault)


# ---------------------------------------------------------------------------
# Bad vault detection
# ---------------------------------------------------------------------------


def test_bad_magic_raises(tmp_path):
    path = tmp_path / "bad.mc"
    path.write_bytes(b"BADMAGIC" + b"\x00" * 20)
    store = VaultStore(path)
    with pytest.raises(BadVaultError):
        store.load("pw")


def test_truncated_file_raises(tmp_path):
    path = tmp_path / "trunc.mc"
    path.write_bytes(b"MCRD")  # only magic, nothing else
    store = VaultStore(path)
    with pytest.raises(BadVaultError):
        store.load("pw")
