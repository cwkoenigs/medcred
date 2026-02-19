"""Encrypted vault file I/O.

Binary file format
------------------
Offset  Length  Content
0       4       Magic bytes b"MCRD"
4       1       Format version (uint8)
5       2       Salt length in bytes (big-endian uint16)
7       N       Salt
7+N     …       Fernet ciphertext (JSON-encoded Vault)
"""

from __future__ import annotations

import os
import struct
from pathlib import Path

from .crypto import decrypt, encrypt, generate_salt
from .models import Vault

_MAGIC = b"MCRD"
_FORMAT_VERSION = 1


class BadVaultError(Exception):
    """Raised when the vault file is unreadable or corrupt."""


class VaultStore:
    """Manages reading and writing the encrypted vault file."""

    def __init__(self, path: Path) -> None:
        self.path = path

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def exists(self) -> bool:
        return self.path.exists()

    def init(self, password: str) -> None:
        """Create a new, empty vault protected by *password*."""
        self._write(Vault(), password)

    def load(self, password: str) -> Vault:
        """Read and decrypt the vault; returns a :class:`Vault` instance."""
        raw = self.path.read_bytes()
        salt, ciphertext = _parse(raw)
        plaintext = decrypt(ciphertext, password, salt)
        return Vault.model_validate_json(plaintext)

    def save(self, vault: Vault, password: str) -> None:
        """Encrypt and persist *vault* to disk."""
        self._write(vault, password)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _write(self, vault: Vault, password: str) -> None:
        salt = generate_salt()
        plaintext = vault.model_dump_json().encode("utf-8")
        ciphertext = encrypt(plaintext, password, salt)

        header = (
            _MAGIC
            + struct.pack(">B", _FORMAT_VERSION)
            + struct.pack(">H", len(salt))
            + salt
        )
        data = header + ciphertext

        self.path.parent.mkdir(parents=True, exist_ok=True)

        # Atomic write via temp file
        tmp = self.path.with_suffix(".tmp")
        tmp.write_bytes(data)
        tmp.replace(self.path)

        # Restrict permissions: owner read/write only
        os.chmod(self.path, 0o600)


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _parse(data: bytes) -> tuple[bytes, bytes]:
    """Return *(salt, ciphertext)* from raw vault bytes."""
    if len(data) < 7 or not data.startswith(_MAGIC):
        raise BadVaultError("Not a valid medcred vault file.")

    offset = len(_MAGIC)
    (fmt_ver,) = struct.unpack_from(">B", data, offset)
    offset += 1

    if fmt_ver != _FORMAT_VERSION:
        raise BadVaultError(f"Unsupported vault format version: {fmt_ver}.")

    (salt_len,) = struct.unpack_from(">H", data, offset)
    offset += 2

    salt = data[offset : offset + salt_len]
    offset += salt_len
    ciphertext = data[offset:]

    if not salt or not ciphertext:
        raise BadVaultError("Vault file is truncated or corrupt.")

    return salt, ciphertext
