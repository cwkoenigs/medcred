"""Cryptographic primitives for medcred.

Key derivation: PBKDF2-HMAC-SHA256 (600 000 iterations, 32-byte salt).
Encryption:     Fernet (AES-128-CBC + HMAC-SHA256).
"""

from __future__ import annotations

import base64
import os

from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE = 32
PBKDF2_ITERATIONS = 600_000


def generate_salt() -> bytes:
    """Return a cryptographically-random 32-byte salt."""
    return os.urandom(SALT_SIZE)


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte Fernet-compatible key from *password* and *salt*."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    raw = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(raw)


def encrypt(plaintext: bytes, password: str, salt: bytes) -> bytes:
    """Encrypt *plaintext* with a password-derived key."""
    key = derive_key(password, salt)
    return Fernet(key).encrypt(plaintext)


def decrypt(ciphertext: bytes, password: str, salt: bytes) -> bytes:
    """Decrypt *ciphertext*; raises :class:`ValueError` on failure."""
    key = derive_key(password, salt)
    try:
        return Fernet(key).decrypt(ciphertext)
    except (InvalidToken, InvalidSignature) as exc:
        raise ValueError("Decryption failed — wrong password or corrupted vault.") from exc
