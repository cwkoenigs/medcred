"""Tests for medcred.crypto."""

import pytest

from medcred.crypto import decrypt, derive_key, encrypt, generate_salt


def test_generate_salt_returns_32_bytes():
    salt = generate_salt()
    assert len(salt) == 32


def test_generate_salt_is_random():
    salts = {generate_salt() for _ in range(20)}
    assert len(salts) == 20, "Salts should be unique"


def test_derive_key_is_deterministic():
    salt = generate_salt()
    k1 = derive_key("password", salt)
    k2 = derive_key("password", salt)
    assert k1 == k2


def test_derive_key_differs_with_different_salt():
    k1 = derive_key("password", generate_salt())
    k2 = derive_key("password", generate_salt())
    assert k1 != k2


def test_derive_key_differs_with_different_password():
    salt = generate_salt()
    k1 = derive_key("pw1", salt)
    k2 = derive_key("pw2", salt)
    assert k1 != k2


def test_encrypt_decrypt_roundtrip():
    salt = generate_salt()
    plaintext = b"super secret data"
    ct = encrypt(plaintext, "correcthorsebatterystaple", salt)
    assert decrypt(ct, "correcthorsebatterystaple", salt) == plaintext


def test_decrypt_wrong_password_raises():
    salt = generate_salt()
    ct = encrypt(b"data", "correct", salt)
    with pytest.raises(ValueError, match="Decryption failed"):
        decrypt(ct, "wrong", salt)


def test_encrypt_produces_different_ciphertext_each_call():
    # Fernet uses a random IV per call
    salt = generate_salt()
    pt = b"same data"
    ct1 = encrypt(pt, "pw", salt)
    ct2 = encrypt(pt, "pw", salt)
    assert ct1 != ct2


def test_ciphertext_is_not_plaintext():
    salt = generate_salt()
    plaintext = b"secret"
    ct = encrypt(plaintext, "pw", salt)
    assert plaintext not in ct
