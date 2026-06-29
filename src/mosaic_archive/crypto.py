"""Standard password KDF and AEAD primitives; no custom cryptography."""

from __future__ import annotations

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from mosaic_archive.exceptions import AuthenticationError

KEY_LENGTH = 32
SALT_LENGTH = 16
NONCE_LENGTH = 12
AEAD_TAG_LENGTH = 16


def normalize_password(password: str | bytes) -> bytes:
    encoded = password.encode("utf-8") if isinstance(password, str) else bytes(password)
    if not encoded:
        raise ValueError("password must not be empty")
    return encoded


def derive_key(
    password: str | bytes,
    salt: bytes,
    *,
    log_n: int,
    r: int,
    p: int,
) -> bytes:
    if len(salt) != SALT_LENGTH:
        raise ValueError("scrypt salt must be 16 bytes")
    kdf = Scrypt(salt=salt, length=KEY_LENGTH, n=1 << log_n, r=r, p=p)
    return kdf.derive(normalize_password(password))


def encrypt(key: bytes, nonce: bytes, plaintext: bytes, associated_data: bytes) -> bytes:
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, associated_data)


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes) -> bytes:
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, associated_data)
    except InvalidTag as error:
        raise AuthenticationError("wrong password or archive was modified") from error

