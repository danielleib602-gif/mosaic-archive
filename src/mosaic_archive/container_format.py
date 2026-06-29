"""Binary structures and defensive parsers for MSC1."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from mosaic_archive.crypto import AEAD_TAG_LENGTH, NONCE_LENGTH, SALT_LENGTH
from mosaic_archive.exceptions import ArchiveFormatError, UnsupportedVersionError

MAGIC = b"MSC1"
VERSION = 1
FLAG_PADDED = 0x01
KDF_SCRYPT = 1
AEAD_CHACHA20_POLY1305 = 1

# magic, version, flags, KDF, AEAD, chunk size, padding size, salt, nonce,
# scrypt log2(N), r, p, ciphertext length
PUBLIC_HEADER = struct.Struct(">4sBBBBII16s12sBBBQ")
INNER_PREFIX = struct.Struct(">4sQH")
INNER_MAGIC = b"MSCP"
BLOCK_COUNT = struct.Struct(">I")
BLOCK_HEADER = struct.Struct(">BII")
SHA256_SIZE = 32

MAX_CHUNK_SIZE = 16 * 1024 * 1024
MAX_PADDING_SIZE = 16 * 1024 * 1024
MAX_BLOCK_COUNT = 16_777_216


@dataclass(frozen=True, slots=True)
class PublicHeader:
    version: int
    flags: int
    kdf_id: int
    aead_id: int
    chunk_size: int
    padding_size: int
    salt: bytes
    nonce: bytes
    kdf_log_n: int
    kdf_r: int
    kdf_p: int
    ciphertext_length: int

    def pack(self) -> bytes:
        return PUBLIC_HEADER.pack(
            MAGIC,
            self.version,
            self.flags,
            self.kdf_id,
            self.aead_id,
            self.chunk_size,
            self.padding_size,
            self.salt,
            self.nonce,
            self.kdf_log_n,
            self.kdf_r,
            self.kdf_p,
            self.ciphertext_length,
        )


def validate_public_header(header: PublicHeader) -> None:
    if header.version != VERSION:
        raise UnsupportedVersionError(f"unsupported MSC version: {header.version}")
    if header.flags != FLAG_PADDED:
        raise ArchiveFormatError("archive uses unsupported header flags")
    if header.kdf_id != KDF_SCRYPT or header.aead_id != AEAD_CHACHA20_POLY1305:
        raise ArchiveFormatError("archive uses unsupported cryptographic algorithms")
    if not 1 <= header.chunk_size <= MAX_CHUNK_SIZE:
        raise ArchiveFormatError("archive chunk size is outside the supported range")
    if not 256 <= header.padding_size <= MAX_PADDING_SIZE:
        raise ArchiveFormatError("archive padding size is outside the supported range")
    if len(header.salt) != SALT_LENGTH or len(header.nonce) != NONCE_LENGTH:
        raise ArchiveFormatError("archive salt or nonce has an invalid size")
    if not 14 <= header.kdf_log_n <= 18:
        raise ArchiveFormatError("archive scrypt cost is outside the supported range")
    if header.kdf_r != 8 or header.kdf_p != 1:
        raise ArchiveFormatError("archive scrypt parameters are outside the supported range")
    if header.ciphertext_length < AEAD_TAG_LENGTH:
        raise ArchiveFormatError("archive ciphertext length is invalid")


def parse_public_header(data: bytes) -> PublicHeader:
    if len(data) != PUBLIC_HEADER.size:
        raise ArchiveFormatError("archive public header is truncated")
    unpacked = PUBLIC_HEADER.unpack(data)
    if unpacked[0] != MAGIC:
        raise ArchiveFormatError("not a Mosaic Archive (missing MSC1 magic)")
    header = PublicHeader(
        version=unpacked[1],
        flags=unpacked[2],
        kdf_id=unpacked[3],
        aead_id=unpacked[4],
        chunk_size=unpacked[5],
        padding_size=unpacked[6],
        salt=unpacked[7],
        nonce=unpacked[8],
        kdf_log_n=unpacked[9],
        kdf_r=unpacked[10],
        kdf_p=unpacked[11],
        ciphertext_length=unpacked[12],
    )
    validate_public_header(header)
    return header
