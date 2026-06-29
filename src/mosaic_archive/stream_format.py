"""Public structures for the bounded-memory MSC2 framed container."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from mosaic_archive.container_format import (
    AEAD_CHACHA20_POLY1305,
    KDF_SCRYPT,
    MAX_CHUNK_SIZE,
    MAX_PADDING_SIZE,
)
from mosaic_archive.crypto import AEAD_TAG_LENGTH, SALT_LENGTH
from mosaic_archive.exceptions import ArchiveFormatError, UnsupportedVersionError

MSC2_MAGIC = b"MSC2"
MSC2_VERSION = 2
MSC2_FLAGS = 0x03  # independently authenticated frames + padded frame plaintexts
NONCE_PREFIX_LENGTH = 4
MAX_FRAME_COUNT = 16_777_216
MAX_MANIFEST_CIPHERTEXT = 256 * 1024 * 1024

# magic, version, flags, KDF, AEAD, chunk size, padding size, salt,
# 4-byte nonce prefix, scrypt log2(N), r, p, frame count
MSC2_HEADER = struct.Struct(">4sBBBBII16s4sBBBQ")
FRAME_HEADER = struct.Struct(">QBI")

FRAME_MANIFEST = 1
FRAME_DATA = 2


@dataclass(frozen=True, slots=True)
class Msc2Header:
    version: int
    flags: int
    kdf_id: int
    aead_id: int
    chunk_size: int
    padding_size: int
    salt: bytes
    nonce_prefix: bytes
    kdf_log_n: int
    kdf_r: int
    kdf_p: int
    frame_count: int

    def pack(self) -> bytes:
        return MSC2_HEADER.pack(
            MSC2_MAGIC,
            self.version,
            self.flags,
            self.kdf_id,
            self.aead_id,
            self.chunk_size,
            self.padding_size,
            self.salt,
            self.nonce_prefix,
            self.kdf_log_n,
            self.kdf_r,
            self.kdf_p,
            self.frame_count,
        )


@dataclass(frozen=True, slots=True)
class FrameHeader:
    index: int
    frame_type: int
    ciphertext_length: int

    def pack(self) -> bytes:
        return FRAME_HEADER.pack(self.index, self.frame_type, self.ciphertext_length)


def parse_msc2_header(data: bytes) -> Msc2Header:
    if len(data) != MSC2_HEADER.size:
        raise ArchiveFormatError("MSC2 public header is truncated")
    unpacked = MSC2_HEADER.unpack(data)
    if unpacked[0] != MSC2_MAGIC:
        raise ArchiveFormatError("not a framed Mosaic Archive (missing MSC2 magic)")
    header = Msc2Header(
        version=unpacked[1],
        flags=unpacked[2],
        kdf_id=unpacked[3],
        aead_id=unpacked[4],
        chunk_size=unpacked[5],
        padding_size=unpacked[6],
        salt=unpacked[7],
        nonce_prefix=unpacked[8],
        kdf_log_n=unpacked[9],
        kdf_r=unpacked[10],
        kdf_p=unpacked[11],
        frame_count=unpacked[12],
    )
    if header.version != MSC2_VERSION:
        raise UnsupportedVersionError(f"unsupported MSC2 version: {header.version}")
    if header.flags != MSC2_FLAGS:
        raise ArchiveFormatError("MSC2 archive uses unsupported header flags")
    if header.kdf_id != KDF_SCRYPT or header.aead_id != AEAD_CHACHA20_POLY1305:
        raise ArchiveFormatError("MSC2 archive uses unsupported cryptographic algorithms")
    if not 1 <= header.chunk_size <= MAX_CHUNK_SIZE:
        raise ArchiveFormatError("MSC2 chunk size is outside the supported range")
    if not 256 <= header.padding_size <= MAX_PADDING_SIZE:
        raise ArchiveFormatError("MSC2 padding size is outside the supported range")
    if len(header.salt) != SALT_LENGTH:
        raise ArchiveFormatError("MSC2 salt has an invalid size")
    if len(header.nonce_prefix) != NONCE_PREFIX_LENGTH:
        raise ArchiveFormatError("MSC2 nonce prefix has an invalid size")
    if not 14 <= header.kdf_log_n <= 18:
        raise ArchiveFormatError("MSC2 scrypt cost is outside the supported range")
    if header.kdf_r != 8 or header.kdf_p != 1:
        raise ArchiveFormatError("MSC2 scrypt parameters are outside the supported range")
    if not 1 <= header.frame_count <= MAX_FRAME_COUNT:
        raise ArchiveFormatError("MSC2 frame count is outside the supported range")
    return header


def parse_frame_header(data: bytes) -> FrameHeader:
    if len(data) != FRAME_HEADER.size:
        raise ArchiveFormatError("MSC2 frame header is truncated")
    index, frame_type, ciphertext_length = FRAME_HEADER.unpack(data)
    if frame_type not in {FRAME_MANIFEST, FRAME_DATA}:
        raise ArchiveFormatError(f"MSC2 frame type is unknown: {frame_type}")
    if ciphertext_length < AEAD_TAG_LENGTH:
        raise ArchiveFormatError("MSC2 frame ciphertext length is invalid")
    return FrameHeader(index, frame_type, ciphertext_length)


def frame_nonce(prefix: bytes, index: int) -> bytes:
    if len(prefix) != NONCE_PREFIX_LENGTH:
        raise ValueError("MSC2 nonce prefix must be four bytes")
    return prefix + index.to_bytes(8, "big")
