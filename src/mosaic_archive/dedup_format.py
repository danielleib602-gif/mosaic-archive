"""Public header for the MSC3 content-defined deduplicating container."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from mosaic_archive.container_format import AEAD_CHACHA20_POLY1305, KDF_SCRYPT
from mosaic_archive.crypto import SALT_LENGTH
from mosaic_archive.exceptions import ArchiveFormatError, UnsupportedVersionError
from mosaic_archive.stream_format import MAX_FRAME_COUNT, NONCE_PREFIX_LENGTH

MSC3_MAGIC = b"MSC3"
MSC3_VERSION = 3
MSC4_MAGIC = b"MSC4"
MSC4_VERSION = 4
MSC5_MAGIC = b"MSC5"
MSC5_VERSION = 5
MSC6_MAGIC = b"MSC6"
MSC6_VERSION = 6
MSC3_FLAGS = 0x07  # framed, padded, content-defined/deduplicated
MSC3_HEADER = struct.Struct(">4sBBBBIIII16s4sBBBQ")


@dataclass(frozen=True, slots=True)
class Msc3Header:
    version: int
    flags: int
    kdf_id: int
    aead_id: int
    min_chunk_size: int
    avg_chunk_size: int
    max_chunk_size: int
    padding_size: int
    salt: bytes
    nonce_prefix: bytes
    kdf_log_n: int
    kdf_r: int
    kdf_p: int
    frame_count: int

    def pack(self) -> bytes:
        magic = {
            MSC3_VERSION: MSC3_MAGIC,
            MSC4_VERSION: MSC4_MAGIC,
            MSC5_VERSION: MSC5_MAGIC,
            MSC6_VERSION: MSC6_MAGIC,
        }.get(self.version, MSC6_MAGIC)
        return MSC3_HEADER.pack(
            magic,
            self.version,
            self.flags,
            self.kdf_id,
            self.aead_id,
            self.min_chunk_size,
            self.avg_chunk_size,
            self.max_chunk_size,
            self.padding_size,
            self.salt,
            self.nonce_prefix,
            self.kdf_log_n,
            self.kdf_r,
            self.kdf_p,
            self.frame_count,
        )


def parse_msc3_header(data: bytes) -> Msc3Header:
    if len(data) != MSC3_HEADER.size:
        raise ArchiveFormatError("MSC3 public header is truncated")
    values = MSC3_HEADER.unpack(data)
    if values[0] not in {MSC3_MAGIC, MSC4_MAGIC, MSC5_MAGIC, MSC6_MAGIC}:
        raise ArchiveFormatError("not a deduplicating Mosaic Archive")
    header = Msc3Header(*values[1:])
    expected_version = {
        MSC3_MAGIC: MSC3_VERSION,
        MSC4_MAGIC: MSC4_VERSION,
        MSC5_MAGIC: MSC5_VERSION,
        MSC6_MAGIC: MSC6_VERSION,
    }[values[0]]
    if header.version != expected_version:
        raise UnsupportedVersionError("dedup archive magic/version mismatch")
    if header.flags != MSC3_FLAGS:
        raise ArchiveFormatError("MSC3 archive uses unsupported flags")
    if header.kdf_id != KDF_SCRYPT or header.aead_id != AEAD_CHACHA20_POLY1305:
        raise ArchiveFormatError("MSC3 archive uses unsupported cryptographic algorithms")
    if (
        header.min_chunk_size < 64
        or header.avg_chunk_size & (header.avg_chunk_size - 1)
        or not header.min_chunk_size
        <= header.avg_chunk_size
        <= header.max_chunk_size
        <= 16 * 1024 * 1024
    ):
        raise ArchiveFormatError("MSC3 chunking parameters are invalid")
    if not 256 <= header.padding_size <= 16 * 1024 * 1024:
        raise ArchiveFormatError("MSC3 padding size is invalid")
    if len(header.salt) != SALT_LENGTH or len(header.nonce_prefix) != NONCE_PREFIX_LENGTH:
        raise ArchiveFormatError("MSC3 salt or nonce prefix is invalid")
    if not 14 <= header.kdf_log_n <= 18 or header.kdf_r != 8 or header.kdf_p != 1:
        raise ArchiveFormatError("MSC3 scrypt parameters are outside supported limits")
    if not 1 <= header.frame_count <= MAX_FRAME_COUNT:
        raise ArchiveFormatError("MSC3 frame count is outside supported limits")
    return header
