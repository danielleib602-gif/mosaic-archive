"""Length-bucket padding placed inside the authenticated ciphertext."""

from __future__ import annotations

import os
import struct

from mosaic_archive.exceptions import ArchiveFormatError

_LENGTH = struct.Struct(">Q")


def pad_payload(payload: bytes, block_size: int) -> bytes:
    if block_size < 256 or block_size > 16 * 1024 * 1024:
        raise ValueError("padding size must be between 256 bytes and 16 MiB")
    envelope_size = _LENGTH.size + len(payload)
    padded_size = ((envelope_size + block_size - 1) // block_size) * block_size
    return _LENGTH.pack(len(payload)) + payload + os.urandom(padded_size - envelope_size)


def unpad_payload(padded: bytes) -> bytes:
    if len(padded) < _LENGTH.size:
        raise ArchiveFormatError("encrypted payload is too short")
    (payload_length,) = _LENGTH.unpack_from(padded)
    if payload_length > len(padded) - _LENGTH.size:
        raise ArchiveFormatError("encrypted payload length is invalid")
    return padded[_LENGTH.size : _LENGTH.size + payload_length]

