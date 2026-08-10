"""Deterministic streaming content-defined chunk boundaries."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from dataclasses import dataclass
from functools import cache
from typing import BinaryIO

_WINDOW_SIZE = 64
_READ_SIZE = 64 * 1024


def _build_table() -> tuple[int, ...]:
    return tuple(
        int.from_bytes(
            hashlib.sha256(b"Mosaic-Gear-v1/" + bytes((7, value))).digest()[:8],
            "big",
        )
        for value in range(256)
    )


_DEFAULT_GEAR_TABLE = _build_table()
_GEAR_TABLE = _DEFAULT_GEAR_TABLE


@cache
def _default_masked_table(boundary_mask: int) -> tuple[int, ...]:
    return tuple(value & boundary_mask for value in _DEFAULT_GEAR_TABLE)


def _masked_table(boundary_mask: int) -> tuple[int, ...]:
    if _GEAR_TABLE is _DEFAULT_GEAR_TABLE:
        return _default_masked_table(boundary_mask)
    return tuple(_GEAR_TABLE[index] & boundary_mask for index in range(256))


@dataclass(frozen=True, slots=True)
class ChunkingConfig:
    min_size: int = 16 * 1024
    avg_size: int = 64 * 1024
    max_size: int = 256 * 1024

    def __post_init__(self) -> None:
        if self.min_size < _WINDOW_SIZE:
            raise ValueError("minimum CDC chunk size must be at least 64 bytes")
        if self.avg_size & (self.avg_size - 1):
            raise ValueError("average CDC chunk size must be a power of two")
        if not self.min_size <= self.avg_size <= self.max_size:
            raise ValueError("CDC sizes must satisfy min <= average <= max")
        if self.max_size > 16 * 1024 * 1024:
            raise ValueError("maximum CDC chunk size must not exceed 16 MiB")


DEFAULT_CHUNKING = ChunkingConfig()


def iter_content_defined_chunks(
    stream: BinaryIO,
    config: ChunkingConfig = DEFAULT_CHUNKING,
) -> Iterator[bytes]:
    """Yield bounded chunks using a deterministic Gear boundary signal.

    Boundary decisions depend on recent content rather than absolute offsets,
    so alignment recovers after insertions or deletions.
    """
    boundary_mask = config.avg_size - 1
    chunk = bytearray()
    chunk_size = 0
    emitted_size = 0
    fingerprint = 0
    table: tuple[int, ...] | None = None
    minimum_size = config.min_size
    maximum_size = config.max_size

    while input_block := stream.read(_READ_SIZE):
        chunk.extend(input_block)
        position = 0
        input_size = len(input_block)
        while position < input_size:
            skip = min(
                max(0, minimum_size - 1 - chunk_size),
                input_size - position,
            )
            chunk_size += skip
            position += skip
            if position >= input_size:
                break

            scan_end = min(
                input_size,
                position + maximum_size - chunk_size,
            )
            if table is None:
                table = _masked_table(boundary_mask)
            boundary_offset: int | None = None
            for offset in range(position, scan_end):
                byte = input_block[offset]
                # Only the low log2(avg_size) bits can affect a boundary, and
                # later low bits depend exclusively on those same low bits.
                # Keeping the exact boundary state modulo avg_size avoids
                # carrying a wider 64-bit Python integer through every byte.
                fingerprint = ((fingerprint << 1) ^ table[byte]) & boundary_mask
                if fingerprint == 0:
                    boundary_offset = offset
                    break
            if boundary_offset is None:
                chunk_size += scan_end - position
                position = scan_end
                if chunk_size < maximum_size:
                    continue
            else:
                chunk_size += boundary_offset - position + 1
                position = boundary_offset + 1
            current_end = emitted_size + chunk_size
            yield bytes(memoryview(chunk)[emitted_size:current_end])
            emitted_size = current_end
            chunk_size = 0
            fingerprint = 0
        if emitted_size:
            del chunk[:emitted_size]
            emitted_size = 0

    if chunk:
        yield bytes(chunk)
