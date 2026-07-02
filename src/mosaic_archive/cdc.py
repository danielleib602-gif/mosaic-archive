"""Deterministic streaming content-defined chunk boundaries."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from dataclasses import dataclass
from typing import BinaryIO

_MASK_64 = (1 << 64) - 1
_WINDOW_SIZE = 64
_READ_SIZE = 64 * 1024


def _build_table() -> tuple[int, ...]:
    return tuple(
        int.from_bytes(
            hashlib.sha256(b"Mosaic-CDC-v1" + bytes((value,))).digest()[:8],
            "big",
        )
        for value in range(256)
    )


_BUZHASH_TABLE = _build_table()


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


def _fill_recent_window(
    window: bytearray,
    completed_segments: list[memoryview],
    current_segment: memoryview,
) -> None:
    position = _WINDOW_SIZE
    for segment in (current_segment, *reversed(completed_segments)):
        if position == 0:
            break
        count = min(position, len(segment))
        position -= count
        window[position : position + count] = segment[-count:]
    if position:
        raise RuntimeError("internal CDC window is incomplete")


def iter_content_defined_chunks(
    stream: BinaryIO,
    config: ChunkingConfig = DEFAULT_CHUNKING,
) -> Iterator[bytes]:
    """Yield bounded chunks using a 64-byte rolling Buzhash boundary signal.

    Boundary decisions depend on the recent byte window rather than absolute
    offsets, so alignment recovers after insertions or deletions.
    """
    boundary_mask = config.avg_size - 1
    chunk_segments: list[memoryview] = []
    chunk_size = 0
    window = bytearray(_WINDOW_SIZE)
    window_position = 0
    fingerprint = 0
    fingerprint_active = False
    table = _BUZHASH_TABLE
    minimum_size = config.min_size
    maximum_size = config.max_size

    while input_block := stream.read(_READ_SIZE):
        block_view = memoryview(input_block)
        segment_start = 0
        for index, byte in enumerate(input_block):
            chunk_size += 1
            if not fingerprint_active:
                if chunk_size < minimum_size:
                    continue
                _fill_recent_window(
                    window,
                    chunk_segments,
                    block_view[segment_start : index + 1],
                )
                fingerprint = 0
                for initial in window:
                    fingerprint = (
                        ((fingerprint << 1) | (fingerprint >> 63)) & _MASK_64
                    ) ^ table[initial]
                fingerprint_active = True
            else:
                outgoing = window[window_position]
                window[window_position] = byte
                window_position = (window_position + 1) & (_WINDOW_SIZE - 1)
                rotated = ((fingerprint << 1) | (fingerprint >> 63)) & _MASK_64
                fingerprint = (
                    rotated
                    ^ table[outgoing]
                    ^ table[byte]
                )

            at_content_boundary = (
                chunk_size >= minimum_size and fingerprint & boundary_mask == 0
            )
            if at_content_boundary or chunk_size >= maximum_size:
                chunk_segments.append(block_view[segment_start : index + 1])
                yield b"".join(chunk_segments)
                chunk_segments.clear()
                segment_start = index + 1
                chunk_size = 0
                window_position = 0
                fingerprint = 0
                fingerprint_active = False
        if segment_start < len(input_block):
            chunk_segments.append(block_view[segment_start:])

    if chunk_segments:
        yield b"".join(chunk_segments)
