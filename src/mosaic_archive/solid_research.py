"""Experimental solid-lane compression over an ordered unique-chunk stream."""

from __future__ import annotations

import lzma
import struct
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from mosaic_archive.exceptions import ArchiveFormatError
from mosaic_archive.features import analyze_block

_MAGIC: Final = b"SLZ1"
_HEADER: Final = struct.Struct(">4sI")
_DESCRIPTOR: Final = struct.Struct(">BI")
_LANE_HEADER: Final = struct.Struct(">QQ")
_STANDARD: Final = 0
_DELTA4: Final = 1
_HIGH_ENTROPY: Final = 2
_LANE_NAMES: Final = ("standard", "delta4", "high_entropy")
_LANE_COUNT: Final = len(_LANE_NAMES)
_MAX_CHUNKS: Final = 1_000_000
_MAX_CHUNK_SIZE: Final = 16 * 1024 * 1024
SOLID_LZMA_PRESET: Final = lzma.PRESET_DEFAULT
_DELTA_FILTERS: Final = (
    {"id": lzma.FILTER_DELTA, "dist": 4},
    {"id": lzma.FILTER_LZMA2, "preset": SOLID_LZMA_PRESET},
)


@dataclass(frozen=True, slots=True)
class SolidLaneEncoding:
    payload: bytes
    lane_distribution: dict[str, int]
    raw_size: int

    @property
    def compression_ratio(self) -> float:
        return len(self.payload) / self.raw_size if self.raw_size else 0.0


def _compress_standard(data: bytes) -> bytes:
    return lzma.compress(data, preset=SOLID_LZMA_PRESET) if data else b""


def _compress_delta4(data: bytes) -> bytes:
    return (
        lzma.compress(data, format=lzma.FORMAT_RAW, filters=list(_DELTA_FILTERS))
        if data
        else b""
    )


def _choose_lane(chunk: bytes) -> int:
    if not chunk:
        return _STANDARD
    if analyze_block(chunk).entropy_bits_per_byte >= 7.75:
        return _HIGH_ENTROPY
    standard_size = len(_compress_standard(chunk))
    delta_size = len(_compress_delta4(chunk))
    return _DELTA4 if delta_size * 2 < standard_size else _STANDARD


def encode_solid_chunks(chunks: Sequence[bytes]) -> SolidLaneEncoding:
    """Route chunks by content and compress each lane as one solid stream."""
    if len(chunks) > _MAX_CHUNKS:
        raise ValueError("solid research chunk count exceeds the safety limit")
    normalized = tuple(bytes(chunk) for chunk in chunks)
    if any(len(chunk) > _MAX_CHUNK_SIZE for chunk in normalized):
        raise ValueError("solid research chunk exceeds the 16 MiB safety limit")

    lanes = [bytearray() for _ in range(_LANE_COUNT)]
    descriptors: list[tuple[int, int]] = []
    counts = [0] * _LANE_COUNT
    for chunk in normalized:
        lane = _choose_lane(chunk)
        lanes[lane].extend(chunk)
        descriptors.append((lane, len(chunk)))
        counts[lane] += 1

    compressed_lanes = (
        _compress_standard(bytes(lanes[_STANDARD])),
        _compress_delta4(bytes(lanes[_DELTA4])),
        _compress_standard(bytes(lanes[_HIGH_ENTROPY])),
    )
    output = bytearray(_HEADER.pack(_MAGIC, len(normalized)))
    for lane, size in descriptors:
        output.extend(_DESCRIPTOR.pack(lane, size))
    for raw, compressed in zip(lanes, compressed_lanes, strict=True):
        output.extend(_LANE_HEADER.pack(len(raw), len(compressed)))
    for compressed in compressed_lanes:
        output.extend(compressed)

    return SolidLaneEncoding(
        payload=bytes(output),
        lane_distribution=dict(zip(_LANE_NAMES, counts, strict=True)),
        raw_size=sum(len(chunk) for chunk in normalized),
    )


def _decompress_lane(payload: bytes, expected_size: int, lane: int) -> bytes:
    if expected_size == 0:
        if payload:
            raise ArchiveFormatError("empty solid lane has a payload")
        return b""
    try:
        if lane == _DELTA4:
            decoder = lzma.LZMADecompressor(
                format=lzma.FORMAT_RAW,
                filters=list(_DELTA_FILTERS),
            )
        else:
            decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        output = decoder.decompress(payload, max_length=expected_size + 1)
    except (lzma.LZMAError, EOFError) as error:
        raise ArchiveFormatError("solid lane payload is malformed") from error
    if len(output) != expected_size or not decoder.eof or decoder.unused_data:
        raise ArchiveFormatError("solid lane decoded size is inconsistent")
    return output


def decode_solid_chunks(
    payload: bytes,
    expected_sizes: Sequence[int],
) -> tuple[bytes, ...]:
    """Decode a solid-lane payload with strict chunk and expansion bounds."""
    if len(payload) < _HEADER.size:
        raise ArchiveFormatError("solid lane header is truncated")
    magic, chunk_count = _HEADER.unpack_from(payload)
    if magic != _MAGIC:
        raise ArchiveFormatError("solid lane magic is invalid")
    if chunk_count != len(expected_sizes) or chunk_count > _MAX_CHUNKS:
        raise ArchiveFormatError("solid lane chunk count is inconsistent")

    position = _HEADER.size
    descriptor_bytes = chunk_count * _DESCRIPTOR.size
    lane_header_bytes = _LANE_COUNT * _LANE_HEADER.size
    if descriptor_bytes + lane_header_bytes > len(payload) - position:
        raise ArchiveFormatError("solid lane descriptor table is truncated")

    descriptors: list[tuple[int, int]] = []
    calculated_raw_sizes = [0] * _LANE_COUNT
    for expected_size in expected_sizes:
        lane, size = _DESCRIPTOR.unpack_from(payload, position)
        position += _DESCRIPTOR.size
        if (
            lane >= _LANE_COUNT
            or size != expected_size
            or size > _MAX_CHUNK_SIZE
        ):
            raise ArchiveFormatError("solid lane chunk descriptor is invalid")
        descriptors.append((lane, size))
        calculated_raw_sizes[lane] += size

    lane_sizes: list[tuple[int, int]] = []
    for lane in range(_LANE_COUNT):
        raw_size, compressed_size = _LANE_HEADER.unpack_from(payload, position)
        position += _LANE_HEADER.size
        if raw_size != calculated_raw_sizes[lane]:
            raise ArchiveFormatError("solid lane raw size is inconsistent")
        lane_sizes.append((raw_size, compressed_size))
    if sum(size for _, size in lane_sizes) != len(payload) - position:
        raise ArchiveFormatError("solid lane payload sizes are inconsistent")

    decoded_lanes: list[bytes] = []
    for lane, (raw_size, compressed_size) in enumerate(lane_sizes):
        compressed = payload[position : position + compressed_size]
        position += compressed_size
        decoded_lanes.append(_decompress_lane(compressed, raw_size, lane))

    lane_positions = [0] * _LANE_COUNT
    chunks: list[bytes] = []
    for lane, size in descriptors:
        start = lane_positions[lane]
        end = start + size
        chunks.append(decoded_lanes[lane][start:end])
        lane_positions[lane] = end
    if any(
        position != len(decoded)
        for position, decoded in zip(lane_positions, decoded_lanes, strict=True)
    ):
        raise ArchiveFormatError("solid lane contains unreferenced bytes")
    return tuple(chunks)
