"""Experimental solid-lane compression over an ordered unique-chunk stream."""

from __future__ import annotations

import hashlib
import lzma
import math
import struct
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from mosaic_archive.exceptions import ArchiveFormatError

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
_DELTA_EXACT_OBSERVATION_LIMIT: Final = 8192
_DELTA_SAMPLE_OBSERVATION_COUNT: Final = 4095
_DELTA_SAMPLE_WINDOW_COUNT: Final = 15
_DELTA_SAMPLE_OBSERVATIONS_PER_WINDOW: Final = (
    _DELTA_SAMPLE_OBSERVATION_COUNT // _DELTA_SAMPLE_WINDOW_COUNT
)
_DELTA_SAMPLE_WINDOW_BYTES: Final = _DELTA_SAMPLE_OBSERVATIONS_PER_WINDOW + 4
_DELTA_ROUTE_GUARD_BITS: Final = 0.25
_DELTA_SAMPLE_ENTROPY_GUARD_BITS: Final = 1.0
_DELTA_SAMPLE_GOLDEN_STEP: Final = 0x9E3779B97F4A7C15
_UINT64_MASK: Final = (1 << 64) - 1


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
        lzma.compress(data, format=lzma.FORMAT_RAW, filters=list(_DELTA_FILTERS)) if data else b""
    )


def _delta4_entropy_bits_per_byte(chunk: bytes) -> float:
    if len(chunk) <= 4:
        return 0.0
    counts = [0] * 256
    for index in range(4, len(chunk)):
        counts[(chunk[index] - chunk[index - 4]) & 0xFF] += 1
    total = len(chunk) - 4
    return -sum((count / total) * math.log2(count / total) for count in counts if count)


def _delta_sample_window_starts(chunk: bytes) -> tuple[int, ...]:
    seed = int.from_bytes(hashlib.sha256(chunk).digest()[:8], "big")
    starts: list[int] = []
    for index in range(_DELTA_SAMPLE_WINDOW_COUNT):
        region_start = index * len(chunk) // _DELTA_SAMPLE_WINDOW_COUNT
        region_end = (index + 1) * len(chunk) // _DELTA_SAMPLE_WINDOW_COUNT
        available_starts = region_end - region_start - _DELTA_SAMPLE_WINDOW_BYTES + 1
        seed = (seed + _DELTA_SAMPLE_GOLDEN_STEP) & _UINT64_MASK
        starts.append(region_start + seed % available_starts)
    return tuple(starts)


def _sampled_delta4_and_byte_entropy_bits_per_byte(
    chunk: bytes,
) -> tuple[float, float]:
    counts = [0] * 256
    sampled_bytes: list[bytes] = []
    total = 0
    for start in _delta_sample_window_starts(chunk):
        stop = start + _DELTA_SAMPLE_WINDOW_BYTES
        sampled_bytes.append(chunk[start:stop])
        for index in range(start + 4, stop):
            counts[(chunk[index] - chunk[index - 4]) & 0xFF] += 1
            total += 1
    delta_entropy = -sum((count / total) * math.log2(count / total) for count in counts if count)
    return delta_entropy, _byte_entropy_bits_per_byte(b"".join(sampled_bytes))


def _byte_entropy_bits_per_byte(chunk: bytes) -> float:
    total = len(chunk)
    return -sum((count / total) * math.log2(count / total) for count in Counter(chunk).values())


def choose_solid_lane(chunk: bytes) -> int:
    """Route from cheap byte features without trial-compressing the chunk."""
    if not chunk:
        return _STANDARD
    entropy = _byte_entropy_bits_per_byte(chunk)
    if entropy >= 7.75:
        return _HIGH_ENTROPY
    if entropy < 3.0:
        return _STANDARD

    delta_observations = len(chunk) - 4
    if delta_observations <= _DELTA_EXACT_OBSERVATION_LIMIT:
        delta_entropy = _delta4_entropy_bits_per_byte(chunk)
    else:
        sampled_delta_entropy, sampled_byte_entropy = (
            _sampled_delta4_and_byte_entropy_bits_per_byte(chunk)
        )
        sampled_advantage = entropy - sampled_delta_entropy
        sampled_lane: int | None = None
        if sampled_advantage >= 2.0 + _DELTA_ROUTE_GUARD_BITS:
            sampled_lane = _DELTA4
        elif sampled_advantage <= 2.0 - _DELTA_ROUTE_GUARD_BITS:
            sampled_lane = _STANDARD
        if (
            sampled_lane is not None
            and abs(entropy - sampled_byte_entropy) <= _DELTA_SAMPLE_ENTROPY_GUARD_BITS
        ):
            return sampled_lane
        delta_entropy = _delta4_entropy_bits_per_byte(chunk)

    if entropy - delta_entropy >= 2.0:
        return _DELTA4
    return _STANDARD


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
        lane = choose_solid_lane(chunk)
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
        if lane >= _LANE_COUNT or size != expected_size or size > _MAX_CHUNK_SIZE:
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
