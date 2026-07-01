"""Incremental solid compression split into independently authenticated frames."""

from __future__ import annotations

import lzma
import struct
from dataclasses import dataclass
from typing import BinaryIO, Final

from mosaic_archive.crypto import AEAD_TAG_LENGTH, decrypt, encrypt
from mosaic_archive.exceptions import ArchiveFormatError
from mosaic_archive.padding import pad_payload, unpad_payload
from mosaic_archive.solid_research import SOLID_LZMA_PRESET
from mosaic_archive.stream_format import frame_nonce

SOLID_LANE_STANDARD: Final = 0
SOLID_LANE_DELTA4: Final = 1
SOLID_LANE_HIGH_ENTROPY: Final = 2
_VALID_LANES: Final = {
    SOLID_LANE_STANDARD,
    SOLID_LANE_DELTA4,
    SOLID_LANE_HIGH_ENTROPY,
}
_FRAME_HEADER: Final = struct.Struct(">IBBI")
_FLAG_FINAL: Final = 1
_IO_BLOCK_SIZE: Final = 64 * 1024
_OUTPUT_BLOCK_SIZE: Final = 64 * 1024
_DELTA_FILTERS: Final = (
    {"id": lzma.FILTER_DELTA, "dist": 4},
    {"id": lzma.FILTER_LZMA2, "preset": SOLID_LZMA_PRESET},
)


@dataclass(frozen=True, slots=True)
class SolidFrameWriteStats:
    frame_count: int
    next_index: int
    compressed_size: int
    padded_size: int
    max_frame_payload: int


@dataclass(frozen=True, slots=True)
class SolidFrameReadStats:
    frame_count: int
    next_index: int
    decoded_size: int


def _validate_options(
    lane: int,
    nonce_prefix: bytes,
    frame_payload_size: int,
    padding_size: int,
) -> None:
    if lane not in _VALID_LANES:
        raise ValueError(f"unknown solid lane: {lane}")
    if len(nonce_prefix) != 4:
        raise ValueError("solid frame nonce prefix must be four bytes")
    if not 1024 <= frame_payload_size <= 16 * 1024 * 1024:
        raise ValueError("solid frame payload size must be between 1 KiB and 16 MiB")
    if not 256 <= padding_size <= frame_payload_size:
        raise ValueError("solid frame padding size is invalid")


def _compressor(lane: int) -> lzma.LZMACompressor:
    if lane == SOLID_LANE_DELTA4:
        return lzma.LZMACompressor(
            format=lzma.FORMAT_RAW,
            filters=list(_DELTA_FILTERS),
        )
    return lzma.LZMACompressor(format=lzma.FORMAT_XZ, preset=SOLID_LZMA_PRESET)


def _decompressor(lane: int) -> lzma.LZMADecompressor:
    if lane == SOLID_LANE_DELTA4:
        return lzma.LZMADecompressor(
            format=lzma.FORMAT_RAW,
            filters=list(_DELTA_FILTERS),
        )
    return lzma.LZMADecompressor(format=lzma.FORMAT_XZ)


def write_solid_lane_frames(
    source: BinaryIO,
    destination: BinaryIO,
    *,
    key: bytes,
    nonce_prefix: bytes,
    associated_data: bytes,
    lane: int,
    start_index: int,
    frame_payload_size: int = 1024 * 1024,
    padding_size: int = 1024,
) -> SolidFrameWriteStats:
    """Compress one continuous lane and emit bounded authenticated frames."""
    _validate_options(lane, nonce_prefix, frame_payload_size, padding_size)
    if not 0 <= start_index <= 0xFFFFFFFF:
        raise ValueError("solid frame start index is outside the uint32 range")
    compressor = _compressor(lane)
    pending = bytearray()
    index = start_index
    compressed_size = padded_size = maximum = 0

    def emit(payload: bytes, *, final: bool) -> None:
        nonlocal index, compressed_size, padded_size, maximum
        if index > 0xFFFFFFFF:
            raise ValueError("solid frame index exceeds the uint32 range")
        padded = pad_payload(payload, padding_size)
        header = _FRAME_HEADER.pack(
            index,
            lane,
            _FLAG_FINAL if final else 0,
            len(padded) + AEAD_TAG_LENGTH,
        )
        ciphertext = encrypt(
            key,
            frame_nonce(nonce_prefix, index),
            padded,
            associated_data + header,
        )
        destination.write(header)
        destination.write(ciphertext)
        index += 1
        compressed_size += len(payload)
        padded_size += len(padded)
        maximum = max(maximum, len(payload))

    while block := source.read(_IO_BLOCK_SIZE):
        pending.extend(compressor.compress(block))
        while len(pending) > frame_payload_size:
            emit(bytes(pending[:frame_payload_size]), final=False)
            del pending[:frame_payload_size]
    pending.extend(compressor.flush())
    while len(pending) > frame_payload_size:
        emit(bytes(pending[:frame_payload_size]), final=False)
        del pending[:frame_payload_size]
    emit(bytes(pending), final=True)
    return SolidFrameWriteStats(
        frame_count=index - start_index,
        next_index=index,
        compressed_size=compressed_size,
        padded_size=padded_size,
        max_frame_payload=maximum,
    )


def _read_exact(stream: BinaryIO, size: int, description: str) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise ArchiveFormatError(f"solid frame stream is truncated at {description}")
    return data


def read_solid_lane_frames(
    source: BinaryIO,
    destination: BinaryIO,
    *,
    key: bytes,
    nonce_prefix: bytes,
    associated_data: bytes,
    lane: int,
    start_index: int,
    frame_count: int,
    expected_size: int,
    frame_payload_size: int = 1024 * 1024,
    padding_size: int = 1024,
) -> SolidFrameReadStats:
    """Authenticate and incrementally decompress one continuous lane."""
    _validate_options(lane, nonce_prefix, frame_payload_size, padding_size)
    if frame_count <= 0 or expected_size < 0:
        raise ArchiveFormatError("solid frame count or decoded size is invalid")
    decoder = _decompressor(lane)
    decoded_size = 0
    maximum_padded = (
        (8 + frame_payload_size + padding_size - 1) // padding_size
    ) * padding_size

    for offset in range(frame_count):
        index = start_index + offset
        header = _read_exact(source, _FRAME_HEADER.size, f"frame {index} header")
        actual_index, actual_lane, flags, ciphertext_length = _FRAME_HEADER.unpack(header)
        final = offset == frame_count - 1
        if (
            actual_index != index
            or actual_lane != lane
            or flags != (_FLAG_FINAL if final else 0)
            or ciphertext_length < AEAD_TAG_LENGTH
            or ciphertext_length > maximum_padded + AEAD_TAG_LENGTH
            or (ciphertext_length - AEAD_TAG_LENGTH) % padding_size
        ):
            raise ArchiveFormatError("solid frame header is inconsistent")
        ciphertext = _read_exact(
            source,
            ciphertext_length,
            f"frame {index} ciphertext",
        )
        compressed = unpad_payload(
            decrypt(
                key,
                frame_nonce(nonce_prefix, index),
                ciphertext,
                associated_data + header,
            )
        )
        if len(compressed) > frame_payload_size or (
            not final and len(compressed) != frame_payload_size
        ):
            raise ArchiveFormatError("solid frame payload exceeds its bound")

        input_data = compressed
        while True:
            remaining = expected_size - decoded_size
            output = decoder.decompress(
                input_data,
                max_length=min(_OUTPUT_BLOCK_SIZE, remaining + 1),
            )
            input_data = b""
            if len(output) > remaining:
                raise ArchiveFormatError("solid frame stream exceeds its declared size")
            destination.write(output)
            decoded_size += len(output)
            if decoder.eof or decoder.needs_input:
                break
        if decoder.eof != final or decoder.unused_data:
            raise ArchiveFormatError("solid frame stream terminates inconsistently")

    if decoded_size != expected_size or not decoder.eof:
        raise ArchiveFormatError("solid frame decoded size is inconsistent")
    return SolidFrameReadStats(frame_count, start_index + frame_count, decoded_size)
