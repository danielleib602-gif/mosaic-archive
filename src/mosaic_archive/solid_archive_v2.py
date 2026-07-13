"""Disk-backed streaming MSR2 solid archive experiment."""

from __future__ import annotations

import hashlib
import mmap
import os
import shutil
import struct
import tempfile
import time
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Final, cast

from mosaic_archive.cdc import DEFAULT_CHUNKING, ChunkingConfig
from mosaic_archive.container_format import AEAD_CHACHA20_POLY1305, KDF_SCRYPT
from mosaic_archive.crypto import AEAD_TAG_LENGTH, SALT_LENGTH, decrypt, derive_key, encrypt
from mosaic_archive.dedup_archive import (
    MAX_CHUNK_RECORDS,
    ZERO_HASH,
    ChunkRecord,
    DedupEntry,
    DedupManifest,
    _apply_metadata,
    _scan_manifest,
    parse_dedup_manifest,
    serialize_dedup_manifest,
)
from mosaic_archive.dedup_format import MSC3_FLAGS, MSC6_VERSION, Msc3Header
from mosaic_archive.exceptions import ArchiveFormatError, IntegrityError
from mosaic_archive.padding import pad_payload, unpad_payload
from mosaic_archive.paths import path_matches_file_identity
from mosaic_archive.resource_limits import (
    DEFAULT_MAX_FRAME_COUNT,
    DEFAULT_MAX_OUTPUT_SIZE,
)
from mosaic_archive.solid_frames import (
    compress_solid_lane,
    read_solid_lane_frames,
    write_precompressed_solid_lane_frames,
)
from mosaic_archive.solid_research import choose_solid_lane
from mosaic_archive.stream_archive import (
    ENTRY_DIRECTORY,
    ENTRY_FILE,
    KIND_FILE,
    KIND_FOLDER,
)
from mosaic_archive.stream_format import MAX_MANIFEST_CIPHERTEXT, frame_nonce

MSR2_MAGIC: Final = b"MSR2"
_HEADER: Final = struct.Struct(">4sBIIIIII16s4sI")
_METADATA_PREFIX: Final = struct.Struct(">QI")
_LANE_RECORD: Final = struct.Struct(">QI")
_LANE_COUNT: Final = 3
_MAX_METADATA_CIPHERTEXT: Final = 64 * 1024 * 1024
_METADATA_MAGIC: Final = b"MDZ1"
_METADATA_ENVELOPE: Final = struct.Struct(">4sBQ")
_RAW_LZMA2_CODEC: Final = 1
_COMPACT_METADATA_MAGIC_V1: Final = b"MC21"
_COMPACT_METADATA_MAGIC: Final = b"MC22"
_MAX_COMPACT_UINT: Final = (1 << 64) - 1
_LANE_CODEC_LZMA2: Final = 0
_LANE_CODEC_RAW: Final = 1
_REUSE_PROBE_COUNT: Final = 32
_REUSE_PROBE_SIZE: Final = 64
_MAX_REUSE_PROBE_LANE_SIZE: Final = 64 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class SolidArchiveV2EncodeStats:
    format_name: str
    original_size: int
    archive_size: int
    unique_chunk_count: int
    frame_count: int
    maximum_frame_payload: int
    chunking_passes: int
    compression_passes: int
    routing_trial_compressions: int
    routing_reuse_probes: int
    elapsed_seconds: float


@dataclass(frozen=True, slots=True)
class SolidArchiveV2DecodeStats:
    format_name: str
    original_size: int
    archive_size: int
    unique_chunk_count: int
    hash_verified: bool
    elapsed_seconds: float


@dataclass(frozen=True, slots=True)
class Msr2Header:
    kdf_log_n: int
    min_chunk_size: int
    avg_chunk_size: int
    max_chunk_size: int
    padding_size: int
    frame_payload_size: int
    unique_chunk_count: int
    salt: bytes
    nonce_prefix: bytes
    metadata_ciphertext_length: int

    def pack(self) -> bytes:
        return _HEADER.pack(
            MSR2_MAGIC,
            self.kdf_log_n,
            self.min_chunk_size,
            self.avg_chunk_size,
            self.max_chunk_size,
            self.padding_size,
            self.frame_payload_size,
            self.unique_chunk_count,
            self.salt,
            self.nonce_prefix,
            self.metadata_ciphertext_length,
        )


def _metadata(
    manifest: DedupManifest,
    assignments: bytes,
    raw_sizes: tuple[int, int, int],
    frame_counts: tuple[int, int, int],
) -> bytes:
    serialized = serialize_dedup_manifest(manifest)
    output = bytearray(_METADATA_PREFIX.pack(len(serialized), len(assignments)))
    for raw_size, frame_count in zip(raw_sizes, frame_counts, strict=True):
        output.extend(_LANE_RECORD.pack(raw_size, frame_count))
    output.extend(serialized)
    output.extend(assignments)
    return bytes(output)


def _encode_compact_uint(value: int) -> bytes:
    if not 0 <= value <= _MAX_COMPACT_UINT:
        raise ValueError("compact metadata integer is outside uint64")
    output = bytearray()
    while value >= 0x80:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def _decode_compact_uint(
    payload: bytes,
    position: int,
    maximum: int,
    description: str,
) -> tuple[int, int]:
    start = position
    value = 0
    shift = 0
    while position < len(payload) and shift <= 63:
        byte = payload[position]
        position += 1
        component = byte & 0x7F
        if shift == 63 and component > 1:
            break
        value |= component << shift
        if not byte & 0x80:
            if (position - start > 1 and component == 0) or value > maximum:
                break
            return value, position
        shift += 7
    raise ArchiveFormatError(f"MSR2 compact {description} is invalid")


def _encode_compact_sint(value: int) -> bytes:
    if not -(1 << 63) <= value < 1 << 63:
        raise ValueError("compact metadata integer is outside int64")
    return _encode_compact_uint((value << 1) ^ (value >> 63))


def _decode_compact_sint(
    payload: bytes,
    position: int,
    description: str,
) -> tuple[int, int]:
    encoded, position = _decode_compact_uint(
        payload,
        position,
        _MAX_COMPACT_UINT,
        description,
    )
    return (encoded >> 1) ^ -(encoded & 1), position


def _compact_metadata(
    manifest: DedupManifest,
    assignments: bytes,
    frame_counts: tuple[int, int, int],
    lane_codecs: tuple[int, int, int] | None = None,
) -> bytes:
    output = bytearray(
        _COMPACT_METADATA_MAGIC if lane_codecs is not None else _COMPACT_METADATA_MAGIC_V1
    )
    root = manifest.root_name.encode("utf-8")
    if manifest.kind not in {KIND_FILE, KIND_FOLDER}:
        raise RuntimeError("internal MSR2 archive kind is invalid")
    kind_bit = int(manifest.kind == KIND_FOLDER)
    output.extend(_encode_compact_uint((len(root) << 1) | kind_bit))
    output.extend(root)
    output.extend(_encode_compact_uint(len(manifest.entries)))
    output.extend(_encode_compact_uint(len(manifest.chunks)))
    for frame_count in frame_counts:
        output.extend(_encode_compact_uint(frame_count))
    if lane_codecs is not None:
        for codec in lane_codecs:
            if codec not in {_LANE_CODEC_LZMA2, _LANE_CODEC_RAW}:
                raise RuntimeError("internal MSR2 lane codec is invalid")
            output.extend(_encode_compact_uint(codec))
    previous_mtime_ns = 0
    for entry in manifest.entries:
        path = entry.relative_path.encode("utf-8")
        if entry.entry_type not in {ENTRY_FILE, ENTRY_DIRECTORY}:
            raise RuntimeError("internal MSR2 entry type is invalid")
        directory_bit = int(entry.entry_type == ENTRY_DIRECTORY)
        output.extend(_encode_compact_uint((len(path) << 1) | directory_bit))
        output.extend(path)
        output.extend(_encode_compact_uint(entry.mode))
        output.extend(_encode_compact_sint(entry.mtime_ns - previous_mtime_ns))
        previous_mtime_ns = entry.mtime_ns
        if entry.entry_type == ENTRY_FILE:
            output.extend(_encode_compact_uint(entry.chunk_count))
            output.extend(entry.digest)
    for index, chunk in enumerate(manifest.chunks):
        if chunk.source_index == index:
            output.append(0)
            output.extend(_encode_compact_uint(chunk.size))
            output.extend(chunk.digest)
        else:
            output.append(1)
            output.extend(_encode_compact_uint(chunk.source_index))
    packed_assignments = bytearray((len(assignments) + 3) // 4)
    for index, lane in enumerate(assignments):
        if lane >= _LANE_COUNT:
            raise RuntimeError("internal MSR2 lane assignment is invalid")
        packed_assignments[index // 4] |= lane << ((index % 4) * 2)
    output.extend(packed_assignments)
    return bytes(output)


def _encode_metadata_envelope(payload: bytes) -> bytes:
    return _METADATA_ENVELOPE.pack(
        _METADATA_MAGIC,
        _RAW_LZMA2_CODEC,
        len(payload),
    ) + zlib.compress(payload, level=9)


def _decode_metadata_envelope(payload: bytes) -> tuple[bytes, bool]:
    if not payload.startswith(_METADATA_MAGIC):
        return payload, False
    if len(payload) < _METADATA_ENVELOPE.size:
        raise ArchiveFormatError("MSR2 metadata envelope is truncated")
    magic, codec, expected_size = _METADATA_ENVELOPE.unpack_from(payload)
    if (
        magic != _METADATA_MAGIC
        or codec != _RAW_LZMA2_CODEC
        or expected_size > MAX_MANIFEST_CIPHERTEXT
    ):
        raise ArchiveFormatError("MSR2 metadata envelope is invalid")
    decoder = zlib.decompressobj()
    try:
        decoded = decoder.decompress(
            payload[_METADATA_ENVELOPE.size :],
            expected_size + 1,
        )
        if len(decoded) > expected_size or decoder.unconsumed_tail:
            raise ArchiveFormatError("MSR2 compressed metadata exceeds its size bound")
    except zlib.error as error:
        raise ArchiveFormatError("MSR2 compressed metadata is malformed") from error
    if (
        len(decoded) != expected_size
        or not decoder.eof
        or decoder.unused_data
        or decoder.unconsumed_tail
    ):
        raise ArchiveFormatError("MSR2 compressed metadata size is inconsistent")
    return decoded, True


def _high_entropy_lane_has_distant_reuse(path: Path, raw_size: int) -> bool:
    """Find exact distant reuse without trial-compressing the assembled lane."""
    if raw_size <= 0:
        return False
    if raw_size > _MAX_REUSE_PROBE_LANE_SIZE:
        return True
    if raw_size < _REUSE_PROBE_SIZE * 2:
        return False
    with (
        path.open("rb") as source,
        mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data,
    ):
        last_start = raw_size - _REUSE_PROBE_SIZE
        for sample_index in range(_REUSE_PROBE_COUNT):
            position = (
                (sample_index + 1) * last_start // (_REUSE_PROBE_COUNT + 1)
            )
            sample = data[position : position + _REUSE_PROBE_SIZE]
            if data.find(sample, 0, max(0, position - _REUSE_PROBE_SIZE + 1)) >= 0:
                return True
            if data.find(sample, position + _REUSE_PROBE_SIZE) >= 0:
                return True
    return False


def encode_solid_archive_v2(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    password: str | bytes,
    *,
    config: ChunkingConfig = DEFAULT_CHUNKING,
    frame_payload_size: int = 1024 * 1024,
    padding_size: int = 1024,
    kdf_log_n: int = 15,
) -> SolidArchiveV2EncodeStats:
    """Create an encrypted MSR2 archive without whole-payload buffering."""
    started = time.perf_counter()
    source, destination = Path(input_path), Path(output_path)
    if source.resolve() == destination.resolve():
        raise ValueError("input and output paths must be different")
    if source.is_dir() and destination.resolve().is_relative_to(source.resolve()):
        raise ValueError("folder archives must be written outside the input tree")
    if (
        not isinstance(frame_payload_size, int)
        or isinstance(frame_payload_size, bool)
        or not 1024 <= frame_payload_size <= 16 * 1024 * 1024
    ):
        raise ValueError("solid frame payload size must be between 1 KiB and 16 MiB")
    if (
        not isinstance(padding_size, int)
        or isinstance(padding_size, bool)
        or not 256 <= padding_size <= frame_payload_size
    ):
        raise ValueError("solid frame padding size is invalid")
    if (
        not isinstance(kdf_log_n, int)
        or isinstance(kdf_log_n, bool)
        or not 14 <= kdf_log_n <= 18
    ):
        raise ValueError("scrypt cost is outside supported limits")

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None

    with tempfile.TemporaryDirectory(
        dir=destination.parent, prefix=f".{destination.name}.lanes."
    ) as lane_dir:
        lane_paths = tuple(Path(lane_dir) / f"lane-{lane}" for lane in range(_LANE_COUNT))
        lane_streams = tuple(path.open("w+b") for path in lane_paths)
        assignments_buffer = bytearray()
        raw_size_values = [0, 0, 0]

        def spool_unique_chunk(chunk: bytes) -> None:
            lane = choose_solid_lane(chunk)
            lane_streams[lane].write(chunk)
            raw_size_values[lane] += len(chunk)
            assignments_buffer.append(lane)

        try:
            manifest, _ = _scan_manifest(
                source,
                config,
                on_unique_chunk=spool_unique_chunk,
            )
        finally:
            for stream in lane_streams:
                stream.close()
        assignments = bytes(assignments_buffer)
        raw_sizes = cast(tuple[int, int, int], tuple(raw_size_values))
        unique_count = sum(
            record.source_index == index for index, record in enumerate(manifest.chunks)
        )
        if len(assignments) != unique_count:
            raise RuntimeError("internal MSR2 unique-chunk mismatch")

        salt, nonce_prefix = os.urandom(SALT_LENGTH), os.urandom(4)
        key = derive_key(password, salt, log_n=kdf_log_n, r=8, p=1)
        compressed_paths = tuple(
            Path(lane_dir) / f"lane-{lane}.lzma2" for lane in range(_LANE_COUNT)
        )
        high_entropy_codec = (
            _LANE_CODEC_LZMA2
            if _high_entropy_lane_has_distant_reuse(
                lane_paths[2],
                raw_sizes[2],
            )
            else _LANE_CODEC_RAW
        )
        lane_codecs = (
            _LANE_CODEC_LZMA2,
            _LANE_CODEC_LZMA2,
            high_entropy_codec,
        )
        routing_probe_count = int(raw_sizes[2] > 0)
        compressed_sizes: list[int] = []
        payload_paths: list[Path] = []
        frame_count_values: list[int] = []
        for lane, (raw_path, compressed_path) in enumerate(
            zip(lane_paths, compressed_paths, strict=True)
        ):
            if raw_sizes[lane] == 0:
                compressed_path.touch()
                compressed_sizes.append(0)
                payload_paths.append(compressed_path)
                frame_count_values.append(0)
                continue
            if lane_codecs[lane] == _LANE_CODEC_RAW:
                compressed_size = raw_sizes[lane]
                payload_paths.append(raw_path)
            else:
                with raw_path.open("rb") as lane_source, compressed_path.open(
                    "wb"
                ) as compressed_output:
                    compressed_size = compress_solid_lane(
                        lane_source,
                        compressed_output,
                        lane=lane,
                        raw_lzma2=True,
                    )
                payload_paths.append(compressed_path)
            compressed_sizes.append(compressed_size)
            frame_count_values.append(
                (compressed_size + frame_payload_size - 1) // frame_payload_size
            )
        frame_counts = cast(tuple[int, int, int], tuple(frame_count_values))
        metadata = _encode_metadata_envelope(
            _compact_metadata(manifest, assignments, frame_counts, lane_codecs)
        )
        if len(metadata) > MAX_MANIFEST_CIPHERTEXT:
            raise ValueError("MSR2 encrypted metadata exceeds its resource limit")
        padded_metadata = pad_payload(metadata, padding_size)
        metadata_ciphertext_length = len(padded_metadata) + AEAD_TAG_LENGTH
        header = Msr2Header(
            kdf_log_n,
            config.min_size,
            config.avg_size,
            config.max_size,
            padding_size,
            frame_payload_size,
            unique_count,
            salt,
            nonce_prefix,
            metadata_ciphertext_length,
        ).pack()
        metadata_ciphertext = encrypt(
            key,
            frame_nonce(nonce_prefix, 0),
            padded_metadata,
            header,
        )
        frame_aad = header + hashlib.sha256(metadata_ciphertext).digest()

        maximum_payload = 0
        actual_frame_count = 0
        try:
            with tempfile.NamedTemporaryFile(
                "w+b",
                dir=destination.parent,
                prefix=f".{destination.name}.",
                delete=False,
            ) as temporary:
                temporary_name = temporary.name
                output = cast(BinaryIO, temporary)
                output.write(header)
                output.write(metadata_ciphertext)
                index = 1
                for lane, path in enumerate(payload_paths):
                    if raw_sizes[lane] == 0:
                        continue
                    with path.open("rb") as lane_source:
                        stats = write_precompressed_solid_lane_frames(
                            lane_source,
                            output,
                            compressed_size=compressed_sizes[lane],
                            key=key,
                            nonce_prefix=nonce_prefix,
                            associated_data=frame_aad,
                            lane=lane,
                            start_index=index,
                            frame_payload_size=frame_payload_size,
                            padding_size=padding_size,
                        )
                    if stats.frame_count != frame_counts[lane]:
                        raise RuntimeError("MSR2 frame probe was not deterministic")
                    actual_frame_count += stats.frame_count
                    maximum_payload = max(maximum_payload, stats.max_frame_payload)
                    index = stats.next_index
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary_name, destination)
            temporary_name = None
        finally:
            if temporary_name:
                Path(temporary_name).unlink(missing_ok=True)

    return SolidArchiveV2EncodeStats(
        "MSR2",
        sum(entry.size for entry in manifest.entries),
        destination.stat().st_size,
        unique_count,
        actual_frame_count,
        maximum_payload,
        1,
        1,
        0,
        routing_probe_count,
        time.perf_counter() - started,
    )


def _read_exact(stream: BinaryIO, size: int, description: str) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise ArchiveFormatError(f"MSR2 is truncated at {description}")
    return data


def parse_msr2_header(data: bytes) -> Msr2Header:
    """Parse an exact MSR2 public header under strict resource limits."""
    if len(data) != _HEADER.size:
        raise ArchiveFormatError("MSR2 public header length is invalid")
    values = _HEADER.unpack(data)
    magic, log_n, minimum, average, maximum, padding, frame_size = values[:7]
    unique_count, salt, nonce_prefix, metadata_length = values[7:]
    metadata_length = values[-1]
    if (
        magic != MSR2_MAGIC
        or not 14 <= log_n <= 18
        or not 256 <= padding <= frame_size
        or not 1024 <= frame_size <= 16 * 1024 * 1024
        or metadata_length < AEAD_TAG_LENGTH
        or metadata_length > _MAX_METADATA_CIPHERTEXT
        or (metadata_length - AEAD_TAG_LENGTH) % padding
    ):
        raise ArchiveFormatError("MSR2 public header is invalid")
    try:
        ChunkingConfig(minimum, average, maximum)
    except ValueError as error:
        raise ArchiveFormatError("MSR2 chunking limits are invalid") from error
    return Msr2Header(
        log_n,
        minimum,
        average,
        maximum,
        padding,
        frame_size,
        unique_count,
        salt,
        nonce_prefix,
        metadata_length,
    )


def _read_header(stream: BinaryIO) -> tuple[bytes, Msr2Header]:
    serialized = _read_exact(stream, _HEADER.size, "header")
    return serialized, parse_msr2_header(serialized)


def _take_compact_bytes(
    payload: bytes,
    position: int,
    size: int,
    description: str,
) -> tuple[bytes, int]:
    end = position + size
    if end > len(payload):
        raise ArchiveFormatError(f"MSR2 compact {description} is truncated")
    return payload[position:end], end


def _metadata_compatibility_header(
    *,
    unique_count: int,
    config: ChunkingConfig,
    padding_size: int,
    salt: bytes,
    nonce_prefix: bytes,
) -> Msc3Header:
    return Msc3Header(
        MSC6_VERSION,
        MSC3_FLAGS,
        KDF_SCRYPT,
        AEAD_CHACHA20_POLY1305,
        config.min_size,
        config.avg_size,
        config.max_size,
        padding_size,
        salt,
        nonce_prefix,
        14,
        8,
        1,
        unique_count + 1,
    )


def _parse_compact_metadata(
    payload: bytes,
    *,
    unique_count: int,
    config: ChunkingConfig,
    padding_size: int,
    salt: bytes,
    nonce_prefix: bytes,
) -> tuple[
    DedupManifest,
    bytes,
    tuple[int, int, int],
    tuple[int, int, int],
    tuple[int, int, int],
]:
    modern = payload.startswith(_COMPACT_METADATA_MAGIC)
    position = len(_COMPACT_METADATA_MAGIC)
    root_descriptor, position = _decode_compact_uint(
        payload, position, (65_535 << 1) | 1, "root descriptor"
    )
    kind = KIND_FOLDER if root_descriptor & 1 else KIND_FILE
    root_length = root_descriptor >> 1
    root_bytes, position = _take_compact_bytes(
        payload, position, root_length, "root name"
    )
    try:
        root_name = root_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ArchiveFormatError("MSR2 compact root name is invalid") from error
    entry_count, position = _decode_compact_uint(
        payload, position, 1_000_000, "entry count"
    )
    chunk_count, position = _decode_compact_uint(
        payload, position, MAX_CHUNK_RECORDS, "chunk count"
    )
    frame_count_values: list[int] = []
    for lane in range(_LANE_COUNT):
        frame_count, position = _decode_compact_uint(
            payload,
            position,
            DEFAULT_MAX_FRAME_COUNT,
            f"lane {lane} frame count",
        )
        frame_count_values.append(frame_count)
    lane_codec_values: list[int] = []
    if modern:
        for lane in range(_LANE_COUNT):
            codec, position = _decode_compact_uint(
                payload,
                position,
                _LANE_CODEC_RAW,
                f"lane {lane} codec",
            )
            lane_codec_values.append(codec)
    else:
        lane_codec_values.extend([_LANE_CODEC_LZMA2] * _LANE_COUNT)

    entry_specs: list[tuple[int, str, int, int, int, bytes]] = []
    previous_mtime_ns = 0
    for index in range(entry_count):
        path_descriptor, position = _decode_compact_uint(
            payload,
            position,
            (65_535 << 1) | 1,
            f"entry {index} path descriptor",
        )
        entry_type = ENTRY_DIRECTORY if path_descriptor & 1 else ENTRY_FILE
        path_length = path_descriptor >> 1
        path_bytes, position = _take_compact_bytes(
            payload, position, path_length, f"entry {index} path"
        )
        try:
            relative_path = path_bytes.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ArchiveFormatError(
                f"MSR2 compact entry {index} path is invalid"
            ) from error
        mode, position = _decode_compact_uint(
            payload, position, 0o777, f"entry {index} mode"
        )
        mtime_delta, position = _decode_compact_sint(
            payload, position, f"entry {index} modification time"
        )
        mtime_ns = previous_mtime_ns + mtime_delta
        if not -(1 << 63) <= mtime_ns < 1 << 63:
            raise ArchiveFormatError(
                f"MSR2 compact entry {index} modification time is invalid"
            )
        previous_mtime_ns = mtime_ns
        if entry_type == ENTRY_FILE:
            count, position = _decode_compact_uint(
                payload, position, chunk_count, f"entry {index} chunk count"
            )
            digest, position = _take_compact_bytes(
                payload, position, 32, f"entry {index} digest"
            )
        else:
            count = 0
            digest = ZERO_HASH
        entry_specs.append(
            (entry_type, relative_path, mode, mtime_ns, count, digest)
        )

    chunks: list[ChunkRecord] = []
    compact_unique_count = 0
    for index in range(chunk_count):
        tag_bytes, position = _take_compact_bytes(
            payload, position, 1, f"chunk {index} tag"
        )
        tag = tag_bytes[0]
        if tag == 0:
            size, position = _decode_compact_uint(
                payload, position, config.max_size, f"chunk {index} size"
            )
            if size == 0:
                raise ArchiveFormatError(f"MSR2 compact chunk {index} size is invalid")
            digest, position = _take_compact_bytes(
                payload, position, 32, f"chunk {index} digest"
            )
            chunks.append(ChunkRecord(digest, size, index))
            compact_unique_count += 1
        elif tag == 1:
            if index == 0:
                raise ArchiveFormatError("MSR2 compact first chunk cannot be duplicate")
            source, position = _decode_compact_uint(
                payload, position, index - 1, f"chunk {index} source"
            )
            canonical = chunks[source]
            if canonical.source_index != source:
                raise ArchiveFormatError("MSR2 compact duplicate chains are forbidden")
            chunks.append(ChunkRecord(canonical.digest, canonical.size, source))
        else:
            raise ArchiveFormatError(f"MSR2 compact chunk {index} tag is invalid")
    if compact_unique_count != unique_count:
        raise ArchiveFormatError("MSR2 compact unique chunk count is inconsistent")

    packed_size = (unique_count + 3) // 4
    packed, position = _take_compact_bytes(
        payload, position, packed_size, "lane assignments"
    )
    if position != len(payload):
        raise ArchiveFormatError("MSR2 compact metadata contains trailing bytes")
    if unique_count % 4 and packed and packed[-1] >> ((unique_count % 4) * 2):
        raise ArchiveFormatError("MSR2 compact lane assignment padding is nonzero")
    assignments_buffer = bytearray()
    for index in range(unique_count):
        lane = (packed[index // 4] >> ((index % 4) * 2)) & 0x03
        if lane >= _LANE_COUNT:
            raise ArchiveFormatError("MSR2 compact lane assignment is invalid")
        assignments_buffer.append(lane)
    assignments = bytes(assignments_buffer)

    entries: list[DedupEntry] = []
    next_chunk = 0
    for entry_type, relative_path, mode, mtime_ns, count, digest in entry_specs:
        if entry_type == ENTRY_DIRECTORY:
            entries.append(
                DedupEntry(
                    entry_type,
                    relative_path,
                    mode,
                    mtime_ns,
                    0,
                    0,
                    0,
                    ZERO_HASH,
                )
            )
            continue
        end = next_chunk + count
        if end > len(chunks):
            raise ArchiveFormatError("MSR2 compact file chunk range is invalid")
        size = sum(chunk.size for chunk in chunks[next_chunk:end])
        entries.append(
            DedupEntry(
                entry_type,
                relative_path,
                mode,
                mtime_ns,
                size,
                next_chunk,
                count,
                digest,
            )
        )
        next_chunk = end
    if next_chunk != len(chunks):
        raise ArchiveFormatError("MSR2 compact file chunks are unreferenced")

    manifest = DedupManifest(kind, root_name, tuple(entries), tuple(chunks))
    compatibility_header = _metadata_compatibility_header(
        unique_count=unique_count,
        config=config,
        padding_size=padding_size,
        salt=salt,
        nonce_prefix=nonce_prefix,
    )
    manifest = parse_dedup_manifest(
        serialize_dedup_manifest(manifest),
        compatibility_header,
    )
    raw_sizes = [0, 0, 0]
    unique_records = [
        chunk
        for index, chunk in enumerate(manifest.chunks)
        if chunk.source_index == index
    ]
    for chunk, lane in zip(unique_records, assignments, strict=True):
        raw_sizes[lane] += chunk.size
    for raw_size, frame_count in zip(
        raw_sizes, frame_count_values, strict=True
    ):
        if (raw_size == 0) != (frame_count == 0):
            raise ArchiveFormatError("MSR2 compact lane frame count is inconsistent")
    return (
        manifest,
        assignments,
        cast(tuple[int, int, int], tuple(raw_sizes)),
        cast(tuple[int, int, int], tuple(frame_count_values)),
        cast(tuple[int, int, int], tuple(lane_codec_values)),
    )


def _parse_metadata(
    payload: bytes,
    *,
    unique_count: int,
    config: ChunkingConfig,
    padding_size: int,
    salt: bytes,
    nonce_prefix: bytes,
) -> tuple[
    DedupManifest,
    bytes,
    tuple[int, int, int],
    tuple[int, int, int],
    tuple[int, int, int],
]:
    if payload.startswith((_COMPACT_METADATA_MAGIC_V1, _COMPACT_METADATA_MAGIC)):
        return _parse_compact_metadata(
            payload,
            unique_count=unique_count,
            config=config,
            padding_size=padding_size,
            salt=salt,
            nonce_prefix=nonce_prefix,
        )
    required = _METADATA_PREFIX.size + _LANE_COUNT * _LANE_RECORD.size
    if len(payload) < required:
        raise ArchiveFormatError("MSR2 metadata is truncated")
    manifest_size, assignment_count = _METADATA_PREFIX.unpack_from(payload)
    position = _METADATA_PREFIX.size
    raw_sizes: list[int] = []
    frame_counts: list[int] = []
    for _ in range(_LANE_COUNT):
        raw_size, frame_count = _LANE_RECORD.unpack_from(payload, position)
        position += _LANE_RECORD.size
        if (raw_size == 0) != (frame_count == 0):
            raise ArchiveFormatError("MSR2 lane frame count is inconsistent")
        raw_sizes.append(raw_size)
        frame_counts.append(frame_count)
    if assignment_count != unique_count or manifest_size > MAX_MANIFEST_CIPHERTEXT:
        raise ArchiveFormatError("MSR2 metadata counts are inconsistent")
    if manifest_size + assignment_count != len(payload) - position:
        raise ArchiveFormatError("MSR2 metadata length is inconsistent")
    manifest_payload = payload[position : position + manifest_size]
    assignments = payload[position + manifest_size :]
    if any(lane >= _LANE_COUNT for lane in assignments):
        raise ArchiveFormatError("MSR2 lane assignment is invalid")
    compatibility_header = _metadata_compatibility_header(
        unique_count=unique_count,
        config=config,
        padding_size=padding_size,
        salt=salt,
        nonce_prefix=nonce_prefix,
    )
    manifest = parse_dedup_manifest(manifest_payload, compatibility_header)
    unique_records = [
        record
        for index, record in enumerate(manifest.chunks)
        if record.source_index == index
    ]
    if len(unique_records) != unique_count:
        raise ArchiveFormatError("MSR2 unique chunk count is inconsistent")
    calculated = [0, 0, 0]
    for record, lane in zip(unique_records, assignments, strict=True):
        calculated[lane] += record.size
    if calculated != raw_sizes:
        raise ArchiveFormatError("MSR2 lane sizes are inconsistent")
    return (
        manifest,
        assignments,
        cast(tuple[int, int, int], tuple(raw_sizes)),
        cast(tuple[int, int, int], tuple(frame_counts)),
        (_LANE_CODEC_LZMA2, _LANE_CODEC_LZMA2, _LANE_CODEC_LZMA2),
    )


def _restore(
    manifest: DedupManifest,
    canonical: BinaryIO,
    locations: dict[int, tuple[int, int]],
    destination: Path,
    opened_archive: os.stat_result,
) -> None:
    if manifest.kind == KIND_FOLDER:
        if destination.exists():
            raise FileExistsError(f"folder destination already exists: {destination}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary_root = Path(
            tempfile.mkdtemp(prefix=f".{destination.name}.", dir=destination.parent)
        )
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "wb", dir=destination.parent, prefix=f".{destination.name}.", delete=False
        ) as handle:
            temporary_root = Path(handle.name)
    try:
        for entry in manifest.entries:
            target = (
                temporary_root
                if manifest.kind == KIND_FILE
                else temporary_root.joinpath(*entry.relative_path.split("/"))
            )
            if entry.entry_type == ENTRY_DIRECTORY:
                target.mkdir(parents=True, exist_ok=False)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            with target.open("wb") as output:
                for record in manifest.chunks[
                    entry.first_chunk : entry.first_chunk + entry.chunk_count
                ]:
                    offset, size = locations[record.source_index]
                    canonical.seek(offset)
                    chunk = _read_exact(canonical, size, "canonical chunk")
                    output.write(chunk)
                    digest.update(chunk)
            if digest.digest() != entry.digest:
                raise IntegrityError(f"MSR2 file digest failed: {entry.relative_path}")
            _apply_metadata(target, entry)
        if manifest.kind == KIND_FOLDER:
            directories = (
                entry for entry in manifest.entries if entry.entry_type == ENTRY_DIRECTORY
            )
            for entry in sorted(
                directories,
                key=lambda item: item.relative_path.count("/"),
                reverse=True,
            ):
                _apply_metadata(
                    temporary_root.joinpath(*entry.relative_path.split("/")),
                    entry,
                )
        if path_matches_file_identity(destination, opened_archive):
            raise ValueError("archive and output paths must be different")
        os.replace(temporary_root, destination)
    except Exception:
        if temporary_root.exists():
            if manifest.kind == KIND_FOLDER:
                shutil.rmtree(temporary_root)
            else:
                temporary_root.unlink(missing_ok=True)
        raise


def decode_solid_archive_v2(
    archive_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    password: str | bytes,
    *,
    max_output_size: int = DEFAULT_MAX_OUTPUT_SIZE,
    max_frame_count: int = DEFAULT_MAX_FRAME_COUNT,
) -> SolidArchiveV2DecodeStats:
    """Authenticate, disk-spool, and atomically restore an MSR2 archive."""
    if max_output_size < 0 or max_frame_count <= 0:
        raise ValueError("MSR2 decode limits must be positive")
    started = time.perf_counter()
    archive, destination = Path(archive_path), Path(output_path)
    if archive.resolve() == destination.resolve():
        raise ValueError("archive and output paths must be different")
    with archive.open("rb") as raw:
        opened_archive = os.fstat(raw.fileno())
        if path_matches_file_identity(destination, opened_archive):
            raise ValueError("archive and output paths must be different")
        stream = cast(BinaryIO, raw)
        serialized_header, header = _read_header(stream)
        config = ChunkingConfig(
            header.min_chunk_size,
            header.avg_chunk_size,
            header.max_chunk_size,
        )
        key = derive_key(password, header.salt, log_n=header.kdf_log_n, r=8, p=1)
        metadata_ciphertext = _read_exact(
            stream, header.metadata_ciphertext_length, "metadata ciphertext"
        )
        metadata = unpad_payload(
            decrypt(
                key,
                frame_nonce(header.nonce_prefix, 0),
                metadata_ciphertext,
                serialized_header,
            )
        )
        raw_metadata, raw_lzma2 = _decode_metadata_envelope(metadata)
        manifest, assignments, raw_sizes, frame_counts, lane_codecs = _parse_metadata(
            raw_metadata,
            unique_count=header.unique_chunk_count,
            config=config,
            padding_size=header.padding_size,
            salt=header.salt,
            nonce_prefix=header.nonce_prefix,
        )
        total_output_size = sum(entry.size for entry in manifest.entries)
        total_frame_count = sum(frame_counts)
        if total_output_size > max_output_size:
            raise ArchiveFormatError("MSR2 restored size exceeds the decode limit")
        if total_frame_count > max_frame_count:
            raise ArchiveFormatError("MSR2 frame count exceeds the decode limit")
        frame_aad = serialized_header + hashlib.sha256(metadata_ciphertext).digest()

        with tempfile.TemporaryDirectory(prefix=f".{destination.name}.decode.") as spool_dir:
            lane_paths = tuple(Path(spool_dir) / f"lane-{lane}" for lane in range(_LANE_COUNT))
            index = 1
            for lane, path in enumerate(lane_paths):
                if frame_counts[lane] == 0:
                    path.touch()
                    continue
                with path.open("w+b") as lane_output:
                    stats = read_solid_lane_frames(
                        stream,
                        lane_output,
                        key=key,
                        nonce_prefix=header.nonce_prefix,
                        associated_data=frame_aad,
                        lane=lane,
                        start_index=index,
                        frame_count=frame_counts[lane],
                        expected_size=raw_sizes[lane],
                        frame_payload_size=header.frame_payload_size,
                        padding_size=header.padding_size,
                        raw_lzma2=raw_lzma2,
                        passthrough=lane_codecs[lane] == _LANE_CODEC_RAW,
                    )
                index = stats.next_index
            if stream.read(1):
                raise ArchiveFormatError("MSR2 archive has trailing data")

            unique_records = [
                (index, record)
                for index, record in enumerate(manifest.chunks)
                if record.source_index == index
            ]
            lane_inputs = tuple(path.open("rb") for path in lane_paths)
            canonical_path = Path(spool_dir) / "canonical"
            locations: dict[int, tuple[int, int]] = {}
            try:
                with canonical_path.open("w+b") as canonical:
                    for (source_index, record), lane in zip(
                        unique_records, assignments, strict=True
                    ):
                        chunk = _read_exact(
                            lane_inputs[lane], record.size, "decoded solid lane"
                        )
                        if hashlib.sha256(chunk).digest() != record.digest:
                            raise IntegrityError("MSR2 unique chunk digest failed")
                        offset = canonical.tell()
                        canonical.write(chunk)
                        locations[source_index] = (offset, len(chunk))
                    if any(lane.read(1) for lane in lane_inputs):
                        raise ArchiveFormatError("MSR2 lane contains unreferenced bytes")
                    canonical.flush()
                    _restore(
                        manifest,
                        canonical,
                        locations,
                        destination,
                        opened_archive,
                    )
            finally:
                for lane_input in lane_inputs:
                    lane_input.close()

    return SolidArchiveV2DecodeStats(
        "MSR2",
        sum(entry.size for entry in manifest.entries),
        opened_archive.st_size,
        header.unique_chunk_count,
        True,
        time.perf_counter() - started,
    )


def inspect_solid_archive_v2(
    archive_path: str | os.PathLike[str],
    password: str | bytes,
    *,
    max_output_size: int = DEFAULT_MAX_OUTPUT_SIZE,
    max_frame_count: int = DEFAULT_MAX_FRAME_COUNT,
) -> SolidArchiveV2DecodeStats:
    """Fully authenticate and hash-check MSR2 without retaining restored output."""
    with tempfile.TemporaryDirectory(prefix="mosaic-msr2-inspect.") as temp_dir:
        return decode_solid_archive_v2(
            archive_path,
            Path(temp_dir) / "restored",
            password,
            max_output_size=max_output_size,
            max_frame_count=max_frame_count,
        )
