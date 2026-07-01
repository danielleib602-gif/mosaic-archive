"""Disk-backed streaming MSR2 solid archive experiment."""

from __future__ import annotations

import hashlib
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
    DedupManifest,
    _apply_metadata,
    _scan_manifest,
    parse_dedup_manifest,
    serialize_dedup_manifest,
)
from mosaic_archive.dedup_format import MSC3_FLAGS, MSC6_VERSION, Msc3Header
from mosaic_archive.exceptions import ArchiveFormatError, IntegrityError
from mosaic_archive.padding import pad_payload, unpad_payload
from mosaic_archive.solid_frames import (
    compress_solid_lane,
    read_solid_lane_frames,
    write_precompressed_solid_lane_frames,
)
from mosaic_archive.solid_research import choose_solid_lane
from mosaic_archive.stream_archive import ENTRY_DIRECTORY, KIND_FILE, KIND_FOLDER
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
DEFAULT_MAX_OUTPUT_SIZE: Final = 1024 * 1024 * 1024 * 1024
DEFAULT_MAX_FRAME_COUNT: Final = 1_000_000


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
        decoded += decoder.flush()
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
    if not 14 <= kdf_log_n <= 18:
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
        compressed_sizes: list[int] = []
        frame_count_values: list[int] = []
        for lane, (raw_path, compressed_path) in enumerate(
            zip(lane_paths, compressed_paths, strict=True)
        ):
            if raw_sizes[lane] == 0:
                compressed_path.touch()
                compressed_sizes.append(0)
                frame_count_values.append(0)
                continue
            with raw_path.open("rb") as lane_source, compressed_path.open(
                "wb"
            ) as compressed_output:
                compressed_size = compress_solid_lane(
                    lane_source,
                    compressed_output,
                    lane=lane,
                    raw_lzma2=True,
                )
            compressed_sizes.append(compressed_size)
            frame_count_values.append(
                (compressed_size + frame_payload_size - 1) // frame_payload_size
            )
        frame_counts = cast(tuple[int, int, int], tuple(frame_count_values))
        metadata = _encode_metadata_envelope(
            _metadata(manifest, assignments, raw_sizes, frame_counts)
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
                for lane, path in enumerate(compressed_paths):
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


def _parse_metadata(
    payload: bytes,
    *,
    unique_count: int,
    config: ChunkingConfig,
    padding_size: int,
    salt: bytes,
    nonce_prefix: bytes,
) -> tuple[DedupManifest, bytes, tuple[int, int, int], tuple[int, int, int]]:
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
    compatibility_header = Msc3Header(
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
    )


def _restore(
    manifest: DedupManifest,
    canonical: BinaryIO,
    locations: dict[int, tuple[int, int]],
    destination: Path,
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
    with archive.open("rb") as raw:
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
        manifest, assignments, raw_sizes, frame_counts = _parse_metadata(
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
                    _restore(manifest, canonical, locations, destination)
            finally:
                for lane_input in lane_inputs:
                    lane_input.close()

    return SolidArchiveV2DecodeStats(
        "MSR2",
        sum(entry.size for entry in manifest.entries),
        archive.stat().st_size,
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
