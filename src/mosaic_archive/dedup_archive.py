"""MSC3 content-defined chunking and direct backward-reference deduplication."""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import struct
import tempfile
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, cast

from mosaic_archive.cdc import ChunkingConfig, iter_content_defined_chunks
from mosaic_archive.container_format import AEAD_CHACHA20_POLY1305, KDF_SCRYPT
from mosaic_archive.crypto import AEAD_TAG_LENGTH, SALT_LENGTH, decrypt, derive_key, encrypt
from mosaic_archive.dedup_format import (
    MSC3_FLAGS,
    MSC3_HEADER,
    MSC6_VERSION,
    Msc3Header,
    parse_msc3_header,
)
from mosaic_archive.exceptions import ArchiveFormatError, IntegrityError
from mosaic_archive.features import BlockFeatures, analyze_block
from mosaic_archive.modes import choose_routed_mode, get_mode
from mosaic_archive.padding import pad_payload, unpad_payload
from mosaic_archive.paths import validate_relative_path
from mosaic_archive.stream_archive import (
    ENTRY_DIRECTORY,
    ENTRY_FILE,
    KIND_FILE,
    KIND_FOLDER,
    ProgressCallback,
    ProgressEvent,
    scan_input,
)
from mosaic_archive.stream_format import (
    FRAME_DATA,
    FRAME_HEADER,
    FRAME_MANIFEST,
    MAX_MANIFEST_CIPHERTEXT,
    FrameHeader,
    frame_nonce,
    parse_frame_header,
)

MANIFEST_MAGIC = b"M3MF"
MANIFEST_PREFIX = struct.Struct(">4sBHIQ")
ENTRY_FIXED = struct.Struct(">BHIqQQI32s")
CHUNK_RECORD = struct.Struct(">32sIQ")
DATA_PREFIX = struct.Struct(">QIB")
MAX_CHUNK_RECORDS = 16_777_215
ZERO_HASH = b"\x00" * 32


@dataclass(frozen=True, slots=True)
class ChunkRecord:
    digest: bytes
    size: int
    source_index: int


@dataclass(frozen=True, slots=True)
class DedupEntry:
    entry_type: int
    relative_path: str
    mode: int
    mtime_ns: int
    size: int
    first_chunk: int
    chunk_count: int
    digest: bytes


@dataclass(frozen=True, slots=True)
class DedupManifest:
    kind: int
    root_name: str
    entries: tuple[DedupEntry, ...]
    chunks: tuple[ChunkRecord, ...]


@dataclass(frozen=True, slots=True)
class DedupEncodeStats:
    format_version: int
    archive_kind: str
    original_size: int
    compressed_size: int
    padded_plaintext_size: int
    archive_size: int
    padding_overhead: int
    block_count: int
    file_count: int
    directory_count: int
    mode_distribution: dict[str, int]
    duplicate_blocks: int
    average_features: dict[str, float]
    logical_chunk_count: int
    unique_chunk_count: int
    duplicate_chunk_count: int
    cross_file_duplicate_chunks: int
    dedup_saved_bytes: int
    cross_file_dedup_saved_bytes: int
    elapsed_seconds: float


@dataclass(frozen=True, slots=True)
class DedupDecodeStats:
    format_version: int
    archive_kind: str
    original_size: int
    block_count: int
    file_count: int
    directory_count: int
    mode_distribution: dict[str, int]
    logical_chunk_count: int
    unique_chunk_count: int
    duplicate_chunk_count: int
    dedup_saved_bytes: int
    cross_file_duplicate_chunks: int
    cross_file_dedup_saved_bytes: int
    hash_verified: bool
    elapsed_seconds: float


@dataclass(frozen=True, slots=True)
class DedupArchiveInfo:
    format_version: int
    archive_kind: str
    root_name: str
    original_size: int
    compressed_size: int
    padded_plaintext_size: int
    archive_size: int
    padding_overhead: int
    chunk_size: int
    min_chunk_size: int
    max_chunk_size: int
    block_count: int
    file_count: int
    directory_count: int
    mode_distribution: dict[str, int]
    logical_chunk_count: int
    unique_chunk_count: int
    duplicate_chunk_count: int
    dedup_saved_bytes: int
    cross_file_duplicate_chunks: int
    cross_file_dedup_saved_bytes: int
    metadata_encrypted: bool
    hash_verified: bool


class _NullWriter:
    def write(self, data: bytes) -> int:
        return len(data)

    def close(self) -> None:
        pass


def _read_exact(stream: BinaryIO, size: int, description: str) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise ArchiveFormatError(f"MSC3 is truncated at {description}")
    return data


def serialize_dedup_manifest(manifest: DedupManifest) -> bytes:
    root = manifest.root_name.encode("utf-8")
    output = io.BytesIO()
    output.write(
        MANIFEST_PREFIX.pack(
            MANIFEST_MAGIC, manifest.kind, len(root), len(manifest.entries), len(manifest.chunks)
        )
    )
    output.write(root)
    for entry in manifest.entries:
        path = entry.relative_path.encode("utf-8")
        output.write(
            ENTRY_FIXED.pack(
                entry.entry_type,
                len(path),
                entry.mode,
                entry.mtime_ns,
                entry.size,
                entry.first_chunk,
                entry.chunk_count,
                entry.digest,
            )
        )
        output.write(path)
    for chunk in manifest.chunks:
        output.write(CHUNK_RECORD.pack(chunk.digest, chunk.size, chunk.source_index))
    return output.getvalue()


def parse_dedup_manifest(data: bytes, header: Msc3Header) -> DedupManifest:
    stream = io.BytesIO(data)
    magic, kind, root_length, entry_count, chunk_count = MANIFEST_PREFIX.unpack(
        _read_exact(stream, MANIFEST_PREFIX.size, "manifest prefix")
    )
    if magic != MANIFEST_MAGIC or kind not in {KIND_FILE, KIND_FOLDER}:
        raise ArchiveFormatError("MSC3 manifest prefix is invalid")
    if entry_count > 1_000_000 or chunk_count > MAX_CHUNK_RECORDS:
        raise ArchiveFormatError("MSC3 manifest exceeds entry or chunk limits")
    try:
        raw_root = _read_exact(stream, root_length, "root name").decode("utf-8")
        root_name = validate_relative_path(raw_root)
    except (UnicodeDecodeError, ValueError) as error:
        raise ArchiveFormatError("MSC3 root name is invalid") from error
    if raw_root != root_name or "/" in root_name:
        raise ArchiveFormatError("MSC3 root name is not canonical")

    entries: list[DedupEntry] = []
    collisions: set[str] = set()
    next_chunk = 0
    for index in range(entry_count):
        values = ENTRY_FIXED.unpack(_read_exact(stream, ENTRY_FIXED.size, f"entry {index}"))
        entry_type, path_length, mode, mtime_ns, size, first_chunk, count, digest = values
        if entry_type not in {ENTRY_FILE, ENTRY_DIRECTORY} or mode > 0o777:
            raise ArchiveFormatError(f"MSC3 entry {index} metadata is invalid")
        try:
            raw_path = _read_exact(stream, path_length, f"entry {index} path").decode("utf-8")
            relative = validate_relative_path(raw_path)
        except (UnicodeDecodeError, ValueError) as error:
            raise ArchiveFormatError(f"MSC3 entry {index} path is unsafe") from error
        if raw_path != relative or relative.casefold() in collisions:
            raise ArchiveFormatError("MSC3 manifest has a noncanonical path collision")
        collisions.add(relative.casefold())
        if entry_type == ENTRY_DIRECTORY:
            if size or first_chunk or count or digest != ZERO_HASH:
                raise ArchiveFormatError(f"MSC3 directory entry {index} is malformed")
        else:
            if first_chunk != next_chunk or (size == 0) != (count == 0):
                raise ArchiveFormatError(f"MSC3 file entry {index} chunk range is invalid")
            next_chunk += count
        entries.append(
            DedupEntry(entry_type, relative, mode, mtime_ns, size, first_chunk, count, digest)
        )
    if next_chunk != chunk_count:
        raise ArchiveFormatError("MSC3 file chunk ranges do not cover the chunk table")

    chunks: list[ChunkRecord] = []
    unique_count = 0
    for index in range(chunk_count):
        digest, size, source = CHUNK_RECORD.unpack(
            _read_exact(stream, CHUNK_RECORD.size, f"chunk {index}")
        )
        if not 1 <= size <= header.max_chunk_size:
            raise ArchiveFormatError(f"MSC3 chunk {index} has an invalid size")
        if source == index:
            unique_count += 1
        else:
            if source >= index:
                raise ArchiveFormatError("MSC3 dedup references must point backward")
            canonical = chunks[source]
            if canonical.source_index != source:
                raise ArchiveFormatError("MSC3 dedup reference chains are forbidden")
            if canonical.digest != digest or canonical.size != size:
                raise ArchiveFormatError("MSC3 dedup reference metadata is inconsistent")
        chunks.append(ChunkRecord(digest, size, source))

    if stream.read(1):
        raise ArchiveFormatError("MSC3 manifest contains trailing bytes")
    if unique_count + 1 != header.frame_count:
        raise ArchiveFormatError("MSC3 unique chunks do not match the public frame count")
    for entry in entries:
        if entry.entry_type == ENTRY_FILE:
            total = sum(
                chunk.size
                for chunk in chunks[entry.first_chunk : entry.first_chunk + entry.chunk_count]
            )
            if total != entry.size:
                raise ArchiveFormatError("MSC3 chunk sizes do not match their file size")
    if kind == KIND_FILE and (
        len(entries) != 1
        or entries[0].entry_type != ENTRY_FILE
        or entries[0].relative_path != root_name
    ):
        raise ArchiveFormatError("MSC3 single-file manifest is malformed")
    if kind == KIND_FOLDER:
        directories = {
            entry.relative_path
            for entry in entries
            if entry.entry_type == ENTRY_DIRECTORY
        }
        for entry in entries:
            parent = Path(entry.relative_path).parent.as_posix()
            if parent != "." and parent not in directories:
                raise ArchiveFormatError("MSC3 manifest omits a required parent directory")
    return DedupManifest(kind, root_name, tuple(entries), tuple(chunks))


def _source_path(source: Path, manifest_kind: int, relative: str) -> Path:
    return source if manifest_kind == KIND_FILE else source.joinpath(*relative.split("/"))


def _scan_manifest(
    source: Path,
    config: ChunkingConfig,
    *,
    on_unique_chunk: Callable[[bytes], None] | None = None,
) -> tuple[DedupManifest, list[int]]:
    base = scan_input(source, config.max_size)
    chunks: list[ChunkRecord] = []
    entries: list[DedupEntry] = []
    canonical: dict[tuple[bytes, int], int] = {}
    owners: list[int] = []
    for file_index, entry in enumerate(base.entries):
        if entry.entry_type == ENTRY_DIRECTORY:
            entries.append(
                DedupEntry(
                    entry.entry_type,
                    entry.relative_path,
                    entry.mode,
                    entry.mtime_ns,
                    0,
                    0,
                    0,
                    ZERO_HASH,
                )
            )
            continue
        first = len(chunks)
        path = _source_path(source, base.kind, entry.relative_path)
        file_digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter_content_defined_chunks(stream, config):
                file_digest.update(chunk)
                digest = hashlib.sha256(chunk).digest()
                key = (digest, len(chunk))
                source_index = canonical.setdefault(key, len(chunks))
                if source_index == len(chunks) and on_unique_chunk is not None:
                    on_unique_chunk(chunk)
                chunks.append(ChunkRecord(digest, len(chunk), source_index))
                owners.append(file_index)
        if file_digest.digest() != entry.digest:
            raise OSError(f"input changed while content-defined chunks were scanned: {path}")
        entries.append(
            DedupEntry(
                entry.entry_type,
                entry.relative_path,
                entry.mode,
                entry.mtime_ns,
                entry.size,
                first,
                len(chunks) - first,
                entry.digest,
            )
        )
    return DedupManifest(base.kind, base.root_name, tuple(entries), tuple(chunks)), owners


def _write_frame(
    output: BinaryIO,
    index: int,
    frame_type: int,
    payload: bytes,
    key: bytes,
    global_header: bytes,
    header: Msc3Header,
) -> tuple[int, int, int]:
    padded = pad_payload(payload, header.padding_size)
    frame = FrameHeader(index, frame_type, len(padded) + AEAD_TAG_LENGTH)
    frame_bytes = frame.pack()
    ciphertext = encrypt(
        key,
        frame_nonce(header.nonce_prefix, index),
        padded,
        global_header + frame_bytes,
    )
    output.write(frame_bytes)
    output.write(ciphertext)
    return len(payload), len(padded), len(padded) - 8 - len(payload)


def _read_frame(
    stream: BinaryIO,
    index: int,
    frame_type: int,
    key: bytes,
    global_header: bytes,
    header: Msc3Header,
) -> tuple[bytes, int]:
    frame_bytes = _read_exact(stream, FRAME_HEADER.size, f"frame {index} header")
    frame = parse_frame_header(frame_bytes)
    if frame.index != index or frame.frame_type != frame_type:
        raise ArchiveFormatError(f"MSC3 frame {index} is out of order")
    if (frame.ciphertext_length - AEAD_TAG_LENGTH) % header.padding_size:
        raise ArchiveFormatError(f"MSC3 frame {index} violates its padding policy")
    maximum = (
        MAX_MANIFEST_CIPHERTEXT
        if frame_type == FRAME_MANIFEST
        else header.max_chunk_size + header.padding_size + DATA_PREFIX.size + 32
    )
    if frame.ciphertext_length > maximum:
        raise ArchiveFormatError(f"MSC3 frame {index} exceeds its resource limit")
    ciphertext = _read_exact(stream, frame.ciphertext_length, f"frame {index} ciphertext")
    padded = decrypt(
        key,
        frame_nonce(header.nonce_prefix, index),
        ciphertext,
        global_header + frame_bytes,
    )
    return unpad_payload(padded), len(padded)


def _averages(features: list[BlockFeatures]) -> dict[str, float]:
    names = (
        "entropy_bits_per_byte",
        "byte_repetition_ratio",
        "substring_repetition_ratio",
        "delta_smoothness_ratio",
        "ascii_ratio",
        "zero_ratio",
        "small_symbol_ratio",
    )
    if not features:
        return {name: 0.0 for name in names} | {"random_looking_ratio": 0.0}
    return {
        **{
            name: sum(getattr(feature, name) for feature in features) / len(features)
            for name in names
        },
        "random_looking_ratio": sum(item.random_looking for item in features)
        / len(features),
    }


def encode_dedup_archive(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    password: str | bytes,
    *,
    config: ChunkingConfig,
    padding_size: int = 4096,
    kdf_log_n: int = 15,
    profile: str = "balanced",
    progress: ProgressCallback | None = None,
) -> DedupEncodeStats:
    started = time.perf_counter()
    source, destination = Path(input_path), Path(output_path)
    if source.resolve() == destination.resolve():
        raise ValueError("input and output paths must be different")
    if source.is_dir() and destination.resolve().is_relative_to(source.resolve()):
        raise ValueError("folder archives must be written outside the input tree")
    if not 256 <= padding_size <= 16 * 1024 * 1024 or not 14 <= kdf_log_n <= 18:
        raise ValueError("padding or scrypt cost is outside supported limits")
    if profile not in {"fast", "balanced", "research"}:
        raise ValueError(f"unknown compression profile: {profile}")
    manifest, owners = _scan_manifest(source, config)
    unique = sum(chunk.source_index == index for index, chunk in enumerate(manifest.chunks))
    if unique + 1 > 16_777_216:
        raise ValueError("input produces too many unique MSC3 chunks")
    salt, nonce_prefix = os.urandom(SALT_LENGTH), os.urandom(4)
    header = Msc3Header(
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
        kdf_log_n,
        8,
        1,
        unique + 1,
    )
    global_header = header.pack()
    key = derive_key(password, salt, log_n=kdf_log_n, r=8, p=1)
    manifest_payload = serialize_dedup_manifest(manifest)
    if len(manifest_payload) > MAX_MANIFEST_CIPHERTEXT - padding_size - AEAD_TAG_LENGTH:
        raise ValueError("MSC3 manifest exceeds its resource limit")

    files = sum(entry.entry_type == ENTRY_FILE for entry in manifest.entries)
    original_size = sum(entry.size for entry in manifest.entries)
    distribution: Counter[str] = Counter()
    features: list[BlockFeatures] = []
    compressed = padded_total = padding_overhead = 0
    completed_bytes = completed_files = occurrence = 0
    frame_index = 0
    if progress:
        progress(ProgressEvent("encode", 0, original_size, 0, files))

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w+b", dir=destination.parent, prefix=f".{destination.name}.", delete=False
        ) as temporary:
            temporary_name = temporary.name
            output = cast(BinaryIO, temporary)
            output.write(global_header)
            metrics = _write_frame(
                output, 0, FRAME_MANIFEST, manifest_payload, key, global_header, header
            )
            compressed += metrics[0]
            padded_total += metrics[1]
            padding_overhead += metrics[2]
            frame_index = 1
            for entry in manifest.entries:
                if entry.entry_type != ENTRY_FILE:
                    continue
                path = _source_path(source, manifest.kind, entry.relative_path)
                digest = hashlib.sha256()
                with path.open("rb") as stream:
                    for chunk in iter_content_defined_chunks(stream, config):
                        record = manifest.chunks[occurrence]
                        actual_digest = hashlib.sha256(chunk).digest()
                        if len(chunk) != record.size or actual_digest != record.digest:
                            raise OSError(f"input changed while it was encoded: {path}")
                        digest.update(chunk)
                        if record.source_index == occurrence:
                            selected = choose_routed_mode(chunk, profile=profile)
                            distribution[selected.mode.name] += 1
                            features.append(analyze_block(chunk))
                            payload = DATA_PREFIX.pack(
                                occurrence, len(chunk), int(selected.mode.id)
                            ) + selected.payload
                            metrics = _write_frame(
                                output,
                                frame_index,
                                FRAME_DATA,
                                payload,
                                key,
                                global_header,
                                header,
                            )
                            compressed += metrics[0]
                            padded_total += metrics[1]
                            padding_overhead += metrics[2]
                            frame_index += 1
                        occurrence += 1
                        completed_bytes += len(chunk)
                        if progress:
                            progress(
                                ProgressEvent(
                                    "encode",
                                    completed_bytes,
                                    original_size,
                                    completed_files,
                                    files,
                                )
                            )
                if digest.digest() != entry.digest:
                    raise OSError(f"input changed while it was encoded: {path}")
                completed_files += 1
                if progress:
                    progress(
                        ProgressEvent(
                            "encode",
                            completed_bytes,
                            original_size,
                            completed_files,
                            files,
                        )
                    )
            output.flush()
            os.fsync(output.fileno())
        if occurrence != len(manifest.chunks) or frame_index != header.frame_count:
            raise RuntimeError("internal MSC3 occurrence/frame mismatch")
        os.replace(temporary_name, destination)
        temporary_name = None
    finally:
        if temporary_name:
            Path(temporary_name).unlink(missing_ok=True)

    duplicate_indexes = [
        index for index, chunk in enumerate(manifest.chunks) if chunk.source_index != index
    ]
    cross_indexes = [
        index
        for index in duplicate_indexes
        if owners[index] != owners[manifest.chunks[index].source_index]
    ]
    return DedupEncodeStats(
        MSC6_VERSION,
        "file" if manifest.kind == KIND_FILE else "folder",
        original_size,
        compressed,
        padded_total,
        destination.stat().st_size,
        padding_overhead,
        unique,
        files,
        sum(entry.entry_type == ENTRY_DIRECTORY for entry in manifest.entries),
        dict(sorted(distribution.items())),
        len(duplicate_indexes),
        _averages(features),
        len(manifest.chunks),
        unique,
        len(duplicate_indexes),
        len(cross_indexes),
        sum(manifest.chunks[index].size for index in duplicate_indexes),
        sum(manifest.chunks[index].size for index in cross_indexes),
        time.perf_counter() - started,
    )


def _apply_metadata(path: Path, entry: DedupEntry) -> None:
    os.chmod(path, entry.mode)
    os.utime(path, ns=(entry.mtime_ns, entry.mtime_ns))


def _target(root: Path | None, manifest: DedupManifest, entry: DedupEntry) -> Path | None:
    if root is None:
        return None
    return root if manifest.kind == KIND_FILE else root.joinpath(*entry.relative_path.split("/"))


def _decode(
    archive: Path,
    password: str | bytes,
    destination: Path | None,
    progress: ProgressCallback | None,
) -> tuple[DedupDecodeStats, DedupArchiveInfo]:
    started = time.perf_counter()
    archive_size = archive.stat().st_size
    temporary_root: Path | None = None
    with archive.open("rb") as raw, tempfile.TemporaryDirectory(
        prefix="msc3-chunk-cache-"
    ) as cache_name:
        stream = cast(BinaryIO, raw)
        global_header = _read_exact(stream, MSC3_HEADER.size, "public header")
        header = parse_msc3_header(global_header)
        key = derive_key(password, header.salt, log_n=header.kdf_log_n, r=8, p=1)
        manifest_payload, manifest_padded = _read_frame(
            stream, 0, FRAME_MANIFEST, key, global_header, header
        )
        manifest = parse_dedup_manifest(manifest_payload, header)
        if destination is None:
            output_root = None
        elif manifest.kind == KIND_FOLDER:
            if destination.exists():
                raise FileExistsError(f"folder destination already exists: {destination}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary_root = Path(
                tempfile.mkdtemp(prefix=f".{destination.name}.", dir=destination.parent)
            )
            output_root = temporary_root
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                "wb", dir=destination.parent, prefix=f".{destination.name}.", delete=False
            ) as temporary:
                temporary_root = Path(temporary.name)
            output_root = temporary_root

        cache = Path(cache_name)
        referenced = {
            chunk.source_index
            for index, chunk in enumerate(manifest.chunks)
            if chunk.source_index != index
        }
        distribution: Counter[str] = Counter()
        frame_index = 1
        compressed, padded_total = len(manifest_payload), manifest_padded
        completed_bytes = completed_files = 0
        total_size = sum(entry.size for entry in manifest.entries)
        file_count = sum(entry.entry_type == ENTRY_FILE for entry in manifest.entries)
        if progress:
            progress(ProgressEvent("decode", 0, total_size, 0, file_count))
        try:
            for entry in manifest.entries:
                target = _target(output_root, manifest, entry)
                if entry.entry_type == ENTRY_DIRECTORY:
                    if target:
                        target.mkdir(parents=True, exist_ok=False)
                    continue
                if target and manifest.kind == KIND_FOLDER:
                    target.parent.mkdir(parents=True, exist_ok=True)
                sink: BinaryIO = (
                    cast(BinaryIO, _NullWriter()) if target is None else target.open("wb")
                )
                digest = hashlib.sha256()
                try:
                    for occurrence in range(
                        entry.first_chunk, entry.first_chunk + entry.chunk_count
                    ):
                        record = manifest.chunks[occurrence]
                        if record.source_index == occurrence:
                            payload, padded = _read_frame(
                                stream,
                                frame_index,
                                FRAME_DATA,
                                key,
                                global_header,
                                header,
                            )
                            compressed += len(payload)
                            padded_total += padded
                            if len(payload) < DATA_PREFIX.size:
                                raise ArchiveFormatError("MSC3 data frame is truncated")
                            actual_index, size, mode_id = DATA_PREFIX.unpack_from(payload)
                            if actual_index != occurrence or size != record.size:
                                raise ArchiveFormatError("MSC3 data frame metadata is inconsistent")
                            mode = get_mode(mode_id)
                            chunk = mode.decode(payload[DATA_PREFIX.size :], size)
                            distribution[mode.name] += 1
                            frame_index += 1
                            if hashlib.sha256(chunk).digest() != record.digest:
                                raise IntegrityError("MSC3 unique chunk digest failed")
                            if occurrence in referenced:
                                (cache / f"{occurrence:016x}").write_bytes(chunk)
                        else:
                            chunk = (cache / f"{record.source_index:016x}").read_bytes()
                        sink.write(chunk)
                        digest.update(chunk)
                        completed_bytes += len(chunk)
                        if progress:
                            progress(
                                ProgressEvent(
                                    "decode",
                                    completed_bytes,
                                    total_size,
                                    completed_files,
                                    file_count,
                                )
                            )
                finally:
                    sink.close()
                if digest.digest() != entry.digest:
                    raise IntegrityError(f"MSC3 file digest failed: {entry.relative_path}")
                if target:
                    _apply_metadata(target, entry)
                completed_files += 1
                if progress:
                    progress(
                        ProgressEvent(
                            "decode",
                            completed_bytes,
                            total_size,
                            completed_files,
                            file_count,
                        )
                    )
            if frame_index != header.frame_count or stream.read(1):
                raise ArchiveFormatError("MSC3 frame count or archive termination is invalid")
            if output_root and manifest.kind == KIND_FOLDER:
                for entry in sorted(
                    (item for item in manifest.entries if item.entry_type == ENTRY_DIRECTORY),
                    key=lambda item: item.relative_path.count("/"),
                    reverse=True,
                ):
                    target = _target(output_root, manifest, entry)
                    if target:
                        _apply_metadata(target, entry)
            if destination and temporary_root:
                os.replace(temporary_root, destination)
                temporary_root = None
        finally:
            if temporary_root and temporary_root.exists():
                if manifest.kind == KIND_FOLDER:
                    shutil.rmtree(temporary_root)
                else:
                    temporary_root.unlink(missing_ok=True)

    unique = header.frame_count - 1
    duplicates = len(manifest.chunks) - unique
    saved = sum(
        chunk.size
        for index, chunk in enumerate(manifest.chunks)
        if chunk.source_index != index
    )
    owners = [0] * len(manifest.chunks)
    for entry_index, entry in enumerate(manifest.entries):
        if entry.entry_type == ENTRY_FILE:
            for occurrence in range(
                entry.first_chunk, entry.first_chunk + entry.chunk_count
            ):
                owners[occurrence] = entry_index
    cross_file_indexes = [
        index
        for index, chunk in enumerate(manifest.chunks)
        if chunk.source_index != index and owners[index] != owners[chunk.source_index]
    ]
    cross_file_saved = sum(manifest.chunks[index].size for index in cross_file_indexes)
    kind = "file" if manifest.kind == KIND_FILE else "folder"
    original_size = sum(entry.size for entry in manifest.entries)
    directory_count = sum(
        entry.entry_type == ENTRY_DIRECTORY for entry in manifest.entries
    )
    mode_distribution = dict(sorted(distribution.items()))
    stats = DedupDecodeStats(
        format_version=header.version,
        archive_kind=kind,
        original_size=original_size,
        block_count=unique,
        file_count=file_count,
        directory_count=directory_count,
        mode_distribution=mode_distribution,
        logical_chunk_count=len(manifest.chunks),
        unique_chunk_count=unique,
        duplicate_chunk_count=duplicates,
        dedup_saved_bytes=saved,
        cross_file_duplicate_chunks=len(cross_file_indexes),
        cross_file_dedup_saved_bytes=cross_file_saved,
        hash_verified=True,
        elapsed_seconds=time.perf_counter() - started,
    )
    info = DedupArchiveInfo(
        format_version=header.version,
        archive_kind=kind,
        root_name=manifest.root_name,
        original_size=original_size,
        compressed_size=compressed,
        padded_plaintext_size=padded_total,
        archive_size=archive_size,
        padding_overhead=padded_total - 8 * header.frame_count - compressed,
        chunk_size=header.avg_chunk_size,
        min_chunk_size=header.min_chunk_size,
        max_chunk_size=header.max_chunk_size,
        block_count=unique,
        file_count=file_count,
        directory_count=directory_count,
        mode_distribution=mode_distribution,
        logical_chunk_count=len(manifest.chunks),
        unique_chunk_count=unique,
        duplicate_chunk_count=duplicates,
        dedup_saved_bytes=saved,
        cross_file_duplicate_chunks=len(cross_file_indexes),
        cross_file_dedup_saved_bytes=cross_file_saved,
        metadata_encrypted=True,
        hash_verified=True,
    )
    return stats, info


def decode_dedup_archive(
    archive_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    password: str | bytes,
    *,
    progress: ProgressCallback | None = None,
) -> DedupDecodeStats:
    return _decode(Path(archive_path), password, Path(output_path), progress)[0]


def inspect_dedup_archive(
    archive_path: str | os.PathLike[str], password: str | bytes
) -> DedupArchiveInfo:
    return _decode(Path(archive_path), password, None, None)[1]
