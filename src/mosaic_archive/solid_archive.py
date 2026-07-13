"""Experimental whole-archive solid container; deliberately separate from MSC6."""

from __future__ import annotations

import hashlib
import os
import shutil
import struct
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Final, cast

from mosaic_archive.cdc import DEFAULT_CHUNKING, ChunkingConfig, iter_content_defined_chunks
from mosaic_archive.container_format import AEAD_CHACHA20_POLY1305, KDF_SCRYPT
from mosaic_archive.crypto import (
    AEAD_TAG_LENGTH,
    NONCE_LENGTH,
    SALT_LENGTH,
    decrypt,
    derive_key,
    encrypt,
)
from mosaic_archive.dedup_archive import (
    DedupManifest,
    _apply_metadata,
    _scan_manifest,
    _source_path,
    parse_dedup_manifest,
    serialize_dedup_manifest,
)
from mosaic_archive.dedup_format import MSC3_FLAGS, MSC6_VERSION, Msc3Header
from mosaic_archive.exceptions import ArchiveFormatError, IntegrityError
from mosaic_archive.padding import pad_payload, unpad_payload
from mosaic_archive.paths import path_matches_file_identity
from mosaic_archive.solid_research import decode_solid_chunks, encode_solid_chunks
from mosaic_archive.stream_archive import ENTRY_DIRECTORY, ENTRY_FILE, KIND_FILE, KIND_FOLDER
from mosaic_archive.stream_format import MAX_MANIFEST_CIPHERTEXT

_MAGIC: Final = b"MSR1"
_HEADER: Final = struct.Struct(">4sBIIIIQ16s12sQ")
_PLAIN_PREFIX: Final = struct.Struct(">QQ")
_MAX_CIPHERTEXT: Final = 1024 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class SolidArchiveEncodeStats:
    format_name: str
    original_size: int
    archive_size: int
    solid_payload_size: int
    manifest_size: int
    unique_chunk_count: int
    lane_distribution: dict[str, int]
    elapsed_seconds: float


@dataclass(frozen=True, slots=True)
class SolidArchiveDecodeStats:
    format_name: str
    original_size: int
    archive_size: int
    unique_chunk_count: int
    hash_verified: bool
    elapsed_seconds: float


def _collect_unique_chunks(
    source: Path,
    manifest: DedupManifest,
    config: ChunkingConfig,
) -> tuple[bytes, ...]:
    chunks = manifest.chunks
    entries = manifest.entries
    kind = manifest.kind
    unique: list[bytes] = []
    occurrence = 0
    for entry in entries:
        if entry.entry_type != ENTRY_FILE:
            continue
        path = _source_path(source, kind, entry.relative_path)
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter_content_defined_chunks(stream, config):
                record = chunks[occurrence]
                actual_digest = hashlib.sha256(chunk).digest()
                if len(chunk) != record.size or actual_digest != record.digest:
                    raise OSError(f"input changed while it was encoded: {path}")
                digest.update(chunk)
                if record.source_index == occurrence:
                    unique.append(chunk)
                occurrence += 1
        if digest.digest() != entry.digest:
            raise OSError(f"input changed while it was encoded: {path}")
    if occurrence != len(chunks):
        raise RuntimeError("internal solid archive chunk mismatch")
    return tuple(unique)


def encode_solid_archive(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    password: str | bytes,
    *,
    config: ChunkingConfig = DEFAULT_CHUNKING,
    padding_size: int = 1024,
    kdf_log_n: int = 15,
) -> SolidArchiveEncodeStats:
    """Create an encrypted experimental solid archive atomically."""
    started = time.perf_counter()
    source, destination = Path(input_path), Path(output_path)
    if source.resolve() == destination.resolve():
        raise ValueError("input and output paths must be different")
    if source.is_dir() and destination.resolve().is_relative_to(source.resolve()):
        raise ValueError("folder archives must be written outside the input tree")
    if not 256 <= padding_size <= 16 * 1024 * 1024 or not 14 <= kdf_log_n <= 18:
        raise ValueError("padding or scrypt cost is outside supported limits")

    manifest, _ = _scan_manifest(source, config)
    unique_chunks = _collect_unique_chunks(source, manifest, config)
    solid = encode_solid_chunks(unique_chunks)
    manifest_payload = serialize_dedup_manifest(manifest)
    if len(manifest_payload) > MAX_MANIFEST_CIPHERTEXT:
        raise ValueError("solid archive manifest exceeds its resource limit")
    plaintext = (
        _PLAIN_PREFIX.pack(len(manifest_payload), len(solid.payload))
        + manifest_payload
        + solid.payload
    )
    padded = pad_payload(plaintext, padding_size)
    salt, nonce = os.urandom(SALT_LENGTH), os.urandom(NONCE_LENGTH)
    ciphertext_length = len(padded) + AEAD_TAG_LENGTH
    header = _HEADER.pack(
        _MAGIC,
        kdf_log_n,
        config.min_size,
        config.avg_size,
        config.max_size,
        padding_size,
        len(unique_chunks),
        salt,
        nonce,
        ciphertext_length,
    )
    key = derive_key(password, salt, log_n=kdf_log_n, r=8, p=1)
    ciphertext = encrypt(key, nonce, padded, header)

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            delete=False,
        ) as temporary:
            temporary_name = temporary.name
            temporary.write(header)
            temporary.write(ciphertext)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, destination)
        temporary_name = None
    finally:
        if temporary_name:
            Path(temporary_name).unlink(missing_ok=True)

    return SolidArchiveEncodeStats(
        format_name="MSR1",
        original_size=sum(entry.size for entry in manifest.entries),
        archive_size=destination.stat().st_size,
        solid_payload_size=len(solid.payload),
        manifest_size=len(manifest_payload),
        unique_chunk_count=len(unique_chunks),
        lane_distribution=solid.lane_distribution,
        elapsed_seconds=time.perf_counter() - started,
    )


def _read_archive(
    archive: Path,
    password: str | bytes,
    destination: Path | None = None,
) -> tuple[DedupManifest, tuple[bytes, ...], os.stat_result]:
    with archive.open("rb") as raw:
        opened_archive = os.fstat(raw.fileno())
        if destination is not None and path_matches_file_identity(
            destination, opened_archive
        ):
            raise ValueError("archive and output paths must be different")
        stream = cast(BinaryIO, raw)
        header = stream.read(_HEADER.size)
        if len(header) != _HEADER.size:
            raise ArchiveFormatError("solid archive header is truncated")
        values = _HEADER.unpack(header)
        magic, log_n, minimum, average, maximum, padding = values[:6]
        unique_count, salt, nonce, ciphertext_length = values[6:]
        if (
            magic != _MAGIC
            or not 14 <= log_n <= 18
            or len(salt) != SALT_LENGTH
            or len(nonce) != NONCE_LENGTH
            or not 256 <= padding <= 16 * 1024 * 1024
            or ciphertext_length > _MAX_CIPHERTEXT
            or ciphertext_length < AEAD_TAG_LENGTH
            or (ciphertext_length - AEAD_TAG_LENGTH) % padding
        ):
            raise ArchiveFormatError("solid archive public header is invalid")
        try:
            config = ChunkingConfig(minimum, average, maximum)
        except ValueError as error:
            raise ArchiveFormatError("solid archive chunking limits are invalid") from error
        ciphertext = stream.read(ciphertext_length)
        if len(ciphertext) != ciphertext_length or stream.read(1):
            raise ArchiveFormatError("solid archive length is inconsistent")

    key = derive_key(password, salt, log_n=log_n, r=8, p=1)
    plaintext = unpad_payload(decrypt(key, nonce, ciphertext, header))
    if len(plaintext) < _PLAIN_PREFIX.size:
        raise ArchiveFormatError("solid archive plaintext prefix is truncated")
    manifest_size, solid_size = _PLAIN_PREFIX.unpack_from(plaintext)
    if manifest_size > MAX_MANIFEST_CIPHERTEXT:
        raise ArchiveFormatError("solid archive manifest exceeds its resource limit")
    if manifest_size + solid_size != len(plaintext) - _PLAIN_PREFIX.size:
        raise ArchiveFormatError("solid archive plaintext sizes are inconsistent")
    position = _PLAIN_PREFIX.size
    manifest_payload = plaintext[position : position + manifest_size]
    position += manifest_size
    solid_payload = plaintext[position:]
    compatibility_header = Msc3Header(
        MSC6_VERSION,
        MSC3_FLAGS,
        KDF_SCRYPT,
        AEAD_CHACHA20_POLY1305,
        config.min_size,
        config.avg_size,
        config.max_size,
        padding,
        salt,
        nonce[:4],
        log_n,
        8,
        1,
        unique_count + 1,
    )
    manifest = parse_dedup_manifest(manifest_payload, compatibility_header)
    unique_records = tuple(
        record
        for index, record in enumerate(manifest.chunks)
        if record.source_index == index
    )
    if len(unique_records) != unique_count:
        raise ArchiveFormatError("solid archive unique chunk count is inconsistent")
    chunks = decode_solid_chunks(solid_payload, [record.size for record in unique_records])
    for record, chunk in zip(unique_records, chunks, strict=True):
        if hashlib.sha256(chunk).digest() != record.digest:
            raise IntegrityError("solid archive unique chunk digest failed")
    return manifest, chunks, opened_archive


def decode_solid_archive(
    archive_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    password: str | bytes,
) -> SolidArchiveDecodeStats:
    """Authenticate and atomically restore an experimental solid archive."""
    started = time.perf_counter()
    archive, destination = Path(archive_path), Path(output_path)
    manifest, chunks, opened_archive = _read_archive(
        archive,
        password,
        destination,
    )
    canonical: dict[int, bytes] = {}
    iterator = iter(chunks)
    for index, record in enumerate(manifest.chunks):
        if record.source_index == index:
            canonical[index] = next(iterator)

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
        ) as temporary:
            temporary_root = Path(temporary.name)

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
                    chunk = canonical[record.source_index]
                    output.write(chunk)
                    digest.update(chunk)
            if digest.digest() != entry.digest:
                raise IntegrityError(f"solid archive file digest failed: {entry.relative_path}")
            _apply_metadata(target, entry)
        if manifest.kind == KIND_FOLDER:
            for entry in sorted(
                (item for item in manifest.entries if item.entry_type == ENTRY_DIRECTORY),
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

    return SolidArchiveDecodeStats(
        format_name="MSR1",
        original_size=sum(entry.size for entry in manifest.entries),
        archive_size=opened_archive.st_size,
        unique_chunk_count=len(chunks),
        hash_verified=True,
        elapsed_seconds=time.perf_counter() - started,
    )
