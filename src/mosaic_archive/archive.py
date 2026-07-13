"""Encode, decode, and inspect one-file MSC1 archives."""

from __future__ import annotations

import hashlib
import io
import os
import tempfile
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, cast

from mosaic_archive.container_format import (
    AEAD_CHACHA20_POLY1305,
    BLOCK_COUNT,
    BLOCK_HEADER,
    FLAG_PADDED,
    INNER_MAGIC,
    INNER_PREFIX,
    KDF_SCRYPT,
    MAX_BLOCK_COUNT,
    PUBLIC_HEADER,
    SHA256_SIZE,
    VERSION,
    PublicHeader,
    parse_public_header,
)
from mosaic_archive.crypto import (
    AEAD_TAG_LENGTH,
    NONCE_LENGTH,
    SALT_LENGTH,
    decrypt,
    derive_key,
    encrypt,
    normalize_password,
)
from mosaic_archive.exceptions import ArchiveFormatError, IntegrityError
from mosaic_archive.features import BlockFeatures, analyze_block
from mosaic_archive.modes import choose_best_mode, get_mode
from mosaic_archive.padding import pad_payload, unpad_payload
from mosaic_archive.paths import path_matches_file_identity
from mosaic_archive.resource_limits import (
    DEFAULT_MAX_FRAME_COUNT,
    DEFAULT_MAX_LEGACY_ARCHIVE_SIZE,
    DEFAULT_MAX_OUTPUT_SIZE,
    validate_decode_limits,
)


@dataclass(frozen=True, slots=True)
class EncodeStats:
    original_size: int
    compressed_size: int
    padded_plaintext_size: int
    archive_size: int
    block_count: int
    mode_distribution: dict[str, int]
    padding_overhead: int
    duplicate_blocks: int
    average_features: dict[str, float]
    elapsed_seconds: float


@dataclass(frozen=True, slots=True)
class DecodeStats:
    original_size: int
    block_count: int
    mode_distribution: dict[str, int]
    hash_verified: bool
    elapsed_seconds: float


@dataclass(frozen=True, slots=True)
class ArchiveInfo:
    version: int
    file_name: str
    original_size: int
    compressed_size: int
    padded_plaintext_size: int
    archive_size: int
    padding_overhead: int
    chunk_size: int
    block_count: int
    mode_distribution: dict[str, int]
    metadata_encrypted: bool
    hash_verified: bool


@dataclass(frozen=True, slots=True)
class _EncodedRecord:
    mode_id: int
    original_size: int
    payload: bytes


@dataclass(frozen=True, slots=True)
class _DecodedArchive:
    file_name: str
    original_size: int
    expected_hash: bytes
    records: tuple[_EncodedRecord, ...]
    compressed_size: int
    padded_plaintext_size: int
    header: PublicHeader
    archive_size: int
    archive_identity: os.stat_result


def _validate_encode_options(
    chunk_size: int,
    padding_size: int,
    kdf_log_n: int,
    kdf_r: int,
    kdf_p: int,
) -> None:
    if not 1 <= chunk_size <= 16 * 1024 * 1024:
        raise ValueError("chunk size must be between 1 byte and 16 MiB")
    if not 256 <= padding_size <= 16 * 1024 * 1024:
        raise ValueError("padding size must be between 256 bytes and 16 MiB")
    if not 14 <= kdf_log_n <= 18:
        raise ValueError("scrypt log2(N) must be between 14 and 18")
    if kdf_r != 8 or kdf_p != 1:
        raise ValueError("MSC1 supports only scrypt r=8 and p=1")


def _average_features(features: list[BlockFeatures]) -> dict[str, float]:
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
    count = len(features)
    averages = {
        name: sum(getattr(feature, name) for feature in features) / count for name in names
    }
    averages["random_looking_ratio"] = (
        sum(feature.random_looking for feature in features) / count
    )
    return averages


def _build_inner_stream(
    input_path: Path,
    chunk_size: int,
) -> tuple[bytes, int, Counter[str], int, dict[str, float]]:
    records: list[_EncodedRecord] = []
    digest = hashlib.sha256()
    original_size = 0
    distribution: Counter[str] = Counter()
    seen_hashes: set[bytes] = set()
    duplicate_blocks = 0
    all_features: list[BlockFeatures] = []

    with input_path.open("rb") as source:
        while block := source.read(chunk_size):
            original_size += len(block)
            digest.update(block)
            block_hash = hashlib.sha256(block).digest()
            if block_hash in seen_hashes:
                duplicate_blocks += 1
            seen_hashes.add(block_hash)
            all_features.append(analyze_block(block))
            selected = choose_best_mode(block)
            distribution[selected.mode.name] += 1
            records.append(_EncodedRecord(int(selected.mode.id), len(block), selected.payload))

    if len(records) > MAX_BLOCK_COUNT:
        raise ValueError("input produces too many blocks for MSC1")
    name_bytes = input_path.name.encode("utf-8")
    if len(name_bytes) > 65_535:
        raise ValueError("input filename is too long for MSC1")

    stream = io.BytesIO()
    stream.write(INNER_PREFIX.pack(INNER_MAGIC, original_size, len(name_bytes)))
    stream.write(name_bytes)
    stream.write(digest.digest())
    stream.write(BLOCK_COUNT.pack(len(records)))
    for record in records:
        stream.write(BLOCK_HEADER.pack(record.mode_id, record.original_size, len(record.payload)))
        stream.write(record.payload)
    return (
        stream.getvalue(),
        original_size,
        distribution,
        duplicate_blocks,
        _average_features(all_features),
    )


def _write_atomic(destination: Path, data: bytes) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_name = temporary.name
            temporary.write(data)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, destination)
        temporary_name = None
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)


def encode_file(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    password: str | bytes,
    *,
    chunk_size: int = 65_536,
    padding_size: int = 4096,
    kdf_log_n: int = 15,
    kdf_r: int = 8,
    kdf_p: int = 1,
) -> EncodeStats:
    """Compress, pad, authenticate, and atomically write one input file."""
    started = time.perf_counter()
    source = Path(input_path)
    destination = Path(output_path)
    if not source.is_file():
        raise FileNotFoundError(f"input file does not exist: {source}")
    if source.resolve() == destination.resolve():
        raise ValueError("input and output paths must be different")
    normalize_password(password)
    _validate_encode_options(chunk_size, padding_size, kdf_log_n, kdf_r, kdf_p)

    inner, original_size, distribution, duplicates, features = _build_inner_stream(
        source, chunk_size
    )
    padded = pad_payload(inner, padding_size)
    salt = os.urandom(SALT_LENGTH)
    nonce = os.urandom(NONCE_LENGTH)
    header = PublicHeader(
        version=VERSION,
        flags=FLAG_PADDED,
        kdf_id=KDF_SCRYPT,
        aead_id=AEAD_CHACHA20_POLY1305,
        chunk_size=chunk_size,
        padding_size=padding_size,
        salt=salt,
        nonce=nonce,
        kdf_log_n=kdf_log_n,
        kdf_r=kdf_r,
        kdf_p=kdf_p,
        ciphertext_length=len(padded) + AEAD_TAG_LENGTH,
    )
    associated_data = header.pack()
    key = derive_key(password, salt, log_n=kdf_log_n, r=kdf_r, p=kdf_p)
    ciphertext = encrypt(key, nonce, padded, associated_data)
    archive_data = associated_data + ciphertext
    _write_atomic(destination, archive_data)

    return EncodeStats(
        original_size=original_size,
        compressed_size=len(inner),
        padded_plaintext_size=len(padded),
        archive_size=len(archive_data),
        block_count=sum(distribution.values()),
        mode_distribution=dict(sorted(distribution.items())),
        padding_overhead=len(padded) - 8 - len(inner),
        duplicate_blocks=duplicates,
        average_features=features,
        elapsed_seconds=time.perf_counter() - started,
    )


def read_public_header(archive_path: str | os.PathLike[str]) -> PublicHeader:
    path = Path(archive_path)
    with path.open("rb") as archive:
        header_data = archive.read(PUBLIC_HEADER.size)
    return parse_public_header(header_data)


def _read_exact(stream: BinaryIO, size: int, description: str) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise ArchiveFormatError(f"encrypted metadata is truncated at {description}")
    return data


def _parse_inner(
    inner: bytes,
    header: PublicHeader,
    archive_size: int,
    padded_plaintext_size: int,
    max_output_size: int,
    max_frame_count: int,
    archive_identity: os.stat_result,
) -> _DecodedArchive:
    stream = io.BytesIO(inner)
    prefix = _read_exact(stream, INNER_PREFIX.size, "manifest prefix")
    magic, original_size, name_length = INNER_PREFIX.unpack(prefix)
    if magic != INNER_MAGIC:
        raise ArchiveFormatError("encrypted payload has invalid inner magic")
    if original_size > max_output_size:
        raise ArchiveFormatError("MSC1 restored size exceeds the decode limit")
    name_bytes = _read_exact(stream, name_length, "filename")
    try:
        file_name = name_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ArchiveFormatError("encrypted filename is not valid UTF-8") from error
    if not file_name or Path(file_name).name != file_name:
        raise ArchiveFormatError("encrypted filename is unsafe")
    expected_hash = _read_exact(stream, SHA256_SIZE, "SHA-256 digest")
    (block_count,) = BLOCK_COUNT.unpack(
        _read_exact(stream, BLOCK_COUNT.size, "block count")
    )
    if block_count > MAX_BLOCK_COUNT or block_count > max_frame_count:
        raise ArchiveFormatError("archive declares too many blocks")

    records: list[_EncodedRecord] = []
    total_original_size = 0
    for block_index in range(block_count):
        mode_id, block_size, payload_size = BLOCK_HEADER.unpack(
            _read_exact(stream, BLOCK_HEADER.size, f"block {block_index} header")
        )
        get_mode(mode_id)
        if block_size == 0 or block_size > header.chunk_size:
            raise ArchiveFormatError(f"block {block_index} has an invalid original size")
        payload = _read_exact(stream, payload_size, f"block {block_index} payload")
        records.append(_EncodedRecord(mode_id, block_size, payload))
        total_original_size += block_size

    if stream.read(1):
        raise ArchiveFormatError("encrypted payload contains trailing manifest data")
    if total_original_size != original_size:
        raise ArchiveFormatError("block sizes do not add up to the original file size")
    if original_size == 0 and block_count != 0:
        raise ArchiveFormatError("empty archive unexpectedly contains blocks")

    return _DecodedArchive(
        file_name=file_name,
        original_size=original_size,
        expected_hash=expected_hash,
        records=tuple(records),
        compressed_size=len(inner),
        padded_plaintext_size=padded_plaintext_size,
        header=header,
        archive_size=archive_size,
        archive_identity=archive_identity,
    )


def _open_archive(
    archive_path: Path,
    password: str | bytes,
    *,
    max_output_size: int,
    max_frame_count: int,
    max_archive_size: int,
    destination: Path | None = None,
) -> _DecodedArchive:
    validate_decode_limits(max_output_size, max_frame_count, max_archive_size)
    normalize_password(password)
    with archive_path.open("rb") as archive:
        archive_identity = os.fstat(archive.fileno())
        archive_size = archive_identity.st_size
        if destination is not None and path_matches_file_identity(
            destination, archive_identity
        ):
            raise ValueError("archive and output paths must be different")
        if archive_size > max_archive_size:
            raise ArchiveFormatError("MSC1 archive exceeds the legacy decode limit")
        associated_data = archive.read(PUBLIC_HEADER.size)
        header = parse_public_header(associated_data)
        if archive_size != PUBLIC_HEADER.size + header.ciphertext_length:
            raise ArchiveFormatError("archive size does not match its public header")
        ciphertext = archive.read(header.ciphertext_length)
    key = derive_key(
        password,
        header.salt,
        log_n=header.kdf_log_n,
        r=header.kdf_r,
        p=header.kdf_p,
    )
    padded = decrypt(key, header.nonce, ciphertext, associated_data)
    if len(padded) % header.padding_size:
        raise ArchiveFormatError("decrypted payload violates its padding policy")
    inner = unpad_payload(padded)
    return _parse_inner(
        inner,
        header,
        archive_size,
        len(padded),
        max_output_size,
        max_frame_count,
        archive_identity,
    )


class _NullWriter:
    def write(self, data: bytes) -> int:
        return len(data)


def _decode_records(decoded: _DecodedArchive, sink: BinaryIO) -> tuple[Counter[str], bytes]:
    digest = hashlib.sha256()
    distribution: Counter[str] = Counter()
    for record in decoded.records:
        mode = get_mode(record.mode_id)
        block = mode.decode(record.payload, record.original_size)
        sink.write(block)
        digest.update(block)
        distribution[mode.name] += 1
    return distribution, digest.digest()


def decode_file(
    archive_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    password: str | bytes,
    *,
    max_output_size: int = DEFAULT_MAX_OUTPUT_SIZE,
    max_frame_count: int = DEFAULT_MAX_FRAME_COUNT,
    max_archive_size: int = DEFAULT_MAX_LEGACY_ARCHIVE_SIZE,
) -> DecodeStats:
    """Authenticate, decode, verify, and atomically restore one file."""
    started = time.perf_counter()
    archive = Path(archive_path)
    destination = Path(output_path)
    if archive.resolve() == destination.resolve():
        raise ValueError("archive and output paths must be different")
    decoded = _open_archive(
        archive,
        password,
        max_output_size=max_output_size,
        max_frame_count=max_frame_count,
        max_archive_size=max_archive_size,
        destination=destination,
    )

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w+b",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_name = temporary.name
            distribution, actual_hash = _decode_records(
                decoded, cast(BinaryIO, temporary)
            )
            temporary.flush()
            os.fsync(temporary.fileno())
        if actual_hash != decoded.expected_hash:
            raise IntegrityError("restored file failed SHA-256 verification")
        if path_matches_file_identity(destination, decoded.archive_identity):
            raise ValueError("archive and output paths must be different")
        os.replace(temporary_name, destination)
        temporary_name = None
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)

    return DecodeStats(
        original_size=decoded.original_size,
        block_count=len(decoded.records),
        mode_distribution=dict(sorted(distribution.items())),
        hash_verified=True,
        elapsed_seconds=time.perf_counter() - started,
    )


def inspect_archive(
    archive_path: str | os.PathLike[str],
    password: str | bytes,
    *,
    max_output_size: int = DEFAULT_MAX_OUTPUT_SIZE,
    max_frame_count: int = DEFAULT_MAX_FRAME_COUNT,
    max_archive_size: int = DEFAULT_MAX_LEGACY_ARCHIVE_SIZE,
) -> ArchiveInfo:
    """Authenticate and fully decode to a hash sink without writing output."""
    archive = Path(archive_path)
    decoded = _open_archive(
        archive,
        password,
        max_output_size=max_output_size,
        max_frame_count=max_frame_count,
        max_archive_size=max_archive_size,
    )
    distribution, actual_hash = _decode_records(
        decoded,
        cast(BinaryIO, _NullWriter()),
    )
    hash_verified = actual_hash == decoded.expected_hash
    if not hash_verified:
        raise IntegrityError("archive failed SHA-256 verification")
    return ArchiveInfo(
        version=decoded.header.version,
        file_name=decoded.file_name,
        original_size=decoded.original_size,
        compressed_size=decoded.compressed_size,
        padded_plaintext_size=decoded.padded_plaintext_size,
        archive_size=decoded.archive_size,
        padding_overhead=decoded.padded_plaintext_size - 8 - decoded.compressed_size,
        chunk_size=decoded.header.chunk_size,
        block_count=len(decoded.records),
        mode_distribution=dict(sorted(distribution.items())),
        metadata_encrypted=True,
        hash_verified=True,
    )
