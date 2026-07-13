"""MSC2 folder manifests and independently authenticated streaming frames."""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import stat
import struct
import tempfile
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, cast

from mosaic_archive.container_format import AEAD_CHACHA20_POLY1305, KDF_SCRYPT
from mosaic_archive.crypto import (
    AEAD_TAG_LENGTH,
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
from mosaic_archive.paths import validate_relative_path
from mosaic_archive.resource_limits import (
    DEFAULT_MAX_FRAME_COUNT,
    DEFAULT_MAX_LEGACY_ARCHIVE_SIZE,
    DEFAULT_MAX_OUTPUT_SIZE,
    validate_decode_limits,
)
from mosaic_archive.stream_format import (
    FRAME_DATA,
    FRAME_HEADER,
    FRAME_MANIFEST,
    MAX_MANIFEST_CIPHERTEXT,
    MSC2_FLAGS,
    MSC2_HEADER,
    MSC2_MAGIC,
    MSC2_VERSION,
    FrameHeader,
    Msc2Header,
    frame_nonce,
    parse_frame_header,
    parse_msc2_header,
)

KIND_FILE = 1
KIND_FOLDER = 2
ENTRY_FILE = 1
ENTRY_DIRECTORY = 2
MANIFEST_MAGIC = b"M2MF"
MANIFEST_PREFIX = struct.Struct(">4sBHI")
ENTRY_FIXED = struct.Struct(">BHIqQQI32s")
DATA_PREFIX = struct.Struct(">IIB")
MAX_ENTRY_COUNT = 1_000_000
ZERO_HASH = b"\x00" * 32


@dataclass(frozen=True, slots=True)
class ManifestEntry:
    entry_type: int
    relative_path: str
    mode: int
    mtime_ns: int
    size: int
    first_frame: int
    frame_count: int
    digest: bytes


@dataclass(frozen=True, slots=True)
class Manifest:
    kind: int
    root_name: str
    entries: tuple[ManifestEntry, ...]


@dataclass(frozen=True, slots=True)
class StreamEncodeStats:
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
    elapsed_seconds: float


@dataclass(frozen=True, slots=True)
class StreamDecodeStats:
    format_version: int
    archive_kind: str
    original_size: int
    block_count: int
    file_count: int
    directory_count: int
    mode_distribution: dict[str, int]
    hash_verified: bool
    elapsed_seconds: float


@dataclass(frozen=True, slots=True)
class StreamArchiveInfo:
    format_version: int
    archive_kind: str
    root_name: str
    original_size: int
    compressed_size: int
    padded_plaintext_size: int
    archive_size: int
    padding_overhead: int
    chunk_size: int
    block_count: int
    file_count: int
    directory_count: int
    mode_distribution: dict[str, int]
    metadata_encrypted: bool
    hash_verified: bool


@dataclass(frozen=True, slots=True)
class ProgressEvent:
    stage: str
    completed_bytes: int
    total_bytes: int
    completed_files: int
    total_files: int


ProgressCallback = Callable[[ProgressEvent], None]


class _NullWriter:
    def write(self, data: bytes) -> int:
        return len(data)

    def close(self) -> None:
        pass


def _kind_name(kind: int) -> str:
    return "file" if kind == KIND_FILE else "folder"


def _is_link_or_reparse(path: Path) -> bool:
    metadata = path.stat(follow_symlinks=False)
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse_flag)


def _hash_file(path: Path) -> tuple[int, bytes, os.stat_result]:
    before = path.stat(follow_symlinks=False)
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
            size += len(block)
    after = path.stat(follow_symlinks=False)
    if (
        before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or size != after.st_size
    ):
        raise OSError(f"input changed while it was being scanned: {path}")
    return size, digest.digest(), after


def _entry_metadata(
    entry_type: int,
    relative_path: str,
    path: Path,
    *,
    chunk_size: int,
    first_frame: int,
) -> ManifestEntry:
    if _is_link_or_reparse(path):
        raise ValueError(f"symbolic links and reparse points are not supported: {path}")
    metadata = path.stat(follow_symlinks=False)
    mode = stat.S_IMODE(metadata.st_mode) & 0o777
    if entry_type == ENTRY_DIRECTORY:
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError(f"expected a directory but found another file type: {path}")
        return ManifestEntry(
            entry_type,
            validate_relative_path(relative_path),
            mode,
            metadata.st_mtime_ns,
            0,
            0,
            0,
            ZERO_HASH,
        )
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"special files are not supported: {path}")
    size, digest, stable_metadata = _hash_file(path)
    frame_count = (size + chunk_size - 1) // chunk_size
    return ManifestEntry(
        entry_type,
        validate_relative_path(relative_path),
        mode,
        stable_metadata.st_mtime_ns,
        size,
        first_frame,
        frame_count,
        digest,
    )


def scan_input(source: Path, chunk_size: int) -> Manifest:
    if not source.exists():
        raise FileNotFoundError(f"input path does not exist: {source}")
    if _is_link_or_reparse(source):
        raise ValueError("the archive root cannot be a symbolic link or reparse point")
    root_name = validate_relative_path(source.name)
    if source.is_file():
        entry = _entry_metadata(
            ENTRY_FILE,
            root_name,
            source,
            chunk_size=chunk_size,
            first_frame=1,
        )
        return Manifest(KIND_FILE, root_name, (entry,))
    if not source.is_dir():
        raise ValueError(f"input is neither a regular file nor a directory: {source}")

    discovered: list[tuple[int, str, Path]] = []
    for current_root, directory_names, file_names in os.walk(
        source, topdown=True, followlinks=False
    ):
        current = Path(current_root)
        directory_names.sort()
        file_names.sort()
        for name in directory_names:
            path = current / name
            relative = path.relative_to(source).as_posix()
            if _is_link_or_reparse(path):
                raise ValueError(
                    f"symbolic links and reparse points are not supported: {path}"
                )
            discovered.append((ENTRY_DIRECTORY, relative, path))
        for name in file_names:
            path = current / name
            relative = path.relative_to(source).as_posix()
            discovered.append((ENTRY_FILE, relative, path))

    discovered.sort(key=lambda item: (item[1].count("/"), item[1].casefold(), item[0]))
    entries: list[ManifestEntry] = []
    next_frame = 1
    casefolded_paths: set[str] = set()
    for entry_type, relative, path in discovered:
        normalized = validate_relative_path(relative)
        collision_key = normalized.casefold()
        if collision_key in casefolded_paths:
            raise ValueError(f"portable path collision in input tree: {relative}")
        casefolded_paths.add(collision_key)
        entry = _entry_metadata(
            entry_type,
            normalized,
            path,
            chunk_size=chunk_size,
            first_frame=next_frame,
        )
        entries.append(entry)
        if entry.entry_type == ENTRY_FILE:
            next_frame += entry.frame_count
    if len(entries) > MAX_ENTRY_COUNT:
        raise ValueError("input tree has too many entries for MSC2")
    return Manifest(KIND_FOLDER, root_name, tuple(entries))


def serialize_manifest(manifest: Manifest) -> bytes:
    root_name = manifest.root_name.encode("utf-8")
    output = io.BytesIO()
    output.write(
        MANIFEST_PREFIX.pack(MANIFEST_MAGIC, manifest.kind, len(root_name), len(manifest.entries))
    )
    output.write(root_name)
    for entry in manifest.entries:
        path_bytes = entry.relative_path.encode("utf-8")
        output.write(
            ENTRY_FIXED.pack(
                entry.entry_type,
                len(path_bytes),
                entry.mode,
                entry.mtime_ns,
                entry.size,
                entry.first_frame,
                entry.frame_count,
                entry.digest,
            )
        )
        output.write(path_bytes)
    return output.getvalue()


def _read_exact(stream: BinaryIO, size: int, description: str) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise ArchiveFormatError(f"MSC2 metadata is truncated at {description}")
    return data


def parse_manifest(data: bytes, header: Msc2Header) -> Manifest:
    stream = io.BytesIO(data)
    magic, kind, root_length, entry_count = MANIFEST_PREFIX.unpack(
        _read_exact(stream, MANIFEST_PREFIX.size, "manifest prefix")
    )
    if magic != MANIFEST_MAGIC or kind not in {KIND_FILE, KIND_FOLDER}:
        raise ArchiveFormatError("MSC2 manifest prefix is invalid")
    if entry_count > MAX_ENTRY_COUNT:
        raise ArchiveFormatError("MSC2 manifest has too many entries")
    try:
        raw_root_name = _read_exact(stream, root_length, "root name").decode("utf-8")
        root_name = validate_relative_path(raw_root_name)
    except (UnicodeDecodeError, ValueError) as error:
        raise ArchiveFormatError("MSC2 root name is invalid") from error
    if "/" in root_name or root_name != raw_root_name:
        raise ArchiveFormatError("MSC2 root name is not a canonical basename")

    entries: list[ManifestEntry] = []
    collision_keys: set[str] = set()
    expected_next_frame = 1
    for entry_index in range(entry_count):
        fixed = _read_exact(stream, ENTRY_FIXED.size, f"entry {entry_index}")
        entry_type, path_length, mode, mtime_ns, size, first_frame, frame_count, digest = (
            ENTRY_FIXED.unpack(fixed)
        )
        if entry_type not in {ENTRY_FILE, ENTRY_DIRECTORY}:
            raise ArchiveFormatError(f"MSC2 entry {entry_index} has an unknown type")
        try:
            raw_path = _read_exact(stream, path_length, f"entry {entry_index} path").decode(
                "utf-8"
            )
            relative_path = validate_relative_path(raw_path)
        except (UnicodeDecodeError, ValueError) as error:
            raise ArchiveFormatError(f"MSC2 entry {entry_index} has an unsafe path") from error
        if relative_path != raw_path:
            raise ArchiveFormatError(f"MSC2 entry {entry_index} path is not canonical")
        collision_key = relative_path.casefold()
        if collision_key in collision_keys:
            raise ArchiveFormatError("MSC2 manifest contains a portable path collision")
        collision_keys.add(collision_key)
        if mode > 0o777:
            raise ArchiveFormatError(f"MSC2 entry {entry_index} mode is invalid")

        if entry_type == ENTRY_DIRECTORY:
            if size != 0 or first_frame != 0 or frame_count != 0 or digest != ZERO_HASH:
                raise ArchiveFormatError(f"MSC2 directory entry {entry_index} is malformed")
        else:
            required_frames = (size + header.chunk_size - 1) // header.chunk_size
            if frame_count != required_frames or first_frame != expected_next_frame:
                raise ArchiveFormatError(f"MSC2 file entry {entry_index} frame range is invalid")
            expected_next_frame += frame_count
        entries.append(
            ManifestEntry(
                entry_type,
                relative_path,
                mode,
                mtime_ns,
                size,
                first_frame,
                frame_count,
                digest,
            )
        )

    if stream.read(1):
        raise ArchiveFormatError("MSC2 manifest contains trailing bytes")
    if expected_next_frame != header.frame_count:
        raise ArchiveFormatError("MSC2 manifest frame ranges do not match the public header")
    if kind == KIND_FILE:
        if (
            len(entries) != 1
            or entries[0].entry_type != ENTRY_FILE
            or entries[0].relative_path != root_name
        ):
            raise ArchiveFormatError("MSC2 single-file manifest is malformed")
    else:
        directory_paths = {
            entry.relative_path
            for entry in entries
            if entry.entry_type == ENTRY_DIRECTORY
        }
        for entry in entries:
            parent = Path(entry.relative_path).parent.as_posix()
            if parent != "." and parent not in directory_paths:
                raise ArchiveFormatError("MSC2 manifest omits a required parent directory")
    return Manifest(kind, root_name, tuple(entries))


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
    result = {
        name: sum(getattr(feature, name) for feature in features) / count for name in names
    }
    result["random_looking_ratio"] = sum(item.random_looking for item in features) / count
    return result


def _write_frame(
    output: BinaryIO,
    *,
    index: int,
    frame_type: int,
    payload: bytes,
    key: bytes,
    global_header: bytes,
    header: Msc2Header,
) -> tuple[int, int, int]:
    padded = pad_payload(payload, header.padding_size)
    frame_header = FrameHeader(index, frame_type, len(padded) + AEAD_TAG_LENGTH)
    serialized_frame_header = frame_header.pack()
    ciphertext = encrypt(
        key,
        frame_nonce(header.nonce_prefix, index),
        padded,
        global_header + serialized_frame_header,
    )
    output.write(serialized_frame_header)
    output.write(ciphertext)
    return len(payload), len(padded), len(padded) - 8 - len(payload)


def _source_for_entry(source: Path, manifest: Manifest, entry: ManifestEntry) -> Path:
    if manifest.kind == KIND_FILE:
        return source
    return source.joinpath(*entry.relative_path.split("/"))


def encode_stream_archive(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    password: str | bytes,
    *,
    chunk_size: int = 65_536,
    padding_size: int = 4096,
    kdf_log_n: int = 15,
    kdf_r: int = 8,
    kdf_p: int = 1,
    progress: ProgressCallback | None = None,
) -> StreamEncodeStats:
    started = time.perf_counter()
    source = Path(input_path)
    destination = Path(output_path)
    normalize_password(password)
    if not 1 <= chunk_size <= 16 * 1024 * 1024:
        raise ValueError("chunk size must be between 1 byte and 16 MiB")
    if not 256 <= padding_size <= 16 * 1024 * 1024:
        raise ValueError("padding size must be between 256 bytes and 16 MiB")
    if not 14 <= kdf_log_n <= 18:
        raise ValueError("scrypt log2(N) must be between 14 and 18")
    if kdf_r != 8 or kdf_p != 1:
        raise ValueError("MSC2 supports only scrypt r=8 and p=1")
    if source.resolve() == destination.resolve():
        raise ValueError("input and output paths must be different")
    if source.is_dir() and destination.resolve().is_relative_to(source.resolve()):
        raise ValueError("folder archives must be written outside the input tree")

    manifest = scan_input(source, chunk_size)
    data_frame_count = sum(
        entry.frame_count for entry in manifest.entries if entry.entry_type == ENTRY_FILE
    )
    if 1 + data_frame_count > 16_777_216:
        raise ValueError("input produces too many frames for MSC2")
    salt = os.urandom(SALT_LENGTH)
    nonce_prefix = os.urandom(4)
    header = Msc2Header(
        MSC2_VERSION,
        MSC2_FLAGS,
        KDF_SCRYPT,
        AEAD_CHACHA20_POLY1305,
        chunk_size,
        padding_size,
        salt,
        nonce_prefix,
        kdf_log_n,
        kdf_r,
        kdf_p,
        1 + data_frame_count,
    )
    global_header = header.pack()
    key = derive_key(password, salt, log_n=kdf_log_n, r=kdf_r, p=kdf_p)
    manifest_payload = serialize_manifest(manifest)
    maximum_manifest_payload = MAX_MANIFEST_CIPHERTEXT - padding_size - AEAD_TAG_LENGTH
    if len(manifest_payload) > maximum_manifest_payload:
        raise ValueError("folder manifest is too large for MSC2 resource limits")
    distribution: Counter[str] = Counter()
    features: list[BlockFeatures] = []
    duplicate_blocks = 0
    seen_blocks: set[bytes] = set()
    compressed_size = 0
    padded_size = 0
    padding_overhead = 0
    frame_index = 0
    files = sum(entry.entry_type == ENTRY_FILE for entry in manifest.entries)
    original_size = sum(entry.size for entry in manifest.entries)
    completed_bytes = 0
    completed_files = 0
    if progress is not None:
        progress(ProgressEvent("encode", 0, original_size, 0, files))

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w+b",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_name = temporary.name
            output = cast(BinaryIO, temporary)
            output.write(global_header)
            metrics = _write_frame(
                output,
                index=frame_index,
                frame_type=FRAME_MANIFEST,
                payload=manifest_payload,
                key=key,
                global_header=global_header,
                header=header,
            )
            compressed_size += metrics[0]
            padded_size += metrics[1]
            padding_overhead += metrics[2]
            frame_index += 1

            for entry_index, entry in enumerate(manifest.entries):
                if entry.entry_type != ENTRY_FILE:
                    continue
                path = _source_for_entry(source, manifest, entry)
                digest = hashlib.sha256()
                bytes_read = 0
                with path.open("rb") as file_stream:
                    while block := file_stream.read(chunk_size):
                        digest.update(block)
                        bytes_read += len(block)
                        block_digest = hashlib.sha256(block).digest()
                        duplicate_blocks += block_digest in seen_blocks
                        seen_blocks.add(block_digest)
                        features.append(analyze_block(block))
                        selected = choose_best_mode(block)
                        distribution[selected.mode.name] += 1
                        payload = DATA_PREFIX.pack(
                            entry_index, len(block), int(selected.mode.id)
                        ) + selected.payload
                        metrics = _write_frame(
                            output,
                            index=frame_index,
                            frame_type=FRAME_DATA,
                            payload=payload,
                            key=key,
                            global_header=global_header,
                            header=header,
                        )
                        compressed_size += metrics[0]
                        padded_size += metrics[1]
                        padding_overhead += metrics[2]
                        frame_index += 1
                        completed_bytes += len(block)
                        if progress is not None:
                            progress(
                                ProgressEvent(
                                    "encode",
                                    completed_bytes,
                                    original_size,
                                    completed_files,
                                    files,
                                )
                            )
                if bytes_read != entry.size or digest.digest() != entry.digest:
                    raise OSError(f"input changed while it was being encoded: {path}")
                completed_files += 1
                if progress is not None:
                    progress(
                        ProgressEvent(
                            "encode",
                            completed_bytes,
                            original_size,
                            completed_files,
                            files,
                        )
                    )

            if frame_index != header.frame_count:
                raise RuntimeError("internal MSC2 frame-count mismatch")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_name, destination)
        temporary_name = None
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)

    directories = sum(entry.entry_type == ENTRY_DIRECTORY for entry in manifest.entries)
    return StreamEncodeStats(
        format_version=MSC2_VERSION,
        archive_kind=_kind_name(manifest.kind),
        original_size=original_size,
        compressed_size=compressed_size,
        padded_plaintext_size=padded_size,
        archive_size=destination.stat().st_size,
        padding_overhead=padding_overhead,
        block_count=data_frame_count,
        file_count=files,
        directory_count=directories,
        mode_distribution=dict(sorted(distribution.items())),
        duplicate_blocks=duplicate_blocks,
        average_features=_average_features(features),
        elapsed_seconds=time.perf_counter() - started,
    )


def _read_frame(
    stream: BinaryIO,
    *,
    expected_index: int,
    expected_type: int,
    key: bytes,
    global_header: bytes,
    header: Msc2Header,
) -> tuple[bytes, int]:
    serialized = _read_exact(stream, FRAME_HEADER.size, f"frame {expected_index} header")
    frame = parse_frame_header(serialized)
    if frame.index != expected_index or frame.frame_type != expected_type:
        raise ArchiveFormatError(f"MSC2 frame {expected_index} is out of order")
    if (frame.ciphertext_length - AEAD_TAG_LENGTH) % header.padding_size:
        raise ArchiveFormatError(f"MSC2 frame {expected_index} violates its padding policy")
    if frame.frame_type == FRAME_MANIFEST:
        maximum = MAX_MANIFEST_CIPHERTEXT
    else:
        maximum = header.chunk_size + header.padding_size + DATA_PREFIX.size + 32
    if frame.ciphertext_length > maximum:
        raise ArchiveFormatError(f"MSC2 frame {expected_index} exceeds its resource limit")
    ciphertext = _read_exact(
        stream, frame.ciphertext_length, f"frame {expected_index} ciphertext"
    )
    padded = decrypt(
        key,
        frame_nonce(header.nonce_prefix, expected_index),
        ciphertext,
        global_header + serialized,
    )
    return unpad_payload(padded), len(padded)


def _apply_file_metadata(path: Path, entry: ManifestEntry) -> None:
    # The target tree is newly created by this decoder and contains no links.
    # Windows does not implement follow_symlinks=False for these operations.
    os.chmod(path, entry.mode)
    os.utime(path, ns=(entry.mtime_ns, entry.mtime_ns))


def _prepare_output(
    destination: Path | None,
    manifest: Manifest,
) -> tuple[Path | None, Path | None]:
    if destination is None:
        return None, None
    destination.parent.mkdir(parents=True, exist_ok=True)
    if manifest.kind == KIND_FOLDER:
        if destination.exists():
            raise FileExistsError(
                f"folder destination already exists; refusing to merge: {destination}"
            )
        temporary_root = Path(
            tempfile.mkdtemp(prefix=f".{destination.name}.", dir=destination.parent)
        )
        return temporary_root, temporary_root
    with tempfile.NamedTemporaryFile(
        "wb",
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
        delete=False,
    ) as temporary:
        temporary_path = Path(temporary.name)
    return temporary_path, temporary_path


def _cleanup_output(temporary_root: Path | None, manifest: Manifest) -> None:
    if temporary_root is None or not temporary_root.exists():
        return
    if manifest.kind == KIND_FOLDER:
        shutil.rmtree(temporary_root)
    else:
        temporary_root.unlink(missing_ok=True)


def _target_for_entry(
    output_root: Path | None,
    manifest: Manifest,
    entry: ManifestEntry,
) -> Path | None:
    if output_root is None:
        return None
    if manifest.kind == KIND_FILE:
        return output_root
    return output_root.joinpath(*entry.relative_path.split("/"))


def _decode_or_inspect(
    archive_path: Path,
    password: str | bytes,
    destination: Path | None,
    progress: ProgressCallback | None,
    max_output_size: int,
    max_frame_count: int,
) -> tuple[StreamDecodeStats, StreamArchiveInfo]:
    validate_decode_limits(
        max_output_size,
        max_frame_count,
        DEFAULT_MAX_LEGACY_ARCHIVE_SIZE,
    )
    started = time.perf_counter()
    normalize_password(password)
    archive_size = archive_path.stat().st_size
    temporary_root: Path | None = None
    manifest: Manifest | None = None
    with archive_path.open("rb") as raw_stream:
        stream = cast(BinaryIO, raw_stream)
        global_header = _read_exact(stream, MSC2_HEADER.size, "public header")
        header = parse_msc2_header(global_header)
        if header.frame_count - 1 > max_frame_count:
            raise ArchiveFormatError("MSC2 frame count exceeds the decode limit")
        key = derive_key(
            password,
            header.salt,
            log_n=header.kdf_log_n,
            r=header.kdf_r,
            p=header.kdf_p,
        )
        manifest_payload, manifest_padded_size = _read_frame(
            stream,
            expected_index=0,
            expected_type=FRAME_MANIFEST,
            key=key,
            global_header=global_header,
            header=header,
        )
        manifest = parse_manifest(manifest_payload, header)
        total_bytes = sum(entry.size for entry in manifest.entries)
        if total_bytes > max_output_size:
            raise ArchiveFormatError("MSC2 restored size exceeds the decode limit")
        output_root, temporary_root = _prepare_output(destination, manifest)
        try:
            distribution: Counter[str] = Counter()
            compressed_size = len(manifest_payload)
            padded_size = manifest_padded_size
            frame_index = 1
            total_files = sum(entry.entry_type == ENTRY_FILE for entry in manifest.entries)
            completed_bytes = 0
            completed_files = 0
            if progress is not None:
                progress(ProgressEvent("decode", 0, total_bytes, 0, total_files))
            for entry_index, entry in enumerate(manifest.entries):
                target = _target_for_entry(output_root, manifest, entry)
                if entry.entry_type == ENTRY_DIRECTORY:
                    if target is not None:
                        target.mkdir(parents=True, exist_ok=False)
                    continue

                if target is not None and manifest.kind == KIND_FOLDER:
                    target.parent.mkdir(parents=True, exist_ok=True)
                digest = hashlib.sha256()
                bytes_written = 0
                sink: BinaryIO = (
                    cast(BinaryIO, _NullWriter()) if target is None else target.open("wb")
                )
                try:
                    for local_frame in range(entry.frame_count):
                        payload, frame_padded_size = _read_frame(
                            stream,
                            expected_index=frame_index,
                            expected_type=FRAME_DATA,
                            key=key,
                            global_header=global_header,
                            header=header,
                        )
                        compressed_size += len(payload)
                        padded_size += frame_padded_size
                        if len(payload) < DATA_PREFIX.size:
                            raise ArchiveFormatError(
                                f"MSC2 data frame {frame_index} is truncated"
                            )
                        actual_entry, original_size, mode_id = DATA_PREFIX.unpack_from(payload)
                        expected_size = min(
                            header.chunk_size,
                            entry.size - (local_frame * header.chunk_size),
                        )
                        if actual_entry != entry_index or original_size != expected_size:
                            raise ArchiveFormatError(
                                f"MSC2 data frame {frame_index} metadata is inconsistent"
                            )
                        mode = get_mode(mode_id)
                        block = mode.decode(payload[DATA_PREFIX.size :], original_size)
                        sink.write(block)
                        digest.update(block)
                        bytes_written += len(block)
                        completed_bytes += len(block)
                        distribution[mode.name] += 1
                        frame_index += 1
                        if progress is not None:
                            progress(
                                ProgressEvent(
                                    "decode",
                                    completed_bytes,
                                    total_bytes,
                                    completed_files,
                                    total_files,
                                )
                            )
                finally:
                    sink.close()
                if bytes_written != entry.size or digest.digest() != entry.digest:
                    raise IntegrityError(
                        f"restored file failed SHA-256 verification: {entry.relative_path}"
                    )
                if target is not None:
                    _apply_file_metadata(target, entry)
                completed_files += 1
                if progress is not None:
                    progress(
                        ProgressEvent(
                            "decode",
                            completed_bytes,
                            total_bytes,
                            completed_files,
                            total_files,
                        )
                    )

            if frame_index != header.frame_count:
                raise ArchiveFormatError("MSC2 data frames do not match the manifest")
            if stream.read(1):
                raise ArchiveFormatError("MSC2 archive contains trailing bytes")
            if output_root is not None and manifest.kind == KIND_FOLDER:
                directory_entries = sorted(
                    (
                        entry
                        for entry in manifest.entries
                        if entry.entry_type == ENTRY_DIRECTORY
                    ),
                    key=lambda entry: entry.relative_path.count("/"),
                    reverse=True,
                )
                for entry in directory_entries:
                    target = _target_for_entry(output_root, manifest, entry)
                    if target is not None:
                        _apply_file_metadata(target, entry)
            if destination is not None and temporary_root is not None:
                os.replace(temporary_root, destination)
                temporary_root = None
        finally:
            _cleanup_output(temporary_root, manifest)

    files = sum(entry.entry_type == ENTRY_FILE for entry in manifest.entries)
    directories = sum(entry.entry_type == ENTRY_DIRECTORY for entry in manifest.entries)
    original_size = sum(entry.size for entry in manifest.entries)
    kind = _kind_name(manifest.kind)
    decode_stats = StreamDecodeStats(
        format_version=MSC2_VERSION,
        archive_kind=kind,
        original_size=original_size,
        block_count=header.frame_count - 1,
        file_count=files,
        directory_count=directories,
        mode_distribution=dict(sorted(distribution.items())),
        hash_verified=True,
        elapsed_seconds=time.perf_counter() - started,
    )
    info = StreamArchiveInfo(
        format_version=MSC2_VERSION,
        archive_kind=kind,
        root_name=manifest.root_name,
        original_size=original_size,
        compressed_size=compressed_size,
        padded_plaintext_size=padded_size,
        archive_size=archive_size,
        padding_overhead=padded_size - (8 * header.frame_count) - compressed_size,
        chunk_size=header.chunk_size,
        block_count=header.frame_count - 1,
        file_count=files,
        directory_count=directories,
        mode_distribution=dict(sorted(distribution.items())),
        metadata_encrypted=True,
        hash_verified=True,
    )
    return decode_stats, info


def decode_stream_archive(
    archive_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    password: str | bytes,
    *,
    progress: ProgressCallback | None = None,
    max_output_size: int = DEFAULT_MAX_OUTPUT_SIZE,
    max_frame_count: int = DEFAULT_MAX_FRAME_COUNT,
) -> StreamDecodeStats:
    stats, _ = _decode_or_inspect(
        Path(archive_path),
        password,
        Path(output_path),
        progress,
        max_output_size,
        max_frame_count,
    )
    return stats


def inspect_stream_archive(
    archive_path: str | os.PathLike[str],
    password: str | bytes,
    *,
    max_output_size: int = DEFAULT_MAX_OUTPUT_SIZE,
    max_frame_count: int = DEFAULT_MAX_FRAME_COUNT,
) -> StreamArchiveInfo:
    _, info = _decode_or_inspect(
        Path(archive_path),
        password,
        None,
        None,
        max_output_size,
        max_frame_count,
    )
    return info


def is_msc2(path: str | os.PathLike[str]) -> bool:
    with Path(path).open("rb") as stream:
        return stream.read(4) == MSC2_MAGIC
