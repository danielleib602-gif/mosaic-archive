"""Version-dispatching archive API used by the CLI."""

from __future__ import annotations

import os
from pathlib import Path

from mosaic_archive.archive import (
    ArchiveInfo,
    DecodeStats,
    decode_file,
    inspect_archive,
)
from mosaic_archive.cdc import ChunkingConfig
from mosaic_archive.container_format import MAGIC
from mosaic_archive.dedup_archive import (
    DedupArchiveInfo,
    DedupDecodeStats,
    DedupEncodeStats,
    decode_dedup_archive,
    encode_dedup_archive,
    inspect_dedup_archive,
)
from mosaic_archive.dedup_format import MSC3_MAGIC
from mosaic_archive.exceptions import ArchiveFormatError
from mosaic_archive.stream_archive import (
    ProgressCallback,
    StreamArchiveInfo,
    StreamDecodeStats,
    decode_stream_archive,
    inspect_stream_archive,
)
from mosaic_archive.stream_format import MSC2_MAGIC


def encode_path(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    password: str | bytes,
    *,
    chunk_size: int = 65_536,
    padding_size: int = 4096,
    kdf_log_n: int = 15,
    cdc_min_size: int | None = None,
    cdc_max_size: int | None = None,
    progress: ProgressCallback | None = None,
) -> DedupEncodeStats:
    minimum = cdc_min_size if cdc_min_size is not None else max(64, chunk_size // 4)
    maximum = (
        cdc_max_size
        if cdc_max_size is not None
        else min(16 * 1024 * 1024, chunk_size * 4)
    )
    return encode_dedup_archive(
        input_path,
        output_path,
        password,
        config=ChunkingConfig(minimum, chunk_size, maximum),
        padding_size=padding_size,
        kdf_log_n=kdf_log_n,
        progress=progress,
    )


def _magic(path: str | os.PathLike[str]) -> bytes:
    with Path(path).open("rb") as stream:
        return stream.read(4)


def decode_path(
    archive_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    password: str | bytes,
    *,
    progress: ProgressCallback | None = None,
) -> DecodeStats | StreamDecodeStats | DedupDecodeStats:
    magic = _magic(archive_path)
    if magic == MSC3_MAGIC:
        return decode_dedup_archive(
            archive_path, output_path, password, progress=progress
        )
    if magic == MSC2_MAGIC:
        return decode_stream_archive(
            archive_path, output_path, password, progress=progress
        )
    if magic == MAGIC:
        return decode_file(archive_path, output_path, password)
    raise ArchiveFormatError("not a supported Mosaic Archive (expected MSC1, MSC2, or MSC3)")


def inspect_path(
    archive_path: str | os.PathLike[str],
    password: str | bytes,
) -> ArchiveInfo | StreamArchiveInfo | DedupArchiveInfo:
    magic = _magic(archive_path)
    if magic == MSC3_MAGIC:
        return inspect_dedup_archive(archive_path, password)
    if magic == MSC2_MAGIC:
        return inspect_stream_archive(archive_path, password)
    if magic == MAGIC:
        return inspect_archive(archive_path, password)
    raise ArchiveFormatError("not a supported Mosaic Archive (expected MSC1, MSC2, or MSC3)")
