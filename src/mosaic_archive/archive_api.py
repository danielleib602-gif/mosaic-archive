"""Version-dispatching archive API used by the CLI."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal, overload

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
from mosaic_archive.dedup_format import MSC3_MAGIC, MSC4_MAGIC, MSC5_MAGIC, MSC6_MAGIC
from mosaic_archive.exceptions import ArchiveFormatError
from mosaic_archive.solid_archive_v2 import (
    MSR2_MAGIC,
    SolidArchiveV2DecodeStats,
    SolidArchiveV2EncodeStats,
    decode_solid_archive_v2,
    encode_solid_archive_v2,
    inspect_solid_archive_v2,
)
from mosaic_archive.stream_archive import (
    ProgressCallback,
    StreamArchiveInfo,
    StreamDecodeStats,
    decode_stream_archive,
    inspect_stream_archive,
)
from mosaic_archive.stream_format import MSC2_MAGIC


@overload
def encode_path(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    password: str | bytes,
    *,
    chunk_size: int = 65_536,
    padding_size: int = 1024,
    kdf_log_n: int = 15,
    cdc_min_size: int | None = None,
    cdc_max_size: int | None = None,
    profile: str = "balanced",
    archive_format: Literal["stable"] = "stable",
    progress: ProgressCallback | None = None,
) -> DedupEncodeStats: ...


@overload
def encode_path(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    password: str | bytes,
    *,
    chunk_size: int = 65_536,
    padding_size: int = 1024,
    kdf_log_n: int = 15,
    cdc_min_size: int | None = None,
    cdc_max_size: int | None = None,
    profile: str = "balanced",
    archive_format: Literal["solid"],
    progress: ProgressCallback | None = None,
) -> SolidArchiveV2EncodeStats: ...


def encode_path(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    password: str | bytes,
    *,
    chunk_size: int = 65_536,
    padding_size: int = 1024,
    kdf_log_n: int = 15,
    cdc_min_size: int | None = None,
    cdc_max_size: int | None = None,
    profile: str = "balanced",
    archive_format: str = "stable",
    progress: ProgressCallback | None = None,
) -> DedupEncodeStats | SolidArchiveV2EncodeStats:
    minimum = cdc_min_size if cdc_min_size is not None else max(64, chunk_size // 4)
    maximum = (
        cdc_max_size
        if cdc_max_size is not None
        else min(16 * 1024 * 1024, chunk_size * 4)
    )
    config = ChunkingConfig(minimum, chunk_size, maximum)
    if archive_format == "solid":
        return encode_solid_archive_v2(
            input_path,
            output_path,
            password,
            config=config,
            padding_size=padding_size,
            kdf_log_n=kdf_log_n,
        )
    if archive_format != "stable":
        raise ValueError(f"unknown archive format: {archive_format}")
    return encode_dedup_archive(
        input_path,
        output_path,
        password,
        config=config,
        padding_size=padding_size,
        kdf_log_n=kdf_log_n,
        profile=profile,
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
) -> DecodeStats | StreamDecodeStats | DedupDecodeStats | SolidArchiveV2DecodeStats:
    magic = _magic(archive_path)
    if magic == MSR2_MAGIC:
        return decode_solid_archive_v2(archive_path, output_path, password)
    if magic in {MSC3_MAGIC, MSC4_MAGIC, MSC5_MAGIC, MSC6_MAGIC}:
        return decode_dedup_archive(
            archive_path, output_path, password, progress=progress
        )
    if magic == MSC2_MAGIC:
        return decode_stream_archive(
            archive_path, output_path, password, progress=progress
        )
    if magic == MAGIC:
        return decode_file(archive_path, output_path, password)
    raise ArchiveFormatError(
        "not a supported Mosaic Archive (expected MSC1 through MSC6 or MSR2)"
    )


def inspect_path(
    archive_path: str | os.PathLike[str],
    password: str | bytes,
) -> ArchiveInfo | StreamArchiveInfo | DedupArchiveInfo | SolidArchiveV2DecodeStats:
    magic = _magic(archive_path)
    if magic == MSR2_MAGIC:
        return inspect_solid_archive_v2(archive_path, password)
    if magic in {MSC3_MAGIC, MSC4_MAGIC, MSC5_MAGIC, MSC6_MAGIC}:
        return inspect_dedup_archive(archive_path, password)
    if magic == MSC2_MAGIC:
        return inspect_stream_archive(archive_path, password)
    if magic == MAGIC:
        return inspect_archive(archive_path, password)
    raise ArchiveFormatError(
        "not a supported Mosaic Archive (expected MSC1 through MSC6 or MSR2)"
    )
