"""End-to-end benchmark harness for the current Mosaic implementation."""

from __future__ import annotations

import hashlib
import os
import struct
import tempfile
import time
import tracemalloc
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, overload

from mosaic_archive.archive import decode_file, encode_file
from mosaic_archive.archive_api import decode_path, encode_path
from mosaic_archive.comparisons import ComparisonResult, compare_common_tools
from mosaic_archive.solid_archive_v2 import SolidArchiveV2EncodeStats


@dataclass(frozen=True, slots=True)
class BenchmarkReport:
    format_version: int
    archive_kind: str
    original_size: int
    compressed_size: int
    padded_plaintext_size: int
    archive_size: int
    compression_ratio: float
    archive_ratio: float
    padding_overhead: int
    encode_seconds: float
    decode_seconds: float
    encode_mib_per_second: float
    decode_mib_per_second: float
    peak_memory_bytes: int
    block_count: int
    file_count: int
    directory_count: int
    mode_distribution: dict[str, int]
    duplicate_blocks: int
    logical_chunk_count: int
    unique_chunk_count: int
    duplicate_chunk_count: int
    dedup_saved_bytes: int
    cross_file_duplicate_chunks: int
    cross_file_dedup_saved_bytes: int
    average_features: dict[str, float]
    round_trip_verified: bool
    comparisons: dict[str, ComparisonResult]


@dataclass(frozen=True, slots=True)
class SolidBenchmarkReport:
    format_name: str
    archive_kind: str
    original_size: int
    archive_size: int
    archive_ratio: float
    encode_seconds: float
    decode_seconds: float
    encode_mib_per_second: float
    decode_mib_per_second: float
    peak_memory_bytes: int
    unique_chunk_count: int
    frame_count: int
    maximum_frame_payload: int
    round_trip_verified: bool
    comparisons: dict[str, ComparisonResult]


def _speed(size: int, seconds: float) -> float:
    return (size / (1024 * 1024)) / seconds if seconds > 0 else 0.0


def _sha256(path: Path) -> bytes:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.digest()


def _tree_digest(path: Path) -> bytes:
    if path.is_file():
        return _sha256(path)
    digest = hashlib.sha256()
    for entry in sorted(path.rglob("*"), key=lambda item: item.relative_to(path).as_posix()):
        relative = entry.relative_to(path).as_posix().encode("utf-8")
        digest.update(b"D" if entry.is_dir() else b"F")
        digest.update(struct.pack(">I", len(relative)))
        digest.update(relative)
        if entry.is_file():
            digest.update(_sha256(entry))
    return digest.digest()


def benchmark_file(
    input_path: str | os.PathLike[str],
    password: str | bytes,
    *,
    chunk_size: int = 65_536,
    padding_size: int = 1024,
    kdf_log_n: int = 15,
) -> BenchmarkReport:
    source = Path(input_path)
    with tempfile.TemporaryDirectory(prefix="msc-benchmark-") as temporary_directory:
        root = Path(temporary_directory)
        archive = root / "benchmark.msc"
        restored = root / "restored.bin"

        encode_started = time.perf_counter()
        encode_stats = encode_file(
            source,
            archive,
            password,
            chunk_size=chunk_size,
            padding_size=padding_size,
            kdf_log_n=kdf_log_n,
        )
        encode_seconds = time.perf_counter() - encode_started
        decode_started = time.perf_counter()
        decode_file(archive, restored, password)
        decode_seconds = time.perf_counter() - decode_started
        verified = _sha256(source) == _sha256(restored)
        memory_archive = root / "memory.msc"
        memory_restored = root / "memory-restored.bin"
        tracemalloc.start()
        encode_file(
            source,
            memory_archive,
            password,
            chunk_size=chunk_size,
            padding_size=padding_size,
            kdf_log_n=kdf_log_n,
        )
        _, encode_peak = tracemalloc.get_traced_memory()
        tracemalloc.reset_peak()
        decode_file(memory_archive, memory_restored, password)
        _, decode_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        original_size = encode_stats.original_size
        return BenchmarkReport(
            format_version=1,
            archive_kind="file",
            original_size=original_size,
            compressed_size=encode_stats.compressed_size,
            padded_plaintext_size=encode_stats.padded_plaintext_size,
            archive_size=encode_stats.archive_size,
            compression_ratio=(
                encode_stats.compressed_size / original_size if original_size else 0.0
            ),
            archive_ratio=encode_stats.archive_size / original_size if original_size else 0.0,
            padding_overhead=encode_stats.padding_overhead,
            encode_seconds=encode_seconds,
            decode_seconds=decode_seconds,
            encode_mib_per_second=_speed(original_size, encode_seconds),
            decode_mib_per_second=_speed(original_size, decode_seconds),
            peak_memory_bytes=max(encode_peak, decode_peak),
            block_count=encode_stats.block_count,
            file_count=1,
            directory_count=0,
            mode_distribution=encode_stats.mode_distribution,
            duplicate_blocks=encode_stats.duplicate_blocks,
            logical_chunk_count=encode_stats.block_count,
            unique_chunk_count=encode_stats.block_count,
            duplicate_chunk_count=0,
            dedup_saved_bytes=0,
            cross_file_duplicate_chunks=0,
            cross_file_dedup_saved_bytes=0,
            average_features=encode_stats.average_features,
            round_trip_verified=verified,
            comparisons={},
        )


@overload
def benchmark_path(
    input_path: str | os.PathLike[str],
    password: str | bytes,
    *,
    chunk_size: int = 65_536,
    padding_size: int = 1024,
    kdf_log_n: int = 15,
    cdc_min_size: int | None = None,
    cdc_max_size: int | None = None,
    profile: str = "balanced",
    archive_format: Literal["stable"] = "stable",
    compare: bool = False,
) -> BenchmarkReport: ...


@overload
def benchmark_path(
    input_path: str | os.PathLike[str],
    password: str | bytes,
    *,
    chunk_size: int = 65_536,
    padding_size: int = 1024,
    kdf_log_n: int = 15,
    cdc_min_size: int | None = None,
    cdc_max_size: int | None = None,
    profile: str = "balanced",
    archive_format: Literal["solid"],
    compare: bool = False,
) -> SolidBenchmarkReport: ...


def benchmark_path(
    input_path: str | os.PathLike[str],
    password: str | bytes,
    *,
    chunk_size: int = 65_536,
    padding_size: int = 1024,
    kdf_log_n: int = 15,
    cdc_min_size: int | None = None,
    cdc_max_size: int | None = None,
    profile: str = "balanced",
    archive_format: str = "stable",
    compare: bool = False,
) -> BenchmarkReport | SolidBenchmarkReport:
    if archive_format == "solid":
        return _benchmark_solid_path(
            input_path,
            password,
            chunk_size=chunk_size,
            padding_size=padding_size,
            kdf_log_n=kdf_log_n,
            cdc_min_size=cdc_min_size,
            cdc_max_size=cdc_max_size,
            compare=compare,
        )
    if archive_format != "stable":
        raise ValueError(f"unknown archive format: {archive_format}")
    source = Path(input_path)
    with tempfile.TemporaryDirectory(prefix="msc2-benchmark-") as temporary_directory:
        root = Path(temporary_directory)
        archive = root / "benchmark.msc"
        restored = root / ("restored" if source.is_dir() else "restored.bin")

        encode_started = time.perf_counter()
        encode_stats = encode_path(
            source,
            archive,
            password,
            chunk_size=chunk_size,
            padding_size=padding_size,
            kdf_log_n=kdf_log_n,
            cdc_min_size=cdc_min_size,
            cdc_max_size=cdc_max_size,
            profile=profile,
        )
        encode_seconds = time.perf_counter() - encode_started
        decode_started = time.perf_counter()
        decode_path(archive, restored, password)
        decode_seconds = time.perf_counter() - decode_started
        verified = _tree_digest(source) == _tree_digest(restored)
        memory_archive = root / "memory.msc"
        memory_restored = root / (
            "memory-restored" if source.is_dir() else "memory-restored.bin"
        )
        tracemalloc.start()
        encode_path(
            source,
            memory_archive,
            password,
            chunk_size=chunk_size,
            padding_size=padding_size,
            kdf_log_n=kdf_log_n,
            cdc_min_size=cdc_min_size,
            cdc_max_size=cdc_max_size,
            profile=profile,
        )
        _, encode_peak = tracemalloc.get_traced_memory()
        tracemalloc.reset_peak()
        decode_path(memory_archive, memory_restored, password)
        _, decode_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        original_size = encode_stats.original_size
        comparisons = (
            compare_common_tools(source, root / "comparisons") if compare else {}
        )
        return BenchmarkReport(
            format_version=encode_stats.format_version,
            archive_kind=encode_stats.archive_kind,
            original_size=original_size,
            compressed_size=encode_stats.compressed_size,
            padded_plaintext_size=encode_stats.padded_plaintext_size,
            archive_size=encode_stats.archive_size,
            compression_ratio=(
                encode_stats.compressed_size / original_size if original_size else 0.0
            ),
            archive_ratio=encode_stats.archive_size / original_size if original_size else 0.0,
            padding_overhead=encode_stats.padding_overhead,
            encode_seconds=encode_seconds,
            decode_seconds=decode_seconds,
            encode_mib_per_second=_speed(original_size, encode_seconds),
            decode_mib_per_second=_speed(original_size, decode_seconds),
            peak_memory_bytes=max(encode_peak, decode_peak),
            block_count=encode_stats.block_count,
            file_count=encode_stats.file_count,
            directory_count=encode_stats.directory_count,
            mode_distribution=encode_stats.mode_distribution,
            duplicate_blocks=encode_stats.duplicate_blocks,
            logical_chunk_count=encode_stats.logical_chunk_count,
            unique_chunk_count=encode_stats.unique_chunk_count,
            duplicate_chunk_count=encode_stats.duplicate_chunk_count,
            dedup_saved_bytes=encode_stats.dedup_saved_bytes,
            cross_file_duplicate_chunks=encode_stats.cross_file_duplicate_chunks,
            cross_file_dedup_saved_bytes=encode_stats.cross_file_dedup_saved_bytes,
            average_features=encode_stats.average_features,
            round_trip_verified=verified,
            comparisons=comparisons,
        )


def _benchmark_solid_path(
    input_path: str | os.PathLike[str],
    password: str | bytes,
    *,
    chunk_size: int,
    padding_size: int,
    kdf_log_n: int,
    cdc_min_size: int | None,
    cdc_max_size: int | None,
    compare: bool,
) -> SolidBenchmarkReport:
    source = Path(input_path)
    with tempfile.TemporaryDirectory(prefix="msr2-benchmark-") as temporary_directory:
        root = Path(temporary_directory)
        archive = root / "benchmark.msr"
        restored = root / ("restored" if source.is_dir() else "restored.bin")

        def encode(destination: Path) -> SolidArchiveV2EncodeStats:
            return encode_path(
                source,
                destination,
                password,
                chunk_size=chunk_size,
                padding_size=padding_size,
                kdf_log_n=kdf_log_n,
                cdc_min_size=cdc_min_size,
                cdc_max_size=cdc_max_size,
                archive_format="solid",
            )

        encode_started = time.perf_counter()
        encode_stats = encode(archive)
        encode_seconds = time.perf_counter() - encode_started
        decode_started = time.perf_counter()
        decode_path(archive, restored, password)
        decode_seconds = time.perf_counter() - decode_started
        verified = _tree_digest(source) == _tree_digest(restored)

        memory_archive = root / "memory.msr"
        memory_restored = root / (
            "memory-restored" if source.is_dir() else "memory-restored.bin"
        )
        tracemalloc.start()
        encode(memory_archive)
        _, encode_peak = tracemalloc.get_traced_memory()
        tracemalloc.reset_peak()
        decode_path(memory_archive, memory_restored, password)
        _, decode_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        original_size = encode_stats.original_size
        comparisons = (
            compare_common_tools(
                source,
                root / "comparisons",
                include_encrypted_7zip=True,
            )
            if compare
            else {}
        )
        return SolidBenchmarkReport(
            format_name=encode_stats.format_name,
            archive_kind="file" if source.is_file() else "folder",
            original_size=original_size,
            archive_size=encode_stats.archive_size,
            archive_ratio=(
                encode_stats.archive_size / original_size if original_size else 0.0
            ),
            encode_seconds=encode_seconds,
            decode_seconds=decode_seconds,
            encode_mib_per_second=_speed(original_size, encode_seconds),
            decode_mib_per_second=_speed(original_size, decode_seconds),
            peak_memory_bytes=max(encode_peak, decode_peak),
            unique_chunk_count=encode_stats.unique_chunk_count,
            frame_count=encode_stats.frame_count,
            maximum_frame_payload=encode_stats.maximum_frame_payload,
            round_trip_verified=verified,
            comparisons=comparisons,
        )
