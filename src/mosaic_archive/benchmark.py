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

from mosaic_archive.archive import decode_file, encode_file
from mosaic_archive.archive_api import decode_path, encode_path
from mosaic_archive.comparisons import ComparisonResult, compare_common_tools


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
    compare: bool = False,
) -> BenchmarkReport:
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
