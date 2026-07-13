from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mosaic_archive.benchmark import (
    BenchmarkReport,
    SolidBenchmarkReport,
    benchmark_file,
    benchmark_path,
)
from mosaic_archive.comparisons import ComparisonResult


class BenchmarkHarnessTests(unittest.TestCase):
    def test_benchmark_file_reports_verified_math_and_options(self) -> None:
        payload = b"0123456789" * 10
        stats = SimpleNamespace(
            original_size=len(payload),
            compressed_size=40,
            padded_plaintext_size=48,
            archive_size=64,
            padding_overhead=8,
            block_count=3,
            mode_distribution={"raw": 1, "zlib": 2},
            duplicate_blocks=1,
            average_features={"entropy": 2.5},
        )

        def fake_encode(
            source: Path,
            destination: Path,
            _password: str,
            **_options: object,
        ) -> object:
            destination.write_bytes(source.read_bytes())
            return stats

        def fake_decode(archive: Path, destination: Path, _password: str) -> None:
            destination.write_bytes(archive.read_bytes())

        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "source.bin"
            source.write_bytes(payload)
            with (
                patch("mosaic_archive.benchmark.encode_file", side_effect=fake_encode) as encode,
                patch("mosaic_archive.benchmark.decode_file", side_effect=fake_decode) as decode,
                patch(
                    "mosaic_archive.benchmark.time.perf_counter",
                    side_effect=(10.0, 12.0, 20.0, 24.0),
                ),
                patch("mosaic_archive.benchmark.tracemalloc.start"),
                patch("mosaic_archive.benchmark.tracemalloc.reset_peak"),
                patch("mosaic_archive.benchmark.tracemalloc.stop"),
                patch(
                    "mosaic_archive.benchmark.tracemalloc.get_traced_memory",
                    side_effect=((0, 111), (0, 222)),
                ),
            ):
                report = benchmark_file(
                    source,
                    "password",
                    chunk_size=17,
                    padding_size=19,
                    kdf_log_n=4,
                )

        self.assertIsInstance(report, BenchmarkReport)
        self.assertTrue(report.round_trip_verified)
        self.assertEqual(report.archive_kind, "file")
        self.assertEqual(report.compression_ratio, 0.4)
        self.assertEqual(report.archive_ratio, 0.64)
        self.assertEqual(report.encode_seconds, 2.0)
        self.assertEqual(report.decode_seconds, 4.0)
        self.assertAlmostEqual(report.encode_mib_per_second, len(payload) / (1024 * 1024) / 2)
        self.assertAlmostEqual(report.decode_mib_per_second, len(payload) / (1024 * 1024) / 4)
        self.assertEqual(report.peak_memory_bytes, 222)
        self.assertEqual(report.logical_chunk_count, 3)
        self.assertEqual(report.unique_chunk_count, 3)
        self.assertEqual(report.duplicate_chunk_count, 0)
        self.assertEqual(encode.call_count, 2)
        self.assertEqual(decode.call_count, 2)
        for invocation in encode.call_args_list:
            self.assertEqual(
                invocation.kwargs,
                {"chunk_size": 17, "padding_size": 19, "kdf_log_n": 4},
            )

    def test_stable_path_propagates_options_comparisons_and_stats(self) -> None:
        payload = b"stable-input"
        stats = SimpleNamespace(
            format_version=2,
            archive_kind="file",
            original_size=len(payload),
            compressed_size=6,
            padded_plaintext_size=8,
            archive_size=16,
            padding_overhead=2,
            block_count=4,
            file_count=1,
            directory_count=0,
            mode_distribution={"zlib": 4},
            duplicate_blocks=1,
            logical_chunk_count=4,
            unique_chunk_count=3,
            duplicate_chunk_count=1,
            dedup_saved_bytes=3,
            cross_file_duplicate_chunks=0,
            cross_file_dedup_saved_bytes=0,
            average_features={"entropy": 1.25},
        )
        comparison = ComparisonResult(True, True, 5, 0.5, 0.1, 0.2, True, "fake")

        def fake_encode(
            source: Path,
            destination: Path,
            _password: bytes,
            **_options: object,
        ) -> object:
            destination.write_bytes(source.read_bytes())
            return stats

        def fake_decode(archive: Path, destination: Path, _password: bytes) -> None:
            destination.write_bytes(archive.read_bytes())

        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "source.bin"
            source.write_bytes(payload)
            with (
                patch("mosaic_archive.benchmark.encode_path", side_effect=fake_encode) as encode,
                patch("mosaic_archive.benchmark.decode_path", side_effect=fake_decode),
                patch(
                    "mosaic_archive.benchmark.compare_common_tools",
                    return_value={"fake": comparison},
                ) as compare,
                patch(
                    "mosaic_archive.benchmark.time.perf_counter",
                    side_effect=(2.0, 3.0, 7.0, 9.0),
                ),
                patch("mosaic_archive.benchmark.tracemalloc.start"),
                patch("mosaic_archive.benchmark.tracemalloc.reset_peak"),
                patch("mosaic_archive.benchmark.tracemalloc.stop"),
                patch(
                    "mosaic_archive.benchmark.tracemalloc.get_traced_memory",
                    side_effect=((0, 90), (0, 80)),
                ),
            ):
                report = benchmark_path(
                    source,
                    b"password",
                    chunk_size=23,
                    padding_size=29,
                    kdf_log_n=5,
                    cdc_min_size=7,
                    cdc_max_size=31,
                    profile="maximum",
                    compare=True,
                )

        self.assertIsInstance(report, BenchmarkReport)
        self.assertTrue(report.round_trip_verified)
        self.assertEqual(report.comparisons, {"fake": comparison})
        self.assertEqual(report.compression_ratio, 6 / len(payload))
        self.assertEqual(report.archive_ratio, 16 / len(payload))
        self.assertEqual(report.peak_memory_bytes, 90)
        self.assertEqual(report.unique_chunk_count, 3)
        self.assertEqual(report.dedup_saved_bytes, 3)
        self.assertEqual(encode.call_count, 2)
        for invocation in encode.call_args_list:
            self.assertEqual(
                invocation.kwargs,
                {
                    "chunk_size": 23,
                    "padding_size": 29,
                    "kdf_log_n": 5,
                    "cdc_min_size": 7,
                    "cdc_max_size": 31,
                    "profile": "maximum",
                },
            )
        compare.assert_called_once()
        comparison_args, comparison_kwargs = compare.call_args
        self.assertEqual(comparison_args[0], source)
        self.assertEqual(comparison_args[1].name, "comparisons")
        self.assertEqual(comparison_kwargs, {})

    def test_solid_path_propagates_options_and_compares_to_encrypted_7zip(self) -> None:
        stats = SimpleNamespace(
            format_name="MSR2",
            original_size=6,
            archive_size=3,
            unique_chunk_count=2,
            frame_count=4,
            maximum_frame_payload=9,
            routing_trial_compressions=7,
            routing_reuse_probes=5,
        )
        comparison = ComparisonResult(True, True, 4, 2 / 3, 0.1, 0.2, True, "fake")

        def fake_encode(
            source: Path,
            destination: Path,
            _password: str,
            **_options: object,
        ) -> object:
            self.assertTrue(source.is_dir())
            destination.write_bytes(b"msr")
            return stats

        def fake_decode(_archive: Path, destination: Path, _password: str) -> None:
            shutil.copytree(source, destination)

        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "source"
            source.mkdir()
            (source / "a.txt").write_bytes(b"abc")
            nested = source / "nested"
            nested.mkdir()
            (nested / "b.txt").write_bytes(b"def")
            with (
                patch("mosaic_archive.benchmark.encode_path", side_effect=fake_encode) as encode,
                patch("mosaic_archive.benchmark.decode_path", side_effect=fake_decode),
                patch(
                    "mosaic_archive.benchmark.compare_common_tools",
                    return_value={"fake": comparison},
                ) as compare,
                patch(
                    "mosaic_archive.benchmark.time.perf_counter",
                    side_effect=(10.0, 10.5, 20.0, 22.0),
                ),
                patch("mosaic_archive.benchmark.tracemalloc.start"),
                patch("mosaic_archive.benchmark.tracemalloc.reset_peak"),
                patch("mosaic_archive.benchmark.tracemalloc.stop"),
                patch(
                    "mosaic_archive.benchmark.tracemalloc.get_traced_memory",
                    side_effect=((0, 40), (0, 60)),
                ),
            ):
                report = benchmark_path(
                    source,
                    "password",
                    chunk_size=41,
                    padding_size=43,
                    kdf_log_n=6,
                    cdc_min_size=11,
                    cdc_max_size=47,
                    archive_format="solid",
                    compare=True,
                )

        self.assertIsInstance(report, SolidBenchmarkReport)
        self.assertEqual(report.format_name, "MSR2")
        self.assertEqual(report.archive_kind, "folder")
        self.assertTrue(report.round_trip_verified)
        self.assertEqual(report.archive_ratio, 0.5)
        self.assertEqual(report.encode_seconds, 0.5)
        self.assertEqual(report.decode_seconds, 2.0)
        self.assertEqual(report.peak_memory_bytes, 60)
        self.assertEqual(report.comparisons, {"fake": comparison})
        self.assertEqual(encode.call_count, 2)
        for invocation in encode.call_args_list:
            self.assertEqual(
                invocation.kwargs,
                {
                    "chunk_size": 41,
                    "padding_size": 43,
                    "kdf_log_n": 6,
                    "cdc_min_size": 11,
                    "cdc_max_size": 47,
                    "archive_format": "solid",
                },
            )
        compare.assert_called_once()
        comparison_args, comparison_kwargs = compare.call_args
        self.assertEqual(comparison_args[0], source)
        self.assertEqual(comparison_args[1].name, "comparisons")
        self.assertEqual(comparison_kwargs, {"include_encrypted_7zip": True})

    def test_unknown_path_format_fails_before_work_begins(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown archive format: future"):
            benchmark_path("unused", "password", archive_format="future")  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
