from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from mosaic_archive.benchmark_publication import (
    _aggregate_comparisons,
    _aggregate_runs,
    publish_benchmark,
)
from mosaic_archive.corpus import generate_corpus


class VersionedBenchmarkPublicationTests(unittest.TestCase):
    def test_encrypted_7zip_size_is_aggregated_as_a_randomized_distribution(
        self,
    ) -> None:
        def result(size: int) -> dict[str, object]:
            return {
                "available": True,
                "supported": True,
                "archive_size": size,
                "ratio": size / 1000,
                "encode_seconds": 0.1,
                "decode_seconds": 0.1,
                "verified": True,
                "note": "randomized encrypted archive",
            }

        comparisons = _aggregate_comparisons(
            [
                {"7z-encrypted": result(112)},
                {"7z-encrypted": result(96)},
                {"7z-encrypted": result(104)},
            ]
        )

        encrypted = comparisons["7z-encrypted"]
        self.assertEqual(encrypted["archive_size"], 104)
        self.assertEqual(
            encrypted["archive_size_distribution"],
            {
                "samples": [112, 96, 104],
                "minimum": 96,
                "median": 104,
                "maximum": 112,
            },
        )

    def test_committed_v0_12_report_is_complete_and_verified(self) -> None:
        report = json.loads(
            Path("benchmarks/v0.12.0/report.json").read_text(encoding="utf-8")
        )

        self.assertEqual(report["release"], "0.12.0")
        self.assertEqual(report["schema_version"], 1)
        self.assertTrue(report["mosaic"]["round_trip_verified"])
        self.assertEqual(set(report["comparisons"]), {"zip", "gzip", "zstd", "7z"})
        self.assertTrue(
            all(result["verified"] for result in report["comparisons"].values())
        )

    def test_committed_v0_35_report_has_repeated_category_evidence(self) -> None:
        report = json.loads(
            Path("benchmarks/v0.35.0/report.json").read_text(encoding="utf-8")
        )

        self.assertEqual(report["release"], "0.35.0")
        self.assertEqual(report["schema_version"], 2)
        self.assertEqual(report["corpus"]["version"], 2)
        self.assertEqual(report["corpus"]["category_count"], 13)
        self.assertEqual(report["measurement"]["independent_runs"], 5)
        self.assertEqual(
            len(report["mosaic"]["timing"]["encode_seconds"]["samples"]),
            5,
        )
        self.assertTrue(report["mosaic"]["round_trip_verified"])
        self.assertTrue(
            all(
                result["mosaic"]["round_trip_verified"]
                for result in report["categories"].values()
            )
        )
        self.assertLess(report["mosaic_size_delta_bytes"]["zip"], 0)

    def test_publication_is_versioned_verified_and_machine_readable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            corpus = root / "corpus"
            output = root / "publication"
            generate_corpus(corpus, seed=12, unit_size=1024)

            report = publish_benchmark(
                corpus,
                output,
                release="0.39.0",
                source_commit="test-commit",
                kdf_log_n=14,
                repeats=3,
                archive_format="solid",
            )

            persisted = json.loads((output / "report.json").read_text(encoding="utf-8"))
            markdown = (output / "report.md").read_text(encoding="utf-8")
            self.assertEqual(persisted, report)
            self.assertEqual(report["schema_version"], 2)
            self.assertEqual(report["release"], "0.39.0")
            self.assertEqual(report["package_version"], "0.39.0")
            self.assertEqual(report["source_commit"], "test-commit")
            self.assertEqual(report["corpus"]["version"], 2)
            self.assertEqual(report["corpus"]["category_count"], 13)
            self.assertEqual(report["corpus"]["file_count"], 78)
            self.assertLess(
                report["corpus"]["declared_data_bytes"],
                report["corpus"]["benchmark_input_bytes"],
            )
            self.assertEqual(report["measurement"]["independent_runs"], 3)
            self.assertEqual(
                len(report["mosaic"]["timing"]["encode_seconds"]["samples"]),
                3,
            )
            self.assertTrue(report["mosaic"]["round_trip_verified"])
            self.assertTrue(report["comparisons"]["zip"]["verified"])
            self.assertTrue(report["comparisons"]["gzip"]["verified"])
            self.assertIn("7z-encrypted", report["comparisons"])
            self.assertIn("zip", report["mosaic_size_delta_bytes"])
            self.assertEqual(
                set(report["categories"]),
                {
                    "dedup",
                    "empty",
                    "image-like",
                    "numeric",
                    "precompressed",
                    "random",
                    "source",
                    "sparse",
                    "structured",
                    "tabular",
                    "text",
                    "tiny-files",
                    "unicode",
                },
            )
            self.assertTrue(
                all(
                    category["mosaic"]["round_trip_verified"]
                    for category in report["categories"].values()
                )
            )
            self.assertIn("compression-only baselines", markdown)
            self.assertIn("| Mosaic Archive (MSR2) |", markdown)
            self.assertIn("| gzip |", markdown)
            self.assertIn("## Category results", markdown)

    def test_repeated_runs_publish_median_raw_samples_and_stable_sizes(self) -> None:
        runs = [
            {
                "archive_size": 100,
                "original_size": 200,
                "archive_ratio": 0.5,
                "encode_seconds": 3.0,
                "decode_seconds": 0.3,
                "encode_mib_per_second": 1.0,
                "decode_mib_per_second": 10.0,
                "peak_memory_bytes": 10,
                "round_trip_verified": True,
            },
            {
                "archive_size": 100,
                "original_size": 200,
                "archive_ratio": 0.5,
                "encode_seconds": 1.0,
                "decode_seconds": 0.1,
                "encode_mib_per_second": 3.0,
                "decode_mib_per_second": 30.0,
                "peak_memory_bytes": 30,
                "round_trip_verified": True,
            },
            {
                "archive_size": 100,
                "original_size": 200,
                "archive_ratio": 0.5,
                "encode_seconds": 2.0,
                "decode_seconds": 0.2,
                "encode_mib_per_second": 2.0,
                "decode_mib_per_second": 20.0,
                "peak_memory_bytes": 20,
                "round_trip_verified": True,
            },
        ]

        aggregate = _aggregate_runs(runs)

        self.assertEqual(aggregate["encode_seconds"], 2.0)
        self.assertEqual(aggregate["decode_seconds"], 0.2)
        self.assertEqual(
            aggregate["timing"]["encode_seconds"]["samples"],
            [3.0, 1.0, 2.0],
        )
        self.assertEqual(aggregate["peak_memory_bytes"], 30)
        self.assertEqual(
            aggregate["timing"]["encode_seconds"]["median_absolute_deviation"],
            1.0,
        )
        changed_size = [dict(run) for run in runs]
        changed_size[-1]["archive_size"] = 101
        with self.assertRaisesRegex(ValueError, "archive_size"):
            _aggregate_runs(changed_size)

    def test_encrypted_baseline_scorecard_records_size_and_speed_tradeoff(self) -> None:
        scorecard = json.loads(
            Path(".ecc/benchmarks/msc-v0.23-encrypted-7zip.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(scorecard["msr2"]["archive_bytes"], 276115)
        self.assertEqual(scorecard["seven_zip_encrypted"]["archive_bytes"], 292912)
        self.assertEqual(scorecard["margin_bytes"], 16797)
        self.assertGreater(
            scorecard["msr2"]["encode_seconds"],
            scorecard["seven_zip_encrypted"]["encode_seconds"],
        )

    def test_single_pass_scorecard_preserves_size_and_improves_hosted_time(self) -> None:
        scorecard = json.loads(
            Path(".ecc/benchmarks/msc-v0.24-single-pass.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(scorecard["after"]["archive_bytes"], 276115)
        self.assertEqual(scorecard["after"]["compression_passes"], 1)
        self.assertLess(
            scorecard["after"]["encode_seconds"],
            scorecard["before"]["encode_seconds"],
        )

    def test_feature_router_scorecard_preserves_size_without_trials(self) -> None:
        scorecard = json.loads(
            Path(".ecc/benchmarks/msc-v0.25-feature-router.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(scorecard["after"]["archive_bytes"], 276115)
        self.assertEqual(scorecard["after"]["routing_trial_compressions"], 0)
        self.assertLess(
            scorecard["after"]["encode_seconds"],
            scorecard["before"]["encode_seconds"],
        )

    def test_single_chunking_pass_scorecard_preserves_size_and_improves_time(
        self,
    ) -> None:
        scorecard = json.loads(
            Path(".ecc/benchmarks/msc-v0.26-single-cdc-pass.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(scorecard["after"]["archive_bytes"], 276115)
        self.assertEqual(scorecard["after"]["chunking_passes"], 1)
        self.assertLess(
            scorecard["after"]["encode_seconds"],
            scorecard["before"]["encode_seconds"],
        )

    def test_focused_router_scorecard_preserves_size_and_improves_time(self) -> None:
        scorecard = json.loads(
            Path(".ecc/benchmarks/msc-v0.27-router-features.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(scorecard["after"]["archive_bytes"], 276115)
        self.assertFalse(scorecard["after"]["general_block_analysis"])
        self.assertLess(
            scorecard["after"]["encode_seconds"],
            scorecard["before"]["encode_seconds"],
        )

    def test_inline_buzhash_scorecard_preserves_size_and_improves_time(self) -> None:
        scorecard = json.loads(
            Path(".ecc/benchmarks/msc-v0.28-inline-buzhash.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(scorecard["after"]["archive_bytes"], 276115)
        self.assertFalse(scorecard["after"]["generic_hot_loop_rotation"])
        self.assertLess(
            scorecard["after"]["encode_seconds"],
            scorecard["before"]["encode_seconds"],
        )

    def test_lazy_buzhash_scorecard_preserves_size_and_improves_time(self) -> None:
        scorecard = json.loads(
            Path(".ecc/benchmarks/msc-v0.29-lazy-buzhash.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(scorecard["after"]["archive_bytes"], 276115)
        self.assertEqual(scorecard["after"]["subminimum_hash_lookups"], 0)
        self.assertLess(
            scorecard["after"]["encode_seconds"],
            scorecard["before"]["encode_seconds"],
        )

    def test_compact_metadata_scorecard_reports_size_win_and_speed_cost(self) -> None:
        scorecard = json.loads(
            Path(".ecc/benchmarks/msc-v0.30-compact-metadata.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(scorecard["after"]["archive_bytes"], 275859)
        self.assertTrue(scorecard["after"]["legacy_metadata_readable"])
        self.assertLess(
            scorecard["after"]["archive_bytes"],
            scorecard["before"]["archive_bytes"],
        )
        self.assertGreater(scorecard["encode_regression_percent"], 0)

    def test_block_buffered_cdc_scorecard_preserves_size_and_improves_time(
        self,
    ) -> None:
        scorecard = json.loads(
            Path(".ecc/benchmarks/msc-v0.31-block-buffered-cdc.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(scorecard["after"]["archive_bytes"], 275859)
        self.assertEqual(scorecard["after"]["per_byte_chunk_appends"], 0)
        self.assertLess(
            scorecard["after"]["encode_seconds"],
            scorecard["before"]["encode_seconds"],
        )

    def test_gear_cdc_scorecard_preserves_size_and_improves_time(self) -> None:
        scorecard = json.loads(
            Path(".ecc/benchmarks/msc-v0.32-gear-cdc.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(scorecard["after"]["archive_bytes"], 275859)
        self.assertLessEqual(
            scorecard["after"]["maximum_frame_payload"],
            scorecard["before"]["maximum_frame_payload"],
        )
        self.assertLess(
            scorecard["after"]["encode_seconds"],
            scorecard["before"]["encode_seconds"],
        )

    def test_workflow_installs_mature_tools_and_uploads_versioned_report(self) -> None:
        workflow = Path(".github/workflows/benchmark.yml").read_text(encoding="utf-8")

        self.assertIn("pull_request:\n    paths:", workflow)
        self.assertIn('"src/mosaic_archive/cdc.py"', workflow)
        self.assertIn('"src/mosaic_archive/solid_archive_v2.py"', workflow)
        self.assertIn('"src/mosaic_archive/solid_frames.py"', workflow)
        self.assertIn('"src/mosaic_archive/solid_research.py"', workflow)
        self.assertIn("apt-get install --yes zstd p7zip-full", workflow)
        self.assertIn("mosaic_archive.benchmark_publication", workflow)
        self.assertIn("--release 0.39.0", workflow)
        self.assertIn("--repeats 5", workflow)
        self.assertIn("--format solid", workflow)
        self.assertIn(
            "${{ github.event.pull_request.head.sha || github.sha }}",
            workflow,
        )
        self.assertIn("published-benchmark/report.json", workflow)
        self.assertIn("published-benchmark/report.md", workflow)
        self.assertIn("mosaic-benchmark-v0.39.0", workflow)


if __name__ == "__main__":
    unittest.main()
