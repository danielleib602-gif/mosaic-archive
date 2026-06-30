from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from mosaic_archive.benchmark_publication import publish_benchmark
from mosaic_archive.corpus import generate_corpus


class VersionedBenchmarkPublicationTests(unittest.TestCase):
    def test_publication_is_versioned_verified_and_machine_readable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            corpus = root / "corpus"
            output = root / "publication"
            generate_corpus(corpus, seed=12, unit_size=1024)

            report = publish_benchmark(
                corpus,
                output,
                release="0.12.0",
                source_commit="test-commit",
                kdf_log_n=14,
            )

            persisted = json.loads((output / "report.json").read_text(encoding="utf-8"))
            markdown = (output / "report.md").read_text(encoding="utf-8")
            self.assertEqual(persisted, report)
            self.assertEqual(report["schema_version"], 1)
            self.assertEqual(report["release"], "0.12.0")
            self.assertEqual(report["package_version"], "0.12.0")
            self.assertEqual(report["source_commit"], "test-commit")
            self.assertEqual(report["corpus"]["version"], 1)
            self.assertTrue(report["mosaic"]["round_trip_verified"])
            self.assertTrue(report["comparisons"]["zip"]["verified"])
            self.assertTrue(report["comparisons"]["gzip"]["verified"])
            self.assertIn("compression-only baselines", markdown)
            self.assertIn("| Mosaic Archive |", markdown)
            self.assertIn("| gzip |", markdown)

    def test_workflow_installs_mature_tools_and_uploads_versioned_report(self) -> None:
        workflow = Path(".github/workflows/benchmark.yml").read_text(encoding="utf-8")

        self.assertIn("pull_request:\n    paths:", workflow)
        self.assertIn("apt-get install --yes zstd p7zip-full", workflow)
        self.assertIn("mosaic_archive.benchmark_publication", workflow)
        self.assertIn("--release 0.12.0", workflow)
        self.assertIn(
            "${{ github.event.pull_request.head.sha || github.sha }}",
            workflow,
        )
        self.assertIn("published-benchmark/report.json", workflow)
        self.assertIn("published-benchmark/report.md", workflow)


if __name__ == "__main__":
    unittest.main()
