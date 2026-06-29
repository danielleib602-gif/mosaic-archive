from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from mosaic_archive.reliability import run_large_file_soak, run_parser_fuzz


class ReliabilityHarnessTests(unittest.TestCase):
    def test_parser_fuzz_is_deterministic_and_covers_all_parser_classes(self) -> None:
        first = run_parser_fuzz(seed=20260629, cases=22)
        second = run_parser_fuzz(seed=20260629, cases=22)

        self.assertEqual(first, second)
        self.assertGreaterEqual(first.target_count, 11)
        self.assertEqual(first.executions, first.cases)
        self.assertEqual(
            first.executions,
            first.accepted_inputs + first.rejected_inputs,
        )

    def test_large_file_soak_streams_an_exact_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            summary = run_large_file_soak(
                Path(temp_dir),
                size_bytes=512 * 1024,
                seed=17,
            )

        self.assertEqual(summary.size_bytes, 512 * 1024)
        self.assertEqual(summary.source_sha256, summary.restored_sha256)
        self.assertEqual(summary.format_version, 6)
        self.assertTrue(summary.hash_verified)

    def test_module_cli_emits_machine_readable_fuzz_summary(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "mosaic_archive.reliability",
                "fuzz",
                "--seed",
                "31",
                "--cases",
                "4",
            ],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        summary = json.loads(completed.stdout)
        self.assertEqual(summary["seed"], 31)
        self.assertEqual(summary["cases"], 4)
        self.assertEqual(
            summary["executions"],
            summary["accepted_inputs"] + summary["rejected_inputs"],
        )


class ReliabilityWorkflowTests(unittest.TestCase):
    def test_scheduled_workflow_runs_bounded_fuzz_and_soak_jobs(self) -> None:
        workflow = Path(".github/workflows/reliability.yml").read_text(encoding="utf-8")

        self.assertIn("schedule:", workflow)
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn("timeout-minutes:", workflow)
        self.assertIn("mosaic_archive.reliability fuzz", workflow)
        self.assertIn("mosaic_archive.reliability soak", workflow)
        self.assertIn("--cases 25000", workflow)
        self.assertIn("--size-mib 256", workflow)


if __name__ == "__main__":
    unittest.main()
