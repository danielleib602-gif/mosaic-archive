from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mosaic_archive.reliability import run_large_file_soak, run_parser_fuzz


class ReliabilityHarnessTests(unittest.TestCase):
    def test_parser_fuzz_is_deterministic_and_covers_all_parser_classes(self) -> None:
        first = run_parser_fuzz(seed=20260629, cases=22)
        second = run_parser_fuzz(seed=20260629, cases=22)

        self.assertEqual(first, second)
        self.assertEqual(first.target_count, 14)
        self.assertEqual(first.executions, first.cases)
        self.assertEqual(
            first.executions,
            first.accepted_inputs + first.rejected_inputs,
        )

    def test_large_file_soak_streams_an_exact_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            work_dir = Path(temp_dir)
            summary = run_large_file_soak(
                work_dir,
                size_bytes=512 * 1024,
                seed=17,
            )

            self.assertFalse((work_dir / "soak-source.bin").exists())
            self.assertTrue((work_dir / "soak-archive.msc").is_file())
            self.assertEqual(
                (work_dir / "soak-restored.bin").stat().st_size,
                512 * 1024,
            )

        self.assertEqual(summary.size_bytes, 512 * 1024)
        self.assertEqual(summary.source_sha256, summary.restored_sha256)
        self.assertEqual(summary.format_version, 6)
        self.assertTrue(summary.hash_verified)
        self.assertTrue(summary.source_released_before_decode)
        self.assertEqual(
            summary.archive_overhead_bytes,
            summary.archive_size - summary.size_bytes,
        )
        self.assertEqual(
            summary.peak_payload_bytes,
            summary.archive_size + summary.size_bytes,
        )
        self.assertGreaterEqual(summary.logical_chunk_count, summary.unique_chunk_count)
        self.assertGreater(summary.unique_chunk_count, 0)
        for duration in (
            summary.generation_seconds,
            summary.encode_seconds,
            summary.decode_seconds,
            summary.verify_seconds,
        ):
            self.assertGreaterEqual(duration, 0.0)

    def test_large_file_soak_fails_before_writes_when_disk_is_insufficient(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            work_dir = Path(temp_dir) / "soak"
            with (
                patch(
                    "mosaic_archive.reliability.shutil.disk_usage",
                    return_value=SimpleNamespace(free=0),
                ),
                self.assertRaisesRegex(OSError, "requires at least"),
            ):
                run_large_file_soak(work_dir, size_bytes=512 * 1024, seed=17)

            self.assertEqual(list(work_dir.iterdir()), [])

    def test_large_file_soak_reclaims_its_stale_outputs_before_disk_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            work_dir = Path(temp_dir)
            stale_paths = tuple(
                work_dir / name
                for name in (
                    "soak-source.bin",
                    "soak-archive.msc",
                    "soak-restored.bin",
                )
            )
            for path in stale_paths:
                path.write_bytes(b"stale")

            def disk_usage_after_cleanup(_path: Path) -> SimpleNamespace:
                self.assertTrue(all(not path.exists() for path in stale_paths))
                return SimpleNamespace(free=1024 * 1024 * 1024)

            with patch(
                "mosaic_archive.reliability.shutil.disk_usage",
                side_effect=disk_usage_after_cleanup,
            ):
                summary = run_large_file_soak(
                    work_dir,
                    size_bytes=512 * 1024,
                    seed=17,
                )

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

        self.assertIn("pull_request:\n    paths:", workflow)
        self.assertIn('"src/mosaic_archive/**"', workflow)
        self.assertIn("workflow_dispatch:\n    inputs:", workflow)
        self.assertIn("soak_size_mib:", workflow)
        self.assertIn("schedule:", workflow)
        self.assertIn('cron: "41 2 * * 0"', workflow)
        self.assertIn('cron: "19 3 1 * *"', workflow)
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn("timeout-minutes: 60", workflow)
        self.assertIn("defaults:\n      run:\n        shell: bash", workflow)
        self.assertIn("mosaic_archive.reliability fuzz", workflow)
        self.assertIn("mosaic_archive.reliability soak", workflow)
        self.assertIn("--cases 10000", workflow)
        self.assertIn("--size-mib 256", workflow)
        self.assertIn("--size-mib 1025", workflow)
        self.assertIn("--size-mib 2049", workflow)
        self.assertIn("github.event.schedule == '41 2 * * 0'", workflow)
        self.assertIn("github.event.schedule == '19 3 1 * *'", workflow)
        self.assertIn("SOAK_SIZE_MIB: ${{ inputs.soak_size_mib }}", workflow)
        self.assertIn("256|1025|2049) ;;", workflow)
        self.assertIn('--size-mib "$SOAK_SIZE_MIB"', workflow)
        self.assertIn(
            "mosaic_archive.reliability soak \\\n"
            '            --seed 20260629 --size-mib "$SOAK_SIZE_MIB" \\\n',
            workflow,
        )
        self.assertIn("if: success()", workflow)
        self.assertIn("if-no-files-found: error", workflow)
        self.assertIn("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", workflow)


if __name__ == "__main__":
    unittest.main()
