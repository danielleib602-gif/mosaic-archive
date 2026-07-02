from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class CliTests(unittest.TestCase):
    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["PYTHONUTF8"] = "1"
        return subprocess.run(
            [sys.executable, "-m", "mosaic_archive", *arguments],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

    def test_reports_v0_31_package_version(self) -> None:
        completed = self.run_cli("--version")

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "msc 0.31.0")

    def test_encode_inspect_decode_and_benchmark_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "sample.txt"
            archive = root / "sample.msc"
            restored = root / "restored.txt"
            source.write_bytes(b"compression is prediction\n" * 300)

            encoded = self.run_cli(
                "encode",
                str(source),
                str(archive),
                "--password",
                "test-password",
                "--kdf-log-n",
                "14",
                "--json",
            )
            self.assertEqual(encoded.returncode, 0, encoded.stderr)
            self.assertTrue(archive.exists())
            self.assertEqual(json.loads(encoded.stdout)["operation"], "encode")

            inspected = self.run_cli(
                "inspect",
                str(archive),
                "--password",
                "test-password",
                "--json",
            )
            self.assertEqual(inspected.returncode, 0, inspected.stderr)
            self.assertTrue(json.loads(inspected.stdout)["hash_verified"])

            decoded = self.run_cli(
                "decode",
                str(archive),
                str(restored),
                "--password",
                "test-password",
                "--json",
            )
            self.assertEqual(decoded.returncode, 0, decoded.stderr)
            self.assertEqual(restored.read_bytes(), source.read_bytes())

            benchmark = self.run_cli(
                "benchmark",
                str(source),
                "--password",
                "test-password",
                "--kdf-log-n",
                "14",
                "--compare",
                "--json",
            )
            self.assertEqual(benchmark.returncode, 0, benchmark.stderr)
            report = json.loads(benchmark.stdout)
            self.assertEqual(report["operation"], "benchmark")
            self.assertTrue(report["round_trip_verified"])
            self.assertIn("mode_distribution", report)
            self.assertIn("peak_memory_bytes", report)

    def test_authentication_failure_has_clean_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "sample.txt"
            archive = root / "sample.msc"
            source.write_text("secret", encoding="utf-8")
            encoded = self.run_cli(
                "encode",
                str(source),
                str(archive),
                "--password",
                "right",
                "--kdf-log-n",
                "14",
            )
            self.assertEqual(encoded.returncode, 0, encoded.stderr)

            decoded = self.run_cli(
                "decode",
                str(archive),
                str(root / "output.txt"),
                "--password",
                "wrong",
            )
            self.assertEqual(decoded.returncode, 2)
            self.assertIn("wrong password or archive was modified", decoded.stderr.lower())
            self.assertNotIn("Traceback", decoded.stderr)

    def test_folder_encode_inspect_and_decode(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "folder"
            (source / "nested").mkdir(parents=True)
            (source / "nested" / "data.txt").write_text(
                "mosaic folder\n" * 100,
                encoding="utf-8",
            )
            (source / "empty").mkdir()
            archive = root / "folder.msc"
            restored = root / "restored"

            encoded = self.run_cli(
                "encode",
                str(source),
                str(archive),
                "--password",
                "test-password",
                "--kdf-log-n",
                "14",
                "--json",
            )
            self.assertEqual(encoded.returncode, 0, encoded.stderr)
            self.assertEqual(json.loads(encoded.stdout)["archive_kind"], "folder")

            inspected = self.run_cli(
                "inspect",
                str(archive),
                "--password",
                "test-password",
                "--json",
            )
            self.assertEqual(inspected.returncode, 0, inspected.stderr)
            self.assertEqual(json.loads(inspected.stdout)["format_version"], 6)

            decoded = self.run_cli(
                "decode",
                str(archive),
                str(restored),
                "--password",
                "test-password",
                "--json",
            )
            self.assertEqual(decoded.returncode, 0, decoded.stderr)
            self.assertEqual(
                (restored / "nested" / "data.txt").read_bytes(),
                (source / "nested" / "data.txt").read_bytes(),
            )
            self.assertTrue((restored / "empty").is_dir())

            benchmark = self.run_cli(
                "benchmark",
                str(source),
                "--password",
                "test-password",
                "--kdf-log-n",
                "14",
                "--compare",
                "--json",
            )
            self.assertEqual(benchmark.returncode, 0, benchmark.stderr)
            report = json.loads(benchmark.stdout)
            self.assertEqual(report["archive_kind"], "folder")
            self.assertEqual(report["format_version"], 6)
            self.assertTrue(report["round_trip_verified"])
            self.assertTrue(report["comparisons"]["zip"]["verified"])
            self.assertTrue(report["comparisons"]["gzip"]["supported"])
            self.assertTrue(report["comparisons"]["gzip"]["verified"])

    def test_opt_in_solid_encode_auto_detects_for_inspect_and_decode(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source, archive, restored = root / "source", root / "solid.msc", root / "out"
            source.mkdir()
            (source / "data.txt").write_bytes(b"solid CLI round trip\n" * 4096)

            encoded = self.run_cli(
                "encode",
                str(source),
                str(archive),
                "--format",
                "solid",
                "--padding-size",
                "256",
                "--password",
                "test-password",
                "--kdf-log-n",
                "14",
                "--json",
            )
            self.assertEqual(encoded.returncode, 0, encoded.stderr)
            self.assertEqual(json.loads(encoded.stdout)["format_name"], "MSR2")
            self.assertEqual(archive.read_bytes()[:4], b"MSR2")

            inspected = self.run_cli(
                "inspect",
                str(archive),
                "--password",
                "test-password",
                "--json",
            )
            self.assertEqual(inspected.returncode, 0, inspected.stderr)
            self.assertEqual(json.loads(inspected.stdout)["format_name"], "MSR2")

            decoded = self.run_cli(
                "decode",
                str(archive),
                str(restored),
                "--password",
                "test-password",
                "--json",
            )
            self.assertEqual(decoded.returncode, 0, decoded.stderr)
            self.assertEqual(
                (restored / "data.txt").read_bytes(),
                (source / "data.txt").read_bytes(),
            )

            benchmark = self.run_cli(
                "benchmark",
                str(source),
                "--format",
                "solid",
                "--padding-size",
                "256",
                "--password",
                "test-password",
                "--kdf-log-n",
                "14",
                "--compare",
                "--json",
            )
            self.assertEqual(benchmark.returncode, 0, benchmark.stderr)
            report = json.loads(benchmark.stdout)
            self.assertEqual(report["format_name"], "MSR2")
            self.assertTrue(report["round_trip_verified"])
            self.assertTrue(report["comparisons"]["zip"]["verified"])
            self.assertIn("7z-encrypted", report["comparisons"])


if __name__ == "__main__":
    unittest.main()
