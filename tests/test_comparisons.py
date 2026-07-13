from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from mosaic_archive import comparisons as comparisons_module
from mosaic_archive.comparisons import (
    ComparisonResult,
    compare_common_tools,
    comparison_tool_versions,
    safe_extract_zip,
)


class ComparisonArchiveSafetyTests(unittest.TestCase):
    def test_encrypted_7zip_baseline_is_explicit_even_when_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source.bin"
            source.write_bytes(b"fair encrypted comparison")

            with patch.object(comparisons_module.shutil, "which", return_value=None):
                results = compare_common_tools(
                    source,
                    root / "comparisons",
                    include_encrypted_7zip=True,
                )

            self.assertIn("7z-encrypted", results)
            self.assertIn("encryption", results["7z-encrypted"].note.lower())

    def test_adapter_failure_is_isolated_from_later_comparisons(self) -> None:
        successful = ComparisonResult(True, True, 9, 0.9, 0.1, 0.2, True, "ok")
        zip_adapter = Mock(side_effect=OSError("zip broke"))
        gzip_adapter = Mock(return_value=successful)
        zstd_adapter = Mock(return_value=successful)
        seven_zip_adapter = Mock(return_value=successful)
        encrypted_adapter = Mock(return_value=successful)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source.bin"
            source.write_bytes(b"0123456789")
            comparison_root = root / "comparisons"
            with (
                patch.object(comparisons_module, "_compare_zip", zip_adapter),
                patch.object(comparisons_module, "_compare_gzip", gzip_adapter),
                patch.object(comparisons_module, "_compare_zstd", zstd_adapter),
                patch.object(comparisons_module, "_compare_7z", seven_zip_adapter),
                patch.object(
                    comparisons_module,
                    "_compare_7z_encrypted",
                    encrypted_adapter,
                ),
            ):
                results = compare_common_tools(
                    source,
                    comparison_root,
                    include_encrypted_7zip=True,
                )

        self.assertEqual(list(results), ["zip", "gzip", "zstd", "7z", "7z-encrypted"])
        self.assertFalse(results["zip"].verified)
        self.assertIn("zip broke", results["zip"].note)
        self.assertIs(results["gzip"], successful)
        self.assertIs(results["7z-encrypted"], successful)
        for name, adapter in (
            ("zip", zip_adapter),
            ("gzip", gzip_adapter),
            ("zstd", zstd_adapter),
            ("7z", seven_zip_adapter),
            ("7z-encrypted", encrypted_adapter),
        ):
            adapter.assert_called_once_with(source, comparison_root / name)

    def test_default_orchestration_omits_encrypted_7zip(self) -> None:
        successful = ComparisonResult(True, True, 1, 1.0, 0.1, 0.1, True, "ok")
        encrypted_adapter = Mock(return_value=successful)
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source.bin"
            source.write_bytes(b"x")
            with (
                patch.object(comparisons_module, "_compare_zip", return_value=successful),
                patch.object(comparisons_module, "_compare_gzip", return_value=successful),
                patch.object(comparisons_module, "_compare_zstd", return_value=successful),
                patch.object(comparisons_module, "_compare_7z", return_value=successful),
                patch.object(
                    comparisons_module,
                    "_compare_7z_encrypted",
                    encrypted_adapter,
                ),
            ):
                results = compare_common_tools(source, root / "comparisons")

        self.assertEqual(list(results), ["zip", "gzip", "zstd", "7z"])
        encrypted_adapter.assert_not_called()

    def test_tool_versions_report_missing_executables(self) -> None:
        with patch.object(comparisons_module.shutil, "which", return_value=None):
            versions = comparison_tool_versions()

        self.assertIn("Python zipfile", versions["zip"] or "")
        self.assertIn("Python gzip", versions["gzip"] or "")
        self.assertIsNone(versions["zstd"])
        self.assertIsNone(versions["7z"])

    def test_tool_versions_use_stderr_and_empty_output_fallbacks(self) -> None:
        def fake_run(command: list[str], **_options: object) -> object:
            if command[-1] == "--version":
                return SimpleNamespace(stdout=b"", stderr=b"zstd 1.5.7\nmore\n")
            return SimpleNamespace(stdout=b"", stderr=b"")

        with (
            patch.object(
                comparisons_module.shutil,
                "which",
                side_effect=lambda name: f"/tools/{name}",
            ),
            patch.object(comparisons_module.subprocess, "run", side_effect=fake_run),
        ):
            versions = comparison_tool_versions()

        self.assertEqual(versions["zstd"], "zstd 1.5.7")
        self.assertEqual(versions["7z"], "version output unavailable")

    def test_tool_version_query_failures_are_reported(self) -> None:
        with (
            patch.object(comparisons_module.shutil, "which", return_value="tool"),
            patch.object(comparisons_module.subprocess, "run", side_effect=OSError("boom")),
        ):
            versions = comparison_tool_versions()

        self.assertEqual(versions["zstd"], "version query failed")
        self.assertEqual(versions["7z"], "version query failed")

    def test_zip_extraction_rejects_parent_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive = root / "malicious.zip"
            destination = root / "restored"
            destination.mkdir()
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("../escape.txt", "escaped")

            with (
                zipfile.ZipFile(archive, "r") as compressed,
                self.assertRaises(zipfile.BadZipFile),
            ):
                safe_extract_zip(compressed, destination)

            self.assertFalse((root / "escape.txt").exists())


if __name__ == "__main__":
    unittest.main()
