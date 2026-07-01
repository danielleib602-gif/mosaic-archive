from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from mosaic_archive.comparisons import compare_common_tools, safe_extract_zip


class ComparisonArchiveSafetyTests(unittest.TestCase):
    def test_encrypted_7zip_baseline_is_explicit_even_when_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source.bin"
            source.write_bytes(b"fair encrypted comparison")

            results = compare_common_tools(
                source,
                root / "comparisons",
                include_encrypted_7zip=True,
            )

            self.assertIn("7z-encrypted", results)
            self.assertIn("encryption", results["7z-encrypted"].note.lower())

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
