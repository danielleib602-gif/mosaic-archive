from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from mosaic_archive.comparisons import safe_extract_zip


class ComparisonArchiveSafetyTests(unittest.TestCase):
    def test_zip_extraction_rejects_parent_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive = root / "malicious.zip"
            destination = root / "restored"
            destination.mkdir()
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("../escape.txt", "escaped")

            with zipfile.ZipFile(archive, "r") as compressed:
                with self.assertRaises(zipfile.BadZipFile):
                    safe_extract_zip(compressed, destination)

            self.assertFalse((root / "escape.txt").exists())


if __name__ == "__main__":
    unittest.main()
