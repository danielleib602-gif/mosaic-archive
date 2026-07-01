from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from mosaic_archive.corpus import generate_corpus, verify_corpus


class ReproducibleCorpusTests(unittest.TestCase):
    def test_generation_is_deterministic_and_self_verifying(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            first = root / "first"
            second = root / "second"

            first_manifest = generate_corpus(first, seed=42, unit_size=4096)
            second_manifest = generate_corpus(second, seed=42, unit_size=4096)

            self.assertEqual(first_manifest["files"], second_manifest["files"])
            self.assertTrue(verify_corpus(first))
            self.assertTrue(verify_corpus(second))

    def test_corpus_covers_general_purpose_categories(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            manifest = generate_corpus(root, seed=7, unit_size=4096)
            categories = {entry["category"] for entry in manifest["files"]}
            self.assertEqual(
                categories,
                {
                    "dedup",
                    "empty",
                    "numeric",
                    "precompressed",
                    "random",
                    "structured",
                    "text",
                },
            )

    def test_verification_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            manifest = generate_corpus(root, seed=9, unit_size=4096)
            target = root / manifest["files"][0]["path"]
            target.write_bytes(target.read_bytes() + b"tampered")
            self.assertFalse(verify_corpus(root))

    def test_module_cli_generates_machine_readable_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "mosaic_archive.corpus",
                    str(root),
                    "--seed",
                    "11",
                    "--unit-size",
                    "4096",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            output = json.loads(completed.stdout)
            self.assertTrue(output["verified"])
            self.assertTrue((root / "manifest.json").is_file())


if __name__ == "__main__":
    unittest.main()

