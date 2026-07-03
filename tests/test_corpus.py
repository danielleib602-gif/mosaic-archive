from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from mosaic_archive.corpus import (
    CORPUS_MTIME_NS,
    CORPUS_VERSION,
    MANIFEST_NAME,
    generate_corpus,
    verify_corpus,
)


class ReproducibleCorpusTests(unittest.TestCase):
    def test_generated_metadata_uses_a_reproducible_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "corpus"
            generate_corpus(root)

            self.assertEqual(root.stat().st_mtime_ns, CORPUS_MTIME_NS)
            self.assertTrue(
                all(
                    path.stat().st_mtime_ns == CORPUS_MTIME_NS
                    for path in root.rglob("*")
                )
            )

    def test_default_manifest_is_byte_identical_to_published_linux_corpus(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            generate_corpus(root)
            manifest = (root / MANIFEST_NAME).read_bytes()

            self.assertNotIn(b"\r\n", manifest)
            self.assertEqual(
                hashlib.sha256(manifest).hexdigest(),
                "57bd4b92efbdeb8be023b2e1c92c586bebe56f90f5cd219f2df97c8f74f20d13",
            )
            self.assertEqual(CORPUS_VERSION, 2)

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

