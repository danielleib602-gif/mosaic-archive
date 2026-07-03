from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from mosaic_archive.corpus import generate_corpus
from mosaic_archive.exceptions import AuthenticationError
from mosaic_archive.solid_archive import decode_solid_archive, encode_solid_archive


def _tree_digest(root: Path) -> bytes:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix().encode()
        digest.update(b"D" if path.is_dir() else b"F")
        digest.update(relative)
        if path.is_file():
            digest.update(path.read_bytes())
    return digest.digest()


class ExperimentalSolidArchiveTests(unittest.TestCase):
    def test_encrypted_round_trip_beats_committed_7zip_size(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "corpus"
            archive = root / "corpus.msr"
            restored = root / "restored"
            generate_corpus(source, corpus_version=1)
            seven_zip_size = json.loads(
                Path("benchmarks/v0.12.0/report.json").read_text(encoding="utf-8")
            )["comparisons"]["7z"]["archive_size"]

            encoded = encode_solid_archive(
                source,
                archive,
                "correct horse battery staple",
                padding_size=1024,
                kdf_log_n=14,
            )
            decoded = decode_solid_archive(
                archive,
                restored,
                "correct horse battery staple",
            )

            self.assertLess(encoded.archive_size, seven_zip_size)
            self.assertEqual(encoded.archive_size, archive.stat().st_size)
            self.assertEqual(encoded.format_name, "MSR1")
            self.assertTrue(decoded.hash_verified)
            self.assertEqual(_tree_digest(source), _tree_digest(restored))
            self.assertNotIn(b"manifest.json", archive.read_bytes())

    def test_wrong_password_and_tampering_never_publish_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source"
            source.mkdir()
            (source / "data.bin").write_bytes(b"solid archive" * 4096)
            archive = root / "archive.msr"
            encode_solid_archive(source, archive, "secret", kdf_log_n=14)

            wrong_output = root / "wrong"
            with self.assertRaises(AuthenticationError):
                decode_solid_archive(archive, wrong_output, "wrong")
            self.assertFalse(wrong_output.exists())

            data = bytearray(archive.read_bytes())
            data[-1] ^= 1
            archive.write_bytes(data)
            tampered_output = root / "tampered"
            with self.assertRaises(AuthenticationError):
                decode_solid_archive(archive, tampered_output, "secret")
            self.assertFalse(tampered_output.exists())


if __name__ == "__main__":
    unittest.main()
