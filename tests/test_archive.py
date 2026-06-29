from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from mosaic_archive.archive import (
    decode_file,
    encode_file,
    inspect_archive,
    read_public_header,
)
from mosaic_archive.exceptions import ArchiveFormatError, AuthenticationError

PASSWORD = "correct horse battery staple"


class ArchiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def round_trip(self, data: bytes, *, chunk_size: int = 65_536) -> None:
        source = self.root / "source.bin"
        archive = self.root / "source.msc"
        restored = self.root / "restored.bin"
        source.write_bytes(data)

        encode_stats = encode_file(
            source,
            archive,
            PASSWORD,
            chunk_size=chunk_size,
            kdf_log_n=14,
        )
        decode_stats = decode_file(archive, restored, PASSWORD)

        self.assertEqual(restored.read_bytes(), data)
        self.assertEqual(encode_stats.original_size, len(data))
        self.assertEqual(decode_stats.original_size, len(data))
        self.assertTrue(decode_stats.hash_verified)

    def test_round_trip_empty_file(self) -> None:
        self.round_trip(b"")

    def test_round_trip_multiple_adaptive_blocks(self) -> None:
        data = (
            b"A" * 256
            + bytes(index % 256 for index in range(256))
            + (b"repeat this substring " * 20)
            + os.urandom(300)
        )
        self.round_trip(data, chunk_size=128)

    def test_metadata_and_content_are_encrypted(self) -> None:
        source = self.root / "private-name.txt"
        archive = self.root / "private.msc"
        secret = b"SECRET-CONTENT-" * 100
        source.write_bytes(secret)
        encode_file(source, archive, PASSWORD, kdf_log_n=14)

        archive_bytes = archive.read_bytes()
        self.assertNotIn(source.name.encode(), archive_bytes)
        self.assertNotIn(secret[:64], archive_bytes)

    def test_wrong_password_does_not_create_output(self) -> None:
        source = self.root / "source.bin"
        archive = self.root / "source.msc"
        output = self.root / "must-not-exist.bin"
        source.write_bytes(b"authenticated data")
        encode_file(source, archive, PASSWORD, kdf_log_n=14)

        with self.assertRaises(AuthenticationError):
            decode_file(archive, output, "wrong password")
        self.assertFalse(output.exists())

    def test_ciphertext_tampering_is_detected(self) -> None:
        source = self.root / "source.bin"
        archive = self.root / "source.msc"
        output = self.root / "output.bin"
        source.write_bytes(b"authenticated data" * 100)
        encode_file(source, archive, PASSWORD, kdf_log_n=14)

        damaged = bytearray(archive.read_bytes())
        damaged[-1] ^= 0x01
        archive.write_bytes(damaged)

        with self.assertRaises(AuthenticationError):
            decode_file(archive, output, PASSWORD)
        self.assertFalse(output.exists())

    def test_public_header_tampering_is_authenticated(self) -> None:
        source = self.root / "source.bin"
        archive = self.root / "source.msc"
        source.write_bytes(b"header authentication" * 100)
        encode_file(source, archive, PASSWORD, kdf_log_n=14)

        damaged = bytearray(archive.read_bytes())
        # The chunk-size field remains structurally valid but no longer matches the AAD.
        damaged[11] ^= 0x01
        archive.write_bytes(damaged)

        with self.assertRaises(AuthenticationError):
            inspect_archive(archive, PASSWORD)

    def test_padding_and_inspection_metrics(self) -> None:
        source = self.root / "metrics.txt"
        archive = self.root / "metrics.msc"
        source.write_bytes(b"mosaic " * 1000)
        stats = encode_file(
            source,
            archive,
            PASSWORD,
            padding_size=4096,
            kdf_log_n=14,
        )
        header = read_public_header(archive)
        info = inspect_archive(archive, PASSWORD)

        self.assertEqual((header.ciphertext_length - 16) % 4096, 0)
        self.assertGreaterEqual(stats.padding_overhead, 0)
        self.assertEqual(info.file_name, source.name)
        self.assertEqual(info.block_count, 1)
        self.assertTrue(info.metadata_encrypted)
        self.assertTrue(info.hash_verified)

    def test_invalid_archive_is_rejected(self) -> None:
        archive = self.root / "invalid.msc"
        archive.write_bytes(b"not an msc archive")
        with self.assertRaises(ArchiveFormatError):
            read_public_header(archive)

    def test_refuses_to_overwrite_input_with_archive(self) -> None:
        source = self.root / "same.bin"
        source.write_bytes(b"do not destroy me")
        with self.assertRaises(ValueError):
            encode_file(source, source, PASSWORD, kdf_log_n=14)
        self.assertEqual(source.read_bytes(), b"do not destroy me")


if __name__ == "__main__":
    unittest.main()
