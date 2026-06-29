from __future__ import annotations

import random
import tempfile
import unittest
from pathlib import Path

from mosaic_archive.archive_api import decode_path, encode_path, inspect_path
from mosaic_archive.stream_archive import encode_stream_archive

PASSWORD = "dedup integration password"


def tree_contents(root: Path) -> dict[str, bytes | None]:
    return {
        path.relative_to(root).as_posix(): None if path.is_dir() else path.read_bytes()
        for path in sorted(root.rglob("*"))
    }


class DedupArchiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_identical_files_store_one_copy_of_each_unique_chunk(self) -> None:
        source = self.root / "source"
        source.mkdir()
        payload = random.Random(7).randbytes(100_000)
        (source / "first.bin").write_bytes(payload)
        (source / "second.bin").write_bytes(payload)
        archive = self.root / "dedup.msc"
        restored = self.root / "restored"

        stats = encode_path(
            source,
            archive,
            PASSWORD,
            chunk_size=2048,
            cdc_min_size=512,
            cdc_max_size=8192,
            kdf_log_n=14,
        )
        decoded = decode_path(archive, restored, PASSWORD)
        info = inspect_path(archive, PASSWORD)

        self.assertEqual(stats.format_version, 4)
        self.assertEqual(tree_contents(restored), tree_contents(source))
        self.assertTrue(decoded.hash_verified)
        self.assertEqual(stats.logical_chunk_count, stats.unique_chunk_count * 2)
        self.assertEqual(stats.duplicate_chunk_count, stats.unique_chunk_count)
        self.assertEqual(stats.cross_file_duplicate_chunks, stats.duplicate_chunk_count)
        self.assertGreaterEqual(stats.dedup_saved_bytes, len(payload))
        self.assertEqual(info.unique_chunk_count, stats.unique_chunk_count)
        self.assertEqual(info.cross_file_duplicate_chunks, stats.duplicate_chunk_count)
        self.assertTrue(info.hash_verified)

    def test_content_defined_boundaries_reuse_shifted_file_regions(self) -> None:
        source = self.root / "source"
        source.mkdir()
        original = random.Random(99).randbytes(300_000)
        shifted = b"new header" * 37 + original
        (source / "original.bin").write_bytes(original)
        (source / "shifted.bin").write_bytes(shifted)
        archive = self.root / "shifted.msc"
        restored = self.root / "restored"

        stats = encode_path(
            source,
            archive,
            PASSWORD,
            chunk_size=2048,
            cdc_min_size=512,
            cdc_max_size=8192,
            kdf_log_n=14,
        )
        decode_path(archive, restored, PASSWORD)

        self.assertEqual(tree_contents(restored), tree_contents(source))
        self.assertGreater(stats.cross_file_dedup_saved_bytes, int(len(original) * 0.8))
        self.assertGreater(stats.cross_file_duplicate_chunks, 0)

    def test_empty_files_and_directories_round_trip(self) -> None:
        source = self.root / "source"
        (source / "empty-dir").mkdir(parents=True)
        (source / "empty.bin").write_bytes(b"")
        archive = self.root / "empty.msc"
        restored = self.root / "restored"

        stats = encode_path(source, archive, PASSWORD, kdf_log_n=14)
        decode_path(archive, restored, PASSWORD)

        self.assertEqual(tree_contents(restored), tree_contents(source))
        self.assertEqual(stats.logical_chunk_count, 0)
        self.assertEqual(stats.unique_chunk_count, 0)

    def test_msc2_archive_remains_decodable(self) -> None:
        source = self.root / "legacy-v2.txt"
        archive = self.root / "legacy-v2.msc"
        restored = self.root / "restored.txt"
        source.write_text("MSC2 compatibility", encoding="utf-8")
        encode_stream_archive(source, archive, PASSWORD, kdf_log_n=14)

        decoded = decode_path(archive, restored, PASSWORD)

        self.assertEqual(restored.read_bytes(), source.read_bytes())
        self.assertEqual(decoded.format_version, 2)


if __name__ == "__main__":
    unittest.main()
