from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from mosaic_archive.archive import encode_file
from mosaic_archive.archive_api import decode_path, encode_path, inspect_path
from mosaic_archive.exceptions import ArchiveFormatError, AuthenticationError
from mosaic_archive.paths import validate_relative_path
from mosaic_archive.stream_archive import encode_stream_archive
from mosaic_archive.stream_format import MSC2_HEADER, parse_msc2_header

PASSWORD = "folder archive test password"


def tree_contents(root: Path) -> dict[str, bytes | None]:
    result: dict[str, bytes | None] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        result[relative] = None if path.is_dir() else path.read_bytes()
    return result


class StreamArchiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def make_folder(self) -> Path:
        source = self.root / "project"
        (source / "empty").mkdir(parents=True)
        (source / "src" / "nested").mkdir(parents=True)
        (source / "src" / "main.py").write_text(
            "print('compression is prediction')\n" * 100,
            encoding="utf-8",
        )
        (source / "src" / "nested" / "ramp.bin").write_bytes(
            bytes(index % 256 for index in range(20_000))
        )
        (source / "שלום.txt").write_text("portable unicode\n", encoding="utf-8")
        return source

    def test_folder_round_trip_preserves_files_and_empty_directories(self) -> None:
        source = self.make_folder()
        archive = self.root / "project.msc"
        restored = self.root / "restored"
        encode_events = []
        decode_events = []

        encoded = encode_path(
            source,
            archive,
            PASSWORD,
            chunk_size=1024,
            kdf_log_n=14,
            progress=encode_events.append,
        )
        decoded = decode_path(
            archive,
            restored,
            PASSWORD,
            progress=decode_events.append,
        )

        self.assertEqual(tree_contents(restored), tree_contents(source))
        self.assertEqual(encoded.format_version, 3)
        self.assertEqual(encoded.archive_kind, "folder")
        self.assertEqual(encoded.file_count, 3)
        self.assertGreater(encoded.block_count, 3)
        self.assertEqual(decoded.file_count, 3)
        self.assertTrue(decoded.hash_verified)
        self.assertEqual(encode_events[-1].completed_bytes, encoded.original_size)
        self.assertEqual(encode_events[-1].completed_files, encoded.file_count)
        self.assertEqual(decode_events[-1].completed_bytes, decoded.original_size)
        self.assertEqual(decode_events[-1].completed_files, decoded.file_count)

    def test_single_file_uses_streaming_msc2_and_round_trips(self) -> None:
        source = self.root / "large.bin"
        source.write_bytes(os.urandom(200_000))
        archive = self.root / "large.msc"
        restored = self.root / "large-restored.bin"

        encode_stream_archive(
            source,
            archive,
            PASSWORD,
            chunk_size=4096,
            kdf_log_n=14,
        )
        with archive.open("rb") as stream:
            header = parse_msc2_header(stream.read(MSC2_HEADER.size))
        decode_path(archive, restored, PASSWORD)

        self.assertEqual(header.version, 2)
        self.assertGreater(header.frame_count, 2)
        self.assertEqual(restored.read_bytes(), source.read_bytes())

    def test_wrong_password_does_not_create_folder(self) -> None:
        source = self.make_folder()
        archive = self.root / "project.msc"
        restored = self.root / "must-not-exist"
        encode_path(source, archive, PASSWORD, kdf_log_n=14)

        with self.assertRaises(AuthenticationError):
            decode_path(archive, restored, "wrong")
        self.assertFalse(restored.exists())

    def test_forged_header_cannot_request_unbounded_scrypt_cost(self) -> None:
        source = self.root / "source.txt"
        archive = self.root / "source.msc"
        source.write_text("bounded KDF", encoding="utf-8")
        encode_path(source, archive, PASSWORD, kdf_log_n=14)

        damaged = bytearray(archive.read_bytes())
        damaged[44] = 19
        archive.write_bytes(damaged)

        with self.assertRaises(ArchiveFormatError):
            inspect_path(archive, PASSWORD)

    def test_frame_tampering_does_not_publish_partial_tree(self) -> None:
        source = self.make_folder()
        archive = self.root / "project.msc"
        restored = self.root / "must-not-exist"
        encode_path(source, archive, PASSWORD, chunk_size=1024, kdf_log_n=14)

        damaged = bytearray(archive.read_bytes())
        damaged[-20] ^= 0x01
        archive.write_bytes(damaged)

        with self.assertRaises(AuthenticationError):
            decode_path(archive, restored, PASSWORD)
        self.assertFalse(restored.exists())

    def test_inspect_reports_encrypted_folder_manifest(self) -> None:
        source = self.make_folder()
        archive = self.root / "project.msc"
        encode_path(source, archive, PASSWORD, chunk_size=1024, kdf_log_n=14)

        info = inspect_path(archive, PASSWORD)

        self.assertEqual(info.format_version, 3)
        self.assertEqual(info.archive_kind, "folder")
        self.assertEqual(info.file_count, 3)
        self.assertGreaterEqual(info.directory_count, 3)
        self.assertTrue(info.metadata_encrypted)
        self.assertTrue(info.hash_verified)

    def test_existing_folder_destination_is_not_merged(self) -> None:
        source = self.make_folder()
        archive = self.root / "project.msc"
        destination = self.root / "existing"
        destination.mkdir()
        (destination / "keep.txt").write_text("keep", encoding="utf-8")
        encode_path(source, archive, PASSWORD, kdf_log_n=14)

        with self.assertRaises(FileExistsError):
            decode_path(archive, destination, PASSWORD)
        self.assertEqual((destination / "keep.txt").read_text(encoding="utf-8"), "keep")

    def test_legacy_msc1_decode_remains_supported(self) -> None:
        source = self.root / "legacy.txt"
        archive = self.root / "legacy.msc"
        restored = self.root / "restored.txt"
        source.write_text("legacy decoder fixture", encoding="utf-8")
        encode_file(source, archive, PASSWORD, kdf_log_n=14)

        decoded = decode_path(archive, restored, PASSWORD)

        self.assertEqual(restored.read_bytes(), source.read_bytes())
        self.assertEqual(decoded.original_size, source.stat().st_size)


class PortablePathTests(unittest.TestCase):
    def test_rejects_traversal_absolute_and_platform_unsafe_paths(self) -> None:
        unsafe = (
            "",
            ".",
            "../escape",
            "safe/../../escape",
            "/absolute",
            "C:/windows",
            r"backslash\name",
            "trailing.",
            "trailing ",
            "CON",
            "folder/NUL.txt",
            "bad:name",
        )
        for path in unsafe:
            with self.subTest(path=path), self.assertRaises(ValueError):
                validate_relative_path(path)

    def test_accepts_normalized_unicode_relative_paths(self) -> None:
        self.assertEqual(validate_relative_path("src/שלום/file.txt"), "src/שלום/file.txt")


if __name__ == "__main__":
    unittest.main()
