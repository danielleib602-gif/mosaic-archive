from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mosaic_archive.archive_api import decode_path
from mosaic_archive.crypto import AEAD_TAG_LENGTH
from mosaic_archive.exceptions import ArchiveFormatError
from mosaic_archive.stream_archive import encode_stream_archive
from mosaic_archive.stream_format import (
    FRAME_HEADER,
    MAX_MANIFEST_CIPHERTEXT,
    MSC2_HEADER,
    FrameHeader,
    parse_frame_header,
    parse_msc2_header,
)

PASSWORD = "stream decoder limit test password"


class StreamArchiveLimitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _encode_file(self, payload: bytes, *, chunk_size: int = 65_536) -> Path:
        source = self.root / "source.bin"
        archive = self.root / "source.msc"
        source.write_bytes(payload)
        encode_stream_archive(
            source,
            archive,
            PASSWORD,
            chunk_size=chunk_size,
            kdf_log_n=14,
        )
        return archive

    def _temporary_outputs_for(self, destination: Path) -> list[Path]:
        return list(destination.parent.glob(f".{destination.name}.*.tmp"))

    def test_trailing_byte_preserves_existing_file_and_removes_temporary_output(self) -> None:
        archive = self._encode_file(b"authenticated payload\n" * 64)
        destination = self.root / "restored.bin"
        original_destination = b"pre-existing destination"
        destination.write_bytes(original_destination)
        with archive.open("ab") as stream:
            stream.write(b"\x00")

        with self.assertRaisesRegex(ArchiveFormatError, "trailing bytes"):
            decode_path(archive, destination, PASSWORD)

        self.assertEqual(destination.read_bytes(), original_destination)
        self.assertEqual(self._temporary_outputs_for(destination), [])

    def test_frame_limit_rejects_multi_frame_archive_before_destination_creation(self) -> None:
        archive = self._encode_file(bytes(range(256)) * 4, chunk_size=256)
        destination = self.root / "must-not-exist.bin"

        with self.assertRaisesRegex(ArchiveFormatError, "frame count exceeds"):
            decode_path(archive, destination, PASSWORD, max_frame_count=1)

        self.assertFalse(destination.exists())
        self.assertEqual(self._temporary_outputs_for(destination), [])

    def test_oversized_aligned_manifest_frame_is_rejected_before_ciphertext_read(self) -> None:
        archive = self._encode_file(b"bounded manifest")
        destination = self.root / "must-not-exist.bin"
        damaged = bytearray(archive.read_bytes())
        global_header = bytes(damaged[: MSC2_HEADER.size])
        header = parse_msc2_header(global_header)
        frame_start = MSC2_HEADER.size
        frame_end = frame_start + FRAME_HEADER.size
        manifest_frame = parse_frame_header(bytes(damaged[frame_start:frame_end]))
        oversized_ciphertext_length = (
            ((MAX_MANIFEST_CIPHERTEXT // header.padding_size) + 1)
            * header.padding_size
            + AEAD_TAG_LENGTH
        )
        self.assertGreater(oversized_ciphertext_length, MAX_MANIFEST_CIPHERTEXT)
        self.assertEqual(
            (oversized_ciphertext_length - AEAD_TAG_LENGTH) % header.padding_size,
            0,
        )
        damaged[frame_start:frame_end] = FrameHeader(
            manifest_frame.index,
            manifest_frame.frame_type,
            oversized_ciphertext_length,
        ).pack()
        archive.write_bytes(damaged)

        with self.assertRaisesRegex(ArchiveFormatError, "exceeds its resource limit"):
            decode_path(archive, destination, PASSWORD)

        self.assertFalse(destination.exists())
        self.assertEqual(self._temporary_outputs_for(destination), [])

    def test_manifest_frame_header_rejects_order_and_unaligned_lengths(self) -> None:
        for case, expected_error in (
            ("order", "out of order"),
            ("padding", "violates its padding policy"),
        ):
            with self.subTest(case=case):
                archive = self._encode_file(f"manifest {case}".encode())
                destination = self.root / f"must-not-exist-{case}.bin"
                damaged = bytearray(archive.read_bytes())
                frame_start = MSC2_HEADER.size
                frame_end = frame_start + FRAME_HEADER.size
                manifest_frame = parse_frame_header(bytes(damaged[frame_start:frame_end]))
                replacement = FrameHeader(
                    manifest_frame.index + (case == "order"),
                    manifest_frame.frame_type,
                    manifest_frame.ciphertext_length + (case == "padding"),
                )
                damaged[frame_start:frame_end] = replacement.pack()
                archive.write_bytes(damaged)

                with self.assertRaisesRegex(ArchiveFormatError, expected_error):
                    decode_path(archive, destination, PASSWORD)

                self.assertFalse(destination.exists())
                self.assertEqual(self._temporary_outputs_for(destination), [])


if __name__ == "__main__":
    unittest.main()
