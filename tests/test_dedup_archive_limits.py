from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mosaic_archive.cdc import ChunkingConfig
from mosaic_archive.crypto import AEAD_TAG_LENGTH
from mosaic_archive.dedup_archive import decode_dedup_archive, encode_dedup_archive
from mosaic_archive.dedup_format import MSC3_HEADER, parse_msc3_header
from mosaic_archive.exceptions import ArchiveFormatError
from mosaic_archive.stream_format import (
    FRAME_HEADER,
    MAX_MANIFEST_CIPHERTEXT,
    FrameHeader,
    parse_frame_header,
)

PASSWORD = "MSC6 decoder limit test password"
CONFIG = ChunkingConfig(min_size=64, avg_size=128, max_size=256)


class DedupArchiveLimitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _encode_file(self, payload: bytes) -> Path:
        source = self.root / "source.bin"
        archive = self.root / "source.msc"
        source.write_bytes(payload)
        encode_dedup_archive(
            source,
            archive,
            PASSWORD,
            config=CONFIG,
            padding_size=256,
            kdf_log_n=14,
        )
        return archive

    @staticmethod
    def _temporary_outputs(destination: Path) -> list[Path]:
        return list(destination.parent.glob(f".{destination.name}.*"))

    def test_trailing_byte_preserves_existing_file_and_removes_temporary_output(self) -> None:
        archive = self._encode_file(b"authenticated MSC6 payload\n" * 64)
        destination = self.root / "restored.bin"
        original_destination = b"pre-existing destination"
        destination.write_bytes(original_destination)
        with archive.open("ab") as stream:
            stream.write(b"\x00")

        with self.assertRaisesRegex(ArchiveFormatError, "termination is invalid"):
            decode_dedup_archive(archive, destination, PASSWORD)

        self.assertEqual(destination.read_bytes(), original_destination)
        self.assertEqual(self._temporary_outputs(destination), [])

    def test_frame_limit_rejects_multiple_unique_chunks_before_output_creation(self) -> None:
        payload = b"".join(
            hashlib.sha256(index.to_bytes(4, "big")).digest()
            for index in range(128)
        )
        archive = self.root / "source.msc"
        source = self.root / "source.bin"
        source.write_bytes(payload)
        encoded = encode_dedup_archive(
            source,
            archive,
            PASSWORD,
            config=CONFIG,
            padding_size=256,
            kdf_log_n=14,
        )
        self.assertGreater(encoded.unique_chunk_count, 1)
        destination = self.root / "must-not-exist.bin"

        with (
            patch(
                "mosaic_archive.dedup_archive.derive_key",
                side_effect=AssertionError("frame limit reached key derivation"),
            ) as derive_key,
            patch(
                "mosaic_archive.dedup_archive.tempfile.NamedTemporaryFile",
                side_effect=AssertionError("frame limit prepared output"),
            ) as prepare_output,
            self.assertRaisesRegex(ArchiveFormatError, "frame count exceeds"),
        ):
            decode_dedup_archive(
                archive,
                destination,
                PASSWORD,
                max_frame_count=1,
            )

        derive_key.assert_not_called()
        prepare_output.assert_not_called()

        self.assertFalse(destination.exists())
        self.assertEqual(self._temporary_outputs(destination), [])

    def test_oversized_aligned_manifest_is_rejected_before_ciphertext_read(self) -> None:
        archive = self._encode_file(b"bounded MSC6 manifest")
        destination = self.root / "must-not-exist.bin"
        damaged = bytearray(archive.read_bytes())
        global_header = bytes(damaged[: MSC3_HEADER.size])
        header = parse_msc3_header(global_header)
        frame_start = MSC3_HEADER.size
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
            decode_dedup_archive(archive, destination, PASSWORD)

        self.assertFalse(destination.exists())
        self.assertEqual(self._temporary_outputs(destination), [])

    def test_manifest_header_rejects_order_and_unaligned_lengths(self) -> None:
        for case, expected_error in (
            ("order", "out of order"),
            ("padding", "violates its padding policy"),
        ):
            with self.subTest(case=case):
                archive = self._encode_file(f"manifest {case}".encode())
                destination = self.root / f"must-not-exist-{case}.bin"
                damaged = bytearray(archive.read_bytes())
                frame_start = MSC3_HEADER.size
                frame_end = frame_start + FRAME_HEADER.size
                frame = parse_frame_header(bytes(damaged[frame_start:frame_end]))
                replacement = FrameHeader(
                    frame.index + (case == "order"),
                    frame.frame_type,
                    frame.ciphertext_length + (case == "padding"),
                )
                damaged[frame_start:frame_end] = replacement.pack()
                archive.write_bytes(damaged)

                with self.assertRaisesRegex(ArchiveFormatError, expected_error):
                    decode_dedup_archive(archive, destination, PASSWORD)

                self.assertFalse(destination.exists())
                self.assertEqual(self._temporary_outputs(destination), [])


if __name__ == "__main__":
    unittest.main()
