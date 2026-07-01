from __future__ import annotations

import random
import unittest

from mosaic_archive.exceptions import ArchiveFormatError
from mosaic_archive.modes import ModeId
from mosaic_archive.modes.deflate import DeflateMode


class DeflateModeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mode = DeflateMode()

    def test_round_trips_structured_and_random_data(self) -> None:
        samples = (
            b"",
            b"A",
            b"compression is prediction\n" * 2000,
            random.Random(1234).randbytes(20_000),
        )
        for sample in samples:
            with self.subTest(size=len(sample)):
                encoded = self.mode.encode(sample)
                self.assertEqual(self.mode.decode(encoded, len(sample)), sample)

    def test_has_stable_mode_identifier(self) -> None:
        self.assertEqual(self.mode.id, ModeId.DEFLATE)

    def test_compresses_source_like_text(self) -> None:
        data = (b"def encode(block: bytes) -> bytes:\n    return block\n" * 2000)
        self.assertLess(len(self.mode.encode(data)), len(data) // 10)

    def test_rejects_malformed_or_trailing_payload(self) -> None:
        valid = self.mode.encode(b"hello")
        for payload in (b"not-deflate", valid + b"trailing"):
            with self.subTest(payload=payload), self.assertRaises(ArchiveFormatError):
                self.mode.decode(payload, 5)


if __name__ == "__main__":
    unittest.main()

