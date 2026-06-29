from __future__ import annotations

import random
import unittest

from mosaic_archive.exceptions import ArchiveFormatError
from mosaic_archive.modes import ModeId
from mosaic_archive.modes.lz_rans import LzRansMode


class LzRansModeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mode = LzRansMode()

    def test_round_trips_literals_matches_and_overlapping_runs(self) -> None:
        samples = (
            b"",
            b"short literal",
            b"A" * 100_000,
            b"the red fox jumped over the blue fence; " * 3000,
            random.Random(55).randbytes(10_000),
        )
        for sample in samples:
            with self.subTest(size=len(sample)):
                encoded = self.mode.encode(sample)
                self.assertEqual(self.mode.decode(encoded, len(sample)), sample)

    def test_has_stable_mode_identifier(self) -> None:
        self.assertEqual(self.mode.id, ModeId.LZ_RANS)

    def test_compresses_repetitive_text(self) -> None:
        data = b'{"name":"mosaic","value":12345}\n' * 5000
        self.assertLess(len(self.mode.encode(data)), len(data) // 20)

    def test_rejects_truncated_and_trailing_streams(self) -> None:
        valid = self.mode.encode(b"repeated data " * 100)
        for payload in (b"", valid[:20], valid + b"trailing"):
            with self.subTest(size=len(payload)), self.assertRaises(ArchiveFormatError):
                self.mode.decode(payload, 1400)


if __name__ == "__main__":
    unittest.main()

