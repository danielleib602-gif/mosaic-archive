from __future__ import annotations

import random
import unittest

from mosaic_archive.exceptions import ArchiveFormatError
from mosaic_archive.modes import ModeId, choose_best_mode
from mosaic_archive.modes.rans import ByteRansMode


class ByteRansTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mode = ByteRansMode()

    def test_round_trips_empty_skewed_and_full_alphabet_data(self) -> None:
        rng = random.Random(123)
        samples = (
            b"",
            b"A",
            bytes(range(256)) * 4,
            bytes(rng.choices(range(8), weights=(80, 10, 3, 2, 2, 1, 1, 1), k=50_000)),
        )
        for sample in samples:
            with self.subTest(size=len(sample)):
                encoded = self.mode.encode(sample)
                self.assertEqual(self.mode.decode(encoded, len(sample)), sample)

    def test_compresses_skewed_non_run_data(self) -> None:
        rng = random.Random(456)
        data = bytes(rng.choices(range(16), weights=[50] + [1] * 15, k=65_536))
        encoded = self.mode.encode(data)
        self.assertLess(len(encoded), len(data) // 2)

    def test_adaptive_selector_can_choose_rans(self) -> None:
        rng = random.Random(789)
        data = bytes(rng.choices(range(16), weights=[50] + [1] * 15, k=65_536))
        selected = choose_best_mode(data)
        self.assertEqual(selected.mode.id, ModeId.BYTE_RANS)

    def test_rejects_truncated_or_inconsistent_payload(self) -> None:
        malformed = (b"\x00", b"\x00\x01A", b"\x00\x01A\x00\x00\x00\x00\x00")
        for payload in malformed:
            with self.subTest(payload=payload), self.assertRaises(ArchiveFormatError):
                self.mode.decode(payload, 100)


if __name__ == "__main__":
    unittest.main()
