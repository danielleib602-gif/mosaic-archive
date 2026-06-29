from __future__ import annotations

import random
import unittest

from mosaic_archive.exceptions import ArchiveFormatError
from mosaic_archive.modes import ALL_MODES, ModeId, choose_best_mode, get_mode


class ModeRoundTripTests(unittest.TestCase):
    def test_every_mode_round_trips_edge_cases(self) -> None:
        samples = [
            b"",
            b"x",
            bytes(range(256)),
            b"\x00" * 4096,
            bytes(index % 256 for index in range(4096)),
            (b"mosaic archive prediction residual " * 300),
        ]
        for mode in ALL_MODES:
            for sample in samples:
                with self.subTest(mode=mode.name, size=len(sample)):
                    encoded = mode.encode(sample)
                    self.assertEqual(mode.decode(encoded, len(sample)), sample)

    def test_rle_wins_for_long_runs(self) -> None:
        block = b"".join(bytes((value,)) * 5 for value in range(100))
        chosen = choose_best_mode(block)
        self.assertEqual(chosen.mode.id, ModeId.RLE)
        self.assertLess(len(chosen.payload), len(block))

    def test_delta_wins_for_smooth_wrapping_bytes(self) -> None:
        block = bytes(index % 256 for index in range(4096))
        chosen = choose_best_mode(block)
        self.assertEqual(chosen.mode.id, ModeId.DELTA8)
        self.assertLess(len(chosen.payload), len(block))

    def test_lz_wins_for_repeated_substrings(self) -> None:
        block = (b"the red fox jumped over the blue fence; " * 500)
        chosen = choose_best_mode(block)
        self.assertEqual(chosen.mode.id, ModeId.LZ_SIMPLE)
        self.assertLess(len(chosen.payload), len(block) // 4)

    def test_raw_wins_for_deterministic_noise(self) -> None:
        rng = random.Random(20260628)
        block = rng.randbytes(8192)
        chosen = choose_best_mode(block)
        self.assertEqual(chosen.mode.id, ModeId.RAW)

    def test_decoders_reject_malformed_payloads(self) -> None:
        malformed = {
            ModeId.RLE: b"\x00A",
            ModeId.DELTA8: b"A\x00B",
            ModeId.LZ_SIMPLE: b"\x01\x00\x01\x00\x06",
        }
        for mode_id, payload in malformed.items():
            with self.subTest(mode=mode_id), self.assertRaises(ArchiveFormatError):
                get_mode(mode_id).decode(payload, 8)


if __name__ == "__main__":
    unittest.main()
