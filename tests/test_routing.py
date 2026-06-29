from __future__ import annotations

import random
import unittest
from unittest.mock import patch

from mosaic_archive.modes import ModeId, choose_routed_mode, get_mode


class RoutedSelectionTests(unittest.TestCase):
    def test_balanced_router_skips_slow_simple_lz(self) -> None:
        data = b"the red fox jumped over the blue fence; " * 2000
        slow_lz = get_mode(ModeId.LZ_SIMPLE)
        with patch.object(
            slow_lz,
            "encode",
            side_effect=AssertionError("slow LZ should not run in balanced mode"),
        ):
            selected = choose_routed_mode(data)
        self.assertLess(len(selected.payload), len(data))

    def test_router_retains_delta_for_smooth_signals(self) -> None:
        data = bytes(index % 256 for index in range(65_536))
        selected = choose_routed_mode(data)
        self.assertIn(selected.mode.id, {ModeId.DELTA8, ModeId.DEFLATE})
        self.assertLess(len(selected.payload), len(data) // 10)

    def test_router_uses_raw_for_incompressible_data(self) -> None:
        data = random.Random(99).randbytes(65_536)
        selected = choose_routed_mode(data)
        self.assertEqual(selected.mode.id, ModeId.RAW)

    def test_router_can_use_rans_for_skewed_symbols(self) -> None:
        rng = random.Random(789)
        data = bytes(rng.choices(range(16), weights=[50] + [1] * 15, k=65_536))
        selected = choose_routed_mode(data)
        self.assertIn(selected.mode.id, {ModeId.BYTE_RANS, ModeId.DEFLATE})
        self.assertLess(len(selected.payload), len(data) // 2)


if __name__ == "__main__":
    unittest.main()

