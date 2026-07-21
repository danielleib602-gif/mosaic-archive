from __future__ import annotations

import random
import unittest
from contextlib import ExitStack
from unittest.mock import patch

from mosaic_archive.features import analyze_block
from mosaic_archive.modes import ALL_MODES, ModeId, choose_routed_mode, get_mode


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

    def test_fast_profile_uses_only_raw_or_deflate(self) -> None:
        data = bytes(index % 256 for index in range(65_536))
        expected = min(
            (get_mode(mode_id) for mode_id in (ModeId.RAW, ModeId.DEFLATE)),
            key=lambda mode: len(mode.encode(data)),
        )
        with patch(
            "mosaic_archive.modes.analyze_block",
            side_effect=AssertionError("fast routing must not analyze unused features"),
        ):
            selected = choose_routed_mode(data, profile="fast")
        self.assertIn(selected.mode.id, {ModeId.RAW, ModeId.DEFLATE})
        self.assertEqual(selected.mode.id, expected.id)
        self.assertEqual(selected.payload, expected.encode(data))

    def test_fast_profile_retains_mode_order_tie_break_without_analysis(self) -> None:
        with ExitStack() as patches:
            for mode_id in (ModeId.RAW, ModeId.DEFLATE):
                patches.enter_context(
                    patch.object(get_mode(mode_id), "encode", return_value=b"tie")
                )
            patches.enter_context(
                patch(
                    "mosaic_archive.modes.analyze_block",
                    side_effect=AssertionError(
                        "fast routing must not analyze unused features"
                    ),
                )
            )
            selected = choose_routed_mode(b"payload", profile="fast")

        self.assertEqual(selected.mode.id, ModeId.RAW)
        self.assertEqual(selected.payload, b"tie")

    def test_research_profile_can_execute_lz_rans(self) -> None:
        data = b"research profile repeated content " * 2000
        expected = min(ALL_MODES, key=lambda mode: len(mode.encode(data)))
        with patch(
            "mosaic_archive.modes.analyze_block",
            side_effect=AssertionError("research routing must not analyze unused features"),
        ):
            selected = choose_routed_mode(data, profile="research")
        self.assertLess(len(selected.payload), len(data))
        self.assertEqual(selected.mode.id, expected.id)
        self.assertEqual(selected.payload, expected.encode(data))

    def test_research_profile_retains_mode_order_tie_break_without_analysis(self) -> None:
        with ExitStack() as patches:
            for mode in ALL_MODES:
                patches.enter_context(patch.object(mode, "encode", return_value=b"tie"))
            patches.enter_context(
                patch(
                    "mosaic_archive.modes.analyze_block",
                    side_effect=AssertionError(
                        "research routing must not analyze unused features"
                    ),
                )
            )
            selected = choose_routed_mode(b"payload", profile="research")

        self.assertEqual(selected.mode.id, ModeId.RAW)
        self.assertEqual(selected.payload, b"tie")

    def test_balanced_profile_analyzes_features_once(self) -> None:
        data = b"balanced profile data" * 100
        with patch(
            "mosaic_archive.modes.analyze_block",
            wraps=analyze_block,
        ) as analyzer:
            choose_routed_mode(data, profile="balanced")

        analyzer.assert_called_once_with(data)

    def test_rejects_unknown_profile(self) -> None:
        with self.assertRaises(ValueError):
            choose_routed_mode(b"data", profile="turbo")


if __name__ == "__main__":
    unittest.main()
