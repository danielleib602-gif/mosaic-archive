from __future__ import annotations

import json
import random
import statistics
import unittest
from contextlib import ExitStack
from pathlib import Path
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

    def test_fast_profile_scorecard_is_format_neutral_and_repeated(self) -> None:
        scorecard = json.loads(
            Path(".ecc/benchmarks/msc-v0.40-fast-profile-analysis.json").read_text(
                encoding="utf-8"
            )
        )

        self.assertEqual(
            scorecard["baseline_commit"],
            "ea6348e03f4bd5d1886b575d465c4d3969a8af93",
        )
        self.assertEqual(
            scorecard["candidate_commit"],
            "d3b10229a48f79c86ef5f97a793710aa547273fb",
        )
        self.assertTrue(scorecard["configuration"]["alternating_fresh_processes"])
        self.assertEqual(
            scorecard["configuration"]["runs_per_revision_per_corpus"],
            11,
        )
        for corpus_name in ("corpus_v1", "corpus_v2"):
            corpus = scorecard[corpus_name]
            before = corpus["before"]
            after = corpus["after"]
            self.assertEqual(
                corpus["archive_improvement_bytes"],
                before["archive_bytes"] - after["archive_bytes"],
            )
            self.assertEqual(before["invariant_sha256"], after["invariant_sha256"])
            self.assertEqual(len(before["encode_seconds_runs"]), 11)
            self.assertEqual(len(after["encode_seconds_runs"]), 11)
            self.assertTrue(before["round_trip_verified"])
            self.assertTrue(after["round_trip_verified"])
            for measurement in (before, after):
                samples = measurement["encode_seconds_runs"]
                median = statistics.median(samples)
                self.assertEqual(measurement["encode_seconds_median"], median)
                self.assertEqual(
                    measurement["encode_seconds_median_absolute_deviation"],
                    statistics.median(abs(sample - median) for sample in samples),
                )
            expected_improvement = round(
                (
                    before["encode_seconds_median"]
                    - after["encode_seconds_median"]
                )
                / before["encode_seconds_median"]
                * 100,
                6,
            )
            self.assertEqual(corpus["encode_improvement_percent"], expected_improvement)
            self.assertGreater(corpus["encode_improvement_percent"], 20.0)

    def test_rejects_unknown_profile(self) -> None:
        with self.assertRaises(ValueError):
            choose_routed_mode(b"data", profile="turbo")


if __name__ == "__main__":
    unittest.main()
