from __future__ import annotations

import math
import unittest

from mosaic_archive.features import analyze_block


class FeatureTests(unittest.TestCase):
    def test_empty_block_has_finite_zero_features(self) -> None:
        features = analyze_block(b"")
        self.assertEqual(features.entropy_bits_per_byte, 0.0)
        self.assertEqual(features.ascii_ratio, 0.0)
        self.assertFalse(features.random_looking)

    def test_features_identify_text_and_zero_density(self) -> None:
        text = (b'{"name":"mosaic","count":0}\n' * 100) + (b"\x00" * 100)
        features = analyze_block(text)
        self.assertGreater(features.ascii_ratio, 0.8)
        self.assertGreater(features.zero_ratio, 0.02)
        self.assertGreater(features.substring_repetition_ratio, 0.5)
        self.assertFalse(features.random_looking)

    def test_uniform_byte_distribution_has_high_entropy(self) -> None:
        data = bytes(range(256)) * 32
        features = analyze_block(data)
        self.assertTrue(math.isclose(features.entropy_bits_per_byte, 8.0, abs_tol=0.01))
        self.assertGreater(features.small_symbol_ratio, 0.05)

    def test_smooth_delta_signal_is_detected(self) -> None:
        data = bytes(index % 256 for index in range(4096))
        features = analyze_block(data)
        self.assertGreater(features.delta_smoothness_ratio, 0.99)


if __name__ == "__main__":
    unittest.main()

