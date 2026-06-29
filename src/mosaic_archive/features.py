"""Cheap, file-agnostic block statistics used for observability and routing research."""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from itertools import pairwise


@dataclass(frozen=True, slots=True)
class BlockFeatures:
    entropy_bits_per_byte: float
    byte_repetition_ratio: float
    substring_repetition_ratio: float
    delta_smoothness_ratio: float
    ascii_ratio: float
    zero_ratio: float
    small_symbol_ratio: float
    random_looking: bool


def _substring_repetition_ratio(block: bytes) -> float:
    if len(block) < 8:
        return 0.0
    possible = len(block) - 3
    stride = max(1, possible // 4096)
    grams = [block[index : index + 4] for index in range(0, possible, stride)]
    return 1.0 - (len(set(grams)) / len(grams))


def analyze_block(block: bytes) -> BlockFeatures:
    """Return bounded statistics without consulting a filename or media type."""
    if not block:
        return BlockFeatures(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, False)

    length = len(block)
    histogram = Counter(block)
    entropy = -sum(
        (count / length) * math.log2(count / length) for count in histogram.values()
    )
    ascii_count = sum(byte in (9, 10, 13) or 32 <= byte <= 126 for byte in block)
    zero_count = histogram.get(0, 0)
    small_symbol_count = sum(count for byte, count in histogram.items() if byte < 16)
    substring_repetition = _substring_repetition_ratio(block)

    if length < 2:
        delta_smoothness = 0.0
    else:
        smooth = 0
        for previous, current in pairwise(block):
            signed_delta = ((current - previous + 128) % 256) - 128
            smooth += abs(signed_delta) <= 3
        delta_smoothness = smooth / (length - 1)

    byte_repetition = 1.0 - (len(histogram) / length)
    random_looking = (
        length >= 1024
        and entropy >= 7.85
        and substring_repetition <= 0.02
        and delta_smoothness <= 0.08
    )
    return BlockFeatures(
        entropy_bits_per_byte=entropy,
        byte_repetition_ratio=byte_repetition,
        substring_repetition_ratio=substring_repetition,
        delta_smoothness_ratio=delta_smoothness,
        ascii_ratio=ascii_count / length,
        zero_ratio=zero_count / length,
        small_symbol_ratio=small_symbol_count / length,
        random_looking=random_looking,
    )
