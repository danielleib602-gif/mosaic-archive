from __future__ import annotations

import hashlib
import io
import json
import lzma
import math
import random
import struct
import tempfile
import unittest
import zlib
from collections import Counter
from pathlib import Path
from unittest.mock import patch

from mosaic_archive import dedup_archive, solid_research
from mosaic_archive.cdc import DEFAULT_CHUNKING, iter_content_defined_chunks
from mosaic_archive.corpus import MANIFEST_NAME, generate_corpus
from mosaic_archive.exceptions import ArchiveFormatError
from mosaic_archive.solid_frames import (
    SOLID_LANE_DELTA4,
    SOLID_LANE_HIGH_ENTROPY,
    SOLID_LANE_STANDARD,
)
from mosaic_archive.solid_research import (
    SOLID_LZMA_PRESET,
    choose_solid_lane,
    decode_solid_chunks,
    encode_solid_chunks,
)


def _numeric_ramp(size: int) -> bytes:
    count = (size + 3) // 4
    return b"".join(struct.pack("<i", index * 3 - 100_000) for index in range(count))[:size]


def _legacy_exact_route(chunk: bytes) -> int:
    if not chunk:
        return SOLID_LANE_STANDARD
    entropy = solid_research._byte_entropy_bits_per_byte(chunk)
    if entropy >= 7.75:
        return SOLID_LANE_HIGH_ENTROPY
    if entropy >= 3.0 and entropy - solid_research._delta4_entropy_bits_per_byte(chunk) >= 2.0:
        return SOLID_LANE_DELTA4
    return SOLID_LANE_STANDARD


class SolidLaneResearchTests(unittest.TestCase):
    def test_feature_router_avoids_trial_compression(self) -> None:
        numeric = b"".join(struct.pack("<i", index * 3) for index in range(16_384))
        text = b"compression is prediction\n" * 4096
        random_data = random.Random(25).randbytes(64 * 1024)

        with (
            patch(
                "mosaic_archive.solid_research._compress_standard",
                side_effect=AssertionError("trial compression was called"),
            ),
            patch(
                "mosaic_archive.solid_research._compress_delta4",
                side_effect=AssertionError("trial compression was called"),
            ),
            patch(
                "mosaic_archive.solid_research.analyze_block",
                side_effect=AssertionError("unneeded block features were analyzed"),
                create=True,
            ),
        ):
            self.assertEqual(choose_solid_lane(numeric), SOLID_LANE_DELTA4)
            self.assertEqual(choose_solid_lane(text), SOLID_LANE_STANDARD)
            self.assertEqual(
                choose_solid_lane(random_data),
                SOLID_LANE_HIGH_ENTROPY,
            )

    def test_solid_lanes_use_the_bounded_default_lzma_preset(self) -> None:
        self.assertEqual(SOLID_LZMA_PRESET, lzma.PRESET_DEFAULT)
        self.assertEqual(SOLID_LZMA_PRESET & lzma.PRESET_EXTREME, 0)

    def test_delta_router_switches_from_exact_to_bounded_sampling_at_limit(
        self,
    ) -> None:
        exact = solid_research._delta4_entropy_bits_per_byte
        sampled = solid_research._sampled_delta4_and_byte_entropy_bits_per_byte
        with (
            patch.object(
                solid_research,
                "_delta4_entropy_bits_per_byte",
                wraps=exact,
            ) as exact_spy,
            patch.object(
                solid_research,
                "_sampled_delta4_and_byte_entropy_bits_per_byte",
                wraps=sampled,
            ) as sampled_spy,
        ):
            self.assertEqual(choose_solid_lane(_numeric_ramp(8196)), SOLID_LANE_DELTA4)
            self.assertEqual(exact_spy.call_count, 1)
            self.assertEqual(sampled_spy.call_count, 0)

        with (
            patch.object(
                solid_research,
                "_delta4_entropy_bits_per_byte",
                wraps=exact,
            ) as exact_spy,
            patch.object(
                solid_research,
                "_sampled_delta4_and_byte_entropy_bits_per_byte",
                wraps=sampled,
            ) as sampled_spy,
        ):
            self.assertEqual(choose_solid_lane(_numeric_ramp(8197)), SOLID_LANE_DELTA4)
            self.assertEqual(exact_spy.call_count, 0)
            self.assertEqual(sampled_spy.call_count, 1)

    def test_bounded_delta_sampler_reads_distributed_contiguous_windows(self) -> None:
        class CountingBytes(bytes):
            def __new__(cls, value: bytes):
                instance = super().__new__(cls, value)
                instance.accesses = []
                return instance

            def __getitem__(self, key):
                if isinstance(key, int):
                    self.accesses.append(key)
                return super().__getitem__(key)

        chunk = CountingBytes((bytes(range(256)) * 391)[:100_004])
        delta_entropy, byte_entropy = solid_research._sampled_delta4_and_byte_entropy_bits_per_byte(
            chunk
        )
        starts = solid_research._delta_sample_window_starts(chunk)

        self.assertTrue(math.isfinite(delta_entropy))
        self.assertTrue(math.isfinite(byte_entropy))
        self.assertEqual(solid_research._DELTA_EXACT_OBSERVATION_LIMIT, 8192)
        self.assertEqual(solid_research._DELTA_SAMPLE_OBSERVATION_COUNT, 4095)
        self.assertEqual(solid_research._DELTA_SAMPLE_WINDOW_COUNT, 15)
        self.assertEqual(
            solid_research._DELTA_SAMPLE_OBSERVATIONS_PER_WINDOW,
            273,
        )
        self.assertEqual(solid_research._DELTA_SAMPLE_WINDOW_BYTES, 277)
        self.assertEqual(
            solid_research._DELTA_SAMPLE_WINDOW_COUNT
            * solid_research._DELTA_SAMPLE_OBSERVATIONS_PER_WINDOW,
            solid_research._DELTA_SAMPLE_OBSERVATION_COUNT,
        )
        self.assertEqual(len(chunk.accesses), 8190)
        self.assertEqual(len(set(chunk.accesses)), 4155)
        self.assertEqual(
            starts,
            (
                5663,
                7311,
                17774,
                25866,
                29938,
                38030,
                42102,
                52565,
                54266,
                64729,
                68801,
                76893,
                80965,
                89057,
                99520,
            ),
        )
        for index, start in enumerate(starts):
            region_start = index * len(chunk) // len(starts)
            region_end = (index + 1) * len(chunk) // len(starts)
            self.assertGreaterEqual(start, region_start)
            self.assertLessEqual(
                start + solid_research._DELTA_SAMPLE_WINDOW_BYTES,
                region_end,
            )
        self.assertTrue(
            all(
                current - previous == 4
                for current, previous in zip(
                    chunk.accesses[::2],
                    chunk.accesses[1::2],
                    strict=True,
                )
            )
        )

    def test_delta_sample_guard_boundaries_are_inclusive(self) -> None:
        chunk = bytes(8197)
        cases = (
            (2.75, SOLID_LANE_DELTA4),
            (3.25, SOLID_LANE_STANDARD),
        )
        for sampled_entropy, expected_lane in cases:
            with (
                self.subTest(sampled_entropy=sampled_entropy),
                patch.object(
                    solid_research,
                    "_byte_entropy_bits_per_byte",
                    return_value=5.0,
                ),
                patch.object(
                    solid_research,
                    "_sampled_delta4_and_byte_entropy_bits_per_byte",
                    return_value=(sampled_entropy, 5.0),
                ),
                patch.object(
                    solid_research,
                    "_delta4_entropy_bits_per_byte",
                    side_effect=AssertionError("guard boundary used exact fallback"),
                ),
            ):
                self.assertEqual(choose_solid_lane(chunk), expected_lane)

    def test_ambiguous_delta_sample_falls_back_to_exact_delta_route(self) -> None:
        size = 64 * 1024
        numeric = _numeric_ramp(size)
        random_data = random.Random(1).randbytes(size)
        cut = size * 61 // 100
        chunk = numeric[:cut] + random_data[cut:]
        exact = solid_research._delta4_entropy_bits_per_byte

        with patch.object(solid_research, "_delta4_entropy_bits_per_byte", wraps=exact) as spy:
            self.assertEqual(choose_solid_lane(chunk), SOLID_LANE_DELTA4)
            self.assertEqual(spy.call_count, 1)

    def test_ambiguous_delta_sample_falls_back_to_exact_standard_route(self) -> None:
        size = 64 * 1024
        numeric = _numeric_ramp(size)
        random_data = random.Random(1).randbytes(size)
        cut = size * 52 // 100
        chunk = numeric[:cut] + random_data[cut:]
        exact = solid_research._delta4_entropy_bits_per_byte

        with patch.object(solid_research, "_delta4_entropy_bits_per_byte", wraps=exact) as spy:
            self.assertEqual(choose_solid_lane(chunk), SOLID_LANE_STANDARD)
            self.assertEqual(spy.call_count, 1)

    def test_distributed_sample_ignores_fixed_window_poison(self) -> None:
        size = 64 * 1024
        chunk = bytearray(_numeric_ramp(size))
        window = 1369
        starts = (0, (size - window) // 2, size - window)
        fragment = b"Compression is prediction. Mosaic routes local structure safely.\n"
        replacement = (fragment * ((window + len(fragment) - 1) // len(fragment)))[:window]
        for start in starts:
            chunk[start : start + window] = replacement
        payload = bytes(chunk)
        sampled_delta_entropy, _ = solid_research._sampled_delta4_and_byte_entropy_bits_per_byte(
            payload
        )

        self.assertGreaterEqual(
            solid_research._byte_entropy_bits_per_byte(payload) - sampled_delta_entropy,
            2.25,
        )
        with patch.object(
            solid_research,
            "_delta4_entropy_bits_per_byte",
            side_effect=AssertionError("distributed sample used exact fallback"),
        ) as spy:
            self.assertEqual(choose_solid_lane(payload), SOLID_LANE_DELTA4)
            self.assertEqual(spy.call_count, 0)

    def test_distributed_sample_rejects_fixed_window_false_delta(self) -> None:
        size = 64 * 1024
        payload = bytearray(_numeric_ramp(size))
        window = 1369
        starts = (0, (size - window) // 2, size - window)
        outside = [
            index
            for index in range(size)
            if not any(start <= index < start + window for start in starts)
        ]
        shuffled = [payload[index] for index in outside]
        random.Random(41).shuffle(shuffled)
        for index, value in zip(outside, shuffled, strict=True):
            payload[index] = value
        chunk = bytes(payload)

        self.assertEqual(_legacy_exact_route(chunk), SOLID_LANE_STANDARD)
        self.assertLess(
            len(solid_research._compress_standard(chunk)),
            len(solid_research._compress_delta4(chunk)),
        )
        self.assertEqual(choose_solid_lane(chunk), SOLID_LANE_STANDARD)

    def test_distributed_sample_rejects_fixed_window_false_standard(self) -> None:
        size = 64 * 1024
        payload = bytearray(_numeric_ramp(size))
        window = 1369
        starts = (0, (size - window) // 2, size - window)
        rng = random.Random(41)
        for start in starts:
            shuffled = list(payload[start : start + window])
            rng.shuffle(shuffled)
            payload[start : start + window] = bytes(shuffled)
        chunk = bytes(payload)

        self.assertEqual(_legacy_exact_route(chunk), SOLID_LANE_DELTA4)
        self.assertLess(
            len(solid_research._compress_delta4(chunk)),
            len(solid_research._compress_standard(chunk)),
        )
        self.assertEqual(choose_solid_lane(chunk), SOLID_LANE_DELTA4)

    def test_contiguous_sampling_avoids_unicode_stride_phase_alias(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            generate_corpus(root, corpus_version=2)
            chunk = (root / "unicode" / "multilingual.txt").read_bytes()

        byte_entropy = solid_research._byte_entropy_bits_per_byte(chunk)
        sampled_delta_entropy, _ = solid_research._sampled_delta4_and_byte_entropy_bits_per_byte(
            chunk
        )
        stride = (len(chunk) - 4) // 4095
        strided_counts = Counter(
            (chunk[index] - chunk[index - 4]) & 0xFF for index in range(4, len(chunk), stride)
        )
        strided_total = sum(strided_counts.values())
        strided_delta_entropy = -sum(
            (count / strided_total) * math.log2(count / strided_total)
            for count in strided_counts.values()
        )

        self.assertEqual(stride, 32)
        self.assertLessEqual(byte_entropy - sampled_delta_entropy, 1.75)
        self.assertGreaterEqual(byte_entropy - strided_delta_entropy, 2.25)
        with patch.object(
            solid_research,
            "_delta4_entropy_bits_per_byte",
            side_effect=AssertionError("decisive distributed sample used exact fallback"),
        ):
            self.assertEqual(choose_solid_lane(chunk), SOLID_LANE_STANDARD)

    def test_public_corpora_preserve_every_legacy_exact_route(self) -> None:
        cases = (
            (1, 13, 3, 3, 7),
            (2, 89, 76, 6, 7),
        )
        for version, unique_count, standard, delta4, high_entropy in cases:
            with self.subTest(corpus_version=version), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                generate_corpus(root, corpus_version=version)
                chunks: list[bytes] = []
                dedup_archive._scan_manifest(
                    root,
                    DEFAULT_CHUNKING,
                    on_unique_chunk=chunks.append,
                )

                legacy_routes = [_legacy_exact_route(chunk) for chunk in chunks]
                bounded_routes = [choose_solid_lane(chunk) for chunk in chunks]

                self.assertEqual(len(chunks), unique_count)
                self.assertEqual(bounded_routes, legacy_routes)
                self.assertEqual(
                    Counter(bounded_routes),
                    Counter(
                        {
                            SOLID_LANE_STANDARD: standard,
                            SOLID_LANE_DELTA4: delta4,
                            SOLID_LANE_HIGH_ENTROPY: high_entropy,
                        }
                    ),
                )

    def test_committed_scorecard_is_verified_and_not_a_release_claim(self) -> None:
        scorecard = json.loads(
            Path(".ecc/benchmarks/msc-v0.14-solid-lanes.json").read_text(encoding="utf-8")
        )

        self.assertTrue(scorecard["prototype"]["round_trip_verified"])
        self.assertLess(
            scorecard["prototype"]["projected_archive_bytes"],
            scorecard["committed_baselines"]["seven_zip_archive_bytes"],
        )
        self.assertEqual(
            scorecard["corpus"]["manifest_sha256"],
            "7588b726e796b3abf6047ead06101ea63c4e37900bcef5c060f8e36351c82290",
        )
        self.assertIn("not an MSC archive or release claim", scorecard["status"])

    def test_three_content_routed_lanes_round_trip(self) -> None:
        random_bytes = random.Random(17).randbytes(64 * 1024)
        numeric = b"".join(struct.pack("<i", index * 3 - 100_000) for index in range(16_384))
        prose = b"Compression is prediction; solid lanes preserve distant relationships.\n" * 1024
        chunks = (random_bytes, zlib.compress(random_bytes, level=0), numeric, prose)

        encoded = encode_solid_chunks(chunks)
        restored = decode_solid_chunks(encoded.payload, [len(chunk) for chunk in chunks])

        self.assertEqual(restored, chunks)
        self.assertEqual(
            encoded.lane_distribution,
            {"delta4": 1, "high_entropy": 2, "standard": 1},
        )
        self.assertLess(len(encoded.payload), 80 * 1024)

    def test_decoder_rejects_corruption_and_declared_size_mismatch(self) -> None:
        chunks = (b"solid lane safety" * 1024,)
        encoded = encode_solid_chunks(chunks)
        corrupted = encoded.payload[:-1] + bytes((encoded.payload[-1] ^ 1,))

        with self.assertRaises(ArchiveFormatError):
            decode_solid_chunks(corrupted, [len(chunks[0])])
        with self.assertRaises(ArchiveFormatError):
            decode_solid_chunks(encoded.payload, [len(chunks[0]) + 1])

    def test_fixed_corpus_payload_leaves_room_to_beat_7zip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest = generate_corpus(root, corpus_version=1)
            chunks: list[bytes] = []
            seen: set[bytes] = set()
            for entry in manifest["files"]:
                data = root.joinpath(*entry["path"].split("/")).read_bytes()
                for chunk in iter_content_defined_chunks(io.BytesIO(data)):
                    digest = hashlib.sha256(chunk).digest()
                    if digest not in seen:
                        seen.add(digest)
                        chunks.append(chunk)
            manifest_data = (root / MANIFEST_NAME).read_bytes()
            for chunk in iter_content_defined_chunks(io.BytesIO(manifest_data)):
                digest = hashlib.sha256(chunk).digest()
                if digest not in seen:
                    seen.add(digest)
                    chunks.append(chunk)

            encoded = encode_solid_chunks(chunks)
            report = json.loads(Path("benchmarks/v0.12.0/report.json").read_text(encoding="utf-8"))
            seven_zip_size = report["comparisons"]["7z"]["archive_size"]

            self.assertLess(len(encoded.payload) + 16 * 1024, seven_zip_size)
            self.assertEqual(
                decode_solid_chunks(encoded.payload, [len(chunk) for chunk in chunks]),
                tuple(chunks),
            )


if __name__ == "__main__":
    unittest.main()
