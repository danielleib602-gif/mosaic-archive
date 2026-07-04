from __future__ import annotations

import io
import json
import random
import struct
import unittest
from pathlib import Path
from unittest.mock import patch

from mosaic_archive.exceptions import (
    ArchiveFormatError,
    AuthenticationError,
)
from mosaic_archive.solid_frames import (
    SOLID_LANE_DELTA4,
    SOLID_LANE_HIGH_ENTROPY,
    SOLID_LANE_STANDARD,
    compress_solid_lane,
    read_solid_lane_frames,
    write_precompressed_solid_lane_frames,
    write_solid_lane_frames,
)


class AuthenticatedSolidFrameTests(unittest.TestCase):
    def test_encoder_uses_lane_specific_bounded_match_search(self) -> None:
        with patch("mosaic_archive.solid_frames.lzma.LZMACompressor") as factory:
            factory.return_value.compress.return_value = b""
            factory.return_value.flush.return_value = b""
            compress_solid_lane(
                io.BytesIO(b"standard"),
                io.BytesIO(),
                lane=SOLID_LANE_STANDARD,
                raw_lzma2=True,
            )
            compress_solid_lane(
                io.BytesIO(b"delta"),
                io.BytesIO(),
                lane=SOLID_LANE_DELTA4,
                raw_lzma2=True,
            )

        standard = factory.call_args_list[0].kwargs["filters"][-1]
        delta = factory.call_args_list[1].kwargs["filters"][-1]
        self.assertEqual(standard["preset"], 6)
        self.assertEqual(standard["nice_len"], 48)
        self.assertEqual(standard["depth"], 12)
        self.assertEqual(delta["preset"], 5)

    def test_committed_public_corpus_scorecard_preserves_the_7zip_margin(self) -> None:
        scorecard = json.loads(
            Path(".ecc/benchmarks/msc-v0.17-authenticated-solid-frames.json").read_text(
                encoding="utf-8"
            )
        )

        self.assertTrue(scorecard["framed_lanes"]["round_trip_verified"])
        self.assertEqual(scorecard["framed_lanes"]["maximum_frame_payload_bytes"], 263576)
        self.assertLessEqual(
            scorecard["framed_lanes"]["maximum_frame_payload_bytes"],
            scorecard["configuration"]["frame_payload_limit_bytes"],
        )
        self.assertEqual(scorecard["projection"]["remaining_margin_vs_7zip_bytes"], 13000)
        self.assertFalse(scorecard["projection"]["end_to_end_msr2_claim"])

    def setUp(self) -> None:
        self.key = bytes(range(32))
        self.nonce_prefix = b"MSR2"
        self.aad = b"authenticated solid frame test"

    def test_incremental_stream_spans_bounded_authenticated_frames(self) -> None:
        data = random.Random(41).randbytes(256 * 1024)
        archive = io.BytesIO()

        written = write_solid_lane_frames(
            io.BytesIO(data),
            archive,
            key=self.key,
            nonce_prefix=self.nonce_prefix,
            associated_data=self.aad,
            lane=SOLID_LANE_HIGH_ENTROPY,
            start_index=7,
            frame_payload_size=4096,
            padding_size=512,
        )
        restored = io.BytesIO()
        archive.seek(0)
        read = read_solid_lane_frames(
            archive,
            restored,
            key=self.key,
            nonce_prefix=self.nonce_prefix,
            associated_data=self.aad,
            lane=SOLID_LANE_HIGH_ENTROPY,
            start_index=7,
            frame_count=written.frame_count,
            expected_size=len(data),
            frame_payload_size=4096,
            padding_size=512,
        )

        self.assertEqual(restored.getvalue(), data)
        self.assertGreater(written.frame_count, 10)
        self.assertLessEqual(written.max_frame_payload, 4096)
        self.assertEqual(read.next_index, written.next_index)
        self.assertEqual(read.decoded_size, len(data))

    def test_precompressed_lane_is_framed_without_a_second_compression_pass(
        self,
    ) -> None:
        data = random.Random(84).randbytes(256 * 1024)
        compressed = io.BytesIO()
        compressed_size = compress_solid_lane(
            io.BytesIO(data),
            compressed,
            lane=SOLID_LANE_HIGH_ENTROPY,
            raw_lzma2=True,
        )
        archive = io.BytesIO()
        compressed.seek(0)
        written = write_precompressed_solid_lane_frames(
            compressed,
            archive,
            compressed_size=compressed_size,
            key=self.key,
            nonce_prefix=self.nonce_prefix,
            associated_data=self.aad,
            lane=SOLID_LANE_HIGH_ENTROPY,
            start_index=0,
            frame_payload_size=4096,
            padding_size=512,
        )
        restored = io.BytesIO()
        archive.seek(0)
        read_solid_lane_frames(
            archive,
            restored,
            key=self.key,
            nonce_prefix=self.nonce_prefix,
            associated_data=self.aad,
            lane=SOLID_LANE_HIGH_ENTROPY,
            start_index=0,
            frame_count=written.frame_count,
            expected_size=len(data),
            frame_payload_size=4096,
            padding_size=512,
            raw_lzma2=True,
        )

        self.assertEqual(written.compressed_size, compressed_size)
        self.assertEqual(restored.getvalue(), data)

    def test_authenticated_raw_lane_round_trips_without_decompression(self) -> None:
        data = random.Random(85).randbytes(64 * 1024)
        archive = io.BytesIO()
        written = write_precompressed_solid_lane_frames(
            io.BytesIO(data),
            archive,
            compressed_size=len(data),
            key=self.key,
            nonce_prefix=self.nonce_prefix,
            associated_data=self.aad,
            lane=SOLID_LANE_HIGH_ENTROPY,
            start_index=0,
            frame_payload_size=4096,
            padding_size=512,
        )
        restored = io.BytesIO()
        archive.seek(0)

        read = read_solid_lane_frames(
            archive,
            restored,
            key=self.key,
            nonce_prefix=self.nonce_prefix,
            associated_data=self.aad,
            lane=SOLID_LANE_HIGH_ENTROPY,
            start_index=0,
            frame_count=written.frame_count,
            expected_size=len(data),
            frame_payload_size=4096,
            padding_size=512,
            passthrough=True,
        )

        self.assertEqual(restored.getvalue(), data)
        self.assertEqual(read.decoded_size, len(data))

    def test_delta_lane_round_trips_across_the_same_stream_contract(self) -> None:
        data = b"".join(struct.pack("<i", index * 3) for index in range(32_768))
        archive = io.BytesIO()
        written = write_solid_lane_frames(
            io.BytesIO(data),
            archive,
            key=self.key,
            nonce_prefix=self.nonce_prefix,
            associated_data=self.aad,
            lane=SOLID_LANE_DELTA4,
            start_index=0,
            frame_payload_size=4096,
            padding_size=512,
        )
        restored = io.BytesIO()
        archive.seek(0)
        read_solid_lane_frames(
            archive,
            restored,
            key=self.key,
            nonce_prefix=self.nonce_prefix,
            associated_data=self.aad,
            lane=SOLID_LANE_DELTA4,
            start_index=0,
            frame_count=written.frame_count,
            expected_size=len(data),
            frame_payload_size=4096,
            padding_size=512,
        )
        self.assertEqual(restored.getvalue(), data)

    def test_mutation_and_truncation_fail_closed(self) -> None:
        archive = io.BytesIO()
        written = write_solid_lane_frames(
            io.BytesIO(b"frame authentication" * 8192),
            archive,
            key=self.key,
            nonce_prefix=self.nonce_prefix,
            associated_data=self.aad,
            lane=SOLID_LANE_HIGH_ENTROPY,
            start_index=3,
            frame_payload_size=4096,
            padding_size=512,
        )
        encoded = bytearray(archive.getvalue())
        encoded[-1] ^= 1
        with self.assertRaises(AuthenticationError):
            read_solid_lane_frames(
                io.BytesIO(encoded),
                io.BytesIO(),
                key=self.key,
                nonce_prefix=self.nonce_prefix,
                associated_data=self.aad,
                lane=SOLID_LANE_HIGH_ENTROPY,
                start_index=3,
                frame_count=written.frame_count,
                expected_size=len(b"frame authentication" * 8192),
                frame_payload_size=4096,
                padding_size=512,
            )
        with self.assertRaises(ArchiveFormatError):
            read_solid_lane_frames(
                io.BytesIO(archive.getvalue()[:-1]),
                io.BytesIO(),
                key=self.key,
                nonce_prefix=self.nonce_prefix,
                associated_data=self.aad,
                lane=SOLID_LANE_HIGH_ENTROPY,
                start_index=3,
                frame_count=written.frame_count,
                expected_size=len(b"frame authentication" * 8192),
                frame_payload_size=4096,
                padding_size=512,
            )


if __name__ == "__main__":
    unittest.main()
