from __future__ import annotations

import io
import random
import struct
import unittest

from mosaic_archive.exceptions import (
    ArchiveFormatError,
    AuthenticationError,
)
from mosaic_archive.solid_frames import (
    SOLID_LANE_DELTA4,
    SOLID_LANE_HIGH_ENTROPY,
    read_solid_lane_frames,
    write_solid_lane_frames,
)


class AuthenticatedSolidFrameTests(unittest.TestCase):
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
