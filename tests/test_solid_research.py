from __future__ import annotations

import hashlib
import io
import json
import random
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

from mosaic_archive.cdc import iter_content_defined_chunks
from mosaic_archive.corpus import MANIFEST_NAME, generate_corpus
from mosaic_archive.exceptions import ArchiveFormatError
from mosaic_archive.solid_research import decode_solid_chunks, encode_solid_chunks


class SolidLaneResearchTests(unittest.TestCase):
    def test_committed_scorecard_is_verified_and_not_a_release_claim(self) -> None:
        scorecard = json.loads(
            Path(".ecc/benchmarks/msc-v0.14-solid-lanes.json").read_text(
                encoding="utf-8"
            )
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
        prose = (
            b"Compression is prediction; solid lanes preserve distant relationships.\n"
            * 1024
        )
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
            manifest = generate_corpus(root)
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
            report = json.loads(
                Path("benchmarks/v0.12.0/report.json").read_text(encoding="utf-8")
            )
            seven_zip_size = report["comparisons"]["7z"]["archive_size"]

            self.assertLess(len(encoded.payload) + 16 * 1024, seven_zip_size)
            self.assertEqual(
                decode_solid_chunks(encoded.payload, [len(chunk) for chunk in chunks]),
                tuple(chunks),
            )


if __name__ == "__main__":
    unittest.main()
