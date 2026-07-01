from __future__ import annotations

import hashlib
import json
import random
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mosaic_archive import dedup_archive, solid_archive_v2
from mosaic_archive.corpus import generate_corpus
from mosaic_archive.exceptions import ArchiveFormatError, AuthenticationError
from mosaic_archive.solid_archive_v2 import (
    _decode_metadata_envelope,
    decode_solid_archive_v2,
    encode_solid_archive_v2,
)


def _tree_digest(root: Path) -> bytes:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        digest.update(b"D" if path.is_dir() else b"F")
        digest.update(path.relative_to(root).as_posix().encode())
        if path.is_file():
            digest.update(path.read_bytes())
    return digest.digest()


class StreamingSolidArchiveTests(unittest.TestCase):
    def test_encoder_content_defined_chunks_each_file_only_once(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source, archive = root / "source.bin", root / "archive.msr"
            source.write_bytes((b"single-pass chunking evidence\n" * 8192) + bytes(range(256)))

            with (
                patch.object(
                    dedup_archive,
                    "iter_content_defined_chunks",
                    wraps=dedup_archive.iter_content_defined_chunks,
                ) as manifest_chunker,
                patch.object(
                    solid_archive_v2,
                    "iter_content_defined_chunks",
                    wraps=solid_archive_v2.iter_content_defined_chunks,
                ) as spool_chunker,
            ):
                encoded = encode_solid_archive_v2(
                    source,
                    archive,
                    "secret",
                    kdf_log_n=14,
                )

            self.assertEqual(manifest_chunker.call_count, 1)
            self.assertEqual(spool_chunker.call_count, 0)
            self.assertEqual(encoded.chunking_passes, 1)

    def test_metadata_envelope_retains_legacy_payloads_and_rejects_malformed_data(
        self,
    ) -> None:
        legacy = b"legacy MSR2 metadata"
        self.assertEqual(_decode_metadata_envelope(legacy), (legacy, False))
        with self.assertRaises(ArchiveFormatError):
            _decode_metadata_envelope(b"MDZ1\x01")

    def test_decode_limits_reject_expansion_and_frame_budgets_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source, archive = root / "source", root / "archive.msr"
            source.write_bytes(random.Random(91).randbytes(256 * 1024))
            encode_solid_archive_v2(
                source,
                archive,
                "secret",
                frame_payload_size=4096,
                kdf_log_n=14,
            )

            for name, limits in (
                ("size", {"max_output_size": 1024}),
                ("frames", {"max_frame_count": 2}),
            ):
                output = root / name / "output.bin"
                with self.subTest(limit=name), self.assertRaises(ArchiveFormatError):
                    decode_solid_archive_v2(archive, output, "secret", **limits)
                self.assertFalse(output.exists())
                self.assertFalse(output.parent.exists())

    def test_authentication_failure_has_no_filesystem_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source, archive = root / "source", root / "archive.msr"
            source.write_bytes(b"authenticate before creating output directories")
            encode_solid_archive_v2(source, archive, "secret", kdf_log_n=14)
            output = root / "new" / "nested" / "output.bin"

            with self.assertRaises(AuthenticationError):
                decode_solid_archive_v2(archive, output, "wrong")

            self.assertFalse(output.parent.exists())

    def test_empty_solid_lanes_do_not_emit_padded_frames(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source, archive, restored = root / "source.txt", root / "archive.msr", root / "out"
            source.write_bytes(b"the same compact sentence\n" * 4096)

            encoded = encode_solid_archive_v2(
                source,
                archive,
                "secret",
                kdf_log_n=14,
            )
            decoded = decode_solid_archive_v2(archive, restored, "secret")

            self.assertEqual(encoded.frame_count, 1)
            self.assertLess(encoded.archive_size, 3000)
            self.assertTrue(decoded.hash_verified)
            self.assertEqual(restored.read_bytes(), source.read_bytes())

    def test_compact_padding_beats_zip_on_the_text_category(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            corpus, archive, restored = root / "corpus", root / "text.msr", root / "out"
            generate_corpus(corpus)

            encoded = encode_solid_archive_v2(
                corpus / "text",
                archive,
                "secret",
                padding_size=256,
                kdf_log_n=14,
            )
            decoded = decode_solid_archive_v2(archive, restored, "secret")

            self.assertLess(encoded.archive_size, 680)
            self.assertTrue(decoded.hash_verified)
            self.assertEqual(_tree_digest(corpus / "text"), _tree_digest(restored))

    def test_committed_scorecard_records_an_actual_archive_win(self) -> None:
        scorecard = json.loads(
            Path(".ecc/benchmarks/msc-v0.18-msr2.json").read_text(encoding="utf-8")
        )
        self.assertTrue(scorecard["archive"]["round_trip_verified"])
        self.assertEqual(scorecard["archive"]["archive_bytes"], 279699)
        self.assertEqual(scorecard["archive"]["margin_vs_7zip_bytes"], 13132)
        self.assertFalse(scorecard["archive"]["stable_writer"])

    def test_v0_19_category_scorecard_reports_losses_as_plainly_as_wins(self) -> None:
        scorecard = json.loads(
            Path(".ecc/benchmarks/msc-v0.19-category-suite.json").read_text(
                encoding="utf-8"
            )
        )
        categories = {row["category"]: row for row in scorecard["categories"]}
        self.assertEqual(categories["numeric"]["delta_vs_zip_bytes"], -43566)
        self.assertEqual(categories["text"]["delta_vs_zip_bytes"], 1463)
        self.assertEqual(categories["random"]["delta_vs_zip_bytes"], 1985)
        self.assertTrue(all(row["round_trip_verified"] for row in categories.values()))

    def test_v0_20_compact_scorecard_beats_zip_except_on_incompressible_inputs(
        self,
    ) -> None:
        scorecard = json.loads(
            Path(".ecc/benchmarks/msc-v0.20-compact-suite.json").read_text(
                encoding="utf-8"
            )
        )
        categories = {row["category"]: row for row in scorecard["categories"]}
        self.assertEqual(scorecard["mixed"]["archive_bytes"], 276115)
        self.assertEqual(scorecard["mixed"]["margin_vs_7zip_bytes"], 16716)
        self.assertEqual(categories["text"]["delta_vs_zip_bytes"], -73)
        self.assertEqual(categories["random"]["delta_vs_zip_bytes"], 449)

    def test_public_corpus_round_trip_beats_committed_7zip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source, archive, restored = root / "corpus", root / "corpus.msr", root / "out"
            generate_corpus(source)
            seven_zip_size = json.loads(
                Path("benchmarks/v0.12.0/report.json").read_text(encoding="utf-8")
            )["comparisons"]["7z"]["archive_size"]

            encoded = encode_solid_archive_v2(
                source,
                archive,
                "correct horse battery staple",
                kdf_log_n=14,
            )
            decoded = decode_solid_archive_v2(
                archive,
                restored,
                "correct horse battery staple",
            )

            self.assertEqual(archive.read_bytes()[:4], b"MSR2")
            self.assertEqual(encoded.compression_passes, 1)
            self.assertEqual(encoded.routing_trial_compressions, 0)
            self.assertLess(encoded.archive_size, seven_zip_size)
            self.assertLessEqual(encoded.maximum_frame_payload, 1024 * 1024)
            self.assertTrue(decoded.hash_verified)
            self.assertEqual(_tree_digest(source), _tree_digest(restored))

    def test_small_frames_stream_and_tampering_never_publishes_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source"
            source.mkdir()
            (source / "data.bin").write_bytes(random.Random(18).randbytes(256 * 1024))
            archive = root / "archive.msr"
            encoded = encode_solid_archive_v2(
                source,
                archive,
                "secret",
                frame_payload_size=4096,
                kdf_log_n=14,
            )
            self.assertGreater(encoded.frame_count, 3)

            data = bytearray(archive.read_bytes())
            data[-1] ^= 1
            archive.write_bytes(data)
            output = root / "tampered"
            with self.assertRaises(AuthenticationError):
                decode_solid_archive_v2(archive, output, "secret")
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
