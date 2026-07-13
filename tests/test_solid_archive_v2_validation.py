from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mosaic_archive.solid_archive_v2 import (
    _restore,
    decode_solid_archive_v2,
    encode_solid_archive_v2,
)

PASSWORD = "solid-v2-validation"


class SolidArchiveV2ValidationTests(unittest.TestCase):
    def _create_archive(self, root: Path) -> tuple[Path, bytes]:
        source = root / "source.bin"
        archive = root / "archive.msr"
        source.write_bytes(b"solid archive validation fixture\n" * 64)
        encode_solid_archive_v2(source, archive, PASSWORD, kdf_log_n=14)
        return archive, archive.read_bytes()

    def test_decoder_rejects_archive_as_its_own_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive, original_archive = self._create_archive(Path(temp_dir))

            try:
                with self.assertRaises(ValueError):
                    decode_solid_archive_v2(archive, archive, PASSWORD)
            finally:
                self.assertEqual(archive.read_bytes(), original_archive)

    def test_decoder_rejects_hard_link_alias_of_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive, original_archive = self._create_archive(root)
            alias = root / "archive-alias.msr"
            try:
                os.link(archive, alias)
            except (NotImplementedError, OSError) as error:
                self.skipTest(f"hard links are unavailable: {error}")

            try:
                with (
                    patch(
                        "mosaic_archive.solid_archive_v2.derive_key",
                        side_effect=AssertionError(
                            "archive alias reached password derivation"
                        ),
                    ) as derive_key,
                    patch(
                        "mosaic_archive.solid_archive_v2.tempfile.TemporaryDirectory",
                        side_effect=AssertionError("archive alias created a decode spool"),
                    ) as temporary_directory,
                    self.assertRaises(ValueError),
                ):
                    decode_solid_archive_v2(archive, alias, PASSWORD)
                derive_key.assert_not_called()
                temporary_directory.assert_not_called()
            finally:
                self.assertEqual(archive.read_bytes(), original_archive)
                self.assertEqual(alias.read_bytes(), original_archive)

    def test_decoder_rejects_symbolic_link_alias_of_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive, original_archive = self._create_archive(root)
            alias = root / "archive-symbolic-alias.msr"
            try:
                alias.symlink_to(archive)
            except (NotImplementedError, OSError) as error:
                self.skipTest(f"symbolic links are unavailable: {error}")

            try:
                with self.assertRaises(ValueError):
                    decode_solid_archive_v2(archive, alias, PASSWORD)
            finally:
                self.assertEqual(archive.read_bytes(), original_archive)
                self.assertTrue(alias.is_symlink())
                self.assertEqual(alias.read_bytes(), original_archive)

    def test_decoder_rechecks_open_archive_identity_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive, original_archive = self._create_archive(root)
            destination = root / "late-alias.msr"
            try:
                os.link(archive, destination)
                destination.unlink()
            except (NotImplementedError, OSError) as error:
                self.skipTest(f"hard links are unavailable: {error}")

            def rebind_destination_before_restore(*args: object) -> None:
                os.link(archive, destination)
                _restore(*args)  # type: ignore[arg-type]

            try:
                with (
                    patch(
                        "mosaic_archive.solid_archive_v2._restore",
                        side_effect=rebind_destination_before_restore,
                    ),
                    self.assertRaises(ValueError),
                ):
                    decode_solid_archive_v2(archive, destination, PASSWORD)
            finally:
                self.assertEqual(archive.read_bytes(), original_archive)
                self.assertEqual(destination.read_bytes(), original_archive)
                self.assertEqual(list(root.glob(f".{destination.name}.*")), [])

    def test_encoder_rejects_invalid_frame_options_before_work_or_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source.bin"
            source.write_bytes(b"non-empty input")

            cases = (
                ("zero-frame", {"frame_payload_size": 0}, "payload size"),
                ("small-frame", {"frame_payload_size": 1023}, "payload size"),
                (
                    "large-frame",
                    {"frame_payload_size": 16 * 1024 * 1024 + 1},
                    "payload size",
                ),
                ("small-padding", {"padding_size": 255}, "padding size"),
                (
                    "large-padding",
                    {"frame_payload_size": 1024, "padding_size": 2048},
                    "padding size",
                ),
                ("float-frame", {"frame_payload_size": 1024.0}, "payload size"),
                ("float-padding", {"padding_size": 256.0}, "padding size"),
                ("float-kdf", {"kdf_log_n": 14.0}, "scrypt cost"),
            )
            for name, options, expected_error in cases:
                with self.subTest(name=name):
                    destination = root / f"{name}.msr"
                    parameters = {"kdf_log_n": 14} | options
                    with (
                        patch(
                            "mosaic_archive.solid_archive_v2._scan_manifest",
                            side_effect=AssertionError("invalid options scanned input"),
                        ) as scan_manifest,
                        patch(
                            "mosaic_archive.solid_archive_v2.derive_key",
                            side_effect=AssertionError("invalid options derived a key"),
                        ) as derive_key,
                        self.assertRaisesRegex(ValueError, expected_error),
                    ):
                        encode_solid_archive_v2(
                            source,
                            destination,
                            PASSWORD,
                            **parameters,
                        )

                    scan_manifest.assert_not_called()
                    derive_key.assert_not_called()
                    self.assertFalse(destination.exists())
                    self.assertEqual(list(root.glob(f".{destination.name}.*")), [])


if __name__ == "__main__":
    unittest.main()
