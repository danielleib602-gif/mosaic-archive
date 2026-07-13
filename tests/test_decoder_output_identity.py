from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import mosaic_archive.archive as legacy_archive
import mosaic_archive.solid_archive as solid_archive
from mosaic_archive.archive_api import decode_path
from mosaic_archive.solid_archive import decode_solid_archive, encode_solid_archive
from mosaic_archive.stream_archive import ProgressEvent

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "compat"
FIXTURE_MANIFEST = json.loads(
    (FIXTURE_ROOT / "manifest.json").read_text(encoding="utf-8")
)
FIXTURE_PASSWORD = FIXTURE_MANIFEST["password"]
MSR1_PASSWORD = "decoder output identity"


def _temporary_outputs(destination: Path) -> list[Path]:
    return list(destination.parent.glob(f".{destination.name}.*"))


class StableDecoderOutputIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _archive(self, version: int) -> tuple[Path, bytes]:
        fixture = FIXTURE_ROOT / f"msc{version}.msc"
        archive = self.root / f"archive-v{version}.msc"
        original = fixture.read_bytes()
        archive.write_bytes(original)
        return archive, original

    def test_every_stable_decoder_rejects_archive_as_its_destination(self) -> None:
        for version in range(1, 7):
            with self.subTest(version=version):
                archive, original = self._archive(version)

                with self.assertRaisesRegex(
                    ValueError,
                    "archive and output paths must be different",
                ):
                    decode_path(archive, archive, FIXTURE_PASSWORD)

                self.assertEqual(archive.read_bytes(), original)
                self.assertEqual(_temporary_outputs(archive), [])

    def test_every_stable_decoder_rejects_hard_link_alias(self) -> None:
        probe_source = self.root / "hard-link-probe-source"
        probe = self.root / "hard-link-probe"
        probe_source.write_bytes(b"hard-link capability probe")
        try:
            os.link(probe_source, probe)
            probe.unlink()
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"hard links are unavailable: {error}")

        for version in range(1, 7):
            with self.subTest(version=version):
                archive, original = self._archive(version)
                alias = self.root / f"hard-link-v{version}.msc"
                os.link(archive, alias)

                with self.assertRaisesRegex(
                    ValueError,
                    "archive and output paths must be different",
                ):
                    decode_path(archive, alias, FIXTURE_PASSWORD)

                self.assertEqual(archive.read_bytes(), original)
                self.assertEqual(alias.read_bytes(), original)
                self.assertEqual(_temporary_outputs(alias), [])

    def test_every_stable_decoder_rejects_symbolic_link_alias(self) -> None:
        probe = self.root / "symbolic-link-probe"
        try:
            probe.symlink_to(FIXTURE_ROOT / "msc1.msc")
            probe.unlink()
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"symbolic links are unavailable: {error}")

        for version in range(1, 7):
            with self.subTest(version=version):
                archive, original = self._archive(version)
                alias = self.root / f"symbolic-link-v{version}.msc"
                alias.symlink_to(archive)

                with self.assertRaisesRegex(
                    ValueError,
                    "archive and output paths must be different",
                ):
                    decode_path(archive, alias, FIXTURE_PASSWORD)

                self.assertEqual(archive.read_bytes(), original)
                self.assertTrue(alias.is_symlink())
                self.assertEqual(alias.read_bytes(), original)
                self.assertEqual(_temporary_outputs(alias), [])

    def test_initial_aliases_fail_before_password_derivation(self) -> None:
        cases = (
            (1, "mosaic_archive.archive.derive_key"),
            (2, "mosaic_archive.stream_archive.derive_key"),
            (6, "mosaic_archive.dedup_archive.derive_key"),
        )
        for version, derive_key_target in cases:
            with self.subTest(version=version):
                archive, original = self._archive(version)
                alias = self.root / f"fail-fast-v{version}.msc"
                try:
                    os.link(archive, alias)
                except (NotImplementedError, OSError) as error:
                    self.skipTest(f"hard links are unavailable: {error}")

                with (
                    patch(
                        derive_key_target,
                        side_effect=AssertionError("alias reached password derivation"),
                    ) as derive_key,
                    self.assertRaisesRegex(
                        ValueError,
                        "archive and output paths must be different",
                    ),
                ):
                    decode_path(archive, alias, FIXTURE_PASSWORD)

                derive_key.assert_not_called()
                self.assertEqual(archive.read_bytes(), original)
                self.assertEqual(alias.read_bytes(), original)
                self.assertEqual(_temporary_outputs(alias), [])

    def test_msc6_initial_alias_fails_before_chunk_cache_creation(self) -> None:
        archive, original = self._archive(6)
        alias = self.root / "fail-fast-v6-cache.msc"
        try:
            os.link(archive, alias)
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"hard links are unavailable: {error}")

        with (
            patch(
                "mosaic_archive.dedup_archive.tempfile.TemporaryDirectory",
                side_effect=AssertionError("archive alias created a chunk cache"),
            ) as temporary_directory,
            self.assertRaisesRegex(
                ValueError,
                "archive and output paths must be different",
            ),
        ):
            decode_path(archive, alias, FIXTURE_PASSWORD)

        temporary_directory.assert_not_called()
        self.assertEqual(archive.read_bytes(), original)
        self.assertEqual(alias.read_bytes(), original)
        self.assertEqual(_temporary_outputs(alias), [])

    def test_msc1_rechecks_archive_identity_before_publication(self) -> None:
        archive, original = self._archive(1)
        destination = self.root / "late-msc1-alias.msc"
        real_decode_records = legacy_archive._decode_records

        def decode_then_rebind(*args: object) -> object:
            result = real_decode_records(*args)  # type: ignore[arg-type]
            os.link(archive, destination)
            return result

        try:
            with (
                patch(
                    "mosaic_archive.archive._decode_records",
                    side_effect=decode_then_rebind,
                ),
                self.assertRaisesRegex(
                    ValueError,
                    "archive and output paths must be different",
                ),
            ):
                decode_path(archive, destination, FIXTURE_PASSWORD)
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"hard links are unavailable: {error}")

        self.assertEqual(archive.read_bytes(), original)
        self.assertEqual(destination.read_bytes(), original)
        self.assertEqual(_temporary_outputs(destination), [])

    def test_stream_and_dedup_decoders_recheck_identity_before_publication(self) -> None:
        real_temporary_directory = tempfile.TemporaryDirectory
        for version in (2, 6):
            with self.subTest(version=version):
                archive, original = self._archive(version)
                destination = self.root / f"late-v{version}-alias.msc"
                rebound = False
                cache_paths: list[Path] = []

                def tracked_chunk_cache(
                    *args: object,
                    paths: list[Path] = cache_paths,
                    **kwargs: object,
                ) -> object:
                    kwargs["dir"] = self.root
                    cache = real_temporary_directory(
                        *args,  # type: ignore[arg-type]
                        **kwargs,  # type: ignore[arg-type]
                    )
                    paths.append(Path(cache.name))
                    return cache

                def rebind_after_final_progress(
                    event: ProgressEvent,
                    archive_path: Path = archive,
                    output_path: Path = destination,
                ) -> None:
                    nonlocal rebound
                    if event.completed_files == 1 and not rebound:
                        try:
                            os.link(archive_path, output_path)
                        except (NotImplementedError, OSError) as error:
                            raise unittest.SkipTest(
                                f"hard links are unavailable: {error}"
                            ) from error
                        rebound = True

                with (
                    patch(
                        "mosaic_archive.dedup_archive.tempfile.TemporaryDirectory",
                        side_effect=tracked_chunk_cache,
                    ),
                    self.assertRaisesRegex(
                        ValueError,
                        "archive and output paths must be different",
                    ),
                ):
                    decode_path(
                        archive,
                        destination,
                        FIXTURE_PASSWORD,
                        progress=rebind_after_final_progress,
                    )

                self.assertTrue(rebound)
                if version == 6:
                    self.assertEqual(len(cache_paths), 1)
                    self.assertFalse(cache_paths[0].exists())
                else:
                    self.assertEqual(cache_paths, [])
                self.assertEqual(archive.read_bytes(), original)
                self.assertEqual(destination.read_bytes(), original)
                self.assertEqual(_temporary_outputs(destination), [])


class ExperimentalSolidDecoderOutputIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        source = self.root / "source.bin"
        source.write_bytes(b"MSR1 output identity payload\n" * 64)
        self.archive = self.root / "archive.msr"
        encode_solid_archive(
            source,
            self.archive,
            MSR1_PASSWORD,
            padding_size=256,
            kdf_log_n=14,
        )
        self.original = self.archive.read_bytes()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_msr1_rejects_archive_as_its_destination(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            "archive and output paths must be different",
        ):
            decode_solid_archive(self.archive, self.archive, MSR1_PASSWORD)

        self.assertEqual(self.archive.read_bytes(), self.original)
        self.assertEqual(_temporary_outputs(self.archive), [])

    def test_msr1_rejects_hard_link_alias_before_password_derivation(self) -> None:
        alias = self.root / "hard-link.msr"
        try:
            os.link(self.archive, alias)
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"hard links are unavailable: {error}")

        with (
            patch(
                "mosaic_archive.solid_archive.derive_key",
                side_effect=AssertionError("alias reached password derivation"),
            ) as derive_key,
            self.assertRaisesRegex(
                ValueError,
                "archive and output paths must be different",
            ),
        ):
            decode_solid_archive(self.archive, alias, MSR1_PASSWORD)

        derive_key.assert_not_called()
        self.assertEqual(self.archive.read_bytes(), self.original)
        self.assertEqual(alias.read_bytes(), self.original)
        self.assertEqual(_temporary_outputs(alias), [])

    def test_msr1_rejects_symbolic_link_alias(self) -> None:
        alias = self.root / "symbolic-link.msr"
        try:
            alias.symlink_to(self.archive)
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"symbolic links are unavailable: {error}")

        with self.assertRaisesRegex(
            ValueError,
            "archive and output paths must be different",
        ):
            decode_solid_archive(self.archive, alias, MSR1_PASSWORD)

        self.assertEqual(self.archive.read_bytes(), self.original)
        self.assertTrue(alias.is_symlink())
        self.assertEqual(alias.read_bytes(), self.original)
        self.assertEqual(_temporary_outputs(alias), [])

    def test_msr1_rechecks_archive_identity_before_publication(self) -> None:
        destination = self.root / "late-alias.msr"
        real_apply_metadata = solid_archive._apply_metadata
        rebound = False

        def apply_metadata_then_rebind(*args: object) -> None:
            nonlocal rebound
            real_apply_metadata(*args)  # type: ignore[arg-type]
            if not rebound:
                os.link(self.archive, destination)
                rebound = True

        try:
            with (
                patch(
                    "mosaic_archive.solid_archive._apply_metadata",
                    side_effect=apply_metadata_then_rebind,
                ),
                self.assertRaisesRegex(
                    ValueError,
                    "archive and output paths must be different",
                ),
            ):
                decode_solid_archive(self.archive, destination, MSR1_PASSWORD)
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"hard links are unavailable: {error}")

        self.assertTrue(rebound)
        self.assertEqual(self.archive.read_bytes(), self.original)
        self.assertEqual(destination.read_bytes(), self.original)
        self.assertEqual(_temporary_outputs(destination), [])

    def test_msr1_late_folder_alias_removes_temporary_tree(self) -> None:
        source = self.root / "folder-source"
        source.mkdir()
        (source / "payload.bin").write_bytes(b"folder identity payload" * 64)
        archive = self.root / "folder-archive.msr"
        encode_solid_archive(
            source,
            archive,
            MSR1_PASSWORD,
            padding_size=256,
            kdf_log_n=14,
        )
        original = archive.read_bytes()
        destination = self.root / "late-folder-alias.msr"
        real_apply_metadata = solid_archive._apply_metadata
        rebound = False

        def apply_metadata_then_rebind(*args: object) -> None:
            nonlocal rebound
            real_apply_metadata(*args)  # type: ignore[arg-type]
            if not rebound:
                os.link(archive, destination)
                rebound = True

        try:
            with (
                patch(
                    "mosaic_archive.solid_archive._apply_metadata",
                    side_effect=apply_metadata_then_rebind,
                ),
                self.assertRaisesRegex(
                    ValueError,
                    "archive and output paths must be different",
                ),
            ):
                decode_solid_archive(archive, destination, MSR1_PASSWORD)
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"hard links are unavailable: {error}")

        self.assertTrue(rebound)
        self.assertEqual(archive.read_bytes(), original)
        self.assertEqual(destination.read_bytes(), original)
        self.assertEqual(_temporary_outputs(destination), [])


if __name__ == "__main__":
    unittest.main()
