from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from mosaic_archive.archive_api import decode_path, inspect_path

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "compat"
MANIFEST_PATH = FIXTURE_ROOT / "manifest.json"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _manifest() -> dict[str, Any]:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


class PermanentCompatibilityFixtureTests(unittest.TestCase):
    """A current decoder must continue restoring every committed format generation."""

    def test_manifest_covers_every_supported_format_version(self) -> None:
        manifest = _manifest()

        versions = {entry["format_version"] for entry in manifest["fixtures"]}

        self.assertEqual(versions, set(range(1, 7)))
        self.assertEqual(manifest["fixture_schema"], 1)

    def test_committed_archives_restore_and_match_their_manifest(self) -> None:
        manifest = _manifest()
        password = manifest["password"]

        for entry in manifest["fixtures"]:
            with self.subTest(version=entry["format_version"]):
                archive = FIXTURE_ROOT / entry["archive"]
                archive_bytes = archive.read_bytes()
                version = entry["format_version"]
                self.assertEqual(archive_bytes[:4], f"MSC{version}".encode("ascii"))
                self.assertEqual(_sha256(archive_bytes), entry["archive_sha256"])

                info = inspect_path(archive, password)
                actual_version = getattr(info, "format_version", None)
                if actual_version is None:
                    actual_version = info.version
                self.assertEqual(actual_version, version)
                self.assertEqual(info.mode_distribution, {entry["mode"]: 1})
                self.assertTrue(info.hash_verified)

                with tempfile.TemporaryDirectory() as temp_dir:
                    restored = Path(temp_dir) / f"restored-v{version}.bin"
                    stats = decode_path(archive, restored, password)
                    self.assertTrue(stats.hash_verified)
                    self.assertEqual(_sha256(restored.read_bytes()), entry["content_sha256"])


if __name__ == "__main__":
    unittest.main()
