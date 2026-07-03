import hashlib
import json
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.prepare_review_bundle import build_review_bundle, verify_review_bundle


class ReviewBundleTests(unittest.TestCase):
    def _repository(self, root: Path) -> str:
        (root / "src").mkdir()
        (root / "src/example.py").write_text("VALUE = 1\n", encoding="utf-8")
        (root / "pyproject.toml").write_text(
            '[project]\nname = "example"\nversion = "1.2.3"\n',
            encoding="utf-8",
        )
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(["git", "add", "."], cwd=root, check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=Review Test",
                "-c",
                "user.email=review@example.invalid",
                "commit",
                "-qm",
                "fixture",
            ],
            cwd=root,
            check=True,
        )
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            text=True,
        ).strip()

    def test_bundle_is_deterministic_and_bound_to_git_objects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            commit = self._repository(root)
            first = root.parent / f"{root.name}-first.zip"
            second = root.parent / f"{root.name}-second.zip"
            self.addCleanup(first.unlink, missing_ok=True)
            self.addCleanup(second.unlink, missing_ok=True)

            build_review_bundle(root, first, "HEAD")
            (root / "src/example.py").write_text("DIRTY = True\n", encoding="utf-8")
            build_review_bundle(root, second, commit)

            self.assertEqual(first.read_bytes(), second.read_bytes())
            manifest = verify_review_bundle(first)
            self.assertEqual(manifest["source_commit"], commit)
            self.assertEqual(manifest["package_version"], "1.2.3")
            self.assertEqual(
                [item["path"] for item in manifest["files"]],
                ["pyproject.toml", "src/example.py"],
            )

    def test_verifier_rejects_modified_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._repository(root)
            bundle = root.parent / f"{root.name}-bundle.zip"
            tampered = root.parent / f"{root.name}-tampered.zip"
            self.addCleanup(bundle.unlink, missing_ok=True)
            self.addCleanup(tampered.unlink, missing_ok=True)
            build_review_bundle(root, bundle, "HEAD")

            with zipfile.ZipFile(bundle) as source, zipfile.ZipFile(
                tampered, "w", compression=zipfile.ZIP_STORED
            ) as target:
                for info in source.infolist():
                    payload = source.read(info.filename)
                    if info.filename.endswith("src/example.py"):
                        payload = b"VALUE = 2\n"
                    target.writestr(info, payload)

            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                verify_review_bundle(tampered)

    def test_verifier_rejects_compressed_members(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._repository(root)
            bundle = root.parent / f"{root.name}-bundle.zip"
            compressed = root.parent / f"{root.name}-compressed.zip"
            self.addCleanup(bundle.unlink, missing_ok=True)
            self.addCleanup(compressed.unlink, missing_ok=True)
            build_review_bundle(root, bundle, "HEAD")

            with zipfile.ZipFile(bundle) as source, zipfile.ZipFile(
                compressed, "w", compression=zipfile.ZIP_DEFLATED
            ) as target:
                for info in source.infolist():
                    target.writestr(
                        info.filename,
                        source.read(info.filename),
                        compress_type=zipfile.ZIP_DEFLATED,
                    )

            with self.assertRaisesRegex(ValueError, "stored without compression"):
                verify_review_bundle(compressed)

    def test_manifest_has_a_digest_for_every_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._repository(root)
            bundle = root.parent / f"{root.name}-bundle.zip"
            self.addCleanup(bundle.unlink, missing_ok=True)
            build_review_bundle(root, bundle, "HEAD")

            with zipfile.ZipFile(bundle) as archive:
                manifest_name = next(
                    name for name in archive.namelist() if name.endswith("REVIEW-MANIFEST.json")
                )
                prefix = manifest_name.removesuffix("REVIEW-MANIFEST.json")
                manifest = json.loads(archive.read(manifest_name))
                for entry in manifest["files"]:
                    payload = archive.read(prefix + entry["path"])
                    self.assertEqual(hashlib.sha256(payload).hexdigest(), entry["sha256"])
                    self.assertEqual(len(payload), entry["size"])


if __name__ == "__main__":
    unittest.main()
