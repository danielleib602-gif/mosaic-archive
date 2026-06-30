import unittest
from pathlib import Path
import tomllib


class ReleaseBinaryTests(unittest.TestCase):
    def test_release_recipe_matches_package_version(self) -> None:
        project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
        workflow = Path(".github/workflows/release.yml").read_text(encoding="utf-8")

        self.assertEqual(project["project"]["version"], "0.13.0")
        self.assertIn("--expected-version 0.13.0", workflow)

    def test_release_workflow_builds_and_smoke_tests_every_platform(self) -> None:
        workflow = Path(".github/workflows/release.yml").read_text(encoding="utf-8")

        self.assertIn("pull_request:\n    paths:", workflow)
        self.assertIn('tags: ["v*"]', workflow)
        for runner in ("ubuntu-latest", "windows-latest", "macos-latest"):
            self.assertIn(runner, workflow)
        self.assertIn("pyinstaller==6.21.0", workflow)
        self.assertIn("--onefile", workflow)
        self.assertIn("--noupx", workflow)
        self.assertIn("actions/upload-artifact@", workflow)
        helper = Path("scripts/prepare_release_binary.py").read_text(encoding="utf-8")
        self.assertIn('"--version"', helper)

    def test_tag_release_has_checksums_and_keyless_signed_provenance(self) -> None:
        workflow = Path(".github/workflows/release.yml").read_text(encoding="utf-8")

        self.assertIn("if: startsWith(github.ref, 'refs/tags/v')", workflow)
        self.assertIn("contents: write", workflow)
        self.assertIn("id-token: write", workflow)
        self.assertIn("attestations: write", workflow)
        self.assertIn("SHA256SUMS", workflow)
        self.assertIn("actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26", workflow)
        self.assertIn("subject-checksums: release/SHA256SUMS", workflow)
        self.assertIn("gh release", workflow)

    def test_release_verification_is_documented(self) -> None:
        documentation = Path("docs/RELEASES.md").read_text(encoding="utf-8")

        self.assertIn("gh attestation verify", documentation)
        self.assertIn("SHA256SUMS", documentation)
        self.assertIn("Authenticode", documentation)
        self.assertIn("Apple Developer ID", documentation)


if __name__ == "__main__":
    unittest.main()
