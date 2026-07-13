import os
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.prepare_release_binary import _normalized_architecture


class ReleaseBinaryTests(unittest.TestCase):
    def test_architecture_name_falls_back_to_windows_environment(self) -> None:
        with (
            patch("scripts.prepare_release_binary.platform.machine", return_value=""),
            patch.dict(
                os.environ,
                {"RUNNER_ARCH": "", "PROCESSOR_ARCHITECTURE": "AMD64"},
                clear=False,
            ),
        ):
            self.assertEqual(_normalized_architecture(), "x86_64")

    def test_architecture_name_falls_back_to_python_platform_tag(self) -> None:
        with (
            patch("scripts.prepare_release_binary.platform.machine", return_value=""),
            patch(
                "scripts.prepare_release_binary.sysconfig.get_platform",
                return_value="win-amd64",
            ),
            patch.dict(
                os.environ,
                {"RUNNER_ARCH": "", "PROCESSOR_ARCHITECTURE": ""},
                clear=False,
            ),
        ):
            self.assertEqual(_normalized_architecture(), "x86_64")

    def test_release_recipe_matches_package_version(self) -> None:
        project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
        workflow = Path(".github/workflows/release.yml").read_text(encoding="utf-8")

        self.assertEqual(project["project"]["version"], "0.39.0")
        self.assertIn("--expected-version 0.39.0", workflow)
        self.assertIn("msc readiness --require-automatic --json", workflow)

    def test_stable_tags_require_all_one_zero_gates_before_building(self) -> None:
        workflow = Path(".github/workflows/release.yml").read_text(encoding="utf-8")

        self.assertIn("preflight:", workflow)
        self.assertIn("needs: preflight", workflow)
        self.assertIn("fetch-depth: 0", workflow)
        self.assertIn("Require repository gates for non-stable builds", workflow)
        self.assertIn("Require candidate-bound evidence for stable releases", workflow)
        self.assertIn("Require stable tag to target current protected main", workflow)
        self.assertIn('--release-tag "$GITHUB_REF_NAME"', workflow)
        self.assertIn('--release-commit "$GITHUB_SHA"', workflow)
        self.assertIn("--require-ready --json", workflow)
        self.assertGreaterEqual(workflow.count('--release-tag "$GITHUB_REF_NAME"'), 2)
        self.assertIn("--review-bundle", workflow)
        self.assertIn("gh attestation verify", workflow)
        self.assertIn('release["immutable"] is True', workflow)
        self.assertIn("Re-verify stable candidate seal before publication", workflow)
        self.assertIn("refs/tags/v0.", workflow)
        self.assertIn("startsWith(github.ref, 'refs/tags/')", workflow)

    def test_manual_workflow_can_publish_attested_candidate_release(self) -> None:
        workflow = Path(".github/workflows/release.yml").read_text(encoding="utf-8")

        self.assertIn("publish_candidate:", workflow)
        self.assertIn("candidate-v${PACKAGE_VERSION}-${GITHUB_SHA::12}", workflow)
        self.assertIn("git fetch --no-tags origin main", workflow)
        self.assertIn('test "$GITHUB_SHA" = "$(git rev-parse FETCH_HEAD)"', workflow)
        self.assertIn("--prerelease", workflow)
        self.assertIn("subject-checksums: release/SHA256SUMS", workflow)

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
        self.assertIn("actions/attest@a1948c3f048ba23858d222213b7c278aabede763", workflow)
        self.assertIn("subject-checksums: release/SHA256SUMS", workflow)
        self.assertIn('test "$GITHUB_REF_NAME" = "v$PACKAGE_VERSION"', workflow)
        self.assertIn("prepare_review_bundle.py build", workflow)
        self.assertIn("prepare_review_bundle.py verify", workflow)
        self.assertIn("mosaic-review-*.zip", workflow)
        self.assertIn("gh release", workflow)

    def test_review_bundle_workflow_builds_the_checked_out_commit(self) -> None:
        workflow = Path(".github/workflows/review-bundle.yml").read_text(encoding="utf-8")

        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn('fetch-depth: 0', workflow)
        self.assertIn('--revision "$GITHUB_SHA"', workflow)
        self.assertIn("prepare_review_bundle.py verify", workflow)
        self.assertIn("actions/upload-artifact@", workflow)

    def test_release_verification_is_documented(self) -> None:
        documentation = Path("docs/RELEASES.md").read_text(encoding="utf-8")

        self.assertIn("gh attestation verify", documentation)
        self.assertIn("SHA256SUMS", documentation)
        self.assertIn("Authenticode", documentation)
        self.assertIn("Apple Developer ID", documentation)


if __name__ == "__main__":
    unittest.main()
