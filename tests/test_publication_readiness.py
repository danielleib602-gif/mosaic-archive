from __future__ import annotations

import re
import tomllib
import unittest
from pathlib import Path
from urllib.parse import unquote, urlparse


class PublicationReadinessTests(unittest.TestCase):
    def test_readme_capability_heading_matches_package_version(self) -> None:
        project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
        version = project["project"]["version"]
        release_line = ".".join(version.split(".")[:2])
        readme = Path("README.md").read_text(encoding="utf-8")

        self.assertIn(f"## What v{release_line} does", readme)
        self.assertIn("deterministic Gear", readme)

    def test_package_metadata_links_to_public_project_surfaces(self) -> None:
        project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
        urls = project["project"]["urls"]

        self.assertEqual(
            urls["Repository"],
            "https://github.com/danielleib602-gif/mosaic-archive",
        )
        self.assertTrue(urls["Issues"].endswith("/issues"))
        self.assertTrue(urls["Changelog"].endswith("/blob/main/CHANGELOG.md"))

    def test_public_maintainer_documents_are_present(self) -> None:
        required = {
            "CHANGELOG.md": "## [0.39.0]",
            "CONTRIBUTING.md": "## Verification",
            "SECURITY.md": "## Reporting a vulnerability",
            "PROJECT_STATUS.md": "Publication status: v0.39.0",
        }
        for relative_path, marker in required.items():
            with self.subTest(path=relative_path):
                content = Path(relative_path).read_text(encoding="utf-8")
                self.assertIn(marker, content)

    def test_github_community_templates_are_present(self) -> None:
        required = {
            ".github/ISSUE_TEMPLATE/bug_report.yml": "name: Bug report",
            ".github/ISSUE_TEMPLATE/feature_request.yml": "name: Feature request",
            ".github/ISSUE_TEMPLATE/config.yml": "blank_issues_enabled: false",
            ".github/pull_request_template.md": "## Verification",
        }
        for relative_path, marker in required.items():
            with self.subTest(path=relative_path):
                content = Path(relative_path).read_text(encoding="utf-8")
                self.assertIn(marker, content)

    def test_status_snapshot_names_current_version_and_active_work(self) -> None:
        status = Path("PROJECT_STATUS.md").read_text(encoding="utf-8")

        self.assertIn("Package version: 0.39.0", status)
        self.assertIn("## Current development focus", status)
        self.assertIn("independent security review", status)
        self.assertIn("`v0.39.0` is published", status)
        self.assertIn("Repository status at this snapshot: public", status)
        self.assertNotIn("rerun PR #", status)

    def test_independent_review_brief_is_bound_to_released_candidate(self) -> None:
        brief = Path("docs/INDEPENDENT_REVIEW.md").read_text(encoding="utf-8")

        self.assertIn("f99495cfc5be73617da8f929f89c3c044abbce89", brief)
        self.assertIn("e8c56dbecc0398deafcbcdf6c2193f503a084b8d", brief)
        self.assertIn(
            "2307cb50355e1b942718364780c8cb1af2dd9228d9550d864213f9d79ac7c130",
            brief,
        )
        self.assertIn("releases/tag/v0.39.0", brief)
        self.assertIn("../benchmarks/v0.39.0/report.md", brief)
        self.assertIn("mosaic-archive/issues/50", brief)

    def test_relative_markdown_links_resolve(self) -> None:
        markdown_files = (
            list(Path(".").glob("*.md"))
            + list(Path("benchmarks").rglob("*.md"))
            + list(Path("docs").rglob("*.md"))
            + list(Path("plans").rglob("*.md"))
        )
        link_pattern = re.compile(r"\[[^\]]+\]\(([^)]+)\)")

        for markdown_file in markdown_files:
            content = markdown_file.read_text(encoding="utf-8")
            for raw_target in link_pattern.findall(content):
                target = raw_target.strip().strip("<>").split("#", 1)[0]
                if not target or urlparse(target).scheme:
                    continue
                resolved = markdown_file.parent / unquote(target)
                with self.subTest(source=str(markdown_file), target=target):
                    self.assertTrue(resolved.exists(), f"broken link: {resolved}")


if __name__ == "__main__":
    unittest.main()
