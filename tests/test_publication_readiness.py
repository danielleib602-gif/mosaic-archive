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
            "CHANGELOG.md": "## [0.32.0]",
            "CONTRIBUTING.md": "## Verification",
            "SECURITY.md": "## Reporting a vulnerability",
            "PROJECT_STATUS.md": "Publication status: READY",
        }
        for relative_path, marker in required.items():
            with self.subTest(path=relative_path):
                content = Path(relative_path).read_text(encoding="utf-8")
                self.assertIn(marker, content)

    def test_status_snapshot_names_current_version_and_active_work(self) -> None:
        status = Path("PROJECT_STATUS.md").read_text(encoding="utf-8")

        self.assertIn("Package version: 0.32.0", status)
        self.assertIn("## Current development focus", status)
        self.assertIn("independent security review", status)

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
