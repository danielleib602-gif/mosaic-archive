from __future__ import annotations

import unittest
from pathlib import Path


class CiConfigurationTests(unittest.TestCase):
    def test_ci_uses_pinned_actions_and_read_only_permissions(self) -> None:
        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn("actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0", workflow)
        self.assertIn(
            "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1",
            workflow,
        )
        self.assertIn(
            "astral-sh/setup-uv@d31148d669074a8d0a63714ba94f3201e7020bc3",
            workflow,
        )

    def test_ci_covers_supported_platforms_and_security_gates(self) -> None:
        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
        for platform in ("ubuntu-latest", "windows-latest", "macos-latest"):
            self.assertIn(platform, workflow)
        for command in (
            "unittest discover",
            "ruff check",
            "mypy src",
            "bandit -q -r src -lll",
            "pip-audit",
            "msc readiness --require-automatic --json",
        ):
            self.assertIn(command, workflow)


if __name__ == "__main__":
    unittest.main()
