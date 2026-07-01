from __future__ import annotations

import unittest
from pathlib import Path


class CiConfigurationTests(unittest.TestCase):
    def test_ci_uses_pinned_actions_and_read_only_permissions(self) -> None:
        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn("actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10", workflow)
        self.assertIn(
            "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1",
            workflow,
        )
        self.assertIn(
            "astral-sh/setup-uv@08807647e7069bb48b6ef5acd8ec9567f424441b",
            workflow,
        )

    def test_ci_covers_supported_platforms_and_security_gates(self) -> None:
        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
        for platform in ("ubuntu-latest", "windows-latest", "macos-latest"):
            self.assertIn(platform, workflow)
        for command in ("unittest discover", "ruff check", "mypy src", "pip-audit"):
            self.assertIn(command, workflow)


if __name__ == "__main__":
    unittest.main()
