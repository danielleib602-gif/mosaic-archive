from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from mosaic_archive.compatibility import current_policy


class CompatibilityPolicyTests(unittest.TestCase):
    def test_policy_freezes_msc6_and_preserves_every_committed_decoder(self) -> None:
        fixture_manifest = json.loads(
            Path("tests/fixtures/compat/manifest.json").read_text(encoding="utf-8")
        )
        fixture_versions = tuple(
            entry["format_version"] for entry in fixture_manifest["fixtures"]
        )

        policy = current_policy()

        self.assertEqual(policy.package_version, "0.17.0")
        self.assertEqual(policy.writer_format_version, 6)
        self.assertEqual(policy.readable_format_versions, fixture_versions)
        self.assertEqual(policy.format_status, "frozen-for-1.0")
        self.assertEqual(policy.deprecation_notice_minor_releases, 2)
        self.assertTrue(policy.removal_requires_major_version)

    def test_cli_reports_machine_readable_policy_without_a_password(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "mosaic_archive",
                "compatibility",
                "--json",
            ],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual(report["operation"], "compatibility")
        self.assertEqual(report["writer_format_version"], 6)
        self.assertEqual(report["readable_format_versions"], list(range(1, 7)))
        self.assertEqual(report["incompatible_change_rule"], "new-format-version")

    def test_written_policy_records_upgrade_and_deprecation_rules(self) -> None:
        policy = Path("docs/COMPATIBILITY.md").read_text(encoding="utf-8")

        self.assertIn("MSC6 writer format is frozen", policy)
        self.assertIn("MSC1 through MSC6", policy)
        self.assertIn("two minor package releases", policy)
        self.assertIn("next major package version", policy)


if __name__ == "__main__":
    unittest.main()
