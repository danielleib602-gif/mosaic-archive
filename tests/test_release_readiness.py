from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from mosaic_archive.release_readiness import evaluate_release_readiness


class ReleaseReadinessTests(unittest.TestCase):
    def test_current_repository_is_seven_of_nine_gates_complete(self) -> None:
        report = evaluate_release_readiness(Path("."))

        self.assertEqual(report.package_version, "0.35.0")
        self.assertEqual(report.completed_gates, 7)
        self.assertEqual(report.total_gates, 9)
        self.assertEqual(report.automatic_completed_gates, 7)
        self.assertEqual(report.automatic_total_gates, 7)
        self.assertTrue(report.automatic_ready)
        self.assertAlmostEqual(report.completion_percent, 77.777778, places=6)
        self.assertFalse(report.ready_for_1_0)
        self.assertEqual(
            {gate.name for gate in report.gates if not gate.complete},
            {"independent_security_review", "first_attested_binary_release"},
        )
        self.assertTrue(
            all(gate.evidence for gate in report.gates if gate.complete)
        )

    def test_external_gates_reject_unsubstantiated_boolean_flips(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            shutil.copytree(
                ".",
                root,
                ignore=shutil.ignore_patterns(
                    ".git",
                    ".venv",
                    ".mypy_cache",
                    ".ruff_cache",
                    "__pycache__",
                    "build",
                    "dist",
                ),
            )
            gates_path = root / "docs/1.0-external-gates.json"
            payload = json.loads(gates_path.read_text(encoding="utf-8"))
            for gate in payload["gates"].values():
                gate["complete"] = True
            gates_path.write_text(json.dumps(payload), encoding="utf-8")

            report = evaluate_release_readiness(root)

            self.assertEqual(report.completed_gates, 7)
            self.assertFalse(report.ready_for_1_0)

    def test_matching_structured_external_evidence_completes_one_zero(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            shutil.copytree(
                ".",
                root,
                ignore=shutil.ignore_patterns(
                    ".git",
                    ".venv",
                    ".mypy_cache",
                    ".ruff_cache",
                    "__pycache__",
                    "build",
                    "dist",
                ),
            )
            commit = "a" * 40
            payload = {
                "schema_version": 2,
                "gates": {
                    "independent_security_review": {
                        "complete": True,
                        "evidence": "https://example.invalid/security-report",
                        "reviewer": "Independent Reviewer",
                        "reviewed_commit": commit,
                        "completed_at": "2026-07-03",
                    },
                    "first_attested_binary_release": {
                        "complete": True,
                        "evidence": "https://example.invalid/releases/v1.0.0",
                        "source_commit": commit,
                        "checksum_manifest_url": "https://example.invalid/SHA256SUMS",
                        "attestation_url": "https://example.invalid/attestation",
                        "verified_by": "Independent Verifier",
                        "verified_at": "2026-07-03",
                    },
                },
            }
            (root / "docs/1.0-external-gates.json").write_text(
                json.dumps(payload),
                encoding="utf-8",
            )

            report = evaluate_release_readiness(root)

            self.assertEqual(report.completed_gates, 9)
            self.assertTrue(report.ready_for_1_0)


if __name__ == "__main__":
    unittest.main()
