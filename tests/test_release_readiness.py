from __future__ import annotations

import unittest
from pathlib import Path

from mosaic_archive.release_readiness import evaluate_release_readiness


class ReleaseReadinessTests(unittest.TestCase):
    def test_current_repository_is_seven_of_nine_gates_complete(self) -> None:
        report = evaluate_release_readiness(Path("."))

        self.assertEqual(report.package_version, "0.33.0")
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


if __name__ == "__main__":
    unittest.main()
