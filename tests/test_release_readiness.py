from __future__ import annotations

import io
import json
import shutil
import subprocess
import tempfile
import unittest
from collections.abc import Iterator
from contextlib import contextmanager, redirect_stdout
from pathlib import Path

from mosaic_archive.cli import main
from mosaic_archive.release_readiness import evaluate_release_readiness


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), "-c", "core.autocrlf=false", *arguments],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout.strip()


@contextmanager
def _release_repository() -> Iterator[Path]:
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
                "htmlcov",
                ".coverage*",
            ),
        )
        project_path = root / "pyproject.toml"
        project_path.write_text(
            project_path.read_text(encoding="utf-8").replace(
                'version = "0.39.0"',
                'version = "1.0.0"',
                1,
            ),
            encoding="utf-8",
        )
        _git(root, "init", "--initial-branch=main")
        _git(root, "config", "user.name", "Mosaic Test")
        _git(root, "config", "user.email", "mosaic@example.invalid")
        _git(root, "add", "--all")
        _git(root, "commit", "-m", "test release candidate")
        yield root


def _complete_tag_evidence(commit: str, tag: str = "v1.0.0") -> dict[str, object]:
    return {
        "schema_version": 3,
        "release_tag": tag,
        "release_commit": commit,
        "gates": {
            "independent_security_review": {
                "complete": True,
                "evidence": "https://example.invalid/security-report",
                "reviewer": "Independent Reviewer",
                "reviewed_commit": commit,
                "review_bundle_sha256": "b" * 64,
                "completed_at": "2026-07-13",
            },
            "first_attested_binary_release": {
                "complete": True,
                "evidence": "https://example.invalid/releases/candidate-v1.0.0",
                "source_commit": commit,
                "checksum_manifest_url": (
                    "https://example.invalid/releases/candidate-v1.0.0/SHA256SUMS"
                ),
                "attestation_url": "https://example.invalid/attestation",
                "candidate_tag": f"candidate-{tag}-{commit[:12]}",
                "verified_by": "Independent Verifier",
                "verified_at": "2026-07-13",
            },
        },
    }


def _annotated_tag(
    root: Path,
    tag: str,
    commit: str,
    evidence: dict[str, object] | str,
) -> None:
    message = root.parent / "release-tag-message.json"
    if isinstance(evidence, str):
        message.write_text(evidence, encoding="utf-8")
    else:
        message.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    _git(root, "tag", "--annotate", tag, "--file", str(message), commit)


class ReleaseReadinessTests(unittest.TestCase):
    def test_current_repository_is_seven_of_nine_gates_complete(self) -> None:
        report = evaluate_release_readiness(Path("."))

        self.assertEqual(report.package_version, "0.39.0")
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

    def test_structured_external_evidence_without_tag_stays_fail_closed(self) -> None:
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

            self.assertEqual(report.completed_gates, 7)
            self.assertFalse(report.ready_for_1_0)
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                return_code = main(
                    [
                        "readiness",
                        "--root",
                        str(root),
                        "--require-ready",
                        "--json",
                    ]
                )
            self.assertEqual(return_code, 2)
            self.assertEqual(stdout.getvalue(), "")

    def test_annotated_stable_tag_binds_evidence_to_checkout(self) -> None:
        with _release_repository() as root:
            commit = _git(root, "rev-parse", "HEAD")
            tag = "v1.0.0"
            _annotated_tag(root, tag, commit, _complete_tag_evidence(commit, tag))

            report = evaluate_release_readiness(
                root,
                release_tag=tag,
                release_commit=commit,
            )

            self.assertEqual(report.completed_gates, 9)
            self.assertTrue(report.release_binding_verified)
            self.assertTrue(report.ready_for_1_0)
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                return_code = main(
                    [
                        "readiness",
                        "--root",
                        str(root),
                        "--release-tag",
                        tag,
                        "--release-commit",
                        commit,
                        "--require-ready",
                        "--json",
                    ]
                )
            self.assertEqual(return_code, 0)
            self.assertTrue(json.loads(stdout.getvalue())["release_binding_verified"])

    def test_lightweight_tag_cannot_bind_external_evidence(self) -> None:
        with _release_repository() as root:
            commit = _git(root, "rev-parse", "HEAD")
            _git(root, "tag", "v1.0.0", commit)

            report = evaluate_release_readiness(
                root,
                release_tag="v1.0.0",
                release_commit=commit,
            )

            self.assertEqual(report.completed_gates, 7)
            self.assertFalse(report.release_binding_verified)
            self.assertFalse(report.ready_for_1_0)

    def test_tag_evidence_commit_must_match_tag_target(self) -> None:
        with _release_repository() as root:
            commit = _git(root, "rev-parse", "HEAD")
            fake_commit = "a" * 40
            _annotated_tag(
                root,
                "v1.0.0",
                commit,
                _complete_tag_evidence(fake_commit),
            )

            report = evaluate_release_readiness(
                root,
                release_tag="v1.0.0",
                release_commit=commit,
            )

            self.assertEqual(report.completed_gates, 7)
            self.assertFalse(report.release_binding_verified)
            self.assertFalse(report.ready_for_1_0)

    def test_tag_evidence_requires_bundle_digest_and_candidate_identity(self) -> None:
        mutations = (
            lambda evidence: evidence["gates"]["independent_security_review"].pop(
                "review_bundle_sha256"
            ),
            lambda evidence: evidence["gates"]["first_attested_binary_release"].update(
                {"candidate_tag": "candidate-v1.0.0-wrongcommit"}
            ),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate), _release_repository() as root:
                commit = _git(root, "rev-parse", "HEAD")
                evidence = _complete_tag_evidence(commit)
                mutate(evidence)
                _annotated_tag(root, "v1.0.0", commit, evidence)

                report = evaluate_release_readiness(
                    root,
                    release_tag="v1.0.0",
                    release_commit=commit,
                )

                self.assertEqual(report.completed_gates, 7)
                self.assertFalse(report.ready_for_1_0)

    def test_release_tag_must_match_project_version(self) -> None:
        with _release_repository() as root:
            commit = _git(root, "rev-parse", "HEAD")
            tag = "v1.0.1"
            _annotated_tag(root, tag, commit, _complete_tag_evidence(commit, tag))

            report = evaluate_release_readiness(
                root,
                release_tag=tag,
                release_commit=commit,
            )

            self.assertEqual(report.completed_gates, 7)
            self.assertFalse(report.release_binding_verified)

    def test_release_tag_target_must_be_checked_out(self) -> None:
        with _release_repository() as root:
            candidate = _git(root, "rev-parse", "HEAD")
            _annotated_tag(
                root,
                "v1.0.0",
                candidate,
                _complete_tag_evidence(candidate),
            )
            (root / "post-candidate.txt").write_text("different source\n", encoding="utf-8")
            _git(root, "add", "post-candidate.txt")
            _git(root, "commit", "-m", "move checkout past candidate")

            report = evaluate_release_readiness(
                root,
                release_tag="v1.0.0",
                release_commit=candidate,
            )

            self.assertEqual(report.completed_gates, 7)
            self.assertFalse(report.release_binding_verified)

    def test_malformed_or_oversized_tag_evidence_is_rejected(self) -> None:
        for tag, evidence in (
            ("v1.0.0", "not json"),
            ("v1.0.0", json.dumps({"padding": "x" * 65536})),
        ):
            with self.subTest(evidence_size=len(evidence)), _release_repository() as root:
                commit = _git(root, "rev-parse", "HEAD")
                _annotated_tag(root, tag, commit, evidence)

                report = evaluate_release_readiness(
                    root,
                    release_tag=tag,
                    release_commit=commit,
                )

                self.assertEqual(report.completed_gates, 7)
                self.assertFalse(report.release_binding_verified)


if __name__ == "__main__":
    unittest.main()
