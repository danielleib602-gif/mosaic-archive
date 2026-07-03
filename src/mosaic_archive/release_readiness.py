"""Machine-readable MSC 1.0 roadmap gate evaluation."""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit


@dataclass(frozen=True, slots=True)
class ReadinessGate:
    name: str
    complete: bool
    evidence: str
    external: bool = False


@dataclass(frozen=True, slots=True)
class ReleaseReadiness:
    package_version: str
    completed_gates: int
    total_gates: int
    completion_percent: float
    ready_for_1_0: bool
    automatic_completed_gates: int
    automatic_total_gates: int
    automatic_ready: bool
    gates: tuple[ReadinessGate, ...]


def _contains(path: Path, *markers: str) -> bool:
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return False
    return all(marker in content for marker in markers)


def _fixture_versions(root: Path) -> set[int]:
    try:
        manifest = json.loads(
            (root / "tests/fixtures/compat/manifest.json").read_text(encoding="utf-8")
        )
        return {int(item["format_version"]) for item in manifest["fixtures"]}
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return set()


def _external_gate_state(root: Path) -> dict[str, dict[str, object]]:
    try:
        payload = json.loads(
            (root / "docs/1.0-external-gates.json").read_text(encoding="utf-8")
        )
        if payload.get("schema_version") != 2:
            return {}
        return {
            str(name): value
            for name, value in payload["gates"].items()
            if isinstance(value, dict)
        }
    except (AttributeError, OSError, KeyError, TypeError, json.JSONDecodeError):
        return {}


def _is_https_url(value: object) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urlsplit(value)
    return parsed.scheme == "https" and bool(parsed.netloc)


def _is_commit(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def _is_nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_date(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


def _security_review_complete(state: dict[str, object]) -> bool:
    return (
        state.get("complete") is True
        and _is_https_url(state.get("evidence"))
        and _is_nonempty_string(state.get("reviewer"))
        and _is_commit(state.get("reviewed_commit"))
        and _is_date(state.get("completed_at"))
    )


def _attested_release_complete(
    state: dict[str, object],
    reviewed_commit: object,
) -> bool:
    return (
        state.get("complete") is True
        and _is_https_url(state.get("evidence"))
        and _is_commit(state.get("source_commit"))
        and state.get("source_commit") == reviewed_commit
        and _is_https_url(state.get("checksum_manifest_url"))
        and _is_https_url(state.get("attestation_url"))
        and _is_nonempty_string(state.get("verified_by"))
        and _is_date(state.get("verified_at"))
    )


def evaluate_release_readiness(root: Path) -> ReleaseReadiness:
    """Evaluate the nine committed MSC 1.0 roadmap gates under ``root``."""
    root = root.resolve()
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    package_version = str(project["project"]["version"])
    external = _external_gate_state(root)

    automatic_gates = (
        ReadinessGate(
            "frozen_format_and_compatibility_policy",
            _contains(
                root / "docs/COMPATIBILITY.md",
                "MSC6 writer format is frozen",
                "MSC1 through MSC6",
            ),
            "docs/COMPATIBILITY.md",
        ),
        ReadinessGate(
            "deterministic_mutation_and_soak_testing",
            _contains(
                root / ".github/workflows/reliability.yml",
                "--cases 10000",
                "--size-mib 256",
            ),
            ".github/workflows/reliability.yml",
        ),
        ReadinessGate(
            "coverage_guided_fuzzing",
            _contains(
                root / ".github/workflows/coverage-fuzz.yml",
                "atheris",
                "fuzz-corpus",
            ),
            ".github/workflows/coverage-fuzz.yml",
        ),
        ReadinessGate(
            "reproducible_public_benchmark",
            _contains(
                root / ".github/workflows/benchmark.yml",
                "mosaic_archive.corpus",
                "--repeats 5",
                "--format solid",
            ),
            ".github/workflows/benchmark.yml",
        ),
        ReadinessGate(
            "permanent_decoder_fixtures",
            _fixture_versions(root) == set(range(1, 7)),
            "tests/fixtures/compat/manifest.json",
        ),
        ReadinessGate(
            "versioned_mature_compressor_results",
            (root / "benchmarks/v0.12.0/report.json").is_file()
            and (root / ".ecc/benchmarks/msc-v0.32-gear-cdc.json").is_file(),
            "benchmarks/v0.12.0/report.json; .ecc/benchmarks/msc-v0.32-gear-cdc.json",
        ),
        ReadinessGate(
            "upgrade_and_deprecation_policy",
            _contains(
                root / "docs/COMPATIBILITY.md",
                "two minor package releases",
                "requires the next major package version",
            ),
            "docs/COMPATIBILITY.md",
        ),
    )

    review_state = external.get("independent_security_review", {})
    release_state = external.get("first_attested_binary_release", {})
    external_gates = (
        ReadinessGate(
            "independent_security_review",
            _security_review_complete(review_state),
            str(review_state.get("evidence", "external evidence required")),
            True,
        ),
        ReadinessGate(
            "first_attested_binary_release",
            _attested_release_complete(
                release_state,
                review_state.get("reviewed_commit"),
            ),
            str(release_state.get("evidence", "external evidence required")),
            True,
        ),
    )
    gates = automatic_gates[:3] + external_gates[:1] + automatic_gates[3:] + external_gates[1:]
    completed = sum(gate.complete for gate in gates)
    total = len(gates)
    repository_gates = tuple(gate for gate in gates if not gate.external)
    automatic_completed = sum(gate.complete for gate in repository_gates)
    automatic_total = len(repository_gates)
    return ReleaseReadiness(
        package_version,
        completed,
        total,
        (completed / total) * 100,
        completed == total,
        automatic_completed,
        automatic_total,
        automatic_completed == automatic_total,
        gates,
    )
