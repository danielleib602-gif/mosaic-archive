"""Machine-readable MSC 1.0 roadmap gate evaluation."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
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
    release_binding_verified: bool
    release_tag: str | None
    release_commit: str | None
    candidate_tag_verified: bool
    review_bundle_verified: bool | None
    gates: tuple[ReadinessGate, ...]


_MAX_TAG_EVIDENCE_BYTES = 64 * 1024
_STABLE_TAG_PATTERN = re.compile(
    r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
)


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
        if payload.get("schema_version") not in {2, 3}:
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


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _file_sha256(path: Path) -> str | None:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            while block := source.read(1024 * 1024):
                digest.update(block)
    except OSError:
        return None
    return digest.hexdigest()


def _git_bytes(root: Path, *arguments: str) -> bytes | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout


def _git_text(root: Path, *arguments: str) -> str | None:
    output = _git_bytes(root, *arguments)
    if output is None:
        return None
    try:
        return output.decode("utf-8").strip()
    except UnicodeDecodeError:
        return None


def _tag_external_gate_state(
    root: Path,
    package_version: str,
    release_tag: str,
    release_commit: str | None,
) -> tuple[dict[str, dict[str, object]], bool, str | None, bool]:
    expected_tag = f"v{package_version}"
    if (
        _STABLE_TAG_PATTERN.fullmatch(release_tag) is None
        or release_tag != expected_tag
    ):
        return {}, False, None, False

    tag_ref = f"refs/tags/{release_tag}"
    if _git_text(root, "cat-file", "-t", tag_ref) != "tag":
        return {}, False, None, False
    tag_target = _git_text(root, "rev-parse", "--verify", f"{tag_ref}^{{commit}}")
    checkout_commit = _git_text(root, "rev-parse", "--verify", "HEAD^{commit}")
    supplied_commit = release_commit if release_commit is not None else checkout_commit
    if not all(_is_commit(value) for value in (tag_target, checkout_commit, supplied_commit)):
        return {}, False, tag_target, False
    if tag_target != checkout_commit or tag_target != supplied_commit:
        return {}, False, tag_target, False
    assert isinstance(tag_target, str)

    raw_tag = _git_bytes(root, "cat-file", "tag", tag_ref)
    if raw_tag is None:
        return {}, False, tag_target, False
    _, separator, message = raw_tag.partition(b"\n\n")
    if not separator or len(message) > _MAX_TAG_EVIDENCE_BYTES:
        return {}, False, tag_target, False
    try:
        payload = json.loads(message.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}, False, tag_target, False
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "release_tag",
        "release_commit",
        "gates",
    }:
        return {}, False, tag_target, False
    if (
        payload.get("schema_version") != 3
        or payload.get("release_tag") != release_tag
        or payload.get("release_commit") != tag_target
    ):
        return {}, False, tag_target, False
    gates = payload.get("gates")
    if not isinstance(gates, dict) or set(gates) != {
        "independent_security_review",
        "first_attested_binary_release",
    }:
        return {}, False, tag_target, False
    external = {
        str(name): value
        for name, value in gates.items()
        if isinstance(value, dict)
    }
    if len(external) != len(gates):
        return {}, False, tag_target, False
    candidate_tag = external["first_attested_binary_release"].get("candidate_tag")
    expected_candidate_tag = f"candidate-v{package_version}-{tag_target[:12]}"
    candidate_target = (
        _git_text(
            root,
            "rev-parse",
            "--verify",
            f"refs/tags/{expected_candidate_tag}^{{commit}}",
        )
        if candidate_tag == expected_candidate_tag
        else None
    )
    return external, True, tag_target, candidate_target == tag_target


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


def _security_review_complete(
    state: dict[str, object],
    release_commit: str | None,
    review_bundle_verified: bool | None,
) -> bool:
    return (
        release_commit is not None
        and state.get("complete") is True
        and _is_https_url(state.get("evidence"))
        and _is_nonempty_string(state.get("reviewer"))
        and _is_commit(state.get("reviewed_commit"))
        and state.get("reviewed_commit") == release_commit
        and _is_sha256(state.get("review_bundle_sha256"))
        and review_bundle_verified is True
        and _is_date(state.get("completed_at"))
    )


def _attested_release_complete(
    state: dict[str, object],
    reviewed_commit: object,
    release_commit: str | None,
    expected_candidate_tag: str | None,
    candidate_tag_verified: bool,
) -> bool:
    return (
        release_commit is not None
        and state.get("complete") is True
        and _is_https_url(state.get("evidence"))
        and _is_commit(state.get("source_commit"))
        and state.get("source_commit") == reviewed_commit
        and state.get("source_commit") == release_commit
        and _is_https_url(state.get("checksum_manifest_url"))
        and _is_https_url(state.get("attestation_url"))
        and expected_candidate_tag is not None
        and state.get("candidate_tag") == expected_candidate_tag
        and candidate_tag_verified
        and _is_nonempty_string(state.get("verified_by"))
        and _is_date(state.get("verified_at"))
    )


def evaluate_release_readiness(
    root: Path,
    *,
    release_tag: str | None = None,
    release_commit: str | None = None,
    review_bundle: Path | None = None,
) -> ReleaseReadiness:
    """Evaluate the nine committed MSC 1.0 roadmap gates under ``root``."""
    root = root.resolve()
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    package_version = str(project["project"]["version"])
    external = _external_gate_state(root)
    release_binding_verified = False
    bound_commit: str | None = None
    candidate_tag_verified = False
    if release_tag is not None:
        (
            external,
            release_binding_verified,
            bound_commit,
            candidate_tag_verified,
        ) = _tag_external_gate_state(
            root,
            package_version,
            release_tag,
            release_commit,
        )

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
    review_bundle_verified: bool | None = None
    if review_bundle is not None:
        bundle_path = review_bundle if review_bundle.is_absolute() else root / review_bundle
        expected_digest = review_state.get("review_bundle_sha256")
        review_bundle_verified = _is_sha256(expected_digest) and _file_sha256(
            bundle_path
        ) == expected_digest
    expected_candidate_tag = (
        f"candidate-v{package_version}-{bound_commit[:12]}"
        if bound_commit is not None
        else None
    )
    external_gates = (
        ReadinessGate(
            "independent_security_review",
            _security_review_complete(
                review_state,
                bound_commit,
                review_bundle_verified,
            ),
            str(review_state.get("evidence", "external evidence required")),
            True,
        ),
        ReadinessGate(
            "first_attested_binary_release",
            _attested_release_complete(
                release_state,
                review_state.get("reviewed_commit"),
                bound_commit,
                expected_candidate_tag,
                candidate_tag_verified,
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
        package_version=package_version,
        completed_gates=completed,
        total_gates=total,
        completion_percent=(completed / total) * 100,
        ready_for_1_0=completed == total and release_binding_verified,
        automatic_completed_gates=automatic_completed,
        automatic_total_gates=automatic_total,
        automatic_ready=automatic_completed == automatic_total,
        release_binding_verified=release_binding_verified,
        release_tag=release_tag,
        release_commit=bound_commit,
        candidate_tag_verified=candidate_tag_verified,
        review_bundle_verified=review_bundle_verified,
        gates=gates,
    )
