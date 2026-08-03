"""Strict whole-report boundary for Competitive Contract v1.

``report-v1`` is a recomputed competitive-development report.  It is deliberately
not release schema-v4 evidence and cannot satisfy a release-readiness gate.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Literal, cast
from urllib.parse import urlsplit

from .competitive_contract import (
    BINDING_ENCRYPTED_TOOLS,
    BINDING_RAW_TOOLS,
    BINDING_TOOLS,
    COMPETITIVE_CONTRACT_V1,
    CONTRACT_SHA256,
    MEASURED_RUNS,
    METRICS,
    CaseIdentity,
    ScorecardCase,
    evaluate_scorecard_case,
)
from .competitive_corpus import REQUIRED_CORPUS_IDS
from .competitive_report_io import (
    MAX_JSON_NESTING as MAX_JSON_NESTING,
)
from .competitive_report_io import (
    MAX_REPORT_JSON_BYTES as MAX_REPORT_JSON_BYTES,
)
from .competitive_report_io import (
    READ_CHUNK_BYTES as READ_CHUNK_BYTES,
)
from .competitive_report_io import (
    ReportValidationError as ReportValidationError,
)
from .competitive_report_io import (
    load_competitive_report_payload,
)

SCHEMA_NAME: Final = "report-v1"
DEVELOPMENT_EVIDENCE_CLASS: Final[Literal["development-unverified"]] = "development-unverified"
EXPECTED_CASE_COUNT: Final = len(REQUIRED_CORPUS_IDS) * 2 * len(METRICS)
EXPECTED_EVIDENCE_COUNT: Final = EXPECTED_CASE_COUNT * (1 + len(BINDING_TOOLS)) * MEASURED_RUNS
MAX_URL_BYTES: Final = 2_048
MAX_WORKFLOW_IDENTITY_BYTES: Final = 512
MAX_CANDIDATE_TAG_BYTES: Final = 128

_THREAD_TIERS: Final = (1, 8)
_TOOLS_WITH_CANDIDATE: Final = ("candidate", *BINDING_TOOLS)
_SHA256_RE: Final = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_RE: Final = re.compile(r"[0-9a-f]{40}\Z")
_DNS_LABEL_RE: Final = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_IPV4_LIKE_RE: Final = re.compile(r"[0-9.]+\Z")
_URL_PATH_SEGMENT_RE: Final = re.compile(r"[A-Za-z0-9._~-]+\Z")
_CANDIDATE_TAG_RE: Final = re.compile(
    r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?\Z"
)
_WORKFLOW_IDENTITY_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,511}\Z")

_REPORT_KEYS: Final = frozenset(
    {
        "schema_name",
        "contract_sha256",
        "corpus_manifest_sha256",
        "candidate",
        "runner",
        "cases",
        "raw_evidence_index",
    }
)
_CANDIDATE_KEYS: Final = frozenset(
    {
        "archive_format",
        "profile",
        "configuration_id",
        "native_binary_sha256",
        "commit_sha",
        "candidate_tag",
    }
)
_RUNNER_KEYS: Final = frozenset(
    {
        "evidence_class",
        "runner_policy_sha256",
        "hardware_fingerprint_sha256",
        "workflow_identity",
    }
)
_EVIDENCE_KEYS: Final = frozenset({"sha256", "url"})
_SCORECARD_CASE_KEYS: Final = frozenset(
    {
        "case_id",
        "contract_sha256",
        "corpus_manifest_sha256",
        "corpus_id",
        "input_sha256",
        "thread_count",
        "metric",
        "input_bytes",
        "candidate_archive_bytes",
        "candidate_samples",
        "comparator_samples",
        "raw_comparator_archive_bytes",
        "encrypted_comparator_archive_bytes",
    }
)


@dataclass(frozen=True, slots=True)
class CandidateIdentity:
    """Declared candidate identity represented by one development report.

    Digest and version fields are structurally validated declarations.  This
    offline report boundary does not resolve them against a trusted provenance
    service.
    """

    archive_format: str
    profile: str
    configuration_id: str
    native_binary_sha256: str
    commit_sha: str
    candidate_tag: str


@dataclass(frozen=True, slots=True)
class RunnerIdentity:
    """Declared, explicitly unverified development-run provenance metadata.

    The policy, hardware, and workflow strings are syntax-checked but are not
    authenticated identities and confer no binding authority.
    """

    evidence_class: Literal["development-unverified"]
    runner_policy_sha256: str
    hardware_fingerprint_sha256: str
    workflow_identity: str


@dataclass(frozen=True, slots=True)
class RawEvidenceReference:
    """Syntax-checked content-address declaration for one submitted sample.

    ``url`` is not fetched and ``sha256`` is not compared with remote content by
    report-v1.  Instances are references only, never verified evidence records.
    """

    sample_id: str
    sha256: str
    url: str


@dataclass(frozen=True, slots=True)
class CompetitiveReport:
    """Structurally validated, arithmetically recomputed report-v1 result.

    ``scorecard_passed`` means only that the submitted numeric arrays pass the
    Competitive Contract v1 arithmetic.  The offline boundary does not fetch raw
    references or authenticate declared provenance.  Consequently all authority
    and verification flags are immutable false values, cannot be supplied in
    input JSON, and this type cannot satisfy a binding or release-readiness gate.
    """

    schema_name: str
    contract_sha256: str
    corpus_manifest_sha256: str
    candidate: CandidateIdentity
    runner: RunnerIdentity
    cases: tuple[ScorecardCase, ...]
    raw_evidence_index: tuple[RawEvidenceReference, ...]
    scorecard_passed: bool = field(init=False)
    raw_evidence_verified: Literal[False] = field(default=False, init=False)
    binding_eligible: Literal[False] = field(default=False, init=False)
    release_readiness_eligible: Literal[False] = field(default=False, init=False)

    def __post_init__(self) -> None:
        """Compute the arithmetic-only summary from immutable evaluated cases."""
        object.__setattr__(
            self,
            "scorecard_passed",
            len(self.cases) == EXPECTED_CASE_COUNT and all(case.passed for case in self.cases),
        )


@dataclass(frozen=True, slots=True)
class _PreflightCase:
    payload: Mapping[str, object]
    identity: CaseIdentity
    size_fingerprint: tuple[object, ...]


def _utf8_length(value: str, context: str) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise ReportValidationError(
            f"{context} must contain valid Unicode scalar values"
        ) from error


def _require_object(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ReportValidationError(f"{context} must be an object")
    if any(type(key) is not str for key in value):
        raise ReportValidationError(f"{context} keys must be strings")
    return cast(Mapping[str, object], value)


def _require_exact_keys(
    value: Mapping[str, object],
    expected: frozenset[str],
    context: str,
) -> None:
    actual = frozenset(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        raise ReportValidationError(
            f"{context} keys must be exact; missing={missing}, unexpected={unexpected}"
        )


def _require_literal(value: object, expected: str, context: str) -> str:
    if type(value) is not str or value != expected:
        raise ReportValidationError(f"{context} must equal {expected!r}")
    return value


def _require_sha256(value: object, context: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ReportValidationError(f"{context} must be a lowercase SHA-256 digest")
    return value


def _require_positive_integer(value: object, context: str) -> int:
    if type(value) is not int or value <= 0:
        raise ReportValidationError(f"{context} must be a positive integer")
    return value


def _require_sequence(value: object, context: str, length: int) -> Sequence[object]:
    if (
        isinstance(value, str | bytes | bytearray)
        or not isinstance(value, Sequence)
        or len(value) != length
    ):
        raise ReportValidationError(f"{context} must contain exactly {length} items")
    return cast(Sequence[object], value)


def _parse_candidate(value: object) -> CandidateIdentity:
    candidate = _require_object(value, "candidate")
    _require_exact_keys(candidate, _CANDIDATE_KEYS, "candidate")
    archive_format = _require_literal(
        candidate["archive_format"],
        COMPETITIVE_CONTRACT_V1.candidate.archive_format,
        "candidate.archive_format",
    )
    profile = _require_literal(
        candidate["profile"],
        COMPETITIVE_CONTRACT_V1.candidate.profile,
        "candidate.profile",
    )
    configuration_id = _require_literal(
        candidate["configuration_id"],
        COMPETITIVE_CONTRACT_V1.candidate.configuration_id,
        "candidate.configuration_id",
    )
    native_binary_sha256 = _require_sha256(
        candidate["native_binary_sha256"],
        "candidate.native_binary_sha256",
    )
    commit_sha = candidate["commit_sha"]
    if type(commit_sha) is not str or _COMMIT_RE.fullmatch(commit_sha) is None:
        raise ReportValidationError("candidate.commit_sha must be a lowercase 40-character SHA")
    candidate_tag = candidate["candidate_tag"]
    if (
        type(candidate_tag) is not str
        or _utf8_length(candidate_tag, "candidate.candidate_tag") > MAX_CANDIDATE_TAG_BYTES
        or _CANDIDATE_TAG_RE.fullmatch(candidate_tag) is None
    ):
        raise ReportValidationError("candidate.candidate_tag must be a canonical version tag")
    return CandidateIdentity(
        archive_format=archive_format,
        profile=profile,
        configuration_id=configuration_id,
        native_binary_sha256=native_binary_sha256,
        commit_sha=commit_sha,
        candidate_tag=candidate_tag,
    )


def _parse_runner(value: object) -> RunnerIdentity:
    runner = _require_object(value, "runner")
    _require_exact_keys(runner, _RUNNER_KEYS, "runner")
    _require_literal(
        runner["evidence_class"],
        DEVELOPMENT_EVIDENCE_CLASS,
        "runner.evidence_class",
    )
    runner_policy_sha256 = _require_sha256(
        runner["runner_policy_sha256"],
        "runner.runner_policy_sha256",
    )
    hardware_fingerprint_sha256 = _require_sha256(
        runner["hardware_fingerprint_sha256"],
        "runner.hardware_fingerprint_sha256",
    )
    workflow_identity = runner["workflow_identity"]
    if (
        type(workflow_identity) is not str
        or _utf8_length(workflow_identity, "runner.workflow_identity") > MAX_WORKFLOW_IDENTITY_BYTES
        or _WORKFLOW_IDENTITY_RE.fullmatch(workflow_identity) is None
    ):
        raise ReportValidationError(
            "runner.workflow_identity must be a canonical bounded workflow identity"
        )
    return RunnerIdentity(
        evidence_class=DEVELOPMENT_EVIDENCE_CLASS,
        runner_policy_sha256=runner_policy_sha256,
        hardware_fingerprint_sha256=hardware_fingerprint_sha256,
        workflow_identity=workflow_identity,
    )


def _require_exact_size_mapping(
    value: object,
    expected_ids: tuple[str, ...],
    context: str,
) -> tuple[tuple[str, int], ...]:
    sizes = _require_object(value, context)
    expected = frozenset(expected_ids)
    _require_exact_keys(sizes, expected, context)
    return tuple(
        (
            comparator_id,
            _require_positive_integer(
                sizes[comparator_id],
                f"{context}.{comparator_id}",
            ),
        )
        for comparator_id in expected_ids
    )


def _require_encrypted_sizes(value: object) -> tuple[tuple[str, tuple[int, ...]], ...]:
    context = "encrypted_comparator_archive_bytes"
    sizes = _require_object(value, context)
    _require_exact_keys(sizes, frozenset(BINDING_ENCRYPTED_TOOLS), context)
    result: list[tuple[str, tuple[int, ...]]] = []
    for comparator_id in BINDING_ENCRYPTED_TOOLS:
        samples = _require_sequence(
            sizes[comparator_id],
            f"{context}.{comparator_id}",
            MEASURED_RUNS,
        )
        result.append(
            (
                comparator_id,
                tuple(
                    _require_positive_integer(sample, f"{context}.{comparator_id}")
                    for sample in samples
                ),
            )
        )
    return tuple(result)


def _preflight_case(
    value: object,
    *,
    index: int,
    contract_sha256: str,
    corpus_manifest_sha256: str,
) -> _PreflightCase:
    context = f"cases[{index}]"
    case = _require_object(value, context)
    _require_exact_keys(case, _SCORECARD_CASE_KEYS, context)

    if case["contract_sha256"] != contract_sha256:
        raise ReportValidationError(f"{context}.contract_sha256 is inconsistent with report")
    if case["corpus_manifest_sha256"] != corpus_manifest_sha256:
        raise ReportValidationError(f"{context}.corpus_manifest_sha256 is inconsistent with report")
    corpus_id = case["corpus_id"]
    if type(corpus_id) is not str or corpus_id not in REQUIRED_CORPUS_IDS:
        raise ReportValidationError(f"{context}.corpus_id is not in the exact corpus matrix")
    metric = case["metric"]
    if type(metric) is not str or metric not in METRICS:
        raise ReportValidationError(f"{context}.metric is not in the exact metric matrix")
    thread_count = case["thread_count"]
    if type(thread_count) is not int or thread_count not in _THREAD_TIERS:
        raise ReportValidationError(f"{context}.thread_count is not in the exact thread matrix")

    try:
        identity = CaseIdentity(
            contract_sha256=case["contract_sha256"],
            corpus_manifest_sha256=case["corpus_manifest_sha256"],
            corpus_id=corpus_id,
            input_sha256=cast(str, case["input_sha256"]),
            input_bytes=cast(int, case["input_bytes"]),
            thread_count=thread_count,
            metric=metric,
        )
    except (TypeError, ValueError) as error:
        raise ReportValidationError(f"{context}: {error}") from error
    if type(case["case_id"]) is not str or case["case_id"] != identity.case_id:
        raise ReportValidationError(f"{context}.case_id does not match its bound identity")

    input_bytes = _require_positive_integer(case["input_bytes"], f"{context}.input_bytes")
    candidate_archive_bytes = _require_positive_integer(
        case["candidate_archive_bytes"],
        f"{context}.candidate_archive_bytes",
    )
    raw_sizes = _require_exact_size_mapping(
        case["raw_comparator_archive_bytes"],
        BINDING_RAW_TOOLS,
        f"{context}.raw_comparator_archive_bytes",
    )
    encrypted_sizes = _require_encrypted_sizes(case["encrypted_comparator_archive_bytes"])
    return _PreflightCase(
        payload=case,
        identity=identity,
        size_fingerprint=(
            identity.input_sha256,
            input_bytes,
            candidate_archive_bytes,
            raw_sizes,
            encrypted_sizes,
        ),
    )


def _preflight_cases(
    value: object,
    *,
    contract_sha256: str,
    corpus_manifest_sha256: str,
) -> tuple[_PreflightCase, ...]:
    cases = _require_sequence(value, "cases", EXPECTED_CASE_COUNT)
    preflight = tuple(
        _preflight_case(
            case,
            index=index,
            contract_sha256=contract_sha256,
            corpus_manifest_sha256=corpus_manifest_sha256,
        )
        for index, case in enumerate(cases)
    )
    by_coordinate: dict[tuple[str, int, str], _PreflightCase] = {}
    size_by_tier: dict[tuple[str, int], tuple[object, ...]] = {}
    input_by_corpus: dict[str, tuple[object, ...]] = {}
    for case in preflight:
        coordinate = (
            case.identity.corpus_id,
            case.identity.thread_count,
            case.identity.metric,
        )
        if coordinate in by_coordinate:
            raise ReportValidationError(f"duplicate report case coordinate: {coordinate!r}")
        by_coordinate[coordinate] = case
        tier = (case.identity.corpus_id, case.identity.thread_count)
        previous = size_by_tier.setdefault(tier, case.size_fingerprint)
        if previous != case.size_fingerprint:
            raise ReportValidationError(
                f"inconsistent input identity or size records for corpus/thread {tier!r}"
            )
        corpus_input = case.size_fingerprint[:2]
        previous_input = input_by_corpus.setdefault(case.identity.corpus_id, corpus_input)
        if previous_input != corpus_input:
            raise ReportValidationError(
                f"inconsistent prepared input identity across corpus thread tiers: "
                f"{case.identity.corpus_id!r}"
            )

    expected = {
        (corpus_id, thread_count, metric)
        for corpus_id in REQUIRED_CORPUS_IDS
        for thread_count in _THREAD_TIERS
        for metric in METRICS
    }
    if set(by_coordinate) != expected:
        raise ReportValidationError("cases do not form the exact required report matrix")
    return tuple(
        by_coordinate[(corpus_id, thread_count, metric)]
        for corpus_id in REQUIRED_CORPUS_IDS
        for thread_count in _THREAD_TIERS
        for metric in METRICS
    )


def _sample_id(case_id: str, tool_id: str, run_index: int) -> str:
    return f"{case_id}/{tool_id}/{run_index:02d}"


def _canonical_url_authority(hostname: str, context: str) -> str:
    """Return the canonical authority spelling for one DNS or IP host."""
    try:
        hostname.encode("ascii")
    except UnicodeEncodeError as error:
        raise ReportValidationError(f"{context} host must use canonical ASCII syntax") from error

    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        if (
            not hostname
            or len(hostname) > 253
            or hostname.endswith(".")
            or _IPV4_LIKE_RE.fullmatch(hostname) is not None
        ):
            raise ReportValidationError(
                f"{context} host must be a canonical DNS name or IP address"
            ) from None
        labels = hostname.split(".")
        if any(_DNS_LABEL_RE.fullmatch(label) is None for label in labels):
            raise ReportValidationError(
                f"{context} host must be a canonical DNS name or IP address"
            ) from None
        return hostname

    if isinstance(address, ipaddress.IPv6Address):
        return f"[{address.compressed}]"
    return str(address)


def _validate_evidence_url(value: object, digest: str, context: str) -> str:
    """Validate URL syntax and content-address naming without loading the URL."""
    if (
        type(value) is not str
        or not value
        or _utf8_length(value, context) > MAX_URL_BYTES
        or value != value.strip()
        or "%" in value
        or "\\" in value
        or any(
            character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F
            for character in value
        )
    ):
        raise ReportValidationError(f"{context} must be a bounded canonical HTTPS URL")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ReportValidationError(f"{context} must be a valid HTTPS URL") from error
    hostname = parsed.hostname
    if (
        parsed.scheme != "https"
        or not value.startswith("https://")
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ReportValidationError(
            f"{context} must be an unauthenticated content-addressed HTTPS URL"
        )

    canonical_authority = _canonical_url_authority(hostname, context)
    path_segments = parsed.path.split("/")
    if (
        parsed.netloc != canonical_authority
        or not parsed.path.startswith("/")
        or len(path_segments) < 2
        or any(
            not segment or segment in {".", ".."} or _URL_PATH_SEGMENT_RE.fullmatch(segment) is None
            for segment in path_segments[1:]
        )
        or path_segments[-1] not in {digest, f"{digest}.json"}
    ):
        raise ReportValidationError(f"{context} must be a canonical content-addressed HTTPS URL")
    return value


def _parse_raw_evidence_index(
    value: object,
    cases: tuple[_PreflightCase, ...],
) -> tuple[RawEvidenceReference, ...]:
    """Parse exhaustive raw-reference declarations without resolving any URL."""
    evidence = _require_object(value, "raw_evidence_index")
    expected_ids = {
        _sample_id(case.identity.case_id, tool_id, run_index)
        for case in cases
        for tool_id in _TOOLS_WITH_CANDIDATE
        for run_index in range(MEASURED_RUNS)
    }
    actual_ids = set(evidence)
    if len(evidence) != EXPECTED_EVIDENCE_COUNT or actual_ids != expected_ids:
        missing_count = len(expected_ids - actual_ids)
        unexpected_count = len(actual_ids - expected_ids)
        raise ReportValidationError(
            "raw_evidence_index must map every and only expected run/sample; "
            f"expected={EXPECTED_EVIDENCE_COUNT}, actual={len(evidence)}, "
            f"missing={missing_count}, unexpected={unexpected_count}"
        )

    result: list[RawEvidenceReference] = []
    for sample_id in sorted(expected_ids):
        context = f"raw_evidence_index[{sample_id!r}]"
        entry = _require_object(evidence[sample_id], context)
        _require_exact_keys(entry, _EVIDENCE_KEYS, context)
        digest = _require_sha256(entry["sha256"], f"{context}.sha256")
        url = _validate_evidence_url(entry["url"], digest, f"{context}.url")
        result.append(
            RawEvidenceReference(
                sample_id=sample_id,
                sha256=digest,
                url=url,
            )
        )
    return tuple(result)


def evaluate_competitive_report(report: Mapping[str, object]) -> CompetitiveReport:
    """Validate structure and recompute arithmetic for one development report.

    Raw-reference URLs and declared provenance identities remain unverified.
    Input may not claim summaries, verification, binding authority, or release
    readiness because the exact-key schema excludes all such fields.
    """
    root = _require_object(report, "report")
    _require_exact_keys(root, _REPORT_KEYS, "report")
    schema_name = _require_literal(root["schema_name"], SCHEMA_NAME, "schema_name")
    contract_sha256 = _require_sha256(root["contract_sha256"], "contract_sha256")
    if contract_sha256 != CONTRACT_SHA256:
        raise ReportValidationError(
            "contract_sha256 must bind the exact Competitive Contract v1 bytes"
        )
    corpus_manifest_sha256 = _require_sha256(
        root["corpus_manifest_sha256"],
        "corpus_manifest_sha256",
    )
    candidate = _parse_candidate(root["candidate"])
    runner = _parse_runner(root["runner"])
    preflight_cases = _preflight_cases(
        root["cases"],
        contract_sha256=contract_sha256,
        corpus_manifest_sha256=corpus_manifest_sha256,
    )
    raw_evidence_index = _parse_raw_evidence_index(
        root["raw_evidence_index"],
        preflight_cases,
    )

    evaluated_cases: list[ScorecardCase] = []
    for index, case in enumerate(preflight_cases):
        try:
            evaluated_cases.append(evaluate_scorecard_case(case.payload))
        except (TypeError, ValueError) as error:
            raise ReportValidationError(
                f"cases[{index}] failed raw recomputation: {error}"
            ) from error
    cases = tuple(evaluated_cases)
    return CompetitiveReport(
        schema_name=schema_name,
        contract_sha256=contract_sha256,
        corpus_manifest_sha256=corpus_manifest_sha256,
        candidate=candidate,
        runner=runner,
        cases=cases,
        raw_evidence_index=raw_evidence_index,
    )


def load_competitive_report(
    path: str | Path,
    *,
    max_bytes: int = MAX_REPORT_JSON_BYTES,
) -> CompetitiveReport:
    """Safely load one offline development report and recompute its scorecard.

    The final path must remain a no-follow, single-link regular file throughout
    the descriptor read.  At most ``max_bytes`` are read.  Raw-reference URLs in
    the JSON are syntax/content-address declarations only and are never loaded.
    """
    payload = load_competitive_report_payload(path, max_bytes=max_bytes)
    return evaluate_competitive_report(payload)
