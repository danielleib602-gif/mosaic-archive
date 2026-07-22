"""Strict, deterministic primitives for Competitive Contract v1 evidence."""

from __future__ import annotations

import hashlib
import json
import math
import re
import statistics
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn, cast

SCHEMA_VERSION = 1
CONTRACT_ID = "mosaic-competitive-contract-v1"
CONTRACT_DIGEST_ALGORITHM = "sha256_canonical_json_v1"
CONTRACT_SHA256 = "5f76317e4e03c2b4a5e5c9414e08edd7fd64d53e35afb3681cd6ba93e93b3d6d"
MAX_CONTRACT_JSON_BYTES = 64 * 1024
BOOTSTRAP_RESAMPLES = 10_000
BOOTSTRAP_CONFIDENCE_LEVEL = 0.95
MEASURED_RUNS = 11
MINIMUM_INPUT_BYTES = 67_108_864
MAX_CGROUP_MEMORY_PEAK_BYTES = (1 << 63) - 1
MAX_CORPUS_ID_BYTES = 128
CASE_ID_PREFIX = "msc-case-v1-"
MAX_CASE_ID_BYTES = len(CASE_ID_PREFIX) + 64
_UINT64_RANGE = 1 << 64
_CASE_ID_DOMAIN = "mosaic-competitive-case-id-v1"
_BOOTSTRAP_STREAM_DOMAIN = "mosaic-competitive-bootstrap-stream-v1"

BINDING_TOOLS = (
    "7zip_raw",
    "7zip_aes256_headers",
    "zstd_raw",
    "zstd_age_passphrase",
)
BINDING_RAW_TOOLS = ("7zip_raw", "zstd_raw")
BINDING_ENCRYPTED_TOOLS = (
    "7zip_aes256_headers",
    "zstd_age_passphrase",
)
DIAGNOSTIC_TOOLS = ("gzip", "zip", "xz", "brotli", "lz4")
METRICS = (
    "encode_wall_seconds",
    "decode_wall_seconds",
    "encode_cgroup_v2_memory_peak_bytes",
    "decode_cgroup_v2_memory_peak_bytes",
)
MEMORY_METRICS = (
    "encode_cgroup_v2_memory_peak_bytes",
    "decode_cgroup_v2_memory_peak_bytes",
)
METRIC_SAMPLE_DOMAINS = (
    ("encode_wall_seconds", "positive_finite_number"),
    ("decode_wall_seconds", "positive_finite_number"),
    ("encode_cgroup_v2_memory_peak_bytes", "positive_signed_64_bit_integer"),
    ("decode_cgroup_v2_memory_peak_bytes", "positive_signed_64_bit_integer"),
)
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_CORPUS_ID_PATTERN = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*")


class ContractValidationError(ValueError):
    """Raised when contract JSON does not exactly match the v1 contract."""


@dataclass(frozen=True, slots=True)
class CandidateContract:
    archive_format: str
    profile: str
    configuration_id: str


@dataclass(frozen=True, slots=True)
class CorpusContract:
    minimum_input_bytes: int


@dataclass(frozen=True, slots=True)
class ExecutionContract:
    threads: tuple[int, ...]
    warmup_runs: int
    measured_runs: int
    fresh_process_per_run: bool
    alternating_candidate_comparator_order: bool
    containment: str
    cpu_tier_enforcement: str
    memory_peak_source: str
    swap_peak_scope: str
    page_cache_policy: str
    even_run_order: tuple[str, ...]
    odd_run_order: tuple[str, ...]
    warmup_order: tuple[str, ...]
    run_index_origin: str
    pairing_rule: str


@dataclass(frozen=True, slots=True)
class ComparatorContract:
    binding_tools: tuple[str, ...]
    diagnostic_tools: tuple[str, ...]
    performance_pass_scope: str


@dataclass(frozen=True, slots=True)
class BootstrapContract:
    statistic: str
    resamples: int
    identity_encoding: str
    case_id_derivation: str
    stream_algorithm: str
    counter_encoding: str
    index_sampling: str
    percentile_interpolation: str
    confidence_level: float
    pass_rule: str


@dataclass(frozen=True, slots=True)
class SizeContract:
    compressible_pass_rule: str
    incompressible_if_best_raw_ratio_gt: float
    allowance_minimum_bytes: int
    allowance_divisor: int
    incompressible_pass_rule: str
    deterministic_size_statistic: str
    encrypted_size_statistic: str
    encrypted_distribution_samples: int


@dataclass(frozen=True, slots=True)
class CompetitiveContract:
    schema_version: int
    contract_id: str
    contract_digest_algorithm: str
    candidate: CandidateContract
    corpus: CorpusContract
    execution: ExecutionContract
    comparators: ComparatorContract
    metrics: tuple[str, ...]
    metric_sample_domains: tuple[tuple[str, str], ...]
    bootstrap: BootstrapContract
    size: SizeContract


@dataclass(frozen=True, slots=True)
class ConfidenceInterval:
    lower: float
    upper: float
    confidence_level: float


@dataclass(frozen=True, slots=True)
class CaseIdentity:
    """Immutable inputs that uniquely bind one competitive metric case."""

    contract_sha256: str
    corpus_manifest_sha256: str
    corpus_id: str
    input_sha256: str
    input_bytes: int
    thread_count: int
    metric: str

    def __post_init__(self) -> None:
        _validate_case_identity(self)

    @property
    def case_id(self) -> str:
        """Return the canonical display identifier derived from all fields."""
        return derive_case_id(self)


@dataclass(frozen=True, slots=True)
class MetricVerdict:
    metric: str
    comparator_id: str
    sample_count: int
    candidate_median: float
    comparator_median: float
    candidate_mad: float
    comparator_mad: float
    paired_median_ratio: float
    confidence_interval: ConfidenceInterval
    passed: bool


@dataclass(frozen=True, slots=True)
class SizeVerdict:
    input_bytes: int
    candidate_archive_bytes: int
    best_raw_comparator_id: str
    best_raw_archive_bytes: int
    smallest_encrypted_comparator_id: str
    smallest_encrypted_comparator_archive_bytes: int
    smallest_comparator_id: str
    smallest_comparator_archive_bytes: int
    incompressible: bool
    allowance_bytes: int
    selected_limit_bytes: int
    selected_limit_source: str
    selected_limit_inclusive: bool
    passed: bool


@dataclass(frozen=True, slots=True)
class ScorecardCase:
    case_id: str
    identity: CaseIdentity
    thread_count: int
    fastest_comparator_id: str
    metric_verdicts: tuple[MetricVerdict, ...]
    size_verdict: SizeVerdict
    passed: bool


COMPETITIVE_CONTRACT_V1 = CompetitiveContract(
    schema_version=SCHEMA_VERSION,
    contract_id=CONTRACT_ID,
    contract_digest_algorithm=CONTRACT_DIGEST_ALGORITHM,
    candidate=CandidateContract(
        archive_format="MSC7",
        profile="adaptive-v1",
        configuration_id="msc7-default-v1",
    ),
    corpus=CorpusContract(minimum_input_bytes=MINIMUM_INPUT_BYTES),
    execution=ExecutionContract(
        threads=(1, 8),
        warmup_runs=1,
        measured_runs=MEASURED_RUNS,
        fresh_process_per_run=True,
        alternating_candidate_comparator_order=True,
        containment="pre_exec_fresh_cgroup_v2_and_pid_namespace",
        cpu_tier_enforcement="exact_cpuset_and_tool_threads",
        memory_peak_source="cgroup_v2_memory_peak_after_populated_zero",
        swap_peak_scope="excluded",
        page_cache_policy=(
            "input_prewarmed_outside_measured_cgroup_output_cache_included_v1"
        ),
        even_run_order=("candidate", *BINDING_TOOLS),
        odd_run_order=tuple(reversed(("candidate", *BINDING_TOOLS))),
        warmup_order=("candidate", *BINDING_TOOLS),
        run_index_origin="zero_based",
        pairing_rule="shared_candidate_index_to_each_comparator_same_index",
    ),
    comparators=ComparatorContract(
        binding_tools=BINDING_TOOLS,
        diagnostic_tools=DIAGNOSTIC_TOOLS,
        performance_pass_scope="all_binding_tools",
    ),
    metrics=METRICS,
    metric_sample_domains=METRIC_SAMPLE_DOMAINS,
    bootstrap=BootstrapContract(
        statistic="paired_median_ratio",
        resamples=BOOTSTRAP_RESAMPLES,
        identity_encoding="utf8_u32be_length_prefixed_fields_v1",
        case_id_derivation="sha256_case_identity_v1",
        stream_algorithm="sha256_counter_v1",
        counter_encoding="u64be_start_zero",
        index_sampling="u64be_rejection_modulo",
        percentile_interpolation="type_7",
        confidence_level=BOOTSTRAP_CONFIDENCE_LEVEL,
        pass_rule="every_binding_comparator_upper_bound_lt_1",
    ),
    size=SizeContract(
        compressible_pass_rule="candidate_lt_smallest_comparator",
        incompressible_if_best_raw_ratio_gt=0.99,
        allowance_minimum_bytes=4096,
        allowance_divisor=2000,
        incompressible_pass_rule=("candidate_lte_input_plus_allowance_and_lte_smallest_encrypted"),
        deterministic_size_statistic="archive_bytes",
        encrypted_size_statistic="median",
        encrypted_distribution_samples=MEASURED_RUNS,
    ),
)


_CONTRACT_KEYS = {
    "schema_version",
    "contract_id",
    "contract_digest_algorithm",
    "candidate",
    "corpus",
    "execution",
    "comparators",
    "metrics",
    "metric_sample_domains",
    "bootstrap",
    "size",
}
_SCORECARD_CASE_KEYS = {
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


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ContractValidationError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> NoReturn:
    raise ContractValidationError(f"non-finite JSON constant is forbidden: {value}")


def _require_object(value: object, context: str) -> dict[str, object]:
    if type(value) is not dict:
        raise ContractValidationError(f"{context} must be a JSON object")
    return cast(dict[str, object], value)


def _require_keys(
    value: Mapping[str, object],
    expected: set[str],
    context: str,
    *,
    error_type: type[ValueError] = ContractValidationError,
) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(repr(key) for key in actual - expected)
        raise error_type(
            f"{context} keys must be exact; missing={missing}, unexpected={unexpected}"
        )


def _require_literal(value: object, expected: object, context: str) -> None:
    if type(value) is not type(expected) or value != expected:
        raise ContractValidationError(f"{context} must equal {expected!r}")


def _require_literal_list(
    value: object,
    expected: tuple[object, ...],
    context: str,
) -> None:
    if type(value) is not list or len(value) != len(expected):
        raise ContractValidationError(f"{context} must equal {list(expected)!r}")
    assert isinstance(value, list)
    if any(
        type(actual) is not type(wanted) or actual != wanted
        for actual, wanted in zip(value, expected, strict=True)
    ):
        raise ContractValidationError(f"{context} must equal {list(expected)!r}")


def _validate_contract_payload(payload: object) -> CompetitiveContract:
    root = _require_object(payload, "contract")
    _require_keys(root, _CONTRACT_KEYS, "contract")

    candidate = _require_object(root["candidate"], "candidate")
    corpus = _require_object(root["corpus"], "corpus")
    execution = _require_object(root["execution"], "execution")
    comparators = _require_object(root["comparators"], "comparators")
    metric_sample_domains = _require_object(
        root["metric_sample_domains"],
        "metric_sample_domains",
    )
    bootstrap = _require_object(root["bootstrap"], "bootstrap")
    size = _require_object(root["size"], "size")

    _require_keys(
        candidate,
        {"archive_format", "profile", "configuration_id"},
        "candidate",
    )
    _require_keys(corpus, {"minimum_input_bytes"}, "corpus")
    _require_keys(
        execution,
        {
            "threads",
            "warmup_runs",
            "measured_runs",
            "fresh_process_per_run",
            "alternating_candidate_comparator_order",
            "containment",
            "cpu_tier_enforcement",
            "memory_peak_source",
            "swap_peak_scope",
            "page_cache_policy",
            "even_run_order",
            "odd_run_order",
            "warmup_order",
            "run_index_origin",
            "pairing_rule",
        },
        "execution",
    )
    _require_keys(
        comparators,
        {"binding_tools", "diagnostic_tools", "performance_pass_scope"},
        "comparators",
    )
    _require_keys(metric_sample_domains, set(METRICS), "metric_sample_domains")
    _require_keys(
        bootstrap,
        {
            "statistic",
            "resamples",
            "identity_encoding",
            "case_id_derivation",
            "stream_algorithm",
            "counter_encoding",
            "index_sampling",
            "percentile_interpolation",
            "confidence_level",
            "pass_rule",
        },
        "bootstrap",
    )
    _require_keys(
        size,
        {
            "compressible_pass_rule",
            "incompressible_if_best_raw_ratio_gt",
            "allowance_minimum_bytes",
            "allowance_divisor",
            "incompressible_pass_rule",
            "deterministic_size_statistic",
            "encrypted_size_statistic",
            "encrypted_distribution_samples",
        },
        "size",
    )

    _require_literal(root["schema_version"], SCHEMA_VERSION, "schema_version")
    _require_literal(root["contract_id"], CONTRACT_ID, "contract_id")
    _require_literal(
        root["contract_digest_algorithm"],
        CONTRACT_DIGEST_ALGORITHM,
        "contract_digest_algorithm",
    )
    _require_literal(candidate["archive_format"], "MSC7", "candidate.archive_format")
    _require_literal(candidate["profile"], "adaptive-v1", "candidate.profile")
    _require_literal(
        candidate["configuration_id"],
        "msc7-default-v1",
        "candidate.configuration_id",
    )
    _require_literal(
        corpus["minimum_input_bytes"],
        MINIMUM_INPUT_BYTES,
        "corpus.minimum_input_bytes",
    )
    _require_literal_list(execution["threads"], (1, 8), "execution.threads")
    _require_literal(execution["warmup_runs"], 1, "execution.warmup_runs")
    _require_literal(
        execution["measured_runs"],
        MEASURED_RUNS,
        "execution.measured_runs",
    )
    _require_literal(
        execution["fresh_process_per_run"],
        True,
        "execution.fresh_process_per_run",
    )
    _require_literal(
        execution["alternating_candidate_comparator_order"],
        True,
        "execution.alternating_candidate_comparator_order",
    )
    _require_literal(
        execution["containment"],
        "pre_exec_fresh_cgroup_v2_and_pid_namespace",
        "execution.containment",
    )
    _require_literal(
        execution["cpu_tier_enforcement"],
        "exact_cpuset_and_tool_threads",
        "execution.cpu_tier_enforcement",
    )
    _require_literal(
        execution["memory_peak_source"],
        "cgroup_v2_memory_peak_after_populated_zero",
        "execution.memory_peak_source",
    )
    _require_literal(
        execution["swap_peak_scope"],
        "excluded",
        "execution.swap_peak_scope",
    )
    _require_literal(
        execution["page_cache_policy"],
        "input_prewarmed_outside_measured_cgroup_output_cache_included_v1",
        "execution.page_cache_policy",
    )
    _require_literal_list(
        execution["even_run_order"],
        ("candidate", *BINDING_TOOLS),
        "execution.even_run_order",
    )
    _require_literal_list(
        execution["odd_run_order"],
        tuple(reversed(("candidate", *BINDING_TOOLS))),
        "execution.odd_run_order",
    )
    _require_literal_list(
        execution["warmup_order"],
        ("candidate", *BINDING_TOOLS),
        "execution.warmup_order",
    )
    _require_literal(
        execution["run_index_origin"],
        "zero_based",
        "execution.run_index_origin",
    )
    _require_literal(
        execution["pairing_rule"],
        "shared_candidate_index_to_each_comparator_same_index",
        "execution.pairing_rule",
    )
    _require_literal_list(
        comparators["binding_tools"],
        BINDING_TOOLS,
        "comparators.binding_tools",
    )
    _require_literal_list(
        comparators["diagnostic_tools"],
        DIAGNOSTIC_TOOLS,
        "comparators.diagnostic_tools",
    )
    _require_literal(
        comparators["performance_pass_scope"],
        "all_binding_tools",
        "comparators.performance_pass_scope",
    )
    _require_literal_list(root["metrics"], METRICS, "metrics")
    for metric, domain in METRIC_SAMPLE_DOMAINS:
        _require_literal(
            metric_sample_domains[metric],
            domain,
            f"metric_sample_domains.{metric}",
        )
    _require_literal(
        bootstrap["statistic"],
        "paired_median_ratio",
        "bootstrap.statistic",
    )
    _require_literal(
        bootstrap["resamples"],
        BOOTSTRAP_RESAMPLES,
        "bootstrap.resamples",
    )
    _require_literal(
        bootstrap["identity_encoding"],
        "utf8_u32be_length_prefixed_fields_v1",
        "bootstrap.identity_encoding",
    )
    _require_literal(
        bootstrap["case_id_derivation"],
        "sha256_case_identity_v1",
        "bootstrap.case_id_derivation",
    )
    _require_literal(
        bootstrap["stream_algorithm"],
        "sha256_counter_v1",
        "bootstrap.stream_algorithm",
    )
    _require_literal(
        bootstrap["counter_encoding"],
        "u64be_start_zero",
        "bootstrap.counter_encoding",
    )
    _require_literal(
        bootstrap["index_sampling"],
        "u64be_rejection_modulo",
        "bootstrap.index_sampling",
    )
    _require_literal(
        bootstrap["percentile_interpolation"],
        "type_7",
        "bootstrap.percentile_interpolation",
    )
    _require_literal(
        bootstrap["confidence_level"],
        BOOTSTRAP_CONFIDENCE_LEVEL,
        "bootstrap.confidence_level",
    )
    _require_literal(
        bootstrap["pass_rule"],
        "every_binding_comparator_upper_bound_lt_1",
        "bootstrap.pass_rule",
    )
    _require_literal(
        size["compressible_pass_rule"],
        "candidate_lt_smallest_comparator",
        "size.compressible_pass_rule",
    )
    _require_literal(
        size["incompressible_if_best_raw_ratio_gt"],
        0.99,
        "size.incompressible_if_best_raw_ratio_gt",
    )
    _require_literal(
        size["allowance_minimum_bytes"],
        4096,
        "size.allowance_minimum_bytes",
    )
    _require_literal(
        size["allowance_divisor"],
        2000,
        "size.allowance_divisor",
    )
    _require_literal(
        size["incompressible_pass_rule"],
        "candidate_lte_input_plus_allowance_and_lte_smallest_encrypted",
        "size.incompressible_pass_rule",
    )
    _require_literal(
        size["deterministic_size_statistic"],
        "archive_bytes",
        "size.deterministic_size_statistic",
    )
    _require_literal(
        size["encrypted_size_statistic"],
        "median",
        "size.encrypted_size_statistic",
    )
    _require_literal(
        size["encrypted_distribution_samples"],
        MEASURED_RUNS,
        "size.encrypted_distribution_samples",
    )
    return COMPETITIVE_CONTRACT_V1


def load_competitive_contract(
    path: str | Path,
    *,
    max_bytes: int = MAX_CONTRACT_JSON_BYTES,
) -> CompetitiveContract:
    """Load the exact v1 contract from size-bounded, strict UTF-8 JSON."""
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    with Path(path).open("rb") as source:
        payload_bytes = source.read(max_bytes + 1)
    if len(payload_bytes) > max_bytes:
        raise ContractValidationError(f"contract JSON exceeds {max_bytes} bytes")
    try:
        payload_text = payload_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ContractValidationError("contract JSON must be valid UTF-8") from error
    try:
        payload = json.loads(
            payload_text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except json.JSONDecodeError as error:
        raise ContractValidationError("invalid JSON in competitive contract") from error
    except RecursionError as error:
        raise ContractValidationError("competitive contract JSON is too deeply nested") from error
    return _validate_contract_payload(payload)


def _validated_samples(
    samples: Sequence[int | float],
    context: str,
    *,
    positive: bool,
) -> tuple[float, ...]:
    if isinstance(samples, str | bytes | bytearray) or not isinstance(samples, Sequence):
        raise ValueError(f"{context} must be a numeric sequence")
    if not samples:
        raise ValueError(f"{context} must not be empty")
    result: list[float] = []
    for value in samples:
        if type(value) not in {int, float}:
            raise ValueError(f"{context} must contain only numbers (not booleans)")
        try:
            number = float(value)
        except OverflowError as error:
            raise ValueError(f"{context} values must be finite") from error
        if not math.isfinite(number):
            raise ValueError(f"{context} values must be finite")
        if positive and number <= 0.0:
            raise ValueError(f"{context} values must be greater than zero")
        result.append(number)
    return tuple(result)


def median_absolute_deviation(samples: Sequence[int | float]) -> float:
    """Return the unscaled median absolute deviation of finite samples."""
    values = _validated_samples(samples, "samples", positive=False)
    median = float(statistics.median(values))
    return float(statistics.median(abs(value - median) for value in values))


def _percentile_type7(values: Sequence[int | float], percentile: float) -> float:
    """Return an R Type-7 linearly interpolated percentile."""
    samples = sorted(_validated_samples(values, "values", positive=False))
    if (
        type(percentile) not in {int, float}
        or not math.isfinite(float(percentile))
        or not 0.0 <= float(percentile) <= 1.0
    ):
        raise ValueError("percentile must be a finite number from zero through one")
    position = (len(samples) - 1) * float(percentile)
    lower_index = math.floor(position)
    upper_index = math.ceil(position)
    if lower_index == upper_index:
        return samples[lower_index]
    fraction = position - lower_index
    return samples[lower_index] + fraction * (samples[upper_index] - samples[lower_index])


def _require_sha256(value: object, context: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{context} must be a lowercase SHA-256 digest")
    return value


def _validate_case_identity(identity: CaseIdentity) -> None:
    contract_sha256 = _require_sha256(identity.contract_sha256, "contract_sha256")
    if contract_sha256 != CONTRACT_SHA256:
        raise ValueError("contract_sha256 must bind the exact Competitive Contract v1 bytes")
    _require_sha256(identity.corpus_manifest_sha256, "corpus_manifest_sha256")
    if (
        not isinstance(identity.corpus_id, str)
        or _CORPUS_ID_PATTERN.fullmatch(identity.corpus_id) is None
        or len(identity.corpus_id.encode("utf-8")) > MAX_CORPUS_ID_BYTES
    ):
        raise ValueError("corpus_id must be a canonical lowercase identifier of at most 128 bytes")
    _require_sha256(identity.input_sha256, "input_sha256")
    if type(identity.input_bytes) is not int or identity.input_bytes < MINIMUM_INPUT_BYTES:
        raise ValueError(f"input_bytes must meet minimum_input_bytes={MINIMUM_INPUT_BYTES}")
    if type(identity.thread_count) is not int or identity.thread_count not in (1, 8):
        raise ValueError("thread_count must be one of (1, 8)")
    if identity.metric not in METRICS:
        raise ValueError(f"metric must be one of {METRICS!r}")


def _length_prefixed_identity(domain: str, fields: Sequence[str]) -> bytes:
    encoded = bytearray()
    for value in (domain, *fields):
        field = value.encode("utf-8")
        if len(field) > 0xFFFF_FFFF:
            raise ValueError("identity field exceeds the unsigned 32-bit length encoding")
        encoded.extend(len(field).to_bytes(4, "big"))
        encoded.extend(field)
    return bytes(encoded)


def _case_identity_fields(identity: CaseIdentity) -> tuple[str, ...]:
    if not isinstance(identity, CaseIdentity):
        raise ValueError("identity must be a CaseIdentity")
    _validate_case_identity(identity)
    return (
        identity.contract_sha256,
        identity.corpus_manifest_sha256,
        identity.corpus_id,
        identity.input_sha256,
        str(identity.input_bytes),
        str(identity.thread_count),
        identity.metric,
    )


def derive_case_id(identity: CaseIdentity) -> str:
    """Derive the canonical display ID from every immutable case-identity field."""
    material = _length_prefixed_identity(_CASE_ID_DOMAIN, _case_identity_fields(identity))
    return f"{CASE_ID_PREFIX}{hashlib.sha256(material).hexdigest()}"


def _require_case_id(value: object, expected: str) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"msc-case-v1-[0-9a-f]{64}", value) is None
        or len(value.encode("utf-8")) > MAX_CASE_ID_BYTES
    ):
        raise ValueError("case_id must be the canonical derived identifier")
    if value != expected:
        raise ValueError("case_id does not match the bound case identity")
    return value


def _require_binding_comparator_id(comparator_id: object) -> str:
    if not isinstance(comparator_id, str) or comparator_id not in BINDING_TOOLS:
        raise ValueError(f"comparator_id must be one of {BINDING_TOOLS!r}")
    return comparator_id


def _sha256_counter_words(material: bytes) -> Iterator[int]:
    counter = 0
    while counter < _UINT64_RANGE:
        block = hashlib.sha256(material + counter.to_bytes(8, "big")).digest()
        for offset in range(0, len(block), 8):
            yield int.from_bytes(block[offset : offset + 8], "big")
        counter += 1
    raise RuntimeError("SHA-256 counter stream exhausted")


def _bootstrap_indices(
    identity: CaseIdentity,
    comparator_id: str,
    *,
    count: int,
    upper_bound: int,
) -> tuple[int, ...]:
    """Return portable rejection-sampled indices from the v1 SHA-256 stream."""
    comparator = _require_binding_comparator_id(comparator_id)
    if type(count) is not int or count < 0:
        raise ValueError("count must be a nonnegative integer")
    if type(upper_bound) is not int or not 0 < upper_bound <= _UINT64_RANGE:
        raise ValueError("upper_bound must be an integer from 1 through 2^64")
    material = _length_prefixed_identity(
        _BOOTSTRAP_STREAM_DOMAIN,
        (*_case_identity_fields(identity), comparator),
    )
    if count == 0:
        return ()
    acceptance_limit = _UINT64_RANGE - (_UINT64_RANGE % upper_bound)
    result: list[int] = []
    for word in _sha256_counter_words(material):
        if word < acceptance_limit:
            result.append(word % upper_bound)
            if len(result) == count:
                return tuple(result)
    raise RuntimeError("SHA-256 counter stream exhausted")


def _validated_metric_samples(
    metric: str,
    samples: Sequence[int | float],
    context: str,
) -> tuple[float, ...]:
    if metric not in METRICS:
        raise ValueError(f"metric must be one of {METRICS!r}")
    if metric not in MEMORY_METRICS:
        return _validated_samples(samples, context, positive=True)
    if isinstance(samples, str | bytes | bytearray) or not isinstance(samples, Sequence):
        raise ValueError(f"{context} cgroup memory.peak values must be a numeric sequence")
    if not samples:
        raise ValueError(f"{context} cgroup memory.peak values must not be empty")
    result: list[float] = []
    for value in samples:
        if type(value) is not int or not 0 < value <= MAX_CGROUP_MEMORY_PEAK_BYTES:
            raise ValueError(
                f"{context} cgroup memory.peak values must be positive "
                "signed 64-bit integers"
            )
        result.append(float(value))
    return tuple(result)


def paired_bootstrap_ratio_ci(
    candidate_samples: Sequence[int | float],
    comparator_samples: Sequence[int | float],
    *,
    identity: CaseIdentity,
    comparator_id: str,
    resamples: int = BOOTSTRAP_RESAMPLES,
    confidence_level: float = BOOTSTRAP_CONFIDENCE_LEVEL,
) -> ConfidenceInterval:
    """Bootstrap paired ratios with the portable, identity-bound v1 stream."""
    if not isinstance(identity, CaseIdentity):
        raise ValueError("identity must be a CaseIdentity")
    candidate = _validated_metric_samples(
        identity.metric,
        candidate_samples,
        "candidate_samples",
    )
    comparator = _validated_metric_samples(
        identity.metric,
        comparator_samples,
        "comparator_samples",
    )
    if len(candidate) != len(comparator):
        raise ValueError("candidate_samples and comparator_samples must have equal lengths")
    if type(resamples) is not int or not 0 < resamples <= BOOTSTRAP_RESAMPLES:
        raise ValueError(f"resamples must be an integer from 1 through {BOOTSTRAP_RESAMPLES}")
    if (
        type(confidence_level) not in {int, float}
        or not math.isfinite(float(confidence_level))
        or not 0.0 < float(confidence_level) < 1.0
    ):
        raise ValueError("confidence_level must be a finite number between zero and one")

    paired_ratios = tuple(
        candidate_value / comparator_value
        for candidate_value, comparator_value in zip(
            candidate,
            comparator,
            strict=True,
        )
    )
    if not all(math.isfinite(ratio) and ratio > 0.0 for ratio in paired_ratios):
        raise ValueError("paired candidate/comparator ratios must be finite and positive")
    sample_count = len(paired_ratios)
    indices = iter(
        _bootstrap_indices(
            identity,
            comparator_id,
            count=resamples * sample_count,
            upper_bound=sample_count,
        )
    )
    bootstrap_statistics = []
    for _ in range(resamples):
        bootstrap_statistics.append(
            float(statistics.median(paired_ratios[next(indices)] for _ in range(sample_count)))
        )
    tail = (1.0 - float(confidence_level)) / 2.0
    return ConfidenceInterval(
        lower=_percentile_type7(bootstrap_statistics, tail),
        upper=_percentile_type7(bootstrap_statistics, 1.0 - tail),
        confidence_level=float(confidence_level),
    )


def evaluate_metric_case(
    metric: str,
    candidate_samples: Sequence[int | float],
    comparator_samples: Sequence[int | float],
    *,
    identity: CaseIdentity,
    comparator_id: str,
) -> MetricVerdict:
    """Evaluate one binding metric from exactly eleven raw paired samples."""
    if metric not in METRICS:
        raise ValueError(f"metric must be one of {METRICS!r}")
    if not isinstance(identity, CaseIdentity) or identity.metric != metric:
        raise ValueError("identity.metric must match metric")
    comparator = _require_binding_comparator_id(comparator_id)
    candidate = _validated_metric_samples(
        metric,
        candidate_samples,
        "candidate_samples",
    )
    comparator_values = _validated_metric_samples(
        metric,
        comparator_samples,
        "comparator_samples",
    )
    if len(candidate) != MEASURED_RUNS or len(comparator_values) != MEASURED_RUNS:
        raise ValueError(f"metric cases require exactly {MEASURED_RUNS} paired samples")
    interval = paired_bootstrap_ratio_ci(
        candidate_samples,
        comparator_samples,
        identity=identity,
        comparator_id=comparator,
    )
    paired_ratio = float(
        statistics.median(
            candidate_value / comparator_value
            for candidate_value, comparator_value in zip(
                candidate,
                comparator_values,
                strict=True,
            )
        )
    )
    return MetricVerdict(
        metric=metric,
        comparator_id=comparator,
        sample_count=MEASURED_RUNS,
        candidate_median=float(statistics.median(candidate)),
        comparator_median=float(statistics.median(comparator_values)),
        candidate_mad=median_absolute_deviation(candidate),
        comparator_mad=median_absolute_deviation(comparator_values),
        paired_median_ratio=paired_ratio,
        confidence_interval=interval,
        passed=interval.upper < 1.0,
    )


def _positive_integer(value: object, context: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{context} must be a positive integer")
    return value


def allowed_incompressible_overhead(input_bytes: int) -> int:
    """Return ``max(4096, ceil(input_bytes / 2000))`` using integers."""
    size = _positive_integer(input_bytes, "input_bytes")
    return max(4096, (size + 1999) // 2000)


def _positive_size_mapping(value: object, context: str) -> dict[str, int]:
    if not isinstance(value, Mapping) or not value:
        raise ValueError(f"{context} must be a nonempty mapping")
    result: dict[str, int] = {}
    for comparator_id, size in value.items():
        if not isinstance(comparator_id, str) or not comparator_id.strip():
            raise ValueError(f"{context} keys must be nonempty strings")
        result[comparator_id] = _positive_integer(size, f"{context}.{comparator_id}")
    return result


def _encrypted_size_mapping(value: object, context: str) -> dict[str, int]:
    if not isinstance(value, Mapping) or not value:
        raise ValueError(f"{context} must be a nonempty mapping")
    result: dict[str, int] = {}
    for comparator_id, distribution in value.items():
        if not isinstance(comparator_id, str) or not comparator_id.strip():
            raise ValueError(f"{context} keys must be nonempty strings")
        if (
            isinstance(distribution, str | bytes | bytearray)
            or not isinstance(distribution, Sequence)
            or len(distribution) != MEASURED_RUNS
        ):
            raise ValueError(
                f"{context}.{comparator_id} must contain exactly {MEASURED_RUNS} sizes"
            )
        sizes = tuple(
            _positive_integer(size, f"{context}.{comparator_id}") for size in distribution
        )
        result[comparator_id] = sorted(sizes)[MEASURED_RUNS // 2]
    return result


def _smallest_size(sizes: Mapping[str, int]) -> tuple[str, int]:
    size, comparator_id = min((size, comparator_id) for comparator_id, size in sizes.items())
    return comparator_id, size


def evaluate_size_case(
    *,
    input_bytes: int,
    candidate_archive_bytes: int,
    raw_comparator_archive_bytes: Mapping[str, int],
    encrypted_comparator_archive_bytes: Mapping[str, Sequence[int]],
) -> SizeVerdict:
    """Apply the v1 compressible rule or its bounded incompressible exception."""
    input_size = _positive_integer(input_bytes, "input_bytes")
    candidate_size = _positive_integer(
        candidate_archive_bytes,
        "candidate_archive_bytes",
    )
    raw_sizes = _positive_size_mapping(
        raw_comparator_archive_bytes,
        "raw_comparator_archive_bytes",
    )
    encrypted_sizes = _encrypted_size_mapping(
        encrypted_comparator_archive_bytes,
        "encrypted_comparator_archive_bytes",
    )
    overlap = set(raw_sizes) & set(encrypted_sizes)
    if overlap:
        raise ValueError(f"raw and encrypted comparator IDs must be disjoint: {sorted(overlap)}")

    best_raw_id, best_raw_size = _smallest_size(raw_sizes)
    smallest_encrypted_id, smallest_encrypted_size = _smallest_size(encrypted_sizes)
    all_sizes = {**raw_sizes, **encrypted_sizes}
    smallest_id, smallest_size = _smallest_size(all_sizes)
    incompressible = best_raw_size * 100 > input_size * 99
    allowance = allowed_incompressible_overhead(input_size)

    if incompressible:
        input_limit = input_size + allowance
        if smallest_encrypted_size <= input_limit:
            selected_limit = smallest_encrypted_size
            selected_source = smallest_encrypted_id
        else:
            selected_limit = input_limit
            selected_source = "input_plus_allowance"
        selected_limit_inclusive = True
        passed = candidate_size <= input_limit and candidate_size <= smallest_encrypted_size
    else:
        selected_limit = smallest_size
        selected_source = smallest_id
        selected_limit_inclusive = False
        passed = candidate_size < smallest_size

    return SizeVerdict(
        input_bytes=input_size,
        candidate_archive_bytes=candidate_size,
        best_raw_comparator_id=best_raw_id,
        best_raw_archive_bytes=best_raw_size,
        smallest_encrypted_comparator_id=smallest_encrypted_id,
        smallest_encrypted_comparator_archive_bytes=smallest_encrypted_size,
        smallest_comparator_id=smallest_id,
        smallest_comparator_archive_bytes=smallest_size,
        incompressible=incompressible,
        allowance_bytes=allowance,
        selected_limit_bytes=selected_limit,
        selected_limit_source=selected_source,
        selected_limit_inclusive=selected_limit_inclusive,
        passed=passed,
    )


def _scorecard_object(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError("scorecard case must be an object")
    return cast(Mapping[str, object], value)


def _binding_metric_samples(value: object, metric: str) -> dict[str, tuple[float, ...]]:
    if not isinstance(value, Mapping):
        raise ValueError("comparator_samples must be an object")
    if set(value) != set(BINDING_TOOLS):
        raise ValueError(f"metric comparator IDs must be exactly {sorted(BINDING_TOOLS)!r}")
    result: dict[str, tuple[float, ...]] = {}
    for comparator_id in BINDING_TOOLS:
        samples = _validated_metric_samples(
            metric,
            value[comparator_id],
            f"comparator_samples.{comparator_id}",
        )
        if len(samples) != MEASURED_RUNS:
            raise ValueError(
                f"comparator_samples.{comparator_id} must contain exactly {MEASURED_RUNS} samples"
            )
        result[comparator_id] = samples
    return result


def evaluate_scorecard_case(case: Mapping[str, object]) -> ScorecardCase:
    """Strictly evaluate one synthetic case solely from its raw measurements."""
    payload = _scorecard_object(case)
    _require_keys(
        payload,
        _SCORECARD_CASE_KEYS,
        "scorecard case",
        error_type=ValueError,
    )
    contract_sha256 = _require_sha256(payload["contract_sha256"], "contract_sha256")
    manifest_sha256 = _require_sha256(
        payload["corpus_manifest_sha256"],
        "corpus_manifest_sha256",
    )
    corpus_id = payload["corpus_id"]
    if not isinstance(corpus_id, str):
        raise ValueError("corpus_id must be a canonical lowercase identifier")
    input_sha256 = _require_sha256(payload["input_sha256"], "input_sha256")
    input_bytes = _positive_integer(payload["input_bytes"], "input_bytes")
    thread_count = payload["thread_count"]
    if type(thread_count) is not int or thread_count not in (1, 8):
        raise ValueError("thread_count must be one of (1, 8)")
    metric = payload["metric"]
    if metric not in METRICS:
        raise ValueError(f"metric must be one of {METRICS!r}")
    assert isinstance(metric, str)
    identity = CaseIdentity(
        contract_sha256=contract_sha256,
        corpus_manifest_sha256=manifest_sha256,
        corpus_id=corpus_id,
        input_sha256=input_sha256,
        input_bytes=input_bytes,
        thread_count=thread_count,
        metric=metric,
    )
    case_id = _require_case_id(payload["case_id"], identity.case_id)

    metric_comparators = _binding_metric_samples(payload["comparator_samples"], metric)
    fastest_comparator_id = min(
        metric_comparators,
        key=lambda name: (statistics.median(metric_comparators[name]), name),
    )
    raw_sizes = payload["raw_comparator_archive_bytes"]
    encrypted_sizes = payload["encrypted_comparator_archive_bytes"]
    if not isinstance(raw_sizes, Mapping) or set(raw_sizes) != set(BINDING_RAW_TOOLS):
        raise ValueError(f"raw comparator IDs must be exactly {sorted(BINDING_RAW_TOOLS)!r}")
    if not isinstance(encrypted_sizes, Mapping) or set(encrypted_sizes) != set(
        BINDING_ENCRYPTED_TOOLS
    ):
        raise ValueError(
            f"encrypted comparator IDs must be exactly {sorted(BINDING_ENCRYPTED_TOOLS)!r}"
        )

    metric_verdicts = tuple(
        evaluate_metric_case(
            metric,
            payload["candidate_samples"],  # type: ignore[arg-type]
            metric_comparators[comparator_id],
            identity=identity,
            comparator_id=comparator_id,
        )
        for comparator_id in BINDING_TOOLS
    )
    size_verdict = evaluate_size_case(
        input_bytes=input_bytes,
        candidate_archive_bytes=payload["candidate_archive_bytes"],  # type: ignore[arg-type]
        raw_comparator_archive_bytes=raw_sizes,
        encrypted_comparator_archive_bytes=encrypted_sizes,
    )
    return ScorecardCase(
        case_id=case_id,
        identity=identity,
        thread_count=thread_count,
        fastest_comparator_id=fastest_comparator_id,
        metric_verdicts=metric_verdicts,
        size_verdict=size_verdict,
        passed=all(verdict.passed for verdict in metric_verdicts) and size_verdict.passed,
    )
