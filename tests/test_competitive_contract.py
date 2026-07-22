from __future__ import annotations

import hashlib
import json
import math
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

from mosaic_archive.competitive_contract import (
    BINDING_ENCRYPTED_TOOLS,
    BINDING_TOOLS,
    CONTRACT_SHA256,
    MAX_CASE_ID_BYTES,
    MAX_CGROUP_MEMORY_PEAK_BYTES,
    CaseIdentity,
    ConfidenceInterval,
    ContractValidationError,
    MetricVerdict,
    ScorecardCase,
    SizeVerdict,
    _bootstrap_indices,
    _percentile_type7,
    allowed_incompressible_overhead,
    derive_case_id,
    evaluate_metric_case,
    evaluate_scorecard_case,
    evaluate_size_case,
    load_competitive_contract,
    median_absolute_deviation,
    paired_bootstrap_ratio_ci,
)

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "benchmarks" / "competitive-v1" / "contract.json"
METRICS = (
    "encode_wall_seconds",
    "decode_wall_seconds",
    "encode_cgroup_v2_memory_peak_bytes",
    "decode_cgroup_v2_memory_peak_bytes",
)
CORPUS_MANIFEST_SHA256 = "1" * 64
INPUT_SHA256 = "2" * 64


def _case_identity(
    *,
    thread_count: int = 1,
    metric: str = "encode_wall_seconds",
) -> CaseIdentity:
    return CaseIdentity(
        contract_sha256=CONTRACT_SHA256,
        corpus_manifest_sha256=CORPUS_MANIFEST_SHA256,
        corpus_id="enwik8-text",
        input_sha256=INPUT_SHA256,
        input_bytes=67_108_864,
        thread_count=thread_count,
        metric=metric,
    )


def _contract_payload() -> dict[str, Any]:
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


def _encrypted_sizes(value: int) -> dict[str, list[int]]:
    return {name: [value] * 11 for name in BINDING_ENCRYPTED_TOOLS}


def _scorecard_payload() -> dict[str, object]:
    identity = _case_identity()
    return {
        "case_id": derive_case_id(identity),
        "contract_sha256": CONTRACT_SHA256,
        "corpus_manifest_sha256": CORPUS_MANIFEST_SHA256,
        "corpus_id": "enwik8-text",
        "input_sha256": INPUT_SHA256,
        "thread_count": 1,
        "metric": "encode_wall_seconds",
        "input_bytes": 67_108_864,
        "candidate_archive_bytes": 30_000_000,
        "candidate_samples": [8.0] * 11,
        "comparator_samples": {
            "7zip_raw": [10.0] * 11,
            "7zip_aes256_headers": [12.0] * 11,
            "zstd_raw": [11.0] * 11,
            "zstd_age_passphrase": [13.0] * 11,
        },
        "raw_comparator_archive_bytes": {
            "7zip_raw": 32_000_000,
            "zstd_raw": 35_000_000,
        },
        "encrypted_comparator_archive_bytes": {
            "7zip_aes256_headers": [33_000_000] * 11,
            "zstd_age_passphrase": [36_000_000] * 11,
        },
    }


class ContractTestCase(unittest.TestCase):
    def load_temporary_payload(
        self,
        payload: object,
        *,
        raw: bytes | None = None,
        max_bytes: int = 64 * 1024,
    ) -> object:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "contract.json"
            if raw is not None:
                path.write_bytes(raw)
            else:
                path.write_text(json.dumps(payload), encoding="utf-8")
            return load_competitive_contract(path, max_bytes=max_bytes)


class TestContractLoading(ContractTestCase):
    def test_committed_contract_locks_every_v1_decision(self) -> None:
        contract = load_competitive_contract(CONTRACT_PATH)

        canonical_contract = json.dumps(
            _contract_payload(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertEqual(
            hashlib.sha256(canonical_contract).hexdigest(),
            CONTRACT_SHA256,
        )
        self.assertEqual(contract.schema_version, 1)
        self.assertEqual(contract.contract_id, "mosaic-competitive-contract-v1")
        self.assertEqual(contract.contract_digest_algorithm, "sha256_canonical_json_v1")
        self.assertEqual(contract.candidate.archive_format, "MSC7")
        self.assertEqual(contract.candidate.profile, "adaptive-v1")
        self.assertEqual(contract.candidate.configuration_id, "msc7-default-v1")
        self.assertEqual(contract.corpus.minimum_input_bytes, 67_108_864)
        self.assertEqual(contract.execution.threads, (1, 8))
        self.assertEqual(contract.execution.warmup_runs, 1)
        self.assertEqual(contract.execution.measured_runs, 11)
        self.assertIs(contract.execution.fresh_process_per_run, True)
        self.assertIs(
            contract.execution.alternating_candidate_comparator_order,
            True,
        )
        self.assertEqual(
            contract.execution.containment,
            "pre_exec_fresh_cgroup_v2_and_pid_namespace",
        )
        self.assertEqual(
            contract.execution.cpu_tier_enforcement,
            "exact_cpuset_and_tool_threads",
        )
        self.assertEqual(
            contract.execution.memory_peak_source,
            "cgroup_v2_memory_peak_after_populated_zero",
        )
        self.assertEqual(contract.execution.swap_peak_scope, "excluded")
        self.assertEqual(
            contract.execution.page_cache_policy,
            "input_prewarmed_outside_measured_cgroup_output_cache_included_v1",
        )
        self.assertEqual(
            contract.execution.even_run_order,
            ("candidate", "7zip_raw", "7zip_aes256_headers", "zstd_raw", "zstd_age_passphrase"),
        )
        self.assertEqual(
            contract.execution.odd_run_order,
            tuple(reversed(contract.execution.even_run_order)),
        )
        self.assertEqual(
            contract.execution.warmup_order,
            contract.execution.even_run_order,
        )
        self.assertEqual(contract.execution.run_index_origin, "zero_based")
        self.assertEqual(
            contract.execution.pairing_rule,
            "shared_candidate_index_to_each_comparator_same_index",
        )
        self.assertEqual(
            contract.comparators.binding_tools,
            (
                "7zip_raw",
                "7zip_aes256_headers",
                "zstd_raw",
                "zstd_age_passphrase",
            ),
        )
        self.assertEqual(
            contract.comparators.diagnostic_tools,
            ("gzip", "zip", "xz", "brotli", "lz4"),
        )
        self.assertEqual(
            contract.comparators.performance_pass_scope,
            "all_binding_tools",
        )
        self.assertEqual(contract.metrics, METRICS)
        self.assertEqual(
            dict(contract.metric_sample_domains),
            {
                "encode_wall_seconds": "positive_finite_number",
                "decode_wall_seconds": "positive_finite_number",
                "encode_cgroup_v2_memory_peak_bytes": "positive_signed_64_bit_integer",
                "decode_cgroup_v2_memory_peak_bytes": "positive_signed_64_bit_integer",
            },
        )
        self.assertEqual(contract.bootstrap.statistic, "paired_median_ratio")
        self.assertEqual(contract.bootstrap.resamples, 10_000)
        self.assertEqual(
            contract.bootstrap.identity_encoding,
            "utf8_u32be_length_prefixed_fields_v1",
        )
        self.assertEqual(
            contract.bootstrap.case_id_derivation,
            "sha256_case_identity_v1",
        )
        self.assertEqual(
            contract.bootstrap.stream_algorithm,
            "sha256_counter_v1",
        )
        self.assertEqual(contract.bootstrap.counter_encoding, "u64be_start_zero")
        self.assertEqual(
            contract.bootstrap.index_sampling,
            "u64be_rejection_modulo",
        )
        self.assertEqual(contract.bootstrap.percentile_interpolation, "type_7")
        self.assertEqual(contract.bootstrap.confidence_level, 0.95)
        self.assertEqual(
            contract.bootstrap.pass_rule,
            "every_binding_comparator_upper_bound_lt_1",
        )
        self.assertEqual(
            contract.size.compressible_pass_rule,
            "candidate_lt_smallest_comparator",
        )
        self.assertEqual(contract.size.incompressible_if_best_raw_ratio_gt, 0.99)
        self.assertEqual(contract.size.allowance_minimum_bytes, 4096)
        self.assertEqual(contract.size.allowance_divisor, 2000)
        self.assertEqual(
            contract.size.incompressible_pass_rule,
            "candidate_lte_input_plus_allowance_and_lte_smallest_encrypted",
        )
        self.assertEqual(contract.size.deterministic_size_statistic, "archive_bytes")
        self.assertEqual(contract.size.encrypted_size_statistic, "median")
        self.assertEqual(contract.size.encrypted_distribution_samples, 11)

    def test_contract_and_nested_specs_are_immutable(self) -> None:
        contract = load_competitive_contract(CONTRACT_PATH)

        with self.assertRaises(FrozenInstanceError):
            contract.contract_id = "changed"  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            contract.candidate.profile = "changed"  # type: ignore[misc]
        with self.assertRaises(AttributeError):
            contract.metrics.append("changed")  # type: ignore[attr-defined]

    def test_contract_requires_exact_keys(self) -> None:
        mutations = {
            "top-level-extra": lambda payload: payload.update(extra=True),
            "top-level-missing": lambda payload: payload.pop("metrics"),
            "nested-extra": lambda payload: payload["candidate"].update(extra=True),
            "nested-missing": lambda payload: payload["execution"].pop("measured_runs"),
            "sample-domain-extra": lambda payload: payload["metric_sample_domains"].update(
                extra="positive_finite_number"
            ),
            "size-extra": lambda payload: payload["size"].update(extra=True),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                payload = _contract_payload()
                mutate(payload)
                with self.assertRaisesRegex(ContractValidationError, "keys"):
                    self.load_temporary_payload(payload)

    def test_contract_rejects_wrong_values_and_bool_as_int(self) -> None:
        cases = (
            (None, "schema_version", True),
            ("corpus", "minimum_input_bytes", True),
            ("execution", "warmup_runs", False),
            ("execution", "measured_runs", 10),
            ("execution", "fresh_process_per_run", 1),
            ("bootstrap", "resamples", True),
            ("bootstrap", "stream_algorithm", "implementation_random"),
            ("bootstrap", "confidence_level", math.inf),
            ("comparators", "performance_pass_scope", "selected_fastest_only"),
            ("size", "allowance_divisor", 2001),
            ("size", "encrypted_distribution_samples", 10),
        )
        for section, field, value in cases:
            with self.subTest(section=section, field=field, value=value):
                payload = _contract_payload()
                target = payload if section is None else payload[section]
                target[field] = value
                with self.assertRaises(ContractValidationError):
                    self.load_temporary_payload(payload)

    def test_contract_rejects_nonobject_sections(self) -> None:
        payload = _contract_payload()
        payload["candidate"] = []

        with self.assertRaisesRegex(ContractValidationError, "JSON object"):
            self.load_temporary_payload(payload)

    def test_contract_rejects_wrong_exact_lists(self) -> None:
        cases = (
            ("threads", [1, True]),
            ("threads", [8, 1]),
            ("binding_tools", ["7zip_raw"]),
            ("metrics", [*METRICS, "extra"]),
        )
        for field, value in cases:
            with self.subTest(field=field):
                payload = _contract_payload()
                if field == "threads":
                    payload["execution"][field] = value
                elif field == "binding_tools":
                    payload["comparators"][field] = value
                else:
                    payload[field] = value
                with self.assertRaises(ContractValidationError):
                    self.load_temporary_payload(payload)

    def test_loader_rejects_duplicate_keys_at_any_depth(self) -> None:
        raw = (
            b'{"contract_id":"first","candidate":{"profile":"one",'
            b'"profile":"two"},"contract_id":"second"}'
        )
        with self.assertRaisesRegex(ContractValidationError, "duplicate JSON key"):
            self.load_temporary_payload({}, raw=raw)

    def test_loader_rejects_nonstandard_json_constants(self) -> None:
        for constant in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(constant=constant):
                raw = f'{{"value": {constant}}}'.encode()
                with self.assertRaisesRegex(
                    ContractValidationError,
                    "non-finite JSON constant",
                ):
                    self.load_temporary_payload({}, raw=raw)

    def test_loader_reads_only_through_the_size_limit(self) -> None:
        with self.assertRaisesRegex(ContractValidationError, "exceeds 16 bytes"):
            self.load_temporary_payload(
                {},
                raw=b"{" + b" " * 32 + b"}",
                max_bytes=16,
            )

    def test_loader_rejects_invalid_size_limits(self) -> None:
        for max_bytes in (True, 0, -1):
            with (
                self.subTest(max_bytes=max_bytes),
                self.assertRaisesRegex(
                    ValueError,
                    "max_bytes",
                ),
            ):
                self.load_temporary_payload({}, max_bytes=max_bytes)  # type: ignore[arg-type]

    def test_loader_rejects_invalid_utf8_and_json(self) -> None:
        with self.assertRaisesRegex(ContractValidationError, "UTF-8"):
            self.load_temporary_payload({}, raw=b"\xff")
        with self.assertRaisesRegex(ContractValidationError, "invalid JSON"):
            self.load_temporary_payload({}, raw=b"{")


class TestStatistics(unittest.TestCase):
    def test_median_absolute_deviation(self) -> None:
        for samples, expected in (
            ([1], 0.0),
            ([1, 1, 2, 2, 4], 1.0),
            ([1.0, 2.0, 4.0, 8.0], 1.5),
        ):
            with self.subTest(samples=samples):
                self.assertEqual(median_absolute_deviation(samples), expected)

    def test_mad_rejects_invalid_samples(self) -> None:
        for samples in (None, "1", [], [True], [math.nan], [math.inf], ["1"], [10**400]):
            with self.subTest(samples=samples), self.assertRaises(ValueError):
                median_absolute_deviation(samples)  # type: ignore[arg-type]

    def test_percentile_uses_type_7_interpolation(self) -> None:
        cases = (
            ([0.0, 10.0], 0.0, 0.0),
            ([0.0, 10.0], 0.25, 2.5),
            ([0.0, 10.0], 0.975, 9.75),
            ([0.0, 10.0], 1.0, 10.0),
            ([5.0], 0.25, 5.0),
        )
        for values, percentile, expected in cases:
            with self.subTest(percentile=percentile):
                self.assertEqual(
                    _percentile_type7(values, percentile),
                    expected,
                )

    def test_percentile_rejects_invalid_probability(self) -> None:
        for percentile in (-0.1, 1.1, math.nan, True):
            with self.subTest(percentile=percentile), self.assertRaises(ValueError):
                _percentile_type7([1.0], percentile)  # type: ignore[arg-type]

    def test_case_id_and_bootstrap_stream_have_published_vectors(self) -> None:
        identity = _case_identity()

        self.assertEqual(
            derive_case_id(identity),
            "msc-case-v1-57a983a3a9a137ae86248d400b9c4a645c643c8079a793b0a07d22879b3fd30d",
        )
        self.assertEqual(
            _bootstrap_indices(
                identity,
                "7zip_raw",
                count=16,
                upper_bound=11,
            ),
            (10, 9, 3, 9, 2, 9, 8, 8, 6, 0, 7, 6, 9, 7, 10, 8),
        )

    def test_case_identity_rejects_unbound_or_noncanonical_fields(self) -> None:
        cases = (
            {"contract_sha256": "0" * 64},
            {"corpus_manifest_sha256": "A" * 64},
            {"corpus_id": " enwik8-text"},
            {"corpus_id": "enwik8/text"},
            {"corpus_id": "x" * 129},
            {"input_sha256": "2" * 63},
            {"thread_count": True},
            {"thread_count": 2},
            {"metric": "cpu_seconds"},
        )
        baseline: dict[str, object] = {
            "contract_sha256": CONTRACT_SHA256,
            "corpus_manifest_sha256": CORPUS_MANIFEST_SHA256,
            "corpus_id": "enwik8-text",
            "input_sha256": INPUT_SHA256,
            "input_bytes": 67_108_864,
            "thread_count": 1,
            "metric": "encode_wall_seconds",
        }
        for mutation in cases:
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                CaseIdentity(**{**baseline, **mutation})  # type: ignore[arg-type]

    def test_bootstrap_stream_binds_comparator_and_rejection_samples_without_bias(
        self,
    ) -> None:
        identity = _case_identity()
        raw = _bootstrap_indices(identity, "7zip_raw", count=16, upper_bound=11)
        zstd = _bootstrap_indices(identity, "zstd_raw", count=16, upper_bound=11)

        self.assertNotEqual(raw, zstd)
        self.assertEqual(
            _bootstrap_indices(
                identity,
                "7zip_raw",
                count=8,
                upper_bound=(1 << 63) + 1,
            ),
            (
                7_176_288_723_068_545_501,
                6_104_043_190_513_902_434,
                1_085_137_305_915_464_254,
                8_002_573_917_637_613_092,
                4_868_417_030_652_469_687,
                3_773_463_698_296_260_319,
                9_106_907_628_935_786_744,
                2_743_353_560_921_369_763,
            ),
        )

        for count, upper_bound in ((True, 11), (-1, 11), (1, True), (1, 0)):
            with self.subTest(count=count, upper_bound=upper_bound), self.assertRaises(ValueError):
                _bootstrap_indices(
                    identity,
                    "7zip_raw",
                    count=count,  # type: ignore[arg-type]
                    upper_bound=upper_bound,  # type: ignore[arg-type]
                )
        self.assertEqual(
            _bootstrap_indices(identity, "7zip_raw", count=0, upper_bound=11),
            (),
        )

    def test_identity_helpers_require_a_valid_bound_identity(self) -> None:
        with self.assertRaisesRegex(ValueError, "CaseIdentity"):
            derive_case_id("alias")  # type: ignore[arg-type]

    def test_bootstrap_is_paired_deterministic_and_returns_95_percent_ci(self) -> None:
        candidate = [float(value) for value in range(1, 12)]
        comparator = [value + 3.0 for value in candidate]

        identity = _case_identity()
        first = paired_bootstrap_ratio_ci(
            candidate,
            comparator,
            identity=identity,
            comparator_id="7zip_raw",
        )
        second = paired_bootstrap_ratio_ci(
            candidate,
            comparator,
            identity=identity,
            comparator_id="7zip_raw",
        )

        self.assertEqual(first, second)
        self.assertIsInstance(first, ConfidenceInterval)
        self.assertEqual(first.confidence_level, 0.95)
        self.assertTrue(0.0 < first.lower <= first.upper < 1.0)

    def test_bootstrap_constant_ratio_has_exact_interval(self) -> None:
        comparator = [float(value) for value in range(1, 12)]
        candidate = [value / 2.0 for value in comparator]

        interval = paired_bootstrap_ratio_ci(
            candidate,
            comparator,
            identity=_case_identity(),
            comparator_id="7zip_raw",
            resamples=37,
        )

        self.assertEqual(interval.lower, 0.5)
        self.assertEqual(interval.upper, 0.5)

    def test_bootstrap_rejects_invalid_inputs(self) -> None:
        cases: tuple[tuple[object, object, dict[str, object]], ...] = (
            ([], [], {}),
            ([1.0], [1.0, 2.0], {}),
            ([1.0], [0.0], {}),
            ([1.0], [-1.0], {}),
            ([True], [1.0], {}),
            ([1.0], [1.0], {"resamples": True}),
            ([1.0], [1.0], {"resamples": 0}),
            ([1.0], [1.0], {"confidence_level": 1.0}),
        )
        for candidate, comparator, kwargs in cases:
            with (
                self.subTest(
                    candidate=candidate,
                    comparator=comparator,
                    kwargs=kwargs,
                ),
                self.assertRaises(ValueError),
            ):
                paired_bootstrap_ratio_ci(
                    candidate,  # type: ignore[arg-type]
                    comparator,  # type: ignore[arg-type]
                    identity=_case_identity(),
                    comparator_id="7zip_raw",
                    **kwargs,  # type: ignore[arg-type]
                )

        with self.assertRaisesRegex(ValueError, "comparator_id"):
            paired_bootstrap_ratio_ci(
                [1.0],
                [2.0],
                identity=_case_identity(),
                comparator_id="gzip",
            )
        with self.assertRaisesRegex(ValueError, "CaseIdentity"):
            paired_bootstrap_ratio_ci(
                [1.0],
                [2.0],
                identity="alias",  # type: ignore[arg-type]
                comparator_id="7zip_raw",
            )
        with self.assertRaisesRegex(ValueError, "finite and positive"):
            paired_bootstrap_ratio_ci(
                [1e308],
                [5e-324],
                identity=_case_identity(),
                comparator_id="7zip_raw",
            )


class TestMetricVerdicts(unittest.TestCase):
    def test_metric_verdict_recomputes_medians_mad_ratio_and_pass(self) -> None:
        verdict = evaluate_metric_case(
            "encode_wall_seconds",
            [8.0] * 11,
            [10.0] * 11,
            identity=_case_identity(),
            comparator_id="7zip_raw",
        )

        self.assertIsInstance(verdict, MetricVerdict)
        self.assertEqual(verdict.metric, "encode_wall_seconds")
        self.assertEqual(verdict.comparator_id, "7zip_raw")
        self.assertEqual(verdict.sample_count, 11)
        self.assertEqual(verdict.candidate_median, 8.0)
        self.assertEqual(verdict.comparator_median, 10.0)
        self.assertEqual(verdict.candidate_mad, 0.0)
        self.assertEqual(verdict.comparator_mad, 0.0)
        self.assertEqual(verdict.paired_median_ratio, 0.8)
        self.assertEqual(verdict.confidence_interval.lower, 0.8)
        self.assertEqual(verdict.confidence_interval.upper, 0.8)
        self.assertIs(verdict.passed, True)

    def test_metric_pass_is_strictly_upper_bound_below_one(self) -> None:
        verdict = evaluate_metric_case(
            "decode_wall_seconds",
            [10.0] * 11,
            [10.0] * 11,
            identity=_case_identity(metric="decode_wall_seconds"),
            comparator_id="zstd_raw",
        )

        self.assertEqual(verdict.confidence_interval.upper, 1.0)
        self.assertIs(verdict.passed, False)

    def test_metric_requires_a_contract_metric(self) -> None:
        for metric in ("", "cpu_seconds", 1):
            with (
                self.subTest(metric=metric),
                self.assertRaisesRegex(
                    ValueError,
                    "metric",
                ),
            ):
                evaluate_metric_case(
                    metric,  # type: ignore[arg-type]
                    [1.0] * 11,
                    [2.0] * 11,
                    identity=_case_identity(),
                    comparator_id="7zip_raw",
                )

    def test_metric_requires_eleven_positive_samples(self) -> None:
        cases = (
            ([1.0] * 10, [2.0] * 10),
            ([1.0] * 12, [2.0] * 12),
            ([0.0] * 11, [2.0] * 11),
        )
        for candidate, comparator in cases:
            with self.subTest(sample_count=len(candidate)), self.assertRaises(ValueError):
                evaluate_metric_case(
                    "encode_wall_seconds",
                    candidate,
                    comparator,
                    identity=_case_identity(),
                    comparator_id="7zip_raw",
                )

    def test_metric_identity_and_comparator_are_bound(self) -> None:
        with self.assertRaisesRegex(ValueError, "identity.metric"):
            evaluate_metric_case(
                "decode_wall_seconds",
                [1.0] * 11,
                [2.0] * 11,
                identity=_case_identity(metric="encode_wall_seconds"),
                comparator_id="7zip_raw",
            )
        with self.assertRaisesRegex(ValueError, "comparator_id"):
            evaluate_metric_case(
                "encode_wall_seconds",
                [1.0] * 11,
                [2.0] * 11,
                identity=_case_identity(),
                comparator_id="gzip",
            )

    def test_cgroup_memory_metrics_require_bounded_positive_nonboolean_integers(self) -> None:
        identity = _case_identity(metric="encode_cgroup_v2_memory_peak_bytes")
        valid = evaluate_metric_case(
            identity.metric,
            [1] * 11,
            [MAX_CGROUP_MEMORY_PEAK_BYTES] * 11,
            identity=identity,
            comparator_id="7zip_raw",
        )
        self.assertIs(valid.passed, True)

        for invalid in (0, -1, True, 1.5, MAX_CGROUP_MEMORY_PEAK_BYTES + 1):
            with (
                self.subTest(invalid=invalid),
                self.assertRaisesRegex(ValueError, "cgroup memory.peak"),
            ):
                evaluate_metric_case(
                    identity.metric,
                    [invalid] * 11,  # type: ignore[list-item]
                    [2] * 11,
                    identity=identity,
                    comparator_id="7zip_raw",
                )
        for invalid_samples in ([], "memory"):
            with (
                self.subTest(invalid_samples=invalid_samples),
                self.assertRaisesRegex(ValueError, "cgroup memory.peak"),
            ):
                evaluate_metric_case(
                    identity.metric,
                    invalid_samples,  # type: ignore[arg-type]
                    [2] * 11,
                    identity=identity,
                    comparator_id="7zip_raw",
                )

    def test_wall_metrics_accept_positive_finite_numeric_samples(self) -> None:
        verdict = evaluate_metric_case(
            "encode_wall_seconds",
            [1] * 11,
            [2.5] * 11,
            identity=_case_identity(),
            comparator_id="7zip_raw",
        )

        self.assertIs(verdict.passed, True)


class TestSizeVerdicts(unittest.TestCase):
    def test_incompressible_allowance_uses_maximum_and_ceiling_fraction(self) -> None:
        for input_bytes, expected in (
            (1, 4096),
            (8_192_000, 4096),
            (8_192_001, 4097),
            (67_108_864, 33_555),
        ):
            with self.subTest(input_bytes=input_bytes):
                self.assertEqual(
                    allowed_incompressible_overhead(input_bytes),
                    expected,
                )

    def test_allowance_requires_a_positive_integer(self) -> None:
        for input_bytes in (0, -1, True, 1.0):
            with (
                self.subTest(input_bytes=input_bytes),
                self.assertRaisesRegex(
                    ValueError,
                    "input_bytes",
                ),
            ):
                allowed_incompressible_overhead(input_bytes)  # type: ignore[arg-type]

    def test_compressible_case_must_be_strictly_smaller_than_every_comparator(
        self,
    ) -> None:
        passed = evaluate_size_case(
            input_bytes=10_000,
            candidate_archive_bytes=7_999,
            raw_comparator_archive_bytes={"raw-a": 8_000, "raw-b": 9_000},
            encrypted_comparator_archive_bytes=_encrypted_sizes(8_500),
        )
        tied = evaluate_size_case(
            input_bytes=10_000,
            candidate_archive_bytes=8_000,
            raw_comparator_archive_bytes={"raw-a": 8_000, "raw-b": 9_000},
            encrypted_comparator_archive_bytes=_encrypted_sizes(8_500),
        )

        self.assertIsInstance(passed, SizeVerdict)
        self.assertIs(passed.incompressible, False)
        self.assertEqual(passed.best_raw_comparator_id, "raw-a")
        self.assertEqual(passed.best_raw_archive_bytes, 8_000)
        self.assertEqual(passed.smallest_comparator_id, "raw-a")
        self.assertEqual(passed.smallest_comparator_archive_bytes, 8_000)
        self.assertEqual(passed.selected_limit_bytes, 8_000)
        self.assertIs(passed.selected_limit_inclusive, False)
        self.assertIs(passed.passed, True)
        self.assertIs(tied.passed, False)

    def test_exactly_99_percent_is_still_compressible(self) -> None:
        verdict = evaluate_size_case(
            input_bytes=10_000,
            candidate_archive_bytes=9_899,
            raw_comparator_archive_bytes={"raw": 9_900},
            encrypted_comparator_archive_bytes={"encrypted": [9_950] * 11},
        )

        self.assertIs(verdict.incompressible, False)
        self.assertIs(verdict.passed, True)

    def test_over_99_percent_uses_both_inclusive_incompressible_limits(self) -> None:
        passed = evaluate_size_case(
            input_bytes=10_000,
            candidate_archive_bytes=10_100,
            raw_comparator_archive_bytes={"raw": 9_901},
            encrypted_comparator_archive_bytes={"encrypted": [10_100] * 11},
        )
        too_large_for_encrypted = evaluate_size_case(
            input_bytes=10_000,
            candidate_archive_bytes=10_101,
            raw_comparator_archive_bytes={"raw": 9_901},
            encrypted_comparator_archive_bytes={"encrypted": [10_100] * 11},
        )
        too_large_for_allowance = evaluate_size_case(
            input_bytes=10_000,
            candidate_archive_bytes=14_097,
            raw_comparator_archive_bytes={"raw": 9_901},
            encrypted_comparator_archive_bytes={"encrypted": [20_000] * 11},
        )

        self.assertIs(passed.incompressible, True)
        self.assertEqual(passed.allowance_bytes, 4096)
        self.assertEqual(passed.smallest_encrypted_comparator_id, "encrypted")
        self.assertEqual(passed.smallest_encrypted_comparator_archive_bytes, 10_100)
        self.assertEqual(passed.selected_limit_bytes, 10_100)
        self.assertIs(passed.selected_limit_inclusive, True)
        self.assertIs(passed.passed, True)
        self.assertIs(too_large_for_encrypted.passed, False)
        self.assertEqual(too_large_for_allowance.selected_limit_bytes, 14_096)
        self.assertIs(too_large_for_allowance.passed, False)

    def test_encrypted_size_uses_median_of_eleven_samples(self) -> None:
        distribution = [99_999, 10_003, 10_001, 10_009, 10_008, 10_002]
        distribution += [10_004, 10_005, 10_006, 10_007, 1]
        verdict = evaluate_size_case(
            input_bytes=10_000,
            candidate_archive_bytes=10_005,
            raw_comparator_archive_bytes={"raw": 9_901},
            encrypted_comparator_archive_bytes={"encrypted": distribution},
        )

        self.assertEqual(
            verdict.smallest_encrypted_comparator_archive_bytes,
            10_005,
        )
        self.assertIs(verdict.passed, True)

    def test_comparator_ties_are_resolved_by_identifier(self) -> None:
        verdict = evaluate_size_case(
            input_bytes=10_000,
            candidate_archive_bytes=7_000,
            raw_comparator_archive_bytes={"z-raw": 8_000, "a-raw": 8_000},
            encrypted_comparator_archive_bytes={
                "z-encrypted": [8_000] * 11,
                "a-encrypted": [8_000] * 11,
            },
        )

        self.assertEqual(verdict.best_raw_comparator_id, "a-raw")
        self.assertEqual(verdict.smallest_encrypted_comparator_id, "a-encrypted")
        self.assertEqual(verdict.smallest_comparator_id, "a-encrypted")

    def test_size_case_strictly_validates_sizes_and_mappings(self) -> None:
        cases: tuple[tuple[object, object, object, object], ...] = (
            (True, 1, {"raw": 1}, {"encrypted": [1] * 11}),
            (1, True, {"raw": 1}, {"encrypted": [1] * 11}),
            (1, 1, {}, {"encrypted": [1] * 11}),
            (1, 1, {"raw": 0}, {"encrypted": [1] * 11}),
            (1, 1, {1: 1}, {"encrypted": [1] * 11}),
            (1, 1, {"raw": 1}, {}),
            (1, 1, {"raw": 1}, {1: [1] * 11}),
            (1, 1, {"same": 1}, {"same": [1] * 11}),
            (1, 1, {"raw": 1}, {"encrypted": [1] * 10}),
            (1, 1, {"raw": 1}, {"encrypted": [True] * 11}),
        )
        for input_bytes, candidate, raw, encrypted in cases:
            with (
                self.subTest(
                    input_bytes=input_bytes,
                    candidate=candidate,
                    raw=raw,
                    encrypted=encrypted,
                ),
                self.assertRaises(ValueError),
            ):
                evaluate_size_case(
                    input_bytes=input_bytes,  # type: ignore[arg-type]
                    candidate_archive_bytes=candidate,  # type: ignore[arg-type]
                    raw_comparator_archive_bytes=raw,  # type: ignore[arg-type]
                    encrypted_comparator_archive_bytes=encrypted,  # type: ignore[arg-type]
                )


class TestSyntheticScorecardCase(unittest.TestCase):
    def test_evaluator_recomputes_both_verdicts_from_raw_samples(self) -> None:
        result = evaluate_scorecard_case(_scorecard_payload())

        self.assertIsInstance(result, ScorecardCase)
        self.assertEqual(result.case_id, derive_case_id(_case_identity()))
        self.assertEqual(result.thread_count, 1)
        self.assertEqual(result.fastest_comparator_id, "7zip_raw")
        self.assertEqual(
            tuple(verdict.comparator_id for verdict in result.metric_verdicts),
            BINDING_TOOLS,
        )
        self.assertEqual(result.metric_verdicts[0].candidate_median, 8.0)
        self.assertEqual(result.metric_verdicts[0].paired_median_ratio, 0.8)
        self.assertTrue(all(verdict.passed for verdict in result.metric_verdicts))
        self.assertIs(result.size_verdict.passed, True)
        self.assertIs(result.passed, True)

    def test_evaluator_does_not_accept_claimed_summary_or_pass_fields(self) -> None:
        for field, value in (
            ("passed", True),
            ("metric_passed", True),
            ("candidate_median", 0.0),
            ("comparator_id", "7zip_raw"),
            ("metric_verdicts", []),
        ):
            with self.subTest(field=field):
                payload = _scorecard_payload()
                payload[field] = value
                with self.assertRaisesRegex(ValueError, "keys"):
                    evaluate_scorecard_case(payload)

    def test_evaluator_enforces_contract_identity_and_eligibility(self) -> None:
        cases = (
            ("case_id", "", "case_id"),
            ("case_id", "msc-case-v1-" + "0" * 64, "case_id"),
            ("case_id", "msc-case-v1-" + "0" * 63 + "\n", "case_id"),
            ("case_id", "x" * (MAX_CASE_ID_BYTES + 1), "case_id"),
            ("contract_sha256", "0" * 64, "contract_sha256"),
            ("corpus_manifest_sha256", "A" * 64, "corpus_manifest_sha256"),
            ("corpus_id", 7, "corpus_id"),
            ("corpus_id", "enwik8 text", "corpus_id"),
            ("corpus_id", "x" * 129, "corpus_id"),
            ("input_sha256", "2" * 63, "input_sha256"),
            ("thread_count", True, "thread_count"),
            ("thread_count", 2, "thread_count"),
            ("metric", "cpu_seconds", "metric"),
            ("input_bytes", 67_108_863, "minimum_input_bytes"),
        )
        for field, value, message in cases:
            with self.subTest(field=field, value=value):
                payload = _scorecard_payload()
                payload[field] = value
                with self.assertRaisesRegex(ValueError, message):
                    evaluate_scorecard_case(payload)

    def test_evaluator_requires_all_binding_size_comparators(self) -> None:
        payload = _scorecard_payload()
        raw = payload["raw_comparator_archive_bytes"]
        assert isinstance(raw, dict)
        raw.pop("zstd_raw")
        with self.assertRaisesRegex(ValueError, "raw comparator IDs"):
            evaluate_scorecard_case(payload)

        payload = _scorecard_payload()
        encrypted = payload["encrypted_comparator_archive_bytes"]
        assert isinstance(encrypted, dict)
        encrypted.pop("zstd_age_passphrase")
        with self.assertRaisesRegex(ValueError, "encrypted comparator IDs"):
            evaluate_scorecard_case(payload)

    def test_evaluator_reports_the_lowest_median_comparator_as_diagnostic(self) -> None:
        payload = _scorecard_payload()
        samples = payload["comparator_samples"]
        assert isinstance(samples, dict)
        samples["zstd_raw"] = [9.0] * 11

        result = evaluate_scorecard_case(payload)

        self.assertEqual(result.fastest_comparator_id, "zstd_raw")
        verdicts = {verdict.comparator_id: verdict for verdict in result.metric_verdicts}
        self.assertEqual(verdicts["zstd_raw"].comparator_median, 9.0)

    def test_evaluator_resolves_comparator_metric_ties_by_identifier(self) -> None:
        payload = _scorecard_payload()
        samples = payload["comparator_samples"]
        assert isinstance(samples, dict)
        samples["7zip_aes256_headers"] = [10.0] * 11

        result = evaluate_scorecard_case(payload)

        self.assertEqual(result.fastest_comparator_id, "7zip_aes256_headers")

    def test_every_binding_comparator_must_pass_even_when_fastest_passes(self) -> None:
        payload = _scorecard_payload()
        payload["candidate_samples"] = [100.0] * 6 + [1.0] * 5
        payload["comparator_samples"] = {
            "7zip_raw": [101.0] * 4 + [0.1] * 2 + [2.0] * 5,
            "7zip_aes256_headers": [1000.0] * 11,
            "zstd_raw": [99.0] * 6 + [1000.0] * 5,
            "zstd_age_passphrase": [1000.0] * 11,
        }

        result = evaluate_scorecard_case(payload)
        verdicts = {verdict.comparator_id: verdict for verdict in result.metric_verdicts}

        self.assertEqual(result.fastest_comparator_id, "7zip_raw")
        self.assertLess(verdicts["7zip_raw"].confidence_interval.upper, 1.0)
        self.assertGreaterEqual(verdicts["zstd_raw"].confidence_interval.upper, 1.0)
        self.assertIs(result.size_verdict.passed, True)
        self.assertIs(result.passed, False)

    def test_evaluator_requires_all_binding_metric_comparators(self) -> None:
        payload = _scorecard_payload()
        samples = payload["comparator_samples"]
        assert isinstance(samples, dict)
        samples.pop("zstd_raw")

        with self.assertRaisesRegex(ValueError, "metric comparator IDs"):
            evaluate_scorecard_case(payload)

        for invalid in (None, {name: [1.0] * 10 for name in BINDING_TOOLS}):
            payload = _scorecard_payload()
            payload["comparator_samples"] = invalid
            with (
                self.subTest(invalid=invalid),
                self.assertRaisesRegex(
                    ValueError,
                    "comparator_samples",
                ),
            ):
                evaluate_scorecard_case(payload)

    def test_evaluator_requires_an_object(self) -> None:
        for payload in (None, [], "case"):
            with (
                self.subTest(payload=payload),
                self.assertRaisesRegex(
                    ValueError,
                    "object",
                ),
            ):
                evaluate_scorecard_case(payload)  # type: ignore[arg-type]

    def test_evaluated_case_is_immutable(self) -> None:
        result = evaluate_scorecard_case(_scorecard_payload())

        with self.assertRaises(FrozenInstanceError):
            result.passed = False  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            result.metric_verdicts[0].passed = False  # type: ignore[misc]
        with self.assertRaises(AttributeError):
            result.metric_verdicts.append(result.metric_verdicts[0])  # type: ignore[attr-defined]


if __name__ == "__main__":
    unittest.main()
