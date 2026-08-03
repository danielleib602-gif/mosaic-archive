from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import stat
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest import mock

from mosaic_archive.competitive_contract import (
    BINDING_TOOLS,
    CONTRACT_SHA256,
    METRICS,
    CaseIdentity,
    derive_case_id,
)
from mosaic_archive.competitive_corpus import REQUIRED_CORPUS_IDS
from mosaic_archive.competitive_report import (
    MAX_REPORT_JSON_BYTES,
    CandidateIdentity,
    CompetitiveReport,
    ReportValidationError,
    RunnerIdentity,
    evaluate_competitive_report,
    load_competitive_report,
)

MANIFEST_SHA256 = "1" * 64
BINARY_SHA256 = "2" * 64
RUNNER_POLICY_SHA256 = "3" * 64
HARDWARE_SHA256 = "4" * 64


def _input_sha256(corpus_id: str) -> str:
    return hashlib.sha256(f"prepared:{corpus_id}".encode()).hexdigest()


def _scorecard_case(
    corpus_id: str,
    thread_count: int,
    metric: str,
) -> dict[str, object]:
    identity = CaseIdentity(
        contract_sha256=CONTRACT_SHA256,
        corpus_manifest_sha256=MANIFEST_SHA256,
        corpus_id=corpus_id,
        input_sha256=_input_sha256(corpus_id),
        input_bytes=67_108_864,
        thread_count=thread_count,
        metric=metric,
    )
    memory_metric = metric.endswith("_memory_peak_bytes")
    candidate_value: int | float = 8_000_000 if memory_metric else 8.0
    comparator_values: tuple[int | float, ...] = (
        (10_000_000, 12_000_000, 11_000_000, 13_000_000)
        if memory_metric
        else (10.0, 12.0, 11.0, 13.0)
    )
    return {
        "case_id": derive_case_id(identity),
        "contract_sha256": CONTRACT_SHA256,
        "corpus_manifest_sha256": MANIFEST_SHA256,
        "corpus_id": corpus_id,
        "input_sha256": _input_sha256(corpus_id),
        "thread_count": thread_count,
        "metric": metric,
        "input_bytes": 67_108_864,
        "candidate_archive_bytes": 30_000_000,
        "candidate_samples": [candidate_value] * 11,
        "comparator_samples": {
            comparator_id: [value] * 11
            for comparator_id, value in zip(
                BINDING_TOOLS,
                comparator_values,
                strict=True,
            )
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


def _evidence_sample_id(case_id: str, tool_id: str, run_index: int) -> str:
    return f"{case_id}/{tool_id}/{run_index:02d}"


def _report_payload() -> dict[str, object]:
    cases = [
        _scorecard_case(corpus_id, thread_count, metric)
        for corpus_id in REQUIRED_CORPUS_IDS
        for thread_count in (1, 8)
        for metric in METRICS
    ]
    raw_evidence_index: dict[str, object] = {}
    for case in cases:
        case_id = case["case_id"]
        assert isinstance(case_id, str)
        for tool_id in ("candidate", *BINDING_TOOLS):
            for run_index in range(11):
                sample_id = _evidence_sample_id(case_id, tool_id, run_index)
                digest = hashlib.sha256(sample_id.encode()).hexdigest()
                raw_evidence_index[sample_id] = {
                    "sha256": digest,
                    "url": f"https://evidence.example.invalid/sha256/{digest}.json",
                }
    return {
        "schema_name": "report-v1",
        "contract_sha256": CONTRACT_SHA256,
        "corpus_manifest_sha256": MANIFEST_SHA256,
        "candidate": {
            "archive_format": "MSC7",
            "profile": "adaptive-v1",
            "configuration_id": "msc7-default-v1",
            "native_binary_sha256": BINARY_SHA256,
            "commit_sha": "a" * 40,
            "candidate_tag": "v0.40.0-rc.1",
        },
        "runner": {
            "evidence_class": "development-unverified",
            "runner_policy_sha256": RUNNER_POLICY_SHA256,
            "hardware_fingerprint_sha256": HARDWARE_SHA256,
            "workflow_identity": (
                "github:danielleib602-gif/mosaic-archive:competitive.yml:123456789:1"
            ),
        },
        "cases": cases,
        "raw_evidence_index": raw_evidence_index,
    }


class CompetitiveReportTestCase(unittest.TestCase):
    def load_temporary_payload(
        self,
        payload: object,
        *,
        raw: bytes | None = None,
        max_bytes: int = MAX_REPORT_JSON_BYTES,
    ) -> CompetitiveReport:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            if raw is None:
                path.write_text(json.dumps(payload), encoding="utf-8")
            else:
                path.write_bytes(raw)
            return load_competitive_report(path, max_bytes=max_bytes)


class TestCompetitiveReportEvaluation(CompetitiveReportTestCase):
    _cached_report: CompetitiveReport | None = None

    @classmethod
    def valid_report(cls) -> CompetitiveReport:
        if cls._cached_report is None:
            cls._cached_report = evaluate_competitive_report(_report_payload())
        return cls._cached_report

    def test_recomputes_the_exact_whole_report_matrix(self) -> None:
        report = self.valid_report()

        self.assertIsInstance(report, CompetitiveReport)
        self.assertEqual(report.schema_name, "report-v1")
        self.assertEqual(report.contract_sha256, CONTRACT_SHA256)
        self.assertEqual(report.corpus_manifest_sha256, MANIFEST_SHA256)
        self.assertIsInstance(report.candidate, CandidateIdentity)
        self.assertIsInstance(report.runner, RunnerIdentity)
        self.assertEqual(len(report.cases), 48)
        self.assertEqual(len(report.raw_evidence_index), 48 * 5 * 11)
        self.assertEqual(
            {
                (
                    case.identity.corpus_id,
                    case.identity.thread_count,
                    case.identity.metric,
                )
                for case in report.cases
            },
            {
                (corpus_id, thread_count, metric)
                for corpus_id in REQUIRED_CORPUS_IDS
                for thread_count in (1, 8)
                for metric in METRICS
            },
        )
        self.assertEqual(report.runner.evidence_class, "development-unverified")
        self.assertIs(report.scorecard_passed, True)
        self.assertFalse(hasattr(report, "passed"))
        self.assertIs(report.raw_evidence_verified, False)
        self.assertIs(report.binding_eligible, False)
        self.assertIs(report.release_readiness_eligible, False)

    def test_evaluated_report_and_nested_records_are_immutable(self) -> None:
        report = self.valid_report()

        with self.assertRaises(FrozenInstanceError):
            report.scorecard_passed = False  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            report.raw_evidence_verified = True  # type: ignore[assignment,misc]
        with self.assertRaises(FrozenInstanceError):
            report.binding_eligible = True  # type: ignore[assignment,misc]
        with self.assertRaises(FrozenInstanceError):
            report.release_readiness_eligible = True  # type: ignore[assignment,misc]
        with self.assertRaises(FrozenInstanceError):
            report.candidate.profile = "changed"  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            report.runner.evidence_class = "diagnostic"  # type: ignore[assignment,misc]
        with self.assertRaises(AttributeError):
            report.cases.append(report.cases[0])  # type: ignore[attr-defined]
        with self.assertRaises(AttributeError):
            report.raw_evidence_index.append(  # type: ignore[attr-defined]
                report.raw_evidence_index[0]
            )

    def test_recomputes_failure_instead_of_accepting_a_claim(self) -> None:
        payload = _report_payload()
        cases = payload["cases"]
        assert isinstance(cases, list)
        first = cases[0]
        assert isinstance(first, dict)
        first["candidate_samples"] = [100.0] * 11

        report = evaluate_competitive_report(payload)

        self.assertIs(report.scorecard_passed, False)
        self.assertIs(report.cases[0].passed, False)

    def test_rejects_claimed_passes_and_precomputed_summaries(self) -> None:
        for field, value in (
            ("passed", True),
            ("scorecard_passed", True),
            ("summary", {"passed": True}),
            ("case_count", 48),
            ("raw_evidence_verified", True),
            ("binding_eligible", True),
            ("release_readiness_eligible", True),
        ):
            with self.subTest(field=field):
                payload = _report_payload()
                payload[field] = value
                with self.assertRaisesRegex(ReportValidationError, "keys"):
                    evaluate_competitive_report(payload)

        payload = _report_payload()
        cases = payload["cases"]
        assert isinstance(cases, list)
        first = cases[0]
        assert isinstance(first, dict)
        first["passed"] = True
        with self.assertRaisesRegex(ReportValidationError, "keys"):
            evaluate_competitive_report(payload)

        payload = _report_payload()
        runner = payload["runner"]
        assert isinstance(runner, dict)
        runner["binding_eligible"] = False
        with self.assertRaisesRegex(ReportValidationError, "keys"):
            evaluate_competitive_report(payload)

        payload = _report_payload()
        evidence = payload["raw_evidence_index"]
        assert isinstance(evidence, dict)
        first_reference = next(iter(evidence.values()))
        assert isinstance(first_reference, dict)
        first_reference["verified"] = False
        with self.assertRaisesRegex(ReportValidationError, "keys"):
            evaluate_competitive_report(payload)

    def test_requires_the_exact_case_matrix_without_duplicates(self) -> None:
        payload = _report_payload()
        cases = payload["cases"]
        assert isinstance(cases, list)
        cases.pop()
        with self.assertRaisesRegex(ReportValidationError, "exactly 48"):
            evaluate_competitive_report(payload)

        payload = _report_payload()
        cases = payload["cases"]
        assert isinstance(cases, list)
        cases[-1] = copy.deepcopy(cases[0])
        with self.assertRaisesRegex(ReportValidationError, "duplicate|matrix"):
            evaluate_competitive_report(payload)

        payload = _report_payload()
        cases = payload["cases"]
        assert isinstance(cases, list)
        first = cases[0]
        assert isinstance(first, dict)
        first["corpus_id"] = "unregistered-corpus"
        with self.assertRaisesRegex(ReportValidationError, "corpus|matrix"):
            evaluate_competitive_report(payload)

    def test_binds_every_case_to_report_wide_digests(self) -> None:
        for field, value, message in (
            ("contract_sha256", "0" * 64, "contract_sha256"),
            ("corpus_manifest_sha256", "9" * 64, "corpus_manifest_sha256"),
        ):
            with self.subTest(field=field):
                payload = _report_payload()
                cases = payload["cases"]
                assert isinstance(cases, list)
                first = cases[0]
                assert isinstance(first, dict)
                first[field] = value
                with self.assertRaisesRegex(ReportValidationError, message):
                    evaluate_competitive_report(payload)

    def test_requires_consistent_inputs_and_size_records_for_each_tier(self) -> None:
        mutations = (
            ("input_sha256", "9" * 64),
            ("input_bytes", 67_108_865),
            ("candidate_archive_bytes", 30_000_001),
            ("raw_comparator_archive_bytes", {"7zip_raw": 1, "zstd_raw": 2}),
            (
                "encrypted_comparator_archive_bytes",
                {
                    "7zip_aes256_headers": [33_000_001] * 11,
                    "zstd_age_passphrase": [36_000_000] * 11,
                },
            ),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                payload = _report_payload()
                cases = payload["cases"]
                assert isinstance(cases, list)
                second_metric = cases[1]
                assert isinstance(second_metric, dict)
                second_metric[field] = value
                if field in {"input_sha256", "input_bytes"}:
                    identity = CaseIdentity(
                        contract_sha256=CONTRACT_SHA256,
                        corpus_manifest_sha256=MANIFEST_SHA256,
                        corpus_id=str(second_metric["corpus_id"]),
                        input_sha256=str(second_metric["input_sha256"]),
                        input_bytes=int(second_metric["input_bytes"]),
                        thread_count=int(second_metric["thread_count"]),
                        metric=str(second_metric["metric"]),
                    )
                    second_metric["case_id"] = derive_case_id(identity)
                with self.assertRaisesRegex(ReportValidationError, "inconsistent"):
                    evaluate_competitive_report(payload)

    def test_requires_the_same_prepared_input_at_both_thread_tiers(self) -> None:
        payload = _report_payload()
        cases = payload["cases"]
        assert isinstance(cases, list)
        for eight_thread_case in cases[len(METRICS) : 2 * len(METRICS)]:
            assert isinstance(eight_thread_case, dict)
            eight_thread_case["input_sha256"] = "9" * 64
            identity = CaseIdentity(
                contract_sha256=CONTRACT_SHA256,
                corpus_manifest_sha256=MANIFEST_SHA256,
                corpus_id=str(eight_thread_case["corpus_id"]),
                input_sha256=str(eight_thread_case["input_sha256"]),
                input_bytes=int(eight_thread_case["input_bytes"]),
                thread_count=int(eight_thread_case["thread_count"]),
                metric=str(eight_thread_case["metric"]),
            )
            eight_thread_case["case_id"] = derive_case_id(identity)

        with self.assertRaisesRegex(ReportValidationError, "inconsistent.*corpus"):
            evaluate_competitive_report(payload)

    def test_requires_exact_candidate_and_unverified_development_runner_identity(self) -> None:
        payload = _report_payload()
        candidate = payload["candidate"]
        assert isinstance(candidate, dict)
        candidate["profile"] = "unregistered"
        with self.assertRaisesRegex(ReportValidationError, "candidate.profile"):
            evaluate_competitive_report(payload)

        invalid_candidate_values = (
            ("native_binary_sha256", "A" * 64),
            ("commit_sha", "a" * 39),
            ("candidate_tag", "../latest"),
        )
        for field, value in invalid_candidate_values:
            with self.subTest(field=field):
                payload = _report_payload()
                candidate = payload["candidate"]
                assert isinstance(candidate, dict)
                candidate[field] = value
                with self.assertRaisesRegex(ReportValidationError, field):
                    evaluate_competitive_report(payload)

        invalid_runner_values = (
            ("evidence_class", "binding"),
            ("evidence_class", "diagnostic"),
            ("evidence_class", "unverified"),
            ("runner_policy_sha256", "3" * 63),
            ("hardware_fingerprint_sha256", "4" * 63),
            ("workflow_identity", "workflow identity with spaces"),
            ("workflow_identity", "\ud800"),
        )
        for field, value in invalid_runner_values:
            with self.subTest(field=field):
                payload = _report_payload()
                runner = payload["runner"]
                assert isinstance(runner, dict)
                runner[field] = value
                with self.assertRaisesRegex(ReportValidationError, field):
                    evaluate_competitive_report(payload)

    def test_declared_provenance_and_raw_references_do_not_grant_authority(self) -> None:
        payload = _report_payload()
        runner = payload["runner"]
        assert isinstance(runner, dict)
        runner["runner_policy_sha256"] = "7" * 64
        runner["hardware_fingerprint_sha256"] = "8" * 64
        runner["workflow_identity"] = "local:arbitrary-development-declaration"
        evidence = payload["raw_evidence_index"]
        assert isinstance(evidence, dict)
        first_reference, second_reference = tuple(evidence.values())[:2]
        assert isinstance(first_reference, dict)
        assert isinstance(second_reference, dict)
        first_digest = first_reference["sha256"]
        second_digest = second_reference["sha256"]
        assert isinstance(first_digest, str)
        assert isinstance(second_digest, str)
        first_reference["url"] = f"https://127.0.0.1/sha256/{first_digest}.json"
        second_reference["url"] = f"https://[2001:db8::1]/sha256/{second_digest}.json"

        report = evaluate_competitive_report(payload)

        self.assertEqual(
            report.runner.workflow_identity,
            "local:arbitrary-development-declaration",
        )
        self.assertEqual(len(report.raw_evidence_index), 2_640)
        self.assertIs(report.scorecard_passed, True)
        self.assertIs(report.raw_evidence_verified, False)
        self.assertIs(report.binding_eligible, False)
        self.assertIs(report.release_readiness_eligible, False)

    def test_requires_an_exact_content_addressed_raw_evidence_index(self) -> None:
        payload = _report_payload()
        evidence = payload["raw_evidence_index"]
        assert isinstance(evidence, dict)
        evidence.pop(next(iter(evidence)))
        with self.assertRaisesRegex(ReportValidationError, "raw_evidence_index"):
            evaluate_competitive_report(payload)

        invalid_entries: tuple[tuple[str, object], ...] = (
            ("sha256", "A" * 64),
            ("url", "http://evidence.example.invalid/file.json"),
            ("url", "https://user:secret@evidence.example.invalid/file.json"),
            ("url", "https://evidence .example.invalid/file.json"),
            ("url", "https://evidence.example.invalid/not-content-addressed.json"),
        )
        for field, value in invalid_entries:
            with self.subTest(field=field, value=value):
                payload = _report_payload()
                evidence = payload["raw_evidence_index"]
                assert isinstance(evidence, dict)
                first = next(iter(evidence.values()))
                assert isinstance(first, dict)
                first[field] = value
                with self.assertRaisesRegex(ReportValidationError, field):
                    evaluate_competitive_report(payload)

        payload = _report_payload()
        evidence = payload["raw_evidence_index"]
        assert isinstance(evidence, dict)
        first = next(iter(evidence.values()))
        assert isinstance(first, dict)
        digest = first["sha256"]
        assert isinstance(digest, str)
        first["url"] = f"https://evidence.example.invalid/prefix-{digest}.json"
        with self.assertRaisesRegex(ReportValidationError, "url"):
            evaluate_competitive_report(payload)

        invalid_urls = (
            f"HTTPS://evidence.example.invalid/sha256/{digest}.json",
            f"https://Evidence.example.invalid/sha256/{digest}.json",
            f"https://evidence.example.invalid.:443/sha256/{digest}.json",
            f"https://evidence.example.invalid:443/sha256/{digest}.json",
            f"https://./{digest}.json",
            f"https://../{digest}.json",
            f"https://_bad.example/sha256/{digest}.json",
            f"https://-bad.example/sha256/{digest}.json",
            f"https://bad-.example/sha256/{digest}.json",
            f"https://bad..example/sha256/{digest}.json",
            f"https://999.999.999.999/sha256/{digest}.json",
            f"https://127.000.000.001/sha256/{digest}.json",
            f"https://[0:0:0:0:0:0:0:1]/sha256/{digest}.json",
            f"https://evidence%2eexample.invalid/sha256/{digest}.json",
            f"https://evidence.example.invalid/sha%32%35%36/{digest}.json",
            f"https://evidence.example.invalid\\attacker.invalid/sha256/{digest}.json",
            f"https://evidence.example.invalid/sha256/../{digest}.json",
            f"https://evidence.example.invalid/sha256/./{digest}.json",
            f"https://evidence.example.invalid/sha256//{digest}.json",
            f"https://évidence.example.invalid/sha256/{digest}.json",
            f"https://evidence.example.invalid/sha256/{digest}.json?download=1",
            f"https://evidence.example.invalid/sha256/{digest}.json#fragment",
        )
        for url in invalid_urls:
            with self.subTest(url=url):
                payload = _report_payload()
                evidence = payload["raw_evidence_index"]
                assert isinstance(evidence, dict)
                first = next(iter(evidence.values()))
                assert isinstance(first, dict)
                first["url"] = url
                with self.assertRaisesRegex(ReportValidationError, "url"):
                    evaluate_competitive_report(payload)


class TestCompetitiveReportLoading(CompetitiveReportTestCase):
    def test_loads_strict_bounded_json_and_recomputes_the_result(self) -> None:
        loaded = self.load_temporary_payload(_report_payload())

        self.assertEqual(loaded.schema_name, "report-v1")
        self.assertEqual(len(loaded.cases), 48)
        self.assertIs(loaded.scorecard_passed, True)
        self.assertIs(loaded.raw_evidence_verified, False)
        self.assertIs(loaded.binding_eligible, False)
        self.assertIs(loaded.release_readiness_eligible, False)

    def test_rejects_duplicate_keys_nonfinite_json_and_invalid_utf8(self) -> None:
        duplicate = b'{"schema_name":"report-v1","schema_name":"report-v1"}'
        with self.assertRaisesRegex(ReportValidationError, "duplicate"):
            self.load_temporary_payload({}, raw=duplicate)

        for value in (math.nan, math.inf, -math.inf):
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(ReportValidationError, "non-finite"),
            ):
                self.load_temporary_payload(
                    {},
                    raw=json.dumps({"value": value}).encode(),
                )

        with self.assertRaisesRegex(ReportValidationError, "non-finite"):
            self.load_temporary_payload({}, raw=b'{"value":1e9999}')

        with self.assertRaises(ReportValidationError):
            self.load_temporary_payload(
                {},
                raw=b'{"value":' + b"9" * 5_000 + b"}",
            )

        with self.assertRaisesRegex(ReportValidationError, "UTF-8"):
            self.load_temporary_payload({}, raw=b"\xff")

    def test_rejects_oversized_and_deeply_nested_json(self) -> None:
        with self.assertRaisesRegex(ReportValidationError, "exceeds"):
            self.load_temporary_payload({}, raw=b"{}x", max_bytes=2)

        nested = b"[" * 2_000 + b"0" + b"]" * 2_000
        with self.assertRaisesRegex(ReportValidationError, "deeply nested"):
            self.load_temporary_payload({}, raw=nested)

    def test_accepts_a_report_exactly_at_the_requested_byte_cap(self) -> None:
        raw = json.dumps(_report_payload()).encode("utf-8")

        loaded = self.load_temporary_payload({}, raw=raw, max_bytes=len(raw))

        self.assertIs(loaded.scorecard_passed, True)

    def test_rejects_invalid_max_bytes(self) -> None:
        for value in (True, 0, -1, 1.5, MAX_REPORT_JSON_BYTES + 1):
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(ValueError, "max_bytes"),
            ):
                self.load_temporary_payload({}, max_bytes=value)  # type: ignore[arg-type]

    def test_normalizes_missing_and_non_regular_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            missing = root / "missing.json"
            for path in (missing, root):
                with (
                    self.subTest(path=path),
                    self.assertRaises(ReportValidationError),
                ):
                    load_competitive_report(path)

    def test_rejects_symlinks_where_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.json"
            target.write_bytes(b"{}")
            link = root / "report-link.json"
            try:
                link.symlink_to(target)
            except (NotImplementedError, OSError) as error:
                self.skipTest(f"symlinks unavailable: {error}")

            with self.assertRaisesRegex(ReportValidationError, "regular|safely|stable"):
                load_competitive_report(link)

    def test_rejects_hardlinks_where_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report_path = root / "report.json"
            report_path.write_bytes(b"{}")
            alias = root / "report-alias.json"
            try:
                os.link(report_path, alias)
            except (NotImplementedError, OSError) as error:
                self.skipTest(f"hardlinks unavailable: {error}")

            with self.assertRaisesRegex(ReportValidationError, "single-link|regular|stable"):
                load_competitive_report(report_path)

    def test_rejects_filesystems_without_stable_inode_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            path.write_bytes(b"{}")
            metadata_fields = list(os.lstat(path))
            metadata_fields[stat.ST_INO] = 0
            zero_inode_metadata = os.stat_result(metadata_fields)

            with (
                mock.patch(
                    "mosaic_archive.competitive_report_io.os.lstat",
                    return_value=zero_inode_metadata,
                ),
                self.assertRaisesRegex(ReportValidationError, "regular|stable"),
            ):
                load_competitive_report(path)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFOs are unavailable on this platform")
    def test_rejects_fifo_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fifo = Path(temporary) / "report.fifo"
            os.mkfifo(fifo)  # type: ignore[attr-defined]

            with self.assertRaisesRegex(ReportValidationError, "regular|stable"):
                load_competitive_report(fifo)

    def test_rejects_a_report_mutated_during_descriptor_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            path.write_text(json.dumps(_report_payload()), encoding="utf-8")
            original_read = os.read
            mutated = False

            def read_then_mutate(descriptor: int, count: int) -> bytes:
                nonlocal mutated
                chunk = original_read(descriptor, count)
                if not mutated:
                    metadata = os.stat(path, follow_symlinks=False)
                    os.utime(
                        path,
                        ns=(
                            metadata.st_atime_ns,
                            metadata.st_mtime_ns + 1_000_000_000,
                        ),
                    )
                    mutated = True
                return chunk

            with (
                mock.patch(
                    "mosaic_archive.competitive_report_io.os.read",
                    side_effect=read_then_mutate,
                ),
                self.assertRaisesRegex(ReportValidationError, "changed|stable"),
            ):
                load_competitive_report(path)

            self.assertTrue(mutated)


if __name__ == "__main__":
    unittest.main()
