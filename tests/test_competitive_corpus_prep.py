from __future__ import annotations

import hashlib
import json
import os
import pickle
import tempfile
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from typing import Any
from unittest import mock

import mosaic_archive.competitive_corpus_prep as corpus_prep
from mosaic_archive.competitive_corpus import REQUIRED_CORPUS_IDS
from mosaic_archive.competitive_corpus_prep import (
    COPY_RECIPE_ID,
    COPY_RECIPE_IMPLEMENTATION_SHA256,
    COPY_RECIPE_VERSION,
    EXPECTED_PLAN_ID,
    MAX_JSON_INTEGER_DIGITS,
    MAX_JSON_NESTING,
    AcquisitionPlanValidationError,
    CompetitiveAcquisitionPlan,
    CorpusPreparationCleanupError,
    CorpusPreparationError,
    CorpusPublicationDurabilityError,
    CorpusPublicationNameUnavailableError,
    CorpusPublicationOutcomeUnknownError,
    load_acquisition_plan,
    prepare_local_source,
    reopen_prepared_local_corpus,
    reopen_verified_local_source,
    verify_local_source,
)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _blocked_descriptor(corpus_id: str) -> dict[str, object]:
    return {
        "id": corpus_id,
        "status": "blocked",
        "blocked_reason": "Source identity and external approvals are not complete.",
        "source_url": None,
        "expected_source_bytes": None,
        "expected_source_sha256": None,
        "input_kind": "single_file",
        "recipe": {
            "id": COPY_RECIPE_ID,
            "version": COPY_RECIPE_VERSION,
            "implementation_sha256": COPY_RECIPE_IMPLEMENTATION_SHA256,
        },
        "member_manifest_sha256": None,
        "license_evidence_sha256": None,
        "benchmark_use_approved": False,
        "redistribution_approved": False,
        "approval_record": None,
    }


def _runnable_descriptor(corpus_id: str, source: bytes) -> dict[str, object]:
    source_sha256 = _digest(source)
    approval_sha256 = _digest(f"approval:{corpus_id}".encode())
    return {
        "id": corpus_id,
        "status": "runnable",
        "blocked_reason": None,
        "source_url": (f"https://datasets.example.test/sha256/{source_sha256}/{corpus_id}.bin"),
        "expected_source_bytes": len(source),
        "expected_source_sha256": source_sha256,
        "input_kind": "single_file",
        "recipe": {
            "id": COPY_RECIPE_ID,
            "version": COPY_RECIPE_VERSION,
            "implementation_sha256": COPY_RECIPE_IMPLEMENTATION_SHA256,
        },
        "member_manifest_sha256": None,
        "license_evidence_sha256": _digest(f"license:{corpus_id}".encode()),
        "benchmark_use_approved": True,
        "redistribution_approved": True,
        "approval_record": {
            "identity": f"sha256:{approval_sha256}",
            "sha256": approval_sha256,
        },
    }


def _plan(
    *,
    runnable_id: str | None = None,
    source: bytes = b"competitive corpus bytes",
) -> dict[str, object]:
    corpora = [_blocked_descriptor(corpus_id) for corpus_id in REQUIRED_CORPUS_IDS]
    if runnable_id is not None:
        index = REQUIRED_CORPUS_IDS.index(runnable_id)
        corpora[index] = _runnable_descriptor(runnable_id, source)
    return {
        "schema_version": 1,
        "plan_id": EXPECTED_PLAN_ID,
        "binding": False,
        "corpora": corpora,
    }


def _write_json(path: Path, payload: object) -> bytes:
    raw = (json.dumps(payload, indent=2) + "\n").encode()
    path.write_bytes(raw)
    return raw


def _write_plan(
    root: Path,
    payload: object | None = None,
) -> Path:
    path = root / "acquisition-plan.json"
    _write_json(path, _plan() if payload is None else payload)
    return path


def _descriptor(
    payload: dict[str, object],
    index: int = 0,
) -> dict[str, Any]:
    corpora = payload["corpora"]
    assert isinstance(corpora, list)
    result = corpora[index]
    assert isinstance(result, dict)
    return result


class AcquisitionPlanLoadingTests(unittest.TestCase):
    def test_repository_plan_is_strict_non_binding_and_explicitly_blocked(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        plan = load_acquisition_plan(
            repository_root / "benchmarks" / "competitive-v1" / "acquisition-plan.json"
        )

        self.assertIsInstance(plan, CompetitiveAcquisitionPlan)
        self.assertFalse(plan.binding)
        self.assertEqual(
            tuple(descriptor.id for descriptor in plan.corpora),
            REQUIRED_CORPUS_IDS,
        )
        self.assertTrue(all(descriptor.status == "blocked" for descriptor in plan.corpora))
        self.assertTrue(all(descriptor.blocked_reason for descriptor in plan.corpora))

    def test_loads_exact_schema_and_binds_result_to_raw_plan_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "plan.json"
            raw = _write_json(path, _plan())

            plan = load_acquisition_plan(path)

        self.assertEqual(plan.schema_version, 1)
        self.assertEqual(plan.plan_id, EXPECTED_PLAN_ID)
        self.assertFalse(plan.binding)
        self.assertEqual(plan.plan_sha256, _digest(raw))
        self.assertEqual(plan.corpora[0].recipe.id, COPY_RECIPE_ID)

    def test_values_are_frozen_slotted_and_deeply_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            plan = load_acquisition_plan(_write_plan(Path(temp_dir)))

        values = (
            plan,
            plan.corpora[0],
            plan.corpora[0].recipe,
            plan.corpora[0].unverified_approval_claims,
        )
        self.assertTrue(all(not hasattr(value, "__dict__") for value in values))
        with self.assertRaises(FrozenInstanceError):
            plan.binding = True  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            plan.corpora[0].status = "unverified_technical_copy"  # type: ignore[misc]
        with self.assertRaises(AttributeError):
            plan.corpora.append(plan.corpora[0])  # type: ignore[attr-defined]

    def test_rejects_missing_extra_and_nested_schema_keys(self) -> None:
        mutations = (
            ("top missing", lambda payload: payload.pop("binding")),
            ("top extra", lambda payload: payload.update(extra=True)),
            ("descriptor missing", lambda payload: _descriptor(payload).pop("source_url")),
            ("descriptor extra", lambda payload: _descriptor(payload).update(extra=True)),
            (
                "recipe missing",
                lambda payload: _descriptor(payload)["recipe"].pop("version"),
            ),
            (
                "recipe extra",
                lambda payload: _descriptor(payload)["recipe"].update(extra=True),
            ),
        )
        for name, mutate in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp_dir:
                payload = _plan()
                mutate(payload)
                with self.assertRaisesRegex(AcquisitionPlanValidationError, "keys"):
                    load_acquisition_plan(_write_plan(Path(temp_dir), payload))

    def test_rejects_duplicate_keys_non_finite_values_floats_and_invalid_utf8(self) -> None:
        invalid_documents = (
            b'{"schema_version":1,"schema_version":1}',
            b'{"schema_version":NaN}',
            b'{"schema_version":1.0}',
            b"\xff",
            b"\xef\xbb\xbf{}",
        )
        for raw in invalid_documents:
            with self.subTest(raw=raw[:30]), tempfile.TemporaryDirectory() as temp_dir:
                path = Path(temp_dir) / "plan.json"
                path.write_bytes(raw)
                with self.assertRaises(AcquisitionPlanValidationError):
                    load_acquisition_plan(path)

    def test_oversized_json_integer_uses_plan_validation_error_contract(self) -> None:
        oversized_integer = b"9" * (max(4_301, MAX_JSON_INTEGER_DIGITS + 1))
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "plan.json"
            path.write_bytes(b'{"schema_version":' + oversized_integer + b"}")
            with self.assertRaisesRegex(
                AcquisitionPlanValidationError,
                "integer",
            ):
                load_acquisition_plan(path)

    def test_escaped_lone_surrogate_uses_plan_validation_error_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            payload = _plan()
            _descriptor(payload)["blocked_reason"] = "\ud800"
            with self.assertRaisesRegex(
                AcquisitionPlanValidationError,
                "canonical string",
            ):
                load_acquisition_plan(_write_plan(Path(temp_dir), payload))

    def test_json_nesting_is_bounded_and_recursion_errors_are_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "plan.json"
            path.write_bytes(b"[" * (MAX_JSON_NESTING + 1) + b"0" + b"]" * (MAX_JSON_NESTING + 1))
            with self.assertRaisesRegex(
                AcquisitionPlanValidationError,
                "nesting",
            ):
                load_acquisition_plan(path)

        with tempfile.TemporaryDirectory() as temp_dir:
            path = _write_plan(Path(temp_dir))
            with (
                mock.patch.object(
                    corpus_prep.json,
                    "loads",
                    side_effect=RecursionError("parser recursion"),
                ),
                self.assertRaisesRegex(
                    AcquisitionPlanValidationError,
                    "nesting",
                ) as raised,
            ):
                load_acquisition_plan(path)
            self.assertIsInstance(raised.exception.__cause__, RecursionError)

    def test_read_is_strictly_bounded_and_limit_rejects_bool(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = _write_plan(Path(temp_dir))
            size = path.stat().st_size
            self.assertEqual(
                load_acquisition_plan(path, max_bytes=size).plan_id,
                EXPECTED_PLAN_ID,
            )
            with self.assertRaisesRegex(AcquisitionPlanValidationError, "exceeds"):
                load_acquisition_plan(path, max_bytes=size - 1)
            for invalid_limit in (True, 0, -1, corpus_prep.MAX_PLAN_BYTES + 1):
                with (
                    self.subTest(invalid_limit=invalid_limit),
                    self.assertRaisesRegex(
                        AcquisitionPlanValidationError,
                        "max_bytes",
                    ),
                ):
                    load_acquisition_plan(path, max_bytes=invalid_limit)

    def test_plan_read_tolerates_only_windows_ctime_drift(self) -> None:
        class StatWithCtime:
            def __init__(self, base: os.stat_result, ctime_ns: int) -> None:
                self._base = base
                self.st_ctime_ns = ctime_ns

            def __getattr__(self, name: str) -> Any:
                return getattr(self._base, name)

        def exercise(*, emulate_windows: bool) -> None:
            with tempfile.TemporaryDirectory() as temp_dir:
                path = _write_plan(Path(temp_dir))
                real_fstat = os.fstat
                fstat_calls = 0

                def drift_ctime(descriptor: int) -> Any:
                    nonlocal fstat_calls
                    metadata = real_fstat(descriptor)
                    fstat_calls += 1
                    if fstat_calls == 1:
                        return metadata
                    return StatWithCtime(
                        metadata,
                        metadata.st_ctime_ns + fstat_calls,
                    )

                with (
                    mock.patch.object(
                        corpus_prep,
                        "_WINDOWS_PLAN_CTIME_UNSTABLE",
                        emulate_windows,
                    ),
                    mock.patch.object(
                        corpus_prep.os,
                        "fstat",
                        side_effect=drift_ctime,
                    ),
                ):
                    if emulate_windows:
                        self.assertEqual(
                            load_acquisition_plan(path).plan_id,
                            EXPECTED_PLAN_ID,
                        )
                    else:
                        with self.assertRaisesRegex(
                            AcquisitionPlanValidationError,
                            "changed while it was being read",
                        ):
                            load_acquisition_plan(path)

        exercise(emulate_windows=True)
        exercise(emulate_windows=False)

    def test_plan_read_rejects_byte_and_mtime_mutation_between_exact_reads(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = _write_plan(Path(temp_dir))
            original = path.read_bytes()
            expected_id = EXPECTED_PLAN_ID.encode()
            mutated_id = b"x" + expected_id[1:]
            mutated = original.replace(expected_id, mutated_id)
            self.assertEqual(len(mutated), len(original))
            real_fstat = os.fstat
            fstat_calls = 0

            def mutate_after_first_read(descriptor: int) -> os.stat_result:
                nonlocal fstat_calls
                metadata = real_fstat(descriptor)
                fstat_calls += 1
                if fstat_calls == 2:
                    path.write_bytes(mutated)
                return metadata

            with (
                mock.patch.object(
                    corpus_prep.os,
                    "fstat",
                    side_effect=mutate_after_first_read,
                ),
                self.assertRaisesRegex(
                    AcquisitionPlanValidationError,
                    "two exact bounded reads",
                ),
            ):
                load_acquisition_plan(path)
            self.assertEqual(path.read_bytes(), mutated)

    def test_rejects_symlink_and_hardlinked_plan_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = _write_plan(root)
            link = root / "link.json"
            try:
                link.symlink_to(target)
            except OSError as exc:
                self.skipTest(f"symlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(AcquisitionPlanValidationError, "regular file"):
                load_acquisition_plan(link)

            hardlink = root / "hardlink.json"
            try:
                os.link(target, hardlink)
            except OSError as exc:
                self.skipTest(f"hardlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(AcquisitionPlanValidationError, "hardlink"):
                load_acquisition_plan(target)

    @unittest.skipUnless(
        callable(getattr(os, "mkfifo", None)),
        "FIFO creation is unavailable",
    )
    def test_plan_open_is_nonblocking_when_a_regular_file_is_swapped_for_fifo(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = _write_plan(Path(temp_dir))
            real_open = os.open
            swapped = False

            def swap_before_open(
                target: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal swapped
                if not swapped and os.fspath(target) == os.fspath(path):
                    path.unlink()
                    os.mkfifo(path)
                    swapped = True
                    self.assertTrue(flags & os.O_NONBLOCK)
                return real_open(target, flags, mode, dir_fd=dir_fd)

            with (
                mock.patch.object(
                    corpus_prep.os,
                    "open",
                    side_effect=swap_before_open,
                ),
                self.assertRaisesRegex(
                    AcquisitionPlanValidationError,
                    "changed|regular file",
                ),
            ):
                load_acquisition_plan(path)
            self.assertTrue(swapped)

    def test_requires_exact_non_binding_header_and_canonical_corpus_ids(self) -> None:
        cases: tuple[tuple[str, object], ...] = (
            ("schema_version", True),
            ("schema_version", 2),
            ("plan_id", "another-plan"),
            ("binding", True),
            ("binding", 0),
            ("corpora", {}),
        )
        for field, value in cases:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temp_dir:
                payload = _plan()
                payload[field] = value
                with self.assertRaises(AcquisitionPlanValidationError):
                    load_acquisition_plan(_write_plan(Path(temp_dir), payload))

        for mutation in ("missing", "duplicate", "unknown"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp_dir:
                payload = _plan()
                corpora = payload["corpora"]
                assert isinstance(corpora, list)
                if mutation == "missing":
                    corpora.pop()
                elif mutation == "duplicate":
                    corpora[-1]["id"] = corpora[0]["id"]
                else:
                    corpora[-1]["id"] = "unknown-corpus"
                with self.assertRaisesRegex(AcquisitionPlanValidationError, "corpus IDs"):
                    load_acquisition_plan(_write_plan(Path(temp_dir), payload))

    def test_blocked_entries_require_reason_but_may_keep_unknown_fields_null(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            plan = load_acquisition_plan(_write_plan(Path(temp_dir)))
        descriptor = plan.corpora[0]
        self.assertEqual(descriptor.status, "blocked")
        self.assertIsNone(descriptor.source_url)
        self.assertIsNone(descriptor.expected_source_bytes)
        self.assertIsNone(descriptor.expected_source_sha256)
        self.assertIsNone(descriptor.license_evidence_sha256_claim)
        claims = descriptor.unverified_approval_claims
        self.assertFalse(claims.benchmark_use_claim)
        self.assertFalse(claims.redistribution_claim)
        self.assertIsNone(claims.record_claim)
        self.assertFalse(claims.externally_verified)
        self.assertFalse(claims.binding)

        for reason in (None, "", "   ", "bad\nreason", 7):
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as temp_dir:
                payload = _plan()
                _descriptor(payload)["blocked_reason"] = reason
                with self.assertRaisesRegex(
                    AcquisitionPlanValidationError,
                    "blocked_reason",
                ):
                    load_acquisition_plan(_write_plan(Path(temp_dir), payload))

    def test_runnable_entries_fail_closed_until_every_identity_is_complete(self) -> None:
        corpus_id = REQUIRED_CORPUS_IDS[0]
        source = b"runnable corpus"
        mutations = (
            ("source_url", None, "source_url"),
            ("expected_source_bytes", None, "expected_source_bytes"),
            ("expected_source_bytes", True, "expected_source_bytes"),
            ("expected_source_sha256", None, "expected_source_sha256"),
            ("license_evidence_sha256", None, "license_evidence_sha256"),
            ("benchmark_use_approved", False, "benchmark_use_approved"),
            ("redistribution_approved", False, "redistribution_approved"),
            ("approval_record", None, "approval_record"),
            ("blocked_reason", "still blocked", "blocked_reason"),
        )
        for field, value, message in mutations:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temp_dir:
                payload = _plan(runnable_id=corpus_id, source=source)
                _descriptor(payload)[field] = value
                with self.assertRaisesRegex(AcquisitionPlanValidationError, message):
                    load_acquisition_plan(_write_plan(Path(temp_dir), payload))

    def test_runnable_json_is_only_an_unverified_technical_copy_claim(self) -> None:
        corpus_id = REQUIRED_CORPUS_IDS[0]
        with tempfile.TemporaryDirectory() as temp_dir:
            plan = load_acquisition_plan(
                _write_plan(
                    Path(temp_dir),
                    _plan(runnable_id=corpus_id, source=b"technical input"),
                )
            )

        descriptor = plan.corpora[0]
        self.assertEqual(descriptor.status, "unverified_technical_copy")
        self.assertFalse(hasattr(descriptor, "benchmark_use_approved"))
        self.assertFalse(hasattr(descriptor, "redistribution_approved"))
        self.assertFalse(hasattr(descriptor, "approval_record"))
        claims = descriptor.unverified_approval_claims
        self.assertTrue(claims.benchmark_use_claim)
        self.assertTrue(claims.redistribution_claim)
        self.assertFalse(claims.externally_verified)
        self.assertFalse(claims.binding)
        self.assertIsNotNone(claims.record_claim)
        assert claims.record_claim is not None
        self.assertFalse(claims.record_claim.externally_verified)
        self.assertFalse(claims.record_claim.binding)
        self.assertFalse(plan.binding)

    def test_blocked_entry_cannot_claim_unbound_external_approval(self) -> None:
        for approval_field in (
            "benchmark_use_approved",
            "redistribution_approved",
        ):
            with (
                self.subTest(approval_field=approval_field),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                payload = _plan()
                _descriptor(payload)[approval_field] = True
                with self.assertRaisesRegex(
                    AcquisitionPlanValidationError,
                    "approval_record",
                ):
                    load_acquisition_plan(_write_plan(Path(temp_dir), payload))

    def test_runnable_source_url_is_https_and_hash_bound(self) -> None:
        corpus_id = REQUIRED_CORPUS_IDS[0]
        source = b"runnable corpus"
        urls = (
            "http://datasets.example.test/source.bin",
            "https:///missing-host",
            "https://user:secret@example.test/source.bin",
            "https://datasets.example.test/source.bin?token=secret",
            "https://datasets.example.test/source.bin#moving",
            "https://datasets.example.test/not-the-expected-hash/source.bin",
        )
        for url in urls:
            with self.subTest(url=url), tempfile.TemporaryDirectory() as temp_dir:
                payload = _plan(runnable_id=corpus_id, source=source)
                _descriptor(payload)["source_url"] = url
                with self.assertRaisesRegex(
                    AcquisitionPlanValidationError,
                    "source_url",
                ):
                    load_acquisition_plan(_write_plan(Path(temp_dir), payload))

    def test_recipe_and_approval_record_are_exact_and_hash_bound(self) -> None:
        corpus_id = REQUIRED_CORPUS_IDS[0]
        source = b"runnable corpus"
        mutations = (
            (
                lambda entry: entry["recipe"].update(id="another-recipe"),
                "recipe.id",
            ),
            (
                lambda entry: entry["recipe"].update(version=True),
                "recipe.version",
            ),
            (
                lambda entry: entry["recipe"].update(implementation_sha256="0" * 64),
                "implementation_sha256",
            ),
            (
                lambda entry: entry["approval_record"].update(extra=True),
                "keys",
            ),
            (
                lambda entry: entry["approval_record"].update(identity="approval-latest"),
                "hash-bound",
            ),
            (
                lambda entry: entry["approval_record"].update(sha256="A" * 64),
                "sha256",
            ),
        )
        for mutate, message in mutations:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as temp_dir:
                payload = _plan(runnable_id=corpus_id, source=source)
                mutate(_descriptor(payload))
                with self.assertRaisesRegex(AcquisitionPlanValidationError, message):
                    load_acquisition_plan(_write_plan(Path(temp_dir), payload))

    def test_aggregate_runnable_input_requires_member_manifest_identity(self) -> None:
        corpus_id = REQUIRED_CORPUS_IDS[0]
        source = b"aggregate bundle"
        with tempfile.TemporaryDirectory() as temp_dir:
            payload = _plan(runnable_id=corpus_id, source=source)
            entry = _descriptor(payload)
            entry["input_kind"] = "aggregate_bundle"
            with self.assertRaisesRegex(
                AcquisitionPlanValidationError,
                "member_manifest_sha256",
            ):
                load_acquisition_plan(_write_plan(Path(temp_dir), payload))

            entry["member_manifest_sha256"] = _digest(b"member manifest")
            plan = load_acquisition_plan(_write_plan(Path(temp_dir), payload))
            self.assertEqual(
                plan.corpora[0].member_manifest_sha256,
                _digest(b"member manifest"),
            )

    def test_single_file_rejects_misleading_member_manifest_identity(self) -> None:
        corpus_id = REQUIRED_CORPUS_IDS[0]
        with tempfile.TemporaryDirectory() as temp_dir:
            payload = _plan(runnable_id=corpus_id)
            _descriptor(payload)["member_manifest_sha256"] = _digest(b"unused")
            with self.assertRaisesRegex(
                AcquisitionPlanValidationError,
                "single_file",
            ):
                load_acquisition_plan(_write_plan(Path(temp_dir), payload))

    def test_invalid_text_hash_size_boolean_and_input_types_are_rejected(self) -> None:
        cases = (
            ("id", "bad id", "id"),
            ("status", "latest", "status"),
            ("source_url", 1, "source_url"),
            ("expected_source_bytes", -1, "expected_source_bytes"),
            ("expected_source_sha256", "A" * 64, "expected_source_sha256"),
            ("input_kind", "archive", "input_kind"),
            ("license_evidence_sha256", "0" * 63, "license_evidence_sha256"),
            ("benchmark_use_approved", 1, "benchmark_use_approved"),
            ("redistribution_approved", None, "redistribution_approved"),
        )
        for field, value, message in cases:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temp_dir:
                payload = _plan()
                _descriptor(payload)[field] = value
                with self.assertRaisesRegex(AcquisitionPlanValidationError, message):
                    load_acquisition_plan(_write_plan(Path(temp_dir), payload))


@unittest.skipUnless(
    corpus_prep.secure_local_preparation_supported(),
    "host lacks atomic no-follow local preparation support",
)
class LocalSourcePreparationTests(unittest.TestCase):
    def _runnable_fixture(
        self,
        root: Path,
        source: bytes,
        *,
        corpus_id: str = REQUIRED_CORPUS_IDS[0],
    ) -> tuple[Path, Path]:
        plan_path = _write_plan(
            root,
            _plan(runnable_id=corpus_id, source=source),
        )
        source_path = root / "source.bin"
        source_path.write_bytes(source)
        return plan_path, source_path

    def test_verifies_expected_bytes_and_digest_from_one_open_file(self) -> None:
        source = b"verified source" * 100
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path, source_path = self._runnable_fixture(root, source)

            verified = verify_local_source(
                plan_path,
                REQUIRED_CORPUS_IDS[0],
                source_path,
            )

            self.assertEqual(verified.display_path, source_path)
            self.assertFalse(hasattr(verified, "path"))
            self.assertEqual(verified.bytes, len(source))
            self.assertEqual(verified.sha256, _digest(source))
            self.assertEqual(verified.identity.file_device, source_path.stat().st_dev)
            self.assertEqual(verified.identity.file_inode, source_path.stat().st_ino)
            self.assertEqual(verified.identity.parent_device, root.stat().st_dev)
            self.assertEqual(verified.identity.parent_inode, root.stat().st_ino)
            self.assertFalse(verified.binding)

            reopened = reopen_verified_local_source(verified)
            try:
                self.assertEqual(os.read(reopened, len(source) + 1), source)
            finally:
                os.close(reopened)

    def test_verification_reads_in_bounded_chunks(self) -> None:
        source = b"x" * (corpus_prep.READ_CHUNK_BYTES * 2 + 17)
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path, source_path = self._runnable_fixture(root, source)
            real_read = os.read
            requested: list[int] = []

            def tracking_read(descriptor: int, size: int) -> bytes:
                requested.append(size)
                return real_read(descriptor, size)

            with mock.patch.object(corpus_prep.os, "read", side_effect=tracking_read):
                verify_local_source(plan_path, REQUIRED_CORPUS_IDS[0], source_path)

        self.assertTrue(requested)
        self.assertLessEqual(max(requested), corpus_prep.READ_CHUNK_BYTES)

    def test_rejects_blocked_descriptor_before_opening_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path = _write_plan(root)
            source_path = root / "source.bin"
            source_path.write_bytes(b"source")
            with (
                mock.patch.object(
                    corpus_prep,
                    "_open_regular_path_secure",
                    wraps=corpus_prep._open_regular_path_secure,
                ) as opener,
                self.assertRaisesRegex(CorpusPreparationError, "blocked"),
            ):
                verify_local_source(plan_path, REQUIRED_CORPUS_IDS[0], source_path)
            opener.assert_not_called()

    def test_rejects_wrong_source_size_and_digest(self) -> None:
        source = b"expected source"
        for mutation, message in ((b"short", "size"), (b"x" * len(source), "SHA-256")):
            with self.subTest(message=message), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir).resolve(strict=True)
                plan_path, source_path = self._runnable_fixture(root, source)
                source_path.write_bytes(mutation)
                with self.assertRaisesRegex(CorpusPreparationError, message):
                    verify_local_source(plan_path, REQUIRED_CORPUS_IDS[0], source_path)

    def test_rejects_symlinked_components_and_hardlinked_sources(self) -> None:
        source = b"source identity"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path, source_path = self._runnable_fixture(root, source)
            linked_source = root / "linked-source.bin"
            try:
                linked_source.symlink_to(source_path)
            except OSError as exc:
                self.skipTest(f"symlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(CorpusPreparationError, "symlink"):
                verify_local_source(plan_path, REQUIRED_CORPUS_IDS[0], linked_source)

            hardlink = root / "hardlink.bin"
            os.link(source_path, hardlink)
            with self.assertRaisesRegex(CorpusPreparationError, "hardlink"):
                verify_local_source(plan_path, REQUIRED_CORPUS_IDS[0], source_path)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path = _write_plan(
                root,
                _plan(runnable_id=REQUIRED_CORPUS_IDS[0], source=source),
            )
            real_parent = root / "real"
            real_parent.mkdir()
            (real_parent / "source.bin").write_bytes(source)
            linked_parent = root / "linked-parent"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaisesRegex(CorpusPreparationError, "symlink"):
                verify_local_source(
                    plan_path,
                    REQUIRED_CORPUS_IDS[0],
                    linked_parent / "source.bin",
                )

    def test_secure_source_reopen_rejects_same_content_path_swap(self) -> None:
        source = b"same bytes do not preserve inode authority"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path, source_path = self._runnable_fixture(root, source)
            verified = verify_local_source(
                plan_path,
                REQUIRED_CORPUS_IDS[0],
                source_path,
            )

            source_path.rename(root / "displaced-source.bin")
            source_path.write_bytes(source)
            self.assertEqual(source_path.read_bytes(), source)
            with self.assertRaisesRegex(CorpusPreparationError, "verified inode"):
                reopen_verified_local_source(verified)

    def test_secure_source_reopen_rejects_renamed_and_recreated_parent(self) -> None:
        source = b"parent directory identity is authoritative"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path = _write_plan(
                root,
                _plan(runnable_id=REQUIRED_CORPUS_IDS[0], source=source),
            )
            source_parent = root / "source-parent"
            source_parent.mkdir()
            source_path = source_parent / "source.bin"
            source_path.write_bytes(source)
            verified = verify_local_source(
                plan_path,
                REQUIRED_CORPUS_IDS[0],
                source_path,
            )

            source_parent.rename(root / "moved-source-parent")
            source_parent.mkdir()
            (source_parent / "source.bin").write_bytes(source)
            with self.assertRaisesRegex(CorpusPreparationError, "parent path"):
                reopen_verified_local_source(verified)

    @unittest.skipUnless(
        callable(getattr(os, "mkfifo", None)),
        "FIFO creation is unavailable",
    )
    def test_source_and_reopen_fifo_paths_are_opened_nonblocking(self) -> None:
        source = b"fifo swaps must not block"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path, source_path = self._runnable_fixture(root, source)
            source_path.unlink()
            os.mkfifo(source_path)
            source_flags: list[int] = []
            real_regular_flags = corpus_prep._regular_read_flags

            def track_source_flags() -> int:
                flags = real_regular_flags()
                source_flags.append(flags)
                return flags

            with (
                mock.patch.object(
                    corpus_prep,
                    "_regular_read_flags",
                    side_effect=track_source_flags,
                ),
                self.assertRaisesRegex(CorpusPreparationError, "regular file"),
            ):
                verify_local_source(
                    plan_path,
                    REQUIRED_CORPUS_IDS[0],
                    source_path,
                )
            self.assertTrue(source_flags)
            self.assertTrue(all(flags & os.O_NONBLOCK for flags in source_flags))

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path, source_path = self._runnable_fixture(root, source)
            verified = verify_local_source(
                plan_path,
                REQUIRED_CORPUS_IDS[0],
                source_path,
            )
            source_path.unlink()
            os.mkfifo(source_path)
            reopen_flags: list[int] = []
            real_regular_flags = corpus_prep._regular_read_flags

            def track_reopen_flags() -> int:
                flags = real_regular_flags()
                reopen_flags.append(flags)
                return flags

            with (
                mock.patch.object(
                    corpus_prep,
                    "_regular_read_flags",
                    side_effect=track_reopen_flags,
                ),
                self.assertRaisesRegex(CorpusPreparationError, "regular file"),
            ):
                reopen_verified_local_source(verified)
            self.assertTrue(reopen_flags)
            self.assertTrue(all(flags & os.O_NONBLOCK for flags in reopen_flags))

    def test_reopen_returns_sealed_snapshot_immune_to_later_source_mutation(
        self,
    ) -> None:
        import fcntl

        source = b"immutable snapshot source"
        replacement = b"X" * len(source)
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path, source_path = self._runnable_fixture(root, source)
            verified = verify_local_source(
                plan_path,
                REQUIRED_CORPUS_IDS[0],
                source_path,
            )
            writer = os.open(source_path, os.O_RDWR)
            real_seal = corpus_prep._seal_snapshot_fd

            def mutate_source_then_seal(snapshot: int) -> None:
                self.assertEqual(os.pwrite(writer, replacement, 0), len(replacement))
                real_seal(snapshot)

            try:
                with mock.patch.object(
                    corpus_prep,
                    "_seal_snapshot_fd",
                    side_effect=mutate_source_then_seal,
                ):
                    snapshot = reopen_verified_local_source(verified)
            finally:
                os.close(writer)

            duplicate = os.dup(snapshot)
            try:
                self.assertEqual(os.read(snapshot, len(source) + 1), source)
                self.assertEqual(source_path.read_bytes(), replacement)
                _add_seals, _get_seals, required = corpus_prep._snapshot_sealing_constants()
                self.assertEqual(
                    fcntl.fcntl(snapshot, fcntl.F_GET_SEALS) & required,
                    required,
                )
                for descriptor in (snapshot, duplicate):
                    with self.assertRaises(OSError):
                        os.pwrite(descriptor, b"!", 0)
                    with self.assertRaises(OSError):
                        os.ftruncate(descriptor, 0)
            finally:
                os.close(duplicate)
                os.close(snapshot)

    def test_prepared_reopen_snapshot_is_immune_to_later_output_mutation(
        self,
    ) -> None:
        source = b"immutable prepared snapshot"
        replacement = b"Y" * len(source)
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path, source_path = self._runnable_fixture(root, source)
            output_path = root / "prepared.bin"
            prepared = prepare_local_source(
                plan_path,
                REQUIRED_CORPUS_IDS[0],
                source_path,
                output_path,
            )
            writer = os.open(output_path, os.O_RDWR)
            real_seal = corpus_prep._seal_snapshot_fd

            def mutate_output_then_seal(snapshot: int) -> None:
                self.assertEqual(os.pwrite(writer, replacement, 0), len(replacement))
                real_seal(snapshot)

            try:
                with mock.patch.object(
                    corpus_prep,
                    "_seal_snapshot_fd",
                    side_effect=mutate_output_then_seal,
                ):
                    snapshot = reopen_prepared_local_corpus(prepared)
            finally:
                os.close(writer)

            duplicate = os.dup(snapshot)
            try:
                self.assertEqual(os.read(snapshot, len(source) + 1), source)
                self.assertEqual(output_path.read_bytes(), replacement)
                for descriptor in (snapshot, duplicate):
                    with self.assertRaises(OSError):
                        os.pwrite(descriptor, b"!", 0)
                    with self.assertRaises(OSError):
                        os.ftruncate(descriptor, 0)
            finally:
                os.close(duplicate)
                os.close(snapshot)

    def test_snapshot_tampering_at_seal_boundary_is_detected_after_sealing(
        self,
    ) -> None:
        source = b"post-seal hash is authoritative"
        tampered = b"Z" * len(source)
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path, source_path = self._runnable_fixture(root, source)
            verified = verify_local_source(
                plan_path,
                REQUIRED_CORPUS_IDS[0],
                source_path,
            )
            real_seal = corpus_prep._seal_snapshot_fd

            def tamper_then_seal(snapshot: int) -> None:
                self.assertEqual(os.pwrite(snapshot, tampered, 0), len(tampered))
                real_seal(snapshot)

            with (
                mock.patch.object(
                    corpus_prep,
                    "_seal_snapshot_fd",
                    side_effect=tamper_then_seal,
                ),
                self.assertRaisesRegex(
                    CorpusPreparationError,
                    "sealed snapshot content",
                ),
            ):
                reopen_verified_local_source(verified)

    def test_reopen_rejects_oversized_snapshot_before_open_or_allocation(self) -> None:
        source = b"small issued source"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path, source_path = self._runnable_fixture(root, source)
            verified = verify_local_source(
                plan_path,
                REQUIRED_CORPUS_IDS[0],
                source_path,
            )
            object.__setattr__(
                verified,
                "bytes",
                corpus_prep.MAX_REOPEN_SNAPSHOT_BYTES + 1,
            )

            with (
                mock.patch.object(
                    corpus_prep,
                    "_open_regular_path_secure",
                ) as opener,
                mock.patch.object(
                    corpus_prep,
                    "_create_snapshot_fd",
                ) as snapshot_creator,
                self.assertRaisesRegex(
                    CorpusPreparationError,
                    "sealed snapshot limit",
                ),
            ):
                reopen_verified_local_source(verified)
            opener.assert_not_called()
            snapshot_creator.assert_not_called()

        self.assertGreaterEqual(
            corpus_prep.MAX_REOPEN_SNAPSHOT_BYTES,
            100_000_000,
        )
        self.assertLessEqual(
            corpus_prep.MAX_REOPEN_SNAPSHOT_BYTES,
            128 * 1024**2,
        )

    def test_constructed_copied_and_deserialized_records_are_not_issued(
        self,
    ) -> None:
        source = b"issued-record provenance"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path, source_path = self._runnable_fixture(root, source)
            output_path = root / "prepared.bin"
            verified = verify_local_source(
                plan_path,
                REQUIRED_CORPUS_IDS[0],
                source_path,
            )
            prepared = prepare_local_source(
                plan_path,
                REQUIRED_CORPUS_IDS[0],
                source_path,
                output_path,
            )
            constructed_source = corpus_prep.VerifiedLocalSource(
                corpus_id=verified.corpus_id,
                display_path=verified.display_path,
                identity=verified.identity,
                bytes=verified.bytes,
                sha256=verified.sha256,
                plan_sha256=verified.plan_sha256,
            )
            constructed_prepared = corpus_prep.PreparedLocalCorpus(
                corpus_id=prepared.corpus_id,
                display_path=prepared.display_path,
                identity=prepared.identity,
                bytes=prepared.bytes,
                sha256=prepared.sha256,
                source_sha256=prepared.source_sha256,
                recipe_id=prepared.recipe_id,
                recipe_version=prepared.recipe_version,
                recipe_implementation_sha256=prepared.recipe_implementation_sha256,
                plan_sha256=prepared.plan_sha256,
                publication_state=prepared.publication_state,
            )
            forged_sources = (
                constructed_source,
                replace(verified),
                pickle.loads(pickle.dumps(verified)),
            )
            forged_prepared = (
                constructed_prepared,
                replace(prepared),
                pickle.loads(pickle.dumps(prepared)),
            )

            with mock.patch.object(
                corpus_prep,
                "_open_regular_path_secure",
            ) as opener:
                for forged in forged_sources:
                    with (
                        self.subTest(record="verified", variant=type(forged)),
                        self.assertRaisesRegex(
                            CorpusPreparationError,
                            "not issued by this process",
                        ),
                    ):
                        reopen_verified_local_source(forged)
                for forged in forged_prepared:
                    with (
                        self.subTest(record="prepared", variant=type(forged)),
                        self.assertRaisesRegex(
                            CorpusPreparationError,
                            "not issued by this process",
                        ),
                    ):
                        reopen_prepared_local_corpus(forged)
            opener.assert_not_called()

    def test_prepares_exact_atomic_copy_without_overwriting(self) -> None:
        source = b"deterministic copy bytes" * 1_000
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path, source_path = self._runnable_fixture(root, source)
            output_path = root / "prepared.bin"

            prepared = prepare_local_source(
                plan_path,
                REQUIRED_CORPUS_IDS[0],
                source_path,
                output_path,
            )

            self.assertEqual(output_path.read_bytes(), source)
            self.assertEqual(prepared.bytes, len(source))
            self.assertEqual(prepared.sha256, _digest(source))
            self.assertEqual(prepared.source_sha256, _digest(source))
            self.assertEqual(prepared.display_path, output_path)
            self.assertFalse(hasattr(prepared, "path"))
            self.assertEqual(prepared.publication_state, "durable")
            self.assertEqual(prepared.identity.file_device, output_path.stat().st_dev)
            self.assertEqual(prepared.identity.file_inode, output_path.stat().st_ino)
            self.assertEqual(prepared.identity.parent_device, root.stat().st_dev)
            self.assertEqual(prepared.identity.parent_inode, root.stat().st_ino)
            self.assertEqual(
                prepared.recipe_implementation_sha256,
                COPY_RECIPE_IMPLEMENTATION_SHA256,
            )
            self.assertFalse(prepared.binding)
            self.assertEqual(output_path.stat().st_nlink, 1)
            self.assertEqual(
                {path.name for path in root.iterdir()},
                {"acquisition-plan.json", "source.bin", "prepared.bin"},
            )

            reopened = reopen_prepared_local_corpus(prepared)
            try:
                self.assertEqual(os.read(reopened, len(source) + 1), source)
            finally:
                os.close(reopened)

            with self.assertRaisesRegex(CorpusPreparationError, "already exists"):
                prepare_local_source(
                    plan_path,
                    REQUIRED_CORPUS_IDS[0],
                    source_path,
                    output_path,
                )
            self.assertEqual(output_path.read_bytes(), source)

    def test_publication_fsyncs_file_then_destination_directory(self) -> None:
        source = b"durability ordering"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path, source_path = self._runnable_fixture(root, source)
            output_path = root / "prepared.bin"
            real_fsync = os.fsync
            real_publish = corpus_prep._publish_anonymous_no_replace
            events: list[tuple[str, int]] = []

            def tracking_fsync(descriptor: int) -> None:
                events.append(("fsync", descriptor))
                real_fsync(descriptor)

            def tracking_publish(
                temporary_descriptor: int,
                destination_parent: int,
                final_name: str,
            ) -> None:
                events.append(("linkat", destination_parent))
                real_publish(
                    temporary_descriptor,
                    destination_parent,
                    final_name,
                )

            with (
                mock.patch.object(
                    corpus_prep.os,
                    "fsync",
                    side_effect=tracking_fsync,
                ),
                mock.patch.object(
                    corpus_prep,
                    "_publish_anonymous_no_replace",
                    side_effect=tracking_publish,
                ),
            ):
                prepared = prepare_local_source(
                    plan_path,
                    REQUIRED_CORPUS_IDS[0],
                    source_path,
                    output_path,
                )

            self.assertEqual([event[0] for event in events], ["fsync", "linkat", "fsync"])
            self.assertEqual(events[1][1], events[2][1])
            self.assertEqual(prepared.publication_state, "durable")

    def test_directory_fsync_failure_reports_committed_not_durable_without_unlink(
        self,
    ) -> None:
        source = b"visible but durability unconfirmed"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path, source_path = self._runnable_fixture(root, source)
            output_path = root / "prepared.bin"
            real_fsync = os.fsync
            fsync_calls: list[int] = []

            def fail_directory_fsync(descriptor: int) -> None:
                fsync_calls.append(descriptor)
                if len(fsync_calls) == 2:
                    raise OSError("simulated directory fsync failure")
                real_fsync(descriptor)

            with (
                mock.patch.object(
                    corpus_prep.os,
                    "fsync",
                    side_effect=fail_directory_fsync,
                ),
                mock.patch.object(
                    corpus_prep.os,
                    "unlink",
                    side_effect=AssertionError("post-publication unlink is forbidden"),
                ),
                self.assertRaises(CorpusPublicationDurabilityError) as raised,
            ):
                prepare_local_source(
                    plan_path,
                    REQUIRED_CORPUS_IDS[0],
                    source_path,
                    output_path,
                )

            error = raised.exception
            self.assertTrue(error.committed)
            self.assertFalse(error.durable)
            self.assertEqual(error.publication_state, "committed_not_durable")
            self.assertEqual(error.prepared.publication_state, "committed_not_durable")
            self.assertFalse(error.prepared.binding)
            self.assertEqual(output_path.read_bytes(), source)
            self.assertEqual(len(fsync_calls), 2)

    def test_post_fsync_name_probe_rejects_unlinked_or_replaced_destination(
        self,
    ) -> None:
        source = b"the final directory entry must retain the committed inode"
        attacker = b"attacker replacement"

        def make_directory_fsync_race(
            *,
            output_name: str,
            replace_destination: bool,
            calls: list[int],
            fsync: Any,
        ) -> Any:
            def race_before_directory_fsync(descriptor: int) -> None:
                calls.append(descriptor)
                if len(calls) == 2:
                    os.unlink(output_name, dir_fd=descriptor)
                    if replace_destination:
                        attacker_descriptor = os.open(
                            output_name,
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                            0o600,
                            dir_fd=descriptor,
                        )
                        try:
                            os.write(attacker_descriptor, attacker)
                        finally:
                            os.close(attacker_descriptor)
                fsync(descriptor)

            return race_before_directory_fsync

        for replacement in (False, True):
            with (
                self.subTest(replacement=replacement),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir).resolve(strict=True)
                plan_path, source_path = self._runnable_fixture(root, source)
                output_path = root / "prepared.bin"
                real_fsync = os.fsync
                fsync_calls: list[int] = []
                race_before_directory_fsync = make_directory_fsync_race(
                    output_name=output_path.name,
                    replace_destination=replacement,
                    calls=fsync_calls,
                    fsync=real_fsync,
                )

                with (
                    mock.patch.object(
                        corpus_prep.os,
                        "fsync",
                        side_effect=race_before_directory_fsync,
                    ),
                    self.assertRaises(CorpusPublicationNameUnavailableError) as raised,
                ):
                    prepare_local_source(
                        plan_path,
                        REQUIRED_CORPUS_IDS[0],
                        source_path,
                        output_path,
                    )

                error = raised.exception
                self.assertTrue(error.committed)
                self.assertFalse(error.durable)
                self.assertFalse(error.name_bound)
                self.assertTrue(error.directory_fsync_completed)
                self.assertEqual(
                    error.publication_state,
                    "committed_name_unavailable",
                )
                self.assertEqual(
                    error.prepared.publication_state,
                    "committed_name_unavailable",
                )
                self.assertFalse(error.prepared.binding)
                self.assertEqual(len(fsync_calls), 2)
                if replacement:
                    self.assertEqual(output_path.read_bytes(), attacker)
                else:
                    self.assertFalse(output_path.exists())

    def test_post_fsync_name_probe_rejects_content_drift_during_fsync(self) -> None:
        source = b"post-publication metadata continuity"
        tampered = b"M" * len(source)
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path, source_path = self._runnable_fixture(root, source)
            output_path = root / "prepared.bin"
            real_fsync = os.fsync
            fsync_calls: list[int] = []

            def mutate_before_directory_fsync(descriptor: int) -> None:
                fsync_calls.append(descriptor)
                if len(fsync_calls) == 2:
                    attacker_descriptor = os.open(output_path, os.O_WRONLY)
                    try:
                        self.assertEqual(
                            os.pwrite(attacker_descriptor, tampered, 0),
                            len(tampered),
                        )
                    finally:
                        os.close(attacker_descriptor)
                    os.utime(output_path, ns=(1_000_000_000, 1_000_000_000))
                real_fsync(descriptor)

            with (
                mock.patch.object(
                    corpus_prep.os,
                    "fsync",
                    side_effect=mutate_before_directory_fsync,
                ),
                self.assertRaises(CorpusPublicationNameUnavailableError) as raised,
            ):
                prepare_local_source(
                    plan_path,
                    REQUIRED_CORPUS_IDS[0],
                    source_path,
                    output_path,
                )

            error = raised.exception
            self.assertEqual(
                error.publication_state,
                "committed_name_unavailable",
            )
            self.assertFalse(error.name_bound)
            self.assertTrue(error.directory_fsync_completed)
            self.assertEqual(
                error.prepared.publication_state,
                "committed_name_unavailable",
            )
            self.assertEqual(output_path.read_bytes(), tampered)
            self.assertEqual(len(fsync_calls), 2)

    def test_error_after_successful_link_is_detected_as_committed(self) -> None:
        source = b"link succeeded before the injected failure"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path, source_path = self._runnable_fixture(root, source)
            output_path = root / "prepared.bin"
            real_publish = corpus_prep._publish_anonymous_no_replace
            post_link_error = OSError("failure after successful linkat")

            def publish_then_fail(
                temporary_descriptor: int,
                destination_parent: int,
                final_name: str,
            ) -> None:
                real_publish(
                    temporary_descriptor,
                    destination_parent,
                    final_name,
                )
                raise post_link_error

            with (
                mock.patch.object(
                    corpus_prep,
                    "_publish_anonymous_no_replace",
                    side_effect=publish_then_fail,
                ),
                mock.patch.object(
                    corpus_prep.os,
                    "unlink",
                    side_effect=AssertionError("post-publication unlink is forbidden"),
                ),
                self.assertRaises(CorpusPublicationDurabilityError) as raised,
            ):
                prepare_local_source(
                    plan_path,
                    REQUIRED_CORPUS_IDS[0],
                    source_path,
                    output_path,
                )

            self.assertIs(raised.exception.__cause__, post_link_error)
            self.assertEqual(
                raised.exception.publication_state,
                "committed_not_durable",
            )
            self.assertEqual(output_path.read_bytes(), source)

    def test_commit_boundary_same_size_tamper_is_rehashed_after_link(self) -> None:
        source = b"post-publication descriptor hash"
        tampered = b"T" * len(source)
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path, source_path = self._runnable_fixture(root, source)
            output_path = root / "prepared.bin"
            real_publish = corpus_prep._publish_anonymous_no_replace

            def tamper_then_publish(
                temporary_descriptor: int,
                destination_parent: int,
                final_name: str,
            ) -> None:
                self.assertEqual(
                    os.pwrite(temporary_descriptor, tampered, 0),
                    len(tampered),
                )
                real_publish(
                    temporary_descriptor,
                    destination_parent,
                    final_name,
                )

            with (
                mock.patch.object(
                    corpus_prep,
                    "_publish_anonymous_no_replace",
                    side_effect=tamper_then_publish,
                ),
                mock.patch.object(
                    corpus_prep,
                    "_publication_link_metadata_changed",
                    return_value=False,
                ),
                self.assertRaises(CorpusPublicationDurabilityError) as raised,
            ):
                prepare_local_source(
                    plan_path,
                    REQUIRED_CORPUS_IDS[0],
                    source_path,
                    output_path,
                )

            error = raised.exception
            self.assertEqual(error.publication_state, "committed_not_durable")
            self.assertIsInstance(error.__cause__, CorpusPreparationError)
            self.assertIn("post-publication SHA-256", str(error.__cause__))
            self.assertEqual(error.prepared.sha256, _digest(source))
            self.assertFalse(error.prepared.binding)
            self.assertEqual(output_path.read_bytes(), tampered)

    def test_first_linkat_callable_link_then_oserror_is_not_misclassified(
        self,
    ) -> None:
        source = b"foreign call committed before raising"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path, source_path = self._runnable_fixture(root, source)
            output_path = root / "prepared.bin"
            real_library = corpus_prep.ctypes.CDLL(None, use_errno=True)
            real_linkat = real_library.linkat
            real_linkat.argtypes = (
                corpus_prep.ctypes.c_int,
                corpus_prep.ctypes.c_char_p,
                corpus_prep.ctypes.c_int,
                corpus_prep.ctypes.c_char_p,
                corpus_prep.ctypes.c_int,
            )
            real_linkat.restype = corpus_prep.ctypes.c_int
            post_link_error = OSError("callable raised after real linkat")

            class LinkatThenRaise:
                argtypes: object = None
                restype: object = None

                def __call__(
                    self,
                    source_descriptor: int,
                    source_name: bytes,
                    destination_parent: int,
                    destination_name: bytes,
                    flags: int,
                ) -> int:
                    result = real_linkat(
                        source_descriptor,
                        source_name,
                        destination_parent,
                        destination_name,
                        flags,
                    )
                    if result == 0:
                        raise post_link_error
                    return result

            class FakeLibrary:
                linkat = LinkatThenRaise()

            with (
                mock.patch.object(
                    corpus_prep.ctypes,
                    "CDLL",
                    return_value=FakeLibrary(),
                ),
                self.assertRaises(CorpusPublicationDurabilityError) as raised,
            ):
                prepare_local_source(
                    plan_path,
                    REQUIRED_CORPUS_IDS[0],
                    source_path,
                    output_path,
                )

            self.assertIs(raised.exception.__cause__, post_link_error)
            self.assertEqual(
                raised.exception.publication_state,
                "committed_not_durable",
            )
            self.assertEqual(output_path.read_bytes(), source)

    def test_link_then_attacker_unlink_then_error_is_commit_outcome_unknown(
        self,
    ) -> None:
        source = b"link history cannot be inferred from a zero link count"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path, source_path = self._runnable_fixture(root, source)
            output_path = root / "prepared.bin"
            real_publish = corpus_prep._publish_anonymous_no_replace
            post_unlink_error = OSError("failure after attacker removed committed name")

            def publish_then_attacker_unlink_then_fail(
                temporary_descriptor: int,
                destination_parent: int,
                final_name: str,
            ) -> None:
                real_publish(
                    temporary_descriptor,
                    destination_parent,
                    final_name,
                )
                os.unlink(final_name, dir_fd=destination_parent)
                raise post_unlink_error

            with (
                mock.patch.object(
                    corpus_prep,
                    "_publish_anonymous_no_replace",
                    side_effect=publish_then_attacker_unlink_then_fail,
                ),
                self.assertRaises(CorpusPublicationOutcomeUnknownError) as raised,
            ):
                prepare_local_source(
                    plan_path,
                    REQUIRED_CORPUS_IDS[0],
                    source_path,
                    output_path,
                )

            error = raised.exception
            self.assertIs(error.operation_error, post_unlink_error)
            self.assertIsNone(error.inspection_error)
            self.assertIs(error.__cause__, post_unlink_error)
            self.assertEqual(error.publication_state, "commit_outcome_unknown")
            self.assertEqual(error.candidate.publication_state, "commit_outcome_unknown")
            self.assertFalse(output_path.exists())

    def test_secure_prepared_reopen_rejects_same_content_path_swap(self) -> None:
        source = b"prepared inode is authoritative"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path, source_path = self._runnable_fixture(root, source)
            output_path = root / "prepared.bin"
            prepared = prepare_local_source(
                plan_path,
                REQUIRED_CORPUS_IDS[0],
                source_path,
                output_path,
            )

            output_path.rename(root / "displaced-prepared.bin")
            output_path.write_bytes(source)
            self.assertEqual(output_path.read_bytes(), source)
            with self.assertRaisesRegex(CorpusPreparationError, "verified inode"):
                reopen_prepared_local_corpus(prepared)

    def test_parent_rename_during_publication_keeps_path_display_only(self) -> None:
        source = b"directory fd survives a parent rename"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path, source_path = self._runnable_fixture(root, source)
            destination_parent = root / "destination"
            destination_parent.mkdir()
            moved_parent = root / "moved-destination"
            output_path = destination_parent / "prepared.bin"
            real_publish = corpus_prep._publish_anonymous_no_replace

            def publish_then_rename_parent(
                temporary_descriptor: int,
                destination_parent_descriptor: int,
                final_name: str,
            ) -> None:
                real_publish(
                    temporary_descriptor,
                    destination_parent_descriptor,
                    final_name,
                )
                destination_parent.rename(moved_parent)
                destination_parent.mkdir()
                (destination_parent / final_name).write_bytes(source)

            with mock.patch.object(
                corpus_prep,
                "_publish_anonymous_no_replace",
                side_effect=publish_then_rename_parent,
            ):
                prepared = prepare_local_source(
                    plan_path,
                    REQUIRED_CORPUS_IDS[0],
                    source_path,
                    output_path,
                )

            self.assertEqual(output_path.read_bytes(), source)
            self.assertEqual((moved_parent / "prepared.bin").read_bytes(), source)
            self.assertEqual(prepared.identity.parent_inode, moved_parent.stat().st_ino)
            self.assertNotEqual(
                prepared.identity.parent_inode,
                destination_parent.stat().st_ino,
            )
            with self.assertRaisesRegex(CorpusPreparationError, "parent path"):
                reopen_prepared_local_corpus(prepared)

    def test_successful_commit_never_uses_pathname_unlink(self) -> None:
        source = b"verified before the commit point"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path, source_path = self._runnable_fixture(root, source)
            output_path = root / "prepared.bin"
            with (
                mock.patch.object(
                    corpus_prep,
                    "secure_local_preparation_supported",
                    return_value=True,
                ),
                mock.patch.object(
                    corpus_prep.os,
                    "unlink",
                    side_effect=AssertionError("pathname rollback is forbidden"),
                ),
            ):
                prepare_local_source(
                    plan_path,
                    REQUIRED_CORPUS_IDS[0],
                    source_path,
                    output_path,
                )
            self.assertEqual(output_path.read_bytes(), source)

    def test_preparation_refuses_destination_symlink_and_hardlink(self) -> None:
        source = b"source"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path, source_path = self._runnable_fixture(root, source)
            outside = root / "outside.bin"
            outside.write_bytes(b"outside")
            output_path = root / "prepared.bin"
            output_path.symlink_to(outside)
            with self.assertRaisesRegex(CorpusPreparationError, "already exists"):
                prepare_local_source(
                    plan_path,
                    REQUIRED_CORPUS_IDS[0],
                    source_path,
                    output_path,
                )
            self.assertEqual(outside.read_bytes(), b"outside")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path, source_path = self._runnable_fixture(root, source)
            real_output_parent = root / "real-output"
            real_output_parent.mkdir()
            linked_output_parent = root / "linked-output"
            linked_output_parent.symlink_to(real_output_parent, target_is_directory=True)
            with self.assertRaisesRegex(CorpusPreparationError, "symlink"):
                prepare_local_source(
                    plan_path,
                    REQUIRED_CORPUS_IDS[0],
                    source_path,
                    linked_output_parent / "prepared.bin",
                )

    def test_atomic_publication_never_overwrites_a_destination_created_by_a_racer(
        self,
    ) -> None:
        source = b"verified source"
        attacker = b"attacker-owned destination"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path, source_path = self._runnable_fixture(root, source)
            output_path = root / "prepared.bin"
            real_publish = corpus_prep._publish_anonymous_no_replace

            def publish_after_collision(
                temporary_descriptor: int,
                destination_parent: int,
                final_name: str,
            ) -> None:
                attacker_descriptor = os.open(
                    final_name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=destination_parent,
                )
                try:
                    os.write(attacker_descriptor, attacker)
                finally:
                    os.close(attacker_descriptor)
                real_publish(
                    temporary_descriptor,
                    destination_parent,
                    final_name,
                )

            with (
                mock.patch.object(
                    corpus_prep,
                    "_publish_anonymous_no_replace",
                    side_effect=publish_after_collision,
                ),
                self.assertRaisesRegex(CorpusPreparationError, "already exists"),
            ):
                prepare_local_source(
                    plan_path,
                    REQUIRED_CORPUS_IDS[0],
                    source_path,
                    output_path,
                )

            self.assertEqual(output_path.read_bytes(), attacker)
            self.assertEqual(
                {path.name for path in root.iterdir()},
                {"acquisition-plan.json", "source.bin", "prepared.bin"},
            )

    def test_source_hardlink_created_during_read_is_detected(self) -> None:
        source = b"verified source" * 100
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path, source_path = self._runnable_fixture(root, source)
            extra_link = root / "late-hardlink.bin"
            real_hash = corpus_prep._hash_fd_exact

            def hash_after_link(descriptor: int, expected_bytes: int) -> tuple[int, str]:
                os.link(source_path, extra_link)
                return real_hash(descriptor, expected_bytes)

            with (
                mock.patch.object(
                    corpus_prep,
                    "_hash_fd_exact",
                    side_effect=hash_after_link,
                ),
                self.assertRaisesRegex(CorpusPreparationError, "changed"),
            ):
                verify_local_source(
                    plan_path,
                    REQUIRED_CORPUS_IDS[0],
                    source_path,
                )

    def test_cleanup_is_fail_closed_after_copy_or_post_write_verification_failure(
        self,
    ) -> None:
        source = b"source data" * 100
        failure_patches = (
            mock.patch.object(
                corpus_prep,
                "_write_all",
                side_effect=OSError("simulated write failure"),
            ),
            mock.patch.object(
                corpus_prep,
                "_hash_fd_exact",
                return_value=(len(source), "0" * 64),
            ),
        )
        for index, failure_patch in enumerate(failure_patches):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir).resolve(strict=True)
                plan_path, source_path = self._runnable_fixture(root, source)
                output_path = root / "prepared.bin"
                with failure_patch, self.assertRaises(CorpusPreparationError):
                    prepare_local_source(
                        plan_path,
                        REQUIRED_CORPUS_IDS[0],
                        source_path,
                        output_path,
                    )
                self.assertFalse(output_path.exists())
                self.assertEqual(
                    {path.name for path in root.iterdir()},
                    {"acquisition-plan.json", "source.bin"},
                )

    def test_reopen_cleanup_preserves_every_original_and_snapshot_close_error(
        self,
    ) -> None:
        source = b"sealed snapshot cleanup"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path, source_path = self._runnable_fixture(root, source)
            verified = verify_local_source(
                plan_path,
                REQUIRED_CORPUS_IDS[0],
                source_path,
            )
            real_seal = corpus_prep._seal_snapshot_fd
            real_close = os.close
            armed = False
            close_calls: list[int] = []
            close_errors: list[OSError] = []

            def seal_and_arm(snapshot: int) -> None:
                nonlocal armed
                real_seal(snapshot)
                armed = True

            def close_then_fail(descriptor: int) -> None:
                if not armed:
                    real_close(descriptor)
                    return
                close_calls.append(descriptor)
                real_close(descriptor)
                error = OSError(f"snapshot close failure {len(close_calls)}")
                close_errors.append(error)
                raise error

            with (
                mock.patch.object(
                    corpus_prep,
                    "_seal_snapshot_fd",
                    side_effect=seal_and_arm,
                ),
                mock.patch.object(
                    corpus_prep.os,
                    "close",
                    side_effect=close_then_fail,
                ),
                self.assertRaises(CorpusPreparationCleanupError) as raised,
            ):
                reopen_verified_local_source(verified)

            self.assertEqual(len(close_calls), 3)
            self.assertEqual(raised.exception.cleanup_errors, tuple(close_errors))
            self.assertIsNone(raised.exception.primary_error)
            self.assertEqual(raised.exception.publication_state, "not_committed")
            self.assertIsNone(raised.exception.prepared)

    def test_every_descriptor_close_is_attempted_after_durable_commit(self) -> None:
        source = b"close all descriptors independently"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path, source_path = self._runnable_fixture(root, source)
            output_path = root / "prepared.bin"
            real_publish = corpus_prep._publish_anonymous_no_replace
            real_close = os.close
            armed = False
            close_calls: list[int] = []
            close_errors: list[OSError] = []

            def publish_and_arm(
                temporary_descriptor: int,
                destination_parent: int,
                final_name: str,
            ) -> None:
                nonlocal armed
                real_publish(
                    temporary_descriptor,
                    destination_parent,
                    final_name,
                )
                armed = True

            def close_then_fail(descriptor: int) -> None:
                if not armed:
                    real_close(descriptor)
                    return
                close_calls.append(descriptor)
                real_close(descriptor)
                error = OSError(f"close failure {len(close_calls)}")
                close_errors.append(error)
                raise error

            with (
                mock.patch.object(
                    corpus_prep,
                    "_publish_anonymous_no_replace",
                    side_effect=publish_and_arm,
                ),
                mock.patch.object(
                    corpus_prep.os,
                    "close",
                    side_effect=close_then_fail,
                ),
                self.assertRaises(CorpusPreparationCleanupError) as raised,
            ):
                prepare_local_source(
                    plan_path,
                    REQUIRED_CORPUS_IDS[0],
                    source_path,
                    output_path,
                )

            self.assertEqual(len(close_calls), 4)
            self.assertEqual(raised.exception.cleanup_errors, tuple(close_errors))
            self.assertIsNone(raised.exception.primary_error)
            self.assertEqual(raised.exception.publication_state, "durable")
            self.assertIsNotNone(raised.exception.prepared)
            self.assertEqual(output_path.read_bytes(), source)

    def test_primary_and_baseexception_cleanup_failures_are_all_preserved(self) -> None:
        source = b"preserve primary and cleanup failures"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path, source_path = self._runnable_fixture(root, source)
            output_path = root / "prepared.bin"
            real_close = os.close
            armed = False
            close_calls: list[int] = []
            primary_error = RuntimeError("copy body failed")
            cleanup_errors: list[BaseException] = []

            def fail_write(_descriptor: int, _data: bytes) -> None:
                nonlocal armed
                armed = True
                raise primary_error

            def close_then_fail(descriptor: int) -> None:
                if not armed:
                    real_close(descriptor)
                    return
                close_calls.append(descriptor)
                real_close(descriptor)
                error: BaseException
                if len(close_calls) == 1:
                    error = KeyboardInterrupt("close interrupted")
                else:
                    error = OSError(f"close failure {len(close_calls)}")
                cleanup_errors.append(error)
                raise error

            with (
                mock.patch.object(
                    corpus_prep,
                    "_write_all",
                    side_effect=fail_write,
                ),
                mock.patch.object(
                    corpus_prep.os,
                    "close",
                    side_effect=close_then_fail,
                ),
                self.assertRaises(BaseExceptionGroup) as raised,
            ):
                prepare_local_source(
                    plan_path,
                    REQUIRED_CORPUS_IDS[0],
                    source_path,
                    output_path,
                )

            self.assertEqual(len(close_calls), 4)
            self.assertEqual(
                raised.exception.exceptions,
                (primary_error, *cleanup_errors),
            )
            self.assertIn("publication_state=not_committed", str(raised.exception))
            self.assertFalse(output_path.exists())

    def test_corpus_id_and_destination_name_are_validated(self) -> None:
        source = b"source data"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve(strict=True)
            plan_path, source_path = self._runnable_fixture(root, source)
            for corpus_id in ("unknown", "", True):
                with (
                    self.subTest(corpus_id=corpus_id),
                    self.assertRaises(CorpusPreparationError),
                ):
                    prepare_local_source(
                        plan_path,
                        corpus_id,  # type: ignore[arg-type]
                        source_path,
                        root / "output.bin",
                    )
            with self.assertRaisesRegex(CorpusPreparationError, "normalized"):
                prepare_local_source(
                    plan_path,
                    REQUIRED_CORPUS_IDS[0],
                    source_path,
                    root / "nested" / ".." / "output.bin",
                )


class UnsupportedHostTests(unittest.TestCase):
    def test_local_operations_fail_closed_when_secure_primitives_are_unavailable(
        self,
    ) -> None:
        source = b"source"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            plan_path = _write_plan(
                root,
                _plan(runnable_id=REQUIRED_CORPUS_IDS[0], source=source),
            )
            source_path = root / "source.bin"
            source_path.write_bytes(source)
            with (
                mock.patch.object(
                    corpus_prep,
                    "secure_local_preparation_supported",
                    return_value=False,
                ),
                self.assertRaisesRegex(CorpusPreparationError, "unavailable"),
            ):
                verify_local_source(plan_path, REQUIRED_CORPUS_IDS[0], source_path)
            with (
                mock.patch.object(
                    corpus_prep,
                    "secure_local_preparation_supported",
                    return_value=False,
                ),
                self.assertRaisesRegex(CorpusPreparationError, "unavailable"),
            ):
                prepare_local_source(
                    plan_path,
                    REQUIRED_CORPUS_IDS[0],
                    source_path,
                    root / "output.bin",
                )
