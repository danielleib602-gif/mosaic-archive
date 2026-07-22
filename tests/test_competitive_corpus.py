from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from collections import Counter
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from typing import Any
from unittest import mock

import mosaic_archive.competitive_corpus as competitive_corpus
from mosaic_archive.competitive_corpus import (
    EXPECTED_CONTRACT_ID,
    MIN_PREPARED_BYTES,
    REQUIRED_CORPUS_IDS,
    CompetitiveCorpusLock,
    CompetitiveCorpusVerification,
    CorpusLockValidationError,
    CorpusVerificationError,
    verify_competitive_corpus,
)
from mosaic_archive.competitive_corpus import (
    load_competitive_corpus_lock as _secure_load_competitive_corpus_lock,
)


def _secure_open_supported() -> bool:
    checker = getattr(
        competitive_corpus,
        "secure_local_verification_supported",
        None,
    )
    return bool(checker is not None and checker())


SECURE_OPEN_SUPPORTED = _secure_open_supported()


def _canonical_temp_root(temp_dir: str) -> Path:
    """Remove platform-owned symlink components from a test temp root."""

    root = Path(temp_dir)
    return root.resolve(strict=True) if os.name == "posix" else root


def load_competitive_corpus_lock(
    path: Path,
    *,
    max_bytes: int = competitive_corpus.MAX_LOCK_BYTES,
) -> CompetitiveCorpusLock:
    """Exercise parsing on unsupported hosts without weakening production access."""

    if SECURE_OPEN_SUPPORTED:
        return _secure_load_competitive_corpus_lock(path, max_bytes=max_bytes)

    def bounded_test_read(test_path: Path, limit: int) -> bytes:
        raw = Path(test_path).read_bytes()
        if len(raw) > limit:
            raise CorpusLockValidationError(f"corpus lock exceeds {limit} bytes")
        return raw

    with mock.patch.object(
        competitive_corpus,
        "_read_lock_bytes_secure",
        side_effect=bounded_test_read,
        create=True,
    ):
        return _secure_load_competitive_corpus_lock(path, max_bytes=max_bytes)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _entry(corpus_id: str, index: int) -> dict[str, object]:
    return {
        "id": corpus_id,
        "snapshot_id": f"snapshot-2026-07-{index + 1:02d}-sha256-{index:02x}",
        "source": {
            "path": f"sources/{corpus_id}.source",
            "bytes": index + 1,
            "sha256": f"{index + 1:064x}",
            "url": f"https://datasets.example.test/{corpus_id}/snapshot-{index}",
        },
        "prepared": {
            "path": f"prepared/{corpus_id}.bin",
            "bytes": MIN_PREPARED_BYTES + index,
            "sha256": f"{index + 11:064x}",
        },
        "preparation": {
            "recipe_id": "deterministic-copy-v1",
            "parameters": [
                {"name": "mtime_unix_ns", "value": 0},
                {"name": "path_order", "value": "utf8-bytewise"},
                {"name": "strip_metadata", "value": True},
            ],
        },
        "license": {
            "name": "Example Data License",
            "spdx_id": "CC-BY-4.0",
            "non_spdx_explanation": None,
            "url": f"https://licenses.example.test/{corpus_id}",
            "attribution": f"Example attribution for {corpus_id}",
            "attribution_url": f"https://credits.example.test/{corpus_id}",
            "redistribution_approved": True,
            "human_approver": "Alex Example",
            "approval_date": "2026-07-22",
            "evidence": {
                "path": f"license-evidence/{corpus_id}.txt",
                "bytes": index + 2,
                "sha256": f"{index + 21:064x}",
            },
        },
    }


def _payload() -> dict[str, object]:
    return {
        "schema_version": 1,
        "contract_id": EXPECTED_CONTRACT_ID,
        "corpora": [
            _entry(corpus_id, index) for index, corpus_id in enumerate(REQUIRED_CORPUS_IDS)
        ],
    }


def _write_json(path: Path, payload: object) -> bytes:
    raw = (json.dumps(payload, indent=2) + "\n").encode()
    path.write_bytes(raw)
    return raw


def _write_lock(root: Path, payload: object | None = None) -> Path:
    path = root / "corpora.lock.json"
    _write_json(path, _payload() if payload is None else payload)
    return path


def _entry_for(payload: dict[str, object], index: int = 0) -> dict[str, Any]:
    corpora = payload["corpora"]
    assert isinstance(corpora, list)
    entry = corpora[index]
    assert isinstance(entry, dict)
    return entry


def _prepare_verification_tree(
    temporary_root: Path,
) -> tuple[CompetitiveCorpusLock, Path, Path, dict[str, bytes]]:
    payload = _payload()
    corpus_root = temporary_root / "corpus-root"
    contents: dict[str, bytes] = {}
    corpora = payload["corpora"]
    assert isinstance(corpora, list)
    for index, raw_entry in enumerate(corpora):
        assert isinstance(raw_entry, dict)
        source_data = f"source-{index}".encode()
        prepared_data = f"prepared-{index}".encode()
        evidence_data = f"evidence-{index}".encode()
        license_record = raw_entry["license"]
        assert isinstance(license_record, dict)
        sections = (
            (raw_entry["source"], source_data),
            (raw_entry["prepared"], prepared_data),
            (license_record["evidence"], evidence_data),
        )
        for raw_section, data in sections:
            assert isinstance(raw_section, dict)
            relative = raw_section["path"]
            assert isinstance(relative, str)
            destination = corpus_root.joinpath(*relative.split("/"))
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            raw_section["bytes"] = len(data)
            raw_section["sha256"] = _digest(data)
            contents[relative] = data
    lock_path = _write_lock(temporary_root, payload)
    return (
        load_competitive_corpus_lock(lock_path),
        corpus_root,
        lock_path,
        contents,
    )


class CompetitiveCorpusLockLoadingTests(unittest.TestCase):
    def test_loads_exact_suite_and_preserves_exact_manifest_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = _canonical_temp_root(temp_dir)
            path = root / "corpora.lock.json"
            raw = _write_json(path, _payload())

            lock = load_competitive_corpus_lock(path)

        self.assertIsInstance(lock, CompetitiveCorpusLock)
        self.assertEqual(lock.schema_version, 1)
        self.assertEqual(lock.contract_id, EXPECTED_CONTRACT_ID)
        self.assertEqual(tuple(corpus.id for corpus in lock.corpora), REQUIRED_CORPUS_IDS)
        self.assertEqual(lock.manifest_sha256, _digest(raw))
        self.assertEqual(lock.corpora[0].source.bytes, 1)
        self.assertEqual(lock.corpora[0].prepared.bytes, MIN_PREPARED_BYTES)
        self.assertEqual(
            lock.corpora[0].preparation.parameters[0].name,
            "mtime_unix_ns",
        )
        self.assertEqual(lock.corpora[0].license.approval_date.isoformat(), "2026-07-22")

    def test_normalizes_order_while_retaining_raw_byte_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = _canonical_temp_root(temp_dir)
            payload = _payload()
            corpora = payload["corpora"]
            self.assertIsInstance(corpora, list)
            payload["corpora"] = list(reversed(corpora))  # type: ignore[arg-type]
            path = root / "corpora.lock.json"
            raw = _write_json(path, payload)

            lock = load_competitive_corpus_lock(path)

        self.assertEqual(tuple(corpus.id for corpus in lock.corpora), REQUIRED_CORPUS_IDS)
        self.assertEqual(lock.manifest_sha256, _digest(raw))

    def test_lock_and_nested_values_are_frozen_slotted_and_deeply_immutable(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            lock = load_competitive_corpus_lock(_write_lock(_canonical_temp_root(temp_dir)))

        values = (
            lock,
            lock.corpora[0],
            lock.corpora[0].source,
            lock.corpora[0].prepared,
            lock.corpora[0].preparation,
            lock.corpora[0].preparation.parameters[0],
            lock.corpora[0].license,
            lock.corpora[0].license.evidence,
        )
        self.assertTrue(all(not hasattr(value, "__dict__") for value in values))
        with self.assertRaises(FrozenInstanceError):
            lock.contract_id = "changed"  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            lock.corpora[0].source.path = "changed"  # type: ignore[misc]
        with self.assertRaises(AttributeError):
            lock.corpora.append(lock.corpora[0])  # type: ignore[attr-defined]

    def test_rejects_all_extra_and_missing_schema_keys(self) -> None:
        mutations = (
            ("top-extra", lambda payload: payload.update(extra=True)),
            ("top-missing", lambda payload: payload.pop("contract_id")),
            ("corpus-extra", lambda payload: _entry_for(payload).update(extra=True)),
            (
                "source-extra",
                lambda payload: _entry_for(payload)["source"].update(extra=True),
            ),
            (
                "prepared-missing",
                lambda payload: _entry_for(payload)["prepared"].pop("sha256"),
            ),
            (
                "preparation-extra",
                lambda payload: _entry_for(payload)["preparation"].update(extra=True),
            ),
            (
                "license-extra",
                lambda payload: _entry_for(payload)["license"].update(extra=True),
            ),
            (
                "evidence-extra",
                lambda payload: _entry_for(payload)["license"]["evidence"].update(extra=True),
            ),
            (
                "parameter-extra",
                lambda payload: _entry_for(payload)["preparation"]["parameters"][0].update(
                    extra=True
                ),
            ),
        )
        for name, mutate in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp_dir:
                payload = _payload()
                mutate(payload)
                with self.assertRaisesRegex(CorpusLockValidationError, "keys"):
                    load_competitive_corpus_lock(
                        _write_lock(_canonical_temp_root(temp_dir), payload)
                    )

    def test_rejects_wrong_top_level_types_values_and_bool_as_int(self) -> None:
        cases = (
            ("schema_version", True),
            ("schema_version", 2),
            ("contract_id", "another-contract"),
            ("corpora", {}),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value), tempfile.TemporaryDirectory() as temp_dir:
                payload = _payload()
                payload[field] = value
                with self.assertRaises(CorpusLockValidationError):
                    load_competitive_corpus_lock(
                        _write_lock(_canonical_temp_root(temp_dir), payload)
                    )

    def test_requires_exactly_the_six_named_corpus_ids(self) -> None:
        for change in ("missing", "duplicate", "unknown"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp_dir:
                payload = _payload()
                corpora = payload["corpora"]
                self.assertIsInstance(corpora, list)
                if change == "missing":
                    corpora.pop()  # type: ignore[union-attr]
                elif change == "duplicate":
                    corpora[-1]["id"] = corpora[0]["id"]  # type: ignore[index]
                else:
                    corpora[-1]["id"] = "not-a-required-corpus"  # type: ignore[index]
                with self.assertRaisesRegex(CorpusLockValidationError, "corpus IDs"):
                    load_competitive_corpus_lock(
                        _write_lock(_canonical_temp_root(temp_dir), payload)
                    )

    def test_requires_distinct_prepared_paths_and_digests_for_every_corpus(self) -> None:
        for duplicate_field in ("path", "sha256"):
            with (
                self.subTest(duplicate_field=duplicate_field),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                payload = _payload()
                corpora = payload["corpora"]
                self.assertIsInstance(corpora, list)
                first_prepared = corpora[0]["prepared"]  # type: ignore[index]
                second_prepared = corpora[1]["prepared"]  # type: ignore[index]
                second_prepared[duplicate_field] = first_prepared[duplicate_field]

                with self.assertRaisesRegex(
                    CorpusLockValidationError,
                    f"prepared {duplicate_field}s must be distinct",
                ):
                    load_competitive_corpus_lock(
                        _write_lock(_canonical_temp_root(temp_dir), payload)
                    )

    def test_rejects_bad_lengths_hashes_and_bool_as_int(self) -> None:
        cases = (
            ("source", "bytes", True, "bytes"),
            ("source", "bytes", 0, "bytes"),
            (
                "source",
                "bytes",
                competitive_corpus.MAX_CORPUS_FILE_BYTES + 1,
                "per-file limit",
            ),
            ("source", "sha256", "A" * 64, "sha256"),
            ("prepared", "bytes", True, "bytes"),
            ("prepared", "bytes", MIN_PREPARED_BYTES - 1, "minimum"),
            ("prepared", "sha256", "0" * 63, "sha256"),
            ("evidence", "bytes", False, "bytes"),
            ("evidence", "bytes", -1, "bytes"),
            ("evidence", "sha256", 7, "sha256"),
        )
        for section, field, value, message in cases:
            with (
                self.subTest(section=section, field=field),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                payload = _payload()
                entry = _entry_for(payload)
                target = entry["license"]["evidence"] if section == "evidence" else entry[section]
                target[field] = value
                with self.assertRaisesRegex(CorpusLockValidationError, message):
                    load_competitive_corpus_lock(
                        _write_lock(_canonical_temp_root(temp_dir), payload)
                    )

    def test_rejects_a_manifest_over_the_total_declared_byte_budget(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            mock.patch.object(
                competitive_corpus,
                "MAX_TOTAL_DECLARED_BYTES",
                MIN_PREPARED_BYTES,
            ),
            self.assertRaisesRegex(CorpusLockValidationError, "total limit"),
        ):
            load_competitive_corpus_lock(_write_lock(_canonical_temp_root(temp_dir), _payload()))

    def test_requires_safe_https_source_license_and_attribution_urls(self) -> None:
        cases = (
            ("source", "url", "http://datasets.example.test/snapshot"),
            ("source", "url", "https:///missing-host"),
            ("license", "url", "file:///license.txt"),
            ("license", "attribution_url", "/relative/credit"),
            ("license", "url", "https://user:secret@example.test/license"),
            ("source", "url", "https://example.test:99999/snapshot"),
            ("source", "url", "https://example.test/has space"),
        )
        for section, field, value in cases:
            with (
                self.subTest(section=section, field=field),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                payload = _payload()
                _entry_for(payload)[section][field] = value
                with self.assertRaisesRegex(CorpusLockValidationError, "HTTPS URL"):
                    load_competitive_corpus_lock(
                        _write_lock(_canonical_temp_root(temp_dir), payload)
                    )

    def test_snapshot_ids_are_explicit_and_not_moving_aliases(self) -> None:
        for snapshot_id in ("", "   ", "latest", "HEAD", "main", "has spaces", 7):
            with self.subTest(snapshot_id=snapshot_id), tempfile.TemporaryDirectory() as temp_dir:
                payload = _payload()
                _entry_for(payload)["snapshot_id"] = snapshot_id
                with self.assertRaisesRegex(CorpusLockValidationError, "snapshot_id"):
                    load_competitive_corpus_lock(
                        _write_lock(_canonical_temp_root(temp_dir), payload)
                    )

    def test_preparation_recipe_and_parameters_are_stable_and_explicit(self) -> None:
        recipe_ids = ("", "latest", "Recipe With Spaces", 1)
        for recipe_id in recipe_ids:
            with self.subTest(recipe_id=recipe_id), tempfile.TemporaryDirectory() as temp_dir:
                payload = _payload()
                _entry_for(payload)["preparation"]["recipe_id"] = recipe_id
                with self.assertRaisesRegex(CorpusLockValidationError, "recipe_id"):
                    load_competitive_corpus_lock(
                        _write_lock(_canonical_temp_root(temp_dir), payload)
                    )

        parameter_cases = (
            ("not-a-list", "array"),
            ([{"name": "mtime_unix_ns", "value": 1.5}], "value"),
            ([{"name": "", "value": 0}], "name"),
            (
                [
                    {"name": "same", "value": 0},
                    {"name": "same", "value": 1},
                ],
                "duplicate",
            ),
        )
        for parameters, message in parameter_cases:
            with self.subTest(parameters=parameters), tempfile.TemporaryDirectory() as temp_dir:
                payload = _payload()
                _entry_for(payload)["preparation"]["parameters"] = parameters
                with self.assertRaisesRegex(CorpusLockValidationError, message):
                    load_competitive_corpus_lock(
                        _write_lock(_canonical_temp_root(temp_dir), payload)
                    )

    def test_license_requires_exactly_one_spdx_id_or_explanation(self) -> None:
        cases = ((None, None), ("CC-BY-4.0", "also explained"), ("", None), (None, ""))
        for spdx_id, explanation in cases:
            with self.subTest(spdx_id=spdx_id), tempfile.TemporaryDirectory() as temp_dir:
                payload = _payload()
                license_record = _entry_for(payload)["license"]
                license_record["spdx_id"] = spdx_id
                license_record["non_spdx_explanation"] = explanation
                with self.assertRaisesRegex(CorpusLockValidationError, "exactly one"):
                    load_competitive_corpus_lock(
                        _write_lock(_canonical_temp_root(temp_dir), payload)
                    )

        for field, value in (("spdx_id", 7), ("non_spdx_explanation", [])):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temp_dir:
                payload = _payload()
                license_record = _entry_for(payload)["license"]
                license_record["spdx_id"] = None
                license_record["non_spdx_explanation"] = "documented terms"
                license_record[field] = value
                with self.assertRaises(CorpusLockValidationError):
                    load_competitive_corpus_lock(
                        _write_lock(_canonical_temp_root(temp_dir), payload)
                    )

        with tempfile.TemporaryDirectory() as temp_dir:
            payload = _payload()
            _entry_for(payload)["license"]["spdx_id"] = "CC BY"
            with self.assertRaisesRegex(CorpusLockValidationError, "SPDX ID"):
                load_competitive_corpus_lock(_write_lock(_canonical_temp_root(temp_dir), payload))

    def test_accepts_a_documented_non_spdx_license(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            payload = _payload()
            license_record = _entry_for(payload)["license"]
            license_record["spdx_id"] = None
            license_record["non_spdx_explanation"] = (
                "Custom terms permit redistribution of this immutable snapshot."
            )

            lock = load_competitive_corpus_lock(
                _write_lock(_canonical_temp_root(temp_dir), payload)
            )

        self.assertIsNone(lock.corpora[0].license.spdx_id)
        self.assertIn(
            "Custom terms",
            lock.corpora[0].license.non_spdx_explanation or "",
        )

    def test_license_requires_attribution_and_human_redistribution_approval(
        self,
    ) -> None:
        cases = (
            ("name", ""),
            ("attribution", "   "),
            ("redistribution_approved", False),
            ("redistribution_approved", 1),
            ("human_approver", ""),
            ("human_approver", "reviewer\nforged-log-line"),
            ("attribution", "credit\x1b[2J"),
            ("approval_date", "2026-02-30"),
            ("approval_date", "2026-07-22T10:00:00Z"),
        )
        for field, value in cases:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temp_dir:
                payload = _payload()
                _entry_for(payload)["license"][field] = value
                with self.assertRaises(CorpusLockValidationError):
                    load_competitive_corpus_lock(
                        _write_lock(_canonical_temp_root(temp_dir), payload)
                    )

    def test_rejects_absolute_nonportable_and_escaping_paths(self) -> None:
        paths = (
            "",
            "/absolute.bin",
            "../escape.bin",
            "folder/../escape.bin",
            "folder/./file.bin",
            r"folder\file.bin",
            "C:/escape.bin",
            " leading-space.bin",
            "trailing-space.bin ",
            "folder/newline\nfile.bin",
            "folder/escape\x1bfile.bin",
            "folder/format-\u202efile.bin",
            "folder/" + "a" * 256,
            "a" * 4_097,
        )
        for relative_path in paths:
            with self.subTest(path=relative_path), tempfile.TemporaryDirectory() as temp_dir:
                payload = _payload()
                _entry_for(payload)["source"]["path"] = relative_path
                with self.assertRaisesRegex(CorpusLockValidationError, "path"):
                    load_competitive_corpus_lock(
                        _write_lock(_canonical_temp_root(temp_dir), payload)
                    )

    def test_rejects_duplicate_keys_and_non_finite_numbers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = _canonical_temp_root(temp_dir)
            path = root / "corpora.lock.json"
            path.write_text(
                '{"schema_version":1,"contract_id":"first","contract_id":"second","corpora":[]}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(CorpusLockValidationError, "duplicate JSON key"):
                load_competitive_corpus_lock(path)

        for constant in ("NaN", "Infinity", "-Infinity", "1e999"):
            with self.subTest(constant=constant), tempfile.TemporaryDirectory() as temp_dir:
                path = _canonical_temp_root(temp_dir) / "corpora.lock.json"
                path.write_text(f'{{"schema_version": {constant}}}', encoding="utf-8")
                with self.assertRaisesRegex(CorpusLockValidationError, "non-finite"):
                    load_competitive_corpus_lock(path)

    def test_manifest_read_is_size_bounded_and_limit_is_strictly_typed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = _canonical_temp_root(temp_dir)
            path = root / "corpora.lock.json"
            path.write_bytes(b"{" + b" " * 32 + b"}")
            with self.assertRaisesRegex(CorpusLockValidationError, "exceeds 16 bytes"):
                load_competitive_corpus_lock(path, max_bytes=16)

        for max_bytes in (True, 0, -1, 1.5):
            with self.subTest(max_bytes=max_bytes), tempfile.TemporaryDirectory() as temp_dir:
                path = _write_lock(_canonical_temp_root(temp_dir))
                with self.assertRaisesRegex(ValueError, "max_bytes"):
                    load_competitive_corpus_lock(
                        path,
                        max_bytes=max_bytes,  # type: ignore[arg-type]
                    )

    def test_rejects_invalid_utf8_json_and_non_object_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = _canonical_temp_root(temp_dir) / "corpora.lock.json"
            path.write_bytes(b"\xff")
            with self.assertRaisesRegex(CorpusLockValidationError, "UTF-8"):
                load_competitive_corpus_lock(path)

            path.write_text("{", encoding="utf-8")
            with self.assertRaisesRegex(CorpusLockValidationError, "invalid JSON"):
                load_competitive_corpus_lock(path)

            path.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(CorpusLockValidationError, "object"):
                load_competitive_corpus_lock(path)

    @unittest.skipUnless(
        SECURE_OPEN_SUPPORTED,
        "atomic no-follow descriptor traversal is unavailable",
    )
    def test_rejects_missing_directory_and_symlink_lock_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = _canonical_temp_root(temp_dir)
            with self.assertRaisesRegex(CorpusLockValidationError, "regular file"):
                load_competitive_corpus_lock(root / "missing.json")
            with self.assertRaisesRegex(CorpusLockValidationError, "regular file"):
                load_competitive_corpus_lock(root)

            target = _write_lock(root)
            link = root / "linked-lock.json"
            try:
                link.symlink_to(target)
            except OSError as exc:
                self.skipTest(f"symlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(CorpusLockValidationError, "symlink"):
                load_competitive_corpus_lock(link)

    @unittest.skipUnless(
        SECURE_OPEN_SUPPORTED,
        "atomic no-follow descriptor traversal is unavailable",
    )
    def test_rejects_explicit_symlink_in_caller_lock_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = _canonical_temp_root(temp_dir)
            real_parent = root / "real-parent"
            real_parent.mkdir()
            target = _write_lock(real_parent)
            linked_parent = root / "linked-parent"
            try:
                linked_parent.symlink_to(real_parent, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlink creation is unavailable: {exc}")

            with self.assertRaisesRegex(CorpusLockValidationError, "symlinks are forbidden"):
                load_competitive_corpus_lock(linked_parent / target.name)

    @unittest.skipUnless(
        SECURE_OPEN_SUPPORTED,
        "atomic no-follow descriptor traversal is unavailable",
    )
    def test_lock_swap_to_symlink_at_final_open_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = _canonical_temp_root(temp_dir)
            lock_path = _write_lock(root)
            original = root / "original-lock.json"
            attacker = root / "attacker-lock.json"
            _write_json(attacker, _payload())
            real_open = os.open
            swapped = False

            def swapping_open(
                path: str | bytes,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal swapped
                if (
                    not swapped
                    and os.fsdecode(path) == lock_path.name
                    and not flags & os.O_DIRECTORY
                ):
                    lock_path.rename(original)
                    lock_path.symlink_to(attacker)
                    swapped = True
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with (
                mock.patch.object(os, "open", swapping_open),
                self.assertRaisesRegex(CorpusLockValidationError, "securely open"),
            ):
                _secure_load_competitive_corpus_lock(lock_path)
            self.assertTrue(swapped)


class CompetitiveCorpusVerificationTests(unittest.TestCase):
    @unittest.skipUnless(
        SECURE_OPEN_SUPPORTED,
        "atomic no-follow descriptor traversal is unavailable",
    )
    def test_verifies_each_fd_once_with_bounded_reads_and_manifest_binding(
        self,
    ) -> None:
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            mock.patch.object(competitive_corpus, "MIN_PREPARED_BYTES", 1),
        ):
            root = _canonical_temp_root(temp_dir)
            _, corpus_root, lock_path, contents = _prepare_verification_tree(root)
            real_open = os.open
            real_read = os.read
            opened: Counter[str] = Counter()
            read_sizes: list[int] = []

            def tracked_open(
                path: str | bytes,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
                if dir_fd is not None and not flags & os.O_DIRECTORY:
                    opened[os.fsdecode(path)] += 1
                return descriptor

            def tracked_read(descriptor: int, size: int) -> bytes:
                read_sizes.append(size)
                return real_read(descriptor, size)

            with (
                mock.patch.object(os, "open", tracked_open),
                mock.patch.object(os, "read", tracked_read),
            ):
                result = verify_competitive_corpus(lock_path, corpus_root)

            expected_manifest_digest = _digest(lock_path.read_bytes())

        expected_opens = Counter({Path(path).name: 1 for path in contents})
        expected_opens[lock_path.name] = 1
        self.assertIsInstance(result, CompetitiveCorpusVerification)
        self.assertEqual(result.contract_id, EXPECTED_CONTRACT_ID)
        self.assertEqual(result.manifest_sha256, expected_manifest_digest)
        self.assertEqual(result.corpus_ids, REQUIRED_CORPUS_IDS)
        self.assertEqual(result.total_verified_bytes, sum(map(len, contents.values())))
        self.assertEqual(len(result.files), len(contents))
        self.assertEqual(opened, expected_opens)
        self.assertTrue(read_sizes)
        self.assertTrue(all(0 < size <= competitive_corpus.READ_CHUNK_BYTES for size in read_sizes))
        self.assertFalse(hasattr(result, "__dict__"))
        with self.assertRaises(FrozenInstanceError):
            result.manifest_sha256 = "changed"  # type: ignore[misc]

    @unittest.skipUnless(
        SECURE_OPEN_SUPPORTED,
        "atomic no-follow descriptor traversal is unavailable",
    )
    def test_rejects_short_long_and_same_length_digest_tampering(self) -> None:
        for failure in ("short", "long", "digest"):
            with (
                self.subTest(failure=failure),
                tempfile.TemporaryDirectory() as temp_dir,
                mock.patch.object(competitive_corpus, "MIN_PREPARED_BYTES", 1),
            ):
                lock, corpus_root, lock_path, _ = _prepare_verification_tree(
                    _canonical_temp_root(temp_dir)
                )
                target = corpus_root.joinpath(*lock.corpora[0].source.path.split("/"))
                original = target.read_bytes()
                if failure == "short":
                    target.write_bytes(original[:-1])
                    message = "byte length"
                elif failure == "long":
                    target.write_bytes(original + b"x")
                    message = "byte length"
                else:
                    target.write_bytes(b"x" * len(original))
                    message = "SHA-256"
                with self.assertRaisesRegex(CorpusVerificationError, message):
                    verify_competitive_corpus(lock_path, corpus_root)

    @unittest.skipUnless(
        SECURE_OPEN_SUPPORTED,
        "atomic no-follow descriptor traversal is unavailable",
    )
    def test_rejects_missing_files_directories_and_non_directory_parents(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            mock.patch.object(competitive_corpus, "MIN_PREPARED_BYTES", 1),
        ):
            lock, corpus_root, lock_path, _ = _prepare_verification_tree(
                _canonical_temp_root(temp_dir)
            )
            target = corpus_root.joinpath(*lock.corpora[0].source.path.split("/"))
            target.unlink()
            with self.assertRaisesRegex(CorpusVerificationError, "securely open"):
                verify_competitive_corpus(lock_path, corpus_root)

            target.mkdir()
            with self.assertRaisesRegex(CorpusVerificationError, "regular file"):
                verify_competitive_corpus(lock_path, corpus_root)

            target.rmdir()
            parent = target.parent
            for child in parent.iterdir():
                child.unlink()
            parent.rmdir()
            parent.write_bytes(b"not-a-directory")
            with self.assertRaisesRegex(CorpusVerificationError, "securely open"):
                verify_competitive_corpus(lock_path, corpus_root)

    @unittest.skipUnless(
        SECURE_OPEN_SUPPORTED,
        "atomic no-follow descriptor traversal is unavailable",
    )
    def test_rejects_final_and_intermediate_symlinks(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            mock.patch.object(competitive_corpus, "MIN_PREPARED_BYTES", 1),
        ):
            root = _canonical_temp_root(temp_dir)
            lock, corpus_root, lock_path, _ = _prepare_verification_tree(root)
            source = lock.corpora[0].source
            target = corpus_root.joinpath(*source.path.split("/"))
            outside = root / "outside.bin"
            outside.write_bytes(target.read_bytes())
            target.unlink()
            target.symlink_to(outside)
            with self.assertRaisesRegex(CorpusVerificationError, "securely open"):
                verify_competitive_corpus(lock_path, corpus_root)

            target.unlink()
            target.write_bytes(outside.read_bytes())
            source_directory = corpus_root / "sources"
            moved = corpus_root / "real-sources"
            source_directory.rename(moved)
            source_directory.symlink_to(moved, target_is_directory=True)
            with self.assertRaisesRegex(CorpusVerificationError, "securely open"):
                verify_competitive_corpus(lock_path, corpus_root)

    @unittest.skipUnless(
        SECURE_OPEN_SUPPORTED,
        "atomic no-follow descriptor traversal is unavailable",
    )
    def test_rejects_missing_file_and_symlink_verification_roots(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            mock.patch.object(competitive_corpus, "MIN_PREPARED_BYTES", 1),
        ):
            root = _canonical_temp_root(temp_dir)
            _, corpus_root, lock_path, _ = _prepare_verification_tree(root)
            with self.assertRaisesRegex(CorpusVerificationError, "securely open"):
                verify_competitive_corpus(lock_path, root / "missing-root")

            root_file = root / "root-file"
            root_file.write_bytes(b"x")
            with self.assertRaisesRegex(CorpusVerificationError, "directory"):
                verify_competitive_corpus(lock_path, root_file)

            root_link = root / "root-link"
            root_link.symlink_to(corpus_root, target_is_directory=True)
            with self.assertRaisesRegex(CorpusVerificationError, "securely open"):
                verify_competitive_corpus(lock_path, root_link)

    @unittest.skipUnless(
        SECURE_OPEN_SUPPORTED,
        "atomic no-follow descriptor traversal is unavailable",
    )
    def test_swap_to_symlink_at_final_open_fails_closed(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            mock.patch.object(competitive_corpus, "MIN_PREPARED_BYTES", 1),
        ):
            root = _canonical_temp_root(temp_dir)
            lock, corpus_root, lock_path, _ = _prepare_verification_tree(root)
            target = corpus_root.joinpath(*lock.corpora[0].source.path.split("/"))
            backup = root / "original-source.bin"
            outside = root / "attacker-source.bin"
            outside.write_bytes(target.read_bytes())
            real_open = os.open
            swapped = False

            def swapping_open(
                path: str | bytes,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal swapped
                if not swapped and os.fsdecode(path) == target.name and not flags & os.O_DIRECTORY:
                    target.rename(backup)
                    target.symlink_to(outside)
                    swapped = True
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with (
                mock.patch.object(os, "open", swapping_open),
                self.assertRaisesRegex(CorpusVerificationError, "securely open"),
            ):
                verify_competitive_corpus(lock_path, corpus_root)
            self.assertTrue(swapped)

    @unittest.skipUnless(
        SECURE_OPEN_SUPPORTED,
        "atomic no-follow descriptor traversal is unavailable",
    )
    def test_swap_to_symlink_at_intermediate_open_fails_closed(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            mock.patch.object(competitive_corpus, "MIN_PREPARED_BYTES", 1),
        ):
            root = _canonical_temp_root(temp_dir)
            _, corpus_root, lock_path, _ = _prepare_verification_tree(root)
            source_directory = corpus_root / "sources"
            backup = corpus_root / "sources-original"
            outside = root / "attacker-directory"
            outside.mkdir()
            real_open = os.open
            swapped = False

            def swapping_open(
                path: str | bytes,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                nonlocal swapped
                if not swapped and os.fsdecode(path) == "sources" and flags & os.O_DIRECTORY:
                    source_directory.rename(backup)
                    source_directory.symlink_to(outside, target_is_directory=True)
                    swapped = True
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with (
                mock.patch.object(os, "open", swapping_open),
                self.assertRaisesRegex(CorpusVerificationError, "securely open"),
            ):
                verify_competitive_corpus(lock_path, corpus_root)
            self.assertTrue(swapped)

    @unittest.skipUnless(
        SECURE_OPEN_SUPPORTED,
        "atomic no-follow descriptor traversal is unavailable",
    )
    def test_swap_after_open_hashes_the_original_lock_and_corpus_fds(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            mock.patch.object(competitive_corpus, "MIN_PREPARED_BYTES", 1),
        ):
            root = _canonical_temp_root(temp_dir)
            lock, corpus_root, lock_path, _ = _prepare_verification_tree(root)
            original_manifest = lock_path.read_bytes()
            source = corpus_root.joinpath(*lock.corpora[0].source.path.split("/"))
            source_backup = root / "opened-source.bin"
            lock_backup = root / "opened-lock.json"
            real_open = os.open
            swapped: set[str] = set()

            def swap_after_open(
                path: str | bytes,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
                name = os.fsdecode(path)
                if name == lock_path.name and name not in swapped:
                    lock_path.rename(lock_backup)
                    lock_path.write_bytes(b"attacker manifest")
                    swapped.add(name)
                elif name == source.name and name not in swapped:
                    source.rename(source_backup)
                    source.write_bytes(b"attacker corpus")
                    swapped.add(name)
                return descriptor

            with mock.patch.object(os, "open", swap_after_open):
                result = verify_competitive_corpus(lock_path, corpus_root)

        self.assertEqual(swapped, {lock_path.name, source.name})
        self.assertEqual(result.manifest_sha256, _digest(original_manifest))

    def test_rejects_forged_public_dataclasses_including_nested_fields(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            mock.patch.object(competitive_corpus, "MIN_PREPARED_BYTES", 1),
        ):
            lock, corpus_root, _, _ = _prepare_verification_tree(_canonical_temp_root(temp_dir))
            first = lock.corpora[0]
            forged_corpora = (
                replace(first, snapshot_id="forged-snapshot-123"),
                *lock.corpora[1:],
            )
            forged_preparation = replace(
                first,
                preparation=replace(first.preparation, recipe_id="forged-recipe-v2"),
            )
            forged_license = replace(
                first,
                license=replace(first.license, human_approver="Mallory Example"),
            )
            forged = (
                lock,
                replace(lock, manifest_sha256="0" * 64),
                replace(lock, corpora=forged_corpora),
                replace(lock, corpora=(forged_preparation, *lock.corpora[1:])),
                replace(lock, corpora=(forged_license, *lock.corpora[1:])),
            )
            for candidate in forged:
                with (
                    self.subTest(candidate=candidate),
                    self.assertRaisesRegex(TypeError, "lock_path"),
                ):
                    verify_competitive_corpus(  # type: ignore[arg-type]
                        candidate,
                        corpus_root,
                    )

    def test_requires_a_lock_path_not_an_arbitrary_object(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            self.assertRaisesRegex(TypeError, "lock_path"),
        ):
            verify_competitive_corpus(  # type: ignore[arg-type]
                {},
                _canonical_temp_root(temp_dir),
            )

    def test_rejects_invalid_root_and_lock_size_limit_before_platform_access(
        self,
    ) -> None:
        with self.assertRaisesRegex(TypeError, "root"):
            verify_competitive_corpus(Path("lock.json"), 7)  # type: ignore[arg-type]
        for max_lock_bytes in (True, 0, -1):
            with (
                self.subTest(max_lock_bytes=max_lock_bytes),
                self.assertRaisesRegex(ValueError, "max_lock_bytes"),
            ):
                verify_competitive_corpus(
                    Path("lock.json"),
                    Path("corpus"),
                    max_lock_bytes=max_lock_bytes,  # type: ignore[arg-type]
                )


class UnsupportedSecureAccessTests(unittest.TestCase):
    @unittest.skipIf(
        SECURE_OPEN_SUPPORTED,
        "host provides atomic no-follow descriptor traversal",
    )
    def test_public_lock_loading_and_verification_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = _canonical_temp_root(temp_dir)
            lock_path = _write_lock(root)
            corpus_root = root / "corpus"
            corpus_root.mkdir()
            with self.assertRaisesRegex(CorpusLockValidationError, "atomic no-follow"):
                _secure_load_competitive_corpus_lock(lock_path)
            with self.assertRaisesRegex(CorpusVerificationError, "atomic no-follow"):
                verify_competitive_corpus(lock_path, corpus_root)


if __name__ == "__main__":
    unittest.main()
