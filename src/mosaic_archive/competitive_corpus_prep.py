"""Offline, non-binding preparation foundation for competitive corpus inputs.

This module never downloads, extracts, approves, or emits a binding corpus lock.
It only loads an exact acquisition plan and, on hosts with the required POSIX
primitives, verifies one already-local source file before publishing an exact
byte-for-byte copy atomically.

Fields named as approvals in the input schema are parsed only as unverified plan
claims. Loading or using them does not verify legal authority, create an approval,
or make any result binding.

Verified/prepared record provenance is tracked in a process-local issuance registry
to reject accidental use of caller-constructed, copied, replaced, or deserialized
records. This is misuse hardening, not a Python security or authority boundary:
callers that can mutate private module state or patch process internals remain inside
the same trust boundary. Publication checks describe the inode at their last
successful observation; a same-UID writer can mutate an ordinary filesystem inode
afterward, so consumers that need immutable bytes must use a sealed reopen snapshot.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import re
import stat
import sys
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Final, Literal, NoReturn, TypeVar, cast
from urllib.parse import urlsplit
from weakref import WeakValueDictionary

from mosaic_archive.competitive_corpus import REQUIRED_CORPUS_IDS

SCHEMA_VERSION: Final = 1
EXPECTED_PLAN_ID: Final = "mosaic-competitive-acquisition-plan-v1"
MAX_PLAN_BYTES: Final = 1_048_576
MAX_JSON_NESTING: Final = 64
MAX_JSON_INTEGER_DIGITS: Final = 20
MAX_TEXT_BYTES: Final = 4_096
MAX_SOURCE_BYTES: Final = 16 * 1024**3
# Sealed snapshots are intentionally memory-bounded. This covers the 100,000,000-byte
# enwik8 input, while larger future locked corpora need an explicitly designed
# disk-backed immutable handoff rather than an unbounded memfd allocation.
MAX_REOPEN_SNAPSHOT_BYTES: Final = 128 * 1024**2
READ_CHUNK_BYTES: Final = 1_048_576
COPY_RECIPE_ID: Final = "deterministic-copy"
COPY_RECIPE_VERSION: Final = 1
_COPY_RECIPE_IMPLEMENTATION_SPEC: Final = (
    b"mosaic-competitive-deterministic-copy\n"
    b"version=1\n"
    b"input=one-verified-regular-file-with-one-link\n"
    b"output=byte-for-byte-copy\n"
    b"metadata=not-copied\n"
    b"publication=atomic-no-overwrite\n"
)
COPY_RECIPE_IMPLEMENTATION_SHA256: Final = hashlib.sha256(
    _COPY_RECIPE_IMPLEMENTATION_SPEC
).hexdigest()

_TOP_LEVEL_KEYS: Final = frozenset({"schema_version", "plan_id", "binding", "corpora"})
_DESCRIPTOR_KEYS: Final = frozenset(
    {
        "id",
        "status",
        "blocked_reason",
        "source_url",
        "expected_source_bytes",
        "expected_source_sha256",
        "input_kind",
        "recipe",
        "member_manifest_sha256",
        "license_evidence_sha256",
        "benchmark_use_approved",
        "redistribution_approved",
        "approval_record",
    }
)
_RECIPE_KEYS: Final = frozenset({"id", "version", "implementation_sha256"})
_APPROVAL_RECORD_KEYS: Final = frozenset({"identity", "sha256"})
_SHA256_RE: Final = re.compile(r"[0-9a-f]{64}\Z")
_STABLE_ID_RE: Final = re.compile(r"[a-z0-9][a-z0-9._-]{2,127}\Z")
_WINDOWS_PLAN_CTIME_UNSTABLE: Final = os.name == "nt"

AcquisitionStatus = Literal["blocked", "unverified_technical_copy"]
InputKind = Literal["single_file", "aggregate_bundle"]
PublicationState = Literal[
    "not_committed",
    "commit_outcome_unknown",
    "committed_not_durable",
    "committed_name_unavailable",
    "durable",
]


class AcquisitionPlanValidationError(ValueError):
    """Raised when an acquisition plan is not exact and fail-closed."""


class CorpusPreparationError(ValueError):
    """Raised when local verification or preparation cannot complete safely."""


@dataclass(frozen=True, slots=True)
class _DescriptorCleanupFailure:
    role: str
    error: BaseException


class AcquisitionPlanCleanupError(AcquisitionPlanValidationError):
    """A plan read and one or more descriptor closes both failed."""

    def __init__(
        self,
        context: str,
        *,
        primary_error: BaseException | None,
        cleanup_failures: tuple[_DescriptorCleanupFailure, ...],
    ) -> None:
        self.primary_error = primary_error
        self.cleanup_failures = cleanup_failures
        detail = "; ".join(
            f"{failure.role}: {type(failure.error).__name__}: {failure.error}"
            for failure in cleanup_failures
        )
        primary = (
            "none" if primary_error is None else f"{type(primary_error).__name__}: {primary_error}"
        )
        super().__init__(f"{context}; primary={primary}; descriptor cleanup={detail}")


class CorpusPublicationDurabilityError(CorpusPreparationError):
    """Publication committed, but destination-directory durability is unconfirmed."""

    committed: Final = True
    durable: Final = False

    def __init__(
        self,
        message: str,
        *,
        prepared: PreparedLocalCorpus,
    ) -> None:
        self.publication_state: PublicationState = "committed_not_durable"
        self.prepared = prepared
        super().__init__(message)


class CorpusPublicationNotCommittedError(CorpusPreparationError):
    """A known publication primitive failure that created no destination link."""

    committed: Final = False
    durable: Final = False
    publication_state: Final[PublicationState] = "not_committed"


class CorpusPublicationOutcomeUnknownError(CorpusPreparationError):
    """The commit syscall was attempted, but its outcome could not be inspected."""

    committed: Final = None
    durable: Final = False

    def __init__(
        self,
        *,
        operation_error: BaseException,
        inspection_error: BaseException | None,
        candidate: PreparedLocalCorpus,
    ) -> None:
        self.publication_state: PublicationState = "commit_outcome_unknown"
        self.operation_error = operation_error
        self.inspection_error = inspection_error
        self.candidate = candidate
        inspection_detail = (
            "the anonymous inode had no remaining link"
            if inspection_error is None
            else f"inspection failed with {type(inspection_error).__name__}: {inspection_error}"
        )
        super().__init__(
            "publication commit outcome is unknown after an unclassified commit-attempt "
            f"failure; {inspection_detail}; no pathname rollback was attempted"
        )


class CorpusPublicationNameUnavailableError(CorpusPreparationError):
    """The commit occurred, but the fsynced destination name no longer binds it."""

    committed: Final = True
    durable: Final = False
    name_bound: Final = False

    def __init__(
        self,
        message: str,
        *,
        prepared: PreparedLocalCorpus,
    ) -> None:
        self.publication_state: PublicationState = "committed_name_unavailable"
        self.prepared = prepared
        self.directory_fsync_completed = True
        super().__init__(message)


class CorpusPreparationCleanupError(CorpusPreparationError):
    """An operation and/or one or more independent descriptor closes failed."""

    def __init__(
        self,
        context: str,
        *,
        primary_error: BaseException | None,
        cleanup_failures: tuple[_DescriptorCleanupFailure, ...],
        publication_state: PublicationState,
        prepared: PreparedLocalCorpus | None,
    ) -> None:
        self.primary_error = primary_error
        self.cleanup_failures = cleanup_failures
        self.cleanup_errors = tuple(failure.error for failure in cleanup_failures)
        self.publication_state = publication_state
        self.prepared = prepared
        cleanup_detail = "; ".join(
            f"{failure.role}: {type(failure.error).__name__}: {failure.error}"
            for failure in cleanup_failures
        )
        primary_detail = (
            "none" if primary_error is None else f"{type(primary_error).__name__}: {primary_error}"
        )
        super().__init__(
            f"{context}; publication_state={publication_state}; "
            f"primary={primary_detail}; descriptor cleanup={cleanup_detail}"
        )


@dataclass(frozen=True, slots=True)
class PreparationRecipeIdentity:
    """Frozen identity of the only preparation recipe implemented here."""

    id: str
    version: int
    implementation_sha256: str


@dataclass(frozen=True, slots=True)
class UnverifiedApprovalRecordClaim:
    """A hash-shaped approval-record claim copied from the untrusted plan."""

    identity_claim: str
    sha256_claim: str
    externally_verified: Literal[False] = field(default=False, init=False)
    binding: Literal[False] = field(default=False, init=False)


@dataclass(frozen=True, slots=True)
class UnverifiedApprovalClaims:
    """Self-asserted approval values that carry no external authority."""

    benchmark_use_claim: bool
    redistribution_claim: bool
    record_claim: UnverifiedApprovalRecordClaim | None
    externally_verified: Literal[False] = field(default=False, init=False)
    binding: Literal[False] = field(default=False, init=False)


@dataclass(frozen=True, slots=True)
class CorpusAcquisitionDescriptor:
    """One non-binding acquisition/preparation descriptor."""

    id: str
    status: AcquisitionStatus
    blocked_reason: str | None
    source_url: str | None
    expected_source_bytes: int | None
    expected_source_sha256: str | None
    input_kind: InputKind
    recipe: PreparationRecipeIdentity
    member_manifest_sha256: str | None
    license_evidence_sha256_claim: str | None
    unverified_approval_claims: UnverifiedApprovalClaims


@dataclass(frozen=True, slots=True)
class CompetitiveAcquisitionPlan:
    """Parsed non-binding plan plus the SHA-256 of its exact JSON bytes."""

    schema_version: int
    plan_id: str
    corpora: tuple[CorpusAcquisitionDescriptor, ...]
    plan_sha256: str
    binding: Literal[False] = field(default=False, init=False)


@dataclass(frozen=True, slots=True)
class LocalFileIdentity:
    """Descriptor-derived directory-entry identity; pathnames are not authority."""

    parent_device: int
    parent_inode: int
    file_device: int
    file_inode: int


@dataclass(frozen=True, slots=True, weakref_slot=True)
class VerifiedLocalSource:
    """Identity verified from one open file; ``display_path`` is display-only."""

    corpus_id: str
    display_path: Path
    identity: LocalFileIdentity
    bytes: int
    sha256: str
    plan_sha256: str
    binding: Literal[False] = field(default=False, init=False)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class PreparedLocalCorpus:
    """A descriptor-bound copy result; ``display_path`` is display-only."""

    corpus_id: str
    display_path: Path
    identity: LocalFileIdentity
    bytes: int
    sha256: str
    source_sha256: str
    recipe_id: str
    recipe_version: int
    recipe_implementation_sha256: str
    plan_sha256: str
    publication_state: PublicationState
    binding: Literal[False] = field(default=False, init=False)


_IssuedRecord = VerifiedLocalSource | PreparedLocalCorpus
_IssuedRecordT = TypeVar(
    "_IssuedRecordT",
    VerifiedLocalSource,
    PreparedLocalCorpus,
)
_ISSUED_RECORDS: WeakValueDictionary[int, _IssuedRecord] = WeakValueDictionary()


def _issue_record(record: _IssuedRecordT) -> _IssuedRecordT:
    _ISSUED_RECORDS[id(record)] = record
    return record


def _require_issued_record(record: _IssuedRecord) -> None:
    if _ISSUED_RECORDS.get(id(record)) is not record:
        raise CorpusPreparationError(
            "record was not issued by this process or was copied/replaced; "
            "record provenance cannot be established"
        )


def _duplicate_rejecting_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AcquisitionPlanValidationError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> NoReturn:
    raise AcquisitionPlanValidationError(f"non-finite JSON constant is forbidden: {value}")


def _reject_json_float(value: str) -> NoReturn:
    raise AcquisitionPlanValidationError(f"floating-point JSON number is forbidden: {value}")


def _parse_json_int(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > MAX_JSON_INTEGER_DIGITS:
        raise AcquisitionPlanValidationError(
            f"JSON integer exceeds the maximum of {MAX_JSON_INTEGER_DIGITS} digits"
        )
    try:
        return int(value)
    except ValueError as exc:
        raise AcquisitionPlanValidationError("invalid JSON integer") from exc


def _validate_json_nesting(text: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_NESTING:
                raise AcquisitionPlanValidationError(
                    f"JSON nesting exceeds the maximum depth of {MAX_JSON_NESTING}"
                )
        elif character in "]}":
            depth = max(0, depth - 1)


def _close_descriptors_independently(
    descriptors: tuple[tuple[str, int | None], ...],
) -> tuple[_DescriptorCleanupFailure, ...]:
    failures: list[_DescriptorCleanupFailure] = []
    for role, descriptor in descriptors:
        if descriptor is None:
            continue
        try:
            os.close(descriptor)
        except BaseException as exc:
            failures.append(_DescriptorCleanupFailure(role=role, error=exc))
    return tuple(failures)


def _raise_operation_or_cleanup(
    context: str,
    *,
    primary_error: BaseException | None,
    cleanup_failures: tuple[_DescriptorCleanupFailure, ...],
    domain: Literal["plan", "corpus"],
    publication_state: PublicationState = "not_committed",
    prepared: PreparedLocalCorpus | None = None,
) -> None:
    if not cleanup_failures:
        if primary_error is not None:
            raise primary_error.with_traceback(primary_error.__traceback__)
        return

    all_errors = (() if primary_error is None else (primary_error,)) + tuple(
        failure.error for failure in cleanup_failures
    )
    if all(isinstance(error, Exception) for error in all_errors):
        if domain == "plan":
            raise AcquisitionPlanCleanupError(
                context,
                primary_error=primary_error,
                cleanup_failures=cleanup_failures,
            ) from cleanup_failures[-1].error
        raise CorpusPreparationCleanupError(
            context,
            primary_error=primary_error,
            cleanup_failures=cleanup_failures,
            publication_state=publication_state,
            prepared=prepared,
        ) from cleanup_failures[-1].error

    roles = ", ".join(failure.role for failure in cleanup_failures)
    group = BaseExceptionGroup(
        f"{context}; publication_state={publication_state}; descriptor cleanup roles={roles}",
        list(all_errors),
    )
    if prepared is not None:
        group.add_note(
            "A descriptor-bound PreparedLocalCorpus record is attached only to the "
            "operation's domain exception, if present; no pathname rollback was attempted."
        )
    raise group from cleanup_failures[-1].error


def _local_file_identity(
    file_metadata: os.stat_result,
    parent_metadata: os.stat_result,
) -> LocalFileIdentity:
    return LocalFileIdentity(
        parent_device=parent_metadata.st_dev,
        parent_inode=parent_metadata.st_ino,
        file_device=file_metadata.st_dev,
        file_inode=file_metadata.st_ino,
    )


def _identity_matches(metadata: os.stat_result, *, device: int, inode: int) -> bool:
    return metadata.st_dev == device and metadata.st_ino == inode


def _metadata_changed(before: os.stat_result, after: os.stat_result) -> bool:
    fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    return any(getattr(before, field) != getattr(after, field) for field in fields)


def _plan_metadata_changed(before: os.stat_result, after: os.stat_result) -> bool:
    fields: tuple[str, ...] = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
    )
    if not _WINDOWS_PLAN_CTIME_UNSTABLE:
        fields += ("st_ctime_ns",)
    return any(getattr(before, field) != getattr(after, field) for field in fields)


def _publication_link_metadata_changed(
    before_link: os.stat_result,
    after_link: os.stat_result,
) -> bool:
    fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_size",
        "st_mtime_ns",
    )
    # The link operation itself must change st_nlink and may update st_ctime_ns.
    # The post-link metadata becomes the continuity baseline for both fields.
    return (
        before_link.st_nlink != 0
        or after_link.st_nlink != 1
        or any(getattr(before_link, field) != getattr(after_link, field) for field in fields)
    )


def _is_reparse_point(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(reparse_flag and attributes & reparse_flag)


def _read_plan_descriptor_bounded(descriptor: int, max_bytes: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    remaining = max_bytes + 1
    chunks: list[bytes] = []
    while remaining:
        chunk = os.read(descriptor, min(READ_CHUNK_BYTES, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    if len(raw) > max_bytes:
        raise AcquisitionPlanValidationError(f"acquisition plan exceeds {max_bytes} bytes")
    return raw


def _read_plan_bytes(path: Path, max_bytes: int) -> bytes:
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_PLAN_BYTES:
        raise AcquisitionPlanValidationError(
            f"max_bytes must be an integer from 1 through {MAX_PLAN_BYTES}"
        )
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise AcquisitionPlanValidationError(
            "acquisition plan must be an existing regular file"
        ) from exc
    if not stat.S_ISREG(before.st_mode) or _is_reparse_point(before) or before.st_nlink != 1:
        detail = "hardlinks are forbidden" if before.st_nlink != 1 else "regular file required"
        raise AcquisitionPlanValidationError(
            f"acquisition plan is not an independent regular file; {detail}"
        )
    if before.st_size > max_bytes:
        raise AcquisitionPlanValidationError(f"acquisition plan exceeds {max_bytes} bytes")

    flags = (
        os.O_RDONLY
        | int(getattr(os, "O_BINARY", 0))
        | int(getattr(os, "O_CLOEXEC", 0))
        | int(getattr(os, "O_NOFOLLOW", 0))
        | int(getattr(os, "O_NONBLOCK", 0))
    )
    descriptor: int | None = None
    raw: bytes | None = None
    primary_error: BaseException | None = None
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse_point(opened)
            or opened.st_nlink != 1
            or not os.path.samestat(before, opened)
        ):
            raise AcquisitionPlanValidationError(
                "acquisition plan changed or became a symlink/hardlink while opening"
            )
        if _plan_metadata_changed(before, opened):
            raise AcquisitionPlanValidationError(
                "acquisition plan changed while it was being opened"
            )
        raw = _read_plan_descriptor_bounded(descriptor, max_bytes)
        after_first_read = os.fstat(descriptor)
        if _plan_metadata_changed(opened, after_first_read):
            raise AcquisitionPlanValidationError("acquisition plan changed while it was being read")
        confirmed_raw = _read_plan_descriptor_bounded(descriptor, max_bytes)
        after_second_read = os.fstat(descriptor)
        if raw != confirmed_raw or _plan_metadata_changed(
            after_first_read,
            after_second_read,
        ):
            raise AcquisitionPlanValidationError(
                "acquisition plan changed between two exact bounded reads"
            )
    except AcquisitionPlanValidationError as exc:
        primary_error = exc
    except OSError as exc:
        primary_error = AcquisitionPlanValidationError("could not safely read acquisition plan")
        primary_error.__cause__ = exc
    except BaseException as exc:
        primary_error = exc

    cleanup_failures = _close_descriptors_independently((("acquisition plan", descriptor),))
    _raise_operation_or_cleanup(
        "acquisition plan read/close failed",
        primary_error=primary_error,
        cleanup_failures=cleanup_failures,
        domain="plan",
    )
    assert raw is not None
    return raw


def _expect_object(
    value: object,
    expected_keys: frozenset[str],
    context: str,
) -> dict[str, object]:
    if type(value) is not dict:
        raise AcquisitionPlanValidationError(f"{context} must be a JSON object")
    result = cast(dict[str, object], value)
    keys = frozenset(result)
    if keys != expected_keys:
        missing = sorted(expected_keys - keys)
        extra = sorted(keys - expected_keys)
        raise AcquisitionPlanValidationError(
            f"{context} keys are not exact; missing={missing}, extra={extra}"
        )
    return result


def _expect_array(value: object, context: str) -> list[object]:
    if type(value) is not list:
        raise AcquisitionPlanValidationError(f"{context} must be a JSON array")
    return cast(list[object], value)


def _expect_string(value: object, context: str) -> str:
    if type(value) is not str:
        raise AcquisitionPlanValidationError(f"{context} must be a string")
    result = value
    if (
        not result
        or result.strip() != result
        or any(0xD800 <= ord(character) <= 0xDFFF for character in result)
        or len(result.encode("utf-8")) > MAX_TEXT_BYTES
        or unicodedata.normalize("NFC", result) != result
        or any(unicodedata.category(character) in {"Cc", "Cf"} for character in result)
    ):
        raise AcquisitionPlanValidationError(
            f"{context} must be a bounded canonical string without control characters"
        )
    return result


def _expect_optional_string(value: object, context: str) -> str | None:
    if value is None:
        return None
    return _expect_string(value, context)


def _expect_bool(value: object, context: str) -> bool:
    if type(value) is not bool:
        raise AcquisitionPlanValidationError(f"{context} must be a boolean")
    return value


def _expect_optional_positive_int(value: object, context: str) -> int | None:
    if value is None:
        return None
    if type(value) is not int or not 1 <= value <= MAX_SOURCE_BYTES:
        raise AcquisitionPlanValidationError(
            f"{context} must be an integer from 1 through {MAX_SOURCE_BYTES}"
        )
    return value


def _expect_sha256(value: object, context: str) -> str:
    result = _expect_string(value, context)
    if _SHA256_RE.fullmatch(result) is None:
        raise AcquisitionPlanValidationError(f"{context} must be a lowercase SHA-256 digest")
    return result


def _expect_optional_sha256(value: object, context: str) -> str | None:
    if value is None:
        return None
    return _expect_sha256(value, context)


def _expect_stable_id(value: object, context: str) -> str:
    result = _expect_string(value, context)
    if _STABLE_ID_RE.fullmatch(result) is None:
        raise AcquisitionPlanValidationError(f"{context} must be a lowercase stable identifier")
    return result


def _expect_source_url(value: object, context: str) -> str | None:
    if value is None:
        return None
    result = _expect_string(value, context)
    try:
        parsed = urlsplit(result)
        port = parsed.port
    except ValueError as exc:
        raise AcquisitionPlanValidationError(f"{context} must be a safe HTTPS URL") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
        or parsed.path == "/"
        or any(character.isspace() for character in result)
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise AcquisitionPlanValidationError(f"{context} must be a safe HTTPS URL")
    return result


def _parse_recipe(value: object, context: str) -> PreparationRecipeIdentity:
    raw = _expect_object(value, _RECIPE_KEYS, context)
    recipe_id = _expect_stable_id(raw["id"], f"{context}.id")
    version = raw["version"]
    if type(version) is not int or version != COPY_RECIPE_VERSION:
        raise AcquisitionPlanValidationError(
            f"{context}.version must be exactly {COPY_RECIPE_VERSION}"
        )
    implementation_sha256 = _expect_sha256(
        raw["implementation_sha256"],
        f"{context}.implementation_sha256",
    )
    if recipe_id != COPY_RECIPE_ID:
        raise AcquisitionPlanValidationError(f"{context}.id must be exactly {COPY_RECIPE_ID!r}")
    if implementation_sha256 != COPY_RECIPE_IMPLEMENTATION_SHA256:
        raise AcquisitionPlanValidationError(
            f"{context}.implementation_sha256 is not the implemented recipe identity"
        )
    return PreparationRecipeIdentity(
        id=recipe_id,
        version=version,
        implementation_sha256=implementation_sha256,
    )


def _parse_approval_record(
    value: object,
    context: str,
) -> UnverifiedApprovalRecordClaim | None:
    if value is None:
        return None
    raw = _expect_object(value, _APPROVAL_RECORD_KEYS, context)
    sha256 = _expect_sha256(raw["sha256"], f"{context}.sha256")
    identity = _expect_string(raw["identity"], f"{context}.identity")
    if identity != f"sha256:{sha256}":
        raise AcquisitionPlanValidationError(
            f"{context}.identity must be hash-bound as sha256:<sha256>"
        )
    return UnverifiedApprovalRecordClaim(
        identity_claim=identity,
        sha256_claim=sha256,
    )


def _parse_descriptor(
    value: object,
    index: int,
) -> CorpusAcquisitionDescriptor:
    context = f"corpora[{index}]"
    raw = _expect_object(value, _DESCRIPTOR_KEYS, context)
    corpus_id = _expect_stable_id(raw["id"], f"{context}.id")
    status_raw = _expect_string(raw["status"], f"{context}.status")
    if status_raw not in {"blocked", "runnable"}:
        raise AcquisitionPlanValidationError(f"{context}.status must be 'blocked' or 'runnable'")
    status: AcquisitionStatus = (
        "blocked" if status_raw == "blocked" else "unverified_technical_copy"
    )
    blocked_reason = _expect_optional_string(
        raw["blocked_reason"],
        f"{context}.blocked_reason",
    )
    source_url = _expect_source_url(raw["source_url"], f"{context}.source_url")
    expected_source_bytes = _expect_optional_positive_int(
        raw["expected_source_bytes"],
        f"{context}.expected_source_bytes",
    )
    expected_source_sha256 = _expect_optional_sha256(
        raw["expected_source_sha256"],
        f"{context}.expected_source_sha256",
    )
    input_kind_raw = _expect_string(raw["input_kind"], f"{context}.input_kind")
    if input_kind_raw not in {"single_file", "aggregate_bundle"}:
        raise AcquisitionPlanValidationError(
            f"{context}.input_kind must be 'single_file' or 'aggregate_bundle'"
        )
    input_kind = cast(InputKind, input_kind_raw)
    recipe = _parse_recipe(raw["recipe"], f"{context}.recipe")
    member_manifest_sha256 = _expect_optional_sha256(
        raw["member_manifest_sha256"],
        f"{context}.member_manifest_sha256",
    )
    license_evidence_sha256_claim = _expect_optional_sha256(
        raw["license_evidence_sha256"],
        f"{context}.license_evidence_sha256",
    )
    benchmark_use_claim = _expect_bool(
        raw["benchmark_use_approved"],
        f"{context}.benchmark_use_approved",
    )
    redistribution_claim = _expect_bool(
        raw["redistribution_approved"],
        f"{context}.redistribution_approved",
    )
    approval_record_claim = _parse_approval_record(
        raw["approval_record"],
        f"{context}.approval_record",
    )
    if (benchmark_use_claim or redistribution_claim) and approval_record_claim is None:
        raise AcquisitionPlanValidationError(
            f"{context}.approval_record is required for every unverified approval claim"
        )

    if status == "blocked":
        if blocked_reason is None:
            raise AcquisitionPlanValidationError(
                f"{context}.blocked_reason is required for a blocked descriptor"
            )
    else:
        missing: list[str] = []
        if blocked_reason is not None:
            missing.append("blocked_reason must be null")
        if source_url is None:
            missing.append("source_url")
        if expected_source_bytes is None:
            missing.append("expected_source_bytes")
        if expected_source_sha256 is None:
            missing.append("expected_source_sha256")
        if license_evidence_sha256_claim is None:
            missing.append("license_evidence_sha256")
        if not benchmark_use_claim:
            missing.append("benchmark_use_approved claim must be true")
        if not redistribution_claim:
            missing.append("redistribution_approved claim must be true")
        if approval_record_claim is None:
            missing.append("approval_record")
        if input_kind == "aggregate_bundle" and member_manifest_sha256 is None:
            missing.append("member_manifest_sha256")
        if missing:
            raise AcquisitionPlanValidationError(
                f"{context} unverified technical-copy descriptor is incomplete: "
                f"{', '.join(missing)}"
            )
        assert source_url is not None
        assert expected_source_sha256 is not None
        path_segments = urlsplit(source_url).path.split("/")
        if expected_source_sha256 not in path_segments:
            raise AcquisitionPlanValidationError(
                f"{context}.source_url must contain expected_source_sha256 "
                "as an exact content-addressed path segment"
            )

    if input_kind == "single_file" and member_manifest_sha256 is not None:
        raise AcquisitionPlanValidationError(
            f"{context}.member_manifest_sha256 must be null for single_file input"
        )

    return CorpusAcquisitionDescriptor(
        id=corpus_id,
        status=status,
        blocked_reason=blocked_reason,
        source_url=source_url,
        expected_source_bytes=expected_source_bytes,
        expected_source_sha256=expected_source_sha256,
        input_kind=input_kind,
        recipe=recipe,
        member_manifest_sha256=member_manifest_sha256,
        license_evidence_sha256_claim=license_evidence_sha256_claim,
        unverified_approval_claims=UnverifiedApprovalClaims(
            benchmark_use_claim=benchmark_use_claim,
            redistribution_claim=redistribution_claim,
            record_claim=approval_record_claim,
        ),
    )


def load_acquisition_plan(
    path: Path,
    *,
    max_bytes: int = MAX_PLAN_BYTES,
) -> CompetitiveAcquisitionPlan:
    """Load an exact bounded acquisition plan that can never be binding evidence."""

    raw_bytes = _read_plan_bytes(Path(path), max_bytes)
    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        raise AcquisitionPlanValidationError("UTF-8 BOM is forbidden")
    try:
        text = raw_bytes.decode("utf-8", errors="strict")
        _validate_json_nesting(text)
        parsed = json.loads(
            text,
            object_pairs_hook=_duplicate_rejecting_object,
            parse_constant=_reject_json_constant,
            parse_float=_reject_json_float,
            parse_int=_parse_json_int,
        )
    except AcquisitionPlanValidationError:
        raise
    except RecursionError as exc:
        raise AcquisitionPlanValidationError(
            f"JSON nesting exceeds the maximum depth of {MAX_JSON_NESTING}"
        ) from exc
    except (UnicodeDecodeError, ValueError) as exc:
        raise AcquisitionPlanValidationError("acquisition plan must be strict UTF-8 JSON") from exc

    top = _expect_object(parsed, _TOP_LEVEL_KEYS, "acquisition plan")
    schema_version = top["schema_version"]
    if type(schema_version) is not int or schema_version != SCHEMA_VERSION:
        raise AcquisitionPlanValidationError(f"schema_version must be exactly {SCHEMA_VERSION}")
    plan_id = _expect_stable_id(top["plan_id"], "plan_id")
    if plan_id != EXPECTED_PLAN_ID:
        raise AcquisitionPlanValidationError(f"plan_id must be exactly {EXPECTED_PLAN_ID!r}")
    binding = _expect_bool(top["binding"], "binding")
    if binding:
        raise AcquisitionPlanValidationError("binding must be exactly false")
    raw_corpora = _expect_array(top["corpora"], "corpora")
    descriptors = tuple(_parse_descriptor(value, index) for index, value in enumerate(raw_corpora))
    ids = tuple(descriptor.id for descriptor in descriptors)
    if (
        len(ids) != len(REQUIRED_CORPUS_IDS)
        or len(set(ids)) != len(ids)
        or set(ids) != set(REQUIRED_CORPUS_IDS)
    ):
        raise AcquisitionPlanValidationError(
            "corpus IDs must contain exactly the six contract corpus IDs"
        )
    by_id = {descriptor.id: descriptor for descriptor in descriptors}
    canonical = tuple(by_id[corpus_id] for corpus_id in REQUIRED_CORPUS_IDS)
    return CompetitiveAcquisitionPlan(
        schema_version=schema_version,
        plan_id=plan_id,
        corpora=canonical,
        plan_sha256=hashlib.sha256(raw_bytes).hexdigest(),
    )


def secure_local_preparation_supported() -> bool:
    """Return whether secure preparation plus sealed snapshot reopen is available."""

    if os.name != "posix" or not sys.platform.startswith("linux"):
        return False
    required_flags = ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
    dir_fd_functions = (os.open, os.stat)
    try:
        import fcntl

        library = ctypes.CDLL(None, use_errno=True)
    except (ImportError, OSError):
        return False
    sealing_constants = (
        "F_ADD_SEALS",
        "F_GET_SEALS",
        "F_SEAL_SEAL",
        "F_SEAL_SHRINK",
        "F_SEAL_GROW",
        "F_SEAL_WRITE",
    )
    return (
        all(
            type(getattr(os, name, None)) is int and getattr(os, name) != 0
            for name in required_flags
        )
        and type(getattr(os, "O_TMPFILE", None)) is int
        and getattr(os, "O_TMPFILE", 0) != 0
        and getattr(library, "linkat", None) is not None
        and all(function in os.supports_dir_fd for function in dir_fd_functions)
        and os.stat in os.supports_follow_symlinks
        and callable(getattr(os, "memfd_create", None))
        and type(getattr(os, "MFD_CLOEXEC", None)) is int
        and type(getattr(os, "MFD_ALLOW_SEALING", None)) is int
        and all(type(getattr(fcntl, name, None)) is int for name in sealing_constants)
    )


def _require_secure_preparation() -> None:
    if not secure_local_preparation_supported():
        raise CorpusPreparationError(
            "atomic no-follow local preparation is unavailable on this platform"
        )


def _os_open_flag(name: str) -> int:
    value = getattr(os, name, None)
    if type(value) is not int:
        raise RuntimeError(f"required secure-open flag disappeared: {name}")
    return value


def _required_os_constant(name: str) -> int:
    value = getattr(os, name, None)
    if type(value) is not int:
        raise CorpusPreparationError(f"required Linux snapshot constant is unavailable: {name}")
    return value


def _snapshot_sealing_constants() -> tuple[int, int, int]:
    try:
        import fcntl
    except ImportError as exc:
        raise CorpusPreparationError("Linux file sealing is unavailable") from exc

    names = (
        "F_ADD_SEALS",
        "F_GET_SEALS",
        "F_SEAL_SEAL",
        "F_SEAL_SHRINK",
        "F_SEAL_GROW",
        "F_SEAL_WRITE",
    )
    values = tuple(getattr(fcntl, name, None) for name in names)
    if any(type(value) is not int for value in values):
        raise CorpusPreparationError("required Linux file-sealing constants are unavailable")
    add_seals, get_seals, *seal_values = cast(tuple[int, ...], values)
    seal_mask = 0
    for value in seal_values:
        seal_mask |= value
    return add_seals, get_seals, seal_mask


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | _os_open_flag("O_CLOEXEC")
        | _os_open_flag("O_DIRECTORY")
        | _os_open_flag("O_NOFOLLOW")
    )


def _regular_read_flags() -> int:
    return (
        os.O_RDONLY
        | _os_open_flag("O_CLOEXEC")
        | _os_open_flag("O_NOFOLLOW")
        | _os_open_flag("O_NONBLOCK")
    )


def _secure_path_parts(
    path: Path,
    context: str,
    *,
    allow_anchor_only: bool,
) -> tuple[str, tuple[str, ...]]:
    path_text = os.fspath(path)
    if not path_text or "\x00" in path_text or path_text.startswith("//") or "\\" in path_text:
        raise CorpusPreparationError(f"{context} must be a normalized local path")
    if path_text in {"/", "."}:
        if not allow_anchor_only:
            raise CorpusPreparationError(f"{context} must name a regular file")
        return path_text, ()
    absolute = path_text.startswith("/")
    raw_parts = path_text.split("/")
    parts = raw_parts[1:] if absolute else raw_parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise CorpusPreparationError(f"{context} must be a normalized local path")
    return ("/" if absolute else "."), tuple(parts)


@dataclass(frozen=True, slots=True)
class _SecureOpenedRegular:
    file_descriptor: int
    file_metadata: os.stat_result
    parent_descriptor: int
    parent_metadata: os.stat_result


def _open_anchor_directory(anchor: str, context: str) -> int:
    descriptor: int | None = None
    primary_error: BaseException | None = None
    try:
        descriptor = os.open(anchor, _directory_open_flags())
        metadata = os.fstat(descriptor)
    except OSError as exc:
        primary_error = CorpusPreparationError(
            f"could not securely open {context}; symlinks are forbidden"
        )
        primary_error.__cause__ = exc
    except BaseException as exc:
        primary_error = exc
    else:
        if not stat.S_ISDIR(metadata.st_mode):
            primary_error = CorpusPreparationError(f"{context} is not a directory")

    if primary_error is not None:
        cleanup_failures = _close_descriptors_independently(((f"{context} anchor", descriptor),))
        _raise_operation_or_cleanup(
            f"securely opening {context} failed",
            primary_error=primary_error,
            cleanup_failures=cleanup_failures,
            domain="corpus",
        )
        raise AssertionError("unreachable")
    assert descriptor is not None
    return descriptor


def _open_directory_parts_secure(
    anchor: str,
    parts: tuple[str, ...],
    context: str,
) -> int:
    current = _open_anchor_directory(anchor, context)
    for part in parts:
        following: int | None = None
        primary_error: BaseException | None = None
        try:
            following = os.open(part, _directory_open_flags(), dir_fd=current)
            following_metadata = os.fstat(following)
            if not stat.S_ISDIR(following_metadata.st_mode):
                raise CorpusPreparationError(f"{context} is not a directory")
        except CorpusPreparationError as exc:
            primary_error = exc
        except OSError as exc:
            primary_error = CorpusPreparationError(
                f"could not securely open {context}; symlinks are forbidden"
            )
            primary_error.__cause__ = exc
        except BaseException as exc:
            primary_error = exc

        if primary_error is not None:
            cleanup_failures = _close_descriptors_independently(
                (
                    (f"{context} next component", following),
                    (f"{context} current component", current),
                )
            )
            _raise_operation_or_cleanup(
                f"secure directory traversal for {context} failed",
                primary_error=primary_error,
                cleanup_failures=cleanup_failures,
                domain="corpus",
            )
            raise AssertionError("unreachable")

        assert following is not None
        cleanup_failures = _close_descriptors_independently(
            ((f"{context} previous component", current),)
        )
        if cleanup_failures:
            cleanup_failures += _close_descriptors_independently(
                ((f"{context} next component", following),)
            )
            _raise_operation_or_cleanup(
                f"secure directory traversal for {context} could not release ancestors",
                primary_error=None,
                cleanup_failures=cleanup_failures,
                domain="corpus",
            )
            raise AssertionError("unreachable")
        current = following

    primary_error = None
    try:
        metadata = os.fstat(current)
        if not stat.S_ISDIR(metadata.st_mode):
            raise CorpusPreparationError(f"{context} is not a directory")
    except CorpusPreparationError as exc:
        primary_error = exc
    except OSError as exc:
        primary_error = CorpusPreparationError(f"could not validate {context}")
        primary_error.__cause__ = exc
    except BaseException as exc:
        primary_error = exc
    if primary_error is not None:
        cleanup_failures = _close_descriptors_independently(
            ((f"{context} final component", current),)
        )
        _raise_operation_or_cleanup(
            f"secure directory validation for {context} failed",
            primary_error=primary_error,
            cleanup_failures=cleanup_failures,
            domain="corpus",
        )
        raise AssertionError("unreachable")
    return current


def _open_regular_path_secure(path: Path, context: str) -> _SecureOpenedRegular:
    _require_secure_preparation()
    anchor, parts = _secure_path_parts(path, context, allow_anchor_only=False)
    parent = _open_directory_parts_secure(anchor, parts[:-1], f"{context} parent")
    descriptor: int | None = None
    primary_error: BaseException | None = None
    try:
        parent_metadata = os.fstat(parent)
        descriptor = os.open(parts[-1], _regular_read_flags(), dir_fd=parent)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise CorpusPreparationError(f"{context} must be a regular file")
        if metadata.st_nlink != 1:
            raise CorpusPreparationError(f"{context} hardlinks are forbidden")
    except CorpusPreparationError as exc:
        primary_error = exc
    except OSError as exc:
        primary_error = CorpusPreparationError(
            f"could not securely open {context}; symlinks are forbidden"
        )
        primary_error.__cause__ = exc
    except BaseException as exc:
        primary_error = exc

    if primary_error is not None:
        cleanup_failures = _close_descriptors_independently(
            (
                (context, descriptor),
                (f"{context} parent", parent),
            )
        )
        _raise_operation_or_cleanup(
            f"securely opening {context} failed",
            primary_error=primary_error,
            cleanup_failures=cleanup_failures,
            domain="corpus",
        )
        raise AssertionError("unreachable")

    assert descriptor is not None
    return _SecureOpenedRegular(
        file_descriptor=descriptor,
        file_metadata=metadata,
        parent_descriptor=parent,
        parent_metadata=parent_metadata,
    )


def _open_destination_parent_secure(
    path: Path,
) -> tuple[int, str, os.stat_result]:
    _require_secure_preparation()
    anchor, parts = _secure_path_parts(
        path,
        "destination path",
        allow_anchor_only=False,
    )
    parent = _open_directory_parts_secure(
        anchor,
        parts[:-1],
        "destination parent",
    )
    try:
        metadata = os.fstat(parent)
    except BaseException as exc:
        cleanup_failures = _close_descriptors_independently((("destination parent", parent),))
        primary_error: BaseException
        if isinstance(exc, OSError):
            primary_error = CorpusPreparationError("could not validate destination parent identity")
            primary_error.__cause__ = exc
        else:
            primary_error = exc
        _raise_operation_or_cleanup(
            "destination parent validation failed",
            primary_error=primary_error,
            cleanup_failures=cleanup_failures,
            domain="corpus",
        )
        raise AssertionError("unreachable") from None
    return parent, parts[-1], metadata


def _destination_exists(parent: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise CorpusPreparationError(
            "could not inspect destination without following symlinks"
        ) from exc
    return True


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("write made no progress")
        view = view[written:]


def _create_snapshot_fd() -> int:
    descriptor: int | None = None
    primary_error: BaseException | None = None
    try:
        creator = getattr(os, "memfd_create", None)
        if not callable(creator):
            raise CorpusPreparationError("Linux sealed snapshot creation is unavailable")
        flags = _required_os_constant("MFD_CLOEXEC") | _required_os_constant("MFD_ALLOW_SEALING")
        descriptor = creator("mosaic-corpus-snapshot", flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 0 or metadata.st_size != 0:
            raise CorpusPreparationError(
                "sealed snapshot backing object is not a fresh anonymous regular file"
            )
    except CorpusPreparationError as exc:
        primary_error = exc
    except OSError as exc:
        primary_error = CorpusPreparationError("could not create sealed Linux snapshot")
        primary_error.__cause__ = exc
    except BaseException as exc:
        primary_error = exc

    if primary_error is not None:
        cleanup_failures = _close_descriptors_independently((("sealed snapshot", descriptor),))
        _raise_operation_or_cleanup(
            "sealed snapshot creation failed",
            primary_error=primary_error,
            cleanup_failures=cleanup_failures,
            domain="corpus",
        )
        raise AssertionError("unreachable")
    assert descriptor is not None
    return descriptor


def _snapshot_fcntl_function() -> Callable[..., int]:
    try:
        import fcntl

        fcntl_function = getattr(fcntl, "fcntl", None)
        if not callable(fcntl_function):
            raise CorpusPreparationError("Linux file-sealing operation is unavailable")
        return cast(Callable[..., int], fcntl_function)
    except ImportError as exc:
        raise CorpusPreparationError("Linux file-sealing operation is unavailable") from exc


def _verify_snapshot_seals(descriptor: int) -> None:
    try:
        _add_seals, get_seals, required_seals = _snapshot_sealing_constants()
        actual_seals = _snapshot_fcntl_function()(descriptor, get_seals)
    except CorpusPreparationError:
        raise
    except OSError as exc:
        raise CorpusPreparationError("could not inspect verified Linux snapshot seals") from exc
    if type(actual_seals) is not int or actual_seals & required_seals != required_seals:
        raise CorpusPreparationError("verified Linux snapshot is missing required immutable seals")


def _seal_snapshot_fd(descriptor: int) -> None:
    try:
        add_seals, _get_seals, required_seals = _snapshot_sealing_constants()
        _snapshot_fcntl_function()(descriptor, add_seals, required_seals)
        _verify_snapshot_seals(descriptor)
    except CorpusPreparationError:
        raise
    except OSError as exc:
        raise CorpusPreparationError("could not seal verified Linux snapshot") from exc


def _hash_fd_exact(descriptor: int, expected_bytes: int) -> tuple[int, str]:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    total = 0
    remaining = expected_bytes
    while remaining:
        chunk = os.read(descriptor, min(READ_CHUNK_BYTES, remaining))
        if not chunk:
            raise CorpusPreparationError(
                f"file ended after {total} bytes; expected {expected_bytes}"
            )
        digest.update(chunk)
        total += len(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise CorpusPreparationError(f"file exceeds expected byte length {expected_bytes}")
    return total, digest.hexdigest()


def _copy_source_to_fd(
    source_descriptor: int,
    output_descriptor: int,
    expected_bytes: int,
) -> tuple[int, str]:
    os.lseek(source_descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    total = 0
    remaining = expected_bytes
    while remaining:
        chunk = os.read(source_descriptor, min(READ_CHUNK_BYTES, remaining))
        if not chunk:
            raise CorpusPreparationError(
                f"source ended after {total} bytes; expected {expected_bytes}"
            )
        _write_all(output_descriptor, chunk)
        digest.update(chunk)
        total += len(chunk)
        remaining -= len(chunk)
    if os.read(source_descriptor, 1):
        raise CorpusPreparationError(f"source exceeds expected byte length {expected_bytes}")
    return total, digest.hexdigest()


def _validate_source_metadata(
    metadata: os.stat_result,
    expected_bytes: int,
) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise CorpusPreparationError("source must be a regular file")
    if metadata.st_nlink != 1:
        raise CorpusPreparationError("source hardlinks are forbidden")
    if metadata.st_size != expected_bytes:
        raise CorpusPreparationError(
            f"source size is {metadata.st_size}; expected {expected_bytes}"
        )


def _descriptor_for_operation(
    plan: CompetitiveAcquisitionPlan,
    corpus_id: str,
) -> CorpusAcquisitionDescriptor:
    if type(corpus_id) is not str or corpus_id not in REQUIRED_CORPUS_IDS:
        raise CorpusPreparationError("corpus_id is not a canonical contract corpus ID")
    descriptor = next(item for item in plan.corpora if item.id == corpus_id)
    if descriptor.status != "unverified_technical_copy":
        raise CorpusPreparationError(
            f"corpus {corpus_id!r} is blocked and cannot be verified or prepared"
        )
    claims = descriptor.unverified_approval_claims
    if (
        descriptor.expected_source_bytes is None
        or descriptor.expected_source_sha256 is None
        or descriptor.source_url is None
        or descriptor.license_evidence_sha256_claim is None
        or claims.record_claim is None
        or not claims.benchmark_use_claim
        or not claims.redistribution_claim
    ):
        raise CorpusPreparationError(
            f"corpus {corpus_id!r} is not a complete unverified technical-copy descriptor"
        )
    return descriptor


def verify_local_source(
    plan_path: Path,
    corpus_id: str,
    source_path: Path,
    *,
    max_plan_bytes: int = MAX_PLAN_BYTES,
) -> VerifiedLocalSource:
    """Verify one local source from the same open file, without preparing output."""

    plan = load_acquisition_plan(plan_path, max_bytes=max_plan_bytes)
    descriptor = _descriptor_for_operation(plan, corpus_id)
    _require_secure_preparation()
    expected_bytes = cast(int, descriptor.expected_source_bytes)
    expected_sha256 = cast(str, descriptor.expected_source_sha256)
    opened_source: _SecureOpenedRegular | None = None
    result: VerifiedLocalSource | None = None
    primary_error: BaseException | None = None
    try:
        opened_source = _open_regular_path_secure(
            Path(source_path),
            "source path",
        )
        _validate_source_metadata(opened_source.file_metadata, expected_bytes)
        actual_bytes, actual_sha256 = _hash_fd_exact(
            opened_source.file_descriptor,
            expected_bytes,
        )
        after = os.fstat(opened_source.file_descriptor)
        if _metadata_changed(opened_source.file_metadata, after):
            raise CorpusPreparationError("source changed while it was being verified")
        if actual_sha256 != expected_sha256:
            raise CorpusPreparationError(
                f"source SHA-256 mismatch: expected {expected_sha256}, got {actual_sha256}"
            )
        result = _issue_record(
            VerifiedLocalSource(
                corpus_id=corpus_id,
                display_path=Path(source_path),
                identity=_local_file_identity(
                    opened_source.file_metadata,
                    opened_source.parent_metadata,
                ),
                bytes=actual_bytes,
                sha256=actual_sha256,
                plan_sha256=plan.plan_sha256,
            )
        )
    except CorpusPreparationError as exc:
        primary_error = exc
    except OSError as exc:
        primary_error = CorpusPreparationError("could not verify local source safely")
        primary_error.__cause__ = exc
    except BaseException as exc:
        primary_error = exc

    cleanup_failures = _close_descriptors_independently(
        (
            (
                "verified source file",
                None if opened_source is None else opened_source.file_descriptor,
            ),
            (
                "verified source parent",
                None if opened_source is None else opened_source.parent_descriptor,
            ),
        )
    )
    _raise_operation_or_cleanup(
        "local source verification/cleanup failed",
        primary_error=primary_error,
        cleanup_failures=cleanup_failures,
        domain="corpus",
    )
    assert result is not None
    return result


def _reopen_bound_local_file(
    *,
    display_path: Path,
    identity: LocalFileIdentity,
    expected_bytes: int,
    expected_sha256: str,
    context: str,
    publication_state: PublicationState,
    prepared: PreparedLocalCorpus | None,
) -> int:
    opened: _SecureOpenedRegular | None = None
    snapshot_descriptor: int | None = None
    primary_error: BaseException | None = None
    try:
        if not 1 <= expected_bytes <= MAX_REOPEN_SNAPSHOT_BYTES:
            raise CorpusPreparationError(
                f"{context} exceeds the sealed snapshot limit of {MAX_REOPEN_SNAPSHOT_BYTES} bytes"
            )
        opened = _open_regular_path_secure(display_path, context)
        if not _identity_matches(
            opened.parent_metadata,
            device=identity.parent_device,
            inode=identity.parent_inode,
        ):
            raise CorpusPreparationError(
                f"{context} display-only parent path no longer names the verified directory"
            )
        if not _identity_matches(
            opened.file_metadata,
            device=identity.file_device,
            inode=identity.file_inode,
        ):
            raise CorpusPreparationError(
                f"{context} display-only pathname no longer names the verified inode"
            )
        _validate_source_metadata(opened.file_metadata, expected_bytes)
        snapshot_descriptor = _create_snapshot_fd()
        actual_bytes, actual_sha256 = _copy_source_to_fd(
            opened.file_descriptor,
            snapshot_descriptor,
            expected_bytes,
        )
        after = os.fstat(opened.file_descriptor)
        if _metadata_changed(opened.file_metadata, after):
            raise CorpusPreparationError(f"{context} changed while it was being reopened")
        if actual_bytes != expected_bytes or actual_sha256 != expected_sha256:
            raise CorpusPreparationError(
                f"{context} content no longer matches its descriptor-bound identity"
            )
        snapshot_metadata = os.fstat(snapshot_descriptor)
        if (
            not stat.S_ISREG(snapshot_metadata.st_mode)
            or snapshot_metadata.st_nlink != 0
            or snapshot_metadata.st_size != expected_bytes
        ):
            raise CorpusPreparationError(
                f"{context} sealed snapshot identity or size changed during copy"
            )
        _seal_snapshot_fd(snapshot_descriptor)
        sealed_metadata = os.fstat(snapshot_descriptor)
        snapshot_bytes, snapshot_sha256 = _hash_fd_exact(
            snapshot_descriptor,
            expected_bytes,
        )
        final_snapshot_metadata = os.fstat(snapshot_descriptor)
        _verify_snapshot_seals(snapshot_descriptor)
        if (
            not stat.S_ISREG(sealed_metadata.st_mode)
            or sealed_metadata.st_nlink != 0
            or sealed_metadata.st_size != expected_bytes
            or not os.path.samestat(snapshot_metadata, sealed_metadata)
            or _metadata_changed(sealed_metadata, final_snapshot_metadata)
        ):
            raise CorpusPreparationError(
                f"{context} sealed snapshot identity changed while sealing"
            )
        if snapshot_bytes != expected_bytes or snapshot_sha256 != expected_sha256:
            raise CorpusPreparationError(
                f"{context} sealed snapshot content does not match the verified SHA-256"
            )
        os.lseek(snapshot_descriptor, 0, os.SEEK_SET)
    except CorpusPreparationError as exc:
        primary_error = exc
    except OSError as exc:
        primary_error = CorpusPreparationError(f"could not securely reopen {context}")
        primary_error.__cause__ = exc
    except BaseException as exc:
        primary_error = exc

    if primary_error is not None:
        cleanup_failures = _close_descriptors_independently(
            (
                ("sealed immutable snapshot", snapshot_descriptor),
                (
                    context,
                    None if opened is None else opened.file_descriptor,
                ),
                (
                    f"{context} parent",
                    None if opened is None else opened.parent_descriptor,
                ),
            )
        )
        _raise_operation_or_cleanup(
            f"secure reopen of {context} failed",
            primary_error=primary_error,
            cleanup_failures=cleanup_failures,
            domain="corpus",
            publication_state=publication_state,
            prepared=prepared,
        )
        raise AssertionError("unreachable")

    assert opened is not None
    cleanup_failures = _close_descriptors_independently(
        (
            (context, opened.file_descriptor),
            (f"{context} parent", opened.parent_descriptor),
        )
    )
    if cleanup_failures:
        cleanup_failures += _close_descriptors_independently(
            (("sealed immutable snapshot", snapshot_descriptor),)
        )
        _raise_operation_or_cleanup(
            f"secure reopen of {context} could not release original descriptors",
            primary_error=None,
            cleanup_failures=cleanup_failures,
            domain="corpus",
            publication_state=publication_state,
            prepared=prepared,
        )
        raise AssertionError("unreachable")
    assert snapshot_descriptor is not None
    return snapshot_descriptor


def reopen_verified_local_source(source: VerifiedLocalSource) -> int:
    """Return a sealed snapshot fd; ``source.display_path`` is display-only.

    The caller owns the returned descriptor and must close it. The pathname-bound
    source is copied and hashed in bounded chunks into a Linux memfd, then shrink,
    grow, write, and further-sealing operations are forbidden before return. Inputs
    above ``MAX_REOPEN_SNAPSHOT_BYTES`` are explicitly unsupported, and neither the
    record nor snapshot conveys binding or approval authority.
    """

    if type(source) is not VerifiedLocalSource:
        raise TypeError("source must be an exact VerifiedLocalSource")
    _require_issued_record(source)
    return _reopen_bound_local_file(
        display_path=source.display_path,
        identity=source.identity,
        expected_bytes=source.bytes,
        expected_sha256=source.sha256,
        context="verified source",
        publication_state="not_committed",
        prepared=None,
    )


def reopen_prepared_local_corpus(prepared: PreparedLocalCorpus) -> int:
    """Return a sealed snapshot fd for a process-issued prepared-corpus record.

    The caller owns the returned sealed snapshot descriptor and must close it. The
    display-only pathname is rejected if either its parent directory or file inode
    was swapped; later changes to the pathname-bound inode cannot change the snapshot.
    Inputs above ``MAX_REOPEN_SNAPSHOT_BYTES`` are explicitly unsupported, and neither
    the record nor snapshot conveys binding or approval authority.
    """

    if type(prepared) is not PreparedLocalCorpus:
        raise TypeError("prepared must be an exact PreparedLocalCorpus")
    _require_issued_record(prepared)
    return _reopen_bound_local_file(
        display_path=prepared.display_path,
        identity=prepared.identity,
        expected_bytes=prepared.bytes,
        expected_sha256=prepared.sha256,
        context="prepared corpus",
        publication_state=prepared.publication_state,
        prepared=prepared,
    )


def _create_temporary_output(parent: int) -> int:
    flags = os.O_RDWR | _os_open_flag("O_TMPFILE") | _os_open_flag("O_CLOEXEC")
    descriptor: int | None = None
    primary_error: BaseException | None = None
    try:
        descriptor = os.open(".", flags, 0o600, dir_fd=parent)
        metadata = os.fstat(descriptor)
    except OSError as exc:
        primary_error = CorpusPreparationError(
            "destination filesystem does not support anonymous atomic output"
        )
        primary_error.__cause__ = exc
    except BaseException as exc:
        primary_error = exc
    else:
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 0:
            primary_error = CorpusPreparationError(
                "anonymous temporary output is not an unlinked regular file"
            )

    if primary_error is not None:
        cleanup_failures = _close_descriptors_independently(
            (("anonymous temporary output", descriptor),)
        )
        _raise_operation_or_cleanup(
            "anonymous temporary output creation failed",
            primary_error=primary_error,
            cleanup_failures=cleanup_failures,
            domain="corpus",
        )
        raise AssertionError("unreachable")
    assert descriptor is not None
    return descriptor


def _publish_anonymous_no_replace(
    temporary_descriptor: int,
    destination_parent: int,
    final_name: str,
) -> None:
    """Atomically publish an anonymous Linux file without overwriting anything."""

    at_empty_path = 0x1000
    try:
        library = ctypes.CDLL(None, use_errno=True)
        linkat = library.linkat
        linkat.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
        )
        linkat.restype = ctypes.c_int
        encoded_final_name = os.fsencode(final_name)
        encoded_descriptor_path = os.fsencode(f"/proc/self/fd/{temporary_descriptor}")
    except (AttributeError, OSError) as exc:
        raise CorpusPublicationNotCommittedError(
            "atomic no-overwrite publication primitive is unavailable"
        ) from exc
    result = linkat(
        temporary_descriptor,
        b"",
        destination_parent,
        encoded_final_name,
        at_empty_path,
    )
    error_number = ctypes.get_errno() if result != 0 else 0
    if result != 0 and error_number in {errno.ENOENT, errno.EPERM, errno.EINVAL}:
        # Linux permits this kernel-owned fd path fallback when AT_EMPTY_PATH is
        # unavailable to an unprivileged process. The source identity remains the
        # already-open anonymous descriptor, not a caller-controlled path.
        at_fdcwd = -100
        at_symlink_follow = 0x400
        ctypes.set_errno(0)
        result = linkat(
            at_fdcwd,
            encoded_descriptor_path,
            destination_parent,
            encoded_final_name,
            at_symlink_follow,
        )
    if result != 0:
        error_number = ctypes.get_errno()
        if error_number == errno.EEXIST:
            raise CorpusPublicationNotCommittedError(
                "destination already exists; overwrite is forbidden"
            )
        raise CorpusPublicationNotCommittedError(
            "atomic no-overwrite publication failed"
        ) from OSError(error_number, os.strerror(error_number))


def prepare_local_source(
    plan_path: Path,
    corpus_id: str,
    source_path: Path,
    destination_path: Path,
    *,
    max_plan_bytes: int = MAX_PLAN_BYTES,
) -> PreparedLocalCorpus:
    """Verify and durably publish one deterministic local byte-for-byte copy."""

    plan = load_acquisition_plan(plan_path, max_bytes=max_plan_bytes)
    descriptor = _descriptor_for_operation(plan, corpus_id)
    _require_secure_preparation()
    expected_bytes = cast(int, descriptor.expected_source_bytes)
    expected_sha256 = cast(str, descriptor.expected_source_sha256)

    opened_source: _SecureOpenedRegular | None = None
    destination_parent: int | None = None
    destination_parent_metadata: os.stat_result | None = None
    temporary_descriptor: int | None = None
    publication_state: PublicationState = "not_committed"
    prepared_result: PreparedLocalCorpus | None = None
    committed_candidate: PreparedLocalCorpus | None = None
    publication_attempted = False
    primary_error: BaseException | None = None
    try:
        opened_source = _open_regular_path_secure(
            Path(source_path),
            "source path",
        )
        _validate_source_metadata(opened_source.file_metadata, expected_bytes)
        (
            destination_parent,
            final_name,
            destination_parent_metadata,
        ) = _open_destination_parent_secure(Path(destination_path))
        if _destination_exists(destination_parent, final_name):
            raise CorpusPreparationError("destination already exists; overwrite is forbidden")
        temporary_descriptor = _create_temporary_output(destination_parent)

        copied_bytes, source_sha256 = _copy_source_to_fd(
            opened_source.file_descriptor,
            temporary_descriptor,
            expected_bytes,
        )
        source_after = os.fstat(opened_source.file_descriptor)
        if _metadata_changed(opened_source.file_metadata, source_after):
            raise CorpusPreparationError("source changed while it was being copied")
        if source_sha256 != expected_sha256:
            raise CorpusPreparationError(
                f"source SHA-256 mismatch: expected {expected_sha256}, got {source_sha256}"
            )

        os.fsync(temporary_descriptor)
        output_metadata = os.fstat(temporary_descriptor)
        if (
            not stat.S_ISREG(output_metadata.st_mode)
            or output_metadata.st_nlink != 0
            or output_metadata.st_size != expected_bytes
        ):
            raise CorpusPreparationError(
                "temporary output identity or size changed before publication"
            )
        _prepared_bytes, prepared_sha256 = _hash_fd_exact(
            temporary_descriptor,
            expected_bytes,
        )
        output_after_hash = os.fstat(temporary_descriptor)
        if _metadata_changed(output_metadata, output_after_hash):
            raise CorpusPreparationError("temporary output changed during post-write verification")
        if prepared_sha256 != expected_sha256 or prepared_sha256 != source_sha256:
            raise CorpusPreparationError(
                "post-write SHA-256 does not match the verified source identity"
            )

        committed_candidate = _issue_record(
            PreparedLocalCorpus(
                corpus_id=corpus_id,
                display_path=Path(destination_path),
                identity=_local_file_identity(
                    output_metadata,
                    destination_parent_metadata,
                ),
                bytes=copied_bytes,
                sha256=prepared_sha256,
                source_sha256=source_sha256,
                recipe_id=descriptor.recipe.id,
                recipe_version=descriptor.recipe.version,
                recipe_implementation_sha256=descriptor.recipe.implementation_sha256,
                plan_sha256=plan.plan_sha256,
                publication_state="committed_not_durable",
            )
        )
        # All validation, allocation, hashing, and result construction completes
        # before this single commit point. A successful fd-bound linkat creates
        # the exact verified inode and cannot overwrite an existing name. There
        # is deliberately no pathname rollback after publication.
        publication_attempted = True
        _publish_anonymous_no_replace(
            temporary_descriptor,
            destination_parent,
            final_name,
        )
        publication_state = "committed_not_durable"
        prepared_result = committed_candidate

        published_metadata = os.fstat(temporary_descriptor)
        if (
            not stat.S_ISREG(published_metadata.st_mode)
            or published_metadata.st_nlink != 1
            or published_metadata.st_size != expected_bytes
            or _publication_link_metadata_changed(
                output_after_hash,
                published_metadata,
            )
            or not _identity_matches(
                published_metadata,
                device=committed_candidate.identity.file_device,
                inode=committed_candidate.identity.file_inode,
            )
        ):
            raise CorpusPreparationError(
                "published inode identity changed; publication is committed but "
                "directory durability is unconfirmed"
            )

        _post_publication_bytes, post_publication_sha256 = _hash_fd_exact(
            temporary_descriptor,
            expected_bytes,
        )
        post_publication_metadata = os.fstat(temporary_descriptor)
        if _metadata_changed(published_metadata, post_publication_metadata):
            raise CorpusPreparationError(
                "published inode changed during post-publication verification; "
                "publication is committed but directory durability is unconfirmed"
            )
        if (
            post_publication_sha256 != expected_sha256
            or post_publication_sha256 != source_sha256
            or post_publication_sha256 != prepared_sha256
        ):
            raise CorpusPreparationError(
                "post-publication SHA-256 does not match the verified source identity; "
                "publication is committed but directory durability is unconfirmed"
            )

        # linkat is the sole commit point. Directory fsync is required afterward
        # to distinguish an atomically visible name from a durably recorded one.
        os.fsync(destination_parent)
        publication_state = "committed_name_unavailable"
        prepared_result = _issue_record(
            replace(
                committed_candidate,
                publication_state="committed_name_unavailable",
            )
        )
        try:
            named_metadata = os.stat(
                final_name,
                dir_fd=destination_parent,
                follow_symlinks=False,
            )
        except OSError as name_exc:
            raise CorpusPublicationNameUnavailableError(
                "destination directory was fsynced, but the committed name is "
                "absent or cannot be inspected; no pathname rollback was attempted",
                prepared=prepared_result,
            ) from name_exc
        if (
            not stat.S_ISREG(named_metadata.st_mode)
            or named_metadata.st_nlink != 1
            or named_metadata.st_size != expected_bytes
            or _metadata_changed(
                post_publication_metadata,
                named_metadata,
            )
            or not _identity_matches(
                named_metadata,
                device=committed_candidate.identity.file_device,
                inode=committed_candidate.identity.file_inode,
            )
        ):
            raise CorpusPublicationNameUnavailableError(
                "destination directory was fsynced, but the committed name was "
                "replaced or no longer has the last verified inode identity and "
                "metadata; no pathname rollback was attempted",
                prepared=prepared_result,
            )
        publication_state = "durable"
        prepared_result = _issue_record(replace(committed_candidate, publication_state="durable"))
    except BaseException as exc:
        inspection_error: BaseException | None = None
        if (
            publication_attempted
            and publication_state == "not_committed"
            and temporary_descriptor is not None
            and committed_candidate is not None
            and not isinstance(exc, CorpusPublicationNotCommittedError)
        ):
            try:
                failure_metadata = os.fstat(temporary_descriptor)
                if failure_metadata.st_nlink >= 1 and _identity_matches(
                    failure_metadata,
                    device=committed_candidate.identity.file_device,
                    inode=committed_candidate.identity.file_inode,
                ):
                    publication_state = "committed_not_durable"
                    prepared_result = committed_candidate
                else:
                    if failure_metadata.st_nlink >= 1:
                        inspection_error = CorpusPreparationError(
                            "post-failure anonymous inode identity changed"
                        )
                    publication_state = "commit_outcome_unknown"
                    prepared_result = _issue_record(
                        replace(
                            committed_candidate,
                            publication_state="commit_outcome_unknown",
                        )
                    )
            except BaseException as state_exc:
                inspection_error = state_exc
                publication_state = "commit_outcome_unknown"
                prepared_result = _issue_record(
                    replace(
                        committed_candidate,
                        publication_state="commit_outcome_unknown",
                    )
                )

        if publication_state == "commit_outcome_unknown":
            assert prepared_result is not None
            if isinstance(exc, Exception) and (
                inspection_error is None or isinstance(inspection_error, Exception)
            ):
                primary_error = CorpusPublicationOutcomeUnknownError(
                    operation_error=exc,
                    inspection_error=inspection_error,
                    candidate=prepared_result,
                )
                primary_error.__cause__ = exc if inspection_error is None else inspection_error
            else:
                outcome_marker = CorpusPublicationOutcomeUnknownError(
                    operation_error=exc,
                    inspection_error=inspection_error,
                    candidate=prepared_result,
                )
                grouped_errors = [exc]
                if inspection_error is not None:
                    grouped_errors.append(inspection_error)
                grouped_errors.append(outcome_marker)
                outcome_group = BaseExceptionGroup(
                    "publication_state=commit_outcome_unknown; no pathname rollback was attempted",
                    grouped_errors,
                )
                outcome_group.add_note(
                    "The candidate PreparedLocalCorpus is descriptor-bound, but the "
                    "commit outcome is unknown."
                )
                primary_error = outcome_group
        elif publication_state == "committed_not_durable":
            assert prepared_result is not None
            if isinstance(exc, Exception):
                durability_error = CorpusPublicationDurabilityError(
                    "destination inode was committed, but destination-directory "
                    "durability was not confirmed; no pathname rollback was attempted",
                    prepared=prepared_result,
                )
                durability_error.__cause__ = exc
                primary_error = durability_error
            else:
                exc.add_note(
                    "The destination inode was committed, directory durability is "
                    "unconfirmed, and no pathname rollback was attempted."
                )
                primary_error = exc
        elif publication_state == "committed_name_unavailable":
            assert prepared_result is not None
            if isinstance(exc, CorpusPublicationNameUnavailableError):
                primary_error = exc
            elif isinstance(exc, Exception):
                name_error = CorpusPublicationNameUnavailableError(
                    "destination directory was fsynced, but post-fsync name "
                    "inspection did not complete; no pathname rollback was attempted",
                    prepared=prepared_result,
                )
                name_error.__cause__ = exc
                primary_error = name_error
            else:
                exc.add_note(
                    "The destination inode was committed and its directory fsynced, "
                    "but final name identity was not confirmed; no pathname rollback "
                    "was attempted."
                )
                primary_error = exc
        elif isinstance(exc, CorpusPreparationError):
            primary_error = exc
        elif isinstance(exc, OSError):
            primary_error = CorpusPreparationError(
                "local deterministic preparation failed safely before publication"
            )
            primary_error.__cause__ = exc
        else:
            if publication_state == "durable":
                exc.add_note(
                    "The destination inode and directory entry were durably committed; "
                    "no pathname rollback was attempted."
                )
            primary_error = exc

    cleanup_failures = _close_descriptors_independently(
        (
            ("anonymous prepared output", temporary_descriptor),
            ("destination parent", destination_parent),
            (
                "source file",
                None if opened_source is None else opened_source.file_descriptor,
            ),
            (
                "source parent",
                None if opened_source is None else opened_source.parent_descriptor,
            ),
        )
    )
    _raise_operation_or_cleanup(
        "local deterministic preparation/cleanup failed",
        primary_error=primary_error,
        cleanup_failures=cleanup_failures,
        domain="corpus",
        publication_state=publication_state,
        prepared=prepared_result,
    )
    assert prepared_result is not None
    return prepared_result
