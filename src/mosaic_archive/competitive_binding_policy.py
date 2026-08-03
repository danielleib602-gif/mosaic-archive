"""Immutable resource policy for the competitive cgroup qualification foundation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn, cast

from .competitive_contract import CONTRACT_SHA256

_POLICY_ID = "mosaic-binding-runner-policy-v1"
_DIGEST_ALGORITHM = "sha256_canonical_json_v1"
_THREAD_TIERS = (1, 8)
_REQUIRED_CONTROLLERS = ("cpuset", "memory", "pids")
_PIDS_MAX = 512
_MEMORY_MAX_BYTES = 64 * 1024**3
_MEMORY_SWAP_MAX_BYTES = 0
_OUTPUT_MAX_BYTES = 32 * 1024**3
_WALL_TIME_LIMIT_SECONDS = 3_600
_CLEANUP_TIMEOUT_SECONDS = 30
_CLEANUP_POLL_INTERVAL_MILLISECONDS = 10
_LEAF_NAME_PREFIX = "mosaic-binding-"
_MANIFEST_ID = "mosaic-competitive-runner-manifest-v1"
_MANIFEST_DIGEST_ALGORITHM = "sha256_canonical_json_without_manifest_digest_v1"
_MANIFEST_AUTHORITY_STATE = "qualification_only_until_native_pidns_exec_identity_v1"
_MAX_MANIFEST_BYTES = 256 * 1024
_READ_CHUNK_BYTES = 64 * 1024
_MAX_JSON_INTEGER_DIGITS = 20
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "manifest_id",
        "manifest_digest_algorithm",
        "manifest_sha256",
        "contract_sha256",
        "authority_state",
        "binding_eligible",
        "qualification_policy",
        "implemented_qualification_controls",
        "required_before_binding",
    }
)
_IMPLEMENTED_QUALIFICATION_CONTROLS = {
    "host": "Linux_x86_64_cgroup_v2_v1",
    "cpuset_selection": "lowest_allowed_logical_cpu_ids_v1",
    "cpuset_mems": "all_parent_effective_memory_nodes_v1",
    "fresh_leaf_per_measurement": True,
    "exact_control_write_readback": True,
    "effective_cpuset_verification": "after_setup_before_attach_and_after_run_v1",
    "lease_state_machine": "single_attach_exclusive_finalize_v1",
    "memory_peak_origin": "fresh_leaf_creation_v1",
    "memory_peak_read": "positive_i64_after_unpopulated_v1",
    "cleanup": "cgroup_kill_wait_unpopulated_remove_v1",
}
_REQUIRED_BEFORE_BINDING = {
    "native_pid_namespace_launcher": True,
    "exclusive_delegated_cgroup_root": True,
    "pre_exec_cgroup_placement": True,
    "complete_descendant_exec_identity": True,
    "fixed_public_environment_capture": True,
    "bounded_output_capture": True,
    "input_prewarm_evidence": True,
    "round_trip_and_archive_identity": True,
    "signed_raw_run_evidence": True,
}


class BindingRunnerManifestError(ValueError):
    """The committed runner manifest is malformed, ambiguous, or inconsistent."""


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise BindingRunnerManifestError(f"duplicate runner-manifest key: {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> NoReturn:
    raise BindingRunnerManifestError(
        f"non-finite runner-manifest JSON constant is forbidden: {value}"
    )


def _reject_json_float(value: str) -> NoReturn:
    raise BindingRunnerManifestError(
        f"floating-point runner-manifest JSON number is forbidden: {value}"
    )


def _parse_json_int(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > _MAX_JSON_INTEGER_DIGITS:
        raise BindingRunnerManifestError("runner-manifest JSON integer exceeds the digit limit")
    return int(value)


def _is_reparse_point(metadata: os.stat_result) -> bool:
    attributes = cast(int, getattr(metadata, "st_file_attributes", 0))
    reparse_flag = cast(int, getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    return bool(reparse_flag and attributes & reparse_flag)


def _require_single_link_regular_file(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_ino == 0
        or metadata.st_nlink != 1
        or _is_reparse_point(metadata)
    ):
        raise BindingRunnerManifestError(
            "runner manifest must be a stable single-link regular file"
        )


def _path_metadata_matches_descriptor(
    path_metadata: os.stat_result,
    descriptor_metadata: os.stat_result,
) -> bool:
    return (
        path_metadata.st_dev,
        path_metadata.st_ino,
        path_metadata.st_mode,
        path_metadata.st_nlink,
        path_metadata.st_size,
    ) == (
        descriptor_metadata.st_dev,
        descriptor_metadata.st_ino,
        descriptor_metadata.st_mode,
        descriptor_metadata.st_nlink,
        descriptor_metadata.st_size,
    )


def _metadata_changed(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )


def _read_manifest_bytes(path: Path) -> bytes:
    """Read a bounded stable manifest without ever blocking on a special file."""
    try:
        path_value = os.fspath(path)
        path_before = os.lstat(path_value)
        _require_single_link_regular_file(path_before)
        if path_before.st_size > _MAX_MANIFEST_BYTES:
            raise BindingRunnerManifestError("runner manifest exceeds the byte limit")

        flags = (
            os.O_RDONLY
            | int(getattr(os, "O_BINARY", 0))
            | int(getattr(os, "O_CLOEXEC", 0))
            | int(getattr(os, "O_NOINHERIT", 0))
            | int(getattr(os, "O_NOFOLLOW", 0))
            | int(getattr(os, "O_NONBLOCK", 0))
        )
        descriptor = os.open(path_value, flags)
        try:
            opened = os.fstat(descriptor)
            _require_single_link_regular_file(opened)
            if not _path_metadata_matches_descriptor(path_before, opened):
                raise BindingRunnerManifestError(
                    "runner manifest changed while it was being opened"
                )

            chunks: list[bytes] = []
            remaining = opened.st_size
            while remaining:
                chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, remaining))
                if not chunk:
                    raise BindingRunnerManifestError(
                        "runner manifest changed while it was being read"
                    )
                chunks.append(chunk)
                remaining -= len(chunk)

            descriptor_after = os.fstat(descriptor)
            _require_single_link_regular_file(descriptor_after)
            if _metadata_changed(opened, descriptor_after):
                raise BindingRunnerManifestError("runner manifest changed while it was being read")
            path_after = os.lstat(path_value)
            _require_single_link_regular_file(path_after)
            if not _path_metadata_matches_descriptor(path_after, descriptor_after):
                raise BindingRunnerManifestError(
                    "runner manifest path changed while it was being read"
                )
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    except BindingRunnerManifestError:
        raise
    except (OSError, OverflowError, TypeError, ValueError) as error:
        raise BindingRunnerManifestError("cannot safely read runner manifest") from error


def _exact_structure_equal(actual: object, expected: object) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        assert isinstance(actual, dict)
        return set(actual) == set(expected) and all(
            _exact_structure_equal(actual[key], value) for key, value in expected.items()
        )
    if isinstance(expected, list):
        assert isinstance(actual, list)
        return len(actual) == len(expected) and all(
            _exact_structure_equal(actual_item, expected_item)
            for actual_item, expected_item in zip(actual, expected, strict=True)
        )
    return actual == expected


def _policy_payload(
    *,
    schema_version: int,
    policy_id: str,
    thread_tiers: tuple[int, ...],
    required_controllers: tuple[str, ...],
    pids_max: int,
    memory_max_bytes: int,
    memory_swap_max_bytes: int,
    output_max_bytes: int,
    wall_time_limit_seconds: int,
    cleanup_timeout_seconds: int,
    cleanup_poll_interval_milliseconds: int,
    leaf_name_prefix: str,
) -> dict[str, object]:
    return {
        "schema_version": schema_version,
        "policy_id": policy_id,
        "thread_tiers": list(thread_tiers),
        "required_controllers": list(required_controllers),
        "pids_max": pids_max,
        "memory_max_bytes": memory_max_bytes,
        "memory_swap_max_bytes": memory_swap_max_bytes,
        "output_max_bytes": output_max_bytes,
        "wall_time_limit_seconds": wall_time_limit_seconds,
        "cleanup_timeout_seconds": cleanup_timeout_seconds,
        "cleanup_poll_interval_milliseconds": cleanup_poll_interval_milliseconds,
        "leaf_name_prefix": leaf_name_prefix,
    }


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class BindingRunnerPolicy:
    """The immutable resource boundary used by this qualification foundation."""

    schema_version: int
    policy_id: str
    digest_algorithm: str
    policy_sha256: str
    thread_tiers: tuple[int, ...]
    required_controllers: tuple[str, ...]
    pids_max: int
    memory_max_bytes: int
    memory_swap_max_bytes: int
    output_max_bytes: int
    wall_time_limit_seconds: int
    cleanup_timeout_seconds: int
    cleanup_poll_interval_milliseconds: int
    leaf_name_prefix: str

    def __post_init__(self) -> None:
        exact_types = (
            type(self.schema_version) is int
            and type(self.policy_id) is str
            and type(self.digest_algorithm) is str
            and type(self.policy_sha256) is str
            and type(self.thread_tiers) is tuple
            and all(type(value) is int for value in self.thread_tiers)
            and type(self.required_controllers) is tuple
            and all(type(value) is str for value in self.required_controllers)
            and type(self.pids_max) is int
            and type(self.memory_max_bytes) is int
            and type(self.memory_swap_max_bytes) is int
            and type(self.output_max_bytes) is int
            and type(self.wall_time_limit_seconds) is int
            and type(self.cleanup_timeout_seconds) is int
            and type(self.cleanup_poll_interval_milliseconds) is int
            and type(self.leaf_name_prefix) is str
        )
        if not exact_types:
            raise TypeError("binding runner policy fields require exact canonical types")
        fixed_values = (
            self.schema_version == 1
            and self.policy_id == _POLICY_ID
            and self.digest_algorithm == _DIGEST_ALGORITHM
            and self.thread_tiers == _THREAD_TIERS
            and self.required_controllers == _REQUIRED_CONTROLLERS
            and self.pids_max == _PIDS_MAX
            and self.memory_max_bytes == _MEMORY_MAX_BYTES
            and self.memory_swap_max_bytes == _MEMORY_SWAP_MAX_BYTES
            and self.output_max_bytes == _OUTPUT_MAX_BYTES
            and self.wall_time_limit_seconds == _WALL_TIME_LIMIT_SECONDS
            and self.cleanup_timeout_seconds == _CLEANUP_TIMEOUT_SECONDS
            and self.cleanup_poll_interval_milliseconds == _CLEANUP_POLL_INTERVAL_MILLISECONDS
            and self.leaf_name_prefix == _LEAF_NAME_PREFIX
        )
        if not fixed_values:
            raise ValueError("binding runner policy fields must match the fixed v1 policy")
        payload = _policy_payload(
            schema_version=self.schema_version,
            policy_id=self.policy_id,
            thread_tiers=self.thread_tiers,
            required_controllers=self.required_controllers,
            pids_max=self.pids_max,
            memory_max_bytes=self.memory_max_bytes,
            memory_swap_max_bytes=self.memory_swap_max_bytes,
            output_max_bytes=self.output_max_bytes,
            wall_time_limit_seconds=self.wall_time_limit_seconds,
            cleanup_timeout_seconds=self.cleanup_timeout_seconds,
            cleanup_poll_interval_milliseconds=self.cleanup_poll_interval_milliseconds,
            leaf_name_prefix=self.leaf_name_prefix,
        )
        if self.policy_sha256 != _canonical_sha256(payload):
            raise ValueError("binding runner policy SHA-256 does not match its canonical payload")


def fixed_binding_policy() -> BindingRunnerPolicy:
    """Return the sole supported, independently digestible runner policy."""
    payload = _policy_payload(
        schema_version=1,
        policy_id=_POLICY_ID,
        thread_tiers=_THREAD_TIERS,
        required_controllers=_REQUIRED_CONTROLLERS,
        pids_max=_PIDS_MAX,
        memory_max_bytes=_MEMORY_MAX_BYTES,
        memory_swap_max_bytes=_MEMORY_SWAP_MAX_BYTES,
        output_max_bytes=_OUTPUT_MAX_BYTES,
        wall_time_limit_seconds=_WALL_TIME_LIMIT_SECONDS,
        cleanup_timeout_seconds=_CLEANUP_TIMEOUT_SECONDS,
        cleanup_poll_interval_milliseconds=_CLEANUP_POLL_INTERVAL_MILLISECONDS,
        leaf_name_prefix=_LEAF_NAME_PREFIX,
    )
    return BindingRunnerPolicy(
        schema_version=1,
        policy_id=_POLICY_ID,
        digest_algorithm=_DIGEST_ALGORITHM,
        policy_sha256=_canonical_sha256(payload),
        thread_tiers=_THREAD_TIERS,
        required_controllers=_REQUIRED_CONTROLLERS,
        pids_max=_PIDS_MAX,
        memory_max_bytes=_MEMORY_MAX_BYTES,
        memory_swap_max_bytes=_MEMORY_SWAP_MAX_BYTES,
        output_max_bytes=_OUTPUT_MAX_BYTES,
        wall_time_limit_seconds=_WALL_TIME_LIMIT_SECONDS,
        cleanup_timeout_seconds=_CLEANUP_TIMEOUT_SECONDS,
        cleanup_poll_interval_milliseconds=_CLEANUP_POLL_INTERVAL_MILLISECONDS,
        leaf_name_prefix=_LEAF_NAME_PREFIX,
    )


def load_binding_runner_manifest(path: Path) -> dict[str, object]:
    """Strictly load and authenticate the canonical non-binding runner manifest."""
    if not isinstance(path, Path):
        raise TypeError("runner manifest path must be a Path")
    raw = _read_manifest_bytes(path)
    try:
        text = raw.decode("utf-8")
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
            parse_float=_reject_json_float,
            parse_int=_parse_json_int,
        )
    except BindingRunnerManifestError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise BindingRunnerManifestError(f"invalid runner-manifest JSON: {error}") from error
    if type(parsed) is not dict:
        raise BindingRunnerManifestError("runner manifest must be a JSON object")
    manifest = cast(dict[str, object], parsed)
    if set(manifest) != _MANIFEST_KEYS:
        raise BindingRunnerManifestError("runner manifest keys are not the exact v1 schema")
    if manifest.get("schema_version") != 1 or type(manifest.get("schema_version")) is not int:
        raise BindingRunnerManifestError("runner manifest schema_version must be exact integer 1")
    if manifest.get("manifest_id") != _MANIFEST_ID:
        raise BindingRunnerManifestError("runner manifest ID is not the fixed v1 identity")
    if manifest.get("manifest_digest_algorithm") != _MANIFEST_DIGEST_ALGORITHM:
        raise BindingRunnerManifestError("runner manifest digest algorithm is not canonical")
    claimed_sha256 = manifest.get("manifest_sha256")
    if type(claimed_sha256) is not str or _SHA256_RE.fullmatch(claimed_sha256) is None:
        raise BindingRunnerManifestError("runner manifest SHA-256 is not canonical")
    digest_payload = {
        key: value
        for key, value in manifest.items()
        if key not in {"manifest_digest_algorithm", "manifest_sha256"}
    }
    try:
        actual_sha256 = _canonical_sha256(digest_payload)
    except UnicodeError as error:
        raise BindingRunnerManifestError("runner manifest contains invalid Unicode") from error
    if claimed_sha256 != actual_sha256:
        raise BindingRunnerManifestError("runner manifest SHA-256 does not match its payload")
    if manifest.get("authority_state") != _MANIFEST_AUTHORITY_STATE:
        raise BindingRunnerManifestError(
            "runner manifest authority state is not qualification-only"
        )
    if manifest.get("binding_eligible") is not False:
        raise BindingRunnerManifestError("runner manifest must remain non-binding")
    if manifest.get("contract_sha256") != CONTRACT_SHA256:
        raise BindingRunnerManifestError("runner manifest contract digest is inconsistent")
    qualification = manifest.get("qualification_policy")
    if type(qualification) is not dict:
        raise BindingRunnerManifestError("runner qualification policy must be an object")
    policy = fixed_binding_policy()
    expected_qualification = _policy_payload(
        schema_version=policy.schema_version,
        policy_id=policy.policy_id,
        thread_tiers=policy.thread_tiers,
        required_controllers=policy.required_controllers,
        pids_max=policy.pids_max,
        memory_max_bytes=policy.memory_max_bytes,
        memory_swap_max_bytes=policy.memory_swap_max_bytes,
        output_max_bytes=policy.output_max_bytes,
        wall_time_limit_seconds=policy.wall_time_limit_seconds,
        cleanup_timeout_seconds=policy.cleanup_timeout_seconds,
        cleanup_poll_interval_milliseconds=policy.cleanup_poll_interval_milliseconds,
        leaf_name_prefix=policy.leaf_name_prefix,
    )
    expected_qualification["digest_algorithm"] = policy.digest_algorithm
    expected_qualification["policy_sha256"] = policy.policy_sha256
    if not _exact_structure_equal(qualification, expected_qualification):
        raise BindingRunnerManifestError("runner qualification policy is not the exact v1 policy")
    if not _exact_structure_equal(
        manifest.get("implemented_qualification_controls"),
        _IMPLEMENTED_QUALIFICATION_CONTROLS,
    ):
        raise BindingRunnerManifestError("implemented runner controls are not the exact v1 set")
    if not _exact_structure_equal(
        manifest.get("required_before_binding"),
        _REQUIRED_BEFORE_BINDING,
    ):
        raise BindingRunnerManifestError("remaining binding requirements are not the exact v1 set")
    return manifest
