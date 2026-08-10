"""Fail-closed delegated cgroup creation and lease lifecycle."""

from __future__ import annotations

import os
import re
from collections.abc import Iterator
from contextlib import contextmanager
from threading import RLock
from typing import Literal

from .competitive_binding_common import (
    BindingRunnerHostError,
    _backend_call,
    _control_scalar,
    _raise_combined_failures,
    _verify_effective_id_set,
    _write_and_verify,
    _write_exact,
)
from .competitive_binding_io import _MAX_CONTROL_BYTES, _BindingBackend, _validate_leaf_name
from .competitive_binding_qualification import BindingHostQualification
from .competitive_binding_supervisor import (
    DelegatedRootCapabilityError,
    ExclusiveDelegatedCgroupRoot,
    _locked_capability_access,
)

_MAX_SIGNED_64 = (1 << 63) - 1
_POSITIVE_INTEGER_RE = re.compile(r"[1-9][0-9]*\Z")


class BindingCgroupLease:
    """A fresh cgroup leaf with fail-closed lifecycle and memory-peak operations."""

    __slots__ = (
        "_attachment_authority",
        "_backend",
        "_closed",
        "_issuing_pid",
        "_leaf_handle",
        "_lock",
        "_production_capability",
        "_root_handle",
        "_state",
        "leaf_name",
        "qualification",
    )

    def __init__(
        self,
        *,
        qualification: BindingHostQualification,
        leaf_name: str,
        backend: _BindingBackend,
        root_handle: object,
        leaf_handle: object,
        attachment_authority: Literal["native-preexec-required", "test-only-direct-attach"],
        production_capability: ExclusiveDelegatedCgroupRoot | None = None,
    ) -> None:
        if qualification._backend is not backend or qualification._root_handle is not root_handle:
            raise ValueError("cgroup lease must retain its exact qualified backend and root")
        if attachment_authority == "native-preexec-required":
            if (
                type(production_capability) is not ExclusiveDelegatedCgroupRoot
                or qualification._capability is not production_capability
            ):
                raise ValueError(
                    "a production cgroup lease requires its exact qualifying capability"
                )
        elif attachment_authority == "test-only-direct-attach":
            if production_capability is not None:
                raise ValueError("a test-only cgroup lease cannot retain production authority")
        else:
            raise ValueError("cgroup lease attachment authority is invalid")
        self.qualification = qualification
        self.leaf_name = leaf_name
        self._backend = backend
        self._root_handle = root_handle
        self._leaf_handle = leaf_handle
        self._attachment_authority = attachment_authority
        self._production_capability = production_capability
        self._issuing_pid = os.getpid()
        self._closed = False
        self._lock = RLock()
        self._state = "ready"

    @property
    def binding_eligible(self) -> Literal[False]:
        return False

    @property
    def attachment_authority(
        self,
    ) -> Literal["native-preexec-required", "test-only-direct-attach"]:
        return self._attachment_authority

    def _require_open(self) -> None:
        if self._closed:
            raise BindingRunnerHostError("cgroup lease is closed")

    def _require_issuing_process(self) -> None:
        if self._issuing_pid != os.getpid():
            raise BindingRunnerHostError("cgroup lease belongs to another process")

    @contextmanager
    def _locked_backend_authority(self) -> Iterator[None]:
        """Hold supervisor authority across every production backend operation."""
        self._require_issuing_process()
        capability = self._production_capability
        if capability is None:
            yield
            return
        try:
            with _locked_capability_access(capability) as access:
                if (
                    not access.production_inherited
                    or access.backend is not self._backend
                    or access.root_handle is not self._root_handle
                    or self.qualification._capability is not capability
                    or self.qualification.session_id != access.session_id
                    or self.qualification.root_identity != access.root_identity
                    or self.qualification.policy_digest != access.policy_digest
                ):
                    raise BindingRunnerHostError(
                        "cgroup lease authority no longer matches its delegated-root session"
                    )
                yield
        except DelegatedRootCapabilityError as error:
            raise BindingRunnerHostError(f"invalid delegated-root capability: {error}") from error

    def _require_state(self, expected: str, operation: str) -> None:
        if self._state != expected:
            raise BindingRunnerHostError(
                f"cannot {operation} while cgroup lease state is {self._state!r}"
            )

    def _read_leaf(self, filename: str) -> str:
        return _backend_call(
            f"failed to read {filename}",
            lambda: self._backend.read_leaf(self._leaf_handle, filename),
        )

    def _is_populated(self) -> bool:
        value = self._read_leaf("cgroup.events")
        if type(value) is not str or len(value.encode("utf-8")) > _MAX_CONTROL_BYTES:
            raise BindingRunnerHostError("cgroup.events is not bounded text")
        populated: int | None = None
        for line in value.splitlines():
            fields = line.split(" ")
            if len(fields) != 2 or not fields[0] or fields[1] not in {"0", "1"}:
                raise BindingRunnerHostError("cgroup.events is malformed")
            if fields[0] == "populated":
                if populated is not None:
                    raise BindingRunnerHostError("cgroup.events repeats populated")
                populated = int(fields[1])
        if populated is None:
            raise BindingRunnerHostError("cgroup.events does not report populated")
        return populated == 1

    def attach_process(self, pid: int) -> None:
        with self._lock:
            self._require_issuing_process()
            self._require_open()
            if self._attachment_authority == "native-preexec-required":
                raise BindingRunnerHostError(
                    "production process attachment requires native clone3 pre-exec placement"
                )
            with self._locked_backend_authority():
                if type(pid) is not int or pid <= 0:
                    raise ValueError("process ID must be a positive exact integer")
                self._require_state("ready", "attach a process")
                self.verify_effective_cpuset()
                self._state = "attachment-uncertain"
                value = str(pid)
                _write_exact(self._backend, self._leaf_handle, "cgroup.procs", value)
                observed = self._read_leaf("cgroup.procs")
                members: set[int] = set()
                for line in observed.splitlines():
                    if _POSITIVE_INTEGER_RE.fullmatch(line) is None:
                        raise BindingRunnerHostError(
                            "cgroup.procs membership readback is malformed"
                        )
                    members.add(int(line))
                if pid not in members:
                    raise BindingRunnerHostError(
                        f"cgroup.procs membership readback does not contain process {pid}"
                    )
                self._state = "attached"

    def verify_effective_cpuset(self) -> None:
        with self._lock:
            self._require_issuing_process()
            self._require_open()
            with self._locked_backend_authority():
                _verify_effective_id_set(
                    self._backend,
                    self._leaf_handle,
                    filename="cpuset.cpus.effective",
                    expected=self.qualification.selected_cpus,
                    context="child CPU",
                )
                _verify_effective_id_set(
                    self._backend,
                    self._leaf_handle,
                    filename="cpuset.mems.effective",
                    expected=self.qualification.selected_mems,
                    context="child memory-node",
                )

    def read_memory_peak_bytes(self) -> int:
        with self._lock:
            self._require_issuing_process()
            self._require_open()
            with self._locked_backend_authority():
                self._require_state("attached", "finalize memory.peak")
                self._state = "finalizing"
                self.await_unpopulated()
                self.verify_effective_cpuset()
                if self._is_populated():
                    raise BindingRunnerHostError(
                        "cgroup became populated before memory.peak capture"
                    )
                value = _control_scalar(self._read_leaf("memory.peak"), "memory.peak")
                if self._is_populated():
                    raise BindingRunnerHostError(
                        "cgroup became populated during memory.peak capture"
                    )
                self.verify_effective_cpuset()
                if _POSITIVE_INTEGER_RE.fullmatch(value) is None:
                    raise BindingRunnerHostError("memory.peak is not a canonical positive integer")
                result = int(value)
                if result > _MAX_SIGNED_64:
                    raise BindingRunnerHostError("memory.peak exceeds the signed 64-bit bound")
                self._state = "measured"
                return result

    def await_unpopulated(self) -> None:
        with self._lock:
            self._require_issuing_process()
            self._require_open()
            with self._locked_backend_authority():
                policy = self.qualification.policy
                deadline = (
                    _backend_call(
                        "failed to read cleanup clock",
                        self._backend.monotonic,
                    )
                    + policy.cleanup_timeout_seconds
                )
                poll_seconds = policy.cleanup_poll_interval_milliseconds / 1000
                while self._is_populated():
                    now = _backend_call(
                        "failed to read cleanup clock",
                        self._backend.monotonic,
                    )
                    if now >= deadline:
                        raise BindingRunnerHostError(
                            "cgroup cleanup timed out while the leaf remained populated"
                        )
                    _backend_call(
                        "cgroup cleanup polling failed",
                        lambda: self._backend.sleep(poll_seconds),
                    )

    def kill(self) -> None:
        with self._lock:
            self._require_issuing_process()
            self._require_open()
            with self._locked_backend_authority():
                self._state = "termination-requested"
                _write_exact(self._backend, self._leaf_handle, "cgroup.kill", "1")

    def cleanup(self) -> None:
        with self._lock:
            self._require_issuing_process()
            if self._closed:
                return
            with self._locked_backend_authority():
                if self._is_populated():
                    self.kill()
                self.await_unpopulated()
                _backend_call(
                    "failed to remove cgroup leaf",
                    lambda: self._backend.remove_leaf(self._root_handle, self._leaf_handle),
                )
                self._closed = True

    def __enter__(self) -> BindingCgroupLease:
        with self._lock:
            self._require_issuing_process()
            self._require_open()
            return self

    def __exit__(
        self,
        _exception_type: type[BaseException] | None,
        _exception: BaseException | None,
        _traceback: object,
    ) -> Literal[False]:
        try:
            self.cleanup()
        except BaseException as cleanup_error:
            if _exception is None:
                raise
            _raise_combined_failures(
                "cgroup body and cleanup both failed",
                primary_error=_exception,
                cleanup_error=cleanup_error,
            )
        return False


def create_binding_cgroup(
    qualification: BindingHostQualification,
    *,
    capability: ExclusiveDelegatedCgroupRoot,
    leaf_name: str,
) -> BindingCgroupLease:
    """Create a leaf only from the exact live capability that qualified its root."""
    if not isinstance(qualification, BindingHostQualification):
        raise TypeError("qualification must be BindingHostQualification")
    try:
        with _locked_capability_access(capability) as access:
            if not access.production_inherited:
                raise BindingRunnerHostError(
                    "production cgroup creation requires inherited native-supervisor provenance"
                )
            if (
                qualification._capability is not capability
                or qualification._backend is not access.backend
                or qualification._root_handle is not access.root_handle
                or qualification.session_id != access.session_id
                or qualification.root_identity != access.root_identity
                or qualification.policy_digest != access.policy_digest
                or qualification.policy.policy_sha256 != access.policy_digest
            ):
                raise BindingRunnerHostError(
                    "qualification does not match the exact delegated-root capability session"
                )
            return _create_configured_binding_cgroup(
                qualification,
                leaf_name=leaf_name,
                attachment_authority="native-preexec-required",
                production_capability=capability,
            )
    except DelegatedRootCapabilityError as error:
        raise BindingRunnerHostError(f"invalid delegated-root capability: {error}") from error


def _create_binding_cgroup_for_testing(
    qualification: BindingHostQualification,
    *,
    leaf_name: str,
    backend: object,
) -> BindingCgroupLease:
    """Exercise qualification-only lifecycle logic without a production mutation API."""
    if not isinstance(qualification, BindingHostQualification):
        raise TypeError("qualification must be BindingHostQualification")
    selected_backend = qualification._backend
    if backend is not selected_backend:
        raise ValueError("cgroup creation must use the backend that inspected the root")
    return _create_configured_binding_cgroup(
        qualification,
        leaf_name=leaf_name,
        attachment_authority="test-only-direct-attach",
    )


def _create_configured_binding_cgroup(
    qualification: BindingHostQualification,
    *,
    leaf_name: str,
    attachment_authority: Literal["native-preexec-required", "test-only-direct-attach"],
    production_capability: ExclusiveDelegatedCgroupRoot | None = None,
) -> BindingCgroupLease:
    """Shared fail-closed leaf setup after the caller establishes authority."""
    selected_backend = qualification._backend
    _validate_leaf_name(leaf_name, qualification.policy)
    leaf_handle = _backend_call(
        "fresh cgroup leaf creation failed",
        lambda: selected_backend.create_leaf(qualification._root_handle, leaf_name),
    )
    try:
        for filename, value in (
            ("cpuset.mems", qualification.cpuset_mems),
            ("cpuset.cpus", qualification.cpuset_cpus),
            ("pids.max", str(qualification.policy.pids_max)),
            ("memory.max", str(qualification.policy.memory_max_bytes)),
            ("memory.swap.max", str(qualification.policy.memory_swap_max_bytes)),
        ):
            _write_and_verify(selected_backend, leaf_handle, filename, value)
        _verify_effective_id_set(
            selected_backend,
            leaf_handle,
            filename="cpuset.cpus.effective",
            expected=qualification.selected_cpus,
            context="child CPU",
        )
        _verify_effective_id_set(
            selected_backend,
            leaf_handle,
            filename="cpuset.mems.effective",
            expected=qualification.selected_mems,
            context="child memory-node",
        )
        initial_peak = _backend_call(
            "initial memory.peak read failed",
            lambda: selected_backend.read_leaf(leaf_handle, "memory.peak"),
        )
        if _control_scalar(initial_peak, "memory.peak") != "0":
            raise BindingRunnerHostError("fresh unpopulated cgroup memory.peak must start at zero")
    except BaseException as setup_error:
        try:
            selected_backend.remove_leaf(qualification._root_handle, leaf_handle)
        except BaseException as cleanup_error:
            _raise_combined_failures(
                "cgroup setup and fresh-leaf cleanup both failed",
                primary_error=setup_error,
                cleanup_error=cleanup_error,
            )
        if isinstance(setup_error, BindingRunnerHostError):
            raise
        if not isinstance(setup_error, Exception):
            raise
        raise BindingRunnerHostError(f"cgroup leaf setup failed: {setup_error}") from setup_error
    return BindingCgroupLease(
        qualification=qualification,
        leaf_name=leaf_name,
        backend=selected_backend,
        root_handle=qualification._root_handle,
        leaf_handle=leaf_handle,
        attachment_authority=attachment_authority,
        production_capability=production_capability,
    )
