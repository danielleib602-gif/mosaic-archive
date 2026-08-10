"""Host and delegated-root qualification for the binding runner."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Literal, cast

from .competitive_binding_common import (
    BindingRunnerHostError,
    _backend_call,
    _controller_names,
    _format_id_set,
    _parse_id_set,
    _raise_combined_failures,
    _single_line,
)
from .competitive_binding_io import (
    _BindingBackend,
    _DescriptorRelativeFilesystemBackend,
)
from .competitive_binding_policy import (
    _REQUIRED_CONTROLLERS,
    _THREAD_TIERS,
    BindingRunnerPolicy,
    fixed_binding_policy,
)
from .competitive_binding_supervisor import (
    DelegatedRootCapabilityError,
    DelegatedRootIdentity,
    ExclusiveDelegatedCgroupRoot,
    _locked_capability_access,
)


@dataclass(frozen=True, slots=True)
class BindingHostFacts:
    """Minimal host facts used to qualify an exact CPU lane."""

    os_name: str
    machine: str
    allowed_cpu_affinity: tuple[int, ...]

    def __post_init__(self) -> None:
        if type(self.os_name) is not str or not self.os_name:
            raise TypeError("host OS name must be a non-empty string")
        if type(self.machine) is not str or not self.machine:
            raise TypeError("host machine must be a non-empty string")
        affinity = self.allowed_cpu_affinity
        if type(affinity) is not tuple or not affinity:
            raise ValueError("allowed CPU affinity must be a non-empty tuple")
        if any(type(cpu) is not int or cpu < 0 for cpu in affinity):
            raise ValueError("allowed CPU affinity must contain non-negative exact integers")
        if len(set(affinity)) != len(affinity):
            raise ValueError("allowed CPU affinity must not contain duplicates")


@dataclass(frozen=True, slots=True)
class BindingHostQualification:
    """A pinned host/cgroup qualification that remains explicitly non-binding."""

    policy: BindingRunnerPolicy
    cgroup_root: Path
    facts: BindingHostFacts
    requested_threads: int
    selected_cpus: tuple[int, ...]
    cpuset_cpus: str
    selected_mems: tuple[int, ...]
    cpuset_mems: str
    binding_eligible: Literal[False] = False
    session_id: str | None = None
    root_identity: DelegatedRootIdentity | None = None
    policy_digest: str | None = None
    _backend: _BindingBackend = field(repr=False, compare=False, default=None)  # type: ignore[assignment]
    _root_handle: object = field(repr=False, compare=False, default=None)
    _capability: ExclusiveDelegatedCgroupRoot | None = field(
        repr=False,
        compare=False,
        default=None,
    )

    def __post_init__(self) -> None:
        if self.binding_eligible is not False:
            raise ValueError("cgroup host qualification is never binding-eligible")
        if type(self.policy) is not BindingRunnerPolicy:
            raise TypeError("qualification policy must be a BindingRunnerPolicy")
        if not isinstance(self.cgroup_root, Path) or not self.cgroup_root.is_absolute():
            raise ValueError("qualification cgroup root must be an absolute Path")
        if not isinstance(self.facts, BindingHostFacts):
            raise TypeError("qualification facts must be BindingHostFacts")
        if type(self.requested_threads) is not int or self.requested_threads not in _THREAD_TIERS:
            raise ValueError(f"requested threads must be exactly one of {_THREAD_TIERS!r}")
        if (
            type(self.selected_cpus) is not tuple
            or len(self.selected_cpus) != self.requested_threads
            or any(type(cpu) is not int or cpu < 0 for cpu in self.selected_cpus)
            or tuple(sorted(set(self.selected_cpus))) != self.selected_cpus
        ):
            raise ValueError("selected CPUs must be a sorted exact thread-count tuple")
        if not set(self.selected_cpus).issubset(self.facts.allowed_cpu_affinity):
            raise ValueError("selected CPUs must be within the allowed host affinity")
        if self.cpuset_cpus != _format_id_set(self.selected_cpus):
            raise ValueError("cpuset CPU text is not canonical")
        if (
            type(self.selected_mems) is not tuple
            or not self.selected_mems
            or any(type(node) is not int or node < 0 for node in self.selected_mems)
            or tuple(sorted(set(self.selected_mems))) != self.selected_mems
        ):
            raise ValueError("selected memory nodes must be a sorted non-empty tuple")
        if self.cpuset_mems != _format_id_set(self.selected_mems):
            raise ValueError("cpuset memory-node text is not canonical")
        if self._backend is None or self._root_handle is None:
            raise ValueError("qualification must retain its inspected cgroup root")
        supervised = (
            self.session_id,
            self.root_identity,
            self.policy_digest,
            self._capability,
        )
        if any(value is not None for value in supervised) and not all(
            value is not None for value in supervised
        ):
            raise ValueError("supervised qualification binding must be complete")
        if self.session_id is not None:
            if (
                type(self.session_id) is not str
                or re.fullmatch(r"[0-9a-f]{32}", self.session_id) is None
            ):
                raise ValueError("supervised qualification session ID is not canonical")
            if not isinstance(self.root_identity, DelegatedRootIdentity):
                raise TypeError("supervised qualification root identity is invalid")
            if self.policy_digest != self.policy.policy_sha256:
                raise ValueError("supervised qualification policy digest is mismatched")


class _FilesystemBindingBackend(_DescriptorRelativeFilesystemBackend):
    def __init__(self) -> None:
        super().__init__(raise_combined_failures=_raise_combined_failures)


def _validate_requested_threads(requested_threads: int) -> None:
    if type(requested_threads) is not int or requested_threads not in _THREAD_TIERS:
        raise ValueError(f"requested threads must be exactly one of {_THREAD_TIERS!r}")


def qualify_binding_host(
    cgroup_root: Path,
    requested_threads: int,
    *,
    facts: BindingHostFacts | None = None,
    backend: object | None = None,
) -> BindingHostQualification:
    """Diagnose a path-selected root without granting mutation authority."""
    _validate_requested_threads(requested_threads)
    if not isinstance(cgroup_root, Path):
        raise TypeError("cgroup root must be a Path")
    if not cgroup_root.is_absolute():
        raise ValueError("cgroup root must be absolute")
    selected_backend = cast(
        _BindingBackend,
        _FilesystemBindingBackend() if backend is None else backend,
    )
    root_handle = _backend_call(
        "cgroup v2 delegated-root inspection failed",
        lambda: selected_backend.inspect_root(cgroup_root),
    )
    return _qualify_pinned_root(
        cgroup_root=cgroup_root,
        requested_threads=requested_threads,
        facts=facts,
        backend=selected_backend,
        root_handle=root_handle,
    )


def qualify_supervised_binding_host(
    capability: ExclusiveDelegatedCgroupRoot,
    requested_threads: int,
    *,
    facts: BindingHostFacts | None = None,
) -> BindingHostQualification:
    """Qualify only the inherited descriptor/root authenticated by a supervisor."""
    _validate_requested_threads(requested_threads)
    try:
        with _locked_capability_access(capability) as access:
            display_root = getattr(access.backend, "display_path", None)
            if not isinstance(display_root, Path):
                candidate = getattr(access.backend, "root_path", None)
                display_root = (
                    candidate
                    if isinstance(candidate, Path)
                    else (
                        Path("/pinned-cgroup") if os.name == "posix" else Path("C:/pinned-cgroup")
                    )
                )
            if not display_root.is_absolute():
                raise BindingRunnerHostError(
                    "delegated-root diagnostic display path is not absolute"
                )
            return _qualify_pinned_root(
                cgroup_root=display_root,
                requested_threads=requested_threads,
                facts=facts,
                backend=access.backend,
                root_handle=access.root_handle,
                capability=capability,
                session_id=access.session_id,
                root_identity=access.root_identity,
                policy_digest=access.policy_digest,
            )
    except DelegatedRootCapabilityError as error:
        raise BindingRunnerHostError(f"invalid delegated-root capability: {error}") from error


def _qualify_pinned_root(
    *,
    cgroup_root: Path,
    requested_threads: int,
    facts: BindingHostFacts | None,
    backend: _BindingBackend,
    root_handle: object,
    capability: ExclusiveDelegatedCgroupRoot | None = None,
    session_id: str | None = None,
    root_identity: DelegatedRootIdentity | None = None,
    policy_digest: str | None = None,
) -> BindingHostQualification:
    """Inspect a selected root; ``cgroup_root`` is diagnostic text only here."""
    selected_backend = backend
    if facts is None:
        os_name = _backend_call("failed to inspect host OS", selected_backend.system)
        machine = _backend_call("failed to inspect host machine", selected_backend.machine)
        affinity = _backend_call(
            "failed to inspect allowed CPU affinity",
            selected_backend.allowed_cpu_affinity,
        )
        facts = BindingHostFacts(
            os_name=os_name,
            machine=machine,
            allowed_cpu_affinity=affinity,
        )
    elif not isinstance(facts, BindingHostFacts):
        raise TypeError("facts must be BindingHostFacts")
    if facts.os_name != "Linux":
        raise BindingRunnerHostError("binding runner qualification requires Linux")
    if facts.machine.lower() not in {"x86_64", "amd64"}:
        raise BindingRunnerHostError("binding runner qualification requires x86_64")
    if len(facts.allowed_cpu_affinity) < requested_threads:
        raise BindingRunnerHostError(
            f"host affinity cannot supply the exact {requested_threads}-thread tier"
        )

    root_values: dict[str, str] = {}
    for filename in (
        "cgroup.controllers",
        "cgroup.subtree_control",
        "cgroup.type",
        "cpuset.cpus.effective",
        "cpuset.mems.effective",
    ):
        root_values[filename] = _backend_call(
            f"cgroup v2 root read failed for {filename}",
            partial(selected_backend.read_root, root_handle, filename),
        )

    controllers = _controller_names(
        root_values["cgroup.controllers"],
        "cgroup.controllers",
    )
    delegated = _controller_names(
        root_values["cgroup.subtree_control"],
        "cgroup.subtree_control",
    )
    for controller in _REQUIRED_CONTROLLERS:
        if controller not in controllers:
            raise BindingRunnerHostError(f"cgroup v2 root is missing the {controller} controller")
        if controller not in delegated:
            raise BindingRunnerHostError(f"cgroup v2 subtree delegation is missing {controller}")
    if _single_line(root_values["cgroup.type"], "cgroup.type") != "domain":
        raise BindingRunnerHostError("cgroup v2 root must be a domain cgroup")

    effective_cpus = _parse_id_set(
        root_values["cpuset.cpus.effective"],
        "effective CPU",
    )
    allowed = set(facts.allowed_cpu_affinity)
    candidates = tuple(cpu for cpu in effective_cpus if cpu in allowed)
    if len(candidates) < requested_threads:
        raise BindingRunnerHostError(
            f"effective CPU set cannot supply the exact {requested_threads}-thread tier"
        )
    selected_cpus = candidates[:requested_threads]
    selected_mems = _parse_id_set(
        root_values["cpuset.mems.effective"],
        "effective memory-node",
    )
    return BindingHostQualification(
        policy=fixed_binding_policy(),
        cgroup_root=cgroup_root,
        facts=facts,
        requested_threads=requested_threads,
        selected_cpus=selected_cpus,
        cpuset_cpus=_format_id_set(selected_cpus),
        selected_mems=selected_mems,
        cpuset_mems=_format_id_set(selected_mems),
        binding_eligible=False,
        session_id=session_id,
        root_identity=root_identity,
        policy_digest=policy_digest,
        _backend=selected_backend,
        _root_handle=root_handle,
        _capability=capability,
    )
