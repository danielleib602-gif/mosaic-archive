from __future__ import annotations

import dataclasses
import hashlib
import importlib
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import threading
import unittest
from collections.abc import Callable
from contextlib import nullcontext
from pathlib import Path, PurePosixPath
from typing import Any, cast
from unittest import mock

import mosaic_archive.competitive_binding_cgroup as binding_cgroup_module
import mosaic_archive.competitive_binding_io as binding_io_module
import mosaic_archive.competitive_binding_runner as binding_runner_module
from mosaic_archive.competitive_binding_policy import (
    BindingRunnerManifestError,
    BindingRunnerPolicy,
    fixed_binding_policy,
    load_binding_runner_manifest,
)
from mosaic_archive.competitive_binding_runner import (
    BindingCgroupLease,
    BindingHostFacts,
    BindingHostQualification,
    BindingRunnerCleanupError,
    BindingRunnerHostError,
    create_binding_cgroup,
    qualify_binding_host,
    qualify_supervised_binding_host,
)
from mosaic_archive.competitive_binding_supervisor import (
    DELEGATED_ROOT_POLICY_SHA256,
    _issue_capability_for_testing,
    _require_capability_access,
)
from mosaic_archive.competitive_contract import CONTRACT_SHA256

_ROOT = Path("/delegated-cgroup") if os.name == "posix" else Path("C:/delegated-cgroup")
_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_POLICY_PATH = _REPOSITORY_ROOT / "benchmarks" / "competitive-v1" / "runner-policy.json"
_LEAF_NAME = "mosaic-binding-test-0001"
_POLICY_ID = "mosaic-binding-runner-policy-v1"
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_MAX_SIGNED_64 = (1 << 63) - 1


@dataclasses.dataclass(frozen=True, slots=True)
class _RootHandle:
    identity: object


@dataclasses.dataclass(frozen=True, slots=True)
class _LeafHandle:
    identity: object
    name: str


class FakeBindingBackend:
    """Descriptor-shaped in-memory cgroup backend for platform-independent tests."""

    def __init__(
        self,
        *,
        system: str = "Linux",
        machine: str = "x86_64",
        affinity: tuple[int, ...] = tuple(range(2, 10)),
    ) -> None:
        self.system_name = system
        self.machine_name = machine
        self.affinity = affinity
        self.root_path = _ROOT
        self.root_handle = _RootHandle(object())
        self.root_files = {
            "cgroup.controllers": "cpuset memory pids\n",
            "cgroup.subtree_control": "cpuset memory pids\n",
            "cgroup.type": "domain\n",
            "cpuset.cpus.effective": "2-9\n",
            "cpuset.mems.effective": "0-1\n",
        }
        self.leaves: dict[str, dict[str, str]] = {}
        self.calls: list[tuple[Any, ...]] = []
        self.inspect_error: OSError | None = None
        self.create_error: OSError | None = None
        self.read_root_error: dict[str, OSError] = {}
        self.read_leaf_error: dict[str, OSError] = {}
        self.write_leaf_error: dict[str, OSError] = {}
        self.partial_write_file: str | None = None
        self.readback_override: dict[str, str] = {}
        self.remove_error: OSError | None = None
        self.kill_leaves_populated = True
        self.now = 0.0
        self.sleep_calls: list[float] = []

    def system(self) -> str:
        self.calls.append(("system",))
        return self.system_name

    def machine(self) -> str:
        self.calls.append(("machine",))
        return self.machine_name

    def allowed_cpu_affinity(self) -> tuple[int, ...]:
        self.calls.append(("allowed_cpu_affinity",))
        return self.affinity

    def inspect_root(self, root: Path) -> _RootHandle:
        self.calls.append(("inspect_root", root))
        if self.inspect_error is not None:
            raise self.inspect_error
        if root != self.root_path:
            raise FileNotFoundError(f"unexpected root: {root}")
        return self.root_handle

    def read_root(self, root: _RootHandle, filename: str) -> str:
        self.calls.append(("read_root", root, filename))
        if root is not self.root_handle:
            raise OSError("unpinned root handle")
        if filename in self.read_root_error:
            raise self.read_root_error[filename]
        try:
            return self.root_files[filename]
        except KeyError as error:
            raise FileNotFoundError(filename) from error

    def create_leaf(self, root: _RootHandle, name: str) -> _LeafHandle:
        self.calls.append(("create_leaf", root, name))
        if root is not self.root_handle:
            raise OSError("unpinned root handle")
        if self.create_error is not None:
            raise self.create_error
        if name in self.leaves:
            raise FileExistsError(name)
        self.leaves[name] = {
            "cgroup.events": "populated 0\nfrozen 0\n",
            "cgroup.procs": "",
            "cgroup.kill": "",
            "cpuset.cpus": "",
            "cpuset.cpus.effective": "",
            "cpuset.mems": "",
            "cpuset.mems.effective": "",
            "pids.max": "max\n",
            "memory.max": "max\n",
            "memory.swap.max": "max\n",
            "memory.peak": "0\n",
        }
        return _LeafHandle(object(), name)

    def read_leaf(self, leaf: _LeafHandle, filename: str) -> str:
        self.calls.append(("read_leaf", leaf, filename))
        if filename in self.read_leaf_error:
            raise self.read_leaf_error[filename]
        if filename in self.readback_override:
            return self.readback_override[filename]
        try:
            return self.leaves[leaf.name][filename]
        except KeyError as error:
            raise FileNotFoundError(filename) from error

    def write_leaf(self, leaf: _LeafHandle, filename: str, value: str) -> int:
        self.calls.append(("write_leaf", leaf, filename, value))
        if filename in self.write_leaf_error:
            raise self.write_leaf_error[filename]
        files = self.leaves[leaf.name]
        if self.partial_write_file == filename:
            partial = value[:-1]
            files[filename] = partial
            return len(partial.encode("ascii"))
        files[filename] = value
        if filename in {"cpuset.cpus", "cpuset.mems"}:
            files[f"{filename}.effective"] = value
        if filename == "cgroup.kill" and value == "1" and self.kill_leaves_populated:
            files["cgroup.events"] = "populated 0\nfrozen 0\n"
            files["cgroup.procs"] = ""
        return len(value.encode("ascii"))

    def remove_leaf(self, root: _RootHandle, leaf: _LeafHandle) -> None:
        self.calls.append(("remove_leaf", root, leaf))
        if root is not self.root_handle:
            raise OSError("unpinned root handle")
        if self.remove_error is not None:
            raise self.remove_error
        del self.leaves[leaf.name]

    def monotonic(self) -> float:
        self.calls.append(("monotonic",))
        return self.now

    def sleep(self, seconds: float) -> None:
        self.calls.append(("sleep", seconds))
        self.sleep_calls.append(seconds)
        self.now += seconds

    def leaf_writes(self, filename: str) -> list[str]:
        return [
            call[3] for call in self.calls if call[:1] == ("write_leaf",) and call[2] == filename
        ]


def _facts(
    *,
    system: str = "Linux",
    machine: str = "x86_64",
    affinity: tuple[int, ...] = tuple(range(2, 10)),
) -> BindingHostFacts:
    return BindingHostFacts(
        os_name=system,
        machine=machine,
        allowed_cpu_affinity=affinity,
    )


def _qualification(
    backend: FakeBindingBackend,
    *,
    requested_threads: int = 1,
) -> BindingHostQualification:
    return qualify_binding_host(
        _ROOT,
        requested_threads,
        facts=_facts(affinity=backend.affinity),
        backend=backend,
    )


def _lease(
    backend: FakeBindingBackend,
    *,
    requested_threads: int = 1,
    leaf_name: str = _LEAF_NAME,
) -> BindingCgroupLease:
    return binding_runner_module._create_binding_cgroup_for_testing(
        _qualification(backend, requested_threads=requested_threads),
        leaf_name=leaf_name,
        backend=backend,
    )


def _policy_payload(policy: BindingRunnerPolicy) -> dict[str, object]:
    return {
        "schema_version": policy.schema_version,
        "policy_id": policy.policy_id,
        "thread_tiers": list(policy.thread_tiers),
        "required_controllers": list(policy.required_controllers),
        "pids_max": policy.pids_max,
        "memory_max_bytes": policy.memory_max_bytes,
        "memory_swap_max_bytes": policy.memory_swap_max_bytes,
        "output_max_bytes": policy.output_max_bytes,
        "wall_time_limit_seconds": policy.wall_time_limit_seconds,
        "cleanup_timeout_seconds": policy.cleanup_timeout_seconds,
        "cleanup_poll_interval_milliseconds": policy.cleanup_poll_interval_milliseconds,
        "leaf_name_prefix": policy.leaf_name_prefix,
    }


class BindingRunnerModuleSplitTests(unittest.TestCase):
    def test_runner_facade_reexports_exact_implementation_symbols(self) -> None:
        common = importlib.import_module("mosaic_archive.competitive_binding_common")
        qualification = importlib.import_module("mosaic_archive.competitive_binding_qualification")
        cgroup = importlib.import_module("mosaic_archive.competitive_binding_cgroup")

        for facade_name, implementation, implementation_name in (
            ("BindingRunnerHostError", common, "BindingRunnerHostError"),
            ("BindingRunnerCleanupError", common, "BindingRunnerCleanupError"),
            ("BindingHostFacts", qualification, "BindingHostFacts"),
            ("BindingHostQualification", qualification, "BindingHostQualification"),
            ("qualify_binding_host", qualification, "qualify_binding_host"),
            (
                "qualify_supervised_binding_host",
                qualification,
                "qualify_supervised_binding_host",
            ),
            ("BindingCgroupLease", cgroup, "BindingCgroupLease"),
            ("create_binding_cgroup", cgroup, "create_binding_cgroup"),
            (
                "_create_binding_cgroup_for_testing",
                cgroup,
                "_create_binding_cgroup_for_testing",
            ),
        ):
            with self.subTest(symbol=facade_name):
                self.assertIs(
                    getattr(binding_runner_module, facade_name),
                    getattr(implementation, implementation_name),
                )

    def test_binding_modules_import_cleanly_in_dependency_orders(self) -> None:
        source_root = str(_REPOSITORY_ROOT / "src")
        environment = os.environ.copy()
        existing_pythonpath = environment.get("PYTHONPATH")
        environment["PYTHONPATH"] = (
            source_root
            if not existing_pythonpath
            else source_root + os.pathsep + existing_pythonpath
        )
        import_orders = (
            ("mosaic_archive.competitive_binding_runner",),
            (
                "mosaic_archive.competitive_binding_qualification",
                "mosaic_archive.competitive_binding_cgroup",
                "mosaic_archive.competitive_binding_runner",
            ),
            (
                "mosaic_archive.competitive_binding_cgroup",
                "mosaic_archive.competitive_binding_runner",
            ),
        )

        for modules in import_orders:
            with self.subTest(modules=modules):
                statement = "; ".join(f"import {module}" for module in modules)
                completed = subprocess.run(
                    [sys.executable, "-c", statement],
                    cwd=_REPOSITORY_ROOT,
                    env=environment,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(
                    completed.returncode,
                    0,
                    completed.stderr or completed.stdout,
                )


class DescriptorBindingIoTests(unittest.TestCase):
    def test_path_rotation_never_retries_ambiguous_close_or_leaks_new_fd(self) -> None:
        close_calls: list[int] = []
        close_error = OSError("old descriptor close failed")

        def close_once(descriptor: int) -> None:
            close_calls.append(descriptor)
            if descriptor == 10:
                raise close_error

        with (
            mock.patch("mosaic_archive.competitive_binding_io.os.name", "posix"),
            mock.patch(
                "mosaic_archive.competitive_binding_io.os.open",
                side_effect=(10, 11),
            ),
            mock.patch(
                "mosaic_archive.competitive_binding_io.os.close",
                side_effect=close_once,
            ),
            self.assertRaises(OSError) as raised,
        ):
            binding_io_module._secure_open_absolute_directory(
                cast(Any, PurePosixPath("/delegated"))
            )

        self.assertIs(raised.exception, close_error)
        self.assertEqual(close_calls, [10, 11])

    def test_leaf_open_closes_new_leaf_once_when_root_close_fails(self) -> None:
        backend = binding_io_module._DescriptorRelativeFilesystemBackend(
            raise_combined_failures=cast(Any, None)
        )
        root = binding_io_module._FilesystemRootHandle(
            path=Path("/delegated"),
            device=1,
            inode=2,
        )
        leaf = binding_io_module._FilesystemLeafHandle(
            root=root,
            name=_LEAF_NAME,
            device=1,
            inode=3,
        )
        close_calls: list[int] = []
        close_error = OSError("root close failed")

        def close_once(descriptor: int) -> None:
            close_calls.append(descriptor)
            if descriptor == 20:
                raise close_error

        with (
            mock.patch.object(backend, "_open_root", return_value=20),
            mock.patch(
                "mosaic_archive.competitive_binding_io.os.open",
                return_value=21,
            ),
            mock.patch(
                "mosaic_archive.competitive_binding_io.os.close",
                side_effect=close_once,
            ),
            self.assertRaises(OSError) as raised,
        ):
            backend._open_leaf(leaf)

        self.assertIs(raised.exception, close_error)
        self.assertEqual(close_calls, [20, 21])


class BindingRunnerPolicyTests(unittest.TestCase):
    def test_fixed_policy_has_independently_recomputable_canonical_digest(self) -> None:
        policy = fixed_binding_policy()
        second = fixed_binding_policy()
        canonical = json.dumps(
            _policy_payload(policy),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        self.assertIsInstance(policy, BindingRunnerPolicy)
        self.assertEqual(policy, second)
        self.assertEqual(policy.schema_version, 1)
        self.assertEqual(policy.policy_id, _POLICY_ID)
        self.assertEqual(policy.digest_algorithm, "sha256_canonical_json_v1")
        self.assertEqual(policy.policy_sha256, hashlib.sha256(canonical).hexdigest())
        self.assertRegex(policy.policy_sha256, _SHA256_RE)
        self.assertEqual(policy.thread_tiers, (1, 8))
        self.assertEqual(policy.required_controllers, ("cpuset", "memory", "pids"))

    def test_committed_manifest_binds_the_exact_qualification_policy(self) -> None:
        policy = fixed_binding_policy()
        manifest = load_binding_runner_manifest(_POLICY_PATH)
        qualification_policy = _policy_payload(policy)
        qualification_policy["digest_algorithm"] = policy.digest_algorithm
        qualification_policy["policy_sha256"] = policy.policy_sha256
        expected_payload = {
            "schema_version": 1,
            "manifest_id": "mosaic-competitive-runner-manifest-v1",
            "contract_sha256": CONTRACT_SHA256,
            "authority_state": "qualification_only_until_native_pidns_exec_identity_v1",
            "binding_eligible": False,
            "qualification_policy": qualification_policy,
            "implemented_qualification_controls": {
                "host": "Linux_x86_64_cgroup_v2_v1",
                "cpuset_selection": "lowest_allowed_logical_cpu_ids_v1",
                "cpuset_mems": "all_parent_effective_memory_nodes_v1",
                "fresh_leaf_per_measurement": True,
                "exact_control_write_readback": True,
                "effective_cpuset_verification": ("after_setup_before_attach_and_after_run_v1"),
                "lease_state_machine": "single_attach_exclusive_finalize_v1",
                "memory_peak_origin": "fresh_leaf_creation_v1",
                "memory_peak_read": "positive_i64_after_unpopulated_v1",
                "cleanup": "cgroup_kill_wait_unpopulated_remove_v1",
            },
            "required_before_binding": {
                "native_pid_namespace_launcher": True,
                "exclusive_delegated_cgroup_root": True,
                "pre_exec_cgroup_placement": True,
                "complete_descendant_exec_identity": True,
                "fixed_public_environment_capture": True,
                "bounded_output_capture": True,
                "input_prewarm_evidence": True,
                "round_trip_and_archive_identity": True,
                "signed_raw_run_evidence": True,
            },
        }
        canonical = json.dumps(
            expected_payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        expected_manifest_sha256 = hashlib.sha256(canonical).hexdigest()
        self.assertEqual(
            manifest,
            {
                **expected_payload,
                "manifest_digest_algorithm": ("sha256_canonical_json_without_manifest_digest_v1"),
                "manifest_sha256": expected_manifest_sha256,
            },
        )

    def test_manifest_loader_rejects_duplicate_or_nonfinite_authority(self) -> None:
        cases = (
            (
                b'{"binding_eligible":true,"binding_eligible":false}',
                "duplicate",
            ),
            (
                b'{"binding_eligible":NaN}',
                "non-finite",
            ),
        )
        for raw, pattern in cases:
            with tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "runner-policy.json"
                path.write_bytes(raw)
                with (
                    self.subTest(raw=raw),
                    self.assertRaisesRegex(BindingRunnerManifestError, pattern),
                ):
                    load_binding_runner_manifest(path)

    def test_manifest_loader_bounds_integer_tokens_before_python_limit(self) -> None:
        raw = b'{"schema_version":' + (b"9" * 5_000) + b"}"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "runner-policy.json"
            path.write_bytes(raw)
            with self.assertRaisesRegex(BindingRunnerManifestError, "integer.*digit limit"):
                load_binding_runner_manifest(path)

    def test_manifest_loader_rejects_directory_hardlink_and_fifo_without_blocking(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(BindingRunnerManifestError, "regular file"):
                load_binding_runner_manifest(root)

            source = root / "source.json"
            source.write_bytes(_POLICY_PATH.read_bytes())
            hardlink = root / "hardlink.json"
            try:
                os.link(source, hardlink)
            except OSError as error:
                self.skipTest(f"hard links are unavailable: {error}")
            with self.assertRaisesRegex(BindingRunnerManifestError, "single-link"):
                load_binding_runner_manifest(source)

            make_fifo = getattr(os, "mkfifo", None)
            if make_fifo is None:
                return
            fifo = root / "manifest.fifo"
            make_fifo(fifo)
            outcome: list[BaseException] = []

            def load_fifo() -> None:
                try:
                    load_binding_runner_manifest(fifo)
                except BaseException as error:
                    outcome.append(error)

            thread = threading.Thread(target=load_fifo, daemon=True)
            thread.start()
            thread.join(timeout=1)
            self.assertFalse(thread.is_alive(), "manifest FIFO open blocked")
            self.assertEqual(len(outcome), 1)
            self.assertIsInstance(outcome[0], BindingRunnerManifestError)

    def test_manifest_loader_rejects_rehashed_identity_or_policy_mutations(self) -> None:
        mutations = (
            ("contract_sha256", "0" * 64),
            ("qualification_policy.memory_max_bytes", 1),
            ("qualification_policy.schema_version", True),
            ("qualification_policy.memory_swap_max_bytes", False),
            ("qualification_policy.thread_tiers", [True, 8]),
            ("required_before_binding.native_pid_namespace_launcher", False),
            ("required_before_binding.exclusive_delegated_cgroup_root", 1),
            ("implemented_qualification_controls.fresh_leaf_per_measurement", 1),
        )
        for field, value in mutations:
            manifest = load_binding_runner_manifest(_POLICY_PATH)
            if "." in field:
                parent, child = field.split(".", 1)
                nested = manifest[parent]
                assert isinstance(nested, dict)
                nested[child] = value
            else:
                manifest[field] = value
            digest_payload = {
                key: item
                for key, item in manifest.items()
                if key not in {"manifest_digest_algorithm", "manifest_sha256"}
            }
            canonical = json.dumps(
                digest_payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            manifest["manifest_sha256"] = hashlib.sha256(canonical).hexdigest()

            with tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "runner-policy.json"
                path.write_text(
                    json.dumps(manifest, ensure_ascii=False),
                    encoding="utf-8",
                )
                with (
                    self.subTest(field=field),
                    self.assertRaises(BindingRunnerManifestError),
                ):
                    load_binding_runner_manifest(path)

    def test_policy_limits_are_fixed_exact_types_and_not_caller_tunable(self) -> None:
        policy = fixed_binding_policy()
        positive_integer_limits = (
            policy.pids_max,
            policy.memory_max_bytes,
            policy.output_max_bytes,
            policy.wall_time_limit_seconds,
            policy.cleanup_timeout_seconds,
            policy.cleanup_poll_interval_milliseconds,
        )
        self.assertTrue(all(type(value) is int and value > 0 for value in positive_integer_limits))
        self.assertIs(type(policy.memory_swap_max_bytes), int)
        self.assertEqual(policy.memory_swap_max_bytes, 0)
        self.assertLess(
            policy.cleanup_poll_interval_milliseconds,
            policy.cleanup_timeout_seconds * 1000,
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            policy.pids_max = 1  # type: ignore[misc]

    def test_policy_rejects_type_confusion_that_compares_equal_to_fixed_values(
        self,
    ) -> None:
        class HostileInteger(int):
            def __str__(self) -> str:
                return "max"

        class HostileString(str):
            pass

        policy = fixed_binding_policy()
        mutations = (
            {"schema_version": True},
            {"memory_max_bytes": HostileInteger(policy.memory_max_bytes)},
            {"thread_tiers": [1, 8]},
            {"required_controllers": ("cpuset", "memory", HostileString("pids"))},
            {"leaf_name_prefix": HostileString(policy.leaf_name_prefix)},
            {"policy_sha256": HostileString(policy.policy_sha256)},
        )
        for mutation in mutations:
            with (
                self.subTest(mutation=mutation),
                self.assertRaises((TypeError, ValueError)),
            ):
                dataclasses.replace(policy, **mutation)


class BindingHostQualificationTests(unittest.TestCase):
    def test_filesystem_magic_rejects_non_linux_before_libc_call(self) -> None:
        with (
            mock.patch.object(binding_io_module.sys, "platform", "darwin"),
            mock.patch.object(binding_io_module.ctypes, "CDLL") as load_library,
            self.assertRaisesRegex(OSError, "requires Linux"),
        ):
            binding_io_module._filesystem_magic(0)
        load_library.assert_not_called()

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux fstatfs semantics")
    def test_production_backend_rejects_ordinary_filesystem_as_cgroup_v2(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            # macOS spells its temporary root through /var, which is a symlink.
            # Resolve the test fixture so this case reaches the filesystem-type
            # rejection instead of correctly failing earlier on that path alias.
            root = Path(temporary).resolve(strict=True)
            facts = BindingHostFacts(
                os_name="Linux",
                machine="x86_64",
                allowed_cpu_affinity=tuple(range(8)),
            )
            with self.assertRaisesRegex(BindingRunnerHostError, "cgroup-v2 filesystem"):
                qualify_binding_host(root, 1, facts=facts)

    def test_selects_the_lowest_exact_affinity_lane_and_all_effective_mems(self) -> None:
        backend = FakeBindingBackend(affinity=(9, 5, 2, 7, 4, 8, 3, 6))

        one = qualify_binding_host(
            _ROOT,
            1,
            facts=_facts(affinity=backend.affinity),
            backend=backend,
        )
        eight = qualify_binding_host(
            _ROOT,
            8,
            facts=_facts(affinity=backend.affinity),
            backend=backend,
        )

        self.assertEqual(one.selected_cpus, (2,))
        self.assertEqual(one.cpuset_cpus, "2")
        self.assertEqual(eight.selected_cpus, tuple(range(2, 10)))
        self.assertEqual(eight.cpuset_cpus, "2-9")
        self.assertEqual(one.selected_mems, (0, 1))
        self.assertEqual(one.cpuset_mems, "0-1")
        self.assertEqual(eight.selected_mems, one.selected_mems)
        self.assertIs(one.binding_eligible, False)
        self.assertIs(eight.binding_eligible, False)

    def test_supervised_qualification_uses_only_capability_backend_and_binds_session(
        self,
    ) -> None:
        backend = FakeBindingBackend()
        capability = _issue_capability_for_testing(
            backend=backend,
            root_handle=backend.root_handle,
            root_device=31,
            root_inode=41,
        )
        self.addCleanup(capability.close)

        qualification = qualify_supervised_binding_host(
            capability,
            1,
            facts=_facts(),
        )

        self.assertFalse(any(call[:1] == ("inspect_root",) for call in backend.calls))
        self.assertEqual(qualification.session_id, capability.session_id)
        self.assertEqual(qualification.root_identity, capability.root_identity)
        self.assertEqual(qualification.policy_digest, DELEGATED_ROOT_POLICY_SHA256)
        self.assertIs(qualification._backend, backend)
        self.assertIs(qualification._root_handle, backend.root_handle)
        self.assertIs(qualification._capability, capability)
        self.assertIs(qualification.binding_eligible, False)

    def test_captures_facts_from_backend_when_not_supplied(self) -> None:
        backend = FakeBindingBackend(machine="AMD64")

        qualification = qualify_binding_host(_ROOT, 8, backend=backend)

        self.assertEqual(qualification.facts.os_name, "Linux")
        self.assertEqual(qualification.facts.machine, "AMD64")
        self.assertEqual(
            qualification.facts.allowed_cpu_affinity,
            tuple(range(2, 10)),
        )
        self.assertIn(("system",), backend.calls)
        self.assertIn(("machine",), backend.calls)
        self.assertIn(("allowed_cpu_affinity",), backend.calls)

    def test_policy_facts_and_qualification_are_frozen_non_binding_values(self) -> None:
        backend = FakeBindingBackend()
        facts = _facts()
        qualification = qualify_binding_host(
            _ROOT,
            1,
            facts=facts,
            backend=backend,
        )

        for value in (facts, qualification):
            self.assertFalse(hasattr(value, "__dict__"))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            facts.machine = "aarch64"  # type: ignore[misc]
        with self.assertRaises(dataclasses.FrozenInstanceError):
            qualification.cpuset_cpus = "7"  # type: ignore[misc]
        with self.assertRaisesRegex(ValueError, "never binding-eligible"):
            dataclasses.replace(qualification, binding_eligible=True)  # type: ignore[arg-type]

    def test_rejects_every_thread_tier_except_exact_integer_one_or_eight(self) -> None:
        backend = FakeBindingBackend()
        for value in (0, 2, 4, 16, -1, True, 1.0, "1", None):
            with (
                self.subTest(value=value),
                self.assertRaises((TypeError, ValueError)),
            ):
                qualify_binding_host(
                    _ROOT,
                    cast(Any, value),
                    facts=_facts(),
                    backend=backend,
                )

    def test_rejects_non_linux_non_x86_64_and_insufficient_affinity(self) -> None:
        cases = (
            (_facts(system="Windows"), "Linux"),
            (_facts(system="Darwin"), "Linux"),
            (_facts(machine="aarch64"), "x86_64"),
            (_facts(machine="i686"), "x86_64"),
            (_facts(affinity=(0, 1, 2, 3)), "8"),
        )
        for facts, pattern in cases:
            with (
                self.subTest(facts=facts),
                self.assertRaisesRegex(BindingRunnerHostError, pattern),
            ):
                qualify_binding_host(
                    _ROOT,
                    8,
                    facts=facts,
                    backend=FakeBindingBackend(),
                )

    def test_requires_unified_domain_and_all_delegated_controllers(self) -> None:
        mutations = (
            ("cgroup.controllers", "cpuset pids\n", "memory"),
            ("cgroup.subtree_control", "cpuset memory\n", "pids"),
            ("cgroup.type", "threaded\n", "domain"),
        )
        for filename, value, pattern in mutations:
            backend = FakeBindingBackend()
            backend.root_files[filename] = value
            with (
                self.subTest(filename=filename),
                self.assertRaisesRegex(BindingRunnerHostError, pattern),
            ):
                _qualification(backend)

        backend = FakeBindingBackend()
        del backend.root_files["cgroup.controllers"]
        with self.assertRaisesRegex(BindingRunnerHostError, "cgroup v2"):
            _qualification(backend)

    def test_rejects_malformed_or_insufficient_effective_sets(self) -> None:
        cases = (
            ("cpuset.cpus.effective", "", "CPU"),
            ("cpuset.cpus.effective", "2-4,broken\n", "CPU"),
            ("cpuset.cpus.effective", "2-8\n", "8"),
            ("cpuset.mems.effective", "", "memory"),
            ("cpuset.mems.effective", "-1\n", "memory"),
        )
        for filename, value, pattern in cases:
            backend = FakeBindingBackend()
            backend.root_files[filename] = value
            with (
                self.subTest(filename=filename, value=value),
                self.assertRaisesRegex(BindingRunnerHostError, pattern),
            ):
                _qualification(backend, requested_threads=8)

    def test_root_is_inspected_once_and_symlink_or_read_failures_fail_closed(self) -> None:
        backend = FakeBindingBackend()
        qualification = _qualification(backend)
        self.assertIsInstance(qualification, BindingHostQualification)
        self.assertEqual(
            [call for call in backend.calls if call[:1] == ("inspect_root",)],
            [("inspect_root", _ROOT)],
        )

        for error, pattern in (
            (OSError("root is a symlink"), "symlink"),
            (PermissionError("delegation denied"), "delegation"),
        ):
            failing = FakeBindingBackend()
            failing.inspect_error = error
            with (
                self.subTest(error=error),
                self.assertRaisesRegex(BindingRunnerHostError, pattern),
            ):
                _qualification(failing)

        failing = FakeBindingBackend()
        failing.read_root_error["cpuset.mems.effective"] = OSError("short read")
        with self.assertRaisesRegex(BindingRunnerHostError, "short read"):
            _qualification(failing)

    def test_rejects_hostile_fact_and_root_argument_types(self) -> None:
        for affinity in ((), (0, 0), (1, -1), (True,), (1.0,), ("1",)):
            with (
                self.subTest(affinity=affinity),
                self.assertRaises((TypeError, ValueError)),
            ):
                BindingHostFacts(
                    os_name="Linux",
                    machine="x86_64",
                    allowed_cpu_affinity=cast(Any, affinity),
                )

        backend = FakeBindingBackend()
        for root in (None, "", "C:/delegated-cgroup", Path("relative/root")):
            with (
                self.subTest(root=root),
                self.assertRaises((TypeError, ValueError, BindingRunnerHostError)),
            ):
                qualify_binding_host(
                    cast(Any, root),
                    1,
                    facts=_facts(),
                    backend=backend,
                )


class BindingCgroupCreationTests(unittest.TestCase):
    def test_production_leaf_creation_requires_native_exclusive_root_capability(
        self,
    ) -> None:
        backend = FakeBindingBackend()
        qualification = _qualification(backend)
        with self.assertRaisesRegex(
            BindingRunnerHostError,
            "exact issued delegated-root capability",
        ):
            create_binding_cgroup(
                qualification,
                capability=cast(Any, object()),
                leaf_name=_LEAF_NAME,
            )
        self.assertEqual(backend.leaves, {})

    def test_path_qualification_and_test_capability_cannot_authorize_mutation(self) -> None:
        backend = FakeBindingBackend()
        capability = _issue_capability_for_testing(
            backend=backend,
            root_handle=backend.root_handle,
        )
        self.addCleanup(capability.close)

        with self.assertRaisesRegex(BindingRunnerHostError, "native-supervisor provenance"):
            create_binding_cgroup(
                _qualification(backend),
                capability=capability,
                leaf_name=_LEAF_NAME,
            )
        self.assertEqual(backend.leaves, {})

    def test_capability_mismatch_is_checked_before_leaf_mutation(self) -> None:
        backend = FakeBindingBackend()
        capability = _issue_capability_for_testing(
            backend=backend,
            root_handle=backend.root_handle,
        )
        self.addCleanup(capability.close)
        qualification = qualify_supervised_binding_host(capability, 1, facts=_facts())
        mismatched = dataclasses.replace(qualification, session_id="ff" * 16)
        production_access = dataclasses.replace(
            _require_capability_access(capability),
            production_inherited=True,
        )

        with (
            mock.patch.object(
                binding_cgroup_module,
                "_locked_capability_access",
                return_value=nullcontext(production_access),
            ),
            self.assertRaisesRegex(BindingRunnerHostError, "does not match"),
        ):
            create_binding_cgroup(
                mismatched,
                capability=capability,
                leaf_name=_LEAF_NAME,
            )
        self.assertEqual(backend.leaves, {})

    def test_production_lease_revalidates_capability_before_backend_access(self) -> None:
        backend = FakeBindingBackend()
        capability = _issue_capability_for_testing(
            backend=backend,
            root_handle=backend.root_handle,
        )
        qualification = qualify_supervised_binding_host(capability, 1, facts=_facts())
        production_access = dataclasses.replace(
            _require_capability_access(capability),
            production_inherited=True,
        )
        with mock.patch.object(
            binding_cgroup_module,
            "_locked_capability_access",
            return_value=nullcontext(production_access),
        ):
            lease = create_binding_cgroup(
                qualification,
                capability=capability,
                leaf_name=_LEAF_NAME,
            )

        capability.close()
        calls_before = list(backend.calls)
        with self.assertRaisesRegex(BindingRunnerHostError, "capability.*closed"):
            lease.verify_effective_cpuset()
        self.assertEqual(backend.calls, calls_before)

        with mock.patch.object(
            binding_cgroup_module,
            "_locked_capability_access",
            return_value=nullcontext(production_access),
        ):
            lease.cleanup()

    def test_creates_fresh_leaf_with_exact_cpuset_and_fixed_resource_limits(self) -> None:
        backend = FakeBindingBackend()
        qualification = _qualification(backend, requested_threads=8)
        policy = fixed_binding_policy()

        lease = binding_runner_module._create_binding_cgroup_for_testing(
            qualification,
            leaf_name=_LEAF_NAME,
            backend=backend,
        )

        self.assertIsInstance(lease, BindingCgroupLease)
        self.assertEqual(lease.qualification, qualification)
        self.assertEqual(lease.leaf_name, _LEAF_NAME)
        self.assertIs(lease.binding_eligible, False)
        files = backend.leaves[_LEAF_NAME]
        self.assertEqual(files["cpuset.cpus"], qualification.cpuset_cpus)
        self.assertEqual(files["cpuset.mems"], qualification.cpuset_mems)
        self.assertEqual(files["pids.max"], str(policy.pids_max))
        self.assertEqual(files["memory.max"], str(policy.memory_max_bytes))
        self.assertEqual(files["memory.swap.max"], str(policy.memory_swap_max_bytes))
        self.assertEqual(backend.leaf_writes("memory.peak"), [])
        lease.cleanup()

    def test_rejects_leaf_reuse_symlinks_and_hostile_names_without_writing(self) -> None:
        hostile_names = (
            "",
            ".",
            "..",
            "../escape",
            "nested/escape",
            r"nested\escape",
            " leading",
            "trailing ",
            "mosaic-\N{FIRE}",
            "a" * 256,
            "nul\x00byte",
        )
        for name in hostile_names:
            backend = FakeBindingBackend()
            qualification = _qualification(backend)
            with (
                self.subTest(name=name),
                self.assertRaises((TypeError, ValueError, BindingRunnerHostError)),
            ):
                binding_runner_module._create_binding_cgroup_for_testing(
                    qualification,
                    leaf_name=name,
                    backend=backend,
                )
            self.assertEqual(backend.leaves, {})

        backend = FakeBindingBackend()
        qualification = _qualification(backend)
        backend.leaves[_LEAF_NAME] = {"occupied": "directory"}
        with self.assertRaisesRegex(BindingRunnerHostError, "fresh|exist"):
            binding_runner_module._create_binding_cgroup_for_testing(
                qualification,
                leaf_name=_LEAF_NAME,
                backend=backend,
            )
        self.assertEqual(backend.leaves[_LEAF_NAME], {"occupied": "directory"})

        backend = FakeBindingBackend()
        backend.create_error = OSError("leaf collision is a symlink")
        with self.assertRaisesRegex(BindingRunnerHostError, "symlink"):
            binding_runner_module._create_binding_cgroup_for_testing(
                _qualification(backend),
                leaf_name=_LEAF_NAME,
                backend=backend,
            )
        self.assertFalse(any(call[:1] == ("write_leaf",) for call in backend.calls))

    def test_partial_write_or_readback_mismatch_cleans_leaf_and_fails_closed(self) -> None:
        for failure_kind in ("partial", "readback"):
            backend = FakeBindingBackend()
            qualification = _qualification(backend)
            if failure_kind == "partial":
                backend.partial_write_file = "memory.max"
            else:
                backend.readback_override["pids.max"] = "999"

            with (
                self.subTest(failure_kind=failure_kind),
                self.assertRaisesRegex(BindingRunnerHostError, "write|readback|exact"),
            ):
                binding_runner_module._create_binding_cgroup_for_testing(
                    qualification,
                    leaf_name=_LEAF_NAME,
                    backend=backend,
                )

            self.assertNotIn(_LEAF_NAME, backend.leaves)
            self.assertTrue(
                any(call[:1] == ("remove_leaf",) for call in backend.calls),
                "failed setup must clean its fresh leaf",
            )

    def test_effective_cpuset_mismatch_cleans_leaf_and_fails_closed(self) -> None:
        for filename, value in (
            ("cpuset.cpus.effective", "3"),
            ("cpuset.mems.effective", "1"),
        ):
            backend = FakeBindingBackend()
            backend.readback_override[filename] = value

            with (
                self.subTest(filename=filename),
                self.assertRaisesRegex(BindingRunnerHostError, "effective.*mismatch"),
            ):
                binding_runner_module._create_binding_cgroup_for_testing(
                    _qualification(backend),
                    leaf_name=_LEAF_NAME,
                    backend=backend,
                )

            self.assertNotIn(_LEAF_NAME, backend.leaves)

    def test_setup_cleanup_failure_is_reported_and_leaf_is_not_forgotten(self) -> None:
        backend = FakeBindingBackend()
        backend.partial_write_file = "memory.max"
        backend.remove_error = OSError("rmdir denied")

        with self.assertRaisesRegex(
            BindingRunnerCleanupError,
            "memory.max.*rmdir denied",
        ) as raised:
            binding_runner_module._create_binding_cgroup_for_testing(
                _qualification(backend),
                leaf_name=_LEAF_NAME,
                backend=backend,
            )

        self.assertIsInstance(raised.exception.primary_error, BindingRunnerHostError)
        self.assertIs(raised.exception.cleanup_error, backend.remove_error)
        self.assertIn(_LEAF_NAME, backend.leaves)

    def test_setup_preserves_process_control_base_exceptions_after_cleanup(self) -> None:
        backend = FakeBindingBackend()
        interrupt = KeyboardInterrupt("stop now")
        backend.write_leaf_error["memory.max"] = interrupt  # type: ignore[assignment]

        with self.assertRaises(KeyboardInterrupt) as raised:
            binding_runner_module._create_binding_cgroup_for_testing(
                _qualification(backend),
                leaf_name=_LEAF_NAME,
                backend=backend,
            )

        self.assertIs(raised.exception, interrupt)
        self.assertNotIn(_LEAF_NAME, backend.leaves)

    def test_setup_groups_process_control_and_cleanup_failures(self) -> None:
        backend = FakeBindingBackend()
        interrupt = KeyboardInterrupt("stop now")
        backend.write_leaf_error["memory.max"] = interrupt  # type: ignore[assignment]
        backend.remove_error = OSError("rmdir denied")

        with self.assertRaises(BaseExceptionGroup) as raised:
            binding_runner_module._create_binding_cgroup_for_testing(
                _qualification(backend),
                leaf_name=_LEAF_NAME,
                backend=backend,
            )

        self.assertEqual(
            raised.exception.exceptions,
            (interrupt, backend.remove_error),
        )
        self.assertIn(_LEAF_NAME, backend.leaves)


class BindingCgroupLeaseTests(unittest.TestCase):
    def test_production_lease_refuses_attachment_before_backend_access(self) -> None:
        backend = FakeBindingBackend()
        capability = _issue_capability_for_testing(
            backend=backend,
            root_handle=backend.root_handle,
        )
        self.addCleanup(capability.close)
        qualification = qualify_supervised_binding_host(capability, 1, facts=_facts())
        production_access = dataclasses.replace(
            _require_capability_access(capability),
            production_inherited=True,
        )
        with mock.patch.object(
            binding_cgroup_module,
            "_locked_capability_access",
            return_value=nullcontext(production_access),
        ):
            lease = create_binding_cgroup(
                qualification,
                capability=capability,
                leaf_name=_LEAF_NAME,
            )
        calls_before = list(backend.calls)

        with self.assertRaisesRegex(BindingRunnerHostError, "clone3 pre-exec"):
            lease.attach_process(4242)

        self.assertEqual(lease.attachment_authority, "native-preexec-required")
        self.assertEqual(backend.calls, calls_before)
        with mock.patch.object(
            binding_cgroup_module,
            "_locked_capability_access",
            return_value=nullcontext(production_access),
        ):
            lease.cleanup()

    def test_attach_process_accepts_only_positive_exact_int_and_verifies_membership(
        self,
    ) -> None:
        backend = FakeBindingBackend()
        lease = _lease(backend)

        lease.attach_process(4242)
        self.assertEqual(backend.leaf_writes("cgroup.procs"), ["4242"])
        self.assertEqual(backend.leaves[_LEAF_NAME]["cgroup.procs"], "4242")

        for pid in (0, -1, True, 1.0, "1", None):
            with (
                self.subTest(pid=pid),
                self.assertRaises((TypeError, ValueError)),
            ):
                lease.attach_process(pid)  # type: ignore[arg-type]
        lease.cleanup()

        backend = FakeBindingBackend()
        lease = _lease(backend)
        backend.readback_override["cgroup.procs"] = "9999\n"
        with self.assertRaisesRegex(BindingRunnerHostError, "membership|cgroup.procs"):
            lease.attach_process(4243)
        lease.cleanup()

    def test_attach_and_peak_read_recheck_the_effective_cpuset(self) -> None:
        backend = FakeBindingBackend()
        lease = _lease(backend)
        lease.attach_process(4242)
        backend.readback_override["cpuset.cpus.effective"] = "3"

        with self.assertRaisesRegex(BindingRunnerHostError, "effective.*mismatch"):
            lease.read_memory_peak_bytes()

        del backend.readback_override["cpuset.cpus.effective"]
        lease.cleanup()

    def test_peak_read_is_forbidden_while_populated(self) -> None:
        backend = FakeBindingBackend()
        lease = _lease(backend)
        lease.attach_process(4242)
        backend.leaves[_LEAF_NAME]["cgroup.events"] = "populated 1\nfrozen 0\n"
        peak_reads_before = len(
            [
                call
                for call in backend.calls
                if call[:1] == ("read_leaf",) and call[2] == "memory.peak"
            ]
        )

        with self.assertRaisesRegex(BindingRunnerHostError, "populated"):
            lease.read_memory_peak_bytes()

        peak_reads_after = len(
            [
                call
                for call in backend.calls
                if call[:1] == ("read_leaf",) and call[2] == "memory.peak"
            ]
        )
        self.assertEqual(peak_reads_after, peak_reads_before)
        lease.cleanup()

    def test_peak_read_requires_positive_signed_64_bit_canonical_integer(self) -> None:
        invalid_values = ("0\n", "-1\n", f"{1 << 63}\n", "1.0\n", "nan\n", " 1\n", "1 2\n")
        for value in invalid_values:
            backend = FakeBindingBackend()
            lease = _lease(backend)
            lease.attach_process(4242)
            backend.leaves[_LEAF_NAME]["memory.peak"] = value
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(BindingRunnerHostError, "memory.peak"),
            ):
                lease.read_memory_peak_bytes()
            lease.cleanup()

        backend = FakeBindingBackend()
        lease = _lease(backend)
        lease.attach_process(4242)
        backend.leaves[_LEAF_NAME]["memory.peak"] = f"{_MAX_SIGNED_64}\n"
        self.assertEqual(lease.read_memory_peak_bytes(), _MAX_SIGNED_64)
        lease.cleanup()

    def test_lease_allows_only_one_attachment_and_one_peak_finalization(self) -> None:
        backend = FakeBindingBackend()
        lease = _lease(backend)
        lease.attach_process(4242)
        backend.leaves[_LEAF_NAME]["memory.peak"] = "12345\n"

        self.assertEqual(lease.read_memory_peak_bytes(), 12345)
        with self.assertRaisesRegex(BindingRunnerHostError, "state"):
            lease.attach_process(4243)
        with self.assertRaisesRegex(BindingRunnerHostError, "state"):
            lease.read_memory_peak_bytes()
        lease.cleanup()

    def test_peak_finalization_rejects_repopulation_during_capture(self) -> None:
        backend = FakeBindingBackend()
        lease = _lease(backend)
        lease.attach_process(4242)
        backend.leaves[_LEAF_NAME]["memory.peak"] = "12345\n"
        original_read_leaf = backend.read_leaf

        def repopulate_after_peak(leaf: _LeafHandle, filename: str) -> str:
            result = original_read_leaf(leaf, filename)
            if filename == "memory.peak":
                backend.leaves[_LEAF_NAME]["cgroup.events"] = "populated 1\n"
            return result

        backend.read_leaf = repopulate_after_peak  # type: ignore[method-assign]
        with self.assertRaisesRegex(BindingRunnerHostError, "during memory.peak"):
            lease.read_memory_peak_bytes()

        lease.cleanup()

    def test_await_unpopulated_polls_with_fixed_policy_and_times_out_closed(self) -> None:
        backend = FakeBindingBackend()
        lease = _lease(backend)
        backend.leaves[_LEAF_NAME]["cgroup.events"] = "populated 1\n"
        original_sleep = backend.sleep
        poll_count = 0

        def release_after_two_polls(seconds: float) -> None:
            nonlocal poll_count
            original_sleep(seconds)
            poll_count += 1
            if poll_count == 2:
                backend.leaves[_LEAF_NAME]["cgroup.events"] = "populated 0\n"

        backend.sleep = release_after_two_polls  # type: ignore[method-assign]
        lease.await_unpopulated()
        self.assertEqual(len(backend.sleep_calls), 2)
        expected_poll = fixed_binding_policy().cleanup_poll_interval_milliseconds / 1000
        self.assertTrue(all(seconds == expected_poll for seconds in backend.sleep_calls))
        lease.cleanup()

        backend = FakeBindingBackend()
        lease = _lease(backend)
        backend.leaves[_LEAF_NAME]["cgroup.events"] = "populated 1\n"
        with self.assertRaisesRegex(BindingRunnerHostError, "timed out|populated"):
            lease.await_unpopulated()
        self.assertIn(_LEAF_NAME, backend.leaves)
        backend.kill_leaves_populated = True
        lease.cleanup()

    def test_kill_and_cleanup_are_fail_closed_and_remove_only_after_population_zero(
        self,
    ) -> None:
        backend = FakeBindingBackend()
        lease = _lease(backend)
        backend.leaves[_LEAF_NAME]["cgroup.events"] = "populated 1\n"

        lease.cleanup()

        self.assertEqual(backend.leaf_writes("cgroup.kill"), ["1"])
        self.assertNotIn(_LEAF_NAME, backend.leaves)
        call_names = [call[0] for call in backend.calls]
        self.assertLess(
            call_names.index("write_leaf", call_names.index("create_leaf")),
            call_names.index("remove_leaf"),
        )

    def test_kill_forbids_later_attachment_or_peak_finalization(self) -> None:
        backend = FakeBindingBackend()
        lease = _lease(backend)

        lease.kill()

        with self.assertRaisesRegex(BindingRunnerHostError, "state"):
            lease.attach_process(4242)
        with self.assertRaisesRegex(BindingRunnerHostError, "state"):
            lease.read_memory_peak_bytes()
        lease.cleanup()

    def test_kill_poll_and_remove_failures_surface_without_false_success(self) -> None:
        scenarios: tuple[tuple[str, str], ...] = (
            ("kill", "kill denied"),
            ("poll", "timed out|populated"),
            ("remove", "rmdir denied"),
        )
        for scenario, pattern in scenarios:
            backend = FakeBindingBackend()
            lease = _lease(backend)
            backend.leaves[_LEAF_NAME]["cgroup.events"] = "populated 1\n"
            if scenario == "kill":
                backend.write_leaf_error["cgroup.kill"] = OSError("kill denied")
            elif scenario == "poll":
                backend.kill_leaves_populated = False
            else:
                backend.remove_error = OSError("rmdir denied")

            with (
                self.subTest(scenario=scenario),
                self.assertRaisesRegex(BindingRunnerHostError, pattern),
            ):
                lease.cleanup()

            self.assertIn(_LEAF_NAME, backend.leaves)

    def test_context_manager_cleans_on_body_error_and_does_not_hide_cleanup_error(
        self,
    ) -> None:
        backend = FakeBindingBackend()
        with (
            self.assertRaisesRegex(RuntimeError, "body failed"),
            _lease(backend),
        ):
            raise RuntimeError("body failed")
        self.assertNotIn(_LEAF_NAME, backend.leaves)

        backend = FakeBindingBackend()
        backend.remove_error = OSError("cleanup failed")
        with (
            self.assertRaisesRegex(BindingRunnerHostError, "cleanup failed"),
            _lease(backend),
        ):
            pass
        self.assertIn(_LEAF_NAME, backend.leaves)

    def test_context_manager_preserves_body_and_cleanup_failures(self) -> None:
        backend = FakeBindingBackend()
        backend.remove_error = OSError("cleanup failed")
        body_error = RuntimeError("body failed")

        with (
            self.assertRaisesRegex(
                BindingRunnerCleanupError,
                "body failed.*cleanup failed",
            ) as raised,
            _lease(backend),
        ):
            raise body_error

        self.assertIs(raised.exception.primary_error, body_error)
        self.assertIsInstance(raised.exception.cleanup_error, BindingRunnerHostError)
        self.assertIs(raised.exception.cleanup_error.__cause__, backend.remove_error)
        self.assertIn(_LEAF_NAME, backend.leaves)

    def test_context_manager_groups_process_control_and_cleanup_failures(self) -> None:
        backend = FakeBindingBackend()
        backend.remove_error = OSError("cleanup failed")
        interrupt = KeyboardInterrupt("stop now")

        with (
            self.assertRaises(BaseExceptionGroup) as raised,
            _lease(backend),
        ):
            raise interrupt

        primary_error, cleanup_error = raised.exception.exceptions
        self.assertIs(primary_error, interrupt)
        self.assertIsInstance(cleanup_error, BindingRunnerHostError)
        self.assertIs(cleanup_error.__cause__, backend.remove_error)
        self.assertIn(_LEAF_NAME, backend.leaves)

    def test_closed_lease_rejects_all_further_operations(self) -> None:
        backend = FakeBindingBackend()
        lease = _lease(backend)
        lease.cleanup()

        operations: tuple[tuple[str, Callable[[], object]], ...] = (
            ("attach", lambda: lease.attach_process(1)),
            ("cpuset", lease.verify_effective_cpuset),
            ("read", lease.read_memory_peak_bytes),
            ("kill", lease.kill),
            ("await", lease.await_unpopulated),
        )
        for name, operation in operations:
            with (
                self.subTest(operation=name),
                self.assertRaisesRegex(BindingRunnerHostError, "closed"),
            ):
                operation()

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX fork")
    def test_fork_child_cannot_mutate_a_preexisting_lease(self) -> None:
        backend = FakeBindingBackend()
        lease = _lease(backend)
        read_fd, write_fd = os.pipe()
        fork = cast(Callable[[], int], os.fork)
        child_pid = fork()
        if child_pid == 0:
            os.close(read_fd)
            calls_before = len(backend.calls)
            try:
                lease.kill()
            except BaseException as error:
                result = (
                    f"{type(error).__name__}:{error}:{calls_before}:{len(backend.calls)}".encode()
                )
            else:
                result = b"unexpected-success"
            os.write(write_fd, result)
            os.close(write_fd)
            os._exit(0)

        os.close(write_fd)
        try:
            result = os.read(read_fd, 4096).decode("utf-8")
        finally:
            os.close(read_fd)
            waited_pid, status = os.waitpid(child_pid, 0)
        self.assertEqual(waited_pid, child_pid)
        self.assertEqual(status, 0)
        self.assertRegex(result, r"BindingRunnerHostError:.*another process")
        calls_before, calls_after = result.rsplit(":", 2)[-2:]
        self.assertEqual(calls_before, calls_after)
        lease.cleanup()


_DELEGATED_ROOT = os.environ.get("MOSAIC_BINDING_CGROUP_ROOT")


@unittest.skipUnless(
    sys.platform.startswith("linux") and bool(_DELEGATED_ROOT),
    "requires Linux and explicit MOSAIC_BINDING_CGROUP_ROOT delegation",
)
class DelegatedLinuxBindingCgroupIntegrationTests(unittest.TestCase):
    def test_real_delegated_root_qualifies_but_requires_native_capability(self) -> None:
        assert _DELEGATED_ROOT is not None
        root = Path(_DELEGATED_ROOT)
        qualification = qualify_binding_host(root, 1)
        leaf_name = (
            f"{fixed_binding_policy().leaf_name_prefix}it-{os.getpid()}-{secrets.token_hex(8)}"
        )

        with self.assertRaisesRegex(
            BindingRunnerHostError,
            "exact issued delegated-root capability",
        ):
            create_binding_cgroup(
                qualification,
                capability=cast(Any, object()),
                leaf_name=leaf_name,
            )
        self.assertFalse((root / leaf_name).exists())
