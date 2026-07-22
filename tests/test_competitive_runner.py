from __future__ import annotations

import dataclasses
import hashlib
import os
import platform
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mosaic_archive.competitive_runner import (
    MeasurementVerificationError,
    ProcessIdentity,
    ProcessIsolationError,
    ProcessRunResult,
    ProvisionalHardwareFingerprint,
    ProvisionalMeasurement,
    ProvisionalRunnerHostError,
    StreamDigest,
    _capture_process_identity,
    _environment_sha256,
    _observe_processes,
    _parse_cpu_model,
    _parse_mem_total_bytes,
    _parse_proc_stat,
    _ProcSnapshot,
    _send_identity_sigkill,
    capture_provisional_hardware,
    run_provisional_process,
    validate_provisional_host,
    validate_requested_threads,
)


def _fingerprint(
    *,
    system: str = "Linux",
    machine: str = "x86_64",
    affinity: tuple[int, ...] = tuple(range(8)),
) -> ProvisionalHardwareFingerprint:
    return ProvisionalHardwareFingerprint(
        os_name=system,
        kernel_release="6.8.0-test",
        kernel_version="#1 test",
        machine=machine,
        cpu_model="Example CPU",
        logical_cpu_count=8,
        allowed_cpu_count=len(affinity),
        allowed_cpu_affinity=affinity,
        total_ram_bytes=16 * 1024**3,
        cpu_governors=tuple((cpu, "performance") for cpu in affinity),
    )


def _identity() -> ProcessIdentity:
    return ProcessIdentity(
        pid=123,
        process_group_id=123,
        session_id=123,
        start_time_ticks=456,
        executable="/usr/bin/example",
        executable_sha256="a" * 64,
    )


def _run_result(
    *,
    returncode: int = 0,
    timed_out: bool = False,
    termination_reason: str = "exited",
) -> ProcessRunResult:
    empty = StreamDigest(sha256=hashlib.sha256(b"").hexdigest(), byte_count=0)
    return ProcessRunResult(
        argv=("example",),
        cwd="/tmp",
        requested_threads=1,
        hardware=_fingerprint(),
        identity=_identity(),
        wall_time_seconds=0.25,
        peak_process_tree_rss_bytes=4096,
        returncode=returncode,
        timed_out=timed_out,
        termination_reason=termination_reason,
        observed_pids=(123,),
        stdout=empty,
        stderr=empty,
    )


class CompetitiveRunnerValidationTests(unittest.TestCase):
    def test_result_dataclasses_are_immutable(self) -> None:
        fingerprint = _fingerprint()
        result = _run_result()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            fingerprint.machine = "arm64"  # type: ignore[misc]
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.returncode = 7  # type: ignore[misc]
        self.assertEqual(result.evidence_class, "diagnostic")
        self.assertIs(result.binding_eligible, False)
        with self.assertRaisesRegex(ValueError, "never binding-eligible"):
            dataclasses.replace(result, binding_eligible=True)  # type: ignore[arg-type]

    def test_requested_threads_are_exactly_one_or_eight(self) -> None:
        self.assertEqual(validate_requested_threads(1), 1)
        self.assertEqual(validate_requested_threads(8), 8)
        for invalid in (0, 2, 4, 16, True):
            with (
                self.subTest(invalid=invalid),
                self.assertRaisesRegex(ValueError, "exactly 1 or 8"),
            ):
                validate_requested_threads(invalid)

    def test_provisional_host_rejects_non_linux_and_non_x86_64(self) -> None:
        with self.assertRaisesRegex(ProvisionalRunnerHostError, "requires Linux"):
            validate_provisional_host(1, fingerprint=_fingerprint(system="Windows"))
        with self.assertRaisesRegex(ProvisionalRunnerHostError, "x86_64/AMD64"):
            validate_provisional_host(1, fingerprint=_fingerprint(machine="aarch64"))

    def test_eight_thread_tier_rejects_four_cpu_affinity(self) -> None:
        with self.assertRaisesRegex(
            ProvisionalRunnerHostError,
            "8-thread provisional tier requires at least 8.*found 4",
        ):
            validate_provisional_host(8, fingerprint=_fingerprint(affinity=(0, 1, 2, 3)))

    def test_amd64_host_with_enough_allowed_cpus_is_accepted(self) -> None:
        fingerprint = _fingerprint(machine="AMD64")
        self.assertIs(validate_provisional_host(8, fingerprint=fingerprint), fingerprint)


class LinuxFactParserTests(unittest.TestCase):
    def test_proc_parsers_are_strict_and_platform_independent(self) -> None:
        self.assertEqual(
            _parse_cpu_model("processor: 0\nmodel name : Example 9000  \n"),
            "Example 9000",
        )
        self.assertIsNone(_parse_cpu_model("processor: 0\nvendor_id: Example\n"))
        self.assertEqual(_parse_mem_total_bytes("MemTotal:       16384 kB\n"), 16384 * 1024)
        self.assertIsNone(_parse_mem_total_bytes("MemTotal: 2 MB\n"))

    def test_proc_stat_parser_handles_spaces_and_closing_parenthesis_in_comm(self) -> None:
        fields = ["S", "10", "123", "123", *("0" for _ in range(15)), "999", "1000", "7"]
        snapshot = _parse_proc_stat(
            f"42 (worker ) name) {' '.join(fields)}",
            page_size=4096,
        )
        self.assertEqual(
            snapshot,
            _ProcSnapshot(
                pid=42,
                parent_pid=10,
                process_group_id=123,
                session_id=123,
                state="S",
                start_time_ticks=999,
                rss_bytes=7 * 4096,
            ),
        )

    def test_observer_sums_concurrent_group_rss_and_detects_escape(self) -> None:
        root = _ProcSnapshot(100, 1, 100, 100, "S", 10, 1000)
        child = _ProcSnapshot(101, 100, 100, 100, "S", 11, 2000)
        grandchild = _ProcSnapshot(102, 101, 100, 100, "S", 12, 3000)
        observation = _observe_processes(
            (root, child, grandchild),
            root_pid=100,
            root_start_time_ticks=10,
            known_identities=frozenset(),
        )
        self.assertEqual(observation.process_group_rss_bytes, 6000)
        self.assertEqual(observation.group_member_pids, (100, 101, 102))
        self.assertEqual(observation.escaped_pids, ())

        escaped = _ProcSnapshot(102, 101, 102, 102, "S", 12, 3000)
        second = _observe_processes(
            (root, child, escaped),
            root_pid=100,
            root_start_time_ticks=10,
            known_identities=observation.known_identities,
        )
        self.assertEqual(second.process_group_rss_bytes, 3000)
        self.assertEqual(second.escaped_pids, (102,))

    def test_hardware_capture_records_affinity_memory_model_and_governors(self) -> None:
        files = {
            Path("/proc/cpuinfo"): "model name : Mock CPU\n",
            Path("/proc/meminfo"): "MemTotal: 1024 kB\n",
            Path("/sys/devices/system/cpu/cpu2/cpufreq/scaling_governor"): "powersave\n",
            Path("/sys/devices/system/cpu/cpu5/cpufreq/scaling_governor"): "performance\n",
        }

        def fake_read(path: Path) -> str | None:
            return files.get(path)

        with (
            patch("mosaic_archive.competitive_runner.platform.system", return_value="Linux"),
            patch("mosaic_archive.competitive_runner.platform.release", return_value="6.8"),
            patch("mosaic_archive.competitive_runner.platform.version", return_value="#1"),
            patch("mosaic_archive.competitive_runner.platform.machine", return_value="x86_64"),
            patch("mosaic_archive.competitive_runner.os.cpu_count", return_value=12),
            patch(
                "mosaic_archive.competitive_runner._current_allowed_affinity",
                return_value=(2, 5),
            ),
            patch("mosaic_archive.competitive_runner._read_text", side_effect=fake_read),
        ):
            fingerprint = capture_provisional_hardware()

        self.assertEqual(fingerprint.cpu_model, "Mock CPU")
        self.assertEqual(fingerprint.logical_cpu_count, 12)
        self.assertEqual(fingerprint.allowed_cpu_affinity, (2, 5))
        self.assertEqual(fingerprint.allowed_cpu_count, 2)
        self.assertEqual(fingerprint.total_ram_bytes, 1024 * 1024)
        self.assertEqual(
            fingerprint.cpu_governors,
            ((2, "powersave"), (5, "performance")),
        )

    def test_process_identity_path_and_hash_come_from_one_pinned_executable_fd(self) -> None:
        fields = ["S", "1", "123", "123", *("0" for _ in range(15)), "456", "0", "1"]
        stat_text = f"123 (wrapper) {' '.join(fields)}"

        def fake_readlink(path: Path) -> str:
            self.assertEqual(path, Path("/proc/self/fd/77"))
            return "/usr/bin/final-tool"

        with (
            patch(
                "mosaic_archive.competitive_runner._read_text",
                side_effect=(stat_text, stat_text),
            ),
            patch("mosaic_archive.competitive_runner._page_size", return_value=4096),
            patch("mosaic_archive.competitive_runner.os.open", return_value=77) as open_fd,
            patch(
                "mosaic_archive.competitive_runner.os.readlink",
                side_effect=fake_readlink,
            ),
            patch(
                "mosaic_archive.competitive_runner._sha256_fd",
                return_value=("b" * 64, 1234),
            ) as hash_fd,
            patch("mosaic_archive.competitive_runner.os.close") as close_fd,
        ):
            identity = _capture_process_identity(123, 123)

        self.assertEqual(identity.executable, "/usr/bin/final-tool")
        self.assertEqual(identity.executable_sha256, "b" * 64)
        self.assertEqual(open_fd.call_args.args[0], Path("/proc/123/exe"))
        hash_fd.assert_called_once_with(77)
        close_fd.assert_called_once_with(77)


class ProvisionalMeasurementTests(unittest.TestCase):
    def test_constructor_requires_successful_exit_and_exact_restored_hash(self) -> None:
        payload = b"restored payload"
        expected = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            restored = Path(temporary) / "restored.bin"
            restored.write_bytes(payload)
            measurement = ProvisionalMeasurement(
                process=_run_result(),
                restored_payload=restored,
                expected_payload_sha256=expected,
            )
            self.assertEqual(measurement.restored_payload_sha256, expected)
            self.assertEqual(measurement.restored_payload_bytes, len(payload))
            self.assertEqual(measurement.restored_payload_path, str(restored.resolve()))
            self.assertEqual(measurement.process.evidence_class, "diagnostic")
            self.assertIs(measurement.binding_eligible, False)

            restored.write_bytes(payload + b"corrupt")
            with self.assertRaisesRegex(MeasurementVerificationError, "hash mismatch"):
                ProvisionalMeasurement(
                    process=_run_result(),
                    restored_payload=restored,
                    expected_payload_sha256=expected,
                )

        with self.assertRaisesRegex(MeasurementVerificationError, "exit status 9"):
            ProvisionalMeasurement(
                process=_run_result(returncode=9),
                restored_payload=Path("unused"),
                expected_payload_sha256=expected,
            )

    def test_constructor_rejects_timeout_before_reading_restored_payload(self) -> None:
        with self.assertRaisesRegex(MeasurementVerificationError, "timed out"):
            ProvisionalMeasurement(
                process=_run_result(returncode=-9, timed_out=True, termination_reason="timeout"),
                restored_payload=Path("must-not-be-read"),
                expected_payload_sha256="a" * 64,
            )


class ProvisionalProcessUnitTests(unittest.TestCase):
    def test_runner_rejects_secret_or_unapproved_environment_keys(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            self.assertRaisesRegex(ValueError, "public-diagnostic-env-v1"),
        ):
            run_provisional_process(
                ("tool",),
                cwd=temporary,
                env={"AGE_PASSPHRASE": "must-not-be-retained-or-hashed"},
                requested_threads=1,
                timeout_seconds=1,
            )

    def test_runner_uses_argument_vector_new_session_and_explicit_context(self) -> None:
        captured: dict[str, object] = {}

        class FakeProcess:
            pid = 123
            returncode = 0

            def poll(self) -> int:
                return 0

            def wait(self, timeout: float | None = None) -> int:
                del timeout
                return 0

        def fake_popen(argv: tuple[str, ...], **kwargs: object) -> FakeProcess:
            captured["argv"] = argv
            captured.update(kwargs)
            stdout = kwargs["stdout"]
            stderr = kwargs["stderr"]
            assert hasattr(stdout, "write")
            assert hasattr(stderr, "write")
            stdout.write(b"standard output")  # type: ignore[union-attr]
            stderr.write(b"standard error")  # type: ignore[union-attr]
            return FakeProcess()

        root = _ProcSnapshot(123, 1, 123, 123, "S", 456, 8192)
        with tempfile.TemporaryDirectory() as temporary:
            cwd = Path(temporary)
            with (
                patch(
                    "mosaic_archive.competitive_runner.validate_provisional_host",
                    return_value=_fingerprint(),
                ),
                patch("mosaic_archive.competitive_runner.subprocess.Popen", side_effect=fake_popen),
                patch(
                    "mosaic_archive.competitive_runner._capture_process_identity",
                    return_value=_identity(),
                ),
                patch(
                    "mosaic_archive.competitive_runner._read_proc_snapshots",
                    side_effect=((root,), ()),
                ),
                patch(
                    "mosaic_archive.competitive_runner.time.monotonic",
                    side_effect=(10.0, 10.25),
                ),
            ):
                result = run_provisional_process(
                    ("tool", "--flag", "literal;not-shell"),
                    cwd=cwd,
                    env={"PATH": "explicit"},
                    requested_threads=1,
                    timeout_seconds=5,
                )

        self.assertEqual(captured["argv"], ("tool", "--flag", "literal;not-shell"))
        self.assertEqual(captured["cwd"], str(cwd.resolve()))
        self.assertEqual(captured["env"], {"PATH": "explicit"})
        self.assertIs(captured["start_new_session"], True)
        self.assertIs(captured["shell"], False)
        self.assertEqual(result.peak_process_tree_rss_bytes, 8192)
        self.assertEqual(result.stdout.byte_count, len(b"standard output"))
        self.assertEqual(result.stderr.byte_count, len(b"standard error"))
        self.assertEqual(result.stdout.sha256, hashlib.sha256(b"standard output").hexdigest())
        self.assertEqual(result.sample_interval_seconds, 0.010)
        self.assertEqual(result.environment_policy_id, "public-diagnostic-env-v1")
        self.assertEqual(result.public_environment, (("PATH", "explicit"),))
        self.assertEqual(
            result.public_environment_sha256,
            _environment_sha256({"PATH": "explicit"}),
        )
        self.assertEqual(result.evidence_class, "diagnostic")
        self.assertIs(result.binding_eligible, False)

    def test_timeout_kills_the_whole_process_group(self) -> None:
        class FakeProcess:
            pid = 123
            returncode: int | None = None

            def poll(self) -> int | None:
                return self.returncode

            def wait(self, timeout: float | None = None) -> int:
                del timeout
                self.returncode = -9
                return self.returncode

        process = FakeProcess()
        root = _ProcSnapshot(123, 1, 123, 123, "S", 456, 4096)
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch(
                "mosaic_archive.competitive_runner.validate_provisional_host",
                return_value=_fingerprint(),
            ),
            patch("mosaic_archive.competitive_runner.subprocess.Popen", return_value=process),
            patch(
                "mosaic_archive.competitive_runner._capture_process_identity",
                return_value=_identity(),
            ),
            patch(
                "mosaic_archive.competitive_runner._read_proc_snapshots",
                side_effect=((root,), (root,), ()),
            ),
            patch(
                "mosaic_archive.competitive_runner.time.monotonic",
                side_effect=(1.0, 1.0, 2.5, 2.5),
            ),
            patch("mosaic_archive.competitive_runner.time.sleep"),
            patch("mosaic_archive.competitive_runner._send_group_sigkill") as killpg,
        ):
            result = run_provisional_process(
                ("tool",),
                cwd=Path(temporary),
                env={},
                requested_threads=1,
                timeout_seconds=1,
            )

        killpg.assert_called_once_with(123)
        self.assertTrue(result.timed_out)
        self.assertEqual(result.termination_reason, "timeout")
        self.assertEqual(result.returncode, -9)

    def test_timeout_rejects_child_that_escapes_during_cleanup(self) -> None:
        class FakeProcess:
            pid = 123
            returncode: int | None = None

            def poll(self) -> int | None:
                return self.returncode

            def wait(self, timeout: float | None = None) -> int:
                del timeout
                self.returncode = -9
                return self.returncode

        root = _ProcSnapshot(123, 1, 123, 123, "S", 456, 4096)
        child = _ProcSnapshot(124, 123, 123, 123, "S", 457, 2048)
        escaped = _ProcSnapshot(124, 1, 124, 124, "S", 457, 2048)
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch(
                "mosaic_archive.competitive_runner.validate_provisional_host",
                return_value=_fingerprint(),
            ),
            patch(
                "mosaic_archive.competitive_runner.subprocess.Popen",
                return_value=FakeProcess(),
            ),
            patch(
                "mosaic_archive.competitive_runner._capture_process_identity",
                return_value=_identity(),
            ),
            patch(
                "mosaic_archive.competitive_runner._read_proc_snapshots",
                side_effect=((root, child), (root, child), (escaped,)),
            ),
            patch(
                "mosaic_archive.competitive_runner.time.monotonic",
                side_effect=(1.0, 1.0, 2.5),
            ),
            patch("mosaic_archive.competitive_runner.time.sleep"),
            patch("mosaic_archive.competitive_runner._send_group_sigkill"),
            patch("mosaic_archive.competitive_runner._send_identity_sigkill") as kill_identity,
            self.assertRaisesRegex(
                ProcessIsolationError,
                "escaped during timeout cleanup",
            ),
        ):
            run_provisional_process(
                ("tool",),
                cwd=Path(temporary),
                env={},
                requested_threads=1,
                timeout_seconds=1,
            )

        kill_identity.assert_called_once_with((124, 457))

    def test_timeout_rejects_live_child_remaining_in_process_group(self) -> None:
        class FakeProcess:
            pid = 123
            returncode: int | None = None

            def poll(self) -> int | None:
                return self.returncode

            def wait(self, timeout: float | None = None) -> int:
                del timeout
                self.returncode = -9
                return self.returncode

        root = _ProcSnapshot(123, 1, 123, 123, "S", 456, 4096)
        child = _ProcSnapshot(124, 123, 123, 123, "D", 457, 2048)
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch(
                "mosaic_archive.competitive_runner.validate_provisional_host",
                return_value=_fingerprint(),
            ),
            patch(
                "mosaic_archive.competitive_runner.subprocess.Popen",
                return_value=FakeProcess(),
            ),
            patch(
                "mosaic_archive.competitive_runner._capture_process_identity",
                return_value=_identity(),
            ),
            patch(
                "mosaic_archive.competitive_runner._read_proc_snapshots",
                side_effect=((root, child), (root, child), (child,)),
            ),
            patch(
                "mosaic_archive.competitive_runner.time.monotonic",
                side_effect=(1.0, 1.0, 2.5),
            ),
            patch("mosaic_archive.competitive_runner.time.sleep"),
            patch("mosaic_archive.competitive_runner._send_group_sigkill") as killpg,
            patch("mosaic_archive.competitive_runner._send_identity_sigkill") as kill_identity,
            self.assertRaisesRegex(
                ProcessIsolationError,
                "remained after timeout SIGKILL",
            ),
        ):
            run_provisional_process(
                ("tool",),
                cwd=Path(temporary),
                env={},
                requested_threads=1,
                timeout_seconds=1,
            )

        killpg.assert_called_once_with(123)
        kill_identity.assert_called_once_with((124, 457))

    def test_observable_process_group_escape_is_rejected(self) -> None:
        class FakeProcess:
            pid = 123
            returncode: int | None = None

            def poll(self) -> int | None:
                return self.returncode

            def wait(self, timeout: float | None = None) -> int:
                del timeout
                self.returncode = -9
                return self.returncode

        root = _ProcSnapshot(123, 1, 123, 123, "S", 456, 4096)
        escaped = _ProcSnapshot(124, 123, 124, 124, "S", 457, 2048)
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch(
                "mosaic_archive.competitive_runner.validate_provisional_host",
                return_value=_fingerprint(),
            ),
            patch(
                "mosaic_archive.competitive_runner.subprocess.Popen",
                return_value=FakeProcess(),
            ),
            patch(
                "mosaic_archive.competitive_runner._capture_process_identity",
                return_value=_identity(),
            ),
            patch(
                "mosaic_archive.competitive_runner._read_proc_snapshots",
                side_effect=((root, escaped), ()),
            ),
            patch("mosaic_archive.competitive_runner.time.monotonic", return_value=1.0),
            patch("mosaic_archive.competitive_runner._send_group_sigkill"),
            patch("mosaic_archive.competitive_runner._send_identity_sigkill") as kill,
            self.assertRaisesRegex(ProcessIsolationError, "escaped process group"),
        ):
            run_provisional_process(
                ("tool",),
                cwd=Path(temporary),
                env={},
                requested_threads=1,
                timeout_seconds=5,
            )

        kill.assert_called_once_with((124, 457))

    def test_parent_exit_with_live_group_member_is_rejected_as_daemonization(self) -> None:
        class FakeProcess:
            pid = 123
            returncode = 0

            def poll(self) -> int:
                return 0

            def wait(self, timeout: float | None = None) -> int:
                del timeout
                return 0

        root = _ProcSnapshot(123, 1, 123, 123, "S", 456, 4096)
        child = _ProcSnapshot(124, 123, 123, 123, "S", 457, 2048)
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch(
                "mosaic_archive.competitive_runner.validate_provisional_host",
                return_value=_fingerprint(),
            ),
            patch(
                "mosaic_archive.competitive_runner.subprocess.Popen",
                return_value=FakeProcess(),
            ),
            patch(
                "mosaic_archive.competitive_runner._capture_process_identity",
                return_value=_identity(),
            ),
            patch(
                "mosaic_archive.competitive_runner._read_proc_snapshots",
                side_effect=((root, child), (child,)),
            ),
            patch(
                "mosaic_archive.competitive_runner.time.monotonic",
                side_effect=(1.0, 1.1),
            ),
            patch("mosaic_archive.competitive_runner._send_group_sigkill") as killpg,
            patch("mosaic_archive.competitive_runner._send_identity_sigkill") as kill_identity,
            self.assertRaisesRegex(
                ProcessIsolationError,
                "exited while descendants remained",
            ) as raised,
        ):
            run_provisional_process(
                ("tool",),
                cwd=Path(temporary),
                env={},
                requested_threads=1,
                timeout_seconds=5,
            )

        killpg.assert_not_called()
        kill_identity.assert_called_once_with((124, 457))
        self.assertIsNotNone(raised.exception.result)
        assert raised.exception.result is not None
        self.assertEqual(raised.exception.result.termination_reason, "daemonization")

    def test_child_escape_after_root_reap_never_signals_reusable_process_group(self) -> None:
        class FakeProcess:
            pid = 123
            returncode = 0

            def poll(self) -> int:
                return 0

            def wait(self, timeout: float | None = None) -> int:
                del timeout
                return 0

        root = _ProcSnapshot(123, 1, 123, 123, "S", 456, 4096)
        child = _ProcSnapshot(124, 123, 123, 123, "S", 457, 2048)
        escaped = _ProcSnapshot(124, 1, 124, 124, "S", 457, 2048)
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch(
                "mosaic_archive.competitive_runner.validate_provisional_host",
                return_value=_fingerprint(),
            ),
            patch(
                "mosaic_archive.competitive_runner.subprocess.Popen",
                return_value=FakeProcess(),
            ),
            patch(
                "mosaic_archive.competitive_runner._capture_process_identity",
                return_value=_identity(),
            ),
            patch(
                "mosaic_archive.competitive_runner._read_proc_snapshots",
                side_effect=((root, child), (escaped,)),
            ),
            patch(
                "mosaic_archive.competitive_runner.time.monotonic",
                side_effect=(1.0, 1.1),
            ),
            patch("mosaic_archive.competitive_runner._send_group_sigkill") as killpg,
            patch("mosaic_archive.competitive_runner._send_identity_sigkill") as kill_identity,
            self.assertRaisesRegex(ProcessIsolationError, "escaped process group"),
        ):
            run_provisional_process(
                ("tool",),
                cwd=Path(temporary),
                env={},
                requested_threads=1,
                timeout_seconds=5,
            )

        killpg.assert_not_called()
        kill_identity.assert_called_once_with((124, 457))

    def test_reused_post_reap_group_cannot_make_runner_kill_unrelated_child(self) -> None:
        class FakeProcess:
            pid = 123
            returncode = 0

            def poll(self) -> int:
                return 0

            def wait(self, timeout: float | None = None) -> int:
                del timeout
                return 0

        root = _ProcSnapshot(123, 1, 123, 123, "S", 456, 4096)
        reused_group_leader = _ProcSnapshot(123, 1, 123, 123, "S", 999, 4096)
        unrelated_child = _ProcSnapshot(200, 123, 200, 200, "S", 1000, 2048)
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch(
                "mosaic_archive.competitive_runner.validate_provisional_host",
                return_value=_fingerprint(),
            ),
            patch(
                "mosaic_archive.competitive_runner.subprocess.Popen",
                return_value=FakeProcess(),
            ),
            patch(
                "mosaic_archive.competitive_runner._capture_process_identity",
                return_value=_identity(),
            ),
            patch(
                "mosaic_archive.competitive_runner._read_proc_snapshots",
                side_effect=((root,), (reused_group_leader, unrelated_child)),
            ),
            patch(
                "mosaic_archive.competitive_runner.time.monotonic",
                side_effect=(1.0, 1.1),
            ),
            patch("mosaic_archive.competitive_runner._send_group_sigkill") as killpg,
            patch("mosaic_archive.competitive_runner._send_identity_sigkill") as kill_identity,
            self.assertRaisesRegex(ProcessIsolationError, "escaped process group"),
        ):
            run_provisional_process(
                ("tool",),
                cwd=Path(temporary),
                env={},
                requested_threads=1,
                timeout_seconds=5,
            )

        killpg.assert_not_called()
        kill_identity.assert_not_called()

    def test_sampling_interval_is_bounded_before_host_or_process_use(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            for interval in (0.0, 0.0009, 0.251, float("inf")):
                with (
                    self.subTest(interval=interval),
                    patch(
                        "mosaic_archive.competitive_runner.validate_provisional_host"
                    ) as validate_host,
                    self.assertRaisesRegex(ValueError, "sample_interval_seconds"),
                ):
                    run_provisional_process(
                        ("tool",),
                        cwd=Path(temporary),
                        env={},
                        requested_threads=1,
                        timeout_seconds=5,
                        sample_interval_seconds=interval,
                    )
                validate_host.assert_not_called()

    def test_identity_kill_revalidates_start_time_before_signaling_pid(self) -> None:
        fields = ["S", "1", "124", "124", *("0" for _ in range(15)), "457", "0", "1"]
        with (
            patch(
                "mosaic_archive.competitive_runner._open_pidfd",
                side_effect=(50, 51),
            ),
            patch(
                "mosaic_archive.competitive_runner._read_text",
                return_value=f"124 (escaped) {' '.join(fields)}",
            ),
            patch("mosaic_archive.competitive_runner._page_size", return_value=4096),
            patch("mosaic_archive.competitive_runner._send_pidfd_sigkill") as kill_pidfd,
            patch("mosaic_archive.competitive_runner.os.close") as close,
        ):
            _send_identity_sigkill((124, 457))
            _send_identity_sigkill((124, 999))

        kill_pidfd.assert_called_once_with(50, 124)
        self.assertEqual([call.args for call in close.call_args_list], [(50,), (51,)])


@unittest.skipUnless(
    platform.system() == "Linux"
    and platform.machine().lower() in {"x86_64", "amd64"}
    and hasattr(os, "sched_getaffinity")
    and len(os.sched_getaffinity(0)) >= 1,
    "requires a Linux x86-64 host with sched_getaffinity",
)
class LinuxProvisionalProcessIntegrationTests(unittest.TestCase):
    def test_reports_output_and_process_tree_rss_for_real_process(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = run_provisional_process(
                (
                    sys.executable,
                    "-c",
                    "import sys,time; print('out'); print('err', file=sys.stderr); time.sleep(.05)",
                ),
                cwd=Path(temporary),
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                requested_threads=1,
                timeout_seconds=5,
                sample_interval_seconds=0.005,
            )

        self.assertEqual(result.returncode, 0)
        self.assertFalse(result.timed_out)
        self.assertGreater(result.peak_process_tree_rss_bytes, 0)
        self.assertEqual(result.stdout.sha256, hashlib.sha256(b"out\n").hexdigest())
        self.assertEqual(result.stderr.sha256, hashlib.sha256(b"err\n").hexdigest())


if __name__ == "__main__":
    unittest.main()
