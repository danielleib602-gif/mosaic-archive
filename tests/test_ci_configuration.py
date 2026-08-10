from __future__ import annotations

import configparser
import subprocess
import sys
import unittest
from pathlib import Path

from tools.run_native_cgroup_integration import _validated_parent, _wait_for_supervisor


class CiConfigurationTests(unittest.TestCase):
    def test_ci_uses_pinned_actions_and_read_only_permissions(self) -> None:
        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn("actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0", workflow)
        self.assertIn(
            "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1",
            workflow,
        )
        setup_uv_pin = "astral-sh/setup-uv@11f9893b081a58869d3b5fccaea48c9e9e46f990"
        for workflow_name in (
            "benchmark.yml",
            "ci.yml",
            "coverage-fuzz.yml",
            "release.yml",
            "reliability.yml",
        ):
            with self.subTest(workflow=workflow_name):
                configured = Path(".github/workflows", workflow_name).read_text(encoding="utf-8")
                self.assertIn(setup_uv_pin, configured)

    def test_ci_covers_supported_platforms_and_security_gates(self) -> None:
        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
        for platform in ("ubuntu-latest", "windows-latest", "macos-latest"):
            self.assertIn(platform, workflow)
        for command in (
            "unittest discover",
            "ruff check",
            "mypy src",
            "bandit -q -r src -lll",
            "pip-audit",
            "msc readiness --require-automatic --json",
        ):
            self.assertIn(command, workflow)

    def test_coverage_gate_measures_branches_across_the_entire_package(self) -> None:
        configuration = configparser.ConfigParser()
        configuration.read(".coveragerc", encoding="utf-8")

        run = configuration["run"]
        self.assertTrue(run.getboolean("branch"))
        self.assertEqual(run.get("source"), "src/mosaic_archive")
        self.assertNotIn("omit", run)
        self.assertEqual(configuration["report"].getint("precision"), 2)

    def test_native_supervisor_uses_pinned_rust_quality_gates(self) -> None:
        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
        for required in (
            "name: native Linux supervisor",
            "timeout-minutes: 10",
            'python-version: "3.13"',
            "uv sync --frozen",
            "rustup toolchain install 1.96.0 --profile minimal --component rustfmt,clippy",
            "cargo +1.96.0 fmt --all --check",
            "cargo +1.96.0 clippy --workspace --all-targets --locked -- -D warnings",
            "cargo +1.96.0 test --workspace --locked",
            "name: Exercise a real delegated cgroup lifecycle",
            "PYTHONPATH=src uv run --frozen python tools/run_native_cgroup_integration.py",
            "MOSAIC_NATIVE_CGROUP_PARENT",
            "mosaic-native-ci-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}",
            "mosaic-binding-abi-probe",
            "--internal-clone3-abi-probe",
            (
                "expected_probe_output='clone3 ABI probe passed "
                "(PID namespace and initial cgroup placement only); binding_eligible=false'"
            ),
            '[[ "$probe_output" == "$expected_probe_output" ]]',
            'exec 3<&-; exec "$1" --internal-clone3-abi-probe',
            'bash "$supervisor_binary" 2>"$negative_stderr"',
            "(( negative_status == 1 ))",
            '[[ -z "$negative_stdout" ]]',
            (
                "expected_negative_error='clone3 ABI probe failed; binding_eligible=false; "
                "cannot inspect clone3 ABI probe cgroup leaf FD 3: Bad file descriptor "
                "(os error 9)'"
            ),
            'negative_error="$(<"$negative_stderr")"',
            '[[ "$negative_error" == "$expected_negative_error" ]]',
            "cargo +1.96.0 build --workspace --release --locked",
        ):
            self.assertIn(required, workflow)
        self.assertIn("name: native Windows supervisor", workflow)
        self.assertIn("runs-on: windows-latest", workflow)

    def test_native_cgroup_helper_accepts_only_the_fixed_direct_ci_namespace(self) -> None:
        self.assertEqual(
            _validated_parent("/sys/fs/cgroup/mosaic-native-ci-123-4"),
            Path("/sys/fs/cgroup/mosaic-native-ci-123-4"),
        )
        for invalid in (
            "relative/mosaic-native-ci-123-4",
            "/sys/fs/cgroup/nested/mosaic-native-ci-123-4",
            "/sys/fs/cgroup/mosaic-native-ci-123-4/child",
            "/sys/fs/cgroup/mosaic-native-ci-123-x",
            "/sys/fs/cgroup/mosaic-native-ci-123-4;touch-pwned",
            "/tmp/mosaic-native-ci-123-4",
        ):
            with self.subTest(parent=invalid), self.assertRaises(ValueError):
                _validated_parent(invalid)

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux descriptor APIs")
    def test_native_helper_backups_cannot_alias_fixed_descriptors(self) -> None:
        program = """
import errno
import fcntl
import os
from tools.run_native_cgroup_integration import _backup_descriptor, _restore_descriptor

temporary_read, temporary_write = os.pipe()
read_fd = fcntl.fcntl(temporary_read, fcntl.F_DUPFD_CLOEXEC, 10)
write_fd = fcntl.fcntl(temporary_write, fcntl.F_DUPFD_CLOEXEC, 10)
os.close(temporary_read)
os.close(temporary_write)
os.dup2(read_fd, 3)
os.close(read_fd)
identity = os.fstat(3)
try:
    os.close(4)
except OSError as error:
    assert error.errno == errno.EBADF
backup_three = _backup_descriptor(3)
backup_four = _backup_descriptor(4)
assert backup_three is not None and backup_three[0] >= 5
assert backup_four is None
_restore_descriptor(4, backup_four)
_restore_descriptor(3, backup_three)
restored = os.fstat(3)
assert (restored.st_dev, restored.st_ino) == (identity.st_dev, identity.st_ino)
os.close(3)
os.close(write_fd)
"""
        completed = subprocess.run(
            [sys.executable, "-c", program],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_native_helper_timeout_reaping_continues_after_terminate_race(self) -> None:
        class RaceProcess:
            def __init__(self) -> None:
                self.calls: list[str] = []
                self.communicate_calls = 0
                self.poll_calls = 0

            def poll(self) -> int | None:
                self.calls.append("poll")
                self.poll_calls += 1
                return None if self.poll_calls == 1 else 0

            def terminate(self) -> None:
                self.calls.append("terminate")
                raise ProcessLookupError("injected terminate race")

            def communicate(self, *, timeout: int) -> tuple[str, str]:
                self.calls.append(f"communicate:{timeout}")
                self.communicate_calls += 1
                if self.communicate_calls < 3:
                    raise subprocess.TimeoutExpired("supervisor", timeout)
                return "", ""

            def kill(self) -> None:
                self.calls.append("kill")

        process = RaceProcess()
        with self.assertRaises(BaseExceptionGroup):
            _wait_for_supervisor(process)  # type: ignore[arg-type]
        self.assertEqual(
            process.calls,
            [
                "communicate:45",
                "poll",
                "terminate",
                "communicate:10",
                "kill",
                "communicate:10",
                "poll",
            ],
        )


if __name__ == "__main__":
    unittest.main()
