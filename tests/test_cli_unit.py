from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import mosaic_archive
from mosaic_archive import cli
from mosaic_archive.exceptions import MosaicError
from mosaic_archive.stream_archive import ProgressEvent


class CliUnitTests(unittest.TestCase):
    def test_version_tracks_package_version(self) -> None:
        stdout = io.StringIO()

        with redirect_stdout(stdout), self.assertRaises(SystemExit) as raised:
            cli.main(["--version"])

        self.assertEqual(raised.exception.code, 0)
        self.assertEqual(stdout.getvalue(), f"msc {mosaic_archive.__version__}\n")

    def test_readiness_forwards_release_binding_arguments(self) -> None:
        report = SimpleNamespace(automatic_ready=True, ready_for_1_0=False)
        commit = "a" * 40

        with (
            patch(
                "mosaic_archive.cli.evaluate_release_readiness",
                return_value=report,
            ) as evaluate,
            patch("mosaic_archive.cli._print_result") as print_result,
        ):
            return_code = cli.main(
                [
                    "readiness",
                    "--root",
                    "repository",
                    "--release-tag",
                    "v1.0.0",
                    "--release-commit",
                    commit,
                    "--review-bundle",
                    "review.zip",
                    "--json",
                ]
            )

        self.assertEqual(return_code, 0)
        evaluate.assert_called_once_with(
            Path("repository"),
            release_tag="v1.0.0",
            release_commit=commit,
            review_bundle=Path("review.zip"),
        )
        print_result.assert_called_once_with("readiness", report, True)

    def test_require_automatic_failure_is_contained(self) -> None:
        report = SimpleNamespace(automatic_ready=False, ready_for_1_0=False)
        stderr = io.StringIO()

        with (
            patch(
                "mosaic_archive.cli.evaluate_release_readiness",
                return_value=report,
            ),
            patch("mosaic_archive.cli._print_result") as print_result,
            redirect_stderr(stderr),
        ):
            return_code = cli.main(["readiness", "--require-automatic"])

        self.assertEqual(return_code, 2)
        self.assertEqual(
            stderr.getvalue(),
            "msc: error: one or more automatic MSC 1.0 gates are incomplete\n",
        )
        print_result.assert_not_called()

    def test_password_sources(self) -> None:
        with patch("mosaic_archive.cli.getpass.getpass") as prompt:
            password = cli._password_from_args(
                SimpleNamespace(password="direct", password_env=None)
            )
        self.assertEqual(password, "direct")
        prompt.assert_not_called()

        with patch.dict(cli.os.environ, {"MSC_TEST_PASSWORD": "environment"}):
            password = cli._password_from_args(
                SimpleNamespace(password=None, password_env="MSC_TEST_PASSWORD")
            )
        self.assertEqual(password, "environment")

        with patch(
            "mosaic_archive.cli.getpass.getpass", return_value="prompted"
        ) as prompt:
            password = cli._password_from_args(
                SimpleNamespace(password=None, password_env=None)
            )
        self.assertEqual(password, "prompted")
        prompt.assert_called_once_with("Password: ")

    def test_password_errors(self) -> None:
        with (
            patch.dict(cli.os.environ, {}, clear=True),
            self.assertRaisesRegex(
                ValueError,
                "password environment variable is not set: MISSING_PASSWORD",
            ),
        ):
            cli._password_from_args(
                SimpleNamespace(password=None, password_env="MISSING_PASSWORD")
            )

        for arguments in (
            SimpleNamespace(password="", password_env=None),
            SimpleNamespace(password=None, password_env="EMPTY_PASSWORD"),
            SimpleNamespace(password=None, password_env=None),
        ):
            with (
                self.subTest(arguments=arguments),
                patch.dict(cli.os.environ, {"EMPTY_PASSWORD": ""}),
                patch("mosaic_archive.cli.getpass.getpass", return_value=""),
                self.assertRaisesRegex(ValueError, "password must not be empty"),
            ):
                cli._password_from_args(arguments)

    def test_encode_dispatch_contract(self) -> None:
        result = object()
        with (
            patch("mosaic_archive.cli.encode_path", return_value=result) as encode,
            patch("mosaic_archive.cli._print_result") as print_result,
        ):
            return_code = cli.main(
                [
                    "encode",
                    "input",
                    "archive.msc",
                    "--password",
                    "secret",
                    "--chunk-size",
                    "8192",
                    "--cdc-min-size",
                    "4096",
                    "--cdc-max-size",
                    "16384",
                    "--profile",
                    "fast",
                    "--padding-size",
                    "256",
                    "--kdf-log-n",
                    "14",
                    "--format",
                    "solid",
                    "--no-progress",
                    "--json",
                ]
            )

        self.assertEqual(return_code, 0)
        encode.assert_called_once_with(
            Path("input"),
            Path("archive.msc"),
            "secret",
            chunk_size=8192,
            padding_size=256,
            kdf_log_n=14,
            cdc_min_size=4096,
            cdc_max_size=16384,
            profile="fast",
            archive_format="solid",
            progress=None,
        )
        print_result.assert_called_once_with("encode", result, True)

    def test_decode_dispatch_contract(self) -> None:
        result = object()
        with (
            patch("mosaic_archive.cli.decode_path", return_value=result) as decode,
            patch("mosaic_archive.cli._print_result") as print_result,
        ):
            return_code = cli.main(
                [
                    "decode",
                    "archive.msc",
                    "output",
                    "--password",
                    "secret",
                    "--progress",
                    "--max-output-size",
                    "123",
                    "--max-frame-count",
                    "456",
                    "--max-legacy-archive-size",
                    "789",
                    "--json",
                ]
            )

        self.assertEqual(return_code, 0)
        positional, keywords = decode.call_args
        self.assertEqual(
            positional,
            (Path("archive.msc"), Path("output"), "secret"),
        )
        progress = keywords.pop("progress")
        self.assertIsInstance(progress, cli._ProgressPrinter)
        self.assertEqual(
            keywords,
            {
                "max_output_size": 123,
                "max_frame_count": 456,
                "max_legacy_archive_size": 789,
            },
        )
        print_result.assert_called_once_with("decode", result, True)

    def test_inspect_dispatch_contract(self) -> None:
        result = object()
        with (
            patch.dict(cli.os.environ, {"MSC_TEST_PASSWORD": "secret"}),
            patch("mosaic_archive.cli.inspect_path", return_value=result) as inspect,
            patch("mosaic_archive.cli._print_result") as print_result,
        ):
            return_code = cli.main(
                [
                    "inspect",
                    "archive.msc",
                    "--password-env",
                    "MSC_TEST_PASSWORD",
                    "--max-output-size",
                    "123",
                    "--max-frame-count",
                    "456",
                    "--max-legacy-archive-size",
                    "789",
                    "--json",
                ]
            )

        self.assertEqual(return_code, 0)
        inspect.assert_called_once_with(
            Path("archive.msc"),
            "secret",
            max_output_size=123,
            max_frame_count=456,
            max_legacy_archive_size=789,
        )
        print_result.assert_called_once_with("inspect", result, True)

    def test_benchmark_dispatch_contract(self) -> None:
        result = object()
        with (
            patch(
                "mosaic_archive.cli.benchmark_path", return_value=result
            ) as benchmark,
            patch("mosaic_archive.cli._print_result") as print_result,
        ):
            return_code = cli.main(
                [
                    "benchmark",
                    "input",
                    "--password",
                    "secret",
                    "--chunk-size",
                    "8192",
                    "--cdc-min-size",
                    "4096",
                    "--cdc-max-size",
                    "16384",
                    "--profile",
                    "research",
                    "--padding-size",
                    "512",
                    "--kdf-log-n",
                    "14",
                    "--format",
                    "solid",
                    "--compare",
                    "--json",
                ]
            )

        self.assertEqual(return_code, 0)
        benchmark.assert_called_once_with(
            Path("input"),
            "secret",
            chunk_size=8192,
            padding_size=512,
            kdf_log_n=14,
            cdc_min_size=4096,
            cdc_max_size=16384,
            profile="research",
            archive_format="solid",
            compare=True,
        )
        print_result.assert_called_once_with("benchmark", result, True)

    def test_compatibility_dispatch_contract(self) -> None:
        result = object()
        with (
            patch("mosaic_archive.cli.current_policy", return_value=result) as policy,
            patch("mosaic_archive.cli._print_result") as print_result,
        ):
            return_code = cli.main(["compatibility", "--json"])

        self.assertEqual(return_code, 0)
        policy.assert_called_once_with()
        print_result.assert_called_once_with("compatibility", result, True)

    def test_human_result_formatting_handles_sizes_floats_and_nested_data(self) -> None:
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            cli._print_result(
                "inspect",
                {
                    "archive_size": 2048,
                    "ratio": 0.5,
                    "metadata": {"format": "MSC6"},
                    "labels": ("stable", "authenticated"),
                },
                False,
            )

        rendered = stdout.getvalue()
        self.assertIn("Mosaic Archive - inspect", rendered)
        self.assertIn("Archive Size: 2.00 KiB", rendered)
        self.assertIn("Ratio: 0.500000", rendered)
        self.assertIn('Metadata: {"format": "MSC6"}', rendered)
        self.assertIn("Labels: ['stable', 'authenticated']", rendered)

    def test_expected_exceptions_are_contained(self) -> None:
        for error in (
            MosaicError("domain failure"),
            OSError("filesystem failure"),
            ValueError("invalid value"),
        ):
            with self.subTest(error=type(error).__name__):
                stderr = io.StringIO()
                with (
                    patch("mosaic_archive.cli._run", side_effect=error),
                    redirect_stderr(stderr),
                ):
                    return_code = cli.main(["compatibility"])

                self.assertEqual(return_code, 2)
                self.assertEqual(stderr.getvalue(), f"msc: error: {error}\n")
                self.assertNotIn("Traceback", stderr.getvalue())

    def test_progress_printer_reports_bytes_files_and_one_completion_newline(self) -> None:
        stderr = io.StringIO()
        byte_progress = cli._ProgressPrinter()
        with redirect_stderr(stderr):
            byte_progress(ProgressEvent("encoding", 25, 100, 0, 1))
            byte_progress(ProgressEvent("encoding", 100, 100, 1, 1))
            byte_progress(ProgressEvent("encoding", 100, 100, 1, 1))

        rendered = stderr.getvalue()
        self.assertIn("Encoding:  25.00%", rendered)
        self.assertIn("Encoding: 100.00%", rendered)
        self.assertEqual(rendered.count("\n"), 1)

        stderr = io.StringIO()
        file_progress = cli._ProgressPrinter()
        with redirect_stderr(stderr):
            file_progress(ProgressEvent("decoding", 0, 0, 1, 2))
            file_progress(ProgressEvent("decoding", 0, 0, 2, 2))

        rendered = stderr.getvalue()
        self.assertIn("Decoding: 1/2 files", rendered)
        self.assertIn("Decoding: 2/2 files", rendered)
        self.assertEqual(rendered.count("\n"), 1)


if __name__ == "__main__":
    unittest.main()
