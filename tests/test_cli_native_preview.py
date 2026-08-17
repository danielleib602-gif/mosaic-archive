from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

from mosaic_archive import cli


def _contained_main(arguments: list[str]) -> int:
    try:
        return cli.main(arguments)
    except SystemExit as error:
        raise AssertionError(
            f"native preview CLI errors must be contained as return code 2, got {error.code}"
        ) from error


@dataclass(frozen=True)
class _Stats:
    format_name: str = "M7A0"
    archive_kind: str = "file"
    status: str = "non-stable-preview"
    stable: bool = False
    encrypted: bool = True
    authenticated: bool = True
    hash_verified: bool = True
    original_size: int = 1_024
    inner_encoded_size: int = 800
    archive_size: int = 2_176
    segment_count: int = 1
    record_count: int = 3
    deduplicated_records: int = 0
    raw_records: int = 1
    lzma2_records: int = 1
    delta_zstd_records: int = 0
    zstd_records: int = 1
    data_records: int = 1
    padding_bytes: int = 256
    authentication_bytes: int = 32
    inner_ratio: float = 0.78125
    archive_ratio: float = 2.125


class NativePreviewCliTests(unittest.TestCase):
    def test_encode_native_preview_uses_only_named_environment_password(self) -> None:
        stats = _Stats(hash_verified=False)
        with (
            patch.dict(cli.os.environ, {"MOSAIC_PASSWORD": "päss🔐"}),
            patch("mosaic_archive.cli.getpass.getpass") as prompt,
            patch(
                "mosaic_archive.cli.encode_native_preview_file",
                return_value=stats,
                create=True,
            ) as encode,
            patch("mosaic_archive.cli._print_result") as print_result,
        ):
            return_code = _contained_main(
                [
                    "encode-native-preview",
                    "input.bin",
                    "archive.m7a",
                    "--password-env",
                    "MOSAIC_PASSWORD",
                    "--threads",
                    "4",
                    "--kdf-log-n",
                    "16",
                    "--max-input-bytes",
                    "12345",
                    "--json",
                ]
            )

        self.assertEqual(return_code, 0)
        prompt.assert_not_called()
        encode.assert_called_once_with(
            Path("input.bin"),
            Path("archive.m7a"),
            "päss🔐",
            threads=4,
            kdf_log_n=16,
            max_input_bytes=12_345,
        )
        print_result.assert_called_once_with("encode-native-preview", stats, True)

    def test_decode_native_preview_forwards_every_resource_ceiling(self) -> None:
        stats = _Stats()
        with (
            patch.dict(cli.os.environ, {"MOSAIC_PASSWORD": "secret"}),
            patch(
                "mosaic_archive.cli.decode_native_preview_file",
                return_value=stats,
                create=True,
            ) as decode,
            patch("mosaic_archive.cli._print_result") as print_result,
        ):
            return_code = _contained_main(
                [
                    "decode-native-preview",
                    "archive.m7a",
                    "restored.bin",
                    "--password-env",
                    "MOSAIC_PASSWORD",
                    "--max-output-bytes",
                    "11",
                    "--max-encoded-bytes",
                    "12",
                    "--max-segments",
                    "13",
                    "--max-records",
                    "14",
                    "--max-expansion-ratio",
                    "15",
                    "--max-archive-bytes",
                    "16",
                    "--max-data-records",
                    "17",
                    "--max-kdf-log-n",
                    "18",
                ]
            )

        self.assertEqual(return_code, 0)
        decode.assert_called_once_with(
            Path("archive.m7a"),
            Path("restored.bin"),
            "secret",
            max_output_bytes=11,
            max_encoded_bytes=12,
            max_segments=13,
            max_records=14,
            max_expansion_ratio=15,
            max_archive_bytes=16,
            max_data_records=17,
            max_kdf_log_n=18,
        )
        print_result.assert_called_once_with("decode-native-preview", stats, False)

    def test_inspect_native_preview_prints_exact_json_flags(self) -> None:
        stats = _Stats()
        stdout = io.StringIO()
        with (
            patch.dict(cli.os.environ, {"MOSAIC_PASSWORD": "secret"}),
            patch(
                "mosaic_archive.cli.inspect_native_preview_file",
                return_value=stats,
                create=True,
            ),
            redirect_stdout(stdout),
        ):
            return_code = _contained_main(
                [
                    "inspect-native-preview",
                    "archive.m7a",
                    "--password-env",
                    "MOSAIC_PASSWORD",
                    "--json",
                ]
            )

        self.assertEqual(return_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["operation"], "inspect-native-preview")
        self.assertEqual(
            {
                key: payload[key]
                for key in (
                    "format_name",
                    "archive_kind",
                    "status",
                    "stable",
                    "encrypted",
                    "authenticated",
                    "hash_verified",
                )
            },
            {
                "format_name": "M7A0",
                "archive_kind": "file",
                "status": "non-stable-preview",
                "stable": False,
                "encrypted": True,
                "authenticated": True,
                "hash_verified": True,
            },
        )

    def test_literal_password_is_rejected_without_echoing_the_secret(self) -> None:
        for password_argument in (
            "--password",
            "--password=must-not-escape",
            "--pass=must-not-escape",
            "-p",
            "-pmust-not-escape",
            "--pwd",
            "-P",
        ):
            stderr = io.StringIO()
            arguments = [
                "inspect-native-preview",
                "archive.m7a",
                password_argument,
            ]
            if password_argument in {"--password", "-p", "--pwd", "-P"}:
                arguments.append("must-not-escape")

            with self.subTest(argument=password_argument), redirect_stderr(stderr):
                return_code = _contained_main(arguments)
                self.assertEqual(return_code, 2)
                self.assertIn(
                    "literal password arguments are not accepted; use --password-env NAME",
                    stderr.getvalue(),
                )
                self.assertNotIn("must-not-escape", stderr.getvalue())

    def test_literal_password_before_native_command_is_rejected_without_echo(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            return_code = _contained_main(
                [
                    "--password",
                    "must-not-escape",
                    "inspect-native-preview",
                    "archive.m7a",
                ]
            )

        self.assertEqual(return_code, 2)
        self.assertIn("literal password arguments are not accepted", stderr.getvalue())
        self.assertNotIn("must-not-escape", stderr.getvalue())

    def test_legacy_command_may_use_a_path_named_like_native_command(self) -> None:
        stats = _Stats()
        with (
            patch("mosaic_archive.cli.encode_path", return_value=stats) as encode,
            patch("mosaic_archive.cli._print_result"),
        ):
            return_code = _contained_main(
                [
                    "encode",
                    "inspect-native-preview",
                    "archive.msc",
                    "--password",
                    "legacy-secret",
                ]
            )

        self.assertEqual(return_code, 0)
        encode.assert_called_once()
        self.assertEqual(
            encode.call_args.args[:2],
            (Path("inspect-native-preview"), Path("archive.msc")),
        )

    def test_leading_end_of_options_preserves_legacy_command_authority(self) -> None:
        stats = _Stats()
        with (
            patch("mosaic_archive.cli.encode_path", return_value=stats) as encode,
            patch("mosaic_archive.cli._print_result"),
        ):
            return_code = _contained_main(
                [
                    "--",
                    "encode",
                    "inspect-native-preview",
                    "archive.msc",
                    "--password",
                    "legacy-secret",
                ]
            )

        self.assertEqual(return_code, 0)
        encode.assert_called_once()

    def test_end_of_options_allows_dash_prefixed_archive_path(self) -> None:
        stats = _Stats()
        with (
            patch.dict(cli.os.environ, {"MOSAIC_PASSWORD": "secret"}),
            patch(
                "mosaic_archive.cli.inspect_native_preview_file",
                return_value=stats,
            ) as inspect,
            patch("mosaic_archive.cli._print_result"),
        ):
            return_code = _contained_main(
                [
                    "inspect-native-preview",
                    "--password-env",
                    "MOSAIC_PASSWORD",
                    "--",
                    "--archive",
                ]
            )

        self.assertEqual(return_code, 0)
        inspect.assert_called_once()
        self.assertEqual(inspect.call_args.args[0], Path("--archive"))

    def test_leading_and_command_sentinels_allow_password_named_path(self) -> None:
        stats = _Stats()
        with (
            patch.dict(cli.os.environ, {"MOSAIC_PASSWORD": "secret"}),
            patch(
                "mosaic_archive.cli.inspect_native_preview_file",
                return_value=stats,
            ) as inspect,
            patch("mosaic_archive.cli._print_result"),
        ):
            return_code = _contained_main(
                [
                    "--",
                    "inspect-native-preview",
                    "--password-env",
                    "MOSAIC_PASSWORD",
                    "--",
                    "--password",
                ]
            )

        self.assertEqual(return_code, 0)
        self.assertEqual(inspect.call_args.args[0], Path("--password"))

    def test_surplus_literal_password_after_sentinel_is_rejected_without_echo(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            return_code = _contained_main(
                [
                    "inspect-native-preview",
                    "archive.m7a",
                    "--",
                    "--password",
                    "must-not-escape",
                ]
            )

        self.assertEqual(return_code, 2)
        self.assertIn("literal password arguments are not accepted", stderr.getvalue())
        self.assertNotIn("must-not-escape", stderr.getvalue())

    def test_every_native_parse_failure_is_contained_without_echoing_values(self) -> None:
        for suspicious_argument in ("/password", "password=must-not-escape"):
            stderr = io.StringIO()
            arguments = [
                "inspect-native-preview",
                "archive.m7a",
                suspicious_argument,
            ]
            if suspicious_argument == "/password":
                arguments.append("must-not-escape")

            with self.subTest(argument=suspicious_argument), redirect_stderr(stderr):
                return_code = _contained_main(arguments)

            self.assertEqual(return_code, 2)
            self.assertIn("invalid native preview arguments", stderr.getvalue())
            self.assertNotIn("must-not-escape", stderr.getvalue())

    def test_unrepresentable_native_limit_is_contained(self) -> None:
        stderr = io.StringIO()
        with (
            patch.dict(cli.os.environ, {"MOSAIC_PASSWORD": "secret"}),
            redirect_stderr(stderr),
        ):
            return_code = _contained_main(
                [
                    "inspect-native-preview",
                    "archive.m7a",
                    "--password-env",
                    "MOSAIC_PASSWORD",
                    "--max-output-bytes",
                    "-1",
                ]
            )

        self.assertEqual(return_code, 2)
        self.assertIn("max_output_bytes", stderr.getvalue())

    def test_missing_or_empty_password_environment_variable_is_contained(self) -> None:
        for environment in ({}, {"MOSAIC_PASSWORD": ""}):
            stderr = io.StringIO()
            with (
                self.subTest(environment=environment),
                patch.dict(cli.os.environ, environment, clear=True),
                patch("mosaic_archive.cli.inspect_native_preview_file", create=True) as inspect,
                redirect_stderr(stderr),
            ):
                return_code = _contained_main(
                    [
                        "inspect-native-preview",
                        "archive.m7a",
                        "--password-env",
                        "MOSAIC_PASSWORD",
                    ]
                )
                self.assertEqual(return_code, 2)
                self.assertIn("msc: error:", stderr.getvalue())
                inspect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
