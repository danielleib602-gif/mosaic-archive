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
        stats = _Stats()
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
        for password_argument in ("--password", "--password=must-not-escape"):
            stderr = io.StringIO()
            arguments = [
                "inspect-native-preview",
                "archive.m7a",
                password_argument,
            ]
            if password_argument == "--password":
                arguments.append("must-not-escape")

            with self.subTest(argument=password_argument), redirect_stderr(stderr):
                return_code = _contained_main(arguments)
                self.assertEqual(return_code, 2)
                self.assertIn(
                    "literal password arguments are not accepted; use --password-env NAME",
                    stderr.getvalue(),
                )
                self.assertNotIn("must-not-escape", stderr.getvalue())

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
