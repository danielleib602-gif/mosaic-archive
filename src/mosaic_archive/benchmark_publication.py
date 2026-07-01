"""Create versioned JSON and Markdown reports for the public benchmark corpus."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import platform
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mosaic_archive import __version__
from mosaic_archive.benchmark import benchmark_path
from mosaic_archive.comparisons import comparison_tool_versions
from mosaic_archive.corpus import MANIFEST_NAME, verify_corpus

SCHEMA_VERSION = 1
_PASSWORD = "synthetic-public-corpus"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _method_row(name: str, result: dict[str, Any], note: str) -> str:
    archive_size = result.get("archive_size")
    ratio = result.get("ratio", result.get("archive_ratio"))
    encode = result.get("encode_seconds")
    decode = result.get("decode_seconds")
    verified = result.get("verified", result.get("round_trip_verified"))
    size_text = str(archive_size) if archive_size is not None else "n/a"
    ratio_text = f"{ratio:.4f}" if isinstance(ratio, int | float) else "n/a"
    encode_text = f"{encode:.4f}" if isinstance(encode, int | float) else "n/a"
    decode_text = f"{decode:.4f}" if isinstance(decode, int | float) else "n/a"
    verified_text = "yes" if verified is True else "no" if verified is False else "n/a"
    return (
        f"| {name} | {size_text} | {ratio_text} | {encode_text} | "
        f"{decode_text} | {verified_text} | {note} |"
    )


def render_markdown(report: dict[str, Any]) -> str:
    configuration = report["configuration"]
    lines = [
        f"# Mosaic Archive benchmark {report['release']}",
        "",
        f"- Source commit: `{report['source_commit']}`",
        f"- Corpus manifest SHA-256: `{report['corpus']['manifest_sha256']}`",
        f"- Original bytes: {report['corpus']['total_bytes']}",
        f"- Platform: {report['environment']['platform']}",
        f"- Python: {report['environment']['python']}",
        (
            "- Mosaic configuration: "
            f"profile={configuration['profile']}, chunk={configuration['chunk_size']}, "
            f"padding={configuration['padding_size']}, scrypt logN={configuration['kdf_log_n']}"
        ),
        "",
        "Mosaic includes authenticated encryption and padding. All comparison",
        "tools below are compression-only baselines; ratios are therefore useful",
        "context, not feature-equivalent claims.",
        "",
        "| Method | Archive bytes | Ratio | Encode s | Decode s | Verified | Notes |",
        "|---|---:|---:|---:|---:|:---:|---|",
        _method_row(
            "Mosaic Archive",
            report["mosaic"],
            "MSC6; scrypt + ChaCha20-Poly1305; padded",
        ),
    ]
    for name, result in report["comparisons"].items():
        lines.append(_method_row(name, result, result["note"]))
    lines.extend(
        [
            "",
            "## Tool versions",
            "",
        ]
    )
    for name, version in report["tool_versions"].items():
        lines.append(f"- {name}: {version or 'unavailable'}")
    return "\n".join(lines) + "\n"


def publish_benchmark(
    corpus: Path,
    output: Path,
    *,
    release: str,
    source_commit: str,
    kdf_log_n: int = 14,
) -> dict[str, Any]:
    if not verify_corpus(corpus):
        raise ValueError("benchmark corpus failed verification")
    manifest_path = corpus / MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    benchmark = benchmark_path(
        corpus,
        _PASSWORD,
        chunk_size=65_536,
        padding_size=1024,
        kdf_log_n=kdf_log_n,
        profile="balanced",
        compare=True,
    )
    raw = dataclasses.asdict(benchmark)
    comparisons = raw.pop("comparisons")
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "release": release,
        "source_commit": source_commit,
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "package_version": __version__,
        "format_version": benchmark.format_version,
        "corpus": {
            "version": manifest["corpus_version"],
            "seed": manifest["seed"],
            "unit_size": manifest["unit_size"],
            "total_bytes": benchmark.original_size,
            "manifest_sha256": _sha256(manifest_path),
        },
        "environment": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "configuration": {
            "profile": "balanced",
            "chunk_size": 65_536,
            "padding_size": 1024,
            "kdf_log_n": kdf_log_n,
        },
        "mosaic": raw,
        "comparisons": comparisons,
        "tool_versions": comparison_tool_versions(),
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output / "report.md").write_text(render_markdown(report), encoding="utf-8")
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--release", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--kdf-log-n", type=int, default=14)
    arguments = parser.parse_args(argv)
    report = publish_benchmark(
        arguments.corpus,
        arguments.output,
        release=arguments.release,
        source_commit=arguments.source_commit,
        kdf_log_n=arguments.kdf_log_n,
    )
    print(
        json.dumps(
            {
                "report": str(arguments.output),
                "verified": report["mosaic"]["round_trip_verified"],
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
