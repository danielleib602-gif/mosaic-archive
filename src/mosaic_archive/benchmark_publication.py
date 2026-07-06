"""Create versioned JSON and Markdown reports for the public benchmark corpus."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import platform
import shutil
import statistics
import tempfile
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from mosaic_archive import __version__
from mosaic_archive.benchmark import benchmark_path
from mosaic_archive.comparisons import comparison_tool_versions
from mosaic_archive.corpus import MANIFEST_NAME, verify_corpus

SCHEMA_VERSION = 2
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


def _comparison_size(comparisons: dict[str, dict[str, Any]], name: str) -> str:
    value = comparisons.get(name, {}).get("archive_size")
    return str(value) if isinstance(value, int) else "n/a"


def _aggregate_runs(
    runs: list[dict[str, Any]],
    *,
    randomized_archive_size: bool = False,
) -> dict[str, Any]:
    if not runs:
        raise ValueError("at least one benchmark run is required")
    result = dict(runs[0])
    volatile_fields = {
        "decode_mib_per_second",
        "decode_seconds",
        "encode_mib_per_second",
        "encode_seconds",
        "peak_memory_bytes",
    }
    if randomized_archive_size:
        volatile_fields.update(("archive_size", "ratio"))
    for field, expected in result.items():
        if field in volatile_fields:
            continue
        if any(run.get(field) != expected for run in runs[1:]):
            raise ValueError(f"{field} changed across repeated benchmark runs")
    verification_field = (
        "round_trip_verified" if "round_trip_verified" in result else "verified"
    )
    verifications = [run.get(verification_field) for run in runs]
    if any(verified is False for verified in verifications):
        raise ValueError("one or more repeated benchmark runs failed verification")

    timing: dict[str, dict[str, float | list[float]]] = {}
    for field in ("encode_seconds", "decode_seconds"):
        values = [run.get(field) for run in runs]
        if all(isinstance(value, int | float) for value in values):
            samples = [float(value) for value in cast(list[int | float], values)]
            median = statistics.median(samples)
            result[field] = median
            timing[field] = {
                "samples": samples,
                "minimum": min(samples),
                "median": median,
                "median_absolute_deviation": statistics.median(
                    abs(value - median) for value in samples
                ),
                "maximum": max(samples),
            }
    if timing:
        result["timing"] = timing
    peaks = [run.get("peak_memory_bytes") for run in runs]
    if all(isinstance(value, int) for value in peaks):
        result["peak_memory_bytes"] = max(cast(list[int], peaks))
    if randomized_archive_size:
        archive_sizes = [run.get("archive_size") for run in runs]
        if all(isinstance(value, int) for value in archive_sizes):
            size_samples = cast(list[int], archive_sizes)
            result["archive_size"] = int(statistics.median(size_samples))
            result["archive_size_distribution"] = {
                "samples": size_samples,
                "minimum": min(size_samples),
                "median": statistics.median(size_samples),
                "maximum": max(size_samples),
            }
        ratios = [run.get("ratio") for run in runs]
        if all(isinstance(value, int | float) for value in ratios):
            result["ratio"] = statistics.median(cast(list[int | float], ratios))
    original_size = result.get("original_size")
    if isinstance(original_size, int):
        for seconds_field, speed_field in (
            ("encode_seconds", "encode_mib_per_second"),
            ("decode_seconds", "decode_mib_per_second"),
        ):
            seconds = result.get(seconds_field)
            if isinstance(seconds, int | float):
                result[speed_field] = (
                    (original_size / (1024 * 1024)) / seconds if seconds > 0 else 0.0
                )
    return result


def _size_deltas(
    mosaic: dict[str, Any],
    comparisons: dict[str, dict[str, Any]],
) -> dict[str, int]:
    mosaic_size = mosaic.get("archive_size")
    if not isinstance(mosaic_size, int):
        return {}
    return {
        name: mosaic_size - archive_size
        for name, comparison in comparisons.items()
        if isinstance((archive_size := comparison.get("archive_size")), int)
    }


def _aggregate_comparisons(
    runs: list[dict[str, dict[str, Any]]],
) -> dict[str, dict[str, Any]]:
    if not runs:
        raise ValueError("at least one comparison run is required")
    names = set(runs[0])
    if any(set(run) != names for run in runs[1:]):
        raise ValueError("comparison methods changed across repeated runs")
    return {
        name: _aggregate_runs(
            [run[name] for run in runs],
            randomized_archive_size=name == "7z-encrypted",
        )
        for name in sorted(names)
    }


def _benchmark_runs(
    source: Path,
    *,
    repeats: int,
    archive_format: str,
    kdf_log_n: int,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    mosaic_runs: list[dict[str, Any]] = []
    comparison_runs: list[dict[str, dict[str, Any]]] = []
    for _ in range(repeats):
        if archive_format == "solid":
            benchmark_result = benchmark_path(
                source,
                _PASSWORD,
                chunk_size=65_536,
                padding_size=256,
                kdf_log_n=kdf_log_n,
                profile="balanced",
                archive_format="solid",
                compare=True,
            )
            raw = dataclasses.asdict(benchmark_result)
        else:
            stable_benchmark = benchmark_path(
                source,
                _PASSWORD,
                chunk_size=65_536,
                padding_size=1024,
                kdf_log_n=kdf_log_n,
                profile="balanced",
                archive_format="stable",
                compare=True,
            )
            raw = dataclasses.asdict(stable_benchmark)
        comparisons = raw.pop("comparisons")
        mosaic_runs.append(raw)
        comparison_runs.append(comparisons)
    return _aggregate_runs(mosaic_runs), _aggregate_comparisons(comparison_runs)


def _category_benchmarks(
    corpus: Path,
    manifest: dict[str, Any],
    *,
    archive_format: str,
    kdf_log_n: int,
) -> dict[str, dict[str, Any]]:
    entries_by_category: dict[str, list[dict[str, Any]]] = {}
    for entry in manifest["files"]:
        entries_by_category.setdefault(str(entry["category"]), []).append(entry)
    results: dict[str, dict[str, Any]] = {}
    with tempfile.TemporaryDirectory(prefix="msc-category-benchmark-") as temporary:
        temporary_root = Path(temporary)
        for category in sorted(entries_by_category):
            entries = entries_by_category[category]
            category_root = temporary_root / category
            for entry in entries:
                relative = Path(*str(entry["path"]).split("/"))
                source = corpus / relative
                destination = category_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
            mosaic, comparisons = _benchmark_runs(
                category_root,
                repeats=1,
                archive_format=archive_format,
                kdf_log_n=kdf_log_n,
            )
            results[category] = {
                "file_count": len(entries),
                "original_size": sum(int(entry["size"]) for entry in entries),
                "mosaic": mosaic,
                "comparisons": comparisons,
                "mosaic_size_delta_bytes": _size_deltas(mosaic, comparisons),
            }
    return results


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
            f"format={configuration['format']}, profile={configuration['profile']}, "
            f"chunk={configuration['chunk_size']}, "
            f"padding={configuration['padding_size']}, scrypt logN={configuration['kdf_log_n']}"
        ),
        (
            "- Timing statistic: median of "
            f"{report['measurement']['independent_runs']} independent runs"
        ),
        "",
        "Mosaic includes authenticated encryption and padding. Encrypted 7-Zip",
        "uses AES-256 data/header encryption; the other comparison tools are",
        "compression-only baselines. Ratios are context, not universal claims.",
        "",
        "| Method | Archive bytes | Ratio | Encode s | Decode s | Verified | Notes |",
        "|---|---:|---:|---:|---:|:---:|---|",
        _method_row(
            f"Mosaic Archive ({report['mosaic']['format_name']})",
            report["mosaic"],
            "scrypt + ChaCha20-Poly1305; padded",
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
    lines.extend(
        [
            "",
            "## Category results",
            "",
            "| Category | Input bytes | Files | Mosaic bytes | ZIP bytes | "
            "zstd bytes | Encrypted 7-Zip bytes |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for category, result in report["categories"].items():
        comparisons = result["comparisons"]
        lines.append(
            f"| {category} | {result['original_size']} | {result['file_count']} | "
            f"{result['mosaic']['archive_size']} | "
            f"{_comparison_size(comparisons, 'zip')} | "
            f"{_comparison_size(comparisons, 'zstd')} | "
            f"{_comparison_size(comparisons, '7z-encrypted')} |"
        )
    return "\n".join(lines) + "\n"


def publish_benchmark(
    corpus: Path,
    output: Path,
    *,
    release: str,
    source_commit: str,
    kdf_log_n: int = 14,
    repeats: int = 5,
    archive_format: str = "solid",
) -> dict[str, Any]:
    if repeats < 1 or repeats > 11 or repeats % 2 == 0:
        raise ValueError("repeats must be an odd integer between 1 and 11")
    if archive_format not in {"stable", "solid"}:
        raise ValueError("format must be stable or solid")
    if not verify_corpus(corpus):
        raise ValueError("benchmark corpus failed verification")
    manifest_path = corpus / MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    mosaic, comparisons = _benchmark_runs(
        corpus,
        repeats=repeats,
        archive_format=archive_format,
        kdf_log_n=kdf_log_n,
    )
    categories = _category_benchmarks(
        corpus,
        manifest,
        archive_format=archive_format,
        kdf_log_n=kdf_log_n,
    )
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "release": release,
        "source_commit": source_commit,
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "package_version": __version__,
        "corpus": {
            "version": manifest["corpus_version"],
            "seed": manifest["seed"],
            "unit_size": manifest["unit_size"],
            "total_bytes": mosaic["original_size"],
            "benchmark_input_bytes": mosaic["original_size"],
            "declared_data_bytes": sum(
                int(entry["size"]) for entry in manifest["files"]
            ),
            "file_count": len(manifest["files"]),
            "category_count": len(
                {str(entry["category"]) for entry in manifest["files"]}
            ),
            "manifest_sha256": _sha256(manifest_path),
        },
        "environment": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "configuration": {
            "format": archive_format,
            "profile": "balanced",
            "chunk_size": 65_536,
            "padding_size": 256 if archive_format == "solid" else 1024,
            "kdf_log_n": kdf_log_n,
        },
        "measurement": {
            "independent_runs": repeats,
            "timing_statistic": "median",
            "raw_samples_included": True,
            "category_runs": 1,
        },
        "mosaic": mosaic,
        "comparisons": comparisons,
        "mosaic_size_delta_bytes": _size_deltas(mosaic, comparisons),
        "categories": categories,
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
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--format", choices=("stable", "solid"), default="solid")
    arguments = parser.parse_args(argv)
    report = publish_benchmark(
        arguments.corpus,
        arguments.output,
        release=arguments.release,
        source_commit=arguments.source_commit,
        kdf_log_n=arguments.kdf_log_n,
        repeats=arguments.repeats,
        archive_format=arguments.format,
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
