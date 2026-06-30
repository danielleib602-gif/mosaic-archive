"""Deterministic parser fuzzing and configurable large-file soak checks."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

from mosaic_archive.archive_api import decode_path, encode_path
from mosaic_archive.container_format import PublicHeader, parse_public_header
from mosaic_archive.dedup_archive import (
    DedupEntry,
    DedupManifest,
    parse_dedup_manifest,
    serialize_dedup_manifest,
)
from mosaic_archive.dedup_format import MSC3_FLAGS, Msc3Header, parse_msc3_header
from mosaic_archive.exceptions import ArchiveFormatError
from mosaic_archive.modes import ALL_MODES
from mosaic_archive.stream_archive import (
    ENTRY_FILE,
    KIND_FILE,
    Manifest,
    ManifestEntry,
    parse_manifest,
    serialize_manifest,
)
from mosaic_archive.stream_format import (
    FRAME_MANIFEST,
    FrameHeader,
    Msc2Header,
    parse_frame_header,
    parse_msc2_header,
)

_PASSWORD = "mosaic-public-reliability-harness"
_WRITE_BLOCK_SIZE = 1024 * 1024


@dataclass(frozen=True, slots=True)
class FuzzSummary:
    seed: int
    cases: int
    target_count: int
    executions: int
    accepted_inputs: int
    rejected_inputs: int


@dataclass(frozen=True, slots=True)
class SoakSummary:
    seed: int
    size_bytes: int
    archive_size: int
    format_version: int
    source_sha256: str
    restored_sha256: str
    hash_verified: bool


@dataclass(frozen=True, slots=True)
class _FuzzTarget:
    name: str
    valid_input: bytes
    invoke: Callable[[bytes], None]


def _accept_parser(parser: Callable[[bytes], object], payload: bytes) -> None:
    parser(payload)


def _parser_invoker(parser: Callable[[bytes], object]) -> Callable[[bytes], None]:
    def invoke(payload: bytes) -> None:
        _accept_parser(parser, payload)

    return invoke


def _parser_targets() -> tuple[_FuzzTarget, ...]:
    public = PublicHeader(
        version=1,
        flags=1,
        kdf_id=1,
        aead_id=1,
        chunk_size=4096,
        padding_size=256,
        salt=b"\x00" * 16,
        nonce=b"\x00" * 12,
        kdf_log_n=14,
        kdf_r=8,
        kdf_p=1,
        ciphertext_length=16,
    ).pack()
    stream_header = Msc2Header(
        version=2,
        flags=3,
        kdf_id=1,
        aead_id=1,
        chunk_size=4096,
        padding_size=256,
        salt=b"\x00" * 16,
        nonce_prefix=b"\x00" * 4,
        kdf_log_n=14,
        kdf_r=8,
        kdf_p=1,
        frame_count=1,
    )
    dedup_header = Msc3Header(
        version=6,
        flags=MSC3_FLAGS,
        kdf_id=1,
        aead_id=1,
        min_chunk_size=64,
        avg_chunk_size=256,
        max_chunk_size=1024,
        padding_size=256,
        salt=b"\x00" * 16,
        nonce_prefix=b"\x00" * 4,
        kdf_log_n=14,
        kdf_r=8,
        kdf_p=1,
        frame_count=1,
    )
    frame = FrameHeader(index=0, frame_type=FRAME_MANIFEST, ciphertext_length=16).pack()
    stream_manifest = serialize_manifest(
        Manifest(
            KIND_FILE,
            "seed",
            (ManifestEntry(ENTRY_FILE, "seed", 0o600, 0, 0, 1, 0, b"\x00" * 32),),
        )
    )
    dedup_manifest = serialize_dedup_manifest(
        DedupManifest(
            KIND_FILE,
            "seed",
            (DedupEntry(ENTRY_FILE, "seed", 0o600, 0, 0, 0, 0, b"\x00" * 32),),
            (),
        )
    )

    def parse_stream_manifest(payload: bytes) -> None:
        parse_manifest(payload, stream_header)

    def parse_content_defined_manifest(payload: bytes) -> None:
        parse_dedup_manifest(payload, dedup_header)

    parser_inputs = (
        ("msc1-public-header", public, parse_public_header),
        ("msc2-public-header", stream_header.pack(), parse_msc2_header),
        ("msc3-public-header", dedup_header.pack(), parse_msc3_header),
        ("frame-header", frame, parse_frame_header),
        ("msc2-manifest", stream_manifest, parse_stream_manifest),
        ("msc3-manifest", dedup_manifest, parse_content_defined_manifest),
    )
    return tuple(
        _FuzzTarget(
            name,
            valid_input,
            _parser_invoker(parser),
        )
        for name, valid_input, parser in parser_inputs
    )


def _mode_targets() -> tuple[_FuzzTarget, ...]:
    # Keep each decode attempt small so sustained campaigns spend their budget
    # exploring mutations rather than repeatedly expanding long valid outputs.
    original = b"Mosaic fuzz corpus\x00\x01\xff"
    targets: list[_FuzzTarget] = []
    for mode in ALL_MODES:
        valid_input = mode.encode(original)

        def invoke(
            payload: bytes,
            *,
            decoder: Callable[[bytes, int], bytes] = mode.decode,
            expected_size: int = len(original),
        ) -> None:
            decoded = decoder(payload, expected_size)
            if len(decoded) != expected_size:
                raise AssertionError("decoder accepted output with an inconsistent size")

        targets.append(_FuzzTarget(f"mode-{mode.name.lower()}", valid_input, invoke))
    return tuple(targets)


def _mutate(payload: bytes, rng: random.Random, case: int) -> bytes:
    if case == 0:
        return payload
    operation = case % 4
    if operation == 1:
        return payload[: rng.randrange(len(payload) + 1)]
    if operation == 2:
        damaged = bytearray(payload)
        if damaged:
            for _ in range(1 + rng.randrange(min(4, len(damaged)))):
                index = rng.randrange(len(damaged))
                damaged[index] ^= 1 << rng.randrange(8)
        return bytes(damaged)
    if operation == 3:
        return payload + rng.randbytes(rng.randrange(1, 17))
    return rng.randbytes(rng.randrange(0, max(2, len(payload) * 2)))


def run_parser_fuzz(*, seed: int, cases: int) -> FuzzSummary:
    """Round-robin mutations across parsers and require domain-safe failures."""
    if cases < 1:
        raise ValueError("fuzz cases must be positive")
    rng = random.Random(seed)
    targets = _parser_targets() + _mode_targets()
    accepted = rejected = 0
    for execution in range(cases):
        target = targets[execution % len(targets)]
        mutation_round = execution // len(targets)
        payload = _mutate(target.valid_input, rng, mutation_round)
        try:
            target.invoke(payload)
        except ArchiveFormatError:
            rejected += 1
        else:
            accepted += 1
    return FuzzSummary(seed, cases, len(targets), cases, accepted, rejected)


def _write_deterministic_file(path: Path, *, size_bytes: int, seed: int) -> str:
    rng = random.Random(seed)
    digest = hashlib.sha256()
    remaining = size_bytes
    with path.open("wb") as stream:
        while remaining:
            block = rng.randbytes(min(_WRITE_BLOCK_SIZE, remaining))
            stream.write(block)
            digest.update(block)
            remaining -= len(block)
    return digest.hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(_WRITE_BLOCK_SIZE), b""):
            digest.update(block)
    return digest.hexdigest()


def run_large_file_soak(work_dir: Path, *, size_bytes: int, seed: int) -> SoakSummary:
    """Stream a deterministic file through MSC6 and verify its restored digest."""
    if size_bytes < 1:
        raise ValueError("soak size must be positive")
    work_dir.mkdir(parents=True, exist_ok=True)
    source = work_dir / "soak-source.bin"
    archive = work_dir / "soak-archive.msc"
    restored = work_dir / "soak-restored.bin"
    for path in (source, archive, restored):
        path.unlink(missing_ok=True)

    source_sha256 = _write_deterministic_file(source, size_bytes=size_bytes, seed=seed)
    encoded = encode_path(
        source,
        archive,
        _PASSWORD,
        chunk_size=1024 * 1024,
        padding_size=4096,
        kdf_log_n=14,
        profile="fast",
    )
    decoded = decode_path(archive, restored, _PASSWORD)
    restored_sha256 = _sha256_file(restored)
    if source_sha256 != restored_sha256:
        raise AssertionError("large-file soak round trip changed the content digest")
    return SoakSummary(
        seed=seed,
        size_bytes=size_bytes,
        archive_size=archive.stat().st_size,
        format_version=encoded.format_version,
        source_sha256=source_sha256,
        restored_sha256=restored_sha256,
        hash_verified=decoded.hash_verified,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    fuzz = subparsers.add_parser("fuzz", help="run deterministic mutation fuzzing")
    fuzz.add_argument("--seed", type=int, default=20260629)
    fuzz.add_argument("--cases", type=int, default=1000)
    soak = subparsers.add_parser("soak", help="run a streaming large-file round trip")
    soak.add_argument("--seed", type=int, default=20260629)
    soak.add_argument("--size-mib", type=int, default=256)
    soak.add_argument("--work-dir", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "fuzz":
        summary: FuzzSummary | SoakSummary = run_parser_fuzz(
            seed=args.seed,
            cases=args.cases,
        )
    elif args.work_dir is not None:
        summary = run_large_file_soak(
            args.work_dir,
            size_bytes=args.size_mib * 1024 * 1024,
            seed=args.seed,
        )
    else:
        with tempfile.TemporaryDirectory(prefix="mosaic-soak-") as temp_dir:
            summary = run_large_file_soak(
                Path(temp_dir),
                size_bytes=args.size_mib * 1024 * 1024,
                seed=args.seed,
            )
    print(json.dumps(asdict(summary), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
