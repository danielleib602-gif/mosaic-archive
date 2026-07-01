# Mosaic Archive

Mosaic Archive is an experimental general-purpose compression and encryption
tool. It walks arbitrary files or folders, splits file content into blocks, measures local statistical
structure, keeps the smallest result from several simple lossless models, pads
the compressed stream to reduce precise-length leakage, then encrypts and
authenticates the whole archive.

The guiding idea is deliberately plain: compression is prediction. A useful
compressor finds a cheaper description of repeated or predictable bytes.

> **Experimental alpha:** Mosaic Archive is not security-audited and is not
> expected to beat mature compressors such as zstd, xz, or 7-Zip on general
> benchmarks. Security uses standard ChaCha20-Poly1305 authenticated encryption;
> the experimental part is the adaptive compression engine.

## What v0.24 does

- accepts an arbitrary file or folder and produces an encrypted `.msc` archive;
- finds stable content-defined boundaries with a 64-byte rolling Buzhash;
- stores each unique chunk once and uses direct authenticated backward
  references for repeated chunks across files and shifted versions;
- adds a normalized byte-histogram rANS entropy mode for skewed symbol streams;
- adds a fast C-backed DEFLATE baseline and a feature router that avoids the
  quadratic teaching LZ mode in normal encoding;
- adds an experimental LZ parser with separately rANS-coded token, literal,
  length, and distance streams;
- provides `fast`, `balanced`, and `research` codec-search profiles;
- tries `RAW`, `RLE`, `DELTA8`, and `LZ_SIMPLE` independently on every block;
- selects the smallest actual encoding, without relying on file extensions;
- stores portable relative paths, file metadata, and per-file SHA-256 restoration
  digests in an encrypted manifest;
- derives a fresh archive key with scrypt and a random 16-byte salt;
- independently authenticates the manifest and each bounded-memory data frame;
- derives each frame nonce from a random archive prefix and a monotonic index;
- pads each encrypted frame to configurable length buckets;
- defaults to 1 KiB padding buckets, with larger privacy-oriented buckets
  available through `--padding-size`;
- writes encoded and restored files atomically;
- rejects traversal paths, links, reparse points, special files, portable-name
  collisions, and merges into existing folder destinations;
- emits optional progress and continues to decode legacy MSC1 archives;
- reports mode selection, block features, padding cost, speed, and peak Python
  allocation in benchmark mode;
- optionally compares against ZIP, gzip, zstd, and 7-Zip, reporting unavailable
  or unsupported tools honestly;
- provides `inspect` to authenticate, decode, hash-check, and explain an archive;
- generates a deterministic, SHA-256-verified public benchmark corpus spanning
  text, structured records, numeric data, duplicates, random bytes,
  precompressed bytes, and empty inputs;
- runs the complete test suite across Python 3.11 and 3.13 on Linux, Windows,
  and macOS, with separate lint, type, coverage, dependency-audit, and build
  gates;
- records a scheduled benchmark artifact each month so performance changes can
  be compared against an identical generated corpus;
- commits permanent encrypted decoder fixtures for MSC1 through MSC6 so current
  releases must keep restoring every claimed archive generation;
- provides a deterministic mutation-fuzz harness for every public header parser,
  frame parser, and compression-mode decoder;
- runs a bounded 10,000-case fuzz campaign and streaming 256 MiB archive
  round trip on a weekly scheduled workflow;
- seeds Atheris coverage-guided fuzzing with valid inputs for six structural
  parsers and all seven compression-mode decoders;
- preserves evolving corpora and crash, timeout, or out-of-memory artifacts
  from bounded pull-request and weekly fuzz campaigns;
- freezes MSC6 as the 1.0 writer format and commits to decoding MSC1 through
  MSC6 throughout the 1.x package line;
- exposes the format, upgrade, and deprecation contract as human-readable text
  and machine-readable CLI output;
- publishes reproducible, versioned JSON and Markdown results against ZIP,
  tar+gzip, tar+zstd, and 7-Zip on the identical generated corpus;
- builds smoke-tested native Linux, Windows, and macOS executables and attaches
  keyless Sigstore/SLSA provenance plus SHA-256 checksums to tagged releases.

## Install for development

Python 3.11 or newer and [uv](https://docs.astral.sh/uv/) are recommended:

```console
uv sync --extra dev
uv run msc --help
```

Or install the project with another PEP 517-compatible Python package manager.

## Use

Let `msc` prompt for the password so it does not appear in command history or
the local process list:

```console
uv run msc encode report.pdf report.msc
uv run msc inspect report.msc
uv run msc decode report.msc restored-report.pdf
uv run msc benchmark report.pdf
uv run msc encode project-folder project.msc
uv run msc encode project-folder project.msr --format solid --padding-size 256
uv run msc decode project.msc restored-project
uv run msc benchmark project-folder --compare
uv run msc benchmark project-folder --format solid --padding-size 256 --compare
uv run msc benchmark project-folder --profile research
uv run python -m mosaic_archive.corpus benchmark-corpus
uv run msc benchmark benchmark-corpus --json
uv run python -m mosaic_archive.reliability fuzz --cases 1000
uv run python -m mosaic_archive.reliability soak --size-mib 256
uv run python -m mosaic_archive.coverage_fuzzing fuzz-corpus
uv run msc compatibility --json
```

For scripts, read the password from an environment variable:

```console
$env:MSC_PASSWORD = "use-a-long-unique-passphrase"
uv run msc encode report.pdf report.msc --password-env MSC_PASSWORD
```

Every command also supports `--json`. A literal `--password` option exists for
test automation and compatibility, but is less private on a shared machine.

Example benchmark fields include:

- original, compressed, padded, and final archive sizes;
- pre-padding compression ratio and final archive ratio;
- padding overhead;
- encode/decode time and throughput;
- block count and compression-mode distribution;
- duplicate-block observations and average file-agnostic block features;
- end-to-end round-trip verification.

## Architecture

```text
file/folder tree
  -> encrypted portable manifest
  -> content-defined chunks (min / average / max bounds)
  -> SHA-256 chunk identity and cross-file duplicate routing
  -> entropy/repetition/delta/text-likelihood measurements
  -> try RAW, RLE, DELTA8+RLE, and simple LZ
  -> retain the smallest payload per block
  -> one randomly padded authenticated frame per block
  -> scrypt-derived archive key
  -> ChaCha20-Poly1305 ciphertext + tag per frame
```

The balanced router always tries RAW, RLE, and DEFLATE, adds DELTA8 for smooth
signals, and adds BYTE_RANS for lower-entropy symbol distributions. The final
choice still uses exact encoded size. LZ_SIMPLE remains decodable and available
for exhaustive research comparisons, and LZ_RANS provides split entropy-coded
streams. Both are skipped by the default encoder. `fast` tries RAW/DEFLATE only;
`research` tries every registered codec.

## Development checks

```console
uv run python -m unittest discover -s tests -v
uv run ruff check .
uv run mypy src
uv run --with coverage coverage run -m unittest discover -s tests
uv run --with coverage coverage report --fail-under=80
uv run --with pip-audit pip-audit --local
uv build
```

The generated benchmark corpus is deterministic for a given seed and unit
size. Its manifest records every file's category, byte count, and SHA-256
digest; `verify_corpus` also rejects undeclared files. CI regenerates a small
smoke corpus on every pull request, while the scheduled benchmark uses the
default corpus and uploads both its manifest and machine-readable result.

Permanent compatibility fixtures live under `tests/fixtures/compat`. Each
fixture is a tiny encrypted archive with a manifest-recorded SHA-256 digest,
format version, mode, and restored-content hash. Regenerate them only for an
intentional compatibility-policy change:

```console
uv run python tools/generate_compatibility_fixtures.py
```

The binary layout is documented in [docs/FORMAT.md](docs/FORMAT.md), and the
security boundaries are explicit in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
Format stability, upgrades, and deprecations are defined in
[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).
Published performance evidence is indexed in
[benchmarks/README.md](benchmarks/README.md).
Binary build, publication, and verification instructions are in
[docs/RELEASES.md](docs/RELEASES.md).

The v0.12 corpus result is encouraging but specific: Mosaic's encrypted,
padded archive reached a 0.471 ratio, better than ZIP/gzip on this duplicate-rich
tree, while zstd reached 0.349 and 7-Zip 0.279. Mosaic encoding was substantially
slower, making throughput and entropy coding the clearest optimization targets.

The v0.14 solid-lane prototype closes that ratio gap at the research-payload
layer. Exact deduplication is followed by three file-agnostic solid LZMA lanes:
ordinary compressible chunks, delta-4 numeric chunks, and high-entropy chunks
that may still share distant content. On the byte-identical corpus it produced
274,400 payload bytes. Reserving a conservative 16 KiB for the future manifest,
encryption, authentication, and padding projects a 290,784-byte archive, 2,047
bytes below the committed 7-Zip result. This is not yet an MSC archive or a
release claim; integration must prove the full end-to-end result.

The v0.15 MSR1 experiment proves that integration end to end: the actual
scrypt-derived, ChaCha20-Poly1305-authenticated, 1 KiB-padded archive is 277,585
bytes (0.2643), 15,246 bytes smaller than the committed 7-Zip result of 292,831
bytes (0.2788), and restores the corpus exactly. This remains an experimental
whole-archive research format with higher memory use and slower encoding; MSC6
continues to be the stable writer.

The v0.16 experiment replaces LZMA preset 9 extreme with the default preset 6.
The final corpus archive remains exactly 277,585 bytes, while the recorded local
encode time falls from 2.29 seconds to 1.17 seconds and decode time from 0.077
seconds to 0.049 seconds. This reduces the codec-state memory requirement, but
MSR1 still buffers the full solid payload and ciphertext.

The v0.17 primitive keeps one continuous LZMA history per solid lane while
splitting its compressed output into independently numbered, padded, and
ChaCha20-Poly1305-authenticated frames. Decoding authenticates before
decompression, enforces frame and output bounds, and rejects reordered,
truncated, or modified streams. On the public corpus the three lane frames use
276,558 wire bytes, adding 2,246 bytes to the unframed compressed lanes. Adding
that measured cost to MSR1 projects 279,831 bytes, leaving 13,000 bytes against
the committed 7-Zip result. This is a component measurement, not an end-to-end
MSR2 claim; container integration is the next gate.

The v0.18 MSR2 experiment completes that integration with encrypted routing
metadata, disk-backed lane and canonical-chunk spools, continuous compression
history, and independently authenticated bounded frames. Its actual public
corpus archive is 279,699 bytes (0.2663), 13,132 bytes smaller than 7-Zip, and
restores exactly. Local encode/decode measurements were 1.22/0.053 seconds.
MSR2 remains experimental while parser hardening and broader corpus evaluation
continue; MSC6 is still the stable writer.

The v0.19 hardening pass adds explicit restored-size and frame-count budgets,
authenticates and validates an archive before creating destination directories,
and adds the exact MSR2 header parser to both deterministic and coverage-guided
fuzzing. Empty solid lanes no longer emit padded frames, saving 2,100 bytes on
each one-lane category in the public corpus. Category results are mixed and
reported plainly: MSR2 beats ZIP on structured, numeric, and duplicate-heavy
data, but its encrypted container remains about 1.5–2 KiB larger on tiny text,
random, and precompressed subsets.

The v0.20 compact experiment compresses authenticated routing metadata and uses
raw LZMA2 lane streams while retaining legacy MSR2 metadata decoding. With
explicit 256-byte padding, the mixed corpus reaches 276,115 bytes, 16,716 bytes
below 7-Zip. The text subset now reaches 607 bytes versus ZIP's 680, while
structured, numeric, and duplicate-heavy subsets also win. Random and
precompressed subsets remain 449 and 401 bytes larger than ZIP because MSR2
also carries encryption, authentication, and restoration metadata. The compact
profile leaks length at 256-byte rather than 1 KiB granularity.

The v0.21 CLI makes MSR2 usable without changing the stable default:
`msc encode --format solid` opts into the research container, while `decode`
and `inspect` recognize MSR2 automatically. MSC6 remains the default writer.
The compact 256-byte padding result must be selected explicitly because it
reveals archive lengths at finer granularity than the 1 KiB default.

The v0.22 CLI extends that opt-in path to
`msc benchmark --format solid`. Its JSON report records MSR2 archive size,
ratio, frame bounds, throughput, peak Python allocation, verified restoration,
and optional mature-tool comparisons without pretending MSR2 has MSC6 block
mode metrics.

The v0.23 benchmark adds a fair encrypted 7-Zip baseline using a fixed public
benchmark password, AES-256 data encryption, and encrypted headers. On hosted
Linux, compact MSR2 produced 276,115 bytes versus encrypted 7-Zip's 292,912,
a 16,797-byte (5.73%) size win. MSR2 encoding took 1.89 seconds versus 0.076
seconds for 7-Zip, so throughput remains the clearest measured weakness.

The v0.24 encoder compresses each solid lane once into a disk-backed spool,
then splits that exact stream into authenticated frames. This removes the
previous frame-count probe and second compression pass without changing a
single archive byte. Hosted encode time falls from 1.889 to 1.757 seconds
(7.0%); chunk routing and hashing now dominate the remaining gap.

## Current limits

- v0.3 deduplicates within one archive, but does not yet reuse chunks across
  separate archive generations;
- file data is bounded by the configured chunk size, but the encrypted manifest
  still scales in memory with the number and length of archived paths;
- links, junctions/reparse points, device nodes, sockets, and FIFOs are rejected;
- folder restoration refuses an existing destination instead of merging;
- duplicate restoration uses a temporary disk-backed cache for canonical chunks
  referenced later in the archive;
- padding reduces precise-length leakage but cannot hide the archive's rough
  size;
- the simple codecs prioritize clarity and correctness over mature-compressor
  performance;
- the package is still pre-1.0, while MSC6 decoder semantics and existing mode
  identifiers are frozen for the 1.0 format line.

The near-term roadmap is in
[plans/mosaic-archive-roadmap.md](plans/mosaic-archive-roadmap.md).
