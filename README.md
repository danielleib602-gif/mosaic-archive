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

## What v0.7 does

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
- provides `inspect` to authenticate, decode, hash-check, and explain an archive.
- generates a deterministic, SHA-256-verified public benchmark corpus spanning
  text, structured records, numeric data, duplicates, random bytes,
  precompressed bytes, and empty inputs;
- runs the complete test suite across Python 3.11 and 3.13 on Linux, Windows,
  and macOS, with separate lint, type, coverage, dependency-audit, and build
  gates;
- records a scheduled benchmark artifact each month so performance changes can
  be compared against an identical generated corpus.

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
uv run msc decode project.msc restored-project
uv run msc benchmark project-folder --compare
uv run msc benchmark project-folder --profile research
uv run python -m mosaic_archive.corpus benchmark-corpus
uv run msc benchmark benchmark-corpus --json
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

The binary layout is documented in [docs/FORMAT.md](docs/FORMAT.md), and the
security boundaries are explicit in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

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
- format compatibility is not promised until a future stable release.

The near-term roadmap is in
[plans/mosaic-archive-roadmap.md](plans/mosaic-archive-roadmap.md).
