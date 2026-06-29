# Mosaic Archive construction roadmap

Objective: deliver a general-purpose adaptive encrypted archive format for
arbitrary files and folders, prioritizing correctness, security, portability,
transparent measurements, and stable decoding before compression novelty.

## Invariants for every milestone

1. Compression remains lossless and block decisions remain file-agnostic.
2. Experimental codecs never replace standard password KDF and AEAD security.
3. Authentication and restoration-hash failures never publish partial output.
4. Every format change has parser limits, round-trip tests, corruption tests,
   and a written compatibility decision.
5. Benchmarks report losses as plainly as wins and separate compression,
   padding, encryption, and container overhead.

## Dependency graph

```text
A: single-file MSC1
  -> B: folder manifest + streaming frames
      -> C: content-defined chunks + cross-file dedup
          -> D: entropy coding + trained routing experiments
              -> E: stable MSC 1.0 specification and releases
```

## A — MSC v0.1 single-file alpha

Status: implemented in this workspace.

Context: establish the smallest trustworthy end-to-end archive before adding
folder semantics or advanced entropy coding.

Deliverables:

- RAW, RLE, DELTA8+RLE, and LZ_SIMPLE block plugins;
- exact-size best-mode selection over fixed 64 KiB blocks;
- encrypted filename, size, block table, and SHA-256 restoration digest;
- scrypt plus ChaCha20-Poly1305 with authenticated public header;
- random 4 KiB bucket padding, atomic writes, inspect, and benchmark commands;
- file-format specification, threat model, CLI docs, and automated tests.

Verification:

```console
uv run python -m unittest discover -s tests -v
uv run ruff check .
uv run mypy src
uv build
```

Exit criteria: all checks pass; text, smooth bytes, repetitive bytes, random
bytes, empty files, wrong passwords, and modified archives have explicit tests.

Rollback: because no stable release predates MSC1, revert the alpha as one unit
if its authenticated-container design changes materially.

## B — MSC v0.2 folders and bounded-memory I/O

Dependencies: A.

Status: core milestone implemented. MSC2 now provides encrypted folder
manifests, independently authenticated padded frames, bounded-memory file-data
I/O, safe portable path rules, atomic tree publication, progress events,
legacy-MSC1 decoding, and optional ZIP/gzip/zstd/7-Zip benchmark adapters.

Context: the current whole-archive AEAD operation is easy to reason about but
buffers too much data. Folder support also needs safe relative-path metadata.

Tasks:

- [x] design authenticated independently numbered frames and nonce derivation;
- [x] add an encrypted folder manifest with normalized relative paths, file types,
  permissions policy, modification times, and collision rules;
- [x] reject absolute paths, `..`, links by default, and platform-unsafe names;
- [x] stream encoding and restoration with configurable memory limits;
- [x] add progress events and structured error categories;
- [x] compare against gzip, zip, zstd, and 7z when installed.

Exit criteria: multi-gigabyte sparse/test files operate under a documented
memory ceiling; path-traversal and interrupted-write tests pass on Windows,
Linux, and macOS.

Rollback: retain MSC1 single-file decoding and gate folder archives behind a new
format version or profile ID.

## C — MSC v0.3 content-defined chunks and deduplication

Dependencies: B.

Status: implemented. MSC3 uses deterministic rolling Buzhash boundaries,
SHA-256 chunk identities, direct backward dedup references, unique-chunk data
frames, disk-backed bounded-memory restoration, and separate logical/unique/
cross-file savings metrics.

Context: repeated files and shifted versions can produce larger practical wins
than a more complex local codec.

Tasks:

- [x] evaluate rolling content-defined boundaries with min/average/max limits;
- [x] use cryptographic chunk identifiers inside the authenticated manifest;
- [x] add backward-only dedup references with cycle/impossible-reference rejection;
- [x] measure dedup savings separately from codec savings;
- [x] add streaming inspect with per-chunk and per-file verification.

Exit criteria: inserted-prefix versions recover chunk alignment; adversarial
chunk graphs cannot loop, escape limits, or cause unbounded expansion.

Rollback: retain fixed-size chunk profile as the portable baseline.

## D — entropy coding and model routing research

Dependencies: A for isolated experiments, C for the integrated archive.

Status: in progress. MSC4 added normalized byte-histogram rANS. MSC5 adds a
bounded C-backed DEFLATE baseline and a rule-based feature router that skips the
quadratic teaching LZ path while preserving exact-size final selection.
MSC6 adds separately entropy-coded LZ token/literal/length/distance streams and
explicit fast/balanced/research profiles. Current source-corpus evidence keeps
LZ_RANS research-only because it did not beat DEFLATE and doubled encode time.
Package v0.7 adds a deterministic, self-verifying general-purpose corpus,
cross-platform CI, coverage and dependency-audit gates, and scheduled benchmark
artifacts. The archive format remains MSC6 because these changes do not alter
the decoder contract. Package v0.8 adds permanent decoder fixtures for every
claimed archive generation from MSC1 through MSC6, making compatibility
regressions visible in normal test runs.

Parallel research tracks:

- canonical rANS for delta and literal/token streams;
- better LZ parsing and separate literal/length/distance streams;
- byte-context and structured-text residual models;
- a classifier that predicts which modes are worth attempting from cheap block
  features, while final selection remains based on actual encoded size.

Exit criteria: each mode beats its own header/CPU cost on a published corpus,
has standalone property/fuzz tests, and can be disabled without affecting other
mode decoders.

Rollback: mode IDs are additive; encoders can stop emitting a weak mode while
decoders retain compatibility.

## E — MSC 1.0 stable release

Dependencies: B and C; selected D work only when proven.

Status: foundation started. The public corpus, cross-platform automation, and
permanent MSC1-through-MSC6 decoder fixtures are in place; sustained fuzzing,
soak tests, independent review, and signed binaries remain.

Tasks:

- freeze a versioned format and compatibility policy;
- complete parser fuzzing, large-file soak tests, and independent security
  review;
- [x] publish a reproducible generated corpus and scheduled benchmark workflow;
- [x] commit permanent backward-compatibility fixtures for every claimed decoder
  version;
- publish versioned benchmark results and comparisons with mature compressors;
- ship signed cross-platform binaries and an upgrade/deprecation policy.

Exit criteria: backward-compatibility fixtures are permanent, threat-model
findings are resolved or documented, and no benchmark claim depends on a
private corpus.

Rollback: experimental profiles stay opt-in and outside the stable baseline.

## Plan mutation protocol

New codec ideas enter as D-track experiments; they do not block B or C. Split a
milestone when its format decision and implementation cannot be reviewed
together. Insert urgent security work before all dependents. Skipped work must
state which invariant remains satisfied. Any incompatible change before 1.0
increments the on-disk version and retains fixtures for every decoder version
the project still claims to support.
