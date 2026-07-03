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
regressions visible in normal test runs. Package v0.9 adds a deterministic
11-target parser/decoder mutation harness plus a bounded weekly 256 MiB
streaming soak round trip. Package v0.10 expands that surface to both nested
manifest parsers and adds seeded Atheris coverage-guided campaigns.
Package v0.11 freezes MSC6 for the 1.0 writer, makes MSC1-through-MSC6 decoder
support binding for the 1.x line, and publishes upgrade/deprecation rules.
Package v0.12 publishes a versioned, verified Linux benchmark against ZIP,
gzip, zstd, and 7-Zip using the deterministic public corpus.
Package v0.13 adds smoke-tested native Linux, Windows, and macOS release
executables, SHA-256 manifests, and keyless Sigstore/SLSA provenance. The first
signed assets publish when a reviewed v0.13 tag is created.
Package v0.14 prototypes file-agnostic solid compression lanes over the unique
chunk stream. Its verified 274,400-byte research payload leaves a conservative
16 KiB integration budget and projects 2,047 bytes below the committed 7-Zip
result. This is evidence for an experimental next format, not yet an end-to-end
archive claim.
Package v0.15 integrates those lanes into a separate encrypted and padded MSR1
research container. The actual 277,585-byte archive round-trips the public
corpus and is 15,246 bytes smaller than the committed 7-Zip result. MSR1 is not
yet the stable writer because its whole-archive solid stream trades bounded
memory and random access for ratio.
Package v0.16 replaces the extreme LZMA preset with the bounded default preset
while preserving the exact 277,585-byte final archive on the public corpus.
Local encode time falls from 2.29 seconds to 1.17 seconds. Whole-archive
buffering still blocks promotion; MSR2-style independently authenticated
compressed frames are next.
Package v0.17 implements and verifies that framed-stream primitive. Each lane
keeps continuous LZMA history while emitting bounded, independently numbered
ChaCha20-Poly1305 frames. The public-corpus component measurement adds 2,246
bytes over the raw compressed lanes and leaves a projected 13,000-byte margin
against 7-Zip. Full MSR2 container integration remains the next milestone.
Package v0.18 integrates the primitive into the disk-backed MSR2 container.
The actual encrypted, padded 279,699-byte public-corpus archive round-trips and
beats 7-Zip by 13,132 bytes without buffering the whole solid payload or
ciphertext. Parser hardening and broader-corpus validation are next.
Package v0.19 bounds restored bytes and frame counts before extraction, avoids
destination-side effects until authentication succeeds, and adds the MSR2
header to both mutation harnesses. Empty lanes no longer cost padded frames.
The category suite records strong structured/numeric/dedup wins and honest
small-text/random/precompressed losses; model and overhead routing are next.
Package v0.20 compresses the authenticated metadata envelope and removes XZ
wrapper overhead from new solid lanes, while retaining legacy MSR2 metadata
decoding. Its explicit 256-byte compact-padding result is 276,115 bytes on the
mixed corpus and now beats ZIP on the text subset. Random/precompressed data
still exposes the small unavoidable authenticated-container overhead.
Package v0.21 exposes MSR2 as the explicit `msc encode --format solid` option
and auto-detects it for authenticated inspect and decode. Stable MSC6 remains
the default writer; compact 256-byte padding remains an explicit privacy/ratio
choice.
Package v0.22 adds format-aware `msc benchmark --format solid` reports with
round-trip verification, frame bounds, memory/speed measurements, and optional
ZIP/gzip/zstd/7-Zip comparisons. The stable MSC6 benchmark schema remains
unchanged.
Package v0.23 adds an AES-256 and header-encrypted 7-Zip baseline with a fixed
public benchmark password. Hosted evidence records compact MSR2 at 276,115
bytes versus encrypted 7-Zip at 292,912 bytes, while also recording MSR2's
substantially slower encode time. Throughput optimization is next.
Package v0.24 separates continuous lane compression from authenticated framing,
so each lane is compressed exactly once. Archive bytes remain 276,115 while
hosted encode time improves from 1.889 to 1.757 seconds. Trial compression in
the lane router is the next measured throughput target.
Package v0.25 replaces trial compression in the lane router with entropy and
distance-4 residual features. Hosted encode time improves from 1.757 to 1.694
seconds with identical routing and archive bytes on the public corpus. Combined
v0.24/v0.25 improvement is 10.3%; profiling the remaining scan/hash/LZMA work
is next.
Package v0.26 fuses dedup discovery and unique-chunk lane spooling into one
content-defined chunking traversal. The public archive remains 276,115 bytes
while hosted encode time improves from 1.694 to 1.082 seconds. The cumulative
v0.23-to-v0.26 improvement is 42.7%; optimizing feature extraction without
changing lane decisions is the next measured throughput target.
Package v0.27 specializes solid routing to byte entropy plus conditional
distance-4 entropy, avoiding six general block features that cannot affect the
lane decision. Hosted encode time improves from 1.082 to 0.940 seconds with
the same 276,115-byte archive. The cumulative v0.23-to-v0.27 improvement is
50.3%; the rolling chunker and remaining Python delta pass are the next
throughput candidates.
Package v0.28 algebraically simplifies the 64-byte rolling Buzhash hot loop.
The public corpus retains identical chunk boundaries and its 276,115-byte
archive while hosted encode time improves from 0.940 to 0.700 seconds. The
cumulative v0.23-to-v0.28 improvement is 62.9%; independent security review
is now the principal stable-release gate.
Package v0.29 initializes Buzhash from the latest 64-byte window only when a
chunk first reaches its minimum size, eliminating hash work that cannot affect
a boundary. Hosted encode time improves from 0.700 to 0.592 seconds with
identical chunk boundaries and archive size. A larger-chunk size experiment
was rejected because it harmed shifted repetitive-data deduplication.
Package v0.30 compacts authenticated MSR2 metadata without changing chunking or
lane compression. Hosted archive size improves from 276,115 to 275,859 bytes;
legacy metadata remains readable. The hosted run records a small 2.5% encode
cost, reported as plainly as the 256-byte size win. Generated corpus mtimes are
now deterministic so archive-size evidence is reproducible across platforms.
Package v0.31 replaces per-byte chunk-buffer appends with one extend per 64 KiB
input block while preserving direct byte iteration. Hosted Linux encode time
improves from a five-run median of 0.618 to 0.588 seconds with identical chunk
boundaries and the same 275,859-byte archive. This supersedes an earlier
segmented-memoryview experiment whose Linux overhead outweighed its local gain.
Package v0.32 replaces rolling Buzhash with a deterministic one-lookup Gear
boundary signal. Five contemporaneous hosted Linux runs per revision improve
median encode time from 0.618 to 0.437 seconds. The padded archive remains
275,859 bytes, maximum frame payload improves by 8 bytes, and existing
insertion-shift and cross-file dedup recovery tests remain green.
Package v0.33 applies caller-overridable restored-size and frame/block limits
to every decoder, caps whole-buffer MSC1 input before allocation, removes the
unbounded final MSR2 metadata decompressor flush, and adds a machine-readable
nine-gate 1.0 readiness report. The internal review leaves the independent
review and first verified attested release as the two formal open gates.
Package v0.34 makes the external handoff reproducible: a deterministic source
bundle is built from exact Git objects, every tracked payload is hashed in an
embedded manifest, tagged releases bind that bundle into checksums and signed
provenance, and structured gate validation requires the released commit to
match the independently reviewed commit.

Parallel research tracks:

- canonical rANS for delta and literal/token streams;
- better LZ parsing and separate literal/length/distance streams;
- byte-context and structured-text residual models;
- [x] solid second-stage lanes for distant relationships between unique chunks;
- a classifier that predicts which modes are worth attempting from cheap block
  features, while final selection remains based on actual encoded size.

Exit criteria: each mode beats its own header/CPU cost on a published corpus,
has standalone property/fuzz tests, and can be disabled without affecting other
mode decoders.

Rollback: mode IDs are additive; encoders can stop emitting a weak mode while
decoders retain compatibility.

## E — MSC 1.0 stable release

Dependencies: B and C; selected D work only when proven.

Status: release candidate foundation complete (7/9 gates). The public corpus,
cross-platform automation,
permanent MSC1-through-MSC6 decoder fixtures, deterministic sustained mutation
fuzzing, scheduled large-file soak coverage, seeded coverage-guided campaigns,
the frozen compatibility policy, versioned mature-compressor results, and the
cross-platform attested-binary release pipeline are in place; independent
review and the first tagged binary publication remain.

Tasks:

- [x] freeze a versioned format and compatibility policy;
- [x] add deterministic parser fuzzing and scheduled large-file soak tests;
- [x] add seeded coverage-guided parser and decoder fuzzing;
- complete an independent security review;
- [x] publish a reproducible generated corpus and scheduled benchmark workflow;
- [x] commit permanent backward-compatibility fixtures for every claimed decoder
  version;
- [x] publish versioned benchmark results and comparisons with mature compressors;
- [x] publish an upgrade/deprecation policy;
- ship signed cross-platform binaries (pipeline complete; awaits reviewed tag).

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
