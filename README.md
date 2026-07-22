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

The exact publication state, evidence, limitations, and active development
focus are tracked in [PROJECT_STATUS.md](PROJECT_STATUS.md).
The scoped 1.0 performance target is preregistered in
[Competitive Contract v1](docs/COMPETITIVE_CONTRACT_V1.md), and the additive
format/compatibility direction is recorded in
[the MSC7 decision](docs/MSC7_DECISION.md). Neither document claims that the
current Python implementation already meets that target.

## What v0.39 does

- accepts an arbitrary file or folder and produces an encrypted `.msc` archive;
- finds stable content-defined boundaries with a deterministic Gear hash;
- stores each unique chunk once and uses direct authenticated backward
  references for repeated chunks across files and shifted versions;
- adds a normalized byte-histogram rANS entropy mode for skewed symbol streams;
- adds a fast C-backed DEFLATE baseline and a feature router that avoids the
  quadratic teaching LZ mode in normal encoding;
- adds an experimental LZ parser with separately rANS-coded token, literal,
  length, and distance streams;
- provides `fast`, `balanced`, and `research` codec-search profiles;
- provides seven lossless modes and routes cheap candidates by measured block
  features, with exhaustive mode search available through the research profile;
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
- runs a bounded 10,000-case fuzz campaign with a streaming 256 MiB
  pull-request soak, a weekly 1,025 MiB tier crossing 1 GiB, and a monthly
  2,049 MiB tier crossing signed 32-bit offsets;
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
  keyless Sigstore/SLSA provenance plus SHA-256 checksums to tagged releases;
- builds deterministic source-review bundles from exact Git objects, hashes
  every tracked payload, and binds the reviewed source bundle into release
  checksums and provenance;
- publishes repeated-run medians, raw timing samples, dispersion, and
  per-category size comparisons on a 78-file, 13-category deterministic corpus.

## Install

Install a tagged source checkout with `pip`:

```console
python -m pip install .
msc --version
```

Tagged releases also build smoke-tested single-file executables for Linux,
Windows, and macOS. Check their SHA-256 manifest and GitHub build provenance as
described in [docs/RELEASES.md](docs/RELEASES.md).

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
uv run msc readiness --json
```

The ordinary readiness report is 7/10 by design. Seven repository-verifiable
gates are complete; independent review, Competitive Contract v1 dominance,
and the first independently verified attested release remain external. The new
tenth gate changes the checklist denominator from nine to ten; 70% is not a
quality regression or a statistical estimate of engineering completion.

Schema-v3 annotated-tag evidence can bind the reviewed source and immutable
attested candidate, but it cannot complete the competitive gate or authorize a
stable 1.0 release. A future schema-v4 flow must additionally bind an exact
native binary, locked corpus manifest, raw scorecard, benchmark environment,
and recomputed passing verdict. Until then, `--require-ready` intentionally
fails while the seven-gate pre-1.0 release policy remains available.

Exact-commit local evidence for the 1,025 MiB tier is committed at
`.ecc/benchmarks/msc-v0.40-1025mib-soak-windows.json`. Exact protected-main
hosted evidence for the 2,049 MiB tier is committed at
`.ecc/benchmarks/msc-v0.40-2049mib-soak-ubuntu.json`. The hosted run processed
2,148,532,224 source bytes, produced a 2,152,567,212-byte MSC6 archive, crossed
signed 32-bit offsets, and restored the source SHA-256 exactly.

Decode and inspect accept caller-defined resource ceilings:

```console
uv run msc decode archive.msc restored \
  --max-output-size 1073741824 --max-frame-count 100000
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

Coverage is branch-aware across the entire `mosaic_archive` package; no source
modules are excluded from the 80% gate, and reports retain two decimal places
so incremental improvements remain visible.

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
Changes are recorded in [CHANGELOG.md](CHANGELOG.md), contribution checks in
[CONTRIBUTING.md](CONTRIBUTING.md), and private vulnerability-reporting
guidance in [SECURITY.md](SECURITY.md).

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

The v0.25 router replaces per-chunk standard-versus-delta trial compression
with entropy and distance-4 residual features. It preserves the public
corpus's lane assignments and exact 276,115-byte archive while reducing hosted
encode time from 1.757 to 1.694 seconds (3.6%). Together, v0.24 and v0.25
improve hosted encode time by 10.3%; hashing, scanning, and LZMA itself remain.

The v0.26 encoder fuses dedup-manifest construction with unique-chunk lane
spooling. Each file now crosses the content-defined chunker once instead of
twice, while the earlier whole-file hash pass continues to detect input
changes. The public archive remains exactly 276,115 bytes and hosted encode
time falls from 1.694 to 1.082 seconds (36.1%). The cumulative hosted
improvement since v0.23 is 42.7%; feature analysis now dominates the Python
side of the remaining encode work.

The v0.27 router computes only the byte entropy needed for its first decision
instead of invoking the general-purpose block analyzer and discarding six
unrelated feature families. Distance-4 entropy remains conditional, so chunks
that already classify as standard or high-entropy avoid it. Hosted encode time
falls from 1.082 to 0.940 seconds (13.2%) with the same 276,115-byte archive.
Together, v0.24 through v0.27 cut the v0.23 hosted encode time by 50.3%.

The v0.28 chunker inlines its fixed one-bit Buzhash rotation and replaces the
outgoing byte's redundant 64-bit rotation with the identical table value. It
also tracks chunk length locally and advances the 64-slot ring with a mask.
Chunk boundaries and the 276,115-byte public archive remain unchanged, while
hosted encode time falls from 0.940 to 0.700 seconds (25.5%). The cumulative
hosted improvement since v0.23 is 62.9%.

The v0.29 chunker defers Buzhash initialization until the first legal content
boundary. Since the rolling value depends only on the latest 64-byte window,
hashing earlier bytes cannot affect any observable boundary decision. Exact
chunk boundaries and the 276,115-byte archive remain unchanged, while hosted
encode time falls from 0.700 to 0.592 seconds (15.5%). The cumulative hosted
improvement since v0.23 is 68.7%.

The v0.30 metadata representation removes repeated fields from duplicate chunk
records, derives file and lane sizes, packs lane IDs into two bits, and uses
bounded canonical integers. Compact manifests are revalidated through the
existing hardened manifest parser, while legacy fixed-width MSR2 metadata
remains readable. Deterministic corpus timestamps make archived metadata
reproducible across platforms. The hosted archive falls from 276,115 to
275,859 bytes; encode time measured 0.607 instead of 0.592 seconds, so this is
a 256-byte size win with a small 2.5% measured speed cost.

The v0.31 chunker extends its chunk buffer once per 64 KiB input block instead
of appending every byte individually. It retains direct byte iteration, emits
completed chunks through one-copy views, and compacts consumed storage once
per block. Exact chunk boundaries and the 275,859-byte archive remain
unchanged, while the median of five hosted Linux runs falls from 0.618 to
0.588 seconds (4.9%). The cumulative hosted encode improvement since v0.23 is
68.9%.

The v0.32 chunker replaces the rolling Buzhash boundary signal with a
deterministic Gear hash requiring one table lookup per legal boundary probe.
Minimum, average, and maximum chunk bounds and insertion-shift recovery remain
covered by tests. Five contemporaneous hosted Linux runs per revision show
median encode time falling from 0.618 to 0.437 seconds (29.2%). The archive
remains 275,859 bytes, while maximum frame payload improves by 8 bytes. The
cumulative hosted encode improvement since v0.23 is 76.8%.

The v0.33 release-hardening pass applies one caller-overridable decode resource
policy to MSC1 through MSC6 and MSR2. It caps restored bytes and frame/block
counts before destination creation, bounds whole-buffer legacy MSC1 archives
before ciphertext allocation, removes an unbounded MSR2 metadata-decompressor
flush, and prevents MSC1 inspection from retaining restored bytes. The v0.33
`msc readiness --json` command introduced nine committed 1.0 roadmap gates.
Competitive Contract v1 now adds a tenth external gate; seven are complete,
while independent review, single-profile competitive dominance, and the first
attested release remain.

The v0.34 review-evidence pass builds a byte-reproducible source ZIP from an
exact Git commit, verifies every tracked payload against its embedded manifest,
and attaches that source bundle to tagged-release checksums and provenance.
The readiness evaluator requires structured external evidence and refuses an
attested release built from a commit different from the reviewed one. Stable
publication now seals that evidence into an annotated tag and also requires the
reviewed commit, candidate-attestation commit, tag target, workflow SHA, and
checked-out source to be identical before any native build starts.

The v0.35 evidence pass replaces the single-run benchmark with schema-v2
median reporting and expands the deterministic corpus from seven to thirteen
workload categories. On the committed local Windows run, encrypted and padded
MSR2 produces a 293,523-byte archive from 1,719,961 benchmark input bytes. It
beats ZIP by 540,213 bytes overall and is smaller in ten of thirteen meaningful
nonempty categories. It loses by 269 bytes on precompressed data and 345 bytes
on random data; its 325-byte empty archive is 107 bytes larger than ZIP. The
five-run median encode time is 0.441192 seconds with 0.011131-second median
absolute deviation. Local 7-Zip and zstd were unavailable, so their v0.35
comparisons remain pending the hosted workflow.

The v0.38 Gear chunker caps each scan at the mandatory maximum chunk boundary,
removing a counter update and maximum-size comparison from every eligible byte.
Eleven alternating independent Windows processes per revision improve expanded
corpus-v2 median encode time by 3.748490%; corpus v1 remains effectively flat
at +0.206949%. Chunk counts, maximum frame payloads, and the 275,859-byte and
293,523-byte archives are unchanged.

The v0.39 solid lanes separate LZMA encoder search parameters from the decoder
filter chain. The standard lane bounds match search at nice length 48 and depth
12, while the delta lane drops to the faster LZMA2 preset 5. Both lanes keep
declaring the preset-6 8 MiB LZMA2 dictionary property byte, so the
unchanged v0.38 decoder still restores every candidate archive. Eleven
alternating independent Windows processes per revision shrink expanded corpus-v2
from 293,523 to 291,731 bytes (1,792 bytes) while improving median encode time
by 6.727759% on corpus v1 and 2.986441% on corpus v2. Chunk counts and maximum
frame payloads are unchanged.

The unreleased bounded-delta router keeps exact analysis for small chunks and
uses 15 deterministic, region-stratified windows for larger chunks, with
conservative exact fallbacks when the sample is ambiguous or heterogeneous.
Eleven alternating independent Windows processes per revision improve median
encode time by 10.304818% on locked corpus v1 and 10.873414% on locked corpus
v2. Route-sequence hashes, lane distributions, archive bytes, chunk counts,
maximum frame payloads, and authenticated round trips remain unchanged on both
corpora. These measurements are corpus-specific rather than a claim of
universal route equivalence or compressor superiority.

The unreleased identity-bound one-pass encoder captures each root, directory,
and file accepted during traversal, validates ancestor paths and the exact
opened handle around every read, and performs a complete topology rescan before
atomic publication. Consolidating manifest hashing and chunk discovery reduces
physical source opens from three to two per file for MSC6, from three to one
for MSR1, and from two to one for MSR2. Thirty-three alternating independent
Windows processes per revision show corpus v1 effectively flat at 0.295302%
slower; corpus v2 improves by 6.972763%. The 275,859-byte and 291,731-byte
archives, unique-chunk counts, maximum frame payloads, and authenticated round
trips are unchanged.

Fast and research MSC6 routing now skips the general feature analysis that
their fixed candidate sets never consumed; the encoder's separate public
statistics pass remains intact. Eleven alternating fresh Windows processes per
revision improve median fast-profile encode time from 0.464328 to 0.339373
seconds on corpus v1 (26.910926%) and from 0.760783 to 0.547597 seconds on
corpus v2 (28.022006%). Both archives remain exactly 493,005 and 632,681 bytes,
with identical mode distributions, feature statistics, chunk counts, and
verified round trips. These small-corpus timings demonstrate removed work, not
universal throughput or compressor superiority.

The v0.37 Gear chunker skips the subminimum prefix where a content boundary
cannot legally occur. Eleven contemporaneous Windows runs per revision improve
median encode time by 3.557517% on corpus v1 and 7.923612% on corpus v2. Chunk
boundaries, the 275,859-byte and 293,523-byte archives, and maximum frame
payloads are unchanged.

The v0.36 high-entropy router recognizes a pattern hidden by per-chunk entropy:
some apparently random lanes contain distant exact reuse, while genuinely
random or precompressed lanes do not. A bounded 64-byte reuse probe preserves
LZMA for the former and writes the latter through authenticated raw frames.
Eleven contemporaneous runs per revision improve median random encode time by
26.514452% and precompressed encode time by 24.328667%. Both retain the same
131,679-byte encrypted and padded archive, and the distant-reuse corpus retains
its 275,859-byte result. MC21 and fixed-width MSR2 metadata remain readable.

## Current limits

- v0.3 deduplicates within one archive, but does not yet reuse chunks across
  separate archive generations;
- file data is bounded by the configured chunk size, but the encrypted manifest
  still scales in memory with the number and length of archived paths;
- links, junctions/reparse points, device nodes, sockets, and FIFOs are rejected;
- encoders bind discovered source identities through every read and a final
  topology rescan, but portable path lookup/open/publication operations are not
  one indivisible transaction against a hostile local process; replacement
  after an object's final check, a transient rebind, or a same-object,
  same-size write that restores timestamps is outside the
  uncompromised-local-machine threat assumption;
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
