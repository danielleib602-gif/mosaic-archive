# MSC7 additive-format decision

Status: accepted design direction; wire format and implementation are not yet
frozen.

## Context

MSC6 is the current stable writer and its decoder contract is frozen. It is a
portable Python implementation, but the public v0.39 measurements do not meet
the proposed 1.0 competitive contract: the strongest size result is an
experimental MSR2 profile, encode/decode throughput trails mature tools, and
the existing in-process memory measurement is not comparable with a fresh
cgroup-v2 `memory.peak` measurement.

Changing MSC6 mode identifiers or record semantics would invalidate its
compatibility promise. Promoting MSR2 would also preserve architectural costs
that the 1.0 target is intended to remove, including Python hot loops and a
container that was designed as a research vehicle.

## Decision

Mosaic will pursue an additive `MSC7` format instead of changing MSC6 in place.
The implementation direction is:

- a Rust core library for chunking, hashing, routing, codecs, framing, and the
  bounded worker pipeline;
- a native CLI as the binding performance target and a PyO3 wrapper for the
  supported Python API;
- one authenticated streaming content pass with atomic publication, numbered
  AEAD records, backward-only deduplication references, explicit codec IDs, and
  a final authenticated transcript;
- a single public `adaptive-v1` profile whose deterministic, content-only
  router selects a bounded primary codec plus raw fallback;
- preserved scrypt and ChaCha20-Poly1305 security semantics, with new-format
  identities and vectors specified before the wire layout freezes.

Candidate codecs and transforms may be evaluated in development builds, but a
codec receives an MSC7 wire identifier only after it survives the complete
locked development matrix. The initial tournament may include raw, zstd,
Brotli, LZMA2, delta plus zstd, and bitshuffle plus zstd. This list is research
scope, not a promise that every candidate ships.

## Compatibility and rollout

MSC1 through MSC6 decoders remain unchanged. MSC6 remains explicitly writable
through the current `--format stable` path; existing archives never require
conversion. MSC7 is
opt-in throughout the 0.x preview period, and `decode` and `inspect` will use
magic-based autodetection once the new decoder exists.

The package does not switch its default writer to MSC7 merely because an
implementation exists. The switch and the 1.0 release require permanent MSC7
fixtures, cross-platform functional coverage, resource and corruption tests,
an exact candidate-attested competitive scorecard, independent review, and the
attested release gate. Until those conditions hold, MSC6 remains the default
and the project remains pre-1.0.

## Competitive claim boundary

The target is dominance under the versioned Competitive Contract v1, not a
claim that any finite compressor is best for every possible byte string,
machine, tool, or future release. Authenticated archives have unavoidable
headers, nonces, tags, and padding, so the contract contains an explicit
incompressible-input overhead rule.

Binding scorecards are run only after the format, router, thresholds, tool
commands, and corpus manifest are frozen. A failed scorecard creates a new
candidate; it does not permit editing or overwriting the evidence for the
failed one.

## Consequences

- Version 1.0 is delayed until the tenth readiness gate passes.
- The native CLI, rather than Python-wrapper overhead, is the performance and
  cgroup-v2 memory-peak subject of the competitive claim.
- A controlled Linux host with at least eight available CPU threads is needed
  for binding 1-thread and 8-thread measurements. Variable 4-vCPU hosted
  runners are functional/diagnostic only.
- Corpus acquisition must fail closed on missing hashes, mutable sources, or
  unverified license and attribution records. Public downloadability is not a
  license grant.
