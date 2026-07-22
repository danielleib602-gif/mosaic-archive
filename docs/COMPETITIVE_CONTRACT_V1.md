# Competitive Contract v1

Status: preregistered target; no passing Mosaic candidate exists yet.

This contract defines the narrow, reproducible meaning of the planned 1.0
performance claim. It supplements the historical v0.x benchmark and does not
rewrite or reinterpret any existing report.

## Candidate and methods

The candidate is the native MSC7 CLI using exactly one public profile,
`adaptive-v1`, and configuration identity `msc7-default-v1`. The four binding
comparators are raw 7-Zip, 7-Zip with AES-256 data and header encryption, raw
zstd, and zstd wrapped with passphrase-encrypted age. ZIP, gzip, xz, Brotli,
and LZ4 are diagnostic and cannot make the gate pass or fail.

Tree inputs use one versioned canonical-tar recipe where a compared tool does
not natively preserve the same tree. End-to-end time includes required input
traversal or tar construction, compression, encryption/KDF work, output I/O,
decode, extraction, and independent restoration verification.

## Corpus and runner lock

Every binding corpus is a real public workload of at least 67,108,864 prepared
bytes. The intended category set is mixed data, Wikipedia text, two related
Linux source trees, structured event JSON, tabular/geospatial text, and a
precompressed media workload. Exact URLs, immutable snapshots, byte lengths,
SHA-256 digests, preparation outputs, licenses, and attribution records must be
locked before any binding scorecard runs. Sources with ambiguous permission or
mutable-only downloads are replaced rather than silently approved.

Binding performance uses a hardware-fingerprinted Linux x86-64 host with at
least eight CPUs in its allowed affinity. Hosted Linux, Windows, and macOS
runs remain valuable functional and diagnostic evidence, but a runner that
cannot enforce both equal 1-thread and equal 8-thread lanes cannot satisfy the
gate. The machine contract requires pre-exec placement in a fresh cgroup-v2 and
PID namespace, exact cpuset plus tool-thread enforcement, and cgroup memory-peak
collection after the group reports no populated processes.

The current `competitive_runner` module is provisional diagnostic scaffolding,
not that binding runner. Its sampled `/proc` telemetry can miss between-sample
descendants and RSS peaks; it does not yet provide inherited cgroup-v2/PID
containment, exact cpuset and tool-thread enforcement, kernel `memory.peak`, a
fixed non-tunable measurement policy, complete descendant executable identity,
or canonical environment/configuration retention. It is not a sandbox, must run
only trusted binaries inside a disposable externally constrained host, and its
outputs must never feed schema-v4 evidence or complete the readiness gate.
Promotion requires pre-exec containment, resource/output limits, full cleanup,
and signed raw per-run evidence satisfying every requirement above.

## Sampling and metrics

Each corpus/tool/thread cell runs one warmup and eleven measured fresh
processes. The warmup order is `candidate` followed by the four binding tools
in contract order. Measured indices are zero-based. Even indices run `candidate`, `7zip_raw`,
`7zip_aes256_headers`, `zstd_raw`, then `zstd_age_passphrase`; odd indices run
that exact order in reverse. The candidate sample at index `i` is shared only
with each comparator sample at the same index. The two binding thread tiers are
1 and 8.

The four performance metrics are encode wall time, decode wall time, encode
cgroup-v2 memory peak, and decode cgroup-v2 memory peak. Each memory value is
the byte count read from a fresh dedicated cgroup's kernel `memory.peak` only
after `cgroup.events` reports `populated 0`; hosts without that controller and
file are ineligible. It includes the memory charged by cgroup v2 and does not
claim separate swap-peak accounting or process-tree RSS. Wall times must be
positive finite numbers. Memory byte counts must be positive non-boolean
integers no larger than `2^63 - 1`. Every raw sample, command, environment,
executable digest, archive digest, payload hash, process identity, hardware
fact, and round-trip result is retained.

Before every lane, immutable inputs are fully read and verified outside the
measured cgroup so first-reader page-cache charging cannot choose the winner.
Output page cache created by the tool remains intentionally included in
`memory.peak`; the exact prewarm completion and hashes are retained as raw
evidence.

For each performance metric and every binding comparator, paired run index `i`
uses `mosaic[i] / comparator[i]`; its point estimate is the median of those
eleven paired ratios. Every comparator must have a percentile-bootstrap 95%
confidence interval whose upper bound is strictly less than 1.0. The versioned
statistic uses 10,000 deterministic resamples and Type-7 percentile
interpolation. Equality or any confidence interval touching 1.0 fails the case.
The lowest standalone comparator median is recorded only as a diagnostic and
cannot make the case pass.

## Evidence identity and portable resampling

Every case identity binds the exact canonical contract digest, locked corpus
manifest digest, canonical corpus ID, prepared-input digest and byte length,
thread tier, and metric. `case_id` is derived from that identity and cannot be
chosen by the report producer. Comparator identity is added before deriving its
resampling stream. This prevents aliases from selecting a different stream or
transferring measurements between inputs, contracts, tiers, metrics, or tools.

The v1 stream is defined only in terms of SHA-256, U32BE length-prefixed UTF-8
identity fields, an appended U64BE counter starting at zero, and unbiased U64BE
rejection sampling. It does not use Python's or another runtime's pseudorandom
generator. The exact domains, field order, canonical-contract digest, rejection
rule, and published vector are recorded beside `contract.json` in
`benchmarks/competitive-v1/README.md`.

## Size rules

On a compressible workload, the deterministic Mosaic archive must be strictly
smaller than every binding comparator. An input is eligible for the
incompressible exception only when the best raw comparator produces more than
99% of the input bytes; exactly 99% remains under the normal strict rule.

Under the exception, Mosaic must satisfy both conditions:

1. archive overhead is at most `max(4096, ceil(input_bytes / 2000))` bytes;
2. its archive is no larger than the smallest encrypted binding comparator.

Encrypted randomized archive sizes use the median of the eleven measured
sizes. The validator derives every verdict from raw records and never trusts a
stored `complete` flag or precomputed summary.

## Gate and evidence lifecycle

`competitive_single_profile_dominance` is the tenth readiness gate. It is an
external gate and remains incomplete in the current schema-v3 release flow.
The future schema-v4 tag evidence must bind the candidate commit and tag,
native binary checksum and attestation, contract digest, corpus-manifest
digest, scorecard digest and immutable URL, benchmark workflow identity,
hardware fingerprint, comparator versions/commands, and raw samples.

The readiness validator must read the exact bound report and recompute its
statistics and size outcomes for every comparator. A passing report on a
different commit, binary, manifest, runner class, or command set is not
transferable. The current individual-case evaluator is only a foundation and
does not complete the report or release gate by itself.
