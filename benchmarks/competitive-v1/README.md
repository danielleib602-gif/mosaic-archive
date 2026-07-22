# Competitive Contract v1

`contract.json` is the exact machine-readable contract for future MSC7 competitive
evidence. It is a foundation for evaluating individual raw scorecard cases, not a
claim that a complete competitive run already exists.

The candidate is MSC7 with profile `adaptive-v1` and configuration
`msc7-default-v1`. Every eligible corpus input is at least 67,108,864 bytes. Each
case runs at one and eight threads, performs one warmup, then records eleven
measured runs in fresh processes. Warmups use `candidate` followed by contract
tool order. Measured indices are zero-based; even indices use `candidate` followed by the
four binding tools in contract order; odd indices use the exact reverse. One
candidate sample at index `i` pairs only with comparator samples at index `i`.

The four binding tools are `7zip_raw`, `7zip_aes256_headers`, `zstd_raw`, and
`zstd_age_passphrase`. `gzip`, `zip`, `xz`, `brotli`, and `lz4` are diagnostic
only and cannot make a case pass. The binding metrics are encode/decode wall time
and encode/decode cgroup-v2 `memory.peak` bytes from a fresh dedicated cgroup.

## Statistical verdict

For each measured run, form the paired ratio
`candidate_sample[i] / comparator_sample[i]`. The point statistic is the median
of those eleven paired ratios; it is not the ratio of two separately computed
medians. Each bootstrap replicate resamples the eleven paired indices with
replacement and takes the median paired ratio.

The evaluator performs 10,000 deterministic resamples for every binding
comparator. The 95% percentile interval uses Type-7 linear interpolation. A
metric case passes only when every binding comparator's upper confidence bound
is strictly less than 1.0. Equality or a bound touching 1.0 fails. The comparator
with the lowest standalone metric median, with comparator-ID tie breaking, is
retained as a diagnostic only and cannot determine the verdict.

Wall-time samples are positive finite JSON numbers. Cgroup memory-peak samples
are positive, non-boolean integers no larger than `2^63 - 1`; fractional byte
values are invalid. `memory.peak` is read only after the cgroup is unpopulated;
it is not mislabeled as process-tree RSS or separate swap-peak accounting.
Inputs are fully prewarmed and hash-verified outside every measured cgroup;
output page cache remains intentionally included.

## Canonical identity and resampling stream

The exact contract digest is
`5f76317e4e03c2b4a5e5c9414e08edd7fd64d53e35afb3681cd6ba93e93b3d6d`.
It is SHA-256 over UTF-8 JSON serialized with recursively sorted keys, no ASCII
escaping, and compact `,`/`:` separators (`sha256_canonical_json_v1`). This
canonical form makes the digest independent of checkout line endings and source
indentation.

Identity fields are UTF-8 encoded in this fixed order: contract digest, corpus
manifest digest, canonical corpus ID, prepared-input digest, decimal input byte
length, decimal thread count, and metric ID. The domain and then every field are
encoded as `U32BE(byte_length) || bytes`. The case-ID domain is
`mosaic-competitive-case-id-v1`; the displayed ID is `msc-case-v1-` followed by
the SHA-256 hex digest of that encoded identity. A submitted ID must equal this
derived value. Corpus IDs are lowercase canonical identifiers of at most 128
UTF-8 bytes, so aliases, whitespace, control characters, and oversized IDs fail.

For each comparator, the bootstrap material uses domain
`mosaic-competitive-bootstrap-stream-v1`, the same ordered identity fields, and
the comparator ID as one additional length-prefixed field. For counter values
starting at zero, a stream block is
`SHA-256(material || U64BE(counter))`; each block is split into four U64BE words.
To select one of eleven paired indices, let
`limit = 2^64 - (2^64 mod 11)`, discard words at least `limit`, and use
`word mod 11`. This rejection rule is unbiased and independent of a language's
standard random-number generator.

Published vector: with a manifest digest of 64 ASCII `1` characters, an input
digest of 64 ASCII `2` characters, corpus ID `enwik8-text`, input size
`67108864`, thread `1`, metric
`encode_wall_seconds`, and comparator `7zip_raw`, the case ID is
`msc-case-v1-57a983a3a9a137ae86248d400b9c4a645c643c8079a793b0a07d22879b3fd30d`.
The first sixteen resampled indices are
`10, 9, 3, 9, 2, 9, 8, 8, 6, 0, 7, 6, 9, 7, 10, 8`.

## Size verdict

Raw comparator sizes are deterministic archive byte counts. Each encrypted
comparator contributes the median of exactly eleven archive byte counts. The
smallest representative comparator is used for the ordinary size rule.

An input is incompressible only when the best raw comparator is strictly greater
than 99% of the input size. Exactly 99% is therefore still compressible. On a
compressible input, the candidate must be strictly smaller than the smallest
binding comparator.

For an incompressible input, the allowed expansion is
`max(4096, ceil(input_bytes / 2000))`. The exception passes only if the candidate
is no larger than both `input_bytes + allowance` and the smallest encrypted
comparator. Both incompressible bounds are inclusive.

## Strict loading and synthetic cases

`mosaic_archive.competitive_contract.load_competitive_contract` reads no more
than 64 KiB plus one detection byte, requires UTF-8 JSON, rejects duplicate keys
and `NaN`/infinities, and validates exact keys, exact values, and exact JSON
types. In particular, booleans are never accepted as integers.

`evaluate_scorecard_case` accepts exactly these raw fields:

- derived `case_id`, exact `contract_sha256`, `corpus_manifest_sha256`,
  canonical `corpus_id`, and prepared `input_sha256`
- `thread_count` and `metric`
- `input_bytes` and `candidate_archive_bytes`
- eleven `candidate_samples`
- `comparator_samples`, keyed by every binding comparator with eleven samples
- deterministic `raw_comparator_archive_bytes`
- `encrypted_comparator_archive_bytes`, with eleven sizes per encrypted tool

Claimed medians, confidence intervals, selected comparators, or pass booleans are
not accepted. The evaluator recomputes every summary, all four comparator metric
verdicts, and the size verdict from the raw values. This API evaluates one case;
it does not claim that a corpus matrix or the release gate is complete.

## Runner implementation status

`mosaic_archive.competitive_runner` is provisional diagnostic scaffolding only.
Its `/proc` process-group sampler cannot prove containment, enforce the 1/8 CPU
and tool-thread lanes, or retain every configuration and descendant executable
identity required above. Results are marked `evidence_class="diagnostic"` and
`binding_eligible=false`; they must never be submitted as schema-v4 evidence.
An authoritative runner still requires inherited cgroup-v2/PID containment,
kernel peak-memory accounting, fixed resource/output limits and policy, exact
cpusets, sanitized public environment retention, and complete cleanup on a
disposable constrained host.

## Corpus lock status

`corpus-plan.json` is deliberately non-binding. It lists the six intended
workload categories and the immutable-source, digest, license, attribution, and
preparation work still required. Only a future validated `corpora.lock.json`
may identify inputs for a candidate scorecard; draft plan entries can never
complete the competitive readiness gate.

The singular `source` and `license` records in that future lock represent one
separately reviewed, immutable aggregate bundle per corpus. When a workload is
assembled from multiple upstream archives or differently licensed media, its
bundle must include a content-addressed member manifest and bundle-wide license
evidence covering every member; a live upstream alias or undocumented member is
not eligible.
