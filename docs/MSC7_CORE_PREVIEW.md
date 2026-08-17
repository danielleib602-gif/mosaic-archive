# Native MSC7 compression-core preview

`M7R0` is a laboratory envelope for exercising the native MSC7 compression
pipeline. It is intentionally non-stable, not encrypted, not authenticated,
not binding evidence, and not part of the MSC1–MSC6 compatibility contract.
The stable writer and the default Python CLI remain unchanged.

The separate [authenticated native preview](MSC7_AUTH_PREVIEW.md) now streams
the exact `M7R0` bytes through the non-stable `M7A0` envelope. That addition
does not change `M7R0` bytes or turn this inner envelope into an authenticator.

## Pipeline

- Mosaic Gear v1 CDC with the existing 16/64/256 KiB boundaries and table.
- SHA-256 exact-match deduplication to earlier chunk starts within a bounded
  8 MiB decoded-output window.
- The deterministic solid-research routing concepts: byte entropy at 7.75 for
  high entropy, a 3.0 low-entropy standard threshold, and a 2-bit delta4
  entropy advantage.
- Standard lane: raw LZMA2 preset 3, tuned to a 256 KiB dictionary.
- Delta lane: delta4 followed by zstd level 5.
- High-entropy lane: zstd level 1.
- Exact record-size fallback: compressed and raw candidates both include the
  fixed 16-byte record descriptor; ties use raw.
- Ordered output from a private Rayon pool. The number of workers changes
  throughput, not bytes on the wire.

Input is consumed as a byte stream. At most 8 MiB of decoded records are
assembled in a segment before compression and ordered emission. Decode checks
all declared lengths before allocation, caps segments at 8 MiB, caps records
at 256 KiB, uses constant-time offset lookup, caps retained history at 1,024
records, and enforces caller-configurable total input, output, segment, record,
and expansion ceilings. Default encode/decode limits are mutually compatible
through 8 GiB of decoded data; callers can select lower limits for untrusted
laboratory inputs.

## Laboratory envelope

All integers are little-endian. The 32-byte header contains `M7R0`, its fixed
length, the three CDC sizes, the segment limit, the deduplication window, and a
zero reserved field. Each `SG07` segment contains its sequence number, decoded
size, record-table and payload sizes, and the SHA-256 of the decoded segment.

Each 16-byte record declares data or backward reference, codec, decoded size,
and either payload size or backward decoded-byte distance. Data payloads follow
the complete descriptor table in descriptor order. `END7` records the segment,
decoded-byte, and record totals plus SHA-256 of the complete decoded stream.
Any unsupported field, nonzero reserved bit, inconsistent total, truncation,
out-of-window reference, digest mismatch, or trailing byte is rejected.

The SHA-256 fields are corruption checks only. An attacker can recompute them.

## CLI

```text
mosaic-msc7-lab encode [--threads N] [--max-input-bytes N] [INPUT|-] [OUTPUT|-]
mosaic-msc7-lab decode [LIMIT OPTIONS] [INPUT|-] [OUTPUT|-]
mosaic-msc7-lab inspect [LIMIT OPTIONS] [INPUT|-]
mosaic-msc7-lab benchmark [--threads N] [INPUT|-]
```

`encode` and `decode` accept files or standard streams. `inspect` performs a
full bounded decode to a sink so its report is not based on unverified
metadata. `benchmark` is a convenience command and intentionally loads its
input and encoded result in memory; use direct encode/decode commands for
bounded-memory process measurements. File outputs are written to a sibling
temporary file, flushed and synchronized, and atomically published only after
the complete operation succeeds. Exact-path, symlink, hardlink, and redirected
standard-input aliases are rejected before publication.

Decode limit options are `--max-output-bytes`, `--max-encoded-bytes`,
`--max-segments`, `--max-records`, and `--max-expansion-ratio`.

## Current diagnostic

At implementation commit `c50698e1f8bbf7f482fad31e117783443ef0daa4`, a
deterministic 64 MiB standard-lane input encodes to 5,145,673 bytes (ratio
0.0766765). Three in-memory runs per tier produce median encode throughput of
42.049 MiB/s with one worker and 145.347 MiB/s with eight; median decode
throughput across the six runs is 184.374 MiB/s. Both thread tiers emit the
same archive SHA-256, and the restored input hash matches exactly. This
convenience-command result excludes disk publication time and is not binding
competitive evidence. Raw timings and hashes are in
`.ecc/benchmarks/msc-v0.41-low-bit-zstd-native-core.json`.

## Deliberate gaps

`M7R0` itself has no AEAD framing or KDF. `M7A0` supplies a non-stable
authenticated outer composition and now has a path-only private ABI3 Python
binding. Neither preview has file-tree metadata, stable codec identifiers,
permanent compatibility fixtures, binding cross-platform attestation, or a
release claim. Those belong to the later MSC7 format-freeze and qualification
work, not this compression-core experiment.
