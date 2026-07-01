# Published benchmarks

Each versioned directory contains the exact JSON and Markdown report produced
by the pinned GitHub Actions workflow for that package release.

| Release | Corpus | Platform | Report |
|---|---|---|---|
| 0.12.0 | generated corpus v1 | Ubuntu x86-64, Python 3.13 | [results](v0.12.0/report.md) |

## Interpretation

Mosaic reports include authenticated encryption, scrypt key derivation, and
padding. ZIP, gzip, zstd, and 7-Zip are compression-only baselines. Archive
ratios and timings are therefore useful engineering context, not claims that
the tools provide equivalent security or metadata semantics.

Reports record the corpus manifest digest, source commit, configuration,
runtime environment, tool versions, archive sizes, timings, and round-trip
verification. A result is published only when every represented method restores
the original logical tree.
