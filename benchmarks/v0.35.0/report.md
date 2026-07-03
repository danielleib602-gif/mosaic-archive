# Mosaic Archive benchmark 0.35.0

- Source commit: `99ef791`
- Corpus manifest SHA-256: `57bd4b92efbdeb8be023b2e1c92c586bebe56f90f5cd219f2df97c8f74f20d13`
- Original bytes: 1719961
- Platform: Windows-11-10.0.26200-SP0
- Python: 3.13.13
- Mosaic configuration: format=solid, profile=balanced, chunk=65536, padding=256, scrypt logN=14
- Timing statistic: median of 5 independent runs

Mosaic includes authenticated encryption and padding. Encrypted 7-Zip
uses AES-256 data/header encryption; the other comparison tools are
compression-only baselines. Ratios are context, not universal claims.

| Method | Archive bytes | Ratio | Encode s | Decode s | Verified | Notes |
|---|---:|---:|---:|---:|:---:|---|
| Mosaic Archive (MSR2) | 293523 | 0.1707 | 0.4412 | 0.0848 | yes | scrypt + ChaCha20-Poly1305; padded |
| 7z | n/a | n/a | n/a | n/a | n/a | 7-Zip executable not found |
| 7z-encrypted | n/a | n/a | n/a | n/a | n/a | 7-Zip executable not found; AES-256 encryption comparison unavailable |
| gzip | 831728 | 0.4836 | 0.0488 | 0.0633 | yes | tar + gzip level 6; compression only, no encryption |
| zip | 833736 | 0.4847 | 0.0448 | 0.0443 | yes | ZIP_DEFLATED level 6; compression only, no encryption |
| zstd | n/a | n/a | n/a | n/a | n/a | zstd executable not found |

## Tool versions

- zip: Python zipfile / zlib 1.3.1
- gzip: Python gzip / zlib 1.3.1
- zstd: unavailable
- 7z: unavailable

## Category results

| Category | Input bytes | Files | Mosaic bytes | ZIP bytes | zstd bytes | Encrypted 7-Zip bytes |
|---|---:|---:|---:|---:|---:|---:|
| dedup | 393232 | 3 | 131935 | 393780 | n/a | n/a |
| empty | 0 | 1 | 325 | 218 | n/a | n/a |
| image-like | 131072 | 1 | 607 | 80986 | n/a | n/a |
| numeric | 131072 | 1 | 607 | 45817 | n/a | n/a |
| precompressed | 131118 | 1 | 131679 | 131410 | n/a | n/a |
| random | 131072 | 1 | 131679 | 131334 | n/a | n/a |
| source | 131072 | 1 | 607 | 851 | n/a | n/a |
| sparse | 131072 | 1 | 1631 | 1673 | n/a | n/a |
| structured | 131072 | 1 | 10079 | 14176 | n/a | n/a |
| tabular | 131072 | 1 | 9823 | 18611 | n/a | n/a |
| text | 131072 | 1 | 607 | 776 | n/a | n/a |
| tiny-files | 1162 | 64 | 3167 | 9474 | n/a | n/a |
| unicode | 131072 | 1 | 607 | 807 | n/a | n/a |
