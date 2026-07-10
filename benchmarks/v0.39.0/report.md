# Mosaic Archive benchmark 0.39.0

- Source commit: `2f610516cc5d1f368647993844b8a7c7b9efb0c7`
- Corpus manifest SHA-256: `57bd4b92efbdeb8be023b2e1c92c586bebe56f90f5cd219f2df97c8f74f20d13`
- Original bytes: 1719961
- Platform: Linux-6.17.0-1018-azure-x86_64-with-glibc2.39
- Python: 3.13.14
- Mosaic configuration: format=solid, profile=balanced, chunk=65536, padding=256, scrypt logN=14
- Timing statistic: median of 5 independent runs

Mosaic includes authenticated encryption and padding. Encrypted 7-Zip
uses AES-256 data/header encryption; the other comparison tools are
compression-only baselines. Ratios are context, not universal claims.

| Method | Archive bytes | Ratio | Encode s | Decode s | Verified | Notes |
|---|---:|---:|---:|---:|:---:|---|
| Mosaic Archive (MSR2) | 291731 | 0.1696 | 0.3696 | 0.0394 | yes | scrypt + ChaCha20-Poly1305; padded |
| 7z | 336723 | 0.1958 | 0.0513 | 0.0151 | yes | 7z defaults; compression only, no encryption |
| 7z-encrypted | 336784 | 0.1958 | 0.0652 | 0.0346 | yes | 7z defaults with AES-256 data and header encryption; fixed public benchmark password |
| gzip | 831900 | 0.4837 | 0.0399 | 0.0139 | yes | tar + gzip level 6; compression only, no encryption |
| zip | 833736 | 0.4847 | 0.0335 | 0.0088 | yes | ZIP_DEFLATED level 6; compression only, no encryption |
| zstd | 496246 | 0.2885 | 0.0133 | 0.0143 | yes | tar + zstd default level; compression only, no encryption |

## Tool versions

- zip: Python zipfile / zlib 1.3
- gzip: Python gzip / zlib 1.3
- zstd: *** Zstandard CLI (64-bit) v1.5.7, by Yann Collet ***
- 7z: 7-Zip 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20

## Category results

| Category | Input bytes | Files | Mosaic bytes | ZIP bytes | zstd bytes | Encrypted 7-Zip bytes |
|---|---:|---:|---:|---:|---:|---:|
| dedup | 393232 | 3 | 131935 | 393780 | 131453 | 131968 |
| empty | 0 | 1 | 325 | 218 | 215 | 188 |
| image-like | 131072 | 1 | 607 | 80986 | 109122 | 20688 |
| numeric | 131072 | 1 | 607 | 45817 | 87552 | 17280 |
| precompressed | 131118 | 1 | 131679 | 131410 | 131403 | 131408 |
| random | 131072 | 1 | 131679 | 131334 | 131353 | 131328 |
| source | 131072 | 1 | 607 | 851 | 334 | 463 |
| sparse | 131072 | 1 | 1631 | 1673 | 1481 | 1519 |
| structured | 131072 | 1 | 10335 | 14176 | 14751 | 10591 |
| tabular | 131072 | 1 | 10335 | 18611 | 20208 | 10607 |
| text | 131072 | 1 | 607 | 776 | 334 | 447 |
| tiny-files | 1162 | 64 | 3167 | 9474 | 731 | 831 |
| unicode | 131072 | 1 | 607 | 807 | 342 | 447 |
