# Mosaic Archive benchmark 0.12.0

- Source commit: `2f34ce290d84c307808a1c8b199f8e0ffa67a45b`
- Corpus manifest SHA-256: `7588b726e796b3abf6047ead06101ea63c4e37900bcef5c060f8e36351c82290`
- Original bytes: 1050407
- Platform: Linux-6.17.0-1018-azure-x86_64-with-glibc2.39
- Python: 3.13.14
- Mosaic configuration: profile=balanced, chunk=65536, padding=1024, scrypt logN=14

Mosaic includes authenticated encryption and padding. All comparison
tools below are compression-only baselines; ratios are therefore useful
context, not feature-equivalent claims.

| Method | Archive bytes | Ratio | Encode s | Decode s | Verified | Notes |
|---|---:|---:|---:|---:|:---:|---|
| Mosaic Archive | 495053 | 0.4713 | 2.2342 | 0.0417 | yes | MSC6; scrypt + ChaCha20-Poly1305; padded |
| zip | 718214 | 0.6837 | 0.0396 | 0.0043 | yes | ZIP_DEFLATED level 6; compression only, no encryption |
| gzip | 720445 | 0.6859 | 0.0352 | 0.0072 | yes | tar + gzip level 6; compression only, no encryption |
| zstd | 366090 | 0.3485 | 0.0100 | 0.0082 | yes | tar + zstd default level; compression only, no encryption |
| 7z | 292831 | 0.2788 | 0.2511 | 0.0193 | yes | 7z defaults; compression only, no encryption |

## Tool versions

- zip: Python zipfile / zlib 1.3
- gzip: Python gzip / zlib 1.3
- zstd: *** Zstandard CLI (64-bit) v1.5.7, by Yann Collet ***
- 7z: 7-Zip 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20
