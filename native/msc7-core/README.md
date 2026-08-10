# MSC7 native core laboratory

This crate implements the deliberately non-stable `M7R0` compression-core
preview. It is not encrypted, authenticated, binding, release-ready, or a
stable format. It does not alter MSC1–MSC6 or the default Python CLI.

The stream uses Mosaic Gear CDC (16/64/256 KiB), an 8 MiB backward SHA-256
deduplication window, deterministic feature routing, and ordered 8 MiB
segments. Standard records use tuned raw LZMA2 (preset 3 with a 256 KiB
dictionary), delta records use delta4 plus zstd level 5, and high-entropy
records use zstd level 1. A candidate is retained only when its complete
16-byte record is smaller than the corresponding complete raw record; ties
fall back to raw.

```text
cargo run --release -p mosaic-msc7-core --bin mosaic-msc7-lab -- encode --threads 8 input.bin output.m7r0
cargo run --release -p mosaic-msc7-core --bin mosaic-msc7-lab -- decode output.m7r0 restored.bin
cargo run --release -p mosaic-msc7-core --bin mosaic-msc7-lab -- inspect output.m7r0
cargo run --release -p mosaic-msc7-core --bin mosaic-msc7-lab -- benchmark --threads 8 input.bin
```

Decode enforces fixed parameters, bounded segment/record sizes, exact payload
sizes, backward-only in-window references, per-segment SHA-256, a whole-stream
SHA-256 footer, total resource ceilings, and rejection of trailing bytes. File
output uses synchronized same-directory temporary files and atomic publication;
input/output aliases fail before mutation. These hashes detect damage; they do
not provide authenticity against an attacker.
