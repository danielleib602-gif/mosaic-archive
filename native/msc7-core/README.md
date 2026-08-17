# MSC7 native laboratory

This crate implements two deliberately non-stable native previews:

- `M7R0` is the deterministic compression-core envelope. By itself it is not
  encrypted or authenticated.
- `M7A0` streams that exact `M7R0` envelope through bounded scrypt and
  ChaCha20-Poly1305 authenticated records plus a mandatory transcript footer.

Neither identifier is the stable MSC7 format, a compatibility fixture, binding
competitive evidence, or a release-ready archive. The crate currently handles
one byte stream or regular file, not a file tree. It does not alter MSC1–MSC6 or
the MSC6 default writer. A separate private ABI3 crate exposes only the
authenticated regular-file API through explicit Python preview commands.

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

## Authenticated preview

Set a temporary environment variable, then use the separate authenticated
commands. Literal password arguments are rejected.

```text
cargo run --release -p mosaic-msc7-core --bin mosaic-msc7-lab -- encode-auth --password-env MOSAIC_PASSWORD --threads 8 input.bin output.m7a
cargo run --release -p mosaic-msc7-core --bin mosaic-msc7-lab -- inspect-auth --password-env MOSAIC_PASSWORD output.m7a
cargo run --release -p mosaic-msc7-core --bin mosaic-msc7-lab -- decode-auth --password-env MOSAIC_PASSWORD output.m7a restored.bin
cargo run --release -p mosaic-msc7-core --bin mosaic-msc7-lab -- benchmark-auth --password-env MOSAIC_PASSWORD --threads 8 input.bin
```

`M7A0` derives a 32-byte key with scrypt (writer `log2(N)=17` by default,
writer range 14–18, `r=8`, `p=1`) and a fresh 16-byte salt. Decode accepts at
most 17 by default; `--max-kdf-log-n` selects a policy from 14 through 18 and is
enforced before scrypt. ChaCha20-Poly1305 protects each record with a
nonce made from a fresh four-byte prefix and its monotonic 64-bit index. Exact
headers are associated data; the final authenticated footer binds the complete
inner-stream hash, record/byte totals, and a transcript of every data record. A
record carries at most 2,097,144 inner bytes; with its eight-byte private prefix,
full plaintext records are exactly 2 MiB and shorter records receive fresh
random padding to a 1 KiB quantum. See
[the complete M7A0 description](../../docs/MSC7_AUTH_PREVIEW.md).

`encode-auth` and `decode-auth` require file output. The CLI uses an alias-safe
sibling temporary file and publishes it atomically only after success. The
generic Rust library functions cannot roll back an arbitrary `Write`; direct
callers must stage output and publish it themselves after a successful return.
On Unix, a parent-directory sync error can be reported after the complete file
has already been renamed into place; that case means durability is uncertain,
not that publication was rolled back.

The public `encode_authenticated_file`, `decode_authenticated_file`, and
`inspect_authenticated_file` functions centralize that regular-file boundary
for the laboratory CLI and `mosaic-msc7-python` binding. The binding releases
the GIL for native work, owns a zeroizing password copy, and returns exact outer
and inner statistics. Its Python facade and CLI remain explicitly non-stable;
they do not enter MSC1–MSC6 magic dispatch.
