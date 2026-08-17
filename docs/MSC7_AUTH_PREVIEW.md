# Authenticated MSC7 native preview

`M7A0` is the first password-encrypted, authenticated native vertical slice on
the path toward MSC7. It wraps the exact non-stable `M7R0` compression-core byte
stream in bounded ChaCha20-Poly1305 records and finishes with an authenticated
transcript footer.

`M7A0` is deliberately not the stable `MSC7` format. Its identifiers and layout
may change, it is not a compatibility fixture, and it is not eligible for a
Competitive Contract result. It currently handles one byte stream or regular
file, not a Mosaic file tree. MSC6 remains the default writer and the only
frozen current writer contract.

## Construction

The outer envelope uses established primitives through RustCrypto:

- scrypt derives a 32-byte key from the password and a fresh random 16-byte
  salt. The writer defaults to `log2(N)=17`; writer values are 14 through 18,
  with fixed `r=8` and `p=1`. Decode has a separate caller policy: it accepts
  at most 17 by default and can be explicitly set from 14 through 18.
- ChaCha20-Poly1305 encrypts and authenticates every data record and the final
  footer. Each record receives a 16-byte authentication tag.
- Every archive has a fresh random four-byte nonce prefix. A record nonce is
  that prefix followed by the record's monotonic big-endian 64-bit index.
- Associated data is a domain separator, the exact 64-byte public header, and
  the exact 16-byte record header. Changing a supported header or record field
  therefore invalidates authentication.
- Password copies and the derived key use zeroizing storage. Salt, nonce prefix,
  and padding bytes come from the operating system random source.

Wrong passwords and record-tag failures intentionally produce the same generic
`authentication failed` result. Unsupported or malformed public structure is a
separate format error. The fixed public header and caller-selected KDF ceiling
are checked before scrypt. Record headers, count/size ceilings, and the outer
byte ceiling are checked before record-payload allocation.

## Envelope

All `M7A0` integers are big-endian. The fixed 64-byte header declares:

- magic `M7A0`, version 0, the required flags, and the currently fixed KDF,
  AEAD, core, and profile identifiers;
- header length 64, a 1,024-byte plaintext padding quantum, and a maximum
  2,097,152-byte data-record plaintext;
- the random salt and nonce prefix; and
- the selected scrypt parameters, with every reserved field required to be
  zero.

Each 16-byte record header contains its 64-bit index, kind, zero flags and
reserved bits, and ciphertext length. Data-record plaintext is `M7D0`, the
nonzero inner-payload length, at most 2,097,144 bytes of the `M7R0` stream, and
fresh opaque padding to a 1 KiB multiple. The eight-byte private prefix makes a
full record exactly 2 MiB, avoiding an otherwise unnecessary 1,016-byte pad;
the final short record remains padded to the next quantum.

The mandatory footer record contains an `M7F0` payload with the data-record
count, exact inner-stream and original byte counts, inner segment and record
totals, SHA-256 of the complete inner `M7R0` stream, and SHA-256 of a
domain-separated transcript. The transcript binds the exact outer header and
every non-footer record header plus its complete ciphertext and tag. The footer
itself is AEAD-protected and padded to the same 1 KiB quantum.

The decoder authenticates a complete outer record before exposing its inner
bytes. It also requires the authenticated footer, agreement between footer and
inner statistics, and physical end-of-file before accepting the archive;
truncation, reordering, duplication, trailing bytes, inconsistent totals, and
digest or transcript changes fail closed.

## Resource bounds

The authenticated decoder retains all `M7R0` limits and adds independent outer
ceilings. Defaults are:

- 8 GiB restored output;
- 8 GiB plus 16 MiB for the inner `M7R0` stream;
- that inner ceiling plus 64 MiB for the complete `M7A0` archive;
- 131,072 inner segments, 2,000,000 inner records, and an expansion-ratio
  ceiling of 16,384 after the existing 8 MiB allowance;
- 1,000,000 authenticated data records; and
- a maximum accepted scrypt `log2(N)` of 17.

Callers can lower the byte and record ceilings. They can select a maximum
accepted scrypt `log2(N)` from 14 through 18; raising it above the default 17
explicitly permits an archive-controlled higher KDF cost. The decoder enforces
that policy before scrypt. Record kind, index, ciphertext length, outer totals,
and the applicable per-record bound are validated before payload allocation.

## Current overhead diagnostic

A local deterministic 64 MiB incompressible input (67,108,864 bytes, SHA-256
`1b32965ba0d3ff2b493624048f6961dde1edc82f65922b7579abeacba77a9a83`)
produces a 67,123,984-byte inner `M7R0` stream and a 67,127,424-byte `M7A0`
archive. The complete encrypted archive is 18,560 bytes, or 0.027656%, larger
than the source and remains below the diagnostic `ceil(input/2000)` threshold
of 33,555 bytes.

The outer envelope adds 3,440 bytes to the inner stream: 64 header bytes, 544
record-header bytes, 544 authentication-tag bytes, 264 private data-prefix
bytes, 112 footer-payload bytes, and 1,912 random padding bytes across 33 data
records plus the footer. Capping inner payloads at 2,097,144 bytes aligns every
full data plaintext to exactly 2 MiB and saves 31,744 bytes versus the earlier
unaligned 67,159,168-byte result. This is a local size diagnostic, not timing
evidence, an attested benchmark, or a Competitive Contract result.

## Native CLI

The authenticated commands are deliberately separate from the existing `M7R0`
laboratory commands:

```text
mosaic-msc7-lab encode-auth --password-env NAME [--threads N] [--kdf-log-n N]
                            [--max-input-bytes N] [INPUT|-] OUTPUT
mosaic-msc7-lab decode-auth --password-env NAME [AUTH LIMIT OPTIONS] [INPUT|-] OUTPUT
mosaic-msc7-lab inspect-auth --password-env NAME [AUTH LIMIT OPTIONS] [INPUT|-]
mosaic-msc7-lab benchmark-auth --password-env NAME [--threads N] [INPUT|-]
```

Inner decode limits are `--max-output-bytes`, `--max-encoded-bytes`,
`--max-segments`, `--max-records`, and `--max-expansion-ratio`. Authenticated
limits are `--max-archive-bytes`, `--max-data-records`, and
`--max-kdf-log-n`. The KDF ceiling defaults to 17; choosing 18 opts in to the
larger archive-controlled scrypt cost, while 14 through 16 lower it.

`encode-auth` and `decode-auth` require a real output file; authenticated output
cannot be sent to standard output. With one positional path they read standard
input and write that path. With two they read the first path and write the
second. `inspect-auth` performs a complete bounded authenticated decode to a
sink. `benchmark-auth` is a convenience diagnostic that buffers both its input
and archive in memory and therefore is not the bounded-memory or binding
benchmark path.

Passwords are accepted only through the named environment variable. Literal
`--password` arguments are rejected so they do not enter the command line. The
CLI reads but does not remove the variable from its parent environment; the
caller must clear it after use. Environment variables are still visible to
software with sufficient access to the running process, so this interface does
not defend a compromised local machine.

For file output, the shared Rust file API rejects exact-path, hard-link, and
symbolic-link aliases before mutation. It writes a sibling temporary file,
flushes and synchronizes it, atomically persists it after the archive operation
succeeds, and then synchronizes the parent directory on Unix. The laboratory
CLI retains an additional redirected-standard-input alias check for its stdin
mode. Wrong-password and other pre-publication failures preserve an existing
destination. If the final Unix directory sync fails, the operation reports an
error after the complete destination may already be visible; crash durability
is then uncertain and the publication cannot be rolled back.

## Python ABI3 preview

The mixed Maturin distribution contains a private
`mosaic_archive._native` CPython 3.11+ ABI3 extension. The typed
`mosaic_archive.native_preview` facade exposes only path-based regular-file
operations:

- `encode_native_preview_file`;
- `inspect_native_preview_file`; and
- `decode_native_preview_file`.

The binding owns a zeroizing password copy, releases the Python GIL while Rust
performs compression, KDF, authentication, or decode work, and delegates file
publication to the same transactional Rust API as the laboratory CLI. Native
authentication failures map to one generic public `AuthenticationError`;
format, option, codec, and operating-system failures keep distinct Python
types. The facade accepts `str` passwords as exact UTF-8 and preserves `bytes`
without normalization. Python-owned password objects cannot be reliably erased
by the extension.

The Python CLI keeps the preview outside normal archive dispatch through
separate `encode-native-preview`, `inspect-native-preview`, and
`decode-native-preview` commands. They accept a hidden prompt or
`--password-env NAME`, reject literal password arguments, and expose every
native resource ceiling. MSC6 remains the default writer; normal decode and
inspect do not auto-detect `M7A0` during this non-stable phase.

CI builds ABI3 wheels on Linux, Windows, and macOS, installs each wheel into a
clean environment, and exercises Unicode paths, authenticated round trip, and
failure preservation. Tagged PyInstaller executables are configured to bundle
the extension and run the same smoke before publication. This is packaging
coverage for the preview, not a frozen compatibility or PyPI-publishing claim.

## Direct library caveat

`encode_authenticated` and `decode_authenticated` intentionally accept generic
Rust `Read` and `Write` implementations. This makes streaming composition
possible, but a generic writer cannot be rolled back. A late input, output,
footer, transcript, or trailing-data failure can leave bytes in a caller-owned
writer even though the function returns an error: authenticated inner segments
can reach that writer before the outer footer and physical EOF are verified.
Direct users must write to a discardable or same-directory temporary
destination and publish it only after a successful return. The public Rust
file functions, Python preview facade, and both CLIs supply that publication
boundary.

## Deliberate gaps

This sprint does not add file-tree metadata, permanent codec identifiers or
fixtures, a stable MSC7 magic, normal format dispatch, PyPI trusted publishing,
an attested competitive measurement, or an independent security review.
`M7R0` remains useful as deterministic compression evidence; `M7A0`
demonstrates the authenticated streaming composition and a real path-only
Python delivery boundary. Neither is the release candidate.
