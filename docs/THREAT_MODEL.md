# Threat model

Mosaic Archive v0.39 aims to provide a defensible experimental container around
an intentionally simple compression engine. It does not claim cryptographic
novelty.

## Protected properties

Given a strong, secret password and an uncompromised local machine, an attacker
who obtains or modifies an `.msc` file should not be able to:

- read the original bytes, filename, digest, compression choices, or exact
  compressed length;
- alter, remove, duplicate, or reorder the public header, encrypted manifest, or
  numbered data frames without authentication or structural failure;
- make the decoder publish a partially restored file after a wrong password,
  malformed payload, failed authentication, or failed SHA-256 restoration
  check.

These properties use scrypt for password-based key derivation and
ChaCha20-Poly1305 for authenticated encryption. MSC2 authenticates the public
header and each frame header as associated data. Each archive receives a new
random salt and four-byte nonce prefix; the remaining nonce bytes are the
monotonic 64-bit frame index.

## Explicit non-goals and residual leakage

Mosaic Archive does not protect:

- weak or reused passwords from offline guessing;
- plaintext or passwords on an already-compromised endpoint;
- command-line passwords from shell history or local process inspection;
- archive existence, format version, chunk size, KDF cost, padding policy, or
  final ciphertext length;
- rough content length—the bucket padding hides precision, not magnitude;
- access timing, deletion history, filesystem metadata, or denial of service;
- data availability when the only password is forgotten.

Compression ratios can correlate with content. Padding reduces this signal but
does not eliminate it. Do not use this alpha in an interactive compression
oracle where an attacker can influence plaintext and observe repeated archive
lengths.

## Paths, parser, and resource limits

The decoder bounds public chunk/padding sizes and KDF parameters, rejects
unknown algorithms and modes, verifies ciphertext length before allocation,
checks every nested field, and enforces exact decoded block sizes.
Because KDF parameters must be read before authentication, decoders cap
`log2(N)` at 18 and accept only scrypt `r=8`, `p=1`.

MSC2 accepts only canonical relative POSIX paths that are also safe on Windows.
It rejects traversal, absolute/drive paths, reserved device names, control
characters, backslashes, case-insensitive collisions, links/reparse points, and
special files. Folder extraction happens in a new temporary sibling directory
and is published only after every frame and file digest verifies. Existing
folder destinations are never merged.

File content is processed one chunk and authenticated frame at a time. The
encrypted manifest is still held in memory and is capped at 256 MiB; entry,
frame, chunk, padding, and KDF parameters also have explicit limits. A
60-minute sustained-reliability job runs 10,000 deterministic mutations plus a
256 MiB pull-request soak, a weekly 1,025 MiB tier crossing 1 GiB, or a monthly
2,049 MiB tier crossing signed 32-bit offsets. Both the local 1,025 MiB tier and
the protected-main hosted 2,049 MiB tier restore exactly; independent review
remains required before a stable large-file release. Atheris additionally runs bounded
coverage-guided campaigns from valid seeds for outer headers, frame headers,
encrypted-manifest parsers, and all compression modes.
Decode and inspect callers can lower the shared 1 TiB restored-output
and 1,000,000-frame ceilings. Legacy whole-buffer MSC1 input defaults to a
separate 1 GiB archive cap.

Every active MSC1, MSC2, MSC6, MSR1, and MSR2 encoder captures the identity and
replacement-sensitive metadata of the selected root and each discovered
directory and file. Each content read validates its ancestor bindings and the
metadata from the exact opened handle before and after reading. Immediately
before atomic publication, the encoder rescans the complete topology and
rejects additions, removals, replacements, and link/reparse-point substitution.
Failures remove temporary output. Persistent namespace changes observable when
a binding is checked are rejected, but portable filesystem calls do not form a
transaction. A hostile local process can race a replacement after an object's
final check, make transient changes between `stat`, `scandir`, `open`, and
`replace`, or mutate the same file object while restoring its size and
timestamps. Those attacks are outside the uncompromised-local-machine
assumption above.

The final `os.replace` is an atomic namespace switch, but Mosaic does not fsync
the containing directory and therefore does not promise power-loss durability.

Deterministic mutation tests exercise authenticated archive corruption, every
public header/frame parser, both encrypted-manifest parsers, and malformed
payloads across every codec. DEFLATE decoding uses an explicit authenticated
output bound and rejects trailing compressed data. These tests and
coverage-guided campaigns improve failure coverage but are not a substitute for
an independent audit.

Structured MSC2 corruption tests re-encrypt altered manifests and data frames
to exercise traversal, digest-mismatch, truncation, and entry-index/size
metadata defenses after authentication succeeds. Separate structural cases
cover trailing bytes, malformed frame headers, and resource limits. Every
failure is required to preserve an existing destination and remove temporary
output.

Structured MSC6 corruption tests likewise re-encrypt altered frames to reach
traversal, file/chunk digest, truncation, and occurrence/size metadata defenses
after authentication succeeds. Separate cases cover trailing bytes, malformed
frame headers, and caller resource limits. MSC2 and MSC6 progress-callback
exceptions are propagated only after the atomic-output cleanup path removes any
temporary file or folder tree.

Structured MSR2 tests have the production encoder authenticate deliberately
malformed traversal and file/chunk-digest metadata, then require destination
preservation and temporary-tree cleanup on failure. Every MSC1-through-MSC6
decoder plus experimental MSR1 and MSR2 binds output-alias checks to the
identity of the archive file actually opened. Direct, symbolic-link, and
hard-link aliases fail before password derivation, and a second check runs
immediately before atomic publication to reject late rebinding. Archive sizes
also come from the opened handle rather than a separately resolved pathname.
Portable `stat` and `replace` calls are not an indivisible defense against a
hostile process concurrently mutating destination directory entries. Such a
process is outside the uncompromised-local-machine assumption above.

LZ_RANS validates every nested stream length, frequency table, varint, match
distance, token kind, and final output length. Nested decoded stream lengths
are rejected before rANS decoding when they exceed the authenticated block
size, preventing descriptor-driven expansion work. LZ_RANS remains opt-in
through the research profile, limiting exposure while it gathers benchmark
evidence.

MSC3 dedup references may point only to an earlier canonical chunk and may not
point to another reference. The parser verifies matching digest/size metadata,
so forward references, chains, cycles, and reference-driven expansion are
rejected before restoration. Referenced canonical chunks are kept in a
temporary disk-backed cache capped indirectly by authenticated unique content.

## Security status

The Python `cryptography` package supplies the cryptographic primitives.
Mosaic's format composition and implementation have not received an independent
security audit. Treat v0.39 as a research and learning tool, not as the sole
protection for irreplaceable or high-risk secrets.
