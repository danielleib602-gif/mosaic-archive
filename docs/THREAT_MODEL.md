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

## Native M7A0 preview boundary

The non-stable `M7A0` native preview applies the same primitive families to one
byte stream, but is not yet the MSC7 security contract. Scrypt derives a
32-byte key from a fresh random 16-byte salt using writer-selected `log2(N)` 14
through 18 (default 17), fixed `r=8`, and fixed `p=1`. Decode separately caps
the accepted `log2(N)` at 17 by default; a caller may explicitly select a
ceiling through 18. ChaCha20-Poly1305 protects each bounded record with a nonce
made from a fresh random four-byte prefix and its monotonic big-endian 64-bit
record index. The exact public and record headers are associated data.

Each data record contains at most 2,097,144 bytes of the inner `M7R0` stream.
Its eight-byte private prefix makes a full plaintext record exactly 2 MiB;
shorter records receive random padding to a 1 KiB quantum. A mandatory
authenticated footer binds the complete inner-stream hash, byte/record totals,
and a domain-separated transcript over the public header and every data record
header plus ciphertext.
The decoder authenticates a complete outer record before exposing its inner
bytes and requires the footer plus physical end-of-file before accepting the
archive. Wrong passwords and tag failures share one generic authentication
error. Header fields and the caller's KDF ceiling are validated before KDF
work. Record headers, counts, ciphertext sizes, and the outer byte ceiling are
validated before record-payload allocation.

The outer decoder adds caller-adjustable archive-byte and authenticated-record
ceilings to every existing inner output, encoded-byte, segment, record, and
expansion limit. These controls bound accepted work; they do not stop offline
password guessing, hide archive existence or rough padded length, or protect a
compromised endpoint. Raising the decode KDF ceiling above 17 explicitly allows
an archive-controlled scrypt cost up to the selected cap. `M7R0` hashes alone
remain non-authenticating corruption checks.

Authenticated native CLI passwords are accepted only through a named
environment variable; literal command-line passwords are rejected. This avoids
placing the password in ordinary command arguments, but the environment remains
available to sufficiently privileged local software and must be cleared by the
caller. Password copies and the derived key use zeroizing storage.

For authenticated encode/decode file output, the native CLI uses an alias-safe
sibling temporary file, synchronizes it, and atomically publishes only after
success; Unix also synchronizes the parent directory. Wrong-password and late
validation failures preserve an existing destination. The direct Rust library
accepts a generic `Write` and cannot retract bytes already written. A caller
using `encode_authenticated` or `decode_authenticated` must stage output and
publish it only after success; otherwise a late footer, transcript,
trailing-data, input, or output failure can leave partial bytes in that writer.
Authenticated inner segments may reach a direct caller's writer before the
outer footer and physical EOF are verified; only the file CLI supplies the
transactional publication boundary.
If the Unix parent-directory synchronization fails after atomic rename, the CLI
reports an error even though the complete destination may already be visible;
its crash durability is then uncertain. Only failures before publication are
guaranteed to preserve the prior destination.

`M7A0` is currently single-stream only. It has no file-tree path/metadata
surface, stable magic or codec IDs, Python/PyO3 API, permanent fixture,
competitive evidence, independent audit, or release claim.

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

The experimental competitive runner uses a narrower Linux trust boundary. A
native supervisor and trusted Python coordinator share one dedicated service
identity and PID/user namespaces; measured tools will not share that identity.
The supervisor accepts only an inherited cgroup-v2 descriptor, delegates exactly
the fixed controller set, and hands off a fresh session descriptor only after an
`SO_PASSCRED` readiness exchange. Python mutation requires the exact live,
process-bound capability. Signal revocation waits for coordinator EOF before
native cleanup, preventing ordinary shutdown from racing in-flight mutations.
Malformed traffic and half-close do not satisfy that barrier; if full peer
closure cannot be proven, cleanup is suppressed and the session remains visible
for recovery. Fixed-control inheritance is one-shot per socket identity and is
serialized with `fork()`, preventing an accidental duplicate receiver from
closing live authority outside its capability lock. This does not handle
`SIGKILL`, prove future measured-process containment, or make current diagnostic
results binding; stale-root reconciliation and native pre-exec `clone3`
placement remain required.

The opt-in internal clone3 ABI probe consumes an already-open empty leaf and
proves only exact initial cgroup placement, namespace PID 1, and pidfd-bound
bounded reaping. It accepts no path or workload command, does not create or
remove the caller-owned leaf, and always remains non-binding. The future
executable self-test and arbitrary-tool launcher require the additional mount,
identity, reaper, output, and evidence controls documented separately.

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

The stable Python formats use primitives from the `cryptography` package. The
native `M7A0` preview uses the RustCrypto `scrypt` and `chacha20poly1305` crates
plus the operating-system random source. Mosaic's format compositions and
implementations have not received an independent security audit. Treat v0.39
and both native previews as research and learning tools, not as the sole
protection for irreplaceable or high-risk secrets.
