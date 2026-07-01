# MSC format specification

Status: experimental, version 0.6. Integer fields are unsigned and big-endian
unless stated otherwise.
All offsets below are decimal. Implementations must reject truncated fields,
unknown required identifiers, impossible sizes, trailing manifest bytes, and
decoded blocks that do not match their declared sizes.

## MSC3 content-defined deduplicating format

MSC3 was the v0.3 encoder format. Its 55-byte public header contains `MSC3`,
version `3`, flags `0x07`, the KDF/AEAD IDs, minimum/average/maximum chunk
sizes, padding size, 16-byte salt, four-byte nonce prefix, scrypt parameters,
and frame count. The nonce and frame AAD construction are identical to MSC2.

The encrypted `M3MF` manifest contains the same safe file/directory metadata as
MSC2, but file entries identify a range in a global chunk-occurrence table.
Each occurrence record stores:

| Size | Field |
|---:|---|
| 32 | SHA-256 chunk digest |
| 4 | uncompressed chunk size |
| 8 | canonical source-occurrence index |

A unique chunk points to its own occurrence index. A duplicate must point
directly to an earlier unique occurrence with identical size and digest.
Forward references, reference chains, and cycles are invalid. The public frame
count equals one manifest frame plus the number of unique chunks.

Each unique data frame contains an eight-byte occurrence index, four-byte
uncompressed size, one-byte compression mode, and mode payload. Duplicate
occurrences have no data frame. File SHA-256 digests remain authoritative
end-to-end restoration checks.

## MSC4 rANS-capable format

MSC4 retains MSC3 framing, manifests, chunking, deduplication, and cryptography,
but permits compression mode 4. Its distinct magic/version prevents an older
v0.3 decoder from encountering a newly emitted mode.

## MSC5 routed DEFLATE format

MSC5 retains all MSC4 semantics and permits compression mode 5. The default
encoder uses a file-agnostic feature router to avoid expensive candidates, but
the on-disk mode remains explicit and decoding never depends on classifier
behavior.

## MSC6 split-stream LZ+rANS format

MSC6 retains MSC5 semantics and permits compression mode 6. Encoder profiles
affect which candidates are attempted but are not required for decoding and are
not trusted archive metadata.

## MSC2 framed file/folder format

MSC2 was the v0.2 encoder format. It keeps folder metadata encrypted and
processes file content in bounded-memory, independently authenticated frames.

### MSC2 public header

The MSC2 public header is 47 bytes:

| Offset | Size | Field | v0.2 value or meaning |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII `MSC2` |
| 4 | 1 | version | `2` |
| 5 | 1 | flags | `0x03` (framed and padded) |
| 6 | 1 | KDF ID | `1` (scrypt) |
| 7 | 1 | AEAD ID | `1` (ChaCha20-Poly1305) |
| 8 | 4 | chunk size | maximum uncompressed data-frame content |
| 12 | 4 | padding size | per-frame plaintext bucket size |
| 16 | 16 | salt | random per-archive scrypt salt |
| 32 | 4 | nonce prefix | random per-archive prefix |
| 36 | 1 | log N | scrypt cost as `log2(N)` |
| 37 | 1 | r | scrypt block-size parameter |
| 38 | 1 | p | scrypt parallelization parameter |
| 39 | 8 | frame count | one manifest frame plus all data frames |

The 12-byte nonce for frame `i` is the four-byte nonce prefix followed by `i`
as an eight-byte big-endian integer. Frame indexes begin at zero and must be
strictly consecutive.

### MSC2 frame

Every frame begins with a 13-byte public frame header:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | frame index |
| 8 | 1 | frame type (`1` manifest, `2` data) |
| 9 | 4 | ciphertext length, including the 16-byte AEAD tag |

The associated data for each ChaCha20-Poly1305 operation is:

```text
complete MSC2 public header || complete frame header
```

The encrypted plaintext uses the same envelope for every frame:

| Size | Field |
|---:|---|
| 8 | actual frame-payload length |
| variable | frame payload |
| variable | cryptographically random padding |

The padded plaintext length must be an exact multiple of the public padding
size. The archive ends immediately after the declared number of frames; missing
or appended bytes are errors.

### Encrypted manifest payload

The manifest frame is frame zero. Its payload begins:

| Size | Field |
|---:|---|
| 4 | manifest magic `M2MF` |
| 1 | archive kind (`1` file, `2` folder) |
| 2 | root-name UTF-8 byte length |
| 4 | entry count |
| variable | root-name bytes |
| variable | entry records |

Each entry record is:

| Size | Field |
|---:|---|
| 1 | entry type (`1` regular file, `2` directory) |
| 2 | relative-path UTF-8 byte length |
| 4 | portable permission bits |
| 8 | signed modification time in nanoseconds |
| 8 | file size; zero for directories |
| 8 | first data-frame index; zero for directories |
| 4 | data-frame count; zero for directories and empty files |
| 32 | SHA-256 file digest; all zero for directories |
| variable | canonical relative-path bytes |

File frame ranges must be consecutive, non-overlapping, and cover every frame
after the manifest. A folder manifest must include every non-root parent
directory. Paths use `/`, are NFC-normalized, and must pass the portable safety
rules described in the threat model.

### Encrypted data-frame payload

| Size | Field |
|---:|---|
| 4 | manifest entry index |
| 4 | uncompressed block size |
| 1 | compression mode ID |
| variable | mode payload |

The expected uncompressed size is derived independently from the manifest file
size, chunk size, and local frame position. The stored value must match it.

## Legacy MSC1 single-file format

Decoders retain MSC1 support for archives produced by Mosaic Archive v0.1. New
CLI encoding uses MSC2.

### MSC1 public header

The public header is 55 bytes and is passed byte-for-byte to
ChaCha20-Poly1305 as associated data.

| Offset | Size | Field | v0.1 value or meaning |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII `MSC1` |
| 4 | 1 | version | `1` |
| 5 | 1 | flags | `0x01` (padded) |
| 6 | 1 | KDF ID | `1` (scrypt) |
| 7 | 1 | AEAD ID | `1` (ChaCha20-Poly1305) |
| 8 | 4 | chunk size | uncompressed block target |
| 12 | 4 | padding size | ciphertext plaintext bucket size |
| 16 | 16 | salt | random per-archive scrypt salt |
| 32 | 12 | nonce | random per-archive AEAD nonce |
| 44 | 1 | log N | scrypt CPU/memory cost as `log2(N)` |
| 45 | 1 | r | scrypt block-size parameter |
| 46 | 1 | p | scrypt parallelization parameter |
| 47 | 8 | ciphertext length | includes the 16-byte AEAD tag |

The archive ends immediately after `ciphertext length` bytes. Appended or
missing data is an error.

Filename, original size, digest, block count, mode IDs, and codec payload sizes
are not public metadata.

### MSC1 key derivation and encryption

The UTF-8 password bytes are passed to scrypt with the parameters in the public
header to derive a 32-byte key. v0.1 encoding defaults to:

```text
N = 2^15
r = 8
p = 1
salt = 16 random bytes
```

Both decoders accept `log2(N)` from 14 through 18 and require `r=8`, `p=1`.
These pre-authentication limits prevent a forged public header from requesting
unbounded KDF memory or CPU.

ChaCha20-Poly1305 encrypts the padded plaintext with a 12-byte random nonce. The
complete serialized public header is associated data. The resulting ciphertext
already includes its 16-byte authentication tag.

### MSC1 padded plaintext envelope

After successful AEAD authentication, the plaintext is:

| Size | Field |
|---:|---|
| 8 | actual inner-stream length |
| variable | inner stream |
| variable | cryptographically random padding |

The total padded plaintext length must be an exact multiple of the public
padding size. The inner length is encrypted and authenticated.

### MSC1 inner stream

| Size | Field |
|---:|---|
| 4 | inner magic `MSCP` |
| 8 | original file size |
| 2 | UTF-8 filename byte length |
| variable | safe basename, with no directory components |
| 32 | SHA-256 digest of original bytes |
| 4 | block count |
| variable | block records |

Each block record is:

| Size | Field |
|---:|---|
| 1 | compression mode ID |
| 4 | uncompressed block size |
| 4 | encoded payload size |
| variable | encoded payload |

The sum of uncompressed block sizes must equal the original file size.

## Shared compression modes

### 0 — RAW

The payload is the original block. Payload size must exactly equal the declared
uncompressed size.

### 1 — RLE

The payload is a sequence of two-byte `(run length, byte value)` pairs. Run
length is in the range 1–255. The decoded total must exactly equal the declared
uncompressed size.

### 2 — DELTA8

For a non-empty block, the first byte is stored literally. Every following byte
becomes the wrapping difference `(current - previous) mod 256`; that delta
stream is encoded using mode 1's RLE representation. Empty blocks have an empty
payload, although MSC1 file manifests do not emit zero-size blocks.

### 3 — LZ_SIMPLE

The payload is a token sequence:

- literal: tag `0`, 2-byte literal length, literal bytes;
- match: tag `1`, 2-byte backward distance, 2-byte match length.

Literal and match lengths are non-zero. Match distance must reference already
decoded output. v0.1 emits matches of at least six bytes and supports overlap
copying.

### 4 — BYTE_RANS

The payload stores a sparse normalized byte-frequency table whose frequencies
sum to 4096, followed by a 32-bit rANS state and byte renormalization stream.
Symbols and frequencies must be unique and nonzero; decoding verifies complete
stream consumption and the final state.

### 5 — DEFLATE

The payload is a zlib-wrapped DEFLATE stream. Decoding is output-bounded to the
authenticated chunk size and rejects malformed streams, excess expansion, and
unused/trailing bytes.

### 6 — LZ_RANS

LZ tokens are split into token-kind, literal-byte, literal-length,
match-length, and match-distance streams. Lengths and distances use bounded
varints; each stream is independently BYTE_RANS encoded with authenticated raw
and encoded lengths. Decoding rejects unknown tokens, invalid matches, trailing
varints/streams, and output beyond the authenticated chunk size.

## Verification

After authenticated decryption, every block decoder enforces its declared
output size. MSC1 then verifies the total original size and SHA-256 digest
before atomically replacing the requested output path. MSC2 verifies every
file digest and all frame ranges before atomically publishing a file or folder.
