//! Non-stable native MSC7 compression-core laboratory preview.
//!
//! `M7R0` is deliberately not a stable Mosaic wire format. Alone, it is neither
//! encrypted nor authenticated. `M7A0` adds a non-stable scrypt and
//! ChaCha20-Poly1305 authenticated envelope around the exact M7R0 byte stream.
//! Neither preview format is a compatibility fixture.

mod auth_format;
mod authenticated;

pub use auth_format::AUTHENTICATED_MAGIC;
pub use authenticated::{
    AuthenticatedDecodeOptions, AuthenticatedEncodeOptions, AuthenticatedStats,
    DEFAULT_MAX_AUTHENTICATED_ARCHIVE_BYTES, DEFAULT_MAX_AUTHENTICATED_DATA_RECORDS,
    MIN_AUTHENTICATED_ARCHIVE_BYTES, decode_authenticated, encode_authenticated,
};

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io::{self, BufRead, BufReader, Cursor, Read, Write};
use std::sync::Arc;

use lzma_rust2::{Lzma2Options, Lzma2Reader, Lzma2Writer};
use rayon::prelude::*;
use sha2::{Digest, Sha256};

/// Non-stable preview magic. It is not an MSC7 compatibility identifier.
pub const MAGIC: [u8; 4] = *b"M7R0";
/// Minimum Mosaic Gear chunk size used by this preview.
pub const MIN_CHUNK_SIZE: usize = 16 * 1024;
/// Target average Mosaic Gear chunk size used by this preview.
pub const AVG_CHUNK_SIZE: usize = 64 * 1024;
/// Maximum Mosaic Gear chunk and decoded record size.
pub const MAX_CHUNK_SIZE: usize = 256 * 1024;
/// Maximum decoded bytes in one independently verified segment.
pub const MAX_SEGMENT_SIZE: usize = 8 * 1024 * 1024;
/// Maximum decoded-byte distance for a backward deduplication reference.
pub const DEDUP_WINDOW_SIZE: usize = 8 * 1024 * 1024;
/// Default decoded-input/output ceiling used by the CLI-facing options.
pub const DEFAULT_MAX_ORIGINAL_BYTES: u64 = 8 * 1024 * 1024 * 1024;
/// Default envelope ceiling, including worst-case RAW record and segment overhead.
pub const DEFAULT_MAX_ENCODED_BYTES: u64 = DEFAULT_MAX_ORIGINAL_BYTES + 16 * 1024 * 1024;

const HEADER_SIZE: usize = 32;
const SEGMENT_TAG: [u8; 4] = *b"SG07";
const FOOTER_TAG: [u8; 4] = *b"END7";
const SEGMENT_HEADER_REST: usize = 52;
const FOOTER_REST: usize = 52;
const RECORD_SIZE: usize = 16;
const MAX_RECORDS_PER_SEGMENT: usize = 1024;
const MAX_RECORDS_IN_DEDUP_WINDOW: usize = 1024;
const LZMA2_PRESET: u32 = 3;
const LZMA2_DICT_SIZE: u32 = MAX_CHUNK_SIZE as u32;
const MAX_THREADS: usize = 64;

/// Error returned by the non-stable compression-core preview.
#[derive(Debug)]
pub enum Error {
    /// An underlying read or write failed.
    Io(io::Error),
    /// Caller-supplied encode or decode limits are invalid.
    InvalidOptions(&'static str),
    /// The input stream violates a bounded native-preview envelope.
    InvalidFormat(&'static str),
    /// A codec could not encode an internally routed record.
    Codec(&'static str),
    /// A password or authenticated-record tag could not be verified.
    Authentication,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::InvalidOptions(message) => write!(formatter, "invalid options: {message}"),
            Self::InvalidFormat(message) => {
                write!(formatter, "invalid native preview stream: {message}")
            }
            Self::Codec(message) => write!(formatter, "codec error: {message}"),
            Self::Authentication => formatter.write_str("authentication failed"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidOptions(_)
            | Self::InvalidFormat(_)
            | Self::Codec(_)
            | Self::Authentication => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Result type used by the preview API.
pub type Result<T> = std::result::Result<T, Error>;

/// Encoder resource options.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodeOptions {
    /// Number of independent record-compression workers, in `1..=64`.
    pub threads: usize,
    /// Maximum decoded input bytes accepted by this encoder invocation.
    pub max_input_bytes: u64,
}

impl Default for EncodeOptions {
    fn default() -> Self {
        Self {
            threads: 1,
            max_input_bytes: DEFAULT_MAX_ORIGINAL_BYTES,
        }
    }
}

/// Decoder resource ceilings.
///
/// Raising these limits is safe only when the caller also controls available
/// output storage and CPU time. Authentication is supplied only by the outer
/// M7A0 API; M7R0 hashes alone remain unsuitable for adversarial transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodeOptions {
    /// Maximum total decoded bytes.
    pub max_output_bytes: u64,
    /// Maximum total encoded bytes, including headers and the footer.
    pub max_encoded_bytes: u64,
    /// Maximum number of segments.
    pub max_segments: u32,
    /// Maximum number of data and reference records.
    pub max_records: u64,
    /// Maximum cumulative decoded-to-encoded ratio after an 8 MiB allowance.
    pub max_expansion_ratio: u64,
}

pub(crate) fn validate_encode_options(options: EncodeOptions) -> Result<()> {
    if options.threads == 0 || options.threads > MAX_THREADS || options.max_input_bytes == 0 {
        return Err(Error::InvalidOptions(
            "thread count must be in 1..=64 and the input limit must be positive",
        ));
    }
    Ok(())
}

pub(crate) fn validate_decode_options(options: DecodeOptions) -> Result<()> {
    if options.max_output_bytes == 0
        || options.max_encoded_bytes < HEADER_SIZE as u64 + (4 + FOOTER_REST) as u64
        || options.max_segments == 0
        || options.max_records == 0
        || options.max_expansion_ratio == 0
    {
        return Err(Error::InvalidOptions(
            "decode resource ceilings must all be positive and fit an empty envelope",
        ));
    }
    Ok(())
}

impl Default for DecodeOptions {
    fn default() -> Self {
        Self {
            max_output_bytes: DEFAULT_MAX_ORIGINAL_BYTES,
            max_encoded_bytes: DEFAULT_MAX_ENCODED_BYTES,
            max_segments: 131_072,
            max_records: 2_000_000,
            max_expansion_ratio: 16_384,
        }
    }
}

/// Counts and codec decisions observed during encoding or decoding.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StreamStats {
    /// Decoded byte count.
    pub original_bytes: u64,
    /// Encoded envelope byte count.
    pub encoded_bytes: u64,
    /// Segment count.
    pub segments: u32,
    /// Total data and reference record count.
    pub records: u64,
    /// Backward-reference record count.
    pub deduplicated_records: u64,
    /// Raw data record count.
    pub raw_records: u64,
    /// Raw-LZMA2 data record count.
    pub lzma2_records: u64,
    /// Delta4 followed by zstd data record count.
    pub delta_zstd_records: u64,
    /// Plain zstd data record count.
    pub zstd_records: u64,
}

impl StreamStats {
    /// Return encoded bytes divided by decoded bytes, or zero for empty input.
    #[must_use]
    pub fn ratio(self) -> f64 {
        if self.original_bytes == 0 {
            0.0
        } else {
            self.encoded_bytes as f64 / self.original_bytes as f64
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum Codec {
    Raw = 0,
    Lzma2 = 1,
    Delta4Zstd = 2,
    Zstd = 3,
}

impl Codec {
    fn parse(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Raw),
            1 => Ok(Self::Lzma2),
            2 => Ok(Self::Delta4Zstd),
            3 => Ok(Self::Zstd),
            _ => Err(Error::InvalidFormat("record codec is unknown")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Lane {
    Standard,
    Delta4,
    HighEntropy,
}

struct GearChunker<R: Read> {
    reader: BufReader<R>,
    table: [u64; 256],
    chunk: Vec<u8>,
    fingerprint: u64,
    finished: bool,
}

impl<R: Read> GearChunker<R> {
    fn new(reader: R) -> Self {
        Self {
            reader: BufReader::with_capacity(64 * 1024, reader),
            table: gear_table(),
            chunk: Vec::with_capacity(MIN_CHUNK_SIZE),
            fingerprint: 0,
            finished: false,
        }
    }

    fn next_chunk(&mut self) -> Result<Option<Vec<u8>>> {
        if self.finished {
            return Ok(None);
        }
        loop {
            let mut consumed = 0;
            let mut boundary = false;
            {
                let available = self.reader.fill_buf()?;
                if available.is_empty() {
                    self.finished = true;
                    return if self.chunk.is_empty() {
                        Ok(None)
                    } else {
                        self.fingerprint = 0;
                        Ok(Some(std::mem::take(&mut self.chunk)))
                    };
                }
                for &byte in available {
                    self.chunk.push(byte);
                    consumed += 1;
                    if self.chunk.len() >= MIN_CHUNK_SIZE {
                        self.fingerprint = ((self.fingerprint << 1)
                            ^ self.table[usize::from(byte)])
                            & (AVG_CHUNK_SIZE as u64 - 1);
                        if self.fingerprint == 0 || self.chunk.len() == MAX_CHUNK_SIZE {
                            boundary = true;
                            break;
                        }
                    }
                }
            }
            self.reader.consume(consumed);
            if boundary {
                self.fingerprint = 0;
                return Ok(Some(std::mem::replace(
                    &mut self.chunk,
                    Vec::with_capacity(MIN_CHUNK_SIZE),
                )));
            }
        }
    }
}

fn gear_table() -> [u64; 256] {
    std::array::from_fn(|value| {
        let digest = Sha256::digest([b"Mosaic-Gear-v1/".as_slice(), &[7, value as u8]].concat());
        u64::from_be_bytes(
            digest[..8]
                .try_into()
                .expect("SHA-256 prefix has eight bytes"),
        ) & (AVG_CHUNK_SIZE as u64 - 1)
    })
}

fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0_u32; 256];
    for &byte in data {
        counts[usize::from(byte)] += 1;
    }
    let total = data.len() as f64;
    counts
        .into_iter()
        .filter(|count| *count != 0)
        .map(|count| {
            let probability = f64::from(count) / total;
            -probability * probability.log2()
        })
        .sum()
}

fn delta4(data: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(data.len());
    for (index, &byte) in data.iter().enumerate() {
        output.push(if index < 4 {
            byte
        } else {
            byte.wrapping_sub(data[index - 4])
        });
    }
    output
}

fn inverse_delta4(data: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(data.len());
    for (index, &byte) in data.iter().enumerate() {
        let value = if index < 4 {
            byte
        } else {
            byte.wrapping_add(output[index - 4])
        };
        output.push(value);
    }
    output
}

fn choose_lane(data: &[u8]) -> (Lane, Option<Vec<u8>>) {
    let byte_entropy = entropy(data);
    if byte_entropy >= 7.75 {
        (Lane::HighEntropy, None)
    } else if byte_entropy < 3.0 || data.len() <= 4 {
        (Lane::Standard, None)
    } else {
        let delta = delta4(data);
        if byte_entropy - entropy(&delta[4..]) >= 2.0 {
            (Lane::Delta4, Some(delta))
        } else {
            (Lane::Standard, None)
        }
    }
}

fn lzma2_options() -> Lzma2Options {
    let mut options = Lzma2Options::with_preset(LZMA2_PRESET);
    options.lzma_options.dict_size = LZMA2_DICT_SIZE;
    options
}

fn compress_lzma2(data: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut writer = Lzma2Writer::new(&mut output, lzma2_options());
    writer.write_all(data)?;
    writer.finish().map_err(Error::Io)?;
    Ok(output)
}

fn compress_for_lane(
    data: &[u8],
    lane: Lane,
    transformed: Option<&[u8]>,
) -> Result<(Codec, Vec<u8>)> {
    let candidate = match lane {
        Lane::Standard => (Codec::Lzma2, compress_lzma2(data)?),
        Lane::Delta4 => (
            Codec::Delta4Zstd,
            zstd::bulk::compress(
                transformed.ok_or(Error::Codec("delta4 route has no transformed bytes"))?,
                5,
            )
            .map_err(|_| Error::Codec("zstd encode failed"))?,
        ),
        Lane::HighEntropy => (
            Codec::Zstd,
            zstd::bulk::compress(data, 1).map_err(|_| Error::Codec("zstd encode failed"))?,
        ),
    };
    // Record headers are part of both exact encoded sizes. Ties select raw.
    let encoded_size = RECORD_SIZE
        .checked_add(candidate.1.len())
        .ok_or(Error::Codec("encoded record size overflow"))?;
    let raw_size = RECORD_SIZE
        .checked_add(data.len())
        .ok_or(Error::Codec("raw record size overflow"))?;
    if encoded_size < raw_size {
        Ok(candidate)
    } else {
        Ok((Codec::Raw, data.to_vec()))
    }
}

#[derive(Clone)]
struct DedupEntry {
    digest: [u8; 32],
    offset: u64,
    data: Arc<[u8]>,
}

struct DedupWindow {
    latest: HashMap<[u8; 32], DedupEntry>,
    ordered: VecDeque<DedupEntry>,
}

impl DedupWindow {
    fn new() -> Self {
        Self {
            latest: HashMap::new(),
            ordered: VecDeque::new(),
        }
    }

    fn prepare(&mut self, chunk: Vec<u8>, offset: u64) -> PreparedRecord {
        while self
            .ordered
            .front()
            .is_some_and(|entry| offset.saturating_sub(entry.offset) > DEDUP_WINDOW_SIZE as u64)
        {
            let expired = self.ordered.pop_front().expect("front entry exists");
            if self
                .latest
                .get(&expired.digest)
                .is_some_and(|entry| entry.offset == expired.offset)
            {
                self.latest.remove(&expired.digest);
            }
        }

        let digest: [u8; 32] = Sha256::digest(&chunk).into();
        let duplicate = self.latest.get(&digest).and_then(|entry| {
            (entry.data.as_ref() == chunk.as_slice()).then_some(offset - entry.offset)
        });
        let data: Arc<[u8]> = chunk.into();
        let entry = DedupEntry {
            digest,
            offset,
            data: Arc::clone(&data),
        };
        self.latest.insert(digest, entry.clone());
        self.ordered.push_back(entry);

        match duplicate {
            None => PreparedRecord::Data { data },
            Some(distance) => PreparedRecord::Reference {
                raw_len: data.len() as u32,
                distance,
            },
        }
    }
}

enum PreparedRecord {
    Data { data: Arc<[u8]> },
    Reference { raw_len: u32, distance: u64 },
}

enum EncodedRecord {
    Data {
        codec: Codec,
        raw_len: u32,
        payload: Vec<u8>,
    },
    Reference {
        raw_len: u32,
        distance: u64,
    },
}

fn encode_record(record: &PreparedRecord) -> Result<EncodedRecord> {
    match record {
        PreparedRecord::Data { data } => {
            let (lane, transformed) = choose_lane(data);
            let (codec, payload) = compress_for_lane(data, lane, transformed.as_deref())?;
            Ok(EncodedRecord::Data {
                codec,
                raw_len: data.len() as u32,
                payload,
            })
        }
        PreparedRecord::Reference { raw_len, distance } => Ok(EncodedRecord::Reference {
            raw_len: *raw_len,
            distance: *distance,
        }),
    }
}

fn write_header(writer: &mut impl Write) -> Result<()> {
    writer.write_all(&MAGIC)?;
    write_u32(writer, HEADER_SIZE as u32)?;
    write_u32(writer, MIN_CHUNK_SIZE as u32)?;
    write_u32(writer, AVG_CHUNK_SIZE as u32)?;
    write_u32(writer, MAX_CHUNK_SIZE as u32)?;
    write_u32(writer, MAX_SEGMENT_SIZE as u32)?;
    write_u32(writer, DEDUP_WINDOW_SIZE as u32)?;
    write_u32(writer, 0)?;
    Ok(())
}

/// Encode a byte stream into the non-stable M7R0 laboratory envelope.
///
/// Records are emitted in deterministic order even when multiple compression
/// workers are selected. The writer is direct: an error can leave a partial
/// envelope, so file-oriented callers should publish through a temporary file.
pub fn encode<R: Read, W: Write>(
    reader: R,
    mut writer: W,
    options: EncodeOptions,
) -> Result<StreamStats> {
    validate_encode_options(options)?;
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(options.threads)
        .build()
        .map_err(|_| Error::InvalidOptions("could not construct worker pool"))?;
    write_header(&mut writer)?;
    let mut encoded_bytes = HEADER_SIZE as u64;
    let mut stats = StreamStats::default();
    let mut original_hash = Sha256::new();
    let mut dedup = DedupWindow::new();
    let mut chunker = GearChunker::new(reader);
    let mut pending = None;
    let mut original_offset = 0_u64;

    loop {
        let first = match pending.take() {
            Some(chunk) => chunk,
            None => match chunker.next_chunk()? {
                Some(chunk) => chunk,
                None => break,
            },
        };
        let mut chunks = vec![first];
        let mut segment_size = chunks[0].len();
        while let Some(chunk) = chunker.next_chunk()? {
            if segment_size + chunk.len() > MAX_SEGMENT_SIZE {
                pending = Some(chunk);
                break;
            }
            segment_size += chunk.len();
            chunks.push(chunk);
        }
        if chunks.len() > MAX_RECORDS_PER_SEGMENT {
            return Err(Error::Codec("CDC produced too many records in one segment"));
        }
        let mut segment_hasher = Sha256::new();
        for chunk in &chunks {
            segment_hasher.update(chunk);
            original_hash.update(chunk);
        }
        let segment_hash: [u8; 32] = segment_hasher.finalize().into();
        let mut offset = original_offset;
        let prepared: Vec<_> = chunks
            .into_iter()
            .map(|chunk| {
                let record = dedup.prepare(chunk, offset);
                offset += u64::from(match &record {
                    PreparedRecord::Data { data } => data.len() as u32,
                    PreparedRecord::Reference { raw_len, .. } => *raw_len,
                });
                record
            })
            .collect();
        original_offset = offset;
        let records: Vec<EncodedRecord> = pool.install(|| {
            prepared
                .par_iter()
                .map(encode_record)
                .collect::<Result<Vec<_>>>()
        })?;

        let payload_len: usize = records
            .iter()
            .map(|record| match record {
                EncodedRecord::Data { payload, .. } => payload.len(),
                EncodedRecord::Reference { .. } => 0,
            })
            .sum();
        let next_segments = stats
            .segments
            .checked_add(1)
            .ok_or(Error::Codec("segment count exceeds the wire limit"))?;
        let next_records = stats
            .records
            .checked_add(records.len() as u64)
            .ok_or(Error::Codec("record count overflows"))?;
        let next_original_bytes = stats
            .original_bytes
            .checked_add(segment_size as u64)
            .ok_or(Error::Codec("decoded byte count overflows"))?;
        if next_original_bytes > options.max_input_bytes {
            return Err(Error::InvalidOptions("encode input byte limit is exceeded"));
        }
        let segment_encoded = 4 + SEGMENT_HEADER_REST + records.len() * RECORD_SIZE + payload_len;
        let next_encoded_bytes = encoded_bytes
            .checked_add(segment_encoded as u64)
            .ok_or(Error::Codec("encoded byte count overflows"))?;
        writer.write_all(&SEGMENT_TAG)?;
        write_u32(&mut writer, stats.segments)?;
        write_u32(&mut writer, segment_size as u32)?;
        write_u32(&mut writer, records.len() as u32)?;
        write_u32(&mut writer, (records.len() * RECORD_SIZE) as u32)?;
        write_u32(&mut writer, payload_len as u32)?;
        writer.write_all(&segment_hash)?;
        for record in &records {
            match record {
                EncodedRecord::Data {
                    codec,
                    raw_len,
                    payload,
                } => {
                    writer.write_all(&[0, *codec as u8])?;
                    writer.write_all(&[0, 0])?;
                    write_u32(&mut writer, *raw_len)?;
                    write_u64(&mut writer, payload.len() as u64)?;
                    match codec {
                        Codec::Raw => stats.raw_records += 1,
                        Codec::Lzma2 => stats.lzma2_records += 1,
                        Codec::Delta4Zstd => stats.delta_zstd_records += 1,
                        Codec::Zstd => stats.zstd_records += 1,
                    }
                }
                EncodedRecord::Reference { raw_len, distance } => {
                    writer.write_all(&[1, 0, 0, 0])?;
                    write_u32(&mut writer, *raw_len)?;
                    write_u64(&mut writer, *distance)?;
                    stats.deduplicated_records += 1;
                }
            }
        }
        for record in &records {
            if let EncodedRecord::Data { payload, .. } = record {
                writer.write_all(payload)?;
            }
        }
        encoded_bytes = next_encoded_bytes;
        stats.segments = next_segments;
        stats.records = next_records;
        stats.original_bytes = next_original_bytes;
    }

    writer.write_all(&FOOTER_TAG)?;
    write_u32(&mut writer, stats.segments)?;
    write_u64(&mut writer, stats.original_bytes)?;
    write_u64(&mut writer, stats.records)?;
    writer.write_all(&original_hash.finalize())?;
    encoded_bytes = encoded_bytes
        .checked_add((4 + FOOTER_REST) as u64)
        .ok_or(Error::Codec("encoded byte count overflows"))?;
    writer.flush()?;
    stats.encoded_bytes = encoded_bytes;
    Ok(stats)
}

#[derive(Clone, Copy)]
struct Descriptor {
    kind: u8,
    codec: Codec,
    raw_len: u32,
    value: u64,
}

struct DecodeHistory {
    ordered: VecDeque<u64>,
    by_offset: HashMap<u64, Arc<[u8]>>,
}

impl DecodeHistory {
    fn new() -> Self {
        Self {
            ordered: VecDeque::new(),
            by_offset: HashMap::new(),
        }
    }

    fn insert(&mut self, offset: u64, data: Arc<[u8]>) -> Result<()> {
        while self
            .ordered
            .front()
            .is_some_and(|old_offset| offset - *old_offset > DEDUP_WINDOW_SIZE as u64)
        {
            let old_offset = self.ordered.pop_front().expect("front entry exists");
            self.by_offset.remove(&old_offset);
        }
        if self.ordered.len() >= MAX_RECORDS_IN_DEDUP_WINDOW || self.by_offset.contains_key(&offset)
        {
            return Err(Error::InvalidFormat(
                "dedup history contains too many or duplicate records",
            ));
        }
        self.ordered.push_back(offset);
        self.by_offset.insert(offset, data);
        Ok(())
    }

    fn resolve(&self, source_offset: u64, raw_len: usize) -> Result<Arc<[u8]>> {
        self.by_offset
            .get(&source_offset)
            .filter(|data| data.len() == raw_len)
            .map(Arc::clone)
            .ok_or(Error::InvalidFormat(
                "dedup reference is outside the bounded history",
            ))
    }
}

fn decode_payload(codec: Codec, payload: &[u8], raw_len: usize) -> Result<Vec<u8>> {
    let output = match codec {
        Codec::Raw => payload.to_vec(),
        Codec::Lzma2 => {
            let cursor = Cursor::new(payload);
            let reader = Lzma2Reader::new(cursor, LZMA2_DICT_SIZE, None);
            let mut limited = reader.take(raw_len as u64 + 1);
            let mut decoded = Vec::with_capacity(raw_len.min(MAX_CHUNK_SIZE));
            limited
                .read_to_end(&mut decoded)
                .map_err(|_| Error::InvalidFormat("LZMA2 payload is malformed"))?;
            let reader = limited.into_inner();
            if reader.into_inner().position() != payload.len() as u64 {
                return Err(Error::InvalidFormat("LZMA2 payload has trailing bytes"));
            }
            decoded
        }
        Codec::Delta4Zstd | Codec::Zstd => {
            let decoded = zstd::bulk::decompress(payload, raw_len + 1)
                .map_err(|_| Error::InvalidFormat("zstd payload is malformed"))?;
            if codec == Codec::Delta4Zstd {
                inverse_delta4(&decoded)
            } else {
                decoded
            }
        }
    };
    if output.len() != raw_len {
        return Err(Error::InvalidFormat("decoded record size is inconsistent"));
    }
    Ok(output)
}

/// Decode with the conservative default resource ceilings.
///
/// M7R0 hashes detect accidental corruption but are not authenticators. Output
/// is verified one segment at a time; if a later segment or footer fails,
/// earlier segments remain written to `writer`.
pub fn decode<R: Read, W: Write>(reader: R, writer: W) -> Result<StreamStats> {
    decode_with_options(reader, writer, DecodeOptions::default())
}

/// Decode with explicit total-output, input, record, segment, and expansion
/// ceilings.
///
/// The same segment-atomic and non-authenticating caveats as [`decode`] apply.
pub fn decode_with_options<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    options: DecodeOptions,
) -> Result<StreamStats> {
    validate_decode_options(options)?;
    let mut header = [0_u8; HEADER_SIZE];
    read_exact_format(&mut reader, &mut header, "header is truncated")?;
    if header[..4] != MAGIC
        || parse_u32(&header[4..8]) != HEADER_SIZE as u32
        || parse_u32(&header[8..12]) != MIN_CHUNK_SIZE as u32
        || parse_u32(&header[12..16]) != AVG_CHUNK_SIZE as u32
        || parse_u32(&header[16..20]) != MAX_CHUNK_SIZE as u32
        || parse_u32(&header[20..24]) != MAX_SEGMENT_SIZE as u32
        || parse_u32(&header[24..28]) != DEDUP_WINDOW_SIZE as u32
        || parse_u32(&header[28..32]) != 0
    {
        return Err(Error::InvalidFormat("header is unsupported or malformed"));
    }

    let mut stats = StreamStats {
        encoded_bytes: HEADER_SIZE as u64,
        ..StreamStats::default()
    };
    let mut history = DecodeHistory::new();
    let mut stream_hash = Sha256::new();
    let mut output_offset = 0_u64;
    loop {
        let mut tag = [0_u8; 4];
        read_exact_format(&mut reader, &mut tag, "stream terminator is missing")?;
        stats.encoded_bytes = stats
            .encoded_bytes
            .checked_add(4)
            .ok_or(Error::InvalidFormat("encoded byte count overflows"))?;
        if stats.encoded_bytes > options.max_encoded_bytes {
            return Err(Error::InvalidFormat("encoded byte limit is exceeded"));
        }
        if tag == FOOTER_TAG {
            let footer_encoded_bytes = stats
                .encoded_bytes
                .checked_add(FOOTER_REST as u64)
                .ok_or(Error::InvalidFormat("encoded byte count overflows"))?;
            if footer_encoded_bytes > options.max_encoded_bytes {
                return Err(Error::InvalidFormat("encoded byte limit is exceeded"));
            }
            let mut footer = [0_u8; FOOTER_REST];
            read_exact_format(&mut reader, &mut footer, "footer is truncated")?;
            stats.encoded_bytes = footer_encoded_bytes;
            if parse_u32(&footer[..4]) != stats.segments
                || parse_u64(&footer[4..12]) != stats.original_bytes
                || parse_u64(&footer[12..20]) != stats.records
                || footer[20..52] != stream_hash.finalize()[..]
            {
                return Err(Error::InvalidFormat(
                    "footer totals or digest are inconsistent",
                ));
            }
            let mut trailing = [0_u8; 1];
            if reader.read(&mut trailing)? != 0 {
                return Err(Error::InvalidFormat("trailing bytes follow the footer"));
            }
            writer.flush()?;
            return Ok(stats);
        }
        if tag != SEGMENT_TAG {
            return Err(Error::InvalidFormat("segment tag is invalid"));
        }
        let mut segment_header = [0_u8; SEGMENT_HEADER_REST];
        read_exact_format(
            &mut reader,
            &mut segment_header,
            "segment header is truncated",
        )?;
        stats.encoded_bytes = stats
            .encoded_bytes
            .checked_add(SEGMENT_HEADER_REST as u64)
            .ok_or(Error::InvalidFormat("encoded byte count overflows"))?;
        let index = parse_u32(&segment_header[..4]);
        let decoded_len = parse_u32(&segment_header[4..8]) as usize;
        let record_count = parse_u32(&segment_header[8..12]) as usize;
        let descriptor_len = parse_u32(&segment_header[12..16]) as usize;
        let payload_len = parse_u32(&segment_header[16..20]) as usize;
        let expected_hash = &segment_header[20..52];
        if index != stats.segments
            || decoded_len == 0
            || decoded_len > MAX_SEGMENT_SIZE
            || record_count == 0
            || record_count > MAX_RECORDS_PER_SEGMENT
            || descriptor_len != record_count * RECORD_SIZE
            || payload_len > decoded_len
        {
            return Err(Error::InvalidFormat("segment bounds are invalid"));
        }
        let next_segments = stats
            .segments
            .checked_add(1)
            .ok_or(Error::InvalidFormat("segment count overflows"))?;
        let next_records = stats
            .records
            .checked_add(record_count as u64)
            .ok_or(Error::InvalidFormat("record count overflows"))?;
        let next_output_bytes = stats
            .original_bytes
            .checked_add(decoded_len as u64)
            .ok_or(Error::InvalidFormat("decoded byte count overflows"))?;
        let next_encoded_bytes = stats
            .encoded_bytes
            .checked_add(descriptor_len as u64)
            .and_then(|size| size.checked_add(payload_len as u64))
            .ok_or(Error::InvalidFormat("encoded byte count overflows"))?;
        let expansion_limit = next_encoded_bytes
            .saturating_mul(options.max_expansion_ratio)
            .saturating_add(MAX_SEGMENT_SIZE as u64);
        if next_segments > options.max_segments
            || next_records > options.max_records
            || next_output_bytes > options.max_output_bytes
            || next_encoded_bytes > options.max_encoded_bytes
            || next_output_bytes > expansion_limit
        {
            return Err(Error::InvalidFormat("decode resource ceiling is exceeded"));
        }
        let mut descriptor_bytes = vec![0_u8; descriptor_len];
        read_exact_format(
            &mut reader,
            &mut descriptor_bytes,
            "record table is truncated",
        )?;
        let mut descriptors = Vec::with_capacity(record_count);
        let mut raw_total = 0_usize;
        let mut payload_total = 0_usize;
        for bytes in descriptor_bytes.chunks_exact(RECORD_SIZE) {
            if bytes[2] != 0 || bytes[3] != 0 {
                return Err(Error::InvalidFormat("record reserved bits are nonzero"));
            }
            let kind = bytes[0];
            let codec = Codec::parse(bytes[1])?;
            let raw_len = parse_u32(&bytes[4..8]);
            let value = parse_u64(&bytes[8..16]);
            if raw_len == 0 || raw_len as usize > MAX_CHUNK_SIZE {
                return Err(Error::InvalidFormat("record decoded size is invalid"));
            }
            raw_total = raw_total
                .checked_add(raw_len as usize)
                .ok_or(Error::InvalidFormat("segment decoded size overflows"))?;
            match kind {
                0 => {
                    if value == 0 || value > u64::from(raw_len) {
                        return Err(Error::InvalidFormat("record payload size is invalid"));
                    }
                    payload_total = payload_total
                        .checked_add(value as usize)
                        .ok_or(Error::InvalidFormat("segment payload size overflows"))?;
                }
                1 => {
                    if codec != Codec::Raw || value == 0 || value > DEDUP_WINDOW_SIZE as u64 {
                        return Err(Error::InvalidFormat("dedup record is invalid"));
                    }
                }
                _ => return Err(Error::InvalidFormat("record kind is unknown")),
            }
            descriptors.push(Descriptor {
                kind,
                codec,
                raw_len,
                value,
            });
        }
        if raw_total != decoded_len || payload_total != payload_len {
            return Err(Error::InvalidFormat("segment totals are inconsistent"));
        }

        let mut segment = Vec::with_capacity(decoded_len);
        for descriptor in descriptors {
            let chunk = if descriptor.kind == 0 {
                let mut payload = vec![0_u8; descriptor.value as usize];
                read_exact_format(&mut reader, &mut payload, "record payload is truncated")?;
                let decoded =
                    decode_payload(descriptor.codec, &payload, descriptor.raw_len as usize)?;
                match descriptor.codec {
                    Codec::Raw => stats.raw_records += 1,
                    Codec::Lzma2 => stats.lzma2_records += 1,
                    Codec::Delta4Zstd => stats.delta_zstd_records += 1,
                    Codec::Zstd => stats.zstd_records += 1,
                }
                Arc::<[u8]>::from(decoded)
            } else {
                if descriptor.value > output_offset {
                    return Err(Error::InvalidFormat(
                        "dedup reference points before the stream",
                    ));
                }
                stats.deduplicated_records += 1;
                history.resolve(
                    output_offset - descriptor.value,
                    descriptor.raw_len as usize,
                )?
            };
            segment.extend_from_slice(&chunk);
            history.insert(output_offset, Arc::clone(&chunk))?;
            output_offset = output_offset
                .checked_add(chunk.len() as u64)
                .ok_or(Error::InvalidFormat("decoded byte offset overflows"))?;
        }
        stats.encoded_bytes = next_encoded_bytes;
        if Sha256::digest(&segment)[..] != *expected_hash {
            return Err(Error::InvalidFormat("segment digest is inconsistent"));
        }
        writer.write_all(&segment)?;
        stream_hash.update(&segment);
        stats.original_bytes = next_output_bytes;
        stats.records = next_records;
        stats.segments = next_segments;
    }
}

fn read_exact_format(
    reader: &mut impl Read,
    buffer: &mut [u8],
    message: &'static str,
) -> Result<()> {
    reader.read_exact(buffer).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            Error::InvalidFormat(message)
        } else {
            Error::Io(error)
        }
    })
}

fn parse_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("field has four bytes"))
}

fn parse_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("field has eight bytes"))
}

fn write_u32(writer: &mut impl Write, value: u32) -> Result<()> {
    writer.write_all(&value.to_le_bytes())?;
    Ok(())
}

fn write_u64(writer: &mut impl Write, value: u64) -> Result<()> {
    writer.write_all(&value.to_le_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus() -> Vec<u8> {
        let mut data = Vec::new();
        for index in 0..120_000_u32 {
            data.extend_from_slice(format!("row={index:08},value={}\n", index % 97).as_bytes());
        }
        data.extend_from_within(..512 * 1024);
        data
    }

    #[test]
    fn round_trip_and_thread_count_are_deterministic() -> Result<()> {
        let input = corpus();
        let mut one = Vec::new();
        let mut eight = Vec::new();
        let one_stats = encode(
            input.as_slice(),
            &mut one,
            EncodeOptions {
                threads: 1,
                ..EncodeOptions::default()
            },
        )?;
        let eight_stats = encode(
            input.as_slice(),
            &mut eight,
            EncodeOptions {
                threads: 8,
                ..EncodeOptions::default()
            },
        )?;
        assert_eq!(one, eight);
        assert_eq!(one_stats, eight_stats);
        let mut output = Vec::new();
        let decoded = decode(one.as_slice(), &mut output)?;
        assert_eq!(output, input);
        assert_eq!(decoded.original_bytes, input.len() as u64);
        Ok(())
    }

    #[test]
    fn backward_dedup_is_used() -> Result<()> {
        let block = vec![b'x'; MAX_CHUNK_SIZE];
        let input = [block.as_slice(), block.as_slice(), block.as_slice()].concat();
        let mut archive = Vec::new();
        let stats = encode(input.as_slice(), &mut archive, EncodeOptions::default())?;
        assert!(stats.deduplicated_records >= 1);
        let mut output = Vec::new();
        decode(archive.as_slice(), &mut output)?;
        assert_eq!(output, input);
        Ok(())
    }

    #[test]
    fn default_limits_round_trip_high_dedup_output() -> Result<()> {
        let block = vec![b'x'; MAX_CHUNK_SIZE];
        let input = block.repeat(80);
        let mut archive = Vec::new();
        let encoded = encode(input.as_slice(), &mut archive, EncodeOptions::default())?;
        assert!(encoded.deduplicated_records > 32);
        let mut output = Vec::new();
        decode(archive.as_slice(), &mut output)?;
        assert_eq!(output, input);
        Ok(())
    }

    #[test]
    fn every_truncation_fails_closed() -> Result<()> {
        let input = b"a bounded truncation test".repeat(1000);
        let mut archive = Vec::new();
        encode(input.as_slice(), &mut archive, EncodeOptions::default())?;
        for end in 0..archive.len() {
            assert!(
                decode(&archive[..end], io::sink()).is_err(),
                "accepted prefix {end}"
            );
        }
        Ok(())
    }

    #[test]
    fn malformed_and_oversized_streams_fail_closed() -> Result<()> {
        let mut archive = Vec::new();
        encode(b"hello".as_slice(), &mut archive, EncodeOptions::default())?;
        archive[40..44].copy_from_slice(&((MAX_SEGMENT_SIZE as u32) + 1).to_le_bytes());
        assert!(decode(archive.as_slice(), io::sink()).is_err());

        let mut archive = Vec::new();
        encode(b"hello".as_slice(), &mut archive, EncodeOptions::default())?;
        archive.push(0);
        assert!(decode(archive.as_slice(), io::sink()).is_err());
        Ok(())
    }

    #[test]
    fn explicit_decode_output_limit_fails_before_segment_output() -> Result<()> {
        let input = b"bounded output".repeat(1024);
        let mut archive = Vec::new();
        encode(input.as_slice(), &mut archive, EncodeOptions::default())?;
        let options = DecodeOptions {
            max_output_bytes: (input.len() - 1) as u64,
            ..DecodeOptions::default()
        };
        let mut output = Vec::new();
        assert!(decode_with_options(archive.as_slice(), &mut output, options).is_err());
        assert!(output.is_empty());
        Ok(())
    }

    #[test]
    fn tiny_record_history_is_bounded_and_constant_time() -> Result<()> {
        let mut history = DecodeHistory::new();
        for offset in 0..MAX_RECORDS_IN_DEDUP_WINDOW {
            history.insert(offset as u64, Arc::<[u8]>::from([offset as u8]))?;
        }
        assert_eq!(
            history
                .resolve((MAX_RECORDS_IN_DEDUP_WINDOW - 1) as u64, 1)?
                .len(),
            1
        );
        assert!(
            history
                .insert(MAX_RECORDS_IN_DEDUP_WINDOW as u64, Arc::<[u8]>::from([0]),)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn corrupted_segment_is_rejected_before_segment_output() -> Result<()> {
        let mut archive = Vec::new();
        encode(b"hello".as_slice(), &mut archive, EncodeOptions::default())?;
        archive[HEADER_SIZE + 4 + SEGMENT_HEADER_REST + RECORD_SIZE] ^= 0x80;
        let mut output = Vec::new();
        assert!(decode(archive.as_slice(), &mut output).is_err());
        assert!(output.is_empty());
        Ok(())
    }

    #[test]
    fn empty_stream_round_trips() -> Result<()> {
        let mut archive = Vec::new();
        let encoded = encode(io::empty(), &mut archive, EncodeOptions::default())?;
        let mut output = Vec::new();
        let decoded = decode(archive.as_slice(), &mut output)?;
        assert!(output.is_empty());
        assert_eq!(encoded.original_bytes, 0);
        assert_eq!(decoded.segments, 0);
        Ok(())
    }

    #[test]
    fn gear_boundaries_match_the_python_mosaic_gear_v1_reference() -> Result<()> {
        let data: Vec<u8> = (0..2 * 1024 * 1024_usize)
            .map(|index| {
                ((index.wrapping_mul(1_315_423_911))
                    ^ (index >> 7)
                    ^ (index.wrapping_mul(index) >> 13)) as u8
            })
            .collect();
        let mut chunker = GearChunker::new(data.as_slice());
        let mut sizes = Vec::new();
        while let Some(chunk) = chunker.next_chunk()? {
            sizes.push(chunk.len());
        }
        assert_eq!(
            sizes,
            [
                69_116, 75_317, 76_215, 82_948, 67_099, 20_109, 39_179, 18_524, 62_764, 16_592,
                33_839, 141_807, 127_800, 80_201, 52_938, 64_846, 88_398, 75_317, 76_215, 82_948,
                67_099, 20_109, 39_179, 18_524, 62_764, 16_592, 33_839, 141_807, 127_800, 80_201,
                52_938, 64_846, 19_282,
            ]
        );
        Ok(())
    }

    #[test]
    fn router_selects_all_three_content_lanes() {
        let standard = b"the quick brown fox jumps over the lazy dog\n".repeat(2000);
        let delta: Vec<u8> = (0..40_000_u32).flat_map(u32::to_le_bytes).collect();
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let high: Vec<u8> = (0..64 * 1024)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        assert_eq!(choose_lane(&standard).0, Lane::Standard);
        assert_eq!(choose_lane(&delta).0, Lane::Delta4);
        assert_eq!(choose_lane(&high).0, Lane::HighEntropy);
    }

    #[test]
    fn delta_lane_is_materially_encoded_and_round_trips() -> Result<()> {
        let input: Vec<u8> = (0..250_000_u32).flat_map(u32::to_le_bytes).collect();
        let mut archive = Vec::new();
        let stats = encode(
            input.as_slice(),
            &mut archive,
            EncodeOptions {
                threads: 8,
                ..EncodeOptions::default()
            },
        )?;
        assert!(stats.delta_zstd_records > 0);
        let mut output = Vec::new();
        decode(archive.as_slice(), &mut output)?;
        assert_eq!(output, input);
        Ok(())
    }
}
