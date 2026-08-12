use std::io;

use sha2::{Digest, Sha256};

use crate::{Error, Result};

/// Magic prefix for the explicitly non-stable authenticated native preview.
pub const AUTHENTICATED_MAGIC: [u8; 4] = *b"M7A0";
pub(crate) const HEADER_SIZE: usize = 64;
pub(crate) const RECORD_HEADER_SIZE: usize = 16;
pub(crate) const AEAD_TAG_SIZE: usize = 16;
pub(crate) const PADDING_QUANTUM: usize = 1024;
pub(crate) const MAX_RECORD_PLAINTEXT: usize = 2 * 1024 * 1024;
const DATA_PREFIX_SIZE: usize = 8;
pub(crate) const MAX_DATA_PAYLOAD: usize = MAX_RECORD_PLAINTEXT - DATA_PREFIX_SIZE;
pub(crate) const MIN_KDF_LOG_N: u8 = 14;
pub(crate) const MAX_KDF_LOG_N: u8 = 18;
pub(crate) const DEFAULT_KDF_LOG_N: u8 = 17;
pub(crate) const KDF_R: u32 = 8;
pub(crate) const KDF_P: u32 = 1;
pub(crate) const DATA_RECORD_KIND: u8 = 1;
pub(crate) const FOOTER_RECORD_KIND: u8 = 2;
pub(crate) const FOOTER_PLAINTEXT_SIZE: usize = 112;
pub(crate) const AEAD_AAD_DOMAIN: &[u8] = b"Mosaic-M7A0-AAD/v0\0";
pub(crate) const TRANSCRIPT_DOMAIN: &[u8] = b"Mosaic-M7A0-transcript/v0\0";

const VERSION: u8 = 0;
const FLAGS: u8 = 3;
const KDF_ID: u8 = 1;
const AEAD_ID: u8 = 1;
const CORE_ID: u8 = 0;
const PROFILE_ID: u8 = 0;
const DATA_MAGIC: [u8; 4] = *b"M7D0";
const FOOTER_MAGIC: [u8; 4] = *b"M7F0";

#[derive(Clone, Debug)]
pub(crate) struct Header {
    bytes: [u8; HEADER_SIZE],
    salt: [u8; 16],
    nonce_prefix: [u8; 4],
    kdf_log_n: u8,
}

impl Header {
    pub(crate) fn from_parts(salt: [u8; 16], nonce_prefix: [u8; 4], kdf_log_n: u8) -> Result<Self> {
        validate_kdf_log_n(kdf_log_n, Error::InvalidOptions)?;
        let bytes = serialize_header(salt, nonce_prefix, kdf_log_n);
        Ok(Self {
            bytes,
            salt,
            nonce_prefix,
            kdf_log_n,
        })
    }

    pub(crate) fn generate(kdf_log_n: u8) -> Result<Self> {
        let mut salt = [0_u8; 16];
        let mut nonce_prefix = [0_u8; 4];
        fill_random(&mut salt)?;
        fill_random(&mut nonce_prefix)?;
        Self::from_parts(salt, nonce_prefix, kdf_log_n)
    }

    pub(crate) fn parse(bytes: [u8; HEADER_SIZE]) -> Result<Self> {
        if bytes[..4] != AUTHENTICATED_MAGIC
            || bytes[4] != VERSION
            || bytes[5] != FLAGS
            || bytes[6] != KDF_ID
            || bytes[7] != AEAD_ID
            || bytes[8] != CORE_ID
            || bytes[9] != PROFILE_ID
            || parse_u16(&bytes[10..12]) != 0
            || parse_u32(&bytes[12..16]) != HEADER_SIZE as u32
            || parse_u32(&bytes[16..20]) != PADDING_QUANTUM as u32
            || parse_u32(&bytes[20..24]) != MAX_RECORD_PLAINTEXT as u32
            || bytes[47] != 0
            || bytes[48..64] != [0_u8; 16]
        {
            return Err(Error::InvalidFormat(
                "authenticated header is unsupported or malformed",
            ));
        }
        let kdf_log_n = bytes[44];
        validate_kdf_log_n(kdf_log_n, Error::InvalidFormat)?;
        if u32::from(bytes[45]) != KDF_R || u32::from(bytes[46]) != KDF_P {
            return Err(Error::InvalidFormat(
                "authenticated KDF parameters are unsupported",
            ));
        }
        let mut salt = [0_u8; 16];
        salt.copy_from_slice(&bytes[24..40]);
        let mut nonce_prefix = [0_u8; 4];
        nonce_prefix.copy_from_slice(&bytes[40..44]);
        Ok(Self {
            bytes,
            salt,
            nonce_prefix,
            kdf_log_n,
        })
    }

    pub(crate) fn bytes(&self) -> &[u8; HEADER_SIZE] {
        &self.bytes
    }

    pub(crate) fn salt(&self) -> &[u8; 16] {
        &self.salt
    }

    pub(crate) fn nonce_prefix(&self) -> [u8; 4] {
        self.nonce_prefix
    }

    pub(crate) fn kdf_log_n(&self) -> u8 {
        self.kdf_log_n
    }
}

fn serialize_header(salt: [u8; 16], nonce_prefix: [u8; 4], kdf_log_n: u8) -> [u8; HEADER_SIZE] {
    let mut bytes = [0_u8; HEADER_SIZE];
    bytes[..4].copy_from_slice(&AUTHENTICATED_MAGIC);
    bytes[4] = VERSION;
    bytes[5] = FLAGS;
    bytes[6] = KDF_ID;
    bytes[7] = AEAD_ID;
    bytes[8] = CORE_ID;
    bytes[9] = PROFILE_ID;
    bytes[12..16].copy_from_slice(&(HEADER_SIZE as u32).to_be_bytes());
    bytes[16..20].copy_from_slice(&(PADDING_QUANTUM as u32).to_be_bytes());
    bytes[20..24].copy_from_slice(&(MAX_RECORD_PLAINTEXT as u32).to_be_bytes());
    bytes[24..40].copy_from_slice(&salt);
    bytes[40..44].copy_from_slice(&nonce_prefix);
    bytes[44] = kdf_log_n;
    bytes[45] = KDF_R as u8;
    bytes[46] = KDF_P as u8;
    bytes
}

fn validate_kdf_log_n(kdf_log_n: u8, error: fn(&'static str) -> Error) -> Result<()> {
    if !(MIN_KDF_LOG_N..=MAX_KDF_LOG_N).contains(&kdf_log_n) {
        return Err(error("scrypt log N must be in 14..=18"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RecordHeader {
    bytes: [u8; RECORD_HEADER_SIZE],
    index: u64,
    kind: u8,
    ciphertext_len: usize,
}

impl RecordHeader {
    pub(crate) fn new(index: u64, kind: u8, ciphertext_len: usize) -> Result<Self> {
        if kind != DATA_RECORD_KIND && kind != FOOTER_RECORD_KIND {
            return Err(Error::Codec("authenticated record kind is invalid"));
        }
        let encoded_len = u32::try_from(ciphertext_len)
            .map_err(|_| Error::Codec("authenticated record is too large"))?;
        let mut bytes = [0_u8; RECORD_HEADER_SIZE];
        bytes[..8].copy_from_slice(&index.to_be_bytes());
        bytes[8] = kind;
        bytes[12..16].copy_from_slice(&encoded_len.to_be_bytes());
        Ok(Self {
            bytes,
            index,
            kind,
            ciphertext_len,
        })
    }

    pub(crate) fn parse(bytes: [u8; RECORD_HEADER_SIZE]) -> Result<Self> {
        let index = parse_u64(&bytes[..8]);
        let kind = bytes[8];
        if (kind != DATA_RECORD_KIND && kind != FOOTER_RECORD_KIND)
            || bytes[9] != 0
            || parse_u16(&bytes[10..12]) != 0
        {
            return Err(Error::InvalidFormat(
                "authenticated record header is malformed",
            ));
        }
        let ciphertext_len = parse_u32(&bytes[12..16]) as usize;
        Ok(Self {
            bytes,
            index,
            kind,
            ciphertext_len,
        })
    }

    pub(crate) fn bytes(&self) -> &[u8; RECORD_HEADER_SIZE] {
        &self.bytes
    }

    pub(crate) fn index(self) -> u64 {
        self.index
    }

    pub(crate) fn kind(self) -> u8 {
        self.kind
    }

    pub(crate) fn ciphertext_len(self) -> usize {
        self.ciphertext_len
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Footer {
    pub(crate) core_record_count: u64,
    pub(crate) core_plaintext_bytes: u64,
    pub(crate) original_bytes: u64,
    pub(crate) segments: u32,
    pub(crate) inner_records: u64,
    pub(crate) inner_hash: [u8; 32],
    pub(crate) transcript_hash: [u8; 32],
}

impl Footer {
    pub(crate) fn serialize(self) -> [u8; FOOTER_PLAINTEXT_SIZE] {
        let mut bytes = [0_u8; FOOTER_PLAINTEXT_SIZE];
        bytes[..4].copy_from_slice(&FOOTER_MAGIC);
        bytes[4] = VERSION;
        bytes[8..16].copy_from_slice(&self.core_record_count.to_be_bytes());
        bytes[16..24].copy_from_slice(&self.core_plaintext_bytes.to_be_bytes());
        bytes[24..32].copy_from_slice(&self.original_bytes.to_be_bytes());
        bytes[32..36].copy_from_slice(&self.segments.to_be_bytes());
        bytes[40..48].copy_from_slice(&self.inner_records.to_be_bytes());
        bytes[48..80].copy_from_slice(&self.inner_hash);
        bytes[80..112].copy_from_slice(&self.transcript_hash);
        bytes
    }

    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != FOOTER_PLAINTEXT_SIZE
            || bytes[..4] != FOOTER_MAGIC
            || bytes[4] != VERSION
            || bytes[5..8] != [0_u8; 3]
            || parse_u32(&bytes[36..40]) != 0
        {
            return Err(Error::InvalidFormat(
                "authenticated footer is unsupported or malformed",
            ));
        }
        let mut inner_hash = [0_u8; 32];
        inner_hash.copy_from_slice(&bytes[48..80]);
        let mut transcript_hash = [0_u8; 32];
        transcript_hash.copy_from_slice(&bytes[80..112]);
        Ok(Self {
            core_record_count: parse_u64(&bytes[8..16]),
            core_plaintext_bytes: parse_u64(&bytes[16..24]),
            original_bytes: parse_u64(&bytes[24..32]),
            segments: parse_u32(&bytes[32..36]),
            inner_records: parse_u64(&bytes[40..48]),
            inner_hash,
            transcript_hash,
        })
    }
}

pub(crate) fn data_plaintext(mut payload: Vec<u8>) -> Result<(Vec<u8>, u64)> {
    if payload.is_empty() || payload.len() > MAX_DATA_PAYLOAD {
        return Err(Error::Codec(
            "authenticated data payload must be nonempty and within the limit",
        ));
    }
    let base_len = DATA_PREFIX_SIZE
        .checked_add(payload.len())
        .ok_or(Error::Codec("authenticated plaintext size overflows"))?;
    let padded_len = padded_len(base_len)?;
    let padding_len = padded_len - base_len;
    let payload_len = payload.len();
    let mut plaintext = Vec::with_capacity(padded_len);
    plaintext.extend_from_slice(&DATA_MAGIC);
    plaintext.extend_from_slice(
        &u32::try_from(payload_len)
            .map_err(|_| Error::Codec("authenticated data payload is too large"))?
            .to_be_bytes(),
    );
    plaintext.append(&mut payload);
    plaintext.resize(padded_len, 0);
    fill_random(&mut plaintext[base_len..])?;
    Ok((plaintext, padding_len as u64))
}

pub(crate) fn parse_data_plaintext(plaintext: Vec<u8>) -> Result<(Vec<u8>, u64)> {
    if plaintext.len() < PADDING_QUANTUM
        || !plaintext.len().is_multiple_of(PADDING_QUANTUM)
        || plaintext[..4] != DATA_MAGIC
    {
        return Err(Error::InvalidFormat(
            "authenticated data plaintext is malformed",
        ));
    }
    let payload_len = parse_u32(&plaintext[4..8]) as usize;
    if payload_len == 0 || payload_len > MAX_DATA_PAYLOAD {
        return Err(Error::InvalidFormat(
            "authenticated data payload must be nonempty and within the limit",
        ));
    }
    let base_len = DATA_PREFIX_SIZE
        .checked_add(payload_len)
        .ok_or(Error::InvalidFormat(
            "authenticated data payload size overflows",
        ))?;
    if base_len > plaintext.len() || padded_len(base_len)? != plaintext.len() {
        return Err(Error::InvalidFormat(
            "authenticated data padding is malformed",
        ));
    }
    let padding_len = plaintext.len() - base_len;
    Ok((
        plaintext[DATA_PREFIX_SIZE..base_len].to_vec(),
        padding_len as u64,
    ))
}

pub(crate) fn padded_footer(footer: Footer) -> Result<(Vec<u8>, u64)> {
    let bytes = footer.serialize();
    let padded_len = padded_len(bytes.len())?;
    let padding_len = padded_len - bytes.len();
    let mut plaintext = vec![0_u8; padded_len];
    plaintext[..bytes.len()].copy_from_slice(&bytes);
    fill_random(&mut plaintext[bytes.len()..])?;
    Ok((plaintext, padding_len as u64))
}

pub(crate) fn parse_padded_footer(plaintext: &[u8]) -> Result<(Footer, u64)> {
    let expected_len = padded_len(FOOTER_PLAINTEXT_SIZE)?;
    if plaintext.len() != expected_len {
        return Err(Error::InvalidFormat(
            "authenticated footer padding is malformed",
        ));
    }
    let footer = Footer::parse(&plaintext[..FOOTER_PLAINTEXT_SIZE])?;
    Ok((footer, (expected_len - FOOTER_PLAINTEXT_SIZE) as u64))
}

pub(crate) fn max_data_ciphertext_len() -> Result<usize> {
    padded_len(
        DATA_PREFIX_SIZE
            .checked_add(MAX_DATA_PAYLOAD)
            .ok_or(Error::InvalidFormat("authenticated record size overflows"))?,
    )?
    .checked_add(AEAD_TAG_SIZE)
    .ok_or(Error::InvalidFormat(
        "authenticated ciphertext size overflows",
    ))
}

pub(crate) fn footer_ciphertext_len() -> Result<usize> {
    padded_len(FOOTER_PLAINTEXT_SIZE)?
        .checked_add(AEAD_TAG_SIZE)
        .ok_or(Error::InvalidFormat("authenticated footer size overflows"))
}

pub(crate) fn nonce(prefix: [u8; 4], index: u64) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[..4].copy_from_slice(&prefix);
    nonce[4..].copy_from_slice(&index.to_be_bytes());
    nonce
}

pub(crate) fn aad(header: &Header, record: RecordHeader) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AEAD_AAD_DOMAIN.len() + HEADER_SIZE + RECORD_HEADER_SIZE);
    aad.extend_from_slice(AEAD_AAD_DOMAIN);
    aad.extend_from_slice(header.bytes());
    aad.extend_from_slice(record.bytes());
    aad
}

pub(crate) fn new_transcript(header: &Header) -> Sha256 {
    let mut transcript = Sha256::new();
    transcript.update(TRANSCRIPT_DOMAIN);
    transcript.update(header.bytes());
    transcript
}

fn padded_len(size: usize) -> Result<usize> {
    let remainder = size % PADDING_QUANTUM;
    let padding = if remainder == 0 {
        0
    } else {
        PADDING_QUANTUM - remainder
    };
    size.checked_add(padding)
        .ok_or(Error::InvalidFormat("authenticated padding size overflows"))
}

fn fill_random(buffer: &mut [u8]) -> Result<()> {
    getrandom::fill(buffer).map_err(|_| {
        Error::Io(io::Error::other(
            "operating-system secure randomness is unavailable",
        ))
    })
}

fn parse_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes(bytes.try_into().expect("field has two bytes"))
}

fn parse_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes.try_into().expect("field has four bytes"))
}

fn parse_u64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().expect("field has eight bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_bytes(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|digits| {
                let digits = std::str::from_utf8(digits).expect("test vector is ASCII");
                u8::from_str_radix(digits, 16).expect("test vector is hexadecimal")
            })
            .collect()
    }

    #[test]
    fn header_has_the_exact_big_endian_layout() -> Result<()> {
        let header = Header::from_parts(
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f,
            ],
            [0xaa, 0xbb, 0xcc, 0xdd],
            14,
        )?;
        let expected = hex_bytes(concat!(
            "4d3741300003010100000000",
            "00000040",
            "00000400",
            "00200000",
            "000102030405060708090a0b0c0d0e0f",
            "aabbccdd",
            "0e080100",
            "00000000000000000000000000000000"
        ));
        assert_eq!(header.bytes().as_slice(), expected);
        assert_eq!(Header::parse(*header.bytes())?.bytes(), header.bytes());
        Ok(())
    }

    #[test]
    fn nonce_vectors_cover_first_second_and_last_index() {
        let prefix = [0xa0, 0xb1, 0xc2, 0xd3];
        assert_eq!(
            nonce(prefix, 0),
            [0xa0, 0xb1, 0xc2, 0xd3, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            nonce(prefix, 1),
            [0xa0, 0xb1, 0xc2, 0xd3, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert_eq!(
            nonce(prefix, u64::MAX),
            [
                0xa0, 0xb1, 0xc2, 0xd3, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
            ]
        );
    }

    #[test]
    fn record_header_is_big_endian_and_rejects_flags_and_reserved_bits() -> Result<()> {
        let record = RecordHeader::new(0x0102_0304_0506_0708, DATA_RECORD_KIND, 0x1020_3040)?;
        assert_eq!(
            record.bytes().as_slice(),
            hex_bytes("01020304050607080100000010203040")
        );
        assert_eq!(
            RecordHeader::parse(*record.bytes())?.index(),
            record.index()
        );

        let mut changed_flags = *record.bytes();
        changed_flags[9] = 1;
        assert!(RecordHeader::parse(changed_flags).is_err());
        let mut changed_reserved = *record.bytes();
        changed_reserved[10] = 1;
        assert!(RecordHeader::parse(changed_reserved).is_err());
        Ok(())
    }

    #[test]
    fn footer_exactly_round_trips_all_fields() -> Result<()> {
        let footer = Footer {
            core_record_count: 3,
            core_plaintext_bytes: 4,
            original_bytes: 5,
            segments: 6,
            inner_records: 7,
            inner_hash: [0x88; 32],
            transcript_hash: [0x99; 32],
        };
        let bytes = footer.serialize();
        assert_eq!(bytes.len(), FOOTER_PLAINTEXT_SIZE);
        assert_eq!(
            &bytes[..48],
            hex_bytes(concat!(
                "4d37463000000000",
                "0000000000000003",
                "0000000000000004",
                "0000000000000005",
                "00000006",
                "00000000",
                "0000000000000007"
            ))
        );
        let parsed = Footer::parse(&bytes)?;
        assert_eq!(parsed.core_record_count, footer.core_record_count);
        assert_eq!(parsed.core_plaintext_bytes, footer.core_plaintext_bytes);
        assert_eq!(parsed.original_bytes, footer.original_bytes);
        assert_eq!(parsed.segments, footer.segments);
        assert_eq!(parsed.inner_records, footer.inner_records);
        assert_eq!(parsed.inner_hash, footer.inner_hash);
        assert_eq!(parsed.transcript_hash, footer.transcript_hash);
        Ok(())
    }

    #[test]
    fn data_padding_is_opaque_and_empty_payloads_are_rejected() -> Result<()> {
        assert!(data_plaintext(Vec::new()).is_err());
        assert!(data_plaintext(vec![0; MAX_DATA_PAYLOAD + 1]).is_err());
        let (mut plaintext, expected_padding) = data_plaintext(b"opaque padding".to_vec())?;
        let last = plaintext.len() - 1;
        plaintext[last] ^= 0xff;
        let (payload, padding) = parse_data_plaintext(plaintext)?;
        assert_eq!(payload, b"opaque padding");
        assert_eq!(padding, expected_padding);

        let mut empty = vec![0x5a; PADDING_QUANTUM];
        empty[..4].copy_from_slice(&DATA_MAGIC);
        empty[4..8].copy_from_slice(&0_u32.to_be_bytes());
        assert!(parse_data_plaintext(empty).is_err());
        Ok(())
    }

    #[test]
    fn full_data_payload_exactly_fills_the_plaintext_bucket() -> Result<()> {
        let payload = vec![0xa5; MAX_DATA_PAYLOAD];
        let (plaintext, padding) = data_plaintext(payload.clone())?;
        assert_eq!(plaintext.len(), MAX_RECORD_PLAINTEXT);
        assert_eq!(padding, 0);
        let (decoded, decoded_padding) = parse_data_plaintext(plaintext)?;
        assert_eq!(decoded, payload);
        assert_eq!(decoded_padding, 0);
        Ok(())
    }
}
