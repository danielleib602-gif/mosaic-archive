use std::cmp;
use std::io::{self, Read, Write};

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use scrypt::Params;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::auth_format::{
    AEAD_TAG_SIZE, DATA_RECORD_KIND, DEFAULT_KDF_LOG_N, FOOTER_RECORD_KIND, Footer, HEADER_SIZE,
    Header, KDF_P, KDF_R, MAX_DATA_PAYLOAD, MAX_KDF_LOG_N, MIN_KDF_LOG_N, PADDING_QUANTUM,
    RECORD_HEADER_SIZE, RecordHeader, aad, data_plaintext, footer_ciphertext_len,
    max_data_ciphertext_len, new_transcript, nonce, padded_footer, parse_data_plaintext,
    parse_padded_footer,
};
use crate::{
    DEFAULT_MAX_ENCODED_BYTES, DecodeOptions, EncodeOptions, Error, Result, StreamStats,
    decode_with_options, encode, validate_decode_options, validate_encode_options,
};

/// Default byte ceiling for the complete authenticated preview envelope.
pub const DEFAULT_MAX_AUTHENTICATED_ARCHIVE_BYTES: u64 =
    DEFAULT_MAX_ENCODED_BYTES + 64 * 1024 * 1024;
/// Default maximum count of independently authenticated data records.
pub const DEFAULT_MAX_AUTHENTICATED_DATA_RECORDS: u64 = 1_000_000;
/// Smallest possible M7A0 envelope: header, one DATA record, and one footer.
pub const MIN_AUTHENTICATED_ARCHIVE_BYTES: u64 =
    (HEADER_SIZE + 2 * RECORD_HEADER_SIZE + 2 * (PADDING_QUANTUM + AEAD_TAG_SIZE)) as u64;

/// Options for the non-stable authenticated MSC7 preview writer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedEncodeOptions {
    /// Inner M7R0 compression-core options.
    pub core: EncodeOptions,
    /// Base-two scrypt work factor exponent, in `14..=18`.
    pub kdf_log_n: u8,
}

impl Default for AuthenticatedEncodeOptions {
    fn default() -> Self {
        Self {
            core: EncodeOptions::default(),
            kdf_log_n: DEFAULT_KDF_LOG_N,
        }
    }
}

/// Resource ceilings for the authenticated preview reader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedDecodeOptions {
    /// Inner M7R0 decoder ceilings.
    pub core: DecodeOptions,
    /// Maximum complete outer archive size, including framing and tags.
    pub max_archive_bytes: u64,
    /// Maximum count of outer data records, excluding the final footer.
    pub max_data_records: u64,
    /// Maximum scrypt base-two work-factor exponent accepted before KDF work.
    pub max_kdf_log_n: u8,
}

impl Default for AuthenticatedDecodeOptions {
    fn default() -> Self {
        Self {
            core: DecodeOptions::default(),
            max_archive_bytes: DEFAULT_MAX_AUTHENTICATED_ARCHIVE_BYTES,
            max_data_records: DEFAULT_MAX_AUTHENTICATED_DATA_RECORDS,
            max_kdf_log_n: DEFAULT_KDF_LOG_N,
        }
    }
}

/// Inner compression and authenticated-envelope statistics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AuthenticatedStats {
    /// Statistics from the exact inner M7R0 byte stream.
    pub core: StreamStats,
    /// Complete outer archive size, including every header, tag, and pad byte.
    pub archive_bytes: u64,
    /// Count of independently authenticated data records.
    pub data_records: u64,
    /// Random plaintext padding bytes across data records and the footer.
    pub padding_bytes: u64,
    /// ChaCha20-Poly1305 tag bytes across data records and the footer.
    pub authentication_bytes: u64,
}

/// Encode an M7R0 stream inside the non-stable `M7A0` authenticated envelope.
///
/// The password and derived key are held in zeroizing storage. The outer salt,
/// nonce prefix, and padding are independently random for every invocation.
/// The writer is direct: an I/O or compression failure can leave a partial
/// envelope, so file-oriented callers should publish through a temporary file.
pub fn encode_authenticated<R: Read, W: Write>(
    reader: R,
    writer: W,
    password: &[u8],
    options: AuthenticatedEncodeOptions,
) -> Result<AuthenticatedStats> {
    validate_password(password)?;
    validate_encode_options(options.core)?;
    let password = Zeroizing::new(password.to_vec());
    let mut authenticated = AuthenticatedWriter::new(writer, &password, options.kdf_log_n)?;
    let core = encode(reader, &mut authenticated, options.core)?;
    authenticated.finish(core)
}

/// Decode a non-stable `M7A0` envelope after authenticating each complete
/// record and the final transcript.
///
/// Wrong passwords and record-tag failures intentionally share the single
/// [`Error::Authentication`] result.
///
/// Each complete outer record is authenticated before its inner bytes are
/// decoded, but earlier verified segments can reach `writer` before the final
/// footer, transcript, and physical EOF are checked. File-oriented callers
/// should decode into a temporary file and publish only after this function
/// returns successfully.
pub fn decode_authenticated<R: Read, W: Write>(
    reader: R,
    writer: W,
    password: &[u8],
    options: AuthenticatedDecodeOptions,
) -> Result<AuthenticatedStats> {
    validate_password(password)?;
    validate_decode_options(options.core)?;
    if options.max_archive_bytes < MIN_AUTHENTICATED_ARCHIVE_BYTES
        || options.max_data_records == 0
        || !(MIN_KDF_LOG_N..=MAX_KDF_LOG_N).contains(&options.max_kdf_log_n)
    {
        return Err(Error::InvalidOptions(
            "authenticated decode ceilings must fit one complete record/footer and KDF policy must be in 14..=18",
        ));
    }
    let password = Zeroizing::new(password.to_vec());
    let mut authenticated = AuthenticatedReader::new(reader, &password, options)?;
    let core_result = decode_with_options(&mut authenticated, writer, options.core);
    if let Some(error) = authenticated.take_failure() {
        return Err(error);
    }
    let core = core_result?;
    authenticated.finish(core)
}

fn validate_password(password: &[u8]) -> Result<()> {
    if password.is_empty() {
        return Err(Error::InvalidOptions("password must not be empty"));
    }
    Ok(())
}

fn derive_cipher(password: &[u8], header: &Header, decoding: bool) -> Result<ChaCha20Poly1305> {
    let parameters = Params::new(header.kdf_log_n(), KDF_R, KDF_P).map_err(|_| {
        if decoding {
            Error::Authentication
        } else {
            Error::InvalidOptions("scrypt parameters are invalid")
        }
    })?;
    let mut key = Zeroizing::new([0_u8; 32]);
    scrypt::scrypt(password, header.salt(), &parameters, key.as_mut()).map_err(|_| {
        if decoding {
            Error::Authentication
        } else {
            Error::Codec("scrypt key derivation failed")
        }
    })?;
    ChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| {
        if decoding {
            Error::Authentication
        } else {
            Error::Codec("derived encryption key has an invalid size")
        }
    })
}

struct AuthenticatedWriter<W: Write> {
    writer: W,
    cipher: ChaCha20Poly1305,
    header: Header,
    nonce_prefix: [u8; 4],
    pending: Vec<u8>,
    next_index: u64,
    core_plaintext_bytes: u64,
    core_hasher: Sha256,
    transcript: Sha256,
    archive_bytes: u64,
    data_records: u64,
    padding_bytes: u64,
    authentication_bytes: u64,
}

impl<W: Write> AuthenticatedWriter<W> {
    fn new(mut writer: W, password: &[u8], kdf_log_n: u8) -> Result<Self> {
        let header = Header::generate(kdf_log_n)?;
        let cipher = derive_cipher(password, &header, false)?;
        writer.write_all(header.bytes())?;
        let nonce_prefix = header.nonce_prefix();
        let transcript = new_transcript(&header);
        Ok(Self {
            writer,
            cipher,
            header,
            nonce_prefix,
            pending: Vec::with_capacity(MAX_DATA_PAYLOAD),
            next_index: 0,
            core_plaintext_bytes: 0,
            core_hasher: Sha256::new(),
            transcript,
            archive_bytes: HEADER_SIZE as u64,
            data_records: 0,
            padding_bytes: 0,
            authentication_bytes: 0,
        })
    }

    fn seal_data_record(&mut self) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let payload = std::mem::replace(&mut self.pending, Vec::with_capacity(MAX_DATA_PAYLOAD));
        let (plaintext, padding_bytes) = data_plaintext(payload)?;
        self.write_encrypted_record(DATA_RECORD_KIND, plaintext, true)?;
        self.data_records = self
            .data_records
            .checked_add(1)
            .ok_or(Error::Codec("authenticated data-record count overflows"))?;
        self.padding_bytes = self
            .padding_bytes
            .checked_add(padding_bytes)
            .ok_or(Error::Codec("authenticated padding count overflows"))?;
        Ok(())
    }

    fn write_encrypted_record(
        &mut self,
        kind: u8,
        plaintext: Vec<u8>,
        include_in_transcript: bool,
    ) -> Result<()> {
        let ciphertext_len = plaintext
            .len()
            .checked_add(AEAD_TAG_SIZE)
            .ok_or(Error::Codec("authenticated ciphertext size overflows"))?;
        let record = RecordHeader::new(self.next_index, kind, ciphertext_len)?;
        let nonce_bytes = nonce(self.nonce_prefix, self.next_index);
        let aad_bytes = aad(&self.header, record);
        let nonce = Nonce::from(nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &plaintext,
                    aad: &aad_bytes,
                },
            )
            .map_err(|_| Error::Codec("authenticated encryption failed"))?;
        if ciphertext.len() != ciphertext_len {
            return Err(Error::Codec(
                "authenticated encryption returned an invalid size",
            ));
        }
        self.writer.write_all(record.bytes())?;
        self.writer.write_all(&ciphertext)?;
        if include_in_transcript {
            self.transcript.update(record.bytes());
            self.transcript.update(&ciphertext);
        }
        let record_bytes = RECORD_HEADER_SIZE
            .checked_add(ciphertext.len())
            .ok_or(Error::Codec("authenticated archive size overflows"))?;
        self.archive_bytes = self
            .archive_bytes
            .checked_add(record_bytes as u64)
            .ok_or(Error::Codec("authenticated archive size overflows"))?;
        self.authentication_bytes = self
            .authentication_bytes
            .checked_add(AEAD_TAG_SIZE as u64)
            .ok_or(Error::Codec("authentication-byte count overflows"))?;
        self.next_index = self
            .next_index
            .checked_add(1)
            .ok_or(Error::Codec("authenticated record index overflows"))?;
        Ok(())
    }

    fn finish(mut self, core: StreamStats) -> Result<AuthenticatedStats> {
        self.seal_data_record()?;
        if self.data_records == 0 || self.core_plaintext_bytes != core.encoded_bytes {
            return Err(Error::Codec(
                "inner compression statistics do not match the authenticated stream",
            ));
        }
        let inner_hash: [u8; 32] = self.core_hasher.clone().finalize().into();
        let transcript_hash: [u8; 32] = self.transcript.clone().finalize().into();
        let footer = Footer {
            core_record_count: self.data_records,
            core_plaintext_bytes: self.core_plaintext_bytes,
            original_bytes: core.original_bytes,
            segments: core.segments,
            inner_records: core.records,
            inner_hash,
            transcript_hash,
        };
        let (plaintext, footer_padding) = padded_footer(footer)?;
        self.write_encrypted_record(FOOTER_RECORD_KIND, plaintext, false)?;
        self.padding_bytes = self
            .padding_bytes
            .checked_add(footer_padding)
            .ok_or(Error::Codec("authenticated padding count overflows"))?;
        self.writer.flush()?;
        Ok(AuthenticatedStats {
            core,
            archive_bytes: self.archive_bytes,
            data_records: self.data_records,
            padding_bytes: self.padding_bytes,
            authentication_bytes: self.authentication_bytes,
        })
    }
}

impl<W: Write> Write for AuthenticatedWriter<W> {
    fn write(&mut self, mut buffer: &[u8]) -> io::Result<usize> {
        let original_len = buffer.len();
        while !buffer.is_empty() {
            let available = MAX_DATA_PAYLOAD - self.pending.len();
            let copied = cmp::min(available, buffer.len());
            let chunk = &buffer[..copied];
            self.pending.extend_from_slice(chunk);
            self.core_hasher.update(chunk);
            self.core_plaintext_bytes = self
                .core_plaintext_bytes
                .checked_add(copied as u64)
                .ok_or_else(|| io::Error::other("inner plaintext byte count overflows"))?;
            buffer = &buffer[copied..];
            if self.pending.len() == MAX_DATA_PAYLOAD {
                self.seal_data_record().map_err(error_into_io)?;
            }
        }
        Ok(original_len)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

fn error_into_io(error: Error) -> io::Error {
    match error {
        Error::Io(error) => error,
        other => io::Error::other(other.to_string()),
    }
}

struct AuthenticatedReader<R: Read> {
    reader: R,
    cipher: ChaCha20Poly1305,
    header: Header,
    nonce_prefix: [u8; 4],
    options: AuthenticatedDecodeOptions,
    current: Vec<u8>,
    current_offset: usize,
    next_index: u64,
    core_plaintext_bytes: u64,
    core_hasher: Sha256,
    transcript: Sha256,
    archive_bytes: u64,
    data_records: u64,
    padding_bytes: u64,
    authentication_bytes: u64,
    footer: Option<Footer>,
    finished: bool,
    failure: Option<Error>,
}

impl<R: Read> AuthenticatedReader<R> {
    fn new(mut reader: R, password: &[u8], options: AuthenticatedDecodeOptions) -> Result<Self> {
        if options.max_archive_bytes < HEADER_SIZE as u64 {
            return Err(Error::InvalidFormat(
                "authenticated archive byte limit is exceeded",
            ));
        }
        let mut header_bytes = [0_u8; HEADER_SIZE];
        read_exact_format(
            &mut reader,
            &mut header_bytes,
            "authenticated header is truncated",
        )?;
        // Parse and reject unsupported public parameters before performing KDF
        // work, then bind the exact accepted bytes into every record AAD.
        let header = Header::parse(header_bytes)?;
        if header.kdf_log_n() > options.max_kdf_log_n {
            return Err(Error::InvalidFormat(
                "authenticated KDF cost exceeds the caller policy",
            ));
        }
        let cipher = derive_cipher(password, &header, true)?;
        let nonce_prefix = header.nonce_prefix();
        let transcript = new_transcript(&header);
        Ok(Self {
            reader,
            cipher,
            header,
            nonce_prefix,
            options,
            current: Vec::new(),
            current_offset: 0,
            next_index: 0,
            core_plaintext_bytes: 0,
            core_hasher: Sha256::new(),
            transcript,
            archive_bytes: HEADER_SIZE as u64,
            data_records: 0,
            padding_bytes: 0,
            authentication_bytes: 0,
            footer: None,
            finished: false,
            failure: None,
        })
    }

    fn load_next_record(&mut self) -> Result<()> {
        let mut record_bytes = [0_u8; RECORD_HEADER_SIZE];
        self.read_outer_exact(
            &mut record_bytes,
            "authenticated record header is truncated",
        )?;
        let record = RecordHeader::parse(record_bytes)?;
        if record.index() != self.next_index {
            return Err(Error::InvalidFormat(
                "authenticated record index is inconsistent",
            ));
        }
        self.validate_ciphertext_bound(record)?;
        let ciphertext_len = record.ciphertext_len();
        self.ensure_archive_room(ciphertext_len)?;
        // Allocation occurs only after kind, index, per-record bounds, record
        // count, total count, and outer archive byte ceilings are accepted.
        let mut ciphertext = vec![0_u8; ciphertext_len];
        self.read_outer_exact(
            &mut ciphertext,
            "authenticated record ciphertext is truncated",
        )?;
        let nonce_bytes = nonce(self.nonce_prefix, self.next_index);
        let aad_bytes = aad(&self.header, record);
        let nonce = Nonce::from(nonce_bytes);
        let plaintext = self
            .cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &ciphertext,
                    aad: &aad_bytes,
                },
            )
            .map_err(|_| Error::Authentication)?;
        self.authentication_bytes = self
            .authentication_bytes
            .checked_add(AEAD_TAG_SIZE as u64)
            .ok_or(Error::InvalidFormat("authentication-byte count overflows"))?;

        match record.kind() {
            DATA_RECORD_KIND => self.accept_data(record, ciphertext, plaintext)?,
            FOOTER_RECORD_KIND => self.accept_footer(plaintext)?,
            _ => {
                return Err(Error::InvalidFormat(
                    "authenticated record kind is unsupported",
                ));
            }
        }
        self.next_index = self
            .next_index
            .checked_add(1)
            .ok_or(Error::InvalidFormat("authenticated record index overflows"))?;
        Ok(())
    }

    fn validate_ciphertext_bound(&self, record: RecordHeader) -> Result<()> {
        match record.kind() {
            DATA_RECORD_KIND => {
                if self.footer.is_some() || self.data_records >= self.options.max_data_records {
                    return Err(Error::InvalidFormat(
                        "authenticated data-record ceiling is exceeded",
                    ));
                }
                let ciphertext_len = record.ciphertext_len();
                if ciphertext_len < 1024 + AEAD_TAG_SIZE
                    || ciphertext_len > max_data_ciphertext_len()?
                    || !(ciphertext_len - AEAD_TAG_SIZE).is_multiple_of(1024)
                {
                    return Err(Error::InvalidFormat(
                        "authenticated data-record size is invalid",
                    ));
                }
            }
            FOOTER_RECORD_KIND => {
                if self.footer.is_some()
                    || self.data_records == 0
                    || record.ciphertext_len() != footer_ciphertext_len()?
                {
                    return Err(Error::InvalidFormat(
                        "authenticated footer record is invalid",
                    ));
                }
            }
            _ => {
                return Err(Error::InvalidFormat(
                    "authenticated record kind is unsupported",
                ));
            }
        }
        Ok(())
    }

    fn accept_data(
        &mut self,
        record: RecordHeader,
        ciphertext: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> Result<()> {
        let (payload, padding_bytes) = parse_data_plaintext(plaintext)?;
        self.transcript.update(record.bytes());
        self.transcript.update(&ciphertext);
        self.core_hasher.update(&payload);
        self.core_plaintext_bytes = self
            .core_plaintext_bytes
            .checked_add(payload.len() as u64)
            .ok_or(Error::InvalidFormat(
                "authenticated inner byte count overflows",
            ))?;
        self.data_records = self
            .data_records
            .checked_add(1)
            .ok_or(Error::InvalidFormat(
                "authenticated data-record count overflows",
            ))?;
        self.padding_bytes =
            self.padding_bytes
                .checked_add(padding_bytes)
                .ok_or(Error::InvalidFormat(
                    "authenticated padding count overflows",
                ))?;
        self.current = payload;
        self.current_offset = 0;
        Ok(())
    }

    fn accept_footer(&mut self, plaintext: Vec<u8>) -> Result<()> {
        let (footer, padding_bytes) = parse_padded_footer(&plaintext)?;
        let expected_inner_hash: [u8; 32] = self.core_hasher.clone().finalize().into();
        let expected_transcript: [u8; 32] = self.transcript.clone().finalize().into();
        if footer.core_record_count != self.data_records
            || footer.core_plaintext_bytes != self.core_plaintext_bytes
            || footer.inner_hash != expected_inner_hash
            || footer.transcript_hash != expected_transcript
        {
            return Err(Error::InvalidFormat(
                "authenticated footer totals or digests are inconsistent",
            ));
        }
        self.padding_bytes =
            self.padding_bytes
                .checked_add(padding_bytes)
                .ok_or(Error::InvalidFormat(
                    "authenticated padding count overflows",
                ))?;
        self.require_physical_eof()?;
        self.footer = Some(footer);
        self.finished = true;
        Ok(())
    }

    fn read_outer_exact(&mut self, buffer: &mut [u8], message: &'static str) -> Result<()> {
        self.ensure_archive_room(buffer.len())?;
        read_exact_format(&mut self.reader, buffer, message)?;
        self.archive_bytes =
            self.archive_bytes
                .checked_add(buffer.len() as u64)
                .ok_or(Error::InvalidFormat(
                    "authenticated archive byte count overflows",
                ))?;
        Ok(())
    }

    fn ensure_archive_room(&self, additional: usize) -> Result<()> {
        let next =
            self.archive_bytes
                .checked_add(additional as u64)
                .ok_or(Error::InvalidFormat(
                    "authenticated archive byte count overflows",
                ))?;
        if next > self.options.max_archive_bytes {
            return Err(Error::InvalidFormat(
                "authenticated archive byte limit is exceeded",
            ));
        }
        Ok(())
    }

    fn require_physical_eof(&mut self) -> Result<()> {
        let mut byte = [0_u8; 1];
        loop {
            match self.reader.read(&mut byte) {
                Ok(0) => return Ok(()),
                Ok(_) => {
                    self.ensure_archive_room(1)?;
                    self.archive_bytes += 1;
                    return Err(Error::InvalidFormat(
                        "trailing bytes follow the authenticated footer",
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(Error::Io(error)),
            }
        }
    }

    fn take_failure(&mut self) -> Option<Error> {
        self.failure.take()
    }

    fn finish(self, core: StreamStats) -> Result<AuthenticatedStats> {
        let footer = self.footer.ok_or(Error::InvalidFormat(
            "authenticated footer was not consumed",
        ))?;
        if footer.core_plaintext_bytes != core.encoded_bytes
            || footer.original_bytes != core.original_bytes
            || footer.segments != core.segments
            || footer.inner_records != core.records
        {
            return Err(Error::InvalidFormat(
                "authenticated footer does not match inner stream statistics",
            ));
        }
        Ok(AuthenticatedStats {
            core,
            archive_bytes: self.archive_bytes,
            data_records: self.data_records,
            padding_bytes: self.padding_bytes,
            authentication_bytes: self.authentication_bytes,
        })
    }
}

impl<R: Read> Read for AuthenticatedReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        loop {
            if self.current_offset < self.current.len() {
                let available = &self.current[self.current_offset..];
                let copied = cmp::min(available.len(), output.len());
                output[..copied].copy_from_slice(&available[..copied]);
                self.current_offset += copied;
                if self.current_offset == self.current.len() {
                    self.current.clear();
                    self.current_offset = 0;
                }
                return Ok(copied);
            }
            if self.finished {
                return Ok(0);
            }
            if self.failure.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "authenticated envelope read previously failed",
                ));
            }
            if let Err(error) = self.load_next_record() {
                self.failure = Some(error);
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "authenticated envelope read failed",
                ));
            }
        }
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
    fn scrypt_and_aead_match_the_external_deterministic_vector() -> Result<()> {
        let header = Header::from_parts(
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f,
            ],
            [0x10, 0x20, 0x30, 0x40],
            14,
        )?;
        let password = b"mosaic-vector-password";
        let expected_key =
            hex_bytes("ec44b0f7384365481fae60f47012da9dc204151081222b987dd125f3dbfddd0c");
        let parameters = Params::new(14, KDF_R, KDF_P)
            .map_err(|_| Error::Codec("test KDF parameters are invalid"))?;
        let mut key = [0_u8; 32];
        scrypt::scrypt(password, header.salt(), &parameters, &mut key)
            .map_err(|_| Error::Codec("test KDF failed"))?;
        assert_eq!(key.as_slice(), expected_key);

        let cipher = derive_cipher(password, &header, false)?;
        let plaintext = b"M7A0 deterministic AEAD";
        let record = RecordHeader::new(7, DATA_RECORD_KIND, plaintext.len() + AEAD_TAG_SIZE)?;
        let nonce_bytes = nonce(header.nonce_prefix(), 7);
        let nonce = Nonce::from(nonce_bytes);
        let aad_bytes = aad(&header, record);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad_bytes,
                },
            )
            .map_err(|_| Error::Codec("test authenticated encryption failed"))?;
        assert_eq!(
            ciphertext,
            hex_bytes(concat!(
                "db992d0bb9d9f609ef78326093231022d8e70cd74da4e1",
                "c2004360ed76b724848bcb9ecb3e361b"
            ))
        );
        Ok(())
    }
}
