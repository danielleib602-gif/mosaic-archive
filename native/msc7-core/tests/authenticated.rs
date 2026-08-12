use std::convert::TryInto;

use mosaic_msc7_core::{
    AUTHENTICATED_MAGIC, AuthenticatedDecodeOptions, AuthenticatedEncodeOptions,
    AuthenticatedStats, DecodeOptions, EncodeOptions, Error, MIN_AUTHENTICATED_ARCHIVE_BYTES,
    Result, decode_authenticated, encode_authenticated,
};

const PASSWORD: &[u8] = b"correct horse battery staple";
const FAST_TEST_KDF_LOG_N: u8 = 14;
const AUTHENTICATED_HEADER_SIZE: usize = 64;
const RECORD_HEADER_SIZE: usize = 16;
const FIRST_RECORD_CIPHERTEXT_OFFSET: usize = AUTHENTICATED_HEADER_SIZE + RECORD_HEADER_SIZE;
const FIRST_RECORD_CIPHERTEXT_LENGTH_OFFSET: usize = 76;
const AEAD_TAG_SIZE: usize = 16;

fn encode_options(threads: usize) -> AuthenticatedEncodeOptions {
    AuthenticatedEncodeOptions {
        core: EncodeOptions {
            threads,
            ..EncodeOptions::default()
        },
        kdf_log_n: FAST_TEST_KDF_LOG_N,
    }
}

fn encode_archive(input: &[u8], threads: usize) -> Result<(Vec<u8>, AuthenticatedStats)> {
    let mut archive = Vec::new();
    let stats = encode_authenticated(input, &mut archive, PASSWORD, encode_options(threads))?;

    assert!(archive.starts_with(&AUTHENTICATED_MAGIC));
    assert_eq!(stats.archive_bytes, archive.len() as u64);
    assert_eq!(stats.core.original_bytes, input.len() as u64);
    Ok((archive, stats))
}

fn decode_archive(
    archive: &[u8],
    password: &[u8],
    options: AuthenticatedDecodeOptions,
) -> Result<(Vec<u8>, AuthenticatedStats)> {
    let mut restored = Vec::new();
    let stats = decode_authenticated(archive, &mut restored, password, options)?;
    Ok((restored, stats))
}

fn assert_matching_stats(encoded: AuthenticatedStats, decoded: AuthenticatedStats) {
    assert_eq!(decoded.core, encoded.core);
    assert_eq!(decoded.archive_bytes, encoded.archive_bytes);
    assert_eq!(decoded.data_records, encoded.data_records);
    assert_eq!(decoded.padding_bytes, encoded.padding_bytes);
    assert_eq!(decoded.authentication_bytes, encoded.authentication_bytes);
}

fn assert_thread_independent_round_trip(input: &[u8]) -> Result<()> {
    let (one_archive, one_encoded) = encode_archive(input, 1)?;
    let (eight_archive, eight_encoded) = encode_archive(input, 8)?;

    let (one_restored, one_decoded) = decode_archive(
        &one_archive,
        PASSWORD,
        AuthenticatedDecodeOptions::default(),
    )?;
    let (eight_restored, eight_decoded) = decode_archive(
        &eight_archive,
        PASSWORD,
        AuthenticatedDecodeOptions::default(),
    )?;

    assert_eq!(one_restored, input);
    assert_eq!(eight_restored, input);
    assert_matching_stats(one_encoded, one_decoded);
    assert_matching_stats(eight_encoded, eight_decoded);

    // Salt and nonces deliberately make the outer archives random. The inner
    // compression result and all size/count decisions must remain independent
    // of the worker count.
    assert_eq!(one_encoded.core, eight_encoded.core);
    assert_eq!(one_encoded.archive_bytes, eight_encoded.archive_bytes);
    assert_eq!(one_encoded.data_records, eight_encoded.data_records);
    assert_eq!(one_encoded.padding_bytes, eight_encoded.padding_bytes);
    assert_eq!(
        one_encoded.authentication_bytes,
        eight_encoded.authentication_bytes
    );
    Ok(())
}

fn deterministic_noise(size: usize) -> Vec<u8> {
    let mut state = 0x243f_6a88_85a3_08d3_u64;
    let mut bytes = Vec::with_capacity(size);
    for _ in 0..size {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        bytes.push(state as u8);
    }
    bytes
}

fn assert_authentication_error(archive: &[u8], password: &[u8]) {
    let error = decode_authenticated(
        archive,
        Vec::new(),
        password,
        AuthenticatedDecodeOptions::default(),
    )
    .expect_err("unauthenticated input must be rejected");

    assert!(matches!(&error, Error::Authentication));
    assert_eq!(error.to_string(), "authentication failed");
}

#[test]
fn authenticated_empty_round_trip_is_worker_independent() -> Result<()> {
    assert_thread_independent_round_trip(&[])
}

#[test]
fn authenticated_small_round_trip_is_worker_independent() -> Result<()> {
    assert_thread_independent_round_trip(
        b"Mosaic authenticated preview: small Unicode-adjacent byte stream \xf0\x9f\xa7\xa9",
    )
}

#[test]
fn authenticated_multi_record_round_trip_is_worker_independent() -> Result<()> {
    let input = deterministic_noise(3 * 1024 * 1024 + 17);
    assert_thread_independent_round_trip(&input)
}

#[test]
fn wrong_password_has_one_generic_authentication_error() -> Result<()> {
    let (archive, _) = encode_archive(b"password oracle probe", 1)?;
    assert_authentication_error(&archive, b"definitely the wrong password");
    Ok(())
}

#[test]
fn authenticated_header_ciphertext_and_tag_mutations_are_rejected() -> Result<()> {
    let input = deterministic_noise(256 * 1024 + 31);
    let (archive, _) = encode_archive(&input, 1)?;

    let mut changed_header = archive.clone();
    changed_header[32] ^= 0x01;
    assert_authentication_error(&changed_header, PASSWORD);

    let first_ciphertext_length = u32::from_be_bytes(
        archive[FIRST_RECORD_CIPHERTEXT_LENGTH_OFFSET..FIRST_RECORD_CIPHERTEXT_LENGTH_OFFSET + 4]
            .try_into()
            .expect("four-byte ciphertext length"),
    ) as usize;
    assert!(first_ciphertext_length > AEAD_TAG_SIZE + 8);
    assert!(
        FIRST_RECORD_CIPHERTEXT_OFFSET + first_ciphertext_length <= archive.len(),
        "first record must fit inside the archive"
    );

    let mut changed_ciphertext = archive.clone();
    changed_ciphertext[FIRST_RECORD_CIPHERTEXT_OFFSET + 8] ^= 0x80;
    assert_authentication_error(&changed_ciphertext, PASSWORD);

    let mut changed_tag = archive.clone();
    let first_tag_last_byte = FIRST_RECORD_CIPHERTEXT_OFFSET + first_ciphertext_length - 1;
    changed_tag[first_tag_last_byte] ^= 0x40;
    assert_authentication_error(&changed_tag, PASSWORD);
    Ok(())
}

#[test]
fn authenticated_archive_rejects_truncation_and_trailing_bytes() -> Result<()> {
    let (archive, _) = encode_archive(b"complete transcript required", 1)?;

    let truncated = &archive[..archive.len() - 1];
    assert!(
        decode_authenticated(
            truncated,
            Vec::new(),
            PASSWORD,
            AuthenticatedDecodeOptions::default(),
        )
        .is_err(),
        "a truncated final authentication tag must be rejected"
    );

    let mut appended = archive;
    appended.push(0);
    assert!(
        decode_authenticated(
            appended.as_slice(),
            Vec::new(),
            PASSWORD,
            AuthenticatedDecodeOptions::default(),
        )
        .is_err(),
        "bytes after the authenticated transcript must be rejected"
    );
    Ok(())
}

#[test]
fn authenticated_decode_enforces_outer_and_inner_resource_ceilings() -> Result<()> {
    let input = deterministic_noise(3 * 1024 * 1024 + 17);
    let (archive, stats) = encode_archive(&input, 1)?;
    assert!(stats.data_records > 1, "fixture must span multiple records");

    let archive_limit = AuthenticatedDecodeOptions {
        max_archive_bytes: stats.archive_bytes - 1,
        ..AuthenticatedDecodeOptions::default()
    };
    assert!(
        decode_authenticated(archive.as_slice(), Vec::new(), PASSWORD, archive_limit).is_err(),
        "the authenticated-envelope byte ceiling must be enforced"
    );

    let record_limit = AuthenticatedDecodeOptions {
        max_data_records: stats.data_records - 1,
        ..AuthenticatedDecodeOptions::default()
    };
    assert!(
        decode_authenticated(archive.as_slice(), Vec::new(), PASSWORD, record_limit).is_err(),
        "the authenticated data-record ceiling must be enforced"
    );

    let decoded_limit = AuthenticatedDecodeOptions {
        core: DecodeOptions {
            max_output_bytes: input.len() as u64 - 1,
            ..DecodeOptions::default()
        },
        ..AuthenticatedDecodeOptions::default()
    };
    assert!(
        decode_authenticated(archive.as_slice(), Vec::new(), PASSWORD, decoded_limit).is_err(),
        "the inner decoded-output ceiling must still be enforced"
    );
    Ok(())
}

#[test]
fn invalid_options_fail_before_authenticated_io() {
    let mut archive = Vec::new();
    let encode_error = encode_authenticated(
        b"must not be consumed".as_slice(),
        &mut archive,
        PASSWORD,
        AuthenticatedEncodeOptions {
            core: EncodeOptions {
                threads: 0,
                ..EncodeOptions::default()
            },
            kdf_log_n: FAST_TEST_KDF_LOG_N,
        },
    )
    .expect_err("invalid inner encode options must fail");
    assert!(matches!(encode_error, Error::InvalidOptions(_)));
    assert!(archive.is_empty(), "no authenticated header may be written");

    let decode_error = decode_authenticated(
        b"not read".as_slice(),
        Vec::new(),
        PASSWORD,
        AuthenticatedDecodeOptions {
            core: DecodeOptions {
                max_output_bytes: 0,
                ..DecodeOptions::default()
            },
            ..AuthenticatedDecodeOptions::default()
        },
    )
    .expect_err("invalid inner decode options must fail");
    assert!(matches!(decode_error, Error::InvalidOptions(_)));

    let outer_limit_error = decode_authenticated(
        b"not read".as_slice(),
        Vec::new(),
        PASSWORD,
        AuthenticatedDecodeOptions {
            max_archive_bytes: MIN_AUTHENTICATED_ARCHIVE_BYTES - 1,
            ..AuthenticatedDecodeOptions::default()
        },
    )
    .expect_err("an impossible outer ceiling must fail before input or KDF work");
    assert!(matches!(outer_limit_error, Error::InvalidOptions(_)));
}

#[test]
fn excessive_header_kdf_cost_is_rejected_by_policy_before_derivation() {
    let mut header = [0_u8; AUTHENTICATED_HEADER_SIZE];
    header[..4].copy_from_slice(&AUTHENTICATED_MAGIC);
    header[4] = 0;
    header[5] = 3;
    header[6] = 1;
    header[7] = 1;
    header[12..16].copy_from_slice(&(AUTHENTICATED_HEADER_SIZE as u32).to_be_bytes());
    header[16..20].copy_from_slice(&1024_u32.to_be_bytes());
    header[20..24].copy_from_slice(&(2_u32 * 1024 * 1024).to_be_bytes());
    header[44] = 18;
    header[45] = 8;
    header[46] = 1;

    let error = decode_authenticated(
        header.as_slice(),
        Vec::new(),
        PASSWORD,
        AuthenticatedDecodeOptions::default(),
    )
    .expect_err("the default KDF policy must reject logN 18 before derivation");
    assert!(matches!(error, Error::InvalidFormat(_)));
    assert!(error.to_string().contains("KDF cost exceeds"));
}
