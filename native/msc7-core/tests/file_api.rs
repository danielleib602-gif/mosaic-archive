use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::Path;

use mosaic_msc7_core::{
    AuthenticatedDecodeOptions, AuthenticatedEncodeOptions, AuthenticatedStats, EncodeOptions,
    Error, Result, decode_authenticated_file, encode_authenticated, encode_authenticated_file,
    inspect_authenticated_file,
};

const PASSWORD: &[u8] = b"correct horse battery staple";
const WRONG_PASSWORD: &[u8] = b"wrong horse battery staple";
const FAST_TEST_KDF_LOG_N: u8 = 14;

fn encode_options() -> AuthenticatedEncodeOptions {
    AuthenticatedEncodeOptions {
        core: EncodeOptions {
            threads: 2,
            ..EncodeOptions::default()
        },
        kdf_log_n: FAST_TEST_KDF_LOG_N,
    }
}

fn directory_entries(directory: &Path) -> io::Result<Vec<OsString>> {
    let mut entries = fs::read_dir(directory)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<io::Result<Vec<_>>>()?;
    entries.sort();
    Ok(entries)
}

fn assert_matching_stats(expected: AuthenticatedStats, actual: AuthenticatedStats) {
    assert_eq!(actual.core, expected.core);
    assert_eq!(actual.archive_bytes, expected.archive_bytes);
    assert_eq!(actual.data_records, expected.data_records);
    assert_eq!(actual.padding_bytes, expected.padding_bytes);
    assert_eq!(actual.authentication_bytes, expected.authentication_bytes);
}

fn assert_alias_rejected(error: Error) {
    match error {
        Error::Io(error) => assert_eq!(error.kind(), io::ErrorKind::InvalidInput),
        other => panic!("same-file alias should be an invalid-input I/O error, got {other}"),
    }
}

fn assert_non_regular_rejected(error: Error) {
    match error {
        Error::Io(error) => {
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(error.to_string().contains("regular file"));
        }
        other => panic!("non-regular path should be an invalid-input I/O error, got {other}"),
    }
}

fn make_archive_bytes(input: &[u8]) -> Result<Vec<u8>> {
    let mut archive = Vec::new();
    encode_authenticated(input, &mut archive, PASSWORD, encode_options())?;
    Ok(archive)
}

#[test]
fn authenticated_file_api_round_trips_unicode_paths_and_inspects() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("מקור-🧩.bin");
    let archive = directory.path().join("压缩-🌍.m7a");
    let restored = directory.path().join("восстановлено-🎶.bin");
    let contents = b"Mosaic authenticated file API\0with unicode paths\n".repeat(8_192);
    fs::write(&input, &contents)?;

    let encoded = encode_authenticated_file(&input, &archive, PASSWORD, encode_options())?;
    let inspected =
        inspect_authenticated_file(&archive, PASSWORD, AuthenticatedDecodeOptions::default())?;
    let decoded = decode_authenticated_file(
        &archive,
        &restored,
        PASSWORD,
        AuthenticatedDecodeOptions::default(),
    )?;

    assert_eq!(fs::read(&restored)?, contents);
    assert_matching_stats(encoded, inspected);
    assert_matching_stats(encoded, decoded);
    let mut expected_entries = vec![
        archive
            .file_name()
            .expect("archive has a file name")
            .to_os_string(),
        input
            .file_name()
            .expect("input has a file name")
            .to_os_string(),
        restored
            .file_name()
            .expect("restored has a file name")
            .to_os_string(),
    ];
    expected_entries.sort();
    assert_eq!(
        directory_entries(directory.path())?,
        expected_entries,
        "successful file operations must not leave sibling temporary files"
    );
    Ok(())
}

#[test]
fn decode_failures_preserve_existing_destination_and_leave_no_temp_residue() -> Result<()> {
    let contents = b"destination preservation under authenticated failure".repeat(4_096);
    let valid_archive = make_archive_bytes(&contents)?;
    let sentinel = b"pre-existing destination must survive";

    let mut truncated = valid_archive.clone();
    truncated.truncate(truncated.len() - 1);
    let mut trailing = valid_archive.clone();
    trailing.extend_from_slice(b"trailing bytes");

    for (case, archive_bytes, password) in [
        ("wrong-password", valid_archive.as_slice(), WRONG_PASSWORD),
        ("truncated", truncated.as_slice(), PASSWORD),
        ("trailing", trailing.as_slice(), PASSWORD),
    ] {
        let directory = tempfile::tempdir()?;
        let archive = directory.path().join(format!("{case}.m7a"));
        let destination = directory.path().join("existing-output.bin");
        fs::write(&archive, archive_bytes)?;
        fs::write(&destination, sentinel)?;
        let entries_before = directory_entries(directory.path())?;

        decode_authenticated_file(
            &archive,
            &destination,
            password,
            AuthenticatedDecodeOptions::default(),
        )
        .expect_err("an invalid authenticated archive must fail before publication");

        assert_eq!(
            fs::read(&destination)?,
            sentinel,
            "{case} replaced the existing destination"
        );
        assert_eq!(
            directory_entries(directory.path())?,
            entries_before,
            "{case} left a sibling temporary file"
        );
    }
    Ok(())
}

#[test]
fn invalid_encode_options_preserve_existing_destination_and_leave_no_temp_residue() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("input.bin");
    let destination = directory.path().join("existing.m7a");
    let sentinel = b"pre-existing archive must survive";
    fs::write(&input, b"input that must remain readable")?;
    fs::write(&destination, sentinel)?;
    let entries_before = directory_entries(directory.path())?;

    encode_authenticated_file(
        &input,
        &destination,
        PASSWORD,
        AuthenticatedEncodeOptions {
            core: EncodeOptions {
                threads: 0,
                ..EncodeOptions::default()
            },
            kdf_log_n: FAST_TEST_KDF_LOG_N,
        },
    )
    .expect_err("invalid options must fail before publication");

    assert_eq!(fs::read(&destination)?, sentinel);
    assert_eq!(directory_entries(directory.path())?, entries_before);
    Ok(())
}

#[test]
fn directories_are_rejected_before_output_side_effects() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("input.bin");
    let output = directory.path().join("output.m7a");
    let existing_directory = directory.path().join("existing-directory");
    fs::write(&input, b"regular input")?;
    fs::create_dir(&existing_directory)?;
    let entries_before = directory_entries(directory.path())?;

    let input_error =
        encode_authenticated_file(&existing_directory, &output, PASSWORD, encode_options())
            .expect_err("an input directory must be rejected before it is opened as codec input");
    assert_non_regular_rejected(input_error);

    let inspect_error = inspect_authenticated_file(
        &existing_directory,
        PASSWORD,
        AuthenticatedDecodeOptions::default(),
    )
    .expect_err("an input directory must be rejected before inspection");
    assert_non_regular_rejected(inspect_error);

    let output_error =
        encode_authenticated_file(&input, &existing_directory, PASSWORD, encode_options())
            .expect_err("an existing output directory must be rejected before temp creation");
    assert_non_regular_rejected(output_error);

    assert!(!output.exists());
    assert_eq!(directory_entries(directory.path())?, entries_before);
    Ok(())
}

#[cfg(unix)]
#[test]
fn unix_special_files_are_rejected_before_open_or_temp_creation() -> Result<()> {
    use std::os::unix::net::UnixListener;

    let directory = tempfile::tempdir()?;
    let regular = directory.path().join("regular.bin");
    let output = directory.path().join("output.m7a");
    let socket = directory.path().join("special.socket");
    fs::write(&regular, b"regular input")?;
    let _listener = UnixListener::bind(&socket)?;
    let entries_before = directory_entries(directory.path())?;

    let input_error = encode_authenticated_file(&socket, &output, PASSWORD, encode_options())
        .expect_err("a socket input must be rejected without opening it as codec input");
    assert_non_regular_rejected(input_error);

    let output_error = encode_authenticated_file(&regular, &socket, PASSWORD, encode_options())
        .expect_err("an existing socket output must be rejected before temp creation");
    assert_non_regular_rejected(output_error);

    assert!(!output.exists());
    assert_eq!(directory_entries(directory.path())?, entries_before);
    Ok(())
}

#[cfg(unix)]
#[test]
fn non_writable_regular_destination_is_replaceable_when_parent_permits() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir()?;
    let input = directory.path().join("input.bin");
    let output = directory.path().join("readonly-output.m7a");
    let contents = b"the destination file itself need not be writable".repeat(4_096);
    fs::write(&input, &contents)?;
    fs::write(&output, b"old destination")?;
    fs::set_permissions(&output, fs::Permissions::from_mode(0o444))?;

    encode_authenticated_file(&input, &output, PASSWORD, encode_options())?;
    let inspected =
        inspect_authenticated_file(&output, PASSWORD, AuthenticatedDecodeOptions::default())?;

    assert_eq!(inspected.core.original_bytes, contents.len() as u64);
    assert_ne!(fs::read(&output)?, b"old destination");
    Ok(())
}

#[test]
fn direct_input_output_aliases_are_rejected_without_modification() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("same-input.bin");
    let original = b"direct alias source must survive".repeat(1_024);
    fs::write(&input, &original)?;
    let entries_before_encode = directory_entries(directory.path())?;

    let encode_error = encode_authenticated_file(&input, &input, PASSWORD, encode_options())
        .expect_err("encoding onto the input path must fail");
    assert_alias_rejected(encode_error);
    assert_eq!(fs::read(&input)?, original);
    assert_eq!(directory_entries(directory.path())?, entries_before_encode);

    let archive = directory.path().join("same-archive.m7a");
    encode_authenticated_file(&input, &archive, PASSWORD, encode_options())?;
    let original_archive = fs::read(&archive)?;
    let entries_before_decode = directory_entries(directory.path())?;

    let decode_error = decode_authenticated_file(
        &archive,
        &archive,
        PASSWORD,
        AuthenticatedDecodeOptions::default(),
    )
    .expect_err("decoding onto the archive path must fail");
    assert_alias_rejected(decode_error);
    assert_eq!(fs::read(&archive)?, original_archive);
    assert_eq!(directory_entries(directory.path())?, entries_before_decode);
    Ok(())
}

#[test]
fn hardlink_input_output_aliases_are_rejected_without_modification() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("hardlink-input.bin");
    let output_alias = directory.path().join("hardlink-output.m7a");
    let original = b"hardlink alias source must survive".repeat(1_024);
    fs::write(&input, &original)?;
    fs::hard_link(&input, &output_alias)?;
    let entries_before_encode = directory_entries(directory.path())?;

    let encode_error = encode_authenticated_file(&input, &output_alias, PASSWORD, encode_options())
        .expect_err("encoding through a hardlink to the input must fail");
    assert_alias_rejected(encode_error);
    assert_eq!(fs::read(&input)?, original);
    assert_eq!(fs::read(&output_alias)?, original);
    assert_eq!(directory_entries(directory.path())?, entries_before_encode);

    let archive = directory.path().join("hardlink-archive.m7a");
    let decode_alias = directory.path().join("hardlink-restored.bin");
    encode_authenticated_file(&input, &archive, PASSWORD, encode_options())?;
    let original_archive = fs::read(&archive)?;
    fs::hard_link(&archive, &decode_alias)?;
    let entries_before_decode = directory_entries(directory.path())?;

    let decode_error = decode_authenticated_file(
        &archive,
        &decode_alias,
        PASSWORD,
        AuthenticatedDecodeOptions::default(),
    )
    .expect_err("decoding through a hardlink to the archive must fail");
    assert_alias_rejected(decode_error);
    assert_eq!(fs::read(&archive)?, original_archive);
    assert_eq!(fs::read(&decode_alias)?, original_archive);
    assert_eq!(directory_entries(directory.path())?, entries_before_decode);
    Ok(())
}

#[cfg(unix)]
fn create_file_symlink(source: &Path, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(source, link)
}

#[cfg(windows)]
fn create_file_symlink(source: &Path, link: &Path) -> io::Result<()> {
    std::os::windows::fs::symlink_file(source, link)
}

#[cfg(any(unix, windows))]
#[test]
fn symlink_input_output_aliases_are_rejected_without_modification() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("symlink-input.bin");
    let output_alias = directory.path().join("symlink-output.m7a");
    let original = b"symlink alias source must survive".repeat(1_024);
    fs::write(&input, &original)?;
    if let Err(error) = create_file_symlink(&input, &output_alias) {
        if cfg!(windows)
            && (matches!(
                error.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::Unsupported
            ) || error.raw_os_error() == Some(1314))
        {
            return Ok(());
        }
        return Err(error.into());
    }
    let entries_before_encode = directory_entries(directory.path())?;

    let encode_error = encode_authenticated_file(&input, &output_alias, PASSWORD, encode_options())
        .expect_err("encoding through a symlink to the input must fail");
    assert_alias_rejected(encode_error);
    assert!(
        fs::symlink_metadata(&output_alias)?
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(&input)?, original);
    assert_eq!(directory_entries(directory.path())?, entries_before_encode);

    let archive = directory.path().join("symlink-archive.m7a");
    let decode_alias = directory.path().join("symlink-restored.bin");
    encode_authenticated_file(&input, &archive, PASSWORD, encode_options())?;
    let original_archive = fs::read(&archive)?;
    create_file_symlink(&archive, &decode_alias)?;
    let entries_before_decode = directory_entries(directory.path())?;

    let decode_error = decode_authenticated_file(
        &archive,
        &decode_alias,
        PASSWORD,
        AuthenticatedDecodeOptions::default(),
    )
    .expect_err("decoding through a symlink to the archive must fail");
    assert_alias_rejected(decode_error);
    assert!(
        fs::symlink_metadata(&decode_alias)?
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(&archive)?, original_archive);
    assert_eq!(directory_entries(directory.path())?, entries_before_decode);
    Ok(())
}

#[test]
fn trailing_write_failure_cleans_up_temporary_output() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("input.bin");
    let destination = directory.path().join("destination.m7a");
    fs::write(&input, b"bounded input")?;
    let entries_before = directory_entries(directory.path())?;

    let mut options = encode_options();
    options.core.max_input_bytes = 1;
    encode_authenticated_file(&input, &destination, PASSWORD, options)
        .expect_err("an encoder failure after temporary output creation must be transactional");

    assert!(!destination.exists());
    assert_eq!(directory_entries(directory.path())?, entries_before);
    Ok(())
}
