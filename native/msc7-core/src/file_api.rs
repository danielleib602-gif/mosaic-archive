use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, BufReader, BufWriter, Write};
use std::path::Path;

use same_file::Handle;
use tempfile::NamedTempFile;

use crate::{
    AuthenticatedDecodeOptions, AuthenticatedEncodeOptions, AuthenticatedStats, Error, Result,
    decode_authenticated, encode_authenticated,
};

fn invalid_input(message: &'static str) -> Error {
    Error::Io(io::Error::new(io::ErrorKind::InvalidInput, message))
}

fn require_regular(metadata: &Metadata, message: &'static str) -> Result<()> {
    if !metadata.is_file() {
        return Err(invalid_input(message));
    }
    Ok(())
}

fn open_regular_file(path: &Path) -> Result<File> {
    // This metadata check rejects directories, FIFOs, sockets, and devices
    // without first opening a potentially blocking special file.
    require_regular(&fs::metadata(path)?, "input must identify a regular file")?;
    let file = File::open(path)?;
    // Recheck the opened handle so a path swap to another non-regular object
    // between metadata and open cannot enter the codec.
    require_regular(&file.metadata()?, "input must identify a regular file")?;
    Ok(file)
}

fn ensure_distinct_output(path: &Path, source: &Handle) -> Result<()> {
    let destination_metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    require_regular(
        &destination_metadata,
        "existing output must identify a regular file",
    )?;
    // Read-only access is sufficient for identity comparison, so a regular
    // destination need not itself be writable when its parent permits atomic
    // replacement.
    let destination = OpenOptions::new().read(true).open(path)?;
    require_regular(
        &destination.metadata()?,
        "existing output must identify a regular file",
    )?;
    if *source == Handle::from_file(destination)? {
        return Err(invalid_input("input and output identify the same file"));
    }
    Ok(())
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn with_transactional_output<T>(
    input: &Path,
    output: &Path,
    action: impl FnOnce(BufReader<File>, &mut dyn Write) -> Result<T>,
) -> Result<T> {
    let source = open_regular_file(input)?;
    let source_identity = Handle::from_file(source.try_clone()?)?;
    ensure_distinct_output(output, &source_identity)?;

    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = NamedTempFile::new_in(parent)?;
    let value = {
        let mut writer = BufWriter::new(temporary.as_file_mut());
        let value = action(BufReader::new(source), &mut writer)?;
        writer.flush()?;
        value
    };
    temporary.as_file().sync_all()?;

    // Recheck after the potentially long encode/decode so a destination that
    // became an alias while work was in progress is never opened for mutation.
    ensure_distinct_output(output, &source_identity)?;
    temporary
        .persist(output)
        .map_err(|error| Error::Io(error.error))?;
    sync_parent(parent)?;
    Ok(value)
}

/// Encode one regular file into a transactionally published M7A0 archive.
///
/// The temporary archive is created beside `output`, flushed and synchronized,
/// then atomically published. Any failure before publication preserves an
/// existing destination and removes the temporary file.
///
/// Path metadata is checked before opening input or examining an existing
/// output, and the opened input handle is checked again. A caller that grants
/// another process concurrent rename access to these paths must still prevent
/// path replacement between the metadata check and `open`; on platforms where
/// opening a FIFO blocks, such an adversarial swap can block that open.
pub fn encode_authenticated_file(
    input: &Path,
    output: &Path,
    password: &[u8],
    options: AuthenticatedEncodeOptions,
) -> Result<AuthenticatedStats> {
    with_transactional_output(input, output, |reader, writer| {
        encode_authenticated(reader, writer, password, options)
    })
}

/// Decode one regular M7A0 archive into a transactionally published file.
///
/// Authentication, the inner hashes, the footer, and physical EOF are all
/// verified before the destination path is replaced.
pub fn decode_authenticated_file(
    input: &Path,
    output: &Path,
    password: &[u8],
    options: AuthenticatedDecodeOptions,
) -> Result<AuthenticatedStats> {
    with_transactional_output(input, output, |reader, writer| {
        decode_authenticated(reader, writer, password, options)
    })
}

/// Authenticate and inspect one regular M7A0 archive without publishing data.
pub fn inspect_authenticated_file(
    input: &Path,
    password: &[u8],
    options: AuthenticatedDecodeOptions,
) -> Result<AuthenticatedStats> {
    let source = open_regular_file(input)?;
    decode_authenticated(BufReader::new(source), io::sink(), password, options)
}
