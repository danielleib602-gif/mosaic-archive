//! Private ABI3 bridge to the non-stable authenticated MSC7 file preview.

use std::path::PathBuf;

use mosaic_msc7_core::{
    AuthenticatedDecodeOptions, AuthenticatedEncodeOptions, AuthenticatedStats, DecodeOptions,
    EncodeOptions, Error, decode_authenticated_file, encode_authenticated_file,
    inspect_authenticated_file,
};
use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyOSError};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use zeroize::Zeroizing;

/// Version of the private Rust/Python binding contract.
pub const BINDING_API_VERSION: u8 = 1;

create_exception!(mosaic_archive._native, AuthenticationError, PyException);
create_exception!(mosaic_archive._native, FormatError, PyException);
create_exception!(mosaic_archive._native, OptionsError, PyException);
create_exception!(mosaic_archive._native, CodecError, PyException);

#[cfg(windows)]
type WindowsOSErrorArguments = (i32, String, Option<String>, i32);

#[cfg(windows)]
fn windows_os_error_arguments(
    error: &std::io::Error,
    winerror: i32,
    operation: &'static str,
) -> WindowsOSErrorArguments {
    // CPython replaces this hint with its canonical Win32-to-errno mapping
    // when the fourth argument is present. Keep EACCES explicit as well so
    // this tuple remains meaningful to alternate ABI3-compatible runtimes.
    let errno_hint = match error.kind() {
        std::io::ErrorKind::PermissionDenied => 13,
        _ => 0,
    };
    (
        errno_hint,
        format!("{operation}: {error}"),
        Option::<String>::None,
        winerror,
    )
}

#[cfg(windows)]
fn io_to_python(py: Python<'_>, error: std::io::Error, operation: &'static str) -> PyErr {
    match error.raw_os_error() {
        Some(winerror) => {
            // On Windows, CPython derives the portable errno and concrete
            // OSError subclass from the fourth (winerror) argument. Passing
            // the Win32 value as errno would turn access denied (5) into an
            // unrelated errno instead of PermissionError(errno=13, winerror=5).
            match py
                .get_type::<PyOSError>()
                .call1(windows_os_error_arguments(&error, winerror, operation))
            {
                Ok(value) => PyErr::from_value(value.into_any()),
                Err(construction_error) => construction_error,
            }
        }
        None => PyErr::from(std::io::Error::new(
            error.kind(),
            format!("{operation}: {error}"),
        )),
    }
}

#[cfg(not(windows))]
fn io_to_python(py: Python<'_>, error: std::io::Error, operation: &'static str) -> PyErr {
    match error.raw_os_error() {
        Some(errno) => match py
            .get_type::<PyOSError>()
            .call1((errno, format!("{operation}: {error}")))
        {
            Ok(value) => PyErr::from_value(value.into_any()),
            Err(construction_error) => construction_error,
        },
        None => PyErr::from(std::io::Error::new(
            error.kind(),
            format!("{operation}: {error}"),
        )),
    }
}

fn to_python_error(py: Python<'_>, error: Error, operation: &'static str) -> PyErr {
    match error {
        Error::Io(error) => io_to_python(py, error, operation),
        Error::InvalidOptions(message) => OptionsError::new_err(message),
        Error::InvalidFormat(message) => FormatError::new_err(message),
        Error::Codec(message) => CodecError::new_err(message),
        Error::Authentication => {
            AuthenticationError::new_err("wrong password or archive was modified")
        }
    }
}

fn stats_to_python<'py>(
    py: Python<'py>,
    stats: AuthenticatedStats,
    hash_verified: bool,
) -> PyResult<Bound<'py, PyDict>> {
    let values = PyDict::new(py);
    let original_size = stats.core.original_bytes;
    let archive_ratio = if original_size == 0 {
        0.0
    } else {
        stats.archive_bytes as f64 / original_size as f64
    };

    values.set_item("format_name", "M7A0")?;
    values.set_item("archive_kind", "file")?;
    values.set_item("status", "non-stable-preview")?;
    values.set_item("stable", false)?;
    values.set_item("encrypted", true)?;
    values.set_item("authenticated", true)?;
    values.set_item("hash_verified", hash_verified)?;
    values.set_item("original_size", original_size)?;
    values.set_item("inner_encoded_size", stats.core.encoded_bytes)?;
    values.set_item("archive_size", stats.archive_bytes)?;
    values.set_item("segment_count", stats.core.segments)?;
    values.set_item("record_count", stats.core.records)?;
    values.set_item("deduplicated_records", stats.core.deduplicated_records)?;
    values.set_item("raw_records", stats.core.raw_records)?;
    values.set_item("lzma2_records", stats.core.lzma2_records)?;
    values.set_item("delta_zstd_records", stats.core.delta_zstd_records)?;
    values.set_item("zstd_records", stats.core.zstd_records)?;
    values.set_item("data_records", stats.data_records)?;
    values.set_item("padding_bytes", stats.padding_bytes)?;
    values.set_item("authentication_bytes", stats.authentication_bytes)?;
    values.set_item("inner_ratio", stats.core.ratio())?;
    values.set_item("archive_ratio", archive_ratio)?;
    Ok(values)
}

#[pyfunction]
#[pyo3(signature = (input, output, password, *, threads=1, kdf_log_n=17, max_input_bytes=8_589_934_592))]
fn encode_file<'py>(
    py: Python<'py>,
    input: PathBuf,
    output: PathBuf,
    password: &[u8],
    threads: usize,
    kdf_log_n: u8,
    max_input_bytes: u64,
) -> PyResult<Bound<'py, PyDict>> {
    let password = Zeroizing::new(password.to_vec());
    let options = AuthenticatedEncodeOptions {
        core: EncodeOptions {
            threads,
            max_input_bytes,
        },
        kdf_log_n,
    };
    let stats = py
        .detach(|| encode_authenticated_file(&input, &output, password.as_slice(), options))
        .map_err(|error| to_python_error(py, error, "native preview encode"))?;
    stats_to_python(py, stats, false)
}

#[allow(clippy::too_many_arguments)]
#[pyfunction]
#[pyo3(signature = (
    input,
    output,
    password,
    *,
    max_output_bytes=8_589_934_592,
    max_encoded_bytes=8_606_711_808,
    max_segments=131_072,
    max_records=2_000_000,
    max_expansion_ratio=16_384,
    max_archive_bytes=8_673_820_672,
    max_data_records=1_000_000,
    max_kdf_log_n=17
))]
fn decode_file<'py>(
    py: Python<'py>,
    input: PathBuf,
    output: PathBuf,
    password: &[u8],
    max_output_bytes: u64,
    max_encoded_bytes: u64,
    max_segments: u32,
    max_records: u64,
    max_expansion_ratio: u64,
    max_archive_bytes: u64,
    max_data_records: u64,
    max_kdf_log_n: u8,
) -> PyResult<Bound<'py, PyDict>> {
    let password = Zeroizing::new(password.to_vec());
    let options = decode_options(
        max_output_bytes,
        max_encoded_bytes,
        max_segments,
        max_records,
        max_expansion_ratio,
        max_archive_bytes,
        max_data_records,
        max_kdf_log_n,
    );
    let stats = py
        .detach(|| decode_authenticated_file(&input, &output, password.as_slice(), options))
        .map_err(|error| to_python_error(py, error, "native preview decode"))?;
    stats_to_python(py, stats, true)
}

#[allow(clippy::too_many_arguments)]
#[pyfunction]
#[pyo3(signature = (
    input,
    password,
    *,
    max_output_bytes=8_589_934_592,
    max_encoded_bytes=8_606_711_808,
    max_segments=131_072,
    max_records=2_000_000,
    max_expansion_ratio=16_384,
    max_archive_bytes=8_673_820_672,
    max_data_records=1_000_000,
    max_kdf_log_n=17
))]
fn inspect_file<'py>(
    py: Python<'py>,
    input: PathBuf,
    password: &[u8],
    max_output_bytes: u64,
    max_encoded_bytes: u64,
    max_segments: u32,
    max_records: u64,
    max_expansion_ratio: u64,
    max_archive_bytes: u64,
    max_data_records: u64,
    max_kdf_log_n: u8,
) -> PyResult<Bound<'py, PyDict>> {
    let password = Zeroizing::new(password.to_vec());
    let options = decode_options(
        max_output_bytes,
        max_encoded_bytes,
        max_segments,
        max_records,
        max_expansion_ratio,
        max_archive_bytes,
        max_data_records,
        max_kdf_log_n,
    );
    let stats = py
        .detach(|| inspect_authenticated_file(&input, password.as_slice(), options))
        .map_err(|error| to_python_error(py, error, "native preview inspect"))?;
    stats_to_python(py, stats, true)
}

#[allow(clippy::too_many_arguments)]
fn decode_options(
    max_output_bytes: u64,
    max_encoded_bytes: u64,
    max_segments: u32,
    max_records: u64,
    max_expansion_ratio: u64,
    max_archive_bytes: u64,
    max_data_records: u64,
    max_kdf_log_n: u8,
) -> AuthenticatedDecodeOptions {
    AuthenticatedDecodeOptions {
        core: DecodeOptions {
            max_output_bytes,
            max_encoded_bytes,
            max_segments,
            max_records,
            max_expansion_ratio,
        },
        max_archive_bytes,
        max_data_records,
        max_kdf_log_n,
    }
}

#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("BINDING_API_VERSION", BINDING_API_VERSION)?;
    module.add(
        "AuthenticationError",
        module.py().get_type::<AuthenticationError>(),
    )?;
    module.add("FormatError", module.py().get_type::<FormatError>())?;
    module.add("OptionsError", module.py().get_type::<OptionsError>())?;
    module.add("CodecError", module.py().get_type::<CodecError>())?;
    module.add_function(wrap_pyfunction!(encode_file, module)?)?;
    module.add_function(wrap_pyfunction!(decode_file, module)?)?;
    module.add_function(wrap_pyfunction!(inspect_file, module)?)?;
    Ok(())
}
