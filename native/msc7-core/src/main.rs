use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::time::Instant;

use mosaic_msc7_core::{
    AuthenticatedDecodeOptions, AuthenticatedEncodeOptions, AuthenticatedStats, DecodeOptions,
    EncodeOptions, StreamStats, decode, decode_authenticated, decode_with_options, encode,
    encode_authenticated,
};
use same_file::Handle;
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

type DynError = Box<dyn std::error::Error>;

fn usage() -> &'static str {
    "M7R0 laboratory preview (not encrypted, not authenticated, not binding, not stable)\n\
M7A0 authenticated preview (encrypted and authenticated, not binding, not stable)\n\
usage:\n\
  mosaic-msc7-lab encode [--threads N] [--max-input-bytes N] [INPUT|-] [OUTPUT|-]\n\
  mosaic-msc7-lab decode [LIMIT OPTIONS] [INPUT|-] [OUTPUT|-]\n\
  mosaic-msc7-lab inspect [LIMIT OPTIONS] [INPUT|-]\n\
  mosaic-msc7-lab benchmark [--threads N] [INPUT|-]\n\
  mosaic-msc7-lab encode-auth --password-env NAME [--threads N] [--kdf-log-n N]\n\
                              [--max-input-bytes N] [INPUT|-] OUTPUT\n\
  mosaic-msc7-lab decode-auth --password-env NAME [AUTH LIMIT OPTIONS] [INPUT|-] OUTPUT\n\
  mosaic-msc7-lab inspect-auth --password-env NAME [AUTH LIMIT OPTIONS] [INPUT|-]\n\
  mosaic-msc7-lab benchmark-auth --password-env NAME [--threads N] [INPUT|-]\n\
LIMIT OPTIONS: --max-output-bytes N --max-encoded-bytes N --max-segments N\n\
               --max-records N --max-expansion-ratio N\n\
AUTH LIMIT OPTIONS: LIMIT OPTIONS plus --max-archive-bytes N --max-data-records N\n\
                    --max-kdf-log-n N\n\
Authenticated passwords are read only from the named environment variable; literal password\n\
arguments are not accepted. Authenticated encode/decode OUTPUT must be a file, not '-'."
}

fn take_required_option(args: &mut Vec<String>, name: &str) -> Result<String, String> {
    let matches: Vec<_> = args
        .iter()
        .enumerate()
        .filter_map(|(index, argument)| (argument == name).then_some(index))
        .collect();
    if matches.len() > 1 {
        return Err(format!("{name} may be specified only once"));
    }
    let Some(index) = matches.first().copied() else {
        return Err(format!("{name} is required"));
    };
    let value = args
        .get(index + 1)
        .ok_or_else(|| format!("{name} requires a value"))?;
    if value.is_empty() || value.starts_with('-') {
        return Err(format!("{name} requires a non-empty value"));
    }
    let value = value.clone();
    args.drain(index..=index + 1);
    Ok(value)
}

fn parse_password_env_name(args: &mut Vec<String>) -> Result<String, String> {
    let name = take_required_option(args, "--password-env")?;
    if name.contains(['\0', '=']) {
        return Err("--password-env names may not contain NUL or '='".to_owned());
    }
    Ok(name)
}

fn password_from_env(name: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let value = env::var(name).map_err(|error| match error {
        env::VarError::NotPresent => {
            format!("password environment variable {name:?} is not set")
        }
        env::VarError::NotUnicode(_) => {
            format!("password environment variable {name:?} is not valid Unicode")
        }
    })?;
    if value.is_empty() {
        return Err(format!(
            "password environment variable {name:?} must not be empty"
        ));
    }
    Ok(Zeroizing::new(value.into_bytes()))
}

fn parse_threads(args: &mut Vec<String>) -> Result<usize, String> {
    let matches: Vec<_> = args
        .iter()
        .enumerate()
        .filter_map(|(index, argument)| (argument == "--threads").then_some(index))
        .collect();
    if matches.len() > 1 {
        return Err("--threads may be specified only once".to_owned());
    }
    let Some(index) = matches.first().copied() else {
        return Ok(1);
    };
    if index + 1 >= args.len() {
        return Err("--threads requires a value".to_owned());
    }
    let value = args[index + 1]
        .parse::<usize>()
        .map_err(|_| "--threads must be an integer".to_owned())?;
    if !(1..=64).contains(&value) {
        return Err("--threads must be in 1..=64".to_owned());
    }
    args.drain(index..=index + 1);
    Ok(value)
}

fn reject_unknown_options(args: &[String]) -> Result<(), String> {
    if args
        .iter()
        .any(|argument| argument == "--password" || argument.starts_with("--password="))
    {
        return Err(
            "literal password arguments are not accepted; use --password-env NAME".to_owned(),
        );
    }
    if let Some(argument) = args
        .iter()
        .find(|argument| argument.starts_with('-') && argument.as_str() != "-")
    {
        return Err(format!("unknown option {argument:?}"));
    }
    Ok(())
}

fn take_limit(args: &mut Vec<String>, name: &str) -> Result<Option<u64>, String> {
    let matches: Vec<_> = args
        .iter()
        .enumerate()
        .filter_map(|(index, argument)| (argument == name).then_some(index))
        .collect();
    if matches.len() > 1 {
        return Err(format!("{name} may be specified only once"));
    }
    let Some(index) = matches.first().copied() else {
        return Ok(None);
    };
    let raw = args
        .get(index + 1)
        .ok_or_else(|| format!("{name} requires a value"))?;
    let value = raw
        .parse::<u64>()
        .map_err(|_| format!("{name} must be a positive integer"))?;
    if value == 0 {
        return Err(format!("{name} must be a positive integer"));
    }
    args.drain(index..=index + 1);
    Ok(Some(value))
}

fn parse_decode_options(args: &mut Vec<String>) -> Result<DecodeOptions, String> {
    let mut options = DecodeOptions::default();
    if let Some(value) = take_limit(args, "--max-output-bytes")? {
        options.max_output_bytes = value;
    }
    if let Some(value) = take_limit(args, "--max-encoded-bytes")? {
        options.max_encoded_bytes = value;
    }
    if let Some(value) = take_limit(args, "--max-segments")? {
        options.max_segments = value
            .try_into()
            .map_err(|_| "--max-segments exceeds uint32".to_owned())?;
    }
    if let Some(value) = take_limit(args, "--max-records")? {
        options.max_records = value;
    }
    if let Some(value) = take_limit(args, "--max-expansion-ratio")? {
        options.max_expansion_ratio = value;
    }
    Ok(options)
}

fn parse_kdf_log_n(args: &mut Vec<String>) -> Result<u8, String> {
    let default = AuthenticatedEncodeOptions::default().kdf_log_n;
    let Some(value) = take_limit(args, "--kdf-log-n")? else {
        return Ok(default);
    };
    if !(14..=18).contains(&value) {
        return Err("--kdf-log-n must be in 14..=18".to_owned());
    }
    Ok(value as u8)
}

fn parse_authenticated_decode_options(
    args: &mut Vec<String>,
) -> Result<AuthenticatedDecodeOptions, String> {
    let core = parse_decode_options(args)?;
    let mut options = AuthenticatedDecodeOptions {
        core,
        ..AuthenticatedDecodeOptions::default()
    };
    if let Some(value) = take_limit(args, "--max-archive-bytes")? {
        options.max_archive_bytes = value;
    }
    if let Some(value) = take_limit(args, "--max-data-records")? {
        options.max_data_records = value;
    }
    if let Some(value) = take_limit(args, "--max-kdf-log-n")? {
        if !(14..=18).contains(&value) {
            return Err("--max-kdf-log-n must be in 14..=18".to_owned());
        }
        options.max_kdf_log_n = value as u8;
    }
    Ok(options)
}

fn required_file_paths<'a>(
    args: &'a [String],
    command: &str,
) -> Result<(Option<&'a str>, &'a str), String> {
    let (input_path, output_path) = match args {
        [output] => (None, output.as_str()),
        [input, output] => (Some(input.as_str()), output.as_str()),
        [] => return Err(format!("{command} requires an OUTPUT file")),
        _ => return Err(format!("{command} accepts at most INPUT and OUTPUT")),
    };
    if output_path.is_empty() || output_path == "-" {
        return Err(format!("{command} OUTPUT must be a file, not '-'"));
    }
    Ok((input_path, output_path))
}

fn input(path: Option<&str>) -> io::Result<Box<dyn Read>> {
    match path {
        None | Some("-") => Ok(Box::new(io::stdin().lock())),
        Some(path) => Ok(Box::new(BufReader::new(File::open(path)?))),
    }
}

fn ensure_distinct_output(path: &Path, source: &Handle) -> io::Result<()> {
    let destination = match OpenOptions::new().write(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if *source == Handle::from_file(destination.try_clone()?)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "input and output identify the same file",
        ));
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

fn with_io<T>(
    input_path: Option<&str>,
    output_path: Option<&str>,
    action: impl FnOnce(Box<dyn Read>, &mut dyn Write) -> Result<T, DynError>,
) -> Result<T, DynError> {
    let source_file = match input_path {
        None | Some("-") => None,
        Some(path) => Some(File::open(path)?),
    };
    let file_output = output_path.is_some_and(|path| path != "-");
    let source_identity = if file_output {
        Some(match source_file.as_ref() {
            Some(file) => Handle::from_file(file.try_clone()?)?,
            None => Handle::stdin()?,
        })
    } else {
        None
    };
    let source: Box<dyn Read> = match source_file {
        Some(file) => Box::new(BufReader::new(file)),
        None => Box::new(io::stdin().lock()),
    };
    let Some(path) = output_path.filter(|path| *path != "-") else {
        let mut destination = io::stdout().lock();
        return action(source, &mut destination);
    };

    let destination = Path::new(path);
    ensure_distinct_output(
        destination,
        source_identity
            .as_ref()
            .expect("file output has a source identity"),
    )?;
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = NamedTempFile::new_in(parent)?;
    let value = {
        let mut writer = BufWriter::new(temporary.as_file_mut());
        let value = action(source, &mut writer)?;
        writer.flush()?;
        value
    };
    temporary.as_file().sync_all()?;
    temporary
        .persist(destination)
        .map_err(|error| error.error)?;
    sync_parent(parent)?;
    Ok(value)
}

#[derive(Clone, Copy)]
enum Direction {
    Encode,
    Decode,
}

fn print_stats(label: &str, stats: StreamStats, elapsed_seconds: f64, direction: Direction) {
    let mib = stats.original_bytes as f64 / (1024.0 * 1024.0);
    let (input_bytes, output_bytes) = match direction {
        Direction::Encode => (stats.original_bytes, stats.encoded_bytes),
        Direction::Decode => (stats.encoded_bytes, stats.original_bytes),
    };
    let throughput = if elapsed_seconds == 0.0 {
        0.0
    } else {
        mib / elapsed_seconds
    };
    eprintln!(
        "{label}: input={} output={} ratio={:.6} segments={} records={} dedup={} raw={} lzma2={} delta-zstd={} zstd={} seconds={elapsed_seconds:.6} MiB/s={throughput:.3}",
        input_bytes,
        output_bytes,
        stats.ratio(),
        stats.segments,
        stats.records,
        stats.deduplicated_records,
        stats.raw_records,
        stats.lzma2_records,
        stats.delta_zstd_records,
        stats.zstd_records,
    );
}

fn authenticated_ratio(stats: &AuthenticatedStats) -> f64 {
    if stats.core.original_bytes == 0 {
        0.0
    } else {
        stats.archive_bytes as f64 / stats.core.original_bytes as f64
    }
}

fn print_authenticated_stats(
    label: &str,
    stats: &AuthenticatedStats,
    elapsed_seconds: f64,
    direction: Direction,
) {
    let mib = stats.core.original_bytes as f64 / (1024.0 * 1024.0);
    let (input_bytes, output_bytes) = match direction {
        Direction::Encode => (stats.core.original_bytes, stats.archive_bytes),
        Direction::Decode => (stats.archive_bytes, stats.core.original_bytes),
    };
    let throughput = if elapsed_seconds == 0.0 {
        0.0
    } else {
        mib / elapsed_seconds
    };
    eprintln!(
        "{label}: input={input_bytes} output={output_bytes} ratio={:.6} inner_encoded={} archive_bytes={} data_records={} padding_bytes={} authentication_bytes={} segments={} records={} dedup={} raw={} lzma2={} delta-zstd={} zstd={} seconds={elapsed_seconds:.6} MiB/s={throughput:.3}",
        authenticated_ratio(stats),
        stats.core.encoded_bytes,
        stats.archive_bytes,
        stats.data_records,
        stats.padding_bytes,
        stats.authentication_bytes,
        stats.core.segments,
        stats.core.records,
        stats.core.deduplicated_records,
        stats.core.raw_records,
        stats.core.lzma2_records,
        stats.core.delta_zstd_records,
        stats.core.zstd_records,
    );
}

fn print_authenticated_inspection(stats: &AuthenticatedStats) {
    println!("format=M7A0");
    println!("status=non-stable-preview");
    println!("encrypted=true");
    println!("authenticated=true");
    println!("binding=false");
    println!("stable=false");
    println!("original_bytes={}", stats.core.original_bytes);
    println!("inner_encoded_bytes={}", stats.core.encoded_bytes);
    println!("archive_bytes={}", stats.archive_bytes);
    println!("inner_ratio={:.6}", stats.core.ratio());
    println!("archive_ratio={:.6}", authenticated_ratio(stats));
    println!("segments={}", stats.core.segments);
    println!("records={}", stats.core.records);
    println!("deduplicated_records={}", stats.core.deduplicated_records);
    println!("raw_records={}", stats.core.raw_records);
    println!("lzma2_records={}", stats.core.lzma2_records);
    println!("delta_zstd_records={}", stats.core.delta_zstd_records);
    println!("zstd_records={}", stats.core.zstd_records);
    println!("data_records={}", stats.data_records);
    println!("padding_bytes={}", stats.padding_bytes);
    println!("authentication_bytes={}", stats.authentication_bytes);
}

fn run() -> Result<(), DynError> {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        println!("{}", usage());
        return Ok(());
    }
    let command = args.remove(0);
    match command.as_str() {
        "encode" => {
            let threads = parse_threads(&mut args)?;
            let max_input_bytes = take_limit(&mut args, "--max-input-bytes")?
                .unwrap_or_else(|| EncodeOptions::default().max_input_bytes);
            reject_unknown_options(&args)?;
            if args.len() > 2 {
                return Err("encode accepts at most INPUT and OUTPUT".into());
            }
            let started = Instant::now();
            let stats = with_io(
                args.first().map(String::as_str),
                args.get(1).map(String::as_str),
                |source, destination| {
                    Ok(encode(
                        source,
                        destination,
                        EncodeOptions {
                            threads,
                            max_input_bytes,
                        },
                    )?)
                },
            )?;
            print_stats(
                "encode",
                stats,
                started.elapsed().as_secs_f64(),
                Direction::Encode,
            );
        }
        "encode-auth" => {
            let password_env_name = parse_password_env_name(&mut args)?;
            let threads = parse_threads(&mut args)?;
            let kdf_log_n = parse_kdf_log_n(&mut args)?;
            let max_input_bytes = take_limit(&mut args, "--max-input-bytes")?
                .unwrap_or_else(|| EncodeOptions::default().max_input_bytes);
            reject_unknown_options(&args)?;
            let (input_path, output_path) = required_file_paths(&args, "encode-auth")?;
            let password = password_from_env(&password_env_name)?;
            let started = Instant::now();
            let stats = with_io(input_path, Some(output_path), |source, destination| {
                Ok(encode_authenticated(
                    source,
                    destination,
                    password.as_slice(),
                    AuthenticatedEncodeOptions {
                        core: EncodeOptions {
                            threads,
                            max_input_bytes,
                        },
                        kdf_log_n,
                    },
                )?)
            })?;
            print_authenticated_stats(
                "encode-auth",
                &stats,
                started.elapsed().as_secs_f64(),
                Direction::Encode,
            );
        }
        "decode" => {
            let options = parse_decode_options(&mut args)?;
            reject_unknown_options(&args)?;
            if args.len() > 2 {
                return Err("decode accepts at most INPUT and OUTPUT".into());
            }
            let started = Instant::now();
            let stats = with_io(
                args.first().map(String::as_str),
                args.get(1).map(String::as_str),
                |source, destination| Ok(decode_with_options(source, destination, options)?),
            )?;
            print_stats(
                "decode",
                stats,
                started.elapsed().as_secs_f64(),
                Direction::Decode,
            );
        }
        "decode-auth" => {
            let password_env_name = parse_password_env_name(&mut args)?;
            let options = parse_authenticated_decode_options(&mut args)?;
            reject_unknown_options(&args)?;
            let (input_path, output_path) = required_file_paths(&args, "decode-auth")?;
            let password = password_from_env(&password_env_name)?;
            let started = Instant::now();
            let stats = with_io(input_path, Some(output_path), |source, destination| {
                Ok(decode_authenticated(
                    source,
                    destination,
                    password.as_slice(),
                    options,
                )?)
            })?;
            print_authenticated_stats(
                "decode-auth",
                &stats,
                started.elapsed().as_secs_f64(),
                Direction::Decode,
            );
        }
        "inspect" => {
            let options = parse_decode_options(&mut args)?;
            reject_unknown_options(&args)?;
            if args.len() > 1 {
                return Err("inspect accepts at most INPUT".into());
            }
            let stats = decode_with_options(
                input(args.first().map(String::as_str))?,
                io::sink(),
                options,
            )?;
            println!("format=M7R0");
            println!("status=non-stable-preview");
            println!("encrypted=false");
            println!("authenticated=false");
            println!("binding=false");
            println!("stable=false");
            println!("original_bytes={}", stats.original_bytes);
            println!("encoded_bytes={}", stats.encoded_bytes);
            println!("ratio={:.6}", stats.ratio());
            println!("segments={}", stats.segments);
            println!("records={}", stats.records);
            println!("deduplicated_records={}", stats.deduplicated_records);
            println!("raw_records={}", stats.raw_records);
            println!("lzma2_records={}", stats.lzma2_records);
            println!("delta_zstd_records={}", stats.delta_zstd_records);
            println!("zstd_records={}", stats.zstd_records);
        }
        "inspect-auth" => {
            let password_env_name = parse_password_env_name(&mut args)?;
            let options = parse_authenticated_decode_options(&mut args)?;
            reject_unknown_options(&args)?;
            if args.len() > 1 {
                return Err("inspect-auth accepts at most INPUT".into());
            }
            let password = password_from_env(&password_env_name)?;
            let stats = decode_authenticated(
                input(args.first().map(String::as_str))?,
                io::sink(),
                password.as_slice(),
                options,
            )?;
            print_authenticated_inspection(&stats);
        }
        "benchmark" => {
            let threads = parse_threads(&mut args)?;
            reject_unknown_options(&args)?;
            if args.len() > 1 {
                return Err("benchmark accepts at most INPUT".into());
            }
            let mut source = Vec::new();
            input(args.first().map(String::as_str))?.read_to_end(&mut source)?;
            let mut archive = Vec::new();
            let encode_started = Instant::now();
            let encode_stats = encode(
                source.as_slice(),
                &mut archive,
                EncodeOptions {
                    threads,
                    ..EncodeOptions::default()
                },
            )?;
            let encode_elapsed = encode_started.elapsed().as_secs_f64();
            let decode_started = Instant::now();
            let decode_stats = decode(archive.as_slice(), io::sink())?;
            let decode_elapsed = decode_started.elapsed().as_secs_f64();
            print_stats("encode", encode_stats, encode_elapsed, Direction::Encode);
            print_stats("decode", decode_stats, decode_elapsed, Direction::Decode);
        }
        "benchmark-auth" => {
            let password_env_name = parse_password_env_name(&mut args)?;
            let threads = parse_threads(&mut args)?;
            reject_unknown_options(&args)?;
            if args.len() > 1 {
                return Err("benchmark-auth accepts at most INPUT".into());
            }
            let password = password_from_env(&password_env_name)?;
            let mut source = Vec::new();
            input(args.first().map(String::as_str))?.read_to_end(&mut source)?;
            let mut archive = Vec::new();
            let encode_started = Instant::now();
            let encode_stats = encode_authenticated(
                source.as_slice(),
                &mut archive,
                password.as_slice(),
                AuthenticatedEncodeOptions {
                    core: EncodeOptions {
                        threads,
                        ..EncodeOptions::default()
                    },
                    ..AuthenticatedEncodeOptions::default()
                },
            )?;
            let encode_elapsed = encode_started.elapsed().as_secs_f64();
            let decode_started = Instant::now();
            let decode_stats = decode_authenticated(
                archive.as_slice(),
                io::sink(),
                password.as_slice(),
                AuthenticatedDecodeOptions::default(),
            )?;
            let decode_elapsed = decode_started.elapsed().as_secs_f64();
            print_authenticated_stats(
                "encode-auth",
                &encode_stats,
                encode_elapsed,
                Direction::Encode,
            );
            print_authenticated_stats(
                "decode-auth",
                &decode_stats,
                decode_elapsed,
                Direction::Decode,
            );
        }
        _ => return Err(format!("unknown command {command:?}\n{}", usage()).into()),
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("mosaic-msc7-lab: {error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn resource_options_are_parsed_before_positional_paths() {
        let mut encode_args = vec![
            "input".to_owned(),
            "--threads".to_owned(),
            "8".to_owned(),
            "--max-input-bytes".to_owned(),
            "12345".to_owned(),
            "output".to_owned(),
        ];
        assert_eq!(parse_threads(&mut encode_args).expect("threads parse"), 8);
        assert_eq!(
            take_limit(&mut encode_args, "--max-input-bytes").expect("limit parses"),
            Some(12_345)
        );
        assert_eq!(encode_args, ["input", "output"]);

        let mut decode_args = vec![
            "--max-output-bytes".to_owned(),
            "4096".to_owned(),
            "archive".to_owned(),
        ];
        let options = parse_decode_options(&mut decode_args).expect("decode options parse");
        assert_eq!(options.max_output_bytes, 4096);
        assert_eq!(decode_args, ["archive"]);
    }

    #[test]
    fn invalid_resource_options_fail_before_io() {
        let mut threads = vec!["--threads".to_owned(), "0".to_owned()];
        assert!(parse_threads(&mut threads).is_err());
        let mut duplicate_threads = vec![
            "--threads".to_owned(),
            "1".to_owned(),
            "--threads".to_owned(),
            "2".to_owned(),
        ];
        assert!(parse_threads(&mut duplicate_threads).is_err());
        let mut duplicate = vec![
            "--max-output-bytes".to_owned(),
            "1".to_owned(),
            "--max-output-bytes".to_owned(),
            "2".to_owned(),
        ];
        assert!(parse_decode_options(&mut duplicate).is_err());
        assert!(reject_unknown_options(&["--typo".to_owned()]).is_err());
        assert!(reject_unknown_options(&["-".to_owned()]).is_ok());
    }

    #[test]
    fn authenticated_options_are_parsed_before_positional_paths() {
        let mut encode_args = vec![
            "input".to_owned(),
            "--password-env".to_owned(),
            "MOSAIC_TEST_PASSWORD".to_owned(),
            "--threads".to_owned(),
            "8".to_owned(),
            "--kdf-log-n".to_owned(),
            "14".to_owned(),
            "--max-input-bytes".to_owned(),
            "12345".to_owned(),
            "output".to_owned(),
        ];
        assert_eq!(
            parse_password_env_name(&mut encode_args).expect("password env name parses"),
            "MOSAIC_TEST_PASSWORD"
        );
        assert_eq!(parse_threads(&mut encode_args).expect("threads parse"), 8);
        assert_eq!(
            parse_kdf_log_n(&mut encode_args).expect("KDF work factor parses"),
            14
        );
        assert_eq!(
            take_limit(&mut encode_args, "--max-input-bytes").expect("limit parses"),
            Some(12_345)
        );
        assert_eq!(encode_args, ["input", "output"]);
        assert_eq!(
            required_file_paths(&encode_args, "encode-auth").expect("paths parse"),
            (Some("input"), "output")
        );

        let mut decode_args = vec![
            "--password-env".to_owned(),
            "MOSAIC_TEST_PASSWORD".to_owned(),
            "--max-output-bytes".to_owned(),
            "4096".to_owned(),
            "--max-archive-bytes".to_owned(),
            "8192".to_owned(),
            "--max-data-records".to_owned(),
            "7".to_owned(),
            "--max-kdf-log-n".to_owned(),
            "16".to_owned(),
            "archive".to_owned(),
            "restored".to_owned(),
        ];
        parse_password_env_name(&mut decode_args).expect("password env name parses");
        let options = parse_authenticated_decode_options(&mut decode_args).expect("limits parse");
        assert_eq!(options.core.max_output_bytes, 4096);
        assert_eq!(options.max_archive_bytes, 8192);
        assert_eq!(options.max_data_records, 7);
        assert_eq!(options.max_kdf_log_n, 16);
        assert_eq!(decode_args, ["archive", "restored"]);
    }

    #[test]
    fn invalid_authenticated_options_fail_before_io() {
        assert!(parse_password_env_name(&mut Vec::new()).is_err());
        assert!(
            parse_password_env_name(&mut vec!["--password-env".to_owned(), "".to_owned()]).is_err()
        );
        assert!(
            parse_password_env_name(&mut vec![
                "--password-env".to_owned(),
                "ONE".to_owned(),
                "--password-env".to_owned(),
                "TWO".to_owned(),
            ])
            .is_err()
        );
        assert!(
            parse_password_env_name(&mut vec![
                "--password-env".to_owned(),
                "--threads".to_owned(),
                "1".to_owned(),
            ])
            .is_err()
        );

        let mut low_kdf = vec!["--kdf-log-n".to_owned(), "13".to_owned()];
        assert!(parse_kdf_log_n(&mut low_kdf).is_err());
        let mut high_kdf = vec!["--kdf-log-n".to_owned(), "19".to_owned()];
        assert!(parse_kdf_log_n(&mut high_kdf).is_err());
        let mut duplicate_outer_limit = vec![
            "--max-archive-bytes".to_owned(),
            "1".to_owned(),
            "--max-archive-bytes".to_owned(),
            "2".to_owned(),
        ];
        assert!(parse_authenticated_decode_options(&mut duplicate_outer_limit).is_err());
        let mut invalid_kdf_policy = vec!["--max-kdf-log-n".to_owned(), "19".to_owned()];
        assert!(parse_authenticated_decode_options(&mut invalid_kdf_policy).is_err());

        let mut literal_password = vec![
            "--password-env".to_owned(),
            "MOSAIC_TEST_PASSWORD".to_owned(),
            "--password".to_owned(),
            "must-not-be-accepted".to_owned(),
        ];
        parse_password_env_name(&mut literal_password).expect("password env name parses");
        assert!(reject_unknown_options(&literal_password).is_err());

        let attempted_secret = "must-not-appear-in-the-error";
        let error = reject_unknown_options(&[format!("--password={attempted_secret}")])
            .expect_err("literal password must be rejected");
        assert!(!error.contains(attempted_secret));
    }

    #[test]
    fn authenticated_encode_and_decode_require_file_output() {
        assert!(required_file_paths(&[], "encode-auth").is_err());
        assert!(required_file_paths(&["-".to_owned()], "encode-auth").is_err());
        assert!(
            required_file_paths(&["archive".to_owned(), "-".to_owned()], "decode-auth").is_err()
        );
        assert_eq!(
            required_file_paths(&["archive.m7a".to_owned()], "encode-auth")
                .expect("one path is the required output"),
            (None, "archive.m7a")
        );
    }

    #[test]
    fn password_environment_child() {
        const CHILD_MODE: &str = "MOSAIC_M7A0_PASSWORD_TEST_CHILD_MODE";
        const CHILD_NAME: &str = "MOSAIC_M7A0_PASSWORD_TEST_CHILD_NAME";
        let Some(mode) = env::var_os(CHILD_MODE) else {
            return;
        };
        let name = env::var(CHILD_NAME).expect("parent provides the temporary variable name");
        match mode.to_str().expect("test mode is Unicode") {
            "set" => assert_eq!(
                password_from_env(&name)
                    .expect("non-empty password is accepted")
                    .as_slice(),
                b"isolated child password"
            ),
            "empty" => assert!(password_from_env(&name).is_err()),
            "unset" => assert!(password_from_env(&name).is_err()),
            other => panic!("unexpected child mode {other:?}"),
        }
    }

    #[test]
    fn password_is_read_from_an_isolated_environment_and_cleaned_up() {
        const CHILD_MODE: &str = "MOSAIC_M7A0_PASSWORD_TEST_CHILD_MODE";
        const CHILD_NAME: &str = "MOSAIC_M7A0_PASSWORD_TEST_CHILD_NAME";
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after the Unix epoch")
            .as_nanos();

        for (suffix, mode, value) in [
            ("SET", "set", Some("isolated child password")),
            ("EMPTY", "empty", Some("")),
            ("UNSET", "unset", None),
        ] {
            let name = format!(
                "MOSAIC_M7A0_PASSWORD_{}_{}_{}",
                std::process::id(),
                unique,
                suffix
            );
            assert!(env::var_os(&name).is_none());
            let mut child = Command::new(env::current_exe().expect("test executable is available"));
            child
                .args([
                    "--exact",
                    "tests::password_environment_child",
                    "--nocapture",
                ])
                .env(CHILD_MODE, mode)
                .env(CHILD_NAME, &name)
                .env_remove(&name);
            if let Some(value) = value {
                child.env(&name, value);
            }
            let output = child.output().expect("password test child starts");
            assert!(
                output.status.success(),
                "password test child failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                env::var_os(&name).is_none(),
                "the child environment must not leak into the parent"
            );
        }
    }

    #[test]
    fn output_alias_is_rejected_before_truncation() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after the Unix epoch")
            .as_nanos();
        let directory = env::temp_dir().join(format!("m7r0-alias-{}-{unique}", std::process::id()));
        fs::create_dir(&directory).expect("temporary directory is created");
        let source_path = directory.join("source.bin");
        let alias_path = directory.join("alias.bin");
        let original = b"must not be truncated";
        fs::write(&source_path, original).expect("source is written");
        fs::hard_link(&source_path, &alias_path).expect("hardlink is created");

        let identity = Handle::from_path(&source_path).expect("source identity is available");
        let error =
            ensure_distinct_output(&alias_path, &identity).expect_err("alias must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            fs::read(&source_path).expect("source is readable"),
            original
        );

        fs::remove_dir_all(directory).expect("temporary directory is removed");
    }

    #[test]
    fn failed_operation_preserves_existing_destination() {
        let directory = tempfile::tempdir().expect("temporary directory is created");
        let source = directory.path().join("source.bin");
        let destination = directory.path().join("output.bin");
        fs::write(&source, b"source").expect("source is written");
        fs::write(&destination, b"existing destination").expect("destination is written");

        let result: Result<(), DynError> =
            with_io(source.to_str(), destination.to_str(), |_reader, writer| {
                writer.write_all(b"partial replacement")?;
                Err(io::Error::other("injected failure").into())
            });
        assert!(result.is_err());
        assert_eq!(
            fs::read(destination).expect("destination is readable"),
            b"existing destination"
        );
    }

    #[test]
    fn failed_authenticated_decode_preserves_existing_destination() {
        let directory = tempfile::tempdir().expect("temporary directory is created");
        let archive_path = directory.path().join("source.m7a");
        let destination = directory.path().join("output.bin");
        let mut archive = Vec::new();
        encode_authenticated(
            b"authenticated input".as_slice(),
            &mut archive,
            b"correct password",
            AuthenticatedEncodeOptions {
                kdf_log_n: 14,
                ..AuthenticatedEncodeOptions::default()
            },
        )
        .expect("authenticated fixture encodes");
        fs::write(&archive_path, archive).expect("archive is written");
        fs::write(&destination, b"existing destination").expect("destination is written");

        let result = with_io(
            archive_path.to_str(),
            destination.to_str(),
            |reader, writer| {
                Ok(decode_authenticated(
                    reader,
                    writer,
                    b"wrong password",
                    AuthenticatedDecodeOptions::default(),
                )?)
            },
        );
        assert!(result.is_err());
        assert_eq!(
            fs::read(destination).expect("destination is readable"),
            b"existing destination"
        );
    }
}
