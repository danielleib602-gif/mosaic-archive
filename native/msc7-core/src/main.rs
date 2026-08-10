use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::time::Instant;

use mosaic_msc7_core::{
    DecodeOptions, EncodeOptions, StreamStats, decode, decode_with_options, encode,
};
use same_file::Handle;
use tempfile::NamedTempFile;

type DynError = Box<dyn std::error::Error>;

fn usage() -> &'static str {
    "non-stable M7R0 laboratory preview (not encrypted, not authenticated, not binding, not stable)\n\
usage:\n\
  mosaic-msc7-lab encode [--threads N] [--max-input-bytes N] [INPUT|-] [OUTPUT|-]\n\
  mosaic-msc7-lab decode [LIMIT OPTIONS] [INPUT|-] [OUTPUT|-]\n\
  mosaic-msc7-lab inspect [LIMIT OPTIONS] [INPUT|-]\n\
  mosaic-msc7-lab benchmark [--threads N] [INPUT|-]\n\
LIMIT OPTIONS: --max-output-bytes N --max-encoded-bytes N --max-segments N\n\
               --max-records N --max-expansion-ratio N"
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
}
