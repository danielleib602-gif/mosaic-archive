use std::process::ExitCode;

const USAGE: &str = "mosaic-binding-supervisor\n\
Creates one non-authoritative delegated cgroup-v2 session.\n\
Production descriptors are fixed: parent cgroup directory FD 3 and connected\n\
AF_UNIX SOCK_SEQPACKET control FD 4. No pathname arguments are accepted.";

fn main() -> ExitCode {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    match (arguments.next(), arguments.next()) {
        (None, None) => run(),
        (Some(argument), None) if argument == "--help" => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        (Some(argument), None) if argument == "--version" => {
            println!("mosaic-binding-supervisor {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("unexpected arguments; no cgroup pathname is accepted");
            ExitCode::from(2)
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn run() -> ExitCode {
    match mosaic_binding_supervisor::linux::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("mosaic-binding-supervisor: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn run() -> ExitCode {
    eprintln!("mosaic-binding-supervisor is unsupported: Linux x86_64 is required");
    ExitCode::from(64)
}
