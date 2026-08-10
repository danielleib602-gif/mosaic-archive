use std::process::ExitCode;

const USAGE: &str = "mosaic-binding-supervisor\n\
Creates one non-authoritative delegated cgroup-v2 session.\n\
Production descriptors are fixed: parent cgroup directory FD 3 and connected\n\
AF_UNIX SOCK_SEQPACKET control FD 4. No pathname arguments are accepted.\n\
Internal opt-in diagnostic: --internal-clone3-abi-probe uses an already-open\n\
empty cgroup-v2 leaf FD 3. It probes only clone3 ABI, PID-namespace, and initial\n\
cgroup placement support; it always reports binding_eligible=false.";

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
        (Some(argument), None) if argument == "--internal-clone3-abi-probe" => {
            run_clone3_abi_probe()
        }
        _ => {
            eprintln!("unexpected arguments; no cgroup pathname is accepted");
            ExitCode::from(2)
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn run_clone3_abi_probe() -> ExitCode {
    match mosaic_binding_supervisor::linux::run_internal_clone3_abi_probe() {
        Ok(()) => {
            println!(
                "clone3 ABI probe passed (PID namespace and initial cgroup placement only); binding_eligible=false"
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("clone3 ABI probe failed; binding_eligible=false; {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn run_clone3_abi_probe() -> ExitCode {
    eprintln!("clone3 ABI probe is unsupported: Linux x86_64 is required; binding_eligible=false");
    ExitCode::from(64)
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
