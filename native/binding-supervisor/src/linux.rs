//! Linux x86-64 cgroup-v2 delegation and lifecycle implementation.

use crate::{
    CONTROL_READY, CONTROL_REVOKE, CleanupFailures, HandoffPacket, LEAF_PREFIX, LifecycleError,
    MAX_CONTROL_BYTES, finish_lifecycle, is_valid_leaf_name, is_valid_session_name,
    is_valid_session_nonce, parse_controller_set, parse_id_set, parse_populated, parse_single_line,
    session_name,
};
use std::collections::BTreeSet;
use std::ffi::{CStr, CString};
use std::fmt::{self, Display, Formatter};
use std::io;
use std::mem::{MaybeUninit, size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;
use std::time::Duration;

const PARENT_CGROUP_FD: RawFd = 3;
const CONTROL_SOCKET_FD: RawFd = 4;
const CGROUP2_SUPER_MAGIC: libc::c_long = 0x6367_7270;
const SESSION_COLLISION_ATTEMPTS: usize = 16;
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(30);
const CLEANUP_POLL_INTERVAL: Duration = Duration::from_millis(10);
const REQUIRED_CONTROLLERS: [&str; 3] = ["cpuset", "memory", "pids"];
const ENABLE_CONTROLLERS: &[u8] = b"+cpuset +memory +pids";

#[derive(Debug)]
pub struct SupervisorError(String);

impl SupervisorError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    fn io(context: &str, error: io::Error) -> Self {
        Self(format!("{context}: {error}"))
    }
}

impl Display for SupervisorError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for SupervisorError {}

impl From<LifecycleError> for SupervisorError {
    fn from(error: LifecycleError) -> Self {
        Self(error.to_string())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
    mode: libc::mode_t,
}

impl Identity {
    fn require_directory(self, context: &str) -> Result<Self, SupervisorError> {
        if self.device == 0 || self.inode == 0 {
            return Err(SupervisorError::new(format!(
                "{context} has a zero filesystem identity"
            )));
        }
        if self.mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(SupervisorError::new(format!(
                "{context} is not a directory"
            )));
        }
        Ok(self)
    }

    fn require_regular(self, context: &str) -> Result<Self, SupervisorError> {
        if self.device == 0 || self.inode == 0 {
            return Err(SupervisorError::new(format!(
                "{context} has a zero filesystem identity"
            )));
        }
        if self.mode & libc::S_IFMT != libc::S_IFREG {
            return Err(SupervisorError::new(format!(
                "{context} is not a regular control file"
            )));
        }
        Ok(self)
    }
}

struct QualifiedParent {
    descriptor: OwnedFd,
    identity: Identity,
    effective_cpus: String,
    effective_mems: String,
}

struct Session {
    parent: QualifiedParent,
    descriptor: OwnedFd,
    identity: Identity,
    name: String,
    nonce: [u8; 16],
    cleanup_attempted: bool,
}

struct SignalMonitor {
    descriptor: OwnedFd,
}

#[derive(Debug)]
struct HandoffSendError {
    error: SupervisorError,
    transfer_possible: bool,
}

impl From<SupervisorError> for HandoffSendError {
    fn from(error: SupervisorError) -> Self {
        Self {
            error,
            transfer_possible: false,
        }
    }
}

enum BarrierOutcome {
    EofVerified(Result<(), SupervisorError>),
    EofUnverified(SupervisorError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControlRead {
    Byte(u8),
    EmptyRecord,
    InvalidLength,
    Truncated,
    WouldBlock,
}

mod cgroup;
mod control;
mod launcher;

use cgroup::{configure_session, create_session, qualify_parent, require_cgroup2, stable_identity};
use control::{send_handoff, validate_control_socket, wait_for_post_handoff_eof, wait_for_ready};

#[cfg(test)]
use cgroup::{
    contains_only_fixed_controllers, has_exact_fixed_controllers, parse_enabled_controller_set,
    require_exact_fixed_controllers, require_only_fixed_controllers,
};
#[cfg(test)]
use control::{receive_control_packet, send_one_rights_packet, validate_handoff_send_count};
pub fn run() -> Result<(), SupervisorError> {
    let signals = SignalMonitor::install()?;
    let (parent_descriptor, control_descriptor) = acquire_inherited_descriptors()?;
    let parent = qualify_parent(parent_descriptor)?;
    let mut session = create_session(parent)?;

    if let Err(primary) = configure_session(&session) {
        let cleanup = session.cleanup();
        return finish_lifecycle(Err(primary), cleanup).map_err(Into::into);
    }

    if let Err(primary) = wait_for_ready(&control_descriptor, &signals) {
        let cleanup = session.cleanup();
        return finish_lifecycle(Err(primary), cleanup).map_err(Into::into);
    }

    let initial_failure = match send_handoff(&control_descriptor, &session) {
        Ok(()) => None,
        Err(failure) if !failure.transfer_possible => {
            let cleanup = session.cleanup();
            return finish_lifecycle(Err(failure.error), cleanup).map_err(Into::into);
        }
        Err(failure) => Some(failure.error),
    };

    match wait_for_post_handoff_eof(&control_descriptor, &signals, initial_failure) {
        BarrierOutcome::EofVerified(primary) => {
            let cleanup = session.cleanup();
            finish_lifecycle(primary, cleanup).map_err(Into::into)
        }
        BarrierOutcome::EofUnverified(error) => {
            let session_name = session.name.clone();
            session.suppress_cleanup_for_recovery();
            Err(SupervisorError::new(format!(
                "{error}; peer EOF was not verified, so cleanup is suppressed and session {session_name} is left visible for recovery"
            )))
        }
    }
}

/// Run the opt-in clone3 ABI probe against inherited cgroup leaf FD 3.
///
/// This internal diagnostic proves only syscall/flag availability, namespace
/// PID 1, and initial cgroup placement. It does not execute a workload or
/// implement the accepted launcher self-test, never produces binding-eligible
/// evidence, and does not accept a pathname or workload command. The caller
/// owns creation, configuration, and removal of the already-open leaf.
#[doc(hidden)]
pub fn run_internal_clone3_abi_probe() -> Result<(), SupervisorError> {
    require_initial_descriptor_flags(PARENT_CGROUP_FD, "clone3 ABI probe cgroup leaf FD 3")?;
    require_descriptor_access(PARENT_CGROUP_FD, false, "clone3 ABI probe cgroup leaf FD 3")?;
    stable_identity(PARENT_CGROUP_FD, "clone3 ABI probe cgroup leaf FD 3")?
        .require_directory("clone3 ABI probe cgroup leaf FD 3")?;
    require_cgroup2(PARENT_CGROUP_FD, "clone3 ABI probe cgroup leaf FD 3")?;
    set_close_on_exec(PARENT_CGROUP_FD, "clone3 ABI probe cgroup leaf FD 3")?;
    // SAFETY: fixed FD 3 was validated above and ownership transfers exactly
    // once into the bounded ABI probe invocation.
    let leaf = unsafe { OwnedFd::from_raw_fd(PARENT_CGROUP_FD) };
    launcher::run(leaf)
}

fn acquire_inherited_descriptors() -> Result<(OwnedFd, OwnedFd), SupervisorError> {
    require_initial_descriptor_flags(PARENT_CGROUP_FD, "delegated parent cgroup FD 3")?;
    require_initial_descriptor_flags(CONTROL_SOCKET_FD, "control socket FD 4")?;
    require_descriptor_access(PARENT_CGROUP_FD, false, "delegated parent cgroup FD 3")?;
    require_descriptor_access(CONTROL_SOCKET_FD, true, "control socket FD 4")?;
    validate_control_socket(CONTROL_SOCKET_FD)?;
    let parent_identity = stable_identity(PARENT_CGROUP_FD, "delegated parent cgroup FD 3")?
        .require_directory("delegated parent cgroup FD 3")?;
    require_cgroup2(PARENT_CGROUP_FD, "delegated parent cgroup FD 3")?;
    if parent_identity.device == 0 || parent_identity.inode == 0 {
        return Err(SupervisorError::new(
            "delegated parent cgroup FD 3 has an invalid identity",
        ));
    }
    set_close_on_exec(PARENT_CGROUP_FD, "delegated parent cgroup FD 3")?;
    set_close_on_exec(CONTROL_SOCKET_FD, "control socket FD 4")?;

    // SAFETY: both fixed descriptor numbers were validated above and ownership
    // is transferred exactly once to these values.
    let parent = unsafe { OwnedFd::from_raw_fd(PARENT_CGROUP_FD) };
    // SAFETY: see the ownership argument above; FD 4 is distinct from FD 3.
    let control = unsafe { OwnedFd::from_raw_fd(CONTROL_SOCKET_FD) };
    Ok((parent, control))
}

fn require_descriptor_access(
    fd: RawFd,
    require_read_write: bool,
    context: &str,
) -> Result<(), SupervisorError> {
    // SAFETY: fcntl accepts any integer descriptor and does not dereference pointers.
    let status_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if status_flags < 0 {
        return Err(SupervisorError::io(
            &format!("cannot inspect access mode for {context}"),
            io::Error::last_os_error(),
        ));
    }
    if status_flags & libc::O_PATH != 0 {
        return Err(SupervisorError::new(format!(
            "{context} must not be an O_PATH descriptor"
        )));
    }
    let access_mode = status_flags & libc::O_ACCMODE;
    if access_mode == libc::O_WRONLY || require_read_write && access_mode != libc::O_RDWR {
        return Err(SupervisorError::new(format!(
            "{context} has an incompatible access mode"
        )));
    }
    Ok(())
}

fn require_initial_descriptor_flags(fd: RawFd, context: &str) -> Result<(), SupervisorError> {
    // SAFETY: fcntl accepts any integer descriptor and does not dereference pointers.
    let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if descriptor_flags < 0 {
        return Err(SupervisorError::io(
            &format!("cannot inspect {context}"),
            io::Error::last_os_error(),
        ));
    }
    if descriptor_flags & libc::FD_CLOEXEC != 0 {
        return Err(SupervisorError::new(format!(
            "{context} unexpectedly arrived with FD_CLOEXEC set"
        )));
    }
    Ok(())
}

fn set_close_on_exec(fd: RawFd, context: &str) -> Result<(), SupervisorError> {
    // SAFETY: fcntl accepts the validated live descriptor.
    let result = unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    if result < 0 {
        return Err(SupervisorError::io(
            &format!("cannot set FD_CLOEXEC on {context}"),
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
