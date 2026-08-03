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

fn validate_control_socket(fd: RawFd) -> Result<(), SupervisorError> {
    let identity = stable_identity(fd, "control socket FD 4")?;
    if identity.mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err(SupervisorError::new("control FD 4 is not a socket"));
    }

    let socket_type = get_socket_option(fd, libc::SO_TYPE, "SO_TYPE")?;
    if socket_type != libc::SOCK_SEQPACKET {
        return Err(SupervisorError::new(
            "control FD 4 is not a SOCK_SEQPACKET socket",
        ));
    }
    let accepting = get_socket_option(fd, libc::SO_ACCEPTCONN, "SO_ACCEPTCONN")?;
    if accepting != 0 {
        return Err(SupervisorError::new(
            "control FD 4 is a listening socket, not a connected endpoint",
        ));
    }
    require_unix_socket_address(fd, false)?;
    require_unix_socket_address(fd, true)?;
    Ok(())
}

fn get_socket_option(
    fd: RawFd,
    option: libc::c_int,
    name: &str,
) -> Result<libc::c_int, SupervisorError> {
    let mut value = MaybeUninit::<libc::c_int>::uninit();
    let mut length = size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: value points to length writable bytes and length is initialized.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            value.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result < 0 {
        return Err(SupervisorError::io(
            &format!("cannot read control socket {name}"),
            io::Error::last_os_error(),
        ));
    }
    if length as usize != size_of::<libc::c_int>() {
        return Err(SupervisorError::new(format!(
            "control socket {name} returned an unexpected value length"
        )));
    }
    // SAFETY: getsockopt succeeded and reported exactly one initialized c_int.
    Ok(unsafe { value.assume_init() })
}

fn require_unix_socket_address(fd: RawFd, peer: bool) -> Result<(), SupervisorError> {
    // SAFETY: sockaddr_storage is valid when zero-initialized.
    let mut address: libc::sockaddr_storage = unsafe { zeroed() };
    let mut length = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: address and length describe a writable sockaddr buffer.
    let result = unsafe {
        if peer {
            libc::getpeername(
                fd,
                (&mut address as *mut libc::sockaddr_storage).cast(),
                &mut length,
            )
        } else {
            libc::getsockname(
                fd,
                (&mut address as *mut libc::sockaddr_storage).cast(),
                &mut length,
            )
        }
    };
    if result < 0 {
        let endpoint = if peer { "peer" } else { "local" };
        return Err(SupervisorError::io(
            &format!("cannot inspect control socket {endpoint} address"),
            io::Error::last_os_error(),
        ));
    }
    if length < size_of::<libc::sa_family_t>() as libc::socklen_t
        || libc::c_int::from(address.ss_family) != libc::AF_UNIX
    {
        return Err(SupervisorError::new(
            "control FD 4 is not an AF_UNIX connected endpoint",
        ));
    }
    Ok(())
}

fn qualify_parent(descriptor: OwnedFd) -> Result<QualifiedParent, SupervisorError> {
    let raw_fd = descriptor.as_raw_fd();
    let identity = stable_identity(raw_fd, "delegated parent cgroup")?
        .require_directory("delegated parent cgroup")?;
    require_cgroup2(raw_fd, "delegated parent cgroup")?;
    require_domain_unpopulated(raw_fd, "delegated parent cgroup")?;
    require_empty_processes(raw_fd, "delegated parent cgroup")?;

    let controllers = parse_controller_set(&read_control(raw_fd, "cgroup.controllers")?)
        .map_err(|error| SupervisorError::new(format!("invalid cgroup.controllers: {error}")))?;
    require_controllers(&controllers, "delegated parent cgroup.controllers")?;

    let effective_cpus_bytes = read_control(raw_fd, "cpuset.cpus.effective")?;
    parse_id_set(&effective_cpus_bytes).map_err(|error| {
        SupervisorError::new(format!("invalid parent cpuset.cpus.effective: {error}"))
    })?;
    let effective_mems_bytes = read_control(raw_fd, "cpuset.mems.effective")?;
    parse_id_set(&effective_mems_bytes).map_err(|error| {
        SupervisorError::new(format!("invalid parent cpuset.mems.effective: {error}"))
    })?;
    let effective_cpus = parse_single_line(&effective_cpus_bytes)
        .expect("ID-set parsing already enforced one line")
        .to_owned();
    let effective_mems = parse_single_line(&effective_mems_bytes)
        .expect("ID-set parsing already enforced one line")
        .to_owned();

    for (name, access) in [
        ("cgroup.controllers", Access::Read),
        ("cgroup.subtree_control", Access::ReadWrite),
        ("cgroup.type", Access::Read),
        ("cgroup.events", Access::Read),
        ("cgroup.procs", Access::ReadWrite),
        ("cpuset.cpus.effective", Access::Read),
        ("cpuset.mems.effective", Access::Read),
    ] {
        verify_control_access(raw_fd, name, access)?;
    }

    let initially_delegated =
        parse_enabled_controller_set(&read_control(raw_fd, "cgroup.subtree_control")?).map_err(
            |error| {
                SupervisorError::new(format!(
                    "invalid parent cgroup.subtree_control before mutation: {error}"
                ))
            },
        )?;
    require_only_fixed_controllers(
        &initially_delegated,
        "delegated parent cgroup.subtree_control before mutation",
    )?;
    write_control(raw_fd, "cgroup.subtree_control", ENABLE_CONTROLLERS)?;
    let delegated = parse_enabled_controller_set(&read_control(raw_fd, "cgroup.subtree_control")?)
        .map_err(|error| {
            SupervisorError::new(format!("invalid parent cgroup.subtree_control: {error}"))
        })?;
    require_exact_fixed_controllers(&delegated, "delegated parent cgroup.subtree_control")?;
    require_same_identity(raw_fd, identity, "delegated parent cgroup")?;

    Ok(QualifiedParent {
        descriptor,
        identity,
        effective_cpus,
        effective_mems,
    })
}

fn require_controllers(
    controllers: &BTreeSet<String>,
    context: &str,
) -> Result<(), SupervisorError> {
    for required in REQUIRED_CONTROLLERS {
        if !controllers.contains(required) {
            return Err(SupervisorError::new(format!(
                "{context} is missing {required}"
            )));
        }
    }
    Ok(())
}

fn parse_enabled_controller_set(
    bytes: &[u8],
) -> Result<BTreeSet<String>, crate::ParseControlError> {
    // cgroup v2 emits zero bytes, not a blank LF-terminated line, when no
    // subtree controllers are enabled.
    if bytes.is_empty() {
        Ok(BTreeSet::new())
    } else {
        parse_controller_set(bytes)
    }
}

fn contains_only_fixed_controllers(controllers: &BTreeSet<String>) -> bool {
    controllers
        .iter()
        .all(|controller| REQUIRED_CONTROLLERS.contains(&controller.as_str()))
}

fn has_exact_fixed_controllers(controllers: &BTreeSet<String>) -> bool {
    controllers.len() == REQUIRED_CONTROLLERS.len() && contains_only_fixed_controllers(controllers)
}

fn require_only_fixed_controllers(
    controllers: &BTreeSet<String>,
    context: &str,
) -> Result<(), SupervisorError> {
    if contains_only_fixed_controllers(controllers) {
        Ok(())
    } else {
        Err(SupervisorError::new(format!(
            "{context} enables a controller outside the fixed cpuset/memory/pids set"
        )))
    }
}

fn require_exact_fixed_controllers(
    controllers: &BTreeSet<String>,
    context: &str,
) -> Result<(), SupervisorError> {
    if has_exact_fixed_controllers(controllers) {
        Ok(())
    } else {
        Err(SupervisorError::new(format!(
            "{context} is not exactly cpuset, memory, and pids"
        )))
    }
}

fn create_session(parent: QualifiedParent) -> Result<Session, SupervisorError> {
    for attempt in 1..=SESSION_COLLISION_ATTEMPTS {
        let mut nonce = [0_u8; 16];
        rustix::rand::getrandom(&mut nonce, rustix::rand::GetRandomFlags::empty())
            .map_err(|error| SupervisorError::new(format!("getrandom failed: {error}")))?;
        if !is_valid_session_nonce(&nonce) {
            if attempt == SESSION_COLLISION_ATTEMPTS {
                return Err(SupervisorError::new(
                    "getrandom returned an all-zero nonce through the retry bound",
                ));
            }
            continue;
        }
        let name = session_name(&nonce);
        if !is_valid_session_name(name.as_bytes()) {
            return Err(SupervisorError::new(
                "internal session-name generation violated its invariant",
            ));
        }
        let c_name = CString::new(name.as_bytes())
            .map_err(|_| SupervisorError::new("generated session name contains NUL"))?;
        // SAFETY: parent is a live directory FD and c_name is NUL terminated.
        let result =
            unsafe { libc::mkdirat(parent.descriptor.as_raw_fd(), c_name.as_ptr(), 0o700) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EEXIST) && attempt < SESSION_COLLISION_ATTEMPTS {
                continue;
            }
            return Err(SupervisorError::io(
                if error.raw_os_error() == Some(libc::EEXIST) {
                    "session-name collision retry bound exhausted"
                } else {
                    "cannot create direct session cgroup"
                },
                error,
            ));
        }

        let descriptor = match open_directory_at(parent.descriptor.as_raw_fd(), &c_name) {
            Ok(descriptor) => descriptor,
            Err(primary) => {
                // SAFETY: parent/name are the exact pair just passed to mkdirat.
                let cleanup_result = unsafe {
                    libc::unlinkat(
                        parent.descriptor.as_raw_fd(),
                        c_name.as_ptr(),
                        libc::AT_REMOVEDIR,
                    )
                };
                if cleanup_result < 0 {
                    return Err(SupervisorError::new(format!(
                        "{primary}; cleanup failure: cannot remove unopened session cgroup: {}",
                        io::Error::last_os_error()
                    )));
                }
                return Err(primary);
            }
        };
        let identity_result = stable_identity(descriptor.as_raw_fd(), "new session cgroup")
            .and_then(|identity| identity.require_directory("new session cgroup"))
            .and_then(|identity| {
                require_cgroup2(descriptor.as_raw_fd(), "new session cgroup")?;
                Ok(identity)
            });
        let identity = match identity_result {
            Ok(identity) => identity,
            Err(primary) => {
                drop(descriptor);
                // SAFETY: parent/name are still the exact direct entry created above.
                let cleanup_result = unsafe {
                    libc::unlinkat(
                        parent.descriptor.as_raw_fd(),
                        c_name.as_ptr(),
                        libc::AT_REMOVEDIR,
                    )
                };
                if cleanup_result < 0 {
                    return Err(SupervisorError::new(format!(
                        "{primary}; cleanup failure: cannot remove invalid new session cgroup: {}",
                        io::Error::last_os_error()
                    )));
                }
                return Err(primary);
            }
        };
        return Ok(Session {
            parent,
            descriptor,
            identity,
            name,
            nonce,
            cleanup_attempted: false,
        });
    }
    unreachable!("bounded session collision loop always returns")
}

fn configure_session(session: &Session) -> Result<(), SupervisorError> {
    let fd = session.descriptor.as_raw_fd();
    require_same_identity(fd, session.identity, "session cgroup")?;
    require_same_identity(
        session.parent.descriptor.as_raw_fd(),
        session.parent.identity,
        "delegated parent cgroup",
    )?;
    require_parent_entry_identity(session)?;
    require_domain_unpopulated(fd, "new session cgroup")?;
    require_empty_processes(fd, "new session cgroup")?;

    write_control(fd, "cpuset.cpus", session.parent.effective_cpus.as_bytes())?;
    write_control(fd, "cpuset.mems", session.parent.effective_mems.as_bytes())?;
    verify_id_set_equals(fd, "cpuset.cpus.effective", &session.parent.effective_cpus)?;
    verify_id_set_equals(fd, "cpuset.mems.effective", &session.parent.effective_mems)?;

    let controllers =
        parse_controller_set(&read_control(fd, "cgroup.controllers")?).map_err(|error| {
            SupervisorError::new(format!("invalid session cgroup.controllers: {error}"))
        })?;
    require_controllers(&controllers, "session cgroup.controllers")?;
    write_control(fd, "cgroup.subtree_control", ENABLE_CONTROLLERS)?;
    let delegated = parse_enabled_controller_set(&read_control(fd, "cgroup.subtree_control")?)
        .map_err(|error| {
            SupervisorError::new(format!("invalid session cgroup.subtree_control: {error}"))
        })?;
    require_exact_fixed_controllers(&delegated, "session cgroup.subtree_control")?;

    for (name, access) in [
        ("cgroup.controllers", Access::Read),
        ("cgroup.subtree_control", Access::ReadWrite),
        ("cgroup.type", Access::Read),
        ("cgroup.events", Access::Read),
        ("cgroup.procs", Access::ReadWrite),
        ("cgroup.kill", Access::Write),
        ("cpuset.cpus", Access::ReadWrite),
        ("cpuset.cpus.effective", Access::Read),
        ("cpuset.mems", Access::ReadWrite),
        ("cpuset.mems.effective", Access::Read),
        ("memory.max", Access::ReadWrite),
        ("memory.high", Access::ReadWrite),
        ("memory.swap.max", Access::ReadWrite),
        ("memory.peak", Access::Read),
        ("pids.max", Access::ReadWrite),
    ] {
        verify_control_access(fd, name, access)?;
    }

    require_domain_unpopulated(fd, "configured session cgroup")?;
    require_empty_processes(fd, "configured session cgroup")?;
    require_parent_entry_identity(session)?;
    require_same_identity(fd, session.identity, "configured session cgroup")
}

fn verify_id_set_equals(fd: RawFd, name: &str, expected_text: &str) -> Result<(), SupervisorError> {
    let observed = read_control(fd, name)?;
    let observed_ranges = parse_id_set(&observed)
        .map_err(|error| SupervisorError::new(format!("invalid {name}: {error}")))?;
    let mut expected_bytes = expected_text.as_bytes().to_vec();
    expected_bytes.push(b'\n');
    let expected_ranges = parse_id_set(&expected_bytes)
        .map_err(|error| SupervisorError::new(format!("invalid expected {name}: {error}")))?;
    if observed_ranges != expected_ranges {
        return Err(SupervisorError::new(format!(
            "{name} does not match the delegated parent's effective set"
        )));
    }
    Ok(())
}

fn require_domain_unpopulated(fd: RawFd, context: &str) -> Result<(), SupervisorError> {
    let cgroup_type = read_control(fd, "cgroup.type")?;
    if parse_single_line(&cgroup_type)
        .map_err(|error| SupervisorError::new(format!("invalid {context} cgroup.type: {error}")))?
        != "domain"
    {
        return Err(SupervisorError::new(format!(
            "{context} is not a domain cgroup"
        )));
    }
    let events = read_control(fd, "cgroup.events")?;
    if parse_populated(&events).map_err(|error| {
        SupervisorError::new(format!("invalid {context} cgroup.events: {error}"))
    })? {
        return Err(SupervisorError::new(format!("{context} is populated")));
    }
    Ok(())
}

fn require_empty_processes(fd: RawFd, context: &str) -> Result<(), SupervisorError> {
    if !read_control(fd, "cgroup.procs")?.is_empty() {
        return Err(SupervisorError::new(format!(
            "{context} contains processes despite reporting unpopulated"
        )));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Access {
    Read,
    Write,
    ReadWrite,
}

fn verify_control_access(fd: RawFd, name: &str, access: Access) -> Result<(), SupervisorError> {
    match access {
        Access::Read => drop(open_control(fd, name, libc::O_RDONLY)?),
        Access::Write => drop(open_control(fd, name, libc::O_WRONLY)?),
        Access::ReadWrite => {
            drop(open_control(fd, name, libc::O_RDONLY)?);
            drop(open_control(fd, name, libc::O_WRONLY)?);
        }
    }
    Ok(())
}

fn open_control(fd: RawFd, name: &str, access: libc::c_int) -> Result<OwnedFd, SupervisorError> {
    if name.is_empty() || name.contains('/') || name.as_bytes().contains(&0) {
        return Err(SupervisorError::new("unsafe internal cgroup control name"));
    }
    let c_name =
        CString::new(name).map_err(|_| SupervisorError::new("cgroup control name contains NUL"))?;
    // SAFETY: fd is a live cgroup directory and c_name is a valid C string.
    let opened = unsafe {
        libc::openat(
            fd,
            c_name.as_ptr(),
            access | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if opened < 0 {
        return Err(SupervisorError::io(
            &format!("cannot open cgroup control {name}"),
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: openat returned a new owned descriptor.
    let descriptor = unsafe { OwnedFd::from_raw_fd(opened) };
    stable_identity(opened, &format!("cgroup control {name}"))?
        .require_regular(&format!("cgroup control {name}"))?;
    require_cgroup2(opened, &format!("cgroup control {name}"))?;
    Ok(descriptor)
}

fn read_control(fd: RawFd, name: &str) -> Result<Vec<u8>, SupervisorError> {
    let descriptor = open_control(fd, name, libc::O_RDONLY)?;
    let mut bytes = Vec::with_capacity(256);
    loop {
        let mut buffer = [0_u8; 4096];
        // SAFETY: buffer points to writable storage and descriptor is live.
        let count = unsafe {
            libc::read(
                descriptor.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
            )
        };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(SupervisorError::io(
                &format!("cannot read cgroup control {name}"),
                error,
            ));
        }
        if count == 0 {
            break;
        }
        let count = count as usize;
        if bytes.len() + count > MAX_CONTROL_BYTES {
            return Err(SupervisorError::new(format!(
                "cgroup control {name} exceeds the bounded read limit"
            )));
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    Ok(bytes)
}

fn write_control(fd: RawFd, name: &str, bytes: &[u8]) -> Result<(), SupervisorError> {
    if bytes.is_empty() || bytes.len() > MAX_CONTROL_BYTES {
        return Err(SupervisorError::new(format!(
            "refusing invalid-sized write to cgroup control {name}"
        )));
    }
    let descriptor = open_control(fd, name, libc::O_WRONLY)?;
    loop {
        // SAFETY: bytes is a readable buffer and descriptor is live.
        let count =
            unsafe { libc::write(descriptor.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(SupervisorError::io(
                &format!("cannot write cgroup control {name}"),
                error,
            ));
        }
        if count as usize != bytes.len() {
            return Err(SupervisorError::new(format!(
                "short write to cgroup control {name}: {count} of {} bytes",
                bytes.len()
            )));
        }
        return Ok(());
    }
}

fn open_directory_at(parent_fd: RawFd, name: &CStr) -> Result<OwnedFd, SupervisorError> {
    // SAFETY: parent_fd is a live directory and name is NUL terminated.
    let opened = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    if opened < 0 {
        return Err(SupervisorError::io(
            "cannot open direct child cgroup without following links",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: openat returned a fresh owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(opened) })
}

fn stable_identity(fd: RawFd, context: &str) -> Result<Identity, SupervisorError> {
    let before = descriptor_identity(fd, context)?;
    let after = descriptor_identity(fd, context)?;
    if before != after {
        return Err(SupervisorError::new(format!(
            "{context} identity changed during inspection"
        )));
    }
    Ok(before)
}

fn descriptor_identity(fd: RawFd, context: &str) -> Result<Identity, SupervisorError> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: stat points to sufficient writable storage.
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } < 0 {
        return Err(SupervisorError::io(
            &format!("cannot stat {context}"),
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: fstat succeeded and initialized the structure.
    let stat = unsafe { stat.assume_init() };
    Ok(Identity {
        device: stat.st_dev,
        inode: stat.st_ino,
        mode: stat.st_mode,
    })
}

fn require_same_identity(
    fd: RawFd,
    expected: Identity,
    context: &str,
) -> Result<(), SupervisorError> {
    let observed = stable_identity(fd, context)?;
    if observed != expected {
        return Err(SupervisorError::new(format!(
            "{context} no longer has its retained identity"
        )));
    }
    Ok(())
}

fn require_cgroup2(fd: RawFd, context: &str) -> Result<(), SupervisorError> {
    let mut stat = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: stat points to sufficient writable storage.
    if unsafe { libc::fstatfs(fd, stat.as_mut_ptr()) } < 0 {
        return Err(SupervisorError::io(
            &format!("cannot inspect filesystem for {context}"),
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: fstatfs succeeded and initialized the structure.
    let stat = unsafe { stat.assume_init() };
    if stat.f_type != CGROUP2_SUPER_MAGIC {
        return Err(SupervisorError::new(format!(
            "{context} is not on cgroup v2"
        )));
    }
    Ok(())
}

fn require_parent_entry_identity(session: &Session) -> Result<(), SupervisorError> {
    if !is_valid_session_name(session.name.as_bytes()) {
        return Err(SupervisorError::new("retained session name is invalid"));
    }
    let name = CString::new(session.name.as_bytes())
        .map_err(|_| SupervisorError::new("retained session name contains NUL"))?;
    let reopened = open_directory_at(session.parent.descriptor.as_raw_fd(), &name)?;
    require_cgroup2(reopened.as_raw_fd(), "reopened direct session child")?;
    let reopened_identity = stable_identity(reopened.as_raw_fd(), "reopened direct session child")?
        .require_directory("reopened direct session child")?;
    if reopened_identity != session.identity {
        return Err(SupervisorError::new(
            "session name no longer identifies the retained direct child",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControlRead {
    Byte(u8),
    EmptyRecord,
    InvalidLength,
    Truncated,
    WouldBlock,
}

fn receive_control_packet(socket: RawFd) -> Result<ControlRead, io::Error> {
    // Two bytes distinguish an exact one-byte packet from a short, untruncated
    // multi-byte packet. Larger packets are rejected through MSG_TRUNC.
    let mut bytes = [0_u8; 2];
    let mut io_vector = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    // No ancillary buffer is supplied: ancillary data is discarded by the
    // kernel and reported via MSG_CTRUNC, avoiding leaked received descriptors.
    // SAFETY: zero is the required initial representation for an msghdr.
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut io_vector;
    message.msg_iovlen = 1;

    loop {
        // SAFETY: msghdr references the live bounded byte buffer for this call.
        let received = unsafe {
            libc::recvmsg(
                socket,
                &raw mut message,
                libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
            )
        };
        if received < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if error.kind() == io::ErrorKind::WouldBlock {
                return Ok(ControlRead::WouldBlock);
            }
            return Err(error);
        }
        if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
            return Ok(ControlRead::Truncated);
        }
        if received == 0 {
            // For SOCK_SEQPACKET this may be a live peer's zero-length record.
            // Only the poll state can promote it to a verified peer EOF.
            return Ok(ControlRead::EmptyRecord);
        }
        if received != 1 {
            return Ok(ControlRead::InvalidLength);
        }
        return Ok(ControlRead::Byte(bytes[0]));
    }
}

fn read_termination_signal(signals: &SignalMonitor) -> Result<bool, SupervisorError> {
    loop {
        let mut signal_info = MaybeUninit::<libc::signalfd_siginfo>::uninit();
        // SAFETY: signal_info points to a full writable signalfd_siginfo.
        let count = unsafe {
            libc::read(
                signals.descriptor.as_raw_fd(),
                signal_info.as_mut_ptr().cast(),
                size_of::<libc::signalfd_siginfo>(),
            )
        };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if error.kind() == io::ErrorKind::WouldBlock {
                return Ok(false);
            }
            return Err(SupervisorError::io(
                "cannot read supervisor termination signal",
                error,
            ));
        }
        if count as usize != size_of::<libc::signalfd_siginfo>() {
            return Err(SupervisorError::new(
                "signalfd produced an incomplete termination event",
            ));
        }
        // SAFETY: the full successful read initialized signal_info.
        let signal = unsafe { signal_info.assume_init() }.ssi_signo as libc::c_int;
        if !matches!(signal, libc::SIGTERM | libc::SIGINT | libc::SIGHUP) {
            return Err(SupervisorError::new(
                "signalfd produced an unexpected signal number",
            ));
        }
        return Ok(true);
    }
}

fn wait_for_ready(control: &OwnedFd, signals: &SignalMonitor) -> Result<(), SupervisorError> {
    loop {
        let mut poll_descriptors = [
            libc::pollfd {
                fd: control.as_raw_fd(),
                events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                revents: 0,
            },
            libc::pollfd {
                fd: signals.descriptor.as_raw_fd(),
                events: libc::POLLIN | libc::POLLERR,
                revents: 0,
            },
        ];
        // SAFETY: the array contains two initialized pollfd values.
        let ready = unsafe { libc::poll(poll_descriptors.as_mut_ptr(), 2, -1) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(SupervisorError::io("readiness poll failed", error));
        }
        if poll_descriptors[0].revents & libc::POLLNVAL != 0
            || poll_descriptors[1].revents & libc::POLLNVAL != 0
        {
            return Err(SupervisorError::new(
                "readiness poll reported an invalid retained descriptor",
            ));
        }
        if poll_descriptors[1].revents & libc::POLLIN != 0 && read_termination_signal(signals)? {
            return Err(SupervisorError::new(
                "termination signal received before the coordinator became ready",
            ));
        }
        if poll_descriptors[1].revents & libc::POLLERR != 0 {
            return Err(SupervisorError::new("signalfd reported POLLERR"));
        }
        if poll_descriptors[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            match receive_control_packet(control.as_raw_fd()).map_err(|error| {
                SupervisorError::io("cannot receive readiness control packet", error)
            })? {
                ControlRead::Byte(CONTROL_READY) => return Ok(()),
                ControlRead::Byte(_) => {
                    return Err(SupervisorError::new(
                        "coordinator sent an invalid readiness byte",
                    ));
                }
                ControlRead::EmptyRecord => {
                    return Err(SupervisorError::new(
                        if poll_descriptors[0].revents & libc::POLLHUP != 0 {
                            "control peer closed before the readiness handshake"
                        } else {
                            "coordinator sent an empty readiness record"
                        },
                    ));
                }
                ControlRead::InvalidLength => {
                    return Err(SupervisorError::new(
                        "readiness control packet is not exactly one byte",
                    ));
                }
                ControlRead::Truncated => {
                    return Err(SupervisorError::new(
                        "readiness control packet or ancillary data was truncated",
                    ));
                }
                ControlRead::WouldBlock => {
                    if poll_descriptors[0].revents & libc::POLLERR != 0 {
                        return Err(SupervisorError::new(
                            "control socket reported POLLERR before readiness",
                        ));
                    }
                }
            }
        }
    }
}

fn send_handoff(control: &OwnedFd, session: &Session) -> Result<(), HandoffSendError> {
    require_parent_entry_identity(session)?;
    require_same_identity(
        session.descriptor.as_raw_fd(),
        session.identity,
        "session cgroup before handoff",
    )?;
    require_domain_unpopulated(session.descriptor.as_raw_fd(), "session before handoff")?;
    require_empty_processes(session.descriptor.as_raw_fd(), "session before handoff")?;

    // getpid, getuid, and getgid have no failure return on Linux.  These are the
    // actual process credentials which the receiver must compare with the
    // kernel-generated SCM_CREDENTIALS message enabled by SO_PASSCRED.
    let pid = u32::try_from(unsafe { libc::getpid() })
        .map_err(|_| SupervisorError::new("actual sender PID is not a positive u32"))?;
    // SAFETY: these credential getters have no preconditions.
    let uid = unsafe { libc::getuid() };
    // SAFETY: these credential getters have no preconditions.
    let gid = unsafe { libc::getgid() };
    let packet = HandoffPacket {
        sender_pid: pid,
        sender_uid: uid,
        sender_gid: gid,
        root_device: session.identity.device,
        root_inode: session.identity.inode,
        session_nonce: session.nonce,
    }
    .encode();

    send_one_rights_packet(control.as_raw_fd(), &packet, session.descriptor.as_raw_fd())
}

fn send_one_rights_packet(
    socket: RawFd,
    packet: &[u8; crate::CONTROL_PACKET_BYTES],
    passed_fd: RawFd,
) -> Result<(), HandoffSendError> {
    let mut io_vector = libc::iovec {
        iov_base: packet.as_ptr().cast_mut().cast(),
        iov_len: packet.len(),
    };
    // An array of usize supplies cmsghdr's required native alignment.
    const ANCILLARY_WORDS: usize = 8;
    let mut ancillary = [0_usize; ANCILLARY_WORDS];
    // SAFETY: zero is the required initial representation for an msghdr.
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut io_vector;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.as_mut_ptr().cast();
    message.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as _) as usize };

    // SAFETY: message owns a sufficiently large aligned ancillary buffer.
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    if header.is_null() {
        return Err(
            SupervisorError::new("cannot construct the single SCM_RIGHTS control message").into(),
        );
    }
    // SAFETY: header points inside ancillary and has room for one RawFd.
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as _) as usize;
        ptr::write_unaligned(libc::CMSG_DATA(header).cast::<RawFd>(), passed_fd);
    }

    loop {
        // SAFETY: msghdr references live packet/ancillary buffers for this call.
        let sent = unsafe { libc::sendmsg(socket, &message, libc::MSG_NOSIGNAL) };
        if sent < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(SupervisorError::io("cannot send cgroup session handoff", error).into());
        }
        return validate_handoff_send_count(sent, packet.len());
    }
}

fn validate_handoff_send_count(sent: isize, expected: usize) -> Result<(), HandoffSendError> {
    if sent >= 0 && sent as usize == expected {
        Ok(())
    } else {
        Err(HandoffSendError {
            error: SupervisorError::new(format!(
                "session handoff returned an ambiguous short count of {sent} for {expected} packet bytes"
            )),
            // Any nonnegative sendmsg result may have installed SCM_RIGHTS at
            // the peer, even if a supposedly atomic SOCK_SEQPACKET operation
            // reports a kernel behavior outside its documented contract.
            transfer_possible: sent >= 0,
        })
    }
}

impl SignalMonitor {
    fn install() -> Result<Self, SupervisorError> {
        // SAFETY: sigset_t may be initialized through sigemptyset.
        let mut mask = unsafe { zeroed::<libc::sigset_t>() };
        // SAFETY: mask is a valid writable sigset_t.
        if unsafe { libc::sigemptyset(&mut mask) } < 0 {
            return Err(SupervisorError::io(
                "cannot initialize supervisor signal mask",
                io::Error::last_os_error(),
            ));
        }
        for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            // SAFETY: mask is initialized and signal values are valid.
            if unsafe { libc::sigaddset(&mut mask, signal) } < 0 {
                return Err(SupervisorError::io(
                    "cannot build supervisor signal mask",
                    io::Error::last_os_error(),
                ));
            }
        }
        // SAFETY: current thread has a valid pthread identity and mask is initialized.
        let mask_result = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &mask, ptr::null_mut()) };
        if mask_result != 0 {
            return Err(SupervisorError::io(
                "cannot block supervisor termination signals",
                io::Error::from_raw_os_error(mask_result),
            ));
        }
        // SAFETY: mask is initialized; flags request a fresh nonblocking descriptor.
        let descriptor =
            unsafe { libc::signalfd(-1, &mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) };
        if descriptor < 0 {
            return Err(SupervisorError::io(
                "cannot create signalfd",
                io::Error::last_os_error(),
            ));
        }
        // SAFETY: signalfd returned a fresh owned descriptor.
        Ok(Self {
            descriptor: unsafe { OwnedFd::from_raw_fd(descriptor) },
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RevokeOutcome {
    Sent,
    PeerUnavailable,
}

fn send_revoke(control: &OwnedFd) -> Result<RevokeOutcome, SupervisorError> {
    let byte = CONTROL_REVOKE;
    loop {
        // SAFETY: byte points to one readable byte and the socket is retained.
        let sent = unsafe {
            libc::send(
                control.as_raw_fd(),
                (&raw const byte).cast(),
                1,
                libc::MSG_NOSIGNAL,
            )
        };
        if sent < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if matches!(
                error.raw_os_error(),
                Some(libc::EPIPE | libc::ECONNRESET | libc::ENOTCONN | libc::ESHUTDOWN)
            ) {
                return Ok(RevokeOutcome::PeerUnavailable);
            }
            return Err(SupervisorError::io(
                "cannot send coordinator revocation",
                error,
            ));
        }
        if sent != 1 {
            return Err(SupervisorError::new(
                "coordinator revocation was not sent as exactly one byte",
            ));
        }
        return Ok(RevokeOutcome::Sent);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RevocationState {
    NotRequested,
    Sent,
    PeerUnavailable,
    Failed,
}

fn record_primary(primary: &mut Option<String>, message: impl Into<String>) {
    if primary.is_none() {
        *primary = Some(message.into());
    }
}

fn append_failure(primary: &mut Option<String>, message: impl Into<String>) {
    let message = message.into();
    match primary {
        Some(primary) => {
            primary.push_str("; ");
            primary.push_str(&message);
        }
        None => *primary = Some(message),
    }
}

fn request_revocation(
    control: &OwnedFd,
    state: &mut RevocationState,
    primary: &mut Option<String>,
) {
    if *state != RevocationState::NotRequested {
        return;
    }
    match send_revoke(control) {
        Ok(RevokeOutcome::Sent) => *state = RevocationState::Sent,
        Ok(RevokeOutcome::PeerUnavailable) => *state = RevocationState::PeerUnavailable,
        Err(error) => {
            *state = RevocationState::Failed;
            append_failure(primary, format!("revocation send failed: {error}"));
        }
    }
}

fn eof_verified(primary: Option<String>) -> BarrierOutcome {
    BarrierOutcome::EofVerified(match primary {
        Some(error) => Err(SupervisorError::new(error)),
        None => Ok(()),
    })
}

fn eof_unverified(mut primary: Option<String>, error: impl Display) -> BarrierOutcome {
    append_failure(
        &mut primary,
        format!("post-handoff EOF barrier failed: {error}"),
    );
    BarrierOutcome::EofUnverified(SupervisorError::new(
        primary.expect("the hard EOF-barrier failure was just recorded"),
    ))
}

fn wait_for_post_handoff_eof(
    control: &OwnedFd,
    signals: &SignalMonitor,
    initial_failure: Option<SupervisorError>,
) -> BarrierOutcome {
    let mut primary = initial_failure.map(|error| error.to_string());
    let mut revocation = RevocationState::NotRequested;
    let mut monitor_signals = true;
    let mut peer_write_half_closed = false;

    if primary.is_some() {
        request_revocation(control, &mut revocation, &mut primary);
        monitor_signals = false;
    }

    loop {
        let mut poll_descriptors = [
            libc::pollfd {
                fd: control.as_raw_fd(),
                events: if peer_write_half_closed {
                    libc::POLLERR
                } else {
                    libc::POLLIN | libc::POLLERR | libc::POLLRDHUP
                },
                revents: 0,
            },
            libc::pollfd {
                fd: if monitor_signals {
                    signals.descriptor.as_raw_fd()
                } else {
                    -1
                },
                events: libc::POLLIN | libc::POLLERR,
                revents: 0,
            },
        ];
        // SAFETY: the array contains two initialized pollfd values.
        let ready = unsafe { libc::poll(poll_descriptors.as_mut_ptr(), 2, -1) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            request_revocation(control, &mut revocation, &mut primary);
            return eof_unverified(primary, format!("control poll failed: {error}"));
        }
        if poll_descriptors[0].revents & libc::POLLNVAL != 0 {
            request_revocation(control, &mut revocation, &mut primary);
            return eof_unverified(
                primary,
                "control poll reported an invalid retained socket descriptor",
            );
        }
        if poll_descriptors[0].revents
            & (libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLRDHUP)
            != 0
        {
            let revents = poll_descriptors[0].revents;
            let full_close = revents & libc::POLLHUP != 0;
            let read_half_close = revents & libc::POLLRDHUP != 0;
            match receive_control_packet(control.as_raw_fd()) {
                Ok(ControlRead::Byte(_)) => {
                    record_primary(
                        &mut primary,
                        "control peer sent unexpected data after the one-way handoff",
                    );
                    request_revocation(control, &mut revocation, &mut primary);
                    monitor_signals = false;
                }
                Ok(ControlRead::EmptyRecord) => {
                    if full_close {
                        return eof_verified(primary);
                    }
                    if read_half_close {
                        record_primary(
                            &mut primary,
                            "control peer half-closed its write side without closing the endpoint",
                        );
                        request_revocation(control, &mut revocation, &mut primary);
                        monitor_signals = false;
                        peer_write_half_closed = true;
                    } else {
                        record_primary(
                            &mut primary,
                            "control peer sent a zero-length SOCK_SEQPACKET record after handoff",
                        );
                        request_revocation(control, &mut revocation, &mut primary);
                        monitor_signals = false;
                    }
                }
                Ok(ControlRead::InvalidLength) => {
                    record_primary(
                        &mut primary,
                        "control peer sent a post-handoff record that was not exactly one byte",
                    );
                    request_revocation(control, &mut revocation, &mut primary);
                    monitor_signals = false;
                }
                Ok(ControlRead::Truncated) => {
                    record_primary(
                        &mut primary,
                        "control peer sent truncated post-handoff data or ancillary rights",
                    );
                    request_revocation(control, &mut revocation, &mut primary);
                    monitor_signals = false;
                }
                Ok(ControlRead::WouldBlock) => {
                    if full_close {
                        return eof_verified(primary);
                    }
                    if read_half_close {
                        record_primary(
                            &mut primary,
                            "control peer half-closed its write side without closing the endpoint",
                        );
                        request_revocation(control, &mut revocation, &mut primary);
                        monitor_signals = false;
                        peer_write_half_closed = true;
                    } else if revents & libc::POLLERR != 0 {
                        request_revocation(control, &mut revocation, &mut primary);
                        return eof_unverified(
                            primary,
                            "control socket reported POLLERR without readable closure state",
                        );
                    }
                }
                Err(error) => {
                    if full_close
                        || error.raw_os_error() == Some(libc::ECONNRESET)
                            && revocation == RevocationState::Sent
                    {
                        return eof_verified(primary);
                    }
                    request_revocation(control, &mut revocation, &mut primary);
                    return eof_unverified(
                        primary,
                        format!("cannot receive post-handoff control state: {error}"),
                    );
                }
            }
        }
        if monitor_signals && poll_descriptors[1].revents & libc::POLLNVAL != 0 {
            record_primary(
                &mut primary,
                "signal poll reported an invalid retained signalfd descriptor",
            );
            request_revocation(control, &mut revocation, &mut primary);
            monitor_signals = false;
        }
        if monitor_signals && poll_descriptors[1].revents & libc::POLLIN != 0 {
            match read_termination_signal(signals) {
                Ok(true) => {
                    request_revocation(control, &mut revocation, &mut primary);
                    monitor_signals = false;
                }
                Ok(false) => {}
                Err(error) => {
                    record_primary(
                        &mut primary,
                        format!("cannot consume termination signal: {error}"),
                    );
                    request_revocation(control, &mut revocation, &mut primary);
                    monitor_signals = false;
                }
            }
        }
        if monitor_signals && poll_descriptors[1].revents & libc::POLLERR != 0 {
            record_primary(&mut primary, "signalfd reported POLLERR");
            request_revocation(control, &mut revocation, &mut primary);
            monitor_signals = false;
        }
    }
}

impl Session {
    fn suppress_cleanup_for_recovery(&mut self) {
        self.cleanup_attempted = true;
    }

    fn cleanup(&mut self) -> CleanupFailures {
        self.cleanup_attempted = true;
        let mut failures = CleanupFailures::default();
        failures.record(
            "write cgroup.kill at session root",
            write_control(self.descriptor.as_raw_fd(), "cgroup.kill", b"1"),
        );
        failures.record(
            "wait for session cgroup to become unpopulated",
            wait_until_unpopulated(self.descriptor.as_raw_fd()),
        );

        match list_direct_children(self.descriptor.as_raw_fd()) {
            Ok(entries) => {
                for entry in entries {
                    if entry.starts_with(LEAF_PREFIX.as_bytes()) {
                        if !is_valid_leaf_name(&entry) {
                            failures.push(format!(
                                "refused malformed fixed-namespace direct child {:?}",
                                String::from_utf8_lossy(&entry)
                            ));
                            continue;
                        }
                        let display_name = String::from_utf8_lossy(&entry).into_owned();
                        failures.record(
                            &format!("remove validated direct leaf {display_name}"),
                            remove_validated_leaf(self.descriptor.as_raw_fd(), &entry),
                        );
                    }
                }
            }
            Err(error) => failures.record("enumerate direct session children", Err::<(), _>(error)),
        }

        let session_identity_valid = match require_parent_entry_identity(self) {
            Ok(()) => true,
            Err(error) => {
                failures.record(
                    "validate session identity before removal",
                    Err::<(), _>(error),
                );
                false
            }
        };
        let parent_identity_valid = match require_same_identity(
            self.parent.descriptor.as_raw_fd(),
            self.parent.identity,
            "delegated parent cgroup during cleanup",
        ) {
            Ok(()) => true,
            Err(error) => {
                failures.record(
                    "validate delegated parent identity before removal",
                    Err::<(), _>(error),
                );
                false
            }
        };

        if session_identity_valid
            && parent_identity_valid
            && is_valid_session_name(self.name.as_bytes())
        {
            match CString::new(self.name.as_bytes()) {
                Ok(name) => {
                    // SAFETY: parent is retained, name is validated/direct, and no
                    // path separators are admitted by the session-name grammar.
                    let result = unsafe {
                        libc::unlinkat(
                            self.parent.descriptor.as_raw_fd(),
                            name.as_ptr(),
                            libc::AT_REMOVEDIR,
                        )
                    };
                    if result < 0 {
                        failures.push(format!(
                            "remove session root via retained parent FD: {}",
                            io::Error::last_os_error()
                        ));
                    }
                }
                Err(error) => failures.push(format!("session name became invalid: {error}")),
            }
        } else if session_identity_valid && parent_identity_valid {
            failures.push("refused to remove session root with an invalid name".to_owned());
        } else {
            failures.push(
                "refused to remove session root after direct-child identity validation failed"
                    .to_owned(),
            );
        }
        failures
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if self.cleanup_attempted {
            return;
        }
        let failures = self.cleanup();
        for failure in failures.into_vec() {
            eprintln!("mosaic-binding-supervisor: emergency cleanup failure: {failure}");
        }
    }
}

fn wait_until_unpopulated(fd: RawFd) -> Result<(), SupervisorError> {
    let start = monotonic_now()?;
    loop {
        let events = read_control(fd, "cgroup.events")?;
        let populated = parse_populated(&events)
            .map_err(|error| SupervisorError::new(format!("invalid cgroup.events: {error}")))?;
        if !populated {
            return Ok(());
        }
        let now = monotonic_now()?;
        if now.checked_sub(start).unwrap_or_default() >= CLEANUP_TIMEOUT {
            return Err(SupervisorError::new(
                "bounded cleanup timeout expired while session remained populated",
            ));
        }
        sleep_no_signal_handler(CLEANUP_POLL_INTERVAL)?;
    }
}

fn monotonic_now() -> Result<Duration, SupervisorError> {
    let mut value = MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: value points to sufficient writable storage.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, value.as_mut_ptr()) } < 0 {
        return Err(SupervisorError::io(
            "cannot read cleanup monotonic clock",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: clock_gettime succeeded and initialized value.
    let value = unsafe { value.assume_init() };
    let seconds = u64::try_from(value.tv_sec)
        .map_err(|_| SupervisorError::new("monotonic clock returned negative seconds"))?;
    let nanoseconds = u32::try_from(value.tv_nsec)
        .map_err(|_| SupervisorError::new("monotonic clock returned invalid nanoseconds"))?;
    if nanoseconds >= 1_000_000_000 {
        return Err(SupervisorError::new(
            "monotonic clock returned out-of-range nanoseconds",
        ));
    }
    Ok(Duration::new(seconds, nanoseconds))
}

fn sleep_no_signal_handler(duration: Duration) -> Result<(), SupervisorError> {
    let request = libc::timespec {
        tv_sec: duration.as_secs() as libc::time_t,
        tv_nsec: libc::c_long::from(duration.subsec_nanos()),
    };
    let mut remaining = MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: request is initialized and remaining is writable.
    let result = unsafe { libc::nanosleep(&request, remaining.as_mut_ptr()) };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return Ok(());
        }
        return Err(SupervisorError::io("cleanup polling sleep failed", error));
    }
    Ok(())
}

fn list_direct_children(fd: RawFd) -> Result<Vec<Vec<u8>>, SupervisorError> {
    // SAFETY: fcntl duplicates a live descriptor and gives independent ownership.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 5) };
    if duplicate < 0 {
        return Err(SupervisorError::io(
            "cannot duplicate session FD for direct-child enumeration",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: duplicate is a fresh descriptor; fdopendir consumes it on success.
    let directory = unsafe { libc::fdopendir(duplicate) };
    if directory.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: fdopendir failed and therefore did not consume duplicate.
        unsafe { libc::close(duplicate) };
        return Err(SupervisorError::io(
            "cannot enumerate direct session children",
            error,
        ));
    }

    let mut entries = Vec::new();
    let read_result = loop {
        set_errno_zero();
        // SAFETY: directory is a live DIR pointer and readdir owns its buffer.
        let entry = unsafe { libc::readdir(directory) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(0) {
                break Ok(());
            }
            break Err(SupervisorError::io(
                "cannot read a direct session directory entry",
                error,
            ));
        }
        // SAFETY: d_name is NUL terminated for a successful readdir result.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            entries.push(name.to_vec());
        }
    };
    // SAFETY: directory is live and closedir consumes it and the duplicated FD.
    let close_result = unsafe { libc::closedir(directory) };
    if let Err(primary) = read_result {
        if close_result < 0 {
            return Err(SupervisorError::new(format!(
                "{primary}; directory close also failed: {}",
                io::Error::last_os_error()
            )));
        }
        return Err(primary);
    }
    if close_result < 0 {
        return Err(SupervisorError::io(
            "cannot close direct-child enumeration",
            io::Error::last_os_error(),
        ));
    }
    Ok(entries)
}

fn set_errno_zero() {
    // SAFETY: __errno_location returns this thread's valid errno pointer on glibc.
    unsafe { *libc::__errno_location() = 0 };
}

fn remove_validated_leaf(parent_fd: RawFd, name: &[u8]) -> Result<(), SupervisorError> {
    if !is_valid_leaf_name(name) {
        return Err(SupervisorError::new(
            "refusing to remove a child outside the fixed leaf namespace",
        ));
    }
    let name =
        CString::new(name).map_err(|_| SupervisorError::new("validated leaf name contains NUL"))?;
    let leaf = open_directory_at(parent_fd, &name)?;
    let identity = stable_identity(leaf.as_raw_fd(), "direct session leaf")?
        .require_directory("direct session leaf")?;
    require_cgroup2(leaf.as_raw_fd(), "direct session leaf")?;
    require_domain_unpopulated(leaf.as_raw_fd(), "direct session leaf")?;
    let reopened = open_directory_at(parent_fd, &name)?;
    let reopened_identity = stable_identity(reopened.as_raw_fd(), "reopened direct session leaf")?
        .require_directory("reopened direct session leaf")?;
    if reopened_identity != identity {
        return Err(SupervisorError::new(
            "direct session leaf identity changed before removal",
        ));
    }
    drop(reopened);
    drop(leaf);
    // SAFETY: name is validated as one direct namespace component.
    if unsafe { libc::unlinkat(parent_fd, name.as_ptr(), libc::AT_REMOVEDIR) } < 0 {
        return Err(SupervisorError::io(
            "cannot remove validated direct session leaf",
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socket_pair() -> (OwnedFd, OwnedFd) {
        let mut sockets = [-1; 2];
        // SAFETY: sockets points to two writable descriptor slots.
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    sockets.as_mut_ptr(),
                )
            },
            0
        );
        // SAFETY: socketpair returned two new, distinct descriptors.
        let first = unsafe { OwnedFd::from_raw_fd(sockets[0]) };
        // SAFETY: socketpair returned two new, distinct descriptors.
        let second = unsafe { OwnedFd::from_raw_fd(sockets[1]) };
        (first, second)
    }

    fn send_test_packet(socket: &OwnedFd, bytes: &[u8]) {
        // SAFETY: bytes is readable for its supplied length and socket is live.
        assert_eq!(
            unsafe {
                libc::send(
                    socket.as_raw_fd(),
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    libc::MSG_NOSIGNAL,
                )
            },
            bytes.len() as isize
        );
    }

    fn send_test_packet_with_right(socket: &OwnedFd, byte: u8, passed_fd: RawFd) {
        let mut io_vector = libc::iovec {
            iov_base: (&raw const byte).cast_mut().cast(),
            iov_len: 1,
        };
        let mut ancillary = [0_usize; 8];
        // SAFETY: zero is the required initial representation for an msghdr.
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = &raw mut io_vector;
        message.msg_iovlen = 1;
        message.msg_control = ancillary.as_mut_ptr().cast();
        message.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as _) as usize };
        // SAFETY: message owns a sufficiently large aligned ancillary buffer.
        let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        assert!(!header.is_null());
        // SAFETY: header points inside ancillary and has room for one RawFd.
        unsafe {
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as _) as usize;
            ptr::write_unaligned(libc::CMSG_DATA(header).cast::<RawFd>(), passed_fd);
        }
        // SAFETY: message references live byte and ancillary buffers.
        assert_eq!(
            unsafe { libc::sendmsg(socket.as_raw_fd(), &message, libc::MSG_NOSIGNAL) },
            1
        );
    }

    fn inert_signal_monitor() -> SignalMonitor {
        // SAFETY: eventfd has no pointer arguments and returns a new descriptor.
        let descriptor = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        assert!(descriptor >= 0);
        // SAFETY: eventfd returned a new owned descriptor.
        SignalMonitor {
            descriptor: unsafe { OwnedFd::from_raw_fd(descriptor) },
        }
    }

    fn receive_revoke(socket: &OwnedFd) {
        let mut byte = 0_u8;
        // SAFETY: byte is writable and socket is a live endpoint.
        assert_eq!(
            unsafe { libc::recv(socket.as_raw_fd(), (&raw mut byte).cast(), 1, 0) },
            1
        );
        assert_eq!(byte, CONTROL_REVOKE);
    }

    fn expect_verified_failure(outcome: BarrierOutcome, expected: &str) {
        match outcome {
            BarrierOutcome::EofVerified(Err(error)) => {
                assert!(error.to_string().contains(expected), "{error}");
            }
            BarrierOutcome::EofVerified(Ok(())) => {
                panic!("EOF was verified without the expected protocol failure")
            }
            BarrierOutcome::EofUnverified(error) => {
                panic!("peer closure was not verified: {error}")
            }
        }
    }

    #[test]
    fn enabled_controller_checks_distinguish_subset_exact_and_extra() {
        let empty = parse_enabled_controller_set(b"").unwrap();
        assert!(contains_only_fixed_controllers(&empty));
        assert!(!has_exact_fixed_controllers(&empty));
        assert!(parse_enabled_controller_set(b"\n").is_err());

        let subset = BTreeSet::from(["memory".to_owned(), "pids".to_owned()]);
        assert!(contains_only_fixed_controllers(&subset));
        assert!(!has_exact_fixed_controllers(&subset));

        let exact = BTreeSet::from(["cpuset".to_owned(), "memory".to_owned(), "pids".to_owned()]);
        assert!(contains_only_fixed_controllers(&exact));
        assert!(has_exact_fixed_controllers(&exact));

        let mut extra = exact;
        assert!(extra.insert("io".to_owned()));
        assert!(!contains_only_fixed_controllers(&extra));
        assert!(!has_exact_fixed_controllers(&extra));
        assert!(require_only_fixed_controllers(&extra, "test").is_err());
        assert!(require_exact_fixed_controllers(&extra, "test").is_err());
    }

    #[test]
    fn readiness_packet_is_exact_and_truncation_safe() {
        let (sender, receiver) = socket_pair();
        send_test_packet(&sender, &[CONTROL_READY]);
        assert_eq!(
            receive_control_packet(receiver.as_raw_fd()).unwrap(),
            ControlRead::Byte(CONTROL_READY)
        );

        send_test_packet(&sender, &[CONTROL_READY, CONTROL_READY]);
        assert_eq!(
            receive_control_packet(receiver.as_raw_fd()).unwrap(),
            ControlRead::InvalidLength
        );

        send_test_packet(&sender, &[CONTROL_READY; 3]);
        assert_eq!(
            receive_control_packet(receiver.as_raw_fd()).unwrap(),
            ControlRead::Truncated
        );

        // SAFETY: eventfd has no pointer arguments and returns a new descriptor.
        let passed_raw = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
        assert!(passed_raw >= 0);
        // SAFETY: eventfd returned a new owned descriptor.
        let passed = unsafe { OwnedFd::from_raw_fd(passed_raw) };
        send_test_packet_with_right(&sender, CONTROL_READY, passed.as_raw_fd());
        assert_eq!(
            receive_control_packet(receiver.as_raw_fd()).unwrap(),
            ControlRead::Truncated
        );
    }

    #[test]
    fn revocation_is_one_byte_and_cleanup_waits_for_eof() {
        let (supervisor, coordinator) = socket_pair();
        std::thread::scope(|scope| {
            let signals = inert_signal_monitor();
            let (result_sender, result_receiver) = std::sync::mpsc::channel();
            scope.spawn(move || {
                result_sender
                    .send(wait_for_post_handoff_eof(
                        &supervisor,
                        &signals,
                        Some(SupervisorError::new("test shutdown request")),
                    ))
                    .unwrap();
            });
            receive_revoke(&coordinator);
            assert!(matches!(
                result_receiver.recv_timeout(Duration::from_millis(50)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ));
            drop(coordinator);
            let outcome = result_receiver
                .recv_timeout(Duration::from_secs(2))
                .unwrap();
            expect_verified_failure(outcome, "test shutdown request");
        });

        let (supervisor, coordinator) = socket_pair();
        drop(coordinator);
        let signals = inert_signal_monitor();
        expect_verified_failure(
            wait_for_post_handoff_eof(
                &supervisor,
                &signals,
                Some(SupervisorError::new("closed-peer shutdown request")),
            ),
            "closed-peer shutdown request",
        );
    }

    #[test]
    fn post_handoff_data_waits_for_eof_before_returning_failure() {
        let (coordinator, supervisor) = socket_pair();
        std::thread::scope(|scope| {
            let signals = inert_signal_monitor();
            let (result_sender, result_receiver) = std::sync::mpsc::channel();
            scope.spawn(move || {
                result_sender
                    .send(wait_for_post_handoff_eof(&supervisor, &signals, None))
                    .unwrap();
            });
            send_test_packet(&coordinator, b"?");
            receive_revoke(&coordinator);
            assert!(matches!(
                result_receiver.recv_timeout(Duration::from_millis(50)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ));
            drop(coordinator);
            let outcome = result_receiver
                .recv_timeout(Duration::from_secs(2))
                .unwrap();
            expect_verified_failure(outcome, "unexpected data");
        });
    }

    #[test]
    fn zero_length_record_from_live_peer_does_not_pass_eof_barrier() {
        let (coordinator, supervisor) = socket_pair();
        std::thread::scope(|scope| {
            let signals = inert_signal_monitor();
            let (result_sender, result_receiver) = std::sync::mpsc::channel();
            scope.spawn(move || {
                result_sender
                    .send(wait_for_post_handoff_eof(&supervisor, &signals, None))
                    .unwrap();
            });
            send_test_packet(&coordinator, b"");
            receive_revoke(&coordinator);
            assert!(matches!(
                result_receiver.recv_timeout(Duration::from_millis(50)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ));
            drop(coordinator);
            let outcome = result_receiver
                .recv_timeout(Duration::from_secs(2))
                .unwrap();
            expect_verified_failure(outcome, "zero-length SOCK_SEQPACKET record");
        });
    }

    #[test]
    fn peer_half_close_does_not_pass_eof_barrier() {
        let (coordinator, supervisor) = socket_pair();
        std::thread::scope(|scope| {
            let signals = inert_signal_monitor();
            let (result_sender, result_receiver) = std::sync::mpsc::channel();
            scope.spawn(move || {
                result_sender
                    .send(wait_for_post_handoff_eof(&supervisor, &signals, None))
                    .unwrap();
            });
            // SAFETY: coordinator is a live connected socket endpoint.
            assert_eq!(
                unsafe { libc::shutdown(coordinator.as_raw_fd(), libc::SHUT_WR) },
                0
            );
            receive_revoke(&coordinator);
            assert!(matches!(
                result_receiver.recv_timeout(Duration::from_millis(50)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ));
            drop(coordinator);
            let outcome = result_receiver
                .recv_timeout(Duration::from_secs(2))
                .unwrap();
            expect_verified_failure(outcome, "half-closed");
        });
    }

    #[test]
    fn coordinator_can_close_with_revoke_unread() {
        let (coordinator, supervisor) = socket_pair();
        std::thread::scope(|scope| {
            let signals = inert_signal_monitor();
            let (result_sender, result_receiver) = std::sync::mpsc::channel();
            scope.spawn(move || {
                result_sender
                    .send(wait_for_post_handoff_eof(
                        &supervisor,
                        &signals,
                        Some(SupervisorError::new("test shutdown request")),
                    ))
                    .unwrap();
            });
            let mut descriptor = libc::pollfd {
                fd: coordinator.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: descriptor points to one initialized pollfd value.
            assert_eq!(unsafe { libc::poll(&raw mut descriptor, 1, 2_000) }, 1);
            assert_ne!(descriptor.revents & libc::POLLIN, 0);
            drop(coordinator);
            let outcome = result_receiver
                .recv_timeout(Duration::from_secs(2))
                .unwrap();
            expect_verified_failure(outcome, "test shutdown request");
        });
    }

    #[test]
    fn short_handoff_result_is_treated_as_possible_authority_transfer() {
        assert!(validate_handoff_send_count(88, 88).is_ok());
        let short = validate_handoff_send_count(87, 88).unwrap_err();
        assert!(short.transfer_possible);
        assert!(short.error.to_string().contains("ambiguous short count"));

        let syscall_failure = validate_handoff_send_count(-1, 88).unwrap_err();
        assert!(!syscall_failure.transfer_possible);
    }

    #[test]
    fn handoff_sends_exact_packet_one_right_and_kernel_credentials() {
        let (sender, receiver) = socket_pair();

        let enabled: libc::c_int = 1;
        // SAFETY: enabled points to an initialized c_int of the supplied size.
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    receiver.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PASSCRED,
                    (&raw const enabled).cast(),
                    size_of::<libc::c_int>() as libc::socklen_t,
                )
            },
            0
        );
        // SAFETY: eventfd has no pointer arguments and returns a new descriptor.
        let passed_raw = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
        assert!(passed_raw >= 0);
        // SAFETY: eventfd returned a new owned descriptor.
        let passed = unsafe { OwnedFd::from_raw_fd(passed_raw) };

        let expected = HandoffPacket {
            sender_pid: u32::try_from(unsafe { libc::getpid() }).unwrap(),
            sender_uid: unsafe { libc::getuid() },
            sender_gid: unsafe { libc::getgid() },
            root_device: 7,
            root_inode: 11,
            session_nonce: [0x5a; 16],
        }
        .encode();
        send_one_rights_packet(sender.as_raw_fd(), &expected, passed.as_raw_fd()).unwrap();

        let mut packet = [0_u8; crate::CONTROL_PACKET_BYTES];
        let mut io_vector = libc::iovec {
            iov_base: packet.as_mut_ptr().cast(),
            iov_len: packet.len(),
        };
        let mut ancillary = [0_usize; 16];
        // SAFETY: zero initializes all optional msghdr pointers and lengths.
        let mut message = unsafe { zeroed::<libc::msghdr>() };
        message.msg_iov = &raw mut io_vector;
        message.msg_iovlen = 1;
        message.msg_control = ancillary.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&ancillary);
        // SAFETY: message references writable packet and ancillary buffers.
        let received = unsafe { libc::recvmsg(receiver.as_raw_fd(), &raw mut message, 0) };
        assert_eq!(received as usize, expected.len());
        assert_eq!(packet, expected);
        assert_eq!(message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC), 0);

        let mut rights = Vec::new();
        let mut credentials = Vec::new();
        // SAFETY: message was initialized by successful recvmsg and its ancillary
        // buffer remains alive for the complete traversal.
        let mut header = unsafe { libc::CMSG_FIRSTHDR(&raw const message) };
        while !header.is_null() {
            // SAFETY: header is a current cmsg pointer produced by libc traversal.
            let current = unsafe { &*header };
            assert_eq!(current.cmsg_level, libc::SOL_SOCKET);
            match current.cmsg_type {
                libc::SCM_RIGHTS => {
                    assert_eq!(current.cmsg_len, unsafe {
                        libc::CMSG_LEN(size_of::<RawFd>() as _) as usize
                    });
                    // SAFETY: exact cmsg length above guarantees one RawFd payload.
                    rights.push(unsafe {
                        ptr::read_unaligned(libc::CMSG_DATA(header).cast::<RawFd>())
                    });
                }
                libc::SCM_CREDENTIALS => {
                    assert_eq!(current.cmsg_len, unsafe {
                        libc::CMSG_LEN(size_of::<libc::ucred>() as _) as usize
                    });
                    // SAFETY: exact cmsg length above guarantees one ucred payload.
                    credentials.push(unsafe {
                        ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::ucred>())
                    });
                }
                unexpected => panic!("unexpected ancillary message type {unexpected}"),
            }
            // SAFETY: libc validates the next header against msg_controllen.
            header = unsafe { libc::CMSG_NXTHDR(&raw const message, header) };
        }
        assert_eq!(rights.len(), 1);
        assert_eq!(credentials.len(), 1);
        assert_eq!(credentials[0].pid, unsafe { libc::getpid() });
        assert_eq!(credentials[0].uid, unsafe { libc::getuid() });
        assert_eq!(credentials[0].gid, unsafe { libc::getgid() });
        // SAFETY: SCM_RIGHTS installed one new receiver-owned descriptor.
        drop(unsafe { OwnedFd::from_raw_fd(rights[0]) });
    }

    #[test]
    #[ignore = "mutates an explicitly delegated real cgroup; opt in with environment and --ignored"]
    fn real_delegated_parent_setup_and_cleanup() {
        if std::env::var_os("MOSAIC_BINDING_SUPERVISOR_INTEGRATION").as_deref()
            != Some(std::ffi::OsStr::new("1"))
        {
            return;
        }
        let fd: RawFd = std::env::var("MOSAIC_BINDING_SUPERVISOR_PARENT_FD")
            .expect("set inherited delegated parent FD number")
            .parse()
            .expect("parent FD number must be an integer");
        // SAFETY: explicit integration setup promises this inherited FD is live.
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 5) };
        assert!(duplicate >= 0, "cannot duplicate integration cgroup FD");
        // SAFETY: fcntl returned a fresh descriptor.
        let owned = unsafe { OwnedFd::from_raw_fd(duplicate) };
        let parent = qualify_parent(owned).expect("real delegated parent qualification failed");
        let mut session = create_session(parent).expect("real session creation failed");
        let setup = configure_session(&session);
        let cleanup = session.cleanup();
        finish_lifecycle(setup, cleanup).expect("real session lifecycle failed");
    }
}
