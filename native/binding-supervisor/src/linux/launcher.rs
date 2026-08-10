//! Non-binding clone3 ABI probe substrate.
//!
//! This module deliberately stops before the accepted executable self-test:
//! it never execs or launches a payload, and the caller owns the already-open
//! leaf's creation and removal. A successful result proves only the exact
//! clone3 ABI, namespace PID 1, pidfd ownership, and initial leaf placement.

use super::cgroup::{
    require_cgroup2, require_domain_unpopulated, require_empty_processes, require_only_process,
    require_same_identity, stable_identity, wait_until_unpopulated,
};
use super::*;

const CLONE_INTO_CGROUP_FLAG: u64 = 1_u64 << 33;
const REQUIRED_CLONE_FLAGS: u64 =
    CLONE_INTO_CGROUP_FLAG | libc::CLONE_NEWPID as u64 | libc::CLONE_PIDFD as u64;
const CHILD_CONTROL_FD: RawFd = 4;
const READY_MAGIC: [u8; 8] = *b"MSCLONE1";
const READY_RECORD_BYTES: usize = 12;
const RELEASE_BYTE: u8 = b'G';
const READY_TIMEOUT: Duration = Duration::from_secs(3);
const EXIT_TIMEOUT: Duration = Duration::from_secs(3);
const FORCED_EXIT_TIMEOUT: Duration = Duration::from_secs(3);
const CHILD_DESCRIPTOR_FAILURE: libc::c_int = 120;
const CHILD_READY_FAILURE: libc::c_int = 121;
const CHILD_RELEASE_FAILURE: libc::c_int = 122;
const CHILD_WRONG_PID: libc::c_int = 123;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Clone3FailureClass {
    UnsupportedKernel,
    MisprovisionedHost,
    InvalidTarget,
    Unexpected,
}

impl Clone3FailureClass {
    const fn description(self) -> &'static str {
        match self {
            Self::UnsupportedKernel => "unsupported kernel or clone3 flag combination",
            Self::MisprovisionedHost => "misprovisioned namespace or cgroup permissions",
            Self::InvalidTarget => "invalid cgroup-v2 target",
            Self::Unexpected => "unexpected clone3 failure",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReadyRecord {
    inner_pid: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChildExit {
    Exited(libc::c_int),
    Signaled(libc::c_int),
    Other {
        code: libc::c_int,
        status: libc::c_int,
    },
}

struct LaunchedChild {
    host_pid: libc::pid_t,
    pidfd: OwnedFd,
    control: OwnedFd,
    reaped: bool,
}

pub(super) fn run(leaf: OwnedFd) -> Result<(), SupervisorError> {
    let leaf_fd = leaf.as_raw_fd();
    let identity = stable_identity(leaf_fd, "clone3 ABI probe cgroup leaf")?
        .require_directory("clone3 ABI probe cgroup leaf")?;
    require_cgroup2(leaf_fd, "clone3 ABI probe cgroup leaf")?;
    require_domain_unpopulated(leaf_fd, "clone3 ABI probe cgroup leaf")?;
    require_empty_processes(leaf_fd, "clone3 ABI probe cgroup leaf")?;

    let (parent_control, child_control) = socket_pair()?;
    let mut pidfd_raw = -1;
    let arguments = build_clone_args(leaf_fd, &mut pidfd_raw);
    // SAFETY: arguments is the exact fully initialized clone_args layout tested
    // below. The child path performs only fixed-descriptor, read/write, getpid,
    // and _exit operations and never unwinds through the cloned Rust stack.
    let cloned = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            (&raw const arguments).cast::<libc::c_void>(),
            size_of::<libc::clone_args>(),
        )
    };
    if cloned < 0 {
        return Err(classified_clone3_error(
            io::Error::last_os_error(),
            leaf_fd,
            identity,
        ));
    }
    if cloned == 0 {
        child_after_clone(
            parent_control.as_raw_fd(),
            child_control.as_raw_fd(),
            leaf_fd,
        );
    }

    drop(child_control);
    let host_pid = cloned as libc::pid_t;
    // SAFETY: successful clone3 with CLONE_PIDFD initializes pidfd_raw with one
    // fresh parent-owned pidfd. No fallback pidfd acquisition is permitted.
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd_raw) };
    let mut child = LaunchedChild {
        host_pid,
        pidfd,
        control: parent_control,
        reaped: false,
    };

    let primary = verify_release_and_reap(&mut child, leaf_fd, identity);
    let mut cleanup = CleanupFailures::default();
    if !child.reaped {
        cleanup.record(
            "force and reap clone3 ABI probe child through pidfd",
            child.force_and_reap(),
        );
    }
    cleanup.record(
        "wait for clone3 ABI probe leaf to become unpopulated",
        wait_until_unpopulated(leaf_fd),
    );
    cleanup.record(
        "verify clone3 ABI probe leaf process list is empty",
        require_empty_processes(leaf_fd, "clone3 ABI probe cgroup leaf after reaping"),
    );
    cleanup.record(
        "verify clone3 ABI probe leaf domain state after reaping",
        require_domain_unpopulated(leaf_fd, "clone3 ABI probe cgroup leaf after reaping"),
    );
    cleanup.record(
        "verify clone3 ABI probe leaf identity after reaping",
        require_same_identity(
            leaf_fd,
            identity,
            "clone3 ABI probe cgroup leaf after reaping",
        ),
    );
    finish_lifecycle(primary, cleanup).map_err(Into::into)
}

fn verify_release_and_reap(
    child: &mut LaunchedChild,
    leaf_fd: RawFd,
    identity: Identity,
) -> Result<(), SupervisorError> {
    let ready = child.wait_for_ready()?;
    if ready.inner_pid != 1 {
        return Err(SupervisorError::new(format!(
            "clone3 ABI probe child reported namespace PID {}, not PID 1",
            ready.inner_pid
        )));
    }
    require_only_process(
        leaf_fd,
        child.host_pid,
        "clone3 ABI probe cgroup leaf during child readiness",
    )?;
    require_same_identity(
        leaf_fd,
        identity,
        "clone3 ABI probe cgroup leaf during child readiness",
    )?;
    child.release()?;
    match child.wait_and_reap(EXIT_TIMEOUT)? {
        ChildExit::Exited(0) => Ok(()),
        outcome => Err(SupervisorError::new(format!(
            "clone3 ABI probe child did not exit cleanly after release: {outcome:?}"
        ))),
    }
}

fn build_clone_args(cgroup_fd: RawFd, pidfd: &mut libc::c_int) -> libc::clone_args {
    // SAFETY: zero is the required initial representation for clone_args; the
    // four fields below are the complete ABI probe contract.
    let mut arguments = unsafe { zeroed::<libc::clone_args>() };
    arguments.flags = REQUIRED_CLONE_FLAGS;
    arguments.pidfd = (&raw mut *pidfd).addr() as u64;
    arguments.exit_signal = libc::SIGCHLD as u64;
    arguments.cgroup = cgroup_fd as u64;
    arguments
}

fn classify_clone3_errno(
    errno: libc::c_int,
    retained_target_revalidated: bool,
) -> Clone3FailureClass {
    match errno {
        libc::EINVAL if !retained_target_revalidated => Clone3FailureClass::InvalidTarget,
        libc::ENOSYS | libc::EINVAL | libc::E2BIG => Clone3FailureClass::UnsupportedKernel,
        libc::EPERM | libc::EACCES => Clone3FailureClass::MisprovisionedHost,
        libc::EBUSY | libc::EOPNOTSUPP => Clone3FailureClass::InvalidTarget,
        _ => Clone3FailureClass::Unexpected,
    }
}

fn classified_clone3_error(
    error: io::Error,
    leaf_fd: RawFd,
    expected_identity: Identity,
) -> SupervisorError {
    let errno = error.raw_os_error().unwrap_or_default();
    let target_revalidation = if errno == libc::EINVAL {
        Some(revalidate_clone_target(leaf_fd, expected_identity))
    } else {
        None
    };
    let retained_target_revalidated = matches!(target_revalidation.as_ref(), None | Some(Ok(())));
    let class = classify_clone3_errno(errno, retained_target_revalidated);
    let target_detail = match target_revalidation {
        Some(Err(target_error)) => {
            format!("; retained target revalidation failed: {target_error}")
        }
        Some(Ok(())) => "; retained target revalidated after EINVAL".to_owned(),
        None => String::new(),
    };
    clone3_failure_diagnostic(&error, class, &target_detail)
}

fn clone3_failure_diagnostic(
    error: &io::Error,
    class: Clone3FailureClass,
    target_detail: &str,
) -> SupervisorError {
    let errno = error.raw_os_error().unwrap_or_default();
    SupervisorError::new(format!(
        "clone3 ABI probe failed: {} (errno {errno}): {error}{target_detail}",
        class.description()
    ))
}

fn revalidate_clone_target(
    leaf_fd: RawFd,
    expected_identity: Identity,
) -> Result<(), SupervisorError> {
    require_same_identity(
        leaf_fd,
        expected_identity,
        "clone3 ABI probe cgroup leaf after EINVAL",
    )?;
    require_cgroup2(leaf_fd, "clone3 ABI probe cgroup leaf after EINVAL")?;
    require_domain_unpopulated(leaf_fd, "clone3 ABI probe cgroup leaf after EINVAL")?;
    require_empty_processes(leaf_fd, "clone3 ABI probe cgroup leaf after EINVAL")
}

fn socket_pair() -> Result<(OwnedFd, OwnedFd), SupervisorError> {
    let mut descriptors = [-1; 2];
    // SAFETY: descriptors contains two writable descriptor slots.
    let result = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            descriptors.as_mut_ptr(),
        )
    };
    if result < 0 {
        return Err(SupervisorError::io(
            "cannot create clone3 ABI probe control socket pair",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: socketpair returned two new, distinct owned descriptors.
    let parent = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    // SAFETY: socketpair returned two new, distinct owned descriptors.
    let child = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    Ok((parent, child))
}

fn child_after_clone(parent_control: RawFd, child_control: RawFd, leaf_fd: RawFd) -> ! {
    // close and dup3 are async-signal-safe descriptor normalization operations.
    unsafe {
        libc::close(parent_control);
    }
    let control = if child_control == CHILD_CONTROL_FD {
        child_control
    } else {
        // SAFETY: both values are integer descriptors; failure is handled only
        // through the fixed child exit code and never unwinds.
        if unsafe { libc::dup3(child_control, CHILD_CONTROL_FD, libc::O_CLOEXEC) } < 0 {
            child_exit(CHILD_DESCRIPTOR_FAILURE);
        }
        // SAFETY: the duplicated descriptor now owns the child's endpoint.
        unsafe {
            libc::close(child_control);
        }
        CHILD_CONTROL_FD
    };
    if leaf_fd != control {
        // SAFETY: placement is complete before clone3 makes the child runnable;
        // the cgroup descriptor is no longer needed in the child.
        unsafe {
            libc::close(leaf_fd);
        }
    }

    // SAFETY: getpid has no preconditions and is async-signal-safe.
    let inner_pid = unsafe { libc::getpid() };
    let pid_bytes = (inner_pid as u32).to_be_bytes();
    let ready = [
        READY_MAGIC[0],
        READY_MAGIC[1],
        READY_MAGIC[2],
        READY_MAGIC[3],
        READY_MAGIC[4],
        READY_MAGIC[5],
        READY_MAGIC[6],
        READY_MAGIC[7],
        pid_bytes[0],
        pid_bytes[1],
        pid_bytes[2],
        pid_bytes[3],
    ];
    if !child_write_exact(control, &ready) {
        child_exit(CHILD_READY_FAILURE);
    }
    if inner_pid != 1 {
        child_exit(CHILD_WRONG_PID);
    }
    if !child_wait_for_release(control) {
        child_exit(CHILD_RELEASE_FAILURE);
    }
    child_exit(0)
}

fn child_write_exact(fd: RawFd, bytes: &[u8]) -> bool {
    loop {
        // SAFETY: bytes is readable, and fd is the retained child control
        // endpoint. write is async-signal-safe. SOCK_SEQPACKET must preserve
        // this bounded readiness record as one atomic packet.
        let count = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if count < 0 {
            if child_errno() == libc::EINTR {
                continue;
            }
            return false;
        }
        return count as usize == bytes.len();
    }
}

fn child_wait_for_release(fd: RawFd) -> bool {
    let mut bytes = [0_u8; 2];
    loop {
        // SAFETY: bytes is writable and fd is the retained child control
        // endpoint. read is async-signal-safe.
        let count = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
        if count < 0 {
            if child_errno() == libc::EINTR {
                continue;
            }
            return false;
        }
        return count == 1 && bytes[0] == RELEASE_BYTE;
    }
}

fn child_errno() -> libc::c_int {
    // SAFETY: __errno_location returns the current thread's valid errno pointer
    // on the supported glibc Linux x86-64 target.
    unsafe { *libc::__errno_location() }
}

fn child_exit(status: libc::c_int) -> ! {
    // SAFETY: _exit terminates only the cloned child and runs no Rust destructors.
    unsafe { libc::_exit(status) }
}

impl LaunchedChild {
    fn wait_for_ready(&mut self) -> Result<ReadyRecord, SupervisorError> {
        let deadline = deadline_after(READY_TIMEOUT)?;
        loop {
            let mut descriptors = [
                libc::pollfd {
                    fd: self.control.as_raw_fd(),
                    events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                    revents: 0,
                },
                libc::pollfd {
                    fd: self.pidfd.as_raw_fd(),
                    events: libc::POLLIN | libc::POLLERR,
                    revents: 0,
                },
            ];
            if !poll_until(&mut descriptors, deadline)? {
                return Err(SupervisorError::new(
                    "clone3 ABI probe readiness timeout expired",
                ));
            }
            if descriptors
                .iter()
                .any(|descriptor| descriptor.revents & libc::POLLNVAL != 0)
            {
                return Err(SupervisorError::new(
                    "clone3 ABI probe poll reported an invalid retained descriptor",
                ));
            }
            if descriptors[0].revents & libc::POLLIN != 0 {
                return receive_ready_record(self.control.as_raw_fd());
            }
            if descriptors[1].revents & libc::POLLIN != 0 {
                let outcome = self.reap()?;
                return Err(SupervisorError::new(format!(
                    "clone3 ABI probe child exited before readiness: {outcome:?}"
                )));
            }
            if descriptors[0].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                return Err(SupervisorError::new(
                    "clone3 ABI probe control channel closed before readiness",
                ));
            }
            if descriptors[1].revents & libc::POLLERR != 0 {
                return Err(SupervisorError::new(
                    "clone3 ABI probe pidfd reported POLLERR before readiness",
                ));
            }
        }
    }

    fn release(&self) -> Result<(), SupervisorError> {
        let byte = RELEASE_BYTE;
        loop {
            // SAFETY: byte is readable and control is a retained connected
            // SOCK_SEQPACKET endpoint.
            let sent = unsafe {
                libc::send(
                    self.control.as_raw_fd(),
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
                return Err(SupervisorError::io(
                    "cannot release clone3 ABI probe child",
                    error,
                ));
            }
            if sent != 1 {
                return Err(SupervisorError::new(
                    "clone3 ABI probe release was not exactly one byte",
                ));
            }
            return Ok(());
        }
    }

    fn wait_and_reap(&mut self, timeout: Duration) -> Result<ChildExit, SupervisorError> {
        if self.reaped {
            return Err(SupervisorError::new(
                "clone3 ABI probe child was already reaped",
            ));
        }
        let deadline = deadline_after(timeout)?;
        let mut descriptor = [libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN | libc::POLLERR,
            revents: 0,
        }];
        if !poll_until(&mut descriptor, deadline)? {
            return Err(SupervisorError::new(
                "clone3 ABI probe pidfd exit timeout expired",
            ));
        }
        if descriptor[0].revents & libc::POLLNVAL != 0 {
            return Err(SupervisorError::new(
                "clone3 ABI probe exit poll reported an invalid pidfd",
            ));
        }
        if descriptor[0].revents & libc::POLLIN == 0 {
            return Err(SupervisorError::new(
                "clone3 ABI probe pidfd did not report a waitable exit",
            ));
        }
        self.reap()
    }

    fn reap(&mut self) -> Result<ChildExit, SupervisorError> {
        // SAFETY: zero is the required initial representation for siginfo_t.
        let mut information = unsafe { zeroed::<libc::siginfo_t>() };
        loop {
            // SAFETY: pidfd is live, information is writable, and P_PIDFD binds
            // the wait to this retained process identity rather than a numeric
            // PID lookup.
            let result = unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    self.pidfd.as_raw_fd() as libc::id_t,
                    &raw mut information,
                    libc::WEXITED | libc::WNOHANG,
                )
            };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(SupervisorError::io(
                    "cannot reap clone3 ABI probe child through pidfd",
                    error,
                ));
            }
            // SAFETY: successful waitid initialized the process fields.
            let observed_pid = unsafe { information.si_pid() };
            if observed_pid == 0 {
                return Err(SupervisorError::new(
                    "clone3 ABI probe pidfd was readable without a waitable child",
                ));
            }
            self.reaped = true;
            if observed_pid != self.host_pid {
                return Err(SupervisorError::new(
                    "clone3 ABI probe pidfd reaped an unexpected process identity",
                ));
            }
            // SAFETY: successful waitid initialized si_status for CLD outcomes.
            let status = unsafe { information.si_status() };
            return Ok(match information.si_code {
                libc::CLD_EXITED => ChildExit::Exited(status),
                libc::CLD_KILLED | libc::CLD_DUMPED => ChildExit::Signaled(status),
                code => ChildExit::Other { code, status },
            });
        }
    }

    fn force_and_reap(&mut self) -> Result<(), SupervisorError> {
        if self.reaped {
            return Ok(());
        }
        let signal_result = send_pidfd_signal(self.pidfd.as_raw_fd(), libc::SIGKILL);
        // SAFETY: control is a retained socket. Shutting it down is a secondary
        // bounded wakeup for the fixed child read if pidfd signaling itself was
        // rejected; it is not a process-attachment or numeric-PID fallback.
        let shutdown_result = unsafe { libc::shutdown(self.control.as_raw_fd(), libc::SHUT_RDWR) };
        let shutdown_error = if shutdown_result < 0 {
            let error = io::Error::last_os_error();
            if matches!(error.raw_os_error(), Some(libc::ENOTCONN | libc::EINVAL)) {
                None
            } else {
                Some(error)
            }
        } else {
            None
        };
        let reap_result = self.wait_and_reap(FORCED_EXIT_TIMEOUT);
        signal_result?;
        if let Some(error) = shutdown_error {
            return Err(SupervisorError::io(
                "cannot shut down clone3 ABI probe control channel during cleanup",
                error,
            ));
        }
        let _ = reap_result?;
        Ok(())
    }
}

impl Drop for LaunchedChild {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        // SAFETY: best-effort channel shutdown wakes the fixed child read even
        // if pidfd signaling fails. All operations remain bounded.
        unsafe {
            libc::shutdown(self.control.as_raw_fd(), libc::SHUT_RDWR);
        }
        let _ = send_pidfd_signal(self.pidfd.as_raw_fd(), libc::SIGKILL);
        let _ = self.wait_and_reap(FORCED_EXIT_TIMEOUT);
    }
}

fn receive_ready_record(fd: RawFd) -> Result<ReadyRecord, SupervisorError> {
    let mut bytes = [0_u8; READY_RECORD_BYTES + 1];
    loop {
        // SAFETY: bytes is writable and fd is a retained connected endpoint.
        let received = unsafe {
            libc::recv(
                fd,
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if received < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(SupervisorError::io(
                "cannot receive clone3 ABI probe readiness record",
                error,
            ));
        }
        return decode_ready_record(&bytes[..received as usize]);
    }
}

fn decode_ready_record(bytes: &[u8]) -> Result<ReadyRecord, SupervisorError> {
    if bytes.len() != READY_RECORD_BYTES {
        return Err(SupervisorError::new(
            "clone3 ABI probe readiness record has an invalid length",
        ));
    }
    if bytes[..READY_MAGIC.len()] != READY_MAGIC {
        return Err(SupervisorError::new(
            "clone3 ABI probe readiness record has invalid magic",
        ));
    }
    Ok(ReadyRecord {
        inner_pid: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
    })
}

fn send_pidfd_signal(pidfd: RawFd, signal: libc::c_int) -> Result<(), SupervisorError> {
    loop {
        // SAFETY: pidfd is retained, signal is a valid signal number, and null
        // siginfo plus zero flags are the pidfd_send_signal contract.
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd,
                signal,
                ptr::null::<libc::siginfo_t>(),
                0_u32,
            )
        };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        return Err(SupervisorError::io(
            "cannot signal clone3 ABI probe child through pidfd",
            error,
        ));
    }
}

fn deadline_after(timeout: Duration) -> Result<Duration, SupervisorError> {
    monotonic_now()?
        .checked_add(timeout)
        .ok_or_else(|| SupervisorError::new("clone3 ABI probe monotonic deadline overflowed"))
}

fn monotonic_now() -> Result<Duration, SupervisorError> {
    let mut value = MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: value points to sufficient writable storage.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, value.as_mut_ptr()) } < 0 {
        return Err(SupervisorError::io(
            "cannot read clone3 ABI probe monotonic clock",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: clock_gettime succeeded and initialized value.
    let value = unsafe { value.assume_init() };
    let seconds = u64::try_from(value.tv_sec)
        .map_err(|_| SupervisorError::new("clone3 ABI probe clock returned negative seconds"))?;
    let nanoseconds = u32::try_from(value.tv_nsec)
        .map_err(|_| SupervisorError::new("clone3 ABI probe clock returned invalid nanoseconds"))?;
    if nanoseconds >= 1_000_000_000 {
        return Err(SupervisorError::new(
            "clone3 ABI probe clock returned out-of-range nanoseconds",
        ));
    }
    Ok(Duration::new(seconds, nanoseconds))
}

fn poll_until(
    descriptors: &mut [libc::pollfd],
    deadline: Duration,
) -> Result<bool, SupervisorError> {
    loop {
        let now = monotonic_now()?;
        if now >= deadline {
            return Ok(false);
        }
        let remaining = deadline - now;
        let milliseconds = remaining.as_millis().saturating_add(1);
        let timeout = i32::try_from(milliseconds).unwrap_or(i32::MAX);
        // SAFETY: descriptors references initialized pollfd values for the
        // complete call.
        let ready = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                descriptors.len() as libc::nfds_t,
                timeout,
            )
        };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(SupervisorError::io("clone3 ABI probe poll failed", error));
        }
        return Ok(ready > 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clone_args_have_exact_layout_flags_and_zero_fields() {
        let mut pidfd = -1;
        let args = build_clone_args(17, &mut pidfd);

        assert_eq!(size_of::<libc::clone_args>(), 88);
        assert_eq!(std::mem::align_of::<libc::clone_args>(), 8);
        assert_eq!(REQUIRED_CLONE_FLAGS, 0x2_2000_1000);
        assert_eq!(args.flags, REQUIRED_CLONE_FLAGS);
        assert_eq!(args.pidfd, (&raw mut pidfd).addr() as u64);
        assert_eq!(args.exit_signal, libc::SIGCHLD as u64);
        assert_eq!(args.cgroup, 17);
        assert_eq!(args.child_tid, 0);
        assert_eq!(args.parent_tid, 0);
        assert_eq!(args.stack, 0);
        assert_eq!(args.stack_size, 0);
        assert_eq!(args.tls, 0);
        assert_eq!(args.set_tid, 0);
        assert_eq!(args.set_tid_size, 0);
    }

    #[test]
    fn clone3_errno_classes_are_fail_closed_and_distinct() {
        for errno in [libc::ENOSYS, libc::EINVAL, libc::E2BIG] {
            assert_eq!(
                classify_clone3_errno(errno, true),
                Clone3FailureClass::UnsupportedKernel
            );
        }
        assert_eq!(
            classify_clone3_errno(libc::EINVAL, false),
            Clone3FailureClass::InvalidTarget
        );
        for errno in [libc::EPERM, libc::EACCES] {
            assert_eq!(
                classify_clone3_errno(errno, true),
                Clone3FailureClass::MisprovisionedHost
            );
        }
        for errno in [libc::EBUSY, libc::EOPNOTSUPP] {
            assert_eq!(
                classify_clone3_errno(errno, true),
                Clone3FailureClass::InvalidTarget
            );
        }
        assert_eq!(
            classify_clone3_errno(libc::EFAULT, true),
            Clone3FailureClass::Unexpected
        );
    }

    #[test]
    fn clone3_error_diagnostics_preserve_the_failure_class() {
        for (errno, expected) in [
            (libc::ENOSYS, "unsupported kernel"),
            (libc::E2BIG, "unsupported kernel"),
            (libc::EPERM, "misprovisioned"),
            (libc::EBUSY, "invalid cgroup-v2 target"),
            (libc::EFAULT, "unexpected clone3 failure"),
        ] {
            let error = io::Error::from_raw_os_error(errno);
            let class = classify_clone3_errno(errno, true);
            let diagnostic = clone3_failure_diagnostic(&error, class, "");
            assert!(diagnostic.to_string().contains(expected), "{diagnostic}");
            assert!(
                diagnostic.to_string().contains(&format!("errno {errno}")),
                "{diagnostic}"
            );
        }
    }

    #[test]
    fn readiness_record_is_exact_and_reports_inner_pid() {
        let mut record = READY_MAGIC.to_vec();
        record.extend_from_slice(&1_u32.to_be_bytes());
        assert_eq!(
            decode_ready_record(&record).unwrap(),
            ReadyRecord { inner_pid: 1 }
        );
        assert!(decode_ready_record(&record[..record.len() - 1]).is_err());
        record.push(0);
        assert!(decode_ready_record(&record).is_err());
        record.truncate(READY_RECORD_BYTES);
        record[0] ^= 1;
        assert!(decode_ready_record(&record).is_err());
    }

    #[test]
    #[ignore = "requires an explicitly delegated empty cgroup-v2 leaf FD and namespace privilege"]
    fn live_clone3_pid_namespace_and_cgroup_placement_abi_probe() {
        if std::env::var_os("MOSAIC_BINDING_SUPERVISOR_CLONE3_ABI_PROBE").as_deref()
            != Some(std::ffi::OsStr::new("1"))
        {
            return;
        }
        let fd: RawFd = std::env::var("MOSAIC_BINDING_SUPERVISOR_ABI_PROBE_LEAF_FD")
            .expect("set inherited ABI probe cgroup leaf FD number")
            .parse()
            .expect("ABI probe cgroup leaf FD must be an integer");
        // SAFETY: explicit integration setup promises fd is a live delegated
        // cgroup leaf descriptor. The duplicate avoids consuming test-harness
        // ownership and stays away from the fixed child status FD.
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 5) };
        assert!(duplicate >= 0, "cannot duplicate ABI probe cgroup leaf FD");
        // SAFETY: fcntl returned one new owned descriptor.
        let leaf = unsafe { OwnedFd::from_raw_fd(duplicate) };
        run(leaf).expect("live clone3 ABI probe failed");
    }
}
