use super::*;

// A healthy session has only a small number of short-lived measurement leaves.
// 1,024 entries leaves ample operational headroom while bounding retained name
// storage to a few hundred KiB even at the cgroup filesystem's name limit.
const MAX_DIRECT_SESSION_ENTRIES: usize = 1_024;

pub(super) fn qualify_parent(descriptor: OwnedFd) -> Result<QualifiedParent, SupervisorError> {
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

pub(super) fn parse_enabled_controller_set(
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

pub(super) fn contains_only_fixed_controllers(controllers: &BTreeSet<String>) -> bool {
    controllers
        .iter()
        .all(|controller| REQUIRED_CONTROLLERS.contains(&controller.as_str()))
}

pub(super) fn has_exact_fixed_controllers(controllers: &BTreeSet<String>) -> bool {
    controllers.len() == REQUIRED_CONTROLLERS.len() && contains_only_fixed_controllers(controllers)
}

pub(super) fn require_only_fixed_controllers(
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

pub(super) fn require_exact_fixed_controllers(
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

pub(super) fn create_session(parent: QualifiedParent) -> Result<Session, SupervisorError> {
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

pub(super) fn configure_session(session: &Session) -> Result<(), SupervisorError> {
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

pub(super) fn require_domain_unpopulated(fd: RawFd, context: &str) -> Result<(), SupervisorError> {
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

pub(super) fn require_empty_processes(fd: RawFd, context: &str) -> Result<(), SupervisorError> {
    if !read_control(fd, "cgroup.procs")?.is_empty() {
        return Err(SupervisorError::new(format!(
            "{context} contains processes despite reporting unpopulated"
        )));
    }
    Ok(())
}

pub(super) fn require_only_process(
    fd: RawFd,
    expected_pid: libc::pid_t,
    context: &str,
) -> Result<(), SupervisorError> {
    if expected_pid <= 0 {
        return Err(SupervisorError::new(format!(
            "{context} has an invalid expected process ID"
        )));
    }
    let expected = format!("{expected_pid}\n");
    if read_control(fd, "cgroup.procs")? != expected.as_bytes() {
        return Err(SupervisorError::new(format!(
            "{context} does not contain exactly the clone3 child"
        )));
    }
    let events = read_control(fd, "cgroup.events")?;
    if !parse_populated(&events).map_err(|error| {
        SupervisorError::new(format!("invalid {context} cgroup.events: {error}"))
    })? {
        return Err(SupervisorError::new(format!(
            "{context} reports unpopulated while containing the clone3 child"
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

pub(super) fn stable_identity(fd: RawFd, context: &str) -> Result<Identity, SupervisorError> {
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

pub(super) fn require_same_identity(
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

pub(super) fn require_cgroup2(fd: RawFd, context: &str) -> Result<(), SupervisorError> {
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

pub(super) fn require_parent_entry_identity(session: &Session) -> Result<(), SupervisorError> {
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

impl Session {
    pub(super) fn suppress_cleanup_for_recovery(&mut self) {
        self.cleanup_attempted = true;
    }

    pub(super) fn cleanup(&mut self) -> CleanupFailures {
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

        let direct_children_enumerated = match list_direct_children(self.descriptor.as_raw_fd()) {
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
                true
            }
            Err(error) => {
                failures.record("enumerate direct session children", Err::<(), _>(error));
                false
            }
        };

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

        if !direct_children_enumerated {
            failures.push(
                "refused to remove session root after direct-child enumeration failed; session remains visible for recovery"
                    .to_owned(),
            );
        } else if session_identity_valid
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

pub(super) fn wait_until_unpopulated(fd: RawFd) -> Result<(), SupervisorError> {
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
    // Reopen the pinned directory through itself instead of duplicating the FD.
    // dup/fcntl would share the directory-stream offset with the retained FD,
    // making a later cleanup enumeration start at an old EOF position.
    const CURRENT_DIRECTORY: &[u8] = b".\0";
    // SAFETY: fd is a live directory descriptor and CURRENT_DIRECTORY is NUL terminated.
    let enumeration_fd = unsafe {
        libc::openat(
            fd,
            CURRENT_DIRECTORY.as_ptr().cast(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    if enumeration_fd < 0 {
        return Err(SupervisorError::io(
            "cannot reopen session FD for direct-child enumeration",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: enumeration_fd is a fresh descriptor; fdopendir consumes it on success.
    let directory = unsafe { libc::fdopendir(enumeration_fd) };
    if directory.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: fdopendir failed and therefore did not consume enumeration_fd.
        unsafe { libc::close(enumeration_fd) };
        return Err(SupervisorError::io(
            "cannot enumerate direct session children",
            error,
        ));
    }

    let mut entries = Vec::new();
    let mut non_dot_entry_count = 0_usize;
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
            let Some(next_count) = non_dot_entry_count.checked_add(1) else {
                break Err(SupervisorError::new(
                    "direct session entry count overflowed during cleanup enumeration",
                ));
            };
            if let Err(error) = require_direct_session_entry_count(next_count) {
                break Err(error);
            }
            non_dot_entry_count = next_count;
            entries.push(name.to_vec());
        }
    };
    // SAFETY: directory is live and closedir consumes it and the reopened enumeration FD.
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

fn require_direct_session_entry_count(count: usize) -> Result<(), SupervisorError> {
    if count <= MAX_DIRECT_SESSION_ENTRIES {
        Ok(())
    } else {
        Err(SupervisorError::new(format!(
            "direct session directory contains more than {MAX_DIRECT_SESSION_ENTRIES} non-dot entries; refusing cleanup enumeration at its fixed memory bound"
        )))
    }
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
    use std::fs::{self, File};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            for _ in 0..32 {
                let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "mosaic-binding-supervisor-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self { path },
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("cannot create test directory {path:?}: {error}"),
                }
            }
            panic!("cannot allocate a unique direct-child enumeration test directory");
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn create_entry(&self, index: usize) -> PathBuf {
            let path = self.path.join(format!("entry-{index:04}"));
            File::create(&path)
                .unwrap_or_else(|error| panic!("cannot create test entry {path:?}: {error}"));
            path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn direct_session_entry_bound_accepts_exact_limit_and_rejects_next() {
        assert!(require_direct_session_entry_count(MAX_DIRECT_SESSION_ENTRIES).is_ok());

        let error = require_direct_session_entry_count(MAX_DIRECT_SESSION_ENTRIES + 1)
            .expect_err("one entry beyond the cleanup bound must fail closed");
        assert!(
            error.to_string().contains("more than 1024 non-dot entries"),
            "{error}"
        );
    }

    #[test]
    fn direct_child_enumeration_enforces_bound_and_remains_recoverable() {
        let directory = TestDirectory::new();
        for index in 0..MAX_DIRECT_SESSION_ENTRIES {
            directory.create_entry(index);
        }
        let descriptor = File::open(directory.path()).expect("test directory must be openable");

        let entries = list_direct_children(descriptor.as_raw_fd())
            .expect("the exact cleanup entry bound must be enumerable");
        assert_eq!(entries.len(), MAX_DIRECT_SESSION_ENTRIES);

        let overflow_entry = directory.create_entry(MAX_DIRECT_SESSION_ENTRIES);
        let error = list_direct_children(descriptor.as_raw_fd())
            .expect_err("one entry beyond the cleanup bound must fail closed");
        assert!(
            error.to_string().contains("more than 1024 non-dot entries"),
            "{error}"
        );

        fs::remove_file(&overflow_entry).expect("overflow test entry must be removable");
        let recovered_entries = list_direct_children(descriptor.as_raw_fd())
            .expect("a failed enumeration must leave the retained descriptor usable");
        assert_eq!(recovered_entries.len(), MAX_DIRECT_SESSION_ENTRIES);
    }
}
