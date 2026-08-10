use super::cgroup::{
    require_domain_unpopulated, require_empty_processes, require_parent_entry_identity,
    require_same_identity, stable_identity,
};
use super::*;

pub(super) fn validate_control_socket(fd: RawFd) -> Result<(), SupervisorError> {
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

pub(super) fn receive_control_packet(socket: RawFd) -> Result<ControlRead, io::Error> {
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

pub(super) fn wait_for_ready(
    control: &OwnedFd,
    signals: &SignalMonitor,
) -> Result<(), SupervisorError> {
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

pub(super) fn send_handoff(control: &OwnedFd, session: &Session) -> Result<(), HandoffSendError> {
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

pub(super) fn send_one_rights_packet(
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

pub(super) fn validate_handoff_send_count(
    sent: isize,
    expected: usize,
) -> Result<(), HandoffSendError> {
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
    pub(super) fn install() -> Result<Self, SupervisorError> {
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

pub(super) fn wait_for_post_handoff_eof(
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
