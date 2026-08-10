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
                rights
                    .push(unsafe { ptr::read_unaligned(libc::CMSG_DATA(header).cast::<RawFd>()) });
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
