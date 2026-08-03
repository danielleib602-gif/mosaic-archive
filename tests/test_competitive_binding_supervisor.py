from __future__ import annotations

import copy
import os
import pickle
import socket
import struct
import sys
import threading
import unittest
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from unittest.mock import patch

import mosaic_archive.competitive_binding_supervisor as supervisor_module
from mosaic_archive.competitive_binding_supervisor import (
    DELEGATED_ROOT_CONTROL_FD,
    DELEGATED_ROOT_PACKET_BYTES,
    DELEGATED_ROOT_POLICY_SHA256,
    DELEGATED_ROOT_RECEIVER_READY,
    DELEGATED_ROOT_SUPERVISOR_REVOKE,
    DelegatedRootCapabilityError,
    DelegatedRootProtocolError,
    ExclusiveDelegatedCgroupRoot,
    _issue_capability_for_testing,
    _parse_supervisor_packet,
    _require_capability_access,
    inherit_exclusive_delegated_root,
)
from tests.test_competitive_binding_runner import FakeBindingBackend

_PROTOCOL_VECTOR_HEX = (
    "4d534342494e443100010000010203041112131421222324"
    "01020304050607081112131415161718"
    "bd8039119e7ab17b5776fd2025531ff2cd2275ce13c912405792eecc09388e58"
    "000102030405060708090a0b0c0d0e0f"
)
_PACKET = struct.Struct("!8sHHIIIQQ32s16s")


def _packet(
    *,
    pid: int,
    uid: int,
    gid: int,
    device: int,
    inode: int,
    digest: bytes | None = None,
    nonce: bytes = bytes.fromhex("00112233445566778899aabbccddeeff"),
) -> bytes:
    return _PACKET.pack(
        b"MSCBIND1",
        1,
        0,
        pid,
        uid,
        gid,
        device,
        inode,
        bytes.fromhex(DELEGATED_ROOT_POLICY_SHA256) if digest is None else digest,
        nonce,
    )


class SupervisorPacketTests(unittest.TestCase):
    def test_published_network_order_protocol_vector_is_exact(self) -> None:
        payload = _PACKET.pack(
            b"MSCBIND1",
            1,
            0,
            0x01020304,
            0x11121314,
            0x21222324,
            0x0102030405060708,
            0x1112131415161718,
            bytes.fromhex(DELEGATED_ROOT_POLICY_SHA256),
            bytes(range(16)),
        )

        self.assertEqual(len(payload), DELEGATED_ROOT_PACKET_BYTES)
        self.assertEqual(payload.hex(), _PROTOCOL_VECTOR_HEX)
        parsed = _parse_supervisor_packet(bytes.fromhex(_PROTOCOL_VECTOR_HEX))
        self.assertEqual(parsed.supervisor_pid, 0x01020304)
        self.assertEqual(parsed.supervisor_uid, 0x11121314)
        self.assertEqual(parsed.supervisor_gid, 0x21222324)
        self.assertEqual(parsed.root_identity.device, 0x0102030405060708)
        self.assertEqual(parsed.root_identity.inode, 0x1112131415161718)
        self.assertEqual(parsed.session_id, "000102030405060708090a0b0c0d0e0f")

    def test_parser_rejects_malformed_fixed_fields_and_lengths(self) -> None:
        valid = bytes.fromhex(_PROTOCOL_VECTOR_HEX)
        mutations = (
            valid[:-1],
            valid + b"x",
            b"BADMAGIC" + valid[8:],
            valid[:9] + b"\x02" + valid[10:],
            valid[:11] + b"\x01" + valid[12:],
            valid[:12] + bytes(4) + valid[16:],
            valid[:24] + bytes(8) + valid[32:],
            valid[:32] + bytes(8) + valid[40:],
            valid[:40] + bytes(32) + valid[72:],
            valid[:72] + bytes(16),
        )
        for payload in mutations:
            with self.subTest(payload=payload.hex()), self.assertRaises(DelegatedRootProtocolError):
                _parse_supervisor_packet(payload)
        with self.assertRaises(TypeError):
            _parse_supervisor_packet(bytearray(valid))  # type: ignore[arg-type]

    def test_ancillary_parser_rejects_missing_multiple_and_unknown_messages(self) -> None:
        credentials_type = getattr(socket, "SCM_CREDENTIALS", 2)
        rights_type = getattr(socket, "SCM_RIGHTS", 1)
        one_fd = struct.pack("i", 7)
        credentials = struct.pack("3i", 1, 2, 3)
        invalid = (
            [],
            [(socket.SOL_SOCKET, rights_type, one_fd)],
            [
                (socket.SOL_SOCKET, rights_type, one_fd + struct.pack("i", 8)),
                (socket.SOL_SOCKET, credentials_type, credentials),
            ],
            [
                (socket.SOL_SOCKET, rights_type, one_fd),
                (socket.SOL_SOCKET, credentials_type, credentials),
                (socket.SOL_SOCKET, 0x7FFF, b"x"),
            ],
        )
        for ancillary in invalid:
            with self.subTest(ancillary=ancillary), self.assertRaises(DelegatedRootProtocolError):
                supervisor_module._received_descriptors_and_credentials(ancillary)


class ExclusiveDelegatedRootTests(unittest.TestCase):
    def test_capability_is_exact_process_issued_and_nontransferable(self) -> None:
        backend = FakeBindingBackend()
        capability = _issue_capability_for_testing(
            backend=backend,
            root_handle=backend.root_handle,
            root_device=11,
            root_inode=12,
        )
        self.addCleanup(capability.close)

        self.assertIs(capability.binding_eligible, False)
        self.assertTrue(capability.is_open)
        self.assertEqual(capability.session_id, "00112233445566778899aabbccddeeff")
        self.assertEqual(capability.policy_digest, DELEGATED_ROOT_POLICY_SHA256)
        access = _require_capability_access(capability)
        self.assertIs(access.backend, backend)
        self.assertIs(access.root_handle, backend.root_handle)
        self.assertFalse(access.production_inherited)

        for operation in (
            lambda: copy.copy(capability),
            lambda: copy.deepcopy(capability),
            lambda: pickle.dumps(capability),
        ):
            with self.assertRaises(TypeError):
                operation()
        with self.assertRaises(TypeError):
            ExclusiveDelegatedCgroupRoot()
        forged = object.__new__(ExclusiveDelegatedCgroupRoot)
        with self.assertRaises(DelegatedRootCapabilityError):
            _require_capability_access(forged)

    def test_closed_stale_or_mutated_capability_fails_closed(self) -> None:
        backend = FakeBindingBackend()
        capability = _issue_capability_for_testing(
            backend=backend,
            root_handle=backend.root_handle,
        )
        capability._issuing_pid += 1
        with self.assertRaisesRegex(DelegatedRootCapabilityError, "another process"):
            _require_capability_access(capability)
        capability._issuing_pid = os.getpid()
        capability._session_id = "ff" * 16
        with self.assertRaisesRegex(DelegatedRootCapabilityError, "mismatched"):
            _require_capability_access(capability)
        capability.close()
        self.assertTrue(capability.is_closed)
        with self.assertRaisesRegex(DelegatedRootCapabilityError, "closed"):
            _require_capability_access(capability)

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX fork")
    def test_fork_child_revokes_all_inherited_capability_objects(self) -> None:
        backend = FakeBindingBackend()
        capability = _issue_capability_for_testing(
            backend=backend,
            root_handle=backend.root_handle,
        )
        self.addCleanup(capability.close)
        read_fd, write_fd = os.pipe()
        child_pid = os.fork()
        if child_pid == 0:
            os.close(read_fd)
            rejected = False
            try:
                _require_capability_access(capability)
            except DelegatedRootCapabilityError:
                rejected = True
            payload = f"closed={capability.is_closed};rejected={rejected}".encode("ascii")
            os.write(write_fd, payload)
            os.close(write_fd)
            os._exit(0)

        os.close(write_fd)
        try:
            payload = os.read(read_fd, 256)
        finally:
            os.close(read_fd)
        waited_pid, status = os.waitpid(child_pid, 0)
        self.assertEqual(waited_pid, child_pid)
        self.assertEqual(status, 0)
        self.assertEqual(payload, b"closed=True;rejected=True")
        self.assertTrue(capability.is_open)


_LINUX_SOCKET_PROTOCOL = (
    sys.platform.startswith("linux")
    and hasattr(socket, "SO_PASSCRED")
    and hasattr(socket, "SCM_CREDENTIALS")
    and hasattr(socket, "MSG_CMSG_CLOEXEC")
    and Path("/sys/fs/cgroup").is_dir()
)


@unittest.skipUnless(_LINUX_SOCKET_PROTOCOL, "requires Linux seqpacket credential passing")
class LinuxSupervisorSocketTests(unittest.TestCase):
    @contextmanager
    def _installed_control_socket(self, receiver: socket.socket) -> Iterator[None]:
        try:
            backup = os.dup(DELEGATED_ROOT_CONTROL_FD)
        except OSError:
            backup = None
        source = receiver.detach()
        if source != DELEGATED_ROOT_CONTROL_FD:
            os.dup2(source, DELEGATED_ROOT_CONTROL_FD)
            os.close(source)
        try:
            yield
        finally:
            if backup is None:
                with suppress(OSError):
                    os.close(DELEGATED_ROOT_CONTROL_FD)
            else:
                os.dup2(backup, DELEGATED_ROOT_CONTROL_FD)
                os.close(backup)

    def _channel(self) -> tuple[socket.socket, socket.socket]:
        receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        return receiver, sender

    def test_socketpair_inherits_rights_and_kernel_credentials(self) -> None:
        root_fd = os.open("/sys/fs/cgroup", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        status = os.fstat(root_fd)
        receiver, sender = self._channel()
        self.addCleanup(sender.close)
        payload = _packet(
            pid=os.getpid(),
            uid=os.geteuid(),
            gid=os.getegid(),
            device=status.st_dev,
            inode=status.st_ino,
        )
        sender.sendmsg(
            [payload],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", root_fd))],
        )
        os.close(root_fd)

        with self._installed_control_socket(receiver):
            capability = inherit_exclusive_delegated_root()
            try:
                self.assertTrue(capability.is_open)
                self.assertEqual(capability.supervisor_pid, os.getpid())
                self.assertEqual(capability.supervisor_uid, os.geteuid())
                self.assertEqual(capability.supervisor_gid, os.getegid())
                self.assertEqual(capability.root_identity.device, status.st_dev)
                self.assertEqual(capability.root_identity.inode, status.st_ino)
                self.assertTrue(_require_capability_access(capability).production_inherited)
                self.assertEqual(sender.recv(2, socket.MSG_DONTWAIT), DELEGATED_ROOT_RECEIVER_READY)
            finally:
                capability.close()

    def test_control_descriptor_cannot_be_claimed_twice(self) -> None:
        root_fd = os.open("/sys/fs/cgroup", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        status = os.fstat(root_fd)
        receiver, sender = self._channel()
        sender.sendmsg(
            [
                _packet(
                    pid=os.getpid(),
                    uid=os.geteuid(),
                    gid=os.getegid(),
                    device=status.st_dev,
                    inode=status.st_ino,
                )
            ],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", root_fd))],
        )
        os.close(root_fd)

        try:
            with self._installed_control_socket(receiver):
                capability = inherit_exclusive_delegated_root()
                try:
                    self.assertEqual(sender.recv(2), DELEGATED_ROOT_RECEIVER_READY)
                    with self.assertRaisesRegex(
                        DelegatedRootProtocolError,
                        "already claimed",
                    ):
                        inherit_exclusive_delegated_root()
                    self.assertTrue(_require_capability_access(capability).production_inherited)
                    with self.assertRaises(BlockingIOError):
                        sender.recv(2, socket.MSG_DONTWAIT)
                finally:
                    capability.close()
        finally:
            sender.close()

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX fork")
    def test_fork_child_closes_inherited_production_descriptors(self) -> None:
        root_fd = os.open("/sys/fs/cgroup", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        status = os.fstat(root_fd)
        receiver, sender = self._channel()
        sender.sendmsg(
            [
                _packet(
                    pid=os.getpid(),
                    uid=os.geteuid(),
                    gid=os.getegid(),
                    device=status.st_dev,
                    inode=status.st_ino,
                )
            ],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", root_fd))],
        )
        os.close(root_fd)
        try:
            with self._installed_control_socket(receiver):
                capability = inherit_exclusive_delegated_root()
                self.assertEqual(
                    sender.recv(2, socket.MSG_DONTWAIT),
                    DELEGATED_ROOT_RECEIVER_READY,
                )
                read_fd, write_fd = os.pipe()
                child_pid = os.fork()
                if child_pid == 0:
                    os.close(read_fd)
                    payload = (
                        f"closed={capability.is_closed};"
                        f"backend_open={capability._backend.is_open};"
                        f"control_none={capability._control_socket is None}"
                    ).encode("ascii")
                    os.write(write_fd, payload)
                    os.close(write_fd)
                    os._exit(0)

                os.close(write_fd)
                try:
                    payload = os.read(read_fd, 256)
                finally:
                    os.close(read_fd)
                waited_pid, wait_status = os.waitpid(child_pid, 0)
                self.assertEqual((waited_pid, wait_status), (child_pid, 0))
                self.assertEqual(
                    payload,
                    b"closed=True;backend_open=False;control_none=True",
                )
                self.assertTrue(_require_capability_access(capability).production_inherited)
                capability.close()
        finally:
            sender.close()

    def test_receiver_ready_precedes_the_authenticated_authority_packet(self) -> None:
        receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        root_fd = os.open("/sys/fs/cgroup", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        if sender.fileno() == DELEGATED_ROOT_CONTROL_FD:
            replacement = socket.socket(fileno=os.dup(sender.fileno()))
            sender.close()
            sender = replacement
        if root_fd == DELEGATED_ROOT_CONTROL_FD:
            replacement_fd = os.dup(root_fd)
            os.set_inheritable(replacement_fd, False)
            os.close(root_fd)
            root_fd = replacement_fd
        status = os.fstat(root_fd)
        sender_errors: list[BaseException] = []
        ready_records: list[bytes] = []

        def send_after_ready() -> None:
            try:
                ready_records.append(sender.recv(2))
                sender.sendmsg(
                    [
                        _packet(
                            pid=os.getpid(),
                            uid=os.geteuid(),
                            gid=os.getegid(),
                            device=status.st_dev,
                            inode=status.st_ino,
                        )
                    ],
                    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", root_fd))],
                )
            except BaseException as error:
                sender_errors.append(error)

        sender_thread = threading.Thread(target=send_after_ready)
        sender_thread.start()
        try:
            with self._installed_control_socket(receiver):
                capability = inherit_exclusive_delegated_root()
                capability.close()
        finally:
            sender_thread.join(timeout=5)
            sender.close()
            os.close(root_fd)

        self.assertFalse(sender_thread.is_alive())
        self.assertEqual(sender_errors, [])
        self.assertEqual(ready_records, [DELEGATED_ROOT_RECEIVER_READY])

    def test_inheritance_times_out_when_supervisor_withholds_handoff(self) -> None:
        receiver, sender = self._channel()
        try:
            with (
                self._installed_control_socket(receiver),
                patch.object(
                    supervisor_module,
                    "_DELEGATED_ROOT_HANDSHAKE_TIMEOUT_SECONDS",
                    0.01,
                ),
                self.assertRaisesRegex(DelegatedRootProtocolError, "handshake timed out"),
            ):
                inherit_exclusive_delegated_root()
            self.assertEqual(sender.recv(2), DELEGATED_ROOT_RECEIVER_READY)
        finally:
            sender.close()

    def test_timeout_reset_failure_closes_received_descriptor(self) -> None:
        descriptors_before = len(os.listdir("/proc/self/fd"))
        root_fd = os.open("/sys/fs/cgroup", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        status = os.fstat(root_fd)
        receiver, sender = self._channel()
        sender.sendmsg(
            [
                _packet(
                    pid=os.getpid(),
                    uid=os.geteuid(),
                    gid=os.getegid(),
                    device=status.st_dev,
                    inode=status.st_ino,
                )
            ],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", root_fd))],
        )
        os.close(root_fd)

        def fail_reset(control: socket.socket, timeout: float | None) -> None:
            if timeout is None:
                raise OSError("injected timeout reset failure")
            control.settimeout(timeout)

        try:
            with (
                self._installed_control_socket(receiver),
                patch.object(supervisor_module, "_set_control_timeout", side_effect=fail_reset),
                self.assertRaisesRegex(OSError, "injected timeout reset failure"),
            ):
                inherit_exclusive_delegated_root()
        finally:
            sender.close()
        self.assertEqual(len(os.listdir("/proc/self/fd")), descriptors_before)

    def test_rejects_wrong_credentials_policy_identity_and_descriptor_type(self) -> None:
        root_path = "/sys/fs/cgroup"
        scenarios = ("credentials", "policy", "identity", "descriptor")
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                root_fd = os.open(root_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                status = os.fstat(root_fd)
                transfer_fd = root_fd
                if scenario == "descriptor":
                    transfer_fd = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
                payload = _packet(
                    pid=os.getpid() + (1 if scenario == "credentials" else 0),
                    uid=os.geteuid(),
                    gid=os.getegid(),
                    device=status.st_dev + (1 if scenario == "identity" else 0),
                    inode=status.st_ino,
                    digest=bytes(32) if scenario == "policy" else None,
                )
                receiver, sender = self._channel()
                sender.sendmsg(
                    [payload],
                    [
                        (
                            socket.SOL_SOCKET,
                            socket.SCM_RIGHTS,
                            struct.pack("i", transfer_fd),
                        )
                    ],
                )
                os.close(root_fd)
                if transfer_fd != root_fd:
                    os.close(transfer_fd)
                try:
                    with (
                        self._installed_control_socket(receiver),
                        self.assertRaises(DelegatedRootProtocolError),
                    ):
                        inherit_exclusive_delegated_root()
                finally:
                    sender.close()

    def test_live_capability_revokes_on_supervisor_eof_or_inbound_data(self) -> None:
        for scenario in ("eof", "inbound-data"):
            with self.subTest(scenario=scenario):
                root_fd = os.open(
                    "/sys/fs/cgroup",
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
                )
                status = os.fstat(root_fd)
                receiver, sender = self._channel()
                sender.sendmsg(
                    [
                        _packet(
                            pid=os.getpid(),
                            uid=os.geteuid(),
                            gid=os.getegid(),
                            device=status.st_dev,
                            inode=status.st_ino,
                        )
                    ],
                    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", root_fd))],
                )
                os.close(root_fd)
                try:
                    with self._installed_control_socket(receiver):
                        capability = inherit_exclusive_delegated_root()
                        if scenario == "eof":
                            sender.close()
                        else:
                            sender.send(DELEGATED_ROOT_SUPERVISOR_REVOKE)
                        with self.assertRaisesRegex(
                            DelegatedRootCapabilityError,
                            "control channel",
                        ):
                            _require_capability_access(capability)
                        self.assertTrue(capability.is_closed)
                        capability.close()
                finally:
                    sender.close()

    def test_rejects_truncated_multiple_packets_and_wrong_descriptor_counts(self) -> None:
        descriptors_before = len(os.listdir("/proc/self/fd"))
        root_fd = os.open("/sys/fs/cgroup", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        status = os.fstat(root_fd)
        valid = _packet(
            pid=os.getpid(),
            uid=os.geteuid(),
            gid=os.getegid(),
            device=status.st_dev,
            inode=status.st_ino,
        )
        scenarios = (
            "oversized",
            "ancillary-truncated",
            "multiple-packets",
            "multiple-rights-packets",
            "no-rights",
            "two-rights",
        )
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                receiver, sender = self._channel()
                ancillary = []
                if scenario != "no-rights":
                    descriptor_bytes = struct.pack("i", root_fd)
                    if scenario == "two-rights":
                        descriptor_bytes += struct.pack("i", root_fd)
                    elif scenario == "ancillary-truncated":
                        descriptor_bytes *= 32
                    ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, descriptor_bytes)]
                sender.sendmsg([valid + (b"x" if scenario == "oversized" else b"")], ancillary)
                if scenario == "multiple-packets":
                    sender.send(valid)
                elif scenario == "multiple-rights-packets":
                    sender.sendmsg(
                        [b"x"],
                        [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", root_fd))],
                    )
                try:
                    with (
                        self._installed_control_socket(receiver),
                        self.assertRaises(DelegatedRootProtocolError),
                    ):
                        inherit_exclusive_delegated_root()
                finally:
                    sender.close()
        os.close(root_fd)
        self.assertEqual(len(os.listdir("/proc/self/fd")), descriptors_before)
